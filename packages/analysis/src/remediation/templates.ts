import {
  contextualizeAccess,
  contextualizeCsrf,
  contextualizeDependency,
  contextualizeExposure,
  contextualizeMassAssignment,
  contextualizeMisconfig,
  contextualizeNoSql,
  contextualizeSecret,
  contextualizeSql,
  contextualizeWeakCrypto,
  contextualizeXss,
} from './contextualize.js';
import { REFS } from './references.js';
import type { FixTemplate, TemplateSet } from './types.js';

/**
 * Fix templates for every built-in detector. Content is deterministic and offline; each
 * template's example is a correct vulnerable/secure pair for the class.
 */

const sql: FixTemplate = {
  id: 'A1-sql-injection',
  title: 'Use a parameterized query',
  why:
    'Request data is concatenated into the SQL text, so the database parses attacker input as ' +
    "SQL: a value like `' OR 1=1--` changes the query's logic.",
  impact:
    'Authentication bypass (log in as any user, e.g. the admin), reading every table ' +
    '(UNION SELECT), and modifying or deleting data.',
  steps: [
    'Find every place the query string is built from variables (+, template literals, string helpers).',
    'Replace each interpolated value with a placeholder ($1 / ? / :name) so the SQL text is a constant.',
    'Pass the values separately: Sequelize `bind`/`replacements`, pg/mysql/sqlite parameter arrays, knex.raw bindings.',
    "For identifiers that can't be parameters (table/column names, sort direction), map the input to an allowlist of known values.",
    'Validate input types early (e.g. Number(id)) and run the database account with least privilege.',
    "Re-test with a payload such as `' OR 1=1--`: it must be treated as a literal value.",
  ],
  example: {
    language: 'typescript',
    before: "sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email}'`)",
    after: "sequelize.query('SELECT * FROM Users WHERE email = $1', { bind: [req.body.email] })",
  },
  references: [REFS.sqlInjection, REFS.queryParameterization],
};

const nosql: FixTemplate = {
  id: 'A2-nosql-injection',
  title: 'Cast selector values to scalars',
  why:
    'The query selector takes client JSON as-is, and MongoDB treats objects as operators: ' +
    '{"id": {"$ne": -1}} turns "this record" into "every record".',
  impact:
    'Reading or updating every document (e.g. editing all reviews at once), bypassing ' +
    'login checks, and, with $where, running JavaScript on the database server.',
  steps: [
    'Never pass req.body / req.query directly as a selector or update document.',
    'Build the selector from explicit fields and cast each value to the expected type: String(), Number(), or a validated ObjectId.',
    'Validate the request body shape with a schema (zod/joi) that rejects objects where scalars are expected.',
    'Replace $where / mapReduce strings with regular query operators.',
    'Enable mongo-sanitize (or strictQuery/sanitizeFilter in Mongoose) as a safety net.',
  ],
  example: {
    language: 'typescript',
    before: 'db.reviews.update({ _id: req.body.id }, { $set: { message: req.body.message } })',
    after:
      'db.reviews.update({ _id: String(req.body.id) }, { $set: { message: String(req.body.message) } })',
  },
  references: [REFS.injection, REFS.inputValidation],
};

const ssti: FixTemplate = {
  id: 'A3-ssti',
  title: 'Remove dynamic evaluation of user data',
  why:
    'User-controlled text reaches eval / Function / vm or a template engine compiling a ' +
    'template string, so the text runs as code on the server.',
  impact:
    "Remote code execution with the server's privileges, e.g. #{global.process.mainModule" +
    ".require('child_process').execSync('id')}: full compromise of the host and its data.",
  steps: [
    'Delete the eval/Function/vm call; data never needs to be executed.',
    'If you need structured data, parse it (JSON.parse) instead of evaluating it.',
    'If you need a choice of behaviour, map the input to an allowlist of functions.',
    'Keep templates static (files under your control) and pass user values only as render data, never as template source; prefer logic-less templates (Mustache/Handlebars without helpers).',
    'Treat stored profile fields (username, bio) as untrusted input too.',
  ],
  example: {
    language: 'typescript',
    before: 'const greeting = eval("\'Hello " + user.username + "\'")',
    after: 'const greeting = `Hello ${user.username}` // plain data, rendered with auto-escaping',
  },
  references: [REFS.injection, REFS.nodejs],
};

const xssBase: Pick<FixTemplate, 'references'> = {
  references: [REFS.xss, REFS.domXss],
};

const xssDom: FixTemplate = {
  ...xssBase,
  id: 'A4-xss/dom',
  title: 'Write untrusted data as text, not HTML',
  why:
    'Browser code writes URL-controlled data (query string, fragment, route params) into the ' +
    'page as HTML, so markup in a crafted link executes.',
  impact:
    "Script execution in the victim's session: token theft, actions as the user, phishing overlays.",
  steps: [
    'Use textContent / innerText (or framework bindings like {{ value }} and {value}) instead of innerHTML, document.write, insertAdjacentHTML.',
    'Remove bypassSecurityTrust* / dangerouslySetInnerHTML on user-influenced values.',
    'If HTML is genuinely required, sanitize it with DOMPurify.sanitize() right before rendering.',
    'Add a Content-Security-Policy that forbids inline scripts as defence in depth.',
  ],
  example: {
    language: 'typescript',
    before: 'el.innerHTML = this.route.snapshot.queryParams.q',
    after: 'el.textContent = this.route.snapshot.queryParams.q',
  },
};

const xssReflected: FixTemplate = {
  ...xssBase,
  id: 'A4-xss/reflected',
  title: 'Encode output for its HTML context',
  why: "Request input is echoed into an HTML response without encoding, so a crafted link makes the app deliver the attacker's script.",
  impact:
    "Script execution in the victim's browser under your origin: session theft and account actions.",
  steps: [
    'Return JSON (res.json) for API responses instead of hand-built HTML.',
    'When HTML is needed, render with an auto-escaping template engine or encode each value (escape-html) for its context.',
    'Never mark reflected values as trusted (bypassSecurityTrust*).',
    'Add a Content-Security-Policy and set X-Content-Type-Options: nosniff.',
  ],
  example: {
    language: 'typescript',
    before: "res.send('<b>' + req.query.id + '</b>')",
    after:
      "res.send('<b>' + escapeHtml(String(req.query.id)) + '</b>') // import escapeHtml from 'escape-html'",
  },
};

const xssStored: FixTemplate = {
  ...xssBase,
  id: 'A4-xss/stored',
  title: 'Sanitize on input and encode on output',
  why:
    'User-supplied text is stored unsanitized and later rendered as HTML for other users. ' +
    'Client-side validation is bypassed by calling the API directly.',
  impact:
    'Persistent script execution for every viewer, often administrators: account takeover at scale.',
  steps: [
    'Validate fields on the server (format, length); never rely on client-side checks.',
    'Sanitize rich text before storing it (sanitize-html with a tag allowlist), or store plain text only.',
    'Render stored values with auto-escaping bindings; remove innerHTML / bypassSecurityTrust* / dangerouslySetInnerHTML on them.',
    'Clean existing records that already contain markup.',
  ],
  example: {
    language: 'typescript',
    before: 'await product.update({ description: req.body.description })',
    after:
      "await product.update({ description: sanitizeHtml(req.body.description) }) // import sanitizeHtml from 'sanitize-html'",
  },
};

const secrets: FixTemplate = {
  id: 'A5-hardcoded-secrets',
  title: 'Move the secret out of the code and rotate it',
  why:
    'A credential is committed in source; everyone with the repository, a build artifact, ' +
    'or (for client code) any browser can read it.',
  impact:
    'Impersonation of the application against the service the secret unlocks (cloud accounts, databases, APIs).',
  steps: [
    'Rotate the credential now: treat the committed value as compromised.',
    'Load it at runtime from the environment or a secret manager (Vault, AWS Secrets Manager, …) instead of a literal.',
    'For client-side code: move the call that needs the secret to the server; never ship secrets to the browser.',
    'Remove the value from git history (git filter-repo / BFG) and add the file pattern to .gitignore.',
    'Add a pre-commit secret scanner (e.g. gitleaks) to stop it recurring.',
  ],
  example: {
    language: 'typescript',
    before: "const awsSecretAccessKey = 'q8Hx…[redacted]'",
    after: 'const awsSecretAccessKey = process.env.AWS_SECRET_ACCESS_KEY',
  },
  references: [REFS.secrets],
};

const cryptoPassword: FixTemplate = {
  id: 'A6-weak-crypto/password',
  title: 'Hash passwords with argon2id (or bcrypt)',
  why: 'Passwords are hashed with a fast, unsalted hash (MD5/SHA-1/SHA-256) that GPUs brute-force at billions of guesses per second.',
  impact:
    'A leaked user table reveals most passwords (rainbow tables / brute force), enabling account takeover here and elsewhere.',
  steps: [
    'Replace the hash with a slow, salted KDF: argon2id (argon2.hash) or bcrypt with cost ≥ 12.',
    'Verify with argon2.verify / bcrypt.compare; never compare hashes yourself.',
    "Migrate existing hashes: re-hash on the user's next successful login and force resets for dormant accounts.",
    'Keep the hashing in one helper so it can be upgraded later.',
  ],
  example: {
    language: 'typescript',
    before: "const hash = crypto.createHash('md5').update(password).digest('hex')",
    after: 'const hash = await argon2.hash(password) // argon2id with a random salt',
  },
  references: [REFS.passwordStorage],
};

const cryptoCipher: FixTemplate = {
  id: 'A6-weak-crypto/cipher',
  title: 'Use authenticated encryption (AES-256-GCM)',
  why: 'An obsolete cipher or mode (createCipher, DES/3DES, RC4, ECB) is used, so ciphertext can be broken or analysed.',
  impact: 'Encrypted data is readable or forgeable by an attacker.',
  steps: [
    "Use crypto.createCipheriv('aes-256-gcm', key, iv) with a random 12-byte IV per message.",
    'Store the IV and the auth tag (getAuthTag) with the ciphertext and verify the tag on decrypt.',
    'Derive keys with a KDF or load them from a secret manager; never reuse an IV with the same key.',
    'Re-encrypt existing data with the new scheme.',
  ],
  example: {
    language: 'typescript',
    before: "const cipher = crypto.createCipher('aes192', key)",
    after:
      "const iv = crypto.randomBytes(12)\nconst cipher = crypto.createCipheriv('aes-256-gcm', key, iv) // store iv + cipher.getAuthTag()",
  },
  references: [REFS.cryptoStorage],
};

const cryptoEncoding: FixTemplate = {
  id: 'A6-weak-crypto/encoding',
  title: 'Replace encoding with real encryption or a signature',
  why: 'base64/hex/z85/rot13 is used as if it were encryption; encoding has no key and anyone can reverse it.',
  impact: '"Encrypted" values (coupons, tokens) can be read and forged.',
  steps: [
    'Decide what is needed: confidentiality (encrypt with AES-256-GCM) or integrity (sign with HMAC-SHA-256).',
    'Keep the key on the server (secret manager); never in the client.',
    'Verify signatures/auth tags before trusting the value.',
  ],
  example: {
    language: 'typescript',
    before: "const coupon = Buffer.from(code).toString('base64')",
    after:
      "const sig = crypto.createHmac('sha256', process.env.COUPON_KEY!).update(code).digest('base64url')\nconst coupon = `${code}.${sig}` // verify the HMAC before accepting",
  },
  references: [REFS.cryptoStorage],
};

const cryptoWeakHash: FixTemplate = {
  id: 'A6-weak-crypto/weak-hash',
  title: 'Use SHA-256 or better where a cryptographic hash is needed',
  why: 'MD5/SHA-1 have practical collisions; they must not protect anything an attacker could tamper with.',
  impact:
    'Forged files/tokens with matching hashes, if the hash is used for integrity or identity.',
  steps: [
    'If the hash is a non-security checksum or cache key, document that (no change needed).',
    "Otherwise switch to crypto.createHash('sha256') (or HMAC-SHA-256 when a key is involved).",
  ],
  example: {
    language: 'typescript',
    before: "crypto.createHash('sha1').update(data).digest('hex')",
    after: "crypto.createHash('sha256').update(data).digest('hex')",
  },
  references: [REFS.cryptoStorage],
};

const exposureFiles: FixTemplate = {
  id: 'A7-sensitive-file-exposure',
  title: 'Serve only an explicit public directory',
  why: 'Backups, dumps, keys, or confidential documents sit inside a directory the server serves to anyone.',
  impact:
    'Source code, dependency lists, credentials, and business data downloadable by anyone who guesses the name.',
  steps: [
    'Remove backups, dumps, keys, and internal documents from served directories (and from the deployed artifact).',
    'Serve static files from one dedicated public/ directory containing only intended assets.',
    'Disable directory listing (remove serveIndex).',
    'Block sensitive extensions (.bak, .sql, .env, .key, …) at the proxy as defence in depth.',
    'Rotate any credential found in an exposed file.',
  ],
  example: {
    language: 'typescript',
    before: "app.use('/ftp', serveIndex('ftp', { icons: true }))",
    after:
      "app.use('/assets', express.static(path.join(__dirname, 'public'), { dotfiles: 'deny' }))",
  },
  references: [REFS.pathTraversal],
};

const exposureFilter: FixTemplate = {
  id: 'A7-sensitive-file-exposure/filter',
  title: 'Validate the decoded file name against an allowlist',
  why: 'The file server only checks the name suffix, which a poison null byte (x.bak%2500.md) or double extension bypasses.',
  impact: 'Any file in the served directory can be downloaded, including backups and keys.',
  steps: [
    'Decode the requested name first (decodeURIComponent) and reject control characters / null bytes.',
    'Accept only names on an explicit allowlist (or a strict /^[\\w-]+\\.(md|pdf)$/ on the decoded value).',
    'Resolve the path and confirm it stays inside the served directory before sending.',
  ],
  example: {
    language: 'typescript',
    before: "if (file.endsWith('.md')) res.sendFile(path.resolve('ftp/', file))",
    after:
      "const name = decodeURIComponent(file)\nif (!ALLOWED_FILES.has(name)) return res.sendStatus(403)\nres.sendFile(name, { root: path.resolve('ftp') })",
  },
  references: [REFS.pathTraversal, REFS.inputValidation],
};

const exposureJsonp: FixTemplate = {
  id: 'A7-sensitive-file-exposure/jsonp',
  title: 'Remove JSONP for user data',
  why: 'JSONP lets any website read the response cross-domain via a callback parameter.',
  impact: "Leaks the logged-in user's data (e.g. email) to any site they visit.",
  steps: [
    'Return plain JSON (res.json) and remove the callback branch.',
    'Allow cross-origin reads only for trusted origins via CORS.',
  ],
  example: { language: 'typescript', before: 'res.jsonp(response)', after: 'res.json(response)' },
  references: [REFS.headers],
};

const accessRoute: FixTemplate = {
  id: 'A8-broken-access-control/route',
  title: 'Enforce authorization on the server route',
  why: 'A state-changing or admin route has no server-side authorization; hiding it in the UI does not stop direct API calls.',
  impact:
    "Anyone can perform the action: delete other users' data, read admin configuration, change settings.",
  steps: [
    'Add authentication middleware to the route (or the router it is mounted on).',
    'Add an authorization check for the required role/permission (e.g. requireRole("admin")).',
    'Deny by default: register a catch-all guard for /api routes and opt specific public routes out.',
    'Add tests that call the route as anonymous and as a normal user and expect 401/403.',
  ],
  example: {
    language: 'typescript',
    before: "app.delete('/api/Feedbacks/:id', deleteFeedback())",
    after: "app.delete('/api/Feedbacks/:id', requireAuth, requireRole('admin'), deleteFeedback())",
  },
  references: [REFS.authorization],
};

const accessIdor: FixTemplate = {
  id: 'A8-broken-access-control/idor',
  title: 'Scope the lookup to the authenticated user',
  why: 'The record is loaded or changed by a client-supplied id without checking that it belongs to the logged-in user.',
  impact:
    "Reading or modifying other users' records by changing an id in the URL or body (e.g. other baskets).",
  steps: [
    'Add an ownership predicate to the query: where: { id, UserId: req.user.id }.',
    "Return 404 (not 403) when no owned record matches, so ids can't be enumerated.",
    "For writes with foreign keys (BasketId), verify the referenced record is owned by the user, or take it from the user's session.",
    "Add tests that access another user's record and expect 404.",
  ],
  example: {
    language: 'typescript',
    before: 'const basket = await BasketModel.findByPk(req.params.id)',
    after:
      'const basket = await BasketModel.findOne({ where: { id: req.params.id, UserId: req.user.id } })',
  },
  references: [REFS.idor, REFS.authorization],
};

const massAssign: FixTemplate = {
  id: 'A9-mass-assignment',
  title: 'Use an explicit field allowlist (DTO)',
  why: 'The whole request body is written to the model, so the client can set any column, including privileged ones.',
  impact:
    'Privilege escalation ({"role": "admin"}), acting as another user ({"UserId": 2}), or changing prices/balances.',
  steps: [
    "Copy only the fields the client may set: pick(req.body, ['email', 'password']) or a DTO class.",
    'Validate the body with a strict schema (zod .strict(), joi with unknown keys rejected).',
    'Set privileged fields (role, UserId, price) on the server from the session or business logic.',
    'Configure the ORM to protect sensitive attributes where supported.',
  ],
  example: {
    language: 'typescript',
    before: 'await UserModel.create(req.body)',
    after:
      "await UserModel.create(pick(req.body, ['email', 'password'])) // role is set server-side",
  },
  references: [REFS.massAssignment, REFS.inputValidation],
};

const overSelect: FixTemplate = {
  id: 'A9-mass-assignment/over-selection',
  title: 'Use a fixed server-side attribute list',
  why: 'The client chooses which columns are returned, so it can request password hashes or secrets.',
  impact: 'Disclosure of sensitive columns (password hashes, TOTP secrets, tokens).',
  steps: [
    'Return a fixed attribute list defined on the server.',
    'If clients may choose fields, intersect the request with an allowlist that excludes secrets.',
    'Exclude sensitive columns by default in the model (default scopes / toJSON).',
  ],
  example: {
    language: 'typescript',
    before: "UserModel.findByPk(id, { attributes: req.query.fields.split(',') })",
    after: "UserModel.findByPk(id, { attributes: ['id', 'email', 'username'] })",
  },
  references: [REFS.massAssignment],
};

const csrf: FixTemplate = {
  id: 'A10-missing-csrf',
  title: 'Add CSRF protection and SameSite cookies',
  why: 'The route trusts a cookie for authentication with no CSRF token, so any site can make the browser send it.',
  impact:
    'Actions performed as the victim without their knowledge (change username/email/password).',
  steps: [
    'Add a CSRF token check (synchronizer or double-submit, e.g. csrf-csrf / lusca) to state-changing routes.',
    'Set the session/auth cookie to SameSite=Lax (or Strict), Secure and HttpOnly.',
    'Alternatively authenticate the API with an Authorization: Bearer header instead of cookies.',
    'Never perform state changes on GET requests.',
  ],
  example: {
    language: 'typescript',
    before: "app.post('/profile', updateUserProfile())",
    after:
      "app.use(session({ secret, cookie: { sameSite: 'lax', secure: true, httpOnly: true } }))\napp.post('/profile', csrfProtection, updateUserProfile())",
  },
  references: [REFS.csrf],
};

const depVuln: FixTemplate = {
  id: 'A11-vulnerable-deps',
  title: 'Upgrade the vulnerable dependency',
  why: 'A dependency version with a published vulnerability is installed; attackers scan for exactly these versions.',
  impact: 'Whatever the advisory describes: XSS, auth bypass, prototype pollution, RCE.',
  steps: [
    'Upgrade to the fixed version (or later) shown in the finding; for transitive packages, upgrade the parent or use npm overrides.',
    'Run the test suite and re-scan.',
    'Enable automated dependency updates (Dependabot/Renovate) and npm audit in CI.',
  ],
  example: {
    language: 'json',
    before: '"sanitize-html": "1.4.2"',
    after: '"sanitize-html": "^1.4.3"',
  },
  references: [REFS.dependencies, REFS.npm],
};

const depEol: FixTemplate = {
  ...depVuln,
  id: 'A11-vulnerable-deps/eol',
  title: 'Replace the end-of-life dependency',
  why: 'The package is unmaintained; future vulnerabilities will not be fixed.',
  impact: 'Unpatchable exposure to any vulnerability found later.',
  steps: [
    'Pick a maintained alternative (e.g. node-fetch/undici/axios instead of request).',
    'Migrate the call sites and remove the old package.',
    'Re-run tests and the scan.',
  ],
  example: {
    language: 'typescript',
    before: "const request = require('request')",
    after: '// use the built-in fetch (Node 18+) or undici',
  },
};

const depTyposquat: FixTemplate = {
  ...depVuln,
  id: 'A11-vulnerable-deps/typosquat',
  title: 'Replace the suspected typosquat with the intended package',
  why: 'The dependency name imitates a popular package; typosquats run malicious install scripts or ship backdoors.',
  impact:
    'Arbitrary code execution on developer machines and CI, credential theft, or a backdoored build.',
  steps: [
    'Verify the package on the npm registry (publisher, downloads, repository).',
    'If unintended, uninstall it and install the intended package.',
    'Audit what it ran: install scripts, network access, changed files; rotate secrets available to CI.',
    'Use lockfiles and `npm ci`, and review new dependencies before adding them.',
  ],
  example: {
    language: 'json',
    before: '"epilogue-js": "~0.7.0"',
    after: '"epilogue": "<verified version>"',
  },
};

const misconfigErrors: FixTemplate = {
  id: 'A12-security-misconfig/errors',
  title: 'Return generic errors; log details server-side',
  why: 'Stack traces or raw error objects are sent to clients, revealing paths, versions, and queries.',
  impact: 'Reconnaissance that makes other attacks (injection, path traversal) much easier.',
  steps: [
    'Use one final error handler that logs the error and returns a generic message with a correlation id.',
    "Enable verbose handlers (errorhandler) only when NODE_ENV === 'development'.",
    'Make sure the production build sets NODE_ENV=production.',
  ],
  example: {
    language: 'typescript',
    before: 'app.use((err, req, res, next) => res.status(500).send(err.stack))',
    after:
      "app.use((err, req, res, next) => {\n  logger.error(err)\n  res.status(500).json({ error: 'Internal server error' })\n})",
  },
  references: [REFS.errorHandling],
};

const misconfigHeaders: FixTemplate = {
  id: 'A12-security-misconfig/headers',
  title: 'Add security headers with helmet()',
  why: 'Without CSP, HSTS and nosniff, injected scripts run freely, users can be downgraded to HTTP, and uploads may be sniffed as scripts.',
  impact: 'Easier XSS exploitation, SSL stripping, and content-type confusion attacks.',
  steps: [
    'Add app.use(helmet()) before your routes.',
    'Tune the Content-Security-Policy for your assets (avoid unsafe-inline).',
    'Confirm the headers on a live response; a proxy/CDN may also set them.',
  ],
  example: {
    language: 'typescript',
    before: 'const app = express()',
    after: 'const app = express()\napp.use(helmet())',
  },
  references: [REFS.headers],
};

const misconfigListing: FixTemplate = {
  ...exposureFiles,
  id: 'A12-security-misconfig/listing',
  title: 'Disable directory listing',
};

const misconfigDeprecated: FixTemplate = {
  id: 'A12-security-misconfig/deprecated',
  title: 'Remove deprecated interfaces',
  why: 'A deprecated or legacy endpoint is still registered; forgotten endpoints rarely receive security fixes.',
  impact:
    'Attack surface such as XXE in an old XML upload or missing checks in an old API version.',
  steps: [
    'Remove the route and its handler if it is no longer needed.',
    'If it must stay, protect it like current endpoints (authz, validation) and track its removal date.',
    'For XML, disable external entities (noent: false) and DTD loading.',
  ],
  example: {
    language: 'typescript',
    before: "app.post('/file-upload', upload.single('file'), handleXmlUpload)",
    after:
      "app.post('/file-upload', upload.single('file'), handlePdfOrZipUpload) // XML interface removed",
  },
  references: [REFS.headers],
};

const misconfigSecurityTxt: FixTemplate = {
  id: 'A12-security-misconfig/security-txt',
  title: 'Publish /.well-known/security.txt',
  why: 'Researchers have no documented way to report vulnerabilities to you.',
  impact: 'Vulnerabilities go unreported or are disclosed publicly first.',
  steps: [
    'Create /.well-known/security.txt with Contact and Expires fields (RFC 9116).',
    'Serve it from the app (static file or express-security.txt) or the web server/CDN.',
    'Keep the Expires date current.',
  ],
  example: {
    language: 'text',
    before: '(no /.well-known/security.txt)',
    after: 'Contact: mailto:security@example.com\nExpires: 2027-12-31T23:59:59.000Z',
  },
  references: [REFS.securityTxt],
};

const todo: FixTemplate = {
  id: 'example-todo-comment',
  title: 'Resolve the security TODO',
  why: 'A "TODO SECURITY" comment marks known, unfinished security work.',
  impact: 'Depends on the missing control described in the comment.',
  steps: [
    'Read the comment and implement the missing control (or open a tracked issue).',
    'Remove the TODO once the work is done and tested.',
  ],
  example: {
    language: 'typescript',
    before: '// TODO SECURITY: add rate limiting',
    after: "app.use('/users', rateLimit({ windowMs: 60_000, max: 100 }))",
  },
  references: [REFS.nodejs],
};

export const TEMPLATE_SETS: readonly TemplateSet[] = [
  { detectorId: 'example-todo-comment', default: todo },
  { detectorId: 'A1-sql-injection', default: sql, contextualize: contextualizeSql },
  { detectorId: 'A2-nosql-injection', default: nosql, contextualize: contextualizeNoSql },
  { detectorId: 'A3-ssti', default: ssti },
  {
    detectorId: 'A4-xss',
    default: xssDom,
    variants: { dom: xssDom, reflected: xssReflected, stored: xssStored },
    select: (f) => /^(DOM|Reflected|Stored) XSS/.exec(f.evidence[0] ?? '')?.[1]?.toLowerCase(),
    contextualize: contextualizeXss,
  },
  { detectorId: 'A5-hardcoded-secrets', default: secrets, contextualize: contextualizeSecret },
  {
    detectorId: 'A6-weak-crypto',
    default: cryptoCipher,
    variants: {
      'CWE-916': cryptoPassword,
      'CWE-327': cryptoCipher,
      'CWE-261': cryptoEncoding,
      weak: cryptoWeakHash,
    },
    select: (f) => (f.cwe === 'CWE-327' && f.severity === 'low' ? 'weak' : (f.cwe ?? undefined)),
    contextualize: contextualizeWeakCrypto,
  },
  {
    detectorId: 'A7-sensitive-file-exposure',
    default: exposureFiles,
    variants: { 'CWE-22': exposureFilter, 'CWE-359': exposureJsonp, 'CWE-548': exposureFiles },
    contextualize: contextualizeExposure,
  },
  {
    detectorId: 'A8-broken-access-control',
    default: accessRoute,
    variants: { 'CWE-862': accessRoute, 'CWE-639': accessIdor },
    contextualize: contextualizeAccess,
  },
  {
    detectorId: 'A9-mass-assignment',
    default: massAssign,
    variants: { 'CWE-915': massAssign, 'CWE-213': overSelect },
    contextualize: contextualizeMassAssignment,
  },
  { detectorId: 'A10-missing-csrf', default: csrf, contextualize: contextualizeCsrf },
  {
    detectorId: 'A11-vulnerable-deps',
    default: depVuln,
    variants: { 'CWE-1395': depVuln, 'CWE-1104': depEol, 'CWE-1357': depTyposquat },
    contextualize: contextualizeDependency,
  },
  {
    detectorId: 'A12-security-misconfig',
    default: misconfigErrors,
    variants: {
      'CWE-209': misconfigErrors,
      'CWE-693': misconfigHeaders,
      'CWE-548': misconfigListing,
      'CWE-912': misconfigDeprecated,
      'CWE-1059': misconfigSecurityTxt,
    },
    contextualize: contextualizeMisconfig,
  },
];
