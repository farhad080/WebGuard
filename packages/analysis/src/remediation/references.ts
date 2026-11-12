import type { RemediationReference } from '@webguard/core';

const cheat = (title: string, slug: string): RemediationReference => ({
  title: `OWASP ${title} Cheat Sheet`,
  url: `https://cheatsheetseries.owasp.org/cheatsheets/${slug}.html`,
});

export const REFS = {
  sqlInjection: cheat('SQL Injection Prevention', 'SQL_Injection_Prevention_Cheat_Sheet'),
  queryParameterization: cheat('Query Parameterization', 'Query_Parameterization_Cheat_Sheet'),
  injection: cheat('Injection Prevention', 'Injection_Prevention_Cheat_Sheet'),
  inputValidation: cheat('Input Validation', 'Input_Validation_Cheat_Sheet'),
  nodejs: cheat('Node.js Security', 'Nodejs_Security_Cheat_Sheet'),
  xss: cheat('Cross Site Scripting Prevention', 'Cross_Site_Scripting_Prevention_Cheat_Sheet'),
  domXss: cheat('DOM based XSS Prevention', 'DOM_based_XSS_Prevention_Cheat_Sheet'),
  secrets: cheat('Secrets Management', 'Secrets_Management_Cheat_Sheet'),
  passwordStorage: cheat('Password Storage', 'Password_Storage_Cheat_Sheet'),
  cryptoStorage: cheat('Cryptographic Storage', 'Cryptographic_Storage_Cheat_Sheet'),
  authorization: cheat('Authorization', 'Authorization_Cheat_Sheet'),
  idor: cheat(
    'Insecure Direct Object Reference Prevention',
    'Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet',
  ),
  massAssignment: cheat('Mass Assignment', 'Mass_Assignment_Cheat_Sheet'),
  csrf: cheat(
    'Cross-Site Request Forgery Prevention',
    'Cross-Site_Request_Forgery_Prevention_Cheat_Sheet',
  ),
  dependencies: cheat(
    'Vulnerable Dependency Management',
    'Vulnerable_Dependency_Management_Cheat_Sheet',
  ),
  npm: cheat('NPM Security', 'NPM_Security_Cheat_Sheet'),
  errorHandling: cheat('Error Handling', 'Error_Handling_Cheat_Sheet'),
  headers: cheat('HTTP Headers', 'HTTP_Headers_Cheat_Sheet'),
  pathTraversal: {
    title: 'OWASP Path Traversal',
    url: 'https://owasp.org/www-community/attacks/Path_Traversal',
  },
  securityTxt: {
    title: 'RFC 9116: A File Format to Aid in Security Vulnerability Disclosure',
    url: 'https://www.rfc-editor.org/rfc/rfc9116',
  },
} satisfies Record<string, RemediationReference>;
