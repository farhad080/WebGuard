/**
 * Popular npm package names used as typosquatting targets (bundled, offline). A dependency
 * whose name is 1–2 edits away from one of these (or equal after stripping a `-js` / `node-`
 * style affix) and is not itself on the list is a typosquat candidate.
 */
export const POPULAR_PACKAGES: readonly string[] = [
  // web frameworks & middleware
  'express', 'koa', 'fastify', 'hapi', 'restify', 'body-parser', 'cookie-parser', 'cors',
  'helmet', 'morgan', 'multer', 'compression', 'express-session', 'express-jwt',
  'express-validator', 'express-rate-limit', 'serve-static', 'serve-index', 'errorhandler',
  'connect', 'finale-rest', 'epilogue', 'http-proxy', 'socket.io', 'socket.io-client', 'ws',
  // auth & crypto
  'jsonwebtoken', 'passport', 'passport-jwt', 'passport-local', 'bcrypt', 'bcryptjs', 'argon2',
  'crypto-js', 'jose', 'otplib', 'speakeasy', 'uuid', 'nanoid',
  // data
  'mongoose', 'mongodb', 'sequelize', 'typeorm', 'prisma', 'knex', 'pg', 'mysql', 'mysql2',
  'sqlite3', 'redis', 'ioredis', 'marsdb', 'lowdb',
  // utilities
  'lodash', 'underscore', 'ramda', 'moment', 'dayjs', 'date-fns', 'axios', 'request',
  'node-fetch', 'got', 'superagent', 'chalk', 'commander', 'yargs', 'minimist', 'debug',
  'dotenv', 'config', 'glob', 'rimraf', 'mkdirp', 'fs-extra', 'semver', 'async', 'bluebird',
  'q', 'colors', 'inquirer', 'ora', 'winston', 'pino', 'bunyan', 'validator', 'joi', 'yup',
  'zod', 'ajv', 'sanitize-html', 'dompurify', 'xss', 'marked', 'markdown-it', 'cheerio',
  'jsdom', 'puppeteer', 'sharp', 'jimp', 'pdfkit', 'xml2js', 'libxmljs', 'libxmljs2',
  'js-yaml', 'yaml', 'qs', 'query-string', 'classnames', 'prop-types', 'immutable', 'rxjs',
  'tslib', 'core-js', 'regenerator-runtime', 'ms', 'mime', 'mime-types', 'unzipper',
  'archiver', 'z85', 'pug', 'ejs', 'handlebars', 'nunjucks', 'i18n', 'nodemailer',
  // front end
  'react', 'react-dom', 'react-router', 'react-router-dom', 'redux', 'react-redux', 'vue',
  'vue-router', 'vuex', 'pinia', 'svelte', 'next', 'nuxt', 'jquery', 'bootstrap',
  '@angular/core', 'ngx-cookie', 'ngx-cookie-service', 'ngx-translate', 'zone.js',
  // tooling
  'typescript', 'webpack', 'webpack-cli', 'vite', 'rollup', 'esbuild', 'babel-loader',
  'eslint', 'prettier', 'jest', 'mocha', 'chai', 'sinon', 'vitest', 'nodemon', 'ts-node',
  'tsx', 'concurrently', 'cross-env', 'husky', 'lint-staged', 'grunt', 'gulp',
]; // prettier-ignore

/**
 * Verified legitimate packages whose names are close to a popular one. Never reported as
 * typosquats.
 */
export const TYPOSQUAT_ALLOWLIST: ReadonlySet<string> = new Set([
  'preact', 'pino', 'chai', 'vuex', 'koa', 'got', 'ms', 'qs', 'pg', 'ws', 'q', 'dayjs', 'jose',
  'yup', 'zod', 'nuxt', 'next', 'yaml', 'mysql2', 'libxmljs2', 'bcryptjs', 'sinon', 'axios',
  'node-fetch', 'ioredis', 'react-dom', 'jsdom', 'ejs', 'pug', 'tsx', 'vite', 'mime', 'xss',
  'redux', 'yargs', 'cors', 'core-js', 'colors', 'config', 'connect', 'request', 'jest',
  'eslint', 'mongodb', 'mongoose',
]); // prettier-ignore
