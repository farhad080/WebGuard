// SAFE: proper password hashing with salted, slow KDFs. No findings.
const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const crypto = require('crypto');

async function hashWithBcrypt(password) {
  return bcrypt.hash(password, 12);
}

async function hashWithArgon2(password) {
  return argon2.hash(password, { type: argon2.argon2id });
}

function hashWithScrypt(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function hashWithPbkdf2(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 310000, 32, 'sha256').toString('hex');
}

module.exports = { hashWithBcrypt, hashWithArgon2, hashWithScrypt, hashWithPbkdf2 };
