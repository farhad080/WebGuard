// Broken / obsolete ciphers, plus one correct AES-GCM use.
const crypto = require('crypto');

function legacyEncrypt(key, text) {
  const cipher = crypto.createCipher('aes192', key);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function tripleDes(key, iv, text) {
  return crypto.createCipheriv('des-ede3-cbc', key, iv).update(text, 'utf8', 'hex');
}

const MODE = 'aes-256-ecb';
function ecb(key, text) {
  return crypto.createCipheriv(MODE, key, null).update(text, 'utf8', 'hex');
}

// SAFE
function modern(key, text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([iv, cipher.update(text, 'utf8'), cipher.final(), cipher.getAuthTag()]);
}

module.exports = { legacyEncrypt, tripleDes, ecb, modern };
