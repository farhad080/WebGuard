// "Encryption" that is only base64 encoding (encoding-as-encryption, #40).
function encrypt(text) {
  return Buffer.from(text).toString('base64');
}

function decrypt(encoded) {
  return Buffer.from(encoded, 'base64').toString('utf8');
}

const obfuscated = { encryptedToken: btoa('session-42') };

module.exports = { encrypt, decrypt, obfuscated };
