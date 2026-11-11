// MD5/SHA-1 with an input that is not a secret: reported, but only as low severity.
const crypto = require('crypto');

module.exports = function requestId() {
  const requestToken = crypto.createHash('sha1').update(String(Math.random())).digest('hex');
  return requestToken;
};
