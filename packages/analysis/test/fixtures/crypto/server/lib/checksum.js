// SAFE (non-security MD5/SHA-1): file checksums, ETags, cache keys. No findings.
const crypto = require('crypto');
const fs = require('fs');

function fileChecksum(file) {
  const checksum = crypto.createHash('md5').update(fs.readFileSync(file)).digest('hex');
  return checksum;
}

function etagFor(body) {
  return crypto.createHash('sha1').update(body).digest('base64');
}

function cacheKeyFor(url) {
  const cacheKey = crypto.createHash('md5').update(url).digest('hex');
  return cacheKey;
}

function contentHash(buffer) {
  const h = crypto.createHash('sha256');
  h.update(buffer);
  return h.digest('hex');
}

module.exports = { fileChecksum, etagFor, cacheKeyFor, contentHash };
