// Mirrors Juice Shop routes/fileServer.ts: a suffix-only allowlist, null byte cut *after* the check.
const path = require('path');

function endsWithAllowlistedFileType(param) {
  return param.endsWith('.md') || param.endsWith('.pdf');
}

function cutOffPoisonNullByte(str) {
  const nullByte = '%00';
  return str.includes(nullByte) ? str.substring(0, str.indexOf(nullByte)) : str;
}

module.exports.fileServer = function fileServer() {
  return ({ params }, res, next) => {
    const file = params.file;
    if (!file.includes('/')) {
      if (endsWithAllowlistedFileType(file)) {
        res.sendFile(path.resolve('ftp/', cutOffPoisonNullByte(file)));
      } else {
        res.status(403);
        next(new Error('Only .md and .pdf files are allowed!'));
      }
    } else {
      res.status(403);
      next(new Error('File names cannot contain forward slashes!'));
    }
  };
};
