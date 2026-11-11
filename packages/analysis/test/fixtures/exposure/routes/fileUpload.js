// The UI only offers PDF/ZIP uploads, but XML is still parsed (deprecated B2B interface).
const libxml = require('libxmljs');

function handleXmlUpload(req, res, next) {
  if (req.file && req.file.originalname.toLowerCase().endsWith('.xml')) {
    const xmlDoc = libxml.parseXml(req.file.buffer.toString(), { noblanks: true, noent: true, nocdata: true });
    res.status(410).send('B2B customer complaints via file upload have been deprecated: ' + xmlDoc.toString().slice(0, 50));
  } else {
    next();
  }
}

module.exports = { handleXmlUpload };
