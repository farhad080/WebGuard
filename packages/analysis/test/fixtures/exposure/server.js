// Mirrors Juice Shop server.js static serving, error handling, and legacy routes.
const express = require('express');
const serveIndex = require('serve-index');
const errorhandler = require('errorhandler');
const multer = require('multer');
const { fileServer } = require('./routes/fileServer');
const { whoami } = require('./routes/currentUser');
const { handleXmlUpload } = require('./routes/fileUpload');
const { legacyOrders } = require('./routes/b2bOrders');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });
app.use(express.json());

// Public assets (safe)
app.use(express.static('public'));

// #38 / #12 / #16 / #18: the "ftp" folder is browsable and file-served
app.use('/ftp', serveIndex('ftp', { icons: true }));
app.use('/ftp/:file', fileServer());

// #19: JSONP user endpoint
app.get('/rest/user/whoami', whoami());

// #37: upload endpoint that still processes XML (old B2B interface)
app.post('/file-upload', upload.single('file'), handleXmlUpload);
// Deprecated B2B order API: removed from the UI in v8, still mounted for "compatibility"
app.post('/b2b/v1/orders', legacyOrders);

// #36: verbose error handler, always on
app.use(errorhandler());

app.listen(3000);
