// SAFE: helmet, explicit public dir, environment-gated error details, security.txt present.
const express = require('express');
const helmet = require('helmet');
const errorhandler = require('errorhandler');

const app = express();
app.use(helmet());
app.use(express.static('public'));

if (process.env.NODE_ENV === 'development') {
  app.use(errorhandler());
}

app.use((err, req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

app.listen(3000);
