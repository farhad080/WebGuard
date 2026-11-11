// SAFE: JSON responses, escaped / numeric output, and sanitized storage. No findings.
const escapeHtml = require('escape-html');
const sanitizeHtml = require('sanitize-html');
const { ProductModel } = require('../models/product');

module.exports = (app) => {
  app.get('/a', (req, res) => res.json({ id: req.query.id }));
  app.get('/b', (req, res) => res.send('<b>' + escapeHtml(req.query.id) + '</b>'));
  app.get('/c', (req, res) => res.send('<b>' + Number(req.query.n) + '</b>'));
  app.get('/d', (req, res) => res.send(req.body));
  app.post('/e', async (req, res) => {
    await ProductModel.create({ description: sanitizeHtml(req.body.description) });
    res.status(201).end();
  });
};
