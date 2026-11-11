// Classic string concatenation with destructured input, and a sqlite3-style db.all sink.
const db = require('../../db');

module.exports = function (app) {
  app.get('/orders', (req, res) => {
    const { status } = req.query;
    const sql = "SELECT * FROM orders WHERE status = '" + status + "'";
    db.all(sql, (err, rows) => res.json(rows));
  });
};
