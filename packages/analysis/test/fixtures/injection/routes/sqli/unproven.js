// Dynamic SQL from a function parameter: origin can't be proven in this file (medium).
const pool = require('../../db');

function findByName(name) {
  return pool.query("SELECT * FROM users WHERE name = '" + name + "'");
}

module.exports = { findByName };
