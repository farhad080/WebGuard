const express = require('express');
const db = require('../db');

const usersRouter = express.Router();

usersRouter.post('/search', async (req, res) => {
  const name = req.body.name;
  const rows = await db.query("SELECT * FROM users WHERE name = '" + name + "'");
  res.json(rows);
});

usersRouter.get('/:id', async (req, res) => {
  const rows = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
  res.json(rows[0]);
});

module.exports = { usersRouter };
