// SAFE (CSRF): session cookie is SameSite=Strict, so cross-site requests carry no session.
const express = require('express');
const session = require('express-session');

const app = express();
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { sameSite: 'strict', secure: true, httpOnly: true } }));

function requireLogin(req, res, next) {
  return req.session.userId ? next() : res.status(401).end();
}

app.post('/profile', requireLogin, (req, res) => {
  req.session.displayName = String(req.body.displayName);
  res.json({ ok: true });
});

app.listen(3000);
