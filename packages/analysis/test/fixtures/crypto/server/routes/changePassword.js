// Fast, unsalted password hashing done inline.
const crypto = require('crypto');

module.exports = function changePassword(user) {
  return (req, res) => {
    const pw = req.body.newPassword;
    user.passwordHash = crypto.createHash('md5').update(pw).digest('hex');
    user.legacyHash = crypto.createHash('sha256').update(user.password).digest('hex');
    res.json({ ok: true });
  };
};
