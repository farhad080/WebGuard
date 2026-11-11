// Mirrors Juice Shop routes/currentUser.ts: answers JSONP when a callback is given (#19).
module.exports.whoami = function whoami() {
  return (req, res) => {
    const user = global.sessions?.get(req.cookies.token);
    const response = { user: { id: user?.id, email: user?.email } };
    if (req.query.callback === undefined) {
      res.json(response);
    } else {
      res.jsonp(response);
    }
  };
};
