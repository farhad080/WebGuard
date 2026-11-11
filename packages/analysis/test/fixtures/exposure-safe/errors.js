// SAFE: a generic error handler that never leaks details.
module.exports = function genericErrors(err, req, res, next) {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong' });
};
