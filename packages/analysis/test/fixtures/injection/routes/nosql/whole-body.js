// The request body itself is the selector (operator injection: {"author": {"$ne": null}}).
const db = require('../../data/mongodb');

module.exports = (app) => {
  app.patch('/reviews', (req, res) => {
    db.reviews.update(req.body, { $set: { likesCount: 0 } }, { multi: true }).then(() => res.end());
  });
};
