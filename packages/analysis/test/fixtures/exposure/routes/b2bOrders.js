function legacyOrders(req, res) {
  res.status(201).json({ accepted: Array.isArray(req.body.orderLines) });
}

module.exports = { legacyOrders };
