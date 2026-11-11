// Reflected XSS: the order id from the query string is echoed into an HTML response.
module.exports = function trackOrder() {
  return (req, res) => {
    res.send('<b>' + req.query.id + '</b>');
  };
};

module.exports.status = function orderStatus() {
  return (req, res) => {
    const id = req.params.id;
    res.status(404).send(`<h1>Order ${id} not found</h1>`);
  };
};
