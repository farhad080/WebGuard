// Direct concatenation of a profile field into eval.
function greet(user) {
  return eval("'" + user.username + "'");
}
module.exports = { greet };
