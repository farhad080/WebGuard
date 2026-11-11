// SAFE: constants, sandbox without user input, functions in timers. No findings.
const vm = require('vm');
const pug = require('pug');
const fs = require('fs');

const FOUR = eval('2+2');
const SCRIPT = 'result = 6 * 7';
const sandbox = { result: 0 };
vm.runInNewContext(SCRIPT, sandbox);
vm.runInNewContext('1 + 1', {});
setTimeout(() => console.log(FOUR), 10);
const page = pug.compile(fs.readFileSync('views/page.pug', 'utf8'));

module.exports = function render(req, res) {
  res.send(page({ name: req.query.name }));
};
