const ms = require('ms');

function timeoutFrom(header) {
  return ms(header);
}

module.exports = { timeoutFrom };
