const omit = require('lodash/omit');
const get = require('lodash/get.js');

function sanitize(req) {
  return omit(get(req, 'body', {}), ['password']);
}

module.exports = { sanitize };
