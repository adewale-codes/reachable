const { defaultsDeep, map } = require('lodash');

function withDefaults(options) {
  return defaultsDeep({}, options, { retries: 3, backoff: { base: 100 } });
}

function names(items) {
  return map(items, 'name');
}

module.exports = { withDefaults, names };
