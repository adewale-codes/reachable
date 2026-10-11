var _ = require('underscore');

var body = _.template('Dear <%= name %>, your order <%= id %> has shipped.');

exports.render = function (order) {
  return body(order);
};
