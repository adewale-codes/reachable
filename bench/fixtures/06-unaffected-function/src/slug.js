const _ = require('lodash');

function slugFor(record) {
  return _.kebabCase(_.get(record, 'title', 'untitled'));
}

module.exports.slugFor = slugFor;
