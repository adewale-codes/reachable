const trimNewlines = require('trim-newlines');

module.exports.stripLeading = (text) => trimNewlines.start(text);
