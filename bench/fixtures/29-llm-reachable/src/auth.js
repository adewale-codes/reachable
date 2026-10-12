const jwt = require('jsonwebtoken');

exports.check = (token, publicKey) => jwt.verify(token, publicKey, { algorithms: ['RS256'] });
