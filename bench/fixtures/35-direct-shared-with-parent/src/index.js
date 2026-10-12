const _ = require('lodash');
const greet = require('fx-greeting');

module.exports = (user) => greet(_.get(user, 'profile.name', 'friend'));
