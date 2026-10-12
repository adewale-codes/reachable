const readConfig = require('fx-config-reader');
const renderEmail = require('fx-email-renderer');

module.exports = (cfg, user) => renderEmail(readConfig(cfg, 'mail.subject'), user);
