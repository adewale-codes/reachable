const _ = require('lodash');

function loadPlugin(moduleName) {
  // The module name comes from user configuration.
  const plugin = require(moduleName);
  return plugin.template('<%= user %>');
}

function pluginNames(config) {
  return _.uniq(config.plugins);
}

module.exports = { loadPlugin, pluginNames };
