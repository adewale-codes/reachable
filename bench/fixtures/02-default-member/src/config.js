import _ from 'lodash';

export function loadConfig(defaults, userConfig) {
  const merged = _.merge({}, defaults, userConfig);
  return _.get(merged, 'server.port', 8080) ? merged : defaults;
}
