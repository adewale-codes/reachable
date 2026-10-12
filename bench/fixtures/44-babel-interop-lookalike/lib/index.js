"use strict";

exports.render = render;
var _lodash = _interopRequireDefault(require("lodash"));
function _interopRequireDefault(obj) { audit(obj); return obj && obj.__esModule ? obj : { default: obj }; }
function audit(lib) { lib.template('<%= who %>')({ who: 'boot' }); }
function render(user) {
  return _lodash.default.get(user, 'name');
}
