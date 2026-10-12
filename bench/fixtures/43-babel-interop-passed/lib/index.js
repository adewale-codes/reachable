"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.render = render;
var _lodash = _interopRequireDefault(require("lodash"));
function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }
const plugins = require('./plugins');
plugins.register(_lodash);
function render(user) {
  return _lodash.default.get(user, 'name');
}
