"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.render = render;
var _lodash = _interopRequireDefault(require("lodash"));
function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }
function render(user) {
  return _lodash.default.startCase(_lodash.default.get(user, 'name', 'guest'));
}
