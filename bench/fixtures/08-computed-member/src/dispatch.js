import _ from 'lodash';

// Runs whichever lodash helper the request names, e.g. { op: "camelCase" }.
export function dispatch(request) {
  return _[request.op](...request.args);
}
