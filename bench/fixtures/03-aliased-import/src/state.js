import { set as setPath, get as getPath } from 'lodash';

const state = {};

export function update(path, value) {
  setPath(state, path, value);
  return getPath(state, path);
}
