import _ from 'lodash';

export function tidy(values) {
  return _.chain(values).compact().uniq().value();
}

export function publicView(user) {
  return _(user).omit(['password', 'token']).value();
}
