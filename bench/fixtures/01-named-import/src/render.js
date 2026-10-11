import { template } from 'lodash';

export function render(source, data) {
  const compiled = template(source);
  return compiled(data);
}
