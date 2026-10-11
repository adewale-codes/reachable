import { get } from 'lodash';

export function total(order) {
  const base = get(order, 'amount', 0);
  return base + eval('2 * 3');
}
