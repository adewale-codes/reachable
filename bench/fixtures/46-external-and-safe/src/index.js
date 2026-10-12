import { get } from 'lodash';

export const nameOf = (user) => get(user, 'profile.name');
