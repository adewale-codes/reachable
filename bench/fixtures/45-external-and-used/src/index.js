import _ from 'lodash';

export const render = (source, data) => _.template(source)(data);
