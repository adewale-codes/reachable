const externals = ['lodash'];

export default {
  input: 'src/index.js',
  external: (id) => externals.includes(id),
};
