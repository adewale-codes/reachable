export default {
  build: {
    lib: { entry: 'src/index.js', formats: ['es'] },
    rollupOptions: { external: ['lodash'] },
  },
};
