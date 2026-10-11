export function installHelpers(lib) {
  return {
    greet: lib.template('Hello <%= name %>'),
  };
}
