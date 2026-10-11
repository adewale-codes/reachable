import JSON5 from 'json5';

export function dump(value) {
  return JSON5.stringify(value, { space: 2, quote: "'" });
}
