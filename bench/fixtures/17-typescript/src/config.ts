import JSON5 = require('json5');
import type { JwtPayload } from 'jsonwebtoken';

export interface Config {
  issuer: string;
  claims?: JwtPayload;
}

export function loadConfig(text: string): Config {
  return JSON5.parse(text) as Config;
}
