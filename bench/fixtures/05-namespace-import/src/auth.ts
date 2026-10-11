import * as jwt from 'jsonwebtoken';

export interface Claims {
  sub: string;
}

export function readToken(token: string, secret: string): Claims {
  return jwt.verify(token, secret) as Claims;
}
