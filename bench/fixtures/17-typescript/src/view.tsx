import JSON5 from 'json5';
import type { Config } from './config';

export function ConfigView({ config }: { config: Config }) {
  return <pre>{JSON5.stringify(config, null, 2)}</pre>;
}
