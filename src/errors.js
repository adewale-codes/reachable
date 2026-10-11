// A ScanError means the scan could not complete. The CLI prints it loudly and
// exits with code 2; it never prints a clean report after one.
export class ScanError extends Error {
  constructor(message, code = 'scan_failed') {
    super(message);
    this.name = 'ScanError';
    this.code = code;
  }
}
