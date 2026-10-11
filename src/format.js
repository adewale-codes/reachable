// Terminal and JSON rendering of a scan report.

const GROUPS = [
  ['reachable', 'REACHABLE'],
  ['cant_tell', "CAN'T TELL"],
  ['unreachable', 'UNREACHABLE'],
];

function palette(color) {
  const wrap = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return { red: wrap('31'), green: wrap('32'), yellow: wrap('33'), bold: wrap('1'), dim: wrap('2'), redBold: wrap('1;31') };
}

function where(l) {
  return `${l.file}${l.line ? `:${l.line}` : ''}`;
}

function pad(s, n) {
  return s.length >= n ? s + ' ' : s + ' '.repeat(n - s.length);
}

function osvSource(osv) {
  if (osv.mode === 'offline') return 'local cache (--offline)';
  if (osv.networkError) return `local cache (OSV unreachable: ${osv.networkError})`;
  return 'api.osv.dev';
}

export function formatText(report, { color = false, verbose = false } = {}) {
  const c = palette(color);
  const out = [];
  const p = (s = '') => out.push(s);

  p(`${c.bold(`reachable ${report.tool.version}`)}  ${report.project.name}  ${c.dim(report.project.path)}`);
  p(c.dim(`  ${report.source.filesScanned} source files · ${report.inventory.direct} direct / ${report.inventory.transitive} transitive packages · advisories from ${osvSource(report.osv)}`));
  p();

  const incompleteBanner = () => {
    p(c.redBold('SCAN INCOMPLETE: part of the scan did not run. Do not treat this report as clean.'));
    for (const e of report.errors.slice(0, 15)) p(c.red(`  - [${e.code}] ${e.message}`));
    if (report.errors.length > 15) p(c.red(`  - ... and ${report.errors.length - 15} more`));
    p();
  };
  if (!report.complete) incompleteBanner();

  const s = report.summary;
  if (s.alerts === 0) {
    p(report.complete ? 'No known advisories affect the installed packages.' : 'No advisories found, but the scan was incomplete (see above).');
  } else {
    p(`${c.bold(`${s.alerts} advisory alerts`)}: ${c.red(`${s.reachable} reachable`)} · ${c.green(`${s.unreachable} unreachable`)} · ${c.yellow(`${s.cant_tell} can't tell`)}`);
  }

  for (const [verdict, title] of GROUPS) {
    const items = report.results.filter((r) => r.verdict === verdict);
    if (!items.length) continue;
    const tint = verdict === 'reachable' ? c.red : verdict === 'unreachable' ? c.green : c.yellow;
    p();
    p(tint(c.bold(`${title} (${items.length})`)));
    for (const r of items) {
      const kind = r.direct ? (r.dev ? 'direct, dev' : 'direct') : 'transitive';
      p(`  ${c.bold(r.id)}  ${r.package}@${r.version}  ${c.dim(`(${kind})`)}  ${r.summary}`);
      if (verdict === 'reachable') {
        p(`    affected: ${r.affectedSymbols.join(', ')}`);
        for (const ev of r.evidence.references.slice(0, verbose ? 20 : 3)) {
          const [first, ...rest] = ev.chain;
          p(`    ${c.dim(pad(where(first), 28))}${first.text}`);
          for (const step of rest) p(`      → ${c.dim(pad(where(step), 26))}${step.text}`);
        }
        const more = r.evidence.referenceCount - (verbose ? 20 : 3);
        if (more > 0) p(c.dim(`    (+${more} more reference${more === 1 ? '' : 's'}; use --json for all)`));
      } else if (verdict === 'unreachable') {
        const e = r.evidence;
        p(`    affected: ${e.symbols.join(', ')}; none referenced. ${e.usesChecked} use${e.usesChecked === 1 ? '' : 's'} of ${r.installName} checked from ${e.importCount} import site${e.importCount === 1 ? '' : 's'}:`);
        p(c.dim(`    ${e.importSites.slice(0, 5).map(where).join(', ')}${e.importCount > 5 ? ', ...' : ''}`));
      } else {
        const [primary, ...others] = r.reasons;
        p(`    ${c.yellow(primary.code)}: ${primary.message}`);
        for (const l of primary.locations.slice(0, verbose ? 10 : 3)) {
          p(`      ${c.dim(pad(where(l), 26))}${l.text || ''}${l.detail ? c.dim(`  [${l.detail}]`) : ''}`);
        }
        if (primary.count > (verbose ? 10 : 3)) p(c.dim(`      (+${primary.count - (verbose ? 10 : 3)} more)`));
        if (others.length) p(c.dim(`    also: ${others.map((o) => o.code).join(', ')}`));
      }
    }
  }

  if (report.withdrawn.length) {
    p();
    p(c.dim(`Withdrawn advisories ignored: ${report.withdrawn.map((w) => `${w.id} (${w.package}@${w.version})`).join(', ')}`));
  }
  if (report.warnings.length) {
    p();
    p(c.yellow('Warnings:'));
    for (const w of report.warnings) p(c.yellow(`  - ${w}`));
  }
  if (!report.complete) {
    p();
    incompleteBanner();
  }
  return out.join('\n') + '\n';
}

export function formatJson(report) {
  return JSON.stringify(report, null, 2) + '\n';
}
