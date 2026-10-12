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
  for (const n of report.notices || []) p(c.dim(`  note: ${n}`));
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
  if (report.prodOnly && report.hiddenDevAlerts) p(c.dim(`  --prod-only: ${report.hiddenDevAlerts} dev-only alert(s) hidden (they still exist; verdicts are unchanged)`));

  for (const [verdict, title] of GROUPS) {
    const items = report.results.filter((r) => r.verdict === verdict);
    if (!items.length) continue;
    const tint = verdict === 'reachable' ? c.red : verdict === 'unreachable' ? c.green : c.yellow;
    p();
    p(tint(c.bold(`${title} (${items.length})`)));
    for (const r of items) {
      const kind = `${r.direct ? 'direct' : 'transitive'}, ${r.scope}`;
      p(`  ${c.bold(r.id)}  ${r.package}@${r.version}  ${c.dim(`(${kind})`)}  ${r.summary}`);
      if (verdict === 'reachable') {
        p(`    affected: ${r.affectedSymbols.join(', ')}${r.symbolTier === 'llm' ? c.yellow(`  [source: llm, ${r.llm.model}]`) : ''}`);
        for (const ev of r.evidence.references.slice(0, verbose ? 20 : 3)) {
          if (ev.source === 'llm') p(c.dim(`    ${ev.symbol} — advisory says: "${ev.quote.replace(/s+/g, ' ').slice(0, 160)}"`));
          const [first, ...rest] = ev.chain;
          p(`    ${c.dim(pad(where(first), 28))}${first.text}`);
          for (const step of rest) p(`      → ${c.dim(pad(where(step), 26))}${step.text}`);
        }
        const more = r.evidence.referenceCount - (verbose ? 20 : 3);
        if (more > 0) p(c.dim(`    (+${more} more reference${more === 1 ? '' : 's'}; use --json for all)`));
      } else if (verdict === 'unreachable') {
        const e = r.evidence;
        if (e.importCount) {
          p(`    affected: ${e.symbols.join(', ')}; none referenced. ${e.usesChecked} use${e.usesChecked === 1 ? '' : 's'} of ${r.installName} checked from ${e.importCount} import site${e.importCount === 1 ? '' : 's'}:`);
        } else {
          p(`    affected: ${e.symbols.join(', ')}; none referenced. Not imported by the project; every installed package that loads it was checked:`);
        }
        if (e.importCount) p(c.dim(`    ${e.importSites.slice(0, 5).map(where).join(', ')}${e.importCount > 5 ? ', ...' : ''}`));
        for (const L of (e.loaders || []).slice(0, verbose ? 50 : 4)) p(c.dim(`    loader ${L.loader}${L.declared === false ? ' (undeclared)' : ''}: ${L.result}`));
        if ((e.loaders || []).length > (verbose ? 50 : 4)) p(c.dim(`    (+${e.loaders.length - (verbose ? 50 : 4)} more loaders)`));
        if (e.paths) p(c.dim(`    ${e.paths.total}${e.paths.complete ? '' : '+'} dependency path(s), e.g. ${e.paths.sample[0] ? e.paths.sample[0].join(' > ') : '-'}`));
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

// ---------------------------------------------------------------- markdown

const mdCell = (s) => String(s == null ? '' : s).replace(/\|/g, '\|').replace(/\r?\n/g, ' ').trim();
const mdCode = (s) => {
  const t = String(s == null ? '' : s).replace(/\r?\n/g, ' ').trim().slice(0, 100);
  // Pipes must be escaped even inside code spans, or they split the table cell.
  return t ? `\`${t.replace(/`/g, "'").replace(/\|/g, '\\|')}\`` : '';
};
const MD_ROWS = 30;

/**
 * Compact Markdown report for a pull-request comment or a job summary.
 * @param opts.title  heading text
 */
export function formatMarkdown(report, { title = 'reachable: dependency advisories your code can trigger' } = {}) {
  const out = [];
  const p = (s = '') => out.push(s);
  const s = report.summary;
  p(`### ${title}`);
  p();
  if (!report.complete) {
    p('> [!CAUTION]');
    p('> **Scan incomplete.** Part of the scan did not run, so this report is not clean:');
    for (const e of report.errors.slice(0, 10)) p(`> - \`${e.code}\` ${mdCell(e.message)}`);
    p();
  }
  p(`**${s.reachable} reachable** · **${s.unreachable} unreachable** · **${s.cant_tell} can't tell** · ${s.alerts} alerts in \`${mdCell(report.project.name)}\``);
  if (report.prodOnly && report.hiddenDevAlerts) p(`<sub>--prod-only: ${report.hiddenDevAlerts} dev-only alert(s) hidden.</sub>`);
  for (const n of report.notices || []) p(`<sub>${mdCell(n)}</sub>`);
  p();

  const reach = report.results.filter((r) => r.verdict === 'reachable');
  if (reach.length) {
    p('| Advisory | Package | Scope | Affected | Evidence |');
    p('|---|---|---|---|---|');
    for (const r of reach.slice(0, MD_ROWS)) {
      const ev = r.evidence.references[0];
      const last = ev.chain[ev.chain.length - 1];
      const src = r.symbolTier === 'llm' ? ' _(LLM-extracted)_' : '';
      const more = r.evidence.referenceCount > 1 ? ` (+${r.evidence.referenceCount - 1} more)` : '';
      p(`| [${r.id}](${r.url}) | \`${r.package}@${r.version}\`${r.direct ? '' : ' (transitive)'} | ${r.scope} | ${mdCell(r.affectedSymbols.join(', '))}${src} | \`${mdCell(where(last))}\` ${mdCode(last.text)}${more} |`);
    }
    if (reach.length > MD_ROWS) p(`\n_+${reach.length - MD_ROWS} more reachable alerts; see the JSON report._`);
    p();
  }

  const unreach = report.results.filter((r) => r.verdict === 'unreachable');
  if (unreach.length) {
    p(`<details><summary>Unreachable (${unreach.length}): proven not referenced</summary>`);
    p();
    for (const r of unreach.slice(0, MD_ROWS)) {
      const e = r.evidence;
      const how = [e.importCount ? `${e.usesChecked} uses checked from ${e.importCount} import site(s)` : null,
        (e.loaders || []).length ? `${e.loaders.length} loader package(s) checked` : null].filter(Boolean).join('; ');
      p(`- [${r.id}](${r.url}) \`${r.package}@${r.version}\` (${r.scope}): ${mdCell(e.symbols.join(', '))} not referenced${how ? `; ${how}` : ''}`);
    }
    if (unreach.length > MD_ROWS) p(`- _+${unreach.length - MD_ROWS} more_`);
    p();
    p('</details>');
    p();
  }

  const cant = report.results.filter((r) => r.verdict === 'cant_tell');
  if (cant.length) {
    const byReason = new Map();
    for (const r of cant) {
      if (!byReason.has(r.reason)) byReason.set(r.reason, []);
      byReason.get(r.reason).push(r);
    }
    p(`<details><summary>Can't tell (${cant.length}), by reason</summary>`);
    p();
    for (const [code, items] of [...byReason.entries()].sort((a, b) => b[1].length - a[1].length)) {
      p(`**\`${code}\`** (${items.length}): ${mdCell(items[0].reasons[0].message)}`);
      const pkgs = [...new Set(items.map((r) => `${r.package}@${r.version}`))];
      p(`<sub>${mdCell(pkgs.slice(0, 15).join(', '))}${pkgs.length > 15 ? `, +${pkgs.length - 15} more` : ''}</sub>`);
      p();
    }
    p('</details>');
    p();
  }

  p('---');
  p('<sub><b>reachable</b> means your code references a function the advisory names; it is not the same as exploitable. ' +
    '<b>unreachable</b> is only reported with proof; anything unproven is <b>can\'t tell</b>. ' +
    `Generated by reachable ${report.tool.version}.</sub>`);
  return out.join('\n') + '\n';
}
