#!/usr/bin/env node
/* EMB3D Workbench command line. Same engine as the browser app; Node 18+, no dependencies.
 *
 *   emb3d-wb library [--json]                 component types and their questions (what a project can answer)
 *   emb3d-wb versions                         EMB3D versions available in data/stix
 *   emb3d-wb validate <project.json>          check a project; exit 1 on errors
 *   emb3d-wb scan [inputs] -o <project.json> [analyze options]
 *                          first model of a Yocto image, from its build outputs and CycloneDX SBOMs
 *       --deploy <dir>         deploy dir (tmp/deploy/images/<machine>): finds manifest, testdata.json, rootfs, SBOMs
 *       --image <name>         which image in the deploy dir, when there are several
 *       --testdata <file>      <image>.testdata.json            --bbenv <file>     `bitbake -e <image>` output
 *       --manifest <file>      <image>.manifest                 --rootfs <tar|dir> image rootfs
 *       --sbom <file>          CycloneDX JSON, repeatable       --kernel-config <file>  --uboot-config <file>
 *       --rules <file>         scanner rules (default library/yocto-rules.json)
 *   emb3d-wb analyze  <project.json> [options]
 *       --emb3d <ver>          EMB3D version (default: the project's, else data/stix default)
 *       --tmbom <file>         write the TM-BOM (OWASP Threat Model Library schema v1.0.2)
 *       --report <file.html>   write a standalone HTML report
 *       --pdf <file.pdf>       also print the report to PDF with a local Chrome/Chromium
 *       --summary <file.json>  write counts as JSON
 *       --project <file>       write the normalised project (positions filled in) for the browser app
 *       --list                 print every threat per component
 *       --fulltext             full MITRE threat descriptions in the report
 *       --fail-on-open <n>     exit 2 when more than n threats are open (CI gate)
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const STIX = require(path.join(ROOT, 'stix.js'));
const ENGINE = require(path.join(ROOT, 'engine.js'));

const readJson = (f) => JSON.parse(fs.readFileSync(f, 'utf8'));
const die = (msg, code = 1) => { process.stderr.write(msg + '\n'); process.exit(code); };

function args(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--') || a === '-o') {
      const k = a === '-o' ? 'o' : a.slice(2);
      const v = argv[i + 1];
      let val = true;
      if (v !== undefined && !v.startsWith('--')) { val = v; i++; }
      if (k in out) out[k] = [].concat(out[k], val); else out[k] = val;
    } else out._.push(a);
  }
  return out;
}

const library = () => readJson(path.join(ROOT, 'library', 'components.json'));
const index = () => readJson(path.join(ROOT, 'data', 'stix', 'index.json'));

function loadEmb3d(version) {
  const idx = index();
  const v = version || idx.default;
  const meta = idx.versions.find((x) => x.version === v);
  if (!meta) die(`EMB3D ${v} is not in data/stix. Available: ${idx.versions.map((x) => x.version).join(', ')}. Add it with tools/emb3d_update.py add ${v}`);
  return STIX.parse(readJson(path.join(ROOT, 'data', 'stix', meta.file)), v);
}

function loadProject(file) {
  let p = readJson(file);
  if (!Array.isArray(p.nodes) && !Array.isArray(p.pages) && p.extensions && p.extensions[ENGINE.EXT_KEY]) p = p.extensions[ENGINE.EXT_KEY].project;
  if (!p || (!Array.isArray(p.nodes) && !Array.isArray(p.pages))) die(`${file}: not an EMB3D Workbench project`);
  return p;
}

function cmdLibrary(a) {
  const lib = library();
  if (a.json) { process.stdout.write(JSON.stringify(lib, null, 2) + '\n'); return; }
  for (const g of lib.groups) {
    console.log(`\n## ${g}`);
    for (const c of lib.components.filter((x) => x.group === g)) {
      console.log(`\ntype: ${c.type}  (${c.name})${c.external ? '  external' : ''}${c.container ? '  container: fields page, qty' : ''}\n  ${c.hint}`);
      for (const q of c.questions) {
        if (q.kind === 'bool') console.log(`  - ${q.id}: true|false  default ${q.default}  — ${q.text}`);
        else console.log(`  - ${q.id}: ${q.options.map((o) => o.value).join('|')}  default ${q.default}  — ${q.text}\n${q.options.map((o) => `      ${o.value}: ${o.label}`).join('\n')}`);
      }
    }
  }
}

function cmdVersions() {
  const idx = index();
  idx.versions.forEach((v) => console.log(`${v.version}${v.version === idx.default ? '  (default)' : ''}  ${v.file}  added ${v.added}`));
}

function engineFor(p, a) {
  const version = a.emb3d || p.emb3d || index().default;
  const E = loadEmb3d(version);
  p.emb3d = version;
  return ENGINE.make(E, library());
}

function cmdValidate(a) {
  const file = a._[1] || die('usage: emb3d-wb validate <project.json>');
  const p = loadProject(file);
  const eng = engineFor(p, a);
  const { errors, warnings } = eng.validate(p);
  warnings.forEach((w) => console.log('warning: ' + w));
  errors.forEach((e) => console.log('error:   ' + e));
  const rv = (eng.normalize(p), eng.reviewItems(p));
  rv.forEach((r) => console.log(`review:  ${r.node.name}: ${r.question}${r.reason ? ' — ' + r.reason : ''}`));
  console.log(`${errors.length} errors, ${warnings.length} warnings, ${rv.length} answers to review`);
  process.exit(errors.length ? 1 : 0);
}

function standaloneHtml(p, eng, opts) {
  const index = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
  const m = index.match(/\/\* report-css:begin[^*]*\*\/([\s\S]*?)\/\* report-css:end \*\//);
  if (!m) die('index.html: report-css markers not found');
  const base = `
:root { --f-display: "IBM Plex Sans Condensed", "Arial Narrow", system-ui, sans-serif; --f-body: "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
  --f-mono: "IBM Plex Mono", ui-monospace, Menlo, monospace; --shadow: none; color-scheme: light; }
html, body { margin: 0; background: #fff; color: #1d2320; font-family: var(--f-body); font-size: 14px; line-height: 1.45; }
body { padding: 24px max(16px, env(safe-area-inset-left, 0px)); }
.small { font-size: 12.5px; } .muted { color: #5c6662; }`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat model - ${ENGINE.esc(p.name)}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans+Condensed:wght@500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap">
<style>${base}\n${m[1]}</style></head>
<body>${eng.reportHtml(p, opts)}</body></html>
`;
}

function findChrome() {
  const c = [process.env.CHROME, 'chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable', '/opt/pw-browsers/chromium',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'].filter(Boolean);
  for (const bin of c) {
    try { execFileSync(bin, ['--version'], { stdio: 'ignore' }); return bin; } catch (_) { /* try next */ }
  }
  return null;
}

function cmdAnalyze(a) {
  const file = a._[1] || die('usage: emb3d-wb analyze <project.json> [--tmbom f] [--report f.html] [--pdf f.pdf] [--summary f.json]');
  const p = loadProject(file);
  const eng = engineFor(p, a);
  const { errors } = eng.validate(p);
  if (errors.length) die('Project has errors; run "emb3d-wb validate":\n' + errors.join('\n'));
  eng.normalize(p);
  writeOutputs(p, eng, a);
}

function cmdScan(a) {
  const { scan, fromDeployDir } = require('./yocto-scan.js');
  const one = (k) => (Array.isArray(a[k]) ? a[k][a[k].length - 1] : a[k]);
  const out = one('o') || one('out') || die('usage: emb3d-wb scan --deploy <dir> [--sbom f ...] -o project.json [--tmbom f] [--report f.html]');
  let inputs = { sboms: [] };
  if (a.deploy) inputs = fromDeployDir(one('deploy'), one('image'));
  for (const [flag, key] of [['testdata', 'testdata'], ['bbenv', 'bbenv'], ['manifest', 'manifest'], ['rootfs', 'rootfs'], ['kernel-config', 'kernelConfig'], ['uboot-config', 'ubootConfig'], ['image', 'image']]) {
    if (a[flag]) inputs[key] = one(flag);
  }
  if (a.sbom) inputs.sboms = [...new Set([...(inputs.sboms || []), ...[].concat(a.sbom)])];
  if (!inputs.testdata && !inputs.bbenv && !inputs.manifest && !inputs.sboms.length && !inputs.rootfs) die('No inputs found. Give --deploy, or --testdata/--bbenv, --manifest, --sbom, --rootfs.');
  const rules = readJson(one('rules') || path.join(ROOT, 'library', 'yocto-rules.json'));
  let res;
  try { res = scan(inputs, rules, library()); } catch (e) { die('scan: ' + e.message); }
  const p = res.project;
  const eng = engineFor(p, a);
  const { errors } = eng.validate(p);
  if (errors.length) die('Scanner produced an invalid project (check the rules file):\n' + errors.join('\n'));
  eng.normalize(p);
  fs.writeFileSync(out, JSON.stringify(p, null, 2) + '\n');
  console.log(`Scanned ${inputs.image || p.name}: ${res.notes.variables} variables, ${res.notes.packages} packages, ${res.notes.sboms.length} SBOMs (${res.notes.cveOpen} open vulnerabilities)`);
  console.log(`  inputs: ${res.notes.used.join(', ')}`);
  res.notes.skipped.forEach((x) => console.log('  ' + x));
  console.log(`wrote ${out}`);
  writeOutputs(p, eng, a);
}

function writeOutputs(p, eng, a) {
  const s = eng.summary(p);

  if (a.tmbom) fs.writeFileSync(a.tmbom, JSON.stringify(eng.toTmbom(p), null, 2) + '\n');
  if (a.project) fs.writeFileSync(a.project, JSON.stringify(p, null, 2) + '\n');
  if (a.summary) fs.writeFileSync(a.summary, JSON.stringify(s, null, 2) + '\n');
  const opts = { fulltext: !!a.fulltext };
  let html = null;
  if (a.report || a.pdf) html = standaloneHtml(p, eng, opts);
  if (a.report) fs.writeFileSync(a.report, html);
  if (a.pdf) {
    const chrome = findChrome();
    if (!chrome) die('No Chrome/Chromium found for --pdf. Set CHROME=/path/to/chrome, or open the HTML report and print it.');
    const tmp = a.report ? path.resolve(a.report) : path.join(require('os').tmpdir(), `emb3d-report-${process.pid}.html`);
    if (!a.report) fs.writeFileSync(tmp, html);
    execFileSync(chrome, ['--headless', '--disable-gpu', '--no-sandbox', '--no-pdf-header-footer', `--print-to-pdf=${path.resolve(a.pdf)}`, 'file://' + tmp], { stdio: 'ignore' });
    if (!a.report) fs.unlinkSync(tmp);
  }

  console.log(`${p.name} — MITRE EMB3D ${s.emb3d}`);
  console.log(`  ${s.pages > 1 ? `devices ${s.devices}, pages ${s.pages}, ` : ''}components ${s.components}, data flows ${s.flows}`);
  console.log(`  threats ${s.threats}: open ${s.open}, mitigated ${s.mitigated}, not applicable ${s.notApplicable}, accepted ${s.accepted}`);
  console.log(`  open by evidence: observed in attacks ${s.openByEvidence.observedInAttacks}, observed technique ${s.openByEvidence.observedTechnique}, known weakness ${s.openByEvidence.knownWeakness}, proof of concept ${s.openByEvidence.proofOfConcept}`);
  console.log(`  countermeasures implemented ${s.implemented} of ${s.countermeasures}`);
  if (s.missingJustifications) console.log(`  decisions missing a justification: ${s.missingJustifications}`);
  if (s.needsReview) {
    console.log(`  answers needing review: ${s.needsReview}`);
    eng.reviewItems(p).forEach((r) => console.log(`    - ${eng.pagesOf(p).length > 1 && r.page ? r.page.name + ' > ' : ''}${r.node.name}: ${r.question}${r.reason ? ' — ' + r.reason : ''}`));
  }
  if (a.list) {
    eng.allNodes(p).filter((n) => eng.hasThreats(n)).forEach((n) => {
      const pg = eng.pageOf(n.id);
      console.log(`\n${eng.pagesOf(p).length > 1 && pg ? pg.name + ' > ' : ''}${n.name} (${eng.TYPES[n.type].name})`);
      eng.nodeThreats(p, n).forEach((r) => console.log(`  ${r.tid}  ${eng.threatState(n, r.tid).padEnd(9)} ${r.t.name}  [via ${r.via.join(', ')}]`));
    });
  }
  ['tmbom', 'report', 'pdf', 'summary', 'project'].filter((k) => a[k]).forEach((k) => console.log(`wrote ${a[k]}`));
  const limit = a['fail-on-open'];
  if (limit !== undefined && s.open > Number(limit)) process.exit(2);
}

const a = args(process.argv.slice(2));
const cmd = a._[0];
({ library: cmdLibrary, versions: cmdVersions, validate: cmdValidate, analyze: cmdAnalyze, scan: cmdScan }[cmd] || (() => {
  const src = fs.readFileSync(__filename, 'utf8');
  process.stdout.write(src.slice(src.indexOf('/*') + 3, src.indexOf('*/')).replace(/^ \* ?/gm, '') + '\n');
  process.exit(cmd ? 1 : 0);
}))(a);
