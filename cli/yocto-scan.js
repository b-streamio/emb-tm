/* Yocto image + CycloneDX SBOMs -> EMB3D Workbench project. Deterministic: rules in library/yocto-rules.json.
 *
 * Inputs (all optional, the more the better):
 *   variables   <image>.testdata.json (written to the deploy dir by every image build) or `bitbake -e <image>` output
 *   packages    <image>.manifest and/or CycloneDX SBOMs (JSON)
 *   rootfs      the image's rootfs tarball (.tar, .tar.gz/.bz2/.xz/.zst, read with the system tar) or an unpacked directory
 *   configs     kernel .config, bootloader (U-Boot / barebox) .config
 *
 * Conditions are three-valued: true, false, or null when the input they need was not given.
 * A null never picks an answer; the answer falls through and is flagged for review, naming the missing input.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

/* ---------- inputs ---------- */

function parseBbenv(file) {
  const vars = new Map();
  let origins = [];
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  for (const line of lines) {
    const o = line.match(/^#\s{2,}\S.*?\s(\/\S+):(\d+)\s*$/);
    if (o) { origins.push({ file: o[1], line: Number(o[2]) }); continue; }
    const m = line.match(/^(?:export )?([A-Za-z0-9_][A-Za-z0-9_\-:/.+~${}]*)="(.*)"$/);
    if (m) {
      vars.set(m[1], { value: m[2].replace(/\\"/g, '"').replace(/\\\$/g, '$'), file, origins });
      origins = [];
    } else if (line === '#' || /^\w+\s*\(\)/.test(line)) {
      if (line !== '#') origins = [];
    }
  }
  return vars;
}

function parseTestdata(file) {
  const vars = new Map();
  const d = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const [k, v] of Object.entries(d)) {
    if (v === null || typeof v === 'object') continue;
    vars.set(k, { value: String(v), file, origins: [] });
  }
  return vars;
}

function parseManifest(file, pkgs) {
  fs.readFileSync(file, 'utf8').split('\n').forEach((l) => {
    const [name, , version] = l.trim().split(/\s+/);
    if (!name) return;
    const p = pkgs.get(name) || { name, version: '', sources: [], cves: [] };
    p.version = p.version || version || '';
    p.sources.push(path.basename(file));
    pkgs.set(name, p);
  });
}

const CLOSED_VEX = new Set(['resolved', 'resolved_with_pedigree', 'not_affected', 'false_positive']);

function parseCycloneDx(file, pkgs) {
  const bom = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (bom.bomFormat !== 'CycloneDX') throw new Error(`${file}: not a CycloneDX BOM (bomFormat is ${bom.bomFormat})`);
  const byRef = new Map();
  let count = 0;
  const walk = (list) => (list || []).forEach((c) => {
    count++;
    if (c.name) {
      const p = pkgs.get(c.name) || { name: c.name, version: '', sources: [], cves: [] };
      p.version = p.version || c.version || '';
      p.purl = p.purl || c.purl;
      p.sources.push(path.basename(file));
      pkgs.set(c.name, p);
      if (c['bom-ref']) byRef.set(c['bom-ref'], p);
    }
    walk(c.components);
  });
  walk(bom.components);
  let open = 0;
  (bom.vulnerabilities || []).forEach((v) => {
    const state = v.analysis && v.analysis.state;
    const isOpen = !CLOSED_VEX.has(state);
    (v.affects || []).forEach((a) => {
      const p = byRef.get(a.ref);
      if (p && !p.cves.some((x) => x.id === v.id)) { p.cves.push({ id: v.id, open: isOpen, state: state || 'unanalysed' }); if (isOpen) open++; }
    });
  });
  const meta = bom.metadata && bom.metadata.component;
  return { file: path.basename(file), components: count, vulnerabilities: (bom.vulnerabilities || []).length, open, subject: meta ? `${meta.name}${meta.version ? ' ' + meta.version : ''}` : '' };
}

function parseConfig(file) {
  const m = new Map();
  fs.readFileSync(file, 'utf8').split('\n').forEach((l, i) => {
    let x = l.match(/^(CONFIG_[A-Za-z0-9_]+)=(.*)$/);
    if (x) { m.set(x[1], { value: x[2].replace(/^"(.*)"$/, '$1'), line: i + 1, text: l }); return; }
    x = l.match(/^# (CONFIG_[A-Za-z0-9_]+) is not set/);
    if (x) m.set(x[1], { value: 'n', line: i + 1, text: l });
  });
  return { file, map: m };
}

// Rootfs from a directory or a tarball (system tar handles gz/bz2/xz/zst).
function openRootfs(src) {
  if (fs.statSync(src).isDirectory()) {
    const list = [];
    const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).forEach((e) => {
      const p = path.join(d, e.name);
      list.push('/' + path.relative(src, p).split(path.sep).join('/'));
      if (e.isDirectory()) walk(p);
    });
    walk(src);
    return { label: src, list, read: (p) => { try { return fs.readFileSync(path.join(src, p), 'utf8'); } catch (_) { return null; } } };
  }
  const raw = execFileSync('tar', ['-tf', src], { maxBuffer: 1 << 28 }).toString().split('\n').filter(Boolean);
  const map = new Map(raw.map((r) => ['/' + r.replace(/^\.?\//, '').replace(/\/$/, ''), r]));
  const cache = new Map();
  return {
    label: path.basename(src), list: [...map.keys()],
    read: (p) => {
      if (!map.has(p)) return null;
      if (!cache.has(p)) {
        try { cache.set(p, execFileSync('tar', ['-xOf', src, map.get(p)], { maxBuffer: 1 << 26 }).toString()); } catch (_) { cache.set(p, null); }
      }
      return cache.get(p);
    },
  };
}

/* ---------- condition evaluation ---------- */

const globRe = (g) => new RegExp('^' + g.split('*').map((s) => s.replace(/[.+?^${}()[\]\\]/g, '\\$&')).join('[^/]*') + '$');
const short = (s, n = 160) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

function makeEvaluator(inp) {
  const varEv = (name, v) => {
    const o = v.origins && v.origins.length ? v.origins[v.origins.length - 1] : null;
    return o ? { file: o.file, line: o.line, text: short(`${name} = "${v.value}"`) } : { file: path.basename(v.file), text: short(`${name} = "${v.value}"`) };
  };

  function evalCond(c) {
    const R = (v, ev = [], miss = []) => ({ v, ev, miss });
    if (c.always) return R(true);
    if (c.any || c.all) {
      const parts = (c.any || c.all).map(evalCond);
      const miss = parts.flatMap((p) => p.miss);
      if (c.any) {
        const t = parts.filter((p) => p.v === true);
        if (t.length) return R(true, t.flatMap((p) => p.ev));
        return R(parts.some((p) => p.v === null) ? null : false, [], miss);
      }
      if (parts.some((p) => p.v === false)) return R(false);
      if (parts.some((p) => p.v === null)) return R(null, [], miss);
      return R(true, parts.flatMap((p) => p.ev));
    }
    if (c.not) { const r = evalCond(c.not); return R(r.v === null ? null : !r.v, [], r.miss); }
    if (c.var) {
      if (!inp.vars) return R(null, [], ['build variables (testdata.json or bitbake -e)']);
      const v = inp.vars.get(c.var);
      const val = v ? v.value : '';
      let ok;
      if (c.set !== undefined) ok = (val.trim() !== '') === c.set;
      else if (c.word !== undefined) ok = val.split(/\s+/).includes(c.word);
      else if (c.eq !== undefined) ok = val.trim() === c.eq;
      else if (c.re !== undefined) ok = new RegExp(c.re).test(val);
      return R(ok, ok && v ? [varEv(c.var, v)] : []);
    }
    if (c.pkg) {
      if (!inp.pkgs.size) return R(null, [], ['package list (manifest or SBOM)']);
      const re = new RegExp('^(' + c.pkg + ')$');
      const hit = [...inp.pkgs.values()].filter((p) => re.test(p.name));
      return R(hit.length > 0, hit.slice(0, 3).map((p) => ({ file: p.sources[0], text: `${p.name} ${p.version}`.trim() })));
    }
    if (c.kconfig || c.uboot) {
      const cfg = c.kconfig ? inp.kconfig : inp.uconfig;
      const name = c.kconfig || c.uboot;
      if (!cfg) return R(null, [], [c.kconfig ? 'kernel .config' : 'bootloader .config']);
      const e = cfg.map.get(name);
      const val = e ? e.value : 'n';
      const ok = c.eq !== undefined ? val === c.eq : new RegExp(c.re).test(val);
      return R(ok, ok && e ? [{ file: path.basename(cfg.file), line: e.line, text: e.text }] : []);
    }
    if (c.file || c.exists) {
      if (!inp.rootfs) return R(null, [], ['rootfs']);
      const pats = (c.file || c.exists).split('|').map(globRe);
      const files = inp.rootfs.list.filter((p) => pats.some((re) => re.test(p)));
      if (c.exists) return R(files.length > 0, files.slice(0, 2).map((f) => ({ file: 'rootfs:' + f, text: 'present' })));
      const re = new RegExp(c.re, 'm');
      for (const f of files) {
        const txt = inp.rootfs.read(f);
        if (txt === null) continue;
        const m = re.exec(txt);
        if (m) {
          const line = txt.slice(0, m.index).split('\n').length;
          return R(true, [{ file: 'rootfs:' + f, line, text: short(txt.split('\n')[line - 1].trim()) }]);
        }
      }
      return R(false);
    }
    throw new Error('Unknown rule condition: ' + JSON.stringify(c));
  }
  return evalCond;
}

/* ---------- scan ---------- */

function scan(inputs, rules, library) {
  const inp = { vars: null, pkgs: new Map(), kconfig: null, uconfig: null, rootfs: null };
  const used = [];
  const sboms = [];
  if (inputs.testdata) { inp.vars = parseTestdata(inputs.testdata); used.push(path.basename(inputs.testdata)); }
  if (inputs.bbenv) {
    const b = parseBbenv(inputs.bbenv);
    inp.vars = inp.vars || new Map();
    b.forEach((v, k) => inp.vars.set(k, v)); // bitbake -e wins: it carries file:line origins
    used.push(path.basename(inputs.bbenv));
  }
  if (inputs.manifest) { parseManifest(inputs.manifest, inp.pkgs); used.push(path.basename(inputs.manifest)); }
  (inputs.sboms || []).forEach((f) => { sboms.push(parseCycloneDx(f, inp.pkgs)); used.push(path.basename(f)); });
  if (inputs.kernelConfig) { inp.kconfig = parseConfig(inputs.kernelConfig); used.push(path.basename(inputs.kernelConfig)); }
  if (inputs.ubootConfig) { inp.uconfig = parseConfig(inputs.ubootConfig); used.push(path.basename(inputs.ubootConfig)); }
  if (inputs.rootfs) { inp.rootfs = openRootfs(inputs.rootfs); used.push(inp.rootfs.label); }

  const evalCond = makeEvaluator(inp);
  const TYPES = Object.fromEntries(library.components.map((c) => [c.type, c]));
  const getVar = (n) => (inp.vars && inp.vars.get(n) ? inp.vars.get(n).value : '');
  const fill = (tpl) => tpl.replace(/\$\{([^}]+)\}/g, (_, alts) => alts.split('|').map(getVar).find((x) => x) || '').replace(/\s+/g, ' ').trim();

  const nodes = [], byRule = {}, skipped = [];
  for (const rule of rules.components) {
    const def = TYPES[rule.type];
    if (!def) throw new Error(`rule ${rule.id}: unknown component type ${rule.type}`);
    const w = evalCond(rule.when);
    if (w.v !== true) {
      if (w.v === null) skipped.push(`${rule.name.replace(/\$\{[^}]+\}\s*/g, '')}: not checked, needs ${[...new Set(w.miss)].join(', ')}`);
      continue;
    }
    let name = fill(rule.name) || def.name;
    const evidence = { _component: w.ev.slice(0, 3) };
    const review = {};
    if (rule.version) {
      const re = new RegExp('^(' + rule.version + ')$');
      const hits = [...inp.pkgs.values()].filter((x) => re.test(x.name));
      const withVer = hits.find((x) => x.version);
      if (withVer) name += ` ${withVer.version.replace(/-r\d+$/, '')}`;
      // SBOMs name recipes (openssh), manifests name packages (openssh-sshd): gather CVEs from every match.
      hits.filter((x) => x.cves.length).forEach((p) => {
        const open = p.cves.filter((c) => c.open);
        evidence._component.push({ file: p.sources.find((s) => !/manifest$/.test(s)) || p.sources[0], text: `${p.name} ${p.version}: ${open.length} open of ${p.cves.length} CVEs in SBOM${open.length ? ' (' + open.slice(0, 6).map((c) => c.id).join(', ') + (open.length > 6 ? ', …' : '') + ')' : ''}` });
      });
    }
    if (rule.review) review._component = rule.review;
    const answers = {};
    for (const q of def.questions) {
      const list = (rule.answers && rule.answers[q.id]) || [];
      const missing = new Set();
      let chosen = null;
      for (const r of list) {
        if (!r.if) { chosen = { r, ev: [] }; break; }
        const res = evalCond(r.if);
        if (res.v === true) { chosen = { r, ev: res.ev }; break; }
        if (res.v === null) res.miss.forEach((m) => missing.add(m));
      }
      if (!chosen) {
        answers[q.id] = q.default;
        review[q.id] = 'no scanner rule for this question';
        continue;
      }
      answers[q.id] = chosen.r.value;
      if (chosen.ev.length) evidence[q.id] = chosen.ev;
      const notes = [];
      if (chosen.r.review) notes.push(chosen.r.review);
      if (missing.size) notes.push('not checked, needs ' + [...missing].join(', '));
      if (notes.length) review[q.id] = notes.join('; ');
    }
    if (!evidence._component.length) delete evidence._component;
    const node = { id: nodes.length + 1, type: rule.type, name, answers, evidence };
    if (Object.keys(review).length) node.review = review;
    nodes.push(node);
    byRule[rule.id] = node;
  }

  const flows = [];
  for (const f of rules.flows || []) {
    const a = byRule[f.from], b = byRule[f.to];
    if (!a || !b) continue;
    let enc = f.encrypted;
    if (typeof enc === 'string') { const [rid, qid] = enc.replace(/^answer:/, '').split('.'); enc = !!(byRule[rid] && byRule[rid].answers[qid]); }
    flows.push({ from: a.id, to: b.id, label: f.label, encrypted: !!enc, sensitive: !!f.sensitive });
  }

  const image = getVar('IMAGE_BASENAME') || getVar('PN') || inputs.image || (sboms.find((s) => s.subject) || {}).subject || 'Yocto image';
  const machine = getVar('MACHINE');
  const distro = [getVar('DISTRO'), getVar('DISTRO_VERSION')].filter(Boolean).join(' ');
  const cveOpen = sboms.reduce((a, s) => a + s.open, 0);
  const desc = [
    `${image}${machine ? ' for ' + machine : ''}${distro ? ', ' + distro : ''}.`,
    `Generated by emb3d-wb scan from: ${used.join(', ') || 'nothing'}.`,
    sboms.length ? `SBOMs: ${sboms.map((s) => `${s.file} (${s.components} components, ${s.vulnerabilities} vulnerabilities, ${s.open} open)`).join('; ')}.` : '',
    'Product applications and data flows beyond the defaults are not detected; add them in the Workbench.',
  ].filter(Boolean).join(' ');

  return {
    project: {
      name: `${image}${machine ? ' (' + machine + ')' : ''}`,
      generator: { tool: 'emb3d-wb scan', source: image, revision: getVar('BUILDNAME') || getVar('DATETIME') || '', date: new Date().toISOString().slice(0, 10) },
      meta: { description: desc, owner: '', reviewer: '' },
      nodes, flows,
    },
    notes: { used, skipped, sboms, packages: inp.pkgs.size, variables: inp.vars ? inp.vars.size : 0, cveOpen },
  };
}

// Find the inputs of one image in a Yocto deploy directory (tmp/deploy/images/<machine>).
function fromDeployDir(dir, image) {
  const files = fs.readdirSync(dir).filter((f) => fs.statSync(path.join(dir, f)).isFile() || fs.lstatSync(path.join(dir, f)).isSymbolicLink());
  const manifests = files.filter((f) => /\.manifest$/.test(f) && !/\.spdx|\.sdk/.test(f));
  const images = [...new Set(manifests.map((f) => f.replace(/(\.rootfs)?\.manifest$/, '').replace(/-\d{14}$/, '')))];
  if (!image) {
    if (images.length > 1) throw new Error(`Several images in ${dir}: ${images.join(', ')}. Pick one with --image.`);
    image = images[0];
  }
  const pick = (re) => {
    const c = files.filter((f) => re.test(f) && (!image || f.startsWith(image)));
    // prefer the stable symlink name (no timestamp)
    return c.sort((a, b) => (/-\d{14}/.test(a) ? 1 : 0) - (/-\d{14}/.test(b) ? 1 : 0))[0];
  };
  const p = (f) => (f ? path.join(dir, f) : undefined);
  return {
    image,
    manifest: p(pick(/\.manifest$/)),
    testdata: p(pick(/\.testdata\.json$/)),
    rootfs: p(pick(/\.tar(\.(gz|bz2|xz|zst))?$/)),
    sboms: files.filter((f) => /(\.cdx\.json|cyclonedx.*\.json|\.bom\.json)$/i.test(f) && (!image || f.startsWith(image) || !/^[\w.-]+-\w+\.rootfs/.test(f))).map((f) => path.join(dir, f)),
  };
}

module.exports = { scan, fromDeployDir, parseBbenv, parseCycloneDx };
