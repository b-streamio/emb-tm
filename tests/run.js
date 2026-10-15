#!/usr/bin/env node
/* Tests for the scanner and the engine. Run: node tests/run.js (Node 18+, no dependencies). */
'use strict';
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'cli', 'emb3d-wb.js');
const EX = path.join(ROOT, 'examples', 'yocto-scan');
const DEPLOY = path.join(EX, 'deploy');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'emb3d-wb-test-'));
const run = (...a) => execFileSync('node', [CLI, ...a], { encoding: 'utf8' });
const nodesOf = (p) => (p.pages ? p.pages.flatMap((g) => g.nodes) : p.nodes);
const node = (p, type, re) => nodesOf(p).find((n) => n.type === type && (!re || re.test(n.name)));
let passed = 0;
const test = (name, fn) => { fn(); passed++; console.log('ok  ' + name); };

if (!fs.existsSync(DEPLOY)) execFileSync('python3', [path.join(EX, 'make-fixture.py')]);

test('full deploy dir scan', () => {
  const out = path.join(tmp, 'full.json');
  run('scan', '--deploy', DEPLOY, '--kernel-config', path.join(DEPLOY, 'config-raspberrypi4-64'), '-o', out, '--tmbom', path.join(tmp, 'full.tmbom.json'));
  const p = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.strictEqual(p.name, 'core-image-gateway (raspberrypi4-64)');
  assert.strictEqual(node(p, 'bootloader').name, 'U-Boot 2024.01');
  assert.strictEqual(node(p, 'bootloader').answers.verify, 'signature');
  assert.ok(node(p, 'bootloader').evidence._component.some((e) => /CVE-2024-57256/.test(e.text)), 'u-boot SBOM CVE in evidence');
  assert.strictEqual(node(p, 'update').answers.integrity, 'signature');
  assert.strictEqual(node(p, 'update').answers.remote, true);
  assert.strictEqual(node(p, 'ui', /SSH/).answers.auth, 'crypto');
  assert.deepStrictEqual(node(p, 'ui', /SSH/).evidence.auth[0], { file: 'rootfs:/etc/ssh/sshd_config', line: 3, text: 'PasswordAuthentication no' });
  const mq = node(p, 'netsvc', /Mosquitto/);
  assert.strictEqual(mq.answers.no_enc, false);
  assert.strictEqual(mq.answers.no_auth, false);
  const ssh = node(p, 'netsvc', /OpenSSH/);
  assert.ok(ssh.evidence._component.some((e) => /1 open of 2 CVEs.*CVE-2024-6387/.test(e.text)), 'VEX not_affected is not counted as open');
  assert.strictEqual(node(p, 'os').answers.modules, true);
  assert.ok(!node(p, 'rot'), 'no TPM in this image');
  assert.strictEqual(p.pages[0].flows.length, 3);
  const tm = JSON.parse(fs.readFileSync(path.join(tmp, 'full.tmbom.json'), 'utf8'));
  assert.ok(tm.threats.length > 50 && tm.controls.length > 100);
  assert.ok(nodesOf(tm.extensions['emb3d-workbench.invalid/project'].project).length === nodesOf(p).length, 'project embedded for re-import');
});

test('SBOM only: missing inputs become review flags, never guesses', () => {
  const out = path.join(tmp, 'sbom.json');
  run('scan', '--sbom', path.join(DEPLOY, 'core-image-gateway-raspberrypi4-64.rootfs.cdx.json'), '-o', out);
  const p = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.ok(!node(p, 'soc'), 'no MACHINE, no SoC node');
  const login = node(p, 'ui', /SSH/);
  assert.strictEqual(login.answers.auth, 'password');
  assert.match(login.review.auth, /not checked, needs .*rootfs/);
  assert.strictEqual(node(p, 'update').answers.integrity, 'signature');
  assert.match(node(p, 'update').review.integrity, /not checked, needs rootfs/);
});

test('bitbake -e parsing keeps file:line origins', () => {
  const { parseBbenv } = require(path.join(ROOT, 'cli', 'yocto-scan.js'));
  const v = parseBbenv(path.join(EX, 'bitbake-e.sample.txt'));
  assert.strictEqual(v.get('IMAGE_FEATURES').value, 'ssh-server-openssh debug-tweaks');
  assert.deepStrictEqual(v.get('IMAGE_FEATURES').origins.pop(), { file: '/work/build/conf/local.conf', line: 40 });
  assert.deepStrictEqual(v.get('UBOOT_SIGN_ENABLE').origins, [{ file: '/work/layers/meta-acme/conf/distro/acme.conf', line: 31 }]);
  assert.strictEqual(v.get('PATH').value, '/usr/bin:/bin');
});

test('bitbake -e overrides testdata and drives answers', () => {
  const out = path.join(tmp, 'bbenv.json');
  run('scan', '--deploy', DEPLOY, '--bbenv', path.join(EX, 'bitbake-e.sample.txt'), '-o', out);
  const p = JSON.parse(fs.readFileSync(out, 'utf8'));
  assert.strictEqual(node(p, 'ui', /SSH/).answers.auth, 'none', 'debug-tweaks means no root password');
  assert.deepStrictEqual(node(p, 'debug').evidence.sw_debug[0], { file: '/work/build/conf/local.conf', line: 40, text: 'IMAGE_FEATURES = "ssh-server-openssh debug-tweaks"' });
});

test('analyze accepts its own TM-BOM back', () => {
  const s = run('analyze', path.join(tmp, 'full.tmbom.json'), '--summary', path.join(tmp, 'sum.json'));
  assert.match(s, /core-image-gateway/);
  assert.ok(JSON.parse(fs.readFileSync(path.join(tmp, 'sum.json'), 'utf8')).threats > 50);
});

test('system example: devices, shared pages, quantities, custom blocks', () => {
  const ENGINE = require(path.join(ROOT, 'engine.js'));
  const STIX = require(path.join(ROOT, 'stix.js'));
  const idx = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'stix', 'index.json'), 'utf8'));
  const E = STIX.parse(JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'stix', idx.versions.find((v) => v.version === idx.default).file), 'utf8')), idx.default);
  const lib = JSON.parse(fs.readFileSync(path.join(ROOT, 'library', 'components.json'), 'utf8'));
  const p = JSON.parse(fs.readFileSync(path.join(EX, '..', 'system', 'connected-vision-system.project.json'), 'utf8'));
  const eng = ENGINE.make(E, lib);
  eng.bind(p);
  assert.deepStrictEqual(eng.validate(p).errors, []);
  eng.normalize(p);
  const cams = eng.allNodes(p).find((n) => ENGINE.isDevice(n) && /camera/i.test(n.name));
  assert.strictEqual(cams.qty, 4);
  const rows = eng.allRows(p);
  assert.ok(rows.some((r) => r.tid.startsWith('CUS-')), 'custom threats are part of the model');
  const tm = eng.toTmbom(p);
  const sensor = tm.components.find((c) => /image sensor/i.test(c.title));
  assert.ok(sensor && sensor.parent_component, 'components point at their device');
  assert.ok(tm.threats.some((t) => /^CUS-/.test(t.title)), 'custom threats exported');
  const back = JSON.parse(JSON.stringify(tm)).extensions['emb3d-workbench.invalid/project'].project;
  assert.strictEqual(back.pages.length, p.pages.length, 'pages survive the TM-BOM round trip');
});

test('old single-page projects still open', () => {
  const out = path.join(tmp, 'legacy.json');
  const old = JSON.parse(fs.readFileSync(path.join(tmp, 'full.json'), 'utf8'));
  const legacy = { name: old.name, nodes: (old.pages ? old.pages[0].nodes : old.nodes), flows: (old.pages ? old.pages[0].flows : old.flows) };
  fs.writeFileSync(out, JSON.stringify(legacy));
  const s = run('analyze', out, '--project', path.join(tmp, 'migrated.json'));
  assert.match(s, /core-image-gateway/);
  const m = JSON.parse(fs.readFileSync(path.join(tmp, 'migrated.json'), 'utf8'));
  assert.ok(Array.isArray(m.pages) && m.pages.length === 1 && m.root === m.pages[0].id);
});

console.log(`\n${passed} tests passed`);
