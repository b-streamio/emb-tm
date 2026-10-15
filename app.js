/* EMB3D Workbench — embedded threat modeling on top of MITRE EMB3D.
 * Plain JS, no build step. Data: MITRE's STIX files in data/stix/ (see index.json), library/components.json (hand-maintained).
 * Rules: component answers -> EMB3D properties -> threats -> mitigations.
 */
(() => {
  'use strict';

  const STORE_KEY = 'emb3d-workbench/project';
  const TMBOM_SCHEMA = 'https://github.com/OWASP/www-project-threat-model-library/blob/v1.0.2/threat-model.schema.json';
  const EXT_KEY = 'emb3d-workbench.invalid/project';
  const NODE_W = 168;
  const NODE_H = 64;
  const MITRE_SITE = 'https://emb3d.mitre.org';

  const CM_STATUS = [
    ['recommended', 'Recommended'],
    ['required', 'Required'],
    ['implemented', 'Implemented'],
    ['rejected', 'Rejected'],
    ['na', 'Not applicable'],
  ];
  const CM_TO_TMBOM = { recommended: 'suggested', required: 'approved', implemented: 'active', rejected: 'wont_do', na: 'wont_do' };
  const MATURITY = {
    'observed adversarial behavior': [0, 'Observed in attacks'],
    'observed adversarial technique': [1, 'Observed technique'],
    'known exploitable weakness': [2, 'Known weakness'],
    'proof of concept': [3, 'Proof of concept'],
  };
  const MIT_RANK = { foundational: 0, intermediate: 1, leading: 2 };
  const ZONE = {
    Hardware: ['hardware', 'Hardware'],
    'System software': ['system-software', 'System software'],
    Application: ['application', 'Application'],
    Networking: ['networking', 'Networking'],
    External: ['external', 'External'],
  };

  let E = null;       // EMB3D data for the project's version
  let IDX = null;     // data/stix/index.json
  const STIX = new Map(); // version -> parsed data
  const SESSION_VERSIONS = []; // versions fetched from emb3d.mitre.org for this session only
  let LIB = null;     // component library
  let TYPES = {};     // type -> library entry
  let S = null;       // project state
  let sel = null;     // {kind:'node'|'flow', id}
  let connectFrom = null;
  let openThreat = null;
  let view = 'diagram';
  let filters = { tState: 'all', tComp: 'all', cStatus: 'all' };
  let reportOpts = { diagram: true, mitigated: true, closed: true, empty: false, props: true, fulltext: false };

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const slug = (s) => String(s).toLowerCase().replace(/[^0-9a-z-]+/g, '-').replace(/^-+|-+$/g, '');
  const groupClass = (g) => 'k-' + String(g).split(' ')[0];

  /* ---------- project state ---------- */

  function sampleProject() {
    const n = (id, type, name, x, y, answers = {}) => ({ id, type, name, x, y, answers, cm: {}, accepted: {}, why: {} });
    return {
      name: 'Example: industrial edge gateway',
      seq: 13,
      nodes: [
        n(1, 'soc', 'Arm SoC', 360, 80),
        n(2, 'dram', 'LPDDR4', 600, 60),
        n(3, 'storage', 'eMMC', 600, 190),
        n(4, 'debug', 'UART console', 120, 80),
        n(5, 'rot', 'TPM 2.0', 120, 230, { rot_kind: 'immutable' }),
        n(6, 'bootloader', 'U-Boot', 360, 300),
        n(7, 'os', 'Yocto Linux', 600, 340),
        n(8, 'update', 'OTA agent', 840, 340, { integrity: 'signature', plaintext: true, remote: true }),
        n(9, 'ui', 'Web admin', 600, 520),
        n(10, 'netsvc', 'MQTT telemetry', 840, 520),
        n(11, 'cloud', 'Fleet backend', 1100, 430),
        n(12, 'person', 'Field technician', 120, 520),
      ],
      flows: [
        { id: 1, from: 10, to: 11, label: 'telemetry (TLS)', encrypted: true, sensitive: true },
        { id: 2, from: 11, to: 8, label: 'firmware bundle', encrypted: true, sensitive: true },
        { id: 3, from: 12, to: 9, label: 'config (HTTPS)', encrypted: true, sensitive: true },
        { id: 4, from: 12, to: 4, label: 'serial console', encrypted: false, sensitive: true },
        { id: 5, from: 6, to: 7, label: 'boot handoff', encrypted: false, sensitive: false },
      ],
      flowSeq: 6,
      meta: { description: 'Example model: an Arm-based Linux gateway with a TPM, signed OTA updates, a web admin UI and MQTT telemetry to a fleet backend.', owner: '', reviewer: '' },
    };
  }

  function emptyProject() {
    return { name: 'Untitled device', seq: 1, nodes: [], flows: [], flowSeq: 1 };
  }

  function save() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(S)); } catch (_) { /* storage unavailable */ }
  }

  function load() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (raw) { const p = JSON.parse(raw); if (p && Array.isArray(p.nodes)) return p; }
    } catch (_) { /* ignore */ }
    return sampleProject();
  }

  const nodeById = (id) => S.nodes.find((n) => n.id === id);

  /* ---------- rules engine ---------- */

  function answer(node, q) {
    return node.answers && q.id in node.answers ? node.answers[q.id] : q.default;
  }

  // EMB3D properties of a component: base + questionnaire answers + parent closure + device-level rules.
  function nodePids(node) {
    const def = TYPES[node.type];
    const out = new Map(); // pid -> 'base' | 'answer' | 'parent' | 'rule'
    if (!def) return out;
    def.base.forEach((p) => out.set(p, 'base'));
    def.questions.forEach((q) => {
      const a = answer(node, q);
      if (q.kind === 'bool' && a) q.pids.forEach((p) => out.has(p) || out.set(p, 'answer'));
      if (q.kind === 'choice') {
        const opt = q.options.find((o) => o.value === a);
        if (opt) opt.pids.forEach((p) => out.has(p) || out.set(p, 'answer'));
      }
    });
    // Device-level rule: no update agent in the model -> the firmware cannot be updated (PID-26).
    if (!S.nodes.some((n) => n.type === 'update')) {
      const host = S.nodes.find((n) => n.type === 'os') || S.nodes.find((n) => n.type === 'soc');
      if (host && host.id === node.id) out.set('PID-26', 'rule');
    }
    // A sub-property implies its parent.
    for (const p of [...out.keys()]) {
      if (!E.properties[p]) { out.delete(p); continue; } // not defined in this EMB3D version
      let par = E.properties[p].parent;
      while (par) { if (!out.has(par)) out.set(par, 'parent'); par = E.properties[par].parent; }
    }
    return out;
  }

  function nodeThreats(node) {
    const pids = nodePids(node);
    const res = [];
    for (const [tid, t] of Object.entries(E.threats)) {
      const hit = t.pids.filter((p) => pids.has(p));
      if (hit.length) res.push({ tid, t, via: hit });
    }
    res.sort((a, b) => (MATURITY[a.t.maturity]?.[0] ?? 9) - (MATURITY[b.t.maturity]?.[0] ?? 9) || a.tid.localeCompare(b.tid));
    return res;
  }

  const cmStatus = (node, mid) => (node.cm && node.cm[mid]) || 'recommended';
  const NEEDS_WHY = ['na', 'rejected'];
  const why = (node, key) => ((node.why && node.why[key]) || '').trim();
  const missingWhy = (node, mid) => NEEDS_WHY.includes(cmStatus(node, mid)) && !why(node, mid);
  // Threat-level decision: '' (handle with countermeasures), 'na' or 'accept'. Older files stored true for accept.
  const decision = (node, tid) => { const v = node.accepted && node.accepted[tid]; return v === true ? 'accept' : (v || ''); };
  const missingAcceptWhy = (node, tid) => !!decision(node, tid) && !why(node, 'accept:' + tid);
  function whyBox(node, key, label) {
    const v = (node.why && node.why[key]) || '';
    const fid = `why-${node.id}-${key.replace(/[^\w-]/g, '_')}`;
    return `<div class="why${v.trim() ? '' : ' missing'}"><label for="${fid}">${label}</label>
      <textarea id="${fid}" data-why="${esc(key)}" rows="2" placeholder="For example: this product variant has no network interface">${esc(v)}</textarea></div>`;
  }

  function threatState(node, tid) {
    if (decision(node, tid) === 'accept') return 'Accepted';
    if (decision(node, tid) === 'na') return 'NA';
    const mids = E.threats[tid].mids;
    if (mids.some((m) => cmStatus(node, m) === 'implemented')) return 'Mitigated';
    if (mids.length && mids.every((m) => cmStatus(node, m) === 'na')) return 'NA';
    return 'Open';
  }
  const stateLabel = (s) => (s === 'NA' ? 'Not applicable' : s);

  function allRows() {
    const rows = [];
    S.nodes.forEach((node) => nodeThreats(node).forEach((r) => rows.push({ node, ...r, state: threatState(node, r.tid) })));
    return rows;
  }

  function cmRows() {
    const rows = [];
    S.nodes.forEach((node) => {
      const byMid = new Map();
      nodeThreats(node).forEach(({ tid, t }) => t.mids.forEach((m) => {
        if (!byMid.has(m)) byMid.set(m, []);
        byMid.get(m).push(tid);
      }));
      byMid.forEach((tids, mid) => rows.push({ node, mid, m: E.mitigations[mid], tids, status: cmStatus(node, mid) }));
    });
    rows.sort((a, b) => (MIT_RANK[a.m.maturity] ?? 9) - (MIT_RANK[b.m.maturity] ?? 9) || a.mid.localeCompare(b.mid) || a.node.id - b.node.id);
    return rows;
  }

  /* ---------- library rail ---------- */

  function renderRail() {
    const groups = LIB.groups.map((g) => {
      const items = LIB.components.filter((c) => c.group === g).map((c) => `
        <button class="libitem" draggable="true" data-type="${esc(c.type)}" title="${esc(c.hint)}">
          <span class="tag ${groupClass(c.group)}">${esc(c.tag)}</span><span class="libname">${esc(c.name)}</span>
        </button>`).join('');
      return `<div class="group"><p class="eyebrow">${esc(g)}</p><div class="lib">${items}</div></div>`;
    }).join('');
    $('rail').innerHTML = `<div class="groups">${groups}</div>
      <p class="note">Tap or drag a component onto the board. Each one asks a few questions; the answers decide which EMB3D threats apply.</p>`;
    $('rail').querySelectorAll('.libitem').forEach((b) => {
      b.addEventListener('click', () => addNode(b.dataset.type));
      b.addEventListener('dragstart', (e) => { e.dataTransfer.setData('text/x-emb3d', b.dataset.type); e.dataTransfer.effectAllowed = 'copy'; });
    });
  }

  function addNode(type, x, y) {
    const def = TYPES[type];
    if (!def) return;
    if (x === undefined) {
      const w = $('boardwrap');
      const k = S.nodes.length % 6;
      x = w.scrollLeft + Math.max(20, w.clientWidth / 2 - NODE_W / 2) + k * 18;
      y = w.scrollTop + Math.max(20, w.clientHeight / 2 - 40) + k * 18;
    }
    const answers = {};
    def.questions.forEach((q) => { answers[q.id] = q.default; });
    const node = { id: S.seq++, type, name: def.name, x: Math.round(x), y: Math.round(y), answers, cm: {}, accepted: {}, why: {} };
    S.nodes.push(node);
    sel = { kind: 'node', id: node.id };
    openThreat = null;
    commit();
  }

  /* ---------- board ---------- */

  function renderBoard() {
    const board = $('board');
    board.querySelectorAll('.node').forEach((el) => el.remove());
    S.nodes.forEach((node) => {
      const def = TYPES[node.type] || { group: 'External', tag: '?', name: node.type };
      const el = document.createElement('div');
      el.className = 'node' + (def.external ? ' ext' : '') + (sel && sel.kind === 'node' && sel.id === node.id ? ' sel' : '') + (connectFrom ? ' target' : '');
      el.style.left = node.x + 'px';
      el.style.top = node.y + 'px';
      el.dataset.id = node.id;
      el.tabIndex = 0;
      let meta = '';
      if (!def.external) {
        const ts = nodeThreats(node);
        const open = ts.filter((r) => threatState(node, r.tid) === 'Open').length;
        meta = `<div class="meta"><span class="dot open">${open} open</span><span class="dot done">${ts.length - open} handled</span></div>`;
      } else {
        meta = '<div class="meta">external</div>';
      }
      el.innerHTML = `<div class="top"><span class="tag ${groupClass(def.group)}">${esc(def.tag)}</span><span class="mono muted">#${node.id}</span></div>
        <div class="nm">${esc(node.name)}</div>${meta}`;
      board.appendChild(el);
      wireNode(el, node);
    });
    renderEdges();
  }

  function wireNode(el, node) {
    let start = null;
    el.addEventListener('pointerdown', (e) => {
      if (e.button !== 0) return;
      start = { px: e.clientX, py: e.clientY, x: node.x, y: node.y, moved: false };
      el.setPointerCapture(e.pointerId);
    });
    el.addEventListener('pointermove', (e) => {
      if (!start) return;
      const dx = e.clientX - start.px, dy = e.clientY - start.py;
      if (!start.moved && Math.hypot(dx, dy) < 4) return;
      start.moved = true;
      node.x = Math.max(0, Math.min(1500 - NODE_W, start.x + dx));
      node.y = Math.max(0, Math.min(940, start.y + dy));
      el.style.left = node.x + 'px';
      el.style.top = node.y + 'px';
      renderEdges();
    });
    const end = () => {
      if (!start) return;
      const moved = start.moved;
      start = null;
      if (moved) { save(); return; }
      clickNode(node);
    };
    el.addEventListener('pointerup', end);
    el.addEventListener('pointercancel', () => { start = null; save(); });
    el.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); clickNode(node); } });
  }

  function clickNode(node) {
    if (connectFrom !== null) {
      if (connectFrom !== node.id) {
        const f = { id: S.flowSeq++, from: connectFrom, to: node.id, label: 'data flow', encrypted: false, sensitive: false };
        S.flows.push(f);
        sel = { kind: 'flow', id: f.id };
      }
      connectFrom = null;
      $('hint').hidden = true;
      commit();
      return;
    }
    if (!(sel && sel.kind === 'node' && sel.id === node.id)) openThreat = null;
    sel = { kind: 'node', id: node.id };
    renderBoard();
    renderInspector();
  }

  function anchor(a, b) {
    // point on node a's border towards node b centre
    const h = 64;
    const ac = { x: a.x + NODE_W / 2, y: a.y + h / 2 };
    const bc = { x: b.x + NODE_W / 2, y: b.y + h / 2 };
    const dx = bc.x - ac.x, dy = bc.y - ac.y;
    if (!dx && !dy) return ac;
    const sx = (NODE_W / 2 + 6) / Math.abs(dx || 1e-9), sy = (h / 2 + 8) / Math.abs(dy || 1e-9);
    const s = Math.min(sx, sy);
    return { x: ac.x + dx * s, y: ac.y + dy * s };
  }

  function renderEdges() {
    const svg = $('edges');
    let out = `<defs>
      <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="arrowhead" d="M0,0 L10,5 L0,10 z"></path></marker>
      <marker id="arrSel" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" style="fill:var(--accent)"></path></marker></defs>`;
    S.flows.forEach((f) => {
      const a = nodeById(f.from), b = nodeById(f.to);
      if (!a || !b) return;
      const p = anchor(a, b), q = anchor(b, a);
      const isSel = sel && sel.kind === 'flow' && sel.id === f.id;
      const mx = (p.x + q.x) / 2, my = (p.y + q.y) / 2;
      out += `<g data-flow="${f.id}">
        <line class="edge ${f.encrypted ? 'enc' : 'plain'}${isSel ? ' sel' : ''}" x1="${p.x}" y1="${p.y}" x2="${q.x}" y2="${q.y}" marker-end="url(#${isSel ? 'arrSel' : 'arr'})"></line>
        <line class="edgehit" x1="${p.x}" y1="${p.y}" x2="${q.x}" y2="${q.y}"></line>
        <text class="edgelabel" x="${mx}" y="${my - 6}" text-anchor="middle">${esc(f.label)}</text></g>`;
    });
    svg.innerHTML = out;
    svg.querySelectorAll('g[data-flow]').forEach((g) => g.addEventListener('click', () => {
      sel = { kind: 'flow', id: Number(g.dataset.flow) };
      renderBoard(); renderInspector();
    }));
  }

  /* ---------- inspector ---------- */

  function renderInspector() {
    const ins = $('inspector');
    if (sel && sel.kind === 'node' && nodeById(sel.id)) return renderNodeInspector(ins, nodeById(sel.id));
    if (sel && sel.kind === 'flow' && S.flows.find((f) => f.id === sel.id)) return renderFlowInspector(ins, S.flows.find((f) => f.id === sel.id));
    sel = null;
    const rows = allRows();
    const open = rows.filter((r) => r.state === 'Open').length;
    const cms = cmRows();
    ins.innerHTML = `<div class="empty">
      <p class="eyebrow">Device</p><h2>${esc(S.name)}</h2>
      <div class="stats">
        <div class="stat"><b>${S.nodes.length}</b><span>components</span></div>
        <div class="stat"><b>${S.flows.length}</b><span>data flows</span></div>
        <div class="stat open"><b>${open}</b><span>open threats</span></div>
        <div class="stat done"><b>${cms.filter((c) => c.status === 'implemented').length}</b><span>countermeasures implemented of ${cms.length}</span></div>
      </div>
      <p class="small">Select a component to answer its questions and work through its threats. Use <b>Draw data flow</b> on a component to connect it to another.</p>
      <p class="small">Threats and countermeasures come from MITRE EMB3D STIX ${esc(E.version)}. EMB3D rates evidence, not severity, so threats are ordered by how much real-world evidence exists for them.</p>
    </div>`;
  }

  function renderNodeInspector(ins, node) {
    const def = TYPES[node.type];
    const pids = nodePids(node);
    const qs = def.questions.map((q) => {
      const a = answer(node, q);
      if (q.kind === 'bool') {
        return `<div class="q"><label class="check"><input type="checkbox" id="q-${node.id}-${q.id}" data-q="${q.id}" ${a ? 'checked' : ''}><span>${esc(q.text)}</span></label></div>`;
      }
      const opts = q.options.map((o) => `<label class="radio"><input type="radio" name="q-${node.id}-${q.id}" id="q-${node.id}-${q.id}-${o.value}" data-q="${q.id}" value="${esc(o.value)}" ${a === o.value ? 'checked' : ''}><span>${esc(o.label)}</span></label>`).join('');
      return `<div class="q"><span class="qt">${esc(q.text)}</span><div class="radios">${opts}</div></div>`;
    }).join('');

    let threatsHtml = '';
    if (!def.external) {
      const ts = nodeThreats(node);
      threatsHtml = `<div class="sect"><p class="eyebrow">Threats · ${ts.length}</p>` + (ts.length ? ts.map(({ tid, t, via }) => {
        const st = threatState(node, tid);
        const mat = MATURITY[t.maturity] || [9, t.maturity];
        const cms = t.mids.slice().sort((a, b) => (MIT_RANK[E.mitigations[a].maturity] ?? 9) - (MIT_RANK[E.mitigations[b].maturity] ?? 9)).map((mid) => {
          const m = E.mitigations[mid];
          const opts = CM_STATUS.map(([v, l]) => `<option value="${v}" ${cmStatus(node, mid) === v ? 'selected' : ''}>${l}</option>`).join('');
          return `<div class="cm"><span class="cmn"><span class="tid">${mid}</span> <button class="linkbtn" data-detail="${mid}">${esc(m.name)}</button></span>
            <select class="status" id="cm-${node.id}-${tid}-${mid}" data-mid="${mid}" aria-label="Status of ${esc(m.name)}">${opts}</select>
            <span class="cmm">${esc(m.maturity)}${m.iec.length ? ' · IEC 62443 ' + esc(m.iec.map((x) => x.split('–')[0].replace(/^.*?(\d)/, '$1').trim()).join(', ')) : ''}</span>
            ${NEEDS_WHY.includes(cmStatus(node, mid)) ? whyBox(node, mid, cmStatus(node, mid) === 'na' ? 'Why is it not applicable?' : 'Why is it rejected?') : ''}</div>`;
        }).join('');
        const cwes = t.cwes.length ? `<p class="small"><span class="lbl">Weaknesses</span> ${t.cwes.map(([i, n]) => `<span class="tid">CWE-${i}</span> ${esc(n)}`).join('; ')}</p>` : '';
        return `<details class="threat" data-tid="${tid}" ${openThreat === tid ? 'open' : ''}>
          <summary><span class="tid">${tid}</span><span class="tname">${esc(t.name)}</span>
            <span class="chips"><span class="pill st-${st}">${stateLabel(st)}</span>${t.mids.some((m) => missingWhy(node, m)) || missingAcceptWhy(node, tid) ? '<span class="pill st-Open">Justification missing</span>' : ''}<span class="mat m${mat[0]}">${esc(mat[1])}</span>${t.cves ? `<span class="mat">${t.cves} CVE</span>` : ''}</span></summary>
          <div class="tbody">
            <p>${esc(t.desc)}</p>
            <div class="row"><button class="linkbtn small" data-detail="${tid}">Read more</button><a class="extlink" href="${mitreUrl(tid)}" target="_blank" rel="noopener">${tid} on emb3d.mitre.org ↗</a></div>
            <p class="small"><span class="lbl">Applies because of</span> ${via.map((p) => `<span class="tid" title="${esc(E.properties[p].name)}">${p}</span>`).join(', ')}</p>
            ${cwes}
            <div class="cms">${cms || '<span class="muted small">EMB3D lists no mitigation for this threat.</span>'}</div>
            <div class="row small"><label for="acc-${node.id}-${tid}" class="lbl">Decision for this threat</label>
              <select class="status" id="acc-${node.id}-${tid}" data-accept="${tid}">
                ${[['', 'Handle with countermeasures'], ['na', 'Not applicable'], ['accept', 'Accept the risk']].map(([v, l]) => `<option value="${v}" ${decision(node, tid) === v ? 'selected' : ''}>${l}</option>`).join('')}
              </select></div>
            ${decision(node, tid) ? whyBox(node, 'accept:' + tid, decision(node, tid) === 'na' ? 'Why does this threat not apply?' : 'Why is the risk accepted?') : ''}
          </div></details>`;
      }).join('') : '<p class="muted small">No EMB3D threats for the current answers.</p>') + '</div>';
    }

    const pidChips = [...pids.entries()].sort().map(([p, why]) => `<span class="pid${why === 'rule' ? ' rule' : ''}" title="${esc(E.properties[p].name)}${why === 'rule' ? ' (added because the model has no update agent)' : ''}">${p}</span>`).join('');

    ins.innerHTML = `
      <p class="eyebrow"><span class="${groupClass(def.group)}">${esc(def.group)}</span> · ${esc(def.name)}</p>
      <div class="field"><label for="nm-${node.id}">Name</label><input type="text" id="nm-${node.id}" value="${esc(node.name)}"></div>
      <p class="small muted">${esc(def.hint)}</p>
      <div class="row">
        <button class="btn small" id="btnConnect">Draw data flow</button>
        <button class="btn small danger" id="btnDel">Delete</button>
      </div>
      ${qs ? `<div class="sect"><p class="eyebrow">Questions</p>${qs}</div>` : ''}
      ${pids.size ? `<div class="sect"><p class="eyebrow">EMB3D properties</p><div class="pids">${pidChips}</div></div>` : ''}
      ${threatsHtml}`;

    $('nm-' + node.id).addEventListener('input', (e) => { node.name = e.target.value; save(); renderBoard(); });
    $('btnConnect').addEventListener('click', () => { connectFrom = node.id; $('hint').hidden = false; renderBoard(); });
    armDelete($('btnDel'), () => {
      S.nodes = S.nodes.filter((n) => n.id !== node.id);
      S.flows = S.flows.filter((f) => f.from !== node.id && f.to !== node.id);
      sel = null; commit();
    });
    ins.querySelectorAll('input[data-q]').forEach((inp) => inp.addEventListener('change', () => {
      node.answers[inp.dataset.q] = inp.type === 'checkbox' ? inp.checked : inp.value;
      commit();
    }));
    ins.querySelectorAll('details.threat').forEach((d) => d.addEventListener('toggle', () => {
      if (d.open) openThreat = d.dataset.tid; else if (openThreat === d.dataset.tid) openThreat = null;
    }));
    ins.querySelectorAll('select[data-mid]').forEach((s) => s.addEventListener('change', () => {
      node.cm[s.dataset.mid] = s.value;
      commit();
      if (NEEDS_WHY.includes(s.value)) { const t = $('inspector').querySelector(`textarea[data-why="${s.dataset.mid}"]`); if (t) t.focus(); }
    }));
    wireWhy(ins, node);
    ins.querySelectorAll('select[data-accept]').forEach((c) => c.addEventListener('change', () => {
      node.accepted[c.dataset.accept] = c.value || false;
      commit();
      if (c.value) { const t = $('inspector').querySelector(`textarea[data-why="accept:${c.dataset.accept}"]`); if (t) t.focus(); }
    }));
  }

  function renderFlowInspector(ins, f) {
    const a = nodeById(f.from), b = nodeById(f.to);
    ins.innerHTML = `
      <p class="eyebrow">Data flow</p>
      <h2>${esc(a.name)} → ${esc(b.name)}</h2>
      <div class="field" style="margin-top:14px"><label for="fl-${f.id}">Label</label><input type="text" id="fl-${f.id}" value="${esc(f.label)}"></div>
      <div class="q"><label class="check"><input type="checkbox" id="fe-${f.id}" ${f.encrypted ? 'checked' : ''}><span>Encrypted in transit</span></label></div>
      <div class="q"><label class="check"><input type="checkbox" id="fs-${f.id}" ${f.sensitive ? 'checked' : ''}><span>Carries sensitive data</span></label></div>
      <p class="small muted">Dashed lines are unencrypted. EMB3D threats come from component properties, so flows document the design and go into the TM-BOM export.</p>
      <div class="row"><button class="btn small" id="btnRev">Reverse direction</button><button class="btn small danger" id="btnDel">Delete</button></div>`;
    $('fl-' + f.id).addEventListener('input', (e) => { f.label = e.target.value; save(); renderEdges(); });
    $('fe-' + f.id).addEventListener('change', (e) => { f.encrypted = e.target.checked; commit(); });
    $('fs-' + f.id).addEventListener('change', (e) => { f.sensitive = e.target.checked; commit(); });
    $('btnRev').addEventListener('click', () => { [f.from, f.to] = [f.to, f.from]; commit(); });
    armDelete($('btnDel'), () => { S.flows = S.flows.filter((x) => x.id !== f.id); sel = null; commit(); });
  }

  // Justification text: saved while typing; badges refresh when the field is left.
  function wireWhy(root, nodeOrFn) {
    root.querySelectorAll('textarea[data-why]').forEach((t) => {
      const node = typeof nodeOrFn === 'function' ? nodeOrFn(t) : nodeOrFn;
      t.addEventListener('input', () => {
        node.why = node.why || {};
        node.why[t.dataset.why] = t.value;
        t.closest('.why').classList.toggle('missing', !t.value.trim());
        save();
      });
      t.addEventListener('change', () => { if (view === 'diagram') renderInspector(); else if (view === 'cms') renderCms(); updateCount(); });
    });
  }

  function armDelete(btn, action) {
    let armed = false;
    btn.addEventListener('click', () => {
      if (armed) return action();
      armed = true;
      btn.textContent = 'Click again to delete';
      setTimeout(() => { armed = false; if (btn.isConnected) btn.textContent = 'Delete'; }, 3000);
    });
  }

  /* ---------- detail reader ---------- */

  const mitreUrl = (id) => `https://emb3d.mitre.org/${id.startsWith('MID') ? 'mitigations' : 'threats'}/${id}.html`;
  const detailStack = [];

  // Paragraph text: *emphasis*, and TID-/MID- references become links inside the reader.
  function richText(txt) {
    return esc(txt)
      .replace(/\*([^*]+)\*/g, '<em>$1</em>')
      .replace(/\b((?:TID|MID)-\d{3})\b/g, (m) => (E.threats[m] || E.mitigations[m]) ? `<button class="linkbtn" data-detail="${m}">${m}</button>` : m);
  }

  function threatsOfMitigation(mid) {
    return Object.entries(E.threats).filter(([, t]) => t.mids.includes(mid)).map(([tid]) => tid);
  }

  function renderDetail(id) {
    let html;
    if (id.startsWith('MID')) {
      const m = E.mitigations[id];
      const tids = threatsOfMitigation(id);
      html = `<div class="dhead"><span class="eyebrow" style="margin:0">${id} · ${esc(m.maturity)} mitigation</span>
          <a class="extlink" href="${mitreUrl(id)}" target="_blank" rel="noopener">Open on emb3d.mitre.org ↗</a></div>
        <h3>${esc(m.name)}</h3>
        ${(m.text || [m.desc]).map((t) => `<p>${richText(t)}</p>`).join('')}
        ${m.iec.length ? `<div><p class="eyebrow">IEC 62443-4-2</p><p class="small">${m.iec.map(esc).join('<br>')}</p></div>` : ''}
        <div><p class="eyebrow">Mitigates ${tids.length} threats</p><div class="tlist">${tids.map((t) => `<button data-detail="${t}"><span class="tid">${t}</span> ${esc(E.threats[t].name)}</button>`).join('')}</div></div>
        ${m.refs && m.refs.length ? `<div><p class="eyebrow">References</p><ol class="refs">${m.refs.map((r) => `<li>${esc(r.t)}${r.u ? ` <a href="${esc(r.u)}" target="_blank" rel="noopener">${esc(r.u)}</a>` : ''}</li>`).join('')}</ol></div>` : ''}`;
    } else {
      const t = E.threats[id];
      const mat = MATURITY[t.maturity] || [9, t.maturity];
      html = `<div class="dhead"><span class="eyebrow" style="margin:0">${id} · ${esc(t.cat)} threat</span><span class="mat m${mat[0]}">${esc(mat[1])}</span>
          <a class="extlink" href="${mitreUrl(id)}" target="_blank" rel="noopener">Open on emb3d.mitre.org ↗</a></div>
        <h3>${esc(t.name)}</h3>
        ${(t.text || [t.desc]).map((x) => `<p>${richText(x)}</p>`).join('')}
        <div><p class="eyebrow">Device properties</p><p class="small">${t.pids.map((p) => `<span class="tid">${p}</span> ${esc(E.properties[p].name)}`).join('<br>')}</p></div>
        ${t.cwes.length ? `<div><p class="eyebrow">Weaknesses</p><p class="small">${t.cwes.map(([i, n]) => `<a class="extlink" href="https://cwe.mitre.org/data/definitions/${i}.html" target="_blank" rel="noopener">CWE-${i}</a> ${esc(n)}`).join('<br>')}</p></div>` : ''}
        <div><p class="eyebrow">Mitigations · ${t.mids.length}</p><div class="tlist">${t.mids.map((m) => `<button data-detail="${m}"><span class="tid">${m}</span> ${esc(E.mitigations[m].name)}</button>`).join('')}</div></div>`;
    }
    $('dBody').innerHTML = html;
    $('dBody').scrollTop = 0;
    $('dBack').hidden = detailStack.length < 2;
  }

  function openDetail(id) {
    if (!E.threats[id] && !E.mitigations[id]) return;
    detailStack.push(id);
    $('dAction').hidden = true;
    $('dClose').textContent = 'Close';
    $('dClose').onclick = closeDetail;
    renderDetail(id);
    $('dOverlay').hidden = false;
    $('dClose').focus();
  }

  function closeDetail() { detailStack.length = 0; $('dOverlay').hidden = true; }

  /* ---------- table views ---------- */

  function summaryHtml(rows) {
    const c = (s) => rows.filter((r) => r.state === s).length;
    return `<div class="summary"><span><b>${rows.length}</b>threats</span><span style="color:var(--s-open)"><b>${c('Open')}</b>open</span>
      <span style="color:var(--s-done)"><b>${c('Mitigated')}</b>mitigated</span><span style="color:var(--s-acc)"><b>${c('Accepted')}</b>accepted</span><span class="muted"><b>${c('NA')}</b>n/a</span></div>`;
  }

  function compOptions(cur) {
    return `<option value="all">All components</option>` + S.nodes.filter((n) => !TYPES[n.type]?.external)
      .map((n) => `<option value="${n.id}" ${String(cur) === String(n.id) ? 'selected' : ''}>${esc(n.name)}</option>`).join('');
  }

  function renderThreats() {
    let rows = allRows();
    const all = rows;
    if (filters.tState !== 'all') rows = rows.filter((r) => r.state === filters.tState);
    if (filters.tComp !== 'all') rows = rows.filter((r) => String(r.node.id) === String(filters.tComp));
    const states = [['all', 'All states'], ['Open', 'Open'], ['Mitigated', 'Mitigated'], ['Accepted', 'Accepted'], ['NA', 'Not applicable']];
    $('view-threats').innerHTML = `
      <div class="tablehead"><h2>Threats</h2>${summaryHtml(all)}
        <div class="filters">
          <select id="fState" aria-label="Filter by state">${states.map(([v, l]) => `<option value="${v}" ${filters.tState === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
          <select id="fComp" aria-label="Filter by component">${compOptions(filters.tComp)}</select>
        </div></div>
      <div class="tablescroll"><table><thead><tr><th>Component</th><th>Threat</th><th>Evidence</th><th>State</th><th>Countermeasures</th></tr></thead><tbody>
      ${rows.map((r) => {
        const mat = MATURITY[r.t.maturity] || [9, r.t.maturity];
        const impl = r.t.mids.filter((m) => cmStatus(r.node, m) === 'implemented').length;
        return `<tr class="link" data-node="${r.node.id}" data-tid="${r.tid}">
          <td>${esc(r.node.name)}<div class="sub">${esc(TYPES[r.node.type].name)}</div></td>
          <td><span class="tid">${r.tid}</span> ${esc(r.t.name)}</td>
          <td><span class="mat m${mat[0]}">${esc(mat[1])}</span></td>
          <td><span class="pill st-${r.state}">${stateLabel(r.state)}</span>${r.t.mids.some((m) => missingWhy(r.node, m)) || missingAcceptWhy(r.node, r.tid) ? '<div class="sub" style="color:var(--s-open)">Justification missing</div>' : ''}</td>
          <td class="num">${impl} / ${r.t.mids.length} implemented</td></tr>`;
      }).join('') || '<tr><td colspan="5" class="muted">No threats match these filters.</td></tr>'}
      </tbody></table></div>`;
    $('fState').addEventListener('change', (e) => { filters.tState = e.target.value; renderThreats(); });
    $('fComp').addEventListener('change', (e) => { filters.tComp = e.target.value; renderThreats(); });
    $('view-threats').querySelectorAll('tr.link').forEach((tr) => tr.addEventListener('click', () => {
      sel = { kind: 'node', id: Number(tr.dataset.node) };
      openThreat = tr.dataset.tid;
      setView('diagram');
      const el = document.querySelector(`#inspector details[data-tid="${tr.dataset.tid}"]`);
      if (el) el.scrollIntoView({ block: 'center' });
    }));
  }

  function renderCms() {
    let rows = cmRows();
    const total = rows.length;
    const cnt = (s) => rows.filter((r) => r.status === s).length;
    if (filters.cStatus !== 'all') rows = rows.filter((r) => r.status === filters.cStatus);
    $('view-cms').innerHTML = `
      <div class="tablehead"><h2>Countermeasures</h2>
        <div class="summary"><span><b>${total}</b>total</span><span style="color:var(--s-done)"><b>${cnt('implemented')}</b>implemented</span><span style="color:var(--s-open)"><b>${cnt('required')}</b>required</span><span class="muted"><b>${cnt('recommended')}</b>recommended</span>${(() => { const k = cmRows().filter((r) => missingWhy(r.node, r.mid)).length; return k ? `<span style="color:var(--s-open)"><b>${k}</b>missing justification</span>` : ''; })()}</div>
        <div class="filters"><select id="fCm" aria-label="Filter by status"><option value="all">All statuses</option>
          ${CM_STATUS.map(([v, l]) => `<option value="${v}" ${filters.cStatus === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div></div>
      <div class="tablescroll"><table><thead><tr><th>Countermeasure</th><th>Level</th><th>Component</th><th>Threats</th><th>IEC 62443-4-2</th><th>Status</th><th>Justification</th></tr></thead><tbody>
      ${rows.map((r) => `<tr>
          <td><span class="tid">${r.mid}</span> <button class="linkbtn" data-detail="${r.mid}">${esc(r.m.name)}</button></td>
          <td>${esc(r.m.maturity)}</td>
          <td>${esc(r.node.name)}</td>
          <td class="num">${r.tids.join(', ')}</td>
          <td class="sub">${esc(r.m.iec.join('; ')) || '—'}</td>
          <td><select class="status" id="cmt-${r.node.id}-${r.mid}" data-node="${r.node.id}" data-mid="${r.mid}" aria-label="Status">
            ${CM_STATUS.map(([v, l]) => `<option value="${v}" ${r.status === v ? 'selected' : ''}>${l}</option>`).join('')}</select></td>
          <td class="whycell" data-node="${r.node.id}">${NEEDS_WHY.includes(r.status) ? whyBox(r.node, r.mid, 'Justification') : '<span class="muted">—</span>'}</td></tr>`).join('')
        || '<tr><td colspan="7" class="muted">No countermeasures match this filter.</td></tr>'}
      </tbody></table></div>`;
    $('fCm').addEventListener('change', (e) => { filters.cStatus = e.target.value; renderCms(); });
    $('view-cms').querySelectorAll('select[data-mid]').forEach((s) => s.addEventListener('change', () => {
      nodeById(Number(s.dataset.node)).cm[s.dataset.mid] = s.value;
      save(); renderCms(); updateCount();
      if (NEEDS_WHY.includes(s.value)) { const t = $('view-cms').querySelector(`td[data-node="${s.dataset.node}"] textarea[data-why="${s.dataset.mid}"]`); if (t) t.focus(); }
    }));
    wireWhy($('view-cms'), (t) => nodeById(Number(t.closest('td').dataset.node)));
  }

  /* ---------- TM-BOM export ---------- */

  function toTmbom() {
    const sym = (n) => `n${n.id}-${slug(n.type)}`;
    const isExt = (n) => !!TYPES[n.type]?.external;
    const used = new Set();
    S.nodes.forEach((n) => used.add(ZONE[TYPES[n.type].group][0]));
    const trust_zones = Object.values(ZONE).filter(([z]) => used.has(z)).map(([z, t]) => ({ symbolic_name: z, title: t, description: `${t} parts of the device` + (z === 'external' ? ' (outside the device)' : '') }));
    if (!trust_zones.length) trust_zones.push({ symbolic_name: 'device', title: 'Device', description: 'The device' });
    const actors = S.nodes.filter(isExt).map((n) => ({
      symbolic_name: sym(n), title: n.name, description: TYPES[n.type].hint,
      type: n.type === 'person' ? 'user' : 'third_party', trust_zone: 'external',
    }));
    const components = S.nodes.filter((n) => !isExt(n)).map((n) => ({
      symbolic_name: sym(n), title: n.name,
      description: `${TYPES[n.type].name}. EMB3D properties: ${[...nodePids(n).keys()].sort().join(', ')}`,
      trust_zone: ZONE[TYPES[n.type].group][0],
    }));
    const ref = (n) => ({ type: isExt(n) ? 'actor' : 'component', object: sym(n) });
    const data_flows = S.flows.filter((f) => nodeById(f.from) && nodeById(f.to)).map((f) => ({
      symbolic_name: `f${f.id}`, title: f.label || 'data flow', description: `${nodeById(f.from).name} to ${nodeById(f.to).name}`,
      source: ref(nodeById(f.from)), destination: ref(nodeById(f.to)), has_sensitive_data: !!f.sensitive, encrypted: !!f.encrypted,
    }));
    const threats = [], controls = [], assumptions = [];
    S.nodes.filter((n) => !isExt(n)).forEach((n) => {
      const byMid = new Map();
      nodeThreats(n).forEach(({ tid, t, via }) => {
        const id = `${tid.toLowerCase()}-${sym(n)}`;
        const th = {
          symbolic_name: id, title: `${tid}: ${t.name}`,
          description: `${t.desc}\n\nEMB3D evidence: ${t.maturity}.`, components_affected: [sym(n)],
          threat_persona: t.cat === 'hardware' ? 'physical-adversary' : 'remote-adversary',
          event: 'Applies because the component has: ' + via.map((p) => `${p} ${E.properties[p].name}`).join('; '),
          sources: ['adversary'],
        };
        if (t.cwes.length) th.weaknesses = t.cwes.map(([i, title]) => ({ cwe_id: i, cwe_title: title }));
        threats.push(th);
        const d = decision(n, tid);
        if (d) assumptions.push({
          description: (d === 'na' ? `${tid} (${t.name}) does not apply to ${n.name}.` : `Risk of ${tid} (${t.name}) accepted for ${n.name}.`)
            + (why(n, 'accept:' + tid) ? ` Justification: ${why(n, 'accept:' + tid)}` : ' No justification given.'),
          topics: [id], validity: 'confirmed',
        });
        t.mids.forEach((m) => { if (!byMid.has(m)) byMid.set(m, []); byMid.get(m).push(id); });
      });
      byMid.forEach((tids, mid) => {
        const m = E.mitigations[mid];
        const st = cmStatus(n, mid);
        controls.push({
          symbolic_name: `${mid.toLowerCase()}-${sym(n)}`, title: `${mid}: ${m.name}`,
          description: `${m.desc}\n\nEMB3D level: ${m.maturity}.` + (m.iec.length ? `\nIEC 62443-4-2: ${m.iec.join('; ')}` : '') + `\nWorkbench status: ${CM_STATUS.find((s) => s[0] === st)[1]}.` + (why(n, mid) ? `\nJustification: ${why(n, mid)}` : ''),
          threats: tids, status: CM_TO_TMBOM[st], priority: st === 'required' ? 'high' : 'none',
        });
      });
    });
    const doc = {
      $schema: TMBOM_SCHEMA,
      version: '1.0',
      scope: {
        title: S.name,
        description: S.meta?.description || `Threat model of ${S.name}, built with EMB3D Workbench on MITRE EMB3D STIX ${E.version}.`,
        business_criticality: 'moderate', data_sensitivity: ['cred', 'ip', 'op'], exposure: 'external', tier: 'important',
      },
      description: 'Threats and countermeasures derived from MITRE EMB3D device properties (https://emb3d.mitre.org/).',
      reviewed_at: new Date().toISOString().slice(0, 10),
      trust_zones, trust_boundaries: [], actors, components, data_stores: [], data_sets: [], data_flows,
      threat_personas: [
        { symbolic_name: 'physical-adversary', title: 'Adversary with physical device access', description: 'Skilled attacker holding the device, able to probe buses, debug ports and side channels.', is_person: true, skill_level: 'expert_engineer', access_level: 'anonymous', malicious_intent: true, applicability_to_org: 'moderate' },
        { symbolic_name: 'remote-adversary', title: 'Remote or local software adversary', description: 'Attacker reaching the device over a network or through code running on it.', is_person: true, skill_level: 'engineer', access_level: 'anonymous', malicious_intent: true, applicability_to_org: 'high' },
      ],
      threats, controls,
      extensions: { [EXT_KEY]: { emb3d_version: E.version, project: S } },
    };
    if (assumptions.length) doc.assumptions = assumptions;
    return doc;
  }

  /* ---------- modal, open, save ---------- */

  function modal(title, text, body, extra) {
    $('mTitle').textContent = title;
    $('mText').textContent = text;
    $('mBody').value = body;
    $('mBody').readOnly = !extra;
    $('mMsg').textContent = '';
    $('mExtra').hidden = !extra;
    if (extra) { $('mExtra').textContent = extra.label; $('mExtra').onclick = extra.run; }
    $('mCopy').hidden = !!extra;
    $('overlay').hidden = false;
    $('mBody').focus();
    $('mBody').setSelectionRange(0, 0);
  }

  function importText(text) {
    let obj;
    try { obj = JSON.parse(text); } catch (e) { return 'This is not valid JSON: ' + e.message; }
    let p = null;
    if (obj && Array.isArray(obj.nodes)) p = obj;
    else if (obj && obj.extensions && obj.extensions[EXT_KEY]) p = obj.extensions[EXT_KEY].project;
    if (!p || !Array.isArray(p.nodes)) return 'This file is not an EMB3D Workbench project or a TM-BOM exported from it.';
    const unknown = p.nodes.filter((n) => !TYPES[n.type]).map((n) => n.type);
    if (unknown.length) return 'Unknown component types: ' + [...new Set(unknown)].join(', ');
    p.nodes.forEach((n) => { n.answers = n.answers || {}; n.cm = n.cm || {}; n.accepted = n.accepted || {}; n.why = n.why || {}; });
    p.flows = p.flows || [];
    p.seq = Math.max(p.seq || 1, ...p.nodes.map((n) => n.id + 1));
    p.flowSeq = Math.max(p.flowSeq || 1, ...p.flows.map((f) => f.id + 1), 1);
    const wanted = p.emb3d;
    if (!wanted || !allVersions().some((v) => v.version === wanted)) p.emb3d = IDX.default;
    S = p; sel = null; openThreat = null;
    loadVersion(S.emb3d).then((d) => {
      E = d; renderVersionSelect(); commit();
      if (wanted && wanted !== S.emb3d) panel('', `<h3>Opened with EMB3D ${esc(S.emb3d)}</h3><p>This model was made with EMB3D ${esc(wanted)}, which is not available here. It now uses ${esc(S.emb3d)}. Add the original with <span class="mono">python3 tools/emb3d_update.py add ${esc(wanted)}</span> to reproduce it exactly.</p>`);
    });
    return null;
  }

  function wireChrome() {
    document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => setView(b.dataset.view)));
    $('projName').addEventListener('input', (e) => { S.name = e.target.value; save(); if (!sel) renderInspector(); });
    $('hintCancel').addEventListener('click', () => { connectFrom = null; $('hint').hidden = true; renderBoard(); });
    document.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape') return;
      if (!$('dOverlay').hidden) { $('dClose').click(); return; }
      if (!$('overlay').hidden) { $('overlay').hidden = true; return; }
      if (connectFrom !== null) { connectFrom = null; $('hint').hidden = true; renderBoard(); }
    });
    $('board').addEventListener('pointerdown', (e) => {
      if (e.target === $('board') || e.target === $('edges')) {
        if (connectFrom !== null) return;
        if (sel) { sel = null; openThreat = null; renderBoard(); renderInspector(); }
      }
    });
    $('board').addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
    $('board').addEventListener('drop', (e) => {
      const type = e.dataTransfer.getData('text/x-emb3d');
      if (!type) return;
      e.preventDefault();
      const r = $('board').getBoundingClientRect();
      addNode(type, Math.max(0, e.clientX - r.left - NODE_W / 2), Math.max(0, e.clientY - r.top - 30));
    });
    $('btnTmbom').addEventListener('click', () => modal('TM-BOM export',
      'OWASP Threat Model Library schema v1.0.2. Copy it into a .json file and open it in OWASP Threat Dragon, or open it here again later.',
      JSON.stringify(toTmbom(), null, 2)));
    $('btnSave').addEventListener('click', () => modal('Project file',
      'Your work is kept in this browser automatically. Copy this into a .json file to keep a copy or move it to another machine.',
      JSON.stringify(S, null, 2)));
    $('fileIn').addEventListener('change', async (e) => {
      const f = e.target.files[0];
      e.target.value = '';
      if (!f) return;
      const err = importText(await f.text());
      if (err) modal('Could not open the file', err, '');
    });
    let newArmed = false;
    $('btnNew').addEventListener('click', () => {
      if (!newArmed) {
        newArmed = true; $('btnNew').textContent = 'Discard current?';
        setTimeout(() => { newArmed = false; $('btnNew').textContent = 'New'; }, 3000);
        return;
      }
      newArmed = false; $('btnNew').textContent = 'New';
      S = emptyProject(); S.emb3d = E.version; sel = null; commit();
    });
    $('mClose').addEventListener('click', () => { $('overlay').hidden = true; });
    $('verSel').addEventListener('change', (e) => proposeVersion(e.target.value));
    $('btnUpd').addEventListener('click', checkForUpdates);
    document.addEventListener('click', (e) => {
      const b = e.target.closest('[data-detail]');
      if (!b) return;
      e.preventDefault(); e.stopPropagation();
      openDetail(b.dataset.detail);
    }, true);
    $('dBack').addEventListener('click', () => { detailStack.pop(); renderDetail(detailStack[detailStack.length - 1]); });
    $('dOverlay').addEventListener('click', (e) => { if (e.target === $('dOverlay')) $('dClose').click(); });
    $('overlay').addEventListener('click', (e) => { if (e.target === $('overlay')) $('overlay').hidden = true; });
    $('mCopy').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText($('mBody').value); $('mMsg').textContent = 'Copied'; }
      catch (_) { $('mBody').focus(); $('mBody').select(); $('mMsg').textContent = 'Selected. Press Ctrl+C or Cmd+C to copy.'; }
    });
    // Paste import: "Open…" via paste in a blank modal is offered through the file picker; also accept pasted JSON anywhere on the board.
    document.addEventListener('paste', (e) => {
      if (!$('overlay').hidden || /input|textarea/i.test(document.activeElement?.tagName || '')) return;
      const t = e.clipboardData && e.clipboardData.getData('text');
      if (t && t.trim().startsWith('{')) { const err = importText(t); if (err) modal('Could not open the pasted text', err, ''); }
    });
  }

  function setView(v) {
    view = v;
    document.querySelectorAll('.tabs button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.view === v)));
    $('view-diagram').hidden = v !== 'diagram';
    $('view-threats').hidden = v !== 'threats';
    $('view-cms').hidden = v !== 'cms';
    $('view-report').hidden = v !== 'report';
    render();
  }

  function updateCount() {
    const open = allRows().filter((r) => r.state === 'Open').length;
    $('openCount').textContent = open ? String(open) : '';
  }

  function render() {
    $('projName').value = S.name;
    if (view === 'diagram') { renderBoard(); renderInspector(); }
    if (view === 'threats') renderThreats();
    if (view === 'cms') renderCms();
    if (view === 'report') renderReport();
    updateCount();
  }

  function commit() { save(); render(); }


  /* ---------- EMB3D versions ---------- */

  const allVersions = () => [...IDX.versions, ...SESSION_VERSIONS];
  const vkey = (v) => v.split('.').map(Number);
  const vcmp = (a, b) => { const x = vkey(a), y = vkey(b); for (let i = 0; i < Math.max(x.length, y.length); i++) { const d = (x[i] || 0) - (y[i] || 0); if (d) return d; } return 0; };

  async function loadVersion(v) {
    if (STIX.has(v)) return STIX.get(v);
    const meta = allVersions().find((x) => x.version === v);
    if (!meta) throw new Error(`EMB3D STIX ${v} is not available`);
    const bundle = meta.bundle || await fetch('data/stix/' + meta.file).then((r) => { if (!r.ok) throw new Error(`${meta.file}: HTTP ${r.status}`); return r.json(); });
    const data = window.EMB3D_STIX.parse(bundle, v);
    STIX.set(v, data);
    return data;
  }

  function renderVersionSelect() {
    const list = allVersions().slice().sort((a, b) => vcmp(b.version, a.version));
    $('verSel').innerHTML = list.map((m) => `<option value="${esc(m.version)}" ${m.version === E.version ? 'selected' : ''}>EMB3D ${esc(m.version)}${m.version === IDX.default ? ' (default)' : ''}${m.session ? ' (this session)' : ''}</option>`).join('');
  }

  // Threat IDs that apply to each component under a given data set.
  function threatSets(data) {
    const keep = E;
    E = data;
    const out = new Map();
    try { S.nodes.filter((n) => !TYPES[n.type]?.external).forEach((n) => out.set(n.id, new Set(nodeThreats(n).map((r) => r.tid)))); }
    finally { E = keep; }
    return out;
  }

  function libraryPids() {
    const set = new Set();
    LIB.components.forEach((c) => {
      c.base.forEach((p) => set.add(p));
      c.questions.forEach((q) => { (q.pids || []).forEach((p) => set.add(p)); (q.options || []).forEach((o) => o.pids.forEach((p) => set.add(p))); });
    });
    return set;
  }

  async function proposeVersion(v) {
    if (v === E.version) return;
    let next;
    try { next = await loadVersion(v); } catch (e) { panel('Could not load that version', `<p>${esc(e.message)}</p>`); renderVersionSelect(); return; }
    const d = window.EMB3D_STIX.diff(E, next);
    const before = threatSets(E), after = threatSets(next);
    const rows = S.nodes.filter((n) => before.has(n.id)).map((n) => {
      const add = [...after.get(n.id)].filter((t) => !before.get(n.id).has(t));
      const rem = [...before.get(n.id)].filter((t) => !after.get(n.id).has(t));
      return { n, add, rem };
    }).filter((r) => r.add.length || r.rem.length);
    const missing = [...libraryPids()].filter((p) => !next.properties[p]);
    const tl = (ids, data) => ids.map((t) => `<span class="tid">${t}</span> ${esc(data.threats[t].name)}`).join('<br>');
    const renamed = [...d.threatsRenamed.map((t) => [t, E.threats[t].name, next.threats[t].name]), ...d.mitigationsRenamed.map((m) => [m, E.mitigations[m].name, next.mitigations[m].name])];
    const html = `<div class="dhead"><span class="eyebrow" style="margin:0">Switch EMB3D version</span></div>
      <h3>EMB3D ${esc(E.version)} → ${esc(v)}</h3>
      <p>Countermeasure statuses, decisions and justifications are kept: they are stored by threat and mitigation ID.</p>
      <div><p class="eyebrow">Your components</p>${rows.length ? `<table class="mini"><thead><tr><th>Component</th><th>Threats added</th><th>Threats removed</th></tr></thead><tbody>
        ${rows.map((r) => `<tr><td>${esc(r.n.name)}</td><td>${tl(r.add, next) || '—'}</td><td>${tl(r.rem, E) || '—'}</td></tr>`).join('')}</tbody></table>` : '<p class="small">No threats are added or removed for this model.</p>'}</div>
      ${renamed.length ? `<div><p class="eyebrow">Renamed in ${esc(v)}</p><p class="small">${renamed.map(([id, a, b]) => `<span class="tid">${id}</span> ${esc(a)} → <b>${esc(b)}</b>`).join('<br>')}</p></div>` : ''}
      <div><p class="eyebrow">Catalogue changes</p><p class="small">
        Threats: ${d.threatsAdded.length} added, ${d.threatsRemoved.length} removed, ${d.threatsRemapped.length} with changed properties or mitigations.<br>
        Mitigations: ${d.mitigationsAdded.length} added, ${d.mitigationsRemoved.length} removed.</p></div>
      ${missing.length ? `<p class="warn">The component library uses properties that ${esc(v)} does not define: ${missing.join(', ')}. Those answers will add nothing.</p>` : ''}`;
    panel('', html, { label: `Use EMB3D ${v}`, run: () => { E = next; S.emb3d = v; closeDetail(); renderVersionSelect(); commit(); } }, () => renderVersionSelect());
  }

  async function checkForUpdates() {
    panel('', '<p class="muted">Checking emb3d.mitre.org…</p>');
    let found;
    try {
      const html = await fetch(MITRE_SITE + '/subtabs/data.html', { cache: 'no-store' }).then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); });
      found = [...new Set([...html.matchAll(/emb3d-stix-(\d+(?:\.\d+)*)\.json/g)].map((m) => m[1]))].sort((a, b) => vcmp(b, a));
      if (!found.length) throw new Error('no STIX links on the data page');
    } catch (e) {
      panel('', `<h3>Could not reach emb3d.mitre.org</h3>
        <p>The browser could not read MITRE's data page (${esc(e.message)}). This happens offline and in sandboxed previews.</p>
        <p>From the project folder, run:</p><pre class="cmd">python3 tools/emb3d_update.py check</pre>`);
      return;
    }
    const have = new Set(allVersions().map((x) => x.version));
    const fresh = found.filter((v) => !have.has(v));
    if (!fresh.length) {
      panel('', `<h3>EMB3D is up to date</h3><p>emb3d.mitre.org lists ${found.map(esc).join(', ')}. All of them are available here.</p>`);
      return;
    }
    const v = fresh[0];
    panel('', `<h3>EMB3D STIX ${esc(v)} is available</h3>
      <p>emb3d.mitre.org lists ${found.map(esc).join(', ')}. This copy of the Workbench has ${[...have].sort((a, b) => vcmp(b, a)).map(esc).join(', ')}.</p>
      <p>To add it for everyone using this copy, run this in the project folder and commit the result:</p>
      <pre class="cmd">python3 tools/emb3d_update.py add ${esc(v)}</pre>
      <p>Or try it now: the file is downloaded into this browser session only.</p>`,
    { label: `Try ${v} now`, run: async () => {
      try {
        const bundle = await fetch(`${MITRE_SITE}/assets/emb3d-stix-${v}.json`).then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
        window.EMB3D_STIX.parse(bundle, v);
        SESSION_VERSIONS.push({ version: v, file: `emb3d-stix-${v}.json`, session: true, bundle });
        renderVersionSelect();
        proposeVersion(v);
      } catch (e) { panel('', `<h3>Download failed</h3><p>${esc(e.message)}</p><pre class="cmd">python3 tools/emb3d_update.py add ${esc(v)}</pre>`); }
    } });
  }

  // Generic panel in the reader dialog with an optional primary action.
  function panel(_title, html, action, onCancel) {
    detailStack.length = 0;
    $('dBody').innerHTML = html;
    $('dBody').scrollTop = 0;
    $('dBack').hidden = true;
    $('dAction').hidden = !action;
    if (action) { $('dAction').textContent = action.label; $('dAction').onclick = action.run; }
    $('dClose').textContent = action ? 'Cancel' : 'Close';
    $('dClose').onclick = () => { closeDetail(); if (onCancel) onCancel(); };
    $('dOverlay').hidden = false;
    (action ? $('dAction') : $('dClose')).focus();
  }

  /* ---------- report (layout follows OWASP Threat Dragon's report) ---------- */

  function diagramSvg() {
    if (!S.nodes.length) return '<p class="muted">The diagram is empty.</p>';
    const pad = 30;
    const minX = Math.min(...S.nodes.map((n) => n.x)) - pad, minY = Math.min(...S.nodes.map((n) => n.y)) - pad;
    const maxX = Math.max(...S.nodes.map((n) => n.x + NODE_W)) + pad, maxY = Math.max(...S.nodes.map((n) => n.y + NODE_H)) + pad;
    const wrap = (t) => { const w = String(t).split(/\s+/); const lines = ['']; w.forEach((x) => { if ((lines[lines.length - 1] + ' ' + x).trim().length > 22 && lines[lines.length - 1]) lines.push(x); else lines[lines.length - 1] = (lines[lines.length - 1] + ' ' + x).trim(); }); return lines.slice(0, 2); };
    let out = `<svg class="rdiagram" viewBox="${minX} ${minY} ${maxX - minX} ${maxY - minY}" role="img" aria-label="Device diagram">
      <defs><marker id="rarr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="rarrow"></path></marker></defs>`;
    S.flows.forEach((f) => {
      const a = nodeById(f.from), b = nodeById(f.to);
      if (!a || !b) return;
      const p = anchor(a, b), q = anchor(b, a);
      out += `<line class="redge${f.encrypted ? '' : ' plain'}" x1="${p.x}" y1="${p.y}" x2="${q.x}" y2="${q.y}" marker-end="url(#rarr)"></line>
        <text class="rlabel" x="${(p.x + q.x) / 2}" y="${(p.y + q.y) / 2 - 6}" text-anchor="middle">${esc(f.label)}</text>`;
    });
    S.nodes.forEach((n) => {
      const def = TYPES[n.type];
      const lines = wrap(n.name);
      out += `<g class="rnode ${groupClass(def.group)}${def.external ? ' ext' : ''}">
        <rect x="${n.x}" y="${n.y}" width="${NODE_W}" height="${NODE_H}" rx="8"></rect>
        <text class="rtag" x="${n.x + 10}" y="${n.y + 17}">${esc(def.tag)} · #${n.id}</text>
        ${lines.map((l, i) => `<text class="rname" x="${n.x + 10}" y="${n.y + 36 + i * 16}">${esc(l)}</text>`).join('')}</g>`;
    });
    return out + '</svg>';
  }

  function renderReport() {
    const o = reportOpts;
    const m = S.meta || (S.meta = { description: '', owner: '', reviewer: '' });
    const rows = allRows();
    const c = (st) => rows.filter((r) => r.state === st).length;
    const openBy = (lvl) => rows.filter((r) => r.state === 'Open' && (MATURITY[r.t.maturity]?.[0] ?? 9) === lvl).length;
    const cms = cmRows();
    const missing = cms.filter((r) => missingWhy(r.node, r.mid)).length + rows.filter((r) => missingAcceptWhy(r.node, r.tid)).length;
    const stats = [
      ['Total Threats', rows.length], ['Total Mitigated', c('Mitigated')], ['Total Open', c('Open')],
      ...(c('NA') ? [['Total Not Applicable', c('NA')]] : []), ...(c('Accepted') ? [['Total Accepted', c('Accepted')]] : []),
      ['Open / Observed in attacks', openBy(0)], ['Open / Observed technique', openBy(1)], ['Open / Known weakness', openBy(2)], ['Open / Proof of concept', openBy(3)],
      ['Countermeasures implemented', `${cms.filter((r) => r.status === 'implemented').length} of ${cms.length}`],
      ...(missing ? [['Decisions missing a justification', missing]] : []),
    ];
    let num = 0;
    const comps = S.nodes.filter((n) => !TYPES[n.type].external).map((n) => {
      const ts = nodeThreats(n).map((r) => ({ ...r, state: threatState(n, r.tid) }))
        .filter((r) => (o.mitigated || r.state !== 'Mitigated') && (o.closed || (r.state !== 'NA' && r.state !== 'Accepted')));
      if (!ts.length && !o.empty) return '';
      const def = TYPES[n.type];
      const props = [...nodePids(n).keys()].sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
      const body = ts.map((r) => {
        num += 1;
        const d = decision(n, r.tid);
        const mat = MATURITY[r.t.maturity] || [9, r.t.maturity];
        const cmCell = r.t.mids.map((mid) => {
          const st = cmStatus(n, mid);
          return `<div class="rcm"><b>${mid}</b> ${esc(E.mitigations[mid].name)} — <i>${CM_STATUS.find((x) => x[0] === st)[1]}</i>${why(n, mid) ? `<div class="rwhy">${esc(why(n, mid))}</div>` : ''}</div>`;
        }).join('') || '—';
        return `<tr><td class="num">${num}</td><td><b>${r.tid}</b> ${esc(r.t.name)}</td><td>${esc(r.t.cat)}</td><td>${esc(mat[1])}</td>
          <td>${stateLabel(r.state)}${d ? `<div class="rwhy">${d === 'na' ? 'Not applicable' : 'Risk accepted'}: ${esc(why(n, 'accept:' + r.tid)) || '<i>no justification</i>'}</div>` : ''}</td>
          <td>${(o.fulltext ? (r.t.text || [r.t.desc]) : [r.t.desc]).map((x) => `<p class="rp">${esc(x.replace(/\*/g, ''))}</p>`).join('')}${!o.fulltext && (r.t.text || []).length > 1 ? `<p class="rp rmore">Full text: emb3d.mitre.org/threats/${r.tid}.html</p>` : ''}</td><td>${cmCell}</td></tr>`;
      }).join('');
      return `<section class="rentity">
        <div class="rhead"><h3>${esc(n.name)} (${esc(def.name)})</h3>
        ${o.props ? `<p class="rprops">EMB3D properties: ${props.map((p) => `${p} ${esc(E.properties[p].name)}`).join('; ') || 'none'}</p>` : ''}</div>
        ${ts.length ? `<div class="rscroll"><table class="rtable rthreats"><colgroup><col style="width:3%"><col style="width:15%"><col style="width:8%"><col style="width:9%"><col style="width:10%"><col style="width:33%"><col style="width:22%"></colgroup><thead><tr><th>#</th><th>Threat</th><th>Type</th><th>Evidence</th><th>Status</th><th>Description</th><th>Countermeasures</th></tr></thead><tbody>${body}</tbody></table></div>` : '<p class="muted">No threats to report for this component.</p>'}
      </section>`;
    }).join('');
    const today = new Date().toISOString().slice(0, 10);
    $('view-report').innerHTML = `
      <div class="ropts no-print">
        <div class="ropt-row">
          ${[['diagram', 'Show model diagram'], ['mitigated', 'Show mitigated threats'], ['closed', 'Show not applicable and accepted threats'], ['empty', 'Show components without threats'], ['props', 'Show EMB3D properties'], ['fulltext', 'Full threat descriptions']]
            .map(([k, l]) => `<label class="check"><input type="checkbox" id="ro-${k}" data-ro="${k}" ${o[k] ? 'checked' : ''}><span>${l}</span></label>`).join('')}
          <button class="btn primary" id="btnPrint">Print / Save as PDF</button>
        </div>
        <div class="ropt-meta">
          <div class="field"><label for="rm-owner">Owner</label><input type="text" id="rm-owner" data-meta="owner" value="${esc(m.owner)}"></div>
          <div class="field"><label for="rm-reviewer">Reviewer</label><input type="text" id="rm-reviewer" data-meta="reviewer" value="${esc(m.reviewer)}"></div>
          <div class="field wide"><label for="rm-description">Description</label><textarea id="rm-description" data-meta="description" rows="2" placeholder="What the device is, where it is deployed, what is in scope">${esc(m.description)}</textarea></div>
        </div>
        <p class="small muted">Print opens your browser's print dialog; choose "Save as PDF". Sandboxed previews block printing, so use the app from its own folder or server.</p>
      </div>
      <article class="report">
        <p class="rbrand">${today} | EMB3D Workbench</p>
        <div class="rcard">
          <div class="rcard-h">Threat model report for ${esc(S.name)}</div>
          <table class="rkv"><tbody>
            <tr><th>Owner</th><td>${esc(m.owner) || '—'}</td><th>Reviewer</th><td>${esc(m.reviewer) || '—'}</td></tr>
            <tr><th>Threat catalogue</th><td>MITRE EMB3D STIX ${esc(E.version)}</td><th>Date generated</th><td>${today}</td></tr>
          </tbody></table>
        </div>
        <div class="rcard">
          <div class="rcard-h">Executive Summary</div>
          <h4>Description</h4><p class="rdesc">${esc(m.description) || 'Not provided'}</p>
          <h4>Summary</h4>
          <table class="rtable rsum"><thead><tr><th>Metric</th><th>Total</th></tr></thead><tbody>${stats.map(([k, v]) => `<tr><td>${k}</td><td class="num">${v}</td></tr>`).join('')}</tbody></table>
        </div>
        ${o.diagram ? `<section class="rpage"><h2>${esc(S.name)}</h2>${diagramSvg()}<p class="small muted">Dashed lines are unencrypted data flows.</p></section>` : ''}
        ${comps || '<p class="muted">No components match the report options.</p>'}
      </article>`;
    $('view-report').querySelectorAll('input[data-ro]').forEach((i) => i.addEventListener('change', () => { reportOpts[i.dataset.ro] = i.checked; renderReport(); }));
    $('view-report').querySelectorAll('[data-meta]').forEach((i) => {
      i.addEventListener('input', () => { S.meta[i.dataset.meta] = i.value; save(); });
      i.addEventListener('change', () => renderReport());
    });
    $('btnPrint').addEventListener('click', () => { document.title = `Threat model - ${S.name}`; window.print(); document.title = 'EMB3D Workbench'; });
  }

  /* ---------- boot ---------- */

  Promise.all([fetch('data/stix/index.json').then((r) => r.json()), fetch('library/components.json').then((r) => r.json())])
    .then(async ([idx, lib]) => {
      IDX = idx; LIB = lib;
      LIB.components.forEach((c) => { TYPES[c.type] = c; });
      S = load();
      S.nodes.forEach((n) => { n.why = n.why || {}; });
      if (!S.emb3d || !IDX.versions.some((v) => v.version === S.emb3d)) S.emb3d = IDX.default;
      E = await loadVersion(S.emb3d);
      renderVersionSelect();
      renderRail();
      wireChrome();
      render();
    })
    .catch((err) => {
      $('rail').innerHTML = `<div class="loading">Could not load the EMB3D data (${esc(err.message)}). If you opened index.html from disk, serve the folder instead, for example with <span class="mono">python3 -m http.server</span>.</div>`;
    });
})();
