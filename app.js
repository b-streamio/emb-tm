/* EMB3D Workbench — embedded threat modeling on top of MITRE EMB3D.
 * Plain JS, no build step. Data: MITRE's STIX files in data/stix/ (see index.json), library/components.json (hand-maintained).
 * Rules: component answers -> EMB3D properties -> threats -> mitigations.
 * A project has pages: the root page shows the system (device boxes), each device box opens its own page.
 */
(() => {
  'use strict';

  const STORE_KEY = 'emb3d-workbench/project';
  const ENGINE = window.EMB3D_ENGINE;
  const { esc, slug, groupClass, stateLabel, anchor, sizeOf, isDevice, NODE_W, CM_STATUS, MATURITY, MIT_RANK, NEEDS_WHY, EXT_KEY } = ENGINE;
  const BOARD_W = 1500, BOARD_H = 980;
  const MITRE_SITE = 'https://emb3d.mitre.org';

  let E = null;       // EMB3D data for the project's version
  let ENG = null;     // engine bound to E and the library (rebuild with setData)
  let IDX = null;     // data/stix/index.json
  const STIX = new Map(); // version -> parsed data
  const SESSION_VERSIONS = []; // versions fetched from emb3d.mitre.org for this session only
  let LIB = null;     // component library
  let S = null;       // project state
  let cur = null;     // id of the page shown on the board
  let sel = null;     // {kind:'node'|'flow', id}
  const multi = new Set(); // further selected node ids on the current page (shift/ctrl/cmd-click)
  let clip = null;    // internal clipboard (see copySelection)
  let pasteNudge = 0;
  let connectFrom = null;
  let openThreat = null;
  let view = 'diagram';
  let filters = { tState: 'all', tComp: 'all', cStatus: 'all' };
  let reportOpts = { diagram: true, mitigated: true, closed: true, empty: false, props: true, fulltext: false };

  const $ = (id) => document.getElementById(id);

  /* ---------- project state ---------- */

  const SAMPLE_URL = 'examples/system/connected-vision-system.project.json';

  function emptyProject() {
    return { name: 'Untitled system', root: 'p1', pages: [{ id: 'p1', name: 'System', nodes: [], flows: [] }], customTypes: [], seq: 1, flowSeq: 1, meta: { description: '', owner: '', reviewer: '' } };
  }

  function save() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(S)); } catch (_) { /* storage unavailable */ }
  }

  function load() {
    try {
      const raw = localStorage.getItem(STORE_KEY);
      if (raw) { const p = JSON.parse(raw); if (p && (Array.isArray(p.pages) || Array.isArray(p.nodes))) return p; }
    } catch (_) { /* ignore */ }
    return null;
  }

  async function sampleProject() {
    try { const r = await fetch(SAMPLE_URL); if (r.ok) return await r.json(); } catch (_) { /* fall through */ }
    return emptyProject();
  }

  const nodeById = (id) => ENG.nodeById(S, id);
  const T = (type) => ENG.TYPES[type];
  const curPage = () => ENG.pageById(S, cur) || ENG.pageById(S, S.root) || S.pages[0];
  const multiPage = () => S.pages.length > 1;

  function openPage(id) {
    if (!ENG.pageById(S, id)) return;
    cur = id; sel = null; openThreat = null; connectFrom = null;
    $('hint').hidden = true;
    if (view !== 'diagram') setView('diagram'); else render();
    $('boardwrap').scrollTo(0, 0);
  }

  // Root ... current page, following the first device box that uses each page.
  function pagePath(id) {
    const path = [];
    let p = ENG.pageById(S, id);
    for (let guard = 0; p && guard < 30; guard++) {
      path.unshift(p);
      if (p.id === S.root) break;
      const par = ENG.parentsOf(S, p.id)[0];
      p = par ? ENG.pageOf(par.id) : null;
    }
    if (path[0] && path[0].id !== S.root && ENG.pageById(S, S.root)) path.unshift(ENG.pageById(S, S.root));
    return path;
  }

  /* ---------- rules (engine.js) ---------- */

  function setData(data) { E = data; ENG = ENGINE.make(E, LIB); if (S) ENG.bind(S); }
  const answer = (node, q) => ENG.answer(node, q);
  const nodePids = (node) => ENG.nodePids(S, node);
  const nodeThreats = (node) => ENG.nodeThreats(S, node);
  const cmStatus = (node, mid) => ENG.cmStatus(node, mid);
  const why = (node, key) => ENG.why(node, key);
  const missingWhy = (node, mid) => ENG.missingWhy(node, mid);
  const decision = (node, tid) => ENG.decision(node, tid);
  const missingAcceptWhy = (node, tid) => ENG.missingAcceptWhy(node, tid);
  const threatState = (node, tid) => ENG.threatState(node, tid);
  const allRows = () => ENG.allRows(S);
  const cmRows = () => ENG.cmRows(S);
  function whyBox(node, key, label) {
    const v = (node.why && node.why[key]) || '';
    const fid = `why-${node.id}-${key.replace(/[^\w-]/g, '_')}`;
    return `<div class="why${v.trim() ? '' : ' missing'}"><label for="${fid}">${label}</label>
      <textarea id="${fid}" data-why="${esc(key)}" rows="2" placeholder="For example: this product variant has no network interface">${esc(v)}</textarea></div>`;
  }


  /* ---------- library rail ---------- */

  function renderRail() {
    const item = (c) => `
        <div class="libitem-row"><button class="libitem" draggable="true" data-type="${esc(c.type)}" title="${esc(c.hint)}">
          <span class="tag ${groupClass(c.group)}">${esc(c.tag)}</span><span class="libname">${esc(c.name)}</span>
        </button>${c.custom ? `<button class="iconbtn" data-editcustom="${esc(c.type)}" title="Edit ${esc(c.name)}" aria-label="Edit ${esc(c.name)}">✎</button>` : ''}</div>`;
    const customs = Object.values(ENG.TYPES).filter((c) => c.custom);
    const groups = LIB.groups.map((g) => {
      const items = LIB.components.filter((c) => c.group === g).map(item).join('');
      return `<div class="group"><p class="eyebrow">${esc(g)}</p><div class="lib">${items}</div></div>`;
    }).join('') + `<div class="group"><p class="eyebrow">Custom blocks</p><div class="lib">${customs.map(item).join('')}
        <button class="libitem addcustom" id="btnNewCustom"><span class="tag k-Custom">+</span><span class="libname">New custom block</span></button></div></div>`;
    $('rail').innerHTML = `<div class="pagesbox" id="pagesbox"></div><div class="groups">${groups}</div>
      <p class="note">Tap or drag a block onto the board, or drop it on a Device box to put it inside. Drag blocks onto a Device box to move them in; shift-click selects several; Ctrl/⌘ C, X, V copy, cut and paste (into the selected Device box). Custom blocks carry the EMB3D properties and threats you give them.</p>`;
    $('rail').querySelectorAll('.libitem[data-type]').forEach((b) => {
      b.addEventListener('click', () => addNode(b.dataset.type));
      b.addEventListener('dragstart', (e) => { e.dataTransfer.setData('text/x-emb3d', b.dataset.type); e.dataTransfer.effectAllowed = 'copy'; });
    });
    $('btnNewCustom').addEventListener('click', () => openCustomEditor(null));
    renderPages();
  }

  function renderPages() {
    const box = $('pagesbox');
    if (!box) return;
    const depth = new Map([[S.root, 0]]);
    ENG.pageOrder(S).forEach((p) => p.nodes.filter(isDevice).forEach((n) => { if (!depth.has(n.page)) depth.set(n.page, (depth.get(p.id) || 0) + 1); }));
    box.innerHTML = `<p class="eyebrow">Pages</p><ul class="pagelist">${ENG.pageOrder(S).map((p) => {
      const r = ENG.rollup(S, p.id);
      const unused = p.id !== S.root && !ENG.parentsOf(S, p.id).length;
      return `<li><button class="pagebtn${p.id === cur ? ' cur' : ''}" data-page="${esc(p.id)}" style="padding-left:${8 + (depth.get(p.id) || 0) * 14}px">
        <span class="pn">${esc(p.id === S.root ? (multiPage() ? 'System' : p.name) : p.name)}</span>${unused ? '<span class="unused">unused</span>' : ''}<span class="pc">${r.open}</span></button>
        ${unused ? `<button class="iconbtn" data-delpage="${esc(p.id)}" title="Delete page ${esc(p.name)}" aria-label="Delete page ${esc(p.name)}">×</button>` : ''}</li>`;
    }).join('')}</ul>
      <button class="btn small wide" id="btnAddDev">Add device from file…</button>`;
    box.querySelectorAll('.pagebtn').forEach((b) => b.addEventListener('click', () => openPage(b.dataset.page)));
    box.querySelectorAll('[data-delpage]').forEach((b) => {
      let armed = false;
      b.addEventListener('click', () => {
        if (!armed) { armed = true; b.textContent = 'Delete?'; b.classList.add('armed'); setTimeout(() => { armed = false; if (b.isConnected) { b.textContent = '×'; b.classList.remove('armed'); } }, 3000); return; }
        S.pages = S.pages.filter((p) => p.id !== b.dataset.delpage);
        if (cur === b.dataset.delpage) cur = S.root;
        commit();
      });
    });
    $('btnAddDev').addEventListener('click', () => $('devFile').click());
  }

  function renderCrumbs() {
    const c = $('crumbs');
    const path = pagePath(cur);
    c.hidden = !multiPage();
    if (c.hidden) return;
    c.innerHTML = path.map((p, i) => (i < path.length - 1
      ? `<button class="crumb" data-page="${esc(p.id)}">${esc(p.id === S.root ? 'System' : p.name)}</button><span class="sep">›</span>`
      : `<span class="crumb here">${esc(p.id === S.root ? 'System' : p.name)}</span>`)).join('');
    c.querySelectorAll('button[data-page]').forEach((b) => b.addEventListener('click', () => openPage(b.dataset.page)));
  }

  /* ---------- custom blocks ---------- */

  function nextId(prefix, taken) {
    let i = 1;
    while (taken.has(`${prefix}-${String(i).padStart(3, '0')}`)) i++;
    const id = `${prefix}-${String(i).padStart(3, '0')}`;
    taken.add(id);
    return id;
  }

  function customIdsInUse() {
    const ids = new Set();
    (S.customTypes || []).forEach((c) => (c.threats || []).forEach((t) => { ids.add(t.id); (t.cms || []).forEach((m) => ids.add(m.id)); }));
    return ids;
  }

  function openCustomEditor(typeId, copyFrom) {
    const existing = copyFrom ? null : (S.customTypes || []).find((c) => c.type === typeId);
    const ct = existing || (copyFrom
      ? { ...clone(copyFrom), type: '', name: copyFrom.name + ' (copy)', threats: clone(copyFrom.threats || []).map((t) => ({ ...t, id: '', cms: (t.cms || []).map((m) => ({ ...m, id: '' })) })) }
      : { type: '', name: '', group: 'Hardware', tag: '', hint: '', base: [], threats: [] });
    const groups = ['Hardware', 'System software', 'Application', 'Networking', 'Custom'];
    const cats = ['Hardware', 'System Software', 'Application Software', 'Networking'];
    const depth = (pid) => { let d = 0, p = E.properties[pid].parent; while (p) { d++; p = E.properties[p].parent; } return d; };
    const pidList = cats.map((cat) => {
      const ids = Object.keys(E.properties).filter((pid) => E.properties[pid].cat === cat).sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
      return `<div class="pidcat"><p class="lbl">${esc(cat)}</p>${ids.map((pid) => `<label class="check small" style="padding-left:${depth(pid) * 14}px"><input type="checkbox" data-pid="${pid}" ${ct.base.includes(pid) ? 'checked' : ''}><span><span class="tid">${pid}</span> ${esc(E.properties[pid].name)}</span></label>`).join('')}</div>`;
    }).join('');
    const threatRow = (t) => `<div class="cthreat" data-tid="${esc(t.id || '')}" data-cmid="${esc((t.cms && t.cms[0] && t.cms[0].id) || '')}">
        <div class="field"><label>Threat</label><input type="text" class="ct-name" value="${esc(t.name || '')}" placeholder="For example: Optical blinding of the sensor"></div>
        <div class="field"><label>Description</label><textarea class="ct-desc" rows="2">${esc(t.desc || '')}</textarea></div>
        <div class="field"><label>Countermeasure (optional)</label><input type="text" class="cm-name" value="${esc((t.cms && t.cms[0] && t.cms[0].name) || '')}" placeholder="For example: Detect blinding and alert"></div>
        <div class="field"><label>Countermeasure description</label><textarea class="cm-desc" rows="2">${esc((t.cms && t.cms[0] && t.cms[0].desc) || '')}</textarea></div>
        <button class="linkbtn small ct-del">Remove this threat</button></div>`;
    const used = existing && ENG.allNodes(S).filter((n) => n.type === existing.type).length;
    panel('', `<div class="dhead"><span class="eyebrow" style="margin:0">${existing ? 'Edit custom block' : 'New custom block'}</span></div>
      <h3>${existing ? esc(existing.name) : 'Custom block'}</h3>
      <div class="cform">
        <div class="field"><label for="cb-name">Name</label><input type="text" id="cb-name" value="${esc(ct.name)}" placeholder="For example: Image sensor module"></div>
        <div class="row2">
          <div class="field"><label for="cb-tag">Tag (up to 4 letters)</label><input type="text" id="cb-tag" maxlength="4" value="${esc(ct.tag)}" placeholder="CAM"></div>
          <div class="field"><label for="cb-group">Group</label><select id="cb-group" class="status">${groups.map((g) => `<option ${ct.group === g ? 'selected' : ''}>${g}</option>`).join('')}</select></div>
        </div>
        <div class="field"><label for="cb-hint">Description</label><input type="text" id="cb-hint" value="${esc(ct.hint)}"></div>
        <div><p class="eyebrow">EMB3D properties</p><p class="small muted">Every EMB3D threat linked to a ticked property applies to this block. Ticking a sub-property implies its parent.</p>
          <div class="pidlist">${pidList}</div></div>
        <div><p class="eyebrow">Custom threats</p><p class="small muted">Threats EMB3D does not cover. Each can have its own countermeasure.</p>
          <div id="cb-threats">${(ct.threats || []).map(threatRow).join('')}</div>
          <button class="btn small" id="cb-add">Add a threat</button></div>
        <p class="warn" id="cb-err" hidden></p>
        ${existing ? `<div class="row"><button class="btn small" id="cb-dup">Duplicate as a new type</button><button class="btn small danger" id="cb-delete" ${used ? 'disabled title="Remove the blocks of this type first"' : ''}>Delete block type</button>${used ? `<span class="small muted">Used by ${used} block${used > 1 ? 's' : ''}.</span>` : ''}</div>` : ''}
      </div>`, { label: existing ? 'Save block' : 'Create block', run: () => saveCustom(existing) });
    const wireRow = (row) => row.querySelector('.ct-del').addEventListener('click', () => row.remove());
    $('dBody').querySelectorAll('.cthreat').forEach(wireRow);
    $('cb-add').addEventListener('click', () => {
      const box = $('cb-threats');
      box.insertAdjacentHTML('beforeend', threatRow({}));
      wireRow(box.lastElementChild);
      box.lastElementChild.querySelector('.ct-name').focus();
    });
    if (existing) $('cb-dup').addEventListener('click', () => openCustomEditor(null, existing));
    if (existing && !used) {
      let armed = false;
      $('cb-delete').addEventListener('click', () => {
        if (!armed) { armed = true; $('cb-delete').textContent = 'Click again to delete'; return; }
        S.customTypes = S.customTypes.filter((c) => c !== existing);
        closeDetail(); commit();
      });
    }
    $('cb-name').focus();
  }

  function saveCustom(existing) {
    const name = $('cb-name').value.trim();
    const err = (m) => { $('cb-err').textContent = m; $('cb-err').hidden = false; };
    if (!name) return err('Give the block a name.');
    const base = [...$('dBody').querySelectorAll('input[data-pid]:checked')].map((i) => i.dataset.pid);
    const taken = customIdsInUse();
    const threats = [];
    for (const row of $('dBody').querySelectorAll('.cthreat')) {
      const tn = row.querySelector('.ct-name').value.trim();
      if (!tn) continue;
      const t = { id: row.dataset.tid || nextId('CUS', taken), name: tn, desc: row.querySelector('.ct-desc').value.trim(), cms: [] };
      const cn = row.querySelector('.cm-name').value.trim();
      if (cn) t.cms.push({ id: row.dataset.cmid || nextId('CUM', taken), name: cn, desc: row.querySelector('.cm-desc').value.trim() });
      threats.push(t);
    }
    if (!base.length && !threats.length) return err('Tick at least one EMB3D property or add a custom threat, otherwise the block has no threats.');
    const tag = ($('cb-tag').value.trim() || name.replace(/[^A-Za-z0-9]/g, '').slice(0, 3)).toUpperCase().slice(0, 4);
    const def = { type: existing ? existing.type : '', name, group: $('cb-group').value, tag, hint: $('cb-hint').value.trim() || 'Custom block', base, threats };
    S.customTypes = S.customTypes || [];
    if (existing) Object.assign(existing, def);
    else {
      let t = 'custom-' + (slug(name) || 'block');
      const types = new Set([...Object.keys(ENG.TYPES)]);
      for (let i = 2; types.has(t); i++) t = `custom-${slug(name) || 'block'}-${i}`;
      def.type = t;
      S.customTypes.push(def);
    }
    closeDetail();
    commit();
  }

  /* ---------- add a device from another project or a scanned image ---------- */

  function importAsDevice(text) {
    let obj;
    try { obj = JSON.parse(text); } catch (e) { return 'This is not valid JSON: ' + e.message; }
    const p = projectFrom(obj);
    if (!p) return 'This file is not an EMB3D Workbench project or a TM-BOM exported from it.';
    const v = ENG.validate(p);
    if (v.errors.length) { ENG.bind(S); return 'This project has problems:\n' + v.errors.slice(0, 8).join('\n'); }
    ENG.normalize(p);
    ENG.bind(S);
    // Custom block types: reuse ours when the type exists, otherwise bring them in with fresh threat ids if needed.
    const taken = customIdsInUse();
    const remap = {};
    (p.customTypes || []).forEach((ct) => {
      if (S.customTypes.some((c) => c.type === ct.type)) return;
      (ct.threats || []).forEach((t) => {
        if (taken.has(t.id)) { const n = nextId('CUS', taken); remap[t.id] = n; t.id = n; } else taken.add(t.id);
        (t.cms || []).forEach((m) => { if (taken.has(m.id)) { const n = nextId('CUM', taken); remap[m.id] = n; m.id = n; } else taken.add(m.id); });
      });
      S.customTypes.push(ct);
    });
    const rekey = (o) => Object.fromEntries(Object.entries(o || {}).map(([k, val]) => [remap[k] || (k.startsWith('accept:') && remap[k.slice(7)] ? 'accept:' + remap[k.slice(7)] : k), val]));
    const pageMap = {}, idMap = {};
    p.pages.forEach((pg) => { pageMap[pg.id] = newPageId(); S.pages.push({ id: pageMap[pg.id], name: '', nodes: [], flows: [] }); });
    p.pages.forEach((pg) => {
      const dst = ENG.pageById(S, pageMap[pg.id]);
      dst.name = pg.id === p.root ? p.name : pg.name;
      pg.nodes.forEach((n) => { idMap[n.id] = S.seq++; });
      dst.nodes = pg.nodes.map((n) => Object.assign({}, n, { id: idMap[n.id], page: n.page ? pageMap[n.page] : undefined, cm: rekey(n.cm), accepted: rekey(n.accepted), why: rekey(n.why) }));
      dst.flows = (pg.flows || []).map((f) => Object.assign({}, f, { id: S.flowSeq++, from: idMap[f.from], to: idMap[f.to] }));
    });
    const here = curPage();
    const w = $('boardwrap');
    const dev = { id: S.seq++, type: 'device', name: p.name, qty: 1, page: pageMap[p.root], x: Math.round(w.scrollLeft + 60 + (here.nodes.length % 5) * 30), y: Math.round(w.scrollTop + 60 + (here.nodes.length % 5) * 30), answers: {}, cm: {}, accepted: {}, why: {} };
    here.nodes.push(dev);
    sel = { kind: 'node', id: dev.id };
    commit();
    return null;
  }

  function newPageId() {
    let i = S.pages.length + 1;
    while (ENG.pageById(S, 'p' + i)) i++;
    return 'p' + i;
  }

  function addNode(type, x, y, intoDev) {
    const def = T(type);
    if (!def) return;
    const pg = intoDev ? ENG.pageById(S, intoDev.page) : curPage();
    if (intoDev) { x = 0; y = 0; }
    if (x === undefined) {
      const w = $('boardwrap');
      const k = pg.nodes.length % 6;
      x = w.scrollLeft + Math.max(20, w.clientWidth / 2 - NODE_W / 2) + k * 18;
      y = w.scrollTop + Math.max(20, w.clientHeight / 2 - 40) + k * 18;
    }
    const answers = {};
    def.questions.forEach((q) => { answers[q.id] = q.default; });
    const node = { id: S.seq++, type, name: def.name, x: Math.round(x), y: Math.round(y), answers, cm: {}, accepted: {}, why: {} };
    if (type === 'device') {
      const n = ENG.allNodes(S).filter(isDevice).length + 1;
      node.name = `Device ${n}`;
      node.qty = 1;
      node.page = newPageId();
      S.pages.push({ id: node.page, name: node.name, nodes: [], flows: [] });
    }
    pg.nodes.push(node);
    if (intoDev) {
      placeOnPage(pg, [node]);
      sel = { kind: 'node', id: intoDev.id }; multi.clear(); openThreat = null;
      commit();
      toast(`Added ${def.name} to ${intoDev.name}.`);
      return;
    }
    sel = { kind: 'node', id: node.id };
    multi.clear();
    openThreat = null;
    commit();
  }

  /* ---------- board ---------- */

  function renderBoard() {
    const board = $('board');
    board.querySelectorAll('.node').forEach((el) => el.remove());
    curPage().nodes.forEach((node) => {
      const def = T(node.type) || { group: 'External', tag: '?', name: node.type };
      const el = document.createElement('div');
      el.className = 'node' + (def.external ? ' ext' : '') + (isDevice(node) ? ' device' : '') + (def.custom ? ' custom' : '') + (sel && sel.kind === 'node' && sel.id === node.id ? ' sel' : '') + (multi.has(node.id) ? ' sel multi' : '') + (connectFrom ? ' target' : '');
      el.style.left = node.x + 'px';
      el.style.top = node.y + 'px';
      el.dataset.id = node.id;
      el.tabIndex = 0;
      let meta = '';
      if (isDevice(node)) {
        const r = ENG.rollup(S, node.page);
        meta = `<div class="meta"><span class="dot open">${r.open} open</span><span class="dot done">${r.threats - r.open} handled</span>${r.review ? `<span class="rvcount" title="${r.review} answers need review">${r.review}?</span>` : ''}</div>
          <div class="devhint">${esc((ENG.pageById(S, node.page) || {}).name || '')} · double-click to open</div>`;
      } else if (!def.external) {
        const ts = nodeThreats(node);
        const open = ts.filter((r) => threatState(node, r.tid) === 'Open').length;
        const rv = Object.values(node.review || {}).filter(Boolean).length;
        meta = `<div class="meta"><span class="dot open">${open} open</span><span class="dot done">${ts.length - open} handled</span>${rv ? `<span class="rvcount" title="${rv} answers need review">${rv}?</span>` : ''}</div>`;
      } else {
        meta = '<div class="meta">external</div>';
      }
      el.innerHTML = `<div class="top"><span class="tag ${groupClass(def.group)}">${esc(def.tag)}</span><span class="mono muted">#${node.id}</span></div>
        <div class="nm">${esc(node.name)}${isDevice(node) && node.qty > 1 ? ` <span class="qty">×${node.qty}</span>` : ''}</div>${meta}`;
      board.appendChild(el);
      wireNode(el, node);
    });
    renderEdges();
  }

  const lastTap = { id: null, t: 0 };
  function wireNode(el, node) {
    let start = null;
    el.addEventListener('pointerdown', (e) => {
      if (e.button !== 0) return;
      // Dragging a selected block drags the whole selection.
      const ids = (selectedIds().includes(node.id) ? selectedIds() : [node.id]);
      const group = ids.map((id) => nodeById(id)).filter(Boolean).map((n) => ({ n, x: n.x, y: n.y }));
      start = { px: e.clientX, py: e.clientY, group, moved: false, target: null };
      el.setPointerCapture(e.pointerId);
    });
    el.addEventListener('pointermove', (e) => {
      if (!start) return;
      const dx = e.clientX - start.px, dy = e.clientY - start.py;
      if (!start.moved && Math.hypot(dx, dy) < 4) return;
      start.moved = true;
      start.group.forEach((g) => {
        g.n.x = Math.max(0, Math.min(BOARD_W - sizeOf(g.n)[0], g.x + dx));
        g.n.y = Math.max(0, Math.min(BOARD_H - sizeOf(g.n)[1], g.y + dy));
        const ge = document.querySelector(`#board .node[data-id="${g.n.id}"]`);
        if (ge) { ge.style.left = g.n.x + 'px'; ge.style.top = g.n.y + 'px'; }
      });
      const t = deviceAt(e.clientX, e.clientY, new Set(start.group.map((g) => g.n.id)));
      if (t !== start.target) { start.target = t; markDropTarget(t); }
      renderEdges();
    });
    const end = (e) => {
      if (!start) return;
      const moved = start.moved;
      const st = start;
      start = null;
      markDropTarget(null);
      if (moved && st.target) {
        st.group.forEach((g) => { g.n.x = g.x; g.n.y = g.y; }); // positions are recomputed on the device page
        moveIntoDevice(st.group.map((g) => g.n.id), st.target);
        return;
      }
      if (moved) { save(); return; }
      // The board re-renders on every click, so a native dblclick never reaches the same element:
      // detect a double click (or double tap) on the same node id instead.
      const now = Date.now();
      if (isDevice(node) && lastTap.id === node.id && now - lastTap.t < 450 && connectFrom === null) { lastTap.id = null; openPage(node.page); return; }
      lastTap.id = node.id; lastTap.t = now;
      clickNode(node, e);
    };
    el.addEventListener('pointerup', end);
    el.addEventListener('pointercancel', () => { start = null; save(); });
    el.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); clickNode(node); } });
  }

  function clickNode(node, ev) {
    if (connectFrom === null && ev && (ev.shiftKey || ev.ctrlKey || ev.metaKey) && sel && sel.kind === 'node') {
      if (sel.id === node.id) { /* keep primary */ } else if (multi.has(node.id)) multi.delete(node.id); else multi.add(node.id);
      renderBoard(); renderInspector();
      return;
    }
    multi.clear();
    if (connectFrom !== null) {
      if (connectFrom !== node.id) {
        const f = { id: S.flowSeq++, from: connectFrom, to: node.id, label: 'data flow', encrypted: false, sensitive: false };
        curPage().flows.push(f);
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

  /* ---------- selection, moving into devices, copy and paste ---------- */

  function selectedIds() {
    if (!sel || sel.kind !== 'node') return [];
    const here = new Set(curPage().nodes.map((n) => n.id));
    return [sel.id, ...multi].filter((id) => here.has(id));
  }

  // Device box on the current page under a screen point, ignoring the given node ids.
  function deviceAt(cx, cy, skip) {
    const r = $('board').getBoundingClientRect();
    const x = cx - r.left, y = cy - r.top;
    return curPage().nodes.find((n) => isDevice(n) && !(skip && skip.has(n.id)) && x >= n.x && y >= n.y && x <= n.x + sizeOf(n)[0] && y <= n.y + sizeOf(n)[1]) || null;
  }

  function markDropTarget(dev) {
    document.querySelectorAll('#board .node.droptarget').forEach((el) => el.classList.remove('droptarget'));
    if (dev) { const el = document.querySelector(`#board .node[data-id="${dev.id}"]`); if (el) el.classList.add('droptarget'); }
  }

  // Pages reachable from a page through device boxes (the page itself included).
  function subtreePages(pageId, out = new Set()) {
    if (out.has(pageId)) return out;
    out.add(pageId);
    const pg = ENG.pageById(S, pageId);
    if (pg) pg.nodes.filter(isDevice).forEach((d) => subtreePages(d.page, out));
    return out;
  }

  // Put nodes below whatever the page already holds, keeping their arrangement.
  function placeOnPage(pg, nodes) {
    if (!nodes.length) return;
    const minX = Math.min(...nodes.map((n) => n.x)), minY = Math.min(...nodes.map((n) => n.y));
    const others = pg.nodes.filter((n) => !nodes.includes(n));
    const top = others.length ? Math.max(...others.map((n) => n.y + sizeOf(n)[1])) + 40 : 60;
    nodes.forEach((n) => {
      n.x = Math.max(0, Math.min(BOARD_W - sizeOf(n)[0], Math.round(n.x - minX + 60)));
      n.y = Math.max(0, Math.min(BOARD_H - sizeOf(n)[1], Math.round(n.y - minY + top)));
    });
  }

  let toastTimer = null;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 4200);
  }

  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

  function moveIntoDevice(ids, dev) {
    const src = curPage();
    const target = ENG.pageById(S, dev.page);
    if (!target || ids.includes(dev.id)) return;
    const moving = src.nodes.filter((n) => ids.includes(n.id));
    const loop = moving.find((n) => isDevice(n) && subtreePages(n.page).has(target.id));
    if (loop) { toast(`"${loop.name}" contains "${dev.name}", so it cannot go inside it.`); renderBoard(); return; }
    const idSet = new Set(moving.map((n) => n.id));
    const inside = src.flows.filter((f) => idSet.has(f.from) && idSet.has(f.to));
    const cut = src.flows.filter((f) => (idSet.has(f.from) !== idSet.has(f.to)));
    src.nodes = src.nodes.filter((n) => !idSet.has(n.id));
    src.flows = src.flows.filter((f) => !idSet.has(f.from) && !idSet.has(f.to));
    target.nodes.push(...moving);
    target.flows.push(...inside);
    placeOnPage(target, moving);
    sel = { kind: 'node', id: dev.id }; multi.clear(); openThreat = null;
    commit();
    toast(`Moved ${plural(moving.length, 'block')} into ${dev.name}.` + (cut.length ? ` ${plural(cut.length, 'data flow')} to blocks outside it ${cut.length === 1 ? 'was' : 'were'} removed.` : ''));
  }

  const CLIP_KEY = 'emb3dWorkbenchClipboard';
  const clone = (o) => JSON.parse(JSON.stringify(o));

  // Self-contained copy of some blocks of the current page, with the design pages of any devices among them.
  function buildClip(ids) {
    const pg = curPage();
    const nodes = pg.nodes.filter((n) => ids.includes(n.id));
    const idSet = new Set(ids);
    const pageIds = new Set();
    nodes.filter(isDevice).forEach((d) => subtreePages(d.page, pageIds));
    const pages = S.pages.filter((p) => pageIds.has(p.id));
    const types = new Set([...nodes, ...pages.flatMap((p) => p.nodes)].map((n) => n.type));
    return clone({
      [CLIP_KEY]: 1, emb3d: S.emb3d, nodes, pages,
      flows: pg.flows.filter((f) => idSet.has(f.from) && idSet.has(f.to)),
      customTypes: (S.customTypes || []).filter((c) => types.has(c.type)),
    });
  }

  function copySelection(cutToo) {
    const ids = selectedIds();
    if (!ids.length) return false;
    const pg = curPage();
    const idSet = new Set(ids);
    const pageIds = new Set();
    pg.nodes.filter((n) => idSet.has(n.id) && isDevice(n)).forEach((d) => subtreePages(d.page, pageIds));
    clip = buildClip(ids);
    const nodes = clip.nodes, pages = clip.pages;
    pasteNudge = 0;
    try { navigator.clipboard.writeText(JSON.stringify(clip)).catch(() => {}); } catch (_) { /* internal clipboard still works */ }
    if (cutToo) {
      pg.nodes = pg.nodes.filter((n) => !idSet.has(n.id));
      pg.flows = pg.flows.filter((f) => !idSet.has(f.from) && !idSet.has(f.to));
      // Pages only these boxes used leave with them (they travel in the clipboard).
      const stillUsed = new Set();
      S.pages.filter((p) => !pageIds.has(p.id)).forEach((p) => p.nodes.filter(isDevice).forEach((d) => stillUsed.add(d.page)));
      S.pages = S.pages.filter((p) => !pageIds.has(p.id) || stillUsed.has(p.id) || p.id === S.root);
      sel = null; multi.clear();
      commit();
    }
    toast(`${cutToo ? 'Cut' : 'Copied'} ${plural(nodes.length, 'block')}${pages.length ? ` with ${plural(pages.length, 'device page')}` : ''}. Select a device box and paste to put ${nodes.length === 1 ? 'it' : 'them'} inside.`);
    return true;
  }

  function pasteClip(c, opts = {}) {
    if (!c || !Array.isArray(c.nodes) || !c.nodes.length) return false;
    // Paste into the selected device box, else onto the current page.
    const selNode = !opts.here && sel && sel.kind === 'node' && !multi.size ? nodeById(sel.id) : null;
    const intoDev = selNode && isDevice(selNode) ? selNode : null;
    const target = intoDev ? ENG.pageById(S, intoDev.page) : curPage();
    // Pasted devices get fresh pages, so a paste can never create a loop.
    (c.customTypes || []).forEach((ct) => { if (!ENG.TYPES[ct.type]) { S.customTypes = S.customTypes || []; S.customTypes.push(clone(ct)); } });
    ENG.bind(S);
    const unknown = c.nodes.concat(c.pages.flatMap((p) => p.nodes)).filter((n) => !ENG.TYPES[n.type]).map((n) => n.type);
    if (unknown.length) { toast('Cannot paste: unknown block types ' + [...new Set(unknown)].join(', ')); return true; }
    const pageMap = {}, idMap = {};
    c.pages.forEach((p) => { pageMap[p.id] = newPageId(); S.pages.push({ id: pageMap[p.id], name: p.name, nodes: [], flows: [] }); });
    const fresh = (n) => { const m = clone(n); idMap[n.id] = m.id = S.seq++; if (isDevice(m)) m.page = pageMap[n.page] || m.page; return m; };
    const remapFlow = (f) => ({ ...clone(f), id: S.flowSeq++, from: idMap[f.from], to: idMap[f.to] });
    c.pages.forEach((p) => {
      const np = ENG.pageById(S, pageMap[p.id]);
      np.nodes = p.nodes.map(fresh);
      np.flows = p.flows.filter((f) => idMap[f.from] && idMap[f.to]).map(remapFlow);
    });
    const added = c.nodes.map(fresh);
    if (opts.suffix) added.forEach((n) => { n.name += opts.suffix; if (isDevice(n)) { const np = ENG.pageById(S, n.page); if (np) np.name = n.name; } });
    target.nodes.push(...added);
    target.flows.push(...c.flows.filter((f) => idMap[f.from] && idMap[f.to]).map(remapFlow));
    if (intoDev) placeOnPage(target, added);
    else { pasteNudge += 30; added.forEach((n) => { n.x = Math.min(BOARD_W - sizeOf(n)[0], n.x + pasteNudge); n.y = Math.min(BOARD_H - sizeOf(n)[1], n.y + pasteNudge); }); }
    if (c.emb3d && c.emb3d !== S.emb3d) toast(`Pasted blocks made with EMB3D ${c.emb3d}; this project uses ${S.emb3d}.`);
    if (intoDev) { sel = { kind: 'node', id: intoDev.id }; multi.clear(); }
    else { sel = { kind: 'node', id: added[0].id }; multi.clear(); added.slice(1).forEach((n) => multi.add(n.id)); }
    commit();
    toast(opts.message || `Pasted ${plural(added.length, 'block')}${intoDev ? ` into ${intoDev.name}` : ''}.`);
    return true;
  }

  // An independent copy of the selection next to it: devices get their own copy of the design to change freely.
  function duplicateSelection() {
    const ids = selectedIds();
    if (!ids.length) return false;
    const c = buildClip(ids);
    const keepNudge = pasteNudge;
    pasteNudge = 0;
    pasteClip(c, { here: true, suffix: ' (copy)', message: `Duplicated ${plural(c.nodes.length, 'block')}${c.pages.length ? ' with their own design pages' : ''}. Change the copy freely.` });
    pasteNudge = keepNudge;
    return true;
  }

  // Deep copy of a design page and the device pages below it. Returns the new top page id.
  function cloneDesign(pageId, name) {
    const ids = [...subtreePages(pageId)];
    const pageMap = {}, idMap = {};
    ids.forEach((id) => { pageMap[id] = newPageId(); S.pages.push({ id: pageMap[id], name: '', nodes: [], flows: [] }); });
    ids.forEach((id) => {
      const src = ENG.pageById(S, id), dst = ENG.pageById(S, pageMap[id]);
      dst.name = id === pageId && name ? name : src.name;
      dst.nodes = src.nodes.map((n) => { const m = clone(n); idMap[n.id] = m.id = S.seq++; if (isDevice(m) && pageMap[n.page]) m.page = pageMap[n.page]; return m; });
      dst.flows = src.flows.filter((f) => idMap[f.from] && idMap[f.to]).map((f) => ({ ...clone(f), id: S.flowSeq++, from: idMap[f.from], to: idMap[f.to] }));
    });
    return pageMap[pageId];
  }

  // This box stops sharing its design page with other boxes.
  function detachDesign(node) {
    node.page = cloneDesign(node.page, node.name);
    commit();
    toast(`${node.name} now has its own copy of the design. Changes to it no longer affect the other boxes.`);
  }

  // Take one unit out of a "×N" box into its own box with its own copy of the design.
  function splitUnit(node) {
    if (!(node.qty > 1)) return;
    node.qty -= 1;
    const one = clone(node);
    one.id = S.seq++;
    one.qty = 1;
    one.name = `${node.name} (variant)`;
    one.page = cloneDesign(node.page, one.name);
    one.x = Math.min(BOARD_W - sizeOf(one)[0], node.x + 40);
    one.y = Math.min(BOARD_H - sizeOf(one)[1], node.y + sizeOf(node)[1] + 30);
    const pg = curPage();
    pg.nodes.push(one);
    pg.flows.filter((f) => f.from === node.id || f.to === node.id).forEach((f) => pg.flows.push({ ...clone(f), id: S.flowSeq++, from: f.from === node.id ? one.id : f.from, to: f.to === node.id ? one.id : f.to }));
    sel = { kind: 'node', id: one.id }; multi.clear();
    commit();
    toast(`Split one unit out: ${node.name} ×${node.qty} and ${one.name} ×1, which has its own design to change.`);
  }

  function moveControls(node) {
    const devs = curPage().nodes.filter((n) => isDevice(n) && n.id !== node.id);
    return `<div class="row movebar">
      <button class="btn small" data-act="dup" title="Ctrl/Cmd+D">Duplicate</button><button class="btn small" data-act="copy" title="Ctrl/Cmd+C">Copy</button><button class="btn small" data-act="cut" title="Ctrl/Cmd+X">Cut</button>
      ${clip ? `<button class="btn small" data-act="paste" title="Ctrl/Cmd+V">${isDevice(node) ? 'Paste inside' : 'Paste'}</button>` : ''}
      ${devs.length ? `<select class="status" id="mv-${node.id}" aria-label="Move into a device"><option value="">Move into device…</option>${devs.map((d) => `<option value="${d.id}">${esc(d.name)}</option>`).join('')}</select>` : ''}
      ${multi.size ? `<span class="small muted">${multi.size + 1} blocks selected</span>` : ''}</div>`;
  }

  function wireMoveControls(node) {
    const ins = $('inspector');
    ins.querySelectorAll('[data-act]').forEach((b) => b.addEventListener('click', () => {
      if (b.dataset.act === 'dup') duplicateSelection();
      if (b.dataset.act === 'copy') { copySelection(false); renderInspector(); }
      if (b.dataset.act === 'cut') copySelection(true);
      if (b.dataset.act === 'paste') pasteClip(clip);
    }));
    const mv = $('mv-' + node.id);
    if (mv) mv.addEventListener('change', () => { const d = nodeById(Number(mv.value)); if (d) moveIntoDevice(selectedIds().length ? selectedIds() : [node.id], d); });
  }

  function renderEdges() {
    const svg = $('edges');
    let out = `<defs>
      <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="arrowhead" d="M0,0 L10,5 L0,10 z"></path></marker>
      <marker id="arrSel" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" style="fill:var(--accent)"></path></marker></defs>`;
    curPage().flows.forEach((f) => {
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
    const fl = sel && sel.kind === 'flow' && curPage().flows.find((f) => f.id === sel.id);
    if (fl) return renderFlowInspector(ins, fl);
    sel = null;
    const pg = curPage();
    const isRoot = pg.id === S.root;
    const r = ENG.rollup(S, pg.id);
    const all = allRows();
    const cms = cmRows();
    const users = ENG.parentsOf(S, pg.id);
    ins.innerHTML = `<div class="empty">
      <p class="eyebrow">${isRoot ? (multiPage() ? 'System' : 'Device') : 'Device page'}</p><h2>${esc(isRoot ? S.name : pg.name)}</h2>
      ${!isRoot ? `<div class="field" style="margin-top:12px"><label for="pgname">Page name</label><input type="text" id="pgname" value="${esc(pg.name)}"></div>
        <p class="small muted">${users.length ? 'Used by ' + users.map((u) => esc(u.name) + (u.qty > 1 ? ' ×' + u.qty : '')).join(', ') : 'Not used by any device box.'}</p>` : ''}
      <div class="stats">
        <div class="stat"><b>${pg.nodes.length}</b><span>blocks on this page</span></div>
        <div class="stat"><b>${pg.flows.length}</b><span>data flows on this page</span></div>
        <div class="stat open"><b>${r.open}</b><span>open threats${isRoot ? '' : ' in this device'}</span></div>
        <div class="stat done"><b>${cms.filter((c) => c.status === 'implemented').length}</b><span>countermeasures implemented of ${cms.length} (whole model)</span></div>
      </div>
      ${ENG.reviewItems(S).length ? `<p class="small"><span class="pill st-Open">${ENG.reviewItems(S).length} answers need review</span> These were not determined from the source and use a default. Blocks with them are marked on the board.</p>` : ''}
      ${S.generator ? `<p class="small muted">Generated from ${esc(S.generator.source || '')}${S.generator.revision ? ' @ ' + esc(S.generator.revision) : ''}${S.generator.tool ? ' by ' + esc(S.generator.tool) : ''}.</p>` : ''}
      <p class="small">Select a block to answer its questions and work through its threats. A <b>Device</b> box stands for a whole device: double-click it to design its inside on its own page. Use <b>Draw data flow</b> to connect blocks on the same page.</p>
      <p class="small">${all.length} threats in the whole model, from MITRE EMB3D STIX ${esc(E.version)} and your custom blocks. EMB3D rates evidence, not severity, so threats are ordered by how much real-world evidence exists for them.</p>
    </div>`;
    const pn = $('pgname');
    if (pn) pn.addEventListener('input', (e) => { pg.name = e.target.value; save(); renderCrumbs(); renderPages(); });
  }

  // Evidence and review flags written by the Yocto skill (or any other generator).
  const qFlag = (node, q) => (node.review && node.review[q.id] ? ' review' : '');
  function qExtra(node, q) {
    const ev = (node.evidence && node.evidence[q.id]) || [];
    const rv = node.review && node.review[q.id];
    return (rv ? `<div class="qreview"><span class="pill st-Open">Needs review</span>${rv === true ? '' : ' ' + esc(rv)} <button class="linkbtn small" data-confirm="${q.id}">Mark as reviewed</button></div>` : '')
      + (ev.length ? `<ul class="qev">${ev.map((e) => `<li><span class="mono">${esc(e.file)}${e.line ? ':' + e.line : ''}</span>${e.text ? ` <span class="evtext">${esc(e.text)}</span>` : ''}</li>`).join('')}</ul>` : '');
  }

  function renderDeviceInspector(ins, node) {
    const r = ENG.rollup(S, node.page);
    // A device may not use a page that contains it (directly or further up).
    const ancestors = new Set(pagePath(cur).map((p) => p.id));
    const choices = S.pages.filter((p) => !ancestors.has(p.id));
    ins.innerHTML = `
      <p class="eyebrow"><span class="k-System">System</span> · Device</p>
      <div class="field"><label for="nm-${node.id}">Name</label><input type="text" id="nm-${node.id}" value="${esc(node.name)}"></div>
      <div class="field"><label for="qty-${node.id}">Quantity of identical units</label><input type="number" min="1" step="1" id="qty-${node.id}" value="${node.qty || 1}" class="qtyin"></div>
      <div class="field"><label for="pg-${node.id}">Design page</label><select id="pg-${node.id}" class="status">
        ${choices.map((p) => `<option value="${esc(p.id)}" ${p.id === node.page ? 'selected' : ''}>${esc(p.name)}</option>`).join('')}
        <option value="__new">New empty page</option></select></div>
      <p class="small muted">Boxes that share a design page share its threats and decisions: model a camera once and use it for every camera.</p>
      ${(() => {
        const sharers = ENG.parentsOf(S, node.page).filter((n) => n.id !== node.id);
        const parts = [];
        if (node.qty > 1) parts.push(`<button class="btn small" id="btnSplit">Split one unit out to modify</button>`);
        if (sharers.length) parts.push(`<button class="btn small" id="btnDetach">Use a separate copy of the design</button>`);
        return parts.length ? `<div class="variant"><p class="small">${node.qty > 1 ? `All ${node.qty} units use one design. ` : ''}${sharers.length ? `This design is also used by ${sharers.map((n) => esc(n.name)).join(', ')}. ` : ''}To change one of them, make it separate first.</p><div class="row">${parts.join('')}</div></div>` : '';
      })()}
      <div class="row"><button class="btn small primary" id="btnOpen">Open design</button><button class="btn small" id="btnConnect">Draw data flow</button><button class="btn small danger" id="btnDel">Delete</button></div>
      ${moveControls(node)}
      <div class="stats" style="margin-top:14px">
        <div class="stat"><b>${(ENG.pageById(S, node.page) || { nodes: [] }).nodes.length}</b><span>blocks inside</span></div>
        <div class="stat open"><b>${r.open}</b><span>open threats of ${r.threats}</span></div>
      </div>
      ${r.review ? `<p class="small"><span class="pill st-Open">${r.review} answers need review</span> inside this device.</p>` : ''}`;
    $('nm-' + node.id).addEventListener('input', (e) => {
      const pgx = ENG.pageById(S, node.page);
      if (pgx && pgx.name === node.name && ENG.parentsOf(S, pgx.id).length === 1) pgx.name = e.target.value; // keep page name in step while it matches
      node.name = e.target.value; save(); renderBoard(); renderPages();
    });
    $('qty-' + node.id).addEventListener('change', (e) => { node.qty = Math.max(1, parseInt(e.target.value, 10) || 1); commit(); });
    $('pg-' + node.id).addEventListener('change', (e) => {
      if (e.target.value === '__new') { node.page = newPageId(); S.pages.push({ id: node.page, name: node.name, nodes: [], flows: [] }); }
      else node.page = e.target.value;
      commit();
    });
    $('btnOpen').addEventListener('click', () => openPage(node.page));
    if ($('btnSplit')) $('btnSplit').addEventListener('click', () => splitUnit(node));
    if ($('btnDetach')) $('btnDetach').addEventListener('click', () => detachDesign(node));
    wireMoveControls(node);
    $('btnConnect').addEventListener('click', () => { connectFrom = node.id; $('hint').hidden = false; renderBoard(); });
    armDelete($('btnDel'), () => { removeNode(node); });
  }

  // Remove a block from the current page; a device's page goes too when nothing else uses it and it is empty.
  function removeNode(node) {
    const pg = curPage();
    pg.nodes = pg.nodes.filter((n) => n.id !== node.id);
    pg.flows = pg.flows.filter((f) => f.from !== node.id && f.to !== node.id);
    if (isDevice(node)) {
      const sub = ENG.pageById(S, node.page);
      if (sub && !sub.nodes.length && !ENG.allNodes(S).some((n) => isDevice(n) && n.page === sub.id)) S.pages = S.pages.filter((p) => p !== sub);
    }
    sel = null; commit();
  }

  function renderNodeInspector(ins, node) {
    if (isDevice(node)) return renderDeviceInspector(ins, node);
    const def = T(node.type);
    const pids = nodePids(node);
    const qs = def.questions.map((q) => {
      const a = answer(node, q);
      if (q.kind === 'bool') {
        return `<div class="q${qFlag(node, q)}"><label class="check"><input type="checkbox" id="q-${node.id}-${q.id}" data-q="${q.id}" ${a ? 'checked' : ''}><span>${esc(q.text)}</span></label>${qExtra(node, q)}</div>`;
      }
      const opts = q.options.map((o) => `<label class="radio"><input type="radio" name="q-${node.id}-${q.id}" id="q-${node.id}-${q.id}-${o.value}" data-q="${q.id}" value="${esc(o.value)}" ${a === o.value ? 'checked' : ''}><span>${esc(o.label)}</span></label>`).join('');
      return `<div class="q${qFlag(node, q)}"><span class="qt">${esc(q.text)}</span><div class="radios">${opts}</div>${qExtra(node, q)}</div>`;
    }).join('');

    let threatsHtml = '';
    if (!def.external) {
      const ts = nodeThreats(node);
      threatsHtml = `<div class="sect"><p class="eyebrow">Threats · ${ts.length}</p>` + (ts.length ? ts.map(({ tid, t, via }) => {
        const st = threatState(node, tid);
        const mat = MATURITY[t.maturity] || [9, t.maturity];
        const cms = t.mids.filter((m) => ENG.mitigation(m)).sort((a, b) => (MIT_RANK[ENG.mitigation(a).maturity] ?? 9) - (MIT_RANK[ENG.mitigation(b).maturity] ?? 9)).map((mid) => {
          const m = ENG.mitigation(mid);
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
            ${t.custom ? '' : `<div class="row"><button class="linkbtn small" data-detail="${tid}">Read more</button><a class="extlink" href="${mitreUrl(tid)}" target="_blank" rel="noopener">${tid} on emb3d.mitre.org ↗</a></div>`}
            <p class="small"><span class="lbl">Applies because of</span> ${t.custom ? `custom threat of the "${esc(def.name)}" block` : via.map((p) => `<span class="tid" title="${esc(E.properties[p].name)}">${p}</span>`).join(', ')}</p>
            ${cwes}
            <div class="cms">${cms || `<span class="muted small">${t.custom ? 'No countermeasure defined for this custom threat.' : 'EMB3D lists no mitigation for this threat.'}</span>`}</div>
            <div class="row small"><label for="acc-${node.id}-${tid}" class="lbl">Decision for this threat</label>
              <select class="status" id="acc-${node.id}-${tid}" data-accept="${tid}">
                ${[['', 'Handle with countermeasures'], ['na', 'Not applicable'], ['accept', 'Accept the risk']].map(([v, l]) => `<option value="${v}" ${decision(node, tid) === v ? 'selected' : ''}>${l}</option>`).join('')}
              </select></div>
            ${decision(node, tid) ? whyBox(node, 'accept:' + tid, decision(node, tid) === 'na' ? 'Why does this threat not apply?' : 'Why is the risk accepted?') : ''}
          </div></details>`;
      }).join('') : '<p class="muted small">No threats for the current answers.</p>') + '</div>';
    }

    const pidChips = [...pids.entries()].sort().map(([p, why]) => `<span class="pid${why === 'rule' ? ' rule' : ''}" title="${esc(E.properties[p].name)}${why === 'rule' ? ' (added because the model has no update agent)' : ''}">${p}</span>`).join('');

    ins.innerHTML = `
      <p class="eyebrow"><span class="${groupClass(def.group)}">${esc(def.group)}</span> · ${esc(def.name)}</p>
      <div class="field"><label for="nm-${node.id}">Name</label><input type="text" id="nm-${node.id}" value="${esc(node.name)}"></div>
      <p class="small muted">${esc(def.hint)}${def.custom ? ` <button class="linkbtn small" data-editcustom="${esc(def.type)}">Edit block type</button>` : ''}</p>
      ${node.evidence && node.evidence._component ? `<div class="q${qFlag(node, { id: '_component' })}"><span class="lbl">Identified from</span><ul class="qev">${node.evidence._component.map((e) => `<li><span class="mono">${esc(e.file)}${e.line ? ':' + e.line : ''}</span>${e.text ? ` <span class="evtext">${esc(e.text)}</span>` : ''}</li>`).join('')}</ul>${qExtra(node, { id: '_component' }).replace(/<ul class="qev">[\s\S]*$/, '')}</div>` : (node.review && node.review._component ? `<div class="q review">${qExtra(node, { id: '_component' })}</div>` : '')}
      <div class="row">
        <button class="btn small" id="btnConnect">Draw data flow</button>
        <button class="btn small danger" id="btnDel">Delete</button>
      </div>
      ${moveControls(node)}
      ${qs ? `<div class="sect"><p class="eyebrow">Questions</p>${qs}</div>` : ''}
      ${pids.size ? `<div class="sect"><p class="eyebrow">EMB3D properties</p><div class="pids">${pidChips}</div></div>` : ''}
      ${threatsHtml}`;

    $('nm-' + node.id).addEventListener('input', (e) => { node.name = e.target.value; save(); renderBoard(); });
    wireMoveControls(node);
    $('btnConnect').addEventListener('click', () => { connectFrom = node.id; $('hint').hidden = false; renderBoard(); });
    armDelete($('btnDel'), () => removeNode(node));
    ins.querySelectorAll('input[data-q]').forEach((inp) => inp.addEventListener('change', () => {
      node.answers[inp.dataset.q] = inp.type === 'checkbox' ? inp.checked : inp.value;
      if (node.review) delete node.review[inp.dataset.q]; // a human answered it
      commit();
    }));
    ins.querySelectorAll('[data-confirm]').forEach((b) => b.addEventListener('click', () => { delete node.review[b.dataset.confirm]; commit(); }));
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
    armDelete($('btnDel'), () => { const pg = curPage(); pg.flows = pg.flows.filter((x) => x.id !== f.id); sel = null; commit(); });
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
    const ct = ENG.threat(id), cm = ENG.mitigation(id);
    if ((ct && ct.custom) || (!ct && cm && cm.custom)) {
      const x = ct || cm;
      const linked = ct ? ct.mids.map((m) => [m, ENG.mitigation(m)]).filter(([, v]) => v) : [];
      html = `<div class="dhead"><span class="eyebrow" style="margin:0">${esc(id)} · custom ${ct ? 'threat' : 'countermeasure'}</span></div>
        <h3>${esc(x.name)}</h3><p>${esc(x.desc || 'No description.')}</p>
        ${linked.length ? `<div><p class="eyebrow">Countermeasures</p><div class="tlist">${linked.map(([m, v]) => `<button data-detail="${m}"><span class="tid">${m}</span> ${esc(v.name)}</button>`).join('')}</div></div>` : ''}
        <p class="small muted">Defined in this project's custom blocks.</p>`;
      $('dBody').innerHTML = html; $('dBody').scrollTop = 0; $('dBack').hidden = detailStack.length < 2;
      return;
    }
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
    if (!ENG.threat(id) && !ENG.mitigation(id)) return;
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
    return `<option value="all">All components</option>` + ENG.allNodes(S).filter(ENG.hasThreats)
      .map((n) => `<option value="${n.id}" ${String(cur) === String(n.id) ? 'selected' : ''}>${multiPage() ? esc(ENG.pageOf(n.id).name) + ' › ' : ''}${esc(n.name)}</option>`).join('');
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
          <td>${esc(r.node.name)}<div class="sub">${multiPage() && r.page ? esc(r.page.name) + ' · ' : ''}${esc(T(r.node.type).name)}</div></td>
          <td><span class="tid">${r.tid}</span> ${esc(r.t.name)}</td>
          <td><span class="mat m${mat[0]}">${esc(mat[1])}</span></td>
          <td><span class="pill st-${r.state}">${stateLabel(r.state)}</span>${r.t.mids.some((m) => missingWhy(r.node, m)) || missingAcceptWhy(r.node, r.tid) ? '<div class="sub" style="color:var(--s-open)">Justification missing</div>' : ''}</td>
          <td class="num">${impl} / ${r.t.mids.length} implemented</td></tr>`;
      }).join('') || '<tr><td colspan="5" class="muted">No threats match these filters.</td></tr>'}
      </tbody></table></div>`;
    $('fState').addEventListener('change', (e) => { filters.tState = e.target.value; renderThreats(); });
    $('fComp').addEventListener('change', (e) => { filters.tComp = e.target.value; renderThreats(); });
    $('view-threats').querySelectorAll('tr.link').forEach((tr) => tr.addEventListener('click', () => {
      const pg = ENG.pageOf(Number(tr.dataset.node));
      if (pg) cur = pg.id;
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
          <td>${esc(r.node.name)}${multiPage() && r.page ? `<div class="sub">${esc(r.page.name)}</div>` : ''}</td>
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

  const toTmbom = () => ENG.toTmbom(S);

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

  const projectFrom = (obj) => {
    let p = null;
    if (obj && (Array.isArray(obj.nodes) || Array.isArray(obj.pages))) p = obj;
    else if (obj && obj.extensions && obj.extensions[EXT_KEY]) p = obj.extensions[EXT_KEY].project;
    return p && (Array.isArray(p.nodes) || Array.isArray(p.pages)) ? p : null;
  };

  function importText(text) {
    let obj;
    try { obj = JSON.parse(text); } catch (e) { return 'This is not valid JSON: ' + e.message; }
    const p = projectFrom(obj);
    if (!p) return 'This file is not an EMB3D Workbench project or a TM-BOM exported from it.';
    const v = ENG.validate(p);
    if (v.errors.length) { ENG.bind(S); return 'This project has problems:\n' + v.errors.slice(0, 8).join('\n'); }
    ENG.normalize(p);
    cur = p.root;
    const wanted = p.emb3d;
    if (!wanted || !allVersions().some((v) => v.version === wanted)) p.emb3d = IDX.default;
    S = p; sel = null; openThreat = null;
    loadVersion(S.emb3d).then((d) => {
      setData(d); renderVersionSelect(); commit();
      if (wanted && wanted !== S.emb3d) panel('', `<h3>Opened with EMB3D ${esc(S.emb3d)}</h3><p>This model was made with EMB3D ${esc(wanted)}, which is not available here. It now uses ${esc(S.emb3d)}. Add the original with <span class="mono">python3 tools/emb3d_update.py add ${esc(wanted)}</span> to reproduce it exactly.</p>`);
    });
    return null;
  }

  function wireChrome() {
    document.querySelectorAll('.tabs button').forEach((b) => b.addEventListener('click', () => setView(b.dataset.view)));
    $('projName').addEventListener('input', (e) => { S.name = e.target.value; save(); if (!sel) renderInspector(); });
    $('hintCancel').addEventListener('click', () => { connectFrom = null; $('hint').hidden = true; renderBoard(); });
    document.addEventListener('keydown', (e) => {
      const typing = /input|textarea|select/i.test(document.activeElement?.tagName || '') || !$('overlay').hidden || !$('dOverlay').hidden;
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !typing && view === 'diagram') {
        const k = e.key.toLowerCase();
        if (k === 'c' && window.getSelection().toString() === '' && copySelection(false)) { e.preventDefault(); renderInspector(); return; }
        if (k === 'x' && copySelection(true)) { e.preventDefault(); return; }
        if (k === 'd') { e.preventDefault(); duplicateSelection(); return; }
        if (k === 'a') { e.preventDefault(); const ns = curPage().nodes; if (ns.length) { sel = { kind: 'node', id: ns[0].id }; multi.clear(); ns.slice(1).forEach((n) => multi.add(n.id)); renderBoard(); renderInspector(); } return; }
      }
      if (e.key !== 'Escape') return;
      if (multi.size && $('overlay').hidden && $('dOverlay').hidden) { multi.clear(); renderBoard(); renderInspector(); return; }
      if (!$('dOverlay').hidden) { $('dClose').click(); return; }
      if (!$('overlay').hidden) { $('overlay').hidden = true; return; }
      if (connectFrom !== null) { connectFrom = null; $('hint').hidden = true; renderBoard(); }
    });
    $('board').addEventListener('pointerdown', (e) => {
      if (e.target === $('board') || e.target === $('edges')) {
        if (connectFrom !== null) return;
        if (sel) { sel = null; multi.clear(); openThreat = null; renderBoard(); renderInspector(); }
      }
    });
    $('board').addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; markDropTarget(deviceAt(e.clientX, e.clientY)); });
    $('board').addEventListener('dragleave', (e) => { if (e.target === $('board')) markDropTarget(null); });
    $('board').addEventListener('drop', (e) => {
      const type = e.dataTransfer.getData('text/x-emb3d');
      markDropTarget(null);
      if (!type) return;
      e.preventDefault();
      const dev = deviceAt(e.clientX, e.clientY);
      if (dev) { addNode(type, undefined, undefined, dev); return; }
      const r = $('board').getBoundingClientRect();
      addNode(type, Math.max(0, e.clientX - r.left - (type === 'device' ? 110 : NODE_W / 2)), Math.max(0, e.clientY - r.top - 30));
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
      S = emptyProject(); S.emb3d = E.version; cur = S.root; sel = null; commit();
    });
    $('mClose').addEventListener('click', () => { $('overlay').hidden = true; });
    $('devFile').addEventListener('change', async (e) => {
      const f = e.target.files[0];
      e.target.value = '';
      if (!f) return;
      const err = importAsDevice(await f.text());
      if (err) modal('Could not add the device', err, '');
    });
    document.addEventListener('click', (e) => {
      const b = e.target.closest('[data-editcustom]');
      if (b) { e.preventDefault(); openCustomEditor(b.dataset.editcustom); }
    });
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
      let c = null;
      if (t && t.includes(CLIP_KEY)) { try { c = JSON.parse(t); } catch (_) { c = null; } }
      if (c && c[CLIP_KEY]) { e.preventDefault(); if (view !== 'diagram') setView('diagram'); pasteClip(c); return; }
      if (t && t.trim().startsWith('{')) { const err = importText(t); if (err) modal('Could not open the pasted text', err, ''); return; }
      if (clip && view === 'diagram') { e.preventDefault(); pasteClip(clip); }
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
    ENG.bind(S);
    if (!ENG.pageById(S, cur)) cur = S.root;
    $('projName').value = S.name;
    renderRail();
    if (view === 'diagram') { renderCrumbs(); renderBoard(); renderInspector(); }
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
    const eng = ENGINE.make(data, LIB);
    const out = new Map();
    eng.allNodes(S).filter((n) => eng.hasThreats(n)).forEach((n) => out.set(n.id, new Set(eng.nodeThreats(S, n).map((r) => r.tid))));
    ENG.bind(S);
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
    const rows = ENG.allNodes(S).filter((n) => before.has(n.id)).map((n) => {
      const add = [...after.get(n.id)].filter((t) => !before.get(n.id).has(t));
      const rem = [...before.get(n.id)].filter((t) => !after.get(n.id).has(t));
      return { n, add, rem };
    }).filter((r) => r.add.length || r.rem.length);
    const missing = [...libraryPids()].filter((p) => !next.properties[p]);
    const tl = (ids, data) => ids.map((t) => `<span class="tid">${t}</span> ${esc((data.threats[t] || ENG.threat(t) || { name: '' }).name)}`).join('<br>');
    const renamed = [...d.threatsRenamed.map((t) => [t, E.threats[t].name, next.threats[t].name]), ...d.mitigationsRenamed.map((m) => [m, E.mitigations[m].name, next.mitigations[m].name])];
    const html = `<div class="dhead"><span class="eyebrow" style="margin:0">Switch EMB3D version</span></div>
      <h3>EMB3D ${esc(E.version)} → ${esc(v)}</h3>
      <p>Countermeasure statuses, decisions and justifications are kept: they are stored by threat and mitigation ID.</p>
      <div><p class="eyebrow">Your components</p>${rows.length ? `<table class="mini"><thead><tr><th>Component</th><th>Threats added</th><th>Threats removed</th></tr></thead><tbody>
        ${rows.map((r) => `<tr><td>${multiPage() ? esc(ENG.pageOf(r.n.id).name) + ' › ' : ''}${esc(r.n.name)}</td><td>${tl(r.add, next) || '—'}</td><td>${tl(r.rem, E) || '—'}</td></tr>`).join('')}</tbody></table>` : '<p class="small">No threats are added or removed for this model.</p>'}</div>
      ${renamed.length ? `<div><p class="eyebrow">Renamed in ${esc(v)}</p><p class="small">${renamed.map(([id, a, b]) => `<span class="tid">${id}</span> ${esc(a)} → <b>${esc(b)}</b>`).join('<br>')}</p></div>` : ''}
      <div><p class="eyebrow">Catalogue changes</p><p class="small">
        Threats: ${d.threatsAdded.length} added, ${d.threatsRemoved.length} removed, ${d.threatsRemapped.length} with changed properties or mitigations.<br>
        Mitigations: ${d.mitigationsAdded.length} added, ${d.mitigationsRemoved.length} removed.</p></div>
      ${missing.length ? `<p class="warn">The component library uses properties that ${esc(v)} does not define: ${missing.join(', ')}. Those answers will add nothing.</p>` : ''}`;
    panel('', html, { label: `Use EMB3D ${v}`, run: () => { setData(next); S.emb3d = v; closeDetail(); renderVersionSelect(); commit(); } }, () => renderVersionSelect());
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

  function renderReport() {
    const o = reportOpts;
    const m = S.meta || (S.meta = { description: '', owner: '', reviewer: '' });
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
      ${ENG.reportHtml(S, o)}`;
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
      S = load() || await sampleProject();
      ENGINE.migrate(S);
      if (!S.emb3d || !IDX.versions.some((v) => v.version === S.emb3d)) S.emb3d = IDX.default;
      setData(await loadVersion(S.emb3d));
      ENG.normalize(S);
      cur = S.root;
      renderVersionSelect();
      wireChrome();
      render();
    })
    .catch((err) => {
      $('rail').innerHTML = `<div class="loading">Could not load the EMB3D data (${esc(err.message)}). If you opened index.html from disk, serve the folder instead, for example with <span class="mono">python3 -m http.server</span>.</div>`;
    });
})();
