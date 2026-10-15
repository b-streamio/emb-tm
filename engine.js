/* EMB3D Workbench engine: rules, TM-BOM export and report markup.
 * Shared by the browser app (app.js) and the command line (cli/emb3d-wb.js). No DOM access here.
 *
 * Project format (v2):
 *   { name, emb3d, meta, root: 'p1', seq, flowSeq,
 *     pages: [ { id, name, nodes: [...], flows: [...] } ],   one diagram per page
 *     customTypes: [ { type, name, group, tag, hint, base: [PID], threats: [ { id, name, desc, cms: [ { id, name, desc } ] } ] } ] }
 *   A node of type "device" is a box that stands for a whole device; its `page` holds the detailed design and
 *   `qty` says how many identical units there are. Node ids are unique across the project.
 *   Version 1 files ({ nodes, flows } at top level) are migrated by normalize().
 *
 *   const eng = EMB3D_ENGINE.make(emb3dData, library);
 *   eng.allRows(project); eng.toTmbom(project); eng.reportHtml(project, opts);
 */
(function (root) {
  'use strict';

  const TMBOM_SCHEMA = 'https://github.com/OWASP/www-project-threat-model-library/blob/v1.0.2/threat-model.schema.json';
  const EXT_KEY = 'emb3d-workbench.invalid/project';
  const NODE_W = 168, NODE_H = 64, DEV_W = 220, DEV_H = 96;

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
    custom: [4, 'Custom threat'],
  };
  const MIT_RANK = { foundational: 0, intermediate: 1, leading: 2, custom: 3 };
  const ZONE = {
    System: ['system', 'System'],
    Hardware: ['hardware', 'Hardware'],
    'System software': ['system-software', 'System software'],
    Application: ['application', 'Application'],
    Networking: ['networking', 'Networking'],
    External: ['external', 'External'],
    Custom: ['custom', 'Custom'],
  };
  const NEEDS_WHY = ['na', 'rejected'];

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const slug = (s) => String(s).toLowerCase().replace(/[^0-9a-z-]+/g, '-').replace(/^-+|-+$/g, '');
  const groupClass = (g) => 'k-' + String(g).split(' ')[0];
  const numSort = (a, b) => String(a).localeCompare(String(b), 'en', { numeric: true });
  const stateLabel = (s) => (s === 'NA' ? 'Not applicable' : s);
  const cmLabel = (st) => (CM_STATUS.find((x) => x[0] === st) || [st, st])[1];
  const isDevice = (n) => n.type === 'device';
  const sizeOf = (n) => (isDevice(n) ? [DEV_W, DEV_H] : [NODE_W, NODE_H]);

  // Point on node a's border towards node b's centre.
  function anchor(a, b) {
    const [aw, ah] = sizeOf(a), [bw, bh] = sizeOf(b);
    const ac = { x: a.x + aw / 2, y: a.y + ah / 2 };
    const bc = { x: b.x + bw / 2, y: b.y + bh / 2 };
    const dx = bc.x - ac.x, dy = bc.y - ac.y;
    if (!dx && !dy) return ac;
    const sx = (aw / 2 + 6) / Math.abs(dx || 1e-9), sy = (ah / 2 + 8) / Math.abs(dy || 1e-9);
    const s = Math.min(sx, sy);
    return { x: ac.x + dx * s, y: ac.y + dy * s };
  }

  // Version 1 (single diagram) -> version 2 (pages). Mutates and returns S.
  function migrate(S) {
    if (!S.pages) {
      S.pages = [{ id: 'p1', name: S.name || 'Device', nodes: S.nodes || [], flows: S.flows || [] }];
      S.root = 'p1';
      delete S.nodes; delete S.flows;
    }
    S.root = S.root || (S.pages[0] && S.pages[0].id);
    S.customTypes = S.customTypes || [];
    return S;
  }

  function make(E, LIB) {
    const BASE = {};
    LIB.components.forEach((c) => { BASE[c.type] = c; });
    let TYPES = BASE;
    let CT = { threats: {}, mits: {} };
    let PAGE_OF = new Map();

    const pagesOf = (S) => S.pages || [{ id: 'main', name: S.name, nodes: S.nodes || [], flows: S.flows || [] }];
    const pageById = (S, id) => pagesOf(S).find((p) => p.id === id);
    const allNodes = (S) => pagesOf(S).flatMap((p) => p.nodes);
    const allFlows = (S) => pagesOf(S).flatMap((p) => p.flows || []);

    // Index a project: custom component types, custom threats, node -> page.
    function bind(S) {
      TYPES = Object.assign({}, BASE);
      CT = { threats: {}, mits: {} };
      (S.customTypes || []).forEach((c) => {
        TYPES[c.type] = { type: c.type, name: c.name, group: c.group || 'Custom', tag: (c.tag || 'CUS').slice(0, 4), hint: c.hint || 'Custom block', base: c.base || [], questions: [], custom: true, threats: c.threats || [] };
        (c.threats || []).forEach((t) => {
          CT.threats[t.id] = { name: t.name, cat: 'custom', maturity: 'custom', desc: t.desc || '', text: [t.desc || ''], cwes: [], cves: 0, pids: [], mids: (t.cms || []).map((m) => m.id), custom: true };
          (t.cms || []).forEach((m) => { CT.mits[m.id] = { name: m.name, maturity: 'custom', desc: m.desc || '', text: [m.desc || ''], refs: [], iec: [], custom: true }; });
        });
      });
      PAGE_OF = new Map();
      pagesOf(S).forEach((p) => p.nodes.forEach((n) => PAGE_OF.set(n.id, p)));
      return api;
    }

    const threat = (tid) => E.threats[tid] || CT.threats[tid];
    const mitigation = (mid) => E.mitigations[mid] || CT.mits[mid];
    const typeOf = (n) => TYPES[n.type];
    const nodeById = (S, id) => allNodes(S).find((n) => n.id === id);
    const isExternal = (n) => !!(TYPES[n.type] && TYPES[n.type].external);
    const hasThreats = (n) => !isExternal(n) && !isDevice(n);
    const parentsOf = (S, pageId) => allNodes(S).filter((n) => isDevice(n) && n.page === pageId);

    function answer(node, q) {
      return node.answers && q.id in node.answers ? node.answers[q.id] : q.default;
    }

    // EMB3D properties of a component: base + answers + device-level rule + parent closure.
    // Map pid -> 'base' | 'answer' | 'parent' | 'rule'
    function nodePids(S, node) {
      bind(S);
      const def = TYPES[node.type];
      const out = new Map();
      if (!def || isDevice(node)) return out;
      def.base.forEach((p) => out.set(p, 'base'));
      def.questions.forEach((q) => {
        const a = answer(node, q);
        if (q.kind === 'bool' && a) q.pids.forEach((p) => out.has(p) || out.set(p, 'answer'));
        if (q.kind === 'choice') {
          const opt = q.options.find((o) => o.value === a);
          if (opt) opt.pids.forEach((p) => out.has(p) || out.set(p, 'answer'));
        }
      });
      // A device page without an update agent: its firmware cannot be updated (PID-26), attached to its OS or SoC.
      const page = PAGE_OF.get(node.id);
      const peers = page ? page.nodes : [];
      if (!peers.some((n) => n.type === 'update')) {
        const host = peers.find((n) => n.type === 'os') || peers.find((n) => n.type === 'soc');
        if (host && host.id === node.id) out.set('PID-26', 'rule');
      }
      for (const p of [...out.keys()]) {
        if (!E.properties[p]) { out.delete(p); continue; } // not defined in this EMB3D version
        let par = E.properties[p].parent;
        while (par) { if (!out.has(par)) out.set(par, 'parent'); par = E.properties[par].parent; }
      }
      return out;
    }

    function nodeThreats(S, node) {
      if (!hasThreats(node)) return [];
      const pids = nodePids(S, node);
      const res = [];
      for (const [tid, t] of Object.entries(E.threats)) {
        const hit = t.pids.filter((p) => pids.has(p));
        if (hit.length) res.push({ tid, t, via: hit });
      }
      const def = TYPES[node.type];
      (def && def.threats || []).forEach((ct) => { if (CT.threats[ct.id]) res.push({ tid: ct.id, t: CT.threats[ct.id], via: ['custom'] }); });
      res.sort((a, b) => (MATURITY[a.t.maturity]?.[0] ?? 9) - (MATURITY[b.t.maturity]?.[0] ?? 9) || numSort(a.tid, b.tid));
      return res;
    }

    const cmStatus = (node, mid) => (node.cm && node.cm[mid]) || 'recommended';
    const why = (node, key) => ((node.why && node.why[key]) || '').trim();
    const missingWhy = (node, mid) => NEEDS_WHY.includes(cmStatus(node, mid)) && !why(node, mid);
    // Threat-level decision: '' (handle with countermeasures), 'na' or 'accept'. Older files stored true for accept.
    const decision = (node, tid) => { const v = node.accepted && node.accepted[tid]; return v === true ? 'accept' : (v || ''); };
    const missingAcceptWhy = (node, tid) => !!decision(node, tid) && !why(node, 'accept:' + tid);

    function threatState(node, tid) {
      if (decision(node, tid) === 'accept') return 'Accepted';
      if (decision(node, tid) === 'na') return 'NA';
      const t = threat(tid);
      const mids = t ? t.mids : [];
      if (mids.some((m) => cmStatus(node, m) === 'implemented')) return 'Mitigated';
      if (mids.length && mids.every((m) => cmStatus(node, m) === 'na')) return 'NA';
      return 'Open';
    }

    function allRows(S) {
      bind(S);
      const rows = [];
      allNodes(S).forEach((node) => nodeThreats(S, node).forEach((r) => rows.push({ node, page: PAGE_OF.get(node.id), ...r, state: threatState(node, r.tid) })));
      return rows;
    }

    function cmRows(S) {
      bind(S);
      const rows = [];
      allNodes(S).forEach((node) => {
        const byMid = new Map();
        nodeThreats(S, node).forEach(({ tid, t }) => t.mids.forEach((m) => {
          if (!byMid.has(m)) byMid.set(m, []);
          byMid.get(m).push(tid);
        }));
        byMid.forEach((tids, mid) => { const m = mitigation(mid); if (m) rows.push({ node, page: PAGE_OF.get(node.id), mid, m, tids, status: cmStatus(node, mid) }); });
      });
      rows.sort((a, b) => (MIT_RANK[a.m.maturity] ?? 9) - (MIT_RANK[b.m.maturity] ?? 9) || numSort(a.mid, b.mid) || a.node.id - b.node.id);
      return rows;
    }

    // Threat counts of a page including nested device pages (each page counted once).
    function rollup(S, pageId, seen = new Set()) {
      bind(S);
      const out = { threats: 0, open: 0, review: 0 };
      if (seen.has(pageId)) return out;
      seen.add(pageId);
      const p = pageById(S, pageId);
      if (!p) return out;
      p.nodes.forEach((n) => {
        if (isDevice(n)) { const r = rollup(S, n.page, seen); out.threats += r.threats; out.open += r.open; out.review += r.review; return; }
        nodeThreats(S, n).forEach((r) => { out.threats++; if (threatState(n, r.tid) === 'Open') out.open++; });
        out.review += Object.values(n.review || {}).filter(Boolean).length;
      });
      return out;
    }

    // Pages in reading order: root first, then breadth-first through device boxes, then unreferenced pages.
    function pageOrder(S) {
      const pages = pagesOf(S);
      const order = [], seen = new Set();
      const queue = [S.root || (pages[0] && pages[0].id)];
      while (queue.length) {
        const id = queue.shift();
        if (!id || seen.has(id)) continue;
        const p = pageById(S, id);
        if (!p) continue;
        seen.add(id); order.push(p);
        p.nodes.filter(isDevice).forEach((n) => queue.push(n.page));
      }
      pages.forEach((p) => { if (!seen.has(p.id)) order.push(p); });
      return order;
    }

    // Answers that need a human look: flagged by whoever wrote the project (e.g. the Yocto scanner).
    function reviewItems(S) {
      bind(S);
      const out = [];
      allNodes(S).forEach((n) => {
        const def = TYPES[n.type];
        if (!def || !n.review) return;
        Object.entries(n.review).forEach(([qid, reason]) => {
          if (!reason) return;
          const q = def.questions.find((x) => x.id === qid);
          out.push({ node: n, page: PAGE_OF.get(n.id), qid, question: q ? q.text : (qid === '_component' ? 'Component' : qid), reason: reason === true ? '' : String(reason) });
        });
      });
      return out;
    }

    function summary(S) {
      const rows = allRows(S);
      const c = (st) => rows.filter((r) => r.state === st).length;
      const openBy = (lvl) => rows.filter((r) => r.state === 'Open' && (MATURITY[r.t.maturity]?.[0] ?? 9) === lvl).length;
      const cms = cmRows(S);
      return {
        emb3d: E.version, pages: pagesOf(S).length, devices: allNodes(S).filter(isDevice).length,
        components: allNodes(S).filter(hasThreats).length, flows: allFlows(S).length,
        threats: rows.length, open: c('Open'), mitigated: c('Mitigated'), notApplicable: c('NA'), accepted: c('Accepted'),
        openByEvidence: { observedInAttacks: openBy(0), observedTechnique: openBy(1), knownWeakness: openBy(2), proofOfConcept: openBy(3), custom: openBy(4) },
        countermeasures: cms.length, implemented: cms.filter((r) => r.status === 'implemented').length,
        missingJustifications: cms.filter((r) => missingWhy(r.node, r.mid)).length + rows.filter((r) => missingAcceptWhy(r.node, r.tid)).length,
        needsReview: reviewItems(S).length,
      };
    }

    // Structural checks used by the CLI and on import. Accepts v1 and v2 projects. Returns { errors, warnings }.
    function validate(S) {
      const errors = [], warnings = [];
      if (!S || (!Array.isArray(S.nodes) && !Array.isArray(S.pages))) return { errors: ['Project has neither "pages" nor "nodes"'], warnings };
      bind(S);
      const pages = pagesOf(S);
      const pageIds = new Set();
      pages.forEach((p, i) => {
        if (!p.id) errors.push(`pages[${i}]: missing id`);
        if (pageIds.has(p.id)) errors.push(`pages[${i}]: duplicate page id ${p.id}`);
        pageIds.add(p.id);
        if (!Array.isArray(p.nodes)) errors.push(`pages[${i}] (${p.name}): "nodes" must be an array`);
      });
      if (errors.length) return { errors, warnings };
      const ids = new Set();
      pages.forEach((p) => {
        const pageIdsHere = new Set();
        p.nodes.forEach((n, i) => {
          const where = `${pages.length > 1 ? p.name + ': ' : ''}nodes[${i}] (${n.name || n.type})`;
          if (typeof n.id !== 'number') errors.push(`${where}: id must be a number`);
          if (ids.has(n.id)) errors.push(`${where}: duplicate id ${n.id}`);
          ids.add(n.id); pageIdsHere.add(n.id);
          const def = TYPES[n.type];
          if (!def) { errors.push(`${where}: unknown type "${n.type}". Run "emb3d-wb library" for the list.`); return; }
          if (isDevice(n)) {
            if (!pageIds.has(n.page)) errors.push(`${where}: device page "${n.page}" does not exist`);
            if (n.qty !== undefined && !(Number.isInteger(n.qty) && n.qty > 0)) errors.push(`${where}: qty must be a positive integer`);
            return;
          }
          Object.entries(n.answers || {}).forEach(([qid, v]) => {
            const q = def.questions.find((x) => x.id === qid);
            if (!q) { errors.push(`${where}: unknown question "${qid}" for type ${n.type}`); return; }
            if (q.kind === 'bool' && typeof v !== 'boolean') errors.push(`${where}: "${qid}" must be true or false`);
            if (q.kind === 'choice' && !q.options.some((o) => o.value === v)) errors.push(`${where}: "${qid}" must be one of ${q.options.map((o) => o.value).join(', ')}`);
          });
          def.questions.forEach((q) => {
            if (!(n.answers && q.id in n.answers)) warnings.push(`${where}: "${q.id}" not answered, default (${JSON.stringify(q.default)}) used`);
          });
          Object.keys(n.evidence || {}).forEach((qid) => { if (!def.questions.some((q) => q.id === qid) && qid !== '_component') warnings.push(`${where}: evidence for unknown question "${qid}"`); });
        });
        (p.flows || []).forEach((f, i) => {
          if (!pageIdsHere.has(f.from) || !pageIdsHere.has(f.to)) errors.push(`${pages.length > 1 ? p.name + ': ' : ''}flows[${i}]: from/to must reference nodes on the same page`);
        });
      });
      // A device must not contain itself, directly or through nested devices.
      const visit = (id, stack) => {
        if (stack.includes(id)) { errors.push(`device pages form a loop: ${[...stack, id].map((x) => (pageById(S, x) || {}).name || x).join(' > ')}`); return; }
        const p = pageById(S, id);
        if (p) p.nodes.filter(isDevice).forEach((n) => visit(n.page, [...stack, id]));
      };
      if (S.pages) visit(S.root || pages[0].id, []);
      return { errors, warnings };
    }

    // Place nodes that have no position: one column per group, in library group order.
    function layout(S) {
      bind(S);
      pagesOf(S).forEach((p) => {
        const cols = {};
        LIB.groups.forEach((g, i) => { cols[g] = { x: 60 + i * 240, y: 60 }; });
        p.nodes.forEach((n) => {
          if (typeof n.x === 'number' && typeof n.y === 'number') return;
          const g = (TYPES[n.type] && TYPES[n.type].group) || LIB.groups[0];
          const c = cols[g] || (cols[g] = { x: 60 + Object.keys(cols).length * 240, y: 60 });
          n.x = c.x; n.y = c.y; c.y += isDevice(n) ? 160 : 130;
        });
      });
      return S;
    }

    // Migrate v1 files and fill in fields an externally written project may omit.
    function normalize(S) {
      migrate(S);
      bind(S);
      let fid = 1;
      S.pages.forEach((p, i) => {
        p.id = p.id || `p${i + 1}`;
        p.name = p.name || `Page ${i + 1}`;
        p.flows = p.flows || [];
        p.nodes.forEach((n) => {
          n.answers = n.answers || {}; n.cm = n.cm || {}; n.accepted = n.accepted || {}; n.why = n.why || {};
          n.name = n.name || (TYPES[n.type] && TYPES[n.type].name) || n.type;
          if (isDevice(n)) n.qty = n.qty || 1;
        });
        p.flows.forEach((f) => { if (typeof f.id !== 'number') f.id = 0; f.label = f.label || 'data flow'; fid = Math.max(fid, f.id + 1); });
      });
      S.pages.forEach((p) => p.flows.forEach((f) => { if (!f.id) f.id = fid++; }));
      const nodes = allNodes(S), flows = allFlows(S);
      S.seq = Math.max(S.seq || 1, ...nodes.map((n) => n.id + 1), 1);
      S.flowSeq = Math.max(S.flowSeq || 1, ...flows.map((f) => f.id + 1), 1);
      S.meta = S.meta || { description: '', owner: '', reviewer: '' };
      return layout(S);
    }

    /* ---------- TM-BOM ---------- */

    function toTmbom(S) {
      bind(S);
      const nodes = allNodes(S);
      const sym = (n) => `n${n.id}-${slug(n.type)}`;
      const zoneOf = (n) => (ZONE[(TYPES[n.type] || {}).group] || ZONE.Custom)[0];
      const used = new Set(nodes.map(zoneOf));
      const trust_zones = Object.values(ZONE).filter(([z]) => used.has(z)).map(([z, t]) => ({ symbolic_name: z, title: t, description: z === 'system' ? 'Devices of the solution' : `${t} parts of the devices` + (z === 'external' ? ' (outside the devices)' : '') }));
      if (!trust_zones.length) trust_zones.push({ symbolic_name: 'device', title: 'Device', description: 'The device' });
      const parentSym = (n) => { const p = PAGE_OF.get(n.id); const par = p && parentsOf(S, p.id)[0]; return par ? sym(par) : undefined; };
      const actors = nodes.filter(isExternal).map((n) => ({
        symbolic_name: sym(n), title: n.name, description: TYPES[n.type].hint,
        type: n.type === 'person' ? 'user' : 'third_party', trust_zone: 'external',
      }));
      const components = nodes.filter((n) => !isExternal(n)).map((n) => {
        const c = {
          symbolic_name: sym(n), title: isDevice(n) && n.qty > 1 ? `${n.name} (x${n.qty})` : n.name,
          description: isDevice(n)
            ? `Device${n.qty > 1 ? `, ${n.qty} identical units` : ''}. Detailed design: page "${(pageById(S, n.page) || {}).name || n.page}".`
            : `${TYPES[n.type].name}${TYPES[n.type].custom ? ' (custom block)' : ''}. EMB3D properties: ${[...nodePids(S, n).keys()].sort(numSort).join(', ') || 'none'}`,
          trust_zone: zoneOf(n),
        };
        const ps = parentSym(n);
        if (ps && ps !== c.symbolic_name) c.parent_component = ps;
        return c;
      });
      const ref = (n) => ({ type: isExternal(n) ? 'actor' : 'component', object: sym(n) });
      const data_flows = allFlows(S).filter((f) => nodeById(S, f.from) && nodeById(S, f.to)).map((f) => ({
        symbolic_name: `f${f.id}`, title: f.label || 'data flow', description: `${nodeById(S, f.from).name} to ${nodeById(S, f.to).name}`,
        source: ref(nodeById(S, f.from)), destination: ref(nodeById(S, f.to)), has_sensitive_data: !!f.sensitive, encrypted: !!f.encrypted,
      }));
      const threats = [], controls = [], assumptions = [];
      nodes.filter(hasThreats).forEach((n) => {
        const byMid = new Map();
        nodeThreats(S, n).forEach(({ tid, t, via }) => {
          const id = `${slug(tid)}-${sym(n)}`;
          const th = {
            symbolic_name: id, title: `${tid}: ${t.name}`,
            description: t.custom ? (t.desc || t.name) + '\n\nCustom threat defined in the project.' : `${t.desc}\n\nEMB3D evidence: ${t.maturity}.`,
            components_affected: [sym(n)],
            threat_persona: t.cat === 'hardware' ? 'physical-adversary' : 'remote-adversary',
            event: t.custom ? `Custom threat of block type "${TYPES[n.type].name}"` : 'Applies because the component has: ' + via.map((p) => `${p} ${E.properties[p].name}`).join('; '),
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
          const m = mitigation(mid);
          if (!m) return;
          const st = cmStatus(n, mid);
          controls.push({
            symbolic_name: `${slug(mid)}-${sym(n)}`, title: `${mid}: ${m.name}`,
            description: `${m.desc}\n\n${m.custom ? 'Custom countermeasure.' : `EMB3D level: ${m.maturity}.`}` + (m.iec.length ? `\nIEC 62443-4-2: ${m.iec.join('; ')}` : '') + `\nWorkbench status: ${cmLabel(st)}.` + (why(n, mid) ? `\nJustification: ${why(n, mid)}` : ''),
            threats: tids, status: CM_TO_TMBOM[st], priority: st === 'required' ? 'high' : 'none',
          });
        });
      });
      const doc = {
        $schema: TMBOM_SCHEMA,
        version: '1.0',
        scope: {
          title: S.name,
          description: (S.meta && S.meta.description) || `Threat model of ${S.name}, built with EMB3D Workbench on MITRE EMB3D STIX ${E.version}.`,
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

    /* ---------- report (layout follows OWASP Threat Dragon's report: one section per diagram) ---------- */

    function diagramSvg(S, page) {
      bind(S);
      const p = page || pageById(S, S.root) || pagesOf(S)[0];
      if (!p || !p.nodes.length) return '<p class="muted">This page is empty.</p>';
      const pad = 30;
      const minX = Math.min(...p.nodes.map((n) => n.x)) - pad, minY = Math.min(...p.nodes.map((n) => n.y)) - pad;
      const maxX = Math.max(...p.nodes.map((n) => n.x + sizeOf(n)[0])) + pad, maxY = Math.max(...p.nodes.map((n) => n.y + sizeOf(n)[1])) + pad;
      const wrap = (t, w) => { const words = String(t).split(/\s+/); const lines = ['']; words.forEach((x) => { if ((lines[lines.length - 1] + ' ' + x).trim().length > w && lines[lines.length - 1]) lines.push(x); else lines[lines.length - 1] = (lines[lines.length - 1] + ' ' + x).trim(); }); return lines.slice(0, 2); };
      let out = `<svg class="rdiagram" viewBox="${minX} ${minY} ${maxX - minX} ${maxY - minY}" role="img" aria-label="${esc(p.name)} diagram">
        <defs><marker id="rarr-${esc(p.id)}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="rarrow"></path></marker></defs>`;
      (p.flows || []).forEach((f) => {
        const a = p.nodes.find((n) => n.id === f.from), b = p.nodes.find((n) => n.id === f.to);
        if (!a || !b) return;
        const s = anchor(a, b), q = anchor(b, a);
        out += `<line class="redge${f.encrypted ? '' : ' plain'}" x1="${s.x}" y1="${s.y}" x2="${q.x}" y2="${q.y}" marker-end="url(#rarr-${esc(p.id)})"></line>
          <text class="rlabel" x="${(s.x + q.x) / 2}" y="${(s.y + q.y) / 2 - 6}" text-anchor="middle">${esc(f.label)}</text>`;
      });
      p.nodes.forEach((n) => {
        const def = TYPES[n.type] || { group: 'Custom', tag: '?' };
        const [w, h] = sizeOf(n);
        const lines = wrap(n.name + (isDevice(n) && n.qty > 1 ? ` ×${n.qty}` : ''), isDevice(n) ? 28 : 22);
        out += `<g class="rnode ${groupClass(def.group)}${def.external ? ' ext' : ''}${isDevice(n) ? ' dev' : ''}">
          <rect x="${n.x}" y="${n.y}" width="${w}" height="${h}" rx="8"></rect>
          <text class="rtag" x="${n.x + 10}" y="${n.y + 17}">${esc(def.tag)} · #${n.id}</text>
          ${lines.map((l, i) => `<text class="rname" x="${n.x + 10}" y="${n.y + 36 + i * 16}">${esc(l)}</text>`).join('')}
          ${isDevice(n) ? `<text class="rtag" x="${n.x + 10}" y="${n.y + h - 12}">see page: ${esc((pageById(S, n.page) || {}).name || '')}</text>` : ''}</g>`;
      });
      return out + '</svg>';
    }

    function answerLabel(node, q) {
      const a = answer(node, q);
      if (q.kind === 'bool') return a ? 'Yes' : 'No';
      const o = q.options.find((x) => x.value === a);
      return o ? o.label : String(a);
    }

    const evidenceText = (ev) => (ev || []).map((e) => `${e.file}${e.line ? ':' + e.line : ''}${e.text ? ' — ' + e.text : ''}`);

    // The report body (<article>). opts: diagram, mitigated, closed, empty, props, fulltext, date
    function reportHtml(S, opts) {
      bind(S);
      const o = Object.assign({ diagram: true, mitigated: true, closed: true, empty: false, props: true, fulltext: false }, opts || {});
      const m = S.meta || { description: '', owner: '', reviewer: '' };
      const sum = summary(S);
      const stats = [
        ...(sum.pages > 1 ? [['Devices', sum.devices], ['Pages', sum.pages]] : []),
        ['Total Threats', sum.threats], ['Total Mitigated', sum.mitigated], ['Total Open', sum.open],
        ...(sum.notApplicable ? [['Total Not Applicable', sum.notApplicable]] : []), ...(sum.accepted ? [['Total Accepted', sum.accepted]] : []),
        ['Open / Observed in attacks', sum.openByEvidence.observedInAttacks], ['Open / Observed technique', sum.openByEvidence.observedTechnique],
        ['Open / Known weakness', sum.openByEvidence.knownWeakness], ['Open / Proof of concept', sum.openByEvidence.proofOfConcept],
        ...(sum.openByEvidence.custom ? [['Open / Custom threats', sum.openByEvidence.custom]] : []),
        ['Countermeasures implemented', `${sum.implemented} of ${sum.countermeasures}`],
        ...(sum.missingJustifications ? [['Decisions missing a justification', sum.missingJustifications]] : []),
        ...(sum.needsReview ? [['Answers needing review', sum.needsReview]] : []),
      ];
      let num = 0;
      const entity = (n) => {
        const def = TYPES[n.type];
        if (isDevice(n)) {
          const r = rollup(S, n.page);
          return `<section class="rentity"><div class="rhead"><h3>${esc(n.name)} (Device${n.qty > 1 ? ' ×' + n.qty : ''})</h3>
            <p class="rprops">Detailed on page "${esc((pageById(S, n.page) || {}).name || n.page)}": ${r.threats} threats, ${r.open} open${n.qty > 1 ? `; applies to each of the ${n.qty} units` : ''}.</p></div></section>`;
        }
        const ts = nodeThreats(S, n).map((r) => ({ ...r, state: threatState(n, r.tid) }))
          .filter((r) => (o.mitigated || r.state !== 'Mitigated') && (o.closed || (r.state !== 'NA' && r.state !== 'Accepted')));
        if (!ts.length && !o.empty) return '';
        const props = [...nodePids(S, n).keys()].sort(numSort);
        const answers = def.questions.map((q) => {
          const ev = evidenceText(n.evidence && n.evidence[q.id]);
          const rv = n.review && n.review[q.id];
          return `<li><span class="rq">${esc(q.text)}:</span> <b>${esc(answerLabel(n, q))}</b>${rv ? ` <span class="rflag">needs review${rv === true ? '' : ': ' + esc(rv)}</span>` : ''}${ev.length ? `<div class="rwhy">${ev.map(esc).join('<br>')}</div>` : ''}</li>`;
        }).join('');
        const compEv = evidenceText(n.evidence && n.evidence._component);
        const body = ts.map((r) => {
          num += 1;
          const d = decision(n, r.tid);
          const mat = MATURITY[r.t.maturity] || [9, r.t.maturity];
          const cmCell = r.t.mids.map((mid) => {
            const st = cmStatus(n, mid);
            const mm = mitigation(mid);
            return mm ? `<div class="rcm"><b>${esc(mid)}</b> ${esc(mm.name)} — <i>${cmLabel(st)}</i>${why(n, mid) ? `<div class="rwhy">${esc(why(n, mid))}</div>` : ''}</div>` : '';
          }).join('') || '—';
          const text = o.fulltext ? (r.t.text || [r.t.desc]) : [r.t.desc];
          return `<tr><td class="num">${num}</td><td><b>${esc(r.tid)}</b> ${esc(r.t.name)}</td><td>${esc(r.t.cat)}</td><td>${esc(mat[1])}</td>
            <td>${stateLabel(r.state)}${d ? `<div class="rwhy">${d === 'na' ? 'Not applicable' : 'Risk accepted'}: ${esc(why(n, 'accept:' + r.tid)) || '<i>no justification</i>'}</div>` : ''}</td>
            <td>${text.map((x) => `<p class="rp">${esc(String(x).replace(/\*/g, ''))}</p>`).join('')}${!o.fulltext && !r.t.custom && (r.t.text || []).length > 1 ? `<p class="rp rmore">Full text: emb3d.mitre.org/threats/${r.tid}.html</p>` : ''}</td><td>${cmCell}</td></tr>`;
        }).join('');
        return `<section class="rentity">
          <div class="rhead"><h3>${esc(n.name)} (${esc(def.name)})</h3>
          ${compEv.length ? `<p class="rprops">Identified from: ${compEv.map(esc).join('; ')}</p>` : ''}
          ${n.review && n.review._component ? `<p class="rprops"><span class="rflag">needs review:</span> ${esc(n.review._component === true ? '' : n.review._component)}</p>` : ''}
          ${o.props ? `<p class="rprops">EMB3D properties: ${props.map((p) => `${p} ${esc(E.properties[p].name)}`).join('; ') || 'none'}</p>
            ${answers ? `<ul class="ranswers">${answers}</ul>` : ''}` : ''}</div>
          ${ts.length ? `<div class="rscroll"><table class="rtable rthreats"><colgroup><col style="width:3%"><col style="width:15%"><col style="width:8%"><col style="width:9%"><col style="width:10%"><col style="width:33%"><col style="width:22%"></colgroup><thead><tr><th>#</th><th>Threat</th><th>Type</th><th>Evidence</th><th>Status</th><th>Description</th><th>Countermeasures</th></tr></thead><tbody>${body}</tbody></table></div>` : '<p class="muted">No threats to report for this component.</p>'}
        </section>`;
      };
      const multi = pagesOf(S).length > 1;
      const sections = pageOrder(S).map((p) => {
        const users = parentsOf(S, p.id);
        const ents = p.nodes.filter((n) => !isExternal(n)).map(entity).join('');
        return `${o.diagram || multi ? `<section class="rpage"><h2>${esc(multi ? p.name : S.name)}</h2>
          ${users.length ? `<p class="small muted">Used by: ${users.map((u) => esc(u.name) + (u.qty > 1 ? ' ×' + u.qty : '')).join(', ')}</p>` : ''}
          ${o.diagram ? diagramSvg(S, p) + '<p class="small muted">Dashed lines are unencrypted data flows.</p>' : ''}</section>` : ''}
          ${ents}`;
      }).join('');
      const today = o.date || new Date().toISOString().slice(0, 10);
      const g = S.generator;
      return `<article class="report">
          <p class="rbrand">${today} | EMB3D Workbench</p>
          <div class="rcard">
            <div class="rcard-h">Threat model report for ${esc(S.name)}</div>
            <table class="rkv"><tbody>
              <tr><th>Owner</th><td>${esc(m.owner) || '—'}</td><th>Reviewer</th><td>${esc(m.reviewer) || '—'}</td></tr>
              <tr><th>Threat catalogue</th><td>MITRE EMB3D STIX ${esc(E.version)}</td><th>Date generated</th><td>${today}</td></tr>
              ${g ? `<tr><th>Generated from</th><td colspan="3">${esc(g.source || '')}${g.revision ? ' @ ' + esc(g.revision) : ''}${g.tool ? ' by ' + esc(g.tool) : ''}${g.date ? ' on ' + esc(g.date) : ''}</td></tr>` : ''}
            </tbody></table>
          </div>
          <div class="rcard">
            <div class="rcard-h">Executive Summary</div>
            <h4>Description</h4><p class="rdesc">${esc(m.description) || 'Not provided'}</p>
            <h4>Summary</h4>
            <table class="rtable rsum"><thead><tr><th>Metric</th><th>Total</th></tr></thead><tbody>${stats.map(([k, v]) => `<tr><td>${k}</td><td class="num">${v}</td></tr>`).join('')}</tbody></table>
          </div>
          ${sections || '<p class="muted">No components match the report options.</p>'}
        </article>`;
    }

    const api = {
      E, get TYPES() { return TYPES; }, bind, pagesOf, pageById, allNodes, allFlows, pageOrder, parentsOf, rollup, threat, mitigation, typeOf,
      nodeById, isExternal, isDevice, hasThreats, answer, answerLabel, nodePids, nodeThreats, cmStatus, why, missingWhy, decision, missingAcceptWhy,
      threatState, allRows, cmRows, reviewItems, summary, validate, layout, normalize, toTmbom, diagramSvg, reportHtml,
      pageOf: (id) => PAGE_OF.get(id),
    };
    return api;
  }

  const api = { make, migrate, anchor, sizeOf, isDevice, esc, slug, groupClass, stateLabel, cmLabel, numSort, TMBOM_SCHEMA, EXT_KEY, NODE_W, NODE_H, DEV_W, DEV_H, CM_STATUS, CM_TO_TMBOM, MATURITY, MIT_RANK, ZONE, NEEDS_WHY };
  root.EMB3D_ENGINE = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
