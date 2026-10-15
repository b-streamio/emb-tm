/* EMB3D STIX 2.1 bundle -> Workbench data model.
 * Reads MITRE's published file unchanged, so adding an EMB3D release is just dropping in the file.
 *
 *   properties:  { 'PID-11': { name, cat, parent } }
 *   threats:     { 'TID-101': { name, cat, maturity, desc, cwes: [[id, title]], cves, pids, mids } }
 *   mitigations: { 'MID-001': { name, maturity, desc, text: [para], refs: [{t, u}], iec: [str] } }
 */
(function (root) {
  'use strict';

  const CWE_RE = /\[CWE-(\d+):\s*([^\]]+?)\s*(?:\([A-Za-z ]+\))?\]/g;

  const firstPara = (s) => String(s || '').trim().split(/\n\s*\n/)[0].trim();

  // Light markdown cleanup: paragraphs of plain text, *emphasis* markers kept.
  function paras(md) {
    const s = String(md || '').replace(/<\/?u>/g, '').replace(/\\\[/g, '[').replace(/\\\]/g, ']').replace(/ /g, ' ');
    return s.split(/\n\s*\n/).map((p) => p.replace(/\s*\n\s*/g, ' ').trim()).filter(Boolean);
  }

  function refs(md) {
    return paras(md).map((p) => {
      const m = p.match(/<(https?:\/\/[^>]+)>/);
      const t = p.replace(/^\[\d+\]\s*/, '').replace(/\s*\[Online\.?\]\s*Available:\s*<[^>]+>\s*/, '').trim();
      return { t, u: m ? m[1] : '' };
    });
  }

  function bullets(md) {
    return String(md || '').split('\n').filter((l) => l.startsWith('- ')).map((l) => l.slice(2).trim())
      .map((b) => b.replace(/\[([^\]]+)\]\([^)]*\)/g, '$1'))
      .filter((b) => b.toLowerCase() !== 'none referenced');
  }

  const sortIds = (a, b) => a.localeCompare(b, 'en', { numeric: true });

  function parse(bundle, version) {
    if (!bundle || bundle.type !== 'bundle' || !Array.isArray(bundle.objects)) {
      throw new Error('Not a STIX bundle');
    }
    const objs = bundle.objects;
    const by = {};
    objs.forEach((o) => { by[o.id] = o; });
    const P = {}, T = {}, M = {};
    for (const o of objs) {
      if (o.type === 'x-mitre-emb3d-property') {
        P[o.x_mitre_emb3d_property_id] = { name: o.name, cat: o.category, parent: null };
      } else if (o.type === 'vulnerability' && o.x_mitre_emb3d_threat_id) {
        const cw = [];
        for (const m of String(o.x_mitre_emb3d_threat_CWEs || '').matchAll(CWE_RE)) cw.push([Number(m[1]), m[2]]);
        T[o.x_mitre_emb3d_threat_id] = {
          name: o.name, cat: o.x_mitre_emb3d_threat_category, maturity: o.x_mitre_emb3d_threat_maturity,
          desc: firstPara(o.description), text: paras(o.description), cwes: cw, cves: bullets(o.x_mitre_emb3d_threat_CVEs).length, pids: [], mids: [],
        };
      } else if (o.type === 'course-of-action' && o.x_mitre_emb3d_mitigation_id) {
        M[o.x_mitre_emb3d_mitigation_id] = {
          name: o.name, maturity: o.x_mitre_emb3d_mitigation_maturity, desc: firstPara(o.description),
          text: paras(o.description), refs: refs(o.x_mitre_emb3d_mitigation_references),
          iec: bullets(o.x_mitre_emb3d_mitigation_IEC_62443_mappings),
        };
      }
    }
    for (const r of objs) {
      if (r.type !== 'relationship') continue;
      const s = by[r.source_ref], t = by[r.target_ref];
      if (!s || !t) continue;
      if (r.relationship_type === 'subproperty-of' && P[s.x_mitre_emb3d_property_id]) {
        P[s.x_mitre_emb3d_property_id].parent = t.x_mitre_emb3d_property_id;
      } else if (r.relationship_type === 'relates-to' && T[t.x_mitre_emb3d_threat_id]) {
        T[t.x_mitre_emb3d_threat_id].pids.push(s.x_mitre_emb3d_property_id);
      } else if (r.relationship_type === 'mitigates' && T[t.x_mitre_emb3d_threat_id]) {
        T[t.x_mitre_emb3d_threat_id].mids.push(s.x_mitre_emb3d_mitigation_id);
      }
    }
    Object.values(T).forEach((t) => { t.pids = [...new Set(t.pids)].sort(sortIds); t.mids = [...new Set(t.mids)].sort(sortIds); });
    const ordered = (o) => Object.fromEntries(Object.keys(o).sort(sortIds).map((k) => [k, o[k]]));
    return { version, properties: P, threats: ordered(T), mitigations: ordered(M) };
  }

  // What changes for a project when moving between two parsed versions.
  function diff(a, b) {
    const keys = (o) => new Set(Object.keys(o));
    const changed = (x, y, f) => [...keys(x)].filter((k) => k in y && f(x[k], y[k]));
    return {
      threatsAdded: [...keys(b.threats)].filter((k) => !(k in a.threats)),
      threatsRemoved: [...keys(a.threats)].filter((k) => !(k in b.threats)),
      threatsRenamed: changed(a.threats, b.threats, (x, y) => x.name !== y.name),
      threatsRemapped: changed(a.threats, b.threats, (x, y) => x.pids.join() !== y.pids.join() || x.mids.join() !== y.mids.join()),
      mitigationsAdded: [...keys(b.mitigations)].filter((k) => !(k in a.mitigations)),
      mitigationsRemoved: [...keys(a.mitigations)].filter((k) => !(k in b.mitigations)),
      mitigationsRenamed: changed(a.mitigations, b.mitigations, (x, y) => x.name !== y.name),
      propertiesRemoved: [...keys(a.properties)].filter((k) => !(k in b.properties)),
    };
  }

  root.EMB3D_STIX = { parse, diff };
  if (typeof module !== 'undefined') module.exports = { parse, diff };
})(typeof window !== 'undefined' ? window : globalThis);
