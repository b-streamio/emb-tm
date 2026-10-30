// SPDX-License-Identifier: GPL-2.0-only
//! OWASP Threat Model Library (TM-BOM) export.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::{cm_label, cm_status, decision, slug, why, Hit, Model};
use crate::model::{num_cmp, Node, Project, EXT_KEY};

pub const TMBOM_SCHEMA: &str = "https://github.com/OWASP/www-project-threat-model-library/blob/v1.0.2/threat-model.schema.json";

/// Library groups as trust zones: `(group, symbolic name, title)`.
const ZONES: [(&str, &str, &str); 7] = [
    ("System", "system", "System"),
    ("Hardware", "hardware", "Hardware"),
    ("System software", "system-software", "System software"),
    ("Application", "application", "Application"),
    ("Networking", "networking", "Networking"),
    ("External", "external", "External"),
    ("Custom", "custom", "Custom"),
];

/// Symbolic name of a node.
fn sym(n: &Node) -> String {
    format!("n{}-{}", n.id, slug(&n.kind))
}

/// Threats, controls and assumptions, in first-seen order.
#[derive(Default)]
struct Findings {
    threats: Vec<Value>,
    controls: Vec<Value>,
    assumptions: Vec<Value>,
}

impl Model<'_> {
    /// OWASP Threat Model Library (TM-BOM) v1.0.2 document; embeds the project.
    pub fn to_tmbom(&self, p: &Project, today: &str) -> Value {
        let nodes: Vec<&Node> = p.nodes().collect();
        let actors: Vec<Value> = nodes
            .iter()
            .filter(|n| self.is_external(n))
            .map(|n| json!({
                "symbolic_name": sym(n), "title": n.name, "description": self.types[&n.kind].hint,
                "type": if n.kind == "person" { "user" } else { "third_party" }, "trust_zone": "external",
            }))
            .collect();
        let components: Vec<Value> = nodes
            .iter()
            .filter(|n| !self.is_external(n))
            .map(|n| self.component(p, n))
            .collect();
        let mut f = Findings::default();
        for n in nodes.iter().filter(|n| self.has_threats(n)) {
            self.findings(p, n, &mut f);
        }
        let description = if p.meta.description.is_empty() {
            format!(
                "Threat model of {}, built with EMB3D Workbench on MITRE EMB3D STIX {}.",
                p.name, self.e.version
            )
        } else {
            p.meta.description.clone()
        };
        let mut doc = json!({
            "$schema": TMBOM_SCHEMA,
            "version": "1.0",
            "scope": {
                "title": p.name, "description": description,
                "business_criticality": "moderate", "data_sensitivity": ["cred", "ip", "op"], "exposure": "external", "tier": "important",
            },
            "description": "Threats and countermeasures derived from MITRE EMB3D device properties (https://emb3d.mitre.org/).",
            "reviewed_at": today,
            "trust_zones": self.trust_zones(&nodes), "trust_boundaries": [], "actors": actors, "components": components,
            "data_stores": [], "data_sets": [], "data_flows": self.data_flows(p),
            "threat_personas": [
                {"symbolic_name": "physical-adversary", "title": "Adversary with physical device access", "description": "Skilled attacker holding the device, able to probe buses, debug ports and side channels.", "is_person": true, "skill_level": "expert_engineer", "access_level": "anonymous", "malicious_intent": true, "applicability_to_org": "moderate"},
                {"symbolic_name": "remote-adversary", "title": "Remote or local software adversary", "description": "Attacker reaching the device over a network or through code running on it.", "is_person": true, "skill_level": "engineer", "access_level": "anonymous", "malicious_intent": true, "applicability_to_org": "high"},
            ],
            "threats": f.threats, "controls": f.controls,
            "extensions": { EXT_KEY: { "emb3d_version": self.e.version, "project": p } },
        });
        if !f.assumptions.is_empty() {
            doc["assumptions"] = f.assumptions.into();
        }
        doc
    }

    fn zone(&self, n: &Node) -> &'static str {
        let g = self.type_of(n).map_or("Custom", |t| t.group.as_str());
        ZONES.iter().find(|z| z.0 == g).unwrap_or(&ZONES[6]).1
    }

    fn trust_zones(&self, nodes: &[&Node]) -> Vec<Value> {
        let used: BTreeSet<&str> = nodes.iter().map(|n| self.zone(n)).collect();
        let mut zones: Vec<Value> = ZONES
            .iter()
            .filter(|z| used.contains(z.1))
            .map(|&(_, z, t)| {
                let desc = match z {
                    "system" => "Devices of the solution".to_owned(),
                    "external" => format!("{t} parts of the devices (outside the devices)"),
                    _ => format!("{t} parts of the devices"),
                };
                json!({"symbolic_name": z, "title": t, "description": desc})
            })
            .collect();
        if zones.is_empty() {
            zones.push(
                json!({"symbolic_name": "device", "title": "Device", "description": "The device"}),
            );
        }
        zones
    }

    fn component(&self, p: &Project, n: &Node) -> Value {
        let (title, description) = if n.is_device() {
            let page = n.page.as_deref().unwrap_or_default();
            let page = p.page(page).map_or(page, |pg| pg.name.as_str());
            let units = if n.qty() > 1 {
                format!(", {} identical units", n.qty())
            } else {
                String::new()
            };
            let title = if n.qty() > 1 {
                format!("{} (x{})", n.name, n.qty())
            } else {
                n.name.clone()
            };
            (
                title,
                format!("Device{units}. Detailed design: page \"{page}\"."),
            )
        } else {
            let t = self.type_of(n);
            let mut pids: Vec<String> = self.node_pids(p, n).into_keys().collect();
            pids.sort_by(|a, b| num_cmp(a, b));
            let pids = if pids.is_empty() {
                "none".into()
            } else {
                pids.join(", ")
            };
            let custom = if t.is_some_and(|t| t.custom) {
                " (custom block)"
            } else {
                ""
            };
            (
                n.name.clone(),
                format!(
                    "{}{custom}. EMB3D properties: {pids}",
                    t.map_or("", |t| t.name.as_str())
                ),
            )
        };
        let mut c = json!({"symbolic_name": sym(n), "title": title, "description": description, "trust_zone": self.zone(n)});
        let parent = p
            .page_of(n.id)
            .and_then(|pg| p.parents_of(&pg.id).first().map(|d| sym(d)));
        if let Some(ps) = parent.filter(|ps| *ps != sym(n)) {
            c["parent_component"] = ps.into();
        }
        c
    }

    fn data_flows(&self, p: &Project) -> Vec<Value> {
        let reference = |n: &Node| json!({"type": if self.is_external(n) { "actor" } else { "component" }, "object": sym(n)});
        p.pages
            .iter()
            .flat_map(|pg| &pg.flows)
            .filter_map(|f| {
                let (a, b) = (p.node(f.from)?, p.node(f.to)?);
                Some(json!({
                    "symbolic_name": format!("f{}", f.id), "title": if f.label.is_empty() { "data flow" } else { &f.label },
                    "description": format!("{} to {}", a.name, b.name), "source": reference(a), "destination": reference(b),
                    "has_sensitive_data": f.sensitive, "encrypted": f.encrypted,
                }))
            })
            .collect()
    }

    /// The threats of one component, their decisions and countermeasures.
    fn findings(&self, p: &Project, n: &Node, f: &mut Findings) {
        // First-seen order, like the JavaScript engine.
        let mut by_mid: Vec<(String, Vec<String>)> = Vec::new();
        for hit in self.node_threats(p, n) {
            let id = format!("{}-{}", slug(&hit.tid), sym(n));
            f.threats.push(self.threat_json(n, &hit, &id));
            f.assumptions.extend(assumption(n, &hit, &id));
            for m in &hit.t.mids {
                match by_mid.iter_mut().find(|(k, _)| k == m) {
                    Some((_, tids)) => tids.push(id.clone()),
                    None => by_mid.push((m.clone(), vec![id.clone()])),
                }
            }
        }
        for (mid, tids) in by_mid {
            f.controls.extend(self.control(n, &mid, tids));
        }
    }

    fn threat_json(&self, n: &Node, Hit { tid, t, via }: &Hit, id: &str) -> Value {
        let (description, event) = if t.custom {
            let d = if t.desc.is_empty() { &t.name } else { &t.desc };
            (
                format!("{d}\n\nCustom threat defined in the project."),
                format!(
                    "Custom threat of block type \"{}\"",
                    self.types[&n.kind].name
                ),
            )
        } else {
            let via: Vec<String> = via
                .iter()
                .map(|pid| format!("{pid} {}", self.property_name(pid)))
                .collect();
            (
                format!("{}\n\nEMB3D evidence: {}.", t.desc, t.maturity),
                format!("Applies because the component has: {}", via.join("; ")),
            )
        };
        let mut th = json!({
            "symbolic_name": id, "title": format!("{tid}: {}", t.name), "description": description,
            "components_affected": [sym(n)],
            "threat_persona": if t.cat == "hardware" { "physical-adversary" } else { "remote-adversary" },
            "event": event, "sources": ["adversary"],
        });
        if !t.cwes.is_empty() {
            th["weaknesses"] = t
                .cwes
                .iter()
                .map(|(i, title)| json!({"cwe_id": i, "cwe_title": title}))
                .collect();
        }
        th
    }

    fn control(&self, n: &Node, mid: &str, tids: Vec<String>) -> Option<Value> {
        let m = self.mitigation(mid)?;
        let st = cm_status(n, mid);
        let mut d = format!(
            "{}\n\n{}",
            m.desc,
            if m.custom {
                "Custom countermeasure.".into()
            } else {
                format!("EMB3D level: {}.", m.maturity)
            }
        );
        if !m.iec.is_empty() {
            d += &format!("\nIEC 62443-4-2: {}", m.iec.join("; "));
        }
        d += &format!("\nWorkbench status: {}.", cm_label(st));
        if !why(n, mid).is_empty() {
            d += &format!("\nJustification: {}", why(n, mid));
        }
        let status = match st {
            "required" => "approved",
            "implemented" => "active",
            "rejected" | "na" => "wont_do",
            _ => "suggested",
        };
        Some(json!({
            "symbolic_name": format!("{}-{}", slug(mid), sym(n)), "title": format!("{mid}: {}", m.name), "description": d,
            "threats": tids, "status": status, "priority": if st == "required" { "high" } else { "none" },
        }))
    }
}

/// A threat declared not applicable or accepted, as a TM-BOM assumption.
fn assumption(n: &Node, Hit { tid, t, .. }: &Hit, id: &str) -> Option<Value> {
    let d = decision(n, tid);
    if d.is_empty() {
        return None;
    }
    let head = if d == "na" {
        format!("{tid} ({}) does not apply to {}.", t.name, n.name)
    } else {
        format!("Risk of {tid} ({}) accepted for {}.", t.name, n.name)
    };
    let w = why(n, &format!("accept:{tid}"));
    let tail = if w.is_empty() {
        " No justification given.".into()
    } else {
        format!(" Justification: {w}")
    };
    Some(json!({"description": head + &tail, "topics": [id], "validity": "confirmed"}))
}
