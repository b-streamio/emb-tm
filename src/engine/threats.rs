// SPDX-License-Identifier: GPL-2.0-only
//! What applies to a component: its answers and decisions, EMB3D properties, threats and countermeasures.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{maturity, mit_rank, Model, State, NEEDS_WHY};
use crate::{
    model::{num_cmp, Node, Page, Project, Question},
    stix::{Mitigation, Threat},
};

/// Why a component has a property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Base,
    Answer,
    Parent,
    /// PID-26: the device has no update agent.
    Rule,
}

pub struct Hit<'m> {
    pub tid: String,
    pub t: &'m Threat,
    /// Properties (or `custom`) that make it apply.
    pub via: Vec<String>,
}

pub struct Row<'m, 'p> {
    pub node: &'p Node,
    pub page: &'p Page,
    pub hit: Hit<'m>,
    pub state: State,
}

pub struct CmRow<'m, 'p> {
    pub node: &'p Node,
    pub page: &'p Page,
    pub mid: String,
    pub m: &'m Mitigation,
    pub tids: Vec<String>,
    pub status: String,
}

pub fn answer<'a>(node: &'a Node, q: &'a Question) -> &'a Value {
    node.answers.get(&q.id).unwrap_or(&q.default)
}

pub fn answer_label(node: &Node, q: &Question) -> String {
    let a = answer(node, q);
    if q.kind == "bool" {
        return if a.as_bool().unwrap_or(false) {
            "Yes"
        } else {
            "No"
        }
        .into();
    }
    let s = a.as_str().unwrap_or_default();
    q.options
        .iter()
        .find(|o| o.value == s)
        .map_or_else(|| s.to_owned(), |o| o.label.clone())
}

pub fn cm_status<'n>(node: &'n Node, mid: &str) -> &'n str {
    node.cm.get(mid).map_or("recommended", String::as_str)
}

pub fn why<'n>(node: &'n Node, key: &str) -> &'n str {
    node.why.get(key).map_or("", |s| s.trim())
}

pub fn missing_why(node: &Node, mid: &str) -> bool {
    NEEDS_WHY.contains(&cm_status(node, mid)) && why(node, mid).is_empty()
}

/// Threat-level decision: `""` (countermeasures), `"na"` or `"accept"`.
pub fn decision<'n>(node: &'n Node, tid: &str) -> &'n str {
    match node.accepted.get(tid) {
        Some(Value::Bool(true)) => "accept",
        Some(Value::String(s)) => s,
        _ => "",
    }
}

pub fn missing_accept_why(node: &Node, tid: &str) -> bool {
    !decision(node, tid).is_empty() && why(node, &format!("accept:{tid}")).is_empty()
}

impl Model<'_> {
    /// EMB3D properties of a component and why it has each.
    pub fn node_pids(&self, p: &Project, node: &Node) -> BTreeMap<String, Source> {
        let mut out = BTreeMap::new();
        let Some(def) = self.type_of(node).filter(|_| !node.is_device()) else {
            return out;
        };
        for pid in &def.base {
            out.insert(pid.clone(), Source::Base);
        }
        for q in &def.questions {
            let a = answer(node, q);
            let pids = match q.kind.as_str() {
                "bool" if a.as_bool() == Some(true) => &q.pids[..],
                "choice" => q
                    .options
                    .iter()
                    .find(|o| a.as_str() == Some(&o.value))
                    .map_or(&[][..], |o| &o.pids[..]),
                _ => &[],
            };
            for pid in pids {
                out.entry(pid.clone()).or_insert(Source::Answer);
            }
        }
        let peers = p.page_of(node.id).map_or(&[][..], |pg| &pg.nodes[..]);
        if !peers.iter().any(|n| n.kind == "update") {
            let host = peers
                .iter()
                .find(|n| n.kind == "os")
                .or_else(|| peers.iter().find(|n| n.kind == "soc"));
            if host.is_some_and(|h| h.id == node.id) {
                out.insert("PID-26".into(), Source::Rule);
            }
        }
        out.retain(|pid, _| self.e.properties.contains_key(pid)); // not defined in this EMB3D version
        for pid in out.keys().cloned().collect::<Vec<_>>() {
            let mut parent = self.e.properties[&pid].parent.clone();
            while let Some(par) = parent {
                out.entry(par.clone()).or_insert(Source::Parent);
                parent = self.e.properties.get(&par).and_then(|p| p.parent.clone());
            }
        }
        out
    }

    pub fn node_threats(&self, p: &Project, node: &Node) -> Vec<Hit<'_>> {
        if !self.has_threats(node) {
            return Vec::new();
        }
        let pids = self.node_pids(p, node);
        let mut res: Vec<Hit> = self
            .e
            .threats
            .iter()
            .filter_map(|(tid, t)| {
                let via: Vec<String> = t
                    .pids
                    .iter()
                    .filter(|p| pids.contains_key(*p))
                    .cloned()
                    .collect();
                (!via.is_empty()).then(|| Hit {
                    tid: tid.clone(),
                    t,
                    via,
                })
            })
            .collect();
        for ct in self.type_of(node).map_or(&[][..], |d| &d.threats[..]) {
            if let Some(t) = self.threats.get(&ct.id) {
                res.push(Hit {
                    tid: ct.id.clone(),
                    t,
                    via: vec!["custom".into()],
                });
            }
        }
        res.sort_by(|a, b| {
            maturity(&a.t.maturity)
                .0
                .cmp(&maturity(&b.t.maturity).0)
                .then_with(|| num_cmp(&a.tid, &b.tid))
        });
        res
    }

    pub fn threat_state(&self, node: &Node, tid: &str) -> State {
        match decision(node, tid) {
            "accept" => return State::Accepted,
            "na" => return State::NotApplicable,
            _ => {}
        }
        let mids = self.threat(tid).map_or(&[][..], |t| &t.mids[..]);
        if mids.iter().any(|m| cm_status(node, m) == "implemented") {
            State::Mitigated
        } else if !mids.is_empty() && mids.iter().all(|m| cm_status(node, m) == "na") {
            State::NotApplicable
        } else {
            State::Open
        }
    }

    pub fn all_rows<'p>(&self, p: &'p Project) -> Vec<Row<'_, 'p>> {
        let mut rows = Vec::new();
        for page in &p.pages {
            for node in &page.nodes {
                for hit in self.node_threats(p, node) {
                    let state = self.threat_state(node, &hit.tid);
                    rows.push(Row {
                        node,
                        page,
                        hit,
                        state,
                    });
                }
            }
        }
        rows
    }

    pub fn cm_rows<'p>(&self, p: &'p Project) -> Vec<CmRow<'_, 'p>> {
        let mut rows = Vec::new();
        for page in &p.pages {
            for node in &page.nodes {
                let mut by_mid: BTreeMap<String, Vec<String>> = BTreeMap::new();
                for hit in self.node_threats(p, node) {
                    for m in &hit.t.mids {
                        by_mid.entry(m.clone()).or_default().push(hit.tid.clone());
                    }
                }
                for (mid, tids) in by_mid {
                    if let Some(m) = self.mitigation(&mid) {
                        let status = cm_status(node, &mid).to_owned();
                        rows.push(CmRow {
                            node,
                            page,
                            mid,
                            m,
                            tids,
                            status,
                        });
                    }
                }
            }
        }
        rows.sort_by(|a, b| {
            mit_rank(&a.m.maturity)
                .cmp(&mit_rank(&b.m.maturity))
                .then_with(|| num_cmp(&a.mid, &b.mid))
                .then(a.node.id.cmp(&b.node.id))
        });
        rows
    }
}

#[cfg(test)]
#[path = "../../tests/unit/engine/threats.rs"]
mod tests;
