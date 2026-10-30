// SPDX-License-Identifier: GPL-2.0-only
//! Threat counts per component and page, review items and the project summary.

use std::collections::{BTreeMap, BTreeSet};

use super::{maturity, missing_accept_why, missing_why, Model, State};
use crate::model::{Node, Project};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Rollup {
    pub threats: usize,
    pub open: usize,
    pub review: usize,
}

/// Threat counts of every component and every page, computed once per
/// project change and read by the board, the page list and the report.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Counts {
    pub nodes: BTreeMap<u64, Rollup>,
    /// A page includes the device pages inside it, each page once.
    pub pages: BTreeMap<String, Rollup>,
}

impl Counts {
    pub fn node(&self, id: u64) -> Rollup {
        self.nodes.get(&id).copied().unwrap_or_default()
    }

    pub fn page(&self, id: &str) -> Rollup {
        self.pages.get(id).copied().unwrap_or_default()
    }

    /// Open threats of the whole model.
    pub fn open(&self) -> usize {
        self.nodes.values().map(|r| r.open).sum()
    }

    fn rollup(&self, p: &Project, page: &str, seen: &mut BTreeSet<String>) -> Rollup {
        let mut out = Rollup::default();
        if !seen.insert(page.to_owned()) {
            return out;
        }
        for n in p.page(page).map_or(&[][..], |pg| &pg.nodes[..]) {
            let r = match &n.page {
                Some(inner) if n.is_device() => self.rollup(p, inner, seen),
                _ => self.node(n.id),
            };
            out.threats += r.threats;
            out.open += r.open;
            out.review += r.review;
        }
        out
    }
}

pub struct ReviewItem<'p> {
    pub node: &'p Node,
    pub question: String,
    pub reason: String,
}

#[derive(Debug, Default, PartialEq)]
pub struct Summary {
    pub pages: usize,
    pub devices: usize,
    pub components: usize,
    pub flows: usize,
    pub threats: usize,
    pub open: usize,
    pub mitigated: usize,
    pub not_applicable: usize,
    pub accepted: usize,
    /// Open threats per evidence rank 0..=4.
    pub open_by_evidence: [usize; 5],
    pub countermeasures: usize,
    pub implemented: usize,
    pub missing_justifications: usize,
    pub needs_review: usize,
}

impl Model<'_> {
    /// Threat counts of every component and page.
    pub fn counts(&self, p: &Project) -> Counts {
        let mut c = Counts::default();
        for n in p.nodes().filter(|n| !n.is_device()) {
            let hits = self.node_threats(p, n);
            let open = hits
                .iter()
                .filter(|h| self.threat_state(n, &h.tid) == State::Open)
                .count();
            let review = n.reviews().count();
            c.nodes.insert(
                n.id,
                Rollup {
                    threats: hits.len(),
                    open,
                    review,
                },
            );
        }
        for pg in &p.pages {
            let r = c.rollup(p, &pg.id, &mut BTreeSet::new());
            c.pages.insert(pg.id.clone(), r);
        }
        c
    }

    /// Answers flagged for a human look (e.g. by the Yocto scanner).
    pub fn review_items<'p>(&self, p: &'p Project) -> Vec<ReviewItem<'p>> {
        let mut out = Vec::new();
        for node in p.nodes() {
            let Some(def) = self.type_of(node) else {
                continue;
            };
            // In questionnaire order, the component itself first.
            let mut reviews: Vec<_> = node.reviews().collect();
            reviews.sort_by_key(|(qid, _)| {
                match def.questions.iter().position(|q| &q.id == *qid) {
                    Some(i) => i + 1,
                    None if *qid == "_component" => 0,
                    None => usize::MAX,
                }
            });
            for (qid, reason) in reviews {
                let question = match def.questions.iter().find(|q| &q.id == qid) {
                    Some(q) => q.text.clone(),
                    None if qid == "_component" => "Component".into(),
                    None => qid.clone(),
                };
                out.push(ReviewItem {
                    node,
                    question,
                    reason,
                });
            }
        }
        out
    }

    pub fn summary(&self, p: &Project) -> Summary {
        let rows = self.all_rows(p);
        let cms = self.cm_rows(p);
        let count = |s: State| rows.iter().filter(|r| r.state == s).count();
        let mut open_by_evidence = [0; 5];
        for r in rows.iter().filter(|r| r.state == State::Open) {
            if let Some(n) = open_by_evidence.get_mut(usize::from(maturity(&r.hit.t.maturity).0)) {
                *n += 1;
            }
        }
        Summary {
            pages: p.pages.len(),
            devices: p.nodes().filter(|n| n.is_device()).count(),
            components: p.nodes().filter(|n| self.has_threats(n)).count(),
            flows: p.pages.iter().map(|pg| pg.flows.len()).sum(),
            threats: rows.len(),
            open: count(State::Open),
            mitigated: count(State::Mitigated),
            not_applicable: count(State::NotApplicable),
            accepted: count(State::Accepted),
            open_by_evidence,
            countermeasures: cms.len(),
            implemented: cms.iter().filter(|r| r.status == "implemented").count(),
            missing_justifications: cms.iter().filter(|r| missing_why(r.node, &r.mid)).count()
                + rows
                    .iter()
                    .filter(|r| missing_accept_why(r.node, &r.hit.tid))
                    .count(),
            needs_review: self.review_items(p).len(),
        }
    }
}
