// SPDX-License-Identifier: GPL-2.0-only
//! One report section per component: properties, answers and threat table.

use super::ReportOpts;
use crate::{
    engine::{
        answer_label, around, cm_label, cm_status, decision, esc, maturity, why, Counts, Hit,
        Model, State,
    },
    model::{num_cmp, Node, Project, TypeDef},
};

impl Model<'_> {
    pub(super) fn report_entity(
        &self,
        p: &Project,
        n: &Node,
        o: ReportOpts,
        counts: &Counts,
        num: &mut usize,
    ) -> String {
        if n.is_device() {
            return device_entity(p, n, counts);
        }
        let Some(def) = self.type_of(n) else {
            return String::new();
        };
        let hits = self.reported_hits(p, n, o);
        if hits.is_empty() && !o.empty {
            return String::new();
        }
        let comp_ev = around(
            r#"<p class="rprops">Identified from: "#,
            &evidence(n, "_component", "; "),
            "</p>",
        );
        let comp_rv = n.review_of("_component").map_or(String::new(), |r| {
            format!(
                r#"<p class="rprops"><span class="rflag">needs review:</span> {}</p>"#,
                esc(&r)
            )
        });
        let props = if o.props {
            self.props_html(p, n, def)
        } else {
            String::new()
        };
        let table = if hits.is_empty() {
            r#"<p class="muted">No threats to report for this component.</p>"#.to_owned()
        } else {
            let body: String = hits
                .iter()
                .map(|(h, st)| {
                    *num += 1;
                    self.threat_row(n, h, *st, o, *num)
                })
                .collect();
            format!(
                r#"<div class="rscroll"><table class="rtable rthreats"><colgroup><col style="width:3%"><col style="width:15%"><col style="width:8%"><col style="width:9%"><col style="width:10%"><col style="width:33%"><col style="width:22%"></colgroup><thead><tr><th>#</th><th>Threat</th><th>Type</th><th>Evidence</th><th>Status</th><th>Description</th><th>Countermeasures</th></tr></thead><tbody>{body}</tbody></table></div>"#
            )
        };
        format!(
            r#"<section class="rentity"><div class="rhead"><h3>{} ({})</h3>{comp_ev}{comp_rv}{props}</div>{table}</section>"#,
            esc(&n.name),
            esc(&def.name)
        )
    }

    /// A component's threats and states, as far as the options include them.
    fn reported_hits(&self, p: &Project, n: &Node, o: ReportOpts) -> Vec<(Hit<'_>, State)> {
        self.node_threats(p, n)
            .into_iter()
            .map(|h| {
                let st = self.threat_state(n, &h.tid);
                (h, st)
            })
            .filter(|(_, st)| {
                (o.mitigated || *st != State::Mitigated)
                    && (o.closed || !matches!(st, State::NotApplicable | State::Accepted))
            })
            .collect()
    }

    /// A component's EMB3D properties and its answers, with evidence.
    fn props_html(&self, p: &Project, n: &Node, def: &TypeDef) -> String {
        let answers: String = def
            .questions
            .iter()
            .map(|q| {
                let flag = n.review_of(&q.id).map_or(String::new(), |r| {
                    format!(
                        r#" <span class="rflag">needs review{}</span>"#,
                        around(": ", &esc(&r), "")
                    )
                });
                let ev = around(
                    r#"<div class="rwhy">"#,
                    &evidence(n, &q.id, "<br>"),
                    "</div>",
                );
                format!(
                    r#"<li><span class="rq">{}:</span> <b>{}</b>{flag}{ev}</li>"#,
                    esc(&q.text),
                    esc(&answer_label(n, q))
                )
            })
            .collect();
        let mut pids: Vec<String> = self.node_pids(p, n).into_keys().collect();
        pids.sort_by(|a, b| num_cmp(a, b));
        let pids: Vec<String> = pids
            .iter()
            .map(|pid| format!("{pid} {}", esc(self.property_name(pid))))
            .collect();
        let pids = if pids.is_empty() {
            "none".into()
        } else {
            pids.join("; ")
        };
        let answers = around(r#"<ul class="ranswers">"#, &answers, "</ul>");
        format!(r#"<p class="rprops">EMB3D properties: {pids}</p>{answers}"#)
    }

    /// One row of a component's threat table.
    fn threat_row(&self, n: &Node, h: &Hit, st: State, o: ReportOpts, num: usize) -> String {
        let cms: String =
            h.t.mids
                .iter()
                .filter_map(|mid| {
                    let m = self.mitigation(mid)?;
                    let w = around(r#"<div class="rwhy">"#, &esc(why(n, mid)), "</div>");
                    Some(format!(
                        r#"<div class="rcm"><b>{}</b> {} — <i>{}</i>{w}</div>"#,
                        esc(mid),
                        esc(&m.name),
                        esc(cm_label(cm_status(n, mid)))
                    ))
                })
                .collect();
        let text = if o.fulltext {
            h.t.text.clone()
        } else {
            vec![h.t.desc.clone()]
        };
        let mut desc: String = text
            .iter()
            .map(|x| format!(r#"<p class="rp">{}</p>"#, esc(&x.replace('*', ""))))
            .collect();
        if !o.fulltext && !h.t.custom && h.t.text.len() > 1 {
            desc += &format!(
                r#"<p class="rp rmore">Full text: emb3d.mitre.org/threats/{}.html</p>"#,
                esc(&h.tid)
            );
        }
        format!(
            r#"<tr><td class="num">{num}</td><td><b>{}</b> {}</td><td>{}</td><td>{}</td><td>{}{}</td><td>{desc}</td><td>{}</td></tr>"#,
            esc(&h.tid),
            esc(&h.t.name),
            esc(&h.t.cat),
            esc(maturity(&h.t.maturity).1),
            st.label(),
            decided(n, &h.tid),
            if cms.is_empty() { "—".into() } else { cms },
        )
    }
}

/// A device: a pointer to its page and that page's counts.
fn device_entity(p: &Project, n: &Node, counts: &Counts) -> String {
    let page = n.page.as_deref().unwrap_or_default();
    let r = counts.page(page);
    let qty = n.units();
    let each = if n.qty() > 1 {
        format!("; applies to each of the {} units", n.qty())
    } else {
        String::new()
    };
    let name = p.page(page).map_or(page, |pg| pg.name.as_str());
    format!(
        r#"<section class="rentity"><div class="rhead"><h3>{} (Device{qty})</h3><p class="rprops">Detailed on page "{}": {} threats, {} open{each}.</p></div></section>"#,
        esc(&n.name),
        esc(name),
        r.threats,
        r.open
    )
}

/// Evidence of an answer (or `_component`), escaped, joined by `sep`.
fn evidence(n: &Node, qid: &str, sep: &str) -> String {
    n.evidence.get(qid).map_or_else(String::new, |ev| {
        ev.iter()
            .map(|e| esc(&e.label()))
            .collect::<Vec<_>>()
            .join(sep)
    })
}

/// A threat-level decision and its justification.
fn decided(n: &Node, tid: &str) -> String {
    let d = decision(n, tid);
    if d.is_empty() {
        return String::new();
    }
    let w = esc(why(n, &format!("accept:{tid}")));
    let w = if w.is_empty() {
        "<i>no justification</i>".into()
    } else {
        w
    };
    format!(
        r#"<div class="rwhy">{}: {w}</div>"#,
        if d == "na" {
            "Not applicable"
        } else {
            "Risk accepted"
        }
    )
}
