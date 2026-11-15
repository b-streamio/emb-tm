// SPDX-License-Identifier: GPL-2.0-only
//! The HTML report: header, summary and one section per page.

mod entity;

use super::{around, esc, Model, Summary};
use crate::model::{Page, Project};

/// Which parts of the report to include.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReportOpts {
    pub diagram: bool,
    pub mitigated: bool,
    pub closed: bool,
    pub empty: bool,
    pub props: bool,
    pub fulltext: bool,
}

impl Default for ReportOpts {
    fn default() -> Self {
        Self {
            diagram: true,
            mitigated: true,
            closed: true,
            empty: false,
            props: true,
            fulltext: false,
        }
    }
}

impl Model<'_> {
    /// The report body (`<article>`), laid out like OWASP Threat Dragon's report.
    pub fn report_html(&self, p: &Project, o: ReportOpts, today: &str) -> String {
        let (mut num, counts) = (0, self.counts(p));
        let multi = p.pages.len() > 1;
        let mut sections = String::new();
        for pg in p.page_order() {
            if o.diagram || multi {
                sections += &self.page_section(p, pg, o, multi);
            }
            for n in pg.nodes.iter().filter(|n| !self.is_external(n)) {
                sections += &self.report_entity(p, n, o, &counts, &mut num);
            }
        }
        if sections.is_empty() {
            sections = r#"<p class="muted">No components match the report options.</p>"#.into();
        }
        let m = &p.meta;
        let dash = |s: &str| {
            if s.is_empty() {
                "—".to_owned()
            } else {
                esc(s)
            }
        };
        let generator = p.generator().map_or(String::new(), |g| {
            format!(
                r#"<tr><th>Generated from</th><td colspan="3">{}</td></tr>"#,
                esc(&g)
            )
        });
        let rows: String = stats(&self.summary(p))
            .iter()
            .map(|(k, v)| format!(r#"<tr><td>{k}</td><td class="num">{v}</td></tr>"#))
            .collect();
        format!(
            r#"<article class="report"><p class="rbrand">{today} | emb-tm</p><div class="rcard"><div class="rcard-h">Threat model report for {}</div><table class="rkv"><tbody><tr><th>Owner</th><td>{}</td><th>Reviewer</th><td>{}</td></tr><tr><th>Threat catalogue</th><td>MITRE EMB3D STIX {}</td><th>Date generated</th><td>{today}</td></tr>{generator}</tbody></table></div><div class="rcard"><div class="rcard-h">Executive Summary</div><h4>Description</h4><p class="rdesc">{}</p><h4>Summary</h4><table class="rtable rsum"><thead><tr><th>Metric</th><th>Total</th></tr></thead><tbody>{rows}</tbody></table></div>{sections}<p class="rmore">©2026 The MITRE Corporation (MITRE EMB3D™ data). This work is reproduced and distributed with the permission of The MITRE Corporation; terms of use: emb3d.mitre.org/subtabs/terms-of-use.html. Not affiliated with or endorsed by MITRE.</p></article>"#,
            esc(&p.name),
            dash(&m.owner),
            dash(&m.reviewer),
            esc(&self.e.version),
            if m.description.is_empty() {
                "Not provided".into()
            } else {
                esc(&m.description)
            },
        )
    }

    /// A page heading: where the page is used, and its diagram.
    fn page_section(&self, p: &Project, pg: &Page, o: ReportOpts, multi: bool) -> String {
        let users: Vec<String> = p
            .parents_of(&pg.id)
            .iter()
            .map(|u| esc(&u.name) + &u.units())
            .collect();
        let used = around(
            r#"<p class="small muted">Used by: "#,
            &users.join(", "),
            "</p>",
        );
        let diagram = if o.diagram {
            self.diagram_svg(p, pg)
                + r#"<p class="small muted">Dashed lines are unencrypted data flows.</p>"#
        } else {
            String::new()
        };
        format!(
            r#"<section class="rpage"><h2>{}</h2>{used}{diagram}</section>"#,
            esc(if multi { &pg.name } else { &p.name })
        )
    }
}

/// The summary table: `(metric, value)`.
fn stats(s: &Summary) -> Vec<(&'static str, String)> {
    let mut stats: Vec<(&str, String)> = Vec::new();
    if s.pages > 1 {
        stats.extend([
            ("Devices", s.devices.to_string()),
            ("Pages", s.pages.to_string()),
        ]);
    }
    stats.extend([
        ("Total Threats", s.threats.to_string()),
        ("Total Mitigated", s.mitigated.to_string()),
        ("Total Open", s.open.to_string()),
    ]);
    if s.not_applicable > 0 {
        stats.push(("Total Not Applicable", s.not_applicable.to_string()));
    }
    if s.accepted > 0 {
        stats.push(("Total Accepted", s.accepted.to_string()));
    }
    let ev = s.open_by_evidence;
    stats.extend([
        ("Open / Observed in attacks", ev[0].to_string()),
        ("Open / Observed technique", ev[1].to_string()),
        ("Open / Known weakness", ev[2].to_string()),
        ("Open / Proof of concept", ev[3].to_string()),
    ]);
    if ev[4] > 0 {
        stats.push(("Open / Custom threats", ev[4].to_string()));
    }
    stats.push((
        "Countermeasures implemented",
        format!("{} of {}", s.implemented, s.countermeasures),
    ));
    if s.missing_justifications > 0 {
        stats.push((
            "Decisions missing a justification",
            s.missing_justifications.to_string(),
        ));
    }
    if s.needs_review > 0 {
        stats.push(("Answers needing review", s.needs_review.to_string()));
    }
    stats
}
