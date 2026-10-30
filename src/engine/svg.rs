// SPDX-License-Identifier: GPL-2.0-only
//! The diagram of a page as SVG, for the report and print.

use super::{esc, group_class, Model};
use crate::model::{Node, Page, Project};

impl Model<'_> {
    /// The diagram of a page as SVG (report and print).
    pub fn diagram_svg(&self, p: &Project, page: &Page) -> String {
        if page.nodes.is_empty() {
            return r#"<p class="muted">This page is empty.</p>"#.into();
        }
        let pad = 30.0;
        let min = |f: fn(&Node) -> f64| page.nodes.iter().map(f).fold(f64::INFINITY, f64::min);
        let max = |f: fn(&Node) -> f64| page.nodes.iter().map(f).fold(f64::NEG_INFINITY, f64::max);
        let (x0, y0) = (min(|n| n.x) - pad, min(|n| n.y) - pad);
        let (x1, y1) = (
            max(|n| n.x + n.size().0) + pad,
            max(|n| n.y + n.size().1) + pad,
        );
        let id = esc(&page.id);
        let mut out = format!(
            r#"<svg class="rdiagram" viewBox="{x0} {y0} {} {}" role="img" aria-label="{} diagram"><defs><marker id="rarr-{id}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="rarrow"></path></marker></defs>"#,
            x1 - x0,
            y1 - y0,
            esc(&page.name)
        );
        for f in &page.flows {
            let (Some(a), Some(b)) = (
                page.nodes.iter().find(|n| n.id == f.from),
                page.nodes.iter().find(|n| n.id == f.to),
            ) else {
                continue;
            };
            let ((sx, sy), (qx, qy)) = (anchor(a, b), anchor(b, a));
            let plain = if f.encrypted { "" } else { " plain" };
            out += &format!(
                r#"<line class="redge{plain}" x1="{sx}" y1="{sy}" x2="{qx}" y2="{qy}" marker-end="url(#rarr-{id})"></line><text class="rlabel" x="{}" y="{}" text-anchor="middle">{}</text>"#,
                (sx + qx) / 2.0,
                (sy + qy) / 2.0 - 6.0,
                esc(&f.label)
            );
        }
        for n in &page.nodes {
            out += &self.node_svg(p, n);
        }
        out + "</svg>"
    }

    /// One block: its box, tag, name and, for a device, its page.
    fn node_svg(&self, p: &Project, n: &Node) -> String {
        let (group, tag, external) = self.type_of(n).map_or(("Custom", "?", false), |t| {
            (t.group.as_str(), t.tag.as_str(), t.external)
        });
        let (w, h) = n.size();
        let lines = wrap(
            &format!("{}{}", n.name, n.units()),
            if n.is_device() { 28 } else { 22 },
        );
        let names: String = lines
            .iter()
            .enumerate()
            .map(|(i, l)| {
                format!(
                    r#"<text class="rname" x="{}" y="{}">{}</text>"#,
                    n.x + 10.0,
                    n.y + 36.0 + i as f64 * 16.0,
                    esc(l)
                )
            })
            .collect();
        let see = if n.is_device() {
            let name = n
                .page
                .as_deref()
                .and_then(|id| p.page(id))
                .map_or("", |pg| pg.name.as_str());
            format!(
                r#"<text class="rtag" x="{}" y="{}">see page: {}</text>"#,
                n.x + 10.0,
                n.y + h - 12.0,
                esc(name)
            )
        } else {
            String::new()
        };
        format!(
            r#"<g class="rnode {}{}{}"><rect x="{}" y="{}" width="{w}" height="{h}" rx="8"></rect><text class="rtag" x="{}" y="{}">{} · #{}</text>{names}{see}</g>"#,
            group_class(group),
            if external { " ext" } else { "" },
            if n.is_device() { " dev" } else { "" },
            n.x,
            n.y,
            n.x + 10.0,
            n.y + 17.0,
            esc(tag),
            n.id
        )
    }
}

/// Point on node `a`'s border towards node `b`'s centre.
pub fn anchor(a: &Node, b: &Node) -> (f64, f64) {
    let ((aw, ah), (bw, bh)) = (a.size(), b.size());
    let (acx, acy) = (a.x + aw / 2.0, a.y + ah / 2.0);
    let (dx, dy) = (b.x + bw / 2.0 - acx, b.y + bh / 2.0 - acy);
    if dx == 0.0 && dy == 0.0 {
        return (acx, acy);
    }
    let sx = (aw / 2.0 + 6.0) / if dx == 0.0 { 1e-9 } else { dx.abs() };
    let sy = (ah / 2.0 + 8.0) / if dy == 0.0 { 1e-9 } else { dy.abs() };
    let s = sx.min(sy);
    (acx + dx * s, acy + dy * s)
}

/// At most two lines of about `w` characters.
fn wrap(t: &str, w: usize) -> Vec<String> {
    let mut lines = vec![String::new()];
    for word in t.split_whitespace() {
        let last = lines.last_mut().expect("never empty");
        if !last.is_empty() && last.chars().count() + 1 + word.chars().count() > w {
            lines.push(word.to_owned());
        } else {
            if !last.is_empty() {
                last.push(' ');
            }
            last.push_str(word);
        }
    }
    lines.truncate(2);
    lines
}

#[cfg(test)]
#[path = "../../tests/unit/engine/svg.rs"]
mod tests;
