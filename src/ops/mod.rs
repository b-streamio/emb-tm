// SPDX-License-Identifier: GPL-2.0-only
//! Editing operations on a project: adding blocks, moving them into devices,
//! copy and paste, splitting units, importing a project as a device and
//! custom block types. No browser API here; the UI calls these.

mod clip;
mod custom;

use std::collections::BTreeSet;

use crate::{
    engine::Model,
    model::{Flow, Node, Page, Project},
};
pub use clip::{build_clip, clone_design, cut, paste, Clip, CLIP_KEY};
pub use custom::{
    add_types, custom_ids, import_as_device, import_types, next_id, problems, save_custom, types_in,
};

pub const BOARD_W: f64 = 1500.0;
pub const BOARD_H: f64 = 980.0;

pub fn plural(n: usize, w: &str) -> String {
    format!("{n} {w}{}", if n == 1 { "" } else { "s" })
}

fn clamp_x(n: &Node, x: f64) -> f64 {
    x.clamp(0.0, BOARD_W - n.size().0)
}

fn clamp_y(n: &Node, y: f64) -> f64 {
    y.clamp(0.0, BOARD_H - n.size().1)
}

pub fn new_page_id(p: &Project) -> String {
    (p.pages.len() + 1..)
        .map(|i| format!("p{i}"))
        .find(|id| p.page(id).is_none())
        .expect("unbounded")
}

fn next_seq(p: &mut Project) -> u64 {
    p.seq += 1;
    p.seq - 1
}

fn next_flow(p: &mut Project) -> u64 {
    p.flow_seq += 1;
    p.flow_seq - 1
}

/// Adds a block of type `kind` at `(x, y)` on page `page`; a device gets a new
/// empty design page. Returns its id.
pub fn add_node(p: &mut Project, m: &Model, kind: &str, page: &str, x: f64, y: f64) -> Option<u64> {
    let def = m.types.get(kind)?;
    let id = next_seq(p);
    let mut node = Node::new(id, kind, &def.name, x.round(), y.round());
    for q in &def.questions {
        node.answers.insert(q.id.clone(), q.default.clone());
    }
    if node.is_device() {
        node.name = format!("Device {}", p.nodes().filter(|n| n.is_device()).count() + 1);
        node.qty = Some(1);
        let pid = new_page_id(p);
        p.pages.push(Page {
            id: pid.clone(),
            name: node.name.clone(),
            ..Default::default()
        });
        node.page = Some(pid);
    }
    p.page_mut(page)?.nodes.push(node);
    Some(id)
}

/// Pages reachable from `page` through device boxes, `page` included.
pub fn subtree_pages(p: &Project, page: &str, out: &mut BTreeSet<String>) {
    if !out.insert(page.to_owned()) {
        return;
    }
    for n in p.page(page).map_or(&[][..], |pg| &pg.nodes[..]) {
        if let Some(sub) = n.page.as_deref().filter(|_| n.is_device()) {
            subtree_pages(p, sub, out);
        }
    }
}

/// Puts nodes `ids` of `page` below what the page already holds, keeping their arrangement.
pub fn place_on_page(page: &mut Page, ids: &[u64]) {
    let moving = |n: &&mut Node| ids.contains(&n.id);
    let (mut x0, mut y0) = (f64::INFINITY, f64::INFINITY);
    for n in page.nodes.iter_mut().filter(moving) {
        x0 = x0.min(n.x);
        y0 = y0.min(n.y);
    }
    if x0.is_infinite() {
        return;
    }
    let top = page
        .nodes
        .iter()
        .filter(|n| !ids.contains(&n.id))
        .map(|n| n.y + n.size().1 + 40.0)
        .fold(60.0_f64, f64::max);
    for n in page.nodes.iter_mut().filter(moving) {
        n.x = clamp_x(n, (n.x - x0 + 60.0).round());
        n.y = clamp_y(n, (n.y - y0 + top).round());
    }
}

/// Moves blocks `ids` of page `src` into device `dev`. Flows between moved
/// blocks move with them; flows to blocks left outside are removed and counted.
pub fn move_into_device(
    p: &mut Project,
    src: &str,
    ids: &[u64],
    dev: u64,
) -> Result<(usize, usize), String> {
    let device = p
        .node(dev)
        .filter(|n| n.is_device())
        .ok_or("not a device")?;
    let (dev_name, target) = (device.name.clone(), device.page.clone().unwrap_or_default());
    if ids.contains(&dev) || p.page(&target).is_none() {
        return Err(String::new());
    }
    let page = p.page(src).ok_or("no page")?;
    for n in page
        .nodes
        .iter()
        .filter(|n| ids.contains(&n.id) && n.is_device())
    {
        let mut sub = BTreeSet::new();
        subtree_pages(p, n.page.as_deref().unwrap_or_default(), &mut sub);
        if sub.contains(&target) {
            return Err(format!(
                "\"{}\" contains \"{dev_name}\", so it cannot go inside it.",
                n.name
            ));
        }
    }
    let page = p.page_mut(src).expect("checked");
    let (moving, stay): (Vec<Node>, Vec<Node>) =
        page.nodes.drain(..).partition(|n| ids.contains(&n.id));
    page.nodes = stay;
    let inside = |f: &Flow| ids.contains(&f.from) && ids.contains(&f.to);
    let touches = |f: &Flow| ids.contains(&f.from) || ids.contains(&f.to);
    let flows: Vec<Flow> = page.flows.iter().filter(|f| inside(f)).cloned().collect();
    let cut = page
        .flows
        .iter()
        .filter(|f| touches(f) && !inside(f))
        .count();
    page.flows.retain(|f| !touches(f));
    let count = moving.len();
    let moved: Vec<u64> = moving.iter().map(|n| n.id).collect();
    let target = p.page_mut(&target).expect("checked");
    target.nodes.extend(moving);
    target.flows.extend(flows);
    place_on_page(target, &moved);
    Ok((count, cut))
}

/// Takes one unit out of a "×N" device box into its own box with its own
/// copy of the design; its flows are duplicated. Returns the new box id.
pub fn split_unit(p: &mut Project, page: &str, id: u64) -> Option<u64> {
    let node = p.node(id).filter(|n| n.qty() > 1)?.clone();
    let mut one = node.clone();
    one.id = next_seq(p);
    one.qty = Some(1);
    one.name = format!("{} (variant)", node.name);
    one.page = Some(clone_design(p, node.page.as_deref()?, &one.name));
    one.x = clamp_x(&one, node.x + 40.0);
    one.y = clamp_y(&one, node.y + node.size().1 + 30.0);
    p.node_mut(id)?.qty = Some(node.qty() - 1);
    let flows: Vec<Flow> = p
        .page(page)?
        .flows
        .iter()
        .filter(|f| f.from == id || f.to == id)
        .cloned()
        .collect();
    let mut copies = Vec::new();
    for f in flows {
        let fid = next_flow(p);
        copies.push(Flow {
            id: fid,
            from: if f.from == id { one.id } else { f.from },
            to: if f.to == id { one.id } else { f.to },
            ..f
        });
    }
    let pg = p.page_mut(page)?;
    let new = one.id;
    pg.nodes.push(one);
    pg.flows.extend(copies);
    Some(new)
}

/// Removes a block; a device's page goes too when it is empty and unused.
pub fn remove_node(p: &mut Project, page: &str, id: u64) {
    let sub = p
        .node(id)
        .filter(|n| n.is_device())
        .and_then(|n| n.page.clone());
    if let Some(pg) = p.page_mut(page) {
        pg.nodes.retain(|n| n.id != id);
        pg.flows.retain(|f| f.from != id && f.to != id);
    }
    if let Some(sub) = sub {
        let empty = p.page(&sub).is_some_and(|x| x.nodes.is_empty());
        if empty && p.parents_of(&sub).is_empty() {
            p.pages.retain(|x| x.id != sub);
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/ops/mod.rs"]
pub mod tests;
