// SPDX-License-Identifier: GPL-2.0-only
//! Copy, cut and paste of blocks, with the design pages of devices among them.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    clamp_x, clamp_y,
    custom::{add_types, rekey},
    new_page_id, next_flow, next_seq, place_on_page, subtree_pages,
};
use crate::{
    engine::Model,
    model::{CustomType, Flow, Node, Page, Project},
};

/// Marker field of a clipboard payload.
pub const CLIP_KEY: &str = "emb3dWorkbenchClipboard";

/// A self-contained copy of some blocks of a page, with the design pages of
/// any devices among them. Plain JSON, so it pastes across tabs.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Clip {
    #[serde(rename = "emb3dWorkbenchClipboard")]
    pub marker: u8,
    #[serde(default)]
    pub emb3d: Option<String>,
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub pages: Vec<Page>,
    #[serde(default)]
    pub flows: Vec<Flow>,
    #[serde(default, rename = "customTypes")]
    pub custom_types: Vec<CustomType>,
}

/// Copy of blocks `ids` of page `page`.
pub fn build_clip(p: &Project, page: &str, ids: &[u64]) -> Clip {
    let pg = p.page(page).cloned().unwrap_or_default();
    let nodes: Vec<Node> = pg
        .nodes
        .iter()
        .filter(|n| ids.contains(&n.id))
        .cloned()
        .collect();
    let pages = pages_below(
        p,
        nodes
            .iter()
            .filter(|n| n.is_device())
            .filter_map(|n| n.page.as_deref()),
    );
    let types: BTreeSet<&str> = nodes
        .iter()
        .chain(pages.iter().flat_map(|x| &x.nodes))
        .map(|n| n.kind.as_str())
        .collect();
    Clip {
        marker: 1,
        emb3d: p.emb3d.clone(),
        flows: pg
            .flows
            .iter()
            .filter(|f| ids.contains(&f.from) && ids.contains(&f.to))
            .cloned()
            .collect(),
        custom_types: p
            .custom_types
            .iter()
            .filter(|c| types.contains(c.kind.as_str()))
            .cloned()
            .collect(),
        nodes,
        pages,
    }
}

/// Removes blocks `ids` (and their flows) from page `page`, with the design
/// pages only they used.
pub fn cut(p: &mut Project, page: &str, ids: &[u64]) {
    let mut gone = BTreeSet::new();
    if let Some(pg) = p.page(page) {
        for d in pg
            .nodes
            .iter()
            .filter(|n| ids.contains(&n.id) && n.is_device())
        {
            subtree_pages(p, d.page.as_deref().unwrap_or_default(), &mut gone);
        }
    }
    if let Some(pg) = p.page_mut(page) {
        pg.nodes.retain(|n| !ids.contains(&n.id));
        pg.flows
            .retain(|f| !ids.contains(&f.from) && !ids.contains(&f.to));
    }
    let used: BTreeSet<String> = p
        .pages
        .iter()
        .filter(|x| !gone.contains(&x.id))
        .flat_map(|x| &x.nodes)
        .filter_map(|n| n.page.clone().filter(|_| n.is_device()))
        .collect();
    let root = p.root.clone();
    p.pages
        .retain(|x| !gone.contains(&x.id) || used.contains(&x.id) || x.id == root);
}

/// Pastes `c` onto page `page` (inside device `into` when given). Pasted
/// devices get fresh pages, so a paste can never create a loop. Returns the
/// new block ids.
pub fn paste(
    p: &mut Project,
    m: &Model,
    c: &Clip,
    page: &str,
    into: Option<u64>,
    nudge: f64,
    suffix: &str,
) -> Result<Vec<u64>, String> {
    let unknown = unknown_types(p, m, c);
    if !unknown.is_empty() {
        return Err(format!(
            "Cannot paste: unknown block types {}",
            unknown.join(", ")
        ));
    }
    let (_, remap) = add_types(p, m, c.custom_types.clone());
    let mut c = c.clone();
    for n in c
        .nodes
        .iter_mut()
        .chain(c.pages.iter_mut().flat_map(|x| &mut x.nodes))
    {
        rekey(n, &remap);
    }
    let target = match into {
        Some(dev) => p
            .node(dev)
            .and_then(|d| d.page.clone())
            .ok_or("no device")?,
        None => page.to_owned(),
    };
    let page_map = copy_pages(p, &c.pages);
    let (mut added, flows) = copy_blocks(p, &c.nodes, &c.flows, &page_map);
    let ids: Vec<u64> = added.iter().map(|n| n.id).collect();
    for n in &mut added {
        n.name += suffix;
        if into.is_none() {
            n.x = clamp_x(n, n.x + nudge);
            n.y = clamp_y(n, n.y + nudge);
        }
    }
    if !suffix.is_empty() {
        name_pages(p, &added, &page_map);
    }
    let pg = p.page_mut(&target).ok_or("no page")?;
    pg.nodes.extend(added);
    pg.flows.extend(flows);
    if into.is_some() {
        place_on_page(pg, &ids);
    }
    Ok(ids)
}

/// Block types of `c` that neither the library nor a custom type defines.
fn unknown_types<'c>(p: &Project, m: &Model, c: &'c Clip) -> Vec<&'c str> {
    let known = |k: &str| {
        m.types.contains_key(k)
            || c.custom_types
                .iter()
                .chain(&p.custom_types)
                .any(|t| t.kind == k)
    };
    let mut unknown: Vec<&str> = c
        .nodes
        .iter()
        .chain(c.pages.iter().flat_map(|x| &x.nodes))
        .map(|n| n.kind.as_str())
        .filter(|k| !known(k))
        .collect();
    unknown.dedup();
    unknown
}

/// Names the pasted design pages of devices `added` after their boxes.
fn name_pages(p: &mut Project, added: &[Node], page_map: &BTreeMap<String, String>) {
    for n in added.iter().filter(|n| n.is_device()) {
        let pasted = n
            .page
            .as_ref()
            .filter(|id| page_map.values().any(|v| v == *id));
        if let Some(pg) = pasted.and_then(|id| p.page_mut(id)) {
            pg.name = n.name.clone();
        }
    }
}

/// Copies of the pages reachable from `roots` through device boxes.
fn pages_below<'a>(p: &Project, roots: impl IntoIterator<Item = &'a str>) -> Vec<Page> {
    let mut ids = BTreeSet::new();
    for r in roots {
        subtree_pages(p, r, &mut ids);
    }
    p.pages
        .iter()
        .filter(|x| ids.contains(&x.id))
        .cloned()
        .collect()
}

/// Adds copies of `pages` under fresh page, block and flow ids; device boxes
/// on them point at the copies. Returns old → new page ids.
fn copy_pages(p: &mut Project, pages: &[Page]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for x in pages {
        let id = new_page_id(p);
        p.pages.push(Page {
            id: id.clone(),
            name: x.name.clone(),
            ..Default::default()
        });
        map.insert(x.id.clone(), id);
    }
    for x in pages {
        let (nodes, flows) = copy_blocks(p, &x.nodes, &x.flows, &map);
        let pg = p.page_mut(&map[&x.id]).expect("just added");
        (pg.nodes, pg.flows) = (nodes, flows);
    }
    map
}

/// Copies of `nodes` and of the `flows` between them under fresh ids; device
/// boxes point at the page that `pages` maps their design to, if any.
fn copy_blocks(
    p: &mut Project,
    nodes: &[Node],
    flows: &[Flow],
    pages: &BTreeMap<String, String>,
) -> (Vec<Node>, Vec<Flow>) {
    let mut ids = BTreeMap::new();
    let nodes = nodes
        .iter()
        .map(|n| {
            let mut c = n.clone();
            c.id = next_seq(p);
            ids.insert(n.id, c.id);
            if let Some(np) = c
                .page
                .as_ref()
                .and_then(|x| pages.get(x))
                .filter(|_| c.is_device())
            {
                c.page = Some(np.clone());
            }
            c
        })
        .collect();
    let flows = flows
        .iter()
        .filter_map(|f| {
            let (from, to) = (*ids.get(&f.from)?, *ids.get(&f.to)?);
            Some(Flow {
                id: next_flow(p),
                from,
                to,
                ..f.clone()
            })
        })
        .collect();
    (nodes, flows)
}

/// Deep copy of design page `page` and the device pages below it, named
/// `name` when given; returns the new top page id.
pub fn clone_design(p: &mut Project, page: &str, name: &str) -> String {
    let pages = pages_below(p, [page]);
    let top = copy_pages(p, &pages)
        .remove(page)
        .expect("page itself is in its subtree");
    if !name.is_empty() {
        p.page_mut(&top).expect("just added").name = name.to_owned();
    }
    top
}

#[cfg(test)]
#[path = "../../tests/unit/ops/clip.rs"]
mod tests;
