//! Editing operations on a project: adding blocks, moving them into devices,
//! copy and paste, splitting units, importing a project as a device and
//! custom block types. No browser API here; the UI calls these.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    engine::{slug, Model},
    model::{CustomType, Flow, Library, Node, Page, Project},
};

pub const BOARD_W: f64 = 1500.0;
pub const BOARD_H: f64 = 980.0;

/// Marker field of a clipboard payload.
pub const CLIP_KEY: &str = "emb3dWorkbenchClipboard";

pub fn plural(n: usize, w: &str) -> String {
    format!("{n} {w}{}", if n == 1 { "" } else { "s" })
}

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
    let pg = p.page_mut(&target).ok_or("no page")?;
    pg.nodes.extend(added);
    pg.flows.extend(flows);
    if into.is_some() {
        place_on_page(pg, &ids);
    }
    Ok(ids)
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

/// Threat and countermeasure ids used by custom block types.
pub fn custom_ids(p: &Project) -> BTreeSet<String> {
    p.custom_types
        .iter()
        .flat_map(|c| &c.threats)
        .flat_map(|t| std::iter::once(t.id.clone()).chain(t.cms.iter().map(|m| m.id.clone())))
        .collect()
}

/// `PREFIX-001`, the first not in `taken` (which receives it).
pub fn next_id(prefix: &str, taken: &mut BTreeSet<String>) -> String {
    let id = (1..)
        .map(|i| format!("{prefix}-{i:03}"))
        .find(|id| !taken.contains(id))
        .expect("unbounded");
    taken.insert(id.clone());
    id
}

/// Saves a custom block type: replaces `existing` or adds `def` under a new
/// unique type id. Missing threat and countermeasure ids are assigned.
pub fn save_custom(
    p: &mut Project,
    m: &Model,
    existing: Option<&str>,
    mut def: CustomType,
) -> String {
    let mut taken = custom_ids(p);
    for t in &mut def.threats {
        if t.id.is_empty() {
            t.id = next_id("CUS", &mut taken);
        }
        for c in t.cms.iter_mut().filter(|c| c.id.is_empty()) {
            c.id = next_id("CUM", &mut taken);
        }
    }
    if let Some(kind) = existing {
        def.kind = kind.to_owned();
        if let Some(c) = p.custom_types.iter_mut().find(|c| c.kind == kind) {
            *c = def;
        }
        return kind.to_owned();
    }
    let base = format!(
        "custom-{}",
        Some(slug(&def.name))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "block".into())
    );
    let kind = std::iter::once(base.clone())
        .chain((2..).map(|i| format!("{base}-{i}")))
        .find(|t| !m.types.contains_key(t))
        .expect("unbounded");
    def.kind = kind.clone();
    p.custom_types.push(def);
    kind
}

/// `"<what> has problems:"` and the first errors, one per line.
pub fn problems(what: &str, errors: &[String]) -> String {
    let first: Vec<&str> = errors.iter().take(8).map(String::as_str).collect();
    format!("{what} has problems:\n{}", first.join("\n"))
}

/// Adds the block types of `types` the project has no type for (what the
/// project has wins); custom threat and countermeasure ids that clash with
/// the project's are renumbered. Returns how many were added and the
/// renumbering.
pub fn add_types(
    p: &mut Project,
    m: &Model,
    types: Vec<CustomType>,
) -> (usize, BTreeMap<String, String>) {
    let mut taken = custom_ids(p);
    let mut remap = BTreeMap::new();
    let mut added = 0;
    for mut ct in types {
        if ct.kind.is_empty()
            || m.types.contains_key(&ct.kind)
            || p.custom_types.iter().any(|c| c.kind == ct.kind)
        {
            continue;
        }
        for t in &mut ct.threats {
            for id in std::iter::once(&mut t.id).chain(t.cms.iter_mut().map(|c| &mut c.id)) {
                if taken.contains(id.as_str()) {
                    let fresh = next_id(
                        if id.starts_with("CUM") { "CUM" } else { "CUS" },
                        &mut taken,
                    );
                    remap.insert(std::mem::replace(id, fresh.clone()), fresh);
                } else {
                    taken.insert(id.clone());
                }
            }
        }
        p.custom_types.push(ct);
        added += 1;
    }
    (added, remap)
}

/// Block types of a project, a Workbench TM-BOM or a component library
/// (`{"components": [...]}`, the format of `library/components.json`);
/// the Device box is built in, so `container` components are left out.
pub fn types_in(v: Value) -> Result<Vec<CustomType>, String> {
    let lib = v["components"].is_array().then(|| v.clone());
    match (Project::from_json(v), lib) {
        (Ok(p), _) => Ok(p.custom_types),
        (Err(_), Some(lib)) => {
            let lib: Library = serde_json::from_value(lib)
                .map_err(|e| format!("This component library has problems:\n{e}"))?;
            Ok(lib
                .components
                .into_iter()
                .filter(|d| !d.container)
                .map(|d| CustomType {
                    kind: d.kind,
                    name: d.name,
                    group: d.group,
                    tag: d.tag,
                    hint: d.hint,
                    base: d.base,
                    threats: Vec::new(),
                    questions: d.questions,
                    external: d.external,
                })
                .collect())
        }
        (Err(e), None) => Err(e),
    }
}

/// Points the decisions of block `n` at renumbered threat and countermeasure ids.
fn rekey(n: &mut Node, remap: &BTreeMap<String, String>) {
    if remap.is_empty() {
        return;
    }
    let key = |k: &String| match k.strip_prefix("accept:") {
        Some(t) if remap.contains_key(t) => format!("accept:{}", remap[t]),
        _ => remap.get(k).cloned().unwrap_or_else(|| k.clone()),
    };
    n.cm = n.cm.iter().map(|(k, v)| (key(k), v.clone())).collect();
    n.why = n.why.iter().map(|(k, v)| (key(k), v.clone())).collect();
    n.accepted = n
        .accepted
        .iter()
        .map(|(k, v)| (key(k), v.clone()))
        .collect();
}

/// "Import blocks…": adds the block types of file `v`, all or
/// none. Returns how many were added and how many the project already had.
pub fn import_types(p: &mut Project, m: &Model, v: Value) -> Result<(usize, usize), String> {
    let types = types_in(v)?;
    let total = types.len();
    let mut q = p.clone();
    let (added, _) = add_types(&mut q, m, types);
    let (errors, _) = Model::new(m.e, m.lib, &q).validate(&q);
    if !errors.is_empty() {
        return Err(problems("This file", &errors));
    }
    *p = q;
    Ok((added, total - added))
}

/// Brings project `other` in as a device box on page `page` at `(x, y)`.
pub fn import_as_device(
    p: &mut Project,
    m: &Model,
    mut other: Project,
    page: &str,
    x: f64,
    y: f64,
) -> Result<u64, String> {
    let om = Model::new(m.e, m.lib, &other);
    let (errors, _) = om.validate(&{
        let mut o = other.clone();
        o.migrate();
        o
    });
    if !errors.is_empty() {
        return Err(problems("This project", &errors));
    }
    om.normalize(&mut other);
    let name = other.name.clone();
    let mut dev = Node::new(0, "device", &name, x.round(), y.round());
    dev.page = Some(other.root.clone());
    dev.qty = Some(1);
    let clip = Clip {
        nodes: vec![dev],
        pages: other.pages,
        custom_types: other.custom_types,
        ..Default::default()
    };
    let ids = paste(p, m, &clip, page, None, 0.0, "")?;
    let dev = p.node(ids[0]).expect("pasted").clone();
    if let Some(pg) = dev.page.as_deref().and_then(|id| p.page_mut(id)) {
        pg.name = name;
    }
    Ok(dev.id)
}

#[cfg(test)]
#[path = "../tests/unit/ops.rs"]
mod tests;
