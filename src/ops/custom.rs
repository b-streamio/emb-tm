// SPDX-License-Identifier: GPL-2.0-only
//! Custom block types: saving them, importing them from other files, and a
//! whole project brought in as a device.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::clip::{paste, Clip};

use crate::{
    engine::{slug, Model},
    model::{CustomType, Library, Node, Project},
};

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
pub(super) fn rekey(n: &mut Node, remap: &BTreeMap<String, String>) {
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
#[path = "../../tests/unit/ops/custom.rs"]
mod tests;
