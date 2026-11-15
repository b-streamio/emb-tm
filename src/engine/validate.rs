// SPDX-License-Identifier: GPL-2.0-only
//! Structural checks, layout of unplaced nodes and normalizing of loaded projects.

use std::collections::BTreeSet;

use super::Model;
use crate::model::{CustomType, Node, Project, TypeDef};

impl Model<'_> {
    /// Structural checks of a (migrated) project: `(errors, warnings)`.
    pub fn validate(&self, p: &Project) -> (Vec<String>, Vec<String>) {
        let (mut errors, mut warnings) = (Vec::new(), Vec::new());
        let mut page_ids = BTreeSet::new();
        for (i, pg) in p.pages.iter().enumerate() {
            if pg.id.is_empty() {
                errors.push(format!("pages[{i}]: missing id"));
            } else if !page_ids.insert(pg.id.as_str()) {
                errors.push(format!("pages[{i}]: duplicate page id {}", pg.id));
            }
        }
        for c in &p.custom_types {
            check_questions(c, &mut errors);
        }
        if !errors.is_empty() {
            return (errors, warnings);
        }
        let multi = p.pages.len() > 1;
        let mut ids = BTreeSet::new();
        for pg in &p.pages {
            let prefix = if multi {
                format!("{}: ", pg.name)
            } else {
                String::new()
            };
            for (i, n) in pg.nodes.iter().enumerate() {
                let label = if n.name.is_empty() { &n.kind } else { &n.name };
                let at = format!("{prefix}nodes[{i}] ({label})");
                if !ids.insert(n.id) {
                    errors.push(format!("{at}: duplicate id {}", n.id));
                }
                self.check_node(n, &at, &page_ids, &mut errors, &mut warnings);
            }
            let here: BTreeSet<u64> = pg.nodes.iter().map(|n| n.id).collect();
            for (i, f) in pg.flows.iter().enumerate() {
                if !here.contains(&f.from) || !here.contains(&f.to) {
                    errors.push(format!(
                        "{prefix}flows[{i}]: from/to must reference nodes on the same page"
                    ));
                }
            }
        }
        check_loops(p, &p.root, &mut Vec::new(), &mut errors);
        (errors, warnings)
    }

    fn check_node(
        &self,
        n: &Node,
        at: &str,
        page_ids: &BTreeSet<&str>,
        errors: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) {
        let Some(def) = self.type_of(n) else {
            errors.push(format!(
                "{at}: unknown type \"{}\". Run \"emb-tm library\" for the list.",
                n.kind
            ));
            return;
        };
        if n.is_device() {
            if !n.page.as_deref().is_some_and(|id| page_ids.contains(id)) {
                errors.push(format!(
                    "{at}: device page \"{}\" does not exist",
                    n.page.as_deref().unwrap_or_default()
                ));
            }
            if n.qty == Some(0) {
                errors.push(format!("{at}: qty must be a positive integer"));
            }
            return;
        }
        check_answers(n, def, at, errors);
        for q in def
            .questions
            .iter()
            .filter(|q| !n.answers.contains_key(&q.id))
        {
            warnings.push(format!(
                "{at}: \"{}\" not answered, default ({}) used",
                q.id, q.default
            ));
        }
        for qid in n.evidence.keys() {
            if qid != "_component" && !def.questions.iter().any(|q| &q.id == qid) {
                warnings.push(format!("{at}: evidence for unknown question \"{qid}\""));
            }
        }
    }

    /// Places nodes without a position: one column per library group.
    pub fn layout(&self, p: &mut Project) {
        for pg in &mut p.pages {
            let mut cols: Vec<(String, f64, f64)> = self
                .lib
                .groups
                .iter()
                .enumerate()
                .map(|(i, g)| (g.clone(), 60.0 + i as f64 * 240.0, 60.0))
                .collect();
            for n in pg.nodes.iter_mut().filter(|n| n.x.is_nan() || n.y.is_nan()) {
                let g = self
                    .types
                    .get(&n.kind)
                    .map_or_else(|| self.lib.groups[0].clone(), |t| t.group.clone());
                let i = cols.iter().position(|c| c.0 == g).unwrap_or_else(|| {
                    cols.push((g, 60.0 + cols.len() as f64 * 240.0, 60.0));
                    cols.len() - 1
                });
                n.x = cols[i].1;
                n.y = cols[i].2;
                cols[i].2 += if n.is_device() { 160.0 } else { 130.0 };
            }
        }
    }

    /// Migrates v1 files and fills in what an externally written project may omit.
    pub fn normalize(&self, p: &mut Project) {
        p.migrate();
        let mut fid = 1;
        for (i, pg) in p.pages.iter_mut().enumerate() {
            if pg.id.is_empty() {
                pg.id = format!("p{}", i + 1);
            }
            if pg.name.is_empty() {
                pg.name = format!("Page {}", i + 1);
            }
            for n in &mut pg.nodes {
                if n.name.is_empty() {
                    n.name = self
                        .types
                        .get(&n.kind)
                        .map_or_else(|| n.kind.clone(), |t| t.name.clone());
                }
                if n.is_device() && n.qty.is_none() {
                    n.qty = Some(1);
                }
            }
            for f in &mut pg.flows {
                if f.label.is_empty() {
                    f.label = "data flow".into();
                }
                fid = fid.max(f.id + 1);
            }
        }
        for f in p
            .pages
            .iter_mut()
            .flat_map(|pg| &mut pg.flows)
            .filter(|f| f.id == 0)
        {
            f.id = fid;
            fid += 1;
        }
        p.seq = p
            .nodes()
            .map(|n| n.id + 1)
            .chain([p.seq, 1])
            .max()
            .unwrap_or(1);
        p.flow_seq = p
            .pages
            .iter()
            .flat_map(|pg| &pg.flows)
            .map(|f| f.id + 1)
            .chain([p.flow_seq, 1])
            .max()
            .unwrap_or(1);
        self.layout(p);
    }
}

/// Question ids, kinds and defaults of a custom block type.
fn check_questions(c: &CustomType, errors: &mut Vec<String>) {
    let mut ids = BTreeSet::new();
    for q in &c.questions {
        let at = format!("customTypes ({}): question \"{}\"", c.kind, q.id);
        if q.id.is_empty() || !ids.insert(q.id.as_str()) {
            errors.push(format!("{at}: missing or repeated id"));
        }
        match q.kind.as_str() {
            "bool" if !q.default.is_boolean() => {
                errors.push(format!("{at}: default must be true or false"));
            }
            "choice"
                if !q
                    .options
                    .iter()
                    .any(|o| q.default.as_str() == Some(&o.value)) =>
            {
                errors.push(format!("{at}: default must be one of its options"));
            }
            "bool" | "choice" => {}
            _ => errors.push(format!("{at}: kind must be bool or choice")),
        }
    }
}

/// Each answer names a question of the type and has one of its values.
fn check_answers(n: &Node, def: &TypeDef, at: &str, errors: &mut Vec<String>) {
    for (qid, v) in &n.answers {
        let Some(q) = def.questions.iter().find(|q| &q.id == qid) else {
            errors.push(format!(
                "{at}: unknown question \"{qid}\" for type {}",
                n.kind
            ));
            continue;
        };
        if q.kind == "bool" && !v.is_boolean() {
            errors.push(format!("{at}: \"{qid}\" must be true or false"));
        }
        if q.kind == "choice" && !q.options.iter().any(|o| v.as_str() == Some(&o.value)) {
            let values: Vec<_> = q.options.iter().map(|o| o.value.as_str()).collect();
            errors.push(format!(
                "{at}: \"{qid}\" must be one of {}",
                values.join(", ")
            ));
        }
    }
}

/// A device must not contain itself, directly or through nested devices.
fn check_loops(p: &Project, id: &str, stack: &mut Vec<String>, errors: &mut Vec<String>) {
    if stack.iter().any(|s| s == id) {
        let names: Vec<String> = stack
            .iter()
            .chain([&id.to_owned()])
            .map(|x| p.page(x).map_or(x.clone(), |pg| pg.name.clone()))
            .collect();
        errors.push(format!("device pages form a loop: {}", names.join(" > ")));
        return;
    }
    let Some(pg) = p.page(id) else { return };
    stack.push(id.to_owned());
    for n in pg.nodes.iter().filter(|n| n.is_device()) {
        check_loops(p, n.page.as_deref().unwrap_or_default(), stack, errors);
    }
    stack.pop();
}

#[cfg(test)]
#[path = "../../tests/unit/engine/validate.rs"]
mod tests;
