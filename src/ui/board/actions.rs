// SPDX-License-Identifier: GPL-2.0-only
//! Editing actions of the diagram: selecting and connecting blocks, adding
//! and moving them, and importing devices and block types.

use std::collections::BTreeSet;

use leptos::prelude::*;

use crate::{
    model::{Flow, Project, NODE_W},
    ops,
    ui::{parse, Ctx, Sel},
};

/// Selects, extends the selection, or ends a data flow at block `id`.
pub(super) fn click_node(ctx: Ctx, id: u64, modifier: bool) {
    let sel = ctx.sel.get_untracked();
    if ctx.connect.get_untracked().is_none() && modifier && matches!(sel, Some(Sel::Node(_))) {
        if sel != Some(Sel::Node(id)) {
            ctx.multi.update(|m| {
                if !m.remove(&id) {
                    m.insert(id);
                }
            });
        }
        return;
    }
    ctx.multi.update(BTreeSet::clear);
    if let Some(from) = ctx.connect.get_untracked() {
        ctx.connect.set(None);
        if from != id {
            let page = ctx.page();
            let fid = ctx.edit(|p, _| {
                let fid = p.flow_seq;
                p.flow_seq += 1;
                let f = Flow {
                    id: fid,
                    from,
                    to: id,
                    label: "data flow".into(),
                    encrypted: false,
                    sensitive: false,
                };
                if let Some(pg) = p.page_mut(&page) {
                    pg.flows.push(f);
                }
                fid
            });
            ctx.sel.set(Some(Sel::Flow(fid)));
        }
        return;
    }
    if sel != Some(Sel::Node(id)) {
        ctx.open_threat.set(None);
    }
    ctx.sel.set(Some(Sel::Node(id)));
}

/// New block of `kind` at `(x, y)` on the current page, selected.
pub(super) fn add_at(ctx: Ctx, kind: &str, x: f64, y: f64) {
    let page = ctx.page();
    if let Some(id) = ctx.edit(|p, m| ops::add_node(p, m, kind, &page, x, y)) {
        ctx.select(Some(Sel::Node(id)));
        ctx.open_threat.set(None);
    }
}

/// New block of `kind` in the middle of the visible board.
pub(super) fn add_visible(ctx: Ctx, kind: &str) {
    let page = ctx.page();
    let k = ctx
        .project
        .with_untracked(|p| p.page(&page).map_or(0, |pg| pg.nodes.len() % 6)) as f64;
    let (x, y) = ctx.wrap.get_untracked().map_or((60.0, 60.0), |w| {
        let (sl, st, cw, ch) = (
            f64::from(w.scroll_left()),
            f64::from(w.scroll_top()),
            f64::from(w.client_width()),
            f64::from(w.client_height()),
        );
        (
            sl + (cw / 2.0 - NODE_W / 2.0).max(20.0) + k * 18.0,
            st + (ch / 2.0 - 40.0).max(20.0) + k * 18.0,
        )
    });
    add_at(ctx, kind, x, y);
}

/// New block of `kind` inside device `dev`.
pub(super) fn add_into(ctx: Ctx, kind: &str, dev: u64) {
    let Some((page, dev_name)) = ctx.project.with_untracked(|p| {
        p.node(dev)
            .and_then(|d| Some((d.page.clone()?, d.name.clone())))
    }) else {
        return;
    };
    let added = ctx.edit(|p, m| {
        let id = ops::add_node(p, m, kind, &page, 0.0, 0.0)?;
        ops::place_on_page(p.page_mut(&page)?, &[id]);
        Some(m.types.get(kind)?.name.clone())
    });
    if let Some(name) = added {
        ctx.select(Some(Sel::Node(dev)));
        ctx.open_threat.set(None);
        ctx.toast(format!("Added {name} to {dev_name}."));
    }
}

/// Moves blocks into device `dev` and says what happened.
pub fn move_into(ctx: Ctx, ids: &[u64], dev: u64) {
    let page = ctx.page();
    let name = ctx
        .project
        .with_untracked(|p| p.node(dev).map(|d| d.name.clone()).unwrap_or_default());
    match ctx.edit(|p, _| ops::move_into_device(p, &page, ids, dev)) {
        Ok((moved, cut)) => {
            ctx.select(Some(Sel::Node(dev)));
            ctx.open_threat.set(None);
            let cut = match cut {
                0 => String::new(),
                1 => format!(
                    " {} to blocks outside it was removed.",
                    ops::plural(1, "data flow")
                ),
                n => format!(
                    " {} to blocks outside it were removed.",
                    ops::plural(n, "data flow")
                ),
            };
            ctx.toast(format!(
                "Moved {} into {name}.{cut}",
                ops::plural(moved, "block")
            ));
        }
        Err(e) if !e.is_empty() => ctx.toast(e),
        Err(_) => {}
    }
}

/// "Add device from file…": another project or TM-BOM as a device box.
pub fn add_device_from(ctx: Ctx, text: &str) {
    let parsed = parse(text).and_then(Project::from_json);
    let other = match parsed {
        Ok(o) => o,
        Err(e) => return ctx.error("Could not add the device", e),
    };
    let page = ctx.page();
    let k = ctx
        .project
        .with_untracked(|p| p.page(&page).map_or(0, |pg| pg.nodes.len() % 5)) as f64;
    let (sl, st) = ctx.wrap.get_untracked().map_or((0.0, 0.0), |w| {
        (f64::from(w.scroll_left()), f64::from(w.scroll_top()))
    });
    match ctx.edit(|p, m| {
        ops::import_as_device(
            p,
            m,
            other,
            &page,
            sl + 60.0 + k * 30.0,
            st + 60.0 + k * 30.0,
        )
    }) {
        Ok(id) => ctx.select(Some(Sel::Node(id))),
        Err(e) => ctx.error("Could not add the device", e),
    }
}

/// "Import blocks…": the block types of a project, TM-BOM or component
/// library file.
pub fn import_types(ctx: Ctx, text: &str) {
    match parse(text).and_then(|v| ctx.edit(|p, m| ops::import_types(p, m, v))) {
        Ok((0, 0)) => ctx.toast("This file has no block types."),
        Ok((added, had)) => {
            let skipped = if had > 0 {
                format!(
                    " Skipped {} the project already has.",
                    ops::plural(had, "type")
                )
            } else {
                String::new()
            };
            ctx.toast(format!(
                "Imported {}.{skipped}",
                ops::plural(added, "block type")
            ));
        }
        Err(e) => ctx.error("Could not import the blocks", e),
    }
}
