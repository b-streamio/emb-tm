// SPDX-License-Identifier: GPL-2.0-only
//! One block on the board: tag, name, threat counts; dragged with the pointer.

use std::collections::BTreeSet;

use leptos::prelude::*;

use super::{actions::click_node, Drag};
use crate::{
    engine::{group_class, Counts, Model},
    model::{Node, Project},
    ui::{Ctx, Sel},
};

/// How the board marks blocks: selection, connecting, drop target.
pub(super) struct Marks<'a> {
    pub(super) sel: Option<Sel>,
    pub(super) multi: &'a BTreeSet<u64>,
    pub(super) connecting: bool,
    pub(super) target: Option<u64>,
}

pub(super) fn block(
    ctx: Ctx,
    p: &Project,
    m: &Model,
    c: &Counts,
    id: u64,
    marks: &Marks,
    drag: RwSignal<Option<Drag>>,
) -> impl IntoView {
    let n = p.node(id).expect("on page");
    let (group, tag, external, custom) =
        m.type_of(n).map_or(("External", "?", false, false), |d| {
            (d.group.as_str(), d.tag.as_str(), d.external, d.custom)
        });
    let mut class = String::from("node");
    for (on, c) in [
        (external, " ext"),
        (n.is_device(), " device"),
        (custom, " custom"),
        (marks.sel == Some(Sel::Node(id)), " sel"),
        (marks.multi.contains(&id), " sel multi"),
        (marks.connecting, " target"),
        (marks.target == Some(id), " droptarget"),
    ] {
        if on {
            class += c;
        }
    }
    let meta = meta(ctx, n, c, external);
    let units = n.units();
    let qty = (!units.is_empty()).then(|| view! { <span class="qty">{units}</span> });
    let (x, y, size) = (n.x, n.y, n.size());
    let at = move || {
        drag.with(|d| d.as_ref().and_then(|d| d.place(id, size)))
            .unwrap_or((x, y))
    };
    view! {
        <div class=class tabindex="0" style:left=move || format!("{}px", at().0) style:top=move || format!("{}px", at().1)
            on:pointerdown=move |e| {
                if e.button() != 0 { return; }
                let mut ids = ctx.selected_ids();
                if !ids.contains(&id) { ids = vec![id]; }
                let start = ctx.project.with_untracked(|p| ids.iter().filter_map(|i| p.node(*i)).map(|n| (n.id, n.x, n.y)).collect());
                let modifier = e.ctrl_key() || e.meta_key();
                drag.set(Some(Drag { node: id, start, px: f64::from(e.client_x()), py: f64::from(e.client_y()), dx: 0.0, dy: 0.0, moved: false, target: None, modifier }));
            }
            on:keydown=move |e| if e.key() == "Enter" || e.key() == " " { e.prevent_default(); click_node(ctx, id, false); }>
            <div class="top"><span class=format!("tag {}", group_class(group))>{tag.to_owned()}</span><span class="mono muted">{format!("#{id}")}</span></div>
            <div class="nm">{live(ctx, move |p| p.node(id).map(|n| n.name.clone()))}{qty}</div>
            {meta}
        </div>
    }
}

/// Threat counts of a block; for a device, of its page.
fn meta(ctx: Ctx, n: &Node, c: &Counts, external: bool) -> AnyView {
    let counts = |open: usize, total: usize, review: usize| {
        let review = (review > 0).then(|| view! { <span class="rvcount" title=format!("{review} answers need review")>{format!("{review}?")}</span> });
        view! { <div class="meta"><span class="dot open">{format!("{open} open")}</span><span class="dot done">{format!("{} handled", total - open)}</span>{review}</div> }
    };
    if n.is_device() {
        let page = n.page.clone().unwrap_or_default();
        let r = c.page(&page);
        let name = live(ctx, move |p| p.page(&page).map(|pg| pg.name.clone()));
        view! { {counts(r.open, r.threats, r.review)}<div class="devhint">{name}" · double-click to open"</div> }.into_any()
    } else if !external {
        let r = c.node(n.id);
        counts(r.open, r.threats, r.review).into_any()
    } else {
        view! { <div class="meta">"external"</div> }.into_any()
    }
}

/// Text that follows the project while the user types.
fn live(
    ctx: Ctx,
    get: impl Fn(&Project) -> Option<String> + Send + Sync + 'static,
) -> impl Fn() -> String {
    move || {
        ctx.soft.track();
        ctx.project.with(|p| get(p).unwrap_or_default())
    }
}
