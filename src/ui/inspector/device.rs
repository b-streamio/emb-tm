// SPDX-License-Identifier: GPL-2.0-only
//! The inspector of a device box: name, quantity, design page and variants.

use leptos::prelude::*;

use super::{move_controls, remove, ArmedDelete};
use crate::{
    model::{Node, Page, Project},
    ops,
    ui::{board, Ctx, Sel},
};

pub(super) fn device(ctx: Ctx, p: &Project, n: &Node) -> impl IntoView {
    let page = ctx.page();
    let id = n.id;
    let design = n.page.clone().unwrap_or_default();
    let r = ctx.counts.with(|c| c.page(&design));
    let inside = p.page(&design).map_or(0, |x| x.nodes.len());
    view! {
        <p class="eyebrow"><span class="k-System">"System"</span>" · Device"</p>
        {fields(ctx, p, n, &page)}
        <p class="small muted">"Boxes that share a design page share its threats and decisions: model a camera once and use it for every camera."</p>
        {variant(ctx, p, n, &page)}
        <div class="row">
            <button class="btn small primary" on:click=move |_| ctx.open_page(&design)>"Open design"</button>
            <button class="btn small" on:click=move |_| ctx.connect.set(Some(id))>"Draw data flow"</button>
            <ArmedDelete on_confirm=move |_| remove(ctx, id) />
        </div>
        {move_controls(ctx, p, n, &page)}
        <div class="stats" style="margin-top:14px">
            <div class="stat"><b>{inside}</b><span>"blocks inside"</span></div>
            <div class="stat open"><b>{r.open}</b><span>{format!("open threats of {}", r.threats)}</span></div>
        </div>
        {(r.review > 0).then(|| view! { <p class="small"><span class="pill st-Open">{format!("{} answers need review", r.review)}</span>" inside this device."</p> })}
    }
}

/// Name, quantity and design page of device box `n`.
fn fields(ctx: Ctx, p: &Project, n: &Node, page: &str) -> impl IntoView {
    let (id, design) = (n.id, n.page.clone().unwrap_or_default());
    // A device may not use a page that contains it.
    let ancestors: Vec<String> = board::page_path(p, page).into_iter().map(|x| x.0).collect();
    let choices: Vec<(String, String)> = p
        .pages
        .iter()
        .filter(|x| !ancestors.contains(&x.id))
        .map(|x| (x.id.clone(), x.name.clone()))
        .collect();
    view! {
        <div class="field"><label for="dev-name">"Name"</label>
            <input type="text" id="dev-name" value=n.name.clone() on:input=move |e| {
                let v = event_target_value(&e);
                ctx.typing(|p| {
                    let Some(n) = p.node(id).cloned() else { return };
                    let only = p.parents_of(n.page.as_deref().unwrap_or_default()).len() == 1;
                    if let Some(pg) = p.page_mut(n.page.as_deref().unwrap_or_default()).filter(|pg| only && pg.name == n.name) {
                        pg.name = v.clone(); // keep the page name in step while it matches
                    }
                    if let Some(n) = p.node_mut(id) { n.name = v; }
                });
            } /></div>
        <div class="field"><label for="dev-qty">"Quantity of identical units"</label>
            <input type="number" min="1" step="1" id="dev-qty" class="qtyin" value=n.qty().to_string() on:change=move |e| {
                let q = event_target_value(&e).parse::<u32>().unwrap_or(1).max(1);
                ctx.edit(|p, _| if let Some(n) = p.node_mut(id) { n.qty = Some(q) });
            } /></div>
        <div class="field"><label for="dev-page">"Design page"</label>
            <select id="dev-page" class="status" on:change=move |e| {
                let v = event_target_value(&e);
                ctx.edit(|p, _| {
                    let page = if v == "__new" {
                        let fresh = ops::new_page_id(p);
                        let name = p.node(id).map(|n| n.name.clone()).unwrap_or_default();
                        p.pages.push(Page { id: fresh.clone(), name, ..Default::default() });
                        fresh
                    } else { v };
                    if let Some(n) = p.node_mut(id) { n.page = Some(page); }
                });
            }>
                {choices.into_iter().map(|(pid, name)| view! { <option value=pid.clone() selected=pid == design>{name}</option> }).collect_view()}
                <option value="__new">"New empty page"</option>
            </select></div>
    }
}

/// When several units or boxes share the design: how to make one separate.
fn variant(ctx: Ctx, p: &Project, n: &Node, page: &str) -> Option<impl IntoView> {
    let id = n.id;
    let sharers: Vec<String> = p
        .parents_of(n.page.as_deref().unwrap_or_default())
        .iter()
        .filter(|d| d.id != id)
        .map(|d| d.name.clone())
        .collect();
    if n.qty() <= 1 && sharers.is_empty() {
        return None;
    }
    let mut text = String::new();
    if n.qty() > 1 {
        text += &format!("All {} units use one design. ", n.qty());
    }
    if !sharers.is_empty() {
        text += &format!("This design is also used by {}. ", sharers.join(", "));
    }
    text += "To change one of them, make it separate first.";
    let page = page.to_owned();
    let split = (n.qty() > 1).then(|| view! { <button class="btn small" on:click=move |_| {
        let page = page.clone();
        if let Some(one) = ctx.edit(|p, _| ops::split_unit(p, &page, id)) {
            let msg = ctx.project.with_untracked(|p| match (p.node(id), p.node(one)) {
                (Some(a), Some(b)) => format!("Split one unit out: {} ×{} and {} ×1, which has its own design to change.", a.name, a.qty(), b.name),
                _ => String::new(),
            });
            ctx.select(Some(Sel::Node(one)));
            ctx.toast(msg);
        }
    }>"Split one unit out to modify"</button> });
    let detach = (!sharers.is_empty()).then(|| view! { <button class="btn small" on:click=move |_| {
        let name = ctx.edit(|p, _| {
            let n = p.node(id)?.clone();
            let page = ops::clone_design(p, n.page.as_deref()?, &n.name);
            p.node_mut(id)?.page = Some(page);
            Some(n.name)
        });
        if let Some(name) = name {
            ctx.toast(format!("{name} now has its own copy of the design. Changes to it no longer affect the other boxes."));
        }
    }>"Use a separate copy of the design"</button> });
    Some(
        view! { <div class="variant"><p class="small">{text}</p><div class="row">{split}{detach}</div></div> },
    )
}
