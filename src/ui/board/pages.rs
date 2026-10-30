// SPDX-License-Identifier: GPL-2.0-only
//! Pages: the page list of the rail and the breadcrumbs above the board.

use leptos::prelude::*;

use crate::{
    model::Project,
    ui::{ctx, web},
};

#[component]
pub(super) fn Pages() -> impl IntoView {
    let ctx = ctx();
    let list = move || {
        ctx.soft.track();
        let cur = ctx.page();
        let c = ctx.counts.get();
        ctx.project.with(|p| {
            let order = p.page_order();
            let mut depth = std::collections::BTreeMap::from([(p.root.clone(), 0_usize)]);
            for pg in &order {
                let d = depth.get(&pg.id).copied().unwrap_or(0);
                for n in pg.nodes.iter().filter(|n| n.is_device()) {
                    depth.entry(n.page.clone().unwrap_or_default()).or_insert(d + 1);
                }
            }
            let multi = p.pages.len() > 1;
            order.iter().map(|pg| {
                let r = c.page(&pg.id);
                let unused = pg.id != p.root && p.parents_of(&pg.id).is_empty();
                let name = if pg.id == p.root && multi { "System".to_owned() } else { pg.name.clone() };
                let (id, id2) = (pg.id.clone(), pg.id.clone());
                let pad = format!("{}px", 8 + depth.get(&pg.id).copied().unwrap_or(0) * 14);
                let del = unused.then(|| {
                    let armed = RwSignal::new(false);
                    let label = format!("Delete page {}", pg.name);
                    view! {
                        <button class="iconbtn" class:armed=move || armed.get() title=label.clone() aria-label=label on:click=move |_| {
                            if !armed.get_untracked() {
                                armed.set(true);
                                set_timeout(move || armed.try_set(false).map_or((), |_| ()), std::time::Duration::from_secs(3));
                                return;
                            }
                            let id = id2.clone();
                            ctx.edit(|p, _| p.pages.retain(|x| x.id != id));
                        }>{move || if armed.get() { "Delete?" } else { "×" }}</button>
                    }
                });
                view! {
                    <li>
                        <button class="pagebtn" class:cur=pg.id == cur style:padding-left=pad on:click=move |_| ctx.open_page(&id)>
                            <span class="pn">{name}</span>{unused.then(|| view! { <span class="unused">"unused"</span> })}<span class="pc">{r.open}</span>
                        </button>
                        {del}
                    </li>
                }
            }).collect_view()
        })
    };
    view! {
        <div class="pagesbox">
            <p class="eyebrow">"Pages"</p>
            <ul class="pagelist">{list}</ul>
            <button class="btn small wide" on:click=move |_| web::click("devFile")>"Add device from file…"</button>
        </div>
    }
}

/// Root … current page, following the first device box that uses each page.
pub fn page_path(p: &Project, id: &str) -> Vec<(String, String)> {
    let mut path = Vec::new();
    let mut cur = p.page(id);
    for _ in 0..30 {
        let Some(pg) = cur else { break };
        path.insert(
            0,
            (
                pg.id.clone(),
                if pg.id == p.root {
                    "System".into()
                } else {
                    pg.name.clone()
                },
            ),
        );
        if pg.id == p.root {
            break;
        }
        cur = p.parents_of(&pg.id).first().and_then(|d| p.page_of(d.id));
    }
    if path.first().is_some_and(|(i, _)| *i != p.root) && p.page(&p.root).is_some() {
        path.insert(0, (p.root.clone(), "System".into()));
    }
    path
}

#[component]
pub(super) fn Crumbs() -> impl IntoView {
    let ctx = ctx();
    move || {
        ctx.soft.track();
        let cur = ctx.page();
        ctx.project.with(|p| {
            (p.pages.len() > 1).then(|| {
                let path = page_path(p, &cur);
                let last = path.len() - 1;
                let items = path.into_iter().enumerate().map(|(i, (id, name))| {
                    if i < last {
                        view! { <button class="crumb" on:click=move |_| ctx.open_page(&id)>{name}</button><span class="sep">"›"</span> }.into_any()
                    } else {
                        view! { <span class="crumb here">{name}</span> }.into_any()
                    }
                }).collect_view();
                view! { <nav class="crumbs" aria-label="Page path">{items}</nav> }
            })
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/ui/board/pages.rs"]
mod tests;
