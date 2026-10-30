// SPDX-License-Identifier: GPL-2.0-only
//! Right-hand panel: page summary, or the selected block, device box or data flow.

mod block;
mod device;
mod threats;

use std::time::Duration;

use leptos::prelude::*;

use super::{board, ctx, web, Ctx, Sel};
use crate::{
    engine::Model,
    model::{Node, Project},
    ops,
};
use block::block;
use device::device;
pub use threats::{cm_select, why_box};

#[component]
pub fn Inspector() -> impl IntoView {
    let ctx = ctx();
    move || {
        let (sel, page) = (ctx.sel.get(), ctx.page());
        ctx.with(|p, m| match sel {
            Some(Sel::Node(id)) if p.node(id).is_some() => {
                let n = p.node(id).expect("checked");
                if n.is_device() {
                    device(ctx, p, n).into_any()
                } else {
                    block(ctx, p, m, n).into_any()
                }
            }
            Some(Sel::Flow(id))
                if p.page(&page)
                    .is_some_and(|pg| pg.flows.iter().any(|f| f.id == id)) =>
            {
                flow(ctx, p, &page, id).into_any()
            }
            _ => summary(ctx, p, m, &page).into_any(),
        })
    }
}

fn summary(ctx: Ctx, p: &Project, m: &Model, page: &str) -> impl IntoView {
    let pg = p.page(page).expect("current page exists");
    let root = pg.id == p.root;
    let multi = p.pages.len() > 1;
    let r = ctx.counts.with(|c| c.page(page));
    let cms = m.cm_rows(p);
    let total = m.all_rows(p).len();
    let reviews = m.review_items(p).len();
    let page_id = pg.id.clone();
    let name_field = (!root).then(|| {
        let users = p.parents_of(page);
        let used = if users.is_empty() {
            "Not used by any device box.".to_owned()
        } else {
            format!(
                "Used by {}",
                users
                    .iter()
                    .map(|u| u.name.clone() + &u.units())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        view! {
            <div class="field" style="margin-top:12px"><label for="pgname">"Page name"</label>
                <input type="text" id="pgname" value=pg.name.clone() on:input=move |e| {
                    let v = event_target_value(&e);
                    let id = page_id.clone();
                    ctx.typing(|p| if let Some(pg) = p.page_mut(&id) { pg.name = v });
                } /></div>
            <p class="small muted">{used}</p>
        }
    });
    let eyebrow = if root {
        if multi {
            "System"
        } else {
            "Device"
        }
    } else {
        "Device page"
    };
    view! {
        <div class="empty">
            <p class="eyebrow">{eyebrow}</p>
            <h2>{if root { p.name.clone() } else { pg.name.clone() }}</h2>
            {name_field}
            <div class="stats">
                <div class="stat"><b>{pg.nodes.len()}</b><span>"blocks on this page"</span></div>
                <div class="stat"><b>{pg.flows.len()}</b><span>"data flows on this page"</span></div>
                <div class="stat open"><b>{r.open}</b><span>{format!("open threats{}", if root { "" } else { " in this device" })}</span></div>
                <div class="stat done"><b>{cms.iter().filter(|c| c.status == "implemented").count()}</b><span>{format!("countermeasures implemented of {} (whole model)", cms.len())}</span></div>
            </div>
            {(reviews > 0).then(|| view! { <p class="small"><span class="pill st-Open">{format!("{reviews} answers need review")}</span>" These were not determined from the source and use a default. Blocks with them are marked on the board."</p> })}
            {p.generator().map(|g| view! { <p class="small muted">{format!("Generated from {g}.")}</p> })}
            <p class="small">"Select a block to answer its questions and work through its threats. A " <b>"Device"</b> " box stands for a whole device: double-click it to design its inside on its own page. Use " <b>"Draw data flow"</b> " to connect blocks on the same page."</p>
            <p class="small">{format!("{total} threats in the whole model, from MITRE EMB3D STIX {} and your custom blocks. EMB3D rates evidence, not severity, so threats are ordered by how much real-world evidence exists for them.", m.e.version)}</p>
        </div>
    }
}

/// "Delete" that needs a second click within three seconds.
#[component]
pub fn ArmedDelete(#[prop(into)] on_confirm: Callback<()>) -> impl IntoView {
    let armed = RwSignal::new(false);
    view! {
        <button class="btn small danger" on:click=move |_| {
            if armed.get_untracked() {
                on_confirm.run(());
                return;
            }
            armed.set(true);
            set_timeout(move || { let _ = armed.try_set(false); }, Duration::from_secs(3));
        }>{move || if armed.get() { "Click again to delete" } else { "Delete" }}</button>
    }
}

fn remove(ctx: Ctx, id: u64) {
    let page = ctx.page();
    ctx.edit(|p, _| ops::remove_node(p, &page, id));
    ctx.select(None);
}

/// The keyboard shortcut of a button (`keyboard` in `ui/keys.rs`): `⌘V` on
/// Apple systems, `Ctrl+V` elsewhere.
fn key(letter: char) -> impl IntoView {
    let label = if web::apple() {
        format!("⌘{letter}")
    } else {
        format!("Ctrl+{letter}")
    };
    view! { <kbd>{label}</kbd> }
}

/// Duplicate / copy / cut / paste and "move into device".
fn move_controls(ctx: Ctx, p: &Project, n: &Node, page: &str) -> impl IntoView {
    let devs: Vec<(u64, String)> = p.page(page).map_or_else(Vec::new, |pg| {
        pg.nodes
            .iter()
            .filter(|d| d.is_device() && d.id != n.id)
            .map(|d| (d.id, d.name.clone()))
            .collect()
    });
    let id = n.id;
    let paste_label = if n.is_device() {
        "Paste inside"
    } else {
        "Paste"
    };
    let extra = ctx.multi.get_untracked().len();
    view! {
        <div class="row movebar">
            <button class="btn small" on:click=move |_| ctx.duplicate()>"Duplicate"{key('D')}</button>
            <button class="btn small" on:click=move |_| { ctx.copy(false); }>"Copy"{key('C')}</button>
            <button class="btn small" on:click=move |_| { ctx.copy(true); }>"Cut"{key('X')}</button>
            {move || ctx.clip.get().map(|c| view! { <button class="btn small" on:click=move |_| ctx.paste(&c, false, "", None)>{paste_label}{key('V')}</button> })}
            {(!devs.is_empty()).then(|| view! {
                <select class="status" aria-label="Move into a device" on:change=move |e| {
                    let Ok(dev) = event_target_value(&e).parse::<u64>() else { return };
                    let mut ids = ctx.selected_ids();
                    if ids.is_empty() { ids = vec![id]; }
                    board::move_into(ctx, &ids, dev);
                }>
                    <option value="">"Move into device…"</option>
                    {devs.into_iter().map(|(d, name)| view! { <option value=d.to_string()>{name}</option> }).collect_view()}
                </select>
            })}
            {(extra > 0).then(|| view! { <span class="small muted">{format!("{} blocks selected", extra + 1)}</span> })}
        </div>
    }
}

fn flow(ctx: Ctx, p: &Project, page: &str, id: u64) -> impl IntoView {
    let f = p
        .page(page)
        .and_then(|pg| pg.flows.iter().find(|f| f.id == id))
        .cloned()
        .expect("checked");
    let name = |n: u64| p.node(n).map(|x| x.name.clone()).unwrap_or_default();
    let (page1, page2) = (page.to_owned(), page.to_owned());
    let set = move |f: Box<dyn FnOnce(&mut crate::model::Flow)>| {
        let page = page1.clone();
        ctx.edit(move |p, _| {
            if let Some(fl) = p
                .page_mut(&page)
                .and_then(|pg| pg.flows.iter_mut().find(|x| x.id == id))
            {
                f(fl)
            }
        });
    };
    let (s1, s2, s3) = (set.clone(), set.clone(), set);
    view! {
        <p class="eyebrow">"Data flow"</p>
        <h2>{format!("{} → {}", name(f.from), name(f.to))}</h2>
        <div class="field" style="margin-top:14px"><label for="flow-label">"Label"</label>
            <input type="text" id="flow-label" value=f.label.clone() on:input=move |e| {
                let v = event_target_value(&e);
                let page = page2.clone();
                ctx.typing(|p| if let Some(fl) = p.page_mut(&page).and_then(|pg| pg.flows.iter_mut().find(|x| x.id == id)) { fl.label = v });
            } /></div>
        <div class="q"><label class="check"><input type="checkbox" prop:checked=f.encrypted on:change=move |e| { let c = event_target_checked(&e); s1(Box::new(move |f| f.encrypted = c)) } /><span>"Encrypted in transit"</span></label></div>
        <div class="q"><label class="check"><input type="checkbox" prop:checked=f.sensitive on:change=move |e| { let c = event_target_checked(&e); s2(Box::new(move |f| f.sensitive = c)) } /><span>"Carries sensitive data"</span></label></div>
        <p class="small muted">"Dashed lines are unencrypted. EMB3D threats come from component properties, so flows document the design and go into the TM-BOM export."</p>
        <div class="row">
            <button class="btn small" on:click=move |_| s3(Box::new(|f| std::mem::swap(&mut f.from, &mut f.to)))>"Reverse direction"</button>
            <ArmedDelete on_confirm=move |_| {
                let page = ctx.page();
                ctx.edit(|p, _| if let Some(pg) = p.page_mut(&page) { pg.flows.retain(|x| x.id != id) });
                ctx.select(None);
            } />
        </div>
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/ui/inspector/mod.rs"]
mod tests;
