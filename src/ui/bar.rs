// SPDX-License-Identifier: GPL-2.0-only
//! The header: EMB3D version, project name, tabs and file actions.

use leptos::{ev, prelude::*};

use super::{board, ctx, dialogs, file_name, pretty, version_key, web, Ctx, View};
use crate::engine::Counts;

#[component]
pub(super) fn Bar() -> impl IntoView {
    let ctx = ctx();
    let open_count = move || ctx.counts.with(Counts::open);
    let tab = move |v: View, label: &'static str| {
        let count = (v == View::Threats).then(
            || view! { <span class="count">{move || Some(open_count()).filter(|n| *n > 0)}</span> },
        );
        view! { <button role="tab" aria-selected=move || (ctx.view.get() == v).to_string() on:click=move |_| ctx.view.set(v)>{label}{count}</button> }
    };
    // The hidden file inputs: Open…, Add device from file…, Import blocks….
    let on_file = move |ev: ev::Event, open: fn(Ctx, &str)| {
        leptos::task::spawn_local(async move {
            if let Some(text) = web::read_file(&ev).await {
                open(ctx, &text);
            }
        });
    };
    let open = |ctx: Ctx, text: &str| {
        if let Err(e) = ctx.import(text) {
            ctx.error("Could not open the file", e);
        }
    };
    view! {
        <header class="bar">
            <div class="brand">"emb-tm"</div>
            <div class="ver">
                <select aria-label="EMB3D version" prop:value=move || ctx.emb3d.get().version.clone()
                    on:change=move |e| dialogs::propose_version(ctx, event_target_value(&e))>{move || versions(ctx)}</select>
                <button class="btn small" title="Check emb3d.mitre.org for a newer EMB3D release" on:click=move |_| dialogs::check_updates(ctx)>"Updates"</button>
            </div>
            <input id="projName" type="text" aria-label="Project name" spellcheck="false"
                prop:value=move || { ctx.epoch.track(); ctx.project.with_untracked(|p| p.name.clone()) }
                on:input=move |e| { let v = event_target_value(&e); ctx.typing(|p| p.name = v) } />
            <nav class="tabs" role="tablist">
                {tab(View::Diagram, "Diagram")}{tab(View::Threats, "Threats")}{tab(View::Cms, "Countermeasures")}{tab(View::Report, "Report")}
            </nav>
            <div class="actions">
                <label class="btn" for="fileIn">"Open…"</label>
                <input id="fileIn" type="file" accept=".json,application/json" hidden on:change=move |e| on_file(e, open) />
                <input id="devFile" type="file" accept=".json,application/json" hidden aria-label="Add a device from a project or TM-BOM file" on:change=move |e| on_file(e, board::add_device_from) />
                <input id="typesFile" type="file" accept=".json,application/json" hidden aria-label="Import block types from a project, TM-BOM or component library file" on:change=move |e| on_file(e, board::import_types) />
                <button class="btn" title="Download the project file (your work is also kept in this browser)" on:click=move |_| ctx.save_file()>"Save"</button>
                <button class="btn primary" title="Download an OWASP TM-BOM (Threat Model Library v1.0.2) for Threat Dragon; it opens here again too" on:click=move |_| export_tmbom(ctx)>"Export TM-BOM"</button>
                <button class="btn" on:click=move |_| dialogs::templates(ctx)>"New"</button>
            </div>
        </header>
    }
}

/// The EMB3D releases this copy can use, newest first.
fn versions(ctx: Ctx) -> impl IntoView {
    let mut list = ctx.index.get().versions;
    list.sort_by_key(|r| std::cmp::Reverse(version_key(&r.version)));
    let default = ctx.index.with(|i| i.default.clone());
    list.into_iter()
        .map(|r| {
            let label = format!(
                "EMB3D {}{}{}",
                r.version,
                if r.version == default {
                    " (default)"
                } else {
                    ""
                },
                if r.session.is_some() {
                    " (this session)"
                } else {
                    ""
                }
            );
            view! { <option value=r.version.clone()>{label}</option> }
        })
        .collect_view()
}

/// Downloads the OWASP TM-BOM of the project.
fn export_tmbom(ctx: Ctx) {
    let (name, tm) = ctx.with(|p, m| (p.name.clone(), m.to_tmbom(p, &Ctx::today())));
    let file = file_name(&name, "tmbom");
    web::download(&file, &pretty(&tm));
    ctx.toast(format!("Saved {file} to your downloads."));
}
