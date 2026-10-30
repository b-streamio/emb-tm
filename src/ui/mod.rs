// SPDX-License-Identifier: GPL-2.0-only
//! Leptos UI. All state lives in [`Ctx`]. An edit goes through [`Ctx::edit`]
//! (re-render and save); typing goes through [`Ctx::typing`], which saves and
//! refreshes the board but leaves the focused form alone.

mod bar;
mod board;
mod clip;
mod ctx;
mod dialogs;
mod inspector;
mod keys;
mod tables;
mod web;

use std::sync::Arc;

use leptos::prelude::*;
use serde::Deserialize;
use serde_json::Value;

use bar::Bar;
pub use ctx::Ctx;
pub use dialogs::Dialog;
use keys::keyboard;

use crate::{
    engine::Model,
    model::{Library, Project},
};

const STORE_KEY: &str = "emb3d-workbench/project";
/// Templates offered by New; the first one opens on a first visit.
const EXAMPLES: &str = "examples/index.json";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum View {
    Diagram,
    Threats,
    Cms,
    Report,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sel {
    Node(u64),
    Flow(u64),
}

/// An EMB3D release this copy can use.
#[derive(Clone, Debug, Deserialize)]
pub struct Release {
    pub version: String,
    pub file: String,
    /// Fetched from emb3d.mitre.org for this session only.
    #[serde(skip)]
    pub session: Option<Arc<Value>>,
}

/// `data/stix/index.json`.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Index {
    pub default: String,
    pub versions: Vec<Release>,
}

/// An example project of `examples/index.json`, offered as a template.
#[derive(Clone, Debug, Deserialize)]
pub struct Example {
    pub file: String,
    pub name: String,
    pub description: String,
}

#[derive(Deserialize)]
struct Examples {
    examples: Vec<Example>,
}

/// The examples, in the order of the index.
pub async fn examples() -> Result<Vec<Example>, String> {
    let v = web::fetch_json(EXAMPLES).await?;
    serde_json::from_value::<Examples>(v)
        .map(|e| e.examples)
        .map_err(|e| format!("{EXAMPLES}: {e}"))
}

/// Project file of an example.
pub async fn example(e: &Example) -> Result<Project, String> {
    Project::from_json(web::fetch_json(&format!("examples/{}", e.file)).await?)
}

#[derive(Clone, PartialEq)]
pub struct Filters {
    pub state: String,
    pub comp: String,
    pub status: String,
}

pub fn ctx() -> Ctx {
    expect_context::<Ctx>()
}

/// JSON text → `Value` (typed values are read from `Value` only, see [`Project::to_json`]).
pub fn parse(text: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|e| format!("This is not valid JSON: {e}"))
}

pub fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

/// `My system`, `tmbom` → `my-system.tmbom.json`.
pub fn file_name(project: &str, kind: &str) -> String {
    let stem = crate::engine::slug(project);
    let stem = if stem.is_empty() { "project" } else { &stem };
    format!("{stem}.{kind}.json")
}

#[component]
pub fn App() -> impl IntoView {
    let ctx = Ctx::new();
    provide_context(ctx);
    let failed = RwSignal::new(None::<String>);
    let ready = RwSignal::new(false);
    leptos::task::spawn_local(async move {
        if let Err(e) = boot(ctx).await {
            failed.set(Some(e));
        } else {
            ready.set(true);
        }
    });
    keyboard(ctx);
    view! {
        <div class="app">
            {move || if ready.get() { view! { <Bar /> }.into_any() } else { view! { <header class="bar"><div class="brand">"EMB3D Workbench"</div></header> }.into_any() }}
            {move || match (ready.get(), failed.get()) {
                (true, _) => view! { <Main /> }.into_any(),
                (false, Some(e)) => view! { <div class="loading">"Could not load the EMB3D data (" {e} "). The app needs to be opened from a web server, not as a file."</div> }.into_any(),
                (false, None) => view! { <div class="loading">"Loading EMB3D…"</div> }.into_any(),
            }}
        </div>
        {move || ctx.toast.get().map(|(_, msg)| view! { <div class="toast" role="status" aria-live="polite">{msg}</div> })}
        <dialogs::Host />
    }
}

async fn boot(ctx: Ctx) -> Result<(), String> {
    let index: Index = serde_json::from_value(web::fetch_json("data/stix/index.json").await?)
        .map_err(|e| e.to_string())?;
    let lib: Library = serde_json::from_value(web::fetch_json("library/components.json").await?)
        .map_err(|e| e.to_string())?;
    let saved = web::load(STORE_KEY)
        .and_then(|raw| parse(&raw).ok())
        .and_then(|v| Project::from_json(v).ok());
    let mut p = match saved {
        Some(p) => p,
        None => match examples().await {
            Ok(list) if !list.is_empty() => {
                example(&list[0]).await.unwrap_or_else(|_| Project::empty())
            }
            _ => Project::empty(),
        },
    };
    p.migrate();
    let version = p
        .emb3d
        .clone()
        .filter(|v| index.versions.iter().any(|r| &r.version == v))
        .unwrap_or_else(|| index.default.clone());
    p.emb3d = Some(version.clone());
    ctx.index.set(index);
    ctx.lib.set(Arc::new(lib));
    let e = ctx.release(&version).await?;
    Model::new(&e, &ctx.lib.get_untracked(), &p).normalize(&mut p);
    ctx.emb3d.set(e);
    ctx.cur.set(p.root.clone());
    ctx.project.set(p);
    Ok(())
}

/// `2.0.1` → `[2, 0, 1]`, for newest-first ordering.
pub fn version_key(v: &str) -> Vec<u64> {
    v.split('.').map(|x| x.parse().unwrap_or(0)).collect()
}

#[component]
fn Main() -> impl IntoView {
    let ctx = ctx();
    move || match ctx.view.get() {
        View::Diagram => {
            view! { <main class="view diagram-host"><board::Diagram /></main> }.into_any()
        }
        View::Threats => {
            view! { <main class="view tableview"><tables::Threats /></main> }.into_any()
        }
        View::Cms => {
            view! { <main class="view tableview"><tables::Countermeasures /></main> }.into_any()
        }
        View::Report => {
            view! { <main class="view tableview reportview"><tables::Report /></main> }.into_any()
        }
    }
}

/// Installs the offline cache and mounts the app on `<body>`.
pub fn start() {
    web::register_service_worker();
    leptos::mount::mount_to_body(App);
}

#[cfg(test)]
#[path = "../../tests/unit/ui/mod.rs"]
mod tests;
