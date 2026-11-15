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
/// MITRE's EMB3D site: releases, threat pages, the Updates check.
pub const MITRE: &str = "https://emb3d.mitre.org";
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

/// An EMB3D release this copy can use. emb-tm ships none: each browser
/// downloads it from MITRE once (MITRE's terms of use) and keeps it offline.
#[derive(Clone, Debug, Deserialize)]
pub struct Release {
    pub version: String,
    pub file: String,
    /// MITRE's URL of the file.
    #[serde(default)]
    pub source: String,
    /// SHA-256 (hex) the download must match.
    #[serde(default)]
    pub sha256: String,
    /// Fetched from emb3d.mitre.org for this session only.
    #[serde(skip)]
    pub session: Option<Arc<Value>>,
}

impl Release {
    /// Subresource integrity of the file (`sha256-<base64>`): the browser
    /// rejects a download that does not match the pinned hash.
    pub fn sri(&self) -> String {
        const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes: Vec<u8> = (0..self.sha256.len() / 2)
            .filter_map(|i| u8::from_str_radix(self.sha256.get(2 * i..2 * i + 2)?, 16).ok())
            .collect();
        let mut out = String::from("sha256-");
        for c in bytes.chunks(3) {
            let n = c
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
            for i in 0..4 {
                out.push(if i <= c.len() {
                    char::from(B64[(n >> (18 - 6 * i)) as usize & 63])
                } else {
                    '='
                });
            }
        }
        out
    }
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

/// Where the start-up is.
#[derive(Clone)]
enum Stage {
    Loading,
    /// The release the project needs is not downloaded yet: ask first.
    NeedData(Box<Project>, Release),
    Failed(String),
    Ready,
}

#[component]
pub fn App() -> impl IntoView {
    let ctx = Ctx::new();
    provide_context(ctx);
    let stage = RwSignal::new(Stage::Loading);
    leptos::task::spawn_local(async move {
        let next = match prepare(ctx).await {
            Err(e) => Stage::Failed(e),
            Ok((p, r)) if r.session.is_none() && web::cached(&r.source).await.is_none() => {
                Stage::NeedData(Box::new(p), r)
            }
            Ok((p, r)) => finish(ctx, p, &r.version).await,
        };
        stage.set(next);
    });
    keyboard(ctx);
    view! {
        <div class="app">
            {move || if matches!(stage.get(), Stage::Ready) { view! { <Bar /> }.into_any() } else { view! { <header class="bar"><div class="brand">"emb-tm"</div></header> }.into_any() }}
            {move || match stage.get() {
                Stage::Ready => view! { <Main /> }.into_any(),
                Stage::NeedData(p, r) => view! { <FirstRun stage p r /> }.into_any(),
                Stage::Failed(e) => view! { <div class="loading">"Could not load the EMB3D data (" {e} "). Check the connection and reload. The app needs to be opened from a web server, not as a file."</div> }.into_any(),
                Stage::Loading => view! { <div class="loading">"Loading EMB3D…"</div> }.into_any(),
            }}
        </div>
        {move || ctx.toast.get().map(|(_, msg)| view! { <div class="toast" role="status" aria-live="polite">{msg}</div> })}
        <dialogs::Host />
    }
}

/// First start: emb-tm ships no MITRE data, so the user downloads the
/// release from emb3d.mitre.org once, under MITRE's terms of use.
#[component]
fn FirstRun(stage: RwSignal<Stage>, p: Box<Project>, r: Release) -> impl IntoView {
    let ctx = ctx();
    let v = r.version.clone();
    let download = move |_| {
        let (p, v) = (p.clone(), v.clone());
        stage.set(Stage::Loading);
        leptos::task::spawn_local(async move { stage.set(finish(ctx, *p, &v).await) });
    };
    view! {
        <div class="loading">
            <h3>{format!("Download MITRE EMB3D™ {}", r.version)}</h3>
            <p>"emb-tm works from MITRE's EMB3D threat catalogue but does not ship it. Download it once from emb3d.mitre.org; it then stays in this browser and works offline."</p>
            <p class="small">"MITRE EMB3D™ is © The MITRE Corporation and comes under MITRE's " <a class="extlink" href=format!("{MITRE}/subtabs/terms-of-use.html") target="_blank" rel="noopener">"terms of use"</a> ". emb-tm is not affiliated with or endorsed by MITRE."</p>
            <button class="btn primary" on:click=download>{format!("Download EMB3D {}", r.version)}</button>
        </div>
    }
}

/// Loads the index, the library and the project to open; returns the
/// project and the EMB3D release it needs.
async fn prepare(ctx: Ctx) -> Result<(Project, Release), String> {
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
    let find = |v: &str| index.versions.iter().find(|r| r.version == v).cloned();
    let release = p
        .emb3d
        .as_deref()
        .and_then(find)
        .or_else(|| find(&index.default))
        .ok_or("data/stix/index.json lists no EMB3D release")?;
    p.emb3d = Some(release.version.clone());
    ctx.index.set(index);
    ctx.lib.set(Arc::new(lib));
    Ok((p, release))
}

/// Loads release `version` (from the cache, else from MITRE) and opens `p`.
async fn finish(ctx: Ctx, mut p: Project, version: &str) -> Stage {
    let e = match ctx.release(version).await {
        Ok(e) => e,
        Err(e) => return Stage::Failed(e),
    };
    Model::new(&e, &ctx.lib.get_untracked(), &p).normalize(&mut p);
    ctx.emb3d.set(e);
    ctx.cur.set(p.root.clone());
    ctx.project.set(p);
    Stage::Ready
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
