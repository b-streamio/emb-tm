// SPDX-License-Identifier: GPL-2.0-only
//! Leptos UI. All state lives in [`Ctx`]. An edit goes through [`Ctx::edit`]
//! (re-render and save); typing goes through [`Ctx::typing`], which saves and
//! refreshes the board but leaves the focused form alone.

mod board;
mod dialogs;
mod inspector;
mod tables;
mod web;

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use leptos::{ev, html, prelude::*};
use serde::Deserialize;
use serde_json::Value;

pub use dialogs::Dialog;

use crate::{
    engine::{Counts, Model, ReportOpts},
    model::{Library, Project},
    ops::{self, Clip, CLIP_KEY},
    stix::{self, Emb3d},
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

#[derive(Clone, Copy)]
pub struct Ctx {
    pub project: RwSignal<Project>,
    /// Threat counts, recomputed on edits but not while typing.
    pub counts: Memo<Counts>,
    /// Bumped while typing: the board and rail follow, forms keep their focus.
    pub soft: RwSignal<u64>,
    /// Bumped when the whole project is replaced (new, open).
    pub epoch: RwSignal<u64>,
    pub emb3d: RwSignal<Arc<Emb3d>>,
    pub lib: RwSignal<Arc<Library>>,
    pub index: RwSignal<Index>,
    parsed: StoredValue<BTreeMap<String, Arc<Emb3d>>>,
    pub cur: RwSignal<String>,
    pub sel: RwSignal<Option<Sel>>,
    pub multi: RwSignal<BTreeSet<u64>>,
    pub connect: RwSignal<Option<u64>>,
    pub open_threat: RwSignal<Option<String>>,
    pub view: RwSignal<View>,
    pub toast: RwSignal<Option<(u64, String)>>,
    pub dialog: RwSignal<Option<Dialog>>,
    pub clip: RwSignal<Option<Clip>>,
    pub nudge: StoredValue<f64>,
    pub filters: RwSignal<Filters>,
    pub report: RwSignal<ReportOpts>,
    pub wrap: NodeRef<html::Section>,
}

impl Ctx {
    fn new() -> Self {
        let project = RwSignal::new(Project::empty());
        let emb3d = RwSignal::new(Arc::<Emb3d>::default());
        let lib = RwSignal::new(Arc::<Library>::default());
        Self {
            project,
            counts: Memo::new(move |_| {
                let (e, lib) = (emb3d.get(), lib.get());
                project.with(|p| Model::new(&e, &lib, p).counts(p))
            }),
            soft: RwSignal::new(0),
            epoch: RwSignal::new(0),
            emb3d,
            lib,
            index: RwSignal::new(Index::default()),
            parsed: StoredValue::new(BTreeMap::new()),
            cur: RwSignal::new("p1".into()),
            sel: RwSignal::new(None),
            multi: RwSignal::new(BTreeSet::new()),
            connect: RwSignal::new(None),
            open_threat: RwSignal::new(None),
            view: RwSignal::new(View::Diagram),
            toast: RwSignal::new(None),
            dialog: RwSignal::new(None),
            clip: RwSignal::new(None),
            nudge: StoredValue::new(0.0),
            filters: RwSignal::new(Filters {
                state: "all".into(),
                comp: "all".into(),
                status: "all".into(),
            }),
            report: RwSignal::new(ReportOpts::default()),
            wrap: NodeRef::new(),
        }
    }

    /// Reads the project with its model (tracked).
    pub fn with<R>(&self, f: impl FnOnce(&Project, &Model) -> R) -> R {
        let (e, lib) = (self.emb3d.get(), self.lib.get());
        // A read guard, not `with`: one reactive read for every caller.
        let p = self.project.read();
        f(&p, &Model::new(&e, &lib, &p))
    }

    /// Changes the project, re-renders and saves.
    pub fn edit<R>(&self, f: impl FnOnce(&mut Project, &Model) -> R) -> R {
        let (e, lib) = (self.emb3d.get_untracked(), self.lib.get_untracked());
        let r = self.project.try_update(|p| {
            let m = Model::new(&e, &lib, p);
            f(p, &m)
        });
        self.save();
        r.expect("project signal lives as long as the app")
    }

    /// Changes the project while the user types: saves, refreshes the board only.
    pub fn typing(&self, f: impl FnOnce(&mut Project)) {
        self.project.update_untracked(f);
        self.soft.update(|n| *n += 1);
        self.save();
    }

    fn save(&self) {
        self.project
            .with_untracked(|p| web::store(STORE_KEY, &p.to_json().to_string()));
    }

    /// Id of the page on the board.
    pub fn page(&self) -> String {
        let cur = self.cur.get();
        self.project.with(|p| {
            if p.page(&cur).is_some() {
                cur
            } else {
                p.root.clone()
            }
        })
    }

    pub fn open_page(&self, id: &str) {
        self.cur.set(id.to_owned());
        self.sel.set(None);
        self.multi.update(BTreeSet::clear);
        self.open_threat.set(None);
        self.connect.set(None);
        self.view.set(View::Diagram);
        if let Some(w) = self.wrap.get_untracked() {
            w.scroll_to_with_x_and_y(0.0, 0.0);
        }
    }

    pub fn select(&self, s: Option<Sel>) {
        self.sel.set(s);
        self.multi.update(BTreeSet::clear);
    }

    /// The primary selection followed by the other selected blocks of this page.
    pub fn selected_ids(&self) -> Vec<u64> {
        let Some(Sel::Node(first)) = self.sel.get_untracked() else {
            return Vec::new();
        };
        let page = self.page();
        let here: BTreeSet<u64> = self.project.with_untracked(|p| {
            p.page(&page)
                .map(|pg| pg.nodes.iter().map(|n| n.id).collect())
                .unwrap_or_default()
        });
        std::iter::once(first)
            .chain(self.multi.get_untracked())
            .filter(|id| here.contains(id))
            .collect()
    }

    pub fn toast(&self, msg: impl Into<String>) {
        let id = self.toast.get_untracked().map_or(0, |(i, _)| i + 1);
        self.toast.set(Some((id, msg.into())));
        let toast = self.toast;
        set_timeout(
            move || {
                if toast.get_untracked().is_some_and(|(i, _)| i == id) {
                    toast.set(None);
                }
            },
            Duration::from_millis(4200),
        );
    }

    pub fn show(&self, d: Dialog) {
        self.dialog.set(Some(d));
    }

    pub fn error(&self, title: &str, text: String) {
        self.show(Dialog::Info {
            title: title.into(),
            text,
        });
    }

    /// Replaces the whole project (open, new).
    fn replace(&self, p: Project) {
        self.cur.set(p.root.clone());
        self.select(None);
        self.open_threat.set(None);
        self.project.set(p);
        self.epoch.update(|n| *n += 1);
        self.save();
    }

    /// Parsed EMB3D release `v`, fetched on first use.
    pub async fn release(&self, v: &str) -> Result<Arc<Emb3d>, String> {
        if let Some(e) = self.parsed.with_value(|m| m.get(v).cloned()) {
            return Ok(e);
        }
        let meta = self
            .index
            .with_untracked(|i| i.versions.iter().find(|r| r.version == v).cloned());
        let meta = meta.ok_or(format!("EMB3D STIX {v} is not available"))?;
        let bundle = match meta.session {
            Some(b) => b,
            None => Arc::new(web::fetch_gzip_json(&format!("data/stix/{}.gz", meta.file)).await?),
        };
        let e = Arc::new(stix::parse(&bundle, v)?);
        self.parsed.update_value(|m| {
            m.insert(v.to_owned(), e.clone());
        });
        Ok(e)
    }

    /// Opens a project or TM-BOM from JSON text.
    pub fn import(&self, text: &str) -> Result<(), String> {
        self.open(Project::from_json(parse(text)?)?)
    }

    /// Replaces the project with `p`, on its EMB3D release when available.
    pub fn open(&self, mut p: Project) -> Result<(), String> {
        p.migrate();
        let (e, lib) = (self.emb3d.get_untracked(), self.lib.get_untracked());
        let m = Model::new(&e, &lib, &p);
        let (errors, _) = m.validate(&p);
        if !errors.is_empty() {
            return Err(ops::problems("This project", &errors));
        }
        m.normalize(&mut p);
        let wanted = p.emb3d.clone();
        let have = |v: &str| {
            self.index
                .with_untracked(|i| i.versions.iter().any(|r| r.version == v))
        };
        let version = wanted
            .clone()
            .filter(|v| have(v))
            .unwrap_or_else(|| self.index.with_untracked(|i| i.default.clone()));
        p.emb3d = Some(version.clone());
        let ctx = *self;
        leptos::task::spawn_local(async move {
            match ctx.release(&version).await {
                Ok(e) => ctx.emb3d.set(e),
                Err(e) => ctx.error("Could not load EMB3D", e),
            }
            ctx.replace(p);
            if let Some(w) = wanted.filter(|w| *w != version) {
                ctx.show(Dialog::Info {
                    title: format!("Opened with EMB3D {version}"),
                    text: format!("This model was made with EMB3D {w}, which is not available here. It now uses {version}, so some threats may differ."),
                });
            }
        });
        Ok(())
    }

    fn copy(&self, cut: bool) -> bool {
        let ids = self.selected_ids();
        if ids.is_empty() {
            return false;
        }
        let page = self.page();
        let clip = self
            .project
            .with_untracked(|p| ops::build_clip(p, &page, &ids));
        let (nodes, pages) = (clip.nodes.len(), clip.pages.len());
        let json = serde_json::to_value(&clip).unwrap_or_default();
        web::write_clipboard(&json.to_string());
        self.clip.set(Some(clip));
        self.nudge.set_value(0.0);
        if cut {
            self.edit(|p, _| ops::cut(p, &page, &ids));
            self.select(None);
        }
        let with = if pages > 0 {
            format!(" with {}", ops::plural(pages, "device page"))
        } else {
            String::new()
        };
        let what = if nodes == 1 { "it" } else { "them" };
        self.toast(format!(
            "{} {}{with}. Select a device box and paste to put {what} inside.",
            if cut { "Cut" } else { "Copied" },
            ops::plural(nodes, "block")
        ));
        true
    }

    /// Pastes `c` into the selected device box, else onto the current page.
    pub fn paste(&self, c: &Clip, here: bool, suffix: &str, message: Option<String>) {
        let page = self.page();
        let into = match (
            here,
            self.sel.get_untracked(),
            self.multi.with_untracked(BTreeSet::is_empty),
        ) {
            (false, Some(Sel::Node(id)), true) => self.project.with_untracked(|p| {
                p.node(id)
                    .filter(|n| n.is_device())
                    .map(|n| (n.id, n.name.clone()))
            }),
            _ => None,
        };
        let nudge = if into.is_some() {
            0.0
        } else {
            self.nudge.get_value() + 30.0
        };
        if into.is_none() && suffix.is_empty() {
            self.nudge.set_value(nudge);
        }
        let res =
            self.edit(|p, m| ops::paste(p, m, c, &page, into.as_ref().map(|d| d.0), nudge, suffix));
        match res {
            Err(e) => self.toast(e),
            Ok(ids) => {
                let project_version = self.project.with_untracked(|p| p.emb3d.clone());
                if c.emb3d.is_some() && c.emb3d != project_version {
                    self.toast(format!(
                        "Pasted blocks made with EMB3D {}; this project uses {}.",
                        c.emb3d.clone().unwrap_or_default(),
                        project_version.unwrap_or_default()
                    ));
                }
                match &into {
                    Some((dev, _)) => self.select(Some(Sel::Node(*dev))),
                    None => {
                        self.select(ids.first().map(|id| Sel::Node(*id)));
                        self.multi.set(ids.iter().skip(1).copied().collect());
                    }
                }
                let into = into.map_or(String::new(), |(_, name)| format!(" into {name}"));
                self.toast(message.unwrap_or_else(|| {
                    format!("Pasted {}{into}.", ops::plural(ids.len(), "block"))
                }));
            }
        }
    }

    pub fn duplicate(&self) {
        let ids = self.selected_ids();
        if ids.is_empty() {
            return;
        }
        let page = self.page();
        let c = self
            .project
            .with_untracked(|p| ops::build_clip(p, &page, &ids));
        let pages = if c.pages.is_empty() {
            ""
        } else {
            " with their own design pages"
        };
        let msg = format!(
            "Duplicated {}{pages}. Change the copy freely.",
            ops::plural(c.nodes.len(), "block")
        );
        self.paste(&c, true, " (copy)", Some(msg));
    }

    /// Downloads the project as `<name>.project.json`.
    pub fn save_file(&self) {
        let (name, json) = self
            .project
            .with_untracked(|p| (p.name.clone(), p.to_json()));
        let file = file_name(&name, "project");
        web::download(&file, &pretty(&json));
        self.toast(format!("Saved {file} to your downloads."));
    }

    pub fn today() -> String {
        String::from(js_sys::Date::new_0().to_iso_string())
            .chars()
            .take(10)
            .collect()
    }
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

/// Ctrl/⌘ C X V D A, Escape and pasting JSON anywhere.
fn keyboard(ctx: Ctx) {
    let typing = || web::typing_in_field();
    let _ = window_event_listener(ev::keydown, move |e| {
        let open = ctx.dialog.with_untracked(Option::is_some);
        if (e.ctrl_key() || e.meta_key())
            && !e.alt_key()
            && !typing()
            && !open
            && ctx.view.get_untracked() == View::Diagram
        {
            let handled = match e.key().to_lowercase().as_str() {
                "c" => !web::has_text_selection() && ctx.copy(false),
                "x" => ctx.copy(true),
                "d" => {
                    ctx.duplicate();
                    true
                }
                "a" => {
                    let page = ctx.page();
                    let ids: Vec<u64> = ctx.project.with_untracked(|p| {
                        p.page(&page)
                            .map(|pg| pg.nodes.iter().map(|n| n.id).collect())
                            .unwrap_or_default()
                    });
                    if let Some((first, rest)) = ids.split_first() {
                        ctx.sel.set(Some(Sel::Node(*first)));
                        ctx.multi.set(rest.iter().copied().collect());
                    }
                    true
                }
                _ => false,
            };
            if handled {
                e.prevent_default();
            }
            return;
        }
        if e.key() != "Escape" {
            return;
        }
        if open {
            ctx.dialog.set(None);
        } else if ctx.multi.with_untracked(|m| !m.is_empty()) {
            ctx.multi.update(BTreeSet::clear);
        } else if ctx.connect.get_untracked().is_some() {
            ctx.connect.set(None);
        }
    });
    let _ = window_event_listener(ev::paste, move |e| {
        if ctx.dialog.with_untracked(Option::is_some) || web::typing_in_field() {
            return;
        }
        let text = e
            .clipboard_data()
            .and_then(|d| d.get_data("text").ok())
            .unwrap_or_default();
        if text.contains(CLIP_KEY) {
            if let Some(c) = parse(&text)
                .ok()
                .and_then(|v| serde_json::from_value::<Clip>(v).ok())
            {
                e.prevent_default();
                ctx.view.set(View::Diagram);
                ctx.paste(&c, false, "", None);
                return;
            }
        }
        if text.trim_start().starts_with('{') {
            if let Err(err) = ctx.import(&text) {
                ctx.error("Could not open the pasted text", err);
            }
        } else if let Some(c) = ctx
            .clip
            .get_untracked()
            .filter(|_| ctx.view.get_untracked() == View::Diagram)
        {
            e.prevent_default();
            ctx.paste(&c, false, "", None);
        }
    });
}

/// Header: version, project name, tabs, file actions.
#[component]
fn Bar() -> impl IntoView {
    let ctx = ctx();
    let open_count = move || ctx.counts.with(Counts::open);
    let tab = move |v: View, label: &'static str| {
        let count = (v == View::Threats).then(
            || view! { <span class="count">{move || Some(open_count()).filter(|n| *n > 0)}</span> },
        );
        view! { <button role="tab" aria-selected=move || (ctx.view.get() == v).to_string() on:click=move |_| ctx.view.set(v)>{label}{count}</button> }
    };
    let versions = move || {
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
            <div class="brand">"EMB3D Workbench"</div>
            <div class="ver">
                <select aria-label="EMB3D version" prop:value=move || ctx.emb3d.get().version.clone()
                    on:change=move |e| dialogs::propose_version(ctx, event_target_value(&e))>{versions}</select>
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
                <button class="btn primary" title="Download an OWASP TM-BOM (Threat Model Library v1.0.2) for Threat Dragon; it opens here again too" on:click=move |_| {
                    let (name, tm) = ctx.with(|p, m| (p.name.clone(), m.to_tmbom(p, &Ctx::today())));
                    let file = file_name(&name, "tmbom");
                    web::download(&file, &pretty(&tm));
                    ctx.toast(format!("Saved {file} to your downloads."));
                }>"Export TM-BOM"</button>
                <button class="btn" on:click=move |_| dialogs::templates(ctx)>"New"</button>
            </div>
        </header>
    }
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
