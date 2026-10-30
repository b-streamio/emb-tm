// SPDX-License-Identifier: GPL-2.0-only
//! The application state: the project, the EMB3D release and library, and
//! what the user has selected, open or copied.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use leptos::{html, prelude::*};

use super::{file_name, parse, pretty, web, Dialog, Filters, Index, Sel, View, STORE_KEY};
use crate::{
    engine::{Counts, Model, ReportOpts},
    model::{Library, Project},
    ops::{self, Clip},
    stix::{self, Emb3d},
};

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
    pub(super) fn new() -> Self {
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
