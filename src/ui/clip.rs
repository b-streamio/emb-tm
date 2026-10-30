// SPDX-License-Identifier: GPL-2.0-only
//! Copy, cut, paste and duplicate of the selected blocks.

use std::collections::BTreeSet;

use leptos::prelude::*;

use super::{web, Ctx, Sel};
use crate::ops::{self, Clip};

impl Ctx {
    pub(super) fn copy(&self, cut: bool) -> bool {
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
}
