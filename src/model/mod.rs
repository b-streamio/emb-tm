// SPDX-License-Identifier: GPL-2.0-only
//! Project and component-library files. The JSON is the one the JavaScript
//! app and the CLI use (format v2: pages); unknown fields are kept.
//!
//! A node of type `device` is a box standing for a whole device: `page` holds
//! its design and `qty` says how many identical units there are. Node ids are
//! unique across the project.

mod library;
mod node;

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use library::{Choice, CustomCm, CustomThreat, CustomType, Library, Question, TypeDef};
pub use node::{Evidence, Flow, Node, DEV_H, DEV_W, NODE_H, NODE_W};

/// Object storage for fields this app does not interpret.
pub type Extra = Map<String, Value>;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Project {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emb3d: Option<String>,
    #[serde(default)]
    pub meta: Meta,
    #[serde(default)]
    pub root: String,
    #[serde(default)]
    pub seq: u64,
    #[serde(default, rename = "flowSeq")]
    pub flow_seq: u64,
    #[serde(default)]
    pub pages: Vec<Page>,
    #[serde(default, rename = "customTypes")]
    pub custom_types: Vec<CustomType>,
    /// Version 1 files: one diagram at the top level (see [`Project::migrate`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<Node>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flows: Option<Vec<Flow>>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub reviewer: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Page {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub nodes: Vec<Node>,
    #[serde(default)]
    pub flows: Vec<Flow>,
}

impl Project {
    pub fn empty() -> Self {
        Self {
            name: "Untitled system".into(),
            root: "p1".into(),
            pages: vec![Page {
                id: "p1".into(),
                name: "System".into(),
                ..Default::default()
            }],
            seq: 1,
            flow_seq: 1,
            ..Default::default()
        }
    }

    /// Accepts a project file or a TM-BOM exported by the Workbench.
    pub fn from_json(v: Value) -> Result<Self, String> {
        let v = match v.pointer(&format!(
            "/extensions/{}/project",
            EXT_KEY.replace('/', "~1")
        )) {
            Some(p) if v.get("pages").is_none() && v.get("nodes").is_none() => p.clone(),
            _ => v,
        };
        if !(v["pages"].is_array() || v["nodes"].is_array()) {
            return Err(
                "This file is not an EMB3D Workbench project or a TM-BOM exported from it.".into(),
            );
        }
        serde_json::from_value(v).map_err(|e| format!("This project has problems:\n{e}"))
    }

    /// The project as JSON. Every serialisation goes through `Value`, so the
    /// wasm carries one serialiser per type.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Version 1 (single diagram) → version 2 (pages).
    pub fn migrate(&mut self) {
        if self.pages.is_empty() || self.nodes.is_some() {
            let nodes = self.nodes.take().unwrap_or_default();
            let flows = self.flows.take().unwrap_or_default();
            if self.pages.is_empty() {
                let name = if self.name.is_empty() {
                    "Device".into()
                } else {
                    self.name.clone()
                };
                self.pages.push(Page {
                    id: "p1".into(),
                    name,
                    nodes,
                    flows,
                });
                self.root = "p1".into();
            }
        }
        if self.root.is_empty() {
            self.root = self.pages[0].id.clone();
        }
    }

    pub fn generator(&self) -> Option<String> {
        let g = self.extra.get("generator")?;
        let s = |k: &str| g[k].as_str().unwrap_or_default().to_owned();
        let mut out = s("source");
        for (sep, k) in [(" @ ", "revision"), (" by ", "tool"), (" on ", "date")] {
            if !s(k).is_empty() {
                out += &format!("{sep}{}", s(k));
            }
        }
        Some(out)
    }

    pub fn page(&self, id: &str) -> Option<&Page> {
        self.pages.iter().find(|p| p.id == id)
    }

    pub fn page_mut(&mut self, id: &str) -> Option<&mut Page> {
        self.pages.iter_mut().find(|p| p.id == id)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.pages.iter().flat_map(|p| &p.nodes)
    }

    pub fn node(&self, id: u64) -> Option<&Node> {
        self.nodes().find(|n| n.id == id)
    }

    pub fn node_mut(&mut self, id: u64) -> Option<&mut Node> {
        self.pages
            .iter_mut()
            .flat_map(|p| &mut p.nodes)
            .find(|n| n.id == id)
    }

    /// The page holding node `id`.
    pub fn page_of(&self, id: u64) -> Option<&Page> {
        self.pages
            .iter()
            .find(|p| p.nodes.iter().any(|n| n.id == id))
    }

    /// Device boxes whose design is page `id`.
    pub fn parents_of(&self, id: &str) -> Vec<&Node> {
        self.nodes()
            .filter(|n| n.is_device() && n.page.as_deref() == Some(id))
            .collect()
    }

    /// Pages in reading order: root first, then breadth-first through device
    /// boxes, then pages nothing uses.
    pub fn page_order(&self) -> Vec<&Page> {
        let mut order: Vec<&Page> = Vec::new();
        let mut queue = std::collections::VecDeque::from([self.root.clone()]);
        while let Some(id) = queue.pop_front() {
            let Some(p) = self.page(&id) else { continue };
            if order.iter().any(|o| o.id == id) {
                continue;
            }
            order.push(p);
            queue.extend(
                p.nodes
                    .iter()
                    .filter_map(|n| n.page.clone().filter(|_| n.is_device())),
            );
        }
        for p in &self.pages {
            if !order.iter().any(|o| o.id == p.id) {
                order.push(p);
            }
        }
        order
    }
}

/// Key of the project inside a TM-BOM's `extensions`.
pub const EXT_KEY: &str = "emb3d-workbench.invalid/project";

/// Natural order of ids: `PID-11` < `PID-12` < `PID-111`.
pub fn num_cmp(a: &str, b: &str) -> Ordering {
    fn split(s: &str) -> (&str, u64) {
        let i = s.trim_end_matches(|c: char| c.is_ascii_digit()).len();
        (&s[..i], s[i..].parse().unwrap_or(0))
    }
    split(a).cmp(&split(b)).then_with(|| a.cmp(b))
}

#[cfg(test)]
#[path = "../../tests/unit/model/mod.rs"]
mod tests;
