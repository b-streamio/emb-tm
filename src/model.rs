// SPDX-License-Identifier: GPL-2.0-only
//! Project and component-library files. The JSON is the one the JavaScript
//! app and the CLI use (format v2: pages); unknown fields are kept.
//!
//! A node of type `device` is a box standing for a whole device: `page` holds
//! its design and `qty` says how many identical units there are. Node ids are
//! unique across the project.

use std::{cmp::Ordering, collections::BTreeMap};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

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

fn unset() -> f64 {
    f64::NAN
}

/// A position written as `null` (unset) reads as `NaN`.
fn position<'de, D: serde::Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    Ok(Option::<f64>::deserialize(d)?.unwrap_or(f64::NAN))
}

/// Whole positions are written as integers (`540`, not `540.0`), unset as `null`.
fn coordinate<S: serde::Serializer>(v: &f64, s: S) -> Result<S::Ok, S::Error> {
    match *v {
        v if v.is_nan() => s.serialize_none(),
        v if v.fract() == 0.0 && v.abs() < 1e15 => s.serialize_i64(v as i64),
        v => s.serialize_f64(v),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: u64,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    /// `NaN` until [`crate::engine::Model::layout`] places it.
    #[serde(
        default = "unset",
        deserialize_with = "position",
        serialize_with = "coordinate"
    )]
    pub x: f64,
    #[serde(
        default = "unset",
        deserialize_with = "position",
        serialize_with = "coordinate"
    )]
    pub y: f64,
    /// Question id → `true`/`false` or a choice value.
    #[serde(default)]
    pub answers: Map<String, Value>,
    /// Mitigation id → countermeasure status.
    #[serde(default)]
    pub cm: BTreeMap<String, String>,
    /// Threat id → decision: `"na"`, `"accept"` (or `true` in old files), `false`/`""` for none.
    #[serde(default)]
    pub accepted: Map<String, Value>,
    /// Mitigation id or `accept:<threat id>` → justification.
    #[serde(default)]
    pub why: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qty: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<String>,
    /// Question id (or `_component`) → where the answer comes from.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub evidence: BTreeMap<String, Vec<Evidence>>,
    /// Question id (or `_component`) → `true` or the reason it needs a human look.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub review: Map<String, Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl Node {
    pub fn new(id: u64, kind: &str, name: &str, x: f64, y: f64) -> Self {
        Self {
            id,
            kind: kind.to_owned(),
            name: name.to_owned(),
            x,
            y,
            answers: Map::new(),
            cm: BTreeMap::new(),
            accepted: Map::new(),
            why: BTreeMap::new(),
            qty: None,
            page: None,
            evidence: BTreeMap::new(),
            review: Map::new(),
            extra: Extra::new(),
        }
    }

    pub fn is_device(&self) -> bool {
        self.kind == "device"
    }

    pub fn qty(&self) -> u32 {
        self.qty.unwrap_or(1)
    }

    /// Box size on the board: `(width, height)`.
    pub fn size(&self) -> (f64, f64) {
        if self.is_device() {
            (DEV_W, DEV_H)
        } else {
            (NODE_W, NODE_H)
        }
    }

    /// `" ×4"` for a device box of several units, else `""`.
    pub fn units(&self) -> String {
        if self.is_device() && self.qty() > 1 {
            format!(" ×{}", self.qty())
        } else {
            String::new()
        }
    }

    /// Why answer `qid` needs a human look; `""` when no reason is given.
    pub fn review_of(&self, qid: &str) -> Option<String> {
        match self.review.get(qid)? {
            Value::Bool(true) => Some(String::new()),
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    }

    /// Review reasons that are set.
    pub fn reviews(&self) -> impl Iterator<Item = (&String, String)> {
        self.review
            .keys()
            .filter_map(|k| Some((k, self.review_of(k)?)))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
}

impl Evidence {
    pub fn label(&self) -> String {
        let line = self.line.map(|l| format!(":{l}")).unwrap_or_default();
        let text = if self.text.is_empty() {
            String::new()
        } else {
            format!(" — {}", self.text)
        };
        format!("{}{line}{text}", self.file)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    #[serde(default)]
    pub id: u64,
    pub from: u64,
    pub to: u64,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub sensitive: bool,
}

/// A block type defined in the project (left rail, "New custom block").
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CustomType {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub hint: String,
    #[serde(default)]
    pub base: Vec<String>,
    #[serde(default)]
    pub threats: Vec<CustomThreat>,
    /// Questionnaire, as in the library.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub questions: Vec<Question>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub external: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CustomThreat {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub desc: String,
    #[serde(default)]
    pub cms: Vec<CustomCm>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CustomCm {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub desc: String,
}

/// `library/components.json`: the component palette and its questionnaires.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct Library {
    /// Rail order; a library file to import may leave it out.
    #[serde(default)]
    pub groups: Vec<String>,
    pub components: Vec<TypeDef>,
}

#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct TypeDef {
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub group: String,
    pub tag: String,
    #[serde(default)]
    pub hint: String,
    #[serde(default)]
    pub base: Vec<String>,
    #[serde(default)]
    pub questions: Vec<Question>,
    #[serde(default)]
    pub external: bool,
    /// Holds a page (the device box).
    #[serde(default)]
    pub container: bool,
    /// Set for project custom types.
    #[serde(skip)]
    pub custom: bool,
    #[serde(skip)]
    pub threats: Vec<CustomThreat>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Question {
    pub id: String,
    pub text: String,
    /// `bool` or `choice`.
    pub kind: String,
    pub default: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<Choice>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Choice {
    pub value: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pids: Vec<String>,
}

pub const NODE_W: f64 = 168.0;
pub const NODE_H: f64 = 64.0;
pub const DEV_W: f64 = 220.0;
pub const DEV_H: f64 = 96.0;

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
#[path = "../tests/unit/model.rs"]
mod tests;
