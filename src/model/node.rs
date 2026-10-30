// SPDX-License-Identifier: GPL-2.0-only
//! Blocks on a page, their evidence, and the data flows between them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::Extra;

pub const NODE_W: f64 = 168.0;
pub const NODE_H: f64 = 64.0;
pub const DEV_W: f64 = 220.0;
pub const DEV_H: f64 = 96.0;

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
