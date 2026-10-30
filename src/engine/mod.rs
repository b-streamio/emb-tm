// SPDX-License-Identifier: GPL-2.0-only
//! Rules, roll-ups, validation, TM-BOM export and report markup.
//!
//! 1. A component's EMB3D properties = its type's `base` PIDs + the PIDs of
//!    its answers; a sub-property implies its parent.
//! 2. A device page without an update agent gives its OS (or SoC) PID-26.
//! 3. A threat applies to a component sharing at least one property with it;
//!    custom block types add their own threats.
//! 4. A threat handled with countermeasures is Mitigated when one is
//!    implemented, Not applicable when all are, Open otherwise; the threat
//!    can also be declared not applicable or accepted, with a justification.

mod counts;
mod labels;
mod report;
mod svg;
mod threats;
mod tmbom;
mod validate;

use std::{borrow::Cow, collections::BTreeMap};

use crate::{
    model::{CustomCm, CustomThreat, CustomType, Library, Node, Project, TypeDef},
    stix::{Emb3d, Mitigation, Threat},
};

pub use counts::{Counts, ReviewItem, Rollup, Summary};
pub use labels::*;
pub use report::ReportOpts;
pub use svg::anchor;
pub use threats::*;
pub use tmbom::TMBOM_SCHEMA;

/// The EMB3D catalogue and component library, bound to one project's custom
/// types. Cheap to build: library types are borrowed, not copied.
pub struct Model<'a> {
    pub e: &'a Emb3d,
    pub lib: &'a Library,
    pub types: BTreeMap<String, Cow<'a, TypeDef>>,
    threats: BTreeMap<String, Threat>,
    mits: BTreeMap<String, Mitigation>,
}

impl<'a> Model<'a> {
    pub fn new(e: &'a Emb3d, lib: &'a Library, p: &Project) -> Self {
        let mut types: BTreeMap<String, Cow<TypeDef>> = lib
            .components
            .iter()
            .map(|c| (c.kind.clone(), Cow::Borrowed(c)))
            .collect();
        let (mut threats, mut mits) = (BTreeMap::new(), BTreeMap::new());
        for c in &p.custom_types {
            types.insert(c.kind.clone(), Cow::Owned(custom_type(c)));
            for t in &c.threats {
                threats.insert(t.id.clone(), custom_threat(t));
                for m in &t.cms {
                    mits.insert(m.id.clone(), custom_cm(m));
                }
            }
        }
        Self {
            e,
            lib,
            types,
            threats,
            mits,
        }
    }

    pub fn threat(&self, tid: &str) -> Option<&Threat> {
        self.e.threats.get(tid).or_else(|| self.threats.get(tid))
    }

    pub fn mitigation(&self, mid: &str) -> Option<&Mitigation> {
        self.e.mitigations.get(mid).or_else(|| self.mits.get(mid))
    }

    pub fn type_of(&self, n: &Node) -> Option<&TypeDef> {
        self.types.get(&n.kind).map(|t| &**t)
    }

    pub fn is_external(&self, n: &Node) -> bool {
        self.type_of(n).is_some_and(|t| t.external)
    }

    pub fn has_threats(&self, n: &Node) -> bool {
        !self.is_external(n) && !n.is_device()
    }

    fn property_name(&self, pid: &str) -> &str {
        self.e.properties.get(pid).map_or("", |p| p.name.as_str())
    }
}

/// `s`, or `default` when it is empty.
fn or(s: &str, default: &str) -> String {
    if s.is_empty() { default } else { s }.to_owned()
}

fn custom_type(c: &CustomType) -> TypeDef {
    TypeDef {
        kind: c.kind.clone(),
        name: c.name.clone(),
        group: or(&c.group, "Custom"),
        tag: or(&c.tag.chars().take(4).collect::<String>(), "CUS"),
        hint: or(&c.hint, "Custom block"),
        base: c.base.clone(),
        questions: c.questions.clone(),
        external: c.external,
        custom: true,
        threats: c.threats.clone(),
        ..Default::default()
    }
}

fn custom_threat(t: &CustomThreat) -> Threat {
    Threat {
        name: t.name.clone(),
        cat: "custom".into(),
        maturity: "custom".into(),
        desc: t.desc.clone(),
        text: vec![t.desc.clone()],
        mids: t.cms.iter().map(|m| m.id.clone()).collect(),
        custom: true,
        ..Default::default()
    }
}

fn custom_cm(m: &CustomCm) -> Mitigation {
    Mitigation {
        name: m.name.clone(),
        maturity: "custom".into(),
        desc: m.desc.clone(),
        text: vec![m.desc.clone()],
        custom: true,
        ..Default::default()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/engine/mod.rs"]
pub mod tests;
