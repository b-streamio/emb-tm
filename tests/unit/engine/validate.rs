// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/engine/validate.rs` (a child module of it, so private items are in reach).

use super::*;
use crate::{
    engine::tests::{data, one_page},
    model::{Flow, Node, Page},
};

#[test]
fn validation_errors() {
    let (e, lib) = data();
    let mut p = one_page(&["os", "nope"]);
    p.pages[0].nodes[0]
        .answers
        .insert("modules".into(), "yes".into());
    p.pages[0].nodes[0]
        .answers
        .insert("bogus".into(), true.into());
    p.pages[0].flows.push(Flow {
        id: 1,
        from: 1,
        to: 9,
        ..Default::default()
    });
    let mut dev = Node::new(3, "device", "Loop", 0.0, 0.0);
    dev.page = Some("p1".into());
    p.pages[0].nodes.push(dev);
    let m = Model::new(&e, &lib, &p);
    let (errors, warnings) = m.validate(&p);
    let all = errors.join("\n");
    for want in [
        "unknown type \"nope\"",
        "\"modules\" must be true or false",
        "unknown question \"bogus\"",
        "same page",
        "loop: System > System",
    ] {
        assert!(all.contains(want), "{want} missing in:\n{all}");
    }
    assert!(!warnings.is_empty());
    p.pages.push(Page {
        id: "p1".into(),
        ..Default::default()
    });
    assert!(m.validate(&p).0[0].contains("duplicate page id"));
}
