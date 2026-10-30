// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ui/board/mod.rs` (a child module of it, so private items are in reach).

use super::*;
use crate::model::{Flow, Node};

#[test]
fn edges_are_escaped() {
    let mut pg = Page::default();
    pg.nodes.push(Node::new(1, "os", "", 0.0, 0.0));
    pg.nodes.push(Node::new(2, "os", "", 300.0, 0.0));
    pg.flows.push(Flow {
        id: 7,
        from: 1,
        to: 2,
        label: "<b>x</b>".into(),
        ..Default::default()
    });
    let svg = edges_svg(&pg, Some(Sel::Flow(7)));
    assert!(svg.contains("&lt;b&gt;x") && svg.contains("arrSel") && svg.contains("edge plain sel"));
}
