// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ui/board.rs` (a child module of it, so private items are in reach).

use super::*;
use crate::model::Node;

#[test]
fn path_goes_up_through_devices() {
    let mut p = Project::empty();
    let mut d = Node::new(1, "device", "Cam", 0.0, 0.0);
    d.page = Some("p2".into());
    p.pages[0].nodes.push(d);
    p.pages.push(Page {
        id: "p2".into(),
        name: "Camera".into(),
        ..Default::default()
    });
    p.pages.push(Page {
        id: "p3".into(),
        name: "Loose".into(),
        ..Default::default()
    });
    let names = |id| {
        page_path(&p, id)
            .into_iter()
            .map(|x| x.1)
            .collect::<Vec<_>>()
    };
    assert_eq!(names("p2"), ["System", "Camera"]);
    assert_eq!(names("p3"), ["System", "Loose"]);
}

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
