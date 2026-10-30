// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ui/board/pages.rs` (a child module of it, so private items are in reach).

use super::*;
use crate::model::{Node, Page};

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
