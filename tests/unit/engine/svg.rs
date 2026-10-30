// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/engine/svg.rs` (a child module of it, so private items are in reach).

use super::*;

#[test]
fn wraps_and_anchors() {
    assert_eq!(
        wrap("one two three four five six seven", 9),
        ["one two", "three"]
    );
    let (a, b) = (
        Node::new(1, "os", "", 0.0, 0.0),
        Node::new(2, "os", "", 400.0, 0.0),
    );
    assert_eq!(anchor(&a, &b), (NODE_W_PLUS, 32.0));
    assert_eq!(anchor(&a, &a), (84.0, 32.0));
}

const NODE_W_PLUS: f64 = 168.0 + 6.0;
