// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ui/dialogs/detail.rs` (a child module of it, so private items are in reach).

use super::*;

#[test]
fn rich_text_segments() {
    let known = |x: &str| x == "TID-101";
    assert_eq!(
        rich("See *this* and TID-101, not TID-999 or XTID-101.", known),
        [
            Seg::Text("See ".into()),
            Seg::Em("this".into()),
            Seg::Text(" and ".into()),
            Seg::Link("TID-101".into()),
            Seg::Text(", not TID-999 or XTID-101.".into())
        ]
    );
    assert_eq!(rich("a * b é", known), [Seg::Text("a * b é".into())]);
}
