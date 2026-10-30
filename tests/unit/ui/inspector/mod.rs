// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ui/inspector/mod.rs` (a child module of it, so private items are in reach).

#[test]
fn states_have_css_keys() {
    assert_eq!(crate::engine::State::NotApplicable.key(), "NA");
}
