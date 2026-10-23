// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ui/mod.rs` (a child module of it, so private items are in reach).

use super::version_key;

#[test]
fn versions_sort_numerically() {
    let mut v = ["2.0", "10.1", "2.0.1"];
    v.sort_by_key(|x| version_key(x));
    assert_eq!(v, ["2.0", "2.0.1", "10.1"]);
}
