// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/cli/yocto/mod.rs` (a child module of it, so private items are in reach).

use serde_json::json;

use super::*;

#[test]
fn helpers() {
    assert_eq!(short("abcdef", 4), "abc…");
    assert!(truthy(&json!("x")) && !truthy(&json!("")) && !truthy(&json!(0)));
    let mut v = vec!["a".to_owned(), "b".into(), "a".into()];
    dedup(&mut v);
    assert_eq!(v, ["a", "b"]);
}
