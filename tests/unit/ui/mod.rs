// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/ui/mod.rs` (a child module of it, so private items are in reach).

use super::{version_key, Release};

#[test]
fn versions_sort_numerically() {
    let mut v = ["2.0", "10.1", "2.0.1"];
    v.sort_by_key(|x| version_key(x));
    assert_eq!(v, ["2.0", "2.0.1", "10.1"]);
}

#[test]
fn release_integrity_from_pinned_hash() {
    let r = |sha256: &str| Release {
        version: "0".into(),
        file: String::new(),
        source: String::new(),
        sha256: sha256.into(),
        session: None,
    };
    let empty = r("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(
        empty.sri(),
        "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
    );
    assert_eq!(r("ff").sri(), "sha256-/w==");
    assert_eq!(r("ffff").sri(), "sha256-//8=");
}
