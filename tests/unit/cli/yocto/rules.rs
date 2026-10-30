// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/cli/yocto/rules.rs` (a child module of it, so private items are in reach).

use serde_json::json;

use super::*;

#[test]
fn globs() {
    let g = glob("/etc/*.conf").unwrap();
    assert!(
        g.is_match("/etc/a.conf") && !g.is_match("/etc/x/a.conf") && !g.is_match("/etcXa.conf")
    );
}

#[test]
fn conditions_are_three_valued() {
    let mut f = Found::default();
    let c = json!({"any": [{"var": "X", "eq": "1"}, {"pkg": "a"}]});
    let r = f.eval(&c).unwrap();
    assert_eq!(r.v, None);
    assert_eq!(r.miss.len(), 2);
    f.pkgs.entry("a").sources.push("m".into());
    assert_eq!(f.eval(&c).unwrap().v, Some(true));
    assert_eq!(
        f.eval(&json!({"all": [{"pkg": "b"}, {"var": "X"}]}))
            .unwrap()
            .v,
        Some(false)
    );
    assert_eq!(
        f.eval(&json!({"not": {"pkg": "a"}})).unwrap().v,
        Some(false)
    );
    assert!(f.eval(&json!({"bogus": 1})).is_err());
}
