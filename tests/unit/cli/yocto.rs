// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/cli/yocto.rs` (a child module of it, so private items are in reach).

use super::*;

#[test]
fn bbenv_keeps_file_and_line() {
    let v = parse_bbenv(
        &read(Path::new("examples/yocto-scan/bitbake-e.sample.txt")).unwrap(),
        "bb.txt",
    );
    assert_eq!(v["IMAGE_FEATURES"].value, "ssh-server-openssh debug-tweaks");
    assert_eq!(
        v["IMAGE_FEATURES"].origins.last().unwrap(),
        &("/work/build/conf/local.conf".to_owned(), 40)
    );
    assert_eq!(
        v["UBOOT_SIGN_ENABLE"].origins,
        [(
            "/work/layers/meta-acme/conf/distro/acme.conf".to_owned(),
            31
        )]
    );
    assert_eq!(v["PATH"].value, "/usr/bin:/bin");
}

#[test]
fn configs_and_globs() {
    let c = parse_config(
        "CONFIG_A=y\n# CONFIG_B is not set\nCONFIG_C=\"x y\"\nNOT=1\n",
        "c",
    );
    assert_eq!(c.map["CONFIG_A"].0, "y");
    assert_eq!(
        c.map["CONFIG_B"],
        ("n".into(), 2, "# CONFIG_B is not set".into())
    );
    assert_eq!(c.map["CONFIG_C"].0, "x y");
    assert_eq!(c.map.len(), 3);
    let g = glob("/etc/*.conf").unwrap();
    assert!(
        g.is_match("/etc/a.conf") && !g.is_match("/etc/x/a.conf") && !g.is_match("/etcXa.conf")
    );
    assert_eq!(short("abcdef", 4), "abc…");
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
    assert!(truthy(&json!("x")) && !truthy(&json!("")) && !truthy(&json!(0)));
}
