// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/cli/yocto/parse.rs` (a child module of it, so private items are in reach).

use std::path::Path;

use super::*;
use crate::cli::yocto::read;

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
fn configs() {
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
}
