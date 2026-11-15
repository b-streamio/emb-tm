// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/cli/yocto/deploy.rs` (a child module of it, so private items are in reach).

use std::fs;

use super::*;

#[test]
fn rootfs_is_the_fastest_archive() {
    let d = std::env::temp_dir().join(format!("emb-tm-deploy-test-{}", std::process::id()));
    fs::create_dir_all(&d).unwrap();
    for f in [
        "os.rootfs.manifest",
        "os.rootfs.tar.bz2",
        "os.rootfs.tar.xz",
        "os.rootfs.tar.gz",
    ] {
        fs::write(d.join(f), "").unwrap();
    }
    let rootfs = |d: &Path| from_deploy_dir(d, None).unwrap().rootfs.unwrap();
    assert_eq!(rootfs(&d), d.join("os.rootfs.tar.gz"));
    fs::remove_file(d.join("os.rootfs.tar.gz")).unwrap();
    assert_eq!(rootfs(&d), d.join("os.rootfs.tar.xz"));
    fs::remove_dir_all(&d).unwrap();
}
