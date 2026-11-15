// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/cli/yocto/rootfs.rs` (a child module of it, so private items are in reach).

use std::{fs, os::unix::fs::symlink, process::Command};

use super::*;

#[test]
fn tarball_extracts_what_the_rules_read_once() {
    let d = std::env::temp_dir().join(format!("emb-tm-rootfs-test-{}", std::process::id()));
    let img = d.join("img");
    fs::create_dir_all(img.join("etc")).unwrap();
    fs::write(img.join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
    fs::write(img.join("etc/other"), "not wanted\n").unwrap();
    symlink("/etc/hostname", img.join("etc/hostname")).unwrap();
    let tgz = d.join("img.tar.gz");
    let ok = Command::new("tar")
        .arg("-czf")
        .arg(&tgz)
        .arg("-C")
        .arg(&img)
        .arg(".")
        .status()
        .unwrap();
    assert!(ok.success());

    let wanted = [regex::Regex::new("^/etc/(passwd|hostname)$").unwrap()];
    let r = Rootfs::open(&tgz, &wanted).unwrap();
    assert!(r.list.iter().any(|p| p == "/etc/other"), "{:?}", r.list);
    assert!(r.read("/etc/passwd").unwrap().starts_with("root:"));
    assert_eq!(r.read("/etc/other"), None, "only the files the rules read");
    assert_eq!(r.read("/etc/hostname"), None, "a link out of the image");
    let tmp = r.root.clone();
    assert!(tmp.is_dir());
    drop(r);
    assert!(
        !tmp.exists(),
        "the temporary directory goes with the Rootfs"
    );

    let dir = Rootfs::open(&img, &[]).unwrap();
    assert_eq!(dir.read("/etc/other").as_deref(), Some("not wanted\n"));
    fs::remove_dir_all(&d).unwrap();
}
