// SPDX-License-Identifier: GPL-2.0-only
//! An image root file system: an unpacked directory or a tarball (read with
//! the system `tar`, which handles gz, bz2, xz and zst).

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use regex::Regex;

use super::{base, read};

/// An image root file system: an unpacked directory, or a tarball whose
/// files the rules read are extracted once, into a temporary directory.
pub(super) struct Rootfs {
    pub(super) label: String,
    pub(super) list: Vec<String>,
    /// Where the files are: the directory, or the temporary one.
    root: PathBuf,
    /// The temporary directory of a tarball, removed with the `Rootfs`.
    tmp: Option<PathBuf>,
}

impl Rootfs {
    /// Opens `src`; of a tarball, extracts the files matching `wanted`
    /// (rootfs paths), in one pass: each pass decompresses the whole image.
    pub(super) fn open(src: &Path, wanted: &[Regex]) -> Result<Self, String> {
        if src.is_dir() {
            let mut list = Vec::new();
            walk(src, src, &mut list);
            let (label, root) = (src.display().to_string(), src.to_owned());
            return Ok(Self {
                label,
                list,
                root,
                tmp: None,
            });
        }
        println!("Listing {} (a large image takes a while)", base(src));
        let (mut list, mut members) = (Vec::new(), Vec::new());
        for raw in tar(src, &["-tf"])?.lines().filter(|l| !l.is_empty()) {
            let path = raw.trim_start_matches("./").trim_start_matches('/');
            let path = format!("/{}", path.trim_end_matches('/'));
            if wanted.iter().any(|g| g.is_match(&path)) {
                members.push(raw.to_owned());
            }
            list.push(path);
        }
        // (a new directory: it fails rather than use one someone prepared)
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp = std::env::temp_dir().join(format!("emb-tm-{}-{stamp}", std::process::id()));
        fs::create_dir(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        let fs = Self {
            label: base(src),
            list,
            root: tmp.clone(),
            tmp: Some(tmp),
        };
        if !members.is_empty() {
            println!("Extracting the {} files the rules read", members.len());
            let dir = fs.root.to_string_lossy().into_owned();
            let mut args = vec!["-xf"];
            args.extend(["-C", dir.as_str(), "--"]);
            args.extend(members.iter().map(String::as_str));
            tar(src, &args)?;
        }
        Ok(fs)
    }

    /// Text of a file; a tarball's symbolic links are not followed (they
    /// would lead out of the image).
    pub(super) fn read(&self, path: &str) -> Option<String> {
        let p = self.root.join(path.trim_start_matches('/'));
        if self.tmp.is_some() && p.symlink_metadata().ok()?.file_type().is_symlink() {
            return None;
        }
        read(&p).ok()
    }
}

impl Drop for Rootfs {
    fn drop(&mut self) {
        if let Some(t) = &self.tmp {
            let _ = fs::remove_dir_all(t);
        }
    }
}

/// Every path under `dir`, as `/rel/path`, in order.
fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in entries {
        let rel = p.strip_prefix(root).unwrap_or(&p);
        out.push(format!("/{}", rel.to_string_lossy().replace('\\', "/")));
        if p.is_dir() && !p.is_symlink() {
            walk(root, &p, out);
        }
    }
}

/// Runs the system `tar` on `archive` (it handles gz, bz2, xz and zst).
fn tar(archive: &Path, args: &[&str]) -> Result<String, String> {
    let (flag, rest) = args.split_first().expect("a tar flag");
    let out = Command::new("tar")
        .arg(flag)
        .arg(archive)
        .args(rest)
        .output()
        .map_err(|e| format!("tar: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "tar {flag} {}: {}",
            archive.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/yocto/rootfs.rs"]
mod tests;
