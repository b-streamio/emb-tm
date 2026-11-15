// SPDX-License-Identifier: GPL-2.0-only
//! The image of a Yocto deploy directory and its input files.

use std::{fs, path::Path};

use regex::Regex;

use super::{dedup, Inputs};

/// The inputs of one image in a Yocto deploy directory
/// (`tmp/deploy/images/<machine>`).
pub fn from_deploy_dir(dir: &Path, image: Option<&str>) -> Result<Inputs, String> {
    let mut files: Vec<String> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .filter(|e| e.path().is_file() || e.path().is_symlink())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    let re = |r: &str| Regex::new(r).expect("valid");
    let (stamp, suffix) = (re(r"-\d{14}"), re(r"(\.rootfs)?\.manifest$"));
    let mut images: Vec<String> = files
        .iter()
        .filter(|f| f.ends_with(".manifest") && !f.contains(".spdx") && !f.contains(".sdk"))
        .map(|f| {
            let name = suffix.replace(f, "");
            re(r"-\d{14}$").replace(&name, "").into_owned()
        })
        .collect();
    dedup(&mut images);
    let image = match image {
        Some(i) => Some(i.to_owned()),
        None if images.len() > 1 => {
            return Err(format!(
                "Several images in {}: {}. Pick one with --image.",
                dir.display(),
                images.join(", ")
            ))
        }
        None => images.into_iter().next(),
    };
    let ours = |f: &str| image.as_deref().is_none_or(|i| f.starts_with(i));
    // The stable symlink name (no timestamp) first.
    let pick = |pattern: &str| {
        let r = re(pattern);
        let mut c: Vec<&String> = files.iter().filter(|f| r.is_match(f) && ours(f)).collect();
        c.sort_by_key(|f| stamp.is_match(f));
        c.first().map(|f| dir.join(f))
    };
    let (sbom, rootfs_of_other) = (
        re(r"(?i)(\.cdx\.json|cyclonedx.*\.json|\.bom\.json)$"),
        re(r"^[\w.-]+-\w+\.rootfs"),
    );
    Ok(Inputs {
        manifest: pick(r"\.manifest$"),
        testdata: pick(r"\.testdata\.json$"),
        // (the fastest to decompress first: the scan reads it twice)
        rootfs: ["zst", "gz", "", "xz", "bz2"].iter().find_map(|z| {
            pick(&format!(
                r"\.tar{}{z}$",
                if z.is_empty() { "" } else { r"\." }
            ))
        }),
        sboms: files
            .iter()
            .filter(|f| sbom.is_match(f) && (ours(f) || !rootfs_of_other.is_match(f)))
            .map(|f| dir.join(f))
            .collect(),
        image,
        ..Default::default()
    })
}

#[cfg(test)]
#[path = "../../../tests/unit/cli/yocto/deploy.rs"]
mod tests;
