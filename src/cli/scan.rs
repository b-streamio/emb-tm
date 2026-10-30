// SPDX-License-Identifier: GPL-2.0-only
//! `scan`: a first project from a Yocto image's build outputs.

use std::path::Path;

use super::{
    analyze::outputs,
    load_library, pretty, read_json, release_for, root, today, write,
    yocto::{from_deploy_dir, scan, Inputs},
    Args,
};
use crate::engine::Model;

pub(super) fn scan_cmd(a: &Args) -> Result<i32, String> {
    let out = a.get("o").or_else(|| a.get("out")).ok_or(
        "usage: emb3d-wb scan --deploy <dir> [--sbom f ...] -o project.json [--tmbom f] [--report f.html]",
    )?;
    let inputs = inputs(a)?;
    let rules = match a.get("rules") {
        Some(f) => read_json(Path::new(f))?,
        None => read_json(&root().join("library/yocto-rules.json"))?,
    };
    let lib = load_library()?;
    let (mut p, notes) = scan(&inputs, &rules, &lib, &today()).map_err(|e| format!("scan: {e}"))?;
    p.migrate();
    let e = release_for(&mut p, a)?;
    let m = Model::new(&e, &lib, &p);
    let (errors, _) = m.validate(&p);
    if !errors.is_empty() {
        return Err(format!(
            "Scanner produced an invalid project (check the rules file):\n{}",
            errors.join("\n")
        ));
    }
    m.normalize(&mut p);
    write(out, &pretty(&p.to_json()))?;
    println!(
        "Scanned {}: {} variables, {} packages, {} SBOMs ({} open vulnerabilities)",
        inputs.image.as_deref().unwrap_or(&p.name),
        notes.variables,
        notes.packages,
        notes.sboms.len(),
        notes.cve_open
    );
    println!("  inputs: {}", notes.used.join(", "));
    for s in &notes.skipped {
        println!("  {s}");
    }
    println!("wrote {out}");
    outputs(&p, &m, a)
}

/// The deploy directory's inputs, overridden by the single-file options.
fn inputs(a: &Args) -> Result<Inputs, String> {
    let mut inputs = match a.get("deploy") {
        Some(dir) => from_deploy_dir(Path::new(dir), a.get("image"))?,
        None => Inputs::default(),
    };
    for (flag, slot) in [
        ("testdata", &mut inputs.testdata),
        ("bbenv", &mut inputs.bbenv),
        ("manifest", &mut inputs.manifest),
        ("rootfs", &mut inputs.rootfs),
        ("kernel-config", &mut inputs.kernel_config),
        ("uboot-config", &mut inputs.uboot_config),
    ] {
        if let Some(v) = a.get(flag) {
            *slot = Some(v.into());
        }
    }
    if let Some(i) = a.get("image") {
        inputs.image = Some(i.into());
    }
    for s in a.all("sbom") {
        if !inputs.sboms.iter().any(|x| x == Path::new(s)) {
            inputs.sboms.push(s.into());
        }
    }
    if inputs.testdata.is_none()
        && inputs.bbenv.is_none()
        && inputs.manifest.is_none()
        && inputs.sboms.is_empty()
        && inputs.rootfs.is_none()
    {
        return Err(
            "No inputs found. Give --deploy, or --testdata/--bbenv, --manifest, --sbom, --rootfs."
                .into(),
        );
    }
    Ok(inputs)
}
