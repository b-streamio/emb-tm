//! The command line on the Yocto fixture and the system example.

use std::{path::PathBuf, process::Command};

use serde_json::Value;

const DEPLOY: &str = "examples/yocto-scan/deploy";
const SYSTEM: &str = "examples/system/connected-vision-system.project.json";

/// A fresh scratch directory for one test.
fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("emb3d-wb-test-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Runs `emb3d-wb args…`; returns `(exit code, stdout)`.
fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_emb3d-wb"))
        .args(args)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.is_empty() || !out.status.success(), "{stderr}");
    (
        out.status.code().unwrap(),
        String::from_utf8(out.stdout).unwrap() + &stderr,
    )
}

fn json(path: &PathBuf) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn nodes(p: &Value) -> Vec<&Value> {
    p["pages"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|pg| pg["nodes"].as_array().unwrap())
        .collect()
}

/// The first node of `kind` whose name contains `name`.
fn node<'a>(p: &'a Value, kind: &str, name: &str) -> Option<&'a Value> {
    nodes(p)
        .into_iter()
        .find(|n| n["type"] == kind && n["name"].as_str().unwrap().contains(name))
}

fn evidence_has(n: &Value, key: &str, text: &str) -> bool {
    n["evidence"][key]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["text"].as_str().unwrap().contains(text))
}

#[test]
fn full_deploy_dir_scan() {
    let d = tmp("full");
    let (out, tmbom) = (d.join("p.json"), d.join("t.json"));
    let kconfig = format!("{DEPLOY}/config-raspberrypi4-64");
    let (code, text) = run(&[
        "scan",
        "--deploy",
        DEPLOY,
        "--kernel-config",
        &kconfig,
        "-o",
        out.to_str().unwrap(),
        "--tmbom",
        tmbom.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{text}");
    let p = json(&out);
    assert_eq!(p["name"], "core-image-gateway (raspberrypi4-64)");
    let boot = node(&p, "bootloader", "").unwrap();
    assert_eq!(
        (boot["name"].as_str(), boot["answers"]["verify"].as_str()),
        (Some("U-Boot 2024.01"), Some("signature"))
    );
    assert!(
        evidence_has(boot, "_component", "CVE-2024-57256"),
        "u-boot SBOM CVE in evidence"
    );
    let update = node(&p, "update", "").unwrap();
    assert_eq!(
        (
            &update["answers"]["integrity"],
            &update["answers"]["remote"]
        ),
        (&"signature".into(), &true.into())
    );
    let ssh = node(&p, "ui", "SSH").unwrap();
    assert_eq!(ssh["answers"]["auth"], "crypto");
    assert_eq!(
        ssh["evidence"]["auth"][0],
        serde_json::json!({"file": "rootfs:/etc/ssh/sshd_config", "line": 3, "text": "PasswordAuthentication no"})
    );
    let mq = node(&p, "netsvc", "Mosquitto").unwrap();
    assert_eq!(
        (&mq["answers"]["no_enc"], &mq["answers"]["no_auth"]),
        (&false.into(), &false.into())
    );
    let sshd = node(&p, "netsvc", "OpenSSH").unwrap();
    assert!(
        evidence_has(sshd, "_component", "1 open of 2 CVEs"),
        "VEX not_affected is not counted as open"
    );
    assert!(evidence_has(sshd, "_component", "CVE-2024-6387"));
    assert_eq!(node(&p, "os", "").unwrap()["answers"]["modules"], true);
    assert!(node(&p, "rot", "").is_none(), "no TPM in this image");
    assert_eq!(p["pages"][0]["flows"].as_array().unwrap().len(), 3);
    let tm = json(&tmbom);
    assert!(
        tm["threats"].as_array().unwrap().len() > 50
            && tm["controls"].as_array().unwrap().len() > 100
    );
    let back = &tm["extensions"]["emb3d-workbench.invalid/project"]["project"];
    assert_eq!(
        nodes(back).len(),
        nodes(&p).len(),
        "project embedded for re-import"
    );

    // analyze accepts its own TM-BOM back
    let sum = d.join("s.json");
    let (code, text) = run(&[
        "analyze",
        tmbom.to_str().unwrap(),
        "--summary",
        sum.to_str().unwrap(),
    ]);
    assert!(code == 0 && text.contains("core-image-gateway"), "{text}");
    assert!(json(&sum)["threats"].as_u64().unwrap() > 50);
    assert_eq!(
        run(&["analyze", tmbom.to_str().unwrap(), "--fail-on-open", "0"]).0,
        2,
        "CI gate"
    );

    // old single-page projects still open
    let legacy = d.join("legacy.json");
    let old = serde_json::json!({"name": p["name"], "nodes": p["pages"][0]["nodes"], "flows": p["pages"][0]["flows"]});
    std::fs::write(&legacy, old.to_string()).unwrap();
    let migrated = d.join("m.json");
    let (code, _) = run(&[
        "analyze",
        legacy.to_str().unwrap(),
        "--project",
        migrated.to_str().unwrap(),
    ]);
    let m = json(&migrated);
    assert_eq!((code, m["pages"].as_array().unwrap().len()), (0, 1));
    assert_eq!(m["root"], m["pages"][0]["id"]);
}

#[test]
fn sbom_only_flags_missing_inputs_for_review() {
    let d = tmp("sbom");
    let out = d.join("p.json");
    let sbom = format!("{DEPLOY}/core-image-gateway-raspberrypi4-64.rootfs.cdx.json");
    assert_eq!(
        run(&["scan", "--sbom", &sbom, "-o", out.to_str().unwrap()]).0,
        0
    );
    let p = json(&out);
    assert!(node(&p, "soc", "").is_none(), "no MACHINE, no SoC node");
    let login = node(&p, "ui", "SSH").unwrap();
    assert_eq!(login["answers"]["auth"], "password");
    assert!(
        login["review"]["auth"]
            .as_str()
            .unwrap()
            .contains("not checked, needs")
            && login["review"]["auth"].as_str().unwrap().contains("rootfs")
    );
    let update = node(&p, "update", "").unwrap();
    assert_eq!(update["answers"]["integrity"], "signature");
    assert!(update["review"]["integrity"]
        .as_str()
        .unwrap()
        .contains("not checked, needs rootfs"));
}

#[test]
fn bitbake_e_overrides_testdata() {
    let d = tmp("bbenv");
    let out = d.join("p.json");
    let bb = "examples/yocto-scan/bitbake-e.sample.txt";
    assert_eq!(
        run(&[
            "scan",
            "--deploy",
            DEPLOY,
            "--bbenv",
            bb,
            "-o",
            out.to_str().unwrap()
        ])
        .0,
        0
    );
    let p = json(&out);
    assert_eq!(
        node(&p, "ui", "SSH").unwrap()["answers"]["auth"],
        "none",
        "debug-tweaks means no root password"
    );
    assert_eq!(
        node(&p, "debug", "").unwrap()["evidence"]["sw_debug"][0],
        serde_json::json!({"file": "/work/build/conf/local.conf", "line": 40, "text": "IMAGE_FEATURES = \"ssh-server-openssh debug-tweaks\""})
    );
}

#[test]
fn system_example_analysis_and_report() {
    let d = tmp("system");
    let (sum, report) = (d.join("s.json"), d.join("r.html"));
    let (code, text) = run(&[
        "analyze",
        SYSTEM,
        "--summary",
        sum.to_str().unwrap(),
        "--report",
        report.to_str().unwrap(),
        "--list",
    ]);
    assert_eq!(code, 0, "{text}");
    let s = json(&sum);
    assert_eq!(
        (
            s["threats"].as_u64(),
            s["devices"].as_u64(),
            s["emb3d"].as_str()
        ),
        (Some(179), Some(4), Some("2.0.1"))
    );
    assert!(text.contains("devices 4, pages 5") && text.contains(" > ") && text.contains("[via "));
    let html = std::fs::read_to_string(&report).unwrap();
    assert!(html.starts_with("<!doctype html>") && html.contains("class=\"report\""));
    assert!(
        !html.contains("https://"),
        "a standalone report loads nothing from the network"
    );
    assert_eq!(run(&["analyze", SYSTEM, "--emb3d", "9.9"]).0, 1);
}

#[test]
fn validate_library_versions_and_usage() {
    let (code, text) = run(&["validate", SYSTEM]);
    assert!(code == 0 && text.contains("0 errors"), "{text}");
    let (_, text) = run(&["library"]);
    assert!(text.contains("## Hardware") && text.contains("container: fields page, qty"));
    let (_, text) = run(&["library", "--json"]);
    assert!(serde_json::from_str::<Value>(&text).unwrap()["components"].is_array());
    assert!(run(&["versions"]).1.contains("2.0.1  (default)"));
    assert_eq!(run(&[]).0, 0);
    assert_eq!(run(&["nope"]).0, 1);
    let (code, text) = run(&["--version"]);
    assert_eq!((code, text.trim()), (0, concat!("emb3d-wb ", env!("CARGO_PKG_VERSION"))));
    let (code, text) = run(&["scan", "-o", "x.json"]);
    assert!(code == 1 && text.contains("No inputs found"));
    let (code, text) = run(&["validate", "Cargo.toml"]);
    assert!(code == 1 && text.contains("Cargo.toml"));
}

#[test]
fn app_needs_the_embedded_build() {
    // `cargo test` builds without the `pwa` feature.
    let (code, out) = run(&["app", "--no-open"]);
    assert_eq!(code, 1);
    assert!(out.contains("does not include the browser app"), "{out}");
    let (code, out) = run(&["app", "--port", "x"]);
    assert_eq!(code, 1);
    assert!(out.contains("not a port number"), "{out}");
}
