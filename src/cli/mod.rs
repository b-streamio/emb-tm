//! The command line: the browser app's engine, from a terminal or CI.

mod app;
mod yocto;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Value};

use crate::{
    engine::{around, esc, Model, ReportOpts, Summary},
    model::{Library, Project},
    stix::{self, Emb3d},
};

pub use yocto::{from_deploy_dir, parse_bbenv, scan, Inputs};

const USAGE: &str = "\
EMB3D Workbench command line. Same engine as the browser app.

  emb3d-wb --version                        the version of this program
  emb3d-wb app [--port <n>] [--no-open]     open the browser app in its own window; it runs on this
                                            computer only (http://127.0.0.1, default port 8000)
  emb3d-wb library [--json]                 component types and their questions (what a project can answer)
  emb3d-wb versions                         EMB3D versions available in data/stix
  emb3d-wb validate <project.json>          check a project; exit 1 on errors
  emb3d-wb scan [inputs] -o <project.json> [analyze options]
                         first model of a Yocto image, from its build outputs and CycloneDX SBOMs
      --deploy <dir>         deploy dir (tmp/deploy/images/<machine>): finds manifest, testdata.json, rootfs, SBOMs
      --image <name>         which image in the deploy dir, when there are several
      --testdata <file>      <image>.testdata.json            --bbenv <file>     `bitbake -e <image>` output
      --manifest <file>      <image>.manifest                 --rootfs <tar|dir> image rootfs
      --sbom <file>          CycloneDX JSON, repeatable       --kernel-config <file>  --uboot-config <file>
      --rules <file>         scanner rules (default library/yocto-rules.json)
  emb3d-wb analyze  <project.json> [options]
      --emb3d <ver>          EMB3D version (default: the project's, else data/stix default)
      --tmbom <file>         write the TM-BOM (OWASP Threat Model Library schema v1.0.2)
      --report <file.html>   write a standalone HTML report
      --pdf <file.pdf>       also print the report to PDF with a local Chrome/Chromium
      --summary <file.json>  write counts as JSON
      --project <file>       write the normalised project (positions filled in) for the browser app
      --list                 print every threat per component
      --fulltext             full MITRE threat descriptions in the report
      --fail-on-open <n>     exit 2 when more than n threats are open (CI gate)

Data (library/, data/stix/, style.css) is read from $EMB3D_WB_ROOT, by default the source tree.
";

/// Positional arguments and `--key [value]` options (repeatable; `-o` is `--o`).
#[derive(Debug, Default)]
struct Args {
    pos: Vec<String>,
    opts: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse(argv: Vec<String>) -> Self {
        let mut a = Self::default();
        let mut it = argv.into_iter().peekable();
        while let Some(x) = it.next() {
            let key = if x == "-o" {
                Some("o")
            } else {
                x.strip_prefix("--")
            };
            match key {
                Some(k) => {
                    let v = it.next_if(|v| !v.starts_with("--"));
                    a.opts.push((k.to_owned(), v));
                }
                None => a.pos.push(x),
            }
        }
        a
    }

    fn has(&self, k: &str) -> bool {
        self.opts.iter().any(|(o, _)| o == k)
    }

    /// Last value of `--k`.
    fn get(&self, k: &str) -> Option<&str> {
        self.all(k).last().copied()
    }

    fn all(&self, k: &str) -> Vec<&str> {
        self.opts
            .iter()
            .filter(|(o, _)| o == k)
            .filter_map(|(_, v)| v.as_deref())
            .collect()
    }
}

/// Runs a command; returns the exit code.
pub fn main(argv: Vec<String>) -> i32 {
    let a = Args::parse(argv);
    if a.has("version") {
        println!("emb3d-wb {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    let res = match a.pos.first().map(String::as_str) {
        Some("library") => library(&a),
        Some("versions") => versions(),
        Some("validate") => validate(&a),
        Some("analyze") => analyze(&a),
        Some("scan") => scan_cmd(&a),
        Some("app") => {
            let port = match a.get("port") {
                Some(p) => p
                    .parse()
                    .map_err(|_| format!("--port {p}: not a port number")),
                None => Ok(app::PORT),
            };
            let open = !a.has("no-open");
            port.and_then(|p| app::run(p, open, find_chrome().filter(|_| open)))
        }
        cmd => {
            print!("{USAGE}");
            return i32::from(cmd.is_some());
        }
    };
    res.unwrap_or_else(|e| {
        eprintln!("{e}");
        1
    })
}

fn root() -> PathBuf {
    std::env::var_os("EMB3D_WB_ROOT")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_json(path: &Path) -> Result<Value, String> {
    serde_json::from_str(&read(path)?).map_err(|e| format!("{}: {e}", path.display()))
}

fn write(path: &str, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|e| format!("{path}: {e}"))
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default() + "\n"
}

fn load_library() -> Result<Library, String> {
    serde_json::from_value(read_json(&root().join("library/components.json"))?)
        .map_err(|e| format!("library/components.json: {e}"))
}

fn index() -> Result<Value, String> {
    read_json(&root().join("data/stix/index.json"))
}

fn load_emb3d(version: &str) -> Result<Emb3d, String> {
    let idx = index()?;
    let versions = idx["versions"].as_array().map_or(&[][..], Vec::as_slice);
    let Some(meta) = versions.iter().find(|v| v["version"] == version) else {
        let have: Vec<&str> = versions
            .iter()
            .filter_map(|v| v["version"].as_str())
            .collect();
        return Err(format!("EMB3D {version} is not in data/stix. Available: {}. Add it with tools/emb3d_update.py add {version}", have.join(", ")));
    };
    let file = root()
        .join("data/stix")
        .join(meta["file"].as_str().unwrap_or_default());
    stix::parse(&read_json(&file)?, version)
}

/// Today (UTC) as `YYYY-MM-DD`.
fn today() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    civil(i64::try_from(secs / 86_400).unwrap_or(0))
}

/// Days since 1970-01-01 → `YYYY-MM-DD` (H. Hinnant's `civil_from_days`).
fn civil(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `true`/`false` or a choice value, unquoted.
fn plain(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), str::to_owned)
}

fn library(a: &Args) -> Result<i32, String> {
    if a.has("json") {
        print!(
            "{}",
            pretty(&read_json(&root().join("library/components.json"))?)
        );
        return Ok(0);
    }
    let lib = load_library()?;
    for g in &lib.groups {
        println!("\n## {g}");
        for c in lib.components.iter().filter(|c| &c.group == g) {
            let ext = if c.external { "  external" } else { "" };
            let cont = if c.container {
                "  container: fields page, qty"
            } else {
                ""
            };
            println!("\ntype: {}  ({}){ext}{cont}\n  {}", c.kind, c.name, c.hint);
            for q in &c.questions {
                let default = plain(&q.default);
                if q.kind == "bool" {
                    println!("  - {}: true|false  default {default}  — {}", q.id, q.text);
                    continue;
                }
                let values: Vec<&str> = q.options.iter().map(|o| o.value.as_str()).collect();
                println!(
                    "  - {}: {}  default {default}  — {}",
                    q.id,
                    values.join("|"),
                    q.text
                );
                for o in &q.options {
                    println!("      {}: {}", o.value, o.label);
                }
            }
        }
    }
    Ok(0)
}

fn versions() -> Result<i32, String> {
    let idx = index()?;
    for v in idx["versions"].as_array().into_iter().flatten() {
        let default = if v["version"] == idx["default"] {
            "  (default)"
        } else {
            ""
        };
        println!(
            "{}{default}  {}  added {}",
            plain(&v["version"]),
            plain(&v["file"]),
            plain(&v["added"])
        );
    }
    Ok(0)
}

fn load_project(file: &str) -> Result<Project, String> {
    let v = read_json(Path::new(file))?;
    let mut p = Project::from_json(v).map_err(|e| format!("{file}: {e}"))?;
    p.migrate();
    Ok(p)
}

/// The EMB3D release of `--emb3d`, else the project's, else the default; recorded in `p`.
fn release_for(p: &mut Project, a: &Args) -> Result<Emb3d, String> {
    let version = match a
        .get("emb3d")
        .map(str::to_owned)
        .or_else(|| p.emb3d.clone())
    {
        Some(v) => v,
        None => plain(&index()?["default"]),
    };
    p.emb3d = Some(version.clone());
    load_emb3d(&version)
}

fn validate(a: &Args) -> Result<i32, String> {
    let file = a
        .pos
        .get(1)
        .ok_or("usage: emb3d-wb validate <project.json>")?;
    let mut p = load_project(file)?;
    let (e, lib) = (release_for(&mut p, a)?, load_library()?);
    let m = Model::new(&e, &lib, &p);
    let (errors, warnings) = m.validate(&p);
    for w in &warnings {
        println!("warning: {w}");
    }
    for e in &errors {
        println!("error:   {e}");
    }
    m.normalize(&mut p);
    let review = m.review_items(&p);
    for r in &review {
        println!(
            "review:  {}: {}{}",
            r.node.name,
            r.question,
            around(" — ", &r.reason, "")
        );
    }
    println!(
        "{} errors, {} warnings, {} answers to review",
        errors.len(),
        warnings.len(),
        review.len()
    );
    Ok(i32::from(!errors.is_empty()))
}

fn analyze(a: &Args) -> Result<i32, String> {
    let file = a.pos.get(1).ok_or("usage: emb3d-wb analyze <project.json> [--tmbom f] [--report f.html] [--pdf f.pdf] [--summary f.json]")?;
    let mut p = load_project(file)?;
    let (e, lib) = (release_for(&mut p, a)?, load_library()?);
    let m = Model::new(&e, &lib, &p);
    let (errors, _) = m.validate(&p);
    if !errors.is_empty() {
        return Err(format!(
            "Project has errors; run \"emb3d-wb validate\":\n{}",
            errors.join("\n")
        ));
    }
    m.normalize(&mut p);
    outputs(&p, &m, a)
}

fn scan_cmd(a: &Args) -> Result<i32, String> {
    let out = a.get("o").or_else(|| a.get("out")).ok_or(
        "usage: emb3d-wb scan --deploy <dir> [--sbom f ...] -o project.json [--tmbom f] [--report f.html]",
    )?;
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

/// `--summary`: the counts, with the key names of the original Node CLI.
fn summary_json(s: &Summary, version: &str) -> Value {
    let e = s.open_by_evidence;
    json!({
        "emb3d": version, "pages": s.pages, "devices": s.devices, "components": s.components, "flows": s.flows,
        "threats": s.threats, "open": s.open, "mitigated": s.mitigated, "notApplicable": s.not_applicable, "accepted": s.accepted,
        "openByEvidence": {"observedInAttacks": e[0], "observedTechnique": e[1], "knownWeakness": e[2], "proofOfConcept": e[3], "custom": e[4]},
        "countermeasures": s.countermeasures, "implemented": s.implemented,
        "missingJustifications": s.missing_justifications, "needsReview": s.needs_review,
    })
}

/// A report that opens anywhere: the app's report styles inlined, no web fonts.
fn standalone_html(p: &Project, m: &Model, o: ReportOpts) -> Result<String, String> {
    let css = read(&root().join("style.css"))?;
    let block = css
        .split_once("/* report-css:begin")
        .and_then(|(_, rest)| rest.split_once("*/"))
        .and_then(|(_, rest)| rest.split_once("/* report-css:end */"))
        .map(|(block, _)| block)
        .ok_or("style.css: report-css markers not found")?;
    Ok(format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat model - {}</title>
<style>
:root {{ --f-display: "IBM Plex Sans Condensed", "Arial Narrow", system-ui, sans-serif; --f-body: "IBM Plex Sans", system-ui, -apple-system, "Segoe UI", sans-serif;
  --f-mono: "IBM Plex Mono", ui-monospace, Menlo, monospace; --shadow: none; color-scheme: light; }}
html, body {{ margin: 0; background: #fff; color: #1d2320; font-family: var(--f-body); font-size: 14px; line-height: 1.45; }}
body {{ padding: 24px max(16px, env(safe-area-inset-left, 0px)); }}
.small {{ font-size: 12.5px; }} .muted {{ color: #5c6662; }}
{block}</style></head>
<body>{}</body></html>
"#,
        esc(&p.name),
        m.report_html(p, o, &today())
    ))
}

/// A Chrome or Chromium that runs: `$CHROME`, then the usual names.
fn find_chrome() -> Option<String> {
    let env = std::env::var("CHROME").ok();
    let names = [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "/opt/pw-browsers/chromium",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ];
    env.into_iter().chain(names.map(str::to_owned)).find(|bin| {
        Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

fn print_pdf(html: &str, a: &Args, pdf: &str) -> Result<(), String> {
    let chrome = find_chrome().ok_or("No Chrome/Chromium found for --pdf. Set CHROME=/path/to/chrome, or open the HTML report and print it.")?;
    let abs = |f: &str| std::path::absolute(f).map_err(|e| format!("{f}: {e}"));
    let (page, temporary) = match a.get("report") {
        Some(r) => (abs(r)?, false),
        None => {
            let t = std::env::temp_dir().join(format!("emb3d-report-{}.html", std::process::id()));
            fs::write(&t, html).map_err(|e| format!("{}: {e}", t.display()))?;
            (t, true)
        }
    };
    let status = Command::new(&chrome)
        .args([
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--no-pdf-header-footer",
        ])
        .arg(format!("--print-to-pdf={}", abs(pdf)?.display()))
        .arg(format!("file://{}", page.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if temporary {
        let _ = fs::remove_file(&page);
    }
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => Err(format!("{chrome} could not print {pdf}")),
    }
}

/// Writes the requested files and prints the summary; 2 when `--fail-on-open` trips.
fn outputs(p: &Project, m: &Model, a: &Args) -> Result<i32, String> {
    let s = m.summary(p);
    if let Some(f) = a.get("tmbom") {
        write(f, &pretty(&m.to_tmbom(p, &today())))?;
    }
    if let Some(f) = a.get("project") {
        write(f, &pretty(&p.to_json()))?;
    }
    if let Some(f) = a.get("summary") {
        write(f, &pretty(&summary_json(&s, &m.e.version)))?;
    }
    if a.has("report") || a.has("pdf") {
        let o = ReportOpts {
            fulltext: a.has("fulltext"),
            ..Default::default()
        };
        let html = standalone_html(p, m, o)?;
        if let Some(f) = a.get("report") {
            write(f, &html)?;
        }
        if let Some(f) = a.get("pdf") {
            print_pdf(&html, a, f)?;
        }
    }

    let multi = p.pages.len() > 1;
    let ev = s.open_by_evidence;
    println!("{} — MITRE EMB3D {}", p.name, m.e.version);
    let devices = if s.pages > 1 {
        format!("devices {}, pages {}, ", s.devices, s.pages)
    } else {
        String::new()
    };
    println!(
        "  {devices}components {}, data flows {}",
        s.components, s.flows
    );
    println!(
        "  threats {}: open {}, mitigated {}, not applicable {}, accepted {}",
        s.threats, s.open, s.mitigated, s.not_applicable, s.accepted
    );
    println!("  open by evidence: observed in attacks {}, observed technique {}, known weakness {}, proof of concept {}", ev[0], ev[1], ev[2], ev[3]);
    println!(
        "  countermeasures implemented {} of {}",
        s.implemented, s.countermeasures
    );
    if s.missing_justifications > 0 {
        println!(
            "  decisions missing a justification: {}",
            s.missing_justifications
        );
    }
    let page_prefix = |id: u64| match p.page_of(id) {
        Some(pg) if multi => format!("{} > ", pg.name),
        _ => String::new(),
    };
    if s.needs_review > 0 {
        println!("  answers needing review: {}", s.needs_review);
        for r in m.review_items(p) {
            println!(
                "    - {}{}: {}{}",
                page_prefix(r.node.id),
                r.node.name,
                r.question,
                around(" — ", &r.reason, "")
            );
        }
    }
    if a.has("list") {
        for n in p.nodes().filter(|n| m.has_threats(n)) {
            let kind = m.type_of(n).map_or("", |t| t.name.as_str());
            println!("\n{}{} ({kind})", page_prefix(n.id), n.name);
            for h in m.node_threats(p, n) {
                let state = m.threat_state(n, &h.tid).key();
                println!(
                    "  {}  {state:<9} {}  [via {}]",
                    h.tid,
                    h.t.name,
                    h.via.join(", ")
                );
            }
        }
    }
    for k in ["tmbom", "report", "pdf", "summary", "project"] {
        if let Some(f) = a.get(k) {
            println!("wrote {f}");
        }
    }
    let limit = a.get("fail-on-open").and_then(|n| n.parse::<usize>().ok());
    Ok(if limit.is_some_and(|n| s.open > n) {
        2
    } else {
        0
    })
}

#[cfg(test)]
#[path = "../../tests/unit/cli/mod.rs"]
mod tests;
