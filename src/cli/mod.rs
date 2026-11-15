// SPDX-License-Identifier: GPL-2.0-only
//! The command line: the browser app's engine, from a terminal or CI.

mod analyze;
mod app;
mod fetch;
mod library;
mod report;
mod scan;
mod yocto;

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

use crate::{
    model::{Library, Project},
    stix::{self, Emb3d},
};
use analyze::{analyze, validate};
use fetch::{fetch, read_release};
use library::{library, versions};
use report::find_chrome;
use scan::scan_cmd;
pub use yocto::{from_deploy_dir, parse_bbenv, scan, Inputs};

const USAGE: &str = "\
emb-tm command line. Same engine as the browser app.

  emb-tm --version                        the version of this program
  emb-tm app [--port <n>] [--no-open]     open the browser app in its own window; it runs on this
                                            computer only (http://127.0.0.1, default port 8000)
  emb-tm library [--json]                 component types and their questions (what a project can answer)
  emb-tm versions                         EMB3D versions listed in data/stix, and which are downloaded
  emb-tm fetch [<version>]                 download EMB3D releases from emb3d.mitre.org (MITRE's terms of use)
  emb-tm validate <project.json>          check a project; exit 1 on errors
  emb-tm scan [inputs] -o <project.json> [analyze options]
                         first model of a Yocto image, from its build outputs and CycloneDX SBOMs
      --deploy <dir>         deploy dir (tmp/deploy/images/<machine>): finds manifest, testdata.json, rootfs, SBOMs
      --image <name>         which image in the deploy dir, when there are several
      --testdata <file>      <image>.testdata.json            --bbenv <file>     `bitbake -e <image>` output
      --manifest <file>      <image>.manifest                 --rootfs <tar|dir> image rootfs
      --sbom <file>          CycloneDX JSON, repeatable       --kernel-config <file>  --uboot-config <file>
      --rules <file>         scanner rules (default: the built-in ones)
  emb-tm analyze  <project.json> [options]
      --emb3d <ver>          EMB3D version (default: the project's, else data/stix default)
      --tmbom <file>         write the TM-BOM (OWASP Threat Model Library schema v1.0.2)
      --report <file.html>   write a standalone HTML report
      --pdf <file.pdf>       also print the report to PDF with a local Chrome/Chromium
      --summary <file.json>  write counts as JSON
      --project <file>       write the normalised project (positions filled in) for the browser app
      --list                 print every threat per component
      --fulltext             full MITRE threat descriptions in the report
      --fail-on-open <n>     exit 2 when more than n threats are open (CI gate)

The component library, scanner rules and report style are built in. EMB3D releases are downloaded
to $EMB_TM_DATA, by default ~/.local/share/emb-tm/stix.
MITRE EMB3D(TM) data (c) The MITRE Corporation, under its terms of use (data/stix/README.md); this
program is not affiliated with or endorsed by MITRE.
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
        println!("emb-tm {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    let res = match a.pos.first().map(String::as_str) {
        Some("library") => library(&a),
        Some("versions") => versions(),
        Some("fetch") => fetch(&a),
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

/// Built into the program, so that it runs on its own.
const COMPONENTS: &str = include_str!("../../library/components.json");
const RULES: &str = include_str!("../../library/yocto-rules.json");
const INDEX: &str = include_str!("../../data/stix/index.json");
const STYLE: &str = include_str!("../../web/style.css");

fn built_in(name: &str, text: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|e| format!("{name}: {e}"))
}

/// Where `fetch` keeps the EMB3D releases: $EMB_TM_DATA, else
/// $XDG_DATA_HOME/emb-tm/stix, else ~/.local/share/emb-tm/stix.
fn stix_dir() -> PathBuf {
    let var = |k| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    var("EMB_TM_DATA").unwrap_or_else(|| {
        var("XDG_DATA_HOME")
            .or_else(|| var("HOME").map(|h| h.join(".local/share")))
            .unwrap_or_default()
            .join("emb-tm/stix")
    })
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
    serde_json::from_value(built_in("library/components.json", COMPONENTS)?)
        .map_err(|e| format!("library/components.json: {e}"))
}

fn index() -> Result<Value, String> {
    built_in("data/stix/index.json", INDEX)
}

fn load_emb3d(version: &str) -> Result<Emb3d, String> {
    let idx = index()?;
    let versions = idx["versions"].as_array().map_or(&[][..], Vec::as_slice);
    let Some(meta) = versions.iter().find(|v| v["version"] == version) else {
        let have: Vec<&str> = versions
            .iter()
            .filter_map(|v| v["version"].as_str())
            .collect();
        return Err(format!(
            "EMB3D {version} is not listed in data/stix. Listed: {}.",
            have.join(", ")
        ));
    };
    let bundle = serde_json::from_slice(&read_release(meta)?)
        .map_err(|e| format!("EMB3D {version}: {e}"))?;
    stix::parse(&bundle, version)
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

#[cfg(test)]
#[path = "../../tests/unit/cli/mod.rs"]
mod tests;
