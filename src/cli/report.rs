// SPDX-License-Identifier: GPL-2.0-only
//! The standalone HTML report, and printing it to PDF with a local Chrome.

use std::{
    fs,
    process::{Command, Stdio},
};

use super::{read, root, today, Args};
use crate::{
    engine::{esc, Model, ReportOpts},
    model::Project,
};

/// A report that opens anywhere: the app's report styles inlined, no web fonts.
pub(super) fn standalone_html(p: &Project, m: &Model, o: ReportOpts) -> Result<String, String> {
    let css = read(&root().join("web/style.css"))?;
    let block = css
        .split_once("/* report-css:begin")
        .and_then(|(_, rest)| rest.split_once("*/"))
        .and_then(|(_, rest)| rest.split_once("/* report-css:end */"))
        .map(|(block, _)| block)
        .ok_or("web/style.css: report-css markers not found")?;
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
pub(super) fn find_chrome() -> Option<String> {
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

pub(super) fn print_pdf(html: &str, a: &Args, pdf: &str) -> Result<(), String> {
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
