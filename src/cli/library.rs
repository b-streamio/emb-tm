// SPDX-License-Identifier: GPL-2.0-only
//! `library` and `versions`: what a project can use.

use super::{index, load_library, plain, pretty, read_json, root, Args};

pub(super) fn library(a: &Args) -> Result<i32, String> {
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

pub(super) fn versions() -> Result<i32, String> {
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
