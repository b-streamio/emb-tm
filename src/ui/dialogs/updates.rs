// SPDX-License-Identifier: GPL-2.0-only
//! Switching the project's EMB3D release, and checking emb3d.mitre.org for a
//! newer one.

use std::{collections::BTreeSet, sync::Arc};

use leptos::prelude::*;

use super::{frame, Dialog, MITRE};
use crate::{
    engine::Model,
    model::{num_cmp, Library, Project},
    stix::{self, Emb3d},
    ui::{version_key, web, Ctx, Release},
};

#[derive(Clone)]
pub enum Updates {
    Checking,
    Failed(String),
    Current(Vec<String>),
    Available {
        found: Vec<String>,
        have: Vec<String>,
    },
}

/// Asks to switch the project to EMB3D release `v`, showing what changes.
pub fn propose_version(ctx: Ctx, v: String) {
    if v == ctx.emb3d.get_untracked().version {
        return;
    }
    leptos::task::spawn_local(async move {
        match ctx.release(&v).await {
            Ok(next) => ctx.show(Dialog::Version(next)),
            Err(e) => {
                ctx.emb3d.notify();
                ctx.show(Dialog::Info {
                    title: "Could not load that version".into(),
                    text: e,
                });
            }
        }
    });
}

pub(super) fn version_panel(ctx: Ctx, next: Arc<Emb3d>) -> AnyView {
    let (cur, lib) = (ctx.emb3d.get_untracked(), ctx.lib.get_untracked());
    let d = stix::diff(&cur, &next);
    let v = next.version.clone();
    let label = format!("Use EMB3D {v}");
    let rows = ctx.project.with_untracked(|p| {
        changed_threats(p, &Model::new(&cur, &lib, p), &Model::new(&next, &lib, p))
    });
    let renamed: Vec<String> = d
        .threats_renamed
        .iter()
        .map(|t| format!("{t} {} → {}", cur.threats[t].name, next.threats[t].name))
        .chain(d.mitigations_renamed.iter().map(|x| {
            format!(
                "{x} {} → {}",
                cur.mitigations[x].name, next.mitigations[x].name
            )
        }))
        .collect();
    let missing = missing_pids(&lib, &next);
    let table = if rows.is_empty() {
        view! { <p class="small">"No threats are added or removed for this model."</p> }.into_any()
    } else {
        view! { <table class="mini"><thead><tr><th>"Component"</th><th>"Threats added"</th><th>"Threats removed"</th></tr></thead><tbody>
            {rows.into_iter().map(|(n, a, r)| view! { <tr><td>{n}</td><td>{lines(a)}</td><td>{lines(r)}</td></tr> }).collect_view()}
        </tbody></table> }.into_any()
    };
    let content = view! {
        <div class="dhead"><span class="eyebrow" style="margin:0">"Switch EMB3D version"</span></div>
        <h3>{format!("EMB3D {} → {v}", cur.version)}</h3>
        <p>"Countermeasure statuses, decisions and justifications are kept: they are stored by threat and mitigation ID."</p>
        <div><p class="eyebrow">"Your components"</p>{table}</div>
        {(!renamed.is_empty()).then(|| view! { <div><p class="eyebrow">{format!("Renamed in {v}")}</p><p class="small">{lines(renamed)}</p></div> })}
        <div><p class="eyebrow">"Catalogue changes"</p><p class="small">
            {format!("Threats: {} added, {} removed, {} with changed properties or mitigations.", d.threats_added.len(), d.threats_removed.len(), d.threats_remapped.len())}<br />
            {format!("Mitigations: {} added, {} removed.", d.mitigations_added.len(), d.mitigations_removed.len())}</p></div>
        {(!missing.is_empty()).then(|| view! { <p class="warn">{format!("The component library uses properties that {v} does not define: {}. Those answers will add nothing.", missing.join(", "))}</p> })}
    };
    let use_it = Callback::new(move |()| {
        let next = next.clone();
        let v = next.version.clone();
        ctx.emb3d.set(next);
        ctx.edit(|p, _| p.emb3d = Some(v));
        ctx.dialog.set(None);
    });
    frame(content, Some((label, use_it)), false)
}

/// Components whose threats differ between `a` and `b`: `(name, added, removed)`.
fn changed_threats(p: &Project, a: &Model, b: &Model) -> Vec<(String, Vec<String>, Vec<String>)> {
    let multi = p.pages.len() > 1;
    let names = |ids: Vec<&String>, m: &Model| {
        ids.into_iter()
            .map(|t| {
                format!(
                    "{t} {}",
                    m.threat(t).map(|x| x.name.as_str()).unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
    };
    p.nodes()
        .filter(|n| a.has_threats(n))
        .filter_map(|n| {
            let before: BTreeSet<String> =
                a.node_threats(p, n).into_iter().map(|h| h.tid).collect();
            let after: BTreeSet<String> = b.node_threats(p, n).into_iter().map(|h| h.tid).collect();
            let (add, rem) = (
                names(after.difference(&before).collect(), b),
                names(before.difference(&after).collect(), a),
            );
            let page = if multi {
                format!(
                    "{} › ",
                    p.page_of(n.id).map(|x| x.name.as_str()).unwrap_or_default()
                )
            } else {
                String::new()
            };
            (!add.is_empty() || !rem.is_empty()).then(|| (format!("{page}{}", n.name), add, rem))
        })
        .collect()
}

/// Properties the library uses that release `next` does not define.
fn missing_pids(lib: &Library, next: &Emb3d) -> Vec<String> {
    let mut missing: Vec<String> = lib
        .components
        .iter()
        .flat_map(|c| {
            c.base.iter().chain(
                c.questions
                    .iter()
                    .flat_map(|q| q.pids.iter().chain(q.options.iter().flat_map(|o| &o.pids))),
            )
        })
        .filter(|pid| !next.properties.contains_key(*pid))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    missing.sort_by(|a, b| num_cmp(a, b));
    missing
}

/// One line per item, or a dash.
fn lines(l: Vec<String>) -> AnyView {
    if l.is_empty() {
        "—".into_any()
    } else {
        l.into_iter()
            .map(|x| view! { {x}<br /> })
            .collect_view()
            .into_any()
    }
}

/// Releases linked from MITRE's data page, newest first.
pub fn releases_on_page(html: &str) -> Vec<String> {
    let mut found: Vec<String> = html
        .split("emb3d-stix-")
        .skip(1)
        .filter_map(|s| {
            let v = s.split(".json").next()?;
            (!v.is_empty()
                && v.split('.')
                    .all(|x| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit())))
            .then(|| v.to_owned())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    found.sort_by_key(|v| std::cmp::Reverse(version_key(v)));
    found
}

pub fn check_updates(ctx: Ctx) {
    ctx.show(Dialog::Updates(Updates::Checking));
    leptos::task::spawn_local(async move {
        let state = match web::fetch_text(&format!("{MITRE}/subtabs/data.html")).await {
            Err(e) => Updates::Failed(e),
            Ok(html) => {
                let found = releases_on_page(&html);
                let mut have: Vec<String> = ctx
                    .index
                    .with_untracked(|i| i.versions.iter().map(|r| r.version.clone()).collect());
                have.sort_by_key(|v| std::cmp::Reverse(version_key(v)));
                if found.is_empty() {
                    Updates::Failed("no STIX links on the data page".into())
                } else if found.iter().all(|v| have.contains(v)) {
                    Updates::Current(found)
                } else {
                    Updates::Available { found, have }
                }
            }
        };
        if matches!(ctx.dialog.get_untracked(), Some(Dialog::Updates(_))) {
            ctx.show(Dialog::Updates(state));
        }
    });
}

pub(super) fn updates_panel(ctx: Ctx, u: Updates) -> AnyView {
    let (content, action) = match u {
        Updates::Checking => (
            view! { <p class="muted">"Checking emb3d.mitre.org…"</p> }.into_any(),
            None,
        ),
        Updates::Failed(e) => (
            view! {
                <h3>"Could not reach emb3d.mitre.org"</h3>
                <p>{format!("The browser could not read MITRE's data page ({e}). This happens offline and when MITRE's site does not allow it.")}</p>
            }.into_any(),
            None,
        ),
        Updates::Current(found) => (
            view! {
                <h3>"EMB3D is up to date"</h3><p>{format!("emb3d.mitre.org lists {}. All of them are available here.", found.join(", "))}</p>
            }.into_any(),
            None,
        ),
        Updates::Available { found, have } => {
            let v = found
                .iter()
                .find(|v| !have.contains(v))
                .cloned()
                .unwrap_or_default();
            let label = format!("Try {v} now");
            let content = view! {
                <h3>{format!("EMB3D STIX {v} is available")}</h3>
                <p>{format!("emb3d.mitre.org lists {}. This copy of emb-tm has {}.", found.join(", "), have.join(", "))}</p>
                <p>"Try it now: the release is downloaded into this browser session only."</p>
            };
            let try_it = Callback::new(move |()| try_release(ctx, v.clone()));
            (content.into_any(), Some((label, try_it)))
        }
    };
    frame(content, action, false)
}

/// Downloads release `v` into this browser session and offers to switch to it.
fn try_release(ctx: Ctx, v: String) {
    leptos::task::spawn_local(async move {
        let url = format!("{MITRE}/assets/emb3d-stix-{v}.json");
        let res = web::fetch_json(&url)
            .await
            .and_then(|b| stix::parse(&b, &v).map(|_| b));
        match res {
            Ok(bundle) => {
                let file = format!("emb3d-stix-{v}.json");
                ctx.index.update(|i| {
                    i.versions.push(Release {
                        version: v.clone(),
                        file,
                        source: url,
                        sha256: String::new(),
                        session: Some(Arc::new(bundle)),
                    })
                });
                propose_version(ctx, v);
            }
            Err(e) => ctx.show(Dialog::Info {
                title: "Download failed".into(),
                text: e,
            }),
        }
    });
}

#[cfg(test)]
#[path = "../../../tests/unit/ui/dialogs/updates.rs"]
mod tests;
