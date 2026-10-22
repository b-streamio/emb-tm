//! Dialogs: templates for New, the EMB3D reader, information panels,
//! switching EMB3D release, checking for a new release and the custom block
//! editor.

use std::{collections::BTreeSet, sync::Arc};

use leptos::prelude::*;

use super::{ctx, example, examples, version_key, web, Ctx, Example, Release};
use crate::{
    engine::{maturity, Model},
    model::{num_cmp, CustomCm, CustomThreat, CustomType, Project},
    ops,
    stix::{self, Emb3d},
};

const MITRE: &str = "https://emb3d.mitre.org";

#[derive(Clone)]
pub enum Dialog {
    /// New: the examples to start from (an empty project is always offered).
    Templates(Vec<Example>),
    Info {
        title: String,
        text: String,
    },
    /// Reader history: threat and mitigation ids, last shown.
    Detail(Vec<String>),
    Custom {
        existing: Option<String>,
        copy_of: Option<CustomType>,
    },
    Version(Arc<Emb3d>),
    Updates(Updates),
}

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

#[component]
pub fn Host() -> impl IntoView {
    let ctx = ctx();
    let close = move || ctx.dialog.set(None);
    move || {
        ctx.dialog.get().map(|d| {
            let body = match d {
                Dialog::Templates(list) => templates_panel(ctx, list),
                Dialog::Info { title, text } => frame(view! { <h3>{title}</h3><p class="pre">{text}</p> }, None, false),
                Dialog::Detail(stack) => detail(ctx, stack),
                Dialog::Custom { existing, copy_of } => view! { <CustomEditor existing=existing copy_of=copy_of /> }.into_any(),
                Dialog::Version(next) => version_panel(ctx, next),
                Dialog::Updates(u) => updates_panel(ctx, u),
            };
            view! {
                <div class="overlay" on:click=move |e| if e.target() == e.current_target() { close() }>{body}</div>
            }
        })
    }
}

/// The reader's modal frame with an optional primary action.
fn frame(
    content: impl IntoView + 'static,
    action: Option<(String, Callback<()>)>,
    back: bool,
) -> AnyView {
    let ctx = ctx();
    let cancel = if action.is_some() { "Cancel" } else { "Close" };
    let close = move |_| {
        if matches!(ctx.dialog.get_untracked(), Some(Dialog::Version(_))) {
            ctx.emb3d.notify(); // puts the version selector back
        }
        ctx.dialog.set(None);
    };
    view! {
        <div class="modal" role="dialog" aria-modal="true" aria-label="EMB3D details">
            <div class="detail">{content}</div>
            <footer>
                {back.then(|| view! { <button class="btn" on:click=move |_| ctx.dialog.update(|d| if let Some(Dialog::Detail(s)) = d { s.pop(); })>"Back"</button> })}
                <button class="btn" on:click=close>{cancel}</button>
                {action.map(|(label, run)| view! { <button class="btn primary" on:click=move |_| run.run(())>{label}</button> })}
            </footer>
        </div>
    }
    .into_any()
}

/// New: an empty project or one of the examples of `examples/index.json`.
pub fn templates(ctx: Ctx) {
    leptos::task::spawn_local(async move {
        // Offline without a cached index, only the empty project is offered.
        ctx.show(Dialog::Templates(examples().await.unwrap_or_default()));
    });
}

fn templates_panel(ctx: Ctx, list: Vec<Example>) -> AnyView {
    // The example is fetched only when it is picked.
    let pick = move |x: Option<Example>| {
        leptos::task::spawn_local(async move {
            let p = match x {
                Some(x) => example(&x).await,
                None => {
                    let mut p = Project::empty();
                    p.emb3d = Some(ctx.emb3d.get_untracked().version.clone());
                    Ok(p)
                }
            };
            ctx.dialog.set(None);
            if let Err(e) = p.and_then(|p| ctx.open(p)) {
                ctx.error("Could not open the template", e);
            }
        })
    };
    let items = std::iter::once(None)
        .chain(list.into_iter().map(Some))
        .map(|x| {
            let (name, about) = x.as_ref().map_or_else(
                || ("Empty project".to_owned(), "A blank System page".to_owned()),
                |x| (x.name.clone(), x.description.clone()),
            );
            view! { <li><button class="linkbtn" title=about on:click=move |_| pick(x.clone())>{name}</button></li> }
        })
        .collect_view();
    let content = view! {
        <h3>"New project"</h3>
        <p class="small muted">"The current project is replaced. Save it first to keep a copy."</p>
        <ul class="tpl">{items}</ul>
    };
    let save = Callback::new(move |()| ctx.save_file());
    frame(content, Some(("Save current project".into(), save)), false)
}

/// Part of reader text: plain, *emphasis*, or a link to another threat or mitigation.
#[derive(Debug, PartialEq)]
pub enum Seg {
    Text(String),
    Em(String),
    Link(String),
}

/// Splits `*emphasis*` and `TID-123` / `MID-123` references for which `known` holds.
pub fn rich(text: &str, known: impl Fn(&str) -> bool) -> Vec<Seg> {
    let mut out = Vec::new();
    let mut plain = String::new();
    let b = text.as_bytes();
    let mut i = 0;
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    while i < b.len() {
        if b[i] == b'*' {
            if let Some(j) = text[i + 1..].find('*').filter(|j| *j > 0) {
                out.push(Seg::Text(std::mem::take(&mut plain)));
                out.push(Seg::Em(text[i + 1..i + 1 + j].to_owned()));
                i += j + 2;
                continue;
            }
        }
        let id = text.get(i..i + 7).filter(|s| {
            (s.starts_with("TID-") || s.starts_with("MID-"))
                && s[4..].bytes().all(|c| c.is_ascii_digit())
                && (i == 0 || !word(b[i - 1]))
                && b.get(i + 7).is_none_or(|c| !word(*c))
        });
        match id.filter(|s| known(s)) {
            Some(id) => {
                out.push(Seg::Text(std::mem::take(&mut plain)));
                out.push(Seg::Link(id.to_owned()));
                i += 7;
            }
            None => {
                let c = text[i..].chars().next().expect("in bounds");
                plain.push(c);
                i += c.len_utf8();
            }
        }
    }
    out.push(Seg::Text(plain));
    out.retain(|s| !matches!(s, Seg::Text(t) if t.is_empty()));
    out
}

fn open_detail(ctx: Ctx, id: String) {
    ctx.dialog.update(|d| match d {
        Some(Dialog::Detail(s)) => s.push(id),
        _ => *d = Some(Dialog::Detail(vec![id])),
    });
}

fn id_list(ctx: Ctx, items: Vec<(String, String)>) -> impl IntoView {
    view! {
        <div class="tlist">{items.into_iter().map(|(id, name)| {
            let id2 = id.clone();
            view! { <button on:click=move |_| open_detail(ctx, id2.clone())><span class="tid">{id}</span>{format!(" {name}")}</button> }
        }).collect_view()}</div>
    }
}

fn detail(ctx: Ctx, stack: Vec<String>) -> AnyView {
    let back = stack.len() > 1;
    let Some(id) = stack.last().cloned() else {
        return ().into_any();
    };
    let content = ctx.with(|p, m| {
        let known = |x: &str| m.e.threats.contains_key(x) || m.e.mitigations.contains_key(x);
        let para = |t: &str| {
            let segs = rich(t, known).into_iter().map(|s| match s {
                Seg::Text(t) => t.into_any(),
                Seg::Em(t) => view! { <em>{t}</em> }.into_any(),
                Seg::Link(x) => {
                    let y = x.clone();
                    view! { <button class="linkbtn" on:click=move |_| open_detail(ctx, y.clone())>{x}</button> }.into_any()
                }
            }).collect_view();
            view! { <p>{segs}</p> }
        };
        let site = format!("{MITRE}/{}/{id}.html", if id.starts_with("MID") { "mitigations" } else { "threats" });
        let ext = move || view! { <a class="extlink" href=site.clone() target="_blank" rel="noopener">"Open on emb3d.mitre.org ↗"</a> };
        let (t, mi) = (m.threat(&id), m.mitigation(&id));
        if t.is_some_and(|t| t.custom) || (t.is_none() && mi.is_some_and(|x| x.custom)) {
            let (name, desc) = t.map_or_else(|| mi.map(|x| (x.name.clone(), x.desc.clone())).unwrap_or_default(), |t| (t.name.clone(), t.desc.clone()));
            let linked: Vec<(String, String)> = t.map_or_else(Vec::new, |t| t.mids.iter().filter_map(|x| Some((x.clone(), m.mitigation(x)?.name.clone()))).collect());
            let kind = if t.is_some() { "threat" } else { "countermeasure" };
            return view! {
                <div class="dhead"><span class="eyebrow" style="margin:0">{format!("{id} · custom {kind}")}</span></div>
                <h3>{name}</h3><p>{if desc.is_empty() { "No description.".to_owned() } else { desc }}</p>
                {(!linked.is_empty()).then(|| view! { <div><p class="eyebrow">"Countermeasures"</p>{id_list(ctx, linked)}</div> })}
                <p class="small muted">"Defined in this project's custom blocks."</p>
            }.into_any();
        }
        if let (true, Some(x)) = (id.starts_with("MID"), mi) {
            let tids: Vec<(String, String)> = m.e.threats.iter().filter(|(_, t)| t.mids.contains(&id)).map(|(k, t)| (k.clone(), t.name.clone())).collect();
            let refs = x.refs.clone();
            return view! {
                <div class="dhead"><span class="eyebrow" style="margin:0">{format!("{id} · {} mitigation", x.maturity)}</span>{ext()}</div>
                <h3>{x.name.clone()}</h3>
                {x.text.iter().map(|t| para(t)).collect_view()}
                {(!x.iec.is_empty()).then(|| view! { <div><p class="eyebrow">"IEC 62443-4-2"</p><p class="small">{x.iec.iter().map(|i| view! { {i.clone()}<br /> }).collect_view()}</p></div> })}
                <div><p class="eyebrow">{format!("Mitigates {} threats", tids.len())}</p>{id_list(ctx, tids)}</div>
                {(!refs.is_empty()).then(|| view! { <div><p class="eyebrow">"References"</p><ol class="refs">{refs.into_iter().map(|r| {
                    let link = (!r.u.is_empty()).then(|| view! { " " <a href=r.u.clone() target="_blank" rel="noopener">{r.u.clone()}</a> });
                    view! { <li>{r.t}{link}</li> }
                }).collect_view()}</ol></div> })}
            }.into_any();
        }
        let Some(t) = t else { return view! { <p>"Unknown id."</p> }.into_any() };
        let (rank, mat) = maturity(&t.maturity);
        let mids: Vec<(String, String)> = t.mids.iter().filter_map(|x| Some((x.clone(), m.mitigation(x)?.name.clone()))).collect();
        let _ = p;
        view! {
            <div class="dhead"><span class="eyebrow" style="margin:0">{format!("{id} · {} threat", t.cat)}</span><span class=format!("mat m{rank}")>{mat.to_owned()}</span>{ext()}</div>
            <h3>{t.name.clone()}</h3>
            {t.text.iter().map(|x| para(x)).collect_view()}
            <div><p class="eyebrow">"Device properties"</p><p class="small">{t.pids.iter().map(|pid| view! {
                <span class="tid">{pid.clone()}</span>{format!(" {}", m.e.properties.get(pid).map(|x| x.name.as_str()).unwrap_or_default())}<br />
            }).collect_view()}</p></div>
            {(!t.cwes.is_empty()).then(|| view! { <div><p class="eyebrow">"Weaknesses"</p><p class="small">{t.cwes.iter().map(|(c, name)| view! {
                <a class="extlink" href=format!("https://cwe.mitre.org/data/definitions/{c}.html") target="_blank" rel="noopener">{format!("CWE-{c}")}</a>{format!(" {name}")}<br />
            }).collect_view()}</p></div> })}
            <div><p class="eyebrow">{format!("Mitigations · {}", mids.len())}</p>{id_list(ctx, mids)}</div>
        }.into_any()
    });
    frame(content, None, back)
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

fn version_panel(ctx: Ctx, next: Arc<Emb3d>) -> AnyView {
    let (cur, lib) = (ctx.emb3d.get_untracked(), ctx.lib.get_untracked());
    let d = stix::diff(&cur, &next);
    let v = next.version.clone();
    let label = format!("Use EMB3D {v}");
    let rows = ctx.project.with_untracked(|p| {
        let (a, b) = (Model::new(&cur, &lib, p), Model::new(&next, &lib, p));
        let multi = p.pages.len() > 1;
        p.nodes()
            .filter(|n| a.has_threats(n))
            .filter_map(|n| {
                let before: BTreeSet<String> =
                    a.node_threats(p, n).into_iter().map(|h| h.tid).collect();
                let after: BTreeSet<String> =
                    b.node_threats(p, n).into_iter().map(|h| h.tid).collect();
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
                let (add, rem) = (
                    names(after.difference(&before).collect(), &b),
                    names(before.difference(&after).collect(), &a),
                );
                let page = if multi {
                    format!(
                        "{} › ",
                        p.page_of(n.id).map(|x| x.name.as_str()).unwrap_or_default()
                    )
                } else {
                    String::new()
                };
                (!add.is_empty() || !rem.is_empty())
                    .then(|| (format!("{page}{}", n.name), add, rem))
            })
            .collect::<Vec<_>>()
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
    let lines = |l: Vec<String>| {
        if l.is_empty() {
            "—".into_any()
        } else {
            l.into_iter()
                .map(|x| view! { {x}<br /> })
                .collect_view()
                .into_any()
        }
    };
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

fn updates_panel(ctx: Ctx, u: Updates) -> AnyView {
    match u {
        Updates::Checking => frame(
            view! { <p class="muted">"Checking emb3d.mitre.org…"</p> },
            None,
            false,
        ),
        Updates::Failed(e) => frame(
            view! {
                <h3>"Could not reach emb3d.mitre.org"</h3>
                <p>{format!("The browser could not read MITRE's data page ({e}). This happens offline and when MITRE's site does not allow it.")}</p>
            },
            None,
            false,
        ),
        Updates::Current(found) => frame(
            view! {
                <h3>"EMB3D is up to date"</h3><p>{format!("emb3d.mitre.org lists {}. All of them are available here.", found.join(", "))}</p>
            },
            None,
            false,
        ),
        Updates::Available { found, have } => {
            let v = found
                .iter()
                .find(|v| !have.contains(v))
                .cloned()
                .unwrap_or_default();
            let try_it = {
                let v = v.clone();
                Callback::new(move |()| {
                    let v = v.clone();
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
                })
            };
            frame(
                view! {
                    <h3>{format!("EMB3D STIX {v} is available")}</h3>
                    <p>{format!("emb3d.mitre.org lists {}. This copy of the Workbench has {}.", found.join(", "), have.join(", "))}</p>
                    <p>"Try it now: the release is downloaded into this browser session only."</p>
                },
                Some((format!("Try {v} now"), try_it)),
                false,
            )
        }
    }
}

#[derive(Clone, Default)]
struct ThreatRow {
    key: usize,
    id: String,
    cm_id: String,
    name: String,
    desc: String,
    cm_name: String,
    cm_desc: String,
}

const GROUPS: [&str; 5] = [
    "Hardware",
    "System software",
    "Application",
    "Networking",
    "Custom",
];
const CATEGORIES: [&str; 4] = [
    "Hardware",
    "System Software",
    "Application Software",
    "Networking",
];

#[component]
fn CustomEditor(existing: Option<String>, copy_of: Option<CustomType>) -> impl IntoView {
    let ctx = ctx();
    let found = existing.as_ref().and_then(|k| {
        ctx.project
            .with_untracked(|p| p.custom_types.iter().find(|c| &c.kind == k).cloned())
    });
    let start = match (&found, copy_of) {
        (Some(c), _) => c.clone(),
        (None, Some(c)) => CustomType {
            kind: String::new(),
            name: format!("{} (copy)", c.name),
            threats: c
                .threats
                .iter()
                .map(|t| CustomThreat {
                    id: String::new(),
                    cms: t
                        .cms
                        .iter()
                        .map(|m| CustomCm {
                            id: String::new(),
                            ..m.clone()
                        })
                        .collect(),
                    ..t.clone()
                })
                .collect(),
            ..c
        },
        (None, None) => CustomType {
            group: "Hardware".into(),
            ..Default::default()
        },
    };
    let existing = found.as_ref().map(|c| c.kind.clone());
    let (name, tag, group, hint) = (
        RwSignal::new(start.name.clone()),
        RwSignal::new(start.tag.clone()),
        RwSignal::new(start.group.clone()),
        RwSignal::new(start.hint.clone()),
    );
    let base = RwSignal::new(start.base.iter().cloned().collect::<BTreeSet<String>>());
    let rows = RwSignal::new(
        start
            .threats
            .iter()
            .enumerate()
            .map(|(key, t)| {
                let cm = t.cms.first().cloned().unwrap_or_default();
                ThreatRow {
                    key,
                    id: t.id.clone(),
                    cm_id: cm.id,
                    name: t.name.clone(),
                    desc: t.desc.clone(),
                    cm_name: cm.name,
                    cm_desc: cm.desc,
                }
            })
            .collect::<Vec<_>>(),
    );
    let error = RwSignal::new(None::<&'static str>);
    let used = existing.as_ref().map_or(0, |k| {
        ctx.project
            .with_untracked(|p| p.nodes().filter(|n| &n.kind == k).count())
    });
    let e = ctx.emb3d.get_untracked();
    let depth = |pid: &str| {
        std::iter::successors(e.properties.get(pid).and_then(|p| p.parent.clone()), |p| {
            e.properties.get(p).and_then(|x| x.parent.clone())
        })
        .count()
    };
    let pid_list = CATEGORIES.map(|cat| {
        let mut ids: Vec<&String> = e.properties.iter().filter(|(_, p)| p.cat == cat).map(|(k, _)| k).collect();
        ids.sort_by(|a, b| num_cmp(a, b));
        let boxes = ids.into_iter().map(|pid| {
            let (p1, p2) = (pid.clone(), pid.clone());
            let pad = format!("{}px", depth(pid) * 14);
            view! { <label class="check small" style:padding-left=pad><input type="checkbox" prop:checked=move || base.with(|b| b.contains(&p1))
                on:change=move |ev| { let on = event_target_checked(&ev); let p = p2.clone(); base.update_untracked(|b| { if on { b.insert(p); } else { b.remove(&p); } }) } />
                <span><span class="tid">{pid.clone()}</span>{format!(" {}", e.properties[pid].name)}</span></label> }
        }).collect_view();
        view! { <div class="pidcat"><p class="lbl">{cat}</p>{boxes}</div> }
    });
    let field =
        move |key: usize, get: fn(&ThreatRow) -> String, set: fn(&mut ThreatRow, String)| {
            let value = rows
                .with_untracked(|r| r.iter().find(|x| x.key == key).map(get).unwrap_or_default());
            (value, move |ev: leptos::ev::Event| {
                let v = event_target_value(&ev);
                rows.update_untracked(|r| {
                    if let Some(x) = r.iter_mut().find(|x| x.key == key) {
                        set(x, v)
                    }
                });
            })
        };
    let threat_rows = move || {
        rows.with(|r| r.iter().map(|row| row.key).collect::<Vec<_>>()).into_iter().map(|key| {
        let (n, on_n) = field(key, |r| r.name.clone(), |r, v| r.name = v);
        let (d, on_d) = field(key, |r| r.desc.clone(), |r, v| r.desc = v);
        let (cn, on_cn) = field(key, |r| r.cm_name.clone(), |r, v| r.cm_name = v);
        let (cd, on_cd) = field(key, |r| r.cm_desc.clone(), |r, v| r.cm_desc = v);
        view! {
            <div class="cthreat">
                <div class="field"><label>"Threat"</label><input type="text" id=format!("ct-{key}") value=n placeholder="For example: Optical blinding of the sensor" on:input=on_n /></div>
                <div class="field"><label>"Description"</label><textarea rows="2" on:input=on_d>{d}</textarea></div>
                <div class="field"><label>"Countermeasure (optional)"</label><input type="text" value=cn placeholder="For example: Detect blinding and alert" on:input=on_cn /></div>
                <div class="field"><label>"Countermeasure description"</label><textarea rows="2" on:input=on_cd>{cd}</textarea></div>
                <button class="linkbtn small" on:click=move |_| rows.update(|r| r.retain(|x| x.key != key))>"Remove this threat"</button>
            </div>
        }
    }).collect_view()
    };
    let (questions, external) = (start.questions.clone(), start.external);
    let asked = (!questions.is_empty()).then(|| view! { <p class="small muted">{format!("{} are kept as they are; answer them in the inspector.", ops::plural(questions.len(), "imported question"))}</p> });
    let save = {
        let existing = existing.clone();
        Callback::new(move |()| {
            let name_v = name.get_untracked().trim().to_owned();
            if name_v.is_empty() {
                return error.set(Some("Give the block a name."));
            }
            let threats: Vec<CustomThreat> = rows
                .get_untracked()
                .into_iter()
                .filter(|r| !r.name.trim().is_empty())
                .map(|r| CustomThreat {
                    id: r.id,
                    name: r.name.trim().into(),
                    desc: r.desc.trim().into(),
                    cms: if r.cm_name.trim().is_empty() {
                        Vec::new()
                    } else {
                        vec![CustomCm {
                            id: r.cm_id,
                            name: r.cm_name.trim().into(),
                            desc: r.cm_desc.trim().into(),
                        }]
                    },
                })
                .collect();
            let base_v: Vec<String> = base.get_untracked().into_iter().collect();
            if base_v.is_empty() && threats.is_empty() && questions.is_empty() {
                return error.set(Some("Tick at least one EMB3D property or add a custom threat, otherwise the block has no threats."));
            }
            let tag_v = tag.get_untracked().trim().to_owned();
            let tag_v = if tag_v.is_empty() {
                name_v
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .take(3)
                    .collect()
            } else {
                tag_v
            };
            let hint_v = hint.get_untracked().trim().to_owned();
            let def = CustomType {
                kind: String::new(),
                name: name_v,
                group: group.get_untracked(),
                tag: tag_v.to_uppercase().chars().take(4).collect(),
                hint: if hint_v.is_empty() {
                    "Custom block".into()
                } else {
                    hint_v
                },
                base: base_v,
                threats,
                questions: questions.clone(),
                external,
            };
            let existing = existing.clone();
            ctx.edit(|p, m| ops::save_custom(p, m, existing.as_deref(), def));
            ctx.dialog.set(None);
        })
    };
    let manage = found.map(|c| {
        let kind = c.kind.clone();
        let armed = RwSignal::new(false);
        let in_use = used > 0;
        view! {
            <div class="row">
                <button class="btn small" on:click=move |_| ctx.show(Dialog::Custom { existing: None, copy_of: Some(c.clone()) })>"Duplicate as a new type"</button>
                <button class="btn small danger" disabled=in_use title=in_use.then_some("Remove the blocks of this type first") on:click=move |_| {
                    if !armed.get_untracked() { return armed.set(true); }
                    let k = kind.clone();
                    ctx.edit(|p, _| p.custom_types.retain(|c| c.kind != k));
                    ctx.dialog.set(None);
                }>{move || if armed.get() { "Click again to delete" } else { "Delete block type" }}</button>
                {(used > 0).then(|| view! { <span class="small muted">{format!("Used by {}.", ops::plural(used, "block"))}</span> })}
            </div>
        }
    });
    let title = if existing.is_some() {
        start.name.clone()
    } else {
        "Custom block".into()
    };
    let next_key = StoredValue::new(rows.with_untracked(Vec::len));
    web::focus("cb-name");
    let content = view! {
        <div class="dhead"><span class="eyebrow" style="margin:0">{if existing.is_some() { "Edit custom block" } else { "New custom block" }}</span></div>
        <h3>{title}</h3>
        <div class="cform">
            <div class="field"><label for="cb-name">"Name"</label><input type="text" id="cb-name" value=start.name.clone() placeholder="For example: Image sensor module" on:input=move |e| name.update_untracked(|x| *x = event_target_value(&e)) /></div>
            <div class="row2">
                <div class="field"><label for="cb-tag">"Tag (up to 4 letters)"</label><input type="text" id="cb-tag" maxlength="4" value=start.tag.clone() placeholder="CAM" on:input=move |e| tag.update_untracked(|x| *x = event_target_value(&e)) /></div>
                <div class="field"><label for="cb-group">"Group"</label><select id="cb-group" class="status" on:change=move |e| group.update_untracked(|x| *x = event_target_value(&e))>
                    {GROUPS.map(|g| view! { <option selected=start.group == g>{g}</option> }).collect_view()}</select></div>
            </div>
            <div class="field"><label for="cb-hint">"Description"</label><input type="text" id="cb-hint" value=start.hint.clone() on:input=move |e| hint.update_untracked(|x| *x = event_target_value(&e)) /></div>
            <div><p class="eyebrow">"EMB3D properties"</p><p class="small muted">"Every EMB3D threat linked to a ticked property applies to this block. Ticking a sub-property implies its parent."</p>
                <div class="pidlist">{pid_list}</div>{asked}</div>
            <div><p class="eyebrow">"Custom threats"</p><p class="small muted">"Threats EMB3D does not cover. Each can have its own countermeasure."</p>
                <div>{threat_rows}</div>
                <button class="btn small" on:click=move |_| {
                    let key = next_key.get_value();
                    next_key.set_value(key + 1);
                    rows.update(|r| r.push(ThreatRow { key, ..Default::default() }));
                    web::focus(&format!("ct-{key}"));
                }>"Add a threat"</button></div>
            {move || error.get().map(|e| view! { <p class="warn">{e}</p> })}
            {manage}
        </div>
    };
    frame(
        content,
        Some((
            if existing.is_some() {
                "Save block".into()
            } else {
                "Create block".into()
            },
            save,
        )),
        false,
    )
}

#[cfg(test)]
#[path = "../../tests/unit/ui/dialogs.rs"]
mod tests;
