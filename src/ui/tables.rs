//! Threats and Countermeasures tables, and the Report view.

use leptos::prelude::*;

use super::{
    ctx,
    dialogs::Dialog,
    inspector::{cm_select, why_box},
    web, Ctx, Sel, View,
};
use crate::{
    engine::{
        cm_status, maturity, missing_accept_why, missing_why, ReportOpts, State, CM_STATUS,
        NEEDS_WHY,
    },
    model::Meta,
};

fn summary(rows: &[State]) -> impl IntoView {
    let c = |s: State| rows.iter().filter(|r| **r == s).count();
    view! {
        <div class="summary"><span><b>{rows.len()}</b>"threats"</span><span style="color:var(--s-open)"><b>{c(State::Open)}</b>"open"</span>
            <span style="color:var(--s-done)"><b>{c(State::Mitigated)}</b>"mitigated"</span><span style="color:var(--s-acc)"><b>{c(State::Accepted)}</b>"accepted"</span>
            <span class="muted"><b>{c(State::NotApplicable)}</b>"n/a"</span></div>
    }
}

/// Opens block `id` in the diagram with threat `tid` unfolded.
fn reveal(ctx: Ctx, id: u64, tid: String) {
    if let Some(pg) = ctx
        .project
        .with_untracked(|p| p.page_of(id).map(|pg| pg.id.clone()))
    {
        ctx.cur.set(pg);
    }
    ctx.select(Some(Sel::Node(id)));
    ctx.open_threat.set(Some(tid.clone()));
    ctx.view.set(View::Diagram);
    request_animation_frame(move || {
        let el = document()
            .query_selector(&format!(".inspector details[data-tid=\"{tid}\"]"))
            .ok()
            .flatten();
        if let Some(el) = el {
            el.scroll_into_view();
        }
    });
}

#[component]
pub fn Threats() -> impl IntoView {
    let ctx = ctx();
    let f = ctx.filters;
    move || {
        let (state, comp) = f.with(|f| (f.state.clone(), f.comp.clone()));
        ctx.with(|p, m| {
            let all = m.all_rows(p);
            let multi = p.pages.len() > 1;
            let comps = p.nodes().filter(|n| m.has_threats(n)).map(|n| {
                let label = if multi { format!("{} › {}", p.page_of(n.id).map(|pg| pg.name.as_str()).unwrap_or_default(), n.name) } else { n.name.clone() };
                view! { <option value=n.id.to_string() selected=comp == n.id.to_string()>{label}</option> }
            }).collect_view();
            let states: Vec<State> = all.iter().map(|r| r.state).collect();
            let rows = all.iter()
                .filter(|r| state == "all" || r.state.key() == state)
                .filter(|r| comp == "all" || r.node.id.to_string() == comp)
                .map(|r| {
                    let (rank, mat) = maturity(&r.hit.t.maturity);
                    let implemented = r.hit.t.mids.iter().filter(|x| cm_status(r.node, x) == "implemented").count();
                    let missing = r.hit.t.mids.iter().any(|x| missing_why(r.node, x)) || missing_accept_why(r.node, &r.hit.tid);
                    let page = if multi { format!("{} · ", r.page.name) } else { String::new() };
                    let sub = page + m.type_of(r.node).map_or("", |t| t.name.as_str());
                    let (id, tid) = (r.node.id, r.hit.tid.clone());
                    view! {
                        <tr class="link" on:click=move |_| reveal(ctx, id, tid.clone())>
                            <td>{r.node.name.clone()}<div class="sub">{sub}</div></td>
                            <td><span class="tid">{r.hit.tid.clone()}</span>{format!(" {}", r.hit.t.name)}</td>
                            <td><span class=format!("mat m{rank}")>{mat.to_owned()}</span></td>
                            <td><span class=format!("pill st-{}", r.state.key())>{r.state.label()}</span>
                                {missing.then(|| view! { <div class="sub" style="color:var(--s-open)">"Justification missing"</div> })}</td>
                            <td class="num">{format!("{implemented} / {} implemented", r.hit.t.mids.len())}</td>
                        </tr>
                    }
                })
                .collect::<Vec<_>>();
            let empty = rows.is_empty().then(|| view! { <tr><td colspan="5" class="muted">"No threats match these filters."</td></tr> });
            view! {
                <div class="tablehead"><h2>"Threats"</h2>{summary(&states)}
                    <div class="filters">
                        <select aria-label="Filter by state" on:change=move |e| { let v = event_target_value(&e); f.update(|f| f.state = v) }>
                            {[("all", "All states"), ("Open", "Open"), ("Mitigated", "Mitigated"), ("Accepted", "Accepted"), ("NA", "Not applicable")]
                                .map(|(v, l)| view! { <option value=v selected=state == v>{l}</option> }).collect_view()}
                        </select>
                        <select aria-label="Filter by component" on:change=move |e| { let v = event_target_value(&e); f.update(|f| f.comp = v) }>
                            <option value="all">"All components"</option>{comps}
                        </select>
                    </div></div>
                <div class="tablescroll"><table><thead><tr><th>"Component"</th><th>"Threat"</th><th>"Evidence"</th><th>"State"</th><th>"Countermeasures"</th></tr></thead>
                    <tbody>{rows}{empty}</tbody></table></div>
            }
        })
    }
}

#[component]
pub fn Countermeasures() -> impl IntoView {
    let ctx = ctx();
    let f = ctx.filters;
    move || {
        let status = f.with(|f| f.status.clone());
        ctx.with(|p, m| {
            let all = m.cm_rows(p);
            let cnt = |s: &str| all.iter().filter(|r| r.status == s).count();
            let missing = all.iter().filter(|r| missing_why(r.node, &r.mid)).count();
            let multi = p.pages.len() > 1;
            let rows = all.iter().filter(|r| status == "all" || r.status == status).map(|r| {
                let mid = r.mid.clone();
                let why = NEEDS_WHY.contains(&r.status.as_str());
                let why = if why {
                    why_box(ctx, r.node, r.mid.clone(), "Justification").into_any()
                } else {
                    view! { <span class="muted">"—"</span> }.into_any()
                };
                view! {
                    <tr>
                        <td><span class="tid">{r.mid.clone()}</span>" "<button class="linkbtn" on:click=move |_| ctx.show(Dialog::Detail(vec![mid.clone()]))>{r.m.name.clone()}</button></td>
                        <td>{r.m.maturity.clone()}</td>
                        <td>{r.node.name.clone()}{multi.then(|| view! { <div class="sub">{r.page.name.clone()}</div> })}</td>
                        <td class="num">{r.tids.join(", ")}</td>
                        <td class="sub">{if r.m.iec.is_empty() { "—".to_owned() } else { r.m.iec.join("; ") }}</td>
                        <td>{cm_select(ctx, r.node, &r.mid, "")}</td>
                        <td class="whycell">{why}</td>
                    </tr>
                }
            }).collect::<Vec<_>>();
            let empty = rows.is_empty().then(|| view! { <tr><td colspan="7" class="muted">"No countermeasures match this filter."</td></tr> });
            view! {
                <div class="tablehead"><h2>"Countermeasures"</h2>
                    <div class="summary"><span><b>{all.len()}</b>"total"</span><span style="color:var(--s-done)"><b>{cnt("implemented")}</b>"implemented"</span>
                        <span style="color:var(--s-open)"><b>{cnt("required")}</b>"required"</span><span class="muted"><b>{cnt("recommended")}</b>"recommended"</span>
                        {(missing > 0).then(|| view! { <span style="color:var(--s-open)"><b>{missing}</b>"missing justification"</span> })}</div>
                    <div class="filters"><select aria-label="Filter by status" on:change=move |e| { let v = event_target_value(&e); f.update(|f| f.status = v) }>
                        <option value="all">"All statuses"</option>
                        {CM_STATUS.map(|(v, l)| view! { <option value=v selected=status == v>{l}</option> }).collect_view()}
                    </select></div></div>
                <div class="tablescroll"><table><thead><tr><th>"Countermeasure"</th><th>"Level"</th><th>"Component"</th><th>"Threats"</th><th>"IEC 62443-4-2"</th><th>"Status"</th><th>"Justification"</th></tr></thead>
                    <tbody>{rows}{empty}</tbody></table></div>
            }
        })
    }
}

#[component]
pub fn Report() -> impl IntoView {
    let ctx = ctx();
    let opts = ctx.report;
    let toggles = [
        ("diagram", "Show model diagram"),
        ("mitigated", "Show mitigated threats"),
        ("closed", "Show not applicable and accepted threats"),
        ("empty", "Show components without threats"),
        ("props", "Show EMB3D properties"),
        ("fulltext", "Full threat descriptions"),
    ]
    .map(|(k, label)| {
        let get = move |o: &ReportOpts| match k {
            "diagram" => o.diagram,
            "mitigated" => o.mitigated,
            "closed" => o.closed,
            "empty" => o.empty,
            "props" => o.props,
            _ => o.fulltext,
        };
        let set = move |o: &mut ReportOpts, v: bool| match k {
            "diagram" => o.diagram = v,
            "mitigated" => o.mitigated = v,
            "closed" => o.closed = v,
            "empty" => o.empty = v,
            "props" => o.props = v,
            _ => o.fulltext = v,
        };
        view! { <label class="check"><input type="checkbox" prop:checked=move || opts.with(get) on:change=move |e| { let v = event_target_checked(&e); opts.update(|o| set(o, v)) } /><span>{label}</span></label> }
    });
    let meta = |key: &'static str, label: &'static str, area: bool| {
        let get = move |m: &Meta| match key {
            "owner" => m.owner.clone(),
            "reviewer" => m.reviewer.clone(),
            _ => m.description.clone(),
        };
        let value = ctx.project.with_untracked(|p| get(&p.meta));
        let input = move |e: leptos::ev::Event| {
            let v = event_target_value(&e);
            ctx.typing(|p| match key {
                "owner" => p.meta.owner = v,
                "reviewer" => p.meta.reviewer = v,
                _ => p.meta.description = v,
            });
        };
        let id = format!("rm-{key}");
        if area {
            view! { <div class="field wide"><label for=id.clone()>{label}</label><textarea id=id rows="2" placeholder="What the device is, where it is deployed, what is in scope" on:input=input on:change=move |_| ctx.project.notify()>{value}</textarea></div> }.into_any()
        } else {
            view! { <div class="field"><label for=id.clone()>{label}</label><input type="text" id=id value=value on:input=input on:change=move |_| ctx.project.notify() /></div> }.into_any()
        }
    };
    let html = move || {
        let o = opts.get();
        ctx.with(|p, m| m.report_html(p, o, &Ctx::today()))
    };
    view! {
        <div class="ropts no-print">
            <div class="ropt-row">{toggles}
                <button class="btn primary" on:click=move |_| web::print(&format!("Threat model - {}", ctx.project.with_untracked(|p| p.name.clone())))>"Print / Save as PDF"</button>
            </div>
            <div class="ropt-meta">{meta("owner", "Owner", false)}{meta("reviewer", "Reviewer", false)}{meta("description", "Description", true)}</div>
            <p class="small muted">"Print opens your browser's print dialog; choose \"Save as PDF\"."</p>
        </div>
        <div inner_html=html></div>
    }
}
