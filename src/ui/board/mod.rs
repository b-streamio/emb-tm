// SPDX-License-Identifier: GPL-2.0-only
//! Diagram view: library rail and page list, breadcrumbs, the board with its
//! blocks and data flows, and the inspector beside it.

mod actions;
mod block;
mod drag;
mod pages;
mod rail;

use leptos::{ev, html, prelude::*};
use wasm_bindgen::JsCast;

pub use actions::{add_device_from, import_types, move_into};
use block::{block, Marks};
use drag::{device_at, drop_block, pointer_move, pointer_up, Drag};
pub use pages::page_path;
use pages::Crumbs;
use rail::Rail;

use super::{ctx, inspector::Inspector, Ctx, Sel};
use crate::{
    engine::{anchor, esc},
    model::Page,
};

#[component]
pub fn Diagram() -> impl IntoView {
    let ctx = ctx();
    view! {
        <div class="diagram">
            <aside class="rail"><Rail /></aside>
            <section class="boardwrap" node_ref=ctx.wrap>
                <Crumbs />
                <div class="hint" hidden=move || ctx.connect.get().is_none()>
                    <span>"Tap the destination component"</span>
                    <button on:click=move |_| ctx.connect.set(None)>"Cancel"</button>
                </div>
                <Board />
            </section>
            <aside class="inspector"><Inspector /></aside>
        </div>
    }
}

/// The board: blocks, data flows, dragging and dropping.
#[component]
fn Board() -> impl IntoView {
    let ctx = ctx();
    let board = NodeRef::<html::Div>::new();
    let drag = RwSignal::new(None::<Drag>);
    let drop_target = RwSignal::new(None::<u64>);
    let last_tap = StoredValue::new((0_u64, 0.0_f64));
    let move_handle = window_event_listener(ev::pointermove, move |e| {
        pointer_move(ctx, board, drag, drop_target, &e)
    });
    let up_handle = window_event_listener(ev::pointerup, move |e| {
        pointer_up(ctx, drag, drop_target, last_tap, &e)
    });
    on_cleanup(move || {
        move_handle.remove();
        up_handle.remove();
    });
    view! {
        <div class="board" node_ref=board
            on:pointerdown=move |e| {
                let on_background = e.target().and_then(|t| t.dyn_into::<web_sys::Element>().ok())
                    .is_some_and(|el| el.class_list().contains("board") || el.id() == "edges");
                if on_background && ctx.connect.get_untracked().is_none() && ctx.sel.get_untracked().is_some() {
                    ctx.select(None);
                    ctx.open_threat.set(None);
                }
            }
            on:dragover=move |e: ev::DragEvent| {
                e.prevent_default();
                if let Some(dt) = e.data_transfer() { dt.set_drop_effect("copy"); }
                drop_target.set(device_at(ctx, board, f64::from(e.client_x()), f64::from(e.client_y()), &[]));
            }
            on:dragleave=move |_| drop_target.set(None)
            on:drop=move |e| drop_block(ctx, board, drop_target, &e)>
            <svg id="edges" inner_html=move || edges(ctx, drag)
                on:click=move |e| {
                    let flow = e.target().and_then(|t| t.dyn_into::<web_sys::Element>().ok())
                        .and_then(|el| el.closest("g[data-flow]").ok().flatten())
                        .and_then(|g| g.get_attribute("data-flow")?.parse().ok());
                    if let Some(id) = flow { ctx.select(Some(Sel::Flow(id))); }
                }></svg>
            {move || blocks(ctx, drag, drop_target)}
        </div>
    }
}

/// The blocks of the current page. Typing changes only names: blocks follow
/// it themselves (`live`).
fn blocks(
    ctx: Ctx,
    drag: RwSignal<Option<Drag>>,
    drop_target: RwSignal<Option<u64>>,
) -> Vec<impl IntoView> {
    let page = ctx.page();
    let multi = ctx.multi.get();
    let marks = Marks {
        sel: ctx.sel.get(),
        multi: &multi,
        connecting: ctx.connect.get().is_some(),
        target: drop_target.get(),
    };
    ctx.counts.with(|c| {
        ctx.with(|p, m| {
            let Some(pg) = p.page(&page) else {
                return Vec::new();
            };
            pg.nodes
                .iter()
                .map(|n| block(ctx, p, m, c, n.id, &marks, drag))
                .collect::<Vec<_>>()
        })
    })
}

/// The data flows of the current page, following a drag.
fn edges(ctx: Ctx, drag: RwSignal<Option<Drag>>) -> String {
    ctx.soft.track();
    let (page, sel, d) = (ctx.page(), ctx.sel.get(), drag.get());
    ctx.project
        .with(|p| {
            let pg = p.page(&page)?;
            let Some(d) = d.filter(|d| d.moved) else {
                return Some(edges_svg(pg, sel));
            };
            let mut pg = pg.clone();
            for n in &mut pg.nodes {
                if let Some((x, y)) = d.place(n.id, n.size()) {
                    (n.x, n.y) = (x, y);
                }
            }
            Some(edges_svg(&pg, sel))
        })
        .unwrap_or_default()
}

/// Data flows of a page as SVG markup (every value escaped).
fn edges_svg(pg: &Page, sel: Option<Sel>) -> String {
    let mut out = String::from(
        r#"<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="arrowhead" d="M0,0 L10,5 L0,10 z"></path></marker><marker id="arrSel" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" style="fill:var(--accent)"></path></marker></defs>"#,
    );
    for f in &pg.flows {
        let (Some(a), Some(b)) = (
            pg.nodes.iter().find(|n| n.id == f.from),
            pg.nodes.iter().find(|n| n.id == f.to),
        ) else {
            continue;
        };
        let ((x1, y1), (x2, y2)) = (anchor(a, b), anchor(b, a));
        let on = sel == Some(Sel::Flow(f.id));
        out += &format!(
            r#"<g data-flow="{}"><line class="edge {}{}" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" marker-end="url(#{})"></line><line class="edgehit" x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"></line><text class="edgelabel" x="{}" y="{}" text-anchor="middle">{}</text></g>"#,
            f.id,
            if f.encrypted { "enc" } else { "plain" },
            if on { " sel" } else { "" },
            if on { "arrSel" } else { "arr" },
            (x1 + x2) / 2.0,
            (y1 + y2) / 2.0 - 6.0,
            esc(&f.label)
        );
    }
    out
}

#[cfg(test)]
#[path = "../../../tests/unit/ui/board/mod.rs"]
mod tests;
