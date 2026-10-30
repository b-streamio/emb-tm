// SPDX-License-Identifier: GPL-2.0-only
//! Dragging blocks on the board and dropping blocks from the rail.

use leptos::{ev, html, prelude::*};

use super::{
    actions::{add_at, add_into, click_node},
    move_into,
};
use crate::{
    model::NODE_W,
    ops::{BOARD_H, BOARD_W},
    ui::Ctx,
};

/// A block drag in progress. The project changes once, on release; until
/// then only the dragged blocks and the data flows follow the pointer.
#[derive(Clone)]
pub(super) struct Drag {
    pub(super) node: u64,
    /// Dragged blocks and where they started.
    pub(super) start: Vec<(u64, f64, f64)>,
    pub(super) px: f64,
    pub(super) py: f64,
    pub(super) dx: f64,
    pub(super) dy: f64,
    pub(super) moved: bool,
    pub(super) target: Option<u64>,
    pub(super) modifier: bool,
}

impl Drag {
    /// Where block `id` of size `(w, h)` is drawn now, if it is being moved.
    pub(super) fn place(&self, id: u64, (w, h): (f64, f64)) -> Option<(f64, f64)> {
        let (_, x, y) = self
            .start
            .iter()
            .find(|s| s.0 == id)
            .filter(|_| self.moved)?;
        Some((
            (x + self.dx).clamp(0.0, BOARD_W - w),
            (y + self.dy).clamp(0.0, BOARD_H - h),
        ))
    }
}

/// Device box of the current page under a screen point, ignoring `skip`.
pub(super) fn device_at(
    ctx: Ctx,
    board: NodeRef<html::Div>,
    cx: f64,
    cy: f64,
    skip: &[u64],
) -> Option<u64> {
    let r = board.get_untracked()?.get_bounding_client_rect();
    let (x, y) = (cx - r.left(), cy - r.top());
    let page = ctx.page();
    ctx.project.with_untracked(|p| {
        p.page(&page)?
            .nodes
            .iter()
            .find(|n| {
                n.is_device()
                    && !skip.contains(&n.id)
                    && x >= n.x
                    && y >= n.y
                    && x <= n.x + n.size().0
                    && y <= n.y + n.size().1
            })
            .map(|n| n.id)
    })
}

pub(super) fn pointer_move(
    ctx: Ctx,
    board: NodeRef<html::Div>,
    drag: RwSignal<Option<Drag>>,
    drop_target: RwSignal<Option<u64>>,
    e: &ev::PointerEvent,
) {
    let Some(mut d) = drag.get_untracked() else {
        return;
    };
    let (dx, dy) = (
        f64::from(e.client_x()) - d.px,
        f64::from(e.client_y()) - d.py,
    );
    if !d.moved && dx.hypot(dy) < 4.0 {
        return;
    }
    (d.moved, d.dx, d.dy) = (true, dx, dy);
    let ids: Vec<u64> = d.start.iter().map(|s| s.0).collect();
    d.target = device_at(
        ctx,
        board,
        f64::from(e.client_x()),
        f64::from(e.client_y()),
        &ids,
    );
    if drop_target.get_untracked() != d.target {
        drop_target.set(d.target);
    }
    drag.set(Some(d));
}

/// Ends a drag: moves the blocks, or treats it as a click (a double click
/// opens a device's page).
pub(super) fn pointer_up(
    ctx: Ctx,
    drag: RwSignal<Option<Drag>>,
    drop_target: RwSignal<Option<u64>>,
    last_tap: StoredValue<(u64, f64)>,
    e: &ev::PointerEvent,
) {
    let Some(d) = drag.get_untracked() else {
        return;
    };
    drag.set(None);
    drop_target.set(None);
    if d.moved {
        let ids: Vec<u64> = d.start.iter().map(|s| s.0).collect();
        match d.target {
            Some(dev) => move_into(ctx, &ids, dev),
            None => ctx.edit(|p, _| {
                for id in &ids {
                    if let Some(n) = p.node_mut(*id) {
                        if let Some((x, y)) = d.place(n.id, n.size()) {
                            (n.x, n.y) = (x, y);
                        }
                    }
                }
            }),
        }
        return;
    }
    // The board re-renders on every click, so detect a double click by id.
    let now = js_sys::Date::now();
    let is_device = ctx.project.with_untracked(|p| {
        p.node(d.node)
            .filter(|n| n.is_device())
            .and_then(|n| n.page.clone())
    });
    let (last, t) = last_tap.get_value();
    if let (Some(page), true, None) = (
        is_device,
        last == d.node && now - t < 450.0,
        ctx.connect.get_untracked(),
    ) {
        last_tap.set_value((0, 0.0));
        ctx.open_page(&page);
        return;
    }
    last_tap.set_value((d.node, now));
    click_node(ctx, d.node, d.modifier || e.shift_key());
}

/// A block dropped from the rail: on a device box, or on the board.
pub(super) fn drop_block(
    ctx: Ctx,
    board: NodeRef<html::Div>,
    drop_target: RwSignal<Option<u64>>,
    e: &ev::DragEvent,
) {
    drop_target.set(None);
    let kind = e
        .data_transfer()
        .and_then(|dt| dt.get_data("text/x-emb3d").ok())
        .unwrap_or_default();
    if kind.is_empty() {
        return;
    }
    e.prevent_default();
    let (cx, cy) = (f64::from(e.client_x()), f64::from(e.client_y()));
    if let Some(dev) = device_at(ctx, board, cx, cy, &[]) {
        return add_into(ctx, &kind, dev);
    }
    let Some(r) = board.get_untracked().map(|b| b.get_bounding_client_rect()) else {
        return;
    };
    let half = if kind == "device" {
        110.0
    } else {
        NODE_W / 2.0
    };
    add_at(
        ctx,
        &kind,
        (cx - r.left() - half).max(0.0),
        (cy - r.top() - 30.0).max(0.0),
    );
}
