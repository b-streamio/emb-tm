// SPDX-License-Identifier: GPL-2.0-only
//! Keyboard shortcuts and pasting JSON anywhere.

use std::collections::BTreeSet;

use leptos::{ev, prelude::*};

use super::{parse, web, Ctx, Sel, View};
use crate::ops::{Clip, CLIP_KEY};

/// Ctrl/⌘ C X V D A, Escape and pasting JSON anywhere.
pub(super) fn keyboard(ctx: Ctx) {
    let _ = window_event_listener(ev::keydown, move |e| on_key(ctx, &e));
    let _ = window_event_listener(ev::paste, move |e| on_paste(ctx, &e));
}

fn on_key(ctx: Ctx, e: &ev::KeyboardEvent) {
    let open = ctx.dialog.with_untracked(Option::is_some);
    if (e.ctrl_key() || e.meta_key())
        && !e.alt_key()
        && !web::typing_in_field()
        && !open
        && ctx.view.get_untracked() == View::Diagram
    {
        let handled = match e.key().to_lowercase().as_str() {
            "c" => !web::has_text_selection() && ctx.copy(false),
            "x" => ctx.copy(true),
            "d" => {
                ctx.duplicate();
                true
            }
            "a" => {
                select_all(ctx);
                true
            }
            _ => false,
        };
        if handled {
            e.prevent_default();
        }
        return;
    }
    if e.key() != "Escape" {
        return;
    }
    if open {
        ctx.dialog.set(None);
    } else if ctx.multi.with_untracked(|m| !m.is_empty()) {
        ctx.multi.update(BTreeSet::clear);
    } else if ctx.connect.get_untracked().is_some() {
        ctx.connect.set(None);
    }
}

/// Selects every block of the current page.
fn select_all(ctx: Ctx) {
    let page = ctx.page();
    let ids: Vec<u64> = ctx.project.with_untracked(|p| {
        p.page(&page)
            .map(|pg| pg.nodes.iter().map(|n| n.id).collect())
            .unwrap_or_default()
    });
    if let Some((first, rest)) = ids.split_first() {
        ctx.sel.set(Some(Sel::Node(*first)));
        ctx.multi.set(rest.iter().copied().collect());
    }
}

/// Copied blocks are pasted; other JSON opens as a project or TM-BOM.
fn on_paste(ctx: Ctx, e: &ev::ClipboardEvent) {
    if ctx.dialog.with_untracked(Option::is_some) || web::typing_in_field() {
        return;
    }
    let text = e
        .clipboard_data()
        .and_then(|d| d.get_data("text").ok())
        .unwrap_or_default();
    if text.contains(CLIP_KEY) {
        if let Some(c) = parse(&text)
            .ok()
            .and_then(|v| serde_json::from_value::<Clip>(v).ok())
        {
            e.prevent_default();
            ctx.view.set(View::Diagram);
            ctx.paste(&c, false, "", None);
            return;
        }
    }
    if text.trim_start().starts_with('{') {
        if let Err(err) = ctx.import(&text) {
            ctx.error("Could not open the pasted text", err);
        }
    } else if let Some(c) = ctx
        .clip
        .get_untracked()
        .filter(|_| ctx.view.get_untracked() == View::Diagram)
    {
        e.prevent_default();
        ctx.paste(&c, false, "", None);
    }
}
