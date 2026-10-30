// SPDX-License-Identifier: GPL-2.0-only
//! Status labels, evidence ranks and markup helpers.

/// Countermeasure statuses: `(value, label)`.
pub const CM_STATUS: [(&str, &str); 5] = [
    ("recommended", "Recommended"),
    ("required", "Required"),
    ("implemented", "Implemented"),
    ("rejected", "Rejected"),
    ("na", "Not applicable"),
];

/// Statuses that need a justification.
pub const NEEDS_WHY: [&str; 2] = ["na", "rejected"];

pub fn cm_label(status: &str) -> &str {
    CM_STATUS
        .iter()
        .find(|(v, _)| *v == status)
        .map_or(status, |(_, l)| l)
}

/// EMB3D evidence level: `(rank, label)`; lower ranks have more evidence.
pub fn maturity(m: &str) -> (u8, &str) {
    match m {
        "observed adversarial behavior" => (0, "Observed in attacks"),
        "observed adversarial technique" => (1, "Observed technique"),
        "known exploitable weakness" => (2, "Known weakness"),
        "proof of concept" => (3, "Proof of concept"),
        "custom" => (4, "Custom threat"),
        other => (9, other),
    }
}

pub fn mit_rank(m: &str) -> u8 {
    match m {
        "foundational" => 0,
        "intermediate" => 1,
        "leading" => 2,
        "custom" => 3,
        _ => 9,
    }
}

/// HTML escaping for every value written into markup.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out += "&amp;",
            '<' => out += "&lt;",
            '>' => out += "&gt;",
            '"' => out += "&quot;",
            '\'' => out += "&#39;",
            c => out.push(c),
        }
    }
    out
}

/// `pre`, `s`, `post` joined, or `""` when `s` is empty.
pub fn around(pre: &str, s: &str, post: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        format!("{pre}{s}{post}")
    }
}

/// Lower-case, runs of anything but `[0-9a-z-]` become `-`, trimmed.
pub fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() || c == '-' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_owned()
}

/// CSS class of a library group, e.g. `k-System`.
pub fn group_class(g: &str) -> String {
    format!("k-{}", g.split(' ').next().unwrap_or_default())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Open,
    Mitigated,
    Accepted,
    NotApplicable,
}

impl State {
    pub fn key(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Mitigated => "Mitigated",
            Self::Accepted => "Accepted",
            Self::NotApplicable => "NA",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::NotApplicable => "Not applicable",
            s => s.key(),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/engine/labels.rs"]
mod tests;
