// SPDX-License-Identifier: GPL-2.0-only
//! Unit tests of `src/engine/labels.rs` (a child module of it, so private items are in reach).

use super::*;

#[test]
fn helpers() {
    assert_eq!(
        esc(r#"<a href="x">'&'</a>"#),
        "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
    );
    assert_eq!(slug("TID-101 Ünï  x"), "tid-101-n-x");
    assert_eq!(
        (maturity("custom").0, cm_label("na"), cm_label("??")),
        (4, "Not applicable", "??")
    );
}
