//! Unit tests of `src/ui/inspector.rs` (a child module of it, so private items are in reach).

#[test]
fn short_iec_references() {
    assert_eq!(
        super::iec_short(&["EDR / HDR / NDR 3.14 – Integrity".into(), "CR 2.1".into()]),
        "3.14, 2.1"
    );
}

#[test]
fn states_have_css_keys() {
    assert_eq!(crate::engine::State::NotApplicable.key(), "NA");
}
