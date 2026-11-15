// SPDX-License-Identifier: GPL-2.0-only
//! emb-tm: embedded-device threat modeling on MITRE EMB3D, as an
//! offline PWA and a command line. `stix`, `model`,
//! `engine` and `ops` are plain Rust; `ui` renders them with Leptos, `cli`
//! drives them from a terminal.

#[cfg(not(target_arch = "wasm32"))]
pub mod cli;
pub mod engine;
pub mod model;
pub mod ops;
pub mod stix;
pub mod ui;
