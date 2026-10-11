//! Shared genuine proof builder; no registered test cases.
//! Actual compact catalog closure. Every signed source chain is rebuilt under
//! the common outer key, with exact descriptor/key equality across the roundtrip.
//! Two/three terminal component catalogs are not the complete release catalog.

// Each consumer selects a subset of these genuine construction helpers.
#![allow(dead_code)]

/// Shared real controls-off Send and its authenticated predecessor builders.
#[path = "load_omega.rs"]
mod load_outer;

include!("compact_catalog_body.rs");
