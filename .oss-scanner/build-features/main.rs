//! Cargo feature alignment for the OSS Scanner prebuilds.
//!
//! The scanner enables this package's `scanner` feature to reuse production
//! dependency artifacts while explicit target filters leave this binary unbuilt.
//! Ordinary workspace builds leave these optional dependencies disabled.

fn main() {}
