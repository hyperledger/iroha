# Changelog

## v0.1.0 (unreleased)
- Revalidated parity after the Rust Norito fixed-width primitive decoders now
  reject archived elements shorter than the primitive width, closing an
  out-of-bounds read on truncated tuple/array/field elements; Kotlin bindings
  required no implementation changes beyond rerunning the parity suite because
  this is an internal Rust-side safety check.
