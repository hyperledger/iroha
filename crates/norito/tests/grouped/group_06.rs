//! Grouped Norito integration tests.
#[path = "../unsupported_compression_header.rs"]
mod unsupported_compression_header;
#[path = "../utf8_gate.rs"]
mod utf8_gate;
#[path = "../varint_boundaries.rs"]
mod varint_boundaries;
#[path = "../varint_fastpath.rs"]
mod varint_fastpath;
#[path = "../varint_helpers.rs"]
mod varint_helpers;
#[path = "../varint_ptr_overflow.rs"]
mod varint_ptr_overflow;
#[path = "../vecdeque_align.rs"]
mod vecdeque_align;
#[path = "../yaml_basic.rs"]
mod yaml_basic;
#[path = "../zero_sized_collections.rs"]
mod zero_sized_collections;

#[path = "../schema_identity.rs"]
mod schema_identity;
