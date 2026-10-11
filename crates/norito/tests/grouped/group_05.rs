//! Grouped Norito integration tests.
#[path = "../decode_sequence_limits.rs"]
mod decode_sequence_limits;
#[path = "../proptest_roundtrip.rs"]
mod proptest_roundtrip;
#[path = "../schema_hash.rs"]
mod schema_hash;
#[path = "../schema_sample_payload.rs"]
mod schema_sample_payload;
#[path = "../sequence_len_guard.rs"]
mod sequence_len_guard;
#[path = "../sequence_plan.rs"]
mod sequence_plan;
#[path = "../slice_seq_len_varint.rs"]
mod slice_seq_len_varint;
#[path = "../stream.rs"]
mod stream;
#[path = "../stream_iter.rs"]
mod stream_iter;
#[path = "../streaming_decode.rs"]
mod streaming_decode;
#[path = "../streaming_encoder_golden.rs"]
mod streaming_encoder_golden;
#[path = "../streaming_length_limit.rs"]
mod streaming_length_limit;
#[path = "../streaming_roundtrip.rs"]
mod streaming_roundtrip;
#[path = "../streaming_ticket_golden.rs"]
mod streaming_ticket_golden;
#[path = "../strict_safe.rs"]
mod strict_safe;
#[path = "../string_len_prefix.rs"]
mod string_len_prefix;
#[path = "../struct_index_golden.rs"]
mod struct_index_golden;
#[path = "../struct_index_golden_fixed.rs"]
mod struct_index_golden_fixed;
#[path = "../struct_index_golden_fixtures.rs"]
mod struct_index_golden_fixtures;
#[path = "../struct_index_golden_x86.rs"]
mod struct_index_golden_x86;
#[path = "../struct_index_golden_x86_16.rs"]
mod struct_index_golden_x86_16;
#[path = "../struct_index_random.rs"]
mod struct_index_random;
#[path = "../struct_index_random_x86.rs"]
mod struct_index_random_x86;
#[path = "../telemetry_aggregate_json.rs"]
mod telemetry_aggregate_json;
#[path = "../transport_capabilities.rs"]
mod transport_capabilities;
#[path = "../truncation.rs"]
mod truncation;
#[path = "../tuple_len_fallback.rs"]
mod tuple_len_fallback;
#[path = "../tuple_roundtrip_regressions.rs"]
mod tuple_roundtrip_regressions;
#[path = "../tx_like.rs"]
mod tx_like;
