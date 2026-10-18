//! Actual shared producers must not turn permanent refusal into an AMX retry.

use super::*;
use axum::response::IntoResponse as _;

fn status(error: impl Into<Error>) -> StatusCode {
    error.into().into_response().status()
}

#[test]
fn canonical_response_limit_is_terminal_before_allocation() {
    let payload = 42_u64;
    let length = norito::canonical_frame_len(&payload).unwrap();
    let budget = AllocationBudget::new(length);
    let error = encode_canonical(&payload, length - 1, &budget)
        .err()
        .expect("the fixed response cap must reject");
    assert_ne!(status(error), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn canonical_impossible_pool_demand_is_terminal_but_occupied_pool_retries() {
    let payload = 42_u64;
    let length = norito::canonical_frame_len(&payload).unwrap();
    let impossible = AllocationBudget::new(length - 1);
    let error = encode_canonical(&payload, length, &impossible)
        .err()
        .expect("the original pool cannot ever fit the backing");
    assert_ne!(status(error), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(impossible.reserved_bytes(), 0);

    let budget = AllocationBudget::new(length);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    let error = encode_canonical(&payload, length, &budget)
        .err()
        .expect("the occupied original pool must refuse");
    assert_eq!(status(error), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(budget.reserved_bytes(), 1);
    drop(occupied);
    let encoded = encode_canonical(&payload, length, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), length);
    drop(encoded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn json_response_limit_and_impossible_pool_are_terminal() {
    let payload = 42_u64;
    let budget = AllocationBudget::new(2);
    let error = encode(&payload, ResponseFormat::Json, 1, &budget)
        .err()
        .expect("two JSON bytes exceed the fixed cap");
    assert_ne!(status(error), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(budget.reserved_bytes(), 0);
    let impossible = AllocationBudget::new(1);
    let error = encode(&payload, ResponseFormat::Json, 2, &impossible)
        .err()
        .expect("two JSON bytes cannot fit this pool");
    assert_ne!(status(error), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(impossible.reserved_bytes(), 0);
}

#[derive(norito::derive::NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii.native_projection_response.test.UnsupportedJson")]
struct UnsupportedJson(u64);
impl norito::json::JsonSerialize for UnsupportedJson {
    fn json_serialize(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(&self.0, out);
    }
}

#[test]
fn unsupported_checked_json_is_terminal_without_output_backing() {
    let budget = AllocationBudget::new(128);
    let error = encode(&UnsupportedJson(42), ResponseFormat::Json, 128, &budget)
        .err()
        .expect("the serializer has no bounded writer");
    assert_ne!(status(error), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn committee_geometry_and_cardinality_are_terminal() {
    let key = iroha_crypto::KeyPair::from_seed(vec![91; 32], iroha_crypto::Algorithm::BlsNormal);
    let pop = iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap();
    for error in [
        native_committee_original_bytes(usize::MAX, std::iter::empty()).unwrap_err(),
        native_committee_original_bytes(2, [(key.public_key(), pop.as_slice())]).unwrap_err(),
        native_committee_original_bytes(0, [(key.public_key(), pop.as_slice())]).unwrap_err(),
    ] {
        assert_ne!(status(error), StatusCode::TOO_MANY_REQUESTS);
    }
}

fn limits() -> NativeFinalityLimits {
    use iroha_data_model::sumeragi::finality::{
        NATIVE_FINALITY_MAX_BLOCK_BYTES, NATIVE_FINALITY_MAX_JOURNAL_BYTES,
    };
    NativeFinalityLimits {
        block_bytes: NATIVE_FINALITY_MAX_BLOCK_BYTES,
        journal_bytes: NATIVE_FINALITY_MAX_JOURNAL_BYTES,
        block_count: 8,
        allocated_bytes: 128 * 1024 * 1024,
    }
}

fn unavailable() -> Error {
    conversion_error("native producer test source unavailable".into())
}

#[test]
fn current_root_tip_preserves_actual_second_root_read_refusal() {
    let (chain, approval, _signer) =
        iroha_core::sumeragi::test_chain::native_amx_approval_route_fixture();
    let view = chain.state().view();
    let scope = iroha_data_model::block::consensus::SumeragiRootScope::Dataspace {
        parent_network_id: approval.global_network,
        dataspace_id: approval.dataspace,
    };
    let outer = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        64,
    ));
    let error = outer
        .with(|| current_root_tip(&view, 2, scope, limits(), unavailable))
        .err()
        .expect("actual root JSON decoding must refuse the original zero allocation scope");
    assert_eq!(status(error), StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn current_tip_invalid_or_insufficient_source_policy_is_terminal() {
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1))
        .map_err(|error| error.error)
        .unwrap();
    chain.commit_at(1_000, Vec::new());
    let view = chain.state().view();
    for limits in [
        NativeFinalityLimits {
            block_bytes: 0,
            ..limits()
        },
        NativeFinalityLimits {
            block_bytes: 1,
            ..limits()
        },
    ] {
        let error = current_global_tip(&view, 2, limits, unavailable)
            .err()
            .expect("the unchanged source policy cannot supply this cut");
        assert_ne!(status(error), StatusCode::TOO_MANY_REQUESTS);
    }
}

#[derive(norito::derive::NoritoSerialize, norito::NoritoSchema)]
#[norito_schema(name = "iroha_torii.native_projection_response.test.DecodingJson")]
struct DecodingJson(u64);
impl norito::json::JsonSerialize for DecodingJson {
    fn json_serialize(&self, out: &mut String) {
        norito::json::JsonSerialize::json_serialize(&self.0, out);
    }
    fn json_serialize_to(&self, out: &mut dyn JsonWriteSink) -> Result<(), BoundedJsonError> {
        let value: String = norito::json::from_str("\"native response test\"")
            .map_err(|cause| BoundedJsonError::from_decode_resource(cause.into_core_error()))?;
        norito::json::JsonSerialize::json_serialize_to(&value, out)
    }
}

#[test]
fn response_serializer_retains_its_actual_enclosing_decode_owner() {
    let budget = AllocationBudget::new(128);
    let outer = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        64,
    ));
    let original = outer
        .with(|| encode(&DecodingJson(42), ResponseFormat::Json, 128, &budget))
        .err()
        .expect("actual string decoding refuses the original outer allocation budget");
    let NativeProjectionError::Encoding(cause) = &original else {
        panic!("original serializer failure was replaced: {original}");
    };
    assert_eq!(
        cause.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert!(cause.local_refusal().is_some());
    assert_eq!(status(original), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(budget.reserved_bytes(), 0);
}
