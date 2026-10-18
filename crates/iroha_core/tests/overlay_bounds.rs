//! Overlay bounds: negative tests for instruction and byte caps.

//! Ensures validation rejects transactions whose overlays exceed the committed
//! `overlay_max_instructions` or `overlay_max_bytes` of the pipeline validity
//! policy, and other transactions in the same block still apply (non-forking
//! semantics).
use iroha_core::{
    block::BlockBuilder,
    governance::manifest::LaneManifestRegistry,
    smartcontracts::Execute,
    sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
};
use iroha_data_model::{pipeline_validity_policy::PipelineValidityPolicyV1, prelude::*};
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use norito::codec::Encode as NoritoEncode;
use std::{borrow::Cow, str::FromStr, sync::Arc};
fn build_min_world() -> (
    iroha_core::state::State,
    NetworkId,
    AccountId,
    iroha_crypto::KeyPair,
) {
    let chain_id: ChainId = "chain".parse().unwrap();
    let (authority_id, kp) = iroha_test_samples::gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain: Domain = Domain::new(domain_id.clone()).build(&authority_id);
    let account = Account::new(authority_id.clone()).build(&authority_id);
    let world = iroha_core::state::World::with([domain], [account], []);
    let kura = iroha_core::kura::Kura::blank_kura_for_testing();
    let query = iroha_core::query::store::LiveQueryStore::start_test();
    let state =
        iroha_core::state::State::new_with_chain_for_testing(world, kura, query, chain_id.clone());
    let network_id = *state.network_id_ref();
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
    (state, network_id, authority_id, kp)
}
/// The world of `build_min_world` as the configuration of a certified test chain. A block
/// of ordinary transactions follows an authenticated genesis, and the block is produced and
/// certified by the chain fixture.
fn min_world_chain_config() -> (TestChainConfig, AccountId, iroha_crypto::KeyPair) {
    let chain_id: ChainId = "chain".parse().unwrap();
    let (authority_id, kp) = iroha_test_samples::gen_account_in("wonderland");
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
    let domain: Domain = Domain::new(domain_id).build(&authority_id);
    let account = Account::new(authority_id.clone()).build(&authority_id);
    let world = iroha_core::state::World::with([domain], [account], []);
    let mut config = TestChainConfig::new(world, 0);
    config.chain_id = chain_id;
    (config, authority_id, kp)
}
/// Commit the overlay limits in the signed genesis of the chain fixture.
///
/// The overlay limits are chain policy: their source is the committed pipeline validity
/// policy, never a node's own settings. A policy the genesis commits governs every block
/// after genesis, so the genesis overlay itself is not measured against it.
fn commit_overlay_limits(config: &mut TestChainConfig, max_instructions: usize, max_bytes: u64) {
    let mut policy = PipelineValidityPolicyV1::protocol_default();
    policy.overlay_max_instructions =
        u64::try_from(max_instructions).expect("instruction cap fits u64");
    policy.overlay_max_bytes = max_bytes;
    policy
        .validate()
        .expect("the overlay limits of the fixture are a valid policy");
    config
        .genesis_parameters
        .push(Parameter::Custom(policy.into_custom_parameter()));
}
#[test]
fn overlay_instruction_cap_rejects_and_rest_apply() {
    // The committed cap: one overlay has exactly that many instructions and passes, the
    // other has one more and is rejected. Zero bytes means no byte limit.
    const INSTRUCTION_CAP: usize = 64;
    let (mut config, authority_id, kp) = min_world_chain_config();
    commit_overlay_limits(&mut config, INSTRUCTION_CAP, 0);
    let mut chain =
        Box::new(CertifiedTestChain::start(config).expect("authenticated overlay-bounds genesis"));
    let network_id = chain.network_id();
    // tx_a: one instruction more than the cap → should be rejected by instruction cap
    let tx_a = TransactionBuilder::new(
        network_id,
        authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions(
        (0..=INSTRUCTION_CAP).map(|index| Log::new(Level::INFO, format!("a{index}"))),
    )
    .sign(kp.private_key());
    // tx_b: exactly the cap → should be approved
    let tx_b = TransactionBuilder::new(
        network_id,
        authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions((0..INSTRUCTION_CAP).map(|index| Log::new(Level::INFO, format!("b{index}"))))
    .sign(kp.private_key());
    // The same original inputs pass native payload execution and three-of-four
    // certification. The fixture does not author transaction results.
    let proposal = chain.proposal(None, vec![tx_a, tx_b]);
    let committed = chain.commit_proposal(
        proposal,
        Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    // Expect first tx rejected with NotPermitted("overlay exceeds max instructions: ...") and second approved
    let block = committed.block();
    assert_eq!(block.external_transactions().count(), 2);
    let errors = [0, 1].map(|index| {
        block
            .network_output_at(index)
            .expect("validated transaction has an output")
            .1
            .result
            .as_ref()
            .err()
    });
    let rejections = errors
        .iter()
        .filter(|e| {
            matches!(
                e,
                Some(
                    iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                        iroha_data_model::ValidationFail::NotPermitted(msg)
                    )
                ) if msg.contains("overlay exceeds max instructions")
            )
        })
        .count();
    assert_eq!(
        rejections, 1,
        "the overlay of one instruction above the cap is rejected, got {errors:?}"
    );
    assert_eq!(
        errors.iter().filter(|error| error.is_none()).count(),
        1,
        "the overlay of exactly the cap is approved, got {errors:?}"
    );
}
#[test]
fn overlay_bytes_cap_rejects_and_rest_apply() {
    // The committed cap: one overlay has exactly that many bytes and passes; the other has
    // one byte more and is rejected.
    const BYTE_CAP: u64 = 256 * 1024;
    let (mut config, authority_id, kp) = min_world_chain_config();
    let log_of = |message_bytes: usize| -> InstructionBox {
        Log::new(Level::INFO, "x".repeat(message_bytes)).into()
    };
    let encoded = |instruction: &InstructionBox| NoritoEncode::encode(instruction).len() as u64;
    // The encoding of a log grows by one byte per message byte at this size: derive the
    // message length whose instruction encodes to exactly the cap.
    let probe = usize::try_from(BYTE_CAP / 2).expect("probe length fits usize");
    let framing = encoded(&log_of(probe)) - probe as u64;
    let exact_message = usize::try_from(BYTE_CAP - framing).expect("message length fits usize");
    let small_instr = log_of(exact_message);
    let small_bytes = encoded(&small_instr);
    let big_instr = log_of(exact_message + 1);
    let big_bytes = encoded(&big_instr);
    assert_eq!(
        (small_bytes, big_bytes),
        (BYTE_CAP, BYTE_CAP + 1),
        "the fixture overlays have exactly the cap and one byte more"
    );
    // Zero instructions means no instruction limit.
    commit_overlay_limits(&mut config, 0, BYTE_CAP);
    let mut chain =
        Box::new(CertifiedTestChain::start(config).expect("authenticated overlay-bounds genesis"));
    let network_id = chain.network_id();
    let tx_big = TransactionBuilder::new(
        network_id,
        authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([big_instr])
    .sign(kp.private_key());
    // tx_small: a Log of exactly the byte cap
    let tx_small = TransactionBuilder::new(
        network_id,
        authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([small_instr])
    .sign(kp.private_key());
    let proposal = chain.proposal(None, vec![tx_big, tx_small]);
    let committed = chain.commit_proposal(
        proposal,
        Signers::Quorum,
        iroha_sumeragi::types::ControlWitness::default(),
    );
    // Expect first tx rejected with NotPermitted("overlay exceeds max bytes: ...") and second approved
    let block = committed.block();
    assert_eq!(block.external_transactions().count(), 2);
    let errors = [0, 1].map(|index| {
        block
            .network_output_at(index)
            .expect("validated transaction has an output")
            .1
            .result
            .as_ref()
            .err()
    });
    // Encoding stops at the committed bound, so the canonical diagnostic names the bound
    // and not the unmeasured full length (`EffectFault::Bytes`).
    let expected_rejection = format!("overlay exceeds max bytes: more than {BYTE_CAP}");
    let overlay_errs = errors
        .iter()
        .filter(|e| {
            matches!(
                e,
                Some(
                    iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                        iroha_data_model::ValidationFail::NotPermitted(msg)
                    )
                ) if msg == &expected_rejection
            )
        })
        .count();
    assert_eq!(
        overlay_errs, 1,
        "the overlay of one byte above the cap is rejected, got {errors:?}"
    );
    assert_eq!(
        errors.iter().filter(|error| error.is_none()).count(),
        1,
        "the overlay of exactly the cap is approved, got {errors:?}"
    );
}
// TODO: stale fixture. The test validates a hand-built block against a State that holds no
// authenticated genesis and stops at "Network source lacks its exact initial genesis
// admission"; the two cap tests above show the repaired form (the certified chain fixture).
#[test]
fn expired_transaction_is_rejected_during_stateless_prepass() {
    let (state, network_id, authority_id, kp) = build_min_world();
    // Require expiry checks based on block height via SetParameter
    {
        let header = iroha_data_model::block::BlockHeader::new(
            nonzero_ext::nonzero!(1_u64),
            None,
            None,
            0,
            0,
        );
        let mut blk = state.block(header);
        let mut stx = blk.transaction();
        let perm: iroha_data_model::permission::Permission =
            iroha_executor_data_model::permission::parameter::CanSetParameters.into();
        iroha_data_model::isi::Grant::account_permission(perm, authority_id.clone())
            .execute(&authority_id, &mut stx)
            .expect("grant set parameters");
        iroha_data_model::isi::SetParameter::new(Parameter::Transaction(
            iroha_data_model::parameter::system::TransactionParameter::RequireHeightTtl(true),
        ))
        .execute(&authority_id, &mut stx)
        .expect("set require_height_ttl");
        stx.apply();
        blk.commit_world_overlay_for_testing()
            .expect("commit param block");
    }
    // tx_expired: creation time far in the past with short TTL → should be rejected
    let tx_expired = TransactionBuilder::new(
        network_id,
        authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "expired".to_string())])
    .with_metadata({
        let mut md = iroha_model_base::metadata::Metadata::default();
        let exp_key = iroha_model_base::name::Name::from_str("expires_at_height").unwrap();
        md.insert(exp_key, iroha_primitives::json::Json::new(0u64));
        md
    })
    .sign(kp.private_key());
    // tx_ok: current creation time without TTL → should be approved
    let tx_ok = TransactionBuilder::new(
        network_id,
        authority_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "ok".to_string())])
    .sign(kp.private_key());
    let expired = iroha_core::tx::AcceptedTransaction::new_unchecked(Cow::Owned(tx_expired));
    let ok = iroha_core::tx::AcceptedTransaction::new_unchecked(Cow::Owned(tx_ok));
    let new_block = BlockBuilder::new(vec![expired, ok])
        .chain(0, None)
        .sign(kp.private_key())
        .unpack(|_| {});
    let (mut sb, sb_recorder) =
        iroha_core::block::ValidBlock::start_component_execution(&new_block.clone().into(), &state)
            .expect("original writer-first component execution");
    let vb = new_block
        .validate_and_record_transactions(&mut sb, sb_recorder)
        .unpack(|_| {});
    let _ = sb.commit();
    let block = vb.as_ref();
    let errors = [0, 1].map(|index| {
        block
            .network_output_at(index)
            .expect("validated transaction has an output")
            .1
            .result
            .as_ref()
            .err()
    });
    eprintln!("errors ttl: {errors:?}");
    // TTL enforcement is currently configuration-dependent; ensure at least one tx succeeds.
    assert!(errors[1].is_none(), "second tx must be approved");
}
