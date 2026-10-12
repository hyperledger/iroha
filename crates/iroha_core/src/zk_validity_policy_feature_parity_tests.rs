//! Feature-parity record of the committed ZK validity policy.
//!
//! One fixed scenario is executed and its certified history, policy
//! identities, limit decisions and verification gas are reduced to named
//! digests. The test prints them; `scripts/check_zk_feature_parity.py` builds
//! this crate under several Cargo feature selections, runs this test in each
//! and compares the lines. `must_equal` records have to agree across every
//! selection: a Cargo feature must not change a root, an effect or a gas
//! charge. `gated` records name an operation that is still compiled only
//! under a feature; each one corresponds to an open feature-gate entry of
//! `specs/zk_runtime_validity_census.json`, and the script fails when a gated
//! record and the census disagree.
//!
//! The record holds no pinned constant: it compares builds of one source
//! tree, so an intended change of block layout or execution does not need a
//! fixture update here.

use std::collections::BTreeMap;

use iroha_crypto::Hash;
use iroha_data_model::{
    isi::{InstructionBox, Log, SetParameter},
    parameter::Parameter,
    permission::Permission,
};
use iroha_executor_data_model::permission::parameter::CanSetParameters;
use iroha_test_samples::ALICE_KEYPAIR;

use super::{
    ZkValidityPolicyV1, alice_chain, alice_world, certified_history, committed_policy,
    four_byte_ballot_outcome_on_tip, header, next_header, policy_of, state_with,
};
use crate::state::{compute_zk_consensus_policy_hash, default_genesis_confidential_policy_hash};

/// Prefix of every line the comparison script reads.
const LINE_PREFIX: &str = "ZK_FEATURE_PARITY";

/// The named digests of one build.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ParityRecord {
    /// Records every feature selection must reproduce exactly.
    must_equal: BTreeMap<&'static str, String>,
    /// Records of operations still compiled only under a feature, keyed by
    /// `<feature>.<operation>`.
    gated: BTreeMap<&'static str, String>,
}

fn digest(parts: &[&[u8]]) -> String {
    // Length-prefixed concatenation: two different part lists never collide.
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(
            &u64::try_from(part.len())
                .expect("length fits")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(part);
    }
    hex::encode(Hash::new(bytes).as_ref())
}

fn digest_of_text(parts: &[String]) -> String {
    let slices: Vec<&[u8]> = parts.iter().map(String::as_bytes).collect();
    digest(&slices)
}

/// A certified history that installs the policy with an authorized
/// `SetParameter` and runs before, at and after the change.
fn history_record() -> (String, String, String) {
    let policy = committed_policy();
    let mut chain = alice_chain(
        alice_world([Permission::from(CanSetParameters)]),
        None,
        None,
    );
    chain.commit(Vec::new());
    let before = four_byte_ballot_outcome_on_tip(chain.state());
    let set: InstructionBox =
        SetParameter::new(Parameter::Custom(policy.clone().into_custom_parameter())).into();
    let transaction = chain.sign(&ALICE_KEYPAIR, [set], 1_001);
    assert_eq!(chain.commit(vec![transaction]), vec![true]);
    chain.commit(Vec::new());
    let after = four_byte_ballot_outcome_on_tip(chain.state());
    assert_eq!(policy_of(&chain.state().view().zk), policy);

    let mut parts: Vec<Vec<u8>> = Vec::new();
    for (result, core_hash, commitment, wire) in certified_history(&chain) {
        parts.push(result);
        parts.push(core_hash);
        parts.push(commitment.into_bytes());
        parts.push(wire);
    }
    let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let history = digest(&slices);
    let execution_policy = chain
        .state()
        .execution_policy_digest_v1()
        .expect("execution policy digest");
    let block = chain.state().block(next_header(chain.state()));
    let identities = digest(&[
        &execution_policy,
        &compute_zk_consensus_policy_hash(&block.zk),
        &default_genesis_confidential_policy_hash(),
    ]);
    drop(block);
    (history, identities, digest_of_text(&[before, after]))
}

/// Decisions of the committed work limits at the limit and one above it.
fn limit_record() -> String {
    let mut policy = ZkValidityPolicyV1::protocol_default();
    policy.confidential.max_nullifiers_per_tx = 5;
    policy.confidential.max_commitments_per_tx = 4;
    policy.confidential.max_proof_size_bytes = 4_096;
    policy.confidential.max_verify_calls_per_tx = 2;
    policy.confidential.max_verify_calls_per_block = 2;
    let state = state_with(None, Some(&policy));
    let mut block = state.block(header(2));
    let mut outcomes = Vec::new();
    {
        let mut transaction = block.transaction();
        outcomes.push(format!("{:?}", transaction.register_nullifiers(5)));
        outcomes.push(format!("{:?}", transaction.register_nullifiers(1)));
        outcomes.push(format!("{:?}", transaction.register_commitments(4)));
        outcomes.push(format!("{:?}", transaction.register_commitments(1)));
        outcomes.push(format!(
            "{:?}",
            transaction.register_confidential_proof(4_096)
        ));
        outcomes.push(format!(
            "{:?}",
            transaction.register_confidential_proof(4_097)
        ));
        outcomes.push(format!("{:?}", transaction.register_confidential_proof(8)));
        outcomes.push(format!("{:?}", transaction.register_confidential_proof(8)));
    }
    digest_of_text(&outcomes)
}

/// Gas of a fixed instruction list under the protocol-default schedule and
/// under a committed one, as the next block of each State charges it.
fn gas_record() -> String {
    use iroha_data_model::{
        isi::zk::VerifyProof,
        proof::{ProofAttachment, ProofBox, VerifyingKeyId},
    };

    let instructions: Vec<InstructionBox> = vec![
        Log::new(iroha_data_model::Level::INFO, "parity".to_owned()).into(),
        VerifyProof::new(ProofAttachment::new_ref(
            "stark/fri-v1".into(),
            ProofBox::new("stark/fri-v1".into(), vec![0xA5; 777]),
            VerifyingKeyId::new("stark/fri-v1", "parity"),
        ))
        .into(),
        VerifyProof::new(ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            ProofBox::new("pipa-r/pasta".into(), vec![0x5A; 333]),
            VerifyingKeyId::new("pipa-r/pasta", "parity"),
        ))
        .into(),
    ];
    let mut charges = Vec::new();
    for policy in [None, Some(committed_policy())] {
        let state = state_with(None, policy.as_ref());
        let block = state.block(next_header(&state));
        charges.push(crate::gas::meter_instructions(&instructions, &block.zk.gas).to_string());
        for instruction in &instructions {
            charges.push(crate::gas::confidential_gas_cost(instruction, &block.zk.gas).to_string());
        }
    }
    digest_of_text(&charges)
}

/// Whether the real native STARK fixture proof is accepted by this build, as
/// its certified history records it.
#[cfg(feature = "zk-stark")]
fn stark_real_proof_record() -> String {
    use iroha_data_model::{
        confidential::ConfidentialStatus,
        isi::{verifying_keys::RegisterVerifyingKey, zk::VerifyProof},
        proof::{ProofAttachment, VerifyingKeyId, VerifyingKeyRecord},
        zk::BackendTag,
    };
    use iroha_executor_data_model::permission::governance::CanManageVerifyingKeys;

    let backend = crate::zk::ZK_BACKEND_STARK_FRI_V1;
    let fixture = crate::zk::test_utils::stark_public_binding_fixture_envelope();
    let proof = fixture.proof_box(backend);
    let key = fixture
        .vk_box(backend)
        .expect("the fixture carries its key");
    let key_id = VerifyingKeyId::new(backend, "feature-parity-public-binding");
    let mut record = VerifyingKeyRecord::new_with_owner(
        1,
        format!("{backend}:public-binding-demo"),
        None,
        "test",
        BackendTag::Stark,
        "goldilocks",
        fixture.schema_hash,
        crate::zk::hash_vk(&key),
    );
    record.vk_len = u32::try_from(key.bytes.len()).expect("key length fits u32");
    record.status = ConfidentialStatus::Active;
    record.key = Some(key);
    record.gas_schedule_id = Some("stark_default".to_owned());
    let register: InstructionBox = RegisterVerifyingKey {
        id: key_id.clone(),
        record,
    }
    .into();
    let verify: InstructionBox =
        VerifyProof::new(ProofAttachment::new_ref(backend.into(), proof, key_id)).into();
    let mut world = alice_world([Permission::from(CanManageVerifyingKeys)]);
    world.executor = mv::cell::Cell::new(super::admit_all_executor());
    let mut chain = alice_chain(world, None, None);
    let register_tx = chain.sign(&ALICE_KEYPAIR, [register], 1);
    let registered = chain.commit(vec![register_tx]);
    let verify_tx = chain.sign(&ALICE_KEYPAIR, [verify], 1_001);
    let verified = chain.commit(vec![verify_tx]);
    format!("registered={registered:?} verified={verified:?}")
}

/// Without the `zk-stark` feature the native STARK verifier and its fixture
/// are not compiled, so the operation cannot run in this build.
#[cfg(not(feature = "zk-stark"))]
fn stark_real_proof_record() -> String {
    "not-compiled".to_owned()
}

fn build_record() -> ParityRecord {
    let (history, identities, ballot_outcomes) = history_record();
    let mut record = ParityRecord::default();
    record.must_equal.insert("certified_history", history);
    record.must_equal.insert("policy_identities", identities);
    record
        .must_equal
        .insert("size_limit_outcomes", ballot_outcomes);
    record.must_equal.insert("work_limits", limit_record());
    record.must_equal.insert("verification_gas", gas_record());
    record
        .gated
        .insert("zk-stark.real_proof", stark_real_proof_record());
    record
}

/// Cargo features of this build that the comparison script reports.
fn compiled_features() -> String {
    let mut features = Vec::new();
    for (name, enabled) in [
        ("zk-stark", cfg!(feature = "zk-stark")),
        ("zk-ipa-native", cfg!(feature = "zk-ipa-native")),
        ("zk-preverify", cfg!(feature = "zk-preverify")),
        ("sm", cfg!(feature = "sm")),
        ("gost", cfg!(feature = "gost")),
        ("bls", cfg!(feature = "bls")),
        ("telemetry", cfg!(feature = "telemetry")),
        ("app_api", cfg!(feature = "app_api")),
        ("simd", cfg!(feature = "simd")),
    ] {
        if enabled {
            features.push(name);
        }
    }
    features.join(",")
}

#[test]
fn feature_parity_record() {
    let record = build_record();
    // Every record is a digest or a short outcome; none is empty.
    assert_eq!(record.must_equal.len(), 5);
    for value in record.must_equal.values() {
        assert_eq!(value.len(), 64, "a 32-byte digest in hexadecimal");
    }
    assert!(record.gated.contains_key("zk-stark.real_proof"));
    if cfg!(feature = "zk-stark") {
        assert_eq!(
            record.gated["zk-stark.real_proof"], "registered=[true] verified=[true]",
            "the real proof is accepted where the verifier is compiled"
        );
    }
    // The scenario is deterministic: a second run in this build reproduces it.
    assert_eq!(build_record(), record);
    // The digests separate their inputs.
    assert_ne!(digest(&[b"ab", b"c"]), digest(&[b"a", b"bc"]));
    assert_ne!(
        digest_of_text(&["a".to_owned()]),
        digest_of_text(&["b".to_owned()])
    );

    // The harness prints the test name without a line break first.
    println!();
    println!("{LINE_PREFIX} features={}", compiled_features());
    for (name, value) in &record.must_equal {
        println!("{LINE_PREFIX} must_equal.{name}={value}");
    }
    for (name, value) in &record.gated {
        println!("{LINE_PREFIX} gated.{name}={value}");
    }
}
