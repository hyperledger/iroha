//! Public-boundary tests for the SCCP v1 state, record, registry, light-client and event types and
//! the v1 instruction structs.
//!
//! Covers `specs/sccp.md` §3.5, §4.4, §4.5, §4.11–§4.17 and §4.19: stable schema names and
//! instruction ids, binary (bare, headered and slice) and JSON roundtrips of every type and
//! instruction, closed JSON objects, unknown enum tags (including the unassigned tags of the
//! retired attestation transport) and trailing bytes, the route escrow derivation
//! (deterministic, distinct per route and `NetworkId`, revision-free) and the bounds of the
//! opaque proof, advance and evidence wrappers.

use hex_literal::hex;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::AssetDefinitionId,
    block::BlockHeader,
    bridge::SccpNetworkV1,
    isi::{
        Instruction,
        sccp::{
            AdvanceSccpLightClientV1, InitializeSccpV1, RecordSccpMessage,
            ReportSccpLightClientEquivocationV1, SccpSettleInboundV1, SccpSettleRefundV1,
            SccpSettleTargetV1, SettleSccpV1, SubmitSccpInboundMessageV1, SubmitSccpOutboundVoidV1,
        },
    },
    sccp::{
        bounded_bytes::SccpBoundedBytesError,
        commitment::{SCCP_HISTORY_MAX_SIZE_V1, SccpBlockCommitmentV1, SccpHistoryStateV1},
        control::{
            SCCP_FIRST_CONTROL_NONCE_V1, SccpControlLeafRefV1, SccpControlRecordV1, SccpLeafRefV1,
            SccpTransferLeafRefV1,
        },
        deployment::{SccpDeploymentV1, SccpEvmDeploymentV1},
        escrow::{
            SCCP_ROUTE_ESCROW_DOMAIN_V1, SCCP_TAIRA_XOR_ASSET_DEFINITION_ID_V1,
            SCCP_XOR_ASSET_ID_TEXT, sccp_route_escrow_account_id_v1,
            sccp_taira_xor_asset_definition_id, sccp_xor_route_escrow_account_id_v1,
        },
        events::{
            SccpBlockCommittedV1, SccpBounceReasonV1, SccpCommitteeGenerationCreatedV1,
            SccpCommitteeResyncV1, SccpControlRecordedV1, SccpEvent, SccpEventSet,
            SccpFastPauseLapsedV1, SccpFinalityDegradedReasonV1, SccpFinalityDegradedV1,
            SccpGenerationDestinationClearedV1, SccpGenerationMemberUnslashableV1,
            SccpGovernanceEnactedV1, SccpInboundBouncedV1, SccpInboundLiabilityShortfallV1,
            SccpInboundProvenV1, SccpInboundReleasedV1, SccpLightClientAdvancedV1,
            SccpLightClientFrozenV1, SccpLightClientInitializedV1, SccpMessageRecordedV1,
            SccpOutboundRefundedV1, SccpOutboundStrandedV1, SccpOutboundVoidedV1,
            SccpRecipientRegisteredV1, SccpRevisionActivationChangedV1, SccpStrandedReleasedV1,
            SccpTrustedCheckpointInstalledV1,
        },
        generation::SccpGenerationCauseV1,
        governance::SccpGovernanceSubjectV1,
        inbound::{
            SCCP_SOURCE_PROOF_MAX_BYTES_V1, SccpBounceStatusV1, SccpInboundRecordV1,
            SccpInboundStatusV1, SccpPendingReasonV1, SccpPendingStatusV1, SccpSourceLocatorV1,
            SccpSourceProofBytesV1,
        },
        light_client::{
            SCCP_LC_ADVANCE_MAX_BYTES_V1, SCCP_LC_EVIDENCE_MAX_BYTES_V1, SccpLcAdvanceBytesV1,
            SccpLcConsensusSetV1, SccpLcEquivocationFreezeV1, SccpLcEvidenceBytesV1,
            SccpLcFreezeReasonV1, SccpLcHeadV1, SccpLcParliamentFreezeV1, SccpLcPointV1,
            SccpLightClientParamsV1, SccpLightClientV1,
        },
        outbound::{
            SccpOutboundMessageRecordV1, SccpOutboundStatusV1, SccpStatusHeightV1, SccpVoidKindV1,
            SccpVoidStatusV1,
        },
        params::SccpParametersV1,
        registry::{
            SCCP_ROUTE_ID_TAIRA_BSC_XOR_V1, SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1,
            SCCP_ROUTE_ID_TAIRA_TON_XOR_V1, SccpRouteActivationV1, SccpRouteRevisionV1,
            SccpRouteV1, route_id_for,
        },
    },
};
use iroha_primitives::numeric::Numeric;
use norito::{
    NoritoSchema,
    codec::{DecodeAll, Encode},
    core::DecodeFromSlice,
    json::Value,
};
use std::collections::{BTreeMap, BTreeSet};

const ETH: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const BSC: SccpNetworkV1 = SccpNetworkV1::BscMainnet;
const TON: SccpNetworkV1 = SccpNetworkV1::TonMainnet;
const TAIRA: SccpNetworkV1 = SccpNetworkV1::SoraTaira;
const EXTERNAL: [SccpNetworkV1; 3] = [ETH, BSC, TON];
const ACTIVATIONS: [SccpRouteActivationV1; 5] = [
    SccpRouteActivationV1::Staged,
    SccpRouteActivationV1::Bidirectional,
    SccpRouteActivationV1::Paused,
    SccpRouteActivationV1::InboundOnly,
    SccpRouteActivationV1::Retired,
];

// ---------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------

fn network_id(seed: u8) -> NetworkId {
    NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        [seed; Hash::LENGTH],
    )))
}

fn key_pair(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("deterministic Ed25519 seed")
}

fn account(seed: u8) -> AccountId {
    AccountId::new(key_pair(seed.wrapping_add(0x80)).public_key().clone())
}

fn evm(seed: u8) -> SccpDeploymentV1 {
    SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
        address: [seed; 20],
        runtime_code_hash: [0xc0; 32],
    })
}

fn revision(number: u32, activation: SccpRouteActivationV1) -> SccpRouteRevisionV1 {
    SccpRouteRevisionV1 {
        activation,
        ever_activated: activation != SccpRouteActivationV1::Staged,
        liability: u128::from(number) * 1_000_000_000,
        next_outbound_nonce: u64::from(number) * 3,
        ..SccpRouteRevisionV1::staged(
            number,
            evm(u8::try_from(number).expect("small revision")),
            iroha_data_model::sccp::deployment::SccpCommitteePinV1 {
                generation: 1,
                committee_root: [0x44; 32],
                start_height: 1,
                until_ms: 1_801_209_600_000,
            },
            21_000_000_000_000_000,
            100,
        )
    }
}

fn locator() -> SccpSourceLocatorV1 {
    SccpSourceLocatorV1 {
        source_height: 21_000_000,
        block_hash: [0x77; 32],
        index_in_block: 12,
    }
}

fn point() -> SccpLcPointV1 {
    SccpLcPointV1 {
        source_height: 21_000_000,
        block_hash: [0x21; 32],
        source_time_ms: 1_758_000_000_000,
    }
}

fn head() -> SccpLcHeadV1 {
    SccpLcHeadV1 {
        latest_set_id: 1_400,
        latest_finalized: point(),
        last_progress_taira_ms: 1_758_000_100_000,
    }
}

fn freeze_reasons() -> [SccpLcFreezeReasonV1; 2] {
    [
        SccpLcFreezeReasonV1::Equivocation(SccpLcEquivocationFreezeV1 {
            evidence_hash: [0x51; 32],
        }),
        SccpLcFreezeReasonV1::Parliament(SccpLcParliamentFreezeV1 {
            proposal_id: [0x52; 32],
        }),
    ]
}

fn light_client(network: SccpNetworkV1, frozen: Option<SccpLcFreezeReasonV1>) -> SccpLightClientV1 {
    SccpLightClientV1 {
        params: SccpLightClientParamsV1::defaults_for(network).expect("external network"),
        head: head(),
        frozen,
        state_hash: [0x61; 32],
    }
}

fn outbound_statuses() -> [SccpOutboundStatusV1; 5] {
    [
        SccpOutboundStatusV1::Recorded,
        SccpOutboundStatusV1::Voided(SccpVoidStatusV1 {
            kind: SccpVoidKindV1::Expired,
            proven_at_height: 10,
            refund_pending: false,
        }),
        SccpOutboundStatusV1::Voided(SccpVoidStatusV1 {
            kind: SccpVoidKindV1::Frozen,
            proven_at_height: 11,
            refund_pending: true,
        }),
        SccpOutboundStatusV1::Refunded(SccpStatusHeightV1 { height: 12 }),
        SccpOutboundStatusV1::Stranded(SccpStatusHeightV1 { height: 13 }),
    ]
}

fn outbound(status: SccpOutboundStatusV1) -> SccpOutboundMessageRecordV1 {
    SccpOutboundMessageRecordV1 {
        network: TON,
        revision: 1,
        nonce: 41,
        height: 7_200,
        commitment_index: 3,
        deadline_ms: 1_758_604_800_000,
        sender: account(1),
        amount: (1_u128 << 96) - 1,
        payload: vec![0x02, 0x01, 0x00, 0x00, 0x00, 0x00],
        leaf: [0x99; 32],
        status,
    }
}

fn inbound_statuses() -> [SccpInboundStatusV1; 5] {
    [
        SccpInboundStatusV1::pending(SccpPendingReasonV1::Disabled),
        SccpInboundStatusV1::pending(SccpPendingReasonV1::RevisionNotSettleable),
        SccpInboundStatusV1::pending(SccpPendingReasonV1::LiabilityShortfall),
        SccpInboundStatusV1::Released(SccpStatusHeightV1 { height: 90 }),
        SccpInboundStatusV1::Bounced(SccpBounceStatusV1 {
            bounce_message_id: [0x88; 32],
        }),
    ]
}

fn inbound(status: SccpInboundStatusV1) -> SccpInboundRecordV1 {
    SccpInboundRecordV1 {
        network: BSC,
        revision: 2,
        payload: vec![0x02, 0x01, 0x00, 0x00, 0x00, 0x02],
        source_locator: locator(),
        proven_at_height: 88,
        fee_due: 10_000_000,
        status,
    }
}

fn proof(len: usize) -> SccpSourceProofBytesV1 {
    SccpSourceProofBytesV1::new(vec![0x4e; len]).expect("bounded proof")
}

fn advance(len: usize) -> SccpLcAdvanceBytesV1 {
    SccpLcAdvanceBytesV1::new(vec![0x41; len]).expect("bounded advance")
}

fn evidence(len: usize) -> SccpLcEvidenceBytesV1 {
    SccpLcEvidenceBytesV1::new(vec![0x45; len]).expect("bounded evidence")
}

/// Codec index of every event variant, in declaration order. Indices 2 to 9 belonged to the
/// events of the attestation transport and stay unassigned.
const EVENT_CODEC_INDICES: [u32; 24] = [
    0, 1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];

/// JSON tags of the events deleted with the attestation transport (§4.17).
const RETIRED_EVENT_TAGS: [&str; 8] = [
    "subject_created",
    "attestation_signed",
    "block_attested",
    "roster_generation_created",
    "roster_derivation_failed",
    "handoff_stalled",
    "bridge_key_set",
    "attestation_fault",
];

/// One event of every variant, in declaration order, with its JSON tag.
fn every_event() -> Vec<(SccpEvent, &'static str)> {
    vec![
        (
            SccpEvent::MessageRecorded(SccpMessageRecordedV1 {
                message_id: [1; 32],
                network: ETH,
                revision: 1,
                nonce: 0,
                height: 10,
                commitment_index: 0,
                deadline_ms: 1_758_604_800_000,
            }),
            "message_recorded",
        ),
        (
            SccpEvent::BlockCommitted(SccpBlockCommittedV1 {
                height: 10,
                root: [2; 32],
                count: 512,
                history_size: 4,
            }),
            "block_committed",
        ),
        (
            SccpEvent::InboundProven(SccpInboundProvenV1 {
                message_id: [8; 32],
                network: TON,
                revision: 1,
                amount: u128::MAX,
                source_locator: locator(),
                fee_due: 0,
            }),
            "inbound_proven",
        ),
        (
            SccpEvent::RecipientRegistered(SccpRecipientRegisteredV1 {
                account: account(3),
                network: TON,
                message_id: None,
            }),
            "recipient_registered",
        ),
        (
            SccpEvent::InboundReleased(SccpInboundReleasedV1 {
                message_id: [8; 32],
                network: TON,
                revision: 1,
                recipient: account(3),
                amount: 5_000_000_000,
                fee: 10_000_000,
            }),
            "inbound_released",
        ),
        (
            SccpEvent::InboundBounced(SccpInboundBouncedV1 {
                message_id: [10; 32],
                network: BSC,
                revision: 1,
                bounce_message_id: [11; 32],
                bounce_revision: 2,
                amount: 7,
                reason: SccpBounceReasonV1::UnregistrableRecipient,
            }),
            "inbound_bounced",
        ),
        (
            SccpEvent::InboundLiabilityShortfall(SccpInboundLiabilityShortfallV1 {
                message_id: [12; 32],
                network: BSC,
                revision: 1,
                amount: 9,
                liability: 8,
            }),
            "inbound_liability_shortfall",
        ),
        (
            SccpEvent::OutboundVoided(SccpOutboundVoidedV1 {
                message_id: [13; 32],
                network: TON,
                revision: 1,
                nonce: 4,
                kind: SccpVoidKindV1::Expired,
                refund_pending: false,
            }),
            "outbound_voided",
        ),
        (
            SccpEvent::OutboundRefunded(SccpOutboundRefundedV1 {
                message_id: [13; 32],
                network: TON,
                revision: 1,
                nonce: 4,
                recipient: account(4),
                amount: 1_000_000_000,
            }),
            "outbound_refunded",
        ),
        (
            SccpEvent::OutboundStranded(SccpOutboundStrandedV1 {
                message_id: [14; 32],
                network: TON,
                revision: 1,
                nonce: 5,
                amount: 1_000_000_000,
            }),
            "outbound_stranded",
        ),
        (
            SccpEvent::StrandedReleased(SccpStrandedReleasedV1 {
                network: ETH,
                recipient: account(6),
                amount: 1_000_000_000,
                memo: "return a stranded bounce".to_owned(),
                proposal_id: [15; 32],
            }),
            "stranded_released",
        ),
        (
            SccpEvent::LightClientAdvanced(SccpLightClientAdvancedV1 {
                network: ETH,
                latest_set_id: 1_400,
                latest_finalized: point(),
                state_hash: [16; 32],
            }),
            "light_client_advanced",
        ),
        (
            SccpEvent::LightClientFrozen(SccpLightClientFrozenV1 {
                network: BSC,
                reason: freeze_reasons()[1],
            }),
            "light_client_frozen",
        ),
        (
            SccpEvent::LightClientInitialized(SccpLightClientInitializedV1 {
                network: TON,
                latest_set_id: 44_000_000,
                latest_finalized: point(),
                state_hash: [18; 32],
                proposal_id: [19; 32],
            }),
            "light_client_initialized",
        ),
        (
            SccpEvent::TrustedCheckpointInstalled(SccpTrustedCheckpointInstalledV1 {
                network: ETH,
                source_height: 20_000_000,
                block_hash: [20; 32],
                proposal_id: [21; 32],
            }),
            "trusted_checkpoint_installed",
        ),
        (
            SccpEvent::RevisionActivationChanged(SccpRevisionActivationChangedV1 {
                network: ETH,
                revision: 1,
                from: Some(SccpRouteActivationV1::Bidirectional),
                to: Some(SccpRouteActivationV1::Paused),
            }),
            "revision_activation_changed",
        ),
        (
            SccpEvent::ControlRecorded(SccpControlRecordedV1 {
                network: ETH,
                revision: 1,
                control_nonce: 1,
                track: 1,
                parliament_paused: true,
                fast_pause_until_ms: 0,
                certificate_id: [0x5a; 32],
                height: 30,
                commitment_index: 0,
            }),
            "control_recorded",
        ),
        (
            SccpEvent::GovernanceEnacted(SccpGovernanceEnactedV1 {
                proposal_id: [22; 32],
                subjects: vec![
                    SccpGovernanceSubjectV1::Route(ETH),
                    SccpGovernanceSubjectV1::RouteControl(ETH),
                    SccpGovernanceSubjectV1::Parameters,
                ],
            }),
            "governance_enacted",
        ),
        (
            SccpEvent::CommitteeGenerationCreated(SccpCommitteeGenerationCreatedV1 {
                generation: 1,
                cause: SccpGenerationCauseV1::Genesis,
                committee_root: [23; 32],
                start_height: 1,
                deadline_ms: 1_758_604_800_000,
            }),
            "committee_generation_created",
        ),
        (
            SccpEvent::GenerationMemberUnslashable(SccpGenerationMemberUnslashableV1 {
                generation: 1,
                index: 3,
            }),
            "generation_member_unslashable",
        ),
        (
            SccpEvent::CommitteeResync(SccpCommitteeResyncV1 {
                generation: 2,
                committee_root: [24; 32],
                start_height: 10,
            }),
            "committee_resync",
        ),
        (
            SccpEvent::GenerationDestinationCleared(SccpGenerationDestinationClearedV1 {
                generation: 1,
                lc: 1_759_000_000_000,
            }),
            "generation_destination_cleared",
        ),
        (
            SccpEvent::FinalityDegraded(SccpFinalityDegradedV1 {
                height: 11,
                reason: SccpFinalityDegradedReasonV1::MissingInputs,
            }),
            "finality_degraded",
        ),
        (
            SccpEvent::FastPauseLapsed(SccpFastPauseLapsedV1 {
                network: ETH,
                certificate_id: [29; 32],
                until_ms: 1_758_604_800_000,
            }),
            "fast_pause_lapsed",
        ),
    ]
}

// ---------------------------------------------------------------------------------------------
// Codec helpers
// ---------------------------------------------------------------------------------------------

/// Assert the bare codec, the headered frame and JSON all roundtrip `value`.
fn roundtrip<T>(value: &T)
where
    T: Encode
        + DecodeAll
        + norito::NoritoSerialize
        + for<'a> norito::NoritoDeserialize<'a>
        + norito::json::JsonSerialize
        + norito::json::JsonDeserialize
        + PartialEq
        + core::fmt::Debug,
{
    let encoded = value.encode();
    assert_eq!(
        &T::decode_all(&mut encoded.as_slice()).expect("bare codec decodes"),
        value
    );
    let framed = norito::to_bytes(value).expect("headered frame encodes");
    assert_eq!(
        &norito::decode_from_bytes::<T>(&framed).expect("headered frame decodes"),
        value
    );
    let json = norito::json::to_json(value).expect("JSON serializes");
    assert_eq!(
        &norito::json::from_json::<T>(&json).expect("JSON deserializes"),
        value,
        "{json}"
    );
}

/// [`roundtrip`] plus the zero-copy slice decoder, which must consume every byte.
fn roundtrip_with_slice<T>(value: &T)
where
    T: Encode
        + DecodeAll
        + norito::NoritoSerialize
        + for<'a> norito::NoritoDeserialize<'a>
        + for<'a> DecodeFromSlice<'a>
        + norito::json::JsonSerialize
        + norito::json::JsonDeserialize
        + PartialEq
        + core::fmt::Debug,
{
    roundtrip(value);
    let encoded = value.encode();
    let (decoded, used) = T::decode_from_slice(&encoded).expect("slice decodes");
    assert_eq!(used, encoded.len());
    assert_eq!(&decoded, value);
}

fn json_value<T: norito::json::JsonSerialize>(value: &T) -> Value {
    norito::json::to_value(value).expect("JSON value")
}

fn json_tag<T: norito::json::JsonSerialize>(value: &T, tag: &str) -> String {
    json_value(value)
        .get(tag)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("JSON tag `{tag}` is absent"))
        .to_owned()
}

/// Insert an unknown field into the JSON object reached by `path` (object keys, or decimal
/// indices into arrays) and assert that decoding rejects it.
fn assert_rejects_unknown_field<T>(value: &T, path: &[&str])
where
    T: norito::json::JsonSerialize + norito::json::JsonDeserialize + core::fmt::Debug,
{
    let mut json = json_value(value);
    let mut current = &mut json;
    for segment in path {
        current = match current {
            Value::Object(object) => object
                .get_mut(*segment)
                .unwrap_or_else(|| panic!("JSON path component `{segment}` is absent")),
            Value::Array(items) => {
                let index: usize = segment.parse().expect("array index");
                items.get_mut(index).expect("array index in bounds")
            }
            other => panic!("JSON path component `{segment}` cannot descend into {other:?}"),
        };
    }
    let Value::Object(object) = current else {
        panic!("JSON target at {path:?} is not an object");
    };
    object.insert("adversarial_extension".to_owned(), Value::Null);
    let hostile = norito::json::to_json(&json).expect("JSON serializes");
    assert!(
        norito::json::from_json::<T>(&hostile).is_err(),
        "unknown JSON field at {path:?} must be rejected: {hostile}"
    );
}

/// Remove `field` from the top-level JSON object of `value` and assert that decoding rejects it.
fn assert_requires_field<T>(value: &T, field: &str)
where
    T: norito::json::JsonSerialize + norito::json::JsonDeserialize + core::fmt::Debug,
{
    let mut json = json_value(value);
    json.as_object_mut()
        .expect("JSON object")
        .remove(field)
        .unwrap_or_else(|| panic!("field `{field}` is present"));
    let missing = norito::json::to_json(&json).expect("JSON serializes");
    assert!(
        norito::json::from_json::<T>(&missing).is_err(),
        "missing `{field}` must be rejected: {missing}"
    );
}

/// Assert that the bare decoder of `T` rejects every enum tag in `tags`.
fn assert_rejects_tags<T: DecodeAll + core::fmt::Debug>(tags: &[u32], filler: usize) {
    for tag in tags {
        let mut encoded = tag.encode();
        encoded.extend(std::iter::repeat_n(0x11, filler));
        assert!(
            T::decode_all(&mut encoded.as_slice()).is_err(),
            "{} tag {tag}",
            core::any::type_name::<T>()
        );
    }
}

/// Mirror of the private layout of the bounded byte wrappers, used to forge out-of-bounds
/// encodings past their constructors.
#[derive(Debug, Clone, norito::codec::Encode)]
struct ForgedBytes {
    bytes: Vec<u8>,
}

/// Mirror of the [`SubmitSccpOutboundVoidV1`] layout with a forgeable proof wrapper.
#[derive(Debug, Clone, norito::codec::Encode)]
struct ForgedOutboundVoid {
    network: SccpNetworkV1,
    revision: u32,
    proof: ForgedBytes,
}

/// Assert that every decoder of the bounded wrapper `T` rejects `len` bytes.
fn assert_wrapper_rejects<T>(len: usize)
where
    T: DecodeAll
        + for<'a> norito::NoritoDeserialize<'a>
        + for<'a> DecodeFromSlice<'a>
        + norito::json::JsonDeserialize
        + core::fmt::Debug,
{
    let forged = ForgedBytes {
        bytes: vec![0x5a; len],
    };
    let encoded = forged.encode();
    assert!(
        T::decode_all(&mut encoded.as_slice()).is_err(),
        "bare {len}"
    );
    assert!(T::decode_from_slice(&encoded).is_err(), "slice {len}");
    let json = format!("{{\"bytes\":\"{}\"}}", base64_standard(&forged.bytes));
    assert!(norito::json::from_json::<T>(&json).is_err(), "JSON {len}");
}

/// Standard padded base64, as `crate::json_helpers::base64_vec` writes it.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let triple = chunk.iter().enumerate().fold(0_u32, |acc, (index, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * index))
        });
        for position in 0..4 {
            if position <= chunk.len() {
                let sextet = (triple >> (18 - 6 * position)) & 0x3f;
                let sextet = usize::try_from(sextet).expect("a sextet fits usize");
                out.push(char::from(ALPHABET[sextet]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Constants, schema names and instruction ids
// ---------------------------------------------------------------------------------------------

#[test]
fn constants_match_the_spec() {
    assert_eq!(SCCP_HISTORY_MAX_SIZE_V1, 1_u64 << 32);
    assert_eq!(SCCP_FIRST_CONTROL_NONCE_V1, 1);
    // The proof bound equals the protocol-default per-proof byte limit of the committed ZK validity policy (8 MiB).
    assert_eq!(SCCP_SOURCE_PROOF_MAX_BYTES_V1, 8 * 1024 * 1024);
    assert_eq!(SCCP_LC_ADVANCE_MAX_BYTES_V1, 1024 * 1024);
    assert_eq!(SCCP_LC_EVIDENCE_MAX_BYTES_V1, 1024 * 1024);
    assert_eq!(SCCP_ROUTE_ESCROW_DOMAIN_V1, b"iroha:sccp:v1:route-escrow");
    assert_eq!(SCCP_XOR_ASSET_ID_TEXT, "xor");
    assert_eq!(
        SCCP_TAIRA_XOR_ASSET_DEFINITION_ID_V1,
        "6TEAJqbb8oEPmLncoNiMRbLEK6tw"
    );
    assert_eq!(SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1, "taira_eth_xor");
    assert_eq!(SCCP_ROUTE_ID_TAIRA_BSC_XOR_V1, "taira_bsc_xor");
    assert_eq!(SCCP_ROUTE_ID_TAIRA_TON_XOR_V1, "taira_ton_xor");
}

#[test]
fn schema_names_are_stable() {
    let cases = [
        (
            SccpBlockCommitmentV1::nominal_name(),
            "iroha_data_model::sccp::commitment::SccpBlockCommitmentV1",
        ),
        (
            SccpHistoryStateV1::nominal_name(),
            "iroha_data_model::sccp::commitment::SccpHistoryStateV1",
        ),
        (
            SccpTransferLeafRefV1::nominal_name(),
            "iroha_data_model::sccp::control::SccpTransferLeafRefV1",
        ),
        (
            SccpControlLeafRefV1::nominal_name(),
            "iroha_data_model::sccp::control::SccpControlLeafRefV1",
        ),
        (
            SccpLeafRefV1::nominal_name(),
            "iroha_data_model::sccp::control::SccpLeafRefV1",
        ),
        (
            SccpControlRecordV1::nominal_name(),
            "iroha_data_model::sccp::control::SccpControlRecordV1",
        ),
        (
            SccpVoidKindV1::nominal_name(),
            "iroha_data_model::sccp::outbound::SccpVoidKindV1",
        ),
        (
            SccpStatusHeightV1::nominal_name(),
            "iroha_data_model::sccp::outbound::SccpStatusHeightV1",
        ),
        (
            SccpVoidStatusV1::nominal_name(),
            "iroha_data_model::sccp::outbound::SccpVoidStatusV1",
        ),
        (
            SccpOutboundStatusV1::nominal_name(),
            "iroha_data_model::sccp::outbound::SccpOutboundStatusV1",
        ),
        (
            SccpOutboundMessageRecordV1::nominal_name(),
            "iroha_data_model::sccp::outbound::SccpOutboundMessageRecordV1",
        ),
        (
            SccpSourceProofBytesV1::nominal_name(),
            "iroha_data_model::sccp::inbound::SccpSourceProofBytesV1",
        ),
        (
            SccpSourceLocatorV1::nominal_name(),
            "iroha_data_model::sccp::inbound::SccpSourceLocatorV1",
        ),
        (
            SccpPendingReasonV1::nominal_name(),
            "iroha_data_model::sccp::inbound::SccpPendingReasonV1",
        ),
        (
            SccpPendingStatusV1::nominal_name(),
            "iroha_data_model::sccp::inbound::SccpPendingStatusV1",
        ),
        (
            SccpBounceStatusV1::nominal_name(),
            "iroha_data_model::sccp::inbound::SccpBounceStatusV1",
        ),
        (
            SccpInboundStatusV1::nominal_name(),
            "iroha_data_model::sccp::inbound::SccpInboundStatusV1",
        ),
        (
            SccpInboundRecordV1::nominal_name(),
            "iroha_data_model::sccp::inbound::SccpInboundRecordV1",
        ),
        (
            SccpRouteActivationV1::nominal_name(),
            "iroha_data_model::sccp::registry::SccpRouteActivationV1",
        ),
        (
            SccpRouteRevisionV1::nominal_name(),
            "iroha_data_model::sccp::registry::SccpRouteRevisionV1",
        ),
        (
            SccpRouteV1::nominal_name(),
            "iroha_data_model::sccp::registry::SccpRouteV1",
        ),
        (
            SccpLcAdvanceBytesV1::nominal_name(),
            "iroha_data_model::sccp::light_client::SccpLcAdvanceBytesV1",
        ),
        (
            SccpLcEvidenceBytesV1::nominal_name(),
            "iroha_data_model::sccp::light_client::SccpLcEvidenceBytesV1",
        ),
        (
            SccpLcPointV1::nominal_name(),
            "iroha_data_model::sccp::light_client::SccpLcPointV1",
        ),
        (
            SccpLcHeadV1::nominal_name(),
            "iroha_data_model::sccp::light_client::SccpLcHeadV1",
        ),
        (
            SccpLcEquivocationFreezeV1::nominal_name(),
            "iroha_data_model::sccp::light_client::SccpLcEquivocationFreezeV1",
        ),
        (
            SccpLcParliamentFreezeV1::nominal_name(),
            "iroha_data_model::sccp::light_client::SccpLcParliamentFreezeV1",
        ),
        (
            SccpLcFreezeReasonV1::nominal_name(),
            "iroha_data_model::sccp::light_client::SccpLcFreezeReasonV1",
        ),
        (
            SccpLightClientV1::nominal_name(),
            "iroha_data_model::sccp::light_client::SccpLightClientV1",
        ),
        (
            SccpLcConsensusSetV1::nominal_name(),
            "iroha_data_model::sccp::light_client::SccpLcConsensusSetV1",
        ),
    ];
    let mut seen = BTreeSet::new();
    for (actual, expected) in cases {
        assert_eq!(actual, expected);
        assert!(seen.insert(actual), "duplicate schema name {expected}");
    }
}

#[test]
fn event_schema_names_are_stable() {
    let cases = [
        (
            SccpEvent::nominal_name(),
            "iroha_data_model::sccp::events::SccpEvent",
        ),
        (
            SccpEventSet::nominal_name(),
            "iroha_data_model::sccp::events::SccpEventSet",
        ),
        (
            SccpMessageRecordedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpMessageRecordedV1",
        ),
        (
            SccpBlockCommittedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpBlockCommittedV1",
        ),
        (
            SccpInboundProvenV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpInboundProvenV1",
        ),
        (
            SccpRecipientRegisteredV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpRecipientRegisteredV1",
        ),
        (
            SccpInboundReleasedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpInboundReleasedV1",
        ),
        (
            SccpBounceReasonV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpBounceReasonV1",
        ),
        (
            SccpInboundBouncedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpInboundBouncedV1",
        ),
        (
            SccpInboundLiabilityShortfallV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpInboundLiabilityShortfallV1",
        ),
        (
            SccpOutboundVoidedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpOutboundVoidedV1",
        ),
        (
            SccpOutboundRefundedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpOutboundRefundedV1",
        ),
        (
            SccpOutboundStrandedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpOutboundStrandedV1",
        ),
        (
            SccpStrandedReleasedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpStrandedReleasedV1",
        ),
        (
            SccpLightClientAdvancedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpLightClientAdvancedV1",
        ),
        (
            SccpLightClientFrozenV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpLightClientFrozenV1",
        ),
        (
            SccpLightClientInitializedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpLightClientInitializedV1",
        ),
        (
            SccpTrustedCheckpointInstalledV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpTrustedCheckpointInstalledV1",
        ),
        (
            SccpRevisionActivationChangedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpRevisionActivationChangedV1",
        ),
        (
            SccpControlRecordedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpControlRecordedV1",
        ),
        (
            SccpGovernanceEnactedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpGovernanceEnactedV1",
        ),
        (
            SccpFinalityDegradedReasonV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpFinalityDegradedReasonV1",
        ),
        (
            SccpFinalityDegradedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpFinalityDegradedV1",
        ),
        (
            SccpCommitteeGenerationCreatedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpCommitteeGenerationCreatedV1",
        ),
        (
            SccpCommitteeResyncV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpCommitteeResyncV1",
        ),
        (
            SccpGenerationMemberUnslashableV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpGenerationMemberUnslashableV1",
        ),
        (
            SccpGenerationDestinationClearedV1::nominal_name(),
            "iroha_data_model::sccp::events::SccpGenerationDestinationClearedV1",
        ),
    ];
    let mut seen = BTreeSet::new();
    for (actual, expected) in cases {
        assert_eq!(actual, expected);
        assert!(seen.insert(actual), "duplicate schema name {expected}");
    }
}

#[test]
fn instruction_schema_names_and_ids_are_stable() {
    let schema_names = [
        (
            InitializeSccpV1::nominal_name(),
            "iroha_data_model::isi::sccp::InitializeSccpV1",
        ),
        (
            RecordSccpMessage::nominal_name(),
            "iroha_data_model::isi::sccp::RecordSccpMessage",
        ),
        (
            SubmitSccpInboundMessageV1::nominal_name(),
            "iroha_data_model::isi::sccp::SubmitSccpInboundMessageV1",
        ),
        (
            SccpSettleInboundV1::nominal_name(),
            "iroha_data_model::isi::sccp::SccpSettleInboundV1",
        ),
        (
            SccpSettleRefundV1::nominal_name(),
            "iroha_data_model::isi::sccp::SccpSettleRefundV1",
        ),
        (
            SccpSettleTargetV1::nominal_name(),
            "iroha_data_model::isi::sccp::SccpSettleTargetV1",
        ),
        (
            SettleSccpV1::nominal_name(),
            "iroha_data_model::isi::sccp::SettleSccpV1",
        ),
        (
            SubmitSccpOutboundVoidV1::nominal_name(),
            "iroha_data_model::isi::sccp::SubmitSccpOutboundVoidV1",
        ),
        (
            AdvanceSccpLightClientV1::nominal_name(),
            "iroha_data_model::isi::sccp::AdvanceSccpLightClientV1",
        ),
        (
            ReportSccpLightClientEquivocationV1::nominal_name(),
            "iroha_data_model::isi::sccp::ReportSccpLightClientEquivocationV1",
        ),
    ];
    for (actual, expected) in schema_names {
        assert_eq!(actual, expected);
    }

    let ids = [
        Instruction::id(&InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce: [1; 32],
        }),
        Instruction::id(&RecordSccpMessage {
            network: ETH,
            expected_revision: 1,
            amount: Numeric::from(1_u64),
            recipient: vec![0x22; 20],
        }),
        Instruction::id(&SubmitSccpInboundMessageV1 {
            network: ETH,
            revision: 1,
            payload: vec![2],
            proof: proof(1),
        }),
        Instruction::id(&SettleSccpV1::inbound([0; 32])),
        Instruction::id(&SubmitSccpOutboundVoidV1 {
            network: ETH,
            revision: 1,
            proof: proof(1),
        }),
        Instruction::id(&AdvanceSccpLightClientV1 {
            network: ETH,
            expected_state_hash: None,
            advance: advance(1),
        }),
        Instruction::id(&ReportSccpLightClientEquivocationV1 {
            network: ETH,
            a: evidence(1),
            b: evidence(2),
        }),
    ];
    assert_eq!(
        ids,
        [
            "iroha_data_model::isi::sccp::InitializeSccpV1",
            "iroha_data_model::isi::sccp::RecordSccpMessage",
            "iroha_data_model::isi::sccp::SubmitSccpInboundMessageV1",
            "iroha_data_model::isi::sccp::SettleSccpV1",
            "iroha_data_model::isi::sccp::SubmitSccpOutboundVoidV1",
            "iroha_data_model::isi::sccp::AdvanceSccpLightClientV1",
            "iroha_data_model::isi::sccp::ReportSccpLightClientEquivocationV1",
        ]
    );
}

// ---------------------------------------------------------------------------------------------
// Roundtrips
// ---------------------------------------------------------------------------------------------

#[test]
fn commitment_and_history_state_roundtrips() {
    roundtrip(&SccpBlockCommitmentV1 {
        root: [4; 32],
        message_count: 512,
        history_index: u64::from(u32::MAX),
    });
    roundtrip(&SccpHistoryStateV1::default());
    roundtrip(&SccpHistoryStateV1 {
        size: 7,
        peaks: vec![[5; 32], [6; 32], [7; 32]],
    });
}

#[test]
fn leaf_control_and_record_roundtrips() {
    roundtrip(&SccpLeafRefV1::transfer([7; 32]));
    for network in EXTERNAL {
        roundtrip(&SccpLeafRefV1::control(network, 2, u64::MAX));
    }
    roundtrip(&SccpControlRecordV1 {
        track: 1,
        parliament_paused: false,
        fast_pause_until_ms: 0,
        height: 99,
        commitment_index: 511,
        leaf: [3; 32],
        certificate_id: [4; 32],
        effect_hash: [5; 32],
    });
    for status in outbound_statuses() {
        roundtrip(&status);
        roundtrip(&outbound(status));
    }
    for kind in [SccpVoidKindV1::Expired, SccpVoidKindV1::Frozen] {
        roundtrip(&kind);
    }
    for status in inbound_statuses() {
        roundtrip(&status);
        roundtrip(&inbound(status));
    }
    for reason in [
        SccpPendingReasonV1::CreditRefused,
        SccpPendingReasonV1::FeeSinkUnavailable,
        SccpPendingReasonV1::BlockLeavesFull,
        SccpPendingReasonV1::Held,
    ] {
        roundtrip(&reason);
        roundtrip(&inbound(SccpInboundStatusV1::pending(reason)));
    }
    roundtrip(&locator());
}

#[test]
fn registry_roundtrips() {
    for activation in ACTIVATIONS {
        roundtrip(&activation);
        roundtrip(&revision(3, activation));
    }
    for network in EXTERNAL {
        let escrow =
            sccp_xor_route_escrow_account_id_v1(&network_id(1), network).expect("external network");
        let mut route = SccpRouteV1::empty(network, escrow).expect("external network");
        roundtrip(&route);
        route.stranded = u128::MAX;
        route
            .revisions
            .insert(1, revision(1, SccpRouteActivationV1::InboundOnly));
        route
            .revisions
            .insert(2, revision(2, SccpRouteActivationV1::Bidirectional));
        route
            .revisions
            .insert(3, revision(3, SccpRouteActivationV1::Staged));
        roundtrip(&route);
    }
}

#[test]
fn light_client_state_roundtrips() {
    roundtrip(&point());
    roundtrip(&head());
    for reason in freeze_reasons() {
        roundtrip(&reason);
    }
    for network in EXTERNAL {
        roundtrip(&light_client(network, None));
        for reason in freeze_reasons() {
            roundtrip(&light_client(network, Some(reason)));
        }
    }
    let mut set = SccpLcConsensusSetV1 {
        set_id: 1_400,
        valid_from_source_height: 11_468_800,
        superseded_at_source_ms: None,
        set_bytes: vec![0x4e, 0x52, 0x54, 0x30],
    };
    roundtrip(&set);
    set.superseded_at_source_ms = Some(1_758_000_000_000);
    roundtrip(&set);
    roundtrip_with_slice(&proof(3));
    roundtrip_with_slice(&advance(64));
    roundtrip_with_slice(&evidence(2));
}

#[test]
fn every_event_roundtrips_with_its_snake_case_tag() {
    let events = every_event();
    assert_eq!(
        events.len(),
        EVENT_CODEC_INDICES.len(),
        "one event of every variant"
    );
    let mut tags = BTreeSet::new();
    for ((event, tag), index) in events.iter().zip(EVENT_CODEC_INDICES) {
        roundtrip(event);
        assert_eq!(json_tag(event, "event"), *tag);
        assert!(tags.insert(*tag), "duplicate tag {tag}");
        assert!(
            event.encode().starts_with(&index.encode()),
            "{tag} has codec index {index}"
        );
    }
    for retired in RETIRED_EVENT_TAGS {
        assert!(!tags.contains(retired), "{retired}");
    }
}

#[test]
fn native_generation_event_payloads_cover_every_decoder() {
    for reason in [
        SccpFinalityDegradedReasonV1::MissingInputs,
        SccpFinalityDegradedReasonV1::InvalidInputs,
        SccpFinalityDegradedReasonV1::MissingGeneration,
        SccpFinalityDegradedReasonV1::InvalidGeneration,
        SccpFinalityDegradedReasonV1::MissingParent,
        SccpFinalityDegradedReasonV1::CounterExhausted,
    ] {
        roundtrip_with_slice(&reason);
        roundtrip_with_slice(&SccpFinalityDegradedV1 {
            height: u64::MAX,
            reason,
        });
    }
    for cause in [
        SccpGenerationCauseV1::Genesis,
        SccpGenerationCauseV1::KeyChange,
        SccpGenerationCauseV1::Heartbeat,
        SccpGenerationCauseV1::Resync,
    ] {
        roundtrip_with_slice(&SccpCommitteeGenerationCreatedV1 {
            generation: u64::MAX,
            cause,
            committee_root: [0xff; 32],
            start_height: u64::MAX,
            deadline_ms: u64::MAX,
        });
    }
    roundtrip_with_slice(&SccpCommitteeResyncV1 {
        generation: u64::MAX,
        committee_root: [0x80; 32],
        start_height: u64::MAX,
    });
    for index in [0, 30] {
        roundtrip_with_slice(&SccpGenerationMemberUnslashableV1 {
            generation: u64::MAX,
            index,
        });
    }
    roundtrip_with_slice(&SccpGenerationDestinationClearedV1 {
        generation: u64::MAX,
        lc: u64::MAX,
    });
}

#[test]
fn retired_attestation_and_roster_events_do_not_decode() {
    // Binary: the freed indices 2..=9 are holes, with any payload.
    assert_rejects_tags::<SccpEvent>(&[2, 3, 4, 5, 6, 7, 8, 9], 0);
    assert_rejects_tags::<SccpEvent>(&[2, 3, 4, 5, 6, 7, 8, 9], 256);
    // JSON: a kept event under a retired tag, and a retired tag with an empty payload.
    let (kept, _) = every_event().swap_remove(1);
    let kept = norito::json::to_json(&kept).expect("JSON");
    assert!(kept.contains("\"event\":\"block_committed\""), "{kept}");
    for tag in RETIRED_EVENT_TAGS {
        let renamed = kept.replace("block_committed", tag);
        assert!(
            norito::json::from_json::<SccpEvent>(&renamed).is_err(),
            "{renamed}"
        );
        let empty = format!("{{\"event\":\"{tag}\",\"payload\":{{}}}}");
        assert!(
            norito::json::from_json::<SccpEvent>(&empty).is_err(),
            "{empty}"
        );
    }
}

#[test]
fn event_set_selects_exactly_the_named_variants() {
    let events = every_event();
    for (event, _) in &events {
        assert!(SccpEventSet::all().matches(event));
        assert!(!SccpEventSet::empty().matches(event));
    }
    let set = SccpEventSet::InboundReleased
        | SccpEventSet::OutboundRefunded
        | SccpEventSet::GovernanceEnacted;
    let matched: Vec<&str> = events
        .iter()
        .filter(|(event, _)| set.matches(event))
        .map(|(_, tag)| *tag)
        .collect();
    assert_eq!(
        matched,
        vec![
            "inbound_released",
            "outbound_refunded",
            "governance_enacted"
        ]
    );
}

#[test]
fn every_instruction_roundtrips_through_every_decoder() {
    roundtrip_with_slice(&InitializeSccpV1 {
        parameters: SccpParametersV1::taira_default(),
        reset_nonce: [0x5a; 32],
    });
    roundtrip_with_slice(&RecordSccpMessage {
        network: TON,
        expected_revision: 3,
        amount: Numeric::new(1_500_000_000_u64, 9),
        recipient: vec![0x22; 36],
    });
    roundtrip_with_slice(&SubmitSccpInboundMessageV1 {
        network: BSC,
        revision: 2,
        payload: vec![2, 1, 0, 0, 0, 2],
        proof: proof(128),
    });
    roundtrip_with_slice(&SettleSccpV1::inbound([6; 32]));
    roundtrip_with_slice(&SettleSccpV1::refund(BSC, 1, u64::MAX));
    roundtrip_with_slice(&SubmitSccpOutboundVoidV1 {
        network: ETH,
        revision: 1,
        proof: proof(1),
    });
    roundtrip_with_slice(&AdvanceSccpLightClientV1 {
        network: ETH,
        expected_state_hash: Some([8; 32]),
        advance: advance(64),
    });
    roundtrip_with_slice(&AdvanceSccpLightClientV1 {
        network: TON,
        expected_state_hash: None,
        advance: advance(1),
    });
    roundtrip_with_slice(&ReportSccpLightClientEquivocationV1 {
        network: BSC,
        a: evidence(1),
        b: evidence(2),
    });
}

// ---------------------------------------------------------------------------------------------
// JSON shape
// ---------------------------------------------------------------------------------------------

#[test]
fn json_objects_are_closed_at_every_level() {
    assert_rejects_unknown_field(
        &SccpBlockCommitmentV1 {
            root: [4; 32],
            message_count: 1,
            history_index: 0,
        },
        &[],
    );
    assert_rejects_unknown_field(&SccpHistoryStateV1::default(), &[]);
    assert_rejects_unknown_field(&SccpLeafRefV1::control(ETH, 1, 1), &["reference"]);
    let record = outbound(outbound_statuses()[1]);
    assert_rejects_unknown_field(&record, &[]);
    assert_rejects_unknown_field(&record, &["status", "detail"]);
    let record = inbound(inbound_statuses()[0]);
    assert_rejects_unknown_field(&record, &[]);
    assert_rejects_unknown_field(&record, &["source_locator"]);
    assert_rejects_unknown_field(&record, &["status", "detail"]);
    let mut route = SccpRouteV1::empty(ETH, account(1)).expect("external network");
    route
        .revisions
        .insert(1, revision(1, SccpRouteActivationV1::Bidirectional));
    assert_rejects_unknown_field(&route, &[]);
    assert_rejects_unknown_field(&route, &["revisions", "1"]);
    assert_rejects_unknown_field(&route, &["revisions", "1", "deployment", "deployment"]);
    let client = light_client(ETH, Some(freeze_reasons()[0]));
    assert_rejects_unknown_field(&client, &[]);
    assert_rejects_unknown_field(&client, &["params"]);
    assert_rejects_unknown_field(&client, &["head"]);
    assert_rejects_unknown_field(&client, &["head", "latest_finalized"]);
    assert_rejects_unknown_field(&client, &["frozen", "detail"]);
    for (event, _) in every_event() {
        assert_rejects_unknown_field(&event, &[]);
        assert_rejects_unknown_field(&event, &["payload"]);
    }
    assert_rejects_unknown_field(
        &InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce: [1; 32],
        },
        &["parameters"],
    );
    assert_rejects_unknown_field(&SettleSccpV1::refund(ETH, 1, 1), &["target", "detail"]);
    assert_rejects_unknown_field(
        &AdvanceSccpLightClientV1 {
            network: ETH,
            expected_state_hash: None,
            advance: advance(1),
        },
        &["advance"],
    );
}

#[test]
fn optional_fields_are_explicit_in_json() {
    assert_requires_field(&light_client(TON, None), "frozen");
    assert_requires_field(
        &SccpLcConsensusSetV1 {
            set_id: 1,
            valid_from_source_height: 1,
            superseded_at_source_ms: None,
            set_bytes: vec![1],
        },
        "superseded_at_source_ms",
    );
    assert_requires_field(
        &AdvanceSccpLightClientV1 {
            network: ETH,
            expected_state_hash: None,
            advance: advance(1),
        },
        "expected_state_hash",
    );
}

#[test]
fn json_amounts_are_decimal_strings_and_bytes_are_base64() {
    let record = outbound(SccpOutboundStatusV1::Recorded);
    let json = json_value(&record);
    assert_eq!(
        json.get("amount").and_then(Value::as_str),
        Some("79228162514264337593543950335")
    );
    assert_eq!(
        json.get("payload").and_then(Value::as_str),
        Some("AgEAAAAA")
    );
    let json = json_value(&inbound(inbound_statuses()[3]));
    assert_eq!(
        json.get("fee_due").and_then(Value::as_str),
        Some("10000000")
    );
    let revision = revision(2, SccpRouteActivationV1::Bidirectional);
    let json = json_value(&revision);
    assert_eq!(
        json.get("max_wrapped_supply").and_then(Value::as_str),
        Some("21000000000000000")
    );
    assert_eq!(
        json.get("liability").and_then(Value::as_str),
        Some("2000000000")
    );
    let set = SccpLcConsensusSetV1 {
        set_id: 1,
        valid_from_source_height: 2,
        superseded_at_source_ms: None,
        set_bytes: vec![0xde, 0xad, 0xbe, 0xef],
    };
    assert_eq!(
        json_value(&set).get("set_bytes").and_then(Value::as_str),
        Some("3q2+7w==")
    );
    let record = RecordSccpMessage {
        network: ETH,
        expected_revision: 1,
        amount: Numeric::from(1_u64),
        recipient: vec![0xde, 0xad, 0xbe, 0xef],
    };
    assert_eq!(
        json_value(&record).get("recipient").and_then(Value::as_str),
        Some("3q2+7w==")
    );
    assert_eq!(
        norito::json::to_json(&proof(3)).expect("JSON"),
        "{\"bytes\":\"Tk5O\"}"
    );
    // A JSON number is not an amount.
    let text = norito::json::to_json(&outbound(SccpOutboundStatusV1::Recorded)).expect("JSON");
    let numeric = text.replace(
        "\"amount\":\"79228162514264337593543950335\"",
        "\"amount\":79228162514264337593543950335",
    );
    assert_ne!(numeric, text);
    assert!(norito::json::from_json::<SccpOutboundMessageRecordV1>(&numeric).is_err());
}

#[test]
fn enum_json_tags_are_snake_case() {
    let cases = [
        (
            json_tag(&SccpLeafRefV1::transfer([0; 32]), "leaf"),
            "transfer",
        ),
        (
            json_tag(&SccpLeafRefV1::control(ETH, 1, 1), "leaf"),
            "control",
        ),
        (json_tag(&SccpVoidKindV1::Expired, "kind"), "expired"),
        (json_tag(&SccpVoidKindV1::Frozen, "kind"), "frozen"),
        (json_tag(&outbound_statuses()[0], "status"), "recorded"),
        (json_tag(&outbound_statuses()[1], "status"), "voided"),
        (json_tag(&outbound_statuses()[3], "status"), "refunded"),
        (json_tag(&outbound_statuses()[4], "status"), "stranded"),
        (json_tag(&inbound_statuses()[0], "status"), "pending"),
        (json_tag(&inbound_statuses()[3], "status"), "released"),
        (json_tag(&inbound_statuses()[4], "status"), "bounced"),
        (
            json_tag(&SccpPendingReasonV1::RevisionNotSettleable, "reason"),
            "revision_not_settleable",
        ),
        (
            json_tag(&SccpPendingReasonV1::LiabilityShortfall, "reason"),
            "liability_shortfall",
        ),
        (
            json_tag(&SccpPendingReasonV1::CreditRefused, "reason"),
            "credit_refused",
        ),
        (
            json_tag(&SccpPendingReasonV1::FeeSinkUnavailable, "reason"),
            "fee_sink_unavailable",
        ),
        (
            json_tag(&SccpPendingReasonV1::BlockLeavesFull, "reason"),
            "block_leaves_full",
        ),
        (json_tag(&SccpPendingReasonV1::Held, "reason"), "held"),
        (
            json_tag(&SccpRouteActivationV1::InboundOnly, "activation"),
            "inbound_only",
        ),
        (
            json_tag(&SccpRouteActivationV1::Bidirectional, "activation"),
            "bidirectional",
        ),
        (json_tag(&freeze_reasons()[0], "reason"), "equivocation"),
        (json_tag(&freeze_reasons()[1], "reason"), "parliament"),
        (
            json_tag(&SccpBounceReasonV1::UndecodableRecipient, "reason"),
            "undecodable_recipient",
        ),
        (
            json_tag(&SccpBounceReasonV1::InadmissibleController, "reason"),
            "inadmissible_controller",
        ),
        (
            json_tag(&SccpBounceReasonV1::UnregistrableRecipient, "reason"),
            "unregistrable_recipient",
        ),
        (
            json_tag(&SettleSccpV1::inbound([0; 32]).target, "target"),
            "inbound",
        ),
        (
            json_tag(&SettleSccpV1::refund(ETH, 1, 0).target, "target"),
            "refund",
        ),
    ];
    for (actual, expected) in cases {
        assert_eq!(actual, expected);
    }
}

// ---------------------------------------------------------------------------------------------
// Binary strictness
// ---------------------------------------------------------------------------------------------

#[test]
fn unknown_binary_tags_are_rejected() {
    assert_rejects_tags::<SccpLeafRefV1>(&[2, u32::MAX], 64);
    assert_rejects_tags::<SccpVoidKindV1>(&[2, u32::MAX], 0);
    assert_rejects_tags::<SccpOutboundStatusV1>(&[4, u32::MAX], 64);
    assert_rejects_tags::<SccpPendingReasonV1>(&[7, u32::MAX], 0);
    assert_rejects_tags::<SccpInboundStatusV1>(&[3, u32::MAX], 64);
    assert_rejects_tags::<SccpRouteActivationV1>(&[5, u32::MAX], 0);
    assert_rejects_tags::<SccpLcFreezeReasonV1>(&[2, u32::MAX], 64);
    assert_rejects_tags::<SccpBounceReasonV1>(&[4, u32::MAX], 0);
    assert_rejects_tags::<SccpEvent>(&[26, 27, u32::MAX], 256);
    assert_rejects_tags::<SccpSettleTargetV1>(&[2, u32::MAX], 64);
}

#[test]
fn trailing_bytes_are_rejected() {
    fn assert_trailing_rejected<T: Encode + DecodeAll + core::fmt::Debug>(value: &T) {
        let mut encoded = value.encode();
        encoded.push(0);
        assert!(
            T::decode_all(&mut encoded.as_slice()).is_err(),
            "{}",
            core::any::type_name::<T>()
        );
    }
    fn assert_slice_trailing_rejected<T>(value: &T)
    where
        T: Encode + for<'a> DecodeFromSlice<'a> + core::fmt::Debug,
    {
        let mut encoded = value.encode();
        encoded.push(0);
        assert!(
            T::decode_from_slice(&encoded).is_err(),
            "{}",
            core::any::type_name::<T>()
        );
    }
    assert_trailing_rejected(&SccpBlockCommitmentV1 {
        root: [4; 32],
        message_count: 1,
        history_index: 0,
    });
    assert_trailing_rejected(&SccpHistoryStateV1 {
        size: 1,
        peaks: vec![[5; 32]],
    });
    assert_trailing_rejected(&outbound(SccpOutboundStatusV1::Recorded));
    assert_trailing_rejected(&inbound(inbound_statuses()[0]));
    assert_trailing_rejected(&revision(1, SccpRouteActivationV1::Staged));
    assert_trailing_rejected(&light_client(ETH, None));
    for (event, _) in every_event() {
        assert_trailing_rejected(&event);
    }
    let instruction = SubmitSccpInboundMessageV1 {
        network: ETH,
        revision: 1,
        payload: vec![2],
        proof: proof(4),
    };
    assert_trailing_rejected(&instruction);
    assert_slice_trailing_rejected(&instruction);
    let instruction = SettleSccpV1::refund(TON, 1, 2);
    assert_trailing_rejected(&instruction);
    assert_slice_trailing_rejected(&instruction);
    let instruction = InitializeSccpV1 {
        parameters: SccpParametersV1::taira_default(),
        reset_nonce: [1; 32],
    };
    assert_trailing_rejected(&instruction);
    assert_slice_trailing_rejected(&instruction);
}

// ---------------------------------------------------------------------------------------------
// Byte-wrapper bounds
// ---------------------------------------------------------------------------------------------

#[test]
fn byte_wrappers_hold_their_bounds_at_every_boundary() {
    assert_eq!(
        SccpSourceProofBytesV1::MAX_BYTES,
        SCCP_SOURCE_PROOF_MAX_BYTES_V1
    );
    assert_eq!(
        SccpLcAdvanceBytesV1::MAX_BYTES,
        SCCP_LC_ADVANCE_MAX_BYTES_V1
    );
    assert_eq!(
        SccpLcEvidenceBytesV1::MAX_BYTES,
        SCCP_LC_EVIDENCE_MAX_BYTES_V1
    );

    // Constructors accept exactly 1..=MAX.
    assert_eq!(
        SccpSourceProofBytesV1::new(Vec::new()),
        Err(SccpBoundedBytesError::Empty {
            kind: "SCCP source proof"
        })
    );
    assert_eq!(
        SccpLcAdvanceBytesV1::new(vec![0; SCCP_LC_ADVANCE_MAX_BYTES_V1 + 1]),
        Err(SccpBoundedBytesError::TooLong {
            kind: "SCCP light-client advance",
            len: SCCP_LC_ADVANCE_MAX_BYTES_V1 + 1,
            max: SCCP_LC_ADVANCE_MAX_BYTES_V1,
        })
    );
    assert_eq!(
        SccpLcEvidenceBytesV1::new(Vec::new()),
        Err(SccpBoundedBytesError::Empty {
            kind: "SCCP light-client evidence"
        })
    );
    assert!(SccpSourceProofBytesV1::new(vec![0; SCCP_SOURCE_PROOF_MAX_BYTES_V1 + 1]).is_err());
    assert!(SccpLcEvidenceBytesV1::new(vec![0; SCCP_LC_EVIDENCE_MAX_BYTES_V1 + 1]).is_err());

    let max_proof = proof(SCCP_SOURCE_PROOF_MAX_BYTES_V1);
    assert_eq!(max_proof.len(), SCCP_SOURCE_PROOF_MAX_BYTES_V1);
    assert!(!max_proof.is_empty());
    roundtrip_with_slice(&max_proof);
    roundtrip_with_slice(&advance(SCCP_LC_ADVANCE_MAX_BYTES_V1));
    roundtrip_with_slice(&evidence(SCCP_LC_EVIDENCE_MAX_BYTES_V1));
    roundtrip_with_slice(&proof(1));
    assert_eq!(evidence(3).into_bytes(), vec![0x45; 3]);
    assert_eq!(advance(2).as_bytes(), &[0x41, 0x41]);

    // The forged mirror encodes exactly like an in-bounds wrapper.
    assert_eq!(
        ForgedBytes {
            bytes: vec![0x4e; 5]
        }
        .encode(),
        proof(5).encode()
    );

    // The JSON forgery helper writes what the wrapper's own serializer writes.
    let text = format!("{{\"bytes\":\"{}\"}}", base64_standard(&[0x4e; 5]));
    assert_eq!(text, norito::json::to_json(&proof(5)).expect("JSON"));
    assert_eq!(
        norito::json::from_json::<SccpSourceProofBytesV1>(&text).expect("in bounds"),
        proof(5)
    );

    // Every decoder refuses empty and over-long wrappers forged past the constructor.
    assert_wrapper_rejects::<SccpSourceProofBytesV1>(0);
    assert_wrapper_rejects::<SccpSourceProofBytesV1>(SCCP_SOURCE_PROOF_MAX_BYTES_V1 + 1);
    assert_wrapper_rejects::<SccpLcAdvanceBytesV1>(0);
    assert_wrapper_rejects::<SccpLcAdvanceBytesV1>(SCCP_LC_ADVANCE_MAX_BYTES_V1 + 1);
    assert_wrapper_rejects::<SccpLcEvidenceBytesV1>(0);
    assert_wrapper_rejects::<SccpLcEvidenceBytesV1>(SCCP_LC_EVIDENCE_MAX_BYTES_V1 + 1);
}

#[test]
fn instructions_reject_out_of_bounds_wrappers() {
    let valid = AdvanceSccpLightClientV1 {
        network: ETH,
        expected_state_hash: None,
        advance: advance(1),
    };
    let mut json = json_value(&valid);
    json.as_object_mut()
        .expect("object")
        .insert("advance".to_owned(), norito::json!({ "bytes": "" }));
    let empty = norito::json::to_json(&json).expect("JSON");
    assert!(norito::json::from_json::<AdvanceSccpLightClientV1>(&empty).is_err());

    let valid = ReportSccpLightClientEquivocationV1 {
        network: ETH,
        a: evidence(1),
        b: evidence(1),
    };
    let mut json = json_value(&valid);
    json.as_object_mut()
        .expect("object")
        .insert("b".to_owned(), norito::json!({ "bytes": "" }));
    let empty = norito::json::to_json(&json).expect("JSON");
    assert!(norito::json::from_json::<ReportSccpLightClientEquivocationV1>(&empty).is_err());

    // A binary instruction whose proof is an empty or over-long forged wrapper fails every
    // decoder. The mirror encodes exactly like the instruction while the proof is in bounds.
    let mirror = |bytes: Vec<u8>| ForgedOutboundVoid {
        network: ETH,
        revision: 1,
        proof: ForgedBytes { bytes },
    };
    let valid = SubmitSccpOutboundVoidV1 {
        network: ETH,
        revision: 1,
        proof: proof(2),
    };
    assert_eq!(mirror(vec![0x4e; 2]).encode(), valid.encode());
    for len in [0, SCCP_SOURCE_PROOF_MAX_BYTES_V1 + 1] {
        let forged = mirror(vec![0x4e; len]).encode();
        assert!(
            SubmitSccpOutboundVoidV1::decode_all(&mut forged.as_slice()).is_err(),
            "bare {len}"
        );
        assert!(
            SubmitSccpOutboundVoidV1::decode_from_slice(&forged).is_err(),
            "slice {len}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Escrow identity and the XOR definition
// ---------------------------------------------------------------------------------------------

#[test]
fn escrow_ids_are_deterministic_and_distinct_per_route_and_network_id() {
    let routes = [
        SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1,
        SCCP_ROUTE_ID_TAIRA_BSC_XOR_V1,
        SCCP_ROUTE_ID_TAIRA_TON_XOR_V1,
    ];
    let mut seen = BTreeMap::new();
    for seed in [0x11_u8, 0x12, 0xff] {
        let id = network_id(seed);
        for route in routes {
            let escrow = sccp_route_escrow_account_id_v1(&id, route, SCCP_XOR_ASSET_ID_TEXT);
            assert_eq!(
                escrow,
                sccp_route_escrow_account_id_v1(&id, route, SCCP_XOR_ASSET_ID_TEXT),
                "deterministic"
            );
            let signatory = escrow.try_signatory().expect("single-key escrow");
            assert_eq!(signatory.algorithm(), Algorithm::Ed25519);
            assert!(
                seen.insert(escrow, (seed, route)).is_none(),
                "escrow of {route} under NetworkId {seed:#x} collides"
            );
        }
    }
    assert_eq!(seen.len(), 9);
    let id = network_id(0x11);
    assert_ne!(
        sccp_route_escrow_account_id_v1(&id, SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1, "xor"),
        sccp_route_escrow_account_id_v1(&id, SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1, "val"),
        "distinct per asset id"
    );
    assert_ne!(
        sccp_route_escrow_account_id_v1(&id, "taira_eth_xorx", "or"),
        sccp_route_escrow_account_id_v1(&id, "taira_eth_xor", "xor"),
        "inputs are length-framed"
    );
}

#[test]
fn escrow_is_per_network_helper_and_revision_free() {
    let id = network_id(0x11);
    assert_eq!(sccp_xor_route_escrow_account_id_v1(&id, TAIRA), None);
    let mut escrows = BTreeSet::new();
    for network in EXTERNAL {
        let route_id = route_id_for(network).expect("external route");
        let escrow = sccp_xor_route_escrow_account_id_v1(&id, network).expect("external route");
        assert_eq!(
            escrow,
            sccp_route_escrow_account_id_v1(&id, route_id, SCCP_XOR_ASSET_ID_TEXT)
        );
        assert!(escrows.insert(escrow.clone()), "distinct per network");

        // Every revision of the route, whatever its state, shares the one escrow.
        let mut route = SccpRouteV1::empty(network, escrow.clone()).expect("external route");
        for (number, activation) in (1_u32..).zip(ACTIVATIONS) {
            route.revisions.insert(number, revision(number, activation));
            assert_eq!(
                sccp_xor_route_escrow_account_id_v1(&id, route.network),
                Some(route.escrow.clone())
            );
        }
        assert_eq!(route.route_id, route_id);
        assert_eq!(route.latest_revision(), 5);
    }
    assert_ne!(
        sccp_xor_route_escrow_account_id_v1(&network_id(0x12), ETH),
        sccp_xor_route_escrow_account_id_v1(&id, ETH),
        "distinct per NetworkId"
    );
}

#[test]
fn escrow_derivation_is_pinned() {
    // Golden vector: any change to the domain tag, the field framing or the hash-to-point
    // sampling moves every escrow and is a consensus break.
    let escrow = sccp_route_escrow_account_id_v1(
        &network_id(0x11),
        SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1,
        SCCP_XOR_ASSET_ID_TEXT,
    );
    let (algorithm, payload) = escrow
        .try_signatory()
        .expect("single-key escrow")
        .to_bytes();
    assert_eq!(algorithm, Algorithm::Ed25519);
    assert_eq!(
        payload,
        hex!("214d81aefee4a014c32164cc1b9e7b25fa838c9f5fb12b714afb6f21e789d0c3").as_slice()
    );
}

#[test]
fn escrow_is_not_a_seeded_signing_key() {
    // The escrow point is rejection-sampled from a domain-separated transcript, not derived from
    // a seed; it therefore differs from the key of any seeded account built from the same bytes.
    let id = network_id(0x11);
    let escrow = sccp_route_escrow_account_id_v1(&id, SCCP_ROUTE_ID_TAIRA_ETH_XOR_V1, "xor");
    for seed in [0x01_u8, 0x11, 0xff] {
        assert_ne!(escrow, AccountId::new(key_pair(seed).public_key().clone()));
    }
}

#[test]
fn taira_xor_asset_definition_is_the_canonical_literal() {
    let definition = sccp_taira_xor_asset_definition_id();
    assert_eq!(
        definition,
        AssetDefinitionId::parse_address_literal("6TEAJqbb8oEPmLncoNiMRbLEK6tw")
            .expect("canonical literal")
    );
    assert_eq!(
        definition.to_string(),
        SCCP_TAIRA_XOR_ASSET_DEFINITION_ID_V1
    );
}

// ---------------------------------------------------------------------------------------------
// History and registry rules at the public boundary
// ---------------------------------------------------------------------------------------------

#[test]
fn history_rules() {
    assert!(
        SccpHistoryStateV1 {
            size: 5,
            peaks: vec![[1; 32], [2; 32]],
        }
        .is_well_formed()
    );
    assert!(
        !SccpHistoryStateV1 {
            size: 5,
            peaks: vec![[1; 32]],
        }
        .is_well_formed()
    );
    assert!(
        !SccpHistoryStateV1 {
            size: SCCP_HISTORY_MAX_SIZE_V1 + 1,
            peaks: vec![[1; 32]; 2],
        }
        .is_well_formed()
    );
}

#[test]
fn registry_rules() {
    for network in EXTERNAL {
        assert!(route_id_for(network).is_some(), "{network:?}");
    }
    assert_eq!(route_id_for(TAIRA), None);
    // (state, settles, live)
    for (state, settles, live) in [
        (SccpRouteActivationV1::Staged, false, false),
        (SccpRouteActivationV1::Bidirectional, true, true),
        (SccpRouteActivationV1::Paused, false, true),
        (SccpRouteActivationV1::InboundOnly, true, false),
        (SccpRouteActivationV1::Retired, false, false),
    ] {
        assert_eq!(state.settles(), settles, "{state:?}");
        assert_eq!(state.is_live(), live, "{state:?}");
    }
    assert!(SccpRouteActivationV1::Staged.can_transition_to(SccpRouteActivationV1::Bidirectional));
    assert!(SccpRouteActivationV1::Paused.can_transition_to(SccpRouteActivationV1::InboundOnly));
    assert!(!SccpRouteActivationV1::Retired.can_transition_to(SccpRouteActivationV1::Staged));
    assert!(!SccpRouteActivationV1::Staged.can_transition_to(SccpRouteActivationV1::Paused));

    let staged = SccpRouteRevisionV1::staged(
        1,
        evm(9),
        iroha_data_model::sccp::deployment::SccpCommitteePinV1 {
            generation: 1,
            committee_root: [0x44; 32],
            start_height: 1,
            until_ms: 1_801_209_600_000,
        },
        1_000,
        40,
    );
    assert_eq!(staged.destination_word, evm(9).destination_word());
    assert_eq!(staged.next_control_nonce, SCCP_FIRST_CONTROL_NONCE_V1);
    assert_eq!(staged.next_outbound_nonce, 0);
    assert!(!staged.ever_activated);
    assert_eq!(staged.headroom(), 1_000);

    let mut route = SccpRouteV1::empty(ETH, account(1)).expect("external route");
    route
        .revisions
        .insert(1, revision(1, SccpRouteActivationV1::InboundOnly));
    route
        .revisions
        .insert(2, revision(2, SccpRouteActivationV1::Bidirectional));
    assert_eq!(route.latest_revision(), 2);
    assert_eq!(route.bidirectional_revision().map(|r| r.revision), Some(2));
}

#[test]
fn status_helpers() {
    let [recorded, voided, pending_refund, refunded, stranded] = outbound_statuses();
    assert!(recorded.is_recorded());
    assert!(!voided.is_recorded());
    assert!(pending_refund.is_refund_pending());
    for status in [recorded, voided, refunded, stranded] {
        assert!(!status.is_refund_pending());
    }
    let [disabled, paused, shortfall, released, bounced] = inbound_statuses();
    for status in [disabled, paused, shortfall] {
        assert!(status.is_pending());
    }
    assert!(!released.is_pending());
    assert!(!bounced.is_pending());
    assert_eq!(
        disabled,
        SccpInboundStatusV1::Pending(SccpPendingStatusV1 {
            reason: SccpPendingReasonV1::Disabled
        })
    );
    assert!(!light_client(ETH, None).is_frozen());
    assert!(light_client(ETH, Some(freeze_reasons()[1])).is_frozen());
    assert_eq!(
        SccpLeafRefV1::control(TON, 2, 3),
        SccpLeafRefV1::Control(SccpControlLeafRefV1 {
            network: TON,
            revision: 2,
            control_nonce: 3,
        })
    );
    assert_eq!(
        SccpLeafRefV1::transfer([1; 32]),
        SccpLeafRefV1::Transfer(SccpTransferLeafRefV1 {
            message_id: [1; 32]
        })
    );
    assert_eq!(
        SettleSccpV1::refund(ETH, 1, 2).target,
        SccpSettleTargetV1::Refund(SccpSettleRefundV1 {
            network: ETH,
            revision: 1,
            nonce: 2,
        })
    );
    assert_eq!(
        SettleSccpV1::inbound([4; 32]).target,
        SccpSettleTargetV1::Inbound(SccpSettleInboundV1 {
            message_id: [4; 32]
        })
    );
}
