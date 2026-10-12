//! Deterministic gas metering for native ISI execution.
//!
//! This module provides a minimal, stable cost model for native instructions,
//! including `Executable::Instructions` and explicit instruction items inside
//! `Executable::Batch`. It assigns a base cost per instruction family and adds
//! small dynamic components for payload sizes (e.g., JSON values).
//!
//! Goals
//! - Deterministic across peers and hardware.
//! - Independent of WSV contents (only instruction payloads are considered).
//! - Conservative but simple to reason about.
//!
//! Non-goals
//! - Perfect proportionality to runtime wall-clock. Costs are calibrated to be
//!   monotonic with payload sizes and relative complexity.
use iroha_config::parameters::actual::ConfidentialGas as ActualConfidentialGas;
use iroha_data_model::{
    isi as dm_isi, isi::InstructionBox, proof::ProofAttachment, zk::OpenVerifyEnvelope,
};
use norito::{codec::Encode as _, decode_canonical};
use std::borrow::Borrow;
/// Per-instruction family base costs.
/// Chosen to be small compared to the default per-block gas limit.
// Tuned to target a simple fee envelope:
// - Typical SetKeyValue with small JSON: ~128 gas.
// - Ordinary Register/Unregister variants: ~200/150 gas; account/domain lifecycle
//   variants add bounded state-validation escrows where required.
// - Transfer/Mint/Burn: ~180/150/150 gas.
const BASE_REGISTER: u64 = 200;
const BASE_UNREGISTER: u64 = 150;
/// Fixed native charge for one asset or NFT transfer, also quoted before VM host dispatch.
pub(crate) const BASE_TRANSFER: u64 = 180;
const BASE_MINT: u64 = 150;
const BASE_BURN: u64 = 150;
const BASE_SET_KV: u64 = 64;
const BASE_REMOVE_KV: u64 = 48;
const BASE_GRANT: u64 = 96;
const BASE_REVOKE: u64 = 96;
const BASE_EXECUTE_TRIGGER: u64 = 220;
const BASE_UPGRADE: u64 = 2_000;
const BASE_LOG: u64 = 8;
const BASE_CUSTOM: u64 = 128;
const BASE_REGISTER_PIN_MANIFEST: u64 = BASE_REGISTER;
const BASE_REGISTER_SMART_CONTRACT: u64 = 320;
const BASE_KAIGI_CREATE: u64 = 420;
const BASE_KAIGI_JOIN: u64 = 180;
const BASE_KAIGI_LEAVE: u64 = 150;
const BASE_KAIGI_END: u64 = 220;
const BASE_KAIGI_USAGE: u64 = 240;
const BASE_KAIGI_RELAY_MANIFEST: u64 = 220;
/// Calibrated gas for one bounded pass over a native Kaigi metadata value.
///
/// V1 independently caps each value at 1 MiB. Charging raw bytes as gas would make bounded Kaigi
/// lifecycle operations exceed the shipped 1.68M block limit, so the schedule prices one complete
/// parse/validation pass as a 32 Ki-gas work unit while retaining proportional pass counts.
const KAIGI_METADATA_READ_ESCROW: u64 = 32 * 1024;
/// Worst-case bounded work for loading one retained Kaigi record.
const KAIGI_RECORD_READ_ESCROW: u64 = KAIGI_METADATA_READ_ESCROW;
/// Worst-case bounded work for two independent retained Kaigi metadata reads.
const KAIGI_RELAY_STATE_READ_ESCROW: u64 = KAIGI_METADATA_READ_ESCROW.saturating_mul(2);
/// Worst-case bounded work for loading and replacing one retained Kaigi record.
///
/// This reserves one record unit for the initial decode and two for the deep
/// scrubbed clone plus checked serialization/canonicalization. Native execution
/// reuses dependency information and therefore does not perform a second decode.
const KAIGI_RECORD_MUTATION_ESCROW: u64 = KAIGI_RECORD_READ_ESCROW.saturating_mul(3);
/// Conservative per-row charge for bounded, fail-closed indexed registry validation.
const PER_KAIGI_RELAY_REGISTRY_ENTRY_SCAN: u64 = 32;
const BASE_KAIGI_RELAY_REGISTER: u64 = BASE_REGISTER
    + (iroha_data_model::kaigi::KAIGI_RELAY_REGISTRY_MAX_ENTRIES_V1 as u64)
        * PER_KAIGI_RELAY_REGISTRY_ENTRY_SCAN;
const BASE_KAIGI_RELAY_UNREGISTER: u64 = BASE_UNREGISTER;
const BASE_KAIGI_RELAY_HEALTH: u64 = 180;
const BASE_KAIGI_JOIN_ZK: u64 = 1_520;
const BASE_KAIGI_LEAVE_ZK: u64 = 1_520;
const BASE_KAIGI_USAGE_ZK: u64 = 1_180;
const BASE_SEALED_COMMITMENT: u64 = 96;
/// Base cost for hashing, dispatching, and recording a Parliament instruction.
const BASE_PARLIAMENT: u64 = 1_000;
/// Cost per canonical encoded Parliament instruction byte.
const PER_BYTE_PARLIAMENT: u64 = 5;
/// Fixed charge for one bounded cryptographic proof suite.
const PARLIAMENT_PROOF_UNIT: u64 = 250_000;
/// Fixed charge for one bounded timed-OVN registration proof verification.
const PARLIAMENT_REGISTRATION_VERIFY: u64 = 750_000;
/// Fixed charge for a bounded timed-OVN ballot OR-proof chunk verification.
const PARLIAMENT_BALLOT_OR_VERIFY: u64 = 750_000;
/// Fixed charge for validating a final threshold release.
const PARLIAMENT_RELEASE_VERIFY: u64 = 250_000;
/// Fixed charge for opening and bounded-decoding the timed-OVN aggregate.
const PARLIAMENT_AGGREGATE_OPEN: u64 = 250_000;
/// Cost per canonical public record inspected from committed lifecycle state.
const PER_PARLIAMENT_CACHED_RECORD: u64 = 500;
/// Default gas charged for a single confidential proof verification before any other factors.
pub const DEFAULT_ZK_GAS_BASE_VERIFY: u64 = 250_000;
/// Default gas multiplier per public input exposed by a confidential proof.
pub const DEFAULT_ZK_GAS_PER_PUBLIC_INPUT: u64 = 2_000;
/// Default gas multiplier per byte of the confidential proof payload.
pub const DEFAULT_ZK_GAS_PER_PROOF_BYTE: u64 = 5;
/// Default gas multiplier per nullifier consumed by the transaction.
pub const DEFAULT_ZK_GAS_PER_NULLIFIER: u64 = 300;
/// Default gas multiplier per commitment created by the transaction.
pub const DEFAULT_ZK_GAS_PER_COMMITMENT: u64 = 500;
/// Dynamic factors (per-byte) applied to encoded payloads where sensible.
/// Base cost of an SCCP instruction: bounded SCCP World reads and writes (`specs/sccp.md` §4).
const BASE_SCCP: u64 = BASE_REGISTER;
/// Verification base of one source-chain light-client proof (the source chain's consensus
/// signatures), matching the default ZK verification base.
const SCCP_LIGHT_CLIENT_VERIFY: u64 = DEFAULT_ZK_GAS_BASE_VERIFY;
/// Light-client proof bytes per gas unit (decoding and hashing). A maximal 8 MiB source proof
/// stays below the shipped 1 680 000 block gas limit.
const SCCP_PROOF_BYTES_PER_GAS: u64 = 8;
/// Per byte of SCCP payload or recipient data hashed and stored.
const PER_BYTE_SCCP: u64 = 1;
const PER_BYTE_JSON: u64 = 1; // charge per JSON byte
const PER_BYTE_PIN_MANIFEST: u64 = 1;
const PER_BYTE_SEALED_COMMITMENT: u64 = 1;
const PER_BYTE_KAIGI_RELAY_DESCRIPTOR: u64 = 1;
const PER_KAIGI_RELAY_HOP: u64 = 16;
/// Verification gas schedule of the protocol default ZK validity policy.
///
/// Block execution never reads this constant: it meters with the schedule
/// frozen in the block's ZK settings (`StateBlock::zk`). A chain that commits
/// no `zk_validity_policy_v1` parameter runs under exactly these rates.
pub const DEFAULT_ZK_GAS: ActualConfidentialGas = ActualConfidentialGas {
    proof_base: DEFAULT_ZK_GAS_BASE_VERIFY,
    per_public_input: DEFAULT_ZK_GAS_PER_PUBLIC_INPUT,
    per_proof_byte: DEFAULT_ZK_GAS_PER_PROOF_BYTE,
    per_nullifier: DEFAULT_ZK_GAS_PER_NULLIFIER,
    per_commitment: DEFAULT_ZK_GAS_PER_COMMITMENT,
};

/// Return whether every gas component fits within the shared block limit.
///
/// Components are subtracted from the remaining budget in order so arithmetic
/// overflow cannot turn an over-limit sum into an accepted saturated value. A
/// zero block limit retains the existing meaning of an unlimited budget.
#[must_use]
pub(crate) fn gas_components_fit_block_limit(
    block_limit: u64,
    components: impl IntoIterator<Item = u64>,
) -> bool {
    if block_limit == 0 {
        return true;
    }
    let mut remaining = block_limit;
    for gas in components {
        if gas > remaining {
            return false;
        }
        remaining -= gas;
    }
    true
}

/// Set the telemetry gauges to the schedule a block charges: operators see the
/// committed schedule, never a configured one. Metering does not read the gauges.
pub(crate) fn publish_confidential_gas_gauges(schedule: &ActualConfidentialGas) {
    #[cfg(feature = "telemetry")]
    if let Some(metrics) = iroha_telemetry::metrics::global() {
        metrics.set_confidential_gas_schedule(schedule);
    }
    #[cfg(not(feature = "telemetry"))]
    let _ = schedule;
}
/// Deterministic cost for storing a sealed transaction commitment.
#[must_use]
pub fn meter_sealed_transaction_commitment(encoded_len: usize) -> u64 {
    let encoded_len = u64::try_from(encoded_len).unwrap_or(u64::MAX);
    BASE_SEALED_COMMITMENT.saturating_add(PER_BYTE_SEALED_COMMITMENT.saturating_mul(encoded_len))
}
fn ipa_public_input_count(attachment: &ProofAttachment) -> Option<u64> {
    let backend = attachment.backend.as_str();
    if crate::zk::verifier_backend_registry_tag_v1(backend)
        != Some(iroha_data_model::zk::BackendTag::NativePipaRPasta)
        || attachment.proof.bytes.len()
            > iroha_config::parameters::defaults::zk::pipa_r::MAX_ENVELOPE_BYTES
    {
        return None;
    }
    let env: OpenVerifyEnvelope = decode_canonical(&attachment.proof.bytes).ok()?;
    let columns = crate::zk::native_pipa_r::public_instances(backend, &env).ok()?;
    columns
        .first()
        .and_then(|column| u64::try_from(column.len()).ok())
}
fn gas_for_proof_attachment(
    attachment: &ProofAttachment,
    nullifiers: usize,
    commitments: usize,
    zk_gas: &ActualConfidentialGas,
) -> u64 {
    let mut gas = zk_gas.proof_base;
    let proof_bytes = u64::try_from(attachment.proof.bytes.len()).unwrap_or(u64::MAX);
    gas = gas.saturating_add(zk_gas.per_proof_byte.saturating_mul(proof_bytes));
    if let Some(public_inputs) = ipa_public_input_count(attachment) {
        gas = gas.saturating_add(zk_gas.per_public_input.saturating_mul(public_inputs));
    }
    let nullifiers_u64 = u64::try_from(nullifiers).unwrap_or(u64::MAX);
    let commitments_u64 = u64::try_from(commitments).unwrap_or(u64::MAX);
    gas = gas.saturating_add(zk_gas.per_nullifier.saturating_mul(nullifiers_u64));
    gas = gas.saturating_add(zk_gas.per_commitment.saturating_mul(commitments_u64));
    gas
}
fn gas_for_kaigi_proof_verification(
    proof: &[u8],
    public_inputs: u64,
    nullifiers: u64,
    commitments: u64,
    zk_gas: &ActualConfidentialGas,
) -> u64 {
    let proof_bytes = u64::try_from(proof.len()).unwrap_or(u64::MAX);
    zk_gas
        .proof_base
        .saturating_add(zk_gas.per_public_input.saturating_mul(public_inputs))
        .saturating_add(zk_gas.per_proof_byte.saturating_mul(proof_bytes))
        .saturating_add(zk_gas.per_nullifier.saturating_mul(nullifiers))
        .saturating_add(zk_gas.per_commitment.saturating_mul(commitments))
}
fn gas_for_register_pin_manifest(manifest_bytes: usize) -> u64 {
    BASE_REGISTER_PIN_MANIFEST.saturating_add(
        PER_BYTE_PIN_MANIFEST.saturating_mul(u64::try_from(manifest_bytes).unwrap_or(u64::MAX)),
    )
}
fn parliament_encoded_input_gas(encoded_len: usize) -> u64 {
    BASE_PARLIAMENT.saturating_add(
        PER_BYTE_PARLIAMENT.saturating_mul(u64::try_from(encoded_len).unwrap_or(u64::MAX)),
    )
}

fn kaigi_create_record_gas(create: &dm_isi::kaigi::CreateKaigi) -> u64 {
    KAIGI_RECORD_READ_ESCROW.saturating_add(
        PER_BYTE_JSON.saturating_mul(u64::try_from(create.call.encode().len()).unwrap_or(u64::MAX)),
    )
}

fn parliament_max_cached_record_gas() -> u64 {
    PER_PARLIAMENT_CACHED_RECORD.saturating_mul(
        u64::try_from(iroha_crypto::timed_ovn::TIMED_OVN_MAX_PARTICIPANTS_V1).unwrap_or(u64::MAX),
    )
}

fn parliament_transition_confidential_work_gas(
    transition: &dm_isi::governance::ParliamentLifecycleTransitionV1,
) -> u64 {
    use dm_isi::governance::ParliamentLifecycleTransitionV1 as Transition;

    match transition {
        Transition::RegisterBallotParticipant(_) => {
            PARLIAMENT_PROOF_UNIT.saturating_add(PARLIAMENT_REGISTRATION_VERIFY)
        }
        Transition::FreezeTimedOvnCorpus(_) => {
            PARLIAMENT_PROOF_UNIT.saturating_add(PARLIAMENT_BALLOT_OR_VERIFY)
        }
        Transition::FinalizeOpenedBallot(_) => {
            PARLIAMENT_RELEASE_VERIFY.saturating_add(PARLIAMENT_AGGREGATE_OPEN)
        }
        Transition::ConsumeSortitionPulseBatch(_) | Transition::BeginBallotOpeningBatch(_) => {
            PARLIAMENT_PROOF_UNIT
        }
        _ => 0,
    }
}

fn parliament_transition_cached_work_gas(
    transition: &dm_isi::governance::ParliamentLifecycleTransitionV1,
) -> u64 {
    use dm_isi::governance::ParliamentLifecycleTransitionV1 as Transition;

    match transition {
        Transition::RegisterBallotParticipant(_)
        | Transition::CloseBallotRegistration(_)
        | Transition::RecordBallotDropout(_)
        | Transition::FreezeBallotSurvivors(_)
        | Transition::FinalizeOpenedBallot(_) => parliament_max_cached_record_gas(),
        Transition::FreezeTimedOvnCorpus(payload) => PER_PARLIAMENT_CACHED_RECORD
            .saturating_mul(u64::try_from(payload.ballot_records.len()).unwrap_or(u64::MAX)),
        _ => 0,
    }
}

fn gas_for_parliament_transition(
    instruction: &dm_isi::governance::SubmitParliamentLifecycleTransitionV1,
) -> u64 {
    parliament_encoded_input_gas(instruction.encode().len())
        .saturating_add(parliament_transition_confidential_work_gas(
            &instruction.transition,
        ))
        .saturating_add(parliament_transition_cached_work_gas(
            &instruction.transition,
        ))
}
fn sccp_byte_gas(bytes: usize, per_unit: u64, bytes_per_unit: u64) -> u64 {
    let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    per_unit.saturating_mul(bytes.div_ceil(bytes_per_unit))
}
fn sccp_proof_gas(proof_bytes: usize) -> u64 {
    SCCP_LIGHT_CLIENT_VERIFY.saturating_add(sccp_byte_gas(proof_bytes, 1, SCCP_PROOF_BYTES_PER_GAS))
}
/// Gas of the SCCP v1 instructions (`specs/sccp.md` §4), proportional to their proof work and
/// payload bytes, or `None` for any other instruction.
fn sccp_instruction_gas(any: &dyn core::any::Any) -> Option<u64> {
    use dm_isi::sccp;
    if let Some(record) = any.downcast_ref::<sccp::RecordSccpMessage>() {
        return Some(
            BASE_SCCP
                .saturating_add(BASE_TRANSFER)
                .saturating_add(sccp_byte_gas(record.recipient.len(), PER_BYTE_SCCP, 1)),
        );
    }
    if let Some(inbound) = any.downcast_ref::<sccp::SubmitSccpInboundMessageV1>() {
        return Some(
            BASE_SCCP
                .saturating_add(sccp_proof_gas(inbound.proof.len()))
                .saturating_add(sccp_byte_gas(inbound.payload.len(), PER_BYTE_SCCP, 1)),
        );
    }
    if let Some(void) = any.downcast_ref::<sccp::SubmitSccpOutboundVoidV1>() {
        return Some(BASE_SCCP.saturating_add(sccp_proof_gas(void.proof.len())));
    }
    if let Some(advance) = any.downcast_ref::<sccp::AdvanceSccpLightClientV1>() {
        return Some(BASE_SCCP.saturating_add(sccp_proof_gas(advance.advance.len())));
    }
    if let Some(report) = any.downcast_ref::<sccp::ReportSccpLightClientEquivocationV1>() {
        return Some(
            BASE_SCCP
                .saturating_add(sccp_proof_gas(report.a.len()))
                .saturating_add(sccp_proof_gas(report.b.len())),
        );
    }
    if any.downcast_ref::<sccp::SettleSccpV1>().is_some() {
        // A settlement releases escrow and may register its recipient implicitly.
        return Some(
            BASE_SCCP
                .saturating_add(BASE_TRANSFER)
                .saturating_add(BASE_REGISTER),
        );
    }
    if any.downcast_ref::<sccp::InitializeSccpV1>().is_some() {
        return Some(BASE_SCCP);
    }
    None
}
/// Compute gas for a single instruction using a simple schedule.
///
/// `zk_gas` is the verification gas schedule of the block that executes the
/// instruction (the block's frozen ZK settings). It prices proof-bearing
/// instructions; every other cost is a constant of the release.
#[allow(clippy::too_many_lines)]
pub fn meter_instruction(instr: &InstructionBox, zk_gas: &ActualConfidentialGas) -> u64 {
    // Helper to compute JSON-like payload size when present.
    // Use the canonical JSON string length without re-encoding to avoid
    // extra allocations during metering. `Json` stores a normalized string,
    // so measuring its length yields a deterministic size signal.
    fn json_len(j: &iroha_primitives::json::Json) -> usize {
        j.get().len()
    }
    // Downcast by visiting known grouped enums first, then concrete types.
    // Unclassified instructions use the fixed first-release base cost.
    let any = instr.as_any();
    // Native game charges reserve bounded record traversal and crypto before execution.
    if let Some(proof) = any.downcast_ref::<dm_isi::game::SettleGameSessionV1>() {
        return 250_000_u64
            .saturating_add((proof.proof.proof_bytes.len() as u64).saturating_mul(5));
    }
    if let Some(proof) = any.downcast_ref::<dm_isi::game::VerifyExecutionProofV1>() {
        return 250_000_u64
            .saturating_add((proof.proof.proof_bytes.len() as u64).saturating_mul(5));
    }
    if any.is::<dm_isi::game::RegisterExecutionProofProfileV1>() {
        return 32_000;
    }
    if let Some(checkpoint) = any.downcast_ref::<dm_isi::game::CommitGameCheckpointV1>() {
        return 40_000_u64.saturating_add((checkpoint.encode().len() as u64).saturating_mul(5));
    }
    if let Some(session) = any.downcast_ref::<dm_isi::game::OpenGameSessionV1>() {
        let seats = u64::from(session.manifest.max_participants.min(32));
        let payout_cases = if session.stake.is_zero() {
            0
        } else {
            seats * (seats + 1) / 2
        };
        return 32_000_u64
            .saturating_add(payout_cases.saturating_mul(1_024))
            .saturating_add((session.encode().len() as u64).saturating_mul(5));
    }
    if any.is::<dm_isi::game::JoinGameSessionV1>()
        || any.is::<dm_isi::game::StartGameSessionV1>()
        || any.is::<dm_isi::game::ChallengeGameSessionV1>()
        || any.is::<dm_isi::game::CommitGameInputsV1>()
        || any.is::<dm_isi::game::RevealGameInputsV1>()
        || any.is::<dm_isi::game::AdvanceGameDeadlineV1>()
        || any.is::<dm_isi::game::ExpireGameSessionV1>()
        || any.is::<dm_isi::game::ClaimGamePayoutV1>()
        || any.is::<dm_isi::game::StakeGameItemV1>()
    {
        return 32_000;
    }
    // Register
    if let Some(reg) = any.downcast_ref::<dm_isi::register::RegisterBox>() {
        return match reg {
            dm_isi::register::RegisterBox::Peer(_) => BASE_REGISTER + 20,
            dm_isi::register::RegisterBox::Account(_) => {
                BASE_REGISTER.saturating_add(KAIGI_RECORD_READ_ESCROW)
            }
            dm_isi::register::RegisterBox::Domain(register) => {
                let allowlist_bytes = register
                    .object
                    .metadata
                    .iter()
                    .find(|(key, _)| key.as_ref() == "kaigi_relay_allowlist")
                    .map_or(0, |(_, value)| {
                        u64::try_from(json_len(value)).unwrap_or(u64::MAX)
                    });
                BASE_REGISTER.saturating_add(PER_BYTE_JSON.saturating_mul(allowlist_bytes))
            }
            dm_isi::register::RegisterBox::AssetDefinition(_)
            | dm_isi::register::RegisterBox::Nft(_)
            | dm_isi::register::RegisterBox::Role(_) => BASE_REGISTER,
            dm_isi::register::RegisterBox::Trigger(_) => BASE_REGISTER + 50, // triggers slightly heavier
        };
    }
    // Unregister
    if let Some(unreg) = any.downcast_ref::<dm_isi::register::UnregisterBox>() {
        return match unreg {
            dm_isi::register::UnregisterBox::Account(_)
            | dm_isi::register::UnregisterBox::Domain(_) => {
                BASE_UNREGISTER.saturating_add(KAIGI_RECORD_READ_ESCROW)
            }
            dm_isi::register::UnregisterBox::Peer(_)
            | dm_isi::register::UnregisterBox::AssetDefinition(_)
            | dm_isi::register::UnregisterBox::Nft(_)
            | dm_isi::register::UnregisterBox::Role(_)
            | dm_isi::register::UnregisterBox::Trigger(_) => BASE_UNREGISTER,
        };
    }
    // Transfers
    if let Some(xfer) = any.downcast_ref::<dm_isi::transfer::TransferBox>() {
        return match xfer {
            dm_isi::transfer::TransferBox::AssetDefinition(_)
            | dm_isi::transfer::TransferBox::Domain(_) => BASE_TRANSFER + 20,
            dm_isi::transfer::TransferBox::Asset(_) | dm_isi::transfer::TransferBox::Nft(_) => {
                BASE_TRANSFER
            }
        };
    }
    if let Some(batch) = any.downcast_ref::<dm_isi::transfer::TransferAssetBatch>() {
        let count = u64::try_from(batch.entries().len()).unwrap_or(u64::MAX);
        return BASE_TRANSFER.saturating_mul(count);
    }
    // Mint / Burn
    if let Some(mint) = any.downcast_ref::<dm_isi::mint_burn::MintBox>() {
        return match mint {
            dm_isi::mint_burn::MintBox::Asset(_) => BASE_MINT,
            dm_isi::mint_burn::MintBox::TriggerRepetitions(_) => BASE_MINT / 2,
        };
    }
    if let Some(burn) = any.downcast_ref::<dm_isi::mint_burn::BurnBox>() {
        return match burn {
            dm_isi::mint_burn::BurnBox::Asset(_) => BASE_BURN,
            dm_isi::mint_burn::BurnBox::TriggerRepetitions(_) => BASE_BURN / 2,
        };
    }
    // Key-value
    if let Some(kv) = any.downcast_ref::<dm_isi::SetKeyValueBox>() {
        let sz = match kv {
            dm_isi::SetKeyValueBox::Domain(i) => json_len(&i.value),
            dm_isi::SetKeyValueBox::Account(i) => json_len(&i.value),
            dm_isi::SetKeyValueBox::AssetDefinition(i) => json_len(&i.value),
            dm_isi::SetKeyValueBox::Nft(i) => json_len(&i.value),
            dm_isi::SetKeyValueBox::Trigger(i) => json_len(&i.value),
        } as u64;
        return BASE_SET_KV + PER_BYTE_JSON.saturating_mul(sz);
    }
    if any.downcast_ref::<dm_isi::RemoveKeyValueBox>().is_some() {
        return BASE_REMOVE_KV;
    }
    // Permissions
    if any.downcast_ref::<dm_isi::GrantBox>().is_some() {
        return BASE_GRANT;
    }
    if any.downcast_ref::<dm_isi::RevokeBox>().is_some() {
        return BASE_REVOKE;
    }
    // Misc
    if let Some(et) = any.downcast_ref::<dm_isi::ExecuteTrigger>() {
        let args_len = json_len(&et.args) as u64;
        return BASE_EXECUTE_TRIGGER + PER_BYTE_JSON.saturating_mul(args_len);
    }
    if any.downcast_ref::<dm_isi::Upgrade>().is_some() {
        return BASE_UPGRADE;
    }
    if let Some(log) = any.downcast_ref::<dm_isi::Log>() {
        // Charge per message length (stored as String)
        return BASE_LOG + (log.msg.len() as u64);
    }
    if let Some(custom) = any.downcast_ref::<dm_isi::CustomInstruction>() {
        let sz = json_len(&custom.payload) as u64;
        return BASE_CUSTOM + PER_BYTE_JSON.saturating_mul(sz);
    }
    // Account controller and primary-alias lifecycle instructions can validate one retained,
    // indexed Kaigi metadata value before rejecting a rekey or relay-home move. Reserve that
    // bounded read even when a particular execution does not need it; metering must remain
    // independent of world state.
    if any.downcast_ref::<dm_isi::AddSignatory>().is_some()
        || any.downcast_ref::<dm_isi::RemoveSignatory>().is_some()
        || any.downcast_ref::<dm_isi::SetAccountQuorum>().is_some()
        || any
            .downcast_ref::<dm_isi::account_recovery::ReplaceAccountController>()
            .is_some()
        || any
            .downcast_ref::<dm_isi::account_recovery::FinalizeAccountRecovery>()
            .is_some()
        || any
            .downcast_ref::<dm_isi::alias_setup::CompareAndSetPrimaryAccountAlias>()
            .is_some()
    {
        return BASE_CUSTOM.saturating_add(KAIGI_RECORD_READ_ESCROW);
    }
    if let Some(create) = any.downcast_ref::<dm_isi::kaigi::CreateKaigi>() {
        let proof_gas = create.proof.as_deref().map_or(0, |proof| {
            gas_for_kaigi_proof_verification(proof, 6, 1, 1, zk_gas)
        });
        let relay_gas = create
            .call
            .relay_manifest
            .as_ref()
            .map_or(0, kaigi_relay_manifest_gas);
        return BASE_KAIGI_CREATE
            .saturating_add(proof_gas)
            .saturating_add(relay_gas)
            .saturating_add(kaigi_create_record_gas(create));
    }
    // Private roster transitions remain fail-closed in production and do not dispatch a verifier;
    // retain their calibrated payload bases while sourcing the byte price from governance.
    if let Some(join) = any.downcast_ref::<dm_isi::kaigi::JoinKaigi>() {
        let is_privacy = join.commitment.is_some()
            || join.nullifier.is_some()
            || join.roster_root.is_some()
            || join.proof.is_some();
        if is_privacy {
            let proof_bytes = join
                .proof
                .as_ref()
                .map_or(0, |proof| u64::try_from(proof.len()).unwrap_or(u64::MAX));
            return BASE_KAIGI_JOIN_ZK
                .saturating_add(KAIGI_RECORD_MUTATION_ESCROW)
                .saturating_add(zk_gas.per_proof_byte.saturating_mul(proof_bytes));
        }
        return BASE_KAIGI_JOIN.saturating_add(KAIGI_RECORD_MUTATION_ESCROW);
    }
    if let Some(leave) = any.downcast_ref::<dm_isi::kaigi::LeaveKaigi>() {
        let is_privacy = leave.commitment.is_some()
            || leave.nullifier.is_some()
            || leave.roster_root.is_some()
            || leave.proof.is_some();
        if is_privacy {
            let proof_bytes = leave
                .proof
                .as_ref()
                .map_or(0, |proof| u64::try_from(proof.len()).unwrap_or(u64::MAX));
            return BASE_KAIGI_LEAVE_ZK
                .saturating_add(KAIGI_RECORD_MUTATION_ESCROW)
                .saturating_add(zk_gas.per_proof_byte.saturating_mul(proof_bytes));
        }
        return BASE_KAIGI_LEAVE.saturating_add(KAIGI_RECORD_MUTATION_ESCROW);
    }
    if let Some(end) = any.downcast_ref::<dm_isi::kaigi::EndKaigi>() {
        let proof_gas = end.proof.as_deref().map_or(0, |proof| {
            gas_for_kaigi_proof_verification(proof, 6, 1, 0, zk_gas)
        });
        return BASE_KAIGI_END
            .saturating_add(KAIGI_RECORD_MUTATION_ESCROW)
            .saturating_add(proof_gas);
    }
    if let Some(usage) = any.downcast_ref::<dm_isi::kaigi::RecordKaigiUsage>() {
        let is_privacy = usage.usage_commitment.is_some() || usage.proof.is_some();
        if is_privacy {
            let proof_gas = usage.proof.as_deref().map_or(0, |proof| {
                gas_for_kaigi_proof_verification(proof, 1, 0, 1, zk_gas)
            });
            return BASE_KAIGI_USAGE_ZK
                .saturating_add(KAIGI_RECORD_MUTATION_ESCROW)
                .saturating_add(proof_gas);
        }
        return BASE_KAIGI_USAGE.saturating_add(KAIGI_RECORD_MUTATION_ESCROW);
    }
    if let Some(update) = any.downcast_ref::<dm_isi::kaigi::SetKaigiRelayManifest>() {
        let manifest_gas = update
            .relay_manifest
            .as_ref()
            .map_or(0, kaigi_relay_manifest_gas);
        return BASE_KAIGI_RELAY_MANIFEST
            .saturating_add(KAIGI_RECORD_MUTATION_ESCROW)
            .saturating_add(manifest_gas);
    }
    if let Some(register) = any.downcast_ref::<dm_isi::kaigi::RegisterKaigiRelay>() {
        let key_bytes = u64::try_from(register.relay.hpke_public_key.len()).unwrap_or(u64::MAX);
        return BASE_KAIGI_RELAY_REGISTER
            .saturating_add(KAIGI_RELAY_STATE_READ_ESCROW)
            .saturating_add(PER_BYTE_KAIGI_RELAY_DESCRIPTOR.saturating_mul(key_bytes));
    }
    if any
        .downcast_ref::<dm_isi::kaigi::UnregisterKaigiRelay>()
        .is_some()
    {
        return BASE_KAIGI_RELAY_UNREGISTER.saturating_add(KAIGI_RELAY_STATE_READ_ESCROW);
    }
    if let Some(report) = any.downcast_ref::<dm_isi::kaigi::ReportKaigiRelayHealth>() {
        let notes_bytes = report
            .notes
            .as_ref()
            .map_or(0, |notes| u64::try_from(notes.len()).unwrap_or(u64::MAX));
        return BASE_KAIGI_RELAY_HEALTH
            .saturating_add(KAIGI_RELAY_STATE_READ_ESCROW)
            .saturating_add(PER_BYTE_JSON.saturating_mul(notes_bytes));
    }
    if let Some(verify) = any.downcast_ref::<dm_isi::zk::VerifyProof>() {
        return gas_for_proof_attachment(&verify.attachment, 0, 0, zk_gas);
    }
    if let Some(ballot) = any.downcast_ref::<dm_isi::zk::SubmitBallot>() {
        return gas_for_proof_attachment(&ballot.ballot_proof, 1, 0, zk_gas);
    }
    if let Some(finalize) = any.downcast_ref::<dm_isi::zk::FinalizeElection>() {
        return gas_for_proof_attachment(&finalize.tally_proof, 0, 0, zk_gas);
    }
    if any
        .downcast_ref::<dm_isi::smart_contract_code::RegisterSmartContractCode>()
        .is_some()
    {
        return BASE_REGISTER_SMART_CONTRACT;
    }
    if let Some(register) = any.downcast_ref::<dm_isi::sorafs::RegisterPinManifest>() {
        return gas_for_register_pin_manifest(register.manifest_payload.len());
    }
    if let Some(create) =
        any.downcast_ref::<dm_isi::governance::CreateParliamentGovernanceAttemptV1>()
    {
        return parliament_encoded_input_gas(create.encode().len());
    }
    if let Some(transition) =
        any.downcast_ref::<dm_isi::governance::SubmitParliamentLifecycleTransitionV1>()
    {
        return gas_for_parliament_transition(transition);
    }
    if let Some(gas) = sccp_instruction_gas(any) {
        return gas;
    }
    // Unclassified instructions have a fixed first-release cost. Avoid encoding
    // the full instruction here: the retired per-byte factor was zero, so that
    // allocation and traversal could not affect the charged gas.
    BASE_CUSTOM
}
fn kaigi_relay_manifest_gas(manifest: &iroha_data_model::kaigi::KaigiRelayManifest) -> u64 {
    manifest.hops.iter().fold(0_u64, |total, hop| {
        let key_bytes = u64::try_from(hop.hpke_public_key.len()).unwrap_or(u64::MAX);
        total
            .saturating_add(PER_KAIGI_RELAY_HOP)
            .saturating_add(KAIGI_RELAY_STATE_READ_ESCROW)
            .saturating_add(PER_BYTE_KAIGI_RELAY_DESCRIPTOR.saturating_mul(key_bytes))
    })
}
/// Compute gas for a sequence of instructions under the verification gas
/// schedule `zk_gas` of the executing block.
pub fn meter_instructions(is: &[InstructionBox], zk_gas: &ActualConfidentialGas) -> u64 {
    is.iter().fold(0_u64, |total, instruction| {
        total.saturating_add(meter_instruction(instruction, zk_gas))
    })
}
/// Return the portion of the gas schedule attributed to confidential ISIs,
/// priced by the verification gas schedule `zk_gas` of the executing block.
#[must_use]
pub fn confidential_gas_cost(instr: &InstructionBox, zk_gas: &ActualConfidentialGas) -> u64 {
    let any = instr.as_any();
    if let Some(create) = any.downcast_ref::<dm_isi::kaigi::CreateKaigi>() {
        return create.proof.as_deref().map_or(0, |proof| {
            gas_for_kaigi_proof_verification(proof, 6, 1, 1, zk_gas)
        });
    }
    if let Some(end) = any.downcast_ref::<dm_isi::kaigi::EndKaigi>() {
        return end.proof.as_deref().map_or(0, |proof| {
            gas_for_kaigi_proof_verification(proof, 6, 1, 0, zk_gas)
        });
    }
    if let Some(usage) = any.downcast_ref::<dm_isi::kaigi::RecordKaigiUsage>() {
        return usage.proof.as_deref().map_or(0, |proof| {
            gas_for_kaigi_proof_verification(proof, 1, 0, 1, zk_gas)
        });
    }
    if let Some(verify) = any.downcast_ref::<dm_isi::zk::VerifyProof>() {
        return gas_for_proof_attachment(&verify.attachment, 0, 0, zk_gas);
    }
    if let Some(ballot) = any.downcast_ref::<dm_isi::zk::SubmitBallot>() {
        return gas_for_proof_attachment(&ballot.ballot_proof, 1, 0, zk_gas);
    }
    if let Some(finalize) = any.downcast_ref::<dm_isi::zk::FinalizeElection>() {
        return gas_for_proof_attachment(&finalize.tally_proof, 0, 0, zk_gas);
    }
    if let Some(transition) =
        any.downcast_ref::<dm_isi::governance::SubmitParliamentLifecycleTransitionV1>()
    {
        return parliament_transition_confidential_work_gas(&transition.transition);
    }
    0
}
/// Return the saturating confidential-gas total for an instruction sequence.
pub(crate) fn sum_confidential_gas_costs<I>(instructions: I, zk_gas: &ActualConfidentialGas) -> u64
where
    I: IntoIterator,
    I::Item: Borrow<InstructionBox>,
{
    instructions.into_iter().fold(0_u64, |total, instruction| {
        total.saturating_add(confidential_gas_cost(instruction.borrow(), zk_gas))
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_model_base::domain::DomainId;

    #[test]
    fn two_schedules_meter_independently_in_one_process() {
        use iroha_data_model::{isi::zk::VerifyProof, proof::VerifyingKeyId};
        // The schedule is an argument, not process state: two blocks with
        // different committed policies are metered side by side.
        let changed = ActualConfidentialGas {
            proof_base: DEFAULT_ZK_GAS.proof_base + 1,
            per_public_input: DEFAULT_ZK_GAS.per_public_input + 2,
            per_proof_byte: DEFAULT_ZK_GAS.per_proof_byte + 3,
            per_nullifier: DEFAULT_ZK_GAS.per_nullifier + 4,
            per_commitment: DEFAULT_ZK_GAS.per_commitment + 5,
        };
        let fixture = native_framing_fixture_envelope(
            crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            [0u8; 32],
        );
        let proof_box = fixture.proof_box("pipa-r/pasta");
        let attachment = ProofAttachment::new_ref(
            proof_box.backend.clone(),
            proof_box,
            VerifyingKeyId::new("pipa-r/pasta", "vk-two-schedules"),
        );
        let proof_bytes = attachment.proof.bytes.len() as u64;
        let public_inputs =
            super::ipa_public_input_count(&attachment).expect("native public column");
        assert_eq!(public_inputs, 9);
        let instruction: InstructionBox = VerifyProof::new(attachment).into();
        let under_default = meter_instruction(&instruction, &DEFAULT_ZK_GAS);
        let under_changed = meter_instruction(&instruction, &changed);
        assert_eq!(
            under_changed - under_default,
            1 + 2 * public_inputs + 3 * proof_bytes
        );
        // Metering under one schedule leaves the other unchanged.
        assert_eq!(
            meter_instruction(&instruction, &DEFAULT_ZK_GAS),
            under_default
        );
        assert_eq!(confidential_gas_cost(&instruction, &changed), under_changed);
        // An instruction without a proof costs the same under every schedule.
        let (account, _) = gen_account_in("wonderland");
        let plain = InstructionBox::from(SetKeyValueBox::from(SetKeyValue::account(
            account,
            "k".parse().expect("valid name"),
            Json::new("v"),
        )));
        assert_eq!(
            meter_instruction(&plain, &DEFAULT_ZK_GAS),
            meter_instruction(&plain, &changed)
        );
        assert_eq!(confidential_gas_cost(&plain, &changed), 0);
    }
    #[test]
    fn block_gas_component_fit_is_overflow_safe() {
        assert!(gas_components_fit_block_limit(0, [u64::MAX, 1]));
        assert!(gas_components_fit_block_limit(u64::MAX, [u64::MAX]));
        assert!(!gas_components_fit_block_limit(u64::MAX, [u64::MAX, 1]));
        assert!(!gas_components_fit_block_limit(u64::MAX, [u64::MAX - 1, 2]));
        assert!(gas_components_fit_block_limit(10, [3, 7]));
        assert!(!gas_components_fit_block_limit(10, [3, 8]));
    }
    use crate::{
        kura::Kura, query::store::LiveQueryStore, state::State,
        zk::test_utils::native_framing_fixture_envelope,
    };
    use iroha_config::parameters::actual as cfg;
    use iroha_data_model::governance::types::{
        BallotAttemptId, GovernanceAttemptId, PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1,
    };
    use iroha_data_model::prelude::*;
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::json::Json;
    use iroha_test_samples::gen_account_in;
    fn sample_account() -> AccountId {
        gen_account_in("wonderland").0
    }
    #[test]
    fn set_kv_scales_with_value_length() {
        let id = sample_account();
        let small = SetKeyValue::account(id.clone(), "k".parse().unwrap(), Json::new("v"));
        let big = SetKeyValue::account(id, "k".parse().unwrap(), Json::new("v".repeat(256)));
        let g_small = meter_instruction(
            &InstructionBox::from(SetKeyValueBox::from(small)),
            &DEFAULT_ZK_GAS,
        );
        let g_big = meter_instruction(
            &InstructionBox::from(SetKeyValueBox::from(big)),
            &DEFAULT_ZK_GAS,
        );
        assert!(g_big > g_small);
    }
    #[test]
    fn domain_registration_gas_accounts_for_kaigi_allowlist_bytes() {
        use iroha_data_model::kaigi::{KaigiRelayAllowlist, kaigi_relay_allowlist_key};

        let key = kaigi_relay_allowlist_key().expect("allowlist metadata key");
        let small_value = Json::try_new(KaigiRelayAllowlist::default()).expect("small allowlist");
        let mut large_allowlist = KaigiRelayAllowlist::default();
        for _ in 0..32 {
            large_allowlist.allowed_relays.insert(sample_account());
        }
        let large_value = Json::try_new(large_allowlist).expect("large allowlist");
        let make_registration = |name: &str, value: Json| {
            let mut metadata = Metadata::default();
            metadata.insert(key.clone(), value);
            InstructionBox::from(Register::domain(
                Domain::new(DomainId::try_new(name, "universal").expect("valid domain id"))
                    .with_metadata(metadata),
            ))
        };
        let small = make_registration("small-allowlist-gas", small_value.clone());
        let large = make_registration("large-allowlist-gas", large_value.clone());
        assert_eq!(
            meter_instruction(&small, &DEFAULT_ZK_GAS),
            BASE_REGISTER
                + u64::try_from(small_value.as_ref().len()).expect("JSON length fits u64")
        );
        assert_eq!(
            meter_instruction(&large, &DEFAULT_ZK_GAS),
            BASE_REGISTER
                + u64::try_from(large_value.as_ref().len()).expect("JSON length fits u64")
        );
        assert!(
            meter_instruction(&large, &DEFAULT_ZK_GAS) > meter_instruction(&small, &DEFAULT_ZK_GAS)
        );
    }
    #[test]
    fn mint_and_transfer_have_nonzero_costs() {
        let a = sample_account();
        let def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "xor".parse().unwrap(),
            );
        let mint =
            dm_isi::mint_burn::Mint::asset_quantity(1u64, AssetId::of(def.clone(), a.clone()));
        let xfer = dm_isi::transfer::Transfer::asset_quantity(AssetId::of(def, a.clone()), 1u64, a);
        let g_mint = meter_instruction(
            &InstructionBox::from(dm_isi::mint_burn::MintBox::from(mint)),
            &DEFAULT_ZK_GAS,
        );
        let g_xfer = meter_instruction(
            &InstructionBox::from(dm_isi::transfer::TransferBox::from(xfer)),
            &DEFAULT_ZK_GAS,
        );
        assert!(g_mint > 0 && g_xfer > 0);
    }
    #[test]
    fn sealed_commitment_cost_is_nonzero_and_size_sensitive() {
        let small = meter_sealed_transaction_commitment(32);
        let large = meter_sealed_transaction_commitment(256);
        assert!(small > 0);
        assert!(large > small);
    }
    #[test]
    fn pin_manifest_registration_gas_scales_with_manifest_bytes() {
        let small = InstructionBox::from(dm_isi::sorafs::RegisterPinManifest::new(
            vec![0; 1],
            None,
            None,
        ));
        let large = InstructionBox::from(dm_isi::sorafs::RegisterPinManifest::new(
            vec![0; 4096],
            None,
            None,
        ));
        let small = meter_instruction(&small, &DEFAULT_ZK_GAS);
        let large = meter_instruction(&large, &DEFAULT_ZK_GAS);
        assert_eq!(small, BASE_REGISTER_PIN_MANIFEST + 1);
        assert_eq!(large, BASE_REGISTER_PIN_MANIFEST + 4096);
        assert_eq!(large - small, 4095);
    }
    #[test]
    fn batch_meter_sums_items() {
        let a = sample_account();
        let def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "rose".parse().unwrap(),
            );
        let r = dm_isi::register::Register::asset_definition({
            let __asset_definition_id = def.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "rose".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
        });
        let m = dm_isi::mint_burn::Mint::asset_quantity(10u64, AssetId::of(def, a));
        let v = vec![
            InstructionBox::from(dm_isi::register::RegisterBox::from(r)),
            InstructionBox::from(dm_isi::mint_burn::MintBox::from(m)),
        ];
        let sum_inline = v
            .iter()
            .map(|instruction| meter_instruction(instruction, &DEFAULT_ZK_GAS))
            .sum::<u64>();
        assert_eq!(sum_inline, meter_instructions(&v, &DEFAULT_ZK_GAS));
    }
    #[test]
    fn batch_meter_saturates_governed_kaigi_proof_costs() {
        use iroha_data_model::{
            isi::kaigi::CreateKaigi,
            kaigi::{KaigiId, NewKaigi},
        };

        let saturating = ActualConfidentialGas {
            proof_base: u64::MAX,
            per_public_input: 0,
            per_proof_byte: 0,
            per_nullifier: 0,
            per_commitment: 0,
        };
        let call_id = KaigiId::new(
            DomainId::try_new("kaigi-gas", "universal").expect("valid domain id"),
            "saturated-batch".parse().expect("valid call name"),
        );
        let make_instruction = || {
            InstructionBox::from(CreateKaigi {
                call: NewKaigi::with_defaults(call_id.clone(), sample_account()),
                commitment: None,
                nullifier: None,
                roster_root: None,
                proof: Some(Vec::new()),
            })
        };
        let instructions = [make_instruction(), make_instruction()];
        assert_eq!(meter_instruction(&instructions[0], &saturating), u64::MAX);
        assert_eq!(meter_instructions(&instructions, &saturating), u64::MAX);
        assert_eq!(
            super::sum_confidential_gas_costs(instructions.iter(), &saturating),
            u64::MAX,
            "queued confidential-gas accounting must saturate too"
        );
    }
    #[test]
    fn batch_meter_saturates_on_overflow() {
        use iroha_data_model::{isi::zk::VerifyProof, proof::VerifyingKeyId};

        let saturating = ActualConfidentialGas {
            proof_base: u64::MAX,
            per_public_input: 0,
            per_proof_byte: 0,
            per_nullifier: 0,
            per_commitment: 0,
        };
        let fixture = native_framing_fixture_envelope(
            crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            [0_u8; 32],
        );
        let proof_box = fixture.proof_box("pipa-r/pasta");
        let attachment = ProofAttachment::new_ref(
            proof_box.backend.clone(),
            proof_box,
            VerifyingKeyId::new("pipa-r/pasta", "vk-batch-overflow"),
        );
        let instruction: InstructionBox = VerifyProof::new(attachment).into();
        let gas = meter_instructions(&[instruction.clone(), instruction], &saturating);

        assert_eq!(gas, u64::MAX);
    }
    #[test]
    fn unclassified_instruction_has_fixed_cost() {
        let instruction = InstructionBox::from(dm_isi::SetParameter::new(
            iroha_data_model::parameter::Parameter::Sumeragi(
                iroha_data_model::parameter::system::SumeragiParameter::MaxClockDriftMs(1),
            ),
        ));
        assert_eq!(
            meter_instruction(&instruction, &DEFAULT_ZK_GAS),
            BASE_CUSTOM
        );
    }
    fn parliament_corpus_instruction(
        record_count: usize,
    ) -> dm_isi::governance::SubmitParliamentLifecycleTransitionV1 {
        dm_isi::governance::SubmitParliamentLifecycleTransitionV1 {
            governance_attempt_id: GovernanceAttemptId::new([0x31; 32]),
            transition: dm_isi::governance::ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(
                dm_isi::governance::ParliamentFreezeTimedOvnCorpusV1 {
                    ballot_attempt_id: BallotAttemptId::new([0x32; 32]),
                    ballot_records: vec![
                        vec![0x33; crate::governance::timed_ovn::TIMED_OVN_BALLOT_RECORD_BYTES_V1];
                        record_count
                    ],
                },
            ),
        }
    }
    #[test]
    fn parliament_attempt_creation_uses_encoded_input_schedule() {
        let create = dm_isi::governance::CreateParliamentGovernanceAttemptV1 {
            proposal: iroha_data_model::governance::types::ProposalKind::DeployContract(
                iroha_data_model::governance::types::DeployContractProposal {
                    proposal_operator: sample_account(),
                    contract_address:
                        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
                            .parse()
                            .expect("parse gas fixture contract address"),
                    code_hash: iroha_data_model::governance::types::ContractCodeHash::new(
                        [0x35; 32],
                    ),
                    abi_hash: iroha_data_model::governance::types::ContractAbiHash::new([0x36; 32]),
                    abi_version: 1_u16.into(),
                    manifest_provenance: None,
                },
            ),
            attempt_sequence: 0,
        };
        let expected = parliament_encoded_input_gas(create.encode().len());
        let instruction = InstructionBox::from(create);
        assert_eq!(meter_instruction(&instruction, &DEFAULT_ZK_GAS), expected);
        assert_eq!(confidential_gas_cost(&instruction, &DEFAULT_ZK_GAS), 0);
    }
    #[test]
    fn parliament_transition_gas_is_explicit_and_saturating() {
        let transition = dm_isi::governance::SubmitParliamentLifecycleTransitionV1 {
            governance_attempt_id: GovernanceAttemptId::new([0x34; 32]),
            transition: dm_isi::governance::ParliamentLifecycleTransitionV1::CompleteQualification,
        };
        let expected = parliament_encoded_input_gas(transition.encode().len());
        let instruction = InstructionBox::from(transition);
        assert_eq!(meter_instruction(&instruction, &DEFAULT_ZK_GAS), expected);
        assert!(expected > BASE_CUSTOM);
        let maximum_host_length = parliament_encoded_input_gas(usize::MAX);
        let expected_maximum_host_length = BASE_PARLIAMENT.saturating_add(
            PER_BYTE_PARLIAMENT.saturating_mul(u64::try_from(usize::MAX).unwrap_or(u64::MAX)),
        );
        assert_eq!(maximum_host_length, expected_maximum_host_length);
        if usize::BITS == u64::BITS {
            assert_eq!(maximum_host_length, u64::MAX);
        }
    }
    #[test]
    fn timed_ovn_registration_gas_covers_proof_and_max_committed_roster_scan() {
        let transition = dm_isi::governance::SubmitParliamentLifecycleTransitionV1 {
            governance_attempt_id: GovernanceAttemptId::new([0x37; 32]),
            transition:
                dm_isi::governance::ParliamentLifecycleTransitionV1::RegisterBallotParticipant(
                    dm_isi::governance::ParliamentRegisterBallotParticipantV1 {
                        ballot_attempt_id: BallotAttemptId::new([0x38; 32]),
                        registration_record: vec![
                            0x39;
                            crate::governance::timed_ovn::TIMED_OVN_REGISTRATION_RECORD_BYTES_V1
                        ],
                    },
                ),
        };
        let expected = parliament_encoded_input_gas(transition.encode().len())
            .saturating_add(PARLIAMENT_PROOF_UNIT)
            .saturating_add(PARLIAMENT_REGISTRATION_VERIFY)
            .saturating_add(parliament_max_cached_record_gas());
        let instruction = InstructionBox::from(transition);
        assert_eq!(meter_instruction(&instruction, &DEFAULT_ZK_GAS), expected);
        assert_eq!(
            confidential_gas_cost(&instruction, &DEFAULT_ZK_GAS),
            PARLIAMENT_PROOF_UNIT + PARLIAMENT_REGISTRATION_VERIFY
        );
        assert!(expected <= 1_680_000);
    }
    #[test]
    fn maximum_timed_ovn_chunk_fits_standard_default_genesis_block_gas_limit() {
        let transition =
            parliament_corpus_instruction(PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1);
        let encoded = transition.encode().len();
        let expected = parliament_encoded_input_gas(encoded)
            .saturating_add(PARLIAMENT_PROOF_UNIT)
            .saturating_add(PARLIAMENT_BALLOT_OR_VERIFY)
            .saturating_add(
                PER_PARLIAMENT_CACHED_RECORD.saturating_mul(
                    u64::try_from(PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1)
                        .expect("chunk bound fits u64"),
                ),
            );
        let instruction = InstructionBox::from(transition);
        assert_eq!(meter_instruction(&instruction, &DEFAULT_ZK_GAS), expected);
        assert_eq!(
            confidential_gas_cost(&instruction, &DEFAULT_ZK_GAS),
            PARLIAMENT_PROOF_UNIT + PARLIAMENT_BALLOT_OR_VERIFY
        );
        assert!(
            expected <= 1_680_000,
            "a maximum valid timed-OVN chunk must fit the standard default-genesis block gas limit"
        );
    }
    #[test]
    fn timed_ovn_chunk_gas_is_monotonic_in_record_count() {
        let one = InstructionBox::from(parliament_corpus_instruction(1));
        let maximum = InstructionBox::from(parliament_corpus_instruction(
            PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1,
        ));
        assert!(
            meter_instruction(&maximum, &DEFAULT_ZK_GAS) > meter_instruction(&one, &DEFAULT_ZK_GAS)
        );
    }
    #[test]
    fn transfer_batch_gas_matches_entry_sum() {
        let from = sample_account();
        let to = sample_account();
        let def: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "xor".parse().unwrap(),
            );
        let entry_a = dm_isi::transfer::TransferAssetBatchEntry::new(
            from.clone(),
            to.clone(),
            def.clone(),
            1u64,
        );
        let entry_b = dm_isi::transfer::TransferAssetBatchEntry::new(
            from.clone(),
            to.clone(),
            def.clone(),
            2u64,
        );
        let batch = dm_isi::transfer::TransferAssetBatch::new(vec![entry_a, entry_b]);
        let batch_gas = meter_instruction(&InstructionBox::from(batch), &DEFAULT_ZK_GAS);
        let t1 = dm_isi::transfer::Transfer::asset_quantity(
            AssetId::of(def.clone(), from.clone()),
            1u64,
            to.clone(),
        );
        let t2 = dm_isi::transfer::Transfer::asset_quantity(AssetId::of(def, from), 2u64, to);
        let expected = meter_instruction(
            &InstructionBox::from(dm_isi::transfer::TransferBox::from(t1)),
            &DEFAULT_ZK_GAS,
        )
        .saturating_add(meter_instruction(
            &InstructionBox::from(dm_isi::transfer::TransferBox::from(t2)),
            &DEFAULT_ZK_GAS,
        ));
        assert_eq!(batch_gas, expected);
    }
    #[test]
    fn calibration_bench_gas_snapshot() {
        let (authority, _) = gen_account_in("wonderland");
        let role_id: RoleId = "bench_role".parse().unwrap();
        let trigger_id: TriggerId = "bench_trg".parse().unwrap();
        let bench_domain: DomainId = DomainId::try_new("bench", "universal").unwrap();
        let register_domain: InstructionBox =
            dm_isi::register::Register::domain(Domain::new(bench_domain.clone())).into();
        let register_account: InstructionBox =
            dm_isi::register::Register::account(Account::new(authority.clone())).into();
        let asset_definition_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "xor".parse().unwrap(),
            );
        let register_asset_definition: InstructionBox =
            dm_isi::register::Register::asset_definition({
                let __asset_definition_id = asset_definition_id.clone();
                AssetDefinition::numeric(
                    __asset_definition_id.clone(),
                    "xor".to_owned(),
                    iroha_data_model::asset::AssetBalancePolicy::Global,
                    None,
                )
            })
            .into();
        let set_account_kv: InstructionBox =
            dm_isi::SetKeyValue::account(authority.clone(), "k".parse().unwrap(), Json::new("v"))
                .into();
        let grant_account_role: InstructionBox =
            dm_isi::Grant::account_role(role_id.clone(), authority.clone()).into();
        let revoke_account_role: InstructionBox =
            dm_isi::Revoke::account_role(role_id.clone(), authority.clone()).into();
        let execute_trigger: InstructionBox =
            dm_isi::ExecuteTrigger::new(trigger_id.clone()).into();
        let asset_id = AssetId::of(asset_definition_id.clone(), authority.clone());
        let mint_asset: InstructionBox =
            dm_isi::mint_burn::Mint::asset_quantity(1_u32, asset_id.clone()).into();
        let transfer_asset: InstructionBox =
            dm_isi::transfer::Transfer::asset_quantity(asset_id, 1_u32, authority.clone()).into();
        let cases = [
            ("RegisterDomain", register_domain, 200),
            (
                "RegisterAccount",
                register_account,
                BASE_REGISTER + KAIGI_RECORD_READ_ESCROW,
            ),
            ("RegisterAssetDef", register_asset_definition, 200),
            ("SetAccountKV_small", set_account_kv, 67),
            ("GrantAccountRole", grant_account_role, 96),
            ("RevokeAccountRole", revoke_account_role, 96),
            ("ExecuteTrigger_empty_args", execute_trigger, 222),
            ("MintAsset", mint_asset, 150),
            ("TransferAsset", transfer_asset, 180),
        ];
        let mut total = 0_u64;
        for (label, instr, expected) in &cases {
            let expected = *expected;
            let gas = meter_instruction(instr, &DEFAULT_ZK_GAS);
            assert_eq!(
                gas, expected,
                "{label} gas mismatch (got {gas}, expected {expected})"
            );
            total += gas;
        }
        let expected_total: u64 = cases.iter().map(|(_, _, expected)| *expected).sum();
        assert_eq!(total, expected_total);
    }
    #[test]
    fn verify_proof_gas_matches_schedule() {
        use iroha_data_model::{isi::zk::VerifyProof, proof::VerifyingKeyId};
        let schedule = DEFAULT_ZK_GAS;
        let fixture = native_framing_fixture_envelope(
            crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            [0u8; 32],
        );
        let proof_box = fixture.proof_box("pipa-r/pasta");
        let attachment = ProofAttachment::new_ref(
            proof_box.backend.clone(),
            proof_box,
            VerifyingKeyId::new("pipa-r/pasta", "vk-gas"),
        );
        let proof_bytes = attachment.proof.bytes.len() as u64;
        let public_inputs =
            super::ipa_public_input_count(&attachment).expect("native public column");
        let instruction: InstructionBox = VerifyProof::new(attachment).into();
        let gas = meter_instruction(&instruction, &DEFAULT_ZK_GAS);
        assert_eq!(public_inputs, 9);
        let expected = schedule.proof_base
            + schedule.per_public_input.saturating_mul(public_inputs)
            + schedule.per_proof_byte.saturating_mul(proof_bytes);
        assert_eq!(gas, expected);
        assert_eq!(
            confidential_gas_cost(&instruction, &DEFAULT_ZK_GAS),
            expected
        );
    }
    #[test]
    fn kaigi_proof_gas_uses_every_governed_schedule_dimension() {
        use iroha_data_model::{
            isi::kaigi::{CreateKaigi, EndKaigi, JoinKaigi, LeaveKaigi, RecordKaigiUsage},
            kaigi::{KaigiId, KaigiPrivacyMode, NewKaigi},
        };

        let schedule = ActualConfidentialGas {
            proof_base: 1_337,
            per_public_input: 41,
            per_proof_byte: 17,
            per_nullifier: 43,
            per_commitment: 47,
        };

        let call_id = KaigiId::new(
            DomainId::try_new("kaigi-gas", "universal").expect("valid domain id"),
            "private-call".parse().expect("valid call name"),
        );
        let mut call = NewKaigi::with_defaults(call_id.clone(), sample_account());
        call.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
        let proof = vec![0xA5; 8];
        let proof_len = u64::try_from(proof.len()).expect("fixture proof length fits u64");
        let expected_create_proof_gas = schedule
            .proof_base
            .saturating_add(schedule.per_public_input.saturating_mul(6))
            .saturating_add(schedule.per_nullifier)
            .saturating_add(schedule.per_commitment)
            .saturating_add(schedule.per_proof_byte.saturating_mul(proof_len));
        let expected_end_proof_gas = schedule
            .proof_base
            .saturating_add(schedule.per_public_input.saturating_mul(6))
            .saturating_add(schedule.per_nullifier)
            .saturating_add(schedule.per_proof_byte.saturating_mul(proof_len));
        let expected_usage_proof_gas = schedule
            .proof_base
            .saturating_add(schedule.per_public_input)
            .saturating_add(schedule.per_commitment)
            .saturating_add(schedule.per_proof_byte.saturating_mul(proof_len));

        let create: InstructionBox = CreateKaigi {
            call: call.clone(),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: Some(proof.clone()),
        }
        .into();
        assert_eq!(
            meter_instruction(&create, &schedule),
            BASE_KAIGI_CREATE
                .saturating_add(expected_create_proof_gas)
                .saturating_add(kaigi_create_record_gas(
                    create
                        .as_any()
                        .downcast_ref::<CreateKaigi>()
                        .expect("CreateKaigi instruction"),
                ))
        );
        assert_eq!(
            confidential_gas_cost(&create, &schedule),
            expected_create_proof_gas
        );

        let longer_create: InstructionBox = CreateKaigi {
            call: call.clone(),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: Some(vec![0xA5; proof.len() + 1]),
        }
        .into();
        assert_eq!(
            meter_instruction(&longer_create, &schedule) - meter_instruction(&create, &schedule),
            schedule.per_proof_byte
        );

        let participant = sample_account();
        let join: InstructionBox = JoinKaigi {
            call_id: call_id.clone(),
            participant: participant.clone(),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: Some(proof.clone()),
        }
        .into();
        assert_eq!(
            meter_instruction(&join, &schedule),
            BASE_KAIGI_JOIN_ZK
                .saturating_add(KAIGI_RECORD_MUTATION_ESCROW)
                .saturating_add(schedule.per_proof_byte.saturating_mul(proof_len))
        );

        let leave: InstructionBox = LeaveKaigi {
            call_id: call_id.clone(),
            participant,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: Some(proof.clone()),
        }
        .into();
        assert_eq!(
            meter_instruction(&leave, &schedule),
            BASE_KAIGI_LEAVE_ZK
                .saturating_add(KAIGI_RECORD_MUTATION_ESCROW)
                .saturating_add(schedule.per_proof_byte.saturating_mul(proof_len))
        );

        let end: InstructionBox = EndKaigi {
            call_id: call_id.clone(),
            ended_at_ms: None,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: Some(proof.clone()),
        }
        .into();
        assert_eq!(
            meter_instruction(&end, &schedule),
            BASE_KAIGI_END
                .saturating_add(KAIGI_RECORD_MUTATION_ESCROW)
                .saturating_add(expected_end_proof_gas)
        );
        assert_eq!(
            confidential_gas_cost(&end, &schedule),
            expected_end_proof_gas
        );

        let usage: InstructionBox = RecordKaigiUsage {
            call_id,
            duration_ms: 1,
            billed_gas: 1,
            usage_commitment: None,
            proof: Some(proof),
        }
        .into();
        assert_eq!(
            meter_instruction(&usage, &schedule),
            BASE_KAIGI_USAGE_ZK
                .saturating_add(KAIGI_RECORD_MUTATION_ESCROW)
                .saturating_add(expected_usage_proof_gas)
        );
        assert_eq!(
            confidential_gas_cost(&usage, &schedule),
            expected_usage_proof_gas
        );

        let proofless_create: InstructionBox = CreateKaigi {
            call,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .into();
        let expected_create_record_gas = kaigi_create_record_gas(
            proofless_create
                .as_any()
                .downcast_ref::<CreateKaigi>()
                .expect("CreateKaigi instruction"),
        );
        assert_eq!(
            meter_instruction(&proofless_create, &schedule),
            BASE_KAIGI_CREATE.saturating_add(expected_create_record_gas)
        );
        assert_eq!(confidential_gas_cost(&proofless_create, &schedule), 0);
    }
    #[test]
    fn kaigi_relay_gas_scales_with_bounded_descriptor_payloads() {
        use iroha_data_model::{
            isi::kaigi::{
                CreateKaigi, RegisterKaigiRelay, ReportKaigiRelayHealth, SetKaigiRelayManifest,
                UnregisterKaigiRelay,
            },
            kaigi::{
                KaigiId, KaigiRelayHealthStatus, KaigiRelayHop, KaigiRelayManifest,
                KaigiRelayRegistration, NewKaigi,
            },
        };

        let relay = sample_account();
        let call_id = KaigiId::new(
            DomainId::try_new("kaigi-relay-gas", "universal").expect("valid domain id"),
            "relay-call".parse().expect("valid call name"),
        );
        let manifest = KaigiRelayManifest {
            hops: vec![KaigiRelayHop {
                relay_id: relay.clone(),
                hpke_public_key: vec![1, 2, 3],
                weight: 1,
            }],
            expiry_ms: 1,
        };
        let mut call = NewKaigi::with_defaults(call_id.clone(), sample_account());
        call.relay_manifest = Some(manifest.clone());
        let create: InstructionBox = CreateKaigi {
            call,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .into();
        let create_ref = create
            .as_any()
            .downcast_ref::<CreateKaigi>()
            .expect("CreateKaigi instruction");
        assert_eq!(
            meter_instruction(&create, &DEFAULT_ZK_GAS),
            BASE_KAIGI_CREATE
                + kaigi_create_record_gas(create_ref)
                + KAIGI_RELAY_STATE_READ_ESCROW
                + PER_KAIGI_RELAY_HOP
                + 3
        );
        let set: InstructionBox = SetKaigiRelayManifest {
            call_id: call_id.clone(),
            relay_manifest: Some(manifest),
        }
        .into();
        assert_eq!(
            meter_instruction(&set, &DEFAULT_ZK_GAS),
            BASE_KAIGI_RELAY_MANIFEST
                + KAIGI_RECORD_MUTATION_ESCROW
                + KAIGI_RELAY_STATE_READ_ESCROW
                + PER_KAIGI_RELAY_HOP
                + 3
        );

        let register: InstructionBox = RegisterKaigiRelay {
            relay: KaigiRelayRegistration {
                relay_id: relay.clone(),
                hpke_public_key: vec![1, 2, 3],
                bandwidth_class: 1,
            },
        }
        .into();
        assert_eq!(
            meter_instruction(&register, &DEFAULT_ZK_GAS),
            BASE_KAIGI_RELAY_REGISTER + KAIGI_RELAY_STATE_READ_ESCROW + 3
        );

        let unregister: InstructionBox = UnregisterKaigiRelay {
            relay_id: relay.clone(),
        }
        .into();
        assert_eq!(
            meter_instruction(&unregister, &DEFAULT_ZK_GAS),
            BASE_KAIGI_RELAY_UNREGISTER + KAIGI_RELAY_STATE_READ_ESCROW
        );

        let health: InstructionBox = ReportKaigiRelayHealth {
            call_id,
            relay_id: relay,
            status: KaigiRelayHealthStatus::Healthy,
            reported_at_ms: 0,
            notes: Some("abc".to_owned()),
        }
        .into();
        assert_eq!(
            meter_instruction(&health, &DEFAULT_ZK_GAS),
            BASE_KAIGI_RELAY_HEALTH + KAIGI_RELAY_STATE_READ_ESCROW + 3
        );
    }
    #[test]
    fn kaigi_record_gas_reserves_bounded_work_and_create_input_bytes() {
        use iroha_data_model::{
            isi::kaigi::{
                CreateKaigi, EndKaigi, JoinKaigi, LeaveKaigi, RecordKaigiUsage,
                ReportKaigiRelayHealth, SetKaigiRelayManifest,
            },
            kaigi::{KaigiId, KaigiRelayHealthStatus, NewKaigi},
        };

        assert_eq!(
            KAIGI_RECORD_MUTATION_ESCROW,
            KAIGI_RECORD_READ_ESCROW.saturating_mul(3)
        );
        assert_eq!(
            KAIGI_RELAY_STATE_READ_ESCROW,
            KAIGI_METADATA_READ_ESCROW.saturating_mul(2)
        );
        let host = sample_account();
        let participant = sample_account();
        let call_id = KaigiId::new(
            DomainId::try_new("kaigi-record-gas", "universal").expect("valid domain id"),
            "bounded-call".parse().expect("valid call name"),
        );
        let short_call = NewKaigi::with_defaults(call_id.clone(), host.clone());
        let short_create: InstructionBox = CreateKaigi {
            call: short_call.clone(),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .into();
        let mut long_call = short_call;
        long_call.title = Some("meter every Kaigi call input byte".repeat(32));
        long_call.description = Some("including descriptions and metadata".repeat(32));
        long_call.metadata.insert(
            "metered".parse().expect("valid metadata key"),
            Json::new("metadata bytes".repeat(32)),
        );
        let long_create: InstructionBox = CreateKaigi {
            call: long_call,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .into();
        assert!(
            meter_instruction(&long_create, &DEFAULT_ZK_GAS)
                > meter_instruction(&short_create, &DEFAULT_ZK_GAS),
            "larger title/description input must increase CreateKaigi gas"
        );

        let join: InstructionBox = JoinKaigi {
            call_id: call_id.clone(),
            participant: participant.clone(),
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .into();
        assert_eq!(
            meter_instruction(&join, &DEFAULT_ZK_GAS),
            BASE_KAIGI_JOIN + KAIGI_RECORD_MUTATION_ESCROW
        );
        let leave: InstructionBox = LeaveKaigi {
            call_id: call_id.clone(),
            participant,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .into();
        assert_eq!(
            meter_instruction(&leave, &DEFAULT_ZK_GAS),
            BASE_KAIGI_LEAVE + KAIGI_RECORD_MUTATION_ESCROW
        );
        let end: InstructionBox = EndKaigi {
            call_id: call_id.clone(),
            ended_at_ms: None,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .into();
        assert_eq!(
            meter_instruction(&end, &DEFAULT_ZK_GAS),
            BASE_KAIGI_END + KAIGI_RECORD_MUTATION_ESCROW
        );
        let usage: InstructionBox = RecordKaigiUsage {
            call_id: call_id.clone(),
            duration_ms: 1,
            billed_gas: 1,
            usage_commitment: None,
            proof: None,
        }
        .into();
        assert_eq!(
            meter_instruction(&usage, &DEFAULT_ZK_GAS),
            BASE_KAIGI_USAGE + KAIGI_RECORD_MUTATION_ESCROW
        );
        let manifest: InstructionBox = SetKaigiRelayManifest {
            call_id: call_id.clone(),
            relay_manifest: None,
        }
        .into();
        assert_eq!(
            meter_instruction(&manifest, &DEFAULT_ZK_GAS),
            BASE_KAIGI_RELAY_MANIFEST + KAIGI_RECORD_MUTATION_ESCROW
        );
        let health: InstructionBox = ReportKaigiRelayHealth {
            call_id,
            relay_id: host,
            status: KaigiRelayHealthStatus::Healthy,
            reported_at_ms: 0,
            notes: None,
        }
        .into();
        assert_eq!(
            meter_instruction(&health, &DEFAULT_ZK_GAS),
            BASE_KAIGI_RELAY_HEALTH + KAIGI_RELAY_STATE_READ_ESCROW
        );
    }
    #[test]
    fn proofless_kaigi_max_paths_fit_shipped_block_gas() {
        use iroha_data_model::{
            isi::kaigi::{
                CreateKaigi, EndKaigi, JoinKaigi, LeaveKaigi, RecordKaigiUsage, RegisterKaigiRelay,
                ReportKaigiRelayHealth, SetKaigiRelayManifest, UnregisterKaigiRelay,
            },
            kaigi::{
                KAIGI_RECORD_MAX_JSON_BYTES_V1, KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1,
                KAIGI_RELAY_MANIFEST_MAX_HOPS_V1, KaigiId, KaigiRecord, KaigiRelayHealthStatus,
                KaigiRelayHop, KaigiRelayManifest, KaigiRelayRegistration, NewKaigi,
            },
        };

        const SHIPPED_BLOCK_GAS_LIMIT: u64 = 1_680_000;

        let host = sample_account();
        let participant = sample_account();
        let call_id = KaigiId::new(
            DomainId::try_new("kaigi-shipped-gas", "universal").expect("valid domain id"),
            "max-proofless".parse().expect("valid call name"),
        );
        let manifest = KaigiRelayManifest {
            hops: (0..KAIGI_RELAY_MANIFEST_MAX_HOPS_V1)
                .map(|index| KaigiRelayHop {
                    relay_id: sample_account(),
                    hpke_public_key: vec![
                        u8::try_from(index).expect("hop index fits u8");
                        KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1
                    ],
                    weight: 1,
                })
                .collect(),
            expiry_ms: u64::MAX,
        };
        let mut call = NewKaigi::with_defaults(call_id.clone(), host.clone());
        call.relay_manifest = Some(manifest.clone());
        let fixed_record_len = Json::try_new(KaigiRecord::from_new(&call, 0))
            .expect("bounded fixed record")
            .as_ref()
            .len();
        let description_len = KAIGI_RECORD_MAX_JSON_BYTES_V1
            .checked_sub(fixed_record_len.saturating_add(128))
            .expect("maximum relay manifest leaves room for a description");
        call.description = Some("x".repeat(description_len));
        let near_limit_record = Json::try_new(KaigiRecord::from_new(&call, 0))
            .expect("near-limit protocol-valid record");
        assert!(near_limit_record.as_ref().len() <= KAIGI_RECORD_MAX_JSON_BYTES_V1);
        assert!(
            near_limit_record.as_ref().len() > KAIGI_RECORD_MAX_JSON_BYTES_V1 - 512,
            "fixture must exercise the record byte ceiling"
        );

        let relay_id = manifest.hops[0].relay_id.clone();
        let cases: [(&str, InstructionBox); 9] = [
            (
                "create with eight-hop near-limit record",
                CreateKaigi {
                    call,
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .into(),
            ),
            (
                "join",
                JoinKaigi {
                    call_id: call_id.clone(),
                    participant: participant.clone(),
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .into(),
            ),
            (
                "leave",
                LeaveKaigi {
                    call_id: call_id.clone(),
                    participant,
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .into(),
            ),
            (
                "end",
                EndKaigi {
                    call_id: call_id.clone(),
                    ended_at_ms: None,
                    commitment: None,
                    nullifier: None,
                    roster_root: None,
                    proof: None,
                }
                .into(),
            ),
            (
                "usage",
                RecordKaigiUsage {
                    call_id: call_id.clone(),
                    duration_ms: 1,
                    billed_gas: 1,
                    usage_commitment: None,
                    proof: None,
                }
                .into(),
            ),
            (
                "set eight-hop manifest",
                SetKaigiRelayManifest {
                    call_id: call_id.clone(),
                    relay_manifest: Some(manifest),
                }
                .into(),
            ),
            (
                "register maximum-size relay descriptor",
                RegisterKaigiRelay {
                    relay: KaigiRelayRegistration {
                        relay_id: relay_id.clone(),
                        hpke_public_key: vec![0xA5; KAIGI_RELAY_HPKE_PUBLIC_KEY_MAX_BYTES_V1],
                        bandwidth_class: 1,
                    },
                }
                .into(),
            ),
            (
                "unregister relay",
                UnregisterKaigiRelay {
                    relay_id: relay_id.clone(),
                }
                .into(),
            ),
            (
                "report health with maximum character count",
                ReportKaigiRelayHealth {
                    call_id,
                    relay_id,
                    status: KaigiRelayHealthStatus::Healthy,
                    reported_at_ms: 0,
                    notes: Some("🦀".repeat(512)),
                }
                .into(),
            ),
        ];
        for (label, instruction) in cases {
            let gas = meter_instruction(&instruction, &DEFAULT_ZK_GAS);
            assert!(
                gas < SHIPPED_BLOCK_GAS_LIMIT,
                "proofless {label} costs {gas}, exceeding shipped block gas {SHIPPED_BLOCK_GAS_LIMIT}"
            );
        }
        // Proof-bearing variants add the configured proof schedule and may intentionally require a
        // higher operator-selected block budget; this test only covers proofless native bounds.
    }
    #[test]
    fn account_lifecycle_changes_reserve_kaigi_dependency_reads() {
        use core::num::NonZeroU16;
        use iroha_data_model::{
            account::rekey::AccountAlias,
            isi::account_recovery::{FinalizeAccountRecovery, ReplaceAccountController},
            isi::alias_setup::CompareAndSetPrimaryAccountAlias,
        };
        use iroha_model_base::topology::DataSpaceId;

        let account = sample_account();
        let replacement = sample_account();
        let replacement_signatory = replacement
            .controller()
            .single_signatory()
            .expect("sample account has a single signatory")
            .clone();
        let expected = BASE_CUSTOM.saturating_add(KAIGI_RECORD_READ_ESCROW);
        let controller_changes = [
            InstructionBox::from(dm_isi::AddSignatory::new(
                account.clone(),
                replacement_signatory.clone(),
            )),
            InstructionBox::from(dm_isi::RemoveSignatory::new(
                account.clone(),
                replacement_signatory,
            )),
            InstructionBox::from(dm_isi::SetAccountQuorum::new(
                account.clone(),
                NonZeroU16::new(1).expect("nonzero quorum"),
            )),
            InstructionBox::from(ReplaceAccountController {
                account: account.clone(),
                new_controller: replacement.controller().clone(),
            }),
            InstructionBox::from(FinalizeAccountRecovery {
                request_generation: std::num::NonZeroU64::MIN,
                alias: AccountAlias::domainless(
                    "gas-recovery".parse().expect("valid account alias"),
                    DataSpaceId::UNIVERSAL,
                ),
            }),
            InstructionBox::from(CompareAndSetPrimaryAccountAlias::new(
                account.clone(),
                None,
                None,
            )),
        ];
        for instruction in controller_changes {
            assert_eq!(meter_instruction(&instruction, &DEFAULT_ZK_GAS), expected);
        }

        let unregister_account: InstructionBox = Unregister::account(account).into();
        assert_eq!(
            meter_instruction(&unregister_account, &DEFAULT_ZK_GAS),
            BASE_UNREGISTER + KAIGI_RECORD_READ_ESCROW
        );
        let unregister_domain: InstructionBox = Unregister::domain(
            DomainId::try_new("gas-unregister", "universal").expect("valid domain id"),
        )
        .into();
        assert_eq!(
            meter_instruction(&unregister_domain, &DEFAULT_ZK_GAS),
            BASE_UNREGISTER + KAIGI_RECORD_READ_ESCROW
        );
        let unregister_role: InstructionBox =
            Unregister::role(RoleId::new("gas-role".parse().expect("valid role name"))).into();
        assert_eq!(
            meter_instruction(&unregister_role, &DEFAULT_ZK_GAS),
            BASE_UNREGISTER
        );
    }
    #[test]
    fn proof_public_input_gas_rejects_alternate_norito_layout() {
        use iroha_data_model::proof::VerifyingKeyId;
        let fixture = native_framing_fixture_envelope(
            crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            [0u8; 32],
        );
        let envelope = norito::decode_canonical::<OpenVerifyEnvelope>(&fixture.proof_bytes)
            .expect("fixture proof envelope is canonical");
        let canonical_attachment = ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            fixture.proof_box("pipa-r/pasta"),
            VerifyingKeyId::new("pipa-r/pasta", "vk-canonical-gas"),
        );
        assert_eq!(
            super::ipa_public_input_count(&canonical_attachment),
            Some(9)
        );
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate_bytes = {
            let _guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&envelope).expect("encode alternate-layout proof envelope")
        };
        assert_ne!(alternate_bytes, fixture.proof_bytes);
        assert!(
            norito::decode_from_bytes::<OpenVerifyEnvelope>(&alternate_bytes).is_ok(),
            "ordinary Norito must accept its advertised alternate layout"
        );
        let alternate_attachment = ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            iroha_data_model::proof::ProofBox::new("pipa-r/pasta".into(), alternate_bytes),
            VerifyingKeyId::new("pipa-r/pasta", "vk-alternate-gas"),
        );
        assert_eq!(
            super::ipa_public_input_count(&alternate_attachment),
            None,
            "non-canonical envelopes must not supply consensus-visible gas metadata"
        );
    }
    #[test]
    fn state_configured_gas_schedule_updates_metering() {
        use iroha_data_model::{isi::zk::VerifyProof, proof::VerifyingKeyId};
        let world = crate::state::World::new();
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let mut state = State::new(world, kura, query);
        let mut zk_cfg = state.installed_zk().clone();
        zk_cfg.gas = cfg::ConfidentialGas {
            proof_base: 777_000,
            per_public_input: 3_131,
            per_proof_byte: 29,
            per_nullifier: 47,
            per_commitment: 59,
        };
        state
            .set_zk(zk_cfg.clone())
            .expect("empty state accepts gas test configuration");
        let fixture = native_framing_fixture_envelope(
            crate::zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID,
            [0u8; 32],
        );
        let proof_box = fixture.proof_box("pipa-r/pasta");
        let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
            proof_box.backend.clone(),
            proof_box,
            VerifyingKeyId::new("pipa-r/pasta", "vk-config-gas"),
        );
        let proof_bytes = attachment.proof.bytes.len() as u64;
        let public_inputs =
            ipa_public_input_count(&attachment).expect("fixture exposes native public inputs");
        for backend in [
            "halo2/ipa/orchard",
            "halo2/ipa:production-ready",
            "halo2/ipa: KZG",
            "halo2/ipa:Mock-Proof",
            "halo2/unknown-native-v1",
        ] {
            let rejected_proof = iroha_data_model::proof::ProofBox::new(
                backend.to_owned(),
                attachment.proof.bytes.clone(),
            );
            let rejected_attachment = iroha_data_model::proof::ProofAttachment::new_ref(
                backend.to_owned(),
                rejected_proof,
                VerifyingKeyId::new(backend, "vk-config-gas-rejected"),
            );
            assert_eq!(
                ipa_public_input_count(&rejected_attachment),
                None,
                "non-registry backend {backend} must not be decoded for gas metadata"
            );
        }
        let verify_instr: InstructionBox = VerifyProof::new(attachment.clone()).into();
        // Metering reads the schedule of the State's frozen settings, passed
        // by the caller; no process-wide value exists.
        let view = state.view();
        let verify_gas = meter_instruction(&verify_instr, &view.zk.gas);
        let expected_verify = zk_cfg.gas.proof_base
            + zk_cfg.gas.per_public_input.saturating_mul(public_inputs)
            + zk_cfg.gas.per_proof_byte.saturating_mul(proof_bytes);
        assert_eq!(verify_gas, expected_verify);
        assert_ne!(
            verify_gas,
            meter_instruction(&verify_instr, &DEFAULT_ZK_GAS)
        );
    }
    #[test]
    fn confidential_gas_cost_zero_for_non_confidential_instr() {
        let account = sample_account();
        let asset: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "xor".parse().unwrap(),
            );
        let mint =
            dm_isi::mint_burn::Mint::asset_quantity(1u64, AssetId::of(asset, account.clone()));
        let instr = InstructionBox::from(dm_isi::mint_burn::MintBox::from(mint));
        assert_eq!(confidential_gas_cost(&instr, &DEFAULT_ZK_GAS), 0);
    }
    #[test]
    fn sccp_gas_grows_with_source_proof_work_and_fits_the_block() {
        use crate::smartcontracts::isi::sccp::test_support::SampleInstructions as I;
        use iroha_data_model::sccp::{
            inbound::{SCCP_SOURCE_PROOF_MAX_BYTES_V1, SccpSourceProofBytesV1},
            light_client::{
                SCCP_LC_ADVANCE_MAX_BYTES_V1, SCCP_LC_EVIDENCE_MAX_BYTES_V1, SccpLcAdvanceBytesV1,
                SccpLcEvidenceBytesV1,
            },
        };
        const SHIPPED_BLOCK_GAS_LIMIT: u64 = 1_680_000;
        let gas = |instruction: InstructionBox| meter_instruction(&instruction, &DEFAULT_ZK_GAS);
        for instruction in I::all() {
            assert!(gas(instruction.clone()) >= BASE_SCCP, "{instruction:?}");
            assert!(gas(instruction.clone()) < SHIPPED_BLOCK_GAS_LIMIT);
            assert_eq!(confidential_gas_cost(&instruction, &DEFAULT_ZK_GAS), 0);
        }
        assert_eq!(
            I::all().len(),
            7,
            "the seven SCCP v1 instructions are priced"
        );
        assert_eq!(gas(I::initialize().into()), BASE_SCCP);
        let record = |bytes: usize| {
            let mut record = I::record();
            record.recipient = vec![1; bytes];
            gas(record.into())
        };
        assert!(record(36) > record(20));
        let inbound = |bytes: usize| {
            let mut inbound = I::inbound();
            inbound.proof = SccpSourceProofBytesV1::new(vec![1; bytes]).expect("bounded proof");
            gas(inbound.into())
        };
        assert!(inbound(1_024) >= SCCP_LIGHT_CLIENT_VERIFY);
        assert!(inbound(1_024 * 1_024) > inbound(1_024));
        assert!(inbound(SCCP_SOURCE_PROOF_MAX_BYTES_V1) < SHIPPED_BLOCK_GAS_LIMIT);
        let inbound_payload = |bytes: usize| {
            let mut inbound = I::inbound();
            inbound.payload = vec![2; bytes];
            gas(inbound.into())
        };
        assert!(inbound_payload(512) > inbound_payload(64));
        let void = |bytes: usize| {
            let mut void = I::void();
            void.proof = SccpSourceProofBytesV1::new(vec![1; bytes]).expect("bounded proof");
            gas(void.into())
        };
        assert!(void(4_096) > void(64));
        let advance = |bytes: usize| {
            let mut advance = I::advance();
            advance.advance = SccpLcAdvanceBytesV1::new(vec![1; bytes]).expect("bounded advance");
            gas(advance.into())
        };
        assert!(advance(4_096) > advance(64));
        assert!(advance(SCCP_LC_ADVANCE_MAX_BYTES_V1) < SHIPPED_BLOCK_GAS_LIMIT);
        let equivocation = |bytes: usize| {
            let evidence = || SccpLcEvidenceBytesV1::new(vec![1; bytes]).expect("bounded evidence");
            let mut report = I::equivocation();
            report.a = evidence();
            report.b = evidence();
            gas(report.into())
        };
        assert!(equivocation(4_096) > equivocation(64));
        assert!(equivocation(64) >= 2 * SCCP_LIGHT_CLIENT_VERIFY);
        assert!(equivocation(SCCP_LC_EVIDENCE_MAX_BYTES_V1) < SHIPPED_BLOCK_GAS_LIMIT);
    }
}

#[cfg(test)]
mod native_pipa_r_gas_tests {
    use super::*;

    #[test]
    fn native_gas_counts_exact_public_column_and_rejects_metadata_substitution() {
        use iroha_data_model::{
            proof::{ProofBox, VerifyingKeyId},
            zk::{BackendTag, NativePipaRProofV1},
        };
        let backend = "pipa-r/pasta";
        for (circuit, rows) in [
            (
                "pipa-r/pasta/kaigi-usage-v1",
                crate::zk::native_pipa_r::relation("pipa-r/pasta", "pipa-r/pasta/kaigi-usage-v1")
                    .unwrap()
                    .instance_rows(),
            ),
            ("pipa-r/pasta/confidential-transfer-v1", 9),
            ("pipa-r/pasta/confidential-unshield-full-v1", 8),
            ("pipa-r/pasta/confidential-unshield-change-v1", 9),
        ] {
            let kind = crate::zk::native_pipa_r::relation(backend, circuit).unwrap();
            assert_eq!(kind.instance_rows(), rows);
            // Gas inspection validates framing and arity. These zero transcript bytes
            // are intentionally not a cryptographic proof and are never verified.
            let payload = NativePipaRProofV1 {
                public_inputs: vec![[0; 32]; kind.instance_rows()],
                proof: vec![0; kind.proof_length().unwrap()],
            };
            let mut envelope = OpenVerifyEnvelope {
                backend: BackendTag::NativePipaRPasta,
                circuit_id: circuit.into(),
                vk_hash: [1; 32],
                public_inputs: crate::zk::native_pipa_r::public_schema(kind).to_vec(),
                proof_bytes: norito::encode_canonical(&payload).unwrap(),
                aux: Vec::new(),
            };
            let inspect = |envelope: &OpenVerifyEnvelope, backend: &str| {
                let proof =
                    ProofBox::new(backend.into(), norito::encode_canonical(envelope).unwrap());
                let attachment = ProofAttachment::new_ref(
                    backend.into(),
                    proof,
                    VerifyingKeyId::new(backend, "gas-count"),
                );
                ipa_public_input_count(&attachment)
            };
            assert_eq!(
                inspect(&envelope, backend),
                Some(u64::try_from(kind.instance_rows()).unwrap())
            );
            assert_eq!(inspect(&envelope, "halo2/pasta/kaigi-usage-v1"), None);
            envelope.public_inputs.push(0);
            assert_eq!(inspect(&envelope, backend), None);
            envelope.public_inputs.pop();
            envelope.backend = BackendTag::Stark;
            assert_eq!(inspect(&envelope, backend), None);
        }
    }
}
