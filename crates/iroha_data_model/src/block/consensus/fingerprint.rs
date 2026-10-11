//! Canonical Sumeragi consensus-parameters fingerprint projection.
use super::{
    ConsensusGenesisModeParams, ConsensusGenesisParams, ConsensusMode,
    SumeragiGenesisContextParameters,
};
use iroha_crypto::blake2::{Blake2b512, Digest as _};
use iroha_primitives::numeric::Quantity;
use norito::codec::Encode;
const DOMAIN: &[u8] = b"iroha:sumeragi:v1:consensus-parameters-fingerprint:v1\0";
/// Version of the canonical consensus-parameters projection.
pub const FORMAT_VERSION: u16 = 1;
#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::block::consensus::fingerprint::ConsensusParametersFingerprintInput"
)]
struct ConsensusParametersFingerprintInput {
    format_version: u16,
    protocol_version: u32,
    mode: ConsensusMode,
    block_cadence_ms: core::num::NonZeroU64,
    block_max_transactions: core::num::NonZeroU64,
    context: SumeragiGenesisContextParameters,
    npos: Option<NposGenesisFingerprintInput>,
}
#[derive(Encode, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::block::consensus::fingerprint::NposGenesisFingerprintInput"
)]
struct NposGenesisFingerprintInput {
    epoch_length_blocks: core::num::NonZeroU64,
    epoch_seed: [u8; 32],
    max_validators: u32,
    min_self_bond: Quantity,
    min_nomination_bond: Quantity,
    finality_margin_blocks: u64,
    evidence_horizon_blocks: u64,
    activation_lag_blocks: u64,
    slashing_delay_blocks: u64,
}
/// Compute the deterministic consensus-parameters fingerprint.
///
/// Only first-release frozen inputs are representable in the encoded
/// projection: mode, cadence, block bound, signed DA/Nexus context, and `NPoS`
/// election parameters. Exact network identity is not part of this
/// genesis-embedded value: runtime handshakes
/// authenticate a separate required `NetworkId`, avoiding a self-reference
/// through the genesis block hash.
///
/// # Errors
///
/// Returns an error when the signed genesis parameters violate the first-release
/// consensus invariants.
#[must_use = "a rejected genesis carrier must not be fingerprinted"]
pub fn compute(params: &ConsensusGenesisParams) -> Result<[u8; 32], String> {
    params.validate()?;
    let (mode, npos) = match &params.mode {
        ConsensusGenesisModeParams::Permissioned => (ConsensusMode::Permissioned, None),
        ConsensusGenesisModeParams::Npos(npos) => (
            ConsensusMode::Npos,
            Some(NposGenesisFingerprintInput {
                epoch_length_blocks: npos.epoch_length_blocks,
                epoch_seed: npos.epoch_seed,
                max_validators: npos.max_validators,
                min_self_bond: npos.min_self_bond.clone(),
                min_nomination_bond: npos.min_nomination_bond.clone(),
                finality_margin_blocks: npos.finality_margin_blocks,
                evidence_horizon_blocks: npos.evidence_horizon_blocks,
                activation_lag_blocks: npos.activation_lag_blocks,
                slashing_delay_blocks: npos.slashing_delay_blocks,
            }),
        ),
    };
    let projection = ConsensusParametersFingerprintInput {
        format_version: FORMAT_VERSION,
        protocol_version: params.protocol_version,
        mode,
        block_cadence_ms: params.block_cadence_ms,
        block_max_transactions: params.block_max_transactions,
        context: params.sumeragi_context,
        npos,
    };
    let mut hasher = Blake2b512::new();
    iroha_crypto::blake2::digest::Update::update(&mut hasher, DOMAIN);
    iroha_crypto::blake2::digest::Update::update(&mut hasher, &projection.encode());
    let digest = iroha_crypto::blake2::Digest::finalize(hasher);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&digest[..32]);
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn permissioned_params() -> ConsensusGenesisParams {
        ConsensusGenesisParams {
            block_cadence_ms: core::num::NonZeroU64::new(1_000).unwrap(),
            block_max_transactions: core::num::NonZeroU64::new(512).unwrap(),
            mode: ConsensusGenesisModeParams::Permissioned,
            protocol_version: u32::from(crate::sumeragi::PROTOCOL_VERSION),
            sumeragi_context: super::super::test_genesis_context_parameters(),
        }
    }
    fn npos_params() -> ConsensusGenesisParams {
        let mut params = permissioned_params();
        params.mode = ConsensusGenesisModeParams::Npos(super::super::NposGenesisParams {
            epoch_length_blocks: core::num::NonZeroU64::new(3_600).unwrap(),
            epoch_seed: [7; 32],
            max_validators: 31,
            min_self_bond: 1_000_u64.into(),
            min_nomination_bond: 1_u64.into(),
            finality_margin_blocks: 8,
            evidence_horizon_blocks: 7_200,
            activation_lag_blocks: 1,
            slashing_delay_blocks: 3_600,
        });
        params
    }
    #[test]
    fn signed_cadence_changes_live_fingerprint() {
        let baseline = permissioned_params();
        let mut changed = baseline.clone();
        changed.block_cadence_ms = core::num::NonZeroU64::new(1_001).unwrap();
        assert_ne!(compute(&baseline).unwrap(), compute(&changed).unwrap(),);
    }
    #[test]
    fn signed_context_mismatch_changes_live_fingerprint() {
        let baseline = permissioned_params();
        let mut changed = baseline.clone();
        changed.sumeragi_context.nexus_amx_context_hash[0] ^= 1;
        assert_ne!(compute(&baseline).unwrap(), compute(&changed).unwrap(),);
    }
    #[test]
    fn signed_execution_policy_mismatch_changes_live_fingerprint() {
        let baseline = permissioned_params();
        let mut changed = baseline.clone();
        changed.sumeragi_context.execution_policy_hash[0] ^= 1;
        assert_ne!(compute(&baseline).unwrap(), compute(&changed).unwrap(),);
    }
    #[test]
    fn npos_election_input_changes_live_fingerprint() {
        let baseline = npos_params();
        let mut changed = baseline.clone();
        let ConsensusGenesisModeParams::Npos(npos) = &mut changed.mode else {
            unreachable!()
        };
        npos.epoch_seed[0] ^= 1;
        assert_ne!(compute(&baseline).unwrap(), compute(&changed).unwrap(),);
    }
    #[test]
    fn all_zero_npos_seed_is_rejected_before_hashing() {
        let mut params = npos_params();
        let ConsensusGenesisModeParams::Npos(npos) = &mut params.mode else {
            unreachable!()
        };
        npos.epoch_seed = [0; 32];
        assert!(compute(&params).is_err());
    }
    #[test]
    fn unsupported_protocol_is_rejected_before_hashing() {
        let mut params = permissioned_params();
        params.protocol_version += 1;
        let error = compute(&params).expect_err("unsupported wire revision must fail closed");
        assert!(error.contains("unsupported consensus protocol version"));
    }
    #[test]
    fn invalid_data_availability_context_is_rejected_before_hashing() {
        let mut params = permissioned_params();
        params.sumeragi_context.da_layout.chunk_size_bytes = 0;
        let error = compute(&params).expect_err("zero DA chunk size must fail closed");
        assert!(error.contains("invalid Sumeragi genesis context"));
    }
    #[test]
    fn zero_execution_policy_context_is_rejected_before_hashing() {
        let mut params = permissioned_params();
        params.sumeragi_context.execution_policy_hash = [0; 32];
        let error = compute(&params).expect_err("zero execution-policy hash must fail closed");
        assert!(error.contains("invalid Sumeragi genesis context"));
    }
    #[test]
    fn npos_invalid_committee_geometry_is_rejected_before_hashing() {
        let mut params = npos_params();
        let ConsensusGenesisModeParams::Npos(npos) = &mut params.mode else {
            unreachable!()
        };
        npos.max_validators = 5;
        let error =
            compute(&params).expect_err("invalid signed committee geometry must fail closed");
        assert!(error.contains("3f + 1"));
    }
    #[test]
    fn genesis_embedded_fingerprint_is_deterministic_without_genesis_hash_input() {
        let params = permissioned_params();
        let first = compute(&params).expect("valid parameters fingerprint");
        let second = compute(&params).expect("same valid parameters fingerprint");
        assert_eq!(first, second);
    }
}

#[cfg(test)]
mod captured_fingerprint_schema_tests;
