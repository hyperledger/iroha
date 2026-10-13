//! SCCP genesis profile and durable, non-reusable reset identities.

use color_eyre::eyre::{Result, WrapErr as _, ensure, eyre};
use iroha_data_model::{
    block::consensus::SumeragiRootScope,
    isi::sccp::InitializeSccpV1,
    parameter::{
        Parameter, SumeragiParameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    },
    sccp::params::{SCCP_MIN_EPOCH_MS_V1, SccpParametersV1},
};
use iroha_genesis::RawGenesisTransaction;
use rand::{TryRngCore as _, rngs::OsRng};
use std::{num::NonZeroU64, path::Path};

/// Genesis-pinned liability coverage: fourteen-day validity plus seven-day evidence grace.
pub const UNBONDING_DELAY_MS: u64 = 1_814_400_000;
/// The SCCP profile permits slashing the entire proven liable stake.
pub const MAX_SLASH_BPS: u16 = 10_000;

const NONCE_MARKER: &[u8] = b"sccp-reset-v1\n";

/// Whether the manifest explicitly installs SCCP in its original genesis execution.
pub fn is_enabled(manifest: &RawGenesisTransaction) -> bool {
    manifest
        .instructions()
        .any(|instruction| instruction.as_any().is::<InitializeSccpV1>())
}

/// Install the SCCP parameters and escrows, with no routes or substitute governance.
///
/// The native finalizer derives generation one from the signed committee and staking
/// registrations. The caller must bootstrap those registrations before signing.
/// # Errors
/// Rejects private/permissioned roots, duplicate initialization, absent `NPoS` policy,
/// an excessive validator ceiling, a zero nonce, or inconsistent epoch bounds.
pub fn append_profile(
    manifest: RawGenesisTransaction,
    reset_nonce: [u8; 32],
) -> Result<RawGenesisTransaction> {
    ensure!(
        manifest.consensus_mode() == SumeragiConsensusMode::Npos,
        "SCCP genesis requires NPoS consensus"
    );
    ensure!(
        manifest.sumeragi_context_parameters().root_scope == SumeragiRootScope::Global,
        "SCCP genesis requires the global root"
    );
    ensure!(
        !is_enabled(&manifest),
        "SCCP genesis is already initialized"
    );
    ensure!(reset_nonce != [0; 32], "SCCP reset nonce must be nonzero");
    let parameters = manifest.effective_parameters()?;
    let mut npos = parameters
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .ok_or_else(|| eyre!("SCCP genesis requires an explicit NPoS policy"))?;
    // The protocol permits only 4..=31 voting members. A profile may begin below
    // its election ceiling; its exact 3f+1 topology is validated when signed.
    ensure!(
        (4..=31).contains(&npos.max_validators),
        "SCCP NPoS validator ceiling must be in 4..=31"
    );
    let timing = parameters.sumeragi();
    let cadence = timing.block_cadence_ms().get();
    let floor = SCCP_MIN_EPOCH_MS_V1.div_ceil(cadence);
    let epoch = timing
        .epoch_length_blocks
        .get()
        .max(npos.epoch_length_blocks.get())
        .max(floor);
    ensure!(
        epoch.checked_mul(cadence).is_some(),
        "SCCP epoch duration overflows"
    );
    npos.epoch_length_blocks = NonZeroU64::new(epoch).expect("positive epoch floor");
    npos.validate().map_err(|error| eyre!(error))?;
    manifest
        .into_builder()
        .append_parameter(Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
            npos.epoch_length_blocks,
        )))
        .append_parameter(Parameter::Custom(npos.into_custom_parameter()))
        .next_transaction()
        .append_instruction(InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce,
        })
        .build_raw()?
        .with_consensus_meta()
}

/// Persist a reset nonce before returning it; the history must survive network resets.
/// This directory contains only public nonce/identity markers, never signing keys.
/// # Errors
/// Refuses zero/repeated nonces or any history write/durability failure.
pub fn reserve_reset_nonce(history: &Path, nonce: [u8; 32]) -> Result<()> {
    ensure!(nonce != [0; 32], "SCCP reset nonce must be nonzero");
    record_unique(
        history,
        &format!("nonce-{}", hex::encode(nonce)),
        NONCE_MARKER,
    )
}

/// Generate and durably reserve independent operating-system randomness for one reset.
/// Deterministic validator-key seeds never determine the SCCP reset identity.
/// # Errors
/// Returns an error if entropy or durable identity reservation fails.
pub fn fresh_reset_nonce(history: &Path) -> Result<[u8; 32]> {
    let mut nonce = [0; 32];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|error| eyre!("SCCP reset entropy unavailable: {error}"))?;
    reserve_reset_nonce(history, nonce)?;
    Ok(nonce)
}

/// Give a prepared SCCP genesis a fresh reserved nonce before reseating or signing a reset.
/// All other manifest data and the initializer's transaction position are preserved.
/// # Errors
/// Refuses absent, duplicate or mixed-batch initialization and reservation failures.
pub fn renew_reset_nonce(manifest: &mut RawGenesisTransaction, history: &Path) -> Result<()> {
    let mut found = None;
    for (index, batch) in manifest.transactions().iter().enumerate() {
        for instruction in batch.instructions() {
            if let Some(init) = instruction.as_any().downcast_ref::<InitializeSccpV1>() {
                ensure!(found.is_none(), "SCCP genesis must initialize exactly once");
                ensure!(
                    batch.instructions().len() == 1,
                    "SCCP initialization must occupy its own transaction"
                );
                found = Some((index, *init));
            }
        }
    }
    let (index, mut init) = found.ok_or_else(|| eyre!("SCCP genesis initialization is absent"))?;
    init.reset_nonce = fresh_reset_nonce(history)?;
    manifest.replace_instruction_only_transaction(index, vec![vec![init.into()]])
}

/// Consume a reserved nonce and record the final signed genesis identity exactly once.
/// # Errors
/// Refuses repeated identities or consumed nonces, an unreserved nonce, or a persistence failure.
/// A failed publication can burn a nonce; a subsequent reset must reserve a fresh one.
pub fn record_network_identity(
    history: &Path,
    nonce: [u8; 32],
    genesis_hash: &[u8; 32],
) -> Result<()> {
    ensure!(nonce != [0; 32], "SCCP reset nonce must be nonzero");
    let directory =
        iroha_fs::PrivateDirectory::open(history).wrap_err("open original SCCP reset history")?;
    let marker = directory
        .read(format!("nonce-{}", hex::encode(nonce)), NONCE_MARKER.len())
        .wrap_err("SCCP reset nonce was not durably reserved")?;
    ensure!(
        marker.as_slice() == NONCE_MARKER,
        "invalid SCCP nonce reservation"
    );
    directory
        .write_atomic(
            format!("consumed-nonce-{}", hex::encode(nonce)),
            hex::encode(genesis_hash).as_bytes(),
            iroha_fs::PublishMode::CreateNew,
        )
        .wrap_err("SCCP reset nonce was consumed before or cannot be durably consumed")?;
    directory
        .write_atomic(
            format!("network-{}", hex::encode(genesis_hash)),
            hex::encode(nonce).as_bytes(),
            iroha_fs::PublishMode::CreateNew,
        )
        .wrap_err("SCCP network identity was used before or cannot be durably reserved")?;
    Ok(())
}

fn record_unique(history: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let directory =
        iroha_fs::PrivateDirectory::open_or_create(history).wrap_err("open SCCP reset history")?;
    directory
        .write_atomic(name, bytes, iroha_fs::PublishMode::CreateNew)
        .wrap_err("SCCP reset identity was used before or cannot be durably reserved")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_genesis::GenesisBuilder;
    use iroha_model_base::chain::ChainId;

    fn manifest(cadence: u64) -> RawGenesisTransaction {
        let npos = SumeragiNposParameters {
            max_validators: 4,
            ..SumeragiNposParameters::default().with_epoch_seed([7; 32])
        };
        GenesisBuilder::new_without_executor(ChainId::from("sccp-profile-test"), ".")
            .with_sumeragi_context_parameters(
                iroha_data_model::block::consensus::SumeragiGenesisContextParameters::recommended(),
            )
            .with_block_cadence_ms(NonZeroU64::new(cadence).unwrap())
            .append_parameter(Parameter::Custom(npos.into_custom_parameter()))
            .build_raw()
            .unwrap()
            .with_consensus_mode(SumeragiConsensusMode::Npos)
    }

    #[test]
    fn sccp_profile_sets_joint_epoch_floor_and_only_genesis_initialization() {
        for cadence in [100, 1_000, 4_000, 7_000] {
            let profile = append_profile(manifest(cadence), [1; 32]).unwrap();
            let parameters = profile.effective_parameters().unwrap();
            let npos = SumeragiNposParameters::from_custom_parameter(
                parameters
                    .custom()
                    .get(&SumeragiNposParameters::parameter_id())
                    .unwrap(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                parameters.sumeragi().epoch_length_blocks,
                npos.epoch_length_blocks
            );
            assert!(npos.epoch_length_blocks.get() * cadence >= SCCP_MIN_EPOCH_MS_V1);
            let instructions: Vec<_> = profile.instructions().collect();
            assert_eq!(instructions.len(), 1);
            let init = instructions[0]
                .as_any()
                .downcast_ref::<InitializeSccpV1>()
                .unwrap();
            assert_eq!(init.parameters, SccpParametersV1::taira_default());
            assert_eq!(init.reset_nonce, [1; 32]);
            assert!(append_profile(profile, [2; 32]).is_err());
        }
        let longer_npos = SumeragiNposParameters {
            max_validators: 4,
            epoch_length_blocks: NonZeroU64::new(7_200).unwrap(),
            ..SumeragiNposParameters::default().with_epoch_seed([7; 32])
        };
        let longer = manifest(1_000)
            .into_builder()
            .append_parameter(Parameter::Custom(longer_npos.into_custom_parameter()))
            .build_raw()
            .unwrap();
        let profile = append_profile(longer, [3; 32]).unwrap();
        assert_eq!(
            profile
                .effective_parameters()
                .unwrap()
                .sumeragi()
                .epoch_length_blocks
                .get(),
            7_200
        );
        assert!(append_profile(manifest(1_000), [0; 32]).is_err());
        assert!(
            append_profile(
                manifest(1_000).with_consensus_mode(SumeragiConsensusMode::Permissioned),
                [1; 32]
            )
            .is_err()
        );
    }

    #[test]
    fn sccp_nonce_renewal_changes_only_the_single_initializer() {
        let target = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .canonicalize()
            .unwrap();
        let temporary = tempfile::Builder::new()
            .prefix("sccp-renew-")
            .tempdir_in(target)
            .unwrap();
        let history =
            iroha_fs::PrivateDirectory::open_or_create(temporary.path().join("history")).unwrap();
        let mut profile = append_profile(manifest(1000), [1; 32]).unwrap();
        let original = norito::json::to_value(&profile).unwrap();
        renew_reset_nonce(&mut profile, history.path()).unwrap();
        let init = profile
            .instructions()
            .find_map(|instruction| instruction.as_any().downcast_ref::<InitializeSccpV1>())
            .unwrap();
        assert_ne!(init.reset_nonce, [1; 32]);
        assert_ne!(init.reset_nonce, [0; 32]);
        let nonce = init.reset_nonce;
        record_network_identity(history.path(), nonce, &[2; 32]).unwrap();
        assert!(record_network_identity(history.path(), nonce, &[3; 32]).is_err());
        let index = profile
            .transactions()
            .iter()
            .position(|batch| {
                batch
                    .instructions()
                    .iter()
                    .any(|instruction| instruction.as_any().is::<InitializeSccpV1>())
            })
            .unwrap();
        profile
            .replace_instruction_only_transaction(
                index,
                vec![vec![
                    InitializeSccpV1 {
                        parameters: SccpParametersV1::taira_default(),
                        reset_nonce: [1; 32],
                    }
                    .into(),
                ]],
            )
            .unwrap();
        assert_eq!(
            norito::json::to_value(&profile).unwrap(),
            original,
            "no other genesis field changed"
        );
        assert!(renew_reset_nonce(&mut manifest(1000), history.path()).is_err());
    }

    #[test]
    fn sccp_reset_history_rejects_nonce_and_network_reuse_across_runs() {
        let target = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .canonicalize()
            .unwrap();
        let temporary = tempfile::Builder::new()
            .prefix("sccp-reset-")
            .tempdir_in(target)
            .unwrap();
        let history =
            iroha_fs::PrivateDirectory::open_or_create(temporary.path().join("history")).unwrap();
        assert!(reserve_reset_nonce(history.path(), [0; 32]).is_err());
        reserve_reset_nonce(history.path(), [1; 32]).unwrap();
        assert!(reserve_reset_nonce(history.path(), [1; 32]).is_err());
        assert!(record_network_identity(history.path(), [2; 32], &[3; 32]).is_err());
        record_network_identity(history.path(), [1; 32], &[3; 32]).unwrap();
        assert!(record_network_identity(history.path(), [1; 32], &[4; 32]).is_err());
        let next = fresh_reset_nonce(history.path()).unwrap();
        assert_ne!(next, [1; 32]);
        assert!(record_network_identity(history.path(), next, &[3; 32]).is_err());
        assert!(record_network_identity(history.path(), next, &[4; 32]).is_err());
        let next = fresh_reset_nonce(history.path()).unwrap();
        record_network_identity(history.path(), next, &[4; 32]).unwrap();
        reserve_reset_nonce(history.path(), [5; 32]).unwrap();
        std::fs::write(
            history
                .path()
                .join(format!("nonce-{}", hex::encode([5; 32]))),
            b"invalid",
        )
        .unwrap();
        assert!(record_network_identity(history.path(), [5; 32], &[6; 32]).is_err());
        assert!(
            !history
                .path()
                .join(format!("network-{}", hex::encode([6; 32])))
                .exists()
        );
    }
}
