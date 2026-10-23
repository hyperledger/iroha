//! Helpers for NPoS-specific genesis validation.
use color_eyre::eyre::{Result, eyre};
use iroha_data_model::parameter::system::SumeragiNposParameters;
use iroha_genesis::RawGenesisTransaction;
/// Check that the provided genesis manifest carries `sumeragi_npos_parameters`.
///
/// # Errors
///
/// Returns an error if the NPoS parameter is missing. Callers should surface
/// this early so operators regenerate genesis with `--consensus-mode npos`.
pub fn ensure_npos_parameters(manifest: &RawGenesisTransaction) -> Result<()> {
    if has_npos_parameters(manifest)? {
        Ok(())
    } else {
        Err(eyre!(
            "NPoS consensus requires `sumeragi_npos_parameters` in genesis; regenerate with `kagami genesis generate --consensus-mode npos` or embed the parameter manually"
        ))
    }
}
/// Determine whether `sumeragi_npos_parameters` is present in the manifest.
pub fn has_npos_parameters(manifest: &RawGenesisTransaction) -> Result<bool> {
    let params = manifest.effective_parameters()?;
    let npos_param_id = SumeragiNposParameters::parameter_id();
    Ok(params
        .custom()
        .get(&npos_param_id)
        .map(SumeragiNposParameters::from_custom_parameter)
        .transpose()?
        .flatten()
        .is_some())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        isi::Grant,
        parameter::{
            Parameter,
            system::{SumeragiConsensusMode, SumeragiParameter},
        },
    };
    use iroha_genesis::{GenesisBuilder, RawGenesisTransaction};
    use iroha_model_base::chain::ChainId;
    use iroha_test_samples::ALICE_ID;
    use std::{fs, path::PathBuf};
    use tempfile::NamedTempFile;
    fn manifest_with_params(
        params: Parameter,
        consensus_mode: SumeragiConsensusMode,
    ) -> RawGenesisTransaction {
        let builder = GenesisBuilder::new_without_executor(
            ChainId::from("npos-genesis"),
            PathBuf::from("."),
            iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                iroha_crypto::Algorithm::Ed25519,
                iroha_crypto::Algorithm::Secp256k1,
                iroha_crypto::Algorithm::BlsNormal,
            ])
            .expect("explicit canonical genesis producer policy"),
        )
        .with_staking_policy(crate::genesis::test_staking_policy())
        .expect("explicit fixture staking policy");
        super::super::complete_test_genesis_builder(builder.append_parameter(params))
            .build_raw()
            .expect("complete NPoS parameter test genesis")
            .with_consensus_mode(consensus_mode)
    }
    #[test]
    fn detects_present_npos_parameters() {
        let manifest = roundtrip_manifest(&manifest_with_params(
            Parameter::Custom(SumeragiNposParameters::default().into_custom_parameter()),
            SumeragiConsensusMode::Npos,
        ));
        assert!(has_npos_parameters(&manifest).expect("valid manifest"));
        assert!(ensure_npos_parameters(&manifest).is_ok());
    }
    #[test]
    fn rejects_manifest_without_npos_parameters() {
        let manifest = roundtrip_manifest(&manifest_with_params(
            Parameter::Sumeragi(SumeragiParameter::MaxClockDriftMs(500)),
            SumeragiConsensusMode::Permissioned,
        ));
        assert!(!has_npos_parameters(&manifest).expect("valid manifest"));
        let err = ensure_npos_parameters(&manifest).expect_err("missing params should fail");
        assert!(
            err.to_string().contains("sumeragi_npos_parameters"),
            "unexpected error message: {err}"
        );
    }
    #[test]
    fn ignores_unrelated_set_parameter() {
        let mut builder = GenesisBuilder::new_without_executor(
            ChainId::from("npos-genesis"),
            PathBuf::from("."),
            iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                iroha_crypto::Algorithm::Ed25519,
                iroha_crypto::Algorithm::Secp256k1,
                iroha_crypto::Algorithm::BlsNormal,
            ])
            .expect("explicit canonical genesis producer policy"),
        )
        .with_staking_policy(crate::genesis::test_staking_policy())
        .expect("explicit fixture staking policy");
        let grant = Grant::account_permission(
            iroha_executor_data_model::permission::parameter::CanSetParameters,
            ALICE_ID.clone(),
        );
        builder = builder.append_instruction(grant);
        let manifest = roundtrip_manifest(
            &super::super::complete_test_genesis_builder(builder)
                .build_raw()
                .expect("complete unrelated-parameter test genesis")
                .with_consensus_mode(SumeragiConsensusMode::Permissioned),
        );
        assert!(!has_npos_parameters(&manifest).expect("valid manifest"));
    }
    fn roundtrip_manifest(manifest: &RawGenesisTransaction) -> RawGenesisTransaction {
        let tmp = NamedTempFile::new().expect("create temp file");
        let json = norito::json::to_json_pretty(&manifest).expect("serialize manifest");
        fs::write(tmp.path(), json).expect("write manifest");
        RawGenesisTransaction::from_path(tmp.path()).expect("re-read manifest through parser")
    }
}
