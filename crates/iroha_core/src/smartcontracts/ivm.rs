/// IVM integration helpers.
///
/// This module currently only exposes a runtime cache used by other
/// components for the Iroha Virtual Machine (IVM).
pub mod cache;
/// Host adapter for IVM. See module docs for design and current limitations.
pub mod host;
/// Exact, privacy-safe public return decoding.
pub mod return_value;
use crate::state::WorldReadOnly;
use iroha_crypto::Hash;
use iroha_data_model::{
    ValidationFail,
    executor::{
        ArtifactAbiHashMismatchInfo, ContractRejection, IvmAdmissionError,
        ManifestAbiHashMismatchInfo, ManifestCodeHashMismatchInfo, MaxCyclesExceedsFuelInfo,
        MaxCyclesExceedsUpperBoundInfo,
    },
    runtime::{RuntimeUpgradeManifest, RuntimeUpgradeStatus},
    smart_contract::manifest::ContractManifest,
};
use iroha_model_base::metadata::Metadata;
use mv::storage::StorageReadOnly;
use std::{collections::BTreeSet, num::NonZeroU64};
/// Convert deterministic program preparation failures into public admission errors.
#[must_use]
pub(crate) fn admission_reason_from_vm_error(error: ivm::VMError) -> IvmAdmissionError {
    match error {
        ivm::VMError::UnsupportedProgramVersion { major, minor } => {
            IvmAdmissionError::UnsupportedVersion(
                iroha_data_model::executor::UnsupportedVersionInfo { major, minor },
            )
        }
        ivm::VMError::UnsupportedProgramFeatureBits { bits } => {
            IvmAdmissionError::UnsupportedFeatureBits(bits)
        }
        ivm::VMError::UnsupportedProgramAbiVersion { version } => {
            IvmAdmissionError::UnsupportedAbiVersion(version)
        }
        ivm::VMError::ProgramVectorLengthTooLarge {
            vector_length,
            max_allowed,
        } => IvmAdmissionError::VectorLengthTooLarge(
            iroha_data_model::executor::VectorLengthTooLargeInfo {
                vector_length,
                max_allowed,
            },
        ),
        ivm::VMError::ArtifactAbiHashMismatch { expected, actual } => {
            IvmAdmissionError::ArtifactAbiHashMismatch(ArtifactAbiHashMismatchInfo {
                expected: Hash::prehashed(expected),
                actual: Hash::prehashed(actual),
            })
        }
        ivm::VMError::GenericSyscallNotAllowed { syscall } => {
            IvmAdmissionError::GenericSyscallNotAllowed(syscall)
        }
        other => IvmAdmissionError::BytecodeDecodingFailed(other.to_string()),
    }
}
/// Convert deterministic program preparation failures into public admission errors.
#[must_use]
pub(crate) fn program_admission_error(error: ivm::VMError) -> ValidationFail {
    ValidationFail::IvmAdmission(admission_reason_from_vm_error(error))
}
/// Reject contract/deployment metadata on a contract-less generic program.
///
/// Presence is checked before decoding so malformed values cannot evade the
/// discriminator and every execution path observes identical precedence.
pub(crate) fn validate_generic_execution_metadata(
    metadata: &Metadata,
) -> Result<(), ValidationFail> {
    const RESERVED: [&str; 7] = [
        "contract_manifest",
        "gov_contract_address",
        "gov_manifest_approvers",
        "contract_address",
        "contract_alias",
        "contract_entrypoint",
        "contract_payload",
    ];
    if let Some(key) = RESERVED
        .into_iter()
        .find(|key| metadata.get(*key).is_some())
    {
        return Err(ValidationFail::NotPermitted(format!(
            "generic IVM programs cannot carry reserved `{key}` metadata"
        )));
    }
    Ok(())
}
/// Reject every contract identity shape for a contract-less generic program.
///
/// Metadata and the content-addressed manifest registry are checked together so the same hash
/// cannot execute as generic bytecode on direct/trigger paths while overlay admission classifies
/// it as deployed contract code. Values remain unparsed: mere presence of reserved metadata fails
/// closed.
pub(crate) fn validate_generic_execution_context(
    world: &impl WorldReadOnly,
    metadata: &Metadata,
    artifact_id: iroha_data_model::smart_contract::ContractArtifactId,
) -> Result<(), ValidationFail> {
    validate_generic_execution_metadata(metadata)?;
    let scope = crate::sumeragi::lanes::routing::committed_root_scope(world).ok_or_else(|| {
        ValidationFail::NotPermitted("generic IVM requires immutable root scope".into())
    })?;
    if !matches!(
        scope,
        iroha_data_model::block::consensus::SumeragiRootScope::Global
    ) {
        return Err(ValidationFail::NotPermitted(
            "private roots require address-bound contract execution".into(),
        ));
    }
    if world.contract_manifests().get(&artifact_id).is_some() {
        return Err(ValidationFail::NotPermitted(
            "generic IVM program hash is bound to a contract manifest in live state".to_owned(),
        ));
    }
    Ok(())
}
/// Validate the first-release runtime-upgrade ABI surface against this binary.
///
/// Runtime records are persisted consensus state. A node must fail closed when that state selects
/// an ABI descriptor different from the one compiled into the process; interpreting a block under a
/// substituted local surface would fork consensus.
pub(crate) fn validate_runtime_upgrade_manifest_abi(
    manifest: &RuntimeUpgradeManifest,
) -> Result<Hash, IvmAdmissionError> {
    if manifest.abi_version != 1 {
        let version =
            u8::try_from(manifest.abi_version).map_err(|_| IvmAdmissionError::ManifestMalformed)?;
        return Err(IvmAdmissionError::UnsupportedAbiVersion(version));
    }
    if !manifest.added_syscalls.is_empty() || !manifest.added_pointer_types.is_empty() {
        return Err(IvmAdmissionError::ManifestMalformed);
    }
    let local_bytes = ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1);
    let local = Hash::prehashed(local_bytes);
    if manifest.abi_hash != local_bytes {
        let selected = Hash::prehashed(manifest.abi_hash);
        return Err(IvmAdmissionError::ManifestAbiHashMismatch(
            ManifestAbiHashMismatchInfo {
                expected: selected,
                actual: local,
            },
        ));
    }
    Ok(local)
}
/// Return the ABI hash selected by the latest effective runtime upgrade.
///
/// Equal-height active records are invalid even if their payloads happen to
/// match: consensus must have one unambiguous active runtime selection.
pub(crate) fn active_runtime_abi_hash(
    world: &impl WorldReadOnly,
    height: u64,
) -> Result<Option<Hash>, IvmAdmissionError> {
    let mut active = None;
    let mut activation_heights = BTreeSet::new();
    for (id, record) in world.runtime_upgrades().iter() {
        let manifest = &record.manifest;
        if manifest.start_height >= manifest.end_height {
            return Err(IvmAdmissionError::ManifestMalformed);
        }
        let abi_hash = match record.status {
            RuntimeUpgradeStatus::Canceled => continue,
            RuntimeUpgradeStatus::Proposed => {
                // Proposed records can auto-activate at the start height, so
                // persisted corruption must fail before that transition.
                validate_runtime_upgrade_manifest_abi(manifest)?;
                continue;
            }
            RuntimeUpgradeStatus::ActivatedAt(activated_at) => {
                if activated_at < manifest.start_height || activated_at >= manifest.end_height {
                    return Err(IvmAdmissionError::ManifestMalformed);
                }
                if !activation_heights.insert(activated_at) {
                    return Err(IvmAdmissionError::ManifestMalformed);
                }
                // Validate every activated record, including future records. A
                // newer valid record must never mask an older incompatible one.
                (
                    activated_at,
                    validate_runtime_upgrade_manifest_abi(manifest)?,
                )
            }
        };
        let (activated_at, abi_hash) = abi_hash;
        if activated_at > height {
            continue;
        }
        match active {
            Some((best_height, _, _)) if activated_at < best_height => continue,
            Some((best_height, _, _)) if activated_at == best_height => {
                unreachable!("duplicate activation heights were rejected above")
            }
            _ => active = Some((activated_at, *id, abi_hash)),
        }
    }
    Ok(active.map(|(_, _, abi_hash)| abi_hash))
}
/// Validate the consensus-binding hashes carried by a contract manifest.
///
/// V1 manifests must bind both the complete artifact and the exact ABI descriptor. Missing fields
/// are rejected before mismatches, and the code hash is checked before the ABI hash to give every
/// node identical error precedence.
pub(crate) fn validate_manifest_hashes(
    manifest: &ContractManifest,
    actual_code_hash: Hash,
    actual_abi_hash: Hash,
) -> Result<(), IvmAdmissionError> {
    let expected_code_hash = manifest
        .code_hash
        .ok_or(IvmAdmissionError::ManifestCodeHashMissing)?;
    if expected_code_hash != actual_code_hash {
        return Err(IvmAdmissionError::ManifestCodeHashMismatch(
            ManifestCodeHashMismatchInfo {
                expected: expected_code_hash,
                actual: actual_code_hash,
            },
        ));
    }
    let expected_abi_hash = manifest
        .abi_hash
        .ok_or(IvmAdmissionError::ManifestAbiHashMissing)?;
    if expected_abi_hash != actual_abi_hash {
        return Err(IvmAdmissionError::ManifestAbiHashMismatch(
            ManifestAbiHashMismatchInfo {
                expected: expected_abi_hash,
                actual: actual_abi_hash,
            },
        ));
    }
    Ok(())
}
/// Validate and return an artifact's positive cycle limit under node policy.
///
/// This is shared by executable admission and every path that persists an IVM
/// artifact, so zero cannot mean "unlimited" and an artifact cannot be stored
/// for later execution with a header above the configured ceiling.
pub(crate) fn validate_cycle_ceiling(
    meta: &ivm::ProgramMetadata,
    upper_bound: NonZeroU64,
) -> Result<NonZeroU64, IvmAdmissionError> {
    let cycles = NonZeroU64::new(meta.max_cycles).ok_or(IvmAdmissionError::MissingMaxCycles)?;
    if cycles > upper_bound {
        return Err(IvmAdmissionError::MaxCyclesExceedsUpperBound(
            MaxCyclesExceedsUpperBoundInfo {
                max_cycles: cycles.get(),
                upper_bound: upper_bound.get(),
            },
        ));
    }
    Ok(cycles)
}
/// Validate an artifact cycle budget against both governance fuel and node policy.
///
/// The governance limit is checked first to preserve transaction-admission error
/// precedence when both limits are exceeded.
pub(crate) fn validate_cycle_limits(
    meta: &ivm::ProgramMetadata,
    upper_bound: NonZeroU64,
    fuel: NonZeroU64,
) -> Result<NonZeroU64, IvmAdmissionError> {
    let cycles = NonZeroU64::new(meta.max_cycles).ok_or(IvmAdmissionError::MissingMaxCycles)?;
    if cycles > fuel {
        return Err(IvmAdmissionError::MaxCyclesExceedsFuel(
            MaxCyclesExceedsFuelInfo {
                max_cycles: cycles.get(),
                fuel_limit: fuel.get(),
            },
        ));
    }
    if cycles > upper_bound {
        return Err(IvmAdmissionError::MaxCyclesExceedsUpperBound(
            MaxCyclesExceedsUpperBoundInfo {
                max_cycles: cycles.get(),
                upper_bound: upper_bound.get(),
            },
        ));
    }
    Ok(cycles)
}
/// Compute a conservative gas limit for a given cycle budget.
///
/// The interpreter pads traces to exactly `max_cycles` when cycle limits are enabled, charging one
/// unit of gas per padded cycle in addition to the per‑instruction gas schedule. To ensure padding
/// cannot exhaust gas after executing costlier instructions, use the worst-case instruction cost as
/// the multiplier. V1 requires a positive cycle limit, represented by [`NonZeroU64`], so this
/// helper cannot manufacture an unbounded budget.
#[must_use]
pub fn gas_limit_for_cycles(cycles: NonZeroU64) -> u64 {
    cycles
        .get()
        .saturating_mul(ivm::gas::max_instruction_cost())
}
/// Convenience helper to derive a gas limit from program metadata.
///
/// # Errors
/// Returns [`IvmAdmissionError::MissingMaxCycles`] when the artifact encodes
/// the forbidden zero cycle limit.
pub fn gas_limit_for_meta(meta: &ivm::ProgramMetadata) -> Result<u64, IvmAdmissionError> {
    let cycles = NonZeroU64::new(meta.max_cycles).ok_or(IvmAdmissionError::MissingMaxCycles)?;
    Ok(gas_limit_for_cycles(cycles))
}
/// Classify an original VM failure before rendering completed semantic rejection context.
///
/// Local refusals retain their original release owner and never enter diagnostic
/// formatting. Output allocation for completed validation messages remains separate.
#[must_use]
pub fn map_vm_error_with_context_to_validation(
    vm: &ivm::IVM,
    error: ivm::VMError,
) -> crate::execution_attempt::ExecutionAttemptError<ValidationFail> {
    let fault = vm.execution_fault(
        &error,
        iroha_data_model::executor::fault::IvmFaultPositionV1::ReturnValidation,
    );
    if error.fault_kind().is_some() && fault.is_none() {
        return crate::execution_attempt::ExecutionAttemptError::Deferred(
            ivm::error::ExecutionDeferral::LocalInvariantViolation.into(),
        );
    }
    crate::execution_attempt::vm_attempt_error(error, |error| {
        // The declared rejection already owns its authenticated strings. Remove
        // metering wrappers only for that variant so all other displays retain
        // their original error context.
        let error = if matches!(error.as_unmetered(), ivm::VMError::ContractAbort { .. }) {
            error.into_unmetered()
        } else {
            error
        };
        if let ivm::VMError::ContractAbort {
            contract,
            name,
            error_type,
            schema_hash,
            code,
            message,
        } = error
        {
            // Transfer the original completed output without cloning its backing.
            return ValidationFail::ContractRejected(ContractRejection {
                contract,
                error_type,
                schema_hash,
                name,
                code,
                message,
            });
        }
        match fault {
            Some(fault) => ValidationFail::IvmFault(fault),
            None => program_admission_error(error.into_unmetered()),
        }
    })
}
#[cfg(test)]
#[path = "ivm/diagnostic_tests.rs"]
mod diagnostic_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        runtime::{
            RuntimeUpgradeId, RuntimeUpgradeManifest, RuntimeUpgradeRecord, RuntimeUpgradeStatus,
        },
        smart_contract::manifest::ContractManifest,
    };
    use iroha_model_base::metadata::Metadata;
    use iroha_model_base::name::Name;
    use iroha_primitives::json::Json;
    fn manifest_with_hashes(code_hash: Option<Hash>, abi_hash: Option<Hash>) -> ContractManifest {
        ContractManifest {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            seiyaku_name: None,
            code_hash,
            abi_hash,
            compiler_fingerprint: None,
            features_bitmap: None,
            access_set_hints: None,
            entrypoints: None,
            states: None,
            kotoba: None,
            error_messages: None,
            error_types: None,
            provenance: None,
        }
    }
    fn runtime_manifest() -> RuntimeUpgradeManifest {
        RuntimeUpgradeManifest {
            name: "numeric-v1".to_owned(),
            description: "first-release ABI".to_owned(),
            abi_version: 1,
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            added_syscalls: Vec::new(),
            added_pointer_types: Vec::new(),
            start_height: 1,
            end_height: 100,
            sbom_digests: Vec::new(),
            slsa_attestation: Vec::new(),
            provenance: Vec::new(),
        }
    }
    #[test]
    fn generic_programs_reject_every_contract_metadata_shape_without_decoding_values() {
        for key in [
            "contract_manifest",
            "gov_contract_address",
            "gov_manifest_approvers",
            "contract_address",
            "contract_alias",
            "contract_entrypoint",
            "contract_payload",
        ] {
            let mut metadata = Metadata::default();
            metadata.insert(
                key.parse::<Name>().expect("static metadata key"),
                Json::new("malformed-reserved-value"),
            );
            let error = validate_generic_execution_metadata(&metadata)
                .expect_err("generic programs must reject contract/deployment metadata");
            assert!(
                matches!(error, ValidationFail::NotPermitted(ref message) if message.contains(key)),
                "unexpected rejection for `{key}`: {error}"
            );
        }
    }
    #[test]
    fn generic_program_hash_rejects_live_manifest_binding() {
        let code_hash = Hash::new(b"generic-binding-probe");
        let metadata = Metadata::default();
        let mut world = crate::sumeragi::lanes::routing::test_support::world(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        );
        let artifact_id = iroha_data_model::smart_contract::ContractArtifactId::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            code_hash,
        );
        validate_generic_execution_context(&world.view(), &metadata, artifact_id)
            .expect("unbound generic program is valid");
        world.contract_manifests.insert(
            artifact_id,
            manifest_with_hashes(Some(code_hash), Some(Hash::new(b"generic-abi"))),
        );
        let error = validate_generic_execution_context(&world.view(), &metadata, artifact_id)
            .expect_err("a manifest-bound hash is not generic");
        assert!(error.to_string().contains("contract manifest"));
    }
    #[test]
    fn generic_artifact_classification_is_scoped_and_requires_a_global_root() {
        use iroha_data_model::{
            block::consensus::SumeragiRootScope, smart_contract::ContractArtifactId,
        };
        use iroha_model_base::topology::DataSpaceId;
        let hash = Hash::new(b"same-bytecode-distinct-dataspaces");
        let own = ContractArtifactId::new(DataSpaceId::new((1_u64 << 40) + 7), hash);
        let foreign = ContractArtifactId::new(DataSpaceId::new(7), hash);
        let metadata = Metadata::default();
        let mut world =
            crate::sumeragi::lanes::routing::test_support::world(SumeragiRootScope::Global);
        world.contract_manifests.insert(
            foreign,
            manifest_with_hashes(Some(hash), Some(Hash::new(b"abi"))),
        );
        assert!(validate_generic_execution_context(&world.view(), &metadata, own).is_ok());
        assert!(validate_generic_execution_context(&world.view(), &metadata, foreign).is_err());
        let unbound = crate::state::World::new();
        assert!(validate_generic_execution_context(&unbound.view(), &metadata, own).is_err());
        let private =
            crate::sumeragi::lanes::routing::test_support::world(SumeragiRootScope::Dataspace {
                parent_network_id: iroha_data_model::NetworkId::from_genesis_hash(
                    iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"parent")),
                ),
                dataspace_id: own.dataspace_id,
            });
        assert!(validate_generic_execution_context(&private.view(), &metadata, own).is_err());
    }
    #[test]
    fn runtime_upgrade_manifest_abi_validation_fails_closed() {
        let valid = runtime_manifest();
        assert_eq!(
            validate_runtime_upgrade_manifest_abi(&valid),
            Ok(Hash::prehashed(valid.abi_hash))
        );
        let mut stale = valid.clone();
        stale.abi_hash[0] ^= 0x80;
        assert!(matches!(
            validate_runtime_upgrade_manifest_abi(&stale),
            Err(IvmAdmissionError::ManifestAbiHashMismatch(_))
        ));
        let mut normalized_alias = valid.clone();
        normalized_alias.abi_hash[31] ^= 1;
        assert_eq!(
            Hash::prehashed(normalized_alias.abi_hash),
            Hash::prehashed(valid.abi_hash),
            "Hash normalization must not erase an ABI descriptor mismatch"
        );
        assert!(matches!(
            validate_runtime_upgrade_manifest_abi(&normalized_alias),
            Err(IvmAdmissionError::ManifestAbiHashMismatch(_))
        ));
        let mut delta = valid.clone();
        delta.added_syscalls.push(7);
        assert!(matches!(
            validate_runtime_upgrade_manifest_abi(&delta),
            Err(IvmAdmissionError::ManifestMalformed)
        ));
        let mut unsupported = valid;
        unsupported.abi_version = 2;
        assert!(matches!(
            validate_runtime_upgrade_manifest_abi(&unsupported),
            Err(IvmAdmissionError::UnsupportedAbiVersion(2))
        ));
    }
    #[test]
    fn active_runtime_selection_validates_all_records_and_rejects_ties() {
        let mut world = crate::state::World::new();
        let proposer = iroha_test_samples::ALICE_ID.clone();
        let valid = runtime_manifest();
        let mut stale = valid.clone();
        stale.abi_hash[0] ^= 0x40;
        world.runtime_upgrades.insert(
            RuntimeUpgradeId([1; 32]),
            RuntimeUpgradeRecord {
                manifest: stale,
                status: RuntimeUpgradeStatus::ActivatedAt(2),
                proposer: proposer.clone(),
                created_height: 1,
            },
        );
        world.runtime_upgrades.insert(
            RuntimeUpgradeId([2; 32]),
            RuntimeUpgradeRecord {
                manifest: valid.clone(),
                status: RuntimeUpgradeStatus::ActivatedAt(3),
                proposer: proposer.clone(),
                created_height: 2,
            },
        );
        assert!(matches!(
            active_runtime_abi_hash(&world.view(), 3),
            Err(IvmAdmissionError::ManifestAbiHashMismatch(_))
        ));
        world.runtime_upgrades.insert(
            RuntimeUpgradeId([1; 32]),
            RuntimeUpgradeRecord {
                manifest: valid.clone(),
                status: RuntimeUpgradeStatus::ActivatedAt(2),
                proposer: proposer.clone(),
                created_height: 1,
            },
        );
        assert_eq!(
            active_runtime_abi_hash(&world.view(), 3),
            Ok(Some(Hash::prehashed(valid.abi_hash)))
        );
        let mut future_stale = valid.clone();
        future_stale.abi_hash[0] ^= 0x20;
        world.runtime_upgrades.insert(
            RuntimeUpgradeId([4; 32]),
            RuntimeUpgradeRecord {
                manifest: future_stale,
                status: RuntimeUpgradeStatus::ActivatedAt(99),
                proposer: proposer.clone(),
                created_height: 3,
            },
        );
        assert!(matches!(
            active_runtime_abi_hash(&world.view(), 3),
            Err(IvmAdmissionError::ManifestAbiHashMismatch(_))
        ));
        world.runtime_upgrades.insert(
            RuntimeUpgradeId([4; 32]),
            RuntimeUpgradeRecord {
                manifest: valid.clone(),
                status: RuntimeUpgradeStatus::ActivatedAt(99),
                proposer: proposer.clone(),
                created_height: 3,
            },
        );
        world.runtime_upgrades.insert(
            RuntimeUpgradeId([3; 32]),
            RuntimeUpgradeRecord {
                manifest: valid,
                status: RuntimeUpgradeStatus::ActivatedAt(3),
                proposer,
                created_height: 2,
            },
        );
        assert!(matches!(
            active_runtime_abi_hash(&world.view(), 3),
            Err(IvmAdmissionError::ManifestMalformed)
        ));
    }
    #[test]
    fn manifest_hash_validation_is_complete_and_has_stable_precedence() {
        let code_hash = Hash::new(b"manifest-code");
        let abi_hash = Hash::new(b"manifest-abi");
        let wrong_code_hash = Hash::new(b"wrong-code");
        let wrong_abi_hash = Hash::new(b"wrong-abi");
        assert!(matches!(
            validate_manifest_hashes(&manifest_with_hashes(None, None), code_hash, abi_hash),
            Err(IvmAdmissionError::ManifestCodeHashMissing)
        ));
        assert!(matches!(
            validate_manifest_hashes(
                &manifest_with_hashes(Some(code_hash), None),
                code_hash,
                abi_hash
            ),
            Err(IvmAdmissionError::ManifestAbiHashMissing)
        ));
        assert!(matches!(
            validate_manifest_hashes(
                &manifest_with_hashes(Some(wrong_code_hash), Some(wrong_abi_hash)),
                code_hash,
                abi_hash
            ),
            Err(IvmAdmissionError::ManifestCodeHashMismatch(info))
                if info.expected == wrong_code_hash && info.actual == code_hash
        ));
        assert!(matches!(
            validate_manifest_hashes(
                &manifest_with_hashes(Some(code_hash), Some(wrong_abi_hash)),
                code_hash,
                abi_hash
            ),
            Err(IvmAdmissionError::ManifestAbiHashMismatch(info))
                if info.expected == wrong_abi_hash && info.actual == abi_hash
        ));
        assert_eq!(
            validate_manifest_hashes(
                &manifest_with_hashes(Some(code_hash), Some(abi_hash)),
                code_hash,
                abi_hash
            ),
            Ok(())
        );
    }
    #[test]
    fn gas_limit_for_cycles_scales_by_max_instruction_cost() {
        let cost = ivm::gas::max_instruction_cost();
        assert_eq!(gas_limit_for_cycles(NonZeroU64::new(1).unwrap()), cost);
        assert_eq!(
            gas_limit_for_cycles(NonZeroU64::new(2).unwrap()),
            cost.saturating_mul(2)
        );
    }
    #[test]
    fn gas_limit_for_meta_rejects_zero_cycle_budget() {
        let zero = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length: 0,
            max_cycles: 0,
            abi_version: 1,
        };
        assert!(matches!(
            gas_limit_for_meta(&zero),
            Err(IvmAdmissionError::MissingMaxCycles)
        ));
        let positive = ivm::ProgramMetadata {
            max_cycles: 2,
            ..zero
        };
        assert_eq!(
            gas_limit_for_meta(&positive).unwrap(),
            ivm::gas::max_instruction_cost().saturating_mul(2)
        );
    }
    #[test]
    fn cycle_ceiling_validation_rejects_zero_and_over_bound() {
        let upper_bound = NonZeroU64::new(42).expect("test ceiling is non-zero");
        let mut metadata = ivm::ProgramMetadata {
            max_cycles: 0,
            ..ivm::ProgramMetadata::default()
        };
        assert!(matches!(
            validate_cycle_ceiling(&metadata, upper_bound),
            Err(IvmAdmissionError::MissingMaxCycles)
        ));
        metadata.max_cycles = 42;
        assert_eq!(
            validate_cycle_ceiling(&metadata, upper_bound),
            Ok(upper_bound)
        );
        metadata.max_cycles = 43;
        assert!(matches!(
            validate_cycle_ceiling(&metadata, upper_bound),
            Err(IvmAdmissionError::MaxCyclesExceedsUpperBound(info))
                if info.max_cycles == 43 && info.upper_bound == 42
        ));
    }
    #[test]
    fn compiler_and_node_release_cycle_defaults_match() {
        let compiler_default = kotodama_lang::compiler::CompilerOptions::default().max_cycles;
        let node_default = iroha_config::parameters::defaults::pipeline::IVM_MAX_CYCLES_UPPER_BOUND;
        assert_eq!(compiler_default, node_default.get());
        assert_eq!(compiler_default, 1_000_000);
    }
    #[test]
    fn vm_error_maps_to_not_permitted() {
        let vm = ivm::IVM::try_new(100).unwrap();
        let err = crate::execution_attempt::expect_completed_rejection(
            map_vm_error_with_context_to_validation(&vm, ivm::VMError::OutOfGas),
        );
        assert!(
            matches!(err, ValidationFail::IvmFault(fault) if fault.kind == iroha_data_model::executor::fault::IvmFaultKindV1::OutOfGas)
        );
    }
    #[test]
    fn declared_contract_abort_maps_to_manifest_authenticated_rejection() {
        let artifact = kotodama_lang::compiler::Compiler::new()
            .compile_source(
                r#"
                seiyaku LiquidityPolicy { permission Test;
                    error enum LiquidityError {
                        BelowMinimum = 18,
                    }

                    kotoage fn reject() authorize(Test) {
                        require(false, LiquidityError::BelowMinimum);
                    }
                }
                "#,
            )
            .expect("compile contract rejection fixture");
        let mut vm = ivm::IVM::new(u64::MAX);
        vm.load_program(&artifact)
            .expect("load contract rejection fixture");
        let entry_pc = vm
            .contract_interface()
            .expect("embedded contract interface")
            .entrypoints
            .iter()
            .find(|entrypoint| entrypoint.name == "reject")
            .expect("reject entrypoint")
            .entry_pc;
        let prefix = ivm::ProgramMetadata::parse(&artifact).unwrap().prefix_len() as u64;
        vm.set_program_counter(prefix + entry_pc)
            .expect("select reject entrypoint");
        let error = vm.run().expect_err("declared require must abort");
        let descriptor = vm
            .contract_interface()
            .expect("interface")
            .error_types
            .iter()
            .find(|descriptor| descriptor.variant(18).is_some())
            .expect("declared error");
        assert_eq!(
            error,
            ivm::VMError::ContractAbort {
                contract: "LiquidityPolicy".into(),
                name: "BelowMinimum".to_owned(),
                error_type: descriptor.identity.clone(),
                schema_hash: descriptor.schema_hash(),
                code: 18,
                message: None,
            }
        );
        assert_eq!(
            crate::execution_attempt::expect_completed_rejection(
                map_vm_error_with_context_to_validation(&vm, error),
            ),
            ValidationFail::ContractRejected(ContractRejection {
                contract: "LiquidityPolicy".into(),
                error_type: descriptor.identity.clone(),
                schema_hash: descriptor.schema_hash(),
                name: "BelowMinimum".to_owned(),
                code: 18,
                message: None,
            })
        );
    }
}
