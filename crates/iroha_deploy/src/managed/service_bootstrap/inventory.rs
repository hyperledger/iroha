//! Closed read-only dependency census. Presence can refuse signing, never establish native state.

use super::*;
use crate::managed::service_authority::{ProviderPurpose, ServiceChildInventory};

impl ManagedServiceBootstrap {
    /// Inspect the retained parent and its child purposes without granting dispatch authority.
    pub(super) fn validate_dependency_inventory(
        &self,
        dependencies: &DependencyFrontiers,
    ) -> Result<()> {
        let original = read_original(
            &self.authority.directory.open_child("initial")?,
            &self.authority,
        )?
        .ok_or_else(|| invalid("original bootstrap intent is absent"))?;
        self.validate_child_inventory(&original.policies, Some(dependencies))
    }

    // None means no parent exists: all child purposes must be absent or exactly empty.
    // Presence only refuses publication; this never establishes native completion.
    pub(super) fn validate_child_inventory(
        &self,
        policies: &GeneratedServicePolicies,
        dependencies: Option<&DependencyFrontiers>,
    ) -> Result<()> {
        let inventory = ServiceChildInventory::begin(&self.authority)?;
        let reserve_complete = dependencies.is_some_and(|value| value.reserve_complete);
        let complete = dependencies.is_some_and(|value| value.reputation_complete);
        if let Some(frontiers) = dependencies {
            if frontiers.reputation_complete
                && (!frontiers.reserve_complete || frontiers.providers.iter().any(Option::is_some))
            {
                return Err(invalid("bootstrap dependency frontiers disagree"));
            }
        }
        self.census_network(
            &inventory,
            NetworkPurpose::InitialReservePolicy,
            "set",
            dependencies.is_none(),
        )?;
        for (slot, selected) in policies.providers.iter().enumerate() {
            let provider_id = selected.provider_id;
            let stages = [
                ServiceBootstrapStep::CustodyPolicy { provider_id },
                ServiceBootstrapStep::CustodyEnrollment { provider_id },
                ServiceBootstrapStep::ReserveAccount { provider_id },
                ServiceBootstrapStep::ProviderFunding { provider_id },
                ServiceBootstrapStep::ProviderIngest { provider_id },
                ServiceBootstrapStep::Gateway { provider_id },
            ];
            let pending = dependencies.and_then(|value| value.providers[slot]);
            let first_incomplete = pending
                .map(|step| {
                    stages
                        .iter()
                        .position(|selected| selected == &step)
                        .ok_or_else(|| invalid("bootstrap progress selected another dependency"))
                })
                .transpose()?;
            if !reserve_complete && dependencies.is_some() && first_incomplete != Some(0) {
                return Err(invalid(
                    "bootstrap provider frontier precedes reserve finality",
                ));
            }
            for (index, step) in stages.iter().enumerate() {
                let later =
                    !reserve_complete || first_incomplete.is_some_and(|first| index > first);
                match *step {
                    ServiceBootstrapStep::CustodyPolicy { .. } => self.census_provider(
                        &inventory,
                        provider_id,
                        ProviderPurpose::Custody,
                        "configure",
                        later,
                        !complete,
                    )?,
                    ServiceBootstrapStep::CustodyEnrollment { .. } => self.census_provider(
                        &inventory,
                        provider_id,
                        ProviderPurpose::Custody,
                        "enroll",
                        later,
                        !complete,
                    )?,
                    ServiceBootstrapStep::ReserveAccount { .. } => self.census_provider(
                        &inventory,
                        provider_id,
                        ProviderPurpose::ReserveAccountRegistration,
                        "register",
                        later,
                        false,
                    )?,
                    ServiceBootstrapStep::ProviderFunding { .. } => {
                        // The composite validates its own nested unfinished stage. Wholly later
                        // funding still requires all five original purpose roots exactly empty.
                        for (purpose, operation) in [
                            (ProviderPurpose::ProviderFundingBootstrap, "funding"),
                            (ProviderPurpose::ReserveTopUpRequest, "request"),
                            (ProviderPurpose::ReserveTopUpApproval, "approval"),
                            (ProviderPurpose::InitialProviderCredit, "install"),
                            (ProviderPurpose::ProviderCapacityDeclaration, "declare"),
                        ] {
                            self.census_provider(
                                &inventory,
                                provider_id,
                                purpose,
                                operation,
                                later,
                                false,
                            )?;
                        }
                    }
                    ServiceBootstrapStep::ProviderIngest { .. } => self.census_provider(
                        &inventory,
                        provider_id,
                        ProviderPurpose::InitialProviderIngestAuthority,
                        "setup",
                        later,
                        false,
                    )?,
                    ServiceBootstrapStep::Gateway { .. } => self.census_provider(
                        &inventory,
                        provider_id,
                        ProviderPurpose::InitialGatewaySetup,
                        "setup",
                        later,
                        false,
                    )?,
                    _ => unreachable!("closed provider dependency stage"),
                }
            }
        }
        let providers_complete = dependencies.is_some_and(|value| {
            value.reserve_complete && value.providers.iter().all(Option::is_none)
        });
        self.census_network(
            &inventory,
            NetworkPurpose::InitialReputationPolicy,
            "setup",
            !providers_complete,
        )?;
        inventory.finish()
    }
    fn census_network(
        &self,
        inventory: &ServiceChildInventory<'_>,
        purpose: NetworkPurpose,
        operation: &str,
        later: bool,
    ) -> Result<()> {
        if let Some(owner) = inventory.open_network(purpose)? {
            validate_checkpoint(&owner)?;
            census(&owner.directory, operation, later, false, false)?;
        }
        Ok(())
    }
    fn census_provider(
        &self,
        inventory: &ServiceChildInventory<'_>,
        provider: ProviderId,
        purpose: ProviderPurpose,
        operation: &str,
        later: bool,
        incomplete: bool,
    ) -> Result<()> {
        let custody = matches!(purpose, ProviderPurpose::Custody);
        if let Some(owner) = inventory.open_provider(provider, purpose)? {
            validate_checkpoint(&owner)?;
            census(&owner.directory, operation, later, custody, incomplete)?;
            if custody {
                crate::managed::stream_token_custody::validate_enrollment_inventory(owner)?;
            }
        }
        Ok(())
    }
}

fn validate_checkpoint(owner: &ServiceAuthority) -> Result<()> {
    if let Some(bytes) = crate::managed::native_operation::read_optional(
        &owner.directory,
        "current-checkpoint.nrt",
        crate::managed::native_operation::MAX_CHECKPOINT_BYTES,
    )? {
        // The sole native checkpoint decoder retains network/chain/verified-prefix checks.
        // This census accepts custody, never a fresh observation or dispatch capability.
        owner.decode_checkpoint(&bytes)?;
    }
    Ok(())
}

fn census(
    directory: &PrivateDirectory,
    operation: &str,
    later: bool,
    custody: bool,
    incomplete: bool,
) -> Result<()> {
    let names = directory.entries(if custody { 131 } else { 66 })?;
    for name in &names {
        if name == "operation.lock" || name == "current-checkpoint.nrt" || name == operation {
            continue;
        }
        if custody && (name == "configure" || name == "enroll" || name == "enroll-selection.nrt") {
            continue;
        }
        if custody && !incomplete {
            // Complete initial history may have exact bounded renewal journals. Their native
            // authority is still selected and checked only by the custody renewal owner.
            let valid = (2..=64).any(|sequence| {
                crate::managed::stream_token_custody::renewal::directory_name(sequence).is_ok_and(
                    |expected| {
                        name == std::ffi::OsStr::new(&expected)
                            || name == std::ffi::OsStr::new(&format!("{expected}-selection.nrt"))
                    },
                )
            });
            if valid {
                continue;
            }
        }
        return Err(invalid(
            "bootstrap purpose contains unknown or out-of-order material",
        ));
    }
    if later {
        match directory.open_child_optional(operation)? {
            Some(child) => require_empty(&child).map_err(|_| {
                invalid("later bootstrap material exists behind an incomplete prerequisite")
            })?,
            None => {}
        }
    }
    if directory.entries(if custody { 131 } else { 66 })? != names {
        return Err(invalid(
            "bootstrap dependency inventory changed during inspection",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Inventory refusal retains original custody and never creates native completion.

    use super::*;
    use std::io;

    fn fixture(name: &str) -> (tempfile::TempDir, ManagedServiceBootstrap) {
        let temporary = tempfile::tempdir().unwrap();
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_localnet_at(
            name,
            &temporary.path().join("generation"),
            &ports,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
            None,
        )
        .unwrap();
        let owner = ManagedServiceBootstrap::open(&prepared).unwrap();
        (temporary, owner)
    }

    #[test]
    fn dependency_inventory_refuses_absent_original_without_creating_parent_material() {
        let _guard = crate::managed::native_test_guard();
        let (_temporary, owner) = fixture("inventory-missing-original");
        let policies = GeneratedServicePolicies::select(&owner.authority).unwrap();
        let progress = DependencyFrontiers::before_reserve(&policies);
        let before = owner.authority.directory.entries(4).unwrap();
        assert!(matches!(owner.validate_dependency_inventory(&progress),
            Err(crate::managed::Error::Io(error)) if error.kind() == io::ErrorKind::NotFound));
        assert_eq!(owner.authority.directory.entries(4).unwrap(), before);
        let initial = owner.authority.directory.ensure_child("initial").unwrap();
        let error = owner.validate_dependency_inventory(&progress).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("original bootstrap intent is absent")
        );
        require_empty(&initial).unwrap();
    }

    #[test]
    fn child_inventory_preserves_later_material_and_rejects_foreign_progress() {
        let _guard = crate::managed::native_test_guard();
        let (_temporary, owner) = fixture("inventory-retained-child");
        let policies = GeneratedServicePolicies::select(&owner.authority).unwrap();
        owner.validate_child_inventory(&policies, None).unwrap();
        let provider_id = policies.providers[2].provider_id;
        let later = ServiceAuthority::open_provider(
            &owner.authority.prepared,
            provider_id,
            ProviderPurpose::ProviderCapacityDeclaration,
        )
        .unwrap();
        let child = later.directory.ensure_child("declare").unwrap();
        child
            .write_atomic("original.nrt", b"retained child", PublishMode::CreateNew)
            .unwrap();
        drop(later);
        let original_parent_names = owner.authority.directory.entries(4).unwrap();
        for progress in [None, Some(DependencyFrontiers::before_reserve(&policies))] {
            assert!(
                owner
                    .validate_child_inventory(&policies, progress.as_ref())
                    .is_err()
            );
            assert_eq!(
                owner.authority.directory.entries(4).unwrap(),
                original_parent_names
            );
            assert_eq!(
                child.read("original.nrt", 64).unwrap().as_slice(),
                b"retained child"
            );
        }
        let mut foreign = DependencyFrontiers::before_reserve(&policies);
        foreign.reserve_complete = true;
        foreign.providers[0] = Some(ServiceBootstrapStep::Gateway {
            provider_id: ProviderId::new([0xFA; 32]),
        });
        assert!(
            owner
                .validate_child_inventory(&policies, Some(&foreign))
                .unwrap_err()
                .to_string()
                .contains("bootstrap progress selected another dependency")
        );
        assert_eq!(
            child.read("original.nrt", 64).unwrap().as_slice(),
            b"retained child"
        );
        // This census makes no remote observation and mints no parent or child completion.
        assert!(owner.authority.directory.open_child("initial").is_err());
    }

    #[test]
    fn canonical_native_checkpoint_is_bounded_decoded_custody_and_never_completion() {
        use crate::managed::native_operation::{
            MAX_CHECKPOINT_BYTES, retain_observation,
            test_support::native_fixture::{NativeFixture, quote_instructions},
        };
        use iroha_data_model::isi::{InstructionBox, Log};
        let _guard = crate::managed::native_test_guard();
        let (_temporary, parent) = fixture("inventory-native-checkpoint");
        let policies = GeneratedServicePolicies::select(&parent.authority).unwrap();
        let authority = ServiceAuthority::open_network(
            &parent.authority.prepared,
            NetworkPurpose::InitialReservePolicy,
        )
        .unwrap();
        let mut native = NativeFixture::from_generated(&parent.authority.prepared, &authority);
        let log = quote_instructions(
            &native,
            &authority.config,
            [InstructionBox::from(Log::new(
                iroha_data_model::Level::INFO,
                "actual native checkpoint census".into(),
            ))],
        );
        assert_eq!(native.chain.commit(vec![log]), vec![true]);
        let mut verifier = native.observe(&authority);
        let observation = verifier.observe(&native, &rand::random());
        retain_observation(&authority.directory, &mut verifier, observation).unwrap();
        let bytes = authority
            .directory
            .read("current-checkpoint.nrt", MAX_CHECKPOINT_BYTES)
            .unwrap();
        assert_eq!(
            authority
                .decode_checkpoint(&bytes)
                .unwrap()
                .checkpoint()
                .height(),
            2
        );
        let directory = PrivateDirectory::open_exact(authority.directory.path()).unwrap();
        drop(authority); // The parent census reopens the same canonical exclusive purpose.
        parent.validate_child_inventory(&policies, None).unwrap();
        assert!(parent.authority.directory.open_child("initial").is_err());
        assert!(!directory.path().join("set").exists());
        for bad in [
            bytes.iter().copied().chain([0]).collect::<Vec<_>>(),
            vec![0xFA; MAX_CHECKPOINT_BYTES + 1],
        ] {
            directory
                .write_atomic("current-checkpoint.nrt", &bad, PublishMode::Replace)
                .unwrap();
            assert!(parent.validate_child_inventory(&policies, None).is_err());
            assert_eq!(
                directory.read("current-checkpoint.nrt", bad.len()).unwrap(),
                bad.into()
            );
            directory
                .write_atomic("current-checkpoint.nrt", &bytes, PublishMode::Replace)
                .unwrap();
        }
        std::fs::remove_file(directory.path().join("current-checkpoint.nrt")).unwrap();
        directory.ensure_child("current-checkpoint.nrt").unwrap();
        assert!(parent.validate_child_inventory(&policies, None).is_err());
        std::fs::remove_dir(directory.path().join("current-checkpoint.nrt")).unwrap();
        directory
            .write_atomic("current-checkpoint.nrt", &bytes, PublishMode::CreateNew)
            .unwrap();
        directory
            .write_atomic("unknown-checkpoint.nrt", &bytes, PublishMode::CreateNew)
            .unwrap();
        assert!(parent.validate_child_inventory(&policies, None).is_err());
        std::fs::remove_file(directory.path().join("unknown-checkpoint.nrt")).unwrap();
        parent.validate_child_inventory(&policies, None).unwrap();
        assert_eq!(
            directory
                .read("current-checkpoint.nrt", MAX_CHECKPOINT_BYTES)
                .unwrap(),
            bytes
        );
    }
}
