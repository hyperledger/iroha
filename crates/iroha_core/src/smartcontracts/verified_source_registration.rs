//! Native compile-once preparation for consensus-owned verified source.
//!
//! This unregistered draft separates input/idempotence, actual native compilation, and immutable
//! state publication. It accepts no publisher-supplied compilation receipt and reads no unsigned
//! Torii source record. GET uses the borrowed authenticated World value after visibility admission.
//!
//! TODO: Integrate only after the canonical compiler has a complete stack/heap execution owner,
//! typed local capacity deferral, and funded immutable state backing. The test-only constructor
//! below performs genuine native compilation; it is not a production allocation certificate.

use crate::execution_attempt::{ExecutionAttemptError, ExecutionDeferred};
use iroha_allocation::AllocationBudget;
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    smart_contract::{
        ContractArtifactId,
        manifest::ContractManifest,
        verified_source::{
            ContractSourceInventory, NativeCompilationReceipt, NativeCompiledSourceRecord,
        },
    },
};

const MANIFEST_DOMAIN: &[u8] = b"iroha.contract.native-source-manifest.v1\0";

/// Deterministic input mismatch. Local native allocation failure is a separate deferred attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistrationError {
    Inventory,
    Artifact,
    Manifest,
    Receipt,
    Conflict,
    NativeEncoding,
}

/// Identity supplied only by the actual accepted State transaction.
/// No instruction carries these fields or lets a publisher nominate an execution authority.
struct RegistrationIdentity {
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
    registrar: AccountId,
    transaction: Hash,
    height: u64,
}

fn manifest_hash(manifest: &ContractManifest) -> Result<Hash, RegistrationError> {
    Hash::new_from_writer(|out| {
        out.write_all(MANIFEST_DOMAIN)?;
        norito::core::write_canonical_to_writer(manifest, out).map_err(std::io::Error::other)
    })
    .map_err(|_| RegistrationError::NativeEncoding)
}

/// Exact borrowed World join used for both idempotence and GET, with no compiler call.
/// The caller has already authenticated the source World generation and current private access.
fn check_authenticated_record(
    record: &NativeCompiledSourceRecord,
    network_id: NetworkId,
    artifact_id: ContractArtifactId,
    manifest: &ContractManifest,
    registered_code: &[u8],
) -> Result<(), RegistrationError> {
    let receipt = &record.receipt;
    if receipt.network_id != network_id
        || receipt.artifact_id != artifact_id
        || receipt.registration_height == 0
        || receipt.source_inventory_hash
            != record
                .inventory
                .commitment()
                .map_err(|_| RegistrationError::Inventory)?
    {
        return Err(RegistrationError::Receipt);
    }
    if ivm::contract_code_hash(registered_code) != artifact_id.code_hash
        || manifest.code_hash != Some(artifact_id.code_hash)
    {
        return Err(RegistrationError::Artifact);
    }
    if receipt.manifest_hash != manifest_hash(manifest)?
        || manifest.abi_hash != Some(receipt.abi_hash)
        || manifest.compiler_fingerprint.as_deref() != Some(receipt.compiler_fingerprint.as_str())
    {
        return Err(RegistrationError::Manifest);
    }
    Ok(())
}

/// Existing identical native state is admitted before compiler work. Another registrar may reuse
/// the immutable source, but cannot replace its first accepted registrar/transaction provenance.
fn classify_registration(
    identity: &RegistrationIdentity,
    inventory: &ContractSourceInventory,
    manifest: &ContractManifest,
    registered_code: &[u8],
    existing: Option<&NativeCompiledSourceRecord>,
) -> Result<bool, RegistrationError> {
    inventory
        .validate()
        .map_err(|_| RegistrationError::Inventory)?;
    let Some(existing) = existing else {
        return Ok(false);
    };
    check_authenticated_record(
        existing,
        identity.network_id,
        identity.artifact_id,
        manifest,
        registered_code,
    )?;
    if existing.inventory != *inventory {
        return Err(RegistrationError::Conflict);
    }
    Ok(true)
}

/// Sealed actual compiler result. Its production constructor must live inside the canonical,
/// physically admitted compiler worker, not in an HTTP publisher or decoded receipt path.
struct NativeCompilationResult {
    output: kotodama_lang::session::CompileOutput,
    source_inventory_hash: Hash,
}

/// Complete native success, ready to be moved into funded immutable World state.
/// No clone or publication occurs before every source/artifact/manifest join has succeeded.
struct PreparedNativeSourceRegistration {
    record: NativeCompiledSourceRecord,
}

fn finish_native_compilation(
    identity: RegistrationIdentity,
    inventory: ContractSourceInventory,
    manifest: &ContractManifest,
    registered_code: &[u8],
    native: NativeCompilationResult,
    execution_owner: &AllocationBudget,
) -> Result<PreparedNativeSourceRegistration, ExecutionAttemptError<RegistrationError>> {
    inventory
        .validate()
        .map_err(|_| RegistrationError::Inventory)?;
    // Complete byte equality is checked in addition to native content identity. A publisher
    // cannot substitute a self-certified CNTR/source commitment for this actual compiler output.
    let source_inventory_hash = inventory
        .commitment()
        .map_err(|_| RegistrationError::NativeEncoding)?;
    if native.source_inventory_hash != source_inventory_hash {
        return Err(RegistrationError::Inventory.into());
    }
    if native.output.artifact.as_slice() != registered_code
        || ivm::contract_code_hash(registered_code) != identity.artifact_id.code_hash
    {
        return Err(RegistrationError::Artifact.into());
    }
    let verified =
        ivm::verify_contract_artifact_with_memory_budget(&native.output.artifact, execution_owner)
            .map_err(|error| {
                error
                    .local_vm_error()
                    .and_then(|error| ExecutionDeferred::from_vm_error(&error))
                    .map(ExecutionAttemptError::Deferred)
                    .unwrap_or_else(|| RegistrationError::Artifact.into())
            })?;
    if verified.code_hash != identity.artifact_id.code_hash
        || !manifest.same_signed_content(&verified.manifest)
        || !native
            .output
            .manifest
            .same_signed_content(&verified.manifest)
        || native.output.contract_interface != verified.contract_interface
    {
        return Err(RegistrationError::Manifest.into());
    }
    let compiler_fingerprint = verified.contract_interface.compiler_fingerprint;
    let receipt = NativeCompilationReceipt {
        network_id: identity.network_id,
        artifact_id: identity.artifact_id,
        source_inventory_hash,
        manifest_hash: manifest_hash(manifest)?,
        abi_hash: verified.abi_hash,
        compiler_fingerprint,
        registrar: identity.registrar,
        registration_transaction: identity.transaction,
        registration_height: identity.height,
    };
    if receipt.registration_height == 0 {
        return Err(RegistrationError::Receipt.into());
    }
    // The original input is moved, with its compilation/publication allocation owner retained
    // by the eventual native World backing. Dropping compiler scratch cannot refund this input.
    Ok(PreparedNativeSourceRegistration {
        record: NativeCompiledSourceRecord { receipt, inventory },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_data_model::block::BlockHeader;
    use iroha_data_model::smart_contract::verified_source::{
        ContractSourceFile, ContractSourceImport, ContractSourcePackage,
    };
    use iroha_model_base::topology::DataSpaceId;

    fn inventory(value: i32) -> ContractSourceInventory {
        ContractSourceInventory {
            artifacts: Vec::new(),
            root: ContractSourceFile {
                source_name: "main.ko".into(),
                source_text: format!(
                    "seiyaku NativeSource {{ view fn value() authorize(anyone) -> int {{ return {value}; }} }}"
                ),
            },
            sources: Vec::new(),
            imports: Vec::new(),
            packages: Vec::new(),
        }
    }

    // Genuine canonical compilation, confined to this small component fixture. This is not a
    // substitute for the missing production compiler stack+heap ownership certificate.
    fn compile(input: &ContractSourceInventory) -> NativeCompilationResult {
        input.validate().unwrap();
        let session = kotodama_lang::session::CompilerSession::default();
        let output = if input.sources.is_empty()
            && input.artifacts.is_empty()
            && input.imports.is_empty()
            && input.packages.is_empty()
        {
            session
                .build(kotodama_lang::session::CompileRequest {
                    source: &input.root.source_text,
                    source_name: Some(&input.root.source_name),
                })
                .unwrap()
        } else {
            fn file(input: &ContractSourceFile) -> kotodama_lang::linker::SourceModuleUnit {
                kotodama_lang::linker::SourceModuleUnit {
                    source_name: input.source_name.clone(),
                    source: input.source_text.clone(),
                }
            }
            fn import(input: &ContractSourceImport) -> kotodama_lang::linker::ImportBinding {
                kotodama_lang::linker::ImportBinding {
                    alias: input.alias.clone(),
                    package: input.package.clone(),
                }
            }
            // These fixture clones are deliberately not a production conversion owner. Native
            // registration must fund the complete original input/compiler overlap separately.
            let graph = kotodama_lang::linker::SourceLinkRequest {
                artifacts: input
                    .artifacts
                    .iter()
                    .map(|artifact| kotodama_lang::linker::SourceContractArtifact {
                        source_name: artifact.source_name.clone(),
                        artifact: artifact.artifact.clone(),
                    })
                    .collect(),
                root: file(&input.root),
                sources: input.sources.iter().map(file).collect(),
                imports: input.imports.iter().map(import).collect(),
                packages: input
                    .packages
                    .iter()
                    .map(|package| kotodama_lang::linker::SourcePackageUnit {
                        artifacts: package
                            .artifacts
                            .iter()
                            .map(|artifact| kotodama_lang::linker::SourceContractArtifact {
                                source_name: artifact.source_name.clone(),
                                artifact: artifact.artifact.clone(),
                            })
                            .collect(),
                        identity: package.identity.clone(),
                        modules: package.modules.iter().map(file).collect(),
                        sources: package.sources.iter().map(file).collect(),
                        exports: package.exports.iter().cloned().collect(),
                        imports: package.imports.iter().map(import).collect(),
                    })
                    .collect(),
            };
            kotodama_lang::driver::BuildDriver::new(session, "native-source-fixture")
                .compile_project(graph, &input.root.source_name)
                .unwrap()
        };
        NativeCompilationResult {
            output,
            source_inventory_hash: input.commitment().unwrap(),
        }
    }

    fn fixture() -> (
        RegistrationIdentity,
        ContractSourceInventory,
        ContractManifest,
        Vec<u8>,
    ) {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let input = inventory(7);
        let output = compile(&input).output;
        let key = KeyPair::from_seed(
            b"native-source-first-registrar".to_vec(),
            Algorithm::Ed25519,
        );
        let manifest = output
            .manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &key,
            )
            .expect("sign bounded fixture manifest");
        let identity = RegistrationIdentity {
            network_id: NetworkId::from_genesis_hash(
                HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
                    b"independent native genesis fixture",
                )),
            ),
            artifact_id: ContractArtifactId::new(
                DataSpaceId::UNIVERSAL,
                ivm::contract_code_hash(&output.artifact),
            ),
            registrar: AccountId::new(key.public_key().clone()),
            transaction: Hash::new(b"accepted native source registration"),
            height: 7,
        };
        (identity, input, manifest, output.artifact)
    }

    #[test]
    fn actual_native_compilation_creates_exact_immutable_receipt() {
        let (identity, input, manifest, code) = fixture();
        let native = compile(&input);
        let expected_registrar = identity.registrar.clone();
        let expected_tx = identity.transaction;
        let prepared = finish_native_compilation(
            identity,
            input,
            &manifest,
            &code,
            native,
            &AllocationBudget::new(16 * 1024 * 1024),
        )
        .unwrap();
        let record = &prepared.record;
        check_authenticated_record(
            record,
            record.receipt.network_id,
            record.receipt.artifact_id,
            &manifest,
            &code,
        )
        .unwrap();
        assert_eq!(record.receipt.registrar, expected_registrar);
        assert_eq!(record.receipt.registration_transaction, expected_tx);
        assert_eq!(record.receipt.registration_height, 7);
    }

    #[test]
    fn actual_locked_package_compilation_authenticates_complete_original_inventory() {
        let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
        let (mut identity, _, _, _) = fixture();
        let input = ContractSourceInventory {
            artifacts: Vec::new(),
            root: ContractSourceFile {
                source_name: "app.ko".into(),
                source_text:
                    "seiyaku App { include \"parts/view.ko\"; import \"local.ko\" as local; }"
                        .into(),
            },
            sources: vec![
                ContractSourceFile {
                    source_name: "local.ko".into(),
                    source_text: "module Local { export fn value() -> int { return 3; } }".into(),
                },
                ContractSourceFile {
                    source_name: "parts/view.ko".into(),
                    source_text:
                        "view fn value() authorize(anyone) -> int { return local::value() + calc::value(); }".into(),
                },
                ContractSourceFile {
                    source_name: "unused.ko".into(),
                    source_text: "module Unused {}".into(),
                },
            ],
            imports: vec![ContractSourceImport {
                alias: "calc".into(),
                package: "std/math@1".into(),
            }],
            packages: vec![ContractSourcePackage {
                artifacts: Vec::new(),
                identity: "std/math@1".into(),
                modules: vec![ContractSourceFile {
                    source_name: "src/math.ko".into(),
                    source_text: "module Math { include \"body.ko\"; }".into(),
                }],
                sources: vec![ContractSourceFile {
                    source_name: "src/body.ko".into(),
                    source_text: "export fn value() -> int { return 4; }".into(),
                }],
                exports: vec!["value".into()],
                imports: Vec::new(),
            }],
        };
        let native = compile(&input);
        identity.artifact_id.code_hash = ivm::contract_code_hash(&native.output.artifact);
        let key = KeyPair::from_seed(
            b"native-source-locked-package-fixture".to_vec(),
            Algorithm::Ed25519,
        );
        let manifest = native
            .output
            .manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                &key,
            )
            .expect("sign bounded fixture manifest");
        let code = native.output.artifact.clone();
        let prepared = finish_native_compilation(
            identity,
            input,
            &manifest,
            &code,
            native,
            &AllocationBudget::new(16 * 1024 * 1024),
        )
        .unwrap();
        let record = prepared.record;
        check_authenticated_record(
            &record,
            record.receipt.network_id,
            record.receipt.artifact_id,
            &manifest,
            &code,
        )
        .unwrap();
        assert_eq!(
            record.inventory.packages[0].sources[0].source_name,
            "src/body.ko"
        );
        assert_eq!(record.inventory.sources[2].source_name, "unused.ko");
        let mut changed = record.clone();
        changed.inventory.sources[2].source_text.push(' ');
        assert_eq!(
            check_authenticated_record(
                &changed,
                record.receipt.network_id,
                record.receipt.artifact_id,
                &manifest,
                &code,
            ),
            Err(RegistrationError::Receipt)
        );
    }

    #[test]
    fn different_actual_compilation_cannot_certify_registered_bytes() {
        let (identity, input, manifest, code) = fixture();
        let wrong_native = compile(&inventory(8));
        assert!(matches!(
            finish_native_compilation(
                identity,
                input,
                &manifest,
                &code,
                wrong_native,
                &AllocationBudget::new(16 * 1024 * 1024)
            ),
            Err(ExecutionAttemptError::Rejected(
                RegistrationError::Inventory
            ))
        ));
    }

    #[test]
    fn native_output_identity_does_not_allow_a_different_original_inventory() {
        let (identity, mut input, manifest, code) = fixture();
        let native = compile(&input);
        // Trivia can preserve compiled bytes. The native compilation result must still join the
        // exact original inventory; artifact equivalence alone cannot authenticate source text.
        input.root.source_text.push(' ');
        assert!(matches!(
            finish_native_compilation(
                identity,
                input,
                &manifest,
                &code,
                native,
                &AllocationBudget::new(16 * 1024 * 1024)
            ),
            Err(ExecutionAttemptError::Rejected(
                RegistrationError::Inventory
            ))
        ));
    }

    #[test]
    fn local_native_verifier_capacity_is_deferred_without_an_immutable_receipt() {
        let (identity, input, manifest, code) = fixture();
        let native = compile(&input);
        let owner = AllocationBudget::new(0);
        assert!(matches!(
            finish_native_compilation(identity, input, &manifest, &code, native, &owner),
            Err(ExecutionAttemptError::Deferred(_))
        ));
        assert_eq!(owner.reserved_bytes(), 0);
    }

    #[test]
    fn authenticated_receipt_refuses_source_network_scope_and_manifest_substitution() {
        let (identity, input, manifest, code) = fixture();
        let native = compile(&input);
        let prepared = finish_native_compilation(
            identity,
            input,
            &manifest,
            &code,
            native,
            &AllocationBudget::new(16 * 1024 * 1024),
        )
        .unwrap();
        let record = prepared.record;
        let network = record.receipt.network_id;
        let artifact = record.receipt.artifact_id;
        let mut wrong_source = record.clone();
        wrong_source.inventory.root.source_text.push(' ');
        assert_eq!(
            check_authenticated_record(&wrong_source, network, artifact, &manifest, &code),
            Err(RegistrationError::Receipt)
        );
        assert_eq!(
            check_authenticated_record(
                &record,
                NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
                    Hash::new(b"another native genesis")
                )),
                artifact,
                &manifest,
                &code
            ),
            Err(RegistrationError::Receipt)
        );
        assert_eq!(
            check_authenticated_record(
                &record,
                network,
                ContractArtifactId::new(DataSpaceId::new(9), artifact.code_hash),
                &manifest,
                &code
            ),
            Err(RegistrationError::Receipt)
        );
        let mut changed_manifest = manifest.clone();
        changed_manifest.compiler_fingerprint = Some("publisher-selected compiler".into());
        assert_eq!(
            check_authenticated_record(&record, network, artifact, &changed_manifest, &code),
            Err(RegistrationError::Manifest)
        );
    }

    #[test]
    fn duplicate_registration_returns_before_compiler_without_replacing_first_authority() {
        let (identity, input, manifest, code) = fixture();
        let native = compile(&input);
        let prepared = finish_native_compilation(
            identity,
            input,
            &manifest,
            &code,
            native,
            &AllocationBudget::new(16 * 1024 * 1024),
        )
        .unwrap();
        let record = prepared.record;
        let other_key = KeyPair::from_seed(
            b"second registered source publisher".to_vec(),
            Algorithm::Ed25519,
        );
        let next = RegistrationIdentity {
            network_id: record.receipt.network_id,
            artifact_id: record.receipt.artifact_id,
            registrar: AccountId::new(other_key.public_key().clone()),
            transaction: Hash::new(b"different accepted registration"),
            height: 8,
        };
        assert!(
            classify_registration(&next, &record.inventory, &manifest, &code, Some(&record))
                .unwrap()
        );
        let mut changed = record.inventory.clone();
        changed.root.source_text.push(' ');
        assert_eq!(
            classify_registration(&next, &changed, &manifest, &code, Some(&record)),
            Err(RegistrationError::Conflict)
        );
        assert_ne!(record.receipt.registrar, next.registrar);
        assert_ne!(record.receipt.registration_transaction, next.transaction);
    }
}
