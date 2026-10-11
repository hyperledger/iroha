//! Public preparation with genuine sigma proofs and a signed retained receipt.
//!
//! Only Bootstrap and Refresh have monetary source keys here. The remaining
//! engineering verifier entries and Omega are not used to admit any proof. This
//! does not qualify Advance custody, a producer catalog, recursion or wallet open.

use ff::Field;
use iroha_kagemusha_proof::admin_sigma::{
    BootstrapCircuit, BootstrapWitness, RefreshCircuit, RefreshWitness, StateWitness,
    native::{BootstrapProver, RefreshProver},
};
use iroha_pasta::Eq;
use iroha_plonk::{
    ProverRandomness, ProvingKey,
    frontend::Circuit,
    keys::{CosetCachePolicy, KeygenConfigV2, keygen_pk_v2, pk::artifact::ReadConfig},
    pcs::ipa::PinnedParams,
};

use super::*;
use crate::{
    kagemusha_wallet_advance_v1::KagemushaWalletRetainedV1 as Retained,
    kagemusha_wallet_artifacts_v1::{
        ArtifactOriginalV1, StepOriginalV1,
        engineering_fixture::signed_inventory_with_step_originals,
    },
    kagemusha_wallet_state_v1::FrozenTransition,
};

type Operation = KagemushaWalletOperationKindV1;
type InputRole = KagemushaWalletRetainedInputRoleV1;

fn key<C: Circuit<Fp>>(circuit: C, params: &PinnedParams<Eq>) -> ProvingKey<Eq> {
    keygen_pk_v2(
        params,
        &circuit.without_witnesses(),
        &KeygenConfigV2::pipa_r(BootstrapCircuit::instance_types().to_vec()),
    )
    .unwrap()
}
fn original(key: &ProvingKey<Eq>, kind: Operation) -> StepOriginalV1 {
    StepOriginalV1 {
        kind,
        enabled_controls: 0,
        artifact: ArtifactOriginalV1 {
            descriptor: key.binding().encoded().to_vec(),
            verifying_key: key.vk().to_bytes().to_vec(),
        },
    }
}
fn read_config(bytes: &[u8]) -> ReadConfig {
    ReadConfig {
        maximum_bytes: bytes.len(),
        maximum_rows: 1 << 12,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}
fn public(key: &SigningKey) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        key.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap()
}
fn certificate(
    scheme: &KagemushaWalletSchemeV1,
    key: &SigningKey,
    role: Role,
) -> KagemushaWalletSignerCertificateV1 {
    let body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role,
        key: public(key),
        serial: 91,
    };
    let root = SigningKey::from_slice(&[0x11; 32]).unwrap();
    KagemushaWalletSignerCertificateV1::sign(body, scheme, sign(&root, &body.signing_message()))
        .unwrap()
}
fn credential(
    scheme: &KagemushaWalletSchemeV1,
    issuer: &SigningKey,
    certificate: &KagemushaWalletSignerCertificateV1,
    payment: &SigningKey,
) -> KagemushaWalletCredentialV1 {
    let mut body = request().receiver_credential.body;
    body.scheme_id = scheme.scheme_id();
    body.payment_key = public(payment);
    body.wallet_id = kagemusha_wallet_id_v1(
        &body.scheme_id,
        &body.asset_digest,
        &body.payment_key,
        &body.enrollment_id,
    );
    body.issuer_certificate = certificate.certificate_digest();
    KagemushaWalletCredentialV1::sign(body, certificate, sign(issuer, &body.signing_message()))
        .unwrap()
}

fn release(
    credential: KagemushaWalletCredentialV1,
    state: KagemushaWalletStateV1,
    statement: KagemushaWalletStatementV1,
    sigma: KagemushaWalletStepProofV1,
    payment: &SigningKey,
) -> ReleasedStep {
    let proof_digest =
        kagemusha_wallet_proof_digest_v1(Operation::Bootstrap, None, &sigma).unwrap();
    let capsule = KagemushaWalletRecoveryCapsuleV1 {
        version: 1,
        scheme_id: statement.scheme_id,
        wallet_id: state.core.wallet_id,
        operation_id: statement.operation_id(&state.core.wallet_id).unwrap(),
        kind: Operation::Bootstrap,
        predecessor_capsule_digest: [0; 32],
        successor_state: state,
        statement,
        predecessor_lineage: KagemushaWalletLineageSlotV1::None,
        step_proof: sigma,
        payment_digest: [0; 32],
        map_openings: vec![],
        retained_inputs: vec![],
        output: KagemushaWalletOutputDescriptorV1::for_transition(
            &statement,
            &proof_digest,
            &[0; 32],
        )
        .unwrap(),
    };
    let signer = KagemushaWalletReceiptSignerV1::from_credential(&credential).unwrap();
    let body = KagemushaWalletReceiptBodyV1::derive(
        &signer,
        &statement,
        &proof_digest,
        capsule.capsule_digest().unwrap(),
        [0; 32],
    )
    .unwrap();
    let receipt = KagemushaWalletReceiptV1::sign(
        &credential,
        &statement,
        &proof_digest,
        body.capsule_digest,
        [0; 32],
        sign(payment, &body.signing_message()),
    )
    .unwrap();
    let package = KagemushaWalletPackageV1::new(
        statement,
        KagemushaWalletLineageSlotV1::None,
        capsule.step_proof.clone(),
        receipt,
    );
    let output = norito::encode_canonical(&package).unwrap();
    let record = KagemushaWalletCompletionRecordV1::new(&capsule, receipt, output).unwrap();
    record.verify(&credential, &capsule).unwrap();
    ReleasedStep {
        retained: Retained {
            selected_generation: 1,
            operation_id: capsule.operation_id,
            capsule_digest: capsule.capsule_digest().unwrap(),
            completion_digest: record.completion_digest().unwrap(),
            frame: record.to_canonical_bytes().unwrap(),
            record,
        },
        frozen: FrozenTransition {
            credential,
            capsule,
        },
    }
}

// Resign each update for the freshly generated engineering scheme before any
// proof is made. This creates independent originals; it never changes a proved
// receipt, proof or fixture file and cannot stand in for a finalized catalog.
fn rebase_update(
    mut source: Source,
    scheme: KagemushaWalletSchemeV1,
    current: KagemushaWalletCredentialV1,
    state: KagemushaWalletStateV1,
) -> Source {
    let kind = source.originals().kind;
    source.scheme = scheme;
    source.current = current;
    source.successor = current;
    source.state = state;
    source.certificate = certificate(&scheme, &source.signing, source.certificate.body.role);
    let cert = &source.certificate;
    let original = source.complete_original();
    let bytes = match kind {
        Kind::Credential => {
            let previous: KagemushaWalletCredentialV1 = norito::decode_canonical(original).unwrap();
            let mut body = current.body;
            body.issuer_certificate = cert.certificate_digest();
            body.renewal_sequence += 1;
            body.issued_at_ms = previous.body.issued_at_ms;
            body.lease_expires_at_ms = previous.body.lease_expires_at_ms;
            let next = KagemushaWalletCredentialV1::sign(
                body,
                cert,
                sign(&source.signing, &body.signing_message()),
            )
            .unwrap();
            source.successor = next;
            next.to_canonical_bytes().unwrap()
        }
        Kind::SchemePolicy => {
            let old: KagemushaWalletSchemePolicyV1 = norito::decode_canonical(original).unwrap();
            let mut body = old.body;
            body.scheme_id = scheme.scheme_id();
            body.asset_digest = current.body.asset_digest;
            body.signer_certificate = cert.certificate_digest();
            KagemushaWalletSchemePolicyV1::sign(
                body,
                cert,
                sign(&source.signing, &body.signing_message()),
            )
            .unwrap()
            .to_canonical_bytes()
            .unwrap()
        }
        Kind::Blacklist => {
            let old: KagemushaWalletBlacklistV1 = norito::decode_canonical(original).unwrap();
            let mut body = old.body;
            body.scheme_id = scheme.scheme_id();
            body.signer_certificate = cert.certificate_digest();
            KagemushaWalletBlacklistV1::sign(
                body,
                old.entries,
                cert,
                sign(&source.signing, &body.signing_message()),
            )
            .unwrap()
            .to_canonical_bytes()
            .unwrap()
        }
        Kind::QuotaShare => {
            let old: KagemushaWalletQuotaShareV1 = norito::decode_canonical(original).unwrap();
            let mut body = old.body;
            body.scheme_id = scheme.scheme_id();
            body.wallet_id = current.body.wallet_id;
            body.asset_digest = current.body.asset_digest;
            body.signer_certificate = cert.certificate_digest();
            KagemushaWalletQuotaShareV1::sign(
                body,
                old.windows,
                cert,
                sign(&source.signing, &body.signing_message()),
            )
            .unwrap()
            .to_canonical_bytes()
            .unwrap()
        }
        Kind::TimeAnchor => {
            let old: KagemushaWalletTimeAnchorV1 = norito::decode_canonical(original).unwrap();
            let mut body = old.body;
            body.scheme_id = scheme.scheme_id();
            body.wallet_id = current.body.wallet_id;
            body.signer_certificate = cert.certificate_digest();
            KagemushaWalletTimeAnchorV1::sign(
                body,
                cert,
                sign(&source.signing, &body.signing_message()),
            )
            .unwrap()
            .to_canonical_bytes()
            .unwrap()
        }
    };
    if kind == Kind::Blacklist {
        *source.original() =
            crate::kagemusha_wallet_state_v1::BlacklistOriginalReferenceV1::for_original(
                &source.scheme.scheme_id(),
                &bytes,
            )
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        source.complete_blacklist = Some(bytes);
    } else {
        *source.original() = bytes;
    }
    source
        .capsule
        .retained_inputs
        .iter_mut()
        .find(|input| input.role == InputRole::CertificateSet)
        .unwrap()
        .bytes =
        norito::to_bytes(&KagemushaWalletCertificateSetV1::new(vec![source.certificate]).unwrap())
            .unwrap();
    source
}

#[test]
#[ignore = "actual installed sigma/receipt preparation; run optimized explicitly"]
fn installed_public_refresh_proves_all_five_updates_and_rejects_resigned_bad_sigma() {
    let params = PinnedParams::<Eq>::derive(12).unwrap();
    let blank = BootstrapWitness {
        core: [Fp::ZERO; 33],
        rest: [Fp::ZERO; 8],
        lineage: [Fp::ZERO; 18],
        statement: [Fp::ZERO; 26],
    };
    let bootstrap_key = key(BootstrapCircuit::new(&blank), &params);
    let decoded = Source::policy().decode().unwrap();
    let state_blank = StateWitness {
        core: blank.core,
        rest: blank.rest,
        lineage: blank.lineage,
    };
    let refresh_key = key(
        RefreshCircuit::new(&RefreshWitness {
            predecessor: state_blank,
            successor: state_blank,
            statement: blank.statement,
            update: decoded.projection,
        }),
        &params,
    );
    let (pack, installation) = signed_inventory_with_step_originals(vec![
        original(&bootstrap_key, Operation::Bootstrap),
        original(&refresh_key, Operation::RefreshPolicy),
    ]);
    let installed =
        InstalledVerifierPackV1::load(&pack.to_canonical_bytes().unwrap(), installation).unwrap();
    let preparation = PreparationV1::new(&installed).unwrap();
    let scheme = *installed.verifier().scheme();
    let issuer = SigningKey::from_slice(&[0x12; 32]).unwrap();
    let payment = SigningKey::from_slice(&[0x23; 32]).unwrap();
    let enrollment = certificate(&scheme, &issuer, Role::Enrollment);
    let credential = credential(&scheme, &issuer, &enrollment, &payment);
    let owner = preparation
        .authenticate_credential(
            &credential.to_canonical_bytes().unwrap(),
            &enrollment.to_canonical_bytes().unwrap(),
        )
        .unwrap();
    let enrollment_set = KagemushaWalletCertificateSetV1::new(vec![enrollment.clone()]).unwrap();
    let enrollment_set_bytes = norito::to_bytes(&enrollment_set).unwrap();
    let set_owner = preparation
        .authenticate_credential_set(
            &credential.to_canonical_bytes().unwrap(),
            &enrollment_set_bytes,
        )
        .unwrap();
    assert_eq!(set_owner.credential(), owner.credential());
    assert!(
        preparation
            .authenticate_credential_set(
                &credential.to_canonical_bytes().unwrap(),
                &enrollment.to_canonical_bytes().unwrap(),
            )
            .is_err()
    );
    let foreign_set =
        KagemushaWalletCertificateSetV1::new(vec![certificate(&scheme, &issuer, Role::TimeAnchor)])
            .unwrap();
    assert!(
        preparation
            .authenticate_credential_set(
                &credential.to_canonical_bytes().unwrap(),
                &norito::to_bytes(&foreign_set).unwrap(),
            )
            .is_err()
    );
    let state = KagemushaWalletStateV1::bootstrap(&credential, Fp::from(101).to_repr()).unwrap();
    let statement = KagemushaWalletStatementV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        relation_id: scheme.relation_id,
        credential_digest: credential.credential_digest(),
        asset_digest: credential.body.asset_digest,
        lifecycle: state.core.lifecycle,
        sequence: 0,
        next_load: 0,
        enabled_controls: 0,
        lineage_burned_total: 0,
        lineage_pending_outgoing_root: [0; 32],
        predecessor: KagemushaWalletStateCommitmentV1::ZERO,
        successor: state.commitment().unwrap(),
        effect: KagemushaWalletEffectV1::Bootstrap {
            enrollment_id: credential.body.enrollment_id,
            enrollment_marker: [7; 32],
        },
    };
    let public = KagemushaWalletLineagePublicV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        relation_id: scheme.relation_id,
        head: statement.successor,
        wallet_id: credential.body.wallet_id,
        credential_digest: credential.credential_digest(),
        payment_key: credential.body.payment_key,
        lifecycle: state.core.lifecycle,
        policy_epoch: 0,
        enabled_controls: 0,
        burned_total: 0,
        pending_outgoing_root: state.core.pending_outgoing_root,
        credit_digest_root: kagemusha_wallet_empty_map_root_v1(),
    };
    let bytes = bootstrap_key.artifact_bytes_v2().unwrap();
    let bootstrap = BootstrapProver::from_original_artifact(
        params.clone(),
        bootstrap_key.binding().encoded(),
        bootstrap_key.vk().to_bytes(),
        &bytes,
        read_config(&bytes),
    )
    .unwrap();
    let bytes = refresh_key.artifact_bytes_v2().unwrap();
    let refresh = RefreshProver::from_original_artifact(
        params,
        refresh_key.binding().encoded(),
        refresh_key.vk().to_bytes(),
        &bytes,
        read_config(&bytes),
    )
    .unwrap();
    drop((bootstrap_key, refresh_key, bytes));
    let witness = preparation
        .bootstrap_sigma_fields(&owner, &state, &statement, &public)
        .unwrap();
    let sigma = preparation
        .prove_bootstrap_sigma(
            &owner,
            &witness,
            &statement,
            &bootstrap,
            ProverRandomness::hedged(),
            MemoryBudget::DEFAULT,
        )
        .unwrap();
    let released = release(credential, state, statement, sigma, &payment);
    preparation
        .receipt_tape(&owner, &released, MemoryBudget::DEFAULT)
        .unwrap();
    preparation.assert_incoming_restoration_boundary(&owner, &released, &payment);
    for source in [
        Source::credential(),
        Source::policy(),
        Source::blacklist(),
        Source::quota(),
        Source::anchor(),
    ] {
        let source = rebase_update(source, scheme, credential, state);
        let next = if source.successor == credential {
            preparation
                .authenticate_credential(
                    &credential.to_canonical_bytes().unwrap(),
                    &enrollment.to_canonical_bytes().unwrap(),
                )
                .unwrap()
        } else {
            preparation
                .authenticate_credential(
                    &source.successor.to_canonical_bytes().unwrap(),
                    &source.certificate.to_canonical_bytes().unwrap(),
                )
                .unwrap()
        };
        let step = preparation
            .prepare_refresh(
                RefreshOwnersV1 {
                    current: &owner,
                    successor: &next,
                },
                &released,
                source.originals(),
                Fp::from(102).to_repr(),
                MemoryBudget::DEFAULT,
            )
            .unwrap();
        assert_eq!(
            step.source_capsule_digest(),
            released.retained.capsule_digest
        );
        assert_eq!(step.state().core.sequence, 1);
        let proof = preparation
            .prove_refresh_sigma(
                &next,
                &step,
                &refresh,
                ProverRandomness::hedged(),
                MemoryBudget::DEFAULT,
            )
            .unwrap();
        assert!(!proof.bytes.is_empty());
        let frozen = preparation
            .freeze_refresh(&next, &step, proof.clone(), MemoryBudget::DEFAULT)
            .unwrap();
        assert_eq!(frozen.credential, source.successor);
        assert_eq!(frozen.capsule.successor_state, *step.state());
        assert_eq!(frozen.capsule.statement, *step.statement());
        assert_eq!(
            frozen.capsule.predecessor_capsule_digest,
            released.retained.capsule_digest
        );
        assert_eq!(frozen.capsule.retained_inputs, step.originals().0);
        assert_eq!(frozen.capsule.map_openings, step.originals().1);
        assert_eq!(frozen.capsule.step_proof, proof);
        assert!(frozen.capsule.predecessor_lineage().is_none());
        let mut invalid = proof.clone();
        invalid.bytes[32] ^= 1;
        assert!(
            preparation
                .freeze_refresh(&next, &step, invalid, MemoryBudget::DEFAULT)
                .is_err()
        );
        if source.successor != credential {
            assert!(
                preparation
                    .freeze_refresh(&owner, &step, proof.clone(), MemoryBudget::DEFAULT)
                    .is_err()
            );
        }
        eprintln!(
            "INSTALLED_REFRESH kind={:?} sigma_bytes={} sequence=1 real_source_import=true real_retained_receipt=true recursive_admission=false",
            source.originals().kind,
            proof.bytes.len()
        );
        if source.successor != credential {
            assert!(
                preparation
                    .prepare_refresh(
                        RefreshOwnersV1 {
                            current: &owner,
                            successor: &owner,
                        },
                        &released,
                        source.originals(),
                        Fp::from(102).to_repr(),
                        MemoryBudget::DEFAULT,
                    )
                    .is_err(),
                "renewal must select its exact authenticated successor credential"
            );
        }
        let mut wrong = released.clone();
        wrong.retained.frame[0] ^= 1;
        assert!(
            preparation
                .prepare_refresh(
                    RefreshOwnersV1 {
                        current: &owner,
                        successor: &next
                    },
                    &wrong,
                    source.originals(),
                    Fp::from(102).to_repr(),
                    MemoryBudget::DEFAULT,
                )
                .is_err()
        );
        let mut sigma = released.frozen.capsule.step_proof.clone();
        sigma.bytes[32] ^= 1;
        let resigned = release(credential, state, statement, sigma, &payment);
        assert!(
            preparation
                .prepare_refresh(
                    RefreshOwnersV1 {
                        current: &owner,
                        successor: &next
                    },
                    &resigned,
                    source.originals(),
                    Fp::from(102).to_repr(),
                    MemoryBudget::DEFAULT,
                )
                .is_err(),
            "valid signature and rehashed capsule must not admit an invalid predecessor sigma"
        );
    }
    let foreign = Source::policy();
    assert!(
        preparation
            .prepare_refresh(
                RefreshOwnersV1 {
                    current: &owner,
                    successor: &owner,
                },
                &released,
                foreign.originals(),
                Fp::from(102).to_repr(),
                MemoryBudget::DEFAULT,
            )
            .is_err(),
        "a correctly signed policy from another scheme is not an installed update"
    );
}
