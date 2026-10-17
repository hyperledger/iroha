// Single-dispatch tests of the Exact12 roles. Included in `privacy_verifier::tests`.
//
// The role samples are structurally valid envelopes with placeholder proofs. They pass envelope
// and activation validation and are never accepted by a native verifier, so they show which
// verifier arm, or which typed refusal, each role reaches without running a prover.

/// Dispatch context of one role sample: its own network, height 2, no trusted state.
fn role_sample_context(
    sample: &iroha_data_model::privacy::PrivacyActionRoleSampleV1,
) -> PrivacyVerificationContextV1<'_> {
    let statement_context = sample.envelope.statement.context();
    PrivacyVerificationContextV1 {
        activation: &sample.activation,
        consensus_limits: &TEST_CONSENSUS_LIMITS,
        network_id: &statement_context.network_id,
        genesis_hash: *statement_context.network_id.as_bytes(),
        current_height: 2,
        expected_action_index: statement_context.action_index,
        block_timestamp_ms: 1_800_000_000_000,
        pgc_state: None,
        orchard_state: None,
        proof_managed_state: None,
        zk_x509_state: None,
        bootle_lantern_policy: None,
        vega_issuer_record: None,
    }
}

fn role_samples() -> Vec<iroha_data_model::privacy::PrivacyActionRoleSampleV1> {
    iroha_data_model::privacy::privacy_action_role_samples_v1().expect("Exact12 role samples")
}

fn role_sample(role: PrivacyActionRoleV1) -> iroha_data_model::privacy::PrivacyActionRoleSampleV1 {
    role_samples()
        .into_iter()
        .find(|sample| sample.role == role)
        .expect("a sample exists for every role")
}

/// The protocol whose native verifier arm produced `error`, if it came from one.
fn verifier_arm_of(error: &PrivacyVerificationErrorV1) -> Option<PrivacyProtocolIdV1> {
    use PrivacyProtocolIdV1 as Protocol;
    use PrivacyVerificationErrorV1 as Error;
    Some(match error {
        Error::NativeVeRange(_) => Protocol::VeRangeTransparentRangeV1,
        Error::NativeJindo(_) => Protocol::IrohaJindoPolynomialCommitmentV1,
        Error::VegaState(_) | Error::NativeVega(_) => Protocol::VegaExistingCredentialZkV1,
        #[cfg(feature = "zk-stark")]
        Error::NativeZkAce(_) => Protocol::ZkAcePqAuthorizationV1,
        Error::NativeZkAms(_) => Protocol::IrohaZkAmsV1,
        Error::ZkX509State(_) | Error::NativeZkX509(_) => Protocol::IrohaZkX509StarkP256V1,
        Error::OrchardState(_) | Error::NativeOrchard(_) => Protocol::OrchardHalo2ActionsV1,
        Error::FcmpState(_) | Error::NativeFcmp(_) => Protocol::MoneroFcmpPlusPlusV1,
        Error::IvmPrivateNoteState(_) | Error::NativeIvmPrivateNote(_) => {
            Protocol::IrohaIvmPrivateNoteStarkV1
        }
        Error::PqMaspState(_) | Error::NativePqMasp(_) => Protocol::PqMaspStarkV1,
        Error::AnonymousPgcState(_) | Error::NativeAnonymousPgc(_) => {
            Protocol::AnonymousPgcKOutOfNV1
        }
        Error::BootleLanternState(_) | Error::NativeBootleLantern(_) => {
            Protocol::IrohaBootleLanternAnoncredV1
        }
        Error::Context(_)
        | Error::CompiledActivation(_)
        | Error::Envelope(_)
        | Error::UnsupportedOperation(_)
        | Error::EffectRoleMismatch(_)
        | Error::CanonicalEncoding(_) => return None,
    })
}

/// Every role enters the one dispatch and leaves it either through the native
/// verifier of its own protocol or through the typed refusal of the registry.
#[test]
fn every_role_reaches_its_own_native_verifier_or_its_typed_refusal() {
    use crate::privacy_dispatch::{PrivacyRoleVerificationV1, privacy_role_dispatch_row_v1};
    let samples = role_samples();
    assert_eq!(
        samples.iter().map(|sample| sample.role).collect::<Vec<_>>(),
        PrivacyActionRoleV1::ALL
    );
    for sample in &samples {
        let result = verify_privacy_envelope_after_compiled_activation_v1(
            &sample.envelope,
            &role_sample_context(sample),
        );
        match privacy_role_dispatch_row_v1(sample.role).verification {
            PrivacyRoleVerificationV1::Unsupported(limitation) => {
                let Err(PrivacyVerificationErrorV1::UnsupportedOperation(refusal)) = result else {
                    panic!(
                        "{}: expected the typed refusal, got {result:?}",
                        sample.role
                    );
                };
                assert_eq!(
                    *refusal,
                    PrivacyUnsupportedOperationV1::new(sample.role, limitation)
                );
            }
            PrivacyRoleVerificationV1::Implemented => {
                let error = result.expect_err("a placeholder proof is never accepted");
                assert_eq!(
                    verifier_arm_of(&error),
                    Some(sample.role.protocol_id()),
                    "{}: left the dispatch through {error:?}",
                    sample.role
                );
            }
        }
    }
}

/// The typed refusal is the fifth check: compiled activation, envelope, trusted
/// context and canonical byte charging all precede it, and it precedes every
/// native verifier.
#[test]
fn unsupported_refusal_keeps_its_place_in_the_failure_precedence() {
    let refused = role_sample(PrivacyActionRoleV1::ZkAceAuthorization);
    let other = role_sample(PrivacyActionRoleV1::VeRangeRange);

    // Through the public entry the compiled-activation check comes first: the
    // sample activation is not the compiled profile of this binary.
    assert!(matches!(
        verify_privacy_envelope_v1(&refused.envelope, &role_sample_context(&refused)),
        Err(PrivacyVerificationErrorV1::CompiledActivation(_))
    ));

    // Envelope validity precedes the registry.
    let mut foreign_proof = refused.envelope.clone();
    foreign_proof.proof = other.envelope.proof.clone();
    assert!(matches!(
        verify_privacy_envelope_after_compiled_activation_v1(
            &foreign_proof,
            &role_sample_context(&refused)
        ),
        Err(PrivacyVerificationErrorV1::Envelope(_))
    ));

    // The trusted context precedes the registry.
    let mut wrong_index = role_sample_context(&refused);
    wrong_index.expected_action_index = 1;
    assert!(matches!(
        verify_privacy_envelope_after_compiled_activation_v1(&refused.envelope, &wrong_index),
        Err(PrivacyVerificationErrorV1::Context(detail))
            if detail.code == PrivacyVerificationContextFailureCodeV1::ActionIndexMismatch
    ));
    let mut zero_genesis = role_sample_context(&refused);
    zero_genesis.genesis_hash = [0; 32];
    assert!(matches!(
        verify_privacy_envelope_after_compiled_activation_v1(&refused.envelope, &zero_genesis),
        Err(PrivacyVerificationErrorV1::Context(detail))
            if detail.code == PrivacyVerificationContextFailureCodeV1::ZeroGenesisHash
    ));

    // With everything else valid the registry refuses before the native verifier.
    assert!(matches!(
        verify_privacy_envelope_after_compiled_activation_v1(
            &refused.envelope,
            &role_sample_context(&refused)
        ),
        Err(PrivacyVerificationErrorV1::UnsupportedOperation(_))
    ));
}

/// No protocol, statement or proof of one role reaches a verifier under another role.
#[test]
fn dispatch_rejects_substitution_between_every_pair_of_roles_before_any_verifier() {
    let samples = role_samples();
    for own in &samples {
        for other in &samples {
            if own.role == other.role {
                continue;
            }
            let mut substituted = Vec::new();
            let mut foreign_proof = own.envelope.clone();
            foreign_proof.proof = other.envelope.proof.clone();
            substituted.push(("proof", foreign_proof));
            let mut foreign_statement = own.envelope.clone();
            foreign_statement.statement = other.envelope.statement.clone();
            foreign_statement.statement_digest = other.envelope.statement_digest;
            substituted.push(("statement", foreign_statement));
            if own.role.protocol_id() != other.role.protocol_id() {
                let mut relabelled = own.envelope.clone();
                relabelled.protocol_id = other.envelope.protocol_id;
                relabelled.proof_system_id = other.envelope.proof_system_id;
                relabelled.engine_id = other.envelope.engine_id;
                substituted.push(("protocol", relabelled));
            }
            for (what, envelope) in substituted {
                assert!(
                    envelope.action_role_v1().is_err(),
                    "{} with the {what} of {} still resolves to a role",
                    own.role,
                    other.role
                );
                for activation in [&own.activation, &other.activation] {
                    let mut context = role_sample_context(own);
                    context.activation = activation;
                    let error =
                        verify_privacy_envelope_after_compiled_activation_v1(&envelope, &context)
                            .expect_err("a substituted envelope is never verified");
                    assert!(
                        matches!(error, PrivacyVerificationErrorV1::Envelope(_)),
                        "{} with the {what} of {}: {error:?}",
                        own.role,
                        other.role
                    );
                }
            }
        }
    }
}

/// A proof-managed note effect over the bootstrap head of `snapshot`.
fn note_pool_effect(
    snapshot: &PrivacyProofManagedPoolSnapshotV1,
    asset_definition_id: AssetDefinitionId,
    nullifiers: &[PrivacyNullifierV1],
    output_commitments: &[PrivacyCommitmentV1],
    transition: fn(
        Vec<PrivacyNullifierV1>,
        Vec<PrivacyCommitmentV1>,
        PrivacyProofManagedAccumulatorStateV1,
    ) -> VerifiedProofManagedPoolTransitionV1,
) -> VerifiedPrivacyLedgerEffectsV1 {
    let successor = snapshot
        .derive_note_successor(output_commitments)
        .expect("note successor");
    VerifiedPrivacyLedgerEffectsV1::ProofManagedPool(VerifiedProofManagedPoolLedgerEffectV1 {
        namespace: snapshot.namespace(),
        bootstrap_digest: snapshot.bootstrap_digest(),
        asset_definition_id,
        current_root: snapshot.current_root(),
        current_epoch: snapshot.current_epoch(),
        next_root: successor.root(),
        next_epoch: successor.epoch(),
        transition: transition(nullifiers.to_vec(), output_commitments.to_vec(), successor),
        value_balance: None,
        public_balance_scope: None,
    })
}

/// Ledger effects with the one role each may discharge. `None` marks the
/// verify-only effect, which every verify-only role shares.
fn constructed_effects() -> Vec<(Option<PrivacyActionRoleV1>, VerifiedPrivacyLedgerEffectsV1)> {
    let mut effects = vec![(None, VerifiedPrivacyLedgerEffectsV1::None)];

    let ace = role_sample(PrivacyActionRoleV1::ZkAceAuthorization);
    let PrivacyStatementV1::ZkAcePqAuthorizationV1(statement) = &ace.envelope.statement else {
        unreachable!("ZK-ACE sample")
    };
    effects.push((
        Some(PrivacyActionRoleV1::ZkAceAuthorization),
        VerifiedPrivacyLedgerEffectsV1::ZkAceAuthorization(VerifiedZkAceAuthorizationV1 {
            policy_id: statement.policy_id,
            policy_digest: statement.policy_digest,
            identity_commitment: statement.identity_commitment,
            authorization_epoch: statement.authorization_epoch,
            source: statement.source.clone(),
            destination: statement.destination.clone(),
            asset_definition_id: statement.asset_definition_id.clone(),
            public_balance_scope: statement.public_balance_scope,
            amount: statement.amount,
            replay_nullifier: statement.replay_nullifier,
        }),
    ));

    for role in [
        PrivacyActionRoleV1::ZkAmsBatchAdmission,
        PrivacyActionRoleV1::ZkAmsProvisionAccount,
    ] {
        let sample = role_sample(role);
        let PrivacyStatementV1::IrohaZkAmsV1(statement) = &sample.envelope.statement else {
            unreachable!("ZK-AMS sample")
        };
        let effect = match &statement.action {
            PrivacyZkAmsActionV1::BatchAdmission(batch) => {
                VerifiedPrivacyLedgerEffectsV1::ZkAmsBatchAdmission(VerifiedZkAmsBatchAdmissionV1 {
                    issuer_id: statement.issuer_id,
                    policy_id: statement.policy_id,
                    policy_digest: statement.policy_digest,
                    issuer_policy_record_digest: statement.issuer_policy_record_digest,
                    registry_id: statement.registry_id,
                    registry_record_digest: statement.registry_record_digest,
                    current_root: batch.account_registry_root,
                    current_epoch: batch.account_registry_root_epoch,
                    next_root: batch.next_account_registry_root,
                    next_epoch: batch.next_account_registry_root_epoch,
                    anchors: batch.anchors.clone(),
                })
            }
            PrivacyZkAmsActionV1::ProvisionAccount(provision) => {
                VerifiedPrivacyLedgerEffectsV1::ZkAmsProvisionAccount(
                    VerifiedZkAmsProvisionAccountV1 {
                        issuer_id: statement.issuer_id,
                        policy_id: statement.policy_id,
                        policy_digest: statement.policy_digest,
                        issuer_policy_record_digest: statement.issuer_policy_record_digest,
                        registry_id: statement.registry_id,
                        registry_record_digest: statement.registry_record_digest,
                        current_root: provision.account_registry_root,
                        current_epoch: provision.account_registry_root_epoch,
                        ring: provision.admitted_seed_key_ring.clone(),
                        account_id: provision.account_id.clone(),
                        key_image: provision.key_image,
                    },
                )
            }
        };
        effects.push((Some(role), effect));
    }

    let x509 = role_sample(PrivacyActionRoleV1::ZkX509CertificatePresentation);
    let PrivacyStatementV1::IrohaZkX509StarkP256V1(statement) = &x509.envelope.statement else {
        unreachable!("ZK-X509 sample")
    };
    effects.push((
        Some(PrivacyActionRoleV1::ZkX509CertificatePresentation),
        VerifiedPrivacyLedgerEffectsV1::ZkX509Certificate(VerifiedZkX509CertificateEffectV1 {
            namespace: PrivacyNamespaceV1::from_statement(&x509.envelope.statement),
            certificate_nullifier: statement.certificate_nullifier,
            trust_anchor_record_digest:
                iroha_data_model::privacy::PrivacyZkX509TrustAnchorRecordDigestV1::new([0x11; 32]),
            trust_anchor_record_epoch: 1,
            certificate_policy_record_digest:
                iroha_data_model::privacy::PrivacyZkX509CertificatePolicyRecordDigestV1::new(
                    [0x12; 32],
                ),
            certificate_policy_record_epoch: 1,
            crl_record_digest: iroha_data_model::privacy::PrivacyZkX509CrlRecordDigestV1::new(
                [0x13; 32],
            ),
            crl_record_epoch: 1,
        }),
    ));

    let private_note = IvmPrivateNotePreflightFixture::new();
    effects.push((
        Some(PrivacyActionRoleV1::IvmPrivateNoteTransition),
        note_pool_effect(
            &private_note.snapshot,
            private_note.statement.asset_definition_id.clone(),
            &private_note.statement.nullifiers,
            &private_note.statement.output_commitments,
            |nullifiers, output_commitments, successor_state| {
                VerifiedProofManagedPoolTransitionV1::IvmPrivateNote {
                    nullifiers,
                    output_commitments,
                    successor_state,
                }
            },
        ),
    ));
    let pq_masp = PqMaspPreflightFixture::new();
    effects.push((
        Some(PrivacyActionRoleV1::PqMaspTransition),
        note_pool_effect(
            &pq_masp.snapshot,
            pq_masp.statement.asset_definition_id.clone(),
            &pq_masp.statement.nullifiers,
            &pq_masp.statement.output_commitments,
            |nullifiers, output_commitments, successor_state| {
                VerifiedProofManagedPoolTransitionV1::PqMasp {
                    nullifiers,
                    output_commitments,
                    successor_state,
                }
            },
        ),
    ));
    effects
}

/// Assert that `effect` can be sealed for exactly the roles it belongs to.
fn assert_effect_seals_only_for_its_role(
    owner: Option<PrivacyActionRoleV1>,
    effect: &VerifiedPrivacyLedgerEffectsV1,
) {
    use crate::privacy_dispatch::{PrivacyRoleEffectClassV1, privacy_role_dispatch_row_v1};
    let digest = PrivacyStatementDigestV1::new([0x77; 32]);
    for role in PrivacyActionRoleV1::ALL {
        let belongs = match owner {
            Some(owner) => owner == role,
            None => {
                privacy_role_dispatch_row_v1(role).effect_class
                    == PrivacyRoleEffectClassV1::VerifyOnly
            }
        };
        assert_eq!(effect.discharges_role_v1(role), belongs, "{role}");
        match VerifiedPrivacyEffectsV1::seal_v1(role, digest, 3, 77, effect.clone()) {
            Ok(sealed) => {
                assert!(belongs, "{role}: sealed a foreign effect");
                assert_eq!(sealed.role(), role);
                assert_eq!(sealed.protocol_id(), role.protocol_id());
                assert_eq!(sealed.statement_digest(), digest);
                assert_eq!(sealed.action_index(), 3);
                assert_eq!(sealed.encoded_action_bytes(), 77);
                assert_eq!(sealed.ledger(), effect);
            }
            Err(PrivacyVerificationErrorV1::EffectRoleMismatch(mismatch)) => {
                assert!(!belongs, "{role}: refused its own effect");
                assert_eq!(mismatch.role, role);
            }
            Err(other) => panic!("{role}: unexpected sealing failure {other:?}"),
        }
    }
}

/// An effect of another role cannot leave the verifier: the only constructor of
/// verified effects refuses it. The proof-managed class is shared by three
/// protocols and is still told apart by its transition.
#[test]
fn sealed_effects_carry_only_the_effect_of_their_own_role() {
    let effects = constructed_effects();
    let owners = effects
        .iter()
        .filter_map(|(owner, _)| *owner)
        .collect::<Vec<_>>();
    assert_eq!(
        owners,
        [
            PrivacyActionRoleV1::ZkAceAuthorization,
            PrivacyActionRoleV1::ZkAmsBatchAdmission,
            PrivacyActionRoleV1::ZkAmsProvisionAccount,
            PrivacyActionRoleV1::ZkX509CertificatePresentation,
            PrivacyActionRoleV1::IvmPrivateNoteTransition,
            PrivacyActionRoleV1::PqMaspTransition,
        ]
    );
    for (owner, effect) in &effects {
        assert_effect_seals_only_for_its_role(*owner, effect);
    }
}

/// Real proofs: the effect of every verified envelope carries the role of that
/// envelope, and belongs to no other role.
#[test]
fn verified_real_proofs_seal_the_role_of_their_envelope() {
    let (verange, verange_activation, verange_network) = valid_envelope();
    let verange_effects = verify_privacy_envelope_v1(
        &verange,
        &verification_context(&verange_activation, &verange_network),
    )
    .expect("valid VeRange proof");
    let pgc = PgcFixture::new();
    let pgc_effects = verify_privacy_envelope_v1(&pgc.envelope, &pgc.verification_context())
        .expect("valid PGC payment");
    let jindo = jindo_fixture();
    let jindo_effects = verify_privacy_envelope_v1(
        &jindo.envelope,
        &jindo.verification_context(&TEST_CONSENSUS_LIMITS),
    )
    .expect("valid Jindo evaluation");
    let orchard = orchard_fixture();
    let orchard_effects =
        verify_privacy_envelope_v1(&orchard.envelope, &orchard.verification_context())
            .expect("valid Orchard bundle");
    let fcmp = fcmp_fixture();
    let fcmp_effects = verify_privacy_envelope_v1(
        &fcmp.envelope,
        &fcmp.verification_context(Some(&fcmp.snapshot)),
    )
    .expect("valid FCMP++ transaction");

    for (envelope, effects, role) in [
        (&verange, verange_effects, PrivacyActionRoleV1::VeRangeRange),
        (
            &pgc.envelope,
            pgc_effects,
            PrivacyActionRoleV1::AnonymousPgcPayment,
        ),
        (
            &jindo.envelope,
            jindo_effects,
            PrivacyActionRoleV1::JindoBatchedEvaluation,
        ),
        (
            &orchard.envelope,
            orchard_effects,
            PrivacyActionRoleV1::OrchardActions,
        ),
        (
            &fcmp.envelope,
            fcmp_effects,
            PrivacyActionRoleV1::FcmpTransfer,
        ),
    ] {
        assert_eq!(envelope.action_role_v1(), Ok(role));
        assert_eq!(effects.role(), role);
        assert_eq!(effects.protocol_id(), role.protocol_id());
        assert_eq!(effects.statement_digest(), envelope.statement_digest);
        let owner = (effects.ledger() != &VerifiedPrivacyLedgerEffectsV1::None).then_some(role);
        assert_effect_seals_only_for_its_role(owner, effects.ledger());
    }
}

/// A builder that selected a compiled profile accepts exactly the canonical
/// envelopes whose statements were built from that profile.
#[test]
fn compiled_profile_matches_only_envelopes_bound_from_its_own_statements() {
    let (envelope, _, _) = valid_envelope();
    let profile = compiled_privacy_profile_v1(PrivacyProtocolIdV1::VeRangeTransparentRangeV1)
        .expect("compiled VeRange profile");
    assert!(profile.matches_envelope_v1(&envelope));
    // The fixture envelope is the canonical binding of its own statement and proof.
    assert_eq!(
        PrivacyProofEnvelopeV1::bind_v1(envelope.statement.clone(), envelope.proof.clone())
            .as_ref(),
        Ok(&envelope)
    );
    let mutations: [fn(&mut PrivacyProofEnvelopeV1); 5] = [
        |envelope| envelope.parameter_id.0[0] ^= 1,
        |envelope| envelope.parameter_digest.0[0] ^= 1,
        |envelope| envelope.verifier_digest.0[0] ^= 1,
        |envelope| envelope.statement_schema_digest.0[0] ^= 1,
        |envelope| envelope.engine_manifest_digest.0[0] ^= 1,
    ];
    for mutate in mutations {
        let mut changed = envelope.clone();
        mutate(&mut changed);
        assert!(!profile.matches_envelope_v1(&changed));
    }
    // A statement built from other identities binds to an envelope the profile refuses.
    let sample = role_sample(PrivacyActionRoleV1::VeRangeRange);
    assert_eq!(sample.envelope.protocol_id, profile.protocol_id);
    assert!(!profile.matches_envelope_v1(&sample.envelope));
    let other = compiled_privacy_profile_v1(PrivacyProtocolIdV1::IrohaJindoPolynomialCommitmentV1)
        .expect("compiled Jindo profile");
    assert!(!other.matches_envelope_v1(&envelope));
}
