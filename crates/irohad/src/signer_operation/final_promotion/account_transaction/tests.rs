//! Native execution/finality tests for exact prepared account authority; no deployed-readiness claim.

use super::super::observer_transaction::{
    FinalPromotionObserverTransactionErrorV1 as ObserverError, FinalPromotionObserverTransactionsV1,
};
use super::*;
use iroha_core::query::{
    final_promotion_account_custody::{
        observation::{
            FinalPromotionAccountCheckExpectedV1, FinalPromotionAccountCheckFloorV1,
            PreparedFinalPromotionAccountCheckV1, begin_final_promotion_account_check_v1,
        },
        read_final_promotion_account_custody_at_v1,
    },
    final_promotion_authority::{
        observation::{
            FinalPromotionCheckExpectedV1, FinalPromotionCheckFloorV1, FinalPromotionCheckSourceV1,
            PreparedFinalPromotionCheckV1, begin_final_promotion_check_v1,
        },
        read_final_promotion_authority_at_v1,
    },
    signer_check_test_fixture::NativeCheckTestFixtureV1,
};
use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::{
    isi::InstructionBox,
    isi::sorafs::MutateSorafsFinalPromotionAccountCustody,
    sorafs::final_promotion_account_custody::FinalPromotionAccountCustodyActionV1,
    transaction::{SignedTransaction, TransactionBuilder, TransactionDomain},
};
use sorafs_manifest::signer::{
    custody::{SignerCustodyAuthorityV1, SignerCustodyRecordV1, SignerCustodyStatementV1},
    custody_control::SignerCustodyPolicyV1,
    final_promotion::{
        SIGNER_FINAL_PROMOTION_RECEIPT_MAGIC_V1, SignerFinalPromotionRequestV1,
        signer_final_promotion_audit_v1, signer_final_promotion_response_digest_v1,
    },
    protocol::{
        SignerKeyOperationPurposeV1, SignerOperationCommitmentV1, SignerOperationSignatureV1,
        signer_operation_message_digest_v1,
    },
    receipt::SignerOperationProvenanceV1,
};
use std::{fs, os::unix::fs::PermissionsExt as _, time::Duration};

mod current_observation;
mod observer_signing;
mod software_key;

mod statements {
    use sorafs_manifest as manifest;
    include!(
        "../../../../../sorafs_manifest/src/signer/final_promotion/tests/statement_fixture_support.rs"
    );
}
const DEPLOYMENT: &str = "promotion-primary";
const NOW: u64 = 3_000;
/// The observers' clock: after every fixture block. Transactions are created at `NOW` and each
/// certified block is strictly after its parent and its transactions, so the fixture's blocks
/// occupy `NOW + 1`, `NOW + 2`, … and an observation must not precede them.
const OBSERVED: u64 = NOW + 1_000;
fn key(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).unwrap()
}
fn account(seed: u8) -> AccountId {
    AccountId::new(key(seed).public_key().clone())
}
fn times() -> (
    FinalPromotionEligibilityTimeIntervalV1,
    FinalPromotionAccountEligibilityTimeIntervalV1,
) {
    (
        FinalPromotionEligibilityTimeIntervalV1 {
            earliest_unix_ms: OBSERVED,
            latest_unix_ms: OBSERVED,
        },
        FinalPromotionAccountEligibilityTimeIntervalV1 {
            earliest_unix_ms: OBSERVED,
            latest_unix_ms: OBSERVED,
        },
    )
}
fn policy(
    native: &NativeCheckTestFixtureV1,
    role: SignerRoleV1,
    signer: u8,
    attester: u8,
) -> SignerCustodyPolicyV1 {
    let purpose = if role == SignerRoleV1::FinalPromotionProvenance {
        SignerPurposeBindingV1::FinalPromotionProvenance {
            deployment_id: DEPLOYMENT.into(),
        }
    } else {
        SignerPurposeBindingV1::FinalPromotionAccountTransaction {
            deployment_id: DEPLOYMENT.into(),
        }
    };
    let handle_role = if role == SignerRoleV1::FinalPromotionAccountTransaction {
        "final-promotion-account-transaction"
    } else {
        role.as_str()
    };
    SignerCustodyPolicyV1 {
        binding: SignerCustodyBindingV1 {
            chain_id: native.state().chain_id_ref().to_string(),
            network_id: *native.state().network_id_ref().as_bytes(),
            runtime_handle: format!("software://sorafs/{handle_role}/primary"),
            key_handle: format!("software://sorafs/{handle_role}/key-1"),
            service_id: format!("promotion-service-{signer}"),
            administrator_id: format!("promotion-admin-{signer}"),
            role,
            purpose,
            algorithm: SignerKeyAlgorithmV1::Ed25519,
            public_key: key(signer).public_key().clone(),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [signer; 32],
        },
        attester_authority: SignerCustodyAuthorityV1 {
            service_id: format!("custody-service-{attester}"),
            administrator_id: format!("custody-admin-{attester}"),
            key_revision: 1,
            policy_revision: 1,
            policy_digest: [attester; 32],
        },
        attester_public_key: key(attester).public_key().clone(),
        active_from_unix_ms: 100,
        active_until_unix_ms: 500_000,
        max_validity_ms: 120_000,
        max_anchor_age_ms: 60_000,
    }
}
struct Fixture {
    native: NativeCheckTestFixtureV1,
    receipt_policy: SignerCustodyPolicyV1,
    account_policy: SignerCustodyPolicyV1,
    statement: Arc<[u8]>,
    expected: SignerFinalPromotionExpectedV1,
    journal: SignerReceiptJournalV1,
    reserve_signed: Option<SignedTransaction>,
    reserve_floor: Option<FinalPromotionCheckFloorV1>,
    directory: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let native = NativeCheckTestFixtureV1::with_final_promotion_accounts(
            DEPLOYMENT,
            account(1),
            account(2),
            account(3),
        );
        let receipt_policy = policy(&native, SignerRoleV1::FinalPromotionProvenance, 4, 7);
        let account_policy = policy(
            &native,
            SignerRoleV1::FinalPromotionAccountTransaction,
            2,
            8,
        );
        let statement: Arc<[u8]> =
            Arc::from(statements::statement_message(&receipt_policy.binding));
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal = SignerReceiptJournalV1::open_test(
            &directory.path().canonicalize().unwrap(),
            SignerReceiptPurposeV1::FinalPromotionProvenance,
        )
        .unwrap();
        let mut f = Self {
            native,
            receipt_policy,
            account_policy,
            expected: SignerFinalPromotionExpectedV1 {
                operation_id: [15; 32],
                statement_digest: signer_final_promotion_digest_v1(&statement),
                statement_size: statement.len() as u64,
            },
            statement,
            journal,
            reserve_signed: None,
            reserve_floor: None,
            directory,
        };
        let configure_receipt = MutateSorafsFinalPromotionAuthority {
            deployment_id: DEPLOYMENT.into(),
            expected_control_revision: 0,
            expected_control_digest: [0; 32],
            action: FinalPromotionAuthorityActionV1::Configure(
                norito::encode_canonical(&f.receipt_policy).unwrap(),
            ),
        };
        let configure_account = MutateSorafsFinalPromotionAccountCustody {
            deployment_id: DEPLOYMENT.into(),
            expected_control_revision: 0,
            expected_control_digest: [0; 32],
            action: FinalPromotionAccountCustodyActionV1::Configure(
                norito::encode_canonical(&f.account_policy).unwrap(),
            ),
        };
        assert_eq!(
            f.native.commit(
                1_000,
                vec![
                    f.signed(configure_receipt.into(), 1, 1_000),
                    f.signed(configure_account.into(), 1, 1_000)
                ]
            ),
            [true, true]
        );
        let view = f.native.state().view();
        let receipt =
            read_final_promotion_authority_at_v1(&view, &f.receipt_policy.binding, 2, None)
                .unwrap()
                .unwrap();
        let account =
            read_final_promotion_account_custody_at_v1(&view, &f.account_policy.binding, 2)
                .unwrap()
                .unwrap();
        let enrollment = |policy: &SignerCustodyPolicyV1, anchor, attester| {
            let statement = SignerCustodyStatementV1 {
                magic: sorafs_manifest::signer::custody::SIGNER_CUSTODY_MAGIC_V1,
                version: 1,
                binding: policy.binding.clone(),
                authority: policy.attester_authority.clone(),
                anchor,
                sequence: 1,
                predecessor_digest: [0; 32],
                issued_at_unix_ms: 1_500,
                expires_at_unix_ms: 100_000,
                evidence_digest: [12; 32],
                revoked: false,
            };
            let signature = Signature::try_new(
                key(attester).private_key(),
                &statement.signing_payload().unwrap(),
            )
            .unwrap();
            norito::encode_canonical(&SignerCustodyRecordV1 {
                statement,
                attestation: signature.payload().try_into().unwrap(),
            })
            .unwrap()
        };
        let enroll_receipt = MutateSorafsFinalPromotionAuthority {
            deployment_id: DEPLOYMENT.into(),
            expected_control_revision: receipt.control_record.revision,
            expected_control_digest: receipt.custody_anchor.state_digest,
            action: FinalPromotionAuthorityActionV1::Enroll(enrollment(
                &f.receipt_policy,
                receipt.custody_anchor,
                7,
            )),
        };
        let enroll_account = MutateSorafsFinalPromotionAccountCustody {
            deployment_id: DEPLOYMENT.into(),
            expected_control_revision: account.control_record.revision,
            expected_control_digest: account.custody_anchor.state_digest,
            action: FinalPromotionAccountCustodyActionV1::Enroll(enrollment(
                &f.account_policy,
                account.custody_anchor,
                8,
            )),
        };
        drop(view);
        assert_eq!(
            f.native.commit(
                1_500,
                vec![
                    f.signed(enroll_receipt.into(), 1, 1_500),
                    f.signed(enroll_account.into(), 1, 1_500)
                ]
            ),
            [true, true]
        );
        f
    }
    fn signed(&self, instruction: InstructionBox, signer: u8, now: u64) -> SignedTransaction {
        let mut builder = TransactionBuilder::new(
            *self.native.state().network_id_ref(),
            account(signer),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(now));
        builder
            .with_instructions([instruction])
            .try_sign(key(signer).private_key())
            .unwrap()
    }
    fn receipt_check(
        &mut self,
        subject: Option<FinalPromotionCheckSubjectV1>,
    ) -> VerifiedFinalPromotionCheckV1 {
        self.execute_receipt_check(self.prepare_receipt_check(subject, Duration::from_secs(60)))
    }
    fn prepare_receipt_check(
        &self,
        subject: Option<FinalPromotionCheckSubjectV1>,
        max_elapsed: Duration,
    ) -> PreparedFinalPromotionCheckV1 {
        let view = self.native.state().view();
        let snapshot = read_final_promotion_authority_at_v1(
            &view,
            &self.receipt_policy.binding,
            view.height() as u64,
            Some(self.expected.operation_id),
        )
        .unwrap()
        .unwrap();
        let custody = verify_signer_custody_use_v1(
            snapshot.control_record.enrollment.as_deref().unwrap(),
            &self.receipt_policy.binding,
            &self.receipt_policy.custody_trust(),
            &SignerCustodyUseContextV1 {
                now_unix_ms: OBSERVED,
                anchor_observed_at_unix_ms: OBSERVED,
                current_anchor: snapshot.custody_anchor,
                active_head: snapshot.control.active_head.unwrap(),
                signer_revoked: false,
                attester_revoked: false,
            },
        )
        .unwrap();
        let statement =
            prepare_final_promotion_statement_v1(&self.statement, &self.receipt_policy.binding)
                .unwrap();
        let request =
            SignerFinalPromotionRequestV1::new(&custody, &self.expected, &statement).unwrap();
        let (height, block_hash, context_id) = self.native.finalized_floor();
        let floor = if matches!(
            &subject,
            Some(
                FinalPromotionCheckSubjectV1::BeforeProvider(_)
                    | FinalPromotionCheckSubjectV1::AfterProvider(_)
                    | FinalPromotionCheckSubjectV1::BeforeCommit(_)
            )
        ) {
            self.reserve_floor.unwrap_or(FinalPromotionCheckFloorV1 {
                height,
                block_hash,
                context_id,
            })
        } else {
            FinalPromotionCheckFloorV1 {
                height,
                block_hash,
                context_id,
            }
        };
        let prepared = begin_final_promotion_check_v1(
            Arc::clone(self.native.state()),
            FinalPromotionCheckExpectedV1 {
                binding: self.receipt_policy.binding.clone(),
                observer: account(3),
                expected_operator: account(2),
                request,
                subject: subject.unwrap_or(FinalPromotionCheckSubjectV1::Current(
                    snapshot.operations.audit,
                )),
                control_revision: snapshot.control_record.revision,
                control_digest: snapshot.custody_anchor.state_digest,
                floor,
            },
            max_elapsed,
        )
        .unwrap();
        drop(view);
        prepared
    }
    fn execute_receipt_check(
        &mut self,
        prepared: PreparedFinalPromotionCheckV1,
    ) -> VerifiedFinalPromotionCheckV1 {
        let reserved = matches!(
            &prepared.instruction().action,
            FinalPromotionAuthorityActionV1::Check(check)
                if matches!(&check.subject,
                    FinalPromotionCheckSubjectV1::BeforeProvider(_)
                    | FinalPromotionCheckSubjectV1::AfterProvider(_)
                    | FinalPromotionCheckSubjectV1::BeforeCommit(_))
        );
        let payload = self.observer_payload(prepared.instruction().clone().into());
        let pending = self
            .observer_transactions()
            .sign_receipt_with(prepared, payload, |request| {
                Signature::try_new(key(3).private_key(), request.signing_message())
                    .map_err(|_| ObserverError::Provider)
            })
            .unwrap();
        let signed = pending.signed_transaction().clone();
        assert_eq!(self.native.commit(NOW, vec![signed]), [true]);
        let source = if reserved {
            FinalPromotionCheckSourceV1::Reserved(
                self.reserve_signed
                    .as_ref()
                    .expect("original signed Reserve"),
            )
        } else {
            FinalPromotionCheckSourceV1::Current
        };
        pending.verify_finalized(source, || Ok(times().0)).unwrap()
    }
    fn execute_account_check(
        &mut self,
        prepared: PreparedFinalPromotionAccountCheckV1,
    ) -> VerifiedFinalPromotionAccountCheckV1 {
        let payload = self.observer_payload(prepared.instruction().clone().into());
        let pending = self
            .observer_transactions()
            .sign_account_with(prepared, payload, |request| {
                Signature::try_new(key(3).private_key(), request.signing_message())
                    .map_err(|_| ObserverError::Provider)
            })
            .unwrap();
        let signed = pending.signed_transaction().clone();
        assert_eq!(self.native.commit(NOW, vec![signed]), [true]);
        pending.verify_finalized(|| Ok(times().1)).unwrap()
    }
    fn observer_payload(&self, instruction: InstructionBox) -> TransactionPayload {
        let mut builder = TransactionBuilder::new(
            *self.native.state().network_id_ref(),
            account(3),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(NOW));
        builder
            .with_instructions([instruction])
            .into_payload()
            .unwrap()
    }
    fn observer_transactions(&self) -> FinalPromotionObserverTransactionsV1 {
        FinalPromotionObserverTransactionsV1::new(
            self.receipt_policy.binding.clone(),
            self.account_policy.binding.clone(),
            account(3),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .unwrap()
    }
    fn prepare(
        &self,
        receipt: VerifiedFinalPromotionCheckV1,
    ) -> PreparedFinalPromotionAccountTransactionV1 {
        let FinalPromotionAuthorityActionV1::Check(check) = &receipt.instruction().action else {
            panic!("Check");
        };
        let FinalPromotionCheckSubjectV1::Current(audit) = &check.subject else {
            panic!("Current");
        };
        let instruction = MutateSorafsFinalPromotionAuthority {
            deployment_id: DEPLOYMENT.into(),
            expected_control_revision: receipt.instruction().expected_control_revision,
            expected_control_digest: receipt.instruction().expected_control_digest,
            action: FinalPromotionAuthorityActionV1::Reserve(FinalPromotionReserveV1 {
                intent: SignerOperationIntentV1 {
                    action: SignerOperationActionV1::Sign,
                    operation_id: check.request.operation_id,
                    request_digest: check.request.digest().unwrap(),
                    previous_audit: *audit,
                },
                custody: check.request.original_custody,
            }),
        };
        let payload = self.signed(instruction.into(), 2, NOW).payload().clone();
        self.preparer()
            .prepare(
                receipt,
                self.account_policy.binding.clone(),
                &FeePaymentIntent::authority(Vec::new(), None),
                payload,
            )
            .unwrap()
    }
    fn preparer(&self) -> SignerFinalPromotionAccountPreparationV1 {
        SignerFinalPromotionAccountPreparationV1::new(
            self.receipt_policy.binding.clone(),
            self.expected,
            Arc::clone(&self.statement),
            &self.journal,
        )
        .unwrap()
    }
    fn begin_account_check(
        &self,
        prepared: &PreparedFinalPromotionAccountTransactionV1,
    ) -> PreparedFinalPromotionAccountCheckV1 {
        let view = self.native.state().view();
        let snapshot = read_final_promotion_account_custody_at_v1(
            &view,
            &self.account_policy.binding,
            view.height() as u64,
        )
        .unwrap()
        .unwrap();
        let floor = prepared.receipt_check.applied_floor();
        begin_final_promotion_account_check_v1(
            Arc::clone(self.native.state()),
            FinalPromotionAccountCheckExpectedV1 {
                binding: self.account_policy.binding.clone(),
                observer: account(3),
                expected_account: account(2),
                transaction_payload_digest: prepared.payload_digest(),
                control_revision: snapshot.control_record.revision,
                control_digest: snapshot.custody_anchor.state_digest,
                floor: FinalPromotionAccountCheckFloorV1 {
                    height: floor.height,
                    block_hash: floor.block_hash,
                    context_id: floor.context_id,
                },
            },
            Duration::from_secs(60),
        )
        .unwrap()
    }
}

#[test]
fn account_transaction_signing_retains_exact_native_authority_and_payload_through_submission() {
    let mut f = Fixture::new();
    let checked = f.receipt_check(None);
    let pre_reserve_floor = checked.applied_floor();
    let prepared = f.prepare(checked);
    let FinalPromotionAuthorityActionV1::Check(initial_check) =
        &prepared.receipt_check.instruction().action
    else {
        panic!("native receipt Check");
    };
    let initial_request = initial_check.request;
    let original = prepared.payload.clone();
    let account_check = f.execute_account_check(f.begin_account_check(&prepared));
    let authorized = prepared
        .authorize(account_check, times().0, times().1)
        .unwrap();
    let mut calls = 0;
    let (pending, after_account) = authorized
        .sign_with(
            Arc::clone(f.native.state()),
            Duration::from_secs(60),
            || Ok(times()),
            |request| {
                calls += 1;
                assert_eq!(request.payload(), &original);
                assert_eq!(request.binding(), &f.account_policy.binding);
                Signature::try_new(key(2).private_key(), request.signing_message())
                    .map_err(|_| Error::Provider)
            },
        )
        .unwrap();
    assert_eq!(calls, 1);
    let after_account = f.execute_account_check(after_account);
    let (pending, after_receipt) = pending
        .check_account(after_account, times().0, times().1)
        .unwrap();
    let after_receipt = f.execute_receipt_check(after_receipt);
    let signed = pending
        .release(after_receipt, times().0, times().1)
        .unwrap();
    let transaction = signed.for_submission(times().0, times().1).unwrap().clone();
    assert_eq!(transaction.payload(), &original);
    transaction.verify_signature().unwrap();
    assert_eq!(f.native.commit(NOW, vec![transaction.clone()]), [true]);
    f.reserve_signed = Some(transaction.clone());
    f.reserve_floor = Some(pre_reserve_floor);
    assert_eq!(signed.reconciliation_transaction(), &transaction);
    assert!(
        signed
            .for_submission(
                FinalPromotionEligibilityTimeIntervalV1 {
                    earliest_unix_ms: OBSERVED - 1,
                    latest_unix_ms: OBSERVED
                },
                times().1
            )
            .is_err()
    );

    // Stage the actual four signatures after the native Reserve. Complete preparation must
    // authenticate these bytes, not accept a caller's nonzero commitment or journal pathname.
    let view = f.native.state().view();
    let snapshot = read_final_promotion_authority_at_v1(
        &view,
        &f.receipt_policy.binding,
        view.height() as u64,
        Some(f.expected.operation_id),
    )
    .unwrap()
    .unwrap();
    let operation = snapshot.operation.clone().unwrap();
    drop(view);
    let signature = |purpose, message: &[u8]| SignerOperationSignatureV1 {
        purpose,
        message_digest: signer_operation_message_digest_v1(message),
        signature: Signature::try_new(key(4).private_key(), message)
            .unwrap()
            .payload()
            .to_vec(),
    };
    let raw = signature(SignerKeyOperationPurposeV1::RolePayload, &f.statement);
    let audit = signer_final_promotion_audit_v1(
        &initial_request,
        &operation.intent,
        operation.reservation,
        &raw.signature,
    )
    .unwrap();
    let provenance = SignerOperationProvenanceV1 {
        original_custody: initial_request.original_custody,
        signing_anchor: snapshot.custody_anchor,
        intent_digest: operation.intent.digest().unwrap(),
        reservation: operation.reservation,
        audit,
    };
    let mut signatures = vec![
        raw,
        signature(
            SignerKeyOperationPurposeV1::AuditRecord,
            &audit.signing_message(),
        ),
        signature(
            SignerKeyOperationPurposeV1::Provenance,
            &provenance.signing_message().unwrap(),
        ),
    ];
    let commitment = SignerOperationCommitmentV1 {
        audit,
        response_digest: signer_final_promotion_response_digest_v1(
            &initial_request,
            &provenance,
            &signatures,
        )
        .unwrap(),
    };
    signatures.push(signature(
        SignerKeyOperationPurposeV1::Response,
        &commitment.response_signing_message(),
    ));
    let receipt = SignerFinalPromotionReceiptV1 {
        magic: SIGNER_FINAL_PROMOTION_RECEIPT_MAGIC_V1,
        version: 1,
        custody_record: snapshot.control_record.enrollment.unwrap(),
        request: initial_request,
        intent: operation.intent,
        reservation: operation.reservation,
        provenance,
        commitment,
        signatures,
    };
    let staged = f
        .journal
        .stage(
            f.expected.operation_id,
            &norito::encode_canonical(&receipt).unwrap(),
        )
        .unwrap();
    let checked = f.receipt_check(Some(FinalPromotionCheckSubjectV1::BeforeCommit(operation)));
    let instruction = MutateSorafsFinalPromotionAuthority {
        deployment_id: DEPLOYMENT.into(),
        expected_control_revision: checked.instruction().expected_control_revision,
        expected_control_digest: checked.instruction().expected_control_digest,
        action: FinalPromotionAuthorityActionV1::Complete(FinalPromotionCompleteV1 {
            intent: receipt.intent,
            custody: receipt.request.original_custody,
            reservation: receipt.reservation,
            commitment: receipt.commitment,
            signatures_digest: signer_operation_signatures_digest_v1(&receipt.signatures).unwrap(),
        }),
    };
    let payload = f.signed(instruction.into(), 2, NOW).payload().clone();
    let complete = f
        .preparer()
        .prepare(
            checked,
            f.account_policy.binding.clone(),
            &FeePaymentIntent::authority(Vec::new(), None),
            payload,
        )
        .unwrap();
    assert!(complete.receipt.is_some());
    complete.recheck(times().0).unwrap();
    let path = f.directory.path().join(format!(
        "{}.receipt.norito",
        hex::encode(f.expected.operation_id)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path, b"substituted private receipt").unwrap();
    assert_eq!(complete.recheck(times().0), Err(Error::Receipt));
    assert!(staged.recheck().is_err());
}

#[test]
fn account_payload_commitment_covers_all_fields_and_rejects_unapproved_substitutions() {
    let mut f = Fixture::new();
    let checked = f.receipt_check(None);
    let prepared = f.prepare(checked);
    let payload = &prepared.payload;
    let Executable::Instructions(instructions) = &payload.instructions else {
        panic!("native");
    };
    let instruction = instructions[0]
        .as_any()
        .downcast_ref::<MutateSorafsFinalPromotionAuthority>()
        .unwrap();
    let fees = FeePaymentIntent::authority(Vec::new(), None);
    let original_digest = validate_payload(&prepared.binding, instruction, &fees, payload).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(PAYLOAD_DOMAIN);
    hasher.update(norito::encode_canonical(payload).unwrap());
    assert_eq!(original_digest, <[u8; 32]>::from(hasher.finalize()));
    let mut changed = payload.clone();
    changed.creation_time_ms += 1;
    assert_ne!(
        validate_payload(&prepared.binding, instruction, &fees, &changed).unwrap(),
        original_digest
    );
    changed = payload.clone();
    changed.domain = TransactionDomain::Genesis;
    assert_eq!(
        validate_payload(&prepared.binding, instruction, &fees, &changed),
        Err(Error::Payload)
    );
    changed = payload.clone();
    changed.authority = account(3);
    assert_eq!(
        validate_payload(&prepared.binding, instruction, &fees, &changed),
        Err(Error::Payload)
    );
    changed = payload.clone();
    changed.instructions =
        Executable::Instructions(vec![instructions[0].clone(), instructions[0].clone()].into());
    assert_eq!(
        validate_payload(&prepared.binding, instruction, &fees, &changed),
        Err(Error::Payload)
    );
    let mut changed_instruction = instruction.clone();
    changed_instruction.expected_control_digest = [0xEE; 32];
    assert_eq!(
        validate_payload(&prepared.binding, &changed_instruction, &fees, payload),
        Err(Error::Payload)
    );
    let unapproved = FeePaymentIntent::authority(Vec::new(), std::num::NonZeroU64::new(5));
    assert_eq!(
        validate_payload(&prepared.binding, instruction, &unapproved, payload),
        Err(Error::Payload)
    );
}

#[test]
fn prebuilt_account_proof_cannot_satisfy_post_key_challenge() {
    let mut f = Fixture::new();
    let checked = f.receipt_check(None);
    let prepared = f.prepare(checked);
    let before = f.begin_account_check(&prepared);
    let prebuilt = f.begin_account_check(&prepared);
    let signed = [before.instruction().clone(), prebuilt.instruction().clone()]
        .map(|instruction| f.signed(instruction.into(), 3, NOW));
    let before = before.bind_signed_transaction(signed[0].clone()).unwrap();
    let prebuilt = prebuilt.bind_signed_transaction(signed[1].clone()).unwrap();
    assert_eq!(f.native.commit(NOW, signed.to_vec()), [true, true]);
    let before = before.verify_finalized(|| Ok(times().1)).unwrap();
    let prebuilt = prebuilt.verify_finalized(|| Ok(times().1)).unwrap();
    let authorized = prepared.authorize(before, times().0, times().1).unwrap();
    let (pending, _new_challenge) = authorized
        .sign_with(
            Arc::clone(f.native.state()),
            Duration::from_secs(60),
            || Ok(times()),
            |request| {
                Signature::try_new(key(2).private_key(), request.signing_message())
                    .map_err(|_| Error::Provider)
            },
        )
        .unwrap();
    assert!(matches!(
        pending.check_account(prebuilt, times().0, times().1),
        Err(Error::Authority)
    ));
}

#[test]
fn account_signing_rejects_substituted_key_without_issuing_post_key_challenge() {
    let mut f = Fixture::new();
    let checked = f.receipt_check(None);
    let prepared = f.prepare(checked);
    let account_check = f.execute_account_check(f.begin_account_check(&prepared));
    let authorized = prepared
        .authorize(account_check, times().0, times().1)
        .unwrap();
    let before = f.native.finalized_floor();
    assert!(matches!(
        authorized.sign_with(
            Arc::clone(f.native.state()),
            Duration::from_secs(60),
            || Ok(times()),
            |request| {
                Signature::try_new(key(4).private_key(), request.signing_message())
                    .map_err(|_| Error::Provider)
            }
        ),
        Err(Error::Provider)
    ));
    assert_eq!(f.native.finalized_floor(), before);
}
