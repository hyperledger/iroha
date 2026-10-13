//! Exact native role inventory and rejection before any request-time provider I/O.

use super::*;
use iroha_crypto::Hash;
use iroha_data_model::{
    account::Account,
    isi::{CustomInstruction, InstructionBox, Register, sorafs::*},
    smart_contract::ContractAddress,
    sorafs::{
        capacity::ProviderId,
        pin_registry::StorageClass,
        proof_ledger::ProofOutcomeSignerPolicyV1,
        reserve::{
            ReserveDuration, ReserveLifecycleStage, ReserveMovementKindV1, ReserveProviderTermsV1,
            ReserveTier,
        },
    },
    transaction::{
        Executable, ExecutableBatchItem, IvmBytecode, IvmProved, TransactionDomain,
        executable::ContractInvocation,
    },
};
use iroha_model_base::topology::DataSpaceId;
use sorafs_manifest::deal::XorQuantity;

const ROLES: [SorafsNativeTransactionSignerRoleV1; 4] = [
    SorafsNativeTransactionSignerRoleV1::ProofOutcome,
    SorafsNativeTransactionSignerRoleV1::Repair,
    SorafsNativeTransactionSignerRoleV1::Reserve,
    SorafsNativeTransactionSignerRoleV1::Orderbook,
];

// Opaque inner evidence is intentionally not authenticated here. The signer role predicate owns
// the typed instruction envelope; the existing native execution tests own its field eligibility.
pub(super) fn proof_instruction() -> InstructionBox {
    SubmitSorafsProofOutcome::new(SorafsProofOutcomeSubmissionV1::Pdp(
        SorafsPdpProofOutcomeSubmissionV1 {
            archive_payload: vec![1],
        },
    ))
    .into()
}

fn allowed_instructions(
    role: SorafsNativeTransactionSignerRoleV1,
    authority: &AccountId,
) -> Vec<InstructionBox> {
    use SorafsNativeTransactionSignerRoleV1 as Role;
    let provider = ProviderId([0x91; 32]);
    let policy = [0x92; 32];
    let amount = XorQuantity::try_from_micro(1_000_000).expect("positive fixture amount");
    match role {
        Role::ProofOutcome => vec![
            proof_instruction(),
            SubmitSorafsProofOutcome::new(SorafsProofOutcomeSubmissionV1::Potr(
                SorafsPotrProofOutcomeSubmissionV1 {
                    receipt_payload: vec![2],
                    admission_envelope_digest: [3; 32],
                },
            ))
            .into(),
        ],
        Role::Repair => {
            let mut instructions = vec![
                SubmitSorafsRepairTask::new([0x93; 32], vec![4]).into(),
                SubmitSorafsRepairAppeal::new(
                    "repair-ticket".into(),
                    1,
                    [0x94; 32],
                    "appeal".into(),
                    "appeal-operation".into(),
                )
                .into(),
            ];
            for action in [
                SorafsRepairTaskActionV1::Claim(SorafsRepairClaimV1 {
                    lease_duration_ms: 1_000,
                    idempotency_key: "claim".into(),
                }),
                SorafsRepairTaskActionV1::Renew(SorafsRepairRenewV1 {
                    lease_generation: 1,
                    lease_duration_ms: 1_000,
                    idempotency_key: "renew".into(),
                }),
                SorafsRepairTaskActionV1::Complete(SorafsRepairCompleteV1 {
                    lease_generation: 1,
                    evidence_digest: [5; 32],
                    idempotency_key: "complete".into(),
                }),
                SorafsRepairTaskActionV1::Fail(SorafsRepairFailV1 {
                    lease_generation: 1,
                    failure_digest: [6; 32],
                    idempotency_key: "fail".into(),
                }),
                SorafsRepairTaskActionV1::Escalate(SorafsRepairEscalateV1 {
                    lease_generation: 1,
                    slash_proposal_payload: vec![7],
                    idempotency_key: "escalate".into(),
                }),
            ] {
                instructions.push(
                    ApplySorafsRepairTaskAction::new("repair-ticket".into(), 1, action).into(),
                );
            }
            instructions
        }
        Role::Reserve => {
            let mut instructions = vec![
                RegisterSorafsReserveAccount::new(
                    ReserveProviderTermsV1 {
                        provider_id: provider,
                        provider_account: authority.clone(),
                        tier: ReserveTier::TierA,
                        storage_class: StorageClass::Hot,
                        duration: ReserveDuration::Monthly,
                        capacity_gib: 64,
                    },
                    policy,
                )
                .into(),
                DecideSorafsReserveMovement::new([8; 32], 1, policy, true, "approved".into())
                    .into(),
                ChargeSorafsReserveRent::new(provider, 1, 1, policy).into(),
                AdvanceSorafsReserveLifecycle::new(provider, 1, 1, policy).into(),
                DrawSorafsReserveCredit::new(provider, 1, amount.clone(), policy).into(),
                RepaySorafsReserveCredit::new(provider, 1, amount.clone(), policy).into(),
                SubmitSorafsReserveAppeal::new(
                    [9; 32],
                    provider,
                    1,
                    ReserveLifecycleStage::Active,
                    "appeal".into(),
                    Some([10; 32]),
                    policy,
                )
                .into(),
                DecideSorafsReserveAppeal::new([9; 32], 1, policy, true, "accepted".into()).into(),
            ];
            for kind in [
                ReserveMovementKindV1::TopUp,
                ReserveMovementKindV1::Withdrawal,
            ] {
                instructions.push(
                    RequestSorafsReserveMovement::new(
                        [8; 32],
                        provider,
                        kind,
                        amount.clone(),
                        1,
                        policy,
                    )
                    .into(),
                );
            }
            instructions
        }
        Role::Orderbook => vec![
            MatchSorafsOrderbook::new(policy, 1, 1).into(),
            MaintainSorafsOrderbook::new(policy, 1, 1).into(),
            RecordSorafsOrderbookSettlementReceipt::new(vec![11], policy).into(),
        ],
    }
}

fn with_executable(authority: &AccountId, executable: Executable) -> TransactionPayload {
    let mut candidate = payload(authority.clone());
    candidate.instructions = executable;
    candidate
}

fn direct(authority: &AccountId, instruction: InstructionBox) -> TransactionPayload {
    with_executable(
        authority,
        Executable::Instructions(vec![instruction].into()),
    )
}

type SignFixture = Box<dyn Fn(TransactionPayload) -> Result<SignedTransaction, ()>>;

fn qualified_fixture(provider: &Arc<TestProvider>, network_id: NetworkId) -> SignFixture {
    macro_rules! qualify {
        ($constructor:ident, $error:ident) => {{
            let qualified = $constructor(network_id, provider.expected_binding(), provider.clone())
                .expect("qualify exact fixture role");
            Box::new(move |payload| {
                qualified.sign(payload).map_err(|error| {
                    assert_eq!(error, $error::Refused, "must reject the input role/shape");
                })
            })
        }};
    }
    match provider.role {
        SorafsNativeTransactionSignerRoleV1::ProofOutcome => qualify!(
            qualify_sorafs_proof_outcome_transaction_signer_v1,
            SoraFsProofOutcomeSigningError
        ),
        SorafsNativeTransactionSignerRoleV1::Repair => qualify!(
            qualify_sorafs_repair_transaction_signer_v1,
            SoraFsRepairTransactionSigningError
        ),
        SorafsNativeTransactionSignerRoleV1::Reserve => qualify!(
            qualify_sorafs_reserve_transaction_signer_v1,
            SoraFsReserveTransactionSigningError
        ),
        SorafsNativeTransactionSignerRoleV1::Orderbook => qualify!(
            qualify_sorafs_orderbook_transaction_signer_v1,
            SoraFsOrderbookTransactionSigningError
        ),
    }
}

#[test]
fn every_forwarder_action_belongs_to_exactly_one_native_signer_role() {
    let account = TestProvider::new(ROLES[0], "provider://native/role-inventory", 0xA1).authority();
    let mut count = 0;
    for role in ROLES {
        for instruction in allowed_instructions(role, &account) {
            let candidate = direct(&account, instruction);
            for checked_role in ROLES {
                assert_eq!(
                    sorafs_native_transaction_payload_matches_role_v1(checked_role, &candidate),
                    checked_role == role,
                    "only the exact owner may authorize {role:?}: {checked_role:?}"
                );
            }
            count += 1;
        }
    }
    assert_eq!(
        count, 22,
        "all instruction types and nested proof/repair/movement variants"
    );
}

#[test]
fn all_native_facades_sign_every_allowed_action_without_rewriting_payload() {
    for (index, role) in ROLES.into_iter().enumerate() {
        let provider = Arc::new(TestProvider::new(
            role,
            "provider://native/allowed",
            0xB0 + index as u8,
        ));
        let sign = qualified_fixture(&provider, crate::signed_query_test_network_id());
        let account = provider.authority();
        let instructions = allowed_instructions(role, &account);
        for instruction in &instructions {
            let candidate = direct(&account, instruction.clone());
            let before_probes = provider.probe_calls.load(Ordering::SeqCst);
            let transaction = sign(candidate.clone()).expect("allowed native role action");
            assert_eq!(transaction.payload(), &candidate);
            assert_eq!(transaction.authority(), &account);
            assert!(transaction.verify_signature().is_ok());
            assert!(transaction.attachments().is_none());
            assert!(transaction.multisig_signatures().is_none());
            assert!(provider.probe_calls.load(Ordering::SeqCst) > before_probes);
        }
        assert_eq!(
            provider.sign_calls.load(Ordering::SeqCst),
            instructions.len()
        );
    }
}

fn disallowed_shapes(account: &AccountId, allowed: InstructionBox) -> Vec<Executable> {
    let unrelated = InstructionBox::from(Register::account(Account::new(account.clone())));
    let contract = ContractInvocation {
        contract_address: ContractAddress::derive(
            &crate::signed_query_test_network_id(),
            account,
            1,
            DataSpaceId::new(0),
        )
        .expect("derive unrelated contract address"),
        expected_code_hash: Hash::new([0xC1; 32]),
        entrypoint: "submit".into(),
        arguments: None,
    };
    vec![
        Executable::Instructions(Vec::<InstructionBox>::new().into()),
        Executable::Instructions(vec![unrelated.clone()].into()),
        Executable::Instructions(
            vec![SubmitSorafsOrderbookOrder::new(vec![1], [2; 32]).into()].into(),
        ),
        Executable::Instructions(
            vec![CancelSorafsOrderbookOrder::new(vec![1], [2; 32]).into()].into(),
        ),
        Executable::Instructions(
            vec![
                SetSorafsProofOutcomeSignerPolicy::new(ProofOutcomeSignerPolicyV1 {
                    version: 1,
                    provider_id: ProviderId([3; 32]),
                    revision: 1,
                    predecessor_digest: None,
                    admission_envelope_digest: [4; 32],
                    pdp_public_key: [5; 32],
                    potr_mldsa_public_key: vec![6],
                    gateway_public_key: [7; 32],
                    valid_from_unix: 1,
                    valid_until_unix: 2,
                })
                .into(),
            ]
            .into(),
        ),
        Executable::Instructions(vec![allowed.clone(), allowed.clone()].into()),
        Executable::Instructions(vec![allowed.clone(), unrelated.clone()].into()),
        Executable::Instructions(vec![unrelated, allowed.clone()].into()),
        Executable::Instructions(
            vec![
                CustomInstruction::new(
                    norito::json::to_value(&allowed).expect("serialize nested allowed instruction"),
                )
                .into(),
            ]
            .into(),
        ),
        Executable::Batch(vec![ExecutableBatchItem::Instruction(allowed.clone())].into()),
        Executable::Batch(
            vec![
                ExecutableBatchItem::Instruction(allowed.clone()),
                ExecutableBatchItem::ContractCall(contract.clone()),
            ]
            .into(),
        ),
        Executable::Ivm(IvmBytecode::from_compiled(vec![1])),
        Executable::IvmProved(IvmProved {
            bytecode: IvmBytecode::from_compiled(vec![1]),
            overlay: vec![allowed].into(),
            events_commitment: Hash::new([2; 32]),
            gas_policy_commitment: Hash::new([3; 32]),
        }),
        Executable::ContractCall(contract),
    ]
}

#[test]
fn every_native_facade_rejects_other_roles_and_wrappers_before_all_provider_calls() {
    for (index, role) in ROLES.into_iter().enumerate() {
        let provider = Arc::new(TestProvider::new(
            role,
            "provider://native/rejected",
            0xD0 + index as u8,
        ));
        let sign = qualified_fixture(&provider, crate::signed_query_test_network_id());
        let account = provider.authority();
        let allowed = allowed_instructions(role, &account).remove(0);
        let mut attached = direct(&account, allowed.clone());
        attached
            .set_proof_attachments_v1(&[ProofAttachment::new_ref(
                "halo2/ipa".into(),
                ProofBox::new("halo2/ipa".into(), vec![1, 2, 3]),
                VerifyingKeyId::new("halo2/ipa", "native-input-sidecar"),
            )])
            .expect("one bounded input sidecar carrier");
        let mut rejected: Vec<_> = disallowed_shapes(&account, allowed)
            .into_iter()
            .map(|executable| with_executable(&account, executable))
            .collect();
        rejected.push(attached);
        for other_role in ROLES.into_iter().filter(|other| *other != role) {
            rejected.extend(
                allowed_instructions(other_role, &account)
                    .into_iter()
                    .map(|instruction| direct(&account, instruction)),
            );
        }
        // An unavailable live provider must not mask the pure input rejection or receive a probe.
        provider.set_qualification(Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable));
        let before_probes = provider.probe_calls.load(Ordering::SeqCst);
        let before_signs = provider.sign_calls.load(Ordering::SeqCst);
        for candidate in rejected {
            assert!(!sorafs_native_transaction_payload_matches_role_v1(
                role, &candidate
            ));
            assert!(sign(candidate).is_err());
            assert_eq!(provider.probe_calls.load(Ordering::SeqCst), before_probes);
            assert_eq!(provider.sign_calls.load(Ordering::SeqCst), before_signs);
        }
    }
}

#[test]
fn every_native_facade_rejects_foreign_and_genesis_networks_before_all_provider_calls() {
    let foreign = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        Hash::new([0xEF; 32]),
    ));
    assert_ne!(foreign, crate::signed_query_test_network_id());
    for (index, role) in ROLES.into_iter().enumerate() {
        let provider = Arc::new(TestProvider::new(
            role,
            "provider://native/network",
            0xE0 + index as u8,
        ));
        let sign = qualified_fixture(&provider, crate::signed_query_test_network_id());
        let account = provider.authority();
        let valid = direct(&account, allowed_instructions(role, &account).remove(0));
        assert_eq!(
            valid.network_id(),
            Some(&crate::signed_query_test_network_id())
        );
        provider.set_qualification(Err(SorafsNativeTransactionSignerProbeErrorV1::Unavailable));
        let before_probes = provider.probe_calls.load(Ordering::SeqCst);
        for domain in [
            TransactionDomain::Network(foreign),
            TransactionDomain::Genesis,
        ] {
            let mut rejected = valid.clone();
            rejected.domain = domain;
            assert_ne!(rejected, valid, "network mutation must change the payload");
            assert!(sorafs_native_transaction_payload_matches_role_v1(
                role, &rejected
            ));
            assert!(sign(rejected).is_err());
            assert_eq!(provider.probe_calls.load(Ordering::SeqCst), before_probes);
            assert_eq!(provider.sign_calls.load(Ordering::SeqCst), 0);
        }
        provider.set_qualification(Ok(EXPECTED_QUALIFICATION));
        let signed = sign(valid.clone()).expect("retained network and role remain usable");
        assert_eq!(signed.payload(), &valid);
        assert_eq!(provider.sign_calls.load(Ordering::SeqCst), 1);
        let foreign_sign = qualified_fixture(&provider, foreign);
        let mut foreign_valid = valid;
        foreign_valid.domain = TransactionDomain::Network(foreign);
        let signed =
            foreign_sign(foreign_valid.clone()).expect("constructor pins the supplied network");
        assert_eq!(signed.payload(), &foreign_valid);
        assert_eq!(provider.sign_calls.load(Ordering::SeqCst), 2);
    }
}
