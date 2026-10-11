//! Native gateway Check proofs over real signed entries and a four-validator certified fixture.
//!
//! This qualifies local proof composition; it is not replicated network or daemon qualification.

use super::*;
use crate::{
    query::stream_token_gateway::{rows::GatewayRowKey, storage::GatewayCurrentV1},
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::Account,
    isi::{Grant, InstructionBox, Revoke, sorafs::SetSorafsReputationJournalAuthorityPolicy},
    permission::Permission,
    sorafs::{
        capacity::{CapacityDeclarationRecord, ProviderId},
        reputation::{
            ReputationJournalAuthorityPolicyV1, StreamTokenRequestRouteV1,
            StreamTokenValidationRequestContextV1, StreamTokenValidationStatusV1,
            derive_stream_token_gateway_id_v1,
            stream_token_delivery::StreamTokenReputationDeliveryTemplateV1,
        },
        stream_token_gateway::{
            StreamTokenGatewayAdmissionQualificationV1, StreamTokenGatewayAdmissionRecordV1,
            StreamTokenGatewayAdmissionRequestV1, StreamTokenGatewayQuotaRequestV1,
            native::StreamTokenGatewayPolicyV1,
        },
    },
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_executor_data_model::permission::sorafs::{
    CanCheckSorafsStreamTokenGateway, CanManageSorafsReputationJournalPolicy,
    CanManageSorafsStreamTokenGateway, CanOperateSorafsStreamTokenGateway,
    CanRecordSorafsReputationJournal,
};
use std::{collections::BTreeSet, time::Duration};

const START: u64 = 1_700_000_000_000;

fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}

fn account(seed: u8) -> AccountId {
    AccountId::new(key(seed).public_key().clone())
}

struct Fixture {
    chain: CertifiedTestChain,
    policy: StreamTokenGatewayPolicyV1,
}

impl Fixture {
    fn new() -> Self {
        let mut world = World::new();
        for seed in 1..=4 {
            let (id, account) = Account::new(account(seed))
                .build(&account(1))
                .into_key_value();
            world.accounts.insert(id, account);
        }
        let provider = ProviderId::new([0x41; 32]);
        world.provider_owners.insert(provider, account(4));
        world.capacity_declarations.insert(
            provider,
            CapacityDeclarationRecord::new(provider, vec![1], 1, 1, 1, 2, Default::default()),
        );
        let mut configuration = TestChainConfig::new(world, START);
        configuration.genesis_instructions.push(
            Grant::account_permission(
                Permission::from(CanManageSorafsStreamTokenGateway),
                account(1),
            )
            .into(),
        );
        configuration.genesis_instructions.extend([
            Grant::account_permission(
                Permission::from(CanManageSorafsReputationJournalPolicy),
                account(1),
            )
            .into(),
            Grant::account_permission(
                Permission::from(CanRecordSorafsReputationJournal),
                account(4),
            )
            .into(),
        ]);
        let chain = CertifiedTestChain::start(configuration)
            .map_err(|failure| failure.error)
            .expect("genuine genesis seeds gateway governance without knowing its hash");
        let network_id = *chain.state().network_id_ref();
        let mut policy = StreamTokenGatewayPolicyV1 {
            network_id,
            compliance_gateway_id: "native-gateway-fixture".into(),
            qualification: StreamTokenGatewayAdmissionQualificationV1 {
                gateway_id: derive_stream_token_gateway_id_v1(
                    &network_id,
                    "native-gateway-fixture",
                )
                .unwrap(),
                revision: 1,
                policy_digest: [0; 32],
                max_pending: 64,
                max_tracked_tokens: 64,
                lease_ttl_ms: 120_000,
            },
            operators: BTreeSet::from([account(2)]),
            observers: BTreeSet::from([account(3)]),
            valid_from_unix_ms: START,
            valid_until_unix_ms: START + 3_600_000,
            max_observation_age_ms: 300_000,
            admission_enabled: true,
        };
        policy.qualification.policy_digest = policy.calculate_policy_digest().unwrap();
        let mut fixture = Self { chain, policy };
        fixture.configure_reputation();
        fixture
    }

    fn configure_reputation(&mut self) {
        let policy = ReputationJournalAuthorityPolicyV1 {
            version: 1,
            revision: 1,
            predecessor_policy_digest: None,
            por_recorder_authority: account(1),
            dispute_recorder_authority: account(1),
            token_recorder_authority: account(4),
            stream_token_delivery: StreamTokenReputationDeliveryTemplateV1 {
                allowed_gateways: vec![self.policy.qualification.gateway_id],
                fee_payment: FeePaymentIntent::authority(Vec::new(), None),
                time_to_live_ms: 600_000,
                height_ttl: 1_024,
            },
            max_source_age_ms: 3_600_000,
        };
        assert!(self.commit(
            1,
            vec![SetSorafsReputationJournalAuthorityPolicy::new(policy).into()]
        ));
    }

    fn deliver_reputation(&mut self, record: StreamTokenGatewayAdmissionRecordV1) {
        use crate::smartcontracts::isi::sorafs_reputation::stream_token_delivery;
        use iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryDispositionV1 as Disposition;
        let (source, state) = {
            let view = self.chain.state().view();
            stream_token_delivery::read(view.world(), &self.policy.network_id, &record).unwrap()
        };
        if matches!(
            state.disposition,
            Disposition::Delivered { .. } | Disposition::Excluded
        ) {
            return;
        }
        assert_eq!(state.disposition, Disposition::Pending);
        let intent = source
            .intent
            .expect("counted source retains its original native recipe");
        let signed = TransactionBuilder::from_payload(intent.payload)
            .unwrap()
            .try_sign(key(4).private_key())
            .unwrap();
        assert_eq!(
            self.chain.commit_at(self.now(), vec![signed]),
            [true],
            "the original directly signed recorder Append must commit before gateway acknowledgement"
        );
    }

    fn now(&self) -> u64 {
        self.chain.committed(self.chain.height()).block_time_ms() + 1_000
    }

    fn instruction(&self, action: Action) -> MutateSorafsStreamTokenGateway {
        let (expected_policy_revision, expected_policy_digest) = match &action {
            Action::Configure(policy) if policy.qualification.revision == 1 => (0, [0; 32]),
            _ => (
                self.policy.qualification.revision,
                self.policy.qualification.policy_digest,
            ),
        };
        MutateSorafsStreamTokenGateway {
            request: StreamTokenGatewayRequestV1 {
                network_id: self.policy.network_id,
                gateway_id: self.policy.qualification.gateway_id,
                expected_policy_revision,
                expected_policy_digest,
                action,
            },
        }
    }

    fn commit(&mut self, seed: u8, instructions: Vec<InstructionBox>) -> bool {
        let now = self.now();
        let mut builder = TransactionBuilder::new(
            self.policy.network_id,
            account(seed),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(now - 1));
        let signed = builder
            .with_instructions(instructions)
            .sign(key(seed).private_key());
        self.chain.commit_at(now, vec![signed]) == [true]
    }

    fn current(&self) -> Option<GatewayCurrentV1> {
        let view = self.chain.state().view();
        storage::read_current(
            view.world(),
            &self.policy.network_id,
            self.policy.qualification.gateway_id,
        )
        .unwrap()
    }

    fn configure(&mut self) {
        let instruction = self.instruction(Action::Configure(self.policy.clone()));
        assert!(self.commit(1, vec![instruction.into()]));
    }

    fn grant_operator(&mut self) {
        let grant = Grant::account_permission(
            Permission::from(CanOperateSorafsStreamTokenGateway {
                gateway_id: self.policy.qualification.gateway_id,
            }),
            account(2),
        );
        assert!(self.commit(1, vec![grant.into()]));
    }

    fn request(&self, nonce: &str) -> StreamTokenGatewayAdmissionRequestV1 {
        let now = self.now();
        StreamTokenGatewayAdmissionRequestV1 {
            serving_attempt_id: *Hash::new(nonce.as_bytes()).as_ref(),
            context: StreamTokenValidationRequestContextV1::try_new(
                ProviderId::new([0x41; 32]),
                [0x42; 32],
                sorafs_manifest::canonical_manifest_root_cid([0x43; 32]),
                "sorafs.sf1@1.0.0".into(),
                nonce,
                Some(b"Q2Fub25pY2FsVG9rZW4="),
                StreamTokenRequestRouteV1::car_range(64, 1_023).unwrap(),
            )
            .unwrap(),
            token_body_digest: Some([0x44; 32]),
            token_key_version: Some(3),
            validated_at_unix_ms: now,
            status: StreamTokenValidationStatusV1::Accepted,
            quota: Some(StreamTokenGatewayQuotaRequestV1 {
                token_id: "11".repeat(16),
                max_streams: 4,
                requests_per_minute: 120,
                rate_limit_bytes: 1_048_576,
                requested_bytes: 960,
                expires_at_epoch: (START + 600_000) / 1_000,
                observed_at_epoch: now / 1_000,
            }),
        }
    }

    fn record(&self, sequence: u64) -> StreamTokenGatewayAdmissionRecordV1 {
        let view = self.chain.state().view();
        let rows = WorldGatewayRows::new(
            view.world(),
            &self.policy.network_id,
            self.policy.qualification.gateway_id,
        )
        .unwrap();
        let Some(GatewayRow::Admission(row)) =
            rows.read(&GatewayRowKey::Admission(sequence)).unwrap()
        else {
            panic!("native admission is retained");
        };
        row.record
    }
}

impl Fixture {
    fn ready() -> Self {
        let mut this = Self::new();
        this.configure();
        this.grant_operator();
        let grant = Grant::account_permission(
            CanCheckSorafsStreamTokenGateway {
                gateway_id: this.policy.qualification.gateway_id,
            },
            account(3),
        );
        assert!(this.commit(1, vec![grant.into()]));
        this
    }
    fn expected(&self, selector: Selector) -> StreamTokenGatewayCheckExpectedV1 {
        StreamTokenGatewayCheckExpectedV1 {
            network_id: self.policy.network_id,
            qualification: self.policy.qualification,
            operator: account(2),
            observer: account(3),
            selector,
        }
    }
    fn prepare(&self, selector: Selector) -> PreparedStreamTokenGatewayCheckV1 {
        begin_stream_token_gateway_check_v1(
            Arc::clone(self.chain.state()),
            self.expected(selector),
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap()
    }
    fn bind(
        &self,
        prepared: PreparedStreamTokenGatewayCheckV1,
    ) -> PendingStreamTokenGatewayCheckV1 {
        let mut builder = TransactionBuilder::new(
            self.policy.network_id,
            account(3),
            FeePaymentIntent::authority(Vec::new(), None),
        );
        builder.set_creation_time(Duration::from_millis(self.now() - 1));
        let signed = builder
            .with_instructions([prepared.instruction().clone()])
            .sign(key(3).private_key());
        prepared.bind_signed_transaction(signed).unwrap()
    }
    fn publish(&mut self, pending: &PendingStreamTokenGatewayCheckV1) {
        assert_eq!(
            self.chain
                .commit_at(self.now(), vec![pending.signed_transaction().clone()]),
            [true]
        );
    }
    fn clock(&self) -> Time {
        let now = self.chain.committed(self.chain.height()).block_time_ms();
        Time {
            earliest_unix_ms: now,
            latest_unix_ms: now + 1,
        }
    }
    fn verify(&mut self, selector: Selector) -> VerifiedStreamTokenGatewayCheckV1 {
        let pending = self.bind(self.prepare(selector));
        self.publish(&pending);
        pending.verify_finalized(|| Ok(self.clock())).unwrap()
    }
    fn admit(&mut self, request: &Request) -> Record {
        let action = self.instruction(Action::Admit(request.clone()));
        assert!(self.commit(2, vec![action.into()]));
        self.record(self.current().unwrap().head.head.high_water_sequence)
    }
    fn acknowledge(&mut self, record: Record) {
        self.deliver_reputation(record);
        let action = self.instruction(Action::Acknowledge(record));
        assert!(self.commit(2, vec![action.into()]));
    }
}

#[test]
fn six_gateway_check_purposes_authenticate_original_execution_and_exact_pending_prefix() {
    let mut fixture = Fixture::ready();
    assert!(matches!(
        fixture.verify(Selector::Qualification).readback(),
        StreamTokenGatewayCheckReadbackV1::Qualification(_)
    ));
    let empty = fixture.verify(Selector::Pending { max_items: 4 });
    assert!(
        matches!(empty.readback(), StreamTokenGatewayCheckReadbackV1::Pending(readback) if readback.records.is_empty())
    );
    let request = fixture.request("opaque-proof-first");
    let record = fixture.admit(&request);
    let admission = fixture.verify(Selector::Admission(request.clone()));
    assert!(
        matches!(admission.readback(), StreamTokenGatewayCheckReadbackV1::Admission(result) if result.record == record)
    );
    assert!(matches!(
        admission
            .consume_for_serving(&request, || Ok(fixture.clock()), |record| record)
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Authority))
    ));
    let pending = fixture.verify(Selector::Pending { max_items: 4 });
    assert!(
        matches!(pending.readback(), StreamTokenGatewayCheckReadbackV1::Pending(readback) if readback.records == [record])
    );
    assert!(
        begin_stream_token_gateway_check_v1(
            Arc::clone(fixture.chain.state()),
            fixture.expected(Selector::Serving(request.clone())),
            Instant::now() + Duration::from_secs(60)
        )
        .is_err(),
        "callback must be durably acknowledged first"
    );
    fixture.acknowledge(record);
    assert!(
        matches!(fixture.verify(Selector::Acknowledged(record)).readback(), StreamTokenGatewayCheckReadbackV1::Acknowledged(actual) if *actual == record)
    );
    let serving = fixture.verify(Selector::Serving(request.clone()));
    assert_eq!(
        serving
            .consume_for_serving(&request, || Ok(fixture.clock()), |record| record)
            .unwrap(),
        record
    );
    let release = fixture.instruction(Action::ReleaseLease(record));
    assert!(fixture.commit(2, vec![release.into()]));
    assert!(
        matches!(fixture.verify(Selector::Released(record)).readback(), StreamTokenGatewayCheckReadbackV1::Released(actual) if *actual == record)
    );
    assert!(
        matches!(fixture.verify(Selector::Admission(request.clone())).readback(), StreamTokenGatewayCheckReadbackV1::Admission(result) if result.record == record),
        "immutable Admission remains usable for recovery after release"
    );
    assert!(
        begin_stream_token_gateway_check_v1(
            Arc::clone(fixture.chain.state()),
            fixture.expected(Selector::Serving(request)),
            Instant::now() + Duration::from_secs(60)
        )
        .is_err()
    );
    assert!(
        matches!(fixture.verify(Selector::Pending { max_items: 4 }).readback(), StreamTokenGatewayCheckReadbackV1::Pending(readback) if readback.records.is_empty() && readback.high_water_sequence == 1 && readback.acknowledged_through_sequence == 1)
    );
}

#[test]
fn gateway_check_consumes_original_deadline_and_exact_signed_challenge() {
    let fixture = Fixture::ready();
    let prepared = fixture.prepare(Selector::Qualification);
    let mut wrong = prepared.instruction().clone();
    let Action::Check(check) = &mut wrong.request.action else {
        unreachable!()
    };
    check.challenge[0] ^= 1;
    let signed = TransactionBuilder::new(
        fixture.policy.network_id,
        account(3),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([wrong])
    .sign(key(3).private_key());
    assert!(matches!(
        prepared
            .bind_signed_transaction(signed)
            .err()
            .and_then(|failure| failure.rejection()),
        Some(Error::Transaction)
    ));
    let mut prepared = fixture.prepare(Selector::Qualification);
    prepared.round.expire_for_test();
    assert!(matches!(prepared.ensure_live(), Err(Error::Expired)));
    let mut pending = fixture.bind(fixture.prepare(Selector::Qualification));
    pending.prepared.round.expire_for_test();
    assert!(matches!(
        pending
            .verify_finalized(|| panic!("clock must not be sampled before proof"))
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Expired))
    ));
}

#[test]
fn gateway_check_rejects_revoked_current_observer_after_successful_check() {
    let mut fixture = Fixture::ready();
    let pending = fixture.bind(fixture.prepare(Selector::Qualification));
    fixture.publish(&pending);
    let revoke = Revoke::account_permission(
        CanCheckSorafsStreamTokenGateway {
            gateway_id: fixture.policy.qualification.gateway_id,
        },
        account(3),
    );
    assert!(fixture.commit(1, vec![revoke.into()]));
    assert!(matches!(
        pending
            .verify_finalized(|| Ok(fixture.clock()))
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Authority))
    ));
}

#[test]
fn gateway_check_rechecks_original_configure_quorum_without_reusing_capture_evidence() {
    let mut fixture = Fixture::ready();
    let pending = fixture.bind(fixture.prepare(Selector::Qualification));
    fixture.publish(&pending);
    let configure_height = fixture.current().unwrap().policy.execution.height;
    fixture
        .chain
        .corrupt_local_quorum_for_test(configure_height, Signers::BelowQuorum);
    assert!(matches!(
        pending
            .verify_finalized(|| panic!("proof must reject before clock"))
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Finality))
    ));
}

#[test]
fn gateway_serving_consumption_rejects_new_attempt_and_original_expiry() {
    let mut fixture = Fixture::ready();
    let request = fixture.request("opaque-final-serving");
    let record = fixture.admit(&request);
    fixture.acknowledge(record);
    let verified = fixture.verify(Selector::Serving(request.clone()));
    let mut another = request.clone();
    another.serving_attempt_id[0] ^= 1;
    assert!(matches!(
        verified
            .consume_for_serving(&another, || Ok(fixture.clock()), |record| record)
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Authority))
    ));
    let verified = fixture.verify(Selector::Serving(request.clone()));
    let expiry = record.lease_expires_at_unix_ms.unwrap();
    assert!(matches!(
        verified
            .consume_for_serving(
                &request,
                || Ok(Time {
                    earliest_unix_ms: expiry - 1,
                    latest_unix_ms: expiry
                }),
                |record| record
            )
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Authority))
    ));
    let mut verified = fixture.verify(Selector::Serving(request.clone()));
    verified.prepared.round.expire_for_test();
    assert!(matches!(
        verified
            .consume_for_serving(
                &request,
                || panic!("expired proof cannot sample clock"),
                |record| record
            )
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Expired))
    ));
}

#[test]
fn gateway_pending_proof_checks_two_admissions_at_the_same_height_separately() {
    let mut fixture = Fixture::ready();
    let first = fixture.request("opaque-same-height-first");
    let second = fixture.request("opaque-same-height-second");
    let instructions = vec![
        fixture.instruction(Action::Admit(first)).into(),
        fixture.instruction(Action::Admit(second)).into(),
    ];
    assert!(fixture.commit(2, instructions));
    let verified = fixture.verify(Selector::Pending { max_items: 4 });
    assert!(
        matches!(verified.readback(), StreamTokenGatewayCheckReadbackV1::Pending(readback) if readback.records.len() == 2)
    );
    let pending = fixture.bind(fixture.prepare(Selector::Pending { max_items: 4 }));
    fixture.publish(&pending);
    let network = fixture.policy.network_id;
    let gateway = fixture.policy.qualification.gateway_id;
    // Deliberately corrupt only one original instruction position in a World fixture. The
    // committed signed transaction and all certified block bytes remain unchanged.
    fixture.chain.setup_world_at(fixture.now(), |tx| {
        let rows = WorldGatewayRows::new(tx.world(), &network, gateway).unwrap();
        let Some(GatewayRow::Admission(mut second)) =
            rows.read(&GatewayRowKey::Admission(2)).unwrap()
        else {
            panic!("second admission")
        };
        second.execution.instruction_index = 0;
        tx.world.smart_contract_state.insert(
            storage::row_path(gateway, &GatewayRowKey::Admission(2)).unwrap(),
            storage::encode(&second).unwrap(),
        );
    });
    assert!(matches!(
        pending
            .verify_finalized(|| panic!("second target must reject before clock"))
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Execution))
    ));
}

#[test]
fn gateway_post_proof_clock_rejects_both_malformed_endpoints() {
    let mut fixture = Fixture::ready();
    for invalid in [
        Time {
            earliest_unix_ms: 0,
            latest_unix_ms: START,
        },
        Time {
            earliest_unix_ms: START,
            latest_unix_ms: START - 1,
        },
        Time {
            earliest_unix_ms: START,
            latest_unix_ms: u64::MAX,
        },
    ] {
        let pending = fixture.bind(fixture.prepare(Selector::Qualification));
        fixture.publish(&pending);
        assert!(matches!(
            pending
                .verify_finalized(|| Ok(invalid))
                .map_err(|failure| failure.rejection()),
            Err(Some(Error::Clock))
        ));
    }
}

#[test]
fn gateway_phase_start_cannot_renew_an_original_absolute_deadline() {
    let fixture = Fixture::ready();
    let deadline = Instant::now() - Duration::from_millis(1);
    assert!(matches!(
        begin_stream_token_gateway_check_v1(
            Arc::clone(fixture.chain.state()),
            fixture.expected(Selector::Qualification),
            deadline
        ),
        Err(Error::Expired)
    ));
    let excessive = Instant::now() + Duration::from_secs(61);
    assert!(matches!(
        begin_stream_token_gateway_check_v1(
            Arc::clone(fixture.chain.state()),
            fixture.expected(Selector::Qualification),
            excessive
        ),
        Err(Error::Invalid)
    ));
}

#[test]
fn gateway_capture_binding_and_verification_retain_one_absolute_deadline() {
    let mut fixture = Fixture::ready();
    let deadline = Instant::now() + Duration::from_secs(60);
    let prepared = begin_stream_token_gateway_check_v1(
        Arc::clone(fixture.chain.state()),
        fixture.expected(Selector::Qualification),
        deadline,
    )
    .unwrap();
    assert_eq!(prepared.deadline(), deadline);
    let pending = fixture.bind(prepared);
    assert_eq!(pending.deadline(), deadline);
    fixture.publish(&pending);
    let verified = pending.verify_finalized(|| Ok(fixture.clock())).unwrap();
    assert_eq!(verified.deadline(), deadline);
}

#[test]
fn gateway_check_cannot_cross_signer_purpose_or_treat_submission_as_execution() {
    use crate::query::signer_check::{NativeCustodyCheckPurposeV1, PreparedCheckExecutionV1};
    let fixture = Fixture::ready();
    let pending = fixture.bind(fixture.prepare(Selector::Qualification));
    let PendingStreamTokenGatewayCheckV1 { prepared, bound } = pending;
    let view = prepared.state.view();
    assert!(matches!(
        PreparedCheckExecutionV1::new(
            &view,
            NativeCustodyCheckPurposeV1::StreamToken,
            &mut Some(bound),
            &prepared.round
        ),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(
            NativeCheckErrorV1::Invalid
        ))
    ));
    let pending = fixture.bind(fixture.prepare(Selector::Qualification));
    assert!(matches!(
        pending
            .verify_finalized(|| panic!("submission cannot reach eligibility sampling"))
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::NotApplied))
    ));
}

#[test]
fn rejected_exact_signed_gateway_check_cannot_create_verified_readback() {
    let mut fixture = Fixture::ready();
    let pending = fixture.bind(fixture.prepare(Selector::Qualification));
    let revoke = Revoke::account_permission(
        CanOperateSorafsStreamTokenGateway {
            gateway_id: fixture.policy.qualification.gateway_id,
        },
        account(2),
    );
    assert!(fixture.commit(1, vec![revoke.into()]));
    assert_eq!(
        fixture
            .chain
            .commit_at(fixture.now(), vec![pending.signed_transaction().clone()]),
        [false]
    );
    assert!(matches!(
        pending
            .verify_finalized(|| panic!("rejected execution cannot reach the clock"))
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Execution))
    ));
}

#[test]
fn gateway_live_lease_is_checked_at_both_post_proof_clock_endpoints() {
    let mut fixture = Fixture::ready();
    let request = fixture.request("opaque-lease-endpoints");
    let record = fixture.admit(&request);
    fixture.acknowledge(record);
    let pending = fixture.bind(fixture.prepare(Selector::Serving(request)));
    fixture.publish(&pending);
    let expiry = record.lease_expires_at_unix_ms.unwrap();
    assert!(matches!(
        pending
            .verify_finalized(|| Ok(Time {
                earliest_unix_ms: expiry - 1,
                latest_unix_ms: expiry
            }))
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Authority))
    ));
}

#[test]
fn serving_consumption_rejects_every_intervening_state_publication() {
    for change in 0..5 {
        let mut fixture = Fixture::ready();
        let request = fixture.request("opaque-consume-generation");
        let record = fixture.admit(&request);
        fixture.acknowledge(record);
        let verified = fixture.verify(Selector::Serving(request.clone()));
        match change {
            0 => {
                let release = fixture.instruction(Action::ReleaseLease(record));
                assert!(fixture.commit(2, vec![release.into()]));
            }
            1 => {
                let revoke = Revoke::account_permission(
                    CanOperateSorafsStreamTokenGateway {
                        gateway_id: fixture.policy.qualification.gateway_id,
                    },
                    account(2),
                );
                assert!(fixture.commit(1, vec![revoke.into()]));
            }
            2 => {
                let revoke = Revoke::account_permission(
                    CanCheckSorafsStreamTokenGateway {
                        gateway_id: fixture.policy.qualification.gateway_id,
                    },
                    account(3),
                );
                assert!(fixture.commit(1, vec![revoke.into()]));
            }
            3 => {
                let mut next = fixture.policy.clone();
                next.qualification.revision += 1;
                next.admission_enabled = false;
                next.qualification.policy_digest = next.calculate_policy_digest().unwrap();
                let rotate = fixture.instruction(Action::Configure(next));
                assert!(fixture.commit(1, vec![rotate.into()]));
            }
            4 => {
                let unrelated = iroha_data_model::isi::Log::new(
                    iroha_logger::Level::INFO,
                    "unrelated publication invalidates old serving proof".into(),
                );
                assert!(fixture.commit(1, vec![unrelated.into()]));
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            verified
                .consume_for_serving(
                    &request,
                    || panic!("changed publication fails before clock"),
                    |_| panic!("changed publication cannot capture response")
                )
                .map_err(|failure| failure.rejection()),
            Err(Some(Error::Authority))
        ));
    }
}

#[test]
fn serving_consumption_rechecks_durable_qc_even_without_state_publication() {
    let mut fixture = Fixture::ready();
    let request = fixture.request("opaque-consume-certificate");
    let record = fixture.admit(&request);
    fixture.acknowledge(record);
    let verified = fixture.verify(Selector::Serving(request.clone()));
    let generation = fixture.chain.state().state_view_generation();
    let configure_height = fixture.current().unwrap().policy.execution.height;
    fixture
        .chain
        .corrupt_local_quorum_for_test(configure_height, Signers::BelowQuorum);
    assert_eq!(
        fixture.chain.state().state_view_generation(),
        generation,
        "local certificate bytes are outside World publication"
    );
    assert!(matches!(
        verified
            .consume_for_serving(
                &request,
                || panic!("removed durable certificate fails before clock"),
                |_| panic!("missing durable proof cannot capture response")
            )
            .map_err(|failure| failure.rejection()),
        Err(Some(Error::Finality))
    ));
}

#[test]
fn verified_ack_and_release_expose_only_their_authenticated_original_execution() {
    let mut fixture = Fixture::ready();
    let request = fixture.request("opaque-original-terminal-execution");
    let record = fixture.admit(&request);
    fixture.acknowledge(record);
    let ack_height = fixture.chain.height();
    let ack = fixture.verify(Selector::Acknowledged(record));
    let original_ack = fixture
        .chain
        .committed(ack_height)
        .block()
        .network_entrypoint_at(0)
        .unwrap()
        .hash();
    assert_eq!(
        ack.acknowledgement_execution().unwrap().transaction_hash,
        *original_ack.as_ref()
    );
    assert!(ack.lease_terminal_execution().is_none());
    // Repeating the native acknowledgement must not replace the originating execution.
    fixture.acknowledge(record);
    let replay = fixture.verify(Selector::Acknowledged(record));
    assert_eq!(
        replay.acknowledgement_execution().unwrap().transaction_hash,
        *original_ack.as_ref()
    );
    let release = fixture.instruction(Action::ReleaseLease(record));
    assert!(fixture.commit(2, vec![release.into()]));
    let release_height = fixture.chain.height();
    let released = fixture.verify(Selector::Released(record));
    let original_release = fixture
        .chain
        .committed(release_height)
        .block()
        .network_entrypoint_at(0)
        .unwrap()
        .hash();
    let (execution, expired) = released.lease_terminal_execution().unwrap();
    assert_eq!(execution.transaction_hash, *original_release.as_ref());
    assert!(!expired);
    assert!(released.acknowledgement_execution().is_none());
}

#[test]
fn binding_local_refusal_retries_only_original_signed_custody() {
    let fixture = Fixture::ready();
    let prepared = fixture.prepare(Selector::Qualification);
    let mut builder = TransactionBuilder::new(
        fixture.policy.network_id,
        account(3),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    builder.set_creation_time(Duration::from_millis(fixture.now() - 1));
    let signed = builder
        .with_instructions([prepared.instruction().clone()])
        .sign(key(3).private_key());
    let expected_wire = signed.encode_wire_v1().unwrap();
    let deadline = prepared.deadline();
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let failure =
        match norito::with_decode_limits_scope(zero, || prepared.bind_signed_transaction(signed)) {
            Err(failure) => failure,
            Ok(_) => panic!("original caller allocation ceiling must survive"),
        };
    assert!(failure.error().is_retryable());
    assert!(failure.rejection().is_none());
    assert_eq!(failure.deadline(), deadline);
    let pending = failure.retry().unwrap();
    assert_eq!(pending.deadline(), deadline);
    assert_eq!(
        pending.signed_transaction().encode_wire_v1().unwrap(),
        expected_wire
    );
    assert!(Arc::ptr_eq(&pending.prepared.state, fixture.chain.state()));
}

#[test]
fn local_recheck_refusal_preserves_original_signed_owner_and_accepted_time_floor() {
    use crate::execution_attempt::ExecutionAttemptError;
    use iroha_allocation::AllocationRefusal;
    // Stabilize unrelated retired State generations while checking this original pool's
    // exact scratch/refund accounting. This guard neither reserves nor adds capacity.
    let _retirement_pin = crossbeam_epoch::pin();
    let mut fixture = Fixture::ready();
    let request = fixture.request("same-owner-clock-floor");
    let record = fixture.admit(&request);
    fixture.acknowledge(record);
    let pending = fixture.bind(fixture.prepare(Selector::Serving(request.clone())));
    fixture.publish(&pending);
    let deadline = pending.deadline();
    let signed = pending.signed_transaction().encode_wire_v1().unwrap();
    let signed_backing = match pending.signed_transaction().instructions() {
        iroha_data_model::transaction::Executable::Instructions(instructions) => {
            instructions.as_ptr()
        }
        _ => panic!("native instructions"),
    };
    let accepted = fixture.clock();
    let verified = pending.verify_finalized(|| Ok(accepted)).unwrap();
    let budget = fixture.chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let held = budget
        .try_reserve_bytes(budget.limit_bytes() - baseline)
        .unwrap();
    let failure = verified
        .consume_for_serving(
            &request,
            || panic!("source refusal precedes clock sampling"),
            |_| panic!("incomplete source proof cannot capture a response"),
        )
        .err()
        .unwrap();
    assert!(
        matches!(failure.error(), ExecutionAttemptError::Deferred(original)
        if matches!(original.allocation_refusal(), Some(AllocationRefusal::Capacity { .. }))),
        "original source capacity must survive the preliminary ledger-time read: {:?}",
        failure.error(),
    );
    assert_eq!(failure.deadline(), deadline);
    drop(held);
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "failed proof scratch refunded"
    );
    let pending = failure.into_pending();
    assert!(Arc::ptr_eq(&pending.prepared.state, fixture.chain.state()));
    assert_eq!(
        pending.prepared.accepted_earliest_unix_ms,
        Some(accepted.earliest_unix_ms)
    );
    let failure = pending
        .verify_finalized(|| {
            Ok(Time {
                earliest_unix_ms: accepted.earliest_unix_ms - 1,
                latest_unix_ms: accepted.latest_unix_ms,
            })
        })
        .err()
        .unwrap();
    assert_eq!(failure.rejection(), Some(Error::Clock));
    assert_eq!(failure.deadline(), deadline);
    assert_eq!(
        failure.signed_transaction().encode_wire_v1().unwrap(),
        signed
    );
    match failure.signed_transaction().instructions() {
        iroha_data_model::transaction::Executable::Instructions(instructions) => {
            assert_eq!(instructions.as_ptr(), signed_backing)
        }
        _ => panic!("same native instructions"),
    }
    assert_eq!(budget.reserved_bytes(), baseline);
    let verified = failure
        .into_pending()
        .verify_finalized(|| Ok(accepted))
        .unwrap();
    assert_eq!(
        verified
            .consume_for_serving(&request, || Ok(accepted), |record| record)
            .unwrap(),
        record
    );
    assert!(
        budget.reserved_bytes() < baseline,
        "final owner releases original frame"
    );
}

#[test]
fn pending_scheduling_hint_uses_preparation_and_drops_without_a_check() {
    let mut fixture = Fixture::ready();
    let height = fixture.chain.height();
    let original_owners = Arc::strong_count(fixture.chain.state());
    let empty = fixture.prepare(Selector::Pending { max_items: 4 });
    assert_eq!(empty.pending_is_empty().unwrap(), Some(true));
    assert!(empty.deadline() > Instant::now());
    drop(empty);
    assert_eq!(fixture.chain.height(), height);
    assert_eq!(Arc::strong_count(fixture.chain.state()), original_owners);
    let qualification = fixture.prepare(Selector::Qualification);
    assert_eq!(qualification.pending_is_empty().unwrap(), None);
    drop(qualification);

    // Another caller's actual committed admission is observed after an earlier idle hint.
    let request = fixture.request("background-external-work");
    let record = fixture.admit(&request);
    let prepared = fixture.prepare(Selector::Pending { max_items: 4 });
    assert_eq!(prepared.pending_is_empty().unwrap(), Some(false));
    let deadline = prepared.deadline();
    let pending = fixture.bind(prepared);
    assert_eq!(pending.deadline(), deadline);
    fixture.publish(&pending);
    let verified = pending.verify_finalized(|| Ok(fixture.clock())).unwrap();
    assert_eq!(verified.deadline(), deadline);
    assert!(matches!(verified.readback(),
        StreamTokenGatewayCheckReadbackV1::Pending(readback) if readback.records == [record]));
}

#[test]
fn pending_scheduling_hint_rejects_expiry_and_corrupt_native_finality() {
    let fixture = Fixture::ready();
    let mut expired = fixture.prepare(Selector::Pending { max_items: 4 });
    expired.round.expire_for_test();
    assert_eq!(expired.pending_is_empty(), Err(Error::Expired));
    drop(expired);
    let height = fixture.chain.height();
    fixture
        .chain
        .corrupt_local_quorum_for_test(height, Signers::BelowQuorum);
    assert!(
        matches!(
            begin_stream_token_gateway_check_v1(
                Arc::clone(fixture.chain.state()),
                fixture.expected(Selector::Pending { max_items: 4 }),
                Instant::now() + Duration::from_secs(60),
            ),
            Err(Error::Finality)
        ),
        "corrupt original native finality cannot become Idle"
    );
}
