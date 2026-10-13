//! Native gateway transactions over a real four-validator certified test chain.
//!
//! These tests qualify instruction execution and rollback, not a remote gateway provider or
//! the still-required challenged finalized readback boundary.

use super::*;
use crate::{
    query::stream_token_gateway::{
        rows::{GatewayRow, GatewayRowKey, GatewayRows},
        storage::GatewayCurrentV1,
    },
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::Account,
    isi::{Grant, InstructionBox, Revoke, sorafs::SetSorafsReputationJournalAuthorityPolicy},
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
            native::{StreamTokenGatewayPolicyV1, StreamTokenGatewayRequestV1},
        },
    },
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_executor_data_model::permission::sorafs::{
    CanManageSorafsReputationJournalPolicy, CanRecordSorafsReputationJournal,
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
            CapacityDeclarationRecord::new(
                provider,
                vec![1],
                1,
                1,
                1,
                2,
                iroha_model_base::metadata::Metadata::default(),
            ),
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

#[test]
fn native_gateway_bootstrap_requires_governance_then_exact_operator_permission() {
    let mut fixture = Fixture::new();
    let configure = fixture.instruction(Action::Configure(fixture.policy.clone()));
    assert!(!fixture.commit(2, vec![configure.clone().into()]));
    assert!(fixture.current().is_none());
    assert!(fixture.commit(1, vec![configure.into()]));
    let before = fixture.current().unwrap().head;
    let request = fixture.request("first-request");
    let admit = fixture.instruction(Action::Admit(request));
    assert!(!fixture.commit(2, vec![admit.clone().into()]));
    assert_eq!(fixture.current().unwrap().head, before);
    fixture.grant_operator();
    assert!(fixture.commit(2, vec![admit.clone().into()]));
    let accepted = fixture.current().unwrap().head;
    assert_eq!(accepted.head.high_water_sequence, 1);
    assert!(fixture.commit(2, vec![admit.into()]));
    assert_eq!(fixture.current().unwrap().head, accepted);
    let record = fixture.record(1);
    assert_eq!(record.admitted_under, fixture.policy.qualification);
    assert_eq!(
        record.outcome.status,
        StreamTokenValidationStatusV1::Accepted
    );
    assert!(record.lease_id.is_some());

    let revoke = Revoke::account_permission(
        Permission::from(CanOperateSorafsStreamTokenGateway {
            gateway_id: fixture.policy.qualification.gateway_id,
        }),
        account(2),
    );
    assert!(fixture.commit(1, vec![revoke.into()]));
    let next = fixture.instruction(Action::Admit(fixture.request("revoked-request")));
    assert!(!fixture.commit(2, vec![next.into()]));
    assert_eq!(fixture.current().unwrap().head, accepted);
}

#[test]
fn native_gateway_rotation_preserves_original_grants_and_allows_disabled_recovery() {
    let mut fixture = Fixture::new();
    fixture.configure();
    fixture.grant_operator();
    let request = fixture.request("original-grant");
    let admit = fixture.instruction(Action::Admit(request.clone()));
    assert!(fixture.commit(2, vec![admit.into()]));
    let original = fixture.record(1);
    let before = fixture.current().unwrap().head;
    let mut next = fixture.policy.clone();
    next.qualification.revision += 1;
    next.qualification.lease_ttl_ms = 1_000;
    next.admission_enabled = false;
    next.qualification.policy_digest = next.calculate_policy_digest().unwrap();
    let rotate = fixture.instruction(Action::Configure(next.clone()));
    assert!(fixture.commit(1, vec![rotate.into()]));
    fixture.policy = next;
    assert_eq!(fixture.current().unwrap().head, before);
    assert_eq!(fixture.record(1), original);
    let unavailable = fixture.instruction(Action::Admit(request));
    assert!(!fixture.commit(2, vec![unavailable.into()]));
    assert_eq!(fixture.current().unwrap().head, before);
    fixture.deliver_reputation(original);
    for action in [
        Action::Acknowledge(original.clone()),
        Action::ReleaseLease(original.clone()),
    ] {
        let instruction = fixture.instruction(action);
        assert!(fixture.commit(2, vec![instruction.into()]));
    }
    let drained = fixture.current().unwrap().head;
    assert_eq!(drained.head.acknowledged_through_sequence, 1);
    assert_eq!(fixture.record(1), original);
    let exact_release = fixture.instruction(Action::ReleaseLease(original));
    assert!(fixture.commit(2, vec![exact_release.into()]));
    assert_eq!(fixture.current().unwrap().head, drained);
}

#[test]
fn native_gateway_rejects_substitution_and_rolls_back_prior_instructions_atomically() {
    let mut fixture = Fixture::new();
    fixture.configure();
    fixture.grant_operator();
    let before = fixture.current().unwrap().head;
    let request = fixture.request("atomic-request");
    let first = fixture.instruction(Action::Admit(request.clone()));
    let mut substituted = request.clone();
    substituted.serving_attempt_id = [0x79; 32];
    let second = fixture.instruction(Action::Admit(substituted));
    assert!(!fixture.commit(2, vec![first.clone().into(), second.into()]));
    assert_eq!(fixture.current().unwrap().head, before);
    {
        let view = fixture.chain.state().view();
        let rows = WorldGatewayRows::new(
            view.world(),
            &fixture.policy.network_id,
            fixture.policy.qualification.gateway_id,
        )
        .unwrap();
        assert_eq!(rows.read(&GatewayRowKey::Admission(1)).unwrap(), None);
        assert_eq!(
            rows.read(&GatewayRowKey::Context(request.context.digest().unwrap()))
                .unwrap(),
            None
        );
    }
    assert!(fixture.commit(2, vec![first.into()]));
    assert_eq!(fixture.current().unwrap().head.head.high_water_sequence, 1);
    let before = fixture.current().unwrap().head;
    let mut stale = fixture.instruction(Action::Admit(fixture.request("wrong-policy")));
    stale.request.expected_policy_digest = [0x88; 32];
    assert!(!fixture.commit(2, vec![stale.into()]));
    assert_eq!(fixture.current().unwrap().head, before);
    let mut wrong_gateway = fixture.instruction(Action::Admit(fixture.request("wrong-gateway")));
    wrong_gateway.request.gateway_id = [0x99; 32];
    assert!(!fixture.commit(2, vec![wrong_gateway.into()]));
    assert_eq!(fixture.current().unwrap().head, before);
}

#[test]
fn native_gateway_instruction_commitment_binds_authority_scope_policy_and_attempt() {
    let fixture = Fixture::new();
    let original = fixture.instruction(Action::Admit(fixture.request("digest-request")));
    let expected = instruction_digest(&original, &account(2)).unwrap();
    assert_eq!(
        instruction_digest(&original, &account(2)).unwrap(),
        expected
    );
    assert_ne!(
        instruction_digest(&original, &account(1)).unwrap(),
        expected
    );
    let mut changed = original.clone();
    changed.request.gateway_id[0] ^= 1;
    assert_ne!(instruction_digest(&changed, &account(2)).unwrap(), expected);
    let mut changed = original.clone();
    changed.request.expected_policy_digest[0] ^= 1;
    assert_ne!(instruction_digest(&changed, &account(2)).unwrap(), expected);
    let mut changed = original;
    let Action::Admit(request) = &mut changed.request.action else {
        unreachable!()
    };
    request.serving_attempt_id[0] ^= 1;
    assert_ne!(instruction_digest(&changed, &account(2)).unwrap(), expected);
}

#[path = "check_tests.rs"]
mod check_tests;

#[path = "delivery_tests.rs"]
mod delivery_tests;
