//! Actual signed native gateway Check tests over the certified four-validator fixture.
//! Synthetic row corruption cases isolate fail-closed predicates and claim no finalized proof.

use super::*;
use crate::query::stream_token_gateway::{check, read::GatewayReadCut};
use iroha_data_model::sorafs::stream_token_gateway::{
    StreamTokenGatewayAdmissionDeliveryStateV1 as Delivery,
    StreamTokenGatewayAdmissionReadbackV1 as Readback,
    StreamTokenGatewayAdmissionResultV1 as AdmissionResult,
    native::{
        StreamTokenGatewayCheckSubjectV1 as Subject, StreamTokenGatewayCheckV1 as Check,
        StreamTokenGatewayFinalityFloorV1 as Floor,
        stream_token_gateway_pending_readback_digest_v1,
    },
};
use iroha_executor_data_model::permission::sorafs::CanCheckSorafsStreamTokenGateway;

impl Fixture {
    fn checked() -> Self {
        let mut fixture = Self::new();
        fixture.configure();
        fixture.grant_operator();
        let grant = Grant::account_permission(
            Permission::from(CanCheckSorafsStreamTokenGateway {
                gateway_id: fixture.policy.qualification.gateway_id,
            }),
            account(3),
        );
        assert!(fixture.commit(1, vec![grant.into()]));
        fixture
    }

    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the resulting Check instruction owns its complete protocol subject"
    )]
    fn check_instruction(&self, subject: Subject) -> MutateSorafsStreamTokenGateway {
        let block = self.chain.committed(self.chain.height());
        self.instruction(Action::Check(Check {
            challenge: [0x71; 32],
            expected_operator: account(2),
            expected_observer: account(3),
            floor: Floor {
                height: block.height(),
                block_hash: *block.block_hash().as_ref(),
                context_id: block.id(),
            },
            subject,
        }))
    }

    #[expect(
        clippy::large_types_passed_by_value,
        reason = "the committed Check instruction takes ownership of its protocol subject"
    )]
    fn check_subject(&mut self, subject: Subject) -> bool {
        let instruction = self.check_instruction(subject);
        self.commit(3, vec![instruction.into()])
    }

    fn result(&self, sequence: u64) -> AdmissionResult {
        let record = self.record(sequence);
        let head = self.current().unwrap().head.head;
        AdmissionResult {
            record,
            delivery_state: if sequence <= head.acknowledged_through_sequence {
                Delivery::AcknowledgedExactReplay {
                    acknowledged_through_sequence: head.acknowledged_through_sequence,
                }
            } else {
                Delivery::Pending {
                    predecessor_sequence: sequence - 1,
                }
            },
        }
    }

    fn admit_checked(
        &mut self,
        nonce: &str,
    ) -> (StreamTokenGatewayAdmissionRequestV1, AdmissionResult) {
        let original = self.request(nonce);
        let instruction = self.instruction(Action::Admit(original.clone()));
        assert!(self.commit(2, vec![instruction.into()]));
        let sequence = self.current().unwrap().head.head.high_water_sequence;
        (original, self.result(sequence))
    }

    fn pending_readback(&self, limit: u32) -> Readback {
        check::read_pending(
            &self.chain.state().view(),
            &self.current().unwrap(),
            limit,
            self.now(),
        )
        .unwrap()
    }

    fn pending_subject(&self, limit: u32, readback: &Readback) -> Subject {
        Subject::Pending {
            max_items: limit,
            readback_digest: stream_token_gateway_pending_readback_digest_v1(
                self.policy.qualification,
                limit,
                readback,
            )
            .unwrap(),
        }
    }
}

#[test]
fn native_gateway_check_qualification_and_empty_prefix_write_nothing() {
    let mut fixture = Fixture::checked();
    let before = fixture.current().unwrap();
    let view = fixture.chain.state().view();
    let rows_before: Vec<_> = view
        .world()
        .smart_contract_state()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    drop(view);
    let instruction = fixture.check_instruction(Subject::Qualification);
    // Read-only capture allows its actual current tip as floor; only execution requires a successor.
    let captured = check::evaluate_current(
        &fixture.chain.state().view(),
        &instruction.request,
        fixture.now(),
    )
    .unwrap();
    assert_eq!(captured.value, check::GatewayCheckedValueV1::Qualification);
    assert!(fixture.commit(3, vec![instruction.into()]));
    let empty = fixture.pending_readback(16);
    assert!(empty.records.is_empty());
    assert_eq!(
        empty.high_water_sequence,
        empty.acknowledged_through_sequence
    );
    assert!(fixture.check_subject(fixture.pending_subject(16, &empty)));
    assert_eq!(fixture.current().unwrap(), before);
    let view = fixture.chain.state().view();
    assert_eq!(
        view.world()
            .smart_contract_state()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>(),
        rows_before
    );
}

#[test]
fn native_gateway_check_requires_current_registered_independent_roles_and_permissions() {
    let mut fixture = Fixture::checked();
    let instruction = fixture.check_instruction(Subject::Qualification);
    assert!(!fixture.commit(2, vec![instruction.clone().into()]));
    let mut wrong = instruction;
    let Action::Check(check) = &mut wrong.request.action else {
        unreachable!()
    };
    check.expected_operator = account(4);
    assert!(!fixture.commit(3, vec![wrong.into()]));
    let revoke = Revoke::account_permission(
        Permission::from(CanOperateSorafsStreamTokenGateway {
            gateway_id: fixture.policy.qualification.gateway_id,
        }),
        account(2),
    );
    assert!(fixture.commit(1, vec![revoke.into()]));
    assert!(!fixture.check_subject(Subject::Qualification));
    fixture.grant_operator();
    assert!(fixture.check_subject(Subject::Qualification));
    let revoke = Revoke::account_permission(
        Permission::from(CanCheckSorafsStreamTokenGateway {
            gateway_id: fixture.policy.qualification.gateway_id,
        }),
        account(3),
    );
    assert!(fixture.commit(1, vec![revoke.into()]));
    assert!(!fixture.check_subject(Subject::Qualification));
}

#[test]
fn native_gateway_check_separates_original_admission_acknowledgement_serving_and_release() {
    let mut fixture = Fixture::checked();
    let (original, pending) = fixture.admit_checked("serving-original");
    let digest = transition::request_digest(&original).unwrap();
    assert!(fixture.check_subject(Subject::Admission {
        request_digest: digest,
        result: pending
    }));
    assert!(!fixture.check_subject(Subject::Serving {
        request_digest: digest,
        result: pending
    }));
    let premature = fixture.instruction(Action::Acknowledge(pending.record));
    assert!(
        !fixture.commit(2, vec![premature.into()]),
        "live native delivery must commit before acknowledgement"
    );
    fixture.deliver_reputation(&pending.record);
    let ack = fixture.instruction(Action::Acknowledge(pending.record));
    assert!(fixture.commit(2, vec![ack.into()]));
    let acknowledged = fixture.result(1);
    assert!(fixture.check_subject(Subject::Acknowledged {
        record: acknowledged.record
    }));
    assert!(fixture.check_subject(Subject::Serving {
        request_digest: digest,
        result: acknowledged
    }));
    assert!(!fixture.check_subject(Subject::Released {
        record: acknowledged.record
    }));
    let release = fixture.instruction(Action::ReleaseLease(acknowledged.record));
    assert!(fixture.commit(2, vec![release.into()]));
    assert!(fixture.check_subject(Subject::Released {
        record: acknowledged.record
    }));
    assert!(fixture.check_subject(Subject::Admission {
        request_digest: digest,
        result: acknowledged
    }));
    assert!(!fixture.check_subject(Subject::Serving {
        request_digest: digest,
        result: acknowledged
    }));
    // The indexed first Ack and terminal name their actual original governed execution policy.
    let view = fixture.chain.state().view();
    let rows = WorldGatewayRows::new(
        view.world(),
        &fixture.policy.network_id,
        fixture.policy.qualification.gateway_id,
    )
    .unwrap();
    let Some(GatewayRow::Acknowledgement(ack)) =
        rows.read(&GatewayRowKey::Acknowledgement(1)).unwrap()
    else {
        panic!("original ack");
    };
    let Some(GatewayRow::LeaseTerminal(terminal)) = rows
        .read(&GatewayRowKey::LeaseTerminal(
            acknowledged.record.lease_id.unwrap(),
        ))
        .unwrap()
    else {
        panic!("terminal");
    };
    assert_eq!(ack.policy_revision, 1);
    assert_eq!(terminal.policy_revision, 1);
    assert!(terminal.execution.height > ack.execution.height);
}

#[test]
fn native_gateway_check_serving_binds_original_attempt_and_exclusive_deadline() {
    let mut fixture = Fixture::checked();
    let (original, pending) = fixture.admit_checked("exact-attempt");
    fixture.deliver_reputation(&pending.record);
    let ack = fixture.instruction(Action::Acknowledge(pending.record));
    assert!(fixture.commit(2, vec![ack.into()]));
    let result = fixture.result(1);
    let digest = transition::request_digest(&original).unwrap();
    let mut replacement = original.clone();
    replacement.serving_attempt_id[0] ^= 1;
    assert!(!fixture.check_subject(Subject::Serving {
        request_digest: transition::request_digest(&replacement).unwrap(),
        result
    }));
    let instruction = fixture.check_instruction(Subject::Serving {
        request_digest: digest,
        result,
    });
    let expiry = result.record.lease_expires_at_unix_ms.unwrap();
    check::evaluate_current(
        &fixture.chain.state().view(),
        &instruction.request,
        expiry - 1,
    )
    .unwrap();
    assert!(
        check::evaluate_current(&fixture.chain.state().view(), &instruction.request, expiry)
            .is_err()
    );
    check::evaluate_current_rows(
        &fixture.chain.state().view(),
        &instruction.request,
        expiry - 1,
    )
    .unwrap();
    assert!(
        check::evaluate_current_rows(&fixture.chain.state().view(), &instruction.request, expiry,)
            .is_err(),
        "the memory-only publication predicate retains the original exclusive deadline"
    );
    let historical = fixture.check_instruction(Subject::Admission {
        request_digest: digest,
        result,
    });
    check::evaluate_current(&fixture.chain.state().view(), &historical.request, expiry).unwrap();
    fixture.chain.commit_at(expiry, Vec::new());
    assert!(!fixture.check_subject(Subject::Serving {
        request_digest: digest,
        result
    }));
    assert!(fixture.check_subject(Subject::Admission {
        request_digest: digest,
        result
    }));
}

#[test]
fn native_gateway_check_pending_commits_complete_capped_prefix_and_rejects_stale_empty() {
    let mut fixture = Fixture::checked();
    let empty = fixture.pending_readback(2);
    let stale = fixture.pending_subject(2, &empty);
    let (_, first) = fixture.admit_checked("pending-first");
    fixture.admit_checked("pending-second");
    assert!(!fixture.check_subject(stale));
    let capped = fixture.pending_readback(1);
    assert_eq!(capped.high_water_sequence, 2);
    assert_eq!(capped.records, vec![first.record]);
    assert!(fixture.check_subject(fixture.pending_subject(1, &capped)));
    let complete = fixture.pending_readback(2);
    assert_eq!(complete.records.len(), 2);
    assert!(fixture.check_subject(fixture.pending_subject(2, &complete)));
    let mut forged = complete.clone();
    forged.records[0].serving_attempt_id[0] ^= 1;
    assert!(!fixture.check_subject(fixture.pending_subject(2, &forged)));
    fixture.deliver_reputation(&first.record);
    let ack = fixture.instruction(Action::Acknowledge(first.record));
    assert!(fixture.commit(2, vec![ack.into()]));
    assert!(!fixture.check_subject(fixture.pending_subject(2, &complete)));
    let rest = fixture.pending_readback(2);
    assert_eq!(rest.acknowledged_through_sequence, 1);
    assert_eq!(rest.records.len(), 1);
    assert_eq!(rest.records[0].outcome.binding.gateway_sequence, 2);
}

#[test]
fn native_gateway_check_rotation_disables_serving_without_discarding_recovery() {
    let mut fixture = Fixture::checked();
    let (original, pending) = fixture.admit_checked("rotation-retained");
    let old_policy = fixture.policy.qualification;
    let stale = fixture.check_instruction(Subject::Qualification);
    let mut next = fixture.policy.clone();
    next.qualification.revision += 1;
    next.admission_enabled = false;
    next.qualification.policy_digest = next.calculate_policy_digest().unwrap();
    let rotate = fixture.instruction(Action::Configure(next.clone()));
    assert!(fixture.commit(1, vec![rotate.into()]));
    fixture.policy = next;
    assert!(!fixture.commit(3, vec![stale.into()]));
    assert!(fixture.check_subject(Subject::Qualification));
    fixture.deliver_reputation(&pending.record);
    let ack = fixture.instruction(Action::Acknowledge(pending.record));
    assert!(fixture.commit(2, vec![ack.into()]));
    let result = fixture.result(1);
    assert_eq!(result.record.admitted_under, old_policy);
    let digest = transition::request_digest(&original).unwrap();
    assert!(fixture.check_subject(Subject::Admission {
        request_digest: digest,
        result
    }));
    assert!(fixture.check_subject(Subject::Acknowledged {
        record: result.record
    }));
    assert!(!fixture.check_subject(Subject::Serving {
        request_digest: digest,
        result
    }));
    let release = fixture.instruction(Action::ReleaseLease(result.record));
    assert!(fixture.commit(2, vec![release.into()]));
    assert!(fixture.check_subject(Subject::Released {
        record: result.record
    }));
    let view = fixture.chain.state().view();
    let rows = WorldGatewayRows::new(
        view.world(),
        &fixture.policy.network_id,
        fixture.policy.qualification.gateway_id,
    )
    .unwrap();
    let Some(GatewayRow::Acknowledgement(ack)) =
        rows.read(&GatewayRowKey::Acknowledgement(1)).unwrap()
    else {
        panic!("ack");
    };
    let Some(GatewayRow::LeaseTerminal(terminal)) = rows
        .read(&GatewayRowKey::LeaseTerminal(
            result.record.lease_id.unwrap(),
        ))
        .unwrap()
    else {
        panic!("terminal");
    };
    assert_eq!(ack.policy_revision, 2);
    assert_eq!(terminal.policy_revision, 2);
}

#[test]
fn native_gateway_check_floor_requires_exact_committed_frame_but_not_local_qc() {
    let mut fixture = Fixture::checked();
    let positive = fixture.check_instruction(Subject::Qualification);
    let Action::Check(check) = &positive.request.action else {
        unreachable!()
    };
    let height = check.floor.height;
    for field in 0..3 {
        let mut bad = positive.clone();
        let Action::Check(check) = &mut bad.request.action else {
            unreachable!()
        };
        match field {
            0 => check.floor.block_hash[0] ^= 1,
            1 => check.floor.context_id = fixture.chain.committed(1).id(),
            _ => check.floor.height = u64::MAX,
        }
        assert!(!fixture.commit(3, vec![bad.into()]));
    }
    fixture
        .chain
        .corrupt_local_quorum_for_test(height, crate::sumeragi::test_chain::Signers::BelowQuorum);
    // This deterministic predicate deliberately ignores per-node certificates; the separate
    // proof owner must reject the same local evidence as unavailable finality.
    check::evaluate_current(
        &fixture.chain.state().view(),
        &positive.request,
        fixture.now(),
    )
    .unwrap();
}

#[test]
fn native_gateway_check_memory_rows_do_not_replace_durable_floor_verification() {
    let fixture = Fixture::checked();
    let instruction = fixture.check_instruction(Subject::Qualification);
    let now = fixture.now();
    let expected =
        check::evaluate_current(&fixture.chain.state().view(), &instruction.request, now).unwrap();
    assert_eq!(
        check::evaluate_current_rows(&fixture.chain.state().view(), &instruction.request, now,)
            .unwrap(),
        expected
    );
    let Action::Check(check) = &instruction.request.action else {
        unreachable!()
    };
    fixture
        .chain
        .kura()
        .corrupt_canonical_body_for_testing(
            std::num::NonZeroUsize::new(usize::try_from(check.floor.height).unwrap()).unwrap(),
        )
        .unwrap();
    // Deliberately corrupt only durable evidence. The memory-only rows claim remains equal,
    // but cannot replace the outside-lock verifier, which rejects the same captured source.
    assert_eq!(
        check::evaluate_current_rows(&fixture.chain.state().view(), &instruction.request, now,)
            .unwrap(),
        expected
    );
    assert!(
        check::evaluate_current(&fixture.chain.state().view(), &instruction.request, now,).is_err()
    );
}

#[test]
fn native_gateway_check_missing_lifecycle_ack_or_pending_row_fails_closed() {
    let mut fixture = Fixture::checked();
    let (original, pending) = fixture.admit_checked("corrupt-read");
    fixture.deliver_reputation(&pending.record);
    let ack = fixture.instruction(Action::Acknowledge(pending.record));
    assert!(fixture.commit(2, vec![ack.into()]));
    let result = fixture.result(1);
    let instruction = fixture.check_instruction(Subject::Serving {
        request_digest: transition::request_digest(&original).unwrap(),
        result,
    });
    let gateway = fixture.policy.qualification.gateway_id;
    let view = fixture.chain.state().view();
    let rows = WorldGatewayRows::new(view.world(), &fixture.policy.network_id, gateway).unwrap();
    let Some(GatewayRow::Lease(lease)) = rows
        .read(&GatewayRowKey::Lease(result.record.lease_id.unwrap()))
        .unwrap()
    else {
        panic!("lease");
    };
    drop(view);
    for key in [
        GatewayRowKey::QuotaLifecycle(lease.token_scope),
        GatewayRowKey::Acknowledgement(1),
        GatewayRowKey::Admission(1),
    ] {
        let path = storage::row_path(gateway, &key).unwrap();
        let bytes = fixture
            .chain
            .state()
            .view()
            .world()
            .smart_contract_state()
            .get(&path)
            .unwrap()
            .clone();
        fixture.chain.setup_world_at(fixture.now(), |tx| {
            tx.world.smart_contract_state.remove(path.clone());
        });
        assert!(
            check::evaluate_current(
                &fixture.chain.state().view(),
                &instruction.request,
                fixture.now()
            )
            .is_err()
        );
        fixture.chain.setup_world_at(fixture.now(), |tx| {
            tx.world.smart_contract_state.insert(path, bytes);
        });
    }
    check::evaluate_current(
        &fixture.chain.state().view(),
        &instruction.request,
        fixture.now(),
    )
    .unwrap();
    let source = check::read_admission(
        &fixture.chain.state().view(),
        &fixture.current().unwrap(),
        1,
        fixture.now(),
    )
    .unwrap();
    assert_eq!(source.request, original);
    assert!(
        GatewayReadCut::Committed {
            height: fixture.chain.height(),
            now_unix_ms: fixture.now()
        }
        .contains(&source.execution)
    );
}
