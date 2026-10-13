//! Public request identities match real native rows and bind the complete bounded action.
use super::*;
use iroha_data_model::sorafs::final_promotion_authority::FINAL_PROMOTION_MAX_RECORD_BYTES_V1;

fn execute_request(f: &mut Fixture, authority: &AccountId, now: u64, action: Action) -> [u8; 32] {
    let mut expected = None;
    transact(&mut f.state, now, |tx| {
        let mutation = instruction(tx, action);
        expected = Some(final_promotion_authority_request_digest_v1(&mutation, authority).unwrap());
        mutation.execute(authority, tx).unwrap();
    });
    expected.unwrap()
}

#[test]
fn public_request_digest_matches_each_native_custody_and_operation_transition() {
    let mut f = fixture();
    let manager = f.manager.clone();
    let policy = encode(&f.policy).unwrap();
    let configured = execute_request(&mut f, &manager, 1_000, Action::Configure(policy));
    assert_eq!(snapshot(&f, None).control_record.request_digest, configured);
    let enrollment = attest(&f, 1_500, 100_000);
    let enrolled = execute_request(&mut f, &manager, 1_500, Action::Enroll(enrollment));
    assert_ne!(configured, enrolled);
    assert_eq!(snapshot(&f, None).control_record.request_digest, enrolled);

    // Direct Reserve/Complete also require an independently enrolled role-15 account. Use a
    // fresh fixture with both native purposes active; the custody digest checks above retain
    // their exact single-purpose transitions.
    let mut f = fixture();
    configure(&mut f);
    enroll(&mut f);
    let manager = f.manager.clone();
    let operator = f.operator.clone();
    let request = reserve_request(&f, 31);
    let reserved = execute_request(&mut f, &operator, 2_000, Action::Reserve(request));
    let row = snapshot(&f, Some([31; 32])).operation.unwrap();
    assert_eq!(row.request_digest, reserved);
    assert_eq!(row.reserved.authority, operator);
    assert_ne!(row.request_digest, row.intent.request_digest);
    let request = completion(&row);
    let completed = execute_request(&mut f, &operator, 3_000, Action::Complete(request));
    let row = snapshot(&f, Some([31; 32])).operation.unwrap();
    assert_eq!(row.request_digest, completed);
    assert_ne!(completed, reserved);

    let request = reserve_request(&f, 32);
    let reserved = execute_request(&mut f, &operator, 4_000, Action::Reserve(request));
    let row = snapshot(&f, Some([32; 32])).operation.unwrap();
    assert_eq!(row.request_digest, reserved);
    let expires = row.reservation.expires_at_unix_ms;
    let expired_request = execute_request(
        &mut f,
        &operator,
        expires,
        Action::Expire(FinalPromotionExpireV1 {
            operation_id: row.intent.operation_id,
            reservation: row.reservation,
        }),
    );
    let row = snapshot(&f, Some([32; 32])).operation.unwrap();
    assert_eq!(row.outcome, FinalPromotionOperationOutcomeV1::Expired);
    assert_eq!(row.request_digest, expired_request);
    assert_ne!(expired_request, reserved);

    let revoked = execute_request(
        &mut f,
        &manager,
        expires + 1,
        Action::Revoke(FinalPromotionRevocationV1 {
            signer: true,
            attester: false,
        }),
    );
    let current = snapshot(&f, None);
    assert!(current.control.signer_revoked);
    assert_eq!(current.control_record.request_digest, revoked);
    assert_ne!(revoked, enrolled);
}

#[test]
fn public_request_digest_binds_authority_deployment_cas_and_complete_payload() {
    let mut f = fixture();
    configure(&mut f);
    enroll(&mut f);
    let row = reserve(&mut f, 31, 2_000);
    let current = snapshot(&f, None);
    let complete = completion(&row);
    let original = MutateSorafsFinalPromotionAuthority {
        deployment_id: DEPLOYMENT.into(),
        expected_control_revision: current.control_record.revision,
        expected_control_digest: current.custody_anchor.state_digest,
        action: Action::Complete(complete),
    };
    let expected = final_promotion_authority_request_digest_v1(&original, &f.operator).unwrap();
    assert_eq!(
        final_promotion_authority_request_digest_v1(&original.clone(), &f.operator).unwrap(),
        expected
    );
    assert_ne!(
        final_promotion_authority_request_digest_v1(&original, &f.manager).unwrap(),
        expected,
        "the canonical domainless submitting account is part of the native identity"
    );
    for field in 0..4 {
        let mut changed = original.clone();
        match field {
            0 => changed.deployment_id = "promotion-secondary".into(),
            1 => changed.expected_control_revision += 1,
            2 => changed.expected_control_digest[0] ^= 1,
            3 => {
                changed.action = Action::Reserve(FinalPromotionReserveV1 {
                    intent: complete.intent,
                    custody: complete.custody,
                });
            }
            _ => unreachable!(),
        }
        assert_ne!(changed, original, "field {field}");
        assert_ne!(
            final_promotion_authority_request_digest_v1(&changed, &f.operator).unwrap(),
            expected,
            "field {field}"
        );
    }
    let mutations: [fn(&mut FinalPromotionCompleteV1); 14] = [
        |r| r.intent.action = SignerOperationActionV1::ActivateCustody,
        |r| r.intent.operation_id[0] ^= 1,
        |r| r.intent.request_digest[0] ^= 1,
        |r| r.intent.previous_audit.sequence += 1,
        |r| r.intent.previous_audit.digest[0] ^= 1,
        |r| r.custody.record_digest[0] ^= 1,
        |r| r.custody.control_state_digest[0] ^= 1,
        |r| r.reservation.reservation_id[0] ^= 1,
        |r| r.reservation.fence += 1,
        |r| r.reservation.expires_at_unix_ms += 1,
        |r| r.commitment.audit.sequence += 1,
        |r| r.commitment.audit.digest[0] ^= 1,
        |r| r.commitment.response_digest[0] ^= 1,
        |r| r.signatures_digest[0] ^= 1,
    ];
    for (field, mutate) in mutations.into_iter().enumerate() {
        let mut changed = original.clone();
        let Action::Complete(payload) = &mut changed.action else {
            unreachable!();
        };
        mutate(payload);
        assert_ne!(changed, original, "nested field {field}");
        assert_ne!(
            final_promotion_authority_request_digest_v1(&changed, &f.operator).unwrap(),
            expected,
            "nested field {field}"
        );
    }
}

#[test]
fn public_request_digest_enforces_the_canonical_frame_ceiling_before_native_writes() {
    let mut f = fixture();
    configure(&mut f);
    let manager = f.manager.clone();
    transact(&mut f.state, 1_500, |tx| {
        let mut candidate = instruction(tx, Action::Enroll(Vec::new()));
        // Locate the exact payload boundary using canonical frame lengths, not guessed overhead.
        let mut low = 0;
        let mut high = FINAL_PROMOTION_MAX_RECORD_BYTES_V1;
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            candidate.action = Action::Enroll(vec![0x37; middle]);
            if norito::canonical_frame_len(&candidate).unwrap()
                <= FINAL_PROMOTION_MAX_RECORD_BYTES_V1
            {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        candidate.action = Action::Enroll(vec![0x37; low]);
        assert!(final_promotion_authority_request_digest_v1(&candidate, &manager).is_ok());
        candidate.action = Action::Enroll(vec![0x37; low + 1]);
        assert!(
            norito::canonical_frame_len(&candidate).unwrap() > FINAL_PROMOTION_MAX_RECORD_BYTES_V1
        );
        let before = retained(tx);
        assert_eq!(
            final_promotion_authority_request_digest_v1(&candidate, &manager),
            Err(Error::Invalid)
        );
        assert!(candidate.execute(&manager, tx).is_err());
        assert_eq!(retained(tx), before);

        let mut oversized_scope = instruction(
            tx,
            Action::Revoke(FinalPromotionRevocationV1 {
                signer: true,
                attester: false,
            }),
        );
        oversized_scope.deployment_id = "p".repeat(FINAL_PROMOTION_MAX_RECORD_BYTES_V1);
        assert_eq!(
            final_promotion_authority_request_digest_v1(&oversized_scope, &manager),
            Err(Error::Invalid)
        );
        assert!(oversized_scope.execute(&manager, tx).is_err());
        assert_eq!(retained(tx), before);
    });
}
