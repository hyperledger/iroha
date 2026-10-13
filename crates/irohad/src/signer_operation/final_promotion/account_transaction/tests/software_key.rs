//! Role-15 software credential tests using the exact native account continuation.

use super::*;
use crate::signer_operation::final_promotion::account_transaction::software_key::validate_request_payload;
use iroha_crypto::ExposedPrivateKey;
use iroha_data_model::sorafs::final_promotion_account_custody::FinalPromotionAccountCustodyRevocationV1;
use std::path::PathBuf;

fn credential(seed: u8) -> (tempfile::TempDir, PathBuf) {
    // The production reader rejects writable ancestors, including the global temp directory.
    let directory = tempfile::Builder::new()
        .prefix(".final-promotion-account-key-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = fs::canonicalize(directory.path())
        .unwrap()
        .join("account-key");
    let literal = ExposedPrivateKey(key(seed).private_key().clone())
        .try_to_multihash_string()
        .unwrap();
    fs::write(&path, format!("{literal}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
    (directory, path)
}

#[test]
fn role15_software_key_signs_only_the_exact_authorized_reserve_once() {
    let mut f = Fixture::new();
    let receipt = f.receipt_check(None);
    let prepared = f.prepare(receipt);
    let original = prepared.payload.clone();
    let account_check = f.execute_account_check(f.begin_account_check(&prepared));
    let authorized = prepared
        .authorize(account_check, times().0, times().1)
        .unwrap();
    let (_directory, path) = credential(2);
    let signer = SoftwareFinalPromotionAccountKeyV1::load_from_supervisor_credential(
        &path,
        f.account_policy.binding.clone(),
    )
    .unwrap();
    let mut calls = 0;
    let (pending, after_account) = authorized
        .sign_with(
            Arc::clone(f.native.state()),
            Duration::from_secs(60),
            || Ok(times()),
            |request| {
                calls += 1;
                signer.sign(request)
            },
        )
        .unwrap();
    assert_eq!(calls, 1);
    let after_account = f.execute_account_check(after_account);
    let (pending, after_receipt) = pending
        .check_account(after_account, times().0, times().1)
        .unwrap();
    let after_receipt = f.execute_receipt_check(after_receipt);
    let released_transaction = pending
        .release(after_receipt, times().0, times().1)
        .unwrap();
    let transaction = released_transaction
        .for_submission(times().0, times().1)
        .unwrap()
        .clone();
    assert_eq!(transaction.payload(), &original);
    transaction.verify_signature().unwrap();
    assert_eq!(f.native.commit(NOW, vec![transaction.clone()]), [true]);
}

#[test]
fn role15_software_key_rejects_wrong_role_handle_revision_and_foreign_private_key() {
    let mut f = Fixture::new();
    let (_directory, path) = credential(2);
    let mut binding = f.account_policy.binding.clone();
    binding.role = SignerRoleV1::FinalPromotionProvenance;
    binding.purpose = SignerPurposeBindingV1::FinalPromotionProvenance {
        deployment_id: DEPLOYMENT.into(),
    };
    assert!(matches!(
        SoftwareFinalPromotionAccountKeyV1::load_from_supervisor_credential(&path, binding),
        Err(Error::Binding)
    ));
    let mut binding = f.account_policy.binding.clone();
    binding.runtime_handle = "software://sorafs/final_promotion_account_transaction/primary".into();
    assert!(matches!(
        SoftwareFinalPromotionAccountKeyV1::load_from_supervisor_credential(&path, binding),
        Err(Error::Binding)
    ));
    let mut binding = f.account_policy.binding.clone();
    binding.key_handle = "software://sorafs/final_promotion_account_transaction/key-1".into();
    assert!(matches!(
        SoftwareFinalPromotionAccountKeyV1::load_from_supervisor_credential(&path, binding),
        Err(Error::Binding)
    ));
    for malformed in [
        "software://sorafs/final-promotion-account-transaction/",
        "software://sorafs/final-promotion-account-transaction/primary/nested",
    ] {
        let mut binding = f.account_policy.binding.clone();
        binding.runtime_handle = malformed.into();
        assert!(matches!(
            SoftwareFinalPromotionAccountKeyV1::load_from_supervisor_credential(&path, binding),
            Err(Error::Binding)
        ));
        let mut binding = f.account_policy.binding.clone();
        binding.key_handle = malformed.into();
        assert!(matches!(
            SoftwareFinalPromotionAccountKeyV1::load_from_supervisor_credential(&path, binding),
            Err(Error::Binding)
        ));
    }
    let mut binding = f.account_policy.binding.clone();
    binding.key_revision = 0;
    assert!(matches!(
        SoftwareFinalPromotionAccountKeyV1::load_from_supervisor_credential(&path, binding),
        Err(Error::Binding)
    ));
    let (_foreign_directory, foreign_path) = credential(9);
    assert!(matches!(
        SoftwareFinalPromotionAccountKeyV1::load_from_supervisor_credential(
            &foreign_path,
            f.account_policy.binding.clone(),
        ),
        Err(Error::Provider)
    ));

    // A correctly loaded different generation cannot sign a request whose finalized account
    // Check pinned the original generation, even though the underlying public key is unchanged.
    let mut changed = f.account_policy.binding.clone();
    changed.key_revision += 1;
    let signer =
        SoftwareFinalPromotionAccountKeyV1::load_from_supervisor_credential(&path, changed)
            .unwrap();
    let receipt = f.receipt_check(None);
    let prepared = f.prepare(receipt);
    let account_check = f.execute_account_check(f.begin_account_check(&prepared));
    let authorized = prepared
        .authorize(account_check, times().0, times().1)
        .unwrap();
    assert!(matches!(
        authorized.sign_with(
            Arc::clone(f.native.state()),
            Duration::from_secs(60),
            || Ok(times()),
            |request| signer.sign(request),
        ),
        Err(Error::Provider)
    ));
}

#[test]
fn role15_software_key_rechecks_the_complete_native_payload_prehash() {
    let mut f = Fixture::new();
    let receipt = f.receipt_check(None);
    let prepared = f.prepare(receipt);
    let binding = &f.account_policy.binding;
    let payload = &prepared.payload;
    let message = TransactionBuilder::from_payload(payload.clone())
        .unwrap()
        .payload_hash_bytes();
    assert_eq!(validate_request_payload(binding, payload, &message), Ok(()));
    let mut wrong_message = message;
    wrong_message[0] ^= 1;
    assert_eq!(
        validate_request_payload(binding, payload, &wrong_message),
        Err(Error::Payload)
    );
    let mut changed = payload.clone();
    changed.creation_time_ms += 1;
    assert_eq!(
        validate_request_payload(binding, &changed, &message),
        Err(Error::Payload)
    );
    changed = payload.clone();
    changed.authority = account(3);
    assert_eq!(
        validate_request_payload(binding, &changed, &message),
        Err(Error::Payload)
    );
    changed = payload.clone();
    let Executable::Instructions(instructions) = &changed.instructions else {
        panic!("native Reserve instruction");
    };
    let mut instruction = instructions[0]
        .as_any()
        .downcast_ref::<MutateSorafsFinalPromotionAuthority>()
        .unwrap()
        .clone();
    instruction.deployment_id = "another-deployment".into();
    changed.instructions = Executable::Instructions(vec![instruction.into()].into());
    let changed_message = TransactionBuilder::from_payload(changed.clone())
        .unwrap()
        .payload_hash_bytes();
    assert_eq!(
        validate_request_payload(binding, &changed, &changed_message),
        Err(Error::Payload)
    );
}

#[test]
fn role15_software_key_ambiguous_provider_response_exposes_no_transaction_or_post_key_check() {
    let mut f = Fixture::new();
    let receipt = f.receipt_check(None);
    let prepared = f.prepare(receipt);
    let account_check = f.execute_account_check(f.begin_account_check(&prepared));
    let authorized = prepared
        .authorize(account_check, times().0, times().1)
        .unwrap();
    let (_directory, path) = credential(2);
    let signer = SoftwareFinalPromotionAccountKeyV1::load_from_supervisor_credential(
        &path,
        f.account_policy.binding.clone(),
    )
    .unwrap();
    let before = f.native.finalized_floor();
    let mut calls = 0;
    let result = authorized.sign_with(
        Arc::clone(f.native.state()),
        Duration::from_secs(60),
        || Ok(times()),
        |request| {
            calls += 1;
            let _lost_signature = signer.sign(request)?;
            Err(Error::Provider)
        },
    );
    assert!(matches!(result, Err(Error::Provider)));
    assert_eq!(calls, 1);
    assert_eq!(f.native.finalized_floor(), before);
}

#[test]
fn role15_revocation_after_check_execution_rejects_authorization_before_key_use() {
    let mut f = Fixture::new();
    let receipt = f.receipt_check(None);
    let prepared = f.prepare(receipt);
    let account_check = f.begin_account_check(&prepared);
    let payload = f.observer_payload(account_check.instruction().clone().into());
    let pending = f
        .observer_transactions()
        .sign_account_with(account_check, payload, |request| {
            Signature::try_new(key(3).private_key(), request.signing_message())
                .map_err(|_| ObserverError::Provider)
        })
        .unwrap();
    let view = f.native.state().view();
    let snapshot = read_final_promotion_account_custody_at_v1(
        &view,
        &f.account_policy.binding,
        view.height() as u64,
    )
    .unwrap()
    .unwrap();
    drop(view);
    let revoke = MutateSorafsFinalPromotionAccountCustody {
        deployment_id: DEPLOYMENT.into(),
        expected_control_revision: snapshot.control_record.revision,
        expected_control_digest: snapshot.custody_anchor.state_digest,
        action: FinalPromotionAccountCustodyActionV1::Revoke(
            FinalPromotionAccountCustodyRevocationV1 {
                signer: true,
                attester: false,
            },
        ),
    };
    let revoke_signed = f.signed(revoke.into(), 1, NOW);
    assert_eq!(
        f.native.commit(
            NOW,
            vec![pending.signed_transaction().clone(), revoke_signed]
        ),
        [true, true]
    );
    assert!(pending.verify_finalized(|| Ok(times().1)).is_err());
}
