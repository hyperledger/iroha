//! Native adapter boundary tests against real State/Kura finality and private runtime credentials.

use super::*;
use iroha_core::{
    kura::Kura,
    query::{
        store::LiveQueryStore,
        stream_token_authority::test_fixture::StreamTokenRuntimeTestFixtureV1 as Fixture,
    },
    state::World,
};
use iroha_crypto::ExposedPrivateKey;
use iroha_data_model::{
    NetworkId,
    isi::{
        InstructionBox,
        sorafs::{
            ChargeSorafsReserveRent, MatchSorafsOrderbook, SorafsPdpProofOutcomeSubmissionV1,
            SorafsProofOutcomeSubmissionV1, SubmitSorafsProofOutcome, SubmitSorafsRepairTask,
        },
    },
    sorafs::capacity::ProviderId,
    transaction::FeePaymentIntent,
};
use iroha_fs::{PrivateDirectory, PublishMode};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use zeroize::Zeroizing;

fn config(role: Role, seed: u8) -> (tempfile::TempDir, ConfiguredBinding) {
    let directory = tempfile::Builder::new()
        .prefix(".native-sorafs-credential-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    let private = PrivateDirectory::open_or_create(directory.path().join("private")).unwrap();
    let path = private.path().join("credential");
    let key = Fixture::key(seed);
    let encoded = Zeroizing::new(format!(
        "{}\n",
        ExposedPrivateKey(key.private_key().clone())
            .try_to_multihash_string()
            .unwrap()
    ));
    private
        .write_atomic("credential", encoded.as_bytes(), PublishMode::CreateNew)
        .unwrap();
    (
        directory,
        ConfiguredBinding {
            software_credential: Some(path),
            handle: format!("software://sorafs/{}/primary", role.as_str()),
            authority: AccountId::new(key.public_key().clone()),
            algorithm: key.public_key().algorithm(),
            public_key: key.public_key().clone(),
            revision: 7,
            policy_digest: [8; 32],
        },
    )
}
fn instruction(role: Role) -> InstructionBox {
    match role {
        Role::ProofOutcome => SubmitSorafsProofOutcome::new(SorafsProofOutcomeSubmissionV1::Pdp(
            SorafsPdpProofOutcomeSubmissionV1 {
                archive_payload: vec![1],
            },
        ))
        .into(),
        Role::Repair => SubmitSorafsRepairTask::new([2; 32], vec![3]).into(),
        Role::Reserve => {
            ChargeSorafsReserveRent::new(ProviderId::new([4; 32]), 1, 1, [5; 32]).into()
        }
        Role::Orderbook => MatchSorafsOrderbook::new([6; 32], 1, 1).into(),
    }
}
fn payload(state: &State, authority: AccountId, role: Role) -> TransactionPayload {
    TransactionBuilder::new(
        *state.network_id_ref(),
        authority,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([instruction(role)])
    .into_payload()
    .unwrap()
}
fn blank_state(network: NetworkId) -> (Arc<State>, Arc<Kura>) {
    let kura = Kura::blank_kura_for_testing();
    let state = Arc::new(State::new_with_chain_and_network_id_for_testing(
        World::new(),
        Arc::clone(&kura),
        LiveQueryStore::start_test(),
        "native-signer-test".parse().unwrap(),
        network,
    ));
    (state, kura)
}

#[test]
fn every_role_signs_exact_payload_through_qualified_facade_with_real_finality() {
    // These deliberately opaque instruction bodies test signing boundaries; native forwarder and
    // execution tests own their permission/evidence eligibility. No instruction is submitted here.
    let fixture = Fixture::new_at(1_700_000_000_000);
    macro_rules! exercise {
        ($role:ident, $qualify:ident) => {{
            let (_directory, config) = config(Role::$role, 2);
            let provider =
                NativeSoftwareSigner::load(&config, Role::$role, Arc::clone(&fixture.state))
                    .unwrap();
            let signer = iroha_torii::$qualify(
                *fixture.state.network_id_ref(),
                provider.binding.clone(),
                Arc::new(provider),
            )
            .unwrap();
            let original = payload(&fixture.state, config.authority, Role::$role);
            let signed = signer.sign(original.clone()).unwrap();
            assert_eq!(signed.payload(), &original);
            signed.verify_signature().unwrap();
        }};
    }
    exercise!(
        ProofOutcome,
        qualify_sorafs_proof_outcome_transaction_signer_v1
    );
    exercise!(Repair, qualify_sorafs_repair_transaction_signer_v1);
    exercise!(Reserve, qualify_sorafs_reserve_transaction_signer_v1);
    exercise!(Orderbook, qualify_sorafs_orderbook_transaction_signer_v1);
}

#[test]
fn invalid_envelopes_are_rejected_before_missing_finality_and_valid_payload_requires_qc() {
    let fixture = Fixture::new_at(1_700_000_000_000);
    let (mut state, kura) = blank_state(*fixture.state.network_id_ref());
    // A durable complete block and matching State hash alone must never substitute for its
    // commit certificate: the copies carry no certificate.
    for height in 1..=fixture.state.view().height() {
        let block = fixture
            .state
            .block_by_height(std::num::NonZeroUsize::new(height).unwrap())
            .unwrap()
            .unwrap();
        let block = iroha_data_model::block::SharedSignedBlock::try_new(
            block.as_ref().clone().with_commit_certificate(None),
            &state.ivm_execution_budget(),
        )
        .unwrap();
        kura.store_block(block.clone()).unwrap();
        Arc::get_mut(&mut state)
            .unwrap()
            .push_block_hash_for_testing(block.hash());
    }
    let (_directory, config) = config(Role::Repair, 2);
    let signer = NativeSoftwareSigner::load(&config, Role::Repair, Arc::clone(&state)).unwrap();
    let original = payload(&state, config.authority.clone(), Role::Repair);
    assert_eq!(
        signer.sign_exact(Role::Repair, original.clone()),
        Err(SignError::Unavailable)
    );
    assert_eq!(
        signer.sign_exact(Role::Orderbook, original.clone()),
        Err(SignError::Refused)
    );
    assert_eq!(
        signer.sign_exact(
            Role::Repair,
            payload(&state, config.authority.clone(), Role::Orderbook)
        ),
        Err(SignError::Refused)
    );
    let wrong_authority = AccountId::new(Fixture::key(3).public_key().clone());
    assert_eq!(
        signer.sign_exact(Role::Repair, payload(&state, wrong_authority, Role::Repair)),
        Err(SignError::Authority)
    );
    let foreign = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(b"foreign-native-signer-genesis"),
    ));
    let foreign = TransactionBuilder::new(
        foreign,
        config.authority.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([instruction(Role::Repair)])
    .into_payload()
    .unwrap();
    assert_eq!(
        signer.sign_exact(Role::Repair, foreign),
        Err(SignError::Refused)
    );
    let batch = TransactionBuilder::new(
        *state.network_id_ref(),
        config.authority,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([instruction(Role::Repair), instruction(Role::Repair)])
    .into_payload()
    .unwrap();
    assert_eq!(
        signer.sign_exact(Role::Repair, batch),
        Err(SignError::Refused)
    );
}

#[test]
fn absent_account_and_changed_credential_or_qualification_fail_closed() {
    let fixture = Fixture::new_at(1_700_000_000_000);
    let (_directory, mut config) = config(Role::Repair, 9);
    let signer =
        NativeSoftwareSigner::load(&config, Role::Repair, Arc::clone(&fixture.state)).unwrap();
    assert_eq!(
        signer.sign_exact(
            Role::Repair,
            payload(&fixture.state, config.authority.clone(), Role::Repair)
        ),
        Err(SignError::Refused)
    );
    config.revision = 0;
    assert!(NativeSoftwareSigner::load(&config, Role::Repair, Arc::clone(&fixture.state)).is_err());
    config.revision = 7;
    config.policy_digest = [0; 32];
    assert!(NativeSoftwareSigner::load(&config, Role::Repair, Arc::clone(&fixture.state)).is_err());
    config.policy_digest = [8; 32];
    config.public_key = Fixture::key(2).public_key().clone();
    config.authority = AccountId::new(config.public_key.clone());
    assert!(NativeSoftwareSigner::load(&config, Role::Repair, Arc::clone(&fixture.state)).is_err());
    config.public_key = Fixture::key(9).public_key().clone();
    config.authority = AccountId::new(config.public_key.clone());
    #[cfg(unix)]
    {
        fs::set_permissions(
            config.software_credential.as_ref().unwrap(),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(
            NativeSoftwareSigner::load(&config, Role::Repair, Arc::clone(&fixture.state)).is_err()
        );
    }
}

#[test]
fn startup_rejects_validator_key_shared_roles_and_external_adapter_conflicts() {
    let fixture = Fixture::new_at(1_700_000_000_000);
    let (_directory, config) = config(Role::Repair, 2);
    let mut bindings = SorafsNativeTransactionSignerBindings {
        repair: Some(config.clone()),
        ..Default::default()
    };
    let mut deps = IrohaRuntimeDeps::default();
    assert!(
        install_native_software_signers(&bindings, &fixture.state, &config.public_key, &mut deps)
            .is_err()
    );
    bindings.reserve = Some(config.clone());
    assert!(
        install_native_software_signers(
            &bindings,
            &fixture.state,
            Fixture::key(99).public_key(),
            &mut deps
        )
        .is_err()
    );
    bindings.reserve = None;
    deps.sorafs_repair_transaction_signer = Some(Arc::new(
        NativeSoftwareSigner::load(&config, Role::Repair, Arc::clone(&fixture.state)).unwrap(),
    ));
    assert!(
        install_native_software_signers(
            &bindings,
            &fixture.state,
            Fixture::key(99).public_key(),
            &mut deps
        )
        .is_err()
    );
    deps.sorafs_repair_transaction_signer = None;
    install_native_software_signers(
        &bindings,
        &fixture.state,
        Fixture::key(99).public_key(),
        &mut deps,
    )
    .unwrap();
    assert!(deps.sorafs_repair_transaction_signer.is_some());
    assert!(deps.sorafs_proof_outcome_signer.is_none());
    assert!(deps.sorafs_reserve_transaction_signer.is_none());
    assert!(deps.sorafs_orderbook_transaction_signer.is_none());
}

#[test]
fn selected_native_preflight_never_opens_credentials_and_rejects_ambiguous_selection() {
    let (directory, mut binding) = config(Role::Repair, 2);
    binding.software_credential = Some(directory.path().join("does-not-exist"));
    assert!(
        crate::validate_selected_sorafs_native_signer_presence(
            "repair",
            true,
            Some(&binding),
            false
        )
        .is_ok()
    );
    assert!(
        crate::validate_selected_sorafs_native_signer_presence(
            "repair",
            true,
            Some(&binding),
            true
        )
        .is_err()
    );
    assert!(
        crate::validate_selected_sorafs_native_signer_presence(
            "repair",
            false,
            Some(&binding),
            false
        )
        .is_err()
    );
    binding.software_credential = None;
    assert!(
        crate::validate_selected_sorafs_native_signer_presence(
            "repair",
            true,
            Some(&binding),
            false
        )
        .is_err()
    );
    assert!(
        crate::validate_selected_sorafs_native_signer_presence(
            "repair",
            true,
            Some(&binding),
            true
        )
        .is_ok()
    );
}

#[test]
fn qualified_facade_refuses_another_configured_policy_epoch() {
    let fixture = Fixture::new_at(1_700_000_000_000);
    let (_directory, config) = config(Role::Repair, 2);
    let signer =
        NativeSoftwareSigner::load(&config, Role::Repair, Arc::clone(&fixture.state)).unwrap();
    let substituted = Binding::try_new(
        Role::Repair,
        config.handle,
        config.authority,
        config.public_key,
        Qualification::new(config.revision + 1, config.policy_digest),
    )
    .unwrap();
    assert!(
        iroha_torii::qualify_sorafs_repair_transaction_signer_v1(
            *fixture.state.network_id_ref(),
            substituted,
            Arc::new(signer)
        )
        .is_err()
    );
}

#[test]
fn native_software_signer_refuses_shared_credential_and_recovers_exact_private_source() {
    let fixture = Fixture::new_at(1_700_000_000_000);
    let (_directory, binding) = config(Role::Repair, 2);
    let path = binding.software_credential.as_ref().unwrap();
    let link = path.with_file_name("shared-credential");
    fs::hard_link(path, &link).unwrap();
    assert!(
        NativeSoftwareSigner::load(&binding, Role::Repair, Arc::clone(&fixture.state)).is_err()
    );
    fs::remove_file(link).unwrap();
    NativeSoftwareSigner::load(&binding, Role::Repair, Arc::clone(&fixture.state)).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_native_signer_refuses_inherited_dacl_reparse_and_competing_writer() {
    use std::os::windows::fs::symlink_file;
    let fixture = Fixture::new_at(1_700_000_000_000);
    let (_directory, binding) = config(Role::Repair, 2);
    let path = binding.software_credential.as_ref().unwrap();
    let bytes = iroha_fs::read_private(path, 16 * 1024 + 256).unwrap();
    // Ordinary creation does not request the protected current-user DACL installed by
    // PrivateDirectory. Identical secret bytes therefore do not satisfy private custody.
    let inherited = path.with_file_name("inherited-credential");
    fs::write(&inherited, bytes.as_slice()).unwrap();
    let mut other = binding.clone();
    other.software_credential = Some(inherited.clone());
    assert!(matches!(
        crate::runtime_credential::load_bounded_runtime_credential_v1(
            &inherited,
            2,
            16 * 1024 + 256
        ),
        Err(crate::runtime_credential::RuntimeCredentialErrorV1::InvalidSource)
    ));
    assert!(NativeSoftwareSigner::load(&other, Role::Repair, Arc::clone(&fixture.state)).is_err());
    fs::remove_file(inherited).unwrap();

    // Native Windows symlink creation requires its usual privilege or Developer Mode. A
    // fixture creation failure is a test failure, never counted as reparse rejection evidence.
    let linked = path.with_file_name("reparse-credential");
    symlink_file(path, &linked).expect("Windows native reparse fixture privilege");
    other.software_credential = Some(linked.clone());
    assert!(matches!(
        crate::runtime_credential::load_bounded_runtime_credential_v1(&linked, 2, 16 * 1024 + 256),
        Err(crate::runtime_credential::RuntimeCredentialErrorV1::InvalidSource)
    ));
    assert!(NativeSoftwareSigner::load(&other, Role::Repair, Arc::clone(&fixture.state)).is_err());
    fs::remove_file(linked).unwrap();

    // The loader's retained FILE_SHARE_READ handle cannot coexist with a writer, and a
    // retained source refuses write/delete replacement until its original owner is dropped.
    let writer = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    assert!(
        NativeSoftwareSigner::load(&binding, Role::Repair, Arc::clone(&fixture.state)).is_err()
    );
    drop(writer);
    let retained = iroha_fs::RetainedFile::open_private(path).unwrap();
    let write = fs::OpenOptions::new().write(true).open(path).unwrap_err();
    assert!(matches!(write.raw_os_error(), Some(5 | 32)), "{write}");
    let rename = fs::rename(path, path.with_file_name("moved-credential")).unwrap_err();
    assert!(matches!(rename.raw_os_error(), Some(5 | 32)), "{rename}");
    retained.revalidate().unwrap();
    drop(retained);
    NativeSoftwareSigner::load(&binding, Role::Repair, Arc::clone(&fixture.state)).unwrap();
}
