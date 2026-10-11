//! Genuine generated owner-signed Set and original carrier recovery. Component execution only.
use super::tests::{fixture, ingest, options};
use super::*;
use crate::managed::native_operation::Fees;
use crate::managed::native_operation::{
    test_support::{
        UnavailablePeers,
        native_fixture::{NativeFixture, balance, quote_instructions},
    },
    verify_carrier,
};
use iroha_core::state::{StorageReadOnly as _, WorldReadOnly};
use iroha_data_model::{
    asset::{AssetDefinitionId, AssetId},
    isi::{InstructionBox, Log, sorafs::SetProviderIngestCompletionAuthority},
};
use iroha_primitives::numeric::Quantity;
use std::time::Duration;

fn native_fixture(prepared: &PreparedLocalnet, owner: &Setup) -> NativeFixture {
    let mut native = NativeFixture::from_generated(prepared, &owner.authority);
    let log = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "initial provider ingest authority prerequisite".into(),
        ))],
    );
    let wire = log.encode_wire_v1().unwrap();
    assert_eq!(native.chain.commit(vec![log]), vec![true]);
    let observed = native.observe(&owner.authority);
    let tip = observed.verified_tip().unwrap();
    assert_eq!(tip.height(), 2);
    assert_eq!(tip.block().network_entrypoint_count(), 1);
    assert_eq!(
        tip.block()
            .external_transactions()
            .next()
            .unwrap()
            .encode_wire_v1()
            .unwrap(),
        wire
    );
    native
}

#[test]
fn generated_provider_owner_pays_for_exact_set_and_original_carrier_survives_replay_and_outage() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let mut owner = ManagedInitialProviderIngestAuthority::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let binding = ingest(&owner.inner.authority);
    let mut native = native_fixture(&prepared, &owner.inner);
    let provider = owner.inner.authority.provider_id().unwrap();
    assert!(
        native
            .chain
            .state()
            .view()
            .world()
            .provider_ingest_completion_authorities()
            .get(&provider)
            .is_none()
    );
    let asset = AssetDefinitionId::parse_address_literal(
        crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
    )
    .unwrap();
    let owner_asset = AssetId::new(asset.clone(), binding.provider_owner.clone());
    let manager_asset = AssetId::new(asset.clone(), owner.inner.authority.config.account.clone());
    let signer_asset = AssetId::new(asset.clone(), binding.completion_signer.clone());
    let balances = [&owner_asset, &manager_asset, &signer_asset]
        .map(|asset| balance(native.chain.state(), asset));
    let mut opts = options();
    opts.deadline = Instant::now() + Duration::from_secs(600);
    opts.max_total_fees.insert(asset, Quantity::from(1u64));
    let utc = now_ms().unwrap() + 600_000;
    let result = owner.bootstrap_native(&mut native, &binding, utc, &opts);
    assert_eq!(result.transaction_status, OperationStatus::Applied);
    let finalized = result.finalized.unwrap();
    assert_eq!(finalized.height, 3);
    let directory = owner.inner.authority.directory.open_child("setup").unwrap();
    let original = journal::required_original(&directory, owner.inner.purpose().unwrap()).unwrap();
    let signed = owner
        .inner
        .verify_wallet(original.directory(), &original, opts.deadline)
        .unwrap();
    assert_eq!(signed.authority(), &binding.provider_owner);
    assert_ne!(signed.authority(), &binding.completion_signer);
    let observed = native.observe(&owner.inner.authority);
    assert_eq!(verify_carrier(&observed, &signed).unwrap(), finalized);
    assert_eq!(
        observed
            .verified_tip()
            .unwrap()
            .block()
            .network_entrypoint_count(),
        1
    );
    assert_eq!(
        native
            .chain
            .state()
            .view()
            .world()
            .provider_ingest_completion_authorities()
            .get(&provider),
        Some(&binding)
    );
    let paid = balances[0]
        .checked_sub(&balance(native.chain.state(), &owner_asset))
        .unwrap();
    assert!(!paid.is_zero());
    assert!(paid <= Quantity::from(1u64));
    assert_eq!(balance(native.chain.state(), &manager_asset), balances[1]);
    assert_eq!(balance(native.chain.state(), &signer_asset), balances[2]);
    // Native exact-value replay succeeds, but its later signed envelope is not the original.
    let replay = quote_instructions(
        &native,
        &owner.inner.wallet_config().unwrap(),
        [InstructionBox::from(
            SetProviderIngestCompletionAuthority::new(provider, None, binding.clone()),
        )],
    );
    assert_ne!(
        replay.encode_wire_v1().unwrap(),
        signed.encode_wire_v1().unwrap()
    );
    assert_eq!(native.chain.commit(vec![replay.clone()]), vec![true]);
    let replay_carrier = native.observe(&owner.inner.authority);
    assert_eq!(verify_carrier(&replay_carrier, &replay).unwrap().height, 4);
    assert!(verify_carrier(&replay_carrier, &signed).is_err());
    assert_eq!(
        native
            .chain
            .state()
            .view()
            .world()
            .provider_ingest_completion_authorities()
            .get(&provider),
        Some(&binding)
    );
    let original_bytes = std::fs::read(directory.path().join("original.nrt")).unwrap();
    let operation_bytes = std::fs::read(
        original
            .directory()
            .path()
            .join("transaction/operation.json"),
    )
    .unwrap();
    assert!(
        !original
            .directory()
            .path()
            .join("transaction/submission.json")
            .exists(),
        "component helper executes exact wallet wire through native chain, not HTTP POST"
    );
    let mut peers = UnavailablePeers::start(&prepared);
    for _ in 0..2 {
        drop(owner);
        owner = ManagedInitialProviderIngestAuthority::open(
            &prepared,
            crate::managed::native_operation::test_support::provider_id(&prepared, 0),
        )
        .unwrap();
        let recovered = owner
            .recover_selected_if_present(
                &binding,
                &Fees::from_options(&opts).unwrap(),
                opts.deadline,
            )
            .unwrap()
            .unwrap();
        assert_eq!(recovered.finalized, Some(finalized));
        assert_eq!(
            owner.recover(opts.deadline).unwrap().finalized,
            Some(finalized)
        );
        assert!(peers.requests.lock().unwrap().is_empty());
        let mut wrong = binding.clone();
        wrong.signer_policy.policy_digest[0] ^= 1;
        assert!(
            owner
                .recover_selected_if_present(
                    &wrong,
                    &Fees::from_options(&opts).unwrap(),
                    opts.deadline
                )
                .is_err()
        );
    }
    peers.finish();
    assert_eq!(
        std::fs::read(directory.path().join("original.nrt")).unwrap(),
        original_bytes
    );
    assert_eq!(
        std::fs::read(
            original
                .directory()
                .path()
                .join("transaction/operation.json")
        )
        .unwrap(),
        operation_bytes
    );
}

#[test]
fn genuine_ingest_original_expiry_never_creates_wallet_or_requests_http() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let mut owner = ManagedInitialProviderIngestAuthority::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let native = native_fixture(&prepared, &owner.inner);
    let checkpoint = native.observe(&owner.inner.authority);
    let binding = ingest(&owner.inner.authority);
    let original = Original {
        intent: Intent::provider_ingest(&owner.inner.authority, &binding).unwrap(),
        checkpoint: checkpoint_bytes(&checkpoint).unwrap(),
    };
    owner.inner.validate_original(&original).unwrap();
    let directory = owner
        .inner
        .authority
        .directory
        .ensure_child("setup")
        .unwrap();
    let original = super::tests::retain_explicit_request(
        &owner.inner,
        &directory,
        &original,
        || now_ms().unwrap() + 500,
        &options(),
    );
    let bytes = std::fs::read(directory.path().join("original.nrt")).unwrap();
    let prefix_names = [
        "authorization.nrt",
        "observation.nrt",
        "committed.nrt",
        "transaction/preparation.json",
    ];
    let prefix =
        prefix_names.map(|name| std::fs::read(original.directory().path().join(name)).unwrap());
    let end = Instant::now() + Duration::from_secs(2);
    while now_ms().unwrap() < original.terms.signing_deadline_unix_ms {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut peers = UnavailablePeers::start(&prepared);
    for mode in [Mode::ObserveOnly, Mode::SubmitOriginal] {
        let progress = owner
            .inner
            .advance(Instant::now() + Duration::from_secs(30), mode)
            .unwrap();
        assert_eq!(progress.transaction_status, OperationStatus::Expired);
        assert!(progress.finalized.is_none());
        assert!(
            !original
                .directory()
                .path()
                .join("transaction/payload.json")
                .exists()
        );
        assert!(
            !original
                .directory()
                .path()
                .join("transaction/operation.json")
                .exists()
        );
    }
    for (name, bytes) in prefix_names.into_iter().zip(prefix) {
        assert_eq!(
            std::fs::read(original.directory().path().join(name)).unwrap(),
            bytes
        );
    }
    assert!(
        !original
            .directory()
            .path()
            .join("transaction/submission.json")
            .exists()
    );
    peers.finish();
    assert!(peers.requests.lock().unwrap().is_empty());
    assert_eq!(
        std::fs::read(directory.path().join("original.nrt")).unwrap(),
        bytes
    );
}

#[test]
fn original_setup_checkpoint_requires_exact_native_source_and_restoration_retry() {
    let _guard = crate::managed::native_test_guard();
    let (_root, prepared) = fixture();
    let owner = ManagedInitialProviderIngestAuthority::open(
        &prepared,
        crate::managed::native_operation::test_support::provider_id(&prepared, 0),
    )
    .unwrap();
    let native = native_fixture(&prepared, &owner.inner);
    let checkpoint = native.observe(&owner.inner.authority);
    assert_eq!(checkpoint.checkpoint().height(), 2);
    let mut original = Original {
        intent: Intent::provider_ingest(&owner.inner.authority, &ingest(&owner.inner.authority))
            .unwrap(),
        checkpoint: checkpoint_bytes(&checkpoint).unwrap(),
    };
    let exact_source = original.checkpoint.clone();
    owner.inner.validate_original(&original).unwrap();
    // Preserve a genuine original source, offering only its truncated canonical bytes.
    assert!(original.checkpoint.pop().is_some());
    original.validate().unwrap();
    assert!(owner.inner.validate_original(&original).is_err());
    assert_eq!(native.chain.height(), 2);
    original.checkpoint = exact_source;
    owner.inner.validate_original(&original).unwrap();
    assert_eq!(original.checkpoint, checkpoint_bytes(&checkpoint).unwrap());
    assert_eq!(native.chain.height(), 2);
}
