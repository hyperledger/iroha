//! Genuine paid provider branches may interleave and share a certified carrier block.
//! The fixture commits exact wallet envelopes directly; it does not qualify HTTP bootstrap,
//! running peers, current service eligibility or catalog readiness.

use super::*;
use crate::managed::{
    native_operation::{
        now_ms,
        test_support::{
            UnavailablePeers,
            native_fixture::{NativeFixture, quote_instructions},
        },
        verify_carrier,
    },
    service_authority::{ProviderPurpose, ServiceChildInventory},
};
use iroha_data_model::{
    isi::{InstructionBox, Log},
    transaction::SignedTransaction,
};
use std::{collections::BTreeSet, time::Duration};

fn complete_funding(progress: ProviderFundingProgress) -> [ManagedTransactionFinality; 4] {
    let ProviderFundingProgress::Complete {
        request,
        approval,
        credit,
        capacity,
    } = progress
    else {
        panic!("the genuine funding owner must recover all original children");
    };
    let request = request.unwrap();
    let approval = approval.unwrap();
    assert_eq!(request.movement_id(), approval.request().movement_id());
    assert_eq!(request.amount(), approval.request().amount());
    [*request.original(), *approval.original(), credit, capacity]
}

fn pending(progress: &ServiceBootstrapProgress, expected: ServiceBootstrapStep) {
    match progress {
        ServiceBootstrapProgress::Pending { step, status } => {
            assert_eq!(*step, expected);
            assert_eq!(*status, OperationStatus::Absent);
        }
        _ => panic!("the actual earliest unfinished branch must remain pending"),
    }
}

#[test]
fn native_provider_dag_recovers_interleaved_and_same_block_originals() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "native-provider-dag",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
    let deadline = Instant::now() + Duration::from_secs(600);
    let options = generated_fees(deadline).unwrap().options(deadline);
    let authorization = parent.authorize_test_startup(&options).unwrap().unwrap();
    let utc = authorization.test_terms().signing_deadline_unix_ms;
    let directory = parent.authority.directory.open_child("initial").unwrap();
    let original = read_original(&directory, &parent.authority)
        .unwrap()
        .unwrap();
    let parent_bytes = directory.read("original.nrt", MAX_ORIGINAL_BYTES).unwrap();
    let epochs = directory
        .open_child("epochs")
        .unwrap()
        .entries(128)
        .unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &parent.authority);
    let first = quote_instructions(
        &native,
        &parent.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "provider DAG prerequisites".into(),
        ))],
    );
    native.bootstrap_commit(&parent.authority, &first);
    drop(ports);
    let mut reserve = ManagedInitialReservePolicy::open(&prepared).unwrap();
    let reserve_policy = reserve
        .bootstrap_native_generated(
            &mut native,
            &original.policies.network.reserve,
            &authorization.test_child(Purpose::ReservePolicy).unwrap(),
            &options,
        )
        .finalized
        .unwrap();
    drop(reserve);
    let mut expected = vec![reserve_policy];
    let mut branch_carriers: [Vec<ManagedTransactionFinality>; 3] =
        std::array::from_fn(|_| Vec::new());

    // p0 is paused after Configure while p1 advances through its own enrollment/account.
    // The earliest outer Pending report must not discard p1's actual dependency frontier.
    for slot in [0, 1] {
        let selected = &original.policies.providers[slot];
        let mut custody = ManagedStreamTokenCustody::open(&prepared, selected.provider_id).unwrap();
        let configured =
            custody.bootstrap_native_configure(&mut native, &selected.custody, utc, &options);
        assert!(configured.current.is_none());
        branch_carriers[slot].push(configured.finalized.unwrap());
        if slot == 1 {
            let enrolled = custody.bootstrap_native_enroll(
                &mut native,
                &selected.custody,
                selected.initial_enrollment(now_ms().unwrap(), utc).unwrap(),
                &options,
            );
            assert!(enrolled.current.is_none());
            branch_carriers[slot].push(enrolled.finalized.unwrap());
        }
    }
    let selected = &original.policies.providers[1];
    let mut account =
        ManagedReserveAccountRegistration::open(&prepared, selected.provider_id).unwrap();
    branch_carriers[1].push(
        account
            .bootstrap_native(
                &mut native,
                &original.policies.network.reserve,
                &original.underwriting[1],
                utc,
                &options,
            )
            .finalized
            .unwrap(),
    );
    drop(account);
    {
        let mut peers = UnavailablePeers::start(&prepared);
        let outcome = parent.run(deadline, Mode::Local, None).unwrap();
        pending(
            &outcome.progress,
            ServiceBootstrapStep::CustodyEnrollment {
                provider_id: original.policies.providers[0].provider_id,
            },
        );
        assert!(outcome.dependencies.reserve_complete);
        assert_eq!(
            outcome.dependencies.providers,
            [
                Some(ServiceBootstrapStep::CustodyEnrollment {
                    provider_id: original.policies.providers[0].provider_id
                }),
                Some(ServiceBootstrapStep::ProviderFunding {
                    provider_id: original.policies.providers[1].provider_id
                }),
                Some(ServiceBootstrapStep::CustodyPolicy {
                    provider_id: original.policies.providers[2].provider_id
                }),
            ]
        );
        parent
            .validate_dependency_inventory(&outcome.dependencies)
            .unwrap();
        pending(
            &parent.recover(deadline).unwrap(),
            ServiceBootstrapStep::CustodyEnrollment {
                provider_id: original.policies.providers[0].provider_id,
            },
        );

        // Later material in p0 remains forbidden even while p1's independent work is admitted.
        let later = ServiceAuthority::open_provider(
            &prepared,
            original.policies.providers[0].provider_id,
            ProviderPurpose::InitialProviderIngestAuthority,
        )
        .unwrap();
        let leaf = later.directory.ensure_child("setup").unwrap();
        leaf.write_atomic(
            "original.nrt",
            b"unexecuted later original",
            PublishMode::CreateNew,
        )
        .unwrap();
        drop(later);
        assert!(
            parent
                .validate_dependency_inventory(&outcome.dependencies)
                .is_err()
        );
        assert_eq!(
            leaf.read("original.nrt", 64).unwrap().as_slice(),
            b"unexecuted later original"
        );
        std::fs::remove_file(leaf.path().join("original.nrt")).unwrap();
        parent
            .validate_dependency_inventory(&outcome.dependencies)
            .unwrap();
        assert!(peers.requests.lock().unwrap().is_empty());
        peers.finish();
    }

    // Complete the missing prefixes without serializing one whole provider before the next.
    for slot in [2, 0] {
        let selected = &original.policies.providers[slot];
        let mut custody = ManagedStreamTokenCustody::open(&prepared, selected.provider_id).unwrap();
        if slot == 2 {
            branch_carriers[slot].push(
                custody
                    .bootstrap_native_configure(&mut native, &selected.custody, utc, &options)
                    .finalized
                    .unwrap(),
            );
        }
        branch_carriers[slot].push(
            custody
                .bootstrap_native_enroll(
                    &mut native,
                    &selected.custody,
                    selected.initial_enrollment(now_ms().unwrap(), utc).unwrap(),
                    &options,
                )
                .finalized
                .unwrap(),
        );
    }
    for slot in [2, 0] {
        let selected = &original.policies.providers[slot];
        let mut account =
            ManagedReserveAccountRegistration::open(&prepared, selected.provider_id).unwrap();
        branch_carriers[slot].push(
            account
                .bootstrap_native(
                    &mut native,
                    &original.policies.network.reserve,
                    &original.underwriting[slot],
                    utc,
                    &options,
                )
                .finalized
                .unwrap(),
        );
    }
    for slot in [1, 2, 0] {
        let selected = &original.policies.providers[slot];
        let mut funding = ProviderFundingBootstrap::open(&prepared, selected.provider_id).unwrap();
        branch_carriers[slot].extend(complete_funding(funding.bootstrap_native(
            &mut native,
            &original.policies.network.reserve,
            utc,
            &options,
        )));
    }
    for slot in [2, 0, 1] {
        let selected = &original.policies.providers[slot];
        let mut ingest =
            ManagedInitialProviderIngestAuthority::open(&prepared, selected.provider_id).unwrap();
        branch_carriers[slot].push(
            ingest
                .bootstrap_native(&mut native, &selected.provider_ingest, utc, &options)
                .finalized
                .unwrap(),
        );
    }

    // All3 independent Gateway requests have the same prior native cut and one real block.
    let mut signed = Vec::<SignedTransaction>::with_capacity(3);
    for selected in &original.policies.providers {
        let gateway = ManagedInitialGatewaySetup::open(&prepared, selected.provider_id).unwrap();
        signed.push(gateway.bootstrap_native_prepare(&native, &selected.gateway, utc, &options));
    }
    let height = native.chain.height() + 1;
    assert_eq!(native.chain.commit(signed.clone()), vec![true; 3]);
    let carrier = native.observe(&parent.authority);
    let tip = carrier.verified_tip().unwrap();
    assert_eq!(tip.height(), height);
    assert_eq!(tip.block().network_entrypoint_count(), 3);
    assert_eq!(
        tip.block()
            .external_transactions()
            .map(|tx| tx.encode_wire_v1().unwrap())
            .collect::<Vec<_>>(),
        signed
            .iter()
            .map(|tx| tx.encode_wire_v1().unwrap())
            .collect::<Vec<_>>()
    );
    for (slot, selected) in original.policies.providers.iter().enumerate() {
        let input = tip.block().network_entrypoint_at(slot).unwrap();
        let (input_index, output) = tip
            .block()
            .network_output_at(u32::try_from(slot).unwrap())
            .unwrap();
        assert_eq!(usize::try_from(input_index).unwrap(), slot);
        let receipt = output
            .result
            .nexus_fee_receipt()
            .expect("actual native fee settlement");
        receipt.validate_for_network_input(input, height).unwrap();
        assert!(!receipt.fee_amount.is_zero());
        assert!(receipt.fee_amount <= *options.max_total_fees.get(&receipt.fee_asset_id).unwrap());
        let mut gateway =
            ManagedInitialGatewaySetup::open(&prepared, selected.provider_id).unwrap();
        let finalized = verify_carrier(&carrier, &signed[slot]).unwrap();
        gateway.bootstrap_native_retain(&carrier, deadline);
        let progress = gateway
            .recover_selected_if_present(&selected.gateway, &original.fees, deadline)
            .unwrap()
            .unwrap();
        assert_eq!(progress.finalized, Some(finalized));
        branch_carriers[slot].push(finalized);
    }
    let shared: Vec<_> = branch_carriers
        .iter()
        .map(|branch| *branch.last().unwrap())
        .collect();
    assert!(shared.iter().all(
        |finalized| finalized.height == height && finalized.block_hash == shared[0].block_hash
    ));
    assert_eq!(
        shared
            .iter()
            .map(|finalized| finalized.transaction_hash)
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    for branch in &branch_carriers {
        expected.extend(branch);
    }
    let mut reputation = ManagedInitialReputationPolicy::open(&prepared).unwrap();
    expected.push(
        reputation
            .bootstrap_native(
                &mut native,
                &original.policies.gateway_labels(),
                &original.policies.network.reputation,
                utc,
                &options,
            )
            .finalized
            .unwrap(),
    );
    drop(reputation);
    assert_eq!(expected.len(), 29);
    expected.sort_by_key(|finalized| finalized.height);
    assert_eq!(
        expected
            .iter()
            .filter(|finalized| finalized.height == height)
            .count(),
        3
    );
    assert!(branch_carriers[1].last().unwrap().height > branch_carriers[0][0].height);
    assert!(branch_carriers[1][2].height < branch_carriers[0][1].height);

    let mut peers = UnavailablePeers::start(&prepared);
    let ServiceBootstrapProgress::Complete(mut history) = parent.recover(deadline).unwrap() else {
        panic!("the original DAG must independently recover all paid children");
    };
    assert_eq!(history.ordered_carriers().unwrap(), expected);
    assert_eq!(
        history
            .ordered_carriers()
            .unwrap()
            .iter()
            .filter(|finalized| finalized.height == height)
            .count(),
        3
    );
    // Each slot and transaction stays distinct; equal certified block coordinates are allowed.
    let provider = history.providers[1].provider_id;
    history.providers[1].provider_id = history.providers[0].provider_id;
    assert!(history.ordered_carriers().is_err());
    history.providers[1].provider_id = provider;
    let gateway = history.providers[1].gateway;
    let copied = history.providers[0].gateway;
    require_after(&copied, history.providers[1].provider_ingest.height).unwrap();
    require_after(&history.reputation, copied.height).unwrap();
    assert_eq!(copied.height, gateway.height);
    history.providers[1].gateway = copied;
    assert!(history.ordered_carriers().is_err());
    history.providers[1].gateway = gateway;
    assert_eq!(history.ordered_carriers().unwrap(), expected);
    // Within a branch every prerequisite stays strict, even though independent branches tie.
    let configure = history.providers[0].custody_policy;
    history.providers[0].custody_policy.height = history.reserve_policy.height;
    assert!(history.ordered_carriers().is_err());
    history.providers[0].custody_policy = configure;
    let enrollment = history.providers[0].custody_enrollment;
    history.providers[0].custody_enrollment.height = history.providers[0].custody_policy.height;
    assert!(history.ordered_carriers().is_err());
    history.providers[0].custody_enrollment = enrollment;
    let account = history.providers[0].reserve_account;
    history.providers[0].reserve_account.height = enrollment.height - 1;
    assert!(history.ordered_carriers().is_err());
    history.providers[0].reserve_account = account;
    let capacity = history.providers[0].funding.capacity;
    history.providers[0].funding.capacity.height = history.providers[0].funding.credit.height;
    assert!(history.ordered_carriers().is_err());
    history.providers[0].funding.capacity = capacity;
    let reputation = history.reputation;
    history.reputation.height = height;
    assert!(history.ordered_carriers().is_err());
    history.reputation = reputation;
    let request = history.providers[0].funding.request.take().unwrap();
    assert!(history.ordered_carriers().is_err());
    history.providers[0].funding.request = Some(request);
    let (first, rest) = history.providers.split_at_mut(1);
    assert_ne!(
        first[0].funding.request.as_ref().unwrap().movement_id(),
        rest[0].funding.request.as_ref().unwrap().movement_id()
    );
    std::mem::swap(
        &mut first[0].funding.approval,
        &mut rest[0].funding.approval,
    );
    assert!(history.ordered_carriers().is_err());
    let (first, rest) = history.providers.split_at_mut(1);
    std::mem::swap(
        &mut first[0].funding.approval,
        &mut rest[0].funding.approval,
    );
    assert_eq!(history.ordered_carriers().unwrap(), expected);
    assert_eq!(
        directory.read("original.nrt", MAX_ORIGINAL_BYTES).unwrap(),
        parent_bytes
    );
    assert_eq!(
        directory
            .open_child("epochs")
            .unwrap()
            .entries(128)
            .unwrap(),
        epochs
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn provider_frontiers_bind_exact_original_slots_and_fresh_absence() {
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "provider-frontier-shape",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let options = generated_fees(deadline).unwrap().options(deadline);
    let _authorization = parent.authorize_test_startup(&options).unwrap().unwrap();
    let directory = parent.authority.directory.open_child("initial").unwrap();
    let original = read_original(&directory, &parent.authority)
        .unwrap()
        .unwrap();
    let bytes = directory.read("original.nrt", MAX_ORIGINAL_BYTES).unwrap();
    let epochs = directory
        .open_child("epochs")
        .unwrap()
        .entries(128)
        .unwrap();
    drop(ports);
    let mut peers = UnavailablePeers::start(&prepared);
    let mut outcome = parent.run(deadline, Mode::Local, None).unwrap();
    pending(&outcome.progress, ServiceBootstrapStep::ReservePolicy);
    assert!(!outcome.dependencies.reserve_complete && !outcome.dependencies.reputation_complete);
    assert_eq!(
        outcome.dependencies.providers,
        std::array::from_fn(|slot| {
            Some(ServiceBootstrapStep::CustodyPolicy {
                provider_id: original.policies.providers[slot].provider_id,
            })
        })
    );
    parent
        .validate_dependency_inventory(&outcome.dependencies)
        .unwrap();
    let first = outcome.dependencies.providers[0];
    outcome.dependencies.providers[0] = outcome.dependencies.providers[1];
    assert!(
        parent
            .validate_dependency_inventory(&outcome.dependencies)
            .is_err()
    );
    outcome.dependencies.providers[0] = first;
    outcome.dependencies.providers[0] = None;
    assert!(
        parent
            .validate_dependency_inventory(&outcome.dependencies)
            .is_err()
    );
    outcome.dependencies.providers[0] = first;
    outcome.dependencies.reputation_complete = true;
    assert!(
        parent
            .validate_dependency_inventory(&outcome.dependencies)
            .is_err()
    );
    outcome.dependencies.reputation_complete = false;
    parent
        .validate_dependency_inventory(&outcome.dependencies)
        .unwrap();

    assert!(
        ServiceChildInventory::begin(&parent.authority)
            .unwrap()
            .bootstrap_provider_purposes_absent()
            .unwrap()
    );
    // A real retained empty child owner is harmless to census, but it closes fresh-only scheduling.
    let child = ServiceAuthority::open_provider(
        &prepared,
        original.policies.providers[2].provider_id,
        ProviderPurpose::InitialGatewaySetup,
    )
    .unwrap();
    let lock_identity = iroha_fs::FileIdentity::of(&child._lock).unwrap();
    let retained = child.directory.retain().unwrap();
    drop(child);
    parent
        .validate_dependency_inventory(&outcome.dependencies)
        .unwrap();
    assert!(
        !ServiceChildInventory::begin(&parent.authority)
            .unwrap()
            .bootstrap_provider_purposes_absent()
            .unwrap()
    );
    let reopened = ServiceAuthority::open_provider_existing_from_original(
        &parent.authority,
        original.policies.providers[2].provider_id,
        ProviderPurpose::InitialGatewaySetup,
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        iroha_fs::FileIdentity::of(&reopened._lock).unwrap(),
        lock_identity
    );
    reopened.directory.revalidate().unwrap();
    retained.revalidate().unwrap();
    assert_eq!(
        directory.read("original.nrt", MAX_ORIGINAL_BYTES).unwrap(),
        bytes
    );
    assert_eq!(
        directory
            .open_child("epochs")
            .unwrap()
            .entries(128)
            .unwrap(),
        epochs
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
