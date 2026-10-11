//! Genuine generated parent composition, exact native children and offline original recovery.
//! The component commits wallet envelopes directly; it does not qualify running peers, the
//! complete HTTP bootstrap, native per-use eligibility, catalog admission or Serving readiness.

use super::*;
use crate::{
    managed::{
        native_operation::{
            MAX_CHECKPOINT_BYTES, now_ms,
            test_support::{
                UnavailablePeers,
                native_fixture::{NativeFixture, quote_instructions},
            },
            verify_carrier,
        },
        service_authority::ServiceAuthority,
    },
    verify::finality::FinalityVerifier,
};
use iroha_core::state::{AllocationBudget, State, StateReadOnly as _, WorldStateSnapshotError};
use iroha_data_model::{
    isi::{InstructionBox, Log},
    sorafs::{
        reserve::{
            ReserveAuthorityPolicyV1,
            account_proof::{ReserveAccountProofExpectedV1, VerifiedReserveAccountStateV1},
        },
        stream_token_custody::proof::{
            StreamTokenCustodyProofRefV1, StreamTokenCustodyProofV1,
            VerifiedStreamTokenCustodyStateV1,
        },
    },
    transaction::{FeePaymentIntent, SignedTransaction},
};
use iroha_primitives::numeric::Quantity;
use sorafs_manifest::signer::custody_control::SignerCustodyPolicyV1;
use std::{num::NonZeroU64, time::Duration};

impl NativeFixture {
    pub(in crate::managed) fn bootstrap_commit(
        &mut self,
        authority: &ServiceAuthority,
        signed: &SignedTransaction,
    ) -> FinalityVerifier {
        let height = self.chain.height() + 1;
        assert_eq!(
            self.chain.commit(vec![signed.clone()]),
            vec![true],
            "{}",
            self.bootstrap_commit_refusal_diagnostic(height),
        );
        let verifier = self.observe(authority);
        let tip = verifier.verified_tip().unwrap();
        assert_eq!(tip.height(), height);
        assert_eq!(tip.block().network_entrypoint_count(), 1);
        assert_eq!(
            tip.block()
                .external_transactions()
                .next()
                .unwrap()
                .encode_wire_v1()
                .unwrap(),
            signed.encode_wire_v1().unwrap()
        );
        assert_eq!(verify_carrier(&verifier, signed).unwrap().height, height);
        verifier
    }

    // Only the failed assertion evaluates this diagnostic. Keep the committed block and its
    // canonical output out of the successful commit/observe stack frame, with no extra clock.
    #[cold]
    #[inline(never)]
    fn bootstrap_commit_refusal_diagnostic(&self, height: u64) -> String {
        let committed = self.chain.committed(height);
        format!(
            "native bootstrap commit refused: height={height}; block_time_ms={}; network_output_at(0).result={:?}",
            committed.block().header().creation_time().as_millis(),
            committed
                .block()
                .network_output_at(0)
                .map(|(_, output)| &output.result),
        )
    }

    pub(in crate::managed) fn bootstrap_custody(
        &self,
        authority: &ServiceAuthority,
        policy: &SignerCustodyPolicyV1,
        checkpoint: &FinalityVerifier,
    ) -> VerifiedStreamTokenCustodyStateV1 {
        self.bootstrap_custody_snapshot(authority, policy, checkpoint, None)
            .unwrap()
    }

    // Three component workers share this one executed State. Unlike four HTTP peers, its
    // cold complete-World publication has one original exclusive current/undo owner.
    // Retry only that exact temporary acquisition refusal, under the caller's deadline.
    pub(in crate::managed) fn bootstrap_custody_before(
        &self,
        authority: &ServiceAuthority,
        policy: &SignerCustodyPolicyV1,
        checkpoint: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<VerifiedStreamTokenCustodyStateV1> {
        require_deadline(deadline)?;
        self.bootstrap_custody_snapshot(authority, policy, checkpoint, Some(deadline))
    }

    fn bootstrap_custody_snapshot(
        &self,
        authority: &ServiceAuthority,
        policy: &SignerCustodyPolicyV1,
        checkpoint: &FinalityVerifier,
        deadline: Option<Instant>,
    ) -> Result<VerifiedStreamTokenCustodyStateV1> {
        let tip = self.chain.committed(self.chain.height());
        let budget = AllocationBudget::new(32 * 1024 * 1024);
        let capture = || {
            self.chain
                .state()
                .with_native_stream_token_custody_snapshot_v1(
                    &tip,
                    authority.provider_id().unwrap(),
                    &budget,
                    |world, owner, current| {
                        norito::encode_canonical(&StreamTokenCustodyProofRefV1::new(
                            world, owner, current,
                        ))
                        .map_err(|error| error.to_string())
                    },
                )
        };
        let bytes = match deadline {
            Some(deadline) => bounded_native_snapshot(&budget, deadline, capture)?,
            None => capture().map_err(|error| crate::managed::Error::Invalid(error.to_string()))?,
        };
        if deadline.is_none() {
            assert_eq!(budget.reserved_bytes(), 0);
        }
        let current = StreamTokenCustodyProofV1::decode_frame(&bytes).unwrap().verify(
            authority.config.network_id,
            authority.provider_id().unwrap(),
            authority.provider_role(crate::localnet::service_authorities::StreamTokenAuthorityRole::IssuerOperator).unwrap(),
            &policy.binding,
            State::native_world_schema_hash_v1().unwrap(),
            &checkpoint.verified_tip().unwrap(),
        ).unwrap();
        if let Some(deadline) = deadline {
            require_deadline(deadline)?;
        }
        Ok(current)
    }

    pub(in crate::managed) fn bootstrap_reserve(
        &self,
        authority: &ServiceAuthority,
        policy: &ReserveAuthorityPolicyV1,
        checkpoint: &FinalityVerifier,
    ) -> VerifiedReserveAccountStateV1 {
        let operator = authority.reserve_operations_config().unwrap();
        let owner = authority.issuer_operator_config().unwrap();
        self.account_proof(&operator.account, authority.provider_id().unwrap())
            .verify(
                &ReserveAccountProofExpectedV1 {
                    chain: &authority.config.chain.to_string(),
                    network_id: authority.config.network_id,
                    operator: &operator.account,
                    provider_id: authority.provider_id().unwrap(),
                    owner: &owner.account,
                    policy,
                    schema: State::native_world_schema_hash_v1().unwrap(),
                },
                &checkpoint.verified_tip().unwrap(),
            )
            .unwrap()
    }
}

// This test transport retries only typed physical State-reader or snapshot-acquisition Busy.
// Every attempt reruns the complete State cut/source/root checks; no partial proof, verifier,
// or deadline crosses a retry. Both variants retain the exact original release observation.
fn bounded_native_snapshot<T>(
    budget: &AllocationBudget,
    deadline: Instant,
    mut capture: impl FnMut() -> std::result::Result<T, WorldStateSnapshotError>,
) -> Result<T> {
    loop {
        require_deadline(deadline)?;
        match capture() {
            Ok(value) => {
                require_deadline(deadline)?;
                return Ok(value);
            }
            Err(WorldStateSnapshotError::Acquisition(
                mv::storage::AdmittedStorageError::Busy { release, .. },
            ))
            | Err(WorldStateSnapshotError::View(iroha_core::state::StateViewError::Busy(
                release,
            ))) => wait_native_snapshot_release(budget, release, deadline)?,
            Err(error) => return Err(crate::managed::Error::Invalid(error.to_string())),
        }
    }
}

fn wait_native_snapshot_release(
    budget: &AllocationBudget,
    release: iroha_allocation::release::ReleaseWait,
    deadline: Instant,
) -> Result<()> {
    use iroha_allocation::{ChargedShared, release::ReleaseRegistration};

    struct SnapshotWaiter(std::thread::Thread);
    impl iroha_allocation::shared::SharedWake for SnapshotWaiter {
        fn wake(&self) {
            self.0.unpark();
        }
    }
    require_deadline(deadline)?;
    // The failed acquisition has dropped its partial World owners. Actual waiter and wake
    // storage use this same finite snapshot pool. Local controls retire before the next
    // attempt; an in-flight release callback may retain its charged wake until it returns.
    let bytes = ReleaseRegistration::allocation_layout()
        .size()
        .checked_add(ChargedShared::<SnapshotWaiter>::allocation_layout().size())
        .ok_or_else(|| invalid("native snapshot waiter layout overflow"))?;
    let mut prepaid = budget
        .try_reserve_bytes(bytes)
        .map_err(|_| invalid("native snapshot waiter admission refused"))?;
    let mut registration = ReleaseRegistration::from_reservation(&mut prepaid)
        .map_err(|_| invalid("native snapshot waiter allocation refused"))?;
    let wake =
        ChargedShared::from_reservation(SnapshotWaiter(std::thread::current()), &mut prepaid)
            .map_err(|_| invalid("native snapshot wake allocation refused"))?;
    drop(prepaid);
    let waker = wake.into_waker();
    let mut context = std::task::Context::from_waker(&waker);
    let mut wait = release.wait_for_release(&mut registration);
    loop {
        require_deadline(deadline)?;
        if std::future::Future::poll(std::pin::Pin::new(&mut wait), &mut context).is_ready() {
            return Ok(());
        }
        // A wake is only permission to reattempt; spurious wakes grant no snapshot result.
        std::thread::park_timeout(deadline.saturating_duration_since(Instant::now()));
    }
}

#[test]
fn native_snapshot_retry_waits_for_original_world_release_and_preserves_refusals() {
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 10_000)).unwrap();
    let state = chain.state();
    let held_budget = AllocationBudget::new(32 * 1024 * 1024);
    let read_budget = AllocationBudget::new(32 * 1024 * 1024);
    let held = state.world.try_block(&held_budget).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let attempts = AtomicUsize::new(0);
    let (observed, original_busy) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            bounded_native_snapshot(&read_budget, deadline, || {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                let result = state.world.try_block(&read_budget);
                if attempt == 0
                    && matches!(result, Err(mv::storage::AdmittedStorageError::Busy { .. }))
                {
                    observed.send(()).unwrap();
                }
                result
                    .map(drop)
                    .map_err(WorldStateSnapshotError::Acquisition)
            })
        });
        original_busy
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        drop(held);
        reader.join().unwrap().unwrap();
    });
    // World drop releases several original roles in order. A genuine wake may precede
    // another role's release, so later Busy results must neither block this observer nor
    // fabricate atomic release of the complete World.
    assert!(attempts.load(Ordering::SeqCst) >= 2);
    assert_eq!(read_budget.reserved_bytes(), 0);
    assert_eq!(held_budget.reserved_bytes(), 0);

    let held = state.world.try_block(&held_budget).unwrap();
    let mut attempts = 0;
    let refused = bounded_native_snapshot(
        &read_budget,
        Instant::now() + Duration::from_secs(1),
        || {
            attempts += 1;
            state
                .world
                .try_block(&read_budget)
                .map(drop)
                .map_err(WorldStateSnapshotError::Acquisition)
        },
    );
    assert!(matches!(
        refused,
        Err(crate::managed::Error::NativeDeadline)
    ));
    assert_eq!(attempts, 1);
    assert_eq!(read_budget.reserved_bytes(), 0);
    drop(held);

    let mut attempts = 0;
    let refused: Result<()> = bounded_native_snapshot(
        &read_budget,
        Instant::now() + Duration::from_secs(5),
        || {
            attempts += 1;
            Err(WorldStateSnapshotError::Invalid(
                "changed certified cut".into(),
            ))
        },
    );
    assert!(
        matches!(refused, Err(crate::managed::Error::Invalid(message)) if message == "changed certified cut")
    );
    assert_eq!(attempts, 1, "ordinary source refusal cannot become a retry");
    assert_eq!(read_budget.reserved_bytes(), 0);
}

fn funding_finalities(report: ProviderFundingProgress) -> [ManagedTransactionFinality; 4] {
    let ProviderFundingProgress::Complete {
        request,
        approval,
        credit,
        capacity,
    } = report
    else {
        panic!("original funding child owners must report historical completion");
    };
    let request = request.unwrap();
    let approval = approval.unwrap();
    assert_eq!(request.movement_id(), approval.request().movement_id());
    assert_eq!(request.amount(), approval.request().amount());
    [*request.original(), *approval.original(), credit, capacity]
}

fn finalities(report: ServiceBootstrapProgress) -> Vec<ManagedTransactionFinality> {
    let ServiceBootstrapProgress::Complete(mut history) = report else {
        panic!("the parent must recover every original child independently");
    };
    assert_completed_funding_history(&mut history)
}

// Exercise the exact opaque completed history produced by the genuine native child owners.
// Refuse changed pair/source/order claims, then restore every original before returning it.
fn assert_completed_funding_history(
    history: &mut HistoricalServiceBootstrap,
) -> Vec<ManagedTransactionFinality> {
    let expected = history.ordered_carriers().unwrap();
    let request = history.providers[0].funding.request.take().unwrap();
    assert!(
        history
            .ordered_carriers()
            .unwrap_err()
            .to_string()
            .contains("bootstrap funding history omits one original")
    );
    history.providers[0].funding.request = Some(request);
    let approval = history.providers[0].funding.approval.take().unwrap();
    assert!(
        history
            .ordered_carriers()
            .unwrap_err()
            .to_string()
            .contains("bootstrap funding history omits one original")
    );
    history.providers[0].funding.approval = Some(approval);
    let (first, rest) = history.providers.split_at_mut(1);
    assert_ne!(
        first[0].funding.request.as_ref().unwrap().movement_id(),
        rest[0].funding.request.as_ref().unwrap().movement_id()
    );
    std::mem::swap(
        &mut first[0].funding.approval,
        &mut rest[0].funding.approval,
    );
    assert!(
        history
            .ordered_carriers()
            .unwrap_err()
            .to_string()
            .contains("bootstrap funding histories differ")
    );
    let (first, rest) = history.providers.split_at_mut(1);
    std::mem::swap(
        &mut first[0].funding.approval,
        &mut rest[0].funding.approval,
    );
    let capacity = history.providers[0].funding.capacity;
    history.providers[0].funding.capacity.height = history.providers[0].funding.credit.height;
    assert!(
        history
            .ordered_carriers()
            .unwrap_err()
            .to_string()
            .contains("original service child carrier predates its prerequisite")
    );
    history.providers[0].funding.capacity = capacity;
    assert_eq!(history.ordered_carriers().unwrap(), expected);
    expected
}

#[test]
fn original_parent_recovers_all_native_children_offline_and_rejects_foreign_late_carrier() {
    // This native phase borrows the single original fixture and appends its authentic children.
    // No provider reports or fixture aggregate cross the function boundary.
    #[inline(never)]
    fn complete_native_providers(
        native: &mut NativeFixture,
        prepared: &PreparedLocalnet,
        original: &Original,
        authorization: &GeneratedBootstrapAuthorization,
        child_options: &BoundedTransactionOptions,
        utc: u64,
        expected: &mut Vec<ManagedTransactionFinality>,
    ) {
        let policies = &original.policies;
        for (slot, selected) in policies.providers.iter().enumerate() {
            // Preserve the real child order while identifying the last completed provider
            // if a bounded native run fails before reaching offline parent recovery.
            eprintln!(
                "parent recovery diagnostic: starting provider {slot} at native height {}",
                native.chain.height()
            );
            let provider = selected.provider_id;
            let mut custody = ManagedStreamTokenCustody::open(prepared, provider).unwrap();
            let configure = if slot == 0 {
                custody.bootstrap_native_configure_generated(
                    native,
                    &selected.custody,
                    &authorization
                        .test_child(Purpose::CustodyConfigure(provider))
                        .unwrap(),
                    child_options,
                )
            } else {
                custody.bootstrap_native_configure(native, &selected.custody, utc, child_options)
            };
            let enroll = custody.bootstrap_native_enroll(
                native,
                &selected.custody,
                selected.initial_enrollment(now_ms().unwrap(), utc).unwrap(),
                child_options,
            );
            assert!(configure.current.is_none() && enroll.current.is_none());
            expected.extend([configure.finalized.unwrap(), enroll.finalized.unwrap()]);
            drop(custody);
            let mut account = ManagedReserveAccountRegistration::open(prepared, provider).unwrap();
            let registered = account.bootstrap_native(
                native,
                &policies.network.reserve,
                &original.underwriting[slot],
                utc,
                child_options,
            );
            assert!(registered.current.is_none());
            expected.push(registered.finalized.unwrap());
            drop(account);
            let mut funding = ProviderFundingBootstrap::open(prepared, provider).unwrap();
            expected.extend(funding_finalities(funding.bootstrap_native(
                native,
                &policies.network.reserve,
                utc,
                child_options,
            )));
            drop(funding);
            let mut ingest =
                ManagedInitialProviderIngestAuthority::open(prepared, provider).unwrap();
            expected.push(
                ingest
                    .bootstrap_native(native, &selected.provider_ingest, utc, child_options)
                    .finalized
                    .unwrap(),
            );
            drop(ingest);
            let mut gateway = ManagedInitialGatewaySetup::open(prepared, provider).unwrap();
            expected.push(
                gateway
                    .bootstrap_native(native, &selected.gateway, utc, child_options)
                    .finalized
                    .unwrap(),
            );
            drop(gateway);
            eprintln!(
                "parent recovery diagnostic: completed provider {slot} at native height {}",
                native.chain.height()
            );
        }
    }

    // All original offline recovery, refusal, restoration and worker cleanup stays sequential.
    // Borrow the existing snapshots so complete parent progress stays local to this phase.
    #[inline(never)]
    #[expect(
        clippy::too_many_arguments,
        reason = "Borrow the original owners without constructing another fixture aggregate"
    )]
    fn assert_original_offline_recovery(
        prepared: &PreparedLocalnet,
        original: &Original,
        authorization: &GeneratedBootstrapAuthorization,
        directory: &PrivateDirectory,
        parent_bytes: &[u8],
        requested_utc: u64,
        previous_terms: &crate::managed::native_operation::Terms,
        expected: &[ManagedTransactionFinality],
        enrollment_roots: &[(
            PrivateDirectory,
            PrivateDirectory,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        )],
        retained: &[(PrivateDirectory, Vec<u8>, Vec<u8>)],
        temporary: &tempfile::TempDir,
        peers: &mut UnavailablePeers,
    ) {
        let policies = &original.policies;
        for _ in 0..2 {
            let mut owner = ManagedServiceBootstrap::open(prepared).unwrap();
            let fresh = original
                .fees
                .options(Instant::now() + Duration::from_secs(30));
            let recovery_started = Instant::now();
            assert_eq!(finalities(owner.recover(fresh.deadline).unwrap()), expected);
            eprintln!(
                "parent offline recovery timing: recover_elapsed_ms={} fresh_remaining_ms={} original_signing_utc_remaining_ms={:?}",
                recovery_started.elapsed().as_millis(),
                fresh
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
                now_ms().map(|now| authorization
                    .test_terms()
                    .signing_deadline_unix_ms
                    .saturating_sub(now)),
            );
            eprintln!(
                "parent offline recovery timing: before advance fresh_remaining_ms={}",
                fresh
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            );
            let advance_started = Instant::now();
            let (_, passes) = phases::test_passes::count(|| {
                assert_eq!(
                    finalities(owner.advance(authorization, fresh.deadline).unwrap()),
                    expected
                );
            });
            assert_eq!(passes, [1, 0, 0]); // One fresh local graph, no dispatch graph.
            eprintln!(
                "parent offline recovery timing: advance_elapsed_ms={} fresh_remaining_ms={}",
                advance_started.elapsed().as_millis(),
                fresh
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            );
            let epoch_inventory = directory
                .open_child("epochs")
                .unwrap()
                .entries(128)
                .unwrap();
            assert!(owner.authorize_test_startup(&fresh).unwrap().is_none());
            assert_eq!(
                directory
                    .open_child("epochs")
                    .unwrap()
                    .entries(128)
                    .unwrap(),
                epoch_inventory
            );
            assert_eq!(
                encode(&owner.selected_policies().unwrap(), MAX_ORIGINAL_BYTES).unwrap(),
                encode(policies, MAX_ORIGINAL_BYTES).unwrap()
            );
            assert!(previous_terms.matches(requested_utc + 1, &fresh).is_err());
            let mut wrong = original.fees.options(fresh.deadline);
            wrong.fee_payment = FeePaymentIntent::authority(Vec::new(), NonZeroU64::new(65));
            assert!(owner.authorize_test_startup(&wrong).is_err());
            wrong = original.fees.options(fresh.deadline);
            wrong.max_total_fees.clear();
            assert!(owner.authorize_test_startup(&wrong).is_err());
            assert!(peers.requests.lock().unwrap().is_empty());
        }
        assert_eq!(
            directory
                .read("original.nrt", MAX_ORIGINAL_BYTES)
                .unwrap()
                .as_slice(),
            parent_bytes
        );
        for (owner, root, selection, anchor, reference) in enrollment_roots {
            assert_eq!(
                &std::fs::read(root.path().join("original.nrt")).unwrap(),
                selection
            );
            assert_eq!(
                &std::fs::read(root.path().join("anchor.nrt")).unwrap(),
                anchor
            );
            assert_eq!(
                &std::fs::read(owner.path().join("enroll-selection.nrt")).unwrap(),
                reference
            );
        }
        for (child, original, operation) in retained {
            assert_eq!(
                &std::fs::read(child.path().join("original.nrt")).unwrap(),
                original
            );
            let transaction = child
                .open_child("attempts")
                .unwrap()
                .open_child("0001")
                .unwrap()
                .open_child("transaction")
                .unwrap();
            assert_eq!(
                &std::fs::read(transaction.path().join("operation.json")).unwrap(),
                operation
            );
            assert!(!transaction.path().join("submission.json").exists());
        }
        let gateway = retained[27]
            .0
            .open_child("attempts")
            .unwrap()
            .open_child("0001")
            .unwrap();
        let reputation = retained[28]
            .0
            .open_child("attempts")
            .unwrap()
            .open_child("0001")
            .unwrap();
        let original_carrier = reputation
            .read("carrier.nrt", MAX_CHECKPOINT_BYTES)
            .unwrap();
        let foreign_carrier = gateway.read("carrier.nrt", MAX_CHECKPOINT_BYTES).unwrap();
        reputation
            .write_atomic("carrier.nrt", &foreign_carrier, PublishMode::Replace)
            .unwrap();
        let mut owner = ManagedServiceBootstrap::open(prepared).unwrap();
        assert!(
            owner
                .recover(Instant::now() + Duration::from_secs(30))
                .is_err()
        );
        assert!(peers.requests.lock().unwrap().is_empty());
        reputation
            .write_atomic("carrier.nrt", &[0xA5], PublishMode::Replace)
            .unwrap();
        assert!(
            owner
                .recover(Instant::now() + Duration::from_secs(30))
                .is_err()
        );
        assert!(peers.requests.lock().unwrap().is_empty());
        reputation
            .write_atomic("carrier.nrt", &original_carrier, PublishMode::Replace)
            .unwrap();
        assert_eq!(
            finalities(
                owner
                    .recover(Instant::now() + Duration::from_secs(30))
                    .unwrap()
            ),
            expected
        );
        assert!(peers.requests.lock().unwrap().is_empty());
        // Remove only parent custody after all 29 genuine wallet/native originals exist. Neither
        // a missing initial directory nor an empty replacement may reconstruct the paid parent.
        let saved = temporary.path().join("retained-parent-original");
        std::fs::rename(directory.path(), &saved).unwrap();
        for initial_exists in [false, true] {
            if initial_exists {
                owner.authority.directory.ensure_child("initial").unwrap();
            }
            let names = owner.authority.directory.entries(4).unwrap();
            let fresh = original
                .fees
                .options(Instant::now() + Duration::from_secs(30));
            assert!(owner.authorize_test_startup(&fresh).is_err());
            assert_eq!(owner.authority.directory.entries(4).unwrap(), names);
            if initial_exists {
                require_empty(&owner.authority.directory.open_child("initial").unwrap()).unwrap();
            } else {
                assert!(!owner.authority.directory.path().join("initial").exists());
            }
            assert!(peers.requests.lock().unwrap().is_empty());
            for (owner, root, selection, anchor, reference) in enrollment_roots {
                assert_eq!(
                    &std::fs::read(root.path().join("original.nrt")).unwrap(),
                    selection
                );
                assert_eq!(
                    &std::fs::read(root.path().join("anchor.nrt")).unwrap(),
                    anchor
                );
                assert_eq!(
                    &std::fs::read(owner.path().join("enroll-selection.nrt")).unwrap(),
                    reference
                );
            }
            for (child, original, operation) in retained {
                assert_eq!(
                    &std::fs::read(child.path().join("original.nrt")).unwrap(),
                    original
                );
                assert_eq!(
                    &std::fs::read(
                        child
                            .path()
                            .join("attempts/0001/transaction/operation.json")
                    )
                    .unwrap(),
                    operation
                );
            }
        }
        std::fs::remove_dir(owner.authority.directory.path().join("initial")).unwrap();
        std::fs::rename(&saved, owner.authority.directory.path().join("initial")).unwrap();
        assert_eq!(
            finalities(
                owner
                    .recover(Instant::now() + Duration::from_secs(30))
                    .unwrap()
            ),
            expected
        );
        assert!(peers.requests.lock().unwrap().is_empty());
        peers.finish();
    }

    // Inspect the actual signed carrier and committed charge, not a synthetic fee estimate.
    #[inline(never)]
    fn assert_native_fee(
        native: &NativeFixture,
        height: u64,
        options: &BoundedTransactionOptions,
        instruction_count: usize,
        gas: u64,
    ) {
        let committed = native.chain.committed(height);
        let block = committed.block();
        let input = block.network_entrypoint_at(0).unwrap();
        let iroha_data_model::transaction::TransactionEntrypoint::External(signed) = input else {
            panic!("bootstrap must retain its real wallet-signed external input");
        };
        let iroha_data_model::transaction::Executable::Instructions(instructions) =
            signed.instructions()
        else {
            panic!("bootstrap must execute its exact native instruction vector");
        };
        assert_eq!(instructions.len(), instruction_count);
        assert_eq!(iroha_core::gas::meter_instructions(instructions), gas);
        assert_eq!(
            signed.fee_payment_intent().gas_limit(),
            options.fee_payment.gas_limit()
        );
        let (_, output) = block.network_output_at(0).unwrap();
        let receipt = output
            .result
            .nexus_fee_receipt()
            .expect("actual native fee settlement");
        receipt.validate_for_network_input(input, height).unwrap();
        assert_eq!(receipt.schedule.instruction_count, instruction_count as u64);
        assert_eq!(receipt.schedule.gas_used, gas);
        assert!(receipt.fee_amount <= *options.max_total_fees.get(&receipt.fee_asset_id).unwrap());
        let view = native.chain.state().view();
        assert_eq!(
            receipt.schedule.per_instruction_fee,
            view.nexus().fees.per_instruction_fee
        );
        assert_eq!(
            receipt.schedule.per_gas_unit_fee,
            view.nexus().fees.per_gas_unit_fee
        );
    }
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "native-service-bootstrap",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let mut owner = ManagedServiceBootstrap::open(&prepared).unwrap();
    let deadline = Instant::now() + Duration::from_secs(600);
    // Exercise the supported generated native-only intent. Exact quote charge maxima and the
    // immutable parent fee ceiling still apply; gateway's three ISIs meter 320 gas.
    let options = generated_fees(deadline).unwrap().options(deadline);
    assert!(options.fee_payment.gas_limit().is_none());
    let mut authorization = owner.authorize_test_startup(&options).unwrap().unwrap();
    let requested_utc = authorization.test_terms().requested_deadline_unix_ms;
    let utc = authorization.test_terms().signing_deadline_unix_ms;
    assert!(utc <= requested_utc);
    let directory = owner.authority.directory.open_child("initial").unwrap();
    let original = read_original(&directory, &owner.authority)
        .unwrap()
        .unwrap();
    let parent_bytes = encode(&original, MAX_ORIGINAL_BYTES).unwrap();
    let child_options = original.fees.options(options.deadline);
    let policies = &original.policies;
    let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
    let log = quote_instructions(
        &native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "parent bootstrap prerequisites".into(),
        ))],
    );
    native.bootstrap_commit(&owner.authority, &log);
    drop(ports);

    let mut reserve = ManagedInitialReservePolicy::open(&prepared).unwrap();
    let reserve_result = reserve.bootstrap_native_generated(
        &mut native,
        &policies.network.reserve,
        &authorization.test_child(Purpose::ReservePolicy).unwrap(),
        &child_options,
    );
    assert!(reserve_result.current.is_none() && reserve_result.activation().is_none());
    let mut expected = vec![reserve_result.finalized.unwrap()];
    drop(reserve);
    let previous_terms = authorization.test_terms().clone();
    authorization = owner.authorize_test_startup(&options).unwrap().unwrap();
    assert_eq!(authorization.test_ordinal(), 2);
    assert_eq!(
        directory
            .open_child("epochs")
            .unwrap()
            .entries(128)
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        directory
            .read("original.nrt", MAX_ORIGINAL_BYTES)
            .unwrap()
            .as_slice(),
        parent_bytes.as_slice()
    );
    assert!(previous_terms.fees == authorization.test_terms().fees);
    complete_native_providers(
        &mut native,
        &prepared,
        &original,
        &authorization,
        &child_options,
        utc,
        &mut expected,
    );
    let mut reputation = ManagedInitialReputationPolicy::open(&prepared).unwrap();
    expected.push(
        reputation
            .bootstrap_native(
                &mut native,
                &policies.gateway_labels(),
                &policies.network.reputation,
                utc,
                &child_options,
            )
            .finalized
            .unwrap(),
    );
    drop(reputation);
    assert_eq!(expected.len(), 29);
    assert_eq!(
        expected
            .iter()
            .map(|original| original.height)
            .collect::<Vec<_>>(),
        (3..=31).collect::<Vec<_>>()
    );
    for (index, finalized) in expected.iter().enumerate() {
        // Reserve, every single-ISI provider child and reputation use the fixed native cost;
        // each exact gateway vector also grants its operator and observer permissions.
        let gateway = matches!(index, 9 | 18 | 27);
        assert_native_fee(
            &native,
            finalized.height,
            &options,
            if gateway { 3 } else { 1 },
            if gateway { 320 } else { 128 },
        );
    }
    drop(owner);

    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let runtime = generation
        .open_child("runtime")
        .unwrap()
        .open_child("service-operations")
        .unwrap();
    let mut children: Vec<(PrivateDirectory, &str)> = vec![(
        runtime
            .open_child("network")
            .unwrap()
            .open_child("initial-reserve-policy")
            .unwrap(),
        "set",
    )];
    for slot in 0..3 {
        let scope = runtime
            .open_child("providers")
            .unwrap()
            .open_child(&slot.to_string())
            .unwrap();
        for (owner, purpose) in [
            ("stream-token-custody", "configure"),
            ("stream-token-custody", "enroll"),
            ("reserve-account-registration", "register"),
            ("reserve-top-up-request", "request"),
            ("reserve-top-up-approval", "approval"),
            ("initial-provider-credit", "install"),
            ("provider-capacity-declaration", "declare"),
            ("initial-provider-ingest-authority", "setup"),
            ("initial-gateway-setup", "setup"),
        ] {
            children.push((scope.open_child(owner).unwrap(), purpose));
        }
    }
    children.push((
        runtime
            .open_child("network")
            .unwrap()
            .open_child("initial-reputation-policy")
            .unwrap(),
        "setup",
    ));
    let mut enrollment_roots = Vec::new();
    let retained: Vec<_> = children
        .into_iter()
        .map(|(owner, purpose)| {
            let root = owner.open_child(purpose).unwrap();
            let child = if purpose == "enroll" {
                let selection = std::fs::read(root.path().join("original.nrt")).unwrap();
                let anchor = std::fs::read(root.path().join("anchor.nrt")).unwrap();
                let reference = std::fs::read(owner.path().join("enroll-selection.nrt")).unwrap();
                let body = root
                    .open_child("bodies")
                    .unwrap()
                    .open_child("0001")
                    .unwrap();
                enrollment_roots.push((owner, root, selection, anchor, reference));
                body
            } else {
                root
            };
            let original = std::fs::read(child.path().join("original.nrt")).unwrap();
            let transaction = child
                .open_child("attempts")
                .unwrap()
                .open_child("0001")
                .unwrap()
                .open_child("transaction")
                .unwrap();
            let operation = std::fs::read(transaction.path().join("operation.json")).unwrap();
            assert!(!transaction.path().join("submission.json").exists());
            (child, original, operation)
        })
        .collect();
    let mut peers = UnavailablePeers::start(&prepared);
    assert_original_offline_recovery(
        &prepared,
        &original,
        &authorization,
        &directory,
        &parent_bytes,
        requested_utc,
        &previous_terms,
        &expected,
        &enrollment_roots,
        &retained,
        &temporary,
        &mut peers,
    );
}

#[test]
fn generated_runtime_fee_ceiling_pays_real_native_isi_fee_from_original_role() {
    use crate::managed::native_operation::test_support::native_fixture::balance;
    use iroha_data_model::{asset::AssetId, transaction::TransactionBuilder};
    let _guard = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let ports = crate::managed::LocalnetPorts::reserve().unwrap();
    let prepared = crate::localnet::prepare_localnet_at(
        "native-runtime-fees",
        &temporary.path().join("generation"),
        &ports,
        crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities,
        None,
    )
    .unwrap();
    let owner = ManagedServiceBootstrap::open(&prepared).unwrap();
    let policies = GeneratedServicePolicies::select(&owner.authority).unwrap();
    let mut native = NativeFixture::from_generated(&prepared, &owner.authority);
    let provider = policies.providers[0].provider_id;
    let selected = ServiceAuthority::open_provider(
        &prepared,
        provider,
        super::super::service_authority::ProviderPurpose::ProviderCapacityDeclaration,
    )
    .unwrap();
    let issuer = selected.issuer_operator_config().unwrap();
    let asset = AssetId::new(
        policies.network.reserve.asset_definition.clone(),
        issuer.account.clone(),
    );
    let before = balance(native.chain.state(), &asset);
    let mut builder = TransactionBuilder::new(
        issuer.network_id,
        issuer.account.clone(),
        policies.network.runtime_fee_payment.clone(),
    )
    .with_instructions([Log::new(
        iroha_data_model::Level::INFO,
        "generated runtime fee component".into(),
    )]);
    builder.set_creation_time(Duration::from_millis(
        now_ms()
            .unwrap()
            .max(native.chain.genesis().header().creation_time_ms + 1),
    ));
    builder.set_ttl(Duration::from_secs(300));
    let signed = builder.try_sign(issuer.key_pair.private_key()).unwrap();
    assert_eq!(native.chain.commit(vec![signed.clone()]), vec![true]);
    let observed = native.observe(&owner.authority);
    assert_eq!(
        observed
            .verified_tip()
            .unwrap()
            .block()
            .network_entrypoint_count(),
        1
    );
    let original = verify_carrier(&observed, &signed).unwrap();
    assert_eq!(original.height, 2);
    let paid = before
        .checked_sub(&balance(native.chain.state(), &asset))
        .unwrap();
    assert!(!paid.is_zero());
    assert!(paid <= Quantity::from(1_u64));
    assert_eq!(
        signed.fee_payment_intent(),
        &policies.network.runtime_fee_payment
    );
    // Real generated native fee execution, not full stream-token operation or Serving evidence.
}

#[path = "native_tests/reader_busy_tests.rs"]
mod reader_busy_tests;
