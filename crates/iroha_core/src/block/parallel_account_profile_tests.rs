// Included in block::valid::tests. Exercise real parallel static validation, then
// the canonical sequential output owner; no retired detached execution counters.

std::thread_local! {
    static ACCOUNT_PROFILE_VALIDATION_TEST_SCOPE: std::cell::RefCell<
        Option<iroha_data_model::account::address::ChainDiscriminantGuard>
    > = const { std::cell::RefCell::new(None) };
}

std::thread_local! {
    static ACCOUNT_PROFILE_VALIDATION_OBSERVER: std::cell::RefCell<
        Option<Arc<AccountProfileValidationObserver>>
    > = const { std::cell::RefCell::new(None) };
}

pub(super) fn account_profile_validation_observer() -> Option<Arc<AccountProfileValidationObserver>>
{
    ACCOUNT_PROFILE_VALIDATION_OBSERVER.with(|slot| slot.borrow().clone())
}

struct AccountProfileValidationObservationScope;

impl AccountProfileValidationObservationScope {
    fn enter(observer: Arc<AccountProfileValidationObserver>) -> Self {
        ACCOUNT_PROFILE_VALIDATION_OBSERVER.with(|slot| {
            assert!(slot.borrow_mut().replace(observer).is_none());
        });
        Self
    }
}

impl Drop for AccountProfileValidationObservationScope {
    fn drop(&mut self) {
        ACCOUNT_PROFILE_VALIDATION_OBSERVER.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[derive(Debug)]
struct AccountProfileValidationVisit {
    index: usize,
    thread: std::thread::ThreadId,
    worker: Option<usize>,
    inherited: u16,
    active: u16,
}

pub(super) struct AccountProfileValidationObserver {
    worker_discriminant: Option<u16>,
    caller: std::thread::ThreadId,
    visits: std::sync::Mutex<Vec<AccountProfileValidationVisit>>,
    arrived: std::sync::Condvar,
}

impl AccountProfileValidationObserver {
    fn new(worker_discriminant: Option<u16>) -> Self {
        Self {
            worker_discriminant,
            caller: std::thread::current().id(),
            visits: std::sync::Mutex::new(Vec::new()),
            arrived: std::sync::Condvar::new(),
        }
    }

    // Called only from the actual validate_tx closure, after its profile guard.
    pub(super) fn observe(&self, index: usize, inherited: u16, active: u16) {
        let mut visits = self.visits.lock().expect("profile observations");
        visits.push(AccountProfileValidationVisit {
            index,
            thread: std::thread::current().id(),
            worker: rayon::current_thread_index(),
            inherited,
            active,
        });
        self.arrived.notify_all();
        if self.worker_discriminant.is_some() {
            // Force both real validation jobs to overlap. A bounded wait fails
            // a serialized dispatch instead of hanging the test or passing on
            // unrelated pool broadcasts.
            let (visits, _) = self
                .arrived
                .wait_timeout_while(visits, Duration::from_secs(5), |visits| visits.len() < 2)
                .expect("wait for both static validation jobs");
            assert_eq!(
                visits.len(),
                2,
                "both actual validation workers must arrive"
            );
        }
    }

    fn assert_complete(&self) {
        let mut visits = self.visits.lock().expect("profile observations");
        visits.sort_by_key(|visit| visit.index);
        assert_eq!(visits.len(), 2, "exact static validation census");
        assert_eq!(
            visits.iter().map(|visit| visit.index).collect::<Vec<_>>(),
            [0, 1]
        );
        for visit in visits.iter() {
            assert_eq!(
                visit.active, 369,
                "actual validation uses the caller profile"
            );
            assert_eq!(visit.inherited, self.worker_discriminant.unwrap_or(369));
            if self.worker_discriminant.is_some() {
                assert_ne!(
                    visit.thread, self.caller,
                    "validation must execute on a worker"
                );
            } else {
                assert_eq!(
                    visit.thread, self.caller,
                    "serial validation stays on the caller"
                );
                assert_eq!(visit.worker, None);
            }
        }
        if self.worker_discriminant.is_some() {
            assert_ne!(
                visits[0].thread, visits[1].thread,
                "both owned workers execute input validation"
            );
            assert_eq!(
                visits
                    .iter()
                    .map(|visit| visit.worker)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([Some(0), Some(1)])
            );
        }
    }
}

struct AccountProfileValidationPoolScope {
    pool: Arc<rayon::ThreadPool>,
}

impl AccountProfileValidationPoolScope {
    fn enter(pool: Arc<rayon::ThreadPool>, discriminant: u16) -> Self {
        pool.broadcast(|_| {
            ACCOUNT_PROFILE_VALIDATION_TEST_SCOPE.with(|slot| {
                let mut slot = slot.borrow_mut();
                assert!(
                    slot.is_none(),
                    "fresh fixture pool must have no retained scope"
                );
                *slot = Some(
                    iroha_data_model::account::address::ChainDiscriminantGuard::enter(discriminant),
                );
            });
        });
        Self { pool }
    }

    fn assert_profile(&self, expected: u16) {
        assert_eq!(self.pool.current_num_threads(), 2);
        let profiles = self
            .pool
            .broadcast(|_| iroha_data_model::account::address::chain_discriminant());
        assert_eq!(profiles, vec![expected; 2]);
    }
}

impl Drop for AccountProfileValidationPoolScope {
    fn drop(&mut self) {
        self.pool.broadcast(|_| {
            ACCOUNT_PROFILE_VALIDATION_TEST_SCOPE.with(|slot| {
                // Drop each guard on its owning worker; never mutate the process default.
                slot.borrow_mut().take();
            });
        });
    }
}

struct AccountProfileValidationFixture {
    authority: AccountId,
    signer: KeyPair,
    targets: [AccountId; 2],
}

impl AccountProfileValidationFixture {
    fn new() -> Self {
        let (authority, signer) = gen_account_in("wonderland");
        let targets = [
            gen_account_in("wonderland").0,
            gen_account_in("wonderland").0,
        ];
        assert!(targets.iter().all(|target| target != &authority));
        assert_ne!(targets[0], targets[1]);
        Self {
            authority,
            signer,
            targets,
        }
    }

    fn execute(
        &self,
        permission_discriminant: u16,
        worker_discriminant: Option<u16>,
    ) -> (
        Vec<TransactionResultInner>,
        Vec<Option<iroha_primitives::json::Json>>,
    ) {
        use iroha_data_model::{
            account::address::{ChainDiscriminantGuard, chain_discriminant},
            permission::{Permission, Permissions},
        };
        use iroha_executor_data_model::permission::account::CanModifyAccountMetadata;

        let _profile = ChainDiscriminantGuard::enter(369);
        let permissions = {
            let _permission_profile = ChainDiscriminantGuard::enter(permission_discriminant);
            self.targets
                .iter()
                .map(|account| {
                    Permission::from(CanModifyAccountMetadata {
                        account: account.clone(),
                    })
                })
                .collect::<Vec<_>>()
        };
        for (permission, target) in permissions.iter().zip(&self.targets) {
            let decoded = CanModifyAccountMetadata::try_from(permission);
            if permission_discriminant == 369 {
                assert_eq!(
                    decoded.expect("selected permission profile").account,
                    *target
                );
            } else {
                assert!(
                    decoded.is_err(),
                    "foreign I105 payload must fail native decoding"
                );
            }
        }
        let domain_id = DomainId::try_new("wonderland", "universal").expect("domain");
        let domain = Domain::new(domain_id).build(&self.authority);
        let accounts = std::iter::once(&self.authority)
            .chain(self.targets.iter())
            .map(|account| Account::new(account.clone()).build(account));
        let mut world = World::with([domain], accounts, []);
        world
            .account_permissions_mut_for_testing()
            .insert(self.authority.clone(), Permissions::from_iter(permissions));
        let mut config = crate::sumeragi::test_chain::TestChainConfig::new(world, 1);
        config.chain_id = ChainId::from("fc56984b-2be7-431d-840e-21514d1883f0");
        config.pipeline.workers = if worker_discriminant.is_some() { 2 } else { 1 };
        let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(config)
            .expect("original native genesis for account-profile validation");
        let state = chain.state();

        let key: Name = "delegated_profile_marker".parse().expect("metadata key");
        let accepted = self
            .targets
            .iter()
            .enumerate()
            .map(|(index, target)| {
                let mut transaction = TransactionBuilder::new(
                    state.network_id,
                    self.authority.clone(),
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                );
                transaction.set_creation_time(Duration::from_millis(
                    u64::try_from(index).expect("two transactions") + 2,
                ));
                let signed = transaction
                    .with_instructions([iroha_data_model::isi::SetKeyValue::account(
                        target.clone(),
                        key.clone(),
                        iroha_primitives::json::Json::new("delegated under 369"),
                    )])
                    .sign(self.signer.private_key());
                AcceptedTransaction::new_unchecked(Cow::Owned(signed))
            })
            .collect();
        let (_clock, time_source) = TimeSource::new_mock(Duration::from_millis(10));
        let block = BlockBuilder::new_with_time_source(accepted, time_source)
            .chain(
                1,
                state
                    .view()
                    .latest_block()
                    .expect("original block read attempt")
                    .as_deref(),
            )
            .sign(self.signer.private_key())
            .unpack(|_| {});
        let block: SignedBlock = block.into();
        assert_eq!(
            block.network_entrypoint_count(),
            2,
            "exact signed input census"
        );
        // Isolate the production snapshot validator from unrelated consensus
        // header admission, as the neighboring stateless snapshot tests do.
        let view = state.query_view();
        let static_data = {
            let pipeline_cfg = view.pipeline().clone();
            StaticValidationData {
                expected_block_height: 2,
                max_clock_drift: view.world().parameters().sumeragi().max_clock_drift(),
                tx_params: view.world().parameters().transaction(),
                crypto_policy: Some(
                    view.world()
                        .transaction_admission_parameters()
                        .require_crypto_policy()
                        .expect("original signed profile policy"),
                ),
                pipeline_parallelism: crate::state::PipelineParallelism::new(&pipeline_cfg),
                pipeline_cfg,
                aggregate_lane: view.nexus().routing_policy.default_lane,
            }
        };
        let pool_scope = worker_discriminant.map(|discriminant| {
            // Poison the actual pool used by the static snapshot, not State's
            // independent pool or a synthetic worker callback.
            let pool = static_data
                .pipeline_parallelism
                .pool()
                .expect("two-worker static validation pool");
            let scope = AccountProfileValidationPoolScope::enter(pool, discriminant);
            scope.assert_profile(discriminant);
            scope
        });
        let observer = Arc::new(AccountProfileValidationObserver::new(worker_discriminant));
        let observation = AccountProfileValidationObservationScope::enter(Arc::clone(&observer));
        let prepared = ValidBlock::prepare_external_transactions(&block);
        assert_eq!(prepared.len(), 2);
        let committed = vec![None; 2];
        #[cfg(feature = "telemetry")]
        let metrics = Some(&state.telemetry);
        #[cfg(not(feature = "telemetry"))]
        let metrics = ();
        ValidBlock::validate_static_with_snapshot(
            &block,
            &state.network_id,
            &self.authority,
            &static_data,
            &committed,
            &committed,
            &prepared,
            metrics,
        )
        .expect("both signed inputs must pass the actual static validation owner");
        drop(observation);
        observer.assert_complete();
        if let Some(scope) = pool_scope.as_ref() {
            scope.assert_profile(worker_discriminant.expect("parallel profile"));
        }
        drop(static_data);
        drop(view);
        let (mut state_block, recorder) = state
            .block_with_recorded_pristine_carrier_stage(
                &block,
                |_| Ok::<(), String>(()),
                |error| error,
            )
            .expect("signed profile inputs retain prepaid membership custody before effects");
        assert_eq!(
            chain_discriminant(),
            369,
            "worker setup must not alter the caller"
        );
        // Consume the original recorder and signed source allocation after
        // actual signed-input static validation, without resetting either owner.
        let valid = ValidBlock::validate_recorded_unchecked(block, &mut state_block, recorder)
            .unpack(|_| {});
        let block = valid.as_ref();
        state_block
            .verify_execution_output_seal(block)
            .expect("outputs retain their actual State execution owner");
        assert_eq!(
            block.execution_outputs().len(),
            2,
            "exact sealed output census"
        );
        let results = block
            .network_entrypoints()
            .enumerate()
            .map(|(index, entrypoint)| {
                let (output_index, output) = block
                    .network_output_at(
                        u32::try_from(index).expect("fixture Network index fits u32"),
                    )
                    .expect("every queried input has its explicit Network output");
                assert_eq!(usize::try_from(output_index).unwrap(), index);
                (index, entrypoint, &output.result)
            })
            .map(|(_, _, result)| result.0.clone())
            .collect::<Vec<_>>();
        let values = self
            .targets
            .iter()
            .map(|target| {
                state_block
                    .world
                    .map_account(target, |account| {
                        account.value().metadata().get(&key).cloned()
                    })
                    .expect("target account remains present")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            chain_discriminant(),
            369,
            "execution must restore caller profile"
        );
        drop(pool_scope);
        (results, values)
    }
}

#[test]
fn account_profile_validation_preserves_delegated_metadata_results() {
    let fixture = AccountProfileValidationFixture::new();
    let serial = fixture.execute(369, None);
    assert!(
        serial.0.iter().all(Result::is_ok),
        "serial delegation must succeed: {:?}",
        serial.0
    );
    assert_eq!(
        serial.1,
        vec![Some(iroha_primitives::json::Json::new("delegated under 369")); 2]
    );
    for worker_profile in [753, 777] {
        let parallel = fixture.execute(369, Some(worker_profile));
        assert_eq!(
            parallel, serial,
            "static worker profile {worker_profile} changed canonical execution"
        );
    }
}

#[test]
fn account_profile_validation_rejects_foreign_permission_payloads() {
    let fixture = AccountProfileValidationFixture::new();
    for foreign_profile in [753, 777] {
        let serial = fixture.execute(foreign_profile, None);
        assert!(
            serial.0.iter().all(|result| matches!(
                result,
                Err(TransactionRejectionReason::Validation(
                    iroha_data_model::ValidationFail::NotPermitted(_)
                ))
            )),
            "foreign permission must reject for its native policy reason: {:?}",
            serial.0
        );
        assert_eq!(serial.1, vec![None; 2]);
        let parallel = fixture.execute(foreign_profile, Some(foreign_profile));
        assert_eq!(
            parallel, serial,
            "worker profile must not authorize a foreign permission"
        );
    }
}
