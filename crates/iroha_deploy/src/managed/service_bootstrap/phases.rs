//! Reserve-gated independent provider chains, each retaining its sole native child owners.

use super::{super::service_policies::GeneratedProviderPolicies, *};
use crate::managed::service_authority::CheckpointImportScope;
#[cfg(test)]
use crate::managed::service_authority::profile_validation_test_support as profiles;

/// Only completed original evidence advances to the next child; all other progress returns intact.
enum Phase<T> {
    Complete(T),
    Incomplete(Incomplete),
}

/// An unfinished child cannot carry the complete aggregate history.
enum Incomplete {
    Pending {
        step: ServiceBootstrapStep,
        status: OperationStatus,
    },
    Funding {
        provider_id: ProviderId,
        progress: ProviderFundingProgress,
    },
}

impl Incomplete {
    fn step(&self) -> ServiceBootstrapStep {
        match self {
            Self::Pending { step, .. } => *step,
            Self::Funding { provider_id, .. } => ServiceBootstrapStep::ProviderFunding {
                provider_id: *provider_id,
            },
        }
    }

    /// Form the outer report only after the native child owner has returned.
    #[inline(never)]
    fn into_progress(self) -> Result<ServiceBootstrapProgress> {
        Ok(match self {
            Self::Pending { step, status } => ServiceBootstrapProgress::Pending { step, status },
            Self::Funding {
                provider_id,
                progress,
            } => ServiceBootstrapProgress::Funding {
                provider_id,
                progress,
            },
        })
    }
}

fn absent<T>(step: ServiceBootstrapStep) -> Result<Phase<T>> {
    Ok(Phase::Incomplete(Incomplete::Pending {
        step,
        status: OperationStatus::Absent,
    }))
}

// Each existing admission authenticates ordinary native absence without creating material;
// the scheduling census supplies no authority. Only the live startup branch may then create.
// Advance has no import scope; active/owned originals use their full standalone producer.
macro_rules! open_child {
    ($run:expr, $owner:ty, $step:expr $(, $provider:expr)?) => {{
        let existing = <$owner>::open_existing_from_original(
            $run.authority $(, $provider)?, $run.checkpoint_import_scope.as_ref()
        );
        match existing? {
            Some(owner) => owner,
            None if $run.may_submit()? => {
                <$owner>::open_from_original($run.authority $(, $provider)?)?
            }
            None => return absent($step),
        }
    }};
}

// Test-only observations stay in the original phase frame. Counters are thread-local;
// the parallel branch never reports a parent-thread count as the aggregate worker count.
macro_rules! observed_phase {
        ($run:expr, $call:expr, $stage:literal, $slot:expr) => {{
            #[cfg(not(test))]
            {
                $call
            }
            #[cfg(test)]
            {
                let stage_started = Instant::now();
                let profiles_start = profiles::snapshot();
                let imports_start = ServiceAuthority::test_graph_import_snapshot();
                let mode = match $run.mode {
                    Mode::Local => "Local",
                    Mode::Recover => "Recover",
                    Mode::Advance => "Advance",
                };
                eprintln!(
                    "bootstrap phase timing: mode={} stage={} provider_slot={:?} begin",
                    mode, $stage, $slot
                );
                let result = $call;
                eprintln!(
                    "bootstrap phase timing: mode={} stage={} provider_slot={:?} end elapsed_ms={} remaining_ms={} result={} full_profile_validations={:?} cold_checkpoint_imports={:?}",
                    mode,
                    $stage,
                    $slot,
                    stage_started.elapsed().as_millis(),
                    $run.deadline.saturating_duration_since(Instant::now()).as_millis(),
                    match &result {
                        Ok(Phase::Complete(_)) => "complete",
                        Ok(Phase::Incomplete(_)) => "incomplete",
                        Err(_) => "error",
                    },
                    profiles::snapshot().zip(profiles_start).and_then(|(now, start)| now.checked_sub(start)),
                    ServiceAuthority::test_graph_import_snapshot().zip(imports_start).and_then(|(now, start)| now.checked_sub(start)),
                );
                result
            }
        }};
    }

struct Run<'a> {
    authority: &'a ServiceAuthority,
    original: &'a Original,
    deadline: Instant,
    mode: Mode,
    authorization: Option<&'a GeneratedBootstrapAuthorization>,
    checkpoint_import_scope: Option<CheckpointImportScope>,
}

/// Recover each provider frontier independently after reserve finality, retaining every
/// original child and requiring all gateways before the reputation phase.
pub(super) fn run(
    authority: &ServiceAuthority,
    original: &Original,
    deadline: Instant,
    mode: Mode,
    authorization: Option<&GeneratedBootstrapAuthorization>,
) -> Result<RunOutcome> {
    #[cfg(test)]
    test_passes::record(mode);
    // One joined advance may borrow exact immutable receipt certificates for new child cursors.
    // Every child still obtains its own fresh challenge, quorum and current predecessor proof.
    let _certificate_scope = if mode == Mode::Advance {
        Some(authority.begin_certificate_scope()?)
    } else {
        None
    };
    let checkpoint_import_scope = if mode == Mode::Advance {
        None
    } else {
        CheckpointImportScope::for_original(authority)
    };
    let run = Run {
        authority,
        original,
        deadline,
        mode,
        authorization,
        checkpoint_import_scope,
    };
    // Preserve any enclosing counter owner. These guards retain only scalar previous values.
    #[cfg(test)]
    let _profile_counts = profiles::snapshot()
        .is_none()
        .then(profiles::Counter::begin);
    #[cfg(test)]
    let _import_counts = ServiceAuthority::test_graph_import_snapshot()
        .is_none()
        .then(ServiceAuthority::test_begin_graph_import_counts);
    let reserve = observed_phase!(run, run.reserve(), "reserve", None::<usize>)?;
    let reserve_policy = match reserve {
        Phase::Complete(value) => value,
        Phase::Incomplete(progress) => {
            return Ok(RunOutcome {
                progress: progress.into_progress()?,
                dependencies: DependencyFrontiers::before_reserve(&original.policies),
            });
        }
    };
    // Absence is scheduling evidence only. Ordinary native child admission remains mandatory
    // if material appears after the census; shared authorization claims are independently fenced.
    let parallel = mode == Mode::Advance
        && !norito::core::decode_limits_active()
        && crate::managed::service_authority::ServiceChildInventory::begin(authority)?
            .bootstrap_provider_purposes_absent()?;
    let results: [Result<Phase<HistoricalProviderBootstrap>>; 3] = if parallel {
        // Always join every successfully spawned child, including after launch failures or panics.
        // No detached tasks, new deadlines, stack override or provider-specific authorization epoch.
        std::thread::scope(|scope| {
            let handles: [_; 3] = std::array::from_fn(|slot| {
                let run = &run;
                let selected = &original.policies.providers[slot];
                std::thread::Builder::new()
                    .name(format!("bootstrap-provider-{slot}"))
                    .spawn_scoped(scope, move || {
                        retry_fresh_provider(run, || {
                            run.provider(slot, selected, reserve_policy.height)
                        })
                    })
            });
            handles.map(|handle| match handle {
                Ok(handle) => handle
                    .join()
                    .unwrap_or_else(|_| Err(invalid("bootstrap provider worker panicked"))),
                Err(error) => Err(error.into()),
            })
        })
    } else {
        [
            Ok(run.provider(0, &original.policies.providers[0], reserve_policy.height)?),
            Ok(run.provider(1, &original.policies.providers[1], reserve_policy.height)?),
            Ok(run.provider(2, &original.policies.providers[2], reserve_policy.height)?),
        ]
    };
    let mut histories = Vec::with_capacity(3);
    let mut first_incomplete = None;
    let mut dependencies = DependencyFrontiers {
        reserve_complete: true,
        reputation_complete: false,
        providers: [None; 3],
    };
    let mut maximum_gateway_height = reserve_policy.height;
    for (slot, result) in results.into_iter().enumerate() {
        match result? {
            Phase::Complete(history) => {
                maximum_gateway_height = maximum_gateway_height.max(history.gateway.height);
                histories.push(history);
            }
            Phase::Incomplete(progress) => {
                dependencies.providers[slot] = Some(progress.step());
                if first_incomplete.is_none() {
                    first_incomplete = Some(progress);
                }
            }
        }
    }
    if let Some(progress) = first_incomplete {
        return Ok(RunOutcome {
            progress: progress.into_progress()?,
            dependencies,
        });
    }
    let reputation = observed_phase!(
        run,
        run.reputation(reserve_policy, histories, maximum_gateway_height),
        "reputation",
        None::<usize>
    )?;
    dependencies.reputation_complete = matches!(&reputation, Phase::Complete(_));
    Ok(RunOutcome {
        progress: match reputation {
            Phase::Complete(history) => ServiceBootstrapProgress::Complete(history),
            Phase::Incomplete(progress) => progress.into_progress()?,
        },
        dependencies,
    })
}

// A transient failure or incomplete observation belongs to this already-admitted worker.
// Waiting for another provider's whole chain before retrying can consume the shared startup
// interval. Reopen only the same native child owners under the same live epoch and clocks;
// resumed/active-decode serial scheduling above keeps its original admission policy.
fn retry_fresh_provider<T>(
    run: &Run<'_>,
    mut advance: impl FnMut() -> Result<Phase<T>>,
) -> Result<Phase<T>> {
    let authorization = run
        .authorization
        .filter(|_| run.mode == Mode::Advance)
        .ok_or_else(|| invalid("fresh provider retry requires original startup authorization"))?;
    loop {
        authorization.validate(run.authority, run.deadline)?;
        match advance() {
            Ok(complete @ Phase::Complete(_)) => {
                authorization.validate(run.authority, run.deadline)?;
                return Ok(complete);
            }
            Err(error @ crate::managed::Error::Bootstrap(_)) => return Err(error),
            Ok(Phase::Incomplete(_)) | Err(_) => {}
        }
        let deadline = authorization.validate(run.authority, run.deadline)?;
        std::thread::sleep(
            crate::managed::POLL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(test)]
#[path = "provider_retry_tests.rs"]
mod provider_retry_tests;

impl Run<'_> {
    #[inline(never)]
    fn provider(
        &self,
        slot: usize,
        selected: &GeneratedProviderPolicies,
        prior_height: u64,
    ) -> Result<Phase<HistoricalProviderBootstrap>> {
        let run = self;
        #[cfg(test)]
        let _profile_counts = profiles::snapshot()
            .is_none()
            .then(profiles::Counter::begin);
        #[cfg(test)]
        let _import_counts = ServiceAuthority::test_graph_import_snapshot()
            .is_none()
            .then(ServiceAuthority::test_begin_graph_import_counts);
        macro_rules! provider_completed {
            ($phase:expr) => {
                match $phase? {
                    Phase::Complete(value) => value,
                    Phase::Incomplete(progress) => return Ok(Phase::Incomplete(progress)),
                }
            };
        }
        let provider_id = selected.provider_id;
        let (custody_policy, custody_enrollment) = provider_completed!(observed_phase!(
            run,
            run.custody(selected, prior_height),
            "custody",
            Some(slot)
        ));
        let reserve_account = provider_completed!(observed_phase!(
            run,
            run.account(slot, provider_id, custody_enrollment.height),
            "account",
            Some(slot)
        ));
        let (funding_result, funding_height) = provider_completed!(observed_phase!(
            run,
            run.funding(provider_id, reserve_account.height),
            "funding",
            Some(slot)
        ));
        let ingest_finality = provider_completed!(observed_phase!(
            run,
            run.ingest(selected, funding_height),
            "ingest",
            Some(slot)
        ));
        let gateway_finality = provider_completed!(observed_phase!(
            run,
            run.gateway(selected, ingest_finality.height),
            "gateway",
            Some(slot)
        ));
        Ok(Phase::Complete(HistoricalProviderBootstrap {
            provider_id,
            custody_policy,
            custody_enrollment,
            reserve_account,
            funding: funding_result,
            provider_ingest: ingest_finality,
            gateway: gateway_finality,
        }))
    }

    fn may_submit(&self) -> Result<bool> {
        if self.mode != Mode::Advance {
            return Ok(false);
        }
        self.authorization
            .ok_or_else(|| invalid("bootstrap advance requires its live worker authorization"))?
            .validate(self.authority, self.deadline)?;
        Ok(true)
    }

    #[inline(never)]
    fn reserve(&self) -> Result<Phase<ManagedTransactionFinality>> {
        let policies = &self.original.policies;
        let fees = &self.original.fees;
        let deadline = self.deadline;
        let mode = self.mode;
        let authorization = self.authorization;
        // This single phase can reuse the parent's immutable original profile for a fresh
        // name-only absence observation. Enclosing codec owners retain the exact original
        // independent child capture/admission path; present custody keeps its fresh native owner.
        let purpose_absent = if norito::core::decode_limits_active() {
            false
        } else {
            super::super::service_authority::ServiceChildInventory::begin(self.authority)?
                .initial_reserve_policy_absent()?
        };
        let mut reserve = if purpose_absent {
            if !self.may_submit()? {
                return absent(ServiceBootstrapStep::ReservePolicy);
            }
            // The fresh observation grants no signing/current-state authority. The creator
            // retains its own profile and lock after ordinary live authorization.
            ManagedInitialReservePolicy::open_from_original(self.authority)?
        } else {
            let existing = if self.mode == Mode::Advance {
                ManagedInitialReservePolicy::open_existing(&self.authority.prepared)
            } else {
                ManagedInitialReservePolicy::open_existing_from_original(
                    self.authority,
                    self.checkpoint_import_scope.as_ref(),
                )
            };
            match existing? {
                Some(owner) => owner,
                None if self.may_submit()? => {
                    ManagedInitialReservePolicy::open_from_original(self.authority)?
                }
                None => return absent(ServiceBootstrapStep::ReservePolicy),
            }
        };
        let mut result = incomplete(if mode == Mode::Local {
            reserve.recover_local_selected_if_present(&policies.network.reserve, fees, deadline)
        } else {
            reserve.recover_selected_if_present(&policies.network.reserve, fees, deadline)
        })?;
        if result
            .as_ref()
            .is_none_or(|value| value.finalized.is_none())
            && self.may_submit()?
        {
            result = Some(
                reserve.advance_selected(
                    &policies.network.reserve,
                    &authorization
                        .ok_or_else(|| {
                            invalid("bootstrap advance requires its live worker authorization")
                        })?
                        .child(Purpose::ReservePolicy)?,
                    deadline,
                )?,
            );
        }
        let Some(result) = result else {
            return absent(ServiceBootstrapStep::ReservePolicy);
        };
        let Some(reserve_policy) = result.finalized else {
            return Ok(Phase::Incomplete(Incomplete::Pending {
                step: ServiceBootstrapStep::ReservePolicy,
                status: result.transaction_status,
            }));
        };
        drop(reserve);
        Ok(Phase::Complete(reserve_policy))
    }

    #[inline(never)]
    fn custody(
        &self,
        selected: &GeneratedProviderPolicies,
        prior_height: u64,
    ) -> Result<Phase<(ManagedTransactionFinality, ManagedTransactionFinality)>> {
        let fees = &self.original.fees;
        let deadline = self.deadline;
        let mode = self.mode;
        let authorization = self.authorization;
        let provider_id = selected.provider_id;
        let mut custody = open_child!(
            self,
            ManagedStreamTokenCustody,
            ServiceBootstrapStep::CustodyPolicy { provider_id },
            provider_id
        );
        let mut result = incomplete(if mode == Mode::Local {
            custody.recover_configure_local_selected_if_present(&selected.custody, fees, deadline)
        } else {
            custody.recover_configure_selected_if_present(&selected.custody, fees, deadline)
        })?;
        if result
            .as_ref()
            .is_none_or(|value| value.finalized.is_none())
            && self.may_submit()?
        {
            result = Some(
                custody.advance_configure_selected(
                    &selected.custody,
                    &authorization
                        .ok_or_else(|| {
                            invalid("bootstrap advance requires its live worker authorization")
                        })?
                        .child(Purpose::CustodyConfigure(provider_id))?,
                    deadline,
                )?,
            );
        }
        let Some(result) = result else {
            return absent(ServiceBootstrapStep::CustodyPolicy { provider_id });
        };
        let Some(custody_policy) = result.finalized else {
            return Ok(Phase::Incomplete(Incomplete::Pending {
                step: ServiceBootstrapStep::CustodyPolicy { provider_id },
                status: result.transaction_status,
            }));
        };

        require_after(&custody_policy, prior_height)?;
        let mut result = incomplete(if mode == Mode::Local {
            custody.recover_enroll_local_selected_if_present(&selected.custody, fees, deadline)
        } else {
            custody.recover_enroll_selected_if_present(&selected.custody, fees, deadline)
        })?;
        if result
            .as_ref()
            .is_none_or(|value| value.finalized.is_none())
            && self.may_submit()?
        {
            result = Some(
                custody.advance_enroll_selected(
                    &selected.custody,
                    &authorization
                        .ok_or_else(|| {
                            invalid("bootstrap advance requires its live worker authorization")
                        })?
                        .child(Purpose::CustodyEnroll(provider_id))?,
                    deadline,
                )?,
            );
        }
        let Some(result) = result else {
            return absent(ServiceBootstrapStep::CustodyEnrollment { provider_id });
        };
        let Some(custody_enrollment) = result.finalized else {
            return Ok(Phase::Incomplete(Incomplete::Pending {
                step: ServiceBootstrapStep::CustodyEnrollment { provider_id },
                status: result.transaction_status,
            }));
        };
        require_after(&custody_enrollment, custody_policy.height)?;
        drop(custody);
        Ok(Phase::Complete((custody_policy, custody_enrollment)))
    }

    #[inline(never)]
    fn account(
        &self,
        slot: usize,
        provider_id: ProviderId,
        custody_height: u64,
    ) -> Result<Phase<ManagedTransactionFinality>> {
        let policies = &self.original.policies;
        let fees = &self.original.fees;
        let deadline = self.deadline;
        let mode = self.mode;
        let authorization = self.authorization;
        let original = self.original;
        let mut account = open_child!(
            self,
            ManagedReserveAccountRegistration,
            ServiceBootstrapStep::ReserveAccount { provider_id },
            provider_id
        );
        let mut result = incomplete(if mode == Mode::Local {
            account.recover_local_selected_if_present(
                &policies.network.reserve,
                &original.underwriting[slot],
                fees,
                deadline,
            )
        } else {
            account.recover_selected_if_present(
                &policies.network.reserve,
                &original.underwriting[slot],
                fees,
                deadline,
            )
        })?;
        if result
            .as_ref()
            .is_none_or(|value| value.finalized.is_none())
            && self.may_submit()?
        {
            result = Some(
                account.advance_selected(
                    &policies.network.reserve,
                    &original.underwriting[slot],
                    &authorization
                        .ok_or_else(|| {
                            invalid("bootstrap advance requires its live worker authorization")
                        })?
                        .child(Purpose::ReserveAccount(provider_id))?,
                    deadline,
                )?,
            );
        }
        let Some(result) = result else {
            return absent(ServiceBootstrapStep::ReserveAccount { provider_id });
        };
        let Some(reserve_account) = result.finalized else {
            return Ok(Phase::Incomplete(Incomplete::Pending {
                step: ServiceBootstrapStep::ReserveAccount { provider_id },
                status: result.transaction_status,
            }));
        };
        require_after(&reserve_account, custody_height)?;
        drop(account);
        Ok(Phase::Complete(reserve_account))
    }

    #[inline(never)]
    fn funding(
        &self,
        provider_id: ProviderId,
        account_height: u64,
    ) -> Result<Phase<(CompletedFunding, u64)>> {
        let policies = &self.original.policies;
        let fees = &self.original.fees;
        let deadline = self.deadline;
        let mode = self.mode;
        let authorization = self.authorization;
        let mut funding = open_child!(
            self,
            ProviderFundingBootstrap,
            ServiceBootstrapStep::ProviderFunding { provider_id },
            provider_id
        );
        let mut result = incomplete(if mode == Mode::Local {
            funding.recover_local_selected_if_present(&policies.network.reserve, fees, deadline)
        } else {
            funding.recover_selected_if_present(&policies.network.reserve, fees, deadline)
        })?;
        if result
            .as_ref()
            .is_none_or(|value| !matches!(value, ProviderFundingProgress::Complete { .. }))
            && self.may_submit()?
        {
            result = Some(
                funding.advance_selected(
                    &policies.network.reserve,
                    &authorization
                        .ok_or_else(|| {
                            invalid("bootstrap advance requires its live worker authorization")
                        })?
                        .funding(provider_id)?,
                    deadline,
                )?,
            );
        }
        let Some(funding_result) = result else {
            return absent(ServiceBootstrapStep::ProviderFunding { provider_id });
        };
        let ProviderFundingProgress::Complete {
            credit, capacity, ..
        } = &funding_result
        else {
            return Ok(Phase::Incomplete(Incomplete::Funding {
                provider_id,
                progress: funding_result,
            }));
        };
        require_after(credit, account_height)?;
        require_after(capacity, credit.height)?;
        let funding_height = capacity.height;
        drop(funding);
        let completed = CompletedFunding::from_progress(funding_result)?;
        Ok(Phase::Complete((completed, funding_height)))
    }

    #[inline(never)]
    fn ingest(
        &self,
        selected: &GeneratedProviderPolicies,
        funding_height: u64,
    ) -> Result<Phase<ManagedTransactionFinality>> {
        let fees = &self.original.fees;
        let deadline = self.deadline;
        let mode = self.mode;
        let authorization = self.authorization;
        let provider_id = selected.provider_id;
        let mut ingest = open_child!(
            self,
            ManagedInitialProviderIngestAuthority,
            ServiceBootstrapStep::ProviderIngest { provider_id },
            provider_id
        );
        let mut result = incomplete(if mode == Mode::Local {
            ingest.recover_local_selected_if_present(&selected.provider_ingest, fees, deadline)
        } else {
            ingest.recover_selected_if_present(&selected.provider_ingest, fees, deadline)
        })?;
        if result
            .as_ref()
            .is_none_or(|value| value.finalized.is_none())
            && self.may_submit()?
        {
            result = Some(
                ingest.advance_selected(
                    &selected.provider_ingest,
                    &authorization
                        .ok_or_else(|| {
                            invalid("bootstrap advance requires its live worker authorization")
                        })?
                        .child(Purpose::ProviderIngest(provider_id))?,
                    deadline,
                )?,
            );
        }
        let Some(result) = result else {
            return absent(ServiceBootstrapStep::ProviderIngest { provider_id });
        };
        let Some(ingest_finality) = result.finalized else {
            return Ok(Phase::Incomplete(Incomplete::Pending {
                step: ServiceBootstrapStep::ProviderIngest { provider_id },
                status: result.transaction_status,
            }));
        };
        require_after(&ingest_finality, funding_height)?;
        drop(ingest);
        Ok(Phase::Complete(ingest_finality))
    }

    #[inline(never)]
    fn gateway(
        &self,
        selected: &GeneratedProviderPolicies,
        ingest_height: u64,
    ) -> Result<Phase<ManagedTransactionFinality>> {
        let fees = &self.original.fees;
        let deadline = self.deadline;
        let mode = self.mode;
        let authorization = self.authorization;
        let provider_id = selected.provider_id;
        let mut gateway = open_child!(
            self,
            ManagedInitialGatewaySetup,
            ServiceBootstrapStep::Gateway { provider_id },
            provider_id
        );
        let mut result = incomplete(if mode == Mode::Local {
            gateway.recover_local_selected_if_present(&selected.gateway, fees, deadline)
        } else {
            gateway.recover_selected_if_present(&selected.gateway, fees, deadline)
        })?;
        if result
            .as_ref()
            .is_none_or(|value| value.finalized.is_none())
            && self.may_submit()?
        {
            result = Some(
                gateway.advance_selected(
                    &selected.gateway,
                    &authorization
                        .ok_or_else(|| {
                            invalid("bootstrap advance requires its live worker authorization")
                        })?
                        .child(Purpose::Gateway(provider_id))?,
                    deadline,
                )?,
            );
        }
        let Some(result) = result else {
            return absent(ServiceBootstrapStep::Gateway { provider_id });
        };
        let Some(gateway_finality) = result.finalized else {
            return Ok(Phase::Incomplete(Incomplete::Pending {
                step: ServiceBootstrapStep::Gateway { provider_id },
                status: result.transaction_status,
            }));
        };
        require_after(&gateway_finality, ingest_height)?;
        drop(gateway);
        Ok(Phase::Complete(gateway_finality))
    }

    #[inline(never)]
    fn reputation(
        &self,
        reserve_policy: ManagedTransactionFinality,
        histories: Vec<HistoricalProviderBootstrap>,
        prior_height: u64,
    ) -> Result<Phase<HistoricalServiceBootstrap>> {
        let policies = &self.original.policies;
        let fees = &self.original.fees;
        let deadline = self.deadline;
        let mode = self.mode;
        let authorization = self.authorization;
        let mut reputation = open_child!(
            self,
            ManagedInitialReputationPolicy,
            ServiceBootstrapStep::Reputation
        );
        let labels = policies.gateway_labels();
        let mut result = incomplete(if mode == Mode::Local {
            reputation.recover_local_selected_if_present(
                &labels,
                &policies.network.reputation,
                fees,
                deadline,
            )
        } else {
            reputation.recover_selected_if_present(
                &labels,
                &policies.network.reputation,
                fees,
                deadline,
            )
        })?;
        if result
            .as_ref()
            .is_none_or(|value| value.finalized.is_none())
            && self.may_submit()?
        {
            result = Some(
                reputation.advance_selected(
                    &labels,
                    &policies.network.reputation,
                    &authorization
                        .ok_or_else(|| {
                            invalid("bootstrap advance requires its live worker authorization")
                        })?
                        .child(Purpose::Reputation)?,
                    deadline,
                )?,
            );
        }
        let Some(result) = result else {
            return absent(ServiceBootstrapStep::Reputation);
        };
        let Some(reputation_finality) = result.finalized else {
            return Ok(Phase::Incomplete(Incomplete::Pending {
                step: ServiceBootstrapStep::Reputation,
                status: result.transaction_status,
            }));
        };
        require_after(&reputation_finality, prior_height)?;
        let providers = histories
            .try_into()
            .map_err(|_| invalid("bootstrap provider history count differs"))?;
        let history = HistoricalServiceBootstrap {
            reserve_policy,
            providers,
            reputation: reputation_finality,
        };
        history.ordered_carriers()?;
        Ok(Phase::Complete(history))
    }
}

#[cfg(test)]
mod tests {
    //! Unfinished child storage must exclude the impossible complete aggregate payload.

    use super::*;
    use std::mem::size_of;

    #[test]
    fn unfinished_phase_does_not_reserve_complete_aggregate_storage() {
        assert!(size_of::<Incomplete>() < size_of::<ServiceBootstrapProgress>());
        assert!(size_of::<Phase<()>>() < size_of::<ServiceBootstrapProgress>());
    }
}

#[cfg(test)]
#[path = "absence_tests.rs"]
mod absence_tests;

#[cfg(test)]
pub(super) mod test_passes {
    //! Observe actual parent phase passes without supplying completion or authority.

    use super::Mode;
    use std::cell::Cell;

    std::thread_local! {
        static VISITS: Cell<Option<[usize; 3]>> = const { Cell::new(None) };
    }

    pub(super) fn record(mode: Mode) {
        VISITS.with(|value| {
            if let Some(mut visits) = value.get() {
                let index = match mode {
                    Mode::Local => 0,
                    Mode::Advance => 1,
                    Mode::Recover => 2,
                };
                visits[index] = visits[index].checked_add(1).expect("test pass count bound");
                value.set(Some(visits));
            }
        });
    }

    pub(in crate::managed::service_bootstrap) fn count<T>(
        action: impl FnOnce() -> T,
    ) -> (T, [usize; 3]) {
        struct Restore(Option<[usize; 3]>);
        impl Drop for Restore {
            fn drop(&mut self) {
                VISITS.with(|value| value.set(self.0));
            }
        }
        let _restore = Restore(VISITS.with(|value| value.replace(Some([0; 3]))));
        let result = action();
        let visits = VISITS.with(|value| value.get().expect("test pass observer retained"));
        (result, visits)
    }
}

#[cfg(test)]
#[path = "original_profile_tests.rs"]
mod original_profile_tests;

#[cfg(test)]
#[path = "creating_original_tests.rs"]
mod creating_original_tests;
