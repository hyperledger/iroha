//! Reconstruct each original provider history without guessing a global renewal order.
use super::*;
use crate::managed::{
    native_operation::require_retained_material, service_bootstrap::HistoricalServiceBootstrap,
};

#[derive(Clone, Copy)]
enum HeadCheck {
    CurrentUse,
    MaterialOnly,
}

impl GeneratedServiceRuntime {
    /// Only independently current native heads select the three sequences. Every prior component
    /// must already exist; only a currently selected component may finish interrupted publication.
    /// This path never enrolls, signs, submits or replaces original wallet authorization.
    pub(in crate::managed) fn prepare_current_stream_tokens(
        &self,
        deadline: Instant,
    ) -> Result<GeneratedServiceRuntimeRevision> {
        require_deadline(deadline)?;
        let parallel = self.fresh_catalog_round()?;
        let (selection, components, required) =
            self.retain_native_components(deadline, HeadCheck::CurrentUse, parallel)?;
        self.verify_current_components(&selection, &components, &required, deadline, parallel)?;
        self.publish(&selection, Some(components), Some(required), deadline)
    }

    /// Catalog-stage historical material only: preserve all three native-selected predecessor
    /// components before any renewal can make one an ancestor. This grants no launch revision.
    pub(in crate::managed) fn retain_current_custody_material(
        &self,
        deadline: Instant,
    ) -> Result<()> {
        require_deadline(deadline)?;
        let parallel = self.fresh_catalog_round()?;
        self.retain_native_components(deadline, HeadCheck::MaterialOnly, parallel)?;
        Ok(())
    }

    fn retain_native_components(
        &self,
        deadline: Instant,
        check: HeadCheck,
        parallel: bool,
    ) -> Result<(
        RuntimeSelection,
        [Arc<ProviderComponent>; 3],
        RequiredTransactions,
    )> {
        require_deadline(deadline)?;
        let selection = require_retained_material(RuntimeSelection::read(&self.authority))?;
        selection.validate_interval(None)?;
        #[cfg(all(test, unix))]
        tests::before_bootstrap_reopen();
        let mut parent = self.open_original_bootstrap(&self.authority.prepared)?;
        let ServiceBootstrapProgress::Complete(history) = parent.recover(deadline)? else {
            return Err(invalid(
                "generated bootstrap has incomplete original execution",
            ));
        };
        let terminal = history.reputation();
        // Custody and component validation may reopen parent selection. Release its sole lock.
        drop(parent);
        let selected_heads =
            self.current_provider_round(&selection, deadline, parallel, |index, custody| {
                let provider = selection.plans[index].provider_id();
                let policy = &selection.policies.provider(provider)?.custody;
                match check {
                    HeadCheck::CurrentUse => custody.retained_current_enrollment(
                        policy,
                        selection.initial(index)?,
                        terminal.height,
                        *terminal.block_hash.as_ref(),
                        deadline,
                    ),
                    HeadCheck::MaterialOnly => custody.retained_native_head_material(
                        policy,
                        selection.initial(index)?,
                        terminal,
                        deadline,
                    ),
                }
            })?;
        self.retain_selected_components(selection, &history, selected_heads, deadline)
    }

    // Shared historical material publication after the custody owner selected native heads.
    // This produces no launch revision and performs no new current-use verification.
    pub(super) fn retain_selected_components(
        &self,
        selection: RuntimeSelection,
        history: &HistoricalServiceBootstrap,
        selected: [RetainedCustodyEnrollment; 3],
        deadline: Instant,
    ) -> Result<(
        RuntimeSelection,
        [Arc<ProviderComponent>; 3],
        RequiredTransactions,
    )> {
        require_deadline(deadline)?;
        let terminal = history.reputation();
        let carriers = history.ordered_carriers()?;
        let mut components = Vec::with_capacity(3);
        for (index, enrollment) in selected.into_iter().enumerate() {
            require_deadline(deadline)?;
            let provider = selection.plans[index].provider_id();
            let mut custody = ManagedStreamTokenCustody::open(&self.authority.prepared, provider)?;
            let component = self.reconstruct_provider(
                &selection,
                index,
                history.provider(provider)?.custody_enrollment(),
                terminal,
                enrollment,
                &mut custody,
                deadline,
            )?;
            components.push(component);
        }
        let prepared: [PreparedProviderComponent; 3] = components
            .try_into()
            .map_err(|_| invalid("current generated provider count differs"))?;
        let required = RequiredTransactions::from_originals(
            carriers
                .into_iter()
                .chain(prepared.iter().map(|value| value.finalized())),
        )?;
        let digests = std::array::from_fn(|index| prepared[index].digest());
        let retentions =
            require_retained_material(self.component_retentions(&selection, digests, &required))?;
        let components: [Arc<ProviderComponent>; 3] = prepared
            .into_iter()
            .zip(retentions)
            .map(|(value, retention)| {
                let result = value.retain(&self.authority.directory, retention);
                if retention == Retention::ExistingMaterial {
                    require_retained_material(result)
                } else {
                    result
                }
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| invalid("current generated provider count differs"))?;
        Ok((selection, components, required))
    }

    fn reconstruct_provider(
        &self,
        selection: &RuntimeSelection,
        index: usize,
        initial_finality: ManagedTransactionFinality,
        terminal: ManagedTransactionFinality,
        selected: RetainedCustodyEnrollment,
        custody: &mut ManagedStreamTokenCustody,
        deadline: Instant,
    ) -> Result<PreparedProviderComponent> {
        let sequence = selected.statement().sequence;
        if !(1..=64).contains(&sequence) {
            return Err(invalid(
                "current generated enrollment sequence exceeds bound",
            ));
        }
        let identity = selection.identity(&self.authority, index)?;
        let policy = &selection.policies.provider(identity.provider)?.custody;
        let initial = selection.initial(index)?;
        let mut previous: Option<Arc<ProviderComponent>> = None;
        for ancestor_sequence in 1..sequence {
            require_deadline(deadline)?;
            let ancestor = if ancestor_sequence == 1 {
                require_retained_material(
                    custody.retained_initial_enrollment(policy, initial, deadline),
                )?
            } else {
                require_retained_material(custody.retained_renewed_enrollment(
                    ancestor_sequence,
                    policy,
                    deadline,
                ))?
            };
            check_initial(&ancestor, initial, initial_finality, terminal)?;
            previous = Some(require_retained_material(ProviderComponent::retain(
                &self.authority.directory,
                identity,
                ancestor,
                previous.as_deref(),
                Retention::ExistingMaterial,
            ))?);
        }
        check_initial(&selected, initial, initial_finality, terminal)?;
        ProviderComponent::prepare(identity, selected, previous.as_deref())
    }
}

fn check_initial(
    enrollment: &RetainedCustodyEnrollment,
    interval: ManagedCustodyEnrollmentInterval,
    initial: ManagedTransactionFinality,
    terminal: ManagedTransactionFinality,
) -> Result<()> {
    if enrollment.statement().sequence == 1
        && (*enrollment.finalized() != initial
            || enrollment.statement().issued_at_unix_ms != interval.issued_at_unix_ms
            || enrollment.statement().expires_at_unix_ms != interval.expires_at_unix_ms
            || terminal.height < initial.height)
    {
        return Err(invalid(
            "initial component differs from original parent execution",
        ));
    }
    Ok(())
}
