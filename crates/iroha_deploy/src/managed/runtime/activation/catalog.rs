//! Joined fresh catalog promotion with serialized full renderer validation between HTTP calls.

use super::*;
use crate::localnet::service_authorities::RetainedGatewayCompliancePlan;
use std::sync::{Mutex, MutexGuard, TryLockError};

pub(super) fn promote(
    prepared: &PreparedLocalnet,
    live: &mut [OwnedGateway; 3],
    budget: &Budget,
    parallel: bool,
) -> std::result::Result<[PromotedGeneratedCatalog; 3], Failure> {
    budget.check()?;
    // Every full live check reopens the same original Bootstrap and custody selections. Keep
    // that exact recipe exclusive within this round, but hold no guard during catalog HTTP.
    let validation = Mutex::new(());
    let result = crate::managed::provider_round::run(
        live.each_mut(),
        parallel,
        |gateway| {
            let publisher =
                budget.call(|_| ManagedGatewayCompliance::open(prepared, gateway.provider()))?;
            let mut gateway = GuardedGateway {
                gateway,
                validation: &validation,
                budget,
            };
            loop {
                gateway.validate_original(prepared)?;
                let result = publisher.advance(&mut gateway, budget.deadline()?);
                budget.check()?;
                gateway.validate_original(prepared)?;
                if let Ok(catalog) = result {
                    return Ok(catalog);
                }
                budget.wait()?;
            }
        },
        || budget.progress.unconfirmed(),
    );
    // All publishers, live borrows and workers have closed on both success and failure.
    budget.check()?;
    result
}

struct GuardedGateway<'a, G> {
    gateway: &'a mut G,
    validation: &'a Mutex<()>,
    budget: &'a Budget,
}
impl<G: LiveGatewayProcess> LiveGatewayProcess for GuardedGateway<'_, G> {
    fn validate(
        &mut self,
        prepared: &PreparedLocalnet,
        plan: &RetainedGatewayCompliancePlan,
    ) -> Result<()> {
        let _guard = acquire_validation(self.validation, self.budget)?;
        let result = self.gateway.validate(prepared, plan);
        // Cancellation or expiry during the complete native renderer check wins even over
        // an ordinary validation error. Never retain the mutex across the next HTTP effect.
        self.budget
            .check()
            .map_err(|failure| crate::managed::Error::Invalid(failure.message()))?;
        result
    }
}
impl GuardedGateway<'_, OwnedGateway> {
    fn validate_original(
        &mut self,
        prepared: &PreparedLocalnet,
    ) -> std::result::Result<(), Failure> {
        let plan = self.budget.call(|_| {
            self.gateway
                .original_gateway_compliance_plan(prepared)?
                .ok_or_else(|| invalid("generated gateway plan absent"))
        })?;
        let budget = self.budget;
        budget.call(|_| self.validate(prepared, &plan))
    }
}

fn acquire_validation<'a>(
    validation: &'a Mutex<()>,
    budget: &Budget,
) -> Result<MutexGuard<'a, ()>> {
    loop {
        budget
            .check()
            .map_err(|failure| crate::managed::Error::Invalid(failure.message()))?;
        match validation.try_lock() {
            Ok(guard) => {
                budget
                    .check()
                    .map_err(|failure| crate::managed::Error::Invalid(failure.message()))?;
                return Ok(guard);
            }
            Err(TryLockError::WouldBlock) => {
                // The existing poll and unchanged outer timers bound contention. This is
                // scheduling only; no failed native check is turned into an admission.
                budget
                    .wait()
                    .map_err(|failure| crate::managed::Error::Invalid(failure.message()))?;
            }
            Err(TryLockError::Poisoned(_)) => {
                return Err(invalid("catalog validation worker panicked"));
            }
        }
    }
}

#[cfg(test)]
#[path = "catalog_tests.rs"]
mod tests;
