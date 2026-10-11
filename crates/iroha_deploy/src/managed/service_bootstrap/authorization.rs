//! Startup-only scope around the sole generated authorization epoch and live-clock owner.
use super::Original;
use crate::managed::native_operation::now_ms;
use crate::managed::{
    ManagedBootstrapFailure, PreparedLocalnet, Result,
    native_operation::{
        Terms,
        attempts::Purpose,
        authorization::{self, DispatchAuthorization, Lease, Scope},
        encode, invalid,
    },
    service_authority::ServiceAuthority,
    service_policies::GeneratedServicePolicies,
};
pub(super) use authorization::require_active;
use iroha_data_model::sorafs::capacity::ProviderId;
use iroha_fs::PrivateDirectory;
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Instant,
};
#[cfg(test)]
use {
    crate::managed::native_operation::attempts,
    authorization::{MAX_EPOCHS, digest},
    std::sync::atomic::Ordering,
};

/// Initial worker authorization only. A renewal issuer cannot be constructed through this type.
pub(in crate::managed) struct GeneratedBootstrapAuthorization {
    prepared: PreparedLocalnet,
    original: Original,
    lease: Lease,
}
pub(in crate::managed) struct BootstrapChildAuthorization<'a> {
    parent: &'a GeneratedBootstrapAuthorization,
    purpose: Purpose,
}
pub(in crate::managed) struct FundingAuthorization<'a> {
    parent: &'a GeneratedBootstrapAuthorization,
    provider: ProviderId,
}
impl GeneratedBootstrapAuthorization {
    #[cfg(test)]
    pub(in crate::managed) fn test_child(
        &self,
        purpose: Purpose,
    ) -> Result<BootstrapChildAuthorization<'_>> {
        self.child(purpose)
    }
    #[cfg(test)]
    pub(in crate::managed) fn test_terms(&self) -> &Terms {
        &self.lease.epoch.terms
    }
    #[cfg(test)]
    pub(in crate::managed) fn test_ordinal(&self) -> u8 {
        self.lease.epoch.ordinal
    }
    pub(super) fn issue(
        authority: &ServiceAuthority,
        original: Original,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self> {
        require_active(&cancelled)?;
        authority.validate_profile()?;
        original.validate(authority)?;
        let lease = Lease::issue(
            authority.directory.open_child("initial")?,
            encode(&original, super::MAX_ORIGINAL_BYTES)?,
            &original.fees,
            scope(&original),
            profile_expiry(authority, &original)?,
            deadline,
            cancelled,
        )?;
        Ok(Self {
            prepared: authority.prepared.clone(),
            original,
            lease,
        })
    }
    pub(super) fn validate(
        &self,
        authority: &ServiceAuthority,
        deadline: Instant,
    ) -> Result<Instant> {
        authority.validate_profile()?;
        if self.prepared != authority.prepared {
            return Err(invalid(
                "bootstrap capability belongs to another generated profile",
            ));
        }
        self.check(deadline)
    }
    fn check(&self, deadline: Instant) -> Result<Instant> {
        self.lease.check(deadline)
    }
    pub(super) fn child(&self, purpose: Purpose) -> Result<BootstrapChildAuthorization<'_>> {
        scope(&self.original).check(purpose)?;
        Ok(BootstrapChildAuthorization {
            parent: self,
            purpose,
        })
    }
    pub(super) fn funding(&self, provider: ProviderId) -> Result<FundingAuthorization<'_>> {
        self.original.policies.provider(provider)?;
        Ok(FundingAuthorization {
            parent: self,
            provider,
        })
    }
}
impl DispatchAuthorization for BootstrapChildAuthorization<'_> {
    fn lease(&self) -> &Lease {
        &self.parent.lease
    }
    fn purpose(&self) -> Purpose {
        self.purpose
    }
}
impl BootstrapChildAuthorization<'_> {
    pub(in crate::managed) fn bind_account(
        &self,
        account: iroha_wallet::operations::AccountService,
    ) -> Result<iroha_wallet::operations::AccountService> {
        DispatchAuthorization::bind_account(self, account)
    }
    pub(in crate::managed) fn fees(&self) -> &crate::managed::native_operation::Fees {
        DispatchAuthorization::fees(self)
    }
    pub(in crate::managed) fn check(&self, purpose: Purpose, deadline: Instant) -> Result<Instant> {
        DispatchAuthorization::check(self, purpose, deadline)
    }
    pub(in crate::managed) fn validate(
        &self,
        authority: &ServiceAuthority,
        expected: Purpose,
        deadline: Instant,
    ) -> Result<Instant> {
        authority.validate_profile()?;
        if self.purpose != expected || self.parent.prepared != authority.prepared {
            return Err(invalid(
                "bootstrap child capability changed purpose or profile",
            ));
        }
        match provider(expected) {
            Some(provider) if authority.provider_id()? != provider => {
                return Err(invalid(
                    "bootstrap child capability selected another provider",
                ));
            }
            None if authority.provider_id().is_ok() => {
                return Err(invalid(
                    "network bootstrap capability used in provider scope",
                ));
            }
            _ => {}
        }
        self.check(expected, deadline)
    }
    pub(in crate::managed) fn policies(&self) -> &GeneratedServicePolicies {
        &self.parent.original.policies
    }
    pub(in crate::managed) fn terms(
        &self,
        deadline: Instant,
        exclusive_ceiling: Option<u64>,
    ) -> Result<Terms> {
        DispatchAuthorization::terms(self, deadline, exclusive_ceiling)
    }
    #[cfg(test)]
    pub(in crate::managed) fn claim_replacement(
        &self,
        previous_attempt: [u8; 32],
        deadline: Instant,
    ) -> Result<()> {
        DispatchAuthorization::claim_replacement(self, previous_attempt, deadline)
    }
}
impl FundingAuthorization<'_> {
    pub(in crate::managed) fn validate(
        &self,
        authority: &ServiceAuthority,
        deadline: Instant,
    ) -> Result<Instant> {
        authority.validate_profile()?;
        if self.parent.prepared != authority.prepared || authority.provider_id()? != self.provider {
            return Err(invalid(
                "funding authorization selected another profile or provider",
            ));
        }
        self.parent.check(deadline)
    }
    pub(in crate::managed) fn fees(&self) -> &crate::managed::native_operation::Fees {
        &self.parent.original.fees
    }
    pub(in crate::managed) fn policies(&self) -> &GeneratedServicePolicies {
        &self.parent.original.policies
    }
    pub(in crate::managed) fn child(
        &self,
        purpose: Purpose,
    ) -> Result<BootstrapChildAuthorization<'_>> {
        if !matches!(purpose, Purpose::FundingRequest(p) | Purpose::FundingApproval(p) | Purpose::FundingCredit(p) | Purpose::FundingCapacity(p) if p == self.provider)
        {
            return Err(invalid(
                "funding authorization cannot grant another native purpose",
            ));
        }
        self.parent.child(purpose)
    }
}
fn scope(original: &Original) -> Scope {
    Scope::Bootstrap(std::array::from_fn(|index| {
        original.policies.providers[index].provider_id
    }))
}
pub(super) fn validate_inventory(directory: &PrivateDirectory, original: &Original) -> Result<()> {
    let names = directory.entries(2)?;
    if names
        .iter()
        .any(|name| name != "original.nrt" && name != "epochs")
    {
        return Err(invalid(
            "bootstrap intent contains unknown retained material",
        ));
    }
    authorization::validate_retained(
        directory,
        original.digest()?,
        &original.fees,
        scope(original),
    )
}
fn provider(purpose: Purpose) -> Option<ProviderId> {
    match purpose {
        Purpose::ReservePolicy | Purpose::Reputation => None,
        Purpose::CustodyConfigure(provider)
        | Purpose::CustodyEnroll(provider)
        | Purpose::ReserveAccount(provider)
        | Purpose::FundingRequest(provider)
        | Purpose::FundingApproval(provider)
        | Purpose::FundingCredit(provider)
        | Purpose::FundingCapacity(provider)
        | Purpose::ProviderIngest(provider)
        | Purpose::Gateway(provider)
        | Purpose::CustodyRenewal { provider, .. } => Some(provider),
    }
}
fn profile_expiry(authority: &ServiceAuthority, original: &Original) -> Result<u64> {
    let plans = authority.provider_plans()?;
    let mut end = u64::MAX;
    let now = now_ms()?;
    for plan in plans {
        let selected = original.policies.provider(plan.provider_id())?;
        let admission = plan.admission_material();
        let compliance = authority.gateway_compliance_plan(plan.provider_id())?;
        let start = admission
            .issued_at
            .checked_mul(1_000)
            .ok_or_else(|| invalid("original provider interval overflow"))?
            .max(selected.custody.active_from_unix_ms)
            .max(
                compliance
                    .issued_at_unix()
                    .checked_mul(1_000)
                    .ok_or_else(|| invalid("original compliance interval overflow"))?,
            );
        let provider_end = admission
            .retention_epoch
            .checked_mul(1_000)
            .ok_or_else(|| invalid("original provider interval overflow"))?
            .min(selected.custody.active_until_unix_ms)
            .min(
                compliance
                    .expires_at_unix()
                    .checked_mul(1_000)
                    .ok_or_else(|| invalid("original compliance interval overflow"))?,
            );
        if now < start || now >= provider_end {
            return Err(ManagedBootstrapFailure::ProfileExpired.into());
        }
        end = end.min(provider_end);
    }
    Ok(end)
}

#[cfg(test)]
#[path = "authorization/tests.rs"]
mod tests;
