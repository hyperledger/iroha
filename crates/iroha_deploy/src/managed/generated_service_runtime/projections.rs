//! Fresh original gateway projections and existing Bootstrap admission from the retained renderer.

use super::*;

impl GeneratedServiceRuntime {
    /// Only fresh catalog activation may overlap independent provider operations. Existing
    /// purposes, including empty prefixes, retain serial recovery. Under active codec limits
    /// even the scheduling census is omitted so the caller keeps its original decode recipe.
    pub(in crate::managed) fn fresh_catalog_round(&self) -> Result<bool> {
        if norito::core::decode_limits_active() {
            return Ok(false);
        }
        let parent = self.open_original_bootstrap(&self.authority.prepared)?;
        parent.gateway_catalog_purposes_absent()
    }

    /// Reopen the already-created Bootstrap purpose from this exact renderer generation.
    /// This grants no signing authority or current-state verdict; each child keeps its own
    /// fresh native lock and profile admission. Active decode limits and owned profiles
    /// retain the standalone full-capture path in the existing-only constructor.
    pub(in crate::managed) fn open_original_bootstrap(
        &self,
        prepared: &PreparedLocalnet,
    ) -> Result<ManagedServiceBootstrap> {
        if prepared != &self.authority.prepared {
            return Err(invalid(
                "generated runtime bootstrap belongs to another prepared generation",
            ));
        }
        self.authority.validate_profile()?;
        let result = ManagedServiceBootstrap::open_existing_from_original(&self.authority);
        // Keep a successful child's native owner live while closing the renderer on every
        // ordinary result, including active/owned fallback and initial purpose absence.
        self.authority.validate_profile()?;
        result?.ok_or_else(|| invalid("original service bootstrap purpose is absent"))
    }

    pub(in crate::managed) fn original_provider_plan(
        &self,
        prepared: &PreparedLocalnet,
        provider: ProviderId,
    ) -> Result<Option<RetainedProviderServicePlan>> {
        // A retained renderer projects only its own exact prepared generation.
        if prepared != &self.authority.prepared {
            return Err(invalid(
                "generated runtime projection belongs to another prepared generation",
            ));
        }
        let Some(intent) = self.authority.original_intent_if_shared()? else {
            return prepared.provider_service_plan(provider);
        };
        let result = intent
            .provider_plan(provider)
            .map(Some)
            .map_err(|_| invalid("retained generated provider plan differs"));
        // A closing original-image/operation-lock failure supersedes every projection result.
        intent.finish()?;
        result
    }

    pub(in crate::managed) fn original_provider_plans(
        &self,
        prepared: &PreparedLocalnet,
    ) -> Result<Option<[RetainedProviderServicePlan; 3]>> {
        if prepared != &self.authority.prepared {
            return Err(invalid(
                "generated runtime projection belongs to another prepared generation",
            ));
        }
        let Some(intent) = self.authority.original_intent_if_shared()? else {
            return prepared.provider_service_plans();
        };
        let result = intent.provider_plans().map(|plans| Some(plans.clone()));
        intent.finish()?;
        result
    }

    /// The owned gateway round alone uses this pair inside its full aggregate entry/exit.
    /// The first projection and intervening direct-child checks keep their original order.
    /// Both bounded template decodes and all operation-lock/scope observations remain real;
    /// only the second immutable image pair shares the enclosing aggregate observations.
    /// A persistent image change still fails the unconditional aggregate exit, including
    /// after an ordinary child error. Detection may move to that exit, and an intermediate
    /// changed-and-restored image can be unseen. This is not an atomic snapshot or authority.
    /// No intent, plan or cached validation verdict survives this call.
    pub(in crate::managed) fn validate_gateway_compliance_pair(
        &self,
        prepared: &PreparedLocalnet,
        provider: ProviderId,
        before_binding: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if prepared != &self.authority.prepared {
            return Err(invalid(
                "generated runtime projection belongs to another prepared generation",
            ));
        }
        let intent = self.authority.original_intent_if_shared()?;
        let plan = match &intent {
            Some(intent) => {
                let result = intent
                    .gateway_compliance_plan(provider)
                    .map_err(|_| invalid("retained generated compliance plan differs"));
                // Exactly the first projection's full finish, keeping the immutable borrow
                // local for the second projection. Exit refusal still wins its decode error.
                self.authority.validate_profile()?;
                result?
            }
            None => self
                .original_gateway_compliance_plan(prepared, provider)?
                .ok_or_else(|| invalid("generated gateway plan absent"))?,
        };
        before_binding()?;
        let shared = intent
            .as_ref()
            .filter(|_| !norito::core::decode_limits_active());
        #[cfg(test)]
        let shared = shared.filter(|_| !full_gateway_pair_for_test());
        let expected = match shared {
            Some(intent) => {
                // Preserve the second projection's exact native entry and ordinary-result
                // exit. Its mutable custody is never covered by the earlier image read.
                intent.validate_policy_custody()?;
                let result = intent
                    .gateway_compliance_plan(provider)
                    .map_err(|_| invalid("retained generated compliance plan differs"));
                intent.validate_policy_custody()?;
                result?
            }
            None => self
                .original_gateway_compliance_plan(prepared, provider)?
                .ok_or_else(|| invalid("original gateway plan absent"))?,
        };
        if expected.network_id() != plan.network_id()
            || expected.original_commitment() != plan.original_commitment()
            || expected.trust_policy() != plan.trust_policy()
            || expected.gateway_id() != plan.gateway_id()
        {
            return Err(invalid("the observed gateway compliance binding differs"));
        }
        Ok(())
    }

    pub(in crate::managed) fn original_gateway_compliance_plan(
        &self,
        prepared: &PreparedLocalnet,
        provider: ProviderId,
    ) -> Result<Option<RetainedGatewayCompliancePlan>> {
        if prepared != &self.authority.prepared {
            return Err(invalid(
                "generated runtime projection belongs to another prepared generation",
            ));
        }
        let Some(intent) = self.authority.original_intent_if_shared()? else {
            return prepared.gateway_compliance_plan(provider);
        };
        // Compliance still runs its ordinary bounded canonical template decode.
        let result = intent
            .gateway_compliance_plan(provider)
            .map(Some)
            .map_err(|_| invalid("retained generated compliance plan differs"));
        intent.finish()?;
        result
    }
}

#[cfg(test)]
std::thread_local! {
    static FULL_GATEWAY_PAIR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
fn full_gateway_pair_for_test() -> bool {
    FULL_GATEWAY_PAIR.with(std::cell::Cell::get)
}
#[cfg(test)]
impl GeneratedServiceRuntime {
    pub(in crate::managed) fn test_full_gateway_pair<T>(read: impl FnOnce() -> T) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                FULL_GATEWAY_PAIR.with(|value| value.set(self.0));
            }
        }
        let _restore = Restore(FULL_GATEWAY_PAIR.with(|value| value.replace(true)));
        read()
    }
}

#[cfg(test)]
mod tests;
