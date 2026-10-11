//! Reuse the actual initial native absence only for its same-owner unsigned first reservation.

use super::*;
use crate::managed::native_operation::attempts::GeneratedPrerequisite;
pub(super) use crate::managed::native_operation::initial_intent::PublishedInitialIntent;

pub(super) struct InitialAdmission<'a> {
    published: PublishedInitialIntent<'a>,
    verifier: FinalityVerifier,
    native: VerifiedReservePolicyStateV1,
}
impl<'a> InitialAdmission<'a> {
    pub(super) fn new(
        published: PublishedInitialIntent<'a>,
        verifier: FinalityVerifier,
        native: VerifiedReservePolicyStateV1,
    ) -> Self {
        Self {
            published,
            verifier,
            native,
        }
    }
}
impl ManagedInitialReservePolicy {
    // This receipt supplies original provenance only. advance_original retains its later
    // fresh native absence immediately before any quote, payload, signature or dispatch.
    pub(super) fn initial_prerequisite(
        &mut self,
        original: &Original,
        admission: &mut Option<InitialAdmission<'_>>,
        prerequisite: GeneratedPrerequisite<'_>,
        deadline: Instant,
    ) -> Result<Observation> {
        let selected = prerequisite.into_first().zip(admission.take());
        let Some((
            first,
            InitialAdmission {
                published,
                verifier,
                native,
            },
        )) = selected
        else {
            let (_, current) = self.observe(&original.policy, deadline)?;
            if current.current().is_some() {
                return Err(invalid("initial reserve policy already exists"));
            }
            return Ok(Observation::ordinary());
        };
        self.authority.validate_profile()?;
        let result = (|| {
            published.admit(&first, Purpose::ReservePolicy, original.digest()?, || {
                self.validate_original(original)?;
                let tip = verifier
                    .verified_tip_ref()
                    .map_err(|_| invalid("invalid original reserve observation"))?;
                tip.verify_global_scope(
                    self.authority.config.network_id,
                    self.authority.config.chain.as_str(),
                )
                .map_err(|_| invalid("original reserve observation changed Global scope"))?;
                if checkpoint_bytes(&verifier)? != original.checkpoint
                    || native.network_id() != self.authority.config.network_id
                    || native.manager() != &self.authority.config.account
                    || native.height() != tip.height()
                    || native.context_id() != tip.context_id()
                    || native.current().is_some()
                {
                    return Err(invalid("original native reserve absence changed"));
                }
                require_deadline(deadline)?;
                Ok(Observation::ordinary())
            })
        })();
        // Close the live original on success and every ordinary proof/source failure.
        self.authority.validate_profile()?;
        require_deadline(deadline)?;
        result
    }
}
