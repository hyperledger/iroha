//! One original native Configure absence, consumed only by its new unsigned reservation.

use super::*;
use crate::managed::native_operation::attempts::GeneratedPrerequisite;
pub(super) use crate::managed::native_operation::initial_intent::PublishedInitialIntent;

pub(super) struct InitialAdmission<'a> {
    published: PublishedInitialIntent<'a>,
    verifier: FinalityVerifier,
    native: VerifiedStreamTokenCustodyStateV1,
}
impl<'a> InitialAdmission<'a> {
    pub(super) fn new(
        published: PublishedInitialIntent<'a>,
        verifier: FinalityVerifier,
        native: VerifiedStreamTokenCustodyStateV1,
    ) -> Self {
        Self {
            published,
            verifier,
            native,
        }
    }
}
impl ManagedStreamTokenCustody {
    // The original proof is not a current signing grant. The ordinary advance owner still
    // performs its fresh finality/current predecessor read after wallet request retention.
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
            return self.fresh_original_predecessor(original, deadline);
        };
        self.authority.validate_profile()?;
        let result = (|| {
            published.admit(
                &first,
                original.dispatch_purpose()?,
                original.digest()?,
                || {
                    self.validate_original(original, CustodyPurpose::Configure)?;
                    let tip = verifier
                        .verified_tip_ref()
                        .map_err(|_| invalid("invalid original Configure observation"))?;
                    tip.verify_global_scope(
                        self.authority.config.network_id,
                        self.authority.config.chain.as_str(),
                    )
                    .map_err(|_| invalid("original Configure observation changed Global scope"))?;
                    if checkpoint_bytes(&verifier)? != original.checkpoint
                        || native.network_id() != self.authority.config.network_id
                        || native.provider_id() != self.authority.provider_id()?
                        || native.owner()
                            != self
                                .authority
                                .provider_role(StreamTokenAuthorityRole::IssuerOperator)?
                        || native.height() != tip.height()
                        || native.context_id() != tip.context_id()
                        || native.current().is_some()
                        || !matches_predecessor(&original.selection, None)
                    {
                        return Err(invalid("original native Configure absence changed"));
                    }
                    require_deadline(deadline)?;
                    Ok(Observation::ordinary())
                },
            )
        })();
        self.authority.validate_profile()?;
        require_deadline(deadline)?;
        result
    }
}
