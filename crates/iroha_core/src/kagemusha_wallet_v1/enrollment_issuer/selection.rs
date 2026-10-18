//! Fresh configured provider selection against a consistent committed World view.

use super::*;
use crate::{
    kagemusha_wallet_v1::{Registration, storage},
    state::WorldReadOnly,
};
use mv::storage::StorageReadOnly as _;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct CurrentSelection {
    config: Arc<KagemushaEnrollmentIssuer>,
    pub provider: KagemushaEnrollmentProvider,
    account: AccountId,
    fi: [u8; 32],
    actor: [u8; 32],
    registration: Vec<u8>,
}

impl<R: EnrollmentIssuerRuntimeV1> EnrollmentIssuerV1<R> {
    pub(super) fn current(&mut self, dispatch: &PreKeyDispatchV1) -> Result<CurrentSelection> {
        self.select_current(dispatch, true)
    }

    pub(super) fn current_expiry(
        &mut self,
        dispatch: &PreKeyDispatchV1,
    ) -> Result<CurrentSelection> {
        self.select_current(dispatch, false)
    }

    fn select_current(
        &mut self,
        dispatch: &PreKeyDispatchV1,
        require_all_dependencies: bool,
    ) -> Result<CurrentSelection> {
        dispatch.validate().map_err(|_| Invalid)?;
        let config = self.runtime.current_configuration()?;
        if (&config.scope, &config.journal_dir) != (&self.scope, &self.journal_path)
            || config.revision == 0
        {
            return Err(Selection);
        }
        if require_all_dependencies {
            self.runtime.require_dependencies(&config)?;
        }
        // Public FI/actor routing is only provisional DATA. The selected configured provider
        // must independently authenticate their relationship to the account and sign a fresh
        // Approved observation before any enrollment-authority action can proceed.
        let mut candidates = config.providers.iter().filter(|provider| {
            provider.eligibility.authority.scope_digest() == dispatch.fi_digest
                && provider.scheme == dispatch.scheme
                && provider.app == dispatch.app
                && provider
                    .enrollment
                    .for_asset(&dispatch.asset)
                    .is_ok_and(|p| p == dispatch.policy)
                && (
                    &provider.certificate,
                    &provider.manifest_digest,
                    &provider.release_digest,
                    &provider.service_origin_digest,
                ) == (
                    &dispatch.enrollment_certificate,
                    &dispatch.manifest_digest,
                    &dispatch.release_digest,
                    &dispatch.service_origin_digest,
                )
        });
        let provider = candidates.next().ok_or(Selection)?.clone();
        if candidates.next().is_some() {
            return Err(Selection);
        }
        provider.eligibility.validate().map_err(|_| Invalid)?;
        if provider.eligibility.scheme_id != dispatch.scheme.scheme_id()
            || provider.eligibility.network_id != dispatch.scheme.network_id
        {
            return Err(Selection);
        }
        let registration = self.registered(dispatch)?;
        if self.runtime.current_configuration()?.as_ref() != config.as_ref() {
            return Err(Selection);
        }
        Ok(CurrentSelection {
            config,
            provider,
            account: dispatch.account.clone(),
            fi: dispatch.fi_digest,
            actor: dispatch.actor_digest,
            registration,
        })
    }

    fn registered(&self, dispatch: &PreKeyDispatchV1) -> Result<Vec<u8>> {
        let view = self.state.view();
        if view.world.accounts().get(&dispatch.account).is_none()
            || self.state.network_id_ref().as_bytes() != &dispatch.scheme.network_id
        {
            return Err(Selection);
        }
        let key = storage::key(
            storage::REGISTRATION,
            dispatch.scheme.scheme_id(),
            dispatch.asset.asset_digest(),
        );
        let original = view
            .world
            .kagemusha_wallet_ledger()
            .get(&key)
            .ok_or(Selection)?;
        super::super::validate_row(&key, original).map_err(|_| Selection)?;
        let registration: Registration =
            storage::decode(original, original.len()).map_err(|_| Invalid)?;
        if registration.scheme != dispatch.scheme || registration.asset != dispatch.asset {
            return Err(Selection);
        }
        let definition = view
            .world
            .asset_definitions()
            .get(&dispatch.asset.asset)
            .ok_or(Selection)?;
        let incarnation = view
            .world
            .axt_asset_incarnations()
            .get(&dispatch.asset.asset)
            .ok_or(Selection)?;
        if incarnation.as_bytes() != &dispatch.asset.asset_incarnation
            || definition
                .spec()
                .scale()
                .unwrap_or(iroha_primitives::numeric::MAX_DECIMAL_SCALE)
                != dispatch.asset.scale
            || !crate::kagemusha_wallet_v1::wsv::registration_scope_matches_home(
                &view.world,
                definition,
                registration.balance_scope,
            )
        {
            return Err(Selection);
        }
        Ok(original.clone())
    }

    pub(super) fn unchanged(
        &mut self,
        dispatch: &PreKeyDispatchV1,
        selected: &CurrentSelection,
    ) -> Result<()> {
        if self.current(dispatch)? != *selected {
            return Err(Selection);
        }
        Ok(())
    }

    /// Produce and durably consume one fresh provider observation for exactly one closed action.
    pub(super) fn authorize(
        &mut self,
        session: &mut EnrollmentIssuerSessionV1,
        purpose: KagemushaEligibilityPurposeV1,
        operation: [u8; 32],
    ) -> Result<(CurrentSelection, u64)> {
        self.require_session(session)?;
        let selected = self.current(&session.dispatch)?;
        let started = self.now()?;
        let policy = selected
            .provider
            .eligibility
            .for_asset(&session.dispatch.asset)
            .map_err(|_| Invalid)?;
        let mut expires_at_ms = started
            .checked_add(policy.maximum_response_ms)
            .ok_or(Invalid)?;
        if matches!(
            purpose,
            KagemushaEligibilityPurposeV1::PreKeyPermit
                | KagemushaEligibilityPurposeV1::VerifyEvidence
        ) {
            expires_at_ms = expires_at_ms.min(session.attempt.selection().expires_at_ms);
        }
        let request = KagemushaEligibilityRequestV1 {
            version: 1,
            policy_digest: policy.policy_digest().map_err(|_| Invalid)?,
            account_digest: session.attempt.selection().challenge.account_digest,
            actor_digest: selected.actor,
            attempt_id: session.attempt.selection().attempt_id,
            nonce: random_nonce()?,
            operation_digest: operation,
            purpose,
            requested_at_ms: started,
            expires_at_ms,
        };
        self.journal.retain_eligibility_request(
            &mut session.attempt,
            &session.dispatch,
            &policy,
            &request,
            started,
        )?;
        let response = self.runtime.observe_eligibility(
            &selected.provider,
            &session.dispatch.asset,
            &request.encode_canonical(&policy).map_err(|_| Invalid)?,
            selected.config.request_timeout,
        )?;
        let received = self.now()?;
        if response.len() > KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1 {
            return Err(Invalid);
        }
        let checked = KagemushaEligibilityResponseV1::decode_canonical(
            &response, &policy, &request, received,
        )
        .map_err(|_| Invalid)?;
        expires_at_ms = expires_at_ms.min(checked.body.valid_until_ms);
        self.journal.retain_eligibility_response(
            &mut session.attempt,
            &request.nonce,
            &response,
            received,
        )?;
        self.unchanged(&session.dispatch, &selected)?;
        let consumed = self.now()?;
        match self.journal.consume_eligibility(
            &mut session.attempt,
            &session.dispatch,
            &policy,
            &request,
            consumed,
        ) {
            Ok(()) => Ok((selected, expires_at_ms)),
            // Before any credential can exist the journal retained the denial as the attempt's
            // terminal refusal. An Issued attempt keeps its exact E6 and the denial only withholds
            // it; a possibly signed attempt keeps its unknown outcome. Neither becomes a refusal,
            // whatever operation (including a resumed pre-key permit) observed the denial.
            Err(EnrollmentJournalErrorV1::Ineligible(reason)) => {
                Err(if session.attempt.refusal() == Some(reason) {
                    Refused(reason)
                } else if session.attempt.issued().is_some() {
                    DeliveryWithheld(reason)
                } else {
                    OutcomeUnknown
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn finish_boundary(
        &mut self,
        session: &EnrollmentIssuerSessionV1,
        selected: &CurrentSelection,
        expires: u64,
    ) -> Result<()> {
        self.unchanged(&session.dispatch, selected)?;
        if self.now()? >= expires {
            return Err(Selection);
        }
        Ok(())
    }
}
