//! Immutable bounded original provider registration; signed transaction custody remains exclusively wallet-owned.

use super::*;
use crate::managed::native_operation::MAX_CHECKPOINT_BYTES;
use crate::managed::native_operation::attempts::{self, History, Observation, Purpose, Selected};
use iroha_fs::PublishMode;
use iroha_wallet::operations::ReserveAccountRegistrationRequest;

pub(super) const MAX_POLICY_BYTES: usize = 32 * 1024;
pub(super) const MAX_SELECTION_BYTES: usize = 16 * 1024;
pub(super) const MAX_UNDERWRITING_BYTES: usize = 16 * 1024;
const MAX_ORIGINAL_BYTES: usize = MAX_CHECKPOINT_BYTES + 80 * 1024;

#[derive(Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_deploy::managed::reserve_account::Original")]
pub(super) struct Original {
    pub selection: ReserveAccountRegistrationSelection,
    pub policy: ReserveAuthorityPolicyV1,
    pub underwriting: ReserveProviderTermsV1,
    pub checkpoint: Vec<u8>,
}
impl Original {
    pub fn validate(&self) -> Result<()> {
        encode(&self.selection, MAX_SELECTION_BYTES)?;
        encode(&self.policy, MAX_POLICY_BYTES)?;
        encode(&self.underwriting, MAX_UNDERWRITING_BYTES)?;
        self.policy
            .validate()
            .map_err(|_| invalid("invalid original reserve policy"))?;
        if self.checkpoint.is_empty()
            || self.checkpoint.len() > MAX_CHECKPOINT_BYTES
            || self.selection.policy_digest
                != self
                    .policy
                    .digest()
                    .map_err(|_| invalid("invalid original reserve digest"))?
            || self.selection.provider_id
                == iroha_data_model::sorafs::capacity::ProviderId::default()
            || self.selection.provider_id != self.underwriting.provider_id
            || self.selection.provider_account != self.underwriting.provider_account
            || self.selection.provider_account == self.policy.custody_account
            || self.selection.asset_definition != self.policy.asset_definition
            || self.selection.custody_account != self.policy.custody_account
            || self.selection.treasury_account != self.policy.treasury_account
            || self.selection.operations_authority != self.policy.operations_authority
            || self.selection.decision_authority != self.policy.decision_authority
        {
            return Err(invalid(
                "original reserve policy intent differs from its immutable selection",
            ));
        }
        self.policy
            .economics
            .quote(
                self.underwriting.storage_class,
                self.underwriting.capacity_gib,
                self.underwriting.duration,
                self.underwriting.tier,
                sorafs_manifest::deal::XorQuantity::zero(),
            )
            .map_err(|_| invalid("invalid original reserve underwriting"))?;
        Ok(())
    }
    pub fn matches_intent(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
    ) -> Result<()> {
        self.validate()?;
        encode(policy, MAX_POLICY_BYTES)?;
        encode(underwriting, MAX_UNDERWRITING_BYTES)?;
        if self.policy != *policy || self.underwriting != *underwriting {
            return Err(invalid("original reserve policy cannot be replaced"));
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        attempts::semantic_digest(self, MAX_ORIGINAL_BYTES)
    }
    pub fn request(&self, terms: &Terms, deadline: Instant) -> ReserveAccountRegistrationRequest {
        ReserveAccountRegistrationRequest {
            selection: self.selection.clone(),
            policy: self.policy.clone(),
            underwriting: self.underwriting.clone(),
            deadline_unix_ms: terms.signing_deadline_unix_ms,
            options: terms.options(deadline),
        }
    }
}
impl Selected<Original> {
    pub fn matches(
        &self,
        policy: &ReserveAuthorityPolicyV1,
        underwriting: &ReserveProviderTermsV1,
        utc: u64,
        options: &BoundedTransactionOptions,
    ) -> Result<()> {
        self.matches_intent(policy, underwriting)?;
        self.terms.matches(utc, options)
    }
    pub fn request(&self, deadline: Instant) -> ReserveAccountRegistrationRequest {
        Original::request(self, &self.terms, deadline)
    }
}
pub(super) fn read_intent(directory: &PrivateDirectory) -> Result<Option<Original>> {
    let names = directory.entries(3)?;
    if names.iter().any(|name| {
        !["original.nrt", "dispatch.nrt", "attempts"]
            .iter()
            .any(|allowed| name == *allowed)
    }) {
        return Err(invalid("reserve registration contains unknown material"));
    }
    let Some(bytes) = read_optional(directory, "original.nrt", MAX_ORIGINAL_BYTES)? else {
        require_empty(directory)?;
        return Ok(None);
    };
    let original: Original = norito::decode_canonical_with_limits(
        &bytes,
        norito::DecodeLimits::new(
            // Vec<u8> checkpoints consume the sequence-element allowance as bytes. Keep the
            // aggregate element/allocation limits while admitting the documented checkpoint cap.
            MAX_CHECKPOINT_BYTES,
            MAX_ORIGINAL_BYTES,
            MAX_ORIGINAL_BYTES,
            96 * 1024 * 1024,
            40,
        ),
    )
    .map_err(|_| invalid("invalid bounded original reserve intent"))?;
    original.validate()?;
    Ok(Some(original))
}
pub(super) fn read_original(directory: &PrivateDirectory) -> Result<Option<Selected<Original>>> {
    let Some(intent) = read_intent(directory)? else {
        return Ok(None);
    };
    let history = History::read(
        directory,
        Purpose::ReserveAccount(intent.selection.provider_id),
        intent.digest()?,
        &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
    )?;
    Selected::from_history(intent, history).map(Some)
}
pub(super) fn required_original(directory: &PrivateDirectory) -> Result<Selected<Original>> {
    read_original(directory)?.ok_or_else(|| invalid("original reserve registration is absent"))
}
pub(super) fn publish_intent(directory: &PrivateDirectory, original: &Original) -> Result<()> {
    original.validate()?;
    let bytes = encode(original, MAX_ORIGINAL_BYTES)?;
    if let Some(retained) = read_optional(directory, "original.nrt", MAX_ORIGINAL_BYTES)? {
        if retained != bytes {
            return Err(invalid("original reserve registration changed"));
        }
        return Ok(());
    }
    directory.write_atomic("original.nrt", &bytes, PublishMode::CreateNew)?;
    Ok(())
}
pub(super) fn explicit(
    directory: &PrivateDirectory,
    original: &Original,
    utc: u64,
    options: &BoundedTransactionOptions,
    account: &AccountService,
) -> Result<()> {
    let purpose = Purpose::ReserveAccount(original.selection.provider_id);
    let history = History::read(
        directory,
        purpose,
        original.digest()?,
        &crate::managed::native_operation::attempts::HistoryScope::FixedBody,
    )?;
    let terms = match history.retained_terms() {
        Some(terms) => {
            terms.matches(utc, options)?;
            terms.clone()
        }
        None => Terms::new(utc, options)?,
    };
    attempts::initial(
        history,
        terms,
        Observation::ordinary(),
        options.deadline,
        |attempt| {
            account
                .inspect_reserve_account_registration_preparation(
                    &attempt.wallet_path(),
                    &original.request(attempt.terms(), options.deadline),
                )
                .map_err(|_| {
                    invalid("reserve registration differs from its original wallet request")
                })
        },
        |attempt, _, deadline| {
            account
                .retain_reserve_account_registration_request(
                    &original.request(attempt.terms(), deadline),
                    &attempt.wallet_path(),
                )
                .map_err(|_| invalid("cannot retain exact unsigned reserve registration"))
        },
    )
}
