//! Shared strict monetary-policy JSON kernels and original allocation custody.
//!
//! These owners retain decoded leaves, not signatures or State authority. Their
//! enclosing owner funds its own storage, retains the original source/decoder,
//! and postpones refunds beyond every State/storage guard.

use core::num::NonZeroU32;
use std::alloc::Layout;

use iroha_allocation::{AllocationBudget, AllocationCharge, ChargedBuffer, ChargedBufferError};
use iroha_primitives::numeric::{ChargedQuantity, Quantity, QuantityJsonAdmissionError};
use norito::json::{self, JsonDeserialize};

use super::{PublicLaneStakingPolicy, RootFeeExemptions, RootFeePolicy};
use crate::{
    account::{
        AccountId,
        prepared_decode::{AccountJsonAdmissionError, ChargedAccount, ControllerCustody},
    },
    asset::AssetDefinitionId,
};

/// Original JSON/decoder failure or original allocation-pool refusal.
#[derive(Debug, thiserror::Error)]
pub enum MonetaryJsonAdmissionError {
    /// The original parser, typed identity, quantity, or cumulative decoder error.
    #[error(transparent)]
    Json(#[from] json::Error),
    /// Exact original-pool or native allocator refusal before creating its backing.
    #[error(transparent)]
    Allocation(#[from] ChargedBufferError),
}
impl From<QuantityJsonAdmissionError> for MonetaryJsonAdmissionError {
    fn from(error: QuantityJsonAdmissionError) -> Self {
        match error {
            QuantityJsonAdmissionError::Json(error) => Self::Json(error),
            QuantityJsonAdmissionError::Allocation(error) => Self::Allocation(error),
        }
    }
}
impl From<AccountJsonAdmissionError> for MonetaryJsonAdmissionError {
    fn from(error: AccountJsonAdmissionError) -> Self {
        match error {
            AccountJsonAdmissionError::Json(error) => Self::Json(error),
            AccountJsonAdmissionError::Allocation(error) => Self::Allocation(error),
        }
    }
}

/// Original backing charges for the immutable staking policy's dynamic leaves.
///
/// This opaque ledger is meaningful only beside its exact moved value. It must
/// outlive the value, including on refusal or unwind; it is not a cloning budget.
pub struct PublicLaneStakingPolicyCustody {
    minimum: AllocationCharge,
    escrow: ControllerCustody,
    sink: ControllerCustody,
}
impl PublicLaneStakingPolicyCustody {
    /// Check the identity of every original allocation pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.minimum.belongs_to(budget)
            && self.escrow.belongs_to(budget)
            && self.sink.belongs_to(budget)
    }
}

/// Original array, identity and quantity charges of one immutable fee policy.
pub struct RootFeePolicyCustody {
    sink: ControllerCustody,
    sponsor: ControllerCustody,
    exemptions: ExemptionCustody,
    rates: [AllocationCharge; 4],
}
impl RootFeePolicyCustody {
    /// Check every original pool, including the exemption ledger's own backing.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.sink.belongs_to(budget)
            && self.sponsor.belongs_to(budget)
            && self.exemptions.belongs_to(budget)
            && self.rates.iter().all(|charge| charge.belongs_to(budget))
    }
}
struct ExemptionCustody {
    accounts: AllocationCharge,
    identities: ChargedBuffer<ControllerCustody>,
}
impl ExemptionCustody {
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.accounts.belongs_to(budget)
            && self.identities.belongs_to(budget)
            && self
                .identities
                .as_slice()
                .iter()
                .all(|charge| charge.belongs_to(budget))
    }
}
struct AdmittedExemptions {
    value: RootFeeExemptions,
    custody: ExemptionCustody,
}

/// A decoded staking policy paired with its original physical leaf allocations.
///
/// The value is destroyed before its charges. There is no extra heap shell,
/// mutable access, or Clone; the enclosing retained graph admits its own backing.
pub struct AdmittedPublicLaneStakingPolicy {
    value: PublicLaneStakingPolicy,
    custody: PublicLaneStakingPolicyCustody,
}
impl AdmittedPublicLaneStakingPolicy {
    /// Decode directly through the same record relation as ordinary JSON.
    ///
    /// # Errors
    /// Preserves original syntax, decoder, typed-leaf and allocation refusals.
    /// Intrinsic and scope-specific policy validation remains with the State owner.
    pub fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, MonetaryJsonAdmissionError> {
        decode_staking(parser, &mut AdmittedDestination { budget })
    }
    /// Borrow the exact immutable value while retaining its original custody.
    #[must_use]
    pub fn get(&self) -> &PublicLaneStakingPolicy {
        &self.value
    }
    /// Check every original allocation pool by identity.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.custody.belongs_to(budget)
    }
    /// Move the original value and allocation ledger into a pre-funded owner.
    ///
    /// # Safety
    /// Immediately pair both in one closed immutable owner. Do not clone, grow or
    /// replace any backing while reusing this ledger. Drop the value before custody
    /// on all paths, and defer refunds beyond State/storage guards.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(
        self,
    ) -> (PublicLaneStakingPolicy, PublicLaneStakingPolicyCustody) {
        (self.value, self.custody)
    }
}
impl core::fmt::Debug for AdmittedPublicLaneStakingPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AdmittedPublicLaneStakingPolicy")
            .field(self.get())
            .finish()
    }
}
/// A decoded fee policy paired with exact original leaves and exemption backing.
pub struct AdmittedRootFeePolicy {
    value: RootFeePolicy,
    custody: RootFeePolicyCustody,
}
impl AdmittedRootFeePolicy {
    /// Decode directly through the same record relation as ordinary JSON.
    ///
    /// # Errors
    /// Preserves original syntax, decoder, typed-leaf and allocation refusals.
    /// Root-scope validation remains with the enclosing State owner.
    pub fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, MonetaryJsonAdmissionError> {
        decode_fees(parser, &mut AdmittedDestination { budget })
    }
    /// Borrow the exact immutable value while retaining its original custody.
    #[must_use]
    pub fn get(&self) -> &RootFeePolicy {
        &self.value
    }
    /// Check every original allocation pool by identity.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.custody.belongs_to(budget)
    }
    /// Move the exact value and ledger into a pre-funded closed owner.
    ///
    /// # Safety
    /// Retain the ledger beside the exact immutable moved value, never a clone or
    /// replacement. Destroy all value backing before custody on every path and
    /// defer refunds beyond State/storage guards.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(self) -> (RootFeePolicy, RootFeePolicyCustody) {
        (self.value, self.custody)
    }
}
impl core::fmt::Debug for AdmittedRootFeePolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AdmittedRootFeePolicy")
            .field(self.get())
            .finish()
    }
}

struct AdmittedText(ChargedBuffer<u8>);
impl AsMut<[u8]> for AdmittedText {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
impl AsRef<str> for AdmittedText {
    fn as_ref(&self) -> &str {
        core::str::from_utf8(self.0.as_slice()).expect("shared JSON string kernel produces UTF-8")
    }
}
fn admit_text(
    length: usize,
    budget: &AllocationBudget,
) -> Result<AdmittedText, MonetaryJsonAdmissionError> {
    let mut text = ChargedBuffer::new(length, budget)?;
    for _ in 0..length {
        text.push_reserved(0);
    }
    Ok(AdmittedText(text))
}
trait Destination {
    type Error: From<json::Error>;
    type Text: AsRef<str>;
    type Quantity;
    type Account;
    type Accounts;
    type Exemptions;
    type Staking;
    type Fees;
    fn parse_key<'a>(
        &mut self,
        parser: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, Self::Text>, Self::Error>;
    fn parse_text(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::Text, Self::Error>;
    fn quantity(&mut self, parser: &mut json::Parser<'_>) -> Result<Self::Quantity, Self::Error>;
    fn account(&self, parser: &mut json::Parser<'_>) -> Result<Self::Account, Self::Error>;
    fn accounts(&self, count: usize) -> Result<Self::Accounts, Self::Error>;
    fn push_account(accounts: &mut Self::Accounts, account: Self::Account);
    fn finish_accounts(
        &mut self,
        accounts: Self::Accounts,
    ) -> Result<Self::Exemptions, Self::Error>;
    fn finish_staking(
        &mut self,
        fields: StakingFields<Self::Quantity, Self::Account>,
    ) -> Result<Self::Staking, Self::Error>;
    fn finish_fees(
        &mut self,
        fields: FeeFields<Self::Quantity, Self::Account, Self::Exemptions>,
    ) -> Result<Self::Fees, Self::Error>;
}
struct OrdinaryDestination;
impl Destination for OrdinaryDestination {
    type Error = json::Error;
    type Text = String;
    type Quantity = Quantity;
    type Account = AccountId;
    type Accounts = Vec<AccountId>;
    type Exemptions = RootFeeExemptions;
    type Staking = PublicLaneStakingPolicy;
    type Fees = RootFeePolicy;
    fn parse_key<'a>(&mut self, p: &mut json::Parser<'a>) -> Result<json::KeyRef<'a>, json::Error> {
        p.parse_key()
    }
    fn parse_text(&mut self, p: &mut json::Parser<'_>) -> Result<String, json::Error> {
        p.parse_string()
    }
    fn quantity(&mut self, p: &mut json::Parser<'_>) -> Result<Quantity, json::Error> {
        Quantity::json_deserialize(p)
    }
    fn account(&self, p: &mut json::Parser<'_>) -> Result<AccountId, json::Error> {
        AccountId::json_deserialize(p)
    }
    fn accounts(&self, count: usize) -> Result<Vec<AccountId>, json::Error> {
        let bytes = account_array_bytes(count)?;
        norito::core::reserve_decode_allocation(bytes)
            .map_err(json::Error::from_decode_resource)?;
        let mut accounts = Vec::new();
        accounts.try_reserve_exact(count).map_err(|_| {
            json::Error::from_decode_resource(norito::Error::AllocationFailed {
                bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
            })
        })?;
        if accounts.capacity() != count {
            return Err(json::Error::from_decode_resource(
                norito::Error::AllocationFailed {
                    bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
                },
            ));
        }
        Ok(accounts)
    }
    fn push_account(accounts: &mut Vec<AccountId>, account: AccountId) {
        accounts.push(account);
    }
    fn finish_accounts(
        &mut self,
        accounts: Vec<AccountId>,
    ) -> Result<RootFeeExemptions, json::Error> {
        RootFeeExemptions::from_sorted(accounts).map_err(json::Error::from_decode_resource)
    }
    fn finish_staking(
        &mut self,
        f: StakingFields<Quantity, AccountId>,
    ) -> Result<PublicLaneStakingPolicy, json::Error> {
        Ok(f.into_value(|q| q, |a| a))
    }
    fn finish_fees(
        &mut self,
        f: FeeFields<Quantity, AccountId, RootFeeExemptions>,
    ) -> Result<RootFeePolicy, json::Error> {
        Ok(f.into_value(|q| q, |a| a, |e| e))
    }
}
struct AdmittedAccounts {
    // Physical account values must retire before their original nested charges.
    values: ChargedBuffer<AccountId>,
    identities: ChargedBuffer<ControllerCustody>,
}
struct AdmittedDestination<'a> {
    budget: &'a AllocationBudget,
}
impl Destination for AdmittedDestination<'_> {
    type Error = MonetaryJsonAdmissionError;
    type Text = AdmittedText;
    type Quantity = ChargedQuantity;
    type Account = ChargedAccount;
    type Accounts = AdmittedAccounts;
    type Exemptions = AdmittedExemptions;
    type Staking = AdmittedPublicLaneStakingPolicy;
    type Fees = AdmittedRootFeePolicy;
    fn parse_key<'a>(
        &mut self,
        p: &mut json::Parser<'a>,
    ) -> Result<json::KeyRef<'a, AdmittedText>, Self::Error> {
        p.parse_key_with_buffer(|n| admit_text(n, self.budget))
    }
    fn parse_text(&mut self, p: &mut json::Parser<'_>) -> Result<AdmittedText, Self::Error> {
        p.parse_string_with_buffer(|n| admit_text(n, self.budget))
    }
    fn quantity(&mut self, p: &mut json::Parser<'_>) -> Result<ChargedQuantity, Self::Error> {
        Ok(ChargedQuantity::try_decode_json(p, self.budget)?)
    }
    fn account(&self, p: &mut json::Parser<'_>) -> Result<ChargedAccount, Self::Error> {
        Ok(ChargedAccount::try_decode_json(p, self.budget)?)
    }
    fn accounts(&self, count: usize) -> Result<AdmittedAccounts, Self::Error> {
        norito::core::reserve_decode_allocation(account_array_bytes(count)?)
            .map_err(json::Error::from_decode_resource)?;
        // Admit both concrete arrays before constructing any account leaf. The
        // second array is ledger storage, not a second account representation.
        Ok(AdmittedAccounts {
            values: ChargedBuffer::new(count, self.budget)?,
            identities: ChargedBuffer::new(count, self.budget)?,
        })
    }
    #[allow(unsafe_code)]
    fn push_account(accounts: &mut AdmittedAccounts, account: ChargedAccount) {
        // SAFETY: both fixed-capacity arrays are funded before parsing. Moves
        // cannot grow; the closed owner destroys its account array first.
        let (value, custody) = unsafe { account.into_allocation_parts() };
        accounts.values.push_reserved(value);
        accounts.identities.push_reserved(custody);
    }
    #[allow(unsafe_code)]
    fn finish_accounts(
        &mut self,
        accounts: AdmittedAccounts,
    ) -> Result<AdmittedExemptions, Self::Error> {
        // Validate before separating custody: a refusal drops the original closed
        // owner, including every account graph and the ledger's own backing.
        RootFeeExemptions::validate_sorted(accounts.values.as_slice())
            .map_err(json::Error::from_decode_resource)?;
        let AdmittedAccounts { values, identities } = accounts;
        // SAFETY: validation is complete. There is no fallible operation after
        // extraction; the exact Vec and original charge move to a closed owner.
        let (values, charge) = unsafe { values.into_allocation_parts() };
        Ok(AdmittedExemptions {
            value: RootFeeExemptions::from_validated_sorted(values),
            custody: ExemptionCustody {
                accounts: charge,
                identities,
            },
        })
    }
    #[allow(unsafe_code)]
    fn finish_staking(
        &mut self,
        f: StakingFields<ChargedQuantity, ChargedAccount>,
    ) -> Result<AdmittedPublicLaneStakingPolicy, Self::Error> {
        let mut minimum = None;
        let mut escrow = None;
        let mut sink = None;
        let mut account_index = 0;
        // SAFETY: extraction moves the original leaves exactly once; no further
        // fallible operation occurs before the closed value-first owner exists.
        let value = f.into_value(
            |q| {
                let (v, charge) = unsafe { q.into_allocation_parts() };
                minimum = Some(charge);
                v
            },
            |a| {
                let (v, custody) = unsafe { a.into_allocation_parts() };
                if account_index == 0 {
                    escrow = Some(custody);
                } else {
                    sink = Some(custody);
                }
                account_index += 1;
                v
            },
        );
        Ok(AdmittedPublicLaneStakingPolicy {
            value,
            custody: PublicLaneStakingPolicyCustody {
                minimum: minimum.expect("one minimum"),
                escrow: escrow.expect("one escrow"),
                sink: sink.expect("one sink"),
            },
        })
    }
    #[allow(unsafe_code)]
    fn finish_fees(
        &mut self,
        f: FeeFields<ChargedQuantity, ChargedAccount, AdmittedExemptions>,
    ) -> Result<AdmittedRootFeePolicy, Self::Error> {
        let mut rates = [const { None }; 4];
        let mut rate_index = 0;
        let mut sink = None;
        let mut sponsor = None;
        let mut account_index = 0;
        let mut exemptions = None;
        // SAFETY: exact leaves and all their original charges move without any
        // allocation, clone, growth or fallible operation into this closed owner.
        let value = f.into_value(
            |q| {
                let (v, charge) = unsafe { q.into_allocation_parts() };
                rates[rate_index] = Some(charge);
                rate_index += 1;
                v
            },
            |a| {
                let (v, custody) = unsafe { a.into_allocation_parts() };
                if account_index == 0 {
                    sink = Some(custody);
                } else {
                    sponsor = Some(custody);
                }
                account_index += 1;
                v
            },
            |e| {
                exemptions = Some(e.custody);
                e.value
            },
        );
        Ok(AdmittedRootFeePolicy {
            value,
            custody: RootFeePolicyCustody {
                sink: sink.expect("one sink"),
                sponsor: sponsor.expect("one sponsor"),
                exemptions: exemptions.expect("one exemptions array"),
                rates: rates.map(|charge| charge.expect("four exact rates")),
            },
        })
    }
}
fn account_array_bytes(count: usize) -> Result<usize, json::Error> {
    Layout::array::<AccountId>(count)
        .map(|layout| layout.size())
        .map_err(|_| json::Error::DecodeResourceLimit)
}

// The ordinary Vec array kernel serves both destinations, including its exact
// delimiter diagnostics. Strict ordering is checked only after every element,
// preserving malformed-leaf error precedence.
fn decode_exemptions<D: Destination>(
    p: &mut json::Parser<'_>,
    d: &mut D,
) -> Result<D::Exemptions, D::Error> {
    let accounts =
        p.parse_array_with(|count| d.accounts(count), |p| d.account(p), D::push_account)?;
    d.finish_accounts(accounts)
}
pub(super) fn decode_exemptions_ordinary(
    p: &mut json::Parser<'_>,
) -> Result<RootFeeExemptions, json::Error> {
    decode_exemptions(p, &mut OrdinaryDestination)
}
pub(super) fn decode_staking_ordinary(
    p: &mut json::Parser<'_>,
) -> Result<PublicLaneStakingPolicy, json::Error> {
    decode_staking(p, &mut OrdinaryDestination)
}
pub(super) fn decode_fees_ordinary(p: &mut json::Parser<'_>) -> Result<RootFeePolicy, json::Error> {
    decode_fees(p, &mut OrdinaryDestination)
}

struct StakingFields<Q, A> {
    min_validator_stake: Q,
    max_stake_shares_per_validator: NonZeroU32,
    max_pending_unbonds_per_share: NonZeroU32,
    unbonding_delay_ms: u64,
    max_slash_bps: u16,
    stake_asset_id: AssetDefinitionId,
    stake_escrow_account_id: A,
    slash_sink_account_id: A,
}
impl<Q, A> StakingFields<Q, A> {
    fn into_value(
        self,
        mut quantity: impl FnMut(Q) -> Quantity,
        mut account: impl FnMut(A) -> AccountId,
    ) -> PublicLaneStakingPolicy {
        PublicLaneStakingPolicy {
            min_validator_stake: quantity(self.min_validator_stake),
            max_stake_shares_per_validator: self.max_stake_shares_per_validator,
            max_pending_unbonds_per_share: self.max_pending_unbonds_per_share,
            unbonding_delay_ms: self.unbonding_delay_ms,
            max_slash_bps: self.max_slash_bps,
            stake_asset_id: self.stake_asset_id,
            stake_escrow_account_id: account(self.stake_escrow_account_id),
            slash_sink_account_id: account(self.slash_sink_account_id),
        }
    }
}
fn decode_staking<D: Destination>(
    p: &mut json::Parser<'_>,
    d: &mut D,
) -> Result<D::Staking, D::Error> {
    p.skip_ws();
    p.preflight_object_entries()?;
    p.expect(b'{')?;
    p.skip_ws();
    let mut min_validator_stake = None;
    let mut max_stake_shares_per_validator = None;
    let mut max_pending_unbonds_per_share = None;
    let mut unbonding_delay_ms = None;
    let mut max_slash_bps = None;
    let mut stake_asset_id = None;
    let mut stake_escrow_account_id = None;
    let mut slash_sink_account_id = None;
    if !p.try_consume_char(b'}')? {
        loop {
            p.skip_ws();
            let key = d.parse_key(p)?;
            let text = match &key {
                json::KeyRef::Borrowed(value) => *value,
                json::KeyRef::Owned(value) => value.as_ref(),
            };
            match text {
                "min_validator_stake" => {
                    if min_validator_stake.is_some() {
                        return Err(json::Error::duplicate_field("min_validator_stake").into());
                    }
                    min_validator_stake = Some(d.quantity(p)?);
                }
                "max_stake_shares_per_validator" => {
                    if max_stake_shares_per_validator.is_some() {
                        return Err(
                            json::Error::duplicate_field("max_stake_shares_per_validator").into(),
                        );
                    }
                    max_stake_shares_per_validator =
                        Some(<NonZeroU32 as JsonDeserialize>::json_deserialize(p)?);
                }
                "max_pending_unbonds_per_share" => {
                    if max_pending_unbonds_per_share.is_some() {
                        return Err(
                            json::Error::duplicate_field("max_pending_unbonds_per_share").into(),
                        );
                    }
                    max_pending_unbonds_per_share =
                        Some(<NonZeroU32 as JsonDeserialize>::json_deserialize(p)?);
                }
                "unbonding_delay_ms" => {
                    if unbonding_delay_ms.is_some() {
                        return Err(json::Error::duplicate_field("unbonding_delay_ms").into());
                    }
                    unbonding_delay_ms = Some(<u64 as JsonDeserialize>::json_deserialize(p)?);
                }
                "max_slash_bps" => {
                    if max_slash_bps.is_some() {
                        return Err(json::Error::duplicate_field("max_slash_bps").into());
                    }
                    max_slash_bps = Some(<u16 as JsonDeserialize>::json_deserialize(p)?);
                }
                "stake_asset_id" => {
                    if stake_asset_id.is_some() {
                        return Err(json::Error::duplicate_field("stake_asset_id").into());
                    }
                    stake_asset_id = Some({
                        let text = d.parse_text(p)?;
                        AssetDefinitionId::parse_json_address_text(text.as_ref())?
                    });
                }
                "stake_escrow_account_id" => {
                    if stake_escrow_account_id.is_some() {
                        return Err(json::Error::duplicate_field("stake_escrow_account_id").into());
                    }
                    stake_escrow_account_id = Some(d.account(p)?);
                }
                "slash_sink_account_id" => {
                    if slash_sink_account_id.is_some() {
                        return Err(json::Error::duplicate_field("slash_sink_account_id").into());
                    }
                    slash_sink_account_id = Some(d.account(p)?);
                }
                _ => return Err(json::Error::unknown_field(text).into()),
            }
            p.skip_ws();
            if p.try_consume_char(b',')? {
                continue;
            }
            p.expect(b'}')?;
            break;
        }
    }
    d.finish_staking(StakingFields {
        min_validator_stake: min_validator_stake
            .ok_or_else(|| json::Error::missing_field("min_validator_stake"))?,
        max_stake_shares_per_validator: max_stake_shares_per_validator
            .ok_or_else(|| json::Error::missing_field("max_stake_shares_per_validator"))?,
        max_pending_unbonds_per_share: max_pending_unbonds_per_share
            .ok_or_else(|| json::Error::missing_field("max_pending_unbonds_per_share"))?,
        unbonding_delay_ms: unbonding_delay_ms
            .ok_or_else(|| json::Error::missing_field("unbonding_delay_ms"))?,
        max_slash_bps: max_slash_bps.ok_or_else(|| json::Error::missing_field("max_slash_bps"))?,
        stake_asset_id: stake_asset_id
            .ok_or_else(|| json::Error::missing_field("stake_asset_id"))?,
        stake_escrow_account_id: stake_escrow_account_id
            .ok_or_else(|| json::Error::missing_field("stake_escrow_account_id"))?,
        slash_sink_account_id: slash_sink_account_id
            .ok_or_else(|| json::Error::missing_field("slash_sink_account_id"))?,
    })
}

struct FeeFields<Q, A, E> {
    fee_asset_id: AssetDefinitionId,
    fee_sink_account_id: A,
    sponsor_vault_custody_account_id: A,
    successful_claim_fee_exempt_authorities: E,
    base_fee: Q,
    per_byte_fee: Q,
    per_instruction_fee: Q,
    per_gas_unit_fee: Q,
}
impl<Q, A, E> FeeFields<Q, A, E> {
    fn into_value(
        self,
        mut quantity: impl FnMut(Q) -> Quantity,
        mut account: impl FnMut(A) -> AccountId,
        exemption: impl FnOnce(E) -> RootFeeExemptions,
    ) -> RootFeePolicy {
        RootFeePolicy {
            fee_asset_id: self.fee_asset_id,
            fee_sink_account_id: account(self.fee_sink_account_id),
            sponsor_vault_custody_account_id: account(self.sponsor_vault_custody_account_id),
            successful_claim_fee_exempt_authorities: exemption(
                self.successful_claim_fee_exempt_authorities,
            ),
            base_fee: quantity(self.base_fee),
            per_byte_fee: quantity(self.per_byte_fee),
            per_instruction_fee: quantity(self.per_instruction_fee),
            per_gas_unit_fee: quantity(self.per_gas_unit_fee),
        }
    }
}
fn decode_fees<D: Destination>(p: &mut json::Parser<'_>, d: &mut D) -> Result<D::Fees, D::Error> {
    p.skip_ws();
    p.preflight_object_entries()?;
    p.expect(b'{')?;
    p.skip_ws();
    let mut fee_asset_id = None;
    let mut fee_sink_account_id = None;
    let mut sponsor_vault_custody_account_id = None;
    let mut successful_claim_fee_exempt_authorities = None;
    let mut base_fee = None;
    let mut per_byte_fee = None;
    let mut per_instruction_fee = None;
    let mut per_gas_unit_fee = None;
    if !p.try_consume_char(b'}')? {
        loop {
            p.skip_ws();
            let key = d.parse_key(p)?;
            let text = match &key {
                json::KeyRef::Borrowed(value) => *value,
                json::KeyRef::Owned(value) => value.as_ref(),
            };
            match text {
                "fee_asset_id" => {
                    if fee_asset_id.is_some() {
                        return Err(json::Error::duplicate_field("fee_asset_id").into());
                    }
                    fee_asset_id = Some({
                        let text = d.parse_text(p)?;
                        AssetDefinitionId::parse_json_address_text(text.as_ref())?
                    });
                }
                "fee_sink_account_id" => {
                    if fee_sink_account_id.is_some() {
                        return Err(json::Error::duplicate_field("fee_sink_account_id").into());
                    }
                    fee_sink_account_id = Some(d.account(p)?);
                }
                "sponsor_vault_custody_account_id" => {
                    if sponsor_vault_custody_account_id.is_some() {
                        return Err(json::Error::duplicate_field(
                            "sponsor_vault_custody_account_id",
                        )
                        .into());
                    }
                    sponsor_vault_custody_account_id = Some(d.account(p)?);
                }
                "successful_claim_fee_exempt_authorities" => {
                    if successful_claim_fee_exempt_authorities.is_some() {
                        return Err(json::Error::duplicate_field(
                            "successful_claim_fee_exempt_authorities",
                        )
                        .into());
                    }
                    successful_claim_fee_exempt_authorities = Some(decode_exemptions(p, d)?);
                }
                "base_fee" => {
                    if base_fee.is_some() {
                        return Err(json::Error::duplicate_field("base_fee").into());
                    }
                    base_fee = Some(d.quantity(p)?);
                }
                "per_byte_fee" => {
                    if per_byte_fee.is_some() {
                        return Err(json::Error::duplicate_field("per_byte_fee").into());
                    }
                    per_byte_fee = Some(d.quantity(p)?);
                }
                "per_instruction_fee" => {
                    if per_instruction_fee.is_some() {
                        return Err(json::Error::duplicate_field("per_instruction_fee").into());
                    }
                    per_instruction_fee = Some(d.quantity(p)?);
                }
                "per_gas_unit_fee" => {
                    if per_gas_unit_fee.is_some() {
                        return Err(json::Error::duplicate_field("per_gas_unit_fee").into());
                    }
                    per_gas_unit_fee = Some(d.quantity(p)?);
                }
                _ => return Err(json::Error::unknown_field(text).into()),
            }
            p.skip_ws();
            if p.try_consume_char(b',')? {
                continue;
            }
            p.expect(b'}')?;
            break;
        }
    }
    d.finish_fees(FeeFields {
        fee_asset_id: fee_asset_id.ok_or_else(|| json::Error::missing_field("fee_asset_id"))?,
        fee_sink_account_id: fee_sink_account_id
            .ok_or_else(|| json::Error::missing_field("fee_sink_account_id"))?,
        sponsor_vault_custody_account_id: sponsor_vault_custody_account_id
            .ok_or_else(|| json::Error::missing_field("sponsor_vault_custody_account_id"))?,
        successful_claim_fee_exempt_authorities: successful_claim_fee_exempt_authorities
            .ok_or_else(|| json::Error::missing_field("successful_claim_fee_exempt_authorities"))?,
        base_fee: base_fee.ok_or_else(|| json::Error::missing_field("base_fee"))?,
        per_byte_fee: per_byte_fee.ok_or_else(|| json::Error::missing_field("per_byte_fee"))?,
        per_instruction_fee: per_instruction_fee
            .ok_or_else(|| json::Error::missing_field("per_instruction_fee"))?,
        per_gas_unit_fee: per_gas_unit_fee
            .ok_or_else(|| json::Error::missing_field("per_gas_unit_fee"))?,
    })
}

#[cfg(test)]
mod tests;
