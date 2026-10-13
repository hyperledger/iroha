//! Native bond-servicing kernel records.
//!
//! A bond is an ordinary scale-0 fungible asset definition whose identifier is
//! also the bond identifier. [`BondRecord`] stores the immutable registered
//! [`BondTerms`] (including the fully materialised schedule) and the mutable
//! [`BondState`] (lifecycle, holder snapshots and cash-flow accounting). Every
//! legally material cash-flow operation is a native instruction in
//! [`crate::isi::bond`]; see `specs/finance/bond_ops.md` for the normative
//! contract.
//!
//! All arithmetic is exact decimal arithmetic on [`Quantity`]; no floating point
//! is used. Validation that depends only on the terms lives here so that SDKs and
//! Core share one implementation.
use std::collections::{BTreeMap, BTreeSet};

use iroha_crypto::derive_non_signing_ed25519_public_key;
use iroha_primitives::numeric::{Numeric, NumericSpec, Quantity, RoundingMode};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId, asset::AssetDefinitionId,
};

/// A bond is identified by the asset definition of its units.
pub type BondId = AssetDefinitionId;

/// Maximum number of scheduled cash flows in registered terms.
pub const BOND_MAX_CASHFLOWS: usize = 400;
/// Maximum number of investor holders captured by one record-date snapshot.
pub const BOND_MAX_SNAPSHOT_HOLDERS: usize = 4096;
/// Maximum ISIN length (ISO 6166).
pub const BOND_ISIN_MAX_LEN: usize = 12;
/// Maximum CFI length (ISO 10962).
pub const BOND_CFI_MAX_LEN: usize = 6;
/// Maximum issuer LEI length (ISO 17442).
pub const BOND_LEI_MAX_LEN: usize = 20;
/// Maximum bond-data-taxonomy version label length.
pub const BOND_BDT_VERSION_MAX_LEN: usize = 32;
/// Basis-point denominator (`10_000` = 100 %).
pub const BOND_BPS_DENOMINATOR: u32 = 10_000;
/// Coupon frequencies (payments per year) admitted by the regular fixed-rate rule.
pub const BOND_COUPON_FREQUENCIES: [u8; 5] = [0, 1, 2, 4, 12];
/// Domain separator for the deterministic key-less bond vault account.
pub const BOND_VAULT_ACCOUNT_DOMAIN_V1: &[u8] = b"iroha:bond:vault:v1";

/// Derive the deterministic key-less vault account that holds funded payment assets of `bond`.
///
/// The vault public key is the non-signing Ed25519 point
/// `derive_non_signing_ed25519_public_key("iroha:bond:vault:v1", [bond.aid_bytes])`,
/// so no private key exists and nobody can sign for the vault. The derivation
/// is network independent: the bond identifier alone fixes its vault.
#[must_use]
pub fn bond_vault_account_id(bond: &BondId) -> AccountId {
    let aid_bytes = bond.aid_bytes();
    AccountId::new(derive_non_signing_ed25519_public_key(
        BOND_VAULT_ACCOUNT_DOMAIN_V1,
        &[aid_bytes.as_slice()],
    ))
}

/// Day-count convention label recorded with the terms.
///
/// The first-release kernel requires regular periods, so the label does not
/// change any computed amount; it is retained for the legal record.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondDayCount")]
#[repr(u8)]
pub enum BondDayCount {
    /// Actual/Actual (ICMA).
    ActActIcma,
    /// 30/360.
    Thirty360,
    /// Actual/360.
    Act360,
    /// Actual/365 (Fixed).
    Act365Fixed,
}

/// Kind of one scheduled cash flow.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondCashflowKind")]
#[repr(u8)]
pub enum BondCashflowKind {
    /// Periodic interest payment; units are not touched.
    Coupon,
    /// Principal repayment; claiming burns the holder's units.
    Redemption,
}

/// Optional issuer call provision.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondCallTerms")]
#[norito(deny_unknown_fields)]
pub struct BondCallTerms {
    /// Earliest call date (Unix milliseconds).
    pub first_call_date_ms: u64,
    /// Call price in basis points of the denomination (`10_000` = par).
    pub price_bps: u32,
    /// Minimum notice between the committed call block and the call date.
    pub notice_ms: u64,
}

/// Market identifiers and taxonomy references.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondIdentifiers")]
#[norito(deny_unknown_fields)]
pub struct BondIdentifiers {
    /// ISO 6166 ISIN.
    pub isin: Option<String>,
    /// ISO 10962 CFI code.
    pub cfi: Option<String>,
    /// ISO 17442 issuer LEI.
    pub issuer_lei: Option<String>,
    /// Bond data taxonomy version label.
    pub bdt_version: String,
    /// SHA-256 of the bond data taxonomy document, when published.
    #[norito(json = "crate::json_helpers::fixed_bytes_hex::option")]
    pub bdt_document_sha256: Option<[u8; 32]>,
}

/// One fully materialised scheduled cash flow.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondCashflowTerms")]
#[norito(deny_unknown_fields)]
pub struct BondCashflowTerms {
    /// Contiguous schedule index starting at zero.
    pub index: u16,
    /// Coupon or redemption.
    pub kind: BondCashflowKind,
    /// Record date (Unix milliseconds); the holder snapshot is taken at or after it.
    pub record_date_ms: u64,
    /// Payment date (Unix milliseconds); claims open at or after it.
    pub payment_date_ms: u64,
    /// Exact payment-asset amount per bond unit. It may carry more decimals than
    /// the payment asset; each holder's payment is rounded down to the payment
    /// asset scale.
    pub amount_per_unit: Quantity,
}

/// Immutable registered bond terms.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondTerms")]
#[norito(deny_unknown_fields)]
pub struct BondTerms {
    /// Issuer; must own the bond asset definition and sign registration.
    pub issuer: AccountId,
    /// Paying agent; records, funds and may push claims on behalf of holders.
    pub paying_agent: AccountId,
    /// Asset definition used for every payment (for example a EUR e-money token).
    pub payment_asset: AssetDefinitionId,
    /// Payment-asset amount per bond unit.
    pub denomination: Quantity,
    /// Annual coupon rate in basis points (`650` = 6.50 %); zero for zero-coupon bonds.
    pub coupon_rate_bps: u32,
    /// Coupon payments per year: 0 (zero-coupon), 1, 2, 4 or 12.
    pub coupon_frequency: u8,
    /// Day-count label (regular periods only in the first release).
    pub day_count: BondDayCount,
    /// Issue date (Unix milliseconds).
    pub issue_date_ms: u64,
    /// Maturity date (Unix milliseconds); equals the redemption payment date.
    pub maturity_date_ms: u64,
    /// Redemption price in basis points of the denomination (`10_000` = par).
    pub redemption_price_bps: u32,
    /// Optional issuer call provision.
    pub call: Option<BondCallTerms>,
    /// Fully materialised schedule, 1..=400 entries.
    pub cashflows: Vec<BondCashflowTerms>,
    /// Market identifiers and taxonomy references.
    pub identifiers: BondIdentifiers,
    /// SHA-256 of the legal terms document.
    #[norito(json = "crate::json_helpers::fixed_bytes_hex")]
    pub terms_sha256: [u8; 32],
}

/// Bond lifecycle.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondLifecycle")]
#[repr(u8)]
pub enum BondLifecycle {
    /// Registered and servicing its original schedule.
    Active,
    /// Called by the issuer; the call redemption replaced later scheduled cash flows.
    Called,
    /// The redemption cash flow was closed.
    Matured,
    /// The paying agent declared a payment default.
    Defaulted,
}

/// Status of one cash flow.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondCashflowStatus")]
#[repr(u8)]
pub enum BondCashflowStatus {
    /// Not yet recorded.
    Scheduled,
    /// Holder snapshot taken; awaiting funding.
    Recorded,
    /// Exact amount due is held by the bond vault; holders may claim.
    Funded,
    /// Every snapshot holder claimed and the residual returned to the issuer.
    Closed,
    /// Payment default declared for this cash flow.
    Defaulted,
    /// Superseded by an issuer call before it was recorded.
    Cancelled,
}

/// String JSON codec for unit enums (`"Coupon"`, `"Active"`, ...).
macro_rules! bond_unit_enum_json {
    ($ty:ident { $($variant:ident),+ $(,)? }) => {
        impl $ty {
            /// Stable variant label used by JSON and display.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($variant),)+
                }
            }
        }
        impl core::fmt::Display for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }
        impl core::str::FromStr for $ty {
            type Err = String;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $(stringify!($variant) => Ok(Self::$variant),)+
                    other => Err(format!(concat!("unknown ", stringify!($ty), " `{}`"), other)),
                }
            }
        }
        impl norito::json::JsonSerialize for $ty {
            fn json_serialize(&self, out: &mut String) {
                norito::json::JsonSerialize::json_serialize(self.as_str(), out);
            }
            fn json_serialize_to(
                &self,
                out: &mut dyn norito::json::JsonWriteSink,
            ) -> Result<(), norito::json::BoundedJsonError> {
                norito::json::JsonSerialize::json_serialize_to(self.as_str(), out)
            }
        }
        impl norito::json::JsonDeserialize for $ty {
            fn json_deserialize(
                parser: &mut norito::json::Parser<'_>,
            ) -> Result<Self, norito::json::Error> {
                let raw = parser.parse_string()?;
                raw.parse().map_err(norito::json::Error::Message)
            }
        }
    };
}
bond_unit_enum_json!(BondDayCount {
    ActActIcma,
    Thirty360,
    Act360,
    Act365Fixed
});
bond_unit_enum_json!(BondCashflowKind { Coupon, Redemption });
bond_unit_enum_json!(BondLifecycle {
    Active,
    Called,
    Matured,
    Defaulted
});
bond_unit_enum_json!(BondCashflowStatus {
    Scheduled,
    Recorded,
    Funded,
    Closed,
    Defaulted,
    Cancelled
});

/// Mutable servicing state of one cash flow, together with its effective terms.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondCashflowState")]
#[norito(deny_unknown_fields)]
pub struct BondCashflowState {
    /// Effective terms. Registered cash flows copy the registered terms; a call
    /// appends one redemption with the next index.
    pub terms: BondCashflowTerms,
    /// Servicing status.
    pub status: BondCashflowStatus,
    /// Entitled units per investor holder at record time.
    pub snapshot: BTreeMap<AccountId, Quantity>,
    /// Sum of snapshot units.
    pub entitled_units: Quantity,
    /// Sum over holders of `floor(units × amount_per_unit)` at the payment-asset scale.
    pub amount_due: Quantity,
    /// Amount moved into the vault for this cash flow.
    pub funded: Quantity,
    /// Amount paid to holders from the vault for this cash flow.
    pub paid: Quantity,
    /// Holders that already claimed.
    pub claimed: BTreeSet<AccountId>,
    /// Committed block time of the record instruction.
    pub recorded_at_ms: Option<u64>,
    /// Committed block time of the fund instruction.
    pub funded_at_ms: Option<u64>,
    /// Committed block time of the close instruction.
    pub closed_at_ms: Option<u64>,
    /// Evidence digest attached when the cash flow defaulted.
    #[norito(json = "crate::json_helpers::fixed_bytes_hex::option")]
    pub evidence_sha256: Option<[u8; 32]>,
}

impl BondCashflowState {
    /// Fresh scheduled state for `terms`.
    #[must_use]
    pub fn scheduled(terms: BondCashflowTerms) -> Self {
        Self {
            terms,
            status: BondCashflowStatus::Scheduled,
            snapshot: BTreeMap::new(),
            entitled_units: Quantity::zero(),
            amount_due: Quantity::zero(),
            funded: Quantity::zero(),
            paid: Quantity::zero(),
            claimed: BTreeSet::new(),
            recorded_at_ms: None,
            funded_at_ms: None,
            closed_at_ms: None,
            evidence_sha256: None,
        }
    }

    /// Return whether every snapshot holder has claimed.
    #[must_use]
    pub fn all_claimed(&self) -> bool {
        self.snapshot
            .keys()
            .all(|holder| self.claimed.contains(holder))
    }
}

/// Mutable bond state.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondState")]
#[norito(deny_unknown_fields)]
pub struct BondState {
    /// Lifecycle.
    pub lifecycle: BondLifecycle,
    /// Units in existence: the definition total minus units burned by redemption claims.
    pub outstanding_units: Quantity,
    /// Units burned by redemption claims.
    pub redeemed_units: Quantity,
    /// Set when a redemption cash flow is recorded; every movement of the bond
    /// asset other than the redemption claim burn is then rejected.
    pub transfers_frozen: bool,
    /// Effective schedule and servicing state, ordered by index.
    pub cashflows: Vec<BondCashflowState>,
}

/// Authoritative on-chain bond record.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::bond::BondRecord")]
#[norito(deny_unknown_fields)]
pub struct BondRecord {
    /// Bond identifier (the bond asset definition).
    pub id: BondId,
    /// Deterministic key-less vault ([`bond_vault_account_id`] of `id`).
    pub vault: AccountId,
    /// Immutable registered terms.
    pub terms: BondTerms,
    /// Mutable servicing state.
    pub state: BondState,
}

impl BondRecord {
    /// Construct the initial record of a freshly registered bond.
    #[must_use]
    pub fn registered(id: BondId, terms: BondTerms, outstanding_units: Quantity) -> Self {
        let cashflows = terms
            .cashflows
            .iter()
            .cloned()
            .map(BondCashflowState::scheduled)
            .collect();
        Self {
            vault: bond_vault_account_id(&id),
            id,
            terms,
            state: BondState {
                lifecycle: BondLifecycle::Active,
                outstanding_units,
                redeemed_units: Quantity::zero(),
                transfers_frozen: false,
                cashflows,
            },
        }
    }

    /// Effective cash flow with `index`.
    #[must_use]
    pub fn cashflow(&self, index: u16) -> Option<&BondCashflowState> {
        self.state.cashflows.get(usize::from(index))
    }

    /// Mutable effective cash flow with `index`.
    pub fn cashflow_mut(&mut self, index: u16) -> Option<&mut BondCashflowState> {
        self.state.cashflows.get_mut(usize::from(index))
    }

    /// Bond vault account of this record.
    #[must_use]
    pub fn vault(&self) -> &AccountId {
        &self.vault
    }
}

/// Typed bond-kernel rejection.
///
/// Core surfaces every variant as an `InvariantViolation` whose message starts
/// with the stable `bond.<code>:` prefix returned by [`BondError::code`].
#[derive(Debug, Clone, PartialEq, Eq, displaydoc::Display, thiserror::Error)]
pub enum BondError {
    /// bond.invalid_terms: {0}
    InvalidTerms(String),
    /// bond.unauthorized: {0}
    Unauthorized(String),
    /// bond.not_registered: bond {0} is not registered
    NotRegistered(String),
    /// bond.already_registered: bond {0} is already registered
    AlreadyRegistered(String),
    /// bond.unknown_cashflow: bond has no cash flow {0}
    UnknownCashflow(u16),
    /// bond.invalid_state: {0}
    InvalidState(String),
    /// bond.too_early: {0}
    TooEarly(String),
    /// bond.encumbered: {0}
    Encumbered(String),
    /// bond.snapshot_too_large: record-date snapshot has {0} holders (maximum 4096)
    SnapshotTooLarge(usize),
    /// bond.not_in_snapshot: {0} is not entitled to this cash flow
    NotInSnapshot(String),
    /// bond.already_claimed: {0} already claimed this cash flow
    AlreadyClaimed(String),
    /// bond.transfers_frozen: bond {0} is frozen after its redemption record date
    TransfersFrozen(String),
    /// bond.supply_locked: bond {0} supply is fixed by its registered record
    SupplyLocked(String),
    /// bond.vault_custody: {0}
    VaultCustody(String),
    /// bond.retained: {0}
    Retained(String),
    /// bond.arithmetic: {0}
    Arithmetic(String),
}

impl BondError {
    /// Stable machine code of this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidTerms(_) => "bond.invalid_terms",
            Self::Unauthorized(_) => "bond.unauthorized",
            Self::NotRegistered(_) => "bond.not_registered",
            Self::AlreadyRegistered(_) => "bond.already_registered",
            Self::UnknownCashflow(_) => "bond.unknown_cashflow",
            Self::InvalidState(_) => "bond.invalid_state",
            Self::TooEarly(_) => "bond.too_early",
            Self::Encumbered(_) => "bond.encumbered",
            Self::SnapshotTooLarge(_) => "bond.snapshot_too_large",
            Self::NotInSnapshot(_) => "bond.not_in_snapshot",
            Self::AlreadyClaimed(_) => "bond.already_claimed",
            Self::TransfersFrozen(_) => "bond.transfers_frozen",
            Self::SupplyLocked(_) => "bond.supply_locked",
            Self::VaultCustody(_) => "bond.vault_custody",
            Self::Retained(_) => "bond.retained",
            Self::Arithmetic(_) => "bond.arithmetic",
        }
    }
}

impl From<BondError> for crate::isi::error::InstructionExecutionError {
    fn from(error: BondError) -> Self {
        Self::InvariantViolation(error.to_string().into())
    }
}

fn invalid(message: impl Into<String>) -> BondError {
    BondError::InvalidTerms(message.into())
}

fn arithmetic(error: impl core::fmt::Display) -> BondError {
    BondError::Arithmetic(error.to_string())
}

/// Exact coupon amount per unit under the regular fixed-rate rule:
/// `denomination × coupon_rate_bps / (10_000 × coupon_frequency)`.
///
/// # Errors
/// Rejects a zero frequency or a quotient that is not an exact decimal.
pub fn regular_coupon_amount(
    denomination: &Quantity,
    coupon_rate_bps: u32,
    coupon_frequency: u8,
) -> Result<Quantity, BondError> {
    if coupon_frequency == 0 {
        return Err(invalid("zero-coupon bonds have no coupon amount"));
    }
    let divisor = u64::from(BOND_BPS_DENOMINATOR) * u64::from(coupon_frequency);
    denomination
        .try_mul_div_decimal_exact(&Numeric::from(coupon_rate_bps), &Numeric::from(divisor))
        .map_err(|error| {
            invalid(format!(
                "coupon amount {denomination} x {coupon_rate_bps}bps / {coupon_frequency} is not an exact decimal: {error}"
            ))
        })
}

/// Exact redemption amount per unit: `denomination × price_bps / 10_000`.
///
/// # Errors
/// Rejects a quotient that is not an exact decimal.
pub fn redemption_amount(denomination: &Quantity, price_bps: u32) -> Result<Quantity, BondError> {
    denomination
        .try_mul_div_decimal_exact(
            &Numeric::from(price_bps),
            &Numeric::from(BOND_BPS_DENOMINATOR),
        )
        .map_err(|error| {
            invalid(format!(
                "redemption amount {denomination} x {price_bps}bps is not an exact decimal: {error}"
            ))
        })
}

/// Holder payment `floor(units × amount_per_unit)` at the payment-asset scale.
///
/// An unconstrained payment asset receives the exact product.
///
/// # Errors
/// Rejects an unrepresentable product.
pub fn holder_payment(
    units: &Quantity,
    amount_per_unit: &Quantity,
    payment_spec: NumericSpec,
) -> Result<Quantity, BondError> {
    match payment_spec.scale() {
        Some(scale) => units
            .try_mul_div_decimal_round(
                amount_per_unit.as_numeric(),
                &Numeric::one(),
                scale,
                RoundingMode::TowardZero,
            )
            .map_err(arithmetic),
        None => units
            .try_mul_decimal(amount_per_unit.as_numeric())
            .map_err(arithmetic),
    }
}

/// Total amount due for a snapshot: the sum of rounded-down holder payments.
///
/// # Errors
/// Rejects an unrepresentable product or sum.
pub fn snapshot_amount_due(
    snapshot: &BTreeMap<AccountId, Quantity>,
    amount_per_unit: &Quantity,
    payment_spec: NumericSpec,
) -> Result<Quantity, BondError> {
    snapshot
        .values()
        .try_fold(Quantity::zero(), |total, units| {
            let payment = holder_payment(units, amount_per_unit, payment_spec)?;
            total.checked_add(&payment).map_err(arithmetic)
        })
}

fn validate_label(label: &str, value: &str, max: usize) -> Result<(), BondError> {
    if value.is_empty() || value.len() > max || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid(format!(
            "{label} must be 1..={max} printable ASCII characters"
        )));
    }
    Ok(())
}

impl BondIdentifiers {
    /// Validate identifier bounds.
    ///
    /// # Errors
    /// Rejects empty, over-long or non-printable identifiers.
    pub fn validate(&self) -> Result<(), BondError> {
        if let Some(isin) = &self.isin {
            validate_label("isin", isin, BOND_ISIN_MAX_LEN)?;
        }
        if let Some(cfi) = &self.cfi {
            validate_label("cfi", cfi, BOND_CFI_MAX_LEN)?;
        }
        if let Some(lei) = &self.issuer_lei {
            validate_label("issuer_lei", lei, BOND_LEI_MAX_LEN)?;
        }
        validate_label("bdt_version", &self.bdt_version, BOND_BDT_VERSION_MAX_LEN)
    }
}

impl BondTerms {
    /// Validate every state-independent registration rule.
    ///
    /// # Errors
    /// Returns the first violated rule as [`BondError::InvalidTerms`].
    pub fn validate(&self) -> Result<(), BondError> {
        self.identifiers.validate()?;
        if self.denomination.is_zero() {
            return Err(invalid("denomination must be positive"));
        }
        if self.redemption_price_bps == 0 {
            return Err(invalid("redemption price must be positive"));
        }
        if !BOND_COUPON_FREQUENCIES.contains(&self.coupon_frequency) {
            return Err(invalid("coupon frequency must be 0, 1, 2, 4 or 12"));
        }
        if (self.coupon_frequency == 0) != (self.coupon_rate_bps == 0) {
            return Err(invalid(
                "a zero coupon rate requires frequency 0 and a positive rate requires a positive frequency",
            ));
        }
        if self.issue_date_ms >= self.maturity_date_ms {
            return Err(invalid("issue date must precede maturity"));
        }
        if let Some(call) = &self.call {
            if call.price_bps == 0 {
                return Err(invalid("call price must be positive"));
            }
            if call.first_call_date_ms <= self.issue_date_ms
                || call.first_call_date_ms >= self.maturity_date_ms
            {
                return Err(invalid(
                    "first call date must lie strictly between issue and maturity",
                ));
            }
            redemption_amount(&self.denomination, call.price_bps)?;
        }
        self.validate_schedule()
    }

    fn validate_schedule(&self) -> Result<(), BondError> {
        let count = self.cashflows.len();
        if count == 0 || count > BOND_MAX_CASHFLOWS {
            return Err(invalid(format!(
                "schedule must contain 1..={BOND_MAX_CASHFLOWS} cash flows"
            )));
        }
        let coupon_amount = if self.coupon_frequency == 0 {
            None
        } else {
            Some(regular_coupon_amount(
                &self.denomination,
                self.coupon_rate_bps,
                self.coupon_frequency,
            )?)
        };
        let redemption = redemption_amount(&self.denomination, self.redemption_price_bps)?;
        let mut previous: Option<&BondCashflowTerms> = None;
        for (position, cashflow) in self.cashflows.iter().enumerate() {
            if usize::from(cashflow.index) != position {
                return Err(invalid("cash-flow indices must be contiguous from zero"));
            }
            if cashflow.record_date_ms > cashflow.payment_date_ms {
                return Err(invalid(format!(
                    "cash flow {} record date follows its payment date",
                    cashflow.index
                )));
            }
            if cashflow.record_date_ms < self.issue_date_ms
                || cashflow.payment_date_ms > self.maturity_date_ms
            {
                return Err(invalid(format!(
                    "cash flow {} lies outside [issue, maturity]",
                    cashflow.index
                )));
            }
            let last = position + 1 == count;
            match cashflow.kind {
                BondCashflowKind::Redemption => {
                    if !last {
                        return Err(invalid(
                            "exactly one redemption is allowed and it must be last",
                        ));
                    }
                    if cashflow.payment_date_ms != self.maturity_date_ms {
                        return Err(invalid("redemption payment date must equal maturity"));
                    }
                    if cashflow.amount_per_unit != redemption {
                        return Err(invalid(format!(
                            "redemption amount per unit must be {redemption}"
                        )));
                    }
                }
                BondCashflowKind::Coupon => {
                    if last {
                        return Err(invalid("the schedule must end with its redemption"));
                    }
                    let Some(expected) = &coupon_amount else {
                        return Err(invalid("zero-coupon bonds cannot schedule coupons"));
                    };
                    if &cashflow.amount_per_unit != expected {
                        return Err(invalid(format!(
                            "coupon {} amount per unit must be {expected}",
                            cashflow.index
                        )));
                    }
                }
            }
            if let Some(previous) = previous {
                // Coupon payment dates strictly increase. The final coupon and
                // the redemption may share the maturity payment date, as in
                // every bullet bond.
                let same_day_redemption = previous.kind == BondCashflowKind::Coupon
                    && cashflow.kind == BondCashflowKind::Redemption
                    && previous.payment_date_ms == cashflow.payment_date_ms;
                if cashflow.payment_date_ms <= previous.payment_date_ms && !same_day_redemption {
                    return Err(invalid("payment dates must strictly increase"));
                }
                if cashflow.record_date_ms < previous.record_date_ms {
                    return Err(invalid("record dates must not decrease"));
                }
            }
            previous = Some(cashflow);
        }
        Ok(())
    }
}

/// Inputs of [`fixed_rate_bullet_schedule`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BondScheduleRequest {
    /// Payment-asset amount per bond unit.
    pub denomination: Quantity,
    /// Annual coupon rate in basis points.
    pub coupon_rate_bps: u32,
    /// Coupon payments per year: 0, 1, 2, 4 or 12.
    pub coupon_frequency: u8,
    /// Issue date (Unix milliseconds, UTC midnight recommended).
    pub issue_date_ms: u64,
    /// Maturity date (Unix milliseconds).
    pub maturity_date_ms: u64,
    /// Redemption price in basis points.
    pub redemption_price_bps: u32,
    /// Milliseconds between each record date and its payment date.
    pub record_offset_ms: u64,
}

const MS_PER_DAY: u64 = 86_400_000;

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).expect("day of month");
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).expect("month");
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let month = i64::from(month);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(year: i64, month: u32) -> u32 {
    let (next_year, next_month) = if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    };
    u32::try_from(days_from_civil(next_year, next_month, 1) - days_from_civil(year, month, 1))
        .expect("month length")
}

/// Step a Unix-millisecond timestamp back by whole calendar months, clamping the day of month
/// (end-of-month convention) and keeping the time of day.
fn months_before(timestamp_ms: u64, months: u32) -> Option<u64> {
    let days = i64::try_from(timestamp_ms / MS_PER_DAY).ok()?;
    let time_of_day = timestamp_ms % MS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    let total = year * 12 + i64::from(month) - 1 - i64::from(months);
    let target_year = total.div_euclid(12);
    let target_month = u32::try_from(total.rem_euclid(12)).ok()? + 1;
    let target_day = day.min(days_in_month(target_year, target_month));
    let target_days = days_from_civil(target_year, target_month, target_day);
    u64::try_from(target_days)
        .ok()?
        .checked_mul(MS_PER_DAY)?
        .checked_add(time_of_day)
}

/// Materialise the regular schedule of a fixed-rate bullet bond.
///
/// Coupon payment dates are generated backwards from maturity in steps of
/// `12 / coupon_frequency` calendar months (end-of-month clamping) and must
/// land exactly on the issue date, so every period is regular. The final coupon
/// and the redemption share the maturity payment date. Every record date is
/// `payment_date - record_offset_ms`, clamped to the issue date.
///
/// # Errors
/// Rejects irregular first periods, inexact amounts or terms that fail
/// [`BondTerms`] schedule validation.
pub fn fixed_rate_bullet_schedule(
    request: &BondScheduleRequest,
) -> Result<Vec<BondCashflowTerms>, BondError> {
    if !BOND_COUPON_FREQUENCIES.contains(&request.coupon_frequency) {
        return Err(invalid("coupon frequency must be 0, 1, 2, 4 or 12"));
    }
    if request.issue_date_ms >= request.maturity_date_ms {
        return Err(invalid("issue date must precede maturity"));
    }
    let record_date = |payment: u64| {
        payment
            .saturating_sub(request.record_offset_ms)
            .max(request.issue_date_ms)
    };
    let mut payment_dates = Vec::new();
    if request.coupon_frequency != 0 {
        let step = 12 / u32::from(request.coupon_frequency);
        let mut periods = 0_u32;
        loop {
            let date = months_before(request.maturity_date_ms, step * periods)
                .ok_or_else(|| invalid("schedule date out of range"))?;
            if date <= request.issue_date_ms {
                if date != request.issue_date_ms {
                    return Err(invalid(
                        "the first coupon period is irregular; materialise the schedule explicitly",
                    ));
                }
                break;
            }
            payment_dates.push(date);
            periods += 1;
            if payment_dates.len() >= BOND_MAX_CASHFLOWS {
                return Err(invalid("schedule exceeds the cash-flow limit"));
            }
        }
        payment_dates.reverse();
    }
    let coupon = (request.coupon_frequency != 0)
        .then(|| {
            regular_coupon_amount(
                &request.denomination,
                request.coupon_rate_bps,
                request.coupon_frequency,
            )
        })
        .transpose()?;
    let mut cashflows = Vec::with_capacity(payment_dates.len() + 1);
    for payment in payment_dates {
        let index = u16::try_from(cashflows.len()).map_err(arithmetic)?;
        cashflows.push(BondCashflowTerms {
            index,
            kind: BondCashflowKind::Coupon,
            record_date_ms: record_date(payment),
            payment_date_ms: payment,
            amount_per_unit: coupon.clone().expect("coupon amount"),
        });
    }
    cashflows.push(BondCashflowTerms {
        index: u16::try_from(cashflows.len()).map_err(arithmetic)?,
        kind: BondCashflowKind::Redemption,
        record_date_ms: record_date(request.maturity_date_ms),
        payment_date_ms: request.maturity_date_ms,
        amount_per_unit: redemption_amount(&request.denomination, request.redemption_price_bps)?,
    });
    Ok(cashflows)
}

/// Prelude exports for bond records.
pub mod prelude {
    pub use super::{
        BondCallTerms, BondCashflowKind, BondCashflowState, BondCashflowStatus, BondCashflowTerms,
        BondDayCount, BondId, BondIdentifiers, BondLifecycle, BondRecord, BondState, BondTerms,
        bond_vault_account_id,
    };
}

#[cfg(test)]
pub(crate) mod tests;
