//! Events emitted by the native bond-servicing kernel.
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize,
    account::AccountId,
    bond::{BondCashflowKind, BondId},
};
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Bond lifecycle and cash-flow servicing events.
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
#[norito(tag = "event", content = "payload")]
#[norito_schema(name = "iroha_data_model::events::data::bond::BondEvent")]
pub enum BondEvent {
    /// A bond record was registered.
    Registered(BondRegistered),
    /// Recording of a cash flow completed.
    CashflowRecorded(BondCashflowRecorded),
    /// A recorded cash flow was funded into the vault.
    CashflowFunded(BondCashflowFunded),
    /// One holder claimed a funded cash flow.
    CashflowClaimed(BondCashflowClaimed),
    /// The paying agent closed active servicing of a funded cash flow.
    CashflowClosed(BondCashflowClosed),
    /// The issuer called the bond.
    Called(BondCalled),
    /// The paying agent declared a payment default.
    Defaulted(BondDefaulted),
    /// The issuer replaced the paying agent.
    PayingAgentReplaced(BondPayingAgentReplaced),
    /// The issuer retired units it held.
    TreasuryUnitsRetired(BondTreasuryUnitsRetired),
}

impl BondEvent {
    /// Bond the event belongs to.
    #[must_use]
    pub const fn bond(&self) -> &BondId {
        match self {
            Self::Registered(event) => &event.bond,
            Self::CashflowRecorded(event) => &event.bond,
            Self::CashflowFunded(event) => &event.bond,
            Self::CashflowClaimed(event) => &event.bond,
            Self::CashflowClosed(event) => &event.bond,
            Self::Called(event) => &event.bond,
            Self::Defaulted(event) => &event.bond,
            Self::PayingAgentReplaced(event) => &event.bond,
            Self::TreasuryUnitsRetired(event) => &event.bond,
        }
    }
}

macro_rules! bond_event_payload {
    ($(#[$meta:meta])* $name:ident = $schema:literal { $($(#[$field_meta:meta])* $field:ident : $ty:ty),+ $(,)? }) => {
        $(#[$meta])*
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
        #[norito(deny_unknown_fields)]
        #[norito_schema(name = $schema)]
        pub struct $name {
            $($(#[$field_meta])* pub $field: $ty,)+
        }
    };
}

bond_event_payload!(
    /// Payload of [`BondEvent::Registered`].
    BondRegistered = "iroha_data_model::events::data::bond::BondRegistered" {
        /// Bond identifier.
        bond: BondId,
        /// Issuer.
        issuer: AccountId,
        /// Paying agent.
        paying_agent: AccountId,
        /// Outstanding units at registration.
        outstanding_units: Quantity,
        /// Number of scheduled cash flows.
        cashflows: u16,
    }
);
bond_event_payload!(
    /// Payload of [`BondEvent::CashflowRecorded`].
    BondCashflowRecorded = "iroha_data_model::events::data::bond::BondCashflowRecorded" {
        /// Bond identifier.
        bond: BondId,
        /// Cash-flow index.
        index: u16,
        /// Cash-flow kind.
        kind: BondCashflowKind,
        /// Holders with a recorded entitlement.
        holders: u32,
        /// Sum of entitled units.
        entitled_units: Quantity,
        /// Amount due at the payment-asset scale.
        amount_due: Quantity,
    }
);
bond_event_payload!(
    /// Payload of [`BondEvent::CashflowFunded`].
    BondCashflowFunded = "iroha_data_model::events::data::bond::BondCashflowFunded" {
        /// Bond identifier.
        bond: BondId,
        /// Cash-flow index.
        index: u16,
        /// Amount moved into the vault.
        amount: Quantity,
    }
);
bond_event_payload!(
    /// Payload of [`BondEvent::CashflowClaimed`].
    BondCashflowClaimed = "iroha_data_model::events::data::bond::BondCashflowClaimed" {
        /// Bond identifier.
        bond: BondId,
        /// Cash-flow index.
        index: u16,
        /// Paid holder.
        holder: AccountId,
        /// Entitled units (burned for a redemption).
        units: Quantity,
        /// Amount paid to the holder.
        amount: Quantity,
    }
);
bond_event_payload!(
    /// Payload of [`BondEvent::CashflowClosed`].
    BondCashflowClosed = "iroha_data_model::events::data::bond::BondCashflowClosed" {
        /// Bond identifier.
        bond: BondId,
        /// Cash-flow index.
        index: u16,
        /// Entitled holders that have not claimed; they can still claim.
        unclaimed_holders: u32,
        /// Amount kept in the vault for those holders.
        unclaimed_amount: Quantity,
    }
);
bond_event_payload!(
    /// Payload of [`BondEvent::Called`].
    BondCalled = "iroha_data_model::events::data::bond::BondCalled" {
        /// Bond identifier.
        bond: BondId,
        /// Call date.
        call_date_ms: u64,
        /// Index of the appended call redemption.
        redemption_index: u16,
    }
);
bond_event_payload!(
    /// Payload of [`BondEvent::Defaulted`].
    BondDefaulted = "iroha_data_model::events::data::bond::BondDefaulted" {
        /// Bond identifier.
        bond: BondId,
        /// Defaulted cash-flow index.
        index: u16,
        /// SHA-256 of the default evidence.
        #[norito(json = "crate::json_helpers::fixed_bytes_hex")]
        evidence_sha256: [u8; 32],
    }
);

bond_event_payload!(
    /// Payload of [`BondEvent::PayingAgentReplaced`].
    BondPayingAgentReplaced = "iroha_data_model::events::data::bond::BondPayingAgentReplaced" {
        /// Bond identifier.
        bond: BondId,
        /// Replaced paying agent.
        previous: AccountId,
        /// New paying agent.
        paying_agent: AccountId,
    }
);

bond_event_payload!(
    /// Payload of [`BondEvent::TreasuryUnitsRetired`].
    BondTreasuryUnitsRetired = "iroha_data_model::events::data::bond::BondTreasuryUnitsRetired" {
        /// Bond identifier.
        bond: BondId,
        /// Issuer whose units were burned.
        issuer: AccountId,
        /// Units burned by this retirement.
        quantity: Quantity,
        /// Outstanding units after the retirement.
        outstanding_units: Quantity,
        /// Units retired since registration, including this retirement.
        retired_units: Quantity,
        /// Scheduled cash flows cancelled because no unit remains outstanding.
        cancelled_cashflows: u16,
    }
);

/// Prelude exports for bond events.
pub mod prelude {
    pub use super::{
        BondCalled, BondCashflowClaimed, BondCashflowClosed, BondCashflowFunded,
        BondCashflowRecorded, BondDefaulted, BondEvent, BondPayingAgentReplaced, BondRegistered,
        BondTreasuryUnitsRetired,
    };
}
