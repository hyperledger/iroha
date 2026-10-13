//! Repo and reverse-repo agreement data structures.
//!
//! The recorded agreement is an immutable, one-shot economic contract. Exact
//! consent-selected balance scopes and terminal settlement status are retained
//! so maturity settlement cannot infer or substitute caller-controlled terms.
use crate::{
    Identifiable,
    asset::prelude::{AssetDefinitionId, AssetId},
    prelude::AccountId,
};
use derive_more::{Constructor, Display, FromStr};
use getset::{CopyGetters, Getters};
use iroha_data_model_derive::model;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_primitives::numeric::Quantity;
use iroha_schema::IntoSchema;

use norito::json::JsonKeyCodec;
use norito::{
    codec::{Decode, Encode},
    derive::{JsonDeserialize, JsonSerialize},
};
#[model]
mod model {
    use super::*;
    /// Identifier for a repo agreement lifecycle.
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::repo::model::RepoAgreementId")]
    #[derive(
        Debug,
        Display,
        FromStr,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Constructor,
        Getters,
        Decode,
        Encode,
        IntoSchema,
    )]
    #[display("{name}")]
    #[getset(get = "pub")]
    #[repr(transparent)]

    pub struct RepoAgreementId {
        /// Logical name assigned by the initiating desk or workflow.
        pub name: Name,
    }
}
pub use self::model::RepoAgreementId;
string_id!(RepoAgreementId);
/// Cash leg definition used by repo instructions.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Getters,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[getset(get = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::repo::RepoCashLeg")]
pub struct RepoCashLeg {
    /// Asset definition used for the cash consideration.
    pub asset_definition_id: AssetDefinitionId,
    /// Quantity of the cash asset exchanged at initiation.
    pub quantity: Quantity,
}
impl RepoCashLeg {
    /// Construct a cash leg with a nominal non-negative quantity.
    pub fn new(asset_definition_id: AssetDefinitionId, quantity: impl Into<Quantity>) -> Self {
        Self {
            asset_definition_id,
            quantity: quantity.into(),
        }
    }
}
/// Collateral leg definition used by repo instructions.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Getters,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[getset(get = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::repo::RepoCollateralLeg")]
pub struct RepoCollateralLeg {
    /// Asset definition pledged as collateral.
    pub asset_definition_id: AssetDefinitionId,
    /// Quantity of collateral exchanged at initiation.
    pub quantity: Quantity,
    /// Optional metadata (e.g., ISIN/series) attached at admission time.
    pub metadata: Metadata,
}
impl RepoCollateralLeg {
    /// Construct a collateral leg without metadata.
    pub fn new(asset_definition_id: AssetDefinitionId, quantity: impl Into<Quantity>) -> Self {
        Self {
            asset_definition_id,
            quantity: quantity.into(),
            metadata: Metadata::default(),
        }
    }
}
/// Governance knobs captured with each agreement.
#[derive(
    Copy,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    CopyGetters,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[getset(get_copy = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::repo::RepoGovernance")]
pub struct RepoGovernance {
    /// Haircut applied to the collateral leg, measured in basis points.
    pub haircut_bps: u16,
    /// Cadence (seconds) between mandatory margin checks.
    pub margin_frequency_secs: u64,
}
impl RepoGovernance {
    /// Governance defaults used when configuration omits explicit values.
    pub fn with_defaults(haircut_bps: u16, margin_frequency_secs: u64) -> Self {
        Self {
            haircut_bps,
            margin_frequency_secs,
        }
    }
    /// Return the cadence between margin checks in milliseconds.
    pub fn margin_frequency_millis(&self) -> Option<u64> {
        (self.margin_frequency_secs != 0).then(|| self.margin_frequency_secs.saturating_mul(1_000))
    }
}
/// End-to-end repo agreement envelope recorded on-chain.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Getters,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[getset(get = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::repo::RepoAgreement")]
pub struct RepoAgreement {
    /// Stable identifier assigned to this agreement.
    pub id: RepoAgreementId,
    /// Initiating participant.
    pub initiator: AccountId,
    /// Counterparty accepting the terms.
    pub counterparty: AccountId,
    /// Optional custodian holding pledged collateral for tri-party agreements.
    pub custodian: Option<AccountId>,
    /// Cash leg settled at repo open and unwind.
    pub cash_leg: RepoCashLeg,
    /// Exact counterparty balance debited for cash at initiation.
    ///
    /// Its balance scope is also used for the initiator's repayment balance at
    /// maturity. This value comes from the counterparty's exact on-chain
    /// settlement consent rather than ambient balance discovery.
    pub cash_source: AssetId,
    /// Collateral leg pledged for the duration of the repo.
    pub collateral_leg: RepoCollateralLeg,
    /// Exact collateral balance held by the counterparty or custodian.
    ///
    /// Its balance scope is fixed by the collateral holder's maturity consent
    /// before the agreement opens.
    pub collateral_custody_asset: AssetId,
    /// Fixed rate (in basis points) agreed for the term.
    pub rate_bps: u16,
    /// Unix timestamp (milliseconds) for the agreed maturity.
    pub maturity_timestamp_ms: u64,
    /// Unix timestamp (milliseconds) when the repo was initiated on-ledger.
    pub initiated_timestamp_ms: u64,
    /// Unix timestamp (milliseconds) when the most recent margin check completed.
    pub last_margin_check_timestamp_ms: u64,
    /// Governance parameters applied to the agreement.
    pub governance: RepoGovernance,
    /// Agreed settlement timestamp once this one-shot agreement is closed.
    ///
    /// A settled agreement remains on-chain as a tombstone so its identifier can never be replayed.
    pub settlement_timestamp_ms: Option<u64>,
}
impl RepoAgreement {
    /// Builder-style helper for constructing a repo agreement.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: RepoAgreementId,
        initiator: AccountId,
        counterparty: AccountId,
        cash_leg: RepoCashLeg,
        cash_source: AssetId,
        collateral_leg: RepoCollateralLeg,
        collateral_custody_asset: AssetId,
        rate_bps: u16,
        maturity_timestamp_ms: u64,
        initiated_timestamp_ms: u64,
        governance: RepoGovernance,
        custodian: Option<AccountId>,
    ) -> Self {
        Self {
            id,
            initiator,
            counterparty,
            custodian,
            cash_leg,
            cash_source,
            collateral_leg,
            collateral_custody_asset,
            rate_bps,
            maturity_timestamp_ms,
            initiated_timestamp_ms,
            last_margin_check_timestamp_ms: initiated_timestamp_ms,
            governance,
            settlement_timestamp_ms: None,
        }
    }
    /// Return whether the agreement is still open for margining or maturity settlement.
    pub fn is_active(&self) -> bool {
        self.settlement_timestamp_ms.is_none()
    }
    /// Close this agreement at its pre-agreed maturity.
    ///
    /// Returns `false` when the agreement was already settled.
    pub fn settle(&mut self) -> bool {
        if !self.is_active() {
            return false;
        }
        self.settlement_timestamp_ms = Some(self.maturity_timestamp_ms);
        true
    }
    /// Compute the next margin check timestamp after the provided moment.
    ///
    /// Returns `None` when the governance policy disables margin sweeps (frequency set to zero).
    /// Otherwise returns the earliest timestamp strictly greater than `after_timestamp_ms` that
    /// aligns to the configured cadence starting from the last recorded margin check (initially the
    /// initiation timestamp).
    pub fn next_margin_check_after(&self, after_timestamp_ms: u64) -> Option<u64> {
        let freq_ms = self.governance.margin_frequency_millis()?;
        let start = self.last_margin_check_timestamp_ms;
        if after_timestamp_ms < start {
            return Some(start);
        }
        let elapsed = after_timestamp_ms.saturating_sub(start);
        let periods_elapsed = elapsed / freq_ms;
        let next_period = periods_elapsed.saturating_add(1);
        start.checked_add(freq_ms.saturating_mul(next_period))
    }
    /// Determine whether a margin check is due at the supplied timestamp.
    ///
    /// Returns `false` when margining is disabled. When margining is enabled,
    /// a check is considered due at or after the next scheduled cadence
    /// boundary following the last recorded margin check.
    pub fn is_margin_check_due(&self, at_timestamp_ms: u64) -> bool {
        let Some(next_due) = self.next_margin_check_after(self.last_margin_check_timestamp_ms)
        else {
            return false;
        };
        at_timestamp_ms >= next_due
    }
    /// Record completion of a margin check at the supplied timestamp.
    pub fn record_margin_check(&mut self, timestamp_ms: u64) {
        self.last_margin_check_timestamp_ms = timestamp_ms;
    }
}
impl Identifiable for RepoAgreement {
    type Id = RepoAgreementId;
    fn id(&self) -> &Self::Id {
        &self.id
    }
}
/// Common re-exports for repo-related types.
pub mod prelude {
    pub use super::{
        RepoAgreement, RepoAgreementId, RepoCashLeg, RepoCollateralLeg, RepoGovernance,
    };
}

impl JsonKeyCodec for RepoAgreementId {
    fn encode_json_key(&self, out: &mut String) {
        norito::json::write_json_string(&self.to_string(), out);
    }
    fn decode_json_key(encoded: &str) -> Result<Self, norito::json::Error> {
        encoded
            .parse()
            .map_err(|err| norito::json::Error::Message(format!("{err}")))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::Numeric;
    use norito::codec::{Decode, Encode};
    #[derive(Encode)]
    struct ForgedRepoCashLeg {
        asset_definition_id: AssetDefinitionId,
        quantity: Numeric,
    }
    #[derive(Encode)]
    struct ForgedRepoCollateralLeg {
        asset_definition_id: AssetDefinitionId,
        quantity: Numeric,
        metadata: Metadata,
    }
    const ALICE_ID_STR: &str = "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE";
    fn sample_agreement(initiated_ms: u64, margin_frequency_secs: u64) -> RepoAgreement {
        let initiator = AccountId::parse_encoded(ALICE_ID_STR).expect("valid initiator account");
        let counterparty = AccountId::new(
            "ed012004FF5B81046DDCCF19E2E451C45DFB6F53759D4EB30FA2EFA807284D1CC33016"
                .parse()
                .expect("public key"),
        );
        let cash_leg = RepoCashLeg {
            asset_definition_id: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "usd".parse().unwrap(),
            ),
            quantity: Quantity::from(1_000u32),
        };
        let collateral_leg = RepoCollateralLeg::new(
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "bond".parse().unwrap(),
            ),
            Quantity::from(1_100u32),
        );
        RepoAgreement::new(
            "daily".parse().unwrap(),
            initiator.clone(),
            counterparty.clone(),
            cash_leg,
            AssetId::new(
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "usd".parse().unwrap(),
                ),
                counterparty.clone(),
            ),
            collateral_leg,
            AssetId::new(
                iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                    DomainId::try_new("wonderland", "universal").unwrap(),
                    "bond".parse().unwrap(),
                ),
                counterparty,
            ),
            250,
            initiated_ms + 86_400_000,
            initiated_ms,
            RepoGovernance::with_defaults(1_500, margin_frequency_secs),
            None,
        )
    }
    #[test]
    fn margin_schedule_disabled_when_frequency_zero() {
        let agreement = sample_agreement(1_000, 0);
        assert!(agreement.next_margin_check_after(1_000).is_none());
        assert!(!agreement.is_margin_check_due(1_000));
    }
    #[test]
    fn margin_schedule_returns_start_before_initiation() {
        let agreement = sample_agreement(10_000, 60);
        assert_eq!(
            agreement.next_margin_check_after(5_000),
            Some(10_000),
            "margin checks should start at the initiation timestamp"
        );
    }
    #[test]
    fn margin_schedule_advances_in_cadence() {
        let agreement = sample_agreement(10_000, 60);
        // 60 seconds cadence = 60_000 ms
        assert_eq!(
            agreement.next_margin_check_after(10_000),
            Some(70_000),
            "first check after initiation should be one cadence later"
        );
        assert_eq!(
            agreement.next_margin_check_after(70_000),
            Some(130_000),
            "subsequent checks follow the cadence"
        );
        assert!(agreement.is_margin_check_due(70_000));
        assert!(agreement.is_margin_check_due(70_001));
        assert!(!agreement.is_margin_check_due(69_999));
    }
    #[test]
    fn record_margin_check_updates_schedule() {
        let mut agreement = sample_agreement(10_000, 60);
        agreement.record_margin_check(70_000);
        assert_eq!(agreement.next_margin_check_after(70_000), Some(130_000));
        assert!(!agreement.is_margin_check_due(129_999));
        assert!(agreement.is_margin_check_due(130_000));
        assert!(agreement.is_margin_check_due(130_001));
    }
    #[test]
    fn settlement_status_is_one_way() {
        let mut agreement = sample_agreement(10_000, 60);
        assert!(agreement.is_active());
        assert!(agreement.settle());
        assert!(!agreement.is_active());
        assert_eq!(agreement.settlement_timestamp_ms(), &Some(86_410_000));
        assert!(!agreement.settle());
        assert_eq!(agreement.settlement_timestamp_ms(), &Some(86_410_000));
    }
    #[test]
    fn negative_numeric_payloads_cannot_decode_as_repo_leg_quantities() {
        let domain = DomainId::try_new("wonderland", "universal").expect("domain");
        let cash =
            AssetDefinitionId::derive_from_components(domain.clone(), "usd".parse().expect("name"));
        let collateral =
            AssetDefinitionId::derive_from_components(domain, "bond".parse().expect("name"));
        let encoded = ForgedRepoCashLeg {
            asset_definition_id: cash,
            quantity: Numeric::new(-1_i32, 0),
        }
        .encode();
        assert!(
            RepoCashLeg::decode(&mut encoded.as_slice()).is_err(),
            "a negative signed payload must not decode as a repo cash quantity"
        );
        let encoded = ForgedRepoCollateralLeg {
            asset_definition_id: collateral,
            quantity: Numeric::new(-1_i32, 0),
            metadata: Metadata::default(),
        }
        .encode();
        assert!(
            RepoCollateralLeg::decode(&mut encoded.as_slice()).is_err(),
            "a negative signed payload must not decode as a repo collateral quantity"
        );
    }
}

#[cfg(test)]
mod captured_repo_schema_tests;

#[cfg(test)]
mod settlement_transcript_frame_tests {
    use super::*;
    use crate::isi::settlement::SettlementId;
    use iroha_crypto::Hash;
    fn assert_frame<T>(value: &T, owner: &str) -> Vec<u8>
    where
        T: norito::NoritoSerialize
            + for<'de> norito::NoritoDeserialize<'de>
            + PartialEq
            + std::fmt::Debug,
    {
        assert_eq!(T::nominal_name(), owner);
        let frame = norito::encode_canonical(value).expect("canonical owner frame");
        assert_eq!(&frame[6..22], &norito::schema::identity::frame_hash::<T>());
        assert_eq!(norito::decode_canonical::<T>(&frame).unwrap(), *value);
        let mut wrong_owner = frame.clone();
        wrong_owner[6..22].copy_from_slice(&norito::schema::identity::frame_hash::<u8>());
        assert!(matches!(
            norito::decode_canonical::<T>(&wrong_owner),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(norito::decode_canonical::<T>(&frame[..frame.len() - 1]).is_err());
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(norito::decode_canonical::<T>(&trailing).is_err());
        frame
    }

    #[test]
    fn settlement_and_repo_ids_preserve_distinct_scopes_in_transcripts() {
        let settlement = SettlementId::new(
            crate::account::AccountId::new(
                iroha_crypto::KeyPair::from_seed(vec![91; 32], iroha_crypto::Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            ),
            "trade_17".parse().unwrap(),
        );
        let agreement: RepoAgreementId = "trade_17".parse().unwrap();
        let settlement_frame = assert_frame(
            &settlement,
            "iroha_data_model::isi::settlement::model::SettlementId",
        );
        let agreement_frame =
            assert_frame(&agreement, "iroha_data_model::repo::model::RepoAgreementId");
        assert_ne!(settlement.encode(), agreement.encode());
        assert_ne!(settlement_frame, agreement_frame);
        assert!(matches!(
            norito::decode_canonical::<RepoAgreementId>(&settlement_frame),
            Err(norito::Error::SchemaMismatch)
        ));
        assert!(matches!(
            norito::decode_canonical::<SettlementId>(&agreement_frame),
            Err(norito::Error::SchemaMismatch)
        ));
        let initiation = (
            settlement.clone(),
            Hash::new(b"initiation-consent"),
            Hash::new(b"maturity-consent"),
        );
        let initiation_frame = norito::encode_canonical(&initiation).unwrap();
        assert_eq!(
            norito::decode_canonical::<(SettlementId, Hash, Hash)>(&initiation_frame).unwrap(),
            initiation
        );
        assert!(matches!(
            norito::decode_canonical::<(RepoAgreementId, Hash, Hash)>(&initiation_frame),
            Err(norito::Error::SchemaMismatch)
        ));
        let maturity = (agreement, 17_u64);
        let maturity_frame = norito::encode_canonical(&maturity).unwrap();
        assert_eq!(
            norito::decode_canonical::<(RepoAgreementId, u64)>(&maturity_frame).unwrap(),
            maturity
        );
        assert!(matches!(
            norito::decode_canonical::<(SettlementId, u64)>(&maturity_frame),
            Err(norito::Error::SchemaMismatch)
        ));
        assert_ne!(
            maturity_frame,
            norito::encode_canonical(&(maturity.0, 18_u64)).unwrap()
        );
    }
}
