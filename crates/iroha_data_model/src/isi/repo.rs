use super::*;
use crate::{
    isi::SettlementId,
    repo::{RepoAgreementId, RepoCashLeg, RepoCollateralLeg, RepoGovernance},
};
use iroha_crypto::Hash;
use norito::codec::Encode;
isi! {
    /// Initiate or roll a repo agreement between two counterparties.
    #[norito_schema(name = "iroha_data_model::isi::repo::RepoIsi")]
    pub struct RepoIsi {
        /// Stable agreement identifier shared across the lifecycle.
        pub agreement_id: RepoAgreementId,
        /// Initiating account submitting the instruction.
        pub initiator: AccountId,
        /// Counterparty accepting the repo terms.
        pub counterparty: AccountId,
        /// Optional custodian account holding collateral in tri-party agreements.
        pub custodian: Option<AccountId>,
        /// Cash leg exchanged at initiation.
        pub cash_leg: RepoCashLeg,
        /// Collateral leg pledged for the agreement.
        pub collateral_leg: RepoCollateralLeg,
        /// Fixed interest rate, measured in basis points.
        pub rate_bps: u16,
        /// Unix timestamp (milliseconds) of the agreed maturity.
        pub maturity_timestamp_ms: u64,
        /// Governance knobs applied to this agreement.
        pub governance: RepoGovernance,
    }
}
impl core::fmt::Display for RepoIsi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "REPO `{}` INIT `{}` COUNTER `{}` RATE {}bps MAT {}ms",
            self.agreement_id,
            self.initiator,
            self.counterparty,
            self.rate_bps,
            self.maturity_timestamp_ms,
        )?;
        if let Some(custodian) = &self.custodian {
            write!(f, " CUST `{custodian}`")?;
        }
        Ok(())
    }
}
isi! {
    /// Settle an active repo agreement at its pre-agreed maturity.
    ///
    /// Every economic term is loaded from the immutable on-chain agreement.
    /// Early unwind and collateral substitution are intentionally not
    /// representable by this instruction. Any recorded participant may submit
    /// it after maturity, so no single participant can veto settlement.
    #[norito_schema(name = "iroha_data_model::isi::repo::ReverseRepoIsi")]
    pub struct ReverseRepoIsi {
        /// Identifier of the repo agreement being unwound.
        pub agreement_id: RepoAgreementId,
    }
}
impl core::fmt::Display for ReverseRepoIsi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "REPO_SETTLE `{}` AT MATURITY", self.agreement_id)
    }
}
impl core::fmt::Display for RepoMarginCallIsi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "REPO_MARGIN `{}`", self.agreement_id)
    }
}
impl RepoIsi {
    /// Stable Norito wire identifier for registry lookups.
    pub const WIRE_ID: &'static str = "iroha.repo.initiate";
    /// Domain separator for the counterparty's exact cash-debit consent.
    pub const INITIATION_INTENT_HASH_DOMAIN: &'static [u8] = b"iroha:repo:initiation-intent:v1\0";
    /// Domain separator for the collateral holder's exact maturity-release consent.
    pub const MATURITY_INTENT_HASH_DOMAIN: &'static [u8] = b"iroha:repo:maturity-intent:v1\0";
    /// Construct a repo instruction containing the exact terms to be consented.
    ///
    /// Admission validates the terms without silently normalising them from
    /// node-local configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        agreement_id: RepoAgreementId,
        initiator: AccountId,
        counterparty: AccountId,
        custodian: Option<AccountId>,
        cash_leg: RepoCashLeg,
        collateral_leg: RepoCollateralLeg,
        rate_bps: u16,
        maturity_timestamp_ms: u64,
        governance: RepoGovernance,
    ) -> Self {
        Self {
            agreement_id,
            initiator,
            counterparty,
            custodian,
            cash_leg,
            collateral_leg,
            rate_bps,
            maturity_timestamp_ms,
            governance,
        }
    }
    /// Return the settlement identifier used by exact consent permissions.
    pub fn settlement_id(&self) -> SettlementId {
        SettlementId::new(self.initiator.clone(), self.agreement_id.name().clone())
    }
    /// Commit to every term authorized for the counterparty cash debit.
    #[must_use]
    pub fn initiation_intent_hash(&self) -> Hash {
        let encoded = self.encode();
        Hash::new_from_chunks(&[Self::INITIATION_INTENT_HASH_DOMAIN, encoded.as_slice()])
    }
    /// Commit to every term authorized for the collateral release at maturity.
    #[must_use]
    pub fn maturity_intent_hash(&self) -> Hash {
        let encoded = self.encode();
        Hash::new_from_chunks(&[Self::MATURITY_INTENT_HASH_DOMAIN, encoded.as_slice()])
    }
}
impl ReverseRepoIsi {
    /// Stable Norito wire identifier for the unwind.
    pub const WIRE_ID: &'static str = "iroha.repo.reverse";
    /// Construct a fixed-maturity settlement instruction.
    pub fn new(agreement_id: RepoAgreementId) -> Self {
        Self { agreement_id }
    }
}
isi! {
    /// Record a margin check for an active repo agreement.
    #[norito_schema(name = "iroha_data_model::isi::repo::RepoMarginCallIsi")]
    pub struct RepoMarginCallIsi {
        /// Identifier of the repo agreement undergoing a margin check.
        pub agreement_id: RepoAgreementId,
    }
}
impl RepoMarginCallIsi {
    /// Stable Norito wire identifier for a margin call notification.
    pub const WIRE_ID: &'static str = "iroha.repo.margin_call";
    /// Construct a margin call instruction.
    pub fn new(agreement_id: RepoAgreementId) -> Self {
        Self { agreement_id }
    }
}
impl crate::seal::Instruction for RepoIsi {}
impl crate::seal::Instruction for ReverseRepoIsi {}
impl crate::seal::Instruction for RepoMarginCallIsi {}
/// Grouping enum for repo-related instructions.
///
/// The large initiation variant is boxed in memory, but its manual Norito
/// implementation retains the original single field frame. This keeps the
/// canonical wire identical to the former `Initiate(RepoIsi)` representation.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Display, derive_more::From, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::isi::repo::RepoInstructionBox")]
pub enum RepoInstructionBox {
    /// Initiate or roll a repo agreement.
    Initiate(Box<RepoIsi>),
    /// Reverse (unwind) an existing repo agreement.
    Reverse(ReverseRepoIsi),
    /// Record a margin check for an active repo agreement.
    MarginCall(RepoMarginCallIsi),
}
/// Archived Norito representation of `RepoInstructionBox` generated by `#[derive(NoritoSerialize)]`.
pub type ArchivedRepoInstructionBox = norito::core::Archived<RepoInstructionBox>;
impl From<RepoIsi> for RepoInstructionBox {
    fn from(instruction: RepoIsi) -> Self {
        Self::Initiate(Box::new(instruction))
    }
}
impl_into_box! {
    RepoIsi | ReverseRepoIsi | RepoMarginCallIsi => RepoInstructionBox
}
impl crate::seal::Instruction for RepoInstructionBox {}
impl iroha_schema::TypeId for RepoInstructionBox {
    fn id() -> iroha_schema::Ident {
        "RepoInstructionBox".to_owned()
    }
}
impl iroha_schema::IntoSchema for RepoInstructionBox {
    fn type_name() -> iroha_schema::Ident {
        "RepoInstructionBox".to_owned()
    }
    fn update_schema_map(map: &mut iroha_schema::MetaMap) {
        if map.contains_key::<Self>() {
            return;
        }
        map.insert::<Self>(iroha_schema::Metadata::Enum(iroha_schema::EnumMeta {
            variants: vec![
                iroha_schema::EnumVariant {
                    tag: "Initiate".to_owned(),
                    discriminant: 0,
                    ty: Some(core::any::TypeId::of::<RepoIsi>()),
                },
                iroha_schema::EnumVariant {
                    tag: "Reverse".to_owned(),
                    discriminant: 1,
                    ty: Some(core::any::TypeId::of::<ReverseRepoIsi>()),
                },
                iroha_schema::EnumVariant {
                    tag: "MarginCall".to_owned(),
                    discriminant: 2,
                    ty: Some(core::any::TypeId::of::<RepoMarginCallIsi>()),
                },
            ],
        }));
        <RepoIsi as iroha_schema::IntoSchema>::update_schema_map(map);
        <ReverseRepoIsi as iroha_schema::IntoSchema>::update_schema_map(map);
        <RepoMarginCallIsi as iroha_schema::IntoSchema>::update_schema_map(map);
    }
}
impl RepoInstructionBox {
    fn tag_and_payload(&self) -> (u32, &dyn norito::core::SerializePayload) {
        match self {
            Self::Initiate(instruction) => (0, instruction.as_ref()),
            Self::Reverse(instruction) => (1, instruction),
            Self::MarginCall(instruction) => (2, instruction),
        }
    }
}

impl norito::core::SerializePayload for RepoInstructionBox {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        let (tag, payload) = self.tag_and_payload();
        norito::core::SerializePayload::serialize(&tag, writer)?;
        norito::core::write_len_prefixed(writer, payload)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        let (_, payload) = self.tag_and_payload();
        payload
            .encoded_len_hint()
            .map(|len| 4usize.saturating_add(8usize.saturating_add(len)))
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        let (_, payload) = self.tag_and_payload();
        let payload_len = payload.encoded_len_exact()?;
        4usize
            .checked_add(norito::core::len_prefix_len(payload_len))?
            .checked_add(payload_len)
    }
}

impl<'a> norito::core::DeserializePayload<'a> for RepoInstructionBox {
    fn deserialize(archived: &'a norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("RepoInstructionBox deserialization must reject invalid canonical payloads")
    }
    fn try_deserialize(
        archived: &'a norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let ptr = core::ptr::from_ref(archived).cast::<u8>();
        let payload = norito::core::payload_slice_from_ptr(ptr)?;
        let (value, used) = <Self as norito::core::DecodeFromSlice>::decode_from_slice(payload)?;
        if used != payload.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        Ok(value)
    }
}
impl RepoInstructionBox {
    /// Stable Norito wire identifier for boxed repo instructions.
    pub const WIRE_ID: &'static str = "iroha.repo";
}
fn repo_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
macro_rules! impl_repo_decode_from_slice {
    ($ty:ty { $($field:ident : $field_ty:ty),+ $(,)? }) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = repo_decode_flags();
                let mut offset = 0usize;
                $(
                    let $field = super::decode_aos_canonical_field::<$field_ty>(
                        super::read_aos_field(bytes, &mut offset, flags)?,
                        flags,
                    )?;
                )+
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { $($field),+ }, offset))
            }
        }
    };
}
impl_repo_decode_from_slice!(RepoIsi {
    agreement_id: RepoAgreementId,
    initiator: AccountId,
    counterparty: AccountId,
    custodian: Option<AccountId>,
    cash_leg: RepoCashLeg,
    collateral_leg: RepoCollateralLeg,
    rate_bps: u16,
    maturity_timestamp_ms: u64,
    governance: RepoGovernance,
});
impl_repo_decode_from_slice!(ReverseRepoIsi {
    agreement_id: RepoAgreementId,
});
impl_repo_decode_from_slice!(RepoMarginCallIsi {
    agreement_id: RepoAgreementId,
});
impl<'a> norito::core::DecodeFromSlice<'a> for RepoInstructionBox {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = repo_decode_flags();
        let tag_bytes = bytes.get(..4).ok_or(norito::core::Error::LengthMismatch)?;
        let tag = u32::from_le_bytes(
            tag_bytes
                .try_into()
                .map_err(|_| norito::core::Error::LengthMismatch)?,
        );
        let mut offset = 4usize;
        let value = match tag {
            0 => Self::Initiate(Box::new(super::decode_aos_slice_field::<RepoIsi>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?)),
            1 => Self::Reverse(super::decode_aos_slice_field::<ReverseRepoIsi>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            2 => Self::MarginCall(super::decode_aos_slice_field::<RepoMarginCallIsi>(
                super::read_aos_field(bytes, &mut offset, flags)?,
                flags,
            )?),
            _ => {
                return Err(norito::core::Error::Message(format!(
                    "invalid RepoInstructionBox tag {tag}"
                )));
            }
        };
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((value, offset))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::isi::test_support::{assert_registry_decodes, assert_slice_roundtrip};
    use crate::repo::RepoGovernance;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::Numeric;
    use norito::{codec::Encode, core::DecodeFromSlice};
    #[derive(Encode)]
    struct ForgedRepoCashLeg {
        asset_definition_id: AssetDefinitionId,
        quantity: Numeric,
    }
    #[derive(Encode)]
    struct ForgedRepoIsi {
        agreement_id: RepoAgreementId,
        initiator: AccountId,
        counterparty: AccountId,
        custodian: Option<AccountId>,
        cash_leg: ForgedRepoCashLeg,
        collateral_leg: RepoCollateralLeg,
        rate_bps: u16,
        maturity_timestamp_ms: u64,
        governance: RepoGovernance,
    }
    #[derive(Encode)]
    enum LegacyRepoInstructionBox {
        Initiate(RepoIsi),
    }
    const INITIATOR: &str = "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE";
    const COUNTERPARTY: &str = "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D";
    fn parse_account(raw: &str) -> AccountId {
        AccountId::parse_encoded(raw).expect("valid account")
    }
    fn seeded_account(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked repo fixture account keypair");
        AccountId::new(keypair.public_key().clone())
    }
    fn agreement_id() -> RepoAgreementId {
        "daily_repo".parse().expect("id")
    }
    fn cash_leg() -> RepoCashLeg {
        RepoCashLeg {
            asset_definition_id: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "usd".parse().unwrap(),
            ),
            quantity: 1_000u32.into(),
        }
    }
    fn collateral_leg() -> RepoCollateralLeg {
        RepoCollateralLeg::new(
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "bond".parse().unwrap(),
            ),
            1_100u32,
        )
    }
    fn repo_instruction() -> RepoIsi {
        RepoIsi::new(
            agreement_id(),
            parse_account(INITIATOR),
            parse_account(COUNTERPARTY),
            Some(seeded_account(0xCD)),
            cash_leg(),
            collateral_leg(),
            250,
            1_704_000_000_000,
            RepoGovernance::with_defaults(1_500, 86_400),
        )
    }
    fn reverse_repo_instruction() -> ReverseRepoIsi {
        ReverseRepoIsi::new(agreement_id())
    }
    #[test]
    fn repo_instruction_roundtrip() {
        let agreement_id: RepoAgreementId = "daily_repo".parse().expect("id");
        let initiator = parse_account(INITIATOR);
        let counterparty = parse_account(COUNTERPARTY);
        let cash_leg = RepoCashLeg {
            asset_definition_id: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "usd".parse().unwrap(),
            ),
            quantity: 1_000u32.into(),
        };
        let collateral_leg = RepoCollateralLeg::new(
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "bond".parse().unwrap(),
            ),
            1_100u32,
        );
        let governance = RepoGovernance::with_defaults(1_500, 86_400);
        let instruction = RepoIsi::new(
            agreement_id.clone(),
            initiator.clone(),
            counterparty.clone(),
            None,
            cash_leg,
            collateral_leg,
            250,
            1_704_000_000_000,
            governance,
        );
        let bytes = instruction.encode();
        let decoded = RepoIsi::decode(&mut bytes.as_slice()).expect("decode");
        assert_eq!(instruction, decoded);
        assert_eq!(decoded.governance().haircut_bps(), governance.haircut_bps());
    }
    #[test]
    fn repo_display_includes_identifier() {
        let agreement_id: RepoAgreementId = "daily_repo".parse().expect("id");
        let initiator = parse_account(INITIATOR);
        let counterparty = parse_account(COUNTERPARTY);
        let cash_leg = RepoCashLeg {
            asset_definition_id: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "usd".parse().unwrap(),
            ),
            quantity: 1_000u32.into(),
        };
        let collateral_leg = RepoCollateralLeg::new(
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "bond".parse().unwrap(),
            ),
            1_100u32,
        );
        let governance = RepoGovernance::with_defaults(1_500, 86_400);
        let instruction = RepoIsi::new(
            agreement_id.clone(),
            initiator.clone(),
            counterparty.clone(),
            None,
            cash_leg,
            collateral_leg,
            250,
            1_704_000_000_000,
            governance,
        );
        let formatted = format!("{instruction}");
        assert!(formatted.contains("daily_repo"));
        assert!(formatted.contains("250bps"));
    }
    #[test]
    fn repo_display_includes_custodian_when_present() {
        let agreement_id: RepoAgreementId = "daily_repo".parse().expect("id");
        let initiator = parse_account(INITIATOR);
        let counterparty = parse_account(COUNTERPARTY);
        let custodian = seeded_account(0xCD);
        let cash_leg = RepoCashLeg {
            asset_definition_id: iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "usd".parse().unwrap(),
            ),
            quantity: 1_000u32.into(),
        };
        let collateral_leg = RepoCollateralLeg::new(
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "bond".parse().unwrap(),
            ),
            1_100u32,
        );
        let governance = RepoGovernance::with_defaults(1_500, 86_400);
        let instruction = RepoIsi::new(
            agreement_id,
            initiator,
            counterparty,
            Some(custodian.clone()),
            cash_leg,
            collateral_leg,
            250,
            1_704_000_000_000,
            governance,
        );
        let formatted = format!("{instruction}");
        assert!(formatted.contains(&format!("CUST `{custodian}`")));
    }
    #[test]
    fn repo_margin_call_roundtrip() {
        let agreement_id: RepoAgreementId = "daily_repo".parse().expect("id");
        let instruction = RepoMarginCallIsi::new(agreement_id.clone());
        let bytes = instruction.encode();
        let decoded = RepoMarginCallIsi::decode(&mut bytes.as_slice()).expect("decode");
        assert_eq!(instruction, decoded);
        assert_eq!(decoded.agreement_id(), &agreement_id);
        assert_eq!(decoded.to_string(), "REPO_MARGIN `daily_repo`");
    }
    #[test]
    fn reverse_repo_display_is_maturity_only() {
        let agreement_id: RepoAgreementId = "daily_repo".parse().expect("id");
        let instruction = ReverseRepoIsi::new(agreement_id);
        let formatted = format!("{instruction}");
        assert_eq!(formatted, "REPO_SETTLE `daily_repo` AT MATURITY");
    }
    #[test]
    fn repo_consent_hashes_bind_every_term_and_phase() {
        let instruction = repo_instruction();
        let mut changed = instruction.clone();
        changed.collateral_leg.quantity = 1_101u32.into();
        assert_ne!(
            instruction.initiation_intent_hash(),
            changed.initiation_intent_hash()
        );
        assert_ne!(
            instruction.maturity_intent_hash(),
            changed.maturity_intent_hash()
        );
        assert_ne!(
            instruction.initiation_intent_hash(),
            instruction.maturity_intent_hash(),
            "cash and maturity permissions must not be interchangeable"
        );
        assert_eq!(instruction.settlement_id().owner(), instruction.initiator());
        assert_eq!(
            instruction.settlement_id().reference(),
            instruction.agreement_id().name()
        );
    }
    #[test]
    fn repo_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(repo_instruction());
        assert_slice_roundtrip(reverse_repo_instruction());
        assert_slice_roundtrip(RepoMarginCallIsi::new(agreement_id()));
    }
    #[test]
    fn repo_instruction_box_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(RepoInstructionBox::from(repo_instruction()));
        assert_slice_roundtrip(RepoInstructionBox::Reverse(reverse_repo_instruction()));
        assert_slice_roundtrip(RepoInstructionBox::MarginCall(RepoMarginCallIsi::new(
            agreement_id(),
        )));
    }
    #[test]
    fn boxed_repo_initiation_preserves_the_original_canonical_wire() {
        let instruction = repo_instruction();
        let expected = LegacyRepoInstructionBox::Initiate(instruction.clone()).encode();
        let actual = RepoInstructionBox::from(instruction).encode();
        assert_eq!(actual, expected);
    }
    #[test]
    fn boxed_repo_initiation_preserves_the_original_schema_field_type() {
        let schema = <RepoInstructionBox as iroha_schema::IntoSchema>::schema();
        let metadata = schema
            .get::<RepoInstructionBox>()
            .expect("repo instruction schema entry");
        let iroha_schema::Metadata::Enum(enum_metadata) = metadata else {
            panic!("repo instruction schema must remain an enum");
        };
        assert_eq!(
            enum_metadata.variants[0].ty,
            Some(core::any::TypeId::of::<RepoIsi>())
        );
        assert!(schema.contains_key::<RepoIsi>());
        assert!(!schema.contains_key::<Box<RepoIsi>>());
    }
    #[test]
    fn negative_numeric_payload_cannot_decode_as_repo_instruction_quantity() {
        let positive_cash = cash_leg();
        let forged = ForgedRepoIsi {
            agreement_id: agreement_id(),
            initiator: parse_account(INITIATOR),
            counterparty: parse_account(COUNTERPARTY),
            custodian: None,
            cash_leg: ForgedRepoCashLeg {
                asset_definition_id: positive_cash.asset_definition_id,
                quantity: Numeric::new(-1_i32, 0),
            },
            collateral_leg: collateral_leg(),
            rate_bps: 250,
            maturity_timestamp_ms: 1_704_000_000_000,
            governance: RepoGovernance::with_defaults(1_500, 86_400),
        };
        assert!(
            RepoIsi::decode_from_slice(&forged.encode()).is_err(),
            "a negative signed payload must not decode as a repo instruction"
        );
    }
    #[test]
    fn repo_registry_decodes_only_the_stable_box_id() {
        let registry = crate::isi::registry::default();
        for value in [
            RepoInstructionBox::from(repo_instruction()),
            RepoInstructionBox::Reverse(reverse_repo_instruction()),
            RepoInstructionBox::MarginCall(RepoMarginCallIsi::new(agreement_id())),
        ] {
            assert_registry_decodes(&registry, RepoInstructionBox::WIRE_ID, value);
        }
        for name in [
            std::any::type_name::<RepoIsi>(),
            std::any::type_name::<ReverseRepoIsi>(),
            std::any::type_name::<RepoMarginCallIsi>(),
            RepoIsi::WIRE_ID,
            ReverseRepoIsi::WIRE_ID,
            RepoMarginCallIsi::WIRE_ID,
        ] {
            assert!(!registry.contains(name), "{name} must remain boxed-only");
        }
        assert!(!registry.contains(std::any::type_name::<RepoInstructionBox>()));
    }
}
