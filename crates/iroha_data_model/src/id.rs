//! Exact network lineage and the aggregate ledger identity box.

pub use self::model::*;
use crate::{
    account, asset, block::BlockHeader, nft, parameter, permission, repo, role, rwa, trigger,
};
use derive_more::Display;
use iroha_crypto::HashOf;
use iroha_data_model_derive::{EnumRef, model};
use iroha_macro::FromVariant;
use iroha_model_base::error::ParseError;
use iroha_schema::IntoSchema;
use norito::codec::Encode;
use norito::core::{DecodeFromSlice, Error as NoritoError};
const NETWORK_ID_LITERAL_BYTES: usize =
    "hash:".len() + iroha_crypto::Hash::LENGTH * 2 + "#".len() + 4;
#[model]
mod model {
    use super::*;
    /// Exact deployment identity derived from the consensus hash of the genesis header.
    ///
    /// Unlike [`ChainId`](iroha_model_base::chain::ChainId), this value is not an operator-selected label. Distinct genesis
    /// headers necessarily produce distinct network identities, so signed protocol messages can
    /// use this type as an exact-lineage domain separator. Its only accepted text form is the
    /// canonical checked `hash:<UPPERCASE_HEX>#<CHECKSUM>` literal used by Norito JSON.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, IntoSchema)]
    #[repr(transparent)]
    #[schema(transparent)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::id::model::NetworkId")]
    pub struct NetworkId(HashOf<BlockHeader>);
    impl NetworkId {
        /// Construct the network identity from the exact genesis consensus-header hash.
        #[must_use]
        pub const fn from_genesis_hash(hash: HashOf<BlockHeader>) -> Self {
            Self(hash)
        }
        /// Borrow the exact genesis consensus-header hash.
        #[must_use]
        pub const fn as_genesis_hash(&self) -> &HashOf<BlockHeader> {
            &self.0
        }
        /// Recover the exact genesis consensus-header hash.
        #[must_use]
        pub const fn into_genesis_hash(self) -> HashOf<BlockHeader> {
            self.0
        }
        /// Borrow the canonical 32-byte identity.
        #[must_use]
        pub fn as_bytes(&self) -> &[u8; iroha_crypto::Hash::LENGTH] {
            self.0.as_ref()
        }
    }
    impl From<HashOf<BlockHeader>> for NetworkId {
        fn from(value: HashOf<BlockHeader>) -> Self {
            Self::from_genesis_hash(value)
        }
    }
    impl From<NetworkId> for HashOf<BlockHeader> {
        fn from(value: NetworkId) -> Self {
            value.into_genesis_hash()
        }
    }
    impl core::str::FromStr for NetworkId {
        type Err = ParseError;
        fn from_str(value: &str) -> Result<Self, Self::Err> {
            if value.len() != NETWORK_ID_LITERAL_BYTES {
                return Err(ParseError::new(
                    "`NetworkId` must be one 74-byte canonical checked hash literal",
                ));
            }
            let body = norito::literal::parse_without_diagnostics("hash", value).ok_or_else(|| {
                ParseError::new(
                    "`NetworkId` must be one canonical checksummed `hash:<UPPERCASE_HEX>#<CHECKSUM>` literal",
                )
            })?;
            if body.len() != iroha_crypto::Hash::LENGTH * 2
                || body
                    .bytes()
                    .any(|byte| !byte.is_ascii_digit() && !matches!(byte, b'A'..=b'F'))
            {
                return Err(ParseError::new(
                    "`NetworkId` hash body must contain exactly 64 uppercase hexadecimal digits",
                ));
            }
            let genesis_hash = body.parse::<HashOf<BlockHeader>>().map_err(|_| {
                ParseError::new("`NetworkId` hash body is not a valid marked genesis hash")
            })?;
            let network_id = Self::from_genesis_hash(genesis_hash);
            if network_id.to_string() != value {
                return Err(ParseError::new(
                    "`NetworkId` must use its canonical checksummed spelling",
                ));
            }
            Ok(network_id)
        }
    }
    impl core::fmt::Display for NetworkId {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let body = hex::encode_upper(self.as_bytes());
            formatter.write_str(&norito::literal::format("hash", &body))
        }
    }

    impl norito::json::FastJsonWrite for NetworkId {
        fn write_json(&self, out: &mut String) {
            norito::json::FastJsonWrite::write_json(&self.0, out);
        }
        fn write_json_to(
            &self,
            out: &mut dyn norito::json::JsonWriteSink,
        ) -> Result<(), norito::json::BoundedJsonError> {
            norito::json::FastJsonWrite::write_json_to(&self.0, out)
        }
    }

    impl norito::json::JsonDeserialize for NetworkId {
        fn json_deserialize(
            parser: &mut norito::json::Parser<'_>,
        ) -> Result<Self, norito::json::Error> {
            let value = parser.parse_string()?;
            value
                .parse()
                .map_err(|error: ParseError| norito::json::Error::Message(error.reason().into()))
        }
        fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
            let value = value.as_str().ok_or_else(|| {
                norito::json::Error::Message("`NetworkId` must be a JSON string".to_owned())
            })?;
            value
                .parse()
                .map_err(|error: ParseError| norito::json::Error::Message(error.reason().into()))
        }
    }
    /// Sized container for all possible identifications.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        EnumRef,
        FromVariant,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(tag = "kind", content = "content")]
    #[enum_ref(derive(FromVariant))]
    #[allow(clippy::enum_variant_names)]
    #[derive(norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::id::model::IdBox")]
    pub enum IdBox {
        /// [`DomainId`](`iroha_model_base::domain::DomainId`) variant.
        DomainId(iroha_model_base::domain::DomainId),
        /// [`AccountId`](`account::AccountId`) variant.
        #[display("{_0}")]
        AccountId(account::AccountId),
        /// [`AssetDefinitionId`](`asset::id::AssetDefinitionId`) variant.
        #[display("{_0}")]
        AssetDefinitionId(asset::id::AssetDefinitionId),
        /// [`AssetId`](`asset::id::AssetId`) variant.
        #[display("{_0}")]
        AssetId(asset::id::AssetId),
        /// [`NftId`](`nft::NftId`) variant.
        #[display("{_0}")]
        NftId(nft::NftId),
        /// [`RwaId`](`rwa::RwaId`) variant.
        #[display("{_0}")]
        RwaId(rwa::RwaId),
        /// [`PeerId`](`iroha_model_base::peer::PeerId`) variant.
        PeerId(iroha_model_base::peer::PeerId),
        /// [`LaneId`](`iroha_model_base::topology::LaneId`) variant.
        LaneId(iroha_model_base::topology::LaneId),
        /// [`TriggerId`](trigger::TriggerId) variant.
        TriggerId(trigger::TriggerId),
        /// [`RoleId`](`role::RoleId`) variant.
        RoleId(role::RoleId),
        /// [`Permission`](`permission::Permission`) variant.
        Permission(permission::Permission),
        /// [`CustomParameter`](`parameter::CustomParameter`) variant.
        CustomParameterId(parameter::CustomParameterId),
        /// [`RepoAgreementId`](`repo::RepoAgreementId`) variant.
        RepoAgreementId(repo::RepoAgreementId),
    }
}

impl norito::core::SerializePayload for NetworkId {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::SerializePayload::serialize(self.as_genesis_hash(), writer)
    }
    fn encoded_len_hint(&self) -> Option<usize> {
        Some(iroha_crypto::Hash::LENGTH)
    }
    fn encoded_len_exact(&self) -> Option<usize> {
        Some(iroha_crypto::Hash::LENGTH)
    }
}

impl<'a> norito::core::DeserializePayload<'a> for NetworkId {
    fn deserialize(archived: &'a norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived)
            .expect("NetworkId deserialization must succeed for a valid genesis hash")
    }
    fn try_deserialize(
        archived: &'a norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        <HashOf<BlockHeader> as norito::core::DeserializePayload<'a>>::try_deserialize(
            archived.cast(),
        )
        .map(Self::from_genesis_hash)
    }
}
impl<'a> DecodeFromSlice<'a> for NetworkId {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), NoritoError> {
        <HashOf<BlockHeader> as DecodeFromSlice<'a>>::decode_from_slice(bytes)
            .map(|(hash, used)| (Self::from_genesis_hash(hash), used))
    }
}
mod id_box_codec {
    use super::*;
    #[derive(norito::DeserializePayload)]
    #[cfg_attr(test, derive(norito::SerializePayload))]
    enum IdBoxCandidate {
        DomainId(iroha_model_base::domain::DomainId),
        AccountId(account::AccountId),
        AssetDefinitionId(asset::id::AssetDefinitionId),
        AssetId(asset::id::AssetId),
        NftId(nft::NftId),
        RwaId(rwa::RwaId),
        PeerId(iroha_model_base::peer::PeerId),
        LaneId(iroha_model_base::topology::LaneId),
        TriggerId(trigger::TriggerId),
        RoleId(role::RoleId),
        Permission(permission::Permission),
        CustomParameterId(parameter::CustomParameterId),
        RepoAgreementId(repo::RepoAgreementId),
    }
    #[cfg(test)]
    impl From<IdBox> for IdBoxCandidate {
        fn from(id: IdBox) -> Self {
            match id {
                IdBox::DomainId(v) => Self::DomainId(v),
                IdBox::AccountId(v) => Self::AccountId(v),
                IdBox::AssetDefinitionId(v) => Self::AssetDefinitionId(v),
                IdBox::AssetId(v) => Self::AssetId(v),
                IdBox::NftId(v) => Self::NftId(v),
                IdBox::RwaId(v) => Self::RwaId(v),
                IdBox::PeerId(v) => Self::PeerId(v),
                IdBox::LaneId(v) => Self::LaneId(v),
                IdBox::TriggerId(v) => Self::TriggerId(v),
                IdBox::RoleId(v) => Self::RoleId(v),
                IdBox::Permission(v) => Self::Permission(v),
                IdBox::CustomParameterId(v) => Self::CustomParameterId(v),
                IdBox::RepoAgreementId(v) => Self::RepoAgreementId(v),
            }
        }
    }
    impl From<IdBoxCandidate> for IdBox {
        fn from(id: IdBoxCandidate) -> Self {
            match id {
                IdBoxCandidate::DomainId(v) => Self::DomainId(v),
                IdBoxCandidate::AccountId(v) => Self::AccountId(v),
                IdBoxCandidate::AssetDefinitionId(v) => Self::AssetDefinitionId(v),
                IdBoxCandidate::AssetId(v) => Self::AssetId(v),
                IdBoxCandidate::NftId(v) => Self::NftId(v),
                IdBoxCandidate::RwaId(v) => Self::RwaId(v),
                IdBoxCandidate::PeerId(v) => Self::PeerId(v),
                IdBoxCandidate::LaneId(v) => Self::LaneId(v),
                IdBoxCandidate::TriggerId(v) => Self::TriggerId(v),
                IdBoxCandidate::RoleId(v) => Self::RoleId(v),
                IdBoxCandidate::Permission(v) => Self::Permission(v),
                IdBoxCandidate::CustomParameterId(v) => Self::CustomParameterId(v),
                IdBoxCandidate::RepoAgreementId(v) => Self::RepoAgreementId(v),
            }
        }
    }

    // Keep the current variant order and field layout while borrowing the
    // original identity. Counting or writing never clones its name, key or JSON.
    struct BorrowedIdValue<'a, T>(&'a T);

    impl<T: norito::core::SerializePayload> norito::core::SerializePayload for BorrowedIdValue<'_, T> {
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            norito::core::SerializePayload::serialize(self.0, writer)
        }
    }

    #[derive(norito::SerializePayload)]
    enum IdBoxView<'a> {
        DomainId(BorrowedIdValue<'a, iroha_model_base::domain::DomainId>),
        AccountId(BorrowedIdValue<'a, account::AccountId>),
        AssetDefinitionId(BorrowedIdValue<'a, asset::id::AssetDefinitionId>),
        AssetId(BorrowedIdValue<'a, asset::id::AssetId>),
        NftId(BorrowedIdValue<'a, nft::NftId>),
        RwaId(BorrowedIdValue<'a, rwa::RwaId>),
        PeerId(BorrowedIdValue<'a, iroha_model_base::peer::PeerId>),
        LaneId(BorrowedIdValue<'a, iroha_model_base::topology::LaneId>),
        TriggerId(BorrowedIdValue<'a, trigger::TriggerId>),
        RoleId(BorrowedIdValue<'a, role::RoleId>),
        Permission(BorrowedIdValue<'a, permission::Permission>),
        CustomParameterId(BorrowedIdValue<'a, parameter::CustomParameterId>),
        RepoAgreementId(BorrowedIdValue<'a, repo::RepoAgreementId>),
    }

    impl<'a> From<&'a IdBox> for IdBoxView<'a> {
        fn from(id: &'a IdBox) -> Self {
            match id {
                IdBox::DomainId(v) => Self::DomainId(BorrowedIdValue(v)),
                IdBox::AccountId(v) => Self::AccountId(BorrowedIdValue(v)),
                IdBox::AssetDefinitionId(v) => Self::AssetDefinitionId(BorrowedIdValue(v)),
                IdBox::AssetId(v) => Self::AssetId(BorrowedIdValue(v)),
                IdBox::NftId(v) => Self::NftId(BorrowedIdValue(v)),
                IdBox::RwaId(v) => Self::RwaId(BorrowedIdValue(v)),
                IdBox::PeerId(v) => Self::PeerId(BorrowedIdValue(v)),
                IdBox::LaneId(v) => Self::LaneId(BorrowedIdValue(v)),
                IdBox::TriggerId(v) => Self::TriggerId(BorrowedIdValue(v)),
                IdBox::RoleId(v) => Self::RoleId(BorrowedIdValue(v)),
                IdBox::Permission(v) => Self::Permission(BorrowedIdValue(v)),
                IdBox::CustomParameterId(v) => Self::CustomParameterId(BorrowedIdValue(v)),
                IdBox::RepoAgreementId(v) => Self::RepoAgreementId(BorrowedIdValue(v)),
            }
        }
    }

    impl norito::core::SerializePayload for IdBox {
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            norito::core::SerializePayload::serialize(&IdBoxView::from(self), writer)
        }
    }

    impl<'de> norito::core::DeserializePayload<'de> for IdBox {
        fn deserialize(archived: &'de norito::core::Archived<IdBox>) -> Self {
            Self::try_deserialize(archived)
                .expect("IdBox deserialization must succeed for valid archives")
        }
        fn try_deserialize(
            archived: &'de norito::core::Archived<IdBox>,
        ) -> Result<Self, norito::core::Error> {
            <IdBoxCandidate as norito::core::DeserializePayload>::try_deserialize(archived.cast())
                .map(Into::into)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn borrowed_id_box_preserves_every_original_variant_in_both_v1_layouts() {
            let name = "original_identity_"
                .repeat(7)
                .parse::<iroha_model_base::name::Name>()
                .expect("long checked name");
            let domain = iroha_model_base::domain::DomainId::try_new(
                "originaldomainlabel".repeat(2).as_str(),
                "universal",
            )
            .expect("checked domain");
            let key = iroha_crypto::KeyPair::try_from_seed(
                vec![0x39; 32],
                iroha_crypto::Algorithm::Ed25519,
            )
            .expect("deterministic identity key");
            let account = account::AccountId::new(key.public_key().clone());
            let definition =
                asset::id::AssetDefinitionId::derive_from_components(domain.clone(), name.clone());
            let cases = [
                IdBox::DomainId(domain.clone()),
                IdBox::AccountId(account.clone()),
                IdBox::AssetDefinitionId(definition.clone()),
                IdBox::AssetId(asset::id::AssetId::of(definition, account)),
                IdBox::NftId(nft::NftId::new(domain.clone(), name.clone())),
                IdBox::RwaId(rwa::RwaId::new(
                    domain,
                    iroha_crypto::Hash::prehashed([0x17; 32]),
                )),
                IdBox::PeerId(iroha_model_base::peer::PeerId::new(
                    key.public_key().clone(),
                )),
                IdBox::LaneId(iroha_model_base::topology::LaneId::new(7)),
                IdBox::TriggerId(name.as_ref().parse().expect("trigger")),
                IdBox::RoleId(name.as_ref().parse().expect("role")),
                IdBox::Permission(permission::Permission::new(
                    "CanObserve".into(),
                    iroha_primitives::json::Json::default(),
                )),
                IdBox::CustomParameterId(parameter::CustomParameterId::new(name.clone())),
                IdBox::RepoAgreementId(repo::RepoAgreementId::new(name)),
            ];
            for (tag, id) in cases.into_iter().enumerate() {
                let original = IdBoxCandidate::from(id.clone());
                let mut payloads = Vec::new();
                for flags in [0, norito::core::header_flags::COMPACT_LEN] {
                    let _flags = norito::core::DecodeFlagsGuard::enter(flags);
                    let (expected, expected_flags) =
                        norito::codec::encode_with_header_flags(&original);
                    let (actual, actual_flags) = norito::codec::encode_with_header_flags(&id);
                    assert_eq!(expected_flags, flags, "oracle used another layout");
                    assert_eq!(actual_flags, flags, "public identity used another layout");
                    assert_eq!(
                        actual, expected,
                        "variant wire changed in layout {flags:#04x}"
                    );
                    assert_eq!(
                        &actual[..4],
                        &u32::try_from(tag).expect("variant tag").to_le_bytes()
                    );
                    let frame = norito::to_bytes(&id).expect("frame original declared layout");
                    let header =
                        norito::core::Header::read(&mut frame.as_slice()).expect("declared header");
                    assert_eq!(header.flags, flags);
                    assert_eq!(
                        header.schema,
                        norito::schema::identity::frame_hash::<IdBox>()
                    );
                    assert_eq!(
                        norito::decode_from_bytes::<IdBox>(&frame).expect("sole original decoder"),
                        id
                    );
                    payloads.push(actual);
                }
                assert_ne!(
                    payloads[0], payloads[1],
                    "the two actual V1 layouts were not exercised"
                );
            }
        }
    }
}
macro_rules! impl_encode_as_id_box {
    ($($ty:ty),+ $(,)?) => { $(
        impl $ty {
            /// [`Encode`] [`Self`] as [`IdBox`].
            pub fn encode_as_id_box(&self) -> Vec<u8> {
                IdBox::from(self.clone()).encode()
            }
        }
    )+ };
}
impl_encode_as_id_box! {
    account::AccountId,
    asset::id::AssetDefinitionId,
    asset::id::AssetId,
    rwa::RwaId,
    trigger::TriggerId,
    permission::Permission,
    role::RoleId,
    repo::RepoAgreementId,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn network_id_fixture() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0xA5; iroha_crypto::Hash::LENGTH]),
        ))
    }
    #[test]
    fn network_id_is_the_exact_transparent_genesis_hash_wire() {
        let network_id = network_id_fixture();
        let genesis_hash = *network_id.as_genesis_hash();
        let encoded = network_id.encode();
        assert_eq!(encoded.len(), iroha_crypto::Hash::LENGTH);
        assert_eq!(encoded, genesis_hash.encode());
        assert_eq!(network_id.encoded_len(), iroha_crypto::Hash::LENGTH);
        assert_eq!(network_id.as_bytes(), genesis_hash.as_ref());
        assert_eq!(
            NetworkId::decode_from_slice(&encoded).expect("decode exact network identity"),
            (network_id, iroha_crypto::Hash::LENGTH)
        );
        let framed = norito::to_bytes(&network_id).expect("frame network identity");
        assert_eq!(
            norito::decode_from_bytes::<NetworkId>(&framed).expect("framed roundtrip"),
            network_id
        );
        assert_eq!(
            network_id
                .to_string()
                .parse::<NetworkId>()
                .expect("text roundtrip"),
            network_id
        );
    }
    #[test]
    fn network_id_text_uses_one_canonical_checked_literal() {
        let network_id = network_id_fixture();
        let canonical = network_id.to_string();
        assert_eq!(
            canonical,
            norito::literal::format("hash", &hex::encode_upper(network_id.as_bytes()))
        );
        assert_eq!(
            canonical
                .parse::<NetworkId>()
                .expect("canonical checked literal parses"),
            network_id
        );

        let raw_hex = hex::encode_upper(network_id.as_bytes());
        let lowercase_body = norito::literal::format("hash", &raw_hex.to_ascii_lowercase());
        let mut bad_checksum = canonical.clone();
        let replacement = if bad_checksum.ends_with('0') {
            '1'
        } else {
            '0'
        };
        bad_checksum.pop();
        bad_checksum.push(replacement);
        for alias in [raw_hex, lowercase_body, bad_checksum] {
            assert!(
                alias.parse::<NetworkId>().is_err(),
                "noncanonical network identity alias must reject: {alias}"
            );
        }
    }
    #[test]
    fn network_id_rejects_oversized_text_before_literal_parsing() {
        let oversized = format!("hash:{}#0000", "A".repeat(4_096));
        let error = oversized
            .parse::<NetworkId>()
            .expect_err("oversized network identity must fail closed");
        assert_eq!(
            error.reason(),
            "`NetworkId` must be one 74-byte canonical checked hash literal"
        );
    }

    #[test]
    fn network_id_json_is_the_canonical_hash_literal() {
        let network_id = network_id_fixture();
        let network_json = norito::json::to_json(&network_id).expect("serialize network identity");
        let hash_json =
            norito::json::to_json(network_id.as_genesis_hash()).expect("serialize genesis hash");
        assert_eq!(network_json, hash_json);
        assert!(network_json.starts_with("\"hash:"));
        assert_eq!(network_json, format!("\"{network_id}\""));
        assert_eq!(
            norito::json::from_str::<NetworkId>(&network_json).expect("JSON roundtrip"),
            network_id
        );

        let raw_json = format!("\"{}\"", hex::encode_upper(network_id.as_bytes()));
        let lowercase_json = format!(
            "\"{}\"",
            norito::literal::format(
                "hash",
                &hex::encode_upper(network_id.as_bytes()).to_ascii_lowercase()
            )
        );
        for alias in [raw_json, lowercase_json] {
            assert!(
                norito::json::from_str::<NetworkId>(&alias).is_err(),
                "Norito JSON must reject noncanonical NetworkId alias {alias}"
            );
            let value: norito::json::Value =
                norito::json::from_str(&alias).expect("alias is valid generic JSON");
            assert!(
                <NetworkId as norito::json::JsonDeserialize>::json_from_value(&value).is_err(),
                "Norito JSON value conversion must reject noncanonical NetworkId alias {alias}"
            );
        }
    }

    #[test]
    fn network_id_json_rejects_oversized_text() {
        let oversized = format!("hash:{}#0000", "A".repeat(4_096));
        let encoded = format!("\"{oversized}\"");
        assert!(
            norito::json::from_str::<NetworkId>(&encoded).is_err(),
            "Norito JSON must reject oversized NetworkId text"
        );
        let value: norito::json::Value =
            norito::json::from_str(&encoded).expect("oversized identity is generic JSON text");
        assert!(
            <NetworkId as norito::json::JsonDeserialize>::json_from_value(&value).is_err(),
            "Norito JSON value conversion must reject oversized NetworkId text"
        );
    }
}
