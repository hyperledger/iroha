//! Immutable asset-definition home projections from authoritative ledger state.

use super::{AssetBalancePolicy, AssetDefinition};
use crate::nexus::AxtAssetIncarnationV1;
use iroha_model_base::{domain::DomainId, error::ParseError, topology::DataSpaceId};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Immutable direct dataspace home of one live asset-definition incarnation.
///
/// The canonical World table `world.asset_definition_direct_homes` keys this row by the exact
/// [`AssetDefinitionId`](super::AssetDefinitionId). A row exists only while its incarnation is
/// live: native registration inserts it together with the definition, and unregistration
/// removes it together with the definition. There are no tombstones. Aliases, ownership
/// transfers and balance movements never establish or change a home.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::asset::dataspace_definition::AssetDefinitionDirectHomeV1"
)]
pub struct AssetDefinitionDirectHomeV1 {
    /// Incarnation produced by the genuine native asset-registration event.
    pub incarnation: AxtAssetIncarnationV1,
    /// Exact non-universal physical dataspace namespace home.
    pub dataspace_id: DataSpaceId,
}

impl AssetDefinitionDirectHomeV1 {
    /// Validate the canonical incarnation and physical dataspace shape.
    ///
    /// This checks the row alone. Whether it matches a live, domainless definition with the same
    /// incarnation is checked by the State owner that reads or writes the table.
    ///
    /// # Errors
    /// Rejects the reserved universal dataspace or an invalid native incarnation token.
    pub fn validate(&self) -> Result<(), ParseError> {
        if self.dataspace_id == DataSpaceId::UNIVERSAL {
            return Err(ParseError::new(
                "direct asset home requires a non-universal dataspace",
            ));
        }
        self.incarnation
            .validate()
            .map_err(|_| ParseError::new("direct asset home has an invalid incarnation"))
    }
}

/// Immutable namespace home of an asset definition.
///
/// This is a projection of the definition and its separate authoritative direct-home row
/// ([`AssetDefinitionDirectHomeV1`]). It is not appended to the signed [`AssetDefinition`]
/// payload. Aliases and concrete balance buckets do not establish or change a definition's home.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(tag = "kind", content = "content")]
#[norito_schema(name = "iroha_data_model::asset::dataspace_definition::AssetDefinitionHome")]
#[expect(
    variant_size_differences,
    reason = "keep the bounded domain identifier inline in this read projection without another heap allocation"
)]
pub enum AssetDefinitionHome {
    /// An existing global definition with no domain or direct-dataspace home.
    Global,
    /// A definition owned by this exact domain.
    Domain(DomainId),
    /// A definition registered directly under this exact dataspace.
    Dataspace(DataSpaceId),
}

impl AssetDefinitionHome {
    /// Project the immutable home from an asset definition and its committed direct-home row.
    ///
    /// `direct_dataspace` must come from the authoritative row keyed by `definition.id`,
    /// never from an alias, account home, transaction route, or concrete balance bucket.
    /// Both global and dataspace-restricted balance policies may have an explicit home.
    ///
    /// # Errors
    /// Returns an error if a definition claims both domain and direct-dataspace homes, if a
    /// direct row names the reserved universal dataspace, or if a dataspace-restricted
    /// definition has neither home.
    pub fn from_definition(
        definition: &AssetDefinition,
        direct_dataspace: Option<DataSpaceId>,
    ) -> Result<Self, ParseError> {
        Self::validate_definition(definition, direct_dataspace)?;
        Ok(
            match (definition.owning_domain.as_ref(), direct_dataspace) {
                (Some(domain), _) => Self::Domain(domain.clone()),
                (None, Some(dataspace)) => Self::Dataspace(dataspace),
                (None, None) => Self::Global,
            },
        )
    }

    /// Validate an immutable home without constructing an owned projection or cloning names.
    ///
    /// Inspection-only callers can use this check while retaining the original definition.
    /// `direct_dataspace` has the same authoritative-source requirement as
    /// [`Self::from_definition`]. Both methods share this sole validation predicate.
    ///
    /// # Errors
    /// Returns the same errors, in the same order, as [`Self::from_definition`].
    pub fn validate_definition(
        definition: &AssetDefinition,
        direct_dataspace: Option<DataSpaceId>,
    ) -> Result<(), ParseError> {
        match (definition.owning_domain.as_ref(), direct_dataspace) {
            (Some(_), Some(_)) => Err(ParseError::new(
                "asset definition cannot have both domain and direct-dataspace homes",
            )),
            (None, Some(DataSpaceId::UNIVERSAL)) => Err(ParseError::new(
                "direct-dataspace asset home must be a non-universal dataspace",
            )),
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (None, None) if definition.balance_scope_policy == AssetBalancePolicy::Global => Ok(()),
            (None, None) => Err(ParseError::new(
                "dataspace-restricted asset definition requires an immutable home",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Registrable, account::AccountId, asset::AssetDefinitionId};
    use iroha_crypto::{Algorithm, Hash, KeyPair};

    fn incarnation(seed: &[u8]) -> AxtAssetIncarnationV1 {
        AxtAssetIncarnationV1::try_from_bytes(Hash::new(seed).into())
            .expect("canonical nonzero fixture incarnation")
    }

    #[test]
    fn direct_home_row_validates_dataspace_and_incarnation() {
        let row = AssetDefinitionDirectHomeV1 {
            incarnation: incarnation(b"direct home row fixture"),
            dataspace_id: DataSpaceId::new(u64::MAX),
        };
        row.validate().expect("valid exact row");
        let universal = AssetDefinitionDirectHomeV1 {
            dataspace_id: DataSpaceId::UNIVERSAL,
            ..row
        };
        assert!(universal.validate().is_err());
    }

    #[test]
    fn direct_home_row_roundtrips_without_losing_dataspace_bits() {
        let row = AssetDefinitionDirectHomeV1 {
            incarnation: incarnation(b"direct home roundtrip fixture"),
            dataspace_id: DataSpaceId::new(u64::MAX - 3),
        };
        let frame = norito::encode_canonical(&row).expect("encode row");
        assert_eq!(
            norito::decode_canonical::<AssetDefinitionDirectHomeV1>(&frame).expect("decode row"),
            row
        );
        let json = norito::json::to_json(&row).expect("serialize row");
        assert_eq!(
            norito::json::from_json::<AssetDefinitionDirectHomeV1>(&json).expect("deserialize row"),
            row
        );
        let unknown = json.replacen('{', "{\"active\":true,", 1);
        assert!(norito::json::from_json::<AssetDefinitionDirectHomeV1>(&unknown).is_err());
    }

    fn definition(policy: AssetBalancePolicy, domain: Option<DomainId>) -> AssetDefinition {
        let id = AssetDefinitionId::from_uuid_bytes([
            0x91, 0x21, 0x63, 0x05, 0x0a, 0xb8, 0x46, 0x22, 0xab, 0x0d, 0x09, 0x0c, 0x31, 0x41,
            0x51, 0x61,
        ])
        .expect("public synthetic UUIDv4");
        let keys = KeyPair::try_from_seed(vec![0x6c; 32], Algorithm::Ed25519)
            .expect("public synthetic owner");
        AssetDefinition::numeric(id, "Native unit", policy, domain)
            .build(&AccountId::new(keys.public_key().clone()))
    }

    #[test]
    fn exact_committed_home_is_independent_of_balance_policy() {
        let domain = DomainId::try_new("issuer", "public").expect("domain");
        let dataspace = DataSpaceId::new(u64::MAX);
        for policy in [
            AssetBalancePolicy::Global,
            AssetBalancePolicy::DataspaceRestricted,
        ] {
            assert_eq!(
                AssetDefinitionHome::from_definition(&definition(policy, None), Some(dataspace))
                    .expect("direct home"),
                AssetDefinitionHome::Dataspace(dataspace)
            );
            assert_eq!(
                AssetDefinitionHome::from_definition(
                    &definition(policy, Some(domain.clone())),
                    None
                )
                .expect("domain home"),
                AssetDefinitionHome::Domain(domain.clone())
            );
            assert!(
                AssetDefinitionHome::from_definition(
                    &definition(policy, Some(domain.clone())),
                    Some(dataspace)
                )
                .is_err()
            );
            assert!(
                AssetDefinitionHome::from_definition(
                    &definition(policy, None),
                    Some(DataSpaceId::UNIVERSAL)
                )
                .is_err()
            );
        }
        assert_eq!(
            AssetDefinitionHome::from_definition(
                &definition(AssetBalancePolicy::Global, None),
                None
            )
            .expect("existing global home"),
            AssetDefinitionHome::Global
        );
        assert!(
            AssetDefinitionHome::from_definition(
                &definition(AssetBalancePolicy::DataspaceRestricted, None),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn borrowed_home_validation_preserves_projection_and_refusal_precedence() {
        let short = DomainId::try_new("issuer", "public").expect("short domain");
        let label = "d".repeat(63);
        let long = DomainId::try_new(&label, &label).expect("maximum domain components");
        let dataspace = DataSpaceId::new(u64::MAX);
        for policy in [
            AssetBalancePolicy::Global,
            AssetBalancePolicy::DataspaceRestricted,
        ] {
            for domain in [None, Some(&short), Some(&long)] {
                let definition = definition(policy, domain.cloned());
                for direct in [None, Some(DataSpaceId::UNIVERSAL), Some(dataspace)] {
                    let expected = match (domain.is_some(), direct) {
                        (true, Some(_)) => Err(
                            "asset definition cannot have both domain and direct-dataspace homes",
                        ),
                        (false, Some(DataSpaceId::UNIVERSAL)) => {
                            Err("direct-dataspace asset home must be a non-universal dataspace")
                        }
                        (false, None) if policy == AssetBalancePolicy::DataspaceRestricted => {
                            Err("dataspace-restricted asset definition requires an immutable home")
                        }
                        _ => Ok(()),
                    };
                    let borrowed = AssetDefinitionHome::validate_definition(&definition, direct)
                        .map_err(|error| error.reason());
                    assert_eq!(borrowed, expected);
                    assert_eq!(
                        AssetDefinitionHome::from_definition(&definition, direct)
                            .map(|_| ())
                            .map_err(|error| error.reason()),
                        borrowed,
                    );
                }
            }
        }
    }

    #[test]
    fn alias_changes_cannot_rehome_a_definition() {
        let dataspace = DataSpaceId::new(u64::MAX - 17);
        let mut definition = definition(AssetBalancePolicy::DataspaceRestricted, None);
        for alias in [None, Some("unit#other".parse().expect("alias")), None] {
            definition.alias = alias;
            assert_eq!(
                AssetDefinitionHome::from_definition(&definition, Some(dataspace))
                    .expect("direct home"),
                AssetDefinitionHome::Dataspace(dataspace)
            );
        }
    }

    #[test]
    fn typed_homes_roundtrip_without_losing_dataspace_bits() {
        for home in [
            AssetDefinitionHome::Global,
            AssetDefinitionHome::Domain(DomainId::try_new("issuer", "public").expect("domain")),
            AssetDefinitionHome::Dataspace(DataSpaceId::new(u64::MAX)),
        ] {
            let bytes = norito::encode_canonical(&home).expect("encode home");
            assert_eq!(
                norito::decode_canonical::<AssetDefinitionHome>(&bytes).expect("decode home"),
                home
            );
            let json = norito::json::to_json(&home).expect("serialize home");
            assert_eq!(
                norito::json::from_json::<AssetDefinitionHome>(&json).expect("deserialize home"),
                home
            );
        }
    }
}
