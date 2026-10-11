//! JSON envelope helpers for the query DSL.
//!
//! These structures mirror the payloads accepted by Torii query endpoints. The helpers convert
//! between Norito JSON values and strongly-typed query objects, ensuring field ordering stays
//! deterministic and validation errors surface with precise context.
use crate::query::{
    ItemKindTag, QueryRequest, QueryWithParams, SingularQueryBox,
    dsl::{CompoundPredicate, HasProjection, PredicateMarker, SelectorMarker, SelectorTuple},
    json::predicate::{PredicateJson, PredicateParseError},
    parameters::{FetchSize, Pagination, QueryParams, Sorting},
};
use iroha_model_base::name::Name;
use norito::json::{self, JsonDeserialize, JsonSerialize, Map, Value};
use std::{
    format,
    num::NonZeroU64,
    str::FromStr,
    string::{String, ToString},
};
use thiserror::Error;
fn build_query_with_params<T, Q, F>(
    predicate: &CompoundPredicate<T>,
    selector: &SelectorTuple<T>,
    params: QueryParams,
    builder: F,
) -> QueryWithParams
where
    T: HasProjection<PredicateMarker>
        + HasProjection<SelectorMarker, AtomType = ()>
        + Send
        + Sync
        + ItemKindTag
        + 'static,
    Q: crate::query::Query<Item = T> + norito::codec::Encode,
    F: FnOnce() -> Q,
{
    let query = builder();
    QueryWithParams {
        query: (),
        query_payload: query.dyn_encode(),
        item: query.query_item_kind(),
        predicate_bytes: norito::codec::Encode::encode(predicate),
        selector_bytes: norito::codec::Encode::encode(selector),
        params,
    }
}
/// JSON envelope selecting either a singular or iterable query definition.
#[derive(Debug, Clone, PartialEq)]
pub enum QueryEnvelopeJson {
    /// Encodes a singular query (single object response).
    Singular(SingularQueryJson),
    /// Encodes an iterable query (batched response stream).
    Iterable(Box<IterableQueryJson>),
}
impl Eq for QueryEnvelopeJson {}
fn singular_payload(map: &Map) -> Result<&Map, QueryJsonError> {
    map.get("payload")
        .and_then(Value::as_object)
        .ok_or(QueryJsonError::MissingField("singular", "payload"))
}
fn payload_required_string<'a>(
    payload: &'a Map,
    field: &'static str,
) -> Result<&'a str, QueryJsonError> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .ok_or(QueryJsonError::MissingField("payload", field))
}
fn payload_optional_string(
    payload: &Map,
    field: &'static str,
) -> Result<Option<String>, QueryJsonError> {
    payload
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or(QueryJsonError::InvalidField("payload", field))
                .map(str::to_owned)
        })
        .transpose()
}
impl QueryEnvelopeJson {
    fn parse_map(map: &Map) -> Result<Self, QueryJsonError> {
        let mut singular: Option<&Value> = None;
        let mut iterable: Option<&Value> = None;
        for (key, value) in map {
            match key.as_str() {
                "singular" => singular = Some(value),
                "iterable" => iterable = Some(value),
                other => return Err(QueryJsonError::UnknownEnvelopeKey(other.to_owned())),
            }
        }
        match (singular, iterable) {
            (Some(value), None) => {
                let sing = SingularQueryJson::from_value(value)?;
                Ok(QueryEnvelopeJson::Singular(sing))
            }
            (None, Some(value)) => {
                let iter = IterableQueryJson::from_value(value)?;
                Ok(QueryEnvelopeJson::Iterable(Box::new(iter)))
            }
            (Some(_), Some(_)) => Err(QueryJsonError::AmbiguousEnvelope),
            (None, None) => Err(QueryJsonError::EmptyEnvelope),
        }
    }
}
impl JsonSerialize for QueryEnvelopeJson {
    fn json_serialize(&self, out: &mut String) {
        let mut map = Map::new();
        match self {
            QueryEnvelopeJson::Singular(s) => {
                map.insert("singular".to_owned(), s.to_value());
            }
            QueryEnvelopeJson::Iterable(i) => {
                map.insert("iterable".to_owned(), i.to_value());
            }
        }
        Value::Object(map).json_serialize(out);
    }
}
impl JsonDeserialize for QueryEnvelopeJson {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        let value = Value::json_deserialize(parser)?;
        match value {
            Value::Object(map) => QueryEnvelopeJson::parse_map(&map)
                .map_err(|err| json::Error::Message(err.to_string())),
            other => Err(json::Error::Message(format!(
                "expected envelope object, found {}",
                value_type_name(&other)
            ))),
        }
    }
}
/// Supported singular queries for the JSON DSL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingularQueryJson {
    /// Returns the active ABI version exposed by the runtime.
    FindAbiVersion,
    /// Returns metadata describing the executor data model.
    FindExecutorDataModel,
    /// Returns the current blockchain parameter set.
    FindParameters,
    /// Looks up an account by identifier.
    FindAccountById {
        /// Canonical I105 account identifier.
        account_id: String,
    },
    /// Looks up an account by stable alias.
    FindAccountByAlias {
        /// Stable account alias encoded as a structured JSON payload.
        alias: crate::account::AccountAlias,
    },
    /// Lists aliases bound to an account subject.
    FindAliasesByAccountId {
        /// Account identifier used to resolve the subject.
        account_id: String,
        /// Optional dataspace alias filter such as `centralbank`.
        dataspace: Option<String>,
        /// Optional exact domain filter such as `banka`.
        domain: Option<String>,
    },
    /// Looks up an account recovery policy by stable alias.
    FindAccountRecoveryPolicyByAlias {
        /// Stable account alias encoded as a structured JSON payload.
        alias: crate::account::AccountAlias,
    },
    /// Looks up an account recovery request by stable alias.
    FindAccountRecoveryRequestByAlias {
        /// Stable account alias encoded as a structured JSON payload.
        alias: crate::account::AccountAlias,
    },
    /// Looks up an asset by identifier.
    FindAssetById {
        /// Asset definition address identifying the asset type.
        asset: String,
        /// Canonical I105 account identifier owning the asset.
        account_id: String,
        /// Optional balance scope selector.
        scope: Option<Value>,
    },
    /// Looks up an asset definition by identifier.
    FindAssetDefinitionById {
        /// Asset definition address identifying the asset type.
        asset: String,
    },
    /// Looks up the immutable direct dataspace home row of an asset definition.
    FindAssetDefinitionDirectHome {
        /// Asset definition address identifying the directly homed asset type.
        asset: String,
    },
    /// Looks up a non-fungible asset by identifier.
    FindNftById {
        /// Canonical NFT identifier.
        nft_id: String,
    },
    /// Looks up a native asset escrow by identifier.
    FindAssetEscrowById {
        /// Escrow identifier encoded as one canonical checksummed hash literal.
        escrow_id: crate::escrow::EscrowId,
    },
    /// Looks up a trigger by identifier.
    FindTriggerById {
        /// Trigger identifier.
        id: String,
    },
    /// Looks up a contract manifest in one exact dataspace.
    FindContractManifestByArtifactId {
        /// Complete dataspace artifact identity.
        artifact_id: crate::smart_contract::ContractArtifactId,
    },
    /// Looks up a twitter follow binding by keyed hash.
    FindTwitterBindingByHash {
        /// Keyed hash identifying the binding.
        binding_hash: crate::oracle::KeyedHash,
    },
    /// Looks up a domain by identifier.
    FindDomainById {
        /// Fully qualified `domain.dataspace` identifier.
        domain_id: String,
    },
    /// Looks up a fee sponsor program by identifier.
    FindFeeSponsorProgramById {
        /// Fee sponsor program identifier in `sponsor/name` form.
        id: String,
    },
    /// Looks up one immutable native settlement business receipt.
    FindSettlementReceiptById {
        /// Exact committed business settlement identifier.
        id: String,
    },
    /// Fetches the complete protected native FX corridor policy registry.
    FindFxCorridorPolicyRegistry,
    /// Looks up a native FX corridor policy by stable identifier.
    FindFxCorridorPolicyById {
        /// Stable policy identifier.
        policy_id: String,
    },
}
impl SingularQueryJson {
    fn parse_account_by_id(payload: &Map) -> Result<Self, QueryJsonError> {
        Ok(Self::FindAccountById {
            account_id: payload_required_string(payload, "account_id")?.to_owned(),
        })
    }
    fn parse_account_by_alias(payload: &Map) -> Result<Self, QueryJsonError> {
        let alias = payload
            .get("alias")
            .ok_or(QueryJsonError::MissingField("payload", "alias"))
            .and_then(|value| {
                json::from_value::<crate::account::AccountAlias>(value.clone())
                    .map_err(|_| QueryJsonError::InvalidField("payload", "alias"))
            })?;
        Ok(Self::FindAccountByAlias { alias })
    }
    fn parse_aliases(payload: &Map) -> Result<Self, QueryJsonError> {
        Ok(Self::FindAliasesByAccountId {
            account_id: payload_required_string(payload, "account_id")?.to_owned(),
            dataspace: payload_optional_string(payload, "dataspace")?,
            domain: payload_optional_string(payload, "domain")?,
        })
    }
    fn parse_recovery_policy(payload: &Map) -> Result<Self, QueryJsonError> {
        let alias = payload
            .get("alias")
            .ok_or(QueryJsonError::MissingField("payload", "alias"))
            .and_then(|value| {
                json::from_value::<crate::account::AccountAlias>(value.clone())
                    .map_err(|_| QueryJsonError::InvalidField("payload", "alias"))
            })?;
        Ok(Self::FindAccountRecoveryPolicyByAlias { alias })
    }
    fn parse_recovery_request(payload: &Map) -> Result<Self, QueryJsonError> {
        let alias = payload
            .get("alias")
            .ok_or(QueryJsonError::MissingField("payload", "alias"))
            .and_then(|value| {
                json::from_value::<crate::account::AccountAlias>(value.clone())
                    .map_err(|_| QueryJsonError::InvalidField("payload", "alias"))
            })?;
        Ok(Self::FindAccountRecoveryRequestByAlias { alias })
    }
    fn parse_contract_manifest(payload: &Map) -> Result<Self, QueryJsonError> {
        let value = payload
            .get("artifact_id")
            .ok_or(QueryJsonError::MissingField("payload", "artifact_id"))?;
        let artifact_id = json::from_value(value.clone())
            .map_err(|_| QueryJsonError::InvalidField("payload", "artifact_id"))?;
        Ok(Self::FindContractManifestByArtifactId { artifact_id })
    }
    fn parse_fee_sponsor_program_by_id(payload: &Map) -> Result<Self, QueryJsonError> {
        Ok(Self::FindFeeSponsorProgramById {
            id: payload_required_string(payload, "id")?.to_owned(),
        })
    }
    fn parse_settlement_receipt_by_id(payload: &Map) -> Result<Self, QueryJsonError> {
        if payload.len() != 1 || !payload.contains_key("id") {
            return Err(QueryJsonError::InvalidField("payload", "id"));
        }
        let id = payload_required_string(payload, "id")?;
        id.parse::<crate::isi::SettlementId>()
            .map_err(|_| QueryJsonError::InvalidField("payload", "id"))?;
        Ok(Self::FindSettlementReceiptById { id: id.to_owned() })
    }
    fn parse_fx_corridor_policy_by_id(payload: &Map) -> Result<Self, QueryJsonError> {
        Ok(Self::FindFxCorridorPolicyById {
            policy_id: payload_required_string(payload, "policy_id")?.to_owned(),
        })
    }
    fn parse_asset_by_id(payload: &Map) -> Result<Self, QueryJsonError> {
        Ok(Self::FindAssetById {
            asset: payload_required_string(payload, "asset")?.to_owned(),
            account_id: payload_required_string(payload, "account_id")?.to_owned(),
            scope: payload.get("scope").cloned(),
        })
    }
    fn parse_asset_definition(payload: &Map) -> Result<Self, QueryJsonError> {
        Ok(Self::FindAssetDefinitionById {
            asset: payload_required_string(payload, "asset")?.to_owned(),
        })
    }
    fn parse_asset_definition_direct_home(payload: &Map) -> Result<Self, QueryJsonError> {
        Ok(Self::FindAssetDefinitionDirectHome {
            asset: payload_required_string(payload, "asset")?.to_owned(),
        })
    }
    fn parse_nft_by_id(payload: &Map) -> Result<Self, QueryJsonError> {
        Ok(Self::FindNftById {
            nft_id: payload_required_string(payload, "nft_id")?.to_owned(),
        })
    }
    fn parse_asset_escrow(payload: &Map) -> Result<Self, QueryJsonError> {
        let escrow_id = payload
            .get("escrow_id")
            .ok_or(QueryJsonError::MissingField("payload", "escrow_id"))
            .and_then(|value| {
                json::from_value::<crate::escrow::EscrowId>(value.clone())
                    .map_err(|_| QueryJsonError::InvalidField("payload", "escrow_id"))
            })?;
        Ok(Self::FindAssetEscrowById { escrow_id })
    }
    fn parse_trigger_by_id(payload: &Map) -> Result<Self, QueryJsonError> {
        Ok(Self::FindTriggerById {
            id: payload_required_string(payload, "id")?.to_owned(),
        })
    }
    fn parse_twitter_binding(payload: &Map) -> Result<Self, QueryJsonError> {
        let binding_hash_value = payload
            .get("binding_hash")
            .ok_or(QueryJsonError::MissingField("payload", "binding_hash"))?;
        let binding_hash = json::from_value::<crate::oracle::KeyedHash>(binding_hash_value.clone())
            .map_err(|_| QueryJsonError::InvalidField("payload", "binding_hash"))?;
        Ok(Self::FindTwitterBindingByHash { binding_hash })
    }
    fn parse_domain_by_id(payload: &Map) -> Result<Self, QueryJsonError> {
        Ok(Self::FindDomainById {
            domain_id: payload_required_string(payload, "domain_id")?.to_owned(),
        })
    }
    fn alias_payload(alias: &crate::account::AccountAlias) -> Map {
        let mut payload = Map::new();
        payload.insert(
            "alias".to_owned(),
            json::to_value(alias).expect("account alias serializes"),
        );
        payload
    }
    fn decode_account_id(account_id: &str) -> Result<crate::account::AccountId, QueryJsonError> {
        crate::account::AccountId::parse_encoded(account_id)
            .map_err(|_| QueryJsonError::InvalidField("payload", "account_id"))
    }
    fn decode_asset_definition_id(
        asset: &str,
    ) -> Result<crate::asset::AssetDefinitionId, QueryJsonError> {
        crate::asset::AssetDefinitionId::parse_address_literal(asset)
            .map_err(|_| QueryJsonError::InvalidField("payload", "asset"))
    }
    fn decode_asset_scope(
        scope: Option<Value>,
    ) -> Result<crate::asset::AssetBalanceScope, QueryJsonError> {
        scope
            .map(|value| {
                json::from_value::<crate::asset::AssetBalanceScope>(value)
                    .map_err(|_| QueryJsonError::InvalidField("payload", "scope"))
            })
            .transpose()
            .map(Option::unwrap_or_default)
    }
    fn decode_domain_id(
        domain_id: &str,
    ) -> Result<iroha_model_base::domain::DomainId, QueryJsonError> {
        iroha_model_base::domain::DomainId::parse_fully_qualified(domain_id)
            .map_err(|_| QueryJsonError::InvalidField("payload", "domain_id"))
    }
    fn decode_nft_id(nft_id: &str) -> Result<crate::nft::NftId, QueryJsonError> {
        nft_id
            .parse()
            .map_err(|_| QueryJsonError::InvalidField("payload", "nft_id"))
    }
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "type".to_owned(),
            Value::String(self.kind_label().to_owned()),
        );
        match self {
            Self::FindAccountById { account_id } => {
                let mut payload = Map::new();
                payload.insert("account_id".to_owned(), Value::String(account_id.clone()));
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            Self::FindAccountByAlias { alias }
            | Self::FindAccountRecoveryPolicyByAlias { alias }
            | Self::FindAccountRecoveryRequestByAlias { alias } => {
                map.insert(
                    "payload".to_owned(),
                    Value::Object(Self::alias_payload(alias)),
                );
            }
            Self::FindContractManifestByArtifactId { artifact_id } => {
                let mut payload = Map::new();
                payload.insert(
                    "artifact_id".to_owned(),
                    json::to_value(artifact_id).expect("fixed artifact identity serializes"),
                );
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            Self::FindAssetById {
                asset,
                account_id,
                scope,
            } => {
                let mut payload = Map::new();
                payload.insert("asset".to_owned(), Value::String(asset.clone()));
                payload.insert("account_id".to_owned(), Value::String(account_id.clone()));
                if let Some(scope) = scope {
                    payload.insert("scope".to_owned(), scope.clone());
                }
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            Self::FindAssetDefinitionById { asset }
            | Self::FindAssetDefinitionDirectHome { asset } => {
                let mut payload = Map::new();
                payload.insert("asset".to_owned(), Value::String(asset.clone()));
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            Self::FindNftById { nft_id } => {
                let mut payload = Map::new();
                payload.insert("nft_id".to_owned(), Value::String(nft_id.clone()));
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            Self::FindAssetEscrowById { escrow_id } => {
                let mut payload = Map::new();
                payload.insert(
                    "escrow_id".to_owned(),
                    json::to_value(escrow_id).expect("escrow id serializes"),
                );
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            Self::FindTriggerById { id }
            | Self::FindFeeSponsorProgramById { id }
            | Self::FindSettlementReceiptById { id } => {
                let mut payload = Map::new();
                payload.insert("id".to_owned(), Value::String(id.clone()));
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            Self::FindFxCorridorPolicyById { policy_id } => {
                let mut payload = Map::new();
                payload.insert("policy_id".to_owned(), Value::String(policy_id.clone()));
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            Self::FindAliasesByAccountId {
                account_id,
                dataspace,
                domain,
            } => {
                let mut payload = Map::new();
                payload.insert("account_id".to_owned(), Value::String(account_id.clone()));
                if let Some(dataspace) = dataspace {
                    payload.insert("dataspace".to_owned(), Value::String(dataspace.clone()));
                }
                if let Some(domain) = domain {
                    payload.insert("domain".to_owned(), Value::String(domain.clone()));
                }
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            Self::FindTwitterBindingByHash { binding_hash } => {
                let mut payload = Map::new();
                payload.insert(
                    "binding_hash".to_owned(),
                    json::to_value(binding_hash).expect("binding hash serializes"),
                );
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            Self::FindDomainById { domain_id } => {
                let mut payload = Map::new();
                payload.insert("domain_id".to_owned(), Value::String(domain_id.clone()));
                map.insert("payload".to_owned(), Value::Object(payload));
            }
            _ => {}
        }
        Value::Object(map)
    }
    fn from_value(value: &Value) -> Result<Self, QueryJsonError> {
        let map = value
            .as_object()
            .ok_or(QueryJsonError::ExpectedObject("singular"))?;
        let ty = map
            .get("type")
            .and_then(Value::as_str)
            .ok_or(QueryJsonError::MissingField("singular", "type"))?;
        match ty {
            "FindAbiVersion" => Ok(SingularQueryJson::FindAbiVersion),
            "FindExecutorDataModel" => Ok(SingularQueryJson::FindExecutorDataModel),
            "FindParameters" => Ok(SingularQueryJson::FindParameters),
            "FindAccountById" => Self::parse_account_by_id(singular_payload(map)?),
            "FindAccountByAlias" => Self::parse_account_by_alias(singular_payload(map)?),
            "FindAliasesByAccountId" => Self::parse_aliases(singular_payload(map)?),
            "FindAccountRecoveryPolicyByAlias" => {
                Self::parse_recovery_policy(singular_payload(map)?)
            }
            "FindAccountRecoveryRequestByAlias" => {
                Self::parse_recovery_request(singular_payload(map)?)
            }
            "FindContractManifestByArtifactId" => {
                Self::parse_contract_manifest(singular_payload(map)?)
            }
            "FindAssetById" => Self::parse_asset_by_id(singular_payload(map)?),
            "FindAssetDefinitionById" => Self::parse_asset_definition(singular_payload(map)?),
            "FindAssetDefinitionDirectHome" => {
                Self::parse_asset_definition_direct_home(singular_payload(map)?)
            }
            "FindNftById" => Self::parse_nft_by_id(singular_payload(map)?),
            "FindAssetEscrowById" => Self::parse_asset_escrow(singular_payload(map)?),
            "FindTriggerById" => Self::parse_trigger_by_id(singular_payload(map)?),
            "FindTwitterBindingByHash" => Self::parse_twitter_binding(singular_payload(map)?),
            "FindDomainById" => Self::parse_domain_by_id(singular_payload(map)?),
            "FindFeeSponsorProgramById" => {
                Self::parse_fee_sponsor_program_by_id(singular_payload(map)?)
            }
            "FindSettlementReceiptById" => {
                Self::parse_settlement_receipt_by_id(singular_payload(map)?)
            }
            "FindFxCorridorPolicyRegistry" => Ok(Self::FindFxCorridorPolicyRegistry),
            "FindFxCorridorPolicyById" => {
                Self::parse_fx_corridor_policy_by_id(singular_payload(map)?)
            }
            other => Err(QueryJsonError::UnknownSingularType(other.to_owned())),
        }
    }
    fn kind_label(&self) -> &'static str {
        match self {
            SingularQueryJson::FindAbiVersion => "FindAbiVersion",
            SingularQueryJson::FindExecutorDataModel => "FindExecutorDataModel",
            SingularQueryJson::FindParameters => "FindParameters",
            SingularQueryJson::FindAccountById { .. } => "FindAccountById",
            SingularQueryJson::FindAccountByAlias { .. } => "FindAccountByAlias",
            SingularQueryJson::FindAliasesByAccountId { .. } => "FindAliasesByAccountId",
            SingularQueryJson::FindAccountRecoveryPolicyByAlias { .. } => {
                "FindAccountRecoveryPolicyByAlias"
            }
            SingularQueryJson::FindAccountRecoveryRequestByAlias { .. } => {
                "FindAccountRecoveryRequestByAlias"
            }
            SingularQueryJson::FindAssetById { .. } => "FindAssetById",
            SingularQueryJson::FindAssetDefinitionById { .. } => "FindAssetDefinitionById",
            SingularQueryJson::FindAssetDefinitionDirectHome { .. } => {
                "FindAssetDefinitionDirectHome"
            }
            SingularQueryJson::FindNftById { .. } => "FindNftById",
            SingularQueryJson::FindAssetEscrowById { .. } => "FindAssetEscrowById",
            SingularQueryJson::FindTriggerById { .. } => "FindTriggerById",
            SingularQueryJson::FindContractManifestByArtifactId { .. } => {
                "FindContractManifestByArtifactId"
            }
            SingularQueryJson::FindTwitterBindingByHash { .. } => "FindTwitterBindingByHash",
            SingularQueryJson::FindDomainById { .. } => "FindDomainById",
            SingularQueryJson::FindFeeSponsorProgramById { .. } => "FindFeeSponsorProgramById",
            SingularQueryJson::FindSettlementReceiptById { .. } => "FindSettlementReceiptById",
            SingularQueryJson::FindFxCorridorPolicyRegistry => "FindFxCorridorPolicyRegistry",
            SingularQueryJson::FindFxCorridorPolicyById { .. } => "FindFxCorridorPolicyById",
        }
    }
    #[allow(clippy::too_many_lines)]
    fn into_box(self) -> Result<SingularQueryBox, QueryJsonError> {
        match self {
            SingularQueryJson::FindAbiVersion => Ok(SingularQueryBox::FindAbiVersion(
                crate::query::runtime::prelude::FindAbiVersion,
            )),
            SingularQueryJson::FindExecutorDataModel => {
                Ok(SingularQueryBox::FindExecutorDataModel(
                    crate::query::executor::prelude::FindExecutorDataModel,
                ))
            }
            SingularQueryJson::FindParameters => Ok(SingularQueryBox::FindParameters(
                crate::query::executor::prelude::FindParameters,
            )),
            SingularQueryJson::FindAccountById { account_id } => {
                let id = Self::decode_account_id(&account_id)?;
                Ok(SingularQueryBox::FindAccountById(
                    crate::query::account::prelude::FindAccountById::new(id),
                ))
            }
            SingularQueryJson::FindAccountByAlias { alias } => {
                Ok(SingularQueryBox::FindAccountByAlias(
                    crate::query::account::prelude::FindAccountByAlias::new(alias),
                ))
            }
            SingularQueryJson::FindAliasesByAccountId {
                account_id,
                dataspace,
                domain,
            } => {
                let id = Self::decode_account_id(&account_id)?;
                Ok(SingularQueryBox::FindAliasesByAccountId(
                    crate::query::account::prelude::FindAliasesByAccountId::new(
                        id, dataspace, domain,
                    ),
                ))
            }
            SingularQueryJson::FindAccountRecoveryPolicyByAlias { alias } => {
                Ok(SingularQueryBox::FindAccountRecoveryPolicyByAlias(
                    crate::query::account::prelude::FindAccountRecoveryPolicyByAlias::new(alias),
                ))
            }
            SingularQueryJson::FindAccountRecoveryRequestByAlias { alias } => {
                Ok(SingularQueryBox::FindAccountRecoveryRequestByAlias(
                    crate::query::account::prelude::FindAccountRecoveryRequestByAlias::new(alias),
                ))
            }
            SingularQueryJson::FindAssetById {
                asset,
                account_id,
                scope,
            } => {
                let definition = Self::decode_asset_definition_id(&asset)?;
                let account = Self::decode_account_id(&account_id)?;
                let scope = Self::decode_asset_scope(scope)?;
                Ok(SingularQueryBox::FindAssetById(
                    crate::query::asset::prelude::FindAssetById::new(
                        crate::asset::AssetId::with_scope(definition, account, scope),
                    ),
                ))
            }
            SingularQueryJson::FindAssetDefinitionById { asset } => {
                let id = Self::decode_asset_definition_id(&asset)?;
                Ok(SingularQueryBox::FindAssetDefinitionById(
                    crate::query::asset::prelude::FindAssetDefinitionById::new(id),
                ))
            }
            SingularQueryJson::FindAssetDefinitionDirectHome { asset } => {
                let id = Self::decode_asset_definition_id(&asset)?;
                Ok(SingularQueryBox::FindAssetDefinitionDirectHome(
                    crate::query::asset::prelude::FindAssetDefinitionDirectHome::new(id),
                ))
            }
            SingularQueryJson::FindNftById { nft_id } => {
                let id = Self::decode_nft_id(&nft_id)?;
                Ok(SingularQueryBox::FindNftById(
                    crate::query::nft::prelude::FindNftById::new(id),
                ))
            }
            SingularQueryJson::FindAssetEscrowById { escrow_id } => {
                Ok(SingularQueryBox::FindAssetEscrowById(
                    crate::query::escrow::prelude::FindAssetEscrowById::new(escrow_id),
                ))
            }
            SingularQueryJson::FindTriggerById { id } => {
                let id = id
                    .parse::<crate::trigger::TriggerId>()
                    .map_err(|_| QueryJsonError::InvalidField("payload", "id"))?;
                Ok(SingularQueryBox::FindTriggerById(
                    crate::query::trigger::prelude::FindTriggerById::new(id),
                ))
            }
            SingularQueryJson::FindContractManifestByArtifactId { artifact_id } => {
                Ok(SingularQueryBox::FindContractManifestByArtifactId(
                    crate::query::smart_contract::prelude::FindContractManifestByArtifactId {
                        artifact_id,
                    },
                ))
            }
            SingularQueryJson::FindTwitterBindingByHash { binding_hash } => {
                Ok(SingularQueryBox::FindTwitterBindingByHash(
                    crate::query::oracle::prelude::FindTwitterBindingByHash { binding_hash },
                ))
            }
            SingularQueryJson::FindDomainById { domain_id } => {
                let id = Self::decode_domain_id(&domain_id)?;
                Ok(SingularQueryBox::FindDomainById(
                    crate::query::domain::prelude::FindDomainById::new(id),
                ))
            }
            SingularQueryJson::FindFeeSponsorProgramById { id } => {
                let id = id
                    .parse::<crate::nexus::FeeSponsorProgramId>()
                    .map_err(|_| QueryJsonError::InvalidField("payload", "id"))?;
                Ok(SingularQueryBox::FindFeeSponsorProgramById(
                    crate::query::nexus::prelude::FindFeeSponsorProgramById::new(id),
                ))
            }
            SingularQueryJson::FindSettlementReceiptById { id } => {
                let id = id
                    .parse::<crate::isi::SettlementId>()
                    .map_err(|_| QueryJsonError::InvalidField("payload", "id"))?;
                Ok(SingularQueryBox::FindSettlementReceiptById(
                    crate::query::settlement::FindSettlementReceiptById::new(id),
                ))
            }
            SingularQueryJson::FindFxCorridorPolicyRegistry => {
                Ok(SingularQueryBox::FindFxCorridorPolicyRegistry(
                    crate::query::settlement::prelude::FindFxCorridorPolicyRegistry,
                ))
            }
            SingularQueryJson::FindFxCorridorPolicyById { policy_id } => {
                let policy_id = policy_id
                    .parse::<iroha_model_base::name::Name>()
                    .map_err(|_| QueryJsonError::InvalidField("payload", "policy_id"))?;
                Ok(SingularQueryBox::FindFxCorridorPolicyById(
                    crate::query::settlement::prelude::FindFxCorridorPolicyById::new(policy_id),
                ))
            }
        }
    }
}
/// Supported iterable queries for the JSON DSL.
#[derive(Debug, Clone, PartialEq)]
pub struct IterableQueryJson {
    /// Query selector describing which dataset to enumerate.
    pub kind: IterableQueryKind,
    /// Optional pagination and sorting controls.
    pub params: IterableQueryParamsJson,
    /// Optional predicate evaluated against each item.
    pub predicate: Option<PredicateJson>,
}
impl Eq for IterableQueryJson {}
impl IterableQueryJson {
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "type".to_owned(),
            Value::String(self.kind.as_str().to_owned()),
        );
        if !self.params.is_empty() {
            map.insert("params".to_owned(), self.params.to_value());
        }
        if let Some(pred) = &self.predicate {
            map.insert(
                "predicate".to_owned(),
                json::to_value(pred).expect("predicate serialize"),
            );
        }
        Value::Object(map)
    }
    fn from_value(value: &Value) -> Result<Self, QueryJsonError> {
        let map = value
            .as_object()
            .ok_or(QueryJsonError::ExpectedObject("iterable"))?;
        let mut kind: Option<IterableQueryKind> = None;
        let mut params: Option<IterableQueryParamsJson> = None;
        let mut predicate: Option<PredicateJson> = None;
        for (key, value) in map {
            match key.as_str() {
                "type" => {
                    let raw = value
                        .as_str()
                        .ok_or(QueryJsonError::InvalidField("iterable", "type"))?;
                    let parsed = IterableQueryKind::from_str(raw)
                        .map_err(|()| QueryJsonError::UnknownIterableType(raw.to_owned()))?;
                    kind = Some(parsed);
                }
                "params" => {
                    params = Some(IterableQueryParamsJson::from_value(value)?);
                }
                "predicate" => {
                    predicate =
                        Some(PredicateJson::try_from_value(value).map_err(QueryJsonError::from)?);
                }
                other => {
                    return Err(QueryJsonError::UnknownField {
                        section: "iterable",
                        field: other.to_owned(),
                    });
                }
            }
        }
        let kind = kind.ok_or(QueryJsonError::MissingField("iterable", "type"))?;
        let params = params.unwrap_or_default();
        Ok(IterableQueryJson {
            kind,
            params,
            predicate,
        })
    }
    fn predicate_or_pass<T: 'static>(&self) -> Result<CompoundPredicate<T>, QueryJsonError> {
        self.predicate.as_ref().map_or_else(
            || Ok(CompoundPredicate::PASS),
            |pred| {
                pred.into_compound::<T>()
                    .map_err(|err| QueryJsonError::PredicateEncode(err.to_string()))
            },
        )
    }
    fn build_for_kind<Item, Q, F>(
        &self,
        params: QueryParams,
        constructor: F,
    ) -> Result<QueryWithParams, QueryJsonError>
    where
        Item: HasProjection<PredicateMarker>
            + HasProjection<SelectorMarker, AtomType = ()>
            + Send
            + Sync
            + ItemKindTag
            + 'static,
        Q: crate::query::Query<Item = Item> + norito::codec::Encode,
        F: FnOnce() -> Q,
    {
        let predicate = self.predicate_or_pass::<Item>()?;
        Ok(build_query_with_params::<Item, Q, _>(
            &predicate,
            &SelectorTuple::default(),
            params,
            constructor,
        ))
    }
    #[allow(clippy::too_many_lines)]
    fn into_query_with_params(self) -> Result<QueryWithParams, QueryJsonError> {
        let params = self.params.clone().into_query_params()?;
        match self.kind {
            IterableQueryKind::FindPeers => {
                type Item = iroha_model_base::peer::PeerId;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::peer::prelude::FindPeers
                })
            }
            IterableQueryKind::FindDomains => {
                type Item = crate::domain::Domain;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::domain::prelude::FindDomains
                })
            }
            IterableQueryKind::FindAccounts => {
                type Item = crate::account::Account;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::account::prelude::FindAccounts
                })
            }
            IterableQueryKind::FindAccountIds => {
                type Item = crate::account::AccountId;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::account::prelude::FindAccountIds
                })
            }
            IterableQueryKind::FindTriggers => {
                type Item = crate::trigger::Trigger;
                self.build_for_kind::<Item, _, _>(params, || crate::query::trigger::FindTriggers)
            }
            IterableQueryKind::FindActiveTriggerIds => {
                type Item = crate::trigger::TriggerId;
                self.build_for_kind::<Item, _, _>(params, || {
                    crate::query::trigger::FindActiveTriggerIds
                })
            }
            IterableQueryKind::FindAssetDefinitions => {
                type Item = crate::asset::definition::AssetDefinition;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::asset::prelude::FindAssetDefinitions
                })
            }
            IterableQueryKind::FindAssetEscrows => {
                type Item = crate::escrow::AssetEscrowRecord;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::escrow::prelude::FindAssetEscrows
                })
            }
            IterableQueryKind::FindRepoAgreements => {
                type Item = crate::repo::RepoAgreement;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::repo::prelude::FindRepoAgreements
                })
            }
            IterableQueryKind::FindNfts => {
                type Item = crate::nft::Nft;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::nft::prelude::FindNfts
                })
            }
            IterableQueryKind::FindRwas => {
                type Item = crate::rwa::Rwa;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::rwa::prelude::FindRwas
                })
            }
            IterableQueryKind::FindRoles => {
                type Item = crate::role::Role;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::role::prelude::FindRoles
                })
            }
            IterableQueryKind::FindRoleIds => {
                type Item = crate::role::RoleId;
                self.build_for_kind::<Item, _, _>(params, || {
                    crate::query::role::prelude::FindRoleIds
                })
            }
            IterableQueryKind::FindFeeSponsorPrograms => {
                type Item = crate::nexus::FeeSponsorProgram;
                self.build_for_kind::<Item, _, _>(params.clone(), || {
                    crate::query::nexus::prelude::FindFeeSponsorPrograms
                })
            }
            IterableQueryKind::FindFeeSponsorProgramIds => {
                type Item = crate::nexus::FeeSponsorProgramId;
                self.build_for_kind::<Item, _, _>(params, || {
                    crate::query::nexus::prelude::FindFeeSponsorProgramIds
                })
            }
        }
    }
}
/// Iterable query kinds understood by the JSON DSL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IterableQueryKind {
    /// Enumerate registered peers.
    FindPeers,
    /// Enumerate domain records.
    FindDomains,
    /// Enumerate account records.
    FindAccounts,
    /// Enumerate account identifiers only.
    FindAccountIds,
    /// Enumerate trigger records.
    FindTriggers,
    /// Enumerate active trigger identifiers.
    FindActiveTriggerIds,
    /// Enumerate asset definitions.
    FindAssetDefinitions,
    /// Enumerate native asset escrows.
    FindAssetEscrows,
    /// Enumerate registered NFTs.
    FindNfts,
    /// Enumerate registered RWA lots.
    FindRwas,
    /// Enumerate defined roles.
    FindRoles,
    /// Enumerate role identifiers only.
    FindRoleIds,
    /// Enumerate repo agreements.
    FindRepoAgreements,
    /// Enumerate fee sponsor programs.
    FindFeeSponsorPrograms,
    /// Enumerate fee sponsor program identifiers.
    FindFeeSponsorProgramIds,
}
impl IterableQueryKind {
    fn as_str(self) -> &'static str {
        match self {
            IterableQueryKind::FindPeers => "FindPeers",
            IterableQueryKind::FindDomains => "FindDomains",
            IterableQueryKind::FindAccounts => "FindAccounts",
            IterableQueryKind::FindAccountIds => "FindAccountIds",
            IterableQueryKind::FindTriggers => "FindTriggers",
            IterableQueryKind::FindActiveTriggerIds => "FindActiveTriggerIds",
            IterableQueryKind::FindAssetDefinitions => "FindAssetDefinitions",
            IterableQueryKind::FindAssetEscrows => "FindAssetEscrows",
            IterableQueryKind::FindNfts => "FindNfts",
            IterableQueryKind::FindRwas => "FindRwas",
            IterableQueryKind::FindRoles => "FindRoles",
            IterableQueryKind::FindRoleIds => "FindRoleIds",
            IterableQueryKind::FindRepoAgreements => "FindRepoAgreements",
            IterableQueryKind::FindFeeSponsorPrograms => "FindFeeSponsorPrograms",
            IterableQueryKind::FindFeeSponsorProgramIds => "FindFeeSponsorProgramIds",
        }
    }
}
impl FromStr for IterableQueryKind {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "FindPeers" => Ok(IterableQueryKind::FindPeers),
            "FindDomains" => Ok(IterableQueryKind::FindDomains),
            "FindAccounts" => Ok(IterableQueryKind::FindAccounts),
            "FindAccountIds" => Ok(IterableQueryKind::FindAccountIds),
            "FindTriggers" => Ok(IterableQueryKind::FindTriggers),
            "FindActiveTriggerIds" => Ok(IterableQueryKind::FindActiveTriggerIds),
            "FindAssetDefinitions" => Ok(IterableQueryKind::FindAssetDefinitions),
            "FindAssetEscrows" => Ok(IterableQueryKind::FindAssetEscrows),
            "FindNfts" => Ok(IterableQueryKind::FindNfts),
            "FindRwas" => Ok(IterableQueryKind::FindRwas),
            "FindRoles" => Ok(IterableQueryKind::FindRoles),
            "FindRoleIds" => Ok(IterableQueryKind::FindRoleIds),
            "FindRepoAgreements" => Ok(IterableQueryKind::FindRepoAgreements),
            "FindFeeSponsorPrograms" => Ok(IterableQueryKind::FindFeeSponsorPrograms),
            "FindFeeSponsorProgramIds" => Ok(IterableQueryKind::FindFeeSponsorProgramIds),
            _ => Err(()),
        }
    }
}
/// Execution modifiers for iterable queries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IterableQueryParamsJson {
    /// Maximum number of records to return.
    pub limit: Option<u64>,
    /// Offset inside the full result set.
    pub offset: Option<u64>,
    /// Fetch-size hint used by the query executor.
    pub fetch_size: Option<u64>,
    /// Metadata key used for sorting (optional).
    pub sort_by_metadata_key: Option<String>,
    /// Sort direction applied when a metadata key is provided.
    pub order: Option<crate::query::parameters::SortOrder>,
}
impl IterableQueryParamsJson {
    fn is_empty(&self) -> bool {
        self.limit.is_none()
            && self.offset.is_none()
            && self.fetch_size.is_none()
            && self.sort_by_metadata_key.is_none()
            && self.order.is_none()
    }
    fn to_value(&self) -> Value {
        let mut map = Map::new();
        if let Some(limit) = self.limit {
            map.insert("limit".to_owned(), Value::from(limit));
        }
        if let Some(offset) = self.offset {
            map.insert("offset".to_owned(), Value::from(offset));
        }
        if let Some(fetch_size) = self.fetch_size {
            map.insert("fetch_size".to_owned(), Value::from(fetch_size));
        }
        if let Some(key) = &self.sort_by_metadata_key {
            map.insert(
                "sort_by_metadata_key".to_owned(),
                Value::String(key.clone()),
            );
        }
        if let Some(order) = &self.order {
            map.insert(
                "order".to_owned(),
                json::to_value(order).expect("SortOrder serializes"),
            );
        }
        Value::Object(map)
    }
    fn from_value(value: &Value) -> Result<Self, QueryJsonError> {
        let map = value
            .as_object()
            .ok_or(QueryJsonError::ExpectedObject("params"))?;
        let mut limit = None;
        let mut offset = None;
        let mut fetch_size = None;
        let mut sort_by_metadata_key = None;
        let mut order = None;
        for (key, value) in map {
            match key.as_str() {
                "limit" => limit = params_optional_u64(value, "limit")?,
                "offset" => offset = params_optional_u64(value, "offset")?,
                "fetch_size" => fetch_size = params_optional_u64(value, "fetch_size")?,
                "sort_by_metadata_key" => {
                    sort_by_metadata_key = params_optional_string(value, "sort_by_metadata_key")?;
                }
                "order" => {
                    order = Some(match value.as_str() {
                        Some("Asc") => crate::query::parameters::SortOrder::Asc,
                        Some("Desc") => crate::query::parameters::SortOrder::Desc,
                        Some(other) => {
                            return Err(QueryJsonError::InvalidSortOrder(other.to_owned()));
                        }
                        None => {
                            return Err(QueryJsonError::InvalidSortOrder(
                                value_type_name(value).to_owned(),
                            ));
                        }
                    });
                }
                other => {
                    return Err(QueryJsonError::UnknownField {
                        section: "params",
                        field: other.to_owned(),
                    });
                }
            }
        }
        Ok(Self {
            limit,
            offset,
            fetch_size,
            sort_by_metadata_key,
            order,
        })
    }
    fn into_query_params(self) -> Result<QueryParams, QueryJsonError> {
        let Self {
            limit,
            offset,
            fetch_size,
            sort_by_metadata_key,
            order,
        } = self;
        let limit = limit
            .map(|value| {
                NonZeroU64::new(value).ok_or(QueryJsonError::InvalidNonZero("limit", value))
            })
            .transpose()?;
        let offset = offset.unwrap_or(0);
        let pagination = Pagination::new(limit, offset);
        let fetch_size = fetch_size
            .map(|value| {
                NonZeroU64::new(value).ok_or(QueryJsonError::InvalidNonZero("fetch_size", value))
            })
            .transpose()?;
        if order.is_some() && sort_by_metadata_key.is_none() {
            Err(QueryJsonError::OrderWithoutSortKey)
        } else {
            let mut sorting = if let Some(key) = sort_by_metadata_key {
                let name = Name::from_str(&key)
                    .map_err(|_| QueryJsonError::InvalidMetadataKey(key.clone()))?;
                Sorting::by_metadata_key(name)
            } else {
                Sorting::default()
            };
            sorting.order = order;
            let fetch_size = FetchSize::new(fetch_size);
            Ok(QueryParams::new(pagination, sorting, fetch_size))
        }
    }
}
fn params_optional_u64(value: &Value, field: &'static str) -> Result<Option<u64>, QueryJsonError> {
    match value {
        Value::Null => Ok(None),
        _ => value
            .as_u64()
            .map(Some)
            .ok_or(QueryJsonError::InvalidField("params", field)),
    }
}
fn params_optional_string(
    value: &Value,
    field: &'static str,
) -> Result<Option<String>, QueryJsonError> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        _ => Err(QueryJsonError::InvalidField("params", field)),
    }
}
impl QueryEnvelopeJson {
    /// Convert the envelope into a raw [`QueryRequest`].
    ///
    /// Network identity, authority, creation time, lifetime, nonce, and signature belong to the
    /// online client boundary. Keeping those fields out of this JSON conversion prevents callers
    /// from accidentally signing replayable requests with fabricated defaults.
    ///
    /// # Errors
    /// Returns an error when the envelope payload cannot be converted into a query.
    pub fn into_request(self) -> Result<QueryRequest, QueryJsonError> {
        let request = match self {
            QueryEnvelopeJson::Singular(s) => QueryRequest::Singular(s.into_box()?),
            QueryEnvelopeJson::Iterable(i) => {
                let iterable = *i;
                QueryRequest::Start(iterable.into_query_with_params()?)
            }
        };
        Ok(request)
    }
}
/// Errors produced when parsing or converting JSON query envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum QueryJsonError {
    /// query envelope must contain either `singular` or `iterable`
    #[error("query envelope must contain either `singular` or `iterable`")]
    EmptyEnvelope,
    /// `singular` and `iterable` sections cannot be combined
    #[error("`singular` and `iterable` sections cannot be combined")]
    AmbiguousEnvelope,
    /// unknown envelope key `{0}`
    #[error("unknown envelope key `{0}`")]
    UnknownEnvelopeKey(String),
    /// expected object for `{0}` section
    #[error("expected object for `{0}` section")]
    ExpectedObject(&'static str),
    /// missing `{1}` field inside `{0}`
    #[error("missing `{1}` field inside `{0}`")]
    MissingField(&'static str, &'static str),
    /// unknown singular query `{0}`
    #[error("unknown singular query `{0}`")]
    UnknownSingularType(String),
    /// unknown iterable query `{0}`
    #[error("unknown iterable query `{0}`")]
    UnknownIterableType(String),
    /// unknown field `{field}` inside `{section}`
    #[error("unknown field `{field}` inside `{section}`")]
    UnknownField {
        /// Section containing the unknown field.
        section: &'static str,
        /// Name of the offending field.
        field: String,
    },
    /// invalid field `{1}` inside `{0}`
    #[error("invalid field `{1}` inside `{0}`")]
    InvalidField(&'static str, &'static str),
    /// invalid hexadecimal value for `{0}`
    #[error("invalid hexadecimal value for `{0}`")]
    InvalidHex(String),
    /// `{field}` must contain {expected} bytes (got {actual})
    #[error("`{field}` must contain {expected} bytes (got {actual})")]
    InvalidLength {
        /// Name of the offending field.
        field: String,
        /// Expected byte length for the field.
        expected: usize,
        /// Actual byte length that was provided.
        actual: usize,
    },
    /// predicate JSON parse error: {0}
    #[error("predicate JSON parse error: {0}")]
    PredicateParse(String),
    /// predicate encoding error: {0}
    #[error("predicate encoding error: {0}")]
    PredicateEncode(String),
    /// `{0}` must be non-zero (got {1})
    #[error("`{0}` must be non-zero (got {1})")]
    InvalidNonZero(&'static str, u64),
    /// sort order requires `sort_by_metadata_key`
    #[error("sort order requires `sort_by_metadata_key`")]
    OrderWithoutSortKey,
    /// invalid metadata key `{0}`
    #[error("invalid metadata key `{0}`")]
    InvalidMetadataKey(String),
    /// invalid sort order: {0}
    #[error("invalid sort order: {0}")]
    InvalidSortOrder(String),
}
impl From<PredicateParseError> for QueryJsonError {
    fn from(err: PredicateParseError) -> Self {
        QueryJsonError::PredicateParse(err.to_string())
    }
}
fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
impl IterableQueryJson {
    /// Build a raw [`QueryRequest`] from this JSON definition.
    ///
    /// # Errors
    /// Returns an error when pagination or predicate parameters are invalid.
    pub fn into_request(self) -> Result<QueryRequest, QueryJsonError> {
        Ok(QueryRequest::Start(self.into_query_with_params()?))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use std::num::NonZeroU64;
    #[test]
    fn singular_roundtrip() {
        let singular = SingularQueryJson::FindParameters;
        let envelope = QueryEnvelopeJson::Singular(singular.clone());
        let json = norito::json::to_json(&envelope).expect("serialize");
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let request = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        assert!(matches!(
            request,
            SingularQueryBox::FindParameters(crate::query::executor::prelude::FindParameters)
        ));
    }
    #[test]
    fn twitter_binding_query_roundtrip() {
        let binding_hash = crate::oracle::KeyedHash::new("pepper-social-v1", b"pepper", b"payload");
        let singular = SingularQueryJson::FindTwitterBindingByHash {
            binding_hash: binding_hash.clone(),
        };
        let envelope = QueryEnvelopeJson::Singular(singular.clone());
        let json = norito::json::to_json(&envelope).expect("serialize");
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let request = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        assert!(matches!(
            request,
            SingularQueryBox::FindTwitterBindingByHash(query)
                if query.binding_hash == binding_hash
        ));
    }
    #[test]
    fn nft_by_id_query_roundtrip() {
        let nft_id: crate::nft::NftId =
            "ticket$wonderland.universal".parse().expect("valid NFT id");
        let singular = SingularQueryJson::FindNftById {
            nft_id: nft_id.to_string(),
        };
        let envelope = QueryEnvelopeJson::Singular(singular.clone());
        let json = norito::json::to_json(&envelope).expect("serialize");
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let request = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        assert!(matches!(
            request,
            SingularQueryBox::FindNftById(query) if query.nft_id() == &nft_id
        ));
        let invalid = SingularQueryJson::FindNftById {
            nft_id: "missing-domain-separator".to_owned(),
        };
        let error = invalid
            .into_box()
            .expect_err("non-canonical NFT identifiers must be rejected");
        assert_eq!(error, QueryJsonError::InvalidField("payload", "nft_id"));
    }
    #[test]
    fn find_aliases_by_account_id_roundtrip_with_filters() {
        let keypair = KeyPair::try_from_seed(vec![0xAC; 32], Algorithm::Ed25519)
            .expect("fixture seed derives Ed25519 keypair");
        let account_id = crate::account::AccountId::new(keypair.public_key().clone());
        let account_query = SingularQueryJson::FindAccountById {
            account_id: account_id.to_string(),
        };
        let query = account_query.into_box().expect("account query into box");
        match query {
            SingularQueryBox::FindAccountById(q) => {
                assert_eq!(q.account_id(), &account_id);
            }
            other => panic!("unexpected query variant: {other:?}"),
        }
        let alias = crate::account::AccountAlias::domainless(
            "alice".parse().expect("alias label"),
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        );
        let singular = SingularQueryJson::FindAccountByAlias {
            alias: alias.clone(),
        };
        let envelope = QueryEnvelopeJson::Singular(singular.clone());
        let json = norito::json::to_json(&envelope).expect("serialize");
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let query = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        match query {
            SingularQueryBox::FindAccountByAlias(q) => {
                assert_eq!(q.alias(), &alias);
            }
            other => panic!("unexpected query variant: {other:?}"),
        }
        let singular = SingularQueryJson::FindAliasesByAccountId {
            account_id: account_id.to_string(),
            dataspace: Some("centralbank".to_owned()),
            domain: Some("banka".to_owned()),
        };
        let envelope = QueryEnvelopeJson::Singular(singular.clone());
        let json = norito::json::to_json(&envelope).expect("serialize");
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let query = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        match query {
            SingularQueryBox::FindAliasesByAccountId(q) => {
                assert_eq!(q.account_id(), &account_id);
                assert_eq!(q.dataspace(), Some("centralbank"));
                assert_eq!(q.domain(), Some("banka"));
            }
            other => panic!("unexpected query variant: {other:?}"),
        }
        let singular = SingularQueryJson::FindAccountRecoveryPolicyByAlias {
            alias: alias.clone(),
        };
        let envelope = QueryEnvelopeJson::Singular(singular.clone());
        let json = norito::json::to_json(&envelope).expect("serialize");
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let query = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        match query {
            SingularQueryBox::FindAccountRecoveryPolicyByAlias(q) => {
                assert_eq!(q.alias(), &alias);
            }
            other => panic!("unexpected query variant: {other:?}"),
        }
        let domain_id = iroha_model_base::domain::DomainId::try_new("wonderland", "universal")
            .expect("domain id");
        let singular = SingularQueryJson::FindDomainById {
            domain_id: domain_id.to_string(),
        };
        let envelope = QueryEnvelopeJson::Singular(singular.clone());
        let json = norito::json::to_json(&envelope).expect("serialize");
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let query = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        match query {
            SingularQueryBox::FindDomainById(q) => {
                assert_eq!(q.domain_id(), &domain_id);
            }
            other => panic!("unexpected query variant: {other:?}"),
        }
    }
    #[test]
    fn find_asset_queries_roundtrip_with_public_selectors() {
        let definition_id = crate::asset::AssetDefinitionId::derive_from_components(
            iroha_model_base::domain::DomainId::try_new("wonderland", "universal")
                .expect("valid domain id"),
            "rose"
                .parse::<iroha_model_base::name::Name>()
                .expect("valid asset name"),
        );
        let keypair = KeyPair::try_from_seed(vec![0xCD; 32], Algorithm::Ed25519)
            .expect("fixture seed derives Ed25519 keypair");
        let account_id = crate::account::AccountId::new(keypair.public_key().clone());
        let singular = SingularQueryJson::FindAssetById {
            asset: definition_id.to_string(),
            account_id: account_id.to_string(),
            scope: Some(
                norito::json::to_value(&crate::asset::AssetBalanceScope::Global)
                    .expect("serialize canonical global asset scope"),
            ),
        };
        let envelope = QueryEnvelopeJson::Singular(singular.clone());
        let json = norito::json::to_json(&envelope).expect("serialize");
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let query = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        match query {
            SingularQueryBox::FindAssetById(q) => {
                assert_eq!(q.asset_id().definition(), &definition_id);
                assert_eq!(q.asset_id().account(), &account_id);
                assert_eq!(
                    q.asset_id().scope(),
                    &crate::asset::AssetBalanceScope::Global
                );
            }
            other => panic!("unexpected query variant: {other:?}"),
        }
        let definition_query = SingularQueryJson::FindAssetDefinitionById {
            asset: definition_id.to_string(),
        };
        let query = definition_query
            .into_box()
            .expect("query conversion succeeds");
        match query {
            SingularQueryBox::FindAssetDefinitionById(q) => {
                assert_eq!(q.asset_definition_id(), &definition_id);
            }
            other => panic!("unexpected query variant: {other:?}"),
        }
        let home_query = SingularQueryJson::FindAssetDefinitionDirectHome {
            asset: definition_id.to_string(),
        };
        let envelope = QueryEnvelopeJson::Singular(home_query);
        let json = norito::json::to_json(&envelope).expect("serialize");
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let query = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        let SingularQueryBox::FindAssetDefinitionDirectHome(q) = &query else {
            panic!("unexpected query variant: {query:?}");
        };
        assert_eq!(q.asset_definition_id(), &definition_id);
        let frame = norito::codec::Encode::encode(&query);
        assert_eq!(
            <SingularQueryBox as norito::codec::Decode>::decode(&mut frame.as_slice())
                .expect("decode direct-home query"),
            query
        );
        let escrow_id = crate::escrow::EscrowId::new(iroha_crypto::Hash::new("escrow-json"));
        let escrow_query = SingularQueryJson::FindAssetEscrowById { escrow_id };
        let envelope = QueryEnvelopeJson::Singular(escrow_query.clone());
        let json = norito::json::to_json(&envelope).expect("serialize");
        let canonical_literal = norito::json::to_value(&escrow_id)
            .expect("serialize escrow id")
            .as_str()
            .expect("escrow id JSON is a string")
            .to_owned();
        assert!(json.contains(&format!(r#""escrow_id":"{canonical_literal}""#)));
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let query = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        match query {
            SingularQueryBox::FindAssetEscrowById(q) => {
                assert_eq!(q.escrow_id, escrow_id);
            }
            other => panic!("unexpected query variant: {other:?}"),
        }
        assert_eq!(
            IterableQueryKind::from_str("FindAssetEscrows"),
            Ok(IterableQueryKind::FindAssetEscrows)
        );
        let invalid = SingularQueryJson::FindAssetDefinitionById {
            asset: "prefix:2f17c72466f84a4bb8a8e24884fdcd2f".to_owned(),
        };
        let err = invalid
            .into_box()
            .expect_err("prefixed literal must be rejected");
        assert_eq!(err, QueryJsonError::InvalidField("payload", "asset"));
        let trigger_query = SingularQueryJson::FindTriggerById {
            id: "demo_trigger".to_owned(),
        };
        let query = trigger_query.into_box().expect("trigger query into box");
        match query {
            SingularQueryBox::FindTriggerById(q) => {
                assert_eq!(q.trigger_id().to_string(), "demo_trigger");
            }
            other => panic!("unexpected query variant: {other:?}"),
        }
    }
    #[test]
    fn escrow_query_json_rejects_noncanonical_id_shapes() {
        let escrow_id = crate::escrow::EscrowId::new(iroha_crypto::Hash::new("escrow-query-id"));
        let canonical_literal = norito::json::to_value(&escrow_id)
            .expect("serialize escrow id")
            .as_str()
            .expect("escrow id JSON is a string")
            .to_owned();
        let aliases = [
            Value::String(escrow_id.as_hash().to_string()),
            Value::String(canonical_literal.to_lowercase()),
            Value::Array(vec![Value::String(canonical_literal.clone())]),
            norito::json!({"Hash": (canonical_literal.clone())}),
            norito::json!({"hash": (canonical_literal.clone())}),
            norito::json!({"EscrowId": (canonical_literal.clone())}),
        ];
        let kind = "FindAssetEscrowById";
        let canonical = norito::json!({
            "singular": {
                "type": (kind),
                "payload": {"escrow_id": (canonical_literal.clone())}
            }
        });
        assert!(
            norito::json::from_value::<QueryEnvelopeJson>(canonical).is_ok(),
            "{kind} must accept one canonical checksummed hash literal"
        );
        for alias in &aliases {
            let envelope = norito::json!({
                "singular": {
                    "type": (kind),
                    "payload": {"escrow_id": (alias.clone())}
                }
            });
            assert!(
                norito::json::from_value::<QueryEnvelopeJson>(envelope).is_err(),
                "{kind} accepted noncanonical EscrowId JSON {alias:?}"
            );
        }
    }
    #[test]
    fn fee_sponsor_program_queries_roundtrip() {
        let keypair = KeyPair::try_from_seed(vec![0xEF; 32], Algorithm::Ed25519)
            .expect("fixture seed derives Ed25519 keypair");
        let sponsor = crate::account::AccountId::new(keypair.public_key().clone());
        let program_id = crate::nexus::FeeSponsorProgramId::new(
            sponsor.clone(),
            "retail_transfers"
                .parse::<iroha_model_base::name::Name>()
                .expect("valid program name"),
        );
        let singular = SingularQueryJson::FindFeeSponsorProgramById {
            id: program_id.to_string(),
        };
        let envelope = QueryEnvelopeJson::Singular(singular.clone());
        let json = norito::json::to_json(&envelope).expect("serialize");
        let parsed: QueryEnvelopeJson = norito::json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, envelope);
        let query = match parsed {
            QueryEnvelopeJson::Singular(s) => s.into_box().expect("into box"),
            _ => unreachable!(),
        };
        match query {
            SingularQueryBox::FindFeeSponsorProgramById(q) => {
                assert_eq!(q.id(), &program_id);
            }
            other => panic!("unexpected query variant: {other:?}"),
        }
        for kind in [
            IterableQueryKind::FindFeeSponsorPrograms,
            IterableQueryKind::FindFeeSponsorProgramIds,
        ] {
            let iterable = IterableQueryJson {
                kind,
                params: IterableQueryParamsJson {
                    limit: Some(5),
                    ..IterableQueryParamsJson::default()
                },
                predicate: None,
            };
            let envelope = QueryEnvelopeJson::Iterable(Box::new(iterable.clone()));
            let json = norito::json::to_json(&envelope).expect("serialize iterable");
            let parsed: QueryEnvelopeJson =
                norito::json::from_str(&json).expect("deserialize iterable");
            assert_eq!(parsed, envelope);
            let QueryEnvelopeJson::Iterable(parsed_iterable) = parsed else {
                unreachable!();
            };
            assert!(parsed_iterable.into_query_with_params().is_ok());
        }
        assert_eq!(
            IterableQueryKind::from_str("FindFeeSponsorPrograms"),
            Ok(IterableQueryKind::FindFeeSponsorPrograms)
        );
        assert_eq!(
            IterableQueryKind::from_str("FindFeeSponsorProgramIds"),
            Ok(IterableQueryKind::FindFeeSponsorProgramIds)
        );
        let invalid = SingularQueryJson::FindFeeSponsorProgramById {
            id: "missing-program-separator".to_owned(),
        };
        let err = invalid
            .into_box()
            .expect_err("invalid program id must be rejected");
        assert_eq!(err, QueryJsonError::InvalidField("payload", "id"));
    }
    #[test]
    fn iterable_json_builds_canonical_query_components() {
        let iterable = IterableQueryJson {
            kind: IterableQueryKind::FindAssetEscrows,
            params: IterableQueryParamsJson::default(),
            predicate: None,
        };
        let query = iterable
            .into_query_with_params()
            .expect("build canonical asset-escrow iterable query");
        assert_eq!(query.item, crate::query::QueryItemKind::AssetEscrowRecord);
        assert_eq!(
            query.query_payload,
            norito::codec::Encode::encode(&crate::query::escrow::prelude::FindAssetEscrows)
        );
        assert_eq!(
            query.predicate_bytes,
            norito::codec::Encode::encode(
                &CompoundPredicate::<crate::escrow::AssetEscrowRecord>::PASS,
            )
        );
        assert_eq!(
            query.selector_bytes,
            norito::codec::Encode::encode(
                &SelectorTuple::<crate::escrow::AssetEscrowRecord>::default(),
            )
        );
    }
    #[test]
    fn iterable_params_validation() {
        let value = norito::json!({
            "type": "FindDomains",
            "params": {
                "limit": 10,
                "offset": 5,
                "fetch_size": 50,
                "sort_by_metadata_key": "ui.order",
                "order": "Desc"
            }
        });
        let parsed = IterableQueryJson::from_value(&value).expect("parse");
        let params = parsed
            .clone()
            .params
            .into_query_params()
            .expect("build params");
        assert_eq!(params.pagination.offset_value(), 5);
        assert_eq!(
            params
                .pagination
                .limit_value()
                .map(NonZeroU64::get)
                .unwrap(),
            10
        );
        assert_eq!(
            params
                .sorting
                .sort_by_metadata_key
                .as_ref()
                .map(ToString::to_string)
                .unwrap(),
            "ui.order"
        );
        assert_eq!(
            params.fetch_size.fetch_size.map(NonZeroU64::get).unwrap(),
            50
        );
    }
    #[test]
    fn iterable_query_unknown_field_rejected() {
        let value = norito::json!({
            "type": "FindDomains",
            "extra": true
        });
        let err = IterableQueryJson::from_value(&value).expect_err("should reject unknown key");
        assert_eq!(
            err,
            QueryJsonError::UnknownField {
                section: "iterable",
                field: "extra".to_owned(),
            }
        );
    }
    #[test]
    fn iterable_params_unknown_field_rejected() {
        let value = norito::json!({
            "limit": 1,
            "foo": "bar"
        });
        let err =
            IterableQueryParamsJson::from_value(&value).expect_err("should reject unknown key");
        assert_eq!(
            err,
            QueryJsonError::UnknownField {
                section: "params",
                field: "foo".to_owned(),
            }
        );
    }
    #[test]
    fn iterable_params_absent_optional_fields_remain_optional() {
        let parsed = IterableQueryParamsJson::from_value(&norito::json!({}))
            .expect("empty params object should be accepted");
        assert_eq!(parsed, IterableQueryParamsJson::default());
    }
    #[test]
    fn iterable_params_null_optional_fields_equal_default() {
        let value = norito::json!({
            "limit": null,
            "offset": null,
            "fetch_size": null,
            "sort_by_metadata_key": null
        });
        let parsed = IterableQueryParamsJson::from_value(&value)
            .expect("null optional params should be accepted as absent");
        assert_eq!(parsed, IterableQueryParamsJson::default());
    }
    #[test]
    fn iterable_params_reject_present_invalid_optional_fields() {
        let invalid_values = [
            ("limit", Value::from(-1_i64)),
            ("limit", Value::from(1.5_f64)),
            ("limit", Value::from("ten")),
            ("offset", Value::from(-1_i64)),
            ("offset", Value::from(1.5_f64)),
            ("offset", Value::from(false)),
            ("fetch_size", Value::from(-1_i64)),
            ("fetch_size", Value::from(1.5_f64)),
            ("fetch_size", Value::from("fifty")),
            ("sort_by_metadata_key", Value::from(false)),
        ];
        for (field, value) in invalid_values {
            let mut map = Map::new();
            map.insert(field.to_owned(), value);
            let error = IterableQueryParamsJson::from_value(&Value::Object(map))
                .expect_err("present invalid optional field must be rejected");
            assert_eq!(error, QueryJsonError::InvalidField("params", field));
        }
    }
    #[test]
    fn unsupported_iterable_params_are_rejected_as_unknown() {
        for field in ["ids_projection", "lane_id", "dsid"] {
            for value in [
                Value::Null,
                Value::from(false),
                Value::from(1_u64),
                Value::from("0"),
            ] {
                let mut params = Map::new();
                params.insert(field.to_owned(), value);
                let json = norito::json!({
                    "type": "FindPeers",
                    "params": (Value::Object(params))
                });
                assert_eq!(
                    IterableQueryJson::from_value(&json),
                    Err(QueryJsonError::UnknownField {
                        section: "params",
                        field: field.to_owned(),
                    })
                );
            }
        }
    }
    #[test]
    fn asset_definition_query_has_one_canonical_name() {
        let json = norito::json!({"type": "FindAssetDefinitions"});
        let query = IterableQueryJson::from_value(&json).expect("canonical query name");
        assert_eq!(query.to_value(), json);
        let start = query
            .into_query_with_params()
            .expect("canonical query request");
        assert_eq!(
            start.parts().0,
            crate::query::QueryItemKind::AssetDefinition
        );
        assert_eq!(
            IterableQueryJson::from_value(&norito::json!({"type": "FindAssetsDefinitions"})),
            Err(QueryJsonError::UnknownIterableType(
                "FindAssetsDefinitions".to_owned()
            ))
        );
    }
    #[test]
    fn admitted_iterable_kinds_roundtrip_through_json_and_norito() {
        use crate::query::QueryItemKind;
        for (name, kind) in [
            ("FindPeers", QueryItemKind::PeerId),
            ("FindAccountIds", QueryItemKind::AccountId),
            ("FindTriggers", QueryItemKind::Trigger),
            ("FindActiveTriggerIds", QueryItemKind::TriggerId),
        ] {
            let source = norito::json!({"iterable": {"type": name}});
            let json = norito::json::to_json(&source).expect("query JSON");
            let envelope: QueryEnvelopeJson =
                norito::json::from_str(&json).expect("query envelope");
            assert_eq!(
                norito::json::to_value(&envelope).expect("JSON roundtrip"),
                source
            );
            let request = envelope.into_request().expect("admitted query kind");
            let frame = norito::encode_canonical(&request).expect("query wire frame");
            let QueryRequest::Start(start) =
                norito::decode_from_bytes(&frame).expect("query wire roundtrip")
            else {
                panic!("iterable envelope must produce a Start");
            };
            assert_eq!(start.parts().0, kind);
        }
    }
    #[test]
    fn iterable_requests_carry_the_empty_selector() {
        let json = norito::json!({"type": "FindPeers"});
        let start = IterableQueryJson::from_value(&json)
            .expect("parse")
            .into_query_with_params()
            .expect("build");
        let (_, _, selector, _) = start.parts();
        assert_eq!(
            selector,
            norito::codec::Encode::encode(
                &SelectorTuple::<iroha_model_base::peer::PeerId>::default()
            )
            .as_slice(),
            "selectors have exactly one wire layout"
        );
    }
}

#[cfg(test)]
mod settlement_receipt_query_tests {
    use super::*;

    #[test]
    fn settlement_receipt_query_json_is_exact_and_roundtrips() {
        let source = SingularQueryJson::FindSettlementReceiptById {
            id: "business_receipt".to_owned(),
        };
        let value = source.to_value();
        assert_eq!(
            SingularQueryJson::from_value(&value).expect("exact query"),
            source
        );
        let boxed = source.into_box().expect("typed query");
        let SingularQueryBox::FindSettlementReceiptById(query) = boxed else {
            panic!("exact variant");
        };
        assert_eq!(query.id.to_string(), "business_receipt");
        let frame = norito::encode_canonical(&query).expect("query frame");
        let decoded: crate::query::settlement::FindSettlementReceiptById =
            norito::decode_from_bytes(&frame).expect("typed query decode");
        assert_eq!(decoded, query);
    }

    #[test]
    fn settlement_receipt_query_json_rejects_unknown_missing_and_invalid_fields() {
        for payload in [
            norito::json!({}),
            norito::json!({"id": 7}),
            norito::json!({"id": ""}),
            norito::json!({"id": "bad receipt"}),
            norito::json!({"id": "business_receipt", "scope": 1}),
            norito::json!({"settlement_id": "business_receipt"}),
        ] {
            let value = norito::json!({"type": "FindSettlementReceiptById", "payload": payload});
            assert!(SingularQueryJson::from_value(&value).is_err());
        }
        assert!(SingularQueryJson::from_value(&norito::json!({"type": "FindSettlementReceipt", "payload": {"id": "business_receipt"}})).is_err());
    }
}
