//! Lightweight query helpers feeding the MOCHI state explorer views.
use crate::torii::{ToriiClient, ToriiError};
use iroha_data_model::{
    HasMetadata, Identifiable,
    account::{Account, AccountId},
    asset::{AssetId, definition::AssetDefinition, id::AssetDefinitionId, value::Asset},
    domain::Domain,
    query::{
        QueryItemKind, QueryOutput, QueryOutputBatchBox, QueryRequest, QueryWithParams,
        account::prelude::FindAccounts,
        asset::prelude::{FindAssetDefinitions, FindAssets},
        domain::prelude::FindDomains,
        dsl::{CompoundPredicate, SelectorTuple},
        parameters::{FetchSize, ForwardCursor, Pagination, QueryParams, Sorting},
        peer::prelude::FindPeers,
    },
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use norito::json;
use std::{
    num::NonZeroU64,
    panic::{AssertUnwindSafe, catch_unwind},
};
/// Set of iterable queries currently supported by the state explorer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateQueryKind {
    /// List registered accounts.
    Accounts,
    /// List holdings for all accounts.
    Assets,
    /// List asset definitions.
    AssetDefinitions,
    /// List domains.
    Domains,
    /// List registered peers participating in the network.
    Peers,
}
impl StateQueryKind {
    /// Human-readable label shown in the UI.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            StateQueryKind::Accounts => "Accounts",
            StateQueryKind::Assets => "Assets",
            StateQueryKind::AssetDefinitions => "Asset definitions",
            StateQueryKind::Domains => "Domains",
            StateQueryKind::Peers => "Peers",
        }
    }
    /// Enumerate all query kinds (used by UI selectors).
    #[must_use]
    pub fn all() -> [StateQueryKind; 5] {
        [
            StateQueryKind::Accounts,
            StateQueryKind::Assets,
            StateQueryKind::AssetDefinitions,
            StateQueryKind::Domains,
            StateQueryKind::Peers,
        ]
    }
    fn build_request(self, fetch_size: Option<NonZeroU64>) -> QueryRequest {
        let params = QueryParams::new(
            Pagination::default(),
            Sorting::default(),
            FetchSize::new(fetch_size),
        );
        let query = match self {
            StateQueryKind::Accounts => QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindAccounts),
                item: QueryItemKind::Account,
                predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Account>::PASS),
                selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Account>::default()),
                params,
            },
            StateQueryKind::Assets => QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindAssets),
                item: QueryItemKind::Asset,
                predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Asset>::PASS),
                selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Asset>::default()),
                params,
            },
            StateQueryKind::AssetDefinitions => QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindAssetDefinitions),
                item: QueryItemKind::AssetDefinition,
                predicate_bytes: norito::codec::Encode::encode(
                    &CompoundPredicate::<AssetDefinition>::PASS,
                ),
                selector_bytes: norito::codec::Encode::encode(
                    &SelectorTuple::<AssetDefinition>::default(),
                ),
                params,
            },
            StateQueryKind::Domains => QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindDomains),
                item: QueryItemKind::Domain,
                predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Domain>::PASS),
                selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Domain>::default()),
                params,
            },
            StateQueryKind::Peers => QueryWithParams {
                query: (),
                query_payload: norito::codec::Encode::encode(&FindPeers),
                item: QueryItemKind::PeerId,
                predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<PeerId>::PASS),
                selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<PeerId>::default()),
                params,
            },
        };
        QueryRequest::Start(query)
    }
}
/// Resulting entries from a state explorer page.
#[derive(Debug, Clone)]
pub struct StateEntry {
    /// Primary identifier, e.g., account id.
    pub title: String,
    /// Short secondary line (owner, signatory, etc.).
    pub subtitle: String,
    /// Additional detail summarising metadata or numeric fields.
    pub detail: String,
    /// Full debug representation for inspection panels.
    pub raw: String,
    /// Owning domain (if applicable).
    pub domain: Option<String>,
    /// Lowercased domain cache for filtering.
    pub domain_lower: Option<String>,
    /// Owning account or authority (if applicable).
    pub owner: Option<String>,
    /// Lowercased owner cache for filtering.
    pub owner_lower: Option<String>,
    /// Asset definition identifier (if applicable).
    pub asset_definition: Option<String>,
    /// Lowercased asset definition cache.
    pub asset_definition_lower: Option<String>,
    /// Pretty-printed Norito JSON payload.
    pub json: Option<String>,
    /// Norito-encoded bytes of the entry payload.
    pub norito_bytes: Option<Vec<u8>>,
    /// Lowercased blob used by UI-side search filters.
    pub search_blob: String,
}
impl StateEntry {
    fn from_account(account: Account) -> Self {
        let account_id = account.id().clone();
        let title = account_id.to_string();
        let (subtitle, owner) = match account.try_signatory() {
            Some(signatory) => {
                let signatory = signatory.to_string();
                (format!("Signatory {signatory}"), signatory)
            }
            None => ("Multisig controller".to_owned(), account_id.to_string()),
        };
        let detail = metadata_summary(account.metadata());
        let summary_json = build_summary_json(&title, &subtitle, &detail, None, Some(&owner), None);
        let (json, norito_bytes) = encode_payload(&account);
        let json = Some(json.unwrap_or(summary_json));
        let search_blob = build_search_blob(&[&title, &subtitle, &detail, &owner]);
        let raw = format!("{account:#?}");
        Self {
            title,
            subtitle,
            detail,
            raw,
            domain: None,
            domain_lower: None,
            owner: Some(owner.clone()),
            owner_lower: Some(owner.to_ascii_lowercase()),
            asset_definition: None,
            asset_definition_lower: None,
            json,
            norito_bytes,
            search_blob,
        }
    }
    fn from_account_id(id: AccountId) -> Self {
        let subtitle = "Account identifier".to_owned();
        let detail = "Identifier projection".to_owned();
        let title = id.to_string();
        let json_summary = build_summary_json(&title, &subtitle, &detail, None, None, None);
        let (json, norito_bytes) = encode_payload(&id);
        let search_blob = build_search_blob(&[&title, &subtitle, &detail]);
        let raw = format!("{id:#?}");
        Self {
            title,
            subtitle,
            detail,
            raw,
            domain: None,
            domain_lower: None,
            owner: None,
            owner_lower: None,
            asset_definition: None,
            asset_definition_lower: None,
            json: Some(json.unwrap_or(json_summary)),
            norito_bytes,
            search_blob,
        }
    }
    fn from_asset(asset: Asset) -> Self {
        let asset_id = asset.id().clone();
        let owner = asset_id.account().clone();
        let owner_str = owner.to_string();
        let owner_lower = owner_str.to_ascii_lowercase();
        let domain: Option<String> = None;
        let domain_lower = domain.as_ref().map(|value| value.to_ascii_lowercase());
        let definition = asset_id.definition().to_string();
        let definition_lower = definition.to_ascii_lowercase();
        let title = asset_id.to_string();
        let subtitle = format!("Owner {owner_str}");
        let detail = format!("Value {}", asset.value());
        let summary_json = build_summary_json(
            &title,
            &subtitle,
            &detail,
            domain.as_deref(),
            Some(&owner_str),
            Some(&definition),
        );
        let (json, norito_bytes) = encode_payload(&asset);
        let json = Some(json.unwrap_or(summary_json));
        let mut search_parts = vec![
            title.as_str(),
            subtitle.as_str(),
            detail.as_str(),
            owner_str.as_str(),
            definition.as_str(),
        ];
        if let Some(domain) = domain.as_deref() {
            search_parts.push(domain);
        }
        let search_blob = build_search_blob(&search_parts);
        let raw = format!("{asset:#?}");
        Self {
            title,
            subtitle,
            detail,
            raw,
            domain,
            domain_lower,
            owner: Some(owner_str),
            owner_lower: Some(owner_lower),
            asset_definition: Some(definition),
            asset_definition_lower: Some(definition_lower),
            json,
            norito_bytes,
            search_blob,
        }
    }
    fn from_asset_id(asset_id: AssetId) -> Self {
        let owner = asset_id.account().clone();
        let owner_str = owner.to_string();
        let owner_lower = owner_str.to_ascii_lowercase();
        let domain: Option<String> = None;
        let domain_lower = domain.as_ref().map(|value| value.to_ascii_lowercase());
        let definition = asset_id.definition().to_string();
        let definition_lower = definition.to_ascii_lowercase();
        let (json, norito_bytes) = encode_payload(&asset_id);
        let title = asset_id.to_string();
        let detail = "Identifier projection".to_owned();
        let subtitle = format!("Owner {owner_str}");
        let mut search_parts = vec![
            title.as_str(),
            subtitle.as_str(),
            detail.as_str(),
            owner_str.as_str(),
            definition.as_str(),
            json.as_deref().unwrap_or_default(),
        ];
        if let Some(domain) = domain.as_deref() {
            search_parts.push(domain);
        }
        let search_blob = build_search_blob(&search_parts);
        let raw = format!("{asset_id:#?}");
        Self {
            title,
            subtitle,
            detail,
            raw,
            domain,
            domain_lower,
            owner: Some(owner_str),
            owner_lower: Some(owner_lower),
            asset_definition: Some(definition),
            asset_definition_lower: Some(definition_lower),
            json,
            norito_bytes,
            search_blob,
        }
    }
    fn from_asset_definition(definition: AssetDefinition) -> Self {
        let definition_id = definition.id().clone();
        let domain = asset_definition_domain_hint(definition.owning_domain().as_ref());
        let domain_lower = domain.as_ref().map(|value| value.to_ascii_lowercase());
        let owner = definition.owned_by().to_string();
        let owner_lower = owner.to_ascii_lowercase();
        let title = definition_id.to_string();
        let title_lower = title.to_ascii_lowercase();
        let definition_string = title.clone();
        let subtitle = format!("Owner {owner}");
        let detail = metadata_summary(definition.metadata());
        let summary_json = build_summary_json(
            &title,
            &subtitle,
            &detail,
            domain.as_deref(),
            Some(&owner),
            Some(&definition_string),
        );
        let (json, norito_bytes) = encode_payload(&definition);
        let json = Some(json.unwrap_or(summary_json));
        let mut search_parts = vec![
            title.as_str(),
            subtitle.as_str(),
            detail.as_str(),
            owner.as_str(),
        ];
        if let Some(domain) = domain.as_deref() {
            search_parts.push(domain);
        }
        let search_blob = build_search_blob(&search_parts);
        let raw = format!("{definition:#?}");
        Self {
            title,
            subtitle,
            detail,
            raw,
            domain,
            domain_lower,
            owner: Some(owner),
            owner_lower: Some(owner_lower),
            asset_definition: Some(definition_string),
            asset_definition_lower: Some(title_lower),
            json,
            norito_bytes,
            search_blob,
        }
    }
    fn from_asset_definition_id(id: AssetDefinitionId) -> Self {
        let domain: Option<String> = None;
        let domain_lower = domain.as_ref().map(|value| value.to_ascii_lowercase());
        let definition = id.to_string();
        let definition_lower = definition.to_ascii_lowercase();
        let title = definition.clone();
        let (json, norito_bytes) = encode_payload(&id);
        let subtitle = "Asset definition identifier".to_owned();
        let detail = "Identifier projection".to_owned();
        let mut search_parts = vec![
            title.as_str(),
            subtitle.as_str(),
            detail.as_str(),
            json.as_deref().unwrap_or_default(),
        ];
        if let Some(domain) = domain.as_deref() {
            search_parts.push(domain);
        }
        let search_blob = build_search_blob(&search_parts);
        let raw = format!("{id:#?}");
        Self {
            title,
            subtitle,
            detail,
            raw,
            domain,
            domain_lower,
            owner: None,
            owner_lower: None,
            asset_definition: Some(definition),
            asset_definition_lower: Some(definition_lower),
            json,
            norito_bytes,
            search_blob,
        }
    }
    fn from_domain(domain: Domain) -> Self {
        let domain_id = domain.id().clone();
        let title = domain_id.to_string();
        let domain_lower = title.to_ascii_lowercase();
        let domain_string = title.clone();
        let owner = domain.owned_by().to_string();
        let owner_lower = owner.to_ascii_lowercase();
        let subtitle = format!("Owner {owner}");
        let detail = metadata_summary(domain.metadata());
        let summary_json = build_summary_json(
            &title,
            &subtitle,
            &detail,
            Some(&domain_string),
            Some(&owner),
            None,
        );
        let (json, norito_bytes) = encode_payload(&domain);
        let json = Some(json.unwrap_or(summary_json));
        let search_blob = build_search_blob(&[&title, &subtitle, &detail, &owner]);
        let raw = format!("{domain:#?}");
        Self {
            title,
            subtitle,
            detail,
            raw,
            domain: Some(domain_string),
            domain_lower: Some(domain_lower),
            owner: Some(owner),
            owner_lower: Some(owner_lower),
            asset_definition: None,
            asset_definition_lower: None,
            json,
            norito_bytes,
            search_blob,
        }
    }
    fn from_domain_id(id: DomainId) -> Self {
        let title = id.to_string();
        let domain_lower = title.to_ascii_lowercase();
        let domain_string = title.clone();
        let (json, norito_bytes) = encode_payload(&id);
        let subtitle = "Domain identifier".to_owned();
        let detail = "Identifier projection".to_owned();
        let search_blob = build_search_blob(&[
            &title,
            &subtitle,
            &detail,
            json.as_deref().unwrap_or_default(),
        ]);
        let raw = format!("{id:#?}");
        Self {
            title,
            subtitle,
            detail,
            raw,
            domain: Some(domain_string),
            domain_lower: Some(domain_lower),
            owner: None,
            owner_lower: None,
            asset_definition: None,
            asset_definition_lower: None,
            json,
            norito_bytes,
            search_blob,
        }
    }
    fn from_peer_id(peer_id: PeerId) -> Self {
        let title = peer_id.to_string();
        let subtitle = "Peer public key".to_owned();
        let detail = "Registered peer identifier".to_owned();
        let summary_json = build_summary_json(&title, &subtitle, &detail, None, None, None);
        let (json, norito_bytes) = encode_payload(&peer_id);
        let json = Some(json.unwrap_or(summary_json));
        let search_blob = build_search_blob(&[&title, &subtitle, &detail]);
        let raw = format!("{peer_id:#?}");
        Self {
            title,
            subtitle,
            detail,
            raw,
            domain: None,
            domain_lower: None,
            owner: None,
            owner_lower: None,
            asset_definition: None,
            asset_definition_lower: None,
            json,
            norito_bytes,
            search_blob,
        }
    }
}
fn metadata_summary(metadata: &Metadata) -> String {
    if metadata.is_empty() {
        "No metadata entries".to_owned()
    } else {
        let keys = metadata
            .iter()
            .map(|(name, _)| name.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        format!("Metadata keys: {keys}")
    }
}
fn asset_definition_domain_hint(owning_domain: Option<&DomainId>) -> Option<String> {
    owning_domain.map(ToString::to_string)
}
fn encode_payload<T>(value: &T) -> (Option<String>, Option<Vec<u8>>)
where
    T: json::JsonSerialize + norito::NoritoSerialize,
{
    let pretty = catch_unwind(AssertUnwindSafe(|| json::to_json_pretty(value)))
        .ok()
        .and_then(Result::ok);
    let bytes = catch_unwind(AssertUnwindSafe(|| norito::to_bytes(value)))
        .ok()
        .and_then(Result::ok);
    (pretty, bytes)
}
fn build_summary_json(
    title: &str,
    subtitle: &str,
    detail: &str,
    domain: Option<&str>,
    owner: Option<&str>,
    asset_definition: Option<&str>,
) -> String {
    let mut map = json::Map::new();
    map.insert("title".into(), json::Value::String(title.to_owned()));
    map.insert("subtitle".into(), json::Value::String(subtitle.to_owned()));
    map.insert("detail".into(), json::Value::String(detail.to_owned()));
    if let Some(domain) = domain {
        map.insert("domain".into(), json::Value::String(domain.to_owned()));
    }
    if let Some(owner) = owner {
        map.insert("owner".into(), json::Value::String(owner.to_owned()));
    }
    if let Some(asset_definition) = asset_definition {
        map.insert(
            "asset_definition".into(),
            json::Value::String(asset_definition.to_owned()),
        );
    }
    let value = json::Value::Object(map);
    json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_owned())
}
fn build_search_blob(parts: &[&str]) -> String {
    let mut blob = String::new();
    for part in parts {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !blob.is_empty() {
            blob.push(' ');
        }
        blob.push_str(&trimmed.to_ascii_lowercase());
    }
    blob
}
/// Cursor handle returned alongside paginated state responses.
#[derive(Debug, Clone)]
pub struct StateCursor {
    inner: ForwardCursor,
}
impl StateCursor {
    pub(crate) fn clone_inner(&self) -> ForwardCursor {
        self.inner.clone()
    }
}
impl From<ForwardCursor> for StateCursor {
    fn from(inner: ForwardCursor) -> Self {
        Self { inner }
    }
}
/// Materialised page of explorer entries.
#[derive(Debug, Clone)]
pub struct StatePage {
    /// Query this page corresponds to.
    pub kind: StateQueryKind,
    /// Entries rendered in the UI.
    pub entries: Vec<StateEntry>,
    /// Remaining number of items on the server.
    pub remaining: u64,
    /// Cursor for requesting the next batch, if available.
    pub cursor: Option<StateCursor>,
}
/// Errors surfaced while preparing state explorer data.
#[derive(Debug, thiserror::Error)]
pub enum StateQueryError {
    /// HTTP or decoding failure while talking to Torii.
    #[error(transparent)]
    Torii(#[from] ToriiError),
    /// The peer returned a batch variant that does not match the requested query.
    #[error("query {kind:?} returned unsupported batch `{actual}`")]
    UnexpectedBatch {
        /// Requested query kind.
        kind: StateQueryKind,
        /// Batch variant label.
        actual: &'static str,
    },
}
/// Execute one page of a state explorer query.
///
/// Each invocation either starts a new query (`cursor == None`) or resumes an
/// existing cursor. Successful responses provide a [`StatePage`] with optional
/// cursor for further pagination.
pub async fn run_state_query(
    client: ToriiClient,
    signer: &crate::SigningAuthority,
    address_discriminant: u16,
    kind: StateQueryKind,
    cursor: Option<StateCursor>,
    fetch_size: Option<NonZeroU64>,
) -> Result<StatePage, StateQueryError> {
    let request = if let Some(cursor) = cursor {
        QueryRequest::Continue(cursor.clone_inner())
    } else {
        kind.build_request(fetch_size)
    };
    let signed = client.sign_query(request, signer.account_id().clone(), signer.key_pair())?;
    let output = client.execute_query(&signed).await?;
    // A thread-local display profile must never be held across an await.
    let _profile =
        iroha_data_model::account::address::ChainDiscriminantGuard::enter(address_discriminant);
    parse_iterable_output(kind, output)
}
fn parse_iterable_output(
    kind: StateQueryKind,
    output: QueryOutput,
) -> Result<StatePage, StateQueryError> {
    let (batch_tuple, remaining, cursor) = output.into_parts();
    let mut entries = Vec::new();
    for batch in batch_tuple.into_iter() {
        match (kind, batch) {
            (StateQueryKind::Accounts, QueryOutputBatchBox::Account(items)) => {
                entries.extend(items.into_iter().map(StateEntry::from_account));
            }
            (StateQueryKind::Accounts, QueryOutputBatchBox::AccountId(items)) => {
                entries.extend(items.into_iter().map(StateEntry::from_account_id));
            }
            (StateQueryKind::Assets, QueryOutputBatchBox::Asset(items)) => {
                entries.extend(items.into_iter().map(StateEntry::from_asset));
            }
            (StateQueryKind::Assets, QueryOutputBatchBox::AssetId(items)) => {
                entries.extend(items.into_iter().map(StateEntry::from_asset_id));
            }
            (StateQueryKind::AssetDefinitions, QueryOutputBatchBox::AssetDefinition(items)) => {
                entries.extend(items.into_iter().map(StateEntry::from_asset_definition));
            }
            (StateQueryKind::AssetDefinitions, QueryOutputBatchBox::AssetDefinitionId(items)) => {
                entries.extend(items.into_iter().map(StateEntry::from_asset_definition_id));
            }
            (StateQueryKind::Domains, QueryOutputBatchBox::Domain(items)) => {
                entries.extend(items.into_iter().map(StateEntry::from_domain));
            }
            (StateQueryKind::Domains, QueryOutputBatchBox::DomainId(items)) => {
                entries.extend(items.into_iter().map(StateEntry::from_domain_id));
            }
            (StateQueryKind::Peers, QueryOutputBatchBox::Peer(items)) => {
                entries.extend(items.into_iter().map(StateEntry::from_peer_id));
            }
            (_, other) => {
                return Err(StateQueryError::UnexpectedBatch {
                    kind,
                    actual: batch_label(&other),
                });
            }
        }
    }
    Ok(StatePage {
        kind,
        entries,
        remaining,
        cursor: cursor.map(StateCursor::from),
    })
}
fn batch_label(batch: &QueryOutputBatchBox) -> &'static str {
    match batch {
        QueryOutputBatchBox::Account(_) => "Account",
        QueryOutputBatchBox::AccountId(_) => "AccountId",
        QueryOutputBatchBox::Asset(_) => "Asset",
        QueryOutputBatchBox::AssetDefinition(_) => "AssetDefinition",
        QueryOutputBatchBox::Domain(_) => "Domain",
        QueryOutputBatchBox::PublicKey(_) => "PublicKey",
        QueryOutputBatchBox::String(_) => "String",
        QueryOutputBatchBox::Metadata(_) => "Metadata",
        QueryOutputBatchBox::Json(_) => "Json",
        QueryOutputBatchBox::Numeric(_) => "Numeric",
        QueryOutputBatchBox::Name(_) => "Name",
        QueryOutputBatchBox::DomainId(_) => "DomainId",
        QueryOutputBatchBox::AssetId(_) => "AssetId",
        QueryOutputBatchBox::AssetDefinitionId(_) => "AssetDefinitionId",
        QueryOutputBatchBox::RepoAgreement(_) => "RepoAgreement",
        QueryOutputBatchBox::NftId(_) => "NftId",
        QueryOutputBatchBox::Nft(_) => "Nft",
        QueryOutputBatchBox::RwaId(_) => "RwaId",
        QueryOutputBatchBox::Rwa(_) => "Rwa",
        QueryOutputBatchBox::Role(_) => "Role",
        QueryOutputBatchBox::Parameter(_) => "Parameter",
        QueryOutputBatchBox::Permission(_) => "Permission",
        QueryOutputBatchBox::CommittedTransaction(_) => "CommittedTransaction",
        QueryOutputBatchBox::TransactionResult(_) => "TransactionResult",
        QueryOutputBatchBox::TransactionResultHash(_) => "TransactionResultHash",
        QueryOutputBatchBox::TransactionEntrypoint(_) => "TransactionEntrypoint",
        QueryOutputBatchBox::TransactionEntrypointHash(_) => "TransactionEntrypointHash",
        QueryOutputBatchBox::Peer(_) => "Peer",
        QueryOutputBatchBox::RoleId(_) => "RoleId",
        QueryOutputBatchBox::TriggerId(_) => "TriggerId",
        QueryOutputBatchBox::Trigger(_) => "Trigger",
        QueryOutputBatchBox::Action(_) => "Action",
        QueryOutputBatchBox::Block(_) => "Block",
        QueryOutputBatchBox::BlockHeader(_) => "BlockHeader",
        QueryOutputBatchBox::BlockHeaderHash(_) => "BlockHeaderHash",
        QueryOutputBatchBox::ProofRecord(_) => "ProofRecord",
        QueryOutputBatchBox::OracleFeedConfig(_) => "OracleFeedConfig",
        QueryOutputBatchBox::OracleFeedEventRecord(_) => "OracleFeedEventRecord",
        QueryOutputBatchBox::OracleProviderStatsRecord(_) => "OracleProviderStatsRecord",
        QueryOutputBatchBox::OracleDispute(_) => "OracleDispute",
        QueryOutputBatchBox::OracleChangeProposal(_) => "OracleChangeProposal",
        QueryOutputBatchBox::TwitterBindingRecord(_) => "TwitterBindingRecord",
        QueryOutputBatchBox::DefiOracleAttestation(_) => "DefiOracleAttestation",
        QueryOutputBatchBox::AssetEscrowRecord(_) => "AssetEscrowRecord",
        QueryOutputBatchBox::FeeSponsorProgram(_) => "FeeSponsorProgram",
        QueryOutputBatchBox::FeeSponsorProgramId(_) => "FeeSponsorProgramId",
        QueryOutputBatchBox::BondRecord(_) => "BondRecord",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::{Method::POST, MockServer};
    use iroha_data_model::{
        Registrable,
        account::Account as AccountBuilder,
        asset::{
            definition::AssetDefinition,
            id::{AssetDefinitionId, AssetId},
            value::Asset,
        },
        domain::Domain,
        query::{QueryOutputBatchBox, QueryOutputBatchBoxTuple, QueryRequest},
    };
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::{NumericSpec, Quantity};
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
    use norito::{json, to_bytes};
    fn try_start_mock_server() -> Option<MockServer> {
        std::panic::catch_unwind(MockServer::start)
            .ok()
            .or_else(|| {
                eprintln!(
                    "Skipping test: unable to bind mock HTTP server in sandboxed environment."
                );
                None
            })
    }
    #[test]
    fn build_request_uses_start_variant() {
        for kind in StateQueryKind::all() {
            let request = kind.build_request(None);
            assert!(
                matches!(request, QueryRequest::Start(_)),
                "expected QueryRequest::Start for {kind:?}"
            );
        }
    }
    #[test]
    fn build_request_encodes_canonical_domain_components() {
        let QueryRequest::Start(query) = StateQueryKind::Domains.build_request(None) else {
            panic!("domain state query must use the iterable start variant");
        };
        assert_eq!(query.item, QueryItemKind::Domain);
        assert_eq!(
            query.query_payload,
            norito::codec::Encode::encode(&FindDomains)
        );
        assert_eq!(
            query.predicate_bytes,
            norito::codec::Encode::encode(&CompoundPredicate::<Domain>::PASS)
        );
        assert_eq!(
            query.selector_bytes,
            norito::codec::Encode::encode(&SelectorTuple::<Domain>::default())
        );
    }
    #[test]
    fn summary_json_handles_optional_fields() {
        let json_text = build_summary_json(
            "sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D",
            "Signatory alice",
            "Metadata keys: foo",
            Some("test"),
            Some("sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D"),
            None,
        );
        let parsed: json::Value = json::from_str(&json_text).expect("summary json");
        let json::Value::Object(map) = parsed else {
            panic!("expected summary to be encoded as an object");
        };
        assert_eq!(
            map.get("title").and_then(|v| v.as_str()),
            Some("sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
        );
        assert_eq!(map.get("domain").and_then(|v| v.as_str()), Some("test"));
        assert_eq!(
            map.get("owner").and_then(|v| v.as_str()),
            Some("sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D")
        );
        assert!(!map.contains_key("asset_definition"));
        let json_text_with_definition = build_summary_json(
            "xor#wallet",
            "Definitions",
            "Identifier projection",
            None,
            None,
            Some("xor#wallet"),
        );
        let parsed: json::Value = json::from_str(&json_text_with_definition).expect("summary json");
        let json::Value::Object(map) = parsed else {
            panic!("expected summary with definition to be encoded as an object");
        };
        assert_eq!(
            map.get("asset_definition").and_then(|v| v.as_str()),
            Some("xor#wallet")
        );
        assert!(!map.contains_key("domain"));
        assert!(!map.contains_key("owner"));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn accounts_query_decodes_entries() {
        let Some(server) = try_start_mock_server() else {
            return;
        };
        let account = AccountBuilder::new(ALICE_ID.clone()).build(&ALICE_ID);
        let output = QueryOutput::new(
            QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Account(vec![account])),
            0,
            None,
        );
        let encoded = to_bytes(&output).expect("encode query output");
        let mock = server.mock(|when, then| {
            when.method(POST).path("/v1/query");
            then.status(200).body(encoded.clone());
        });
        let client = ToriiClient::new_for_network(server.url("/"), crate::torii::test_network_id())
            .expect("client");
        let page = run_state_query(
            client,
            &crate::SigningAuthority::new("fixture", ALICE_ID.clone(), ALICE_KEYPAIR.clone()),
            iroha_data_model::account::address::chain_discriminant(),
            StateQueryKind::Accounts,
            None,
            None,
        )
        .await
        .expect("state page");
        mock.assert();
        assert_eq!(page.entries.len(), 1);
        assert!(page.cursor.is_none());
        assert_eq!(page.entries[0].title, ALICE_ID.to_string());
        assert!(
            page.entries[0].subtitle.contains("Signatory"),
            "subtitle should mention signatory"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn peers_query_decodes_entries() {
        let Some(server) = try_start_mock_server() else {
            return;
        };
        let peer = PeerId::from(ALICE_KEYPAIR.public_key().clone());
        let output = QueryOutput::new(
            QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Peer(vec![peer])),
            0,
            None,
        );
        let encoded = to_bytes(&output).expect("encode query output");
        let mock = server.mock(|when, then| {
            when.method(POST).path("/v1/query");
            then.status(200).body(encoded.clone());
        });
        let client = ToriiClient::new_for_network(server.url("/"), crate::torii::test_network_id())
            .expect("client");
        let page = run_state_query(
            client,
            &crate::SigningAuthority::new("fixture", ALICE_ID.clone(), ALICE_KEYPAIR.clone()),
            iroha_data_model::account::address::chain_discriminant(),
            StateQueryKind::Peers,
            None,
            None,
        )
        .await
        .expect("state page");
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].subtitle, "Peer public key");
        mock.assert();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn mismatched_batch_produces_error() {
        let Some(server) = try_start_mock_server() else {
            return;
        };
        let output = QueryOutput::new(
            QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Asset(Vec::new())),
            0,
            None,
        );
        let encoded = to_bytes(&output).expect("encode query output");
        server.mock(|when, then| {
            when.method(POST).path("/v1/query");
            then.status(200).body(encoded.clone());
        });
        let client = ToriiClient::new_for_network(server.url("/"), crate::torii::test_network_id())
            .expect("client");
        let err = run_state_query(
            client,
            &crate::SigningAuthority::new("fixture", ALICE_ID.clone(), ALICE_KEYPAIR.clone()),
            iroha_data_model::account::address::chain_discriminant(),
            StateQueryKind::Accounts,
            None,
            None,
        )
        .await
        .expect_err("unexpected batch kind should error");
        assert!(matches!(err, StateQueryError::UnexpectedBatch { .. }));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn state_query_uses_explicit_selected_authority() {
        use iroha_data_model::query::SignedQuery;
        use iroha_test_samples::{BOB_ID, BOB_KEYPAIR};
        use iroha_version::codec::DecodeVersioned as _;
        let Some(server) = try_start_mock_server() else {
            return;
        };
        let output = QueryOutput::new(
            QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::Account(Vec::new())),
            0,
            None,
        );
        let mock = server.mock(|when, then| {
            when.method(POST).path("/v1/query").is_true(|request| {
                SignedQuery::decode_all_versioned(request.body_ref()).is_ok_and(|query| {
                    query.authority() == &*BOB_ID
                        && query.payload.network_id() == crate::torii::test_network_id()
                        && query.verify_signature().is_ok()
                })
            });
            then.status(200).body(to_bytes(&output).unwrap());
        });
        let client =
            ToriiClient::new_for_network(server.url("/"), crate::torii::test_network_id()).unwrap();
        let signer = crate::SigningAuthority::new("selected", BOB_ID.clone(), BOB_KEYPAIR.clone());
        run_state_query(
            client,
            &signer,
            iroha_data_model::account::address::chain_discriminant(),
            StateQueryKind::Accounts,
            None,
            None,
        )
        .await
        .unwrap();
        mock.assert();
    }

    #[test]
    fn state_entry_account_exposes_norito_payload() {
        let account = AccountBuilder::new(ALICE_ID.clone()).build(&ALICE_ID);
        let entry = StateEntry::from_account(account);
        let json = entry.json.expect("account json");
        let account_label = ALICE_ID.to_string();
        assert!(
            json.contains(&account_label),
            "json should contain account id"
        );
        let bytes = entry.norito_bytes.expect("account bytes");
        assert!(!bytes.is_empty(), "norito bytes should not be empty");
        let decoded: AccountBuilder =
            norito::decode_from_bytes(&bytes).expect("decode framed account payload");
        assert_eq!(decoded.id(), &*ALICE_ID);
    }
    #[test]
    fn state_entry_asset_includes_json_encoding() {
        let definition_id: AssetDefinitionId = "4cuvDVPuLBKJyN6dPbRQhmLh68sU"
            .parse()
            .expect("definition id");
        let asset_id = AssetId::new(definition_id, ALICE_ID.clone());
        let asset = Asset::new(asset_id, Quantity::from(42_u32));
        let entry = StateEntry::from_asset(asset);
        assert!(
            entry.domain.is_none(),
            "opaque canonical definition ids should not force a synthetic domain"
        );
        let json = entry.json.expect("asset json");
        assert!(
            json.contains("\"value\""),
            "asset json should include value field"
        );
        let bytes = entry.norito_bytes.expect("asset bytes");
        assert!(!bytes.is_empty(), "asset norito should not be empty");
    }
    #[test]
    fn state_entry_asset_definition_includes_metadata() {
        let definition_id: AssetDefinitionId = "4cuvDVPuLBKJyN6dPbRQhmLh68sU"
            .parse()
            .expect("definition id");
        let definition = AssetDefinition::new(
            definition_id,
            "asset".to_owned(),
            NumericSpec::default(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let entry = StateEntry::from_asset_definition(definition);
        assert!(
            entry.domain.is_none(),
            "opaque canonical definition ids should not force a synthetic domain"
        );
        let json = entry.json.expect("asset definition json");
        assert!(
            json.contains("\"owned_by\""),
            "definition json should include owner"
        );
        let bytes = entry.norito_bytes.expect("definition bytes");
        assert!(
            !bytes.is_empty(),
            "definition norito encoding should not be empty"
        );
    }
    #[test]
    fn state_entry_asset_id_handles_opaque_definition_without_domain_projection() {
        let definition_id: AssetDefinitionId = "4cuvDVPuLBKJyN6dPbRQhmLh68sU"
            .parse()
            .expect("definition id");
        let asset_id = AssetId::new(definition_id, ALICE_ID.clone());
        let entry = StateEntry::from_asset_id(asset_id);
        assert!(entry.domain.is_none());
        assert!(entry.asset_definition.is_some());
    }
    #[test]
    fn state_entry_asset_definition_id_handles_opaque_domainless_identifier() {
        let definition_id: AssetDefinitionId = "4cuvDVPuLBKJyN6dPbRQhmLh68sU"
            .parse()
            .expect("definition id");
        let entry = StateEntry::from_asset_definition_id(definition_id);
        assert!(entry.domain.is_none());
        assert!(entry.asset_definition.is_some());
    }
    #[test]
    fn state_entry_domain_includes_owner() {
        let domain_id = DomainId::try_new("wonderland", "universal").expect("domain id");
        let domain = Domain::new(domain_id).build(&ALICE_ID);
        let entry = StateEntry::from_domain(domain);
        let json = entry.json.expect("domain json");
        assert!(
            json.contains("\"owned_by\""),
            "domain json should include owner field"
        );
        let bytes = entry.norito_bytes.expect("domain bytes");
        assert!(
            !bytes.is_empty(),
            "domain norito encoding should not be empty"
        );
    }
    #[test]
    fn bond_batches_preserve_requested_query_in_unsupported_response() {
        for requested in StateQueryKind::all() {
            let output = QueryOutput::new(
                QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::BondRecord(Vec::new())),
                0,
                None,
            );
            let error = parse_iterable_output(requested, output)
                .expect_err("a bond batch cannot become an empty page of another query kind");
            assert!(matches!(
                error,
                StateQueryError::UnexpectedBatch { kind, actual: "BondRecord" } if kind == requested
            ));
        }
    }

    #[test]
    fn batch_label_handles_rwa_and_escrow_variants() {
        assert_eq!(
            batch_label(&QueryOutputBatchBox::RwaId(Vec::new())),
            "RwaId"
        );
        assert_eq!(batch_label(&QueryOutputBatchBox::Rwa(Vec::new())), "Rwa");
        assert_eq!(
            batch_label(&QueryOutputBatchBox::AssetEscrowRecord(Vec::new())),
            "AssetEscrowRecord"
        );
        assert_eq!(
            batch_label(&QueryOutputBatchBox::OracleFeedConfig(Vec::new())),
            "OracleFeedConfig"
        );
        assert_eq!(
            batch_label(&QueryOutputBatchBox::OracleFeedEventRecord(Vec::new())),
            "OracleFeedEventRecord"
        );
        assert_eq!(
            batch_label(&QueryOutputBatchBox::OracleProviderStatsRecord(Vec::new())),
            "OracleProviderStatsRecord"
        );
        assert_eq!(
            batch_label(&QueryOutputBatchBox::OracleDispute(Vec::new())),
            "OracleDispute"
        );
        assert_eq!(
            batch_label(&QueryOutputBatchBox::OracleChangeProposal(Vec::new())),
            "OracleChangeProposal"
        );
        assert_eq!(
            batch_label(&QueryOutputBatchBox::TwitterBindingRecord(Vec::new())),
            "TwitterBindingRecord"
        );
        assert_eq!(
            batch_label(&QueryOutputBatchBox::DefiOracleAttestation(Vec::new())),
            "DefiOracleAttestation"
        );
        assert_eq!(
            batch_label(&QueryOutputBatchBox::FeeSponsorProgram(Vec::new())),
            "FeeSponsorProgram"
        );
        assert_eq!(
            batch_label(&QueryOutputBatchBox::FeeSponsorProgramId(Vec::new())),
            "FeeSponsorProgramId"
        );
    }
}
