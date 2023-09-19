//! Iroha schema generation support library. Contains the
//! `build_schemas` `fn`, which is the function which decides which
//! types are included in the schema.
#![allow(clippy::arithmetic_side_effects)]

use iroha_crypto::MerkleTree;
use iroha_data_model::{
    block::stream::{BlockMessage, BlockSubscriptionRequest},
    http::VersionedBatchedResponse,
    query::error::QueryExecutionFail,
};
use iroha_genesis::RawGenesisBlock;
use iroha_schema::prelude::*;

macro_rules! types {
    ($($t:ty),+ $(,)?) => {
        /// Apply `callback` to all types in the schema.
        #[macro_export]
        macro_rules! map_all_schema_types {
            ($callback:ident) => {{
                $( $callback!($t); )+

                #[cfg(target_arch = "aarch64")]
                $callback!(Box<VersionedSignedBlock>);
            }}
        }
    }
}

/// Builds the schema for the current state of Iroha.
///
/// You should only include the top-level types, because other types
/// shall be included recursively.
pub fn build_schemas() -> MetaMap {
    use iroha_data_model::prelude::*;

    macro_rules! schemas {
        ($($t:ty),* $(,)?) => {{
            let mut out = MetaMap::new(); $(
            <$t as IntoSchema>::update_schema_map(&mut out); )*
            out
        }};
    }

    schemas! {
        QueryExecutionFail,
        BlockMessage,
        BlockSubscriptionRequest,
        EventMessage,
        EventSubscriptionRequest,
        VersionedBatchedResponse<Value>,
        VersionedBatchedResponse<Vec<VersionedSignedTransaction>>,
        VersionedSignedQuery,

        // Never referenced, but present in type signature. Like `PhantomData<X>`
        MerkleTree<VersionedSignedTransaction>,
        RegistrableBox,
        UpgradableBox,

        // SDK devs want to know how to read serialized genesis block
        RawGenesisBlock,
    }
}

types!(
    Account,
    AccountEvent,
    AccountEventFilter,
    AccountFilter,
    AccountId,
    AccountPermissionChanged,
    AccountRoleChanged,
    Action<TriggeringFilterBox, Executable>,
    Add,
    Algorithm,
    And,
    Asset,
    AssetChanged,
    AssetDefinition,
    AssetDefinitionEvent,
    AssetDefinitionEventFilter,
    AssetDefinitionFilter,
    AssetDefinitionId,
    AssetDefinitionOwnerChanged,
    AssetDefinitionTotalQuantityChanged,
    AssetEvent,
    AssetEventFilter,
    AssetFilter,
    AssetId,
    AssetValue,
    AssetValueType,
    AtIndex,
    BTreeMap<AccountId, Account>,
    BTreeMap<AssetDefinitionId, AssetDefinition>,
    BTreeMap<AssetDefinitionId, NumericValue>,
    BTreeMap<AssetId, Asset>,
    BTreeMap<Name, EvaluatesTo<Value>>,
    BTreeMap<Name, Value>,
    BTreeSet<PermissionToken>,
    BTreeSet<PublicKey>,
    BTreeSet<RoleId>,
    BatchedResponse<Value>,
    BatchedResponse<Vec<VersionedSignedTransaction>>,
    BlockHeader,
    BlockMessage,
    BlockRejectionReason,
    BlockSubscriptionRequest,
    Box<FindError>,
    Box<GenericPredicateBox<ValuePredicate>>,
    Box<Pair>,
    Box<Value>,
    Box<ValuePredicate>,
    BurnBox,
    SignedBlock,
    Conditional,
    ConfigurationEvent,
    ConstString,
    Container,
    Contains,
    ContainsAll,
    ContainsAny,
    ContextValue,
    DataEntityFilter,
    DataEvent,
    DataEventFilter,
    Divide,
    Domain,
    DomainEvent,
    DomainEventFilter,
    DomainFilter,
    DomainId,
    Duration,
    Equal,
    EvaluatesTo<AccountId>,
    EvaluatesTo<AssetDefinitionId>,
    EvaluatesTo<AssetId>,
    EvaluatesTo<DomainId>,
    EvaluatesTo<IdBox>,
    EvaluatesTo<Name>,
    EvaluatesTo<NumericValue>,
    EvaluatesTo<Parameter>,
    EvaluatesTo<RegistrableBox>,
    EvaluatesTo<RoleId>,
    EvaluatesTo<TriggerId>,
    EvaluatesTo<UpgradableBox>,
    EvaluatesTo<Value>,
    EvaluatesTo<Vec<Value>>,
    EvaluatesTo<bool>,
    Event,
    EventMessage,
    EventSubscriptionRequest,
    Executable,
    ExecuteTriggerBox,
    ExecuteTriggerEvent,
    ExecuteTriggerEventFilter,
    ExecutionTime,
    Expression,
    FailBox,
    FilterBox,
    FilterOpt<AccountEventFilter>,
    FilterOpt<AccountFilter>,
    FilterOpt<AssetDefinitionEventFilter>,
    FilterOpt<AssetDefinitionFilter>,
    FilterOpt<AssetEventFilter>,
    FilterOpt<AssetFilter>,
    FilterOpt<DomainEventFilter>,
    FilterOpt<DomainFilter>,
    FilterOpt<OriginFilter<AccountEvent>>,
    FilterOpt<OriginFilter<AssetDefinitionEvent>>,
    FilterOpt<OriginFilter<AssetEvent>>,
    FilterOpt<OriginFilter<DomainEvent>>,
    FilterOpt<OriginFilter<PeerEvent>>,
    FilterOpt<OriginFilter<RoleEvent>>,
    FilterOpt<OriginFilter<TriggerEvent>>,
    FilterOpt<PeerEventFilter>,
    FilterOpt<PeerFilter>,
    FilterOpt<RoleEventFilter>,
    FilterOpt<RoleFilter>,
    FilterOpt<TriggerEventFilter>,
    FilterOpt<TriggerFilter>,
    FindAccountById,
    FindAccountKeyValueByIdAndKey,
    FindAccountsByDomainId,
    FindAccountsByName,
    FindAccountsWithAsset,
    FindAllAccounts,
    FindAllActiveTriggerIds,
    FindAllAssets,
    FindAllAssetsDefinitions,
    FindAllBlockHeaders,
    FindAllBlocks,
    FindAllDomains,
    FindAllParameters,
    FindAllPeers,
    FindPermissionTokenSchema,
    FindAllRoleIds,
    FindAllRoles,
    FindAllTransactions,
    FindAssetById,
    FindAssetDefinitionById,
    FindAssetDefinitionKeyValueByIdAndKey,
    FindAssetKeyValueByIdAndKey,
    FindAssetQuantityById,
    FindAssetsByAccountId,
    FindAssetsByAssetDefinitionId,
    FindAssetsByDomainId,
    FindAssetsByDomainIdAndAssetDefinitionId,
    FindAssetsByName,
    FindBlockHeaderByHash,
    FindDomainById,
    FindDomainKeyValueByIdAndKey,
    FindError,
    FindPermissionTokensByAccountId,
    FindRoleByRoleId,
    FindRolesByAccountId,
    FindTotalAssetQuantityByAssetDefinitionId,
    FindTransactionByHash,
    FindTransactionsByAccountId,
    FindTriggerById,
    FindTriggerKeyValueByIdAndKey,
    FindTriggersByDomainId,
    FixNum,
    Fixed,
    ForwardCursor,
    GrantBox,
    Greater,
    Hash,
    HashOf<MerkleTree<VersionedSignedTransaction>>,
    HashOf<VersionedSignedBlock>,
    HashOf<VersionedSignedTransaction>,
    IdBox,
    IdentifiableBox,
    If,
    InstructionBox,
    InstructionExecutionFail,
    Interval<u16>,
    Interval<u8>,
    IpfsPath,
    Ipv4Addr,
    Ipv4Predicate,
    Ipv6Addr,
    Ipv6Predicate,
    IsAssetDefinitionOwner,
    LengthLimits,
    Less,
    MerkleTree<VersionedSignedTransaction>,
    Metadata,
    MetadataChanged<AccountId>,
    MetadataChanged<AssetDefinitionId>,
    MetadataChanged<AssetId>,
    MetadataChanged<DomainId>,
    MetadataLimits,
    MintBox,
    Mintable,
    Mod,
    Multiply,
    Name,
    NewAccount,
    NewAssetDefinition,
    NewDomain,
    NewParameterBox,
    NewRole,
    NonTrivial<PredicateBox>,
    NonZeroU64,
    Not,
    NotificationEventFilter,
    NumericValue,
    Option<DomainId>,
    Option<Duration>,
    Option<Hash>,
    Option<HashOf<MerkleTree<VersionedSignedTransaction>>>,
    Option<HashOf<VersionedSignedBlock>>,
    Option<InstructionBox>,
    Option<IpfsPath>,
    Option<PipelineEntityKind>,
    Option<PipelineStatusKind>,
    Option<String>,
    Option<TimeInterval>,
    Option<TriggerCompletedOutcomeType>,
    Option<TriggerId>,
    Or,
    OriginFilter<AccountEvent>,
    OriginFilter<AssetDefinitionEvent>,
    OriginFilter<AssetEvent>,
    OriginFilter<DomainEvent>,
    OriginFilter<PeerEvent>,
    OriginFilter<RoleEvent>,
    OriginFilter<TriggerEvent>,
    Pair,
    Parameter,
    ParameterId,
    Peer,
    PeerEvent,
    PeerEventFilter,
    PeerFilter,
    PeerId,
    PermissionRemoved,
    PermissionToken,
    PermissionTokenSchema,
    PermissionTokenSchemaUpdateEvent,
    PipelineEntityKind,
    PipelineEvent,
    PipelineEventFilter,
    PipelineRejectionReason,
    PipelineStatus,
    PipelineStatusKind,
    PredicateBox,
    PublicKey,
    QueryBox,
    QueryExecutionFail,
    QueryPayload,
    RaiseTo,
    RegisterBox,
    RegistrableBox,
    RemoveKeyValueBox,
    Repeats,
    RevokeBox,
    Role,
    RoleEvent,
    RoleEventFilter,
    RoleFilter,
    RoleId,
    SemiInterval<Fixed>,
    SemiInterval<u128>,
    SemiInterval<u32>,
    SemiRange,
    SequenceBox,
    SetKeyValueBox,
    SetParameterBox,
    Signature,
    SignatureCheckCondition,
    SignatureOf<QueryPayload>,
    SignatureOf<TransactionPayload>,
    SignatureWrapperOf<TransactionPayload>,
    SignaturesOf<TransactionPayload>,
    SignedQuery,
    SignedTransaction,
    String,
    StringPredicate,
    Subtract,
    TimeEvent,
    TimeEventFilter,
    TimeInterval,
    TimeSchedule,
    TransactionLimitError,
    TransactionLimits,
    TransactionPayload,
    TransactionQueryOutput,
    TransactionRejectionReason,
    TransactionValue,
    TransferBox,
    Trigger<TriggeringFilterBox, Executable>,
    TriggerEvent,
    TriggerEventFilter,
    TriggerFilter,
    TriggerId,
    TriggerNumberOfExecutionsChanged,
    TriggerCompletedEventFilter,
    TriggerCompletedOutcomeType,
    TriggeringFilterBox,
    UnregisterBox,
    UpgradableBox,
    ValidationFail,
    Validator,
    ValidatorEvent,
    Value,
    ValueOfKey,
    ValuePredicate,
    Vec<Event>,
    Vec<InstructionBox>,
    Vec<PeerId>,
    Vec<PredicateBox>,
    Vec<Value>,
    Vec<VersionedSignedTransaction>,
    Vec<u8>,
    VersionedBatchedResponse<Value>,
    VersionedBatchedResponse<Vec<VersionedSignedTransaction>>,
    VersionedSignedBlock,
    VersionedSignedBlockWrapper,
    VersionedSignedQuery,
    VersionedSignedTransaction,
    WasmExecutionFail,
    WasmSmartContract,
    Where,
    [Interval<u16>; 8],
    [Interval<u8>; 4],
    [u16; 8],
    [u8; 32],
    [u8; 4],
    bool,
    i64,
    u128,
    u16,
    u32,
    u64,
    u8,
);

#[cfg(test)]
mod tests {
    use core::num::NonZeroU64;
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap, HashSet},
        time::Duration,
    };

    use iroha_crypto::*;
    use iroha_data_model::{
        account::NewAccount,
        asset::NewAssetDefinition,
        block::{
            error::BlockRejectionReason,
            stream::{BlockMessage, BlockSubscriptionRequest},
            BlockHeader, SignedBlock, VersionedSignedBlock,
        },
        domain::NewDomain,
        http::{BatchedResponse, VersionedBatchedResponse},
        ipfs::IpfsPath,
        predicate::{
            ip_addr::{Ipv4Predicate, Ipv6Predicate},
            numerical::{Interval, SemiInterval, SemiRange},
            string::StringPredicate,
            value::{AtIndex, Container, ValueOfKey, ValuePredicate},
            GenericPredicateBox, NonTrivial, PredicateBox,
        },
        prelude::*,
        query::{
            error::{FindError, QueryExecutionFail},
            ForwardCursor,
        },
        transaction::{error::TransactionLimitError, SignedTransaction, TransactionLimits},
        validator::Validator,
        VersionedSignedBlockWrapper,
    };
    use iroha_genesis::RawGenesisBlock;
    use iroha_primitives::{
        addr::{Ipv4Addr, Ipv6Addr},
        conststr::ConstString,
        fixed::{FixNum, Fixed},
    };

    use super::IntoSchema;

    fn is_const_generic(generic: &str) -> bool {
        generic.parse::<usize>().is_ok()
    }

    fn generate_test_map() -> BTreeMap<core::any::TypeId, String> {
        let mut map = BTreeMap::new();

        macro_rules! insert_into_test_map {
            ($t:ty) => {{
                let type_id = <$t as iroha_schema::TypeId>::id();

                if let Some(type_id) = map.insert(core::any::TypeId::of::<$t>(), type_id) {
                    panic!(
                        "{}: Duplicate type id. Make sure that type ids are unique",
                        type_id
                    );
                }
            }};
        }
        map_all_schema_types!(insert_into_test_map);
        map
    }

    // For `PhantomData` wrapped types schemas aren't expanded recursively.
    // This test ensures that schemas for those types are present as well.
    fn find_missing_type_params(type_names: &HashSet<String>) -> HashMap<&str, Vec<&str>> {
        let mut missing_schemas = HashMap::<&str, _>::new();

        for type_name in type_names {
            if let (Some(mut start), Some(end)) = (type_name.find('<'), type_name.rfind('>')) {
                start += 1;

                let mut angle_bracket_diff = 0_u8;
                for (i, c) in type_name[start..end].chars().enumerate() {
                    if c == '<' {
                        angle_bracket_diff += 1_u8;
                    }
                    if c == '>' {
                        angle_bracket_diff -= 1_u8;
                    }

                    if c == ',' && angle_bracket_diff == 0_u8 {
                        let generic = type_name[start..(start + i)].trim();

                        start += i + 1;
                        if !is_const_generic(generic) {
                            continue;
                        }

                        if !type_names.contains(generic) {
                            missing_schemas
                                .entry(type_name)
                                .or_insert_with(Vec::new)
                                .push(generic);
                        }
                    }
                }

                let generic = type_name[start..end].trim();
                if !generic.is_empty()
                    && !is_const_generic(generic)
                    && !type_names.contains(generic)
                {
                    missing_schemas
                        .entry(type_name)
                        .or_insert_with(Vec::new)
                        .push(generic);
                }
            }
        }

        missing_schemas
    }

    #[test]
    fn no_extra_or_missing_schemas() {
        let exceptions: HashSet<_> = RawGenesisBlock::schema()
            .into_iter()
            .map(|(type_id, _)| type_id)
            .collect();

        let schemas_types = super::build_schemas()
            .into_iter()
            .collect::<HashMap<_, _>>();
        let map_types = generate_test_map();

        let mut extra_types = HashSet::new();
        for (type_id, schema) in &map_types {
            if !schemas_types.contains_key(type_id) {
                extra_types.insert(schema);
            }
        }
        assert!(extra_types.is_empty(), "Extra types: {extra_types:#?}");

        let mut missing_types = HashSet::new();
        for (type_id, schema) in &schemas_types {
            if !map_types.contains_key(type_id) && !exceptions.contains(type_id) {
                missing_types.insert(schema);
            }
        }
        assert!(
            missing_types.is_empty(),
            "Missing types: {missing_types:#?}",
        );
    }

    #[test]
    fn no_missing_referenced_types() {
        let type_names = super::build_schemas()
            .into_iter()
            .map(|(_, (name, _))| name)
            .collect();
        let missing_schemas = find_missing_type_params(&type_names);

        assert!(
            missing_schemas.is_empty(),
            "Missing schemas: \n{missing_schemas:#?}"
        );
    }

    #[test]
    // NOTE: This test guards from incorrect implementation where
    // `SortedVec<T>` and `Vec<T>` start stepping over each other
    fn no_schema_type_overlap() {
        let mut schemas = super::build_schemas();
        <Vec<PublicKey>>::update_schema_map(&mut schemas);
        <BTreeSet<SignedTransaction>>::update_schema_map(&mut schemas);
    }
}
