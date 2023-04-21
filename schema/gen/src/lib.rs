//! Iroha schema generation support library. Contains the
//! `build_schemas` `fn`, which is the function which decides which
//! types are included in the schema.
#![allow(clippy::arithmetic_side_effects)]

use iroha_data_model::{block::stream::prelude::*, query::error::QueryExecutionFailure};
use iroha_genesis::RawGenesisBlock;
use iroha_schema::prelude::*;

macro_rules! types {
    ($($t:ty),+ $(,)?) => {
        /// Generate map holding all schema types
        #[macro_export]
        macro_rules! generate_map {
            ($insert_entry:ident) => {{
                let mut map = BTreeMap::new();
                $( $insert_entry!(map, $t); )+

                #[cfg(target_arch = "aarch64")]
                $insert_entry!(map, Box<VersionedCommittedBlock>);

                map
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
        // TODO: Should genesis belong to schema? #3284
        RawGenesisBlock,

        QueryExecutionFailure,
        VersionedBlockMessage,
        VersionedBlockSubscriptionRequest,
        VersionedEventMessage,
        VersionedEventSubscriptionRequest,
        VersionedPaginatedQueryResult,
        VersionedSignedQuery,
        VersionedPendingTransactions,
        UpgradableBox,
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
    Action<FilterBox, Executable>,
    Add,
    Algorithm,
    And,
    Asset,
    AssetChanged,
    AssetDefinition,
    AssetDefinitionEntry,
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
    AtomicU32,
    BTreeMap<AccountId, Account>,
    BTreeMap<AssetDefinitionId, AssetDefinitionEntry>,
    BTreeMap<AssetDefinitionId, NumericValue>,
    BTreeMap<AssetId, Asset>,
    BTreeMap<Name, EvaluatesTo<Value>>,
    BTreeMap<Name, Value>,
    BTreeMap<Name, ValueKind>,
    BTreeSet<PermissionToken>,
    BTreeSet<PublicKey>,
    BTreeSet<RoleId>,
    BTreeSet<SignatureWrapperOf<CommittedBlock>>,
    BlockHeader,
    BlockMessage,
    BlockRejectionReason,
    BlockSubscriptionRequest,
    Box<Account>,
    Box<Asset>,
    Box<AssetDefinition>,
    Box<Domain>,
    Box<Expression>,
    Box<FindError>,
    Box<GenericPredicateBox<ValuePredicate>>,
    Box<NewAccount>,
    Box<NewAssetDefinition>,
    Box<NewDomain>,
    Box<NewRole>,
    Box<Pair>,
    Box<Parameter>,
    Box<Peer>,
    Box<PermissionTokenDefinition>,
    Box<Role>,
    Box<Trigger<FilterBox, Executable>>,
    Box<Value>,
    Box<ValuePredicate>,
    Box<VersionedRejectedTransaction>,
    Box<VersionedSignedTransaction>,
    BurnBox,
    CommittedBlock,
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
    DoesAccountHavePermissionToken,
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
    EvaluatesTo<Hash>,
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
    FindAllPermissionTokenDefinitions,
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
    GrantBox,
    Greater,
    Hash,
    HashOf<MerkleTree<VersionedSignedTransaction>>,
    HashOf<VersionedCommittedBlock>,
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
    Not,
    NotPermittedFail,
    NumericValue,
    Option<DomainId>,
    Option<Duration>,
    Option<Hash>,
    Option<HashOf<MerkleTree<VersionedSignedTransaction>>>,
    Option<HashOf<VersionedCommittedBlock>>,
    Option<InstructionBox>,
    Option<IpfsPath>,
    Option<Name>,
    Option<PipelineEntityKind>,
    Option<PipelineStatusKind>,
    Option<TimeInterval>,
    Option<u32>,
    Or,
    OriginFilter<AccountEvent>,
    OriginFilter<AssetDefinitionEvent>,
    OriginFilter<AssetEvent>,
    OriginFilter<DomainEvent>,
    OriginFilter<PeerEvent>,
    OriginFilter<RoleEvent>,
    OriginFilter<TriggerEvent>,
    PaginatedQueryResult,
    Pagination,
    Pair,
    Parameter,
    ParameterId,
    Peer,
    PeerEvent,
    PeerEventFilter,
    PeerFilter,
    PeerId,
    PendingTransactions,
    PermissionRemoved,
    PermissionToken,
    PermissionTokenDefinition,
    PermissionTokenEvent,
    PermissionTokenId,
    PipelineEntityKind,
    PipelineEvent,
    PipelineEventFilter,
    PipelineRejectionReason,
    PipelineStatus,
    PipelineStatusKind,
    PredicateBox,
    PublicKey,
    QueryBox,
    QueryExecutionFailure,
    QueryPayload,
    QueryResult,
    RaiseTo,
    RegisterBox,
    RejectedTransaction,
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
    SignatureOf<CommittedBlock>,
    SignatureOf<QueryPayload>,
    SignatureOf<TransactionPayload>,
    SignatureWrapperOf<CommittedBlock>,
    SignatureWrapperOf<TransactionPayload>,
    SignaturesOf<CommittedBlock>,
    SignaturesOf<TransactionPayload>,
    SignedQuery,
    SignedTransaction,
    Sorting,
    String,
    StringPredicate,
    Subtract,
    TimeEvent,
    TimeEventFilter,
    TimeInterval,
    TimeSchedule,
    TransactionExpired,
    TransactionLimitError,
    TransactionLimits,
    TransactionPayload,
    TransactionQueryResult,
    TransactionRejectionReason,
    TransactionValue,
    TransferBox,
    Trigger<FilterBox, Executable>,
    TriggerEvent,
    TriggerEventFilter,
    TriggerFilter,
    TriggerId,
    TriggerNumberOfExecutionsChanged,
    UnregisterBox,
    UnsatisfiedSignatureConditionFail,
    UpgradableBox,
    ValidTransaction,
    Validator,
    ValidatorEvent,
    Value,
    ValueKind,
    ValueOfKey,
    ValuePredicate,
    Vec<Event>,
    Vec<InstructionBox>,
    Vec<PeerId>,
    Vec<PredicateBox>,
    Vec<SignedTransaction>,
    Vec<Value>,
    Vec<VersionedRejectedTransaction>,
    Vec<VersionedValidTransaction>,
    Vec<u8>,
    VersionedBlockMessage,
    VersionedBlockSubscriptionRequest,
    VersionedCommittedBlock,
    VersionedCommittedBlockWrapper,
    VersionedEventMessage,
    VersionedEventSubscriptionRequest,
    VersionedPaginatedQueryResult,
    VersionedPendingTransactions,
    VersionedRejectedTransaction,
    VersionedSignedQuery,
    VersionedSignedTransaction,
    VersionedValidTransaction,
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
            stream::{
                BlockMessage, BlockSubscriptionRequest, VersionedBlockMessage,
                VersionedBlockSubscriptionRequest,
            },
            BlockHeader, CommittedBlock, VersionedCommittedBlock,
        },
        domain::NewDomain,
        ipfs::IpfsPath,
        predicate::{
            ip_addr::{Ipv4Predicate, Ipv6Predicate},
            numerical::{Interval, SemiInterval, SemiRange},
            string::StringPredicate,
            value::{AtIndex, Container, ValueOfKey, ValuePredicate},
            GenericPredicateBox, NonTrivial, PredicateBox,
        },
        prelude::*,
        query::error::{FindError, QueryExecutionFailure},
        transaction::error::{TransactionExpired, TransactionLimitError},
        validator::Validator,
        ValueKind, VersionedCommittedBlockWrapper,
    };
    use iroha_genesis::RawGenesisBlock;
    use iroha_primitives::{
        addr::{Ipv4Addr, Ipv6Addr},
        atomic::AtomicU32,
        conststr::ConstString,
        fixed::{FixNum, Fixed},
    };

    use super::IntoSchema;

    // NOTE: These type parameters should not be have their schema exposed
    // By default `PhantomData` wrapped types schema will not be included
    const SCHEMALESS_TYPES: [&str; 2] =
        ["MerkleTree<VersionedSignedTransaction>", "RegistrableBox"];

    fn is_const_generic(generic: &str) -> bool {
        generic.parse::<usize>().is_ok()
    }

    macro_rules! insert_into_test_map {
        ( $map:ident, $t:ty) => {{
            let type_id = <$t as iroha_schema::TypeId>::id();

            if let Some(type_id) = $map.insert(core::any::TypeId::of::<$t>(), type_id) {
                panic!(
                    "{}: Duplicate type id. Make sure that type ids are unique",
                    type_id
                );
            }
        }};
    }

    fn generate_test_map() -> BTreeMap<core::any::TypeId, String> {
        let mut map = generate_map! {insert_into_test_map};

        if map
            .insert(
                core::any::TypeId::of::<iroha_schema::Compact<u128>>(),
                <iroha_schema::Compact<u128> as iroha_schema::TypeId>::id(),
            )
            .is_some()
        {
            panic!(
                "{}: Duplicate type id. Make sure that type ids are unique",
                <iroha_schema::Compact<u128> as iroha_schema::TypeId>::id(),
            );
        }

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

                        if !SCHEMALESS_TYPES.contains(&generic) && !type_names.contains(generic) {
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
                    && !SCHEMALESS_TYPES.contains(&generic)
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
        // TODO: Should genesis belong to schema? #3284
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
        assert!(extra_types.is_empty(), "Extra types: {:#?}", extra_types);

        let mut missing_types = HashSet::new();
        for (type_id, schema) in &schemas_types {
            if !map_types.contains_key(type_id) && !exceptions.contains(type_id) {
                missing_types.insert(schema);
            }
        }
        assert!(
            missing_types.is_empty(),
            "Missing types: {:#?}",
            missing_types
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
