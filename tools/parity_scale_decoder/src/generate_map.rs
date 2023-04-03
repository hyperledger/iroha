//! Exports `generate_map()` function and contains implementation details for it

use std::{any::TypeId, collections::BTreeSet, time::Duration};

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
    domain::{IpfsPath, NewDomain},
    permission::validator::{Validator, ValidatorId, ValidatorType},
    predicate::{
        ip_addr::{Ipv4Predicate, Ipv6Predicate},
        numerical::{Interval, SemiInterval, SemiRange},
        string::Predicate as StringPredicate,
        value::{AtIndex, Container, Predicate as ValuePredicate, ValueOfKey},
        GenericPredicateBox, NonTrivial, PredicateBox,
    },
    prelude::*,
    query::error::{FindError, QueryExecutionFailure},
    transaction::error::{TransactionExpired, TransactionLimitError},
    ValueKind, VersionedCommittedBlockWrapper,
};
use iroha_primitives::{
    addr::{Ipv4Addr, Ipv6Addr},
    atomic::AtomicU32,
    conststr::ConstString,
    fixed::{FixNum, Fixed},
};

use super::*;

macro_rules! generate_map {
    ($($t:ty),+ $(,)?) => {{
        let mut map = BTreeMap::new(); $(

        let type_id = <$t as iroha_schema::TypeId>::id();
        if let Some((type_id, _)) = map.insert(core::any::TypeId::of::<$t>(), (type_id, <$t as DumpDecoded>::dump_decoded as DumpDecodedPtr)) {
            panic!("{}: Duplicate type id. Make sure that type ids are unique", type_id);
        } )+

        map
    }};
}

/// Generate map with types and `dump_decoded()` ptr
#[allow(clippy::too_many_lines, trivial_casts)]
pub fn generate_map() -> DumpDecodedMap {
    generate_test_map()
        .into_iter()
        .map(|(_, (type_name, ptr))| (type_name, ptr))
        .collect()
}

/// Generate map with types and `dump_decoded()` ptr
#[allow(clippy::too_many_lines, trivial_casts)]
fn generate_test_map() -> BTreeMap<TypeId, (String, DumpDecodedPtr)> {
    let mut map = generate_map! {
        Account,
        AccountEvent,
        AccountEventFilter,
        AccountFilter,
        AccountId,
        AccountPermissionChanged,
        AccountRoleChanged,
        Action<FilterBox>,
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
        Box<Trigger<FilterBox>>,
        Box<Validator>,
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
        Instruction,
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
        Option<Instruction>,
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
        PermissionValidatorEvent,
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
        SignedQueryRequest,
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
        Trigger<FilterBox>,
        TriggerEvent,
        TriggerEventFilter,
        TriggerFilter,
        TriggerId,
        TriggerNumberOfExecutionsChanged,
        UnregisterBox,
        UnsatisfiedSignatureConditionFail,
        ValidTransaction,
        Validator,
        ValidatorId,
        ValidatorType,
        Value,
        ValueKind,
        ValueOfKey,
        ValuePredicate,
        Vec<Event>,
        Vec<Instruction>,
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
        VersionedSignedQueryRequest,
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
    };

    #[cfg(target_arch = "aarch64")]
    if let Some((type_id, _)) = map.insert(
        core::any::TypeId::of::<Box<VersionedCommittedBlock>>(),
        (
            <Box<VersionedCommittedBlock> as iroha_schema::TypeId>::id(),
            <Box<VersionedCommittedBlock> as DumpDecoded>::dump_decoded as DumpDecodedPtr,
        ),
    ) {
        panic!(
            "{}: Duplicate type id. Make sure that type ids are unique",
            type_id
        );
    }
    if let Some((type_id, _)) = map.insert(
        core::any::TypeId::of::<iroha_schema::Compact<u128>>(),
        (
            <iroha_schema::Compact<u128> as iroha_schema::TypeId>::id(),
            <parity_scale_codec::Compact<u32> as DumpDecoded>::dump_decoded as DumpDecodedPtr,
        ),
    ) {
        panic!(
            "{}: Duplicate type id. Make sure that type ids are unique",
            type_id
        );
    }

    map
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use iroha_genesis::RawGenesisBlock;
    use iroha_schema::IntoSchema;
    use iroha_schema_gen::build_schemas;

    use super::*;

    #[test]
    fn all_schema_types_are_decodable() {
        // TODO: Should genesis belong to schema? #3284
        let exceptions: HashSet<_> = RawGenesisBlock::schema()
            .into_iter()
            .map(|(type_id, _)| type_id)
            .collect();

        let schemas_types = build_schemas().into_iter().collect::<HashMap<_, _>>();
        let map_types = generate_test_map();

        let mut extra_types = HashSet::new();
        for (type_id, schema) in &map_types {
            if !schemas_types.contains_key(type_id) {
                extra_types.insert(&schema.0);
            }
        }
        assert!(extra_types.is_empty(), "Extra types: {:#?}", extra_types);

        let mut missing_types = HashSet::new();
        for (type_id, schema) in &schemas_types {
            if !map_types.contains_key(type_id) && !exceptions.contains(type_id) {
                missing_types.insert(&schema.0);
            }
        }
        assert!(
            missing_types.is_empty(),
            "Missing types: {:#?}",
            missing_types
        );
    }
}
