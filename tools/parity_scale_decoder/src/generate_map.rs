//! Exports `generate_map()` function and contains implementation details for it

use std::collections::BTreeSet;

use iroha_core::*;
use iroha_crypto::*;
use iroha_data_model::{prelude::*, query::SignedQueryRequest, *};
use iroha_primitives::{atomic::*, fixed};
use iroha_schema::IntoSchema;
use iroha_version::*;

use super::*;

/// Trait to retrieve type name
///
/// It is used with abusing [inherit impls](https://doc.rust-lang.org/reference/items/implementations.html#inherent-implementations)
/// to get `None` variant from types, which doesn't implement [`IntoSchema`] and `Some` which does
trait TypeName {
    /// Get name of the type or `None` if type doesn't implement `IntoSchema`
    fn type_name() -> Option<String>;
}

impl<T> TypeName for T {
    fn type_name() -> Option<String> {
        None
    }
}

/// Newtype which has `type_name()` method when `T` implements [`IntoSchema`]
struct WithTypeName<T>(std::marker::PhantomData<T>);

impl<T: IntoSchema + Decode> WithTypeName<T> {
    /// Get type name using [`IntoSchema::type_name()`]
    ///
    /// Because this is implemented directly on `WithTypeName`, it has priority over
    /// the [`TypeName`] trait impl.
    ///
    /// Note: this is a *totally different* function from that in
    /// `TypeName`. This does not specialize the `TypeName` trait impl on `WithTypeName`.
    fn type_name() -> Option<String> {
        Some(<T as IntoSchema>::type_name())
    }
}

macro_rules! generate_map {
    ($($t:ty),* $(,)?) => {
        BTreeMap::from([
            $((
                WithTypeName::<$t>::type_name().unwrap_or(stringify!($t).to_owned()),
                <$t as DumpDecoded>::dump_decoded as DumpDecodedPtr
            )),*
        ])
    };
}

/// Generate map with types and `dump_decoded()` ptr
#[allow(clippy::too_many_lines, trivial_casts)]
pub fn generate_map() -> DumpDecodedMap {
    // Try to keep this list in alphabetical order
    let mut map = generate_map! {
        Account,
        AccountEvent,
        AccountEventFilter,
        AccountFilter,
        AccountId,
        Action<FilterBox>,
        Add,
        And,
        Asset,
        AssetDefinition,
        AssetDefinitionEntry,
        AssetDefinitionEvent,
        AssetDefinitionEventFilter,
        AssetDefinitionFilter,
        AssetDefinitionId,
        AssetEvent,
        AssetEventFilter,
        AssetFilter,
        AssetId,
        AssetValue,
        AssetValueType,
        AtomicU32,
        BTreeMap<AccountId, Account>,
        BTreeMap<AssetDefinitionId, AssetDefinitionEntry>,
        BTreeMap<AssetId, Asset>,
        BTreeMap<Name, Value>,
        BTreeMap<Name, ValueKind>,
        BTreeMap<PublicKey, SignatureOf<block::CommittedBlock>>,
        BTreeMap<PublicKey, SignatureOf<sumeragi::view_change::Proof>>,
        BTreeMap<PublicKey, SignatureOf<transaction::Payload>>,
        BTreeMap<String, expression::EvaluatesTo<Value>>,
        BTreeSet<PermissionToken>,
        BTreeSet<PublicKey>,
        BTreeSet<RoleId>,
        BTreeSet<SignatureOf<block::ValidBlock>>,
        BTreeSet<SignatureOf<transaction::Payload>>,
        BlockHeaderValue,
        BlockRejectionReason,
        BlockValue,
        BurnBox,
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
        Equal,
        Executable,
        ExecuteTriggerBox,
        ExecuteTriggerEvent,
        ExecuteTriggerEventFilter,
        ExecutionTime,
        Expression,
        FailBox,
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
        FindPermissionTokensByAccountId,
        FindRoleByRoleId,
        FindRolesByAccountId,
        FindTransactionByHash,
        FindTransactionsByAccountId,
        FindTriggerById,
        FindTriggerKeyValueByIdAndKey,
        FindTriggersByDomainId,
        GenesisDomain,
        GrantBox,
        Greater,
        Hash,
        HashOf<MerkleTree<transaction::VersionedSignedTransaction>>,
        HashOf<block::VersionedCommittedBlock>,
        HashOf<block::VersionedValidBlock>,
        HashOf<sumeragi::view_change::Proof>,
        HashOf<transaction::VersionedSignedTransaction>,
        IdBox,
        IdentifiableBox,
        IfExpression,
        IfInstruction,
        Instruction,
        InstructionExecutionFail,
        Less,
        Metadata,
        MetadataLimits,
        MintBox,
        Mod,
        Multiply,
        Name,
        Not,
        NotPermittedFail,
        Option<Hash>,
        Option<core::time::Duration>,
        Option<domain::Id>,
        Option<domain::IpfsPath>,
        Option<events::pipeline::EntityKind>,
        Option<events::pipeline::StatusKind>,
        Option<events::time::Interval>,
        Option<isi::Instruction>,
        Option<sumeragi::network_topology::Topology>,
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
        PermissionValidatorEvent,
        PipelineEntityKind,
        PipelineEvent,
        PipelineEventFilter,
        PipelineStatus,
        PublicKey,
        QueryBox,
        QueryRequest,
        QueryResult,
        RaiseTo,
        RawVersioned,
        RegisterBox,
        RegistrableBox,
        RejectedTransaction,
        RejectionReason,
        RemoveKeyValueBox,
        Repeats,
        RevokeBox,
        Role,
        RoleEvent,
        RoleEventFilter,
        RoleFilter,
        RoleId,
        SequenceBox,
        SetKeyValueBox,
        Signature,
        SignatureCheckCondition,
        SignatureOf<block::CommittedBlock>,
        SignatureOf<block::ValidBlock>,
        SignatureOf<query::Payload>,
        SignatureOf<sumeragi::view_change::Proof>,
        SignatureOf<transaction::Payload>,
        SignaturesOf<block::CommittedBlock>,
        SignaturesOf<sumeragi::view_change::Proof>,
        SignaturesOf<transaction::Payload>,
        SignedQueryRequest,
        String,
        Subtract,
        TimeEvent,
        TimeEventFilter,
        TimeInterval,
        TimeSchedule,
        SignedTransaction,
        TransactionRejectionReason,
        TransactionValue,
        TransferBox,
        Trigger<FilterBox>,
        TriggerEvent,
        TriggerEventFilter,
        TriggerFilter,
        TriggerId,
        UnregisterBox,
        UnsatisfiedSignatureConditionFail,
        UnsupportedVersion,
        ValidTransaction,
        Value,
        ValueKind,
        Vec<Hash>,
        Vec<HashOf<block::VersionedValidBlock>>,
        Vec<PeerId>,
        Vec<PermissionToken>,
        Vec<SignatureOf<block::ValidBlock>>,
        Vec<SignatureOf<transaction::Payload>>,
        Vec<Value>,
        Vec<events::Event>,
        Vec<iroha_data_model::predicate::PredicateBox>,
        Vec<isi::Instruction>,
        Vec<sumeragi::view_change::Proof>,
        Vec<transaction::TransactionQueryResult>,
        Vec<transaction::TransactionValue>,
        Vec<transaction::TransactionValue>,
        Vec<transaction::VersionedRejectedTransaction>,
        Vec<transaction::VersionedValidTransaction>,
        Vec<Signature>,
        Vec<u8>,
        VersionedPaginatedQueryResult,
        VersionedPendingTransactions,
        VersionedQueryResult,
        VersionedRejectedTransaction,
        VersionedSignedQueryRequest,
        VersionedSignedTransaction,
        VersionedValidTransaction,
        WasmExecutionFail,
        Where,
        [predicate::ip_addr::Ipv4Predicate; 4],
        [predicate::numerical::Interval<u16>; 8],
        [predicate::numerical::Interval<u8>; 4],
        [u16; 8],
        [u8; 32],
        [u8; 4],
        account::NewAccount,
        asset::Mintable,
        asset::NewAssetDefinition,
        block::BlockHeader,
        block::CommittedBlock,
        block::ValidBlock,
        block::VersionedCommittedBlock,
        block::VersionedValidBlock,
        block::stream::BlockPublisherMessage,
        block::stream::BlockSubscriberMessage,
        block::stream::VersionedBlockPublisherMessage,
        block::stream::VersionedBlockSubscriberMessage,
        bool,
        core::time::Duration,
        domain::IpfsPath,
        domain::NewDomain,
        error::Error,
        events::Event,
        events::EventPublisherMessage,
        events::EventSubscriberMessage,
        events::FilterBox,
        events::VersionedEventPublisherMessage,
        events::VersionedEventSubscriberMessage,
        events::pipeline::StatusKind,
        expression::EvaluatesTo<AccountId>,
        expression::EvaluatesTo<AssetDefinitionId>,
        expression::EvaluatesTo<AssetId>,
        expression::EvaluatesTo<DomainId>,
        expression::EvaluatesTo<Hash>,
        expression::EvaluatesTo<IdBox>,
        expression::EvaluatesTo<Name>,
        expression::EvaluatesTo<RegistrableBox>,
        expression::EvaluatesTo<RoleId>,
        expression::EvaluatesTo<TriggerId>,
        expression::EvaluatesTo<Value>,
        expression::EvaluatesTo<Vec<Value>>,
        expression::EvaluatesTo<bool>,
        expression::EvaluatesTo<u32>,
        fixed::FixNum,
        fixed::Fixed,
        i64,
        iroha_data_model::permission::validator::Validator,
        iroha_primitives::addr::Ipv4Addr,
        iroha_primitives::addr::Ipv6Addr,
        permission::token::Id,
        permission::validator::Id,
        permission::validator::Type,
        predicate::PredicateBox,
        predicate::ip_addr::Ipv4Predicate,
        predicate::ip_addr::Ipv6Predicate,
        predicate::numerical::Interval<iroha_primitives::fixed::Fixed>,
        predicate::numerical::Interval<u128>,
        predicate::numerical::Interval<u16>,
        predicate::numerical::Interval<u32>,
        predicate::numerical::Interval<u8>,
        predicate::numerical::Range,
        predicate::numerical::SemiInterval<iroha_primitives::fixed::Fixed>,
        predicate::numerical::SemiInterval<u128>,
        predicate::numerical::SemiInterval<u32>,
        predicate::numerical::SemiRange,
        predicate::string::Predicate,
        predicate::value::AtIndex,
        predicate::value::Container,
        predicate::value::Predicate,
        predicate::value::ValueOfKey,
        query::Payload,
        role::NewRole,
        smartcontracts::isi::error::FindError,
        smartcontracts::isi::error::Mismatch<permission::validator::Type>,
        smartcontracts::isi::query::Error,
        sumeragi::network_topology::Topology,
        sumeragi::view_change::Proof,
        transaction::Payload,
        transaction::TransactionLimitError,
        transaction::WasmSmartContract,
        u128,
        u16,
        u32,
        u64,
        u8,
    };

    map.insert(
        <iroha_schema::Compact<u128> as IntoSchema>::type_name(),
        <parity_scale_codec::Compact<u128> as DumpDecoded>::dump_decoded as DumpDecodedPtr,
    );

    map
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use iroha_schema_gen::build_schemas;

    use super::*;

    macro_rules! type_names_arr {
        ($($ty:ty),+$(,)?) => {
            [$(
                <$ty as IntoSchema>::type_name(),
            )+]
        }
    }

    #[test]
    fn schemas_types_is_a_subset_of_map_types() {
        // These types **shouldn't** implement `Decode`. As such we need to make an exception.
        let exceptions = HashSet::from(type_names_arr![
            Vec<iroha_core::genesis::GenesisTransaction>,
            iroha_core::genesis::GenesisTransaction,
            iroha_core::genesis::RawGenesisBlock,
            iroha_crypto::MerkleTree<iroha_data_model::transaction::VersionedSignedTransaction>,
            TransactionQueryResult,
        ]);

        let schemas_types = build_schemas()
            .into_keys()
            .filter(|type_name| !exceptions.contains(type_name.as_str()))
            .collect::<HashSet<_>>();
        let map_types = generate_map().into_keys().collect::<HashSet<_>>();

        assert!(
            schemas_types.is_subset(&map_types),
            "Difference: {:#?}",
            schemas_types.difference(&map_types)
        );
    }
}
