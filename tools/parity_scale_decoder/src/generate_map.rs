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
        BTreeMap<PublicKey, SignatureOf<block::CommittedBlock>>,
        BTreeMap<PublicKey, SignatureOf<sumeragi::view_change::Proof>>,
        BTreeMap<PublicKey, SignatureOf<transaction::Payload>>,
        BTreeMap<String, expression::EvaluatesTo<Value>>,
        BTreeSet<PublicKey>,
        BTreeSet<RoleId>,
        BTreeSet<SignatureOf<block::ValidBlock>>,
        BTreeSet<SignatureOf<transaction::Payload>>,
        BTreeSet<permissions::PermissionToken>,
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
        HashOf<MerkleTree<transaction::VersionedTransaction>>,
        HashOf<block::VersionedCommittedBlock>,
        HashOf<block::VersionedValidBlock>,
        HashOf<sumeragi::view_change::Proof>,
        HashOf<transaction::VersionedTransaction>,
        IdBox,
        OriginFilter<AccountEvent>,
        OriginFilter<AssetDefinitionEvent>,
        OriginFilter<AssetEvent>,
        OriginFilter<DomainEvent>,
        OriginFilter<PeerEvent>,
        OriginFilter<RoleEvent>,
        OriginFilter<TriggerEvent>,
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
        PermissionTokenDefinitionId,
        PermissionTokenEvent,
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
        Transaction,
        TransactionRejectionReason,
        TransactionValue,
        TransactionQueryResult,
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
        Vec<Hash>,
        Vec<HashOf<block::VersionedValidBlock>>,
        Vec<PeerId>,
        Vec<SignatureOf<block::ValidBlock>>,
        Vec<SignatureOf<transaction::Payload>>,
        Vec<Value>,
        Vec<events::Event>,
        Vec<iroha_data_model::predicate::PredicateBox>,
        Vec<isi::Instruction>,
        Vec<permissions::PermissionToken>,
        Vec<sumeragi::view_change::Proof>,
        Vec<transaction::TransactionValue>,
        Vec<transaction::VersionedRejectedTransaction>,
        Vec<transaction::VersionedValidTransaction>,
        Vec<transaction::TransactionValue>,
        Vec<transaction::TransactionQueryResult>,
        Vec<u8>,
        VersionedPaginatedQueryResult,
        VersionedPendingTransactions,
        VersionedQueryResult,
        VersionedRejectedTransaction,
        VersionedSignedQueryRequest,
        VersionedTransaction,
        VersionedValidTransaction,
        WasmExecutionFail,
        Where,
        [u8; 32],
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
        iroha_data_model::predicate::PredicateBox,
        iroha_data_model::predicate::numerical::Range,
        iroha_data_model::predicate::numerical::SemiInterval<iroha_primitives::fixed::Fixed>,
        iroha_data_model::predicate::numerical::SemiInterval<u128>,
        iroha_data_model::predicate::numerical::SemiInterval<u32>,
        iroha_data_model::predicate::string::Predicate,
        iroha_data_model::predicate::value::AtIndex,
        iroha_data_model::predicate::value::Container,
        iroha_data_model::predicate::value::Predicate,
        iroha_data_model::predicate::value::ValueOfKey,
        query::Payload,
        role::NewRole,
        smartcontracts::isi::error::FindError,
        smartcontracts::isi::error::Mismatch<smartcontracts::isi::permissions::ValidatorType>,
        smartcontracts::isi::permissions::ValidatorType,
        smartcontracts::isi::query::Error,
        sumeragi::network_topology::Topology,
        sumeragi::view_change::BlockCreationTimeout,
        sumeragi::view_change::CommitTimeout,
        sumeragi::view_change::NoTransactionReceiptReceived,
        sumeragi::view_change::Proof,
        sumeragi::view_change::ProofChain,
        sumeragi::view_change::ProofPayload,
        sumeragi::view_change::Reason,
        transaction::Payload,
        transaction::TransactionLimitError,
        transaction::WasmSmartContract,
        u128,
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

    #[test]
    fn schemas_types_is_a_subset_of_map_types() {
        // Exceptions which does not implement `Decode` so that they can't be decoded by this tool
        let exceptions = HashSet::from([
            "Vec<iroha_core::genesis::GenesisTransaction>",
            "iroha_core::genesis::GenesisTransaction",
            "iroha_core::genesis::RawGenesisBlock",
            "iroha_crypto::merkle::MerkleTree<iroha_data_model::transaction::VersionedTransaction>",
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
