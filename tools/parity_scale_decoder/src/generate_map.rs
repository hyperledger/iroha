//! Exports `generate_map()` function and contains implementation details for it

use std::{collections::BTreeSet, num::NonZeroU8};

use iroha_crypto::*;
use iroha_data_model::{prelude::*, *};
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
        AccountPermissionChanged,
        AccountRoleChanged,
        Action<FilterBox>,
        Add,
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
        AtomicU32,
        BTreeMap<AccountId, Account>,
        BTreeMap<AssetDefinitionId, AssetDefinitionEntry>,
        BTreeMap<AssetDefinitionId, NumericValue>,
        BTreeMap<AssetId, Asset>,
        BTreeMap<Name, Value>,
        BTreeMap<Name, ValueKind>,
        BTreeMap<Name, expression::EvaluatesTo<Value>>,
        BTreeMap<PublicKey, SignatureOf<iroha_data_model::block::CommittedBlock>>,
        BTreeMap<PublicKey, SignatureOf<transaction::Payload>>,
        BTreeSet<PermissionToken>,
        BTreeSet<PublicKey>,
        BTreeSet<RoleId>,
        BTreeSet<SignatureOf<transaction::Payload>>,
        block::error::BlockRejectionReason,
        BurnBox,
        ConfigurationEvent,
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
        FindAssetRegisteringTransaction,
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
        FindTotalAssetQuantityByAssetDefinitionId,
        FindTransactionByHash,
        FindTransactionsByAccountId,
        FindTriggerById,
        FindTriggerKeyValueByIdAndKey,
        FindTriggersByDomainId,
        GrantBox,
        Greater,
        Hash,
        Option<HashOf<MerkleTree<transaction::VersionedSignedTransaction>>>,
        Option<HashOf<iroha_data_model::block::VersionedCommittedBlock>>,
        HashOf<MerkleTree<transaction::VersionedSignedTransaction>>,
        HashOf<iroha_data_model::block::VersionedCommittedBlock>,
        HashOf<transaction::VersionedSignedTransaction>,
        IdBox,
        IdentifiableBox,
        IfExpression,
        IfInstruction,
        Instruction,
        InstructionExecutionFail,
        IsAssetDefinitionOwner,
        iroha_crypto::Algorithm,
        LengthLimits,
        Less,
        Metadata,
        MetadataChanged<AccountId>,
        MetadataChanged<AssetDefinitionId>,
        MetadataChanged<AssetId>,
        MetadataChanged<DomainId>,
        MetadataLimits,
        MintBox,
        Mod,
        Multiply,
        Name,
        NewParameterBox,
        NonZeroU8,
        Not,
        NotPermittedFail,
        NumericValue,
        Option<Hash>,
        Option<HashOf<MerkleTree<transaction::VersionedSignedTransaction>>>,
        Option<HashOf<iroha_data_model::block::VersionedCommittedBlock>>,
        Option<Name>,
        Option<core::time::Duration>,
        Option<domain::Id>,
        Option<domain::IpfsPath>,
        Option<events::pipeline::EntityKind>,
        Option<events::pipeline::StatusKind>,
        Option<events::time::Interval>,
        Option<isi::Instruction>,
        Option<Vec<peer::Id>>,
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
        events::pipeline::RejectionReason,
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
        SetParameterBox,
        Signature,
        SignatureCheckCondition,
        SignatureOf<iroha_data_model::block::CommittedBlock>,
        SignatureOf<query::http::Payload>,
        SignatureOf<transaction::Payload>,
        SignaturesOf<iroha_data_model::block::CommittedBlock>,
        SignaturesOf<transaction::Payload>,
        SignedQueryRequest,
        SignedTransaction,
        Sorting,
        String,
        Subtract,
        TimeEvent,
        TimeEventFilter,
        TimeInterval,
        TimeSchedule,
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
        UnsupportedVersion,
        ValidTransaction,
        Value,
        ValueKind,
        Vec<Hash>,
        Vec<PeerId>,
        Vec<PermissionToken>,
        Vec<Signature>,
        Vec<SignatureOf<iroha_data_model::block::CommittedBlock>>,
        Vec<SignatureOf<transaction::Payload>>,
        Vec<Value>,
        Vec<events::Event>,
        Vec<iroha_data_model::predicate::PredicateBox>,
        Vec<isi::Instruction>,
        Vec<transaction::TransactionQueryResult>,
        Vec<transaction::TransactionValue>,
        Vec<transaction::TransactionValue>,
        Vec<transaction::VersionedRejectedTransaction>,
        Vec<transaction::VersionedSignedTransaction>,
        Vec<transaction::VersionedValidTransaction>,
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
        iroha_data_model::block::BlockHeader,
        iroha_data_model::block::CommittedBlock,
        iroha_data_model::block::VersionedCommittedBlock,
        iroha_data_model::block::stream::BlockMessage,
        iroha_data_model::block::stream::BlockSubscriptionRequest,
        iroha_data_model::block::stream::VersionedBlockMessage,
        iroha_data_model::block::stream::VersionedBlockSubscriptionRequest,
        bool,
        core::time::Duration,
        domain::IpfsPath,
        domain::NewDomain,
        events::Event,
        events::FilterBox,
        events::stream::EventMessage,
        events::stream::EventSubscriptionRequest,
        events::stream::VersionedEventMessage,
        events::stream::VersionedEventSubscriptionRequest,
        events::pipeline::StatusKind,
        expression::EvaluatesTo<AccountId>,
        expression::EvaluatesTo<AssetDefinitionId>,
        expression::EvaluatesTo<AssetId>,
        expression::EvaluatesTo<DomainId>,
        expression::EvaluatesTo<Hash>,
        expression::EvaluatesTo<IdBox>,
        expression::EvaluatesTo<Name>,
        expression::EvaluatesTo<NumericValue>,
        expression::EvaluatesTo<Parameter>,
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
        iroha_data_model::query::error::FindError,
        iroha_data_model::isi::error::Mismatch<permission::validator::Type>,
        iroha_data_model::query::error::QueryExecutionFailure,
        iroha_primitives::addr::Ipv4Addr,
        iroha_primitives::addr::Ipv6Addr,
        iroha_version::error::Error,
        permission::token::Id,
        permission::validator::Id,
        permission::validator::Type,
        predicate::NonTrivial<predicate::PredicateBox>,
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
        query::http::Payload,
        role::NewRole,
        transaction::Payload,
        transaction::error::TransactionExpired,
        transaction::error::TransactionLimitError,
        transaction::TransactionLimits,
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
            Vec<iroha_genesis::GenesisTransaction>,
            iroha_genesis::GenesisTransaction,
            iroha_genesis::RawGenesisBlock,
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
