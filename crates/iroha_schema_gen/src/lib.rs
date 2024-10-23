//! Iroha schema generation support library. Contains the
//! `build_schemas` `fn`, which is the function which decides which
//! types are included in the schema.
use iroha_crypto::MerkleTree;
use iroha_data_model::{
    block::stream::{BlockMessage, BlockSubscriptionRequest},
    query::{QueryResponse, SignedQuery},
};
use iroha_schema::prelude::*;

macro_rules! types {
    ($($t:ty),+ $(,)?) => {
        // use all the types in a type position, so that IDE can resolve them
        const _: () = {
            use complete_data_model::*;
            $(
                let _resolve_my_type_pls: $t;
            )+
        };

        /// Apply `callback` to all types in the schema.
        #[macro_export]
        macro_rules! map_all_schema_types {
            ($callback:ident) => {{
                $( $callback!($t); )+
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
    use iroha_executor_data_model::permission;

    macro_rules! schemas {
        ($($t:ty),* $(,)?) => {{
            let mut out = MetaMap::new(); $(
            <$t as IntoSchema>::update_schema_map(&mut out); )*
            out
        }};
    }

    schemas! {
        // Transaction
        SignedTransaction,

        // Query + response
        SignedQuery,
        QueryResponse,

        // Event stream
        EventMessage,
        EventSubscriptionRequest,

        // Block stream
        BlockMessage,
        BlockSubscriptionRequest,

        // Never referenced, but present in type signature. Like `PhantomData<X>`
        MerkleTree<SignedTransaction>,

        // Default permissions
        permission::peer::CanManagePeers,
        permission::domain::CanUnregisterDomain,
        permission::domain::CanModifyDomainMetadata,
        permission::account::CanRegisterAccount,
        permission::account::CanUnregisterAccount,
        permission::account::CanModifyAccountMetadata,
        permission::asset_definition::CanRegisterAssetDefinition,
        permission::asset_definition::CanUnregisterAssetDefinition,
        permission::asset_definition::CanModifyAssetDefinitionMetadata,
        permission::asset::CanTransferAssetWithDefinition,
        permission::asset::CanMintAsset,
        permission::asset::CanBurnAsset,
        permission::asset::CanTransferAsset,
        permission::parameter::CanSetParameters,
        permission::role::CanManageRoles,
        permission::trigger::CanRegisterTrigger,
        permission::trigger::CanExecuteTrigger,
        permission::trigger::CanUnregisterTrigger,
        permission::trigger::CanModifyTrigger,
        permission::trigger::CanModifyTriggerMetadata,
        permission::executor::CanUpgradeExecutor,

        // Genesis file - used by SDKs to generate the genesis block
        // TODO: IMO it could/should be removed from the schema
        iroha_genesis::RawGenesisTransaction,
    }
}

types!(
    Account,
    AccountEvent,
    AccountEventFilter,
    AccountEventSet,
    AccountId,
    AccountIdPredicateBox,
    AccountPermissionChanged,
    AccountPredicateBox,
    AccountRoleChanged,
    Action,
    Algorithm,
    Asset,
    AssetChanged,
    AssetDefinition,
    AssetDefinitionEvent,
    AssetDefinitionEventFilter,
    AssetDefinitionEventSet,
    AssetDefinitionId,
    AssetDefinitionIdPredicateBox,
    AssetDefinitionOwnerChanged,
    AssetDefinitionPredicateBox,
    AssetDefinitionTotalQuantityChanged,
    AssetEvent,
    AssetEventFilter,
    AssetEventSet,
    AssetId,
    AssetIdPredicateBox,
    AssetPredicateBox,
    BlockEvent,
    BlockEventFilter,
    BlockHashPredicateBox,
    BlockHeader,
    BlockHeaderPredicateBox,
    BlockMessage,
    BlockParameter,
    BlockParameters,
    BlockPayload,
    BlockRejectionReason,
    BlockSignature,
    BlockStatus,
    BlockSubscriptionRequest,
    Box<CompoundPredicate<AccountPredicateBox>>,
    Box<CompoundPredicate<AssetDefinitionPredicateBox>>,
    Box<CompoundPredicate<AssetPredicateBox>>,
    Box<CompoundPredicate<BlockHeaderPredicateBox>>,
    Box<CompoundPredicate<DomainPredicateBox>>,
    Box<CompoundPredicate<PeerPredicateBox>>,
    Box<CompoundPredicate<PermissionPredicateBox>>,
    Box<CompoundPredicate<RoleIdPredicateBox>>,
    Box<CompoundPredicate<RolePredicateBox>>,
    Box<CompoundPredicate<SignedBlockPredicateBox>>,
    Box<CompoundPredicate<TransactionQueryOutputPredicateBox>>,
    Box<CompoundPredicate<TriggerIdPredicateBox>>,
    Box<CompoundPredicate<TriggerPredicateBox>>,
    Box<TransactionRejectionReason>,
    BTreeMap<CustomParameterId, CustomParameter>,
    BTreeMap<Name, Json>,
    BTreeSet<Permission>,
    BTreeSet<String>,
    BurnBox,
    Burn<Numeric, Asset>,
    Burn<u32, Trigger>,
    ChainId,
    CommittedTransaction,
    CommittedTransactionPredicateBox,
    CompoundPredicate<AccountPredicateBox>,
    CompoundPredicate<AssetDefinitionPredicateBox>,
    CompoundPredicate<AssetPredicateBox>,
    CompoundPredicate<BlockHeaderPredicateBox>,
    CompoundPredicate<DomainPredicateBox>,
    CompoundPredicate<PeerPredicateBox>,
    CompoundPredicate<PermissionPredicateBox>,
    CompoundPredicate<RoleIdPredicateBox>,
    CompoundPredicate<RolePredicateBox>,
    CompoundPredicate<SignedBlockPredicateBox>,
    CompoundPredicate<TransactionQueryOutputPredicateBox>,
    CompoundPredicate<TriggerIdPredicateBox>,
    CompoundPredicate<TriggerPredicateBox>,
    ConfigurationEvent,
    ConfigurationEventFilter,
    ConfigurationEventSet,
    ConstString,
    ConstVec<u8>,
    ConstVec<InstructionBox>,
    CustomInstruction,
    CustomParameter,
    CustomParameterId,
    DataEvent,
    DataEventFilter,
    Domain,
    DomainEvent,
    DomainEventFilter,
    DomainEventSet,
    DomainId,
    DomainIdPredicateBox,
    DomainOwnerChanged,
    DomainPredicateBox,
    EventBox,
    EventFilterBox,
    EventMessage,
    EventSubscriptionRequest,
    Executable,
    ExecuteTrigger,
    ExecuteTriggerEvent,
    ExecuteTriggerEventFilter,
    ExecutionTime,
    Executor,
    ExecutorDataModel,
    ExecutorEvent,
    ExecutorEventFilter,
    ExecutorEventSet,
    ExecutorPath,
    ExecutorUpgrade,
    FetchSize,
    FindAccountMetadata,
    FindAccountsWithAsset,
    FindAccounts,
    FindActiveTriggerIds,
    FindAssets,
    FindAssetsDefinitions,
    FindBlockHeaders,
    FindBlocks,
    FindDomains,
    FindParameters,
    FindPeers,
    FindRoleIds,
    FindRoles,
    FindTransactions,
    FindTriggers,
    FindAssetDefinitionMetadata,
    FindAssetQuantityById,
    FindDomainMetadata,
    FindError,
    FindExecutorDataModel,
    FindPermissionsByAccountId,
    FindRolesByAccountId,
    FindTriggerMetadata,
    ForwardCursor,
    GrantBox,
    Grant<Permission, Account>,
    Grant<Permission, Role>,
    Grant<RoleId, Account>,
    Hash,
    HashOf<MerkleTree<SignedTransaction>>,
    HashOf<BlockHeader>,
    HashOf<SignedTransaction>,
    IdBox,
    InstructionBox,
    InstructionEvaluationError,
    InstructionExecutionError,
    InstructionExecutionFail,
    InstructionType,
    InvalidParameterError,
    IpfsPath,
    Ipv4Addr,
    Ipv6Addr,
    QueryBox,
    QueryOutput,
    QueryOutputBatchBox,
    QueryParams,
    QueryWithFilter<FindAccountsWithAsset, AccountPredicateBox>,
    QueryWithFilter<FindAccounts, AccountPredicateBox>,
    QueryWithFilter<FindActiveTriggerIds, TriggerIdPredicateBox>,
    QueryWithFilter<FindAssets, AssetPredicateBox>,
    QueryWithFilter<FindAssetsDefinitions, AssetDefinitionPredicateBox>,
    QueryWithFilter<FindBlockHeaders, BlockHeaderPredicateBox>,
    QueryWithFilter<FindBlocks, SignedBlockPredicateBox>,
    QueryWithFilter<FindDomains, DomainPredicateBox>,
    QueryWithFilter<FindPeers, PeerPredicateBox>,
    QueryWithFilter<FindRoleIds, RoleIdPredicateBox>,
    QueryWithFilter<FindRoles, RolePredicateBox>,
    QueryWithFilter<FindTransactions, TransactionQueryOutputPredicateBox>,
    QueryWithFilter<FindTriggers, TriggerPredicateBox>,
    QueryWithFilter<FindPermissionsByAccountId, PermissionPredicateBox>,
    QueryWithFilter<FindRolesByAccountId, RoleIdPredicateBox>,
    QueryWithParams,
    Json,
    Level,
    Log,
    MathError,
    MerkleTree<SignedTransaction>,
    Metadata,
    MetadataChanged<AccountId>,
    MetadataChanged<AssetDefinitionId>,
    MetadataChanged<DomainId>,
    MetadataChanged<TriggerId>,
    MetadataPredicateBox,
    MintabilityError,
    Mintable,
    MintBox,
    Mint<Numeric, Asset>,
    Mint<u32, Trigger>,
    Mismatch<NumericSpec>,
    Name,
    NewAccount,
    NewAssetDefinition,
    NewDomain,
    NewRole,
    NonZeroU32,
    NonZeroU64,
    Numeric,
    NumericSpec,
    NumericPredicateBox,
    Option<AccountId>,
    Option<AssetDefinitionId>,
    Option<AssetId>,
    Option<BlockStatus>,
    Option<DomainId>,
    Option<ForwardCursor>,
    Option<HashOf<BlockHeader>>,
    Option<HashOf<SignedTransaction>>,
    Option<IpfsPath>,
    Option<Name>,
    Option<NonZeroU32>,
    Option<NonZeroU64>,
    Option<Option<NonZeroU64>>,
    Option<Parameters>,
    Option<PeerId>,
    Option<RoleId>,
    Option<Box<TransactionRejectionReason>>,
    Option<TransactionStatus>,
    Option<TriggerCompletedOutcomeType>,
    Option<TriggerId>,
    Option<u32>,
    Option<u64>,
    Pagination,
    Parameter,
    ParameterChanged,
    Parameters,
    Peer,
    PeerEvent,
    PeerEventFilter,
    PeerEventSet,
    PeerId,
    PeerPredicateBox,
    Permission,
    PermissionPredicateBox,
    PipelineEventBox,
    PipelineEventFilterBox,
    PublicKey,
    PublicKeyPredicateBox,
    QueryExecutionFail,
    QueryRequest,
    QueryRequestWithAuthority,
    QueryResponse,
    QuerySignature,
    Register<Account>,
    Register<AssetDefinition>,
    RegisterBox,
    Register<Domain>,
    Register<Peer>,
    Register<Role>,
    Register<Trigger>,
    RemoveKeyValue<Account>,
    RemoveKeyValue<AssetDefinition>,
    RemoveKeyValueBox,
    RemoveKeyValue<Domain>,
    RemoveKeyValue<Trigger>,
    Repeats,
    RepetitionError,
    RevokeBox,
    Revoke<Permission, Account>,
    Revoke<Permission, Role>,
    Revoke<RoleId, Account>,
    Role,
    RoleEvent,
    RoleEventFilter,
    RoleEventSet,
    RoleId,
    RoleIdPredicateBox,
    RolePermissionChanged,
    RolePredicateBox,
    SetKeyValue<Account>,
    SetKeyValue<AssetDefinition>,
    SetKeyValueBox,
    SetKeyValue<Domain>,
    SetKeyValue<Trigger>,
    SetParameter,
    Signature,
    SignatureOf<BlockHeader>,
    SignatureOf<QueryRequestWithAuthority>,
    SignatureOf<TransactionPayload>,
    SignedBlock,
    SignedBlockPredicateBox,
    SignedBlockV1,
    SignedQuery,
    SignedQueryV1,
    SignedTransaction,
    SignedTransactionPredicateBox,
    SignedTransactionV1,
    SingularQueryBox,
    SingularQueryOutputBox,
    SmartContractParameter,
    SmartContractParameters,
    SocketAddr,
    SocketAddrHost,
    SocketAddrV4,
    SocketAddrV6,
    Sorting,
    String,
    StringPredicateBox,
    SumeragiParameter,
    SumeragiParameters,
    TimeEvent,
    TimeEventFilter,
    TimeInterval,
    TimeSchedule,
    TransactionErrorPredicateBox,
    TransactionEvent,
    TransactionEventFilter,
    TransactionHashPredicateBox,
    TransactionLimitError,
    TransactionParameter,
    TransactionParameters,
    TransactionPayload,
    TransactionQueryOutput,
    TransactionQueryOutputPredicateBox,
    TransactionRejectionReason,
    TransactionSignature,
    TransactionStatus,
    Transfer<Account, AssetDefinitionId, Account>,
    Transfer<Account, DomainId, Account>,
    Transfer<Asset, Numeric, Account>,
    TransferBox,
    Trigger,
    TriggerCompletedEvent,
    TriggerCompletedEventFilter,
    TriggerCompletedOutcome,
    TriggerCompletedOutcomeType,
    TriggerEvent,
    TriggerEventFilter,
    TriggerEventSet,
    TriggerId,
    TriggerIdPredicateBox,
    TriggerPredicateBox,
    TriggerNumberOfExecutionsChanged,
    TypeError,
    Unregister<Account>,
    Unregister<AssetDefinition>,
    UnregisterBox,
    Unregister<Domain>,
    Unregister<Peer>,
    Unregister<Role>,
    Unregister<Trigger>,
    Upgrade,
    ValidationFail,
    Vec<Account>,
    Vec<Asset>,
    Vec<AssetDefinition>,
    Vec<BlockHeader>,
    Vec<BlockSignature>,
    Vec<CommittedTransaction>,
    Vec<CompoundPredicate<AccountPredicateBox>>,
    Vec<CompoundPredicate<AssetDefinitionPredicateBox>>,
    Vec<CompoundPredicate<AssetPredicateBox>>,
    Vec<CompoundPredicate<BlockHeaderPredicateBox>>,
    Vec<CompoundPredicate<DomainPredicateBox>>,
    Vec<CompoundPredicate<PeerPredicateBox>>,
    Vec<CompoundPredicate<PermissionPredicateBox>>,
    Vec<CompoundPredicate<RoleIdPredicateBox>>,
    Vec<CompoundPredicate<RolePredicateBox>>,
    Vec<CompoundPredicate<SignedBlockPredicateBox>>,
    Vec<CompoundPredicate<TransactionQueryOutputPredicateBox>>,
    Vec<CompoundPredicate<TriggerIdPredicateBox>>,
    Vec<CompoundPredicate<TriggerPredicateBox>>,
    Vec<Domain>,
    Vec<EventFilterBox>,
    Vec<InstructionBox>,
    Vec<Parameter>,
    Vec<Peer>,
    Vec<PeerId>,
    Vec<Permission>,
    Vec<Role>,
    Vec<RoleId>,
    Vec<SignedBlock>,
    Vec<TransactionQueryOutput>,
    Vec<Trigger>,
    Vec<TriggerId>,
    Vec<u8>,
    WasmExecutionFail,
    WasmSmartContract,

    [u16; 8],
    [u8; 32],
    [u8; 4],
    u16,
    u32,
    u64,
    u8,

    iroha_genesis::RawGenesisTransaction,
);

pub mod complete_data_model {
    //! Complete set of types participating in the schema

    pub use core::num::{NonZeroU32, NonZeroU64};
    pub use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

    pub use iroha_crypto::*;
    pub use iroha_data_model::{
        account::NewAccount,
        asset::NewAssetDefinition,
        block::{
            error::BlockRejectionReason,
            stream::{BlockMessage, BlockSubscriptionRequest},
            BlockHeader, BlockPayload, BlockSignature, SignedBlock, SignedBlockV1,
        },
        domain::NewDomain,
        events::pipeline::{BlockEventFilter, TransactionEventFilter},
        executor::{Executor, ExecutorDataModel},
        ipfs::IpfsPath,
        isi::{
            error::{
                InstructionEvaluationError, InstructionExecutionError, InvalidParameterError,
                MathError, MintabilityError, Mismatch, RepetitionError, TypeError,
            },
            InstructionType,
        },
        parameter::{
            BlockParameter, BlockParameters, CustomParameter, CustomParameterId, Parameter,
            Parameters, SmartContractParameter, SmartContractParameters, SumeragiParameter,
            SumeragiParameters, TransactionParameter, TransactionParameters,
        },
        prelude::*,
        query::{
            error::{FindError, QueryExecutionFail},
            parameters::{ForwardCursor, QueryParams},
            predicate::CompoundPredicate,
            QueryOutput, QueryOutputBatchBox, QueryRequestWithAuthority, QueryResponse,
            QuerySignature, QueryWithFilter, QueryWithParams, SignedQuery, SignedQueryV1,
            SingularQueryOutputBox,
        },
        transaction::{
            error::TransactionLimitError, SignedTransactionV1, TransactionPayload,
            TransactionSignature,
        },
        Level,
    };
    pub use iroha_genesis::ExecutorPath;
    pub use iroha_primitives::{
        addr::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrHost, SocketAddrV4, SocketAddrV6},
        const_vec::ConstVec,
        conststr::ConstString,
        json::Json,
    };
    pub use iroha_schema::Compact;
}

#[cfg(test)]
mod tests {
    use iroha_schema::MetaMapEntry;

    use super::{complete_data_model::*, IntoSchema};

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

        insert_into_test_map!(Compact<u128>);
        insert_into_test_map!(Compact<u32>);

        insert_into_test_map!(iroha_executor_data_model::permission::peer::CanManagePeers);
        insert_into_test_map!(iroha_executor_data_model::permission::domain::CanUnregisterDomain);
        insert_into_test_map!(
            iroha_executor_data_model::permission::domain::CanModifyDomainMetadata
        );
        insert_into_test_map!(iroha_executor_data_model::permission::account::CanRegisterAccount);
        insert_into_test_map!(iroha_executor_data_model::permission::account::CanUnregisterAccount);
        insert_into_test_map!(
            iroha_executor_data_model::permission::account::CanModifyAccountMetadata
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset_definition::CanRegisterAssetDefinition
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset_definition::CanUnregisterAssetDefinition
        );
        insert_into_test_map!(iroha_executor_data_model::permission::asset_definition::CanModifyAssetDefinitionMetadata);
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition
        );
        insert_into_test_map!(iroha_executor_data_model::permission::asset::CanMintAsset);
        insert_into_test_map!(iroha_executor_data_model::permission::asset::CanBurnAsset);
        insert_into_test_map!(iroha_executor_data_model::permission::asset::CanTransferAsset);
        insert_into_test_map!(iroha_executor_data_model::permission::parameter::CanSetParameters);
        insert_into_test_map!(iroha_executor_data_model::permission::role::CanManageRoles);
        insert_into_test_map!(iroha_executor_data_model::permission::trigger::CanRegisterTrigger);
        insert_into_test_map!(iroha_executor_data_model::permission::trigger::CanExecuteTrigger);
        insert_into_test_map!(iroha_executor_data_model::permission::trigger::CanUnregisterTrigger);
        insert_into_test_map!(iroha_executor_data_model::permission::trigger::CanModifyTrigger);
        insert_into_test_map!(
            iroha_executor_data_model::permission::trigger::CanModifyTriggerMetadata
        );
        insert_into_test_map!(iroha_executor_data_model::permission::executor::CanUpgradeExecutor);

        map
    }

    // For `PhantomData` wrapped types schemas aren't expanded recursively.
    // This test ensures that schemas for those types are present as well.
    fn find_missing_type_params(type_names: &HashSet<String>) -> HashMap<&str, Vec<&str>> {
        let mut missing_schemas = HashMap::<&str, _>::new();

        for type_name in type_names {
            let (Some(start), Some(end)) = (type_name.find('<'), type_name.rfind('>')) else {
                continue;
            };

            assert!(start < end, "Invalid type name: {type_name}");

            for generic in type_name.split(", ") {
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

        missing_schemas
    }

    #[test]
    fn no_extra_or_missing_schemas() {
        // NOTE: Skipping Box<str> until [this PR](https://github.com/paritytech/parity-scale-codec/pull/565) is merged
        let exceptions: [core::any::TypeId; 1] = [core::any::TypeId::of::<Box<str>>()];

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
            .map(|(_, MetaMapEntry { type_id, .. })| type_id)
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
        <BTreeSet<SignedTransactionV1>>::update_schema_map(&mut schemas);
    }
}
