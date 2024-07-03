//! Iroha schema generation support library. Contains the
//! `build_schemas` `fn`, which is the function which decides which
//! types are included in the schema.
use iroha_crypto::MerkleTree;
use iroha_data_model::{
    block::stream::{BlockMessage, BlockSubscriptionRequest},
    query::QueryOutputBox,
    BatchedResponse,
};
use iroha_schema::prelude::*;

macro_rules! types {
    ($($t:ty),+ $(,)?) => {
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
        BatchedResponse<QueryOutputBox>,

        // Event stream
        EventMessage,
        EventSubscriptionRequest,

        // Block stream
        BlockMessage,
        BlockSubscriptionRequest,

        // Never referenced, but present in type signature. Like `PhantomData<X>`
        MerkleTree<SignedTransaction>,

        // Default permissions
        permission::peer::CanUnregisterAnyPeer,
        permission::domain::CanUnregisterDomain,
        permission::domain::CanSetKeyValueInDomain,
        permission::domain::CanRemoveKeyValueInDomain,
        permission::domain::CanRegisterAccountInDomain,
        permission::domain::CanRegisterAssetDefinitionInDomain,
        permission::account::CanUnregisterAccount,
        permission::account::CanSetKeyValueInAccount,
        permission::account::CanRemoveKeyValueInAccount,
        permission::asset_definition::CanUnregisterAssetDefinition,
        permission::asset_definition::CanSetKeyValueInAssetDefinition,
        permission::asset_definition::CanRemoveKeyValueInAssetDefinition,
        permission::asset::CanRegisterAssetWithDefinition,
        permission::asset::CanUnregisterAssetWithDefinition,
        permission::asset::CanUnregisterUserAsset,
        permission::asset::CanBurnAssetWithDefinition,
        permission::asset::CanMintAssetWithDefinition,
        permission::asset::CanMintUserAsset,
        permission::asset::CanBurnUserAsset,
        permission::asset::CanTransferAssetWithDefinition,
        permission::asset::CanTransferUserAsset,
        permission::asset::CanSetKeyValueInUserAsset,
        permission::asset::CanRemoveKeyValueInUserAsset,
        permission::parameter::CanSetParameters,
        permission::role::CanUnregisterAnyRole,
        permission::trigger::CanRegisterUserTrigger,
        permission::trigger::CanExecuteUserTrigger,
        permission::trigger::CanUnregisterUserTrigger,
        permission::trigger::CanMintUserTrigger,
        permission::trigger::CanBurnUserTrigger,
        permission::trigger::CanSetKeyValueInTrigger,
        permission::trigger::CanRemoveKeyValueInTrigger,
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
    AccountPermissionChanged,
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
    AssetDefinitionOwnerChanged,
    AssetDefinitionTotalQuantityChanged,
    AssetEvent,
    AssetEventFilter,
    AssetEventSet,
    AssetId,
    AssetTransferBox,
    AssetType,
    AssetValue,
    AtIndex,
    BTreeMap<CustomParameterId, CustomParameter>,
    BTreeMap<Name, JsonString>,
    BTreeSet<Permission>,
    BTreeSet<String>,
    BatchedResponse<QueryOutputBox>,
    BatchedResponseV1<QueryOutputBox>,
    BlockEvent,
    BlockEventFilter,
    BlockHeader,
    BlockMessage,
    BlockParameter,
    BlockParameters,
    BlockPayload,
    BlockRejectionReason,
    BlockSignature,
    BlockStatus,
    BlockSubscriptionRequest,
    Box<GenericPredicateBox<QueryOutputPredicate>>,
    Box<QueryOutputPredicate>,
    Box<TransactionRejectionReason>,
    Burn<Numeric, Asset>,
    Burn<u32, Trigger>,
    BurnBox,
    ChainId,
    ClientQueryPayload,
    CommittedTransaction,
    ConfigurationEvent,
    ConfigurationEventFilter,
    ConfigurationEventSet,
    ConstString,
    ConstVec<u8>,
    Container,
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
    DomainOwnerChanged,
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
    FindAccountById,
    FindAccountKeyValueByIdAndKey,
    FindAccountsByDomainId,
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
    FindExecutorDataModel,
    FindPermissionsByAccountId,
    FindRoleByRoleId,
    FindRolesByAccountId,
    FindTotalAssetQuantityByAssetDefinitionId,
    FindTransactionByHash,
    FindTransactionsByAccountId,
    FindTriggerById,
    FindTriggerKeyValueByIdAndKey,
    FindTriggersByAuthorityDomainId,
    FindTriggersByAuthorityId,
    ForwardCursor,
    Grant<Permission, Account>,
    Grant<Permission, Role>,
    Grant<RoleId, Account>,
    GrantBox,
    Hash,
    HashOf<MerkleTree<SignedTransaction>>,
    HashOf<SignedBlock>,
    HashOf<SignedTransaction>,
    IdBox,
    IdentifiableBox,
    InstructionBox,
    InstructionEvaluationError,
    InstructionExecutionError,
    InstructionExecutionFail,
    InstructionType,
    InvalidParameterError,
    IpfsPath,
    Ipv4Addr,
    Ipv6Addr,
    JsonString,
    Level,
    Log,
    MathError,
    MerkleTree<SignedTransaction>,
    Metadata,
    MetadataChanged<AccountId>,
    MetadataChanged<AssetDefinitionId>,
    MetadataChanged<AssetId>,
    MetadataChanged<DomainId>,
    MetadataChanged<TriggerId>,
    Mint<Numeric, Asset>,
    Mint<u32, Trigger>,
    MintBox,
    MintabilityError,
    Mintable,
    Mismatch<AssetType>,
    Name,
    NewAccount,
    NewAssetDefinition,
    NewDomain,
    NewRole,
    NonTrivial<PredicateBox>,
    NonZeroU32,
    NonZeroU64,
    Numeric,
    NumericSpec,
    Option<AccountId>,
    Option<AssetDefinitionId>,
    Option<AssetId>,
    Option<BlockStatus>,
    Option<DomainId>,
    Option<HashOf<SignedBlock>>,
    Option<HashOf<SignedTransaction>>,
    Option<IpfsPath>,
    Option<JsonString>,
    Option<Name>,
    Option<NonZeroU32>,
    Option<NonZeroU64>,
    Option<Option<NonZeroU64>>,
    Option<PeerId>,
    Option<RoleId>,
    Option<String>,
    Option<TimeInterval>,
    Option<TransactionRejectionReason>,
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
    Permission,
    PipelineEventBox,
    PipelineEventFilterBox,
    PredicateBox,
    PublicKey,
    QueryBox,
    QueryExecutionFail,
    QueryOutputBox,
    QueryOutputPredicate,
    QuerySignature,
    Register<Account>,
    Register<Asset>,
    Register<AssetDefinition>,
    Register<Domain>,
    Register<Peer>,
    Register<Role>,
    Register<Trigger>,
    RegisterBox,
    RemoveKeyValue<Account>,
    RemoveKeyValue<Asset>,
    RemoveKeyValue<AssetDefinition>,
    RemoveKeyValue<Domain>,
    RemoveKeyValue<Trigger>,
    RemoveKeyValueBox,
    Repeats,
    RepetitionError,
    Revoke<Permission, Account>,
    Revoke<Permission, Role>,
    Revoke<RoleId, Account>,
    RevokeBox,
    Role,
    RoleEvent,
    RoleEventFilter,
    RoleEventSet,
    RoleId,
    RolePermissionChanged,
    SemiInterval<Numeric>,
    SemiInterval<u128>,
    SemiRange,
    SetKeyValue<Account>,
    SetKeyValue<Asset>,
    SetKeyValue<AssetDefinition>,
    SetKeyValue<Domain>,
    SetKeyValue<Trigger>,
    SetKeyValueBox,
    SetParameter,
    Signature,
    SignatureOf<BlockPayload>,
    SignatureOf<ClientQueryPayload>,
    SignatureOf<TransactionPayload>,
    SignedBlock,
    SignedBlockV1,
    SignedQuery,
    SignedQueryV1,
    SignedTransaction,
    SignedTransactionV1,
    SmartContract,
    SmartContractExecutionFail,
    SmartContractParameter,
    SmartContractParameters,
    SocketAddr,
    SocketAddrHost,
    SocketAddrV4,
    SocketAddrV6,
    Sorting,
    String,
    StringPredicate,
    SumeragiParameter,
    SumeragiParameters,
    TimeEvent,
    TimeEventFilter,
    TimeInterval,
    TimeSchedule,
    TransactionEvent,
    TransactionEventFilter,
    TransactionLimitError,
    TransactionParameter,
    TransactionParameters,
    TransactionPayload,
    TransactionQueryOutput,
    TransactionRejectionReason,
    TransactionSignature,
    TransactionStatus,
    Transfer<Account, AssetDefinitionId, Account>,
    Transfer<Account, DomainId, Account>,
    Transfer<Asset, Metadata, Account>,
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
    TriggerNumberOfExecutionsChanged,
    TriggeringEventFilterBox,
    TypeError,
    Unregister<Account>,
    Unregister<Asset>,
    Unregister<AssetDefinition>,
    Unregister<Domain>,
    Unregister<Peer>,
    Unregister<Role>,
    Unregister<Trigger>,
    UnregisterBox,
    Upgrade,
    ValidationFail,
    Vec<BlockSignature>,
    Vec<CommittedTransaction>,
    Vec<EventBox>,
    Vec<EventFilterBox>,
    Vec<InstructionBox>,
    Vec<Parameter>,
    Vec<PeerId>,
    Vec<PredicateBox>,
    Vec<QueryOutputBox>,
    Vec<u8>,
    [u16; 8],
    [u8; 32],
    [u8; 4],
    u128,
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
            predicate::{
                numerical::{SemiInterval, SemiRange},
                string::StringPredicate,
                value::{AtIndex, Container, QueryOutputPredicate},
                GenericPredicateBox, NonTrivial, PredicateBox,
            },
            ForwardCursor, Pagination, QueryOutputBox, Sorting,
        },
        transaction::{
            error::TransactionLimitError, SignedTransactionV1, TransactionPayload,
            TransactionSignature,
        },
        BatchedResponse, BatchedResponseV1, Level,
    };
    pub use iroha_genesis::ExecutorPath;
    pub use iroha_primitives::{
        addr::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrHost, SocketAddrV4, SocketAddrV6},
        const_vec::ConstVec,
        conststr::ConstString,
        json::JsonString,
    };
    pub use iroha_schema::Compact;
}

#[cfg(test)]
mod tests {
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

        insert_into_test_map!(iroha_executor_data_model::permission::peer::CanUnregisterAnyPeer);
        insert_into_test_map!(iroha_executor_data_model::permission::domain::CanUnregisterDomain);
        insert_into_test_map!(
            iroha_executor_data_model::permission::domain::CanSetKeyValueInDomain
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::domain::CanRemoveKeyValueInDomain
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::domain::CanRegisterAccountInDomain
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::domain::CanRegisterAssetDefinitionInDomain
        );
        insert_into_test_map!(iroha_executor_data_model::permission::account::CanUnregisterAccount);
        insert_into_test_map!(
            iroha_executor_data_model::permission::account::CanSetKeyValueInAccount
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::account::CanRemoveKeyValueInAccount
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset_definition::CanUnregisterAssetDefinition
        );
        insert_into_test_map!(iroha_executor_data_model::permission::asset_definition::CanSetKeyValueInAssetDefinition);
        insert_into_test_map!(iroha_executor_data_model::permission::asset_definition::CanRemoveKeyValueInAssetDefinition);
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset::CanRegisterAssetWithDefinition
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset::CanUnregisterAssetWithDefinition
        );
        insert_into_test_map!(iroha_executor_data_model::permission::asset::CanUnregisterUserAsset);
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset::CanBurnAssetWithDefinition
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset::CanMintAssetWithDefinition
        );
        insert_into_test_map!(iroha_executor_data_model::permission::asset::CanMintUserAsset);
        insert_into_test_map!(iroha_executor_data_model::permission::asset::CanBurnUserAsset);
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition
        );
        insert_into_test_map!(iroha_executor_data_model::permission::asset::CanTransferUserAsset);
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset::CanSetKeyValueInUserAsset
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::asset::CanRemoveKeyValueInUserAsset
        );
        insert_into_test_map!(iroha_executor_data_model::permission::parameter::CanSetParameters);
        insert_into_test_map!(iroha_executor_data_model::permission::role::CanUnregisterAnyRole);
        insert_into_test_map!(
            iroha_executor_data_model::permission::trigger::CanRegisterUserTrigger
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::trigger::CanExecuteUserTrigger
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::trigger::CanUnregisterUserTrigger
        );
        insert_into_test_map!(iroha_executor_data_model::permission::trigger::CanMintUserTrigger);
        insert_into_test_map!(iroha_executor_data_model::permission::trigger::CanBurnUserTrigger);
        insert_into_test_map!(
            iroha_executor_data_model::permission::trigger::CanSetKeyValueInTrigger
        );
        insert_into_test_map!(
            iroha_executor_data_model::permission::trigger::CanRemoveKeyValueInTrigger
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
        <BTreeSet<SignedTransactionV1>>::update_schema_map(&mut schemas);
    }
}
