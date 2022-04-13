//! Exports `generate_map()` function and contains implementation details for it

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

/// Neotype which has `type_name()` method when `T` implements [`IntoSchema`]
struct WithTypeName<T>(std::marker::PhantomData<T>);

impl<T: IntoSchema> WithTypeName<T> {
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
        #[allow(trivial_casts)]
        BTreeMap::from([
            $((
                WithTypeName::<$t>::type_name().unwrap_or(stringify!($t).to_owned()),
                <$t as DumpDecoded>::dump_decoded as DumpDecodedPtr
            )),*
        ])
    };
}

/// Generate map with types and `dump_decoded()` ptr
#[allow(clippy::too_many_lines)]
pub fn generate_map() -> DumpDecodedMap {
    generate_map! {
        Account,
        AccountEvent,
        AccountEventFilter,
        AccountFilter,
        AccountId,
        Action,
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
        BlockRejectionReason,
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
        FindAccountById,
        FindAccountKeyValueByIdAndKey,
        FindAccountsByDomainId,
        FindAccountsByName,
        FindAllAccounts,
        FindAllAssets,
        FindAllAssetsDefinitions,
        FindAllDomains,
        FindAllParameters,
        FindAllPeers,
        FindAllRoles,
        FindAssetById,
        FindAssetDefinitionKeyValueByIdAndKey,
        FindAssetKeyValueByIdAndKey,
        FindAssetQuantityById,
        FindAssetsByAccountId,
        FindAssetsByAssetDefinitionId,
        FindAssetsByDomainId,
        FindAssetsByDomainIdAndAssetDefinitionId,
        FindAssetsByName,
        FindDomainById,
        FindDomainKeyValueByIdAndKey,
        FindPermissionTokensByAccountId,
        FindRolesByAccountId,
        FindTransactionByHash,
        FindTransactionsByAccountId,
        GenesisDomain,
        GrantBox,
        Greater,
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
        Not,
        NotPermittedFail,
        Or,
        Pair,
        Payload,
        Peer,
        PeerEvent,
        PeerEventFilter,
        PeerFilter,
        PeerId,
        PendingTransactions,
        PermissionToken,
        PipelineEntityKind,
        PipelineEvent,
        PipelineEventFilter,
        PipelineStatus,
        QueryBox,
        QueryRequest,
        QueryResult,
        RaiseTo,
        RegisterBox,
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
        SignatureCheckCondition,
        SignedQueryRequest,
        Subtract,
        TimeEvent,
        TimeEventFilter,
        TimeInterval,
        TimeSchedule,
        Transaction,
        TransactionRejectionReason,
        TransactionValue,
        TransferBox,
        Trigger,
        TriggerEvent,
        TriggerEventFilter,
        TriggerFilter,
        TriggerId,
        UnregisterBox,
        UnsatisfiedSignatureConditionFail,
        ValidTransaction,
        VersionedPendingTransactions,
        VersionedQueryResult,
        VersionedRejectedTransaction,
        VersionedSignedQueryRequest,
        VersionedTransaction,
        VersionedValidTransaction,
        WasmExecutionFail,
        Where,
    }
}
