//! Iroha schema generation support library. Contains the `build_schemas` `fn`, which is the
//! function which decides which types are included in the schema.
//!
//! Dynamic native instructions need explicit roots because `InstructionBox` has opaque metadata.
//! Nested public types are expanded through their canonical `IntoSchema` implementations.
//! Regenerate the checked-in reference with `bash scripts/tests/consistency.sh --update schema`.
use iroha_data_model::{
    block::stream::{BlockMessage, BlockSubscriptionRequest},
    query::{QueryResponse, SignedQuery},
};
use iroha_schema::prelude::*;
use iroha_torii_shared::status::Status;
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
// Macro containing the list of all top-level schema types. It is used both to
// generate the schema map and to export the `map_all_schema_types!` macro for
// compile-time iteration.
macro_rules! schema_types {
    ($callback:ident) => {
        $callback! {
            Peer,
            SignedTransaction,
            SignedQuery,
            QueryResponse,
            iroha_data_model::query::dsl::CommittedTxPredicate,
            // Event stream
            EventMessage,
            EventSubscriptionRequest,
            // Block stream
            BlockMessage,
            BlockSubscriptionRequest,
            // Current Torii finality responses and challenge-bound node statements.
            iroha_data_model::sumeragi_finality::SumeragiFinalityProof,
            iroha_data_model::sumeragi_finality::SumeragiFinalityCheckpoint,
            iroha_data_model::sumeragi_finality::SumeragiCommitCheckpointV1,
            iroha_data_model::sumeragi_finality::SumeragiFinalityBundle,
            iroha_data_model::sumeragi_finality::SumeragiFinalityAttestation,
            // Independent private roots and body-free parent anchoring.
            iroha_data_model::block::consensus::SumeragiRootScope,
            iroha_data_model::block::consensus::PrivateRootFeePolicy,
            iroha_data_model::private_dataspace::PrivateDataspaceRegistration,
            iroha_data_model::private_dataspace::PrivateDataspaceAnchor,
            iroha_data_model::private_dataspace::PrivateDataspaceAnchorState,
            iroha_data_model::private_dataspace::PrivateDataspaceAdmissionPolicy,
            iroha_data_model::private_dataspace::PrivateDataspaceRecord,
            iroha_data_model::private_dataspace::PrivateDataspaceRegistry,
            iroha_data_model::private_dataspace::PrivateDataspaceRecordProof,
            iroha_data_model::isi::private_dataspace::RegisterPrivateDataspace,
            iroha_data_model::isi::private_dataspace::AnchorPrivateDataspace,
            // Native publication recovery checks retain authority-wide absence and exact row presence.
            iroha_data_model::isi::musubi::AdvanceMusubiPinOutboxV1,
            iroha_data_model::isi::musubi::CheckMusubiPinOutboxV1,
            iroha_data_model::smart_contract::ContractArtifactId,
            // Current finalized provider authority and signed discovery material.
            iroha_data_model::sorafs::provider_admission::discovery::ProviderDiscoveryProofV1,
            iroha_data_model::sorafs::stream_token_custody::proof::StreamTokenCustodyProofV1,
            iroha_data_model::sorafs::reserve::proof::ReservePolicyProofV1,
            iroha_data_model::sorafs::reserve::account_proof::ReserveAccountProofV1,
            iroha_data_model::sorafs::reserve::ReserveProviderAccountV1,
            iroha_data_model::sorafs::reserve::history::ReserveStateV1,
            // Reserve-account responses retain these originals as opaque byte frames.
            iroha_data_model::sorafs::pricing::ProviderCreditRecord,
            iroha_data_model::sorafs::capacity::CapacityDeclarationRecord,
            iroha_data_model::sorafs::pricing::PricingScheduleRecord,
            iroha_data_model::sorafs::provider_admission::discovery::account_read::RegisteredAccountReadV1,
            iroha_data_model::sorafs::stream_token_custody::history::StreamTokenCustodyControlIndexV1,
            iroha_data_model::sns::lease::SnsLeaseProofV1,
            iroha_data_model::sorafs::provider_admission::history::AdmissionHistoryRecordV1,
            // Native delivery recipes are public model values; no detached value grants authority.
            iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryIntentV1,
            iroha_data_model::sorafs::reputation::stream_token_delivery::StreamTokenReputationDeliveryDispositionV1,
            // Durable cross-service DA spool envelope.
            iroha_data_model::da::ingest::StoredDaReceipt,
            iroha_data_model::fastpq::TransferTranscript,
            iroha_data_model::fastpq::TransferTranscriptBundle,
            iroha_data_model::fastpq::FastpqTransitionBatch,
            iroha_data_model::fastpq::FastpqStateTransition,
            iroha_data_model::fastpq::FastpqBalanceKeyV1,
            // Nominal execution-effect candidate roots; not proof-dispatch registrations.
            iroha_data_model::fastpq::FastpqExecutionEffectStatementV1,
            iroha_data_model::fastpq::FastpqExecutionQuantityKeyV1,
            iroha_data_model::fastpq::FastpqOrdinaryCompactArtifactV1,
            iroha_data_model::fastpq::FastpqAxtCompactArtifactV1,
            iroha_data_model::fastpq::FastpqArtifactIdentityDescriptionV1,
            iroha_data_model::fastpq::FastpqOrdinarySourceStatementOpeningV1,
            iroha_data_model::fastpq::FastpqOrdinarySourceStatementArchiveV1,
            iroha_data_model::fastpq::FastpqSourceExecutionEntryV1,
            // Agreed source-capacity candidate; installation is owned by Core.
            iroha_data_model::parameter::FastpqSourcePolicyV1,
            // Torii qualification is an opaque response owner and needs an explicit public root.
            iroha_data_model::privacy::PrivacyExact12QualificationRecordV1,
            // Frozen public conviction context and immutable closed result are query/snapshot values.
            iroha_data_model::governance::conviction::PlainVotingContextV1,
            iroha_data_model::governance::conviction::PlainVotingResultV1,
            // Never referenced, but present in type signature. Like `PhantomData<X>`
            MerkleTree<SignedTransaction>,
            iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1,
            iroha_data_model::isi::kagemusha_wallet::load_finality::KagemushaWalletLoadReceiptV1,
            iroha_data_model::kagemusha::KagemushaWalletLoadFinalityV1,
            iroha_data_model::kagemusha::KagemushaWalletLedgerKeyV1,
            iroha_data_model::kagemusha::KagemushaWalletPayoutKeyV1,
            iroha_data_model::kagemusha::KagemushaWalletPayoutRecordV1,
            // Native proof payloads are opaque bytes in the generic envelope.
            iroha_data_model::zk::NativePipaRProofV1,
            // Default permissions
            iroha_executor_data_model::permission::peer::CanManagePeers,
            iroha_executor_data_model::permission::domain::CanRegisterDomain,
            iroha_executor_data_model::permission::domain::CanUnregisterDomain,
            iroha_executor_data_model::permission::domain::CanModifyDomainMetadata,
            iroha_executor_data_model::permission::account::CanRegisterAccount,
            iroha_executor_data_model::permission::account::CanUnregisterAccount,
            iroha_executor_data_model::permission::account::CanModifyAccountMetadata,
            iroha_executor_data_model::permission::asset_definition::CanUnregisterAssetDefinition,
            iroha_executor_data_model::permission::asset_definition::CanModifyAssetDefinitionMetadata,
            iroha_executor_data_model::permission::asset_definition::CanManageAssetDefinitionConfidentialPolicy,
            iroha_executor_data_model::permission::asset_definition::CanManageKagemushaWallet,
            iroha_executor_data_model::permission::asset_definition::CanManageAssetDefinitionAlias,
            iroha_executor_data_model::permission::asset::CanMintAssetWithDefinition,
            iroha_executor_data_model::permission::asset::CanBurnAssetWithDefinition,
            iroha_executor_data_model::permission::asset::CanTransferAssetWithDefinition,
            iroha_executor_data_model::permission::asset::CanMintAssetToAccount,
            iroha_executor_data_model::permission::asset::CanBurnAsset,
            iroha_executor_data_model::permission::asset::CanTransferAsset,
            iroha_executor_data_model::permission::nft::CanRegisterNft,
            iroha_executor_data_model::permission::nft::CanUnregisterNft,
            iroha_executor_data_model::permission::nft::CanTransferNft,
            iroha_executor_data_model::permission::nft::CanModifyNftMetadata,
            iroha_executor_data_model::permission::parameter::CanSetParameters,
            iroha_executor_data_model::permission::parameter::CanSetHijiriParameters,
            iroha_executor_data_model::permission::role::CanManageRoles,
            iroha_executor_data_model::permission::trigger::CanRegisterTrigger,
            iroha_executor_data_model::permission::trigger::CanExecuteTrigger,
            iroha_executor_data_model::permission::trigger::CanUnregisterTrigger,
            iroha_executor_data_model::permission::trigger::CanModifyTrigger,
            iroha_executor_data_model::permission::trigger::CanModifyTriggerMetadata,
            iroha_executor_data_model::permission::executor::CanUpgradeExecutor,
            iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode,
            iroha_executor_data_model::permission::smart_contract::CanGrantSmartContractCodeManagement,
            // Native bounded smart-contract artifact upload protocol
            iroha_data_model::isi::smart_contract_code::UploadSmartContractCodeChunk,
            iroha_data_model::isi::smart_contract_code::FinalizeSmartContractCodeUpload,
            iroha_data_model::isi::smart_contract_code::CancelSmartContractCodeUpload,
            // Native provider custody uses opaque framed Manifest policy/enrollment payloads.
            iroha_data_model::isi::sorafs::MutateSorafsStreamTokenCustody,
            iroha_data_model::sorafs::stream_token_custody::StreamTokenCustodyControlRecordV1,
            iroha_executor_data_model::permission::sorafs::CanManageSorafsStreamTokenCustody,
            // Native operation transitions and retained execution provenance are public V1 DTOs.
            iroha_data_model::isi::sorafs::MutateSorafsStreamTokenAuthority,
            iroha_data_model::sorafs::stream_token_authority::StreamTokenNativeOperationV1,
            iroha_executor_data_model::permission::sorafs::CanOperateSorafsStreamToken,
            iroha_executor_data_model::permission::sorafs::CanCheckSorafsStreamToken,
            // Native gateway quota, lease and callback claims; serving proof remains runtime-owned.
            iroha_data_model::isi::sorafs::MutateSorafsStreamTokenGateway,
            iroha_data_model::sorafs::stream_token_gateway::StreamTokenGatewayAdmissionReadbackV1,
            iroha_executor_data_model::permission::sorafs::CanManageSorafsStreamTokenGateway,
            iroha_executor_data_model::permission::sorafs::CanOperateSorafsStreamTokenGateway,
            iroha_executor_data_model::permission::sorafs::CanCheckSorafsStreamTokenGateway,
            // Signed-genesis admission, canonical capacity input and publisher state assertions.
            iroha_data_model::isi::sorafs::InitializeSorafsProviderAdmissionV1,
            iroha_data_model::isi::sorafs::RegisterCapacityDeclaration,
            iroha_data_model::isi::sorafs::AssertSorafsPublicationV1,
            // Native deployment authority and commitment-only retained histories.
            iroha_data_model::isi::sorafs::MutateSorafsFinalPromotionAuthority,
            // Registered for canonical V1 decoding; Core admission remains closed.
            iroha_data_model::isi::sorafs::MutateSorafsTopologyAuthority,
            iroha_executor_data_model::permission::sorafs::CanManageSorafsTopologyCustody,
            iroha_executor_data_model::permission::sorafs::CanOperateSorafsTopologyApproval,
            iroha_executor_data_model::permission::sorafs::CanCheckSorafsTopologyApproval,
            iroha_data_model::sorafs::final_promotion_authority::FinalPromotionCustodyRecordV1,
            iroha_data_model::sorafs::final_promotion_authority::FinalPromotionOperationRecordV1,
            iroha_executor_data_model::permission::sorafs::CanManageSorafsFinalPromotionCustody,
            iroha_executor_data_model::permission::sorafs::CanOperateSorafsFinalPromotion,
            iroha_executor_data_model::permission::sorafs::CanCheckSorafsFinalPromotion,
            // Distinct account custody reuses opaque canonical Manifest frames.
            iroha_data_model::isi::sorafs::MutateSorafsFinalPromotionAccountCustody,
            iroha_data_model::sorafs::final_promotion_account_custody::FinalPromotionAccountCustodyRecordV1,
            iroha_executor_data_model::permission::sorafs::CanManageSorafsFinalPromotionAccountCustody,
            iroha_executor_data_model::permission::sorafs::CanCheckSorafsFinalPromotionAccountCustody,
            // Multi-signature operations
            iroha_executor_data_model::isi::multisig::MultisigInstructionBox,
            // Multi-signature account metadata
            iroha_executor_data_model::isi::multisig::MultisigSpec,
            iroha_executor_data_model::isi::multisig::MultisigProposalValue,
            // It is exposed via Torii
            Status
        }
    };
}
/// Builds the schema for the current state of Iroha.
///
/// You should only include the top-level types because other types shall be included recursively.
pub fn build_schemas() -> MetaMap {
    use iroha_data_model::prelude::*;
    macro_rules! schemas {
        ($($t:ty),* $(,)?) => {{
            let mut out = MetaMap::new(); $(
                <$t as IntoSchema>::update_schema_map(&mut out);
            )*
            out
        }};
    }
    schema_types!(schemas)
}
schema_types!(types);
pub mod complete_data_model {
    //! Complete set of types participating in the schema
    pub use core::num::{NonZeroU16, NonZeroU32, NonZeroU64};
    pub use iroha_crypto::*;
    pub use iroha_data_model::{
        Level,
        account::NewAccount,
        asset::NewAssetDefinition,
        block::{
            BlockHeader, BlockPayload, BlockResult, BlockSignature, SignedBlock,
            error::BlockRejectionReason,
            stream::{BlockMessage, BlockSubscriptionRequest},
        },
        domain::NewDomain,
        events::pipeline::{BlockEventFilter, TransactionEventFilter},
        executor::{Executor, ExecutorDataModel},
        fastpq::{
            FastpqBalanceKeyV1, FastpqStateTransition, FastpqTransitionBatch,
            TransferDeltaTranscript, TransferTranscript, TransferTranscriptBundle,
        },
        ipfs::IpfsPath,
        isi::{
            InstructionType,
            error::{
                InstructionEvaluationError, InstructionExecutionError, InvalidParameterError,
                MathError, MintabilityError, Mismatch, RepetitionError, TypeError,
            },
        },
        parameter::{
            BlockParameter, BlockParameters, CustomParameter, CustomParameterId, Parameter,
            Parameters, SmartContractParameter, SmartContractParameters, SumeragiParameter,
            SumeragiParameters, TransactionParameter, TransactionParameters,
        },
        prelude::*,
        query::{
            CommittedTransaction, QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple,
            QueryRequestWithAuthority, QueryResponse, QuerySignature, QueryWithFilter,
            QueryWithParams, SignedQuery, SingularQueryOutputBox,
            dsl::{CompoundPredicate, PredicateMarker, SelectorMarker},
            error::{FindError, QueryExecutionFail},
            parameters::{ForwardCursor, QueryParams},
        },
        transaction::{
            TransactionSignature,
            error::TransactionLimitError,
            signed::{SignedTransaction, TransactionPayload},
        },
    };
    pub use iroha_genesis::{GenesisIvmAction, GenesisIvmTrigger, IvmPath};
    pub use iroha_primitives::{
        addr::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrHost, SocketAddrV4, SocketAddrV6},
        const_vec::ConstVec,
        conststr::ConstString,
        json::Json,
    };
    pub use iroha_schema::Compact;
    pub use iroha_torii_shared::status::{Status, Uptime};
    pub use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
}
#[cfg(test)]
mod tests {
    use super::{IntoSchema, complete_data_model::*};
    use iroha_schema::{MetaMap, Metadata};
    mod final_promotion;
    mod final_promotion_account_custody;
    mod musubi;
    mod privacy_qualification;
    mod private_dataspace;
    mod sorafs_publication;
    mod stream_token_authority;
    mod stream_token_custody;
    mod stream_token_gateway;
    mod topology_authority;
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
        insert_into_test_map!(iroha_executor_data_model::isi::multisig::MultisigRegister);
        insert_into_test_map!(iroha_executor_data_model::isi::multisig::MultisigPropose);
        insert_into_test_map!(iroha_executor_data_model::isi::multisig::MultisigApprove);
        insert_into_test_map!(iroha_executor_data_model::isi::multisig::MultisigCancel);
        map
    }
    // Stored metadata edges determine schema closure. Nominal type parameters
    // can be phantom (HashOf<T>) or fully represented by leaf metadata (Compact<T>).
    fn find_missing_schema_references(schemas: &MetaMap) -> BTreeMap<&str, Vec<core::any::TypeId>> {
        let registered: HashSet<_> = schemas.iter().map(|(id, _)| *id).collect();
        let mut missing = BTreeMap::new();
        // Iterating registered nodes once also handles cycles without recursion.
        for (_, entry) in schemas.iter() {
            let references: Vec<_> = match &entry.metadata {
                Metadata::Struct(fields) => {
                    fields.declarations.iter().map(|field| field.ty).collect()
                }
                Metadata::Tuple(fields) => fields.types.clone(),
                Metadata::Enum(variants) => variants
                    .variants
                    .iter()
                    .filter_map(|variant| variant.ty)
                    .collect(),
                Metadata::FixedPoint(fixed) => vec![fixed.base],
                Metadata::Array(array) => vec![array.ty],
                Metadata::Vec(vector) => vec![vector.ty],
                Metadata::Map(map) => vec![map.key, map.value],
                Metadata::Option(inner) => vec![*inner],
                Metadata::Result(result) => vec![result.ok, result.err],
                Metadata::Bitmap(bitmap) => vec![bitmap.repr],
                Metadata::Int(_) | Metadata::Float(_) | Metadata::String | Metadata::Bool => {
                    Vec::new()
                }
            };
            let absent: Vec<_> = references
                .into_iter()
                .filter(|id| !registered.contains(id))
                .collect();
            if !absent.is_empty() {
                missing.insert(entry.type_id.as_str(), absent);
            }
        }
        missing
    }
    #[test]
    fn native_reputation_delivery_schema_includes_exact_payload_and_signed_policy_origin() {
        use iroha_data_model::sorafs::reputation::{
            ReputationJournalPolicyOriginV1,
            stream_token_delivery::{
                StreamTokenReputationDeliveryDispositionV1, StreamTokenReputationDeliveryIntentV1,
                StreamTokenReputationDeliveryTemplateV1,
            },
        };
        let schemas = super::build_schemas();
        assert!(schemas.contains_key::<StreamTokenReputationDeliveryIntentV1>());
        assert!(schemas.contains_key::<StreamTokenReputationDeliveryDispositionV1>());
        assert!(schemas.contains_key::<StreamTokenReputationDeliveryTemplateV1>());
        assert!(schemas.contains_key::<ReputationJournalPolicyOriginV1>());
        assert!(schemas.contains_key::<iroha_data_model::transaction::TransactionPayload>());
    }
    #[test]
    fn stored_da_receipt_schema_includes_its_receipt_payload() {
        use iroha_data_model::da::ingest::{DaIngestReceipt, StoredDaReceipt};

        let schemas = super::build_schemas();
        assert!(schemas.contains_key::<StoredDaReceipt>());
        assert!(schemas.contains_key::<DaIngestReceipt>());
    }
    #[test]
    fn no_extra_or_missing_schemas() {
        // NOTE: Skipping Box<str> until schema generation supports unsized string boxes.
        let exceptions: [core::any::TypeId; 1] = [core::any::TypeId::of::<Box<str>>()];
        let schemas_types = super::build_schemas()
            .into_iter()
            .collect::<HashMap<_, _>>();
        let map_types = generate_test_map();
        let mut missing_types = HashSet::new();
        for (type_id, type_name) in &map_types {
            if !schemas_types.contains_key(type_id) && !exceptions.contains(type_id) {
                missing_types.insert(type_name);
            }
        }
        assert!(
            missing_types.is_empty(),
            "Missing types: {missing_types:#?}",
        );
    }
    #[test]
    fn no_missing_referenced_types() {
        let schemas = super::build_schemas();
        let missing_schemas = find_missing_schema_references(&schemas);
        assert!(
            missing_schemas.is_empty(),
            "Missing schemas: \n{missing_schemas:#?}"
        );
    }
    #[derive(IntoSchema)]
    struct ClosureRoot;

    #[derive(IntoSchema)]
    struct ClosurePeer;

    /// One metadata value per stored-reference shape, paired with the type ids
    /// it references (in slot order) using `byte` and `word` as referents.
    fn stored_reference_slot_cases(
        byte: core::any::TypeId,
        word: core::any::TypeId,
    ) -> Vec<(Metadata, Vec<core::any::TypeId>)> {
        use iroha_schema::{
            ArrayMeta, BitmapMeta, Declaration, EnumMeta, EnumVariant, FixedMeta, MapMeta,
            NamedFieldsMeta, ResultMeta, UnnamedFieldsMeta, VecMeta,
        };
        vec![
            (
                Metadata::Struct(NamedFieldsMeta {
                    declarations: vec![
                        Declaration {
                            name: "first".into(),
                            ty: byte,
                        },
                        Declaration {
                            name: "second".into(),
                            ty: word,
                        },
                    ],
                }),
                vec![byte, word],
            ),
            (
                Metadata::Tuple(UnnamedFieldsMeta {
                    types: vec![byte, word],
                }),
                vec![byte, word],
            ),
            (
                Metadata::Enum(EnumMeta {
                    variants: vec![
                        EnumVariant {
                            tag: "First".into(),
                            discriminant: 0,
                            ty: Some(byte),
                        },
                        EnumVariant {
                            tag: "Unit".into(),
                            discriminant: 1,
                            ty: None,
                        },
                        EnumVariant {
                            tag: "Second".into(),
                            discriminant: 2,
                            ty: Some(word),
                        },
                    ],
                }),
                vec![byte, word],
            ),
            (
                Metadata::FixedPoint(FixedMeta {
                    base: byte,
                    decimal_places: 4,
                }),
                vec![byte],
            ),
            (Metadata::Array(ArrayMeta { ty: byte, len: 32 }), vec![byte]),
            (Metadata::Vec(VecMeta { ty: byte }), vec![byte]),
            (
                Metadata::Map(MapMeta {
                    key: byte,
                    value: word,
                }),
                vec![byte, word],
            ),
            (Metadata::Option(byte), vec![byte]),
            (
                Metadata::Result(ResultMeta {
                    ok: byte,
                    err: word,
                }),
                vec![byte, word],
            ),
            (
                Metadata::Bitmap(BitmapMeta {
                    repr: byte,
                    masks: Vec::new(),
                }),
                vec![byte],
            ),
        ]
    }

    #[test]
    fn metadata_closure_checks_every_stored_reference_slot() {
        use core::any::TypeId;
        let byte = TypeId::of::<u8>();
        let word = TypeId::of::<u16>();
        let owner = <ClosureRoot as iroha_schema::TypeId>::id();
        for (metadata, expected) in stored_reference_slot_cases(byte, word) {
            let mut schemas = MetaMap::new();
            schemas.insert::<ClosureRoot>(metadata);
            let missing = find_missing_schema_references(&schemas);
            assert_eq!(missing.len(), 1);
            assert_eq!(missing.get(owner.as_str()), Some(&expected));
            u8::update_schema_map(&mut schemas);
            u16::update_schema_map(&mut schemas);
            assert!(find_missing_schema_references(&schemas).is_empty());
            // Each slot must be checked independently, including map values and errors.
            for missing_id in expected {
                let mut incomplete = schemas.clone();
                if missing_id == byte {
                    assert!(incomplete.remove::<u8>());
                } else {
                    assert_eq!(missing_id, word);
                    assert!(incomplete.remove::<u16>());
                }
                let missing = find_missing_schema_references(&incomplete);
                assert_eq!(missing.len(), 1);
                assert_eq!(missing.get(owner.as_str()), Some(&vec![missing_id]));
            }
        }
    }

    #[test]
    fn metadata_leaves_and_unit_payloads_have_no_stored_edges() {
        use iroha_schema::{EnumMeta, EnumVariant, FloatMode, IntMode, UnnamedFieldsMeta};
        for metadata in [
            Metadata::Int(IntMode::FixedWidth),
            Metadata::Int(IntMode::Compact),
            Metadata::Float(FloatMode::Binary32),
            Metadata::Float(FloatMode::Binary64),
            Metadata::String,
            Metadata::Bool,
            Metadata::Tuple(UnnamedFieldsMeta { types: Vec::new() }),
            Metadata::Enum(EnumMeta {
                variants: vec![EnumVariant {
                    tag: "Unit".into(),
                    discriminant: 0,
                    ty: None,
                }],
            }),
        ] {
            let mut schemas = MetaMap::new();
            schemas.insert::<ClosureRoot>(metadata);
            assert!(find_missing_schema_references(&schemas).is_empty());
        }
        let compact = Compact::<u32>::schema();
        assert!(!compact.contains_key::<u32>());
        assert!(find_missing_schema_references(&compact).is_empty());
    }

    #[test]
    fn metadata_closure_handles_cycles_and_reports_dangling_edges() {
        use core::any::TypeId;
        use iroha_schema::UnnamedFieldsMeta;
        let mut schemas = MetaMap::new();
        schemas.insert::<ClosureRoot>(Metadata::Option(TypeId::of::<ClosurePeer>()));
        schemas.insert::<ClosurePeer>(Metadata::Tuple(UnnamedFieldsMeta {
            types: vec![TypeId::of::<ClosureRoot>()],
        }));
        assert!(find_missing_schema_references(&schemas).is_empty());
        assert!(schemas.remove::<ClosurePeer>());
        let missing = find_missing_schema_references(&schemas);
        assert_eq!(missing.len(), 1);
        assert_eq!(
            missing.get(<ClosureRoot as iroha_schema::TypeId>::id().as_str()),
            Some(&vec![TypeId::of::<ClosurePeer>()])
        );
    }

    #[derive(iroha_schema::TypeId)]
    struct PhantomReferent;

    impl IntoSchema for PhantomReferent {
        fn type_name() -> String {
            "PhantomReferent".to_owned()
        }

        fn update_schema_map(_: &mut MetaMap) {
            panic!("schema closure must not expand a phantom hash referent");
        }
    }

    #[test]
    fn metadata_closure_checks_hash_storage_without_its_phantom_referent() {
        let mut schemas = HashOf::<PhantomReferent>::schema();
        assert!(!schemas.contains_key::<PhantomReferent>());
        assert!(find_missing_schema_references(&schemas).is_empty());
        assert!(schemas.remove::<Hash>());
        let missing = find_missing_schema_references(&schemas);
        assert_eq!(missing.len(), 1);
        assert_eq!(
            missing.get(<HashOf<PhantomReferent> as iroha_schema::TypeId>::id().as_str()),
            Some(&vec![core::any::TypeId::of::<Hash>()])
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
    #[test]
    fn current_finality_http_contracts_have_complete_schema_entries() {
        use iroha_data_model::{
            sumeragi::SumeragiStatus,
            sumeragi_finality::{
                FinalityValidator, ScheduleOutcome, ScheduledSlot, SumeragiFinalityAttestation,
                SumeragiFinalityAttestationBody, SumeragiFinalityBundle,
                SumeragiFinalityCheckpoint, SumeragiFinalityProof,
            },
        };
        let schemas = super::build_schemas();
        assert!(schemas.contains_key::<FinalityValidator>());
        assert!(schemas.contains_key::<SumeragiFinalityBundle>());
        assert!(schemas.contains_key::<ScheduleOutcome>());
        assert!(schemas.contains_key::<ScheduledSlot>());
        let decision = schemas
            .iter()
            .find(|(_, entry)| entry.type_name == "CheckpointDecision")
            .expect("checkpoint decision is recursively registered");
        let Metadata::Struct(decision) = &decision.1.metadata else {
            panic!("checkpoint decision must disclose its complete retained authority");
        };
        let fields = decision
            .declarations
            .iter()
            .map(|field| field.name.as_str())
            .collect::<Vec<_>>();
        assert!(fields.contains(&"schedule"));
        assert!(fields.contains(&"beacon"));
        assert!(!fields.contains(&"next_committee_digest"));
        let Some(Metadata::Struct(checkpoint)) = schemas.get::<SumeragiFinalityCheckpoint>() else {
            panic!("current compact checkpoint is absent from the canonical schema");
        };
        assert_eq!(
            checkpoint
                .declarations
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            [
                "network_id",
                "chain_id",
                "genesis_wire",
                "genesis_committee",
                "decisions",
                "tip"
            ]
        );
        assert!(schemas.contains_key::<SumeragiStatus>());
        let Some(Metadata::Struct(proof)) = schemas.get::<SumeragiFinalityProof>() else {
            panic!("current finality proof is absent from the canonical schema");
        };
        assert_eq!(
            proof
                .declarations
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["block_header", "block_wire", "committee"]
        );
        let Some(Metadata::Struct(body)) = schemas.get::<SumeragiFinalityAttestationBody>() else {
            panic!("current finality attestation body is absent from the canonical schema");
        };
        assert_eq!(
            body.declarations
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            [
                "challenge",
                "observed_at_unix_ms",
                "network_id",
                "node_id",
                "node_fingerprint",
                "build_fingerprint",
                "config_fingerprint",
                "genesis_block_hash",
                "genesis_finality_proof",
                "status",
                "finality_proof"
            ]
        );
        let Some(Metadata::Struct(attestation)) = schemas.get::<SumeragiFinalityAttestation>()
        else {
            panic!("current finality attestation is absent from the canonical schema");
        };
        assert_eq!(
            attestation
                .declarations
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            ["body", "signature"]
        );
        assert!(find_missing_schema_references(&schemas).is_empty());
    }

    #[test]
    fn public_conviction_context_and_result_have_complete_schema_entries() {
        use iroha_data_model::governance::conviction::{
            PlainConvictionPolicyV1, PlainVotingContextV1, PlainVotingDecisionV1,
            PlainVotingResultV1,
        };
        let schemas = super::build_schemas();
        assert!(schemas.contains_key::<PlainVotingContextV1>());
        assert!(schemas.contains_key::<PlainVotingResultV1>());
        assert!(schemas.contains_key::<PlainVotingDecisionV1>());
        let Some(Metadata::Struct(policy)) = schemas.get::<PlainConvictionPolicyV1>() else {
            panic!("frozen public conviction policy is absent from the canonical schema");
        };
        assert_eq!(
            policy
                .declarations
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            [
                "asset_definition_id",
                "asset_scale",
                "conviction_step_blocks",
                "max_conviction",
                "approval_threshold_numerator",
                "approval_threshold_denominator",
                "minimum_turnout",
                "minimum_bond",
                "bond_escrow_account",
                "slash_receiver_account",
            ]
        );
    }

    #[test]
    fn fastpq_types_have_schema_entries() {
        use iroha_data_model::fastpq::{
            FastpqBalanceKeyV1, FastpqTransitionBatch, TransferTranscript, TransferTranscriptBundle,
        };
        let schemas = super::build_schemas();
        let has_transcript = schemas.contains_key::<TransferTranscript>();
        let has_bundle = schemas.contains_key::<TransferTranscriptBundle>();
        let has_batch = schemas.contains_key::<FastpqTransitionBatch>();
        assert!(has_transcript, "TransferTranscript missing from schema map");
        assert!(
            has_bundle,
            "TransferTranscriptBundle missing from schema map"
        );
        assert!(has_batch, "FastpqTransitionBatch missing from schema map");
        assert!(
            schemas.contains_key::<FastpqBalanceKeyV1>(),
            "FastpqBalanceKeyV1 missing from schema map"
        );
        assert!(
            schemas.contains_key::<iroha_data_model::fastpq::FastpqOrdinaryCompactArtifactV1>()
        );
        assert!(schemas.contains_key::<iroha_data_model::fastpq::FastpqAxtCompactArtifactV1>());
        assert!(
            schemas.contains_key::<iroha_data_model::fastpq::FastpqArtifactIdentityDescriptionV1>()
        );
        assert!(
            schemas.contains_key::<iroha_data_model::fastpq::FastpqPublicTransferStatementV1>()
        );
        assert!(
            schemas.contains_key::<iroha_data_model::fastpq::FastpqExecutionEffectStatementV1>()
        );
        assert!(schemas.contains_key::<iroha_data_model::fastpq::FastpqExecutionQuantityKeyV1>());
        assert!(
            schemas
                .contains_key::<iroha_data_model::fastpq::FastpqOrdinarySourceStatementOpeningV1>()
        );
        assert!(
            schemas.contains_key::<iroha_data_model::fastpq::FastpqOrdinarySourceStatementLeafV1>()
        );
        assert!(
            schemas
                .contains_key::<iroha_data_model::fastpq::FastpqOrdinarySourceStatementManifestV1>(
                )
        );
        assert!(
            schemas
                .contains_key::<iroha_data_model::fastpq::FastpqOrdinarySourceStatementArchiveV1>()
        );
        assert!(schemas.contains_key::<iroha_data_model::fastpq::FastpqSourceStatementContextV1>());
        assert!(schemas.contains_key::<iroha_data_model::fastpq::FastpqSourceRouteV1>());
        assert!(schemas.contains_key::<iroha_data_model::fastpq::FastpqSourceLaneV1>());
        assert!(schemas.contains_key::<iroha_data_model::fastpq::FastpqSourceExecutionKindV1>());
        assert!(schemas.contains_key::<iroha_data_model::fastpq::FastpqSourceExecutionEntryV1>());
        assert!(schemas.contains_key::<iroha_data_model::parameter::FastpqSourcePolicyV1>());
        assert!(schemas.contains_key::<iroha_data_model::parameter::FastpqSourceLimitsV1>());
        assert!(
            schemas.contains_key::<iroha_data_model::parameter::FastpqMandatorySourcePolicyV1>()
        );
    }
}
