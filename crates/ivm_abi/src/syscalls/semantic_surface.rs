//! Semantic ABI descriptor construction for queries, calls and numeric operators.
//!
//! These records are the single input to the parent's canonical ABI encoder.
//! The owner preserves exact field ordering, nominal public schemas, operator
//! legality and numeric semantics; it introduces no alternate ABI or decoder.

use super::*;

fn core_query_projection_surface_v1() -> Vec<AbiCoreQueryProjectionSurface> {
    use crate::core_query::CoreQueryEntityTagV1 as Tag;
    vec![
        AbiCoreQueryProjectionSurface {
            name: "kotodama::AccountView",
            entity_tag: Tag::Account.as_u64(),
            fields: vec![
                AbiNamedTypeSurface {
                    name: "id",
                    ty: "AccountId",
                },
                AbiNamedTypeSurface {
                    name: "metadata",
                    ty: "Json",
                },
            ],
        },
        AbiCoreQueryProjectionSurface {
            name: "kotodama::AssetView",
            entity_tag: Tag::Asset.as_u64(),
            fields: vec![
                AbiNamedTypeSurface {
                    name: "id",
                    ty: "AssetId",
                },
                AbiNamedTypeSurface {
                    name: "amount",
                    ty: "Quantity",
                },
            ],
        },
        AbiCoreQueryProjectionSurface {
            name: "kotodama::AssetDefinitionView",
            entity_tag: Tag::AssetDefinition.as_u64(),
            fields: vec![
                AbiNamedTypeSurface {
                    name: "id",
                    ty: "AssetDefinitionId",
                },
                AbiNamedTypeSurface {
                    name: "name",
                    ty: "String",
                },
                AbiNamedTypeSurface {
                    name: "description",
                    ty: "Option<String>",
                },
                AbiNamedTypeSurface {
                    name: "owned_by",
                    ty: "AccountId",
                },
                AbiNamedTypeSurface {
                    name: "total_quantity",
                    ty: "Quantity",
                },
                AbiNamedTypeSurface {
                    name: "numeric_scale",
                    ty: "Option<int>",
                },
                AbiNamedTypeSurface {
                    name: "metadata",
                    ty: "Json",
                },
            ],
        },
        AbiCoreQueryProjectionSurface {
            name: "kotodama::DomainView",
            entity_tag: Tag::Domain.as_u64(),
            fields: vec![
                AbiNamedTypeSurface {
                    name: "id",
                    ty: "DomainId",
                },
                AbiNamedTypeSurface {
                    name: "owned_by",
                    ty: "AccountId",
                },
                AbiNamedTypeSurface {
                    name: "metadata",
                    ty: "Json",
                },
            ],
        },
        AbiCoreQueryProjectionSurface {
            name: "kotodama::NftView",
            entity_tag: Tag::Nft.as_u64(),
            fields: vec![
                AbiNamedTypeSurface {
                    name: "id",
                    ty: "NftId",
                },
                AbiNamedTypeSurface {
                    name: "owned_by",
                    ty: "AccountId",
                },
                AbiNamedTypeSurface {
                    name: "content",
                    ty: "Json",
                },
            ],
        },
    ]
}
fn numeric_operator_surface_v1() -> Vec<AbiNumericOperatorSurface> {
    const TYPES: [&str; 3] = ["int", "decimal", "quantity"];
    const ARITHMETIC: [&str; 5] = ["+", "-", "*", "/", "%"];
    const COMPARISONS: [&str; 6] = ["==", "!=", "<", "<=", ">", ">="];
    const INVALID: (&str, &str) = ("invalid", "compile-time-error:operator-not-defined");
    let mut rows = Vec::with_capacity(102);
    for ty in TYPES {
        let (allowed, result, semantics) = match ty {
            "int" => (true, "int", "checked-negation;mantissa-overflow-on-min-int"),
            "decimal" => (
                true,
                "decimal",
                "checked-exact-negation;canonicalize-then-final-domain-check",
            ),
            "quantity" => (
                false,
                INVALID.0,
                "compile-time-error:quantity-is-nonnegative",
            ),
            _ => unreachable!("closed numeric type inventory"),
        };
        rows.push(AbiNumericOperatorSurface {
            operator: "unary-",
            lhs: ty,
            rhs: "none",
            allowed,
            result,
            semantics,
        });
    }
    for operator in ARITHMETIC {
        for lhs in TYPES {
            for rhs in TYPES {
                let allowed = matches!(
                    (operator, lhs, rhs),
                    (_, "int", "int")
                        | ("+" | "-" | "*" | "/", "decimal", "decimal")
                        | ("+" | "-", "quantity", "quantity")
                        | ("*" | "/", "quantity", "decimal")
                        | ("/", "quantity", "quantity")
                );
                let (result, semantics) = if !allowed {
                    INVALID
                } else {
                    match (operator, lhs, rhs) {
                        ("+" | "-" | "*", "int", "int") => {
                            ("int", "exact-checked-integer-arithmetic")
                        }
                        ("/", "int", "int") => ("int", "checked-quotient-truncates-toward-zero"),
                        ("%", "int", "int") => (
                            "int",
                            "checked-remainder-sign-is-dividend;paired-quotient-must-fit",
                        ),
                        ("+" | "-", "decimal", "decimal") => (
                            "decimal",
                            "align-scale-exactly;canonicalize;check-final-domain",
                        ),
                        ("*", "decimal", "decimal") => (
                            "decimal",
                            "multiply-exactly;canonicalize;check-final-domain",
                        ),
                        ("/", "decimal", "decimal") => (
                            "decimal",
                            "exact-terminating-division-only;canonical-scale-at-most-28",
                        ),
                        ("+", "quantity", "quantity") => {
                            ("quantity", "exact-checked-nonnegative-addition")
                        }
                        ("-", "quantity", "quantity") => (
                            "quantity",
                            "exact-subtraction;negative-result-is-quantity-underflow",
                        ),
                        ("*", "quantity", "decimal") => (
                            "quantity",
                            "exact-product;negative-result-is-negative-quantity;canonical-final-domain-check",
                        ),
                        ("/", "quantity", "decimal") => (
                            "quantity",
                            "exact-terminating-division;negative-result-is-negative-quantity",
                        ),
                        ("/", "quantity", "quantity") => {
                            ("decimal", "exact-terminating-dimensionless-ratio")
                        }
                        _ => unreachable!("allowed arithmetic row has semantics"),
                    }
                };
                rows.push(AbiNumericOperatorSurface {
                    operator,
                    lhs,
                    rhs,
                    allowed,
                    result,
                    semantics,
                });
            }
        }
    }
    for operator in COMPARISONS {
        for lhs in TYPES {
            for rhs in TYPES {
                let allowed = lhs == rhs;
                let semantics = if !allowed {
                    INVALID.1
                } else if lhs == "quantity" {
                    "compare-canonical-nonnegative-mathematical-values"
                } else {
                    "compare-canonical-mathematical-values"
                };
                rows.push(AbiNumericOperatorSurface {
                    operator,
                    lhs,
                    rhs,
                    allowed,
                    result: if allowed { "bool" } else { INVALID.0 },
                    semantics,
                });
            }
        }
    }
    debug_assert_eq!(rows.len(), 102);
    rows
}
pub(super) fn semantic_abi_surface_v1() -> Result<
    (
        Vec<AbiCoreQueryProjectionSurface>,
        AbiQueryPageSurface,
        AbiEntrypointSurface,
        AbiNumericSurface,
    ),
    AbiSurfaceError,
> {
    use crate::{
        core_query::QUERY_PAGE_CAPACITY_V1,
        entrypoint::{
            MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH, MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES,
            MAX_ENTRYPOINT_LIST_CAPACITY_V1, MIN_ENTRYPOINT_LIST_CAPACITY_V1,
        },
        pointer_abi::PointerType,
    };
    let query_page_capacity =
        u8::try_from(QUERY_PAGE_CAPACITY_V1).map_err(|_| AbiSurfaceError::SurfaceTooLarge)?;
    let max_schema_nodes = u64::try_from(MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES)
        .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?;
    let max_schema_depth = u64::try_from(MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH)
        .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?;
    let int_pointer_type_id = PointerType::Int as u16;
    let decimal_pointer_type_id = PointerType::Decimal as u16;
    let quantity_pointer_type_id = PointerType::Quantity as u16;
    Ok((
        core_query_projection_surface_v1(),
        AbiQueryPageSurface {
            name: "kotodama::QueryPage",
            fields: vec![
                AbiNamedTypeSurface {
                    name: "items",
                    ty: "List<T,64>",
                },
                AbiNamedTypeSurface {
                    name: "next_offset",
                    ty: "Option<int>",
                },
            ],
            items_capacity: query_page_capacity,
            next_offset_semantics: "present-iff-another-canonical-page-exists;some-requires-nonempty-items;nonnegative;not-less-than-item-count;from-window=offset+item-count-with-checked-i64",
            item_ordering: "canonical-entity-id-ascending",
            account_filter: "CORE_QUERY_PAGE:r13=public-nullable-AccountId;zero=unfiltered;nonnull-only-Asset-tag;FindAssetsByAccountId-before-offset-and-limit;ordinary-query-authority-and-executor-permissions;gas-add32+account-payload-bytes-before-decode",
        },
        AbiEntrypointSurface {
            schema_version: 1,
            call_table_layout: "all-functions:r10=argument-table-base,r11=exact-argument-words,r12=caller-owned-result-base,r13=exact-result-capacity;return:r10=same-result-base,r11=exact-initialized-result-words;aligned8-little-endian-u64-slots;empty-arguments=(0,0);Unit-and-empty-named-struct=one-zero-slot;empty-struct=empty-schema-bound-atom-tape;nonempty-struct-and-tuple-fields-flatten-in-declaration-order;sum-and-list=one-active-only-handle;one-canonical-CNTR-callables-vector-sorted-by-entry-pc;callable={entry_pc:u64,frame_bytes:u32,arguments:CallSchemaV1,results:CallSchemaV1};CallSchemaV1=magic43533100+fixed-u64-node-count+complete-preorder-tape;node-tag=u8:Struct0,Tuple1,Option2,Result3,List4,Leaf5,Unit6,Error7,StateCursor8,StateRoot9,Pointer10,SecretNumeric11,Enum12;Struct=Norito-String+Norito-Vec<String>;Tuple=u32;List=u8;Leaf=u8-kind0..13;StateCursor=length-prefixed-complete-Norito-EntrypointValueTypeV1-key-schema;Error-and-Enum=length-prefixed-complete-distinct-Norito-descriptor;Pointer-and-SecretNumeric=u16;child-lengths-use-advertised-Norito-layout-flags;no-node-field-or-vector-span-wrappers;argument-forest;single-result-tree;nodes=Struct{name,ordered-fields},Tuple(u32),Option,Result(ok,err),List{capacity:u8},Leaf(EntrypointValueKindV1),Unit,Error(ContractErrorTypeDescriptor),StateCursor(EntrypointValueTypeV1),StateRoot,Pointer(internal-type:u16),SecretNumeric(numeric-type:u16),Enum(ContractEnumTypeDescriptorV1);inline-children-no-references;private-node-limit250000;depth256;private-and-public-reserved-nominals-match-canonical-shape;schema-derived-table-counts;active-recursive-payload-validation;gas-before-node=1,occupied-word=8,sum-tag=8,list-header=16,canonical-pointer-staged;inactive-and-list-slack-not-visited;full-owned-heap-footprint;exact-list-capacity;state-cursor-frame-key-schema-hash-matches-complete-scalar-or-nested-tuple-node;embedded-key-nodes-and-depth-count-in-outer-budget;public-root-schemas-match-exactly;no-register-value-call-path",
            call_frame_checks: "admission-exact-entrypoint-and-direct-call-roots;acyclic-direct-calls;no-cross-root-ordinary-control-flow;frame-alignment16;frame-max4MiB;root-tables-owned-heap-current-invocation;root-result-reservation-gas=8-times-result-word-count;frame-validation-gas=frame-bytes/8+result-word-count;typed-slot-validation-gas=8-per-word-before-read;public-pointer-validation-gas=16+39+payload-bytes-before-hash;secret-numeric-validation-gas=16+39+declared-type-max-frame-bytes;sum-header-gas=8;list-header-gas=16;root-arguments-prepared-once-before-guest-even-if-unused;root-default-input-route=GET_PUBLIC_INPUT-entrypoint_argument_record-NoritoBytes-with-opcode-and-host-gas;trigger_event_json=actual-firing-Json-independent-of-prepared-root-arguments;no-argument-record-fallback-to-trigger-event-key;internal-tables-disjoint-aligned-caller-frame;SP-on-call=caller-frame-start;entry-counts-exact-and-descriptor-registers-public;argument-slots-all-bytes-initialized-with-exact-role-tags;fresh-callee-frame-initialization;stack-access=own-frame-or-read-only-incoming-arguments-or-write-only-result-table;result-byte-coverage-reset-per-call;return=trusted-pc,restored-entry-SP,same-resultbase,exact-count,all-result-bytes-initialized,canonical-role-values-and-tags;no-callee-stack-result-escape",
            max_call_words: crate::call::MAX_CALL_WORDS_V1 as u64,
            value_utilities: "encode=canonical-framed-EntrypointReturnRecordV1-with-return-schema-hash;public-schema-excludes-cursors;owned-heap-word-table;max-schema64KiB;max-payload=MAX_ENTRYPOINT_RETURN_RECORD_BYTES;concat=exact-left-then-right-Blob-bytes;utf8=valid-same-pointer-or-zero;scalar-text=canonical-Display-full-width;string-length=UTF8-bytes;gas=32+schema-bytes+value-quote+output-bytes;concat-gas=32+2*combined-bytes;utf8-gas=32+bytes;original-pool-scratch;preflight-before-copy-and-publication;quote-failures-retain-cumulative-visited-gas-capped-by-allowance;nested-arguments-add-prior-fields;completed-return-validation=32+8-per-initialized-public-slot-before-traversal",
            context_address: "SYSVAR_CONTRACT_ADDRESS=Blob-canonical-ContractAddress-UTF8-literal-exactly60bytes;identical-address-input-to-imported-ContractRef-at-and-CALL_CONTRACT;no-Norito-ContractAddress-envelope;absent-context=zero;gas=G_sysvar+literal-bytes;quote-includes-published-bytes",
            unit_layout: "Unit=one-public-zero-scalar-word;Unit-atom-has-no-payload;JSON-null;nonzero-word-rejected;also-valid-in-sums-lists-state;every-public-CNTR-entrypoint-requires-return_type-and-return_schema;omitted-source-return-annotation=type-()-and-Unit-schema;absent-return-descriptor-invalid;nested-calls-always-return-schema-hashed-EntrypointReturnRecordV1-including-Unit-null",
            vrf_epoch_seed: "0x7E;r10=public-u64-epoch;exact-committed-world-snapshot-lookup;nullable-Blob-exactly32bytes;absence=zero;no-latest-fallback;r11-unchanged;source=epoch:int->Option<bytes>-with-checked-u64-boundary;gas=G_state_query+8+32-if-found-else-G_state_query+8;gas-before-output-allocation;fixed-stack-envelope;typed-guest-memory-fault;local-allocation-refusal-deferred",
            struct_identity: "local-source-type-name-or-exact-locked-package::SourceUnit::Struct-or-local::<64lowerhex>::SourceUnit::Struct;local-module-digest=Iroha-Hash-v1(domain-iroha:kotodama:local-module:v1\0+u64LE-byte-length-prefixed-fields(root,root-seiyaku-name,canonical-project-relative-module-path));local-module-digest-excludes-source-content-import-alias-absolute-path-source-id-and-discovery-order;max1024-ASCII-bytes;package=slash-separated-components-with-optional-single-@revision;component=[A-Za-z0-9_][A-Za-z0-9_.-]*;unit-and-struct=canonical-unreserved-source-type-identifiers;qualified-linker-private-substring-rejected;no-alias-or-revision-normalization;public-and-durable-schema-hashes-bind-exact-name;plain-core-view-and-page-names-require-reserved-schema-shape",
            error_layout: "Error=one-public-u32-scalar-word;ErrorCode-atom-u32-code;JSON-exact-symbolic-variant-name;nonzero-enum-local-code-must-belong-to-schema;descriptor={identity:String,variants:Vec<{name:String,code:u32}>};identity=root-contract-unit-enum-or-stable-locked-package-unit-enum-or-local::<64lowerhex>::SourceUnit::Enum;local-module-identity-uses-the-struct-identity-digest-provenance-and-exclusions;not-linker-ordinal;canonical-increasing-codes-and-unique-names;max256-variants;schema-hash=Iroha-Hash(domain-iroha:kotodama:error-schema:v1\0+Norito-encoded-ordered-variants);identity-is-bound-separately;every-boundary-state-descriptor-exactly-in-signed-CNTR;max256-error-types;CONTRACT_ABORT-descriptor-frame-max65536-bytes-and-CNTR-member-before-rejection;presentation-catalog={error_type:String,code:u32,message:String};sorted-unique-identity-code-and-declared-variant;message-nonblank-max4096-UTF8-bytes;presentation-excluded-from-error-state-and-boundary-schema-hashes;CONTRACT_ABORT-gas=G_abort+descriptor-bytes+selected-message-UTF8-bytes;rejection-carries-authenticated-origin-contract-variant-identity-schemahash-code-optional-message-through-nesting",
            enum_layout: "Enum=one-public-nonzero-u32-scalar-word;public-schema-node-tag9;public-word-kind-tag6;public-EnumCode-atom-tag6;call-node-tag12;embedded-state-type-tag23;state-schema-node-tag9;state-EnumCode-atom-tag6;JSON-exact-symbolic-variant-name-only;descriptor=ContractEnumTypeDescriptorV1{identity:String,variants:Vec<ContractEnumVariantDescriptorV1{name:String,code:u32}>};stable-nominal-identity-bound-separately;nonempty-max256-variants;canonical-increasing-nonzero-codes-and-unique-names;schema-hash=Iroha-Hash(domain-iroha:kotodama:enum-schema:v1\0+Norito-encoded-ordered-variants);schema-membership-required-at-every-boundary;distinct-from-Error-even-for-identical-identity-and-variants;no-error-catalog-or-contract-abort-membership;valid-in-options-results-products-lists-and-durable-state",
            sum_json: "typed-JSON-uses-exact-single-key-tagged-objects;Option::some(value)={some:value};Option::none()={none:true};Result::ok(value)={ok:value};Result::err(value)={err:value};Some(Unit)={some:null}-distinct-from-None;nested-tags-preserved;no-flattened-or-nullable-Option-form;consistent-public-arguments-returns-and-durable-state-projection;JSON_BUILD-preserves-the-same-Option-tags-for-admitted-native-values;JSON_BUILD-rejects-implicit-Result",
            invocation_outcome: "CALL_CONTRACT=0xA9-only;binding=canonical-framed-Norito-ContractCallBindingV1{code_hash:Hash,entrypoint:u32};binding-max128bytes;exact-live-code-hash-and-CNTR-ordinal-before-effects;r10=Blob-contract-address,r11=NoritoBytes-binding,r12=argument-table-base,r13=exact-argument-words,r14=result-table-base,r15=exact-result-words;no-arguments=(0,0);Unit-result=one-zero-word;schema-bound-funded-capture-and-transfer;no-raw-selector-or-quantity-profile;outer-Result::err=rollback-frame-and-successful-descendants;error-return-is-recoverable;reads-and-consumed-gas-retained;nested-error-values-are-data;active-contract-address-reentry-rejected-including-views;max-nesting32;immediate-caller=parent-contract-subject",
            fault_schema_hash: norito::schema::identity::frame_hash::<
                iroha_data_model::executor::fault::IvmFaultV1,
            >(),
            fault_layout: "IvmFaultV1={kind:IvmFaultKindV1,site:IvmFaultSiteV1};IvmFaultSiteV1={code_hash:Hash,selector:IvmInvocationSelectorV1,position:IvmFaultPositionV1};selector=Generic0|Entrypoint1(u32-CNTR-ordinal);position=Initialization0|Execute1{pc_offset:u64-executable-relative}|ReturnValidation2;kind=OutOfGas0|MemoryLimitExceeded1|MemoryAccessViolation2|MisalignedAccess3|MemoryOutOfBounds4|DecodeError5|InvalidOpcode6|UnknownSyscall7|UnsupportedSyscall8|GasCostOverflow9|Numeric10(NumericFaultV1)|PointerAbi11(PointerAbiFaultV1)|AssertionFailed12|ExceededMaxCycles13|InvalidMetadata14|InvalidVectorLength15|MissingHalt16|VectorExtensionDisabled17|ZkExtensionDisabled18|NullifierAlreadyUsed19|PermissionDenied20|PrivacyViolation21|RegisterOutOfBounds22|NoritoInvalid23|AbiTypeNotAllowed24|HostOutputItemsExceeded25|HostOutputBytesExceeded26|AmxBudgetExceeded27|ReentrantCall28|CallDepthExceeded29;numeric-and-pointer-tags=canonical-numeric-surface;JSON-enums=kind+value;structs=closed-required-fields",
            fault_semantics: "bounded-fixed-size-canonical-fault;code-hash=complete-admitted-artifact-or-generic-raw-code;deepest-origin-survives-nested-unwind;parent-CALL-never-overwrites-child-origin;initialization-and-return-validation-have-no-invented-PC;execute-PC-may-equal-code-end-only-for-MissingHalt;no-source-text-or-local-path-in-consensus;source-symbolization-requires-exact-artifact-hash;allocation-and-execution-deferrals-never-consensus-faults;host-unavailability-and-metering-invariants-never-consensus-faults;contract-rejection-and-recoverable-Result-remain-distinct;fault-rollback-retains-reads-and-consumed-gas",
            event_layout: "required-events-table-after-permissions;ContractEventDescriptorV1(name:Name,payload_type:EntrypointValueTypeV1);strict-sorted-unique-canonical-names;max-declarations=256;max-canonical-table-bytes=65536;root=Struct-qualified-name-final-double-colon-component-equals-event-name;empty-Struct-allowed;Json-and-StateCursor-forbidden-recursively;ContractEmissionV1(contract:ContractAddress,code_hash:Hash,entrypoint:u32,event:u32,caller:AccountId,definition:ContractEventDescriptorV1,payload:EntrypointReturnRecordV1);TransactionResult-fourth-field=required-native-emission-vector",
            event_semantics: "EMIT_CONTRACT_EVENT=0xAA;r10=authenticated-event-ordinal;r11=public-owned-HEAP-word-table-base;r12=exact-schema-word-count;gas=32+canonical-schema-bytes+32-per-active-schema-node+retained-full-TLV-envelope-bytes;prepare-authenticates-descriptors-without-value-traversal;reserve-available-before-execution;quote-and-capture-under-reserved-remaining-gas;failed-traversal-retains-cumulative-work;source-TLV-bytes-retained-exactly;guest-cannot-author-origin-or-definition;generic-and-view-denied;single-transaction-emission-journal;mixed-instruction-emission-queue-retains-order-through-synchronous-callbacks;all-effects-retain-immutable-authorization-chain;Result-err-and-trap-roll-back-affected-branch-events;root-output-drains-once-after-callbacks;rejected-output-has-empty-events;cursor=(block-hash,actual-root-output-index,emission-index);local-allocation-refusal-is-deferred-never-contract-fault",
            authorization: "required-authenticated-permission-table;sorted-unique-names;scope=Instance|Chain(Name);public-authorization=Anyone|Permission(Name);hooks=RuntimeLifecycle;instance-grants=immutable-address+declared-name;shared-grants=exact-chain-name+canonical-null;no-implicit-open-or-string-authorization;current-owner-or-exact-holder-delegation;current-declaration-checked-on-grant-and-revoke;effect-authority-is-independent;raw-IVM-cannot-synthesize-instance-authority",
            lifecycle: "retained-code-binding-survives-suspension;pending-transition-survives-suspension;resume-reuses-exact-pending-transition;replacement-forbidden-while-pending;same-code-resume-never-replays-completed-hook;prepared-calls-bind-lifecycle-revision;existing-state-names-and-complete-types-remain-exact;new-maps-start-empty;new-scalars-require-kaizen-and-canonical-present-values-before-completion;recoverable-error-keeps-pending-transition;direct-and-governance-share-upgrade-validation",
            int_kind: "Int",
            int_pointer_type_id,
            decimal_kind: "Decimal",
            decimal_pointer_type_id,
            quantity_kind: "Quantity",
            quantity_pointer_type_id,
            list_kind: "List",
            list_layout: "flat-preorder;exact-element-subtree-immediately-follows",
            list_child_count: 1,
            list_capacity_is_schema_bound: true,
            list_min_capacity: MIN_ENTRYPOINT_LIST_CAPACITY_V1,
            list_max_capacity: MAX_ENTRYPOINT_LIST_CAPACITY_V1,
            max_schema_nodes,
            max_schema_depth,
        },
        AbiNumericSurface {
            semantics_descriptor_version: 4,
            int_pointer_type_id,
            decimal_pointer_type_id,
            quantity_pointer_type_id,
            mantissa_bits: NUMERIC_MANTISSA_BITS_V1,
            max_scale: DECIMAL_MAX_SCALE_V1,
            int_domain: "-2^511..=2^511-1",
            decimal_domain: "signed-mantissa-times-10^-scale;scale=0..28;exact",
            quantity_domain: "nonnegative-decimal;nominal-ledger-quantity",
            canonicalization: "minimal-signed-little-endian;zero-empty;strip-fractional-trailing-zeroes;zero-scale-is-zero",
            integer_division: "quotient-truncates-toward-zero;remainder-sign-is-dividend",
            wrapping_modulus: "2^512;reinterpret-as-signed-domain",
            rules: vec![
                AbiNumericRuleSurface {
                    name: "checked_intermediates",
                    specification: "compute-exact-mathematical-result-with-conceptually-unbounded-intermediates;canonicalize;then-check-final-domain",
                },
                AbiNumericRuleSurface {
                    name: "result_domain",
                    specification: "canonical-scale-first;then-signed-512-bit-mantissa;then-nonnegative-quantity-invariant",
                },
                AbiNumericRuleSurface {
                    name: "integer_arithmetic",
                    specification: "neg-add-sub-mul-div-rem-are-checked;division-and-remainder-by-zero-fail;min-int-div-or-rem-minus-one-is-mantissa-overflow",
                },
                AbiNumericRuleSurface {
                    name: "integer_helpers",
                    specification: "isqrt-floor-negative-is-negative-square-root;abs-checked;min-max-signed-512;div-ceil-mathematical-ceiling;gcd-nonnegative-absolute-operands-and-zero-zero-is-zero;mean-truncate-wide-sum-div-two-toward-zero;all-final-results-signed-512-checked;shared-observed-primitives-charge-before-every-limb-work-phase",
                },
                AbiNumericRuleSurface {
                    name: "decimal_add_sub",
                    specification: "align-to-common-decimal-scale-exactly;operate;canonicalize;check-final-domain",
                },
                AbiNumericRuleSurface {
                    name: "decimal_multiplication",
                    specification: "multiply-mantissas-exactly;sum-scales;canonicalize;reject-only-if-canonical-final-scale-or-mantissa-is-out-of-domain",
                },
                AbiNumericRuleSurface {
                    name: "exact_division",
                    specification: "reduce-denominator;classify-prime-factors;non-2-or-5-factor-is-repeating-decimal;terminating-minimum-scale-above-28-is-exact-division-scale-overflow;never-round",
                },
                AbiNumericRuleSurface {
                    name: "fused_mul_div_round",
                    specification: "decimal-or-quantity-receiver;decimal-multiplier-and-divisor;mathematical-product-kept-unbounded;one-final-round-at-explicit-scale;shared-observed-primitive-meters-every-work-phase-before-work;r10=value;r11=multiplier;r12=divisor;r13=Int-scale;r14=rounding;r15=zero;all-arithmetic-failures-trap;quantity-result-must-be-nonnegative",
                },
                AbiNumericRuleSurface {
                    name: "rounded_division",
                    specification: "explicit-output-scale-0-through-28-and-one-of-seven-rounding-tags;round-exact-rational-once;canonicalize-result",
                },
                AbiNumericRuleSurface {
                    name: "comparison",
                    specification: "compare-mathematical-values-after-canonicalization;same-declared-numeric-type-required-after-contextual-literal-inference",
                },
                AbiNumericRuleSurface {
                    name: "conversion",
                    specification: "runtime-int-to-decimal-requires-named-decimal-from-int;decimal-to-int-exact-by-default-with-distinct-named-truncating-and-rounded-forms;quantity-entry-checked-and-explicit;exact-literal-inference-is-compile-time-only",
                },
                AbiNumericRuleSurface {
                    name: "conversion_failure_mode",
                    specification: "INT_TO_I64=0x10102;INT_TO_U64=0x10103;DECIMAL_TO_INT_EXACT=0x1012D;QUANTITY_FROM_INT=0x10140;QUANTITY_FROM_DECIMAL=0x10141;r10=authenticated-source-pointer;r11=r12=r13=zero;r14=Trap0-or-Status1;authenticate-operand-before-zero-controls-before-failure-mode-before-arithmetic;Trap-preserves-NumericFaultV1-without-ABORT;Status-returns-r10-zero-and-r11-exact-NumericFaultV1-tag;success-returns-r10-value-and-r11-zero;malformed-controls-always-trap;no-output-envelope-on-failure",
                },
                AbiNumericRuleSurface {
                    name: "quantity",
                    specification: "nominal-nonnegative-domain;addition-checked;representable-negative-subtraction-is-quantity-underflow;multiplication-and-division-by-decimal-preserve-quantity;quantity-ratio-yields-decimal",
                },
                AbiNumericRuleSurface {
                    name: "wrapping",
                    specification: "only-explicit-int-neg-add-sub-mul-wrap-modulo-2^512;ordinary-operators-never-wrap",
                },
                AbiNumericRuleSurface {
                    name: "bitwise_shift_surface",
                    specification: "no-source-bitwise-or-shift-operators-in-abi-v1",
                },
            ],
            operators: numeric_operator_surface_v1(),
            json_grammar: vec![
                AbiNumericJsonSurface {
                    type_name: "int",
                    token_kind: "JSON-string-only",
                    decoded_string_grammar: "0|-?[1-9][0-9]*",
                    validation: "canonical-base-10-no-plus-no-leading-zero-no-negative-zero-no-decimal-point-no-exponent;then-signed-512-bit-domain",
                },
                AbiNumericJsonSurface {
                    type_name: "decimal",
                    token_kind: "JSON-string-only",
                    decoded_string_grammar: "-?(0|[1-9][0-9]*)(\\.[0-9]*[1-9])?",
                    validation: "shortest-canonical-non-exponent-spelling;no-plus-leading-zero-negative-zero-or-removable-fractional-zero;then-scale-0-through-28-and-signed-512-bit-mantissa",
                },
                AbiNumericJsonSurface {
                    type_name: "quantity",
                    token_kind: "JSON-string-only",
                    decoded_string_grammar: "(0|[1-9][0-9]*)(\\.[0-9]*[1-9])?",
                    validation: "shortest-canonical-nonnegative-non-exponent-spelling;no-plus-leading-zero-or-removable-fractional-zero;then-scale-0-through-28-and-signed-512-bit-mantissa",
                },
            ],
            fault_ordering: vec![
                AbiNumericRuleSurface {
                    name: "operand_pointer_validation",
                    specification: "operands-in-register-order:pointer-provenance;type-policy;expected-type;version;capped-length;range;snapshot;hash;frame;schema;canonical",
                },
                AbiNumericRuleSurface {
                    name: "scale_pointer_validation",
                    specification: "after-all-operands-and-before-control-registers-when-the-syscall-has-a-dynamic-scale-pointer",
                },
                AbiNumericRuleSurface {
                    name: "control_validation",
                    specification: "required-zero-registers;rounding-tag;failure-mode-in-syscall-contract-order",
                },
                AbiNumericRuleSurface {
                    name: "division_by_zero",
                    specification: "after-structural-and-control-validation;before-arithmetic-classification",
                },
                AbiNumericRuleSurface {
                    name: "arithmetic_classification",
                    specification: "operation-specific-exact-arithmetic-fault-before-final-result-domain-faults",
                },
                AbiNumericRuleSurface {
                    name: "final_result_domain",
                    specification: "scale-overflow;then-mantissa-overflow;then-negative-quantity",
                },
                AbiNumericRuleSurface {
                    name: "quantity_subtraction",
                    specification: "representable-negative-result-maps-to-quantity-underflow;out-of-range-negative-result-remains-mantissa-overflow",
                },
            ],
            wire_format_version: NUMERIC_WIRE_FORMAT_VERSION_V1,
            int_schema_name: INT_SCHEMA_NAME_V1,
            int_schema_hash: INT_SCHEMA_HASH_V1,
            decimal_schema_name: DECIMAL_SCHEMA_NAME_V1,
            decimal_schema_hash: DECIMAL_SCHEMA_HASH_V1,
            quantity_schema_name: QUANTITY_SCHEMA_NAME_V1,
            quantity_schema_hash: QUANTITY_SCHEMA_HASH_V1,
            frame_header_bytes: u64::try_from(NUMERIC_FRAME_HEADER_BYTES_V1)
                .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
            int_max_frame_bytes: u64::try_from(MAX_INT_FRAME_BYTES_V1)
                .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
            decimal_max_frame_bytes: u64::try_from(MAX_DECIMAL_FRAME_BYTES_V1)
                .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
            quantity_max_frame_bytes: u64::try_from(MAX_QUANTITY_FRAME_BYTES_V1)
                .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
            pointer_envelope_overhead_bytes: u64::try_from(NUMERIC_POINTER_ENVELOPE_OVERHEAD_V1)
                .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
            int_max_envelope_bytes: u64::try_from(MAX_INT_ENVELOPE_BYTES_V1)
                .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
            decimal_max_envelope_bytes: u64::try_from(MAX_DECIMAL_ENVELOPE_BYTES_V1)
                .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
            quantity_max_envelope_bytes: u64::try_from(MAX_QUANTITY_ENVELOPE_BYTES_V1)
                .map_err(|_| AbiSurfaceError::SurfaceTooLarge)?,
            frame_layout: NUMERIC_FRAME_LAYOUT_V1,
            pointer_envelope_layout: NUMERIC_POINTER_ENVELOPE_LAYOUT_V1,
            error_precedence: NUMERIC_ERROR_PRECEDENCE_V1,
            rounding_modes: vec![
                AbiNumericRoundingSurface {
                    name: "toward_zero",
                    tag: crate::numeric::RoundingModeV1::TowardZero.tag(),
                },
                AbiNumericRoundingSurface {
                    name: "away_from_zero",
                    tag: crate::numeric::RoundingModeV1::AwayFromZero.tag(),
                },
                AbiNumericRoundingSurface {
                    name: "floor",
                    tag: crate::numeric::RoundingModeV1::Floor.tag(),
                },
                AbiNumericRoundingSurface {
                    name: "ceil",
                    tag: crate::numeric::RoundingModeV1::Ceil.tag(),
                },
                AbiNumericRoundingSurface {
                    name: "nearest_even",
                    tag: crate::numeric::RoundingModeV1::NearestEven.tag(),
                },
                AbiNumericRoundingSurface {
                    name: "nearest_away",
                    tag: crate::numeric::RoundingModeV1::NearestAway.tag(),
                },
                AbiNumericRoundingSurface {
                    name: "nearest_toward_zero",
                    tag: crate::numeric::RoundingModeV1::NearestTowardZero.tag(),
                },
            ],
            failure_modes: vec![
                AbiNumericRoundingSurface {
                    name: "trap",
                    tag: crate::numeric::NUMERIC_FAILURE_TRAP,
                },
                AbiNumericRoundingSurface {
                    name: "status",
                    tag: crate::numeric::NUMERIC_FAILURE_STATUS,
                },
            ],
            faults: vec![
                AbiNumericFaultSurface {
                    name: "mantissa_overflow",
                    tag: crate::numeric::NumericFaultV1::MantissaOverflow.tag(),
                },
                AbiNumericFaultSurface {
                    name: "scale_overflow",
                    tag: crate::numeric::NumericFaultV1::ScaleOverflow.tag(),
                },
                AbiNumericFaultSurface {
                    name: "division_by_zero",
                    tag: crate::numeric::NumericFaultV1::DivisionByZero.tag(),
                },
                AbiNumericFaultSurface {
                    name: "repeating_decimal",
                    tag: crate::numeric::NumericFaultV1::RepeatingDecimal.tag(),
                },
                AbiNumericFaultSurface {
                    name: "exact_division_scale_overflow",
                    tag: crate::numeric::NumericFaultV1::ExactDivisionScaleOverflow.tag(),
                },
                AbiNumericFaultSurface {
                    name: "invalid_scale",
                    tag: crate::numeric::NumericFaultV1::InvalidScale.tag(),
                },
                AbiNumericFaultSurface {
                    name: "inexact_conversion",
                    tag: crate::numeric::NumericFaultV1::InexactConversion.tag(),
                },
                AbiNumericFaultSurface {
                    name: "negative_quantity",
                    tag: crate::numeric::NumericFaultV1::NegativeQuantity.tag(),
                },
                AbiNumericFaultSurface {
                    name: "quantity_underflow",
                    tag: crate::numeric::NumericFaultV1::QuantityUnderflow.tag(),
                },
                AbiNumericFaultSurface {
                    name: "invalid_rounding_mode",
                    tag: crate::numeric::NumericFaultV1::InvalidRoundingMode.tag(),
                },
                AbiNumericFaultSurface {
                    name: "invalid_failure_mode",
                    tag: crate::numeric::NumericFaultV1::InvalidFailureMode.tag(),
                },
                AbiNumericFaultSurface {
                    name: "reserved_register_nonzero",
                    tag: crate::numeric::NumericFaultV1::ReservedRegisterNonZero.tag(),
                },
                AbiNumericFaultSurface {
                    name: "negative_square_root",
                    tag: crate::numeric::NumericFaultV1::NegativeSquareRoot.tag(),
                },
            ],
            pointer_faults: vec![
                AbiNumericFaultSurface {
                    name: "invalid_address",
                    tag: crate::numeric::PointerAbiFaultV1::InvalidAddress.tag(),
                },
                AbiNumericFaultSurface {
                    name: "unknown_type",
                    tag: crate::numeric::PointerAbiFaultV1::UnknownType.tag(),
                },
                AbiNumericFaultSurface {
                    name: "type_not_allowed",
                    tag: crate::numeric::PointerAbiFaultV1::TypeNotAllowed.tag(),
                },
                AbiNumericFaultSurface {
                    name: "wrong_type",
                    tag: crate::numeric::PointerAbiFaultV1::WrongType.tag(),
                },
                AbiNumericFaultSurface {
                    name: "invalid_envelope_version",
                    tag: crate::numeric::PointerAbiFaultV1::InvalidEnvelopeVersion.tag(),
                },
                AbiNumericFaultSurface {
                    name: "oversized_length",
                    tag: crate::numeric::PointerAbiFaultV1::OversizedLength.tag(),
                },
                AbiNumericFaultSurface {
                    name: "truncated_envelope",
                    tag: crate::numeric::PointerAbiFaultV1::TruncatedEnvelope.tag(),
                },
                AbiNumericFaultSurface {
                    name: "payload_hash_mismatch",
                    tag: crate::numeric::PointerAbiFaultV1::PayloadHashMismatch.tag(),
                },
                AbiNumericFaultSurface {
                    name: "malformed_frame",
                    tag: crate::numeric::PointerAbiFaultV1::MalformedFrame.tag(),
                },
                AbiNumericFaultSurface {
                    name: "schema_mismatch",
                    tag: crate::numeric::PointerAbiFaultV1::SchemaMismatch.tag(),
                },
                AbiNumericFaultSurface {
                    name: "noncanonical",
                    tag: crate::numeric::PointerAbiFaultV1::NonCanonical.tag(),
                },
            ],
        },
    ))
}
