//! Adversarial tests for iterable-query column batch invariants.
use iroha_data_model::query::{
    QueryOutput, QueryOutputBatchBox, QueryOutputBatchBoxTuple, QueryOutputBatchBoxTupleError,
    builder::{QueryExecutor, QueryIterator, TypedBatchDowncastError},
    parameters::ForwardCursor,
};
use iroha_primitives::numeric::Numeric;
use norito::codec::Encode;
#[derive(Encode)]
struct WireTuple {
    tuple: Vec<QueryOutputBatchBox>,
}
#[derive(Encode)]
struct WireQueryOutput {
    batch: WireTuple,
    remaining_items: Option<u64>,
    has_more: bool,
    continue_cursor: Option<ForwardCursor>,
}
fn numeric(values: &[u32]) -> QueryOutputBatchBox {
    QueryOutputBatchBox::Numeric(values.iter().copied().map(Numeric::from).collect())
}
fn every_empty_batch_variant() -> Vec<QueryOutputBatchBox> {
    vec![
        QueryOutputBatchBox::PublicKey(Vec::new()),
        QueryOutputBatchBox::String(Vec::new()),
        QueryOutputBatchBox::Metadata(Vec::new()),
        QueryOutputBatchBox::Json(Vec::new()),
        QueryOutputBatchBox::Numeric(Vec::new()),
        QueryOutputBatchBox::Name(Vec::new()),
        QueryOutputBatchBox::DomainId(Vec::new()),
        QueryOutputBatchBox::Domain(Vec::new()),
        QueryOutputBatchBox::AccountId(Vec::new()),
        QueryOutputBatchBox::Account(Vec::new()),
        QueryOutputBatchBox::AssetId(Vec::new()),
        QueryOutputBatchBox::Asset(Vec::new()),
        QueryOutputBatchBox::AssetDefinitionId(Vec::new()),
        QueryOutputBatchBox::AssetDefinition(Vec::new()),
        QueryOutputBatchBox::RepoAgreement(Vec::new()),
        QueryOutputBatchBox::NftId(Vec::new()),
        QueryOutputBatchBox::Nft(Vec::new()),
        QueryOutputBatchBox::RwaId(Vec::new()),
        QueryOutputBatchBox::Rwa(Vec::new()),
        QueryOutputBatchBox::Role(Vec::new()),
        QueryOutputBatchBox::Parameter(Vec::new()),
        QueryOutputBatchBox::Permission(Vec::new()),
        QueryOutputBatchBox::CommittedTransaction(Vec::new()),
        QueryOutputBatchBox::TransactionResult(Vec::new()),
        QueryOutputBatchBox::TransactionResultHash(Vec::new()),
        QueryOutputBatchBox::TransactionEntrypoint(Vec::new()),
        QueryOutputBatchBox::TransactionEntrypointHash(Vec::new()),
        QueryOutputBatchBox::Peer(Vec::new()),
        QueryOutputBatchBox::RoleId(Vec::new()),
        QueryOutputBatchBox::TriggerId(Vec::new()),
        QueryOutputBatchBox::Trigger(Vec::new()),
        QueryOutputBatchBox::Action(Vec::new()),
        QueryOutputBatchBox::Block(Vec::new()),
        QueryOutputBatchBox::BlockHeader(Vec::new()),
        QueryOutputBatchBox::BlockHeaderHash(Vec::new()),
        QueryOutputBatchBox::ProofRecord(Vec::new()),
        QueryOutputBatchBox::OracleFeedConfig(Vec::new()),
        QueryOutputBatchBox::OracleFeedEventRecord(Vec::new()),
        QueryOutputBatchBox::OracleProviderStatsRecord(Vec::new()),
        QueryOutputBatchBox::OracleDispute(Vec::new()),
        QueryOutputBatchBox::OracleChangeProposal(Vec::new()),
        QueryOutputBatchBox::TwitterBindingRecord(Vec::new()),
        QueryOutputBatchBox::DefiOracleAttestation(Vec::new()),
        QueryOutputBatchBox::AssetEscrowRecord(Vec::new()),
        QueryOutputBatchBox::FeeSponsorProgram(Vec::new()),
        QueryOutputBatchBox::FeeSponsorProgramId(Vec::new()),
        QueryOutputBatchBox::BondRecord(Vec::new()),
        QueryOutputBatchBox::AssetUidPolicyViewV1(Vec::new()),
        QueryOutputBatchBox::AssetFiRelationshipViewV1(Vec::new()),
        QueryOutputBatchBox::AssetFiTransferReceiptV1(Vec::new()),
        QueryOutputBatchBox::AssetFiContextSnapshotV1(Vec::new()),
        QueryOutputBatchBox::AssetUidEnrollmentViewV1(Vec::new()),
        QueryOutputBatchBox::AssetEscrowScopeOriginalV1(Vec::new()),
    ]
}
#[test]
fn public_construction_rejects_missing_and_unequal_columns() {
    assert_eq!(
        QueryOutputBatchBoxTuple::new(Vec::new()),
        Err(QueryOutputBatchBoxTupleError::NoColumns)
    );
    assert_eq!(
        QueryOutputBatchBoxTuple::new(vec![numeric(&[1]), numeric(&[])]),
        Err(QueryOutputBatchBoxTupleError::ColumnLengthMismatch {
            column: 1,
            expected: 1,
            actual: 0,
        })
    );
    assert_eq!(
        QueryOutputBatchBoxTuple::new(vec![numeric(&[]), numeric(&[1])]),
        Err(QueryOutputBatchBoxTupleError::ColumnLengthMismatch {
            column: 1,
            expected: 0,
            actual: 1,
        })
    );
    let empty_page = QueryOutputBatchBoxTuple::new(vec![numeric(&[]), numeric(&[])])
        .expect("equal zero-row columns remain valid for pagination");
    assert_eq!(empty_page.column_count(), 2);
    assert!(empty_page.is_empty());
}
#[test]
fn all_norito_decode_paths_reject_hostile_column_shapes() {
    for wire in [
        WireTuple { tuple: Vec::new() },
        WireTuple {
            tuple: vec![numeric(&[1]), numeric(&[])],
        },
        WireTuple {
            tuple: vec![numeric(&[]), numeric(&[1])],
        },
    ] {
        let bytes = wire.encode();
        assert!(
            norito::codec::decode_adaptive::<QueryOutputBatchBoxTuple>(&bytes).is_err(),
            "adaptive decode accepted hostile columns"
        );
        assert!(
            norito::codec::decode_exact_from_slice::<QueryOutputBatchBoxTuple>(&bytes).is_err(),
            "exact slice decode accepted hostile columns"
        );
    }
}
#[test]
fn nested_query_output_decode_rejects_hostile_columns() {
    let wire = WireQueryOutput {
        batch: WireTuple {
            tuple: vec![numeric(&[1]), numeric(&[])],
        },
        remaining_items: Some(0),
        has_more: false,
        continue_cursor: None,
    };
    let error = norito::codec::decode_adaptive::<QueryOutput>(&wire.encode())
        .expect_err("nested hostile columns must fail before iteration");
    assert!(error.to_string().to_lowercase().contains("column"));
}
#[test]
fn norito_decode_rejects_all_truncated_prefixes_and_trailing_bytes() {
    let batch = QueryOutputBatchBoxTuple::new(vec![numeric(&[1, 2]), numeric(&[3, 4])])
        .expect("equal columns");
    let bytes = batch.encode();
    assert_eq!(
        norito::codec::decode_exact_from_slice::<QueryOutputBatchBoxTuple>(&bytes)
            .expect("valid exact slice decode"),
        batch
    );
    for cut in 0..bytes.len() {
        assert!(
            norito::codec::decode_adaptive::<QueryOutputBatchBoxTuple>(&bytes[..cut]).is_err(),
            "decoded truncated prefix {cut}/{}",
            bytes.len()
        );
    }
    let mut with_trailing = bytes;
    with_trailing.extend_from_slice(&[0xA5, 0x5A]);
    assert!(
        norito::codec::decode_adaptive::<QueryOutputBatchBoxTuple>(&with_trailing).is_err(),
        "decoded payload with trailing bytes"
    );
}

#[test]
fn json_query_output_rejects_hostile_columns() {
    let nonempty = norito::json::to_value(&numeric(&[1])).expect("serialize batch column");
    let empty = norito::json::to_value(&numeric(&[])).expect("serialize empty batch column");
    let value = norito::json!({
        "batch": { "tuple": [nonempty, empty] },
        "remaining_items": 0,
        "has_more": false,
        "continue_cursor": null
    });
    let error = norito::json::from_value::<QueryOutput>(value)
        .expect_err("hostile JSON columns must fail before iteration");
    assert!(error.to_string().to_lowercase().contains("column"));
}
#[test]
fn extend_preflights_late_type_mismatch_without_partial_mutation() {
    let mut left = QueryOutputBatchBoxTuple::new(vec![
        numeric(&[1]),
        QueryOutputBatchBox::String(vec!["one".to_owned()]),
    ])
    .expect("equal columns");
    let snapshot = left.clone();
    let right =
        QueryOutputBatchBoxTuple::new(vec![numeric(&[2]), numeric(&[3])]).expect("equal columns");
    assert_eq!(
        left.extend(right),
        Err(QueryOutputBatchBoxTupleError::ColumnTypeMismatch { column: 1 })
    );
    assert_eq!(left, snapshot);
}
#[test]
fn every_empty_batch_variant_lists_every_batch_kind() {
    let schema = <QueryOutputBatchBox as iroha_schema::IntoSchema>::schema();
    let Some(iroha_schema::Metadata::Enum(metadata)) = schema.get::<QueryOutputBatchBox>() else {
        panic!("QueryOutputBatchBox must be an enum schema");
    };
    let expected: std::collections::BTreeSet<String> = metadata
        .variants
        .iter()
        .map(|variant| variant.tag.clone())
        .collect();
    let listed: std::collections::BTreeSet<String> = every_empty_batch_variant()
        .iter()
        .map(|batch| {
            let rendered = format!("{batch:?}");
            rendered
                .split('(')
                .next()
                .expect("tuple variant debug")
                .to_owned()
        })
        .collect();
    assert_eq!(listed, expected, "every batch kind must be exercised");
}
#[test]
fn erased_batch_extend_is_total_for_every_variant_and_atomic_on_mismatch() {
    let variants = every_empty_batch_variant();
    assert!(!variants.is_empty());
    for (index, batch) in variants.iter().enumerate() {
        let mut matching = batch.clone();
        matching
            .extend(batch.clone())
            .unwrap_or_else(|error| panic!("variant {index} failed matching extend: {error}"));
        assert!(matching.is_empty());
        let mut mismatched = batch.clone();
        let snapshot = mismatched.clone();
        let other = variants[(index + 1) % variants.len()].clone();
        assert!(
            mismatched.extend(other).is_err(),
            "variant {index} mismatch"
        );
        assert_eq!(mismatched, snapshot, "variant {index} mutated on error");
    }
}
struct HostileExecutor;
impl QueryExecutor for HostileExecutor {
    type Cursor = ();
    type Error = TypedBatchDowncastError;
    fn execute_singular_query(
        &self,
        _query: iroha_data_model::query::SingularQueryBox,
    ) -> Result<iroha_data_model::query::SingularQueryOutputBox, Self::Error> {
        unreachable!("not used by iterable test")
    }
    fn start_query(
        &self,
        _query: iroha_data_model::query::QueryWithParams,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<u64>, Option<Self::Cursor>), Self::Error> {
        unreachable!("not used by direct iterator test")
    }
    fn continue_query(
        (): Self::Cursor,
    ) -> Result<(QueryOutputBatchBoxTuple, Option<u64>, Option<Self::Cursor>), Self::Error> {
        Ok((
            QueryOutputBatchBoxTuple::from_batch(QueryOutputBatchBox::String(vec![
                "wrong type".to_owned(),
            ])),
            Some(0),
            Some(()),
        ))
    }
}
#[test]
fn hostile_continuation_returns_one_terminal_typed_error() {
    let first = QueryOutputBatchBoxTuple::from_batch(numeric(&[]));
    let mut iterator = QueryIterator::<HostileExecutor, Numeric>::new(first, Some(()))
        .expect("initial batch type matches");
    assert_eq!(iterator.size_hint(), (0, None));
    assert_eq!(
        iterator.next(),
        Some(Err(TypedBatchDowncastError::WrongType { column: 0 }))
    );
    assert_eq!(iterator.size_hint(), (0, Some(0)));
    assert_eq!(iterator.next(), None, "hostile cursor must be terminated");
}
