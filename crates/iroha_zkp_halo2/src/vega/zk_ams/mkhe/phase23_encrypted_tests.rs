// Test body included from the parent module to keep its production source budget bounded.
use super::super::{
    AuthenticationSecret, IndependentPublicKey, IndependentSecretKey, MaskedRelaxedRandomSourceV1,
    ZkAmsMkhePartyIdV1, aggregate_rkg_round_one, aggregate_rkg_round_two, decrypt_test_plaintext,
    encrypt, generate_galois_key, independent_keygen, rkg_round_one, rkg_round_two, shake256,
};
use super::*;
use crate::vega::{MaskedRelaxedRandomErrorV1, VEGA_T256_SCALAR_MODULUS_BE_V1};
const TEST_MODULI: [u64; 2] = [2_013_265_921, 1_811_939_329];
const TEST_ROOTS: [u64; 2] = [1_400_279_418, 677_356_115];
fn test_profile() -> BgvProfile {
    BgvProfile {
        profile_id: [0x6e; 32],
        ring_degree: 8,
        moduli: &TEST_MODULI,
        negacyclic_roots: &TEST_ROOTS,
        plaintext_modulus: PlaintextModulus::Tiny(17),
        error_eta: 2,
        hybrid_rns_decomposition: false,
        gadget_base_log: 8,
        gadget_digits: 8,
        max_ciphertext_bytes: 1 << 20,
        max_evaluated_key_bytes: 16 << 20,
        max_round_bytes: 16 << 20,
        max_share_bytes: 4 << 20,
        max_workspace_bytes: 16 << 20,
        max_work_units: 1 << 22,
    }
}
struct KatRandom {
    state: [u8; 32],
    counter: u64,
}
impl KatRandom {
    fn new(label: &[u8]) -> Self {
        Self {
            state: keccak256(label),
            counter: 0,
        }
    }
}
impl MaskedRelaxedRandomSourceV1 for KatRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), MaskedRelaxedRandomErrorV1> {
        let mut written = 0;
        while written < destination.len() {
            let mut frame = Vec::with_capacity(40);
            frame.extend_from_slice(&self.state);
            frame.extend_from_slice(&self.counter.to_be_bytes());
            let block = shake256(&frame, 64);
            let take = (destination.len() - written).min(block.len());
            destination[written..written + take].copy_from_slice(&block[..take]);
            self.state = keccak256(&block);
            self.counter = self.counter.wrapping_add(1);
            written += take;
        }
        Ok(())
    }
}
fn s(value: u64) -> Scalar {
    Scalar::from_u64(value)
}
fn legacy_materialized_canonical_bytes_for_test(
    value: &ZkAmsPhase23MaterializedAccumulatorsV1,
) -> Result<Vec<u8>, ZkAmsMkheErrorV1> {
    validate_materialized(value)?;
    let length = materialized_wire_length(value.shape)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ZkAmsMkheErrorV1::ResourceCeilingExceeded)?;
    bytes.push(value.version);
    for digest in [
        value.profile_digest,
        value.roster_digest,
        value.transcript_digest,
        value.batch_id,
        value.ordered_batch_input_digest,
    ] {
        bytes.extend_from_slice(&digest);
    }
    bytes.push(value.fold_count);
    for family_length in [
        value.shape.x,
        1,
        value.shape.e,
        value.shape.r_e,
        value.shape.w,
        value.shape.r_w,
    ] {
        bytes.extend_from_slice(&family_length.to_be_bytes());
    }
    for family in [
        value.x.as_slice(),
        value.u.as_slice(),
        value.e.as_slice(),
        value.r_e.as_slice(),
        value.w.as_slice(),
        value.r_w.as_slice(),
    ] {
        for scalar in family {
            bytes.extend_from_slice(&scalar.to_be_bytes());
        }
    }
    bytes.extend_from_slice(&value.digest);
    assert_eq!(bytes.len(), length);
    Ok(bytes)
}
fn read_materialized_test(
    bytes: &[u8],
) -> Result<ZkAmsPhase23MaterializedAccumulatorsV1, ZkAmsMkheErrorV1> {
    let mut reader = std::io::Cursor::new(bytes);
    super::super::read_zk_ams_phase23_materialized_accumulators_canonical_exact_v1(&mut reader)
}
fn sparse_map(
    kind: ZkAmsPhase23MapKindV1,
    column_count: u32,
    rows: &[Vec<(u32, u64)>],
) -> ZkAmsPhase23SparseMapV1 {
    let mut offsets = Vec::with_capacity(rows.len() + 1);
    let mut columns = Vec::new();
    let mut coefficients = Vec::new();
    offsets.push(0);
    for row in rows {
        for (column, coefficient) in row {
            columns.push(*column);
            coefficients.push(s(*coefficient).to_be_bytes());
        }
        offsets.push(columns.len() as u32);
    }
    ZkAmsPhase23SparseMapV1::new(
        kind,
        rows.len() as u32,
        column_count,
        rows.iter().map(Vec::len).max().unwrap_or(1) as u32,
        offsets,
        columns,
        coefficients,
    )
    .unwrap()
}
fn sample_map() -> ZkAmsPhase23SparseMapV1 {
    sparse_map(
        ZkAmsPhase23MapKindV1::A,
        8,
        &[
            vec![(0, 2), (5, 1)],
            vec![(1, 3), (7, 1)],
            vec![(4, 1), (6, 4)],
            vec![(2, 5)],
            vec![(3, 2), (7, 2)],
            vec![(0, 1), (6, 1)],
        ],
    )
}
#[test]
fn public_release_history_types_enforce_exact_geometry_and_canonical_encodings() {
    type PublicHistoryConstructor = fn(
        super::super::terminal::ZkAmsPhase3TerminalContextV1,
        Vec<u8>,
        ZkAmsPhase23PublicAccumulatorV1,
        Vec<ZkAmsPhase23StrictPublicInstanceV1>,
        Vec<ZkAmsPhase23CrossTermCommitmentV1>,
    )
        -> Result<ZkAmsPhase23PublicFoldHistoryV1, ZkAmsMkheErrorV1>;
    let _public_constructor: PublicHistoryConstructor = ZkAmsPhase23PublicFoldHistoryV1::new;
    assert_eq!(ZK_AMS_PHASE23_RELEASE_PUBLIC_INPUT_COUNT_V1, 89);
    assert_eq!(ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1, 512);
    assert_eq!(ZK_AMS_PHASE23_RELEASE_ERROR_COMMITMENT_ROWS_V1, 1_024);
    let generator = VegaT256PointV1::canonical_generator()
        .unwrap()
        .to_non_identity_wire_bytes()
        .unwrap();
    let public_inputs = [s(3).to_be_bytes(); ZK_AMS_PHASE23_RELEASE_PUBLIC_INPUT_COUNT_V1];
    let witness = vec![generator; ZK_AMS_PHASE23_RELEASE_WITNESS_COMMITMENT_ROWS_V1];
    let error = vec![generator; ZK_AMS_PHASE23_RELEASE_ERROR_COMMITMENT_ROWS_V1];
    assert_eq!(
        ZkAmsPhase23PublicAccumulatorV1::new(
            s(2).to_be_bytes(),
            public_inputs,
            witness[..witness.len() - 1].to_vec(),
            error.clone(),
        ),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    assert_eq!(
        ZkAmsPhase23PublicAccumulatorV1::new(
            VEGA_T256_SCALAR_MODULUS_BE_V1,
            public_inputs,
            witness.clone(),
            error.clone(),
        ),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let accumulator = ZkAmsPhase23PublicAccumulatorV1::new(
        s(2).to_be_bytes(),
        public_inputs,
        witness.clone(),
        error.clone(),
    )
    .unwrap();
    assert_ne!(accumulator.public_input_digest(), [0; 32]);
    assert_ne!(accumulator.witness_commitment_digest(), [0; 32]);
    assert_ne!(accumulator.error_commitment_digest(), [0; 32]);
    assert_ne!(accumulator.digest(), [0; 32]);
    let public_input_digest = public_input_vector_digest(&public_inputs).unwrap();
    assert_eq!(
        ZkAmsPhase23StrictPublicInstanceV1::new(public_inputs, [0; 32], witness.clone(),),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let strict =
        ZkAmsPhase23StrictPublicInstanceV1::new(public_inputs, public_input_digest, witness)
            .unwrap();
    assert_eq!(strict.public_input_digest(), public_input_digest);
    assert_ne!(strict.witness_commitment_digest(), [0; 32]);
    assert_ne!(strict.digest(), [0; 32]);
    let layout = canonical_release_commitment_preimage_layout_v1().unwrap();
    assert_eq!(
        ZkAmsPhase23CrossTermCommitmentV1::new(error.clone(), [0; 32]),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let cross = ZkAmsPhase23CrossTermCommitmentV1::new(error, layout.digest()).unwrap();
    assert_eq!(cross.preimage_layout_digest(), layout.digest());
    assert_ne!(cross.digest(), [0; 32]);
    assert_eq!(
        composition_context_digest_v1(&[]),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    assert_eq!(
        composition_context_digest_v1(&vec![1; PHASE23_MAX_COMPOSITION_CONTEXT_FRAME_BYTES_V1 + 1]),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    assert_ne!(
        composition_context_digest_v1(b"exact-core-context-frame").unwrap(),
        [0; 32]
    );
}
fn fake_materializer_chunk(logical_values: u32, values: &[u64]) -> ZkAmsT256PackedPlaintextV1 {
    let layout = zk_ams_t256_packing_layout_v1(logical_values).unwrap();
    ZkAmsT256PackedPlaintextV1 {
        version: 1,
        profile_digest: layout.profile_digest,
        layout_digest: layout.digest,
        chunk_index: 0,
        used_slots: u32::try_from(values.len()).unwrap(),
        coefficients: values
            .iter()
            .copied()
            .map(|value| Scalar::from_u64(value).to_be_bytes())
            .collect(),
        digest: [0; 32],
    }
}
fn fake_materializer_chunks(u: [u64; 2]) -> Vec<ZkAmsT256PackedPlaintextV1> {
    [
        fake_materializer_chunk(1, &[11]),
        fake_materializer_chunk(2, &u),
        fake_materializer_chunk(2, &[21, 22]),
        fake_materializer_chunk(1, &[31]),
        fake_materializer_chunk(3, &[41, 42, 43]),
        fake_materializer_chunk(1, &[51]),
    ]
    .into()
}
fn decode_fake_materializer_chunk(
    layout: ZkAmsT256PackingLayoutV1,
    packed: &ZkAmsT256PackedPlaintextV1,
    visit: &mut dyn FnMut(&[u8; 32]) -> Result<(), ZkAmsMkheErrorV1>,
) -> Result<(), ZkAmsMkheErrorV1> {
    if packed.layout_digest != layout.digest
        || packed.chunk_index != 0
        || packed.used_slots != layout.logical_value_count
        || packed.coefficients.len() != layout.logical_value_count as usize
    {
        return Err(ZkAmsMkheErrorV1::InvalidPolynomial);
    }
    for value in &packed.coefficients {
        visit(value)?;
    }
    Ok(())
}
fn run_fake_materializer(
    chunks: Vec<Result<ZkAmsT256PackedPlaintextV1, ZkAmsMkheErrorV1>>,
) -> Result<ZkAmsPhase23MaterializedAccumulatorsV1, ZkAmsMkheErrorV1> {
    materialize_release_accumulator_chunk_stream_with_decoder_v1(
        release_profile_v1().digest().unwrap(),
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        1,
        ZkAmsPhase23AccumulatorShapeV1::new(1, 2, 1, 3, 1).unwrap(),
        chunks,
        &mut decode_fake_materializer_chunk,
    )
}
#[test]
fn owned_chunk_materializer_enforces_schedule_exhaustion_and_incremental_u() {
    let materialized = run_fake_materializer(
        fake_materializer_chunks([7, 7])
            .into_iter()
            .map(Ok)
            .collect(),
    )
    .unwrap();
    assert_eq!(materialized.x, vec![Scalar::from_u64(11)]);
    assert_eq!(materialized.u, vec![Scalar::from_u64(7)]);
    assert_eq!(materialized.e.len(), 2);
    assert_eq!(materialized.w.len(), 3);
    let mut reordered = fake_materializer_chunks([7, 7]);
    reordered.swap(0, 1);
    assert_eq!(
        run_fake_materializer(reordered.into_iter().map(Ok).collect()),
        Err(ZkAmsMkheErrorV1::InvalidPolynomial)
    );
    let mut missing = fake_materializer_chunks([7, 7]);
    missing.pop();
    assert_eq!(
        run_fake_materializer(missing.into_iter().map(Ok).collect()),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let mut extra = fake_materializer_chunks([7, 7]);
    extra.push(fake_materializer_chunk(1, &[61]));
    assert_eq!(
        run_fake_materializer(extra.into_iter().map(Ok).collect()),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let before_partial_error = materialized_zeroized_drop_count_v1();
    assert_eq!(
        run_fake_materializer(
            fake_materializer_chunks([7, 8])
                .into_iter()
                .map(Ok)
                .collect()
        ),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    assert_eq!(
        materialized_zeroized_drop_count_v1(),
        before_partial_error + 1
    );
}
#[test]
fn callback_materializer_visibility_stays_parent_private() {
    let source = include_str!("phase23_encrypted.rs");
    assert!(source.contains(
        "pub(super) fn materialize_release_accumulator_chunk_stream_with_decoder_v1<I, D>("
    ));
    assert!(
        !source
            .contains("pub fn materialize_release_accumulator_chunk_stream_with_decoder_v1<I, D>(")
    );
}
#[test]
fn streaming_large_owner_surface_is_move_only_redacted_and_zeroizing() {
    let phase_source = include_str!("phase23_encrypted.rs");
    let materialized_wire_source = include_str!("phase23_materialized_wire.rs");
    let packing_source = include_str!("packing.rs");
    let mkhe_facade = include_str!("../mkhe.rs");
    let public_facades = [
        include_str!("../../zk_ams.rs"),
        include_str!("../../../vega.rs"),
    ];



    assert!(!phase_source.contains("pub fn zk_ams_phase23_materialize_release_accumulators_v1"));
    assert!(!phase_source.contains("ZkAmsPhase23PackedAccumulatorSetV1"));
    assert!(!phase_source.contains("impl ZkAmsPhase23MaterializedAccumulatorsV1"));
    assert!(!mkhe_facade.contains("ZkAmsPhase23PackedAccumulatorSetV1,"));
    for facade in std::iter::once(mkhe_facade).chain(public_facades) {
        assert!(!facade.contains("ZkAmsPhase23PackedAccumulatorSetV1"));
        assert!(!facade.contains("zk_ams_phase23_materialize_release_accumulators_v1"));
        assert!(facade.contains("zk_ams_phase23_materialize_release_accumulator_chunks_v1"));
        assert!(
            facade.contains("read_zk_ams_phase23_materialized_accumulators_canonical_exact_v1")
        );
        assert!(facade.contains("write_zk_ams_phase23_materialized_accumulators_canonical_v1"));
    }
    assert!(materialized_wire_source.contains(
        "struct ZeroizingMaterializedWireBufferV1([u8; PHASE23_MATERIALIZED_WIRE_HEADER_BYTES_V1])"
    ));
    assert!(materialized_wire_source.contains("impl Drop for ZeroizingMaterializedWireBufferV1"));
    assert!(!materialized_wire_source.contains("#[derive("));
    assert!(!materialized_wire_source.contains("impl Clone for ZeroizingMaterializedWireBufferV1"));
    assert!(!materialized_wire_source.contains("impl Debug for ZeroizingMaterializedWireBufferV1"));
    assert!(materialized_wire_source.contains("try_reserve_exact"));
    assert!(materialized_wire_source.contains("require_eof_v1"));
    assert!(!materialized_wire_source.contains("let mut bytes = Vec"));
    assert!(!materialized_wire_source.contains("Vec::with_capacity"));
    assert!(!materialized_wire_source.contains(".to_vec()"));
    assert!(!materialized_wire_source.contains("read_to_end"));
    assert!(!materialized_wire_source.contains("let scalar: [u8; 32]"));
    let materialized_shape = phase_source
        .split("pub struct ZkAmsPhase23MaterializedAccumulatorsV1")
        .nth(1)
        .expect("materialized owner exists")
        .split("impl Drop for ZkAmsPhase23MaterializedAccumulatorsV1")
        .next()
        .expect("materialized owner ends before Drop");
    for field in ["x", "u", "e", "r_e", "w", "r_w"] {
        assert!(materialized_shape.contains(&format!("pub(super) {field}: Vec<Scalar>")));
        assert!(!materialized_shape.contains(&format!("pub {field}: Vec<Scalar>")));
    }
    assert!(!phase_source.contains("FnMut([u8; 32])"));
    assert!(packing_source.contains("struct ZeroizingPackingScalarBytesV1([u8; 32])"));
    assert!(packing_source.contains("visit: impl FnMut(&[u8; 32])"));
    let streaming_decoder = materialized_wire_source
        .split("pub fn read_zk_ams_phase23_materialized_accumulators_canonical_exact_v1")
        .nth(1)
        .unwrap()
        .split("fn write_exact_v1")
        .next()
        .unwrap();
    assert!(
        streaming_decoder
            .find("let mut materialized = ZkAmsPhase23MaterializedAccumulatorsV1")
            .unwrap()
            < streaming_decoder.find("for _ in 0..length").unwrap()
    );
    assert!(
        streaming_decoder
            .find("profile_digest != release_profile_digest")
            .unwrap()
            < streaming_decoder
                .find("let mut materialized = ZkAmsPhase23MaterializedAccumulatorsV1")
                .unwrap()
    );
    type PublicMaterializedWriterV1 =
        fn(&ZkAmsPhase23MaterializedAccumulatorsV1, &mut Vec<u8>) -> Result<(), ZkAmsMkheErrorV1>;
    type PublicMaterializedReaderV1 =
        fn(
            &mut std::io::Cursor<Vec<u8>>,
        ) -> Result<ZkAmsPhase23MaterializedAccumulatorsV1, ZkAmsMkheErrorV1>;
    let _: PublicMaterializedWriterV1 =
        crate::vega::write_zk_ams_phase23_materialized_accumulators_canonical_v1::<Vec<u8>>;
    let _: PublicMaterializedReaderV1 =
        crate::vega::read_zk_ams_phase23_materialized_accumulators_canonical_exact_v1::<
            std::io::Cursor<Vec<u8>>,
        >;
    assert!(phase_source.contains("try_reserve_exact(length as usize)"));
    assert!(phase_source.contains("if family == 1"));
    assert!(phase_source.contains("if let Some(extra) = chunks.next()"));
    assert!(!phase_source.contains("let mut outputs: [Vec<Scalar>; 6]"));
    assert!(
        phase_source
            .find("let mut materialized = ZkAmsPhase23MaterializedAccumulatorsV1")
            .unwrap()
            < phase_source
                .find("let mut chunks = packed_chunks.into_iter()")
                .unwrap()
    );
    assert!(packing_source.contains("T256PackedPlaintextDecodeWorkspaceV1"));
    assert!(packing_source.contains("ClearingPackingFp2BorrowV1"));
    let decoder = packing_source
        .split("pub fn decode_zk_ams_t256_packed_plaintext_v1")
        .nth(1)
        .unwrap()
        .split("pub fn permute_zk_ams_t256_slots_v1")
        .next()
        .unwrap();
    assert!(decoder.contains("visit_validated_packed_plaintext_used_slots_with_workspace_v1"));
    assert!(!decoder.contains("ZeroizingPackingScalarsV1"));
    assert!(!decoder.contains("decode_coefficients("));
    assert!(
        !packing_source.contains(
            "#[derive(Clone, Debug, PartialEq, Eq)]\npub struct ZkAmsT256PackedPlaintextV1"
        )
    );
    assert!(packing_source.contains(
        "#[cfg_attr(test, derive(Clone))]\n#[derive(PartialEq, Eq)]\npub struct ZkAmsT256PackedPlaintextV1"
    ));
    assert!(!packing_source.contains(".field(\"coefficients\", &self.coefficients)"));
    assert!(phase_source.contains(
        "#[cfg_attr(test, derive(Clone))]\n#[derive(PartialEq, Eq)]\npub struct ZkAmsPhase23MaterializedAccumulatorsV1"
    ));
    assert!(!phase_source.contains(".field(\"w\", &self.w)"));
    let chunk = fake_materializer_chunk(1, &[9]);
    assert!(format!("{chunk:?}").len() < 1_024);
    drop(chunk);
    let before_partial_unwind = materialized_zeroized_drop_count_v1();
    let mut decoder_calls = 0_usize;
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut decoder =
            |layout: ZkAmsT256PackingLayoutV1,
             packed: &ZkAmsT256PackedPlaintextV1,
             visit: &mut dyn FnMut(&[u8; 32]) -> Result<(), ZkAmsMkheErrorV1>| {
                decoder_calls += 1;
                if decoder_calls == 3 {
                    panic!("intentional partial-materialization erasure audit");
                }
                decode_fake_materializer_chunk(layout, packed, visit)
            };
        materialize_release_accumulator_chunk_stream_with_decoder_v1(
            release_profile_v1().digest().unwrap(),
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            1,
            ZkAmsPhase23AccumulatorShapeV1::new(1, 2, 1, 3, 1).unwrap(),
            fake_materializer_chunks([7, 7])
                .into_iter()
                .map(Ok)
                .collect::<Vec<_>>(),
            &mut decoder,
        )
        .unwrap();
    }));
    assert!(unwind.is_err());
    assert_eq!(
        materialized_zeroized_drop_count_v1(),
        before_partial_unwind + 1
    );
    let before_materialized = materialized_zeroized_drop_count_v1();
    let materialized = run_fake_materializer(
        fake_materializer_chunks([7, 7])
            .into_iter()
            .map(Ok)
            .collect(),
    )
    .unwrap();
    assert!(format!("{materialized:?}").len() < 1_024);
    drop(materialized);
    assert_eq!(
        materialized_zeroized_drop_count_v1(),
        before_materialized + 1
    );
}
#[test]
fn canonical_release_maps_layout_order_and_source_shape_are_pinned() {
    let release =
        zk_ams_phase23_release_map_manifest_v1().expect("canonical release manifest compiles");
    let [a, b, c] = release.abc();
    assert_eq!(
        [a.kind(), b.kind(), c.kind()],
        [
            ZkAmsPhase23MapKindV1::A,
            ZkAmsPhase23MapKindV1::B,
            ZkAmsPhase23MapKindV1::C,
        ]
    );
    for map in [a, b, c] {
        assert_eq!(map.row_count(), 1_048_576);
        assert_eq!(map.column_count(), 524_378);
        assert!(map.nonzero_count() >= map.max_row_fan_in());
        validate_sparse_map_manifest_v1(map).unwrap();
    }
    let tiny_maps = [
        sparse_map(ZkAmsPhase23MapKindV1::A, 1, &[vec![(0, 1)]]),
        sparse_map(ZkAmsPhase23MapKindV1::B, 1, &[vec![(0, 1)]]),
        sparse_map(ZkAmsPhase23MapKindV1::C, 1, &[vec![(0, 1)]]),
    ];
    assert_eq!(
        require_release_relation_maps_v1([&tiny_maps[0], &tiny_maps[1], &tiny_maps[2]]),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let variable_count = 524_288;
    let public_input_count = 89;
    assert_eq!(
        internal_to_paper_column_v1(variable_count - 1, variable_count, public_input_count),
        Ok(524_287)
    );
    assert_eq!(
        internal_to_paper_column_v1(variable_count, variable_count, public_input_count),
        Ok(524_377)
    );
    assert_eq!(
        internal_to_paper_column_v1(variable_count + 1, variable_count, public_input_count),
        Ok(524_288)
    );
    assert_eq!(
        internal_to_paper_column_v1(
            variable_count + public_input_count,
            variable_count,
            public_input_count,
        ),
        Ok(524_376)
    );
    assert_eq!(
        internal_to_paper_column_v1(
            variable_count + public_input_count + 1,
            variable_count,
            public_input_count,
        ),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let shape = super::super::super::canonical_shape_ref().unwrap();
    assert!(matches!(
        PaperOrderRelationMapViewV1::new(
            ZkAmsPhase23MapKindV1::A,
            &shape.a,
            shape.variable_count(),
            shape.public_input_count() - 1,
        ),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    ));
    let layout = release.commitment_preimage_layout();
    assert_eq!(layout.version(), 1);
    assert_eq!(layout.message_value_count(), 1_048_576);
    assert_eq!(layout.row_count(), 1_024);
    assert_eq!(layout.message_columns(), 1_024);
    assert_eq!(layout.blinding_count(), 1_024);
    assert_eq!(layout.last_row_message_count(), 1_024);
    assert_eq!(layout.hiding_generator_index(), 1_024);
    assert_eq!(layout.blinding_position(0), Ok((0, 1_024)));
    assert_eq!(layout.blinding_position(1_023), Ok((1_023, 1_024)));
    assert_eq!(
        layout.blinding_position(1_024),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    assert_eq!(layout.message_position(0), Ok((0, 0)));
    assert_eq!(layout.message_position(1_023), Ok((0, 1_023)));
    assert_eq!(layout.message_position(1_024), Ok((1, 0)));
    assert_eq!(layout.message_position(1_048_575), Ok((1_023, 1_023)));
    assert_eq!(
        layout.message_position(1_048_576),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    assert_ne!(layout.commitment_key_label_digest(), [0; 32]);
    assert_ne!(layout.generator_basis_digest(), [0; 32]);
    assert_ne!(layout.g_map_digest(), [0; 32]);
    assert_ne!(layout.h_map_digest(), [0; 32]);
    assert_ne!(layout.g_map_digest(), layout.h_map_digest());
    let mut malformed_layout = layout;
    malformed_layout.hiding_generator_index -= 1;
    assert_eq!(
        validate_commitment_preimage_layout(malformed_layout),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let mut spliced_layout = layout;
    spliced_layout.g_map_digest = layout.h_map_digest;
    assert_eq!(
        validate_commitment_preimage_layout(spliced_layout),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    assert_eq!(
        zk_ams_phase23_release_map_set_digest_v1(),
        Ok(release.digest())
    );
    assert_eq!(
        release.digest(),
        ZK_AMS_PHASE23_RELEASE_MAP_SET_KAT_DIGEST_V1,
        "the canonical release-map KAT drifted"
    );
}
#[test]
fn paper_order_manifest_stream_matches_owned_csr_without_row_buffers() {
    let matrix = || {
        SparseMatrix::new(
            2,
            5,
            &[
                (0, 0, s(2)),
                (0, 2, s(3)),
                (0, 3, s(4)),
                (0, 4, s(5)),
                (1, 1, s(6)),
                (1, 2, s(7)),
            ],
        )
        .expect("canonical internal W,u,x matrix")
    };
    let shape = Shape::new(2, 2, 2, matrix(), matrix(), matrix()).expect("tiny relation shape");
    let view = PaperOrderRelationMapViewV1::new(
        ZkAmsPhase23MapKindV1::A,
        &shape.a,
        shape.variable_count(),
        shape.public_input_count(),
    )
    .expect("bounded paper-order view");
    let mut streamed = Vec::new();
    for row in 0..2 {
        let mut entries = Vec::new();
        view.for_each_paper_row_entry(row, |column, coefficient| {
            entries.push((column, coefficient.to_be_bytes()));
            Ok(())
        })
        .expect("stream canonical row");
        streamed.push(entries);
    }
    assert_eq!(
        streamed,
        vec![
            vec![
                (0, s(2).to_be_bytes()),
                (2, s(4).to_be_bytes()),
                (3, s(5).to_be_bytes()),
                (4, s(3).to_be_bytes()),
            ],
            vec![(1, s(6).to_be_bytes()), (4, s(7).to_be_bytes())],
        ]
    );
    let owned = |kind| {
        ZkAmsPhase23SparseMapV1::new(
            kind,
            2,
            5,
            4,
            vec![0, 4, 6],
            vec![0, 2, 3, 4, 1, 4],
            [2, 4, 5, 3, 6, 7]
                .into_iter()
                .map(|value| s(value).to_be_bytes())
                .collect(),
        )
        .expect("canonical owned paper map")
    };
    let maps = [
        owned(ZkAmsPhase23MapKindV1::A),
        owned(ZkAmsPhase23MapKindV1::B),
        owned(ZkAmsPhase23MapKindV1::C),
    ];
    let manifests = [
        compile_paper_order_map_manifest_v1(
            PaperOrderRelationMapViewV1::new(ZkAmsPhase23MapKindV1::A, &shape.a, 2, 2).unwrap(),
        )
        .unwrap(),
        compile_paper_order_map_manifest_v1(
            PaperOrderRelationMapViewV1::new(ZkAmsPhase23MapKindV1::B, &shape.b, 2, 2).unwrap(),
        )
        .unwrap(),
        compile_paper_order_map_manifest_v1(
            PaperOrderRelationMapViewV1::new(ZkAmsPhase23MapKindV1::C, &shape.c, 2, 2).unwrap(),
        )
        .unwrap(),
    ];
    for (map, manifest) in maps.iter().zip(manifests) {
        assert_eq!(sparse_map_manifest_from_owned_v1(map).unwrap(), manifest);
    }
    let layout = compile_commitment_preimage_layout_v1(2).unwrap();
    let release_manifest = ZkAmsPhase23ReleaseMapManifestV1 {
        a: manifests[0],
        b: manifests[1],
        c: manifests[2],
        commitment_preimage_layout: layout,
        digest: release_map_set_digest_v1(manifests[0], manifests[1], manifests[2], layout)
            .unwrap(),
    };
    assert_eq!(
        require_relation_maps_matching_manifest_v1(
            [&maps[0], &maps[1], &maps[2]],
            &shape,
            release_manifest,
        ),
        Ok(())
    );
}
#[test]
fn canonical_release_map_source_retains_only_compact_streaming_metadata() {
    let source = include_str!("phase23_encrypted.rs");
    assert!(!source.contains("Lazy<Result<ZkAmsPhase23ReleaseMapsV1"));
    assert!(!source.contains("compile_paper_order_relation_map_v1"));
    assert!(source.contains("#[cfg(test)]\npub(super) fn require_release_relation_maps_v1"));
    for helper in [
        "sparse_map_manifest_from_owned_v1",
        "sparse_map_matches_paper_view_v1",
        "require_relation_maps_matching_manifest_v1",
    ] {
        let declaration = format!("#[cfg(test)]\nfn {helper}");
        assert!(source.contains(&declaration));
    }
    let manifest_owner = source
        .split("pub struct ZkAmsPhase23ReleaseMapManifestV1")
        .nth(1)
        .and_then(|tail| tail.split("impl ZkAmsPhase23ReleaseMapManifestV1").next())
        .expect("compact manifest declaration");
    assert!(!manifest_owner.contains("Vec<"));
    let row_stream = source
        .split("fn for_each_paper_row_entry")
        .nth(1)
        .and_then(|tail| tail.split("fn compile_release_map_manifest_v1").next())
        .expect("bounded row stream");
    assert!(row_stream.contains("postponed_u"));
    assert!(!row_stream.contains("Vec<"));
    assert!(!row_stream.contains("sort"));
    let compiler = source
        .split("fn compile_release_map_manifest_v1")
        .nth(1)
        .and_then(|tail| tail.split("fn internal_to_paper_column_v1").next())
        .expect("streaming manifest compiler");
    assert!(compiler.contains("compile_paper_order_map_manifest_v1"));
    assert!(!compiler.contains("ZkAmsPhase23SparseMapV1::new"));
    assert!(!compiler.contains("Vec<"));
    assert!(!compiler.contains("sort"));
}
struct TestKeys {
    authentication_a: AuthenticationSecret,
    authentication_b: AuthenticationSecret,
    secret_a: IndependentSecretKey,
    secret_b: IndependentSecretKey,
    public_a: IndependentPublicKey,
    public_b: IndependentPublicKey,
    roster: PartySet,
}
impl TestKeys {
    fn generate(profile: &BgvProfile, random: &mut KatRandom) -> Self {
        let authentication_a = AuthenticationSecret::generate(random).unwrap();
        let authentication_b = AuthenticationSecret::generate(random).unwrap();
        let party_a = authentication_a.party_id().unwrap();
        let party_b = authentication_b.party_id().unwrap();
        let (secret_a, public_a) = independent_keygen(profile, party_a, random).unwrap();
        let (secret_b, public_b) = independent_keygen(profile, party_b, random).unwrap();
        let roster = PartySet::singleton(party_a)
            .union(&PartySet::singleton(party_b))
            .unwrap();
        Self {
            authentication_a,
            authentication_b,
            secret_a,
            secret_b,
            public_a,
            public_b,
            roster,
        }
    }
    fn ordered_secrets(&self) -> Vec<&IndependentSecretKey> {
        if self.secret_a.party < self.secret_b.party {
            vec![&self.secret_a, &self.secret_b]
        } else {
            vec![&self.secret_b, &self.secret_a]
        }
    }
    fn ordered_participants(&self) -> Vec<(&IndependentSecretKey, &AuthenticationSecret)> {
        let mut participants = vec![
            (&self.secret_a, &self.authentication_a),
            (&self.secret_b, &self.authentication_b),
        ];
        participants.sort_by_key(|(secret, _)| secret.party);
        participants
    }
}
fn test_binding(
    profile: &BgvProfile,
    roster: &PartySet,
    accumulated_state_digest: [u8; 32],
    incoming_state_digest: [u8; 32],
) -> ZkAmsPhase23EncryptedBindingV1 {
    ZkAmsPhase23EncryptedBindingV1::new(
        profile.digest().unwrap(),
        roster.digest,
        keccak256(b"phase23-encrypted-test-key-transcript"),
        keccak256(b"phase23-encrypted-test-batch"),
        keccak256(b"phase23-encrypted-test-nifs"),
        keccak256(b"phase23-encrypted-test-ordered-inputs"),
        accumulated_state_digest,
        incoming_state_digest,
        2,
    )
    .unwrap()
}
fn encrypt_collective_vector(
    profile: &BgvProfile,
    binding: ZkAmsPhase23EncryptedBindingV1,
    family: EncryptedFamily,
    values: &[u64],
    keys: &TestKeys,
    random: &mut KatRandom,
) -> EncryptedPackedVector {
    let slots = slots_per_chunk(profile).unwrap();
    let zero = encode_slots_to_rns(profile, &vec![Scalar::zero(); slots]).unwrap();
    let chunks = values
        .chunks(slots)
        .map(|values| {
            let mut packed = vec![Scalar::zero(); slots];
            for (destination, value) in packed.iter_mut().zip(values) {
                *destination = s(*value % 17);
            }
            let message = encode_slots_to_rns(profile, &packed).unwrap();
            let owner = encrypt(profile, &keys.public_a, &message, random).unwrap();
            let other = encrypt(profile, &keys.public_b, &zero, random).unwrap();
            owner.add(&other, profile).unwrap()
        })
        .collect();
    EncryptedPackedVector::new(profile, binding, family, values.len() as u32, chunks).unwrap()
}
fn encrypt_collective_replicated_u(
    profile: &BgvProfile,
    binding: ZkAmsPhase23EncryptedBindingV1,
    scalar: u64,
    row_count: u32,
    keys: &TestKeys,
    random: &mut KatRandom,
) -> EncryptedPackedVector {
    let slots = slots_per_chunk(profile).unwrap();
    let message = encode_slots_to_rns(profile, &vec![s(scalar % 17); slots]).unwrap();
    let zero = encode_slots_to_rns(profile, &vec![Scalar::zero(); slots]).unwrap();
    let owner = encrypt(profile, &keys.public_a, &message, random).unwrap();
    let other = encrypt(profile, &keys.public_b, &zero, random).unwrap();
    let replicated_chunk = owner.add(&other, profile).unwrap();
    let chunk_count = packed_chunk_count(row_count, slots).unwrap();
    EncryptedPackedVector::new(
        profile,
        binding,
        EncryptedFamily::U,
        row_count,
        vec![replicated_chunk; chunk_count],
    )
    .unwrap()
}
fn decrypt_collective_vector(
    profile: &BgvProfile,
    vector: &EncryptedPackedVector,
    keys: &TestKeys,
) -> Result<Vec<u64>, ZkAmsMkheErrorV1> {
    let slots = slots_per_chunk(profile)?;
    let mut output = Vec::with_capacity(vector.chunks.len() * slots);
    let secrets = keys.ordered_secrets();
    for chunk in &vector.chunks {
        let coefficients = decrypt_test_plaintext(profile, chunk, &secrets)?;
        output.extend(
            decode_tiny_slots_from_coefficients(profile, &coefficients)?
                .into_iter()
                .map(tiny_scalar_value)
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    let logical = vector.logical_value_count as usize;
    if vector.family == EncryptedFamily::U {
        let scalar = *output.first().ok_or(ZkAmsMkheErrorV1::InvalidPhase23Fold)?;
        if output.iter().any(|replica| *replica != scalar) {
            return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
        }
    } else if output[logical..].iter().any(|value| *value != 0) {
        return Err(ZkAmsMkheErrorV1::InvalidPhase23Fold);
    }
    output.truncate(logical);
    Ok(output)
}
fn generate_product_key(
    profile: &BgvProfile,
    party_set: &PartySet,
    transcript_digest: [u8; 32],
    left: ZkAmsMkhePartyIdV1,
    right: ZkAmsMkhePartyIdV1,
    participants: &[(&IndependentSecretKey, &AuthenticationSecret)],
    random: &mut KatRandom,
) -> ProductRelinearizationKey {
    let mut ordered = participants.to_vec();
    ordered.sort_by_key(|(secret, _)| secret.party);
    let mut states = Vec::with_capacity(ordered.len());
    let mut first = Vec::with_capacity(ordered.len());
    for &(secret, authentication) in &ordered {
        let (state, contribution) = rkg_round_one(
            profile,
            party_set,
            transcript_digest,
            left,
            right,
            secret,
            authentication,
            random,
        )
        .unwrap();
        states.push(state);
        first.push(contribution);
    }
    let aggregate =
        aggregate_rkg_round_one(profile, party_set, transcript_digest, left, right, &first)
            .unwrap();
    let second = states
        .into_iter()
        .zip(ordered)
        .map(|(state, (secret, authentication))| {
            rkg_round_two(profile, &aggregate, state, secret, authentication, random).unwrap()
        })
        .collect::<Vec<_>>();
    aggregate_rkg_round_two(profile, &aggregate, &second).unwrap()
}
fn evaluation_keys(
    profile: &BgvProfile,
    binding: ZkAmsPhase23EncryptedBindingV1,
    keys: &TestKeys,
    random: &mut KatRandom,
) -> (Vec<GaloisKey>, Vec<ProductRelinearizationKey>) {
    let mut galois = Vec::new();
    let schedule_bits = slots_per_chunk(profile).unwrap().trailing_zeros();
    for bit in 0..schedule_bits {
        let shift = 1_usize << bit;
        let exponent = rotation_exponent(profile, shift).unwrap();
        galois.push(
            generate_galois_key(
                profile,
                binding.transcript_digest,
                exponent,
                &keys.secret_a,
                &keys.public_a,
                &keys.authentication_a,
                random,
            )
            .unwrap(),
        );
        galois.push(
            generate_galois_key(
                profile,
                binding.transcript_digest,
                exponent,
                &keys.secret_b,
                &keys.public_b,
                &keys.authentication_b,
                random,
            )
            .unwrap(),
        );
    }
    // The release schedule omits inverse half-turn because its exponent is
    // identical to the forward half-turn.
    for bit in 0..schedule_bits - 1 {
        let shift = 1_usize << bit;
        let exponent = rotation_exponent_for_direction(profile, shift, true).unwrap();
        galois.push(
            generate_galois_key(
                profile,
                binding.transcript_digest,
                exponent,
                &keys.secret_a,
                &keys.public_a,
                &keys.authentication_a,
                random,
            )
            .unwrap(),
        );
        galois.push(
            generate_galois_key(
                profile,
                binding.transcript_digest,
                exponent,
                &keys.secret_b,
                &keys.public_b,
                &keys.authentication_b,
                random,
            )
            .unwrap(),
        );
    }
    let party_a = keys.secret_a.party;
    let party_b = keys.secret_b.party;
    let participants = keys.ordered_participants();
    let (left, right) = if party_a < party_b {
        (party_a, party_b)
    } else {
        (party_b, party_a)
    };
    let product = vec![
        generate_product_key(
            profile,
            &PartySet::singleton(party_a),
            binding.transcript_digest,
            party_a,
            party_a,
            &[(&keys.secret_a, &keys.authentication_a)],
            random,
        ),
        generate_product_key(
            profile,
            &keys.roster,
            binding.transcript_digest,
            left,
            right,
            &participants,
            random,
        ),
        generate_product_key(
            profile,
            &PartySet::singleton(party_b),
            binding.transcript_digest,
            party_b,
            party_b,
            &[(&keys.secret_b, &keys.authentication_b)],
            random,
        ),
    ];
    (galois, product)
}
#[expect(
    clippy::too_many_arguments,
    reason = "the test helper fixes all six accumulator families plus their exact fixtures"
)]
fn make_state(
    profile: &BgvProfile,
    binding: ZkAmsPhase23EncryptedBindingV1,
    values: [&[u64]; 6],
    strict: bool,
    e_commitment: &[u64],
    w_commitment: &[u64],
    keys: &TestKeys,
    random: &mut KatRandom,
) -> EncryptedAccumulatorState {
    assert_eq!(values[1].len(), 1, "u ingress accepts one relaxed scalar");
    if strict {
        assert_eq!(values[1][0], 1, "strict ingress fixes u=1");
    }
    EncryptedAccumulatorState {
        x: encrypt_collective_vector(
            profile,
            binding,
            EncryptedFamily::X,
            values[0],
            keys,
            random,
        ),
        u: encrypt_collective_replicated_u(
            profile,
            binding,
            values[1][0],
            u32::try_from(values[2].len()).unwrap(),
            keys,
            random,
        ),
        e: encrypt_collective_vector(
            profile,
            binding,
            EncryptedFamily::E,
            values[2],
            keys,
            random,
        ),
        r_e: encrypt_collective_vector(
            profile,
            binding,
            EncryptedFamily::RE,
            values[3],
            keys,
            random,
        ),
        w: encrypt_collective_vector(
            profile,
            binding,
            EncryptedFamily::W,
            values[4],
            keys,
            random,
        ),
        r_w: encrypt_collective_vector(
            profile,
            binding,
            EncryptedFamily::RW,
            values[5],
            keys,
            random,
        ),
        e_commitment: e_commitment.iter().copied().map(s).collect(),
        w_commitment: w_commitment.iter().copied().map(s).collect(),
    }
}
fn evaluate_sparse_oracle(map: &ZkAmsPhase23SparseMapV1, input: &[u64]) -> Vec<u64> {
    (0..map.row_count as usize)
        .map(|row| {
            let start = map.row_offsets[row] as usize;
            let end = map.row_offsets[row + 1] as usize;
            (start..end).fold(0_u64, |sum, index| {
                let coefficient = tiny_scalar_value(
                    Scalar::from_be_bytes_exact(map.coefficients[index]).unwrap(),
                )
                .unwrap();
                (sum + coefficient * input[map.column_indices[index] as usize]) % 17
            })
        })
        .collect()
}
fn linear_fold_oracle(left: &[u64], right: &[u64], challenge: u64) -> Vec<u64> {
    left.iter()
        .zip(right)
        .map(|(left, right)| (left + challenge * right) % 17)
        .collect()
}
fn quadratic_fold_oracle(
    accumulated: &[u64],
    cross: &[u64],
    incoming: &[u64],
    challenge: u64,
    challenge_squared: u64,
) -> Vec<u64> {
    accumulated
        .iter()
        .zip(cross)
        .zip(incoming)
        .map(|((accumulated, cross), incoming)| {
            (accumulated + challenge * cross + challenge_squared * incoming) % 17
        })
        .collect()
}
#[test]
fn canonical_sparse_csr_wire_roundtrip_and_digest_are_exact() {
    let map = sample_map();
    let bytes = map.to_canonical_bytes().unwrap();
    assert_eq!(
        bytes.len(),
        PHASE23_SPARSE_MAP_WIRE_HEADER_BYTES_V1
            + (map.row_count as usize + 1) * 4
            + map.column_indices.len() * 36
            + 32
    );
    assert_eq!(
        ZkAmsPhase23SparseMapV1::from_canonical_bytes(&bytes),
        Ok(map.clone())
    );
    assert_ne!(map.digest, [0; 32]);
    let status = zk_ams_phase23_encrypted_implementation_v1();
    assert_ne!(status.algebra_digest, [0; 32]);
    assert_ne!(status.digest, [0; 32]);
    assert_eq!(status.release_kat_digest, [0; 32]);
    assert!(!status.release_kat_complete);
}

type SparseMapMutationV1 = Box<dyn Fn(&mut ZkAmsPhase23SparseMapV1)>;

#[test]
fn malformed_csr_noncanonical_coefficients_and_resource_bombs_fail_before_use() {
    let baseline = sample_map();
    let invalid_mutations: Vec<SparseMapMutationV1> = vec![
        Box::new(|map| map.version = 2),
        Box::new(|map| map.row_count = 0),
        Box::new(|map| map.column_count = 0),
        Box::new(|map| map.max_row_fan_in = 0),
        Box::new(|map| map.row_offsets[0] = 1),
        Box::new(|map| map.row_offsets[2] = map.row_offsets[1] - 1),
        Box::new(|map| *map.row_offsets.last_mut().unwrap() -= 1),
        Box::new(|map| map.column_indices[1] = map.column_indices[0]),
        Box::new(|map| map.column_indices[1] = 0),
        Box::new(|map| map.column_indices[0] = map.column_count),
        Box::new(|map| map.coefficients[0] = [0; 32]),
        Box::new(|map| map.coefficients[0] = VEGA_T256_SCALAR_MODULUS_BE_V1),
        Box::new(|map| map.digest[0] ^= 1),
    ];
    for mutate in invalid_mutations {
        let mut invalid = baseline.clone();
        mutate(&mut invalid);
        assert!(validate_sparse_map(&invalid).is_err());
    }
    let bytes = baseline.to_canonical_bytes().unwrap();
    for length in [0, 1, 17, bytes.len() - 1] {
        assert!(ZkAmsPhase23SparseMapV1::from_canonical_bytes(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        ZkAmsPhase23SparseMapV1::from_canonical_bytes(&trailing),
        Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
    );
    let mut bad_kind = bytes.clone();
    bad_kind[1] = 0xff;
    assert_eq!(
        ZkAmsPhase23SparseMapV1::from_canonical_bytes(&bad_kind),
        Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
    );
    let mut resource_bomb = bytes;
    resource_bomb[14..18]
        .copy_from_slice(&(ZK_AMS_PHASE23_MAX_CANONICAL_SPARSE_ENTRIES_V1 + 1).to_be_bytes());
    assert_eq!(
        ZkAmsPhase23SparseMapV1::from_canonical_bytes(&resource_bomb),
        Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
    );
}
#[test]
fn tiny_conjugate_slot_packing_multiplies_and_rotates_as_the_ciphertext_oracle_requires() {
    let profile = test_profile();
    let slots = vec![s(1), s(2), s(4), s(8)];
    let encoded = encode_tiny_slots_to_rns(&profile, &slots).unwrap();
    let coefficients = super::super::reduce_test_polynomial(&profile, &encoded).unwrap();
    assert_eq!(
        decode_tiny_slots_from_coefficients(&profile, &coefficients).unwrap(),
        slots
    );
    let squared = encoded.mul(&encoded, &profile).unwrap();
    let coefficients = super::super::reduce_test_polynomial(&profile, &squared).unwrap();
    assert_eq!(
        decode_tiny_slots_from_coefficients(&profile, &coefficients).unwrap(),
        vec![s(1), s(4), s(16), s(13)]
    );
    for shift in 1..4 {
        let transformed = encoded
            .automorphism(rotation_exponent(&profile, shift).unwrap(), &profile)
            .unwrap();
        let coefficients = super::super::reduce_test_polynomial(&profile, &transformed).unwrap();
        let decoded = decode_tiny_slots_from_coefficients(&profile, &coefficients).unwrap();
        assert_eq!(
            decoded,
            (0..4)
                .map(|slot| slots[(slot + shift) % 4])
                .collect::<Vec<_>>()
        );
    }
}
#[test]
fn signed_binary_rotation_preflights_the_complete_work() {
    for slots in [2, 4, 8, 16, 32, 256, 65_536] {
        let observed = (1..slots)
            .map(|shift| {
                let (_, decomposition) = canonical_slot_shift_decomposition(slots, shift).unwrap();
                usize::try_from(decomposition.count_ones()).unwrap()
            })
            .max()
            .unwrap();
        assert_eq!(
            observed,
            super::super::phase23_max_composed_rotation_key_switch_count(slots).unwrap()
        );
    }
    let base = test_profile();
    let party_a = ZkAmsMkhePartyIdV1::new([1; 32]).unwrap();
    let party_b = ZkAmsMkhePartyIdV1::new([2; 32]).unwrap();
    let roster = PartySet::singleton(party_a)
        .union(&PartySet::singleton(party_b))
        .unwrap();
    let rotation_multiplications =
        phase23_rotation_ring_multiplication_count(&base, roster.parties.len(), 1).unwrap();
    let ring_work = super::super::ring_multiplication_work(&base).unwrap();
    let rotation_work = ring_work * u64::try_from(rotation_multiplications).unwrap();
    let mut below_rotation = base.clone();
    below_rotation.max_work_units = rotation_work - 1;
    let below_binding = test_binding(&below_rotation, &roster, [3; 32], [4; 32]);
    let below_ciphertext = zero_ciphertext(&below_rotation, &roster, 0).unwrap();
    assert_eq!(
        rotate_ciphertext_by_slot_shift(&below_rotation, below_binding, &below_ciphertext, 1, &[],),
        Err(ZkAmsMkheErrorV1::ResourceCeilingExceeded)
    );
    let mut exact_rotation = base.clone();
    exact_rotation.max_work_units = rotation_work;
    let exact_binding = test_binding(&exact_rotation, &roster, [3; 32], [4; 32]);
    let exact_ciphertext = zero_ciphertext(&exact_rotation, &roster, 0).unwrap();
    assert_eq!(
        rotate_ciphertext_by_slot_shift(&exact_rotation, exact_binding, &exact_ciphertext, 1, &[],),
        Err(ZkAmsMkheErrorV1::MissingEvaluatedKey)
    );
}
#[test]
fn materialized_six_family_wire_is_canonical_and_mutation_closed() {
    let shape = ZkAmsPhase23AccumulatorShapeV1::new(2, 6, 3, 5, 2).unwrap();
    let materialized = materialized_from_values(
        release_profile_v1().digest().unwrap(),
        [2; 32],
        [3; 32],
        [4; 32],
        [5; 32],
        2,
        shape,
        vec![s(1), s(2)],
        vec![s(3)],
        (4..10).map(s).collect(),
        (10..13).map(s).collect(),
        (1..6).map(s).collect(),
        vec![s(6), s(7)],
    )
    .unwrap();
    let legacy_bytes = legacy_materialized_canonical_bytes_for_test(&materialized).unwrap();
    let mut bytes = Vec::new();
    super::super::write_zk_ams_phase23_materialized_accumulators_canonical_v1(
        &materialized,
        &mut bytes,
    )
    .unwrap();
    assert_eq!(bytes, legacy_bytes);
    assert_eq!(read_materialized_test(&bytes), Ok(materialized.clone()));
    let mut corrupt_digest = bytes.clone();
    *corrupt_digest.last_mut().unwrap() ^= 1;
    assert!(read_materialized_test(&corrupt_digest).is_err());
    let mut noncanonical = bytes.clone();
    let first_value = PHASE23_MATERIALIZED_WIRE_HEADER_BYTES_V1;
    noncanonical[first_value..first_value + 32].copy_from_slice(&VEGA_T256_SCALAR_MODULUS_BE_V1);
    assert!(read_materialized_test(&noncanonical).is_err());
    let mut wrong_u_length = bytes.clone();
    let u_length_offset = 1 + 5 * 32 + 1 + 4;
    wrong_u_length[u_length_offset..u_length_offset + 4].copy_from_slice(&2_u32.to_be_bytes());
    assert!(read_materialized_test(&wrong_u_length).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(read_materialized_test(&trailing).is_err());
}
#[test]
fn materialized_streaming_codec_zeroizes_scratch_and_partial_owner() {
    struct PrefixFailingWriter {
        prefix: Vec<u8>,
        remaining: usize,
    }
    impl std::io::Write for PrefixFailingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::other("intentional sink failure"));
            }
            let written = bytes.len().min(self.remaining);
            self.prefix.extend_from_slice(&bytes[..written]);
            self.remaining -= written;
            Ok(written)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    struct PanicOnScalarWriter {
        written: usize,
    }
    impl std::io::Write for PanicOnScalarWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.written >= PHASE23_MATERIALIZED_WIRE_HEADER_BYTES_V1 {
                panic!("intentional streaming-writer unwind");
            }
            self.written += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    struct PanicAfterReader<'a> {
        bytes: &'a [u8],
        position: usize,
        panic_at: usize,
    }
    impl std::io::Read for PanicAfterReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            if self.position >= self.panic_at {
                panic!("intentional streaming-reader unwind");
            }
            let available = self
                .panic_at
                .saturating_sub(self.position)
                .min(self.bytes.len().saturating_sub(self.position));
            let read = output.len().min(available);
            output[..read].copy_from_slice(&self.bytes[self.position..self.position + read]);
            self.position += read;
            Ok(read)
        }
    }
    let shape = ZkAmsPhase23AccumulatorShapeV1::new(2, 2, 1, 2, 1).unwrap();
    let materialized = materialized_from_values(
        release_profile_v1().digest().unwrap(),
        [2; 32],
        [3; 32],
        [4; 32],
        [5; 32],
        2,
        shape,
        vec![s(1), s(2)],
        vec![s(3)],
        vec![s(4), s(5)],
        vec![s(6)],
        vec![s(7), s(8)],
        vec![s(9)],
    )
    .unwrap();
    let legacy_bytes = legacy_materialized_canonical_bytes_for_test(&materialized).unwrap();
    let scalar_scratch_count = || {
        super::super::phase23_materialized_wire::materialized_scalar_bytes_zeroized_drop_count_v1()
    };
    let before_writer_error = scalar_scratch_count();
    let writer_prefix = PHASE23_MATERIALIZED_WIRE_HEADER_BYTES_V1 + 16;
    let mut failing_writer = PrefixFailingWriter {
        prefix: Vec::new(),
        remaining: writer_prefix,
    };
    assert_eq!(
        super::super::write_zk_ams_phase23_materialized_accumulators_canonical_v1(
            &materialized,
            &mut failing_writer,
        ),
        Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
    );
    assert_eq!(failing_writer.prefix, legacy_bytes[..writer_prefix]);
    assert_eq!(scalar_scratch_count(), before_writer_error + 1);
    let before_writer_unwind = scalar_scratch_count();
    let mut panic_writer = PanicOnScalarWriter { written: 0 };
    let writer_unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::super::write_zk_ams_phase23_materialized_accumulators_canonical_v1(
            &materialized,
            &mut panic_writer,
        )
        .unwrap();
    }));
    assert!(writer_unwind.is_err());
    assert_eq!(scalar_scratch_count(), before_writer_unwind + 1);
    let scratch_count = || {
        super::super::phase23_materialized_wire::materialized_wire_buffer_zeroized_drop_count_v1()
    };
    let before_success = scratch_count();
    let decoded = read_materialized_test(&legacy_bytes).unwrap();
    assert_eq!(decoded, materialized);
    assert_eq!(scratch_count(), before_success + 1);
    drop(decoded);
    let before_error_scratch = scratch_count();
    let before_error_owner = materialized_zeroized_drop_count_v1();
    let mut wrong_profile = legacy_bytes.clone();
    wrong_profile[1] ^= 1;
    assert_eq!(
        read_materialized_test(&wrong_profile),
        Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
    );
    assert_eq!(scratch_count(), before_error_scratch + 1);
    assert_eq!(materialized_zeroized_drop_count_v1(), before_error_owner);
    let before_error_scratch = scratch_count();
    let mut invalid_header = legacy_bytes.clone();
    invalid_header[1 + 5 * 32] = 0;
    assert_eq!(
        read_materialized_test(&invalid_header),
        Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
    );
    assert_eq!(scratch_count(), before_error_scratch + 1);
    assert_eq!(materialized_zeroized_drop_count_v1(), before_error_owner);
    let before_error_scratch = scratch_count();
    let partial_body_end = PHASE23_MATERIALIZED_WIRE_HEADER_BYTES_V1 + 33;
    assert_eq!(
        read_materialized_test(&legacy_bytes[..partial_body_end]),
        Err(ZkAmsMkheErrorV1::InvalidWireEncoding)
    );
    assert_eq!(scratch_count(), before_error_scratch + 1);
    assert_eq!(
        materialized_zeroized_drop_count_v1(),
        before_error_owner + 1
    );
    let before_unwind_scratch = scratch_count();
    let before_unwind_owner = materialized_zeroized_drop_count_v1();
    let mut panic_reader = PanicAfterReader {
        bytes: &legacy_bytes,
        position: 0,
        panic_at: PHASE23_MATERIALIZED_WIRE_HEADER_BYTES_V1 + 32,
    };
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        super::super::read_zk_ams_phase23_materialized_accumulators_canonical_exact_v1(
            &mut panic_reader,
        )
        .unwrap();
    }));
    assert!(unwind.is_err());
    assert_eq!(scratch_count(), before_unwind_scratch + 1);
    assert_eq!(
        materialized_zeroized_drop_count_v1(),
        before_unwind_owner + 1
    );
}
#[test]
fn replicated_u_rejects_mismatched_slots_chunks_lengths_and_legacy_scalar_shape() {
    let u = s(3);
    assert_eq!(collapse_replicated_u_values(vec![u; 8], 8), Ok(vec![u]));
    let mut mismatched_slot = vec![u; 8];
    mismatched_slot[2] = s(4);
    assert_eq!(
        collapse_replicated_u_values(mismatched_slot, 8),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let mut mismatched_chunk = vec![u; 8];
    mismatched_chunk[4] = s(5);
    assert_eq!(
        collapse_replicated_u_values(mismatched_chunk, 8),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    assert_eq!(
        collapse_replicated_u_values(vec![u; 4], 8),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    assert_eq!(
        collapse_replicated_u_values(vec![u], 8),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold),
        "the pre-release single-slot U shape must not be accepted"
    );
    let profile = test_profile();
    let mut random = KatRandom::new(b"phase23-replicated-u-negative-kat");
    let keys = TestKeys::generate(&profile, &mut random);
    let binding = test_binding(&profile, &keys.roster, [0x81; 32], [0x82; 32]);
    let x = [2, 5];
    let scalar_u = [3];
    let e = [1, 2, 3, 4, 5, 6];
    let r_e = [4, 7, 2];
    let w = [1, 4, 6, 8, 3];
    let r_w = [9, 2];
    let valid = make_state(
        &profile,
        binding,
        [&x, &scalar_u, &e, &r_e, &w, &r_w],
        false,
        &[2, 4, 6, 8],
        &[1, 3, 5, 7],
        &keys,
        &mut random,
    );
    validate_accumulator_state(&profile, binding, &valid).unwrap();
    assert_eq!(valid.u.logical_value_count, valid.e.logical_value_count);
    assert_eq!(valid.u.chunks.len(), 2);
    assert_eq!(valid.u.chunks[0], valid.u.chunks[1]);
    let mut different_ciphertext_chunk = valid.clone();
    different_ciphertext_chunk.u.chunks[1] = zero_ciphertext(&profile, &keys.roster, 0).unwrap();
    assert_eq!(
        validate_accumulator_state(&profile, binding, &different_ciphertext_chunk),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let mut wrong_logical_length = valid.clone();
    wrong_logical_length.u.logical_value_count = 5;
    wrong_logical_length.u.digest =
        encrypted_vector_digest(&profile, &wrong_logical_length.u).unwrap();
    assert_eq!(
        validate_accumulator_state(&profile, binding, &wrong_logical_length),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let mut legacy_single_slot = valid.clone();
    legacy_single_slot.u = EncryptedPackedVector::new(
        &profile,
        binding,
        EncryptedFamily::U,
        1,
        vec![valid.u.chunks[0].clone()],
    )
    .unwrap();
    assert_eq!(
        validate_accumulator_state(&profile, binding, &legacy_single_slot),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
}
#[test]
fn encrypted_sparse_equations_6_7_and_9_11_match_independent_two_party_scalar_oracle() {
    let profile = test_profile();
    let mut random = KatRandom::new(b"phase23-encrypted-complete-kat");
    let keys = TestKeys::generate(&profile, &mut random);
    let provisional = test_binding(&profile, &keys.roster, [0x91; 32], [0x92; 32]);
    let acc_x = [2, 5];
    let acc_u = [3];
    let acc_e = [1, 2, 3, 4, 5, 6];
    let acc_re = [4, 7, 2];
    let acc_w = [1, 4, 6, 8, 3];
    let acc_rw = [9, 2];
    let in_x = [7, 1];
    let in_u = [1];
    let in_e = [6, 5, 4, 3, 2, 1];
    let in_re = [8, 3, 6];
    let in_w = [2, 7, 5, 1, 9];
    let in_rw = [4, 6];
    let accumulated = make_state(
        &profile,
        provisional,
        [&acc_x, &acc_u, &acc_e, &acc_re, &acc_w, &acc_rw],
        false,
        &[2, 4, 6, 8],
        &[1, 3, 5, 7],
        &keys,
        &mut random,
    );
    let incoming = make_state(
        &profile,
        provisional,
        [&in_x, &in_u, &in_e, &in_re, &in_w, &in_rw],
        true,
        &[9, 11, 13, 15],
        &[8, 6, 4, 2],
        &keys,
        &mut random,
    );
    let accumulated_digest = accumulator_state_digest(&profile, provisional, &accumulated).unwrap();
    let incoming_digest = accumulator_state_digest(&profile, provisional, &incoming).unwrap();
    let binding = test_binding(&profile, &keys.roster, accumulated_digest, incoming_digest);
    validate_accumulator_state(&profile, binding, &accumulated).unwrap();
    validate_accumulator_state(&profile, binding, &incoming).unwrap();
    let map_a = sample_map();
    let map_b = sparse_map(
        ZkAmsPhase23MapKindV1::B,
        8,
        &[
            vec![(1, 1), (6, 2)],
            vec![(0, 4), (5, 1)],
            vec![(2, 3), (7, 2)],
            vec![(4, 5)],
            vec![(3, 1), (6, 1)],
            vec![(1, 2), (5, 3)],
        ],
    );
    let map_c = sparse_map(
        ZkAmsPhase23MapKindV1::C,
        8,
        &[
            vec![(0, 1), (7, 1)],
            vec![(2, 2), (5, 4)],
            vec![(1, 5)],
            vec![(3, 3), (6, 2)],
            vec![(4, 1), (5, 2)],
            vec![(0, 6), (7, 3)],
        ],
    );
    let (galois_keys, product_keys) = evaluation_keys(&profile, binding, &keys, &mut random);
    let schedule_bits = slots_per_chunk(&profile).unwrap().trailing_zeros() as usize;
    assert_eq!(galois_keys.len(), 2 * (2 * schedule_bits - 1));
    assert_eq!(canonical_slot_shift_decomposition(4, 3), Ok((true, 1)));
    assert_eq!(canonical_slot_shift_decomposition(16, 7), Ok((true, 9)));
    let acc_z = acc_w
        .iter()
        .chain(&acc_x)
        .chain(&acc_u)
        .copied()
        .collect::<Vec<_>>();
    let in_z = in_w
        .iter()
        .chain(&in_x)
        .chain(&in_u)
        .copied()
        .collect::<Vec<_>>();
    let encrypted_az = evaluate_sparse_map(
        &profile,
        binding,
        &map_a,
        &[&accumulated.w, &accumulated.x, &accumulated.u],
        EncryptedFamily::AZ,
        &galois_keys,
    )
    .unwrap();
    assert_eq!(
        decrypt_collective_vector(&profile, &encrypted_az, &keys).unwrap(),
        evaluate_sparse_oracle(&map_a, &acc_z)
    );
    let cross = encrypted_equation_6(
        &profile,
        binding,
        [&map_a, &map_b, &map_c],
        &accumulated,
        &incoming,
        &galois_keys,
        &product_keys,
    )
    .unwrap();
    let az_acc = evaluate_sparse_oracle(&map_a, &acc_z);
    let bz_acc = evaluate_sparse_oracle(&map_b, &acc_z);
    let cz_acc = evaluate_sparse_oracle(&map_c, &acc_z);
    let az_in = evaluate_sparse_oracle(&map_a, &in_z);
    let bz_in = evaluate_sparse_oracle(&map_b, &in_z);
    let cz_in = evaluate_sparse_oracle(&map_c, &in_z);
    let cross_oracle = (0..map_a.row_count as usize)
        .map(|index| {
            (az_acc[index] * bz_in[index] + az_in[index] * bz_acc[index] + 17
                - acc_u[0] * cz_in[index] % 17
                + 17
                - in_u[0] * cz_acc[index] % 17)
                % 17
        })
        .collect::<Vec<_>>();
    let decrypted_cross = decrypt_collective_vector(&profile, &cross, &keys).unwrap();
    assert_eq!(decrypted_cross, cross_oracle);
    assert_eq!(cross.chunks[0].level, 1);
    let r_t_values = [3, 10, 12];
    let r_t = encrypt_collective_vector(
        &profile,
        binding,
        EncryptedFamily::CrossTermRandomness,
        &r_t_values,
        &keys,
        &mut random,
    );
    let g_map = sparse_map(
        ZkAmsPhase23MapKindV1::CommitmentG,
        3,
        &[
            vec![(0, 1), (2, 2)],
            vec![(1, 3)],
            vec![(0, 4)],
            vec![(2, 5)],
        ],
    );
    let h_map = sparse_map(
        ZkAmsPhase23MapKindV1::CommitmentH,
        6,
        &[
            vec![(0, 2), (4, 1)],
            vec![(1, 3), (5, 2)],
            vec![(2, 4)],
            vec![(3, 5), (4, 2)],
        ],
    );
    let committed = encrypted_equation_7(
        &profile,
        binding,
        &g_map,
        &h_map,
        &cross,
        &r_t,
        &galois_keys,
    )
    .unwrap();
    let public_cross_commitment =
        decrypt_collective_vector(&profile, &committed.encrypted_commitment, &keys).unwrap();
    let g_oracle = evaluate_sparse_oracle(&g_map, &r_t_values);
    let h_oracle = evaluate_sparse_oracle(&h_map, &cross_oracle);
    assert_eq!(
        public_cross_commitment,
        g_oracle
            .iter()
            .zip(h_oracle)
            .map(|(left, right)| (left + right) % 17)
            .collect::<Vec<_>>()
    );
    let public_cross_scalars = public_cross_commitment
        .iter()
        .copied()
        .map(s)
        .collect::<Vec<_>>();
    let challenge_context = ZkAmsPhase23ChallengeContextV1 {
        batch_id: binding.batch_id,
        nifs_verifier_digest: binding.nifs_verifier_digest,
        ordered_batch_input_digest: binding.ordered_batch_input_digest,
        accumulated_error_commitment_digest: commitment_vector_digest(
            b"iroha.zk-ams.v1.phase23.error-commitment",
            &accumulated.e_commitment,
        )
        .unwrap(),
        accumulated_witness_commitment_digest: commitment_vector_digest(
            b"iroha.zk-ams.v1.phase23.witness-commitment",
            &accumulated.w_commitment,
        )
        .unwrap(),
        incoming_error_commitment_digest: commitment_vector_digest(
            b"iroha.zk-ams.v1.phase23.error-commitment",
            &incoming.e_commitment,
        )
        .unwrap(),
        incoming_witness_commitment_digest: commitment_vector_digest(
            b"iroha.zk-ams.v1.phase23.witness-commitment",
            &incoming.w_commitment,
        )
        .unwrap(),
        cross_term_commitment_digest: commitment_vector_digest(
            b"iroha.zk-ams.v1.phase23.cross-term-commitment",
            &public_cross_scalars,
        )
        .unwrap(),
        fold_index: binding.fold_index,
    };
    let challenge = zk_ams_phase23_challenge_v1(challenge_context).unwrap();
    let tiny_challenge = tiny_scalar_value(challenge).unwrap();
    let tiny_challenge_squared = tiny_scalar_value(challenge.square()).unwrap();
    assert_ne!(
        tiny_challenge, 0,
        "the pinned KAT must exercise a nonzero tiny challenge"
    );
    let folded = fold_encrypted_accumulators(
        &profile,
        binding,
        &accumulated,
        &incoming,
        &committed,
        &public_cross_scalars,
        challenge_context,
    )
    .unwrap();
    assert_eq!(
        decrypt_collective_vector(&profile, &folded.x, &keys).unwrap(),
        linear_fold_oracle(&acc_x, &in_x, tiny_challenge)
    );
    let expected_u = linear_fold_oracle(&acc_u, &in_u, tiny_challenge)[0];
    assert_eq!(
        decrypt_collective_vector(&profile, &folded.u, &keys).unwrap(),
        vec![expected_u; acc_e.len()]
    );
    assert_eq!(
        decrypt_collective_vector(&profile, &folded.e, &keys).unwrap(),
        quadratic_fold_oracle(
            &acc_e,
            &cross_oracle,
            &in_e,
            tiny_challenge,
            tiny_challenge_squared,
        )
    );
    assert_eq!(
        decrypt_collective_vector(&profile, &folded.r_e, &keys).unwrap(),
        quadratic_fold_oracle(
            &acc_re,
            &r_t_values,
            &in_re,
            tiny_challenge,
            tiny_challenge_squared,
        )
    );
    assert_eq!(
        decrypt_collective_vector(&profile, &folded.w, &keys).unwrap(),
        linear_fold_oracle(&acc_w, &in_w, tiny_challenge)
    );
    assert_eq!(
        decrypt_collective_vector(&profile, &folded.r_w, &keys).unwrap(),
        linear_fold_oracle(&acc_rw, &in_rw, tiny_challenge)
    );
    assert_eq!(folded.e.chunks[0].level, 1);
    assert_eq!(folded.r_e.chunks[0].level, 0);
    let x = decrypt_collective_vector(&profile, &folded.x, &keys).unwrap();
    let u = decrypt_collective_vector(&profile, &folded.u, &keys).unwrap();
    let e = decrypt_collective_vector(&profile, &folded.e, &keys).unwrap();
    let r_e = decrypt_collective_vector(&profile, &folded.r_e, &keys).unwrap();
    let w = decrypt_collective_vector(&profile, &folded.w, &keys).unwrap();
    let r_w = decrypt_collective_vector(&profile, &folded.r_w, &keys).unwrap();
    let shape = ZkAmsPhase23AccumulatorShapeV1::new(2, 6, 3, 5, 2).unwrap();
    let materialized_u =
        collapse_replicated_u_values(u.iter().copied().map(s).collect(), shape.e).unwrap();
    let materialized = materialized_from_values(
        release_profile_v1().digest().unwrap(),
        binding.roster_digest,
        binding.transcript_digest,
        binding.batch_id,
        binding.ordered_batch_input_digest,
        binding.fold_index,
        shape,
        x.iter().copied().map(s).collect(),
        materialized_u,
        e.iter().copied().map(s).collect(),
        r_e.iter().copied().map(s).collect(),
        w.iter().copied().map(s).collect(),
        r_w.iter().copied().map(s).collect(),
    )
    .unwrap();
    let mut materialized_wire = Vec::new();
    super::super::write_zk_ams_phase23_materialized_accumulators_canonical_v1(
        &materialized,
        &mut materialized_wire,
    )
    .unwrap();
    assert_eq!(
        read_materialized_test(&materialized_wire),
        Ok(materialized.clone())
    );
    // Missing, duplicated, or transcript-spliced evaluated keys must never
    // trigger a plaintext or partial-roster fallback.
    assert!(
        evaluate_sparse_map(
            &profile,
            binding,
            &map_a,
            &[&accumulated.w, &accumulated.x, &accumulated.u],
            EncryptedFamily::AZ,
            &[],
        )
        .is_err()
    );
    let mut duplicate_galois_keys = galois_keys.clone();
    duplicate_galois_keys.extend(galois_keys.clone());
    assert!(
        evaluate_sparse_map(
            &profile,
            binding,
            &map_a,
            &[&accumulated.w, &accumulated.x, &accumulated.u],
            EncryptedFamily::AZ,
            &duplicate_galois_keys,
        )
        .is_err()
    );
    let mut spliced_galois_keys = galois_keys.clone();
    for key in &mut spliced_galois_keys {
        key.transcript_digest[0] ^= 1;
    }
    assert!(
        evaluate_sparse_map(
            &profile,
            binding,
            &map_a,
            &[&accumulated.w, &accumulated.x, &accumulated.u],
            EncryptedFamily::AZ,
            &spliced_galois_keys,
        )
        .is_err()
    );
    assert!(
        encrypted_equation_6(
            &profile,
            binding,
            [&map_a, &map_b, &map_c],
            &accumulated,
            &incoming,
            &galois_keys,
            &product_keys[..2],
        )
        .is_err()
    );
    let mut duplicate_product_keys = product_keys.clone();
    duplicate_product_keys.extend(product_keys.clone());
    assert!(
        encrypted_equation_6(
            &profile,
            binding,
            [&map_a, &map_b, &map_c],
            &accumulated,
            &incoming,
            &galois_keys,
            &duplicate_product_keys,
        )
        .is_err()
    );
    let mut spliced_product_keys = product_keys.clone();
    for key in &mut spliced_product_keys {
        key.transcript_digest[0] ^= 1;
    }
    assert!(
        encrypted_equation_6(
            &profile,
            binding,
            [&map_a, &map_b, &map_c],
            &accumulated,
            &incoming,
            &galois_keys,
            &spliced_product_keys,
        )
        .is_err()
    );
    // Session, fold, state, and Fiat--Shamir replay/substitution attempts
    // are rejected even when each substituted object is otherwise valid.
    let different_batch_binding = ZkAmsPhase23EncryptedBindingV1::new(
        binding.profile_digest,
        binding.roster_digest,
        binding.transcript_digest,
        [0x73; 32],
        binding.nifs_verifier_digest,
        binding.ordered_batch_input_digest,
        binding.accumulated_state_digest,
        binding.incoming_state_digest,
        binding.fold_index,
    )
    .unwrap();
    assert!(validate_accumulator_state(&profile, different_batch_binding, &accumulated).is_err());
    let different_fold_binding = ZkAmsPhase23EncryptedBindingV1::new(
        binding.profile_digest,
        binding.roster_digest,
        binding.transcript_digest,
        binding.batch_id,
        binding.nifs_verifier_digest,
        binding.ordered_batch_input_digest,
        binding.accumulated_state_digest,
        binding.incoming_state_digest,
        binding.fold_index + 1,
    )
    .unwrap();
    assert!(validate_accumulator_state(&profile, different_fold_binding, &accumulated).is_err());
    assert!(
        encrypted_equation_6(
            &profile,
            binding,
            [&map_a, &map_b, &map_c],
            &incoming,
            &accumulated,
            &galois_keys,
            &product_keys,
        )
        .is_err()
    );
    assert!(
        fold_encrypted_accumulators(
            &profile,
            binding,
            &incoming,
            &accumulated,
            &committed,
            &public_cross_scalars,
            challenge_context,
        )
        .is_err()
    );
    let mut tampered_accumulated = accumulated.clone();
    tampered_accumulated.x.digest[0] ^= 1;
    assert!(
        fold_encrypted_accumulators(
            &profile,
            binding,
            &tampered_accumulated,
            &incoming,
            &committed,
            &public_cross_scalars,
            challenge_context,
        )
        .is_err()
    );
    let mut replayed_context = challenge_context;
    replayed_context.cross_term_commitment_digest[0] ^= 1;
    assert!(
        fold_encrypted_accumulators(
            &profile,
            binding,
            &accumulated,
            &incoming,
            &committed,
            &public_cross_scalars,
            replayed_context,
        )
        .is_err()
    );
    let mut substituted_public_commitment = public_cross_scalars.clone();
    substituted_public_commitment[0] += s(1);
    assert!(
        fold_encrypted_accumulators(
            &profile,
            binding,
            &accumulated,
            &incoming,
            &committed,
            &substituted_public_commitment,
            challenge_context,
        )
        .is_err()
    );
    let wrong_dimension_map = sparse_map(
        ZkAmsPhase23MapKindV1::A,
        7,
        &[
            vec![(0, 1)],
            vec![(1, 1)],
            vec![(2, 1)],
            vec![(3, 1)],
            vec![(4, 1)],
            vec![(5, 1)],
        ],
    );
    assert!(
        evaluate_sparse_map(
            &profile,
            binding,
            &wrong_dimension_map,
            &[&accumulated.w, &accumulated.x, &accumulated.u],
            EncryptedFamily::AZ,
            &galois_keys,
        )
        .is_err()
    );
    let padded = encrypt_collective_vector(
        &profile,
        binding,
        EncryptedFamily::X,
        &[1, 9],
        &keys,
        &mut random,
    );
    let nonzero_padding =
        EncryptedPackedVector::new(&profile, binding, EncryptedFamily::X, 1, padded.chunks)
            .unwrap();
    assert_eq!(
        decrypt_collective_vector(&profile, &nonzero_padding, &keys),
        Err(ZkAmsMkheErrorV1::InvalidPhase23Fold)
    );
    let mut kat = Keccak256::new();
    let mut kat_frame = b"iroha.zk-ams.v1.phase23.encrypted-tiny-complete-kat".to_vec();
    kat.update(&kat_frame);
    for map in [&map_a, &map_b, &map_c, &g_map, &h_map] {
        let wire = map.to_canonical_bytes().unwrap();
        let mut frame = PHASE23_SPARSE_MAP_DOMAIN_V1.to_vec();
        frame.extend_from_slice(&wire[..wire.len() - 32]);
        assert_eq!(keccak256(&frame), map.digest);
        kat.update(&map.digest);
        kat_frame.extend_from_slice(&map.digest);
    }
    for values in [
        &decrypted_cross,
        &public_cross_commitment,
        &x,
        &u,
        &e,
        &r_e,
        &w,
        &r_w,
    ] {
        kat.update(&(values.len() as u32).to_be_bytes());
        kat_frame.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for value in values {
            kat.update(&value.to_be_bytes());
            kat_frame.extend_from_slice(&value.to_be_bytes());
        }
    }
    let mut materialized_frame = PHASE23_MATERIALIZED_DOMAIN_V1.to_vec();
    materialized_frame.extend_from_slice(&materialized_wire[..materialized_wire.len() - 32]);
    assert_eq!(keccak256(&materialized_frame), materialized.digest);
    kat.update(&materialized.digest);
    kat_frame.extend_from_slice(&materialized.digest);
    let kat_digest = kat.finalize();
    assert_eq!(keccak256(&kat_frame), kat_digest);
    // Independently reproduced with PyCryptodome Keccak-256 over all five
    // complete map frames, the 830-byte materialized frame, and this 547-byte
    // KAT frame. Materialization binds the release BGV profile; the tiny ring
    // remains the encrypted-equation oracle and does not supply that identity.
    assert_eq!(
        kat_digest,
        [
            242, 127, 136, 118, 107, 156, 76, 92, 2, 149, 119, 90, 133, 150, 128, 21, 98, 6, 195,
            35, 201, 86, 90, 199, 150, 248, 159, 46, 227, 19, 172, 186,
        ],
        "the independently checked two-party encrypted Phase-II/III KAT drifted"
    );
}
