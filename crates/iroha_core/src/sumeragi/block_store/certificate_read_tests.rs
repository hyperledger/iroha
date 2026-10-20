//! Real-model certificate parsing, exact retained admission and corruption controls.

use super::*;
use iroha_data_model::{
    block::{CommitCertificate, decode_framed_signed_block},
    sumeragi_finality::test_fixtures::NativeFinalityFixture,
};

fn fixture() -> iroha_data_model::block::SharedSignedBlock {
    let fixture = NativeFinalityFixture::new();
    crate::block::reserve_block_for_tests()
        .initialize(decode_framed_signed_block(&fixture.latest().block_wire).unwrap())
}

fn with_parts(
    source: &SignedBlock,
    header: Vec<u8>,
    qc: Vec<u8>,
    table: Vec<u8>,
) -> iroha_data_model::block::SharedSignedBlock {
    crate::block::reserve_block_for_tests().initialize(
        source
            .clone()
            .with_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
                header,
                qc,
                source
                    .commit_certificate()
                    .unwrap()
                    .result_preimage()
                    .to_vec(),
                table,
            ))),
    )
}

#[test]
fn exact_canonical_artifacts_retain_original_source_and_original_pool() {
    let source = fixture();
    let budget = AllocationBudget::new(1 << 25);
    let decoded = CertificateRead::new(source.clone(), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|_| panic!("valid canonical artifacts"));
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &source,
        &decoded.source
    ));
    assert!(decoded.availability.admitted_to(&budget));
    let original = source.commit_certificate().unwrap();
    assert_eq!(
        norito::encode_canonical(&decoded.header).unwrap(),
        original.consensus_header()
    );
    assert_eq!(
        norito::encode_canonical(&decoded.commit_qc).unwrap(),
        original.commit_qc()
    );
    assert_eq!(
        norito::encode_canonical(&decoded.availability).unwrap(),
        original.availability()
    );
    drop(decoded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn every_backing_and_shared_control_refusal_retains_exact_original_owners() {
    let base = fixture();
    let measure = AllocationBudget::new(1 << 25);
    let decoded = CertificateRead::new(base.clone(), measure.clone())
        .complete(&measure)
        .unwrap_or_else(|_| panic!("measure actual availability control"));
    let table_len = decoded.availability.as_slice().len();
    let table_total = measure.reserved_bytes();
    assert!(table_total > table_len);
    drop(decoded);
    assert_eq!(measure.reserved_bytes(), 0);

    let source = base;
    let budget = AllocationBudget::new(0);
    let (job, error) = CertificateRead::new(source.clone(), budget.clone())
        .complete(&budget)
        .err()
        .expect("table backing refuses");
    assert!(matches!(error, CertificateReadError::Admission(ref e) if e.is_local_refusal()));
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        job.source(),
        &source
    ));
    assert!(job.table_backing.is_none());
    assert_eq!(
        job.retained_owners_for_test(),
        (std::ptr::from_ref(source.as_ref()), None)
    );

    budget.set_limit_bytes(table_len);
    let (job, error) = job
        .complete(&budget)
        .err()
        .expect("table shared control refuses");
    assert!(matches!(error, CertificateReadError::Admission(ref e) if e.is_local_refusal()));
    let table_pointer = job.table_backing.as_ref().unwrap().as_slice().as_ptr();
    assert_eq!(
        job.retained_owners_for_test(),
        (std::ptr::from_ref(source.as_ref()), Some(table_pointer))
    );
    assert_eq!(budget.reserved_bytes(), table_len);
    let (job, _) = job.complete(&budget).err().expect("same table retained");
    assert_eq!(
        job.table_backing.as_ref().unwrap().as_slice().as_ptr(),
        table_pointer
    );

    budget.set_limit_bytes(table_total);
    let decoded = job
        .complete(&budget)
        .unwrap_or_else(|_| panic!("all original owners complete"));
    assert_eq!(decoded.availability.as_slice().as_ptr(), table_pointer);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &decoded.source,
        &source
    ));
    drop(decoded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn foreign_pool_cannot_replace_captured_pool_before_or_during_admission() {
    let source = fixture();
    let budget = AllocationBudget::new(0);
    let foreign = AllocationBudget::new(1 << 25);
    let (job, error) = CertificateRead::new(source.clone(), budget.clone())
        .complete(&foreign)
        .err()
        .expect("foreign initial pool");
    assert!(matches!(error, CertificateReadError::ForeignBudget));
    assert!(job.header.is_none() && job.qc.is_none());
    let (job, _) = job.complete(&budget).err().expect("original refusal");
    let (job, error) = job.complete(&foreign).err().expect("foreign retry pool");
    assert!(matches!(error, CertificateReadError::ForeignBudget));
    assert_eq!(foreign.reserved_bytes(), 0);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        job.source(),
        &source
    ));
    budget.set_limit_bytes(1 << 25);
    let decoded = job
        .complete(&budget)
        .unwrap_or_else(|_| panic!("original pool resumes"));
    assert!(decoded.availability.admitted_to(&budget));
    assert!(!decoded.availability.admitted_to(&foreign));
}

#[test]
fn malformed_frames_remain_corruption_without_funded_destination_or_absence() {
    let source = fixture();
    let c = source.commit_certificate().unwrap();
    let parts = [c.consensus_header(), c.commit_qc(), c.availability()];
    for index in 0..3 {
        for replacement in [vec![], vec![1, 2, 3], [parts[index], &[0]].concat()] {
            let mut changed = parts.map(<[u8]>::to_vec);
            changed[index] = replacement;
            let [header, qc, table] = changed;
            let changed = with_parts(&source, header, qc, table);
            let budget = AllocationBudget::new(1 << 25);
            let (job, error) = CertificateRead::new(changed.clone(), budget.clone())
                .complete(&budget)
                .err()
                .expect("malformed canonical part");
            assert!(matches!(error, CertificateReadError::Decode(_)));
            assert_eq!(budget.reserved_bytes(), 0);
            let (job, error) = job
                .complete(&budget)
                .err()
                .expect("same corruption on retry");
            assert!(matches!(error, CertificateReadError::Decode(_)));
            assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
                job.source(),
                &changed
            ));
        }
    }
}

#[test]
fn malformed_signed_table_count_and_header_cap_reject_before_output_allocation() {
    let source = fixture();
    let c = source.commit_certificate().unwrap();
    let original: AvailabilityFrame = norito::decode_canonical(c.availability()).unwrap();
    for count in [0u32, 1, u32::MAX] {
        let mut bytes = original.as_slice().to_vec();
        bytes[..4].copy_from_slice(&count.to_be_bytes());
        let table =
            norito::encode_canonical(&AvailabilityFrame::from_untrusted(bytes).unwrap()).unwrap();
        let source = with_parts(
            &source,
            c.consensus_header().to_vec(),
            c.commit_qc().to_vec(),
            table,
        );
        let budget = AllocationBudget::new(1 << 25);
        let (_, error) = CertificateRead::new(source, budget.clone())
            .complete(&budget)
            .err()
            .unwrap();
        assert!(matches!(error, CertificateReadError::Decode(_)));
        assert_eq!(budget.reserved_bytes(), 0);
    }
    let oversized = vec![
        0;
        crate::sumeragi::durable_record_codec::MAX_HEADER_METADATA_BYTES
            + ncore::Header::SIZE
            + 1
    ];
    assert!(matches!(
        metadata::decoded_header(&oversized),
        Err(CertificateReadError::Decode(
            norito::Error::FieldLengthExceeded { .. }
        ))
    ));
    let budget = AllocationBudget::new(1 << 25);
    assert!(matches!(
        metadata::header(&oversized, &budget),
        Err(CertificateReadError::Decode(
            norito::Error::FieldLengthExceeded { .. }
        ))
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn absent_certificate_is_an_explicit_error() {
    let source = crate::block::reserve_block_for_tests()
        .initialize(fixture().as_ref().clone().with_commit_certificate(None));
    let budget = AllocationBudget::new(0);
    let (_, error) = CertificateRead::new(source, budget.clone())
        .complete(&budget)
        .err()
        .unwrap();
    assert!(matches!(error, CertificateReadError::MissingCertificate));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn prefix_metadata_refusal_retains_original_source_header_and_release_provenance() {
    let source = fixture();
    let pool = AllocationBudget::new(1 << 25);
    let foreign = AllocationBudget::new(1 << 25);
    let certificate = source.commit_certificate().unwrap();
    let header = metadata::header(certificate.consensus_header(), &pool).unwrap();
    let header_bytes = pool.reserved_bytes();
    let qc = metadata::qc(certificate.commit_qc(), &pool).unwrap();
    let qc_bytes = pool.reserved_bytes() - header_bytes;
    drop((header, qc));
    let blocker = pool
        .try_reserve_bytes(pool.limit_bytes() - header_bytes - qc_bytes + 1)
        .unwrap();
    let (job, error) = CertificateRead::new(source.clone(), pool.clone())
        .complete_for_prefix(&pool)
        .err()
        .expect("original QC capacity refusal");
    let expected = pool.try_reserve_bytes(qc_bytes).unwrap_err();
    assert!(
        matches!(error,
        CertificateReadError::Admission(ByteAdmissionError::Buffer(iroha_allocation::ChargedBufferError::Admission(actual)))
        if actual == expected),
        "prefix metadata preserves the original release observation"
    );
    let header_pointer = std::ptr::from_ref(&**job.prefix_header.as_ref().unwrap());
    assert!(job.prefix_qc.is_none());
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &source,
        job.source()
    ));
    let (job, error) = job
        .complete_for_prefix(&foreign)
        .err()
        .expect("foreign retry");
    assert!(matches!(error, CertificateReadError::ForeignBudget));
    assert_eq!(
        std::ptr::from_ref(&**job.prefix_header.as_ref().unwrap()),
        header_pointer
    );
    assert_eq!(foreign.reserved_bytes(), 0);
    let (job, error) = job
        .complete_for_prefix(&pool)
        .err()
        .expect("same original refusal");
    assert!(matches!(error,
        CertificateReadError::Admission(ByteAdmissionError::Buffer(iroha_allocation::ChargedBufferError::Admission(actual)))
        if actual == expected));
    drop(blocker);
    let decoded = job
        .complete_for_prefix(&pool)
        .unwrap_or_else(|_| panic!("original source resumes"));
    assert_eq!(std::ptr::from_ref(&*decoded.header), header_pointer);
    assert!(decoded.header.belongs_to(&pool) && decoded.commit_qc.belongs_to(&pool));
    assert!(decoded.availability.admitted_to(&pool));
    drop(decoded);
    assert_eq!(pool.reserved_bytes(), 0);
}

/// Independent oracle: the generic derived decoder that the other durable stores use.
fn durable_header(raw: &[u8]) -> Result<BlockHeader, norito::Error> {
    use crate::sumeragi::durable_record_codec::{MAX_HEADER_METADATA_BYTES, decode_header};
    if raw.len() > MAX_HEADER_METADATA_BYTES + ncore::Header::SIZE {
        return Err(norito::Error::FieldLengthExceeded {
            length: raw.len() as u64,
            limit: (MAX_HEADER_METADATA_BYTES + ncore::Header::SIZE) as u64,
        });
    }
    let view = ncore::from_bytes_view(raw)?;
    if view.schema() != norito::schema::identity::frame_hash::<BlockHeader>() {
        return Err(norito::Error::SchemaMismatch);
    }
    let header = {
        let _context = ncore::PayloadCtxGuard::enter_with_schema_and_flags(
            view.as_bytes(),
            view.schema(),
            view.flags(),
        );
        decode_header(view.as_bytes())?
    };
    norito::verify_exact_canonical_frame(&header, raw)?;
    Ok(header)
}

fn durable_qc(raw: &[u8]) -> Result<Qc, norito::Error> {
    use crate::sumeragi::durable_qc_codec::{QcMetadata, parse_frame};
    parse_frame(raw).map(QcMetadata::finish)
}

// The canonical field layouts of BlockHeader and Qc with unchecked leaves, so every
// differential case reaches both decoders as a genuine checksummed frame.
#[derive(norito::Encode)]
struct KeyWire(Vec<u8>);

#[derive(norito::Encode)]
struct HeaderWire {
    instance: iroha_sumeragi::types::Hash32,
    epoch: iroha_sumeragi::types::EpochId,
    height: u64,
    origin_view: u64,
    parent_hash: iroha_sumeragi::types::Hash32,
    parent_result: iroha_sumeragi::types::Hash32,
    payload_hash: iroha_sumeragi::types::Hash32,
    availability_digest: iroha_sumeragi::types::Hash32,
    payload_len: u32,
    proposer: u32,
    skipped_leaders: Vec<KeyWire>,
    control_witness: Vec<u8>,
}
impl norito::NoritoSchema for HeaderWire {
    fn nominal_name() -> String {
        <BlockHeader as norito::NoritoSchema>::nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        Some("iroha_sumeragi::BlockHeader")
    }
}
impl HeaderWire {
    fn from_header(header: &BlockHeader) -> Self {
        Self {
            instance: header.instance,
            epoch: header.epoch,
            height: header.height,
            origin_view: header.origin_view,
            parent_hash: header.parent_hash,
            parent_result: header.parent_result,
            payload_hash: header.payload_hash,
            availability_digest: header.availability_digest,
            payload_len: header.payload_len,
            proposer: header.proposer,
            skipped_leaders: header
                .skipped_leaders
                .iter()
                .map(|key| KeyWire(key.as_bytes().to_vec()))
                .collect(),
            control_witness: header.control_witness.as_slice().to_vec(),
        }
    }
}

#[derive(norito::Encode)]
struct QcWire {
    kind: u32,
    instance: iroha_sumeragi::types::Hash32,
    epoch: iroha_sumeragi::types::EpochId,
    height: u64,
    view: u64,
    block_hash: iroha_sumeragi::types::Hash32,
    result: iroha_sumeragi::types::Hash32,
    signers: iroha_sumeragi::types::Bitmap,
    agg_sig: iroha_sumeragi::types::AggregateSignature,
}
impl norito::NoritoSchema for QcWire {
    fn nominal_name() -> String {
        <Qc as norito::NoritoSchema>::nominal_name()
    }
    fn static_frame_name() -> Option<&'static str> {
        Some("iroha_sumeragi::Qc")
    }
}
impl QcWire {
    fn from_qc(qc: &Qc) -> Self {
        Self {
            kind: match qc.kind {
                iroha_sumeragi::message::VoteKind::Prepare => 0,
                iroha_sumeragi::message::VoteKind::Commit => 1,
            },
            instance: qc.instance,
            epoch: qc.epoch,
            height: qc.height,
            view: qc.view,
            block_hash: qc.block_hash,
            result: qc.result,
            signers: qc.signers.clone(),
            agg_sig: qc.agg_sig,
        }
    }
}

fn alternate_layout<T: norito::core::NoritoSerialize>(value: &T) -> Vec<u8> {
    let _flags = ncore::DecodeFlagsGuard::enter(
        ncore::default_encode_flags() ^ ncore::header_flags::COMPACT_LEN,
    );
    ncore::to_bytes(value).unwrap()
}

fn flipped_layout_flag(raw: &[u8]) -> Vec<u8> {
    let mut changed = raw.to_vec();
    changed[ncore::Header::SIZE - 1] ^= ncore::header_flags::COMPACT_LEN;
    changed
}

fn differential_header_cases(raw: &[u8]) -> Vec<(&'static str, Vec<u8>, bool)> {
    use iroha_sumeragi::types::{
        MAX_COMMITTEE_SIZE, MAX_CONTROL_WITNESS_BYTES, MAX_PUBLIC_KEY_LEN,
    };
    let original: BlockHeader = norito::decode_canonical(raw).unwrap();
    let wire = |change: &dyn Fn(&mut HeaderWire)| {
        let mut value = HeaderWire::from_header(&original);
        change(&mut value);
        norito::encode_canonical(&value).unwrap()
    };
    let keys = |count: usize, length: usize| {
        wire(&|value| {
            value.skipped_leaders = (0..count)
                .map(|index| KeyWire(vec![u8::try_from(index % 251).unwrap() + 1; length]))
                .collect();
        })
    };
    assert_eq!(
        wire(&|_| {}),
        raw,
        "the wire mirror reproduces the canonical header"
    );
    vec![
        ("fixture header", raw.to_vec(), true),
        ("header with a trailing byte", [raw, &[0]].concat(), false),
        ("header with a 0-byte key", keys(1, 0), false),
        ("header with a 1-byte key", keys(1, 1), true),
        (
            "header with a 128-byte key",
            keys(1, MAX_PUBLIC_KEY_LEN),
            true,
        ),
        (
            "header with a 129-byte key",
            keys(1, MAX_PUBLIC_KEY_LEN + 1),
            false,
        ),
        ("header with 32 keys", keys(32, 48), true),
        (
            "header with the maximum key count",
            keys(MAX_COMMITTEE_SIZE, 1),
            true,
        ),
        (
            "header above the maximum key count",
            keys(MAX_COMMITTEE_SIZE + 1, 1),
            false,
        ),
        (
            "header with a 2048-byte witness",
            wire(&|value| value.control_witness = vec![7; MAX_CONTROL_WITNESS_BYTES]),
            true,
        ),
        (
            "header with a 2049-byte witness",
            wire(&|value| value.control_witness = vec![7; MAX_CONTROL_WITNESS_BYTES + 1]),
            false,
        ),
        (
            "header in the alternate COMPACT_LEN layout",
            alternate_layout(&original),
            false,
        ),
        (
            "header with a flipped COMPACT_LEN flag",
            flipped_layout_flag(raw),
            false,
        ),
    ]
}

fn differential_qc_cases(raw: &[u8]) -> Vec<(&'static str, Vec<u8>, bool)> {
    use iroha_sumeragi::{message::MAX_BITMAP_BYTES, types::Bitmap};
    let original: Qc = norito::decode_canonical(raw).unwrap();
    let wire = |change: &dyn Fn(&mut QcWire)| {
        let mut value = QcWire::from_qc(&original);
        change(&mut value);
        norito::encode_canonical(&value).unwrap()
    };
    let bitmap = |length: usize| wire(&|value| value.signers = Bitmap::from_bytes(vec![1; length]));
    assert_eq!(
        wire(&|_| {}),
        raw,
        "the wire mirror reproduces the canonical QC"
    );
    vec![
        ("fixture QC", raw.to_vec(), true),
        ("QC with a trailing byte", [raw, &[0]].concat(), false),
        ("QC with an empty bitmap", bitmap(0), true),
        ("QC with a 5-byte bitmap", bitmap(5), true),
        ("QC with the maximum bitmap", bitmap(MAX_BITMAP_BYTES), true),
        (
            "QC above the maximum bitmap",
            bitmap(MAX_BITMAP_BYTES + 1),
            false,
        ),
        (
            "QC with VoteKind tag 0",
            wire(&|value| value.kind = 0),
            true,
        ),
        (
            "QC with VoteKind tag 1",
            wire(&|value| value.kind = 1),
            true,
        ),
        (
            "QC with VoteKind tag 2",
            wire(&|value| value.kind = 2),
            false,
        ),
        (
            "QC in the alternate COMPACT_LEN layout",
            alternate_layout(&original),
            false,
        ),
        (
            "QC with a flipped COMPACT_LEN flag",
            flipped_layout_flag(raw),
            false,
        ),
    ]
}

/// Both destinations of the sole certificate metadata decoder agree with the generic durable
/// decoder on every accept/reject verdict and accepted value, including each boundary and
/// layout corruption, and the body and prefix readers return the same verdict per frame.
#[test]
fn certificate_metadata_kernel_matches_durable_decoder_verdicts_and_values() {
    let source = fixture();
    let certificate = source.commit_certificate().unwrap();
    let pool = AllocationBudget::new(1 << 25);
    let header_cases = differential_header_cases(certificate.consensus_header());
    let qc_cases = differential_qc_cases(certificate.commit_qc());
    // Swapped frames exercise both schema checks with otherwise genuine canonical bytes.
    let swapped = [
        (
            "QC frame read as a header",
            certificate.commit_qc().to_vec(),
            false,
        ),
        (
            "header frame read as a QC",
            certificate.consensus_header().to_vec(),
            false,
        ),
    ];
    for (label, raw, accepted) in header_cases.iter().chain([&swapped[0]]) {
        let durable = durable_header(raw);
        let funded = metadata::header(raw, &pool);
        let native = metadata::decoded_header(raw);
        match (&durable, &funded, &native) {
            (Ok(durable), Ok(funded), Ok(native)) => {
                assert_eq!(durable, &**funded, "{label}");
                assert_eq!(durable, native, "{label}");
            }
            (
                Err(_),
                Err(CertificateReadError::Decode(_)),
                Err(CertificateReadError::Decode(_)),
            ) => {}
            _ => panic!(
                "{label}: durable {durable:?}, funded {funded:?} and native {native:?} disagree"
            ),
        }
        assert_eq!(durable.is_ok(), *accepted, "{label}");
        drop(funded);
        assert_eq!(pool.reserved_bytes(), 0, "{label}");
        reader_verdicts(&source, label, raw, certificate.commit_qc(), *accepted);
    }
    for (label, raw, accepted) in qc_cases.iter().chain([&swapped[1]]) {
        let durable = durable_qc(raw);
        let funded = metadata::qc(raw, &pool);
        let native = metadata::decoded_qc(raw);
        match (&durable, &funded, &native) {
            (Ok(durable), Ok(funded), Ok(native)) => {
                assert_eq!(durable, &**funded, "{label}");
                assert_eq!(durable, native, "{label}");
            }
            (
                Err(_),
                Err(CertificateReadError::Decode(_)),
                Err(CertificateReadError::Decode(_)),
            ) => {}
            _ => panic!(
                "{label}: durable {durable:?}, funded {funded:?} and native {native:?} disagree"
            ),
        }
        assert_eq!(durable.is_ok(), *accepted, "{label}");
        drop(funded);
        assert_eq!(pool.reserved_bytes(), 0, "{label}");
        reader_verdicts(
            &source,
            label,
            certificate.consensus_header(),
            raw,
            *accepted,
        );
    }
}

// Both certificate reader destinations reach the same verdict for one stored frame pair.
fn reader_verdicts(
    source: &iroha_data_model::block::SharedSignedBlock,
    label: &str,
    header: &[u8],
    qc: &[u8],
    accepted: bool,
) {
    let changed = with_parts(
        source,
        header.to_vec(),
        qc.to_vec(),
        source.commit_certificate().unwrap().availability().to_vec(),
    );
    let pool = AllocationBudget::new(1 << 25);
    let native = CertificateRead::new(changed.clone(), pool.clone()).complete(&pool);
    let prefix = CertificateRead::new(changed, pool.clone()).complete_for_prefix(&pool);
    match (native, prefix) {
        (Ok(native), Ok(prefix)) => {
            assert!(accepted, "{label}: both readers accept a rejected frame");
            assert_eq!(native.header, *prefix.header, "{label}");
            assert_eq!(native.commit_qc, *prefix.commit_qc, "{label}");
        }
        (Err((_, CertificateReadError::Decode(_))), Err((_, CertificateReadError::Decode(_)))) => {
            assert!(!accepted, "{label}: both readers reject an accepted frame")
        }
        (native, prefix) => panic!(
            "{label}: native {:?} and prefix {:?} readers disagree",
            native.err().map(|(_, error)| error),
            prefix.err().map(|(_, error)| error),
        ),
    }
    assert_eq!(pool.reserved_bytes(), 0, "{label}");
}
