// Exact payload and frame contracts for the daemon's positive PoR archive fixture.

#[test]
fn por_replay_archive_fixture_round_trips_exact_production_payload() {
    let record = por_replay_archive_record_fixture();
    let canonical = encode_por_replay_archive_record(&record).expect("valid production record");
    let fixture: PorReplayArchiveRecordFixtureV1 =
        decode_canonical(&canonical, MAX_POR_REPLAY_ARCHIVE_RECORD_BYTES_V1)
            .expect("production payload decodes into the exact fixture layout");
    assert!(fixture.finalized.repair_task_id.is_none());
    assert!(fixture.finalized.repair_handoff_acknowledged);
    let replay = encode_canonical(&fixture, MAX_POR_REPLAY_ARCHIVE_RECORD_BYTES_V1)
        .expect("encode the fixture production frame");
    assert_eq!(replay, canonical);
    assert_eq!(
        decode_por_replay_archive_record(&replay).expect("validate replayed production record"),
        record,
    );
}

#[test]
fn por_replay_archive_fixture_has_distinct_nominal_and_shared_root_frame() {
    use norito::NoritoSchema as _;

    assert_eq!(
        PorReplayArchiveRecordFixtureV1::nominal_name(),
        "irohad::runtime_provider_broker::protocol::platform::tests::PorReplayArchiveRecordFixtureV1",
    );
    assert_eq!(
        node::PorFinalizedReplayArchiveRecordV1::nominal_name(),
        "sorafs_node::por::PorFinalizedReplayArchiveRecordV1",
    );
    assert_ne!(
        PorReplayArchiveRecordFixtureV1::nominal_name(),
        node::PorFinalizedReplayArchiveRecordV1::nominal_name(),
    );
    assert_eq!(
        PorReplayArchiveRecordFixtureV1::frame_name(),
        node::PorFinalizedReplayArchiveRecordV1::frame_name(),
    );
    assert_eq!(
        norito::schema::identity::frame_hash::<PorReplayArchiveRecordFixtureV1>(),
        norito::schema::identity::frame_hash::<node::PorFinalizedReplayArchiveRecordV1>(),
    );
    assert_ne!(
        <Vec<PorReplayArchiveRecordFixtureV1> as norito::NoritoSchema>::nominal_name(),
        <Vec<node::PorFinalizedReplayArchiveRecordV1> as norito::NoritoSchema>::nominal_name(),
    );
}

#[test]
fn por_replay_archive_fixture_rejects_foreign_root_frame() {
    const SCHEMA_OFFSET: usize = 4 + 1 + 1;

    let record = por_replay_archive_record_fixture();
    let canonical = encode_por_replay_archive_record(&record).expect("valid production record");
    assert_eq!(
        decode_por_replay_archive_record(&canonical).expect("positive bounded-reader witness"),
        record,
    );
    let header = norito::core::Header::read(canonical.as_slice()).expect("typed record header");
    assert_eq!(
        header.schema,
        norito::schema::identity::frame_hash::<PorReplayArchiveRecordFixtureV1>(),
    );
    let foreign_schema =
        norito::schema::identity::frame_hash::<Vec<PorReplayArchiveRecordFixtureV1>>();
    assert_ne!(foreign_schema, header.schema);
    let mut foreign = canonical;
    // Change only the fixed header identity. The valid payload and checksum stay exact.
    foreign[SCHEMA_OFFSET..SCHEMA_OFFSET + foreign_schema.len()].copy_from_slice(&foreign_schema);
    assert!(matches!(
        norito::decode_canonical::<node::PorFinalizedReplayArchiveRecordV1>(&foreign),
        Err(norito::Error::SchemaMismatch)
    ));
    assert_eq!(
        decode_por_replay_archive_record(&foreign),
        Err(BrokerError::Protocol),
    );
}
