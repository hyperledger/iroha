#[test]
fn network_defaults_carry_maximal_sumeragi_frames() {
    // Every committed configuration is validated against this chain frame limit: the 16 MiB
    // payload maximum plus the sync-entry and outer-response allowances (`2 * FRAME_OVERHEAD`,
    // `specs/sumeragi.md` §9.4). Proposals, manifests and sync entries carry signed metadata and
    // the availability table, never the payload, and payload rows are at most 256 KiB. The
    // largest Sumeragi frame is therefore a sync response within the local `sync_max_bytes`,
    // which startup keeps at most this limit minus one allowance.
    let chain_frame_limit =
        usize::try_from(iroha_data_model::sumeragi_finality::CHAIN_TRANSPORT_FRAME_LIMIT).unwrap();
    assert_eq!(chain_frame_limit, 17_305_664);
    assert_eq!(
        defaults::network::MAX_FRAME_BYTES.get(),
        17 * 1024 * 1024 + defaults::network::DEFAULT_AEAD_FRAME_OVERHEAD_BYTES
    );
    assert_eq!(
        defaults::network::MAX_FRAME_BYTES_CONSENSUS,
        defaults::network::MAX_PLAINTEXT_FRAME_BYTES
    );
    assert_eq!(
        defaults::network::MAX_FRAME_BYTES_BLOCK_SYNC,
        defaults::network::MAX_PLAINTEXT_FRAME_BYTES
    );
    assert!(
        defaults::network::MAX_FRAME_BYTES_BLOCK_SYNC.get() > chain_frame_limit,
        "the block-sync frame cap must carry every Sumeragi frame a committed configuration allows"
    );
    assert_eq!(
        defaults::network::MAX_FRAME_BYTES_CONTROL.get(),
        2 * 1024 * 1024,
        "Sumeragi control frames (votes, certificates, timeouts, status) use the consensus-safety control topic"
    );
}
