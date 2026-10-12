//! Rust reference generator of `fixtures/sccp/finality_v1.json` and
//! `fixtures/sccp/finality_rust_v1.json` (`specs/sccp.md` §3.6–§3.8, §5.1.3, §11.2, §11.3).
//!
//! `finality_v1.json` is also written by the independent Python reference
//! (`scripts/sccp_reference/vectors_finality.py`), and the two outputs must be byte-identical.
//! This target rebuilds the whole document from `iroha_sccp::v1`, `iroha_data_model` and
//! `iroha_crypto::bls::consensus`: the §11.2 worked examples (every value the specification
//! pins is asserted while building), valid and invalid headers, `result_of_preimage` bounds,
//! signer-bitmap encodings, the §11.3 test keys and committees, full certificates and their
//! negatives, each with the outcome the Rust destination model gives on EVM and on TON.
//!
//! `finality_rust_v1.json` holds the one §11.3 negative the Python reference cannot make: a
//! certificate whose aggregate comes from the generic signing API of `iroha_crypto` (the w3f
//! transcript) instead of the consensus API. Only this target writes it, and
//! `pytests/scripts/test_sccp_reference.py` checks that the Python reference rejects it.
//!
//! Drift tests: `reference_finality_v1_matches_committed_fixture` and
//! `reference_finality_rust_v1_matches_committed_fixture`. After a reviewed change, rewrite
//! the files with
//! `cargo test -p iroha_sccp --test v1_reference_finality -- --ignored regenerate`.

mod reference_support;

use iroha_data_model::bridge::SccpNetworkV1;
use iroha_sccp::v1::{
    committee::{
        BLS12_381_HALF_P, BLS12_381_P, COMMITTEE_TAG, FP_LEN, IDENTITY_SIGNATURE,
        IDENTITY_SIGNATURE_EVM, KEY_LEN, SIGNATURE_LEN, committee_root, key_y,
        signer_point_is_on_curve, signer_ys,
    },
    destination::{DeploymentV1, Destination, DestinationFlavor},
    evidence::{
        anchor_chunk_path, anchor_chunk_position, anchor_chunk_root, anchor_leaf, anchor_node,
        forgery_evidence_id, verify_anchor_path,
    },
    finality::{
        COMMIT_PREIMAGE_LEN, CertificateError, DST_SIG, FLAG_ACTIVE, FLAG_ROTATION,
        MAX_HISTORY_SIZE, MAX_RESULT_BODY_BYTES, MAX_RESULT_PREIMAGE_BYTES, MAX_VALIDITY_MS,
        QC_FIXED_LEN, QcFixedV1, RESULT_BODY_TAG, RESULT_TAG, SccpFinalityHeaderFieldsV1,
        SccpFinalityHeaderV1, TAG_SIG, X_HEAD_LEN, X_LEN, X_MAGIC, X_TAIL_LEN, bitmap_from_signers,
        body_digest, checkpoint_id, commit_message, commit_preimage, outer_result,
        result_of_preimage, signers_from_bitmap, verify_certificate,
    },
    hashes::{to_hex, word_address},
};
use norito::json::Value;
use reference_support::{
    DESTINATION_CLOCK_CONVENTION, REFERENCE_GENERATORS, REGENERATE_COMMAND,
    assert_matches_committed,
    bls_support::{
        curve_point_outside_g2, fp_add, fp_add_small, fp_sub, g1_eip2537, g1_generator, g1_json,
        g1_minus, g1_negated_sum, g1_plus, g1_shift_outside_subgroup, g2_evm192, g2_generator,
        g2_json, group_order, hex_integer, keygen, negated_g1_generator, pairing_input, sign_w3f,
        test_key,
    },
    check_destination_clock, dec, header_fields_json, hexes, hx, hx_string, insert, list, num, obj,
    outcome_name, parsed_header_json, python_json, qc_fixed_json,
    taira_sim::{Certificate, CertifyOptions, Committee, TairaSim, signers_from_indices},
    text, unhex, write_fixture,
};
use sha2::{Digest as _, Sha256};

/// The file both references write.
const FINALITY: &str = "finality_v1.json";
/// The file only this target writes.
const FINALITY_RUST: &str = "finality_rust_v1.json";
/// The command that rewrites [`FINALITY_RUST`], and [`FINALITY`] with it.
const REGENERATE_FINALITY: &str =
    "cargo test -p iroha_sccp --test v1_reference_finality -- --ignored regenerate";

/// Taira's `NetworkId` in every vector.
const NETWORK_ID: [u8; 32] = [0x11; 32];
/// The consensus instance `I` in every vector.
const INSTANCE: [u8; 32] = [0x77; 32];
/// Base Taira time of the certificates (ms).
const T0: u64 = 1_790_000_000_000;
/// One hour (ms).
const HOUR: u64 = 3_600_000;
/// The validity of the pinned generation and of the rotations (ms).
const VALIDITY: u64 = 1_209_600_000;
/// The pinned generation.
const GENERATION: u64 = 7;
/// The first height of the pinned generation.
const START_HEIGHT: u64 = 7000;
/// The NUL ciphersuite tag: a signature under it is no consensus signature.
const DST_NUL: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
/// Kind byte of a Prepare vote.
const KIND_PREPARE: u8 = 0x02;
/// The supply cap of the verification-only deployments.
const SUPPLY_CAP: u128 = 1_000_000_000_000_000_000;

// §11.2 values that the specification pins. They are asserted on every build.
const SPEC_R_ROTATION: &str = "3fcdcdfce761808f1a1f633fd209c197738d93032a0c5496ff20fb9bbcd783d7";
const SPEC_R_HEARTBEAT: &str = "ec15d2c034f21de8f6a6192bd246d5ee7acf99ae452c7a70f7c6003b567b1ed4";
const SPEC_R_NON_ROTATION: &str =
    "93d642e5cd5e489a395a937a88c63834fceaa8db9ef267e600f70ba58027c9ac";
const SPEC_R_INACTIVE: &str = "541b29c5e6058adb34edef96855cb321fdcdc635fc92e4ac25777d1b3ea07b1a";
const SPEC_ID_ROTATION: &str = "b0a93737e03cec3ff52c920efa7db18859883ecb598ff7bdd2bf19f67c1086f6";
const SPEC_ID_HEARTBEAT: &str = "0ae4bff13d50fc7129b3fcd5926df55d5da6afc8a33445abed1a1a7e650537a4";
const SPEC_ID_NON_ROTATION: &str =
    "2d519a8ba8b000583ee3d0e6ec06843d95c3f7de32bf5ff9a76e6fad0fbbda6c";
const SPEC_M: &str = "85c684fac5aab78b197a5e2d40329ec518bc038abd99974a37064ea26e4943e0";
const SPEC_FORGERY_ID: &str = "5fe24c413eba8a5e1d7727f630f9bf0c005286c75662061a8216b0292a454f35";
const SPEC_ANCHOR_7199: &str = "a22346dda5d3ec12cd1308908cbbcb509f68f3b860377153ca4bae4a5f13df65";
const SPEC_ANCHOR_7200: &str = "0422761979d4e89d78edd5dcfbd719b1f6e10f339603a53da14e4b1587202ed7";
const SPEC_ANCHOR_NODE: &str = "1d1e5d3ee82efa64b0c2703e18202b34c29bed398a688bb1626f873c2d36d1a3";
const SPEC_CHUNK0_ROOT: &str = "2367ae00d979ce576c55f1be87c6971c22921aae16c939eb9ff85b820d2e235f";
const SPEC_SYNTHETIC_COMMITTEE_ROOT: &str =
    "fe8902a93a6592a748b8528a9f49312e9cbc5d1abcccb1ff7431b0acba92b2b9";
/// `−g1.y` (§0).
const SPEC_NEG_G1_Y: &str = "114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";
/// `HALF_P = (p − 1) / 2` (§0).
const SPEC_HALF_P: &str = "0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555";

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

/// Fail unless `actual` is the value the specification prints.
fn check_spec(actual: &[u8], expected_hex: &str, what: &str) {
    assert_eq!(
        to_hex(actual),
        expected_hex,
        "{what} differs from the specification value"
    );
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The parsed header of `fields`.
///
/// # Panics
/// When the fields violate X1–X7.
fn valid(fields: &SccpFinalityHeaderFieldsV1) -> SccpFinalityHeaderV1 {
    SccpFinalityHeaderV1::from_fields(fields).expect("a header that satisfies X1-X7")
}

/// `fields` after `change`: one header that differs from another in the fields named.
fn with(
    mut fields: SccpFinalityHeaderFieldsV1,
    change: impl FnOnce(&mut SccpFinalityHeaderFieldsV1),
) -> SccpFinalityHeaderFieldsV1 {
    change(&mut fields);
    fields
}

/// The fields of the inactive form at `height`.
fn inactive(height: u64, timestamp_ms: u64) -> SccpFinalityHeaderFieldsV1 {
    SccpFinalityHeaderFieldsV1 {
        network_id: NETWORK_ID,
        height,
        timestamp_ms,
        ..SccpFinalityHeaderFieldsV1::default()
    }
}

/// `{ascii, hex}` of a tag.
fn tag_json(tag: &[u8]) -> Value {
    obj([("ascii", ascii(tag)), ("hex", hx(tag))])
}

fn ascii(tag: &[u8]) -> Value {
    text(core::str::from_utf8(tag).expect("an ASCII tag"))
}

/// The destination word of the TON verification context: a minter's account id. This one is
/// a placeholder (`control_v1.json` lists the same value under `destination_words`).
const TON_DESTINATION_WORD: [u8; 32] = [0x35; 32];

fn destination_word() -> [u8; 32] {
    word_address(&[0x22; 20])
}

fn indices_json(indices: &[usize]) -> Value {
    list(indices.iter().map(|index| num(*index as u64)))
}

fn fp_array(bytes: &[u8]) -> [u8; FP_LEN] {
    bytes.try_into().expect("48 bytes")
}

// ---------------------------------------------------------------------------------------------
// Constants and worked examples (§3.9, §11.2)
// ---------------------------------------------------------------------------------------------

fn constants_json() -> Value {
    let negated = negated_g1_generator();
    let negated_y = key_y(&negated).expect("−g1 is a point of the curve");
    check_spec(&negated_y, SPEC_NEG_G1_Y, "−g1.y");
    check_spec(&BLS12_381_HALF_P, SPEC_HALF_P, "HALF_P");
    obj([
        ("x_magic", tag_json(X_MAGIC)),
        ("x_len", num(X_LEN as u64)),
        ("x_head_len", num(X_HEAD_LEN as u64)),
        ("x_tail_len", num(X_TAIL_LEN as u64)),
        ("result_tag", tag_json(RESULT_TAG)),
        ("result_body_tag", tag_json(RESULT_BODY_TAG)),
        ("tag_sig", tag_json(TAG_SIG)),
        (
            "dst_sig",
            obj([
                ("ascii", ascii(DST_SIG)),
                ("hex", hx(DST_SIG)),
                ("len", num(DST_SIG.len() as u64)),
            ]),
        ),
        ("qc_fixed_len", num(QC_FIXED_LEN as u64)),
        ("commit_preimage_len", num(COMMIT_PREIMAGE_LEN as u64)),
        ("committee_tag", ascii(COMMITTEE_TAG)),
        ("max_validity_ms", num(MAX_VALIDITY_MS)),
        ("max_history_size", dec(MAX_HISTORY_SIZE.into())),
        (
            "bls12_381",
            obj([
                ("p", hex_integer(&BLS12_381_P)),
                ("half_p", hex_integer(&BLS12_381_HALF_P)),
                ("r", hex_integer(&group_order())),
                ("g1", g1_json(&g1_generator())),
                ("neg_g1", g1_json(&negated)),
                ("neg_g1_y", hex_integer(&negated_y)),
                ("g2", g2_json(&g2_generator())),
            ]),
        ),
    ])
}

/// §11.2, every value asserted against the specification.
fn worked_examples() -> Value {
    let d_body = [0x66; 32];
    let rotation = SccpFinalityHeaderFieldsV1 {
        network_id: [0x11; 32],
        height: 7200,
        timestamp_ms: 1_790_000_000_000,
        flags: FLAG_ACTIVE | FLAG_ROTATION,
        message_count: 2,
        sccp_root: [0x22; 32],
        history_size: 5,
        history_root: [0x33; 32],
        generation: 3,
        committee_root: [0x44; 32],
        validity_ms: 1_209_600_000,
        next_committee_root: [0x55; 32],
    };
    let heartbeat = with(rotation, |x| x.next_committee_root = [0x44; 32]);
    let non_rotation = with(rotation, |x| {
        x.height = 7199;
        x.timestamp_ms = 1_789_999_999_000;
        x.flags = FLAG_ACTIVE;
        x.validity_ms = 0;
        x.next_committee_root = [0; 32];
    });
    let spec_x = |height_and_time: &str, flags: &str, validity: &str, next: &str| {
        [
            "534343502f46494e414c4954592f5631",
            &"11".repeat(32),
            height_and_time,
            flags,
            "00000002",
            &"22".repeat(32),
            "0000000000000005",
            &"33".repeat(32),
            "0000000000000003",
            &"44".repeat(32),
            validity,
            &next.repeat(32),
        ]
        .concat()
    };
    let cases = [
        (
            "rotation",
            rotation,
            SPEC_R_ROTATION,
            Some(SPEC_ID_ROTATION),
            Some(spec_x(
                "0000000000001c20000001a0c4506c00",
                "03",
                "0000000048190800",
                "55",
            )),
        ),
        (
            "heartbeat",
            heartbeat,
            SPEC_R_HEARTBEAT,
            Some(SPEC_ID_HEARTBEAT),
            None,
        ),
        (
            "non_rotation",
            non_rotation,
            SPEC_R_NON_ROTATION,
            Some(SPEC_ID_NON_ROTATION),
            Some(spec_x(
                "0000000000001c1f000001a0c4506818",
                "01",
                "0000000000000000",
                "00",
            )),
        ),
        (
            "inactive",
            SccpFinalityHeaderFieldsV1 {
                network_id: [0x11; 32],
                height: 9,
                timestamp_ms: 1_790_000_000_000,
                ..SccpFinalityHeaderFieldsV1::default()
            },
            SPEC_R_INACTIVE,
            None,
            None,
        ),
    ];
    let mut cases_json = obj([]);
    for (name, fields, spec_r, spec_id, spec_bytes) in cases {
        let header = valid(&fields);
        let r = outer_result(&header, &d_body).0;
        check_spec(&r, spec_r, &format!("R({name})"));
        let mut entry = obj([
            ("fields", header_fields_json(&fields)),
            ("x", hx(header.as_bytes())),
            ("d_body", hx(&d_body)),
            ("r", hx(&r)),
        ]);
        if let Some(spec_id) = spec_id {
            let id = checkpoint_id(header.as_bytes());
            check_spec(&id, spec_id, &format!("checkpoint_id({name})"));
            insert(&mut entry, "checkpoint_id", hx(&id));
        }
        if let Some(spec_bytes) = spec_bytes {
            check_spec(header.as_bytes(), &spec_bytes, &format!("X({name})"));
        }
        insert(&mut cases_json, name, entry);
    }

    let signer_indices = [0, 9, 30];
    let qc = QcFixedV1 {
        epoch: 2,
        epoch_context: [0x88; 32],
        view: 1,
        block_hash: [0x99; 32],
        result_body: [0x66; 32],
        signers: signers_from_indices(&signer_indices),
    };
    let spec_qc = [
        "0000000000000002",
        &"88".repeat(32),
        "0000000000000001",
        &"99".repeat(32),
        &"66".repeat(32),
        "40000201",
    ]
    .concat();
    check_spec(&qc.encode(), &spec_qc, "QC_FIXED");
    assert_eq!(QcFixedV1::parse(&qc.encode()), Ok(qc));
    let bitmap = bitmap_from_signers(qc.signers, 31).expect("the indices are below 31");
    assert_eq!(signers_from_bitmap(&bitmap, 31), Some(qc.signers));

    let r_rotation = outer_result(&valid(&rotation), &d_body).0;
    let r_non_rotation = outer_result(&valid(&non_rotation), &d_body).0;
    let preimage = commit_preimage(&INSTANCE, &qc, 7200, &r_rotation);
    let m = commit_message(&preimage);
    check_spec(&m, SPEC_M, "m");
    let forgery_id = forgery_evidence_id(3, &m, 0x4000_0201);
    check_spec(&forgery_id, SPEC_FORGERY_ID, "forgery evidence id");

    let core_hash = [0x99; 32];
    let leaf_7199 = anchor_leaf(7199, &core_hash, &r_non_rotation);
    let leaf_7200 = anchor_leaf(7200, &core_hash, &r_rotation);
    check_spec(&leaf_7199, SPEC_ANCHOR_7199, "anchor_leaf(7199)");
    check_spec(&leaf_7200, SPEC_ANCHOR_7200, "anchor_leaf(7200)");
    let pair = anchor_node(&leaf_7199, &leaf_7200);
    check_spec(&pair, SPEC_ANCHOR_NODE, "anchor node");
    assert_eq!(anchor_chunk_position(7199), Some((1, 3102)));
    assert_eq!(anchor_chunk_position(7200), Some((1, 3103)));
    let chunk0: Vec<[u8; 32]> = (1..=4096)
        .map(|height| anchor_leaf(height, &core_hash, &d_body))
        .collect();
    let chunk0_root = anchor_chunk_root(&chunk0).expect("a completed chunk");
    check_spec(&chunk0_root, SPEC_CHUNK0_ROOT, "chunk 0 root");
    let path_of = |position: usize| {
        let path = anchor_chunk_path(&chunk0, position).expect("a position of the chunk");
        assert!(verify_anchor_path(
            &chunk0[position],
            position,
            &path,
            &chunk0_root
        ));
        hexes(&path)
    };

    let synthetic_keys = [[1_u8; KEY_LEN], [2; KEY_LEN], [3; KEY_LEN], [4; KEY_LEN]];
    let synthetic = committee_root(&synthetic_keys).expect("four keys have a root");
    check_spec(
        &synthetic,
        SPEC_SYNTHETIC_COMMITTEE_ROOT,
        "synthetic committee root",
    );

    obj([
        ("cases", cases_json),
        (
            "qc_fixed",
            obj([
                ("fields", qc_fixed_json(&qc)),
                ("signer_indices", indices_json(&signer_indices)),
                ("bitmap", hx(&bitmap)),
                ("encoded", hx(&qc.encode())),
                // The bitmap bytes read big-endian: what a raw copy would put in `signers`.
                ("raw_bitmap_signers_negative", hex_integer(&bitmap)),
            ]),
        ),
        (
            "commit",
            obj([
                ("instance", hx(&INSTANCE)),
                ("epoch", num(qc.epoch)),
                ("epoch_context", hx(&qc.epoch_context)),
                ("height", num(7200)),
                ("view", num(qc.view)),
                ("block_hash", hx(&qc.block_hash)),
                ("r", hx(&r_rotation)),
                ("preimage", hx(&preimage)),
                ("m", hx(&m)),
            ]),
        ),
        (
            "forgery_evidence_id",
            obj([
                ("generation", num(3)),
                ("m", hx(&m)),
                ("signers", num(0x4000_0201)),
                ("id", hx(&forgery_id)),
            ]),
        ),
        (
            "anchors",
            obj([
                ("core_hash", hx(&core_hash)),
                (
                    "leaf_7199",
                    obj([
                        ("chunk", num(1)),
                        ("position", num(3102)),
                        ("r", hx(&r_non_rotation)),
                        ("leaf", hx(&leaf_7199)),
                    ]),
                ),
                (
                    "leaf_7200",
                    obj([
                        ("chunk", num(1)),
                        ("position", num(3103)),
                        ("r", hx(&r_rotation)),
                        ("leaf", hx(&leaf_7200)),
                    ]),
                ),
                ("node_7199_7200", hx(&pair)),
                (
                    "chunk0_all_99_66",
                    obj([
                        ("root", hx(&chunk0_root)),
                        ("path_height_1", path_of(0)),
                        ("path_height_4096", path_of(4095)),
                        ("leaf_height_1", hx(&chunk0[0])),
                        ("leaf_height_4096", hx(&chunk0[4095])),
                    ]),
                ),
            ]),
        ),
        (
            "synthetic_committee_root",
            obj([("keys", hexes(&synthetic_keys)), ("root", hx(&synthetic))]),
        ),
    ])
}

// ---------------------------------------------------------------------------------------------
// Headers, `result_of_preimage` and signer encodings (§3.6, §3.7)
// ---------------------------------------------------------------------------------------------

/// `headers.valid` and `headers.invalid`. The `destination` column is what the destination
/// model answers for a certificate that carries the header, not a literal.
#[allow(
    clippy::too_many_lines,
    reason = "one list of the header vectors, in the order of the file"
)]
fn header_vectors(world: &World) -> Value {
    // Any well-formed certificate: the header checks precede everything that reads its other
    // fields.
    let n4 = &world.n4;
    let probe = world.certify_plain(&header(n4, 7099), n4);
    let outcome = |pin: &Pin, flavor: DestinationFlavor, x: &[u8]| {
        let carried = Certificate {
            header: x.to_vec(),
            ..probe.clone()
        };
        pin.outcome(flavor, &carried, world.now)
    };
    let base = SccpFinalityHeaderFieldsV1 {
        network_id: NETWORK_ID,
        height: 7100,
        timestamp_ms: T0,
        flags: FLAG_ACTIVE,
        message_count: 3,
        sccp_root: [0x21; 32],
        history_size: 12,
        history_root: [0x31; 32],
        generation: GENERATION,
        committee_root: [0x41; 32],
        validity_ms: 0,
        next_committee_root: [0; 32],
    };
    let rotation = with(base, |x| {
        x.flags = FLAG_ACTIVE | FLAG_ROTATION;
        x.validity_ms = VALIDITY;
        x.next_committee_root = [0x51; 32];
    });
    let empty_block = with(base, |x| {
        x.message_count = 0;
        x.sccp_root = [0; 32];
    });
    let valid_rows = [
        ("non_rotation", base),
        ("rotation", rotation),
        (
            "heartbeat",
            with(rotation, |x| x.next_committee_root = base.committee_root),
        ),
        ("empty_block", empty_block),
        (
            "empty_history",
            with(empty_block, |x| {
                x.history_size = 0;
                x.history_root = [0; 32];
            }),
        ),
        (
            "maximal",
            with(rotation, |x| {
                x.message_count = 512;
                x.history_size = MAX_HISTORY_SIZE;
                x.validity_ms = MAX_VALIDITY_MS;
                x.height = (1 << 53) - 1;
                x.timestamp_ms = (1 << 53) - 1;
            }),
        ),
        ("inactive", inactive(7100, T0)),
        ("inactive_height_1", inactive(1, 0)),
    ]
    .map(|(label, fields)| {
        let header = valid(&fields);
        assert_eq!(header.fields(), fields);
        // An active header passes step 2 on a destination pinned at its generation and root
        // (it is then refused for the calldata committee, which is not the one the synthetic
        // root names); an inactive one does not.
        let pin = Pin {
            generation: if fields.generation == 0 {
                GENERATION
            } else {
                fields.generation
            },
            committee_root: if fields.committee_root == [0; 32] {
                [0x41; 32]
            } else {
                fields.committee_root
            },
            ..Pin::of(n4)
        };
        let evm = outcome(&pin, DestinationFlavor::Evm, header.as_bytes());
        assert_eq!(evm != "BadHeader", header.is_active(), "{label}: {evm}");
        obj([
            ("label", text(label)),
            ("fields", header_fields_json(&fields)),
            ("x", hx(header.as_bytes())),
            ("x_head", hx(header.head())),
            ("x_tail", hx(header.tail())),
            ("checkpoint_id", hx(&checkpoint_id(header.as_bytes()))),
            ("active", Value::Bool(header.is_active())),
            ("rotation", Value::Bool(header.is_rotation())),
            (
                "destination",
                text(if header.is_active() {
                    "accept"
                } else {
                    "BadHeader"
                }),
            ),
        ])
    });

    let bytes = |fields: SccpFinalityHeaderFieldsV1| fields.to_bytes().to_vec();
    let mut bad_magic = bytes(base);
    bad_magic[0] ^= 0x01;
    let invalid_rows = [
        ("magic", "X1", bad_magic),
        ("flag_bit_2", "X1", bytes(with(base, |x| x.flags = 0x05))),
        ("flag_bit_7", "X1", bytes(with(base, |x| x.flags = 0x81))),
        ("flags_0xc0", "X1", bytes(with(base, |x| x.flags = 0xc1))),
        (
            "inactive_with_message_count",
            "X2",
            bytes(with(inactive(7100, T0), |x| {
                x.message_count = 1;
                x.sccp_root = [0x21; 32];
            })),
        ),
        (
            "inactive_with_generation",
            "X2",
            bytes(with(inactive(7100, T0), |x| x.generation = 1)),
        ),
        (
            "inactive_with_rotation",
            "X2",
            bytes(with(inactive(7100, T0), |x| x.flags = FLAG_ROTATION)),
        ),
        (
            "generation_zero",
            "X3",
            bytes(with(base, |x| x.generation = 0)),
        ),
        (
            "committee_root_zero",
            "X3",
            bytes(with(base, |x| x.committee_root = [0; 32])),
        ),
        (
            "count_without_root",
            "X4",
            bytes(with(base, |x| x.sccp_root = [0; 32])),
        ),
        (
            "root_without_count",
            "X4",
            bytes(with(base, |x| x.message_count = 0)),
        ),
        (
            "count_513",
            "X4",
            bytes(with(base, |x| x.message_count = 513)),
        ),
        (
            "history_size_without_root",
            "X5",
            bytes(with(base, |x| x.history_root = [0; 32])),
        ),
        (
            "history_root_without_size",
            "X5",
            bytes(with(base, |x| x.history_size = 0)),
        ),
        (
            "history_size_2_32_plus_1",
            "X5",
            bytes(with(base, |x| x.history_size = MAX_HISTORY_SIZE + 1)),
        ),
        (
            "rotation_validity_zero",
            "X6",
            bytes(with(rotation, |x| x.validity_ms = 0)),
        ),
        (
            "rotation_validity_above_max",
            "X6",
            bytes(with(rotation, |x| x.validity_ms = MAX_VALIDITY_MS + 1)),
        ),
        (
            "rotation_next_root_zero",
            "X6",
            bytes(with(rotation, |x| x.next_committee_root = [0; 32])),
        ),
        // The successor would start at height 2^64, which no u64 holds.
        (
            "rotation_at_max_height",
            "X6",
            bytes(with(rotation, |x| x.height = u64::MAX)),
        ),
        // The successor would be generation 2^64.
        (
            "rotation_at_max_generation",
            "X6",
            bytes(with(rotation, |x| x.generation = u64::MAX)),
        ),
        (
            "non_rotation_with_validity",
            "X6",
            bytes(with(base, |x| x.validity_ms = 1)),
        ),
        (
            "non_rotation_with_next_root",
            "X6",
            bytes(with(base, |x| x.next_committee_root = [0x51; 32])),
        ),
        ("height_zero", "X7", bytes(with(base, |x| x.height = 0))),
        ("inactive_height_zero", "X7", bytes(inactive(0, T0))),
        ("length_220", "Length", bytes(base)[..X_LEN - 1].to_vec()),
        ("length_222", "Length", [bytes(base), vec![0]].concat()),
        // Two violations each, one row per adjacent pair of the order Length, X1, X2 | X3,
        // X4, X5, X6, X7: the reported error is the earlier one.
        ("magic_and_inactive_with_generation", "X1", {
            let mut x = bytes(with(inactive(7100, T0), |x| x.generation = 1));
            x[0] ^= 0x01;
            x
        }),
        (
            "flag_bit_2_and_generation_zero",
            "X1",
            bytes(with(base, |x| {
                x.flags = 0x05;
                x.generation = 0;
            })),
        ),
        (
            "generation_zero_and_count_513",
            "X3",
            bytes(with(base, |x| {
                x.generation = 0;
                x.message_count = 513;
            })),
        ),
        (
            "count_513_and_history_root_without_size",
            "X4",
            bytes(with(base, |x| {
                x.message_count = 513;
                x.history_size = 0;
            })),
        ),
        (
            "history_size_without_root_and_rotation_validity_zero",
            "X5",
            bytes(with(rotation, |x| {
                x.history_root = [0; 32];
                x.validity_ms = 0;
            })),
        ),
        (
            "rotation_validity_zero_and_height_zero",
            "X6",
            bytes(with(rotation, |x| {
                x.validity_ms = 0;
                x.height = 0;
            })),
        ),
        (
            "inactive_with_generation_and_height_zero",
            "X2",
            bytes(with(inactive(0, T0), |x| x.generation = 1)),
        ),
    ]
    .map(|(label, error, data)| {
        let refused = SccpFinalityHeaderV1::parse(&data)
            .expect_err("an invalid header")
            .name();
        assert_eq!(refused, error, "{label}");
        let pin = Pin::of(n4);
        let evm = outcome(&pin, DestinationFlavor::Evm, &data);
        let ton = outcome(&pin, DestinationFlavor::Ton, &data);
        assert_eq!((evm, ton), ("BadHeader", "BadHeader"), "{label}");
        obj([
            ("label", text(label)),
            ("x", hx(&data)),
            ("error", text(refused)),
            ("destination", text(evm)),
        ])
    });

    // The nearest neighbours of `rotation_at_max_height` and `rotation_at_max_generation`
    // parse. Their values exceed 2^53, so they are not rows.
    for neighbour in [
        with(rotation, |x| x.height = u64::MAX - 1),
        with(base, |x| x.height = u64::MAX),
        with(rotation, |x| x.generation = u64::MAX - 1),
        with(base, |x| x.generation = u64::MAX),
    ] {
        valid(&neighbour);
    }
    obj([("valid", list(valid_rows)), ("invalid", list(invalid_rows))])
}

fn result_of_preimage_vectors() -> Value {
    let x = SccpFinalityHeaderFieldsV1 {
        network_id: NETWORK_ID,
        height: 7100,
        timestamp_ms: T0,
        flags: FLAG_ACTIVE,
        generation: GENERATION,
        committee_root: [0x41; 32],
        ..SccpFinalityHeaderFieldsV1::default()
    }
    .to_bytes();
    let inactive_x = inactive(7100, T0).to_bytes();
    let certified = |preimage: &[u8]| result_of_preimage(preimage).expect("a result preimage").0;
    let mut rows = Vec::new();
    for (label, header, body) in [
        ("one_byte_body", x, &b"\x00"[..]),
        ("short_body", x, &b"sccp-reference body"[..]),
        ("inactive_x", inactive_x, &b"\x01\x02\x03"[..]),
    ] {
        let preimage = [&header[..], body].concat();
        rows.push(obj([
            ("label", text(label)),
            ("preimage", hx(&preimage)),
            ("d_body", hx(&body_digest(body))),
            ("r", hx(&certified(&preimage))),
        ]));
    }

    assert_eq!(X_LEN + MAX_RESULT_BODY_BYTES, MAX_RESULT_PREIMAGE_BYTES);
    let max_body = vec![0_u8; MAX_RESULT_BODY_BYTES];
    let max_preimage = [&x[..], &max_body].concat();
    let too_long = [&max_preimage[..], &[0]].concat();
    assert!(result_of_preimage(&too_long).is_none());
    rows.push(obj([
        ("label", text("maximal_body")),
        (
            "construction",
            text("the X of row one_byte_body followed by 65315 zero bytes (65536 bytes in total)"),
        ),
        ("preimage_len", num(max_preimage.len() as u64)),
        ("d_body", hx(&body_digest(&max_body))),
        ("r", hx(&certified(&max_preimage))),
    ]));
    rows.push(obj([
        ("label", text("body_too_long")),
        (
            "construction",
            text("the X of row one_byte_body followed by 65316 zero bytes (65537 bytes)"),
        ),
        ("preimage_len", num(too_long.len() as u64)),
        ("r", Value::Null),
    ]));
    for (label, preimage) in [
        ("x_only", x.to_vec()),
        ("truncated_x", x[..200].to_vec()),
        ("unparseable_x", vec![0; X_LEN + 1]),
    ] {
        assert!(result_of_preimage(&preimage).is_none(), "{label}");
        rows.push(obj([
            ("label", text(label)),
            ("preimage", hx(&preimage)),
            ("r", Value::Null),
        ]));
    }
    Value::Array(rows)
}

fn signer_encoding_vectors() -> Value {
    let rows: [(&str, usize, Vec<usize>); 7] = [
        ("n4_lowest", 4, vec![0, 1, 2]),
        ("n4_highest", 4, vec![1, 2, 3]),
        ("n7_lowest", 7, vec![0, 1, 2, 3, 4]),
        ("n7_highest", 7, vec![2, 3, 4, 5, 6]),
        ("n31_example", 31, vec![0, 9, 30]),
        ("n31_lowest", 31, (0..21).collect()),
        ("n31_highest", 31, (10..31).collect()),
    ];
    list(rows.map(|(label, n, indices)| {
        let signers = signers_from_indices(&indices);
        let bitmap = bitmap_from_signers(signers, n).expect("the indices are below n");
        assert_eq!(signers_from_bitmap(&bitmap, n), Some(signers), "{label}");
        // A bitmap of more than one byte can be misread: its bytes as a big-endian `u32`.
        let misreading = if n > 8 {
            let mut raw = [0_u8; 4];
            raw[..bitmap.len()].copy_from_slice(&bitmap);
            hex_integer(&raw)
        } else {
            Value::Null
        };
        obj([
            ("label", text(label)),
            ("n", num(n as u64)),
            ("indices", indices_json(&indices)),
            ("bitmap", hx(&bitmap)),
            ("signers", num(signers.into())),
            ("signers_be32", hx(&signers.to_be_bytes())),
            ("raw_bitmap_misreading", misreading),
        ])
    }))
}

fn test_keys_json() -> Value {
    list((0..35).map(|index| {
        let key = test_key(index);
        obj([
            ("index", num(index.into())),
            ("ikm", hx(&key.ikm)),
            ("sk", hx(&key.secret)),
            ("pk", hx(&key.public)),
            ("pk_eip2537", hx(&g1_eip2537(&key.public))),
            (
                "pk_y",
                hx(&key_y(&key.public).expect("a point of the curve")),
            ),
        ])
    }))
}

// ---------------------------------------------------------------------------------------------
// Certificates (§11.3)
// ---------------------------------------------------------------------------------------------

/// The committees and the simulator of the certificate vectors.
struct World {
    n4: Committee,
    n7: Committee,
    n31: Committee,
    other4: Committee,
    sim: TairaSim,
    /// The destination clock of every verification.
    now: u64,
}

impl World {
    fn new() -> Self {
        Self {
            n4: Committee::new("n4", 0..4),
            n7: Committee::new("n7", 0..7),
            n31: Committee::new("n31", 0..31),
            other4: Committee::new("n4_other", 31..35),
            sim: TairaSim::new(
                NETWORK_ID,
                INSTANCE,
                SccpNetworkV1::EthereumMainnet,
                destination_word(),
            ),
            now: T0 + HOUR,
        }
    }

    /// A certificate of `header` by `committee`.
    fn certify(
        &self,
        header: &SccpFinalityHeaderFieldsV1,
        committee: &Committee,
        options: &CertifyOptions,
    ) -> Certificate {
        self.sim.certify(&header.to_bytes(), committee, options)
    }

    /// A genuine certificate by the lowest `q` members.
    fn certify_plain(
        &self,
        header: &SccpFinalityHeaderFieldsV1,
        committee: &Committee,
    ) -> Certificate {
        self.certify(header, committee, &CertifyOptions::default())
    }

    fn verification_context(&self) -> Value {
        obj([
            ("taira_network_id", hx(&NETWORK_ID)),
            ("consensus_instance", hx(&INSTANCE)),
            ("network", text(self.sim.target.profile_key())),
            ("destination_word", hx(&destination_word())),
            (
                "ton",
                obj([
                    ("network", text(SccpNetworkV1::TonMainnet.profile_key())),
                    ("destination_word", hx(&TON_DESTINATION_WORD)),
                ]),
            ),
        ])
    }
}

/// The header of a block at `height` certified by `committee`: one block per second from
/// `START_HEIGHT` at `T0`, two messages, a history of 40 blocks.
fn header(committee: &Committee, height: u64) -> SccpFinalityHeaderFieldsV1 {
    SccpFinalityHeaderFieldsV1 {
        network_id: NETWORK_ID,
        height,
        timestamp_ms: T0 - START_HEIGHT * 1000 + height * 1000,
        flags: FLAG_ACTIVE,
        message_count: 2,
        sccp_root: sha256(&[b"sccp-reference/block-root", &height.to_be_bytes()]),
        history_size: 40,
        history_root: sha256(&[b"sccp-reference/history-root", &height.to_be_bytes()]),
        generation: GENERATION,
        committee_root: committee.root(),
        validity_ms: 0,
        next_committee_root: [0; 32],
    }
}

/// The pin of a verification-only destination.
#[derive(Clone, Debug)]
struct Pin {
    generation: u64,
    committee_root: [u8; 32],
    start_height: u64,
    until_ms: u64,
    keys: Vec<[u8; KEY_LEN]>,
    /// The keys are not those of a named committee, so the row prints them.
    custom_keys: bool,
}

impl Pin {
    /// Generation 7 of `committee` from height 7000 until `T0 + VALIDITY`.
    fn of(committee: &Committee) -> Self {
        Self {
            generation: GENERATION,
            committee_root: committee.root(),
            start_height: START_HEIGHT,
            until_ms: T0 + VALIDITY,
            keys: committee.keys(),
            custom_keys: false,
        }
    }

    /// The same pin over other key bytes: the root commits to them exactly as they are.
    fn over(&self, keys: Vec<[u8; KEY_LEN]>) -> Self {
        Self {
            committee_root: committee_root(&keys).expect("a root of the key bytes"),
            keys,
            custom_keys: true,
            ..self.clone()
        }
    }

    /// The verification-only destination of `flavor`, on the profile of that flavour.
    fn deployment(&self, flavor: DestinationFlavor) -> DeploymentV1 {
        let (network, destination_word) = match flavor {
            DestinationFlavor::Evm => (SccpNetworkV1::EthereumMainnet, destination_word()),
            DestinationFlavor::Ton => (SccpNetworkV1::TonMainnet, TON_DESTINATION_WORD),
        };
        DeploymentV1 {
            flavor,
            taira_network_id: NETWORK_ID,
            consensus_instance: INSTANCE,
            network,
            destination_word,
            route_revision: 1,
            max_wrapped_supply: SUPPLY_CAP,
            pin_generation: self.generation,
            pin_root: self.committee_root,
            pin_start_height: self.start_height,
            pin_until_ms: self.until_ms,
            pin_keys: Some(self.keys.clone()),
        }
    }

    /// The §5.2.2 outcome of `VerifyCertificate` steps 1–12 on a fresh destination deployed
    /// with this pin.
    fn outcome(
        &self,
        flavor: DestinationFlavor,
        certificate: &Certificate,
        now_ms: u64,
    ) -> &'static str {
        let destination = Destination::new(self.deployment(flavor))
            .unwrap_or_else(|error| panic!("{} deployment: {error}", flavor.name()));
        outcome_name(&destination.verify_certificate(&certificate.wire(), now_ms))
    }
}

/// `m` as a verifier derives it from the wire: `SHA-256(P)` with the pinned instance, kind
/// `0x03`, the `QC_FIXED` fields and `X.height` and `R` of the header bytes as they are.
fn wire_commit_message(header: &[u8; X_LEN], qc: &QcFixedV1) -> [u8; 32] {
    let result = sha256(&[RESULT_TAG, header, &qc.result_body]);
    let mut height = [0_u8; 8];
    height.copy_from_slice(&header[48..56]);
    commit_message(&commit_preimage(
        &INSTANCE,
        qc,
        u64::from_be_bytes(height),
        &result,
    ))
}

/// One certificate row and what it is verified against.
struct Row<'a> {
    label: &'a str,
    description: &'a str,
    /// The name of the committee the row belongs to.
    committee: &'a str,
    certificate: &'a Certificate,
    pin: &'a Pin,
    now_ms: u64,
    /// Whether the EVM form can express the vector.
    evm: bool,
    /// Whether the TON form can express the vector.
    ton: bool,
}

impl Row<'_> {
    /// The fields every certificate row has. `expected` is `null` for a flavour that cannot
    /// express the vector.
    fn json(&self) -> Value {
        check_destination_clock(self.now_ms, None, &format!("certificate {}", self.label));
        let certificate = self.certificate;
        let meta = &certificate.meta;
        let outcome = |enabled: bool, flavor| {
            if enabled {
                text(self.pin.outcome(flavor, certificate, self.now_ms))
            } else {
                Value::Null
            }
        };
        let header = <&[u8; X_LEN]>::try_from(&certificate.header[..]).ok();
        let mut pin = obj([
            ("generation", num(self.pin.generation)),
            ("committee_root", hx(&self.pin.committee_root)),
            ("start_height", num(self.pin.start_height)),
            ("until_ms", num(self.pin.until_ms)),
        ]);
        if self.pin.custom_keys {
            insert(&mut pin, "keys", hexes(&self.pin.keys));
        }
        let mut entry = obj([
            ("label", text(self.label)),
            ("description", text(self.description)),
            ("committee", text(self.committee)),
            ("pin", pin),
            ("now_ms", num(self.now_ms)),
            ("header_fields", parsed_header_json(&certificate.header)),
            ("signer_indices", indices_json(&meta.signer_indices)),
            ("bitmap", hx(&meta.bitmap)),
            ("qc_fixed_fields", qc_fixed_json(&meta.qc)),
            ("commit_kind", num(meta.kind.into())),
            ("r", hx(&meta.result)),
            ("commit_preimage", hx(&meta.preimage)),
            ("m", hx(&meta.message)),
            (
                "checkpoint_id",
                header.map_or(Value::Null, |header| hx(&checkpoint_id(header))),
            ),
            ("evm", certificate.evm_json()),
            ("ton", certificate.ton_json()),
            (
                "expected",
                obj([
                    ("evm", outcome(self.evm, DestinationFlavor::Evm)),
                    ("ton", outcome(self.ton, DestinationFlavor::Ton)),
                ]),
            ),
        ]);
        // The forgery-evidence identity is over the `m` a verifier derives from the wire
        // (§4.9), so a row carries it only when its `m`, the message that was signed, is that
        // value.
        if let (Some(header), Ok(qc)) = (header, QcFixedV1::parse(&certificate.qc))
            && wire_commit_message(header, &qc) == meta.message
        {
            let mut generation = [0_u8; 8];
            generation.copy_from_slice(&header[141..149]);
            insert(
                &mut entry,
                "forgery_evidence_id",
                hx(&forgery_evidence_id(
                    u64::from_be_bytes(generation),
                    &meta.message,
                    qc.signers,
                )),
            );
        }
        entry
    }

    /// A row of `finality_v1.json`: it names the tag the signature was made under, and a
    /// positive row carries the intermediate points of the pairing check.
    fn reference_json(&self, detail: bool) -> Value {
        let meta = &self.certificate.meta;
        let mut entry = self.json();
        insert(&mut entry, "dst", ascii(&meta.dst));
        if detail {
            insert(&mut entry, "hash_to_g2_m", g2_json(&meta.hash_point));
            insert(&mut entry, "aggregate_public_key", g1_json(&meta.apk));
            insert(&mut entry, "aggregate_signature", g2_json(&meta.sigma));
            insert(
                &mut entry,
                "pairing_input",
                hx(&pairing_input(&meta.apk, &meta.hash_point, &meta.sigma)),
            );
        }
        entry
    }
}

fn expected_of<'a>(entry: &'a Value, flavor: &str) -> Option<&'a str> {
    entry.get("expected")?.get(flavor)?.as_str()
}

fn positive_certificates(world: &World) -> Vec<Value> {
    let mut rows = Vec::new();
    let scattered_31: Vec<usize> = (0..31).filter(|index| index % 3 != 1).collect();
    assert!([0, 9, 30].iter().all(|index| scattered_31.contains(index)));
    for (committee, scattered) in [
        (&world.n4, vec![0, 1, 3]),
        (&world.n7, vec![0, 2, 3, 5, 6]),
        (&world.n31, scattered_31),
    ] {
        let (n, q) = (committee.n(), committee.quorum());
        let pin = Pin::of(committee);
        for (set_label, indices) in [
            ("lowest", (0..q).collect()),
            ("highest", (n - q..n).collect()),
            ("scattered", scattered),
        ] {
            let x = header(committee, 7100 + rows.len() as u64);
            let options = CertifyOptions {
                signer_indices: Some(indices),
                ..CertifyOptions::default()
            };
            rows.push(
                Row {
                    label: &format!("{}_{set_label}_q", committee.name),
                    description: &format!(
                        "non-rotation certificate, {set_label} {q} signers of n = {n}"
                    ),
                    committee: &committee.name,
                    certificate: &world.certify(&x, committee, &options),
                    pin: &pin,
                    now_ms: world.now,
                    evm: true,
                    ton: true,
                }
                .reference_json(true),
            );
        }
    }

    let n4 = &world.n4;
    let pin4 = Pin::of(n4);
    for (label, x) in [
        (
            "key_change_rotation",
            with(header(n4, 7200), |x| {
                x.flags = FLAG_ACTIVE | FLAG_ROTATION;
                x.validity_ms = VALIDITY;
                x.next_committee_root = world.other4.root();
            }),
        ),
        (
            "heartbeat_rotation",
            with(header(n4, 7201), |x| {
                x.flags = FLAG_ACTIVE | FLAG_ROTATION;
                x.validity_ms = VALIDITY;
                x.next_committee_root = n4.root();
            }),
        ),
        ("non_rotation", header(n4, 7203)),
        (
            "empty_block_non_rotation",
            with(header(n4, 7205), |x| {
                x.message_count = 0;
                x.sccp_root = [0; 32];
            }),
        ),
    ] {
        rows.push(
            Row {
                label,
                description: &format!("{} (n = 4)", label.replace('_', " ")),
                committee: "n4",
                certificate: &world.certify_plain(&x, n4),
                pin: &pin4,
                now_ms: world.now,
                evm: true,
                ton: true,
            }
            .reference_json(true),
        );
    }
    for entry in &rows {
        for flavor in ["evm", "ton"] {
            assert_eq!(
                expected_of(entry, flavor),
                Some("ok"),
                "{:?}/{flavor}",
                entry.get("label")
            );
        }
    }
    rows
}

/// The negative rows as they accumulate.
struct Negatives<'a> {
    world: &'a World,
    pin4: Pin,
    rows: Vec<Value>,
}

/// The outcome a negative row must have on both flavours.
fn both(outcome: &'static str) -> [Option<&'static str>; 2] {
    [Some(outcome), Some(outcome)]
}

/// The outcome of a negative that only the EVM form can express.
fn evm_only(outcome: &'static str) -> [Option<&'static str>; 2] {
    [Some(outcome), None]
}

/// The outcome of a negative that only the TON form can express.
fn ton_only(outcome: &'static str) -> [Option<&'static str>; 2] {
    [None, Some(outcome)]
}

impl Negatives<'_> {
    /// Add a row for the committee `n4` under its pin.
    fn add(
        &mut self,
        label: &str,
        description: &str,
        certificate: &Certificate,
        expect: [Option<&'static str>; 2],
    ) {
        let pin = self.pin4.clone();
        self.add_under(label, description, certificate, &pin, "n4", expect);
    }

    /// Add a row: `expect` is the outcome on `[evm, ton]`, absent for a flavour that cannot
    /// express the vector. The model must give exactly these outcomes.
    fn add_under(
        &mut self,
        label: &str,
        description: &str,
        certificate: &Certificate,
        pin: &Pin,
        committee: &str,
        expect: [Option<&'static str>; 2],
    ) {
        let entry = Row {
            label,
            description,
            committee,
            certificate,
            pin,
            now_ms: self.world.now,
            evm: expect[0].is_some(),
            ton: expect[1].is_some(),
        }
        .reference_json(false);
        for (flavor, outcome) in ["evm", "ton"].into_iter().zip(expect) {
            assert_eq!(
                expected_of(&entry, flavor),
                outcome,
                "{label}/{flavor}: the model gave another outcome"
            );
        }
        self.rows.push(entry);
    }
}

/// `certificate` with `signerYs` of exactly `48q` bytes, so that EVM passes the step 1 length
/// check.
///
/// The `y` values of the encoded in-range signers come first (ascending index); a short list
/// is padded with the `y` of the lowest keys outside the encoded set, a long one truncated.
fn signer_ys_exactly_q(certificate: &Certificate, committee: &Committee) -> Certificate {
    let wanted = FP_LEN * committee.quorum();
    let signers = QcFixedV1::parse(&certificate.qc)
        .expect("a QC_FIXED of 116 bytes")
        .signers;
    let mut ys = certificate.signer_ys.clone();
    for (index, key) in committee.keys().iter().enumerate() {
        if ys.len() >= wanted {
            break;
        }
        if signers >> index & 1 == 0 {
            ys.extend_from_slice(&key_y(key).expect("a point of the curve"));
        }
    }
    ys.truncate(wanted);
    Certificate {
        signer_ys: ys,
        ..certificate.clone()
    }
}

/// `certificate` with the `y` of its signer at position `position` of `signerYs` replaced.
fn with_y(certificate: &Certificate, position: usize, y: &[u8; FP_LEN]) -> Certificate {
    let mut out = certificate.clone();
    out.signer_ys[FP_LEN * position..FP_LEN * (position + 1)].copy_from_slice(y);
    out
}

#[allow(
    clippy::too_many_lines,
    reason = "one list of the §11.3 negatives, in the order of the file"
)]
/// A certificate of the committee `n4` with its members listed under the key bytes of
/// `listed`, pinned under the root of those exact bytes in canonical order. The first three
/// members sign with their genuine secrets, at the seats the order gives them; the fourth
/// member does not sign.
fn odd_committee(world: &World, listed: [[u8; KEY_LEN]; 4], height: u64) -> (Certificate, Pin) {
    let n4 = &world.n4;
    let mut custom = listed.to_vec();
    custom.sort_unstable();
    custom.dedup();
    assert_eq!(custom.len(), 4, "the listed keys are distinct");
    let seat = |key: &[u8; KEY_LEN]| {
        custom
            .iter()
            .position(|listed| listed == key)
            .expect("a listed key")
    };
    let mut seats: Vec<usize> = listed[..3].iter().map(seat).collect();
    seats.sort_unstable();
    let pin = Pin::of(n4).over(custom.clone());
    let mut fields = header(n4, height);
    fields.committee_root = pin.committee_root;
    // The members sign what the header says; the seats of `signers` are not part of `P`.
    let signed = world.certify(
        &fields,
        n4,
        &CertifyOptions {
            signer_indices: Some(vec![0, 1, 2]),
            ..CertifyOptions::default()
        },
    );
    let signers = signers_from_indices(&seats);
    let qc = QcFixedV1 {
        signers,
        ..signed.meta.qc
    };
    let mut certificate = Certificate {
        qc: qc.encode().to_vec(),
        committee: custom.concat(),
        signer_ys: signer_ys(&custom, signers).expect("the listed keys are points"),
        ..signed
    };
    certificate.meta.signer_indices = seats;
    certificate.meta.signers = signers;
    certificate.meta.bitmap = bitmap_from_signers(signers, 4).expect("four seats");
    certificate.meta.qc = qc;
    (certificate, pin)
}

/// The rows of `negative_certificates`, and the rows of `flavor_specific_certificates`:
/// certificates that one flavour accepts and the other does not pin.
fn negative_certificates(world: &World) -> (Vec<Value>, Vec<Value>) {
    let (n4, n7, n31, other4) = (&world.n4, &world.n7, &world.n31, &world.other4);
    let pin4 = Pin::of(n4);
    let mut out = Negatives {
        world,
        pin4: pin4.clone(),
        rows: Vec::new(),
    };
    let good = world.certify_plain(&header(n4, 7300), n4);

    out.add(
        "prepare_kind",
        "PrepareQC (kind 0x02) instead of CommitQC",
        &world.certify(
            &header(n4, 7301),
            n4,
            &CertifyOptions {
                kind: Some(KIND_PREPARE),
                ..CertifyOptions::default()
            },
        ),
        both("BadSignature"),
    );
    // The signer-set rows carry exactly 48q bytes of signerYs, so EVM passes the step 1
    // length check and reaches the step 5 bitmap check they exist for (`signer_ys_short`
    // pins step 1).
    out.add(
        "popcount_q_minus_1",
        "q − 1 signers (signerYs padded to 48q with a non-signer's y)",
        &signer_ys_exactly_q(
            &world.certify(
                &header(n4, 7302),
                n4,
                &CertifyOptions {
                    signer_indices: Some(vec![0, 1]),
                    ..CertifyOptions::default()
                },
            ),
            n4,
        ),
        both("BadCertificate"),
    );
    out.add(
        "popcount_q_plus_1_extra_signer",
        "q + 1 signers, an extra signer (signerYs truncated to 48q)",
        &signer_ys_exactly_q(
            &world.certify(
                &header(n4, 7303),
                n4,
                &CertifyOptions {
                    signer_indices: Some(vec![0, 1, 2, 3]),
                    ..CertifyOptions::default()
                },
            ),
            n4,
        ),
        both("BadCertificate"),
    );
    out.add(
        "spare_bits",
        "a signer bit at index n (spare bit) with popcount q (signerYs of 48q bytes)",
        &signer_ys_exactly_q(
            &world.certify(
                &header(n4, 7304),
                n4,
                &CertifyOptions {
                    signer_indices: Some(vec![0, 1, 2]),
                    signers_field: Some(0b10011),
                    ..CertifyOptions::default()
                },
            ),
            n4,
        ),
        both("BadCertificate"),
    );
    out.add(
        "retired_qc_extension",
        "retired attestation field in QC_FIXED",
        &Certificate {
            qc: [&good.qc[..80], &[0x01], &good.qc[80..]].concat(),
            ..good.clone()
        },
        both("BadCertificate"),
    );
    out.add(
        "wrong_instance",
        "signed over a Commit preimage with another instance I",
        &world.certify(
            &header(n4, 7306),
            n4,
            &CertifyOptions {
                signed_instance: Some([0x78; 32]),
                ..CertifyOptions::default()
            },
        ),
        both("BadSignature"),
    );
    out.add(
        "wrong_network",
        "X.network_id differs from the destination's Taira NetworkId",
        &world.certify_plain(&with(header(n4, 7307), |x| x.network_id = [0x12; 32]), n4),
        both("BadHeader"),
    );
    out.add(
        "wrong_dst",
        "signed with the NUL ciphersuite DST instead of DST_SIG",
        &world.certify(
            &header(n4, 7308),
            n4,
            &CertifyOptions {
                dst: Some(DST_NUL.to_vec()),
                ..CertifyOptions::default()
            },
        ),
        both("BadSignature"),
    );
    out.add(
        "signed_height_mismatch",
        "the Commit preimage names X.height + 1",
        &world.certify(
            &header(n4, 7309),
            n4,
            &CertifyOptions {
                signed_height: Some(7310),
                ..CertifyOptions::default()
            },
        ),
        both("BadSignature"),
    );
    let signed = header(n4, 7310);
    out.add(
        "tampered_x",
        "a valid-layout X changed after signing (different sccp_root)",
        &Certificate {
            header: with(signed, |x| x.sccp_root = [0xee; 32])
                .to_bytes()
                .to_vec(),
            ..world.certify_plain(&signed, n4)
        },
        both("BadSignature"),
    );
    let keys = n4.keys();
    out.add(
        "signature_of_other_subset",
        "the bitmap names {0,1,2} but {1,2,3} signed",
        &world.certify(
            &header(n4, 7311),
            n4,
            &CertifyOptions {
                signer_indices: Some(vec![0, 1, 2]),
                signing_keys: Some(vec![keys[1], keys[2], keys[3]]),
                ..CertifyOptions::default()
            },
        ),
        both("BadSignature"),
    );

    // Dirty X, each signed by the committee, so only the header check rejects it.
    let mut bad_magic = header(n4, 7330).to_bytes();
    bad_magic[3] ^= 0x20;
    let dirty: [(&str, [u8; X_LEN]); 12] = [
        ("x1_magic", bad_magic),
        (
            "x1_flags_0x04",
            with(header(n4, 7320), |x| x.flags = 0x05).to_bytes(),
        ),
        (
            "x2_inactive_with_fields",
            with(inactive(7321, T0), |x| x.generation = GENERATION).to_bytes(),
        ),
        ("inactive_x", inactive(7322, T0).to_bytes()),
        (
            "x3_generation_zero",
            with(header(n4, 7323), |x| x.generation = 0).to_bytes(),
        ),
        (
            "x4_count_without_root",
            with(header(n4, 7324), |x| x.sccp_root = [0; 32]).to_bytes(),
        ),
        (
            "x4_count_513",
            with(header(n4, 7325), |x| x.message_count = 513).to_bytes(),
        ),
        (
            "x5_history_size_without_root",
            with(header(n4, 7326), |x| x.history_root = [0; 32]).to_bytes(),
        ),
        (
            "x6_rotation_validity_zero",
            with(header(n4, 7327), |x| {
                x.flags = FLAG_ACTIVE | FLAG_ROTATION;
                x.validity_ms = 0;
                x.next_committee_root = other4.root();
            })
            .to_bytes(),
        ),
        (
            "x6_non_rotation_with_validity",
            with(header(n4, 7328), |x| x.validity_ms = VALIDITY).to_bytes(),
        ),
        (
            "x6_non_rotation_with_next_root",
            with(header(n4, 7329), |x| x.next_committee_root = other4.root()).to_bytes(),
        ),
        ("x7_height_zero", header(n4, 0).to_bytes()),
    ];
    for (label, raw) in dirty {
        out.add(
            &format!("dirty_{label}"),
            &format!("dirty X ({}), validly signed", label.replace('_', " ")),
            &world.sim.certify(&raw, n4, &CertifyOptions::default()),
            both("BadHeader"),
        );
    }

    // Classification.
    out.add(
        "past_generation",
        "a genuine-looking certificate of generation g − 1 (same keys)",
        &world.certify_plain(
            &with(header(n4, 7340), |x| x.generation = GENERATION - 1),
            n4,
        ),
        both("CommitteeNotAccepted"),
    );
    out.add_under(
        "foreign_committee_root",
        "X.committee_root names another committee",
        &world.certify_plain(&header(other4, 7341), other4),
        &pin4,
        "n4_other",
        both("CommitteeNotAccepted"),
    );

    // EVM committee and signerYs inputs.
    out.add(
        "committee_root_mismatch",
        "calldata committee whose keccak root differs from cur.root",
        &Certificate {
            committee: other4.keys().concat(),
            ..good.clone()
        },
        evm_only("BadCommittee"),
    );
    let ys: Vec<[u8; FP_LEN]> = keys
        .iter()
        .map(|key| key_y(key).expect("a point of the curve"))
        .collect();
    out.add(
        "signer_y_wrong_sign",
        "signerYs[0] = p − y, inconsistent with the key's sign bit",
        &with_y(&good, 0, &fp_sub(&BLS12_381_P, &ys[0])),
        evm_only("BadCommittee"),
    );
    out.add(
        "signer_y_ge_p",
        "signerYs[1] = y + p",
        &with_y(&good, 1, &fp_add(&ys[1], &BLS12_381_P)),
        evm_only("BadCommittee"),
    );
    // The nearest value above `y` with the sign class of `y` that is not on the curve.
    let off_curve = (1..64)
        .map(|delta| fp_add_small(&ys[2], delta))
        .find(|candidate| {
            (*candidate > BLS12_381_HALF_P) == (ys[2] > BLS12_381_HALF_P)
                && !signer_point_is_on_curve(&keys[2], candidate)
        })
        .expect("an off-curve neighbour of y");
    out.add(
        "signer_y_off_curve",
        "signerYs[2] has the right sign class but is not on the curve",
        &with_y(&good, 2, &off_curve),
        evm_only("BadCommittee"),
    );
    for (label, height, flag) in [
        ("key_flag_infinity_0xc0", 7350, keys[0][0] | 0x40),
        ("key_flag_uncompressed", 7351, keys[0][0] & 0x7f),
    ] {
        let mut bad_keys = keys.clone();
        bad_keys[0][0] = flag;
        let pin = pin4.over(bad_keys.clone());
        let certificate = Certificate {
            committee: bad_keys.concat(),
            ..world.certify_plain(
                &with(header(n4, height), |x| {
                    x.committee_root = pin.committee_root
                }),
                n4,
            )
        };
        out.add_under(
            label,
            "committee key 0 with a bad flag byte, pinned under the root of those exact bytes",
            &certificate,
            &pin,
            "n4",
            evm_only("BadCommittee"),
        );
    }
    // Signer coordinates that are no precompile input for a finite point (step 6): x ≥ p, and
    // (0, 0), which EIP-2537 reads as the point at infinity. Each key keeps valid flags, so
    // only its own check refuses it.
    let mut x_ge_p = [0xff; KEY_LEN];
    x_ge_p[0] = (keys[0][0] & 0xe0) | 0x1f;
    let mut x_of_key = x_ge_p;
    x_of_key[0] &= 0x1f;
    assert!(x_of_key >= BLS12_381_P);
    let mut zero_x = [0; KEY_LEN];
    zero_x[0] = 0x80;
    for (label, description, bad_key, y, height) in [
        (
            "signer_x_ge_p",
            "committee key 0 whose x (every coordinate bit set) is not below p, with its genuine y",
            x_ge_p,
            ys[0],
            7352,
        ),
        (
            "signer_zero_coordinates",
            "committee key 0 with x = 0 and signerYs[0] = 0: the coordinates (0, 0)",
            zero_x,
            [0; FP_LEN],
            7353,
        ),
    ] {
        let mut bad_keys = keys.clone();
        bad_keys[0] = bad_key;
        let pin = pin4.over(bad_keys.clone());
        let certificate = Certificate {
            committee: bad_keys.concat(),
            ..world.certify_plain(
                &with(header(n4, height), |x| {
                    x.committee_root = pin.committee_root
                }),
                n4,
            )
        };
        out.add_under(
            label,
            &format!("{description}, pinned under the root of those exact bytes"),
            &with_y(&certificate, 0, &y),
            &pin,
            "n4",
            evm_only("BadCommittee"),
        );
    }

    // Signature encodings.
    let outside = curve_point_outside_g2();
    out.add(
        "sigma_not_in_subgroup",
        "σ on the curve but outside G2",
        &Certificate {
            signature_evm: g2_evm192(&outside).to_vec(),
            signature_ton: outside.to_vec(),
            ..good.clone()
        },
        both("BadSignature"),
    );
    out.add(
        "sigma_zero",
        "σ = 0^192 (EVM) / the compressed identity (TON)",
        &Certificate {
            signature_evm: IDENTITY_SIGNATURE_EVM.to_vec(),
            signature_ton: IDENTITY_SIGNATURE.to_vec(),
            ..good.clone()
        },
        both("BadSignature"),
    );
    let evm = g2_evm192(&good.meta.sigma);
    for (position, limb_name) in ["x_c0", "x_c1", "y_c0", "y_c1"].into_iter().enumerate() {
        let range = FP_LEN * position..FP_LEN * (position + 1);
        let mut limbs = evm;
        limbs[range.clone()].copy_from_slice(&fp_add(&fp_array(&evm[range]), &BLS12_381_P));
        out.add(
            &format!("sigma_limb_{limb_name}_ge_p"),
            &format!("σ.{} + p in the EVM form", limb_name.replace('_', ".")),
            &Certificate {
                signature_evm: limbs.to_vec(),
                ..good.clone()
            },
            evm_only("BadSignature"),
        );
    }
    out.add(
        "sigma_c0_c1_swapped",
        "EVM σ with c1 ‖ c0 limb order (ZCash order mistaken for EIP-2537)",
        &Certificate {
            signature_evm: [&evm[48..96], &evm[..48], &evm[144..], &evm[96..144]].concat(),
            ..good.clone()
        },
        evm_only("BadSignature"),
    );
    let mut off_curve_sigma = evm;
    off_curve_sigma[191] ^= 0x01;
    out.add(
        "sigma_off_curve",
        "EVM σ with y.c1 changed by one bit",
        &Certificate {
            signature_evm: off_curve_sigma.to_vec(),
            ..good.clone()
        },
        evm_only("BadSignature"),
    );
    let mut uncompressed_flag = good.meta.sigma;
    uncompressed_flag[0] &= 0x7f;
    out.add(
        "sigma_ton_uncompressed_flag",
        "TON σ without the compression flag",
        &Certificate {
            signature_ton: uncompressed_flag.to_vec(),
            ..good.clone()
        },
        ton_only("BadSignature"),
    );

    // Bitmap order (n = 31 scattered set, and n = 7).
    let indices_31: Vec<usize> = (0..31).filter(|index| index % 3 != 1).collect();
    let bitmap_31 = bitmap_from_signers(signers_from_indices(&indices_31), 31)
        .expect("the indices are below 31");
    let raw_misread = u32::from_be_bytes(bitmap_31.try_into().expect("a bitmap of four bytes"));
    out.add_under(
        "raw_bitmap_signers",
        "signers = the Sumeragi bitmap bytes read big-endian (n = 31)",
        &world.certify(
            &header(n31, 7360),
            n31,
            &CertifyOptions {
                signer_indices: Some(indices_31),
                signers_field: Some(raw_misread),
                ..CertifyOptions::default()
            },
        ),
        &Pin::of(n31),
        "n31",
        both("BadSignature"),
    );
    let indices_7 = vec![0, 1, 2, 3, 4];
    let msb_first = indices_7.iter().fold(0_u32, |bits, index| {
        bits | 1 << (8 * (index / 8) + 7 - index % 8)
    });
    out.add_under(
        "msb_first_bitmap",
        "signers with MSB-first bit order inside the byte (n = 7; signerYs of 48q bytes)",
        &signer_ys_exactly_q(
            &world.certify(
                &header(n7, 7361),
                n7,
                &CertifyOptions {
                    signer_indices: Some(indices_7),
                    signers_field: Some(msb_first),
                    ..CertifyOptions::default()
                },
            ),
            n7,
        ),
        &Pin::of(n7),
        "n7",
        both("BadCertificate"),
    );

    // Exact lengths.
    let shorter = |bytes: &[u8], by: usize| bytes[..bytes.len() - by].to_vec();
    out.add(
        "qc_length_115",
        "QC_FIXED of 115 bytes",
        &Certificate {
            qc: shorter(&good.qc, 1),
            ..good.clone()
        },
        both("BadCertificate"),
    );
    out.add(
        "header_length_220",
        "X of 220 bytes",
        &Certificate {
            header: shorter(&good.header, 1),
            ..good.clone()
        },
        both("BadHeader"),
    );
    out.add(
        "evm_signature_length_191",
        "EVM signature of 191 bytes",
        &Certificate {
            signature_evm: shorter(&good.signature_evm, 1),
            ..good.clone()
        },
        evm_only("BadCertificate"),
    );
    out.add(
        "ton_signature_length_95",
        "TON signature of 95 bytes",
        &Certificate {
            signature_ton: shorter(&good.signature_ton, 1),
            ..good.clone()
        },
        ton_only("BadCertificate"),
    );
    out.add(
        "committee_n_5",
        "calldata committee of 5 keys",
        &Certificate {
            committee: [&good.committee[..], &keys[0]].concat(),
            ..good.clone()
        },
        evm_only("BadCommittee"),
    );
    out.add(
        "signer_ys_short",
        "signerYs of 48(q − 1) bytes",
        &Certificate {
            signer_ys: shorter(&good.signer_ys, FP_LEN),
            ..good.clone()
        },
        evm_only("BadCertificate"),
    );

    // Signer keys that are points of the curve but fail KeyValidate, and an identity aggregate
    // (§5.1.3 steps 10–11). Each committee is pinned under the root of its exact key bytes,
    // in canonical order.
    let shift = g1_shift_outside_subgroup();
    let shifted = g1_plus(&keys[0], &shift);
    let (certificate, pin) = odd_committee(world, [shifted, keys[1], keys[2], keys[3]], 7370);
    out.add_under(
        "signer_key_outside_g1",
        "member 0 listed under its key shifted by a point outside G1, with the genuine \
         signature: the pairing equation holds, the aggregate key is outside G1",
        &certificate,
        &pin,
        "n4",
        both("BadSignature"),
    );
    let (certificate, pin) = odd_committee(
        world,
        [shifted, g1_minus(&keys[1], &shift), keys[2], keys[3]],
        7371,
    );
    let cancelling = Row {
        label: "signer_keys_outside_g1_cancelling",
        description: "members 0 and 1 listed under keys shifted by T and −T outside G1, with \
                      the genuine signature: neither key is in G1, the aggregate key is, and \
                      the pairing holds. EVM sees the aggregate only and accepts; the TON \
                      outcome rests on the per-key checks of BLS_FASTAGGREGATEVERIFY (null \
                      until the Acton harness pins them)",
        committee: "n4",
        certificate: &certificate,
        pin: &pin,
        now_ms: world.now,
        evm: true,
        ton: false,
    }
    .reference_json(false);
    assert_eq!(expected_of(&cancelling, "evm"), Some("ok"));
    assert_eq!(
        pin.outcome(DestinationFlavor::Ton, &certificate, world.now),
        "BadSignature"
    );
    // `apk = O`: member 2 listed under −(PK_0 + PK_1). The signature is the one members 0, 1
    // and 2 make.
    let rogue = g1_negated_sum(&keys[0], &keys[1]);
    let (certificate, pin) = odd_committee(world, [keys[0], keys[1], rogue, keys[3]], 7372);
    out.add_under(
        "aggregate_key_identity",
        "the three signer keys sum to the identity (member 2 listed under −(PK_0 + PK_1)); σ \
         is a point of G2",
        &certificate,
        &pin,
        "n4",
        [Some("BadCommittee"), Some("BadSignature")],
    );
    let mut off_curve_sigma = certificate.signature_evm.clone();
    off_curve_sigma[191] ^= 0x01;
    out.add_under(
        "aggregate_key_identity_sigma_off_curve",
        "the same identity aggregate with an EVM σ that is no point of the curve: apk = O is \
         reported first",
        &Certificate {
            signature_evm: off_curve_sigma,
            ..certificate
        },
        &pin,
        "n4",
        evm_only("BadCommittee"),
    );
    (out.rows, vec![cancelling])
}

// ---------------------------------------------------------------------------------------------
// The documents
// ---------------------------------------------------------------------------------------------

/// The complete `finality_v1.json` document.
fn finality_document() -> Value {
    let world = World::new();
    let committees = [&world.n4, &world.n7, &world.n31, &world.other4];
    let mut committees_json = obj([]);
    for committee in committees {
        insert(&mut committees_json, &committee.name, committee.as_json());
    }
    let (negatives, flavor_specific) = negative_certificates(&world);
    obj([
        ("schema", text("iroha.sccp.finality.v1")),
        (
            "spec",
            text(
                "specs/sccp.md §3.6–§3.8, §5.1.3, §11.2, §11.3 \
                 (revision 5)",
            ),
        ),
        ("generator", text(REFERENCE_GENERATORS)),
        (
            "conventions",
            text(&format!(
                "byte strings are 0x-prefixed lowercase hex; field elements and scalars that \
                 exceed 2^53 are hex strings; `expected.evm`/`expected.ton` name the §5.2.2 \
                 outcome of VerifyCertificate steps 1–12 on a fresh destination deployed \
                 with `pin` at `now_ms` (null where that flavor cannot express the vector). \
                 {DESTINATION_CLOCK_CONVENTION}. `headers.invalid[].error` is the first violated \
                 check in the order Length, X1, X2 (inactive) or X3 (active), X4, X5, X6, X7; X6 \
                 includes the rule that a ROTATION header has height and generation at most 2^64 \
                 - 2, so that the successor's start height + 1 and its generation + 1 fit u64 \
                 (rows rotation_at_max_height and rotation_at_max_generation); the rows named \
                 `<a>_and_<b>` violate two checks and report the earlier one, one row per \
                 adjacent pair of that order. `headers.*[].destination` is what the destination \
                 model answers for a certificate that carries the header. A certificate row \
                 carries `forgery_evidence_id` only when its `m` (the message that was signed) \
                 is the `m` a verifier derives from its wire fields. The TON verification \
                 context is ton-mainnet with the placeholder minter account id 0x35…35. \
                 `flavor_specific_certificates` are certificates that one flavor accepts and \
                 the other does not pin (rows of the same shape, without the pairing details)"
            )),
        ),
        ("constants", constants_json()),
        ("worked_examples", worked_examples()),
        ("headers", header_vectors(&world)),
        ("result_of_preimage", result_of_preimage_vectors()),
        ("signer_encodings", signer_encoding_vectors()),
        ("test_keys", test_keys_json()),
        ("committees", committees_json),
        ("verification_context", world.verification_context()),
        ("certificates", Value::Array(positive_certificates(&world))),
        ("negative_certificates", Value::Array(negatives)),
        (
            "flavor_specific_certificates",
            Value::Array(flavor_specific),
        ),
        (
            "rust_only_vectors",
            text(
                "the w3f-transcript negative of §11.3 (a signature made under the generic \
                 w3f transcript over a consensus digest) needs the iroha_crypto w3f transcript, \
                 which the dependency-free Python reference does not carry. It lives in \
                 fixtures/sccp/finality_rust_v1.json (schema iroha.sccp.finality.rust.v1), \
                 generated and drift-checked by crates/iroha_sccp/tests/v1_reference_finality.rs \
                 and verified as rejected by the Python reference in \
                 pytests/scripts/test_sccp_reference.py",
            ),
        ),
    ])
}

/// The complete `finality_rust_v1.json` document: the §11.3 negative that needs the w3f
/// transcript of `iroha_crypto`.
///
/// A full quorum of the `n = 4` test committee signs the certificate's commit digest `m`
/// through the generic signing API (`iroha_crypto::Signature`), not through the consensus
/// API. Everything else about the certificate is genuine, so only the pairing check can
/// refuse it. The same certificate under the consensus aggregate verifies, which is asserted
/// here and not written.
fn finality_rust_document() -> Value {
    let world = World::new();
    let n4 = &world.n4;
    let pin = Pin::of(n4);
    let genuine = world.certify_plain(&header(n4, 7400), n4);
    for flavor in [DestinationFlavor::Evm, DestinationFlavor::Ton] {
        assert_eq!(pin.outcome(flavor, &genuine, world.now), "ok");
    }
    let signers: Vec<_> = genuine
        .meta
        .signer_indices
        .iter()
        .map(|index| n4.members()[*index])
        .collect();
    assert_eq!(signers.len(), n4.quorum());
    // `sign_w3f` pins the transcript: the generic API's aggregate over `m`.
    let sigma: [u8; SIGNATURE_LEN] = sign_w3f(&signers, &genuine.meta.message);
    assert_ne!(sigma, genuine.meta.sigma);
    // The relation refuses it at the pairing check and nowhere else: every other field of
    // the certificate is the genuine one, which verifies.
    let relation = |signature: &[u8; SIGNATURE_LEN]| {
        verify_certificate(
            &INSTANCE,
            &genuine.qc,
            &genuine.header,
            signature,
            &n4.keys(),
        )
    };
    assert!(relation(&genuine.meta.sigma).is_ok());
    assert_eq!(relation(&sigma).err(), Some(CertificateError::Signature));
    let certificate = Certificate {
        signature_evm: g2_evm192(&sigma).to_vec(),
        signature_ton: sigma.to_vec(),
        ..genuine
    };
    let mut row = Row {
        label: "w3f_transcript_over_commit_digest",
        description: "a full quorum of the n = 4 test committee signs the commit digest m of \
                      the certificate through the generic signing API of iroha_crypto (the w3f \
                      transcript) instead of the consensus API; the certificate is genuine in \
                      every other field",
        committee: "n4",
        certificate: &certificate,
        pin: &pin,
        now_ms: world.now,
        evm: true,
        ton: true,
    }
    .json();
    for flavor in ["evm", "ton"] {
        assert_eq!(expected_of(&row, flavor), Some("BadSignature"), "{flavor}");
    }
    insert(
        &mut row,
        "transcript",
        text(
            "w3f: iroha_crypto::Signature::new(sk_i, m) for every signer i, summed; no \
             signature is made under DST_SIG",
        ),
    );
    let mut committees = obj([]);
    insert(&mut committees, &n4.name, n4.as_json());
    obj([
        ("schema", text("iroha.sccp.finality.rust.v1")),
        (
            "spec",
            text("specs/sccp.md §3.8, §5.1.3, §11.3 (revision 5)"),
        ),
        (
            "generator",
            text(&format!(
                "the Rust reference alone writes this file ({REGENERATE_FINALITY}); the Python \
                 reference verifies every row (pytests/scripts/test_sccp_reference.py)"
            )),
        ),
        (
            "conventions",
            text(&format!(
                "the rows have the shape of the negative_certificates rows of finality_v1.json, \
                 with `transcript` in place of `dst`: byte strings are 0x-prefixed lowercase \
                 hex, and `expected.evm`/`expected.ton` name the §5.2.2 outcome of \
                 VerifyCertificate steps 1–12 on a fresh destination deployed with `pin` \
                 at `now_ms`. {DESTINATION_CLOCK_CONVENTION}. The test keys, the committee and \
                 the verification context are those of finality_v1.json; a row is well formed \
                 up to the pairing check, the only step a foreign transcript can fail"
            )),
        ),
        ("verification_context", world.verification_context()),
        ("committees", committees),
        ("negative_certificates", list([row])),
    ])
}

// ---------------------------------------------------------------------------------------------
// Drift checks and regeneration
// ---------------------------------------------------------------------------------------------

#[test]
fn reference_finality_v1_matches_committed_fixture() {
    assert_matches_committed(FINALITY, &finality_document(), REGENERATE_COMMAND);
}

#[test]
fn reference_finality_rust_v1_matches_committed_fixture() {
    assert_matches_committed(
        FINALITY_RUST,
        &finality_rust_document(),
        REGENERATE_FINALITY,
    );
}

#[test]
#[ignore = "rewrites fixtures/sccp/finality_v1.json; run only after a reviewed change"]
fn regenerate_finality_v1() {
    write_fixture(FINALITY, &finality_document());
}

#[test]
#[ignore = "rewrites fixtures/sccp/finality_rust_v1.json; run only after a reviewed change"]
fn regenerate_finality_rust_v1() {
    write_fixture(FINALITY_RUST, &finality_rust_document());
}

// ---------------------------------------------------------------------------------------------
// The shared support
// ---------------------------------------------------------------------------------------------

/// The renderer writes the text of Python's `json.dumps(…, indent=2, sort_keys=True)`: the
/// first value is the one `test_render_is_canonical` pins on the Python side.
#[test]
fn python_json_renderer_matches_json_dumps() {
    let small: Value = norito::json::from_str(r#"{"b": 1, "a": [2]}"#).expect("JSON");
    assert_eq!(
        python_json::render(&small),
        "{\n  \"a\": [\n    2\n  ],\n  \"b\": 1\n}\n"
    );
    // Empty containers, the constants, nesting, and `ensure_ascii`: a quote, a backslash, the
    // short control escapes, another control character, DEL, the characters of the fixtures
    // outside ASCII and one outside the basic plane (a surrogate pair).
    let document = obj([
        ("empty_list", list([])),
        ("empty_object", obj([])),
        ("null", Value::Null),
        ("flags", list([Value::Bool(true), Value::Bool(false)])),
        ("wide", num((1 << 53) - 1)),
        ("nested", obj([("inner", list([obj([("k", num(0))])]))])),
        (
            "text",
            text("\"\\\n\r\t\u{8}\u{c}\u{1}\u{7f} \u{a7}\u{2013}\u{3c3}\u{2016}\u{2212} \u{1f600}"),
        ),
    ]);
    assert_eq!(
        python_json::render(&document),
        concat!(
            "{\n",
            "  \"empty_list\": [],\n",
            "  \"empty_object\": {},\n",
            "  \"flags\": [\n    true,\n    false\n  ],\n",
            "  \"nested\": {\n    \"inner\": [\n      {\n        \"k\": 0\n      }\n    ]\n  },\n",
            "  \"null\": null,\n",
            "  \"text\": \"\\\"\\\\\\n\\r\\t\\b\\f\\u0001\\u007f ",
            "\\u00a7\\u2013\\u03c3\\u2016\\u2212 \\ud83d\\ude00\",\n",
            "  \"wide\": 9007199254740991\n",
            "}\n",
        )
    );
    // The text parses back to the value it was written from.
    let parsed: Value = norito::json::from_str(&python_json::render(&document)).expect("JSON");
    assert_eq!(python_json::first_difference(&document, &parsed), None);
}

/// A drift failure names the first field that differs.
#[test]
fn first_difference_names_the_path() {
    let left = obj([
        ("a", list([num(1), obj([("b", text("x"))])])),
        ("c", num(3)),
    ]);
    assert_eq!(python_json::first_difference(&left, &left.clone()), None);
    let changed = obj([
        ("a", list([num(1), obj([("b", text("y"))])])),
        ("c", num(3)),
    ]);
    assert_eq!(
        python_json::first_difference(&left, &changed).as_deref(),
        Some("$.a[1].b: generated \"x\", committed \"y\"")
    );
    let shorter = obj([("a", list([num(1)])), ("c", num(3))]);
    assert_eq!(
        python_json::first_difference(&left, &shorter).as_deref(),
        Some("$.a: 2 items generated, 1 committed")
    );
    let missing = obj([("a", list([num(1), obj([("b", text("x"))])]))]);
    assert_eq!(
        python_json::first_difference(&left, &missing).as_deref(),
        Some("$: key `c` is generated but not committed")
    );
    assert_eq!(
        python_json::first_difference(&missing, &left).as_deref(),
        Some("$: key `c` is committed but not generated")
    );
}

/// `KeyGen` against a published known answer: the master key of EIP-2333 test case 0, which
/// is `KeyGen` of the seed with an empty `key_info`.
#[test]
fn keygen_matches_the_eip2333_master_key_vector() {
    let seed = unhex(
        "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1\
         c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
    );
    // 6083874454709270928345386274498605044986640685124978867557563392430687146096.
    assert_eq!(
        to_hex(&keygen(&seed).to_bytes_be()),
        "0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070"
    );
}

/// The test keys are distinct, a committee is in canonical order whatever order its indices
/// come in, and its JSON names the test key at every canonical position.
#[test]
fn committees_are_canonical_orders_of_the_test_keys() {
    let forward = Committee::new("forward", 0..7);
    let backward = Committee::new("backward", (0..7).rev());
    assert_eq!(forward.keys(), backward.keys());
    assert_eq!(forward.root(), backward.root());
    assert!(forward.keys().is_sorted_by(|left, right| left < right));
    assert_eq!((forward.n(), forward.quorum()), (7, 5));
    for (position, member) in forward.members().iter().enumerate() {
        assert_eq!(member.public, forward.keys()[position]);
        assert_eq!(forward.member_of(&member.public).index, member.index);
        assert_eq!(test_key(member.index).secret, member.secret);
    }
    let Value::Object(json) = forward.as_json() else {
        panic!("a committee is a JSON object");
    };
    assert_eq!(
        json.keys().map(String::as_str).collect::<Vec<_>>(),
        ["keys", "n", "q", "root", "test_key_indices"]
    );
    assert_eq!(json["root"], hx(&forward.root()));
    assert_eq!(hx_string(&[0x0a, 0xff]), "0x0aff");
}

/// A genuine certificate of the simulator verifies on both flavours, and every override of
/// [`CertifyOptions`] that changes what is signed makes a certificate that does not.
#[test]
fn certify_options_change_what_is_signed() {
    let world = World::new();
    let n4 = &world.n4;
    let pin = Pin::of(n4);
    let x = header(n4, 7500);
    let outcomes = |certificate: &Certificate| {
        [DestinationFlavor::Evm, DestinationFlavor::Ton]
            .map(|flavor| pin.outcome(flavor, certificate, world.now))
    };
    let genuine = world.certify_plain(&x, n4);
    assert_eq!(outcomes(&genuine), ["ok", "ok"]);
    assert_eq!(genuine.meta.signer_indices, [0, 1, 2]);
    assert_eq!(genuine.meta.kind, 0x03);
    assert_eq!(genuine.meta.dst, DST_SIG);
    assert_eq!(genuine.qc.len(), QC_FIXED_LEN);
    assert_eq!(genuine.signer_ys.len(), FP_LEN * 3);
    // Another result body is another certificate of the same header.
    let other_body = world.certify(
        &x,
        n4,
        &CertifyOptions {
            body_tag: b"/other".to_vec(),
            ..CertifyOptions::default()
        },
    );
    assert_eq!(outcomes(&other_body), ["ok", "ok"]);
    assert_eq!(other_body.header, genuine.header);
    assert_ne!(other_body.qc, genuine.qc);
    for options in [
        CertifyOptions {
            kind: Some(KIND_PREPARE),
            ..CertifyOptions::default()
        },
        CertifyOptions {
            dst: Some(DST_NUL.to_vec()),
            ..CertifyOptions::default()
        },
        CertifyOptions {
            signed_height: Some(7501),
            ..CertifyOptions::default()
        },
        CertifyOptions {
            signed_instance: Some([0x78; 32]),
            ..CertifyOptions::default()
        },
        CertifyOptions {
            signed_header: Some(header(n4, 7502).to_bytes().to_vec()),
            ..CertifyOptions::default()
        },
        CertifyOptions {
            signing_keys: Some(n4.keys()[1..].to_vec()),
            ..CertifyOptions::default()
        },
    ] {
        let certificate = world.certify(&x, n4, &options);
        assert_eq!(certificate.header, genuine.header, "{options:?}");
        assert_eq!(
            outcomes(&certificate),
            ["BadSignature", "BadSignature"],
            "{options:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The simulator and the scenario recorder
// ---------------------------------------------------------------------------------------------

/// The parts of the shared support that `finality_v1.json` does not use: the blocks, leaves
/// and proofs of the simulator, the certificate pool and the scenario recorder. The
/// transitions and control generators are built on them; these tests pin the row shape they
/// write and show how they are driven.
mod recorder {
    use std::{cell::RefCell, rc::Rc};

    use iroha_sccp::v1::control::ControlLeafV1;

    use super::{
        reference_support::{
            scenario::{CertificatePool, Scenario, Source, Submission},
            taira_sim::{Block, LeafKind, Rotate},
        },
        *,
    };

    const SECOND: u64 = 1_000;
    const MINUTE: u64 = 60 * SECOND;
    const DAY: u64 = 24 * HOUR;
    /// The pinned generation of the route.
    const PIN_GENERATION: u64 = 5;
    /// Its first height.
    const PIN_START: u64 = 1000;
    const RECIPIENT: [u8; 20] = [0x44; 20];
    const AMOUNT: u128 = 1_000_000_000;

    /// The committee `K<j>`: test keys `40 + 4j … 43 + 4j`.
    fn committee(j: u8) -> Committee {
        Committee::new(&format!("K{j}"), 40 + 4 * j..44 + 4 * j)
    }

    /// A recipient of the TON route: `addr_std` in workchain 0.
    const TON_RECIPIENT: [u8; 36] = {
        let mut recipient = [0x44; 36];
        recipient[0] = 0;
        recipient[1] = 0;
        recipient[2] = 0;
        recipient[3] = 0;
        recipient
    };

    /// A Taira route with generation 5 (`K0`) pinned at height 1000 and time `T0`, and the
    /// certificate pool its scenarios share.
    struct Route {
        sim: TairaSim,
        pool: Rc<RefCell<CertificatePool>>,
    }

    impl Route {
        /// The Ethereum route.
        fn new() -> Self {
            Self::to(SccpNetworkV1::EthereumMainnet, destination_word())
        }

        /// The TON route, to the placeholder minter account id.
        fn ton() -> Self {
            Self::to(SccpNetworkV1::TonMainnet, TON_DESTINATION_WORD)
        }

        fn to(target: SccpNetworkV1, word: [u8; 32]) -> Self {
            let mut sim = TairaSim::new(NETWORK_ID, INSTANCE, target, word);
            sim.start(PIN_GENERATION, committee(0), PIN_START, T0, VALIDITY);
            Self {
                sim,
                pool: Rc::default(),
            }
        }

        /// A scenario on a destination of the route, of `flavor`: the flavour of the route's
        /// profile, or the deployment is refused.
        fn scenario(&self, name: &str, flavor: DestinationFlavor) -> Scenario {
            let pin = committee(0);
            let deployment = DeploymentV1 {
                flavor,
                taira_network_id: NETWORK_ID,
                consensus_instance: INSTANCE,
                network: self.sim.target,
                destination_word: self.sim.destination_word,
                route_revision: 1,
                max_wrapped_supply: 10 * AMOUNT,
                pin_generation: PIN_GENERATION,
                pin_root: pin.root(),
                pin_start_height: PIN_START,
                pin_until_ms: T0 + VALIDITY,
                pin_keys: Some(pin.keys()),
            };
            Scenario::new(name, "a recorder probe", deployment, &self.pool, true)
        }

        /// An empty block one second per height after the pin.
        fn block(&mut self, height: u64) -> Block {
            self.sim.block(
                height,
                T0 + (height - PIN_START) * SECOND,
                vec![],
                None,
                None,
            )
        }

        /// The certificate of `block` by its own generation, labelled `X_<height>`.
        fn cert(&self, block: &Block) -> Submission {
            let signer = &block.generation.committee;
            Submission::new(
                self.sim
                    .certify(&block.x(), signer, &CertifyOptions::default()),
                &format!("X_{}", block.height),
                &signer.name,
            )
        }
    }

    fn keys_of(value: &Value) -> Vec<&str> {
        value
            .as_object()
            .expect("a JSON object")
            .keys()
            .map(String::as_str)
            .collect()
    }

    /// A block's header commits to its leaves and to the history of the SCCP-bearing blocks,
    /// a rotation starts the next generation at the next height, and the proofs of the
    /// simulator are the ones the destination model accepts.
    #[test]
    fn simulator_blocks_generations_and_proofs() {
        let mut route = Route::new();
        let control = ControlLeafV1 {
            control_nonce: 1,
            track: 1,
            parliament_paused: 1,
            certificate_id: [0xc1; 32],
            effect_hash: [0xe1; 32],
            ..ControlLeafV1::default()
        };
        let leaves = vec![
            route.sim.control(&control, true),
            route.sim.transfer(0, AMOUNT, T0 + DAY, &RECIPIENT),
        ];
        assert_eq!(
            leaves.iter().map(|leaf| leaf.kind).collect::<Vec<_>>(),
            [LeafKind::Control, LeafKind::Transfer]
        );
        // The simulator fills in its own route revision.
        assert_eq!(leaves[0].control.route_revision, 1);
        let empty = route.block(1005);
        let first = route.sim.block(1010, T0 + 10 * SECOND, leaves, None, None);
        let handoff = route.sim.block(
            1100,
            T0 + HOUR,
            vec![],
            Some(Rotate::Key(committee(1))),
            Some(3 * DAY),
        );
        let after = route.block(1101);
        for block in [&empty, &first, &handoff, &after] {
            valid(&block.header);
        }
        assert_eq!((empty.header.message_count, empty.history_index), (0, None));
        assert_eq!(empty.header.history_size, 0);
        assert_eq!(
            (first.header.message_count, first.history_index),
            (2, Some(0))
        );
        assert_eq!(
            (first.header.history_size, handoff.header.history_size),
            (1, 1)
        );
        assert_eq!(handoff.header.flags, FLAG_ACTIVE | FLAG_ROTATION);
        assert_eq!(handoff.header.next_committee_root, committee(1).root());
        assert_eq!(handoff.header.validity_ms, 3 * DAY);
        assert_eq!(handoff.generation.number, PIN_GENERATION);
        // Rule G2: generation g + 1 starts at h + 1 and counts from the handoff's time.
        let successor = &after.generation;
        assert_eq!(successor.number, PIN_GENERATION + 1);
        assert_eq!(successor.committee.name, "K1");
        assert_eq!(successor.start_height, 1101);
        assert_eq!(successor.deadline_ms(), T0 + HOUR + 3 * DAY);
        assert_eq!(after.header.committee_root, committee(1).root());
        assert_eq!(route.sim.generations.len(), 2);

        // The block proves its own leaves directly, and the handoff proves them through its
        // history root.
        let direct = route.sim.message_proof(1010, 1, &first.header);
        assert!(direct.block.history_path.is_empty());
        let historical = route.sim.control_proof(1010, 0, &handoff.header);
        assert_eq!(historical.block.height, 1010);
        assert_eq!(historical.parliament_paused, 1);
        let mut scenario = route.scenario("proofs", DestinationFlavor::Evm);
        scenario
            .finalize(
                Source::Inline(&route.cert(&first)),
                &direct,
                T0 + MINUTE,
                Some("ok"),
            )
            .expect("the transfer is minted");
        scenario
            .apply_control(
                Source::Inline(&route.cert(&handoff)),
                &historical,
                T0 + HOUR + MINUTE,
                Some("ok"),
            )
            .expect("the control is applied");
        assert!(scenario.destination.minting_paused(T0 + HOUR + MINUTE));
        // An inline rotation certificate installs nothing.
        assert_eq!(
            scenario.destination.state().committee.generation,
            PIN_GENERATION
        );
    }

    /// Every call of the recorder writes one step `{call, now_ms, inputs…, expected,
    /// state_after}`; certificates are pooled once and referenced by id.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one scenario that walks every call of the recorder"
    )]
    fn recorder_writes_the_scenario_row_shape() {
        let mut route = Route::new();
        let transfers = vec![
            route.sim.transfer(0, AMOUNT, T0 + DAY, &RECIPIENT),
            route.sim.transfer(1, AMOUNT, T0 + HOUR, &RECIPIENT),
        ];
        let block = route
            .sim
            .block(1010, T0 + 10 * SECOND, transfers, None, None);
        let later = route.block(1020);
        let x = block.x();
        let id = checkpoint_id(valid(&block.header).as_bytes());
        let mut scenario = route.scenario("row_shape", DestinationFlavor::Evm);

        scenario.views(T0 + MINUTE);
        scenario
            .submit(&[route.cert(&block)], T0 + MINUTE, Some("ok"))
            .expect("a checkpoint");
        // The same certificate again: the same pool id, and nothing to do.
        assert_eq!(
            scenario.submit(&[route.cert(&block)], T0 + MINUTE, Some("NothingToDo")),
            Err(iroha_sccp::v1::destination::DestinationError::NothingToDo)
        );
        let minted = scenario
            .finalize(
                Source::Checkpoint(&x),
                &route.sim.message_proof(1010, 0, &block.header),
                T0 + 2 * MINUTE,
                Some("ok"),
            )
            .expect("a mint");
        scenario
            .finalize(
                Source::Checkpoint(&x),
                &route.sim.message_proof(1010, 0, &block.header),
                T0 + 2 * MINUTE,
                Some("AlreadyConsumed"),
            )
            .expect_err("a consumed nonce");
        scenario
            .void_expired(
                7,
                Source::Inline(&route.cert(&later)),
                &route.sim.message_proof(1010, 1, &later.header),
                T0 + HOUR + SECOND,
                Some("BadNonce"),
            )
            .expect_err("the payload names nonce 1");
        scenario
            .void_frozen(u64::MAX, 2, T0 + HOUR + SECOND, Some("BadAmount"))
            .expect_err("a range past the last nonce");
        // Another header at a stored height, signed by the same generation: V1 latches.
        let conflicting = with(block.header, |x| x.sccp_root = [0xee; 32]);
        let forged = Submission::new(
            route.sim.certify(
                &conflicting.to_bytes(),
                &committee(0),
                &CertifyOptions::default(),
            ),
            "forged_X_1010",
            "K0",
        );
        let latched = scenario
            .submit(&[forged], T0 + HOUR + SECOND, Some("ok"))
            .expect("a latch is not a revert");
        assert_eq!(latched.events.len(), 2);
        scenario
            .void_frozen(1, 2, T0 + HOUR + SECOND, Some("ok"))
            .expect("a frozen destination voids");

        let row = scenario.as_json();
        assert_eq!(
            keys_of(&row),
            [
                "deployment",
                "description",
                "flavor",
                "initial_state",
                "name",
                "steps"
            ]
        );
        assert_eq!(row["flavor"], text("evm"));
        assert_eq!(
            keys_of(&row["deployment"]),
            [
                "consensus_instance",
                "destination_word",
                "flavor",
                "max_wrapped_supply",
                "network",
                "pin",
                "route_revision",
                "taira_network_id"
            ]
        );
        assert_eq!(row["deployment"]["max_wrapped_supply"], text("10000000000"));
        assert_eq!(
            row["deployment"]["pin"]["keys"],
            hexes(&committee(0).keys())
        );
        // The initial state has no clock, so no `live` and no effective pause.
        let initial = &row["initial_state"];
        assert_eq!(
            keys_of(initial),
            [
                "checkpoints",
                "committee",
                "consumed",
                "equivocated",
                "op_count",
                "pause",
                "total_supply"
            ]
        );
        assert_eq!(initial["committee"]["high"], num(PIN_START - 1));
        assert_eq!(
            keys_of(&initial["pause"]),
            ["control_nonce", "fast_pause_until_ms", "parliament_paused"]
        );

        let steps = row["steps"].as_array().expect("steps");
        let calls: Vec<&str> = steps
            .iter()
            .map(|step| step["call"].as_str().expect("a call name"))
            .collect();
        assert_eq!(
            calls,
            [
                "views",
                "submitCheckpoints",
                "submitCheckpoints",
                "finalizeFromCheckpoint",
                "finalizeFromCheckpoint",
                "voidExpired",
                "voidFrozen",
                "submitCheckpoints",
                "voidFrozen"
            ]
        );
        let [
            views,
            checkpoint,
            replay,
            mint,
            consumed,
            void,
            bad_range,
            latch,
            frozen,
        ] = &steps[..]
        else {
            panic!("nine steps");
        };

        assert_eq!(
            keys_of(views),
            ["call", "expected", "now_ms", "state_after"]
        );
        assert_eq!(
            keys_of(&views["expected"]),
            [
                "committeeState",
                "controlNonce",
                "equivocated",
                "initialCommittee",
                "live",
                "mintingPaused",
                "opCount",
                "pauseState"
            ]
        );
        assert_eq!(
            views["expected"]["committeeState"]["untilMs"],
            num(T0 + VALIDITY)
        );
        assert_eq!(views["state_after"]["live"], Value::Bool(true));
        assert_eq!(
            views["state_after"]["pause"]["effective"],
            Value::Bool(false)
        );

        assert_eq!(
            keys_of(checkpoint),
            ["call", "certificates", "expected", "now_ms", "state_after"]
        );
        assert_eq!(checkpoint["certificates"], list([text("c001")]));
        assert_eq!(
            checkpoint["expected"],
            obj([
                ("outcome", text("ok")),
                (
                    "events",
                    list([
                        obj([
                            ("event", text("SccpCertificate")),
                            ("height", num(1010)),
                            ("generation", num(PIN_GENERATION)),
                            ("certificate", text("c001")),
                        ]),
                        obj([
                            ("event", text("SccpCheckpointed")),
                            ("height", num(1010)),
                            ("header", hx(&id)),
                        ]),
                    ])
                ),
            ])
        );
        assert_eq!(
            checkpoint["state_after"]["checkpoints"],
            list([obj([("height", num(1010)), ("id", hx(&id))])])
        );
        assert_eq!(checkpoint["state_after"]["committee"]["high"], num(1010));
        // A refusal has no event and leaves the state as it was.
        assert_eq!(replay["certificates"], list([text("c001")]));
        assert_eq!(
            replay["expected"],
            obj([("outcome", text("NothingToDo")), ("events", list([]))])
        );
        assert_eq!(replay["state_after"], checkpoint["state_after"]);

        assert_eq!(
            keys_of(mint),
            [
                "call",
                "checkpoint",
                "expected",
                "now_ms",
                "proof",
                "state_after"
            ]
        );
        assert_eq!(mint["checkpoint"], obj([("header", hx(&x))]));
        assert_eq!(
            keys_of(&mint["proof"]),
            ["block", "leafIndex", "path", "payload"]
        );
        assert_eq!(
            keys_of(&mint["proof"]["block"]),
            [
                "height",
                "historyIndex",
                "historyPath",
                "messageCount",
                "sccpRoot"
            ]
        );
        let message_id = minted.returned.expect("the message id");
        assert_eq!(mint["expected"]["return"], hx(&message_id));
        assert_eq!(
            mint["expected"]["events"],
            list([obj([
                ("event", text("SccpFinalized")),
                ("messageId", hx(&message_id)),
                ("nonce", num(0)),
                ("recipient", hx(&RECIPIENT)),
                ("tokenAmount", text("1000000000")),
            ])])
        );
        assert_eq!(mint["state_after"]["consumed"], list([num(0)]));
        assert_eq!(mint["state_after"]["total_supply"], text("1000000000"));
        assert_eq!(mint["state_after"]["op_count"], num(1));
        assert_eq!(
            consumed["expected"],
            obj([
                ("outcome", text("AlreadyConsumed")),
                ("error_args", obj([("nonce", num(0))])),
                ("events", list([])),
            ])
        );

        // An inline certificate is pooled at its first use and named by id.
        assert_eq!(
            keys_of(void),
            [
                "call",
                "certificate",
                "expected",
                "nonce",
                "now_ms",
                "proof",
                "state_after"
            ]
        );
        assert_eq!(
            (&void["certificate"], &void["nonce"]),
            (&text("c002"), &num(7))
        );
        assert_eq!(
            void["expected"],
            obj([
                ("outcome", text("BadNonce")),
                ("error_args", obj([("expected", num(1))])),
                ("events", list([])),
            ])
        );
        assert_eq!(void["proof"]["block"]["historyIndex"], num(0));
        assert_eq!(
            void["proof"]["block"]["historyPath"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );

        assert_eq!(bad_range["firstNonce"], text("18446744073709551615"));
        assert_eq!(bad_range["count"], num(2));
        assert_eq!(bad_range["expected"]["outcome"], text("BadAmount"));

        // A latch persists: the call succeeds with `stopped`, and the destination is frozen.
        assert_eq!(latch["certificates"], list([text("c003")]));
        assert_eq!(latch["expected"]["stopped"], text("latch"));
        let violation = &latch["expected"]["events"][1];
        assert_eq!(violation["event"], text("SccpLatched"));
        assert_eq!((&violation["reason"], &violation["a"]), (&num(1), &hx(&id)));
        assert_eq!(latch["state_after"]["equivocated"], Value::Bool(true));
        assert_eq!(latch["state_after"]["committee"]["until_ms"], num(0));
        assert_eq!(latch["state_after"]["live"], Value::Bool(false));
        // EVM voids a frozen range one event per nonce.
        assert_eq!(
            frozen["expected"]["events"],
            list([1, 2].map(|nonce| obj([
                ("event", text("SccpVoided")),
                ("messageId", hx(&[0; 32])),
                ("nonce", num(nonce)),
            ])))
        );
        assert_eq!(
            frozen["state_after"]["consumed"],
            list([num(0), num(1), num(2)])
        );

        // The pool: ids in order of first use, one entry per distinct certificate.
        let pool = route.pool.borrow();
        assert_eq!(pool.len(), 3);
        let entries = pool.as_json();
        assert_eq!(keys_of(&entries), ["c001", "c002", "c003"]);
        assert_eq!(
            keys_of(&entries["c001"]),
            [
                "evm",
                "header_fields",
                "label",
                "signed_by",
                "signer_indices",
                "ton",
                "ton_next_keys"
            ]
        );
        assert_eq!(entries["c001"]["label"], text("X_1010"));
        assert_eq!(entries["c001"]["signed_by"], text("K0"));
        assert_eq!(entries["c001"]["evm"]["header"], hx(&x));
        assert_eq!(entries["c001"]["ton_next_keys"], Value::Null);
        assert_eq!(entries["c003"]["label"], text("forged_X_1010"));
        // A published certificate is found among the ids of its step by its `QC_FIXED`, its
        // header and its signature, in either wire form.
        let genuine = route.cert(&block).certificate;
        let ids = ["c001".to_owned(), "c002".to_owned(), "c003".to_owned()];
        for signature in [&genuine.signature_evm, &genuine.signature_ton] {
            assert_eq!(pool.id_of(&genuine.qc, &x, signature, &ids), Some("c001"));
            assert_eq!(pool.id_of(&genuine.qc, &x, signature, &ids[1..]), None);
        }
        assert_eq!(pool.id_of(&[], &x, &genuine.signature_evm, &ids), None);
        assert_eq!(pool.id_of(&genuine.qc, &x, &[0; 96], &ids), None);
    }

    /// A twin of the genuine certificate (the same `QC_FIXED` and `X` under another
    /// signature) that is pooled first does not take the name of the certificate a
    /// destination publishes.
    #[test]
    fn recorder_names_the_published_certificate_by_its_signature() {
        for flavor in [DestinationFlavor::Evm, DestinationFlavor::Ton] {
            let mut route = match flavor {
                DestinationFlavor::Evm => Route::new(),
                DestinationFlavor::Ton => Route::ton(),
            };
            let block = route.block(1010);
            let genuine = route.cert(&block);
            let twin = Submission::new(
                route.sim.certify(
                    &block.x(),
                    &block.generation.committee,
                    &CertifyOptions {
                        signed_instance: Some([0x78; 32]),
                        ..CertifyOptions::default()
                    },
                ),
                "twin",
                "K0",
            );
            assert_eq!(twin.certificate.qc, genuine.certificate.qc);
            assert_eq!(twin.certificate.header, genuine.certificate.header);
            assert_ne!(
                twin.certificate.signature_ton,
                genuine.certificate.signature_ton
            );
            let mut scenario = route.scenario("twin_first", flavor);
            scenario
                .submit(
                    std::slice::from_ref(&twin),
                    T0 + MINUTE,
                    Some("BadSignature"),
                )
                .expect_err("the twin does not verify");
            scenario
                .submit(std::slice::from_ref(&genuine), T0 + MINUTE, Some("ok"))
                .expect("the genuine certificate verifies");
            let row = scenario.as_json();
            let step = &row["steps"][1];
            assert_eq!(step["certificates"], list([text("c002")]));
            assert_eq!(
                step["expected"]["events"][0]["certificate"],
                text("c002"),
                "{}",
                flavor.name()
            );
        }
    }

    /// TON takes one certificate per `sccp_checkpoint` message with its `next_keys`, and its
    /// state holds the committee keys. A certificate first used inline is pooled without
    /// successor keys.
    #[test]
    fn recorder_writes_ton_checkpoints_with_next_keys() {
        let mut route = Route::ton();
        let (k1, k2) = (committee(1), committee(2));
        let handoff = route.sim.block(
            1100,
            T0 + HOUR,
            vec![route.sim.transfer(0, AMOUNT, T0 + DAY, &TON_RECIPIENT)],
            Some(Rotate::Key(k1.clone())),
            None,
        );
        let certificate = route.cert(&handoff).with_next(&k1);
        let now = T0 + HOUR + MINUTE;
        let mut scenario = route.scenario("ton", DestinationFlavor::Ton);
        scenario
            .finalize(
                Source::Inline(&certificate),
                &route.sim.message_proof(1100, 0, &handoff.header),
                now,
                Some("ok"),
            )
            .expect("the handoff proves its own transfer inline");
        scenario
            .submit(
                &[certificate.clone().with_next_keys(None)],
                now,
                Some("BadCommittee"),
            )
            .expect_err("a key change needs the successor keys");
        scenario
            .submit(
                &[certificate.clone().with_next_keys(Some(&k2))],
                now,
                Some("BadCommittee"),
            )
            .expect_err("other keys are not the announced successor");
        scenario
            .submit(&[certificate], now, Some("ok"))
            .expect("the rotation installs K1");

        let row = scenario.as_json();
        assert_eq!(row["flavor"], text("ton"));
        assert_eq!(
            row["initial_state"]["committee"]["keys"],
            hexes(&committee(0).keys())
        );
        let steps = row["steps"].as_array().expect("steps");
        // A TON row names the messages of §5.3.2.
        assert_eq!(steps[0]["call"], text("sccp_finalize"));
        assert_eq!(row["deployment"]["network"], text("ton-mainnet"));
        for (step, next_keys) in steps[1..].iter().zip([Value::Null, text("K2"), text("K1")]) {
            assert_eq!(step["call"], text("sccp_checkpoint"));
            assert_eq!(step["certificates"], list([text("c001")]));
            assert_eq!(step["next_keys"], list([next_keys]));
        }
        let installed = &steps[3];
        assert_eq!(
            installed["expected"]["events"],
            list([obj([
                ("event", text("SccpCommitteeRotated")),
                ("generation", num(PIN_GENERATION + 1)),
                ("root", hx(&k1.root())),
                ("untilMs", num(T0 + HOUR + VALIDITY)),
                ("startHeight", num(1101)),
            ])])
        );
        assert_eq!(
            installed["state_after"]["committee"]["keys"],
            hexes(&k1.keys())
        );
        assert_eq!(installed["state_after"]["committee"]["generation"], num(6));
        // The pool entry keeps what the first use brought: an inline use brings no keys.
        let pool = route.pool.borrow();
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.as_json()["c001"]["ton_next_keys"], Value::Null);
    }

    /// A destination reads whole seconds, so the recorder refuses a sub-second clock value.
    #[test]
    #[should_panic(expected = "is not a whole-second destination clock value")]
    fn recorder_refuses_a_sub_second_clock() {
        Route::new()
            .scenario("sub_second", DestinationFlavor::Evm)
            .views(T0 + 1);
    }

    /// The destination clock never runs backwards inside a scenario; equal values are fine.
    #[test]
    #[should_panic(expected = "is earlier than the previous step's")]
    fn recorder_refuses_a_clock_that_runs_backwards() {
        let mut scenario = Route::new().scenario("backwards", DestinationFlavor::Evm);
        scenario.views(T0 + MINUTE);
        scenario.views(T0 + MINUTE);
        scenario.views(T0 + MINUTE - SECOND);
    }

    /// The flavour of a scenario is the flavour of its route's profile.
    #[test]
    #[should_panic(expected = "the deployment is refused")]
    fn recorder_refuses_a_ton_scenario_on_the_ethereum_route() {
        let _ = Route::new().scenario("mismatch", DestinationFlavor::Ton);
    }

    /// A strict scenario fails when the model does not give the outcome its author wrote.
    #[test]
    #[should_panic(expected = "the model gave")]
    fn strict_scenario_refuses_an_unexpected_outcome() {
        let mut scenario = Route::new().scenario("strict", DestinationFlavor::Evm);
        let _ = scenario.void_frozen(0, 1, T0 + MINUTE, Some("ok"));
    }

    /// A replay on the other flavour is not strict: it records what the model answers.
    #[test]
    fn lenient_scenario_records_whatever_the_model_answers() {
        let route = Route::ton();
        let mut strict = route.scenario("lenient", DestinationFlavor::Ton);
        let deployment = strict.destination.deployment().clone();
        let mut lenient = Scenario::new("lenient", "a replay", deployment, &route.pool, false);
        assert_eq!(lenient.flavor(), DestinationFlavor::Ton);
        let answer = lenient.void_frozen(0, 1, T0 + MINUTE, Some("ok"));
        assert_eq!(outcome_name(&answer), "NotFrozen");
        assert_eq!(lenient.steps[0]["expected"]["outcome"], text("NotFrozen"));
        assert_eq!(
            strict.void_frozen(0, 1, T0 + MINUTE, Some("NotFrozen")),
            answer
        );
        assert_eq!(strict.steps, lenient.steps);
    }
}
