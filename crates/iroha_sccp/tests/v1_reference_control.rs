//! Rust reference generator of `fixtures/sccp/control_v1.json` (`specs/sccp.md` §3.4,
//! §4.14.6, §5.1.6, §11.1).
//!
//! The file is also written by the independent Python reference
//! (`scripts/sccp_reference/vectors_control.py`), and the two outputs must be byte-identical.
//! This target rebuilds the whole document from `iroha_sccp::v1`:
//!
//! - the control leaves of the §3.4 example table, whose leaves and nonce-2 preimage the
//!   specification pins and the build asserts, and the leaves of every target network, both
//!   tracks and both pause values, each with its 199-byte preimage and its two TON `HASHEXT`
//!   builders;
//! - the fields Taira does not record, each with the error of `control::control_leaf` and
//!   with what a destination answers when a block that holds such a leaf is certified all the
//!   same, which the build asks the destination model;
//! - the `SccpControlApplied` topic, recomputed from the canonical signature;
//! - the `applyControl` scenarios (§5.1.6) in the row shape of
//!   `committee_transitions_v1.json`: a fresh EVM destination, then calls with `now_ms`, each
//!   recorded with the outcome, the events and the state that the Rust destination model
//!   (`iroha_sccp::v1::destination`) gives. Headers, certificates and proofs come from the
//!   simulator of `reference_support`, so every key, signature, hash and encoding of the
//!   document is derived here.
//!
//! `now_ms` is the destination clock (`block.timestamp × 1000`, §0): every step uses a whole
//! second and no step is earlier than the one before it, which the recorder asserts. A
//! fast-pause expiry is therefore probed at the last clock value below it and at the first
//! one that is not, for a whole-second expiry and for one that ends in 001 ms.
//!
//! Drift test: `reference_control_v1_matches_committed_fixture`. After a reviewed change,
//! rewrite the file with
//! `cargo test -p iroha_sccp --test v1_reference_control -- --ignored regenerate`.

mod reference_support;

use std::{cell::RefCell, collections::BTreeSet, rc::Rc, sync::LazyLock};

use iroha_data_model::bridge::SccpNetworkV1;
use iroha_sccp::v1::{
    constants::CONTROL_TAG,
    control::{
        CONTROL_LEAF_PREIMAGE_BYTES, CONTROL_TON_B1_BYTES, CONTROL_TON_B2_BYTES, ControlLeafError,
        ControlLeafV1, MAX_FAST_PAUSE_MS, TRACK_FAST_PAUSE, TRACK_PARLIAMENT,
        applied_fast_pause_until_ms, check_control_constraints, control_leaf,
        control_leaf_preimage, control_leaf_unchecked, ton_builders,
    },
    destination::{
        CertificateSourceV1, ControlProofV1, DeploymentV1, Destination, DestinationEvent,
        DestinationFlavor, MessageProofV1,
    },
    destination_abi::{EVENT_CONTROL_APPLIED, TOPIC_CONTROL_APPLIED},
    finality::SccpFinalityHeaderFieldsV1,
    hashes::{keccak256, to_hex, word_address, word_u64},
    network::{lane_bytes, tag},
};
use norito::json::Value;
use reference_support::{
    DESTINATION_CLOCK_CONVENTION, REFERENCE_GENERATORS, REGENERATE_COMMAND,
    SCENARIO_CLOCK_CONVENTION, assert_matches_committed, hx, insert, list, num, obj, outcome_name,
    scenario::{
        CertificatePool, Scenario, Source, Submission, check_scenario_clock,
        check_scenario_outcomes, step_outcome, steps_of,
    },
    taira_sim::{CertifyOptions, Committee, LeafItem, LeafKind, TairaSim},
    text, unhex, write_fixture,
};

/// The file both references write.
const CONTROL: &str = "control_v1.json";

/// Taira's `NetworkId` in every vector.
const NETWORK_ID: [u8; 32] = [0x11; 32];
/// The consensus instance `I` of the scenarios.
const INSTANCE: [u8; 32] = [0x77; 32];
/// Taira time of the pin (ms): the tenure of the pinned generation counts from it.
const T0: u64 = 1_800_000_000_000;
/// One second (ms): the step of the destination clock.
const SECOND: u64 = 1_000;
/// One minute (ms).
const MINUTE: u64 = 60 * SECOND;
/// One hour (ms).
const HOUR: u64 = 60 * MINUTE;
/// One day (ms).
const DAY: u64 = 24 * HOUR;
/// The validity of the pinned generation (ms).
const VALIDITY: u64 = 1_209_600_000;
/// The pinned generation.
const PIN_GENERATION: u64 = 5;
/// Its first height.
const PIN_START: u64 = 1000;
/// The address of the Ethereum contract. Its word is the destination word of the scenarios.
const ETHEREUM_ADDRESS: [u8; 20] = [0x22; 20];
/// The address of the BSC contract.
const BSC_ADDRESS: [u8; 20] = [0x24; 20];
/// The account id of the TON minter.
const TON_ACCOUNT_ID: [u8; 32] = [0x35; 32];
/// The recipient of the transfers.
const RECIPIENT: [u8; 20] = [0x44; 20];
/// The unit of the transfer amounts.
const AMOUNT: u128 = 1_000_000_000;
/// `maxWrappedSupply` of the deployment.
const SUPPLY_CAP: u128 = 1_000_000_000_000_000_000;
/// The fast-pause expiry of the matrix rows that carry one.
const MATRIX_EXPIRY: u64 = T0 + 10 * DAY;
/// A fast-pause expiry that ends in 001 ms: no destination clock value equals it.
const SUB_SECOND_EXPIRY: u64 = T0 + 2 * HOUR + 1;

/// The profiles a control leaf can target, in tag order.
const TARGETS: [SccpNetworkV1; 3] = [
    SccpNetworkV1::EthereumMainnet,
    SccpNetworkV1::BscMainnet,
    SccpNetworkV1::TonMainnet,
];

// §3.4 and §5.2.2 values that the specification pins. They are asserted on every build.

/// `topic0` of `SccpControlApplied` (§5.2.2).
const SPEC_TOPIC: &str = "b069397cc6f8fa22bf7c0216c554253ab0fc92a3178d10969760b028dd174238";
/// The expiry of the §3.4 examples that carry a fast pause.
const SPEC_EXPIRY: u64 = 1_700_604_800_000;
/// The §3.4 example table: the fields of each row and its leaf.
const SPEC_EXAMPLES: [(ControlLeafV1, &str); 4] = [
    (
        spec_example(1, TRACK_PARLIAMENT, 1, 0, 0x33, 0x44),
        "d9be284f6412d8e310b35afa921f8244f8d56cc64fbfc795d58701c11dce4d77",
    ),
    (
        spec_example(2, TRACK_FAST_PAUSE, 0, SPEC_EXPIRY, 0x55, 0x66),
        "fbdf5c5743292897ecf43c3d74fe0a3d3946aa73219bdab2f0a3e33bc0b988e0",
    ),
    (
        spec_example(3, TRACK_PARLIAMENT, 1, SPEC_EXPIRY, 0x77, 0x88),
        "8afcebc533342cb86836b0195edc6a55e8e998d8e52d85f1fbf2c2707193c518",
    ),
    (
        spec_example(4, TRACK_PARLIAMENT, 0, 0, 0x99, 0xaa),
        "b52aafb5bd2fcc77db32e1dfb8a92890b97adc2b9e81dd30f63dba3c059c8df3",
    ),
];

/// A row of the §3.4 example table: route revision 1, with ids of one repeated byte.
const fn spec_example(
    control_nonce: u64,
    track: u8,
    parliament_paused: u8,
    fast_pause_until_ms: u64,
    certificate_id: u8,
    effect_hash: u8,
) -> ControlLeafV1 {
    ControlLeafV1 {
        route_revision: 1,
        control_nonce,
        track,
        parliament_paused,
        fast_pause_until_ms,
        certificate_id: [certificate_id; 32],
        effect_hash: [effect_hash; 32],
    }
}

/// The preimage of the nonce-2 example as §3.4 spells it out, field by field.
fn spec_nonce2_preimage() -> String {
    [
        "534343502f434f4e54524f4c2f5631",
        "40",
        &"11".repeat(32),
        "41",
        &"00".repeat(31),
        "01",
        &"00".repeat(12),
        &"22".repeat(20),
        "00000001",
        "0000000000000002",
        "02",
        "00",
        "0000018bf3f1ec00",
        &"55".repeat(32),
        &"66".repeat(32),
    ]
    .concat()
}

// ---------------------------------------------------------------------------------------------
// Control leaves (§3.4)
// ---------------------------------------------------------------------------------------------

/// The destination word of the route to `target`: `word(address)` of an EVM contract, the
/// account id of the TON minter (§3.4).
///
/// # Panics
/// When `target` is not one of [`TARGETS`].
fn destination_word(target: SccpNetworkV1) -> [u8; 32] {
    match target {
        SccpNetworkV1::EthereumMainnet => word_address(&ETHEREUM_ADDRESS),
        SccpNetworkV1::BscMainnet => word_address(&BSC_ADDRESS),
        SccpNetworkV1::TonMainnet => TON_ACCOUNT_ID,
        other => panic!("{} has no destination word here", other.profile_key()),
    }
}

/// The target and the seven fields of a control as the rows print them. `parliament_paused`
/// is the byte of the layout, not a boolean: a negative row carries 2.
fn control_json(target: SccpNetworkV1, fields: &ControlLeafV1) -> Value {
    obj([
        ("target", text(target.profile_key())),
        ("route_revision", num(fields.route_revision.into())),
        ("control_nonce", num(fields.control_nonce)),
        ("track", num(fields.track.into())),
        ("parliament_paused", num(fields.parliament_paused.into())),
        ("fast_pause_until_ms", num(fields.fast_pause_until_ms)),
        ("certificate_id", hx(&fields.certificate_id)),
        ("effect_hash", hx(&fields.effect_hash)),
    ])
}

/// A row of `spec_examples` and of `controls`: a control Taira records for `target`, with the
/// lane, the 199-byte preimage, the two TON builders and the leaf.
///
/// # Panics
/// When Taira would not record the control, or when the three ways to the leaf disagree: the
/// leaf function, the hash of the preimage and the hash of the two builders.
fn leaf_row(target: SccpNetworkV1, fields: &ControlLeafV1) -> Value {
    let word = destination_word(target);
    let lane = lane_bytes(SccpNetworkV1::SoraTaira, target, &NETWORK_ID)
        .expect("an external target has a lane from Taira");
    let preimage = control_leaf_preimage(&NETWORK_ID, target, &word, fields)
        .expect("an external target has a preimage");
    let (b1, b2) = ton_builders(&preimage);
    let leaf = control_leaf(&NETWORK_ID, target, &word, fields)
        .unwrap_or_else(|error| panic!("Taira does not record the control: {}", error.name()));
    assert_eq!(
        leaf,
        keccak256(&[&preimage]),
        "the leaf hashes the preimage"
    );
    assert_eq!(leaf, keccak256(&[&b1, &b2]), "HASHEXT of b1 and b2");
    assert_eq!(
        preimage[CONTROL_TAG.len()..][..lane.len()],
        lane,
        "the lane follows the tag"
    );
    let mut row = control_json(target, fields);
    insert(&mut row, "destination_word", hx(&word));
    insert(&mut row, "lane_bytes", hx(&lane));
    insert(&mut row, "preimage", hx(&preimage));
    insert(&mut row, "ton_b1", hx(&b1));
    insert(&mut row, "ton_b2", hx(&b2));
    insert(&mut row, "leaf", hx(&leaf));
    row
}

/// `spec_examples`: the four rows of the §3.4 table, on the Ethereum route.
///
/// # Panics
/// When a leaf, or the preimage of nonce 2, is not the value the specification prints.
fn spec_examples() -> Vec<Value> {
    SPEC_EXAMPLES
        .iter()
        .map(|(fields, specified)| {
            let nonce = fields.control_nonce;
            let row = leaf_row(SccpNetworkV1::EthereumMainnet, fields);
            assert_eq!(
                row["leaf"],
                text(&format!("0x{specified}")),
                "control leaf nonce {nonce} differs from the specification value"
            );
            if nonce == 2 {
                assert_eq!(
                    row["preimage"],
                    text(&format!("0x{}", spec_nonce2_preimage())),
                    "the nonce 2 preimage differs from the specification"
                );
            }
            row
        })
        .collect()
}

/// `controls`: every target, two `(route_revision, control_nonce)` pairs, and for each the
/// six pause states a leaf can carry: a Parliament change to paused or not, without and with
/// a live fast pause, and a fast-pause change under either Parliament flag.
///
/// The ids are `keccak256("sccp-reference/control/certificate" ‖ tag)` and
/// `keccak256("sccp-reference/control/effect" ‖ tag)` with
/// `tag = tag(target) ‖ u8 revision ‖ track ‖ parliament_paused ‖ be64(nonce)`.
fn matrix() -> Vec<Value> {
    const STATES: [(u8, u8, u64); 6] = [
        (TRACK_PARLIAMENT, 1, 0),
        (TRACK_PARLIAMENT, 0, 0),
        (TRACK_PARLIAMENT, 1, MATRIX_EXPIRY),
        (TRACK_PARLIAMENT, 0, MATRIX_EXPIRY),
        (TRACK_FAST_PAUSE, 0, MATRIX_EXPIRY),
        (TRACK_FAST_PAUSE, 1, MATRIX_EXPIRY),
    ];
    let mut rows = Vec::new();
    for target in TARGETS {
        for (route_revision, control_nonce) in [(1_u32, 1_u64), (7, (1 << 32) + 5)] {
            for (track, parliament_paused, fast_pause_until_ms) in STATES {
                // The low byte of the revision.
                let revision = route_revision.to_le_bytes()[0];
                let id_tag = [
                    &[tag(target), revision, track, parliament_paused][..],
                    &control_nonce.to_be_bytes(),
                ]
                .concat();
                let fields = ControlLeafV1 {
                    route_revision,
                    control_nonce,
                    track,
                    parliament_paused,
                    fast_pause_until_ms,
                    certificate_id: keccak256(&[b"sccp-reference/control/certificate", &id_tag]),
                    effect_hash: keccak256(&[b"sccp-reference/control/effect", &id_tag]),
                };
                rows.push(leaf_row(target, &fields));
            }
        }
    }
    rows
}

/// What a destination of the Ethereum route answers to `applyControl` with `fields` when a
/// certified block holds `leaf`.
///
/// Taira never records the leaves of `rejected`, so no honest block holds one. The answer is
/// the one a destination gives when a committee certifies such a block all the same: the
/// block has the one leaf, its certificate is offered inline and the proof carries `fields`.
fn destination_answer(fields: &ControlLeafV1, leaf: [u8; 32]) -> &'static str {
    let mut env = Env::new();
    let item = LeafItem {
        kind: LeafKind::Control,
        leaf,
        payload: Vec::new(),
        nonce: 0,
        control: *fields,
    };
    env.block(1010, T0 + MINUTE, vec![item]);
    let mut destination = Destination::new(env.deployment()).expect("the deployment");
    let certificate = env.cert(1010).certificate.wire();
    outcome_name(&destination.apply_control(
        CertificateSourceV1::Inline(&certificate),
        &env.control_proof(1010, 0),
        T0 + 10 * MINUTE,
    ))
}

/// `rejected`: one change at a time to a control Taira records, with the error of the leaf
/// function and the answer of a destination to the unchecked leaf of the same fields.
///
/// A destination computes the leaf with its own route revision, so a leaf of revision 0 is
/// not in the tree it checks (`BadProof`); nonce 0 is never above the stored nonce
/// (`StaleControl`). Taira as the target has no lane, hence no leaf and no destination.
///
/// # Panics
/// When the leaf function does not give the error of the case, or the destination model does
/// not give its answer.
fn rejected() -> Vec<Value> {
    /// One change to the recorded control.
    type Change = fn(&mut SccpNetworkV1, &mut ControlLeafV1);
    /// The error of the leaf function, and the answer of a destination when there is a leaf.
    type Answers = (ControlLeafError, Option<&'static str>);
    const BAD_CONTROL: Answers = (ControlLeafError::BadControl, Some("BadControl"));
    const CASES: [(&str, Change, Answers); 9] = [
        ("track_0", |_, control| control.track = 0, BAD_CONTROL),
        ("track_3", |_, control| control.track = 3, BAD_CONTROL),
        (
            "parliament_paused_2",
            |_, control| control.parliament_paused = 2,
            BAD_CONTROL,
        ),
        (
            "fast_pause_track_zero_expiry",
            |_, control| {
                control.track = TRACK_FAST_PAUSE;
                control.parliament_paused = 0;
                control.fast_pause_until_ms = 0;
            },
            BAD_CONTROL,
        ),
        (
            "zero_certificate_id",
            |_, control| control.certificate_id = [0; 32],
            BAD_CONTROL,
        ),
        (
            "zero_effect_hash",
            |_, control| control.effect_hash = [0; 32],
            BAD_CONTROL,
        ),
        (
            "taira_target",
            |target, _| *target = SccpNetworkV1::SoraTaira,
            (ControlLeafError::TargetNotExternal, None),
        ),
        (
            "zero_revision",
            |_, control| control.route_revision = 0,
            (ControlLeafError::ZeroRevision, Some("BadProof")),
        ),
        (
            "zero_control_nonce",
            |_, control| control.control_nonce = 0,
            (ControlLeafError::ZeroControlNonce, Some("StaleControl")),
        ),
    ];
    let word = destination_word(SccpNetworkV1::EthereumMainnet);
    CASES
        .iter()
        .map(|(label, change, (error, destination))| {
            // The first row of the §3.4 table: a control Taira records.
            let (mut target, mut fields) = (SccpNetworkV1::EthereumMainnet, SPEC_EXAMPLES[0].0);
            change(&mut target, &mut fields);
            assert_eq!(
                control_leaf(&NETWORK_ID, target, &word, &fields),
                Err(*error),
                "{label}"
            );
            let mut row = control_json(target, &fields);
            insert(&mut row, "label", text(label));
            insert(&mut row, "error", text(error.name()));
            let answer = control_leaf_unchecked(&NETWORK_ID, target, &word, &fields)
                .ok()
                .map(|leaf| {
                    insert(&mut row, "unchecked_leaf", hx(&leaf));
                    destination_answer(&fields, leaf)
                });
            assert_eq!(answer, *destination, "{label}: the destination model");
            insert(&mut row, "destination", answer.map_or(Value::Null, text));
            row
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The environment of the scenarios
// ---------------------------------------------------------------------------------------------

/// The fields of a control of the scenarios, with the ids of `id`:
/// `certificate_id = keccak256("sccp-reference/certificate" ‖ word(id))` and
/// `effect_hash = keccak256("sccp-reference/effect" ‖ word(id))`. The simulator that hashes
/// the leaf sets the route revision.
fn control_fields(
    control_nonce: u64,
    track: u8,
    parliament_paused: u8,
    fast_pause_until_ms: u64,
    id: u64,
) -> ControlLeafV1 {
    let id = word_u64(id);
    ControlLeafV1 {
        route_revision: 0,
        control_nonce,
        track,
        parliament_paused,
        fast_pause_until_ms,
        certificate_id: keccak256(&[b"sccp-reference/certificate", &id]),
        effect_hash: keccak256(&[b"sccp-reference/effect", &id]),
    }
}

/// One Taira route to the EVM destination at `0x22…22`, with generation 5 (`K0`, test keys
/// 40 to 43) pinned at height 1000 and time `T0`, and the certificate pool of the file.
struct Env {
    k0: Committee,
    sim: TairaSim,
    pool: Rc<RefCell<CertificatePool>>,
}

impl Env {
    fn new() -> Self {
        let k0 = Committee::new("K0", 40..44);
        let mut sim = TairaSim::new(
            NETWORK_ID,
            INSTANCE,
            SccpNetworkV1::EthereumMainnet,
            destination_word(SccpNetworkV1::EthereumMainnet),
        );
        sim.start(PIN_GENERATION, k0.clone(), PIN_START, T0, VALIDITY);
        Self {
            k0,
            sim,
            pool: Rc::default(),
        }
    }

    /// The destination of the route: `K0` pinned as generation 5 until `T0 + VALIDITY`. The
    /// deployment carries the pinned keys for reference; an EVM destination stores none.
    fn deployment(&self) -> DeploymentV1 {
        DeploymentV1 {
            flavor: DestinationFlavor::Evm,
            taira_network_id: NETWORK_ID,
            consensus_instance: INSTANCE,
            network: SccpNetworkV1::EthereumMainnet,
            destination_word: destination_word(SccpNetworkV1::EthereumMainnet),
            route_revision: 1,
            max_wrapped_supply: SUPPLY_CAP,
            pin_generation: PIN_GENERATION,
            pin_root: self.k0.root(),
            pin_start_height: PIN_START,
            pin_until_ms: T0 + VALIDITY,
            pin_keys: Some(self.k0.keys()),
        }
    }

    /// A scenario on a fresh destination of the route. Every call must give the outcome its
    /// author wrote.
    fn scenario(&self, name: &str, description: &str) -> Run {
        Run(Scenario::new(
            name,
            description,
            self.deployment(),
            &self.pool,
            true,
        ))
    }

    /// A control of the route that Taira records ([`control_fields`]).
    fn control(
        &self,
        control_nonce: u64,
        track: u8,
        parliament_paused: u8,
        fast_pause_until_ms: u64,
        id: u64,
    ) -> LeafItem {
        let fields = control_fields(
            control_nonce,
            track,
            parliament_paused,
            fast_pause_until_ms,
            id,
        );
        self.sim.control(&fields, true)
    }

    /// A transfer of `amount` to [`RECIPIENT`].
    fn transfer(&self, nonce: u64, amount: u128, deadline_ms: u64) -> LeafItem {
        self.sim.transfer(nonce, amount, deadline_ms, &RECIPIENT)
    }

    /// The block at `height` with `leaves`, certified by the pinned generation.
    fn block(&mut self, height: u64, timestamp_ms: u64, leaves: Vec<LeafItem>) {
        self.sim.block(height, timestamp_ms, leaves, None, None);
    }

    /// The fields of `X_height`.
    fn header(&self, height: u64) -> &SccpFinalityHeaderFieldsV1 {
        &self.sim.blocks[&height].header
    }

    /// The 221 bytes of `X_height`: what a checkpoint reference carries.
    fn x(&self, height: u64) -> Vec<u8> {
        self.sim.blocks[&height].x()
    }

    /// The certificate of the block at `height` by `K0`, labelled `X_<height>`.
    fn cert(&self, height: u64) -> Submission {
        Submission::new(
            self.sim
                .certify(&self.x(height), &self.k0, &CertifyOptions::default()),
            &format!("X_{height}"),
            &self.k0.name,
        )
    }

    /// The proof of the control at `leaf_index` of the block at `height`, under its own
    /// header.
    fn control_proof(&self, height: u64, leaf_index: u32) -> ControlProofV1 {
        self.sim
            .control_proof(height, leaf_index, self.header(height))
    }

    /// The proof of the transfer at `leaf_index` of the block at `height`, under its own
    /// header.
    fn message_proof(&self, height: u64, leaf_index: u32) -> MessageProofV1 {
        self.sim
            .message_proof(height, leaf_index, self.header(height))
    }
}

/// A scenario being recorded. Every call names the outcome its author expects, which the
/// strict recorder checks, so the result of a call is not read again.
struct Run(Scenario);

impl Run {
    fn submit(&mut self, certificates: &[Submission], now_ms: u64, expect: &str) {
        let _ = self.0.submit(certificates, now_ms, Some(expect));
    }

    fn finalize(&mut self, source: Source<'_>, proof: &MessageProofV1, now_ms: u64, expect: &str) {
        let _ = self.0.finalize(source, proof, now_ms, Some(expect));
    }

    fn apply_control(
        &mut self,
        source: Source<'_>,
        proof: &ControlProofV1,
        now_ms: u64,
        expect: &str,
    ) {
        let _ = self.0.apply_control(source, proof, now_ms, Some(expect));
    }

    fn void_expired(
        &mut self,
        nonce: u64,
        source: Source<'_>,
        proof: &MessageProofV1,
        now_ms: u64,
        expect: &str,
    ) {
        let _ = self
            .0
            .void_expired(nonce, source, proof, now_ms, Some(expect));
    }

    fn views(&mut self, now_ms: u64) {
        self.0.views(now_ms);
    }

    /// `fastPauseUntilMs` of the destination.
    fn fast_pause_until_ms(&self) -> u64 {
        self.0.destination.state().fast_pause_until_ms
    }
}

// ---------------------------------------------------------------------------------------------
// The Taira blocks of the scenarios
// ---------------------------------------------------------------------------------------------

/// Produce the blocks the scenarios read, heights and times strictly increasing. One chain
/// serves every scenario, so its history grows from block to block.
///
/// The blocks are synthetic destination inputs: every scenario starts from a fresh
/// destination, and the control nonces of a block are chosen for the scenario that reads it,
/// so they do not follow Taira's dense per-revision sequence (§4.14.6 step 1).
fn produce_blocks(env: &mut Env) {
    let fast = T0 + 2 * HOUR;
    let (parliament, fast_pause) = (TRACK_PARLIAMENT, TRACK_FAST_PAUSE);
    env.block(1010, T0 + MINUTE, vec![env.control(1, parliament, 1, 0, 1)]);
    env.block(
        1020,
        T0 + 2 * MINUTE,
        vec![
            env.control(2, fast_pause, 1, fast, 2),
            env.transfer(0, AMOUNT, T0 + DAY),
        ],
    );
    env.block(
        1030,
        T0 + 3 * MINUTE,
        vec![
            env.control(1, fast_pause, 0, fast, 11),
            env.control(2, parliament, 1, fast, 12),
        ],
    );
    env.block(
        1040,
        T0 + 4 * MINUTE,
        vec![
            env.control(1, fast_pause, 0, T0 + HOUR, 21),
            env.transfer(1, 2 * AMOUNT, T0 + DAY),
        ],
    );
    env.block(
        1050,
        T0 + 5 * MINUTE,
        vec![
            env.control(3, parliament, 1, 0, 31),
            env.control(2, parliament, 0, 0, 32),
            env.control(5, parliament, 0, 0, 35),
        ],
    );
    env.block(
        1060,
        T0 + 6 * MINUTE,
        vec![env.control(1, fast_pause, 0, T0 + 6 * MINUTE + 40 * DAY, 41)],
    );
    env.block(
        1070,
        T0 + 7 * MINUTE,
        vec![
            env.control(1, fast_pause, 0, fast, 51),
            env.transfer(2, 3 * AMOUNT, T0 + DAY),
            env.transfer(3, AMOUNT, T0 + 30 * MINUTE),
        ],
    );
    env.block(
        1080,
        T0 + 8 * MINUTE,
        vec![
            env.control(1, parliament, 1, 0, 61),
            env.control(2, parliament, 0, 0, 62),
        ],
    );
    env.block(1090, T0 + 9 * MINUTE, foreign_and_malformed_leaves(env));
    env.block(1100, T0 + 10 * MINUTE, vec![]);
    env.block(
        1110,
        T0 + 11 * MINUTE,
        vec![
            env.control(1, fast_pause, 0, SUB_SECOND_EXPIRY, 81),
            env.transfer(5, AMOUNT, T0 + DAY),
        ],
    );
}

/// The leaves of block 1090: four Parliament pauses that are valid controls of another
/// route (another target network, another Taira network, another route revision, another
/// destination word), a leaf of the route's own fields with `track = 3`, which Taira would
/// not record, and a transfer.
fn foreign_and_malformed_leaves(env: &Env) -> Vec<LeafItem> {
    let ethereum = SccpNetworkV1::EthereumMainnet;
    let word = destination_word(ethereum);
    let pause = |id| control_fields(1, TRACK_PARLIAMENT, 1, 0, id);
    let bsc = TairaSim::new(NETWORK_ID, INSTANCE, SccpNetworkV1::BscMainnet, word);
    let other_network = TairaSim::new([0x12; 32], INSTANCE, ethereum, word);
    let mut other_revision = TairaSim::new(NETWORK_ID, INSTANCE, ethereum, word);
    other_revision.route_revision = 2;
    let other_destination =
        TairaSim::new(NETWORK_ID, INSTANCE, ethereum, word_address(&[0x23; 20]));
    vec![
        bsc.control(&pause(71), true),
        other_network.control(&pause(72), true),
        other_revision.control(&pause(73), true),
        other_destination.control(&pause(75), true),
        env.sim.control(&control_fields(1, 3, 0, 0, 74), false),
        env.transfer(4, AMOUNT, T0 + DAY),
    ]
}

// ---------------------------------------------------------------------------------------------
// The scenarios (§5.1.6)
// ---------------------------------------------------------------------------------------------

/// Every scenario in file order. The certificate pool numbers certificates in order of first
/// use, so a new scenario goes at the end: `fast_pause_sub_second_expiry` follows the others
/// for that reason.
const SCENARIOS: [fn(&Env) -> Run; 10] = [
    parliament_pause_then_fast_pause_then_lapse,
    fast_pause_then_parliament_pause_then_lapse,
    track2_leaf_after_expiry,
    stale_equal_and_gap_nonces,
    max_fast_pause_clamp,
    fast_pause_local_expiry,
    pause_then_resume,
    historical_control_proof,
    foreign_and_malformed_controls,
    fast_pause_sub_second_expiry,
];

/// The blocks and the scenarios over them, in file order.
fn destination_effects() -> (Env, Vec<Scenario>) {
    let mut env = Env::new();
    produce_blocks(&mut env);
    let scenarios = SCENARIOS.iter().map(|scenario| scenario(&env).0).collect();
    (env, scenarios)
}

/// CX-3: the Parliament pause survives the lapse of a later fast pause.
fn parliament_pause_then_fast_pause_then_lapse(env: &Env) -> Run {
    let mut sc = env.scenario(
        "parliament_pause_then_fast_pause_then_lapse",
        "CX-3: a Parliament pause, then a fast pause, then the lapse; the Parliament pause \
         stays in force",
    );
    sc.apply_control(
        Source::Inline(&env.cert(1010)),
        &env.control_proof(1010, 0),
        T0 + 10 * MINUTE,
        "ok",
    );
    sc.apply_control(
        Source::Inline(&env.cert(1020)),
        &env.control_proof(1020, 0),
        T0 + 20 * MINUTE,
        "ok",
    );
    sc.views(T0 + HOUR);
    sc.views(T0 + 3 * HOUR);
    sc.finalize(
        Source::Checkpoint(&env.x(1020)),
        &env.message_proof(1020, 1),
        T0 + 3 * HOUR,
        "MintingIsPaused",
    );
    sc
}

/// CX-3 in the other order: a Parliament leaf carries the live fast pause with it.
fn fast_pause_then_parliament_pause_then_lapse(env: &Env) -> Run {
    let mut sc = env.scenario(
        "fast_pause_then_parliament_pause_then_lapse",
        "CX-3: the fast pause, then a Parliament pause whose leaf carries the live fast \
         pause; after the lapse the Parliament pause remains",
    );
    sc.apply_control(
        Source::Inline(&env.cert(1030)),
        &env.control_proof(1030, 0),
        T0 + 10 * MINUTE,
        "ok",
    );
    sc.apply_control(
        Source::Checkpoint(&env.x(1030)),
        &env.control_proof(1030, 1),
        T0 + 20 * MINUTE,
        "ok",
    );
    sc.views(T0 + 3 * HOUR);
    sc
}

/// CX-4: a fast-pause leaf that arrives after its expiry.
fn track2_leaf_after_expiry(env: &Env) -> Run {
    let mut sc = env.scenario(
        "track2_leaf_after_expiry",
        "CX-4: a fast-pause leaf delivered after its expiry consumes its nonce and does not \
         pause",
    );
    sc.apply_control(
        Source::Inline(&env.cert(1040)),
        &env.control_proof(1040, 0),
        T0 + 2 * HOUR,
        "ok",
    );
    sc.views(T0 + 2 * HOUR);
    sc.finalize(
        Source::Checkpoint(&env.x(1040)),
        &env.message_proof(1040, 1),
        T0 + 2 * HOUR,
        "ok",
    );
    sc
}

/// The nonce rule: only a nonce above the stored one is applied, and gaps are allowed.
fn stale_equal_and_gap_nonces(env: &Env) -> Run {
    let mut sc = env.scenario(
        "stale_equal_and_gap_nonces",
        "newest nonce wins: 3 applied, 2 and 3 stale, 5 accepted across the gap",
    );
    sc.apply_control(
        Source::Inline(&env.cert(1050)),
        &env.control_proof(1050, 0),
        T0 + 10 * MINUTE,
        "ok",
    );
    let stored = env.x(1050);
    for (leaf_index, minute, expect) in [
        (1, 11, "StaleControl"),
        (0, 12, "StaleControl"),
        (2, 13, "ok"),
    ] {
        sc.apply_control(
            Source::Checkpoint(&stored),
            &env.control_proof(1050, leaf_index),
            T0 + minute * MINUTE,
            expect,
        );
    }
    sc
}

/// The clamp of §5.1.6 step 5.
fn max_fast_pause_clamp(env: &Env) -> Run {
    let mut sc = env.scenario(
        "max_fast_pause_clamp",
        "fast_pause_until_ms 40 days ahead is clamped to now + MAX_FAST_PAUSE_MS",
    );
    let now = T0 + 10 * MINUTE;
    sc.apply_control(
        Source::Inline(&env.cert(1060)),
        &env.control_proof(1060, 0),
        now,
        "ok",
    );
    assert_eq!(sc.fast_pause_until_ms(), now + MAX_FAST_PAUSE_MS);
    // The last clock value before the expiry: paused.
    sc.views(now + MAX_FAST_PAUSE_MS - SECOND);
    // `now_ms = fastPauseUntilMs`: not paused.
    sc.views(now + MAX_FAST_PAUSE_MS);
    sc
}

/// A fast pause ends by the destination clock alone, and blocks minting only.
fn fast_pause_local_expiry(env: &Env) -> Run {
    let mut sc = env.scenario(
        "fast_pause_local_expiry",
        "minting is paused while now < fastPauseUntilMs and resumes at the expiry with no \
         relay; voids and checkpoints work while paused",
    );
    let stored = env.x(1070);
    let (mint, void) = (env.message_proof(1070, 1), env.message_proof(1070, 2));
    sc.apply_control(
        Source::Inline(&env.cert(1070)),
        &env.control_proof(1070, 0),
        T0 + 10 * MINUTE,
        "ok",
    );
    sc.finalize(
        Source::Checkpoint(&stored),
        &mint,
        T0 + 20 * MINUTE,
        "MintingIsPaused",
    );
    sc.submit(&[env.cert(1080)], T0 + 20 * MINUTE, "ok");
    // Transfer 3 has `deadline_ms = T0 + 30 min`: at that clock value a void is still early.
    sc.void_expired(
        3,
        Source::Checkpoint(&stored),
        &void,
        T0 + 30 * MINUTE,
        "DeadlineNotReached",
    );
    sc.void_expired(3, Source::Checkpoint(&stored), &void, T0 + HOUR, "ok");
    // `fastPauseUntilMs = T0 + 2 h`: paused at the last clock value before it, minting again
    // at it.
    sc.finalize(
        Source::Checkpoint(&stored),
        &mint,
        T0 + 2 * HOUR - SECOND,
        "MintingIsPaused",
    );
    sc.finalize(Source::Checkpoint(&stored), &mint, T0 + 2 * HOUR, "ok");
    sc
}

/// A pause and its resume from one block.
fn pause_then_resume(env: &Env) -> Run {
    let mut sc = env.scenario(
        "pause_then_resume",
        "a Parliament pause (nonce 1) then a resume (nonce 2) in one block",
    );
    sc.apply_control(
        Source::Inline(&env.cert(1080)),
        &env.control_proof(1080, 0),
        T0 + 10 * MINUTE,
        "ok",
    );
    sc.apply_control(
        Source::Checkpoint(&env.x(1080)),
        &env.control_proof(1080, 1),
        T0 + 11 * MINUTE,
        "ok",
    );
    sc.views(T0 + 11 * MINUTE);
    sc
}

/// A control of an older block under a later certificate (§5.1.5 block reference).
fn historical_control_proof(env: &Env) -> Run {
    let mut sc = env.scenario(
        "historical_control_proof",
        "a control of block 1010 proven through the history path of X_1100",
    );
    sc.apply_control(
        Source::Inline(&env.cert(1100)),
        &env.sim.control_proof(1010, 0, env.header(1100)),
        T0 + 15 * MINUTE,
        "ok",
    );
    sc
}

/// What `applyControl` refuses: the leaves of block 1090, an unknown checkpoint and an
/// expired destination.
fn foreign_and_malformed_controls(env: &Env) -> Run {
    let mut sc = env.scenario(
        "foreign_and_malformed_controls",
        "leaves of another network, Taira network, revision or destination, a transfer leaf \
         offered as a control, and a recorded leaf violating a constraint",
    );
    let now = T0 + 15 * MINUTE;
    let certificate = env.cert(1090);
    let inline = Source::Inline(&certificate);
    for leaf_index in 0..4 {
        sc.apply_control(
            inline,
            &env.control_proof(1090, leaf_index),
            now,
            "BadProof",
        );
    }
    // The transfer leaf with its own path, offered as the two ids of a Parliament pause.
    let transfer = env.message_proof(1090, 5);
    let leaf = env.sim.blocks[&1090].leaves[5].leaf;
    let as_control = ControlProofV1 {
        control_nonce: 1,
        track: TRACK_PARLIAMENT,
        parliament_paused: 1,
        fast_pause_until_ms: 0,
        certificate_id: leaf,
        effect_hash: leaf,
        leaf_index: transfer.leaf_index,
        path: transfer.path,
        block: transfer.block,
    };
    sc.apply_control(inline, &as_control, now, "BadProof");
    sc.apply_control(inline, &env.control_proof(1090, 4), now, "BadControl");
    sc.apply_control(
        Source::Checkpoint(&env.x(1080)),
        &env.control_proof(1080, 0),
        now,
        "UnknownCheckpoint",
    );
    sc.apply_control(
        Source::Inline(&env.cert(1010)),
        &env.control_proof(1010, 0),
        T0 + VALIDITY + SECOND,
        "CommitteeNotAccepted",
    );
    sc
}

/// A fast-pause expiry between two destination clock values.
fn fast_pause_sub_second_expiry(env: &Env) -> Run {
    let mut sc = env.scenario(
        "fast_pause_sub_second_expiry",
        "a fast pause whose expiry ends in 001 ms: the whole-second destination clock is \
         paused at the last clock value below fastPauseUntilMs (1 ms earlier) and mints at \
         the next one (999 ms later)",
    );
    let stored = env.x(1110);
    let mint = env.message_proof(1110, 1);
    sc.apply_control(
        Source::Inline(&env.cert(1110)),
        &env.control_proof(1110, 0),
        T0 + 20 * MINUTE,
        "ok",
    );
    assert_eq!(sc.fast_pause_until_ms(), SUB_SECOND_EXPIRY);
    assert_eq!(SUB_SECOND_EXPIRY % SECOND, 1);
    for (now, expect) in [
        (SUB_SECOND_EXPIRY - 1, "MintingIsPaused"),
        (SUB_SECOND_EXPIRY + 999, "ok"),
    ] {
        sc.views(now);
        sc.finalize(Source::Checkpoint(&stored), &mint, now, expect);
    }
    sc
}

// ---------------------------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------------------------

/// The complete `control_v1.json` document.
///
/// # Panics
/// When a value differs from the one the specification pins: a leaf of the §3.4 table, the
/// nonce-2 preimage, the `SccpControlApplied` topic or the fast-pause bound.
fn control_document() -> Value {
    let topic = keccak256(&[EVENT_CONTROL_APPLIED.as_bytes()]);
    assert_eq!(
        to_hex(&topic),
        SPEC_TOPIC,
        "the SccpControlApplied topic differs from the specification"
    );
    assert_eq!(topic, TOPIC_CONTROL_APPLIED);
    assert_eq!(MAX_FAST_PAUSE_MS, 30 * DAY, "§3.9");
    let (env, scenarios) = destination_effects();
    let mut destination_words = obj([]);
    for target in TARGETS {
        insert(
            &mut destination_words,
            target.profile_key(),
            hx(&destination_word(target)),
        );
    }
    obj([
        ("schema", text("iroha.sccp.control.v1")),
        (
            "spec",
            text("specs/sccp.md §3.4, §4.14.6, §5.1.6 (revision 5)"),
        ),
        ("generator", text(REFERENCE_GENERATORS)),
        (
            "conventions",
            text(&format!(
                "byte strings are 0x-prefixed lowercase hex; `preimage` is the \
                 {CONTROL_LEAF_PREIMAGE_BYTES}-byte control-leaf preimage and \
                 `ton_b1`/`ton_b2` its two TON HASHEXT builders ({CONTROL_TON_B1_BYTES} + \
                 {CONTROL_TON_B2_BYTES} bytes); scenario rows follow \
                 committee_transitions_v1.json. {DESTINATION_CLOCK_CONVENTION}; \
                 {SCENARIO_CLOCK_CONVENTION}. The Taira blocks of `destination_effects` are \
                 synthetic destination inputs: every scenario starts from a fresh \
                 destination, and the control nonces of a block are chosen for that scenario, \
                 so they need not follow Taira's dense per-revision sequence (§4.14.6 step 1). \
                 `rejected[].error` is the refusal of the Rust and Python reference when Taira \
                 records a control: BadControl is the §3.4 constraint error, and \
                 TargetNotExternal, ZeroRevision and ZeroControlNonce are reference labels for \
                 the recording rules of §4.14.6 (a route targets an external network, \
                 revisions and control nonces start at 1), which no contract reports. \
                 `rejected[].destination` is what the destination model answers when such a \
                 leaf is certified anyway (null: the leaf does not exist). Row \
                 parliament_paused_2 cannot reach a contract through its typed interface (`bool \
                 parliamentPaused` on EVM, where the ABI decoder refuses a dirty word, and \
                 `Bool` on TON), so no contract harness replays it"
            )),
        ),
        ("taira_network_id", hx(&NETWORK_ID)),
        ("consensus_instance", hx(&INSTANCE)),
        ("destination_words", destination_words),
        ("event_signature", text(EVENT_CONTROL_APPLIED)),
        ("topic_control_applied", hx(&topic)),
        ("max_fast_pause_ms", num(MAX_FAST_PAUSE_MS)),
        ("spec_examples", list(spec_examples())),
        ("controls", list(matrix())),
        ("rejected", list(rejected())),
        ("committees", obj([(&*env.k0.name, env.k0.as_json())])),
        ("certificates", env.pool.borrow().as_json()),
        (
            "destination_effects",
            list(scenarios.iter().map(Scenario::as_json)),
        ),
        (
            "todo",
            list([text(
                "TODO(reference generators): add TON destination-effect rows to this file. \
                 The Acton harness installs its minter at 0:35…35, and \
                 committee_transitions_v1.json already carries TON control rows for that destination word",
            )]),
        ),
    ])
}

/// The document, built once for the tests that read it.
static DOCUMENT: LazyLock<Value> = LazyLock::new(control_document);

/// The rows of the array `key` of the document.
fn rows(key: &str) -> &'static [Value] {
    DOCUMENT[key]
        .as_array()
        .unwrap_or_else(|| panic!("the document lists `{key}`"))
}

/// The number at `key` of `row`.
fn number_of(row: &Value, key: &str) -> u64 {
    row[key]
        .as_u64()
        .unwrap_or_else(|| panic!("`{key}` is a number"))
}

/// The bytes of the byte string at `key` of `row`.
fn bytes_of(row: &Value, key: &str) -> Vec<u8> {
    let digits = row[key]
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .unwrap_or_else(|| panic!("`{key}` is a 0x byte string"));
    unhex(digits)
}

/// The 32 bytes at `key` of `row`.
fn word_of(row: &Value, key: &str) -> [u8; 32] {
    bytes_of(row, key)
        .try_into()
        .unwrap_or_else(|_| panic!("`{key}` is 32 bytes"))
}

/// The target and the fields of a row, read back from what [`control_json`] prints.
fn control_of(row: &Value) -> (SccpNetworkV1, ControlLeafV1) {
    let byte = |key| u8::try_from(number_of(row, key)).expect("a byte of the layout");
    let target = row["target"]
        .as_str()
        .and_then(SccpNetworkV1::from_profile_key)
        .expect("a profile key");
    let fields = ControlLeafV1 {
        route_revision: u32::try_from(number_of(row, "route_revision")).expect("a u32"),
        control_nonce: number_of(row, "control_nonce"),
        track: byte("track"),
        parliament_paused: byte("parliament_paused"),
        fast_pause_until_ms: number_of(row, "fast_pause_until_ms"),
        certificate_id: word_of(row, "certificate_id"),
        effect_hash: word_of(row, "effect_hash"),
    };
    (target, fields)
}

/// A recorded state without the two readings that depend on the clock: `live` and
/// `pause.effective`. What is left is what the destination stores.
fn stored_state(state: &Value) -> Value {
    let mut state = state.clone();
    if let Some(fields) = state.as_object_mut() {
        fields.remove("live");
    }
    if let Some(pause) = state.get_mut("pause").and_then(Value::as_object_mut) {
        pause.remove("effective");
    }
    state
}

// ---------------------------------------------------------------------------------------------
// Drift check and regeneration
// ---------------------------------------------------------------------------------------------

#[test]
fn reference_control_v1_matches_committed_fixture() {
    assert_matches_committed(CONTROL, &DOCUMENT, REGENERATE_COMMAND);
}

#[test]
#[ignore = "rewrites fixtures/sccp/control_v1.json; run only after a reviewed change"]
fn regenerate_control_v1() {
    write_fixture(CONTROL, &DOCUMENT);
}

// ---------------------------------------------------------------------------------------------
// The regenerated document: leaves
// ---------------------------------------------------------------------------------------------

/// `spec_examples` is the §3.4 table: four leaves of the Ethereum route at revision 1 with
/// the leaves the specification prints, and the preimage of nonce 2 as it spells it out.
#[test]
fn spec_examples_are_the_table_of_the_specification() {
    let examples = rows("spec_examples");
    assert_eq!(examples.len(), SPEC_EXAMPLES.len());
    for ((nonce, row), (fields, specified)) in (1_u64..).zip(examples).zip(&SPEC_EXAMPLES) {
        assert_eq!(
            control_of(row),
            (SccpNetworkV1::EthereumMainnet, *fields),
            "nonce {nonce}"
        );
        assert_eq!((fields.route_revision, fields.control_nonce), (1, nonce));
        assert_eq!(to_hex(&bytes_of(row, "leaf")), *specified, "nonce {nonce}");
        assert_eq!(
            bytes_of(row, "destination_word"),
            word_address(&ETHEREUM_ADDRESS)
        );
    }
    let spelled = spec_nonce2_preimage();
    assert_eq!(spelled.len(), 2 * CONTROL_LEAF_PREIMAGE_BYTES);
    assert_eq!(to_hex(&bytes_of(&examples[1], "preimage")), spelled);
    // The spelled preimage hashes to the leaf of the table: the two pinned values agree.
    assert_eq!(
        to_hex(&keccak256(&[&unhex(&spelled)])),
        SPEC_EXAMPLES[1].1,
        "§3.4"
    );
    // The table covers both tracks, both Parliament flags and both kinds of expiry.
    let covered: BTreeSet<_> = SPEC_EXAMPLES
        .iter()
        .map(|(fields, _)| {
            (
                fields.track,
                fields.parliament_paused,
                fields.fast_pause_until_ms != 0,
            )
        })
        .collect();
    assert_eq!(
        covered,
        BTreeSet::from([(1, 0, false), (1, 1, false), (1, 1, true), (2, 0, true)])
    );
}

/// `controls` holds, for every target and both revisions, the six pause states of the
/// matrix; every row is the leaf of its printed fields, with a preimage of 199 bytes that
/// the two TON builders split at 125.
#[test]
fn controls_cover_every_target_track_and_pause_value() {
    let controls = rows("controls");
    assert_eq!(controls.len(), TARGETS.len() * 2 * 6);
    let mut leaves = BTreeSet::new();
    let mut covered = BTreeSet::new();
    for row in controls {
        let (target, fields) = control_of(row);
        let word = word_of(row, "destination_word");
        assert_eq!(word, destination_word(target));
        let preimage = bytes_of(row, "preimage");
        let (b1, b2) = (bytes_of(row, "ton_b1"), bytes_of(row, "ton_b2"));
        assert_eq!(preimage.len(), CONTROL_LEAF_PREIMAGE_BYTES);
        assert_eq!(
            (b1.len(), b2.len()),
            (CONTROL_TON_B1_BYTES, CONTROL_TON_B2_BYTES)
        );
        assert_eq!([&b1[..], &b2[..]].concat(), preimage);
        // `b2` starts at the track: the first builder ends with the nonce.
        assert_eq!(b2[..2], [fields.track, fields.parliament_paused]);
        assert_eq!(b1[b1.len() - 8..], fields.control_nonce.to_be_bytes());
        // The lane is `0x40 ‖ NetworkId ‖ tag(target) ‖ identity_word(target)`.
        let lane = bytes_of(row, "lane_bytes");
        assert_eq!(lane.len(), 66);
        assert_eq!((lane[0], lane[33]), (0x40, tag(target)));
        assert_eq!(lane[1..33], NETWORK_ID);
        assert_eq!(preimage[..15], *b"SCCP/CONTROL/V1");
        assert_eq!(preimage[15..81], lane[..]);
        assert_eq!(preimage[81..113], word);
        let leaf = control_leaf(&NETWORK_ID, target, &word, &fields).expect("a recorded leaf");
        assert_eq!(word_of(row, "leaf"), leaf);
        assert_eq!(leaf, keccak256(&[&preimage]));
        assert!(leaves.insert(leaf), "every row has its own leaf");
        // The two ids of a row are hashes of its tag under two labels.
        assert_ne!(fields.certificate_id, fields.effect_hash);
        covered.insert((
            tag(target),
            fields.route_revision,
            fields.control_nonce,
            fields.track,
            fields.parliament_paused,
            fields.fast_pause_until_ms,
        ));
    }
    assert_eq!(covered.len(), controls.len());
    for target in TARGETS {
        for (revision, nonce) in [(1, 1), (7, (1 << 32) + 5)] {
            for (track, paused, until) in [
                (1, 1, 0),
                (1, 0, 0),
                (1, 1, MATRIX_EXPIRY),
                (1, 0, MATRIX_EXPIRY),
                (2, 0, MATRIX_EXPIRY),
                (2, 1, MATRIX_EXPIRY),
            ] {
                let state = (tag(target), revision, nonce, track, paused, until);
                assert!(covered.contains(&state), "no row for {state:?}");
            }
        }
    }
    // The destination words the rows use are the ones the document names.
    let words = DOCUMENT["destination_words"]
        .as_object()
        .expect("destination_words");
    assert_eq!(words.len(), TARGETS.len());
    for target in TARGETS {
        assert_eq!(
            words[target.profile_key()],
            hx(&destination_word(target)),
            "{}",
            target.profile_key()
        );
    }
    assert_eq!(destination_word(TARGETS[0])[..12], [0; 12]);
    assert_eq!(destination_word(TARGETS[2]), TON_ACCOUNT_ID);
}

#[test]
#[should_panic(expected = "sora-taira has no destination word here")]
fn destination_word_needs_a_target_of_the_file() {
    let _ = destination_word(SccpNetworkV1::SoraTaira);
}

/// A leaf row is a row of a control Taira records: other fields fail the build.
#[test]
#[should_panic(expected = "Taira does not record the control: BadControl")]
fn leaf_row_refuses_fields_taira_does_not_record() {
    let mut fields = SPEC_EXAMPLES[0].0;
    fields.track = 0;
    let _ = leaf_row(SccpNetworkV1::EthereumMainnet, &fields);
}

/// The printed form of a control reads back to the same target and fields, including a
/// `parliament_paused` byte that is no boolean.
#[test]
fn control_rows_read_back_their_fields() {
    let mut fields = SPEC_EXAMPLES[1].0;
    fields.parliament_paused = 2;
    fields.route_revision = 7;
    for target in [SccpNetworkV1::SoraTaira, SccpNetworkV1::TonMainnet] {
        let row = control_json(target, &fields);
        assert_eq!(control_of(&row), (target, fields));
        assert_eq!(row["parliament_paused"], num(2));
        assert_eq!(number_of(&row, "fast_pause_until_ms"), SPEC_EXPIRY);
        assert_eq!(word_of(&row, "effect_hash"), [0x66; 32]);
    }
    let row = leaf_row(SccpNetworkV1::BscMainnet, &SPEC_EXAMPLES[0].0);
    assert_eq!(bytes_of(&row, "ton_b2").len(), CONTROL_TON_B2_BYTES);
    assert_eq!(
        bytes_of(&row, "destination_word"),
        word_address(&BSC_ADDRESS)
    );
}

/// `rejected` holds every constraint negative of §3.4 and the three recording rules, each
/// breaking one rule of a control Taira records. Each row names the error of the leaf
/// function for its printed fields; a row with a lane carries the unchecked leaf and the
/// answer of a destination, the Taira target neither.
#[test]
fn rejected_rows_carry_the_taira_error_and_the_destination_answer() {
    // Every row with the printed fields in which it differs from the recorded control.
    const CHANGES: [(&str, &[&str]); 9] = [
        ("track_0", &["track"]),
        ("track_3", &["track"]),
        ("parliament_paused_2", &["parliament_paused"]),
        (
            "fast_pause_track_zero_expiry",
            &["parliament_paused", "track"],
        ),
        ("zero_certificate_id", &["certificate_id"]),
        ("zero_effect_hash", &["effect_hash"]),
        ("taira_target", &["target"]),
        ("zero_revision", &["route_revision"]),
        ("zero_control_nonce", &["control_nonce"]),
    ];
    let rejected = rows("rejected");
    assert_eq!(rejected.len(), CHANGES.len());
    let word = destination_word(SccpNetworkV1::EthereumMainnet);
    let recorded = control_json(SccpNetworkV1::EthereumMainnet, &SPEC_EXAMPLES[0].0);
    let recorded = recorded.as_object().expect("the printed fields");
    let mut answers = BTreeSet::new();
    for (row, (label, changes)) in rejected.iter().zip(CHANGES) {
        assert_eq!(row["label"], text(label));
        let (target, fields) = control_of(row);
        let error = control_leaf(&NETWORK_ID, target, &word, &fields)
            .expect_err("Taira does not record the fields");
        assert_eq!(row["error"], text(error.name()), "{label}");
        let changed: Vec<&str> = recorded
            .iter()
            .filter(|(key, value)| row[key.as_str()] != **value)
            .map(|(key, _)| key.as_str())
            .collect();
        assert_eq!(changed, changes, "{label}");
        let constraints = check_control_constraints(&fields);
        assert_eq!(
            constraints.is_err(),
            error == ControlLeafError::BadControl,
            "{label}"
        );
        let unchecked = control_leaf_unchecked(&NETWORK_ID, target, &word, &fields);
        match unchecked {
            Ok(leaf) => {
                assert_eq!(word_of(row, "unchecked_leaf"), leaf, "{label}");
                let answer = row["destination"].as_str().expect("an answer");
                assert_eq!(answer, destination_answer(&fields, leaf), "{label}");
                answers.insert((error.name(), answer));
            }
            Err(error) => {
                assert_eq!(error, ControlLeafError::TargetNotExternal, "{label}");
                assert_eq!(target, SccpNetworkV1::SoraTaira, "{label}");
                assert!(row.get("unchecked_leaf").is_none(), "{label}");
                assert_eq!(row["destination"], Value::Null, "{label}");
            }
        }
    }
    assert_eq!(
        answers,
        BTreeSet::from([
            ("BadControl", "BadControl"),
            ("ZeroControlNonce", "StaleControl"),
            ("ZeroRevision", "BadProof"),
        ])
    );
}

/// The harness of the `destination` column applies a control Taira records, so a refusal in
/// the column comes from the fields of its row. A leaf that is not the leaf of the offered
/// fields is no leaf of the block.
#[test]
fn destination_answer_applies_a_recorded_leaf() {
    let word = destination_word(SccpNetworkV1::EthereumMainnet);
    for (fields, _) in &SPEC_EXAMPLES {
        let leaf = control_leaf(&NETWORK_ID, SccpNetworkV1::EthereumMainnet, &word, fields)
            .expect("a recorded leaf");
        assert_eq!(
            destination_answer(fields, leaf),
            "ok",
            "nonce {}",
            fields.control_nonce
        );
    }
    let (first, second) = (SPEC_EXAMPLES[0].0, SPEC_EXAMPLES[1].0);
    let other = control_leaf(&NETWORK_ID, SccpNetworkV1::EthereumMainnet, &word, &second)
        .expect("a recorded leaf");
    assert_eq!(destination_answer(&first, other), "BadProof");
}

/// The topic of `SccpControlApplied` is the Keccak-256 of the canonical signature, which is
/// the signature of the model's event, and the bound of a fast pause is thirty days.
#[test]
fn control_applied_topic_is_recomputed_from_the_signature() {
    let event = DestinationEvent::ControlApplied {
        control_nonce: 1,
        track: TRACK_PARLIAMENT,
        parliament_paused: true,
        fast_pause_until_ms: 0,
        certificate_id: [0x33; 32],
    };
    assert_eq!(DOCUMENT["event_signature"], text(event.signature()));
    assert_eq!(
        DOCUMENT["event_signature"],
        text("SccpControlApplied(uint64,uint8,bool,uint64,bytes32)")
    );
    assert_eq!(DOCUMENT["topic_control_applied"], hx(&event.topic0()));
    assert_eq!(
        to_hex(&bytes_of(&DOCUMENT, "topic_control_applied")),
        SPEC_TOPIC
    );
    assert_eq!(number_of(&DOCUMENT, "max_fast_pause_ms"), 2_592_000_000);
    assert_eq!(word_of(&DOCUMENT, "taira_network_id"), NETWORK_ID);
    assert_eq!(word_of(&DOCUMENT, "consensus_instance"), INSTANCE);
    assert_eq!(DOCUMENT["schema"], text("iroha.sccp.control.v1"));
}

// ---------------------------------------------------------------------------------------------
// The regenerated document: scenarios
// ---------------------------------------------------------------------------------------------

/// Every scenario runs on an EVM destination, keeps the destination clock convention and
/// reports `ok` or an error of the §5.2.2 table; together they report every refusal of
/// `applyControl` and the pause that blocks minting only.
#[test]
fn every_effect_step_uses_the_destination_clock_and_a_named_error() {
    let effects = rows("destination_effects");
    assert_eq!(effects.len(), SCENARIOS.len());
    let names: BTreeSet<_> = effects
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect();
    assert_eq!(names.len(), effects.len(), "scenario names are unique");
    let mut reported = BTreeSet::new();
    let mut steps = 0;
    for row in effects {
        assert_eq!(row["flavor"], text("evm"));
        assert_eq!(row["deployment"]["flavor"], text("evm"));
        // An EVM destination stores no keys, and every scenario starts unpaused at nonce 0.
        let initial = &row["initial_state"];
        assert!(initial["committee"].get("keys").is_none());
        assert_eq!(number_of(&initial["pause"], "control_nonce"), 0);
        assert_eq!(initial["pause"]["parliament_paused"], Value::Bool(false));
        steps += check_scenario_clock(row);
        reported.extend(check_scenario_outcomes(row));
    }
    assert!(steps > effects.len(), "the scenarios have steps");
    assert_eq!(
        reported,
        BTreeSet::from([
            "BadControl",
            "BadProof",
            "CommitteeNotAccepted",
            "DeadlineNotReached",
            "MintingIsPaused",
            "StaleControl",
            "UnknownCheckpoint",
        ])
    );
}

/// The effective pause is `parliamentPaused ∨ now_ms < fastPauseUntilMs` on every step, a
/// finalization is refused exactly while it holds, and a fast-pause expiry is probed from
/// both sides by whole-second clock values: at the last value below it and at the first
/// that is not, for a whole-second expiry and for one that ends in 001 ms.
#[test]
fn fast_pause_expiries_are_probed_from_both_sides() {
    // (the expiry is sub-second, now_ms − fastPauseUntilMs, the effective pause) of every
    // step without a Parliament pause.
    let mut probes = BTreeSet::new();
    // The same for the finalizations, with their outcome.
    let mut mints = BTreeSet::new();
    for row in rows("destination_effects") {
        for step in steps_of(row) {
            let now_ms = number_of(step, "now_ms");
            let pause = &step["state_after"]["pause"];
            let parliament = pause["parliament_paused"].as_bool().expect("a flag");
            let until_ms = number_of(pause, "fast_pause_until_ms");
            let effective = pause["effective"].as_bool().expect("a reading");
            assert_eq!(effective, parliament || now_ms < until_ms, "{step:?}");
            if step["call"] == text("views") {
                let views = &step["expected"];
                assert_eq!(views["mintingPaused"], Value::Bool(effective));
                assert_eq!(views["pauseState"]["effective"], Value::Bool(effective));
                assert_eq!(
                    number_of(&views["pauseState"], "fastPauseUntilMs"),
                    until_ms
                );
            }
            let distance = i128::from(now_ms) - i128::from(until_ms);
            let sub_second = !until_ms.is_multiple_of(SECOND);
            let outcome = step_outcome(step);
            if step["call"] == text("finalizeFromCheckpoint") {
                assert_eq!(outcome == "MintingIsPaused", effective, "{step:?}");
                if !parliament {
                    mints.insert((sub_second, distance, outcome));
                }
            }
            if !parliament && until_ms != 0 {
                probes.insert((sub_second, distance, effective));
            }
        }
    }
    let second = i128::from(SECOND);
    for probe in [
        (false, -second, true),
        (false, 0, false),
        (true, -1, true),
        (true, 999, false),
    ] {
        assert!(probes.contains(&probe), "no step probes {probe:?}");
    }
    for mint in [
        (false, -second, "MintingIsPaused"),
        (false, 0, "ok"),
        (true, -1, "MintingIsPaused"),
        (true, 999, "ok"),
    ] {
        assert!(mints.contains(&mint), "no finalization probes {mint:?}");
    }
}

/// An applied control sets the complete pause state of its leaf (§5.1.6 steps 4 and 5): the
/// nonce is above the stored one, the Parliament flag is the leaf's, the expiry is the leaf's
/// clamped to `now_ms + MAX_FAST_PAUSE_MS`, `opCount` grows by one and the event carries what
/// was stored. A refused call and a view change nothing. The rows include a clamped expiry,
/// a nonce gap and a fast-pause leaf applied after its expiry.
#[test]
fn applied_controls_set_the_complete_pause_state() {
    let mut seen = BTreeSet::new();
    for row in rows("destination_effects") {
        let mut previous = row["initial_state"].clone();
        for step in steps_of(row) {
            let after = stored_state(&step["state_after"]);
            let call = step["call"].as_str().expect("a call name");
            if call == "views" || step_outcome(step) != "ok" {
                assert_eq!(after, previous, "{call} changes nothing: {step:?}");
            } else if matches!(call, "applyControl" | "applyControlFromCheckpoint") {
                let proof = &step["proof"];
                let now_ms = number_of(step, "now_ms");
                let nonce = number_of(proof, "controlNonce");
                let until_ms = number_of(proof, "fastPauseUntilMs");
                let stored = until_ms.min(now_ms + MAX_FAST_PAUSE_MS);
                assert_eq!(stored, applied_fast_pause_until_ms(until_ms, now_ms));
                let events = step["expected"]["events"].as_array().expect("events");
                // The inline form verifies and stores its certificate first.
                assert_eq!(events.len(), if call == "applyControl" { 3 } else { 1 });
                let event = events.last().expect("the event of the control");
                assert_eq!(event["event"], text("SccpControlApplied"));
                assert_eq!(event["controlNonce"], proof["controlNonce"]);
                assert_eq!(event["track"], proof["track"]);
                assert_eq!(event["parliamentPaused"], proof["parliamentPaused"]);
                assert_eq!(event["fastPauseUntilMs"], num(stored));
                assert_eq!(event["certificateId"], proof["certificateId"]);
                let pause = &after["pause"];
                assert_eq!(pause["control_nonce"], proof["controlNonce"]);
                assert_eq!(pause["parliament_paused"], proof["parliamentPaused"]);
                assert_eq!(pause["fast_pause_until_ms"], num(stored));
                let before = number_of(&previous["pause"], "control_nonce");
                assert!(nonce > before, "{step:?}");
                assert_eq!(
                    number_of(&after, "op_count"),
                    number_of(&previous, "op_count") + 1
                );
                if stored < until_ms {
                    seen.insert("clamped");
                }
                if nonce > before + 1 {
                    seen.insert("gap");
                }
                if until_ms != 0 && until_ms <= now_ms {
                    seen.insert("expired");
                }
                if proof["block"]["historyPath"] != list([]) {
                    seen.insert("historical");
                }
            }
            previous = after;
        }
    }
    assert_eq!(
        seen,
        BTreeSet::from(["clamped", "expired", "gap", "historical"])
    );
}

/// The document pools exactly the certificates its steps name, in order of first use, all
/// signed by the one committee it lists, and none brings TON successor keys.
#[test]
fn document_pools_the_certificates_its_steps_name() {
    let certificates = DOCUMENT["certificates"]
        .as_object()
        .expect("the certificate pool");
    let mut used = Vec::new();
    for row in rows("destination_effects") {
        for step in steps_of(row) {
            let ids = step["certificates"].as_array().into_iter().flatten();
            for id in ids.chain(step.get("certificate")) {
                let id = id.as_str().expect("a pool id");
                assert!(certificates.contains_key(id), "{id} is not pooled");
                if !used.contains(&id) {
                    used.push(id);
                }
            }
        }
    }
    let pooled: Vec<&str> = certificates.keys().map(String::as_str).collect();
    assert_eq!(used, pooled, "ids follow the order of first use");
    let labels: Vec<&str> = certificates
        .values()
        .map(|entry| entry["label"].as_str().expect("a label"))
        .collect();
    assert_eq!(
        labels,
        [
            "X_1010", "X_1020", "X_1030", "X_1040", "X_1050", "X_1060", "X_1070", "X_1080",
            "X_1100", "X_1090", "X_1110",
        ]
    );
    let committees = DOCUMENT["committees"].as_object().expect("committees");
    assert_eq!(committees.keys().collect::<Vec<_>>(), ["K0"]);
    assert_eq!(
        committees["K0"]["test_key_indices"]
            .as_array()
            .map(Vec::len),
        Some(4)
    );
    for entry in certificates.values() {
        assert_eq!(entry["signed_by"], text("K0"));
        assert_eq!(entry["ton_next_keys"], Value::Null);
        assert_eq!(
            entry["header_fields"]["committee_root"],
            committees["K0"]["root"]
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The builders
// ---------------------------------------------------------------------------------------------

/// The environment pins `K0` as generation 5 at height 1000 on the Ethereum route, derives
/// the ids of a control from one number, labels a certificate by its height and proves a
/// leaf under the header of its own block.
#[test]
fn environment_pins_k0_and_proves_its_blocks() {
    let mut env = Env::new();
    let deployment = env.deployment();
    assert_eq!(deployment.flavor, DestinationFlavor::Evm);
    assert_eq!(deployment.network, SccpNetworkV1::EthereumMainnet);
    assert_eq!(deployment.destination_word, word_address(&ETHEREUM_ADDRESS));
    assert_eq!(deployment.route_revision, 1);
    assert_eq!(deployment.max_wrapped_supply, SUPPLY_CAP);
    assert_eq!(deployment.pin_root, env.k0.root());
    assert_eq!(deployment.pin_keys, Some(env.k0.keys()));
    assert_eq!(
        (deployment.pin_generation, deployment.pin_start_height),
        (PIN_GENERATION, PIN_START)
    );
    assert_eq!(deployment.pin_until_ms, T0 + VALIDITY);
    let mut indices: Vec<u8> = env.k0.members().iter().map(|key| key.index).collect();
    indices.sort_unstable();
    assert_eq!(
        (env.k0.name.as_str(), indices),
        ("K0", vec![40, 41, 42, 43])
    );

    // The ids of a control: two hashes of the word of one number, under two tags.
    let fields = control_fields(7, TRACK_FAST_PAUSE, 1, T0 + HOUR, 9);
    let nine = word_u64(9);
    assert_eq!(nine[31], 9);
    assert_eq!(
        fields,
        ControlLeafV1 {
            route_revision: 0,
            control_nonce: 7,
            track: 2,
            parliament_paused: 1,
            fast_pause_until_ms: T0 + HOUR,
            certificate_id: keccak256(&[b"sccp-reference/certificate", &nine]),
            effect_hash: keccak256(&[b"sccp-reference/effect", &nine]),
        }
    );
    assert_ne!(fields.certificate_id, fields.effect_hash);
    assert_ne!(
        fields.certificate_id,
        control_fields(7, TRACK_FAST_PAUSE, 1, T0 + HOUR, 10).certificate_id
    );
    // The route's simulator sets the revision and records the leaf.
    let control = env.control(7, TRACK_FAST_PAUSE, 1, T0 + HOUR, 9);
    assert_eq!(control.kind, LeafKind::Control);
    assert_eq!(
        control.control,
        ControlLeafV1 {
            route_revision: 1,
            ..fields
        }
    );
    assert_eq!(
        Ok(control.leaf),
        control_leaf(
            &NETWORK_ID,
            deployment.network,
            &deployment.destination_word,
            &control.control
        )
    );
    let transfer = env.transfer(0, AMOUNT, T0 + DAY);
    assert_eq!((transfer.kind, transfer.nonce), (LeafKind::Transfer, 0));

    env.block(1010, T0 + MINUTE, vec![control, transfer]);
    env.block(1020, T0 + 2 * MINUTE, vec![]);
    assert_eq!(env.header(1010).message_count, 2);
    assert_eq!(env.header(1020).history_size, 1);
    assert_eq!(env.x(1010), env.header(1010).to_bytes());
    let certificate = env.cert(1010);
    assert_eq!(
        (certificate.label.as_str(), certificate.signed_by.as_str()),
        ("X_1010", "K0")
    );
    assert!(certificate.next_committee.is_none());
    assert_eq!(certificate.certificate.header, env.x(1010));
    let destination = Destination::new(deployment).expect("the deployment");
    assert_eq!(
        outcome_name(&destination.verify_certificate(&certificate.certificate.wire(), T0 + HOUR)),
        "ok"
    );

    // A proof under the header of its own block has no history path; under a later header
    // it has one.
    let own = env.control_proof(1010, 0);
    assert_eq!((own.control_nonce, own.leaf_index), (7, 0));
    assert_eq!(own.path.len(), 1);
    assert!(own.block.history_path.is_empty());
    assert_eq!(own.block.sccp_root, env.header(1010).sccp_root);
    let message = env.message_proof(1010, 1);
    assert_eq!(message.leaf_index, 1);
    assert_eq!(message.block, own.block);
    let later = env.sim.control_proof(1010, 0, env.header(1020));
    assert_eq!((later.block.height, later.block.history_index), (1010, 0));
    assert_eq!(later.path, own.path);

    // A scenario of the environment is strict and shares its pool.
    let mut run = env.scenario("probe", "a probe");
    run.submit(&[env.cert(1020)], T0 + HOUR, "ok");
    run.apply_control(Source::Inline(&certificate), &own, T0 + HOUR, "ok");
    assert_eq!(run.fast_pause_until_ms(), T0 + HOUR);
    run.views(T0 + HOUR);
    run.finalize(
        Source::Checkpoint(&env.x(1010)),
        &message,
        T0 + HOUR,
        "MintingIsPaused",
    );
    run.void_expired(
        0,
        Source::Checkpoint(&env.x(1010)),
        &message,
        T0 + HOUR,
        "DeadlineNotReached",
    );
    assert_eq!(env.pool.borrow().len(), 2);
    let row = run.0.as_json();
    let calls: Vec<_> = steps_of(&row)
        .iter()
        .filter_map(|step| step["call"].as_str())
        .collect();
    assert_eq!(
        calls,
        [
            "submitCheckpoints",
            "applyControl",
            "views",
            "finalizeFromCheckpoint",
            "voidExpiredFromCheckpoint",
        ]
    );
    // The stored form of a recorded state drops the two clock readings and nothing else.
    let recorded = &steps_of(&row)[1]["state_after"];
    let stored = stored_state(recorded);
    assert!(recorded.get("live").is_some() && recorded["pause"].get("effective").is_some());
    assert!(stored.get("live").is_none() && stored["pause"].get("effective").is_none());
    assert_eq!(stored["pause"]["control_nonce"], num(7));
    assert_eq!(stored["committee"], recorded["committee"]);
    assert_eq!(stored_state(&row["initial_state"]), row["initial_state"]);
}

/// A call of a scenario that does not give the outcome its author wrote fails the build.
#[test]
#[should_panic(expected = "the model gave")]
fn run_refuses_an_unexpected_outcome() {
    let mut env = Env::new();
    env.block(
        1010,
        T0 + MINUTE,
        vec![env.control(1, TRACK_PARLIAMENT, 1, 0, 1)],
    );
    env.scenario("strict", "a probe").apply_control(
        Source::Inline(&env.cert(1010)),
        &env.control_proof(1010, 0),
        T0 + HOUR,
        "StaleControl",
    );
}

/// The chain of the scenarios: eleven blocks at strictly increasing heights and times, all
/// certified by the pinned generation inside its tenure, with one history leaf per block
/// that has leaves, controls before transfers.
#[test]
fn blocks_of_the_scenarios_form_one_chain() {
    let (env, scenarios) = destination_effects();
    assert_eq!(scenarios.len(), SCENARIOS.len());
    let heights: Vec<u64> = env.sim.blocks.keys().copied().collect();
    assert_eq!(
        heights,
        [
            1010, 1020, 1030, 1040, 1050, 1060, 1070, 1080, 1090, 1100, 1110
        ]
    );
    let counts: Vec<u32> = heights
        .iter()
        .map(|height| env.header(*height).message_count)
        .collect();
    assert_eq!(counts, [1, 2, 2, 2, 3, 1, 3, 2, 6, 0, 2]);
    let mut history_size = 0;
    let mut previous_ms = T0;
    for (height, block) in &env.sim.blocks {
        assert!(*height > PIN_START);
        assert!(block.timestamp_ms > previous_ms && block.timestamp_ms < T0 + VALIDITY);
        previous_ms = block.timestamp_ms;
        assert_eq!(block.generation.number, PIN_GENERATION);
        history_size += u64::from(!block.leaves.is_empty());
        assert_eq!(block.header.history_size, history_size, "{height}");
        let kinds: Vec<LeafKind> = block.leaves.iter().map(|item| item.kind).collect();
        assert!(kinds.is_sorted_by_key(|kind| *kind == LeafKind::Transfer));
    }
    assert_eq!(env.header(1100).history_root, env.header(1090).history_root);
    // The transfers of the chain carry the nonces 0 to 5, each once.
    let mut nonces: Vec<u64> = env
        .sim
        .blocks
        .values()
        .flat_map(|block| &block.leaves)
        .filter(|item| item.kind == LeafKind::Transfer)
        .map(|item| item.nonce)
        .collect();
    nonces.sort_unstable();
    assert_eq!(nonces, [0, 1, 2, 3, 4, 5]);
}

/// The first four leaves of block 1090 are controls Taira records for another route, so the
/// route's own leaf of the same fields is another hash. The fifth is the route's own leaf of
/// fields no destination accepts, and the sixth is a transfer.
#[test]
fn foreign_leaves_are_not_leaves_of_the_route() {
    let env = Env::new();
    let leaves = foreign_and_malformed_leaves(&env);
    let deployment = env.deployment();
    let own = |fields: &ControlLeafV1| {
        let fields = ControlLeafV1 {
            route_revision: deployment.route_revision,
            ..*fields
        };
        control_leaf_unchecked(
            &deployment.taira_network_id,
            deployment.network,
            &deployment.destination_word,
            &fields,
        )
        .expect("the route has a lane")
    };
    let kinds: Vec<LeafKind> = leaves.iter().map(|item| item.kind).collect();
    assert_eq!(kinds[..5], [LeafKind::Control; 5]);
    assert_eq!(kinds[5], LeafKind::Transfer);
    let mut distinct = BTreeSet::new();
    for (index, item) in leaves[..4].iter().enumerate() {
        assert_eq!(check_control_constraints(&item.control), Ok(()), "{index}");
        assert_ne!(item.leaf, own(&item.control), "leaf {index}");
        assert!(distinct.insert(item.leaf));
    }
    // Only the leaf of the other revision is hashed with another revision.
    let revisions: Vec<u32> = leaves[..5]
        .iter()
        .map(|item| item.control.route_revision)
        .collect();
    assert_eq!(revisions, [1, 1, 2, 1, 1]);
    let malformed = &leaves[4];
    assert_eq!(malformed.leaf, own(&malformed.control));
    assert_eq!(malformed.control.track, 3);
    assert_eq!(
        check_control_constraints(&malformed.control),
        Err(ControlLeafError::BadControl)
    );
    assert_eq!(leaves[5].nonce, 4);
}
