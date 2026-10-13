//! Rust reference generator of `fixtures/sccp/committee_transitions_v1.json`
//! (`specs/sccp.md` §5.1.2–§5.1.8, §11.1).
//!
//! The file is also written by the independent Python reference
//! (`scripts/sccp_reference/vectors_transitions.py`), and the two outputs must be
//! byte-identical. Every required row of §11.1 is a scenario: a fresh destination deployed
//! with a pin, then calls with `now_ms`, each recorded with the outcome, the events and the
//! state that the Rust destination model (`iroha_sccp::v1::destination`) gives. Headers,
//! certificates and proofs come from the simulator of `reference_support`, so every key,
//! signature, hash and encoding of the document is derived here.
//!
//! The scenarios are built twice. The first pass runs each on the flavour its author chose
//! (EVM unless marked TON) and is strict: a call that does not give the outcome its author
//! wrote fails the build. The second pass replays every scenario on the TON model and
//! records what it answers. An EVM row whose replay gives the same outcomes, events and
//! state with one certificate per call is marked `ton_replayable`.
//!
//! A TON-flavoured scenario runs on the TON route: Taira's leaves target `ton-mainnet`, the
//! destination word is the harness-installed minter account id ([`TON_DESTINATION_WORD`]) and
//! recipients are 36-byte TON accounts. A real minter computes its lane and its word from its
//! own chain and address, so a row on any other route could not be replayed against it. The
//! replay pass changes the destination only: the certificates of an EVM-authored scenario
//! stay those of the Ethereum route, and a TON minter takes their checkpoints all the same.
//!
//! `now_ms` is the destination clock (`block.timestamp × 1000`, §0): every step uses a whole
//! second and no step is earlier than the one before it, which the recorder asserts. A time
//! boundary (`Live ⇔ now_ms ≤ untilMs`, a payload deadline) is therefore probed at the
//! boundary value and at the next clock value, one second later, and a sub-second boundary
//! from the nearest whole seconds on both sides.
//!
//! The selectors and the event topics of §5.2.2 are recomputed from the canonical signatures
//! and asserted against the specification values of `iroha_sccp::v1::destination_abi`, whose
//! error table gives the error codes.
//!
//! Drift test: `reference_committee_transitions_v1_matches_committed_fixture`. After a
//! reviewed change, rewrite the file with
//! `cargo test -p iroha_sccp --test v1_reference_transitions -- --ignored regenerate`.

mod reference_support;

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
    sync::LazyLock,
};

use iroha_data_model::bridge::SccpNetworkV1;
use iroha_sccp::v1::{
    committee::{BLS12_381_P, FP_LEN, IDENTITY_SIGNATURE, IDENTITY_SIGNATURE_EVM},
    control::ControlLeafV1,
    destination::{
        BlockRefV1, CertificateSourceV1, CheckpointRefV1, ControlProofV1, DeploymentV1,
        Destination, DestinationError, DestinationFlavor, MAX_CERTIFICATES_PER_CALL,
        MAX_INIT_SLACK_MS, MessageProofV1, TON_CHECKPOINT_SLOTS, init_until_ms_is_valid,
    },
    destination_abi::{EVENT_TOPICS, SELECTORS},
    finality::{
        FLAG_ACTIVE, FLAG_ROTATION, MAX_VALIDITY_MS, SccpFinalityHeaderFieldsV1,
        SccpFinalityHeaderV1,
    },
    hashes::{keccak256, to_hex, word_address},
    payload::SccpTransferPayloadV1,
};
use norito::json::Value;
use reference_support::{
    DESTINATION_CLOCK_CONVENTION, REFERENCE_GENERATORS, REGENERATE_COMMAND,
    SCENARIO_CLOCK_CONVENTION, assert_matches_committed,
    bls_support::{fp_add, fp_sub},
    hx, insert, list, num, obj, outcome_name,
    scenario::{
        CertificatePool, Scenario, Source, Submission, TON_CALL_NAMES, check_scenario_clock,
        check_scenario_outcomes, step_outcome, steps_of,
    },
    taira_sim::{
        Block, Certificate, CertifyOptions, Committee, DEFAULT_SENDER, LeafItem, Rotate, TairaSim,
    },
    text, write_fixture,
};

/// The file both references write.
const TRANSITIONS: &str = "committee_transitions_v1.json";

/// Taira's `NetworkId` in every scenario.
const NETWORK_ID: [u8; 32] = [0x11; 32];
/// The consensus instance `I` in every scenario.
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
/// The validity of the pinned generation, and of a rotation that grants no other (ms).
const VALIDITY: u64 = 1_209_600_000;
/// The pinned generation.
const PIN_GENERATION: u64 = 5;
/// Its first height.
const PIN_START: u64 = 1000;
/// The address of the destination contract. Its word is the destination word of the route.
const DESTINATION_ADDRESS: [u8; 20] = [0x22; 20];
/// The recipient of the transfers.
const RECIPIENT: [u8; 20] = [0x44; 20];
/// The destination word of the TON route: the account id of the minter. A minter's address
/// is fixed by its `StateInit`; the Acton harness installs its fixture minter at this
/// account id (`control_v1.json` lists the same value under `destination_words`).
const TON_DESTINATION_WORD: [u8; 32] = [0x35; 32];
/// The recipient of the transfers of the TON route: `addr_std` in workchain 0
/// (`be32(0) ‖ account_id`).
const TON_RECIPIENT: [u8; 36] = {
    let mut recipient = [0x44; 36];
    recipient[0] = 0;
    recipient[1] = 0;
    recipient[2] = 0;
    recipient[3] = 0;
    recipient
};
/// The unit of the transfer amounts.
const AMOUNT: u128 = 1_000_000_000;
/// `maxWrappedSupply` of every deployment.
const SUPPLY_CAP: u128 = 10 * AMOUNT;

// ---------------------------------------------------------------------------------------------
// The environment of a scenario
// ---------------------------------------------------------------------------------------------

/// The committee `K<j>`: test keys `40 + 4j … 43 + 4j` (n = 4).
fn committee(j: usize) -> Committee {
    let first = u8::try_from(40 + 4 * j).expect("a test key index");
    Committee::new(&format!("K{j}"), first..first + 4)
}

/// A Taira route with generation 5 (`K0`) pinned at height 1000 and time `T0`, and what a
/// scenario on it needs: the flavour of its destination and the certificate pool of the file.
///
/// `ton_route` is the route Taira's leaves are built for: the TON route for a scenario its
/// author wrote for TON, the Ethereum route otherwise. `flavor` is the flavour of the
/// destination. The two differ only in the replay pass, which runs an EVM-authored scenario
/// on a TON destination to decide `ton_replayable`.
struct Env {
    flavor: DestinationFlavor,
    ton_route: bool,
    strict: bool,
    /// `K0 … K<j>`: the committees the scenario has named so far.
    committees: Vec<Committee>,
    sim: TairaSim,
    pool: Rc<RefCell<CertificatePool>>,
}

impl Env {
    fn new(
        pool: &Rc<RefCell<CertificatePool>>,
        flavor: DestinationFlavor,
        ton_route: bool,
        strict: bool,
    ) -> Self {
        let pinned = committee(0);
        let (target, word) = if ton_route {
            (SccpNetworkV1::TonMainnet, TON_DESTINATION_WORD)
        } else {
            (
                SccpNetworkV1::EthereumMainnet,
                word_address(&DESTINATION_ADDRESS),
            )
        };
        let mut sim = TairaSim::new(NETWORK_ID, INSTANCE, target, word);
        sim.start(PIN_GENERATION, pinned.clone(), PIN_START, T0, VALIDITY);
        Self {
            flavor,
            ton_route,
            strict,
            committees: vec![pinned],
            sim,
            pool: Rc::clone(pool),
        }
    }

    /// `K0`, the committee of the pin.
    fn pinned(&self) -> &Committee {
        &self.committees[0]
    }

    /// `K<j>`, naming every committee up to it.
    fn k(&mut self, j: usize) -> Committee {
        while self.committees.len() <= j {
            self.committees.push(committee(self.committees.len()));
        }
        self.committees[j].clone()
    }

    /// The destination: `K0` pinned as generation 5 until `T0 + VALIDITY`, on the profile of
    /// its flavour. The deployment carries the pinned keys on either flavour; only TON stores
    /// them.
    fn deployment(&self) -> DeploymentV1 {
        let pinned = self.pinned();
        let (network, destination_word) = match self.flavor {
            DestinationFlavor::Evm => (
                SccpNetworkV1::EthereumMainnet,
                word_address(&DESTINATION_ADDRESS),
            ),
            DestinationFlavor::Ton => (SccpNetworkV1::TonMainnet, TON_DESTINATION_WORD),
        };
        DeploymentV1 {
            flavor: self.flavor,
            taira_network_id: NETWORK_ID,
            consensus_instance: INSTANCE,
            network,
            destination_word,
            route_revision: 1,
            max_wrapped_supply: SUPPLY_CAP,
            pin_generation: PIN_GENERATION,
            pin_root: pinned.root(),
            pin_start_height: PIN_START,
            pin_until_ms: T0 + VALIDITY,
            pin_keys: Some(pinned.keys()),
        }
    }

    /// A scenario on a fresh destination of the route.
    fn scenario(&self, name: &str, description: &str) -> Run {
        Run(Scenario::new(
            name,
            description,
            self.deployment(),
            &self.pool,
            self.strict,
        ))
    }

    /// A block without SCCP leaves.
    fn block(&mut self, height: u64, timestamp_ms: u64) -> Block {
        self.block_of(height, timestamp_ms, vec![])
    }

    /// A block with `leaves`.
    fn block_of(&mut self, height: u64, timestamp_ms: u64, leaves: Vec<LeafItem>) -> Block {
        self.sim.block(height, timestamp_ms, leaves, None, None)
    }

    /// A handoff to `next` without SCCP leaves, granting the validity of its generation.
    fn key_change(&mut self, height: u64, timestamp_ms: u64, next: &Committee) -> Block {
        self.sim.block(
            height,
            timestamp_ms,
            vec![],
            Some(Rotate::Key(next.clone())),
            None,
        )
    }

    /// The recipient of the route's transfers: [`RECIPIENT`], or [`TON_RECIPIENT`] on the
    /// TON route.
    fn recipient(&self) -> &'static [u8] {
        if self.ton_route {
            &TON_RECIPIENT
        } else {
            &RECIPIENT
        }
    }

    /// A transfer of `amount` to the recipient of the route.
    fn transfer(&self, nonce: u64, amount: u128, deadline_ms: u64) -> LeafItem {
        self.sim
            .transfer(nonce, amount, deadline_ms, self.recipient())
    }

    /// The certificate of `block` by the generation that certifies it, labelled
    /// `X_<height>`.
    fn cert(&self, block: &Block) -> Submission {
        self.cert_of(
            &block.header,
            &block.generation.committee,
            None,
            &CertifyOptions::default(),
        )
    }

    /// A certificate of `header` signed by `signer`, labelled `label` or `X_<height>`.
    fn cert_of(
        &self,
        header: &SccpFinalityHeaderFieldsV1,
        signer: &Committee,
        label: Option<&str>,
        options: &CertifyOptions,
    ) -> Submission {
        let label = label.map_or_else(|| format!("X_{}", header.height), str::to_owned);
        Submission::new(
            self.sim.certify(&header.to_bytes(), signer, options),
            &label,
            &signer.name,
        )
    }

    /// An `X` Taira never certified, signed by `signer`: an attacker holding that quorum. The
    /// header is the empty active form of `generation` with the root of `signer`, after
    /// `change`.
    ///
    /// # Panics
    /// When the changed fields violate X1–X7: a forged header is still a finality header.
    fn forged(
        &self,
        height: u64,
        timestamp_ms: u64,
        generation: u64,
        signer: &Committee,
        change: impl FnOnce(&mut SccpFinalityHeaderFieldsV1),
    ) -> Submission {
        let mut fields = SccpFinalityHeaderFieldsV1 {
            network_id: NETWORK_ID,
            height,
            timestamp_ms,
            flags: FLAG_ACTIVE,
            generation,
            committee_root: signer.root(),
            ..SccpFinalityHeaderFieldsV1::default()
        };
        change(&mut fields);
        SccpFinalityHeaderV1::from_fields(&fields).expect("a forged header satisfies X1-X7");
        self.cert_of(
            &fields,
            signer,
            Some(&format!("forged_X_{height}")),
            &CertifyOptions::default(),
        )
    }
}

/// A scenario being recorded. Every call names the outcome its author expects: the recorder
/// checks it in the strict pass and records what the model answers in the replay pass, so
/// the result of a call is not read again.
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

    fn void_frozen(&mut self, first_nonce: u64, count: u64, now_ms: u64, expect: &str) {
        let _ = self.0.void_frozen(first_nonce, count, now_ms, Some(expect));
    }

    fn views(&mut self, now_ms: u64) {
        self.0.views(now_ms);
    }

    /// `cur.untilMs` of the destination.
    fn until_ms(&self) -> u64 {
        self.0.destination.state().committee.until_ms
    }
}

/// What one pass over [`SCENARIOS`] builds: the scenarios in file order, the pool of their
/// certificates and the committees they name.
struct Tables {
    /// The flavour of the scenarios that choose none: EVM for the document, TON for the
    /// replay that decides `ton_replayable`.
    default_flavor: DestinationFlavor,
    pool: Rc<RefCell<CertificatePool>>,
    scenarios: Vec<Scenario>,
    committees: BTreeMap<String, Committee>,
}

impl Tables {
    fn new(default_flavor: DestinationFlavor) -> Self {
        Self {
            default_flavor,
            pool: Rc::default(),
            scenarios: Vec::new(),
            committees: BTreeMap::new(),
        }
    }

    /// A fresh route for one scenario, on `flavor` or on the default flavour of the pass.
    /// Only the pass that writes the document is strict.
    fn env(&self, flavor: Option<DestinationFlavor>) -> Env {
        // The route follows the flavour the author chose; the replay pass changes the
        // destination only.
        Env::new(
            &self.pool,
            flavor.unwrap_or(self.default_flavor),
            flavor == Some(DestinationFlavor::Ton),
            self.default_flavor == DestinationFlavor::Evm,
        )
    }

    fn push(&mut self, run: Run) {
        self.scenarios.push(run.0);
    }

    /// Keep the committees `env` named for the `committees` object of the file.
    fn remember(&mut self, env: &Env) {
        for named in &env.committees {
            self.committees.insert(named.name.clone(), named.clone());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The scenarios (§11.1)
// ---------------------------------------------------------------------------------------------

/// Every scenario in file order. The certificate pool numbers certificates in order of first
/// use, so a new scenario goes at the end: `rotation_sub_second_deadline` and the rows after
/// it follow the TON rows for that reason, whatever their flavour.
const SCENARIOS: [fn(&mut Tables); 34] = [
    initial_pin,
    checkpoint_raises_high,
    rotation_key_change,
    heartbeat_rotation,
    rotation_lowered_validity,
    rotation_successor_already_expired,
    sixteen_batched_rotations,
    k_kprime_k,
    future_dated_replay_no_extension,
    forged_heights_then_genuine_handoff_latches,
    old_generations_refused,
    v1_two_x_at_one_height,
    v1_neighbour_same_x_other_result_body,
    v2_below_start,
    v2_neighbour_at_start,
    v3_rotation_below_high,
    v3_neighbour_rotation_at_high,
    expiry_then_refusal_then_void_frozen,
    latch_inside_batch,
    inline_v3_latch_required_then_submit_latches,
    future_dated_rotation_t_eff,
    finalize_proofs_cap_and_voids,
    ton_rotation_next_keys,
    ton_checkpoint_eviction,
    rotation_sub_second_deadline,
    cheap_path_identity_signature,
    transfer_deadline_boundaries,
    checkpoint_use_after_rotation,
    void_frozen_range_before_frozen,
    finalize_two_faults,
    check_order_two_faults,
    cheap_path_checks_encodings,
    same_height_block_ref_with_history,
    inline_calls_after_expiry,
];

/// One pass over [`SCENARIOS`].
fn build_scenarios(default_flavor: DestinationFlavor) -> Tables {
    let mut tables = Tables::new(default_flavor);
    for scenario in SCENARIOS {
        scenario(&mut tables);
    }
    tables
}

/// The initial pin.
fn initial_pin(tables: &mut Tables) {
    let env = tables.env(None);
    let mut sc = env.scenario(
        "initial_pin",
        "the state a constructor (EVM) or sccp_init (TON) leaves: cur from the pin, high = \
         start − 1",
    );
    sc.views(T0 + MINUTE);
    tables.push(sc);
}

/// A checkpoint raises `high` and leaves `untilMs` unchanged; a CUR certificate at or below
/// `high`.
fn checkpoint_raises_high(tables: &mut Tables) {
    let mut env = tables.env(None);
    let b1 = env.block(1005, T0 + 5 * SECOND);
    let b2 = env.block(1020, T0 + 20 * SECOND);
    let mut sc = env.scenario(
        "checkpoint_raises_high",
        "a non-rotation CUR certificate records its checkpoint and raises high; untilMs is \
         unchanged; a CUR certificate below high records a checkpoint without moving high; a \
         replay changes nothing",
    );
    sc.submit(&[env.cert(&b2)], T0 + MINUTE, "ok");
    sc.submit(&[env.cert(&b1)], T0 + MINUTE, "ok");
    sc.submit(&[env.cert(&b1)], T0 + 2 * MINUTE, "NothingToDo");
    tables.push(sc);
}

/// A rotation at a key change.
fn rotation_key_change(tables: &mut Tables) {
    let mut env = tables.env(None);
    let k1 = env.k(1);
    let rot = env.key_change(1100, T0 + HOUR, &k1);
    let after = env.block(1101, T0 + HOUR + SECOND);
    let mut sc = env.scenario(
        "rotation_key_change",
        "a ROTATION certificate of the current generation installs generation 6 with untilMs \
         = t_eff(X) + validity_ms; the successor's certificates are then CUR",
    );
    sc.submit(&[env.cert(&rot).with_next(&k1)], T0 + HOUR + MINUTE, "ok");
    sc.submit(&[env.cert(&after)], T0 + HOUR + 2 * MINUTE, "ok");
    tables.push(sc);
    tables.remember(&env);
}

/// A heartbeat.
fn heartbeat_rotation(tables: &mut Tables) {
    let mut env = tables.env(None);
    let hb = env
        .sim
        .block(1100, T0 + DAY, vec![], Some(Rotate::Heartbeat), None);
    let mut sc = env.scenario(
        "heartbeat_rotation",
        "a heartbeat (next_committee_root = committee_root) installs generation 6 with the \
         same keys and a fresh deadline",
    );
    sc.submit(&[env.cert(&hb)], T0 + DAY + MINUTE, "ok");
    tables.push(sc);
}

/// A rotation that lowers the validity.
fn rotation_lowered_validity(tables: &mut Tables) {
    let mut env = tables.env(None);
    let k1 = env.k(1);
    let low = env.sim.block(
        1100,
        T0 + HOUR,
        vec![],
        Some(Rotate::Key(k1.clone())),
        Some(3 * DAY),
    );
    let mut sc = env.scenario(
        "rotation_lowered_validity",
        "a rotation with validity_ms = 3 d gives the successor a deadline earlier than its \
         predecessor's",
    );
    sc.submit(&[env.cert(&low).with_next(&k1)], T0 + HOUR + MINUTE, "ok");
    assert_eq!(sc.until_ms(), T0 + HOUR + 3 * DAY);
    // `now_ms = untilMs`: still Live. The next clock value: Frozen.
    sc.views(T0 + HOUR + 3 * DAY);
    sc.views(T0 + HOUR + 3 * DAY + SECOND);
    tables.push(sc);
    tables.remember(&env);
}

/// A rotation whose successor deadline has already passed.
fn rotation_successor_already_expired(tables: &mut Tables) {
    let mut env = tables.env(None);
    let k1 = env.k(1);
    let late = env.sim.block(
        1100,
        T0 + HOUR,
        vec![],
        Some(Rotate::Key(k1.clone())),
        Some(DAY),
    );
    let later = env.block(1101, T0 + HOUR + SECOND);
    let mut sc = env.scenario(
        "rotation_successor_already_expired",
        "a destination lagging past the successor's deadline applies the rotation, becomes \
         Frozen and stops processing; then voids drain it",
    );
    sc.submit(
        &[env.cert(&late).with_next(&k1), env.cert(&later)],
        T0 + 3 * DAY,
        "ok",
    );
    sc.submit(&[env.cert(&later)], T0 + 3 * DAY, "CommitteeNotAccepted");
    sc.void_frozen(0, 3, T0 + 3 * DAY, "ok");
    tables.push(sc);
    tables.remember(&env);
}

/// Sixteen batched rotations, then seventeen certificates.
fn sixteen_batched_rotations(tables: &mut Tables) {
    let mut env = tables.env(None);
    let mut certificates = Vec::new();
    for j in 0..16_u8 {
        let next = env.k(usize::from(j) + 1);
        let block = env.key_change(
            1100 + 100 * u64::from(j),
            T0 + (u64::from(j) + 1) * HOUR,
            &next,
        );
        certificates.push(env.cert(&block).with_next(&next));
    }
    let mut sc = env.scenario(
        "sixteen_batched_rotations",
        "16 rotations K0 → K16 in one submitCheckpoints call; 17 certificates revert \
         TooManyCertificates",
    );
    sc.submit(&certificates, T0 + 17 * HOUR, "ok");
    assert_eq!(certificates.len(), MAX_CERTIFICATES_PER_CALL);
    let extra = env.block(2700, T0 + 17 * HOUR);
    certificates.push(env.cert(&extra));
    sc.submit(&certificates, T0 + 17 * HOUR, "TooManyCertificates");
    tables.push(sc);
    tables.remember(&env);
}

/// K → K′ → K, then an old generation with the same root.
fn k_kprime_k(tables: &mut Tables) {
    let mut env = tables.env(None);
    let (k0, k1) = (env.k(0), env.k(1));
    let old = env.block(1050, T0 + MINUTE);
    let r1 = env.key_change(1100, T0 + HOUR, &k1);
    let r2 = env.key_change(1200, T0 + 2 * HOUR, &k0);
    let mut sc = env.scenario(
        "k_kprime_k",
        "K → K′ → K: generation 7 has K's root again; a genuine certificate of generation 5 \
         (same root) is refused",
    );
    sc.submit(
        &[env.cert(&r1).with_next(&k1), env.cert(&r2).with_next(&k0)],
        T0 + 2 * HOUR + MINUTE,
        "ok",
    );
    sc.submit(
        &[env.cert(&old)],
        T0 + 2 * HOUR + MINUTE,
        "CommitteeNotAccepted",
    );
    tables.push(sc);
    tables.remember(&env);
}

/// A future-dated certificate replayed across several validity periods.
fn future_dated_replay_no_extension(tables: &mut Tables) {
    let env = tables.env(None);
    let future = env.forged(1010, T0 + 30 * DAY, PIN_GENERATION, env.pinned(), |_| {});
    let mut sc = env.scenario(
        "future_dated_replay_no_extension",
        "a future-dated non-rotation certificate is accepted but never extends untilMs; \
         replays change nothing; after the pin's deadline it is refused and voidFrozen opens",
    );
    let future = [future];
    sc.submit(&future, T0 + HOUR, "ok");
    sc.submit(&future, T0 + 7 * DAY, "NothingToDo");
    // `now_ms = untilMs`: still Live. The next clock value: refused.
    sc.submit(&future, T0 + VALIDITY, "NothingToDo");
    sc.submit(&future, T0 + VALIDITY + SECOND, "CommitteeNotAccepted");
    sc.void_frozen(0, 1, T0 + VALIDITY + SECOND, "ok");
    tables.push(sc);
}

/// Forged in-generation heights after the genuine end, then the genuine handoff (V3).
fn forged_heights_then_genuine_handoff_latches(tables: &mut Tables) {
    let mut env = tables.env(None);
    let k1 = env.k(1);
    let handoff = env.key_change(1100, T0 + HOUR, &k1);
    let f1 = env.forged(
        1101,
        T0 + HOUR + SECOND,
        PIN_GENERATION,
        env.pinned(),
        |_| {},
    );
    let f2 = env.forged(
        1102,
        T0 + HOUR + 2 * SECOND,
        PIN_GENERATION,
        env.pinned(),
        |_| {},
    );
    let mut sc = env.scenario(
        "forged_heights_then_genuine_handoff_latches",
        "a departed quorum of generation 5 signs heights above its genuine end: accepted \
         (bounded); the genuine handoff then trips V3 and latches; voidFrozen opens",
    );
    sc.submit(&[f1, f2], T0 + HOUR + MINUTE, "ok");
    sc.submit(
        &[env.cert(&handoff).with_next(&k1)],
        T0 + HOUR + 2 * MINUTE,
        "ok",
    );
    sc.void_frozen(5, 2, T0 + HOUR + 3 * MINUTE, "ok");
    let after = env.block(1110, T0 + HOUR + 10 * SECOND);
    sc.submit(&[env.cert(&after)], T0 + HOUR + 4 * MINUTE, "Equivocated");
    tables.push(sc);
    tables.remember(&env);
}

/// Old generations refused after every genuine rotation is applied.
fn old_generations_refused(tables: &mut Tables) {
    let mut env = tables.env(None);
    let (k1, k2) = (env.k(1), env.k(2));
    let g5 = env.block(1050, T0 + MINUTE);
    let rot5 = env.key_change(1100, T0 + HOUR, &k1);
    let g6 = env.block(1150, T0 + HOUR + MINUTE);
    let rot6 = env.key_change(1200, T0 + 2 * HOUR, &k2);
    let pinned_root = env.pinned().root();
    let forged_old = env.forged(1300, T0 + 3 * HOUR, PIN_GENERATION, env.pinned(), |x| {
        x.flags = FLAG_ACTIVE | FLAG_ROTATION;
        x.validity_ms = VALIDITY;
        x.next_committee_root = pinned_root;
    });
    let mut sc = env.scenario(
        "old_generations_refused",
        "after generations 6 and 7 are installed, genuine and forged certificates of \
         generations 5 and 6 (any height, ROTATION or not) are refused with no state change",
    );
    let now = T0 + 2 * HOUR + MINUTE;
    sc.submit(
        &[
            env.cert(&rot5).with_next(&k1),
            env.cert(&rot6).with_next(&k2),
        ],
        now,
        "ok",
    );
    sc.submit(&[env.cert(&g5)], now, "CommitteeNotAccepted");
    sc.submit(&[env.cert(&g6)], now, "CommitteeNotAccepted");
    sc.submit(
        &[env.cert(&rot5).with_next(&k1)],
        now,
        "CommitteeNotAccepted",
    );
    sc.submit(&[forged_old], now, "CommitteeNotAccepted");
    tables.push(sc);
    tables.remember(&env);
}

/// V1: two headers at one height.
fn v1_two_x_at_one_height(tables: &mut Tables) {
    let mut env = tables.env(None);
    let genuine = env.block(1030, T0 + 30 * SECOND);
    let conflicting = env.forged(1030, T0 + 30 * SECOND, PIN_GENERATION, env.pinned(), |x| {
        x.message_count = 1;
        x.sccp_root = [0xee; 32];
    });
    let mut sc = env.scenario(
        "v1_two_x_at_one_height",
        "V1: a second, different X at a recorded height signed by cur latches with reason 1",
    );
    sc.submit(&[env.cert(&genuine)], T0 + MINUTE, "ok");
    sc.submit(&[conflicting], T0 + 2 * MINUTE, "ok");
    sc.void_frozen(0, 1, T0 + 3 * MINUTE, "ok");
    tables.push(sc);
}

/// The neighbour of V1: the same header under another result body.
fn v1_neighbour_same_x_other_result_body(tables: &mut Tables) {
    let mut env = tables.env(None);
    let genuine = env.block(1030, T0 + 30 * SECOND);
    let mut sc = env.scenario(
        "v1_neighbour_same_x_other_result_body",
        "the same X with a different result_body (signed) records nothing and does not latch",
    );
    sc.submit(&[env.cert(&genuine)], T0 + MINUTE, "ok");
    let other_body = env.cert_of(
        &genuine.header,
        &genuine.generation.committee,
        None,
        &CertifyOptions {
            body_tag: b"/other".to_vec(),
            ..CertifyOptions::default()
        },
    );
    sc.submit(&[other_body], T0 + 2 * MINUTE, "NothingToDo");
    tables.push(sc);
}

/// V2: a certificate below `cur.start`.
fn v2_below_start(tables: &mut Tables) {
    let env = tables.env(None);
    let mut sc = env.scenario(
        "v2_below_start",
        "V2: a CUR certificate below cur.start latches with reason 2",
    );
    let below = env.forged(999, T0 - SECOND, PIN_GENERATION, env.pinned(), |_| {});
    sc.submit(&[below], T0 + MINUTE, "ok");
    tables.push(sc);
}

/// The neighbour of V2: a certificate at exactly `cur.start`.
fn v2_neighbour_at_start(tables: &mut Tables) {
    let mut env = tables.env(None);
    let mut sc = env.scenario(
        "v2_neighbour_at_start",
        "a CUR certificate at exactly cur.start is accepted",
    );
    let first = env.block(1000, T0);
    sc.submit(&[env.cert(&first)], T0 + MINUTE, "ok");
    tables.push(sc);
}

/// V3: a rotation below `cur.high`.
fn v3_rotation_below_high(tables: &mut Tables) {
    let mut env = tables.env(None);
    let k1 = env.k(1);
    let high = env.block(1060, T0 + MINUTE);
    let mut sc = env.scenario(
        "v3_rotation_below_high",
        "V3: a ROTATION certificate below cur.high latches with reason 3",
    );
    sc.submit(&[env.cert(&high)], T0 + 2 * MINUTE, "ok");
    let k1_root = k1.root();
    let below = env.forged(1050, T0 + 50 * SECOND, PIN_GENERATION, env.pinned(), |x| {
        x.flags = FLAG_ACTIVE | FLAG_ROTATION;
        x.validity_ms = VALIDITY;
        x.next_committee_root = k1_root;
    });
    sc.submit(&[below], T0 + 3 * MINUTE, "ok");
    tables.push(sc);
    tables.remember(&env);
}

/// The neighbour of V3: a rotation at exactly `cur.high`.
fn v3_neighbour_rotation_at_high(tables: &mut Tables) {
    let mut env = tables.env(None);
    let k1 = env.k(1);
    let leaves = vec![env.transfer(0, AMOUNT, T0 + DAY)];
    let rot = env.sim.block(
        1060,
        T0 + MINUTE,
        leaves,
        Some(Rotate::Key(k1.clone())),
        None,
    );
    let rot_cert = env.cert(&rot).with_next(&k1);
    let mut sc = env.scenario(
        "v3_neighbour_rotation_at_high",
        "the handoff used inline first (finalizeFromTaira records it and raises high to its \
         height without installing), then submitted: ROTATION at height = high installs",
    );
    sc.finalize(
        Source::Inline(&rot_cert),
        &env.sim.message_proof(1060, 0, &rot.header),
        T0 + 2 * MINUTE,
        "ok",
    );
    sc.submit(&[rot_cert], T0 + 3 * MINUTE, "ok");
    tables.push(sc);
    tables.remember(&env);
}

/// Expiry, then refusal, then `voidFrozen` and its range.
fn expiry_then_refusal_then_void_frozen(tables: &mut Tables) {
    let mut env = tables.env(None);
    let leaves = vec![env.transfer(0, AMOUNT, T0 + 20 * DAY)];
    let blk = env.block_of(1010, T0 + 10 * SECOND, leaves);
    let mut sc = env.scenario(
        "expiry_then_refusal_then_void_frozen",
        "at untilMs the destination is still Live; at the next clock value (one second later) \
         submitCheckpoints and finalize are refused, voidFrozen voids, a second voidFrozen of \
         the same nonce reverts",
    );
    sc.void_frozen(0, 1, T0 + VALIDITY, "NotFrozen");
    sc.submit(&[env.cert(&blk)], T0 + VALIDITY, "ok");
    let frozen = T0 + VALIDITY + SECOND;
    let next = env.block(1011, T0 + 11 * SECOND);
    sc.submit(&[env.cert(&next)], frozen, "CommitteeNotAccepted");
    sc.finalize(
        Source::Checkpoint(&blk.x()),
        &env.sim.message_proof(1010, 0, &blk.header),
        frozen,
        "CommitteeNotAccepted",
    );
    sc.void_frozen(0, 2, frozen, "ok");
    sc.void_frozen(1, 1, frozen + SECOND, "AlreadyConsumed");
    sc.void_frozen(10, 0, frozen + SECOND, "BadAmount");
    sc.void_frozen(10, 257, frozen + SECOND, "BadAmount");
    sc.void_frozen(u64::MAX, 2, frozen + SECOND, "BadAmount");
    tables.push(sc);
}

/// A latch inside a batch.
fn latch_inside_batch(tables: &mut Tables) {
    let mut env = tables.env(None);
    let a = env.block(1010, T0 + 10 * SECOND);
    let c = env.block(1020, T0 + 20 * SECOND);
    let mut sc = env.scenario(
        "latch_inside_batch",
        "[ok, V2 violation, ok]: the first is applied, the latch persists and the third is \
         not processed",
    );
    let below = env.forged(990, T0 - 10 * SECOND, PIN_GENERATION, env.pinned(), |_| {});
    sc.submit(&[env.cert(&a), below, env.cert(&c)], T0 + MINUTE, "ok");
    tables.push(sc);
}

/// An inline V3 gives `LatchRequired`, then `submitCheckpoints` latches.
fn inline_v3_latch_required_then_submit_latches(tables: &mut Tables) {
    let mut env = tables.env(None);
    let k1 = env.k(1);
    let leaves = vec![env.transfer(0, AMOUNT, T0 + DAY)];
    let handoff = env
        .sim
        .block(1100, T0 + HOUR, leaves, Some(Rotate::Key(k1.clone())), None);
    let forged = env.forged(
        1102,
        T0 + HOUR + 2 * SECOND,
        PIN_GENERATION,
        env.pinned(),
        |_| {},
    );
    let handoff_cert = env.cert(&handoff).with_next(&k1);
    let mut sc = env.scenario(
        "inline_v3_latch_required_then_submit_latches",
        "an inline use of a violating certificate reverts LatchRequired; the relayer \
         resubmits it through submitCheckpoints, which latches",
    );
    sc.submit(&[forged], T0 + HOUR + MINUTE, "ok");
    sc.finalize(
        Source::Inline(&handoff_cert),
        &env.sim.message_proof(1100, 0, &handoff.header),
        T0 + HOUR + 2 * MINUTE,
        "LatchRequired",
    );
    sc.submit(&[handoff_cert], T0 + HOUR + 3 * MINUTE, "ok");
    tables.push(sc);
    tables.remember(&env);
}

/// A future-dated rotation: `t_eff` caps the successor's start at now.
fn future_dated_rotation_t_eff(tables: &mut Tables) {
    let mut env = tables.env(None);
    let k1 = env.k(1);
    let fut = env.key_change(1100, T0 + 10 * DAY, &k1);
    let mut sc = env.scenario(
        "future_dated_rotation_t_eff",
        "a rotation X timed 10 d ahead installs untilMs = now + validity_ms (t_eff = \
         min(X.timestamp_ms, now))",
    );
    sc.submit(&[env.cert(&fut).with_next(&k1)], T0 + HOUR, "ok");
    assert_eq!(sc.until_ms(), T0 + HOUR + VALIDITY);
    tables.push(sc);
    tables.remember(&env);
}

/// Finalization, history proofs, the supply cap and voids.
fn finalize_proofs_cap_and_voids(tables: &mut Tables) {
    let mut env = tables.env(None);
    let leaves = vec![
        env.transfer(0, 2 * AMOUNT, T0 + DAY),
        env.transfer(1, 3 * AMOUNT, T0 + DAY),
        env.transfer(2, AMOUNT, T0 + HOUR),
    ];
    let b10 = env.block_of(1010, T0 + 10 * SECOND, leaves);
    let leaves = vec![
        env.transfer(3, 4 * AMOUNT, T0 + DAY),
        env.transfer(4, 2 * AMOUNT, T0 + DAY),
    ];
    env.block_of(1020, T0 + 20 * SECOND, leaves);
    let b50 = env.block(1050, T0 + 50 * SECOND);
    // A transfer to the destination contract itself.
    let leaves = vec![env.sim.transfer(5, AMOUNT, T0 + DAY, &DESTINATION_ADDRESS)];
    let bad_recipient = env.block_of(1060, T0 + 60 * SECOND, leaves);
    let (x10, x50) = (b10.x(), b50.x());
    let sim = &env.sim;
    let mut sc = env.scenario(
        "finalize_proofs_cap_and_voids",
        "inline and checkpoint finalization, a history proof, replay, deadline, recipient, \
         supply-cap and proof failures, and voidExpired",
    );
    sc.finalize(
        Source::Inline(&env.cert(&b10)),
        &sim.message_proof(1010, 0, &b10.header),
        T0 + MINUTE,
        "ok",
    );
    sc.finalize(
        Source::Checkpoint(&x10),
        &sim.message_proof(1010, 1, &b10.header),
        T0 + MINUTE,
        "ok",
    );
    sc.finalize(
        Source::Checkpoint(&x10),
        &sim.message_proof(1010, 0, &b10.header),
        T0 + MINUTE,
        "AlreadyConsumed",
    );
    sc.finalize(
        Source::Inline(&env.cert(&b50)),
        &sim.message_proof(1020, 0, &b50.header),
        T0 + 2 * MINUTE,
        "ok",
    );
    sc.finalize(
        Source::Checkpoint(&x50),
        &sim.message_proof(1020, 1, &b50.header),
        T0 + 2 * MINUTE,
        "SupplyCapExceeded",
    );
    let third = sim.message_proof(1010, 2, &b10.header);
    let mut wrong_path = third.clone();
    wrong_path.path = std::iter::once([0xab; 32])
        .chain(third.path.iter().skip(1).copied())
        .collect();
    sc.finalize(
        Source::Checkpoint(&x10),
        &wrong_path,
        T0 + 2 * MINUTE,
        "BadProof",
    );
    // Transfer 2 has `deadline_ms = T0 + HOUR`: at that clock value a void is early, at the
    // next one a finalization is late.
    let stored = Source::Checkpoint(&x10);
    sc.void_expired(2, stored, &third, T0 + HOUR, "DeadlineNotReached");
    sc.finalize(stored, &third, T0 + HOUR + SECOND, "DeadlinePassed");
    sc.void_expired(1, stored, &third, T0 + HOUR + SECOND, "BadNonce");
    sc.void_expired(2, stored, &third, T0 + HOUR + SECOND, "ok");
    let late = T0 + HOUR + 2 * SECOND;
    sc.void_expired(2, stored, &third, late, "AlreadyConsumed");
    let to_contract = sim.message_proof(1060, 0, &bad_recipient.header);
    sc.finalize(
        Source::Checkpoint(&bad_recipient.x()),
        &to_contract,
        late,
        "UnknownCheckpoint",
    );
    sc.finalize(
        Source::Inline(&env.cert(&bad_recipient)),
        &to_contract,
        late,
        "BadRecipient",
    );
    sc.void_frozen(10, 1, late, "NotFrozen");
    tables.push(sc);
}

/// TON: `next_keys` of a key change, and a heartbeat without them.
fn ton_rotation_next_keys(tables: &mut Tables) {
    let mut env = tables.env(Some(DestinationFlavor::Ton));
    let k1 = env.k(1);
    let rot = env.key_change(1100, T0 + HOUR, &k1);
    let hb = env
        .sim
        .block(1200, T0 + DAY + HOUR, vec![], Some(Rotate::Heartbeat), None);
    let rc = env.cert(&rot).with_next(&k1);
    let mut sc = env.scenario(
        "ton_rotation_next_keys",
        "TON: a key-changing rotation needs next_keys hashing to X.next_committee_root \
         (missing or wrong → BadCommittee); a heartbeat keeps the stored keys without \
         next_keys",
    );
    let now = T0 + HOUR + MINUTE;
    sc.submit(&[rc.clone().with_next_keys(None)], now, "BadCommittee");
    let k2 = env.k(2);
    sc.submit(&[rc.clone().with_next_keys(Some(&k2))], now, "BadCommittee");
    sc.submit(&[rc], now, "ok");
    sc.submit(&[env.cert(&hb)], T0 + DAY + HOUR + MINUTE, "ok");
    tables.push(sc);
    tables.remember(&env);
}

/// TON: the order of checkpoint eviction.
fn ton_checkpoint_eviction(tables: &mut Tables) {
    let mut env = tables.env(Some(DestinationFlavor::Ton));
    let blocks: BTreeMap<u64, Block> = [1010, 1015, 1020, 1030, 1040]
        .into_iter()
        .map(|height| (height, env.block(height, T0 + (height - 1000) * SECOND)))
        .collect();
    let stray = env.block(1005, T0 + 5 * SECOND);
    let mut sc = env.scenario(
        "ton_checkpoint_eviction",
        "TON keeps three checkpoints: a higher height evicts the lowest, a height at or below \
         the lowest is not stored, conflicts are detected only for retained entries, an \
         evicted checkpoint is unknown",
    );
    for height in [1010, 1020, 1030] {
        sc.submit(&[env.cert(&blocks[&height])], T0 + 2 * MINUTE, "ok");
    }
    sc.submit(&[env.cert(&blocks[&1015])], T0 + 2 * MINUTE, "ok");
    sc.submit(&[env.cert(&stray)], T0 + 2 * MINUTE, "NothingToDo");
    sc.submit(&[env.cert(&blocks[&1040])], T0 + 2 * MINUTE, "ok");
    // Another header at a height: 1010 was evicted, 1030 is retained.
    let conflicting = |height: u64| {
        env.forged(
            height,
            T0 + (height - 1000) * SECOND,
            PIN_GENERATION,
            env.pinned(),
            |x| {
                x.message_count = 1;
                x.sccp_root = [0xee; 32];
            },
        )
    };
    sc.submit(&[conflicting(1010)], T0 + 3 * MINUTE, "NothingToDo");
    sc.finalize(
        Source::Checkpoint(&blocks[&1015].x()),
        &dummy_proof(&env, &blocks[&1015]),
        T0 + 3 * MINUTE,
        "UnknownCheckpoint",
    );
    sc.submit(&[conflicting(1030)], T0 + 4 * MINUTE, "ok");
    tables.push(sc);
}

/// A syntactically complete message proof for a call that fails before the proof is read.
fn dummy_proof(env: &Env, block: &Block) -> MessageProofV1 {
    MessageProofV1 {
        payload: env.transfer(0, AMOUNT, T0 + DAY).payload,
        leaf_index: 0,
        path: Vec::new(),
        block: BlockRefV1 {
            height: block.height,
            sccp_root: [0x01; 32],
            message_count: 1,
            history_index: 0,
            history_path: Vec::new(),
        },
    }
}

/// A sub-second Taira timestamp against the whole-second destination clock.
fn rotation_sub_second_deadline(tables: &mut Tables) {
    let mut env = tables.env(None);
    let k1 = env.k(1);
    let rot = env.key_change(1100, T0 + HOUR + 999, &k1);
    let after = env.block(1101, T0 + HOUR + 2 * SECOND);
    let later = env.block(1102, T0 + HOUR + 3 * SECOND);
    let until = T0 + HOUR + 999 + VALIDITY;
    let mut sc = env.scenario(
        "rotation_sub_second_deadline",
        "a rotation X with a sub-second timestamp_ms installs the sub-second untilMs = \
         t_eff(X) + validity_ms; the whole-second destination clock is Live at the last \
         second at or below untilMs and Frozen at the next one, which is untilMs + 1 ms",
    );
    sc.submit(&[env.cert(&rot).with_next(&k1)], T0 + HOUR + MINUTE, "ok");
    assert_eq!(sc.until_ms(), until);
    assert_eq!(until % SECOND, 999);
    sc.submit(&[env.cert(&after)], until - 999, "ok");
    sc.submit(&[env.cert(&later)], until + 1, "CommitteeNotAccepted");
    tables.push(sc);
    tables.remember(&env);
}

/// The mandatory cheap path (§5.1.3 step 8), and the identity signature that step 6 refuses
/// before it, on EVM and on TON: the two flavours must agree on a certificate whose `X` is
/// already stored.
fn cheap_path_identity_signature(tables: &mut Tables) {
    for (flavor, name) in [
        (None, "cheap_path_identity_signature"),
        (
            Some(DestinationFlavor::Ton),
            "ton_cheap_path_identity_signature",
        ),
    ] {
        let mut env = tables.env(flavor);
        let blk = env.block(1010, T0 + 10 * SECOND);
        let genuine = env.cert(&blk);
        let other_instance = env.cert_of(
            &blk.header,
            &blk.generation.committee,
            Some("X_1010_other_instance_signature"),
            &CertifyOptions {
                signed_instance: Some([0x78; 32]),
                ..CertifyOptions::default()
            },
        );
        let identity = Submission::new(
            Certificate {
                signature_evm: IDENTITY_SIGNATURE_EVM.to_vec(),
                signature_ton: IDENTITY_SIGNATURE.to_vec(),
                ..genuine.certificate.clone()
            },
            "X_1010_identity_signature",
            &genuine.signed_by,
        );
        let mut sc = env.scenario(
            name,
            "the cheap path is mandatory and observable: a certificate of X whose signature \
             covers another instance is refused while X is not stored and accepted without a \
             signature check once it is (nothing changes, so NothingToDo); the identity \
             signature is refused before the cheap path",
        );
        sc.submit(
            std::slice::from_ref(&other_instance),
            T0 + MINUTE,
            "BadSignature",
        );
        sc.submit(&[genuine], T0 + MINUTE, "ok");
        sc.submit(&[other_instance], T0 + 2 * MINUTE, "NothingToDo");
        sc.submit(&[identity], T0 + 2 * MINUTE, "BadSignature");
        tables.push(sc);
    }
}

/// Payload deadlines: a finalization needs `now_ms ≤ deadline_ms` and a void
/// `now_ms > deadline_ms`.
fn transfer_deadline_boundaries(tables: &mut Tables) {
    let mut env = tables.env(None);
    let whole = T0 + HOUR;
    let sub_second = T0 + 2 * HOUR + 999;
    let leaves = vec![
        env.transfer(0, AMOUNT, whole),
        env.transfer(1, AMOUNT, whole),
        env.transfer(2, AMOUNT, sub_second),
        env.transfer(3, AMOUNT, sub_second),
    ];
    let blk = env.block_of(1010, T0 + 10 * SECOND, leaves);
    let x = blk.x();
    let stored = Source::Checkpoint(&x);
    let proof = |leaf_index| env.sim.message_proof(1010, leaf_index, &blk.header);
    let mut sc = env.scenario(
        "transfer_deadline_boundaries",
        "a whole-second deadline_ms: at it a finalization is accepted and a void is early, \
         one second later the finalization is late and the void is accepted; a deadline_ms \
         ending in 999 ms: the same pairs at the last clock value below it (999 ms earlier) \
         and at the next one (1 ms later)",
    );
    sc.submit(&[env.cert(&blk)], T0 + MINUTE, "ok");
    sc.finalize(stored, &proof(0), whole, "ok");
    sc.void_expired(1, stored, &proof(1), whole, "DeadlineNotReached");
    sc.finalize(stored, &proof(1), whole + SECOND, "DeadlinePassed");
    sc.void_expired(1, stored, &proof(1), whole + SECOND, "ok");
    assert_eq!(sub_second % SECOND, 999);
    sc.finalize(stored, &proof(2), sub_second - 999, "ok");
    sc.void_expired(3, stored, &proof(3), sub_second - 999, "DeadlineNotReached");
    sc.finalize(stored, &proof(3), sub_second + 1, "DeadlinePassed");
    sc.void_expired(3, stored, &proof(3), sub_second + 1, "ok");
    tables.push(sc);
}

/// A Parliament-track control of the route that pauses nothing, with ids made of `tag`.
fn control(env: &Env, control_nonce: u64, tag: u8) -> LeafItem {
    env.sim.control(
        &ControlLeafV1 {
            control_nonce,
            track: 1,
            certificate_id: [0xc0 | tag; 32],
            effect_hash: [0xe0 | tag; 32],
            ..ControlLeafV1::default()
        },
        true,
    )
}

/// Checkpoint use after a rotation (§5.1.3): U1, a header of the current generation, or U2,
/// the handoff that installed it. Messages and controls of a retired generation are proven
/// under the handoff, with a history proof. The second scenario is the same rule on TON,
/// with the calls its minter decides alone: the checks of a finalization that precede the
/// bucket, and controls.
fn checkpoint_use_after_rotation(tables: &mut Tables) {
    let mut env = tables.env(None);
    let (k1, k2) = (env.k(1), env.k(2));
    let leaves = vec![
        control(&env, 1, 1),
        env.transfer(0, AMOUNT, T0 + DAY),
        env.transfer(1, AMOUNT, T0 + DAY),
        env.transfer(2, AMOUNT, T0 + 90 * MINUTE),
        env.transfer(3, AMOUNT, T0 + DAY),
    ];
    let b10 = env.block_of(1010, T0 + 10 * SECOND, leaves);
    let rot5 = env.key_change(1100, T0 + HOUR, &k1);
    let leaves = vec![env.transfer(4, AMOUNT, T0 + DAY)];
    let b1150 = env.block_of(1150, T0 + HOUR + MINUTE, leaves);
    let rot6 = env.key_change(1200, T0 + 2 * HOUR, &k2);
    let (x10, x1100, x1150, x1200) = (b10.x(), rot5.x(), b1150.x(), rot6.x());
    let (old, handoff5) = (Source::Checkpoint(&x10), Source::Checkpoint(&x1100));
    let sim = &env.sim;
    let mut sc = env.scenario(
        "checkpoint_use_after_rotation",
        "a stored checkpoint is usable while its header is of the current generation (U1) or \
         is the handoff that installed it (U2): after the handoff of generation 5 is \
         installed, a non-handoff checkpoint of generation 5 is refused for finalize, control \
         and void while the handoff checkpoint proves the same leaves through its history \
         root; after generation 7 is installed the handoff of generation 5 and every \
         non-handoff checkpoint of generations 5 and 6 are refused, and the handoff of \
         generation 6 is usable",
    );
    let now = T0 + MINUTE;
    sc.submit(&[env.cert(&b10)], now, "ok");
    sc.finalize(old, &sim.message_proof(1010, 1, &b10.header), now, "ok");
    let now = T0 + HOUR + MINUTE;
    sc.submit(&[env.cert(&rot5).with_next(&k1)], now, "ok");
    sc.finalize(
        old,
        &sim.message_proof(1010, 2, &b10.header),
        now,
        "CommitteeNotAccepted",
    );
    sc.apply_control(
        old,
        &sim.control_proof(1010, 0, &b10.header),
        now,
        "CommitteeNotAccepted",
    );
    sc.finalize(
        handoff5,
        &sim.message_proof(1010, 2, &rot5.header),
        now,
        "ok",
    );
    sc.apply_control(
        handoff5,
        &sim.control_proof(1010, 0, &rot5.header),
        now,
        "ok",
    );
    let now = T0 + 2 * HOUR;
    sc.void_expired(
        2,
        old,
        &sim.message_proof(1010, 3, &b10.header),
        now,
        "CommitteeNotAccepted",
    );
    sc.void_expired(
        2,
        handoff5,
        &sim.message_proof(1010, 3, &rot5.header),
        now,
        "ok",
    );
    let now = T0 + 2 * HOUR + MINUTE;
    sc.submit(
        &[env.cert(&b1150), env.cert(&rot6).with_next(&k2)],
        now,
        "ok",
    );
    for (header, x, expect) in [
        (&rot5.header, &x1100, "CommitteeNotAccepted"),
        (&b10.header, &x10, "CommitteeNotAccepted"),
        (&b1150.header, &x1150, "CommitteeNotAccepted"),
        (&rot6.header, &x1200, "ok"),
    ] {
        sc.finalize(
            Source::Checkpoint(x),
            &sim.message_proof(1010, 4, header),
            now,
            expect,
        );
    }
    tables.push(sc);
    tables.remember(&env);

    let mut env = tables.env(Some(DestinationFlavor::Ton));
    let (k1, k2) = (env.k(1), env.k(2));
    let leaves = vec![
        control(&env, 1, 1),
        control(&env, 2, 2),
        env.transfer(0, AMOUNT, T0 + DAY),
    ];
    let b10 = env.block_of(1010, T0 + 10 * SECOND, leaves);
    let rot5 = env.key_change(1100, T0 + HOUR, &k1);
    let rot6 = env.key_change(1200, T0 + 2 * HOUR, &k2);
    let (x10, x1100, x1200) = (b10.x(), rot5.x(), rot6.x());
    let (old, handoff5) = (Source::Checkpoint(&x10), Source::Checkpoint(&x1100));
    let sim = &env.sim;
    let mut sc = env.scenario(
        "ton_checkpoint_use_after_rotation",
        "TON: after the handoff of generation 5 is installed its non-handoff checkpoint is \
         refused and the handoff checkpoint applies the control through its history root; \
         after generation 7 is installed the handoff of generation 5 is refused and the \
         handoff of generation 6 is usable",
    );
    let now = T0 + HOUR + MINUTE;
    sc.submit(&[env.cert(&b10)], now, "ok");
    sc.submit(&[env.cert(&rot5).with_next(&k1)], now, "ok");
    sc.apply_control(
        old,
        &sim.control_proof(1010, 0, &b10.header),
        now,
        "CommitteeNotAccepted",
    );
    sc.finalize(
        old,
        &sim.message_proof(1010, 2, &b10.header),
        now,
        "CommitteeNotAccepted",
    );
    sc.apply_control(
        handoff5,
        &sim.control_proof(1010, 0, &rot5.header),
        now,
        "ok",
    );
    let now = T0 + 2 * HOUR + MINUTE;
    sc.submit(&[env.cert(&rot6).with_next(&k2)], now, "ok");
    sc.apply_control(
        handoff5,
        &sim.control_proof(1010, 1, &rot5.header),
        now,
        "CommitteeNotAccepted",
    );
    sc.finalize(
        handoff5,
        &sim.message_proof(1010, 2, &rot5.header),
        now,
        "CommitteeNotAccepted",
    );
    sc.apply_control(
        Source::Checkpoint(&x1200),
        &sim.control_proof(1010, 1, &rot6.header),
        now,
        "ok",
    );
    tables.push(sc);
    tables.remember(&env);
}

/// `voidFrozen` checks its range before `Frozen` (§5.1.8): every range failure on a `Live`
/// destination, then a valid range, which is `NotFrozen`. No certificate is involved.
fn void_frozen_range_before_frozen(tables: &mut Tables) {
    for (flavor, name) in [
        (None, "void_frozen_range_before_frozen"),
        (
            Some(DestinationFlavor::Ton),
            "ton_void_frozen_range_before_frozen",
        ),
    ] {
        let env = tables.env(flavor);
        let mut sc = env.scenario(
            name,
            "voidFrozen on a Live destination: a range failure is reported before NotFrozen \
             (count 0, a count above the bound, a range past 2^64 and, on TON, a range that \
             crosses a 512-nonce bucket); a valid range is NotFrozen",
        );
        let now = T0 + MINUTE;
        let (ranges, refusal): (&[(u64, u64)], &str) = match env.flavor {
            DestinationFlavor::Evm => (&[(10, 0), (10, 257), (u64::MAX, 2)], "BadAmount"),
            DestinationFlavor::Ton => (&[(10, 0), (10, 513), (510, 4), (u64::MAX, 2)], "BadRange"),
        };
        for (first, count) in ranges {
            sc.void_frozen(*first, *count, now, refusal);
        }
        sc.void_frozen(10, 1, now, "NotFrozen");
        tables.push(sc);
    }
}

/// Two faults in one call, which the check order decides. EVM obtains `X` first; the TON
/// minter checks the payload and its recipient before `X` (§5.3.4), because its required
/// value depends on the payload nonce. On both flavours the deadline is checked before the
/// leaf path.
fn finalize_two_faults(tables: &mut Tables) {
    for (flavor, name) in [
        (None, "finalize_two_faults"),
        (Some(DestinationFlavor::Ton), "ton_finalize_two_faults"),
    ] {
        let mut env = tables.env(flavor);
        let evm = env.flavor == DestinationFlavor::Evm;
        let own_word = env.sim.destination_word;
        let to_contract = if env.ton_route {
            [&[0_u8; 4][..], &own_word].concat()
        } else {
            own_word[12..].to_vec()
        };
        let leaves = vec![env.transfer(0, AMOUNT, T0 + HOUR)];
        let blk = env.block_of(1010, T0 + 10 * SECOND, leaves);
        let never_stored = env.block(1020, T0 + 20 * SECOND);
        let payload = |revision: u32, recipient: &[u8]| {
            SccpTransferPayloadV1::outbound(
                env.sim.target,
                0,
                revision,
                T0 + DAY,
                AMOUNT,
                DEFAULT_SENDER.to_vec(),
                recipient.to_vec(),
            )
            .and_then(|payload| payload.encode())
            .expect("a valid outbound payload")
        };
        let proof = |payload: Vec<u8>| MessageProofV1 {
            payload,
            leaf_index: 0,
            path: Vec::new(),
            block: BlockRefV1 {
                height: never_stored.height,
                sccp_root: [0x01; 32],
                message_count: 1,
                history_index: 0,
                history_path: Vec::new(),
            },
        };
        let other_revision = proof(payload(2, env.recipient()));
        let own_recipient = proof(payload(1, &to_contract));
        let x_unknown = never_stored.x();
        let unknown = Source::Checkpoint(&x_unknown);
        let mut sc = env.scenario(
            name,
            "two faults in one call: a payload of another revision, or one that pays the \
             contract itself, under a checkpoint that is not stored (EVM reports the \
             checkpoint, the TON minter the payload); a finalization after the deadline with a \
             wrong leaf path (the deadline is reported); a void with a wrong nonce argument \
             under a checkpoint that is not stored",
        );
        let expect = |ton: &'static str| if evm { "UnknownCheckpoint" } else { ton };
        sc.finalize(unknown, &other_revision, T0 + MINUTE, expect("BadPayload"));
        sc.finalize(unknown, &own_recipient, T0 + MINUTE, expect("BadRecipient"));
        sc.void_expired(
            7,
            unknown,
            &other_revision,
            T0 + MINUTE,
            expect("BadPayload"),
        );
        sc.submit(&[env.cert(&blk)], T0 + MINUTE, "ok");
        let mut late = env.sim.message_proof(1010, 0, &blk.header);
        // One sibling too many for a block of one leaf.
        late.path = vec![[0xab; 32]];
        sc.finalize(
            Source::Checkpoint(&blk.x()),
            &late,
            T0 + HOUR + SECOND,
            "DeadlinePassed",
        );
        tables.push(sc);
    }
}

/// Check orders that a single fault cannot show (EVM): the §3.4 constraints before the
/// control nonce, a consumed nonce before the supply cap, and the nonce argument of
/// `voidExpired` before the consumed set.
fn check_order_two_faults(tables: &mut Tables) {
    let mut env = tables.env(None);
    let leaves = vec![
        control(&env, 5, 5),
        env.sim.control(
            &ControlLeafV1 {
                control_nonce: 3,
                track: 3,
                certificate_id: [0xc3; 32],
                effect_hash: [0xe3; 32],
                ..ControlLeafV1::default()
            },
            false,
        ),
        env.transfer(0, SUPPLY_CAP, T0 + HOUR),
    ];
    let blk = env.block_of(1010, T0 + 10 * SECOND, leaves);
    let x = blk.x();
    let stored = Source::Checkpoint(&x);
    let sim = &env.sim;
    let mut sc = env.scenario(
        "check_order_two_faults",
        "a control leaf with track 3 and a nonce below the stored one is BadControl, not \
         StaleControl; a finalization of a consumed nonce at a full supply cap is \
         AlreadyConsumed, not SupplyCapExceeded; a voidExpired of a consumed payload with a \
         wrong nonce argument is BadNonce, not AlreadyConsumed",
    );
    sc.submit(&[env.cert(&blk)], T0 + MINUTE, "ok");
    sc.apply_control(
        stored,
        &sim.control_proof(1010, 0, &blk.header),
        T0 + MINUTE,
        "ok",
    );
    sc.apply_control(
        stored,
        &sim.control_proof(1010, 1, &blk.header),
        T0 + MINUTE,
        "BadControl",
    );
    let transfer = sim.message_proof(1010, 2, &blk.header);
    sc.finalize(stored, &transfer, T0 + MINUTE, "ok");
    if env.strict {
        // The cap is full.
        assert_eq!(sc.0.destination.state().total_supply, SUPPLY_CAP);
    }
    sc.finalize(stored, &transfer, T0 + MINUTE, "AlreadyConsumed");
    sc.void_expired(1, stored, &transfer, T0 + HOUR + SECOND, "BadNonce");
    sc.void_expired(0, stored, &transfer, T0 + HOUR + SECOND, "AlreadyConsumed");
    tables.push(sc);
}

/// The encodings of step 6 are enforced on the cheap path too (EVM): the same stored `X`
/// under a signer `y` that is not reduced, a signer `y` of the other sign, and a `σ` limb
/// that is not reduced.
fn cheap_path_checks_encodings(tables: &mut Tables) {
    let mut env = tables.env(None);
    let blk = env.block(1010, T0 + 10 * SECOND);
    let genuine = env.cert(&blk);
    let certificate = &genuine.certificate;
    let first = |bytes: &[u8]| -> [u8; FP_LEN] {
        bytes[..FP_LEN]
            .try_into()
            .expect("at least one field element")
    };
    let (y0, limb0) = (
        first(&certificate.signer_ys),
        first(&certificate.signature_evm),
    );
    let with_first = |bytes: &[u8], value: [u8; FP_LEN]| [&value[..], &bytes[FP_LEN..]].concat();
    let variant = |label: &str, changed: Certificate| {
        Submission::new(changed, &format!("X_1010_{label}"), &genuine.signed_by)
    };
    let mut sc = env.scenario(
        "cheap_path_checks_encodings",
        "the encodings of step 6 are checked before the cheap path: once X is stored, the same \
         certificate with signerYs[0] + p, with signerYs[0] = p − y (the other sign) or with \
         the first σ limb + p is refused, and the unchanged certificate is accepted without a \
         signature check (NothingToDo)",
    );
    sc.submit(std::slice::from_ref(&genuine), T0 + MINUTE, "ok");
    let now = T0 + 2 * MINUTE;
    sc.submit(
        &[variant(
            "signer_y_ge_p",
            Certificate {
                signer_ys: with_first(&certificate.signer_ys, fp_add(&y0, &BLS12_381_P)),
                ..certificate.clone()
            },
        )],
        now,
        "BadCommittee",
    );
    sc.submit(
        &[variant(
            "signer_y_wrong_sign",
            Certificate {
                signer_ys: with_first(&certificate.signer_ys, fp_sub(&BLS12_381_P, &y0)),
                ..certificate.clone()
            },
        )],
        now,
        "BadCommittee",
    );
    sc.submit(
        &[variant(
            "sigma_limb_ge_p",
            Certificate {
                signature_evm: with_first(&certificate.signature_evm, fp_add(&limb0, &BLS12_381_P)),
                ..certificate.clone()
            },
        )],
        now,
        "BadSignature",
    );
    sc.submit(std::slice::from_ref(&genuine), now, "NothingToDo");
    tables.push(sc);
}

/// A reference to the certified block itself carries no history proof (§5.1.5):
/// `historyIndex = 0` and an empty `historyPath`. Each refused proof differs from an accepted
/// one in that one field only. The TON row keeps to what its minter decides alone: the
/// refusals, and the control.
fn same_height_block_ref_with_history(tables: &mut Tables) {
    for (flavor, name) in [
        (None, "same_height_block_ref_with_history"),
        (
            Some(DestinationFlavor::Ton),
            "ton_same_height_block_ref_with_history",
        ),
    ] {
        let mut env = tables.env(flavor);
        let leaves = vec![
            control(&env, 1, 1),
            env.transfer(0, AMOUNT, T0 + DAY),
            env.transfer(1, AMOUNT, T0 + HOUR),
        ];
        let blk = env.block_of(1010, T0 + 10 * SECOND, leaves);
        let genuine = env.cert(&blk);
        let x = blk.x();
        let stored = Source::Checkpoint(&x);
        let sim = &env.sim;
        let control_proof = sim.control_proof(1010, 0, &blk.header);
        let mint = sim.message_proof(1010, 1, &blk.header);
        let void = sim.message_proof(1010, 2, &blk.header);
        // The two ways to attach a history proof to a reference that takes none.
        let changes: [fn(&mut BlockRefV1); 2] = [
            |block| block.history_index = 1,
            |block| block.history_path = vec![[0xab; 32]],
        ];
        let message_with = |proof: &MessageProofV1, change: fn(&mut BlockRefV1)| {
            let mut proof = proof.clone();
            change(&mut proof.block);
            proof
        };
        let control_with = |change: fn(&mut BlockRefV1)| {
            let mut proof = control_proof.clone();
            change(&mut proof.block);
            proof
        };
        let mut sc = env.scenario(
            name,
            "a reference to the certified block itself carries no history proof: with \
             historyIndex 1, or with a historyPath of one sibling, it is BadProof for an inline \
             finalization and, under the stored checkpoint, for a control, a finalization and a \
             void; the unchanged proofs are accepted (in the TON row the control only: a mint \
             and a void end in the bucket)",
        );
        let now = T0 + MINUTE;
        sc.finalize(
            Source::Inline(&genuine),
            &message_with(&mint, changes[0]),
            now,
            "BadProof",
        );
        sc.submit(std::slice::from_ref(&genuine), now, "ok");
        for change in changes {
            sc.apply_control(stored, &control_with(change), now, "BadProof");
        }
        for change in changes {
            sc.finalize(stored, &message_with(&mint, change), now, "BadProof");
        }
        // The first clock value after the deadline of transfer 1.
        let late = T0 + HOUR + SECOND;
        for change in changes {
            sc.void_expired(1, stored, &message_with(&void, change), late, "BadProof");
        }
        sc.apply_control(stored, &control_proof, late, "ok");
        if env.flavor == DestinationFlavor::Evm {
            sc.finalize(stored, &mint, late, "ok");
            sc.void_expired(1, stored, &void, late, "ok");
        }
        tables.push(sc);
    }
}

/// An inline entry point obtains `X` before it checks `Live` (§5.1.2 "Check order and
/// errors"). After the deadline of the pinned generation no certificate was stored, so each
/// call verifies its certificate in full first.
fn inline_calls_after_expiry(tables: &mut Tables) {
    for (flavor, name) in [
        (None, "inline_calls_after_expiry"),
        (
            Some(DestinationFlavor::Ton),
            "ton_inline_calls_after_expiry",
        ),
    ] {
        let mut env = tables.env(flavor);
        // The first clock value after the pin's deadline.
        let expired = T0 + VALIDITY + SECOND;
        let leaves = vec![
            control(&env, 1, 1),
            env.transfer(0, AMOUNT, expired + DAY),
            env.transfer(1, AMOUNT, T0 + HOUR),
        ];
        let blk = env.block_of(1010, T0 + 10 * SECOND, leaves);
        let genuine = env.cert(&blk);
        let other_instance = env.cert_of(
            &blk.header,
            &blk.generation.committee,
            Some("X_1010_other_instance_signature"),
            &CertifyOptions {
                signed_instance: Some([0x78; 32]),
                ..CertifyOptions::default()
            },
        );
        let sim = &env.sim;
        let control_proof = sim.control_proof(1010, 0, &blk.header);
        let mint = sim.message_proof(1010, 1, &blk.header);
        let void = sim.message_proof(1010, 2, &blk.header);
        let mut sc = env.scenario(
            name,
            "an inline entry point obtains X before it checks Live: on a destination whose \
             generation has expired, a certificate whose signature covers another instance is \
             BadSignature for a finalization, a control and a void, and the genuine certificate \
             of the current generation is CommitteeNotAccepted; neither stores a checkpoint",
        );
        for (certificate, outcome) in [
            (&other_instance, "BadSignature"),
            (&genuine, "CommitteeNotAccepted"),
        ] {
            let inline = Source::Inline(certificate);
            sc.finalize(inline, &mint, expired, outcome);
            sc.apply_control(inline, &control_proof, expired, outcome);
            sc.void_expired(1, inline, &void, expired, outcome);
        }
        tables.push(sc);
    }
}

// ---------------------------------------------------------------------------------------------
// TON replay
// ---------------------------------------------------------------------------------------------

/// A recorded state without the committee keys, which only a TON destination stores.
fn without_keys(state: &Value) -> Value {
    let mut state = state.clone();
    if let Some(committee) = state.get_mut("committee").and_then(Value::as_object_mut) {
        committee.remove("keys");
    }
    state
}

/// Whether a TON harness replays the EVM row `evm` unchanged, given `ton`, the same calls
/// recorded on the TON model (keys in storage, three checkpoint slots): every call is a
/// checkpoint submission of one certificate or a `views` step, and the two rows agree on the
/// outcome and events of every call and on the state after every step.
fn ton_replayable(evm: &Value, ton: &Value) -> bool {
    let (evm_steps, ton_steps) = (steps_of(evm), steps_of(ton));
    evm_steps.len() == ton_steps.len()
        && evm_steps.iter().zip(ton_steps).all(|(evm_step, ton_step)| {
            let same_result = match evm_step["call"].as_str() {
                Some("views") => true,
                Some("submitCheckpoints") => {
                    evm_step["certificates"].as_array().map(Vec::len) == Some(1)
                        && evm_step["expected"] == ton_step["expected"]
                }
                _ => false,
            };
            same_result
                && without_keys(&evm_step["state_after"]) == without_keys(&ton_step["state_after"])
        })
}

/// A `ton_replayable` row tells a TON harness to send each certificate with its
/// `ton_next_keys`: every key-changing rotation the row installs must therefore be pooled
/// with the successor committee.
///
/// # Panics
/// When a rotation the row installs is pooled without the keys of its successor root.
fn check_successor_keys(row: &Value, pool: &Value, committees: &BTreeMap<String, Committee>) {
    let name = row["name"].as_str().expect("a scenario row has a name");
    for step in steps_of(row) {
        let rotated = step["expected"]["events"].as_array().is_some_and(|events| {
            events
                .iter()
                .any(|event| event["event"] == text("SccpCommitteeRotated"))
        });
        if !rotated {
            continue;
        }
        for id in step["certificates"].as_array().expect("a checkpoint step") {
            let id = id.as_str().expect("a pool id");
            let entry = &pool[id];
            let fields = &entry["header_fields"];
            let is_rotation = fields["flags"]
                .as_u64()
                .is_some_and(|flags| flags & u64::from(FLAG_ROTATION) != 0);
            if !is_rotation || fields["next_committee_root"] == fields["committee_root"] {
                continue;
            }
            let installs = entry["ton_next_keys"]
                .as_str()
                .and_then(|named| committees.get(named))
                .is_some_and(|committee| hx(&committee.root()) == fields["next_committee_root"]);
            assert!(
                installs,
                "{name}: {id} is pooled without the successor keys it installs"
            );
        }
    }
}

/// The deployment bound on `initialUntilMs` (§5.2.1 constructor, §5.3.1 `sccp_init`), around
/// both ends.
fn init_bound_rows() -> Value {
    let now = T0;
    let span = MAX_VALIDITY_MS + MAX_INIT_SLACK_MS;
    list(
        [
            ("until_before_now", now - SECOND, "BadConfig"),
            ("until_equals_now", now, "BadConfig"),
            ("until_one_ms_after_now", now + 1, "ok"),
            ("until_at_the_bound", now + span, "ok"),
            ("until_one_ms_above_the_bound", now + span + 1, "BadConfig"),
        ]
        .map(|(label, until, expected)| {
            assert_eq!(
                init_until_ms_is_valid(now, until),
                expected == "ok",
                "{label}"
            );
            obj([
                ("label", text(label)),
                ("now_ms", num(now)),
                ("until_ms", num(until)),
                ("expected", text(expected)),
            ])
        }),
    )
}

/// The TON message of §5.3.2 for each EVM entry point a scenario step can name.
fn ton_call_names_json() -> Value {
    let mut out = obj([]);
    for (evm, ton) in TON_CALL_NAMES {
        insert(&mut out, evm, text(ton));
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The tables of §5.2.2
// ---------------------------------------------------------------------------------------------

/// The selector of a canonical function signature: the first four bytes of its Keccak-256.
fn selector_of(signature: &str) -> [u8; 4] {
    let hash = keccak256(&[signature.as_bytes()]);
    [hash[0], hash[1], hash[2], hash[3]]
}

/// The entry points and views of §5.2.2 with their selectors, each recomputed from its
/// signature and asserted against the specification value.
fn selectors_json() -> Value {
    let mut out = obj([]);
    for (name, signature, specified) in SELECTORS {
        let computed = selector_of(signature);
        assert_eq!(
            computed, specified,
            "{name}: the selector differs from the specification value"
        );
        insert(
            &mut out,
            name,
            obj([("signature", text(signature)), ("selector", hx(&computed))]),
        );
    }
    out
}

/// The SCCP events of §5.2.2 with `topic0`, each recomputed from its signature and asserted
/// against the specification value.
fn event_topics_json() -> Value {
    let mut out = obj([]);
    for (name, signature, specified) in EVENT_TOPICS {
        let topic = keccak256(&[signature.as_bytes()]);
        assert_eq!(
            topic, specified,
            "{name}: the topic differs from the specification value"
        );
        insert(
            &mut out,
            name,
            obj([("signature", text(signature)), ("topic0", hx(&topic))]),
        );
    }
    out
}

/// The error table of §5.2.2: every shared name with its TON exit code (`null` for an error
/// only EVM has), and the TON-only names.
fn error_codes_json() -> Value {
    let (mut shared, mut ton_only) = (obj([]), obj([]));
    for error in DestinationError::ALL {
        let code = error
            .ton_exit_code()
            .map_or(Value::Null, |code| num(code.into()));
        let table = if error.is_ton_only() {
            &mut ton_only
        } else {
            &mut shared
        };
        insert(table, error.name(), code);
    }
    obj([
        (
            "note",
            text(
                "§5.2.2: the EVM error name and its TON exit code (null: EVM only); scenario \
                 outcomes use the names",
            ),
        ),
        ("shared", shared),
        ("ton_only", ton_only),
    ])
}

/// The error names and the check order of §5.1.2, §5.1.3 and §5.1.8 for the cases where a
/// harness could otherwise key on another name: the file repeats them as one table.
fn error_choices_json() -> Value {
    let name = |error: DestinationError| text(error.name());
    obj([
        ("not_live_latched", name(DestinationError::Equivocated)),
        (
            "not_live_expired",
            name(DestinationError::CommitteeNotAccepted),
        ),
        (
            "length_qc_or_signature_or_signer_ys",
            name(DestinationError::BadCertificate),
        ),
        ("length_x", name(DestinationError::BadHeader)),
        ("length_committee", name(DestinationError::BadCommittee)),
        (
            "signer_key_flags_sign_y_or_off_curve",
            name(DestinationError::BadCommittee),
        ),
        (
            "signer_key_x_not_reduced_or_zero_coordinates",
            name(DestinationError::BadCommittee),
        ),
        ("signature_identity", name(DestinationError::BadSignature)),
        (
            "signature_encoding_subgroup_or_pairing",
            name(DestinationError::BadSignature),
        ),
        (
            "aggregate_key_identity",
            obj([
                ("evm", name(DestinationError::BadCommittee)),
                ("ton", name(DestinationError::BadSignature)),
            ]),
        ),
        (
            "aggregate_key_outside_g1",
            name(DestinationError::BadSignature),
        ),
        (
            "ton_signer_key_refused_by_the_opcode",
            name(DestinationError::BadSignature),
        ),
        (
            "checkpoint_not_current_or_installing_handoff",
            name(DestinationError::CommitteeNotAccepted),
        ),
        (
            "void_frozen_range",
            obj([
                ("evm", name(DestinationError::BadAmount)),
                ("ton", name(DestinationError::BadRange)),
            ]),
        ),
        (
            "check_order",
            text(
                "submitCheckpoints checks TooManyCertificates, then an empty batch \
                 (NothingToDo), then Live, then each certificate; the inline entry points \
                 obtain X first (VerifyCertificate with V1–V3 → LatchRequired) and check Live \
                 after it, in the §5.1.5 step order; the checkpoint entry points check the X \
                 length (BadHeader), the stored id (UnknownCheckpoint), X1–X7 with ACTIVE \
                 (BadHeader), Live, and then that X is of the current generation or the \
                 handoff that installed it (CommitteeNotAccepted); VerifyCertificate checks \
                 the key and signature encodings of step 6, including the identity signature \
                 on both flavors, before the cheap path of step 8; on EVM step 10 reports apk \
                 = O (BadCommittee) before step 11 reads σ as a point; a TON finalize or void \
                 checks the payload and its recipient (BadPayload, BadRecipient) before it \
                 obtains X (§5.3.4), while EVM checks them after X, Live, the pause and the \
                 block reference; on both flavors the deadline is checked before the leaf \
                 path, a consumed nonce (AlreadyConsumed) before the supply cap, the §3.4 \
                 constraints (BadControl) before the control nonce (StaleControl), and the \
                 nonce argument of voidExpired (BadNonce) before the consumed set; voidFrozen \
                 checks the range before Frozen",
            ),
        ),
        (
            "note",
            text(
                "these are the error names and the check order of specs/sccp.md §5.1.2, \
                 §5.1.3 and §5.1.8, repeated here so that every harness keys on one table",
            ),
        ),
    ])
}

/// The §3.9 constants a harness needs, and the rule of the cheap path.
fn constants_json() -> Value {
    obj([
        (
            "max_certificates_per_call",
            num(MAX_CERTIFICATES_PER_CALL as u64),
        ),
        ("ton_checkpoint_slots", num(TON_CHECKPOINT_SLOTS as u64)),
        (
            "max_void_frozen_range_evm",
            num(DestinationFlavor::Evm.max_void_frozen_range()),
        ),
        (
            "max_void_frozen_range_ton",
            num(DestinationFlavor::Ton.max_void_frozen_range()),
        ),
        ("max_validity_ms", num(MAX_VALIDITY_MS)),
        ("max_init_slack_ms", num(MAX_INIT_SLACK_MS)),
        (
            "cheap_path",
            text(
                "mandatory: taken when checkpoint[X.height] = keccak256(X), after the checks \
                 of steps 1–6; steps 9–12 (the signature check and the SccpCertificate event) \
                 are skipped",
            ),
        ),
    ])
}

// ---------------------------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------------------------

/// The complete `committee_transitions_v1.json` document.
fn transitions_document() -> Value {
    let tables = build_scenarios(DestinationFlavor::Evm);
    let replay: BTreeMap<String, Value> = build_scenarios(DestinationFlavor::Ton)
        .scenarios
        .iter()
        .map(|scenario| (scenario.name.clone(), scenario.as_json()))
        .collect();
    assert_eq!(
        replay.len(),
        tables.scenarios.len(),
        "scenario names are unique"
    );
    let pool = tables.pool.borrow().as_json();
    let scenarios: Vec<Value> = tables
        .scenarios
        .iter()
        .map(|scenario| {
            let mut row = scenario.as_json();
            let on_ton = scenario.destination.deployment().network == SccpNetworkV1::TonMainnet;
            assert_eq!(
                scenario.flavor() == DestinationFlavor::Ton,
                on_ton,
                "{}: the flavor and the profile disagree",
                scenario.name
            );
            if scenario.flavor() == DestinationFlavor::Evm {
                let replayable = ton_replayable(&row, &replay[&scenario.name]);
                insert(&mut row, "ton_replayable", Value::Bool(replayable));
                if replayable {
                    check_successor_keys(&row, &pool, &tables.committees);
                }
            }
            // A row reports only errors its flavour has.
            check_scenario_outcomes(&row);
            row
        })
        .collect();
    let mut committees = obj([]);
    for (name, committee) in &tables.committees {
        insert(&mut committees, name, committee.as_json());
    }
    obj([
        ("schema", text("iroha.sccp.committee-transitions.v1")),
        (
            "spec",
            text("specs/sccp.md §5.1.2–§5.1.8, §11.1 (revision 5)"),
        ),
        ("generator", text(REFERENCE_GENERATORS)),
        (
            "conventions",
            text(&format!(
                "each scenario deploys a fresh destination from `deployment` (its \
                 `initial_state`), then runs `steps` in order; a step is (state, call, now_ms) \
                 → (state_after, expected.outcome, expected.events). \
                 {DESTINATION_CLOCK_CONVENTION}; {SCENARIO_CLOCK_CONVENTION}. `ok` is success \
                 (a latch or a lost Live inside submitCheckpoints is success with `stopped`); \
                 any other outcome is the §5.2.2 error and the call changes nothing. \
                 Certificates are pooled under `certificates` and referenced by id; an \
                 SccpCertificate event names the pooled certificate whose QC_FIXED, header and \
                 signature it publishes; `committees` resolve `signed_by` and TON `next_keys`. \
                 A step names its call as its flavor does: the EVM entry point, or the TON \
                 message of §5.3.2 (`ton_call_names`). An EVM scenario runs on \
                 ethereum-mainnet with the destination word word(0x22…22) and 20-byte \
                 recipients. A TON scenario runs on ton-mainnet: Taira's leaves use \
                 lane_bytes(sora-taira, ton-mainnet), recipients are 36-byte accounts of \
                 workchain 0, and the destination word is the harness-installed minter account id \
                 0x35…35. Events list the SCCP events only (the ERC-20 Transfer of a mint is \
                 implied). `state_after.checkpoints` is a set (sorted by height for \
                 readability). `ton_replayable` marks EVM scenarios that a TON harness replays \
                 as one sccp_checkpoint message per step (using each certificate's `ton` form \
                 and `ton_next_keys`) with identical outcomes and state; such a row contains \
                 checkpoint submissions only, which do not depend on the profile. \
                 `init_bounds` lists the deployment bound on the pinned untilMs: the \
                 constructor (EVM) or sccp_init (TON) at `now_ms` accepts `until_ms` iff \
                 now_ms < until_ms ≤ now_ms + max_validity_ms + max_init_slack_ms, and answers \
                 BadConfig otherwise"
            )),
        ),
        ("error_choices", error_choices_json()),
        ("constants", constants_json()),
        ("event_topics", event_topics_json()),
        ("selectors", selectors_json()),
        ("ton_call_names", ton_call_names_json()),
        ("init_bounds", init_bound_rows()),
        ("error_codes", error_codes_json()),
        ("committees", committees),
        ("scenarios", Value::Array(scenarios)),
        ("certificates", pool),
        (
            "model_scope",
            list([
                text(
                    "TON finalize and void bucket round trips and bounce recovery (§5.3.4) are \
                     covered by the Acton contract harness. These atomic-model ton_* scenarios \
                     contain only steps the minter decides alone: checkpoints, controls, and \
                     finalize, void and voidFrozen steps that it refuses before any bucket message",
                ),
                text(
                    "The Acton harness installs the minter at account id 0x35…35 in workchain 0. \
                     The applied controls of ton_checkpoint_use_after_rotation and \
                     ton_same_height_block_ref_with_history commit to that destination word in their leaves",
                ),
                text(
                    "The Acton harness and finality_v1.json pin BadSignature when \
                     BLS_FASTAGGREGATEVERIFY refuses a signer key that is no canonical point, \
                     is the identity or lies outside G1 \
                     (error_choices.ton_signer_key_refused_by_the_opcode)",
                ),
            ]),
        ),
    ])
}

/// The document, built once for the tests that read it.
static DOCUMENT: LazyLock<Value> = LazyLock::new(transitions_document);

/// The scenario rows of the document.
fn scenarios(document: &Value) -> &[Value] {
    document["scenarios"]
        .as_array()
        .expect("the document lists its scenarios")
}

// ---------------------------------------------------------------------------------------------
// Drift check and regeneration
// ---------------------------------------------------------------------------------------------

#[test]
fn reference_committee_transitions_v1_matches_committed_fixture() {
    assert_matches_committed(TRANSITIONS, &DOCUMENT, REGENERATE_COMMAND);
}

#[test]
#[ignore = "rewrites fixtures/sccp/committee_transitions_v1.json; run only after a reviewed change"]
fn regenerate_committee_transitions_v1() {
    write_fixture(TRANSITIONS, &DOCUMENT);
}

// ---------------------------------------------------------------------------------------------
// The regenerated document
// ---------------------------------------------------------------------------------------------

/// Every outcome of the document is `ok` or a name of the §5.2.2 error table that the row's
/// flavour can report, and the table the document prints is the one of `destination_abi`.
#[test]
fn every_scenario_outcome_is_a_named_error() {
    let rows = scenarios(&DOCUMENT);
    let mut reported = BTreeSet::new();
    for row in rows {
        reported.extend(check_scenario_outcomes(row));
        // A TON harness replays the row: every error it reports has an exit code.
        if row["ton_replayable"] == Value::Bool(true) {
            for step in steps_of(row) {
                let outcome = step_outcome(step);
                let exit_code =
                    DestinationError::from_name(outcome).and_then(DestinationError::ton_exit_code);
                assert!(
                    outcome == "ok" || exit_code.is_some(),
                    "{:?}: a TON harness cannot report {outcome}",
                    row["name"].as_str()
                );
            }
        }
    }
    let flavors: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["flavor"].as_str())
        .collect();
    assert_eq!(flavors, BTreeSet::from(["evm", "ton"]));
    // The rows exercise the errors of the committee state machine and of checkpoint use.
    for name in [
        "CommitteeNotAccepted",
        "Equivocated",
        "LatchRequired",
        "NothingToDo",
        "TooManyCertificates",
        "UnknownCheckpoint",
        "NotFrozen",
        "BadCommittee",
        "BadSignature",
    ] {
        assert!(reported.contains(name), "no row reports {name}");
    }
    // Every reported name is in the table the document prints, under the code of the model.
    let codes = &DOCUMENT["error_codes"];
    for name in reported {
        let error = DestinationError::from_name(name).expect("a name of the table");
        let table = if error.is_ton_only() {
            "ton_only"
        } else {
            "shared"
        };
        assert_eq!(
            codes[table].get(name),
            Some(
                &error
                    .ton_exit_code()
                    .map_or(Value::Null, |code| num(code.into()))
            ),
            "{name}"
        );
    }
}

/// The destination clock convention holds on every step of the document: `now_ms` is a whole
/// second and never decreases inside a scenario. Taira-side times keep their milliseconds:
/// `Live` flips between the last clock value at or below `untilMs` and the next one, for a
/// whole-second and for a sub-second `untilMs`.
#[test]
fn every_step_uses_the_destination_clock() {
    let rows = scenarios(&DOCUMENT);
    let steps: usize = rows.iter().map(check_scenario_clock).sum();
    assert!(steps > rows.len(), "the scenarios have steps");

    // (untilMs is sub-second, now_ms − untilMs, Live) of every step of an unlatched
    // destination.
    let mut probes = BTreeSet::new();
    for row in rows {
        for step in steps_of(row) {
            let state = &step["state_after"];
            let now_ms = step["now_ms"].as_u64().expect("now_ms");
            let until_ms = state["committee"]["until_ms"].as_u64().expect("until_ms");
            let equivocated = state["equivocated"].as_bool().expect("equivocated");
            let live = state["live"].as_bool().expect("live");
            assert_eq!(
                live,
                !equivocated && now_ms <= until_ms,
                "{:?} at {now_ms}",
                row["name"].as_str()
            );
            if !equivocated {
                probes.insert((
                    !until_ms.is_multiple_of(SECOND),
                    i128::from(now_ms) - i128::from(until_ms),
                    live,
                ));
            }
        }
    }
    let second = i128::from(SECOND);
    for probe in [
        (false, 0, true),
        (false, second, false),
        (true, -999, true),
        (true, 1, false),
    ] {
        assert!(probes.contains(&probe), "no step probes {probe:?}");
    }
}

/// Payload deadlines are probed from both sides by whole-second clock values: a finalization
/// is accepted up to `deadline_ms` and a void from the first clock value after it, for a
/// whole-second deadline and for one that ends in 999 ms.
#[test]
fn payload_deadlines_are_probed_from_both_sides() {
    // (finalize or void, outcome, the deadline is sub-second, now_ms − deadline_ms).
    let mut probes = BTreeSet::new();
    for row in scenarios(&DOCUMENT) {
        for step in steps_of(row) {
            let finalize = match step["call"].as_str().expect("a call name") {
                "finalizeFromTaira" | "finalizeFromCheckpoint" => true,
                "voidExpired" | "voidExpiredFromCheckpoint" => false,
                _ => continue,
            };
            let outcome = step_outcome(step);
            let payload = step["proof"]["payload"].as_str().expect("a payload");
            let payload = reference_support::unhex(&payload[2..]);
            let deadline_ms = SccpTransferPayloadV1::decode(&payload)
                .expect("a transfer payload")
                .deadline_ms;
            let now_ms = step["now_ms"].as_u64().expect("now_ms");
            let in_time = now_ms <= deadline_ms;
            match (finalize, outcome) {
                (true, "ok") | (false, "DeadlineNotReached") => assert!(in_time, "{step:?}"),
                (true, "DeadlinePassed") | (false, "ok") => assert!(!in_time, "{step:?}"),
                _ => continue,
            }
            probes.insert((
                finalize,
                outcome,
                !deadline_ms.is_multiple_of(SECOND),
                i128::from(now_ms) - i128::from(deadline_ms),
            ));
        }
    }
    let second = i128::from(SECOND);
    for probe in [
        (true, "ok", false, 0),
        (false, "DeadlineNotReached", false, 0),
        (true, "DeadlinePassed", false, second),
        (false, "ok", false, second),
        (true, "ok", true, -999),
        (false, "DeadlineNotReached", true, -999),
        (true, "DeadlinePassed", true, 1),
        (false, "ok", true, 1),
    ] {
        assert!(probes.contains(&probe), "no step probes {probe:?}");
    }
}

/// The document has one row per scenario under a unique name, marks exactly its EVM rows
/// with `ton_replayable`, and pools exactly the certificates its steps name, each signed by a
/// committee it lists.
#[test]
fn document_rows_follow_the_two_passes() {
    let rows = scenarios(&DOCUMENT);
    // `cheap_path_identity_signature`, `checkpoint_use_after_rotation`,
    // `void_frozen_range_before_frozen`, `finalize_two_faults`,
    // `same_height_block_ref_with_history` and `inline_calls_after_expiry` each build an EVM
    // and a TON scenario.
    assert_eq!(rows.len(), SCENARIOS.len() + 6);
    assert_eq!(rows.len(), 40);
    let names: BTreeSet<_> = rows.iter().filter_map(|row| row["name"].as_str()).collect();
    assert_eq!(names.len(), rows.len(), "scenario names are unique");
    let certificates = DOCUMENT["certificates"]
        .as_object()
        .expect("the certificate pool");
    let mut used = BTreeSet::new();
    for row in rows {
        let name = row["name"].as_str().expect("a name");
        let flavor = row["flavor"].as_str().expect("a flavor");
        assert_eq!(row["deployment"]["flavor"].as_str(), Some(flavor), "{name}");
        // A TON row is named so, and only an EVM row is replayed on the other flavour.
        assert_eq!(flavor == "ton", name.starts_with("ton_"), "{name}");
        assert_eq!(
            row.get("ton_replayable").is_some(),
            flavor == "evm",
            "{name}"
        );
        // TON stores the keys of the pin; an EVM state has none.
        assert_eq!(
            row["initial_state"]["committee"].get("keys").is_some(),
            flavor == "ton",
            "{name}"
        );
        for step in steps_of(row) {
            let ids = step["certificates"].as_array().into_iter().flatten();
            for id in ids.chain(step.get("certificate")) {
                let id = id.as_str().expect("a pool id");
                assert!(certificates.contains_key(id), "{name}: {id} is not pooled");
                used.insert(id);
            }
        }
    }
    assert_eq!(used.len(), certificates.len(), "every pooled id is used");
    // The committees are the ones the scenarios name: K0 … K16 of the sixteen rotations.
    let committees = DOCUMENT["committees"].as_object().expect("committees");
    assert_eq!(committees.len(), MAX_CERTIFICATES_PER_CALL + 1);
    for entry in certificates.values() {
        let signed_by = entry["signed_by"].as_str().expect("a committee name");
        assert!(committees.contains_key(signed_by), "{signed_by}");
    }
}

/// Two rules have a row on each flavour, so that every harness sees them: a reference to the
/// certified block that carries a history proof is `BadProof` (§5.1.5), and an inline entry
/// point of an expired destination answers for its certificate before it answers for `Live`
/// (§5.1.2).
#[test]
fn same_height_history_and_expired_inline_calls_have_a_row_per_flavour() {
    let rows = scenarios(&DOCUMENT);
    let row = |name: &str| {
        rows.iter()
            .find(|row| row["name"].as_str() == Some(name))
            .unwrap_or_else(|| panic!("no scenario {name}"))
    };
    let history = |step: &Value| {
        let block = &step["proof"]["block"];
        (
            block["height"].as_u64().expect("a block height"),
            block["historyIndex"].as_u64().expect("a history index"),
            block["historyPath"].as_array().expect("a path").len(),
        )
    };

    for (name, accepted) in [
        ("same_height_block_ref_with_history", 3),
        ("ton_same_height_block_ref_with_history", 1),
    ] {
        let mut refused = BTreeSet::new();
        let mut unchanged = 0;
        for step in steps_of(row(name)) {
            let proves = step.get("proof").is_some();
            match step_outcome(step) {
                "BadProof" => {
                    // The reference names the certified block itself, with a history proof.
                    let (height, index, path) = history(step);
                    assert_eq!(height, 1010, "{name}");
                    assert!(matches!((index, path), (1, 0) | (0, 1)), "{name}: {step:?}");
                    refused.insert((
                        step["call"].as_str().expect("a call").to_owned(),
                        index,
                        path,
                    ));
                }
                "ok" if proves => {
                    assert_eq!(history(step), (1010, 0, 0), "{name}");
                    unchanged += 1;
                }
                outcome => assert_eq!((outcome, proves), ("ok", false), "{name}"),
            }
        }
        // One inline finalization, and both changes for each checkpoint entry point.
        assert_eq!(refused.len(), 7, "{name}");
        assert_eq!(unchanged, accepted, "{name}");
    }

    for (name, flavor) in [
        ("inline_calls_after_expiry", DestinationFlavor::Evm),
        ("ton_inline_calls_after_expiry", DestinationFlavor::Ton),
    ] {
        let outcomes: Vec<(&str, &str)> = steps_of(row(name))
            .iter()
            .map(|step| {
                let state = &step["state_after"];
                // Nothing is stored, and the destination is not `Live` for its deadline alone.
                assert_eq!(state["live"].as_bool(), Some(false), "{name}");
                assert_eq!(state["equivocated"].as_bool(), Some(false), "{name}");
                assert_eq!(state["checkpoints"].as_array().map(Vec::len), Some(0));
                assert!(step.get("certificate").is_some(), "{name}: an inline call");
                (step["call"].as_str().expect("a call"), step_outcome(step))
            })
            .collect();
        let inline = ["finalizeFromTaira", "applyControl", "voidExpired"]
            .map(|entry_point| reference_support::scenario::call_name(flavor, entry_point));
        let expected: Vec<(&str, &str)> = ["BadSignature", "CommitteeNotAccepted"]
            .into_iter()
            .flat_map(|outcome| inline.map(|call| (call, outcome)))
            .collect();
        assert_eq!(outcomes, expected, "{name}");
    }
}

// ---------------------------------------------------------------------------------------------
// The builders
// ---------------------------------------------------------------------------------------------

/// The environment pins `K0` as generation 5 at height 1000, names committees on demand,
/// labels a certificate by its height and its signing committee, and forges a valid header
/// that Taira never produced. Only the pass that writes the document is strict.
#[test]
fn environment_pins_k0_and_labels_its_certificates() {
    let tables = Tables::new(DestinationFlavor::Evm);
    let mut env = tables.env(None);
    assert_eq!((env.flavor, env.strict), (DestinationFlavor::Evm, true));
    let deployment = env.deployment();
    assert_eq!(deployment.pin_root, committee(0).root());
    assert_eq!(deployment.pin_keys, Some(committee(0).keys()));
    assert_eq!(
        (deployment.pin_generation, deployment.pin_start_height),
        (PIN_GENERATION, PIN_START)
    );
    assert_eq!(deployment.pin_until_ms, T0 + VALIDITY);
    assert_eq!(deployment.destination_word[..12], [0; 12]);
    assert_eq!(deployment.destination_word[12..], DESTINATION_ADDRESS);

    let k2 = env.k(2);
    let indices = |committee: &Committee| {
        let mut indices: Vec<u8> = committee.members().iter().map(|key| key.index).collect();
        indices.sort_unstable();
        indices
    };
    assert_eq!(
        (k2.name.as_str(), indices(&k2)),
        ("K2", vec![48, 49, 50, 51])
    );
    assert_eq!(indices(env.pinned()), [40, 41, 42, 43]);
    let names: Vec<&str> = env.committees.iter().map(|k| k.name.as_str()).collect();
    assert_eq!(names, ["K0", "K1", "K2"]);
    assert_eq!(env.k(1).root(), committee(1).root());
    assert_eq!(env.committees.len(), 3);

    let block = env.block(1005, T0 + 5 * SECOND);
    let genuine = env.cert(&block);
    assert_eq!(
        (genuine.label.as_str(), genuine.signed_by.as_str()),
        ("X_1005", "K0")
    );
    assert!(genuine.next_committee.is_none());
    assert_eq!(genuine.certificate.header, block.x());
    let forged = env.forged(1005, T0 + 5 * SECOND, PIN_GENERATION, env.pinned(), |x| {
        x.message_count = 1;
        x.sccp_root = [0xee; 32];
    });
    assert_eq!(
        (forged.label.as_str(), forged.signed_by.as_str()),
        ("forged_X_1005", "K0")
    );
    assert_ne!(forged.certificate.header, genuine.certificate.header);
    // Both verify: a forged header is forged only in that Taira never produced it.
    let destination = Destination::new(deployment).expect("the deployment");
    for submission in [&genuine, &forged] {
        let outcome = destination.verify_certificate(&submission.certificate.wire(), T0 + MINUTE);
        assert_eq!(outcome_name(&outcome), "ok", "{}", submission.label);
    }
    // A handoff grants the validity of its generation and starts the next one.
    let handoff = env.key_change(1100, T0 + HOUR, &k2);
    assert_eq!(handoff.header.flags, FLAG_ACTIVE | FLAG_ROTATION);
    assert_eq!(handoff.header.validity_ms, VALIDITY);
    assert_eq!(handoff.header.next_committee_root, k2.root());
    let after = env.block_of(
        1101,
        T0 + HOUR + SECOND,
        vec![env.transfer(0, AMOUNT, T0 + DAY)],
    );
    assert_eq!(after.generation.number, PIN_GENERATION + 1);
    assert_eq!(env.cert(&after).signed_by, "K2");
    assert_eq!(after.header.message_count, 1);

    // The scenarios of a pass share its pool, and a pass remembers the committees it is told.
    let mut tables = tables;
    let mut run = env.scenario("probe", "a probe");
    run.submit(&[genuine], T0 + MINUTE, "ok");
    assert_eq!(run.until_ms(), T0 + VALIDITY);
    assert_eq!(tables.pool.borrow().len(), 1);
    tables.push(run);
    tables.remember(&env);
    assert_eq!(tables.scenarios.len(), 1);
    assert_eq!(
        tables.committees.keys().collect::<Vec<_>>(),
        ["K0", "K1", "K2"]
    );

    let replay = Tables::new(DestinationFlavor::Ton);
    let env = replay.env(None);
    assert_eq!((env.flavor, env.strict), (DestinationFlavor::Ton, false));
    let env = tables.env(Some(DestinationFlavor::Ton));
    assert_eq!((env.flavor, env.strict), (DestinationFlavor::Ton, true));
}

/// A forged header is still a finality header: fields that violate X1–X7 are refused.
#[test]
#[should_panic(expected = "a forged header satisfies X1-X7")]
fn forged_header_must_satisfy_x1_to_x7() {
    let env = Tables::new(DestinationFlavor::Evm).env(None);
    let _ = env.forged(1005, T0, PIN_GENERATION, env.pinned(), |x| {
        x.message_count = 1
    });
}

/// A call of a strict run that does not give the outcome its author wrote fails the build;
/// the replay pass records what the model answers.
#[test]
fn replay_pass_records_what_the_strict_pass_would_refuse() {
    let replay = Tables::new(DestinationFlavor::Ton);
    let mut env = replay.env(None);
    let block = env.block(1005, T0 + 5 * SECOND);
    let mut run = env.scenario("replay", "a probe");
    // The author of an EVM row expects the EVM range error.
    run.void_frozen(10, 0, T0 + MINUTE, "BadAmount");
    run.views(T0 + MINUTE);
    run.submit(&[env.cert(&block)], T0 + MINUTE, "ok");
    let dummy = dummy_proof(&env, &block);
    run.finalize(Source::Checkpoint(&block.x()), &dummy, T0 + MINUTE, "ok");
    run.void_expired(0, Source::Checkpoint(&block.x()), &dummy, T0 + MINUTE, "ok");
    let row = run.0.as_json();
    let outcomes: Vec<&str> = steps_of(&row).iter().map(step_outcome).collect();
    // The replay runs a TON minter on the certificates of the Ethereum route: it takes
    // their checkpoints, and it refuses a payload of that route before anything else.
    assert_eq!(
        outcomes,
        ["BadRange", "ok", "ok", "BadPayload", "BadPayload"]
    );
    assert_eq!(row["deployment"]["network"], text("ton-mainnet"));
    assert_eq!(env.sim.target, SccpNetworkV1::EthereumMainnet);
    assert_eq!(steps_of(&row)[0]["call"], text("sccp_void_frozen"));
    assert_eq!(steps_of(&row)[2]["call"], text("sccp_checkpoint"));
    assert_eq!(steps_of(&row)[3]["call"], text("sccp_finalize_checkpoint"));
    assert_eq!(dummy.block.height, 1005);
}

/// The same call in the strict pass.
#[test]
#[should_panic(expected = "the model gave")]
fn strict_pass_refuses_an_unexpected_outcome() {
    let tables = Tables::new(DestinationFlavor::Evm);
    let env = tables.env(Some(DestinationFlavor::Ton));
    env.scenario("strict", "a probe")
        .void_frozen(10, 0, T0 + MINUTE, "BadAmount");
}

/// A control leaf of the scenarios is a Parliament-track leaf that Taira would record, and a
/// control proof of the simulator applies it.
#[test]
fn control_leaves_are_recordable_and_apply() {
    let tables = Tables::new(DestinationFlavor::Evm);
    let mut env = tables.env(None);
    let leaf = control(&env, 7, 2);
    assert_eq!(
        leaf.control,
        ControlLeafV1 {
            route_revision: 1,
            control_nonce: 7,
            track: 1,
            parliament_paused: 0,
            fast_pause_until_ms: 0,
            certificate_id: [0xc2; 32],
            effect_hash: [0xe2; 32],
        }
    );
    let block = env.block_of(1010, T0 + 10 * SECOND, vec![leaf]);
    let mut run = env.scenario("control", "a probe");
    run.apply_control(
        Source::Inline(&env.cert(&block)),
        &env.sim.control_proof(1010, 0, &block.header),
        T0 + MINUTE,
        "ok",
    );
    assert_eq!(run.0.destination.state().control_nonce, 7);
}

/// `ton_replayable` holds for single-certificate checkpoint calls and `views` steps whose
/// results agree. The call name and the stored keys of the TON row are no difference.
#[test]
fn ton_replayable_needs_one_certificate_per_call_and_equal_results() {
    let state = |high: u64, keys: Option<&str>| {
        let mut committee = obj([("high", num(high))]);
        if let Some(keys) = keys {
            insert(&mut committee, "keys", list([text(keys)]));
        }
        obj([("committee", committee)])
    };
    let step = |call: &str, certificates: usize, outcome: &str, state: Value| {
        obj([
            ("call", text(call)),
            (
                "certificates",
                list((0..certificates).map(|_| text("c001"))),
            ),
            ("expected", obj([("outcome", text(outcome))])),
            ("state_after", state),
        ])
    };
    let views = |effective: bool, high: u64| {
        obj([
            ("call", text("views")),
            ("expected", obj([("effective", Value::Bool(effective))])),
            ("state_after", state(high, None)),
        ])
    };
    let row = |steps: Vec<Value>| obj([("steps", list(steps))]);

    let stored = state(1010, Some("K0"));
    assert_eq!(without_keys(&stored), state(1010, None));
    assert_eq!(without_keys(&state(1010, None)), state(1010, None));

    let evm = row(vec![step("submitCheckpoints", 1, "ok", state(1010, None))]);
    let ton = |outcome: &str, high: u64| {
        row(vec![step(
            "sccp_checkpoint",
            1,
            outcome,
            state(high, Some("K0")),
        )])
    };
    assert!(ton_replayable(&evm, &ton("ok", 1010)));
    assert!(!ton_replayable(&evm, &ton("NothingToDo", 1010)));
    assert!(!ton_replayable(&evm, &ton("ok", 1011)));
    // A batch, and an entry point other than the checkpoint submission, are not replayed.
    let batch = row(vec![step("submitCheckpoints", 2, "ok", state(1010, None))]);
    assert!(!ton_replayable(&batch, &batch));
    let void = row(vec![step("voidFrozen", 0, "ok", state(1010, None))]);
    assert!(!ton_replayable(&void, &void));
    // A `views` step is compared by its state only: the views of the two flavours differ.
    assert!(ton_replayable(
        &row(vec![views(true, 999)]),
        &row(vec![views(false, 999)])
    ));
    assert!(!ton_replayable(
        &row(vec![views(true, 999)]),
        &row(vec![views(true, 1000)])
    ));
    // The rows have the same steps.
    assert!(!ton_replayable(&evm, &row(vec![])));
    assert!(ton_replayable(&row(vec![]), &row(vec![])));
}

/// The ABI tables are recomputed with Keccak-256 and agree with the specification values of
/// `destination_abi`; the hash itself is checked against the ERC-20 known answers.
#[test]
fn abi_tables_are_recomputed_from_the_canonical_signatures() {
    assert_eq!(
        selector_of("transfer(address,uint256)"),
        [0xa9, 0x05, 0x9c, 0xbb]
    );
    assert_eq!(
        to_hex(&keccak256(&[b"Transfer(address,address,uint256)"])),
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    );

    let entries = |table: &Value| table.as_object().expect("a table").len();
    let selectors = selectors_json();
    assert_eq!(entries(&selectors), 24);
    assert_eq!(
        selectors["submitCheckpoints"],
        obj([
            (
                "signature",
                text("submitCheckpoints((bytes,bytes,bytes,bytes,bytes)[])")
            ),
            ("selector", text("0x07a5e706")),
        ])
    );
    let topics = event_topics_json();
    assert_eq!(entries(&topics), 8);
    assert_eq!(
        topics["SccpCheckpointed"]["signature"],
        text("SccpCheckpointed(uint64,bytes32)")
    );
    assert_eq!(
        topics["SccpCheckpointed"]["topic0"],
        hx(&keccak256(&[b"SccpCheckpointed(uint64,bytes32)"]))
    );

    let codes = error_codes_json();
    let (shared, ton_only) = (&codes["shared"], &codes["ton_only"]);
    assert_eq!((entries(shared), entries(ton_only)), (28, 8));
    assert_eq!(shared["CommitteeNotAccepted"], num(402));
    assert_eq!(shared["LatchRequired"], num(434));
    // An EVM-only error is in the shared table without a code.
    assert_eq!(shared.get("AlreadyConsumed"), Some(&Value::Null));
    assert_eq!(ton_only["BadRange"], num(426));
    assert!(shared.get("BadRange").is_none());

    let constants = constants_json();
    assert_eq!(constants["max_certificates_per_call"], num(16));
    assert_eq!(constants["ton_checkpoint_slots"], num(3));
    assert_eq!(constants["max_void_frozen_range_evm"], num(256));
    assert_eq!(constants["max_void_frozen_range_ton"], num(512));
}

/// Every name of `error_choices` is what the model answers in the case the entry describes,
/// on each flavour that can express it. The key encodings other than a wrong `y` are pinned
/// by the negative certificates of `finality_v1.json`.
#[test]
fn error_choices_are_what_the_model_answers() {
    let choices = error_choices_json();
    let choice = |key: &str| choices[key].as_str().expect("an error name").to_owned();
    let tables = Tables::new(DestinationFlavor::Evm);
    let now = T0 + MINUTE;
    let cut = |bytes: &[u8]| bytes[..bytes.len() - 1].to_vec();
    for flavor in [DestinationFlavor::Evm, DestinationFlavor::Ton] {
        let evm = flavor == DestinationFlavor::Evm;
        let mut env = tables.env(Some(flavor));
        let block = env.block(1010, T0 + 10 * SECOND);
        let k1 = env.k(1);
        let handoff = env.key_change(1100, T0 + HOUR, &k1);
        let genuine = env.cert(&block).certificate;
        let deploy = || Destination::new(env.deployment()).expect("the deployment");
        let verify = |certificate: &Certificate, now_ms: u64| {
            outcome_name(&deploy().verify_certificate(&certificate.wire(), now_ms)).to_owned()
        };
        assert_eq!(verify(&genuine, now), "ok", "{flavor:?}");

        // Lengths (step 1).
        let short_qc = Certificate {
            qc: cut(&genuine.qc),
            ..genuine.clone()
        };
        let short_signature = Certificate {
            signature_evm: cut(&genuine.signature_evm),
            signature_ton: cut(&genuine.signature_ton),
            ..genuine.clone()
        };
        for certificate in [&short_qc, &short_signature] {
            assert_eq!(
                verify(certificate, now),
                choice("length_qc_or_signature_or_signer_ys"),
                "{flavor:?}"
            );
        }
        let short_x = Certificate {
            header: cut(&genuine.header),
            ..genuine.clone()
        };
        assert_eq!(verify(&short_x, now), choice("length_x"), "{flavor:?}");
        if evm {
            // Only EVM takes the committee and the signers' `y` from the call.
            let short_ys = Certificate {
                signer_ys: cut(&genuine.signer_ys),
                ..genuine.clone()
            };
            assert_eq!(
                verify(&short_ys, now),
                choice("length_qc_or_signature_or_signer_ys")
            );
            let short_committee = Certificate {
                committee: cut(&genuine.committee),
                ..genuine.clone()
            };
            assert_eq!(verify(&short_committee, now), choice("length_committee"));
            // `p − y` is on the curve with the other sign: the key's sign flag refuses it.
            let y: [u8; FP_LEN] = genuine.signer_ys[..FP_LEN].try_into().expect("48 bytes");
            let mut negated = genuine.clone();
            negated.signer_ys[..FP_LEN].copy_from_slice(&fp_sub(&BLS12_381_P, &y));
            assert_eq!(
                verify(&negated, now),
                choice("signer_key_flags_sign_y_or_off_curve")
            );
        }

        // The signature (steps 6 and 9–11).
        let identity = Certificate {
            signature_evm: IDENTITY_SIGNATURE_EVM.to_vec(),
            signature_ton: IDENTITY_SIGNATURE.to_vec(),
            ..genuine.clone()
        };
        assert_eq!(
            verify(&identity, now),
            choice("signature_identity"),
            "{flavor:?}"
        );
        let other_instance = env
            .cert_of(
                &block.header,
                env.pinned(),
                None,
                &CertifyOptions {
                    signed_instance: Some([0x78; 32]),
                    ..CertifyOptions::default()
                },
            )
            .certificate;
        assert_eq!(
            verify(&other_instance, now),
            choice("signature_encoding_subgroup_or_pairing"),
            "{flavor:?}"
        );

        // Not Live: expired, then latched.
        assert_eq!(
            verify(&genuine, T0 + VALIDITY + SECOND),
            choice("not_live_expired"),
            "{flavor:?}"
        );
        let mut latched = deploy();
        let below = env.forged(999, T0 - SECOND, PIN_GENERATION, env.pinned(), |_| {});
        latched
            .submit_checkpoints(&[below.certificate.wire()], &[], now)
            .expect("a latch is not a revert");
        assert_eq!(
            outcome_name(&latched.verify_certificate(&genuine.wire(), now)),
            choice("not_live_latched"),
            "{flavor:?}"
        );

        // A stored checkpoint that is neither of the current generation nor its handoff is
        // refused before the proof is read; the handoff that installed the generation is not.
        let mut rotated = deploy();
        let rotation_time = T0 + HOUR + MINUTE;
        rotated
            .submit_checkpoints(
                &[genuine.wire(), env.cert(&handoff).certificate.wire()],
                &[None, Some(k1.keys())],
                rotation_time,
            )
            .expect("the rotation installs K1");
        let mut finalize_from = |stored: &Block| {
            let reference = CheckpointRefV1 { header: stored.x() };
            let result = rotated.finalize(
                CertificateSourceV1::Checkpoint(&reference),
                &dummy_proof(&env, &block),
                rotation_time,
            );
            outcome_name(&result)
        };
        assert_eq!(
            finalize_from(&block),
            choice("checkpoint_not_current_or_installing_handoff"),
            "{flavor:?}"
        );
        assert_eq!(finalize_from(&handoff), "BadProof", "{flavor:?}");

        // The range of `voidFrozen` is checked before `Frozen`: the destination is Live.
        let range = &choices["void_frozen_range"][flavor.name()];
        for (first_nonce, count) in [(10, 0), (10, flavor.max_void_frozen_range() + 1)] {
            assert_eq!(
                text(outcome_name(&deploy().void_frozen(first_nonce, count, now))),
                *range,
                "{flavor:?}"
            );
        }
        assert_eq!(
            outcome_name(&deploy().void_frozen(10, 1, now)),
            "NotFrozen",
            "{flavor:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The checks of recorded rows (`reference_support::scenario`)
// ---------------------------------------------------------------------------------------------

/// A hand-written scenario row of one step per `(call, now_ms, outcome)`.
fn hand_row(flavor: &str, steps: &[(&str, u64, &str)]) -> Value {
    obj([
        ("name", text("hand")),
        ("flavor", text(flavor)),
        (
            "steps",
            list(steps.iter().map(|(call, now_ms, outcome)| {
                obj([
                    ("call", text(call)),
                    ("now_ms", num(*now_ms)),
                    (
                        "expected",
                        obj([("outcome", text(outcome)), ("events", list([]))]),
                    ),
                ])
            })),
        ),
    ])
}

/// The checks read back what the recorder writes: the steps, their outcomes, the clock rule
/// and the errors of the table.
#[test]
fn row_checks_read_back_a_recorded_scenario() {
    let tables = Tables::new(DestinationFlavor::Evm);
    let mut env = tables.env(None);
    let leaves = vec![env.transfer(0, AMOUNT, T0 + DAY)];
    let block = env.block_of(1010, T0 + 10 * SECOND, leaves);
    let proof = env.sim.message_proof(1010, 0, &block.header);
    let stored = block.x();
    let mut run = env.scenario("recorded", "a probe");
    run.views(T0 + MINUTE);
    run.submit(&[env.cert(&block)], T0 + MINUTE, "ok");
    run.submit(&[env.cert(&block)], T0 + MINUTE, "NothingToDo");
    run.finalize(Source::Checkpoint(&stored), &proof, T0 + 2 * MINUTE, "ok");
    // The two errors that carry an argument.
    run.finalize(
        Source::Checkpoint(&stored),
        &proof,
        T0 + 2 * MINUTE,
        "AlreadyConsumed",
    );
    run.void_expired(
        7,
        Source::Checkpoint(&stored),
        &proof,
        T0 + DAY + SECOND,
        "BadNonce",
    );
    let row = run.0.as_json();
    let steps = steps_of(&row);
    assert_eq!(steps.len(), 6);
    assert_eq!(
        steps.iter().map(step_outcome).collect::<Vec<_>>(),
        [
            "ok",
            "ok",
            "NothingToDo",
            "ok",
            "AlreadyConsumed",
            "BadNonce"
        ]
    );
    assert_eq!(check_scenario_clock(&row), 6);
    assert_eq!(
        check_scenario_outcomes(&row),
        BTreeSet::from(["AlreadyConsumed", "BadNonce", "NothingToDo"])
    );

    // A hand-written row: equal clock values are calls in one block, and the flavour decides
    // which errors a row may report.
    let evm = hand_row(
        "evm",
        &[
            ("submitCheckpoints", 5_000, "TooManyCertificates"),
            ("voidFrozen", 5_000, "BadAmount"),
        ],
    );
    assert_eq!(check_scenario_clock(&evm), 2);
    assert_eq!(
        check_scenario_outcomes(&evm),
        BTreeSet::from(["BadAmount", "TooManyCertificates"])
    );
    let ton = hand_row("ton", &[("voidFrozen", 5_000, "BadRange")]);
    assert_eq!(check_scenario_outcomes(&ton), BTreeSet::from(["BadRange"]));
    assert_eq!(check_scenario_clock(&hand_row("evm", &[])), 0);
}

#[test]
#[should_panic(expected = "a scenario row lists its steps")]
fn steps_of_needs_a_scenario_row() {
    let _ = steps_of(&obj([("name", text("no steps"))]));
}

#[test]
#[should_panic(expected = "a call records its outcome")]
fn only_a_views_step_has_no_outcome() {
    let _ = step_outcome(&obj([("call", text("voidFrozen")), ("expected", obj([]))]));
}

#[test]
#[should_panic(expected = "hand step 1: now_ms 5500 is not a whole-second destination clock value")]
fn clock_check_refuses_a_sub_second_step() {
    check_scenario_clock(&hand_row(
        "evm",
        &[("voidFrozen", 5_000, "ok"), ("voidFrozen", 5_500, "ok")],
    ));
}

#[test]
#[should_panic(expected = "hand step 1: now_ms 4000 is earlier than the previous step's 5000")]
fn clock_check_refuses_a_step_back_in_time() {
    check_scenario_clock(&hand_row(
        "evm",
        &[("voidFrozen", 5_000, "ok"), ("voidFrozen", 4_000, "ok")],
    ));
}

#[test]
#[should_panic(expected = "hand step 0: Refused is not a name of the error table")]
fn outcome_check_refuses_an_unknown_name() {
    check_scenario_outcomes(&hand_row("evm", &[("voidFrozen", 5_000, "Refused")]));
}

#[test]
#[should_panic(expected = "hand step 0: BadRange is not an error of the evm flavor")]
fn outcome_check_refuses_a_ton_only_error_on_evm() {
    check_scenario_outcomes(&hand_row("evm", &[("voidFrozen", 5_000, "BadRange")]));
}

#[test]
#[should_panic(expected = "hand step 0: TooManyCertificates is not an error of the ton flavor")]
fn outcome_check_refuses_an_evm_only_error_on_ton() {
    check_scenario_outcomes(&hand_row(
        "ton",
        &[("sccp_checkpoint", 5_000, "TooManyCertificates")],
    ));
}

#[test]
#[should_panic(expected = "error_args goes with an error that carries an argument")]
fn outcome_check_needs_the_argument_of_an_error_that_carries_one() {
    check_scenario_outcomes(&hand_row(
        "evm",
        &[("voidFrozen", 5_000, "AlreadyConsumed")],
    ));
}
