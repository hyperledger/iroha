//! Recording runs of the destination model as fixture scenarios.
//!
//! A scenario is a deployment, its initial state and a list of calls. Each recorded step
//! carries the call, its inputs, `now_ms`, the expected outcome (`ok` or the §5.2.2 error
//! name), the emitted events and the state afterwards: the
//! `(state, input, now) → (state', outcome, event)` row shape of `specs/sccp.md` §11.1.
//! Certificates live in a pool shared by the scenarios of one file and are referenced by id;
//! an `SccpCertificate` event names the pooled certificate it publishes: the one among the
//! certificates of its own step with the `QC_FIXED`, the header and the signature the event
//! carries.
//!
//! A step names its call as the flavour does ([`call_name`]): the EVM entry point, or the
//! TON message of §5.3.2 (`sccp_checkpoint`, `sccp_finalize_checkpoint`, …).
//!
//! `now_ms` of a step is the destination clock, `block.timestamp × 1000` (EVM) or
//! `now() × 1000` (TON, §0). The recorder therefore refuses a step whose `now_ms` is not a
//! multiple of 1000 or is earlier than the previous step's, so that an EDR or Acton harness
//! can replay every scenario with real block times.
//!
//! This is the Rust twin of `scripts/sccp_reference/scenario.py`: the same calls give the
//! same rows.
//!
//! The checks at the end read rows back: [`check_scenario_clock`] and
//! [`check_scenario_outcomes`] hold for every row of a scenario table, whichever generator
//! wrote it.

use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

use iroha_sccp::v1::{
    committee::KEY_LEN,
    destination::{
        BlockRefV1, CallOutcome, CertificateSourceV1, CheckpointRefV1, ControlProofV1,
        DeploymentV1, Destination, DestinationError, DestinationEvent, DestinationFlavor,
        DestinationStateV1, MessageProofV1, TairaCertificateV1,
    },
};
use norito::json::{Map, Value};

use super::{
    check_destination_clock, dec, hexes, hx, hx_string, insert, list, num, obj, outcome_name,
    parsed_header_json,
    taira_sim::{Certificate, Committee},
    text,
};

// ---------------------------------------------------------------------------------------------
// Forms of the destination's inputs, outputs and state
// ---------------------------------------------------------------------------------------------

/// The immutables of a destination as a scenario prints them.
pub fn deployment_json(deployment: &DeploymentV1) -> Value {
    obj([
        ("flavor", text(deployment.flavor.name())),
        ("taira_network_id", hx(&deployment.taira_network_id)),
        ("consensus_instance", hx(&deployment.consensus_instance)),
        ("network", text(deployment.network.profile_key())),
        ("destination_word", hx(&deployment.destination_word)),
        ("route_revision", num(deployment.route_revision.into())),
        ("max_wrapped_supply", dec(deployment.max_wrapped_supply)),
        (
            "pin",
            obj([
                ("generation", num(deployment.pin_generation)),
                ("committee_root", hx(&deployment.pin_root)),
                ("start_height", num(deployment.pin_start_height)),
                ("until_ms", num(deployment.pin_until_ms)),
                (
                    "keys",
                    deployment.pin_keys.as_deref().map_or(Value::Null, hexes),
                ),
            ]),
        ),
    ])
}

/// The state of a destination. With `now_ms` the two clock-dependent readings are added:
/// `live` and `pause.effective`.
pub fn state_json(state: &DestinationStateV1, now_ms: Option<u64>) -> Value {
    let cur = &state.committee;
    let mut committee = obj([
        ("root", hx(&cur.root)),
        ("generation", num(cur.generation)),
        ("start", num(cur.start)),
        ("high", num(cur.high)),
        ("until_ms", num(cur.until_ms)),
    ]);
    if let Some(keys) = &state.keys {
        insert(&mut committee, "keys", hexes(keys));
    }
    let mut pause = obj([
        ("parliament_paused", Value::Bool(state.parliament_paused)),
        ("fast_pause_until_ms", num(state.fast_pause_until_ms)),
        ("control_nonce", num(state.control_nonce)),
    ]);
    if let Some(now_ms) = now_ms {
        insert(
            &mut pause,
            "effective",
            Value::Bool(state.parliament_paused || now_ms < state.fast_pause_until_ms),
        );
    }
    let mut out = obj([
        ("committee", committee),
        (
            "checkpoints",
            list(
                state
                    .checkpoints
                    .iter()
                    .map(|(height, id)| obj([("height", num(*height)), ("id", hx(id))])),
            ),
        ),
        ("equivocated", Value::Bool(cur.equivocated)),
        ("pause", pause),
        ("op_count", num(state.op_count)),
        (
            "consumed",
            list(state.consumed.iter().map(|nonce| num(*nonce))),
        ),
        ("total_supply", dec(state.total_supply)),
    ]);
    if let Some(now_ms) = now_ms {
        insert(&mut out, "live", Value::Bool(cur.is_live(now_ms)));
    }
    out
}

/// `BlockRefV1` under its ABI field names.
pub fn block_ref_json(block: &BlockRefV1) -> Value {
    obj([
        ("height", num(block.height)),
        ("sccpRoot", hx(&block.sccp_root)),
        ("messageCount", num(block.message_count.into())),
        ("historyIndex", num(block.history_index)),
        ("historyPath", hexes(&block.history_path)),
    ])
}

/// `MessageProofV1` under its ABI field names.
pub fn message_proof_json(proof: &MessageProofV1) -> Value {
    obj([
        ("payload", hx(&proof.payload)),
        ("leafIndex", num(proof.leaf_index.into())),
        ("path", hexes(&proof.path)),
        ("block", block_ref_json(&proof.block)),
    ])
}

/// `ControlProofV1` under its ABI field names. `parliamentPaused` is a boolean, or the raw
/// byte when it is neither 0 nor 1 (a value only a negative vector carries).
pub fn control_proof_json(proof: &ControlProofV1) -> Value {
    obj([
        ("controlNonce", num(proof.control_nonce)),
        ("track", num(proof.track.into())),
        (
            "parliamentPaused",
            match proof.parliament_paused {
                0 => Value::Bool(false),
                1 => Value::Bool(true),
                other => num(other.into()),
            },
        ),
        ("fastPauseUntilMs", num(proof.fast_pause_until_ms)),
        ("certificateId", hx(&proof.certificate_id)),
        ("effectHash", hx(&proof.effect_hash)),
        ("leafIndex", num(proof.leaf_index.into())),
        ("path", hexes(&proof.path)),
        ("block", block_ref_json(&proof.block)),
    ])
}

/// The EVM entry points of §5.2.2 with the TON message of §5.3.2 that does the same.
pub const TON_CALL_NAMES: [(&str, &str); 8] = [
    ("submitCheckpoints", "sccp_checkpoint"),
    ("finalizeFromTaira", "sccp_finalize"),
    ("finalizeFromCheckpoint", "sccp_finalize_checkpoint"),
    ("applyControl", "sccp_apply_control"),
    (
        "applyControlFromCheckpoint",
        "sccp_apply_control_checkpoint",
    ),
    ("voidExpired", "sccp_void_expired"),
    ("voidExpiredFromCheckpoint", "sccp_void_expired_checkpoint"),
    ("voidFrozen", "sccp_void_frozen"),
];

/// The name a step of `flavor` records for the entry point `evm_name`.
///
/// # Panics
/// When `evm_name` is not an entry point of [`TON_CALL_NAMES`].
pub fn call_name(flavor: DestinationFlavor, evm_name: &'static str) -> &'static str {
    let (evm, ton) = TON_CALL_NAMES
        .into_iter()
        .find(|(evm, _)| *evm == evm_name)
        .unwrap_or_else(|| panic!("{evm_name} is not an entry point"));
    match flavor {
        DestinationFlavor::Evm => evm,
        DestinationFlavor::Ton => ton,
    }
}

/// One event as a scenario prints it. An `SccpCertificate` names the pooled certificate it
/// publishes: the one among `submitted`, the ids of the step, with its `QC_FIXED`, header
/// and signature.
///
/// # Panics
/// When a published certificate is none the step submitted.
pub fn event_json(event: &DestinationEvent, pool: &CertificatePool, submitted: &[String]) -> Value {
    let named = |fields: Value| {
        let mut fields = fields;
        insert(&mut fields, "event", text(event.name()));
        fields
    };
    match event {
        DestinationEvent::Certificate {
            height,
            generation,
            qc,
            header,
            signature,
        } => named(obj([
            ("height", num(*height)),
            ("generation", num(*generation)),
            (
                "certificate",
                text(
                    pool.id_of(qc, header, signature, submitted)
                        .expect("a published certificate is one the step submitted"),
                ),
            ),
        ])),
        DestinationEvent::Checkpointed { height, id } => {
            named(obj([("height", num(*height)), ("header", hx(id))]))
        }
        DestinationEvent::CommitteeRotated(rotation) => named(obj([
            ("generation", num(rotation.generation)),
            ("root", hx(&rotation.root)),
            ("untilMs", num(rotation.until_ms)),
            ("startHeight", num(rotation.start)),
        ])),
        DestinationEvent::Latched(violation) => named(obj([
            ("reason", num(violation.reason.code().into())),
            ("generation", num(violation.generation)),
            ("height", num(violation.height)),
            ("a", hx(&violation.a)),
            ("b", hx(&violation.b)),
        ])),
        DestinationEvent::ControlApplied {
            control_nonce,
            track,
            parliament_paused,
            fast_pause_until_ms,
            certificate_id,
        } => named(obj([
            ("controlNonce", num(*control_nonce)),
            ("track", num((*track).into())),
            ("parliamentPaused", Value::Bool(*parliament_paused)),
            ("fastPauseUntilMs", num(*fast_pause_until_ms)),
            ("certificateId", hx(certificate_id)),
        ])),
        DestinationEvent::Finalized {
            message_id,
            nonce,
            recipient,
            token_amount,
        } => named(obj([
            ("messageId", hx(message_id)),
            ("nonce", num(*nonce)),
            ("recipient", hx(recipient)),
            ("tokenAmount", dec(*token_amount)),
        ])),
        DestinationEvent::Voided { message_id, nonce } => {
            named(obj([("messageId", hx(message_id)), ("nonce", num(*nonce))]))
        }
        DestinationEvent::VoidedRange {
            message_id,
            first_nonce,
            count,
        } => named(obj([
            ("messageId", hx(message_id)),
            ("firstNonce", num(*first_nonce)),
            ("count", num(*count)),
        ])),
    }
}

/// The `expected` object of a step: the outcome, the arguments of an error that carries
/// them, why a batch stopped, the returned message id, and the events (none for a refusal).
/// `submitted` are the pool ids of the certificates the step carries.
pub fn expected_json(
    result: &Result<CallOutcome, DestinationError>,
    pool: &CertificatePool,
    submitted: &[String],
) -> Value {
    let mut expected = obj([("outcome", text(outcome_name(result)))]);
    match result {
        Ok(outcome) => {
            if let Some(stopped) = outcome.stopped {
                insert(&mut expected, "stopped", text(stopped.name()));
            }
            if let Some(returned) = &outcome.returned {
                insert(&mut expected, "return", hx(returned));
            }
            insert(
                &mut expected,
                "events",
                list(
                    outcome
                        .events
                        .iter()
                        .map(|event| event_json(event, pool, submitted)),
                ),
            );
        }
        Err(error) => {
            match error {
                DestinationError::AlreadyConsumed { nonce } => {
                    insert(&mut expected, "error_args", obj([("nonce", num(*nonce))]))
                }
                DestinationError::BadNonce { expected: nonce } => insert(
                    &mut expected,
                    "error_args",
                    obj([("expected", num(*nonce))]),
                ),
                _ => {}
            }
            insert(&mut expected, "events", list([]));
        }
    }
    expected
}

// ---------------------------------------------------------------------------------------------
// The certificate pool
// ---------------------------------------------------------------------------------------------

/// A certificate with what the pool records about it.
#[derive(Clone, Debug)]
pub struct Submission {
    /// The certificate.
    pub certificate: Certificate,
    /// The label of its pool entry, such as `X_1010`.
    pub label: String,
    /// The name of the committee that signed it.
    pub signed_by: String,
    /// The successor committee a TON `sccp_checkpoint` message brings with it.
    pub next_committee: Option<Committee>,
}

impl Submission {
    /// A certificate that brings no successor keys.
    pub fn new(certificate: Certificate, label: &str, signed_by: &str) -> Self {
        Self {
            certificate,
            label: label.to_owned(),
            signed_by: signed_by.to_owned(),
            next_committee: None,
        }
    }

    /// The same certificate with the keys of `committee` as TON `next_keys`.
    #[must_use]
    pub fn with_next(mut self, committee: &Committee) -> Self {
        self.next_committee = Some(committee.clone());
        self
    }

    /// The same certificate with other TON `next_keys`, or none.
    #[must_use]
    pub fn with_next_keys(mut self, committee: Option<&Committee>) -> Self {
        self.next_committee = committee.cloned();
        self
    }
}

/// The wire bytes that identify a pooled certificate.
type PoolKey = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// The deduplicated certificates of one fixture file, with ids `c001`, `c002`, … in order of
/// first use.
#[derive(Clone, Debug, Default)]
pub struct CertificatePool {
    /// Id, identifying bytes, TON signature and printed entry of each certificate.
    entries: Vec<(String, PoolKey, Vec<u8>, Value)>,
}

impl CertificatePool {
    /// The id of `certificate`, adding it under `label` when the pool does not hold it. A
    /// certificate is the same when its `QC_FIXED`, header, EVM signature, committee and
    /// `signerYs` are; the label, the successor committee and the note of its first use stay.
    pub fn add(
        &mut self,
        certificate: &Certificate,
        label: &str,
        signed_by: &str,
        next_committee: Option<&Committee>,
        note: Option<&str>,
    ) -> String {
        let key: PoolKey = (
            certificate.qc.clone(),
            certificate.header.clone(),
            certificate.signature_evm.clone(),
            certificate.committee.clone(),
            certificate.signer_ys.clone(),
        );
        if let Some((id, ..)) = self.entries.iter().find(|(_, known, ..)| *known == key) {
            return id.clone();
        }
        let id = format!("c{:03}", self.entries.len() + 1);
        let mut entry = obj([
            ("label", text(label)),
            ("signed_by", text(signed_by)),
            (
                "signer_indices",
                list(
                    certificate
                        .meta
                        .signer_indices
                        .iter()
                        .map(|index| num(*index as u64)),
                ),
            ),
            ("header_fields", parsed_header_json(&certificate.header)),
            ("evm", certificate.evm_json()),
            ("ton", certificate.ton_json()),
            (
                "ton_next_keys",
                next_committee.map_or(Value::Null, |committee| text(&committee.name)),
            ),
        ]);
        if let Some(note) = note {
            insert(&mut entry, "note", text(note));
        }
        self.entries
            .push((id.clone(), key, certificate.signature_ton.clone(), entry));
        id
    }

    /// The first id of `among` (the ids a step submitted) whose certificate has this
    /// `QC_FIXED`, header and signature, in its EVM or its TON form.
    ///
    /// A destination publishes only a certificate of the call. Certificates of one `X` under
    /// different signatures are different entries, so the signature decides which of them
    /// it published.
    pub fn id_of(
        &self,
        qc: &[u8],
        header: &[u8],
        signature: &[u8],
        among: &[String],
    ) -> Option<&str> {
        among.iter().find_map(|wanted| {
            self.entries
                .iter()
                .find(|(id, key, signature_ton, _)| {
                    id == wanted
                        && key.0 == qc
                        && key.1 == header
                        && (key.2 == signature || signature_ton == signature)
                })
                .map(|(id, ..)| id.as_str())
        })
    }

    /// How many certificates the pool holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool holds no certificate.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The `certificates` object of a fixture file: id → entry.
    pub fn as_json(&self) -> Value {
        let mut map = Map::new();
        for (id, _, _, entry) in &self.entries {
            map.insert(id.clone(), entry.clone());
        }
        Value::Object(map)
    }
}

// ---------------------------------------------------------------------------------------------
// The recorder
// ---------------------------------------------------------------------------------------------

/// Where a recorded entry point takes its certified header from.
#[derive(Clone, Copy, Debug)]
pub enum Source<'a> {
    /// A certificate verified in the call (`finalizeFromTaira`, `applyControl`, `voidExpired`).
    Inline(&'a Submission),
    /// The header of a stored checkpoint (`*FromCheckpoint`).
    Checkpoint(&'a [u8]),
}

/// The result of a recorded call.
pub type CallResult = Result<CallOutcome, DestinationError>;

/// One recorded scenario over a fresh destination.
#[derive(Debug)]
pub struct Scenario {
    /// The scenario name.
    pub name: String,
    /// What the scenario shows.
    pub description: String,
    /// The destination the calls run on.
    pub destination: Destination,
    /// The recorded steps.
    pub steps: Vec<Value>,
    pool: Rc<RefCell<CertificatePool>>,
    initial_state: Value,
    strict: bool,
    previous_now_ms: Option<u64>,
}

impl Scenario {
    /// A scenario on a fresh deployment. Its certificates go to `pool`.
    ///
    /// A strict scenario fails when a call does not give the outcome its author expected. A
    /// replay of the same calls on the other flavour is not strict: it records what happens.
    ///
    /// # Panics
    /// When `deployment` is not one a destination can be constructed with.
    pub fn new(
        name: &str,
        description: &str,
        deployment: DeploymentV1,
        pool: &Rc<RefCell<CertificatePool>>,
        strict: bool,
    ) -> Self {
        let destination = Destination::new(deployment)
            .unwrap_or_else(|error| panic!("{name}: the deployment is refused: {error}"));
        Self {
            name: name.to_owned(),
            description: description.to_owned(),
            initial_state: state_json(destination.state(), None),
            destination,
            steps: Vec::new(),
            pool: Rc::clone(pool),
            strict,
            previous_now_ms: None,
        }
    }

    /// The flavour of the destination.
    pub fn flavor(&self) -> DestinationFlavor {
        self.destination.deployment().flavor
    }

    /// Require a whole-second `now_ms` that does not precede the last recorded step.
    fn tick(&mut self, call: &str, now_ms: u64) {
        let context = format!("{} step {} ({call})", self.name, self.steps.len());
        check_destination_clock(now_ms, self.previous_now_ms, &context);
        self.previous_now_ms = Some(now_ms);
    }

    /// The pool id of a certificate, pooled at its first use. `next_committee` is what that
    /// use brings as TON `next_keys`: an inline entry point brings none.
    fn pool_id(&self, submission: &Submission, next_committee: Option<&Committee>) -> String {
        self.pool.borrow_mut().add(
            &submission.certificate,
            &submission.label,
            &submission.signed_by,
            next_committee,
            None,
        )
    }

    /// Append the step of `call` with its `inputs` and what the model answered.
    fn record(
        &mut self,
        call: &str,
        inputs: Vec<(&str, Value)>,
        now_ms: u64,
        result: &CallResult,
        expect: Option<&str>,
    ) {
        self.tick(call, now_ms);
        let mut step = obj([("call", text(call)), ("now_ms", num(now_ms))]);
        // The pool ids of the certificates the step carries: a batch or one inline source.
        let mut submitted = Vec::new();
        for (key, value) in inputs {
            match (key, &value) {
                ("certificates", Value::Array(ids)) => {
                    submitted.extend(ids.iter().filter_map(Value::as_str).map(str::to_owned));
                }
                ("certificate", Value::String(id)) => submitted.push(id.clone()),
                _ => {}
            }
            insert(&mut step, key, value);
        }
        insert(
            &mut step,
            "expected",
            expected_json(result, &self.pool.borrow(), &submitted),
        );
        insert(
            &mut step,
            "state_after",
            state_json(self.destination.state(), Some(now_ms)),
        );
        if let Some(expect) = expect.filter(|_| self.strict) {
            assert_eq!(
                outcome_name(result),
                expect,
                "{}/{call}: the model gave {result:?}",
                self.name
            );
        }
        self.steps.push(step);
    }

    /// The `certificate` or `checkpoint` input of a step, with the certificate pooled.
    ///
    /// Only a checkpoint submission carries successor keys, so a certificate whose first use
    /// is inline is pooled with `ton_next_keys: null`, whatever its [`Submission`] names.
    fn source_input(&self, source: Source<'_>) -> (&'static str, Value) {
        match source {
            Source::Inline(submission) => ("certificate", text(&self.pool_id(submission, None))),
            Source::Checkpoint(header) => {
                ("checkpoint", obj([("header", text(&hx_string(header)))]))
            }
        }
    }

    // -- calls ---------------------------------------------------------------------------------

    /// `submitCheckpoints(certs)` on EVM, `sccp_checkpoint` on TON. Each certificate brings
    /// the keys of its `next_committee`, which only TON reads and records.
    pub fn submit(
        &mut self,
        certificates: &[Submission],
        now_ms: u64,
        expect: Option<&str>,
    ) -> CallResult {
        let ids: Vec<Value> = certificates
            .iter()
            .map(|submission| text(&self.pool_id(submission, submission.next_committee.as_ref())))
            .collect();
        let wires: Vec<TairaCertificateV1> = certificates
            .iter()
            .map(|submission| submission.certificate.wire())
            .collect();
        let next_keys: Vec<Option<Vec<[u8; KEY_LEN]>>> = certificates
            .iter()
            .map(|submission| submission.next_committee.as_ref().map(Committee::keys))
            .collect();
        let result = self
            .destination
            .submit_checkpoints(&wires, &next_keys, now_ms);
        let mut inputs = vec![("certificates", Value::Array(ids))];
        if self.flavor() == DestinationFlavor::Ton {
            inputs.push((
                "next_keys",
                list(certificates.iter().map(|submission| {
                    submission
                        .next_committee
                        .as_ref()
                        .map_or(Value::Null, |committee| text(&committee.name))
                })),
            ));
        }
        let call = call_name(self.flavor(), "submitCheckpoints");
        self.record(call, inputs, now_ms, &result, expect);
        result
    }

    /// `finalizeFromTaira(cert, proof)` or `finalizeFromCheckpoint(ref, proof)`.
    pub fn finalize(
        &mut self,
        source: Source<'_>,
        proof: &MessageProofV1,
        now_ms: u64,
        expect: Option<&str>,
    ) -> CallResult {
        let input = self.source_input(source);
        let flavor = self.flavor();
        let (call, result) = match source {
            Source::Inline(submission) => (
                call_name(flavor, "finalizeFromTaira"),
                self.destination.finalize(
                    CertificateSourceV1::Inline(&submission.certificate.wire()),
                    proof,
                    now_ms,
                ),
            ),
            Source::Checkpoint(header) => (
                call_name(flavor, "finalizeFromCheckpoint"),
                self.destination.finalize(
                    CertificateSourceV1::Checkpoint(&checkpoint_ref(header)),
                    proof,
                    now_ms,
                ),
            ),
        };
        let inputs = vec![input, ("proof", message_proof_json(proof))];
        self.record(call, inputs, now_ms, &result, expect);
        result
    }

    /// `applyControl(cert, proof)` or `applyControlFromCheckpoint(ref, proof)`.
    pub fn apply_control(
        &mut self,
        source: Source<'_>,
        proof: &ControlProofV1,
        now_ms: u64,
        expect: Option<&str>,
    ) -> CallResult {
        let input = self.source_input(source);
        let flavor = self.flavor();
        let (call, result) = match source {
            Source::Inline(submission) => (
                call_name(flavor, "applyControl"),
                self.destination.apply_control(
                    CertificateSourceV1::Inline(&submission.certificate.wire()),
                    proof,
                    now_ms,
                ),
            ),
            Source::Checkpoint(header) => (
                call_name(flavor, "applyControlFromCheckpoint"),
                self.destination.apply_control(
                    CertificateSourceV1::Checkpoint(&checkpoint_ref(header)),
                    proof,
                    now_ms,
                ),
            ),
        };
        let inputs = vec![input, ("proof", control_proof_json(proof))];
        self.record(call, inputs, now_ms, &result, expect);
        result
    }

    /// `voidExpired(nonce, cert, proof)` or `voidExpiredFromCheckpoint(nonce, ref, proof)`.
    pub fn void_expired(
        &mut self,
        nonce: u64,
        source: Source<'_>,
        proof: &MessageProofV1,
        now_ms: u64,
        expect: Option<&str>,
    ) -> CallResult {
        let input = self.source_input(source);
        let flavor = self.flavor();
        let (call, result) = match source {
            Source::Inline(submission) => (
                call_name(flavor, "voidExpired"),
                self.destination.void_expired(
                    nonce,
                    CertificateSourceV1::Inline(&submission.certificate.wire()),
                    proof,
                    now_ms,
                ),
            ),
            Source::Checkpoint(header) => (
                call_name(flavor, "voidExpiredFromCheckpoint"),
                self.destination.void_expired(
                    nonce,
                    CertificateSourceV1::Checkpoint(&checkpoint_ref(header)),
                    proof,
                    now_ms,
                ),
            ),
        };
        let inputs = vec![
            ("nonce", num(nonce)),
            input,
            ("proof", message_proof_json(proof)),
        ];
        self.record(call, inputs, now_ms, &result, expect);
        result
    }

    /// `voidFrozen(firstNonce, count)`. The first nonce is printed as a decimal string: the
    /// rows probe the end of `u64`.
    pub fn void_frozen(
        &mut self,
        first_nonce: u64,
        count: u64,
        now_ms: u64,
        expect: Option<&str>,
    ) -> CallResult {
        let result = self.destination.void_frozen(first_nonce, count, now_ms);
        let inputs = vec![
            ("firstNonce", dec(first_nonce.into())),
            ("count", num(count)),
        ];
        let call = call_name(self.flavor(), "voidFrozen");
        self.record(call, inputs, now_ms, &result, expect);
        result
    }

    /// Record the views of the destination at `now_ms`: a step that calls nothing.
    pub fn views(&mut self, now_ms: u64) {
        self.tick("views", now_ms);
        let state = self.destination.state();
        let deployment = self.destination.deployment();
        let pause = self.destination.pause_state(now_ms);
        let expected = obj([
            (
                "committeeState",
                obj([
                    ("root", hx(&state.committee.root)),
                    ("untilMs", num(state.committee.until_ms)),
                    ("start", num(state.committee.start)),
                    ("high", num(state.committee.high)),
                    ("generation", num(state.committee.generation)),
                ]),
            ),
            (
                "initialCommittee",
                obj([
                    ("generation", num(deployment.pin_generation)),
                    ("root", hx(&deployment.pin_root)),
                    ("start", num(deployment.pin_start_height)),
                    ("untilMs", num(deployment.pin_until_ms)),
                ]),
            ),
            (
                "pauseState",
                obj([
                    ("parliamentPaused", Value::Bool(pause.parliament_paused)),
                    ("fastPauseUntilMs", num(pause.fast_pause_until_ms)),
                    ("controlNonce", num(pause.control_nonce)),
                    ("effective", Value::Bool(pause.effective)),
                ]),
            ),
            (
                "mintingPaused",
                Value::Bool(self.destination.minting_paused(now_ms)),
            ),
            ("equivocated", Value::Bool(state.committee.equivocated)),
            ("controlNonce", num(state.control_nonce)),
            ("opCount", num(state.op_count)),
            ("live", Value::Bool(self.destination.is_live(now_ms))),
        ]);
        self.steps.push(obj([
            ("call", text("views")),
            ("now_ms", num(now_ms)),
            ("expected", expected),
            ("state_after", state_json(state, Some(now_ms))),
        ]));
    }

    /// The scenario row: `{name, description, flavor, deployment, initial_state, steps}`.
    pub fn as_json(&self) -> Value {
        let deployment = self.destination.deployment();
        obj([
            ("name", text(&self.name)),
            ("description", text(&self.description)),
            ("flavor", text(deployment.flavor.name())),
            ("deployment", deployment_json(deployment)),
            ("initial_state", self.initial_state.clone()),
            ("steps", Value::Array(self.steps.clone())),
        ])
    }
}

fn checkpoint_ref(header: &[u8]) -> CheckpointRefV1 {
    CheckpointRefV1 {
        header: header.to_vec(),
    }
}

// ---------------------------------------------------------------------------------------------
// Checks of recorded rows
// ---------------------------------------------------------------------------------------------

/// The steps of a scenario row as [`Scenario::as_json`] writes it.
///
/// # Panics
/// When `row` has no `steps` array.
pub fn steps_of(row: &Value) -> &[Value] {
    row["steps"]
        .as_array()
        .expect("a scenario row lists its steps")
}

/// The outcome a step records: `expected.outcome`, and `ok` for a `views` step, which calls
/// nothing.
///
/// # Panics
/// When a step other than `views` records no outcome.
pub fn step_outcome(step: &Value) -> &str {
    step["expected"]["outcome"].as_str().unwrap_or_else(|| {
        assert_eq!(
            step["call"].as_str(),
            Some("views"),
            "a call records its outcome"
        );
        "ok"
    })
}

/// Check the destination clock on every step of a scenario row and return how many steps it
/// has: `now_ms` is a whole second and never earlier than the step before it
/// ([`check_destination_clock`]).
///
/// The recorder enforces the rule while it records. This is the same rule read back from a
/// row, so that a test can check a whole document as it is written.
///
/// # Panics
/// When a step has no `now_ms` or breaks the rule.
pub fn check_scenario_clock(row: &Value) -> usize {
    let name = row["name"].as_str().expect("a scenario row has a name");
    let steps = steps_of(row);
    let mut previous_ms = None;
    for (index, step) in steps.iter().enumerate() {
        let context = format!("{name} step {index}");
        let now_ms = step["now_ms"]
            .as_u64()
            .unwrap_or_else(|| panic!("{context} has no now_ms"));
        check_destination_clock(now_ms, previous_ms, &context);
        previous_ms = Some(now_ms);
    }
    steps.len()
}

/// Check every outcome of a scenario row against the error table of §5.2.2
/// ([`DestinationError`]) and return the names of the errors the row reports.
///
/// An outcome is `ok` or the name of an error that the row's flavour can report: an EVM
/// custom error on `evm`, an exit code on `ton`. A refused step records no event, and it
/// records `error_args` exactly when the error carries an argument.
///
/// # Panics
/// When a step breaks one of these rules, or the row names no flavour.
pub fn check_scenario_outcomes(row: &Value) -> BTreeSet<&'static str> {
    let name = row["name"].as_str().expect("a scenario row has a name");
    let flavor = row["flavor"].as_str().expect("a scenario row has a flavor");
    let mut reported = BTreeSet::new();
    for (index, step) in steps_of(row).iter().enumerate() {
        let outcome = step_outcome(step);
        if outcome == "ok" {
            continue;
        }
        let context = format!("{name} step {index}: {outcome}");
        let error = DestinationError::from_name(outcome)
            .unwrap_or_else(|| panic!("{context} is not a name of the error table"));
        let reportable = match flavor {
            "evm" => error.evm_signature().is_some(),
            "ton" => error.ton_exit_code().is_some(),
            other => panic!("{name}: {other} is not a destination flavor"),
        };
        assert!(
            reportable,
            "{context} is not an error of the {flavor} flavor"
        );
        let expected = &step["expected"];
        assert_eq!(expected["events"], list([]), "{context} records events");
        assert_eq!(
            expected.get("error_args").is_some(),
            error.argument().is_some(),
            "{context}: error_args goes with an error that carries an argument"
        );
        reported.insert(error.name());
    }
    reported
}
