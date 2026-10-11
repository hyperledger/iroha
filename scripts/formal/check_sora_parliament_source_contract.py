#!/usr/bin/env python3
"""Check that the bounded Parliament model remains bound to implementation guards.

This deterministic structural check is intentionally narrower than parsing or
compiling Rust. It fails when a modeled guard disappears, when authenticated
registration or reducer-derived corpus boundaries regress, when a plaintext or
fallback transition enters the closed Parliament instruction enum, when global
timed-OVN reservation admission or restore loses fail-atomic capacity checks, when a
persisted attempt can exceed the authoritative framed-state bound, when a signed
draft can claim a consensus-owned certificate outcome, or when the
current specifications regress to the retired proposal-time JIT description. It
also pins the modeled no-pulse hidden-electorate capacity failure and atomic
Policy-to-Confirmation capacity handoff. The model and implementation must also
share one proposal-wide fresh-randomness redraw ceiling across successor
attempts, sortition/Confirmation generations, and timed-OVN ballot retries;
committed transport replay must remain state-idempotent.
The first-release `Executable::IvmProved` transaction shape remains typed and
fee-checked through native signed-assessment admission and actual User payment
recording. Opaque signed committee/staking authority is checked independently
before optional policy lookup. Private execution admission stays closed until the complete
native STARK relation exists. The retired binding-only Torii producer must not
re-enter the proof-carrying governance corridor.
It also keeps the PR model run bound to archived copies of its exact inputs and
to stable, source-identified result metadata.

Requires Python 3.10+ and the repository sources; no third-party dependencies or
environment variables are needed. Paths resolve from this script and checks are
read-only.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    path = ROOT / relative
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise RuntimeError(f"cannot read {relative}: {error}") from error
    marker = re.search(r"^(?:<<<<<<< .+|=======|>>>>>>> .+)$", text, re.M)
    if marker is not None:
        raise RuntimeError(
            f"{relative}: unresolved merge marker {marker.group(0)!r}"
        )
    return text


RUST_INCLUDE_LINE = re.compile(
    r'^(?P<indent>[ \t]*)include!\(\s*"(?P<path>[^"]+)"\s*\);[ \t]*$', re.M
)


def read_rust_with_includes(relative: str, stack: tuple[str, ...] = ()) -> str:
    """Read one Rust source and recursively expand its textual item includes."""
    if relative in stack:
        chain = " -> ".join((*stack, relative))
        raise RuntimeError(f"cyclic Rust include chain: {chain}")
    text = read(relative)
    parent = Path(relative).parent

    def expand(match: re.Match[str]) -> str:
        include_path = Path(match.group("path"))
        if include_path.is_absolute() or ".." in include_path.parts:
            raise RuntimeError(
                f"{relative}: non-local Rust include path {include_path.as_posix()!r}"
            )
        child = (parent / include_path).as_posix()
        expanded = read_rust_with_includes(child, (*stack, relative))
        indent = match.group("indent")
        if not indent:
            return expanded
        return indent + expanded.replace("\n", f"\n{indent}")

    return RUST_INCLUDE_LINE.sub(expand, text)


def require_all(relative: str, text: str, needles: tuple[str, ...]) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        rendered = ", ".join(repr(item) for item in missing)
        raise RuntimeError(f"{relative}: missing modeled source binding(s): {rendered}")


def require_storage_borrowed_iterators(source: str) -> None:
    """Bind Parliament's ordered reverse reads to native, owner-borrowed GATs."""
    path = "crates/mv/src/storage.rs"
    # These declarations and read methods contain no string literals. Comments
    # cannot substitute for a live bound, concrete family, or original delegate.
    code = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
    code = re.sub(r"\s+", "", code)

    def body(text: str, declaration: str) -> str:
        if text.count(declaration) != 1:
            raise RuntimeError(f"{path}: borrowed iterator declaration changed: {declaration}")
        start = text.index("{", text.index(declaration) + len(declaration))
        depth = 1
        for end in range(start + 1, len(text)):
            depth += (text[end] == "{") - (text[end] == "}")
            if depth == 0:
                return text[start + 1:end]
        raise RuntimeError(f"{path}: unclosed borrowed iterator declaration")

    trait = body(code, "pubtraitStorageReadOnly<K:Key,V:Value>")
    for binding in (
        "typeIter<'a>:DoubleEndedIterator<Item=(&'aK,&'aV)>+ExactSizeIteratorwhereSelf:'a;",
        "typeRangeIter<'a>:DoubleEndedIterator<Item=(&'aK,&'aV)>whereSelf:'a;",
        "fniter(&self)->Self::Iter<'_>;",
        "fnrange<Q>(&self,bounds:implRangeBounds<Q>)->Self::RangeIter<'_>whereK:Borrow<Q>,Q:Ord+?Sized;",
    ):
        if trait.count(binding) != 1:
            raise RuntimeError(f"{path}: borrowed iterator trait contract changed: {binding}")

    implementations = {
        "View": (
            "match&self.blocks{ViewInner::Txn(txn)=>txn.iter(),ViewInner::Snapshot(snapshot)=>snapshot.iter(),}",
            "match&self.blocks{ViewInner::Txn(txn)=>txn.range(bounds),ViewInner::Snapshot(snapshot)=>snapshot.range(bounds),}",
        ),
        "Block": (
            "self.assert_operable();self.writers.as_ref().blocks.iter()",
            "self.assert_operable();self.writers.as_ref().blocks.range(bounds)",
        ),
        "Transaction": ("self.current().iter()", "self.current().range(bounds)"),
    }
    for owner, expected in implementations.items():
        implementation = body(
            code,
            f"impl<K:Key,V:Value,M:StorageMode<K,V>>StorageReadOnly<K,V>for{owner}<'_,K,V,M>",
        )
        for family in ("Iter", "RangeIter"):
            binding = f"type{family}<'a>={family}<'a,K,V,M::Charge>whereSelf:'a;"
            if implementation.count(binding) != 1:
                raise RuntimeError(f"{path}: {owner} borrowed iterator family changed: {family}")
        for declaration, original in zip(
            (
                "fniter(&self)->Self::Iter<'_>",
                "fnrange<Q>(&self,bounds:implRangeBounds<Q>)->Self::RangeIter<'_>whereK:Borrow<Q>,Q:Ord+?Sized,",
            ),
            expected,
        ):
            if body(implementation, declaration) != original:
                raise RuntimeError(f"{path}: {owner} borrowed iterator must use its original native owner")


def require_identifiers_absent(
    relative: str, text: str, identifiers: tuple[str, ...]
) -> None:
    """Reject exact retired identifiers without matching longer live names."""
    alternatives = "|".join(re.escape(identifier) for identifier in identifiers)
    pattern = re.compile(
        rf"(?<![A-Za-z0-9_])(?P<identifier>{alternatives})(?![A-Za-z0-9_])"
    )
    found = sorted({match.group("identifier") for match in pattern.finditer(text)})
    if found:
        rendered = ", ".join(repr(item) for item in found)
        raise RuntimeError(
            f"{relative}: retired public Parliament identifier(s) remain: {rendered}"
        )


def require_public_items_absent(
    relative: str, text: str, identifiers: tuple[str, ...]
) -> None:
    """Reject exact retired public item/field declarations while allowing private internals."""
    alternatives = "|".join(re.escape(identifier) for identifier in identifiers)
    pattern = re.compile(
        rf"(?m)^\s*pub\s+(?:"
        rf"(?:struct|enum|type|const|fn|mod)\s+"
        rf"(?P<item>{alternatives})(?![A-Za-z0-9_])"
        rf"|(?P<field>{alternatives})(?![A-Za-z0-9_])\s*:"
        rf")"
    )
    found = sorted(
        {match.group("item") or match.group("field") for match in pattern.finditer(text)}
    )
    if found:
        rendered = ", ".join(repr(item) for item in found)
        raise RuntimeError(
            f"{relative}: retired public Parliament item(s) remain: {rendered}"
        )


def require_path_absent(relative: str) -> None:
    """Reject a retired source module if it is recreated."""
    if (ROOT / relative).exists():
        raise RuntimeError(f"{relative}: retired public Parliament module remains")


def section(text: str, start: str, end: str, relative: str) -> str:
    pattern = re.compile(re.escape(start) + r"(?P<body>.*?)" + re.escape(end), re.S)
    match = pattern.search(text)
    if match is None:
        raise RuntimeError(f"{relative}: cannot locate section beginning {start!r}")
    return match.group("body")


RUST_TEXT_PATH = Path(__file__).resolve().with_name("rust_text.py")
_RUST_TEXT: dict[str, object] = {}


def mask_rust(source: str) -> str:
    """Blank Rust comments and literals, preserving offsets, with the shared lexer."""
    if not _RUST_TEXT:
        namespace = {"__name__": "sora_parliament_rust_text", "__file__": str(RUST_TEXT_PATH)}
        exec(compile(RUST_TEXT_PATH.read_bytes(), str(RUST_TEXT_PATH), "exec"), namespace)
        _RUST_TEXT.update(namespace)
    return _RUST_TEXT["mask_rust_comments"](source)


def rust_item(text: str, declaration: str, relative: str) -> str:
    """Return one live Rust item from its declaration through its matching brace.

    Comments and literals are masked first, so a commented or quoted copy of the
    declaration is not an owner and a brace inside a string cannot move the end.
    """
    masked = mask_rust(text)
    starts = [match.start() for match in re.finditer(re.escape(declaration), masked)]
    if len(starts) != 1:
        raise RuntimeError(
            f"{relative}: expected one live declaration {declaration!r}, found {len(starts)}"
        )
    # A declaration may include its own opening brace; signatures contain none.
    opening = masked.find("{", starts[0])
    depth = 0
    for index in range(max(opening, 0), len(masked)):
        depth += (masked[index] == "{") - (masked[index] == "}")
        if depth == 0:
            return text[starts[0]:index + 1]
    raise RuntimeError(f"{relative}: unclosed item {declaration!r}")


def compact_rust(text: str) -> str:
    """Drop line comments and all whitespace for exact statement comparison."""
    return re.sub(r"\s+", "", re.sub(r"//[^\n]*", "", text))


def public_field_names(text: str) -> tuple[str, ...]:
    """Return public named fields from one Rust DTO source section."""
    return tuple(re.findall(r"\bpub\s+([A-Za-z_][A-Za-z0-9_]*)\s*:", text))


def require_opaque_release_authorizations(tle_release: str) -> None:
    """Keep constructor-authenticated release owners outside payload and frame codecs."""
    tle_release_path = "crates/iroha_core/src/tle_release.rs"
    authorized_context = section(
        tle_release,
        "/// Constructor-authenticated authorization for one committed TLE release share.",
        "/// Authorize a TLE release from one point-in-time committed state view.",
        tle_release_path,
    )
    for forbidden in (
        "NoritoSerialize", "SerializePayload", "DeserializePayload",
        "JsonSerialize", "Encode", "pub identity:",
    ):
        if forbidden in authorized_context:
            raise RuntimeError(
                f"{tle_release_path}: opaque release authorization exposes {forbidden!r}"
            )
    if re.search(
        r"impl\s+(?:Try)?From<[^>]*ValidatedTleReleaseProjectionV1[^>]*>\s+for\s+AuthorizedTleReleaseContextV1",
        tle_release,
    ):
        raise RuntimeError(
            f"{tle_release_path}: public broker projection can mint opaque Core authorization"
        )

def require_opaque_release_projection(tle_release: str) -> None:
    """Public verification results must never become decodable capabilities."""
    tle_release_path = "crates/iroha_core_timed_ovn/src/tle.rs"
    validated_projection = section(
        tle_release,
        "/// Revalidated public statement admitted by an authenticated runtime broker.",
        "/// Closed failures while validating a public authenticated-broker projection.",
        tle_release_path,
    )
    for forbidden in (
        "NoritoSerialize", "NoritoDeserialize", "SerializePayload", "DeserializePayload",
        "JsonSerialize", "JsonDeserialize",
    ):
        if forbidden in validated_projection:
            raise RuntimeError(
                f"{tle_release_path}: validated broker projection exposes {forbidden!r}"
            )

def require_opaque_casting_authorization(casting: str) -> None:
    """Keep the replay-validated casting context outside payload and frame codecs."""
    casting_path = "crates/iroha_core/src/tle_release/casting.rs"
    authorized_casting = section(
        casting,
        "/// Constructor-authenticated, replay-validated timed-OVN casting context.",
        "/// Authorize and replay-validate one public timed-OVN casting context.",
        casting_path,
    )
    for forbidden in (
        "NoritoSerialize",
        "NoritoDeserialize",
        "SerializePayload",
        "DeserializePayload",
        "JsonSerialize",
        "JsonDeserialize",
        "ballot_records:",
        "dropout_participant_hashes:",
        "partial_release:",
        "opening_root:",
    ):
        if forbidden in authorized_casting:
            raise RuntimeError(
                f"{casting_path}: opaque casting authorization exposes {forbidden!r}"
            )

def require_parliament_broker_primitives(source: str) -> None:
    """Bind Parliament operation IDs and their explicitly framed attestation DTOs."""
    relative = "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs"
    require_all(
        relative,
        source,
        (
            "OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1: u16 = 124",
            "OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1: u16 = 125",
        ),
    )
    ordinal_test = section(
        source,
        "fn post_soracloud_operation_ids_are_exact_and_ordered() {",
        "\n}\n",
        relative,
    )
    require_all(
        relative,
        " ".join(ordinal_test.split()),
        (
            "(OPERATION_PARLIAMENT_TLE_PARTIAL_RELEASE_SIGN_V1, 124)",
            "(OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1, 125)",
            "for (operation, expected) in exact {",
            "assert_eq!(operation, expected);",
            "assert!(super::super::operation_is_known(operation));",
        ),
    )
    for name, fields in (
        (
            "ParliamentTleCapabilityAttestRequestWireV1",
            (
                "pub(super) key_session: iroha_core_timed_ovn::tle::TleKeySessionPublicStateV1",
                "pub(super) participant_index: u16",
            ),
        ),
        (
            "ParliamentTleCapabilityAttestResultWireV1",
            (
                "pub(super) key_session_id: iroha_data_model::governance::types::TleKeySessionId",
                "pub(super) transcript_hash: [u8; 32]",
                "pub(super) participant_index: u16",
            ),
        ),
    ):
        frame_id = f"irohad::runtime_provider_broker::protocol::primitives::{name}"
        pattern = (
            r"define_broker_wire_struct!\(\s*owned\s+frame\s+"
            + re.escape(f'"{frame_id}"')
            + r"\s*;\s*pub\s*\(\s*super\s*\)\s+"
            + re.escape(name)
            + r"\s*\{(?P<fields>[^{}]*)\}\s*\);"
        )
        declarations = list(re.finditer(pattern, source))
        if len(declarations) != 1:
            raise RuntimeError(f"{relative}: expected one framed declaration for {name}")
        require_all(
            relative, " ".join(declarations[0].group("fields").split()), fields
        )


def require_parliament_broker_dispatch(dispatch: str, consensus: str) -> None:
    """Keep the authenticated router connected to the validating attestation owner."""
    dispatch_path = (
        "crates/irohad/src/runtime_provider_broker/platform_operation_dispatch.rs"
    )
    consensus_path = (
        "crates/irohad/src/runtime_provider_broker/"
        "protocol/platform/operation_dispatch/consensus.rs"
    )
    admission = section(
        dispatch,
        "fn dispatch_server_operation_with_session(",
        "let result = match (request.binding.slot, request.operation) {",
        dispatch_path,
    )
    require_all(
        dispatch_path,
        " ".join(admission.split()),
        (
            "let requalify = || qualify_server_binding(state, &request.binding, request.provider_metadata_digest); requalify()?;",
        ),
    )
    require_all(
        dispatch_path,
        " ".join(dispatch.split()),
        (
            '#[path = "protocol/platform/operation_dispatch/consensus.rs"] mod consensus_operations;',
            "let parliament_tle_partial_release_signer_slot = IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id();",
            "(slot, OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1) if slot == parliament_tle_partial_release_signer_slot => { consensus_operations::parliament_tle_capability_attest(state, request) }",
        ),
    )
    handler = section(
        consensus,
        "pub(super) fn parliament_tle_capability_attest(",
        "\n}",
        consensus_path,
    )
    handler = " ".join(handler.split())
    require_all(
        consensus_path,
        handler,
        (
            "let requalify = || qualify_server_binding(state, &request.binding, request.provider_metadata_digest);",
            "decode_parliament_tle_capability_attest_request(&request.payload, &state.network_id)?;",
            "broker_backend!(state, parliament_tle_partial_release_signer)",
            ".attest_partial_release_capability(&session, request.participant_index)",
            "if !attestation.matches(&session, request.participant_index) { return Err(BrokerError::StaleOrRevoked); }",
            "requalify()?;",
            "&ParliamentTleCapabilityAttestResultWireV1 { key_session_id: attestation.key_session_id(), transcript_hash: attestation.transcript_hash(), participant_index: attestation.participant_index(), }, MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1,",
        ),
    )
    positions = [
        handler.find(marker)
        for marker in (
            "decode_parliament_tle_capability_attest_request(",
            ".attest_partial_release_capability(",
            "if !attestation.matches(",
            "requalify()?;",
            "encode_canonical(",
        )
    ]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise RuntimeError(
            f"{consensus_path}: attestation must validate and requalify before encoding"
        )


def require_public_finding_endorsement_order(types: str) -> None:
    """Bind strict supporter ordering to certificate validation, regardless of wrapping."""
    path = "crates/iroha_data_model/src/governance/types.rs"
    evidence = section(
        types, "    fn validate_body_evidence(", "    fn validate_ballot_identity(", path
    )
    ordered_supporters = re.compile(
        r"!\s*public_finding\s*\.\s*endorsing_assignments\s*"
        r"\.\s*windows\s*\(\s*2\s*\)\s*"
        r"\.\s*all\s*\(\s*\|\s*pair\s*\|\s*"
        r"pair\s*\[\s*0\s*\]\s*<\s*pair\s*\[\s*1\s*\]\s*\)"
    )
    if ordered_supporters.search(evidence) is None:
        raise RuntimeError(
            f"{path}: certificate validation must reject supporters that are not strictly ordered"
        )


def require_sortition_registration_guards(world: str) -> None:
    """Follow both registration transitions into their shared admission helper."""
    path = "crates/iroha_core/src/smartcontracts/isi/world.rs"
    for start, end, snapshot, candidates in (
        (
            "gov::ParliamentLifecycleTransitionV1::RegisterInitialSortition => {",
            "gov::ParliamentLifecycleTransitionV1::RegisterSortitionRequest(payload) => {",
            "canonical_initial_parliament_sortition_v1(&attempt, state_transaction)?",
            "candidates",
        ),
        (
            "gov::ParliamentLifecycleTransitionV1::RegisterSortitionRequest(payload) => {",
            "gov::ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(payload) => {",
            "canonical_parliament_candidate_snapshot_v1(",
            "expected_candidates",
        ),
    ):
        branch = section(world, start, end, path)
        require_all(path, branch, (snapshot,))
        admission = re.compile(
            r"no_result_kind\s*=\s*apply_parliament_sortition_request_batch_v1\s*\(\s*"
            r"&mut\s+attempt\s*,\s*payload\s*,\s*"
            + re.escape(candidates)
            + r"\s*,\s*state_transaction\s*,?\s*\)\s*\?"
        )
        if admission.search(branch) is None:
            raise RuntimeError(
                f"{path}: {start!r} must use shared sortition admission with its canonical candidates"
            )
    admission_helper = section(
        world,
        "    fn apply_parliament_sortition_request_batch_v1(",
        "    fn ensure_parliament_logical_beacon_v1(",
        path,
    )
    require_all(
        path,
        admission_helper,
        (
            "entry.request.request_height != current_height",
            "ensure_parliament_logical_beacon_v1(",
            "entry.request.target_seats != configured_target",
            "ParliamentDecisionModeV1::HiddenBindingBallot",
            ".record_hidden_sortition_capacity_failure_batch(",
            "ParliamentNoResultKindV1::SortitionRetriesExhausted",
            ".register_sortition_request_batch(",
        ),
    )
    anonymity_guard = re.compile(
        r"if\s+!crate::governance::parliament::"
        r"hidden_ballot_population_meets_anonymity_floor_v1\s*\(\s*"
        r"expected_candidates\.len\(\)\s*,?\s*\)\s*&&\s*hidden_body_requested"
    )
    if anonymity_guard.search(admission_helper) is None:
        raise RuntimeError(
            f"{path}: shared sortition admission must enforce the hidden-electorate anonymity floor"
        )


def require_sortition_retry_liveness(reducer: str) -> None:
    """Bind the model's one-generation retry and terminal audit to the reducer and planner.

    The model's single sortition generation stands for every failed body, so the reducer must
    admit only a retry of every `NoRoster` body (a partial retry could spend the last redraw
    unit and strand another failed body), on a fresh pulse slot whose awaiting requests share
    one snapshot. A later-stage body may exhaust its sortition while an earlier stage is live,
    and the terminal audit must accept that rejection. The driver plan must emit that exact
    retry (but not a futile capacity re-record) and keep only steps whose successor
    persistence accepts.
    """
    path = "crates/iroha_core/src/governance/parliament.rs"

    def code(item: str) -> str:
        return compact_rust(mask_rust(rust_item(reducer, item, path)))

    require_all(
        path,
        code("fn validate_sortition_registration_batch_v1("),
        (
            ".no_roster_sortition_generations_v1().into_keys()",
            "registered_bodies!=failed_bodies",
            "ifself.sortition_generation_slots_v1().contains(&ParliamentPulseSlotV1::new("
            "first.request.beacon_session_id,first.request.pulse_height,)){"
            "returnErr(ParliamentReducerErrorV1::InvalidSortitionPulseSchedule);}",
        ),
    )
    require_all(
        path,
        code("pub fn validate(&self) -> Result<(), ParliamentReducerErrorV1> {"),
        (
            "election.attempt.status==BodyElectionAttemptStatusV1::AwaitingPulse",
            ".entry(slot).or_insert(election.candidate_snapshot_index)"
            "!=election.candidate_snapshot_index",
        ),
    )
    require_all(
        path,
        code("fn no_roster_sortition_generations_v1("),
        (
            "self.active_elections.iter()",
            "self.active_sortition_capacity_failures.iter()",
            "BodyElectionAttemptStatusV1::NoRoster",
        ),
    )
    require_all(
        path,
        code("fn expected_completed_body_count_v1("),
        (
            "BodyInstanceStatusV1::NoResult=>returnOk(index)",
            "self.required_bodies[index..].iter().any(",
        ),
    )
    planner_path = "crates/iroha_core/src/governance/parliament/planner.rs"
    planner = read(planner_path)
    require_all(
        planner_path,
        compact_rust(mask_rust(rust_item(planner, "fn try_due<T>(", planner_path))),
        ("apply(&mutnext).is_err()||next.validate().is_err()",),
    )
    plan = compact_rust(mask_rust(rust_item(planner, "pub fn plan_driver_v1(", planner_path)))
    require_all(
        planner_path,
        plan,
        (
            ".next_sortition_retry_v1(height,logical_beacon,governance,eligible)",
            "letrecords_capacity_evidence=hidden_body_requested"
            "&&!hidden_ballot_population_meets_anonymity_floor_v1(candidate_snapshot.len());",
            "if!records_capacity_evidence&&trial.register_sortition_request_batch(",
            ".is_ok()&&trial.validate().is_ok()",
            "ParliamentLifecycleTransitionV1::RegisterSortitionRequest(",
        ),
    )


def require_block_start_construction(state: str) -> None:
    """Follow the actual constructor into its original-writer, armed-owner handoff."""
    state_path = "crates/iroha_core/src/state.rs"
    path = "crates/iroha_core/src/state/state_block_construction.rs"

    def compact(text: str) -> str:
        return re.sub(r"\s+", "", re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S))

    state_code = compact(state)
    declaration = '#[path="state/state_block_construction.rs"]modstate_block_construction;'
    if state_code.count(declaration) != 1:
        raise RuntimeError(f"{state_path}: start construction must use its defining module")
    code = compact(read(path))
    signature = (
        "implState{pub(super)fnconstruct_acquired_block<'state,R>("
        "&'stateself,acquired:canonical_runtime::AcquiredRuntimeBlock<'state>,"
        "curr_block:BlockHeader,finish:implFnOnce(StateBlock<'state>)->R,)->R{"
    )
    if not code.startswith("usesuper::*;" + signature):
        raise RuntimeError(f"{path}: start construction must consume the original acquisition")
    ordered = (
        "letmutfinish=Some(finish);",
        "letmutoriginal=Some(acquired);",
        'letacquired=original.as_ref().expect("originalacquiredStateblock").fields();',
        "gas_limit_per_block=Some(gas_limit_from_parameters(acquired.world.parameters()));",
        "runtime_policy=Some(canonical_runtime::CapturedRuntimePolicy::capture(",
        "finish_state_block_construction(||{",
    )
    positions = [code.find(token) for token in ordered]
    if any(code.count(token) != 1 for token in ordered) or positions != sorted(positions):
        raise RuntimeError(f"{path}: start construction must retain original writers through metadata")
    handoff = section(code, "finish_state_block_construction(||{", "})}}#[inline(never)]", path)
    prefix = (
        "letcanonical_runtime::AcquiredRuntimeBlockFields{world,transactions,"
        "commit_topology,prev_commit_topology,canonical_runtime,native_execution_tip,"
        "projection,block_hashes,da_rewind_releases,}=original.take()"
        '.expect("originalacquiredStateblock").into_fields();'
        "letblock=StateBlock::from_fields(StateBlockFields{"
    )
    suffix = '});finish.take().expect("originalStatefinishcontinuation")(block)'
    if not handoff.startswith(prefix) or not handoff.endswith(suffix):
        raise RuntimeError(f"{path}: start construction must arm the original block before its continuation")
    fields = handoff[len(prefix):-len(suffix)]
    # Split only top-level field separators; nested calls, attributes and strings
    # cannot forge a second shorthand writer or substitute a commented binding.
    parts, start, depth, quoted, escaped = [], 0, 0, False, False
    for index, char in enumerate(fields):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(fields[start:index])
            start = index + 1
    if fields[start:] or depth != 0 or quoted:
        raise RuntimeError(f"{path}: start construction has an incomplete original field handoff")
    bindings = {}
    for field in parts:
        field = re.sub(r'^#\[cfg\(feature="[^"]+"\)\]', "", field)
        name, separator, value = field.partition(":")
        if name in bindings or re.fullmatch(r"[a-z_][a-z_0-9]*", name) is None:
            raise RuntimeError(f"{path}: start construction has duplicate or invalid original fields")
        bindings[name] = value if separator else name
    expected = {name: name for name in (
        "world",
    )}
    expected.update({
        "_da_rewind_releases": "da_rewind_releases",
        "canonical_runtime": "block_field::BlockField::new(canonical_runtime)",
        "native_execution_tip": "block_field::BlockField::new(native_execution_tip)",
        "block_hashes": "block_hash_field::BlockHashField::new(block_hashes)",
        "transactions": "storage_transactions::TransactionsBlockField::new(transactions)",
        "commit_topology": "block_field::BlockField::new(commit_topology)",
        "prev_commit_topology": "block_field::BlockField::new(prev_commit_topology)",
        "local_storage_refusal": "None",
        "_da_rewind_releases": "da_rewind_releases",
        "_read_releases": "StateViewReleases::new(self)",
        "state_ref": "self", "_curr_block": "curr_block",
        "nexus": "projection.nexus", "start_of_block_effects_applied": "false",
        "pending_parliament_telemetry_events":
            'pending_parliament_telemetry_events.take().expect("preparedStateinput")',
    })
    if any(bindings.get(name) != value for name, value in expected.items()):
        raise RuntimeError(f"{path}: start construction substituted original writers or Parliament inputs")
    if not code.endswith("#[inline(never)]fnfinish_state_block_construction<R>(finish:implFnOnce()->R)->R{finish()}"):
        raise RuntimeError(f"{path}: start construction must retain its bounded borrowed finish")
    for owner in (
        "impl<'state>StateBlock<'state>{fnfrom_fields(fields:StateBlockFields<'state>)->Self{Self{fields:Some(fields),world_cut_capture:None,publication:None,}}",
        (
            "implDropforStateBlock<'_>{fndrop(&mutself){"
            "letSome(fields)=self.fields.as_ref()else{return;};"
            "letexecution=fields.pipeline_ivm_prepared_cache.execution_budget().clone();"
            "letmembership=fields.state_ref.transactions.budget.clone();"
            "lethashes=fields.state_ref.block_hashes.budget.clone();"
            "execution.with_deferred_refund_notifications(|_|{"
            "membership.with_deferred_refund_notifications(|_|{"
            "hashes.with_deferred_refund_notifications(|_|{"
            "mv::BlockRetirement::release_writers(self);"
            "drop(self.world_cut_capture.take());drop(self.fields.take());drop(self.publication.take());})})});}}"
        ),
    ):
        if state_code.count(owner) != 1:
            raise RuntimeError(f"{state_path}: start construction must install the original armed State owner")


def require_block_start_enactment_phases(state: str) -> None:
    """Bind original ordered start ownership to bounded borrowed phase helpers."""
    state_path = "crates/iroha_core/src/state.rs"
    wrapper = compact_rust(mask_rust(rust_item(
        state,
        "    fn block_with_owned_start_stages<'state, E: std::fmt::Debug, T, R>(",
        state_path,
    )))
    delegate = (
        "self.block_with_owned_start_stages_with_carrier("
        "curr_block,None,before_start,after_start)"
    )
    if wrapper.count(delegate) != 1 or not wrapper.endswith("{" + delegate + "}"):
        raise RuntimeError(f"{state_path}: start phases must retain their original carrier delegate")
    constructor = rust_item(
        state,
        "    fn block_with_owned_start_stages_with_carrier<'state, E: std::fmt::Debug, T, R>(",
        state_path,
    )
    phases = section(
        constructor,
        "        // Height-trigger: open/close referenda at scheduled heights",
        "        let current_slot =",
        state_path,
    )
    # This small statement region contains only the original height and the three
    # unconditional calls. Ignore line comments, but reject hidden conditions,
    # substituted owners/heights, duplicate calls, or swapped execution order.
    phases = re.sub(r"//[^\n]*", "", phases)
    expected = (
        "let now_h = sb._curr_block.height().get();"
        "Self::apply_block_start_private_settlement_expiry(&mut sb, now_h)"
        ".map_err(StateBlockStartError::Storage)?;"
        "Self::apply_block_start_parliament_enactments(&mut sb, now_h)?;"
        "let sccp_header = sb._curr_block;"
        "crate::smartcontracts::isi::sccp::hook::apply_block_start(&mut sb, &sccp_header)"
        ".map_err(StateBlockStartError::Storage)?;"
    )
    if re.sub(r"\s+", "", phases) != re.sub(r"\s+", "", expected):
        raise RuntimeError(f"{state_path}: start phases must use the original block and height in order")
    compact = re.sub(r"\s+", "", constructor)
    # The source quota owner may complete an intrinsic rejection before shared
    # start effects. Bind that exact owner and remove only this checked branch
    # before checking the one ordinary after-start continuation.
    intrinsic_rejection = (
        "ifmatches!(sb.fastpq_source_quota,Some(Err(_))){"
        "letresult=after_start(&mutsb,continuation).map_err(StateBlockStartError::Stage)?;"
        "returnOk((sb,result));}"
    )
    if compact.count(intrinsic_rejection) != 1:
        raise RuntimeError(f"{state_path}: start phases lost the original intrinsic source refusal")
    compact = compact.replace(intrinsic_rejection, "", 1)
    ordered = (
        "letacquired=self.acquire_canonical_runtime_block(false)?;",
        "letmutsb=self.construct_acquired_block(acquired,curr_block,Box::new);",
        "sb.ordinary_carrier_membership_source=ordinary_source;",
        "sb.network_policy_routes=policy_routes;",
        "sb.freeze_fastpq_source_context();",
        "sb.require_storage_admission()?;",
        "sb.freeze_axt_block_start();",
        "letcontinuation=before_start(&mutsb).map_err(StateBlockStartError::Stage)?;",
        "Self::apply_block_start_private_settlement_expiry(&mutsb,now_h).map_err(StateBlockStartError::Storage)?;",
        "Self::apply_block_start_parliament_enactments(&mutsb,now_h)?;",
        "letsccp_header=sb._curr_block;",
        "crate::smartcontracts::isi::sccp::hook::apply_block_start(&mutsb,&sccp_header).map_err(StateBlockStartError::Storage)?;",
        "sb.start_of_block_effects_applied=true;",
        "sb.capture_execution_output_capacity();",
        "letresult=after_start(&mutsb,continuation).map_err(StateBlockStartError::Stage)?;",
    )
    positions = [compact.find(token) for token in ordered]
    if any(compact.count(token) != 1 for token in ordered) or positions != sorted(positions):
        raise RuntimeError(f"{state_path}: start phases must finish before the original continuation")
    require_block_start_construction(state)
    expiry = section(
        state,
        "    fn apply_block_start_private_settlement_expiry(",
        "    /// Resolve due Parliament effects before entering after-start execution.",
        state_path,
    )
    require_all(state_path, expiry, (
        "barrier.manifest.expiry_height < now_h",
        "let mut expiry = sb.try_transaction()?;",
        ".reconcile_expired_private_settlement_staged_locks_v1()",
        "expiry.apply();",
    ))
    due_enactment = rust_item(
        state,
        "    fn apply_block_start_parliament_enactments<E: std::fmt::Debug>(",
        state_path,
    )
    require_all(
        state_path,
        due_enactment,
        (
            ".parliament_certified_enactments.iter().next()",
            "*enact_at_height < now_h",
            ".parliament_certified_enactments",
            ".get(&now_h)",
            "for governance_attempt_id in due_parliament_certificates",
            "execute_due_parliament_certificate_v1(",
            "record_due_parliament_execution_failure_v1(",
            '"Parliament certified-enactment index retained a due bucket',
        ),
    )
    if "sb.world.parliament_attempts.iter()" in due_enactment:
        raise RuntimeError(
            f"{state_path}: block-start enactment selection regressed to an unbounded Parliament attempt scan"
        )

    compact_due = compact_rust(mask_rust(due_enactment))
    deferred = (
        "crate::execution_attempt::ExecutionAttemptError::Deferred(reason)"
        "=>StateBlockStartError::ExecutionDeferred(reason)"
    )
    if ("Result<(),StateBlockStartError<E>>" not in compact_due
            or compact_due.count(deferred) != 2
            or compact_due.count(".map_err(|error|matcherror{") != 2
            or compact_due.count("})?") != 2):
        raise RuntimeError(f"{state_path}: start phases must propagate both original execution deferrals")
    ordered_due = (
        "letmutenactment=sb.try_transaction()?;",
        "execute_due_parliament_certificate_v1(",
        "DueParliamentCertificateExecutionV1::EffectFailed",
        "drop(enactment);",
        "letmutfailure=sb.try_transaction()?;",
        "record_due_parliament_execution_failure_v1(",
        "failure.apply();",
    )
    positions = [compact_due.find(token) for token in ordered_due]
    if any(compact_due.count(token) != 1 for token in ordered_due) or positions != sorted(positions):
        raise RuntimeError(f"{state_path}: a failed effect must drop before its original failure recorder")


def require_parliament_event_capture(state: str) -> None:
    """Capture the committed telemetry projection before draining original events."""
    state_path = "crates/iroha_core/src/state.rs"
    # The committed Sumeragi carrier reaches the sole event drain only through
    # its original carrier-bound preparation; neither caller drains on its own.
    production = compact_rust(mask_rust(rust_item(
        state, "    pub(crate) fn apply_without_execution_with_sumeragi_commit(", state_path,
    )))
    carrier = compact_rust(mask_rust(rust_item(state, "    fn apply_without_execution_inner(", state_path)))
    if (production.count("state.apply_without_execution_inner(block,committee)") != 1
            or carrier.count("self.prepare_carrier_publication_events(block.as_ref().header())") != 1
            or "take_external_events" in production + carrier):
        raise RuntimeError(
            f"{state_path}: committed carrier events must drain only through the "
            "original Parliament projection"
        )
    require_all(state_path, production, (
        "let(events,authorization)=state.apply_without_execution_inner(block,committee);"
        "authorization.map(|()|events)",
    ))
    require_all(state_path, carrier, (
        "let events = match self.prepare_carrier_publication_events(block.as_ref().header()) {"
        "Ok(events) => events, Err(error) => return (Vec::new(), Err(error)), }; (events, Ok(()))".replace(" ", ""),
    ))
    parliament_event_capture = mask_rust(rust_item(
        state, "    fn prepare_carrier_publication_events(", state_path
    ))
    carrier_guard = "ifheader!=self._curr_block{returnErr("
    projection = compact_rust(parliament_event_capture).find("letparliament_transitions=self")
    if not 0 <= compact_rust(parliament_event_capture).find(carrier_guard) < projection:
        raise RuntimeError(
            f"{state_path}: Parliament event capture must belong to the original carrier"
        )
    require_all(
        state_path,
        parliament_event_capture,
        (
            "let parliament_transitions = self",
            "crate::telemetry::parliament_lifecycle_metric_projection(event)",
            ".collect::<Vec<_>>();",
            "self.pending_parliament_telemetry_events",
            ".extend(parliament_transitions);",
            "Ok(self.world.take_external_events())",
        ),
    )
    if parliament_event_capture.count("self.world.take_external_events()") != 1:
        raise RuntimeError(f"{state_path}: Parliament event capture must drain exactly once after projection")
    capture_order = tuple(
        parliament_event_capture.find(token)
        for token in (
            "let parliament_transitions = self",
            "crate::telemetry::parliament_lifecycle_metric_projection(event)",
            ".collect::<Vec<_>>();",
            "self.pending_parliament_telemetry_events",
            ".extend(parliament_transitions);",
            "Ok(self.world.take_external_events())",
        )
    )
    if tuple(sorted(capture_order)) != capture_order:
        raise RuntimeError(
            f"{state_path}: Parliament telemetry projection must be captured before "
            "the external-event buffer is drained"
        )
    if "record_committed_parliament_transition(" in parliament_event_capture:
        raise RuntimeError(
            f"{state_path}: Parliament transition telemetry must not publish before commit"
        )


def require_completed_replay_source(source: str) -> None:
    """Retire the graph while preserving its exact configuration and committee identity."""
    path = "crates/iroha_core/src/sumeragi/executor/replay.rs"
    identity = compact_rust(mask_rust(rust_item(source, "struct ReplaySource {", path)))
    expected = (
        "structReplaySource{instance:Hash32,height:u64,block_hash:Hash32,"
        "epoch:EpochConfig,params:ChainParams,committee_digest:Hash,}"
    )
    if identity != expected:
        raise RuntimeError(f"{path}: completed replay must retain the complete original source identity")
    capture = compact_rust(mask_rust(rust_item(source, "    fn capture(", path)))
    expected_capture = (
        "fncapture(source:&AvailabilitySource)->Self{"
        "letHeightConfig{epoch,committee,params,}=source.config();Self{"
        "instance:source.instance(),height:source.height(),block_hash:source.block_hash(),"
        "epoch:**epoch,params:*params,committee_digest:committee_digest(committee),}}"
    )
    if capture != expected_capture:
        raise RuntimeError(f"{path}: completed replay must capture the complete original source configuration")
    digest = compact_rust(mask_rust(rust_item(source, "fn committee_digest(", path)))
    expected_digest = compact_rust(mask_rust("""
        fn committee_digest(committee: &Committee) -> Hash {
            Hash::new_from_writer(|writer| {
                writer.write_all(iroha_sumeragi::preimage::TAG_COMMITTEE)?;
                writer.write_all(
                    &u32::try_from(committee.n())
                        .expect("validated committee size fits u32")
                        .to_be_bytes(),
                )?;
                for key in committee.members() {
                    let bytes = key.as_bytes();
                    writer.write_all(
                        &u16::try_from(bytes.len())
                            .expect("validated public key length fits u16")
                            .to_be_bytes(),
                    )?;
                    writer.write_all(bytes)?;
                }
                Ok(())
            })
            .expect("incremental hash writer cannot fail")
        }
    """))
    if digest != expected_digest:
        raise RuntimeError(f"{path}: completed replay must stream the complete canonical committee preimage")


def require_parliament_commit_publication(state: str) -> None:
    """Publish Parliament metrics only from the retained State owner, once, after publication."""
    state_path = "crates/iroha_core/src/state.rs"
    require_all(state_path, state, (
        "mod publication;", "publication: Option<publication::StatePublication<'state>>",
    ))
    # The telemetry distinction is retained by the same move-only execution
    # authority. It selects observations only, after the real replay path has
    # admitted sources, witnesses and finality through the ordinary pipeline.
    executor_path = "crates/iroha_core/src/sumeragi/executor.rs"
    executor_source = read(executor_path)
    executor = compact_rust(executor_source)
    require_all(executor_path, executor, (
        "self.prepare_with_origin(block,commit_qc,CommitTelemetryOrigin::Forward)",
        "require_body_admission(block,&self.execution_budget)?;require_qc_witness_admission(commit_qc,&self.execution_budget)?;self.call(|reply|Request::Prepare(block.clone(),commit_qc.clone(),origin,reply))",
        "Request::Prepare(block,qc,origin,reply)=>{let_=reply.send(self.prepare_with_origin(&block,&qc,origin));}",
        "Request::Replay(block,qc,reply)=>{let_=reply.send(self.replay(&block,&qc));}",
        "pending.matches(block,qc)&&pending.telemetry_origin==origin",
        "iflive.telemetry_origin.is_some_and(|original|original!=origin){returnErr(PublicationError::Retryable(\"preparedexecutiontelemetryorigincannotbereplaced\".into(),));}",
        "live.telemetry_origin=Some(origin);",
        'telemetry_origin:live.telemetry_origin.expect("originalpreparedtelemetryorigin")',
        "pub(crate)fntelemetry_origin(&self)->CommitTelemetryOrigin{self.telemetry_origin}",
        "let(state,tip,telemetry_origin)=original.into_parts();Self{state,tip,parent:None,telemetry_origin,}",
    ))
    replay_modules = list(re.finditer(
        r"(?P<attrs>(?:[ \t]*#\[[^\n]+\]\s*)*)\bmod\s+replay\s*;",
        mask_rust(executor_source),
    ))
    if len(replay_modules) != 1 or replay_modules[0].group("attrs").strip():
        raise RuntimeError(f"{executor_path}: replay must use its original unconditional module")
    replay_dispatch = compact_rust(mask_rust(rust_item(
        executor_source, "    pub fn replay(", executor_path,
    )))
    # Admission and the serialized result keep the original PublicationError.
    # Pin their direct order and final expression so a diagnostic conversion,
    # ignored guard or substituted successful reply cannot erase local refusal.
    require_all(executor_path, replay_dispatch, (
        "->Result<(),PublicationError>{"
        "require_body_admission(block,&self.execution_budget)?;"
        "require_qc_witness_admission(commit_qc,&self.execution_budget)?;"
        "self.call(|reply|Request::Replay(block.clone(),commit_qc.clone(),reply))"
        ".unwrap_or_else(||Err(control::stopped()))}",
    ))
    replay_path = "crates/iroha_core/src/sumeragi/executor/replay.rs"
    replay_source = read(replay_path)
    require_completed_replay_source(replay_source)
    worker_replay = compact_rust(mask_rust(rust_item(
        replay_source, "    pub(super) fn replay(", replay_path,
    )))
    require_all(replay_path, worker_replay, ("self.replay_with_encoder(block,qc,encode)",))
    replay = compact_rust(mask_rust(rust_item(
        replay_source, "    fn replay_with_encoder(", replay_path,
    )))
    require_all(replay_path, replay, (
        "require_body_admission(block,&budget)?;require_qc_witness_admission(qc,&budget)?;",
        "returncompleted.acknowledge(block,qc,&budget,&mutencode);",
        "matchself.prepare_with_origin(block,qc,CommitTelemetryOrigin::HistoricalReplay)?{Some(result)ifresult==qc.result=>{}",
        "self.commit(block,qc)?;",
        "ifletErr(error)=self.retire_completed_replay(block,qc){"
        "ifletPublicationError::RecoveryRequired(reason)=&error{"
        "self.recovery=Some(reason.clone());}returnErr(error);}",
    ))
    retirement = compact_rust(mask_rust(rust_item(
        replay_source, "    fn retire_completed_replay(", replay_path,
    )))
    require_all(replay_path, retirement, (
        "iforiginal!=qc||live.header!=*block.header()||live.availability!=*block.availability()||live.source!=*block.source()||live.telemetry_origin!=Some(CommitTelemetryOrigin::HistoricalReplay)",
        "letqc=Hash::new(certificate.commit_qc());",
        "letpayload=Hash::new(block.payload().as_slice());",
        "->Result<(),PublicationError>{",
        "letinvalid=|reason:&str|PublicationError::RecoveryRequired(reason.to_owned());",
        "letview=self.state.try_view_once()?;",
        "self.completed_replay=Some(CompletedReplay{"
        "source:ReplaySource::capture(&live.source),tip,header,qc,availability,payload,});",
    ))
    acknowledgement = compact_rust(mask_rust(rust_item(
        replay_source, "    fn acknowledge(", replay_path,
    )))
    require_all(replay_path, acknowledgement, (
        "else{preparation::encoding_failure(&error)}",
        "letheader=digest(CertificatePart::Header(block.header()))?;",
        "letqc=digest(CertificatePart::Qc(qc))?;",
        "letavailability=digest(CertificatePart::Availability(block.availability()))?;",
        compact_rust(mask_rust(
            'if !cfg!(all(test, sumeragi_core_mutation = "HC94")) '
            '&& self.source != ReplaySource::capture(block.source())'
        )),
        "self.payload!=Hash::new(block.payload().as_slice())"
        "||self.header!=header||self.qc!=qc||self.availability!=availability",
    ))
    startup_path = "crates/iroha_core/src/sumeragi/startup.rs"
    require_all(startup_path, compact_rust(read(startup_path)), (
        "telemetry_origin:matchstored{Some(_)=>super::executor::CommitTelemetryOrigin::HistoricalReplay,None=>super::executor::CommitTelemetryOrigin::Forward,}",
        "(self.state,self.tip,self.telemetry_origin)",
    ))
    seal_path = "crates/iroha_core/src/state/output_seal.rs"
    seal = compact_rust(rust_item(read(seal_path),
                                 "    pub(in crate::state) fn committed_telemetry_origin(", seal_path))
    require_all(seal_path, seal, (
        "Some(ExecutionOutputPlanState::Finalized(finalized))=>{Ok(finalized.authorized.native_execution.telemetry_origin())}",
        '_=>Err("telemetryoriginlacksfinalizedexecutionauthority".into())',
    ))
    path = "crates/iroha_core/src/state/publication.rs"
    publication = read(path)
    source_compact = re.sub(r"\s+", "", re.sub(r"//[^\n]*", "", publication))
    require_all(path, source_compact, (
        "pub(crate)fntry_publish(&mutself)->StatePublicationOutcome{self.try_publish_inner()}",
        "pub(super)fncommit_inner(mutself)->Result<(),TransactionsBlockError>{self.try_publish_inner().into_result()}",
        "letmutoriginal=self.publication.take().unwrap_or_else(||StatePublication::new(self.state_ref));",
        "iforiginal.published{self.publication=Some(original);returnStatePublicationOutcome::Published;}",
        "letresult=self.attempt_original_publication(&mutoriginal);",
        "iforiginal.fields_frozen&&!original.irreversible{self.recover_original_publication_fields();self.retire_original_publication_notices();}",
        "self.publication=Some(original);ifterminal{mv::BlockRetirement::release_writers(self);}result",
        '#[cfg(feature="telemetry")]lettelemetry_origin=this.committed_telemetry_origin().map_err(|_|TransactionsBlockError::WorldCommitPreparation)?;',
    ))
    constructor = section(source_compact, "impl<'state>StatePublication<'state>{", "impl<'state>StateBlock<'state>{", path)
    if not (0 <= constructor.find("effect_cleanup:effect_publication::StateEffectLocks::new(state)")
            < constructor.find("commit_fence:state.state_commit_lock.defer_notifications()")):
        raise RuntimeError(f"{path}: original effect and commit-fence owners must precede publication")
    commit = section(publication, "    fn attempt_original_publication(",
                     "\n#[cfg(test)]", path)
    # All fallible World/geometry work precedes the original State writer and
    # visibility interval. The prepared World effects are consumed under that
    # same writer, after the original World journal publishes.
    compact = re.sub(r"\s+", "", re.sub(r"//[^\n]*", "", commit))
    # The retained effects come from the original propagated preparation and
    # survive the final accumulator write before the immutable field freeze.
    prepare_call = "world_commit::PreparedWorldCommit::prepare_overlay_mutations("
    original_preparation = "leteffects=" + prepare_call
    retained = "*world_effects=Some(effects);"
    refusal = "ExecutionAttemptError::Deferred(reason)=>{TransactionsBlockError::ExecutionDeferred(reason)}}})?"
    preparation_code = compact_rust(mask_rust(commit))
    call = preparation_code.find(prepare_call)
    propagated = preparation_code.find(refusal, call)
    assignment = preparation_code.find(retained)
    frozen = preparation_code.find("if!*fields_frozen{")
    if (preparation_code.count(prepare_call) != 1 or preparation_code.count(original_preparation) != 1
            or preparation_code.count("leteffects=") != 1
            or preparation_code.count(retained) != 1 or preparation_code.count("*world_effects=Some(") != 1
            or not 0 <= call < propagated < frozen
            or not propagated < assignment < frozen):
        raise RuntimeError(f"{path}: World preparation must propagate refusal before publication")
    validation = section(compact, "world_commit::PreparedWorldCommit::validate_prepared_overlay(",
                         "iftiered_snapshot.is_none()", path)
    if not validation.startswith("world,&state_ref.ivm_execution_budget(),).map_err(|error|matcherror{"):
        raise RuntimeError(f"{path}: retained World validation must use the original overlay and allocation budget")
    if not validation.endswith("ExecutionAttemptError::Deferred(reason)=>{TransactionsBlockError::ExecutionDeferred(reason)}})?;"):
        raise RuntimeError(f"{path}: retained World validation must propagate refusal before publication")
    geometry = section(compact, "ifletErr(err)=geometry_result{", "autoscale_start.elapsed()", path)
    if not geometry.endswith("returnErr(TransactionsBlockError::from(err));}"):
        raise RuntimeError(f"{path}: geometry refusal must return before State publication")
    parliament_telemetry = (
        '#[cfg(feature="telemetry")]{iftelemetry_origin==crate::sumeragi::executor::CommitTelemetryOrigin::Forward{for&(transition,no_result_kind)'
        "inpending_parliament_telemetry_events.iter(){"
    )
    ordered = (
        "letcommitted_parliament_attempt_counts=world.parliament_attempt_counts.is_dirty()",
        "let_state_commit_lock=commit_fence.lock();",
        prepare_call,
        "world_commit::PreparedWorldCommit::validate_prepared_overlay(",
        "*tiered_snapshot=Some(",
        "ifletErr(err)=geometry_result{",
        "letstate_write_lock_wait_start=Instant::now();let_state_write_lock=write_fence.lock();",
        "block_hashes.try_prepare_publication().map_err(|error|matcherror{",
        "world.try_prepare_frozen_publication().map_err(original_preparation_error)?;",
        "let_view_generation=publication_notice.begin();",
        "transactions.publish_prepared();",
        "canonical_runtime.publish_prepared();",
        "world.publish_prepared();",
        "block_hashes.publish_prepared();",
        "world_effects.take().expect(\"originalpreparedWorldeffects\").publish(",
        "drop(autoscale_lifecycle_guard);",
        parliament_telemetry,
        "tiered_snapshot.take().expect(\"originalpreparedtieredsnapshot\").publish(",
        "drop(_state_commit_lock);",
        "*published=true;",
    )
    positions = [compact.find(token) for token in ordered]
    # The same State writer is also acquired once during the earlier preflight.
    # Bind this occurrence to the one after geometry refusal, where publication
    # starts, while retaining exactly one match for every other stage.
    writer = "letstate_write_lock_wait_start=Instant::now();let_state_write_lock=write_fence.lock();"
    writer_index = ordered.index(writer)
    positions[writer_index] = compact.rfind(writer)
    if (compact.count(writer) != 2
            or any(compact.count(token) != 1 for token in ordered if token != writer)
            or positions != sorted(positions)):
        raise RuntimeError(f"{path}: Parliament telemetry requires ordered prepared State publication")
    publication = section(compact, "letautoscale_storage_hold=",
                          "ifletSome(post)=lifecycle_post_publication.as_mut(){", path)
    writer_order = (
        "let_state_write_lock=write_fence.lock();",
        "block_hashes.try_prepare_publication().map_err(|error|matcherror{mv::PublicationPreparationError::Busy(wait)=>{TransactionsBlockError::BlockHashesBusy(wait)}_=>TransactionsBlockError::SnapshotObservationChanged,})?;",
        "world.try_prepare_frozen_publication().map_err(original_preparation_error)?;",
        "canonical_runtime.try_prepare_frozen_publication().map_err(original_preparation_error)?;",
        "native_execution_tip.try_prepare_frozen_publication().map_err(original_preparation_error)?;",
        "effect_locks.prepare_blocking();",
        "let_view_generation=publication_notice.begin();",
        "transactions.publish_prepared();", "canonical_runtime.publish_prepared();",
        "native_execution_tip.publish_prepared();",
        "world.publish_prepared();",
        "block_hashes.publish_prepared();",
        "world_effects.take().expect(\"originalpreparedWorldeffects\").publish(",
    )
    writer_positions = [publication.find(token) for token in writer_order]
    if any(publication.count(token) != 1 for token in writer_order) or writer_positions != sorted(writer_positions):
        raise RuntimeError(f"{path}: canonical publication requires the original State writer and generation")
    # The original writer scope must directly execute publication. An intact
    # statement nested in a conditional, or an explicitly released guard, is not
    # the modeled successful commit boundary. Ignore string braces in logging.
    lexical = re.sub(r'"(?:\\.|[^"\\])*"', '""', publication)
    if lexical.count("{") != lexical.count("}"):
        raise RuntimeError(f"{path}: original State writer scope must close before post-publication")
    for token in writer_order:
        lexical_token = re.sub(r'"(?:\\.|[^"\\])*"', '""', token)
        before = lexical[:lexical.index(lexical_token)]
        if before.count("{") - before.count("}") != 1:
            raise RuntimeError(f"{path}: State publication must be unconditional under its original writer")
    if "drop(_state_write_lock);" in publication or "drop(_view_generation);" in publication:
        raise RuntimeError(f"{path}: State publication must retain its original writer and generation")
    # Match the exact nested control-flow region, not independent tokens which
    # could survive while the replay origin, publisher or gauge changes scope.
    telemetry = section(compact, 'ifletSome(post)=da_post_publication.take(){post.publish(state_ref);}',
                        "*published=true;", path)
    start = telemetry.find(parliament_telemetry)
    expected = """
        #[cfg(feature="telemetry")]
        {
            if telemetry_origin == crate::sumeragi::executor::CommitTelemetryOrigin::Forward {
                for &(transition, no_result_kind) in pending_parliament_telemetry_events.iter() {
                    state_ref.telemetry.record_committed_parliament_transition(transition, no_result_kind);
                }
            }
            if let Some(counts) = committed_parliament_attempt_counts {
                let (status_counts, stage_counts) = counts.telemetry_counts();
                state_ref.telemetry.set_parliament_attempt_counts(status_counts, stage_counts);
            }
            if let Some(citizens_total) = committed_citizens_total {
                state_ref.telemetry.record_citizens_total(citizens_total);
            }
        }
        tiered_snapshot.take().expect("original prepared tiered snapshot").publish(state_ref);
        {
            state_ref.enforce_nexus_storage_budget(block_height);
            {
                state_ref.persist_query_index_status(block_height, Some(block_header_hash));
            }
        }
        drop(_state_commit_lock);
    """
    expected = re.sub(r"\s+", "", expected)
    if start < 0 or telemetry[start:] != expected:
        raise RuntimeError(f"{path}: Parliament telemetry requires exact transition and gauge scopes")
    if compact.find(expected) <= positions[ordered.index("drop(autoscale_lifecycle_guard);")]:
        raise RuntimeError(f"{path}: Parliament telemetry must follow successful canonical publication")
    if compact.count(".record_committed_parliament_transition(") != 1:
        raise RuntimeError(f"{path}: Parliament commit must have one exact transition-metric publisher")


EPOCH_BEACON_PATH = "crates/iroha_core/src/sumeragi/epoch_beacon.rs"
BEACON_PRODUCER_PATH = "crates/iroha_core/src/sumeragi/epoch_beacon/producer.rs"
BEACON_PRODUCER_TESTS_PATH = "crates/iroha_core/src/sumeragi/epoch_beacon/producer/tests.rs"
BEACON_EXECUTION_TESTS_PATH = (
    "crates/iroha_core/src/sumeragi/epoch_beacon/producer/execution_tests.rs"
)
SCHEDULE_EXECUTION_PATH = "crates/iroha_core/src/sumeragi/schedule/execution.rs"
NATIVE_HEADER_SOURCE_PATH = "crates/iroha_core/src/block/native_header_source.rs"


BEACON_ROSTER_PATH = "crates/iroha_core/src/beacon.rs"
BEACON_ROSTER_CODEC_PATH = "crates/iroha_core/src/beacon/validation.rs"
BEACON_SEALED_SESSION_PATH = "crates/iroha_core/src/beacon/session_owner/validated.rs"
BEACON_DKG_OWNER_PATH = "crates/iroha_core/src/beacon/session_owner/dkg.rs"


def require_beacon_finalization_roster(committee: str) -> None:
    """Finalization authenticates the original current and frozen target rosters."""
    committee_path = "crates/iroha_core/src/state/validator_committee.rs"
    finalization = section(committee, "pub(crate) fn validate_beacon_finalization(",
                           "impl StateBlock<'_> {", committee_path)
    require_all(committee_path, finalization, (
        "current_authority(state)?", "validate_against_authority(authority)",
        "authority.generation != 0 || authorization.beacon != BeaconEpochBindingV1::Bootstrap",
        "authenticated_global_threshold_beacon_roster_hash_v1(&record.session, authorizing_roster)",
        "validator_committee_transitions()", "validate_against_preparing_authorization(authorization)?",
        "active != Some(incumbent.session_id)", "current.session.transcript_hash != incumbent.transcript_hash",
        "transition.outcome.is_some()", "height >= authorization.last_height",
        "record.session.session_id != preparation.beacon_session_id()?",
        "record.session.adaptive_dkg.session.start_height <= preparation.selection_height",
        "record.session.adaptive_dkg.finalized_at_height >= preparation.first_height - 1",
        "let target_roster = preparation.committee.iter().map(|seat| &seat.validator);",
        "authenticated_global_threshold_beacon_roster_hash_iter_v1(&record.session, target_roster)",
        "Ok(false)",
    ))


def require_borrowed_beacon_roster_and_sealed_binding() -> None:
    """Borrowed identities retain canonical order, exact count and current seal binding."""
    source = read(BEACON_ROSTER_PATH)
    authenticated = compact_rust(rust_item(
        source, "pub(crate) fn authenticated_global_threshold_beacon_roster_hash_iter_v1<",
        BEACON_ROSTER_PATH))
    require_all(BEACON_ROSTER_PATH, authenticated, (
        "I:ExactSizeIterator<Item=&'aPeerId>+Clone,",
        "letcount=roster.len();",
        "letroster_hash=global_threshold_beacon_roster_hash_iter_v1(roster);",
        "ifsession.roster_hash!=roster_hash||usize::from(session.committee_size)!=count{"
        "returnErr(GlobalThresholdBeaconError::RosterMismatch);}",
        "Ok(roster_hash)",
    ))
    digest = compact_rust(rust_item(
        source, "pub fn global_threshold_beacon_roster_hash_iter_v1<", BEACON_ROSTER_PATH))
    require_all(BEACON_ROSTER_PATH, digest, (
        "I:ExactSizeIterator<Item=&'aPeerId>+Clone,",
        "*iroha_crypto::HashOf::new(&validation::RosterIter(roster)).as_ref()",
    ))
    codec = compact_rust(rust_item(
        read(BEACON_ROSTER_CODEC_PATH),
        "impl<'a, I> norito::core::SerializePayload for RosterIter<I>",
        BEACON_ROSTER_CODEC_PATH))
    require_all(BEACON_ROSTER_CODEC_PATH, codec, (
        "I:ExactSizeIterator<Item=&'aPeerId>+Clone,",
        "norito::core::write_element_sequence::<PeerId,_>(writer,self.0.clone())",
    ))
    sealed = read(BEACON_SEALED_SESSION_PATH)
    recheck = compact_rust(rust_item(sealed, "    pub fn check_binding(", BEACON_SEALED_SESSION_PATH))
    require_all(BEACON_SEALED_SESSION_PATH, recheck, (
        "validate_binding(self.record(),expected)",
    ))
    binding = compact_rust(rust_item(sealed, "fn validate_binding(", BEACON_SEALED_SESSION_PATH))
    require_all(BEACON_SEALED_SESSION_PATH, binding, (
        "ifsource.version!=iroha_data_model::consensus::GLOBAL_THRESHOLD_BEACON_VERSION_V1{"
        "returnErr(GlobalThresholdBeaconError::UnsupportedVersion{actual:source.version,});}",
        "ifsource.network_id!=expected.network_id{returnErr(GlobalThresholdBeaconError::NetworkMismatch);}",
        "ifsource.session_id!=expected.session_id{returnErr(GlobalThresholdBeaconError::SessionMismatch);}",
        "ifsource.roster_hash!=expected.roster_hash{returnErr(GlobalThresholdBeaconError::RosterMismatch);}",
        "ifsource.transcript_hash!=expected.transcript_hash{returnErr(GlobalThresholdBeaconError::TranscriptMismatch);}",
        "beacon::validate_adaptive_dkg_geometry(source)?;",
    ))


def require_parliament_beacon_requirement(beacon: str, producer: str) -> None:
    """Authenticated root ownership and exact committed demand gate both consumers."""
    require_borrowed_beacon_roster_and_sealed_binding()
    path = EPOCH_BEACON_PATH
    ownership = compact_rust(rust_item(beacon, "fn owns_global_control(", path))
    expected_ownership = compact_rust("""
        fn owns_global_control(
            scope: SumeragiRootScope,
            world: &impl WorldReadOnly,
            current: &ValidatorEpochContextV1,
        ) -> Result<bool, String> {
            scope.validate().map_err(|error| error.to_string())?;
            if matches!(scope, SumeragiRootScope::Global) {
                return Ok(true);
            }
            if current.mode != ConsensusMode::Permissioned
                || current.authorization.beacon != BeaconEpochBindingV1::Bootstrap
                || world.parliament_required_beacon_pulse_slots().iter().next().is_some()
                || world.active_global_beacon_key_session().is_some()
                || world.global_beacon_pulses().iter().next().is_some()
            {
                return Err("private root cannot own global epoch, Parliament, or beacon control".into());
            }
            Ok(false)
        }
    """)
    if ownership != expected_ownership:
        raise RuntimeError(f"{path}: private roots must refuse global control custody")
    requirement = compact_rust(rust_item(beacon, "pub(crate) fn required(", path))
    expected = compact_rust("""
        pub(crate) fn required(
            scope: SumeragiRootScope,
            world: &impl WorldReadOnly,
            current: &ValidatorEpochContextV1,
            height: u64,
        ) -> Result<bool, String> {
            if !owns_global_control(scope, world, current)? {
                return Ok(false);
            }
            Ok((current.mode == ConsensusMode::Npos
                && height.checked_add(1) == Some(current.authorization.last_height))
                || world
                    .parliament_required_beacon_pulse_slots()
                    .get(&(BeaconSessionId::for_network_v1(&current.network_id), height))
                    .is_some_and(|attempts| !attempts.is_empty()))
        }
    """)
    if requirement != expected:
        raise RuntimeError(
            f"{path}: mandatory beacon demand must use the exact committed network-height index"
        )
    # Follower admission: a demanded pulse is obligatory, an unrequested one is
    # refused, and a supplied pulse passes the committed slot history and the
    # height roster before its threshold proof is verified.
    admission = compact_rust(rust_item(beacon, "pub(crate) fn capture(", path))
    admission_order = (
        "current.validate()?;",
        compact_rust("""
            match (height, expected_context.as_ref()) {
                (1, None) if supplied.is_none() => {}
                (1, _) => {
                    return Err(
                        "signed genesis cannot contain a native pulse or native parent context".into(),
                    );
                }
                (_, Some(context)) => {
                    context.validate().map_err(str::to_owned)?;
                    if context.epoch != current.authorization.epoch
                        || context.epoch_context_id != current.context_id()?
                    {
                        return Err(
                            "native beacon expected context differs from the authenticated epoch".into(),
                        );
                    }
                }
                (_, None) => {
                    return Err(
                        "native beacon admission lacks its independently checked native context".into(),
                    );
                }
            }
        """),
        compact_rust("""
            if height < current.authorization.first_height
                || height > current.authorization.last_height
                || u64::try_from(hashes.hash_count())
                    .ok()
                    .and_then(|height| height.checked_add(1))
                    != Some(height)
            {
                return Err("native beacon witness is outside its exact committed prestate".into());
            }
        """),
        "letdemanded=required(scope,world,current,height)?;",
        compact_rust("""
            let Some(pulse) = supplied else {
                return if demanded {
                    Err("mandatory native beacon control witness is absent".into())
                } else {
                    Ok(VerifiedEpochPulse {
                        pulse: None,
                        link: None,
                    })
                };
            };
        """),
        compact_rust("""
            if !demanded {
                return Err("native beacon control witness was not requested".into());
            }
        """),
        compact_rust("""
            if pulse.network_id != current.network_id
                || pulse.height != height
                || pulse.round != crate::beacon::GLOBAL_THRESHOLD_BEACON_PULSE_ROUND_V1
            {
                return Err("native beacon witness changes its network, height or round".into());
            }
            let parent = height
                .checked_sub(1)
                .filter(|height| *height > 0)
                .ok_or("native beacon witness lacks finalized parent")?;
            let index = usize::try_from(parent - 1).map_err(|_| "native beacon parent index overflows")?;
            let anchor = GlobalThresholdBeaconChainAnchorV1 {
                height: parent,
                block_hash: *hashes
                    .hash_at(index)
                    .ok_or("native beacon parent is absent")?,
            };
        """),
        "validate_pending_slot(world,current,height)?;",
        "letpeers=current.committee.iter().map(|seat|&seat.validator);",
        "authenticated_global_threshold_beacon_roster_hash_iter_v1(&record.session,peers)",
        compact_rust("""
            let binding = GlobalThresholdBeaconSessionBindingV1 {
                network_id: current.network_id,
                session_id: pulse.session_id,
                roster_hash,
                transcript_hash: record.session.transcript_hash,
            };
            let session = &record.session;
            session
                .check_binding(&binding)
                .map_err(|error| error.to_string())?;
            let link = verify_finalized_global_threshold_beacon_pulse_v1(
                &session,
                &pulse,
                anchor,
                expected_context
                    .as_ref()
                    .ok_or("native pulse has no parent context")?,
            )
            .map_err(|error| error.to_string())?;
        """),
    )
    positions = [admission.find(token) for token in admission_order]
    if (any(admission.count(token) != 1 for token in admission_order)
            or positions != sorted(positions)):
        raise RuntimeError(
            f"{path}: follower admission must require, refuse and authenticate the committed demand"
        )
    require_all(path, admission, (
        "record.session.adaptive_dkg.session.authority_generation!=current.authority.generation",
        "current.authorization.beacon!=BeaconEpochBindingV1::Installed(installed)",
        "Ok(VerifiedEpochPulse{pulse:Some(pulse),link:Some(link),})",
    ))
    pending = compact_rust(rust_item(beacon, "fn validate_pending_slot(", path))
    require_all(path, pending, (
        "letslot=(BeaconSessionId::for_network_v1(&current.network_id),height);",
        ".parliament_unavailable_beacon_pulse_slots().get(&slot)"
        ".is_some_and(|attempts|!attempts.is_empty())"
        "||world.global_beacon_pulse_slots().get(&slot).is_some()",
        'returnErr("nativebeaconwitnessrepeatsorcontradictscommittedpulsehistory".into());',
    ))

    # Local production opens one round only on that same committed demand, after
    # the committed slot check, and never builds an empty witness for it.
    producer_path = BEACON_PRODUCER_PATH
    code = compact_rust(mask_rust(producer))
    if code.count("super::required(") != 1 or code.count("ActiveRound::open(") != 1:
        raise RuntimeError(
            f"{producer_path}: native production must retain one original beacon requirement"
        )
    parent_source = compact_rust(rust_item(producer, "    fn parent_source(", producer_path))
    parent_order = (
        "ifcontext.instance!=self.instance||applied.0.checked_add(1)!=Some(context.height)"
        "||applied.1!=context.parent_hash||u64::try_from(state.height()).ok()!=Some(applied.0)"
        "{returnErr(NativeBeaconError::Context);}",
        compact_rust("""
            let parent = state.native_execution_tip().ok_or_else(|| {
                NativeBeaconError::Source("published State has no original execution tip".into())
            })?;
        """),
        compact_rust("""
            let journal_matches = {
                #[cfg(all(test, sumeragi_core_mutation = "HC17"))]
                { true }
                #[cfg(not(all(test, sumeragi_core_mutation = "HC17")))]
                { state.block_hashes().last() == Some(&parent.iroha_hash()) }
            };
            if parent.height() != applied.0 || !journal_matches {
                return Err(NativeBeaconError::Source(
                    "original execution tip differs from the published State hash journal".into(),
                ));
            }
        """),
        "ifparent.core_hash()!=context.parent_hash||parent.result()!=context.parent_result"
        "{returnErr(NativeBeaconError::Context);}",
        "Ok(parent)}",
    )
    positions = [parent_source.find(token) for token in parent_order]
    if (any(parent_source.count(token) != 1 for token in parent_order)
            or positions != sorted(positions) or not parent_source.endswith(parent_order[-1])):
        raise RuntimeError(
            f"{producer_path}: native production must authenticate the original tip and published parent cut"
        )
    source = compact_rust(rust_item(producer, "    fn ensure_source(", producer_path))
    activation = compact_rust("""
        let active = if required {
            super::validate_pending_slot(state.world(), current, context.height)
                .map_err(NativeBeaconError::Source)?;
            Some(ActiveRound::open(
    """)
    installed = "self.active=active;self.prepared=Some(*context);Ok(())}"
    source_order = (
        "letparent=self.parent_source(state,context,applied)?;",
        "letretained=state.world().consensus_schedule();",
        ".ready(context.height)",
        "ifcurrent.network_id!=*state.network_id()||schedule::core_epoch(current)",
        compact_rust("""
            let root_scope = crate::sumeragi::lanes::routing::committed_root_scope(state.world())
                .ok_or_else(|| {
                    NativeBeaconError::Source("native control requires immutable root scope".into())
                })?;
            let required = super::required(root_scope, state.world(), current, context.height)
                .map_err(NativeBeaconError::Source)?;
        """),
        "ifself.prepared.as_ref()==Some(context){returnOk(());}",
        activation,
        "GlobalThresholdBeaconChainAnchorV1{height:applied.0,block_hash:parent.iroha_hash(),}",
        ")?)}else{None};",
        "self.mandatory_attestation=current.mode==ConsensusMode::Npos"
        "&&context.height==current.authorization.last_height;",
        installed,
    )
    positions = [source.find(token) for token in source_order]
    if (any(source.count(token) != 1 for token in source_order)
            or positions != sorted(positions) or not source.endswith(installed)):
        raise RuntimeError(
            f"{producer_path}: native production must activate only on the committed demand"
        )
    build = compact_rust(rust_item(producer, "    pub(crate) fn build(", producer_path))
    witness = compact_rust("""
            let pulse = match &self.active {
                None => None,
                Some(active) => Some(active.finalized.ok_or(NativeBeaconError::AwaitingShares {
                    height: context.height,
                })?),
            };
            Ok((control::encode(pulse)?, self.mandatory_attestation))
        }
    """)
    if (not build.endswith(witness)
            or "ifself.prepared.as_ref()!=Some(&source){returnErr(NativeBeaconError::Context);}"
            not in build):
        raise RuntimeError(
            f"{producer_path}: a demanded pulse must await actual shares, never an empty witness"
        )
    for relative, text in ((path, beacon), (producer_path, producer)):
        for scan in ("requires_beacon_pulse_at(", "classifies_beacon_pulse_unavailable_at(",
                     "parliament_attempts"):
            if scan in text:
                raise RuntimeError(
                    f"{relative}: beacon demand regressed to an unbounded Parliament attempt scan"
                )


def require_native_beacon_pulse_application(
    block: str, native_source: str, schedule: str
) -> None:
    """The signed header witness is the sole pulse owner, admitted before any write."""
    block_path = "crates/iroha_core/src/block.rs"
    payload = compact_rust(rust_item(
        block, "        fn validate_sumeragi_consensus_effects(", block_path
    ))
    require_all(block_path, payload, (
        "ifblock.global_beacon_pulse().is_some()"
        "||block.header().global_beacon_pulse_hash().is_some()"
        '{returnErr(Self::npos_effects_error("nativepayloadrejectsasecondbeaconpulseowner",));}',
    ))
    execution = compact_rust(rust_item(
        block, "        fn state_block_for_execution<'state>(", block_path
    ))
    execution_order = (
        "Self::validate_sumeragi_consensus_effects(block)?;",
        ".block_with_recorded_pristine_carrier_stage(",
        ".request_sumeragi_schedule(genesis_height,block,profile.sumeragi_pulse(),"
        "profile.sumeragi_pulse_context(),).map_err(BlockValidationError::from)?;",
    )
    positions = [execution.find(token) for token in execution_order]
    if (any(execution.count(token) != 1 for token in execution_order)
            or positions != sorted(positions)):
        raise RuntimeError(
            f"{block_path}: the pristine schedule must admit the header pulse before effects"
        )
    # Followers decode the pulse only from the signed native header witness.
    native_path = NATIVE_HEADER_SOURCE_PATH
    include = 'include!("block/native_header_source.rs");'
    masked_block = mask_rust(block)
    live_includes = [
        match.start() for match in re.finditer(re.escape(include), block)
        if masked_block.startswith("include!(", match.start())
    ]
    if len(live_includes) != 1:
        raise RuntimeError(f"{block_path}: the native header source must remain the included owner")
    header_source = compact_rust(rust_item(
        native_source, "    pub(crate) fn native_header_source<'state>(", native_path
    ))
    require_all(native_path, header_source, (
        "letpulse=crate::sumeragi::epoch_beacon::control::decode(&native_header.control_witness)",
        "Ok(NativeHeaderSource{state,generation,header:block.header(),",
        "expected_context,pulse,})",
    ))

    schedule_path = SCHEDULE_EXECUTION_PATH
    request = compact_rust(rust_item(
        schedule, "    pub(crate) fn request_sumeragi_schedule(", schedule_path
    ))
    require_all(schedule_path, request, (
        "source.header()!=self._curr_block",
        "authenticate_successor_context(self,&self._curr_block,expected)?;",
    ))
    capture = (
        "epoch_beacon::capture(root_scope,&self.world,self.block_hashes(),{epoch},height,"
        "supplied_pulse,expected_context,).map_err(ScheduleError::Epoch)?;"
    )
    application = compact_rust("""
            if let (Some(value), Some(link)) = (pulse.pulse(), pulse.link()) {
                let slot = (
                    iroha_data_model::governance::types::BeaconSessionId::for_network_v1(
                        &value.network_id,
                    ),
                    value.height,
                );
                self.world
                    .global_beacon_pulses
                    .insert(value.pulse_id, value);
                self.world
                    .global_beacon_pulse_slots
                    .insert(slot, value.pulse_id);
                self.world
                    .global_beacon_latest_pulse
                    .insert(GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY, link);
            }
            self.sumeragi_schedule = ScheduleStep::Requested { captured, pulse };
            Ok(())
        }
    """)
    request_order = (
        compact_rust("""
                let root_scope = if height == genesis_height {
                    iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(source)
                        .map_err(|error| {
                            crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                                ScheduleError::Epoch(error.to_string())
                            })
                        })?
                    .sumeragi_context
                    .root_scope
            } else {
                crate::sumeragi::lanes::routing::committed_root_scope(&self.world).ok_or_else(|| {
                    ScheduleError::Epoch("native control requires immutable root scope".into())
                })?
            };
        """),
        capture.format(epoch="&epoch"),
        "letcurrent=&schedule.ready(height)?.epoch;",
        capture.format(epoch="current"),
        application,
    )
    positions = [request.find(token) for token in request_order]
    if (any(request.count(token) != 1 for token in request_order)
            or positions != sorted(positions) or not request.endswith(application)
            or request.count(".global_beacon_pulses.insert(") != 1):
        raise RuntimeError(
            f"{schedule_path}: only the verified height-roster pulse may be applied, once"
        )


def require_beacon_parliament_pulse_fixtures(
    core: str,
    fixtures: str,
    state_tests: str,
    producer: str,
    producer_tests: str,
    execution_tests: str,
) -> None:
    """Follow the compiled fixtures to canonical admission and both demand consumers."""
    core_path = "crates/iroha_core/src/beacon.rs"
    tests_path = "crates/iroha_core/src/beacon/tests.rs"
    state_tests_path = "crates/iroha_core/src/state/tests.rs"

    def compiled_module(source: str, relative: str, declaration: str, attributes: str) -> None:
        code = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
        declarations = list(re.finditer(
            r"(?P<attrs>(?:[ \t]*#\[[^\n]+\]\s*)*)" + declaration, code,
        ))
        if (len(declarations) != 1
                or re.sub(r"\s+", "", declarations[0].group("attrs")) != attributes):
            raise RuntimeError(
                f"{relative}: Parliament pulse fixtures must use the original test module"
            )

    compiled_module(core, core_path, r"pub\(crate\)\s+mod\s+tests\s*;", "#[cfg(test)]")
    compiled_module(producer, BEACON_PRODUCER_PATH, r"(?<![A-Za-z0-9_])mod\s+tests\s*;",
                    "#[cfg(test)]")
    compiled_module(
        producer_tests, BEACON_PRODUCER_TESTS_PATH, r"mod\s+execution_tests\s*;",
        '#[path="execution_tests.rs"]',
    )
    rust_item(fixtures, "pub(crate) fn pending_batched_sortition_attempt(", tests_path)

    # Canonical admission maintains both derived slot indexes the consumers read.
    admission = compact_rust(rust_item(
        state_tests,
        "fn parliament_required_beacon_slot_index_tracks_lifecycle_and_removal()",
        state_tests_path,
    ))
    admission_order = (
        "crate::beacon::tests::pending_batched_sortition_attempt(",
        '.put_parliament_attempt(attempt.clone()).expect("persistthelivesortitionrequest");',
        ".parliament_required_beacon_pulse_slots.get(&pulse_slot),"
        "Some(&BTreeSet::from([governance_attempt_id]))",
        ".fail_body_election_no_roster(",
        ".put_parliament_attempt(attempt).expect(",
        ".parliament_unavailable_beacon_pulse_slots.get(&pulse_slot),"
        "Some(&BTreeSet::from([governance_attempt_id]))",
    )
    positions = [admission.find(token) for token in admission_order]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise RuntimeError(
            f"{state_tests_path}: canonical Parliament admission must maintain both "
            "derived pulse-slot indexes"
        )

    # Both native consumers start with canonical attempt admission; directly
    # fabricating the derived pulse index would miss the production handoff.
    fixture = compact_rust(rust_item(
        producer_tests, "fn fixture() -> Fixture {", BEACON_PRODUCER_TESTS_PATH
    ))
    require_all(BEACON_PRODUCER_TESTS_PATH, fixture, (
        "crate::beacon::tests::pending_batched_sortition_attempt(&chain.network_id(),&roster,9)",
        '.put_parliament_attempt(attempt).expect("admittheproducer\'sParliamentdemand");',
        "&(BeaconSessionId::for_network_v1(&chain.network_id()),9)",
        "Some(&BTreeSet::from([attempt_id]))",
    ))
    real_shares = compact_rust(rust_item(
        producer_tests,
        "fn all_seats_drive_real_shares_once_and_followers_use_only_transported_pulse()",
        BEACON_PRODUCER_TESTS_PATH,
    ))
    require_all(BEACON_PRODUCER_TESTS_PATH, real_shares, (
        "Err(NativeBeaconError::AwaitingShares{height:9})",
        "control::verify_result(&witness,None).is_err()",
    ))
    if real_shares.count("Err(NativeBeaconError::AwaitingShares{height:9})") != 2:
        raise RuntimeError(
            f"{BEACON_PRODUCER_TESTS_PATH}: observers and validators must await actual shares"
        )
    foreign_committee = compact_rust(rust_item(
        producer_tests,
        "fn native_active_session_from_a_foreign_real_committee_refuses_before_signing()",
        BEACON_PRODUCER_TESTS_PATH,
    ))
    require_all(BEACON_PRODUCER_TESTS_PATH, foreign_committee, (
        "Err(NativeBeaconError::Source(_))",
        "count.load(Ordering::SeqCst)==0",
    ))
    unavailable = compact_rust(rust_item(
        producer_tests,
        "fn wrong_source_sender_and_proof_never_change_the_owned_round()",
        BEACON_PRODUCER_TESTS_PATH,
    ))
    require_all(BEACON_PRODUCER_TESTS_PATH, unavailable, (
        ".parliament_unavailable_beacon_pulse_slots.insert(",
        "fresh.drive(&source,&fixture.context,applied),Err(NativeBeaconError::Source(_))",
        '"anunavailablecommittedslotcannotopenanewlocalsigninground"',
    ))
    replay = compact_rust(rust_item(
        execution_tests,
        "fn transported_pulse_executes_once_and_cold_replay_reproduces_the_certified_result()",
        BEACON_EXECUTION_TESTS_PATH,
    ))
    require_all(BEACON_EXECUTION_TESTS_PATH, replay, (
        "letreplay=same_predecessor(&fixture,true);",
        "missing_header.control_witness=ControlWitness::empty();",
        "invalid(&mutworker,&replay,&missing);",
        'expect("coldexecutorreproducestheoriginalcertifiedpulsewrites")',
        'expect("completedpublicationisidempotent")',
    ))
    refusals = compact_rust(rust_item(
        execution_tests,
        "fn native_pulse_refusals_preserve_the_exact_predecessor_and_require_actual_work()",
        BEACON_EXECUTION_TESTS_PATH,
    ))
    require_all(BEACON_EXECUTION_TESTS_PATH, refusals, (
        "letunrequested=same_predecessor(&fixture,false);",
        "invalid(&mutexecutor(&unrequested),&unrequested,&unrequested_body);",
    ))
    predecessor = compact_rust(rust_item(
        execution_tests,
        "fn same_predecessor(fixture: &Fixture, demand: bool) -> CertifiedTestChain {",
        BEACON_EXECUTION_TESTS_PATH,
    ))
    require_all(BEACON_EXECUTION_TESTS_PATH, predecessor, (
        "crate::beacon::tests::pending_batched_sortition_attempt(&chain.network_id(),&roster,9)",
        'ifdemand{transaction.world.put_parliament_attempt(attempt)'
        '.expect("admitthereplay\'sParliamentdemand");}',
    ))


def require_encrypted_beacon_dkg_source(model: str, core: str) -> None:
    """Bind the public DKG layout and fail-closed all-edge finalization to source."""
    model_path = "crates/iroha_data_model/src/consensus.rs"
    core_path = "crates/iroha_core/src/beacon.rs"
    fields = {
        "GlobalThresholdBeaconDkgSessionV1": (
            "version", "network_id", "session_id", "attempt_id",
            "authority_generation", "roster_hash", "committee_size", "threshold",
            "start_height", "commitments_end_height", "deliveries_end_height",
            "acceptances_end_height",
        ),
        "GlobalThresholdBeaconDkgDealerCommitmentV1": (
            "dealer_index", "coefficient_commitments", "constant_term_proof", "signature",
        ),
        "GlobalThresholdBeaconDkgRecipientKeyV1": (
            "recipient_index", "validator", "x25519_public_key",
            "mlkem768_public_key", "signature",
        ),
        "GlobalThresholdBeaconDkgEncryptedShareV1": (
            "dealer_index", "recipient_index", "dealer_commitment_hash",
            "recipient_key_hash", "delivery_height", "ephemeral_x25519_public_key",
            "mlkem768_ciphertext", "encrypted_share", "signature",
        ),
        "GlobalThresholdBeaconDkgShareAcceptanceV1": (
            "dealer_index", "recipient_index", "dealer_commitment_hash",
            "encrypted_share_hash", "accepted_height", "signature",
        ),
        "GlobalThresholdBeaconDkgTranscriptV1": (
            "session", "generator_h", "generator_v", "dealer_commitments",
            "recipient_keys", "encrypted_shares", "share_acceptances",
            "qualified_dealers", "event_hash", "finalized_at_height",
        ),
    }
    for name, expected in fields.items():
        body = section(model, f"pub struct {name} {{", "\n}", model_path)
        actual = public_field_names(body)
        if actual != expected:
            raise RuntimeError(
                f"{model_path}: {name} must have exact signed encrypted DKG fields; "
                f"expected {expected!r}, found {actual!r}"
            )
    for retired in (
        "GlobalThresholdBeaconDkgComplaintV1",
        "GlobalThresholdBeaconDkgComplaintResponseV1",
        "complaint_responses",
        "revealed_share",
    ):
        if retired in model:
            raise RuntimeError(f"{model_path}: retired public DKG layout remains: {retired}")

    finalization = section(
        core, "    /// Finalize only after every frozen dealer/recipient edge is accepted.",
        "\n}\n\nfn validate_dkg_session(", core_path,
    )
    require_all(core_path, finalization, (
        "let all_edges = seats\n            .checked_mul(seats)",
        "self.recipient_keys.len() != seats",
        "|| self.dealer_commitments.len() != seats",
        "|| self.encrypted_shares.len() != all_edges",
        "|| self.share_acceptances.len() != all_edges",
        "self.aborted = true;",
        "return Err(GlobalThresholdBeaconError::IncompleteDkgEdges.into());",
        "&encrypted_shares,\n            &share_acceptances,",
    ))
    # Follow the sole retained constructor rather than requiring an uncharged
    # inline DTO. Publication must keep the original snapshot, budget and cause.
    retained_order = (
        "letsnapshot=self.public_snapshot()?;",
        "letfinalized=session_owner::retain_finalized_dkg("
        "snapshot.record(),&qualified_dealers,event_hash,height,&derived,&self.budget,)?;",
        "self.finalized=Some(finalized);",
        "self.last_updated_height=height;",
    )
    compact_finalization = compact_rust(finalization)
    positions = [compact_finalization.rfind(token) for token in retained_order]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise RuntimeError(f"{core_path}: finalization must publish the original retained DKG owner")
    retained = compact_rust(rust_item(
        read(BEACON_DKG_OWNER_PATH), "pub(in crate::beacon) fn retain_finalized_dkg(",
        BEACON_DKG_OWNER_PATH,
    ))
    require_all(BEACON_DKG_OWNER_PATH, retained, (
        "letmutreservation=budget.try_reserve_bytes(demand.total_bytes()?)?;",
        "letmutconstruction=Construction::with_demand(demand,budget,&mutreservation)?;",
        "letpublic_shares=construction.copied(&derived.public_shares)?;",
        "letqualified_dealers=construction.copied(qualified_dealers)?;",
        "letrecipient_keys=construction.recipients(source.recipient_keys.iter())?;",
        "letdealer_commitments=construction.dealers(source.dealer_commitments.iter())?;",
        "letencrypted_shares=construction.edges(source.encrypted_shares.iter())?;",
        "letshare_acceptances=construction.acceptances(source.share_acceptances.iter())?;",
        "letadaptive_dkg=GlobalThresholdBeaconDkgTranscriptV1{session:source.session,"
        "generator_h:source.generator_h,generator_v:source.generator_v,dealer_commitments,"
        "recipient_keys,encrypted_shares,share_acceptances,qualified_dealers,event_hash,"
        "finalized_at_height:height,};",
        "letowner=construction.finish(GlobalThresholdBeaconKeySessionV1{",
        "dkg_contribution_hash:event_hash,transcript_hash:derived.transcript_hash,})?;",
        "ifconstruction.reservation.remaining_bytes()!=0{"
        "returnErr(GlobalThresholdBeaconSessionError::PlanChanged);}",
        "Ok(owner)",
    ))
    geometry = rust_item(core, "fn validate_adaptive_dkg_geometry(", core_path)
    require_all(core_path, geometry, (
        "validate_dkg_session(&transcript.session)?;",
        "let seats = usize::from(session.committee_size);",
        "let all_edges = seats\n        .checked_mul(seats)",
        "transcript.recipient_keys.len() != seats",
        "|| transcript.dealer_commitments.len() != seats",
        "|| transcript.encrypted_shares.len() != all_edges",
        "|| transcript.share_acceptances.len() != all_edges",
        ".eq(1..=session.committee_size)",
        "return Err(GlobalThresholdBeaconError::IncompleteDkgEdges);",
        "validation::DkgSnapshotRef::from(transcript).validate_bounds()?;",
    ))
    verification = rust_item(core, "fn validate_adaptive_dkg_shape<V: validation::DkgSignatureVerifier>(", core_path)
    require_all(core_path, verification, (
        "verifier: &mut V",
        "Result<(), GlobalThresholdBeaconVerificationError<V::Resource>>",
        "validate_adaptive_dkg_geometry(record)?;",
        "validation::DkgSnapshotRef::from(transcript).validate_with_verifier(verifier)?;",
        "&transcript.encrypted_shares,\n        &transcript.share_acceptances,",
        "!= transcript.event_hash",
    ))
    ordered = (
        "validate_adaptive_dkg_geometry(record)?;",
        "validation::DkgSnapshotRef::from(transcript).validate_with_verifier(verifier)?;",
        "global_threshold_beacon_dkg_event_hash_v1(",
    )
    positions = [verification.find(token) for token in ordered]
    if (any(verification.count(token) != 1 for token in ordered)
            or positions != sorted(positions)):
        raise RuntimeError(f"{core_path}: geometry and original verifier must precede event admission")


def require_signed_deferred_authority_and_native_fees(
    fee: str, authority: str, retail: str, asset: str, transaction: str, core: str
) -> None:
    """Bind signed staking authority and fees to their separate current owners.

    Opaque committee/staking checks precede optional policy resolution. Native
    User payments retain one signed assessment and finish in the transaction's
    original overlay; protocol custody movements are not customer payments.
    """
    fee_path = "crates/iroha_core/src/validation_fee.rs"
    authority_path = "crates/iroha_core/src/deferred_authority.rs"
    retail_path = "crates/iroha_core/src/retail_fee.rs"
    asset_path = "crates/iroha_core/src/smartcontracts/isi/asset.rs"
    tx_path = "crates/iroha_core/src/tx.rs"
    core_path = "crates/iroha_core/src/lib.rs"

    def item(source: str, declaration: str, path: str) -> str:
        return re.sub(r"\s+", "", mask_rust(rust_item(source, declaration, path)))

    def require(path: str, source: str, bindings: tuple[str, ...]) -> None:
        require_all(path, source, tuple(re.sub(r"\s+", "", x) for x in bindings))

    core_code = mask_rust(core)
    for module in ("deferred_authority", "retail_fee", "validation_fee", "tx"):
        declarations = list(re.finditer(
            rf"(?m)^pub(?:\(crate\))? mod {module};$", core_code
        ))
        if len(declarations) != 1 or core_code[:declarations[0].start()].rstrip().endswith("]"):
            raise RuntimeError(f"{core_path}: native fee owner {module!r} must be unconditional")

    deferred = item(fee, "pub(crate) fn enforce_opaque_deferred_instruction_groups(", fee_path)
    require(fee_path, deferred, (
        "{crate::deferred_authority::reject_opaque_deferred_authority(groups, stx)"
        ".map_err(|error| transaction_attempt_rejection(stx, error))?;"
        "let registry = validated_policy_registry(stx)",
        "active_policy_from_validated_registry(registry.as_ref(), stx)",
    ))
    authoritative = item(authority, "pub(crate) fn reject_opaque_deferred_authority(", authority_path)
    require(authority_path, authoritative, (
        "Result<(), Attempt<TransactionRejectionReason>>",
        "reject_opaque_instruction_authority(instruction_groups.values()"
        ".flat_map(|instructions| instructions.iter()),state_transaction,)",
        ".map_err(|error| error.map_rejection(TransactionRejectionReason::Validation))",
    ))
    shared_authority = item(authority, "pub(crate) fn reject_opaque_instruction_authority<'a>(", authority_path)
    require(authority_path, shared_authority, (
        "Result<(), Attempt<ValidationFail>>",
        "reject_opaque_committee_operations_with(instructions, &mut visited, 0, &mut |approve|",
        "live_proposal_instructions_for_approval(state_transaction, approve)",
        ".map_err(|error| {error.map_rejection(|error| {ValidationFail::NotPermitted(",
    ))
    refusal = item(fee, "fn transaction_attempt_rejection(", fee_path)
    require(fee_path, refusal, (
        "ExecutionAttemptError::Rejected(error) => error",
        "ExecutionAttemptError::Deferred(reason) => {"
        "TransactionRejectionReason::Validation(state.defer_execution(reason))}",
    ))
    classifier = item(authority, "fn monetary_staking_wire_id(", authority_path)
    require(authority_path, classifier, (
        "instruction.as_any().downcast_ref::<$ty>().is_some()",
        "return iroha_data_model::isi::instruction_wire_id(instruction);",
        "classify!(RegisterPublicLaneCandidate, RegisterPublicLaneValidator,"
        "BondPublicLaneStake, FinalizePublicLaneUnbond, SlashPublicLaneValidator,"
        "RecordPublicLaneRewards, ClaimPublicLaneRewards,);",
    ))
    single = item(authority, "fn reject_opaque_committee_operation(", authority_path)
    require(authority_path, single, (
        "custom.id() == &iroha_data_model::nexus::ValidatorCommitteeOperationV1::parameter_id()",
        "return Err(OpaqueDeferredAuthorityError::CommitteeOperation { instruction_index });",
        "if let Some(instruction_wire_id) = monetary_staking_wire_id(instruction)",
        "return Err(OpaqueDeferredAuthorityError::StakingOperation {instruction_index, instruction_wire_id,});",
    ))
    recursive = item(authority, "fn reject_opaque_committee_operations_with<'a, F>(", authority_path)
    require(authority_path, recursive, (
        "if depth > MAX_OPAQUE_DEFERRED_PROPOSAL_DEPTH {return Err(OpaqueDeferredAuthorityError::ProposalDepthExceeded.into());}",
        "reject_opaque_committee_operation(instruction, index)?;",
        "MultisigInstructionBox::Propose(proposal)",
        "reject_opaque_committee_operations_with(proposal.instructions.iter(), visited, depth + 1, resolve,)?;",
        "MultisigInstructionBox::Approve(approval)",
        "Result<(), Attempt<OpaqueDeferredAuthorityError>>",
        "multisig_instruction_decode_attempt(error, |_| ())",
        "Attempt::Deferred(reason) => return Err(Attempt::Deferred(reason))",
        "Attempt::Rejected(()) => None",
        "let Some((authority, instructions)) = resolve(&approval).map_err(|error| {"
        "error.map_rejection(|error| {OpaqueDeferredAuthorityError::ProposalReadFailed(error.to_string())})})?else",
        "reject_opaque_committee_operations_with(instructions.iter(), visited, depth + 1, resolve,)?;",
        "return Err(OpaqueDeferredAuthorityError::UnresolvedMultisigApproval",
        "if visited.insert(identity)",
        "Executable::Instructions(nested)",
        "reject_opaque_committee_operations_with(nested.iter(), visited, depth + 1, resolve,)?;",
        "Executable::IvmProved(proved)",
        "reject_opaque_committee_operations_with(proved.overlay.iter(), visited, depth + 1, resolve,)?;",
        "Executable::Batch(items)",
        "std::slice::from_ref(instruction), visited, depth + 1, resolve,",
    ))
    require(authority_path, re.sub(r"\s+", "", mask_rust(authority)), (
        "const MAX_OPAQUE_DEFERRED_PROPOSAL_DEPTH: usize = 64;",
    ))

    direct = item(fee, "pub(crate) fn enforce_validation_fee_admission(", fee_path)
    require(fee_path, direct, (
        "{let _ = active_policy(state_transaction)?;crate::retail_fee::admit(tx, state_transaction)?;Ok(())}",
    ))
    proved = item(fee, "pub(crate) fn enforce_ivm_proved_completed_axt_admission(", fee_path)
    require(fee_path, proved, (
        "if completed_envelopes == 0 {return Ok(());}",
        "let policy = active_policy(state_transaction).map_err(",
        "ExecutionAttemptError::Deferred(reason) => state_transaction.world.defer_execution(reason)",
        "if policy.is_none() {return Ok(());}",
        "reject_ivm_proved_completed_axt_effects(completed_envelopes)",
    ))
    reject_proved = item(fee, "fn reject_ivm_proved_completed_axt_effects(", fee_path)
    require(fee_path, reject_proved, (
        "if completed_envelopes == 0 {return Ok(());}",
        "Err(ValidationFeeAdmissionError::OpaqueIvmProvedAxtEffects {completed_envelopes,})",
    ))
    admit = item(retail, "pub(crate) fn admit(", retail_path)
    require(retail_path, admit, (
        "tx.instructions().explicit_instructions().any(",
        "log.msg.starts_with(ASSESSMENT_MARKER_PREFIX)",
        "return Err(rejection(",
        "stx.world.retail_fee_source_transaction_hash = Some(*tx.hash().as_ref());",
        "tx.metadata().get(RETAIL_FEE_ASSESSMENT_METADATA_KEY)",
        "norito::json::from_str::<RetailFeeAssessmentV1>(value.get())",
        "bind_assessment(stx, assessment)?;",
    ))
    bind = item(retail, "fn bind_assessment(", retail_path)
    require(retail_path, bind, (
        "now >= assessment.expires_at_ms",
        "assessment.expires_at_ms > now.saturating_add(RETAIL_FEE_QUOTE_TTL_MS)",
        "if stx.world.retail_fee_assessment.is_some() {return Err(rejection(",
        "stx.world.retail_fee_assessment = Some(assessment);",
    ))
    deferred_admit = item(retail, "pub(crate) fn admit_deferred(", retail_path)
    require(retail_path, deferred_admit, (
        "decode_assessment_marker(log)",
        "if reviewed.replace(assessment).is_some() {return Err(rejection(",
        "bind_assessment(stx, assessment)?;",
        "stx.world.retail_fee_assessment_marker_pending = true;",
    ))
    marker = item(retail, "fn decode_assessment_marker(", retail_path)
    require(retail_path, marker, (
        "if log.level != Level::TRACE {return Err((rejection(",
        "encoded.is_empty() || log.msg.len() > 4096 || encoded.len() % 2 != 0",
        "byte.is_ascii_digit()",
        "let assessment = norito::decode_canonical(&bytes)",
    ))
    consume = item(retail, "pub(crate) fn execute_assessment_marker(", retail_path)
    require(retail_path, consume, (
        "if stx.multisig_deferred_execution_stack.is_empty()"
        "|| !stx.world.retail_fee_assessment_marker_pending"
        "|| stx.world.retail_fee_assessment.as_ref() != Some(&assessment)",
        "stx.world.retail_fee_assessment_marker_pending = false;",
    ))
    record = item(retail, "pub(crate) fn record_payment(", retail_path)
    require(retail_path, record, (
        "if source.definition() != &policy.ds_asset_id || amount.is_zero() {return Ok(());}",
        "approved_source == source && approved_destination == destination && approved_amount == amount",
        "stx.world.retail_fee_exempt_payments.remove(index);",
        "if source.account() == destination && stx.world.retail_fee_assessment.is_none() {return Ok(());}",
        "if stx.world.retail_fee_assessment.is_none() {return Err(invalid(",
        "stx.world.retail_fee_observed_payments.push((source.clone(), RetailFeePaymentLegV1",
        "destination_account_id: destination.clone(), amount_minor_units: minor(amount)?",
    ))
    finish = item(retail, "pub(crate) fn finalize(", retail_path)
    require(retail_path, finish, (
        "if stx.world.retail_fee_assessment_marker_pending {return Err(rejection(",
        "if !stx.world.retail_fee_exempt_payments.is_empty() {return Err(rejection(",
        "let observed = std::mem::take(&mut stx.world.retail_fee_observed_payments);",
        "if observed.iter().any(|(id, _)| id != source) {return Err(rejection(",
        "transfers: observed.iter().map(|(_, leg)| leg.clone()).collect(),",
        "let expected = quote(&stx.world, stx.block_height(), stx.block_unix_timestamp_ms(), &request,)",
        "assessment.retail_enrolled != expected.retail_enrolled",
        "assessment.account_id != expected.account_id",
        "assessment.billing_month_start_ms != expected.billing_month_start_ms",
        "assessment.policy_revision != expected.policy_revision",
        "assessment.payments_used_before != expected.payments_used_before",
        "assessment.qualifying_payments != expected.qualifying_payments",
        "assessment.fee_minor != expected.fee_minor",
        "assessment.state_commitment != expected.state_commitment",
        "assessment.intent_hash != expected.intent_hash",
        "let source_transaction_hash = stx.world.retail_fee_source_transaction_hash.ok_or_else(",
        "let remaining = from.checked_sub(assessment.fee_minor).ok_or_else(",
        "to.checked_add(assessment.fee_minor).ok_or_else(",
        "set_balance(&mut stx.world, source, remaining)",
        "source_transaction_hash: Some(source_transaction_hash)",
        "assessment: Some(assessment.clone())",
        "store_receipt(&mut stx.world, &mut native_receipt)",
        "checked_add(assessment.qualifying_payments)",
        "stx.flush_retail_fee_transfer_transcripts()",
        "crate::validation_fee_rewards::credit_collected_fee(stx, &policy, period, collected)?;",
    ))
    if finish.index("letexpected=quote(") > finish.index("letremaining=from.checked_sub("):
        raise RuntimeError(f"{retail_path}: native fee must revalidate before debiting")

    transfer = rust_item(asset, "impl PreparedNumericTransferPlan {", asset_path)
    prepare = item(transfer, "fn prepare(", asset_path)
    require(asset_path, prepare, (
        "retail_payment: source_policy == NumericAssetTransferSourcePolicy::User",
    ))
    for declaration in ("fn apply(", "fn apply_after_batch_preflight("):
        apply = item(transfer, declaration, asset_path)
        require(asset_path, apply, (
            "if self.retail_payment {crate::retail_fee::record_payment(state_transaction, &self.source_id, self.destination_id.account(), &self.amount,)?;}",
            ".apply_prechecked_numeric_asset_transfer_delta_exact(",
        ))
        if apply.index("crate::retail_fee::record_payment(") > apply.index(".apply_prechecked_numeric_asset_transfer_delta_exact("):
            raise RuntimeError(f"{asset_path}: native assessment must precede principal transfer")

    admission = item(transaction, "pub(crate) fn validate_stateful_admission(", tx_path)
    require(tx_path, admission, (
        "crate::validation_fee::enforce_validation_fee_admission(tx, state_transaction)",
        "ExecutionAttemptError::Deferred(reason)",
        "state_transaction.defer_execution(reason)",
    ))
    execute = item(transaction, "pub(crate) fn execute_accepted_transaction_in_overlay(", tx_path)
    sequence = (
        "Self::validate_stateful_admission(",
        "Self::validate_transaction_with_runtime_executor(tx.clone(), state_transaction, ivm_cache)?;",
        "state_transaction.execute_data_triggers_dfs(&authority)",
        "crate::retail_fee::finalize(state_transaction)?;",
        "state_transaction.world.tx_sequences.insert(authority.clone(), seq);",
        "commit_faucet_claim_consumption(state_transaction, &admission);",
    )
    require(tx_path, execute, sequence)
    positions = [execute.index(re.sub(r"\s+", "", x)) for x in sequence]
    if positions != sorted(positions) or execute.count(re.sub(r"\s+", "", sequence[3])) != 1:
        raise RuntimeError(f"{tx_path}: native fee must finish once in the original transaction overlay")


def require_proved_trigger_rejection(source: str) -> None:
    """Registration may not turn a proof-carrying trigger into plain IVM code."""
    path = "crates/iroha_core/src/smartcontracts/isi/triggers/set.rs"
    require_all(
        path,
        source,
        ("Executable::IvmProved(_) => return Err(Error::ProofBackedTriggerUnavailable)",),
    )
    if "proved.bytecode" in source:
        raise RuntimeError(f"{path}: proved trigger was downgraded to plain bytecode")


def require_threshold_signer_startup_readiness(runtime_deps: str) -> None:
    """Bind retained and expired startup custody to their exact executable test owners."""
    runtime_deps_path = "crates/irohad/src/main/runtime_deps.rs"
    require_all(
        runtime_deps_path,
        runtime_deps,
        (
            "parliament_tle_partial_release_signer:",
            "Option<Arc<dyn iroha_core::tle_release::TlePartialReleaseSignerV1>>",
            "with_parliament_tle_partial_release_signer(",
            "pub(crate) fn parliament_tle_release_coordinator(",
            "TleReleaseCoordinatorV1::without_signer",
            "TleReleaseCoordinatorV1::from_signer",
            "tle_key_sessions_required_for_runtime_custody_v1(committed_height)",
            ".tle_key_session_rosters()",
            "parliament_tle_local_participant_index_v1(frozen_roster, local_peer)",
            "require_parliament_tle_capability_for_local_seat_v1(",
            ".attest_partial_release_capability(session, participant_index)",
            "attestation.matches(session, participant_index)",
        ),
    )
    readiness = rust_item(
        runtime_deps, "fn validate_threshold_signer_startup_readiness_v1(", runtime_deps_path,
    )
    capability = rust_item(
        runtime_deps, "fn require_parliament_tle_capability_for_local_seat_v1(", runtime_deps_path,
    )
    if any(".sign_partial_release(" in owner for owner in (readiness, capability)):
        raise RuntimeError(
            f"{runtime_deps_path}: startup readiness must attest custody without signing"
        )
    require_all(runtime_deps_path, capability, (
        ".attest_partial_release_capability(session, participant_index)",
        "attestation.matches(session, participant_index)",
    ))
    readiness_fixture = rust_item(
        runtime_deps, "fn threshold_signer_readiness_fixture_v1(", runtime_deps_path,
    )
    require_all(
        runtime_deps_path,
        readiness_fixture,
        (
            "const RETAINED_SESSION_BYTE: u8 = 0xD1",
            "const ACTIVE_SESSION_BYTE: u8 = 0xE1",
            "const RETENTION_DEADLINE_HEIGHT: u64 = 13",
            "active_validator_keys.reverse()",
            "let retained_participant_index = 2",
            "let active_participant_index = 3",
            "TleKeySessionId::new([RETAINED_SESSION_BYTE; 32])",
            "put_parliament_attempt_for_testing(attempt_id, attempt)",
            "while u64::try_from(block_hashes.len()).unwrap_or(u64::MAX) < committed_height",
        ),
    )
    retained_readiness_test = rust_item(
        runtime_deps,
        "fn threshold_signer_startup_readiness_scans_active_and_deadline_retained_frozen_rosters() {",
        runtime_deps_path,
    )
    require_all(
        runtime_deps_path,
        retained_readiness_test,
        (
            "threshold_signer_readiness_fixture_v1(13)",
            "validate_threshold_signer_startup_readiness_v1(",
            "fixture.retained_key_session_id",
            "fixture.retained_participant_index",
            "fixture.active_key_session_id",
            "fixture.active_participant_index",
            "assert_eq!(calls, expected)",
            "signer.sign_calls.load(Ordering::Acquire), 0",
        ),
    )
    require_all(runtime_deps_path, compact_rust(retained_readiness_test), (
        "letmutcalls=signer.attestation_calls();calls.sort_unstable();",
        "letmutexpected=vec![(fixture.retained_key_session_id,fixture.retained_participant_index,),"
        "(fixture.active_key_session_id,fixture.active_participant_index,),];"
        "expected.sort_unstable();assert_eq!(calls,expected);",
    ))
    expired_readiness_test = rust_item(
        runtime_deps,
        "fn threshold_signer_startup_readiness_skips_expired_history_and_rejects_mismatch() {",
        runtime_deps_path,
    )
    require_all(
        runtime_deps_path,
        expired_readiness_test,
        (
            "threshold_signer_readiness_fixture_v1(14)",
            "validate_threshold_signer_startup_readiness_v1(",
            "exact_signer.attestation_calls()",
            "fixture.active_key_session_id",
            "fixture.active_participant_index",
            "CapabilityMode::MismatchedSeat",
            "mismatched_signer.attestation_calls()",
            "returned a mismatched runtime custody attestation",
        ),
    )
    expired = compact_rust(expired_readiness_test)
    for signer in ("exact_signer", "mismatched_signer"):
        expected_calls = (
            f"assert_eq!({signer}.attestation_calls(),"
            "vec![(fixture.active_key_session_id,fixture.active_participant_index,)]);"
        )
        no_signing = f"assert_eq!({signer}.sign_calls.load(Ordering::Acquire),0);"
        if expired.count(expected_calls) != 1 or expired.count(no_signing) != 1:
            raise RuntimeError(
                f"{runtime_deps_path}: expired startup readiness must assert only the active exact seat without signing"
            )


def main() -> int:
    ivm_executable_path = "crates/iroha_data_model/src/transaction/executable.rs"
    ivm_executable = read(ivm_executable_path)
    require_all(
        ivm_executable_path,
        ivm_executable,
        (
            "IvmProved(IvmProved)",
            "pub struct IvmProved {",
            '"IvmProved" =>',
            "Executable::IvmProved(proved)",
        ),
    )
    ivm_transaction_path = "crates/iroha_data_model/src/transaction/mod.rs"
    require_all(
        ivm_transaction_path,
        read(ivm_transaction_path),
        ("IvmBytecode, IvmProved, TransactionGasLimitError",),
    )
    ivm_signed_path = "crates/iroha_data_model/src/transaction/signed.rs"
    require_all(
        ivm_signed_path,
        read(ivm_signed_path),
        (
            "PrivacyTransactionIntentUnsupportedPathV1::IvmProved",
            "Executable::IvmProved(proved)",
            "privacy_in_unsupported_path",
        ),
    )
    ivm_overlay_path = "crates/iroha_core/src/pipeline/overlay.rs"
    require_all(
        ivm_overlay_path,
        read(ivm_overlay_path),
        (
            "fn tx_overlay_from_ivm_proved_replay",
            "Executable::IvmProved(proved)",
            "enforce_ivm_proved_completed_axt_admission",
        ),
    )
    for ivm_path, bindings in (
        (
            "crates/iroha_core/src/block.rs",
            ("Executable::IvmProved(_)", "ivm_proved_uses_live_overlay_scheduler_path"),
        ),
        (
            "crates/iroha_core/src/validation_fee.rs",
            ("enforce_validation_fee_admission", "enforce_ivm_proved_completed_axt_admission"),
        ),
        (
            "crates/iroha_core/src/queue.rs",
            ("Executable::IvmProved(proved)",),
        ),
    ):
        require_all(ivm_path, read(ivm_path), bindings)
    torii_path = "crates/iroha_torii/src/lib.rs"
    torii_source = read(torii_path)
    for retired in (
        "derive_ivm_proved_payload_from_ivm_execution_bounded_with_vk_context",
        "handler_zk_ivm_derive",
        "handler_zk_ivm_prove",
    ):
        if retired in torii_source:
            raise RuntimeError(f"{torii_path}: retired IVM proof producer remains: {retired}")
    overlay_path = "crates/iroha_core/src/pipeline/overlay.rs"
    if "derive_ivm_proved_payload_from_ivm_execution" in read(overlay_path):
        raise RuntimeError(f"{overlay_path}: retired IVM proof producer remains")
    trigger_path = "crates/iroha_core/src/smartcontracts/isi/triggers/set.rs"
    require_proved_trigger_rejection(read(trigger_path))

    types_path = "crates/iroha_data_model/src/governance/types.rs"
    types = read(types_path)
    require_all(
        types_path,
        types,
        (
            "if self.pulse_height <= self.request_height",
            "MAX_PARLIAMENT_BALLOT_RETRIES_V1: u32 = 16",
            "MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1: u32 = 16",
            "MAX_PARLIAMENT_SORTITION_RETRIES_V1: u32 = 16",
            "MAX_PARLIAMENT_BALLOT_CORPUS_ENTRIES_V1: u32 = 1_000",
            "PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1: usize = 32",
            "MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1: usize = 16 * 1024 * 1024",
            "MAX_PARLIAMENT_CITIZENS_V1: u32 = 65_536",
            "MAX_PARLIAMENT_CANDIDATE_SNAPSHOT_BYTES_V1: usize =",
            "CandidateCountExceedsMaximum",
            "self.candidate_count > MAX_PARLIAMENT_CITIZENS_V1",
            "pub fn parliament_timed_ovn_required_chunk_blocks_v1",
            "parliament_ballot_failure_root_v1",
            "parliament_ballot_result_root_v1",
            "OpeningDeadlineExpired",
            "pub enum ParliamentNoResultKindV1",
            "PublicFindingQuorumUnreachable",
            "PublicFindingDeadlineExpired",
            "BallotOpeningDeadlineExpired",
            "SortitionRetriesExhausted",
            "ConfirmationJuryCapacityUnavailable",
            "RandomnessRedrawBudgetExhausted",
            "impl From<ParliamentBallotFailureKindV1> for ParliamentNoResultKindV1",
            "ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted => {",
            "Self::RandomnessRedrawBudgetExhausted",
            "pub opening_deadline_height: u64",
            "ExecutionFailed",
            "parliament_execution_failure_root_v1",
            "pub const fn parliament_quorum_seats_v1",
            "parliament_public_finding_endorsement_root_v1",
            "pub struct ParliamentPublicFindingCertificateBindingV1",
            "pub endorsement_root: [u8; 32]",
            "pub endorsing_assignments: Vec<AssignmentId>",
            "pub endorsements: u32",
            "pub quorum: u32",
            "let endorsements = u32::try_from(public_finding.endorsing_assignments.len())",
            "public_finding.endorsements != quorum",
            "ballot.commitment_closed_at_height <= ballot.survivor_freeze_height",
            "ballot.commitment_closed_at_height > ballot.commitment_close_height",
            ".saturating_sub(ballot.survivor_freeze_height)",
            "parliament_timed_ovn_required_chunk_blocks_v1(",
        ),
    )
    require_public_finding_endorsement_order(types)
    if "AggregateOpeningFailed" in types:
        raise RuntimeError(
            f"{types_path}: unverifiable caller-triggered aggregate-opening failure remains"
        )

    reducer_path = "crates/iroha_core/src/governance/parliament.rs"
    reducer = read_rust_with_includes(reducer_path)
    require_all(
        reducer_path,
        reducer,
        (
            "first consumed pulse must cover every initially required body in one",
            "sortition_pulse_delay_blocks: u64",
            ".checked_add(self.sortition_pulse_delay_blocks)",
            "InvalidSortitionPulseSchedule",
            "SortitionPulseAvailable",
            "SortitionRetryLimitExceeded",
            "GovernanceAttemptRetryLimitExceeded",
            "MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1",
            "RandomnessRedrawLimitExceeded",
            "RandomnessRedrawLineageMismatch",
            "randomness_redraws_before_attempt: u32",
            "pub(crate) fn randomness_redraws_used_v1(",
            "fn ensure_sortition_generation_redraw_available_v1(",
            "fn ensure_ballot_redraw_available_v1(",
            "validate_parliament_randomness_redraw_lineage_v1",
            "AttemptStateSizeLimitExceeded",
            "fn candidate_snapshot_fits_resource_bounds_v1(",
            "MAX_PARLIAMENT_CANDIDATE_SNAPSHOT_BYTES_V1",
            "MAX_PARLIAMENT_CITIZENS_V1",
            "!candidate_snapshot_fits_resource_bounds_v1(&candidate_snapshot)",
            "!candidate_snapshot_fits_resource_bounds_v1(snapshot)",
            "TimedOvnResourceScheduleConflict",
            "TooManyConcurrentCastingContexts",
            "pub fn register_sortition_request_batch(",
            "MAX_PARLIAMENT_SORTITION_RETRIES_V1",
            "ParliamentElectionFailureKindV1::PulseUnavailable",
            "ParliamentElectionFailureKindV1::EmptyAcceptedRoster",
            "ParliamentElectionFailureKindV1::InsufficientHiddenBallotRoster",
            "pub struct ParliamentSortitionCapacityFailureV1 {",
            "pub fn record_hidden_sortition_capacity_failure_batch(",
            "hidden_ballot_population_meets_anonymity_floor_v1(candidate_snapshot.len())",
            "failure.failure_height != failure.request_height",
            "active_sortition_capacity_failures",
            "BodyElectionAttemptStatusV1::AwaitingPulse",
            "BodyElectionAttemptStatusV1::Drawing",
            "BodyElectionAttemptStatusV1::AcceptingInvitations",
            "request.request_height < failure_height",
            "election.attempt.sequence == MAX_PARLIAMENT_SORTITION_RETRIES_V1",
            "election_awaiting_pulse_shape_is_empty(election)",
            "pulse_missing_terminal",
            "pub(crate) fn precheck_close_ballot_registration(",
            "current_height == ballot.registration_close_height",
            "pub(crate) fn precheck_freeze_ballot_survivors(",
            "current_height == ballot.survivor_freeze_height",
            "pub(crate) fn precheck_freeze_timed_ovn_corpus(",
            "timed_commitment_height_is_in_window(ballot, current_height)",
            "height > ballot.survivor_freeze_height",
            "height <= ballot.commitment_close_height",
            "timed_commitment_completed_in_window(ballot)",
            "ParliamentBallotFailureKindV1::CommitmentDeadlineExpired",
            "minimum_registration_phase_blocks = u64::from(policy.max_corpus_entries)",
            "policy.registration_phase_blocks < minimum_registration_phase_blocks",
            "policy.survivor_freeze_phase_blocks < minimum_survivor_freeze_phase_blocks",
            "parliament_timed_ovn_required_chunk_blocks_v1(policy.max_corpus_entries)",
            "timed_ovn_policy.max_corpus_entries < original_seats",
            "policy.opening_phase_blocks == 0",
            ".checked_add(policy.opening_phase_blocks)",
            "at_height > ballot.opening_deadline_height",
            "result_height > opening_deadline_height",
            "self.used_tle_sessions.contains_key(&tle_session_id)",
            "self.used_tle_sessions\n            .insert(tle_session_id, ballot_attempt_id)",
            "previous.attempt.status != BallotAttemptStatusV1::NoResult",
            "registered_at_height < failure_height",
            "release_pulse_available: bool",
            "classify_ballot_failure(ballot, release_pulse_available, current_height)",
            "current_height > ballot.opening_deadline_height",
            "ParliamentBallotFailureKindV1::ReleasePulseUnavailable",
            "ParliamentBallotFailureKindV1::OpeningDeadlineExpired",
            "ParliamentBallotFailureKindV1::ConfirmationJuryCapacityUnavailable",
            "ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted",
            "eligible_confirmation_candidates: Option<u32>",
            "eligible_confirmation_candidates < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1",
            "request.target_seats < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1",
            "!hidden_ballot_population_meets_anonymity_floor_v1(candidate_snapshot.len())",
            "request.request_height < policy_result_height",
            "request.request_height != policy_result_height",
            "sequences.get(&0)",
            "fn policy_margin_is_strict_and_atomic_confirmation_roster_is_fresh()",
            "fn hidden_sortition_capacity_failure_is_typed_bounded_and_consumes_no_pulse()",
            "fn hidden_sortition_capacity_restore_rejects_mutated_evidence()",
            "fn live_sortition_candidates_retain_bonds_until_terminal_or_superseded()",
            "fn retryable_singleton_capacity_failure_retains_only_its_live_candidate_bond()",
            "restore must reject a narrow Policy approval without its atomic Confirmation request",
            "restore must reject a Confirmation snapshot backdated before the Policy result",
            "restore must reject a sequence-zero Confirmation snapshot delayed past the Policy result",
            "parliament_ballot_failure_root_v1(",
            "if at_height != certificate.enact_at_height",
            "if observed_head == certificate.expected_head",
            "pub fn mark_execution_failed(",
            "parliament_execution_failure_root_v1(",
            "GovernanceAttemptStatusV1::ExecutionFailed",
            "pub fn record_attempt_absence(",
            "if &assignment.member != member",
            "!body.public_finding_endorsements.is_empty()",
            "pub fn endorse_public_finding(",
            "find(|assignment| &assignment.member == member)",
            ".contains_key(&assignment.assignment_id)",
            "let quorum = parliament_quorum_seats_v1(body.instance.original_seats);",
            ".insert(assignment_id, result_root);",
            "if endorsements < quorum",
            "fn public_finding_quorum_is_unreachable(",
            ".checked_sub(body.excluded_assignments.len())",
            ".checked_sub(body.public_finding_endorsements.len())",
            "strongest_existing_root.saturating_add(remaining) < quorum",
            "pub fn fail_public_finding_no_result(",
            "if current_height <= deadline_height",
            "ParliamentNoResultKindV1::PublicFindingDeadlineExpired",
            "let retry_budget_exhausted = ballot.attempt.sequence == ballot.max_ballot_retries;",
            "proposal_wide_redraw_budget_composes_sortition_and_timed_ovn_retries",
            "successor_attempt_inherits_exact_proposal_redraw_prefix",
            "narrow_policy_at_randomness_redraw_ceiling_persists_terminal_no_result",
            "an exact transport retry must not spend a redraw unit",
            "parliament_public_finding_endorsement_root_v1(",
            "body.public_finding_binding = Some(ParliamentPublicFindingCertificateBindingV1",
            "endorsing_assignments,\n                endorsements,\n                quorum,",
        ),
    )
    canonical_attempt_ids = section(
        reducer,
        "pub fn canonical_governance_attempt_ids_v1(",
        "/// A reducible entity named by",
        reducer_path,
    )
    require_all(
        reducer_path,
        canonical_attempt_ids,
        (
            "0..=MAX_PARLIAMENT_GOVERNANCE_ATTEMPT_RETRIES_V1",
            "GovernanceAttemptId::derive_v1(proposal_content_id, sequence)",
        ),
    )
    attempt_size_validation = section(
        reducer,
        "pub(crate) fn validate_encoded_size_v1(",
        "fn expected_completed_body_count_v1(",
        reducer_path,
    )
    require_all(
        reducer_path,
        attempt_size_validation,
        (
            "norito::core::encoded_frame_len(self)",
            "MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1",
            "ParliamentReducerErrorV1::AttemptStateSizeLimitExceeded",
        ),
    )
    redraw_accounting = section(
        reducer,
        "pub(crate) fn randomness_redraws_used_v1(",
        "fn ensure_sortition_generation_redraw_available_v1(",
        reducer_path,
    )
    require_all(
        reducer_path,
        redraw_accounting,
        (
            "self.attempt.sequence == 0 && sortition_generations > 0",
            ".checked_sub(baseline_generations)",
            ".filter(|ballot| ballot.attempt.sequence > 0)",
            ".randomness_redraws_before_attempt",
            ".checked_add(sortition_redraws)",
            ".and_then(|used| used.checked_add(ballot_redraws))",
            "used > MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1",
        ),
    )
    sortition_redraw_guard = section(
        reducer,
        "fn ensure_sortition_generation_redraw_available_v1(",
        "fn ensure_ballot_redraw_available_v1(",
        reducer_path,
    )
    require_all(
        reducer_path,
        sortition_redraw_guard,
        (
            "generations.contains(&slot)",
            "self.attempt.sequence == 0 && generations.is_empty()",
            "self.randomness_redraws_used_v1()? < MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1",
            "ParliamentReducerErrorV1::RandomnessRedrawLimitExceeded",
        ),
    )
    ballot_redraw_guard = section(
        reducer,
        "fn ensure_ballot_redraw_available_v1(",
        "/// Return the distinct accounts referenced by this attempt",
        reducer_path,
    )
    require_all(
        reducer_path,
        ballot_redraw_guard,
        (
            "sequence == 0",
            "self.randomness_redraws_used_v1()? < MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1",
            "ParliamentReducerErrorV1::RandomnessRedrawLimitExceeded",
        ),
    )
    confirmation_redraw_terminalization = section(
        reducer,
        "pub fn finalize_opened_ballot(",
        "/// Construct and freeze the complete automatic governance certificate.",
        reducer_path,
    )
    require_all(
        reducer_path,
        confirmation_redraw_terminalization,
        (
            "eligible_confirmation_candidates < MIN_PARLIAMENT_HIDDEN_BALLOT_ANONYMITY_V1",
            "self.randomness_redraws_used_v1()? == MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1",
            "Some(ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted)",
            "if let Some(failure_kind) = confirmation_failure_kind",
            "ballot.failure_kind = Some(failure_kind)",
            "ballot.attempt.status = BallotAttemptStatusV1::NoResult",
            "BodyInstanceStatusV1::NoResult",
            "self.attempt.status = GovernanceAttemptStatusV1::Rejected",
            "return Ok(ParliamentAggregateOutcomeV1::NoResult)",
        ),
    )
    sortition_failure_terminalization = section(
        reducer,
        "pub fn fail_body_election_no_roster(",
        "/// Seal a canonical roster into a new body instance.",
        reducer_path,
    )
    require_all(
        reducer_path,
        sortition_failure_terminalization,
        (
            "let proposal_redraw_budget_exhausted =",
            "self.randomness_redraws_used_v1()? == MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1",
            "retry_budget_exhausted || proposal_redraw_budget_exhausted",
            "election.attempt.sequence == MAX_PARLIAMENT_SORTITION_RETRIES_V1",
            "self.attempt.status = GovernanceAttemptStatusV1::Rejected",
        ),
    )
    require_sortition_retry_liveness(reducer)
    ballot_failure_terminalization = section(
        reducer,
        "pub fn fail_ballot_no_result(",
        "/// Finalize a cryptographically opened aggregate and its body result.",
        reducer_path,
    )
    require_all(
        reducer_path,
        ballot_failure_terminalization,
        (
            "let proposal_redraw_budget_exhausted =",
            "self.randomness_redraws_used_v1()? == MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1",
            "retry_budget_exhausted || proposal_redraw_budget_exhausted",
            "self.attempt.status = GovernanceAttemptStatusV1::Rejected",
        ),
    )
    confirmation_redraw_terminal_test = section(
        reducer,
        "fn narrow_policy_at_randomness_redraw_ceiling_persists_terminal_no_result()",
        "fn sealed_and_released_cross_store_bindings_fail_closed_on_substitution()",
        reducer_path,
    )
    require_all(
        reducer_path,
        confirmation_redraw_terminal_test,
        (
            "MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1",
            "ParliamentAggregateOutcomeV1::NoResult",
            "GovernanceAttemptStatusV1::Rejected",
            '"the unaffordable Confirmation draw must never enter the pipeline"',
            '"the narrow Policy result must remain uncommitted"',
            "BodyInstanceStatusV1::NoResult",
            "BallotAttemptStatusV1::NoResult",
            "ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted",
            '"redraw-exhausted opening must restore canonically"',
            '"the redraw-exhaustion classification requires the exact shared ceiling"',
        ),
    )
    redraw_lineage = section(
        reducer,
        "pub fn validate_parliament_randomness_redraw_lineage_v1",
        "#[cfg(test)]\npub(crate) mod tests {",
        reducer_path,
    )
    require_all(
        reducer_path,
        redraw_lineage,
        (
            "attempts.sort_unstable_by_key(|attempt| attempt.borrow().attempt.sequence)",
            "attempt.randomness_redraws_before_attempt != expected_prefix",
            "attempt.randomness_redraws_before_attempt >= MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1",
            "expected_prefix = attempt.randomness_redraws_used_v1()?",
        ),
    )
    full_attempt_validation = section(
        reducer,
        "pub fn validate(&self) -> Result<(), ParliamentReducerErrorV1> {",
        "#[cfg(any(test, feature = \"iroha-core-tests\"))]",
        reducer_path,
    )
    if not full_attempt_validation.lstrip().startswith(
        "self.validate_encoded_size_v1()?;"
    ):
        raise RuntimeError(
            f"{reducer_path}: full attempt validation must begin with the exact size-only guard"
        )
    execution_failure_signature = re.search(
        r"pub fn mark_execution_failed\((?P<params>.*?)\)\s*->", reducer, re.S
    )
    if execution_failure_signature is None:
        raise RuntimeError(f"{reducer_path}: cannot locate execution-failure reducer")
    for caller_field in ("failure_root", "effect_preimage_hash"):
        if caller_field in execution_failure_signature.group("params"):
            raise RuntimeError(
                f"{reducer_path}: execution-failure reducer accepts caller field {caller_field!r}"
            )
    if "AggregateOpeningFailed" in reducer:
        raise RuntimeError(
            f"{reducer_path}: unverifiable caller-triggered aggregate-opening failure remains"
        )
    absence_reducer = section(
        reducer,
        "pub fn record_attempt_absence(",
        "fn build_ballot_binding(",
        reducer_path,
    )
    require_all(
        reducer_path,
        absence_reducer,
        (
            "public_finding_deadline_height",
            ".is_some_and(|deadline| current_height > deadline)",
            "ParliamentReducerErrorV1::PublicFindingWindowClosed",
        ),
    )

    instruction_path = "crates/iroha_data_model/src/isi/governance/parliament.rs"
    instructions = read(instruction_path)
    require_all(
        instruction_path,
        instructions,
        (
            "MAX_PARLIAMENT_SORTITION_REQUESTS_PER_BATCH_V1: usize = 10",
            "pub struct ParliamentSortitionRequestRegistrationV1",
            "pub requests: Vec<ParliamentSortitionRequestRegistrationV1>",
            "next contiguous corpus chunk is appended",
            "complete exact survivor coverage and causes automatic corpus sealing",
            "entry.request.validate_capacity_intent(None).is_err()",
            "fn zero_candidate_sortition_intent_reaches_consensus_capacity_validation()",
        ),
    )
    for misplaced_policy_definition in (
        "pub const PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1",
        "pub fn parliament_timed_ovn_required_chunk_blocks_v1",
    ):
        if misplaced_policy_definition in instructions:
            raise RuntimeError(
                f"{instruction_path}: timed-OVN chunk policy must be owned by {types_path}"
            )
    transition_enum = section(
        instructions,
        "pub enum ParliamentLifecycleTransitionV1 {",
        "/// Bounded audit classification",
        instruction_path,
    )
    for forbidden in (
        "Plain",
        "Plaintext",
        "Fallback",
        "ManualOpen",
        "ConstructCertificate",
        "MarkEnacted",
        "MarkSuperseded",
        "MarkExecutionFailed",
        "FinalizePublicFinding",
    ):
        if forbidden in transition_enum:
            raise RuntimeError(
                f"{instruction_path}: closed Parliament transition enum contains {forbidden!r}"
            )
    automatic_outcome = section(
        instructions,
        "pub enum ParliamentAutomaticExecutionOutcomeV1 {",
        "/// One closed, versioned transition accepted",
        instruction_path,
    )
    require_all(
        instruction_path,
        automatic_outcome,
        (
            "Enacted",
            "Superseded(ParliamentAutomaticSupersededV1)",
            "ExecutionFailed(ParliamentAutomaticExecutionFailedV1)",
        ),
    )
    require_all(
        instruction_path,
        transition_enum,
        (
            "RecordAttemptAbsence(ParliamentRecordAttemptAbsenceV1)",
            "EndorsePublicFinding(ParliamentEndorsePublicFindingV1)",
            "FailPublicFindingNoResult(ParliamentFailPublicFindingNoResultV1)",
        ),
    )
    require_all(
        instruction_path,
        instructions,
        (
            "PARLIAMENT_AUTOMATIC_EXECUTION_OUTCOME_DIGEST_V1",
            "impl ParliamentAutomaticExecutionOutcomeV1",
            "pub fn digest_v1(self) -> [u8; 32]",
        ),
    )
    failure_payload = section(
        instructions,
        "pub struct ParliamentFailBallotNoResultV1 {",
        "/// Canonical public final threshold release record",
        instruction_path,
    )
    require_all(
        instruction_path,
        failure_payload,
        ("pub ballot_attempt_id: BallotAttemptId",),
    )
    if "failure_kind" in failure_payload or "failure_root" in failure_payload:
        raise RuntimeError(
            f"{instruction_path}: caller can select reducer-derived ballot failure evidence"
        )
    objective_election_progress_payloads = (
        (
            "pub struct ParliamentConsumeSortitionPulseBatchV1 {",
            "/// Payload beginning invitation acceptance after a deterministic draw.",
            ("request_ids", "beacon_session_id", "pulse_height", "pulse_id"),
        ),
        (
            "pub struct ParliamentBeginInvitationAcceptanceV1 {",
            "/// Payload terminally recording a missing sortition pulse or empty roster.",
            ("election_attempt_id",),
        ),
        (
            "pub struct ParliamentFailBodyElectionNoRosterV1 {",
            "/// A candidate's response to one canonical Parliament invitation.",
            ("election_attempt_id",),
        ),
        (
            "pub struct ParliamentSealBodyRosterV1 {",
            "/// Payload advancing one sealed body by exactly one deliberation phase.",
            ("election_attempt_id",),
        ),
    )
    for start, end, expected_fields in objective_election_progress_payloads:
        payload = section(instructions, start, end, instruction_path)
        actual_fields = public_field_names(payload)
        if actual_fields != expected_fields:
            raise RuntimeError(
                f"{instruction_path}: objective election-progress payload {start!r} "
                f"must expose exactly {expected_fields!r}, found {actual_fields!r}"
            )
    absence_payload = section(
        instructions,
        "pub struct ParliamentRecordAttemptAbsenceV1 {",
        "/// Payload endorsing one public nonbinding Parliament finding",
        instruction_path,
    )
    require_all(
        instruction_path,
        absence_payload,
        ("pub body_instance_id: BodyInstanceId", "pub assignment_id: AssignmentId"),
    )
    for caller_field in ("pub member:", "pub authority:"):
        if caller_field in absence_payload:
            raise RuntimeError(
                f"{instruction_path}: self-absence accepts caller field {caller_field!r}"
            )
    endorsement_payload = section(
        instructions,
        "pub struct ParliamentEndorsePublicFindingV1 {",
        "/// Payload triggering objective expiry of one public-finding endorsement window.",
        instruction_path,
    )
    require_all(
        instruction_path,
        endorsement_payload,
        ("pub body_instance_id: BodyInstanceId", "pub result_root: [u8; 32]"),
    )
    for caller_field in (
        "pub assignment_id:",
        "pub member:",
        "pub authority:",
        "pub endorsement_root:",
        "pub endorsements:",
        "pub quorum:",
    ):
        if caller_field in endorsement_payload:
            raise RuntimeError(
                f"{instruction_path}: public-finding endorsement accepts caller field {caller_field!r}"
            )
    public_failure_payload = section(
        instructions,
        "pub struct ParliamentFailPublicFindingNoResultV1 {",
        "/// Payload registering a fresh private timed-OVN ballot attempt.",
        instruction_path,
    )
    require_all(
        instruction_path,
        public_failure_payload,
        ("pub body_instance_id: BodyInstanceId",),
    )
    for caller_field in (
        "result_root",
        "failure_kind",
        "failure_height",
        "deadline_height",
    ):
        if caller_field in public_failure_payload:
            raise RuntimeError(
                f"{instruction_path}: public-finding expiry accepts caller field {caller_field!r}"
            )
    for start, end, forbidden in (
        (
            "pub struct ParliamentCloseBallotRegistrationV1 {",
            "/// Payload recording one registered seated member's authenticated dropout.",
            ("registration_records", "roster_root", "registered_voters"),
        ),
        (
            "pub struct ParliamentRecordBallotDropoutV1 {",
            "/// Payload freezing the exact nonempty survivor subset derived by Core.",
            ("participant_hash", "member_id"),
        ),
        (
            "pub struct ParliamentFreezeBallotSurvivorsV1 {",
            "/// Payload appending the exact next timed-OVN ciphertext and one-hot-proof chunk.",
            ("survivor_participant_hashes", "dropout_root", "survivor_corpus_root"),
        ),
    ):
        payload = section(instructions, start, end, instruction_path)
        for field in forbidden:
            if field in payload:
                raise RuntimeError(
                    f"{instruction_path}: caller-selected {field!r} re-entered {start}"
                )

    world_path = "crates/iroha_core/src/smartcontracts/isi/world.rs"
    world = read(world_path)
    require_all(
        world_path,
        world,
        (
            ".checked_add(configured_delay)",
            "parliament_certificate_enactment_height_v1(",
            "observed_head != certificate.expected_head",
            "apply_parliament_proposal_effect_v1",
            "parliament_finalized_pulse_seed_v1",
            "parliament_verified_pulse_available_v1",
            "entry.request.target_seats != configured_target",
            "let first = payload.requests.first()",
            "for entry in &payload.requests",
            ".register_sortition_request_batch(",
            "request.beacon_session_id",
            "request.pulse_height",
            "pulse_available,\n                            current_height",
            ".global_beacon_pulses",
            "ballot.release_beacon_session_id()",
            "release_pulse_available",
            "validate_ballot_registration_member",
            "parliament_ballot_participant_hash_v1",
            "lifecycle.registration_records().len()",
            ".close_registration(&tle_key_session)",
            "validate_ballot_dropout_member",
            ".record_dropout(participant_hash, &tle_key_session)",
            ".freeze_survivors(&tle_key_session)",
            ".seal_ballots(payload.ballot_records, &tle_key_session)",
            "PARLIAMENT_TIMED_OVN_BALLOT_CHUNK_MAX_RECORDS_V1",
            "DueParliamentCertificateExecutionV1",
            "execute_due_parliament_certificate_v1",
            "record_due_parliament_execution_failure_v1",
            "parliament_execution_failure_root_v1(",
            "ParliamentAutomaticExecutionOutcomeV1::Enacted",
            "ParliamentAutomaticExecutionOutcomeV1::Superseded",
            "ParliamentAutomaticSupersededV1 { observed_head }",
            "ParliamentAutomaticExecutionOutcomeV1::ExecutionFailed",
            "ParliamentAutomaticExecutionFailedV1 {",
            "ParliamentLifecycleTransitionV1::RecordAttemptAbsence(payload)",
            ".record_attempt_absence(",
            "payload.assignment_id,\n                            authority,\n                            current_height,",
            "ParliamentLifecycleTransitionV1::EndorsePublicFinding(payload)",
            ".endorse_public_finding(",
            "payload.result_root,\n                            authority,\n                            current_height,",
            "ParliamentLifecycleTransitionV1::FailPublicFindingNoResult(payload)",
            ".fail_public_finding_no_result(",
            "state_transaction.gov.parliament_public_finding_phase_blocks",
            "no_result_kind",
            "fn validated_active_parliament_tle_key_session_for_new_ballot_v1(",
            ".tle_key_session_eligible_for_new_ballots(",
            "key_session_id,\n                state_transaction.block_height(),",
            ".tle_key_session_rosters()",
            "frozen_ordered_roster != Some(ordered_roster)",
            '"active Parliament TLE key session is not bound to the current commit topology"',
            "let randomness_redraws_before_attempt = previous",
            "ParliamentAttemptStateV1::randomness_redraws_used_v1",
            "randomness_redraws_before_attempt\n                    >= crate::governance::parliament::MAX_PARLIAMENT_RANDOMNESS_REDRAWS_V1",
            "ParliamentAttemptStateV1::try_new_with_randomness_redraws_before_attempt(",
        ),
    )
    manager_partition = section(
        world,
        "fn parliament_transition_requires_manager_v1(",
        "fn parliament_certificate_enactment_height_v1(",
        world_path,
    )
    require_all(
        world_path,
        manager_partition,
        (
            # SCCP route governance has no clerk (specs/sccp.md §4.14.5 item 3).
            "Some(ProposalKind::SccpRouteGovernance(_))",
            "ParliamentLifecycleTransitionKindV1::ConsumeSortitionPulseBatch",
            "ParliamentLifecycleTransitionKindV1::BeginInvitationAcceptance",
            "ParliamentLifecycleTransitionKindV1::FailBodyElectionNoRoster",
            "ParliamentLifecycleTransitionKindV1::SealBodyRoster",
            "ParliamentLifecycleTransitionKindV1::FreezeTimedOvnCorpus",
        ),
    )
    for manager_only in (
        "ParliamentLifecycleTransitionKindV1::EscalateRisk",
        "ParliamentLifecycleTransitionKindV1::CompleteQualification",
        "ParliamentLifecycleTransitionKindV1::RegisterSortitionRequest",
        "ParliamentLifecycleTransitionKindV1::AdvanceBodyPhase",
        "ParliamentLifecycleTransitionKindV1::RegisterBallotAttempt",
    ):
        if manager_only in manager_partition:
            raise RuntimeError(
                f"{world_path}: manager-only intent transition became permissionless: "
                f"{manager_only!r}"
            )
    create_attempt_execution = section(
        world,
        "impl Execute for gov::CreateParliamentGovernanceAttemptV1 {",
        "fn confirmation_candidate_snapshot_v1(",
        world_path,
    )
    require_all(
        world_path,
        create_attempt_execution,
        ("require_parliament_manager(authority, state_transaction)?;",),
    )
    require_all(
        world_path,
        world,
        (
            "fn canonical_parliament_eligible_candidates_with_limits_v1(",
            "state_transaction.world.citizens.len() > max_citizens",
            "let mut snapshot_bytes = norito::core::seq_len_prefix_len(0)",
            "norito::core::encoded_payload_len(account_id)",
            "snapshot_bytes > max_snapshot_bytes",
            "fn ensure_parliament_citizen_registry_capacity_with_limit_v1(",
            "!owner_is_already_citizen && current_citizens >= max_citizens",
            "MAX_PARLIAMENT_CITIZENS_V1",
            "fn parliament_candidate_snapshot_derivation_has_preallocation_resource_bounds()",
            "exact_snapshot_bytes - 1",
            "fn parliament_progress_authority_partition_is_exact()",
            "fn parliament_hidden_sortition_capacity_is_objective_for_zero_and_one_candidate()",
            "fn parliament_sortition_pulse_consumption_is_permissionless_and_exactly_bound()",
            "fn parliament_invitation_start_is_permissionless_and_election_bound()",
            "fn parliament_no_roster_failure_is_permissionless_and_reducer_derived()",
            "fn parliament_roster_sealing_is_permissionless_and_transcript_derived()",
            "fn parliament_proof_heavy_ballot_corpus_is_permissionless_but_shape_checked()",
            "fn parliament_non_manager_can_append_the_exact_next_timed_ovn_chunks()",
        ),
    )
    for branch_start, branch_end, bindings in (
        (
            "gov::ParliamentLifecycleTransitionV1::ConsumeSortitionPulseBatch(payload) => {",
            "gov::ParliamentLifecycleTransitionV1::BeginInvitationAcceptance(payload) => {",
            (
                "parliament_finalized_pulse_seed_v1(",
                "payload.request_ids",
                "payload.beacon_session_id",
                "payload.pulse_height",
                "payload.pulse_id",
                "pulse_output",
                "&state_transaction.network_id",
                "&state_transaction.gov",
            ),
        ),
        (
            "gov::ParliamentLifecycleTransitionV1::BeginInvitationAcceptance(payload) => {",
            "gov::ParliamentLifecycleTransitionV1::FailBodyElectionNoRoster(payload) => {",
            (
                "payload.election_attempt_id",
                "current_height",
                "state_transaction.gov.parliament_invitation_phase_blocks",
            ),
        ),
        (
            "gov::ParliamentLifecycleTransitionV1::FailBodyElectionNoRoster(payload) => {",
            "gov::ParliamentLifecycleTransitionV1::SealBodyRoster(payload) => {",
            (
                "parliament_verified_pulse_available_v1(",
                "request.beacon_session_id",
                "request.pulse_height",
                "pulse_available",
                "current_height",
            ),
        ),
        (
            "gov::ParliamentLifecycleTransitionV1::SealBodyRoster(payload) => {",
            "gov::ParliamentLifecycleTransitionV1::AdvanceBodyPhase(payload) =>",
            ("payload.election_attempt_id", "current_height"),
        ),
    ):
        branch = section(world, branch_start, branch_end, world_path)
        require_all(world_path, branch, bindings)
    require_sortition_registration_guards(world)
    for forbidden in (
        "ParliamentLifecycleTransitionV1::ConstructCertificate",
        "ParliamentLifecycleTransitionV1::MarkEnacted",
        "ParliamentLifecycleTransitionV1::MarkSuperseded",
        "ParliamentLifecycleTransitionV1::MarkExecutionFailed",
        "ParliamentLifecycleTransitionV1::FinalizePublicFinding",
    ):
        if forbidden in world:
            raise RuntimeError(
                f"{world_path}: consensus-owned action remains a public transition: {forbidden!r}"
            )
    finalize_branch = section(
        world,
        "gov::ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(payload) => {",
        "gov::ParliamentLifecycleTransitionV1::BeginBallotOpeningBatch(payload) => {",
        world_path,
    )
    require_all(
        world_path,
        finalize_branch,
        (
            "canonical_parliament_eligible_candidates_v1(",
            "confirmation_candidate_snapshot_v1(",
            "eligible_confirmation_candidates",
            ".finalize_opened_ballot(",
            "canonical_confirmation_sortition_request_v1(",
            ".register_sortition_request(",
            ".construct_certificate(",
        ),
    )
    require_all(
        world_path,
        world,
        (
            "fn narrow_confirmation_request_freezes_exact_current_snapshot_and_schedule()",
            "request_height + attempt.sortition_pulse_delay_blocks()",
            "request.id, request.canonical_id()",
        ),
    )
    for branch_start, branch_end, precheck, phase_guard, expensive_call in (
        (
            "gov::ParliamentLifecycleTransitionV1::CloseBallotRegistration(payload) => {",
            "gov::ParliamentLifecycleTransitionV1::RecordBallotDropout(payload) => {",
            ".precheck_close_ballot_registration(",
            "TimedOvnLifecycleStateV1::Registered(_)",
            ".close_registration(&tle_key_session)",
        ),
        (
            "gov::ParliamentLifecycleTransitionV1::FreezeBallotSurvivors(payload) => {",
            "gov::ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(payload) => {",
            ".precheck_freeze_ballot_survivors(",
            "TimedOvnLifecycleStateV1::RegistrationClosed(_)",
            ".freeze_survivors(&tle_key_session)",
        ),
        (
            "gov::ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(payload) => {",
            "gov::ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(payload) => {",
            ".precheck_freeze_timed_ovn_corpus(",
            "TimedOvnLifecycleStateV1::SurvivorsFrozen(_)",
            ".seal_ballots(payload.ballot_records, &tle_key_session)",
        ),
    ):
        branch = section(world, branch_start, branch_end, world_path)
        require_all(world_path, branch, (precheck, phase_guard, expensive_call))
        if branch.find(precheck) > branch.find(expensive_call):
            raise RuntimeError(
                f"{world_path}: {precheck!r} must precede proof-heavy {expensive_call!r}"
            )
        if branch.find(phase_guard) > branch.find(expensive_call):
            raise RuntimeError(
                f"{world_path}: {phase_guard!r} must precede proof-heavy {expensive_call!r}"
            )

    corpus_branch = section(
        world,
        "gov::ParliamentLifecycleTransitionV1::FreezeTimedOvnCorpus(payload) => {",
        "gov::ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(payload) => {",
        world_path,
    )
    require_all(
        world_path,
        corpus_branch,
        (
            "TimedOvnLifecycleStateV1::CorpusOpen(_)",
            "if let TimedOvnLifecycleStateV1::Sealed(sealed) = &lifecycle",
            ".freeze_timed_ovn_corpus(",
        ),
    )
    api_path = "crates/iroha_torii_shared/src/parliament_api.rs"
    api = read(api_path)
    require_all(api_path, api, ("impl ParliamentTransitionDraftRequestV1 {",))
    for forbidden in (
        "Transition::ConstructCertificate",
        "Transition::MarkEnacted",
        "Transition::MarkSuperseded",
        "Transition::MarkExecutionFailed",
        "Transition::FinalizePublicFinding",
    ):
        if forbidden in api:
            raise RuntimeError(
                f"{api_path}: public draft code references retired transition {forbidden!r}"
            )
    require_all(
        api_path,
        api,
        (
            "pub execution_failure_root: Option<[u8; 32]>",
        ),
    )
    if "PARLIAMENT_ATTEMPT_READ_MAX_STATE_BYTES_V1" in api:
        raise RuntimeError(
            f"{api_path}: retired compatibility alias for the authoritative state bound remains"
        )

    torii_gov_path = "crates/iroha_torii/src/gov.rs"
    torii_gov = read(torii_gov_path)
    attempt_read = section(
        torii_gov,
        "pub async fn handle_gov_parliament_attempt_read(",
        "/// GET `/v1/gov/parliament/ballots/{ballot_attempt_id}/release-context`",
        torii_gov_path,
    )
    require_all(
        torii_gov_path,
        attempt_read,
        (
            "norito::core::to_bytes_bounded(",
            "MAX_PARLIAMENT_ATTEMPT_STATE_BYTES_V1",
        ),
    )

    state_path = "crates/iroha_core/src/state.rs"
    state = read(state_path)
    require_all(
        state_path,
        state,
        (
            "due_parliament_certificates",
            "let mut enactment = sb.try_transaction()?;",
            "execute_due_parliament_certificate_v1(",
            "DueParliamentCertificateExecutionV1::EffectFailed",
            "drop(enactment);",
            "let mut failure = sb.try_transaction()?;",
            "record_due_parliament_execution_failure_v1(",
            "failure.apply();",
            "crate::telemetry::parliament_lifecycle_metric_projection(event)",
            "validate_parliament_randomness_redraw_lineage_v1(",
            "canonical_governance_attempt_ids_v1(",
            "for (expected_sequence, persisted_id) in",
            "if persisted_id == id",
            "history.push(&attempt)",
            "let Some(persisted) = self.parliament_attempts.get(&persisted_id) else",
            "if expected_sequence > attempt.attempt().sequence",
            "history.push(persisted)",
            "pub(crate) global_beacon_pulse_slots: Storage<(BeaconSessionId, u64), [u8; 32]>",
        ),
    )
    require_parliament_event_capture(state)
    require_parliament_commit_publication(state)
    parliament_startup = section(
        state,
        "    fn new_inner(",
        "    pub(crate) fn install_active_lane_markers_for_tests(",
        state_path,
    )
    require_all(
        state_path,
        parliament_startup,
        (
            "s.rebuild_derived_state_indexes()",
            "let (status_counts, stage_counts) = s",
            ".parliament_attempt_counts",
            ".telemetry_counts();",
            "telemetry_seed.set_parliament_attempt_counts(status_counts, stage_counts);",
        ),
    )
    startup_gauge_order = tuple(
        parliament_startup.find(token)
        for token in (
            "s.rebuild_derived_state_indexes()",
            "let (status_counts, stage_counts) = s",
            ".parliament_attempt_counts",
            ".telemetry_counts();",
            "telemetry_seed.set_parliament_attempt_counts(status_counts, stage_counts);",
        )
    )
    if tuple(sorted(startup_gauge_order)) != startup_gauge_order:
        raise RuntimeError(
            f"{state_path}: startup must rebuild Parliament derived indexes before "
            "publishing exact status/stage gauges"
        )
    for retired_full_scan in (
        "events.push(projection);",
        "seed_parliament_attempts(",
    ):
        if retired_full_scan in state:
            raise RuntimeError(
                f"{state_path}: retired Parliament telemetry full-scan/immediate-publication "
                f"path remains: {retired_full_scan!r}"
            )
    finalized_pulse_slot_rebuild = section(
        state,
        "pub(crate) fn rebuild_global_beacon_pulse_slots(&mut self) -> Result<(), String>",
        "fn rebuild_confidential_policy_transition_index",
        state_path,
    )
    require_all(
        state_path,
        finalized_pulse_slot_rebuild,
        (
            "BeaconSessionId::for_network_v1(&pulse.network_id)",
            "let slot =",
            "rebuilt.insert(slot, *stored_pulse_id)",
            '"global beacon pulses {} and {} claim the same logical-beacon-height slot"',
            "let current = {",
            "pulse_slot_index(pulses.iter())?",
            "let previous = {",
            "self.global_beacon_pulses.block_and_revert()",
            "self.global_beacon_pulse_slots = rebuild_derived_storage_with_previous(current, previous)",
        ),
    )
    pulse_rebuild_order = tuple(
        finalized_pulse_slot_rebuild.find(token)
        for token in (
            "let current = {",
            "let pulses = self.global_beacon_pulses.view();",
            "pulse_slot_index(pulses.iter())?",
            "let previous = {",
            "self.global_beacon_pulses.block_and_revert()",
            "self.global_beacon_pulse_slots = rebuild_derived_storage_with_previous(current, previous)",
        )
    )
    if tuple(sorted(pulse_rebuild_order)) != pulse_rebuild_order:
        raise RuntimeError(
            f"{state_path}: finalized pulse-slot rebuild must validate current and "
            "reverted views before installing the derived storage overlay"
        )

    events_path = "crates/iroha_data_model/src/events/data/governance.rs"
    events = read(events_path)
    require_all(
        events_path,
        events,
        (
            "pub struct GovernanceParliamentLifecycleTransitionApplied",
            "pub no_result_kind: Option<ParliamentNoResultKindV1>",
            "pub automatic_outcome: Option<ParliamentAutomaticExecutionOutcomeV1>",
        ),
    )

    telemetry_path = "crates/iroha_core/src/telemetry.rs"
    telemetry = read(telemetry_path)
    require_all(
        telemetry_path,
        telemetry,
        (
            "fn parliament_transition_label(",
            "fn parliament_no_result_label(",
            "fn parliament_no_result_matches_transition(",
            "pub(crate) fn parliament_lifecycle_metric_projection(",
            "Some((payload.transition_kind, payload.no_result_kind))",
            "record_committed_parliament_transition(",
            "Transition::FailPublicFindingNoResult",
            "Transition::FailBallotNoResult",
            "Transition::FailBodyElectionNoRoster",
            'Kind::SortitionRetriesExhausted => "sortition_retries_exhausted"',
            "NoResult::SortitionRetriesExhausted => transition == Transition::FailBodyElectionNoRoster",
            '"confirmation_jury_capacity_unavailable"',
            "NoResult::ConfirmationJuryCapacityUnavailable",
            "transition == Transition::FinalizeOpenedBallot",
            "pub(crate) fn seed_parliament_attempts(",
            "governance_parliament_attempts_by_status",
            "governance_parliament_attempts_by_stage",
        ),
    )

    metrics_path = "crates/iroha_telemetry/src/metrics.rs"
    metrics = read(metrics_path)
    require_all(
        metrics_path,
        metrics,
        (
            "pub governance_parliament_transitions_total: int_counter_vec(&[\"transition\"])",
            "pub governance_parliament_no_result_total: int_counter_vec(&[\"class\"])",
            "pub governance_parliament_attempts_by_status: gauge_vec(&[\"status\"])",
            "pub governance_parliament_attempts_by_stage: gauge_vec(&[\"stage\"])",
            '"fail_public_finding_no_result"',
            '"public_finding_quorum_unreachable"',
            '"public_finding_deadline_expired"',
            '"ballot_opening_deadline_expired"',
            '"sortition_retries_exhausted"',
            '"confirmation_jury_capacity_unavailable"',
            "fn confirmation_capacity_no_result_metric_is_pre_registered()",
        ),
    )
    commitment_precheck = section(
        reducer,
        "pub(crate) fn precheck_freeze_timed_ovn_corpus(",
        "fn precheck_ballot_checkpoint(",
        reducer_path,
    )
    require_all(
        reducer_path,
        commitment_precheck,
        (
            "timed_commitment_height_is_in_window(ballot, current_height)",
            "ballot.survivors_frozen_at_height == Some(ballot.survivor_freeze_height)",
        ),
    )
    ballot_failure_classifier = section(
        reducer,
        "fn classify_ballot_failure(",
        "fn ballot_failure_matches_state(",
        reducer_path,
    )
    require_all(
        reducer_path,
        ballot_failure_classifier,
        (
            "BallotAttemptStatusV1::TimedCommitment",
            "current_height > ballot.commitment_close_height",
            "ParliamentBallotFailureKindV1::CommitmentDeadlineExpired",
        ),
    )

    defaults_path = "crates/iroha_config/src/parameters/defaults.rs"
    defaults = read(defaults_path)
    require_all(
        defaults_path,
        defaults,
        (
            "pub const PARLIAMENT_SORTITION_PULSE_DELAY_BLOCKS: u64 = 4",
            "pub const PARLIAMENT_PUBLIC_FINDING_PHASE_BLOCKS: u64 = 3_600",
            "pub const SURVIVOR_FREEZE_PHASE_BLOCKS: u64 = 1_000",
            "pub const OPENING_PHASE_BLOCKS: u64 = 600",
        ),
    )
    actual_config_path = "crates/iroha_config/src/parameters/actual.rs"
    actual_config = read(actual_config_path)
    require_all(
        actual_config_path,
        actual_config,
        (
            "pub parliament_sortition_pulse_delay_blocks: u64",
            '"governance.parliament_sortition_pulse_delay_blocks"',
            "pub parliament_public_finding_phase_blocks: u64",
            '"governance.parliament_public_finding_phase_blocks"',
            "pub opening_phase_blocks: u64",
            ".checked_add(self.opening_phase_blocks)",
            '("opening_phase_blocks", self.opening_phase_blocks)',
            '"governance.parliament_timed_ovn.opening_phase_blocks"',
            "parliament_timed_ovn_required_chunk_blocks_v1(",
            "self.registration_phase_blocks >= required_registration_blocks",
            "self.survivor_freeze_phase_blocks >= required_single_record_blocks",
            "self.commitment_phase_blocks >= required_chunk_blocks",
        ),
    )
    user_config_path = "crates/iroha_config/src/parameters/user.rs"
    user_config = read(user_config_path)
    require_all(
        user_config_path,
        user_config,
        (
            "pub parliament_sortition_pulse_delay_blocks: u64",
            "PARLIAMENT_SORTITION_PULSE_DELAY_BLOCKS",
            "parliament_sortition_pulse_delay_blocks: self",
            '"parliament_sortition_pulse_delay_blocks must be non-zero"',
            "pub parliament_public_finding_phase_blocks: u64",
            "PARLIAMENT_PUBLIC_FINDING_PHASE_BLOCKS",
            "parliament_public_finding_phase_blocks: self",
            '"parliament_public_finding_phase_blocks must be non-zero"',
            "pub opening_phase_blocks: u64",
            "OPENING_PHASE_BLOCKS",
            "opening_phase_blocks: self.opening_phase_blocks",
        ),
    )

    timed_path = "crates/iroha_crypto/src/timed_ovn.rs"
    timed = read(timed_path)
    require_all(
        timed_path,
        timed,
        (
            "no plaintext, manual-opening, or\n//! post-freeze recovery API",
            "validate_timed_ovn_official_release_audit_manifest_bytes_v1",
        ),
    )

    threshold_path = "crates/iroha_crypto/src/threshold_bls.rs"
    threshold = read(threshold_path)
    require_all(
        threshold_path,
        threshold,
        (
            "V1 fixes `n = 3f + 1`, signing threshold `f + 1`",
            "It implements no proactive/mobile-adversary refresh",
            "representation proof on every\n//! partial is mandatory",
            "scalar_bytes: Zeroizing<[[u8; 32]; 3]>",
        ),
    )

    evidence_path = "crates/iroha_core_timed_ovn/src/evidence.rs"
    evidence = read(evidence_path)
    require_all(
        evidence_path,
        evidence,
        (
            "Replayable, public-only evidence",
            "no secret fields, private-share codec, individual opening",
            "aggregate-only tally operation",
            "fn verify_final_release_pregate(",
            "CorpusOpen(TimedOvnCorpusOpenStateV1)",
            "fn is_bounded_ballot_prefix_extension(",
            "pub fn validate_committed_cache(",
        ),
    )
    corpus_open_impl = section(
        evidence,
        "impl TimedOvnCorpusOpenStateV1 {",
        "/// Public-only persisted evidence for a complete sealed timed-OVN ballot corpus.",
        evidence_path,
    )
    require_all(
        evidence_path,
        corpus_open_impl,
        (
            "fn validate_committed_cache(",
            "self.frozen.verification_common(tle_key_session)",
            "self.accumulator.validate_shape()",
        ),
    )
    if "self.frozen.validate_committed_cache" in corpus_open_impl:
        raise RuntimeError(
            f"{evidence_path}: a corpus append must not rederive the predecessor's frozen cache"
        )
    lifecycle_finalize = section(
        evidence,
        "/// Verify the unique threshold release and persist the aggregate-only tally.",
        "/// Replay and validate all public evidence required by the current phase.",
        evidence_path,
    )
    require_all(
        evidence_path,
        lifecycle_finalize,
        ("sealed.finalize_release_committed_cache(",),
    )
    cached_finalize = section(
        evidence,
        "fn finalize_release_committed_cache(",
        "/// Public tally derived only after a valid threshold release opens the aggregate.",
        evidence_path,
    )
    require_all(
        evidence_path,
        cached_finalize,
        ("self.verify_final_release_pregate(", "self.validate_committed_cache("),
    )
    if cached_finalize.find("verify_final_release_pregate") > cached_finalize.find(
        "validate_committed_cache"
    ):
        raise RuntimeError(
            f"{evidence_path}: fixed-size final-release verification must precede committed-cache validation"
        )

    restore_path = "crates/iroha_core/src/state/deserialize_world.rs"
    restore = read(restore_path)
    require_all(
        restore_path,
        restore,
        (
            "TimedOvnLifecycleStateV1::CorpusOpen(_)",
            ".validated_parliament_reducer_binding(key_session)",
            "timed_ovn_reducer_binding_matches(ballot_attempt_id, &lifecycle_binding)",
            "FailureKind::ConfirmationJuryCapacityUnavailable",
            "FailureKind::RandomnessRedrawBudgetExhausted",
            "phase == PersistedTimedOvnPhaseV1::Released",
            "post-opening NoResult must retain its released timed-OVN evidence",
            "let tle_key_session_rosters = world.tle_key_session_rosters.view();",
            "validate_tle_key_session_roster_binding_v1(public_state, ordered_roster)",
            '"TLE key session {key_session_id} is missing its frozen ordered roster"',
            '"frozen ordered roster references missing TLE key session {key_session_id}"',
            "proposal_attempts.sort_unstable_by_key(|attempt| attempt.attempt().sequence)",
            "validate_parliament_randomness_redraw_lineage_v1(",
            '"governance Parliament randomness-redraw lineage is invalid: {error}"',
            "let unavailable_beacon_pulse_slots = world",
            ".flat_map(|(_, attempt)| attempt.unavailable_beacon_pulse_slots_v1())",
            ".collect::<BTreeSet<_>>()",
            "unavailable_beacon_pulse_slots.contains(&(logical_session, pulse.height))",
            '"finalized pulse conflicts with a Parliament slot terminally classified as unavailable"',
        ),
    )
    restore_size_validation = section(
        restore,
        "fn validate_parliament_attempt_encoded_size_bounds_v1(",
        "#[cfg(test)]\nmod timed_ovn_persistence_phase_tests",
        restore_path,
    )
    require_all(
        restore_path,
        restore_size_validation,
        (".validate_encoded_size_v1()", 'field: "parliament_attempts".into()'),
    )
    restore_attempt_prefix = section(
        restore,
        "world\n        .rebuild_global_beacon_pulse_slots()",
        "fn build_state(",
        restore_path,
    )
    require_all(
        restore_path,
        restore_attempt_prefix,
        ("validate_parliament_attempt_encoded_size_bounds_v1(&world)?;",),
    )
    grouped_restore_validation = section(
        restore,
        "let parliament_attempts_view = world.parliament_attempts.view();",
        "validate_tle_ovn_persistence(&world)?;",
        restore_path,
    )
    require_all(
        restore_path,
        grouped_restore_validation,
        (
            "let mut parliament_attempts_by_proposal = BTreeMap::<",
            "for (attempt_id, attempt) in parliament_attempts_view.iter()",
            "parliament_attempts_by_proposal",
            ".entry(attempt.proposal_content_id())",
            ".or_default()",
            ".push(attempt)",
        ),
    )
    grouped_restore_lineage = section(
        restore,
        "for (proposal_id, proposal) in governance_proposals_view.iter()",
        "crate::validation_fee::validate_persisted_policy_registry_governance_v1",
        restore_path,
    )
    require_all(
        restore_path,
        grouped_restore_lineage,
        (
            "let mut proposal_attempts = parliament_attempts_by_proposal",
            ".get(&proposal_content_id)",
            ".cloned()",
            ".unwrap_or_default()",
            "proposal_attempts.sort_unstable_by_key(|attempt| attempt.attempt().sequence)",
            "validate_parliament_randomness_redraw_lineage_v1(",
        ),
    )
    restored_reservations = section(
        restore,
        "    let mut active_resource_reservations = Vec::new();",
        "    let concurrent_casting_contexts = timed_ovn_evidence",
        restore_path,
    )
    require_all(
        restore_path,
        restored_reservations,
        (
            "for (governance_attempt_id, governance_attempt) in parliament_attempts.iter()",
            "for left_index in 0..active_resource_reservations.len()",
            "for right_index in left_index + 1..active_resource_reservations.len()",
            "parliament_timed_ovn_resource_windows_overlap_v1(left_windows, right_windows)",
            '"active timed-OVN resource reservations overlap',
        ),
    )
    restored_capacity = section(
        restore,
        "    let concurrent_casting_contexts = timed_ovn_evidence",
        "    for (governance_attempt_id, governance_attempt) in parliament_attempts.iter()",
        restore_path,
    )
    require_all(
        restore_path,
        restored_capacity,
        (
            "MAX_PARLIAMENT_CONCURRENT_CASTING_CONTEXTS_V1",
            "if concurrent_casting_contexts > maximum_casting_contexts",
            '"concurrent cast-capable timed-OVN contexts exceed the protocol maximum"',
        ),
    )

    state_path = "crates/iroha_core/src/state.rs"
    state = read(state_path)
    tle_roster_binding = section(
        state,
        "pub(crate) fn validate_tle_key_session_roster_binding_v1(",
        "/// Closed failures for the committed Parliament TLE key-session lifecycle.",
        state_path,
    )
    require_all(
        state_path,
        tle_roster_binding,
        (
            "let unique_peers = ordered_roster.iter().collect::<BTreeSet<_>>()",
            "ordered_roster.is_empty()",
            "unique_peers.len() != ordered_roster.len()",
            "usize::from(public_state.committee_size) != ordered_roster.len()",
            "global_threshold_beacon_roster_hash_v1(ordered_roster)",
            "fn validate_tle_key_session_lifecycle_head_v1(",
            "ordered_lifecycles.split_last()",
            "!lifecycle.selection_is_closed()",
            "active_key_session_id == latest.key_session_id",
            'Err("the open latest lifecycle head lacks its exact active TLE pointer")',
            'Err("a closed latest lifecycle head still has an active TLE pointer")',
        ),
    )
    restored_tle_head = section(
        restore,
        "    let mut lifecycle_rows = tle_key_session_lifecycles.iter().collect::<Vec<_>>();",
        "    for (ballot_attempt_id, lifecycle) in timed_ovn_evidence.iter()",
        restore_path,
    )
    require_all(
        restore_path,
        restored_tle_head,
        (
            "lifecycle_rows.sort_by",
            "active_tle_sessions.iter()",
            "*key != TLE_KEY_SESSION_SINGLETON_KEY",
            "active_key_session_id.replace(*key_session_id)",
            "validate_tle_key_session_lifecycle_head_v1(&ordered_lifecycles, active_key_session_id)",
        ),
    )
    checked_reservation_insert = section(
        state,
        "fn insert_parliament_timed_ovn_resource_reservation_v1(",
        "fn parliament_timed_ovn_reservation_reducer_error_v1(",
        state_path,
    )
    require_all(
        state_path,
        checked_reservation_insert,
        (
            "reservations.contains_key(&ballot_attempt_id)",
            "parliament_timed_ovn_resource_windows_overlap_v1(",
            "parliament_timed_ovn_casting_capacity_allows_new_v1(",
            "reservations.insert(ballot_attempt_id, reservation)",
        ),
    )
    insert_guards = (
        checked_reservation_insert.find("reservations.contains_key(&ballot_attempt_id)"),
        checked_reservation_insert.find("parliament_timed_ovn_resource_windows_overlap_v1("),
        checked_reservation_insert.find("parliament_timed_ovn_casting_capacity_allows_new_v1("),
        checked_reservation_insert.find("reservations.insert(ballot_attempt_id, reservation)"),
    )
    if tuple(sorted(insert_guards)) != insert_guards:
        raise RuntimeError(
            f"{state_path}: reservation duplicate/overlap/capacity guards must precede insertion"
        )
    attempt_admission = section(
        state,
        "    pub(crate) fn put_parliament_attempt(",
        "    /// Validate and persist one immutable public-only adaptive TLE key session.",
        state_path,
    )
    require_all(
        state_path,
        attempt_admission,
        (
            "attempt.validate()?",
            "canonical_governance_attempt_ids_v1(",
            "for (expected_sequence, persisted_id) in",
            "if persisted_id == id",
            "history.push(&attempt)",
            "let Some(persisted) = self.parliament_attempts.get(&persisted_id) else",
            "if expected_sequence > attempt.attempt().sequence",
            "history.push(persisted)",
            "let mut next_reservations = BTreeMap::new()",
            "insert_parliament_timed_ovn_resource_reservation_v1(",
            "for ballot_attempt_id in stale_reservations",
            "let stale_casting_candidates = self",
            ".parliament_timed_ovn_casting_candidates",
            "let active_casting_candidates = attempt",
            "parliament_timed_ovn_casting_candidate_v1(id, &attempt, *ballot_attempt_id)",
            "for ballot_attempt_id in stale_casting_candidates",
            "for (ballot_attempt_id, candidate) in active_casting_candidates",
            "let previous_enactment_height =",
            "ParliamentAttemptStateV1::certified_enactment_height_v1",
            "let next_enactment_height = attempt.certified_enactment_height_v1()",
            "self.parliament_certified_enactments",
            "let previous_required_slots =",
            "let next_required_slots = attempt.required_beacon_pulse_slots_v1()",
            "previous_required_slots.difference(&next_required_slots)",
            "self.parliament_required_beacon_pulse_slots",
            "let previous_unavailable_slots =",
            "let next_unavailable_slots = attempt.unavailable_beacon_pulse_slots_v1()",
            "self.global_beacon_pulse_slots.get(slot).is_some()",
            "return Err(ParliamentReducerErrorV1::BeaconPulseAlreadyAvailable)",
            "previous_unavailable_slots.difference(&next_unavailable_slots)",
            "self.parliament_unavailable_beacon_pulse_slots",
            "let previous_tle_retention_contributions =",
            ".map(ParliamentAttemptStateV1::tle_key_session_retention_contributions_v1)",
            "let next_tle_retention_contributions =",
            "attempt.tle_key_session_retention_contributions_v1()",
            "self.remove_parliament_tle_retention_contribution(",
            "self.parliament_attempts.insert(id, attempt)",
            "self.insert_parliament_tle_retention_contribution(",
        ),
    )
    if attempt_admission.find("insert_parliament_timed_ovn_resource_reservation_v1(") > attempt_admission.find(
        "for ballot_attempt_id in stale_reservations"
    ):
        raise RuntimeError(
            f"{state_path}: attempt admission mutates the live reservation index before validation"
        )
    if attempt_admission.find("self.global_beacon_pulse_slots.get(slot).is_some()") > attempt_admission.find(
        "for ballot_attempt_id in stale_reservations"
    ):
        raise RuntimeError(
            f"{state_path}: finalized-pulse contradiction must reject before live index mutation"
        )
    if attempt_admission.find("self.remove_parliament_tle_retention_contribution(") > attempt_admission.find(
        "self.parliament_attempts.insert(id, attempt)"
    ):
        raise RuntimeError(
            f"{state_path}: stale TLE retention contributors must be removed before attempt replacement"
        )
    if attempt_admission.find("self.insert_parliament_tle_retention_contribution(") < attempt_admission.find(
        "self.parliament_attempts.insert(id, attempt)"
    ):
        raise RuntimeError(
            f"{state_path}: replacement TLE retention contributors must follow authoritative attempt replacement"
        )
    late_pulse_admission = section(
        state,
        "    pub(crate) fn verify_and_advance_global_beacon_pulse(",
        "    /// Test helper: seed governance proposals while retaining the exact typed index.",
        state_path,
    )
    require_all(
        state_path,
        late_pulse_admission,
        (
            "BeaconSessionId::for_network_v1(&pulse.network_id)",
            ".parliament_unavailable_beacon_pulse_slots",
            ".get(&(logical_beacon_session_id, pulse.height))",
            "return Err(GlobalThresholdBeaconError::PersistenceConflict)",
        ),
    )
    attempt_removal = section(
        state,
        "    pub fn remove_parliament_attempt_for_testing(",
        "    /// Test helper: index a manually seeded confidential-policy transition.",
        state_path,
    )
    require_all(
        state_path,
        attempt_removal,
        (
            "removed.certified_enactment_height_v1()",
            ".parliament_certified_enactments",
            "ParliamentAttemptStateV1::required_beacon_pulse_slots_v1",
            ".parliament_required_beacon_pulse_slots",
            "ParliamentAttemptStateV1::unavailable_beacon_pulse_slots_v1",
            ".parliament_unavailable_beacon_pulse_slots",
            ".parliament_timed_ovn_casting_candidates",
            "candidate.governance_attempt_id == *id",
            "removed.tle_key_session_retention_contributions_v1()",
            "self.remove_parliament_tle_retention_contribution(",
            "attempts.remove(id)",
            "let member_reference_updates =\n            parliament_member_reference_count_updates_v1(",
            "self.parliament_attempts\n            .remove(*id)",
            "self.apply_parliament_member_reference_count_updates(member_reference_updates)",
        ),
    )
    reference_preflight = attempt_removal.find(
        "let member_reference_updates =\n            parliament_member_reference_count_updates_v1("
    )
    authoritative_removal = attempt_removal.find(
        "self.parliament_attempts\n            .remove(*id)"
    )
    reference_apply = attempt_removal.find(
        "self.apply_parliament_member_reference_count_updates(member_reference_updates)"
    )
    if not reference_preflight < authoritative_removal < reference_apply:
        raise RuntimeError(
            f"{state_path}: Parliament member-reference updates must preflight before "
            "authoritative attempt removal and apply afterward"
        )
    state_tests_path = "crates/iroha_core/src/state/tests.rs"
    state_tests = read(state_tests_path)
    certified_enactment_regressions = section(
        state_tests,
        "fn parliament_certified_enactment_index_tracks_rebuild_transition_and_removal()",
        "fn parliament_required_beacon_slot_index_tracks_lifecycle_and_removal()",
        state_tests_path,
    )
    require_all(
        state_tests_path,
        certified_enactment_regressions,
        (
            "certified_parliament_attempt_for_testing(",
            ".parliament_certified_enactments",
            'expect("idempotent replacement retains one index member")',
            'expect("terminal replacement removes the due index member")',
            ".remove_parliament_attempt_for_testing(&governance_attempt_id)",
        ),
    )
    pulse_slot_regressions = section(
        state_tests,
        "fn parliament_required_beacon_slot_index_tracks_lifecycle_and_removal()",
        "fn governance_lock_index_rebuild_rejects_invalid_authoritative_records_fail_atomically()",
        state_tests_path,
    )
    require_all(
        state_tests_path,
        pulse_slot_regressions,
        (
            ".parliament_required_beacon_pulse_slots",
            'expect("replace the live request with its terminal transcript")',
            "fn parliament_attempt_rejects_unavailable_slot_after_pulse_finalization_atomically()",
            "Err(ParliamentReducerErrorV1::BeaconPulseAlreadyAvailable)",
            '"rejection must not publish a partial unavailable-slot index"',
            "fn parliament_unavailable_slot_rebuild_rejects_finalized_pulse_fail_atomically()",
            'expect_err("a finalized pulse cannot also be terminally unavailable")',
            'error.contains("classifies finalized logical beacon slot")',
            '"a failed rebuild must retain the previously published derived index"',
        ),
    )
    finalized_pulse_slot_regressions = section(
        state_tests,
        "fn global_beacon_pulse_slot_index_is_snapshot_skipped_rebuilt_and_unique()",
        "fn global_beacon_fixture_installs_the_logical_slot_index()",
        state_tests_path,
    )
    require_all(
        state_tests_path,
        finalized_pulse_slot_regressions,
        (
            "BeaconSessionId::for_network_v1(&pulse.network_id)",
            'assert!(!encoded.contains("global_beacon_pulse_slots"))',
            ".rebuild_global_beacon_pulse_slots()",
            ".global_beacon_pulse_at_slot(&pulse.network_id, pulse.height)",
            '"restore must reject two pulse records claiming one logical-beacon-height slot"',
        ),
    )
    tle_retention_regressions = section(
        state_tests,
        "fn tle_runtime_custody_projection_is_inclusive_and_retains_unbounded_history()",
        "fn parliament_timed_ovn_resource_index_tracks_only_the_active_retry()",
        state_tests_path,
    )
    require_all(
        state_tests_path,
        tle_retention_regressions,
        (
            ".rebuild_governance_read_indexes()",
            ".tle_key_sessions_required_for_runtime_custody_v1(62)",
            ".tle_key_sessions_required_for_runtime_custody_v1(63)",
            ".tle_key_sessions_required_for_runtime_custody_v1(u64::MAX)",
            '"the greatest opening deadline is inclusive"',
            '"retained historical custody does not depend on an active session"',
            '"u64::MAX custody remains required even at the maximum committed height"',
            '"terminal-height custody fails closed for the still-selectable session"',
        ),
    )
    tle_selection_index_regression = section(
        state_tests,
        "fn tle_selection_interval_index_resolves_only_the_latest_predecessor()",
        "fn parliament_tle_retention_rebuild_preserves_the_next_maximum()",
        state_tests_path,
    )
    require_all(
        state_tests_path,
        tle_selection_index_regression,
        (
            ".rebuild_governance_read_indexes()",
            ".selectable_tle_key_session_for_fresh_ballot_at(19)",
            ".selectable_tle_key_session_for_fresh_ballot_at(20)",
            ".selectable_tle_key_session_for_fresh_ballot_at(30)",
            '"an expired latest predecessor must not expose older history"',
            "fn tle_lifecycle_head_rebuild_requires_an_exact_reconstructible_pointer()",
            'expect_err("a non-latest lifecycle cannot remain open")',
            'expect_err("an open latest head requires its exact active pointer")',
            'expect_err("a closed latest head cannot retain an active pointer")',
            '"a rejected head must not partially publish rebuilt intervals"',
        ),
    )
    casting_candidate_index_regressions = section(
        state_tests,
        "fn parliament_timed_ovn_casting_candidate_index_tracks_exact_phase_windows()",
        "fn parliament_timed_ovn_resource_index_tracks_only_the_active_retry()",
        state_tests_path,
    )
    require_all(
        state_tests_path,
        casting_candidate_index_regressions,
        (
            ".parliament_timed_ovn_casting_candidates",
            "valid_from_height: 27",
            "valid_until_height_exclusive: 31",
            "valid_from_height: 31",
            "valid_until_height_exclusive: 34",
            "valid_from_height: 34",
            "valid_until_height_exclusive: 36",
            'expect("terminal ballot replacement removes the casting candidate")',
            "fn parliament_casting_snapshot_filters_candidate_window_before_evidence_lookup()",
            "for outside_height in [26, 31]",
            'expect("out-of-window candidates require no point lookups")',
            "TimedOvnCastingAuthorizationErrorV1::MissingTimedOvnEvidence",
        ),
    )
    derived_index_snapshot_regression = section(
        state_tests,
        "fn parliament_derived_indexes_are_snapshot_skipped_and_rebuilt()",
        "fn world_block_snapshot_schema_matches_committed_world()",
        state_tests_path,
    )
    require_all(
        state_tests_path,
        derived_index_snapshot_regression,
        (
            ".parliament_tle_key_session_retention_deadlines",
            'assert!(!encoded.contains("parliament_tle_key_session_retention_deadlines"))',
            ".parliament_timed_ovn_casting_candidates",
            'assert!(!encoded.contains("parliament_timed_ovn_casting_candidates"))',
            ".tle_key_session_selection_intervals",
            'assert!(!encoded.contains("tle_key_session_selection_intervals"))',
            ".rebuild_governance_read_indexes()",
            'expect("empty authoritative attempts rebuild an empty reservation index")',
        ),
    )
    derived_index_merge_regression = section(
        state_tests,
        "fn parliament_derived_index_changes_are_bound_into_merge_write_sets()",
        "fn world_block_snapshot_schema_matches_committed_world()",
        state_tests_path,
    )
    require_all(
        state_tests_path,
        derived_index_merge_regression,
        (
            ".parliament_timed_ovn_resource_reservations",
            ".parliament_timed_ovn_casting_candidates",
            ".merge_execution_write_set_bytes()",
            'b"parliament_timed_ovn_resource_reservations"',
            'b"parliament_timed_ovn_casting_candidates"',
            '"merge certification must bind changes to derived Parliament indexes"',
        ),
    )
    require_all(
        state_path,
        state,
        (
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode)]\nstruct ParliamentTimedOvnResourceReservationV1",
            "#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode)]\npub(crate) struct ParliamentTimedOvnCastingCandidateV1",
            "fn parliament_timed_ovn_casting_candidate_v1(",
            "BallotAttemptStatusV1::Registration => (",
            "BallotAttemptStatusV1::SurvivorFreeze => (",
            "BallotAttemptStatusV1::TimedCommitment => (",
        ),
    )
    tle_session_admission = section(
        state,
        "    pub(crate) fn put_tle_key_session(",
        "    /// Schedule one committed public TLE key session for next-height activation.",
        state_path,
    )
    require_all(
        state_path,
        tle_session_admission,
        (
            "ordered_roster: Vec<PeerId>",
            "validate_tle_key_session_roster_binding_v1(&state, &ordered_roster)?",
            "self.tle_key_sessions.get(&key_session_id)",
            "self.tle_key_session_rosters.get(&key_session_id)",
            "(None, None)",
            "self.tle_key_sessions.insert(key_session_id, state)",
            ".insert(key_session_id, ordered_roster)",
            "_ => Err(TleReleaseAdapterError::TranscriptMismatch)",
        ),
    )
    tle_session_activation = section(
        state,
        "    pub(crate) fn activate_tle_key_session(",
        "    /// Schedule the active TLE key session to stop admitting ballots after this height.",
        state_path,
    )
    require_all(
        state_path,
        tle_session_activation,
        (
            "let latest_predecessor = self",
            "if let Some((previous_activation_height, (selectable_through_height, key_session_id))) =",
            "previous.activation_height != previous_activation_height",
            "previous.selectable_through_height != selectable_through_height",
            "!previous.selection_is_closed()",
        ),
    )
    required_tle_custody = section(
        state,
        "    fn tle_key_sessions_required_for_runtime_custody_v1(",
        "    /// Return the single ABI version accepted by the first release runtime.",
        state_path,
    )
    require_all(
        state_path,
        required_tle_custody,
        (
            "let next_height = committed_height.checked_add(1).unwrap_or(committed_height);",
            "self.selectable_tle_key_session_for_fresh_ballot_at(next_height)",
            "self.parliament_tle_key_session_retention_deadlines()",
            ".keys()",
            ".next_back()",
            ".is_some_and(|deadline| committed_height <= *deadline)",
        ),
    )
    selectable_tle_session = section(
        state,
        "    fn selectable_tle_key_session_for_fresh_ballot_at(",
        "    /// Return whether `key_session_id` is eligible for a fresh ballot at `height`.",
        state_path,
    )
    require_all(
        state_path,
        selectable_tle_session,
        (
            ".tle_key_session_selection_intervals()",
            ".range(..=height)",
            ".next_back()?",
            "self.tle_key_session_lifecycles().get(key_session_id)?",
            "lifecycle.activation_height == *activation_height",
            "lifecycle.selectable_through_height == *selectable_through_height",
            "lifecycle.permits_fresh_ballot_at(height)",
        ),
    )
    if "tle_key_session_lifecycles().iter()" in selectable_tle_session:
        raise RuntimeError(
            f"{state_path}: fresh-ballot TLE selection regressed to a full lifecycle scan"
        )
    tle_selection_intervals = section(
        state,
        "fn tle_key_session_selection_intervals_v1<'a>(",
        "struct ParliamentDerivedReadIndexesV1",
        state_path,
    )
    require_all(
        state_path,
        tle_selection_intervals,
        (
            "let mut intervals = BTreeMap::new()",
            "for (key_session_id, lifecycle) in lifecycles",
            "lifecycle.activation_height,",
            "lifecycle.selectable_through_height",
            "multiple TLE key-session lifecycles activate at height",
            "TLE key-session selection intervals for {previous_key_session_id} and {key_session_id} overlap",
            "for (singleton_key, key_session_id) in active_key_sessions",
            "validate_tle_key_session_lifecycle_head_v1(&ordered_lifecycles, active_key_session_id)",
            "Ok(intervals)",
        ),
    )
    parliament_derived_indexes = section(
        state,
        "fn parliament_derived_read_indexes_v1<'a>(",
        "impl World {",
        state_path,
    )
    require_all(
        state_path,
        parliament_derived_indexes,
        (
            "let mut timed_ovn_resource_reservations = BTreeMap::new()",
            "insert_parliament_timed_ovn_resource_reservation_v1(",
            "let mut timed_ovn_casting_candidates = BTreeMap::new()",
            "parliament_timed_ovn_casting_candidate_v1(",
            "let mut certified_enactments =",
            "attempt.certified_enactment_height_v1()",
            "let mut required_beacon_pulse_slots =",
            "for pulse_slot in attempt.required_beacon_pulse_slots_v1()",
            "let mut unavailable_beacon_pulse_slots =",
            "for pulse_slot in attempt.unavailable_beacon_pulse_slots_v1()",
            "let mut tle_key_session_retention_deadlines =",
            "attempt.tle_key_session_retention_contributions_v1()",
            ".entry(opening_deadline)",
            "Ok(ParliamentDerivedReadIndexesV1 {",
        ),
    )
    rebuilt_reservations = section(
        state,
        "    fn rebuild_governance_read_indexes(",
        "    /// Rebuild the unique logical-beacon height lookup",
        state_path,
    )
    require_all(
        state_path,
        rebuilt_reservations,
        (
            "-> Result<(), String>",
            "self.citizens.view().len() > maximum_citizens",
            "MAX_PARLIAMENT_CITIZENS_V1",
            "parliament_derived_read_indexes_v1(attempts.iter(), &finalized_beacon_pulse_slots)?",
            "tle_key_session_selection_intervals_v1(",
            "let reverted_attempts = self.parliament_attempts.block_and_revert()",
            "let reverted_lifecycles = self.tle_key_session_lifecycles.block_and_revert()",
            "let previous_parliament = parliament_derived_read_indexes_v1(",
            "let previous_tle_key_session_selection_intervals =",
            "let ParliamentDerivedReadIndexesV1 {",
            "self.parliament_timed_ovn_resource_reservations =",
            "self.parliament_timed_ovn_casting_candidates =",
            "self.parliament_certified_enactments =",
            "self.parliament_required_beacon_pulse_slots =",
            "self.parliament_unavailable_beacon_pulse_slots =",
            "self.parliament_tle_key_session_retention_deadlines =",
            "self.tle_key_session_selection_intervals =",
            "Ok(())",
        ),
    )
    if rebuilt_reservations.find("parliament_derived_read_indexes_v1(") > rebuilt_reservations.find(
        "self.parliament_timed_ovn_resource_reservations ="
    ):
        raise RuntimeError(
            f"{state_path}: restore publishes the reservation index before complete validation"
        )

    require_block_start_enactment_phases(state)

    mv_storage_path = "crates/mv/src/storage.rs"
    mv_storage = read(mv_storage_path)
    require_storage_borrowed_iterators(mv_storage)
    require_all(
        mv_storage_path,
        mv_storage,
        (
            "assert_eq!(view.range(..=3).next_back(), Some((&3, &1)))",
            "assert_eq!(transaction.range(..=5).next_back(), Some((&5, &3)))",
        ),
    )

    tle_release_path = "crates/iroha_core/src/tle_release.rs"
    tle_public = read("crates/iroha_core_timed_ovn/src/tle.rs")
    require_opaque_release_projection(tle_public)
    tle_release = read(tle_release_path) + "\n" + tle_public
    require_all(
        tle_release_path,
        tle_release,
        (
            "pub struct AuthorizedTleReleaseContextV1",
            "pub fn authorize_parliament_tle_release_v1(",
            "BallotAttemptStatusV1::Opening",
            "finalized_height > opening_deadline_height",
            "pub trait TlePartialReleaseSignerV1: Send + Sync",
            "fn attest_partial_release_capability(",
            "expected_participant_index: u16,\n    ) -> Result<TlePartialReleaseCapabilityAttestationV1, TlePartialReleaseCapabilityErrorV1>;",
            "pub struct TlePartialReleaseCapabilityAttestationV1",
            "pub enum TlePartialReleaseCapabilityErrorV1",
            "impl TlePartialReleaseSignerV1 for InMemoryTlePartialReleaseSignerV1",
            "expected_participant_index != self.share.index()",
            "TlePartialReleaseCapabilityAttestationV1::for_validated_session(",
            "context: &AuthorizedTleReleaseContextV1",
            "pub struct AuthorizedTleReleaseProjectionV1",
            "pub struct ValidatedTleReleaseProjectionV1",
            "pub trait TleProjectedPartialReleaseSignerV1: Send + Sync",
            "projection: &ValidatedTleReleaseProjectionV1",
            "pub fn broker_projection_v1(",
            "pub const TLE_AUTHORIZED_RELEASE_IDENTITY_PAYLOAD_BYTES_V1: usize = 243",
            "pub identity_payload: [u8; TLE_AUTHORIZED_RELEASE_IDENTITY_PAYLOAD_BYTES_V1]",
            "let session = self.key_session.clone().validate()?;",
            ".validate_release_identity(&identity, self.finalized_height)?",
            "impl TleProjectedPartialReleaseSignerV1 for InMemoryTlePartialReleaseSignerV1",
            "pub struct InMemoryTlePartialReleaseSignerV1",
            "pub use custody::{RuntimeTleReleaseShareCustodyV1",
        ),
    )
    require_opaque_release_authorizations(tle_release)

    release_runtime_path = "crates/iroha_core/src/tle_release/runtime.rs"
    release_runtime = read(release_runtime_path)
    require_all(
        release_runtime_path,
        release_runtime,
        (
            "authorize_parliament_tle_release_v1(state, ballot_attempt_id)?",
            ".sign_partial_release(context)",
            ".verify_partial_release(context.identity(), context.finalized_height(), &partial)",
            "canonical.sort_by_key(|partial| partial.participant_index)",
            ".combine_partial_releases(context.identity(), context.finalized_height(), &canonical)",
            ".verify_final_release(",
            "ParliamentLifecycleTransitionV1::FinalizeOpenedBallot(",
        ),
    )

    custody_path = "crates/iroha_core/src/tle_release/custody.rs"
    custody = read(custody_path)
    require_all(
        custody_path,
        custody,
        (
            "pub struct RuntimeTleReleaseShareCustodyV1",
            "RwLock<BTreeMap<TleKeySessionId, InMemoryTlePartialReleaseSignerV1>>",
            "pub fn insert_validated_share(",
            "pub fn import_components(",
            "pub fn import_committed_components(",
            ".tle_key_sessions()",
            "pub fn retire_session(",
            "let next_height = committed_height.checked_add(1).unwrap_or(committed_height);",
            ".tle_key_session_eligible_for_new_ballots(key_session_id, next_height)",
            ".tle_key_session_retention_deadline_v1(key_session_id)",
            "deadline == u64::MAX || committed_height <= deadline",
            ".remove(&key_session_id)",
            "drop(retired);",
            ".get(&context.session().public_state().key_session_id)",
            "fn attest_partial_release_capability(",
            ".get(&session.public_state().key_session_id)",
            "signer.attest_partial_release_capability(session, expected_participant_index)",
            "impl TleProjectedPartialReleaseSignerV1 for RuntimeTleReleaseShareCustodyV1",
            ".get(&projection.session().public_state().key_session_id)",
            "signer.sign_projected_partial_release(projection)",
        ),
    )
    retirement = section(
        custody,
        "pub fn retire_session(",
        "impl Default for RuntimeTleReleaseShareCustodyV1",
        custody_path,
    )
    if retirement.find("tle_key_session_eligible_for_new_ballots") > retirement.find(
        ".tle_key_session_retention_deadline_v1(key_session_id)"
    ):
        raise RuntimeError(
            f"{custody_path}: active-session retirement guard must precede retention-index lookup"
        )
    custody_type = section(
        custody,
        "pub struct RuntimeTleReleaseShareCustodyV1 {",
        "impl RuntimeTleReleaseShareCustodyV1 {",
        custody_path,
    )
    for forbidden in ("derive(", "pub sessions", "Vec<TleKeySessionId>"):
        if forbidden in custody_type:
            raise RuntimeError(
                f"{custody_path}: runtime custody exposes forbidden inventory surface {forbidden!r}"
            )

    casting_path = "crates/iroha_core/src/tle_release/casting.rs"
    casting_public = read("crates/iroha_core_timed_ovn/src/casting.rs")
    casting_error_offset = casting_public.index(
        "/// Closed failures while authorizing a public timed-OVN casting context."
    )
    # Preserve declaration section boundaries across the state-free and state-authority owners.
    casting = (casting_public[:casting_error_offset] + "\n" + read(casting_path)
               + "\n" + casting_public[casting_error_offset:])
    require_all(
        casting_path,
        casting,
        (
            "pub fn authorize_parliament_timed_ovn_casting_context_v1(",
            "pub struct AuthorizedTimedOvnCastingContextV1",
            "pub struct ParliamentTimedOvnCastingContextArchiveV1",
            "pub struct ValidatedParliamentTimedOvnCastingContextArchiveV1",
            "pub enum ParliamentTimedOvnCastingPhaseV1",
            "PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_VERSION_V1: u16 = 1",
            "PARLIAMENT_TIMED_OVN_CASTING_CONTEXT_ARCHIVE_MAX_BYTES_V1: usize = 4 * 1024 * 1024",
            "norito::core::to_bytes_bounded(",
            "pub fn try_from_parts_v1(",
            "pub fn validate_v1(",
            "rebuild_casting_registration_context_v1(",
            "PreparedTimedOvnAttemptV1::from_records(",
            "lifecycle.validate(&tle_key_session)?",
            "fn validate_casting_phase_window_v1(",
            "registered_at_height < registration_close_height",
            "registration_close_height < survivor_freeze_height",
            "survivor_freeze_height < commitment_close_height",
            "commitment_close_height < release_height",
            "current_height >= registered_at_height",
            "current_height < registration_close_height",
            "current_height >= registration_close_height",
            "current_height < survivor_freeze_height",
            "current_height >= survivor_freeze_height",
            "current_height < commitment_close_height",
            "TimedOvnCastingAuthorizationErrorV1::InvalidPhaseSchedule",
            "TimedOvnCastingAuthorizationErrorV1::PhaseWindowInactive",
            "GovernanceAttemptStatusV1::Active",
            "BodyInstanceStatusV1::Balloting",
            "ParliamentDecisionModeV1::HiddenBindingBallot",
            ".active_ballot_for_body(&body_instance_id)",
            ".registration_opened_at_finalized_height()",
            "TimedOvnLifecycleStateV1::Sealed(_) | TimedOvnLifecycleStateV1::Released(_)",
        ),
    )
    casting_snapshot = section(
        casting,
        "pub(crate) fn derive_parliament_timed_ovn_casting_snapshot_v1(",
        "fn compact_binding_from_world_v1(",
        casting_path,
    )
    require_all(
        casting_path,
        casting_snapshot,
        (
            ".parliament_timed_ovn_casting_candidates()",
            "evaluated_height < candidate.valid_from_height",
            "evaluated_height >= candidate.valid_until_height_exclusive",
            ".timed_ovn_evidence()",
            "TimedOvnCastingAuthorizationErrorV1::MissingTimedOvnEvidence",
            ".ok_or(TimedOvnCastingAuthorizationErrorV1::BindingMismatch)?",
            "bindings.sort_by_key(|binding| binding.ballot_attempt_id)",
        ),
    )
    if "world.timed_ovn_evidence().iter()" in casting_snapshot:
        raise RuntimeError(
            f"{casting_path}: compact casting snapshot regressed to a full evidence scan"
        )
    if casting_snapshot.find("evaluated_height < candidate.valid_from_height") > casting_snapshot.find(
        ".timed_ovn_evidence()"
    ):
        raise RuntimeError(
            f"{casting_path}: casting-candidate height filtering must precede point lookups"
        )
    compact_casting_binding = section(
        casting,
        "fn compact_binding_from_world_v1(",
        "/// Authorize and replay-validate one public timed-OVN casting context.",
        casting_path,
    )
    require_all(
        casting_path,
        compact_casting_binding,
        (
            "candidate.governance_attempt_id != governance_attempt_id",
            "candidate.valid_from_height != expected_valid_from_height",
            "candidate.valid_until_height_exclusive != expected_valid_until_height_exclusive",
            "TimedOvnCastingAuthorizationErrorV1::BindingMismatch",
        ),
    )
    casting_authorization = section(
        casting,
        "pub fn authorize_parliament_timed_ovn_casting_context_v1(",
        "/// Closed failures while authorizing a public timed-OVN casting context.",
        casting_path,
    )
    if casting_authorization.find("validate_casting_phase_window_v1(") > casting_authorization.find(
        "lifecycle.validate(&tle_key_session)?"
    ):
        raise RuntimeError(
            f"{casting_path}: exact phase window must be checked before proof-heavy lifecycle replay"
        )
    require_opaque_casting_authorization(casting)
    casting_archive = section(
        casting,
        "/// Canonical public-only archive for restarting a timed-OVN wallet operation.",
        "/// Constructor-authenticated, replay-validated timed-OVN casting context.",
        casting_path,
    )
    casting_archive_declaration = section(
        casting,
        "/// Canonical public-only archive for restarting a timed-OVN wallet operation.",
        "impl ParliamentTimedOvnCastingContextArchiveV1 {",
        casting_path,
    )
    require_all(
        casting_path,
        casting_archive,
        (
            "NoritoSerialize",
            "NoritoDeserialize",
            "registration_records: Vec<Vec<u8>>",
            "registration_opened_at_finalized_height: u64",
            "survivor_participant_hashes: Option<Vec<[u8; 32]>>",
            "release_identity: Option<TimedOvnReleaseIdentityPublicV1>",
        ),
    )
    for forbidden in (
        "JsonSerialize",
        "JsonDeserialize",
        "ballot_records:",
        "dropout_participant_hashes:",
        "partial_release:",
        "opening_root:",
        "AccountId:",
        "registration_close_height: u64",
        "survivor_freeze_height: u64",
        "commitment_close_height: u64",
    ):
        if forbidden in casting_archive_declaration:
            raise RuntimeError(
                f"{casting_path}: casting archive exposes forbidden material {forbidden!r}"
            )

    local_release_path = "crates/iroha_torii/src/parliament_tle_release.rs"
    local_release = read(local_release_path)
    require_all(
        local_release_path,
        local_release,
        (
            "pub(crate) async fn request_local_partial_release_v1(",
            "ballot_attempt_id: String",
            "signer_admission: crate::QueryAdmissionPermit",
            "crate::panic_recovery::join_recoverable(",
            "crate::panic_recovery::spawn_blocking_recoverable(",
            "let _signer_admission = signer_admission;",
            "coordinator.request_partial_release(&view, ballot_attempt_id)",
            "TleReleaseCoordinatorErrorV1::SignerUnavailable",
            "TleReleaseCoordinatorErrorV1::InvalidSignerOutput",
        ),
    )

    torii_path = "crates/iroha_torii/src/lib.rs"
    torii = read(torii_path)
    partial_handler = section(
        torii,
        "async fn handler_gov_parliament_tle_partial_release(",
        "async fn handler_gov_citizen_status(",
        torii_path,
    )
    require_all(
        torii_path,
        partial_handler,
        (
            '"v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release"',
            "let signer_admission = acquire_query_admission(app.as_ref(), true).await?;",
            "ballot_attempt_id,\n        signer_admission,",
        ),
    )

    route_catalog_path = "crates/iroha_torii_shared/src/route_catalog.rs"
    route_catalog = read(route_catalog_path)
    partial_route = section(
        route_catalog,
        "pub const GOV_PARLIAMENT_TLE_PARTIAL_RELEASE: RouteDescriptor",
        "pub const GOV_PARLIAMENT_TRANSITION_DRAFT: RouteDescriptor",
        route_catalog_path,
    )
    require_all(
        route_catalog_path,
        partial_route,
        (
            "app_signed_post(",
            '"/v1/gov/parliament/ballots/{ballot_attempt_id}/partial-release"',
        ),
    )

    retired_public_parliament_identifiers = (
        "ParliamentTerm",
        "CouncilState",
        "CouncilDerivationKind",
        "ParliamentRoster",
        "ParliamentBodies",
        "CitizenServiceDiscipline",
        "CitizenServiceEvent",
        "RecordCitizenServiceOutcome",
        "GovernanceCouncilPersisted",
        "GovernanceParliamentSelected",
        "GovernanceCitizenServiceRecorded",
        "CouncilPersisted",
        "ParliamentSelected",
        "CitizenServiceRecorded",
        "GovernanceProposalApproved",
        "ProposalApproved",
        "GovernanceParliamentApprovalRecorded",
        "ParliamentApprovalRecorded",
        "GovernanceParliamentAttemptTransitioned",
        "ParliamentAttemptTransitioned",
        "GovernanceParliamentBodyTransitioned",
        "ParliamentBodyTransitioned",
        "GovernanceParliamentBallotTransitioned",
        "ParliamentBallotTransitioned",
        "GovernanceParliamentConcentrationWarning",
        "ParliamentConcentrationWarning",
        "ParliamentConcentrationWarningV1",
        "GovernanceParliamentAggregateFinalized",
        "ParliamentAggregateFinalized",
        "GovernanceParliamentCertificateIssued",
        "ParliamentCertificateIssued",
    )

    # The former feature-gated governance event module duplicated the canonical
    # data-event stream and exposed caller-oriented Parliament outcomes. Keep
    # both the module and every uniquely named public payload/type retired. The
    # declaration-aware check deliberately does not confuse canonical enum
    # variants such as `ReferendumOpened` with those removed payload structs.
    retired_event_module_path = "crates/iroha_data_model/src/governance/events.rs"
    require_path_absent(retired_event_module_path)
    governance_mod_path = "crates/iroha_data_model/src/governance/mod.rs"
    governance_mod = read(governance_mod_path)
    if re.search(r"(?m)^\s*pub\s+mod\s+events\s*;", governance_mod):
        raise RuntimeError(
            f"{governance_mod_path}: retired duplicate governance event module is exported"
        )

    retired_public_item_identifiers = (
        "SudoExecutionResult",
        "SudoFailure",
        "SudoExecuted",
        "ReferendumProposed",
        "ReferendumOpened",
        "VoteCast",
        "ReferendumTallied",
        "GovernanceScheduled",
        "GovernanceEnacted",
        "GovernanceExecutionFailed",
        "ParliamentSelected",
        "ParliamentEnacted",
        "ParliamentExecutionFailed",
        "ParliamentHouse",
        "ParliamentTimeout",
        "ParliamentVetoed",
        "ParliamentMemberEjected",
        "CertificateRejected",
        "RescheduleRequired",
        "FastTrackGranted",
        "DepositSlashed",
        "GovernanceCouncilPersisted",
        "GovernanceParliamentSelected",
        "GovernanceCitizenServiceRecorded",
        "GovernanceProposalApproved",
        "GovernanceParliamentApprovalRecorded",
        "GovernanceParliamentAttemptTransitioned",
        "GovernanceParliamentBodyTransitioned",
        "GovernanceParliamentBallotTransitioned",
        "GovernanceParliamentConcentrationWarning",
        "GovernanceParliamentAggregateFinalized",
        "GovernanceParliamentCertificateIssued",
        "ParliamentConcentrationWarningV1",
        "CouncilDerivationKind",
        "ParliamentRoster",
        "ParliamentBodies",
        "ParliamentTerm",
        "CouncilState",
        "PRIMARY_PARLIAMENT_BODIES_V1",
        "ParliamentDrawPlan",
        "derive_attempt_body_plan_v1",
        "smallest_feasible_assignment_cap",
        "CitizenServiceDiscipline",
        "CitizenServiceEvent",
        "RecordCitizenServiceOutcome",
        "CITIZEN_SEAT_COOLDOWN_BLOCKS",
        "CITIZEN_MAX_SEATS_PER_EPOCH",
        "CITIZEN_FREE_DECLINES_PER_EPOCH",
        "CITIZEN_DECLINE_SLASH_BPS",
        "CITIZEN_NO_SHOW_SLASH_BPS",
        "CITIZEN_MISCONDUCT_SLASH_BPS",
        "citizen_service",
        "role_bond_multipliers",
        "bond_multiplier_for_role",
        "record_citizen_service_event",
        "record_council_draw",
    )
    require_path_absent("crates/iroha_core/src/governance/state.rs")
    retired_public_item_surfaces = (
        (governance_mod_path, governance_mod),
        (types_path, types),
        (instruction_path, instructions),
        (events_path, events),
        (world_path, world),
        (state_path, state),
        (telemetry_path, telemetry),
        (
            "crates/iroha_core/src/governance/draw.rs",
            read("crates/iroha_core/src/governance/draw.rs"),
        ),
        (
            "crates/iroha_config/src/parameters/defaults.rs",
            read("crates/iroha_config/src/parameters/defaults.rs"),
        ),
        (
            "crates/iroha_config/src/parameters/actual.rs",
            read("crates/iroha_config/src/parameters/actual.rs"),
        ),
        (
            "crates/iroha_config/src/parameters/user.rs",
            read("crates/iroha_config/src/parameters/user.rs"),
        ),
    )
    for relative, contract_surface in retired_public_item_surfaces:
        require_public_items_absent(
            relative,
            contract_surface,
            retired_public_item_identifiers,
        )

    retired_identifier_surfaces = (
        (types_path, types),
        (instruction_path, instructions),
        (events_path, events),
        (world_path, world),
        (state_path, state),
        (telemetry_path, telemetry),
        (metrics_path, metrics),
        (api_path, api),
        (torii_gov_path, torii_gov),
        (torii_path, torii),
        (route_catalog_path, route_catalog),
    )
    for relative, contract_surface in retired_identifier_surfaces:
        require_identifiers_absent(
            relative,
            contract_surface,
            retired_public_parliament_identifiers,
        )

    retired_identifier_surface_paths = (
        "crates/iroha_data_model/src/events/data/filters.rs",
        "crates/iroha_data_model/src/isi/governance.rs",
        "crates/iroha_data_model/src/isi/registry.rs",
        "crates/iroha_data_model/src/isi/registry/wire_ids.rs",
        "crates/iroha_torii/src/routing.rs",
        "crates/iroha_cli/src/gov.rs",
        "crates/iroha_config/src/parameters/defaults.rs",
        "crates/iroha_config/src/parameters/actual.rs",
        "crates/iroha_config/src/parameters/user.rs",
        "javascript/iroha_js/index.d.ts",
        "javascript/iroha_js/src/parliamentApiV1.js",
        "python/iroha_torii_client/parliament_api.py",
        "kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/client/ParliamentApiV1.kt",
        "java/iroha_android/src/main/java/org/hyperledger/iroha/android/client/ParliamentApiV1.java",
        "IrohaSwift/Sources/IrohaSwift/ToriiParliamentAPIV1.swift",
        "artifacts/openapi/torii.json",
        "artifacts/openapi/versions/current/torii.json",
        "crates/iroha_torii/assets/openapi/torii.json",
        "specs/governance_api.md",
        "specs/governance_pipeline.md",
        "specs/governance_playbook.md",
        "specs/sorafs/signing_ceremony.md",
        "fixtures/sorafs_chunker/README.md",
        "crates/iroha_cli/README.md",
    )
    for relative in retired_identifier_surface_paths:
        require_identifiers_absent(
            relative,
            read(relative),
            retired_public_parliament_identifiers,
        )

    require_threshold_signer_startup_readiness(read("crates/irohad/src/main/runtime_deps.rs"))

    broker_primitives_path = (
        "crates/irohad/src/runtime_provider_broker/protocol_primitives.rs"
    )
    broker_primitives = read(broker_primitives_path)
    require_parliament_broker_primitives(broker_primitives)
    broker_validation_path = (
        "crates/irohad/src/runtime_provider_broker/protocol_operation_validation.rs"
    )
    broker_validation = read(broker_validation_path)
    broker_semantic_limits = section(
        broker_validation,
        "const fn operation_semantic_frame_limit(operation: u16) -> usize {",
        "const fn operation_frame_limit(operation: u16) -> usize {",
        broker_validation_path,
    )
    require_all(
        broker_validation_path,
        broker_semantic_limits,
        (
            "OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1",
            "MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1",
        ),
    )
    broker_frame_limits = section(
        broker_validation,
        "const fn operation_frame_limit(operation: u16) -> usize {",
        "const fn operation_is_known(operation: u16) -> bool {",
        broker_validation_path,
    )
    require_all(
        broker_validation_path,
        broker_frame_limits,
        (
            "OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1",
            "MAX_CONSENSUS_SIGNER_FRAME_BYTES_V1",
        ),
    )
    broker_known_operations = section(
        broker_validation,
        "const fn operation_is_known(operation: u16) -> bool {",
        "fn provider_ingest_signer_context_from_wire(",
        broker_validation_path,
    )
    require_all(
        broker_validation_path,
        broker_known_operations,
        ("OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1",),
    )
    broker_attestation_request = section(
        broker_validation,
        "fn decode_parliament_tle_capability_attest_request(",
        "fn verify_parliament_tle_capability_attest_result(",
        broker_validation_path,
    )
    require_all(
        broker_validation_path,
        broker_attestation_request,
        (
            "request.key_session.network_id != *session_network_id.as_bytes()",
            ".key_session\n        .clone()\n        .validate()",
            "TlePartialReleaseCapabilityAttestationV1::for_validated_session(",
            "request.participant_index",
        ),
    )
    broker_attestation_result = section(
        broker_validation,
        "fn verify_parliament_tle_capability_attest_result(",
        "fn verify_parliament_tle_partial_release_result(",
        broker_validation_path,
    )
    require_all(
        broker_validation_path,
        broker_attestation_result,
        (
            "result.key_session_id != expected.key_session_id()",
            "result.transcript_hash != expected.transcript_hash()",
            "result.participant_index != expected.participant_index()",
            "return Err(BrokerError::Rejected)",
        ),
    )
    broker_typed_response = section(
        broker_validation,
        "fn validate_operation_response_for_client(",
        "fn validate_operation_response_envelope(",
        broker_validation_path,
    )
    require_all(
        broker_validation_path,
        broker_typed_response,
        (
            "OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1",
            "IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id()",
            "response.status == STATUS_OK_V1",
            "return Ok(())",
        ),
    )
    broker_result_matrix = section(
        broker_validation,
        "fn validate_operation_result(",
        "fn sealed_slot_to_wire(",
        broker_validation_path,
    )
    broker_attestation_result_branch = section(
        broker_result_matrix,
        "            OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1 => {",
        "            OPERATION_MODERATION_HANDOFF_DELIVER_ONCE_V1 => {",
        broker_validation_path,
    )
    require_all(
        broker_validation_path,
        broker_attestation_result_branch,
        (
            "IrohaRuntimeProviderSlotV1::ParliamentTlePartialReleaseSigner.wire_id()",
            "decode_parliament_tle_capability_attest_request(",
            "decode_canonical::<ParliamentTleCapabilityAttestResultWireV1>(",
            "verify_parliament_tle_capability_attest_result(",
            ".map_err(|_| BrokerError::Protocol)?;",
        ),
    )
    broker_payload_path = (
        "crates/irohad/src/runtime_provider_broker/validate_operation_payload.rs"
    )
    broker_payload = read(broker_payload_path)
    broker_attestation_payload_branch = section(
        broker_payload,
        "        (slot, OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1)",
        "        (slot, OPERATION_BOOTLE_LANTERN_ISSUANCE_AUTHENTICATE_V1)",
        broker_payload_path,
    )
    require_all(
        broker_payload_path,
        broker_attestation_payload_branch,
        (
            "if slot == parliament_tle_partial_release_signer_slot",
            "decode_parliament_tle_capability_attest_request(",
            "&request.payload",
            "session_network_id",
        ),
    )
    broker_dispatch_path = (
        "crates/irohad/src/runtime_provider_broker/platform_operation_dispatch.rs"
    )
    broker_dispatch = read(broker_dispatch_path)
    broker_consensus_path = (
        "crates/irohad/src/runtime_provider_broker/"
        "protocol/platform/operation_dispatch/consensus.rs"
    )
    require_parliament_broker_dispatch(
        broker_dispatch, read(broker_consensus_path)
    )
    broker_api_path = "crates/irohad/src/runtime_provider_broker/api.rs"
    broker_api = read(broker_api_path)
    tle_broker_backend = section(
        broker_api,
        "pub trait ParliamentTlePartialReleaseSignerBrokerBackendV1: Send + Sync {",
        "/// One-shot lifecycle control shared by a broker launcher and serving thread.",
        broker_api_path,
    )
    require_all(
        broker_api_path,
        tle_broker_backend,
        (
            "fn attest_partial_release_capability(",
            "session: &iroha_core_timed_ovn::tle::ValidatedTleKeySessionV1",
            "expected_participant_index: u16",
            "ParliamentTlePartialReleaseSignerBrokerBackendErrorV1,\n    >;",
        ),
    )
    broker_client_path = (
        "crates/irohad/src/runtime_provider_broker/platform_provider_clients_03.rs"
    )
    broker_client = read(broker_client_path)
    broker_attestation_client = section(
        broker_client,
        "    fn attest_projected_capability(",
        "    fn sign_projected_partial_release(",
        broker_client_path,
    )
    require_all(
        broker_client_path,
        broker_attestation_client,
        (
            "retry_consensus_signer_once_after_unavailable(",
            "live_exact_qualification(",
            "OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1",
            "ParliamentTleCapabilityAttestResultWireV1",
            "if attested.key_session_id != expected.key_session_id()",
            "attested.transcript_hash != expected.transcript_hash()",
            "attested.participant_index != expected.participant_index()",
            "self.session.poison();",
        ),
    )
    require_all(
        broker_client_path,
        broker_client,
        ("fn attest_partial_release_capability(",),
    )
    software_tle_path = (
        "crates/irohad/src/external_software_signer/consensus_threshold.rs"
    )
    software_tle = read(software_tle_path)
    require_all(
        software_tle_path,
        software_tle,
        (
            "fn attest_partial_release_capability(",
            "self.custody",
            ".attest_partial_release_capability(session, expected_participant_index)",
            "TlePartialReleaseCapabilityErrorV1::Unavailable",
            "ParliamentTlePartialReleaseSignerBrokerBackendErrorV1::Unavailable",
        ),
    )
    broker_tests_path = "crates/irohad/src/runtime_provider_broker/server_tests_04.rs"
    broker_tests = read(broker_tests_path)
    require_all(
        broker_tests_path,
        broker_tests,
        (
            "fn parliament_tle_capability_attestation_round_trips_over_authenticated_broker()",
            "wrong_seat_payload",
            "Err(BrokerError::Rejected)",
        ),
    )
    broker_typed_capability_success = section(
        broker_tests,
        "fn parliament_tle_capability_typed_proxy_requalifies_before_and_after_lookup()",
        "fn parliament_tle_partial_release_round_trips_over_authenticated_broker()",
        broker_tests_path,
    )
    require_all(
        broker_tests_path,
        broker_typed_capability_success,
        (
            "expect_and_answer_consensus_signer_qualification(",
            "&mut stream, 1, revision, policy_digest",
            "assert_eq!(attest.request_id, 2)",
            "OPERATION_PARLIAMENT_TLE_CAPABILITY_ATTEST_V1",
            "ParliamentTleCapabilityAttestResultWireV1",
            "&mut stream, 3, revision, policy_digest",
            ".attest_projected_capability(&session, 1)",
            "attestation.matches(&session, 1)",
        ),
    )
    first_qualification = broker_typed_capability_success.find(
        "expect_and_answer_consensus_signer_qualification("
    )
    capability_lookup = broker_typed_capability_success.find(
        "let attest = read_consensus_signer_operation("
    )
    second_qualification = broker_typed_capability_success.rfind(
        "expect_and_answer_consensus_signer_qualification("
    )
    if not first_qualification < capability_lookup < second_qualification:
        raise RuntimeError(
            f"{broker_tests_path}: typed TLE capability lookup is not surrounded by live qualification"
        )
    broker_typed_capability_failures = section(
        broker_tests,
        "enum ParliamentTleCapabilityResultFault {",
        "fn parliament_tle_partial_release_reconnects_after_broker_restart()",
        broker_tests_path,
    )
    require_all(
        broker_tests_path,
        broker_typed_capability_failures,
        (
            "WrongKeySessionId",
            "WrongTranscriptHash",
            "WrongParticipantIndex",
            "Truncated",
            "result.key_session_id = if candidate == result.key_session_id",
            "result.transcript_hash[0] ^= 1",
            "result.participant_index = 2",
            ".pop()",
            "fn correlated_wrong_tle_key_session_id_is_rejected_by_typed_proxy()",
            "fn correlated_wrong_tle_transcript_hash_is_rejected_by_typed_proxy()",
            "fn correlated_wrong_tle_participant_index_is_rejected_by_typed_proxy()",
            "fn correlated_truncated_tle_capability_is_rejected_by_typed_proxy()",
            "an invalid capability must permanently poison the TLE session without replay",
        ),
    )
    daemon_path = "crates/irohad/src/main.rs"
    daemon = read(daemon_path)
    require_all(
        daemon_path,
        daemon,
        (
            "runtime_deps.parliament_tle_release_coordinator()",
            ".with_parliament_tle_release_coordinator(parliament_tle_release_coordinator)",
        ),
    )

    model_path = "formal/sora_parliament/SoraParliamentV1.tla"
    model = read(model_path)
    require_all(
        model_path,
        model,
        (
            "FuturePulseSortition ==",
            "SortitionPulseDelayBlocks",
            "MaxSortitionRetries",
            "MaxRandomnessRedraws",
            "governanceAttemptSequence",
            "randomnessRedrawsBeforeAttempt",
            "InitialSortitionRedrawCost ==",
            "ProposalRandomnessRedrawsUsed ==",
            "ProposalWideRandomnessRedrawBudget ==",
            "sortitionPulseHeight' = height + SortitionPulseDelayBlocks",
            "FailSortitionPulseUnavailable ==",
            "RetryInitialSortitionBatch ==",
            "ReplayCommittedTransportIdempotently ==",
            "RecordInitialHiddenSortitionCapacityFailure(candidateCount) ==",
            "RecordRetryHiddenSortitionCapacityFailure(candidateCount) ==",
            '"HiddenElectorateCapacityUnavailable"',
            "sortitionCandidateCount",
            "sortitionPulseConsumed",
            "HiddenElectorateCapacityConsumesNoPulse ==",
            'sortitionFailureKind\' = "PulseUnavailable"',
            "sortitionSequence < MaxSortitionRetries",
            "supersededSortitionAttempts' = supersededSortitionAttempts + 1",
            "ObjectiveBoundedSortitionRetries ==",
            "AdmitTimedOvnResourceReservation(candidate) ==",
            "RejectTimedOvnResourceReservation(candidate) ==",
            "ReleaseTimedOvnResourceReservation(candidate) ==",
            "TimedOvnReservationSafety ==",
            "RejectedReservationDoesNotLeak ==",
            "TimedOvnReservationAuditShape ==",
            "reservationAuditStep = 8",
            "SimultaneousInitialDraw ==",
            "RecordSelfAbsence(assignment) ==",
            'IF findingState = "AwaitingReflection"',
            "ELSE height <= findingDeadlineHeight",
            "EndorsePublicFinding(assignment, root) ==",
            "EnterPublicFindingReflection ==",
            "FailPublicFindingNoResult ==",
            "AuthorityBoundImmutableMemberRecords ==",
            "PublicFindingQuorumBinding ==",
            "FindingQuorumUnreachable(absent, endorsements) ==",
            'findingFailureKind\' = "QuorumUnreachable"',
            'findingFailureKind\' = "DeadlineExpired"',
            "PublicFindingQuorum",
            "AssignmentOrder",
            "CanonicalEndorserSequence",
            "certificateFindingEndorsementRoot",
            "certificateFindingEndorsingAssignments",
            "certificateFindingEndorsementCount",
            "certificateFindingQuorum",
            "ExactPhaseBoundaries ==",
            "PhaseCapacity ==",
            "RegistrationBlocks >= MaxCorpusEntries + 1",
            "SurvivorBlocks >= MaxCorpusEntries",
            "CommitmentBlocks * 32 >= MaxCorpusEntries",
            "FreezeCommitmentInWindow ==",
            "height > survivorFreezeHeight",
            "height <= commitmentCloseHeight",
            "commitmentClosedAt > survivorFreezeHeight",
            "commitmentClosedAt <= commitmentCloseHeight",
            "ExactPublicFindingDeadline ==",
            "ObjectiveReleaseAvailability ==",
            "OpeningBlocks",
            "BoundedOpeningWindow ==",
            "FreshRetrySessions ==",
            "NoResultTerminalization ==",
            "NoPlaintextOrFallback ==",
            "CertificateBindsApprovedResult ==",
            "ExactHeightCasEnactment ==",
            "CertifiedCannotPassDueHeight ==",
            '"ExecutionFailed"',
            "FinalizeAggregateApprovedAndCertify ==",
            "FinalizeNarrowPolicyCapacityNoResult(eligibleCount) ==",
            "FinalizeNarrowPolicyRandomnessRedrawBudgetExhausted ==",
            "ParliamentBallotFailureKindV1::RandomnessRedrawBudgetExhausted",
            "FinalizeNarrowPolicyAndRegisterConfirmationRequest ==",
            "AtomicPolicyConfirmationCapacity ==",
            "RecordInternalExecutionFailureAtExactHeight ==",
            "~releasePulseKnown",
        ),
    )
    redraw_accounting_model = section(
        model,
        "InitialSortitionRedrawCost ==",
        "PublicFindingQuorum ==",
        model_path,
    )
    require_all(
        model_path,
        redraw_accounting_model,
        (
            "BoolToNat(governanceAttemptSequence > 0)",
            'IF sortitionState = "None"',
            "sortitionSequence + InitialSortitionRedrawCost",
            'IF ballotState = "None" THEN 0 ELSE ballotSequence',
            "randomnessRedrawsBeforeAttempt +",
            "BoolToNat(confirmationRequestCommitted)",
        ),
    )
    redraw_init_model = section(model, "Init ==", "FindingLifecycleFrame ==", model_path)
    require_all(
        model_path,
        redraw_init_model,
        (
            "governanceAttemptSequence = 0",
            "randomnessRedrawsBeforeAttempt = 0",
            "governanceAttemptSequence = 1",
            "0..(MaxRandomnessRedraws - 1)",
        ),
    )
    redraw_budget_invariant = section(
        model,
        "ProposalWideRandomnessRedrawBudget ==",
        "FuturePulseSortition ==",
        model_path,
    )
    require_all(
        model_path,
        redraw_budget_invariant,
        (
            "ProposalRandomnessRedrawsUsed \\in 0..MaxRandomnessRedraws",
            "randomnessRedrawsBeforeAttempt < MaxRandomnessRedraws",
            'sortitionState = "NoRoster"',
            'ballotState = "NoResult"',
            'attemptStatus = "Rejected"',
        ),
    )
    initial_sortition_action = section(
        model,
        "CommitInitialSortitionBatch ==",
        "RecordInitialHiddenSortitionCapacityFailure(candidateCount) ==",
        model_path,
    )
    require_all(
        model_path,
        initial_sortition_action,
        (
            'sortitionState = "None"',
            "ProposalRandomnessRedrawsUsed + InitialSortitionRedrawCost <=",
            "MaxRandomnessRedraws",
        ),
    )
    sortition_retry_action = section(
        model,
        "RetryInitialSortitionBatch ==",
        "RecordRetryHiddenSortitionCapacityFailure(candidateCount) ==",
        model_path,
    )
    require_all(
        model_path,
        sortition_retry_action,
        (
            "ProposalRandomnessRedrawsUsed < MaxRandomnessRedraws",
            "sortitionSequence' = sortitionSequence + 1",
        ),
    )
    ballot_registration_action = section(
        model,
        "RegisterPrivateBallot ==",
        "CloseRegistrationAtBoundary ==",
        model_path,
    )
    require_all(
        model_path,
        ballot_registration_action,
        (
            'ballotState \\in {"None", "NoResult"}',
            'ballotState = "None" \\/',
            "ProposalRandomnessRedrawsUsed < MaxRandomnessRedraws",
            'ballotSequence\' = IF ballotState = "None" THEN 0 ELSE ballotSequence + 1',
        ),
    )
    transport_replay_action = section(
        model,
        "ReplayCommittedTransportIdempotently ==",
        "ReducerNext ==",
        model_path,
    )
    require_all(
        model_path,
        transport_replay_action,
        (
            "sortitionState",
            "ballotState",
            "confirmationRequestCommitted",
            "UNCHANGED vars",
        ),
    )
    for forbidden_update in (
        "sortitionSequence'",
        "ballotSequence'",
        "confirmationRequestCommitted'",
        "randomnessRedrawsBeforeAttempt'",
    ):
        if forbidden_update in transport_replay_action:
            raise RuntimeError(
                f"{model_path}: committed transport replay mutates {forbidden_update!r}"
            )
    for start, end in (
        (
            "RecordInitialHiddenSortitionCapacityFailure(candidateCount) ==",
            "RevealSortitionPulse ==",
        ),
        (
            "RecordRetryHiddenSortitionCapacityFailure(candidateCount) ==",
            "SealInvitationRosters ==",
        ),
    ):
        capacity_action = section(model, start, end, model_path)
        require_all(
            model_path,
            capacity_action,
            (
                "candidateCount \\in 0..2",
                'sortitionFailureKind\' = "HiddenElectorateCapacityUnavailable"',
                "sortitionFailureHeight' = height",
                "requestHeight' = height",
                "sortitionPulseKnown' = FALSE",
                "sortitionPulseConsumed' = FALSE",
                "sortitionCandidateCount' = candidateCount",
            ),
        )
        if "sortitionPulseConsumed' = TRUE" in capacity_action:
            raise RuntimeError(
                f"{model_path}: hidden-electorate capacity failure consumes a pulse"
            )
    confirmation_capacity_action = section(
        model,
        "FinalizeNarrowPolicyCapacityNoResult(eligibleCount) ==",
        "FinalizeNarrowPolicyRandomnessRedrawBudgetExhausted ==",
        model_path,
    )
    confirmation_redraw_exhaustion_action = section(
        model,
        "FinalizeNarrowPolicyRandomnessRedrawBudgetExhausted ==",
        "FinalizeNarrowPolicyAndRegisterConfirmationRequest ==",
        model_path,
    )
    require_all(
        model_path,
        confirmation_redraw_exhaustion_action,
        (
            "ProposalRandomnessRedrawsUsed = MaxRandomnessRedraws",
            'ballotState\' = "NoResult"',
            'attemptStatus\' = "Rejected"',
            "eligibleConfirmationCandidates' = 3",
            "policyBindingCommitted' = FALSE",
            "confirmationRequirementCommitted' = FALSE",
            "confirmationRequestCommitted' = FALSE",
            "confirmationRequestHeight' = None",
            "confirmationPulseHeight' = None",
        ),
    )
    require_all(
        model_path,
        confirmation_capacity_action,
        (
            "eligibleCount \\in 0..2",
            'ballotState\' = "NoResult"',
            'attemptStatus\' = "Rejected"',
            "policyBindingCommitted' = FALSE",
            "confirmationRequirementCommitted' = FALSE",
            "confirmationRequestCommitted' = FALSE",
            "confirmationRequestHeight' = None",
            "confirmationPulseHeight' = None",
        ),
    )
    confirmation_handoff_action = section(
        model,
        "FinalizeNarrowPolicyAndRegisterConfirmationRequest ==",
        "FinalizeAggregateRejected ==",
        model_path,
    )
    require_all(
        model_path,
        confirmation_handoff_action,
        (
            "eligibleConfirmationCandidates' = 3",
            "policyResultHeight' = height",
            "policyBindingCommitted' = TRUE",
            "confirmationRequirementCommitted' = TRUE",
            "confirmationRequestCommitted' = TRUE",
            "confirmationRequestHeight' = height",
            "confirmationPulseHeight' = height + SortitionPulseDelayBlocks",
            "ProposalRandomnessRedrawsUsed < MaxRandomnessRedraws",
        ),
    )
    if "ConstructCertificate ==" in model:
        raise RuntimeError(
            f"{model_path}: certificate construction remains a separately schedulable action"
        )
    model_config_path = "formal/sora_parliament/SoraParliamentV1.cfg"
    model_config = read(model_config_path)
    require_all(
        model_config_path,
        model_config,
        (
            "SortitionPulseDelayBlocks = 1",
            "MaxSortitionRetries = 2",
            "MaxRandomnessRedraws = 2",
            "MaxConcurrentReservations = 2",
            "ReservationIds = {Reservation0, Reservation1, Reservation2}",
            "FirstConflictingReservation = Reservation0",
            "SecondConflictingReservation = Reservation1",
            "OpeningBlocks = 2",
            "RegistrationBlocks = 4",
            "SurvivorBlocks = 3",
            "CommitmentBlocks = 2",
            "MaxCorpusEntries = 3",
            "FindingBlocks = 2",
            "SeatedAssignments = {Seat0, Seat1}",
            "FirstAssignment = Seat0",
            "SecondAssignment = Seat1",
            "FindingRoots = {Finding0, Finding1}",
            "ObjectiveBoundedSortitionRetries",
            "ProposalWideRandomnessRedrawBudget",
            "HiddenElectorateCapacityConsumesNoPulse",
            "TimedOvnReservationSafety",
            "RejectedReservationDoesNotLeak",
            "TimedOvnReservationAuditShape",
            "AuthorityBoundImmutableMemberRecords",
            "PublicFindingQuorumBinding",
            "ExactPublicFindingDeadline",
            "PhaseCapacity",
            "BoundedOpeningWindow",
            "AtomicPolicyConfirmationCapacity",
            "CertificateBindsApprovedResult",
            "ExactHeightCasEnactment",
            "NoResultTerminalization",
        ),
    )
    expected_invariants = (
        "TypeOK",
        "ProposalWideRandomnessRedrawBudget",
        "FuturePulseSortition",
        "ObjectiveBoundedSortitionRetries",
        "HiddenElectorateCapacityConsumesNoPulse",
        "TimedOvnReservationSafety",
        "RejectedReservationDoesNotLeak",
        "TimedOvnReservationAuditShape",
        "SimultaneousInitialDraw",
        "AuthorityBoundImmutableMemberRecords",
        "PublicFindingQuorumBinding",
        "ExactPublicFindingDeadline",
        "ExactBallotSchedule",
        "PhaseCapacity",
        "ExactPhaseBoundaries",
        "ObjectiveReleaseAvailability",
        "BoundedOpeningWindow",
        "FreshRetrySessions",
        "AtomicPolicyConfirmationCapacity",
        "NoPlaintextOrFallback",
        "CertificateBindsApprovedResult",
        "ExactHeightCasEnactment",
        "CertifiedCannotPassDueHeight",
        "NoResultTerminalization",
    )
    configured_invariants = tuple(
        line.strip()
        for line in section(
            model_config,
            "INVARIANTS\n",
            "\nCHECK_DEADLOCK FALSE",
            model_config_path,
        ).splitlines()
        if line.strip()
    )
    if configured_invariants != expected_invariants:
        raise RuntimeError(
            f"{model_config_path}: invariant block mismatch: "
            f"expected {expected_invariants!r}, found {configured_invariants!r}"
        )
    for invariant in expected_invariants:
        declaration_count = len(
            re.findall(rf"(?m)^{re.escape(invariant)}[ \t]*==", model)
        )
        if declaration_count != 1:
            raise RuntimeError(
                f"{model_path}: invariant {invariant!r} must be declared exactly once; "
                f"found {declaration_count}"
            )

    lifecycle_world_path = "crates/iroha_core/src/smartcontracts/isi/world.rs"
    lifecycle_world = read(lifecycle_world_path)
    global_beacon_finalize = section(
        lifecycle_world,
        "                Action::FinalizeGlobalBeaconKey => {",
        "                Action::InstallParliamentTleKey => {",
        lifecycle_world_path,
    )
    require_all(
        lifecycle_world_path,
        global_beacon_finalize,
        (
            "norito::decode_canonical::<",
            "FinalizedGlobalThresholdBeaconKeySessionRecordV1,",
            "record.session.network_id != certificate.network_id",
            "record.activated_at_height.is_some()",
            "record.retired_at_height.is_some()",
            "validator_committee::validate_beacon_finalization(",
            "if bootstrap {",
            "record.activate(next_height)",
            "global_beacon_active_session.insert(",
        ),
    )
    for conflated_binding in (
        "record.session.roster_hash != certificate.roster_hash",
        "record.session.committee_size != certificate.committee_size",
    ):
        if conflated_binding in global_beacon_finalize:
            raise RuntimeError(
                f"{lifecycle_world_path}: global-beacon target DKG roster was conflated "
                f"with block-height authorization: {conflated_binding!r}"
            )
    lifecycle_model_path = "crates/iroha_data_model/src/isi/consensus_keys.rs"
    for path, source in ((lifecycle_world_path, lifecycle_world),
                         (lifecycle_model_path, read(lifecycle_model_path))):
        for retired in ("Action::InstallGlobalBeaconKey", "RetireGlobalBeaconKey"):
            if retired in source:
                raise RuntimeError(f"{path}: standalone beacon rotation remains: {retired}")

    committee_path = "crates/iroha_core/src/state/validator_committee.rs"
    committee = read(committee_path)
    require_beacon_finalization_roster(committee)
    boundary = section(committee, "pub(crate) fn finalize_validator_committee_boundary(",
                       "fn owns_validator(", committee_path)
    require_all(committee_path, boundary, (
        "let context = frozen.current();", "let boundary = frozen.boundary();",
        "boundary.validate_against(context)?", "let snapshot = &boundary.next;",
        "boundary.height != self._curr_block.height().get()", "context.network_id != self.network_id",
        "self.block_hashes().hash_at(anchor_index) != Some(&boundary.selection_anchor)",
        "self.block_hashes().hash_count() != anchor_index + 1",
        "verify_progress(&self.world, &transition)?",
        "transition.outcome = Some(*outcome)", "transition.validate()?",
        "credentials.authority != snapshot.authority",
        "transition.preparation.committee != snapshot.committee",
        "active_global_beacon_key_session() != Some(previous.session_id)",
        "old.retire(outcome.first_height)", "next.activate(outcome.first_height)",
        "beacon_rotation = Some((old, next))", "if let Some((old, next)) = beacon_rotation",
        "ValidatorEpochDecisionV1::RetainAndCancel",
        "retention must cancel the exact frozen attempt",
    ))

    certificate_state_path = "crates/iroha_core/src/state.rs"
    certificate_state = read(certificate_state_path)
    certificate_preimage = section(
        certificate_state,
        "pub fn threshold_key_lifecycle_certificate_preimage_v1(",
        "pub(crate) fn threshold_key_lifecycle_roster_v1(",
        certificate_state_path,
    )
    require_all(
        certificate_state_path,
        certificate_preimage,
        (
            "let public_state_len = u64::try_from(certificate.public_state.len())",
            "let public_state_hash = Hash::new(&certificate.public_state);",
            "preimage.extend_from_slice(&public_state_len.to_be_bytes());",
            "preimage.extend_from_slice(public_state_hash.as_ref());",
        ),
    )

    beacon_producer = read(BEACON_PRODUCER_PATH)
    require_parliament_beacon_requirement(read(EPOCH_BEACON_PATH), beacon_producer)
    beacon_state_path = "crates/iroha_core/src/beacon.rs"
    beacon_state = read(beacon_state_path)
    require_encrypted_beacon_dkg_source(
        read("crates/iroha_data_model/src/consensus.rs"), beacon_state
    )
    require_signed_deferred_authority_and_native_fees(
        read('crates/iroha_core/src/validation_fee.rs'),
        read('crates/iroha_core/src/deferred_authority.rs'),
        read('crates/iroha_core/src/retail_fee.rs'),
        read('crates/iroha_core/src/smartcontracts/isi/asset.rs'),
        read('crates/iroha_core/src/tx.rs'),
        read('crates/iroha_core/src/lib.rs'),
    )
    require_beacon_parliament_pulse_fixtures(
        beacon_state,
        read("crates/iroha_core/src/beacon/tests.rs"),
        read("crates/iroha_core/src/state/tests.rs"),
        beacon_producer,
        read(BEACON_PRODUCER_TESTS_PATH),
        read(BEACON_EXECUTION_TESTS_PATH),
    )
    require_native_beacon_pulse_application(
        read("crates/iroha_core/src/block.rs"),
        read(NATIVE_HEADER_SOURCE_PATH),
        read(SCHEDULE_EXECUTION_PATH),
    )

    for declaration in ("SPECIFICATION Spec", "INVARIANTS", "CHECK_DEADLOCK FALSE"):
        declaration_count = model_config.count(declaration)
        if declaration_count != 1:
            raise RuntimeError(
                f"{model_config_path}: {declaration!r} must appear exactly once; "
                f"found {declaration_count}"
            )

    workflow_path = ".github/workflows/pr.yml"
    workflow = read(workflow_path)
    formal_job = section(
        workflow,
        "  formal_models:\n",
        "\n  sora_parliament_lifecycle:\n",
        workflow_path,
    )
    require_all(
        workflow_path,
        formal_job,
        (
            '"$invocation_root/artifacts/formal/sora_parliament/inputs"',
            "SORA_PARLIAMENT_FORMAL_EVIDENCE_DIR=%s",
            'install -m 600 -- "$model_source" "$model_input"',
            'install -m 600 -- "$config_source" "$config_input"',
            '"schema": "iroha.sora_parliament.formal_run.v2"',
            '"source_commit": source_commit',
            '"successful": source_status == 0 and model_status == 0',
            '"jar_sha256": digest(jar_name)',
            '**evidence(model_name, "inputs/SoraParliamentV1.tla")',
            '**evidence(config_name, "inputs/SoraParliamentV1.cfg")',
            '"size_bytes": item.stat().st_size',
            'source_status_evidence["exit_status"] = source_status',
            'model_status_evidence["exit_status"] = model_status',
            '2>&1 | tee "$source_contract_log"',
            '-config "$config_input"',
            '"$model_input" 2>&1 | tee "$tlc_log"',
            'printf \'%s\\n\' "$tlc_status" > "$tlc_status_path"',
            "Validate SORA Parliament formal evidence closure",
            'if document.get("source_commit") != expected_commit:',
            'if entry.get("sha256") != hashlib.sha256(payload).hexdigest():',
            "name: sora-parliament-formal-pr",
            "path: ${{ steps.formal_layout.outputs.artifact_root }}/formal/sora_parliament",
            "if-no-files-found: error",
        ),
    )
    for status_capture in (
        'source_contract_status="${PIPESTATUS[0]}"',
        'tlc_status="${PIPESTATUS[0]}"',
    ):
        if formal_job.count(status_capture) != 1:
            raise RuntimeError(
                f"{workflow_path}: Parliament formal job must contain exactly one "
                f"{status_capture!r}"
            )
    if formal_job.count("name: sora-parliament-formal-pr") != 1:
        raise RuntimeError(
            f"{workflow_path}: Parliament formal artifact name must appear exactly once"
        )

    for spec_path in ("specs/governance_pipeline.md", "specs/governance_api.md"):
        spec = read(spec_path)
        folded = " ".join(spec.casefold().split())
        for retired in (
            "proposal-time JIT",
            "proposal-time Parliament snapshot",
            "Proposal-backed PLAIN",
        ):
            if retired.casefold() in folded:
                raise RuntimeError(f"{spec_path}: retired Parliament wording {retired!r}")
        for required in (
            "rollback-isolated",
            "ExecutionFailed",
            "ParliamentAutomaticExecutionOutcomeV1",
            "opening_phase_blocks",
            "parliament_sortition_pulse_delay_blocks",
            "ConsumeSortitionPulseBatch",
            "BeginInvitationAcceptance",
            "FailBodyElectionNoRoster",
            "SealBodyRoster",
            "RecordAttemptAbsence",
            "EndorsePublicFinding",
            "ceil(2 * original_seats / 3)",
            "endorsing_assignments",
            "parliament_public_finding_phase_blocks",
            "FailPublicFindingNoResult",
            "ParliamentNoResultKindV1",
            "not yet an operationally automatic",
        ):
            if required.casefold() not in folded:
                raise RuntimeError(
                    f"{spec_path}: missing automatic execution contract wording {required!r}"
                )

    telemetry_spec_path = "specs/telemetry.md"
    telemetry_spec = read(telemetry_spec_path)
    require_all(
        telemetry_spec_path,
        telemetry_spec,
        (
            "governance_parliament_transitions_total{transition}",
            "governance_parliament_no_result_total{class}",
            "governance_parliament_attempts_by_status{status}",
            "governance_parliament_attempts_by_stage{stage}",
            "ParliamentNoResultKindV1",
            "public_finding_quorum_unreachable",
            "public_finding_deadline_expired",
            "sortition_retries_exhausted",
            "confirmation_jury_capacity_unavailable",
            "never use proposal, governance-attempt, body, ballot, assignment, pulse,",
        ),
    )

    model_readme_path = "formal/sora_parliament/README.md"
    model_readme = " ".join(read(model_readme_path).split())
    require_all(
        model_readme_path,
        model_readme,
        (
            "mathematically irreversible splits",
            "permissionless caller eventually submitting the deadline trigger",
            "post-deadline non-response rejection",
            "empty or live electorate below three",
            "without revealing or consuming a pulse",
            "Policy binding, Confirmation requirement, and Confirmation request all",
            "same transition commits the Policy binding and Confirmation requirement",
            "one proposal-wide redraw budget",
            "successor governance attempt's first sortition",
            "Exact request/session transport replays are state-idempotent",
            "required Confirmation draw at an already exhausted ceiling fails closed",
        ),
    )
    pipeline_spec = read("specs/governance_pipeline.md")
    require_all(
        "specs/governance_pipeline.md",
        pipeline_spec,
        (
            "Coercion-Resistant Voting via Anamorphic",
            "10.1145/3750555.3811888",
            "Timed OVN neither implements nor",
        ),
    )

    print("SORA Parliament source/model contract: ok")
    return 0


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        raise SystemExit(main())
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
