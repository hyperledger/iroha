"""Independent SCCP E0--E4, anchor and offence-custody fixtures.

Python 3.11+, no downloads or environment variables. ``build()`` is consumed by
``generate.py``; source observations are explicit DATA, never live authority.
"""
from __future__ import annotations

from functools import lru_cache
from .bls_sig import fast_aggregate_verify
from .bls12_381 import G1_GENERATOR, g1_compress, g1_mul
from .common import U64_MAX, hx, rep, unhex
from .finality import (FinalityHeader, QcFixed, anchor_leaf, anchor_node,
                       build_certificate, committee_root, forgery_evidence_id,
                       inactive_header, parse_header, parse_qc_fixed, commit_message, commit_preimage, result_r)

GENERATOR = "two independent generators: python3.11 scripts/sccp_reference/generate.py --write; cargo test -p iroha_core --lib sccp -- --ignored regenerate_forgery_evidence_v1"
CONVENTION = "Explicit original-observation DATA exercises Core's production E0, signature, E1-E4, anchor and permanent-offence predicates; it grants no live authority. The record row separately replays authenticated native execution and projects its retained G6 bindings."
NETWORK = rep(0x11)
INSTANCE = rep(0x77)
VALIDITY = 1_209_600_000
GRACE = 604_800_000
CAP = 2_592_000_000


def committee():
    """Four sorted compressed keys from the explicitly public test scalars 1..4."""
    secret = {g1_compress(g1_mul(G1_GENERATOR, k)): k for k in range(1, 5)}
    return sorted(secret), secret


def path_root(height: int, core_hash: bytes, result: bytes, path: list[bytes]) -> bytes:
    """Fold the position-bound twelve-level retained anchor witness."""
    node = anchor_leaf(height, core_hash, result)
    index = (height - 1) % 4096
    for sibling in path:
        node = anchor_node(sibling, node) if index & 1 else anchor_node(node, sibling)
        index >>= 1
    return node


def classify(inp: dict, *, root: bytes) -> str:
    """The independently modeled ordered E0--E4 and anchor relation."""
    x = parse_header(unhex(inp["header"]))
    if not x.active or x.network_id != NETWORK:
        return "NotEvidence"
    if not inp["generation_retained"]:
        return "EvidenceExpired"
    if x.committee_root != root:
        return "NotEvidence"
    if inp["current_generation"] != 7 and inp["lc"] > inp["liable_until_lc"] + CAP:
        return "EvidenceExpired"
    if not verify_signature(inp["header"], inp["qc"], inp["aggregate_signature"]):
        return "BadSignature"
    if x.height < inp["start_height"] or (inp["end_height"] is not None and x.height > inp["end_height"]):
        return "E1"
    if x.height >= inp["execution_height"]:
        return "E2"
    if inp["anchor_source"] == "completed":
        if not inp["chunk_retained"]:
            return "EvidenceExpired"
        if inp["witness"] == "missing":
            return "WitnessRequired"
        path = [unhex(h) for h in inp["path"]]
        if path_root(x.height, unhex(inp["anchor_core_hash"]), unhex(inp["anchor_result"]), path) != unhex(inp["chunk_root"]):
            return "BadWitness"
    qc = unhex(inp["qc"])
    if qc[48:80] != unhex(inp["anchor_core_hash"]):
        return "E3"
    if result_r(unhex(inp["header"]), qc[80:112]) != unhex(inp["anchor_result"]):
        return "E4"
    return "NotEvidence"


@lru_cache(maxsize=None)
def verify_signature(header_hex: str, qc_hex: str, signature_hex: str) -> bool:
    """Verify the wire's exact-q Commit digest with the independent pairing implementation."""
    keys, _ = committee()
    x = parse_header(unhex(header_hex))
    qc = parse_qc_fixed(unhex(qc_hex))
    if qc.signers.bit_count() != 3 or qc.signers >> len(keys):
        return False
    result = result_r(unhex(header_hex), qc.result_body)
    message = commit_message(commit_preimage(INSTANCE, qc.epoch, qc.epoch_context, x.height,
                                             qc.view, qc.block_hash, result))
    return fast_aggregate_verify([key for i, key in enumerate(keys) if qc.signers & (1 << i)],
                                 message, unhex(signature_hex))


@lru_cache(maxsize=None)
def _certificate(height: int, mode: str, signers: int):
    keys, secret = committee()
    fields = FinalityHeader(NETWORK, height, 10_000, generation=7, committee_root=committee_root(keys))
    if mode == "header":
        fields = FinalityHeader(NETWORK, height, 10_001, generation=7, committee_root=committee_root(keys))
    if mode == "inactive":
        fields = inactive_header(NETWORK, height, 10_000)
    return build_certificate(keys=keys, secret_of=secret, signer_indices=[i for i in range(4) if signers & (1 << i)],
                             header=fields.encode(), instance=INSTANCE, epoch=2, epoch_context=rep(0x88), view=1,
                             block_hash=rep(0x98 if mode == "block" else 0x99), result_body=rep(0x67 if mode == "body" else 0x66))


def evidence_rows() -> list[dict]:
    keys, _ = committee()
    root = committee_root(keys)
    cases = [
        ("e0_inclusive_window", "A retained ended generation is still liable exactly at its capped boundary.", "body", 3, {}),
        ("e0_expired_window", "One liability-clock millisecond after the cap expires E0 before pairing.", "body", 3, {"lc": 1_000 + VALIDITY + GRACE + CAP + 1}),
        ("e1_before_start", "A valid quorum signs before the retained generation starts.", "body", 1, {}),
        ("e1_after_end", "Tenure ends before this signed future height; E1 precedes E2.", "body", 5, {"end_height": 4}),
        ("e2_future", "A quorum signs a height not yet committed by the original observation.", "body", 4, {}),
        ("e3_stray_commit_completion", "A quorum completes stray Commit votes for a competing block that never committed.", "block", 3, {}),
        ("e4_false_header", "The original core hash carries a false X.", "header", 3, {}),
        ("e4_genuine_x_different_body", "Genuine X with a different D_body changes the certified outer result.", "body", 3, {}),
        ("genuine_certificate", "The genuine block and result are never evidence.", "genuine", 3, {}),
        ("genuine_other_valid_signers", "A different valid exact quorum for the same genuine result is never evidence.", "genuine", 3, {"signers": 11}),
        ("anchor_tip", "The original tip supplies its own anchor without a witness.", "body", 3, {}),
        ("anchor_open_chunk", "The original open chunk supplies height two without a witness.", "body", 2, {"anchor_source": "open"}),
        ("anchor_completed_chunk", "A retained completed root authenticates the original twelve-sibling witness.", "body", 2, {"anchor_source": "completed", "execution_height": 4098}),
        ("anchor_missing_witness", "A completed chunk refuses an absent witness.", "body", 2, {"anchor_source": "completed", "execution_height": 4098, "witness": "missing"}),
        ("anchor_wrong_path", "A changed sibling does not reach the retained completed root.", "body", 2, {"anchor_source": "completed", "execution_height": 4098, "witness": "wrong"}),
        ("anchor_pruned_chunk", "A witness cannot restore a pruned authoritative root.", "body", 2, {"anchor_source": "completed", "execution_height": 4098, "chunk_retained": False}),
        ("pruned_generation", "A generation missing from retained state has expired.", "body", 3, {"generation_retained": False}),
        ("inactive_x", "An inactive X makes no SCCP claim.", "inactive", 3, {}),
        ("e4_active_at_degraded_height", "An ACTIVE claim differs from the original inactive result at a degraded height.", "genuine", 3, {"degraded_anchor": True}),
    ]
    rows = []
    for label, description, mode, height, change in cases:
        signers = change.get("signers", 7)
        cert = _certificate(height, mode, signers)
        genuine = _certificate(height, "genuine", 7)
        anchor_result = result_r(inactive_header(NETWORK, height, 10_000).encode(), rep(0x66)) if change.get("degraded_anchor") else genuine.meta["r"]
        path = [rep(4)] * 12
        chunk_root = path_root(height, rep(0x99), anchor_result, path)
        inp = dict(header=hx(cert.header), qc=hx(cert.qc), aggregate_signature=hx(cert.signature_ton), signature_evm=hx(cert.signature_evm),
                   generation_retained=True, current_generation=8, lc=1_000 + VALIDITY + GRACE + CAP,
                   liable_until_lc=1_000 + VALIDITY + GRACE, start_height=2, end_height=None,
                   execution_height=4, anchor_source="tip", anchor_core_hash=hx(rep(0x99)),
                   anchor_result=hx(anchor_result), chunk_root=hx(chunk_root), path=[hx(h) for h in path],
                   chunk_retained=True, witness="present")
        inp.update({k: v for k, v in change.items() if k not in ("signers", "degraded_anchor")})
        if inp["witness"] == "wrong":
            inp["path"][0] = hx(bytes([5]) + rep(4, 31))
        outcome = classify(inp, root=root)
        rows.append(dict(label=label, description=description, input=inp,
                         expected=dict(outcome=outcome, message=hx(cert.meta["m"]), result=hx(cert.meta["r"]),
                                       evidence_id=hx(forgery_evidence_id(parse_header(cert.header).generation, cert.meta["m"], signers)))))
    return rows


def dedup_rows() -> list[dict]:
    """Permanent offence identity is generation plus original lane/account, not certificate id."""
    seen = 0
    rows = []
    for label, signers in (("first_signer_set", 7), ("same_signer_set", 7), ("different_signer_set", 11)):
        new = signers & ~seen
        rows.append(dict(label=label, input=dict(generation=7, signers=signers, already_recorded=seen),
                         expected=dict(outcome="Recorded" if new else "EvidenceDuplicate", new_signers=new,
                                       evidence_id=hx(forgery_evidence_id(7, _certificate(4, "body", signers).meta["m"], signers)))))
        seen |= new
    return rows


def build() -> dict:
    """Rebuild every shared value without reading Rust or a committed fixture."""
    keys, _ = committee()
    return dict(schema="iroha.sccp.forgery_evidence.v1", generator=GENERATOR, conventions=CONVENTION,
                constants=dict(network_id=hx(NETWORK), consensus_instance=hx(INSTANCE), committee_keys=[hx(k) for k in keys],
                               committee_root=hx(committee_root(keys)), n=4, q=3, generation=7,
                               start_lc=1_000, validity_ms=VALIDITY, grace_ms=GRACE, progress_cap_ms=CAP),
                rows=evidence_rows(), deduplication=dedup_rows(),
                record=dict(label="self_contained_g6_record", description="Authenticated native genesis and one committed successor produce a verified future claim. The retained record uses start_height, not the attacker height, and copies each original G6 binding; the projection omits chain-specific hashes.",
                            input=dict(generation=1, start_height=1, committed_height=2, claimed_height=3, signers=7),
                            expected=dict(rule="E2", offence_height=1, signed_height=3, generation=1, penalty_status="Pending", self_contained=True,
                                          offenders=[dict(signer=i, lane_id=0, activation_height=1, matches_original_g6=True) for i in range(3)])))
