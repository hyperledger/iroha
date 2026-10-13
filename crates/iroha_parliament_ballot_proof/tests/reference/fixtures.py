#!/usr/bin/env python3
"""Deterministic public test inputs for the independent ballot-proof reference.

Every secret and tape is SHAKE256 of a fixture label. Enc(...) strings are opaque
test bytes; production Norito mappings are outside this standalone experiment.
The final construction uses a 112-byte tape, 128-byte nullifier and 64-byte vote
authorization under the 286-byte descriptor. Never use these public test secrets.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ballot as BL  # noqa: E402


def fx(label, n):
    return hashlib.shake_256(b"PARL-ballot-proto/fixture/v1/" + label).digest(n)


ENC_BODY = b"enc:body_context:fixture-body-1"
ENCS = [b"enc:network_id:fixture-net", b"enc:authority:fixture-authority",
        b"enc:assignment_id:0001", b"enc:governance_attempt_id:0007",
        b"enc:election_attempt_id:0003", b"enc:body_role:member"]
ENC_PROPOSAL = b"enc:canonical_proposal_content:fixture-proposal"
ENC_BODY_INSTANCE = b"enc:body_instance_id:fixture-instance"
ENC_POLICY = b"enc:complete_frozen_policy:fixture-policy"


def member_sk(j):
    return fx(b"member-sk-%d" % j, BL.SK_BYTES)


def reg_case(row, member=0, tape_label=b"reg"):
    sk = member_sk(member)
    b = BL.body_digest(ENC_BODY)
    c = BL.commitment(sk, b)
    d = BL.descriptor_digest(row)
    d_reg = BL.reg_auth_digest(d, ENC_BODY, ENCS, b, c)
    auth = BL.auth_value(sk, d_reg)
    return {"row": row, "kind": "reg", "sk": sk, "B": b, "C": c, "D": d, "D_reg": d_reg,
            "auth": auth, "stmt": BL.reg_statement(ENC_BODY, list(ENCS), c, auth),
            "tape": fx(b"tape/" + tape_label + b"/" + row.encode(), BL.TAPE_BYTES),
            "index": None}


_LISTS = {}


def member_list(s):
    """-> (sorted commitments, sks in the same order)."""
    if s not in _LISTS:
        b = BL.body_digest(ENC_BODY)
        pairs = sorted((BL.commitment(member_sk(j), b), member_sk(j)) for j in range(s))
        _LISTS[s] = ([p[0] for p in pairs], [p[1] for p in pairs])
    return _LISTS[s]


def vote_case(row, s, pos, vote=0, tape_label=b"vote"):
    b = BL.body_digest(ENC_BODY)
    lst, sks = member_list(s)
    sk = sks[pos]
    prop = BL.proposal_digest(ENC_PROPOSAL)
    scope = BL.scope_digest(ENCS[0], prop, ENCS[3], ENC_BODY_INSTANCE)
    pol = BL.policy_hash(ENC_POLICY)
    nf = BL.nullifier(sk, scope)
    stmt = signed_vote_statement(row, sk, b, scope, lst, nf, vote, pol)
    return {"row": row, "kind": "vote", "sk": sk, "B": b, "scope": scope, "nf": nf,
            "policy_hash": pol, "proposal_digest": prop, "L": lst, "sks": sks, "S": s,
            "index": pos, "vote": vote, "D": BL.descriptor_digest(row),
            "D_v": BL.statement_vote_auth_digest(row, stmt), "auth_v": stmt["auth_v"],
            "stmt": stmt,
            "tape": fx(b"tape/" + tape_label + b"/%d/%d/" % (s, pos) + row.encode(),
                       BL.TAPE_BYTES)}


def signed_vote_statement(row, sk, b, scope, lst, nf, vote, pol):
    """A vote statement whose auth_v is the vote authorization value of `sk` for exactly these
    fields (R recomputed from the list, D_v recomputed under the row's descriptor)."""
    st = BL.vote_statement(b, scope, lst, nf, bytes(64), vote, pol)
    st["auth_v"] = BL.vote_auth_value(sk, BL.statement_vote_auth_digest(row, st))
    return st


def resign(case, sk=None, **changes):
    """The case's statement with `changes` applied and auth_v recomputed with `sk` for the
    changed statement (what a cheater who knows a secret can always do)."""
    st = dict(case["stmt"])
    st.update(changes)
    if "L" in changes and "R" not in changes:
        st["R"] = BL.list_digest(st["B"], st["L"], validate=False)
        st["S"] = len(st["L"])
    st["auth_v"] = BL.vote_auth_value(case["sk"] if sk is None else sk,
                                      BL.statement_vote_auth_digest(case["row"], st))
    return st


def honest_witness(case, pad=None):
    ctx = BL.public_context(case["row"], case["kind"], case["stmt"])
    pad = case["tape"][48:80] if pad is None else pad
    return ctx, BL.honest_witness(ctx, pad, case["sk"], case["index"])


def msgs_for(case, sk=None, x1=None, x2=None):
    """The SHAKE messages of a relation (2 for registration, 3 for a vote), optionally with
    another sk, another second 64-byte input (D_reg / scope) or another third one (D_v)."""
    sk = case["sk"] if sk is None else sk
    if case["kind"] == "reg":
        return [BL.shake_message(b"PCR1", sk, case["B"]),
                BL.shake_message(b"PAU1", sk, case["D_reg"] if x1 is None else x1)]
    return [BL.shake_message(b"PCR1", sk, case["B"]),
            BL.shake_message(b"PNF1", sk, case["scope"] if x1 is None else x1),
            BL.shake_message(b"PAV1", sk, case["D_v"] if x2 is None else x2)]


def dv(case, stmt):
    return BL.statement_vote_auth_digest(case["row"], stmt)


def _replace_state(w, perm, g, new_state):
    off = BL.PERM_OFF[perm] + BL.STATE_BITS * (g - 1)
    mask = ((1 << BL.STATE_BITS) - 1) << off
    return (w & ~mask) | (new_state << off)


def faults(case):
    """[(name, statement, invalid witness int, note)] : the semantic faults of the check list.
    The statement is the one the (cheating) prover and the verifier agree on."""
    kind, sk, stmt = case["kind"], case["sk"], case["stmt"]
    pad = case["tape"][48:80]
    other_sk = fx(b"other-sk", BL.SK_BYTES)
    out = []
    bw = BL.build_witness
    if kind == "reg":
        row = case["row"]
        out.append(("wrong sk", stmt, bw("reg", pad, other_sk, msgs_for(case, sk=other_sk)),
                    "honest states of another secret"))
        # public C of another member, D_reg and auth recomputed by the cheater with its own sk
        c2 = BL.commitment(member_sk(1), case["B"])
        d2 = BL.reg_auth_digest(case["D"], ENC_BODY, ENCS, case["B"], c2)
        st2 = BL.reg_statement(ENC_BODY, list(ENCS), c2, BL.auth_value(sk, d2))
        out.append(("right sk, public C of another member", st2,
                    bw("reg", pad, sk, [BL.shake_message(b"PCR1", sk, case["B"]),
                                        BL.shake_message(b"PAU1", sk, d2)]),
                    "auth is honest for the false statement"))
        # auth computed for another D_reg (another network id)
        encs3 = [b"enc:network_id:other-net"] + ENCS[1:]
        d3 = BL.reg_auth_digest(case["D"], ENC_BODY, encs3, case["B"], case["C"])
        st3 = BL.reg_statement(ENC_BODY, list(ENCS), case["C"], BL.auth_value(sk, d3))
        out.append(("auth for another D_reg (states of the statement's D_reg)", st3,
                    bw("reg", pad, sk, msgs_for(case)), "public auth is Auth_D'(sk)"))
        out.append(("auth for another D_reg (states of the other D_reg)", st3,
                    bw("reg", pad, sk, msgs_for(case, x1=d3)), "public auth is Auth_D'(sk)"))
        alt, _ = BL.permutation_states(msgs_for(case, sk=other_sk)[1])
        out.append(("intermediate state A_A^(22) from a different message", stmt,
                    _replace_state(bw("reg", pad, sk, msgs_for(case)), 1, 11, alt[10]), ""))
        alt, _ = BL.permutation_states(msgs_for(case, sk=other_sk)[0])
        out.append(("intermediate state A_C^(12) from a different message", stmt,
                    _replace_state(bw("reg", pad, sk, msgs_for(case)), 0, 6, alt[5]), ""))
        return out
    s, i0 = case["S"], case["index"]
    row = case["row"]
    msgs = msgs_for(case)
    a0, b0 = 1 << (i0 // 32), 1 << (i0 % 32)
    out.append(("wrong sk", stmt, bw("vote", pad, other_sk, msgs_for(case, sk=other_sk), i0),
                "honest states of a secret that is not in the list"))
    out.append(("right sk, selectors on another member", stmt,
                bw("vote", pad, sk, msgs, (i0 + 1) % s), "selects C of another member"))
    out.append(("index i = S encoded in the selectors", stmt,
                bw("vote", pad, sk, msgs, s), "one-hot selectors, position outside the list"))
    out.append(("index i = 1023 encoded in the selectors", stmt,
                bw("vote", pad, sk, msgs, 1023), "one-hot selectors, position outside the list"))
    out.append(("two a bits set", stmt,
                bw("vote", pad, sk, msgs, selectors=(a0 | (a0 << 1), b0)), "even parity"))
    out.append(("three a bits set", stmt,
                bw("vote", pad, sk, msgs, selectors=(a0 | (a0 << 1) | (a0 << 2), b0)),
                "odd parity: the sum constraint alone would pass"))
    out.append(("two b bits set", stmt,
                bw("vote", pad, sk, msgs, selectors=(a0, b0 | (b0 << 5))), "even parity"))
    out.append(("three b bits set", stmt,
                bw("vote", pad, sk, msgs, selectors=(a0, b0 | (b0 << 5) | (b0 << 9))),
                "odd parity: the sum constraint alone would pass"))
    out.append(("no selector bit set", stmt,
                bw("vote", pad, sk, msgs, selectors=(0, 0)), ""))
    scope2 = BL.scope_digest(ENCS[0], BL.proposal_digest(b"enc:another proposal"), ENCS[3],
                             ENC_BODY_INSTANCE)
    out.append(("nullifier states of another scope", stmt,
                bw("vote", pad, sk, msgs_for(case, x1=scope2), i0),
                "public nf, scope and auth_v unchanged"))
    # public nf of another scope; the cheater recomputes auth_v for the false statement, so the
    # vote-authorization equation holds and only the nullifier equation can fail
    st2 = resign(case, nf=BL.nullifier(sk, scope2))
    out.append(("public nf of another scope (states of the statement's scope)", st2,
                bw("vote", pad, sk, msgs_for(case, x2=dv(case, st2)), i0),
                "public nf is Tag_scope'(sk); auth_v honest for the false statement"))
    out.append(("public nf of another scope (states of the other scope)", st2,
                bw("vote", pad, sk, msgs_for(case, x1=scope2, x2=dv(case, st2)), i0),
                "public nf is Tag_scope'(sk); auth_v honest for the false statement"))
    # ---- version 2: nullifier right in its first 512 bits, wrong in the last 512
    nf_other = BL.nullifier(sk, scope2)
    st_half = resign(case, nf=case["nf"][:64] + nf_other[64:])
    assert st_half["nf"][:64] == case["nf"][:64] and st_half["nf"][64:] != case["nf"][64:]
    out.append(("nf correct in its first 512 bits, wrong in the last 512", st_half,
                bw("vote", pad, sk, msgs_for(case, x2=dv(case, st_half)), i0),
                "a 512-bit output check (version 1) would accept; auth_v honest for the "
                "false statement"))
    # ---- version 2: vote authorization
    pol2 = BL.policy_hash(b"enc:another policy")
    st_other = resign(case, policy_hash=pol2)             # the statement auth_v was made for
    d_other = dv(case, st_other)
    st3 = dict(stmt, auth_v=st_other["auth_v"])           # stated fields unchanged, D_v = case D_v
    assert dv(case, st3) == case["D_v"] != d_other
    out.append(("auth_v for another D_v (states of the stated D_v)", st3,
                bw("vote", pad, sk, msgs, i0), "public auth_v is AuthV_{D_v'}(sk)"))
    out.append(("auth_v for another D_v (states of the other D_v)", st3,
                bw("vote", pad, sk, msgs_for(case, x2=d_other), i0),
                "public auth_v is AuthV_{D_v'}(sk)"))
    # the vote byte is changed after auth_v was computed (the relay attack the change closes)
    st4 = dict(stmt, vote=(case["vote"] + 1) % 3)
    d4 = dv(case, st4)
    assert d4 != case["D_v"] and st4["auth_v"] == stmt["auth_v"]
    out.append(("vote byte changed after auth_v was computed (states of the recomputed D_v)", st4,
                bw("vote", pad, sk, msgs_for(case, x2=d4), i0),
                "vote %d -> %d; every other field and the witness secret unchanged" % (
                    case["vote"], st4["vote"])))
    out.append(("vote byte changed after auth_v was computed (the honest witness, states of the "
                "old D_v)", st4, bw("vote", pad, sk, msgs, i0),
                "the unmodified honest witness against the changed statement"))
    # one list entry (not the member's) changed after auth_v was computed; R recomputed, so the
    # statement passes public validation and the member's entry is still selected
    j = (i0 + 1) % s
    lst5 = list(case["L"])
    lst5[j] = lst5[j][:127] + bytes([lst5[j][127] ^ 1])
    BL.validate_list(lst5)                                # still strictly increasing
    st5 = BL.vote_statement(case["B"], case["scope"], lst5, case["nf"], stmt["auth_v"],
                            case["vote"], case["policy_hash"])
    d5 = dv(case, st5)
    assert d5 != case["D_v"] and st5["R"] != stmt["R"]
    out.append(("one list entry changed after auth_v was computed (states of the recomputed D_v)",
                st5, bw("vote", pad, sk, msgs_for(case, x2=d5), i0),
                "entry %d, one bit; R recomputed; the member's entry unchanged" % j))
    out.append(("one list entry changed after auth_v was computed (the honest witness, states of "
                "the old D_v)", st5, bw("vote", pad, sk, msgs, i0),
                "the unmodified honest witness against the changed statement"))
    alt, _ = BL.permutation_states(msgs_for(case, sk=other_sk)[0])
    out.append(("intermediate state A_C^(12) from a different message", stmt,
                _replace_state(bw("vote", pad, sk, msgs, i0), 0, 6, alt[5]), ""))
    alt, _ = BL.permutation_states(msgs_for(case, sk=other_sk)[1])
    out.append(("intermediate state A_N^(22) from a different message", stmt,
                _replace_state(bw("vote", pad, sk, msgs, i0), 1, 11, alt[10]), ""))
    alt, _ = BL.permutation_states(msgs_for(case, sk=other_sk)[2])
    out.append(("intermediate state A_V^(12) from a different message", stmt,
                _replace_state(bw("vote", pad, sk, msgs, i0), 2, 6, alt[5]), ""))
    out.append(("intermediate state A_V^(22) from a different message", stmt,
                _replace_state(bw("vote", pad, sk, msgs, i0), 2, 11, alt[10]), ""))
    out.append(("intermediate state A_V^(2) from a different message", stmt,
                _replace_state(bw("vote", pad, sk, msgs, i0), 2, 1, alt[0]), ""))
    return out
