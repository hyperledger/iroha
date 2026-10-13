#!/usr/bin/env python3
"""Generate the final standalone ballot vectors, independently of the Rust code.

Run with Python 3.10+ and only the standard library. --output-dir is required;
the directory receives deterministic text, complete proof and intermediate files.
The comparator can take around 30 minutes per case on the development machine.
No files are submitted, signed, downloaded, or written outside --output-dir.

Proofs are checked by this reference verifier before their fields and hashes are
written. These are project-generated experimental vectors, never official FAEST
vectors or a security certificate. See README.md for reproduction commands.
"""
import argparse
import hashlib
import multiprocessing
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ballot as BL  # noqa: E402
import faest as FZ  # noqa: E402
import fixtures as FX  # noqa: E402

VEC = os.path.join(HERE, "vectors")
HEADER = [
    "# EXPERIMENTAL ballot-proof vectors for the final standalone construction (2026-10-13).",
    "# Strengthened vote relation: nf128, auth_v64, three permutations; tape112, salt32,",
    "# salted H5, 20-bit counter in LE32, affine112 leaf; SUITE129 and DESC286.",
    "# Generated independently in Python from specs/parliament_ballot_proof_profile.md.",
    "# No profile is selected or qualified. Opaque test inputs are not Norito encodings.",
    "# Format: name = hex; integers little-endian; digests are SHAKE256(x, 64 bytes).",
]
FIELD_NAMES = ["c", "c_mult", "u_tilde", "d", "a_tilde_1_6", "hidden_leaf_commitments",
               "node_seeds", "chall_3", "iv_pre", "salt", "ctr"]


def dg(x):
    return hashlib.shake_256(x).digest(64)


def write(path, title, pairs):
    with open(path, "w") as fh:
        fh.write("\n".join(HEADER) + "\n# " + title + "\n")
        for k, v in pairs:
            fh.write("%s = %s\n" % (k, bytes(v).hex()))


def fe(x):
    return x.to_bytes(32, "little")


def gen(spec):
    t0 = time.time()
    case = FX.reg_case(spec[0]) if spec[1] == "reg" else FX.vote_case(spec[0], spec[2], spec[3])
    row, kind, stmt, sk, tape = case["row"], case["kind"], case["stmt"], case["sk"], case["tape"]
    name = "%s_%s" % (kind, row) if kind == "reg" else "vote_S%d_i%d_%s" % (spec[2], spec[3], row)
    title = "case %s: relation %s, row %s %r" % (name, kind, row, BL.ROWS[row][1:])
    tr = {}
    proof = BL.prove(row, kind, stmt, sk, tape, case["index"], trace=tr)
    tv = {}
    assert BL.verify(row, kind, stmt, proof, trace=tv)
    assert tv["a0"] == tr["at"][0]
    ctx = tr["ctx"]
    ell = BL.ELL[kind]
    wbytes = tr["witness"].to_bytes(ell // 8, "little")
    F = FZ.field(256)
    pairs = [("tape", tape), ("tape_r", tape[:32]), ("tape_iv_pre", tape[32:48]),
             ("tape_pad", tape[48:80]), ("tape_salt", tape[80:112]), ("sk", sk), ("P16", BL.P16)]
    if kind == "reg":
        pairs += [("enc_body_context", stmt["enc_body_context"])]
        pairs += [(k, stmt[k]) for k in BL.REG_ENC_FIELDS]
        pre = ctx.prefix + ctx.F + b"\x08"
        pairs += [("B", ctx.B), ("C", stmt["C"]), ("T_crt", BL.t_crt(row)),
                  ("descriptor", BL.descriptor(row)),
                  ("D", ctx.D), ("D_reg", ctx.D_reg), ("auth", stmt["auth"]),
                  ("NS_REG", ctx.ns), ("NS_VOTE", BL.namespace(ctx.D, "VOTE")),
                  ("PREFIX_REG", ctx.prefix), ("F_REG", ctx.F)]
        msgs = FX.msgs_for(case)
        perm_names = ("C", "A")
    else:
        pairs += [("enc_body_context", FX.ENC_BODY), ("enc_network_id", FX.ENCS[0]),
                  ("enc_governance_attempt_id", FX.ENCS[3]),
                  ("enc_canonical_proposal_content", FX.ENC_PROPOSAL),
                  ("enc_body_instance_id", FX.ENC_BODY_INSTANCE),
                  ("enc_complete_frozen_policy", FX.ENC_POLICY),
                  ("B", ctx.B), ("proposal_digest", case["proposal_digest"]),
                  ("scope", stmt["scope"]), ("policy_hash", stmt["policy_hash"]),
                  ("S_u16", BL.u16(stmt["S"])), ("index_u16", BL.u16(case["index"])),
                  ("vote_u8", BL.u8(stmt["vote"])), ("C_member", stmt["L"][case["index"]]),
                  ("list_concat_shake256_64", dg(b"".join(stmt["L"]))), ("R", stmt["R"]),
                  ("nf", stmt["nf"]),
                  ("vote_auth_frame_len_u32", BL.u32(len(BL.vote_auth_frame(
                      ctx.D, ctx.B, stmt["scope"], stmt["R"], stmt["S"], stmt["L"], stmt["nf"],
                      stmt["vote"], stmt["policy_hash"])))),
                  ("vote_auth_frame_shake256_64", dg(BL.vote_auth_frame(
                      ctx.D, ctx.B, stmt["scope"], stmt["R"], stmt["S"], stmt["L"], stmt["nf"],
                      stmt["vote"], stmt["policy_hash"]))),
                  ("D_v", ctx.D_v), ("auth_v", stmt["auth_v"]), ("T_crt", BL.t_crt(row)),
                  ("descriptor", BL.descriptor(row)), ("D", ctx.D),
                  ("NS_REG", BL.namespace(ctx.D, "REG")), ("NS_VOTE", ctx.ns),
                  ("PREFIX_VOTE", ctx.prefix)]
        pre = ctx.prefix + ctx.F + b"\x08"
        if len(ctx.F) <= 2048:
            pairs.append(("F_VOTE", ctx.F))
        pairs.append(("F_VOTE_len_u32", BL.u32(len(ctx.F))))
        pairs.append(("F_VOTE_shake256_64", dg(ctx.F)))
        if len(ctx.F) <= 2048:
            pairs.append(("vote_auth_frame", BL.vote_auth_frame(
                ctx.D, ctx.B, stmt["scope"], stmt["R"], stmt["S"], stmt["L"], stmt["nf"],
                stmt["vote"], stmt["policy_hash"])))
        write(os.path.join(VEC, name + ".list.txt"), title + " - the list L, in order",
              [("L_%04d" % i, c) for i, c in enumerate(stmt["L"])])
        msgs = FX.msgs_for(case)
        perm_names = ("C", "N", "V")
    ts = BL.test_statement(row, kind, stmt)
    pairs += [("mu_shake_input_shake256_64", dg(pre)), ("mu", tr["mu"]), ("iv", tr["iv"]),
              ("test_statement_shake256_64", dg(ts)),
              ("test_record_shake256_64", dg(BL.test_record(row, kind, stmt, proof))),
              ("witness_bits_u32", BL.u32(ell)), ("witness_shake256_64", dg(wbytes)),
              ("n_constraints_u32", BL.u32(tr["n_constraints"])),
              ("bavc_com", tr["com"]), ("chall_1", tr["chall1"]), ("chall_2", tr["chall2"]),
              ("v_tilde", b"".join(fe(x) for x in tr["v_t"])),
              ("vole_u_shake256_64", dg(tr["u"].to_bytes(ell // 8, "little"))),
              ("vole_V_shake256_64", dg(b"".join(fe(x) for x in tr["V"]))),
              ("vole_Q_shake256_64", dg(b"".join(fe(x) for x in tv["Q"]))),
              ("delta", fe(tv["delta"]))]
    pairs += [("a_tilde_%d" % j, fe(x)) for j, x in enumerate(tr["at"])]
    pairs += [("ctr_u32", BL.u32(tr["ctr"]))]
    layout = BL.proof_fields(row, kind, proof)
    assert len(layout) == len(FIELD_NAMES)
    for nm, (_long, off, ln) in zip(FIELD_NAMES, layout):
        pairs += [("field_%s_offset_u32" % nm, BL.u32(off)), ("field_%s_len_u32" % nm, BL.u32(ln)),
                  ("field_%s_shake256_64" % nm, dg(proof[off:off + ln]))]
    pairs += [("proof_len_u32", BL.u32(len(proof))), ("proof_shake256_64", dg(proof))]
    write(os.path.join(VEC, name + ".txt"), title, pairs)
    write(os.path.join(VEC, name + ".proof.hex"), title + " - complete raw proof", [("proof", proof)])
    # ---- intermediate values
    inter = []
    assert len(msgs) == len(perm_names) == BL.N_PERMS[kind]
    for d in range(len(msgs)):
        init = msgs[d] + b"\x1f\x00\x00\x80" + bytes(64)
        states, final = BL.permutation_states(msgs[d])
        inter.append(("shake_message_%s" % perm_names[d], msgs[d]))
        inter.append(("state_%s_round00_initial" % perm_names[d], init))
        for g in range(11):
            inter.append(("state_%s_round%02d_witness_offset_%d" % (
                perm_names[d], 2 * g + 2, BL.PERM_OFF[d] + 1600 * g), states[g].to_bytes(200, "little")))
        inter.append(("state_%s_round24_final" % perm_names[d], final.to_bytes(200, "little")))
    if kind == "vote":
        inter.append(("selector_a_u32", BL.u32((tr["witness"] >> BL.SEL_A_OFF) & 0xFFFFFFFF)))
        inter.append(("selector_b_u32", BL.u32((tr["witness"] >> BL.SEL_B_OFF) & 0xFFFFFFFF)))
    V = tr["V"]
    wbits = FZ.int_to_bits(tr["witness"], ell)
    first = FZ.booleanity(FZ.ProverBackend(F), [[V[i], wbits[i]] for i in range(16)])
    n = tr["n_constraints"]
    for i in range(16):
        inter.append(("V_%05d" % i, fe(V[i])))
    # every V the 48 coefficient vectors read is in the full dump: one line per witness coordinate
    assert len(V) == ell
    write(os.path.join(VEC, name + ".V.txt"),
          title + " - the prover's VOLE values V_i (field elements, 32 bytes little-endian), one "
          "per witness coordinate i = 0..l-1; SHAKE256-64 of their concatenation is "
          "vole_V_shake256_64 in the main file.  The committed polynomial of coordinate i is "
          "V_i + w_i X", [("V_%05d" % i, fe(V[i])) for i in range(ell)])
    for idx, c in (list(enumerate(first)) + list(zip(range(ell, ell + 16), tr["rel_first16"]))
                   + list(zip(range(n - 16, n), tr["last16"]))):
        assert len(c) == 8 and c[7] == 0
        for j in range(8):
            inter.append(("constraint_%05d_a%d" % (idx, j), fe(c[j])))
    write(os.path.join(VEC, name + ".intermediate.txt"),
          title + " - Keccak states (200 bytes, bit t = 64(x+5y)+z, little-endian) and the "
          "degree-7 coefficient vectors a0..a7 (field elements, 32 bytes little-endian) of the "
          "first 16 constraints (booleanity of the pad), the first 16 after the booleanity "
          "block, and the last 16 constraints", inter)
    return name, len(proof), tr["ctr"], dg(proof).hex(), time.time() - t0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--jobs", type=int, choices=range(1, 9), default=4)
    parser.add_argument("--row", choices=("fast", "comparator"), action="append")
    parser.add_argument("--seats", type=int, choices=(3, 500, 1000), action="append")
    args = parser.parse_args(argv)
    global VEC
    VEC = os.path.abspath(args.output_dir)
    os.makedirs(VEC, exist_ok=True)
    specs = []
    for row in dict.fromkeys(args.row or ("fast", "comparator")):
        specs.append((row, "reg"))
        specs.extend((row, "vote", size, size // 2)
                     for size in dict.fromkeys(args.seats or (3, 500, 1000)))
    with multiprocessing.get_context("fork").Pool(min(args.jobs, len(specs))) as pool:
        for res in pool.imap_unordered(gen, specs):
            print("%s: %d bytes, ctr %d, proof SHAKE256-64 %s (%.0f s)" % res, flush=True)
    print("Final standalone vectors written; no profile is selected or qualified.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
