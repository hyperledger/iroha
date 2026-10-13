#!/usr/bin/env python3
"""Reproduce the extended-backend KAT with the independent Python reference.

Pass the directory containing faest.py and crt_tables_ref.py. For the archived
reference, from the repository root:

    python3 -I crates/iroha_zkp_vole/tests/fixtures/extended_v1/generate.py \
        crates/iroha_parliament_ballot_proof/tests/reference

The result is text on stdout. No Rust code or Rust output is read.
"""

import hashlib
from pathlib import Path
import sys


def pattern(length, step, offset):
    """A fixed, public test input; these bytes are never production randomness."""
    return bytes((i * step + offset) % 256 for i in range(length))


def main():
    """Print the independently computed intermediate values and provenance."""
    reference = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(reference))
    import faest as f

    p = f.Params("faest_256f")
    p.extended = True
    p.prefix = pattern(77, 7, 1)
    p.ell = 320
    p.ell_hat = p.ell + f.N_MASK * p.d0
    p.C = 351
    iv = pattern(16, 1, 0xA0)
    root = pattern(32, 3, 1)
    salt = pattern(32, 1, 0xC0)
    h0 = f.H0(256, iv, p.prefix, p.extended)
    vc = f.bavc_commit(p, root, iv)
    node = p.L - 1
    node_key = vc["keys"][node]
    expanded = f.prg_bytes(node_key, iv, node, 144)
    sd, com = f.leaf_commit(p, node_key, iv, node, h0)
    label = pattern(32, 1, 0x10)
    h5_input = p.prefix + iv + salt + (5).to_bytes(4, "little") + label + b"\x05"
    squeezed = hashlib.shake_256(h5_input).digest(2)
    assert f.H5(256, iv, 5, label, p.prefix, salt) == (
        int.from_bytes(squeezed, "little") & 1023
    )
    mu = pattern(64, 1, 0)
    corrections = pattern(32 * 40, 31, 7)
    mult = pattern(880, 17, 3)
    iv_pre = pattern(16, 1, 0xB0)
    body = mu + vc["com"] + corrections + mult + iv_pre + salt
    challenge = f.H2(256, 1, body, 264, p.prefix)
    values = {
        "h0_output": h0,
        "leaf_node_key": node_key,
        "leaf_sd": sd,
        "leaf_b0": expanded[32:128],
        "leaf_b1": expanded[128:],
        "leaf_c0": com[:96],
        "leaf_c1": com[96:],
        "bavc_commitment": vc["com"],
        "h5_squeezed": squeezed,
        "chall1_input_digest": hashlib.shake_256(
            b"chall_1 input" + p.prefix + body + b"\x09"
        ).digest(32),
        "chall1_output": challenge,
        "pinned": hashlib.shake_256(
            h0 + expanded + com + vc["com"] + squeezed + challenge
        ).digest(16),
    }
    print("# Extended VOLE backend: independent Python known-answer values.")
    print("# Experimental and unqualified; not official FAEST reference vectors.")
    print("# Inputs and regeneration command: generate.py in this directory.")
    for name in ["faest.py", "crt_tables_ref.py"]:
        digest = hashlib.sha256((reference / name).read_bytes()).hexdigest()
        print(f"# SHA256 {name}: {digest}")
    for name, value in values.items():
        print(f"{name} = {value.hex()}")


if __name__ == "__main__":
    main()
