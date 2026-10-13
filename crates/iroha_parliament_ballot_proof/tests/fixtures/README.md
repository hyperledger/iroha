# Ballot-proof cross-implementation vectors

These are independent implementation test vectors for the experimental construction
in `specs/parliament_ballot_proof_profile.md` section 6. They are not official
FAEST vectors, a security proof, or evidence that a ballot profile is qualified.
No profile is selected and the node does not use this crate.

The final construction uses the strengthened vote relation (128-byte nullifier,
64-byte vote authorization, three Keccak permutations), a 112-byte proving tape,
a 32-byte public salt in challenge 1 and H5, a 20-bit counter encoded LE32, and
112-byte affine leaf commitments. The exact suite is 129 bytes and its descriptor
is 286 bytes. Retired descriptors and proof layouts have no compatibility path.

## Reproduce

The independent Python generator is preserved in [../reference](../reference/README.md).
From the repository root:

```sh
python3.11 -I crates/iroha_parliament_ballot_proof/tests/reference/gen_vectors.py \
  --output-dir /tmp/parliament-ballot-vectors --jobs 4
```

Every public test secret and tape derives deterministically from
`SHAKE256("PARL-ballot-proto/fixture/v1/" || label)`. The opaque application
inputs are test byte strings, not Norito encodings. Never use these secrets or
tapes for a real ballot.

## Retained files

| File | Content |
|---|---|
| `<case>.txt` | Inputs, derived public values including `D_v` and `auth_v`, transcript fields, witness and field digests, offsets, lengths, and accepted counter |
| `<case>.intermediate.txt` | SHAKE messages, initial/final and committed states of every application permutation, selectors, and sampled constraint coefficients |
| `<case>.proof` | Complete naked proof bytes, decoded without modification from the generator's `proof = hex` line |
| `vote_S3_i1_<row>.list.txt` | The three-entry sealed list |
| `SHA256SUMS` | Hashes of all retained vector files |

Both rows have registration and vote cases at 3, 500 and 1,000 seats. The large
lists are re-derived by the shared fixture rule (member commitments sorted by
unsigned bytes) and checked against the list digest. Large internal VOLE tag dumps
are not retained.

`tests/vectors.rs` compares every byte of each complete proof, every proof field's
offset/length/digest, descriptor and namespaces, the public values and frames,
witness digest, and every committed application state against the independently
generated values. The stored sampled prover constraint coefficients and initial
VOLE values are not individually reproduced; proof bytes cover their resulting
transcript. The same vectors run with portable arithmetic and with `accel`.

The reference code and fixture agreement establish implementation conformance
only. Primitive assumptions, independent cryptographic review, complete production
envelopes, validator/phone performance, memory, and side-channel qualification
remain open.
