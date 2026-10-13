# Ballot-proof cross-implementation vectors

**These are this project's own cross-implementation vectors, not official vectors
of any specification.** They are experimental: no ballot proof profile is selected
or qualified, and nothing here is evidence of security.

## What they are

The files were produced by the project's pure-Python prototype of the two ballot
proofs (registration and vote) on a pure-Python FAEST v3.0 backend, for the
byte-level protocol frozen for investigation in
`specs/parliament_ballot_proof_profile.md` sections 6.1 to 6.3, 6.6 and 6.7
(`SUITE` ending in `NS-PREFIX77`, the 77-byte role prefix on every backend hash
call). The prototype's backend reproduces the official FAEST v3.0.2 vectors in
reference mode (empty prefix); the ballot vectors themselves have no official
counterpart. They pin one independent reading of the record against another: the
Rust crate and the prototype share no code.

The `Enc(...)` inputs are opaque test byte strings, not Norito encodings. Every
fixture value derives from `SHAKE256("PARL-ballot-proto/fixture/v1/" || label)`.

## Files

Format: `name = hex`, integers little-endian, `*_shake256_64 = SHAKE256(x, 64 bytes)`.

| file | content |
|---|---|
| `<case>.txt` | inputs (tape, secret, opaque inputs, list position, vote), derived public values (`B`, `C`, `D_reg`, `auth`, `scope`, `R`, `nf`, `T_crt`, `DESC`, `D`, `NS_REG`, `NS_VOTE`, `PREFIX_R`, `F_R`, `mu`), transcript values, and SHAKE256-64 digests of the witness, of each proof field and of the complete proof, with the accepted counter |
| `<case>.intermediate.txt` | the SHAKE messages, the eleven committed Keccak states of both permutations, the selector words, and prover coefficient vectors of 48 constraints |
| `vote_S3_i1_<row>.list.txt` | the three-entry sealed list |

Cases: `reg_fast`, `vote_S3_i1_fast`, `vote_S1000_i500_fast` (candidate row),
`reg_comparator`, `vote_S3_i1_comparator` (comparator row).

Not stored, to keep the directory small:

* the complete proofs (159,588 / 159,852 / 109,114 / 109,290 bytes): the tests
  compare the digest of every proof field and of the whole proof;
* the 1,000-entry list of `vote_S1000_i500_fast`: the test re-derives it by the
  prototype's rule (the commitments of the fixture members `0 .. 1000` for the
  fixture body, sorted) and checks `list_concat_shake256_64` and `R`;
* the per-coordinate VOLE tags `V_i` (2.7 MB a case), which the coefficient
  vectors of the relation constraints would need. Only the first sixteen `V_i` are
  in the intermediate files.

What the Rust tests do with the intermediate files: the SHAKE messages, the
initial states and the final states are compared with the crate's `public_block`
and `evaluate`, the eleven committed states of each permutation and the selector
words with the generated witness. The stored prover coefficient vectors
(`constraint_*_a*`) and the sixteen `V_i` are **not** reproduced by the Rust
tests; the proof-field digests cover them.

Consumed by `tests/vectors.rs`.

## Provenance

Copied unchanged from the prototype's `vectors/` directory after its final review
round. SHA-256 of the copied files:

```text
9add328ba0ecc3a3f2c85cf227ba7ed27c8011ca4818227dfea9e43f4897eaac  reg_comparator.intermediate.txt
4fd711a874c878e00e963c1f4990654a19e7f06562c329d765e5e56b98965f24  reg_comparator.txt
7b28b67f0f0759bf514e1fd6be60331bead1af86c021f5a4a5d0d51072680a73  reg_fast.intermediate.txt
4cd3599007b820fd4057782e4f311d0a83d0826984a9092a4b544480ff9b4e14  reg_fast.txt
72369b46d8e4eeb5dc9cfccf0691c8d8eee40ac9866ce7239343f91881d679c8  vote_S1000_i500_fast.intermediate.txt
036ac14095ff9e18cf05dfb90ee13f1e1b0c29c365287a6a86fb0a7169bd338e  vote_S1000_i500_fast.txt
f118b89a3f39eab56977642fefea5d3ef01223ec0e8e7ac0cbed7d9f0037c5ca  vote_S3_i1_comparator.intermediate.txt
2a2de49c6356c4195c4b6c1f899a531a216ff1006345057932f50b4d0e4b8ed9  vote_S3_i1_comparator.list.txt
4c5cbc90439e0aa9ff07243f041ca4fe2fe24ea0101c5c9a0c26227b589ffc2c  vote_S3_i1_comparator.txt
c73aa94ef1bc04ecd25086f22eea38d73a34a369d2c67692f045515bd098e13c  vote_S3_i1_fast.intermediate.txt
0553d9976a36a47b775b20d8f01d9aabd32c7aa40a6081ea615640c3084370e7  vote_S3_i1_fast.list.txt
1456c67db2c70b20bcfefd4b240b29e751155842a07c85b21bdb6bfc4fb12f8e  vote_S3_i1_fast.txt
```
