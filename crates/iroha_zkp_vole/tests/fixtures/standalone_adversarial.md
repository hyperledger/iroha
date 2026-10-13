# Standalone adversarial campaign and source inventory

This is bounded regression and source-review evidence for the standalone
Parliament candidate, dated 2026-10-13. It is not a fuzzing, constant-time,
allocation, or production qualification certificate. Production remains gated.

## Reproducible campaigns

Run from the repository root, once without and once with `--features accel`:

```sh
scripts/cargo_fast.sh --stable-local-metadata --target-slot parliament-backend --incremental -- test -p iroha_zkp_vole -p iroha_parliament_ballot_proof --release --test adversarial -- --nocapture
scripts/cargo_fast.sh --stable-local-metadata --target-slot parliament-backend --incremental -- test -p iroha_zkp_vole -p iroha_parliament_ballot_proof --release --test adversarial --features accel -- --nocapture
scripts/cargo_fast.sh --stable-local-metadata --target-slot parliament-backend --incremental -- clippy -p iroha_zkp_vole -p iroha_parliament_ballot_proof --test adversarial --all-features -- -D warnings
```

Both modes passed with identical SHA3-256 corpus/result digests:

| Campaign | Seed | Cases | True outcomes | False outcomes | Digest |
|---|---|---:|---:|---:|---|
| Backend | `5041524c4241434b` | 3,100 | 1,843 | 1,257 | `dda625d9e970dfc0651e76f5627a89684fa88f2319af5a7b371e73195e2b7c1b` |
| Ballot | `5041524c42414c4c` | 5,656 | 1,033 | 4,623 | `cace017fe544236ec94320349a6a6617c8df88d2ae0e149ce767c73dbad2a862` |

**True outcomes include syntactic parser acceptance of mutated bytes and valid
public statements; they do not mean invalid proofs verified.** Every designated
invalid full-verification case rejects. Most random proof bit mutations run only
the parser; selected late-invalid cases pass parsing and exercise complete
reconstruction/verification. The digest binds the ordered labels, input lengths,
input SHA3-256 hashes, and observed booleans. Every recorded callback is wrapped
in `catch_unwind`, with seed and case number reported on a panic.

The backend campaign covers all twelve official reference rows and both extended
rows: valid signatures/proofs, each proof-field truncation boundary, trailing
bytes, seeded bit changes and garbage, counter boundaries, opening padding,
mask padding where the row has it, and grinding bits. The ballot campaign covers
both rows and both roles: every truncation of the registration/S=3 statement
frames; field and record length mutations; body/opaque-field allocation caps;
invalid list sizes 0, 1, 2, and 1001 rejected before list copying; valid S=500 and
S=1000 statements; exact proof-field boundaries; counters; and late changes to
the coefficients, affine hidden commitment checksum, and salt. This finite
corpus does not replace coverage-guided fuzzing, sanitizer runs, an independent
review, or a sustained campaign across supported targets.

A separate [initial libFuzzer/ASan campaign](../../../iroha_parliament_ballot_proof/fuzz/README.md)
now retains its corpus, logs, bounds, source hashes and deterministic
portable/accel parser replay. Its two 60-second runs add parser evidence without
claiming sustained fuzz qualification or full proof verification coverage.

## Verifier allocation inventory

The following counts are requested vector payload bytes from the current
sources. They exclude allocator rounding/metadata, capacity slack, vector
headers, stack frames, caller-retained encodings, compiler temporaries, provider
state, and process runtime overhead. Their phase lifetimes matter; summing every
row would not describe a live peak. No whole-process upper bound is asserted.

Let `ell` be 35,840 bits for registration or 53,504 for vote; `lb=32`, `n_mask=10`,
and `W=ceil((ell+10*d0)/8)`. Candidate row: `(tau,n_delta,d0,L,n_mult) =
(33,248,8,6400,704)`; comparator: `(22,250,12,61440,696)`.

| Phase and source | Allocations and lifetimes |
|---|---|
| [Profile compilation](../../../iroha_parliament_ballot_proof/src/profile.rs), `Profile::new`, `crt_bytes` | Before reconstruction, `encode_words` and its byte serialization coexist: 10,538 candidate / 10,463 comparator words, or logical payloads 84,304 / 83,704 bytes each. Their vector capacities can exceed those lengths. Descriptor construction adds short parameter/dimension vectors (12/16 bytes) and a 286-byte logical frame; all these vectors drop before the fixed-size `Profile` is returned. |
| [Proof decoder](../../src/codec.rs), `decode_as` | Borrows proof fields. Exact size and counter cap precede challenge work. Challenge indices allocate `2*tau`; `opening_nodes` temporarily allocates `(2L-1)` one-byte `bool` flags. Both are gone before reconstruction. Invalid length/counter avoids these allocations. |
| [BAVC reconstruction](../../src/bavc.rs), `reconstruct_as`, `hash_leaves` | Temporarily coexists: `(2L-1)*32` node keys, `L*32` seed slots (including hidden zero slots), `(2L-1)` flags, and 64 commitment bytes. Payload subtotal 627,231 candidate / 6,021,151 comparator, plus indices and small metadata. Full commitment strings are streamed through one fixed leaf buffer and two hash states; there is no `L*112` commitment array. Node keys and flags drop on return; seeds survive into VOLE conversion. |
| [VOLE conversion](../../src/vole.rs), `reconstruct_as`; [fold](../../src/vole/convert.rs) | Seed slots coexist with `n_delta*W` columns, 320 mask-share bytes, 32 selector bytes, `tau` `Tree` metadata records, and one converter. `fold` allocates `d_i*W` stack plus `W` current bytes, i.e. `(d_i+1)*W`; no `2*N_i*W` expansion array exists. The verifier has no extra caller `u_i` buffer. These are sequential per tree. Seeds drop before gate labels/lift. |
| [Gate labels/masks](../../src/vole.rs), `gate_labels`, `mask_tags` | Heads `n_delta*32` coexist temporarily with labels `n_mult*32`; heads drop when labels return. Labels are 22,528 / 22,272 bytes. Further payloads are selector32, shares320, delta_words32, delta32, gates880, gamma88, row88, commitment64 and q_masks320, which can overlap the lift. Both rows have 11 gate words. Two extra 32-byte mask-product buffers live only inside `mask_tags` and drop before the lift. |
| [CRT lift](../../src/vole.rs), `Layout::lift` | Allocates `256*W` lifted columns while original columns exist, explicitly drops original columns, then allocates `ell*32` row bytes `Q`. Lifted columns and `Q` coexist until transposition ends. The result moves from its zeroizing wrapper; it is not copied into a second `Q`. |
| [Proof transcript](../../src/proof.rs), `grinder_of` | Retains reconstruction (`Q`, 320 mask-key bytes, indices, delta32, commitment64) through the relation. Challenge buffers are 264 and 104 bytes, decoded masks320, serialized `D_tilde`128 transient, and serialized coefficients224 (the growable vector's capacity may exceed 224). Universal-hash state and field accumulators are fixed-size. The final supplied counter is hashed once. |
| [QuickSilver](../../src/quicksilver/verifier.rs) and [Keccak relation scratch](../../../iroha_parliament_ballot_proof/src/keccak_relation.rs) | No constraint-sized key array: witness keys are read from `Q`. `Key<Gf256>` contains degree metadata in addition to its 32-byte field and is 40 bytes on the measured 64-bit host. Scratch owns `(1600+1600+320+320)*40=153,600` value bytes and `1600*sizeof(usize)=12,800` source-map bytes. This single scratch is reused across permutations. Vote adds `S*40` selector-product bytes, at most 40,000. |

Principal matrix payloads, in bytes:

The generic verifier "about 2.3 MB" sentence in `src/proof.rs` describes the
36,000-bit example's lift, not the comparator's earlier 6,021,151-byte BAVC
payload phase. Do not use that sentence as an all-row peak bound; the production
source snapshot remains unchanged for the current measurements.

| Row / role | W | Columns | Max converter scratch | Lifted columns | Q | Lifted columns + Q |
|---|---:|---:|---:|---:|---:|---:|
| Candidate registration | 4,490 | 1,113,520 | 40,410 | 1,149,440 | 1,146,880 | 2,296,320 |
| Candidate vote | 6,698 | 1,661,104 | 60,282 | 1,714,688 | 1,712,128 | 3,426,816 |
| Comparator registration | 4,495 | 1,123,750 | 58,435 | 1,150,720 | 1,146,880 | 2,297,600 |
| Comparator vote | 6,703 | 1,675,750 | 87,139 | 1,715,968 | 1,712,128 | 3,428,096 |

Caller-owned storage must be added for a particular entry point. The naked proof
is borrowed (candidate 160,148/233,012; comparator 109,498/158,074 bytes).
The [test decoder](../../../iroha_parliament_ballot_proof/src/test_codec.rs)
checks the exact field count before allocating its 11/10 borrowed-slice entries
(176/160 payload bytes on this host). Registration copies body context at most
4096 bytes and six opaque fields at most 256 each. Vote checks 3..=1000 entries
before copying its `128*S`-byte list. Record decoding borrows statement/proof
parts. A caller may still retain the entire encoded record.

[Vote instance construction](../../../iroha_parliament_ballot_proof/src/vote.rs)
also owns a concatenated `128*S`-byte public list while the typed statement retains
its list. Public digest/frame builders transiently concatenate/frame the list;
those phases precede reconstruction. Count those buffers and any caller-retained
test encoding when interpreting measured peaks. These test records are not the
future production Norito envelope.

## Work inventory and review limits

`codec::decode_as` and BAVC both traverse the public opening pattern. BAVC does
at most `L-1` internal-node expansions and exactly `L-tau` revealed-leaf
commitments, streaming H1 over all leaves. Extended leaf expansion requests 144
PRG bytes for each revealed leaf. VOLE conversion makes `L-tau` PRG expansions
of `W` bytes and `L-tau` merges; each merge XORs one column and one partial sum.
Gate reconstruction makes exactly `n_mult` salted H5 calls. The lift applies the
fixed public `W_CRT` matrix over width `W` and transposes `ell*256` bits. These
are source operation counts, not cycle counts or a deadline guarantee.

QuickSilver streams 72,576 registration / 108,931 vote constraints, including
Booleanity. The Keccak gadget performs `23*1600+output_bits` chi products per
permutation: 75,136 products over registration's two permutations and 112,960
over vote's three. Vote's public-list multiplexer examines `1024*S` public bits;
its conditional additions depend on these public bits. Degree alignment,
constraint hashing, selectors, field operations and provider costs are
additional work, not included in those chi-product counts. Verification never
searches the counter space.

Source review found bounded parser slices and list copies, public-only verifier
control flow, fixed/public loop bounds in the secret field and relation paths,
zeroizing owners for prover tape/witness/tree/column/value scratch, and explicit
erasure of affine checksum intermediates. This round changed no production
source. That review does not prove whole-program constant time or complete
erasure: field arithmetic assumes the target's integer multiplier timing,
AES/SHAKE providers and generated machine code still need inspection, and
register/spill/copy behavior, panic/abort paths, allocator failure behavior,
stack bounds, allocator overhead, concurrency, and actual production ingress
framing remain outside this inventory. Resource measurements and finite corpus
success alone do not close these gaps.
