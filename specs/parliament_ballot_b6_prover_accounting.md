# B6 implemented prover Keccak allowance

Status, 2026-10-13: **source-derived component calculation; no profile
qualification**. The implemented real prover fits the `2^16` non-counter
Keccak allowance in [arguments §8.5, equation (97)](parliament_ballot_proof_arguments.md)
under the entry boundaries below. This establishes neither the complete honest
oracle/simulator allowance nor the adapted cryptographic reduction. The frozen
request-accounting tools and reports are unchanged.

## Exact entry and units

The ordinary entry is [`registration::prove`](../crates/iroha_parliament_ballot_proof/src/registration.rs)
or [`vote::prove`](../crates/iroha_parliament_ballot_proof/src/vote.rs) on an
already constructed typed statement, a credential secret and the caller's
112-byte tape. Count one logical `Keccak-f[1600]` permutation for each executed
24-round sponge or explicit lane evaluation. SHA3-512 has rate 72 bytes;
SHAKE256 has rate 136 bytes. These are primitive-component units, not cycle or
elementary-gate costs.

Included: public validation and bounded hashing, a fresh profile (CRT digest,
descriptor and both namespaces), `H_mu`, witness lane evaluations,
commitment/transcript hashes and both labels of every H5 gate. Registration
uses the maximum 4,096-byte body and six 256-byte opaque fields. Votes cover
every admitted roster size `3 <= S <= 1,000`, independent of commitment values.
Hashing shorter bounded registration fields cannot increase this count.

The second boundary additionally starts with one `Profile::new` and
`Statement::for_secret`, then calls the ordinary prover. It includes body
digest/credential commitment/registration authorization, or vote list
digest/nullifier/vote authorization, as applicable. Vote inputs **already
contain** the sealed list and body, scope and policy digests. Generating all
list credentials and deriving arbitrary governance context are excluded.
Caller RNG, tape/secret generation and arbitrary repeated setup are excluded.

The source paths also execute `quicksilver::is_satisfied` and relation emission.
Their field/constraint operations are not sponge invocations; their full cost
remains outside this component. Copying, encoding, zeroization, AES work,
allocator/runtime work, quantum access, memory, advice and preprocessing are
not converted to Keccak units. An AES count for the final opening is stated
separately only to make the retry boundary explicit.

## Non-counter derivation

For `x` input bytes and `y` output bytes at rate `r`, the hash schedule uses

```text
P_r(x,y) = floor(x/r) + 1 + max(0, floor((y-1)/r)).
```

The middle term is final padding, including an exactly full input block.
Additional squeeze blocks are counted. An independent byte-at-a-time state
counter tests both rates at input/output boundaries and tests cloned counter
state separately.

[`Profile::new`](../crates/iroha_parliament_ballot_proof/src/profile.rs) hashes
84,304 CRT bytes on the candidate and 83,704 on the comparator. These cost
620/616 permutations. Descriptor/namespace frames of 286, 89 and 90 bytes add
4+2+2, giving **628/624** permutations per fresh profile.

The ordinary registration hashes `D_reg` and `H_mu` inputs of at most
5,975 and 6,024 bytes, adding 83+45. The ordinary vote hashes list, authorization
and `H_mu` inputs of `128S+114`, `128S+536` and `128S+584` bytes. The first two
use SHA3-512, the last SHAKE256. All output 64 bytes.

Let `tau`, `g`, `N_i` and `ell_b` be the row's vector count, gate count, vector
leaf counts and witness bytes. Candidate has `tau=33`, grinding bits 8 and
`g=704`; comparator has `tau=22`, grinding bits 6 and `g=696`. Vector depths
partition `256-grinding_bits` as the source prescribes. Witness bytes are
4,480 for registration and 6,688 for vote. All following hashes use rate 136;
input lengths include the 77-byte namespace and one domain byte.

| Family | Calls | Input bytes per call | Output bytes |
| --- | ---: | ---: | ---: |
| H0 | 1 | 94 | 128 |
| Vector H1 | `tau` | `78+112N_i` | 64 |
| Outer H1 | 1 | `78+64tau` | 64 |
| H4 | 1 | 158 | 16 |
| Challenge 1 | 1 | `254+(tau-1)ell_b+10ceil(g/8)` | 264 |
| Challenge 2 | 1 | `598+ell_b` | 104 |
| H5 | **`2g`** | 162 | 2 |

[`vole::commit_as`](../crates/iroha_zkp_vole/src/vole.rs) evaluates H5 for both
labels; the verifier's one-label schedule would undercount the prover.
[`build_witness`](../crates/iroha_parliament_ballot_proof/src/proving.rs) adds
two explicit [`evaluate`](../crates/iroha_parliament_ballot_proof/src/keccak_relation.rs)
lane permutations for registration and three for vote. The supplied tape
means there is no backend H3 invocation. Challenge 3 is wholly assigned to the
counter family below, including its shared prefix.

| Row / role | Ordinary preparation | Backend non-counter | Witness evaluations | Ordinary prover | Including bounded `for_secret` setup |
| --- | ---: | ---: | ---: | ---: | ---: |
| Candidate registration | 756 | 9,238 | 2 | **9,996** | **10,767** |
| Candidate vote, S=1,000 | 5,140 | 9,773 | 3 | **14,916** | **19,112** |
| Comparator registration | 752 | 54,162 | 2 | **54,916** | **55,683** |
| Comparator vote, S=1,000 | 5,136 | 54,518 | 3 | **59,657** | **63,849** |

The extra setup costs are respectively 771, 4,196, 767 and 4,192. Each includes
two credential lane evaluations: one 128-byte and one 64-byte output, each
from a 132-byte SHAKE input. The checker verifies monotonicity and the allowance
for all 998 vote sizes on each row, plus both registration rows. The comparator
result does **not** transfer the candidate cryptographic ledger to that row.

## Retries and ordinary failure paths

[`proof::prove_bounded`](../crates/iroha_zkp_vole/src/proof.rs) performs the
non-counter schedule once. [`Challenge3::new`](../crates/iroha_zkp_vole/src/transcript.rs)
absorbs 77 namespace bytes, 104 challenge bytes and 224 coefficient bytes: 405
total, hence two permutations and 133 buffered bytes. Each `at` clones that
state, adds four counter bytes and one oracle-domain byte, then pads and
squeezes 32 bytes. That is **two additional permutations per attempt**.

For `A >= 1` attempts, including the attempt that succeeds or exhausts the cap,

```text
W_counter(A) = 2 + 2A <= 4A,       1 <= A <= 2^20.
W_counter(0) = 0 for an earlier normal-return rejection.
```

At the cap, the exact component is 2,097,154 permutations, beneath the ledger's
4,194,304. A grinding rejection and an oversized opening do not add hashes.
[`BAVC::open`](../crates/iroha_zkp_vole/src/bavc.rs) checks the opening-node bound
before recomputing hidden leaves. Each failed oversized opening therefore adds
zero leaf AES blocks; the one successful opening adds `9tau` logical AES blocks
(297 candidate or 198 comparator), using the retained leaf committer without
rehashing H0. This is not a bound on the opening's non-hash traversal work.

Earlier statement/witness/backend normal errors execute prefixes or subsets
of the listed schedule. A successful or exhausted retry execution fits
`W_non_counter + 4A`. These statements assume the pinned fixed row, relation
and table invariants and ordinary returns; abort, cancellation, OOM and runtime
faults are not reclassified as proof rejection. The script checks arithmetic,
not an extracted control-flow proof of the source.

## Scope counterexample and remaining obligation

[`PreimageDigest::policy/proposal`](../crates/iroha_parliament_ballot_proof/src/credential.rs)
accept lengths through `2^32-1`. At that length their framed SHA3 inputs are
`2^32-1+42` and `2^32-1+24` bytes, costing 59,652,325 and 59,652,324 permutations.
Either alone exceeds 65,536. These helpers are not called by the two entry
boundaries above. A complete honest-game driver must explicitly charge or
bound such context work; the allowance cannot cover arbitrary wallet setup.

There is no complete simulator/final-comparison driver in this receipt. The
salted-H5/affine-leaf/bounded-counter adaptation, concrete generator advantages,
and all other mathematical/owner/reviewer premises remain in the
[B6 review](parliament_ballot_b6_security_review.md) and
[generator interface](parliament_ballot_b6_generator_interface.md). This local
source review is not independent human attestation.

## Reproduction and evidence

```sh
python3.11 scripts/parliament_ballot_prover_accounting.py --json
python3.11 -m unittest discover -s scripts/tests -p parliament_ballot_prover_accounting_test.py -v
python3.11 scripts/parliament_ballot_prover_accounting.py --require-qualified
```

The last command returns 2. The
[retained report](../docs/validation/parliament_ballot_prover_accounting/report.json)
pins 76 reviewed Rust/formula files with aggregate
`49d7fa0af0dc1211d7d10a7835b2f2b335b76c360117b67c36dd31fa474c4ca1`.
The independently expressed prover formulas crosscheck the existing verifier
schedule after removing Challenge 3 and doubling H5; the helper's actual source
bytes are pinned and loaded without a cached module. Source changes before,
during loading or after computation refuse component success. This inventory
identifies symbolic source formulas, not compiled binaries or their dependency
graph. Exact commands, outputs and artifact hashes are in the separate
[execution receipt](../docs/validation/parliament_ballot_prover_accounting/receipt.json).
All complete-resource and profile-qualification flags remain false.
