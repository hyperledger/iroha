# iroha_kagemusha_proof

Native-only KAGEMUSHA step relations on the PIPA-v1 engine (`iroha_plonk`,
`specs/plonk_ipa_v1.md`). This crate is the compilation boundary of KAGEMUSHA
relations built on the native stack. It links `iroha_pasta`, `iroha_plonk` and
`iroha_plonk_gadgets` only, never the vendored halo2 stack or `iroha_core_zk`.

## Status

The split-lineage step relations `sigma_send` and `sigma_recv`
(`specs/kagemusha_single_design_proposal.md` sections 3, 3.2, 5.1 and 7) in the
G1 wallet layout of `iroha_data_model` (`specs/kagemusha_wallet_wire_v1.md`
section 3.2). The domains, element lists, commitment, chains, `credit_id` and
statement are the G1 ones, pinned by the shared vectors of
`fixtures/kagemusha/wallet_v1_vectors.json`. No protocol path uses the
relations yet. The artifact set (frozen verifying keys, their digest rule and
the exact proof lengths of the allowlist) is G3 work.

Open (TODO(G3) in `src/witness.rs`): with the blacklist control, `sigma_send`
enforces only the maximum list age; the recipient non-membership opening, the
quota windows and usage update and the lease check are not implemented. A
relation enabling a quota or lease bit is refused (`ParamsError::Relation`),
and no relation with an enabled control may be frozen into an allowlist yet.

## Relations

`sigma_send` and `sigma_recv` (`SigmaCircuit`) on Pow5 sponge lanes,
running-sum range checks, checked `u128`/`u64` arithmetic and glue gates. A
`SigmaRelation` is a step with the enabled-controls mask its verifying key is
selected by: the G1 selector `(operation tag, mask)` (owner answer Q11),
`(3, mask)` for `sigma_send` and `(4, 0)` for `sigma_recv`.

- **Hashes.** `P(d, items)` is the RP57 Poseidon `hash_with_domain` over Pasta
  `Fp`, under the G1 domains `kgwcore1`, `kgwrest1`, `kgwcrdt1`, `kgwschn1`,
  `kgwrchn1` and `kgwstmt1`. An integer is one element, a 32-byte digest two
  `u128` limbs, a `P` value one element.
- **State.** A 32-element core (lifecycle; scheme id, asset digest, `wallet_id`
  and credential digest; balance, `burned_total`, sequence and the send, load
  and redeem ordinals; both chains; the consumed-credit, pending-outgoing,
  load/redeem-recovery, fee-claim and quota-usage roots; the enabled-controls
  mask; the quota-windows root; the blacklist version, root, issue time and
  maximum age; the lease expiry; the policy epoch; the accepted-time floor; the
  state nonce) and a 13-element rest. The head commitment is one `Fp` value,
  `P(kgwcore1, core || P(kgwrest1, rest))` (owner answer Q10): 17 folded
  permutations per opening. The rest digest is carried; no step relation opens
  the rest.
- **Both steps.**
  - Open the predecessor commitment and require the lifecycle to be Active or
    Retiring, carried unchanged (a Retiring wallet keeps sending and
    receiving, spec section 6.3).
  - Require a nonzero `u128` amount and `sequence + 1 < 2^128`.
  - Derive `credit_id = P(kgwcrdt1, 24-element Request body)` in circuit: one
    element (owner answer Q1). The Request's scheme, asset and own wallet are
    the opened core cells.
  - Require distinct payer and receiver wallets.
  - Commit the successor with a fresh state nonce. Roots the step updates are
    carried witnesses; the others are copied. Spec section 3.2 assigns root
    transitions to the native Advance check and to the lineage relation.
- **`sigma_send`.**
  - Takes `burned_total` and the pending-outgoing root of the predecessor's
    lineage proof as public inputs (in the statement).
  - Requires the core's enabled-controls mask to be its relation's.
  - Checks `amount + fee < 2^128` and `amount + fee <= balance - burned_total`.
    The successor balance is `balance - amount - fee`, and its `burned_total`
    is the lineage input.
  - Advances the send ordinal without overflow. Requires
    `request_policy_epoch <= policy_epoch` and
    `max(accepted_time_floor, request_time) <= lower <= upper` (all `u64`),
    and raises the successor's floor to `lower`.
  - With the blacklist control (owner answer Q5): while a list is held under
    an age rule, `issued_at <= upper <= issued_at + max_age` (the native G1
    `check_blacklist` age check), as two gated range checks.
  - `send_chain' = P(kgwschn1, [send_chain, credit_id, receiver (2), ordinal,
    amount, fee, Request digest (2)])`.
- **`sigma_recv`.**
  - Matches the Request's receiver by the core `wallet_id` inside
    `credit_id`. The Request's receiver credential digest is a Request term,
    never compared with the core's (owner answer Q8), so a Request quoted
    before a renewal stays receivable after it. The `payment_key` match is
    the native Payment check and `Λ_recv`'s.
  - Credits the amount without overflow;
    `recv_chain' = P(kgwrchn1, [recv_chain, credit_id, payer (2), amount])`.
- **Public input.** The digest of the 28-element G1 statement under
  `kgwstmt1` (`KagemushaWalletStatementV1::field_items`): version, the
  scheme-level relation identity (two limbs, a witness bound by the digest; it
  cannot be a circuit constant because it binds the verifying-key set),
  scheme, asset, credential, successor lifecycle, sequence and `next_load`,
  mask, the lineage inputs of a Send, both commitments, the effect tag and a
  10-element effect union.

`StepWitness::evaluate` is the native reference. It returns every digest, the
successor and the relation `Violation`s. The circuit compares every in-circuit
digest with it while the witness is known.

`consumer::check_send` and `consumer::check_receive` are the native spec
section 3.2 checks a package consumer runs before verifying the proof: the
relation identity, the predecessor, credential, scheme, lifecycle, mask,
`burned_total` and pending-outgoing root against the lineage proof
(`LineageView`), and the scheme, asset, wallets, amounts and `credit_id`
against the Request body. They return the relation whose verifying key the
consumer selects and the public input.

## Shapes and proofs

- `select_shape` chooses the smallest `k`, then the fewest lanes, at which a
  key-generation synthesis fits. A proof byte budget is optional; the default
  is the 3.5 KB gate. Proof lengths are exact, taken from the descriptor.
- Shapes (folded prefixes; `sigma_send` 67 permutations with or without the
  blacklist control, `sigma_recv` 65):

  | `k` | Lanes (fewest that fit) | Proof |
  | --- | --- | --- |
  | 12 | 1 (the selector's choice within 3.5 KB) | 3,296 B |
  | 11 | 2 | 3,840 B |
  | 10 | 4 (the smallest `k`) | 5,120 B |

- The glue chip shares the columns of the least loaded lane, in the rows after
  its last permutation block.
- `SigmaProver` derives the parameters, generates keys and proves. It refuses
  a witness that breaks the relation.
- `KeyOptions` trades memory for speed and never changes a key or proof byte.
  The default has no fixed-base commitment tables.
- `SigmaVerifier` needs only the descriptor bytes, the verifying-key bytes and
  the pinned parameters. `SigmaAllowlist` holds one verifier per selector,
  selects by `(tag, mask)` and emits the G1 allowlist entries (selector,
  verifying-key digest, exact proof length). The verifying-key digest is the
  PIPA-v1 `transcript_repr` of the key (an interim choice; TODO(G3)).
- The format is the KAGEMUSHA step format: RP57 Poseidon transcript, Direct
  instances and the folded-generator suffix.

## Tests

| File | What it covers |
| --- | --- |
| `tests/digest_parity.rs` | The native reference against `fixtures/native_prover/kats_v1.json`; the G1 vectors of `fixtures/kagemusha/wallet_v1_vectors.json` (domains, core and rest elements, rest digest, commitment, `credit_id`, both chain appends, both statements, and the named, pairwise-distinct `controlled_state` that pins every commitment position) natively and in circuit; in-circuit digests equal native ones on both fields; pinned known answers. |
| `tests/relation_checks.rs` | The 20 range-check cases in the strict constraint checker (three relations, two Poseidon prefix modes): each honest witness plus its mutations (including a debit that ignores the lineage `burned_total` and a stale or future blacklist). Every rejection is a range-check limb lookup. Every other rule, broken alone, and the integer and list-age boundaries, on all six shapes. In release, the per-cell tamper sweep on every honest case. |
| `tests/forgeries.rs` | Consistent-forgery tests, one per soundness rule: identity, receiver binding by `wallet_id` (Q8), `credit_id`, `burned_total`, the blacklist age under the mask-selected relation (Q5), self-payment, accepted time, the opened commitments and the relation identity. |
| `tests/real_proofs.rs` (release) | The 20 cases as real proofs. Honest proofs verify. The library and the engine refuse each mutated witness. A forger who zeroes the failing range checks gets a proof the verifier rejects. Every flipped proof byte is rejected. Proofs on Pallas also verify. A forged identity proves only its own head. A proof verifies only under its own allowlist selector. Keys and proofs are identical on 1, 2, 4 and 7 threads. |
| `tests/shapes.rs` | Shape selection, the pinned shapes at `k = 12, 11, 10`, inventories, and verifiers rebuilt from bytes. |
| `tests/measure.rs` (ignored, release only) | The M12 measurement harness and footprint workloads. |

Validate:

```sh
cargo test -p iroha_kagemusha_proof
cargo test --release -p iroha_kagemusha_proof -- --include-ignored --skip m12_
cargo clippy -p iroha_kagemusha_proof --all-targets -- -D warnings
```

Measure one case per process, in release. The harness reads process CPU time
from `clock_gettime(CLOCK_PROCESS_CPUTIME_ID)`, runs 20 proofs per series and
prints min/median/p95/max with the load average of every run; a series with
`load1 >= 4` is marked `gate_grade=false`:

```sh
/usr/bin/time -l <measure binary> m12_send_k12 --exact --ignored --nocapture --test-threads=1
```
