# RAM-LFE execution-proof completion

Status: the [canonical V1 contract](#canonical-v1-contract) below is implemented
as types, commitments and a cleartext reference interpreter. It requires a
proved [normalizing lowering](#normalizing-lowering) under one
[fixed public schedule](#fixed-public-schedule) for each class profile. That
lowering is specified, and its plaintext definition is a cleartext oracle that
tests compare with the reference; no encrypted normalizer, no schedule and no
proof of the lowering exist. The encrypted
evaluator, the execution relation and the opening proofs are not implemented.
Encrypted policy registration, activation, restored-state validation and
receipts still reject in both signed and proof modes, and no Core, Torii or SDK
path consumes the canonical V1 types yet. This is an implementation contract
for the remaining [ZK03 work](zk_first_release_goals.md) under the
[delivery plan](zk_delivery_plan.md), not a new proof format.

## Current implementation and trust boundary

The retained diagnostic [crypto interpreter](../crates/iroha_crypto/src/ram_lfe.rs) validates the
secret-bound policy, hidden program, registered parameters and encrypted input,
then executes the branchless tape. The closed
[BFV profile](../crates/iroha_crypto/src/fhe_bfv.rs) bounds it to 64 encrypted input
slots, four registers, 32 state lanes, 256 instructions, 64 outputs and
multiplicative depth 16. It has no refresh, so it admits exactly the tapes of
the canonical `bounded.v1` class. It evaluates a tape instruction by
instruction; the canonical contract requires the
[normalizing lowering](#normalizing-lowering) instead. Its ring degree is 64,
plaintext modulus is 257 and ciphertext modulus is `257 * 2^48`.
The public backend tags are `bfv-affine-v1` and `bfv-programmed-v1`; they identify
the evaluator's semantics. Retired `sha3-256` tags are rejected. Exact hash and
initializer choices are specified by the compiled protocol and profile descriptor.

The exact-lift profile is insecure: reducing its public-key equation modulo 257
removes its plaintext-multiple noise. Signatures and execution proofs cannot
repair this encryption defect. Public evaluators and Core/Torii boundaries now
reject both BFV tags before private work; the HKDF PRF remains available.
Arithmetic regression tests use private diagnostic dispatch. Remaining exported
low-level BFV utilities still require retirement or a secure replacement.

Execution produces ciphertext. The former execute response incorrectly signed a
ciphertext hash as an opened-plaintext hash; that issuer and response field are
removed. An identifier's independent plaintext opening currently comes from its
pinned opening authority as a signature. That is a trusted attestation, not a
decryption proof. `RamLfeOpeningV1` with decryption and PRF proofs replaces it.

The [Core receipt helper](../crates/iroha_core/src/smartcontracts/isi/ram_lfe.rs)
refuses the unavailable relation before parsing any proof or key. The former
generic verifier and four-payload-hash-limb acceptance path are removed. The
[identifier consumer](../crates/iroha_core/src/smartcontracts/isi/identifier.rs)
uses the same refusal, independently of policy registration and receipt preflight.
An otherwise valid replay-binding proof cannot establish program execution.
Policy validation also applies during
[state restoration](../crates/iroha_core/src/state/deserialize_core.rs).

What each path does today. Every row names symbols and the one file that
defines them. A test in `iroha_crypto` (`ram_lfe::specification_tests`) fails
when a named symbol leaves its file, when a call order stated here changes, or
when an SDK row no longer matches its file.

<!-- ram-lfe-current-paths -->
| Symbols | File | Current behaviour |
| --- | --- | --- |
| `RamLfeBackend::require_production_support` | `crates/iroha_crypto/src/ram_lfe.rs` | Refuses the two BFV backends with the insecure-profile error. Accepts the HKDF backend. |
| `execute_encrypted`, `require_supported_program_policy` | `crates/iroha_torii/src/identifier_resolution.rs` | Applies the refusal above to both backend fields, then returns the unsupported-backend error for every backend except the programmed BFV one. No backend passes both checks: an HKDF policy registers and then has no encrypted execution. |
| `derive_encrypted` | `crates/iroha_torii/src/identifier_resolution.rs` | Runs the encrypted execution first, then checks the opening. |
| `derive_phone_retail_encrypted` | `crates/iroha_torii/src/identifier_resolution.rs` | Checks the pinned phone-retail contract shape first and returns the invalid-canonicality error for any other policy. Only then runs the encrypted execution. |
| `PROOF_RELATION_UNAVAILABLE`, `validate_program_policy`, `validate_execution_receipt_at` | `crates/iroha_core/src/smartcontracts/isi/ram_lfe.rs` | Proof-mode policies and receipts are refused before any proof or key is parsed. |
| `RamLfeVerificationMode::Signed` | `crates/iroha_crypto/src/ram_lfe.rs` | The signed execution mode still exists. It does not make a BFV policy admissible. |
| `RamLfeReceiptAttestation::Signed`, `RamLfeOutputOpening::verify_signature` | `crates/iroha_data_model/src/ram_lfe.rs` | Signed receipt types still exist. An opening is a signature by the policy's opening key. |
| `sign_attestation_payload`, `validate_output_opening` | `crates/iroha_torii/src/identifier_resolution.rs` | The Torii runtime signer and the signature check of an opening. |
| `PhoneRetailCanonicalityAttestationV1`, `phone_retail_attestor_public_key` | `crates/iroha_data_model/src/identifier.rs` | Phone canonicality is a signature by a pinned attestor. |
| `ramLfeEncryptionUnavailable` | `IrohaSwift/Sources/IrohaSwift/ToriiClient.swift` | The Swift input-encryption helpers throw. The HTTP adapters for the routes exist. |
| `RamLfeEncryptionUnavailableException` | `kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/client/RamLfeEncryptionUnavailableException.kt` | The Kotlin input-encryption helpers throw. The HTTP adapters exist. |
| `encryptInput`, `encryptedRequestFromInput` | `java/iroha_android/src/main/java/org/hyperledger/iroha/android/client/IdentifierPolicySummary.java` | The Java duplicate awaiting migration refuses with the same code. |
| `RamLfeEncryptionUnavailableError`, `encryptIdentifierInputForPolicy` | `javascript/iroha_js/src/toriiClient.js` | The JavaScript input-encryption helper throws before it reads its arguments. |
| `encode_identifier_resolution_receipt_payload`, `verify_identifier_resolution_receipt` | `python/iroha_torii_client/identifier_receipts.py` | Python carries receipt encoding and signature verification only. It has no input-encryption helper. |
| `ToriiRamLfeOutputOpening`, `ToriiIdentifierResolveRequest` | `csharp/src/Hyperledger.Iroha.Sdk/Torii/IdentifierResolveRequest.cs` | C# carries request and opening models only. It has no input-encryption helper. |

Deleting a refusal in this table would expose an insecure and proof-less
product. Each row is replaced by its genuine successor, never by removal alone.
The table lists the paths this contract replaces. The complete machine-readable
consumer inventory, with every importer and every SDK file, is the
[ownership inventory](fhe_ownership_inventory.json) of the delivery plan's task
C.1. Its own checker, `scripts/check_fhe_ownership_map.py`, compares it with
the source.

No existing compiled relation supplies the missing semantics. Retired IVM
binding-only relations did not establish execution and provide no substitute for
the hidden-program relation. The BFV full-bootstrap verifier
requires full execution material, while its public-padding-only verifier rejects.
The proof engine of the execution relation is not selected. The delivery plan
builds the relation on its shared proof backend (tasks B.1 to B.3), and task R.3
selects the construction with it ([open question 1](#open-construction-questions)).
The existing Halo2 IPA engine is one candidate and not a decision. Proving the
current arithmetic does not establish the separate BFV encryption or bootstrap
security claims documented in the crypto module.

## Canonical V1 contract

This section is normative for RAM-LFE roles, leakage, program classes, plaintext
semantics, the normalizing lowering with its fixed public schedule,
commitments and the cleartext reference. Code:
[`iroha_crypto::ram_lfe`](../crates/iroha_crypto/src/ram_lfe.rs) modules
`class`, `canonical`, `reference` and `normal_form`, and
[`iroha_data_model::ram_lfe`](../crates/iroha_data_model/src/ram_lfe.rs).
The sections after it describe the superseded diagnostic backend and the work
that remains.

### Roles and collusion

| Role | Holds | Never holds |
| --- | --- | --- |
| Program owner and evaluator | Hidden tape, program key, public evaluation keys. Registers the policy, computes on ciphertexts and proves execution. | Plaintext input, decryption capability, PRF secret. |
| Encryption-key owner | Generates the encryption key pair for one profile and publishes the encryption and evaluation keys. | Hidden tape, program key. |
| Authorized opener | Decryption capability (one authority, or a threshold committee) and the identifier PRF secret. Proves decryption and PRF derivation for one receipt. | Hidden tape, program key. |
| Client | Plaintext input and encryption coins. Proves its ciphertext is well formed. | Hidden tape, program key, any secret key. |
| Validators | Committed policy, receipts, openings and proofs. | Any secret. |

The program owner and the evaluator are one trust domain: the evaluator cannot
compute without the tape and the program key. With a single opening authority,
the encryption-key owner and the opener are one party. A threshold committee
splits that party; it does not remove it.

Collusion assumptions, stated without a guarantee where none exists:

- **Evaluator alone.** Sees ciphertexts and learns no input beyond what the
  encryption profile leaks. It knows the function, so nothing hides the function
  from it. It cannot make validators accept a result for another function,
  policy, input or beneficiary once the execution relation exists. It can
  encrypt candidate inputs itself and ask for their openings through accounts
  it controls. That online enumeration is bounded by the
  [query limit](#query-limit): at most `per_beneficiary` identifiers for one
  account and at most `total` over all its accounts.
- **Opener alone.** Whoever can decrypt outputs can decrypt inputs: input
  confidentiality against the opener does not exist with a single authority, and
  with a committee it holds only below the threshold. A single opening
  authority can decrypt every ciphertext it obtains, whether or not an opening
  was authorized, so against it the count that matters is accepted executions,
  not accepted openings. With the inputs it can decrypt, the opener holds input
  and output pairs of the function. It must learn nothing else about the
  function; that needs circuit-private evaluation, which ordinary homomorphic
  evaluation does not give.
- **Evaluator and opener together.** No confidentiality remains: they recover
  every input, hold the function and can enumerate identifiers offline. The
  contract gives no guarantee against this coalition.
- **Clients, alone or together.** They choose inputs adaptively and receive
  opened outputs. This is oracle access to the function, bounded by the query
  limit and the leakage contract below. A client may pass an opened result on;
  authorization decides who receives it, not who learns it afterwards.
- **Validators, alone or with any other role.** They add only public data to
  what that role already holds.

The identifier PRF secret stays with the opener. An evaluator that knows the
function still cannot map candidate low-entropy inputs to identifiers offline,
and an opener that holds the PRF secret does not know the function.

Five guarantees are separate, and evidence for one establishes none of the
others:

| Guarantee | Established by |
| --- | --- |
| Input confidentiality | The encryption profile and the client's well-formedness proof. |
| Hidden-function privacy | The blinded function commitment and circuit-private evaluation. |
| Proof zero knowledge | The execution relation's proof system. |
| Output authorization | The [query limit](#query-limit) the function identity commits, and the fixed rule that only a receipt's beneficiary may request its opening. |
| Authenticated opening | The decryption and PRF proofs for one receipt. |

### Leakage contract

Public to everyone: the policy record (class, plaintext-semantics digest, the
two hiding function commitments, the query limit, profile, key commitments,
relation identity); for each execution the network, program, beneficiary,
associated-data digest, initialized-memory commitment, both ciphertext
commitments, expiry and replay scope and nonce; for each opening the receipt
commitment, a hiding output commitment and the two key commitments; submission
order and time.

Never public: the tape, its instruction count, opcodes, indexes and immediates,
the output count, the program key, the state lanes, the plaintext input, the
plaintext output and every refresh point. The
[normal form](#normalizing-lowering) of the tape is as private as the tape: its
gates, their kinds, number and order, and every coefficient. Evaluation and
proof shapes follow one [fixed public schedule](#fixed-public-schedule) for
each class profile, padded to the class maximum; a private count never selects
a smaller one.

No commitment confirms a guess. The function, initializer and
initialized-memory commitments each take the program key or a blinding derived
from it, and the output commitment takes a fresh opener blinding. A party that
learns candidate lanes from an opened output cannot test them against the
initialized-memory commitment, because it cannot derive the blinding.

What stays linkable, by construction:

- A function identity is one value wherever it is registered. Two policies, two
  programs and every encryption-key rotation that name the same class, tape,
  program key and query limit show the same function identity. This is the
  identity the query limit counts.
- Reusing one program key for two different functions is not visible: the
  function commitment and the initializer commitment each differ for every
  class and tape.
- Two function identities with the same class, tape and program key and
  different query limits show the same function commitment and the same
  initializer commitment; only the function identity differs.
- Two policies that commit the same key, profile or relation bytes show the
  same commitment for it.
- Executions with the same associated data show the same associated-data
  digest and have the same state lanes. Their initialized-memory commitments
  differ, because each is blinded for its own execution context (network,
  program, replay scope and nonce), so the commitment adds no link.
- The same ciphertext bytes give the same ciphertext commitment.

Output leakage: one accepted execution discloses at most 64 scalars of F257,
which is less than 513 bits (`2^512 < 257^64 < 2^513`,
`RAM_LFE_V1_OUTPUT_LEAKAGE_BITS`), to the opener and to the beneficiary that
receives the opened result. Nothing else about the input, the function or the
state lanes may reach them.

What they receive is the 64 output slots an
[opening commits](#commitments): the ordered output followed by zeros. The
number of outputs the tape emitted is known to the program owner, who holds
the tape, and an opening conveys it to nobody else. From the 64 scalars the
opener and the beneficiary can infer only that this number reaches at least
the last nonzero slot; a trailing zero the tape emitted is indistinguishable
from padding. Validators and everyone else see the hiding output commitment
and no scalar.

Oracle leakage: a function identity accepts at most `total` executions on one
network over its whole life, so accepted executions disclose at most
`513 * total` bits about it (`RamLfeQueryLimitV1::output_leakage_bound_bits`).
The bound is a count of output bits. It is not a statement that a function with
a smaller budget stays secret:

- 65 suitably chosen valid queries recover the complete input-to-output map of
  an `affine.v1` function for one associated-data value: the empty input, 63
  zero bytes and the 63 unit byte strings of length 63 span every admitted
  input. They do not recover the tape, the program key, or the intercept of
  another associated-data value. The linear part is the same for every
  associated-data value, so each further value costs one more query. A test
  performs exactly this recovery against the cleartext reference.
- A simpler function leaks faster. One opened output of a function that adds a
  state lane to each input slot discloses every lane for that associated data.
- A policy whose function must stay hidden from its clients therefore commits a
  `total` below what its function needs to be determined, and an `affine.v1`
  policy with `total` of 65 or more does not hide its input-to-output map from
  its clients.

Outside the bound, with no guarantee inherited from it:

- A ciphertext that never became an accepted receipt. A single opening
  authority can decrypt it, and an evaluator can produce it, off the protocol.
- Another function identity. A new identity has a new budget and new state
  lanes, but it does not erase what earlier queries disclosed: two identities
  with related tapes share their linear coefficients. The contract makes no
  secrecy claim across independently budgeted identities or across networks.

A client can submit a ciphertext whose plaintext is outside the admitted input.
`SelectEqZero` is the zero test only on canonical scalars, so such an input can
extract function information beyond the bound. Every input ciphertext therefore
needs a well-formedness proof bound to the same input commitment as the
receipt. A zero-knowledge proof of execution hides nothing that the ciphertexts,
the opened output, the access pattern or timing already disclose.

### Query limit

`RamLfeQueryLimitV1` is a field of the function identity, so one function
identity has exactly one limit and the policy and receipt commitments bind it.
Another limit is another function identity with other state lanes.

| Field | Counts | Charged when |
| --- | --- | --- |
| `total` (u64, nonzero) | Accepted receipts of the function identity. | A receipt is accepted. |
| `per_beneficiary` (u32, nonzero, at most `total`) | Accepted openings for one beneficiary account. | An opening of a receipt of that beneficiary is accepted. |

- **Counted unit.** One accepted receipt is one query. A receipt is opened at
  most once, so openings never exceed receipts and no separate total of
  openings exists.
- **Scope.** One function identity on one authoritative network. Counts
  aggregate across every program registration and policy that names the
  identity, every encryption-key rotation, every associated-data value and both
  replay scopes. Nothing resets a count.
- **Lifetime and atomicity.** Counts are lifetime counts in committed State. A
  charge is applied in the same atomic transition that accepts the receipt or
  the opening; a rejected transaction charges nothing.
  `RamLfeQueryLimitV1::charge_receipt` and `charge_opening` are the counting
  rule: each takes the persisted count and returns the next count or the
  exhausted error.
- **Who may request an opening.** Only the receipt's beneficiary, as the
  authenticated authority of the requesting transaction
  (`RamLfeReceiptV1::verify_opening_requester`). An account named by the prover
  or by the opener is not sufficient. The opened result is delivered to that
  beneficiary only. This is a fixed rule of V1, not a policy field.
- **Tightening.** A consumer may refuse a query the limit admits, for example
  by a rate over time. It never admits one the limit refuses.

`per_beneficiary` bounds what one account derives. It does not bound a party
that controls many accounts; only `total` does. An honest opener, and each
member of a threshold committee, contributes to an opening only after
validators accepted the request. The contract cannot stop a single opening
authority from decrypting on its own.

### Exact plaintext semantics

The machine has four registers and 32 state lanes over F257. Registers start at
zero. **State lanes initialize within each execution** from the program key, the
function identity and the associated data. `StoreState` lasts until the tape
ends. No value of one execution is an input of another. Persistent
cross-request mutable state needs its own authenticated prior-state and
next-state order and is outside this contract.

Input is a byte string of at most 63 bytes: slot 0 is the length, slots
`1..=length` are the bytes and every other slot is zero. An output is a scalar
in `0..=256`, never truncated to a byte, and is a snapshot taken when its
`Output` executes.

The descriptor below is the contract. Its digest is the `plaintext_semantics`
field of every function identity. Tests compare these exact bytes with
`RAM_LFE_V1_PLAINTEXT_SEMANTICS_DESCRIPTOR`, rebuild every line except the
opcode lines from the compiled constants, and evaluate each opcode line itself:
its parameter order against the tape codec, its meaning against the cleartext
reference and its rank rule against the class accounting.

<!-- ram-lfe-v1-plaintext-semantics -->
```text
iroha.ram_lfe.plaintext_semantics.v1
field=F257;scalar=0..256;arithmetic=mod257
registers=4;register-init=0;state-lanes=32;state-init=per-execution;state-persistence=none
input-slots=64;input=slot0:length(0..63),slots1..length:byte(0..255),rest:0
instructions=1..256;outputs=1..64;output=ordered-scalar(0..256)-snapshot;immediate=0..256
tape=48-bytes-per-instruction;words=6*u64le;unused-words=0
opcode=0:LoadInput(dst,slot):dst=input[slot];rank=0
opcode=1:LoadState(dst,lane):dst=state[lane];rank=state[lane]
opcode=2:StoreState(lane,src):state[lane]=src;rank=src
opcode=3:LoadConst(dst,imm):dst=imm;rank=0
opcode=4:Add(dst,lhs,rhs):dst=lhs+rhs;rank=max(lhs,rhs)
opcode=5:AddPlain(dst,src,imm):dst=src+imm;rank=src
opcode=6:SubPlain(dst,src,imm):dst=src-imm;rank=src
opcode=7:MulPlain(dst,src,imm):dst=src*imm;rank=src
opcode=8:Mul(dst,lhs,rhs):dst=lhs*rhs;rank=max(lhs,rhs)+1
opcode=9:SelectEqZero(dst,cond,zero,nonzero):dst=nonzero+(1-cond^256)*(zero-nonzero);rank=max(cond+10,zero+1,nonzero+1)
opcode=10:Output(src):append(src);rank=src
class=affine.v1;opcodes=0,1,2,3,4,5,6,7,10;max-rank=0;max-refreshes=0
class=bounded.v1;opcodes=0,1,2,3,4,5,6,7,8,9,10;max-rank=16;max-refreshes=0
class=refresh.v1;opcodes=0,1,2,3,4,5,6,7,8,9,10;max-rank=16;max-refreshes=64
refresh=plaintext-identity;schedule=lazy;trigger=result-rank>max-rank;targets=distinct-nonzero-rank-operand-registers;order=operand;effect=rank:=0,in-place
initializer=blake3-derive-key-xof;context=iroha.ram_lfe.v1.initial_state;frame=iroha_crypto::ram_lfe::RamLfeInitializationInputV1;fields=function_identity,associated_data_hash,program_key;stream-bytes=1024;lane=32-bytes-unsigned-big-endian-mod257;lane-order=ascending
associated-data=0..512-bytes
```

### Program classes

All three classes are mandatory. A class restricts which tapes a policy may
commit to. It never changes what an admitted instruction computes.

| Class | Instructions | Rank limit | Refreshes |
| --- | --- | ---: | ---: |
| `affine.v1` | `LoadInput`, `LoadState`, `StoreState`, `LoadConst`, `Add`, `AddPlain`, `SubPlain`, `MulPlain`, `Output`. No ciphertext multiplication. | 0 | 0 |
| `bounded.v1` | All eleven, including `Mul` and the complete `SelectEqZero`. | 16 | 0 |
| `refresh.v1` | All eleven, with refresh between rank-bounded segments. | 16 between refreshes | at most 64 |

Rank is the dependency depth of ciphertext multiplications, by the rule of each
opcode in the descriptor. `SelectEqZero` counts its actual expansion: eight
squarings of the condition, one multiplication by the embedded one and one
selection multiplication, so a condition adds ten and a branch adds one. Rank
passes through registers and through state lanes. **Rank is not a noise
budget.** Additions and plaintext multiplications consume noise at constant
rank; the leveled noise and work plan belongs to the encryption profile.
[Logical rank and physical noise](#logical-rank-and-physical-noise) states what
rank does and does not bound.

`refresh.v1` keeps the eleven instructions; there is no refresh opcode. Refresh
is the identity on plaintext. Its schedule is a function of the tape: when the
result of a `Mul` or `SelectEqZero` would exceed the rank limit, each distinct
operand register with nonzero rank is refreshed in place, in operand order,
before the instruction executes, and the result rank is recomputed. A register
that appears twice is refreshed once, and a destination that aliases an operand
receives the recomputed rank. The schedule is private with the tape and is not
chosen by the evaluator; the execution relation must constrain it inside the
padded shape. It is logical accounting: it decides membership and places the
refresh gates of the normal form, and it is never the physical refresh
schedule, which the [fixed public schedule](#fixed-public-schedule) fixes for
the class profile. Adding an encryption of zero is not a refresh.

The declared class is part of the function identity. The same tape and key under
two classes are two functions, so a proof for one class cannot serve another.
The tape owner `HiddenRamFheProgram` admits every structurally valid tape;
`RamLfeClassV1::membership` decides the class and returns the private rank,
multiplication and refresh accounting. Its errors name hidden instruction
positions and belong to the program owner, never to a public refusal.

Candidate shape, recorded before any measurement: 64 input slots, 64 outputs,
four registers, 32 state lanes, 256 instructions, rank 16, 64 refreshes. Any
measurement names this shape. A changed bound changes the descriptor and every
function identity, and the affected measurements are repeated.

### Logical rank and physical noise

**Logical rank bounds ciphertext multiplication depth, not physical noise.**
The rank rules of the descriptor count the dependency depth of ciphertext
multiplications and nothing else. Rank does not count:

- **Plaintext operations.** `Add`, `AddPlain`, `SubPlain` and `MulPlain` leave
  rank unchanged and each grows the noise of a ciphertext. One multiplication
  by a hidden constant multiplies a worst-case noise bound by up to
  `(257 - 1) / 2 = 128`, seven bits, at constant rank, and every class admits
  a run of 254 of them on one loaded input at rank 0.
- **The number of ciphertext multiplications.** Rank 16 does not mean at most
  sixteen multiplication operations. A `bounded.v1` tape of 255 independent
  `SelectEqZero` instructions has rank 10 and 2,550 ciphertext
  multiplications; one of 255 independent `Mul` instructions has rank 1.
- **Everything else an encrypted evaluation does**: key switches, modulus
  switches, masks, broadcasts, output zeroing, sanitization and refresh.

Rank therefore decides class membership. It decides no level, no modulus chain
and no failure probability, and the limit 16 is a recorded candidate, not a
property of any encryption profile.

**Instruction-by-instruction evaluation of the existing candidates does not
hold the maximum shape.** The
[RNS-BGV cost model](ram_lfe_encryption_replacement.md#rns-bgv-starting-candidate)
of delivery-plan task C.3 lowers every tape instruction onto the scheme by
itself, with a lazy level policy and exact worst-case bounds, and plans nine
tape families of the [candidate shape](#program-classes) on its three starting
candidates. No candidate holds every family planned for it:

<!-- ram-lfe-maximum-shape-need -->
| Class | Candidate | Main primes in the candidate | Main primes every planned family would need |
| --- | --- | ---: | ---: |
| `affine.v1` | `bgv.f257.n14.q6x50.p2x60` | 6 | 38 |
| `bounded.v1` | `bgv.f257.n16.q22x50.p2x60` | 22 | 52 |
| `refresh.v1` | `bgv.f257.n16.q32x50.p2x60` | 32 | 52 |

The families each candidate refuses, with the instruction at which the plan
runs out of modulus. Every one of them is a member of the candidate's class,
and each contains a long run of constant multiplications:

<!-- ram-lfe-maximum-shape-counterexamples -->
| Candidate | Family | Logical rank | Refused at instruction | Main primes the family needs |
| --- | --- | ---: | ---: | ---: |
| `bgv.f257.n14.q6x50.p2x60` | `affine.scale_chain` | 0 | 36 | 38 |
| `bgv.f257.n14.q6x50.p2x60` | `affine.scale_then_outputs` | 0 | 36 | 29 |
| `bgv.f257.n16.q22x50.p2x60` | `affine.scale_chain` | 0 | 147 | 38 |
| `bgv.f257.n16.q22x50.p2x60` | `affine.scale_then_outputs` | 0 | 147 | 29 |
| `bgv.f257.n16.q22x50.p2x60` | `bounded.scaled_rank_chain` | 16 | 147 | 52 |
| `bgv.f257.n16.q32x50.p2x60` | `affine.scale_chain` | 0 | 217 | 38 |
| `bgv.f257.n16.q32x50.p2x60` | `bounded.scaled_rank_chain` | 16 | 217 | 52 |

`affine.scale_chain` is one input load, 254 sequential constant
multiplications and one output; `affine.scale_then_outputs` is 191 of them and
64 outputs; `bounded.scaled_rank_chain` is 238 of them below sixteen squarings.
The longest run of constant multiplications each candidate holds beside 64
outputs, after a chain of the given rank, against the longest run the class
admits there:

<!-- ram-lfe-plaintext-run-limits -->
| Candidate | After rank 0 | After rank 10 | After rank 16 |
| --- | ---: | ---: | ---: |
| `bgv.f257.n14.q6x50.p2x60` | 30 of 191 | not admitted | not admitted |
| `bgv.f257.n16.q22x50.p2x60` | 142 of 191 | 70 of 181 | 28 of 175 |
| `bgv.f257.n16.q32x50.p2x60` | 191 of 191 | 140 of 181 | 98 of 175 |

A test compares the three tables with the recorded
[cost summary](fhe_bgv_cost_summary.json); a change of the summary changes
them in the same change. The numbers are worst-case plans of
a costing harness. They are counterexamples, not a qualification. The
candidates are unqualified. What is estimated about their security, and what
is not, is recorded with the
[candidates](ram_lfe_encryption_replacement.md#rns-bgv-starting-candidate);
meeting a security target and holding a class are separate conditions, and no
estimate repairs the class fit.

The contract does not answer this by enlarging a modulus chain, and it adds no
plaintext-depth limit to a class: the admitted tapes, the class rules, the
descriptor and every function identity stay as they are. It answers it by the
lowering below.

### Normalizing lowering

A V1 tape is never evaluated on ciphertexts instruction by instruction. It is
evaluated through its **normal form**, by a **normalizing lowering** that is
proved to preserve the cleartext reference. The lowering is mandatory for all
three classes.

It changes no canonical type. The function identity commits the tape, the
class is decided on the tape by `RamLfeClassV1::membership`, and the
plaintext-semantics descriptor is the one above. A normal form has no
canonical encoding and enters no commitment.

**Normal form.** An execution has these columns:

| Columns | Value |
| --- | --- |
| 0 | The constant one. |
| 1 to 64 | The 64 input slots. |
| 65 to 96 | The 32 lanes the execution was initialized with. |
| 97 + g | The result of gate g, in gate order. |

An **affine form** is one coefficient of F257 for each column, reduced to
`0..=256`. Its value is the sum of coefficient times column value modulo 257.
A **gate** takes affine forms over the columns before it and adds one column:

<!-- ram-lfe-v1-normal-gates -->
| Gate | Operand forms | Result | Ciphertext multiplications |
| --- | --- | --- | ---: |
| `Mul` | lhs, rhs | `lhs * rhs` | 1 |
| `SelectEqZero` | cond, zero, nonzero | `nonzero + (1 - cond^256) * (zero - nonzero)`, the expansion of the descriptor | 10 |
| `Refresh` | operand | The operand. It is the identity on plaintext. | 0 |

An **output** is an affine form. A normal form is its gates in order and its
1 to 64 outputs in order.

**Normalization** is a deterministic function of the tape and its class
accounting. Each register and each lane holds an affine form: a register
starts as the zero form and lane `l` as column `65 + l`. The instructions are
taken in tape order, each by the role of its opcode:

<!-- ram-lfe-v1-normal-roles -->
| Opcode | Role | Effect on the forms |
| --- | --- | --- |
| `LoadInput` | folded | The destination becomes the column of the input slot. |
| `LoadState` | folded | The destination becomes the form the lane holds. |
| `StoreState` | folded | The lane becomes the form the source holds. |
| `LoadConst` | folded | The destination becomes the constant form of the immediate. |
| `Add` | folded | The destination becomes the sum of the two forms, column by column. |
| `AddPlain` | folded | The destination becomes the source form with the immediate added to its constant coefficient. |
| `SubPlain` | folded | The destination becomes the source form with the immediate subtracted from its constant coefficient. |
| `MulPlain` | folded | The destination becomes the source form with every coefficient multiplied by the immediate. |
| `Mul` | boundary | One `Mul` gate over the forms of both sources. The destination becomes the gate's column. |
| `SelectEqZero` | boundary | One `SelectEqZero` gate over the forms of the three sources. The destination becomes the gate's column. |
| `Output` | snapshot | The form the source holds is appended to the outputs. |

A **folded** instruction leaves no operation of its own: a run of any number
of them between two boundaries becomes the coefficients of the forms that read
it. Every coefficient is computed exactly in F257 and is reduced before any
encrypted evaluation, which multiplies by its centered representative of
magnitude at most 128.

The lowering must preserve:

- **State updates.** `StoreState` and `LoadState` are resolved in tape order.
  A lane holds the form that was stored, not what the source register became
  afterwards, and a later store replaces an earlier one. The forms refer only
  to the columns of this execution, so nothing reaches another execution.
- **Output snapshots.** An output is the form its register held when its
  `Output` executed. A later write to the register does not change it. The
  outputs keep their order and their count.
- **Aliasing.** Every source is read before the destination is written, as in
  the reference. A destination may be any of its sources and a source may be
  named more than once.
- **Nonlinear boundaries.** Every `Mul` and every `SelectEqZero` stays exactly
  one gate, in tape order, with the formula of the descriptor. No gate is
  merged, split, reordered, replaced by a cheaper one or removed. That holds
  for a gate whose operands are constants, for one whose operands folded to
  zero and for one whose result nothing reads.
- **Refresh points.** For `refresh.v1`, every point of the canonical schedule
  is one `Refresh` gate over the form of the scheduled register, placed
  immediately before the instruction that required it. The register then holds
  the gate's column. Another register or lane that holds the same form is not
  refreshed.

What the lowering removes is what need not survive: the instruction count,
which folded opcodes a run used, which registers and lanes carried a value,
and the number, length and placement of plaintext runs. Plaintext runs that
give the same forms leave no trace: two tapes whose gates have the same kinds
and the same operand forms, in order, and whose output forms are equal have
one normal form, whatever instructions produced those forms.

**A normal form is not canonical for the function a tape computes.** Two tapes
that compute one function can have different normal forms:

- A scaling moved across a gate stays in the coefficients.
  `LoadInput(0,1); Mul(1,0,0); Output(1)` and
  `LoadInput(0,1); MulPlain(0,0,2); Mul(1,0,0); MulPlain(1,1,193); Output(1)`
  both output the square of input slot 1, because `2 * 2 * 193` is 1 modulo
  257. The operand forms of the first carry the coefficient 1 and its output
  form the coefficient 1; those of the second carry 2 and 193.
- A nonzero scaling of a `SelectEqZero` condition selects the same branch and
  stays in the condition form.
- A gate nothing reads and a gate over constants stay gates.

Nothing may therefore rest on equal functions having equal normal forms. What
an evaluated ciphertext discloses about the coefficients is bounded by the
sanitization of `NL-L7` and by nothing in the lowering.

**Depth.** The multiplication depth of a column is zero for the constant, an
input slot, a lane and a `Refresh` gate. The depth of a form is the highest
depth of a column with a nonzero coefficient. A `Mul` gate has the higher
depth of its two forms plus one; a `SelectEqZero` gate has the highest of the
condition plus ten and each branch plus one. The depth of a normal form is at
most the logical rank of its tape, and can be lower when a coefficient folds
to zero. The class is decided on the tape and never on the normal form: a tape
outside its class is refused even when its normal form would be shallower.

**Shape.** The largest normal form of a class is a function of the class
alone. Every member tape normalizes within it, and every bound is reached by a
member tape.

<!-- ram-lfe-v1-normal-shape -->
| Class | `Mul` and `SelectEqZero` gates | `Refresh` gates | Outputs | Columns | Depth | Ciphertext multiplications |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `affine.v1` | 0 | 0 | 64 | 97 | 0 | 0 |
| `bounded.v1` | 255 | 0 | 64 | 352 | 16 | 2,550 |
| `refresh.v1` | 255 | 64 | 64 | 416 | 16 | 2,550 |

The depth of `refresh.v1` is the depth between two refreshes. The last column
counts every gate as a `SelectEqZero`, which is what hiding a gate's kind
costs when gates are evaluated one by one.

**The bounds are reached together, except the outputs.** One member tape of
255 `SelectEqZero` instructions and one output reaches every other bound of
its class at once: for `refresh.v1` 255 nonlinear gates, 64 refreshes, 416
columns, depth 16 and 2,550 ciphertext multiplications, and for `bounded.v1`
255 nonlinear gates, 352 columns, depth 16 and 2,550 ciphertext
multiplications. Only the output bound and the gate bound exclude each other,
because an output and a nonlinear gate are one instruction each and a tape has
at most 256: a tape with 64 outputs has at most 192 nonlinear gates, and it
still reaches the refresh and depth bounds. The fixed public schedule provides
every gate, refresh and output slot whatever the tape uses, so the noise and
the work to derive are those of all bounds of a row together.

**What this does for noise, and what it does not.** In a normal form a value
passes through one coefficient on its way from a column to the next gate or to
an output, however long the plaintext run of the tape was. A form has at most
416 terms of centered magnitude at most 128. The worst-case noise of a
normalized evaluation is therefore a function of the class shape and the
profile, not of the plaintext instructions of a tape. That function is not
derived. The cost summary
projects the folded affine map of the affine candidate at 3 main primes; that
is a projection, not a measurement, and nothing evaluates it. Folding does not
make the existing candidates adequate: task C.3 derives and measures the
worst-case noise and work of the complete padded construction, including key
switches, masking and sanitization.

The evaluator holds the program key, so it knows the lanes of an execution in
cleartext. It may fold the constant column and the lane columns of a form into
one constant for that execution. The lanes change with the associated data;
the normal form does not.

`ram_lfe_reference_normalize_v1` is the plaintext definition of this section
(see [cleartext reference](#cleartext-reference)). It is a cleartext oracle.
No encrypted normalizer exists.

### Fixed public schedule

The encrypted evaluation of a normal form follows **one fixed public schedule
for each class profile**: each pair of a class and an encryption profile that
a policy can name. The policy's `profile` and `relation` commit it; a prover
or an evaluator chooses none of it.

- **A function of the public profile only.** The schedule fixes the level of
  every ciphertext at every step, every ciphertext size, the evaluation keys
  it requires and their sizes, the number, kind and position of every key
  switch, modulus switch, ciphertext multiplication, mask and broadcast, the
  refresh slots, the sequence of operations and of memory and key accesses,
  the shape and size of the proof and the size of every message.
- **Padded to the class maximum.** The schedule provides for the largest
  normal form of the class in the table above. A tape with fewer gates,
  outputs or refreshes, with shorter forms or with zero coefficients runs the
  same schedule. No hidden count selects a shorter schedule, a lower level, a
  smaller ciphertext, a skipped operation or an early exit.
- **Multiplications are concealed.** The number and the placement of the
  ciphertext multiplications of a tape are hidden by the padding, and so is
  the kind of every gate. Rank 16 does not mean at most sixteen multiplication
  operations: the schedule of `bounded.v1` covers 255 nonlinear gates at
  depth 16.
- **Dummy work and hidden routing preserve semantics.** Padding is dummy work
  (a gate slot no gate of the tape uses, an output slot beyond the output
  count, a refresh slot without a logical refresh) and hidden routing (which
  column feeds which slot). Neither changes a column or an output of the
  normal form, and the unused output slots are zero. Their noise and their
  work are inside the bound: the worst-case noise bound and the work, memory
  and proof budgets are those of the complete padded schedule, with every key
  switch, mask, dummy operation and sanitization step, and never those of one
  tape.
- **No visible failure.** Because the bound is that of the padded schedule,
  every member tape and every well-formed input evaluates within it. An
  evaluation never fails, is refused, is retried or takes another path because
  of the tape.
- **The private refresh accounting stays private.** The lazy schedule of the
  class accounting (`RamLfeClassReportV1::refresh_points`) is a function of the
  hidden tape. It decides membership and gives the `Refresh` gates of the
  normal form. It must not become an observable physical schedule: the
  physical refresh slots, their number and their positions are fixed by the
  profile, the logical refreshes are routed into them privately, and an unused
  slot performs a dummy refresh.
- **A fixed schedule alone does not establish circuit privacy.** It hides
  what the shape of the computation would disclose. It does not hide what the
  evaluated ciphertext carries: its noise depends on the hidden coefficients
  and on the values routed through it even when every level and size is
  fixed. Hidden-function privacy against the opener needs the circuit-private
  evaluation and sanitization of task R.11, established for the normalized
  evaluation under this schedule.

No class profile has a schedule yet. No profile is selected
([open question 2](#open-construction-questions)); tasks R.3, R.7 and R.9
build the schedules of `affine.v1`, `bounded.v1` and `refresh.v1` with the
bounds of C.3 ([open question 5](#open-construction-questions)).

### Obligations of the normalizing lowering

Each obligation has an owner in the [delivery plan](zk_delivery_plan.md). The
last column names the tests that check it today. They are tests of the
cleartext oracle in `iroha_crypto` (`ram_lfe::normal_form`); a test fails when
a row names a test that does not exist or a task the plan does not have.
`none` means that nothing checks the obligation yet: it is an obligation of
the tasks named, not a claim.

The `NL-S` rows are the semantic-equivalence obligations. The execution
relation must prove them against the cleartext reference: task R.3 for
`affine.v1`, extended by R.7 to the `Mul` and `SelectEqZero` gates and by R.9
to the `Refresh` gates. The `NL-L` rows are the leakage obligations that
follow from the fixed public schedule.

<!-- ram-lfe-normalizing-lowering-obligations -->
| Id | Obligation | Owner | Checked today by |
| --- | --- | --- | --- |
| `NL-S1` | **Reference equality.** For every class, every member tape, every lane vector and every admitted input, the normal form evaluates to the ordered output of the cleartext reference: the same scalars, the same count, the same order. The equality does not depend on admission: it holds for every 64 scalars of F257 in the input slots. | R.0 | `normal_form_equals_the_reference_on_randomized_tapes_of_every_class`, `normal_form_equals_the_reference_on_every_maximum_shape_family`, `every_instruction_may_alias_its_operands` |
| `NL-S2` | **Machine equality.** The forms the registers and the lanes hold after the last instruction evaluate to the last row of the reference trace, so every state update is resolved exactly. | R.0 | `state_updates_aliasing_and_output_snapshots_are_resolved_exactly`, `normal_form_equals_the_reference_on_randomized_tapes_of_every_class` |
| `NL-S3` | **Boundaries.** Every `Mul`, every `SelectEqZero` and every scheduled refresh is exactly one gate, in execution order. The ciphertext multiplications of the gates are those of the class accounting, and the depth is at most the logical rank. | R.0 | `nonlinear_instructions_stay_gates_in_tape_order`, `refresh_points_become_identity_gates_of_the_canonical_schedule`, `logical_rank_bounds_the_multiplication_depth_of_the_normal_form` |
| `NL-S4` | **Class on the tape.** Normalization refuses exactly the tapes class membership refuses, with the same error, and a tape has the same normal form under every class that admits it. | R.0 | `normalization_is_gated_by_the_declared_class`, `normal_form_equals_the_reference_on_every_maximum_shape_family` |
| `NL-S5` | **Reduced coefficients.** Every coefficient is exact and canonical, and a plaintext run of any length contributes one coefficient for each column. Runs that give the same forms leave no trace; a normal form is not canonical for the function of its tape. | R.0 | `plaintext_runs_fold_into_one_reduced_coefficient`, `plaintext_runs_that_give_the_same_forms_leave_no_trace`, `a_normal_form_is_not_canonical_for_the_function_of_its_tape`, `centered_scalar_is_the_least_magnitude_representative` |
| `NL-S6` | **Encrypted equality.** The output ciphertext of the encrypted evaluation decrypts to the output of `NL-S1` in the 64 padded output slots, with the unused slots zero, for every member tape up to the maximum shape. Those 64 slots are the vector an opening commits. | R.3, R.7, R.9 | none |
| `NL-S7` | **Proved, not asserted.** The execution relation proves, for the tape the function commitment commits, that the evaluated normal form is the normalization of that tape and that the tape is a member of the committed class. A normal form supplied as an unconstrained witness is not accepted. | R.3, R.7, R.9 | none |
| `NL-L1` | **One shape for each class.** Every member tape normalizes within the shape of its class, and every bound of the shape is reached: all of them by one tape, except that 64 outputs leave at most 192 nonlinear gates. | R.0 | `class_shape_is_a_function_of_the_class_and_every_bound_is_reached`, `rank_sixteen_does_not_bound_the_number_of_ciphertext_multiplications` |
| `NL-L2` | **One schedule for each class profile.** Levels, ciphertext sizes, evaluation keys, key switches, refresh slots and operation, access and proof shapes are identical for every member tape. | R.3, R.7, R.9 | none |
| `NL-L3` | **Padded bound.** The worst-case physical noise and the work of the complete padded schedule, with dummy work, key switches, masking and sanitization, are derived and measured at the maximum shape. No evaluation of a member tape fails. | C.3, R.3, R.7, R.9 | none |
| `NL-L4` | **Dummy work and routing.** Dummy operations and hidden routing change no column and no output, and the unused output slots are zero. | R.3, R.7, R.9 | none |
| `NL-L5` | **Private refresh accounting.** The physical refresh slots are fixed by the profile. The number and the placement of the logical refreshes of a tape are not observable. | R.9 | none |
| `NL-L6` | **Time and access.** What an observer outside the evaluator can time or measure for one execution does not depend on the tape. Work whose duration depends on the tape, such as normalizing it in cleartext, is not observable for a request. | R.11 | none |
| `NL-L7` | **Circuit privacy.** The leakage bound of the normalized evaluation under the fixed schedule is established with its sanitization and its maximum-shape physical noise. A fixed schedule is not a substitute. | R.11 | none |

Until the rows without a check are met, no class is usable. This contract
registers no production policy and makes no security claim for the existing
candidates.

### Commitments

Every commitment is one fixed domain followed by one canonical Norito frame
(`norito::encode_canonical`) of a named record. Field order is the order
listed. Enum variants encode in declaration order. Each frame row below is
compared with the definition in code by a test: the borrowed frames record
their field order where they are declared, and the public records are read
from their schema.

Public records use the Iroha Blake2b-256 `Hash`, whose last byte has its low
bit set. No domain is a prefix of another.

| Commitment | Domain | Frame fields, in order |
| --- | --- | --- |
| Plaintext semantics | `iroha.ram_lfe.v1.plaintext_semantics` | The descriptor bytes above, unframed. |
| Function identity `RamLfeFunctionIdV1` | `iroha.ram_lfe.v1.function_identity` | `RamLfeFunctionIdentityV1`: `class`, `plaintext_semantics`, `function`, `initializer`, `query_limit` |
| Query limit, inside the function identity | none of its own | `RamLfeQueryLimitV1`: `total`, `per_beneficiary` |
| Policy `RamLfePolicyCommitmentV1` | `iroha.ram_lfe.v1.policy` | `RamLfePolicyV1`: `function`, `profile`, `encryption_key`, `evaluation_key`, `opening_key`, `prf_key`, `relation` |
| Profile `RamLfeProfileIdV1` | `iroha.ram_lfe.v1.profile` | Byte string. |
| Relation `RamLfeRelationIdV1` | `iroha.ram_lfe.v1.relation` | Byte string. |
| Encryption key | `iroha.ram_lfe.v1.key.encryption` | Byte string. |
| Evaluation keys | `iroha.ram_lfe.v1.key.evaluation` | Byte string. |
| Opening key | `iroha.ram_lfe.v1.key.opening` | Byte string. |
| PRF key | `iroha.ram_lfe.v1.key.prf` | Byte string. |
| Input ciphertext | `iroha.ram_lfe.v1.ciphertext.input` | Byte string. |
| Output ciphertext | `iroha.ram_lfe.v1.ciphertext.output` | Byte string. |
| Associated data | `iroha.ram_lfe.v1.associated_data` | Byte string of 0..512 bytes. |
| Execution context `RamLfeExecutionContextIdV1` | `iroha.ram_lfe.v1.execution_context` | Byte string: the canonical frame of `RamLfeExecutionContextV1`: `network`, `program_id`, `replay` |
| Replay, inside the receipt and the execution context | none of its own | `RamLfeReplayV1`: `domain`, `nonce` |
| Receipt `RamLfeReceiptCommitmentV1` | `iroha.ram_lfe.v1.receipt` | `RamLfeReceiptV1`: `policy`, `network`, `program_id`, `beneficiary`, `associated_data`, `initialized_memory`, `input_ciphertext`, `output_ciphertext`, `expires_at_ms`, `replay` |
| Opening `RamLfeOpeningCommitmentV1` | `iroha.ram_lfe.v1.opening` | `RamLfeOpeningV1`: `receipt`, `output`, `opening_key`, `prf_key` |
| Any byte string above | the domain of its role | `RamLfeOpaqueBytesInputV1`: `length`, `digest` |

A byte string is committed through the last row: `length` is a u64 and `digest`
is the Iroha Blake2b-256 `Hash` of the bytes, with the low bit of its last byte
set (`Hash::new`); it is not the unmarked Blake2b output. Every byte string
except associated data must be nonempty. A key commitment covers the public form of its key. The
opening and PRF secrets never enter a commitment. Each role has its own type, so
a commitment cannot be used in another role.

The commitments with a private preimage use BLAKE3 derive-key over the
canonical frame, with a clearing hash state. They are raw 32-byte values and
carry no Iroha hash marker.

| Value | Context | Frame fields, in order |
| --- | --- | --- |
| Function `RamLfeFunctionCommitmentV1` | `iroha.ram_lfe.v1.function_commitment` | `RamLfeFunctionCommitmentInputV1`: `plaintext_semantics`, `class`, `program_key`, `instruction_count`, `tape` |
| Initializer `RamLfeInitializerCommitmentV1` | `iroha.ram_lfe.v1.initializer_key` | `RamLfeInitializerKeyInputV1`: `plaintext_semantics`, `class`, `function_commitment`, `program_key` |
| State lanes, 1,024 output bytes | `iroha.ram_lfe.v1.initial_state` | `RamLfeInitializationInputV1`: `function_identity`, `associated_data_hash`, `program_key` |
| Memory blinding, 32 secret bytes | `iroha.ram_lfe.v1.memory_blinding` | `RamLfeMemoryBlindingInputV1`: `function_identity`, `associated_data_hash`, `execution_context`, `program_key` |
| Initialized memory `RamLfeInitializedMemoryCommitmentV1` | `iroha.ram_lfe.v1.initialized_memory` | `RamLfeInitializedMemoryInputV1`: `function_identity`, `associated_data_hash`, `blinding`, `lanes` |
| Ordered output `RamLfeOutputCommitmentV1` | `iroha.ram_lfe.v1.ordered_output` | `RamLfeOrderedOutputInputV1`: `blinding`, `output_count`, `scalars` |

`instruction_count` and `output_count` are u16. `lanes` and `scalars` are
consecutive little-endian u16 values. `function_commitment` is the 32 raw bytes
of the function commitment. The state lanes are the extendable output of their
row, reduced as the descriptor states.

The **program key** is 32 uniformly random bytes. It blinds the tape commitment:
a digest of the tape alone would let anyone test a guessed program. It also
seeds the state lanes and the memory blinding. The initializer commitment takes
the class and the function commitment as well as the key, so it is different
for every class and tape and a program key used for two functions is not
visible in it. It takes the function commitment and not the function identity,
which contains the initializer itself.

The **memory blinding** is derived for each execution from the program key, the
function identity, the associated-data digest and the execution context. It is
never published and never leaves a clearing owner. Without it the
initialized-memory commitment would be a plain digest of public values and the
lanes, and a client could confirm lanes it computed from an opened output. The
execution context is built from execution fields (network, program, replay
scope and nonce) and never from the receipt commitment, because the receipt
contains the commitment it blinds. The execution relation must prove the
derivation of the blinding as well as of the lanes.

The **output blinding** is 32 fresh random bytes chosen by the opener for each
opening, so a low-entropy output cannot be guessed from its commitment.

Every secret of this contract lives in one heap allocation for its whole life:
the program key, the output blinding, the memory blinding, the reference input,
the initialized lanes and the reference machine. Moving an owner moves a
pointer. The allocation is cleared on drop, on an error return and during
unwinding, and tests observe the cleared cells on each of the three paths.
Copies a caller keeps and scalars the compiler holds in registers are not
covered.

**Function identity.** `RamLfeFunctionIdentityV1` holds the class, the
plaintext-semantics digest, the function commitment, the initializer commitment
and the query limit. It contains no encryption, evaluation, opening or PRF key
and no network, program or owner. It is therefore unchanged by rotation of any
key, and so are the state lanes, the opened output of every execution and the
query counts. `RamLfePolicyV1::rotate_encryption_keys` replaces the encryption,
evaluation and opening keys together and keeps the function identity, profile,
PRF key and relation.

**Policy.** `RamLfePolicyV1` is the one policy record. Validators take all seven
fields from committed State. A prover supplies none of them, so it cannot select
a weaker relation, another class, another query limit or a replacement key.

**Receipt.** `RamLfeReceiptV1` is the public statement of one execution.
`policy` is the commitment to the complete authoritative policy, `network` is
the `NetworkId` (the hash of the genesis header) and `beneficiary` is an
`AccountId`. Expiry is mandatory. `replay` is a scope, `Execution` or
`IdentifierClaim`, and a 32-byte nonce that must be unused in that scope; a
receipt made for one scope is not valid in the other.
`RamLfeReceiptV1::verify_authority` compares the policy commitment, the network
and the program with the values a validator derived itself. The policy record
names no program, so two programs registered with the same policy are told
apart by the program compared there.
`RamLfeReceiptV1::execution_context` returns the execution fields the memory
blinding binds.

**Opening.** `RamLfeOpeningV1` is the public statement of one opening.
`RamLfeOpeningV1::new` takes both keys from the policy and rejects a receipt of
another policy. Only the receipt's beneficiary may request it
([query limit](#query-limit)).

**Opened output.** Every V1 opening commits the 64 decrypted output slots: the
ordered output of the execution followed by zeros
(`RamLfeOrderedOutputV1::padded_for_opening`). The ordered-output frame of an
opening therefore always has `output_count` 64. This is an acceptance rule for
openings, not an invariant of a type: the frame, the output commitment and the
ordered-output owner are unchanged and still admit 1 to 64 scalars, and the
cleartext reference keeps exactly the scalars the tape emitted, in order. The
opener never holds the tape and cannot tell a trailing zero the tape emitted
from padding, so it has no other vector to commit. An opening conveys the
number of outputs the tape emitted to nobody; the program owner, who holds the
tape, is the only party that knows it. The same 64 slots are what the
decryption proof binds to the output ciphertext, what the output commitment
commits and the output component of the identifier-PRF derivation. The hiding
commitment shows validators no count, so the decryption proof of task R.8
enforces the rule. A differential check against the cleartext reference
compares the opened slots with the reference output padded with zeros to 64.
Tests show the rule on a short output, on trailing zeros the tape emitted and
on 64 outputs.

A receipt or an opening is a statement, not evidence. The execution relation
proves the first. Decryption and PRF proofs prove the second. No opener,
resolver or committee signature over either statement replaces those proofs.

### Cleartext reference

`ram_lfe_reference_execute_v1` runs a tape of a declared class on plaintext with
explicit lanes. `ram_lfe_reference_evaluate_v1` checks that a program key and
tape open a function identity, derives the lanes for that call and runs the
tape. Both return the ordered output, the initialized lanes, the class
accounting with the refresh schedule and a private per-instruction trace.
Registers and lanes exist only inside one call.

It is the oracle for an encrypted evaluator and for an execution relation. It
runs on plaintext, so it is a tool for the program owner and for tests, not an
evaluator, and it is not constant time. Tests pin vectors for every opcode at
the field edges, the complete `SelectEqZero` formula for every condition, the
initializer stream and one full evaluation. One test runs an eleven-opcode tape
through this reference and through the diagnostic encrypted interpreter on the
same lanes and compares the decrypted outputs.

`ram_lfe_reference_normalize_v1` is the plaintext definition of the
[normalizing lowering](#normalizing-lowering). It takes a tape of a declared
class, refuses what class membership refuses, and returns the private normal
form (`RamLfeNormalFormV1`). That owner holds the gates with their operand
forms, the output forms, the forms the registers and lanes hold at the end,
the multiplication depth and the class accounting.
`RamLfeNormalFormV1::evaluate` and
`evaluate_final_state` run it on plaintext. `RamLfeNormalShapeV1::of` is the
largest normal form of a class and `RamLfeNormalRoleV1::of` the role of an
opcode. Tests require the normal form to equal the reference exactly, in the
ordered output and in the final machine: on randomized member tapes of every
class, a quarter of them at the maximum length of 256 instructions, each on
admitted inputs and on arbitrary scalars of F257 in the 64 input slots, on the
nine maximum-shape families of the cost model under every class that admits
them, and on tapes built for state aliasing, operand aliasing, output
snapshots, cancelled coefficients, dead gates and refresh points.

The nine families are mirrored in the tests of the oracle from the tape
builders of the cost model
(`crates/iroha_fhe/tests/support/machine.rs`, module `families`). One test
compares their class, instruction count, output count and peak rank, and the
shape limits, with the recorded [cost summary](fhe_bgv_cost_summary.json).
Another pins a digest of the code of those builders and of the table that
names them, so a changed family fails a test of the oracle until the mirror is
compared again. The summary records no digest of a family tape; recording one
belongs to task C.3.

The normalizer is a cleartext oracle for the program owner and for tests, like
the reference. It reads the hidden tape and is not constant time. Its buffers
are heap allocations of fixed capacity that are cleared when they drop. A
class refusal is returned before any buffer exists, so the only error returned
while a buffer holds data is an allocation failure. Tests observe the cleared
scalars when a form and its evaluations end, when a refused reservation
returns an error after the refresh schedule and the initial symbolic machine
of a normalization or the plaintext column values of an evaluation were
written, and during unwinding. After its last reservation a normalization
returns no error, so no error is returned while a folded form holds data. No
encrypted normalizer exists; task R.3 builds it and compares it with this
oracle.

`RamLfeOrderedOutputV1::padded_for_opening` gives the 64 slots an
[opening commits](#commitments) for a reference output.

### Open construction questions

These are not decided by this contract. Each names its owner in the
[delivery plan](zk_delivery_plan.md).

1. **In-relation hash (R.3).** The relation must prove knowledge of the program
   key and tape behind the function and initializer commitments and derive the
   lanes and the memory blinding inside the shared proof engine. The cost of
   BLAKE3 there is not measured. The
   [Poseidon role table](ram_lfe_semantic_commitments.md) is a proposed
   alternative. Adopting another hash replaces the descriptor, these frames and
   every pinned vector together; it never adds a second accepted commitment.
2. **Encryption profile (C.3).** No profile is selected. The canonical bytes of
   a profile descriptor, of each public key and of a ciphertext frame are
   undefined, so `RamLfeProfileIdV1` and the key and ciphertext commitments have
   no production input yet.
3. **Circuit privacy (R.11).** The sanitization construction, its parameters and
   its proof are not chosen. Until then nothing bounds what an opener learns
   from an evaluated ciphertext.
4. **Client well-formedness (R.11).** The relation and its binding to the input
   commitment are not implemented.
5. **Fixed public schedules (C.3, R.3, R.7, R.9, R.11).** No class profile has
   a [schedule](#fixed-public-schedule). The largest normal form of each class
   is fixed above. The physical schedule of each class profile is not derived:
   its levels, its ciphertext, key and proof sizes, its key switches and
   refresh slots, how a gate slot hides the kind of its gate, how values are
   routed, and its worst-case noise and work bound.
6. **Opening and PRF (R.8).** The public opening material, the PRF, the carrier
   of the derived identifier and any expiry of the opening itself are not chosen.
   What an opening commits is decided: the 64 padded output slots
   ([Commitments](#commitments)), which the decryption proof, the output
   commitment and the output component of the PRF derivation all bind.
7. **Query-limit enforcement (R.8, R.11, R.12).** The limit, its scope and its
   counting rule are specified [above](#query-limit). Where State keeps the
   per-identity and per-beneficiary counts and the set of opened receipts, and
   how a threshold committee checks an accepted request before it contributes,
   are decided where they are enforced.
8. **Refresh (R.9, C.8).** The refresh algorithm does not exist. The rank limit
   16 and the count 64 are candidates to be derived again from a noise model.
   How the private logical refreshes of a tape are routed into refresh slots
   the profile fixes is part of that work.
9. **Threshold opening (R.10).** What the opening-key commitment covers for a
   committee and its epochs is not specified.
10. **Receipt consumers (R.12, R.4).** The time source for expiry, the replay
    set and whether two replay scopes suffice are decided where the receipt is
    consumed.
11. **Proof of the normalizing lowering (R.3, R.7, R.9).** Whether the relation
    constrains normalization step by step or proves equality with the
    reference another way, and how it binds the normal form to the committed
    tape, is not chosen. The cleartext oracle fixes what must be proved.
12. **Whether folding suffices (C.3).** Folding removes the growth of
    plaintext runs. Whether a candidate of this kind holds the padded maximum
    shape of each class after folding, with key switches, masking and
    sanitization, is not known; the only figure is a projection for the
    affine map. A candidate that does not hold it is replaced by construction
    work. No class becomes optional and no limit is added to a class.

## Provider-backed phone control

Status: the records, commitments and verification rules of this section are
implemented as types and tests, in
[`iroha_crypto::ram_lfe`](../crates/iroha_crypto/src/ram_lfe/phone_control.rs)
(number commitment, provider key identity, signature rule) and
[`iroha_data_model::phone_control`](../crates/iroha_data_model/src/phone_control.rs)
(challenge, credential, provider policy). No Core, Torii or SDK path consumes
them. The phone path of the
[current-path inventory](#current-implementation-and-trust-boundary) is
unchanged: it still names the pinned canonicality attestor and still refuses.
The private relation is task R.2, State enforcement and the removal of the
attestor are task R.4, and the one-call flow is task R.5 of the
[delivery plan](zk_delivery_plan.md). Until R.2 and R.4 exist a phone claim
stays refused.

### What control evidence is

A phone claim binds a number to an account, and a payment addressed to the
number then reaches that account. Three facts are separate, and evidence for
one establishes none of the others:

| Fact | Established by |
| --- | --- |
| The encrypted input is one canonical E.164 number. | The private relation over the input ciphertext (R.2). |
| No other live binding holds the number. | The keyed nullifier and the exclusive live binding in State (R.2, R.4). |
| The claimant controls the number. | A provider credential, specified here. |

Canonical format and uniqueness do not show control. Anyone who knows a number
can encrypt it in canonical form, and without control evidence the first such
claim would take the number. A phone claim without valid control evidence is
rejected.

The user selected verification-provider credentials as the control evidence.
The evidence is checked by rule against committed State. No reviewer approves a
claim, and the canonicality attestor is neither kept nor brought back as a
gate: a signature that says "this ciphertext holds a canonical number" is not
evidence of control and is not part of this contract.

A credential replaces no proof of the
[canonical V1 contract](#canonical-v1-contract). Execution, decryption and
identifier derivation are still proven, and no provider signature stands in
for any of them. The credential is not proven inside a relation either:
validators verify the provider signature directly, and the relation of R.2
proves what the signature cannot say, namely that the committed number is the
encrypted input.

### Flow

1. The client normalizes the number to canonical E.164, draws a fresh blinding
   and computes the [number commitment](#number-commitment).
2. Over the provider's authenticated and confidential channel the client sends
   the number, the blinding, a fresh client nonce and the values the credential
   will be bound to: network, identifier namespace, policy commitment and
   beneficiary account.
3. The provider recomputes the commitment from the number and the blinding. It
   adds a fresh provider nonce and a fixed expiry. This fixes the challenge
   record. Only then does it send a one-time code to the number by SMS, or ask
   the carrier.
4. When the claimant answers correctly in time, the provider signs one
   credential for exactly that challenge record.
5. The client presents the challenge record and the signed credential with its
   claim, together with the private proof of R.2.

The provider learns the number, the blinding, the beneficiary account, the
network and the namespace. It sees no ciphertext, no receipt and no
nullifier, and it does not hold the identifier PRF secret. Validators, the
evaluator and the ledger see the commitment and never the number. The opener
can decrypt the input, as the [roles](#roles-and-collusion) already state.

A presented credential is public. It shows that this provider confirmed, at
this time, that this account controls some number. It does not show which.

### Number commitment

The credential carries a hiding commitment to the number so that the relation
of R.2 can tie the credential to the encrypted input without disclosing the
number. The relation recomputes the commitment, so the digest is the hash the
shared proof backend computes in its own field, as the
[primitive decision rule](zk_primitive_workloads.json) requires for a digest
that is recomputed inside a relation.

The commitment is the six-lane digest `GoldilocksDigest384V1` of `fastpq_isi`
over one typed frame (`GoldilocksDigest384FrameV1`):

<!-- phone-control-number-commitment -->
| Frame part | Value |
| --- | --- |
| catalog | `iroha-privacy-exact12-v1` (`FASTPQ_CATALOG_V1`) |
| protocol | `iroha.ram_lfe.v1.phone_control` |
| profile | `goldilocks-digest384-v1`, the label of the digest identity |
| role | `number-commitment` |
| phase | empty |
| level, index, counter | 0 |
| field 0 | 16 bytes: the canonical E.164 ASCII bytes, zero-padded on the right |
| field 1 | 32 bytes: the blinding |

- **Number field.** Canonical E.164 is `+`, a nonzero digit and one to
  fourteen more digits: 3 to 16 bytes. It contains no zero byte, so the padding
  is unambiguous. The field is exactly RAM-LFE input slots `1..=16` of the
  canonical input; slot 0 holds the length and every later slot is zero. The
  set of admitted numbers is the set the keyed nullifier derivation admits; a
  test compares the two.
- **Blinding.** 32 bytes from the client's cryptographic random source, fresh
  for every challenge and never reused. A phone number has at most fifty bits
  of entropy, so an unblinded digest would let anyone test a guess. Two
  commitments to one number under two blindings are unrelated, so credentials
  do not link claims. The keyed nullifier links them, inside State and without
  the number, and it is derived from the canonical unpadded number alone, never
  from the blinding.
- **Value.** 48 bytes: six little-endian Goldilocks words in lane order. Every
  decoder rejects a word at or above the field modulus and never reduces one.
  The provider signs the digest identity and all 48 bytes.
- **Witnesses.** The number and the blinding live in clearing heap owners at
  the client and at the provider, and the digest clears its scratch.

The number `+15551234567` under a blinding of 32 bytes `0x42` commits to
`087ebe46155a3b3b006b68ed8dbe85eba1758ea13d0765454ca2c591d86ecf8b0f34b3a95ef9eee079e95cf27e3d1c43`.

The digest is **unqualified**. The
[digest security record](fastpq_compact_digest_security.md) establishes no
collision, preimage or hiding bound for the six-lane construction. Binding of
the commitment needs its collision resistance. Hiding needs it to behave as a
random function of the blinding. Neither is established, and this contract
does not claim them.

The choice depends on the profile freeze of task H.2, which selects the
in-relation digest of the shared backend. The commitment therefore carries a
typed digest identity, `PhoneNumberCommitmentDigestV1`. Exactly one identity is
implemented, and a decoder rejects every other tag. If H.2 selects another
digest, it replaces this identity, the frame above and the pinned vector
together. Two identities are never accepted side by side.

What the relation of R.2 must prove about the commitment. None of it is
implemented:

- It knows a number field and a blinding whose exact framed digest is the six
  signed words, which are public inputs.
- The number field equals input slots `1..=16` of the plaintext of the
  receipt's input ciphertext. Slot 0 is the length of the number. The bytes
  are `+`, a nonzero digit and one to fourteen more digits. Every slot after
  the number is zero.
- The keyed nullifier is derived from the same canonical unpadded number under
  the registered PRF key.

A verified credential says nothing about a ciphertext until that relation
exists.

### Records and frames

Every commitment and the signed message is one fixed domain followed by one
canonical Norito frame (`norito::encode_canonical`) of a named record, as in
the [commitments](#commitments) of the V1 contract. Field order is the order
listed, and tests compare each row with the definition in code. No domain of
this table or of the V1 tables is a prefix of another.

| Value | Domain | Frame fields, in order |
| --- | --- | --- |
| Number commitment | the typed frame above | `PhoneNumberCommitmentV1`: `digest`, `value` |
| Provider key identity `PhoneControlProviderKeyIdV1` | `iroha.ram_lfe.v1.phone_control.provider_key` | `PhoneControlProviderKeyInputV1`: `algorithm`, `public_key` |
| Provider policy commitment `PhoneControlProviderPolicyCommitmentV1` | `iroha.ram_lfe.v1.phone_control.provider_policy` | `PhoneControlProviderPolicyV1`: `identifier_policy`, `max_credential_lifetime_ms`, `max_binding_lifetime_ms`, `longer_credentials_expire_by_ms`, `keys` |
| Provider key, inside the provider policy | none of its own | `PhoneControlProviderKeyV1`: `public_key`, `active_from_ms`, `state` |
| Challenge identity `PhoneControlChallengeIdV1` | `iroha.ram_lfe.v1.phone_control.challenge` | `PhoneControlChallengeV1`: `provider`, `network`, `identifier_policy`, `policy`, `beneficiary`, `number`, `client_nonce`, `provider_nonce`, `expires_at_ms` |
| Message the provider signs | `iroha.ram_lfe.v1.phone_control.credential` | `PhoneControlCredentialV1`: `provider`, `network`, `identifier_policy`, `policy`, `beneficiary`, `challenge`, `number`, `issued_at_ms`, `expires_at_ms` |
| Signed credential | none of its own | `PhoneControlSignedCredentialV1`: `credential`, `signature` |
| Control evidence of one claim | none of its own | `PhoneControlEvidenceV1`: `challenge`, `credential` |

The provider key identity commits the algorithm tag and the public key bytes.
The three identities and the policy commitment are Iroha Blake2b-256 `Hash`
values. The signature is over the domain bytes followed by the frame, not over
a digest of them.

### What the credential binds

| Field | Binds | A validator compares it with |
| --- | --- | --- |
| `provider` | The provider key, by the commitment to its algorithm-tagged public key. | A key of the committed provider policy of the namespace. |
| `network` | The genesis-derived `NetworkId`. | Its own network. |
| `identifier_policy` | The identifier namespace the claim is made in. | The namespace of the claim. State resolves the program of that namespace, and the receipt must name that program. |
| `policy` | The commitment to the complete RAM-LFE policy: function identity, profile, every key and the relation. | The policy State holds for the program of the namespace, which is also the policy of the receipt. |
| `beneficiary` | The `AccountId` that showed control and receives the binding. | The account the claim binds, which is also the beneficiary of the receipt. |
| `challenge` | The identity of the challenge record. It is the nonce. | The presented challenge record. State consumes it once. |
| `number` | The number commitment: digest identity and 48 bytes. | The public input of the relation of R.2. |
| `issued_at_ms`, `expires_at_ms` | The validity interval, in milliseconds since the Unix epoch. | Consensus time, the committed lifetime bounds and the lifecycle of the key. |

The challenge record binds the provider key, network, namespace, policy,
beneficiary, number commitment and expiry again, with the client nonce and the
provider nonce. The credential must repeat each shared field exactly, and its
expiry must equal the expiry of the record.

Changing any bound field invalidates the evidence. Tests substitute each field
in the credential, in the challenge record and in the authoritative context at
once, so that only the provider signature still names the original value, and
verification fails on the signature. The same substituted statement is
admitted once the named provider really signs it.

Rotation of the encryption key changes the policy commitment. An outstanding
credential then matches no policy, and the client repeats the challenge.

Provider keys are Ed25519 or ML-DSA-65. No other algorithm is admitted.
Verification is strict for the algorithm of the key. An Ed25519 signature must
have a canonical `R` in the prime-order subgroup and satisfy the cofactorless
equation, so a second signature that only an unchecked verifier accepts is
rejected. An ML-DSA-65 signature must have the exact detached length. A
provider uses a dedicated key for credentials.

### Validity, replay and expiry

`now_ms` is the consensus time of the block that admits the claim. It comes
from committed State and never from the clock of a node. The source is
selected with [open question 10](#open-construction-questions).

- **Interval.** A credential is admissible while
  `issued_at_ms <= now_ms < expires_at_ms`. The expiry is exclusive: the
  credential is admitted at `expires_at_ms - 1` and rejected at
  `expires_at_ms`. There is no skew allowance. A provider whose clock runs
  ahead issues credentials that become admissible later, and one whose clock
  runs behind issues credentials that expire sooner.
- **Lifetime.** The interval is not empty, and
  `expires_at_ms - issued_at_ms <= max_credential_lifetime_ms`, the bound the
  provider policy commits. "Short-lived" means bounded by that committed
  value. The contract fixes no number of minutes.
- **Binding bound.** A binding never outlives its credential. The credential
  and the provider policy bound the binding by the earlier of `expires_at_ms`
  and `issued_at_ms + max_binding_lifetime_ms`, counted from the issue time
  and not from the admission. The policy keeps
  `max_binding_lifetime_ms <= max_credential_lifetime_ms`, because a larger
  value could never apply. The committed credential lifetime is therefore also
  the longest time a number stays bound without fresh control.
- **Earliest applicable expiry.** The expiry of a binding is the earliest of
  that bound and the expiry of everything else the binding rests on: the
  receipt, the opening, the keys and the policy. No bound extends another. The
  result must be strictly after the admission time, or the claim is rejected;
  in particular a credential admits nothing once
  `now_ms >= issued_at_ms + max_binding_lifetime_ms`.
- **Renewal.** The same account renews with a fresh challenge and a fresh
  credential. A renewal replaces the expiry with the earliest bound of the new
  evidence, also when that is earlier, and replaces the provider key and the
  admission time kept for [revocation](#provider-policy-in-committed-state).

Challenge replay is prevented in two places.

At the provider, which validators cannot observe and which is part of the
[trust in the provider](#issuer-compromise): the one-time code is bound to one
challenge record, is accepted once, has a short answer deadline and a bounded
number of attempts, and the provider nonce is fresh.

On the ledger, by rule:

- State consumes `(network, challenge)` in the same atomic transition that
  admits the claim. A second claim with the same challenge is rejected,
  whoever submits it and whichever credential it carries. A rejected
  transaction consumes nothing.
- A credential cannot move to another beneficiary, network, namespace or
  policy: each is signed, and each is committed by the challenge identity.
- A party that copies a presented credential cannot use it. The challenge is
  consumed, and the party knows neither the number nor the blinding the
  relation of R.2 needs.
- State may forget a consumed challenge from its recorded expiry on. The
  recorded value is the expiry of the credential and not the bound of the
  binding, which may be earlier: until the credential expiry the provider can
  sign a second credential for the same record, and only the entry rejects
  it. The expiry is a field of the challenge record and the credential must
  repeat it, so one challenge identity has one expiry for ever. After the
  entry is pruned, every credential that names the challenge is expired, and
  the same challenge cannot return with a later expiry.

### Provider policy in committed State

`PhoneControlProviderPolicyV1` is the provider trust policy of one identifier
namespace. Validators take every field from committed State. A claimant and a
provider supply none. The owner of the identifier policy registers it and
changes it through authorized State transitions (R.4), and only through the
transitions listed below. Each takes the consensus time of the block that
applies it where its rule depends on time, and the rules assume that this time
never decreases. It holds at most 32 keys, in every state.

<!-- phone-control-provider-key-lifecycle -->
| State | A credential under the key is issued with | Existing bindings |
| --- | --- | --- |
| `Active` | `active_from_ms <= issued_at_ms` | Unaffected. |
| `Retired` from `retired_from_ms` | `active_from_ms <= issued_at_ms < retired_from_ms` | Unaffected. Retirement is an issuance boundary. A credential issued earlier stays admissible until it expires. |
| `Revoked` with `compromised_from_ms` | Nothing. Every credential under the key is rejected, whatever its issue time. | A binding is evicted when the credential that supports it was admitted at ledger time `>= compromised_from_ms`. |

`active_from_ms` is kept in every state. Every key transition narrows what is
admitted. None makes a rejected credential admissible, and none restores an
evicted binding:

- **Registration.** A key is trusted from its registration on:
  `active_from_ms` is not earlier than the consensus time of the registering
  transition. An identity that is present in any state is not registered
  again.
- **Rotation.** The owner registers the new key and retires the old one. Both
  may be active for an overlap. A retirement is never backdated:
  `retired_from_ms` is not earlier than the consensus time of the retiring
  transition. A retired key may only retire earlier, and again not earlier
  than the time of that transition, so a retirement whose instant has arrived
  is final. Every credential admitted under a retired key was therefore issued
  at or before `retired_from_ms`. A key that may have signed without the
  consent of its provider in the past is not retired into the past. It is
  revoked.
- **Revocation.** It is terminal for the key identity. A compromised key can
  backdate `issued_at_ms`, so the issue time decides nothing: every credential
  under the key is rejected, and eviction uses the ledger time at which the
  supporting credential was admitted, which the key cannot forge. For a
  renewed binding that is the admission of the latest renewal. When the onset
  of a compromise is unknown, the cutoff is conservative and covers every
  admission the compromise may affect. A cutoff may lie in the past and may
  only move earlier.
- **Removal.** A retired key is removed once
  `now_ms >= max(retired_from_ms + max_credential_lifetime_ms, longer_credentials_expire_by_ms)`.
  Every credential admitted under it was issued at or before
  `retired_from_ms` and lives at most the credential lifetime it was admitted
  under. Its expiry is exclusive, so it has expired at that instant, and so
  has every binding, because no binding outlives its credential. Until then
  the record exists, so the key of a live binding can always be revoked. A
  revoked key is never removed.
- **Lifetimes.** `set_lifetimes` is the only change of
  `max_credential_lifetime_ms` and `max_binding_lifetime_ms` after the policy
  is registered. The new bounds apply to every later admission, and a raised
  bound admits credentials the lower one refused. A binding that exists keeps
  the expiry it was admitted with. When the credential lifetime is lowered at
  consensus time `now_ms`, every credential admitted under the previous value
  expires at or before `now_ms` plus that value. The policy keeps the latest
  such instant in `longer_credentials_expire_by_ms`, which is zero until the
  first lowering, so that the lower value never shortens the wait before a
  removal. A lowering whose instant overflows is rejected. Raising a lifetime
  and any change of the binding lifetime record nothing.
- **Capacity.** A retired key frees its slot when it is removed. A revoked key
  never does, because its identity must stay known to stay untrusted. Each
  revocation therefore takes one of the 32 slots for good.
  After 32 revocations every slot holds a revoked key: the namespace can
  register no key and admits no claim, and its remaining bindings run to
  their expiry. This contract defines no way back. Whether State may replace
  the provider policy of a namespace is decided by R.4, and a replacement must
  not silently trust a revoked identity again.

The rules that reach State are functions of the records
(`PhoneControlEvidenceV1::verify`, `PhoneControlAdmissionV1::consume_challenge`
and `earliest_expiry_ms`, `PhoneControlProviderKeyV1::evicts_binding`, and the
key and lifetime transitions of the policy). Each takes the persisted value
and returns the next value or an error, and tests exercise each at its
boundary. One test runs every order and schedule of an admission, retirements
and lifetime changes over a small range of instants and checks that no key is
removable while a credential admitted under it is live. Where State keeps the
provider policy, the consumed challenges and the key and admission time of
each binding is decided by R.4. The record does not enforce that State uses
the transitions and passes consensus time. That is part of R.4.

### Number recycling and reassignment

Carriers reassign numbers. A binding is evidence about the past: it shows who
controlled the number at `issued_at_ms`.

- **A live binding stays exclusive.** Newer control evidence from another
  account does not evict it. The claim of the other account is rejected until
  the binding expires or is revoked.
- **Bounded expiry.** Every binding expires, at the latest
  `max_binding_lifetime_ms` after its credential was issued. The previous
  holder of a reassigned number cannot renew, because renewal needs fresh
  control.
- **Revocation.** The account that holds the binding, or the owner of the
  identifier policy on a dispute, ends it early through the existing
  `RevokeIdentifier` authority.
- **After expiry or revocation** the number is free. The
  first valid claim admitted in ledger order takes it. Obtaining a credential
  reserves nothing, and a former holder has no priority.

Exposure: after a number changes hands, payments addressed to it still reach
the previous holder until the binding expires or is revoked, for at most the
remaining life of the binding. The owner of the namespace chooses that window
with `max_binding_lifetime_ms`. This contract does not shorten it by detecting
reassignment.

### Issuer compromise

The provider is trusted for one statement: the beneficiary answered a fresh
challenge sent to the committed number. Nothing on the ledger can check that
statement. The provider learns the number of every claimant it serves and can
keep a record of numbers and accounts. The contract does not prevent that.

A party that holds a registered provider key, or a provider that signs without
a challenge, can issue a credential for any number and any account. With it,
that party can:

- claim any number that has no live binding, and receive the payments
  addressed to it, until the binding expires or is revoked;
- choose `issued_at_ms` freely, also in the past.

It cannot:

- evict a live binding, which stays exclusive;
- use a credential on another network, namespace, policy or account than the
  one it signed, or use one challenge twice;
- forge an execution, decryption or derivation proof. It still has to produce
  the proofs of a real claim for the number it takes;
- outlast revocation. Once the key is revoked, every credential under it is
  rejected and every binding admitted from the cutoff on is evicted.

Exposure runs from the compromise to the revocation and is bounded by the
bindings admitted in that window. A namespace with several providers is
exposed to the weakest of them: one key suffices for a claim. The contract has
no threshold of providers.

### SIM takeover

A party that receives the SMS of a number, through a SIM swap, a ported number,
an intercepted message or a compromised handset, passes a genuine challenge.
The provider then issues a genuine credential, and no rule of this contract
can tell that claim from the claim of the subscriber. With it, that party can
claim the number when it has no live binding, including the moment a binding
of the subscriber expires, and then receives the payments addressed to it. The
subscriber cannot renew while that binding is live.

It cannot evict a live binding of the subscriber. The exposure of a subscriber
who keeps a binding live is therefore the renewal: whoever controls the SMS
when the binding has ended can take the number.

Recovery is revocation by the owner of the identifier policy, and expiry. A
carrier check in place of SMS, where a provider offers one, changes who can
pass the challenge and not this analysis. Payments already made to a
fraudulent binding are not undone by revocation.

## Encryption replacement requirements

The [implementation plan](ram_lfe_encryption_replacement.md) records the current
rounded-path noise limit, the RNS-BGV starting candidate that now owns genuine
RNS arithmetic in `iroha_fhe`, packing constraints and ordered implementation
steps. Neither the existing BFV arithmetic nor that candidate is a selected
replacement: no profile is qualified and nothing consumes the candidate.

The replacement must protect both encrypted inputs and the hidden function.
Ordinary HE input confidentiality does not by itself establish circuit privacy
against a key owner inspecting evaluated ciphertexts. This distinction is explicit
in [Hwang, Min and Song's BFV analysis](https://eprint.iacr.org/2025/203).
Choosing a library is also not sufficient to justify malicious-input security:
[OpenFHE's security notes](https://openfhe-development.readthedocs.io/en/latest/sphinx_rsts/intro/security.html)
state the semi-honest scope of its ordinary HE APIs. These are requirements for
the new protocol, not endorsements of an unreviewed construction.

The roles and their collusion assumptions are specified
[above](#roles-and-collusion).
Bind admitted keys and ciphertexts to the precise well-formedness relation;
account for malicious parameters, inputs, repeated queries and visible failures.
Select circuit privacy or an appropriate sanitization construction with explicit
assumptions and quantified leakage. Do not claim that ZK about evaluation hides
information already present in its public ciphertext output.

Parameter selection must jointly cover security, correctness and maximum
program work, as described by the
[HE implementation guidelines](https://eprint.iacr.org/2024/463). Pin the complete
RNS chain, distributions, failure probability, operation/noise bounds and query
budget to the selected profile. Existing degree-64 and single-modulus arithmetic
limits are diagnostic implementation facts, not security targets for a replacement.

The developer facade must choose a supported fixed profile from the compiled program,
own private keys and secure randomness, and preflight bounded resources before
private work. Developers supply their program and data; they do not select ring
dimensions, noise distributions, transcript layouts or deterministic encryption
seeds. Keep key generation, input encryption, evaluation, plaintext opening and
proof verification as distinct typed operations with explicit authorities.

## Required relation

The verifier-owned statement is the canonical `RamLfeReceiptV1`. Validators
derive its policy commitment, network and program from committed State and take
the beneficiary, context, ciphertexts, expiry and replay nonce from the
transaction.
The superseded `RamLfeExecutionReceiptPayload` binds neither the full policy,
the network, the beneficiary, the initialized memory nor a replay nonce, and no
relation may be built over it. A proof must not transfer between two function
identities, two policies or two requests.

Private witnesses must establish the policy's secret commitment, exact hidden
program encoding, initialized register reads, every instruction and memory
transition, output ordering, and exact BFV modular arithmetic and relinearization.
All coefficient, index, quotient, remainder and depth bounds belong in the
relation. Host-side interpreter checks alone cannot establish these facts.

The relation proves the [normalizing lowering](#normalizing-lowering), not an
instruction-by-instruction evaluation. For the tape behind the function
commitment it establishes class membership on the tape, that the evaluated
normal form is the normalization of that tape, and that the encrypted
evaluation follows the [fixed public schedule](#fixed-public-schedule) of the
committed class profile and decrypts, in the 64 padded output slots, to what
the cleartext reference outputs followed by zeros.
These are the `NL-S` rows of the
[obligations](#obligations-of-the-normalizing-lowering). A normal form, a
routing or a refresh placement supplied as an unconstrained witness is not
acceptable. The proof has one shape for each class profile.

The canonical hidden program is a validated immutable shared owner. Its sole
`HiddenRamFheProgramV1` frame contains fixed profile metadata followed by 1..256
48-byte instruction slots: six little-endian u64 words per instruction, with
all unused words zero. The typed builder writes into one bounded clearing tape;
the explicit byte/config readers enforce the same format and reject retired
enum-sequence frames. The owner checks structure only; class membership is a
separate check. The relation must constrain every tag, operand, reserved word,
bound and class limit in this exact encoding. Generic archive decoding is
deliberately unavailable for this secret owner.

The retained diagnostic initializer uses a fixed BLAKE3 derive-key XOF schedule.
A borrowed canonical Norito frame binds the initializer descriptor, policy hash,
secret and associated data. Because it binds the policy hash, its lanes change
when an encryption key rotates; the canonical V1 initializer binds the function
identity instead and uses the same stream and reduction.
Exactly 1,024 bytes become 32 consecutive big-endian
256-bit values, each reduced modulo 257 by 32 fixed byte folds. No library range
sampler or rejection loop defines protocol semantics. The published profile's
mandatory `initializer_descriptor_hash` commits the framing, contexts, dimensions
and bounds. Superseded profiles are rejected rather than assigned another mapping.

Secret commitment and private tape hashing now use separate BLAKE3 contexts and
clearing owned hash/XOF state. The outer policy and tape digests remain properly
typed Iroha Blake2b hashes of public commitments. Policy, program and dependent
output vectors change explicitly; parameter and evaluation-key algorithms do not.
The outer policy commits the canonical `PolicyCommitmentInputV1` frame, in field
order: backend, normalized public-parameter bytes and secret commitment. The PRF
uses the canonical `HkdfRequestInputV1` frame: policy hash, public parameters,
associated data and normalized input. These explicit first-release identities
replace ambient-layout tuples. Borrowed interpreter fields and owned reference
fixtures must produce identical frames; no reference-schema alias is introduced.
Torii hashes the canonical ciphertext frame independently of ambient decoder
flags.
The execution trace comes from the sole interpreter and owns clearing snapshots
of its registers and memory. It is private prover input, not execution evidence.
The future circuit must constrain these exact hash/Norito/fold semantics and all
machine transitions; arbitrary initialized-state witnesses remain unacceptable.

## Implementation and acceptance criteria

1. Replace the insecure exact-lift encryption profile with one whose parameters,
   distributions and failure bounds are derived for the complete workload
   (delivery plan task C.3). Define the replacement statement, witness and
   bounded derivation; retain canonical Norito encoding without a legacy decoder
   or alternate relation.
2. Evaluate through the normalizing lowering under the fixed public schedule
   of the class profile. Emit an owned, clearing execution trace from the
   encrypted evaluator and compare it with the cleartext reference and with
   the cleartext normal form, which supply the independent vectors for all
   eleven instructions and the maximum shapes. Trace generation alone is not
   proof completion.
3. Implement the complete fixed-profile relation over the proof engine selected
   under [open question 1](#open-construction-questions), with a dedicated
   relation identity, canonical key owner and typed verifier. Constrain
   encoding/hash preimages, the initial-state derivation and the memory-blinding
   derivation as well as the machine transitions. Do not use unconstrained
   native arithmetic callbacks.
4. Pass real native positive proofs and direct-witness negatives for altered
   secret/policy/program/parameters/keys, input/output/associated data/receipt,
   omitted or repeated transitions, invalid register or memory access, modular
   aliases, wrong relinearization and incorrect `SelectEqZero`, and for a
   normal form that is not the normalization of the committed tape, a wrong
   coefficient, a moved or dropped gate, a wrong routing and a schedule other
   than the profile's. Demonstrate maximum-shape correctness and the
   worst-case physical noise of the padded schedule independently of logical
   rank. Measure maximum
   proof size, prover/verifier work and memory, test error and unwind witness
   erasure, and record every admission limit the relation changes. An
   independent review of soundness and hiding yields findings and repairs; it
   is not a permission to use the relation.
5. Integrate a canonical Torii producer without caller-selected circuits or keys,
   and one purpose-specific verifier shared by stateless and identifier receipt
   consumers. Test registration, restoration and receipt mutations, including
   on a four-validator network. The genuine verifier replaces the
   unavailable-relation refusal in the change that delivers it: no activation
   step, qualification record or approval stands between the implemented
   relation and its use, and deleting the refusal without the relation is not a
   delivery. Enforce the query limit and the beneficiary-only opening request in
   the same consumers. An execution proof is not a decryption proof: the opening
   needs its own decryption and PRF proofs, and no signature replaces them.

Current source review and implementation status are also summarized in the
[audit matrix](zk_audit_matrix.md). There is no safe adapter-only completion or
payload-hash proof substitute for these requirements.
