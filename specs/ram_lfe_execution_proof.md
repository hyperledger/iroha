# RAM-LFE execution-proof completion

Status: the [canonical V1 contract](#canonical-v1-contract) below is implemented
as types, commitments and a cleartext reference interpreter. The encrypted
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
the canonical `bounded.v1` class. Its ring degree is 64, plaintext modulus is
257 and ciphertext modulus is `257 * 2^48`.
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
semantics, commitments and the cleartext reference. Code:
[`iroha_crypto::ram_lfe`](../crates/iroha_crypto/src/ram_lfe.rs) modules
`class`, `canonical` and `reference`, and
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
plaintext output and every refresh point. Evaluation and proof shapes are one
fixed padded shape per class; a private count never selects a smaller one.

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

`refresh.v1` keeps the eleven instructions; there is no refresh opcode. Refresh
is the identity on plaintext. Its schedule is a function of the tape: when the
result of a `Mul` or `SelectEqZero` would exceed the rank limit, each distinct
operand register with nonzero rank is refreshed in place, in operand order,
before the instruction executes, and the result rank is recomputed. A register
that appears twice is refreshed once, and a destination that aliases an operand
receives the recomputed rank. The schedule is private with the tape and is not
chosen by the evaluator; the execution relation must constrain it inside the
padded shape. Adding an encryption of zero is not a refresh.

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
5. **Padded shapes (R.3, R.11).** The fixed ciphertext, key and proof sizes of
   each class are not derived.
6. **Opening and PRF (R.8).** The public opening material, the PRF, the carrier
   of the derived identifier and any expiry of the opening itself are not chosen.
7. **Query-limit enforcement (R.8, R.11, R.12).** The limit, its scope and its
   counting rule are specified [above](#query-limit). Where State keeps the
   per-identity and per-beneficiary counts and the set of opened receipts, and
   how a threshold committee checks an accepted request before it contributes,
   are decided where they are enforced.
8. **Refresh (R.9, C.8).** The refresh algorithm does not exist. The rank limit
   16 and the count 64 are candidates to be derived again from a noise model.
9. **Threshold opening (R.10).** What the opening-key commitment covers for a
   committee and its epochs is not specified.
10. **Receipt consumers (R.12, R.4).** The time source for expiry, the replay
    set and whether two replay scopes suffice are decided where the receipt is
    consumed.

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
2. Emit an owned, clearing execution trace from the encrypted interpreter and
   compare it with the cleartext reference, which supplies the independent
   vectors for all eleven instructions and the maximum shapes. Trace generation
   alone is not proof completion.
3. Implement the complete fixed-profile relation over the proof engine selected
   under [open question 1](#open-construction-questions), with a dedicated
   relation identity, canonical key owner and typed verifier. Constrain
   encoding/hash preimages, the initial-state derivation and the memory-blinding
   derivation as well as the machine transitions. Do not use unconstrained
   native arithmetic callbacks.
4. Pass real native positive proofs and direct-witness negatives for altered
   secret/policy/program/parameters/keys, input/output/associated data/receipt,
   omitted or repeated transitions, invalid register or memory access, modular
   aliases, wrong relinearization and incorrect `SelectEqZero`. Measure maximum
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
