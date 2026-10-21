//! IVM Syscall Table (ABI v1)

This document lists IVM syscall numbers and their ABI for `abi_version = 1`.
The host and VM enforce the fixed first-release ABI v1 policy: the set of
available syscalls is fixed and unknown or disallowed numbers must be rejected
with `E_SCALL_UNKNOWN` (mapped to `VMError::UnknownSyscall`). The canonical
policy is centralized in `ivm::syscalls::is_syscall_allowed(policy, number)`.

ABI policy
- V1 (1): allows the canonical ABI surface listed here and in `abi_syscall_list()`; unknown numbers
  are rejected uniformly across all hosts. The list is kept sorted/deduplicated and the golden test
  fails if ordering or contents drift.
- `abi_hash` commits to every sorted allowed syscall number, its canonical argument and return
  signatures, its conservative host-access class, every sorted allowed pointer-ABI type ID, and
  the complete ABI-v1 semantic descriptor. That descriptor includes numeric domains, arithmetic
  rules, canonical JSON grammars, fault ordering, the CNTR marker/framing, nominal contract-interface
  and state-type schema identities, every embedded state-type tag/layout/sample frame, admission and
  depth rules, and typed durable-state schema/record identities, enum tags, layouts, traversal rules,
  pointer mappings, caps, operation-specific state paths, and CNTR-bound read/write record validation.
  It also binds the generic-program discriminator, reserved transaction metadata,
  and exact sorted list of syscalls unavailable without an authenticated contract identity.
  Display names and gas prices are not part of this digest.
  `ivm::gas::schedule_hash()` commits to the canonical gas schedule and every staged-metering phase
  name/tag independently.
- Every allowed syscall must have exactly one explicit row in `spec/syscalls.toml`. Documentation
  generation rejects missing, duplicate, or extra rows instead of inventing an ABI signature from
  naming heuristics.
- First release: ABI v1 is the only supported policy. `abi_version != 1` is rejected at admission,
  and runtime upgrades must keep `abi_version = 1` without expanding the syscall or pointer‑ABI
  surface. Tightening the unreleased V1 descriptor changes its hash, not its version; artifacts with
  any older V1 hash fail closed at admission.

Contract error presentation
- `#[message("...")]` creates a sorted `ContractErrorMessage { error_type, code, message }`
  catalog in authenticated `CNTR`. Entries refer to declared nominal variants, contain nonblank
  text, and are bounded to 4096 UTF-8 bytes. Catalog bytes affect artifact and manifest signatures;
  wording does not change error, argument, or durable-state schema hashes.
- `ContractRejection.message` is optional and comes from the originating VM's authenticated
  catalog. Nested calls retain that origin and text through rollback. Runtime abort accounting
  charges copied message bytes in addition to the existing nominal-error fields. A manifest-only
  or caller-supplied label cannot override the originating catalog.

Admission/host guardrails
- Admission enforces manifest `code_hash`/`abi_hash` equality for both inline metadata manifests and
  WSV‑stored manifests before execution, returning `ManifestCodeHashMismatch`/`ManifestAbiHashMismatch`
  deterministically.
- A program without a canonical `CNTR` section is Generic. It retains pure
  compute, numeric, codec, crypto, output, query, and ordinary permission-checked
  ISI syscalls, but admission and host dispatch both reject the ABI-bound
  `GENERIC_PROGRAM_DENIED_SYSCALLS_V1` list with
  `GenericSyscallNotAllowed(syscall)` before side effects. The denied list covers
  instance-permission grants, contract code/lifecycle administration, durable
  state, the opaque contract instruction bridge, nested contract calls, and
  contract-identity sysvars. Generic transaction metadata may not carry the
  reserved contract/deployment keys bound by the descriptor.
- Admission decodes the instruction stream and rejects `SCALL` numbers outside the ABI surface with
  `ValidationFail::NotPermitted` before execution, so mutated or malformed bytecode never reaches the
  host.
- Runtime hosts must return `VMError::UnknownSyscall` for disallowed syscall numbers; the executor
  surfaces the failure during validation so contracts cannot rely on undefined syscalls. Allowed
  syscall numbers that are not meaningful for a specific host return a metered
  `VMError::NotImplemented` instead.
- The ten extended `0x00FE0001..=0x00FE000A` Kotodama test helpers (fixture actors, seiyaku calls
  and rejection expectations, assertion failure reports, block height and transaction time
  control, and helper call-site records) are not ABI-v1 syscalls and do
  not contribute to `abi_hash`. A crate-private test-artifact verifier accepts exactly those IDs
  only in unreachable local test bodies, and the VM dispatches them only when the private
  test-suite loader capability is present and the host opts in; the runner supplies
  `KotoTestHost`. Production artifact admission, public raw/program/prepared loaders, adjacent
  `0x00FE` IDs, and permissive custom hosts all fail with `VMError::UnknownSyscall`.
- Reserved-metering host calls compute a deterministic, side-effect-free upper gas quote before
  dispatch, debit it before effects, and reconcile unused reserve afterward. Numeric V1 calls use
  staged metering instead: each phase is debited immediately before its bounded work, and no staged
  charge is refunded. The schedule hash binds both the per-syscall metering mode and every staged
  phase tag.
- Regression tests cover host-side `UnknownSyscall` rejections, admission-time `SCALL` gating
  (including manifest-backed programs), and manifest `abi_hash` enforcement across both metadata and
  WSV manifests to keep the ABI surface deterministic end-to-end.

`SCALL` carries an 8-bit syscall number in bytecode. `SYSTEM` is the extended `SCALLX` form and carries a 24-bit syscall number for ABI V1 calls outside the `SCALL` range. The host receives all syscall numbers as `u32`, and admission checks both encodings before execution. Structured arguments use the pointer‑ABI: canonical Norito TLVs may reside in INPUT, the allocated HEAP prefix, or at an exact loader-validated literal start. Stack, OUTPUT, unallocated HEAP, and arbitrary code offsets are not valid pointer provenance. Scalar values are passed in `r10+`. Return values are `u64` unless noted; pointer results are returned in `r10` and host-produced TLVs prefer INPUT before spilling to allocated HEAP.

Query syscall (Norito)
- `0xA1` and extended `0x010000` expect `r10=&NoritoBytes(QueryRequest)` and return `r10=&NoritoBytes(QueryResponse)`. The authority is always the calling contract; embedded authorities are ignored.
- Iterable queries run in ephemeral cursor mode inside IVM; `QueryRequest::Continue` is rejected to keep query lifetimes bound to the VM run.
- `query_max_fetch_size` of the committed `pipeline_validity_policy_v1` chain parameter caps iterable query `fetch_size` for IVM query syscalls (0 clamps to 1). Torii endpoints continue to use `torii.app_api.max_fetch_size`.
- Gas is `base + per_item + per_byte`, with per-item cost multiplied when sorting is requested and an offset penalty applied for large pagination skips.

Vendor syscall (Norito)
- `0xA0` expects `r10=&NoritoBytes(InstructionBox)` and the mandatory operation tag `1` (`SubmitBallot`) in `r11`. Tag `0`, every other tag, mismatched instruction types, and other instruction types are rejected with `PermissionDenied`. In particular a contract cannot execute `RecordSccpMessage` under any tag: an outbound SCCP record executes only from signed transactions, directly or through a multisig proposal that signed approvals execute (`specs/sccp.md` §4.4).

Ordering and OUTPUT
- Syscalls execute in program order. Hosts must apply their side effects in the order received.
- `COMMIT_OUTPUT (0xFE)` makes the VM OUTPUT region visible to the host. Programs may write multiple times to OUTPUT, but content becomes observable only after `COMMIT_OUTPUT` runs. If `COMMIT_OUTPUT` is called multiple times, hosts should treat the last call’s contents as final for that run.
- The VM clears OUTPUT (and resets its append-only cursor) when loading a program; within a run, OUTPUT writes must move forward (rewinds trap).
- Event emission that reflects syscall outcomes must preserve syscall order. VM implementations must not reorder syscalls, including under acceleration. Deterministic overlays and commit phases in the node preserve this ordering across the pipeline.
- Host lifecycle: `begin_tx`/`finish_tx` return `Result`; hosts must surface overlay flush errors (e.g., durable state writes) instead of swallowing them, clear staged overlays on failure, and rely on checkpoints to restore pre-tx state when a VM run aborts.
- Deployed-contract overlays retain the selected entrypoint authorization for every queued effect and every physical durable-state path. Apply revalidates the exact caller permission against the signed declaration table, address/code/alias binding, lifecycle revision, nested caller lineage, and path ownership before effects and again immediately before each durable write; stale or structurally incomplete metadata applies no effects. Suspension and resumption invalidate prepared effects even when the artifact and pending hook are unchanged. `IvmProved` admission is closed until complete native execution proofs and authenticated finalized State anchors are available.

Legend
- Args: registers and pointer types; `&Type` indicates a provenance-valid pointer to a canonical Norito TLV.
- Return: `u64` or `ptr` (pointer in `r10`).
- Gas: base component name; variable components are added for byte or item counts.

Gas enforcement (CoreHost)
- Syscall quotes are reserved before host effects. The reserved amount remains visible to host
  budget checks, but nested contract bytecode can spend only the unreserved parent gas. Unused
  reserve is refunded after the host reports the actual deterministic cost. This lifecycle applies
  only to calls whose registry entry is `Reserved`; numeric V1 registry entries are `Staged` and
  debit their hash-bound work phases without reservation or refund.
- `JSON_GET_JSON` quotes heap-backed JSON input against the owned HEAP/INPUT payload bound and
  reserves that same HEAP-capable result bound plus its sum handle, so a valid field beyond the
  fixed INPUT arena cannot be rejected during preparation or exceed its pre-dispatch quote.
- Host-state-dependent durable-state, public-input, and WSV ZK read results reserve
  the available syscall gas, compute and preflight their exact encoded cost, and
  only then allocate the result. This keeps
  valid HEAP-sized responses inside the dispatcher quote without mutating registers on
  insufficient gas.
- ISI syscalls charge extra gas using the native ISI schedule (`iroha_core::gas::meter_instruction`).
- FASTPQ transfer batch scope syscalls charge the fixed gas. Gas: `G_fastpq_batch`; batch
  entries are charged separately with the transfer gas family when applied.
- Contract administration bridge syscalls charge `G_contract_admin + bytes`.
- `CALL_CONTRACT` charges `G_call_contract + request bytes + return bytes` in
  the parent VM; child execution gas is consumed by the child VM.
- Native asset escrow bridge syscalls charge `G_escrow + bytes`.
- Soracloud runtime syscalls charge `G_soracloud + request bytes + response bytes`.
- ZK verification uses the immutable `ZkGasScheduleV1` snapshot selected when
  the host is constructed: `proof_base` per proof, `per_public_input` per
  canonical 32-byte public-input unit, and `per_proof_byte` for encoded request
  and bounded response bytes. The ABI-v1 defaults are `250_000`, `2_000`, and
  `5`. A request may contain at most 1 MiB of encoded payload, and
  `ZK_VERIFY_BATCH` accepts at most 16 proofs. The formula version, caps,
  response layout, and default schedule subhash are part of the hashed gas
  schedule; production rate selection is also bound by the ZK policy hash.
- GET_PUBLIC_INPUT charges a base plus a per-byte cost based on the returned TLV length.
- `JSON_OBJECT` helper — Gas: `G_json + bytes`.
- `JSON_GET_*` helpers and their direct variants return compiler-owned
  `Option<T>` sum handles. Only a missing key is `Option::none`; a non-object
  root or a present field of the wrong JSON type traps with `DecodeError`, and
  malformed TLVs remain VM errors. Gas: `G_json_get + input bytes + active payload + sum allocation`.
- `JSON_BUILD` converts one compiler-emitted `JsonConstructionSchemaV1` and a
  flattened word table into one canonical `Json` payload. Gas is charged by
  schema bytes, source bytes, words, collection elements, and encoded bytes.
- `JSON_SET_I64`, `JSON_SET_ACCOUNT_ID`, and their direct variants — Gas: `G_json + bytes`.
- SMARTCONTRACT_EXECUTE_QUERY charges base + per-item + per-byte; sorting multiplies per-item cost. Pagination offsets add an extra per-item penalty for unsorted queries; for sorted queries, the per-item charge is based on all items scanned before pagination (so offsets are already included). Query materialization aborts with OutOfGas when the per-item budget is exhausted, and responses that exceed the per-byte budget are rejected before encoding when exact Norito sizing is available (otherwise after encoding).

Lifecycle / Utility
- 0x00 DEBUG_PRINT — Args: `r10=value:u64` → Return: 0 — Gas: G_debug
- 0x01 EXIT — Args: `r10=status:u64` → Return: `u64=status` — Gas: G_exit
- 0x02 ABORT — Args: none → Return: `u64=0` — Gas: G_abort (halts and marks the run failed)
- 0x03 DEBUG_LOG — Args: `r10=&Json|&Blob|&NoritoBytes` → Return: 0 — Gas: G_debug. Diagnostics only: hosts print the payload in development and test builds and otherwise discard it, so the call has no ledger or durable-state effect and Kotodama permits `debug::info` in views.
- 0x04 CONTRACT_ABORT — Args: `r10=&NoritoBytes(ContractErrorTypeDescriptor), r11=code:u32, r12..r15=0` → Return: `u64=0` — Gas: G_abort + descriptor bytes + selected message UTF-8 bytes (halts with an exact signed-CNTR-authenticated nominal rejection; descriptor frame at most 64 KiB)
- 0xA8 CURRENT_TIME_MS — Args: none → Return: `u64=deterministic_execution_time_ms` — Gas: G_sysvar
- 0xE0 INPUT_PUBLISH_TLV — Args: `r10=&Blob(TLV)` → Return: `ptr (r10)` — Gas: G_input_publish + bytes (rejects invalid TLV envelopes and disallowed pointer types)
- 0x90 SM3_HASH — Args: `r10=&Blob(message)` → Return: `ptr (&Blob(digest))` — Gas: G_hash + bytes
- 0x91 SM2_VERIFY — Args: `r10=&Blob(msg)`, `r11=&Blob(sig)` (64-byte r∥s), `r12=&Blob(pubkey)` (SEC1), `r13=&Blob(distid)` *(optional, 0 for default)* → Return: `u64=0/1` — Gas: G_verify + bytes
- 0x92 SM4_GCM_SEAL — Args: `r10=&Blob(key16)`, `r11=&Blob(nonce12)`, `r12=&Blob(aad)` *(0 => empty)*, `r13=&Blob(plaintext)` → Return: `ptr (&Blob(ciphertext || tag16))` — Gas: G_sm4 + bytes
- 0x93 SM4_GCM_OPEN — Args: `r10=&Blob(key16)`, `r11=&Blob(nonce12)`, `r12=&Blob(aad)` *(0 => empty)*, `r13=&Blob(ciphertext || tag16)` → Return: `ptr (&Blob(plaintext))` or `0` on failure — Gas: G_sm4 + bytes
- 0x94 SM4_CCM_SEAL — Args: `r10=&Blob(key16)`, `r11=&Blob(nonce[7..13])`, `r12=&Blob(aad)` *(0 => empty)*, `r13=&Blob(plaintext)`, `r14=tag_len:u64` *(0 => 16)* → Return: `ptr (&Blob(ciphertext || tag))` — Gas: G_sm4 + bytes
- 0x95 SM4_CCM_OPEN — Args: `r10=&Blob(key16)`, `r11=&Blob(nonce[7..13])`, `r12=&Blob(aad)` *(0 => empty)*, `r13=&Blob(ciphertext || tag)`, `r14=tag_len:u64` *(0 => 16)* → Return: `ptr (&Blob(plaintext))` or `0` on failure — Gas: G_sm4 + bytes
- 0x96 SHA256_HASH, 0x97 SHA3_HASH, 0x98 BLAKE2B256_HASH, 0x99 KECCAK256_HASH, and 0x9A IROHA_HASH all take `r10=&Blob(message)` and return `r10=ptr (&Blob(digest))`. They use fixed CPU implementations or byte-equivalent acceleration only, so the returned digest is byte-identical across machines. Gas: G_hash + bytes.
- 0xF0 ALLOC — Args: `r10=bytes:u64` → Return: `ptr (r10)` — Gas: G_alloc + bytes
- 0xF1 GET_PUBLIC_INPUT — Args: `r10=&Name` → Return: `ptr (&Tlv)` — Gas: G_get_pub + bytes
  - Reads a public input by name from the on-chain registry `Parameters.custom["ivm_public_inputs"]`.
  - Default root preparation requests `entrypoint_argument_record` as a `NoritoBytes` TLV containing the canonical schema-bound record, with the ordinary opcode and host gas charges. An admitted host may instead supply its original prepared record directly.
  - `trigger_event_json` returns the actual firing context as a `Json` TLV. Installing prepared root arguments retains that independent event context; a prepared record alone does not create an event. There is no argument-record lookup through the event key.
  - Registry entries are JSON objects: `{ "name": "<Name>", "type_id": <u16>, "tlv_hex": "<hex>" }` with optional `gas_base`/`gas_per_byte` (`tlv_hex` is the full TLV envelope; `0x` prefix allowed).
  - Missing names return `PermissionDenied`; malformed name TLVs or ABI-disallowed types raise syscall errors. Invalid registry entries are skipped during host hydration.
- 0xF8 PRIVATE_NUMERIC_VALCOM — Args: `r10=private typed numeric TLV`, `r11=private typed numeric TLV` → Return: `r10=public int TLV containing the complete compressed Pedersen point` — Gas: G_private_numeric_valcom
  - Each complete typed numeric TLV is projected with its nominal kind and ABI
    domains. The resulting 256-bit digest is reduced modulo the BLS12-381
    scalar order by exactly two unconditional constant-time
    conditional-subtract rounds; the path contains no secret-dependent
    division, loop, branch, or `u64` truncation.
  - The independent BLS12-381 G1 blinding generator is the ABI-bound compressed
    point `892a15529e5d0a920b4765f578519d79a193903553c1e6676a3cc9b8c89fc1970cba9e5f648bdfd7440dd7d9efb62e26`.
    Runtime decodes this fixed subgroup point; a release test requires it to
    equal `hash_to_curve("KOTODAMA_PRIVATE_NUMERIC_VALCOM_H_V1", DST, [])`.
- 0xFD GET_PRIVATE_INPUT — Args: `r10=index:u64`, `r11=kind (int=0, decimal=1, quantity=2)` → Return: `r10=opaque private typed numeric TLV` — Gas: G_get_priv
  - Available only to local/prover/test hosts. Ordinary production consensus
    dispatch rejects every seiyaku selector with a reachable
    `GET_PRIVATE_INPUT`, including helper-hidden calls.
  - Consensus `CoreHost` also returns `PermissionDenied` from quote preparation
    and direct execution, independently of selector resolution. It never
    forwards this syscall to the local/prover `DefaultHost` transport.
  - Raw witness bytes must never enter signed transactions, `IvmProved`
    payloads, overlays, public argument records, or deterministic validator
    replay. The gate can be removed only when the proof statement binds the
    seiyaku address and code hash, selector, public arguments, authority and
    chain, state root and exact read/write sets, outputs and events, gas
    schedule and ceiling, and circuit and verifier-key versions.
- 0xFE COMMIT_OUTPUT — Args: none → Return: `u64=0` — Gas: G_commit

For the SM4 calls, the host appends the authentication tag to the ciphertext output; callers supply the same layout when invoking the corresponding `OPEN` syscall. `SM4_GCM_*` always uses a 16-byte tag and 12-byte nonce. `SM4_CCM_*` accepts nonce lengths between 7 and 13 bytes and tag sizes {4,6,8,10,12,14,16}; pass the desired tag length in `r14` (use `0` to select 16). Passing `0` in `r12` denotes an empty AAD. Gas charges a fixed SM4 base plus AAD bytes and plaintext/ciphertext bytes inspected, including validation-failure paths after pointer decoding.

Kotodama intrinsics
- ``crypto::sm3(message: bytes) -> bytes`` mirrors `message` into INPUT with `INPUT_PUBLISH_TLV` and issues `SM3_HASH`, returning a pointer to the digest Blob.
- ``crypto::sm2::verify(message:, signature:, public_key:[, distid:]) -> bool`` mirrors each Blob argument into INPUT, invokes `SM2_VERIFY`, and returns `true` for valid signatures. Omitting `distid` selects the runtime-configured default (``Sm2PublicKey::default_distid()``, sourced from `crypto.sm2_distid_default`); providing it enforces a custom distinguishing identifier.
- ``crypto::verify_signature(message:, signature:, public_key:, scheme:) -> bool`` issues `VERIFY_SIGNATURE`. `scheme` is a compile-time `SignatureScheme::Ed25519`, `SignatureScheme::Secp256k1`, or `SignatureScheme::MlDsa`, which the compiler folds into the scheme code `1`, `2`, or `3`; source code cannot pass any other code.
- ``context::transaction_time_ms() -> int`` issues `CURRENT_TIME_MS` and returns the deterministic logical execution time in milliseconds. `CoreHost` binds transaction contract calls to the signed transaction creation time, which the signer chooses within the node's admission tolerance, and trigger calls to the block-header creation time; test/default hosts use an explicitly configured value and default to `0`. No host reads wall-clock time while servicing the syscall. `SYSVAR_BLOCK_TIME_MS` returns the same value on every host and is not a source builtin.
- ``context::authority() -> AccountId`` issues `GET_AUTHORITY` and returns the immediate caller: the transaction or trigger authority for a top-level call, and the calling seiyaku's subject account for a nested call through `CALL_CONTRACT`.
- ``context::block_height() -> int`` issues `SYSVAR_BLOCK_HEIGHT` and returns the host-provided committed block height. `CoreHost` binds this to the attached transaction context; test/default hosts default to `0`.

Exact numeric helpers
- `0x010100..0x01011A` implement signed checked and explicit modulo-`2^512`
  `int` operations; `0x010120..0x01012F` implement exact `decimal` operations;
  and `0x010140..0x01014F` implement nominal non-negative `quantity`
  operations. The generated table below is the signature source of truth.
- `INT_ISQRT`, `INT_ABS`, `INT_MIN`, `INT_MAX`, `INT_DIV_CEIL`, `INT_GCD`,
  and `INT_MEAN` share full-width primitive algorithms with compiler folding.
  Square root floors and rejects negative inputs with `NegativeSquareRoot=13`;
  absolute value and gcd reject an unrepresentable positive result. Ceiling
  division follows mathematical signed ceiling, while mean truncates a wide
  intermediate sum divided by two toward zero. Each work phase is charged
  before execution; trap/status failure modes follow the other checked calls.
- Numeric operands are schema-bound, uncompressed Norito frames in pointer
  types `Quantity=0x0010`, `Int=0x0011`, and `Decimal=0x0012`. Pointer ID
  `0x0013` is the assigned `AxtAnchoredSpendV1` type and is wrong for numeric
  operands. `0x000C` and `0x0014` are unassigned and rejected as unknown.
- The domain is `-2^511..=2^511-1`; decimal and quantity scale is `0..=28`.
  Exact division distinguishes division by zero, repeating expansion, and a
  terminating result whose minimum scale exceeds 28. Rounded operations name
  exactly one of `toward_zero` (tag 0), `away_from_zero` (tag 1), `floor`
  (tag 2), `ceil` (tag 3), `nearest_even` (tag 4), `nearest_away` (tag 5), or
  `nearest_toward_zero` (tag 6).
- Numeric syscalls use Gas: `G_numeric_staged`
  (`asset:gas/G_numeric_staged@ivm.core/v2`) and quote-free staged gas:
  `384 + input_envelope_bytes + input_hash_frame_bytes + output_envelope_bytes
  + 2 * output_frame_bytes + 4 * logical_limb_work` (formula version 6).
  The entry weight covers dispatch, staged bookkeeping, and at most four
  bounded control-register checks. Each logical base-`2^64` work cell receives
  four units for operand access, arithmetic/carry or quotient trial, result
  access, and deterministic loop control; multiplication and division formulas
  enumerate every cell they perform. `cargo bench -p ivm --bench
  gas_calibration` pins work denominators for 1..=8 input limbs, 10-limb scale
  alignment, 16-limb products, and minimum/maximum authenticated envelope
  snapshot/publication pipelines. Release calibration requires a 25% safety
  margin on every supported baseline tier; failure changes the gas formula
  version/hash rather than selecting hardware-dependent semantics.

Native JSON construction
- 0x01004E `JSON_BUILD` takes
  `r10=&NoritoBytes(JsonConstructionSchemaV1)`, `r11=aligned word table`, and
  `r12=exact word count`, returning `r10=&Json`.
- Native construction uses Gas: `G_json_build`; typed getters use Gas: `G_json_get`.
- Object keys are canonicalized by lexical key order, duplicate keys and
  malformed schemas are rejected, and nested `Option`/`List` handles are read
  with an iterative bounded traversal. Options are exactly `{"some": value}`
  or `{"none": true}`, matching public argument and return JSON. Unit is `null`,
  so `Some(())` remains `{"some": null}`; nested Options retain each active tag.
  Nullable Option encodings are not supported. Every Option contributes one
  collection element to gas, and encoded-byte gas includes the complete tag object.
  Booleans remain JSON primitives; `int`, `decimal`, and
  `quantity` render as canonical base-10 JSON strings, including the complete
  signed 512-bit `int` domain, and bytes are lowercase `0x` hex. No
  floating-point conversion or host JSON integer-width conversion occurs.
- Products, `Result`, and resource handles are not accepted as implicit JSON
  values. Typed getters materialize active payloads only. The exact numeric
  getters are exactly `JSON_GET_INT` at `0x010160`, `JSON_GET_DECIMAL` at
  `0x010161`, and `JSON_GET_QUANTITY` at `0x010162`; all three accept canonical
  JSON strings only. A present field holding a JSON number token, an exponent
  form, an alternate spelling, an overflowing value, or a negative quantity
  traps with `DecodeError` instead of reading as absent. Numbers
  `0x010163..0x010165` are unassigned and return `UnknownSyscall` before
  syscall gas charging, allocation, or state mutation. `JSON_GET_STRING` at
  `0x010166` returns a JSON string's UTF-8 bytes as the Kotodama `string`
  pointer, and `JSON_GET_BOOL` at `0x010167` returns a JSON boolean as one
  `0`/`1` payload word.
- Every typed getter returns `Option::none` only when the key is absent from
  the JSON object. A non-object root, or a present field whose JSON value is
  not the getter's exact canonical type, traps with `DecodeError`, so
  malformed input never reads as a missing field. Generic `JSON_SET_I64`
  remains unchanged: it emits a JSON number token and is outside this exact
  numeric surface.

Domains / Peers
- 0x10 REGISTER_DOMAIN — Args: `r10=&DomainId` → 0 — Gas: G_reg_domain
- 0x11 UNREGISTER_DOMAIN — Args: `r10=&DomainId` → 0 — Gas: G_unreg_domain
- 0x12 TRANSFER_DOMAIN — Args: `r10=&DomainId, r11=&AccountId(to)` → 0 — Gas: G_transfer_domain
- 0x15 REGISTER_PEER — Args: `r10=&Json` (RegisterPeerWithPop) → 0 — Gas: G_reg_peer
  - JSON object: `{ "peer": "<public_key or public_key@addr>", "pop": [..], "activation_at": <u64?>, "expiry_at": <u64?> }`
  - `peer` may be a string or an object with `public_key`/`publicKey`/`peer_id`/`peerId`/`key`; those keys are also accepted at top level.
- 0x16 UNREGISTER_PEER — Args: `r10=&Json` (peer id string or object with `peer`/`peer_id`/`peerId`/`public_key`/`publicKey`/`key`) → 0 — Gas: G_unreg_peer

Accounts
- 0x13 REGISTER_ACCOUNT — Args: `r10=&AccountId` → 0 — Gas: G_reg_acct
- 0x14 UNREGISTER_ACCOUNT — Args: `r10=&AccountId` → 0 — Gas: G_unreg_acct
- 0x17 ADD_SIGNATORY — Args: `r10=&AccountId, r11=&Json` (pubkey string or object with `public_key`/`publicKey`/`key`) → 0 — Gas: G_add_sig
- 0x18 REMOVE_SIGNATORY — Args: `r10=&AccountId, r11=&Json` (pubkey string or object with `public_key`/`publicKey`/`key`) → 0 — Gas: G_rm_sig
- 0x19 SET_ACCOUNT_QUORUM — Args: `r10=&AccountId, r11=quorum:u64` → 0 — Gas: G_set_quorum
- 0x1A SET_ACCOUNT_DETAIL — Args: `r10=&AccountId, r11=&Name, r12=&Json` → 0 — Gas: G_set_detail + bytes(val)

Notes:
- Signatory/quorum syscalls update the multisig spec stored in account metadata key `multisig/spec`.
  The target account is selected by canonical `AccountId`; signatory accounts must exist and the
  resulting spec must remain acyclic with quorum reachable.
- These syscalls update multisig roles and metadata and rekey the account controller to the
  canonical multisig id derived from the spec (signatories must be single-key accounts).

Assets (FT)
- 0x20 REGISTER_ASSET — Args: `r10=&AssetDefinitionId, r11=&Blob(UTF-8 display name), r12=numeric_spec:u64, r13=mintability:u64` → 0 — Gas: G_reg_asset
  - `r12` is `0` for `NumericSpec::unconstrained()` and `scale + 1` for a scale in `0..=28`.
  - `r13` carries the `Mintable` tag in its low two bits (`0` infinitely, `1` once, `2` not, `3` limited) and, for limited, the non-zero `u32` token budget in bits 2 and above; the other tags carry no payload. Kotodama writes these as `Mintable::Infinitely`, `Mintable::Once`, `Mintable::Not`, and `Mintable::Limited(tokens)`, and the numeric spec as `NumericSpec::unconstrained()`, `NumericSpec::integer()`, or `NumericSpec::fractional(scale)`.
  - Both words use `iroha_data_model::asset::definition::ivm_registration`, which the compiler and every host share. A malformed word, display name, or definition id traps with `DecodeError`; the registered definition is exactly the named one, with the global balance policy.
- 0x21 UNREGISTER_ASSET — Args: `r10=&AssetDefinitionId` → 0 — Gas: G_unreg_asset
- 0x22 MINT_ASSET — Args: `r10=&AccountId, r11=&AssetDefinitionId, r12=&Quantity` → 0 — Gas: G_mint
- 0x23 BURN_ASSET — Args: `r10=&AccountId, r11=&AssetDefinitionId, r12=&Quantity` → 0 — Gas: G_burn
- 0x24 TRANSFER_V1 — Args: `r10=&AccountId(from), r11=&AccountId(to), r12=&AssetDefinitionId, r13=&Quantity` → 0 — Gas: G_transfer. Batch-internal only; rejected outside an active FASTPQ batch.

NFTs
- 0x25 NFT_MINT_ASSET — Args: `r10=&NftId, r11=&AccountId(owner)` → 0 — Gas: G_nft_mint_asset
- 0x26 NFT_TRANSFER_ASSET — Args: `r10=&AccountId(from), r11=&NftId, r12=&AccountId(to)` → 0 — Gas: G_nft_transfer_asset
- 0x27 NFT_SET_METADATA — Args: `r10=&NftId, r11=&Name, r12=&Json` → 0 — Gas: G_nft_set_metadata
- 0x28 NFT_BURN_ASSET — Args: `r10=&NftId` → 0 — Gas: G_nft_burn_asset
- 0x2C TRANSFER_ASSET_SCOPED — Args: `r10=&AccountId(from), r11=&AccountId(to), r12=&AssetDefinitionId, r13=&Quantity, r14=&DataSpaceId or 0` → 0 — Gas: G_transfer. Queues a transfer using the asset definition's balance-scope policy: global definitions use a global source balance and ignore `r14`; dataspace-restricted definitions use `Dataspace(r14)`. `r14 = 0` (Kotodama omits `dataspace:`) on a restricted definition traps with `NoritoInvalid`, as any missing `DataSpaceId` pointer does; no host falls back to an ambient or universal dataspace.

Zero‑knowledge (verification/state‑read)
- 0x60 ZK_VOTE_VERIFY_BALLOT — Args: `r10=&NoritoBytes(iroha_data_model::zk::OpenVerifyEnvelope)` → `u64=0/1` — Gas: G_verify_proof + bytes
- 0x61 ZK_VOTE_VERIFY_TALLY — Args: `r10=&NoritoBytes(iroha_data_model::zk::OpenVerifyEnvelope)` → `u64=0/1` — Gas: G_verify_proof + bytes
- 0x62 ZK_ROOTS_GET — Args: `r10=&NoritoBytes(RootsGetRequest)` → `ptr (NoritoBytes(RootsGetResponse))` — Gas: G_roots_get + bytes
- 0x63 ZK_VOTE_GET_TALLY — Args: `r10=&NoritoBytes(VoteGetTallyRequest)` → `ptr (NoritoBytes(VoteGetTallyResponse))` — Gas: G_vote_get + bytes

`VoteGetTallyResponse.tally` contains one exact `u128` weight per option in the
canonical V1 Norito payload. The response does not narrow conviction weights to
`u64`; the standalone private-election proof relation remains closed pending
qualification.

ZK gating & determinism
- `CoreHost` performs full proof verification through the configured backend verifier (`iroha_core_zk::verify_backend_with_timing`), not the legacy polynomial-opening helper.
- `DefaultHost` has no verifier-key registry or cryptographic backend. It
  canonical-validates `iroha_data_model::zk::OpenVerifyEnvelope`, enforces
  configured size/batch gates, and then fails closed with `ERR_BACKEND`.
  Batch responses contain one zero byte per item (`1 = verified`, `0 = not
  verified`), set `r11=ERR_BACKEND`, and set `r12=0` for the first failed item.
- `CoreHost` additionally binds each envelope to the on-chain VK registry
  before verification; batch items then run through
  `iroha_core_zk::verify_backend_with_timing_guardrails`.
- Verification is bound to the VK registry before cryptographic checks:
  - envelope/backend must be supported (`backend = halo2-ipa-pasta`), `vk_hash` must be present, and payload/proof sizes must respect config caps.
  - the referenced verifying key must be active and match circuit id, schema hash (`hash(public_inputs)`), namespace, and owner manifest.
  - configured curve/max_k policy is enforced from VK metadata / VK envelope parameters.
- Return conventions:
  - `r10=1`, `r11=0` on success.
  - `r10=0`, `r11=<ERR_*>` on precheck/binding failure (`ERR_DISABLED`, `ERR_BACKEND`, `ERR_CURVE`, `ERR_K`, `ERR_DECODE`, `ERR_VERIFY`, `ERR_ENVELOPE_SIZE`, `ERR_PROOF_LEN`, `ERR_VK_MISSING`, `ERR_VK_MISMATCH`, `ERR_VK_INACTIVE`, `ERR_NAMESPACE`).
- `ERR_DISABLED` is returned only when the configured verifier is disabled.

Roles / Permissions
- 0x30 CREATE_ROLE — Args: `r10=&Name, r11=&Json` (perm set) → 0 — Gas: G_create_role
  - Permissions JSON: array of permission strings/objects or `{ "permissions": [...] }` / `{ "perms": [...] }`.
- 0x31 DELETE_ROLE — Args: `r10=&Name` → 0 — Gas: G_delete_role
- 0x32 GRANT_ROLE — Args: `r10=&AccountId, r11=&Name` → 0 — Gas: G_grant_role
- 0x33 REVOKE_ROLE — Args: `r10=&AccountId, r11=&Name` → 0 — Gas: G_revoke_role
- 0x34 GRANT_PERMISSION — Args: `r10=&AccountId, r11=&Name|&Json(Permission)` → 0 — Gas: G_grant_perm
- 0x35 REVOKE_PERMISSION — Args: `r10=&AccountId, r11=&Name|&Json(Permission)` → 0 — Gas: G_revoke_perm

Triggers
- 0x40 CREATE_TRIGGER — Args: `r10=&Json` (trigger spec) → 0 — Gas: G_create_trig
  - Spec payloads:
    - JSON string: base64 Norito-encoded `Trigger` (canonical).
    - JSON object: `{ "id": "<trigger_id>", "action": <ActionSpec> }` where `action` is either a
      base64 Norito `Action` string or a JSON object with `executable`, `repeats`, `authority`,
      `filter`, and `metadata` fields (matching `SpecializedAction<EventFilterBox>`).
    - `EventFilterBox::TriggerCompleted` filters are rejected for triggering actions.
- 0x41 REMOVE_TRIGGER — Args: `r10=&Name` → 0 — Gas: G_remove_trig
- 0x42 SET_TRIGGER_ENABLED — Args: `r10=&Name, r11=enabled:u64` (`0` or `1`; Kotodama passes a `bool`) → 0 — Gas: G_set_trig
  - Writes trigger metadata key `__enabled` to `true`/`false`; missing key defaults to enabled.
- 0x43 DEACTIVATE_CONTRACT_INSTANCE — Args: `r10=&NoritoBytes(DeactivateContractInstance)` → 0 — Gas: G_contract_admin + bytes
- 0x44 REMOVE_SMART_CONTRACT_BYTES — Args: `r10=&NoritoBytes(RemoveSmartContractBytes)` → 0 — Gas: G_contract_admin + bytes
- 0x45 REGISTER_SMART_CONTRACT_CODE — Args: `r10=&NoritoBytes(RegisterSmartContractCode)` → 0 — Gas: G_contract_admin + bytes
- 0x46 REGISTER_SMART_CONTRACT_BYTES — Args: `r10=&NoritoBytes(RegisterSmartContractBytes)` → 0 — Gas: G_contract_admin + bytes
- 0x47 ACTIVATE_CONTRACT_INSTANCE — Args: `r10=&NoritoBytes(ActivateContractInstance)` → 0 — Gas: G_contract_admin + bytes

Lifecycle operations expect canonical Norito encodings of the corresponding ISI structs. Hosts
trim empty `reason` strings for `DeactivateContractInstance`/`RemoveSmartContractBytes` and
enforce governance permissions before queuing the instruction.

Durable state
- 0x50 STATE_GET — Args: `r10=&NoritoBytes(StatePath)` → `ptr (&NoritoBytes)` or `0` — Gas: G_state_get + bytes
- 0x51 STATE_SET — Args: `r10=&NoritoBytes(StatePath), r11=&NoritoBytes(value)` → 0 — Gas: G_state_set + bytes
- 0x52 STATE_DEL — Args: `r10=&NoritoBytes(StatePath)` → 0 — Gas: G_state_del
- State paths are a distinct nominal storage-path type transported inside
  `NoritoBytes`; a `Name` TLV is not an alternate path carrier.
- Deployed-contract execution scopes every path to `sc/<contract-address-hash>/`.
  Scoped operations never read, enumerate, overwrite, or delete unscoped keys.
  Generic programs have no authenticated contract namespace, so every durable
  state syscall is rejected during admission and again before host dispatch.
- State gas is deterministic and byte-counted: present reads and writes charge
  the fixed base plus the encoded path and `NoritoBytes` value payload lengths.
  Misses and tombstones charge the base plus the encoded path length. Key
  enumeration adds the returned-key count plus encoded result bytes. `STATE_GET` preparation reserves the caller's remaining gas after checking
  the path-only minimum. The host checks the exact path-plus-value cost before
  copying a value, recording the read, or publishing a response; unused gas is
  refunded. A small value or a miss does not require gas for a maximum-size value.
  The 512 KiB value limit remains mandatory.
- The development/test `DurableStateOverlay` is not the ledger state backend.
  Its restart file is a direct regular Norito JSON file capped at 30 MiB and is
  admitted before parse. The retained overlay is capped at 4,096 entries,
  4 MiB of canonical path text, and 16 MiB of raw values. Set, restore, load,
  checkpoint, and flush all share those bounds; persistence writes one encoded
  output buffer to an exclusive sibling (mode 0600 on Unix) and atomically
  replaces a direct single-link regular destination. Stable links, hard links,
  and special files are rejected without opening their targets. The configured
  ancestor directories remain an operator-owned trust boundary.

Smart‑contract helpers (Norito)
- `GRANT_CONTRACT_PERMISSION` (`0x36`) and `REVOKE_CONTRACT_PERMISSION`
  (`0x37`) take `r10=&AccountId` and `r11=&Name` for an Instance permission
  declared by the current contract. The queued native operation requires its
  executing subject to be the current account owner or an exact holder of
  `CanUseContractPermission { contract, permission }`; calling the helper does
  not grant the subject delegation authority. The general code-management
  permission supplies no scoped delegation authority. Native grant and revoke
  operations may use the retained artifact's declarations during suspension,
  but invocation still requires an active instance. Lifecycle hook grants use
  the separate exact address-and-hook token.
- 0xA0 EXECUTE_INSTRUCTION — Args: `r10=&NoritoBytes(InstructionBox)`, `r11=operation_tag` (`1=SubmitBallot`) → 0 — Gas: G_sci
- 0xA5 SUBSCRIPTION_BILL — Args: none → 0 — Gas: G_sub_bill
  - Uses trigger metadata `subscription_ref` to locate the subscription NFT, computes charges, updates subscription metadata (including `subscription_invoice`), and reschedules the billing trigger.
- 0xA6 SUBSCRIPTION_RECORD_USAGE — Args: none → 0 — Gas: G_sub_usage
  - Parses `SubscriptionUsageDelta` from trigger args, increments usage counters, and updates subscription metadata.
- 0xA9 CALL_CONTRACT — Args: `r10=&Blob(contract_address), r11=&NoritoBytes(ContractCallBindingV1), r12=argument-table-base, r13=exact-argument-words, r14=result-table-base, r15=exact-result-words` → `caller-owned typed result table; Unit uses one zero word` — Gas: G_call_contract + request bytes + return bytes + child gas
- 0xAA EMIT_CONTRACT_EVENT — Captures a typed event payload against the executing artifact's signed event declaration. The host supplies the instance, code hash, entrypoint, caller and exact declaration; callers cannot substitute provenance. Emissions retain execution order across nested calls and are published only in a successful committed execution result. A reverted invocation discards its emissions and those of its descendants while preserving gas charges. Views and generic programs cannot emit. Gas is quoted before capture from the canonical schema, active value traversal and complete retained TLV envelopes. Deterministic output limits reject the invocation; a local allocation refusal defers it.


  The callee shares the current invocation's durable-state overlay and sees the
  calling seiyaku's subject as its immediate authority. Queued ledger instructions
  are applied after root execution succeeds; they do not modify the ledger query
  snapshot during nested execution. Any active-address re-entry, including a
  view or indirect callback, is rejected before callee execution; nesting is
  bounded to 32 calls. A canonical outer `Result::err` returns its error record
  while rolling back the callee and its successful descendants. Read dependencies
  and consumed gas survive this recoverable rollback. Results embedded in other
  returned values remain data. VM faults and nominal aborts roll back the frame
  and propagate to the caller. Direct deployed calls and local execution apply
  the same outer-Result rule.
  A deterministic runtime failure carries `IvmFaultV1`: its closed fault kind,
  exact code hash, authenticated CNTR entrypoint ordinal (or generic-program
  selector), and initialization, execution, or return-validation position.
  Execution positions are byte offsets relative to the executable stream.
  Nested unwinding preserves the deepest originating fault; the parent's CALL
  instruction cannot replace it. Source paths and message strings are local
  presentation derived only from a matching artifact. Node-local allocation or
  execution deferrals and host invariants never become consensus faults.
  The ABI descriptor binds this fault layout and propagation policy.
  - Executes the callee in a child VM. The parent escrows the available syscall gas and is charged the fixed request/return overhead plus all gas consumed by child instructions and child syscalls; unused escrow is refunded.
  - Every public callee has an explicit authorization policy and an authenticated permission declaration table. For a `kotoage fn` or `view fn`, `authorize(anyone)` opens invocation and `authorize(Role)` resolves the declared role. An instance role requires an exact address-and-name grant on the calling contract subject. An explicitly imported chain role requires that exact chain token with canonical JSON `null` payload; a typed built-in permission payload cannot satisfy it. Lifecycle hooks require the separate runtime address-and-hook token. Missing permission rejects the syscall with `PermissionDenied`. Invocation authority never supplies the separate permissions needed for ledger effects.

Extended query/sysvar surface (`SYSTEM` / SCALLX)
- 0x010000 QUERY_EXECUTE_NORITO — Args: `r10=&NoritoBytes(QueryRequest)` → `ptr (&NoritoBytes(QueryResponse))` — Gas: G_scq
- 0x010001 CORE_QUERY_GET — Args: `r10=CoreQueryEntityTagV1`, `r11=&typed entity id` → `r10=Option<View>` sum handle. The active projection is flattened in declaration order and contains exact typed leaf TLVs.
- 0x010002 CORE_QUERY_PAGE — Args: `r10=CoreQueryEntityTagV1`, `r11=offset:i64 bits`, `r12=limit:1..=64` → `r10=List<View,64>` handle, `r11=Option<int>` sum handle. Pages preserve canonical ID order and expose a next offset only after a one-item lookahead proves another page exists.
- 0x010006..0x010008 retain the canonical-Norito specialist reads for named parameters, contract manifests, and contract instances. Parameter keys are `&Name`, manifest keys are `&NoritoBytes(ContractArtifactId)`, and instance keys are either `&NoritoBytes(ContractAddress)` or `&Name(alias)`; untyped `NoritoBytes(Name)` carriers are rejected. Core and specialist reads use deterministic item/byte gas schedules.
- `QUERY_GET_PARAMETER` accepts canonical system parameter names such as `block.max_transactions`, `transaction.max_instructions`, `smart_contract.fuel`, `smart_contract.max_output_items`, `smart_contract.max_output_bytes`, and exact custom parameter names.
- 0x010020 SYSVAR_CHAIN_ID — Args: none → `ptr (&Blob(chain_id))` or `0` — Gas: G_sysvar + bytes
- 0x010021 SYSVAR_BLOCK_HEIGHT — Args: none → `u64=height` — Gas: G_sysvar
- 0x010022 SYSVAR_BLOCK_TIME_MS — Args: none → `u64=block_time_ms` — Gas: G_sysvar
- 0x010023 SYSVAR_AUTHORITY — Args: none → `ptr (&AccountId)` — Gas: G_get_auth + bytes
- 0x010024 SYSVAR_CONTRACT_ADDRESS — Args: none → `ptr (&Blob(canonical address UTF-8 literal))` or `0` outside contract scope. The literal has exactly 60 bytes and is accepted by imported seiyaku `at(address:)`. Gas: G_sysvar + bytes.
- 0x010025 SYSVAR_ENTRYPOINT — Args: none → `ptr (&Blob(entrypoint))` or `0` — Gas: G_sysvar + bytes
- 0x010026 DECODE_ARGUMENT_RECORD — Args: `r10=&NoritoBytes(EntrypointArgumentRecordV1)`, `r11=&NoritoBytes(EntrypointArgumentSchemaV1)` → `r10=aligned owned-HEAP table base (0 if empty)`, `r11=exact word count` — Gas: G_argument_decode + record + schema + complete materialization. Raw syscall quoting uses only bounded record/schema envelope lengths and reserves the full HEAP before schema and record authentication. The decoder validates the schema hash, canonical flat atoms, inactive sum payloads, and every embedded typed pointer. It preflights all aligned pointer TLV allocations and raw aggregate/table storage together. Pointer TLVs prefer INPUT and spill into owned HEAP; aggregate storage and argument tables always use owned HEAP. The record limit is inclusive at 1 MiB. Public invocation preparation is mandatory before guest execution and consumes a host-owned prepared record directly; it does not expose a guest binding or invoke this syscall. JSON-to-record conversion occurs only at Torii/CLI tooling boundaries, through the shared state-free `ivm_abi::arguments` codec.
- 0x010027 SYSVAR_CONTRACT_SUBJECT — Args: none → `ptr (&AccountId(contract subject))` — Gas: G_sysvar + bytes. Calls outside a deployed-contract scope fail closed.
- 0x010028 NORMALIZE_NORITO_BYTES — Args: `r10=&Blob or &NoritoBytes` in validated public memory → `ptr (&NoritoBytes(same payload))` — Gas: G_pointer + bytes
  - Compiler transport helper for strict Norito-consuming syscalls. It rejects null, malformed, disallowed, and non-bytes pointers, then allocates a fresh canonical V1 `NoritoBytes` envelope with an identical payload and recomputed hash. It performs no serialization and does not weaken the receiving syscall's exact pointer-type checks.
- 0x010200 SET_ASSET_TRANSFER_AVAILABILITY — Args: `r10=&AccountId, r11=&AssetDefinitionId, r12=expected_revision:u64, r13=availability_flags:u64 (bit 0 incoming, bit 1 outgoing; reserved bits zero), r14=&Option<String>` → 0 — Gas: G_sci + bytes
- 0x010201 SET_ASSET_TRANSFER_DAILY_LIMIT — Args: `r10=&AccountId, r11=&AssetDefinitionId, r12=&Option<Quantity>` → 0 — Gas: G_sci + bytes
- 0x010202 SET_ASSET_HOLDING_LIMIT — Args: `r10=&AccountId, r11=&AssetDefinitionId, r12=&Option<Quantity>` → 0 — Gas: G_sci + bytes
- 0x010210 ACCOUNT_RECOVERY_PROPOSE — Args: `r10=&Blob(alias), r11=&AccountId(replacement), r12=request_generation` → 0 — Gas: G_sci + bytes
- 0x010211 ACCOUNT_RECOVERY_APPROVE — Args: `r10=&Blob(alias), r11=request_generation` → 0 — Gas: G_sci + bytes
- 0x010212 ACCOUNT_RECOVERY_CANCEL — Args: `r10=&Blob(alias), r11=request_generation` → 0 — Gas: G_sci + bytes
- 0x010213 ACCOUNT_RECOVERY_FINALIZE — Args: `r10=&Blob(alias), r11=request_generation` → 0 — Gas: G_sci + bytes
  - Every mutation binds a nonzero alias-specific request generation. PROPOSE requires the next generation after retained terminal history; APPROVE, CANCEL, and FINALIZE require the exact pending generation. Policy replacement or clearing does not reset the sequence. A signature for an earlier request cannot authorize a later request for the same alias.
- 0x010031 STATE_HAS — Args: `r10=&NoritoBytes(StatePath)` → `r10=present` — Gas: G_state_has
  - Tests durable-state key presence with the same scoped overlay, base-state, and tombstone resolution as `STATE_GET`.
- 0x010032 STATE_LEN — Args: `r10=&NoritoBytes(StatePath)` → `r10=len`, `r11=found` — Gas: G_state_len + bytes
  - Returns the `NoritoBytes` payload length for present values, excluding the TLV envelope. Missing values return `len=0, found=0`.
- 0x010033 STATE_COUNT — Args: `r10=&NoritoBytes(StatePath prefix)` → `r10=total` — Gas: G_state_count + count
  - Counts durable-state keys through canonical sorted prefix matching, contract scope stripping, and current overlay/tombstone resolution, without cloning or returning the key list. This explicit total-count operation is independent of bounded map pagination. The ledger host charges for every ordered-range candidate examined, including candidates rejected by path-segment matching and overlay tombstones.
- 0x010034 STATE_MAP_KEY_AT — Args: `r10=&NoritoBytes(Vec<StatePath>), r11=&Name(base), r12=index` → `ptr (&NoritoBytes(canonical key))` or `0` — Gas: G_path + bytes
  - Compiler-internal decoder for bounded `StateMap` iteration. It accepts at most 64 paths in a 1 MiB page, requires an exact `base/<lowercase hex>` child, binds the recovered key to the base's CNTR-declared nominal key type, and rejects missing schemas, type confusion, malformed, non-canonical, or over-4-KiB keys.
- 0x010035 STATE_VALUE_ENCODE — Args: `r10=&NoritoBytes(StateValueSchemaV1), r11=&[u64], r12=word_count` → `ptr (&NoritoBytes(StateValueRecordV1))` — Gas: G_state_value + schema + words + pointers + output
  - Compiler-internal encoder for one canonical typed durable value. The schema is validated, active pointer leaves must carry canonical payloads of their declared ABI types, inactive `Option`/`Result` branches must be all-zero/null, and the stored record is bound to the exact schema by a domain-separated hash. A source-level `bytes` leaf may arrive transiently as `Blob` or `NoritoBytes`; the encoder copies its payload into the single canonical persisted `Blob` envelope. Stored records using `NoritoBytes` for that leaf remain invalid.
- 0x010036 STATE_VALUE_DECODE — Args: `r10=&NoritoBytes(StateValueSchemaV1), r11=&NoritoBytes(StateValueRecordV1)` → `ptr (&Blob(pad:u8 then [u64; word_count]))` — Gas: G_state_value + schema + record + pointers + output
  - Compiler-internal decoder for scalars, structs, tuples, `Option`, and `Result`. Missing map entries are handled by the caller's outer `Option`; a zero record pointer, non-canonical inactive branch, malformed typed leaf, or different schema hash is rejected.
- 0x010037 STATE_PATH_FROM_NAME — Args: `r10=&Name` → `ptr (&NoritoBytes(StatePath))` — Gas: G_path + bytes
  - Compiler-internal conversion for durable-state helper parameters. It does
    not make `Name` a valid carrier for any state operation.
- 0x010038 STATE_SCAN — Args: `r10=&NoritoBytes(StatePath map), r11=&NoritoBytes(StateCursorV1)` or `0`, `r12=limit` (`1..=64`), `r13..r15=0` → `r10=&NoritoBytes(Vec<StatePath>), r11=&NoritoBytes(StateCursorV1)` or `0`, `r12=selected`, `r13=examined` — Gas: G_state_query + canonical map and cursor input frame bytes + canonical map schema bytes + instance UTF-8 bytes + 1 per examined candidate + examined physical key UTF-8 bytes + canonical response frame bytes
  - Seeks after the cursor's last examined key in the current ordered map and overlay. Each call returns at most `limit` live keys and examines at most 64 candidate positions, including tombstones. It performs no lookahead or total count, so a continuation can lead to a terminal empty page. The host binds the canonical cursor frame to its authoritative contract instance, the declared map, its exact key/value schema hash, and its scalar key type before examining state.

Canonical instruction bridge
- `EXECUTE_INSTRUCTION` accepts only a pointer-ABI `NoritoBytes` payload containing the canonical
  Norito frame of one data-model `InstructionBox`. Register `r11` must contain the matching
  operation tag `1`, and the instruction must be `SubmitBallot`.
- JSON pointers, raw JSON envelopes, direct concrete-instruction frames, alternate-layout Norito
  frames, tag `0`, unknown tags, mismatched instruction types, and all other instruction types are
  rejected. There is no compatibility decoding path.
- 0xA1 EXECUTE_QUERY — Args: `r10=&NoritoBytes(QueryRequest)` → `ptr` — Gas: G_scq
- 0xA2 CREATE_NFTS_FOR_ALL_USERS — Args: none → `u64=count` — Gas: G_create_nfts_all
- 0xA3 SET_SMARTCONTRACT_EXECUTION_DEPTH — Args: `r10=depth:u64` → `u64=prev` — Gas: G_sc_depth
- 0xA4 GET_AUTHORITY — Args: none → host-owned `ptr (&AccountId)` — Gas: G_get_auth. The immediate caller: the transaction or trigger authority at top level, the calling seiyaku's subject account in a nested seiyaku call.
- 0xA7 RESOLVE_ACCOUNT_ALIAS — Args: `r10=&Blob(alias literal)` → host-owned `ptr (&AccountId)` — Gas: G_alias_resolve

AXT host flow
- 0xB0 AXT_BEGIN — Args: `r10=&AxtDescriptor`. Resets any in-progress envelope and records its canonical binding. Gas: G_axt + bytes.
- 0xB1 AXT_TOUCH — Args: `r10=&DataSpaceId`, `r11=&NoritoBytes(TouchManifest)` or `0`. Declares the manifest of keys touched for the dataspace within the current envelope. Gas: G_axt + bytes.
- 0xB2 AXT_COMMIT — Args: none. Validates the declared dataspaces, touches, and proofs for the active public envelope and clears host state on success. Remote spends are not accumulated through this syscall. Gas: G_axt + entries.
- 0xB3 VERIFY_DS_PROOF — Args: `r10=&DataSpaceId`, `r11=&ProofBlob` (or `0` to clear). A zero proof pointer clears the recorded proof and cache entry. Iroha's production CoreHost rejects every non-zero standalone proof with `PermissionDenied` and an `AxtRejectReason::Proof` context until the proof is bound to an authoritative finalized source-state anchor; rejection does not record the proof or alter an existing verified-proof cache entry. Gas: G_verify + bytes.
- 0xB5 AXT_STAGE_ANCHORED_SPEND — Args: `r10=&AxtAnchoredSpendV1`. CoreHost accepts only a canonical typed TLV whose public signed-spend fields and active descriptor binding are internally consistent, then stages that exact wire in the active envelope. Staging does not authenticate issuer authority, finality, source execution, transfer occurrence, or replay state. State admission rejects every nonempty spend before effects until those owners are connected. Standalone hosts reject the call. Gas: G_axt + bytes.

The final V1 remote-spend wire is `AxtAnchoredSpendV1` inside
`AxtEnvelopeRecord.spends`. Core block and State admission also refuse every
nonempty spend before mutation until a complete State-owned source anchor,
successful execution receipt, exact transfer occurrence, and atomic
nonce/budget/effect owner are connected. Syscall `0xB4` is unassigned in ABI
V1; it returns `UnknownSyscall` before reading caller memory or charging gas.
There is no reusable-handle remote-spend syscall in the release ABI. The B5
typed producer stages a public signed-spend claim; authenticated State
admission remains open.

The completed anchored-spend admission relation must check handle eras and
sub-nonces against a permanent consensus-persisted per-dataspace authorization
generation and counter. Zero is the inactive sentinel and an active generation
is at least one. Policy-identity transitions atomically advance
both dimensions, with the generation also bounded below by the new manifest's
derived activation era, and neither dimension resets on rotation, reassignment,
removal, or restart. The retained World budget and replay tables are not
currently consumed by remote-spend admission because that path remains closed.

AXT FastPQ proofs authenticate the exact manifest root, optional DA commitment,
optional committed amount, and optional expiry in metadata inserted before the
batch seal. `ProofBlob.expiry_slot` and the envelope fields are outer mirrors;
hosts reject any mismatch, including `None`/`Some` relabelling. The complete
canonical metadata map is committed as eight raw Blake2b-256 `u32` trace limbs.
This is a first-release hard cut: proofs produced without the required metadata
or with the retired single-field metadata projection must be regenerated.
`AssetHandle` and `RemoteSpendIntent.op` both carry the exact
`AssetDefinitionId`; the handle field is part of the mandatory issuer-signature
payload, and V1 accepts only the canonical `transfer` operation. Every handle
use in the completed admission path must consume one proof-bound claim containing that handle's replay
identity—including its exact asset-definition incarnation—asset, canonical
accounts, and effective amount, matched one-for-one to a concrete FASTPQ
transfer transcript. This is a proof-binding requirement, not a currently
accepted host call. A historical claim cannot authorize a handle for a later
registration of the same asset identifier. The `authorization` and
`compliance` labels select an
opaque-effect profile and do not themselves prove authority; such proofs cannot
authorize a remote spend. A reusable handle and intent do not become an
`AxtAnchoredSpendV1` through a VM syscall, and block admission rejects a
nonempty signed-spend set independently of these earlier checks.

`VERIFY_DS_PROOF` is not a standalone authorization primitive. FASTPQ's current
one-field commitment has only a roughly 32-bit collision-binding ceiling, and
the verifier reconstructs the complete caller-carried witness rather than
authenticating a finalized remote state. Production CoreHost admission therefore
fails closed for a non-zero standalone proof. Proofs may still enter the
signed `AxtAnchoredSpendV1` shape only after issuer authorization binds the
intent, proof, amount, receipt, occurrence, anchor and nonce. That signed
shape is still only a claim until State authenticates the finalized source
execution and exact transfer. Native lane
relay and fee-vault admissions use separate finalized/current-state anchors and
do not derive authority from standalone `VERIFY_DS_PROOF` success.

Contract-controlled asset locks

`ledger::asset_lock::{open,drawdown,cancel,expire}` use dedicated syscalls
`0x010220`–`0x010223`. They require an authenticated contract frame. The host
derives the native lock ID from the exact controller address and an application
key of 1–4096 bytes; the guest cannot supply a different controller. Opening
retains the exact key in its typed instruction so native admission can verify
the derivation independently. IDs reserve the `ICL1` prefix plus 224 digest bits;
generic escrow creation must reject this range, and another controller cannot
choose an ID derived for the original controller. The source
account remains the native escrow seller and beneficial owner. The executor
requires the controller's source-asset debit permission and prevents ordinary
lock instructions from bypassing the controlled path.

Opening takes a fixed public heap table containing key, source, beneficiary,
asset definition, quantity, inclusive claim deadline, inclusive earliest
cancellation time, and native expiry. Zero times mean absent. An application
whose refunds require strictly later time passes `business_expiry + 1`, checked
for overflow, as native expiry. Claim and cancellation windows are independent.
Opening returns the exact native protocol custody `AccountId`, derived from the
admitted network, controller-scoped lock ID, and asset definition. Contracts can
retain that identity for per-lock books and movement events. It does not grant
debit authority or prove settlement before the queued instruction commits. The
host refuses a missing network and prepares the typed return, full instruction
plus return-byte gas, whole return allocation, and retained-effect capacity
before publishing the effect or result. Drawing and cancellation retain the
native exact-remainder precondition.
These additions change the IVM ABI hash; compiler, host and contract manifests
must match. They do not change the privacy bridge ABI version.

The owner-granted `ledger::asset::uid_holding_quote` reader (`0x010224`) returns
only the asset, requested account, current policy revision, beneficial holdings,
optional cap and required overflow. Its six-word nominal product retains the
full unsigned 64-bit revision as an exact Kotodama `int`; the optional quantity
uses the standard sum handle. The quote never exposes a UID or account roster
and never grants transfer authority. Every inspected member and escrow row is
metered, including retained terminal rows, before any result is published.

`ledger::fi::transfer_linked` (`0x010225`) and controlled lock
`{drawdown,cancel,expire}_with_waterfall` (`0x010226`–`0x010228`) retain full
policy and approved-link revision pins. The native executor derives the payout
owner and approved FI and checks current consent, gross funding and UID limits.
The controlled settlement prepares all custody and existing-wallet overflow
legs before one escrow decrement; a preceding quote cannot bypass those checks.
Plain lock settlement keeps its existing behavior without an FI opt-in. All
five helpers require an authenticated contract frame and are unavailable to
generic programs. The quote is a ledger read; the four settlements are ledger
writes. The canonical spec binds exact argument and return layouts into the ABI.

`ledger::fi::link_revision` (`0x010229`) is a separate metered ledger read:
`(asset_definition: AssetDefinitionId, account: AccountId, expected_fi: AccountId)
-> int`. The current owner-approved link must name the exact active controller
and match the asserted FI. Current FI eligibility and attestation revisions
are checked under the shared query budget. The returned exact unsigned 64-bit
revision is only a CAS hint; no FI identity or bank reference is disclosed, and
the assertion never selects a settlement destination. Generic programs cannot
use the reader. It allocates the typed integer only after whole gas/allocation
preflight and cannot queue any effect.

`ledger::asset::same_uid` (`0x01022A`) returns only a boolean for two exact
native retail memberships in one Global asset. Both accounts and current
policies must exist, and the active contract needs the current enabled
asset-owner UID reader grant. A false value means valid retail UIDs differ;
missing, unbound, institutional, corrupt or ungranted inputs are errors. Equal
account addresses still undergo all checks. A retained FI/system classification
precludes retail use, including revoked institutional records. It is not a
universal institutional comparison or exemption. UID membership is append-only;
closed-wallet transfer restrictions do not erase retained ownership. The helper
is a metered ledger read with no UID/roster output or queued effect, unavailable
to generic programs. Source/response gas is checked before publishing the public
0/1 word; the native settlement kernel independently derives and validates ownership.

Native asset escrow
- 0xB8 ESCROW_OPEN_OFFER — Args: `r10=&Name(escrow)`, `r11=&AssetDefinitionId`, `r12=&Quantity`, `r13=&NoritoBytes(Vec<Hash>)` or `0` → 0. Gas: G_escrow + bytes. Queues `OpenAssetEscrow`; the seller authority locks funds into the deterministic protocol custody account.
- 0xB9 ESCROW_ACCEPT — Args: `r10=&Name(escrow)` → 0. Gas: G_escrow + bytes. Queues `AcceptAssetEscrow` for the buyer authority.
- 0xBA ESCROW_MARK_PAYMENT_SENT — Args: `r10=&Name(escrow)` → 0. Gas: G_escrow + bytes. Queues `MarkEscrowPaymentSent` for the accepted buyer.
- 0xBB ESCROW_RELEASE — Args: `r10=&Name(escrow)` → 0. Gas: G_escrow + bytes. Queues `ReleaseAssetEscrow` for the seller authority after payment is marked.
- 0xBC ESCROW_CANCEL — Args: `r10=&Name(escrow)` → 0. Gas: G_escrow + bytes. Queues `CancelAssetEscrow`; cancellation is rejected once payment is marked.
- 0xBD ESCROW_OPEN_DISPUTE — Args: `r10=&Name(escrow)`, `r11=&NoritoBytes(Vec<Hash>)` or `0` → 0. Gas: G_escrow + bytes. Queues `OpenEscrowDispute` for the seller or accepted buyer.
- 0xBE ESCROW_RESOLVE_DISPUTE — Args: `r10=&Name(escrow)`, `r11=&Quantity(buyer_amount)`, `r12=&Quantity(seller_amount)`, `r13=&NoritoBytes(Vec<Hash>)` or `0` → 0. Gas: G_escrow + bytes. Queues `ResolveEscrowDispute`; core enforces `CanResolveEscrowDispute` and that the split sums to the held amount.
- IDs `0xAA` through `0xAF` and `0xBF` are unassigned holes and must report `UnknownSyscall`.
- Kotodama escrow names are deterministically mapped to `EscrowId`; native ISIs perform custody movement directly and `TRANSFER_ASSET_SCOPED` resolves the source balance scope from the asset definition policy, using `r14` only for dataspace-restricted definitions and rejecting them when `r14 = 0`.

Soracloud runtime host surface
- 0xC0 SORACLOUD_READ_COMMITTED_STATE — Args: `r10=&SoracloudRequest(ReadCommittedState)` → `r10=&SoracloudResponse(ReadCommittedState)`. Returns committed service-state metadata for one declared binding/key pair.
- 0xC1 SORACLOUD_EMIT_STATE_MUTATION — Args: `r10=&SoracloudRequest(EmitStateMutation)` → `r10=&SoracloudResponse(EmitStateMutation)`. Stages a deterministic write-back validated again by core before persistence.
- 0xC2 SORACLOUD_EMIT_MAILBOX_MESSAGE — Args: `r10=&SoracloudRequest(EmitMailboxMessage)` → `r10=&SoracloudResponse(EmitMailboxMessage)`. Emits an outbound mailbox message for authoritative queueing after receipt validation.
- 0xC3 SORACLOUD_APPEND_JOURNAL — Args: `r10=&SoracloudRequest(AppendJournal)` → `r10=&SoracloudResponse(AppendJournal)`. Stages deterministic journal material and returns its content hash.
- 0xC4 SORACLOUD_PUBLISH_CHECKPOINT — Args: `r10=&SoracloudRequest(PublishCheckpoint)` → `r10=&SoracloudResponse(PublishCheckpoint)`. Stages checkpoint material and returns its content hash.
- 0xC8 SORACLOUD_READ_CONFIG — Args: `r10=&SoracloudRequest(ReadConfig)` → `r10=&SoracloudResponse(ReadConfig)`. Reads authoritative service config payload bytes for the active revision and is valid from ordinary Soracloud handlers.
- IDs `0xC5` through `0xC7` are retired holes and must report `UnknownSyscall`; validator execution exposes neither plaintext node-local secrets nor nondeterministic network egress.
- 0xC9 SORACLOUD_READ_SECRET_ENVELOPE — Args: `r10=&SoracloudRequest(ReadSecretEnvelope)` → `r10=&SoracloudResponse(ReadSecretEnvelope)`. Reads the authoritative committed client-ciphertext secret envelope for the active revision and is valid from ordinary Soracloud handlers.
- All Soracloud payloads are Norito request/response envelopes carried in the Soracloud pointer-ABI types. Gas: G_soracloud + request bytes + response bytes. Host failures must be deterministic and receipt-stable, and unknown numbers still map to `VMError::UnknownSyscall`.
- Dedicated Soracloud handler execution uses `irohad`'s `SoracloudIvmHost` to
  produce response envelopes and stage deterministic runtime side effects.
  Ordinary contract execution through `CoreHostImpl` is fail-closed for these
  numbers: it validates the `SoracloudRequest` pointer type, schema version,
  syscall operation, and payload variant, then returns metered
  `VMError::NotImplemented` with `G_soracloud + request bytes` and queues no
  ISI. Wrong pointer types or operation/payload mismatches fail during request
  validation.

ZK Helpers
- 0xF9 GET_ACCOUNT_BALANCE — Args: `r10=&AccountId, r11=&AssetDefinitionId` → `ptr (&Quantity)` — Gas: G_get_bal
- 0xFC VERIFY_SIGNATURE — Args: `r10=&Blob(message)`, `r11=&Blob(signature)`, `r12=&Blob(pubkey)`, `r13=scheme:u8` → `r10=0/1` — Gas: G_verify_sig + bytes. Scheme codes: `1` Ed25519, `2` secp256k1 ECDSA, `3` ML-DSA. Kotodama's `crypto::verify_signature` takes a compile-time `SignatureScheme` value, so compiled seiyaku never pass any other code.

Runtime Summaries / Proof Verification
- 0xF4 EXECUTION_SUMMARY — Args: none → `r10=&NoritoBytes(ExecutionSummary), r11=status:u64` — Gas: G_execution_summary
  - Returns a deterministic, self-reported execution summary containing fixed fields plus SHA-256 digests of the VM's PC, delta-register, ZK trace, constraint, memory, register, and step-root logs. It is not an independently verifiable proof or an authenticated execution attestation. Cryptographic proof verification uses the dedicated verifier syscalls below.
- 0xF5 GROW_HEAP — Args: `r10=bytes:u64` → `u64=new_limit` — Gas: G_grow_heap per page. Growth fails with `OutOfMemory` when it would exceed the host-installed per-runtime heap ceiling.
- 0xF6 VERIFY_PROOF — Args: `r10=&NoritoBytes(OpenVerifyEnvelope)` → `r10=0/1, r11=status:u64` — Gas: G_verify_proof + bytes
  - `CoreHost` verifies the envelope against the on-chain verifying-key registry with the same deterministic guardrails used by the typed ZK verifier syscalls. The standalone host still returns `NotImplemented` because it has no registry or backend policy context.
- 0xF7 GET_MERKLE_PATH — Args: `r10=addr:u64, r11=out_ptr:u64, r12=root_out:u64?` → `u64=len` — Gas: G_mpath + path_len
  - Writes the authentication path (leaf→root) to `out_ptr`. If `r12 != 0`, also writes the 32‑byte Merkle root to `root_out`.
- 0xFA GET_MERKLE_COMPACT — Args: `r10=addr:u64, r11=out_ptr:u64, r12=depth_cap:u64?, r13=root_out:u64?` → `u64=depth` — Gas: G_mpath + depth
  - Writes a compact proof to `out_ptr` using the layout `[u8 depth][u32 dirs_le][u32 count][count*32 siblings]` with siblings ordered leaf→root.
  - `dirs` encodes, for each level i, whether the running accumulator was the left (0) or right (1) child. Missing siblings are encoded as a 32‑byte zero array (promotion).
  - Caps the depth to `min(depth_cap, 32)` if `r12 != 0`, otherwise uses full path depth up to 32. If `r13 != 0`, writes the 32‑byte Merkle root at `root_out`.
- 0xFF GET_REGISTER_MERKLE_COMPACT — Args: `r10=reg_index:u64, r11=out_ptr:u64, r12=depth_cap:u64?, r13=root_out:u64?` → `u64=depth` — Gas: G_mpath + depth
  - Writes a compact proof for the register commitment using the same layout as GET_MERKLE_COMPACT.

VRF
- 0x66 VRF_VERIFY — Args: `r10=&NoritoBytes(VrfVerifyRequest{variant:u8, pk:bytes, proof:bytes, network_id:NetworkId, input:bytes})`, canonical frame at most 65,536 bytes → Return: `r10=ptr (&Blob(32-byte output))`, `r11=status:u64` — Gas: `64 + 250,000 × examined_items + 5 × canonical_request_bytes`
  - Status codes: `0=ok`, `1=type_mismatch`, `2=decode_error`, `3=unknown_variant`, `4=bad_pk`, `5=bad_proof`, `6=verify_fail`, `8=missing_or_mismatched_host_network`.
  - Canonical-decode failures examine zero items. Every decoded request whose network, variant, key, proof, or pairing validation begins examines one item. Output encoding/allocation failures trap after charging that item.
  - The host must provide the exact genesis-derived `NetworkId`. An absent host network or a request claiming a different identity is rejected with `r11=8`; the guest claim is never used as fallback consensus context.
  - Proof: BLS signature over `Hash("iroha:vrf:v1:input|" || network_id_bytes || "|" || input)` using VRF-specific DSTs:
    - G2 hash: `"BLS12381G2_XMD:SHA-256_SSWU_RO_IROHA_VRF_V1"`
    - G1 hash: `"BLS12381G1_XMD:SHA-256_SSWU_RO_IROHA_VRF_V1"`
    - Output: `Hash("iroha:vrf:v1:output" || canonical_proof_bytes)`.
  - Encodings: pk and proof MUST be canonical compressed encodings; infinity/non-subgroup are rejected.
  - Variants: `1 = SigInG2 (pk=G1 48B, proof=G2 96B)`, `2 = SigInG1 (pk=G2 96B, proof=G1 48B)`.
  - Both VRF verification syscalls decode with the shared V1 resource budget: at most 65,536 elements in any sequence and cumulatively, at most 65,536 bytes in one field, at most 524,288 cumulative allocated bytes, and nesting depth at most 16.

- 0x67 VRF_VERIFY_BATCH — Args: `r10=&NoritoBytes(VrfVerifyBatchRequest{items: [VrfVerifyRequest]})`, 1 through 16 items, canonical frame at most 65,536 bytes → Return: `r10=ptr (&NoritoBytes(Vec<[u8;32]>))`, `r11=status:u64`, `r12=fail_index?:u64` — Gas: `64 + 250,000 × examined_items + 5 × canonical_request_bytes`
  - Verifies each item; on success returns a Norito-encoded vector of 32‑byte outputs (order preserved). On failure, returns `r10=0`, `r11` = error code, `r12` = index (0‑based) of the first failing item.
  - Empty and over-16 batches fail with `r11=9 (batch_bound)` and `r12=u64::MAX` before backend or response-allocation work. Canonical-decode and batch-bound failures examine zero items. The VM reserves 16 items, then deterministically refunds every unexamined item, including the tail after the first failing item.
  - The host must provide its exact `NetworkId` and every item must match it. An absent host network or mismatch fails with `r11=8` and `r12` set to the first affected index.

- 0x7E VRF_EPOCH_SEED — Args: public `r10=epoch:u64` → Return: `r10=&Blob(seed[32])`, or zero when the exact epoch is absent; `r11` is unchanged. Gas: G_state_query + 8 + 32 for a found seed, G_state_query + 8 otherwise. No latest-epoch fallback. VM memory exhaustion is a typed fault; local allocation refusal remains deferred.
  - Reads a world-snapshot VRF epoch seed for governance/sortition use in smart contracts.
  - An absent exact epoch produces `Option::none()` in Kotodama; a present epoch produces `Option::some(seed)`. No other epoch is substituted.

Host gating and exact-network binding
- A host-owned `NetworkId` is mandatory for VRF verification. Missing host
  context and guest/host mismatches both fail closed:
  - Single: `r11=8` and `r10=0`.
  - Batch: `r11=8`, `r12` set to the first affected index, and `r10=0`.
- Output derivation uses domain separation and canonical encodings as described above; outputs are deterministic across hardware.

Notes
- All calls execute via `CoreHost` and are subject to permission checks and invariants identical to built‑in ISIs.
- Gas names reference entries in the generated gas table for the active bytecode header version.

## ABI Stability (ABI v1)

This is the first release, so the ABI surface is still allowed to change before
release cut. The shipped runtime still has exactly one policy, ABI v1, and every
node enforces that policy unconditionally.

- `ProgramMetadata.abi_version` must be `1`; other values are rejected at admission.
- Runtime upgrade manifests must keep `abi_version = 1`; there is no V2 policy yet.
- ABI goldens (syscall list, ABI hash, pointer type IDs) are pinned to the current
  v1 surface and must be updated in the same change whenever the first-release
  surface intentionally changes.
- A changed ABI hash is a `contract_redeployment` cutover
  ([`specs/first_release_history_cutover.md`](../../../specs/first_release_history_cutover.md)).
  Record the new hash under `declared_abi_cutover` in
  `specs/first_release_history_cutover.json` and regenerate, through its own
  generator, every artifact the `abi` surface lists as carrying it;
  `scripts/check_first_release_history.py` fails until the golden, the carriers
  and the inventory agree. Admission keeps rejecting any other `abi_hash`.
- Syscall `0xA0` defines exactly one operation tag, `1=SubmitBallot`; every
  other tag is rejected. Contracts cannot record outbound SCCP messages: an
  encoded `RecordSccpMessage` fails under every tag, and a contract-registered
  trigger or any other opaque execution output that derives `RecordSccpMessage`
  is refused (`specs/sccp.md` §4.4). The argument text of `spec/syscalls.toml`
  is part of the hashed surface, so it must match the implemented registers
  exactly.
- Callable metadata carries complete flat `CallSchemaV1` argument/result trees.
  The sole CS1 body uses magic `43533100`, fixed `u64` node count and one-byte
  node tags with complete canonical payloads; enclosing Norito flags declare
  child length layouts. It removes enum/vector framing redundancy while
  preserving every callable root, role, error identity and eager table check.
  The former vector body is rejected and its ABI hash/captures must be replaced
  by genuine current native output.
  It preserves Option/Result payloads, exact List capacities and element types,
  nominal products/errors, privacy, and complete
  `StateCursor(EntrypointValueTypeV1)` scalar or tuple key schemas.
  Table counts derive from the trees; active nested values use the same checks as
  direct words. Canonical cursor frames with a different key-schema hash are rejected;
  key schemas contain supported scalar leaves and tuples of at least two elements.
  `Json` and live handles are not supported key components. Private schemas retain the compiler's
  250,000-node/depth-256 bounds; public record limits remain unchanged.
- Pointer provenance tests pin INPUT, allocated HEAP, and exact indexed literals as the only
  accepted V1 object stores. Asset mutation fixtures pin canonical `QuantityValueV1` frames;
  scalar and legacy `NoritoBytes(Numeric)` amount arguments remain invalid.
- Compiler transport normalizes semantic request bytes to `NoritoBytes` before strict VRF
  verification, while typed durable `bytes` values persist only canonical `Blob` atoms.
- Every `abi_syscall_list()` entry, with its `syscall_name`, is mapped to its proof-relation
  obligations in [`proof_coverage/syscalls.rs`](../src/proof_coverage/syscalls.rs). There is no
  default exclusion list: an added, removed or renamed syscall fails the inventory tests until
  it is mapped, and an unfinished syscall relation keeps complete proof coverage open. See
  [`proof_coverage.md`](proof_coverage.md).
- Any future post-release ABI break must be delivered through a new policy/version
  with updated tests and docs.

<!-- BEGIN GENERATED SYSCALLS -->
| Number | Name | Args | Return | Gas |
|---|---|---|---|---|
| 0x00 | DEBUG_PRINT | r10=value:u64 | - | asset:gas/G_debug@ivm.core/v2 |
| 0x01 | EXIT | r10=status:u64 | u64=status | asset:gas/G_exit@ivm.core/v2 |
| 0x02 | ABORT | - | u64=0 | asset:gas/G_abort@ivm.core/v2 |
| 0x03 | DEBUG_LOG | r10=&Json | u64=0 | asset:gas/G_debug@ivm.core/v2 |
| 0x04 | CONTRACT_ABORT | r10=&NoritoBytes(ContractErrorTypeDescriptor), r11=code:u32, r12=0, r13=0, r14=0, r15=0 | u64=0 | asset:gas/G_abort@ivm.core/v2 + descriptor bytes + selected message UTF-8 bytes |
| 0x10 | REGISTER_DOMAIN | r10=&DomainId | u64=0 | asset:gas/G_reg_domain@ivm.core/v2 |
| 0x11 | UNREGISTER_DOMAIN | r10=&DomainId | u64=0 | asset:gas/G_unreg_domain@ivm.core/v2 |
| 0x12 | TRANSFER_DOMAIN | r10=&DomainId, r11=&AccountId(to) | u64=0 | asset:gas/G_transfer_domain@ivm.core/v2 |
| 0x13 | REGISTER_ACCOUNT | r10=&AccountId | u64=0 | asset:gas/G_reg_acct@ivm.core/v2 |
| 0x14 | UNREGISTER_ACCOUNT | r10=&AccountId | u64=0 | asset:gas/G_unreg_acct@ivm.core/v2 |
| 0x15 | REGISTER_PEER | r10=&Json | u64=0 | asset:gas/G_reg_peer@ivm.core/v2 |
| 0x16 | UNREGISTER_PEER | r10=&Json | u64=0 | asset:gas/G_unreg_peer@ivm.core/v2 |
| 0x17 | ADD_SIGNATORY | r10=&AccountId, r11=&Json | u64=0 | asset:gas/G_add_sig@ivm.core/v2 |
| 0x18 | REMOVE_SIGNATORY | r10=&AccountId, r11=&Json | u64=0 | asset:gas/G_rm_sig@ivm.core/v2 |
| 0x19 | SET_ACCOUNT_QUORUM | r10=&AccountId, r11=quorum:u64 | u64=0 | asset:gas/G_set_quorum@ivm.core/v2 |
| 0x1A | SET_ACCOUNT_DETAIL | r10=&AccountId, r11=&Name, r12=&Json | u64=0 | asset:gas/G_set_detail@ivm.core/v2 + bytes(val) |
| 0x20 | REGISTER_ASSET | r10=&AssetDefinitionId, r11=&Blob(name), r12=numeric_spec:u64, r13=mintability:u64 | u64=0 | asset:gas/G_reg_asset@ivm.core/v2 |
| 0x21 | UNREGISTER_ASSET | r10=&AssetDefinitionId | u64=0 | asset:gas/G_unreg_asset@ivm.core/v2 |
| 0x22 | MINT_ASSET | r10=&AccountId, r11=&AssetDefinitionId, r12=&Quantity | u64=0 | asset:gas/G_mint@ivm.core/v2 |
| 0x23 | BURN_ASSET | r10=&AccountId, r11=&AssetDefinitionId, r12=&Quantity | u64=0 | asset:gas/G_burn@ivm.core/v2 |
| 0x24 | TRANSFER_V1 | r10=&AccountId(from), r11=&AccountId(to), r12=&AssetDefinitionId, r13=&Quantity; batch-internal only | u64=0 | asset:gas/G_transfer@ivm.core/v2 |
| 0x25 | NFT_MINT_ASSET | r10=&NftId, r11=&AccountId(owner) | u64=0 | asset:gas/G_nft_mint_asset@ivm.core/v2 |
| 0x26 | NFT_TRANSFER_ASSET | r10=&AccountId(from), r11=&NftId, r12=&AccountId(to) | u64=0 | asset:gas/G_nft_transfer_asset@ivm.core/v2 |
| 0x27 | NFT_SET_METADATA | r10=&NftId, r11=&Name, r12=&Json | u64=0 | asset:gas/G_nft_set_metadata@ivm.core/v2 |
| 0x28 | NFT_BURN_ASSET | r10=&NftId | u64=0 | asset:gas/G_nft_burn_asset@ivm.core/v2 |
| 0x29 | TRANSFER_V1_BATCH_BEGIN | - | u64=0 | asset:gas/G_fastpq_batch@ivm.core/v2 |
| 0x2A | TRANSFER_V1_BATCH_END | - | u64=0 | asset:gas/G_fastpq_batch@ivm.core/v2 |
| 0x2B | TRANSFER_V1_BATCH_APPLY | r10=&NoritoBytes(TransferAssetBatch) | u64=0 | asset:gas/G_transfer@ivm.core/v2 per entry |
| 0x2C | TRANSFER_ASSET_SCOPED | r10=&AccountId(from), r11=&AccountId(to), r12=&AssetDefinitionId, r13=&Quantity, r14=&DataSpaceId or 0 | u64=0 | asset:gas/G_transfer@ivm.core/v2 |
| 0x30 | CREATE_ROLE | r10=&Name, r11=&Json(perms) | u64=0 | asset:gas/G_create_role@ivm.core/v2 |
| 0x31 | DELETE_ROLE | r10=&Name | u64=0 | asset:gas/G_delete_role@ivm.core/v2 |
| 0x32 | GRANT_ROLE | r10=&AccountId, r11=&Name | u64=0 | asset:gas/G_grant_role@ivm.core/v2 |
| 0x33 | REVOKE_ROLE | r10=&AccountId, r11=&Name | u64=0 | asset:gas/G_revoke_role@ivm.core/v2 |
| 0x34 | GRANT_PERMISSION | r10=&AccountId, r11=&Name | u64=0 | asset:gas/G_grant_perm@ivm.core/v2 |
| 0x35 | REVOKE_PERMISSION | r10=&AccountId, r11=&Name | u64=0 | asset:gas/G_revoke_perm@ivm.core/v2 |
| 0x36 | GRANT_CONTRACT_PERMISSION | r10=&AccountId, r11=&Name(permission) | u64=0 | asset:gas/G_grant_perm@ivm.core/v2 |
| 0x37 | REVOKE_CONTRACT_PERMISSION | r10=&AccountId, r11=&Name(permission) | u64=0 | asset:gas/G_revoke_perm@ivm.core/v2 |
| 0x40 | CREATE_TRIGGER | r10=&Json(spec) | u64=0 | asset:gas/G_create_trig@ivm.core/v2 |
| 0x41 | REMOVE_TRIGGER | r10=&Name | u64=0 | asset:gas/G_remove_trig@ivm.core/v2 |
| 0x42 | SET_TRIGGER_ENABLED | r10=&Name, r11=enabled:u64 | u64=0 | asset:gas/G_set_trig@ivm.core/v2 |
| 0x43 | DEACTIVATE_CONTRACT_INSTANCE | r10=&NoritoBytes(DeactivateContractInstance) | u64=0 | asset:gas/G_contract_admin@ivm.core/v2 + bytes |
| 0x44 | REMOVE_SMART_CONTRACT_BYTES | r10=&NoritoBytes(RemoveSmartContractBytes) | u64=0 | asset:gas/G_contract_admin@ivm.core/v2 + bytes |
| 0x45 | REGISTER_SMART_CONTRACT_CODE | r10=&NoritoBytes(RegisterSmartContractCode) | u64=0 | asset:gas/G_contract_admin@ivm.core/v2 + bytes |
| 0x46 | REGISTER_SMART_CONTRACT_BYTES | r10=&NoritoBytes(RegisterSmartContractBytes) | u64=0 | asset:gas/G_contract_admin@ivm.core/v2 + bytes |
| 0x47 | ACTIVATE_CONTRACT_INSTANCE | r10=&NoritoBytes(ActivateContractInstance) | u64=0 | asset:gas/G_contract_admin@ivm.core/v2 + bytes |
| 0x50 | STATE_GET | r10=&NoritoBytes(StatePath) | r10=ptr (&NoritoBytes) or 0 | asset:gas/G_state_get@ivm.core/v2 + canonical path frame bytes + returned value bytes |
| 0x51 | STATE_SET | r10=&NoritoBytes(StatePath), r11=&NoritoBytes | u64=0 | asset:gas/G_state_set@ivm.core/v2 + canonical path frame bytes + value bytes |
| 0x52 | STATE_DEL | r10=&NoritoBytes(StatePath) | u64=0 | asset:gas/G_state_del@ivm.core/v2 + canonical path frame bytes |
| 0x56 | BUILD_PATH_KEY_NORITO | r10=&Name(base), r11=&NoritoBytes(key) | r10=ptr (&NoritoBytes(StatePath)) | asset:gas/G_path@ivm.core/v2 + bytes |
| 0x57 | JSON_ENCODE | r10=&Json | ptr (&NoritoBytes) | asset:gas/G_json_encode@ivm.core/v2 + bytes |
| 0x58 | JSON_DECODE | r10=&NoritoBytes(JSON bytes) | ptr (&Json) | asset:gas/G_json_decode@ivm.core/v2 + bytes |
| 0x59 | SCHEMA_ENCODE | r10=&Name(schema), r11=&Json | ptr (&NoritoBytes) | asset:gas/G_schema@ivm.core/v2 + bytes |
| 0x5A | SCHEMA_DECODE | r10=&Name(schema), r11=&NoritoBytes | ptr (&Json) | asset:gas/G_schema@ivm.core/v2 + bytes |
| 0x5B | SCHEMA_INFO | r10=&Name(schema) | ptr (&Json{"id":...,"version":...}) | asset:gas/G_schema@ivm.core/v2 + bytes |
| 0x5C | NAME_DECODE | r10=&NoritoBytes(UTF-8 string) | ptr (&Name) | asset:gas/G_name_decode@ivm.core/v2 + bytes |
| 0x5D | POINTER_TO_NORITO | r10=&PointerType<T> | ptr (&NoritoBytes(TLV envelope)) | asset:gas/G_pointer@ivm.core/v2 + bytes |
| 0x5E | POINTER_FROM_NORITO | r10=&NoritoBytes(TLV envelope), r11=expected?:u16 | ptr (&PointerType<T>) | asset:gas/G_pointer@ivm.core/v2 + bytes |
| 0x5F | TLV_EQ | r10=&Tlv, r11=&Tlv | r10=1/0 | asset:gas/G_tlv_eq@ivm.core/v2 + bytes |
| 0x60 | ZK_VOTE_VERIFY_BALLOT | r10=&NoritoBytes(OpenVerifyEnvelope) | u64=0/1 | asset:gas/G_verify_proof@ivm.core/v2 + bytes |
| 0x61 | ZK_VOTE_VERIFY_TALLY | r10=&NoritoBytes(OpenVerifyEnvelope) | u64=0/1 | asset:gas/G_verify_proof@ivm.core/v2 + bytes |
| 0x62 | ZK_ROOTS_GET | r10=&NoritoBytes(RootsGetRequest) | ptr (NoritoBytes in INPUT) | asset:gas/G_roots_get@ivm.core/v2 + bytes |
| 0x63 | ZK_VOTE_GET_TALLY | r10=&NoritoBytes(VoteGetTallyRequest) | ptr (NoritoBytes in INPUT) | asset:gas/G_vote_get@ivm.core/v2 + bytes |
| 0x64 | ZK_VERIFY_BATCH | r10=&NoritoBytes(Vec<OpenVerifyEnvelope>) | r10=ptr (&NoritoBytes(Vec<u8> statuses)), r11=status:u64 | 250,000 per proof + 5 per encoded byte + bounded per-proof archive/status bytes |
| 0x66 | VRF_VERIFY | r10=&NoritoBytes(VrfVerifyRequest), canonical frame <=65536 bytes | r10=ptr (&Blob(32-byte output)), r11=status:u64 | 64 + 250,000 per examined item + 5 per canonical request byte |
| 0x67 | VRF_VERIFY_BATCH | r10=&NoritoBytes(VrfVerifyBatchRequest), 1..=16 items, canonical frame <=65536 bytes | r10=ptr (&NoritoBytes(Vec<[u8;32]>)), r11=status:u64, r12=fail_index?:u64 | 64 + 250,000 per examined item + 5 per canonical request byte |
| 0x77 | TLV_LEN | r10=&Tlv | r10=payload_len:u64 | asset:gas/G_tlv_len@ivm.core/v2 + bytes |
| 0x79 | JSON_GET_JSON | r10=&Json(object), r11=&Name(key) | r10=Option<Json> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x7A | JSON_GET_NAME | r10=&Json(object), r11=&Name(key) | r10=Option<Name> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x7B | JSON_GET_ACCOUNT_ID | r10=&Json(object), r11=&Name(key) | r10=Option<AccountId> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x7C | JSON_GET_NFT_ID | r10=&Json(object), r11=&Name(key) | r10=Option<NftId> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x7D | JSON_GET_BLOB_HEX | r10=&Json(object), r11=&Name(key) | r10=Option<bytes> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x7E | VRF_EPOCH_SEED | r10=epoch:u64 | r10=&Blob(seed[32]) or 0 if absent | asset:gas/G_state_query@ivm.core/v2 + 8 + 32 if found, otherwise G_state_query + 8 |
| 0x80 | JSON_GET_ASSET_DEFINITION_ID | r10=&Json(object), r11=&Name(key) | r10=Option<AssetDefinitionId> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x81 | JSON_OBJECT | - | r10=&Json(empty object) | asset:gas/G_json@ivm.core/v2 + encoded bytes |
| 0x82 | JSON_SET_I64 | r10=&Json(object), r11=&Name(key), r12=value:i64 | r10=&Json | asset:gas/G_json@ivm.core/v2 + encoded bytes |
| 0x83 | JSON_SET_ACCOUNT_ID | r10=&Json(object), r11=&Name(key), r12=&AccountId | r10=&Json | asset:gas/G_json@ivm.core/v2 + encoded bytes |
| 0x90 | SM3_HASH | r10=&Blob(message) | r10=ptr (&Blob(digest)) | asset:gas/G_hash@ivm.core/v2 + bytes |
| 0x91 | SM2_VERIFY | r10=&Blob(msg), r11=&Blob(sig), r12=&Blob(pubkey), r13=&Blob(distid)? | u64=0/1 | asset:gas/G_verify@ivm.core/v2 + bytes |
| 0x92 | SM4_GCM_SEAL | r10=&Blob(key16), r11=&Blob(nonce12), r12=&Blob(aad)?, r13=&Blob(plaintext) | r10=ptr (&Blob(ciphertext || tag16)) | asset:gas/G_sm4@ivm.core/v2 + bytes |
| 0x93 | SM4_GCM_OPEN | r10=&Blob(key16), r11=&Blob(nonce12), r12=&Blob(aad)?, r13=&Blob(ciphertext || tag16) | r10=ptr (&Blob(plaintext)) or 0 | asset:gas/G_sm4@ivm.core/v2 + bytes |
| 0x94 | SM4_CCM_SEAL | r10=&Blob(key16), r11=&Blob(nonce[7..13]), r12=&Blob(aad)?, r13=&Blob(plaintext), r14=tag_len:u64 | r10=ptr (&Blob(ciphertext || tag)) | asset:gas/G_sm4@ivm.core/v2 + bytes |
| 0x95 | SM4_CCM_OPEN | r10=&Blob(key16), r11=&Blob(nonce[7..13]), r12=&Blob(aad)?, r13=&Blob(ciphertext || tag), r14=tag_len:u64 | r10=ptr (&Blob(plaintext)) or 0 | asset:gas/G_sm4@ivm.core/v2 + bytes |
| 0x96 | SHA256_HASH | r10=&Blob(message) | r10=ptr (&Blob(digest)) | asset:gas/G_hash@ivm.core/v2 + bytes |
| 0x97 | SHA3_HASH | r10=&Blob(message) | r10=ptr (&Blob(digest)) | asset:gas/G_hash@ivm.core/v2 + bytes |
| 0x98 | BLAKE2B256_HASH | r10=&Blob(message) | r10=ptr (&Blob(raw Blake2b-256 digest)) | asset:gas/G_hash@ivm.core/v2 + bytes |
| 0x99 | KECCAK256_HASH | r10=&Blob(message) | r10=ptr (&Blob(Keccak-256 digest)) | asset:gas/G_hash@ivm.core/v2 + bytes |
| 0x9A | IROHA_HASH | r10=&Blob(message) | r10=ptr (&Blob(Iroha Hash::new digest)) | asset:gas/G_hash@ivm.core/v2 + bytes |
| 0xA0 | SMARTCONTRACT_EXECUTE_INSTRUCTION | r10=&NoritoBytes(InstructionBox), r11=operation_tag(1=SubmitBallot) | u64=0 | asset:gas/G_sci@ivm.core/v2 |
| 0xA1 | SMARTCONTRACT_EXECUTE_QUERY | r10=&NoritoBytes(QueryRequest) | r10=ptr (&NoritoBytes(QueryResponse)) | asset:gas/G_scq@ivm.core/v2 |
| 0xA2 | CREATE_NFTS_FOR_ALL_USERS | - | u64=count | asset:gas/G_create_nfts_all@ivm.core/v2 |
| 0xA3 | SET_SMARTCONTRACT_EXECUTION_DEPTH | r10=depth:u64 | u64=prev | asset:gas/G_sc_depth@ivm.core/v2 |
| 0xA4 | GET_AUTHORITY | - | ptr (AccountId in INPUT) | asset:gas/G_get_auth@ivm.core/v2 + bytes |
| 0xA5 | SUBSCRIPTION_BILL | - | u64=0 | asset:gas/G_sub_bill@ivm.core/v2 |
| 0xA6 | SUBSCRIPTION_RECORD_USAGE | - | u64=0 | asset:gas/G_sub_usage@ivm.core/v2 |
| 0xA7 | RESOLVE_ACCOUNT_ALIAS | r10=&Blob(alias literal) | ptr (&AccountId in INPUT) | asset:gas/G_alias_resolve@ivm.core/v2 |
| 0xA8 | CURRENT_TIME_MS | - | r10=unix_time_ms:u64 | asset:gas/G_sysvar@ivm.core/v2 |
| 0xA9 | CALL_CONTRACT | r10=&Blob(contract_address), r11=&NoritoBytes(ContractCallBindingV1), r12=argument-table-base, r13=exact-argument-words, r14=result-table-base, r15=exact-result-words | caller-owned typed result table; Unit uses one zero word | asset:gas/G_call_contract@ivm.core/v2 + request bytes + return bytes + child gas |
| 0xAA | EMIT_CONTRACT_EVENT | r10=authenticated event ordinal, r11=owned public heap word table, r12=exact schema word count | - | 32 + 1 per canonical schema byte + 32 per active schema node + 1 per retained full TLV byte |
| 0xB0 | AXT_BEGIN | r10=&AxtDescriptor | u64=0 | asset:gas/G_axt@ivm.core/v2 + bytes |
| 0xB1 | AXT_TOUCH | r10=&DataSpaceId, r11=&NoritoBytes(TouchManifest) or 0 | u64=0 | asset:gas/G_axt@ivm.core/v2 + bytes |
| 0xB2 | AXT_COMMIT | - | u64=0 | asset:gas/G_axt@ivm.core/v2 + entries |
| 0xB3 | VERIFY_DS_PROOF | r10=&DataSpaceId, r11=&ProofBlob or 0 | u64=0/1 | asset:gas/G_verify@ivm.core/v2 + bytes |
| 0xB5 | AXT_STAGE_ANCHORED_SPEND | r10=&AxtAnchoredSpendV1 | u64=0 | asset:gas/G_axt@ivm.core/v2 + bytes |
| 0xB8 | ESCROW_OPEN_OFFER | r10=&Name(escrow), r11=&AssetDefinitionId, r12=&Quantity, r13=&NoritoBytes(Vec<Hash>) or 0 | u64=0 | asset:gas/G_escrow@ivm.core/v2 + bytes |
| 0xB9 | ESCROW_ACCEPT | r10=&Name(escrow) | u64=0 | asset:gas/G_escrow@ivm.core/v2 + bytes |
| 0xBA | ESCROW_MARK_PAYMENT_SENT | r10=&Name(escrow) | u64=0 | asset:gas/G_escrow@ivm.core/v2 + bytes |
| 0xBB | ESCROW_RELEASE | r10=&Name(escrow) | u64=0 | asset:gas/G_escrow@ivm.core/v2 + bytes |
| 0xBC | ESCROW_CANCEL | r10=&Name(escrow) | u64=0 | asset:gas/G_escrow@ivm.core/v2 + bytes |
| 0xBD | ESCROW_OPEN_DISPUTE | r10=&Name(escrow), r11=&NoritoBytes(Vec<Hash>) or 0 | u64=0 | asset:gas/G_escrow@ivm.core/v2 + bytes |
| 0xBE | ESCROW_RESOLVE_DISPUTE | r10=&Name(escrow), r11=&Quantity(buyer_amount), r12=&Quantity(seller_amount), r13=&NoritoBytes(Vec<Hash>) or 0 | u64=0 | asset:gas/G_escrow@ivm.core/v2 + bytes |
| 0xC0 | SORACLOUD_READ_COMMITTED_STATE | r10=&SoracloudRequest(ReadCommittedState) | r10=&SoracloudResponse(ReadCommittedState) under SoracloudIvmHost; CoreHostImpl returns metered NotImplemented after validation | asset:gas/G_soracloud@ivm.core/v2 + request bytes (+ response bytes under SoracloudIvmHost) |
| 0xC1 | SORACLOUD_EMIT_STATE_MUTATION | r10=&SoracloudRequest(EmitStateMutation) | r10=&SoracloudResponse(EmitStateMutation) under SoracloudIvmHost; CoreHostImpl returns metered NotImplemented after validation | asset:gas/G_soracloud@ivm.core/v2 + request bytes (+ response bytes under SoracloudIvmHost) |
| 0xC2 | SORACLOUD_EMIT_MAILBOX_MESSAGE | r10=&SoracloudRequest(EmitMailboxMessage) | r10=&SoracloudResponse(EmitMailboxMessage) under SoracloudIvmHost; CoreHostImpl returns metered NotImplemented after validation | asset:gas/G_soracloud@ivm.core/v2 + request bytes (+ response bytes under SoracloudIvmHost) |
| 0xC3 | SORACLOUD_APPEND_JOURNAL | r10=&SoracloudRequest(AppendJournal) | r10=&SoracloudResponse(AppendJournal) under SoracloudIvmHost; CoreHostImpl returns metered NotImplemented after validation | asset:gas/G_soracloud@ivm.core/v2 + request bytes (+ response bytes under SoracloudIvmHost) |
| 0xC4 | SORACLOUD_PUBLISH_CHECKPOINT | r10=&SoracloudRequest(PublishCheckpoint) | r10=&SoracloudResponse(PublishCheckpoint) under SoracloudIvmHost; CoreHostImpl returns metered NotImplemented after validation | asset:gas/G_soracloud@ivm.core/v2 + request bytes (+ response bytes under SoracloudIvmHost) |
| 0xC8 | SORACLOUD_READ_CONFIG | r10=&SoracloudRequest(ReadConfig) | r10=&SoracloudResponse(ReadConfig) under SoracloudIvmHost; CoreHostImpl returns metered NotImplemented after validation | asset:gas/G_soracloud@ivm.core/v2 + request bytes (+ response bytes under SoracloudIvmHost) |
| 0xC9 | SORACLOUD_READ_SECRET_ENVELOPE | r10=&SoracloudRequest(ReadSecretEnvelope) | r10=&SoracloudResponse(ReadSecretEnvelope) under SoracloudIvmHost; CoreHostImpl returns metered NotImplemented after validation | asset:gas/G_soracloud@ivm.core/v2 + request bytes (+ response bytes under SoracloudIvmHost) |
| 0xE0 | INPUT_PUBLISH_TLV | r10=&Blob(TLV) | ptr (r10) | asset:gas/G_input_publish@ivm.core/v2 + bytes |
| 0xF0 | ALLOC | r10=bytes:u64 | ptr (r10) | asset:gas/G_alloc@ivm.core/v2 + bytes |
| 0xF1 | GET_PUBLIC_INPUT | r10=&Name | ptr (&Tlv) | asset:gas/G_get_pub@ivm.core/v2 + bytes |
| 0xF4 | EXECUTION_SUMMARY | - | r10=ptr (&NoritoBytes(ExecutionSummary)), r11=status:u64 | asset:gas/G_execution_summary@ivm.core/v2 |
| 0xF5 | GROW_HEAP | r10=bytes:u64 | u64=new_limit | asset:gas/G_grow_heap@ivm.core/v2 per page |
| 0xF6 | VERIFY_PROOF | r10=&NoritoBytes(OpenVerifyEnvelope) | r10=0/1, r11=status:u64 | asset:gas/G_verify_proof@ivm.core/v2 + bytes |
| 0xF7 | GET_MERKLE_PATH | r10=addr:u64, r11=out:u64, r12=root_out?:u64 | u64=len | asset:gas/G_mpath@ivm.core/v2 + len |
| 0xF8 | PRIVATE_NUMERIC_VALCOM | r10=private:&Int|&Decimal|&Quantity(value), r11=private:&Int|&Decimal|&Quantity(blind) | r10=public:&Int(full compressed Pedersen point) | asset:gas/G_private_numeric_valcom@ivm.core/v2 |
| 0xF9 | GET_ACCOUNT_BALANCE | r10=&AccountId, r11=&AssetDefinitionId | ptr (&Quantity) | asset:gas/G_get_bal@ivm.core/v2 |
| 0xFA | GET_MERKLE_COMPACT | r10=addr, r11=out, r12=depth_cap?, r13=root_out? | u64=depth | asset:gas/G_mpath@ivm.core/v2 + depth |
| 0xFC | VERIFY_SIGNATURE | r10=&Blob(message), r11=&Blob(signature), r12=&Blob(pubkey), r13=scheme:u8 | r10=0/1 | asset:gas/G_verify_sig@ivm.core/v2 + bytes |
| 0xFD | GET_PRIVATE_INPUT | r10=index:u64, r11=PrivateInputKindV1 | r10=private:&Int|&Decimal|&Quantity | asset:gas/G_get_priv@ivm.core/v2 |
| 0xFE | COMMIT_OUTPUT | - | u64=0 | asset:gas/G_commit@ivm.core/v2 |
| 0xFF | GET_REGISTER_MERKLE_COMPACT | r10=reg, r11=out, r12=depth_cap?, r13=root_out? | u64=depth | asset:gas/G_mpath@ivm.core/v2 + depth |
| 0x10000 | QUERY_EXECUTE_NORITO | r10=&NoritoBytes(QueryRequest) | r10=ptr (&NoritoBytes(QueryResponse)) | asset:gas/G_scq@ivm.core/v2 |
| 0x10001 | CORE_QUERY_GET | r10=CoreQueryEntityTagV1:u64, r11=&typed entity id | r10=Option<View> sum handle (typed leaf TLVs) | asset:gas/G_scq@ivm.core/v2 + query items + encoded bytes |
| 0x10002 | CORE_QUERY_PAGE | r10=CoreQueryEntityTagV1:u64, r11=offset:i64 bits, r12=limit:1..=64, r13=nullable AccountId pointer (Asset only; zero for every other tag) | r10=List<View,64> handle, r11=Option<int> sum handle | asset:gas/G_scq@ivm.core/v2 + offset + query items + encoded bytes + (32 + AccountId payload bytes when filtered) |
| 0x10006 | QUERY_GET_PARAMETER | r10=&NoritoBytes(Name) | r10=ptr (&NoritoBytes(Parameter)) | asset:gas/G_scq@ivm.core/v2 |
| 0x10007 | QUERY_GET_CONTRACT_MANIFEST | r10=&NoritoBytes(ContractArtifactId) | r10=ptr (&NoritoBytes(ContractManifest)) | asset:gas/G_scq@ivm.core/v2 |
| 0x10008 | QUERY_GET_CONTRACT_INSTANCE | r10=&NoritoBytes(ContractAddress | Name) | r10=ptr (&NoritoBytes(ContractInstance)) | asset:gas/G_scq@ivm.core/v2 |
| 0x10020 | SYSVAR_CHAIN_ID | - | r10=ptr (&Blob(chain_id)) or 0 | asset:gas/G_sysvar@ivm.core/v2 + bytes |
| 0x10021 | SYSVAR_BLOCK_HEIGHT | - | r10=height:u64 | asset:gas/G_sysvar@ivm.core/v2 |
| 0x10022 | SYSVAR_BLOCK_TIME_MS | - | r10=block_time_ms:u64 | asset:gas/G_sysvar@ivm.core/v2 |
| 0x10023 | SYSVAR_AUTHORITY | - | r10=ptr (&AccountId) | asset:gas/G_get_auth@ivm.core/v2 + bytes |
| 0x10024 | SYSVAR_CONTRACT_ADDRESS | - | r10=&Blob(canonical ContractAddress UTF-8 literal, exactly 60 bytes) or 0 without contract context | asset:gas/G_sysvar@ivm.core/v2 + bytes |
| 0x10025 | SYSVAR_ENTRYPOINT | - | r10=ptr (&Blob(entrypoint)) or 0 | asset:gas/G_sysvar@ivm.core/v2 + bytes |
| 0x10026 | DECODE_ARGUMENT_RECORD | r10=&NoritoBytes(EntrypointArgumentRecordV1), r11=&NoritoBytes(EntrypointArgumentSchemaV1) | r10=aligned owned-HEAP table base (0 if empty), r11=exact word count | asset:gas/G_argument_decode@ivm.core/v2 + record + schema + complete materialization |
| 0x10027 | SYSVAR_CONTRACT_SUBJECT | - | r10=ptr (&AccountId(contract subject)) | asset:gas/G_sysvar@ivm.core/v2 + bytes |
| 0x10028 | NORMALIZE_NORITO_BYTES | r10=&Blob or &NoritoBytes (validated public TLV) | r10=&NoritoBytes(same payload) | asset:gas/G_pointer@ivm.core/v2 + bytes |
| 0x10031 | STATE_HAS | r10=&NoritoBytes(StatePath) | r10=present:u64 | asset:gas/G_state_has@ivm.core/v2 + canonical path frame bytes |
| 0x10032 | STATE_LEN | r10=&NoritoBytes(StatePath) | r10=len:u64, r11=found:u64 | asset:gas/G_state_len@ivm.core/v2 + canonical path frame bytes |
| 0x10033 | STATE_COUNT | r10=&NoritoBytes(StatePath prefix) | r10=total:u64 | asset:gas/G_state_count@ivm.core/v2 + canonical prefix frame bytes + 1 per examined candidate + examined candidate UTF-8 bytes |
| 0x10034 | STATE_MAP_KEY_AT | r10=&NoritoBytes(Vec<StatePath>), r11=&Name(base), r12=index:u64 | r10=ptr (&NoritoBytes(canonical key)) or 0 | asset:gas/G_path@ivm.core/v2 + bytes |
| 0x10035 | STATE_VALUE_ENCODE | r10=&NoritoBytes(StateValueSchemaV1), r11=&[u64], r12=word_count:u64 | r10=ptr (&NoritoBytes(StateValueRecordV1)) | asset:gas/G_state_value@ivm.core/v2 + schema + words + pointers + output |
| 0x10036 | STATE_VALUE_DECODE | r10=&NoritoBytes(StateValueSchemaV1), r11=&NoritoBytes(StateValueRecordV1) | r10=ptr (&Blob(pad:u8 then [u64; word_count])) | asset:gas/G_state_value@ivm.core/v2 + schema + record + pointers + output |
| 0x10037 | STATE_PATH_FROM_NAME | r10=&Name | r10=ptr (&NoritoBytes(StatePath)) | asset:gas/G_path@ivm.core/v2 + bytes |
| 0x10038 | STATE_SCAN | r10=&NoritoBytes(StatePath map), r11=&NoritoBytes(StateCursorV1) or 0, r12=limit(1..64), r13=0, r14=0, r15=0 | r10=&NoritoBytes(Vec<StatePath>), r11=&NoritoBytes(StateCursorV1) or 0, r12=selected, r13=examined | asset:gas/G_state_query@ivm.core/v2 + canonical map and cursor input frame bytes + canonical map schema bytes + instance UTF-8 bytes + 1 per examined candidate + examined physical key UTF-8 bytes + canonical response frame bytes; at most 64 candidate positions, no count or lookahead |
| 0x1004E | JSON_BUILD | r10=&NoritoBytes(JsonConstructionSchemaV1), r11=word_table, r12=word_count | r10=&Json | asset:gas/G_json_build@ivm.core/v2 + schema bytes + source bytes + words + collection elements + encoded bytes |
| 0x10050 | VALUE_ENCODE | r10=&NoritoBytes(EntrypointValueTypeV1), r11=owned public heap table, r12=exact word count | r10=&Blob(EntrypointReturnRecordV1) | 32 + 1 per schema byte + value quote + 1 per encoded output byte |
| 0x10051 | BLOB_CONCAT | r10=&Blob(left), r11=&Blob(right) | r10=&Blob(left || right) | 32 + 2 per combined payload byte |
| 0x10052 | UTF8_VALIDATE | r10=&Blob | r10=same pointer for valid UTF-8, otherwise zero | 32 + 1 per payload byte |
| 0x10053 | VALUE_TO_STRING | r10=&NoritoBytes(scalar EntrypointValueTypeV1), r11=owned public heap table, r12=1 | r10=&Blob(canonical scalar text) | 32 + 1 per schema byte + value quote + 1 per UTF-8 output byte |
| 0x10100 | INT_FROM_I64 | r10=value:i64 | r10=&Int, r11=status:0 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10101 | INT_FROM_U64 | r10=value:u64 | r10=&Int, r11=status:0 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10102 | INT_TO_I64 | r10=&Int, r11=reserved:0, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=value:i64-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10103 | INT_TO_U64 | r10=&Int, r11=reserved:0, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=value:u64-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10104 | INT_NEG | r10=&Int, r11=reserved:0, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10105 | INT_ADD | r10=&Int, r11=&Int, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10106 | INT_SUB | r10=&Int, r11=&Int, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10107 | INT_MUL | r10=&Int, r11=&Int, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10108 | INT_DIV | r10=&Int, r11=&Int, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10109 | INT_REM | r10=&Int, r11=&Int, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1010A | INT_EQ | r10=&Int, r11=&Int | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1010B | INT_NE | r10=&Int, r11=&Int | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1010C | INT_LT | r10=&Int, r11=&Int | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1010D | INT_LE | r10=&Int, r11=&Int | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1010E | INT_GT | r10=&Int, r11=&Int | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1010F | INT_GE | r10=&Int, r11=&Int | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10110 | INT_WRAP_NEG | r10=&Int | r10=&Int | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10111 | INT_WRAP_ADD | r10=&Int, r11=&Int | r10=&Int | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10112 | INT_WRAP_SUB | r10=&Int, r11=&Int | r10=&Int | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10113 | INT_WRAP_MUL | r10=&Int, r11=&Int | r10=&Int | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10114 | INT_ISQRT | r10=&Int, r11=reserved:0, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10115 | INT_ABS | r10=&Int, r11=reserved:0, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10116 | INT_MIN | r10=&Int, r11=&Int, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10117 | INT_MAX | r10=&Int, r11=&Int, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10118 | INT_DIV_CEIL | r10=&Int, r11=&Int, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10119 | INT_GCD | r10=&Int, r11=&Int, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1011A | INT_MEAN | r10=&Int, r11=&Int, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10120 | DECIMAL_FROM_INT | r10=&Int | r10=&Decimal | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10121 | DECIMAL_NEG | r10=&Decimal, r11=reserved:0, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Decimal-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10122 | DECIMAL_ADD | r10=&Decimal, r11=&Decimal, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Decimal-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10123 | DECIMAL_SUB | r10=&Decimal, r11=&Decimal, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Decimal-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10124 | DECIMAL_MUL | r10=&Decimal, r11=&Decimal, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Decimal-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10125 | DECIMAL_DIV_EXACT | r10=&Decimal, r11=&Decimal, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Decimal-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10126 | DECIMAL_DIV_ROUND | r10=&Decimal, r11=&Decimal, r12=&Int(scale:0..28), r13=RoundingModeV1, r14=failure_mode:0..1 | r10=&Decimal-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10127 | DECIMAL_EQ | r10=&Decimal, r11=&Decimal | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10128 | DECIMAL_NE | r10=&Decimal, r11=&Decimal | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10129 | DECIMAL_LT | r10=&Decimal, r11=&Decimal | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1012A | DECIMAL_LE | r10=&Decimal, r11=&Decimal | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1012B | DECIMAL_GT | r10=&Decimal, r11=&Decimal | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1012C | DECIMAL_GE | r10=&Decimal, r11=&Decimal | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1012D | DECIMAL_TO_INT_EXACT | r10=&Decimal, r11=reserved:0, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1012E | DECIMAL_TO_INT_TRUNC | r10=&Decimal | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1012F | DECIMAL_TO_INT_ROUND | r10=&Decimal, r11=reserved:0, r12=reserved:0, r13=RoundingModeV1 | r10=&Int-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10130 | DECIMAL_MUL_DIV_ROUND | r10=&Decimal, r11=&Decimal multiplier, r12=&Decimal divisor, r13=&Int scale, r14=rounding:u64, r15=0 | r10=&Decimal | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10140 | QUANTITY_FROM_INT | r10=&Int, r11=reserved:0, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Quantity-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10141 | QUANTITY_FROM_DECIMAL | r10=&Decimal, r11=reserved:0, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Quantity-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10142 | QUANTITY_TO_DECIMAL | r10=&Quantity | r10=&Decimal | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10143 | QUANTITY_ADD | r10=&Quantity, r11=&Quantity, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Quantity-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10144 | QUANTITY_SUB | r10=&Quantity, r11=&Quantity, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Quantity-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10145 | QUANTITY_MUL_DECIMAL | r10=&Quantity, r11=&Decimal, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Quantity-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10146 | QUANTITY_DIV_DECIMAL_EXACT | r10=&Quantity, r11=&Decimal, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Quantity-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10147 | QUANTITY_DIV_DECIMAL_ROUND | r10=&Quantity, r11=&Decimal, r12=&Int(scale:0..28), r13=RoundingModeV1, r14=failure_mode:0..1 | r10=&Quantity-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10148 | QUANTITY_RATIO_EXACT | r10=&Quantity, r11=&Quantity, r12=reserved:0, r13=reserved:0, r14=failure_mode:0..1 | r10=&Decimal-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10149 | QUANTITY_RATIO_ROUND | r10=&Quantity, r11=&Quantity, r12=&Int(scale:0..28), r13=RoundingModeV1, r14=failure_mode:0..1 | r10=&Decimal-or-zero, r11=NumericFaultV1-or-zero | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1014A | QUANTITY_EQ | r10=&Quantity, r11=&Quantity | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1014B | QUANTITY_NE | r10=&Quantity, r11=&Quantity | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1014C | QUANTITY_LT | r10=&Quantity, r11=&Quantity | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1014D | QUANTITY_LE | r10=&Quantity, r11=&Quantity | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1014E | QUANTITY_GT | r10=&Quantity, r11=&Quantity | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x1014F | QUANTITY_GE | r10=&Quantity, r11=&Quantity | r10=0/1 | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10150 | QUANTITY_MUL_DIV_ROUND | r10=&Quantity, r11=&Decimal multiplier, r12=&Decimal divisor, r13=&Int scale, r14=rounding:u64, r15=0 | r10=&Quantity | asset:gas/G_numeric_staged@ivm.core/v2 |
| 0x10160 | JSON_GET_INT | r10=&Json(object), r11=&Name(key) | r10=Option<&Int> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x10161 | JSON_GET_DECIMAL | r10=&Json(object), r11=&Name(key) | r10=Option<&Decimal> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x10162 | JSON_GET_QUANTITY | r10=&Json(object), r11=&Name(key) | r10=Option<&Quantity> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x10166 | JSON_GET_STRING | r10=&Json(object), r11=&Name(key) | r10=Option<&Blob(UTF-8)> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x10167 | JSON_GET_BOOL | r10=&Json(object), r11=&Name(key) | r10=Option<bool> sum handle | asset:gas/G_json_get@ivm.core/v2 + input bytes + active payload + sum allocation |
| 0x10200 | SET_ASSET_TRANSFER_AVAILABILITY | r10=&AccountId, r11=&AssetDefinitionId, r12=expected_revision:u64, r13=availability_flags:u64 (bit 0 incoming, bit 1 outgoing; reserved bits zero), r14=&Option<string> | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
| 0x10201 | SET_ASSET_TRANSFER_DAILY_LIMIT | r10=&AccountId, r11=&AssetDefinitionId, r12=&Option<Quantity> | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
| 0x10202 | SET_ASSET_HOLDING_LIMIT | r10=&AccountId, r11=&AssetDefinitionId, r12=&Option<Quantity> | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
| 0x10210 | ACCOUNT_RECOVERY_PROPOSE | r10=&Blob(alias), r11=&AccountId(replacement), r12=request_generation | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
| 0x10211 | ACCOUNT_RECOVERY_APPROVE | r10=&Blob(alias), r11=request_generation | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
| 0x10212 | ACCOUNT_RECOVERY_CANCEL | r10=&Blob(alias), r11=request_generation | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
| 0x10213 | ACCOUNT_RECOVERY_FINALIZE | r10=&Blob(alias), r11=request_generation | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
| 0x10220 | ASSET_LOCK_OPEN | r10=owned public 8-word heap table [&Blob(key:1..4096 bytes), &AccountId(source), &AccountId(destination), &AssetDefinitionId, &Quantity, release_until_ms:u64, cancel_not_before_ms:u64, expires_at_ms:u64]; controller=authenticated frame | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
| 0x10221 | ASSET_LOCK_DRAWDOWN | r10=&Blob(key:1..4096 bytes), r11=&Quantity(amount), r12=&Quantity(expected_remaining); controller=authenticated frame | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
| 0x10222 | ASSET_LOCK_CANCEL | r10=&Blob(key:1..4096 bytes), r11=&Quantity(expected_remaining); controller=authenticated frame | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
| 0x10223 | ASSET_LOCK_EXPIRE | r10=&Blob(key:1..4096 bytes); controller=authenticated frame | u64=0 | asset:gas/G_sci@ivm.core/v2 + bytes |
<!-- END GENERATED SYSCALLS -->







































Codec helpers
- 0x56 BUILD_PATH_KEY_NORITO — Args: `r10=&Name(base), r11=&NoritoBytes(key)` → Return: `ptr (&NoritoBytes(StatePath))` — Gas: G_path + bytes
  - Compiler-internal schema-bound helper. The base must name exactly one CNTR-declared `StateMap`; the key must be the unique canonical encoding of that map's nominal key type. It produces the distinct nominal storage path `base/<lowercase hex of canonical key bytes>`, rejects missing schemas, type confusion, malformed/noncanonical frames, and keys larger than 4 KiB. The exact suffix is reversible and lexicographic path order equals unsigned canonical-byte order.
- 0x57 JSON_ENCODE — Args: `r10=&Json` → Return: `ptr (&NoritoBytes(Json))` — Gas: G_json_encode + bytes
- 0x58 JSON_DECODE — Args: `r10=&NoritoBytes(Json)` → Return: `ptr (&Json)` — Gas: G_json_decode + bytes
- JSON_DECODE rejects already-typed `Json` and raw/framed `Blob` carriers; callers use JSON_ENCODE/JSON_DECODE for the canonical typed conversion pair.
- 0x59 SCHEMA_ENCODE — Args: `r10=&Name(schema), r11=&Json` → Return: `ptr (&NoritoBytes)` — Gas: G_schema + bytes
- 0x5A SCHEMA_DECODE — Args: `r10=&Name(schema), r11=&NoritoBytes(Json)` → Return: `ptr (&Json)` — Gas: G_schema + bytes
- 0x5B SCHEMA_INFO — Args: `r10=&Name(schema)` → Return: `ptr (&Json{"id":...,"version":...})` — Gas: G_schema + bytes
- 0x5F TLV_EQ — Args: `r10=&Tlv, r11=&Tlv` → Return: `r10=1 if equal else 0` — Gas: G_tlv_eq + bytes
  - Compares TLV type, version, and payload bytes exactly. Gas charges the fixed compare base plus the payload bytes inspected.
- 0x77 TLV_LEN — Args: `r10=&Tlv` → Return: `r10=payload_len` — Gas: G_tlv_len + bytes
  - Returns the TLV payload byte length after pointer-ABI validation. Gas charges the fixed length-read base plus the payload bytes inspected.
- 0x5C NAME_DECODE — Args: `r10=&NoritoBytes(Name)` → Return: `ptr (&Name)` — Gas: G_name_decode + bytes
- NAME_DECODE requires the canonical Norito `Name` frame; raw UTF-8, framed `String`, and alternate-layout frames are rejected.
- 0x5D POINTER_TO_NORITO — Args: `r10=&PointerType<T>` → Return: `ptr (&NoritoBytes(TLV envelope))` — Gas: G_pointer + bytes
  - Copies the canonical pointer-ABI TLV envelope into a NoritoBytes payload, validating Int, Decimal, and Quantity frames before publication. Gas charges the fixed conversion base plus the envelope bytes copied.
- 0x5E POINTER_FROM_NORITO — Args: `r10=&NoritoBytes(TLV envelope), r11=expected?:u16` → Return: `ptr (&PointerType<T>)` — Gas: G_pointer + bytes
- POINTER_FROM_NORITO accepts only the canonical `NoritoBytes` carrier; a `Blob` containing the same inner envelope is a nominal type error.
  - Validates the embedded canonical TLV envelope, optionally checks the expected type id, and rehydrates the pointer. Numeric frames must be canonical and within their nominal V1 domains. Expected numeric types (Int, Decimal, Quantity) reject null. Gas charges the fixed conversion base plus the envelope bytes inspected.
- Null inputs: JSON_DECODE and NAME_DECODE accept `r10=0` and return `r10=0`. POINTER_FROM_NORITO rejects null when the expected type is Int, Decimal, or Quantity; other generic pointer decodes return null.
- All other pointer-typed syscalls require explicit non-zero pointers; there is no implicit last-input fallback.
ZK (Halo2 OpenVerify)
- 0x64 ZK_VERIFY_BATCH — Args: `r10=&NoritoBytes(Vec<iroha_data_model::zk::OpenVerifyEnvelope>)` → Return: `r10=ptr (&NoritoBytes(Vec<u8> statuses))`, `r11=status:u64`, `r12=first_fail_index|u64::MAX` — Gas: configured V1 proof + public-input-unit + encoded request/response byte schedule; 1 MiB encoded-payload and 16-proof hard caps
  - `DefaultHost` has no proof backend. After canonical validation it returns one failure status byte (`0`) per item, `r11=ERR_BACKEND`, and `r12=0`; it never reports a proof as verified.
  - `CoreHost` returns the same status-vector shape and runs the same outer-envelope binding plus full backend verification path as the single-item ZK verify syscalls.
  - Top-level request failures (decode, disabled backend, oversized batch) return `r10=0` and set `r11` (`ERR_DECODE`, `ERR_DISABLED`, `ERR_BACKEND`, `ERR_BATCH`).
  - On vector return, `r11` carries the first observed precheck/verify error code (or `0` when all succeed).
