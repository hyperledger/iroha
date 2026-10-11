# ZK Envelopes (Norito)

This page specifies Norito-encoded envelopes used by native verifiers in the
Iroha 3 codebase. Envelopes are versioned, deterministic, and designed to be
portable between components (clients, IVM, node).

Scope (current)
- Generic ledger proof verification uses the data-model `OpenVerifyEnvelope`,
  with native PIPA-R over Pasta or the exact native STARK profile below.
- The separate `iroha_zkp_halo2::OpenVerifyEnvelope` is a standalone public
  polynomial-opening type used by diagnostic APIs. Its curve selector does not
  select a generic ledger verifier.
- Protocol-specific privacy proofs retain their typed owners and are not
  inferred from a generic engine label.

Backends (exact registry labels)
- `pipa-r/pasta`, or one of the five concrete native circuit labels listed in
  `iroha_data_model::zk::ZK_VERIFIER_BACKEND_REGISTRY_LABELS_V1`.
- `stark/fri/poseidon-x7-goldilocks-6x64-v1`.
- Data-model `BackendTag` has only `NativePipaRPasta` (Norito discriminant 0,
  JSON `native-pipa-r-pasta`) and `Stark` (discriminant 1, JSON `stark`).
  The derived Norito enum discriminant occupies a little-endian `u32`.

General notes
- Norito encoding is used for the envelopes and their nested payloads. Unless
  otherwise specified, scalars are little-endian and sized as per struct types.
- Determinism: challenges are derived from fixed transcript labels and byte
  sequences; native STARK hashing uses the single six-lane construction below
  the standalone polynomial-opening helper uses SHA3, and native PIPA-R uses
  its descriptor-pinned transcript.
- Size limits and validation: implementers must bound vector sizes and reject
  malformed payloads early (see code for current limits). The native verifier
  applies `StarkVerifierLimits` (envelope byte budget, domain/tag length, fold
  arity, queries, Merkle depth, auxiliary terms) inside
  `verify_stark_fri_envelope_with_limits`, with defaults used by the standard
  `verify_stark_fri_envelope` entrypoint.

## Standalone IPA: Polynomial Opening Envelope

Wire types (as implemented in `crates/iroha_zkp_halo2`)

- `IpaParams` (canonical transparent-parameter selector)
  - `version: u16` — format version, currently 1
  - `curve_id: u16` — backend identifier (`1 = Pallas`, `2 = Goldilocks`, `20 = BN254`)
  - `n: u32` — vector length (power of two)

  Generator vectors are not part of the wire format. V1 defines exactly one
  transparent parameter set for each `(curve_id, n)`. For the production Pallas
  (Vesta commitment group) and BN254 backends, every point is independently
  derived with the backend's `CurveExt::hash_to_curve` map under
  `IROHA-ZK-HALO2-IPA-v1-generator`. The mapped message is
  `dst || 0x00 || u64_le(kind_len) || kind || u64_le(n) || u64_le(i)`, where
  `kind` is `G`, `H`, or `U`. If the map ever returns the identity, derivation
  retries with `message || 0xff || u64_le(counter)`, starting at counter 1. This
  prevents a prover from choosing bases or
  learning discrete-log relationships between them and avoids transmitting
  `O(n)` redundant point encodings. Goldilocks is a STARK field and does not
  select an IPA commitment group. Its field identifier (`2`) is unconditionally
  rejected by IPA decoding; no algebraic test backend or feature is shipped.

- `IpaProofData`
  - `version: u16` — format version, currently 1
  - `l: Vec<[u8; 32]>` — per-round L commitments (compressed curve points)
  - `r: Vec<[u8; 32]>` — per-round R commitments
  - `a_final: [u8; 32]` — final reduced scalar for witness vector
  - `b_final: [u8; 32]` — final reduced scalar for public vector

- The standalone polynomial commitment and opening are deterministic and
  unblinded. Their coefficients belong in public storage. They establish the
  stated evaluation only; this envelope is not a confidential application proof.

- `PolyOpenPublic`
  - `version: u16` — format version, currently 1
  - `curve_id: u16` — backend identifier
  - `n: u32` — vector length
  - `z: [u8; 32]` — evaluation point (canonical field encoding)
  - `t: [u8; 32]` — claimed evaluation f(z)
  - `p_g: [u8; 32]` — commitment to coefficients under `g`

- `OpenVerifyEnvelope`
  - `params: IpaParams`
  - `public: PolyOpenPublic`
  - `proof: IpaProofData`
  - `transcript_label: String` — bound by both prover and verifier
  - `vk_commitment: Option<[u8; 32]>` — optional outer VK commitment bound into the transcript
  - `public_inputs_schema_hash: Option<[u8; 32]>` — optional schema hash bound into the transcript
  - `domain_tag: Option<[u8; 32]>` — optional caller-defined domain separator bound into the transcript

Verifier behavior (native IPA)
- Re-derives the public vector b = [1, z, z^2, …, z^{n-1}].
- Derives the canonical `g`, `h`, and `u` generators from the advertised curve
  and `n`; there is no wire representation for alternate bases.
- Binds the claimed statement before the first Fiat-Shamir challenge:
  `transcript_label`, backend/`n`, the complete derived parameter fingerprint,
  `z`, `t`, `p_g`, and any present optional metadata fields (`vk_commitment`,
  `public_inputs_schema_hash`, `domain_tag`).
- Replays transcript rounds to fold generators and update Q.
- Checks the final relation holds with `(a_final, b_final)`.
- Deterministic transcript over SHA3-256 under crate-defined DST.
- Batch helpers: `iroha_zkp_halo2::batch::verify_open_batch` verifies multiple
  envelopes with default settings, while
  `verify_open_batch_with_options` accepts `BatchOptions` to force sequential
  execution or cap rayon parallelism via `Parallelism::{Sequential, Auto, Limited}`.

Example (Rust)
```rust
use iroha_zkp_halo2::{
    Params, PolyOpenTranscriptMetadata, Polynomial, PrimeField64, Transcript,
    norito_helpers as nh,
};
let n = 8; let params = Params::new(n).unwrap();
let coeffs = (0..n).map(|i| PrimeField64::from((i+1) as u64)).collect();
let poly = Polynomial::from_coeffs(coeffs);
let p_g = poly.commit(&params).unwrap();
let z = PrimeField64::from(3u64);
let mut tr = Transcript::new("IROHA-TEST-IPA");
let metadata = PolyOpenTranscriptMetadata {
    vk_commitment: Some([0x11; 32]),
    public_inputs_schema_hash: Some([0x22; 32]),
    domain_tag: Some([0x33; 32]),
};
let (proof, t) = poly.open_with_metadata(&params, &mut tr, z, p_g, metadata).unwrap();
let env = iroha_zkp_halo2::OpenVerifyEnvelope {
    params: nh::params_to_wire(&params),
    public: nh::poly_open_public::<iroha_zkp_halo2::backend::pallas::PallasBackend>(
        n,
        z,
        t,
        p_g,
    ),
    proof: nh::proof_to_wire(&proof),
    transcript_label: "IROHA-TEST-IPA".into(),
    vk_commitment: metadata.vk_commitment,
    public_inputs_schema_hash: metadata.public_inputs_schema_hash,
    domain_tag: metadata.domain_tag,
};
let bytes = norito::to_bytes(&env).unwrap();
```

Example (JSON-like, annotated)
```jsonc
{
  // OpenVerifyEnvelope
  "params": {
    "version": 1,
    "curve_id": 1,           // backend (Pallas)
    "n": 8                   // selects the canonical derived generators
  },
  "public": {
    "version": 1,
    "curve_id": 1,
    "n": 8,
    "z": "0x...",           // evaluation point encoding
    "t": "0x...",           // claimed evaluation f(z)
    "p_g": "0x..."          // commitment encoding
  },
  "proof": {
    "version": 1,
    "l": ["0x...", "0x..."], // per-round L commitments
    "r": ["0x...", "0x..."],
    "a_final": "0x...",
    "b_final": "0x..."
  },
  "transcript_label": "IROHA-TEST-IPA",
  "vk_commitment": "0x...",             // optional, null when omitted
  "public_inputs_schema_hash": "0x...", // optional, null when omitted
  "domain_tag": "0x..."                 // optional, null when omitted
}
```

## STARK: FRI-Style Multi-Fold Envelope

Hashing and transcript
- Every leaf, node, root, public-statement commitment, query draw, and FRI
  challenge uses `GoldilocksDigest384V1`: six independently parameterized
  Poseidon-x7 lanes over `p = 2^64 - 2^32 + 1`, each with width 3, rate 2,
  capacity 1, 8 full rounds, and 57 partial rounds.
- Bytes use canonical seven-byte field packing with explicit length
  termination. A digest is encoded as six canonical little-endian Goldilocks
  words (48 bytes); words greater than or equal to `p` are rejected.
- Every invocation binds the Exact12 catalog commitment and typed protocol,
  profile, tree-role, transcript-phase, level, index, lane, and counter domains.
  Merkle roles distinguish FRI layers, AIR trace rows, AIR composition values,
  and auxiliary composition values.
- Per-layer challenges take four independent digest lanes as the coefficients
  of `Fp4 = Fp[U]/(U^4 - 7)`. Query-index draws use canonical rejection
  sampling and bind the label, selector-free parameters, query ordinal, retry
  counter, and all relevant roots.
- There is no hash selector or alternate native-STARK decoder. Pre-release
  selector-bearing parameter, verifier-key, proof, and envelope bytes fail
  canonical V1 decoding.

Wire types (as implemented in `iroha_core_zk::stark`)

- `StarkFriParamsV1`
  - `version: u16` — format version, currently 1
  - `n_log2: u8` — log2 of evaluation domain size
  - `blowup_log2: u8` — log2 blowup before FRI folding (e.g., 3 for 8×)
  - `fold_arity: u8` — exactly 2 for the sole V1 binary FRI profile
  - `queries: u16` — expected query count (must match `proof.queries.len()`)
  - `merkle_arity: u8` — Merkle branching factor (binary only in v1)
  - `domain_tag: String` — domain separator baked into the transcript/sampler

- `MerklePath`
  - `dirs: Vec<u8>` — direction bits (packed, low bit = lowest level)
  - `siblings: Vec<GoldilocksDigest384V1>` — 48-byte sibling digests from leaf to root

- `StarkCommitmentsV1`
  - `version: u16`
  - `roots: Vec<GoldilocksDigest384V1>` — 48-byte Fp4 FRI layer roots from 0…L
  - `comp_root: Option<GoldilocksDigest384V1>` — optional typed Merkle root over auxiliary composition leaves

- `FoldDecommitV1`
  - `j: u32` — index at this layer
  - `y0: GoldilocksFp4V1`, `y1: GoldilocksFp4V1` — four canonical
    little-endian Goldilocks coefficients for inputs at positions `(2*j, 2*j+1)`;
    each payload is exactly 32 bytes without an inner struct frame. The shared
    FASTPQ field codec rejects any coefficient greater than or equal to `p`.
  - `path_y0: MerklePath`, `path_y1: MerklePath`
  - `z: GoldilocksFp4V1` — domain-aware binary FRI fold
    `(y0 + y1)/2 + r_k * (y0 - y1)/(2x)`, where `x` is the domain element for
    the opened `(x, -x)` pair
  - `path_z: MerklePath` — Merkle path for `z` under `roots[k+1]`

- `StarkProofV1`
  - `version: u16`
  - `commits: StarkCommitmentsV1`
  - `queries: Vec<Vec<FoldDecommitV1>>` — one chain per query
  - `comp_values: Option<Vec<StarkCompositionValueV1>>` — optional composition leaves

- `StarkCompositionValueV1`
  - `leaf: u64` — Merkle leaf recorded under `comp_root`
  - `constant: u64` — constant term
  - `z_coeff: u64` — coefficient applied to the final folded `z`
  - `aux_terms: Vec<StarkCompositionTermV1>` — additional wire/value contributions
  - `path: MerklePath` — inclusion proof under `comp_root`

- `StarkCompositionTermV1`
  - `wire_index: u32` — caller-defined wire ordering (must be strictly increasing)
  - `value: u64` — auxiliary value contributed by this wire
  - `coeff: u64` — coefficient multiplied with the value

- `StarkVerifyEnvelopeV1`
  - `params: StarkFriParamsV1`
  - `proof: StarkProofV1`
  - `transcript_label: String`

Limits and validation
- Bounds enforced by the raw native verifier: `1 ≤ n_log2 ≤ 24`, `queries ≤ 64`,
  `layers ≤ 32`, `merkle depth ≤ 32`, `aux_terms ≤ 64`, `domain_tag` length ≤
  96 bytes (the full lowercase-hex encoding of a six-lane statement digest). `merkle_arity` and `fold_arity` must both be `2`. Canonical ledger
  verifier keys require blowup 8 and at least 64 queries; the current exact
  profile fixes the verifier maximum to the same 64-query value.
- Query sampling and per-round challenges are domain-separated by `domain_tag`,
  the fixed profile, blowup, fold arity, query count, typed phases, and roots;
  mismatched headers or roots are rejected.
- Bad roots, broken Merkle paths, tampered folds, non-canonical field encodings, and
  query-count/profile mismatches are covered by `iroha_core_zk::stark` regression tests.

Verifier behavior (native STARK)
- For each query, replays all folds:
  - Verifies `y0`, `y1` Merkle openings under `roots[k]` and `z` under `roots[k+1]`.
  - Treats each layer as bit-reversed evaluation order, derives `x` from the
    bit-reversed pair index, and checks
    `z == (y0 + y1)/2 + r_k * (y0 - y1)/(2x)` in the field.
  - Authenticates the final folded value under the terminal root and requires
    it to be the zero Fp4 element.
- If `comp_root` is present on a raw generic STARK envelope, verifies the
  composition leaf/path and checks it matches
  `constant + z_coeff * z_final + Σ coeff_i * value_i`. Auxiliary terms must appear
  in strictly increasing `wire_index` order.
- For the V1 verifier-owned binding AIR, compares every coordinate of each
  transcript-sampled current/next row with the deterministic row derived from
  the bound public digest. Public residuals are not compressed with fixed
  coefficients. The verifier also reconstructs the canonical full-domain trace
  root with a streaming Merkle accumulator and requires exact equality. It also
  reconstructs and exactly matches the Merkle root of the all-zero composition
  vector. Generic binding domains are therefore capped at `n_log2 = 12`;
  larger binding proofs and verifying keys fail closed. Explicit full-material
  AIR verification instead recomputes both roots from every supplied row and
  composition value. This generic binding path is not an IVM execution proof;
  private profiles still require a separately qualified degree argument.
- `OpenVerifyEnvelope` STARK verification rejects inner `comp_root`/`comp_values`
  sidecars. The high-level verifier reconstructs the V1 binding-AIR digest from
  backend, circuit id, VK hash, schema descriptor, and public input columns.
  The former dedicated IVM binding context is retired. Generic binding
  verification rejects reserved IVM circuits, and `IvmProved` admission is
  closed until a complete native execution relation is qualified.
  ZK-ACE uses its dedicated typed `SubmitPrivacyProofV1` relation and DEEP/FRI
  verifier; generic Binding AIR cannot target that relation. Local ZK-ACE proving
  and verification are implemented, while governed production activation remains
  unavailable pending independent cryptographic qualification.
- Validation: query indices derive from the transcript label + params + roots; the verifier
  rejects mismatched `j`, missing folds, bad roots/paths, non-canonical field encodings,
  selector-bearing retired layouts, and mismatched query-count headers. Depth/size caps
  guard against oversized envelopes.

	Example (Rust)
	```rust
		use iroha_core_zk::stark::*;
		let n_log2 = 3u8; // domain size 8
		// Build layers 0..L (y0/y1 folds) and Merkle roots/paths externally
		let env = StarkVerifyEnvelopeV1 { /* fill params, proof, transcript */ };
		let bytes = norito::to_bytes(&env).unwrap();
		// Verify the raw envelope bytes with `verify_stark_fri_envelope(&bytes)`.
		// Note: `verify_backend(\"stark/fri/*\", ...)` expects a Norito `OpenVerifyEnvelope` wrapper.
		```

	STARK via `OpenVerifyEnvelope` (consensus / `verify_backend`)
	- `ProofBox.bytes` (outer payload): Norito `OpenVerifyEnvelope` with:
	  - `backend = BackendTag::Stark`
	  - `circuit_id = "stark/fri/<profile>:<circuit>"` (application-level identifier)
	  - The only profile is `poseidon-x7-goldilocks-6x64-v1`. Generic admission requires the exact backend-prefixed colon form with a nonempty portable circuit suffix. Bare, slash-separated and whitespace-padded forms are rejected.
	  - Registry circuit IDs, verifier-key payload IDs, envelope IDs and native AIR IDs compare byte-for-byte; the key cache retains that exact identity. No normalization or alias lookup occurs.
	  - Typed BFV and Soracloud keys retain their exact protocol-owned bare IDs and dedicated native verifier contracts. Profile-prefixed copies of those typed registry IDs are rejected even if their record and key payload agree. Typed keys confer no generic OpenVerify admission. A typed Soracloud binding AIR uses the exact profile-qualified projection of its already validated protocol ID, with no normalization of proof bytes.
	  - `vk_hash = sha256("iroha:zk:v1:vk" || len(backend) || backend || len(vk_bytes) || vk_bytes)`
	  - `public_inputs = schema descriptor bytes` (stable policy-defined layout commitment)
	  - `proof_bytes = norito(StarkFriOpenProofV1 { version, public_inputs, envelope_bytes })`
	- `StarkFriOpenProofV1.public_inputs` carries the concrete public input values
	  (column-major 32-byte words) used for circuit/policy checks.
	- `StarkFriOpenProofV1.envelope_bytes` (inner payload): Norito `StarkVerifyEnvelopeV1`
	- `VerifyingKeyBox.bytes` (for `stark/fri/*`): Norito `StarkFriVerifyingKeyV1`
	  containing the expected `circuit_id` and the FRI parameter set (`n_log2`, `blowup_log2`,
	  `fold_arity`, `queries`, `merkle_arity`).
	  `VerifyingKeyBox.backend` must exactly match the `ProofBox.backend` /
	  `verify_backend` label.
	  Consensus `verify_backend("stark/fri/*", ...)` admission requires this payload
	  to satisfy the canonical admission FRI floors; smaller domain/query
	  settings are rejected before wrapper verification.
- The verifier enforces that the outer wrapper metadata is bound into the inner STARK
  envelope (via `domain_tag`), that the inner envelope parameters match the VK payload,
  that the transcript label is exactly `IROHA-STARK-AIR-V1`, and that the AIR
  public digest matches the verifier-reconstructed generic binding statement.
- Runtime STARK guardrails require the outer `OpenVerifyEnvelope`, decode
  `StarkFriOpenProofV1` before verifier dispatch, and reject malformed outer or
  wrapper bytes, unsupported wrapper versions, and empty native STARK envelope
  bytes with zero-duration failures.
- Generic guardrails reject mismatched `ProofBox.backend`, `VerifyingKeyBox.backend`
  and decoded engine tags before proof work. The native registry resolves an
  exact generic/backend-and-circuit pair. It admits only Kaigi authorization,
  Kaigi usage, confidential transfer, full unshield and change unshield.
  Demo arithmetic, governance stand-ins and incomplete IVM execution relations
  have no generic verifier admission.
- Native `ProofBox.bytes` is the canonical data-model `OpenVerifyEnvelope`.
  `public_inputs` holds the exact compiled relation's schema descriptor;
  `proof_bytes` is canonical Norito `NativePipaRProofV1` with ordered
  `public_inputs: Vec<[u8; 32]>` and `proof: Vec<u8>`. These are one public
  column, canonical little-endian Pasta scalars, and the exact PIPA-R
  transcript. The compiled relation pins the column arity and proof length.
  Auxiliary bytes must be empty. No retired TLV or old-key decoder is present.
- Native `VerifyingKeyBox.bytes` is canonical Norito
  `iroha_core_zk::native_pipa_r::CompiledVerifyingKeyV1`, containing
  `descriptor: Vec<u8>` and `key: Vec<u8>`. Both must match the locally compiled
  relation exactly, with a 64 KiB whole-container ceiling before material
  construction. The descriptor binds the typed schema, transcript, parameters
  and compiled layout; a processed key alone cannot substitute for it.
- `verify_for_relation` checks the caller-required relation before cryptographic
  verification. Active registry status, application public inputs, permissions,
  finalized state and replay checks remain mandatory at the consuming owner.
  Verification success alone authorizes no monetary or execution effect.
- Kaigi commitment, nullifier and usage `Hash` artifacts encode a canonical
  Pasta Fp scalar injectively: byte 31's seven used bits are shifted left once
  and bit 0 is set as Iroha's `Hash` marker. Decoding reverses that shift and
  requires canonical `Fp::from_repr`. Native authorization binds the current
  call, subject, role and sequence; usage binds call, host, segment and billing.
  See [Kaigi privacy](kaigi_privacy_design.md) for the relation and lifecycle boundary.
- STARK `OpenVerifyEnvelope` construction, preverification, and guardrails bind
  circuit ids to the selected STARK family as well: the generic `stark/fri`
  entry point rejects circuit ids that advertise another proof family, including
  slash and colon forms such as `halo2/...`, `halo2:...`, and `kzg:...`;
  trusted-setup aliases such as `bn254`, `bls12_381`, `universal-srs`, and
  profile-prefixed `stark/fri/<profile>:structured-reference-string`; and
  profile-specific STARK backends reject decoded circuit ids that advertise a
  different STARK profile or the generic `stark/fri:` prefix.
- Generic STARK `OpenVerifyEnvelope` construction and verification reserve the
  ZK-ACE and BFV full-bootstrap circuit ids for their dedicated verifier paths. BFV
  full-bootstrap native AIR proofs must use the BFV-specific full-material
  verifier path. The public-padding-only entry points reject unconditionally:
  sampled public rows do not establish low degree for hidden trace columns.
  The canonical BFV arithmetic trace has 38 Goldilocks columns. Columns 5–12
  encode the complete 32-byte statement hash as eight little-endian `u32`
  words, each injected into the field without modular reduction. The former
  four-`u64` modulo-field packing was non-injective and is not a first-release
  layout. The trace profile, AIR contract, proof-key digests, and two-slot
  conformance fixture bind this exact layout.
  Generic preverification rejects metadata-valid OpenVerify wrappers that
  advertise either reserved circuit id, including backend-prefixed colon/slash
  spellings, before deduplication. The canonical ZK-ACE id is accepted only by
  the dedicated typed privacy relation. The BFV
  wrapper accepts only the base native AIR transcript label or canonical
  unpadded retry suffixes emitted by the prover, and rejects generic
  `comp_root`/`comp_values` sidecars instead of accepting auxiliary composition
  commitments on top of the verifier-reconstructed arithmetic trace. Malformed
  BFV proof/commitment version tags, missing or foreign AIR sections, root
  drift, query/opening count drift, duplicate openings, opened row/path drift,
  FRI base-value drift, STARK parameter-profile drift, and caller-supplied
  verifier-limit violations fail before native BFV acceptance. The governed
  full-material verifier performs the public structural checks, then
  reconstructs and exactly matches the complete trace and composition roots.
  Soracloud preflight authenticates the base-field AIR composition tree in its
  own Merkle domain. Fp4 FRI layer roots use distinct domains; their connection
  to the AIR is the authenticated equality of each initial FRI opening and its
  AIR composition evaluation, with zero extension coefficients. Substituting
  either tree's root for the other fails its domain-specific authentication. A
  valid envelope also cannot be replayed with stale BFV prover-input material,
  including layout metadata, trace/AIR digests, trace rows, composition values,
  or prover/verifier proof-key roles.

	Example (JSON-like, annotated)
	```jsonc
	{
  // StarkVerifyEnvelopeV1
  "params": {
    "version": 1,
    "n_log2": 6,             // domain size 64
    "blowup_log2": 3,        // blowup factor 8×
    "fold_arity": 2,         // binary FRI folds
    "queries": 64,           // fixed production query count
    "merkle_arity": 2,       // binary Merkle trees
    "domain_tag": "fastpq:v1:fri"
  },
  "proof": {
    "version": 1,
    "commits": {
      "version": 1,
      "roots": [
        "0xroot_l0...",    // layer-0 root (trace)
        "0xroot_l1...",    // layer-1 root (folded)
        "0xroot_l2..."     // layer-2 root (final)
      ],
      "comp_root": "0xcomproot..." // optional composition root (final layer)
    },
    "queries": [
      [ // query 0 chain (layers 0->1->2)
        {
          "j": 0,
          "y0": { "c0": 5, "c1": 1, "c2": 2, "c3": 3 },
          "y1": { "c0": 8, "c1": 4, "c2": 5, "c3": 6 },
          "path_y0": { "dirs": "AA==", "siblings": ["0xsib0...", "0xsib1..."] },
          "path_y1": { "dirs": "AA==", "siblings": ["0xsib0...", "0xsib1..."] },
          "z": { "c0": 29, "c1": 7, "c2": 11, "c3": 13 },
          "path_z": { "dirs": "AA==", "siblings": ["0xsib0..."] }
        },
        {
          "j": 0,
          "y0": { "c0": 29, "c1": 7, "c2": 11, "c3": 13 },
          "y1": { "c0": 42, "c1": 17, "c2": 19, "c3": 23 },
          "path_y0": { "dirs": "AA==", "siblings": ["0xsib0..."] },
          "path_y1": { "dirs": "AA==", "siblings": ["0xsib0..."] },
          "z": { "c0": 113, "c1": 31, "c2": 37, "c3": 41 },
          "path_z": { "dirs": "AA==", "siblings": [] }
        }
      ]
    ],
    "comp_values": [
      // Composition leaf: constant + z_coeff * z_final + Σ coeff_i * value_i
      {
        "leaf": 227,             // composition leaf at final layer index
        "constant": 7,           // c
        "z_coeff": 2,            // a0 applied to z_final
        "aux_terms": [
          { "wire_index": 0, "value": 90, "coeff": 3 },
          { "wire_index": 1, "value": 42, "coeff": 5 }
        ],
        "path": { "dirs": "", "siblings": [] } // Merkle path into comp_root (single-leaf example)
      }
    ]
  },
  "transcript_label": "TEST-STARK"
}
```

- All structs carry the first-release `version = 1`. There is no compatibility
  decoder: changing the V1 layout requires regenerating fixtures, and retired
  pre-release bytes remain invalid.
- Query indices are derived deterministically from the transcript label, parameters,
  and commitment roots; the verifier recomputes the index and rejects envelopes whose
  payload `j` values do not match the derived result.

### Governance vote circuits

The first-release native PIPA-R registry does not admit the historical
`VoteBoolCommitMerkle` family. Those circuits were test fixtures with a toy
compressor, and one verifier key was previously reinterpreted as both the
`vote-ballot` and `vote-tally` role. Governance now requires exact, distinct
role identifiers; the retired Halo2 labels fail key registration, proof
attachment, preverification, and native dispatch. A future native governance
design must introduce independently reviewed semantic ballot and tally
circuits and add their exact identifiers to the closed registry.
