# Engineering Backlog (Detailed Open Work)

Last updated: 2026-09-29

The public roadmap lives in [`../roadmap.md`](../roadmap.md). Completed
history lives in [`../status.md`](../status.md). This file should only
track detailed unfinished engineering work.

The 2026-07-05 BFV crypto production-readiness hardening tranche is complete:
the remaining wrapper-order follow-up is closed, the targeted BFV regressions
are green, and no new open backlog item was added for that pass.

## Multilane localnet default-soak refresh

The cross-dataspace route-probe corridor now has fresh evidence for ownership,
committed-lane QC, and applied certified-row gates. The successful-swap balance
gate now queries lane client sets, and committed transaction history now
requires matching lane-quorum outcomes before it is treated as authoritative.
Proposal planning now defers lanes with unapplied artifacts/certified blocks,
Kura can rebuild missing lane-block artifact sidecars from local canonical block
bodies, and lane-payload ownership status preserves unrelated lanes by
lane/dataspace upsert. The remaining open work is the DvP lane-block
application liveness gap: under the 13-peer global localnet (twelve lane
validators), route probes can still
stall before committed/applied lane-block convergence, with one DS lane split
between executable-payload wait and canonical application while the other DS
lane has no committed lane-block row. The default 10-iteration soak must be
refreshed only after that Kura/history vs WSV application boundary is closed;
the last default run before the quorum-history hardening exited `ok` with only
3/10 soak iterations passing, so it remains a stress signal rather than release
evidence.

## FHE/RAM-LFE first-release follow-ups

- Replace the current deterministic plaintext-modulus-multiple BFV-shaped
  evaluator with the full BFV-RNS engine planned for release: bounded RLWE
  noise, RNS modulus chains, real relinearization, packed-slot Galois-key
  switching, and full BFV bootstrapping. The current pass makes Torii/Soracloud consume and
  persist real ciphertext envelopes, evaluates `SelectEqZero` correctly over
  all byte values in the `F_257` RAM-LFE profile, and keeps evaluators
  secret-key free. BFV key generation, relinearization-key generation, and
  encryption now use deterministic error polynomials sampled from
  `{0, t, -t}` modulo the ciphertext modulus so exact coefficient-wise
  plaintext decoding remains stable while zero-error ciphertexts are no longer
  emitted. Exact and bounded seeded encryption also resample inert all-zero
  ternary ephemeral masks before deriving ciphertext components, covering
  caller-chosen seeds that would otherwise drop the public-key term. Exact and
  bounded key generation plus key-switch entry generation also resample inert
  all-zero public `a` limbs, and shared key-switch validators reject all-zero
  public `b` or `a` entry components before material can be digested or used.
  Bounded keygen, encryption, Galois keygen, bootstrap refresh-round seed
  derivation, and full-bootstrap sample-extraction switch-key derivation now use
  exact/bounded mode-separated deterministic RNG streams so same-seed artifacts
  do not reuse public limbs, ephemeral masks, or refresh-round seeds across
  modes, including same-public-key exact/bounded bootstrap refresh derivations
  that are accepted only by their matching transcript validators, transcript
  digests, and transcript-bound proof statements; crypto regressions now pin
  the bootstrap round seed preimage to `domain || key_id || max_rounds || seed
  || round_index` and prove it is distinct from rotation seed derivation. The
  Soracloud bootstrap-key proof public-input schema now advertises those
  exact/bounded rotation and bootstrap refresh-round seed-derivation domains,
  with its regression parsing seed-domain, statement-domain,
  refresh-transcript-domain, refresh-material, and proof-statement-material
  objects and binding their fields to the authoritative `iroha_crypto`
  constants. The full-bootstrap material/execution schema regressions also
  parse proof-key commitment-domain objects and bind material/pair fields to
  the same crypto constants, and structurally parse release-audit evidence,
  signoff, record, manifest, and package metadata so
  versions, field counts, digest domains, manifest scope, reviewer-id bounds,
  and audit byte bounds stay tied to crypto constants. The execution schema
  regression now also parses the execution witness, arithmetic trace, arithmetic
  AIR, native AIR envelope, artifact bundle, and release-prover input sections
  so row-shape constants, composition challenge layout, and verifier-obligation
  flags stay tied to `iroha_crypto`; the material schema regression parses
  `material_proof_input` so its proof-input material layout and required
  material/artifact/statement obligations are structurally pinned too. The
  input-admission and public-key schema regressions now parse their small
  bound/domain/material objects so exact/bounded proof domains and statement
  material layouts stay tied to the same constants. The typed crypto proof
  public-input schema artifact now carries the same release-prover digest-domain
  labels, proof-key material/pair commitment domains, and explicit
  separated-domain flags, with adversarial validation rejecting
  placeholder/canonical drift before those domains can diverge from the
  Soracloud execution schema. Release-audit proof-profile records now mirror
  those release-prover digest-domain and proof-key commitment-domain labels,
  advertise field count `58`, and reject stale, placeholder, or non-separated
  domain metadata before release evidence can be digested or accepted.
  Parameter validation now also requires enough ciphertext-modulus
  headroom to keep the configured positive and negative plaintext-multiple
  error representatives distinct. Secret-key diagnostics now expose the exact
  centered residual multiples and remaining centered-modulus headroom for the
  current plaintext-lift evaluator, without treating that diagnostic as a full
  bounded-RLWE noise budget. BFV key generation now self-checks freshly
  generated public keys by verifying that `b + a*s` is a plaintext-modulus
  multiple within the current exact evaluator error bound, and checks generated
  relinearization entries against scaled `s^2` residues before returning key
  material; secret-key admission now rejects non-ternary coefficients outside
  the generated `{0, 1, q - 1}` domain before owner-side residual diagnostics
  run. Exact-residual and bounded-noise public-key/ciphertext material,
  evaluation-key bundle material, and proof-input material byte admission now
  require canonical uncompressed Norito framing before public commitments,
  proof statements, or admission-prover witness packages are hashed. Soracloud RotateLeft now
  requires public
  rotation-key refresh material for the outer ciphertext-slot envelope, and Bootstrap
  applies validated, domain-separated public encrypted-zero refresh material
  by round index instead of reusing one refresh ciphertext. Key-owner
  diagnostics now also verify that generated rotation and bootstrap public
  refresh ciphertexts decrypt to zero under the matching secret key, including
  a bundle-level check over every rotation and bootstrap refresh mask, and
  public bootstrap admission now requires a verifier-backed statement proof
  envelope, but binding-only STARK AIR is rejected after metadata preflight;
  admission remains closed until a dedicated zero-refresh witness AIR proves
  the encrypted-zero and round-consistency relation.
  Public deterministic transcript checks now recompute rotation and bootstrap
  encrypted-zero refresh material from the advertised seed, public key, key id,
  and round count, rejecting wrong-seed, key-id-drifted, or tampered refresh
  ciphertexts without requiring a secret key; the same check now runs at the
  evaluation-key bundle level so admission cannot accidentally validate only a
  subset of public rotation/bootstrap refresh masks. The validated transcript
  inventory now also has nonzero duplicate-free rotation step metadata,
  public seed metadata bounded by the shared BFV deterministic seed cap,
  direct and binary-decorated placeholder-text rejection for deterministic and
  refresh transcript seeds and bootstrap key ids, canonical bootstrap key-id
  metadata bounded by the shared BFV bootstrap key
  cap, and rotation inventory metadata bounded by the shared BFV evaluation-key
  rotation cap plus bounded nonzero bootstrap refresh round metadata and a
  stable
  domain-separated digest over the parameter set, public key, evaluation-key
  digest, and transcript metadata, giving governance/admission code a
  canonical value to bind in the bootstrap-key proof envelope. The crypto layer
  now also exposes exact-lift and bounded-noise transcript-bound
  bootstrap-key zero-refresh proof statement digests that bind parameters,
  public key, evaluation-key digest, refresh-transcript digest, bootstrap
  transcript seed/key id/round capacity, and every public refresh ciphertext
  under mode-separated domains. Raw bootstrap-key zero-refresh statement
  regressions also pin exact and bounded domain constants to the same typed
  bootstrap-key material. Crypto now also exposes exact-lift and
  bounded-noise ciphertext proof statement digests that bind parameters,
  public key material, public-key digest, ciphertext bytes, a non-inert
  ciphertext digest, and the declared residual/noise bound under
  mode-separated domains, with regressions pinning both exact and bounded
  domains to the same typed Norito statement material, rejecting all-zero
  ciphertext sentinels before a verifier-facing statement hash can be emitted.
  Exact ciphertext statement
  hashing now also runs the exact seeded-encryption residual headroom preflight,
  matching exact public-key statement admission so structurally valid but
  non-admissible exact profiles cannot emit verifier-facing ciphertext
  statement hashes. Data-model refresh transcripts
  now derive the exact-lift or bounded-noise ciphertext statement digest from
  their public key, reject inert all-zero transcript public keys in the
  public-key and ciphertext proof-statement wrappers, and the input-admission
  public-input schema advertises the ciphertext statement digest
  domains/material, including the exact seeded-encryption capacity preflight on
  per-ciphertext statement hashes, under schema hash
  `828907b1ebc7d05e38e8528109feff1c92a7761ff8dda725ba1486e513bb84ad`.
  Portable validation now rejects inert all-zero proof public keys, and coverage
  pins proof public-key presence, ciphertext digest-list arity/sentinel checks,
  rejection of `fhe_public_key_digest` metadata on non-FHE state rows, and
  all-zero `fhe_public_key_digest` placeholders on FHE rows.
  Core input-admission preflight recomputes those per-slot statement digests
  from the decoded payload and proof public key, but binding-only AIR is
  rejected at the missing dedicated ciphertext-witness boundary before any FHE
  row, public-key digest, or claimed bound metadata is persisted. The input
  loader still rejects corrupt persisted rows whose public-key digest mismatches
  the governed job key or whose BFV payload is an all-zero sentinel.
  `RunSoracloudFheJob` now carries an
  optional bootstrap-key proof attachment, provenance signs it, and Core
  requires it for bootstrap execution while checking the policy-bound
  statement hash and active Soracloud STARK verifier record before failing
  closed at the missing dedicated zero-refresh witness AIR boundary. The
  verifier registry now rejects canonical
  Soracloud bootstrap verifier records whose registry id, namespace, circuit
  version, public-input schema hash, gas schedule, or active inline key
  material drift from the governed v1 profile, moving those rollout failures
  to `RegisterVerifyingKey`/`UpdateVerifyingKey` admission. BFV bootstrap keys
  now carry an explicit `RefreshOnlyV1` mode, and `FullBootstrapV1` keys carry
  versioned circuit/key-material commitments that bind the canonical circuit id,
  registered BFV parameter digest, RNS modulus-chain digest, key-switch
  decomposition-chain digest, bootstrap artifact digests, and proof
  public-input schema/prover-key/verifier-key digests. The material validator
  rejects zero commitments, duplicate artifact/proof commitments, and artifact
  or proof commitments that reuse registered profile digests, so each governed
  digest role remains domain-separated at admission. Bundle admission and
  digesting bind that material, while refresh/proof paths and direct
  no-artifact registered execution fail closed with an explicit governed
  artifact requirement, so the current refresh bridge cannot be mislabeled as
  full bootstrapping. Direct
  key-authorized refresh execution, bootstrap output-bound helpers, and
  Soracloud exact/bounded bootstrap execution now share the same mode-aware
  request preflight, so reserved full-bootstrap keys are rejected before
  round-count, bound-capacity, ciphertext-shape, or refresh-key entry errors.
  Bundle validation/digesting applies the same public metadata preflight before
  the mode/material gate and before transcript-bound bootstrap proof statements
  can be produced. Bundle-level zero-refresh diagnostics now also use the
  refresh-mode gate, so `FullBootstrapV1` bundles cannot be treated as
  refresh-only exact or bounded-noise diagnostics after admission metadata
  accepts their governed material. The crypto layer also exposes a domain-separated
  full-bootstrap material proof-statement digest that binds the parameter set,
  public key, evaluation-key bundle digest, bootstrap-key metadata, and
  material digest for governed prover inventories. The data-model refresh
  transcript wrapper can derive the same full-bootstrap material statement for
  manifest callers, and execution policies now require bootstrap-capable
	  bundles to bind exactly one bootstrap statement class: exact or
	  bounded-noise zero-refresh for `RefreshOnlyV1`, or full material for
	  `FullBootstrapV1`. Full-bootstrap
	  refresh transcript digesting omits deterministic zero-refresh bootstrap
	  transcript seeds while still checking the bootstrap public-key digest against
	  the supplied public key, and Core rejects missing, mismatched, stale, or
	  cross-mode policy statement bindings before execution. Governed
	  `FullBootstrapV1` keys now also fail closed as no-refresh keys:
	  `full_bootstrap_key_from_material_v1` constructs them with
	  `max_refresh_rounds = 0`, empty `zero_refresh`, and empty
	  `round_refreshes`, and crypto/Core admission, proof-statement, execution
	  preflight, and release-audited prover paths reject mixed full-mode keys that
	  retain encrypted-zero refresh metadata or material before package digesting
	  or artifact execution can hide the drift. Crypto regression coverage now
	  also mutates legacy `zero_refresh` and `round_refreshes` material
	  independently while `max_refresh_rounds = 0`, confirming artifact-aware
	  preflight plus exact/bounded direct execution and bound preflights fail
	  before artifact fallback. The data model now also exposes a
	  distinct full-bootstrap material proof attachment with canonical
	  STARK/`OpenVerifyEnvelope` circuit id, public-input schema, byte bounds,
  verifier-key commitment, statement public input, and envelope-hash checks, so
  governed material proofs no longer reuse the zero-refresh bootstrap proof
  envelope. Core now decodes material proofs through that material-specific
  attachment context, and all Soracloud FHE STARK wrappers reject non-empty
  all-zero native envelope bytes before backend verifier dispatch.
  `RunSoracloudFheJob` and Torii signed FHE job requests now carry
  an optional distinct full-bootstrap material proof attachment, provenance
  signs it, and Core requires it for policy-bound full-bootstrap jobs before
  dispatching through the active Soracloud verifier record or preverified-proof
  cache path. Runtime admission rejects absent, mismatched, non-bootstrap, and
  unverified fake full-material proofs, and
  `RegisterVerifyingKey`/`UpdateVerifyingKey` admission rejects canonical
  full-material verifier-profile drift before job execution. Job admission now
  also requires the material proof schema digest and verifier-key digest to
  match the canonical Soracloud proof schema and proof attachment verifier
  commitment through the BFV crypto proof-profile validator, and rejects
  supplied full-material proof attachments that omit `vk_commitment` at the
  material/profile gate before backend verifier lookup. The Rust, Swift,
  Kotlin/JVM, and Java Android shared Soracloud BFV operation-fixture validators
  now pin the full-bootstrap material/profile digest, verifier-key commitment,
  and statement vector so SDK/release validation can reject fixture drift before
  artifact-aware execution or proof verification. Full-mode exact
  and bounded runtime bootstrap paths now use dedicated crypto preflight
  helpers that validate governed material commitments, registered profile
  digests, ciphertext shape, and exact/bounded metadata before direct
  no-artifact entry points return the governed-artifact requirement. Crypto now
  also exposes a typed
  full-bootstrap artifact bundle validator/digest and artifact-aware execution
  preflight that bind concrete evaluator/proof-profile bytes to those governed
  commitments. Each artifact byte field is now a Norito role/profile envelope
  that declares the canonical circuit id, registered parameter/RNS/decomposition
  digests, and max bootstrap depth, so malformed, role-swapped, stale-profile,
  and empty-payload artifact attachments fail before artifact-aware output
  execution. Coefficient-to-slot and slot-to-coefficient artifacts now carry
  typed diagonal packed-slot linear transforms, and crypto keeps exact and
  bounded deterministic evaluator/bound helpers for those transforms on the
  crate-private registered RNS trace path. The blind-rotation artifact now
  carries canonical packed-slot rotation schedules bound to the governed
  accumulator artifact, and its exact/bounded registered-RNS execution and
  bound-propagation helpers are crate-private internal trace stages that
  consume those governed selector schedules directly. The sample-extraction
  artifact now carries typed source/output
  ciphertext shape and extracted-coefficient metadata, rejects opaque,
  wrong-slot-count, bad-component-count, or out-of-range payloads. Raw
  LWE-style sample extraction, validation, and exact/bounded raw-sample bound
  helpers are crate-private, so canonical trace reconstruction can still
  extract the selected `c0 + c1 * s` coefficient internally without exposing a
  standalone raw-sample proof-material API.
  Crypto now composes the governed coefficient-to-slot, blind-rotation, and raw
  sample-extraction artifacts into an exact/bounded execution-prefix trace with
  propagated bounds, coefficient-zero diagnostic repack output,
  slot-to-coefficient diagnostic execution, and missing-key fail-closed checks.
  Those executable prefix-trace and prefix-bound helpers are crate-private
  internal proof/witness material; external callers must use the public
  artifact-aware release-audited output/bound wrappers or proof-material
  validators.
  The explicit coefficient-zero raw-sample repack diagnostic bridge and its
  exact/bounded coefficient-zero bounds are crate-private, keeping that bridge
  as internal proof material rather than a standalone output API. Deterministic
  exact and bounded raw-sample switch-key material, secret-consistency checks,
  governed artifact carriage, and artifact-aware full-bootstrap output/bound
  helpers still run through slot-to-coefficient; standalone linear-transform,
  blind-rotation, switch execution, and direct output-bound helpers are
  crate-private internal trace stages.
  Full-bootstrap artifact-bundle validation now requires
  executable sample-extraction switch-key material rather than accepting
  metadata-only sample-extraction payloads in the governed bundle. Direct
  no-artifact registered entrypoints now validate preflight, then fail with an
  explicit governed-artifact requirement; the real proof verifier/prover
  backend remains unfinished. The
  accumulator artifact now
  carries typed packed-slot test-vector material and rejects opaque,
  wrong-slot-count, malformed, or all-zero accumulator payloads. The proof
  public-input schema and prover/verifier key artifacts now also carry typed
  proof-profile payloads that bind the canonical backend, key format, circuit
  id, registered parameter profile digests, maximum bootstrap depth,
  statement-hash layout, and governed schema digest while rejecting opaque
  schema/key bytes, profile/depth drift, empty or all-zero key material, and
  duplicate prover/verifier key material; schema artifact regressions pin the
  canonical proof public-input schema payload digest to exact typed Norito
  schema bytes and the artifact digest to the governed registered-profile
  envelope carrying those bytes. Arithmetic trace profile, AIR contract, and
  native proof-circuit fingerprint regressions pin the encoded self-describing
  Norito material under their dedicated digest domains. Crypto now also
  hashes full-bootstrap artifact bundles through a typed digest material with
  version, artifact-digest count, and per-role artifact hashes, and pins valid
  alternate-artifact regressions for every mutable artifact role that can vary
  under the first-release profile; circuit-material, evaluator-artifact-set,
  and artifact-bundle digest regressions also pin the encoded self-describing
  Norito material under the dedicated governance digest domains. Proof-key pair
  and individual material-commitment regressions also pin the dedicated
  domain-separated transcripts over proof-profile metadata, role labels,
  verifier-obligation flags, and backend-native key bytes. The material/execution
  Soracloud public schemas now also advertise their statement digest domains
  plus the circuit-material, evaluator-artifact-set, and artifact-bundle digest
  domains used by the governed artifact transcripts, with regressions binding
  those fields to the authoritative crypto constants. The execution schema now
  also advertises the release-prover proof-input, prover-input, AIR-evaluation,
  trace-material, and AIR-constraint-system digest domains, again bound to the
  authoritative crypto constants. Crypto now also
  pins exact and bounded
  full-bootstrap execution statement digest goldens for that typed artifact
  bundle layout, currently
  `e0fb7248645497af2afada4e0b6e8cfd7e3134f40d19f870cbf0e1854afad6c7`
  for exact residual mode and
  `4d1cc75c22abadfcd967f526e0a58ac9df3432831f4cc389b0cc38bc08e4c133`
  for bounded-noise mode, with both modes checked against self-describing
  Norito statement material. Crypto now also
  declares and validates the v1 statement-material and per-slot claim layout,
  requiring parameter, public-key, bootstrap-key, material, artifact-bundle,
  slot-index, ciphertext, proof-mode, and residual/noise-bound commitments
  before proof artifacts are accepted. Crypto tests also pin the canonical
  typed proof schema artifact digest
  `a1354821e8d00ab90629e00a685827151076b813d132cb10e7684a4ab84b556b`
  and prover-key material commitment digest
  `9d719e7217868f8a74adc155a3b6126a60e5b9a9a9b6c8ead528f4a0f59c8685`,
  with native Merkle/FRI replay and AIR-root FRI query binding flags included
  in the schema and proof-circuit fingerprint material. The material/execution
  Soracloud public schemas now advertise the proof-key material and proof-key
  pair commitment domains used by those transcripts, plus the artifact digest
  domains bound by release-audit evidence.
  Data-model tests pin the Soracloud FHE public-input schema hashes that Core
  verifier records use for input admission, bootstrap-key proof,
  full-bootstrap material proof, and full-bootstrap execution proof gates.
  The input-admission schema now advertises the exact-residual and
  bounded-noise bound modes, capacity validation, and ciphertext proof-statement
  digest domains/material, including the exact seeded-encryption capacity
  preflight on per-ciphertext statement hashes, under schema hash
  `828907b1ebc7d05e38e8528109feff1c92a7761ff8dda725ba1486e513bb84ad`.
  The typed crypto schema and full-bootstrap execution schema now advertise
  artifact-bound release-prover input validation, stale Galois-key-set replay,
  stale proof-key artifact rejection, transcript-derived opening
	  schedule/public-padding replay, native Merkle/FRI verifier replay,
	  AIR-root FRI query binding, and canonical base transcript-label plus
	  suffixed-label alias rejection, and the governed verifier-key wire boundary
	  accepts only the BFV-native V1 payload and rejects wrong-circuit metadata
	  before deterministic internal Core conversion; release-audit
	  evidence now exposes those
	  replay-policy guarantees in its proof-profile record with field count 58,
	  including release-prover digest domains and proof-key material/pair
	  commitment domains; native proof-circuit fingerprint material binds the
	  same guarantees with field count 48, generated circuit bodies carry them
	  with field count 49,
		  deterministic release-audit report/archive inventories label the proof-profile
		  field count, canonical/suffixed transcript-label obligations, and
		  release-prover/proof-key domain contract, release-audit packages validate
		  those proof-profile markers plus
		  generated-body byte length/hex, native
		  prover/verifier payload hex, governed prover/verifier artifact hex, and
	  indexed report/archive signed commitment containment with standalone label tokens,
	  explicit value separators, standalone value tokens, and
	  relabel/cross-field/punctuation/conflicting-duplicate replay rejection,
	  and production external-review report/archive bodies now reject duplicate
	  canonical external-review marker fields plus case-insensitive
	  same-statement marker-token replays, padded-colon marker replays, and
	  non-printable marker-statement bytes, marker-token separator reviewer ids,
	  and separator-alias reviewer labels before trusted package admission,
	  Torii signed job-run proof preflight rejects placeholder native STARK
	  envelope bytes for public-key, bootstrap-key, full-bootstrap material, and
	  full-bootstrap execution proof attachments before backend verification,
	  crypto now exposes a one-shot package builder that derives canonical
	  machine-checkable report/archive bytes from governed artifacts before
		  signing and validating the release-audit package, crypto also exposes a
		  package-plus-digest helper so callers pin the digest of the same validated
		  package they submit, data-model release-audit fixtures consume that helper,
		  and Torii/Core production-path fixtures, including Core exact/bounded
		  runtime and audited-prover rejection fixtures, consume paired
		  external-review package/digest construction rather than split
		  package/digest derivation. Crypto now also exposes an explicit
		  external-review package/digest builder that rejects deterministic
		  machine-generated inventory bodies before returning caller-pinnable
		  package material. The `zk_stark` BFV full-bootstrap AIR prover
		  fixture now keeps the same package/digest pairing for production-accepted
		  external-review artifacts rather than the intentionally rejected
		  machine-generated audit package, and data-model FHE execution policy
		  validation now reuses the crypto external-review marker gate so
		  machine-generated release-audit packages fail before policy admission even
		  when the package digest and trusted reviewer match. Release-audit
		  report/archive body regressions also pin marker tokens split across
		  non-text bytes before report byte construction, signed package
		  validation, or package digesting,
		  the material/execution public schemas advertise the leading
		  external-review report/archive markers, printable-ASCII
		  reviewer-id-labelled external-review marker statements that reject
		  bare reviewer-id prose plus duplicate or conflicting reviewer-id labels,
		  including case-drifted and separator-alias reviewer-label aliases,
		  reject padded-colon external-review marker aliases,
		  plus machine-generated and separator-obfuscated machine-generated
		  audit-body rejection,
		  and the current material/execution schema hashes are
			  `fdfe1d3454a0f3fac98684f24af74bbb0286dda732e7d34e1d99677fcbbc5acb`
			  and `0f8fcf3c6cb5f2889d471dc7b656d8f6174289ce0d1ab40b13076da5fdd5443d`.
		  The registered bounded-noise compatibility wrappers for
		  multiplication, Galois switching, outer-slot rotation, packed rotation,
		  and bootstrap refresh now delegate to the registered target-limb
		  basis-extension corridor, so
		  production callers validate the same decomposition/evaluator-chain
		  binding even when they use the older registered API names. Bounded
		  outer-slot rotation public-bound propagation now also has direct and
		  registered target-limb basis-extension wrappers, and Core uses the
		  registered wrapper for multi-slot bounded `RotateLeft` bound checks.
		  Core's release-audited material and execution prover entrypoints now also
		  reject packages that downgrade the AIR-root FRI query-binding proof profile
		  before native proof emission.
		  Shared Soracloud operation vectors now install constructor-built
		  no-refresh `FullBootstrapV1` keys and keep the governed full-bootstrap
		  material proof schema pinned to the crypto artifact digest
		  `a1354821e8d00ab90629e00a685827151076b813d132cb10e7684a4ab84b556b`,
		  not the Soracloud wrapper schema hash above. The fixture pins prover-key
		  digest `a138d4ba7125de0ff8a368d82d13c697986ced91ed8b8b9c468bc3b694a26929`,
		  prover-key material commitment
		  `66c2f9dbdabcc89150468d3369d1ff7c78824c01211091bc99bed51c4d5d0977`,
		  material digest
		  `3452f02a52628f6a78bfdac707e2fa698264cd7b35ca93ff1cbb5081dc65e5bd`,
		  and statement digest
		  `99682800da76658dc2801ee1db9896edf9803d4d5f8b374bf888584401848f7d`.
  Bootstrap-key zero-refresh proof statements now also encode a v1
  statement-material header plus bootstrap refresh-round count,
  zero-refresh digest, and indexed per-round refresh digests, and the
  public-input schema hash
  `39809de5a8ac82f115fc3df08abffb3629adbf9dd227bccf7f9816cbc86e8563`
  advertises those transcript, refresh-summary, and exact/bounded
  raw/transcript statement-domain plus refresh-transcript-domain bindings,
  including the v1 refresh-transcript material header, with the schema
  regression checking the exported crypto material and digest-domain constants
  directly.
  Core now also requires the full-bootstrap material proof verifier record to
  carry the canonical material-proof gas schedule id and has adversarial
  verifier-record drift coverage matching the execution-proof gate.
  Input-admission and bootstrap-key proof verifier records now likewise require
  their canonical gas schedule ids rather than any non-empty schedule id.
  Crypto now also
  exposes a domain-separated full-bootstrap execution proof statement digest
  that validates and binds the public key, governed bootstrap key/material,
  concrete artifact bundle, input/output ciphertexts, exact or bounded proof
  mode, input/output bound metadata, and execution-witness digest for the
  verifier. The Soracloud execution proof public-input schema and stable hash
  now advertise that witness digest so verifier records cannot keep accepting
  the pre-witness claim layout by metadata accident.
  `RunSoracloudFheJob` now carries optional full-bootstrap artifacts plus an
  ordered execution-proof vector, provenance signs both, and Core routes
  exact/bounded full-mode jobs through artifact-aware full-bootstrap execution
  and bound propagation through sample-switch and slot-to-coefficient output
  before requiring one governed execution proof per output slot.
  Torii signed job-run requests now validate those verifier-backed proof
  attachments locally before instruction construction, so malformed signed
  wrappers fail as bad requests before reaching Core. Torii signed job-run
  preflight now resolves every signed parameter-set descriptor against the
  registered BFV profile and runs the shared policy/job admission validators
  plus BFV evaluation-key and refresh-transcript digest checks before
  proof/artifact validation, recomputes policy proof-statement digests from
  the signed key/transcript material, requires policy-bound bootstrap-key and
  full-bootstrap material proofs to be present with matching statement hashes,
  validates supplied full-bootstrap artifact bundles against the governed
  request material before instruction construction, requires full-bootstrap
  execution requests to carry signed circuit artifacts and a non-empty
  execution-proof vector,
  rejects full-bootstrap material/execution proof attachments outside
  full-bootstrap job/key context, and rejects execution proofs that omit signed
  artifact bundle bytes. Parameter, policy, job, key, transcript, digest, or
  descriptor drift now fails locally before proof or artifact decoding. Core governed
  full-bootstrap execution verifier-key derivation now validates the complete
  artifact bundle before decoding verifier-key material, so drifted
  non-verifier artifacts fail at the helper boundary, and opaque, below-floor,
  or circuit-retargeted STARK/FRI verifier-key payload bytes fail before a
  governed `VerifyingKeyBox` is derived. Data-model and Core
  `OpenVerifyEnvelope` admission now also reject all-zero native STARK
  envelope bytes for Soracloud FHE input, bootstrap-key, full-bootstrap
  material, and full-bootstrap execution proofs, while the shared data-model
  OpenVerify admission guard rejects non-empty all-zero outer proof bytes and,
  after enforcing configured public-input byte bounds, all-zero public-input
  metadata before backend verifier dispatch; Core
  STARK verifier-dispatch and preverify coverage now pin those generic
  rejections before backend-native proof decoding or dedup/cache admission.
  Under `zk-stark`, Core also decodes Soracloud FHE input-admission,
  bootstrap-key, full-bootstrap material, and full-bootstrap execution native
  `StarkVerifyEnvelopeV1` payloads before backend verification and
  adversarially rejects drift across transcript label, domain tag, AIR section
  presence, circuit id, trace width, opening count, composition root, and public
	  digest. Native STARK/FRI proof construction, query replay, and envelope
	  verification also reject noncanonical transcript labels, malformed domain
	  tags, and malformed AIR circuit ids before transcript sampling or
	  verification, and the ZK-ACE AIR
	  path binds the canonical ZK-ACE circuit id and STARK/FRI backend, with
	  preverify/dedup metadata admission rejecting noncanonical backend labels and
	  malformed ZK-ACE public-input or wrapper shapes before cache insert. Public
	  generic AIR constructors reject reserved ZK-ACE and IVM identities before
	  envelope synthesis. Binding-only IVM wrapper and dedicated AIR paths are
	  retired; preverify rejects their identities before cache insertion. Complete
	  native IVM execution and finalized State authority remain open release gates.
	  The governed material-native AIR
	  verifier and release-native execution active verifier now also have drift
	  coverage for transcript labels, STARK parameters, trace roots, composition
	  roots, public digests, and opened composition values. For full-bootstrap
		  material and execution proofs, generic binding-AIR fixtures are fully
		  validated before they are rejected at the dedicated arithmetic-AIR boundary.
		  Base Soracloud FHE input-admission, public-key, and bootstrap-key verifier
		  paths now also preflight the stored STARK/FRI verifier-key payload's
		  production floor, SHA-256 hash selector, and canonical circuit id before
		  native AIR checks, backend dispatch, or preverified-cache acceptance, with
		  wrong-circuit cache-bypass regressions for all three proof families.
		  Governed BFV-native execution AIR now verifies the
	  trace and composition roots plus sampled rows/values against verifier-derived
	  arithmetic material before acceptance, and crypto-side AIR evaluation
	  validation recomputes the trace-bound composition vector before accepting
	  release-prover input material. The `zk-preverify` path is covered
	  with poisoned-cache regressions for input-admission and bootstrap-key native
	  AIR drift plus full-bootstrap material-native AIR drift,
	  execution BFV-native AIR/root drift, required governed execution material,
	  and material/execution generic AIR drift, so cache hits cannot bypass native
	  envelope binding, verifier-owned material checks, the required material
	  context, or the dedicated arithmetic-AIR boundary.
  `zk-stark` full-bootstrap fixtures now install governed artifact-backed
  STARK verifier keys and generate backend-verified binding-AIR
  `OpenVerifyEnvelope` payloads only as rejection fixtures: the active
  full-bootstrap material and execution verifier gates reject them before
  backend dispatch because they do not prove the BFV bootstrap arithmetic. All
  Soracloud FHE proof attachment decoders now reject noncanonical STARK/FRI
  backend labels before verifier lookup or full-bootstrap native verifier
  dispatch.
  Input-admission, public-key, and bootstrap-key binding-AIR payloads are
  rejection fixtures: their public binding does not prove the required BFV
  ciphertext, key-generation, or zero-refresh witness relations.
  Full-bootstrap material proof verification now also preflights the active
  record's stored STARK/FRI verifier-key payload against the canonical material
  circuit before backend dispatch, so corrupted state cannot retarget the
  material verifier key to the execution circuit.
  `zk-preverify` full-bootstrap regressions now prove that preverified cache
	  hits cannot bypass the dedicated arithmetic-AIR boundary for material proof
	  batches or the governed native-AIR checks for execution proof batches.
  Core now also requires full-bootstrap material and execution proofs to pass
  their dedicated native STARK/AIR verifier before acceptance: non-`zk-stark`
  builds fail closed after envelope/verifier-record binding, and preverified
  cache or generic backend verification is no longer a fallback acceptance path
  for those full-bootstrap proof types.
  The confidential verifier-call defaults now admit one such Soracloud
  full-bootstrap execution batch without an operator override.
  Core regressions now also prove that correctly shaped full-bootstrap
  execution proof attachments fail closed before backend verification when the
  governed verifier record is missing or withdrawn.
  The Core proof helper now also reruns local job-shape validation, requires
  input-bound metadata to match the input envelope count, and rejects missing or
  surplus output slots before deriving proof statements. The execution proof
  helper also derives the governed verifier key from the supplied evaluation
  keys and circuit artifacts and rejects caller-supplied verifier keys that do
  not match it before reaching the dedicated-prover boundary, so stale bound
  sidecars, stale output sidecars, wrong verifier keys, and multi-input
  bootstrap drift cannot reach proof verification.
  The lower-level `zk-stark` material and execution proof constructors also
  preflight the supplied verifier-key backend, circuit id, production-floor
  STARK/FRI shape, and SHA-256 selector before returning the
  dedicated-prover-unavailable error.
  It also rejects full-bootstrap execution circuit artifacts outside
  full-bootstrap proof context even when no execution-proof attachments are
  supplied, so artifact-only bypass attempts fail at the proof boundary.
  Core regressions also pin full-bootstrap execution verifier-record metadata
  drift across namespace, backend, curve, public-input schema, circuit/version,
  gas schedule, active circuit mapping, proof byte caps, key presence/length,
  commitment, and governed verifier-key byte binding.
  Full-bootstrap execution proof statements now bind the zero-based output slot
  index, and Core rejects slot-position replay even when duplicate ciphertext
  slots would otherwise produce identical input/output claims.
  Full-bootstrap jobs now also require `bootstrap_count == 1` in Core execution,
  bound propagation, proof verification, and Torii signed-request preflight, so
  the one-proof-per-output-slot statement cannot be replayed as a multi-round
  full-bootstrap claim.
  Core now also preflights full-bootstrap execution-proof material after
  loading FHE inputs and before artifact-aware execution, rejecting proof
  vectors whose length does not match the actual input/output slot count before
  the heavier arithmetic path runs.
  Exact and bounded-noise Core runtime coverage now also rejects drifted signed
  artifact bundles, role-swapped artifact envelopes, and stale prover/verifier
  key-material commitments before Galois-key availability or final output
  execution.
  Full-bootstrap proof-key payloads now also bind the canonical execution
  public-input layout, a generated prover/verifier pair commitment, and a
  deterministic native proof-circuit fingerprint for the typed STARK/FRI
  material; the fingerprint material has field count 48 and binds the same
  artifact-bound prover-input validation, stale Galois-key-set/proof-key
  artifact replay rejection, transcript-derived public-opening policy, canonical
  base transcript-label enforcement, and suffixed-label alias rejection as the
  typed schema. Generated
  pair validation rejects prover/verifier native-circuit mismatch, and
  governed material stores the pair commitment while Core/Torii recompute it
  from decoded proof-key artifacts before accepting signed material. Native
  proof-key material now also rejects noncanonical native
  payload circuit ids outright, so proof-key artifacts cannot be generated for
  or retargeted to any circuit other than `iroha_bfv_full_bootstrap_v1`; native
  circuit fingerprints now reject placeholder digest sentinels before canonical
  fingerprint mismatch diagnostics, and circuit-material registered-profile
  digests now reject zero or placeholder sentinels before registered-profile
  mismatch checks. Release-audit evidence registered-profile digests now run
  the same placeholder preflight before registered-profile or cross-field
  mismatch checks, and artifact envelopes run that profile-digest preflight
	  before governed-material or registered-profile mismatch checks. Proof-key
	  material envelopes now run the same registered-profile digest preflight before
	  outer proof-key metadata mismatch checks, and individual proof-key material
	  commitment derivation decodes that canonical envelope before hashing so
	  opaque or noncanonical native key bytes cannot mint governed commitments.
	  Release-audit archive validation now indexes label/value fields once per
	  body before checking signed commitments, proof-profile obligations, and
	  governed artifact hex, while placeholder-marker scans skip directly between
	  candidate marker starts.
	  Release-audit reports now must carry
	  the signed release evidence digest, and evidence archives must carry the
	  signed generated-circuit-body digest, native circuit fingerprint,
	  proof-key pair commitment, individual prover/verifier key digests, and the
	  release-audit proof-profile field count plus canonical base transcript-label
	  enforcement, suffixed-label alias rejection, release-prover digest domains,
	  and proof-key material/pair commitment domains before a package validates.
  Native proof-key payload shape validation now rejects blank payload bytes and
  known direct/delayed placeholder or inert native payload sentinels before
  Norito decoding, so raw prover/verifier payload validators and material
  constructors fail closed at the payload boundary rather than relying on later
  digest-only rejection, and role-specific raw prover/verifier payload
  validators now require exact canonical uncompressed v1 encoder bytes after
  structural validation so alternate Norito framing cannot satisfy signed native
  payload commitments. Whole artifact-envelope byte preflight now rejects the
  same placeholder text sentinels before governed digest mismatch or Norito
  decode paths, so handoff text cannot be supplied as a full artifact
  attachment; artifact-derived material construction runs that envelope pass
  before hashing artifact bytes into governed material digests, and evaluator
  artifact-set digesting uses it before hashing non-proof artifact bytes. The outer native proof-key material bytes and
  proof-key material envelope bytes now use the same raw text-sentinel preflight
  before Norito decoding, and public proof-key material/pair commitment
  derivation rejects the same empty, all-zero, and placeholder material before
  hashing, so governed material cannot commit to bytes that later fail envelope
  admission. Generated native circuit body validation applies that guard before
  digest and canonical-body comparison, so digest-correct template or handoff
  text cannot reach generic material, envelope, or body-drift paths. Generated
  circuit-body backend/key-format/proof-system/field metadata now uses strict
  canonical text-label preflight before body comparison. Native
  full-bootstrap payload circuit-id metadata now rejects placeholder and
  handoff labels before the generic canonical-id mismatch path. Proof-key
  backend, key-format, and material-envelope backend/key-format metadata now use
  strict canonical text-label preflight, proof-key circuit-id metadata uses the
  same placeholder preflight, and outer proof-key/envelope circuit ids now share
  the strict canonical `iroha_bfv_full_bootstrap_v1` preflight before
  governed-material or envelope metadata matching. Native prover/verifier payload
  backend/key-format/proof-system/field metadata and native proof-key material
  backend/key-format/proof-system/field/payload-kind metadata now use strict
  canonical text-label preflight, while native proof-key material circuit ids
  still reject placeholder labels before generic mismatch checks. Governed
  full-bootstrap circuit material, evaluator
  artifact-set digest material, arithmetic trace profiles, arithmetic AIR
  material, proof public-input schemas, proof-key governed-material checks, and
  artifact envelopes now share the strict canonical
  `iroha_bfv_full_bootstrap_v1` preflight for governed full-bootstrap
  circuit-id metadata.
  Release-audit evidence, signoff payload, and manifest circuit-id metadata now
  also use the strict canonical `iroha_bfv_full_bootstrap_v1` preflight;
  release-audit proof-profile backend/key-format/proof-system/field metadata,
  key-evidence payload-kind labels, and manifest scope metadata now use strict
  canonical text-label preflight.
  Full-bootstrap trace-profile witness, arithmetic AIR composition, proof
  public-input schema statement/witness/AIR/proof-input, proof-key witness,
  proof-key material envelope witness, and generated circuit-body witness
  domains now use strict canonical byte-label preflight before generic domain
  mismatch checks.
  Native verifier payloads now mirror the transparent prover payload profile by
  binding their field count, backend, key format, proof system, and field
  labels before material admission or native-to-Core conversion. That
  conversion independently rejects field-count drift,
  so relabeled STARK/FRI verifier payloads cannot be smuggled through the
  governed artifact path.
  The first-release arithmetic trace layout is now exposed as typed
  `BfvFullBootstrapArithmeticTraceProfileV1` material with a canonical digest
  bound by the proof public-input schema, proof-key material envelope, native
  prover/verifier payloads, native proof-key material, and native
  proof-circuit fingerprint; crypto and Core reject trace-profile digest drift
  before governed artifact admission or verifier-key canonicalization. The
  profile now also binds the active coefficient rows as private witness rows,
  public deterministic padding rows, and the rule that transparent native
  proofs must not open unmasked private rows. Crypto's public padding-row
  helpers reject zero, direct-placeholder, and leading-whitespace
  delayed-placeholder statement hashes before constructing or validating
  verifier-facing row openings, and Core's native BFV AIR public-padding
  verifier shares that gate while validating opened public padding rows against
  the canonical statement, slot, and bound-mode header, rejects duplicated or
  truncated sampled public-opening sets, and rejects empty/all-zero AIR roots or
  auxiliary generic
  composition-value commitments before the dedicated verifier fallback.
  Release prover input now has a typed
  `BfvFullBootstrapMaterialProofInputMaterialV1` boundary for governed
  full-bootstrap material proofs and a typed
  `BfvFullBootstrapExecutionProofInputMaterialV1` boundary that carries the
  public key, validated execution witness material, and canonical statement
  hash together; validation rejects stale input layouts, forged statement
  hashes, stale public keys, stale evaluation-key material, and stale embedded
  witnesses before a dedicated arithmetic prover can consume the material.
  Release execution prover input now also has a typed
	  `BfvFullBootstrapExecutionProverInputMaterialV1` package that binds the proof
	  input, canonical row-major arithmetic trace material/digest, canonical AIR
	  contract digest, governed AIR artifact digest, zero-composition AIR
	  evaluation material/digest, and governed generated prover/verifier
	  proof-key pair before the dedicated prover boundary. Crypto and Core reject
	  stale trace digests, stale AIR contract/artifact/evaluation material
	  digests, non-zero composition values, stale trace rows, trace/proof-input
	  splicing, and unrelated proof-key material or pair commitments before proof
	  generation is attempted. The proof-emitting Core material and execution
	  helpers are now internal; the crypto release-audit validator owns the
	  governed material/artifact, caller-trusted reviewer id/key, and
	  caller-pinned package digest gate used by the callable production material
	  and batch paths, and that gate rejects zero, known placeholder, or
	  leading-whitespace delayed-placeholder pinned package digests plus
		  record/manifest digest aliases and signed inner commitment aliases
		  before stale package
		  validation or digest comparison can mask the caller-pinned digest error;
			  Core material and execution proof wrappers pin those rejections
		  with production-entry tests before native proof generation. Shared
		  execution-policy validation now also recomputes the embedded release
		  package digest, rejects post-signature reviewed report/archive byte
		  mutations, and rejects stale, placeholder, or leading-whitespace
		  delayed-placeholder pinned digests plus record/manifest digest aliases
		  before Core/Torii runtime admission can inherit malformed policy
		  context; Core's full-bootstrap runtime release-audit context pins the
		  same package-digest sentinel rejection before artifact execution. Torii
		  signed FHE job preflight now pins the same reviewer-id
		  and reviewer-key field errors for placeholder reviewer labels and
		  non-Ed25519 trusted reviewer keys before package validation. The
	  trusted-reviewer package gates preflight caller-supplied reviewer id/key
	  inputs, including malformed or all-zero reviewer public-key payloads,
	  and placeholder reviewer-id sentinel text such as draft, fake, TODO,
	  pending-audit, sample, template, example, or not-production-ready labels
	  before package or artifact
	  validation can mask malformed trust
	  configuration, and the standalone signoff, record, and manifest
	  trusted-reviewer validators use the same preflight before stale signed
	  objects can mask malformed trust anchors. Standalone release-audit
	  manifest validation also applies the full reviewer public-key payload
	  preflight, so empty or all-zero manifest reviewer keys fail before
	  manifest digesting can bless malformed trust anchors. Soracloud's material and
	  execution public-input schemas now advertise the same
	  `rejects_placeholder_reviewer_ids` release-audit contract and pin the
	  updated schema hashes. Signoff payload construction now
	  preflights the caller-supplied reviewer id/key and external report/archive
	  digests before stale evidence can mask malformed operator inputs.
	  Release-audit record and package construction also reject malformed
	  reviewer ids, non-Ed25519 reviewer signing keys, and all-zero Ed25519
	  reviewer private-key payloads before public-key derivation, evidence
	  derivation, or audit-byte validation.
	  Release-audit package construction now also runs the shared report/archive
		  byte-pair preflight, including edge-whitespace- and
		  alphanumeric-normalized copied-body rejection, before evidence
		  derivation or record signing can mask malformed external audit bytes.
		  Release-audit package validation and digesting now
	  also reject placeholder stored record/manifest digest sentinels before
	  canonical digest recomputation can collapse them into generic mismatch
	  diagnostics, and the material/execution public-input schemas advertise
	  those package digest sentinels plus caller-pinned record/manifest digest
	  alias rejection under pinned schema hashes. Package digesting now also
	  rejects tampered signed report/archive bytes through the same
	  report/archive digest mismatch gates as package validation.
	  Standalone release audit evidence validation rejects reused
	  artifact/profile/native-payload commitments plus empty/all-zero and short,
	  long, padded, binary-decorated, case-decorated, or whitespace-prefixed
	  placeholder and delayed-content placeholder native-payload digest sentinels, including generated hyphen/dot/underscore separator-spelled handoff, draft,
	  `replace-me`, `changeme`, `stub`, `test-only`, `your-*`, `sample`, `template`, `example`, `not for production`,
	  `not production ready`, and `replace before production`
	  variants, and the material/execution public schemas
	  advertise the direct and whitespace-prefixed sample/template/example
	  native-payload digest sentinel gates explicitly,
	  governed full-bootstrap material digest admission rejects the same direct
	  and deterministic delayed-content
	  draft/not-for-production/replacement/handoff/sample/template/example marker family
	  before circuit material,
	  proof-key material envelope/profile metadata, blind-rotation accumulator
	  material, caller-expected material proof-profile digests, material/execution
	  proof-input statement hashes, public-padding AIR rows, release-audit evidence,
	  signoff, manifest, or caller-pinned package digest slots can pass,
	  standalone record construction
	  plus signoff/manifest validation rejects known header-only, nested-header,
	  whitespace-prefixed nested-header, padded zero/blank-body, and
	  short/long/padded/binary-decorated/case-decorated/whitespace-prefixed
	  placeholder report/archive digests, including generated hyphen/dot/underscore
	  separator-spelled audit-artifact marker variants for handoff/sample/template/example
	  families plus draft, `not for production`, `not production ready`, and
	  `replace before production`,
	  public schemas advertise package-level header-only,
	  nested-header, whitespace-prefixed nested-header, zero-body, blank-body,
	  padded zero/blank-body, and
	  placeholder/case-decorated/whitespace-prefixed/delayed-placeholder external-digest
	  rejection,
	  shared body extraction enforces
	  nested, whitespace-prefixed nested, full-body delayed-placeholder, and
	  delayed sample/template/example audit-artifact body rejection before native
	  material or execution proof generation, the material-native AIR builder replays generated
	  envelope bytes against the governed material AIR context before wrapping, and
	  the internal typed prover-input path still requires the
	  caller-supplied verifier key to match the verifier proof key embedded in the
	  release prover package.
	  Core typed material proof helpers now derive and validate typed input
	  material before emitting a material-native STARK/FRI proof; the hash-only
	  material/execution constructors are crate-scoped internal compatibility
	  helpers that remain fail-closed at the dedicated-prover boundary, leaving
	  release-audit-gated entry points as the public production prover surfaces.
	  The typed execution proof helper derives and validates the canonical row-major
	  arithmetic trace material from proof input, then emits a finalized
	  BFV-native execution proof attachment, so stale governed material, witness,
	  statement material, or native trace rows are rejected before proof generation
	  succeeds.
  Release tooling can now derive governed full-bootstrap circuit material
  directly from a concrete artifact bundle; the crypto helper recomputes every
  artifact digest, proof-key material commitment, and generated pair commitment
  before validating the bundle against the derived material. Derivation now also
  rejects stale proof-key pair commitments even when the individual proof-key
  material commitments have been refreshed, and the crypto/Core fixture helpers
  no longer synthesize malformed sample pair commitments.
  Torii signed-request preflight coverage now also rejects full-bootstrap
  artifact attachments outside full-bootstrap context and binds a matching
  signed material digest to a role-swapped artifact envelope before rejecting
  the wrong declared role or stale prover/verifier key-material commitments
  locally before instruction construction. Torii and production
  `RunSoracloudFheJob` admission now also require `FullBootstrapV1`
  artifact-backed jobs to carry a policy-pinned release-audit package, package
  digest, trusted reviewer id, and reviewer public key before exact or bounded
  artifact execution can dispatch through the release-audit-gated crypto
  helpers, and the policy/runtime package-digest gates now reject
  leading-whitespace delayed-placeholder sentinels before generic mismatch
  diagnostics; the shared Core artifact preflight now preserves artifact
  drift/role/key-material diagnostics first, then rejects valid artifacts
  without that runtime context before exact/bounded bound propagation or
  execution. The
  raw artifact-aware crypto execution/bound helpers are crate-private, so
  external Core/STARK fixture builders use the release-audited helper surface
  rather than a public unaudited artifact path.
  The legacy no-artifact Core execution helpers are test-only, so production
  full-mode jobs must pass through the governed artifact-aware path; the
  no-artifact residual-bound wrapper is also test-only, keeping the non-test
  Core path on artifact-aware execution and bound propagation.
  Refresh-only proof and execution paths still reject `FullBootstrapV1`.
  Core full-bootstrap proof constructors now also reject zero statement hashes
  after verifier-key profile admission and before the dedicated arithmetic
  prover boundary, so release prover tooling cannot request a proof for an
	  empty public statement. The material and execution proof statement materials
	  now also carry their advertised layout versions and field counts inside the
	  canonical hashed bytes, and the Soracloud public-input schemas advertise
	  those self-describing headers. The material proof public-input schema and
	  stable hash now also advertise the typed material proof input contract and
	  release audit package caller-pinned digest enforcement,
	  including governed full-bootstrap material, public-key, evaluation-key,
	  concrete artifact-bundle, statement-hash, and material proof input package
	  digest-domain bindings. Crypto now exposes a domain-separated Norito digest
	  helper for that typed material proof input package, with regressions pinning
	  the digest to the encoded self-describing Norito proof-input material.
	  Public proof input
	  material validation also rejects zero statement hashes, malformed public-key shapes, and material
	  prover artifact bundles that do not match governed material before release
	  prover tooling can hand typed material to the future arithmetic backend, and
	  Core now pins those typed-material rejection cases at the runtime prover
		  boundary. The full-bootstrap execution public-input schema and stable hash
		  now also advertise the arithmetic trace private/public row policy, the
		  BFV arithmetic AIR contract layout/enforcement flags, including
		  row-kind partitioning, active-row/witness consistency, full-bootstrap
		  arithmetic constraints, nonzero statement hashes, and trace output/bound
		  claim matching, the duplicate-free opening policy, the proof-key-bound
		  release prover input package, the execution proof input package digest
		  domain, release-prover AIR constraint-system digest/artifact binding,
		  release audit package caller-pinned digest enforcement with zero and
		  placeholder pinned-digest rejection, and execution proof-input package
		  digesting now pins the encoded self-describing Norito proof-input
		  material under its dedicated domain before release prover
		  verifier-key binding. The arithmetic trace material, AIR evaluation
		  material, and proof-key-bound execution prover-input package digests
		  are likewise pinned to encoded self-describing Norito material under
		  their dedicated domains before verifier-key binding. The typed crypto
		  schema validates those AIR
		  contract, release-prover, execution proof input package digest-domain,
		  artifact-bound prover-input validation, stale Galois-key-set replay
		  rejection, and stale proof-key artifact replay rejection terms directly;
				  release-audit proof-profile evidence now also advertises those replay
					  policy and AIR evaluation material layout/digest/zero-composition
					  terms, native proof-circuit fingerprint material binds the replay-policy
					  terms with field count 48, and native payload regressions pin the
					  generated circuit body raw SHA-256 digest to canonical body bytes plus
					  embedded canonical AIR material bytes, native proof-key material
					  decoding rejects alternate structurally valid Norito framing around
					  the canonical native payloads, generated circuit-body validation
					  rejects alternate Norito framing around the body and embedded AIR
					  material, proof-key material envelope decoding
					  rejects alternate structurally valid Norito framing around canonical
					  native material before key-material commitments can hash it, and the
			  AIR constraint-system digest is now bound through the typed public schema,
		  native prover/verifier payloads, proof-key material envelope, native
		  proof-key material, and native proof-circuit fingerprint. Schema artifact
		  admission now also rejects structurally decodable alternate Norito framing
		  by requiring exact canonical uncompressed v1 schema payload bytes. The AIR
		  constraint-system artifact decoder applies the same canonical uncompressed
		  v1 payload-byte rule after typed AIR validation, and proof-key artifact
		  admission now requires canonical uncompressed prover/verifier key payload
		  bytes after typed key validation, including the registered-profile
		  artifact-derived commitment helpers. The evaluator artifact decoders
		  apply the same canonical uncompressed v1 payload-byte rule to linear
		  transforms, blind rotation, accumulator material, and sample-extraction
		  metadata/switch keys after typed validation. Governed artifact envelope
		  bytes now also have to match the canonical uncompressed v1 envelope
		  encoding before bundle validation, evaluator-set digesting, or
		  artifact-derived proof-key commitment helpers can accept them. The AIR constraint-system
		  material is also a public typed Norito artifact with a canonical validator
		  and digest-from-material helper, so release tooling can reject stale
		  contract material before accepting generated prover/verifier artifacts.
		  Core execution prover preflight converts the sole governed BFV-native
		  verifier-key wire payload into its deterministic internal STARK key before
		  matching caller-supplied internal verifier keys against release-prover
		  input proof-key material or artifact-derived governed verifier keys.
	  Full-bootstrap release artifact bundles now also carry the arithmetic AIR
	  constraint-system material as a governed artifact envelope; circuit
	  material and artifact-bundle digests bind that envelope, bundle validation
	  decodes the inner typed AIR contract material, and the public execution
	  proof schema advertises that artifact-bundle AIR binding explicitly. The
	  shared governed-artifact payload guard now also rejects blank text plus
	  placeholder, pending/TODO, handoff, non-production, template, and example
	  sentinels before role-specific Norito decoding, while keeping
	  sample-extraction role names admissible.
	  Full-mode bootstrap keys now also carry a domain-separated BFV public-key
	  digest, and material/execution statement derivation rejects governed
	  public-key drift before material hashing, witness hashing, or Core
	  proof-helper execution. Execution witness material validation now also
	  recomputes the artifact-bundle digest implied by governed full-bootstrap
	  material commitments, including the arithmetic AIR constraint-system
	  artifact digest, so nonzero stale artifact-bundle digests fail before
	  public witness hashing or release-prover input packaging, reconstructs the
		  raw extracted sample and raw-sample bound from the blind-rotation stage, and
		  recomputes the deterministic coefficient-zero repack ciphertext plus the
		  coefficient-zero and sample-switch bounds from the raw extracted sample
		  before accepting typed witness material.
		  Core's shared FHE STARK native-envelope preflight now rejects
		  blank text bodies plus case-insensitive placeholder,
		  non-production, handoff, sample, template, and example sentinels, including
		  dash/underscore variants, before Norito decoding. Data-model material and
		  execution proof validation plus Core material/execution preflight also pin
		  binary-fragmented placeholder text, including marker tokens split across
		  non-text bytes, so `0xff`-split native-envelope attachments fail closed
		  at the raw native-envelope boundary. The material and execution
		  public-input schemas now also advertise their dedicated
		  native-AIR envelope contracts, including statement-bound domain tags,
		  governed trace/composition root replay, query/opening count, Merkle/FRI
		  binding, auxiliary composition sidecar rejection, verifier-owned
		  trace-material replay for execution, and the same placeholder
		  native-envelope text gates.
			  BFV-shaped native AIR envelopes now also preflight the canonical
			  base transcript label, including rejection of suffixed-label aliases,
			  nonzero statement hash, statement-bound domain tag,
			  STARK/FRI parameters, public digest binding, proof/commitment version tags,
			  commitment/root shape, exact duplicate-free canonical opening/query count,
				  opened row/path shape, Merkle path-to-root binding, FRI query-chain
				  Merkle/fold validation, auxiliary generic composition-value commitment
				  rejection, AIR-to-FRI base value binding, opened public padding-row
			  semantics, and the
				  no-unmasked-private-row plus duplicate-free opening policies before Core
				  accepts governed execution proof attachments; a structurally valid
				  generic-AIR proof under the canonical BFV transcript label but with
				  private-row openings now stays rejected at that BFV-native boundary.
				  The shared BFV-native verifier also exposes a public-padding
				  entry/context path that rejects zero, direct-placeholder,
				  delayed-placeholder, and separator-spelled placeholder
				  statement hashes and checks the canonical parameter-profile/domain-tag,
				  same statement hash, public slot-capacity/bound-mode header,
				  canonical public openings, and zero public composition samples
				  without private row-major trace material; Core's active
				  full-bootstrap execution admission now consumes that shared verifier before the governed
				  trace/composition replay, and the
				  release-prover trace-material replay helper now uses the same
				  public-padding gate before explicit row/composition verification.
				  The public-padding path now also preflights the advertised
				  trace-material digest through the transcript-derived opening
				  schedule, so zero, direct-placeholder, delayed-placeholder, or
				  separator-spelled placeholder public trace digests cannot reach
				  generic envelope replay;
				  Soracloud native BFV AIR boundary
				  coverage now pins the same
				  zero/direct/delayed-placeholder/separator-spelled public
				  trace-digest rejection before release-prover envelopes are accepted.
				  Native AIR proof synthesis now also rejects nonzero final FRI folds
				  before BFV-native or public explicit-AIR proof bytes are returned.
					  Execution native-AIR builder replay also rejects trace-root,
					  composition-root, FRI base-root, row-Merkle sibling, and first-layer
					  FRI value drift before BFV-native proof wrapping; the active verifier
					  and `zk-preverify` cache path now pin sampled row-path shape/root and
					  first-layer FRI decommitment drift before proof acceptance.
				  Generic STARK `OpenVerifyEnvelope` construction and verification now
				  reserve the BFV full-bootstrap circuit id for that BFV-native path,
				  and public generic AIR constructors plus crate-visible
				  row/composition AIR builders reject those circuit aliases before
				  envelope synthesis unless the call goes through an explicitly named
				  reserved-circuit helper, so native full-bootstrap proof attachments
				  cannot be admitted through the generic binding AIR fallback without
				  the public-padding opening checks, including bare `stark/fri` and
				  alternate production-profile aliases; the active BFV native AIR
				  regression now also rejects
				  duplicate or truncated sampled public-padding opening sets at both
				  the public-padding and artifact-bound verifier boundaries.
				  Shared `OpenVerifyEnvelope` admission also enforces public-input
				  byte bounds before rejecting all-zero public-input metadata, so
				  placeholder schema or statement bytes cannot enter the generic
				  preverify/dedup cache path.
				  Soracloud BFV input-admission, bootstrap-key, full-bootstrap
				  material, and execution proof attachments now pin the canonical
				  BFV STARK/FRI backend
				  (`stark/fri/poseidon-x7-goldilocks-6x64-v1`) in validation and in the advertised
				  public-input schema descriptors, so alternate production STARK
				  profiles cannot replay governed BFV attachments.
				  BFV full-bootstrap proof-key profile validation now also rejects
				  known placeholder/draft/not-production sentinel hashes in the
				  registered parameter/RNS/decomposition profile, pair, and material
				  commitment slots before commitment recomputation or governed
				  material matching, and generated proof-key construction no longer
				  uses a known pending material-commitment sentinel while deriving
				  canonical pair and per-key commitments. Public proof-key material
				  and pair commitment derivation now also reject empty, all-zero, and
				  placeholder material bytes before hashing them.
				  Artifact-aware BFV execution witness validation now reports the first
				  mismatched governed trace/bound field, and regressions pin diagnostic
				  slot-to-coefficient plus sample-switch output drift as artifact-only
				  replay failures rather than shape-only witness-material failures.
				  Non-generic full-bootstrap native envelopes with
				  missing or foreign AIR sections now fail before governed native-AIR
				  acceptance, and Soracloud native-envelope admission plus the
					  Core/Torii shared FHE native-envelope preflight now scan each
					  printable span inside mixed binary envelope bytes so handoff markers
					  separated from metadata by binary framing cannot bypass placeholder
				  rejection; the data-model and Core matchers cache collapsed
				  marker material so large binary artifacts do not rebuild marker
				  variants per span.
				  Core's BFV-native AIR fixtures now use a deterministic
			  STARK/FRI envelope builder that commits caller-validated trace rows and
			  explicit typed AIR evaluation composition values, then derives
			  transcript-sampled AIR openings from the same FRI query roots that the
			  verifier replays. The AIR residual evaluator now validates every opened
			  row coordinate as a canonical Goldilocks field element before returning
			  the first nonzero coordinate residual, so malformed tail coordinates
			  cannot be masked by an earlier mismatch and coordinated same-row trace
			  drifts cannot cancel back to a zero composition value. The active Soracloud
			  verifier path now reconstructs the governed arithmetic trace and AIR
			  evaluation material from the public execution proof input, then rejects
			  trace/composition root drift plus opened rows, next rows, or
			  composition values that do not
				  match that verifier-derived material before reaching Merkle/FRI checks.
				  Active execution verification now also treats those governed rows and
				  composition values as required verifier context, so boundary-valid
				  native AIR cannot skip explicit row/composition replay by omitting
				  verifier-derived material.
				  The shared `zk_stark` verifier now also has an explicit
				  rows/composition entry point that recomputes caller-owned trace
				  and composition roots, checks circuit-id/public-digest binding,
				  and rejects sampled row, next-row, or composition-value drift
				  before accepting the existing FRI fold path; the active
				  release-prover BFV execution verifier calls that shared verifier
				  after its BFV-native boundary preflight and the configured STARK
				  enablement plus public-wrapper/native-envelope byte caps.
				  The governed material-native AIR path now uses the same explicit
				  verifier corridor with verifier-reconstructed zero composition
				  values, preserving the v1 FRI final-zero invariant while binding
				  typed material through reconstructed trace and composition roots.
				  The Soracloud release-prover handoff now builds that BFV-native
				  envelope directly from
				  `BfvFullBootstrapExecutionProverInputMaterialV1`, while the test-only
				  typed input-material prover covers
				  `BfvFullBootstrapExecutionProofInputMaterialV1` fixture boundaries.
				  Both finalize execution proof attachments and canonicalize governed
				  native verifier-key payloads to the runtime STARK verifier-key
				  commitment.
				  The BFV AIR
			  composition evaluator derives its per-row/column challenges from the
			  public statement hash, canonical row-major trace-material digest, row
			  index, and column index, remapping zero challenges to one so residuals
			  are bound to the evaluated witness package and rejecting zero,
			  direct-placeholder, or leading-whitespace delayed-placeholder digest
			  inputs before challenge reduction. The typed AIR contract
			  material and Soracloud execution proof public-input schema now
			  advertise that challenge domain, full 32-byte digest reduction, and
			  binding policy explicitly with AIR material field count 33 and
			  refreshed stable schema hashes, so stale
			  schema bytes fail stable hash and validator checks before release
			  tooling can present them. The
			  release artifact layer also emits deterministic audit evidence that
			  binds the generated artifact-bundle digest, evaluator artifact-set
			  digest, prover/verifier pair commitment, native payload digests, native
			  circuit fingerprint, and proof-profile field counts before the bundle
			  can be published, with a public validator for release tooling to reject
			  forged evidence records before digesting them. Evidence, record,
			  manifest, and package digest regressions now pin encoded
			  self-describing Norito payloads under their dedicated release-audit
			  digest domains instead of relying only on canonical roundtrip
			  stability. Release tooling can also
			  sign that evidence together with the external audit report and archive
			  digests, so stale reviewer identities, reused audit hashes, wrong
			  reviewer keys, tampered payloads, evidence drift, and artifact drift
			  fail before signoff is accepted; consumers can rederive the evidence
			  from governed material and concrete artifacts instead of trusting a
			  separately supplied evidence object. The evidence and reviewer signoff
			  are also packaged into a canonical release audit record with its own
			  digest domain, so release archives can publish one self-consistent
			  object and reject stale record headers or mismatched evidence/signoff
			  pairs. The release audit package now carries the external report and
			  evidence archive bytes themselves, hashes them against the signed
			  record with digests pinned to canonical headered artifact bytes rather
			  than body-only hashes, enforces bounded report/archive sizes, and rejects empty,
			  all-zero, unheadered, header-only, whitespace-prefixed nested-header,
			  blank-body, sub-64-byte, zero-body, delayed placeholder-body,
			  tampered, or missing audit artifacts before publication. It also carries a
			  machine-checkable release audit manifest plus manifest digest that bind
			  the approving verdict, canonical audit scope, signed record digest,
			  evidence, artifact, evaluator-set, proof-key, prover/verifier-key,
			  native-circuit, and report/archive commitments, and reviewer id/key
			  before publication. Package consumers can now require the caller-supplied
			  trusted reviewer id and public key, and crypto exposes canonical
			  release-audit evidence, signoff, record, manifest, and package byte
			  decode/digest helpers that reject alternate structurally valid Norito
			  framing before caller-pinned audit bytes are hashed, so a self-consistent
			  package signed by an untrusted reviewer key, a stale manifest, or
			  noncanonical audit framing still fails before
			  publication. Core's audited material and execution prover wrappers now
			  revalidate that package against governed full-bootstrap material,
			  concrete artifacts, the caller-trusted reviewer id/key, and the
			  caller-pinned package digest before emitting native BFV proof
			  attachments. Those audited wrappers now also preflight the refresh
			  transcript public-key digest against the governed `FullBootstrapV1`
			  bootstrap key before release-package validation or proof generation
			  continues, and Core regressions pin delayed report/archive nested
			  audit-header splices at those wrapper boundaries before material or
			  execution proof generation starts. Externally held execution witness, proof-input, and
			  release-prover input material now also have artifact-aware validators
			  that recompute the governed prefix trace from concrete artifacts and
			  Galois keys and require prover/verifier proof-key bytes to match the
			  governed artifacts before callers rely on those packages; typed
			  release-prover packages also reject prover/verifier proof-key role
			  transposition before digesting, and material-proof plus
			  artifact-aware execution package replay rejects caller-supplied BFV
			  parameter-profile, bootstrap-key, artifact-bundle, proof-key artifact,
			  and Galois-key-set retargeting;
			  material-proof caller-bound replay also rejects public-key,
			  governed-artifact, and evaluation-key retargeting.
				  Core's release-prover execution proof handoff now invokes that
				  artifact-aware prover-input validation before native AIR envelope
				  emission, so self-consistent stale prefix traces, caller-owned
				  stale Galois-key sets, and stale proof-key artifacts fail against
				  the governed artifacts.
				  The lower-level material prover rejects stale proof-key artifacts
				  before deriving material proof input material.
				  The lower-level execution proof helper rejects stale proof-key
				  artifacts before deriving per-slot proof material.
				  Release-audit-gated material and execution provers also reject
				  stale proof-key artifacts at the audit package boundary before
				  native proof material is emitted.
				  Standalone release audit evidence validation now also recomputes
				  the evaluator-artifact-set digest, full artifact-bundle digest,
				  and canonical native proof-circuit fingerprint from its advertised
				  fields, so stale-but-distinct digest summaries or matched stale
				  prover/verifier fingerprint summaries fail before evidence is
				  treated as shape-valid. Standalone signoff payloads and
				  machine-checkable manifests now also recompute that canonical
				  native proof-circuit fingerprint from the release circuit id before
				  accepting or digesting the object, and reject external audit digest
				  aliasing with signed release commitments.
					  Material and execution public-input schemas now advertise that
					  report/archive artifacts must carry canonical v1 audit byte headers
					  with nonempty, nonblank, nonzero, at-least-64-byte bodies and
					  no nested canonical audit headers after leading body whitespace,
							  plus distinct report/archive body content after edge-whitespace and
							  alphanumeric normalization before packages can be hashed, signed, or
							  consumed by audited prover wrappers.
					  The shared explicit STARK AIR builder now self-verifies generated
					  row/composition envelopes before returning proof bytes to BFV native
					  AIR callers, the Soracloud release-prover handoff replays encoded
					  envelope bytes against the exact typed trace rows and AIR evaluation
					  composition values before returning proof bytes, the lower-level BFV
					  native AIR proof builder is crate-scoped so public callers stay on
					  Soracloud's artifact/release-audit-aware paths, and crypto now exposes
					  a trace-bound AIR evaluation digest path that hashes only after the same
					  composition-vector validation plus artifact-bound witness, proof-input,
					  and release-prover digest paths that hash only after prefix-trace replay.
						  The active release-prover execution verifier path now also rejects
						  composition-root reconstruction drift and FRI
						  base-root/composition-root mismatch plus sampled row-path shape/root and
						  first-layer FRI decommitment drift before native proof acceptance,
						  including when a poisoned `zk-preverify` cache claims the retargeted
						  release-prover proof bytes are already verified.
						  Material native-AIR replay regressions now also pin
						  composition-root reconstruction drift, FRI
						  base-root/composition-root mismatch, and sampled governed-material
						  opening row, next-row, composition-value, Merkle path-shape, and
						  Merkle row-path drift before wrapping material proof bytes.
						  Material-proof input digests now also have a caller-bound path that
						  reconstructs the package from caller-owned evaluation keys and artifacts
						  before hashing, and Core's material native AIR handoff consumes that
						  caller-bound digest before proof emission. Core's execution native AIR
						  handoff consumes the artifact-bound release-prover digest before proof
						  emission as well. The material and execution native AIR proof wrappers
						  also decode the native STARK/AIR envelope before attachment
						  construction and reject transcript-label, circuit-id, missing-AIR-section,
						  or public-digest/statement-hash drift before proof validation can rely on
						  the wrapper. Core's material and execution full-bootstrap proof gates
						  now share the same statement-bound `OpenVerifyEnvelope` preflight for
						  canonical STARK backend, circuit id, public-input schema, wrapper
						  version, statement-hash public inputs, and native envelope byte checks
						  before dedicated AIR verification. Execution witness material now also binds a
						  domain-separated Galois-key-set digest that canonicalizes by
						  automorphism power, and artifact-aware witness replay rejects
						  same-shape stale Galois-key substitutions before proof-input or
						  release-prover package hashing can rely on them.
					  The shared
					  STARK/AIR prover and verifier derive duplicate-free query schedules by
						  bound-specific transcript rejection sampling without replacement,
								  require noncanonical transcript labels, malformed domain tags,
								  and malformed AIR or verifier-key circuit ids to fail closed before query replay or envelope verification,
								  keep caller-provided verifier limits from relaxing canonical
								  STARK structure and envelope-byte caps, and reject
								  blowup/domain parameter pairs where `blowup_log2`
								  exceeds `n_log2` before proof synthesis, verifier-key
								  admission, or envelope verification,
						  while failing closed when a duplicate-free schedule cannot exist, so
						  duplicate openings cannot reduce effective sampling. The BFV material and execution native-AIR builders
						  still retry bounded material/statement-domain query nonces for privacy-policy
						  public-row constraints, and the material verifier accepts only
						  nonce-bound material domain tags derived from the statement hash and
						  caller-bound material-input digest. The ZK-ACE native AIR prover uses the
						  same duplicate-free query validator plus encoded-envelope
						  self-verification before returning proof bytes. BFV native
						  STARK/FRI proof-key material, verifier payloads, and release-audit
						  proof profiles also reject blowup/domain parameter pairs where
						  `blowup_log2` exceeds `n_log2` before key material or evidence can be
						  admitted. Shared STARK/FRI verification keeps auxiliary generic
						  composition payloads (`comp_root`/`comp_values`) scoped to the
						  generic binding AIR context and rejects them for caller-owned
							  explicit AIR and ZK-ACE AIR before statement replay, and generic
							  sidecars must rederive the AIR public digest from strictly ordered
							  auxiliary terms before their composition leaf is accepted.
							  Caller-owned explicit AIR trace roots also reject non-canonical
							  Goldilocks row elements before hashing, so malformed row material
							  cannot be bound under an otherwise valid explicit AIR verifier
							  context. STARK
						  `OpenVerifyEnvelope` wrapper verification rejects inner auxiliary
						  sidecars for both generic binding and ZK-ACE wrappers, keeping
						  generated wrapper proofs canonical. Generic STARK
						  `OpenVerifyEnvelope` construction and verification also require
						  verifier-key payloads to meet the ledger-grade production FRI
						  floor and verifier-key backend labels to exactly match the
						  requested proof backend before wrapper proofs can be emitted or
						  accepted. Governed
						  full-bootstrap material admission rejects
						  known nonzero pending, placeholder, native proof-key payload,
						  draft, not-for-production, and replacement digest literals before artifact,
						  including direct `0xff`-framed and delayed `0xff`-framed
						  forms of those known placeholder preimages plus evaluator-artifact-set
						  domain-scoped `0xff`-framed transient digests,
						  while native payload and external audit artifact digest
						  sentinel tables reject delayed binary-framed variants too,
						  and Soracloud execution-policy admission rejects direct,
						  delayed, and leading-whitespace delayed `0xff`-framed
						  caller-pinned release-audit package digest placeholders before
						  package validation or digest mismatch can mask policy errors,
						  proof-key pair, key-material envelope/profile metadata, blind-rotation
						  accumulator material, coefficient/slot linear-transform diagonals,
						  sample-extraction switch-key digit limbs, wrong-secret and
						  key/sample-mismatch sample-switch diagnostics,
						  all-zero/malformed/stale
						  evaluator artifact-set envelopes, opaque evaluator artifact payloads,
						  placeholder or duplicate evaluator/bundle digest-material fields,
							  extra, missing, or stale full-bootstrap execution Galois keys,
							  malformed same-schedule full-bootstrap Galois key-switch entries
							  before ciphertext or bound metadata use, inert all-zero
							  Galois/relinearization key-switch entries,
						  BFV public-key digest, seeded-encryption, identifier
						  public-parameter/ciphertext slots, all-zero BFV public-key
						  components, bootstrap statement,
						  full-bootstrap material statement, refresh-transcript,
						  public/secret consistency public-key material, all-zero secret-key material, and
						  full-bootstrap execution claim/trace ciphertext and raw-sample
						  material,
						  bootstrap public-key digest metadata,
						  evaluation-key bundle digest refresh masks, bootstrap
						  zero-refresh proof-statement refresh ciphertexts,
						  aliased execution witness digest commitments,
						  caller-expected material proof-profile digests,
						  material/execution proof-input statement hashes, public-padding AIR rows,
						  or release-audit evidence commitments
						  can be accepted, including standalone release-audit signoff and
						  manifest commitments, release-audit key evidence and native proof-key
						  material admission reject placeholder key digest/material commitments
						  plus oversized raw native proof-key payloads before placeholder
						  scanning, raw native proof-key payload placeholder text, and inert
						  native-payload digest sentinels including generic proof-key
						  payloads and generated hyphen/dot/underscore separator-spelled
						  sample, template, and example placeholder payloads. Native-payload,
							  material, and report/archive inert/placeholder artifact digest gates now
							  use deterministic cached sentinel tables for repeated admission
							  checks, and execution proof
							  statement hashing rejects the known pending, delayed, or transient
								  pre-finalization execution witness digest literals. Generated
								  execution claims still use that transient value only internally
								  before deriving the governed digest. The BFV native
							  STARK/AIR prover/verifier wrapper now derives the domain tag from
								  the crypto-canonical execution statement hash, pins the BFV
								  native AIR transcript label to the canonical base label, rejects
								  suffixed-label alternate proof encodings, requires the canonical
								  circuit id and FRI profile, and rejects sampled openings unless they are the
						  statement-bound public-padding rows. The Core execution native-AIR
						  boundary now also requires governed trace rows and AIR composition values
						  plus the pinned governed trace-material digest before root
						  reconstruction, sampled opening replay, Merkle/FRI validation,
						  or dedicated-verifier fallback, so public-padding-only context cannot
						  drive BFV-native proof admission. The Soracloud execution proof
						  wrapper replays the same canonical base-label preflight before
						  packaging native AIR envelopes into execution proof attachments, so
						  suffixed-label BFV envelopes cannot enter runtime proof admission
						  through the wrapper path; the typed crypto proof public-input
						  schema and execution public-input schema both require
						  `requires_canonical_base_transcript_label` and
						  `rejects_suffixed_transcript_label_aliases` under the pinned
						  execution schema hash. Release-audit reviewer admission now
						  also requires Ed25519 reviewer public keys across signoff, record,
						  manifest, and package validation, rejects empty or all-zero reviewer
						  public-key payloads before stale signed objects can mask malformed
						  trust anchors, and record/package construction
						  fail-fast on non-Ed25519 reviewer signing keys or all-zero Ed25519
						  reviewer private-key payloads before public-key derivation, evidence
						  derivation, or audit-byte validation. Release-audit signoff validation
						  now also routes reviewer signatures through Ed25519 signature
						  admission, rejecting all-zero, short, small-order, or noncanonical
						  payloads before backend verification; the Soracloud full-bootstrap schemas advertise the
						  Ed25519 trusted-reviewer payload contract. Soracloud FHE execution-policy
						  validation now uses the same crypto reviewer-id and reviewer-public-key
						  preflights, so placeholder reviewer ids fail on the trusted-reviewer
						  policy field before package-level matching, and Core's full-bootstrap
						  release-audit runtime context replays that preflight before governed
						  artifact execution while the shared Core artifact preflight rejects
						  valid artifacts if that context is absent after preserving narrower
						  artifact-shape diagnostics. Raw
						  artifact-aware crypto execution and bound helpers are crate-private, so
						  external Core/STARK fixture builders route through release-audited helper
						  calls. The material and execution public-input schemas
						  also mirror the release-audit evidence/signoff/record/manifest,
						  proof-profile, native-payload text/digest sentinel, artifact-binding,
						  trusted-reviewer, and printable-ASCII reviewer-id-labelled
						  external-review marker subcontracts that reject bare reviewer-id
						  prose, duplicate or conflicting reviewer-id labels, case-drifted
						  or separator-alias reviewer labels, and padded-colon marker
						  aliases under the pinned material
							  `fdfe1d3454a0f3fac98684f24af74bbb0286dda732e7d34e1d99677fcbbc5acb`
							  and execution
							  `0f8fcf3c6cb5f2889d471dc7b656d8f6174289ce0d1ab40b13076da5fdd5443d`
							  schema hashes. Crypto now also exposes release-audit-gated
						  exact and bounded artifact-aware execution and bound helpers,
						  requiring the caller-trusted reviewer id/key and caller-pinned
						  package digest to validate before governed artifact execution or
						  public bound propagation can proceed, and Core's release-audited
						  execution prover now recomputes caller-supplied outputs and
						  bounds through those audited helpers before native proof
						  construction. Release-audit report and
						  evidence-archive bodies now reject canonical audit artifact headers anywhere
						  in the body plus delayed handoff/sample/template/example markers before native
						  proof generation. Digest-only gates keep the known header-start,
						  whitespace-prefixed nested-header, and deterministic delayed-placeholder
						  sentinels, while delayed nested-header rejection is advertised only for
						  byte-bearing audit artifacts.
					  BFV full-bootstrap proof-key profile validation also rejects
					  known placeholder/draft/not-production/handoff/sample/template/example
					  sentinel hashes plus internal transient before-finalization
					  commitment hashes in the registered parameter/RNS/decomposition profile, pair, and
					  material commitment slots before commitment recomputation or
					  governed material matching. Native AIR verifier opening schedules
					  are now transcript-derived from the statement hash and row-major
					  trace-material digest, rejection-sampled into public padding rows
					  under a deterministic attempt cap, exact-order validated before
					  proof-backend consumption, and replayed against opened public
					  padding `row`/`next_row` values, slot index, and proof bound mode.
							  The typed AIR contract material, proof public-input schema, native
								  generated circuit bodies, proof-circuit fingerprints, and
									  proof-key material envelopes now bind that opening-schedule/public-padding
									  replay plus typed public-opening material validation and
									  Merkle/FRI/artifact-replay policy, including canonical
									  base transcript-label enforcement, suffixed-label alias rejection,
									  and generated circuit-body fields for artifact-bound prover input,
									  stale Galois-key set replay, and stale proof-key artifact rejection, so
								  governed prover/verifier artifacts cannot describe a weaker circuit.
						  The remaining native-AIR gap is arithmetic proof-producing
						  soundness plus externally audited release artifacts. The
						  transcript-bound opening schedule, composition-vector, challenge,
						  BFV wrapper public-opening, Merkle/FRI replay, caller-limit-aware
						  Core replay, and artifact-aware Galois-key-set digest preflight
						  corridors are already shipped. Direct artifact-aware exact and bounded
							  full-bootstrap prefix constructors now also validate the constructed
							  trace, aggregate prefix-bound vectors, and assembled witness material
							  before returning them, and direct/artifact-aware execution preflight
							  rejects inert all-zero ciphertext inputs before artifact fallback or
							  prefix execution, so inert all-zero trace material, invalid propagated
							  bounds, stale witness packages, or placeholder ciphertext inputs cannot
							  bypass the executable crypto boundary.
				  Release-prover input regressions now also pin all-zero
				  arithmetic trace material and arithmetic AIR contract digest
				  sentinel rejection before stale digest comparisons.
				  Core BFV-native public-padding verification now also rejects
				  auxiliary generic composition sidecars before treating an AIR
				  envelope as a canonical public verifier proof, and malformed
				  proof/AIR metadata, opening-path/sample drift, parameter-profile
				  drift, and caller limit regressions now pin the same public-padding
				  rejection boundary. Crypto-side public-opening schedule tests also
				  reject zero trace-material digests, direct/delayed/separator-spelled
				  placeholders, binary-framed `0xff` placeholder trace digests,
				  placeholder statement hashes, missing next-row openings, and stale
				  caller slot/bound-mode context before Core verifier use. Typed
				  public-opening material now packages
				  that transcript-derived schedule with opened public row/next-row
				  values, validates the material against trace-bound transcript
				  inputs, hashes it under a dedicated domain, and the execution
				  prover-input package now carries that material plus digest so stale
				  or trace-retargeted opening packages fail inside typed release-prover
				  validation. Core's artifact-bound BFV AIR verifier also compares
				  decoded native AIR openings against that typed package before
				  accepting the envelope. Its layout, domain, and replay obligation
				  are pinned into the release-prover contract digest. The canonical
				  proof public-input schema now also
				  advertises the same public-opening material layout, digest domain,
				  and typed replay obligation before generated proof-key artifacts
				  can bind stale schema bytes. Release-audit proof profiles, generated
				  report bodies, and generated evidence archives now sign and replay
				  that public-opening material layout/domain/obligation as part of the
				  audited proof-profile corridor. Proof-key metadata, proof-key material
				  envelopes, native generated circuit bodies, and native proof-circuit
				  fingerprints now also bind the typed public-opening material validation
				  obligation before proof-key material or generated native payloads are
				  admitted. Canonical governed circuit material, arithmetic
				  trace-profile material, AIR contract material, proof public-input
				  schema material, execution Galois key-set, artifact-bundle archive,
				  material proof-input, execution witness, execution proof-input,
				  trace, AIR evaluation, public-opening, and release-prover input
				  material byte admission now rejects compressed,
				  reordered, or otherwise noncanonical Norito framing before circuit
				  material, artifact-bundle material, Galois key-set, witness, material
				  proof-input, proof-input, or release-prover material bytes are hashed.
				  Release-audit key evidence now rederives the canonical
				  role-specific native prover/verifier payload digests from the audited
				  circuit id before evidence, signoff, record, or package validation can
				  accept signed native payload commitments. Signed release-audit payloads
				  and manifests now also repeat those canonical native prover/verifier
				  payload digests so reviewer signoffs and published manifests expose the
				  payload commitments directly. Release-audit evidence archives now also
				  repeat the signed canonical prover/verifier native payload digests so
				  externally reviewed archive bodies cannot omit or drift those payload
				  commitments while still carrying canonical payload hex. Soracloud
				  material/execution proof public-input schemas now mirror the same
				  release-audit contract with signoff payload count `18`, manifest count
				  `23`, and evidence-archive native payload digest requirements. Core BFV-native
				  governed AIR verification
				  now also requires a verifier-owned expected trace-material digest in
				  the public-padding context, so missing or mismatched digest pins fail
				  before governed trace row replay or preverify-cache use. The
				  canonical crypto proof public-input schema now advertises the same
				  verifier-owned trace-material digest obligation and rejects schema
				  downgrades before generated proof-key artifacts can bind stale
				  schema bytes.
				  Release-audit archive field-index tests
				  now also require native prover/verifier payload hex and generated
				  circuit body hex labels/values plus generic governed artifact hex
				  labels/values to be canonical lowercase, rejecting raw
				  native/generated/governed artifact bytes, separator-delimited byte
				  text, and duplicate governed artifact aliases before package-level
				  validation; generated/native payload archive validators now reuse
				  the governed artifact hex decoder before comparing decoded bytes.
				  Release-audit artifact placeholder scanning now also prefilters
				  bodies by possible marker-leading bytes before running the broader
				  case-insensitive and separator-spelled marker scans. Full-bootstrap
				  artifact-vector regressions now also pin marker tokens split across
				  non-text bytes at outer envelope, evaluator-set digest, builder payload,
				  and decoded inner-payload boundaries. Exact and bounded
				  release-audited runtime regressions now also prove deterministic
				  machine-generated release-audit packages with correct caller-pinned
				  digests cannot authorize execution or bound propagation before
				  external-review marker admission. Core's policy-pinned runtime
				  context now mirrors that gate before returning a release-audit
				  context to execution. The shared native STARK/FRI verifier now
				  also requires decoded proof envelopes to re-encode to the exact
				  submitted bytes, so compressed-but-structurally-valid BFV
				  full-bootstrap proof framing fails before AIR replay.
			  Remaining production work is the audited full-bootstrap arithmetic
			  proof-producing backend plus release-grade prover/verifier artifacts
			  and independent audit report/archive production with canonical v1
			  headers and nonzero generated-circuit bodies. The Core verifier,
			  proof-key/schema/native-envelope corridors, expected-circuit
			  native-payload byte preflight, release-audit package
			  builders, reviewed-byte tamper preflights, external-review marker
			  gates, native generated-body and circuit-fingerprint binding,
			  public-opening/native AIR replay, artifact-byte archive matching,
			  exact generated-body length scalars,
			  and policy-pinned Core/Torii runtime release-audit gate are already
			  shipped. Exact and bounded public-key/ciphertext proof statement
			  byte helpers now reject insufficient caller capacity or
			  over-capacity caller-declared bounds before public-key/ciphertext
			  byte decoding. Typed exact and bounded public-key/ciphertext
			  proof-input byte helpers now also reject malformed caller-owned
				  public keys or ciphertexts, insufficient caller capacity, or
				  over-capacity caller-declared bounds before proof-input byte
				  decoding. Exact and bounded public-key/ciphertext proof-input
				  byte tuples now also reject insufficient caller capacity or
				  over-capacity caller-declared bounds before caller-owned
				  public-key/ciphertext and submitted proof-input byte decoding;
				  ciphertext tuples admit caller-owned ciphertext bytes before
				  submitted proof-input bytes, matching the caller-owned
				  byte-tuple admission ordering. Typed
				  artifact-aware material-proof input helpers now also preflight
				  caller parameter, public-key, evaluation-key, and artifact-bundle
				  context before typed material headers. Full-bootstrap execution
				  witness, proof-input, and prover-input helpers now also preflight
				  caller bootstrap-key, artifact-bundle, and Galois-key context
				  before typed material headers or proof-key package comparisons.
				  Public-key-byte proof/prover input helpers preflight the same
				  caller artifact context before public-key or submitted input
				  byte decoding.
				  Witness-bound Galois key-set byte helpers likewise preflight
				  typed execution witness material before submitted Galois key-set
				  bytes.
				  Material-proof governance byte helpers also admit artifact-bundle
				  bytes before submitted proof-input bytes. Execution proof/prover
				  governance byte helpers likewise admit artifact-bundle and
				  Galois-key-set bytes before submitted proof/prover input bytes,
				  so malformed governed artifacts cannot be masked by malformed
				  proof packages.
	  Direct crypto
	  refresh-transcript validation/digesting and Soracloud transcript digesting
	  now also preflight the advertised BFV public-key shape
	  before evaluation-key bundle validation, so malformed transcript key material
		  cannot be masked by unrelated bundle-shape errors. Soracloud public
		  transcript metadata now mirrors crypto seed admission by rejecting all-zero
		  rotation and bootstrap transcript seeds before refresh-key recomputation or
		  unrelated bundle-shape errors, and the bootstrap-key zero-refresh public-input
		  schema advertises that all-zero transcript-seed rejection under the refreshed
		  pinned bootstrap-key schema hash. Scalar/RNS exact and bounded-noise
		  outer-slot rotation, refresh-only bootstrap execution, and residual-bound
		  diagnostic helpers now also reject inert all-zero refresh masks,
		  `zero_refresh` drift from `round_refreshes[0]`, plus duplicate or
		  all-zero per-round refresh ciphertexts before applying or summarizing
		  public refresh material. Core audited
		  release-package wrappers preserve field-level transcript diagnostics through
		  their exact/bounded fallback path and
		  reject all-zero rotation transcript seeds before native proof generation. The lower-level crypto
  bundle validator now enforces the same public metadata preflight for direct
  callers, relinearized multiply execution rejects malformed public
  relinearization digit inventories before malformed ciphertext operands, and
  direct Galois key-switch execution now rejects malformed key-switch entries
  before malformed ciphertext operands across exact, RNS, bounded-noise, and
  bounded basis-extension paths.
  Standalone refresh-key transcript
  generators/validators reject the same empty or oversized public seed
  metadata before deriving or recomputing encrypted-zero masks. Soracloud FHE
  execution policies now carry the refresh-transcript inventory digest,
  `RunSoracloudFheJob` signs the transcript inventory in the provenance
  payload, and core rejects jobs whose supplied refresh transcript is
  unbounded or does not match the governance-bound digest. This hardens the
  current refresh path while the full BFV bootstrapping engine remains open.
  Bundle-level owner diagnostics now also verify that relinearization entries
  decrypt to scaled `s^2` residues and Galois entries decrypt to scaled
  automorphed-secret residues under the matching secret key, with key-switch
  residuals constrained to the current plaintext-multiple error bound;
  standalone Galois key generation now applies that same residual self-check
  before returning generated key-switch material. Rotation and bootstrap
  encrypted-zero refresh diagnostics also reject zero-plaintext masks whose
  residual multiples exceed the deterministic `(2n + 1)E` refresh bound for
  the first-release seeded encryption format. The bounded-noise counterparts
  now also reject zero-plaintext rotation/bootstrap refresh masks whose
  centered rounded noise exceeds the fresh BFV noise bound, and bundle-level
  bounded diagnostics now identify indexed rotation/bootstrap refresh masks
  when nonzero plaintext or oversized rounded noise is detected.
  Public-key owner diagnostics now also reject shape-valid wrong-secret,
  non-plaintext-multiple, or oversized residuals before publication, while
  exact-lift and bounded-noise public-key proof statement digests now bind the
  parameter set, public key, and public-key digest under mode-separated
  domains, with Soracloud refresh-transcript helpers deriving the same
  statements and `SoracloudFhePublicKeyProofV1` validating the canonical
  `soracloud_fhe_public_key_v1` STARK/OpenVerify envelope, schema hash, and
  public-input shape for verifier-backed proof handoff. Core policy-bound
  admission now also requires and signs public-key proof attachments in FHE job
  provenance, derives the expected public-key statement from the refresh
  transcript, and validates active Soracloud verifier records before rejecting
  binding-only AIR at the missing key-generation witness AIR boundary.
  Shared FHE execution-policy validation, production FHE governance-bundle
  admission, Core FHE job admission, and Torii signed FHE job preflight now
  require `public_key_proof_statement_digest`; Core and Torii derive the same
  statement from the signed refresh transcript before admission, and the
  canonical Soracloud FHE execution-policy/governance-bundle fixtures carry
  that digest so deployed governance profiles force runtime public-key
  statement binding for policy-bound key material admission. Torii's signed
  FHE job preflight and `RunSoracloudFheJob` now require `public_key_proof`,
  include it in the canonical job provenance payload, and validate proof
  envelopes against the policy-bound statement hash before Core's dedicated
  witness-AIR fail-closed boundary.
  Seeded key generation and public-key encryption now also fail closed unless
  the parameter set's centered `q/t` capacity covers the same deterministic
  encrypted-zero refresh bound, so structurally valid but too-narrow profiles
  cannot produce first-release ciphertext/key material; deterministic BFV
  keygen, encryption, Galois-key generation, and identifier seed helpers now
  also reject empty or oversized seeds before deriving RNG material. Registered
  BFV profile validation and the production digest path now enforce the same capacity
  invariant before admitting the RAM-LFE profile, and BFV parameter validation
  uses checked exact-arithmetic products for raw and plaintext-scaled scalar
  accumulator bounds rather than relying on saturating overflow guards. The
  key-switch decomposition digit count now also validates parameters and uses
  checked coverage arithmetic, so invalid or future-widened profiles fail with
  `BfvError` instead of silently saturating digit generation; BFV residual-bound
  helpers likewise use checked `t - 1` and decomposition-base-minus-one bounds
  instead of saturating those admission inputs. Identifier envelope slot counts
  now also use checked max-input-plus-length-slot arithmetic instead of
  saturating the reserved length-slot calculation. The crypto crate now also
  has a separate rounded BFV path for the pending BFV-RNS replacement:
  bounded-noise public-key generation samples small centered error, plaintext
  is encoded as `(q / t) * m`, decryption rounds back into `Z_t`, and owner
  diagnostics report centered noise/headroom against the rounded-decoding
  capacity. Rounded
  ciphertext addition now also has conservative centered-noise bound
  propagation tested against real rounded ciphertext addition; subtract,
  rounded plaintext-scalar addition, plaintext-scalar multiplication, and
  plaintext-polynomial multiplication have the same bounded-noise propagation
  coverage. Rounded ciphertext-ciphertext multiplication now has a scalar
  semantic bridge that computes centered raw products before `t/q`
  scale-and-rounding, then relinearizes with bounded-noise key-switch entries
  and validates a conservative output noise budget. Rounded Galois key
  switching now also has small-noise key generation, secret-key consistency
  checks, automorphism application, and output-bound propagation over rounded
  ciphertexts. Rounded packed `RotateLeft` now wires that bounded-noise Galois
  path through the public packed-selector schedule with matching output-bound
  propagation. This still needs the remaining Soracloud evaluator
  migration/broader propagation beyond the exact-lift bridge; governed
  artifact-aware full-bootstrap execution and bounded dispatch are tracked
  separately below.
  RNS polynomials can now be exactly basis-extended between validated modulus
  chains by canonical CRT reconstruction plus target-limb reduction, with
  target-product coverage checks to reject aliasing; this is a deterministic
  reconstructable bridge alongside the target-limb key-switch path rather than
  the final approximate basis-extension algorithm. A deterministic target-limb
  basis-extension helper now computes the CRT quotient correction exactly with
  integer arithmetic and reduces source representatives into target limbs
  without requiring the target product to cover the source product; narrow
  target reconstruction remains visibly lossy. Key-switch components now also
  decompose directly into RNS digit polynomials, exact RNS key switching
  consumes those digit polynomials internally, and basis-extended digits are
  rejected if they no longer reconstruct to canonical decomposition digits. An
  explicit target-limb basis-extension key-switch path now decomposes in a
  source chain, verifies that the source cannot alias decomposition digits,
  basis-extends canonical key-switch digits through the digit-specific
  basis-extension helper without requiring the evaluator target to cover the
  full source-chain product, rejects basis-extended digit-count and RNS
  limb-shape drift at validation, and drives rounded multiplication, Galois,
  and packed `RotateLeft` bridges while matching the scalar bounded-noise
  outputs. Direct key-switch component decomposition and digit
  basis-extension helpers now enforce source/target decomposition-base
  coverage before malformed polynomial shapes can mask the public chain
  descriptor failure. Exact, target-limb, and digit basis-extension helpers now
  validate their constructed RNS polynomial outputs against the target chain
  before returning them, so future arithmetic or limb-construction drift cannot
  escape the helper boundary as malformed target residues.
  Rounded ciphertext multiplication now also has an RNS exact raw-product
  bridge that decomposes ciphertext components as centered residues,
  reconstructs signed negacyclic products before `t/q` scale-and-rounding, and
  relinearizes the scaled quadratic component through the RNS digit/key-switch
  path while matching the scalar bounded-noise multiplication output. The RNS
  chain now also exposes an explicit exact scale-round helper for centered RNS
  product polynomials at the rounded BFV `t/q` boundary, and rounded RNS
  ciphertext multiplication uses that helper for direct product components
  plus a centered two-product sum helper for `c1` cross terms, with exact
  product-sum coverage rejecting aliasing before scale-and-rounding.
  Rounded Galois key switching and packed `RotateLeft` now also have RNS exact bridge
  entry points that match the scalar bounded-noise schedule and reject
  too-narrow chains. Outer-slot rotation and bootstrap refresh material can now
  also be generated and publicly transcript-validated with rounded
  bounded-noise encrypted-zero ciphertexts, refreshed through scalar or exact
  RNS addition, routed through registered target-limb RNS basis-extension
  wrappers for bounded production Bootstrap execution, and propagated with
  centered-noise output bounds. Evaluation-key
  bundles can now validate and digest the bounded-noise rotation/bootstrap
  transcript inventory under a separate domain from the exact-lift refresh
  path, and owner diagnostics can validate bounded relin/Galois key-switch
  residuals with bundle-owned relinearization labels and bundle-indexed Galois
  diagnostics plus every bounded refresh mask in one bundle check. Soracloud FHE
  execution policies now bind the refresh transcript mode, data-model digesting
  routes through exact-lift or bounded-noise transcript derivation explicitly,
  and core runtime admission rejects mode/digest mismatches before job
  execution. Soracloud bounded-noise jobs now dispatch to the bounded-noise RNS
  bridge for Add, outer `RotateLeft`, and encrypted-zero Bootstrap refresh
  when policy/input metadata are explicitly bounded, while Multiply and packed
  `RotateLeft` now call registered `iroha_crypto` helper entry points that
  select the smallest registered key-switch decomposition prefix inside the
  crypto layer before invoking the target-limb basis-extension bridge. The
  crypto layer now exposes that registered decomposition chain and a
  role-separated digest so runtime/admission code can share the same canonical
  target-limb key-switch source basis; registered helper entry points for
  bounded-noise Multiply, Galois key switching, and packed `RotateLeft` now
  derive both the canonical evaluator chain and source basis inside
  `iroha_crypto` before invoking the target-limb bridge, so runtime callers no
  longer pass evaluator RNS chains into those registered bounded-noise entry
  points. The explicit basis-extension key-switch path now also rejects
  decomposition source chains that are not evaluator-chain prefixes, while the
  lower-level target-limb residue conversion primitive remains available for
  checked RNS arithmetic. Soracloud FHE
  parameter-set governance now stores that digest beside the parameter and
  evaluator RNS-chain digests, and input admission statement hashes bind the
  key-switch decomposition-chain digest so proof-carrying ciphertext admission
  cannot drift onto a different decomposition basis. Soracloud registered
  bounded-noise runtime coverage now also exercises two-round Bootstrap through
  the registered RNS refresh bridge,
  decrypts refreshed multi-slot outputs, and checks the propagated
  key-authorized centered-noise bound at the core runtime boundary; the same
  bounded wrapper coverage now pins Multiply and packed `RotateLeft` propagated
  output bounds while decrypting the registered target-limb outputs, and
  direct evaluator coverage pins bounded Multiply, packed `RotateLeft`, and
  two-round Bootstrap output bounds and decrypted plaintext. Ledger-level
  `RunSoracloudFheJob` rejects binding-only public/bootstrap proofs before
  output rows, audit events, internal events, or proof quota are recorded.
  Persisted FHE rows that carry public bound metadata now must also carry an
  explicit exact-residual or bounded-noise mode; Core rejects legacy/corrupt
  bound-only rows at input loading instead of silently treating them as exact.
  The crypto
  layer now owns scalar and exact-RNS multi-round Bootstrap refresh helpers for
  exact and bounded-noise ciphertexts, rejects zero or over-capacity refresh
  counts before applying any round, and single-round scalar/RNS refresh helpers
  now preflight the requested round index before entering ciphertext addition.
  Soracloud routes exact and
  bounded-noise Bootstrap jobs plus shared operation-vector checks through
  those helpers. Registered exact and bounded-noise Add/Subtract, exact and
  bounded-noise Multiply, exact and bounded-noise plaintext-polynomial
  selector products, exact and bounded-noise affine row evaluators, exact and
  bounded-noise packed `RotateLeft`, outer-slot `RotateLeft`, and
  round-zero, indexed-round, and consecutive-round Bootstrap refresh helper
  entry points now derive the canonical evaluator RNS chain inside
  `iroha_crypto`,
  and Soracloud exact and bounded-noise runtime dispatch uses those helpers
  instead of passing the chain through core. The registered-helper rejection
  regression now also covers the decomposition-chain helpers plus exact and
  bounded-noise Subtract, exact and bounded-noise plaintext-polynomial
  selector products, exact and bounded-noise affine row evaluators, exact and
  bounded-noise Bootstrap refresh forms, and the bounded target-limb Multiply,
  Galois, and packed `RotateLeft` entry points,
  proving structurally valid but unregistered profiles fail closed before
  caller-supplied key material is inspected.
  Direct exact-RNS bounded-noise Add/Subtract, affine-row, outer-slot
  `RotateLeft`, and Bootstrap refresh helpers now share a rounded-decoding plus
  exact-addition RNS corridor preflight before supplied-chain accumulation,
  refresh-key checks, or ciphertext-shape checks, and the direct exact-RNS
  bounded-noise Multiply, Galois key-switch, and packed `RotateLeft` fallback
  helpers now also have registered production wrappers, so both
  exact-reconstruction and target-limb basis-extension paths derive canonical
  evaluator chains before inspecting caller-controlled key material. Registered
  full-bootstrap sample-switch, prefix execution, direct execution, and direct
  bound surfaces now derive the production profile first as well, so malformed
  governed artifact/key material cannot mask an unregistered BFV profile.
  Bounded
  Bootstrap refresh now also has direct and registered target-limb
  basis-extension wrappers, and Soracloud bounded Bootstrap execution uses the
  registered wrapper instead of the older direct registered refresh add.
  Bounded-noise RNS packed-selector products now also route through a bounded
  plaintext-polynomial RNS helper with a registered production wrapper, so
  packed `RotateLeft` mask multiplication shares the same rounded-capacity
  preflight in direct RNS, target-limb basis-extension, and registered
  target-limb paths. Public scalar addition and multiplication now also expose
  exact and bounded-noise registered helper entry points that derive the
  canonical BFV evaluator chain before plaintext/ciphertext checks, so public
  plaintext terms fail closed on unregistered profiles; the bounded scalar
  path still preflights rounded decoding capacity before applying public terms
  to bounded ciphertexts. Bounded public affine rows now reuse those helpers with
  registered RNS accumulation and owner-side rounded-noise row-bound
  propagation, so weighted public-row evaluation no longer has only an
  exact-lift surface. Bounded registered Add/Subtract, outer-slot `RotateLeft`,
  and multi-round Bootstrap wrappers now derive the registered evaluator chain
  before bounded-noise capacity checks, so structurally valid but unregistered
  profiles fail with the production registration error first. Public
  bounded-noise output-bound propagation now also preflights fresh rounded BFV
  noise capacity before public arithmetic, key-switch, affine, rotation, or
  bootstrap bound math, so profiles that cannot admit a fresh bounded-noise
  ciphertext fail closed consistently across admission helpers. Scalar
  bounded-noise ciphertext multiplication now shares that fresh-capacity
  preflight before operand or relinearization-key shape checks, matching the
  exact-RNS bounded multiply bridge, and bounded refresh-transcript validation
  now applies the same preflight before bundle key-shape checks. Key-authorized
  bounded bootstrap output-bound admission now also rejects too-narrow rounded
  profiles before bootstrap-key shape checks and shares the bootstrap
  round-count validator, and the exact residual-bound counterpart now rejects
  oversized input residual bounds or invalid refresh-round metadata before
  bootstrap-key shape checks. The key-authorized bounded-noise bootstrap
  output-bound helper now also rejects oversized public input bounds or
  zero-round requests before validating full bootstrap-key ciphertext shape.
  Direct exact and bounded bootstrap refresh output-bound helpers now validate
  supplied public input bounds before rejecting zero-round requests, so
  oversized input-bound metadata cannot be hidden by invalid direct refresh
  counts.
  Bounded full-bootstrap linear-transform, raw-sample, and sample-switch bound
  helpers now preflight public artifact metadata before rounded-capacity errors
  while leaving full key-entry validation behind the capacity gate.
  Direct no-artifact bounded full-bootstrap execution and bound helpers now
  preflight FullBootstrapV1 key/material metadata before rounded-capacity
  errors, and artifact-aware bounded full-bootstrap prefix execution/bound
  helpers share that key/material preflight before concrete artifact or
  ciphertext validation.
  Bounded raw-sample coefficient-zero repack and owner diagnostic helpers now
  reject malformed raw-sample metadata before rounded-capacity errors.
  Bounded raw-sample extraction and sample-switch execution helpers now do the
  same for sample/key metadata and key/sample consistency before inspecting
  ciphertexts or full switch-key entries.
  Exact and bounded multiply bound propagation now
  rejects oversized public input/output bounds before validating
  caller-supplied relinearization key material. Soracloud exact and
  bounded-noise multiply metadata wrappers now preserve that preflight before
  their own multiply-arity checks, so oversized single-input metadata cannot be
  hidden by wrapper shape errors. Soracloud FHE parameter-set admission now
  rejects non-BFV schemes and unregistered BFV backend labels at the shared
  data-model layer, and execution-policy admission now rejects unsupported
  deterministic rounding modes, so first-release BFV manifests cannot carry
  ignored scheme, backend, or rounding metadata. Exact and bounded Galois
  keygen now rejects invalid public automorphism powers and non-empty
  non-all-zero deterministic seed metadata before malformed secret-key shapes,
  and exact/bounded public-key
  consistency diagnostics reject malformed public keys before malformed secret
  keys. Bounded relinearization/Galois consistency diagnostics now also reject
  malformed public evaluation keys before malformed owner secrets, and bounded
  decrypt/profile/ciphertext diagnostics plus rotation, bootstrap, and bundle
  zero-refresh owner diagnostics reject too-narrow public rounded BFV profiles
  and oversized public rounded-noise bounds before malformed owner secrets.
  Exact and bounded add bound propagation now
  validates supplied public input bounds before enforcing the minimum two-input
  shape, so oversized bound metadata
  cannot be hidden by an undersized input list. Exact residual-bound owner
  diagnostics now also reject oversized public residual bounds before malformed
  owner secrets while keeping ciphertext-shape preflight first. Exact
  bundle/rotation/bootstrap zero-refresh owner diagnostics now reject too-narrow
  public seeded-refresh residual profiles before malformed owner secrets while
  keeping refresh ciphertext-shape preflight first. Registered exact and bounded
  bootstrap refresh wrappers now also have round-index/count preflight coverage
  before malformed bootstrap-key or ciphertext shapes, and exact scalar/RNS
  bootstrap execution rejects too-narrow public seeded-refresh profiles before
  applying refresh masks. Exact and bounded direct and bundle refresh-transcript
  admission now preflights public capacity before malformed public-key,
  bundle-key, or refresh-ciphertext entry shapes. Scalar bounded bootstrap
  execution now rejects invalid public key-id and refresh-round requests before
  rounded-capacity failures. Bounded rotation/bootstrap refresh-key generation
  now rejects public step, key-id, round-count, and transcript seed metadata
  before rounded-capacity failures. Exact and bounded seeded keygen/encryption
  now reject public seed and plaintext metadata before exact residual or rounded
  capacity failures. Bounded Galois key generation now rejects public
  automorphism and seed metadata before rounded-capacity failures. Exact and
  bounded plaintext-polynomial bound propagation now rejects oversized public
  input bounds before validating
  caller-supplied plaintext polynomial shape. Exact and bounded Galois
  key-switch bound propagation now also rejects oversized public input bounds
  before Galois-key shape checks, and exact/bounded packed `RotateLeft` bound
  propagation rejects oversized public input bounds or invalid rotation
  schedules before validating caller-supplied Galois key sets. Bounded Galois
  switch and packed `RotateLeft` execution wrappers now reject public
  Galois-key metadata, rotation schedules, and key-set metadata before
  rounded-capacity failures. Bounded outer `RotateLeft` execution wrappers now
  reject public rotation metadata before rounded-capacity failures. Bounded
  affine execution wrappers now reject public circuit metadata before
  caller-supplied RNS/capacity corridor failures. Key-authorized exact and
  bounded bootstrap bound propagation now rejects public bootstrap key-id and
  round-count metadata before caller input-bound failures while preserving full
  refresh-key shape validation after public bound checks. Bounded
  plaintext scalar and polynomial execution wrappers now reject public
  scalar/plaintext metadata before rounded-capacity failures. Bounded scalar and
  plaintext-polynomial bound propagation now rejects invalid public
  scalar/plaintext metadata before rounded-capacity failures while preserving
  oversized input-bound precedence on otherwise valid profiles. Bounded
  ciphertext multiplication bound propagation now rejects invalid public
  relinearization-key metadata before rounded-capacity failures while preserving
  oversized input-bound precedence on otherwise valid profiles. Bounded Galois
  key-switch and packed `RotateLeft` bound propagation now reject invalid public
  Galois metadata, rotation schedules, and key-set metadata before
  rounded-capacity failures while preserving oversized input-bound precedence on
  otherwise valid profiles. Bounded affine, outer `RotateLeft`, and bootstrap
  refresh bound propagation now rejects invalid public circuit, rotation,
  round-count, and bootstrap-key-id metadata before rounded-capacity failures
  while preserving the existing valid-profile precedence: oversized input bounds
  remain first for affine, outer-slot, and direct bootstrap bounds, and
  key-authorized bootstrap bounds keep key-id/round metadata ahead of full
  bootstrap-key shape.
  Packed `RotateLeft` execution helpers now also preflight Galois key-set public
  metadata and key-switch entries before ciphertext shape, and scalar/RNS
  key-switch primitives now preflight full key-switch entries before malformed
  switching components.
  Evaluation-key bundle validation and
  digest admission now preflight public rotation, Galois, and bootstrap
  inventory metadata before malformed relinearization or refresh/key-switch
  entry shapes. Exact/bounded
  outer-slot `RotateLeft` bound propagation now rejects oversized public input
  bounds or full-cycle rotations before validating caller-supplied rotation-key
  refresh ciphertexts, and exact/bounded public affine bound propagation now
  rejects oversized public input bounds before validating caller-supplied
  circuit row and coefficient shape; exact, registered RNS, bounded RNS, and
  registered bounded affine execution helpers now validate public circuit rows
  and coefficients before parsing malformed input ciphertext shapes. Exact,
  registered RNS, bounded-noise, direct RNS, and bounded basis-extension Galois
  key-switch execution helpers now validate public automorphism metadata before
  parsing malformed ciphertext shapes. Exact,
  registered RNS, bounded-noise, direct RNS, and registered bounded public
  scalar/plaintext-polynomial execution helpers now validate scalar ranges and
  plaintext coefficient metadata before parsing malformed ciphertext shapes.
  Exact and bounded-noise seeded encryption, plus identifier envelope
  encryption, now validate public plaintext/input, non-empty non-all-zero
  deterministic seed, and identifier envelope metadata before malformed
  public-key shapes.
  Exact/bounded plaintext-scalar bound propagation now rejects oversized public
  input bounds before validating the public scalar range. Bootstrap
  refresh execution now also validates public key metadata plus requested round
  index/count before full refresh-key ciphertext shape across scalar,
  bounded-noise, direct RNS, and registered RNS paths, so malformed
  `round_refreshes` vectors cannot mask out-of-capacity refresh requests.
  Owner-side decrypt/profile/residual and bounded-noise diagnostics now validate
  ciphertext shape before secret-key shape, and exact/bounded rotation and
  bootstrap refresh-key generators validate public metadata, non-empty
  non-all-zero deterministic seeds, and public-key shape before deriving
  encrypted-zero refresh masks.
  Soracloud BFV
  refresh-transcript admission now also
  derives its deterministic seed, bootstrap key-id, rotation-transcript, and
  bootstrap max-round caps from the public `iroha_crypto` constants.
  Bounded-noise FHE input-admission envelopes receive statement-hash, shared
  `OpenVerifyEnvelope` admission-shape, active-verifier, and native binding
  metadata preflight, then fail closed because no dedicated ciphertext-witness
  AIR exists; they do not persist bounded metadata. Portable proof
  validation now rejects cheap attachment metadata before BFV bound capacity
  (backend consistency, canonical verifier id, verifier-key commitment
  metadata, and envelope-hash presence), while retaining BFV bound-capacity
  rejection before decoded `OpenVerifyEnvelope` admission, expensive verifier
  dispatch, and verifier-record lookup. The data-model proof validator also
  rejects exact and bounded-noise input-admission bounds that exceed registered
  RAM-LFE BFV capacity before runtime admission, and persisted FHE state rows
  now reject exact or bounded bound metadata that exceeds the same registered
  capacity.
  FHE input-admission proof attachments now also require `vk_ref.name` to be the
  canonical v1 circuit id, a supported STARK/FRI v1 proof backend label from
  the shared data-model ZK classifier, a decoded STARK `OpenVerifyEnvelope` with
  the canonical v1 circuit/schema, a v1 STARK public-input wrapper whose single
  public input matches the proof `statement_hash`, a `vk_commitment` that
  matches the embedded `OpenVerifyEnvelope.vk_hash`, and an `envelope_hash`
  that matches the embedded `OpenVerifyEnvelope` bytes at both data-model
  validation and Soracloud runtime admission; the Core attachment helper now
  applies the shared structural guard before decoding the envelope, and core
  runtime admission and backend pre-verification now also reject matching but
  unsupported STARK/FRI backend labels and portable but non-canonical FHE
  circuit ids before verifier-record lookup, so proof-carrying ciphertext
  admission cannot alias the verifier id or omit/forge the verifier-key,
  statement, circuit, or envelope binding. The
  backend verifier now decodes the `OpenVerifyEnvelope` from the attachment
  proof bytes itself, then re-checks the STARK envelope shape, public-input
  schema, statement public input, verifier-id and attachment bindings, plus the
  single supported v1 verifier record version, before verifier lookup, so
  direct verifier use cannot bypass the envelope or statement-hash preflight.
  The data-model validator, Core envelope helper, and backend preverification
  path now also reject STARK wrappers whose backend-native `envelope_bytes` are
  empty, so proof-carrying FHE admission cannot reach verifier lookup with only
  statement metadata and no native proof envelope. Those same data-model and
  Core preverification paths now share Soracloud-specific byte caps for the
  encoded `OpenVerify` envelope, STARK public-input wrapper, and backend-native
  STARK envelope bytes through the exported data-model bounds helper before
  verifier lookup, with Soracloud-sized canonical circuit/schema ceilings, so
  outer envelope, STARK wrapper, canonical metadata, and auxiliary-byte policy
  cannot drift between portable validation and runtime admission. The Core FHE
  input-admission verifier helper now also recomputes the actual payload length
  and payload commitment before BFV shape checks, statement-hash derivation,
  envelope validation, or verifier lookup, so direct helper use cannot bypass
  the same payload metadata binding performed by the mutation executor. Core
  input-admission replay coverage now also mutates the proven bound value and
  bound mode independently, proving both fields are bound into the statement
  hash before verifier lookup.
  FHE job execution admission now computes deterministic output payload-size
  projections with checked `u64` arithmetic and rejects output-size overflow
  before comparing the projection with `max_ciphertext_bytes`; the legacy
  infallible projection helper remains conservative by returning `u64::MAX`
  for unrepresentable projections. Direct service-state upserts and FHE job
  output persistence now share checked binding state-total projection, so
  inconsistent existing-item accounting and `u64` total overflows fail closed
  before max-total admission checks.
  Centered target-limb RNS basis extension now preserves signed raw-product
  representatives such as `-1` and `-2` in narrower target limbs, pins the
  half-product tie as nonnegative and the first above-half residue as negative,
  and keeps that future BFV-RNS conversion boundary distinct from the canonical
  nonnegative key-switch digit path; target-limb scale-round bridge helpers now carry those
  signed products and two-product cross-term sums into the deterministic `t/q`
  rounded BFV boundary, and registered bounded-noise target-limb multiplication
  now derives a role-separated centered scale-round source chain before
  key-switch decomposition. That source-chain digest is now bound into
  full-bootstrap circuit material, evaluator artifact-set summaries, native
  generated circuit bodies, native prover/verifier payloads, native
  proof-circuit fingerprints, proof-key payloads and material envelopes,
  proof-key pair commitments, release-audit proof profiles, release-audit
  proof-key evidence records, release-audit evidence, release-audit signoff
  payloads, and release-audit manifests so stale source-role metadata is
  rejected before artifact or audit acceptance, and caller-pinned package
  digest alias checks reject attempts to reuse the signed source-chain digest as
  the package digest. The target-limb multiply helper now also rejects
  structurally valid centered scale-round source chains that are not evaluator
  prefixes before malformed relinearization-key or ciphertext payloads.
  Full-bootstrap artifact-bundle alias preflight now reuses the canonical typed
  artifact-bundle digest-material validator before hashing, so duplicate
  artifact-role digests fail before material proof input digesting can hide
  them behind later artifact mismatch diagnostics.
  Soracloud material/execution public-input schemas now
  advertise the matching release-audit field counts, source-chain binding flags,
  external-audit signed-commitment distinctness, and caller-pinned
  signed-commitment package-digest alias rejection, plus package audit-body
  requirements for the signed evidence, artifact-bundle, evaluator-artifact-set,
  centered source-chain, generated-body, native-fingerprint, proof-key-pair,
  prover-key, and verifier-key commitments.
  The production bounded-noise admission circuit/prover rollout, broader
  target-limb BFV-RNS evaluator hardening, and audited full-bootstrap
  proof-producing/verifier artifacts remain pending.
	  Full-bootstrap release artifact decoding now mirrors the encoder/evaluator
	  inert-byte policy for hand-crafted envelopes by rejecting all-zero outer
	  envelopes and non-empty all-zero inner payloads before role-specific Norito
	  decoding, including the pre-material proof-key commitment helper used during
	  release material derivation.
		  Generated native STARK/FRI circuit-body coverage now also rejects
		  digest-correct all-zero body bytes and matched stale release-audit
		  generated-body digests before they can satisfy prover/verifier equality,
		  and raw generated body bytes now reject placeholder/template text before
		  digest or canonical-body mismatch handling.
		  Release-audit evidence digesting now also rejects matched stale
		  prover/verifier generated-circuit body digests through the public evidence
		  digest helper, not only standalone evidence validation.
			  Release-audit signoff payloads now also carry that generated-body digest
			  as a signed commitment and validate it against evidence before manifest
			  construction, with regressions covering stale signoff generated-body
			  commitments and runtime-gate rejection before exact/bounded execution
			  preflight.
		  Bounded-noise exact-RNS and target-limb basis-extension bootstrap
	  round-zero wrappers now share the chain-before-shape preflight regression
	  coverage already pinned for indexed and multi-round refresh paths.
	  Bounded-noise bootstrap proof-statement coverage now also rejects all-zero
	  nonzero-index refresh rounds and proves refresh-round tampering changes the
	  bounded statement digest, including reordered multi-round refresh material.
	  Transcript-bound bootstrap proof-statement coverage now also proves the
	  bounded-noise API rejects exact encrypted-zero refresh masks before deriving
	  bounded transcript statements.
		  Bounded transcript proof-statement coverage now also binds bootstrap round
		  count/key material and rejects reordered nonzero-index refresh rounds during
		  deterministic transcript validation.
		  Exact transcript proof-statement coverage now mirrors that round-count/key-material
		  binding and reordered-round rejection before a transcript-bound statement
		  digest is emitted.
			  Full-bootstrap evaluation-key bundle coverage now also proves
			  `FullBootstrapV1` material stays on the material-proof path: transcript
			  inventory digests admit no-seed material binding, while exact and bounded
			  zero-refresh transcript statement APIs explicitly reject full-bootstrap
			  keys and supplied deterministic bootstrap transcript seeds.
			  Governed `FullBootstrapV1` keys now use the
			  `full_bootstrap_key_from_material_v1` no-refresh constructor and must
			  keep `max_refresh_rounds = 0`, empty `zero_refresh`, and empty
			  `round_refreshes`; encrypted-zero refresh material remains
			  `RefreshOnlyV1`-only until the audited BFV-RNS full-bootstrap
			  arithmetic/prover backend replaces the bridge.
		  Registered RNS chain selection now also preflights exact-addition and exact
	  negacyclic-product coverage before exposing the chain or its production digest. Public RNS
  exact evaluator entry points now also preflight their required chain coverage
  before late operation-specific checks, while indexed Bootstrap helpers now
  preflight the requested round capacity before malformed ciphertext shapes can
  enter the addition path; malformed RNS context is still rejected before
  invalid refresh rounds, no-op packed rotations, or key-switch scheduling can
  short-circuit validation. Bounded exact-RNS ciphertext
  multiplication now reuses the same exact evaluator-chain preflight, including
  exact-addition coverage, before operand or relinearization-key shape checks.
  Exact and bounded plaintext-mask selector products are now pinned in the same
  preflight corridor tests, so packed-rotation public mask products cannot hide
  a too-narrow product chain behind malformed ciphertext diagnostics.
  Refresh transcript digest assembly
  now also returns structured shape errors for missing or unmatched rotation
  transcript seeds instead of relying on a post-validation panic invariant.
  Owner-side evaluated-output
  diagnostics can now validate a ciphertext against a caller-declared exact
  residual-multiple bound and reject plaintext-preserving residual inflation,
  while checked helper APIs derive exact add-output and public bootstrap
  refresh-output residual bounds before those diagnostics run. Those helpers
  now also cover exact subtract, plaintext addition, plaintext-scalar
  multiplication, plaintext-polynomial multiplication, and public affine-circuit
  row bounds. Outer ciphertext-slot `RotateLeft` now also propagates rotated
  per-slot bounds and one public encrypted-zero refresh bound per output slot.
  Packed `RotateLeft` now also has conservative exact-bound propagation for the
  current Galois key-switch bridge and plaintext-mask schedule, including
  capacity rejection for parameter profiles whose centered modulus cannot cover
  key-switch residuals. Soracloud service-state rows can carry optional exact
  BFV residual-multiple metadata for FHE ciphertexts, while direct evaluator
  tests preserve propagated-bound coverage for Add, balanced
  Multiply/relinearization, outer/packed `RotateLeft`, and Bootstrap.
  Ledger-level `RunSoracloudFheJob` remains fail-closed at the dedicated
  witness-AIR boundary and persists no binding-only output. The exact packed
  `RotateLeft` evaluator regression decrypts the scheduled output and asserts
  its conservative residual bound. Client-provided FHE state
  mutations without proof-carrying input admission intentionally remain
  metadata-free and cannot feed FHE jobs. Upsert mutations may now carry a
  canonical Soracloud FHE input-admission proof attachment: provenance signs
  the proof statement, core derives the statement from the service, binding,
  key, operation, payload, BFV profile, RNS chain, key-switch decomposition
  chain, and governance transaction, validates the STARK/FRI
  `OpenVerifyEnvelope` against an active `soracloud`
  verifier key for the canonical V1 circuit id, rejects restored verifier
  records whose Goldilocks field label or inline key length drift from the
  stored key material, then rejects binding-only AIR before the claimed
  residual bound can be persisted. The
  production circuit and governed key-material rollout for public noise
  admission remains open, so this is the ledger admission boundary rather than
  a complete BFV-RNS proof system.
  BFV evaluation-key metadata now caps rotation-key and Galois key bundles,
  rejects duplicate Galois automorphism powers, and requires portable bounded
  bootstrap key ids containing only ASCII alphanumeric, `.`, `_`, or `-` bytes.
  The crypto layer now also exposes and validates a
  registered RAM-LFE v1 BFV RNS coefficient-modulus chain with bounded,
  strictly increasing odd-prime, NTT-friendly, pairwise-coprime limbs, bound
  primitive `2n`-th negacyclic NTT roots for the registered RAM-LFE profile,
  and a checked product that covers the current ciphertext modulus, plus a
  stable domain-separated chain digest for governance and release-vector
  binding. The shared RNS validator now also validates the BFV parameter set
  itself, so direct exact-lift and exact `Z_q` coverage checks fail closed on
  malformed parameter profiles before inspecting chain arithmetic bounds, and
  enforces bounded concrete root support for every validated limb. The
  registered chain selector validates that the root table is limb-aligned
  before exposing production RNS chains. The same chain now supports checked
  limb-major polynomial decomposition and CRT
  reconstruction, rejecting malformed limb counts, limb lengths, unreduced
  residues, and source coefficients outside the ciphertext modulus; it also
  has deterministic scalar residue addition and per-limb NTT-backed
  negacyclic multiplication with a scalar fallback in `Z_Q[x] / (x^n + 1)`.
  Generic primitive-root discovery for non-registered limbs is bounded, so
  unsupported caller-supplied primes fall back or fail closed instead of
  running an unbounded candidate scan.
  The shared Soracloud operation fixture now binds the registered RNS
  descriptor/digest plus sample
  decomposition/reconstruction, residue addition, and negacyclic
  multiplication hashes across Rust and lightweight SDK shape checks. The RNS
  chain now also exposes guarded exact ciphertext-modulus polynomial addition
  and negacyclic multiplication for sufficiently wide chains, plus exact
  RNS-backed ciphertext addition, multiplication, relinearization, and Galois
  key-switch bridges that match the scalar evaluator on small wide-chain
  profiles. The registered RAM-LFE chain is now wide enough for that guarded
  exact `Z_q` bridge, so Rust exercises exact RNS ciphertext addition,
  multiplication/relinearization, and Galois key-switching against the
  production RAM-LFE parameters while still rejecting the narrower exact-lift
  compatibility corridor. The programmed RAM-LFE BFV runtime now uses that
  registered exact RNS bridge for ciphertext add, subtract,
  multiply/relinearization, and `SelectEqZero` exponentiation/selection
  arithmetic; plaintext-scalar operations remain scalar because they do not
  require RNS polynomial products. The public Soracloud BFV operation executor
  now uses the same registered exact RNS bridge for Add, Multiply, packed and
  outer `RotateLeft`, and bounded Bootstrap refresh rounds, so the shared
  operation vectors cover the production job path rather than scalar-only
  fallbacks. Bounded target-limb basis-extension wrappers now share a single
  rounded-capacity plus decomposition/evaluator prefix preflight, and Bootstrap
  refresh rejects structurally valid non-prefix decomposition chains before
  malformed refresh keys or ciphertexts can mask corridor errors. The
  deterministic BFV baseline now also has
  packed-polynomial Galois automorphism keys that switch `sigma_k(s)`
  ciphertexts back to the original secret key after applying `x -> x^k`, with
  regressions covering canonical odd powers, malformed key rejection,
  plaintext automorphism parity, and registered-chain exact-RNS parity. The
  shared Soracloud fixture now binds a canonical
  Galois key-switching bundle shape, SDK-visible component hashes, a scalar
  Galois switch output vector, and a packed Galois slot-permutation execution
  vector backed by deterministic packed plaintext CRT slot encoding/decoding,
  with scalar, exact-RNS, and basis-extension key-switch primitives now
  validating full decomposition-entry inventories before operands, components,
  or digit polynomials so malformed key material cannot silently truncate or
  mask a switch,
  plus bounded one-/two-round bootstrap refresh vectors that consume distinct
  per-round public refresh ciphertexts. Rust crypto/core now
  also support arbitrary non-zero packed `RotateLeft` requests by deriving a
  deterministic public Galois-key mask schedule, applying each required
  automorphism, masking contributed slots, and summing the masked ciphertexts.
  The raw packed `RotateLeft` helpers now validate the complete supplied
  Galois-key slice for bounds, duplicates, and malformed entries before
  looking up scheduled powers, so extra bad key material cannot be silently
  ignored outside an evaluation-key bundle.
  Shared BFV key validators now also validate the parameter set before
  inspecting secret, public, rotation, relinearization, Galois, key-switch
  entry, or bootstrap key shapes, so direct validator use cannot bypass
  malformed parameter rejection or reach decomposition math first. Plaintext,
  ciphertext, polynomial, Galois-power, affine-circuit, and RNS-polynomial
  validators now apply the same parameter preflight before inspecting
  caller-controlled shapes. Bootstrap-key validation now also checks the
  declared round-refresh count before inspecting refresh ciphertext shapes, so
  malformed public refresh material cannot mask missing per-round bootstrap
  inventory; exact and bounded refresh-only bootstrap key constructors now
  reject inert all-zero public-key material before deriving encrypted-zero
  refresh masks, with the Soracloud bootstrap-key zero-refresh public-input
  schema advertising that refresh-transcript public-key preflight; and
  refresh-only bootstrap direct execution rejects inert public-key digest
  metadata while transcript/proof-statement validation rejects stale or
  placeholder public-key digest metadata before refresh material or governance
  hashes are accepted.
  The outer ciphertext-slot `RotateLeft` helper now also rejects empty slot
  lists and full-cycle step counts before applying rotation-key refresh
  material, and the exact, registered RNS, bounded-noise, and bounded RNS
  execution helpers perform that public metadata preflight before inspecting
  refresh-key or slot ciphertext shapes. Packed `RotateLeft` execution helpers
  now likewise derive the public rotation schedule before inspecting
  caller-supplied ciphertexts or Galois-key sets across exact, RNS,
  bounded-noise, and bounded basis-extension paths. This keeps no-op rotations
  fail-closed before key material is parsed.
  The exact BFV bridge now exposes reusable first-release evaluation budget
  planners that reject zero-input plans, single-input nonzero-depth plans,
  single-input Add plans, multi-input RotateLeft plans, and zero-round
  or non-single-input Bootstrap plans; the planner now also rejects zero-round
  Bootstrap metadata before input-shape errors and over-budget depth/refresh
  metadata before secondary operation-shape checks. Soracloud Bootstrap
  job-spec validation and runtime planner admission now also reject zero
  `bootstrap_count` metadata before non-single-input shape errors, and Add,
  Multiply, RotateLeft, and Bootstrap operation metadata is rejected before
  secondary arity/input-shape errors across manifest validation and runtime
  planner admission. Soracloud multi-input Multiply executes as a deterministic balanced tree, rejects jobs whose declared
  multiplication depth underestimates that tree at job-spec validation and
  runtime admission through the same crypto planner, and parameter-set /
  execution-policy validation rejects advertised multiplication/bootstrap
  budgets above the exact evaluator budget before governance admission. The
  shared operation fixture pins each runtime vector's requested depth across
  Rust and SDK shape checks.
  Exact-residual and bounded-noise public-key/ciphertext admission now also
  have typed proof-input material that binds public statement hashes to the
  concrete public key/ciphertext, secret-key witness, decoded plaintext, scaled
  coefficients, exact residual multiples or centered-noise polynomials,
  declared bounds, and nonzero public-key/ciphertext residual/noise witnesses
  before prover handoff; deterministic exact and bounded-noise randomness
  generation resamples inert all-zero error/noise polynomials; each proof-input
  package now has a
  role- and mode-separated digest over the canonical self-describing Norito
  material. The Soracloud public-key and input-admission schema regressions
  parse those proof-input material sections and bind digest domains, versions,
  field counts, witness obligations, nonzero witness rejection, and generation
  resampling back to the `iroha_crypto` constants.
  These deterministic `t`-multiple error terms, refresh paths, modulus-chain
  descriptors, residue arithmetic helpers, and packed rotation schedules are
  still not a complete bounded-noise BFV-RNS evaluator or full bootstrap
  circuit.
- Broaden the cross-SDK deterministic BFV-RNS vector corridor: Kotlin, Java,
  Swift, and JavaScript now require `RamLfeOutputOpening` on identifier
  claim/resolve helpers, and a shared Soracloud BFV identifier-envelope fixture
  now covers the baseline encrypted identifier plus three-input Add and
  Multiply operand payloads with deterministic plaintext-modulus-multiple BFV
  error terms in the Rust, JavaScript, Swift, Kotlin/JVM, and Java Android
  envelope builders. The same fixture now pins Rust executor output
  lengths, SHA-256 digests, and plaintext slots for Soracloud Add, Multiply,
  RotateLeft, and Bootstrap operation vectors, as well as deterministic public
  key/public-parameter byte lengths and SHA-256 digests, evaluation-key bundle
  byte length, SHA-256 digest, domain-separated digest, decomposition metadata,
  relinearization entry count, per-relinearization-entry `b`/`a`
  coefficient-vector digests, Galois key count, Galois automorphism powers,
  per-Galois-entry `b`/`a` coefficient-vector digests, rotation key count,
  bootstrap key id, bootstrap key max refresh rounds, rotation encrypted-zero
  refresh digests, bootstrap zero-refresh and per-round encrypted-zero refresh
  digests, and refresh `c0`/`c1` coefficient-vector digests. The fixture now
  also pins a
  scalar Galois switch vector with deterministic input/output ciphertext and
  plaintext coefficient digests, plus a packed Galois switch vector with input
  slots, the induced slot permutation, output slots, packed plaintext
  coefficient digest, ciphertext digests, and output component digests, plus a
  runtime packed `RotateLeft` vector for the registered half-slot rotation
  bound to Galois automorphism power `65`, plus a one-step runtime packed
  `RotateLeft` vector that pins the full BFV Galois mask-and-sum schedule,
  expected packed slot rotation, ciphertext digests, plaintext coefficient
  digest, requested multiplication-depth metadata, and output component
  digests across the same SDK fixture-shape validators, plus bounded bootstrap
  refresh vectors with key-aware refresh-round admission, refresh rounds,
  deterministic input/output ciphertext digests, plaintext coefficient digests,
  and output component digests. The same shared operation fixture now pins the
  registered RNS chain descriptor/digest, deterministic sample coefficients,
  per-limb residue hashes, and reconstructed hashes for RNS decomposition,
  addition, and negacyclic multiplication; Rust recomputes those fields from
  the registered chain, while JavaScript, Swift, Kotlin/JVM, and Java Android
  validate the descriptor and residue-hash shape. JavaScript, Swift,
  Kotlin/JVM, and Java Android now also parse `norito_length_encoding =
  compact-v1` and reproduce the Rust-compatible compact operation-input
  encryption stream for the non-packed Soracloud Add, Multiply, outer
  `RotateLeft`, and Bootstrap input vectors. Packed-slot operation inputs still
  rely on Rust execution plus SDK fixture-shape and digest validators outside
  the browser/native identifier-envelope builders. JavaScript, Swift,
  Kotlin/JVM, and Java Android now validate those component-vector fields from
  the shared fixture and carry adversarial fixture mutations for missing,
  noncanonical-case, duplicate, zeroed, coefficient-count-drifted, and
  key-count-drifted component metadata; the JavaScript lane also carries
  adversarial RNS mutations for missing, duplicate, zeroed, count-drifted, and
  malformed metadata. A shared
  signed/proof-attestation identifier receipt fixture now pins canonical payload
  bytes, Iroha prehash, resolver signature, signed/proof attestation bytes, and
  adversarial receipt/policy mutations across the Rust data model, JavaScript,
  Swift, Kotlin/JVM, Java Android, and Torii runtime claim-receipt signing path.
  The Soracloud FHE governance fixtures now bind the canonical parameter set,
  execution policy, governance bundle, and job spec to the registered
  `bfv-default` RAM-LFE BFV runtime descriptor and reject descriptor drift in
  core admission. Parameter-set descriptors now also carry the canonical
  domain-separated registered BFV RNS modulus-chain digest, and core admission
  rejects RNS descriptor drift before FHE jobs can run; the crypto-side
  registered selector also checks the concrete negacyclic NTT root table before
  exposing that chain or digest. The execution policy now also carries the
  canonical evaluation-key bundle digest from the shared operation fixture, and
  `RunSoracloudFheJob` rejects structurally valid but ungoverned key material
  before output state is emitted. Shared release vectors still need to cover
  the broader BFV-RNS evaluator corridor and audited full-bootstrap proof
  material beyond the current encrypted-zero round-refresh bundles and
  data-model full-bootstrap material proof envelope.
- Broaden validation from the green focused crypto/data-model/core/Torii/daemon
  checks into the next full workspace and SDK corridor. The `iroha_cli
  --all-targets` strict clippy gate now covers the governance-instruction, IVM
  contract deploy, and Taikai helper targets after the previously failing
  length/time arithmetic paths were made warning-clean. The `iroha_crypto
  --all-targets` strict clippy gate is also green after the SoraNet
  token/handshake and RAM-LFE test-target warning blockers were cleared. The
  non-default GOST, SM, forced-NEON SM, SM OpenSSL provider, Rayon-backed
  Merkle, secp256k1 MSM-batch, BLS multi-pairing, FFI export, and crypto
  parity-test feature corridors now also pass strict `iroha_crypto
  --all-targets` clippy and focused library tests, with SM acceleration and
  OpenSSL preview tests serialized around their test-only runtime dispatch
  overrides. The combined `iroha_crypto --all-features` all-targets clippy,
  library, and integration-test corridors are also green after keeping the BFV
  adversarial evaluation-key metadata coverage below strict test-target line
  limits and serializing forced-NEON SM acceleration tests around their shared
  runtime override state; the all-features pass fixed SM dispatch precedence so
  `sm-neon-force` force-enables only the `Auto` policy and explicit
  `force-disable` still pins the scalar fallback. The
  `iroha_data_model --all-targets` strict clippy gate is green after clearing
  the kagemusha/ZK-ACE test/bench lint surface, and the touched-package
  all-target gate for `iroha_data_model`, `connect_norito_bridge`,
  `iroha_js_host`, `iroha_kagami`, and `sorafs_orchestrator` now also passes
  with `--no-deps`. The full `soranet-relay` strict clippy gate now reaches and
  passes relay diagnostics without `--no-deps`. The `iroha_p2p --all-targets`
  strict clippy gate now also passes without `--no-deps` after clearing BFV,
  SoraFS reputation, Petal Stream, and Nexus status dependency warnings.
  Focused
  adversarial tests now cover malformed/truncated ciphertext envelopes,
  hidden-program shape/overflow rejection,
  replayed/tampered/future/expired/wrong-verifier openings,
  receipt-signing/backend mismatch refusal, adversarial BFV public parameters
  and evaluation-key metadata, execution-policy evaluation-key digest
  mismatches, unregistered BFV parameter sets,
  impossible decrypted identifier envelopes, FHE governance lifecycle/linkage
  abuse, operation-shape and budget-smuggling jobs, encrypted-only Torii DTO
  rejection, duplicate JSON encrypted/opening-field and nested shadow-field
  rejection before DTO decoding,
  full receipt/opening security-binding mutation checks, proof-only receipt
  attestations passed to Rust/JavaScript/JVM SDK signature verifiers,
  wrong resolver keys, mismatched receipt policy ids, validly re-signed but
  execution-mismatched output openings on `ClaimIdentifier`, missing/malformed
  Soracloud evaluation keys, empty/malformed ciphertext slots, malformed
  relinearization keys, structurally valid wrong BFV key-bundle component
  material, malformed SDK ciphertext hex, plaintext-only policy misuse,
  slot-count/digest mismatches, shared signed receipt canonical payload
  drift, shared signed/proof attestation canonical byte drift, malformed
  signatures, wrong resolver keys, wrong policy ids, tampered output ciphertext
  hashes, proof-only attestations, ZK-ACE public-input version drift, and
  ZK-ACE prepared authorization proofs rebound to a different transfer digest,
  chain id, receiver, amount, or policy hash across the Rust data-model, JS,
  Swift, Kotlin/JVM, Java Android, and Torii runtime fixture corridor, plus
  core ZK-ACE rotated/revoked identity state, unsupported action classes,
  transaction digest/account substitution, and mutated ZK-ACE/STARK public
  inputs, while the ZK-ACE prover fixture account helper now derives
  deterministic Ed25519 accounts through `KeyPair::try_from_seed` and compares
  the resulting account id with the checked backend public key in focused
  coverage;
  RAM-LFE proof-verifier metadata now rejects noncanonical backend/circuit
  identifiers, zero schema hashes, empty/all-zero verifier keys, and oversized
  verifier keys before proof-carrying programmed policies are admitted;
  crypto identifier-envelope public-parameter validation now rejects
  structurally valid but unregistered BFV profiles before identifier
  encryption, decryption, or downstream Torii/core admission, caps
  `max_input_bytes` at the registered 63-byte/64-slot RAM-LFE identifier
  profile across Rust, JS, Swift, Kotlin/JVM, and Java Android clients, and identifier
  slot encoding now reports byte-length and slot-index conversion failures
  through `BfvError` instead of panic-only assumptions; always-built BFV scalar
  modular addition, multiplication, and coefficient reduction now avoid
  post-reduction `expect` conversions while preserving max-width `u64::MAX`
  modulus behavior, and the RAM-LFE default programmed BFV hidden program now
  uses profile-sized `u16` constants instead of runtime `usize`-to-`u16`
  conversion assumptions; programmed BFV memory RNG transcript derivation now
  binds `u64` step values directly instead of converting through a panic-only
  `expect`; BFV/RAM-LFE domain-separated digest, receipt, and RNG-seed
  transcripts now stream hash chunks directly while preserving the previous
  contiguous byte layout; BFV `RotateLeft` outer-slot step normalization now also uses `u64`
  modulo arithmetic before converting back to `usize`, avoiding
  target-width-dependent behavior for large public rotation-key step counts;
  programmed RAM-LFE BFV hidden-program admission now caps v1 instruction tapes
  at the canonical 64-slot, four-instruction shape before execution and rejects
  `LoadInput` indexes that exceed the encrypted envelope's advertised
  `max_input_bytes`; `LoadConst`, `AddPlain`, `SubPlain`, and `MulPlain`
  immediates must also be canonical `F_257` values before public-program
  digests or programmed parameters are admitted; the
  feature-gated BFV acceleration selector now falls back to deterministic scalar
  schoolbook multiplication for zero or overflowed derived
  convolution lengths, and the CRT-NTT helper path now rejects invalid operand
  lengths, unsupported NTT lengths, and CRT reconstruction overflow before
  using that same fallback instead of panicking on degree or NTT arithmetic;
  programmed RAM-LFE BFV bundle construction now keeps only fallible production
  constructors that reject unregistered identifier profiles and invalid proof
  metadata before public-parameter digests are emitted, while programmed BFV
  public-parameter decoding rejects encrypted-envelope capacities above the
  canonical profile slot count;
  programmed BFV public-parameter admission now rejects zero hidden-program
  digests and relinearization-only violations where unused rotation/bootstrap
  refresh keys are smuggled into identifier-program metadata;
  BFV evaluation-key metadata now rejects noncanonical, delimiter-shaped, or
  oversized bootstrap key ids and oversized rotation-key bundles before
  key-bundle digests are admitted;
  generic RAM-LFE and identifier receipt proof verifiers now have focused
  pre-parse regressions for public-input schema drift and non-zero mismatched
  verifier-key hashes;
  secp256k1 recoverable prehash signing now normalizes low-S output and the
  public-key recovery primitive rejects high-S malleable encodings before
  deriving EVM addresses;
  Ed25519 uncached batch verification now rejects noncanonical or small-order
  signature `R` encodings before entering the dalek batch backend, IVM Ed25519
  helper/syscall/opcode/batch accelerator paths reject the same `R` encodings
  before verifier dispatch, SoraFS manifest Ed25519 verifier paths reject the
	  same `R` encodings before constructing dalek signature material and now use
	  dalek `verify_strict` for backend verification, SoraNet SRCv2 certificate
	  Ed25519 verification routes certificate signatures through the shared strict
		  `R` parser before backend verification, SoraFS CLI detached
			  manifest signature verification now uses dalek `verify_strict` for the same
					  malformed-`R` boundary, SoraFS PoTR receipt validation routes Ed25519
						  receipt signatures and provider-admission council signatures through the
						  same malformed-`R` preflight,
					  transaction submission receipt verification now pins all-zero, short,
					  small-order-`R`, and noncanonical-`R` receipt-signature rejection before
					  receipt signing-byte verification, while generic RAM-LFE execution
					  receipts and output openings now pin short Ed25519 signature-payload
					  rejection at the same parse-before-verify boundary,
					  gateway GAR compact-JWS signatures use the same preflight, alias-proof
					  council signatures reject inert all-zero payloads and malformed `R`
					  encodings before bundle verification, SoraFS proof-token binary decode
					  routes token signatures through the shared strict `R` parser before
					  admission, SoraFS governance log publisher/block/head and PoTR ML-DSA
					  signatures now preflight ML-DSA-65 public-key and detached-signature
					  material through `iroha_crypto::mldsa65_parse_signature` before
					  opaque signature wrapping, shared
					  `iroha_crypto::mldsa65_parse_signature` and Connect identifier receipt
					  parsing now preflight ML-DSA-65 detached signatures before opaque
					  signature storage, JS/Python focused regressions and Kotlin/Java/Swift
					  guarded SDK parity tests now pin valid, short, overlong, and all-zero
					  ML-DSA behavior where the native bridge is available, and Torii
					  operator-auth ML-DSA header signatures, P2P
					  handshake ML-DSA signatures, and Core/Torii Soracloud provenance signatures
					  now use the same shared parser before request, handshake-payload, or
					  provenance-payload verification, and data-model signed transactions,
					  submission receipts, signed queries, validation-fee policies, SoraFS
					  moderation manifests, SoraNet ticket/proof helper and VPN usage vouchers,
					  RAM-LFE receipts/openings, Torii app-auth single-signature/witness
					  payloads, Torii Offline V1/V2 JSON signatures, Torii DA receipt operator
					  signatures, Torii DA Taikai SSM publisher signatures, Torii signed query
						  requests, caller-signed Torii SoraFS repair command transactions, SoraFS orchestrator Taikai
					  cache-admission envelope/gossip signatures, Core oracle observation
					  signatures, Core SoraDNS directory-builder signatures, runtime-upgrade
					  provenance signatures, snapshot ML-DSA signature sidecars, Core
					  fraud-attestation signatures, JDG
					  simple-threshold ML-DSA committee signatures, and Sumeragi direct
					  vote/merge/RBC/VRF plus peer trust-gossip ML-DSA signatures use it before digest, typed-payload
					  verification,
					  governance-policy verification, moderation summary acceptance, transport
					  accounting, provenance-payload, app-auth wrapping/validation, offline JSON,
						  DA receipt, Taikai signing-manifest, query-payload, repair-transaction-payload,
					  cache-admission payload, observation-payload,
					  directory-record, runtime-upgrade-provenance, offline-certificate, attestation-hash,
					  consensus-preimage, or trust-book mutation, and the final signer-admission
						  inventory classifies remaining raw signature constructors as fixed Ed25519
						  formats, signer-aware generic branches, non-Ed25519 fallbacks, BLS-only
						  checked paths, signer-context-free decode staging, or fixtures/examples,
							  the production-readiness corridor records focused crypto/route-sensitive
							  validation plus full workspace clippy as passing, reruns the final
							  constructor/algorithm inventories with no new production signer-aware gap,
							  and closes the prior non-crypto consensus/DA blocker with the full
							  serialized `consensus_and_da` target green locally,
						  and direct byte-key/preparsed batch APIs now filter exact
						  verify-cache hits before signature parsing and backend setup;
	  the thread-local exact verify-ok cache now keeps two entries per exact slot
	  to reduce collision churn for 32-byte transaction-hash verification tuples
	  without returning to a process-wide cache;
  SoraNet relay handshake frame length-prefix writes now use a checked helper
  plus a compile-time `u16` maximum-frame assertion, so oversized relay hellos
  fail as `FrameTooLarge` instead of relying on a narrowing assertion;
  SoraNet constant-rate scheduler dequeue now handles unexpected empty queues
  explicitly and falls through to the dummy-cell path instead of using
  panic-only queue-pop assertions; the P2P SoraNet message sender now treats
  missing high-priority batch class state as `Other` and handles stale empty
  queue selections by ending the current fill pass instead of panicking the peer
  task;
  ML-DSA public-key reconstruction from private-key material now has a
  fallible API, and `KeyPair::from_private_key` uses it so length-valid but
  internally inconsistent ML-DSA secrets return `KeyGen` instead of panicking;
  ML-DSA seeded-keygen now rejects non-empty all-zero seed material before HKDF,
  random ML-DSA keygen draws checked OS seed material through the same
  constructor instead of the infallible PQ random keypair path and validates
  generated public/secret key consistency before return, HKDF expansion
  propagates `Error::KeyGen` through the existing `Result` path instead of
  relying on a panic-only assertion, top-level ML-DSA signing delegates to the
  checked SoraNet PQ hedged signer with RNG-injected failure and all-zero seed
  regressions, direct ML-DSA backend signatures are validated before wrapper
  construction, and its S2 nonce offset conversion now uses the same
  `Error::KeyGen` route instead of a const-conversion `expect`;
  GOST deterministic nonce generation now feeds the domain tag, private scalar,
  message scalar, and optional extra entropy into HMAC-Streebog as separate
  components and streams the HMAC inner hash directly while preserving the
  previous contiguous seed transcript; Ed25519 and secp256k1 now expose checked
  `try_keypair` paths, and top-level
  `KeyPair::try_random_with_algorithm` routes OS-backed Ed25519 seed bytes and
  secp256k1 candidate scalar bytes through `OsRng::try_fill_bytes` so
  entropy-source failures or bounded scalar-sampling exhaustion surface as
  `Error::KeyGen` instead of the infallible compatibility RNG adapter;
  standalone X25519 key exchange now exposes `KeyExchangeScheme::try_keypair`,
  draws OS-backed private-key bytes through `OsRng::try_fill_bytes`, and routes
  P2P, native Connect bridge, and Python Connect keypair generation through
  fallible error surfaces instead of the infallible compatibility adapter;
  Connect Norito bridge C/Java keypair-from-seed helpers and the Swift parity
  regeneration utility now use `KeyPair::try_from_seed`, returning existing
  bridge/key-derivation errors instead of panic-only seed expansion;
  GOST random scalar sampling and per-signature extra entropy now also use
  checked OS fills, random scalar sampling rejects all-zero OS material before
  retry-budget exhaustion, per-signature entropy rejects all-zero OS material
  before falling back to deterministic nonce derivation, and GOST deterministic
  key generation rejects non-empty all-zero seed material before scalar sampling, while both BLS backends derive
  random keys from checked OS
  seed material after rejecting all-zero OS seed output and the default w3f
  backend seeds its key-splitting/signing RNGs only after checked OS fills,
  with both backend test/clippy lanes pinned in release-readiness validation
  while leaving the compatibility `os_rng()` adapter
  test-only; P2P SoraNet runtime handshakes now seed their local `StdRng`
  through `SeedableRng::try_from_os_rng` and surface entropy-source failures as
  `HandshakeSoranet` instead of panicking; Taikai ingest-edge drift jitter now
  keeps explicit seeds deterministic while routing unseeded `StdRng` setup
  through `SeedableRng::try_from_os_rng` and the CLI `Result` path, and CEK
  rotation receipt HKDF salts now use direct checked OS RNG fills when an
  explicit `--hkdf-salt` is not supplied; Kagami keypair, PoP, client-config,
  genesis-signing including NPoS bootstrap escrow, wizard, and localnet
  peer/genesis/gas/extra-account key generation now route
  random, seeded, and private-key-derived material through `KeyPair`'s fallible
  APIs and BLS PoP `Result`s instead of compatibility panic
  wrappers; irohad's ephemeral Torii receipt-signer fallback now uses checked
  secp256k1 key generation and surfaces entropy/keygen failures as `StartTorii`,
  while `iroha_swarm` peer/genesis key generation, seeded network material, and
  BLS PoP proving now return `Error::KeyGeneration` through `Swarm::new`
  instead of panicking; the CLI offline fallback config now uses a nonzero
  domain seed with `KeyPair::try_from_seed`, governance council VRF
  candidate-account derivation also uses `KeyPair::try_from_seed`, and both
  surface config/candidate derivation errors through existing `Result` paths;
  Izanami workload, Nexus gas, NPoS validator, post-topology, and network-builder
  key material now uses `KeyPair::try_random` / `KeyPair::try_from_seed` with
  explicit `Result` propagation instead of panic-only `KeyPair` wrappers, and
  the shared `iroha_test_network` peer-builder random streaming/BLS fallback
  plus local `NetworkPeer` unit fixtures now go through checked random
  constructors before preserving their existing infallible test-harness
  contracts; Torii's shared test utilities now do the same for queued-block,
  authority, minimal-root, genesis, streaming, and transaction-signer fixture
  keys; Torii DA ingest, commitment, and persistence fixtures now route SSM
  publisher, receipt/spool/receipt-log, BLS block, and receipt-log poison
  signers through checked random helpers as well; data-model Nexus endorsement
  unit fixtures now route endorsement signer and committee member keys through
  checked random helpers before body-hash and quorum validation, and the
  role permission-epoch account fixture now uses checked Ed25519 key generation;
  the grouped model-derive block-signature repro fixture now uses checked random
  key generation before signing its sample header, and Hijiri positive-attestation
  reward-account fixtures now use checked random key generation; the grouped
  wallet-flow hex dump account fixtures now use checked random key generation
  before emitting canonical instruction encodings; account-controller multisig
  member fixtures now use checked default and Secp256k1 random helpers while
  preserving the deterministic CTAP2 seed-vector coverage; account-address
  Secp256k1/ML-DSA controller fixtures, transparent
  event-filter account fixtures, smart-contract payload, contract-address, and
  manifest-signing fixtures, plus SoraNet VPN helper-ticket and usage-voucher
  fixtures now use checked random key helpers; signed-transaction builder,
  multisig, TTL/ingress metadata, and fault-injection fixtures now use checked
  default and algorithm-specific random-key helpers, and bridge finality proof,
  bundle, authority-set, and verifier fixtures now use checked
  BLS/default/Ed25519 random-key helpers; block signing, genesis,
  FastPQ/result-proof and canonical-wire fixtures now
  use checked BLS/default random-key helpers; consensus roundtrip QC,
  reconfiguration, RBC, Sumeragi status, and message fixtures now use checked
  BLS/default random-key and peer-id helpers; SoraCloud signer fixtures now use
  a checked random signer helper before decryption request and service audit
  records consume public-key material;
  `MultisigRegister::from_spec` now also returns `Result` and generates its
  temporary registration anchor account through checked default key generation;
  the transaction-gossip frame-cap probe now uses a fixed checked Ed25519 seed
  instead of drawing a runtime dummy key; SoraFS hybrid
  KEM derived material now binds the recipient public keys and encapsulated
  public transcript components through length-prefixed HKDF input with checked
  capacity accounting, and SoraNet session-key HKDF extraction now
  domain-separates and length-prefixes IKM components before expansion, with
  NK2/NK3 interop vectors refreshed under both checked-in fixture bundles;
  SoraNet deterministic SHAKE expansion now also frames its domain, label, part
  count, and every absorbed component before deriving deterministic KEM,
  simulated ML-DSA, dual-mix, or Noise-seed material, with checked-in fixture
  bundles regenerated from the framed outputs;
  `PublicKey::try_to_*` and `ExposedPrivateKey::try_to_*` now expose fallible
  public/private key formatting, public-key Norito serialization now routes
  full-to-compact conversion through a checked payload extractor, and
  `PublicKey::to_prefixed_string` now reuses the malformed compact-key marker
  instead of unwrapping invalid internal key state, while `ExposedPrivateKey`
  display and prefixed compatibility formatting now return a non-secret
  invalid-private-key marker instead of unwrapping checked private-key
  formatting; `Signature::try_new` now routes SM2 through checked private-key
  rebuild/signing helpers, the high-level Rust SDK `Sm2KeyPair` exposes only
  checked `try_sign`; the panicking `sign` compatibility wrapper is removed. Connect/Norito C
  SM2 detached signing returns `ERR_SM2_SIGN` from the checked signer on backend
  failures, and SM2 key-pair/public-key derivation now routes through
  `try_public_key`, SM2
  concrete public-key prefixed formatting now
  returns a deterministic invalid-key marker instead of unwrapping checked
  multihash encoding, SM2 private-key byte export now exposes
  `PrivateKey::try_to_bytes` and routes exposed private-key multihash formatting
  through checked payload extraction, the compatibility `PrivateKey::to_bytes`
  wrapper no longer falls back to an empty private-key payload if checked export
  fails, secp256k1 message signing now exposes
  `try_sign` and routes `Signature::try_new` through the fallible helper,
  deterministic secp256k1 key generation now rejects explicit all-zero
  32-byte seed material before DRBG expansion, direct secp256k1 verification
  maps malformed, all-zero, and zero-`r`/zero-`s` compact signatures
  to `Error::BadSignature`, the compatibility `sign` helper no longer falls
  back to an empty signature if checked signing fails, and
  secp256k1 recoverable prehash signing now checks the low-S recovery-id parity
  flip before emitting EVM-compatible signatures; SM2 embedded-distid payload
  decoding now returns `ParseError` for short length prefixes instead of relying
  on a panic-only fixed-slice assertion, SM2 PEM export now wraps the already
  encoded base64 `String` without a panic-only UTF-8 reconversion, SM2
  DER signature export now exposes `try_as_der` with checked short-form length
  encoding, the compatibility `as_der` helper no longer falls back to an empty
  payload if that invariant is broken, and routes the OpenSSL bridge through
  that fallible exporter before DER parsing, SM2 signature decoding now rejects
  all-zero and zero-scalar encodings before backend parsing, and SM2 verifier
  boundaries map malformed signature material to `Error::BadSignature`, SM2
  random private-key generation now rejects all-zero RNG seed material
  immediately before scalar parsing or retry-budget exhaustion,
  generic ML-DSA public/private key import and direct batch verification now
  reject all-zero public-key, private-key, and detached-signature material before
  backend parsing,
  SM4-CCM now checks tag, nonce,
  AAD, payload, and counter-block
  length narrowing through its existing encrypt/decrypt `Result` paths, the SM
  signature shim's SM4 self-test block now uses the infallible fixed-key
  constructor instead of
  `new_from_slice(...).expect(...)`, and ML-DSA import plus `Signature::try_new`
  reject secrets whose recomputed public material or embedded `tr = H(pk)`
  public hash is inconsistent before signing; SoraNet PQ labeled-HKDF derivation
  now streams the namespace,
  separator, label,
  separator, and context components through `expand_multi_info`, preserving the
  previous contiguous info layout without manual capacity arithmetic;
  SoraNet PQ ML-DSA helpers now apply the same secret-key consistency check to
  direct validation and direct/OS-backed signing, reject all-zero standalone
  public-key, secret-key, and detached-signature material before backend use,
  reject all-zero deterministic `HedgedRngSeed` material before seeded keygen,
  reject all-zero caller/OS seed draws before `*_from_rng` keygen or signing,
  reject all-zero generated backend coins before direct keypair/signing PQClean
  calls, and expose fallible public-key reconstruction from secret material;
  BLS same-message aggregate and preaggregated verification now reject
  duplicate public keys and public-key aggregates that cancel to the identity
  before verification, and the public PoP-gated same-message wrappers reject
  duplicate signer keys before PoP verification/cache work and no longer fall
  back to per-signature verification after aggregate rejection; distinct-message
  aggregate verification rejects duplicate messages and aggregate signatures
  that cancel to the identity before batch verification, and the blstrs feature
  backend compressed G1/G2 public-key decoders now use explicit `CtOption` to
  `Option` handling instead of panic-only unwrap assumptions. The blstrs feature
  backend also reuses the w3f signing/message semantics for normal, small,
  same-message, preaggregated, and distinct-message aggregate verification so
  backend choice does not change accepted signatures, and the feature-gated
  `iroha_crypto --all-targets` strict clippy corridor now covers the blstrs BLS
  test targets while the default w3f `bls` all-targets corridor is also green
  after removing an unused panic-only secret-key wrapper. The default w3f BLS
  backend now exposes fallible secret reload, signing, and public-key derivation
  helpers, both BLS backends expose checked keypair generation and reject
  non-empty all-zero deterministic seed material before deriving a secret, the
  public backend helper names `keypair` and `sign` now return `Result`, and the
  w3f stored-secret `public_key` helper is fallible too. SM2 top-level random
  key generation now routes through `Sm2PrivateKey::try_random`, fallible
  `TryCryptoRng` byte draws, and bounded scalar validation before returning
  key material, grouped SM2 keypair fixtures now consume that path through a
  checked random helper, while SM2 deterministic seed derivation rejects non-empty
  all-zero seed material and validates distinguishing identifiers before
  hashing candidates. Top-level BLS keygen, signing, proof-of-possession
  proving, and public-key derivation route through checked paths on
  `Result`-returning APIs;
  BLS VRF proof construction now returns `Result`, rejects invalid stored
  secret scalars before signing for both Normal and Small variants, and uses
  checked compressed-proof decoding so malformed G1/G2 proof encodings fail
  closed without `CtOption::unwrap`; governance VRF candidate generation
  handles those errors directly instead of relying on `catch_unwind`, and the
  governance council CLI plus core/Torii fixtures now propagate the fallible
  BLS keypair/signing API directly. The
  public `PublicKey::to_bytes` compatibility helper delegates to the checked
  compact-key parser so fallible public-key expansion remains live in
  BLS-enabled builds; Merkle leaf iteration now stops cleanly on an
  unexpected missing leaf slot instead of relying on panic-only internal layout
  assertions, and parent recomputation now stops if malformed in-memory state
  lacks a computed parent slot. Compact Merkle proof conversion and verification
  now share a fixed direction-bitset depth cap instead of converting
  `u32::BITS` through panic-only assertions, while decoded tree layout
  validation remains strict; the multihash `VarUint` codec now decodes through checked `u128`
  accumulation plus final bounded conversion, accepts valid max-width integer
  encodings, rejects oversized canonical varints including high final-chunk
  bits above `u128::MAX`, and constructs continuation bits without unchecked
  tail mutation; SoraNet SRCv2 certificate issue and
  verification now use checked CBOR serialization/digest helpers, with
  canonical integer emission and checked byte/text/array length conversion
  replacing panic-only encoder assumptions; core `Hash` and `HashWriter`
  hashing now use the fixed-output Blake2b-32 digest type, preserving the
  historical digest bytes while removing panic-only variable-output
  initialization/finalization assumptions; Ed25519 and default w3f BLS
  verify-ok cache keys now use the same fixed-output Blake2b-32 route while
  preserving their domain-separated transcripts; Ed25519 public-key parse,
  public-key-full fast-cache, and exact verify cache index helpers now use
  checked little-endian chunk
  extraction and invalid cache-size fallback to index `0`, eliminating
  panic-only cache-index assumptions while preserving the configured
  power-of-two masks, and `Signature::verify` now routes compact public-key
  expansion through checked parsing so malformed in-memory public keys return
  `Error::Parse` instead of reaching Ed25519 invariant panics, and rejects
  non-empty all-zero signature payloads before backend verifier dispatch;
  `KeyPair::new`
  now validates compact public-key payloads through the same checked parser
  before algorithm comparison or GOST pair validation, so malformed in-memory
  public keys return `Error::Parse` instead of panic-compatible full-key
  expansion; Norito streaming key-update verification now extracts remote
  Ed25519 identities through checked compact-key parsing, so malformed
  in-memory identity keys fail as `HandshakeError::BadSignature` before
  signature verification, suite negotiation, or transport-key state changes;
	  BLS PoP verification, PoP proving, and PoP-gated aggregate public-key
	  collection now use checked compact-key extraction, so malformed in-memory
	  BLS public keys surface through `Error::Parse` before proof verification,
	  duplicate-key caching, or aggregate backend work; public-key fallible string
	  encoders now validate compact payloads through full public-key parsing
	  before multihash formatting, so malformed in-memory keys return
	  `ParseError` instead of canonical-looking bare or prefixed strings;
	  `PublicKey` Norito serialization now reuses the cached full-key parser
	  before writing compact wire bytes, so malformed in-memory keys return a
	  Norito error and no exact encoded length instead of emitting invalid
	  archives; direct `PublicKeyCompact` Norito serialization now applies the
	  same full-key validation before writing tag+payload bytes, so malformed
	  compact state cannot bypass the checked `PublicKey` wrapper; the private
	  compact-to-full conversion is now `TryFrom<&PublicKeyCompact>` and uses
	  checked tag/payload accessors, so malformed compact state returns
	  `ParseError` instead of relying on panic-only invariant accessors;
	  `KeyPair::new` also reuses the checked public-key payload for ML-DSA
	  pair validation and compares deterministic public-key recovery output
	  instead of re-entering the compatibility `PublicKey::to_bytes()` helper
	  or issuing a randomized probe signature after compact parsing has
	  succeeded;
	  `PublicKey::try_to_bytes()` is now public, giving downstream
	  `Result`-returning paths a checked algorithm/payload accessor without
	  relying on the infallible compatibility wrapper; the legacy signer-backed
	  SCCP EVM submission helper now uses it when deriving Secp256k1 signer
	  public-key bytes, so malformed or non-Secp256k1 signer state fails closed
	  before address derivation; `PublicKey` hashing and ordering now also use
	  checked tag/payload extraction with a deterministic raw compact fallback
	  for malformed in-memory envelopes, so peer maps and sorted target sets no
	  longer reach the infallible compatibility accessor; `PublicKey::try_algorithm()`
	  now exposes checked tag access, while infallible `Display`, `Debug`, and
	  Norito JSON formatting emit a deterministic invalid-public-key marker for
	  malformed in-memory compact envelopes instead of panicking; the `iroha_core`
	  single-Ed25519 admission precheck, parsed-key cache, and allowed-signing
	  admission gate now use checked public-key accessors for fast-path
	  eligibility and signing algorithm checks, so malformed in-memory compact
	  public-key state misses the optimization or returns a structured
	  malformed-signature rejection instead of touching unchecked key invariant
	  accessors; Sumeragi vote-verifier workers now also prepare peer key
	  algorithms and aggregate-verification public-key bytes through the checked
	  accessor, so malformed in-memory consensus peer keys are reported through
	  `VoteSignatureError::SignatureInvalid` before BLS aggregate grouping or
	  raw key-byte collection; block commit/signature subset validation, native
	  AMX attestation signer checks, vNext aggregate-certificate signer
	  classification, lane-relay QC key collection, consensus peer
	  registration, consensus-key registration policy checks, active-roster
	  filtering, and admission-time signature batch prechecks now share checked
	  algorithm/payload extraction for consensus and transaction signer keys, so
	  malformed in-memory keys are rejected through existing signature and policy
	  error surfaces before BLS role checks, PoP lookup, or batch key-byte
	  collection; account/domain controller capability
	  gates now also pass multisig members through their checked public-key
	  accessors instead of the infallible member convenience methods; account
	  controller multisig policy construction, canonical member sorting, CTAP2
	  policy encoding/digesting, and account-address controller encoding now
	  extract compact public-key payloads through checked accessors, so malformed
	  in-memory controller keys return `MalformedPublicKey` or
	  `InvalidPublicKey` on result-returning paths instead of reaching
	  compatibility invariant accessors; trusted-peer PoP config parsing,
	  trusted-roster validation, staged Sumeragi v2 genesis voter validation,
	  genesis trusted-peer PoP verification, and Torii Sumeragi BLS-key operator
	  views now also classify BLS-normal keys through checked accessors, turning
	  malformed in-memory keys into config errors or non-BLS status entries
	  instead of compatibility accessor panics; SCCP Nexus BLS commit-QC
	  verification and fraud assessment attester preflights now also classify
	  public keys through checked accessors before PoP verification, aggregate
	  signature verification, or Ed25519 signature-shape checks; restricted
		  transaction-gossip target scoring and NPoS validator-election tie-break
		  scoring now also read peer public-key bytes through checked accessors,
		  falling back to the deterministic invalid-key marker for malformed
		  in-memory peer keys while preserving valid-peer score inputs; JDG
		  committee manifest validation, attestation signer membership checks, and
		  BLS aggregate PoP lookup now also canonicalize committee and signer keys
		  through checked accessors before duplicate detection, threshold
		  membership checks, or aggregate verification; SoraFS GAR verification now
		  also classifies registered gateway signer keys through checked accessors
			  before Ed25519 JWS signature verification; SoraDNS resolver-directory
			  signing payloads and Torii VPN quote response metering-key hex rendering
			  now also extract public-key payloads through checked accessors, returning
				  existing invalid-parameter/conversion-error surfaces for malformed
				  in-memory keys; SCCP EVM digest signing and Torii SCCP proof-build
				  diagnostics now also require checked Secp256k1 public-key
				  classification before EVM address/signature handling; SCCP canonical
				  Nexus message-bundle and source-chain proof-envelope packaging now uses
				  checked Merkle-proof, inclusion-branch, and dynamic-vector length writers
				  on production admission paths, returning `None` for oversized bundle,
				  source-proof, or transparent-statement transcript fields instead of
				  relying on panic-only `u32` conversions; SCCP source-adapter
				  verification statement, adapter-commitment, and FastPQ context
				  packaging now also fail closed on unbounded adapter-proof shapes and
				  checked proof-byte length prefixes, and the checked source-adapter
				  proof-body encoder now uses fallible nested proof/list/vector
				  writers across all launch lanes; shared SCCP source-state and
				  source-adapter verifier preflights now also require canonical nested
				  FastPQ proof bytes inside OpenVerify envelopes instead of accepting
				  opaque nonzero backend payloads, and the public source-proof adapter
				  verifier commitment helper verifies the adapter FastPQ proof and
				  transcript before returning metadata; strict SCCP production builders now
				  require non-SORA bundles to satisfy the production source-proof gate
				  before packaging destination submissions, and Rust EVM Groth16
				  proof requests now require canonical bundle bytes plus non-empty
				  source-proof witness bytes for non-SORA source bundles; SCCP
				  Rust TON native-recursive proof requests now apply the same canonical
				  bundle/public-input/source-proof gate before local proof generation
				  and proof-result wrapping, and the JavaScript, Python, Swift,
				  Kotlin/JVM, and Java Android SDK TON request builders now mirror that
				  canonical bundle/public-input/source-proof preflight with negative
				  tests for arbitrary bytes, swapped bundles, tampered commitments,
				  and stripped non-SORA source proofs; SCCP
				  source-verifier template hashes and source-chain proof envelope
				  shapes now reject unmapped source domains instead of falling back
					  to empty source-chain keys, while
					  diagnostic fixture builders remain available for structural fixtures, but
					  `allow_unready` manifest/source-proof bypasses remain test-only and cannot
					  be activated by exact, escaped, feature-only, or line-split
					  non-test `test-fixtures` gates; config
					  parsing for streaming identity, Torii receipt signer, and Torii
				  offline issuer public keys now also uses checked algorithm access
				  before allow-list decisions; the Nexus app
				  facade now classifies selected signing keys through checked
					  accessors before transfer draft construction,
					  Connect approval resolution, or wallet-signature requests; SoraFS
					  gateway PoR proof construction now also extracts the embedded proof
					  signer payload through checked accessors and rejects non-Ed25519
					  gateway signing keys before emitting Ed25519-labelled proof
					  envelopes; native Connect/Norito bridge C ABI and Java/JNI
					  public-key export helpers now also copy public-key payloads only
					  after checked extraction from derived or seeded keypairs; the JS
					  host native binding now also exports generated/derived keypair and
					  alias-proof signer payloads only after checked public-key
						  extraction; reusable core/Torii/config/client/SoraFS Rust fixtures
						  now also use checked public-key payload/algorithm accessors, leaving
						  the targeted compatibility-accessor scan clean across those source
						  roots; operator tooling and daemon paths for SoraDNS resolver signing
						  payloads, SoraNet relay/puzzle identity derivation, Kagami PoP/genesis
						  helpers, Taira canaries, Soracloud release governance proofs, CLI
						  governance/account controller display, and ephemeral Torii receipt-signer
						  logging now also use checked public-key accessors and propagate their
						  existing error surfaces; Taira write-canary generated signers now also
						  use checked Ed25519 keypair generation and surface OS entropy failures
						  through the canary command result path; oracle default reward/slash
						  accounts now derive their fixed Ed25519 ids through checked
						  seed-expansion while preserving infallible config defaults; core oracle
						  source and integration observation fixtures now use checked
						  `KeyPair::try_from_seed` / `SignatureOf::try_new`, with aggregation
						  guards, invalid-signature, unknown-provider, version/connector mismatch,
						  mismatched-scale, dispute, governance, and Twitter binding regressions
						  rerun; Sumeragi localnet smoke route/bootstrap, transfer-load,
						  RAM-LFE email resolver, and receipt-signing fixtures now also use checked
						  deterministic Ed25519 seed expansion and checked RAM-LFE receipt
						  signatures before realistic localnet and receipt regressions consume
						  them; and the
						  config client API snapshot fixture now derives its deterministic public
						  key through `KeyPair::try_from_seed`; the high-level `iroha` Rust SDK
						  account-address I105 fixtures now also derive deterministic Ed25519
						  account keys through `KeyPair::try_from_seed`, and the `iroha`
						  user-config timeout helper fixture now also derives its deterministic
						  account key through `KeyPair::try_from_seed`; the tracked root extracted
						  test-account fixture snippet now also uses checked deterministic Ed25519
						  seed expansion, leaving the repository-wide Rust raw-constructor scan with
						  only the intentional ML-DSA compatibility assertion; the
						  `iroha_genesis` manifest-normalize helper now generates its temporary
						  signing key through checked default key generation and reports entropy
						  failures with binary-specific context; the `iroha_crypto` SoraNet
						  handshake-check helper now derives its fixed client/relay Ed25519 keys
						  through checked seed expansion and reports failures through the
						  handshake harness error path, and the SoraNet handshake fuzz runtime key
						  helper now uses `KeyPair::try_from_seed` and skips invalid generated seed
						  cases instead of panicking; the `iroha_crypto` SoraNet handshake module
						  runtime, low-order public-key, malformed KEM, resume-hash, and relay RNG
						  regression fixtures now use checked random Ed25519 key generation;
						  offline v1/v2 interop vector generators
						  now derive their fixed issuer, account, and note Ed25519 keys through
						  checked seed-expansion helpers with fixture-specific error context; Torii
						  IVM proof-route synthetic transactions now use checked transaction
						  signing and route signing failures through the existing derive/prove
						  error paths, and the STARK route fixture uses production-floor STARK/FRI
						  verifier parameters; the
							  `iroha` dev key-material example now generates its
							  Ed25519 keypair through checked randomness and propagates entropy
							  failures from `main`; the `iroha` Nexus app transfer and tutorial,
							  `iroha_data_model` signed-block/I105 vector, and
							  `iroha_torii_shared` permissions-preimage examples now also use checked
							  Ed25519 generation or seed derivation and surface entropy or fixture-key
							  failures through their example `main` result paths; `iroha_js_host`
							  N-API Ed25519/generic keypair exports and the relay envelope sample now
							  also use checked random generation or seed derivation, mapping failures
							  into N-API errors instead of panic-only keypair wrappers; Offline
							  deterministic escrow account derivation now also uses checked Ed25519
							  seed expansion while preserving the fixed-seed infallible API; account-address
							  vector and compliance-vector fixture public keys now also use checked
							  Ed25519 seed expansion while preserving their fixed seed bytes; Norito
							  fixture-export and trigger-print scripts now also derive their fixed
							  Ed25519 fixture authorities through checked seed expansion; generic
							  Ed25519 deterministic key generation and private-key parsing now reject
							  all-zero 32-byte seed material before accepting caller-supplied signing
							  keys; X25519 deterministic key generation, imported static-secret
							  admission, and OS-backed private-key generation now reject all-zero
							  32-byte seed/private-key material before public-key derivation;
							  `iroha_test_samples`
							  sample-account generation now exposes a fallible helper and routes seeded/random
							  test key material through checked key-generation APIs; `iroha_core` tx-size
							  and memory examples now also use checked random key generation, with `tx_size`
							  surfacing entropy/keygen failures through its example `main` result; the custom
							  data-model sample fault-injection smoke test now also uses checked random
							  key generation for its transaction signer; confidential keyset generation now
							  accepts fallible `rand_core` 0.9 crypto RNGs and maps spend-key entropy
							  failures to `ConfidentialKeyError::RandomBytes`; generated confidential
							  keysets reject all-zero RNG output before HKDF expansion while
							  deterministic fixture derivation remains defined only for nonzero 32-byte spend keys;
							  SoraNet client and relay
							  handshake construction now also uses fallible `TryCryptoRng` draws for nonce,
							  Noise secret, and client ML-KEM seed material, returning labelled
							  `HarnessError::RandomBytes` failures and rejects all-zero generated
							  material before nonce, Noise, or ML-KEM seed state can be emitted;
							  SoraNet PoW and Argon2 puzzle
							  ticket minting now also uses fallible `TryCryptoRng` draws and preserves
							  labelled nonce-generation failures through `MintError::RandomBytes` and
							  the p2p challenge wrapper, with all-zero nonce draws rejected as inert
							  random material; SoraNet admission-token minting and SoraFS
							  proof-token minting now also use fallible `TryCryptoRng` draws and return
							  labelled `MintError::RandomBytes` failures for admission-token nonce and
							  proof-token id generation, including all-zero random draws; the SoraNet
							  puzzle-service admission-token relay fixture now derives its Ed25519
							  identity through `KeyPair::try_from_seed` and compares the service relay
							  id to the checked public-key payload in focused coverage; SoraNet relay
							  incentive, runtime bandwidth-proof, VPN metering, and wrong-metering
							  voucher fixtures now also derive Ed25519 fixture keys through
							  `KeyPair::try_from_seed`; SoraNet
							  request blinding nonce generation now
							  also accepts fallible `TryCryptoRng` inputs and reports entropy failures
							  through `BlindingError::RandomBytes`, while all-zero generated nonces fail
							  through the existing weak-input gate; AEAD convenience encryption now keeps
							  caller-supplied nonce compatibility unchanged while generated
							  `encrypt_easy`/`encrypt_easy_into` nonces reject inert all-zero material
							  through `Error::InertNonce`; P2P handshake hello
							  construction now also extracts local peer key metadata through checked accessors and reports
						  malformed local keys through a dedicated handshake error, while multisig
						  members expose a fallible checked algorithm accessor for result-returning
							  callers; Python native bridge keypair export, account public-key hex,
							  transaction envelope public-key embedding, public-key multihash parsing,
							  public/private multihash formatting, SM2 fixture public-key formatting,
							  and SoraFS alias-proof fixture signer extraction now also use checked
							  public-key payload/formatting access and return Python errors on
							  malformed compact key state; Python Rust binding generic and Ed25519
							  seed-derived keypair exports now also use `KeyPair::try_from_seed`,
							  return Python `ValueError`s on backend derivation failures, and compare
							  Python-exposed bytes with checked backend derivation in focused Rust
							  coverage; SM2 typed formatter export, Connect C
							  SM2 prefixed formatting, JavaScript native generic/SM2 multihash
							  helpers, Kagami prefixed key JSON output, SoraFS manifest-sign key
							  formatting, and ADDR-2 fixture multihash/prefixed fields now also
							  use checked formatter APIs before emitting operator or SDK-facing
							  strings; xtask SoraNet drill bundles, FastPQ manifests, Taikai anchor
						  summaries, OpenAPI manifests, SoraNet rollout captures, SoraDNS release
						  signing payloads, SoraFS admission/pin fixture generators, and SoraFS
						  gateway token-signing key rotation now also extract embedded Ed25519
						  public-key payloads through checked accessors before writing operator
						  artifacts; ADDR-2 compliance vectors now also extract fixture public-key
						  payloads through checked accessors before embedding address fields; the remaining
						  SoraFS conformance/chunker/pin/discovery fixtures, gov draw fixtures,
						  bridge proof vectors, config/test-network assertions, dev key example,
						  Swift parity generator now also uses checked public-key accessors, leaving the compatibility-accessor
						  scan confined to `iroha_crypto` internals, tests, and benches; inside
						  `iroha_crypto`, BLS PoP fixtures, generated public-key roundtrips,
						  Ed25519 aggregate/batch fixtures, ML-DSA/PQC fixtures, and the Ed25519
						  hot-path benchmark setup now also use checked public-key payload extraction,
						  while ML-DSA public/private formatter roundtrips and SM2 public-key
						  formatter fixtures now use checked multihash/prefixed formatter APIs,
						  and `PublicKeyFull` normalization internals now use a fallible borrowed
						  canonical-payload path for formatter encoders, and the blstrs typed BLS
						  backend plus default w3f BLS `PublicKeyFull` variants now borrow stored
						  canonical public-key payloads, clearing the targeted BLS formatter
						  compatibility-accessor scan for both backends; bridge finality
						  commit-QC validator classification now also
						  uses checked public-key algorithm access before BLS aggregate
						  verification, returning a structured malformed-validator-key error
							  for malformed compact key state;
						  JDG SDN commitment validation,
								  registry registration/lookup, and attestation commitment dedup now
								  also build SDN public-key fingerprints through checked payload
								  extraction; VPN helper-ticket serialization now also exposes fallible
								  checked byte/hex builders and Torii helper-ticket issuance uses them
								  before embedding metering public-key payloads; embedded Soracloud
								  provider-advert fixture admission now also validates provider and
								  council Ed25519 public-key payloads through checked accessors before
								  embedding advert/admission bytes;
							  X25519 public-key decoders for hybrid KEM keys, hybrid ephemeral ciphertext
				  keys, and the standalone key-exchange surface now reject low-order encodings
  before ECDH through the shared standalone X25519 predicate, with standalone
  regressions covering every distinct dalek-torsion-derived Montgomery
  encoding while retaining all-zero shared-secret fallback checks, and
  X25519 session-key derivation now maps HKDF expansion failures through the
  shared-secret `Result` path instead of using a panic-only assertion; SoraNet
  PQ ML-KEM key generation now exposes checked direct and seeded constructors,
  routes OS-backed keygen through key-pair validation, and hybrid X25519/ML-KEM
  `try_generate` consumes that checked path before reconstructing the hybrid
  secret. The public `HybridKeyPair::generate` helper now returns `Result`
  instead of panicking after checked generation; hybrid key-generation,
  encapsulation, and SoraFS hybrid payload envelope paths now consume fallible
  `TryCryptoRng` draws and return labelled RNG errors before key, ciphertext,
  or AEAD nonce material is emitted, while hybrid generated X25519 secret and
  ML-KEM seed draws now reject all-zero material before key generation or
  encapsulation can derive transport keys; the public direct and seeded
  `generate_mlkem_keypair*` wrappers now
  return `Result` instead of panicking after validation, and deterministic
  ML-KEM keygen/encapsulation reject all-zero `HedgedRngSeed` material before
  seeded RNG construction while ML-KEM caller/OS seed draws reject all-zero
  material before `*_from_rng` keygen or encapsulation, direct ML-KEM
  keypair/encapsulation reject all-zero generated backend coins before PQClean,
  direct ML-KEM keypair outputs validate generated public/secret consistency
  before return, direct ML-KEM backend shared-secret and ciphertext outputs
  reject all-zero material before wrapper construction, and seeded
  encapsulation preserves invalid-public-key preflight order;
  nonzero PQClean ML-KEM
  backend statuses now surface as
  `MlKemError::BackendFailure` through keygen, encapsulation, and decapsulation
  `Result` paths instead of panic-only assertions, and ML-KEM 12-bit
  coefficient validators now reject partial byte groups as `BadEncoding`
  instead of relying on debug-only divisibility assertions;
  Kotlin/Java Connect X25519 direction-key derivation now maps provider
  low-order agreement failures into `ConnectProtocolException`, while the
  native Connect bridge FFI rejects the same low-order peer key without touching
  output buffers;
  Kotlin/Java Connect nonce, frame/envelope codec, and queue journal paths now
  reject negative signed sequence values before nonce/AAD construction,
  encoding, decode handoff, or journal persistence, high-bit `uint64` frame
  and envelope sequences fail closed, and ciphertext-frame encoding requests the
  canonical zero-flag Connect Norito field layout explicitly;
  Kotlin Connect approval preimages now canonicalize `accountId` through the
  shared I105 account-literal helper before binding it into wallet
  authorization bytes, matching Java Android and rejecting domain-qualified
  aliases;
  Soracloud uploaded-model `X25519HkdfSha256` admission now requires exact
  32-byte recipient and ephemeral public keys and routes both through the same
  low-order decoder before bundle registration;
  confidential key hierarchy derivation now reports HKDF expansion failures via
  `Result`-returning helpers instead of panic-only assertions, and the CLI
  `create-keys` path now propagates those failures through normal command
  errors instead of a post-length-check `expect`;
  BFV identifier slot encoding and per-slot seed derivation now propagate
  conversion failures through `BfvError` instead of panic-only `usize` to `u64`
  assumptions, and BFV scalar modular helpers now avoid panic-only
  post-reduction integer conversions while preserving max-width modulus
  behavior;
  the RAM-LFE default programmed BFV hidden program now uses profile-sized
  `u16` constants instead of panic-only index conversion assumptions, and its
  memory RNG transcript binds `u64` step values directly; BFV/RAM-LFE
  domain-separated digest, receipt, and RNG-seed transcripts now stream hash
  chunks directly while preserving the previous contiguous byte layout; the feature-gated
  BFV acceleration selector now falls back to deterministic scalar schoolbook
  multiplication for zero or overflowed derived convolution lengths, and its
  CRT-NTT helper path now rejects invalid operand lengths, unsupported NTT
  lengths, and CRT reconstruction overflow before using that same fallback
  instead of relying on panic-only degree or NTT arithmetic;
  confidential encrypted memo payloads require supported versions, non-empty
  ciphertext, and low-order-free X25519 ephemeral keys before envelope use;
  this structural validation is not value authorization. The proofless generic
  `zk::Shield` instruction and CLI/native/SDK transaction encoders are removed,
  no generic public-to-confidential ingress instruction remains (the KAGEMUSHA
  V1 top-up was deleted on 2026-10-05), and the standalone envelope utility retains the same payload preflight;
  standalone ML-KEM public-key validation, secret-key validation,
  encapsulation, and decapsulation now reject all-zero public keys, all-zero
  secret keys, all-zero embedded secret-key public keys, all-zero secret-key
  implicit-rejection seeds, all-zero ciphertexts, noncanonical 12-bit
  public-key coefficients, and noncanonical secret-key private coefficients,
  and secret-key validation plus decapsulation reject corrupted embedded `H(ek)`
  public-key hashes before implicit rejection can derive divergent transport
  keys; hybrid envelope constructors and Norito streaming Kyber key-material,
  fingerprint, session, snapshot, encapsulation, and decapsulation admission now
  also reject all-zero ML-KEM public or secret key material before accepting
  fingerprints, transport state, or envelope keys, and Norito streaming
  generated X25519 ephemeral secrets plus GCK wrap nonces reject all-zero
  material before key-update or content-key update state is emitted;
  changing the streaming ML-KEM profile on key material or live sessions now
  clears configured Kyber public keys, fingerprints, and local decapsulation
  secrets before any later HPKE use, and direct local ephemeral-payload
  precomputation no longer commits Kyber transport keys, negotiated-suite, STS,
  or snapshot state before a signed key update is built or accepted;
  Norito streaming X25519 key updates now require prepared local ephemeral
  material and reject low-order remote ephemeral public keys before
  transport-key derivation or committing session state, X25519 ephemeral
  generation and outbound content-key nonce generation now propagate OS RNG
  failures as `HandshakeError::Randomness` instead of relying on the infallible
  RNG compatibility wrapper, signed
  remote key updates verify signatures and stage key-counter, suite, and
  ephemeral-shape admission on a local copy before X25519 shared-secret
  derivation, ML-KEM decapsulation, transport-key derivation, resetting, or
  committing session state, successful remote key updates now return the
  inserted transport keys directly instead of relying on a panic-only option
  readback, outbound key-update construction
  stages ephemeral generation, transcript signing, and Kyber transport
  derivation before committing session state and rejects zero or same-session
  non-increasing counters before ephemeral generation, direct Norito
  key-update state admission now rejects zero counters and suite/payload length
  mismatches before accepting counters by requiring 32-byte X25519 public keys or
  1088-byte Kyber768 ciphertexts, streaming snapshot restore also rejects zero
  key counters before replacing live session state, direct Norito key-update
  state restore/from-snapshot paths reject zero counters before replacing replay
  state, KeyUpdate and capability
  negotiation admission now rejects zero protocol versions before committing
  suite, counter, transport-key, or ACK state, capability reports must carry the
  viewer endpoint role before p2p or core ACK construction records negotiation
  state, viewer-side capability ACKs must echo the report stream id, protocol
  version, negotiated DATAGRAM size, and DPLPMTUD flag before transport state or
  callbacks are updated, direct Norito STS derivation now rejects non-32-byte
  handshake shared secrets before HKDF, and
  Norito streaming content-key updates now authenticate and unwrap the GCK
  before recording accepted rotation state so malformed wrapped keys cannot
  poison replay windows, while outbound content-key construction rejects
  regressed rotations before nonce generation or AEAD wrapping, inbound,
  outbound, and restored snapshot GCKs must now be exactly 32 bytes, including
  direct Norito GCK wrap/unwrap helpers, direct Norito content-key
  state restore/from-snapshot paths reject partial id/valid-from metadata before
  replacing replay state, and streaming snapshot restore stages
  KEM-suite id validation, transport-key derivation, and Kyber
  public-key/fingerprint validation before replacing live session state,
  rejects partial content-key or Kyber metadata, and binds Kyber768 suites to
  ML-KEM-768 snapshot metadata plus either the validated remote fingerprint for
  inbound state or the validated local fingerprint for outbound state, with
  local Kyber metadata requiring an installed decapsulation secret whose embedded
  public key and `H(ek)` public-key hash match before restore can replace state;
  transport
  capability recording and snapshot restore now reject
  DATAGRAM/fallback shape drift before updating live session state or
  capability hashes; streaming
  feedback admission now clamps inbound
  `parity_chunks`, receiver `parity_applied`, and `fec_budget` to the 6-chunk
  FEC ceiling, and caps inbound loss samples at Q16.16 100% before updating
  snapshot or outbound hint state; the first accepted feedback hint or receiver
  report now binds the feedback state to that stream id, and later feedback
  frames with a different stream id are rejected before counters, EWMA loss,
  parity, or snapshot-visible fields change;
  SoraNet NK2/NK3 handshake parsers now reject low-order Noise static and
  ephemeral public keys in decoded client and relay frames, reject malformed
  Dilithium3/Ed25519 handshake signature field lengths and all-zero signature
  payloads, require 1024-byte zero-padded frames, and reject selected
  KEM/signature ids that are absent from either peer's advertised capability
  TLVs, including the relay capability vector echoed in `RelayHello`;
  unsupported KEM ids fail at the KEM profile
  gate before downgrade telemetry is built;
  SoraNet signed-ticket signing now preflights ML-DSA-44 secret-key lengths,
  and signed-ticket decode/direct verification now reject ML-DSA-44 verifier
  public-key and signature vectors whose lengths disagree with the suite
  metadata, and all-zero signed-ticket signature material, before signing
  payloads, accepting tokens, or entering backend verification, while
  signed-ticket relay/transcript binding checks now run
  before signature work in the full verifier, and signed-ticket policy metadata
  now rejects unsupported versions, difficulty mismatches, expiry, and TTL
  window failures before signature work; signed-ticket ML-DSA payloads now use
  a fixed-size buffer with explicit used length for the optional transcript
  binding while preserving the previous contiguous signed payload layout;
  SoraNet PQ helpers now validate ML-KEM
  encapsulation public-key lengths and ML-DSA signing context/secret-key
  lengths before drawing direct or OS-backed randomness for malformed inputs;
  SoraNet runtime client-hello processing now preflights NK2/NK3 client ML-KEM
  public keys before capability telemetry, relay Noise key generation, OS-backed
  ML-KEM key generation, or encapsulation; runtime handshake descriptor
  commitments and resume hashes must now be 32-byte transcript-binding fields
  before client RNG, relay RNG, transcript hashing, KEM key generation, or
  encapsulation, client/relay capability vectors must now fit the
  length-prefixed handshake field before client RNG or frame construction,
  transcript hashing now rejects capability vectors that cannot fit its fixed
  `u32` length field before hashing, len-prefixed handshake message parsing
  now reads frame fields through checked cursor ranges, capability TLV parsing
  now reads headers and value spans through checked cursor helpers, and
  suite-list capability TLV re-encoding now rejects oversized values through
  `update_suite_list` before encoded capabilities are emitted; deterministic
  handshake fixture and telemetry signature rendering now uses checked base64
  output lengths and fallible slice encoding before returning `prefix:base64`
  witness strings; PoW
  ticket parsing now reads fixed fields through checked cursor helpers, ticket verification,
  signed-ticket verification, ticket
  minting, and Argon2 puzzle verification/minting now reject malformed
  descriptor, relay-id, or transcript binding field lengths before challenge
  derivation, solution search, Argon2 work, or public-key validation;
  PoW and Argon2 puzzle policy parameters now expose fallible constructors for
  runtime config loaders so zero minimum TTLs and inverted future-skew bounds
  fail closed without panicking, and their compatibility `new` constructors now
  return fail-closed policies instead of unwinding on invalid timing bounds; PoW
  ticket minting, Argon2 puzzle minting, and
  revocation-store insertion now reject malformed or all-zero raw signatures
  and unrepresentable expiry timestamps through checked `SystemTime`
  conversion; PoW challenge, solution-digest, and
  revocation fingerprints plus Argon2 puzzle challenges now feed BLAKE3
  incrementally while preserving the previous contiguous transcript layout, and
  Argon2 puzzle solution salts now use a fixed-size stack buffer. P2P SoraNet
  runtime construction now uses those fallible constructors for config-derived
  PoW/puzzle bounds;
  relay capability advertisement and runtime GREASE append now check TLV payload
  lengths before writing the two-byte length field, and relay config validation
  rejects configured GREASE payloads that cannot fit that wire field;
  relay descriptor replay filtering is retired because its input is relay-static;
  `pow.replay_filter.enabled = true` now fails configuration explicitly while verified
  credential replay remains in the bounded durable ticket/token stores; the same static
  descriptor is no longer accepted as a pre-authentication quota key, and nonzero
  `per_descriptor_burst` values fail configuration; relay incentive uptime/scheduled-uptime and
  verified-bandwidth epoch accumulators now saturate on overflow instead of
  panicking on extreme telemetry or proof totals; SoraNet relay admission now
  uses one static configured difficulty and rejects the retired `adaptive` key
  as unknown, removing issuer/verifier drift and the old counter/step overflow
  surface; P2P
  QUIC/TCP happy-eyeballs dialing now records the first branch failure and
  returns the second branch failure directly when both dials fail, avoiding
  panic-only option readbacks in the fallback path; SoraNet CID
  blinding key derivation now rejects
  all-zero epoch salts or all-zero circuit secrets before HKDF, and
  request-scoped blinding nonce generation now reports RNG failures without
  panicking; SoraNet
  revocation-store reload now rejects duplicate persisted fingerprints, rejects
  overflowing expiry timestamps, and bounds loaded active records to the
  configured capacity;
  SoraNet guard-directory snapshot decode now rejects duplicate or
  key-mismatched issuer fingerprints and enforces ML-DSA-65 issuer public-key
  length/phase requirements plus all-zero issuer ML-DSA public-key material
  before snapshots are admitted, with issuer key shape, inert-key rejection, and
  the fingerprint `u32` key-length field now checked before fingerprint
  derivation; the public directory issuer-fingerprint helper now returns
  `Result`, rejects all-zero nonempty ML-DSA public keys, and orchestrator
  guard-directory admission maps fingerprint recomputation errors before
  advertised fingerprint comparison; relay
  directory build and snapshot rotation now propagate fingerprint-computation
  errors with issuer context before signing or publishing a snapshot, and
  guard-pinning fixtures carry no static relay KEM material; snapshot
  decode also rejects empty issuer or relay sets before trust-map construction
  or relay certificate verification;
  SoraNet admission-token decode now reads fixed-width body fields and trailing
  signature spans through checked cursor helpers so malformed token prefixes
  return decode errors instead of relying on manual slice invariants; admission
  tokens now expose `try_encode`, and the compatibility encoder fails closed to
  a malformed frame when impossible direct token state cannot fit the v1
  signature-length prefix; admission-token ML-DSA signing bodies now use a
  fixed-size stack buffer for the domain-separated body bytes shared by minting,
  verification, and token-id derivation while preserving the previous
  contiguous transcript layout;
  SoraNet admission-token replay-store reload now rejects duplicate persisted
  token IDs and overflowing expiry timestamps, and admission-token verification
  rejects zero-length or inverted validity windows and preflights ML-DSA issuer
  public-key and detached-signature lengths before classifying full-length
  all-zero detached signatures, all before backend verification or replay-store
  mutation. Torii SoraFS stream-token
  issuance now generates token IDs through checked OS RNG fills and returns
  labelled issuance errors before
  signed token bodies are emitted; Torii internal operator-signature request
  headers now generate their base64url nonces through checked OS RNG fills and
  return labelled signing-header errors before canonical request signing, and
  ZK IVM prove job creation now generates public job ids through checked OS RNG
  fills before inserting async job state; Rust client account-signed multisig
  and operator-signed admin request headers now also generate their base64url
  request nonces through checked OS RNG fills and propagate entropy failures
  before request builders are emitted; SoraFS orchestrator guard-cache
  persistence now generates authentication-tag nonces through checked OS RNG
  fills and returns labelled persistence errors before tagged cache bytes are
  emitted;
  SoraFS orchestrator fetch job IDs now use checked OS RNG fills and return
  `OrchestratorError::JobIdRandomness` before fetch telemetry or provider
  selection continues on entropy failure; local QUIC proxy browser-manifest
  session IDs and cache-tag salts now also use checked OS RNG fills and return
  `ProxyError::RandomBytes` before manifest previews or handshake
  acknowledgements are emitted; Torii MCP async job IDs and Connect session
  SID fallbacks now also use checked OS RNG fills and fail closed with
  JSON-RPC/tool errors before async job state or Connect requests are emitted;
  Torii operator-auth WebAuthn challenge bytes and session tokens now also use
  checked OS RNG fills and fail closed with operator-auth errors before
  challenge or session state is inserted; Torii Connect session app, wallet,
  management, and relay bearer tokens now also use checked OS RNG fills and
  fail closed with internal Connect-session errors before response tokens are
  emitted;
  embedded Soracloud uploaded-model X25519 upload-key persistence now generates
  the local static secret seed through checked OS RNG fills and returns a
  labelled `io::Error` before the key file is written; CLI SM2 keygen and
  confidential `create-keys` random seed paths now generate 32-byte seed
  material through checked OS RNG fills and return normal command errors on
  entropy failure; SoraFS CLI repair idempotency keys, storage-token nonces,
  GAR receipt IDs, and admission-token RNG seeding now use checked OS RNG paths
  and return command errors on entropy failure, while hybrid manifest envelope
  encryption uses the already-fallible `OsRng` path; Soracloud CLI
  mutation-auth signature nonces and staging temporary directory suffixes now
  use checked OS RNG fills and return command errors before request signing or
  staging on entropy failure; Rust client transaction nonces now use checked OS
  RNG reads through fallible `try_build_transaction*` APIs, and client
  submission plus CLI transaction creation paths propagate those entropy
  failures before submit; transaction gossiper public/restricted shuffle seeds
  now derive deterministically from chain/local-peer/max-peer identity material
  and plane domains instead of reading process RNG during actor construction;
  telemetry future ids now use a process-local atomic counter instead of random
  ids; unseeded persisted-RBC chunk sampling now seeds `StdRng` through checked
  OS entropy and reports `SamplingError::RandomSeed` on failure while explicit
  seeds remain deterministic; proactive block-sync gossip now derives
  target-selection seeds from local-peer, height, gossip round, gossip size,
  candidate, and world-peer material instead of reading thread RNG; P2P connect
  scheduling and reconnect backoff jitter now derive bounded delays from
  domain-separated local-peer, remote-peer, address, and attempt-context
  material instead of reading thread RNG; Iroha core queue/storage tests now
  use deterministic counters for synthetic domain names, transaction hashes,
  and stress-test delays instead of process or thread RNG; operator-signature
  integration and Torii fixture helpers now use monotonic deterministic nonces
  instead of thread RNG in test-only signed requests; `iroha_test_network`
  peer selection now uses deterministic round-robin order instead of thread
  RNG; Iroha core memory-example synthetic asset/NFT values now use
  deterministic counters instead of process RNG; Izanami chaos keeps explicit
  seeds deterministic while routing unseeded `StdRng` setup through checked OS
  entropy and returning setup errors on entropy failure; CLI multisig
  auto-account registration now uses checked key generation and returns command
  errors on entropy failure; JS-host SM2 keypair generation now uses checked OS
  entropy through `Sm2PrivateKey::try_random_from_os` and returns N-API errors
  on entropy or key-generation failure; Rust SDK SM2
  `Sm2KeyPair::generate_with_distid` now uses the same checked OS helper and
  returns `ParseError` on entropy or scalar-generation failure; SoraNet PQ
  hedged seed construction now also accepts caller-supplied `TryCryptoRng`
  seed entropy, and ML-DSA keypair/signing plus ML-KEM keypair/encapsulation
  OS helpers delegate through the same fail-closed required-seed boundary
  before deriving PQ material, with direct ML-DSA and ML-KEM backend-coin
  boundaries also rejecting all-zero generated coin material before PQClean
  calls;
  admission-token verifier construction exposes a
  fallible path that rejects malformed issuer public keys before fingerprint
  derivation or runtime state admission, and the compatibility constructor now
  keeps malformed issuer keys as fail-closed verifier state that is rejected
  during ML-DSA preflight before backend signature work or replay-store mutation;
  admission-token decode now rejects unrepresentable `issued_at`/`expires_at`
  UNIX-second fields before downstream relay tools can attempt unchecked
  `SystemTime` conversion;
  admission-token minting now
  preflights issuer ML-DSA secret-key length before nonce generation, body
  construction, or backend signing, and reports nonce RNG failures as typed
  mint errors; SoraNet SRCv2 bundle
  verification re-runs canonical certificate-payload admission for in-memory
  bundles, rejects weak Ed25519 verifier keys, and preflights ML-DSA-65
  issuer public-key and detached-signature lengths plus all-zero Ed25519/ML-DSA
  signature placeholders before backend verification;
  local SRCv2 issuance reuses certificate-payload admission and ML-DSA-65
  issuer secret-key length preflight before signing bundles; first-release
  SRCv2 admission unconditionally requires both Ed25519 and ML-DSA signatures;
  SoraNet SRCv2 certificate decode now rejects key-material length drift for
  ML-DSA-65 identity keys and all-zero ML-DSA identity material, rejects
  malformed/noncanonical/weak Ed25519 identity
  public keys, rejects ML-DSA-65 detached signature length drift and all-zero
  Ed25519/ML-DSA signature fields, and its
  canonical CBOR parser rejects trailing payload/bundle bytes, non-shortest
  integer/length encodings, reordered keys at every bundle/certificate/signature/
  endpoint map boundary, and duplicate nested bundle/signature/endpoint fields,
  with accepted certificate and bundle bytes required to equal their canonical
  re-encoding and with byte/text/exact payload
  reads routed through checked cursor helpers; SRCv2 validity-duration accessors
  now use checked signed timestamp subtraction, expose a checked route for
  callers, and fail closed to `Duration::ZERO` for directly constructed inverted
  or unrepresentable windows; guard-directory relay entries
  now parse as SRCv2 bundles and must bind to a known snapshot issuer, the
  snapshot directory hash, and a unique relay ID, with relay certificate
  signatures verified against embedded issuer keys under the snapshot
  validation phase; zero-length or inverted snapshot validity windows now fail
  closed, and relay certificate validity must cover the full snapshot window
  without being published after the snapshot; SRCv2 role/capability bitmask decode rejects unsupported
  bits instead of masking them away and validity windows fail closed when they
  are inverted or published after expiry; the first-release contiguous
  17-field SRCv2 map rejects retired static relay KEM keys and KEM-rotation
  metadata, and derives PQ capability from authenticated NK2/NK3 suites;
  handshake-suite preference lists and endpoint URL lists must be non-empty and
  duplicate-free, and endpoint URL strings reject empty,
  whitespace-bearing, or control-character values; endpoint tags, when present,
  reject empty, whitespace-bearing, control-character, or duplicate values;
  remaining breadth should emphasize full cross-SDK RNS vectors and broader
  release validation.

## Kotodama first-release follow-ups

- Completed 2026-06-01: static compiler-derived access descriptors now cover
  the formerly opaque peer, subscription, VRF epoch seed, AXT, and Soracloud
  host helper syscalls. Dynamic, malformed, and syscall/operation-mismatched
  payloads stay in the incomplete-hint path and are rejected by production
  compilation instead of being represented with wildcard fallbacks.

## Nexus independent lane consensus follow-ups

> **Status (2026-07-10):** This historical checklist predates the certified
> merge-carrier implementation. Independent lane proposal, DA/RBC, QC, durable
> sidecar recovery, and exact global-carrier application are implemented. The
> canonical current design and remaining validation gates are documented in
> `sumeragi_lanes.md`, `status.md`, and `roadmap.md`.
> References below to direct WSV application describe retired intermediate
> work and are retained only as implementation history.

- Replace the current global proposal-path lane lookahead with the full
  per-lane proposal/vote scheduler so lane blocks are proposed, executed, and
  QC-sealed by their own lane committees instead of being emitted as relay
  metadata from the global block path.
- Finish wiring lane-local DA/RBC payload ownership into that scheduler.
  Proposal assembly now commits final lane ownership/RBC instance identities
  into the block execution context and exports them through Sumeragi status,
  including the QC mode tag needed to recompute the lane-local subject, payload
  ownership, and RBC instance hashes. Validators reject malformed
  execution-context bindings and forged lane ownership hashes. Kura now persists
  those committed identities as Norito-framed lane block artifacts under the
  configured lane segment, anchored to the committing global block hash, and
  rejects stale or forged artifact anchors on read. Validators now reject later
  proposals that try to reuse an already committed lane-local artifact height
  before Kura can overwrite the replay anchor, and Kura itself now rejects
  conflicting lane-artifact rewrites while preserving exact duplicate replay as
  idempotent. Proposal planning now also treats the latest valid committed
  lane artifact as a known lane tip when no relay has been merged yet, so active
  lanes continue at lane-local height `artifact_tip + 1` instead of jumping to
  the global compatibility height after idle periods; the artifact scan is
  dataspace-filtered, so newer artifacts from old/foreign dataspaces do not
  hide the latest active-dataspace tip. Autoscale scale-in now waits for
  verified unmerged relay progress on the selected managed lane at staging time
  and revalidates the same drain condition at commit time before destroying
  lane-local state. The scheduler now exposes a composed lane payload planner
  that reduces known tips, applies reset watermarks, assigns next lane-local
  slots, derives subjects, and validates DA/RBC ownership in one reusable step
  shared by preview and final proposal assembly. That planner now emits
  invariant-checked per-lane descriptors carrying the domain, selected tip,
  next slot, subject, ownership, and accepted transaction hashes together,
  and canonical lane subject/ownership hashes now bind the accepted transaction
  hash sequence that validators recompute from execution-context entrypoints.
  The handoff entries also include a Norito-backed lane block descriptor hash
  that binds the predecessor lane height, accepted work, DA/RBC ownership,
  optional predecessor descriptor hash, validator set, quorum, and QC mode tag
  for standalone proposal/vote replay. The same plan output now includes an
  explicit standalone lane-block proposal artifact and proposal hash for each
  descriptor, while the live global proposal path remains unchanged. The
  proposal artifact is now a canonical consensus data-model payload
  (`LaneBlockDescriptorV1`/`LaneBlockProposalV1`) that derives the proposal hash
  and the prepare/commit vote bodies validators sign.
  Artifact-backed proposal tips now carry the predecessor descriptor hash
  forward, reset-floored synthetic tips clear stale predecessor hashes, and
  same-height tips with conflicting descriptor hashes fail closed instead of
  letting the standalone lane chain choose an ambiguous predecessor.
  Relay-backed proposal tips carry predecessor descriptor hashes only from
  merge-admissible relays, and the relay FastPQ claim plus merge-hint root both
  bind that descriptor metadata.
  Proposal execution contexts and Kura lane artifacts now carry that descriptor
  hash plus replay material with each lane payload ownership: accepted
  transaction hashes, predecessor lane height, predecessor descriptor hash when
  known, canonical validator set, validator count, and quorum. Validators first
  bind those fields to committed route/candidate hashes, topology or lane
  authority, and QC mode tag, then share the same embedded replay-hash verifier
  as Kura artifact reads before accepting committed ownerships or persisted
  sidecars as lane tips. Both paths reject lane ownerships that omit the
  descriptor, reuse another lane identity hash, drift in replay material, claim
  a predecessor descriptor for the genesis predecessor, or carry a descriptor
  built over a different committee or predecessor.
  The plan also emits full-committee prepare and commit vote templates carrying
  canonical `LaneBlockVoteBodyV1` payloads whose signer-independent preimage
  binds proposal hash, descriptor hash, lane coordinates, subject, DA/RBC
  ownership, accepted transaction hashes, validator-set hash, quorum, and QC
  mode tag. `iroha_core::lane_consensus` now validates signed BLS lane votes
  and aggregates deterministic `LaneBlockQcV1` certificates while rejecting
  malformed bodies, validator-set hash drift, non-canonical committees,
  duplicate/unknown signers, non-BLS signers, body drift, invalid signatures,
  and under-quorum vote sets. Data-model unit coverage now mutates every
  descriptor/proposal replay, predecessor, ownership, validator-set hash
  version/hash, quorum, and QC-mode field, and every `LaneBlockVoteBodyV1`
  replay, ownership, validator-set, quorum, and QC-mode field, to prove each
  one changes the relevant canonical identity or signed preimage. This
  gives the standalone scheduler a lane-local
  block handoff and QC construction surface instead of parallel vectors or
  fetched-batch indices alone. The core lane-consensus helper also validates
  standalone proposal artifacts before session insertion, rejecting malformed
  work, invalid predecessor shape, non-canonical or duplicate committees,
  validator-set hash drift, descriptor hash drift, and proposal hash drift.
  Lane-local proposal, vote, and QC artifacts now also have explicit
  `BlockMessage` transport variants, consensus-status labels, fail-closed
  main-loop handlers, and a bounded lane-session cache. The handlers validate
  proposal shape, signed vote ingress, QC structure, signer PoPs, and
  pre-aggregated QC signatures before caching valid artifacts as deferred
  `payload_unapplied` work; exact replays are deduplicated, conflicts fail
  closed, out-of-order artifacts are reconciled when their proposal arrives,
  and lane-local messages bypass the global height/view future-window gate
  because their heights are independent lane heights rather than global block
  heights. Locally sealed QCs are now handed to background broadcast once,
  while inbound QCs are cached without echoing, and sessions with a matching
  proposal plus prepare/commit QCs are moved through a bounded actor-owned
  committed-session staging queue for lane-block application. That staging
  queue now publishes a bounded Sumeragi/Torii status surface with
  descriptor/proposal hashes and compact prepare/commit QC summaries for
  operator rollout evidence. Final proposal assembly now broadcasts finalized
  lane-block proposals plus the local BLS prepare vote after stale-proposal
  checks pass, and four-peer main-loop coverage now verifies a final proposal
  can emit two lane-block proposal artifacts plus two local prepare votes for
  active lanes at different lane-local heights without waiting for idle default
  lane work. Mixed-committee coverage now verifies that the same final path
  still broadcasts proposals for both active lanes while only signing and
  broadcasting the prepare vote for the lane whose validator set includes the
  local peer. Negative main-loop coverage also verifies a cross-lane batch with
  one missing lane authority is deferred atomically, clears stale ownership
  status, and requeues both transactions instead of accepting partial lane
  progress. Validated prepare QCs now unlock a one-shot local BLS commit
  vote broadcast that is cached locally for commit-QC sealing. Queued committed
  sessions now feed proposal-planning lane tips with the committed descriptor
  hash, allowing subsequent lane-local slots to advance from sealed QCs before
  durable standalone execution is complete. Certified standalone lane-block
  sessions are now also persisted as Norito-framed Kura sidecars with
  proposal/prepare-QC/commit-QC plus signer-PoP aggregate validation and
  reloaded into proposal-planning lane tips and the bounded committed-session
  queue/status surface after restart. The status surface now reports
  certified-only sessions as `awaiting_executable_payload` and uses Kura's
  canonical block body plus the lane ownership sidecar to advance recoverable
  sessions to `payload_available_awaiting_executor`; Kura also persists the
  recovered proposal, artifact, entrypoint hashes, and verified accepted
  entrypoints as a durable execution-input sidecar, advancing those handoffs to
  `payload_recovered_awaiting_state_application`. When canonical block results
  are already present, Kura also records a durable application-receipt sidecar
  with the certified proposal, ownership artifact, canonical block height/hash,
  accepted entrypoint indices/hashes, and committed `TransactionResult`s,
  advancing those sessions to `state_applied_by_canonical_block` only for
  canonical receipts. Clean current-tip preflights are readiness evidence only;
  WSV publication and durable application receipts use the canonical global or
  merge execution corridors.
- Add a multi-peer integration corridor proving two active lanes can advance at
  different heights, produce lane-domain QCs, upgrade FastPQ relay proofs, and
  merge without waiting for an idle configured lane. Unit-level restart/replay
  coverage now rejects old-incarnation verified relay contract-state replays
  after lane reset, and relay caches now tolerate out-of-order future artifacts
  while merge candidates/commits advance each lane contiguously. Proposal
  scheduling now floors lane-local block tips at reset watermarks so recreated
  lanes resume after their previous incarnation, including proposal-path stale
  old-incarnation tip coverage. Lane reset also prunes lane-scoped operator
  status snapshots so retired/recreated lanes do not keep stale activity,
  commitment, relay, payload-ownership, or governance status. The autoscale
  soak reporter now records quorum-required maxima, successful scale-out
  minimum peer counts, required scale-in cycle counts, required scale-in quorum
  minima, and optional scale-in cycle counts so rollout summaries expose the
  quorum evidence instead of only aggregate miss counters. The remaining
  breadth is the multi-peer corridor; the 2026-07-07 four-peer strict autoscale
  expand/contract localnet blocker is closed after the strict expansion probe was
  hardened to require fresh deterministic scale-out transition evidence and
  expanded-lane status evidence in the same readiness gate. Once transition
  quorum is observed, strict probes stop adding top-up load while waiting for
  status propagation. The strict run now observes load application,
  deterministic scale-out/status quorum, and scale-in quorum in cycle 1, and the
  public-profile strict transition run passes the same combined evidence gate.
  The repeated two-cycle autoscale localnet also passes under the
  stop-top-up-after-transition-quorum policy.
  Scale-in commit-revalidation coverage now also mirrors the scale-out
  adversarial boundary: tampered pending transition metadata, survivor catalog
  rows, preserved retired-lane catalogs, and derived lane configs all abort
  before retired-lane Kura/tiered storage or committed catalog publication.
  The 13-peer global cross-dataspace localnet route-probe corridor (twelve lane
  validators) now also requires
  observable replayable lane-payload ownership for DS1 and DS2 with exact
  dataspace IDs, the expected four-validator lane committee, and the
  deterministic three-vote quorum. The route-probe parser now requires those
  ownership rows to pass the canonical replay-material hash validator, treats
  same-slot ownership identity drift or malformed latest ownership rows as
  non-progress, and keeps same-height cross-peer observations from combining
  into quorum progress unless their descriptor, subject, payload-ownership, and
  RBC-instance identities match. Conflicting top committed-lane or ownership
  identities that independently satisfy quorum at the same lane height/view now
  fail closed instead of being selected by iterator order. A second DS1 route
  probe proves one active lane can advance beyond another in lane-local block
  height without waiting for the idle configured lane, while helper coverage
  rejects wrong-dataspace, empty-work, under-quorum, single-peer-ahead,
  malformed-latest, forged-replay-hash, and conflicting-identity ownership
  evidence.
  Committed standalone lane-block summaries are also exported through the
  canonical Norito status payload, and the localnet corridor parser requires
  each active lane to publish committed rows whose embedded prepare and commit
  QC signer counts satisfy the exact lane quorum. The parser now also retains
  committed-lane descriptor/proposal hashes, subject hash, payload-ownership
  hash, RBC-instance hash, and QC-mode tag and treats same-height rows with
  identity drift or malformed latest QC metadata as non-progress, so
  conflicting certified payload identities cannot fake scale-out progress,
  combine into cross-peer route progress, or prove safe scale-in contraction.
  Runtime committed-lane status merging now also requires
  descriptor hash plus proposal, prepare-QC, and commit-QC equality before
  replacing an existing row, so malformed in-memory descriptor or QC drift
  remains visible as suspicious evidence instead of overwriting the original
  certified status. That separates independent lane-height planning evidence from
  standalone lane-block QC evidence instead of treating operator status-row
  fanout as the safety proof. Recovered inputs and clean preflights remain
  bounded staging evidence; canonical block or merge receipts are the only WSV
  application proof.
  Nexus-active lane-block queueing also prunes in-memory lane-block
  proposal/QC sessions and committed-lane execution queue entries against the
  current active `(LaneId, DataSpaceId)` routes plus lane reset watermarks
  before status publication, so retired or recreated lane sessions cannot keep
  stale slot claims or committed status alive in actor memory. Proposal
  planning now filters in-memory committed-queue lane tips through the same
  active-route and reset-watermark predicate before mutating prune runs, so
  stale queued old-incarnation sessions cannot become fresh proposal
  predecessors. Committed block-artifact tip snapshots read from Kura and cached
  relay envelopes also honor lane reset watermarks, and relay envelopes must be
  merge-admissible with a standalone lane-block descriptor hash before they can
  seed proposal predecessor tips. Historical lane payload artifacts,
  old-incarnation relays at or below the reset height, or descriptorless
  verified relays therefore do not export stale predecessor descriptor hashes or
  global-height compatibility coordinates into fresh proposal planning.
  Lane-block ingress and local broadcast preflight
  perform the same Nexus-active route and reset-watermark checks before
  proposal/vote/QC caching or transport, so stale route or old-incarnation
  messages cannot seal or rebroadcast QCs, emit local commit votes, or enqueue
  committed lane-block sessions during the pre-prune window. Ingress also
  checks the embedded validator set hash/count/full set and quorum threshold
  before session insertion: shared single-routable-lane mode uses the live
  consensus roster from lane-block planning, and proposal-lookahead mode uses
  current authoritative lane peers. Vote ingress also requires the vote signer
  to belong to that expected committee and requires an authenticated sender
  before session insertion, so senderless votes or orphan votes with spoofed
  committee metadata fail closed before cache side effects. Active-route
  messages from self-appointed or quorum-downgraded committees fail closed
  before cache or broadcast side effects. The generic
  `SumeragiHandle::try_incoming_block_message*` paths now treat standalone
  lane-block proposal/vote/QC messages as blocking consensus evidence, matching
  network relay ingress, so block-worker queue pressure cannot best-effort drop
  lane-block evidence before route, sender, and committee authority validation
  runs.
  Final proposal assembly also loops locally produced lane-block proposals and
  locally signed BLS prepare votes back through the same ingress handlers after
  scheduling their background broadcasts. Leaders no longer wait for network
  echo before caching their own lane-block proposal/vote evidence, while
  nonlocal or tampered prepare-vote plans still skip local vote caching.
  Local lane-block transport preflights route, committee authority, signature,
  and cache-conflict admissibility before scheduling proposal, prepare-vote,
  sealed-QC, or post-prepare-QC commit-vote broadcasts, so duplicate,
  same-slot conflicting, or stale-route locally produced artifacts are recorded
  as duplicate/invalid without reaching background transport. Active-route
  artifacts with spoofed validator-set metadata are pinned at the same local
  broadcast boundary for both post-prepare commit votes and sealed prepare/commit
  QCs, so cached non-authoritative sessions cannot leak to peers or enqueue
  committed lane-block execution. Ingress and local transport-preflight coverage
  also pin the case where the embedded validator set is exactly the live shared
  committee but the quorum threshold is forged downward; proposal, vote,
  post-prepare commit vote, and QC paths all fail before cache, status, queue, or
  transport side effects.
  Lane consensus-domain planning now also refuses explicit committee
  `min_quorum` values that do not match the deterministic commit quorum for the
  canonical validator set, and lane-block vote planning refuses internally
  hash-consistent descriptors whose embedded quorum diverges from that same
  canonical threshold before any local validator signature is produced.
  Local commit-vote production now applies the active-route, authoritative
  committee, canonical-quorum, and local-signer checks before signing cached
  prepare-QC requests, so forged cached sessions for inactive routes,
  self-appointed committees, or quorum-downgraded live committees are skipped
  without producing a local BLS commit vote.
  Local prepare-vote production now applies the same pre-sign checks to
  scheduler vote plans, so spoofed or quorum-downgraded active-route prepare
  plans cannot create a local BLS prepare signature, orphan lane session,
  invalid-vote drop, or background broadcast.
  Committed lane-block queue hydration now revalidates certified sessions
  before bounded restart admission, rejecting invalid proposals, missing
  aggregate QC signatures, wrong prepare/commit phase slots, and proposal/QC
  committee drift before malformed durable sidecars can publish status, recover
  payloads, or consume capacity needed by a later valid certified session.
  Certified lane-block sidecar snapshots also honor lane reset watermarks:
  stale same-lane sidecars at or below the reset height no longer seed
  proposal tips, restart execution queues, or autoscale unapplied-progress
  checks, while fresh post-reset sidecars remain visible. Sumeragi startup
  preloads the persisted DA reset journal before certified sidecar recovery.
  Autoscale commit re-prunes lane-scoped block-local cleanup state immediately
  before publishing the world block, covering AXT replay rows, DA pin indexes,
  public-lane validators/economics, and verified relay contract storage, then
  repeats durable cleanup in committed storage so late inserts after lifecycle
  staging cannot survive scale-in for retired lanes. Autoscale localnet cycle
  outcomes and soak artifacts preserve canonically applied committed lane-block
  peer counts separately from generic committed progress. The rollout parser
  now also rejects conflicting latest committed-lane status rows for the same
  lane height/view instead of choosing one by dataspace id, while preserving
  exact duplicate rows as idempotent evidence. It also counts only
  default-dataspace committed-lane rows as autoscale
  expansion/application/destruction evidence and treats ambiguous or
  certified elastic-lane committed-block evidence as non-idle for scale-in.
  Default-dataspace committed-lane rows also have to carry canonical quorum
  metadata before they can prove rollout progress: `min_quorum` must match the
  deterministic quorum for `validator_count`, the advertised validator set must
  fit the fixed localnet peer set, and prepare/commit signer counts must be in
  range while satisfying that quorum. Quorum-downgraded rows, impossible signer
  counts, or impossible validator-set sizes cannot fake expansion/direct
  execution, and malformed latest default-dataspace rows remain non-idle for
  scale-in instead of being treated as absence.
  Lane-relay summaries now also preserve dataspace ids, standalone descriptor
  presence, and merge-admissibility state. Autoscale expansion only counts
  default-dataspace relay rows that are both descriptor-backed and
  merge-admissible, while descriptorless or non-merge relay rows for the
  retiring elastic lane still count as lingering state and block scale-in.
  Wrong-dataspace relay rows cannot fake default-route progress or block
  destruction.
  Exact duplicate same-height default-dataspace relay rows are idempotent, while
  descriptor-hash drift or merge-admissibility drift in the latest relay row set
  is ambiguous, cannot prove expansion, and remains non-idle for scale-in.
  The runtime lane-relay status cache now keys entries by immutable relay
  identity, including header hash, descriptor hash, DA hash, settlement hash,
  RBC byte count, and manifest root, so descriptor drift remains visible while
  merge-admissible rows can still upgrade matching pending rows and cannot be
  downgraded by later non-merge rows. The state-side `LaneRelayStore` now uses
  the same immutable identity boundary before pending rows can be upgraded with
  QC/FastPQ material, so descriptor drift cannot overwrite pending relay
  evidence under the guise of a verified upgrade. `State::record_lane_relay` has
  matching regression coverage to keep rejected drift from replacing the state
  relay cache or Sumeragi status cache.
  Sumeragi lane-payload ownership status now validates canonical replay material
  before exposing rows or applying the status cap, so malformed subject,
  payload-ownership, RBC-instance, or descriptor hashes cannot leak as ownership
  evidence or evict valid recent rows.
  Committed-lane status now validates each row against its embedded proposal,
  prepare QC, and commit QC before exposing or capping it, reusing the
  lane-consensus committed-session validator so summary drift, malformed
  proposal hashes, QC phase drift, committee drift, missing aggregate
  signatures, and under-quorum signer bitmaps cannot leak as certified
  lane-block evidence.
  Commit-quorum discovery in the localnet corridor now also fails closed after
  timeout when peer status reports split-brain or out-of-range explicit quorum
  values, explicit quorum values that do not match reported validator-set length
  or peer-count fallback quorum, or conflicting/out-of-range validator-set
  lengths, instead of masking that status drift with peer-count fallback.
  Expansion status and deterministic transition comparison now also require
  provided baselines to cover the same peer set as the current snapshot, so
  partial snapshots cannot count current-state lane evidence or transition
  deltas as fresh expansion/scale-in quorum.
  Duplicate elastic-lane status rows are also malformed destruction evidence
  rather than proof that the lane is absent. Ambiguous baseline lane evidence
  for status, commitments, committed blocks, or validators cannot be repaired
  by later clean rows into fresh expansion proof. Lane-specific transition-log
  evidence is counted by unambiguous transition height instead of raw matching
  lines, so exact duplicate same-height rows are idempotent and conflicting
  same-height rows remain visible as ambiguous evidence that blocks fresh
  scale-out/scale-in delta quorum from either the baseline or current snapshot.
  Elastic-lane storage fallback now requires structural growth (file count,
  total bytes, or first presence) instead of metadata-only mtime movement, and
  complete peer storage snapshots plus aligned current/baseline elastic-storage
  rows are required before storage fallback can prove expansion.
  Sumeragi lane-commitment summaries use the same latest-unambiguous rule so conflicting
  latest rows cannot fake current activity, post-baseline progress, or
  post-baseline declaration transitions, and stale positive rows cannot
  override a newer idle commitment. Ambiguous commitment rows also cannot prove
  scale-in idleness.
  Public lane-validator summaries now fail closed for conflicting duplicate
  rows in both directions: ambiguous live/terminal rows do not create expansion
  evidence and do not prove scale-in idleness. The lane-local
  session cache also protects quorum-certified prepare+commit QC sessions from
  ordinary cache eviction until the executor boundary drains them, so
  committed-lane queue backpressure cannot silently drop certified lane
  progress. Sumeragi tick also redrives the committed-lane executor queue,
  records receipt-backed progress for already pending sessions, and admits
  protected committed cache entries once queue capacity is freed, so
  backpressure recovery no longer depends on a fresh lane-block network
  message. Same-tick committed-lane status now merges newly recorded
  applied-receipt evidence with the final post-prune queue snapshot, keeping
  rollout telemetry accurate across that recovery transition. Startup status
  also merges the latest durable application-receipted certified sidecar per
  active lane with the in-memory pending queue, so restarted peers keep
  publishing applied committed-lane evidence for canonical block and merge
  receipts even when already receipted sessions are skipped by execution
  hydration. The broader multi-peer independent-lane corridor is now narrowed
  to full rollout evidence beyond the observable ownership-planning and
  embedded committed-QC gates. Queue-generated execution preflights are bound
  to the canonical committed WSV snapshot hash rather than only the block tip,
  preventing stale preflight evidence from surviving an intervening state
  transition.
  The committed-session queue is now receipt-backed rather than purely sticky:
  it releases capacity only after Kura validates a durable application receipt,
  and restart hydration skips already application-receipted certified sidecars
  so stale applied work cannot crowd out unapplied committed lane blocks. Kura
  now also revalidates recovered execution-input sidecars against the current
  canonical lane payload artifact and proposal block before exposing them to
  canonical application, rejecting stale recovered inputs after
  canonical artifact drift.

## Cross-dataspace AMX follow-ups

- Completed 2026-07-10: the four-peer native AMX routing and restart corridors
  now require every peer to converge on the exact receipt identity, phases,
  participant legs, validator sets, signer bitmaps, and BLS signatures in the
  committed block, typed Sumeragi status, and verified lane relay. The
  downstream relay audit recomputes settlement hashes and rejects adversarial
  source, route, height, leg, digest, phase, bitmap, and signature mutations.
- Completed 2026-07-10: Python and Swift now expose strict first-class Nexus fee
  and native AMX phase/body/QC/leg/receipt models for lane commitments and relay
  envelopes. Their parsers fail closed on malformed or internally inconsistent
  evidence, while Torii uses one canonical JSON shape for status and relays and
  OpenAPI declares exact required fields, versions, enums, array constraints,
  hash literals, bitmaps, and 96-byte BLS signatures. The Rust client already
  preserves these fields through its typed Norito status model; Kotlin, Java,
  and Mochi currently expose no Sumeragi settlement DTO surface to mirror.
- If future coordinator execution supports partial prepare failure inside a
  batch, extend `NativeAmxReceipt` with explicit abort evidence. Finalized
  receipts currently represent only successfully committed native AMX batches.

## Transaction pipeline follow-ups

- Broaden fee/gas/Nexus detached postprocessing beyond the current simple
  transparent single-transfer case. Remaining work includes deterministic
  receipt/effect representation for multi-instruction and multi-asset deltas,
  plus data-trigger-aware fee event ordering. Those shapes intentionally remain
  visible as `fee_postprocessing` detached fallback reasons in Sumeragi status
  and pipeline telemetry.
- Broaden validation from the focused scheduler, dynamic IVM access, telemetry,
  fee-enabled transfer, query-continuation, and receipt-hash tests to the next
  long `cargo test --workspace` corridor once the repository-wide dirty
  worktree settles.

## Torii query API follow-ups

- Completed 2026-06-01: audited endpoint-specific OpenAPI schemas and SDK
  convenience parsers for app endpoints that expose concrete response models.
  Account, domain, account-asset, asset-definition, NFT, RWA, asset-holder, and
  repo-agreement list/query responses now share concrete page schemas that
  document required `has_more`, required `count_mode`, and optional `total`;
  JavaScript and Python convenience parsers preserve bounded page metadata and
  reject malformed count flags before treating a response as valid.
- Completed 2026-06-01: added sustained Torii query-load profiles to
  `torii_hot_paths` for signed iterable `/query` in stored-cursor bounded mode,
  primary account-alias projections, account-asset predicates, asset-holder
  scans, committed-history contract-activity predicates, and generic aggregate
  queries under concurrent in-process HTTP clients. The signed profile walks
  deep continuation chains over the Arc-backed snapshot replay path, the
  contract-activity profile builds real committed transactions with contract
  metadata, and `query_load_profiles` rejects malformed or adversarial
  benchmark shapes before fixture construction.
- Completed 2026-06-01: added a localhost socket transport group for the same
  sustained Torii query profiles. The socket group binds ephemeral Axum
  listeners and drives them with pooled `reqwest` clients so handler-only
  measurements can be compared with real HTTP transport and body IO overhead.
- Run the full signed/app socket profile suite under production-like datasets
  and longer measurement windows to decide whether the existing account-asset,
  asset-holder, and contract-activity predicates need additional indexes or
  materialized views.

## Torii Offline API follow-ups

- Completed 2026-10-05: the KAGEMUSHA V1 Offline API (`/v1/kagemusha/*`
  readiness, top-up, redeem and operation status) was deleted with the old
  KAGEMUSHA implementation. The current wallet exposes only the canonically
  authenticated private finalized-load issuance read at
  `/v1/kagemusha/{scheme}/wallets/{wallet}/loads/{request}`. Other ledger-family
  routes from `specs/kagemusha_single_design_proposal.md` §6 remain open.
- Completed 2026-07-30 and finalized 2026-08-30: removed the unshipped
  governance council `derive-vrf` prototype, its `gov_vrf` feature, HTTP/MCP
  surfaces, and independently authorized persist/replace/manual epoch-roster
  surfaces. Attempt-local Parliament bodies use canonical bonded-citizen
  snapshots plus finalized threshold-beacon pulses.
## SoraFS paid pin validation follow-ups

- Completed 2026-06-04: reran the SoraFS paid-pin validation corridor across
  the data-model SoraFS filter, DA pin intent query-response roundtrip, Core
  pin-registry suite, Torii storage-pin/discovery suite, and integration gateway
  policy/conformance filter. The pass is green after the paid-pin adversarial
  coverage and proof-token hardening work.
- Completed 2026-06-06: Torii DA commitment proof/verify routes are now pinned
  at handler level with a committed block-backed Merkle proof round trip and a
  tampered-root rejection. The OpenAPI and MCP descriptions now describe the
  Merkle proof contract instead of the stale placeholder wording.
- Completed 2026-06-06: Torii DA pin-intent proof/verify handlers are now
  pinned against the live indexed `DaPinStore`: handler coverage proves by
  lane/epoch/sequence, verifies the returned block location payload, rejects a
  tampered indexed location, and the OpenAPI/MCP descriptions now describe the
  indexed-location contract instead of placeholder proof language.
- Completed 2026-06-06: Torii SoraFS CAR range coverage now includes a
  non-full middle-of-manifest window spanning exactly two aligned chunks. The
  regression verifies the streamed CAR against the manifest-bound byte range
  and pins `Content-Range` plus `X-Sora-Chunk-Range` metadata for partial
  responses.
- SoraFS proof-token decode now uses checked cursor reads for fixed-width
  moderation-token fields with truncated-prefix regression coverage while
  rejecting unrepresentable issued/expiry UNIX-second fields before
  `SystemTime` conversion; proof-token body encoding now exposes `try_encode`,
  routes mint/signature/digest helpers through checked entry-count and
  entry-length narrowing, and makes the compatibility `encode` path fail closed
  to a malformed frame for impossible direct token states; proof-token minting
  now reports token-id RNG failures through labelled `MintError::RandomBytes`
  before blinded digest or signature material is produced; proof-token base64
  header encoding/decoding now uses the `base64` crate's checked no-alloc slice
  helpers instead of manual capacity arithmetic and panic-only buffer
  assertions; proof-token binary/base64 decode and direct signature verification
  now reject all-zero Ed25519 signature placeholders before accepting or
  verifying externally supplied moderation-token signature material; gateway
  moderation-token context verification now matches the optional chunk digest
  exactly, so chunk-bound tokens cannot satisfy manifest-level failure evidence
  and manifest-level tokens cannot satisfy chunk-level evidence.
- Remaining breadth should include SDK validation once Java is available and
  any wider admission/manifest-envelope/full-corridor reruns not covered by the
  current focused Torii SoraFS checks.

## Norito columnar and streaming validation follow-ups

- Fold the focused NCB row-count prefix regression into the next full Norito and
  workspace validation budget. Columnar `u64` combo views now read their `u32`
  row-count prefix through a shared checked helper, so truncated prefixes return
  `Error::LengthMismatch` on the normal decode path. AoS optional string/u32
  decoders now reject noncanonical option discriminants instead of treating any
  nonzero tag as `Some`. Streaming baseline RLE
  block decode now reads DC differences and AC records through checked helpers,
  keeping truncated or overflowed cursor state on `CodecError::TruncatedBlock`
  before offset advancement, and baseline frame/chroma metadata uses checked
  fixed-width readers before chunk payload slicing. Bundled rANS SIMD stream
  lane lengths also use a checked prefix reader before cursor advancement or
  lane slicing.

## ZK audit validation follow-ups

- Retired 2026-08-26: the unmounted prover-report HTTP query surface and its
  synthetic integration router were deleted for the first release. Background
  reports remain bounded node-local worker diagnostics, so no public report
  filter or client compatibility contract remains to validate.
- Completed 2026-06-10: developer-only Halo2 fallback commit/Merkle fixtures now
  use a deterministic shifted Pow5 pair hash instead of additive/unshifted
  placeholders for commitment, nullifier, and Merkle2 relations. Focused
  regressions reject stale placeholders for commit-open, anon-transfer, tiny
  Merkle2, and vote-commit Merkle2 while shared Rust/Core and SDK mirror
  backend admission continues to reject legacy/developer-only labels, including
  direct and punctuation-spliced todo/draft/pending and replace/not-for-production
  marker aliases.
- Fold the now-green focused ZK cleanup and adversarial negative corridor into
  the next long `cargo test --workspace` / CI validation budget.

## TradFi ISO 20022 interop follow-ups

- Completed 2026-06-01: added inbound lifecycle endpoints for `pacs.002`,
  `pacs.004`, `camt.056`, `sese.023`, `sese.024`, and `sese.025`, with OpenAPI
  and MCP submission surfaces. The bridge records each lifecycle message in the
  durable ISO record model, rejects duplicate payload, business-message-id, and
  UETR replays, applies `pacs.002`/`pacs.004`/`camt.056` and
  `sese.024`/`sese.025` updates only when the referenced durable record is
  known, and records `sese.023` as a settlement instruction. The 2026-06-04
  ledger-crosswalk gate below now requires account, instrument, venue, CSD, and
  cash-leg mappings before live securities instructions are durably accepted.
- Completed 2026-06-01: added durable-record outbox helpers for `pacs.004`,
  `camt.029`, `sese.024`, and `sese.025`. Payment returns require recorded
  settlement amount/currency from the original payment message; securities
  confirmations require captured `sese.023` amount, currency, quantity, movement,
  payment, and execution-plan fields rather than fabricating missing data.
- Completed 2026-06-01: added a fail-closed Torii verification path for
  `require-verified` embedded-signature profiles. The bridge now accepts the
  supported P-256/SHA-256 enveloped XMLDSig/XAdES subset only after payload
  digest and signature verification, rejects tampered digests/signatures and
  unsupported algorithms, and keeps live `reject-unsupported` profiles rejecting
  embedded signature blocks.
- Completed 2026-06-01: added profile-specific XMLDSig trust pins for
  `require-verified` profiles. Torii now rejects otherwise valid signed
  payloads unless the verified raw public key or DER certificate SHA-256 digest
  matches the selected rail profile, rejects non-canonical/all-zero configured
  pins at startup, and covers the supported C14N 1.0, C14N 1.1, and exclusive
  C14N algorithm identifiers with deterministic fixtures.
- Completed 2026-06-01: added XMLDSig/XAdES certificate-chain verification for
  `KeyInfo/X509Data`. Torii now accepts at most eight unique DER certificates,
  derives the signing key from the leaf
  certificate, verifies each supplied leaf-to-issuer chain link by binding the
  child issuer distinguished name to the parent subject distinguished name and
  checking the child signature before exposing issuer/root DER SHA-256 digests
  to the selected profile, requires leaf critical `keyUsage` carrying
  `digitalSignature` while rejecting CA leaf certificates, requires issuer
  critical CA `basicConstraints` plus critical `keyUsage` carrying
  `keyCertSign`, requires every supplied certificate to use ECDSA-with-SHA256
  over id-ecPublicKey secp256r1 with uncompressed P-256 SEC1 subject public-key
  bytes, enforces issuer `pathLenConstraint` values for subordinate CA chains,
  rejects unknown, malformed, or unsupported parsed critical X.509 extensions
  on every supplied certificate, checks leaf and issuer certificate validity
  against deterministic verified signed `SigningTime` or BAH `CreDt`, and
  covers the pinned-issuer accept/reject corridor with generated P-256 fixtures.
- Completed 2026-06-02: added a deterministic supported XML canonicalization
  subset for XMLDSig verification. Torii now canonicalizes `SignedInfo` and the
  referenced enveloped payload before hashing or signature verification. The
  supported Reference URI scope is a single empty URI or a unique same-document
  `#id` target using exact `Id`, `ID`, `id`, or `xml:id` attributes; remote,
  empty-fragment, duplicate-ID, namespace-qualified non-`xml` ID attributes, and
  same-document payload targets that do not strictly enclose the verified signature carrier
  fail closed, while selected same-document targets carry ancestor namespace
  declarations into root canonicalization. Each supported payload Reference must
  declare an enveloped-signature transform first, may add at most one final
  supported C14N transform that controls digest canonicalization, and must use a
  SHA-256 digest method; missing, reordered, extra, or unsupported transforms
  fail closed. The verifier also accepts one optional XAdES `SignedProperties`
  Reference with the XAdES `SignedProperties` Type URI, a local `#id` target, one
  supported C14N transform, and a SHA-256 digest; its enclosing
  `QualifyingProperties` target must bind to the enclosing `Signature` `Id`, and
  certificate-backed XAdES signatures must present a non-empty, duplicate-free
  ordered prefix of the verified XMLDSig certificate-chain SHA-256 digests,
  starting with the leaf certificate. The supported signed-property subset
  requires direct
  `Signature/Object/QualifyingProperties/SignedProperties/SignedSignatureProperties`
  structure; `QualifyingProperties` accepts only `Target`,
  `SigningCertificateV2` accepts only attribute-free direct `Cert` children with
  attribute-free direct `CertDigest` children, a `DigestMethod` carrying only
  `Algorithm`, and text-only digest values. Signed `SigningTime` is a singleton
  attribute-free text leaf. Any `SignedProperties` element under the signature
  must be the verified referenced direct target; unreferenced, wrapped, or
  duplicate `SignedProperties` elements and unrelated additional References fail
  closed.
  Supported XMLDSig method and transform elements are parameter-free: `CanonicalizationMethod`,
  `SignatureMethod`, `DigestMethod`, payload Reference transforms, and
  `SignedProperties` transforms reject non-whitespace child content such as
  `InclusiveNamespaces`, XPath, HMAC, or digest parameters. Critical XMLDSig
  method elements must appear exactly once, Reference transforms must be
  enclosed in exactly one attribute-free `Transforms` wrapper, and only
  implemented ordinary attributes are accepted (`Algorithm`, payload Reference
  `URI`, and XAdES Reference `URI`/`Type`). Extra direct children under
  `Reference` or `Transforms` fail closed, and supported References must keep
  direct children ordered as `Transforms`, `DigestMethod`, then `DigestValue`.
  Top-level `Signature` and
  `SignedInfo` parsing now accepts only implemented direct children in supported
  XMLDSig order, so reordered or wrapped `SignedInfo`/method nodes, unsupported
  direct children, and duplicate singleton signature nodes fail closed. The
  payload may contain exactly one supported signature carrier: either a bare
  XMLDSig `Signature` or an ISO `Sgntr` wrapper with exactly one direct XMLDSig
  `Signature` child. Any additional `Signature`/`Sgntr` element outside the
  verified carrier fails closed. Required XMLDSig base64 fields
  such as `SignatureValue`, per-Reference `DigestValue`, and XAdES
  `CertDigest` values reject duplicates and must be attribute-free text leaves
  without nested markup or comments; `PublicKey` must be singular, and
  `PublicKey`/`X509Certificate` credential leaves follow the same no-markup
  rule. Public-key material must not be mixed with `X509Certificate` material
  in the same `KeyInfo`. Key material must be scoped to exactly one `KeyInfo`
  using either `KeyValue/ECKeyValue` with the P-256 `NamedCurve` URI whose
  `PublicKey` bytes parse as an uncompressed P-256 SEC1 point, or one bounded
  duplicate-free `X509Data` certificate-chain wrapper; those wrappers accept
  only implemented direct children, and unsupported children, unsupported
  ordinary attributes, non-whitespace wrapper text, duplicates, or out-of-scope
  `PublicKey`/`X509Certificate` elements fail closed. The canonical subset
  covers empty-element expansion, attribute quote normalization, namespace
  declarations, unprefixed attributes, declared prefixed attributes, and implicit
  `xml:` attributes while accepting and omitting the fixed legal `xmlns:xml`
  declaration. It
  also decodes predefined and numeric XML character references before
  re-emitting canonical text/attribute bytes. It applies root namespace
  declarations inherited from an enclosing XMLDSig `Signature` element according
  to the declared C14N mode: inclusive C14N carries all inherited root namespace
  declarations, while exclusive C14N carries only visibly used inherited root
  namespace declarations. No-comments C14N now omits
  valid XML comments from `SignedInfo` and referenced payload bytes while
  rejecting malformed comments. The verifier still rejects processing
  instructions, CDATA/CDEnd tokens, uppercase `#X` numeric character
  references, DTD/general/custom entity expansion, carriage returns, duplicate
  attributes, unbound prefixed attributes, explicit reserved namespace
  rebindings, malformed structural QNames such as double-colon local-name
  matches, inherited namespace context beyond root declarations, raw attribute
  whitespace rewrites, and malformed tag structure.
- Completed 2026-06-02: broadened XMLDSig ECDSA `SignatureValue`
  interoperability. Torii now accepts the fixed-width P-256 `r || s` signature
  encoding used by XMLDSig profiles while retaining DER fixture compatibility,
  requires canonical low-S for both encodings to remove ECDSA malleability, and
  the require-verified suite covers accepted low-S plus rejected high-S
  signatures.
- Completed 2026-06-02: hardened XMLDSig namespace binding for the supported
  signed ISO subset. Prefixed XMLDSig structural elements must now resolve to
  the XMLDSig namespace in their inherited scope across `Signature`,
  `SignedInfo`, `Reference`/`Transforms`/`Transform`/`DigestMethod`/
  `DigestValue`, and public-key or X.509 `KeyInfo` material, with regressions
  covering a correctly signed payload that binds `ds` to a non-XMLDSig URI.
  Unprefixed XMLDSig structural elements remain accepted for legacy fixtures
  only when they do not carry an explicit conflicting default namespace.
- Completed 2026-06-02: tightened supported XML element span matching so a
  selected opening tag must close with the exact same qualified name. This keeps
  local-name discovery for prefixed XMLDSig fixtures while rejecting malformed
  mismatched-prefix close tags before structure or cryptographic verification
  continues.
- Completed 2026-06-02: tightened XMLDSig attribute value extraction to exact
  XML attribute names. Namespace-qualified spoof attributes such as
  `ds:Algorithm` or `ds:URI` no longer have a local-name fallback in the
  accessor and remain rejected before method, transform, digest, or Reference
  policy is evaluated.
- Completed 2026-06-02: hardened XAdES namespace binding for the supported
  signed-property subset. Prefixed XAdES structural elements now must resolve to
  the ETSI XAdES v1.3.2 namespace (`http://uri.etsi.org/01903/v1.3.2#`) across
  `QualifyingProperties`, `SignedProperties`, `SignedSignatureProperties`,
  `SigningTime`, `SigningCertificateV2`, `Cert`, and `CertDigest`; referenced
  `SignedProperties` targets carry inherited namespace scope into verification,
  and wrong-namespace XAdES payloads fail closed even when re-signed. Unprefixed
  XAdES structural elements now also reject explicit conflicting default
  namespaces.
- Completed 2026-06-02: added profile-level XMLDSig certificate revocation
  pins. Operators can configure `revoked_certificate_sha256` alongside the
  trust pins; Torii validates the SHA-256 deny list at startup and rejects an
  otherwise trusted XMLDSig chain when any verified leaf/issuer DER digest is
  explicitly revoked.
- Completed 2026-06-02: tightened ISO XMLDSig X.509 production admission so
  Torii config and shared profile JSON SHA-256 trust/revocation pins must
  already be canonical lowercase hex, and `x509_trust_anchor_sha256_pins`
  require a linked issuer certificate beyond the leaf,
  and CRL/OCSP freshness plus delegated OCSP responder certificate validity are
  evaluated at verified XAdES `SigningTime` or BAH `CreDt` rather than local
  wall clock.
- Completed 2026-06-02: documented the XMLDSig trust-anchor rotation pattern
  for operators: overlap current and next certificate pins during upstream
  cutover, remove the retired pin after cutover, and use
  `revoked_certificate_sha256` only for compromised leaf/anchor digests that
  must override otherwise valid trust pins.
- Completed 2026-06-02: tightened the ISO OCSP DER parser used by
  `require-verified` XMLDSig/XAdES revocation checks. Torii now rejects
  non-shortest long-form DER lengths and non-minimal positive integer encodings
  before OCSP status, responder, or signature validation.
- Completed 2026-06-02: tightened the supported ISO OCSP subset so
  `ResponseData` and `SingleResponse` extensions fail closed instead of being
  ignored by the local parser. Full OCSP extension-policy processing remains
  outside the first-release subset.
- Completed 2026-06-02: extended ISO bridge idempotency to business message
  identifiers. Torii now indexes trimmed `BizMsgIdr`/BAH business-message IDs
  alongside payload hashes and normalized UETRs, rejects replay by business
  message id across distinct durable message records, and preserves the existing
  conflict guard when a rejected message is retried with another record's
  business message id.
- Completed 2026-06-02: tightened reference snapshot checksum coverage for
  profile validation. Torii now has focused coverage proving inbound admission
  metadata records the exact `ReferenceDataSnapshots::snapshot_id()` checksum
  after a BIC/LEI snapshot is loaded, and that the loaded-snapshot checksum
  differs from the all-missing default snapshot.
- Completed 2026-06-02: broadened Torii ISO profile/lifecycle transition
  coverage. Profile admission now returns `UnknownMessageType` when the selected
  rail profile has no inbound message profile for the submitted endpoint family,
  rejects BAH `MsgDefIdr` values outside the selected profile's version set, and
  covers known-original `pacs.004` return plus `camt.056` cancellation paths down
  to durable original-message and lifecycle-message status fields.
- Completed 2026-06-23: tightened Torii live-profile BAH admission so profiles
  that require an application header reject missing `BizMsgIdr`, `MsgDefIdr`,
  or `CreDt` before profile-version fallback can classify the payload as an
  unknown message type. Live Swift, Fedwire, SEPA, and CSD XML fixture
  regressions now also cover missing required `BizSvc`, exact/key-path and
  real-XML unstructured `PstlAdr/AdrLine`, and oversized `SplmtryData`.
  Message-profile configuration now rejects empty or blank-padded accepted
  version allowlists plus case-drifted duplicate version entries.
  Required-BizSvc profile configuration now also fails closed when the
  `business_services` allowlist is empty or contains blank-padded or
  case-drifted duplicate entries, and key-value plus live XML runtime admission
  rejects empty `BizSvc` values before matching allowlists. The offline XSD
  profile-catalog verifier also rejects case-drifted duplicate
  `business_services` entries and numeric scalars above `u64::MAX` before
  release evidence is emitted. Amount minor-unit overrides now reject duplicate
  normalized currencies and values above the ISO 4217 maximum precision used by
  the live rail catalog, and the offline XSD profile-catalog verifier mirrors
  that `4`-unit cap before release evidence is emitted. Override profile IDs,
  required reference dataset lists, and message-profile family/direction entries
  are now duplicate-free at configuration load. Default/override profile IDs,
  rails, embedded signature policies, message types, directions,
  structured-address modes, required reference dataset names, and minor-unit
  currency literals must also be non-empty trimmed values. X.509
  certificate-policy OID lists plus CRL/OCSP DER base64 material now reject
  padded or duplicate entries instead of silently trimming or de-duplicating, so
  padded trust/revocation profile config fails before runtime admission.
  Stale XMLDSig trust-pin alias fields now fail as malformed input, and the
  current public-key, X.509 trust-anchor, and revoked-certificate pin roles must
  not overlap in embedded or runtime profile configuration.
  Final production-readiness XSD replay now also recomputes
  profile-version `schema_backed` flags from the schema-backed XML fixture
  message-definition IDs in the same digest-bound summary, so forged archived
  summaries cannot inflate or suppress profile schema coverage with catalog
  boolean/count edits alone.
  The embedded core catalog loader and offline XSD profile-catalog verifier now
  also reject generic DER SEQUENCE placeholders in CRL/OCSP material by
  requiring CRL-like or successful Basic OCSP response structure before catalog
  construction or release evidence is emitted; embedded-core regressions cover
  malformed DER encodings, CRL child-shape drift, and unsuccessful or
  wrong-response-type OCSP material. Torii runtime override regressions now
  also cover malformed but base64-valid configured CRL and OCSP response DER
  plus over-limit revocation-material lists before live admission. Offline
  profile-catalog verifier and embedded core catalog CRL/OCSP material lists
  now share the Torii runtime `8`-entry cap and reject over-limit lists before
  base64 decode, DER decode, or shape parsing. Trust-bundle verifier
  regressions now also prove every DER material list rejects more than eight
  entries before per-entry object validation or DER parsing. Evidence replay
  and final readiness replay regressions now cover the same cap for archived
  trust-summary DER lists, emitted CRL/OCSP override base64 lists, and compact
  trust-profile DER proof lists before per-entry object validation, base64
  decode, or DER parsing.
  The direct strict XSD profile-catalog gate now reports the count of
  non-schema-backed advertised message versions without echoing the profile or
  message-definition values; the checked-in manifest/catalog pair still has
  `24` missing profile schema proofs pending redistributable official XSDs, all
  now backed by reviewed missing-schema, blocked-source, or official ISO
  pending-source evidence.
- Completed 2026-06-04: added a checked-in `sese.024` securities status-advice
  XML fixture and pinned it at both the IVM parser layer and the Torii
  lifecycle layer. The Torii regressions now cover known-original pending
  updates, unknown-original recording without synthetic record creation,
  wrong-family originals, and conflicting settlement references.
- Completed 2026-06-04: added checked-in `pacs.004` payment-return and
  `camt.056` cancellation-request XML fixtures. IVM parser tests pin the
  canonical return/cancellation fields, and Torii tests prove those fixtures
  drive known-original rejected/pending transitions without synthetic original
  creation.
- Completed 2026-06-04: added a checked-in `pacs.002` payment-status XML
  fixture. IVM parser tests pin the canonical status/original/additional-info
  fields, and Torii tests prove the fixture settles a known original payment.
- Completed 2026-06-04: added adversarial `pacs.002` lifecycle coverage proving
  `TxInfAndSts/StsId` cannot shadow `GrpHdr/MsgId` for durable lifecycle ids or
  audit business-message ids.
- Completed 2026-06-04: added Apache-2.0 mirrored Standards Editor XSD
  fixtures for `pacs.002.001.10`, `pacs.004.001.09`,
  `pacs.004.001.10`, `camt.056.001.08`, and `camt.056.001.09`. The
  MDR/XSD live-profile matrix now validates BAH status, return, and
  cancellation reports with rail-specific version and business-service controls
  wherever the default profiles allow those exact versions.
- Completed 2026-06-10: extended the Torii official-MDR XSD live-profile
  matrix to assert `pacs.004.001.09` for SWIFT CBPR+, Fedwire Funds, SEPA SCT
  Inst, and securities CSD, plus `camt.056.001.09` for SWIFT CBPR+, SEPA SCT
  Inst, and securities CSD, matching the embedded default profile catalog.
- Completed 2026-06-04: extended the XSD fixture preflight and production
  readiness rollup with default profile-catalog coverage. The XSD verifier can
  parse `DEFAULT_PROFILES_JSON`, record concrete profile-advertised message
  versions, and fail `--require-profile-schema-backed-versions` when a version
  lacks a schema-backed XML fixture; readiness rechecks those counts and
  missing-version entries, including canonical profile ids, ISO family message
  types, allowed directions, and message-definition family binding, before
  accepting an XSD summary. The summaries now also bind the manifest SHA-256,
  per-schema source repository/commit/path,
  SPDX license, source SHA-256, profile source-file SHA-256, and embedded
  catalog JSON SHA-256 values for release evidence provenance, cap source
  repository URLs and source paths at 2048 characters, require exactly one active Rust
  `DEFAULT_PROFILES_JSON` raw-string declaration while ignoring
  spoofed declarations in comments or unrelated strings, and fail closed
  on duplicated, malformed, or unknown-key profile/message/direction/version
	  catalog entries. Manifest schema paths, fixture paths, and fixture
	  schema references now fail closed on non-ASCII characters, values longer
	  than 2048 characters, URI/drive prefixes, malformed or smuggled percent
	  escapes, backslashes, leading-dash path segments, empty or dot segments,
	  forbidden parent-segment forms, and
  DTD/entity declarations before an XSD/profile summary is emitted. Schema
  `Document` declarations must also be unambiguous: exactly one top-level
  `Document` element whose type is exactly the local `Document` type, one
  referenced `Document` complex type, one direct `Document` sequence, and one
  direct payload element with exact `name`/`type` attributes, no `ref`
  indirection, a local unprefixed type, and exactly one matching local payload
  complex type containing exactly one direct `xs:sequence`; XSD composition
  (`xs:import`, `xs:include`, `xs:redefine`, `xs:override`) and
  foreign-namespace direct children under schema, `Document`, or payload
  structures fail before evidence can depend on ignored or unpinned schema
  declarations. Schema roots must declare exactly `elementFormDefault` and
  `targetNamespace`, rejecting root-level `attributeFormDefault`,
  `xsi:schemaLocation`, or other schema-root hints before evidence is emitted.
  Checked XML fixture `Document` and immediate payload roots must be
  attribute-free, so fixture-local schema-location hints or root metadata cannot
  enter digest-bound summaries. Manifest, schema, and fixture files are parsed
  and hashed from the same checked byte buffer, with manifest JSON and profile
  catalog source capped at 4 MiB and schema/fixture XML capped at 8 MiB before
	  parsing, while optional `xmllint` stdout/stderr is drained through a 64 KiB
	  cap and validator runtime is bounded by positive finite
	  `--xmllint-timeout-secs` capped at 300 seconds; successful validator output must be empty or the
	  normal `<fixture> validates` line, so warning-bearing success output fails
	  closed before release evidence is emitted. Validator output that mentions
	  local schema/fixture paths is redacted before diagnostics are reported.
	  Secret-looking and
	  control-bearing validator diagnostics are redacted before error reporting.
	  This prevents restricted-term, XML-parse, and emitted-digest evidence from
	  drifting across separate reads.
  Catalog `versions` lists now only skip
  schema-backed checks for the exact message-family alias; unrelated or
  duplicated family aliases fail before an XSD/profile summary is emitted.
  Optional runtime catalog
  fields are also checked against the runtime parser contract: rails,
  embedded-signature policies, and structured-address modes are required;
  optional required reference datasets, trust/revocation pins and OIDs,
  trusted/revoked pin overlap, bounded canonical CRL/OCSP base64 DER-sequence
  material, revocation-flag material requirements, `require-verified`
  trust-pin presence, booleans, supplementary-data caps, business-service
  dependencies, and amount minor-unit currency rows are shape-checked when
  present.
	  Candidate schema imports fail closed when source provenance is missing,
	  malformed, digest-drifted, still uses placeholder GitHub repository
	  coordinates, separator-obfuscated or collapsed placeholder repository
	  components, non-lowercase GitHub owner/repository spelling, or invalid
	  GitHub owner punctuation such as underscores or edge hyphens, or
	  repository names with edge punctuation, all-zero
	  Git commit or SHA-256 provenance placeholders,
	  carries identifier-style secret-looking path material, or when
	  an XSD contains known restricted Standards Editor redistribution terms, and
	  checked-in and blocked candidate schema entries reject omitted `source`
	  separately from explicit null source objects in both direct preflight and
	  archived readiness replay,
	  ISO CLI secret preflight rejects percent-decoded identifier-only or key/value
	  whitespace/dot/underscore/hyphen separated secret key labels before any
	  summary path is accepted,
	  live rail/notary response previews and archived receipt previews reject the
	  same separator-obfuscated secret labels plus regex-only bearer whitespace
	  forms, while successful live previews reject invalid UTF-8 or non-ASCII
	  text before receipt write and failed live previews redact that text before
	  receipt evidence is archived, with accepted newline/tab text folded to one
	  line before archival; archived receipt previews/errors reject multiline or
	  non-ASCII text before replay,
	  the manifest must explicitly record `blocked_schema_sources` as an array even
  when no reviewed restricted source candidates are present, and blocked-source
  records must match a current missing-schema fixture gap or, with a profile
  catalog, a current profile-version gap. The aggregate
  readiness gate replays the same repository-coordinate checks and
  rejects secret-looking repository coordinates before output for archived XSD
  summaries, preventing public mirrors with embedded
  no-redistribution notices or placeholder provenance from being treated as
  production fixture evidence.
- Broaden XMLDSig/XAdES fixture coverage beyond internal P-256 key and
  generated certificate-chain material, including complete canonical XML
  coverage for broader signed ISO envelopes, official
  rail/profile-specific trust-anchor packages, official CRL/OCSP or rail
  revocation-feed fixtures.
- Add official MDR/XSD fixture coverage per profile until both strict
  schema-backed fixture checks and profile-advertised version checks pass; do
  not import mirrored Standards Editor XSDs whose embedded terms prohibit
  redistribution.
- Completed 2026-06-01: tightened the deterministic XMLDSig/XAdES subset so
  `require-verified` profiles only accept the C14N 1.0 + single enveloped
  transform shape that the verifier actually checks. C14N 1.1, exclusive C14N,
  extra transforms, and duplicate `Sgntr` blocks now fail closed.
- Completed 2026-06-02: bound XAdES `QualifyingProperties` objects to their
  enclosing XMLDSig signature id. When a `QualifyingProperties` element is
  present, the supported subset now requires exactly one such element inside a
  single `Object`, requires a non-empty `Target="#..."`, and requires that
  target to match the `Signature`/`Sgntr` `Id`; copied, duplicate,
  mis-targeted, targetless, idless, or out-of-object XAdES properties fail
  closed before signature admission.
- Completed 2026-06-02: required XAdES `SignedProperties` to be
  cryptographically referenced from `SignedInfo`. XAdES-bearing signatures now
  need exactly one payload reference plus exactly one `Reference` whose URI
  targets the `SignedProperties` `Id`, whose `Type` is the XAdES
  SignedProperties reference type, and whose SHA-256 digest matches the
  `SignedProperties` XML in the target-bound `QualifyingProperties` object.
  Missing, wrong-URI, wrong-Type, digest-tampered, content-tampered, or
  missing-element XAdES property references fail closed.
- Completed 2026-06-02: bound XAdES `SigningCertificateV2` to X.509 signer
  material. X.509 `KeyInfo` signatures with XAdES signed properties now require
  a single `SigningCertificateV2` / `Cert` / `CertDigest` entry using the
  supported SHA-256 digest method, and that digest must match the exact signer
  leaf DER certificate admitted from `KeyInfo`. Missing, duplicate,
  wrong-algorithm, wrong-digest, or raw-public-key-with-certificate-property
  cases fail closed.
- Completed 2026-06-02: made known `SigningCertificateV2` issuer/serial
  metadata fail closed until the verifier binds it semantically. Digest-valid
  `IssuerSerial`, `IssuerSerialV2`, prefixed `xades:IssuerSerialV2`, and
  `X509IssuerSerial` material inside the XAdES certificate entry now fails
  before X.509 signer admission.
- Completed 2026-06-02: required the supported XAdES `SignedProperties`
  structure to carry exactly one `SignedSignatureProperties` block with one
  non-empty `SigningTime`. X.509 `SigningCertificateV2` signer evidence is now
  accepted only from inside that `SignedSignatureProperties` block; missing or
  duplicate signature-properties blocks, missing or duplicate signing times, and
  `SigningCertificateV2` material outside `SignedSignatureProperties` fail
  closed.
- Completed 2026-06-02: tightened XAdES `SigningTime` admission to the
  supported canonical UTC `YYYY-MM-DDTHH:MM:SSZ` subset with real calendar and
  clock bounds. Whitespace-spliced values, offsets, fractional seconds,
  non-ASCII digits, malformed widths, year zero, invalid leap days, invalid
  month lengths, and out-of-range hours/minutes/seconds now fail closed even
  when the `SignedProperties` digest and signature are otherwise internally
  consistent.
- Completed 2026-06-02: made the supported XAdES property subset fail closed
  for property classes the verifier does not semantically process. The bridge
  now rejects `SignedDataObjectProperties` and data-object transform metadata,
  signed signature policy/place/role properties, and unsigned timestamp,
  counter-signature, revocation, and archive property families even when the
  `SignedProperties` digest and XMLDSig signature are internally consistent.
- Completed 2026-06-02: added namespace-prefixed XMLDSig/XAdES fixture coverage.
  The `require-verified` verifier now has a positive `ds:`/`xades:` signed
  P-256 fixture whose prefixed `SignedInfo` is signed directly, plus a prefixed
  unsupported-property negative case to prove local-name matching does not let
  namespaced XAdES policy/place/role properties bypass the fail-closed subset.
- Completed 2026-06-01: added profile-level
  `signature_public_key_sha256_pins` for `require-verified` XMLDSig/XAdES
  profiles. The verifier now fails closed without configured pins, accepts raw
  XMLDSig public keys and X.509 certificate subject public keys only when their
  SHA-256 pin matches the profile, rejects malformed/all-zero pins, and rejects
  ambiguous or duplicate key material.
- Completed 2026-06-01: added profile-level
  `x509_trust_anchor_sha256_pins` for X.509 XMLDSig key-info chains in the
  supported P-256/SHA-256 subset. The verifier now validates leaf-to-anchor
  issuer links, ECDSA certificate signatures, certificate validity windows,
  CA/keyCertSign trust anchors, duplicate certificates, non-CA anchors, missing
  anchors, issuer mismatches, and trust-anchor DER SHA-256 pins before using an
  X.509 leaf key that is not directly pinned.
- Completed 2026-06-01: added profile-level
  `x509_required_certificate_policy_oids` for rail-specific X.509 XMLDSig
  signer policy gates. X.509 leaf certificates must now carry every configured
  certificate-policy OID before either direct leaf-key pins or validated
  trust-anchor chains can authorize the XMLDSig key; malformed configured OIDs,
  missing policy extensions, and wrong policy OIDs fail closed.
- Completed 2026-06-01: added profile-level CRL revocation enforcement for
  X.509 XMLDSig key-info chains. Profiles can require a fresh verified CRL via
  `x509_require_crl_revocation_check` and can supply pinned rail CRL material
  through `x509_crl_der_base64`; embedded `X509CRL` material is accepted only
  on the X.509 path. The verifier checks CRL DER parsing, issuer matching,
  issuer `cRLSign`, ECDSA/SHA-256 CRL signatures, freshness windows, duplicate
  CRL rejection, missing required CRLs, wrong issuers, expired CRLs, and revoked
  signer serials before using the X.509 leaf key.
- Completed 2026-06-01: added fail-closed X.509 name-constraint processing for
  trust-anchor-authorized XMLDSig key-info chains. The verifier now enforces
  permitted and excluded subtrees from constrained issuer certificates across
  subordinate signer certificates before using the leaf key, with local support
  for DNS, RFC822, URI-host, IP subnet, and directory-name forms and closed
  rejection for unsupported or invalid general names.
- Completed 2026-06-01: added profile-level OCSP revocation enforcement for
  X.509 XMLDSig key-info chains. Profiles can require fresh OCSP coverage via
  `x509_require_ocsp_revocation_check` and can supply pinned rail response
  material through `x509_ocsp_response_der_base64`; embedded `OCSPResponse` and
  `EncapsulatedOCSPValue` material is accepted only on the X.509 path. The
  verifier parses BasicOCSPResponse DER, binds SHA-256 CertID values to the
  signer and issuer, verifies issuer-signed and delegated ECDSA/SHA-256
  responders, enforces OCSPSigning EKU/digitalSignature key usage for
  delegated responders, checks producedAt/thisUpdate/nextUpdate freshness, and
  rejects missing, revoked, unknown, duplicate, stale, malformed, or unauthored
  responses before using the X.509 leaf key.
- Completed 2026-06-01: required delegated OCSP responder certificates in
  X.509 XMLDSig revocation paths to mark KeyUsage critical when authorizing
  `digitalSignature`. Otherwise-valid delegated responses whose embedded
  responder certificate carries non-critical digitalSignature KeyUsage now fail
  closed before OCSP coverage can satisfy the rail profile.
- Completed 2026-06-01: added X.509 path-length constraint enforcement for
  trust-anchor-authorized XMLDSig key-info chains. The verifier now evaluates
  BasicConstraints `pathLenConstraint` values across intermediate CAs and
  rejects a chain when a constrained root or intermediate authorizes more
  subordinate CA certificates than its policy allows.
- Completed 2026-06-01: required X.509 XMLDSig signer certificates to be
  end-entity certificates. The verifier now rejects signer leaves whose
  BasicConstraints extension is missing or CA:true before either direct public
  key pins or trust-anchor chains can authorize the key, with adversarial
  coverage for CA-capable signer certificates accepted by neither path.
- Completed 2026-06-01: added fail-closed unknown-critical X.509 extension
  handling for XMLDSig signer material. Critical extensions that the parser
  cannot decode or recognize now reject direct-pinned leaves, trust-anchor
  chains, and delegated OCSP responder certificates before any public key is
  accepted.
- Completed 2026-06-01: made X.509 signer certificate validity windows
  mandatory before direct public-key pins can authorize a key. Expired signer
  leaves now fail before direct-pin acceptance as well as on trust-anchor
  chains, with coverage for both paths.
- Completed 2026-06-01: added X.509 signer Extended Key Usage purpose binding
  for XMLDSig signer material. Signer leaves without EKU remain acceptable, but
  EKU-constrained leaves must allow `codeSigning`, `anyExtendedKeyUsage`, or
  the document-signing OID before either direct public-key pins or trust-anchor
  chains can authorize the XMLDSig key; incompatible server-auth-only signer
  leaves fail closed on both paths.
- Completed 2026-06-01: required X.509 XMLDSig signer certificates to mark
  KeyUsage critical when authorizing `digitalSignature`. Direct leaf public-key
  pins and trust-anchor chains now both reject signer leaves whose KeyUsage
  extension carries `digitalSignature` as a non-critical advisory extension.
- Completed 2026-06-01: added X.509 Authority Key Identifier / Subject Key
  Identifier binding for trust-anchor XMLDSig chains. When a subordinate
  certificate presents an AKI key identifier and the issuer presents an SKI, the
  identifiers must match before the trust-anchor path can authorize the leaf
  key; issuer-name/signature-valid chains with mismatched key identifiers fail
  closed.
- Completed 2026-06-02: added conservative required certificate-policy path
  continuity for X.509 trust-anchor XMLDSig chains. When a profile requires
  certificate policy OIDs, every intermediate CA below the pinned terminal
  anchor must carry all required OIDs or `anyPolicy`; generated chain tests
  cover matching, `anyPolicy`, missing, and unrelated intermediate policies.
- Completed 2026-06-02: fail closed on policy mappings, policy constraints,
  and inhibit-any-policy extensions in XMLDSig X.509 material until full RFC
  5280 policy-tree processing is implemented.
- Remaining ISO signature work is optional full RFC 5280 policy-tree processing
  if production profiles need to accept policy mappings, policy constraints, or
  inhibit-any-policy instead of rejecting those extensions in the supported
  subset.
- Completed 2026-06-01: tightened ISO idempotency so replayed Business
  Application Header `BizMsgIdr` values are rejected across different durable
  message identifiers, including after durable-store reload. Live-profile
  validation now also has regression coverage proving recorded metadata carries
  the exact reference-data snapshot checksum and that checksum changes when the
  loaded reference snapshot provenance changes.
- Completed 2026-06-02: tightened live-profile UETR admission and replay
  coverage. Present UETR values now need the canonical UUID hyphen layout and
  ASCII hex digits before profile metadata is produced; Swift CBPR+ coverage
  rejects missing and malformed UETRs, exercises padded/malformed direct
  validator inputs, and proves validated live-profile submissions still reject
  duplicate Business Application Header `BizMsgIdr` values and case-drifted
  duplicate UETRs across different durable message identifiers.
- Completed 2026-06-02: tightened inbound lifecycle reference handling for
  payment returns, cancellation requests, and securities settlement
  confirmations. `pacs.004`, `camt.056`, and `sese.025` payloads that carry
  conflicting original-message references now fail lifecycle id derivation and
  inbound application before any candidate original record is mutated.
- Completed 2026-06-02: tightened securities lifecycle durable identifiers and
  fixture coverage. BAH-wrapped `sese.023`, `sese.024`, and `sese.025`
  messages are now durably keyed by their transaction `TxId` with a message
  type prefix, while `BizMsgIdr` remains profile/idempotency metadata; this lets
  confirmations find the referenced `sese.023:<TxId>` record. Torii tests now
  wrap the checked-in `sese.023`/`sese.025` XML fixtures in AppHdrs, validate
  them through a securities CSD live profile with required reference datasets,
  apply lifecycle state, and reject unsupported version and document-root drift.
- Completed 2026-06-04: moved the default collateral substitution confirmation
  surface to the ISO `colr.012` family. Torii now exposes
  `/v1/iso20022/colr012`, the default generic and securities profiles advertise
  `colr.012.001.05`, the checked-in `colr.012` fixture validates through the
  generic profile and is durably keyed by `colr.012:<TxId>`, and the XSD
  manifest tracks the remaining official `colr.012.001.05` schema gap. The
  older `colr.007` parser/route is retired and remains only as negative fixture
  coverage; operator evidence must not rely on it.
- Completed 2026-06-01: broadened live-profile mismatch and lifecycle
  transition coverage. Swift CBPR+ validation now has negative tests for
  unsupported message-definition versions and business services, while
  `pacs.002`, `pacs.004`, `camt.056`, and `sese.025` lifecycle updates fail
  closed when the referenced durable record belongs to the wrong ISO family.
- Completed 2026-06-01: added XSD document-root admission for real ISO XML
  parsing. Each supported XML family now has a canonical `Document` child-root
  gate, and real XML with a missing or mismatched family root fails before
  field-level validation can materialize a message.
- Completed 2026-06-01: added live rail XSD/profile fixture coverage for the
  embedded Swift CBPR+, Fedwire Funds, SEPA SCT Inst, and securities CSD
  profiles. The fixture matrix now validates accepted `pacs.008`/`pacs.009`
  samples against required reference data, business services, message
  definition versions, reference snapshot metadata, and minor-unit policy, with
  adversarial wrong-service, wrong-version, and fractional-amount drift cases.
- Completed 2026-06-01: added offline Standards Editor generated MDR/XSD
  fixtures for `pacs.008.001.08` and `pacs.009.001.08` and bound them to the
  live rail profile matrix. Swift CBPR+, Fedwire Funds, SEPA SCT Inst, and the
  securities CSD profile now each validate at least one live profile payload
  whose namespace and `Document` child root are asserted against the checked-in
  XSD, with a root-drift negative case proving mismatched MDR roots fail before
  profile admission.
- Completed 2026-06-01; tightened for first release on 2026-07-04: ISO bridge
  profiles accept only the explicit `signature_public_key_sha256_pins` and
  `x509_trust_anchor_sha256_pins` verifier inputs. Stale
  `trusted_public_key_sha256` and `trusted_certificate_sha256` aliases are
  malformed input in runtime config, fixture preflight, trust-bundle summaries,
  and operator evidence.
- Completed 2026-06-04: bound durable ISO message JSON records to a
  deterministic `record_sha256` digest. Persisted records now carry a versioned
  digest over the record body, and reload rejects missing, malformed, or
  mismatched digests without rebuilding message status or replay indexes.
- Completed 2026-06-04: added a deterministic durable ISO audit index at
  `store_dir/audit/messages.index.json`. The index is sorted by message id,
  carries `index_sha256`, links each entry to the corresponding message file and
  `record_sha256`, is atomically written under a 32 MiB aggregate cap, and uses
  an exact versioned root/row schema. Reload now stops on every malformed,
  legacy, tampered, filename-mismatched, or conflicting record instead of
  silently excluding it and overwriting the evidence. A missing or
  schema-valid stale local index remains recoverable because it is derived and
  is regenerated only after the complete V2 record/tombstone store validates.
- Completed 2026-06-04: exposed the durable ISO audit manifest through Torii at
  `GET /v1/iso20022/audit/messages`, backed by the same deterministic index
  builder used for `store_dir/audit/messages.index.json`, and added endpoint
  coverage for successful export plus disabled-bridge rejection.
- Completed 2026-06-04: added config-backed durable ISO store retention and
  compaction. Operators can set `store_retention_secs` or `store_max_records`;
  count retention now defaults to 256 and fails closed above the first-release
  hard maximum of 1024. Reload uses stable bounded reads and deterministic
  streaming newest-record retention before populating replay indexes.
  Compaction is independent from dedupe TTL, removes expired or oldest overflow
  records from memory and disk, clears replay indexes, and regenerates the audit
  manifest from survivors without a full-store prune snapshot.
- Completed 2026-06-04: added the config-backed ISO external audit export spool.
  Operators can set `audit_export_dir`; each audit-index regeneration mirrors
  `messages.index.json` into that external directory and writes digest-addressed
  `.notary.json` preimages that bind `index_sha256`, source `store_dir`, record
  count, the embedded manifest, and `anchor_sha256`.
- Completed 2026-06-04: added `scripts/iso_audit_notary_adapter.py` for
  operator-side archival/notary publication. The adapter consumes
  `audit_export_dir`, verifies canonical nonzero anchor and embedded index
  self-digests, top-level `index_sha256`, digest-addressed filename, local
	  `messages.index.json` equality, duplicate-free audit records, and
	  record-count consistency before any network delivery. Non-empty anchors
	  must expose `store_dir/messages` record
  sources by default, and the adapter verifies every indexed persisted record
  body against its `record_sha256`, audit-index row metadata, and monotonic
  current status history before publication while anchor `anchor_sha256`,
  audit-index `index_sha256`, audit-index `record_sha256` and payload-hash
  fields, plus persisted record metadata payload hashes, must be canonical
  nonzero SHA-256 values before publication, and anchor `store_dir` values
  reject whitespace, leading dashes, leading-dash path segments, backslashes,
  semicolon path parameters, empty path segments, and dot/parent path segments even when the local
  diagnostic `--allow-missing-record-sources` override is supplied. It rejects
  plaintext HTTP unless explicitly enabled for local
  tests, rejects endpoint URLs with credentials, params, query strings,
	  fragments, surrounding or embedded whitespace, or control characters, rejects
	  empty, zero, leading-zero, malformed, out-of-range, or explicit-default ports, non-canonical hosts,
	  reserved placeholder hosts, checked-in template hosts under
	  `operator-canary.bank`, invalid DNS labels, percent-escaped hosts, numeric-host/legacy-IPv4
	  spoofing, and IPv6 transition addresses embedding non-global IPv4 addresses,
	  rejects traversal, backslash, encoded-separator, encoded-semicolon,
	  encoded URL delimiters, encoded-percent,
	  percent-encoded control/space bytes, malformed percent escapes,
	  repeated URL path separators, or embedded-semicolon URL paths, rejects
	  duplicate publication endpoints before network delivery, treats remote
	  redirects as failed receipts without following them, and
	  requires bearer-token files to be regular non-symlink inputs capped at
	  8 KiB before decoding to exact UTF-8 values with no surrounding
	  whitespace, embedded whitespace, or control characters, and
	  requires the export directory, `latest.notary.json`, the digest-addressed
	  anchor peer, `messages.index.json`, and clean `store_dir/messages` record
	  sources to be non-symlink regular directories/files, caps anchor/index
		  JSON inputs at 64 MiB and persisted record-source JSON inputs at 1 MiB,
			  requires positive finite `--timeout-secs` and
			  positive integer `--response-limit-bytes`, and writes bounded
			  per-endpoint receipts without persisting token material, rejecting
			  secret-looking or control-bearing successful remote response bodies
				  before receipt persistence, rejecting boolean or string status
				  aliases before coercion, normalizing non-standard, malformed, or oversized
					  remote HTTP statuses into transport-failed receipts with `status_code=null`, and
				  redacting failed remote response previews or transport errors before
				  persistence, with transport error strings capped at 4096 printable
					  ASCII characters and transport-open/response-read exceptions or
					  failures, normal/HTTP-error close failures, and malformed non-byte
					  remote response bodies recorded as bounded failed receipts. The notary adapter
				  rejects unused `--allow-insecure-http` unless at least one endpoint
				  actually needs the local HTTP/private-host diagnostic policy, and
				  rejects unused `--allow-missing-record-sources` unless at least one
				  validated anchor actually lacks local record sources. Receipt
		  output directories and receipt leaves are preflighted before publication,
		  reject control characters, whitespace, leading-dash segments,
		  backslashes, semicolon parameters, empty segments, dot/parent
		  traversal, symlinked existing ancestors, and hard-linked, symlink, or
		  non-regular targets, and are written via exclusive same-directory
		  owner-private temporary files with bounded digest-derived names that are
		  descriptor-rechecked, fsynced, and atomically replaced where available.
- Completed 2026-06-04: added `scripts/iso_rail_gateway_adapter.py` for
  operator-side live rail file-drop ingress. Each XML payload requires a JSON
  sidecar with `message_type`, explicit `profile` by default, and
  `payload_sha256`; the adapter verifies the sidecar before posting to the
	  matching Torii ISO endpoint, rejects plaintext HTTP unless explicitly enabled
	  for local tests, rejects Torii base URLs with credentials, params, query
	  strings, fragments, surrounding or embedded whitespace, or control
	  characters, overlong URLs or DNS hosts, localhost/local-private IP
	  literals, known local/private rebinding hostnames, or IPv6 transition
	  addresses embedding non-global IPv4 addresses, reserved placeholder hosts,
	  checked-in template hosts under `operator-canary.bank`, rejects malformed, out-of-range,
	  empty, zero, leading-zero, or explicit-default ports and non-canonical hosts, invalid DNS labels, percent-escaped hosts, and
	  numeric-host/legacy-IPv4 spoofing, rejects traversal, backslash, encoded-separator,
	  encoded-semicolon, encoded URL delimiters, encoded-percent, percent-encoded control/space bytes, malformed percent
	  escapes, or embedded-semicolon URL paths, keeps explicit `--message` paths
	  inside the declared inbox, rejects explicit `--message` path and discovered
		  XML leaf whitespace, leading-dash segment, backslash, semicolon,
		  empty-segment, or dot/parent segment smuggling before reads, rejects duplicate
		  payload digests or duplicate `rail_message_id` values within one gateway run before network delivery, rejects sidecar `profile` and `rail_message_id`
			  values that are explicitly `null` or carry surrounding whitespace,
			  embedded whitespace, or control characters, rejects non-canonical sidecar
				  profile IDs, rejects sidecar `rail_message_id` values that are longer
				  than 128 characters or are not canonical ASCII rail-message identifiers,
				  rejects unknown sidecar fields, bounds sidecar JSON before parsing,
					  rejects retired `colr.007`
			  drops with no local override path, rejects unused `--allow-insecure-http`
			  and `--allow-default-profile` flags unless
			  the validated Torii URL or sidecars actually require the corresponding
			  local diagnostic policy, requires bearer-token files to be regular
	  non-symlink inputs capped at 8 KiB before decoding to exact UTF-8 values
	  with no surrounding whitespace, embedded whitespace, or control
	  characters, rejects symlinked XML payload or sidecar files, rejects
		  symlinked inbox roots, requires positive finite `--timeout-secs`,
		  requires positive integer `--max-payload-bytes` and
		  `--response-limit-bytes`, treats remote redirects as failed receipts
		  without following them, preserves explicit
		  `--message` leaves for regular-file checks, and writes bounded
		  submission receipts without persisting token material, rejecting
			  secret-looking or control-bearing successful remote response bodies
			  before receipt persistence, and redacting failed remote response
			  previews or transport errors before persistence, with transport error
				  strings capped at 4096 printable ASCII characters and
				  transport-open/response-read exceptions or failures,
				  normal/HTTP-error close failures, and malformed non-byte remote
				  response bodies recorded as bounded failed receipts. Receipt output
		  directories and receipt leaves are preflighted before Torii submission,
		  reject control characters, whitespace, leading-dash segments,
		  backslashes, semicolon parameters, empty segments, dot/parent
		  traversal, symlinked existing ancestors, and hard-linked, symlink, or
		  non-regular targets, and are written via exclusive same-directory
		  owner-private temporary files with bounded digest-derived names that are
		  descriptor-rechecked, fsynced, and atomically replaced where available.
- Completed 2026-06-04: added `scripts/iso_operator_receipt_verify.py` as a
  read-only canary gate for rail/notary adapter receipts. It recomputes receipt
  digests, rejects all-zero receipt self-digest placeholders, requires successful
  2xx receipts by default, rejects plaintext HTTP evidence unless explicitly
  enabled for local tests, rejects leaked
  authorization/token material and receipt endpoint URLs with credentials,
  params, query strings, fragments, malformed hosts, surrounding or embedded
	  whitespace, empty/zero/leading-zero/malformed/default ports, non-canonical hosts, or control
	  characters, localhost/local-private IP literals, known local/private
	  rebinding hostnames, IPv6 transition addresses embedding non-global IPv4
	  addresses, reserved placeholder hosts such as `.example`, `example.com`,
	  `example.net`, `example.org`, or `example.invalid`, checked-in template
	  hosts under `operator-canary.bank`, invalid DNS labels, percent-escaped hosts, numeric-host
	  or legacy-IPv4 spoofing, plus traversal, backslash, encoded-separator,
	  encoded-semicolon, encoded URL delimiters, encoded-percent,
	  percent-encoded control/space bytes, malformed percent escapes, or
	  embedded/encoded-semicolon/encoded-delimiter/repeated-separator URL paths, can cross-check referenced XML or notary anchor
		  source files, closes the raw receipt schemas per receipt kind plus notary
		  anchor/audit-index source schemas, including an explicit `records[]`
		  array and duplicate-free nested audit records, binds
  audit record filenames to `sha256(message_id).json`, binds each indexed
  `record_sha256` to the persisted `store_dir/messages` body when source files
	  are required or locally available, rejects row/source metadata drift and
	  persisted-state-derived `pacs002_code` or status-history timestamp drift,
	  binds endpoint digests to recorded endpoint URLs, requires timezone-aware adapter timestamps that do not
	  require trimming, enforces HTTP 100-599 `status_code` bounds plus
	  `ok`/`status_code` consistency,
			  requires HTTP response body digests for HTTP responses,
			  `response_body_sha256=null` for `status_code=null` transport failures,
			  all-zero response-body, notary anchor/index, rail payload,
			  audit-index record, and persisted payload-hash placeholder rejection,
			  and failed-receipt error strings,
		  validates bounded response metadata, rejects the redacted response marker
		  on successful receipts, requires rail `xml_path` values to
		  point at `.xml` leaves, cross-checks rail sidecars against the
		  adapter's `xml_path + .json` convention and receipt metadata, requires notary
	  `anchor_path` values to keep the `latest.notary.json` or digest-addressed
	  `anchors/<index_sha256>.notary.json` shape even when source files are not
	  required, rejects raw notary `anchor_path` and `store_dir` values, raw rail
	  receipt `message_type`, `xml_path`, and
	  `sidecar_path` values that carry whitespace, control characters,
			  leading dashes, leading-dash path segments, backslashes, semicolon path
			  parameters, empty path segments, or dot/parent path segments, requires raw
				  `--allow-failed`, `--allow-insecure-http`, and
				  `--allow-default-profile` verifier
				  overrides to match failed receipts, HTTP/local endpoints, or
				  missing rail profiles before emitting the summary,
			  and records version-2 compact
			  `endpoint_requires_insecure_http` evidence per receipt so replay can
			  bind insecure-HTTP policy without carrying raw endpoint URLs, while
			  rejecting summaries that hide insecure/local endpoint evidence behind
			  `allow_insecure_http=false`,
		  rail receipts and archived rail receipt summaries to record nullable
		  `profile`/`rail_message_id` keys, plus receipt and source-sidecar rail
		  `profile`/`rail_message_id` values when they carry surrounding whitespace or
		  embedded whitespace or control characters, rejects source-sidecar explicit
		  null optional metadata instead of treating it as omission, rejects non-canonical receipt or
		  source-sidecar profile IDs, rejects overlong or non-canonical ASCII
		  `rail_message_id` values, caps receipt JSON at 4 MiB, notary anchor/index
  JSON at 64 MiB, persisted notary record-source JSON at 1 MiB, rail source XML
  at 4 MiB, and source-sidecar JSON at 16 KiB before parsing or hashing,
  replays digest-addressed notary-anchor and
  `messages.index.json` checks while rejecting symlinked or non-regular notary
  anchor/index peers and requiring complete audit-index record summary key sets,
  canonical Torii lifecycle states, state-compatible pacs.002 summary codes,
  including nullable Torii-emitted fields, plus complete persisted
  record/context/metadata/history key sets and state-compatible status-history
  pacs.002 codes before
  source-file replay or Torii durable-store reload,
  positive notary record counts before publication and during source-file or
  production-evidence replay,
  Torii reload clean-string enforcement, filename/message-id binding, symlink-free regular-file-only
	  record directory/loading, symlink-free durable-output directories, and a 1 MiB Torii
	  persisted-record persist/reload cap, rejects retired `colr.007` rail
	  source files with no local override path,
  rejects symlinked receipt archive directories before discovery, rejects
  repeated receipt paths or copied receipts with duplicate `receipt_sha256` values, and
  emits a digest-bound verifier summary with per-receipt file paths,
  `receipt_sha256` values, and policy flags.
- Completed 2026-06-04: added `scripts/iso_operator_canary.py` as the generic
  provider canary runner. The runner consumes a strict JSON runbook capped at
  64 KiB with explicit provider/environment labels, executes the rail file-drop adapter,
	  audit notary adapter, and receipt verifier as subprocesses, rejects unknown
	  runbook keys, rejects surrounding whitespace and control characters in
	  runbook strings, rejects present `null` optional path and numeric limit
		  fields instead of silently applying defaults, rejects embedded whitespace,
		  leading-dash path segments, backslashes, semicolon path parameters, empty
		  path segments, dot/parent segments, and secret-looking key/value or
		  identifier-style material in ordinary runbook artifact paths before expansion, keeps relative paths inside
	  the runbook directory while preserving final path leaves for child script
	  symlink/file-boundary checks, keeps bearer-token file paths as redacted
	  runtime secret-file references, rejects identifier-style secret-looking
	  child stdout/stderr previews before summary emission, rejects
		  endpoint URLs with credentials, params, query strings, fragments, embedded
		  whitespace, malformed bracketed hosts, overlong URL strings, or DNS hosts
		  longer than 253 characters, localhost/local-private IP literals, or known
		  local/private rebinding hostnames, reserved placeholder hosts such as
		  `.example`, `example.com`, `example.net`, `example.org`, or
		  `example.invalid`, legacy IPv4 numeric notation, or IPv6 transition
		  addresses embedding non-global IPv4 addresses,
		  accepts checked-in `operator-canary.bank` template endpoints only for
		  `--plan-only` validation and rejects them before non-plan child execution,
	  rejects empty, zero, leading-zero, malformed, out-of-range, or explicit-default ports,
	  rejects non-canonical hosts, invalid DNS labels, percent-escaped hosts,
		  numeric-host spoofing, percent-escape smuggling, and smuggled URL paths
		  including encoded semicolon parameters and encoded URL delimiters,
		  rejects duplicate endpoint lists, duplicate explicit receipt paths or receipt
	  directories, overlapping direct receipt files already covered by explicit or
	  generated verify receipt directories, and shared stage receipt directories, verifies generated
	  receipts by default with source-file cross-checks, redacts bearer-token file
  arguments in the summary, bounds each child stage with positive finite
  `--stage-timeout-secs`, records `timed_out` for killed children, drains child
  stdout/stderr through the configured preview cap instead of retaining
  unbounded output, treats any executed child stdout/stderr preview truncation
  or successful child stderr as a failed canary, supports
  `--require-explicit-policy` so production runbooks must spell out every
  policy boolean plus list-valued notary/verify receipt selector fields and the
  summary records that proof, with regression coverage over the rail, notary,
  and verifier policy-boolean/list surface, and writes a single
  bounded JSON summary suitable for CI or operator evidence archives. Summary
	  output paths are preflighted before subprocess stages, reject control
	  characters, whitespace, leading-dash segments, backslashes, semicolon
	  parameters, empty segments, dot/parent traversal, symlinked existing ancestors, and
	  hard-linked, symlink, or non-regular targets, and are written via
	  exclusive same-directory owner-private temporary files with
	  bounded digest-derived names that are descriptor-rechecked, fsynced, and
	  atomically replaced where available.
  `--plan-only` validates runbooks, prints redacted child commands without
  contacting Torii or notary endpoints, and emits `ok=false` so planned output
  cannot be confused with an executed canary. Executed direct summaries now
  emit `ok=true` only when `--require-explicit-policy` was used, planned policy
  records and executed results are the exact ordered rail/notary/verify
  records, no stage skipped or producer dry-run was used, local diagnostic
  allowances such as insecure HTTP, default profiles, or failed receipts were
  absent, and verifier source-file checks stayed enabled. Aggregate evidence
  summaries now preserve a compact canary `ok` verdict that is true only for
  executed, explicit-policy, non-dry-run canaries with all production stages and
  a production-complete receipt summary; final readiness recomputes that verdict
  and reports
  `evidence.canary_summary_not_ok` or
  `evidence.canary_summary_ok_drift` for diagnostic or relabelled canary
  evidence.
- Completed 2026-06-04: added checked-in ISO operator canary runbook templates
  under `fixtures/iso20022/operator_canary/` for Swift CBPR+, Fedwire Funds,
  SEPA SCT Inst, and securities CSD profile families. The script tests validate
  that each template plans successfully without network access, while non-plan
  canary execution and archived production evidence reject the
  `operator-canary.bank` template endpoint suffix.
- Completed 2026-06-04: added `scripts/iso_trust_bundle_verify.py` as an
  offline XMLDSig/XAdES trust-bundle preflight for operator rail PKI packages.
  It caps bundle JSON at 64 MiB before parsing, verifies canonical lowercase
  profile IDs, known ISO rail IDs, canonical
  lowercase nonzero SHA-256 pins, digest-bound base64 DER envelopes with a
  pre-decode 1 MiB DER-size cap and lightweight semantic shape checks for X.509 certificates,
  X.509 CRLs, and OCSPResponse wrappers, duplicate material, contradictory
  trust/revocation pins, explicit CRL/OCSP revocation policy booleans, required
  CRL/OCSP material, HTTPS provenance without credentials, params, query
	  strings, fragments, malformed bracket syntax, control characters, surrounding
	  or embedded whitespace, empty/zero/leading-zero/malformed/out-of-range/default ports, localhost, or
	  local/private IP literals, non-canonical hosts, invalid DNS labels,
		  percent-escaped hosts, numeric-host/legacy-IPv4 spoofing, IPv6
		  transition embedded-IPv4 smuggling, percent-escape smuggling,
		  smuggled URL paths including encoded semicolon parameters, encoded URL delimiters, and repeated separators, required provenance URL,
			  an explicitly recorded top-level `source` object,
			  required source authority/version values, and timezone-aware
	  non-future retrieval timestamp fields,
  repeated-path/copied-bundle/duplicate
  profile ID rejection, duplicate `bundle_sha256` rejection, unique DER labels
  per material class, mandatory DER-object `sha256` values that must match
  canonical decoded `der_base64` bytes, omitted absent labels in trust summaries,
  archived-summary `label: null` rejection in the evidence gate, and
	  secret-looking fields before emitting Torii profile trust override JSON.
	  Trust bundles must now carry an explicit `embedded_signature_policy`;
	  omitted policy fields are rejected instead of defaulting to
	  `require-verified` during preflight.
	  Every list-typed trust-material field must also be recorded as an array,
	  including explicit `[]` values for intentionally empty pin or DER
	  collections, so profile override emission cannot infer absence as an empty
	  production proof.
	  Profile override emission now also rejects local-audit `--allow-record-only`
		  or `--allow-insecure-source-url` modes and placeholder source provenance
		  (`dummy`, `fake`, `placeholder`, `replace-before-production`, `sample`,
		  `template`, including separator- or compatibility-obfuscated variants, or reserved hosts such as `example.com`, `example.net`,
		  `example.org`, `example.invalid`, and `operator-canary.bank`), leaving those bundles summary-only
		  until real rail source metadata is supplied.
		  It also requires an explicit `--max-source-age-days` freshness budget and
		  leaves stale source packages summary-only instead of writing profile
		  overrides. The digest-bound trust summary records that budget so evidence
			  and readiness can reject omitted, malformed, or weaker source-freshness
			  policy, reject separator- or compatibility-obfuscated trust-source placeholder markers,
			  and recompute whether `profile_json_emittable` still matches the
			  archived source evidence.
		  Local-audit trust-bundle overrides now also reject unused
		  `--allow-record-only`, `--allow-insecure-source-url`, and
		  `--allow-synthetic-der` flags unless a verified bundle actually carries
		  matching non-production policy, insecure source URL, or synthetic DER
		  evidence; private synthetic-DER usage is stripped before summary emission.
		  Trust summaries now record `ok=true` only when profile JSON was emitted,
		  `profile_json_emittable` remains true, and no local trust diagnostic
		  override was used.
	- Completed 2026-06-04: added checked-in trust-bundle templates under
	  `fixtures/iso20022/trust_bundles/` for Swift CBPR+, Fedwire Funds, SEPA SCT
  Inst, and securities CSD profile families. The templates use synthetic DER
  envelopes for CI/schema validation only, require `--allow-synthetic-der`,
  cannot emit profile override JSON, and must be replaced with current rail PKI
  material before production.
- Completed 2026-06-04: added `scripts/iso_operator_evidence_verify.py` as an
	  offline production evidence gate for ISO operator archives. The verifier
	  recomputes canary and trust summary digests, requires successful
	  rail/notary/verify canary stages plus digest-bound receipt-verifier JSON with
	  positive rail/notary receipt evidence, canonical sorted duplicate-free
	  receipt-kind lists and canonical compact receipt entry order by
	  receipt kind, path, and digest, emits top-level canary and trust compact
	  summaries in canonical path/digest order,
	  unique canonical `*.receipt.json` receipt paths, unique per-receipt digests,
	  per-receipt `ok=true` plus 2xx `status_code` success metadata, and
	  kind-specific notary anchor/index/count or rail message/profile/payload
	  metadata,
		  complete child-process stdout/stderr previews for every executed canary
			  stage without unsafe control characters or identifier-style
			  secret-looking material, rejects timed-out stages, rejects non-null successful-stage
			  `reason` fields, rejects forged canary summaries that
			  carry both executed `stages` and plan-only `planned_stages` branches,
			  and readiness replay keeps plan-only compact summaries blocker-producing
			  only when they retain `stage_windows: []` and explicitly recorded
			  `receipt_summary: null`; the evidence gate rejects
			  `--allow-plan-only` unless at least one canary summary records
			  `plan_only=true`, and rejects `--allow-partial-canary` unless at
			  least one canary summary is missing a rail or notary stage,
					  rejects stale legacy summary fields and unused default-profile receipt overrides unless
					  compact rail receipts actually carry missing
						  profile evidence, and rejects unused record-only/synthetic/missing-source
					  trust overrides unless compact trust summaries carry the
					  corresponding diagnostic trust material, binds compact
					  record-only and insecure-source trust policy flags to actual
					  non-production signature policy or `http://` or local/private
					  source provenance per trust summary, so one diagnostic trust
					  summary cannot mask hidden diagnostic material in another,
					  emits `ok=false` on evidence summaries whenever any local
					  non-production `allow_*` policy flag is in force, with
					  final readiness recomputing the top-level evidence verdict,
					  preserving diagnostic policy flags as `"unsupported"`, and
					  reporting `evidence.summary_ok_drift` when a digest-correct
					  summary relabels local policy as production-ready,
					  rejects unused dry-run,
					  failed-receipt, insecure-HTTP, and receipt-source-missing diagnostic overrides unless an
					  archived canary command actually targets HTTP or local/private
					  routing, the receipt summary or trust summary carries that
					  policy, or a receipt summary records
					  `require_source_files=false`, with failed-receipt policy requiring a receipt summary
					  with at least one failed receipt entry rather than planned
					  command text or a summary flag alone, insecure-HTTP receipt
					  policy requiring a compact receipt entry whose endpoint needed
					  the diagnostic override, executed rail/notary child commands
					  carrying the matching `--allow-insecure-http` flag plus
					  matching compact receipt-kind endpoint evidence,
					  executed rail default-profile commands
					  carrying matching compact rail receipt evidence for the same
					  diagnostic condition, with default-profile rail receipts also
					  naming `--default-rail-profile` so trust coverage is checked for
					  the configured fallback profile,
					  executed canary rail/notary stage names matching the compact
					  `receipt_kind` set, with compact `stage_dry_run` booleans
					  aligned to `stage_names`, so partial or dry-run canary
					  evidence cannot borrow receipts from absent or dry-run-only
					  producer stages, verify-stage `--receipt-dir`
					  values covering every non-dry-run rail/notary receipt dir and
					  scoped to the recorded rail/notary stages for executed and
					  plan-only canaries, direct verify-stage `--receipt` files
					  scoped under recorded stage receipt directories, shared
					  rail/notary stage receipt dirs rejected, non-null verify-stage
					  `receipt_dir` fields rejected, duplicate or
					  overlapping verify-stage receipt selectors rejected before stdout
					  is trusted, canary runbook planning requiring generated
					  non-dry-run rail/notary receipt directories to be selected by
					  `include_stage_receipts=true` or explicit generated
					  `verify.receipt_dirs`, and rejecting selected generated receipt
					  verification when the verify policy omits the `allow_insecure_http`
					  or `allow_default_profile` overrides required by non-dry-run
					  producer commands or disables `require_source_files`,
					  executed canaries with `verify.enabled=false` marked failed with a
					  skipped verify stage,
					  raw plan-only stage `dry_run` booleans matching the planned
					  child command's `--dry-run` flag,
					  hidden endpoint-policy evidence
					  requiring the matching summary flag, and binds canary
					  verify-stage receipt-verifier command
				  flags to the captured receipt-verifier JSON policy booleans,
					  mirrors failed-receipt, insecure-HTTP endpoint, stale retired
					  `colr.007`, and default-profile policy bindings in
				  production-readiness compact evidence replay, including
				  resolving compact `profile=null` rail receipts through
				  `policy.default_rail_profile` before trust-profile coverage is
				  evaluated,
				  and timeout-bounded direct receipt archive verification covering canary
		  receipt digests, receipt filenames, receipt kinds, successful status
		  metadata, response-body digests, endpoint-policy evidence, kind-specific compact receipt metadata,
		  successful direct-verifier stderr rejection, and explicit rejection
		  of rail default-profile fallback unless the local override is recorded by
		  the receipt verifier and the evidence policy binds the configured fallback
		  profile; canary-stage-only diagnostic evidence is rejected
		  when direct `--receipt` or `--receipt-dir` archive inputs are supplied
		  and otherwise must retain
		  both `receipt_verification: null` and the matching archived
		  `allow_canary_stage_receipts_only` policy flag before readiness can treat
		  the missing direct archive as an allowed local diagnostic, and that
		  policy flag remains blocked when direct archive verification is present,
	  requires exact expected `--provider` and `--environment` CLI context and
	  records that context in the digest-bound evidence policy for readiness
	  rechecking, requires explicit freshness budgets for canary, trust-summary,
	  and trust-source evidence while recording them in the evidence policy,
	  preserves compact trust profile JSON emission booleans and a digest
	  recomputed from archived profile overrides, rejects an unused
	  `--allow-profile-json-not-emitted` override unless at least one trust
	  summary records `profile_json_emitted=false`, rejects profile-emittable drift
	  and emitted-but-not-emittable contradictions against the archived trust
	  source policy, `bundle_sha256`, required
	  source authority/version plus source URL/retrieval provenance, the trust
	  verifier's `max_source_age_days` emission budget,
	  revoked-certificate pin count, certificate-policy
	  OID count, CRL/OCSP material-class proof, and compact
	  trust-anchor/revoked/CRL/OCSP DER proof digests and byte lengths for the
	  final rollup,
		  rejects compact canary config paths, receipt paths, and child
		  receipt-directory arguments with embedded whitespace, leading-dash path
		  segments, semicolon path parameters, empty segments, raw backslashes,
		  traversal segments, or values longer than 2048 characters,
	  rejects stale digest-correct archive inputs, rejects repeated or copied
  canary/trust summaries by path and `summary_sha256`,
  requires canary summaries to prove they were generated with
  `--require-explicit-policy`, rejects duplicate compact receipt paths/digests,
  rejects rail/notary receipt source path or source digest replay across
  canary summaries at evidence-verification time and across distinct evidence
  summaries at readiness time, rejects rail receipt `source_path`,
  `payload_sha256`, or `rail_message_id` relabels within one compact receipt
  summary while still checking `source_path` and `payload_sha256` when
  `rail_message_id` is null and still allowing legitimate notary multi-endpoint
  publication of one anchor, duplicate
  archived trust profile IDs, copied
  compact trust profile JSON digests, all-zero trust bundle/profile JSON/pin/DER
  digests, profile JSON or bundle digests reused as compact trust material, and
  bundle digests across summaries with
  label-only diagnostics, emits compact trust profiles in canonical `profile_id`
  order for final replay, rejects non-canonical archived trust profile IDs or unknown
  rail IDs, requires each canary rail receipt profile to have matching compact
  trust material for the same profile ID and environment, with same-rail binding
  for built-in rail-named profiles, and reports missing trust coverage without
  printing the compact profile ID or canary environment label, rejects forged trust profile overrides whose id/rail/policy,
  pin/OID/CRL/OCSP counts, canonical OIDs, DER summary digests, DER byte
  lengths, bounded canonical base64 DER SEQUENCE blobs, or trusted/revoked pin
  overlap no longer match the trust-bundle verifier output,
	  rejects duplicate JSON object keys, non-standard `NaN`/`Infinity` JSON
	  constants, and lone UTF-16 surrogate escapes across raw canary, trust,
	  receipt, XSD, evidence, readiness, embedded receipt-verifier stdout, and direct archive
		  receipt-verifier stdout inputs before semantic validation, and rejects
	  symlinked existing ancestors plus symlink or non-regular leaves for canary
	  runbooks, trust bundles, evidence/readiness summaries, XSD manifests,
	  profile catalogs, schema files, XML fixtures, and receipt archive
	  directories before digest, provenance, discovery, or policy checks run,
	  opens those checked file inputs through no-follow file descriptors where
	  available, rejects raw CLI artifact path smuggling for live rail inbox
	  roots, live notary export roots, rail/notary bearer-token files, canary
	  configs, trust bundles, XSD manifests/profile catalogs, receipt
		  files/directories, canary/trust summaries, and XSD/evidence summaries
		  before argparse `Path` normalization or file discovery, rejects
  non-positive or non-finite live rail/notary timeout values,
  non-positive live adapter byte caps, and live response-body retention caps
  above 4 MiB before local reads or network delivery, caps archived
  canary/trust and XSD/evidence summary JSON inputs at 4 MiB before parsing,
  caps recursive ISO JSON surrogate/secret-material scanners at 8192 array
  entries, 8192 object members, and 128 nesting levels before walking unknown
  or unsupported JSON shapes, and wraps parser recursion failures with the same
  label-only nesting diagnostic before local paths or attacker-controlled
  leaves can be echoed,
  caps operator-canary runbook notary endpoint and verifier receipt-selector
  string lists at 8192 entries before entry parsing,
  caps repeatable audit-notary endpoint inputs at 64 values before export
  loading,
  caps receipt/notary audit record, status-history, and change-reason arrays at
  8192 items before replay,
  caps repeatable trust-bundle paths and receipt verifier selector paths at 64
  entries before bundle parsing or receipt discovery,
  caps trust-bundle SHA-256, certificate-policy OID, and DER material lists at
  8192 entries before per-entry parsing,
  caps repeatable evidence canary/trust/receipt/receipt-directory path lists
  at 64 entries before loading evidence files,
  caps repeatable readiness XSD/evidence summary input path lists at 64 entries
  before loading any summary files,
  caps untrusted XSD manifest/profile-catalog, evidence-summary, and
  readiness-summary JSON arrays at 8192 items before semantic replay,
  caps direct receipt-verifier stdout/stderr at 4 MiB before JSON parsing,
  redacts key/value, identifier-style secret-looking, control-bearing,
  non-ASCII, and local-path-shaped direct receipt-verifier stderr before
  reporting failed child verifier diagnostics,
  reports XSD `xmllint`, canary child-stage, and direct receipt-verifier startup
  failures, including runtime/type/value launcher failures, with stage labels
  instead of argv, local paths, or raw process-launch exception text or chained
  traceback causes,
  reports their stdout/stderr runtime/type/value pipe read or close failures
  plus post-wait thread `join()`/`is_alive()` bookkeeping failures as label-only
  stage-output read errors, and requires child-output pipe chunks to be
  byte-like values capped by byte length before preview decoding so
  wide-format `memoryview` chunks cannot bypass output limits, and reports
  runtime/type/value wait failures, cleanup kill failures, and malformed return
  codes as label-only child-finish errors,
		  rejects receipt,
		  summary, and emitted profile-override output paths when they contain
	  control characters, whitespace, leading-dash segments, backslashes,
	  semicolon parameters, empty segments, dot/parent traversal, symlinked existing ancestors,
	  or are hard-linked, symlink, or non-regular targets, then atomically replaces targets from owner-private
	  descriptor-checked temporary files with bounded digest-derived names,
  rejects plan-only or dry-run canaries, insecure HTTP evidence,
	  default-profile fallbacks, stale retired `colr.007` summary fields, unredacted
		  bearer-token paths, secret-looking child output, smuggled, whitespace-bearing,
		  empty-port, malformed-port, non-canonical-host, invalid-host-label, overlong-url,
		  overlong-host, percent-escape,
		  numeric-host/legacy-IPv4-spoofed, IPv6-transition embedded-IPv4,
			  repeated-separator, or traversal-bearing trust-source URLs,
			  placeholder trust-source authority/version metadata including `dummy`,
			  `fake`, `sample`, or `template`, and reserved source provenance hosts
			  such as `.example`, `example.com`, `example.net`, `example.org`, or
			  `example.invalid`, and `operator-canary.bank`,
  missing/malformed/future trust-source retrieval timestamps,
  missing/malformed/future or padded trust-summary `verified_at` timestamps, smuggled
  live adapter, canary runbook, child command, and direct receipt endpoint URLs
  including localhost/local-private IP literals, known local/private rebinding
  hostnames, reserved documentation hosts such as `.example`, `example.com`,
  `example.net`, `example.org`, or `example.invalid`, template child-command
  suffixes such as `operator-canary.bank` even under local insecure-HTTP replay,
  direct receipt archive endpoints under the same checked-in template suffix,
  legacy IPv4 numeric notation, or IPv6 transition addresses embedding non-global IPv4 addresses,
  local-only child command flags in either `--flag` or `--flag=value` form, including the notary adapter's
  `--allow-missing-record-sources` diagnostic override, unsupported child
  command flags outside the expected rail/notary/receipt-verifier CLI surfaces,
  duplicate singleton child command flags, boolean child command flags using
  attached or separate values, non-positive, non-finite, or non-canonical
  numeric child command flag values, leading-dash archived rail/notary endpoint
  URL or bearer-token-file values, non-canonical child command path values, control-bearing or
  whitespace-padded child command entries, missing required child command
  inputs, whitespace-padded strings or paths, non-canonical canary
  rail/notary `receipt_dir` values,
	  rail/notary `receipt_dir` values that do not match the child command's single
	  `--receipt-dir`, verify-stage commands that omit generated rail/notary
	  receipt directories, control-bearing or whitespace-padded
	  provider/stage/receipt-kind/trust-profile identity strings, non-canonical
	  canary runbook `config_path` values, unknown upstream canary/receipt/trust
	  summary fields, synthetic trust DER, record-only trust policy, and trust
	  summaries that did not emit profile override JSON before an archive is
	  accepted as production evidence. Canary command redaction also handles
  `--bearer-token-file=<path>` in addition to the separated argument form.
- Completed 2026-06-04: added `fixtures/iso20022/xsd/fixture_manifest.json`
  and `scripts/iso_xsd_fixture_verify.py` as an offline structural preflight for
  checked-in ISO XSD/XML fixtures. The verifier checks schema target
  namespaces, `Document` payload roots, XML fixture namespaces and payload
  roots, canonical lowercase ISO message definition ids, schema path
  containment under the manifest tree, fixture path containment under the ISO
  fixture tree, manifest duplicates/path escapes, manifest schema/fixture path
	  and fixture schema-reference whitespace, URI/drive-prefix, semicolon, or
	  percent-escape smuggling, duplicate XML
  fixture SHA-256 values, optional `xmllint --nonet` XML schema validation for
  schema-backed fixtures, and digest-bound summaries while making reviewed
  missing-schema fixture exceptions explicit. All
  checked-in payment XSDs now have standalone XML fixtures and validate against
  their checked-in XSDs, so the `--require-fixture-for-schema` strict flag
  passes; the schema-backed strict flag still rejects the current
  official-package gaps until the remaining securities/collateral/legacy-return
  XSDs are checked in. `--require-profile-schema-backed-versions` now uses
  the default `DEFAULT_PROFILES_JSON` catalog when no `--profile-catalog`
	  override is supplied, so the release gate fails directly on the current
	  profile-advertised schema gaps.
  The checked-in manifest records official ISO pending-source evidence,
  including exact direct XSD download URLs, for the remaining unreviewed
  securities/collateral profile message ids, so current compact readiness
  summaries report zero unreviewed unique profile schema gaps while strict
  schema-backed closure still fails. Direct XSD verification and final readiness
  replay now pin those known pending message definitions to their exact recorded
  ISO catalogue URLs, direct download URLs, download type, message names, and
  submitting organisations. Pending direct download URLs must be unique within
  each summary and across archived summary replay, pending official ISO
  catalogue/download URLs must not contain percent escapes, archive catalogue
  URLs must use canonical raw `page=<nonzero decimal>` queries, and pending
  source message names must be unique and use canonical ISO-style CamelCase plus
  `VNN` suffixes that match the corresponding `message_def_id` version segment.
  XSD fixture-summary emission now writes compact `schemas`, `fixtures`,
  `blocked_schema_sources`, `pending_schema_sources`, `missing_schema_fixtures`,
  and `schema_only_entries` in canonical order, emits nested profile-catalog
  `versions`, `missing_schema_versions`, and `skipped_family_versions` in
  canonical profile/message/direction/version order, and readiness rejects
  digest-correct reordered compact schema, fixture, blocked-source,
  pending-source, profile-catalog version, or skipped-family arrays during
  replay.
  Blocked public XSD candidate evidence now must include at least one explicit
  redistribution or public-distribution restriction marker; a copyright-only
  marker list is rejected before manifest summary emission and again during
  readiness replay.
	  Optional manifest/profile fields are optional only when
	  omitted; present `null` reviewed reasons, trust/revocation material lists,
  booleans, numeric caps, business-service arrays, or amount minor-unit arrays
  fail before a digest-bound XSD summary can be emitted. Required and optional
  manifest/profile-catalog strings now reject ASCII control characters before
	  summary emission, including reviewed gap reasons. Reviewed gap reasons and
	  blocked-source review reasons must also remain printable ASCII,
	  secret-looking-free, and capped at 1024 characters in direct XSD summaries
	  and readiness replay.
	  Readiness also rejects archived reviewed gap reasons that are present but
	  empty or non-string instead of treating them as absent, blocks schema-backed archived fixtures
		  that still carry a missing-schema reason, and checked-in XSD source
			  provenance, manifest schema, fixture, fixture schema-reference, and
			  archived profile-catalog paths reject non-ASCII characters, overlong
			  source or relative paths, embedded whitespace, leading-dash path segments,
			  semicolon path parameters, URI/drive prefixes, or malformed/smuggled
			  percent escapes before summary emission and during readiness rechecks.
  Readiness also requires archived XSD summaries to retain the emitted manifest
  path and explicit profile-catalog object/null state.
- Completed 2026-06-04: added `scripts/iso_production_readiness.py` as the
  aggregate offline ISO release gate. It verifies digest-bound XSD fixture and
  operator evidence summaries, requires strict schema-backed/fixture-backed XSD
  proof by default, rejects non-production evidence policies, provider or
  environment drift, missing rail/notary/verify canary stages, missing
  rail/notary receipt kinds, missing or weak direct receipt-archive
  verification, direct archive receipts unrelated to any canary receipt summary,
  unsupported compact receipt entry kinds, copied compact receipt paths or
  digests reused across canary summaries, all-zero compact receipt digest
  placeholders, failed or status-mismatched compact
  canary/archive receipt entries, stripped or cross-kind compact receipt
	  metadata, archive/canary compact receipt status, endpoint-policy evidence, or metadata drift for the
	  same receipt digest, stale retired `colr.007` summary fields,
  canary/trust/receipt/profile material replayed across evidence summaries,
  omitted XSD strict flags,
  XSD summaries produced without XML schema validation,
  inconsistent digest-bound XSD schema/fixture arrays, duplicate XSD schema or
  fixture evidence digests, XSD schema/fixture material replayed across compact
  summaries, non-canonical or message-id-mismatched schema
	  paths, leading-dash path tokens or segments, non-XML, absolute, empty-segment, dot-segment, or non-leading-parent
  fixture paths, schema `target_namespace` drift, schema-reference
  message-id/payload-root drift, unknown XSD summary fields, forged or
	  non-canonical missing-schema/schema-only reviewed gap-list paths and reason
	  strings, forged schema-only flags/reasons, stale missing-schema reasons on
	  schema-backed fixtures, forged
  profile-catalog missing-version lists and represented profile-id counts,
  omitted evidence or nested receipt-summary policy flags, archived trust
  summaries with omitted policy/profile revocation flags, omitted planned-stage
  `dry_run` flags, omitted evidence status booleans, omitted whole XSD or
  evidence input summaries, omitted explicit release `--provider` or
  `--environment` context, omitted explicit freshness budgets, stale
	  digest-correct XSD/evidence/canary/trust summaries, omitted or drifted
			  evidence policy context, omitted or weaker evidence freshness policy fields,
			  omitted, malformed, or release-weaker compact trust source freshness budgets,
		  omitted or malformed compact trust source authority/version provenance,
		  omitted, malformed, placeholder, overlong-url, or overlong-host compact trust source provenance, stale compact trust
  source retrieval timestamps, profile-emittable drift or emitted-but-not-emittable
	  contradictions against compact trust source policy, omitted canary
	  explicit-policy proof, repeated or
	  copied XSD/evidence summaries, reordered compact XSD schema, fixture,
	  blocked-source, pending-source, top-level evidence canary/trust, or
	  receipt-entry arrays, missing or non-canonical compact canary
	  runbook `config_path` values, compact canary/trust summary paths that do
		  not point to `.json` files, canary
		  config paths, and receipt paths with embedded whitespace, leading-dash
		  path segments, semicolon path parameters, empty segments, raw backslashes,
		  traversal segments, or checked-in ISO fixture artifact coordinates,
	  whitespace-padded compact strings or paths, unknown compact evidence fields,
  repeated or copied compact canary/trust summaries, nested receipt-summary
  tampering, non-canonical compact receipt paths, duplicate receipt paths or
  receipt digests, receipt/response/source digest role reuse inside compact
  receipt entries and receipt-verifier stdout, weak trust profiles, duplicate
  compact trust profile IDs,
  copied compact trust profile JSON digests, or bundle digests across trust
  summaries, all-zero compact trust bundle/profile JSON/DER proof digests,
  non-canonical compact trust profile IDs or unknown rail IDs,
  missing or malformed compact trust `bundle_sha256`,
  public-key/certificate SHA-256 pin role reuse in trust bundles, profile
  catalogs, and evidence replay, trust pin reuse against CRL/OCSP DER proof
  material,
  evidence-gate bundle digest role reuse against compact DER proof material,
  final-readiness profile JSON or bundle digest role reuse against compact DER proof material,
  record-only trust policy,
  disabled CRL/OCSP revocation checks, and missing required revocation
  material with label-only blocker text, omitted revoked-certificate or certificate-policy compact trust
  counts, omitted, count-drifted, or cross-role-reused compact DER proof
  fields, mismatched trust
  `verified_bundles`/profile counts, missing compact
  canary/trust source paths, malformed compact canary/trust source paths,
  non-canonical or all-zero compact canary/trust summary digests, and missing,
  control-bearing or whitespace-padded compact identity strings, timezone-less,
  or future
  XSD/evidence/trust `verified_at` timestamps, malformed or reversed canary
  `started_at`/`finished_at` windows,
  missing or out-of-window compact `stage_windows`, overlapping stage
  timelines, name-mismatched or reordered compact stage windows, and emits a
  digest-bound blocker report for valid but not-yet-production summaries.
  Compact canary stage names must also be unique, limited to the production
  stages, and ordered as rail/notary/verify. Local readiness overrides are now
  bound to matching evidence: `--allow-reviewed-xsd-gaps` requires at least one
  reviewed XSD warning beyond a truly unreviewed profile-version gap, only
  downgrades profile-version gaps tied to exact reviewed message-definition
  evidence, and
  `--allow-canary-stage-receipts-only` requires an
  evidence summary with canary-stage-only receipt policy and missing direct
  receipt archive verification. Both overrides still emit stable
  `readiness.policy.*` blockers, so local diagnostic rollups cannot return
  `ok: true` as production-ready release evidence. XSD summaries also expose
  `ok=false` for repository fixture or reviewed-gap diagnostic material, with
  final readiness emitting `xsd.summary_not_ok` or `xsd.summary_ok_drift` when
  replayed fields disagree with that verdict. Compact trust summaries that explicitly record
  `allow_insecure_source_url=true` can replay `http://` or local/private
  trust-source URLs as diagnostic evidence and still produce readiness blockers
  instead of aborting as malformed.
- Completed 2026-06-04: hardened live securities lifecycle profile admission
  against local reference snapshots. `sese.023`/`sese.025` profile validation now
  rejects syntactically valid but unmapped settlement instrument ISIN/CUSIP
  values, inactive or unknown place-of-settlement MICs, and unmapped delivering
  or receiving party BICs before a durable settlement lifecycle record can be
  accepted.
- Completed 2026-06-04: gated live `securities-csd` `sese.023` ledger
  instruction admission on configured CSD venue, securities settlement-account,
  and cash-leg crosswalk snapshots. The gate now rejects missing snapshots,
  incomplete rows, party/account mismatches, and unknown cash-leg currencies
  before durable lifecycle recording, with checked-in sample snapshot schemas
  under `fixtures/iso_bridge/`.
- Broaden XMLDSig/XAdES fixture coverage beyond the current local fixture set,
  including full certificate-chain fixtures and official rail/profile-specific
  trust-anchor packages that replace the synthetic trust-bundle templates and
  emit production profile override JSON with digest-bound `profile_json_sha256`
  evidence.
- Run provider-specific production canaries for the selected archival/notary
  vendors using `scripts/iso_operator_canary.py`, pass the archived summaries
  and receipt files through `scripts/iso_operator_evidence_verify.py`, retain
  the accepted evidence summary and receipts, include the accepted evidence in
  `scripts/iso_production_readiness.py`, and document any vendor-specific
  authentication, SLA, or response evidence required by the production runbook.
- Run provider-specific live gateway canaries for selected
  SWIFT/Fedwire/SEPA/CSD operator integrations using
  `scripts/iso_operator_canary.py`, pass the archived summaries and receipt
  files through `scripts/iso_operator_evidence_verify.py`, retain the accepted
  evidence summary and receipts, include the accepted evidence in
  `scripts/iso_production_readiness.py`, and document rail-specific file-drop,
  retry, and acknowledgement handling.
- Add redistributable official MDR/XSD fixture coverage for the remaining
  profile-advertised gaps beyond the current schema-backed payment and
  cancellation corridor. `pacs.004.001.09` is now checked in and validated in
  the live-profile matrix; remaining blockers include `pacs.002.001.12`,
  `pacs.008.001.10`, and `pacs.009.001.10` (available public candidates
  inspected so far carry restricted redistribution terms and are now recorded as
  blocked sources in the fixture manifest) plus the securities and collateral
  lifecycle packages.
  Make the strict
  `scripts/iso_xsd_fixture_verify.py` schema-backed release flag
  (`--require-schema-backed-fixtures`) pass,
  make the aggregate `scripts/iso_production_readiness.py` gate pass without
  diagnostic overrides, and keep broadening Torii tests for
  additional live-rail profile edge cases beyond the current family-mismatch,
  conflicting-reference, BAH securities-linking, and collateral-substitution
  guards.

### ISO 20022 operator tooling hardening notes

Current ISO 20022 operator tooling already versions digest-bound XSD, canary,
trust-bundle, and receipt-verifier summaries and rejects missing or unsupported
versions in evidence and production-readiness gates. Archived evidence and
readiness summary self-digests plus readiness compact canary/trust summary
references reject all-zero placeholders before digest mismatch checks run, and
digest mismatch diagnostics stay label-only instead of printing expected or
recomputed SHA-256 values. Archived CRL/OCSP override DER drift diagnostics
also report only the DER material role and mismatch class instead of printing
the DER SHA-256 value. Trust-bundle verification and direct evidence replay
also keep unsupported internal DER material kind diagnostics label-only instead
of echoing the supplied kind string. Trust-bundle summaries now emit raw
`bundles` entries in canonical `profile_id`/path/digest order and raw
trust-anchor, revoked-certificate, CRL, OCSP, and profile-override DER material
in SHA-256/byte-length order, with profile-override SHA-256 pin and
certificate-policy OID lists sorted canonically as well; direct evidence replay
rejects digest-correct raw trust summaries that reorder those arrays, and
readiness replay blocks reordered compact trust DER proofs. Schema-critical integer
metadata such as versions, receipt status codes, and notary record counts reject
JSON boolean aliases before evidence can be archived. Receipt status codes are
also bounded to the HTTP 100-599 range before success-policy checks, while live
rail/notary adapters accept only real integer upstream status values, reject
boolean or string aliases before coercion, and normalize non-standard remote
statuses into transport-failed receipts with `status_code=null` instead of
archiving invalid HTTP evidence. Their URL/transport-error receipt strings now
record fixed rail/notary labels instead of OS/library reason text, and the
receipt verifier rejects archived receipt `error` strings that reintroduce local
paths. Evidence/readiness
replay accepts those null-status entries only as failed receipts without
response-body digests, and bounded child-process output byte caps reject boolean
aliases before verifier subprocesses run.
Regular-file and rail payload byte caps now also reject boolean or non-integer
aliases before filesystem metadata is inspected.
Pending XSD source probes now reserve `reachable` for real 2xx responses
with positive bounded samples that start with a namespace-bound XML Schema root
opening tag, not just an XML declaration or embedded schema-looking text;
redirect-class or other non-2xx XSD-looking samples fail closed as
`NetworkError` evidence without retained sample bytes, while non-XSD
1xx/2xx/3xx samples are recorded and replayed as
`unexpected` evidence instead, and malformed
status metadata, zero-byte success responses, malformed non-byte read output,
or stream read failures become `NetworkError` evidence without retained sample
bytes. Bytes-like read outputs are sliced to the configured bounded window by
byte length before digesting or classification even if a response object
over-returns or returns a wide-format `memoryview`, while `truncated` still
records cap overflow.
Archived child-command evidence rejects value-taking flags whose separate or
equals-form values are empty or another flag token, keeping canary command
evidence unambiguous before production archiving.
Archived child-command floating timeout values also reject Unicode digit
confusables before Python numeric parsing can accept them.
Canary runbook path strings and archived child-command local path values must
remain printable ASCII and capped by the 4096-character local path limit, while
production-readiness compact summary/config/receipt path strings replay the
stricter 2048-character archive cap, so Unicode-confusable or oversized path
evidence cannot be planned or replayed into release archives. Evidence and
readiness replay also reject compact canary/trust summary paths reused as canary
config paths, canary-stage receipt paths, direct receipt-verification paths, or
trust-bundle paths, including across relabelled evidence summaries.
Final readiness output now emits top-level XSD, evidence, and pending-probe
summary references, blockers/reviewed-gap warnings, and nested diagnostic
entries in canonical order before computing the readiness summary digest, so
diagnostic archives do not depend on input traversal order. Verified XSD,
evidence, and pending-probe summaries are also canonicalized before
cross-summary blockers are generated, so duplicate/replay diagnostics choose
stable labels and paths. Receipt-summary entry order is checked independently
of receipt-digest shape, so malformed `receipt_sha256` values cannot hide
noncanonical canary or archive receipt replay order. Unsupported receipt kinds
and unsupported or malformed rail `message_type`, `profile`, `rail_message_id`,
and `source_path` values are also scrubbed from the normalized readiness output
as `"unsupported"` while blockers keep label-only diagnostics.
Unsupported summary `version` values in XSD, pending-probe, canary, receipt, and
trust summaries are similarly normalized to `"unsupported"` in final readiness
output.
Archived evidence policy, canary, and trust profile provider/environment context
values that drift from the release CLI context are also normalized to
`"unsupported"` in final readiness output.
Release and archived freshness budgets are capped at 36,500 days; over-ceiling
CLI, evidence policy, or compact trust source values fail without echoing the
submitted number, and weaker archived budgets normalize to `"unsupported"` in
final readiness output.
Blocked compact trust verifier override flags and receipt verifier `allow_*`
policy flags also normalize to `"unsupported"` in final readiness output, as
does `require_source_files=false`.
Receipt entries that preserve local-only legacy rail message types or
default-profile fallback `profile=null` values, or
`endpoint_requires_insecure_http=true` markers, are likewise normalized to
`"unsupported"` in public readiness summaries after their policy blockers are
emitted.
Diagnostic trust-source URLs that require `allow_insecure_source_url=true`,
including `http://` and local/private endpoints, are likewise normalized to
`"unsupported"` in public readiness trust profiles after their override blocker
is emitted.
Missing compact trust source objects (`source=null`) are also normalized to
`"unsupported"` in public readiness trust profiles after source-missing blockers
are emitted.
Blocked canary `plan_only=true`, `require_explicit_policy=false`, per-stage
`stage_dry_run=true`, and compact trust `profile_json_emitted=false` /
`profile_json_emittable=false` states are also normalized to `"unsupported"` in
final readiness output. Compact trust `max_source_age_days=null` is likewise
normalized to `"unsupported"` when profile JSON is not emittable after trust
source blockers are emitted.
Failed pending-XSD probe `ok=false` and per-probe `looks_like_xsd=false` states
are likewise normalized to `"unsupported"` in public readiness summaries and
unreachable-probe blocker entries.
For non-success pending-XSD probes, public readiness output also normalizes
remote response/sample fields (`http_status`, `content_type`,
`downloaded_bytes`, `sample_sha256`, `truncated`, and `error_kind`) to
`"unsupported"` after the existing unreachable-probe blocker is emitted.
XSD strictness proof flags that remain `false` after replay,
`require_schema_backed_fixtures`, `require_fixture_for_schema`,
`require_profile_schema_backed_versions`, and `validate_xml_schema`, are also
normalized to `"unsupported"` in public readiness summaries after their existing
blockers or warnings are emitted.
Failed or malformed receipt entry `ok` values are likewise normalized to
`"unsupported"` in public readiness summaries after receipt status blockers are
emitted.
Receipt response metadata triplets (`ok`, `status_code`, and
`response_body_sha256`) are preserved only when they are internally coherent
successful proofs: `ok=true`, a 2xx integer HTTP status, and a canonical
nonzero response digest. Any failed, mismatched, incomplete, or malformed
triplet is normalized to `"unsupported"` in public readiness output after the
existing blocker is emitted.
Receipt-verifier summaries also carry an aggregate `ok` verdict, which is true
only when both production receipt kinds are present, every receipt entry
succeeds, source files were required, and no local receipt override
(`allow_failed`, `allow_insecure_http`, or `allow_default_profile`) was used.
Evidence and readiness replay recompute that verdict and report
`evidence.receipt_summary_not_ok`, `evidence.receipt_summary_ok_drift`,
`evidence.archive_receipt_summary_not_ok`, or
`evidence.archive_receipt_summary_ok_drift` for diagnostic or forged receipt
summaries.
Final readiness also accepts digest-bound pending-XSD probe summaries and
requires them when reviewed pending-source gaps are allowed, rechecking official
ISO URL metadata, freshness, counts, bounded sample digest shape,
`downloaded_bytes <= max_bytes`, the helper's 65,536-byte maximum sample cap,
the helper's 300-second maximum timeout cap, truncation consistency, and
failed-probe zero-byte/non-XSD-looking status shape, timeout/network-error null
`content_type` shape, malformed response status accessor failures, opener or
response context failures, HTTP-error 4xx/5xx status codes, failed-probe
`error_kind` role shape including exact `NetworkError` for network failures,
`unexpected` status shape as a real 1xx/2xx/3xx HTTP response with positive
sampled bytes and `looks_like_xsd=false`, plus `reachable` status shape as a
real 2xx HTTP response with XSD-looking probe status without importing the
restricted schema bytes. Replay also rejects forged `content_type` values that
the probe producer would have omitted, including whitespace-padded or
secret-looking header material; failed response header access omits
`content_type` without archiving accessor exception text, and runtime read
failures normalize to `NetworkError` without retaining exception text. Probe
summaries supplied without
matching pending official source gaps are now blocked as unreferenced evidence,
including extra probe rows when only a subset of official source gaps remains.
Probe-summary paths and summary digests are also blocked from replay under XSD
or operator-evidence artifact roles, preserving the separation between public
reachability evidence and schema-backed or live-evidence proof material.
Archived canary child commands now also must keep the runner-emitted shape:
Python interpreter, expected stage script path, then supported flags and their
values. Interpreter version suffixes are ASCII-only, so Unicode digit
confusables cannot satisfy replay as Python versions. The archived
interpreter/script paths use the same local-path smuggling preflight as other
artifacts, and extra positional command tokens are rejected before evidence can
be accepted. Unsupported archived command flags that carry secret-looking
material or non-ASCII spellings fail with label-only diagnostics before the
flag spelling can be echoed. Repeatable canary child-command selectors are
also canonicalized by the runner for notary `--endpoint` values and
verify-stage `--receipt-dir` / `--receipt` values, and direct evidence replay
rejects digest-correct archives that reorder those selectors.
Direct ISO CLI path preflights now also treat missing, empty, following
`--flag`, or `--path-flag=--flag` path values as missing before any file or
network work.
Production-readiness direct `run(args)` calls now mirror the CLI path-smuggling
guard for XSD summaries, evidence summaries, and summary outputs before input
loading, without converting checked-in fixture summary inputs from structured
release blockers into hard selector errors. Evidence-gate and final-readiness
direct production-policy flags also must be real booleans before summary
loading, so truthy strings or integers cannot enable diagnostic release
overrides.
Direct XSD fixture and trust-bundle policy flags likewise must be real booleans
before manifest or bundle loading, so programmatic callers cannot use truthy
strings, integers, nulls, or containers to loosen strict fixture or trust
verification.
`scripts/iso_pending_xsd_source_probe.py` now provides bounded, digest-stamped
reachability evidence for the official ISO pending XSD download URLs, including
`sample_sha256` over only the capped downloaded byte sample and `null` when no
bytes are fetched, without importing schema bytes. It rejects malformed
repeatable selectors plus non-ASCII, padded, or non-canonical numeric
timeout/byte-cap values, such as
`.5`, `01`, `1e01`, `1.`, `000512`, `+512`, or `512.0`, before network work.
`--timeout-secs` is capped at 300 seconds, and raw secret-looking CLI arguments
plus malformed `--summary-out` path tokens are also rejected before argparse can
echo them. This keeps the remaining official-package blocker explicit and
reproducible for operators. The
`2026-06-26T10:38:15+00:00` bounded live recheck with
`--timeout-secs 3 --max-bytes 512` still timed out across all eight recorded
official download URLs with `0` downloaded bytes and summary digest
`43b0786d772fd045d645160308ac20ed95aa3c5e9bcdea5625d4d31fe5798448`.
Direct operator-canary, rail-gateway, and audit-notary policy flags must also
be real booleans before canary config, rail inbox, or audit export loading, so
programmatic callers cannot use non-boolean values to alter plan-only,
discovery, insecure-HTTP, default-profile, legacy-message, or missing-source
behavior.
Direct repeatable path and endpoint arguments now reject bare strings and
non-path/non-string entries before loading trust bundles, receipts, evidence
summaries, readiness summaries, or notary exports, so programmatic callers
cannot accidentally split selector strings into character paths or endpoints.
Direct scalar path arguments now normalize string/path-like values and reject
invalid path objects with label-only errors before loading XSD manifests, trust
bundles, canary configs, rail inboxes, audit exports, evidence summaries, or
readiness summaries, and direct rail gateway Torii URLs must be real strings
before URL validation or inbox loading. Direct evidence/readiness
provider/environment/default-profile context values must also be real strings
before summary loading. Missing direct `argparse.Namespace` attributes for
required ISO config/inbox/export paths, policy booleans, evidence/readiness
context strings, freshness budgets, canary output limits, rail payload limits,
and notary response limits now fail through the same controlled validators
before file discovery, summary loading, network work, or child execution
instead of surfacing raw `AttributeError`s; omitted optional trust source
freshness budgets and rail message selectors now take the same defaults as
their CLI forms.
Direct XSD fixture verification and trust-bundle verification `run(args)` calls
also mirror their CLI path-smuggling guards for manifest/profile-catalog,
bundle, profile-output, and summary-output paths before manifest or bundle
loading.
Direct XSD fixture verification also normalizes license-header whitespace before
matching restricted Standards Editor redistribution phrases, so line-wrapped,
tab-separated, or zero-width format-character-obfuscated restricted terms cannot
be archived as redistributable XSD evidence.
Direct canary runner, rail-gateway adapter, and audit-notary adapter `run(args)`
calls now mirror their CLI path-smuggling guards for config/summary,
inbox/message/receipt/token, and export/receipt/token paths before config,
inbox, export, or network loading.
Rail-gateway route construction also rechecks the fixed Torii endpoint map and
fails closed with a label-only unsupported-message diagnostic if an internal
caller bypasses sidecar validation before URL construction.
Receipt-verifier endpoint reconstruction now also rechecks the supported
receipt-kind boundary and fails closed with a label-only unsupported-kind
diagnostic if an internal caller bypasses receipt-kind validation before
summary evidence is assembled.
Evidence-gate receipt metadata comparison now uses the same label-only
unsupported-kind fallback if internal compact receipt entries bypass
receipt-kind validation before direct-archive/canary metadata binding.
Final readiness archive/canary receipt metadata replay mirrors that guard and
turns an unsupported internal compact receipt kind into a structured metadata
blocker instead of comparing only generic receipt fields.
Live rail/notary diagnostic override flags are also pinned by non-dry-run
coverage so unused local overrides fail before submit/publication and before
receipt directories are created.
Dry-run canary receipt evidence now carries `stage_dry_run` through evidence
and readiness replay, and direct receipt archives may be partial only when
stage/digest binding proves the omitted receipt kind belongs to a partial or
dry-run canary path rather than to an executed canary receipt. Final readiness
also replays that archive digest binding from compact summaries, so forged
partial/dry-run policy flags cannot hide a missing archive receipt for a full
executed canary. Direct archive coverage and final readiness archive/canary
receipt blockers report only receipt indexes and mismatch classes for missing,
unreferenced, relabelled, or metadata-drifted receipt digests, without printing
raw `receipt_sha256` values.
Live rail-gateway `--torii-base-url` and audit-notary `--endpoint` flags now
also reject missing, empty, flag-looking, or leading-dash URL values before
argparse parsing.
Those URL value preflights also reject raw control characters, Unicode
characters, surrounding whitespace, and non-URL-shaped secret-looking material
before unrelated required file or directory inputs can mask the bad URL.
Direct ISO numeric CLI preflights now reject malformed, empty, flag-looking, or
secret-looking numeric values before argparse can echo operator-provided input.
They also require printable ASCII before Python's numeric parsers can accept
Unicode digit confusables as operator budgets, timeouts, or byte limits, and
they now require canonical decimal spellings before argparse conversion, so
`.5`, `01`, `1e01`, `1.`, `+1`, `000512`, `512.0`, signed-zero aliases, and
overflow exponents cannot be accepted as operator timeout, freshness-budget, or
byte-cap values. The pending XSD source probe applies the same raw preflight
for timeout and byte-limit flags before argparse can reinterpret negative
numeric spellings as options.
Pending XSD source probe summaries also omit unsafe remote `Content-Type`
metadata before evidence emission and only record real integer 100-599 HTTP
status values, so hostile headers or Python boolean/int aliases cannot become
digest-bound operator evidence; final readiness replays the same omission
policy before accepting archived probe rows.
Network failures in those probe summaries now use a stable `NetworkError` role
instead of raw Python exception class names.
All ISO operator entry points now also reject secret-looking raw CLI tokens
before argparse can echo unknown arguments; the scanner covers bearer tokens,
private keys, passwords/passphrases, API/access/session keys, client secrets,
cookies, and Iroha signatures.
Unknown raw CLI tokens with ASCII control characters are rejected by the same
preflight layer with label-only diagnostics before argparse can echo terminal
control bytes.
Unknown raw CLI tokens must also be printable ASCII, preventing Unicode
confusable option spellings from reaching argparse diagnostics.
Those entry points also reject the `--` argument terminator because the ISO
operator CLIs do not accept positional operands; raw secret, boolean, path,
context, and numeric preflights all fail closed before trailing tokens after
the terminator can bypass scanning and later be echoed by argparse.
The same CLIs disable argparse long-option abbreviation, so partial spellings
such as `--summary-ou` or `--receipt-di` cannot bypass exact preflight flag
matching or be accepted as production options.
Secret scanning now also checks repeated percent-decoded forms and
separator-normalized identifier forms, including Unicode format and mark
characters that are removed or treated as separators and Unicode compatibility
forms that normalize to ASCII labels, so encoded, double-encoded,
zero-width-obfuscated, combining-mark-obfuscated, fullwidth/compatibility-form,
or repeated/collapsed whitespace, dot, underscore, hyphen, slash, and backslash
secret-looking material is rejected in CLI paths, unknown JSON keys, recursive
JSON values, compact summary paths, and remote response previews/errors without
echoing the decoded material. Live rail/notary successful response bodies now
fail before receipt write when their preview would contain invalid UTF-8 or
non-ASCII text, while failed-response preview emission remains
printable-ASCII-only, folds accepted newline/tab text to one line, and
preserves the exact response-body digest; archived receipt replay rejects
multiline or non-ASCII preview/error text. URL transport receipts now
record fixed rail/notary error labels instead of upstream reason strings, and
archived failed receipt errors must match those labels or the matching
`HTTP <status>` response label.
ISO URL path validators now also reject secret-looking key/value material in
literal, percent-encoded, or double-encoded path segments before live network
delivery, archived evidence ingestion, or readiness rollup.
They also reject raw URL delimiter characters in path segments, matching the
existing encoded-delimiter rejection for `:`, `@`, `[`, and `]`.
URL paths must also remain printable ASCII: raw Unicode path characters and
percent-encoded non-ASCII bytes are rejected before live submission, archive
replay, or release-readiness rollup.
Local path, raw CLI, summary-path, artifact-path, and URL-path validators now
also reject narrow identifier-style secret path material such as
`token-*-secret` and strong key markers without treating ordinary token-file
operator paths as secret-bearing by name alone.
Local artifact path validators now also reject raw URI/drive prefixes,
malformed percent escapes, and percent-encoded control/space, dot/separator,
semicolon, URL delimiter, and percent bytes across raw CLI, output, runbook,
XSD, trust, receipt, evidence, and readiness paths before those values are
expanded, replayed, or archived. Direct local CLI/output/artifact path strings
are capped at 4096 characters with label-only diagnostics before secret
scanning, filesystem expansion, summary emission, child command construction, or
archive replay.
Summary/profile outputs and rail/notary receipt output directories now also
reject destinations under checked-in `fixtures/iso20022/` artifacts during
run-level preflight and again before creating parents or writing temporary
output files, so bad destinations fail before input loading, child execution,
network delivery, or accidental emission into the repository fixture corpus.
Live rail/notary adapter runs also reject inbox/export roots under checked-in
`fixtures/iso20022/` artifacts before directory discovery, anchor parsing, XML
fixture parsing, child execution, or network delivery.
Canary runbook artifact paths now use the same narrow local-path scanner,
including non-whitespace control-character rejection, before plan-only output
or child command construction, while bearer-token file paths remain runtime
secret-file references and are redacted in planned commands.
Live canary execution also rejects config/stage/explicit verifier receipt paths
under checked-in `fixtures/iso20022/` artifacts before child commands are
launched, while checked-in runbook templates remain valid for `--plan-only`
validation.
Evidence replay mirrors that rule for executed and planned canary child-command
`--inbox-dir`, `--message`, `--export-dir`, `--receipt-dir`, and `--receipt`
values so forged archived commands cannot reintroduce repository fixtures.
Direct receipt verification and its parent evidence gate also reject `--receipt`
and `--receipt-dir` selectors under checked-in `fixtures/iso20022/` artifacts
before receipt discovery, child verifier launch, file loading, or digest-bound
summary construction. Direct receipt-verifier `run(args)` calls now also mirror
the CLI path-smuggling preflight for those selectors before discovery or file
loading, and require direct policy flags to be real booleans before receipt
selectors are discovered or loaded.
Raw evidence verification now also rejects `--canary-summary` and
`--trust-summary` inputs under checked-in `fixtures/iso20022/` artifacts, and
final readiness blocks forged compact XSD/evidence/canary/trust summary paths
that point back to those artifacts.
Canary child stdout/stderr previews now also reject identifier-style
secret-looking material and unsafe control characters, including Unicode format
controls such as bidi overrides, before summary emission.
XSD `xmllint` diagnostics now redact identifier-style secret-looking validator
output, key/value secret material, unsafe control characters including Unicode
format controls, and non-ASCII material before schema-validation errors are
reported.
Direct evidence receipt-verifier diagnostics now redact key/value and
identifier-style secret-looking stderr plus unsafe control characters before
reporting child verifier failures. ISO input readers, input-directory checks,
ancestor inspection preflights, alias-comparison helpers, and summary/receipt
writers sanitize raw OS `strerror` text and hostile `strerror` accessor
failures, including reader, input-directory, receipt-directory, receipt
source-file, ancestor, output parent/leaf, and alias
`lstat()`/`stat()`/`exists()`/`is_symlink()` inspection failures, output parent
creation failures, rail/notary receipt-directory inspection and creation
failures, input runtime/type/value handle failures, descriptor-close cleanup
runtime/type/value failures plus temporary write/fsync/replace runtime/type/value
failures and cleanup unlink/close runtime/type/value failures, before
diagnostics, preserving
ordinary short ASCII errors while collapsing path-like, secret-looking,
control-bearing, non-ASCII, oversized, or
unreadable error text to `I/O error`. Archived receipt
previews/errors now also reject non-ASCII text before replay. ISO JSON
unknown-key scanners now also hide control-bearing key names, including names
with Unicode format controls, across
live adapters, operator receipts, trust bundles, XSD manifests/catalogs, and
archive rollups, while recursive archive/operator JSON scans and receipt
source-sidecar replay reject unsafe control characters, including Unicode format
controls, in string values before field-specific replay.
Timestamp helpers for direct trust-bundle `source.retrieved_at`, operator
evidence `verified_at`/canary/trust-source windows, receipt `submitted_at` and
`published_at`, and final readiness compact timestamps also reject Unicode
format controls locally, so timestamp parsing cannot preserve bidi or zero-width
text even if validator call order changes. Parseable timezone-aware timestamps
must also use the canonical evidence shape
`YYYY-MM-DDTHH:MM:SS.ffffffZ` (or the equivalent form with a numeric offset),
rejecting space separators,
lowercase separators, comma fractions, compact offsets, and the unknown-offset
`-00:00` spelling while preserving the existing malformed/missing-timezone
diagnostics.
Trust-bundle, XSD fixture, operator-evidence, and final production-readiness
required/optional string helpers now also reject Unicode format controls in
direct source, source URL, policy, trust-material label, manifest,
profile-catalog, archive, rail-message ID, reviewed reason, and string-list
values, matching the recursive unsafe-control scan that catches those markers
during CLI bundle/loading paths. Live rail/audit adapter raw CLI, URL, output
path, bearer-token path, and rail message-path helpers now share that
control-character policy with XSD, operator-evidence, and final readiness raw
CLI token, numeric/context/profile value, local path, source-path,
fixture/schema relative-path, receipt-kind, child-command, stage-name, compact
timestamp, and HTTP URL helpers. Receipt-verifier raw CLI, receipt path, and
HTTP URL helpers plus canary raw CLI, URL, output/runbook path, runbook string,
and numeric preflight helpers now use the same policy too. Trust-bundle raw
CLI, output path, and source-age integer preflight helpers also reject Unicode
format controls at the raw guard layer. ISO operator canary, trust-bundle,
operator-evidence, and final production-readiness replay now also require
`provider` and `environment` context labels to be canonical lowercase IDs with
hyphen separators, rejecting uppercase, slash-bearing, and
leading/trailing-hyphen labels before they can label archived production
evidence. Executed canaries, operator-evidence archival, and final readiness
replay also reject exact placeholder/non-production context IDs such as
`example`, `sample`, `template`, `ci`, and `test`, plus hyphen-tokenized
placeholder aliases such as `example-bank`, `sample-preprod`, and
`test-preprod`, including digest-correct forged canary, evidence-policy, and
compact trust-profile summaries.
ISO URL port parser failures now report only label-level invalid-port
diagnostics instead of including parser exception text that may contain the raw
operator-provided port string.
ISO JSON and XML parser failures now likewise report category-only diagnostics
without appending parser location text across trust bundles, XSD manifests and
profile catalogs, rail/notary source files, canary runbooks, receipts,
evidence summaries, and readiness summaries.
Accepted printable external diagnostics from XSD `xmllint` and direct
receipt-verifier stderr are folded to one line before stderr composition, after
the existing secret, path, control, and non-ASCII redaction checks.
Archived executed rail/notary canary stdout previews must parse as live adapter
summary JSON with zero failures, stage-scoped receipt paths, and counts matching
submitted messages or published anchors/endpoints; rail stdout must report a
single submitted message when the command used explicit `--message`, notary
stdout `endpoint_count` must match the executed command's repeated `--endpoint`
flags, and `published_anchors` must stay at one unless the command used
`--all`; notary receipt summaries must also use `latest.notary.json` without
`--all` and digest-addressed `anchors/<index>.notary.json` with `--all`, so
printable logs, dry-run summaries, inflated endpoint counts, forged
multi-message claims, forged multi-anchor publication claims, or swapped
latest/all-anchor modes cannot stand in for production child-stage evidence.
The compact canary evidence now carries sanitized `stage_command_modes`
(`rail_uses_message`, `rail_submitted_message_count`, `notary_uses_all`,
`notary_endpoint_count`, and `notary_published_anchor_count`) so final
production-readiness replay can reject forged compact summaries whose rail
single-message, rail submitted-message-count, notary all-anchor, notary
endpoint-count, or notary published-anchor-count proof no longer matches the
compact receipts without persisting raw commands or endpoint URLs.
Canary verify-stage receipt-verifier stdout must also keep receipt paths covered
by the verify command's `--receipt-dir`/`--receipt` selectors, with explicit
`--receipt` files present in the captured summary, before archive replay can use
the receipt metadata.
Executed rail/notary adapter stdout receipt path sets must match the
receipt-verifier summary paths for the same receipt kind, preventing a canary
from proving one producer output set and replaying a different verifier output
set under the same receipt directory.
Notary and receipt replay clean metadata strings from audit indexes, persisted
records, nullable context/metadata/history fields, and rail sidecars are capped
at 4096 characters with label-only diagnostics before mismatch, source replay,
or sidecar validation can retain oversized operator evidence.
Direct trust-bundle generic strings/OID lists, XSD profile-catalog generic
strings/lists, canary runbook generic strings/lists, and evidence replay clean
strings/lists plus production-readiness compact clean strings/lists now share
the same 4096-character label-only cap before trust preflight, XSD profile
validation, runbook planning, archive validation, or readiness replay can
preserve oversized metadata; embedded trust/profile DER base64 keeps its
separate decoded-size guard.
Production-readiness replay also reports summaries generated from the checked-in
`fixtures/iso20022/xsd/fixture_manifest.json` corpus as
`xsd.repository_fixture_manifest` blockers by default, and rejects XSD summary
input files under checked-in ISO fixture coordinates as
`xsd.repository_xsd_summary` blockers. Direct XSD `--profile-catalog` inputs
under checked-in `fixtures/iso20022/` artifacts fail before manifest loading,
and archived `profile_catalog.path` values under those artifacts replay as
`xsd.repository_profile_catalog` blockers. The local `--allow-reviewed-xsd-gaps`
diagnostic mode can only downgrade reviewed missing-schema, schema-only,
blocked-source, or pending-source gap warnings, never repository fixture
manifest blockers or a truly unreviewed profile-catalog-only schema gap;
advertised profile-version gaps remain blockers unless the exact message
definition also has reviewed missing-schema, schema-only, blocked-source, or
pending-source evidence. XSD preflight summaries now carry `ok: true` only when
all strict schema-backed, fixture-backed, profile-backed, and XML schema
validation checks pass against non-repository material with no reviewed or
pending gaps; repository fixture manifests and diagnostic reviewed-gap summaries
record `ok: false`, and final readiness recomputes the verdict before accepting
the summary. Cross-summary XSD material replay checks also include
pending-source message IDs, official catalogue/source references, and bounded
direct download URLs, so one operator package cannot satisfy another by
replaying the same pending-source record. Pending-source
submitting-organisation labels are also replayed as canonical ISO-style
organisation metadata: bounded printable ASCII, comma-space-separated names, no
URL/contact delimiters, no semicolon path parameters, no placeholder names, and
no path-like slash smuggling.
Pending-source message names are unique within each XSD summary and across
cross-summary replay, so one official message name cannot be relabelled under a
different pending message definition or download URL.
The live pending-source probe also treats response cleanup as best-effort:
non-callable context hooks normalize to `NetworkError`, while context-exit and
close or close-accessor failures are ignored after bounded sample classification
so cleanup-only failures cannot replace a valid reachability result or archive
exception text. HTTP-error response objects are also closed best-effort before
their bounded error row is archived. Opener/read runtime, type, or value
failures likewise normalize to `NetworkError` without retaining exception text.
XSD summary version 3 now also carries a recomputed
`missing_profile_schema_message_ids` aggregate with unique missing message
definitions, per-message profile-version counts, and reviewed-gap
classifications; final readiness replays the raw gap evidence and blocks forged
aggregate counts or classifications.
Blocked schema-source evidence now also requires candidate SHA-256 values to
stay disjoint from checked-in schema and fixture XML digests, and final
readiness replays those overlaps as dedicated blockers so a forged
blocked-source row cannot reuse already accepted schema or fixture bytes as gap
evidence for another profile version. Final readiness also rejects compact
summaries whose fixture digest reuses a checked-in schema digest, or whose
profile-catalog source/embedded-JSON digests reuse schema, fixture,
blocked-source, or each-other digest roles.
Direct strict XSD preflight diagnostics now report reviewed missing-schema or
schema-only gap classes without echoing the reviewed rationale text, and final
readiness XSD gap blockers/warnings copy only path and message-definition labels
instead of archived free-form gap reasons.
The rail gateway adapter, receipt verifier, direct evidence verification, and
final readiness also reject unsupported receipt-kind and rail-message-type
values with label-only diagnostics, including stage receipt-kind mismatch
blockers that no longer print the unexpected archived kind. Final readiness
normalized receipt output also scrubs unsupported or malformed rail
`message_type`/`profile`/`rail_message_id`/`source_path` values and malformed
or unsupported notary `anchor_sha256`/`index_sha256`/`anchor_path`/`store_dir`/
`index_path`/`record_count` values to `"unsupported"` before public JSON is
emitted. Unsupported canary stage-name diagnostics are also label-only and no
longer echo the unexpected stage label. Direct evidence replay and final
readiness trust blockers now keep
non-production or unsupported embedded-signature policy values out of
diagnostics as well, and final readiness normalized trust profile output scrubs
non-production/unsupported policies plus placeholder trust-source
authority/version/URL values to `"unsupported"` before emitting release JSON.
Unsupported summary `version` values in XSD, pending-probe, canary, receipt, and
trust summaries are similarly normalized to `"unsupported"` before final
readiness JSON is emitted.
Archived provider/environment context values from evidence policy, canary, and
trust profile summaries are likewise normalized to `"unsupported"` when they do
not match the release context.
Release and archived freshness budgets are capped at 36,500 days, and weaker
archived evidence/trust source budgets are normalized to `"unsupported"` in
final readiness JSON.
Blocked compact trust verifier override flags, receipt verifier `allow_*`
policy flags, and `require_source_files=false` are also normalized to
`"unsupported"` in final readiness JSON.
Direct evidence replay also rejects unsupported or
local-only child command flags without echoing the archived flag text.
Operator evidence verification now rejects canary summaries whose
`config_path` still points at checked-in
`fixtures/iso20022/operator_canary/` runbook templates, and final readiness
replays the compact path as an `evidence.repository_canary_config` blocker if a
forged aggregate summary reintroduces it.
Operator evidence verification also preserves each trust-bundle source path in
the compact trust profile and rejects paths under checked-in
`fixtures/iso20022/trust_bundles/` templates; final readiness replays forged
compact paths as `trust.repository_trust_bundle` blockers.
Rail receipt verification now preserves the source XML path as compact
`source_path` evidence and rejects paths under checked-in
`fixtures/iso20022/*.xml` fixtures; evidence and final-readiness replay reject
forged compact receipt source paths that point back at repository XML fixtures,
and the rail gateway adapter now rejects checked-in ISO XML fixture inputs
before network delivery or receipt output.
Notary receipt verification now also preserves compact `anchor_path`,
`store_dir`, and `index_path` evidence, requires the anchor path to stay either
`latest.notary.json` or `anchors/<index_sha256>.notary.json`, requires the
index path to remain the `messages.index.json` peer of that anchor export, and
evidence/readiness replay includes all three values in direct archive metadata
binding so a copied summary cannot strip or drift the operator notary preimage
path, source store, or exported audit index while retaining matching digests;
raw receipts reject notary anchor/store paths under checked-in
`fixtures/iso20022/` artifacts, and compact replay rejects
anchor/store/index paths under those artifacts. The audit notary adapter now
rejects checked-in notary anchor/store fixture inputs before network delivery or
receipt output.
ISO URL host validators now reject secret-looking hostname labels and
non-ASCII raw host labels, and non-port URL parser failures use label-only
diagnostics before malformed URL text can be echoed by parser exceptions.
XSD profile-catalog validation now recursively rejects secret-looking strings
and identifier-style values before rail, signature-policy, reference-dataset,
address-mode, profile-id, or version diagnostics can echo catalog-provided
values.
Profile-catalog enum and list values such as rails, embedded signature
policies, required reference datasets, structured-address modes, and business
services must also be printable ASCII before unknown-value diagnostics or
summary recording can preserve Unicode-confusable spellings.
XSD profile-catalog rail, embedded-signature policy, reference-dataset, and
structured-address-mode unknown enum diagnostics now stay label-only instead of
echoing operator-supplied enum values.
XSD profile-catalog duplicate profile IDs, family aliases, concrete version
mismatches, duplicate concrete versions, and strict schema-backed gate failures
also stay label-only instead of echoing operator-supplied profile/version
strings; final readiness replay mirrors that policy for concrete version
mismatches and skipped-family alias mismatches.
XSD source filename, schema `targetNamespace`, schema payload-root, XML fixture
namespace/payload-root, unknown schema-reference, and linked schema/fixture
mismatch diagnostics now stay label-only instead of echoing manifest, schema, or
fixture-provided values.
XSD document/payload complex-type cardinality and direct-child diagnostics now
stay label-only instead of echoing concrete type names parsed from schemas.
XSD blocked-source already-checked-in and missing-gap diagnostics also stay
label-only in the fixture verifier and final readiness blockers, so forged
candidate message definition IDs are not echoed while normalized blocked-source
evidence remains public.
XSD manifest schema and fixture `payload_root` values now reject secret-looking
material and non-ASCII confusable spelling before namespace/root mismatch
diagnostics can echo manifest-provided payload names.
Checked-in XSD `targetNamespace` attributes now also reject secret-looking
material and non-ASCII material before schema namespace mismatch diagnostics can
echo schema-provided attribute values.
XSD and XML payload identifiers, XML fixture namespace/name identifiers, and
schema-root attribute names now use label-only secret-looking or printable-ASCII
diagnostics instead of echoing schema-provided names or namespace URIs. These
schema and fixture identifiers also reject overlong ASCII spellings before
schema/root mismatch diagnostics can print them.
XML fixture contents are scanned before optional `xmllint` validation, and
secret-looking, control-bearing, or non-ASCII validator output is redacted before
it can be reflected in XSD preflight diagnostics.
Secret-looking field-name markers now also normalize hyphenated
`private-key` and underscore-form `x_iroha_signature` spellings across ISO
validators, and receipt JSON secret-field checks recurse through nested objects
and arrays before receipt semantics are evaluated.
All ISO JSON duplicate-key hooks now report only that a duplicate key exists,
without echoing the repeated key name.
ISO JSON non-finite numeric constant hooks likewise report only the constant
class without echoing `NaN`/`Infinity` spellings. XSD manifests/profile
catalogs, rail sidecars, notary anchors/indexes/record sources, direct receipt
files, trust bundles, canary runbook, operator-evidence summary/stdout, and
final readiness input JSON number tokens now reject non-canonical numeric
spellings, including exponent-normalized floats, negative-zero integers/floats,
and overflow exponents that would parse as non-finite floats, before Python can
normalize fixture metadata, live adapter metadata,
notary material, receipt, trust-material, stage-budget,
receipt-verifier-summary, or release-summary values.
All ISO canonical digest encoders and summary/receipt/profile JSON writers now
serialize with `allow_nan=false`, so internal non-finite `NaN`/`Infinity`
values fail before any digest-stamped evidence or stdout summary can be
emitted.
Unknown JSON field names are rejected with label-only unknown-key diagnostics,
including ordinary unknown-field typos, secret-looking markers, non-ASCII,
overlong, too numerous, or collectively oversized names. This prevents
operator-supplied schema keys from being reflected in errors.
Direct ISO boolean CLI flags reject attached `--flag=value` spellings and
separate non-option values before argparse can echo the value or reinterpret
the option.
Evidence and production-readiness context flags reject missing, empty,
flag-looking, leading-dash, secret-looking, or non-ASCII
provider/environment values before argparse, summary loading, or mismatch
diagnostics can reflect them. The evidence gate also rejects leading-dash
`--default-rail-profile` values before argparse can reinterpret them as
options. Expected provider/environment mismatch diagnostics now stay label-only
and do not print observed or expected context values.
Canary runbook provider/environment labels now reject non-ASCII and
secret-looking identifier-style strings before plan-only output or executed
summaries can preserve them.
Trust-bundle `--max-source-age-days` now rejects missing, empty, flag-looking,
malformed, or secret-looking freshness budgets before argparse or bundle reads.
Trust-bundle profile IDs, rails, environments, embedded signature policies,
source authority/version strings, DER labels, and recursively scanned field
names reject secret-looking identifiers before trust summaries or profile
overrides can persist them, and trust-bundle environment context, embedded
signature policies, and source authority/version provenance must be printable
ASCII before summary emission.
Trust-bundle SHA-256 pins and declared DER digests now reject all-zero
placeholders, and those digests plus certificate policy OIDs also reject
secret-looking marker strings before canonical SHA/OID diagnostics.
Trust-bundle local-audit overrides now reject unused
`--allow-record-only`, `--allow-insecure-source-url`, and
`--allow-synthetic-der` flags unless a verified bundle actually carries matching
non-production policy, insecure source URL, or synthetic DER evidence; private
synthetic-DER usage is stripped before summary emission.
Archived evidence and readiness rollups apply the same no-echo identifier check
to compact canary provider/environment fields, evidence policy context, trust
profile IDs/rails/environments, trust embedded-signature policies,
profile-override policies, trust source authority/version strings, and archived
trust DER labels before release summaries can preserve those values. Archived
provider/environment and trust-profile environment checks now reject both exact
placeholder IDs and hyphen-tokenized placeholder aliases such as `example-bank`,
`sample-preprod`, and `test-preprod` without echoing the submitted value.
Archived trust embedded-signature policies and source authority/version
provenance also
reject non-ASCII confusable spellings before readiness blockers or evidence
summaries can preserve forged policy or provenance values.
Direct trust-bundle material and archived evidence replay also require DER labels
to be printable ASCII before summaries can preserve Unicode-confusable material.
Final readiness trust-profile source, pin, policy, and revocation-material
blockers now stay label-only instead of echoing archived profile IDs.
Archived evidence and readiness SHA-256 fields, including trust bundle digests,
profile-override pins, and receipt payload/anchor/index digests, reject the same
markers before digest-shape diagnostics or blockers can preserve them.
Rail sidecar `profile` and `rail_message_id` identifiers, plus archived rail
receipt `profile` and `rail_message_id` values, now reject secret-looking
identifier-style strings before network delivery, receipt emission, receipt
verification, or receipt-summary rollup.
Rail sidecar `message_type` values must also remain printable ASCII and match
the canonical lowercase ISO family-id shape before unsupported-type diagnostics
can print a short unsupported family value. Rail sidecar
`message_type`/`payload_sha256` values plus archived rail receipt
`message_type` values apply no-echo secret-looking checks before
unsupported-type, digest-mismatch, or receipt-summary diagnostics can preserve
operator-provided marker strings; payload digest mismatches now report only the
field label, direct receipt source-XML payload mismatches no longer echo local
XML paths, required source XML/sidecar presence checks likewise report only the
missing field, missing notary anchor/audit-index/audit-record source checks
report only the missing role, latest-anchor digest-peer failures avoid derived
peer paths, notary anchor and digest-addressed peer symlink diagnostics avoid
embedded source paths, exported audit-index mismatch diagnostics avoid exported
index paths in both receipt verification and audit-notary preflight, live rail
gateway sidecar JSON/XML read-limit/payload-digest mismatch diagnostics avoid
operator inbox paths before network delivery, malformed live notary anchor JSON,
exported-index JSON, store-directory, and persisted record-source diagnostics
avoid operator export/store paths before network delivery, audit-notary
`--export-dir` discovery and empty `--all` anchor discovery failures now use
role labels instead of local export paths before network delivery, audit-notary
latest-anchor digest-peer missing/mismatch failures now use the anchor source
role instead of derived local peer paths before network delivery, audit-notary
receipt-output directory and preflighted receipt-file target failures now use
role labels instead of local output paths before network delivery, malformed rail
source sidecar JSON and source XML read-limit diagnostics use
receipt-relative labels instead of local source paths, and rail gateway
`--inbox-dir` discovery failures now use the `inbox_dir` role label instead of
local operator inbox paths before network delivery. Rail gateway receipt-output
directory and preflighted receipt-file target failures now use role labels
instead of local output paths before network delivery. Rail sidecar
`payload_sha256` values reject all-zero placeholders before network delivery.
Top-level receipt file read, malformed JSON/UTF-8, object-shape, version,
receipt-kind, symlink-ancestor, size-limit, and `--receipt-dir` discovery
failures now use indexed receipt labels instead of local operator receipt paths,
while accepted verifier summaries still preserve receipt paths for audit
evidence.
Direct receipt status, timestamp, endpoint policy/digest, response metadata, and
rail source replay diagnostics now also use indexed receipt labels instead of
local receipt paths.
Rail receipt `message_type` syntax now uses ASCII-only digits and the direct
receipt verifier, evidence replay, readiness replay, and XSD profile catalog
all reject Unicode digit confusables before unsupported-type diagnostics.
XSD profile-catalog enum values such as rails, embedded signature policies,
reference datasets, and structured-address modes now report unknown values by
class without echoing operator-supplied enum values.
Profile-catalog profile IDs, family aliases, concrete version IDs, skipped
family aliases, and strict missing-schema-version failures now use label-only
diagnostics for duplicate, mismatch, and schema-backed gate errors in both
direct XSD verification and final readiness replay.
Profile-catalog business-service entries are capped before the catalog can
emit or archive overlong service identifiers.
XSD profile-catalog `message_def_id` and version entries use the same ASCII-only
digit policy before missing-schema or skipped-version diagnostics can classify
Unicode digit confusables as concrete ISO message IDs.
Evidence and readiness archive/canary receipt kind, filename, and metadata
mismatch blockers no longer print receipt kind values, receipt leaf names, or
full metadata tuples, so invalid marker material is not reflected by follow-on
consistency diagnostics.
Trust-bundle preflight, evidence replay, and production-readiness compact trust
profile IDs, override IDs, embedded signature policy strings, and trust-source
authority/version/timestamp provenance are capped before trust diagnostics can
print or archive them.
Top-level trust-bundle read, parse, symlink-ancestor, and semantic validation
failures now use bundle-index labels instead of local operator bundle paths,
while successful summaries still preserve the path for audit evidence.
Top-level XSD fixture manifest and profile-catalog read, parse, raw-string,
symlink-ancestor, and size-limit failures now use input role labels instead of
local operator manifest/catalog paths, while accepted summaries still preserve
the paths for audit evidence.
Manifest-referenced XSD schema and XML fixture read, parse, DTD/entity,
restricted-terms, structural-validation, symlink-ancestor, and size-limit
failures now use manifest entry labels instead of resolved local source paths,
while accepted summaries still preserve the manifest-relative paths for audit
evidence.
Receipt verifier, evidence, and readiness `receipt_kind` values reject
secret-looking identifier-style markers and non-ASCII confusable spellings before
unsupported-kind diagnostics or blockers can preserve forged archive values.
Archived canary stage names in evidence and readiness rollups also reject
secret-looking identifier-style markers and non-ASCII confusable spellings before
unsupported-stage, ordering, or stage-window diagnostics can preserve forged
values.
The live rail-gateway, audit-notary, canary, and XSD fixture tools also reject
secret-looking key/value material in local output paths before those paths can
be persisted into receipts or archived summaries.
ISO text output writers for rail/notary receipts, trust profile JSON, XSD
summaries, canary summaries, evidence summaries, and readiness summaries now
report parent, leaf, and temporary-file failures with role labels instead of
copying local output paths into stderr.
Explicit rail `--message` containment, XSD manifest-relative containment, and
canary runbook symlink-escape containment failures also report stable role
labels instead of resolved operator roots.
Canary runbook config read, parse, symlink-ancestor, and size-limit failures now
use the `config` label instead of local operator runbook paths before planning
or child command execution.
Operator evidence canary/trust summary read, parse, symlink-ancestor,
size-limit, and semantic validation failures now use indexed summary labels
instead of local archive paths, while accepted compact evidence still records
the summary paths for audit traceability.
Production readiness XSD/evidence summary read, parse, symlink-ancestor, and
size-limit failures now use indexed summary labels instead of local release
input paths before blocker replay; accepted summaries and blocker locations
still preserve paths for audit traceability.
The receipt verifier scans raw receipt strings for secret-looking material
before version or receipt-kind dispatch, so malformed receipt kinds cannot echo
runtime tokens in unsupported-kind diagnostics.
Recursive trust-bundle, receipt, evidence, and readiness secret-material
scanners now report label-only forbidden-field failures, and receipt value
secret checks no longer echo the receipt field name that carried the rejected
material; those recursive scanners use the same expanded secret marker set for
secret-looking field names and values.
Rail and notary adapters reject successful remote response bodies with token,
password, private-key, cookie markers, or unsafe control characters before
receipt persistence, redact failed remote response previews and receipt errors
when upstreams return those markers or unsafe control characters, cap transport
error strings at 4096 printable ASCII characters before receipt emission,
normalize non-standard, malformed, or oversized remote HTTP statuses into failed
receipts with `status_code=null` and label-only invalid-status errors, and
normalize byte-like response bodies by byte length before hashing or previewing
so wide-format `memoryview` responses cannot bypass configured response caps.
Non-byte response bodies still become stable transport-failed receipts without
echoing the value. The adapters also convert transport-open exceptions/failures,
normal/HTTP-error response close
failures, normal/HTTP-error response-body read exceptions/failures, and
malformed non-byte remote response bodies into bounded failed receipts with
stable messages. The
receipt verifier rejects successful archived receipts carrying the redacted
response marker plus archived previews/errors containing the same marker set or
unsafe control characters.
Audit-notary anchor publication now also rejects secret-looking audit-index
identifiers plus persisted record-source string values with secret-looking
material or Unicode format controls before publication or source replay can
archive them, and direct receipt verification mirrors that rule when replaying
archived notary sources.
Archived receipt source paths, including rail XML/sidecar paths, notary anchor
paths, and notary store directories, now reject narrow secret-looking
identifiers, URI/drive prefixes, and percent-encoded path smuggling before
missing-source or mismatch diagnostics can echo them.
Malformed notary source replay diagnostics, including anchor JSON,
exported-index JSON, store-directory, symlinked store-directory ancestor, and
persisted record-source failures, now use receipt-index/source labels instead
of copying local receipt/archive/store paths into stderr.
Live rail sidecars now run the same recursive secret-material scan on known
fields before unsupported message type, profile, payload digest, or
rail-message-id validation can echo operator-provided values. Archived receipt
verification mirrors the unsafe-text policy when replaying source sidecar
`profile` and `rail_message_id` fields.
Duplicate record, list, digest, OID, archived receipt-reuse, and trust-material
diagnostics now report field/index labels without echoing the rejected duplicate
value.
Operator evidence verification and final readiness also treat compact notary
`anchor_path`, `anchor_sha256`, `index_path`, and `index_sha256` values as
receipt source material within each canary or archive receipt summary, so
relabelled duplicate notary anchors or indexes cannot satisfy readiness under
fresh receipt paths/digests. Reusing the same notary `store_dir` within one
summary remains allowed for legitimate multi-anchor publication.
Rail-gateway and audit-notary bearer-token files now reject Unicode format
controls in decoded token contents, and token-file failures report the credential
input label instead of echoing runtime token file paths.
Local ISO source and overlap corridor checks now also wrap `Path.resolve()`
failures for XSD manifest roots and schema/fixture paths, trust/evidence/
readiness summary inputs, canary output/artifact/config/verify receipt paths,
rail sidecar peers, receipt duplicate detection, rail message/receipt-directory
overlap, and notary anchor/source overlap with role-scoped `I/O error`
diagnostics, so resolver exceptions cannot leak local operator paths before
evidence or readiness replay.
Pending official-XSD source probes now also omit hostile `Content-Type` string
metadata when normalization helpers fail, keeping otherwise reachable probes
reachable while avoiding archived header exception text.
Final-readiness replay mirrors that no-echo posture for hostile archived
pending-probe `content_type` and `error_kind` text normalization failures.
Pending-probe CLI selectors, live rail/notary adapter inputs, receipt
verification, canary, trust-bundle, XSD-fixture, operator-evidence, and
final-readiness replay also coerce accepted archived/config text values and list
entries to plain strings before later receipt-kind, stage-name, preview,
context, digest/OID, sidecar, endpoint, and secret-scan checks. Recursive JSON
object-key scans also reject non-string keys and normalize hostile `str`
subclasses before secret/control-field checks, so hostile Python objects cannot
inject exception text into diagnostics or remain in summary outputs. Unknown-key
validators also reject non-plain dict subclasses, non-string keys, and hostile
`str` subclass keys before field-set comparison; receipt and notary exact-key
checks reuse those normalized key sets for missing-key checks. Forbidden
receipt-metadata replay checks also iterate normalized receipt-entry keys
instead of direct dict-set intersections before rail/notary compatibility
diagnostics or blockers are emitted. Recursive surrogate and secret-material
scanners now also reject
non-plain JSON list/dict subclasses before calling container methods, while
normalizing hostile `str` subclasses before surrogate scans. Shared
object/array and list-valued field helpers now also require exact plain JSON
containers before semantic validation. Rail sidecars plus notary/receipt
persisted records, audit indexes, anchors, source sidecars, and top-level
receipt JSON now also reject non-plain object subclasses at their loaded-object
shape checks. Notary and receipt status-derivation helpers now also require
exact plain `change_reason_codes` lists before treating a pending record as
accepted-with-change, avoiding hostile list truthiness during replay.
Trust-bundle public summaries, operator-evidence public canary summaries, and
final-readiness public summary rendering now also copy only exact plain JSON
containers before dropping private fields or scrubbing XSD strict flags,
pending-probe response metadata, receipt summaries, receipt lists, and receipt
entries; unsupported response, insecure-endpoint, legacy-message, or
default-profile metadata is redacted only after those shape checks, so hostile
subclasses cannot run `.get`, `.items`, iteration, membership, assignment, or
deep-copy methods during output sanitization. The same public-summary copier
now redacts non-finite numeric values before JSON rendering, so internal
`NaN`/`Infinity` values cannot bypass `allow_nan=false` output guarantees.
Rail-gateway and audit-notary HTTP status predicates now also reject Python
boolean values directly, keeping direct helper calls aligned with the stricter
response-status parsers before receipt metadata is digested.
Rail/notary response-body bounding also accepts only exact built-in `bytes`,
`bytearray`, or `memoryview` containers before slicing or length checks, so
hostile subclasses cannot run during receipt digest materialization.
Pending XSD source probes and bounded child-process pipe readers for canary,
receipt-verifier, and xmllint output now apply the same exact bytes-like
container rule before sample hashing or output retention.
Repeatable direct selector inputs for pending message IDs, notary endpoints,
trust bundles, receipt selectors, evidence summaries, and readiness summaries
now require exact `list` or `tuple` containers before length checks or
iteration.
Compact evidence/readiness role collectors and XSD material-path collectors now
require exact plain nested summary objects before `.get()` or indexing can run.
Direct scalar and repeatable path arguments now accept only sanitized strings or
exact concrete stdlib `pathlib` path instances before filesystem loading, so
arbitrary path-like objects and path subclasses cannot run `__fspath__` or
`__str__` during validation.
The rail gateway direct `message` selector now follows the same rule and rejects
hostile path-like objects plus list subclasses before inbox discovery.
Operator-evidence canary command arrays now normalize child command entries to
plain strings before flag, path, URL, and redaction scans, preventing hostile
string subclasses from running during evidence validation.
All ISO operator/probe/verifier direct `main(argv=...)` calls now require exact
plain argument lists and copy hostile string subclasses to plain strings before
raw CLI preflight or `argparse` inspection, so direct API callers cannot run
overridden container or text methods at the CLI boundary. The `argv=None` path
also rejects non-plain ambient `sys.argv` containers before slicing, and parser
construction uses explicit program names instead of reading ambient
`sys.argv[0]`. Direct `run(args)` calls also require exact
`argparse.Namespace` values before any caller-provided object can service
`getattr` or `setattr`.
CLI-facing and JSON-summary numeric scalar helpers now also require exact
built-in `int`/`float` values or sanitized numeric strings before conversion,
comparison, freshness-budget, timeout, byte-limit, count, day, version, or
status-code checks, so hostile numeric subclasses cannot run `__int__`,
`__float__`, or comparison hooks during direct API or replay helper use. The
remaining file-read limits, bounded child-command output limits, child
return-code validators, verified-count summaries, freshness projections, and
public response-metadata classifiers now use the same exact built-in integer
boundary.
Operator-evidence and production-readiness direct text validators now also copy
hostile `str` subclasses to plain strings before rail-message-id, CLI context,
artifact path, timestamp, XSD source/fixture path, reviewed-gap, pending-source
URL, pending-probe text, and blocked-source restriction-marker checks.
Trust-bundle source timestamp parsing now mirrors that boundary by rejecting
non-string `source.retrieved_at` values and normalizing hostile `str`
subclasses before canonical timestamp and freshness checks.
Remaining production work still depends on operator-supplied live rail evidence,
redistributable schemas, and official trust/revocation bundles.

## Soracles follow-ups

- Add the off-chain/runtime leader scheduler and pacemaker automation for
  provider fetches and manual aggregate replacement. The MVP keeps deterministic
  committee/leader derivation and quorum checks, but does not yet schedule
  leaders at runtime.
- Wire provider rating weights into governance-approved fetch/leader scheduling
  once policy is finalised. Live provider counters now expose deterministic
  inlier-share reputation scores and clamped governance deltas, but current
  aggregation remains equal-weight median/percentile.

## FASTPQ GPU acceleration follow-ups

- Profile the sole batched Poseidon column plus Merkle-pair path on the release
  CUDA and Metal matrix. Optimize that shared path only when fresh Izanami
  evidence shows a real throughput improvement, with scalar CPU remaining the
  authoritative fallback for every mismatch or dispatch error.

## Sumeragi vNext consensus replacement

- Optimize from the cap `1096` / pipeline `250ms` 20k liveness baseline toward
  higher applied throughput while preserving the hard 2-3s consensus cadence
  gate. The current confirmed 300s stable point is
  `dist/izanami-liveness-matrix-20k-cap1096-p250-pi5-soak-300s-20260511-074409`:
  scan multiplier `32`, collectors/redundant-send `3/3`, backup RBC on, all
  `6,000,000` submissions accepted, strict height `126`, zero view changes,
  runner p95 `2523ms`, parsed peer p95 `2.899s`, max peer gap `3.833s`, full
  detached merge (`1096/1096`, fallback `0`), and `453.13` committed TPS.
  Higher rows are rejected for now: cap `1100`/`250ms` with `3/3` collectors
  failed the parsed peer p95 gate at `3.071s`, cap `1100`/`250ms` with `4/4`
  collectors still failed at `3.022s` with lower committed throughput, cap
  `1104`/`250ms` failed the parsed peer p95 gate at `3.054s` under the finer 5s
  progress monitor, cap `1120`/`250ms` failed both runner and parsed p95 gates,
  cap `1120`/`300ms` was only a runner-gate near miss, and the older cap
  `1312` 120s pass failed the 300s soak. Next, target DA/precommit and
  peer-gap tail reduction before trying to raise cap again. Accept a result
  only if the runner gate, parsed peer p95 gate, zero-view-change requirement,
  and detached-merge counters remain green. Keep backup-on as the default
  recovery posture and use backup-off only as an explicit experiment row. The
  4,096, 8,192, and 16,384 cap experiments already proved that much larger
  blocks are not the next fix without reducing DA/RBC/QC/application tail
  latency and queue-drain cost. Keep the simple-transfer batch path guarded by
  exact trigger-filter matching so per-transaction transcript, event, trigger,
  and rejection semantics remain intact.
- Treat 20k committed TPS as a separate throughput goal from 20k ingress
  liveness. At 2-3s blocks, the current safe cap can only commit hundreds of
  transactions per second; reaching 20k committed TPS requires safe payloads in
  the tens of thousands of transactions per block, equivalent deterministic
  parallel execution, or both. Use the matrix runner for every optimization
  step and require the consensus liveness gate to stay green before accepting a
  higher-throughput result.
- Keep hardening the actor-owned vNext round state now that the standalone
  runtime reactor boundary is gone. vNext control frames, body-backed proposal
  acceptance, DA/RBC availability handoffs, timeout ticks, validation worker
  dispatch/start/result, proposal-backed validation gates, validation
  accept/reject/defer handling, re-chain/view-change aggregation, sidecar
  replay, and commit-persistence completion now run directly through `Actor`.
  Block-sync BlockCreated recovery now also uses named payload-only,
  requested-payload, signed-quorum, and commit-evidence recovery modes instead
  of broad stale/authoritative/revival bypass booleans. The remaining work is
  to delete any legacy cooperative commit sweep paths that become redundant
  once the actor-owned vNext state has equivalent model and integration
  coverage.
- Finish auditing chain-order hash and `rechain_seq` binding in deferred
  vote/QC caches, signer-tally/cache keys, and evidence replay paths used by
  the replacement shell. Vote/QC preimages, precommit signer history,
  block-sync-derived QCs, validator-checkpoint sidecars, raw/deferred vote
  caches, and vote/QC verifier cache keys now carry the selected binding.
- Reconstruct vNext chain order from committed/replayed re-chain and
  view-change certificates during catch-up. The live actor now keeps a bounded
  in-memory certificate journal, persists matching certificates into committed
  Kura roster sidecars, reloads those durable sidecars into outgoing
  `BlockSyncUpdate` payloads, and replays inbound sidecars before vote/QC
  processing. Vote/QC chain-order binding checks also hydrate matching durable
  sidecars from Kura before rejecting a `chain_order_hash`/`rechain_seq`
  mismatch. The remaining open work is to broaden catch-up model and
  integration coverage around restarted-peer durable sidecar replay.
- Add model and integration coverage for slow validation, queue saturation,
  malicious accusers, head failure during re-chain, NPoS stake-quorum
  quarantine edges, and DA/RBC loss during re-chain.

## Validation corridor

- Carry the first-release Sumeragi NPoS/permissioned QC, signed RS16
  availability, exact evidence, and global threshold-beacon paths through the
  next full workspace corridor. Pre-release commit/reveal VRF tests and Torii
  surfaces are not release evidence and must not be restored.
  - Additional Sumeragi/DA adversarial coverage is green as of 2026-05-02 with
    `CARGO_TARGET_DIR=/tmp/iroha-codex-workspace-corridor` for the debug
    witness-root unit, witness-corruption recovery, chunk-drop recovery,
    Kura-eviction DA rehydration, and block-body DA rehydration focused
    reruns. The remaining broad-run Sumeragi DA payload-loss case is also green
    as of 2026-05-03 with the same target dir.
  - NewView QC `highest_qc` binding, exact local-vote `highest_qc` and
    parent/post-root matching, non-NewView `highest_qc` rejection, and
    same-highest aggregate formation are green as of 2026-05-03 with
    `CARGO_TARGET_DIR=/tmp/iroha-codex-sumeragi-highest` for the NPoS
    aggregate-only substitution regression, the `new_view_highest` focused
    slice, and the stale/future NewView QC formation regressions. The same
    target now also covers commit/checkpoint missing-PoP rejection, block-sync
    QC validation with commit-phase enforcement, commit-certificate roster
    validation, checkpoint roster validation, validation telemetry reason
    labels, and the permissioned/NPoS aggregate-fallback quorum checks.
    Embedded commit-QC roster anchoring is green as of 2026-05-04 in the same
    target for both the malicious shrink-roster rejection and the valid
    stale-cache bootstrap path; the embedded-roster missing-PoP rejection is
    green in that same filter. NPoS block-sync roster selection now also has
    focused coverage for carrying a locally resolved stake snapshot when the
    incoming QC/checkpoint hint omits one.
  - The ZK-confidential localnet submit helper has been hardened for startup
    transport jitter and wrapped policy rejections. The classifier/retry-budget
    tests plus disabled shield/unshield localnet regressions are green as of
    2026-05-03 with `CARGO_TARGET_DIR=/tmp/iroha-codex-uaid-target`. The full
    serial `consensus_and_da` target is also green in the same target dir:
    `250` passed, `0` failed, `6` ignored. Focused strict clippy over
    `iroha_core`, `iroha_torii`, `iroha_test_network`, and the
    `consensus_and_da` test target is also green in that target dir.
  - Focused `cargo clippy -p iroha_core -p iroha_data_model -p iroha_torii -p
    irohad --all-targets -- -D warnings` is green as of 2026-05-02 with
    `CARGO_TARGET_DIR=/tmp/iroha-codex-sumeragi-clippy`.
  - Full workspace all-target clippy is green as of 2026-05-03 with
    `CARGO_TARGET_DIR=/tmp/iroha-codex-uaid-target`.
  - The broad workspace test rerun reached `events_and_triggers` after passing
    `consensus_and_da` and `core_api`; the exposed by-call trigger fixture and
    subscription time-trigger billing failures are repaired as of 2026-05-03.
    Focused `events_and_triggers` reruns for the two by-call trigger cases and
    `subscriptions::subscription_scenarios` are green with
    `CARGO_TARGET_DIR=/tmp/iroha-codex-uaid-target`.
    The full `events_and_triggers` target, full `queries_and_proofs` target,
    `network_functional::extra_functional::unstable_network`, full
    `nexus_and_streaming` target, and reduced-sample ignored
    `torii_load_profile` are also green as of 2026-05-04 in the same target
    dir. The stale IVM/Kotodama, Space Directory, lane commitment, Norito
    instruction, and streaming RANS fixtures uncovered by those targets have
    been regenerated.
    The full `core_api` target is green again as of 2026-05-04 after repairing
    private-entrypoint hash handling and widening the slow asset/sealed-reveal
    liveness paths (`171` passed, `4` ignored).
    A broad `cargo test --workspace` reached `integration_tests --lib` after
    compiling the workspace and passing the preceding crate/test targets; the
    first integration-library pass failed on a stale spawned daemon artifact,
    then the exact startup/drop regressions and the full integration library
    passed after rebuild (`41` passed). The core signature slice, crypto
    Ed25519 tests, and strict clippy for core/crypto/integration are also green
    after the deterministic single-Ed25519 verifier cleanup and heartbeat
    execution-context fixture repair. The replay/checkpoint follow-up is green
    as of 2026-05-05 for the focused replay units, Halo2 restart-marker
    verifier, strict core/crypto/consensus integration clippy, and the
    previously failing `consensus_and_da` restart/localnet cases:
    `sumeragi_restart_retains_lock_convergence`,
    `npos_pacemaker_resumes_after_downtime`,
    `confidential_combined_peer_downtime_and_timeout_pressure_localnet`, and
    `confidential_dual_restart_stress_mid_flow_localnet`.
    The 2026-05-07 follow-up also has focused green reruns for the staged
    consensus failures exposed in the latest broad workspace attempt:
    selective-drop recovery, conflicting-ready invalidation, Kura eviction DA
    rehydration, NPoS baseline metrics, pacemaker latency, pacemaker restart
    liveness, stale-evidence rejection, and the VRF randomness module. The
    focused `integration_tests --test consensus_and_da` compile check is green
    in `CARGO_TARGET_DIR=/tmp/iroha-codex-keepgoing-workspace-check`.
  - Remaining validation: rerun `cargo test --workspace` from a clean start to
    completion in an uncontended multi-hour window.
  - Broad workspace all-target compile validation is green as of 2026-05-07
    with `CARGO_TARGET_DIR=/tmp/iroha-codex-keepgoing-workspace-check` after
    repairing the default Linux monitor synth gate and stale
    `LaneBlockCommitment` fixture initializers in Python/`xtask`.
- Carry the RAM-LFE API/proof hardening through the remaining signing and clean
  full-workspace Cargo corridor.
  - Focused OpenAPI detached-envelope tests, crypto RAM-LFE tests, the new
    state-deserialization policy regression, Torii RAM-LFE handler tests,
    JavaScript RAM-LFE tests, Swift execute-response parsing, the focused
    `iroha_core` RAM-LFE gate, the workspace all-target compile corridor,
    focused strict clippy over the repaired tool/SDK/Mochi/CoreHost/proof
    targets, JavaScript/Kotlin/JVM/Java Android identifier BFV parity,
    JavaScript Connect Norito schema-hash parity, Android Norito schema-manifest
    verification, C# SDK tests on macOS with a temporary .NET 8 SDK, full Swift
    package tests, full workspace all-target clippy, `scripts/check_no_legacy_codec.sh`,
    formatting, and diff whitespace checks are green as of 2026-05-02.
  - Remaining validation: run `cargo test --workspace` in an uncontended
    validation window.
  - Windows C# follow-up: on a Windows box with .NET 8, run
    `dotnet restore csharp/Hyperledger.Iroha.Sdk.sln`, then
    `dotnet test csharp/tests/Hyperledger.Iroha.Sdk.Tests/Hyperledger.Iroha.Sdk.Tests.csproj`.
    Confirm the canonical Norito schema-hash test, transaction-builder goldens,
    faucet PoW vectors, and URL escaping expectations pass unchanged; record the
    Windows result in `status.md`.
    Repo-local Linux validation and the read-only public Taira live smoke are
    green as of 2026-05-19; this item is now specifically the external
    Windows-host rerun.
    Also cover the new multisig propose helper work on Windows: the focused
    tests should include
    `ToriiClientTests.ProposeMultisigAsyncPostsNativeNoritoInstructionFrames`
    plus malformed-response cases for invalid or empty `signing_message_b64`,
    false `ok`, negative `creation_time_ms`, and malformed hash metadata,
    and `NoritoCodecTests.EncodeWithSchemaHashUsesProvidedSchemaHash`, and the
    review should confirm `TransactionInstruction.EncodeInstructionBoxBase64`
    emits `InstructionBox` frames suitable for `/v1/multisig/propose`.
  - Focused Kotlin/JVM and Java Android RAM-LFE parser/transport tests are
    green as of 2026-05-02 with Homebrew OpenJDK 21 pinned via `JAVA_HOME`; the
    same harnesses also cover the canonical BFV identifier schema-hash vector.
  - The current static OpenAPI manifest now verifies in explicit unsigned
    first-release mode; before publishing a signed OpenAPI release, rerun the
    same manifest flow with the operator signing key or detached Ed25519
    signature envelope.
- Carry the FastPQ V1 release hardening through the remaining broad validation
  corridor.
  - The 2026-05-17 implementation removes prover-scale CPU replay from
    verification, validates proof-carried roots/transcript challenges/Merkle
    openings/AIR rows/lookup-product binding/FRI query chains from proof
    content, defaults production runtime config to explicit `cpu`, fails
    explicit `gpu` startup closed when preflight is unavailable, bounds Kura
    FASTPQ proof sidecar persistence, adds sidecar telemetry, exposes
    `/v1/pipeline/recovery/{height}/fastpq-proofs`, and adds AXT packaging
    helpers for already-bound batches.
  - Focused `fastpq_prover`, `iroha_config`, `iroha_core fastpq`, Torii recovery
    endpoint, confidential localnet restart/recovery, and explicit
    `fastpq-gpu` release checks are green as of 2026-05-17 with
    `CARGO_TARGET_DIR=target/codex-fastpq-release` and
    `CARGO_TARGET_DIR=target/codex-fastpq-gpu`. The full workspace all-target
    clippy corridor is also green; the remaining open work is only the next
    multi-hour `cargo test --workspace` corridor.
  - AXT proof envelopes now require FastPQ V1 verifier labels at both the
    production FastPQ binding layer and the standalone IVM host envelope-shape
    layer. DefaultHost, CoreHost, and WSVHost reject raw proof bytes and
    synthetic/non-V1 proof labels during diagnostic preflight. Because
    standalone IVM does not link a real FastPQ verifier, proof-consuming AXT
    calls fail closed after preflight; the production AXT verifier rejects oversized
    encoded proof payloads before Norito decode. The descriptor-derived
    synthetic AXT batch builder and CLI fallback have been removed; proof
    generation and measurement require an execution-captured `batch_base64`
    request field. Core state no longer synthesizes FastPQ batch hashes for
    ad-hoc transcript/RWA contexts; those paths require transaction call-hash
    context or a trigger-specific call hash. The shared preflight checks also
    require concrete binding fields,
    supported FastPQ claim types, 32-byte hex digests, and nonempty
    duplicate-free target dataspace sets. DefaultHost also binds handles to the
    manifest root carried by inline, recorded, or late proof envelopes before
    failing closed without a verifier. The focused `fastpq_prover` AXT binding slice,
    `iroha_data_model` `proof_envelope_shape_matches_manifest` slice, `ivm_abi`
    `preflight_fastpq_v1_proof_envelope` test, `ivm` `axt_host_flow` target, and
    `ivm` `host_unknown_syscall`/`core_host_policy` targets are green as of
    2026-05-02. FastPQ AXT deterministic account fixtures now derive
    hash-derived Ed25519 identities through `KeyPair::try_from_seed` and compare
    the generated account id with the checked backend public key before real
    transfer-claim transcript envelope tests consume them.
  - CoreHost raw-root rejection and real FastPQ proof-envelope validation is
    covered by the focused `ivm_corehost_axt` proof-binding test with
    `iroha-core-tests,app_api`; the correctly-featured target is green as of
    2026-05-03 with `28` tests. The `app_api`-only command lists zero tests and
    should not be treated as coverage for this target.
  - Block-level app-API AXT validation and host proof-cache success fixtures now
    use reusable FastPQ-backed proof envelopes. The full
    `axt_validation_tests` module and focused `axt_verify_ds_proof` host sweep
    are green as of 2026-05-02.
  - Shared `ProofBlob` matching, standalone `ivm` CoreHost/WSV tests, state
    replay-ledger fixtures, ISI lane-relay registration, and data-model AXT
    fixtures now reject raw manifest roots and binding-less success envelopes;
    only malformed-negative tests keep those payloads.
  - Lane relay proof metadata has no legacy deterministic digest helper and
    carries a required `verified_at_height` field. Verified lane-relay
    registration binds the envelope digest to the submitted proof blob payload
    hash; the data-model proof-material tests and core `lane_relay` slice are
    green as of 2026-05-02.
  - Replace the current prover-scale canonical replay verifier with a succinct
    quotient-only verifier once the V1 quotient commitment/opening API lands;
    this is a performance follow-up, not permission to accept synthetic AXT or
    placeholder proofs.
- Carry the SoraNet VPN escrow hardening through the remaining ledger and
  deployment corridor.
  - The Torii/relay/helper control plane now requires XOR quote payments,
    non-operator escrow custody, client usage vouchers, one-use helper tickets,
    relay TLS pinning, helper-ticket-bound metering keys, and tariff-derived
    relay settlement.
  - Native lease escrow ISIs, WSV lease records, verified tariff settlement,
    relay/helper streaming voucher debt-window enforcement, Torii native
    `OpenVpnLeaseEscrow` quote skeletons, and Torii native `SettleVpnLease`
    receipt skeleton responses through the generic `tx_instructions`
    tooling convention are implemented. Torii active-session lookup and receipt
    settlement now reload authoritative lease state from WSV instead of relying
    on process-local VPN session caches.
  - Relay/backend deployment now uses `vpn.backend_endpoint`; Unix sockets are
    the default privileged path, while TCP requires a shared bootstrap secret
    and Norito MAC envelopes with timestamp/nonce replay checks.
  - Hidden helper workers now receive magic-prefixed Norito connect-payload
    frames over stdin and batch magic-prefixed Norito traffic-state persistence.
  - Relay operators can set `vpn.receipt_spool_dir` to persist the exact
    `/v1/vpn/receipts` request body for voucher-backed sessions, so settlement
    no longer depends on reconstructing receipt bytes from logs.
  - `soranet-vpn-settlement` consumes those artifacts and signs deterministic
    Torii receipt headers/body, or renders curl, using runtime-only operator seed
    material.
  - The JavaScript, C#, Swift, Python, Kotlin/JVM, and Java Android Torii
    clients now expose the quote-first open flow and operator receipt
    submission helpers with native instruction skeletons.
  - Next, finish the focused Cargo validation once the current shared target
    locks clear, then run a public relay/helper/Torii canary that opens a native
    XOR VPN lease from the wallet flow, submits a spooled operator receipt, and
    signs the returned `SettleVpnLease` transaction.
- Carry the IVM/Kotodama vector and syscall hardening through the next clean
  validation corridor.
  - `cargo test -p ivm_abi`,
    `cargo test -p ivm --test vector_execution_regression`, and
    `cargo test -p kotodama_lang vector_length` are green as of 2026-05-02.
  - The updated IVM gas/metadata/pointer window is also green as of
    2026-05-02:
    `cargo test -p ivm --test gas_conformance --test gas_golden --test metadata --test metadata_roundtrip --test pointer_tlv_neg`.
  - The focused analyzer regression
    `cargo test -p ivm analysis_treats_setvl_operand_as_immediate --lib` is
    green as of 2026-05-02.
  - The SCALLX ABI expansion is green as of 2026-05-02 for
    `cargo test -p ivm --lib ivm_is_send_sync_for_state_sharing`,
    `cargo test -p ivm --lib scallx_dispatches_extended_syscall_id`,
    `cargo test -p ivm --test abi_hash_versions --test gas_schedule_hash --test syscalls_doc_sync --test ivm_abi_doc_sync`, and
    `cargo test -p ivm_abi --lib syscallx_roundtrips_24_bit_number`, all with
    `CARGO_TARGET_DIR=target/codex-ivm-scallx`; the core admission regression
    `cargo test -p iroha_core validate_ivm_unknown_scallx_rejected_at_admission --lib`
    is green with `CARGO_TARGET_DIR=target/codex-core-scallx`.
    Follow-up host-bound coverage
    `cargo test -p ivm --lib ivm_is_send_sync_for_state_sharing`,
    `cargo test -p ivm --lib run_with_host_accepts_non_sync_host`, and
    `cargo test -p ivm --lib block_height_syscall_uses_configured_deterministic_value`
    is green with `CARGO_TARGET_DIR=target/codex-ivm-scallx`. Core host
    coverage for `core_queries_return_typed_handles_and_specialists_remain_norito`,
    `block_height_sysvar_uses_attached_transaction_context`, and scoped
    durable-state `STATE_HAS`/`STATE_LEN`/`STATE_COUNT`
    tombstone resolution is
    green with `CARGO_TARGET_DIR=target/codex-core-scallx`.
    Broader IVM validation is also green with
    `CARGO_TARGET_DIR=target/codex-ivm-scallx cargo test -p ivm --lib` plus
    targeted integration batches for gas/opcode/vector, metadata/pointer ABI,
    predecoder/doc sync, syscalls, WSV-host flows, VRF, and ZK verifier gates.
  - Typed `CORE_QUERY_GET`/`CORE_QUERY_PAGE` cover account, asset,
    asset-definition, domain, and NFT projections through the validated query
    engine and typed V1 handles. `QUERY_GET_CONTRACT_MANIFEST`,
    `QUERY_GET_PARAMETER`, and `QUERY_GET_CONTRACT_INSTANCE` remain specialist
    canonical-Norito APIs; all paths charge the documented deterministic query
    gas model.
    `SYSVAR_BLOCK_HEIGHT` is threaded through default hosts and attached core
    query-state contexts. The final V1 `STATE_SCAN` surface provides bounded live
    keyset pagination with authenticated instance/map cursors and contract-scope
    prefix stripping; final qualification is tracked in `kotodama_v1_redesign.md`.
    `STATE_HAS`/`STATE_LEN` provide cheap presence and payload-length probes,
    and `STATE_COUNT` counts matching durable-state keys without returning the
    key list over the same scoped durable-state resolution. Classic `STATE_GET`,
    `STATE_SET`, and `STATE_DEL` now charge documented deterministic state gas
    instead of returning zero. `GET_ACCOUNT_BALANCE` and
    `RESOLVE_ACCOUNT_ALIAS` also return deterministic nonzero query-style gas.
    `TLV_EQ` and `TLV_LEN` now charge deterministic byte-counted codec-helper
    gas costs instead of inspecting potentially large payloads for free.
    Typed numeric operations charge the deterministic `G_numeric_staged`
    limb-work schedule. `POINTER_TO_NORITO` and `POINTER_FROM_NORITO` charge
    `G_pointer + bytes` across default, WSV, and standalone codec hosts, with
    the byte component tied to the canonical TLV envelope copied or validated.
    Numeric pointer transport validates canonical V1 Int, Decimal, and
    Quantity frames, including the signed-512 Int bound, before publication. Schema helpers and the remaining
    classic codec helpers charge deterministic byte-counted gas: `SCHEMA_*`,
    `JSON_*`, `NAME_DECODE`, and the path builders no longer return zero for
    payload work. `SM2_VERIFY` now
    charges `G_verify + bytes`; `SM4_GCM_*` and `SM4_CCM_*` now charge
    `G_sm4 + bytes` through the shared default-host implementation, preserving
    deterministic vector output while charging AAD and plaintext/ciphertext
    bytes. Deterministic sysvar reads now charge
    `G_sysvar` or `G_sysvar + bytes`, and authority reads charge
    `G_get_auth + bytes`, across default, WSV, standalone codec, and real-host
	    paths. VRF verification now charges `G_verify + bytes` on decoded
	    status-returning paths, and standalone/WSV ZK verification status exits now
	    charge payload-size verification gas instead of returning zero. ZK
	    roots/tally reads and VRF epoch-seed reads now charge request + response
	    byte gas across standalone, WSV, and real CoreHost paths.
	    `VERIFY_DS_PROOF` now charges `G_verify + bytes` in the real
	    smart-contract host and `G_verify` for proof-clear paths across real,
	    default, standalone CoreHost, and WSV mock hosts while standalone
	    proof-consuming AXT calls remain fail-closed without the real FastPQ
	    verifier. Runtime helper syscalls now also avoid documented zero-gas
	    gaps: `INPUT_PUBLISH_TLV`
    charges envelope bytes across default, WSV, and standalone CoreHost paths;
    `VERIFY_SIGNATURE` charges message/signature/key bytes; and private input,
    nullifier, output commit, heap growth, allocation shim, debug/exit/abort,
    validation-only ISI mutation stubs, FastPQ batch-entry/apply validation,
    and Merkle proof helpers return fixed, page, per-entry, or depth costs
    instead of zero. The WSV mock host direct mutation ABI surface, FastPQ
    transfer batch apply path, and development `SMARTCONTRACT_EXECUTE_QUERY` /
    `SMARTCONTRACT_EXECUTE_INSTRUCTION` JSON shims now also return deterministic
    query or mutation gas instead of treating mock-host state changes as free.
    The real smart-contract host now charges the declared `G_sc_depth` floor for
    `SET_SMARTCONTRACT_EXECUTION_DEPTH`, including the zero-depth no-op path,
    and the declared `G_create_nfts_all` floor for empty
    `CREATE_NFTS_FOR_ALL_USERS` snapshots.
    The classic hash helper surface now includes gas-charged SHA-256,
    SHA3-256, raw Blake2b-256, Keccak-256, and Iroha `Hash::new` syscalls
    routed through the real smart-contract host with byte-identical CPU or
    byte-equivalent accelerated output requirements.
  - `VERIFY_PROOF` now has a CoreHost implementation for
    `NoritoBytes(OpenVerifyEnvelope)` payloads backed by on-chain verifying-key
    registry prechecks and deterministic status-code returns; standalone IVM
    hosts continue to reject it without registry context. Acceleration status
    reporting now only marks CUDA parity as OK when the backend is usable after
    policy, hardware detection, and self-tests.
  - `EXECUTION_SUMMARY` returns `NoritoBytes(ExecutionSummary)` instead of a
    reserved stub. The self-reported summary digests deterministic
    trace/log/root material with SHA-256 and is stable across repeated identical
    runs. It is explicitly not a proof or authenticated execution attestation;
    cryptographic verification remains on the dedicated verifier syscalls.
  - The broader `cargo test -p ivm` corridor is green as of 2026-05-02 after
    repairing the data-model compile blocker, refreshing the AXT fixture
    headers, and moving Kotodama test helpers to host-private SCALLX numbers.
    The optimized `cargo test -p ivm --test shifts_prop` focused rerun is also
    green.
  - The `ivm_contract_deploy` staged copy/register fixture tests are green as
    of 2026-05-07 after the literal-table padding repair:
    `cargo test -p iroha_cli --bin ivm_contract_deploy staged_ -- --nocapture`
    with `CARGO_TARGET_DIR=/tmp/iroha-codex-keepgoing-workspace-check`.
  - Follow-up widened checks are green as of 2026-05-02:
    `cargo test -p ivm_abi`, `cargo test -p kotodama_lang`,
    `cargo clippy -p ivm_abi -p kotodama_lang --all-targets -- -D warnings`,
    and `cargo clippy -p ivm --all-targets -- -D warnings`.
  - Fold the 2026-05-03 Kotodama access-hint, contract artifact registry, and
    literal-padding hardening through the next clean full workspace test and
    clippy corridor after the focused validation recorded in `status.md`.
  - Fold the 2026-05-03 IVM ABI v1 gas/error hardening through the next full
    workspace test and strict clippy corridor after the focused syscall-doc,
    host-policy, AXT, and Soracloud validation recorded in `status.md`.
- Carry the UAID onboarding hardening through the next workspace validation
  corridor.
  - Focused formatting, Python syntax checks, Torii UAID parser tests, Torii
    MCP shortcut/raw-body tests, Torii HTTP onboarding negative-contract tests,
    the full Torii onboarding integration target, Torii onboarding
    error-metadata tests, Swift register-account tests, focused IVM host
    thread-safety tests, the OpenAPI sync/version/signature script tests, the
    focused core UAID portfolio grouping test, the DA manifest fixture sweep,
    `cargo test -p iroha_torii --lib --features app_api`, and
    `cargo check --workspace --all-targets` are green as of 2026-05-02. The
    full workspace all-target clippy corridor is also green as of 2026-05-02
    with `CARGO_TARGET_DIR=/tmp/iroha-codex-uaid-target`.
  - The Rust implementation is in place for explicit UAID-only onboarding,
    digest-only identity commitments, MCP/OpenAPI request contracts, Swift
    request canonicalization, asset-scope-aware UAID portfolio grouping, and
    stale OpenAPI manifest-signature suppression in generated version indexes;
    `versions.json` has been refreshed in explicit unsigned mode pending the
    operator signature.
  - Keep the broader `cargo test --workspace` corridor open. The repaired
    `events_and_triggers`, `queries_and_proofs`, `nexus_and_streaming`,
    unstable-network, and `core_api` targets are green individually as of
    2026-05-04. The Sora governance runtime-upgrade path now hashes prepared
    transaction entrypoints from the actual canonical signed payload bytes and
    confirms Torii status with explicit global scope, but the full workspace
    command still needs an uncontended end-to-end pass. The static OpenAPI JSON,
    version index, and unsigned latest/current manifests are refreshed and
    verify under the explicit first-release unsigned corridor.
- Carry the Torii exposure-hardening slice through the remaining workspace
  validation corridor.
  - `cargo fmt --all` and `cargo check -p iroha_config -p iroha_torii` are
    green as of 2026-05-02 for the CORS/pre-auth, MCP tool-effect,
    protected-namespace, route-catchall, mixed-content extractor, and router
    composition changes.
  - `cargo test -p iroha_config torii_cors_parse --lib` and
    `cargo test -p iroha_torii tool_effects --lib` are green as of
    2026-05-02. The follow-up MCP effect audit is also green for
    `cargo test -p iroha_torii get_tools_are_declared_read_effect --lib`,
    `cargo test -p iroha_torii manual_sumeragi_snapshot_tools_remain_read_only --lib`,
    and `cargo test -p iroha_torii tool_effects --lib` with
    `CARGO_TARGET_DIR=/tmp/iroha-codex-torii-continue`. Fold the slice into the
    next workspace clippy/test corridor when validation budget allows.
  - Completed 2026-06-06: app-facing caller-scoped account reads no longer
    accept bare `X-Iroha-Account` as caller identity. Torii now requires
    canonical request signatures or witnesses for private caller visibility,
    while unsigned reads stay limited to public dataspace routes.
  - Completed 2026-06-06: repaired the stale SCCP, SoraFS, ISO20022, ZK IVM,
    and ZK prover fixtures that no longer matched production admission rules;
    `cargo test -p iroha_torii --lib -- --nocapture` is green with `2275`
    passed and `2` ignored.
  - Completed 2026-06-06: Torii's API-token-gated Sumeragi/SCCP/bridge
    telemetry hook now records bounded endpoint/token-state counters without
    exporting raw token material; the feature-enabled Torii clippy corridor is
    green after the SCCP route-manifest alias resolver lint cleanup.
- Carry the Torii first-release API cleanup through the remaining release
  corridor.
  - The route/API/error-envelope implementation, focused Rust sidecar/client
    tests, Swift/Python/Kotlin/JVM/Java Android/JavaScript client regressions,
    JS native/dist rebuild, formatting, and whitespace checks are green as of
    2026-05-17. Static OpenAPI JSON snapshots and latest/current unsigned
    manifests are refreshed and verified; the remaining broad release work is
    the next full workspace test/clippy corridor.
  - Completed 2026-06-06: default Torii builds no longer mount placeholder
    `501 Not Implemented` handlers for `/status`, `/metrics`,
    `/v1/debug/axt/cache`, `/v1/debug/witness`, `/v1/schema`,
    `/debug/pprof/profile`, or `/v1/zk/verify-batch`; these paths are
    feature-owned and absent unless `telemetry`, `schema`, `profiling`, or
    `zk-verify-batch` is compiled. The default OpenAPI snapshots now omit the
    disabled telemetry, schema, and profiling paths as well.
  - Completed 2026-06-06: account-alias resolver service fallbacks no longer
    return `501 Not Implemented` for non-account `AliasTarget` records.
    `/v1/aliases/resolve` and `/v1/aliases/resolve-index` now return a
    documented `409 Conflict` when a stored alias-service record targets an
    asset, peer, or custom payload instead of an account.
  - Completed 2026-06-06: routed-query `query_unsupported` responses now use
    `409 Conflict`, and inbound Torii proxy `Read`, `ReadFanout`, and
    `HostedHttp` requests compiled without `app_api` use `503 route_unavailable`
    instead of `501 Not Implemented`.
  - Completed 2026-06-06: SoraFS proof streaming now rejects
    `proof_kind=pdp` as `400 Bad Request` because the live endpoint accepts only
    PoR/PoTR until the SF-13 PDP provider protocol ships.
  - Completed 2026-06-06: code-only placeholder/TODO sweep removed stale
    governance deploy-proposal and ZK1 validator wording; remaining matches are
    intentional negative tests, placeholder-material fail-closed guards,
    OpenAPI fallback skeleton naming, manifest-derived contract source
    rendering, and telemetry peer compatibility handling.
  - Completed 2026-06-06: Torii's configured SCCP all-lanes launch diagnostic
    now uses the shared supported launch-domain set (ETH, BSC, Solana, TON,
    configured material remains explicitly tested as out of launch scope, and
    `cargo test -p iroha_torii --lib --features app_api -- --nocapture` is
    green with `2309` passed and `2` ignored.
  - Completed 2026-06-06: the same Torii cleanup slice is now green under
    `cargo test -p iroha_torii --tests --features app_api -- --nocapture`.
    The broad run covers the updated governance council stake-asset fallback
    fixture, feature-gated MCP governance tool dispatch, valid ZK roots
    confidential payload fixtures, and the current Norito error-envelope
    contract for signed ZK attachment failures.
  - Completed 2026-06-06: the feature-minimal Torii connect corridor is now
    green under `cargo check -p iroha_torii --no-default-features --features connect`,
    `cargo test -p iroha_torii --no-default-features --features connect --lib -- --nocapture`,
    and `cargo clippy -p iroha_torii --no-default-features --features connect --all-targets -- -D warnings`.
    App-only route helpers, proof-record reads, hosted HTTP proxy fallbacks,
    integration tests, the attachment sanitizer binary, and hot-path bench now
    sit behind `app_api`/required-feature gates, while core ZK roots and
    vote-tally DTOs and handlers remain exported without `app_api`. The
    pre-release decode-only `verify` and `submit-proof` routes were subsequently
    removed because they could be mistaken for authoritative proof acceptance.
- Carry the Iroha Connect hardening through the remaining SDK and workspace
  validation corridor.
  - P2P session claims, hashed token storage, focused Rust checks, JavaScript
    checks, JS `dist`, Python syntax checks, and shared relay-auth vectors are
    green as of 2026-05-01.
  - Python pytest, Kotlin/JVM, Java Android, and Swift package tests remain
    blocked by missing local tools/artifacts.
  - When the validation shell has `pytest`, a Java runtime, and
    `dist/NoritoBridge.xcframework`, rerun the focused Python Connect tests,
    `./gradlew :core-jvm:test --tests org.hyperledger.iroha.sdk.connect.ConnectWalletRequestTest --console=plain`,
    the matching Java Android Connect wallet tests, and the focused Swift
    Connect/Torii tests.
  - Fold the Connect session/relay changes into the next broader
    `cargo test -p iroha_torii`, `cargo test --workspace`, and workspace clippy
    corridor when validation budget allows.
- Carry Offline real-proof support through the remaining release corridor.
  - The native bridge prover FFI focused corridor is green as of 2026-04-30. Fold it into a broader `cargo test -p iroha_core --lib`, SDK test, and workspace clippy corridor when validation budget allows.
  - Offline-to-offline SDK local-final semantics, trusted Ed25519 issuer
    certificate verification, and Android rollback fail-closed storage checks
    are green as of 2026-05-17 across Swift, Kotlin/JVM, Java Android, iOS
    simulator XCTest, and Android emulator instrumentation. Fold this into the
    next full workspace test/clippy corridor when validation budget allows.
  - The pure Swift Offline prover hot path is green as of 2026-05-01 with
    subsecond median native audit/redeem proofs on macOS arm64. Keep that
    benchmark in the next iOS-device corridor and broaden Swift package
    validation when budget allows.
  - Kotlin/JVM and Java Android now have the native Offline instance-value
    groundwork and pure Java Halo2/IPA prover path, including focused JVM and
    Android harness coverage plus env-gated benchmark hooks. Keep the native
    prover tests, Swift/JVM cross-verification payload, and larger benchmark
    iteration counts in the next device and full-SDK corridor.
  - The Torii Offline issuer hardening focused corridor is green as of
    2026-05-01. Fold it into the next broader `cargo test -p iroha_torii`,
    SDK, workspace test, and workspace clippy corridor when validation budget
    allows.
- Carry native numeric asset escrow through the remaining Aitai application
  corridor.
  - Wire the Sora Aitai application UI/backend onto the
    authority-authenticated numeric escrow ISIs, then subscribe through the
    typed numeric escrow query/event APIs.
  - Add app-facing lifecycle events for transparent offer state changes, and
    keep any remaining Kotodama wrapper work scoped to app calls that still
    need contract compatibility.
  - Add end-to-end UI/client smoke coverage once the Sora Aitai application
    replaces the old contract escrow account path for transparent XOR offers.
    Native anonymous escrow is not a first-release surface; any future
    confidential-commerce protocol requires a separate authority- and
    settlement-bound design review.
  - Rerun the full Kotlin, Java Android, and Swift SDK suites after the Aitai app
    wiring lands and a Java 21 runtime is available in the validation shell.
  - Keep NFT/RWA escrow and court fee/payout generalization as separate
    follow-ups; the v1 primitive intentionally resolves only between the escrow
    seller and accepted buyer.
- Carry the Soracloud production posture hardening through the operator-host rollout corridor.
  - Inrou remains opt-in and false by default. Explicit enablement selects the
    sole PortableVM V1 path; startup and capability advertisement require its
    authenticated minimal root, private mount/network/PID/IPC/UTS/cgroup
    namespaces, bounded authenticated listener bridge, exact cgroup-v2 limits,
    locked identity, KVM, filesystem, QMP, and firewall preflight.
  - Independently qualify that path on same-revision Linux/AArch64/KVM hosts
    with malicious guest-root escape, resource-exhaustion, descriptor/socket,
    teardown, advert/withdrawal, and hosted-HTTP canary evidence. TCG and
    operator-selectable backend/accelerator/supplementary-group/capacity knobs
    remain retired.
- Carry the new Taira devex CLI through the opt-in live rollout corridor.
  - The local CLI/Torii/mock-script validation for `iroha taira doctor` and `iroha taira write-canary` is green as of 2026-04-25, but no live Taira write was run from this tree.
  - Before publishing a live receipt, run `iroha taira doctor --public-root https://taira.sora.org` and an operator-approved `iroha taira write-canary --public-root https://taira.sora.org`, preserving only the redacted receipt and any stable failure codes.
  - Fold the Taira CLI/Torii changes into the next broader `cargo test -p iroha_cli`, `cargo test -p iroha_torii`, workspace test, and clippy corridor when validation budget allows.
- Carry the verified lane relay JSON-state/key change through the next UC6 integration corridor.
  - The focused crate checks are green as of 2026-04-24, but no live UC6 settlement-smoke run or topology reset has been performed from this tree.
  - Before any live deployment, confirm the deploy/Core API smoke path still uses `relay_state_key`, JSON relay state, and the simulation gate against the exact finalization payload.
  - If a topology plan selects reset mode while validating this change, stop before approval and reassess the rollout scope.
- Carry the Torii routed-read and telemetry fixes through the next workspace validation corridor.
  - The crate-local sweep is green as of 2026-04-24 with `cargo test -p iroha_torii --lib --features app_api,telemetry -- --nocapture`.
  - When validation budget allows, carry the alias-routing and Torii telemetry slices through the next `cargo test --workspace` / `cargo clippy --workspace --all-targets -- -D warnings` corridor and record the result in `status.md`.
- Broaden validation for the new canonical account-alias lease flow beyond the focused onboarding and executor checks.
  - The onboarding auto-renew grant remains covered by `onboarding_alias_auto_renew_grants_subscriber_metadata_mutation`, and the Torii `alias_auto_renew` filter now also applies a subscriber-signed `/auto-renew` disable against an onboarding-shaped subscription NFT.
  - The SNS subscription auto-renew billing path was rerun with `cargo test -p iroha_core subscription_bill_account_alias_auto_renew_ --lib -- --nocapture`, covering both renewal/reschedule and missing-alias suspension branches.
  - Once the alias lease slice is stable under those focused reruns, fold it into the next broader `cargo test --workspace` / `cargo clippy --workspace --all-targets -- -D warnings` corridor.
- Keep the Sumeragi main-loop broad corridor attached to future consensus
  changes.
  - The 2026-05-08 idle timing-cache change is covered by focused cached
    commit-quorum timeout, NPoS commit-floor, rebroadcast-cooldown,
    commit-pipeline cooldown, effective-timing snapshot, mode-flip tick
    deadline, commit-evidence replay cooldown, and proposal-backpressure timing
    tests. Rerun the full `cargo test -p iroha_core --lib` corridor before the
    next consensus sweep.
  - The 2026-05-08 known-block commit-QC recovery dampening is covered by
    focused cert-only fetch, duplicate-QC cleanup, committed-tip reacquisition,
    stale same-height view pruning, bounded missing-QC view rotation,
    stall-reset fallback handoff, local-payload recovery, retry-loop, and
    same-height `BlockBodyResponse` repair tests. Rerun the full
    `cargo test -p iroha_core --lib` corridor before the next consensus sweep.
  - The realistic 30 TPS, 20-minute transfer soak passes as of the
    2026-05-08 block-body response ingress fix. Remaining open work is
    throughput margin, not liveness: the passing release-daemon run submitted
    at 30.00 TPS but committed 21.61 TPS during load, peaked at 9,973 queued
    transactions, and needed 722 seconds of drain time. Use
    `integration_tests/artifacts/realistic-30tps-transfer-20min-640-release-daemon-block-body-response-block-lane/throughput-1778229477740/`
    for the next worker/proposal throughput tuning pass.
  - The matching realistic 30 TPS, 20-minute RAM-LFE email-claim soak also
    passes as of 2026-05-08. The release-daemon run submitted 36,000
    `ClaimIdentifier` email transactions, reached the 36,008 approved target
    with zero rejects, and finished with all peers at 723 non-empty blocks.
    Margin remains the open item: load committed at 21.27 TPS, final committed
    TPS was 19.17 including drain, peak queue was 10,377, and drain took 677
    seconds. Use
    `integration_tests/artifacts/realistic-30tps-ram-lfe-email-20min-release-daemon/throughput-1778232961671/`
    alongside the transfer artifact for the next worker/proposal throughput
    tuning pass.
  - The 2026-05-08 DA/RBC large RAM-LFE proposal fallback is covered by focused
    DA payload-budget tests, a RAM-LFE oversized-frame fallback regression, and
    the adjacent unservable-payload deferral check. Rerun the full
    `cargo test -p iroha_core --lib` corridor before the next consensus sweep.
  - The 2026-05-06 canonical proposal/block entrypoint-ordering fix is covered
    by focused ordering, mixed-entrypoint builder, rejection mapping, and
    noncanonical static/unchecked-validation regressions. Rerun the full
    `cargo test -p iroha_core --lib`
    corridor before the next consensus sweep.
  - The 2026-05-03 `cargo test -p iroha_core --lib` rerun is green
    (`5129` passed, `22` ignored) after fixing execution-witness recorder
    isolation and hardening the RBC sidecar cooldown fixture.
  - The later 2026-05-03 restarted-peer commit-QC recovery fix is covered by
    focused block-body response regressions and the confidential downtime plus
    timeout localnet scenario, which now enforces restarted-peer non-empty
    height catch-up before final balance checks.
  - The 2026-06-12 `cargo test -p iroha_core --lib -- --nocapture` rerun is
    green (`4647` passed, `0` failed, `262` ignored; finished in `11832.87s`)
    after the retained-summary DA/RBC evidence hardening and default-feature
    STARK-only fixture gating.
  - For the next consensus change, rerun the same broad window so the collector
    fallback, exact-frontier repair, cached-target, vote replay, roster
    recovery, future-new-view, and model-backed reschedule fixtures continue to
    execute together rather than only as isolated filters.
- Broaden Sumeragi verification when new fatal hang classes are identified
  outside the current two-slot frontier abstraction.
  - The 2026-05-03 frontier formal process hardening is green and covers active
    pending progress touch, local-vote and commit-QC progress, stale recovery
    subject-view scope, vote-queue drain, payload recovery, quorum retransmit,
    retransmit follow-through, and future-slot promotion.
  - For any additional fatal hang shape, first add a focused Rust regression,
    then add the corresponding finite formal dimension or mutation so the
    expected-failure suite proves the model would have caught it.
  - If another restarted-peer catch-up issue appears in message admission or
    deduplication, add a small finite admission-order bridge or mutation before
    broadening the frontier model itself; the current model intentionally
    abstracts network-message dedup away.
  - Keep this scoped to the observed hang surface; do not generalize the model
    into an arbitrary pipeline unless a new bug requires more than the active
    plus one-future-slot abstraction.
- Reopen the wider validation corridor after the recent focused `iroha_core`, `iroha_torii`, and `iroha_data_model` test additions.
  - `cargo test -p iroha_core --lib -- --nocapture` is green as of 2026-06-12
    (`4647` passed, `262` ignored); rerun it only after the next core/consensus
    change or before opening the full workspace corridor.
  - `cargo test -p iroha_torii` is green as of 2026-05-03 after fixing the
    macOS attachment-sanitizer subprocess wrapper path; rerun it after the next
    Torii/API change or before opening the full workspace corridor.
  - Rerun `cargo test -p integration_tests -- --nocapture` once the current
    tree is stable enough for network suites.
  - When validation budget allows, rerun `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings`, then capture failures or green status in `status.md`.
## Consensus and Izanami

- Maintain Izanami communication vulnerability publication evidence.
  - The exact-injector 75% packet-loss run at `dist/izanami-exact-packet-paper-20260426` and the 25%/50%/75% sweep at `dist/izanami-packet-sweep-paper-20260427-loss-only` are archived pre-release evidence recorded in `status.md`; they used the retired production-wide P2P packet-drop controls and are not a current release baseline.
  - First-release Izanami has no executable `packet-loss` profile. The matrix preserves the paper's Loss column as a reference-only `not-run` row, while `leader-isolation` follows Sumeragi leader telemetry and applies the existing network-partition approximation.
  - The 2026-04-27 quick matrix at `dist/izanami-quick-both-20260427` is historical pre-hard-cut evidence. The post-ingress-hardening leader-isolation rerun at `dist/izanami-quick-leader-retry-20260427` also predates the switch from packet-drop injection to the network-partition approximation.
  - The result-strengthened matrix and sweep tooling is implemented as of 2026-04-28, including bounded shutdown-drain accounting, latency/recovery evidence, NPoS repair-coverage telemetry, generated `paper-style-final-report.md`, and separate `stress-400` / `stress-800` profiles.
  - Archived seed-7 stress evidence at `dist/izanami-stress-400-seed7-20260428` and `dist/izanami-stress-800-seed7-20260428` was green as of 2026-04-29: both profiles reported 14/14 resilient pre-hard-cut rows across permissioned and NPoS Sumeragi, with no `confirmation_queue_dropped` pressure. This remains historical evidence in `status.md`, not the current scenario count.
  - Run the full paper/stress seed sweep with fresh binaries when validation budget allows: `scripts/run_izanami_communication_vulnerability_sweep.sh --profiles paper,stress-400,stress-800 --sumeragi-mode both --seed-list 7,11,13,17,19,23,29,31,37,41`. Executable paper rows must remain `resilient`; stress rows should stay reported separately as margin evidence across broader seeds.
  - Keep future publication reruns split with `--sumeragi-mode both` so permissioned and NPoS Sumeragi classifications are not collapsed. Preserve the paper's packet-loss classifications as reference data, but do not emit executable or per-loss Iroha subrows.
- Recalibrate the Izanami stable-profile acceptance envelope for sustained workload targets.
  - The fresh 4-peer permissioned `1 TPS` / `300s` / `100 blocks` gate at `dist/izanami-stable-gate-20260427-target100` is green and recorded in `status.md`.
  - The matching `200`-block diagnostic at `dist/izanami-stable-gate-20260427-rerun` crossed the prior stall region and reached strict/quorum height `107` with zero submission or confirmation failures, but missed the target because the stable workload drained before `200` blocks.
  - Before the longer `3600s` / `2000+` block acceptance pass, choose a sustained-workload gate or lower short-run target so the KPI measures liveness instead of exhaustion of submitted work.
- Root-cause the remaining NPoS soak/localnet collapse instead of keeping it as a log-only symptom.
  - Reproduce with preserved peer dirs and `iroha_futures::supervisor=debug`.
  - Identify the first exiting supervised child before investigating downstream connection refusals.
  - Cross-check peer logs with `/v1/sumeragi/status` counters so the fix targets the actual failing layer.

## Throughput and query performance

- Re-establish current throughput knees for the de-amplified harness and shared-host localnet.
  - Rerun the stepped single-host sweep.
  - Repeat permissioned and NPoS passes on the same hardware envelope and compare against the archived `25-50 TPS` / `75-100 TPS` baselines.
  - Record the new knee points and any regressions in `status.md`.
- Carry the 2026-05-02 Norito/Crypto scalar hot-path slice through the remaining
  release validation corridor.
  - The Ed25519 admission follow-up now caches deterministic 32-byte invalid
    public-key parse outcomes, routes compact/full conversion through the
    cached parse path, widens the hot thread-local parse/verify caches for the
    20k stable workload window, skips signature parsing and dalek batch setup
    for all-cached exact verify tuples, and preserves lowest-original-index
    failure reporting for mixed batches. Focused crypto/Torii checks and the
    `ed25519_hotpaths` Criterion bench are recorded in `status.md`.
  - Remaining local benchmark baselines: `cargo bench -p iroha_data_model
    --bench chain_wire`, `cargo bench -p iroha_data_model --bench
    decode_registry`, and `cargo bench -p iroha_core --bench crypto_hotpaths`.
  - The latest 120s release gate rerun exists at
    `dist/izanami-prebuilt-20k-rerun-release-ed25519-cache-120s-20260502-180614`
    and is recorded in `status.md`; the wrapper exited `0`, but it is not a
    clean all-accepted ingress gate. It offered all `2,400,000` planned
    submissions, accepted `2,364,756`, reported `35,244` failures, and reached
    strict approved transactions `20,582` at strict height `7`, with the queue
    still saturated. Active build/gate process lines were captured before and
    after the run, so it remains diagnostic evidence only.
  - The latest contended 30s sampled profile exists at
    `dist/izanami-profile-20k-ed25519-cache-sampled3-30s-20260502-182524`
    and is recorded in `status.md`. It submitted and accepted all `600,000`
    planned ingress attempts but only reached strict approved transactions
    `4,113` at strict height `3`, with the queue still saturated. The next
    bottleneck focus remains peer CPU: FASTPQ transcript finalization over
    Norito account/numeric/array serialization into Poseidon byte hashing;
    Ed25519/Curve25519 batch-verifier miss work and public-key parse/decode
    misses; Norito transaction/signature decode and compact-length work; and
    smaller allocation/copy/CRC64 costs. It is not a clean comparable baseline
    because workspace `cargo test`/rustc and another debug test network were
    active before and after the run.
  - The FASTPQ GPU follow-up is now recorded in `status.md`: Metal toolchain
    preflight is green, `bn254_poseidon_words` uses the Metal backend,
    transcript digest finalization overlaps Metal dispatch with CPU work,
    execution-witness digest propagation avoids a duplicate witness-side
    finalization, the final `fastpq-gpu` 120s release gate accepted all
    `2,400,000` offered submissions and reached `36,986` strict-approved
    transactions, and the delayed load-window sampled peer stacks have no
    scalar `poseidon3_permute` or CPU FASTPQ fallback. CUDA hardware closure
    evidence was captured later on 2026-05-19 and is recorded in `status.md`.
  - The 2026-05-05 hardware-backed FASTPQ Metal parity rerun on macOS is green
    after repairing Goldilocks FFT/LDE, BN254 LDE, and Poseidon Metal/CPU
    mismatches. CUDA hardware closure evidence was captured later on
    2026-05-19 and is recorded in `status.md`.
  - The next throughput slice should target the post-GPU peer CPU stack:
    Ed25519/Curve25519 public-key parse and verification, Norito
    transaction/transfer serialization and decode, transaction metadata
    hashing, allocation/copy traffic, and CRC64/SHA-256 helpers. The first
    bookkeeping slice already removed per-transaction `DashMap::len()` from
    `PipelineStatusCache::prune_if_needed`, and the Ed25519 thread-local slice
    now includes a direct-mapped full-key cache before the generic linear
    verifier cache. The current allocation slice streams typed Norito hashes
    directly into Blake2b, finalizes direct Blake2b hashes into fixed buffers
    without boxed digest allocation, absorbs Merkle parent/commitment chunks
    without staging concatenation buffers, and hashes external transaction
    entrypoints through a borrowed encoder instead of cloning the signed
    transaction into an enum wrapper. The release Izanami/iroha3d binaries now
    rebuild with the allocation slice, and the clean return gate at
    `dist/izanami-prebuilt-20k-fastpq-gpu-return-120s-20260504-012106`
    restored ingress (`2,400,000` accepted and succeeded, `0` failures) but
    still reached only `12,413` strict-approved transactions at height `5`.
    The matching sampled profile at
    `dist/izanami-profile-20k-fastpq-gpu-return-sampled-30s-20260504-012521`
    was intrusive, but its peer stacks confirm the next work remains
    Ed25519/Curve25519 parse and verification, Norito transaction/transfer
    encode/decode, metadata hashing, allocation/copy traffic, and SHA-256/CRC64
    helpers. A first queue-lock slice now releases `push_remove_lock` before
    post-enqueue backpressure/gossip/event/wake side effects. The follow-up
    bottleneck fix repairs the post-queue-lock execution-context mismatch,
    moves RBC READY/DELIVER traffic onto the consensus-chunk lane, gives chunk
    traffic a turn after each high-priority payload frame, caches prepared
    metadata JSON depth, and keeps prepared metadata depth checks on the
    static-validation hot path. The clean rebuilt
    `20k TPS` / `120s` `fastpq-gpu` gate at
    `dist/izanami-prebuilt-20k-fastpq-gpu-bottleneckfix-120s-20260504-183724`
    accepted and succeeded all `2,400,000` submissions with no safety failures
    and reached `37,000` strict-approved transactions at height `11`, but queue
    saturation remained (`854,344 / 2,400,000`). The matching sampled profile at
    `dist/izanami-profile-20k-fastpq-gpu-bottleneckfix-peer-sampled-30s-20260504-184154`
    shows no scalar FASTPQ/Poseidon fallback; the next bottlenecks are block
    validation and serialization costs: Ed25519/Curve25519 verification math,
    Norito compact-length and transaction/transfer encode/decode,
    allocator/reallocation and copy traffic, SHA-256/Blake2/CRC64 helpers,
    `resolve_streaming_metadata`, and pipeline access/overlay preparation.
    A final prepared-hash cleanup after that profile avoids temporary
    signed-transaction byte vectors while preparing hashes/lengths and reuses
    prepared payload/signed hashes in validation cache and signature-batch
    paths. The current-code `20k TPS` / `120s` rerun at
    `dist/izanami-prebuilt-20k-fastpq-gpu-return-current-120s-20260504-194602`
    covered that cleanup: Izanami exited `0`, accepted and succeeded all
    `2,400,000` submissions, recorded no safety failures, and had submit
    latency `p50=6ms`, `p95=21ms`, `p99=99ms`, `max=269ms`. Strict progress
    was lower than the previous gate at `32,956` approved transactions at
    height `10`, with queue saturation still high (`883,791 / 2,400,000`) and
    commit-pipeline EMA `592ms`. Treat the 20k ingress path as restored; the
    committed-throughput target still needs the next validation/serialization
    hotspot pass. The fresh current-code profiles refine that target: the
    immediate `30s` sample at
    `dist/izanami-profile-20k-fastpq-gpu-current-peer-sampled-30s-20260504-195325`
    shows FASTPQ Metal pipeline creation still happens on the first proof hot
    path, while the delayed post-warm `60s` sample at
    `dist/izanami-profile-20k-fastpq-gpu-current-peer-postwarm-sampled-60s-20260504-195720`
    moves the steady-state bottleneck back to validation and serialization.
    The 2026-05-05 FASTPQ lane preflight follow-up moves backend construction
    off the startup/submission path, keeps digest acceleration disabled until
    the lane observes successful GPU preflights, and falls back to CPU prover
    modes after a failed Poseidon GPU preflight. The current May 6 return gate
    at
    `dist/izanami-prebuilt-20k-fastpq-gpu-return-current-120s-20260506-124641`
    accepted and succeeded all `2,400,000` submissions with no safety failures
    and reached `49,428` strict-approved transactions at height `14`, above the
    previous `45,191` preflight gate. Treat first-proof FASTPQ GPU preflight
    and the latest single-transfer digest deferral path as addressed for now;
    the next open work is Ed25519/public-key parse and verify work, Norito
    transaction and transfer encode/decode/length accounting, allocation/copy
    churn, queue-admission/world-view preparation, and queue drain under
    saturated 20k ingress. That older profile avoided scalar FASTPQ/Poseidon
    fallback work until new evidence; the May 7 load-window sample below
    reintroduces scalar cost specifically in the BN254 runtime digest path,
    while general FASTPQ prover parity remains fixed.
    The 2026-05-07 Metal final return gate fixes general FASTPQ Poseidon
    preflight parity and removes normal commit-QC inline validation supersedes;
    keep the next Izanami pass on queue drain/block-validation cost and BN254
    runtime Metal batch stability, not on prover Poseidon preflight parity.
    The corrected load-window profile at
    `dist/izanami-profile-20k-fastpq-gpu-final-loadsample-90s-20260507-225637`
    sharpens that order: scalar Halo2 BN254 Poseidon is again the top sampled
    application leaf after runtime Metal batch failures, while consensus
    progress is limited by payload availability and exact-frontier recovery
    signals under a saturated queue. Fix BN254 runtime batch stability first,
    then reduce local READY/DELIVER deferrals and block-body reacquisition
    latency before revisiting the secondary Norito, Ed25519/Curve25519, SHA-2,
    Blake2, CRC64, and allocation hot paths.
  - Avoid repeating the rejected process-wide Ed25519 public-key parse cache
    approach without new evidence: the 2026-05-03 sharded shared-cache
    experiment regressed short-gate commit progress and was backed out. Keep
    near-term Ed25519 work thread-local, allocation-focused, or validation-path
    specific unless a clean before/after gate proves otherwise. The accepted
    thread-local slice pre-sizes only the public-key parse map, keeps parsed key
    entries boxed to satisfy `variant-size-differences`, and keeps the generic
    verify-ok map lazy so 32-byte transaction hashes do not allocate unused
    generic cache state.
  - Keep broader trait-wide parallel decode, deeper GPU decode materialization,
    deeper dalek backend experimentation, and deterministic hardware-specific
    Ed25519/Curve25519 acceleration as follow-up work until the current
    bottleneck slice has clean before/after evidence.
- Continue the 20k post-cache throughput tuning corridor.
  - The first post-cache 4-peer no-fault prebuilt `20k TPS` / `120s` release
    gate at `dist/izanami-prebuilt-20k-hotpath-120s-20260501-142015` improved
    strict approved transactions to `28,713` but still failed the committed
    20k target.
  - A same-shape repeat at
    `dist/izanami-prebuilt-20k-cachepass-120s-20260501-142429` accepted
    `52,167` ingress transactions but only reached `24,623` strict approved
    transactions, confirming material run-to-run variance and the same
    queue-drain/block-validation bottleneck.
  - The fresh post-cache sampled 20k profile at
    `dist/izanami-profile-20k-cachepass-sampled-30s-20260501-152126` confirms
    the next target has moved from queue gossip encoding to
    `validate_block_for_voting` / `validate_and_record_transactions` /
    `TxOverlay::apply_with_chunk`, incoming transaction-gossip Norito decode,
    and the remaining `AcceptedTransaction::signed_encoded_len` serialization
    fallback.
  - The targeted post-cache tuning pass at
    `dist/izanami-prebuilt-20k-postcache-tuned-120s-20260501-165947` improved
    strict approved transactions over the cachepass repeat to `28,790`, but
    still failed the committed 20k target and accepted fewer ingress
    submissions. The matching sampled profile at
    `dist/izanami-profile-20k-postcache-tuned-sampled-30s-20260501-165811`
    confirms `Queue::encode_gossip_payload`, `TxOverlay::byte_size`, and
    `external_entrypoints_cloned` are absent from current peer samples.
  - The further conservative cache pass is focused-validation green as of
    2026-05-01: prepared transaction metadata is reused through block
    validation/execution recording, all-external block validation keeps
    borrowing the entrypoint slice, signed/external entrypoint encoded-length
    coverage avoids the residual Norito fallback for representative shapes, and
    gossip transaction decode now uses the shared cached payload helper.
  - Rechecked 2026-06-04: the focused `AcceptedTransaction` signed-length,
    decoded-versioned signed transaction, and gossip signed-metadata regressions
    remain green. No additional no-wire-change edit is obvious without a fresh
    sampled profile showing `signed_encoded_len` as a material current bottleneck.
  - The clean release 4-peer no-fault prebuilt `20k TPS` / `120s` rerun at
    `dist/izanami-prebuilt-20k-conservative-cache-rerun-120s-20260501-175213`
    exited `0`, accepted `54,574` ingress transactions, and reached `28,710`
    strict approved transactions at strict height `9`. This is consistent with
    the prior tuned gates and still misses the committed 20k target, with no
    validation rejects, view changes, or RBC pressure.
  - A later requested same-shape rerun at
    `dist/izanami-prebuilt-20k-conservative-cache-rerun2-120s-20260501-144548`
    exited `0` but ran under active debug `cargo test`/`rustc` contention. It
    accepted `52,070` ingress transactions and reached only `12,329` strict
    approved transactions at strict height `5`, with safety intact but `4`
    view-change installs and missing-block recovery activity. Treat this as
    contended evidence only, not a replacement for the clean baseline.
  - The matching requested contended sampled profile at
    `dist/izanami-profile-20k-conservative-cache-rerun2-sampled-30s-20260501-145104`
    exited `0` with valid samples for the load driver and all four peers;
    `sample_status=1` only because the sampler also targeted the bash wrapper
    and one transient process. It accepted `52,817` ingress transactions and
    reached `4,137` strict approved transactions at strict height `3`. The
    bottleneck shape matches the previous conservative-cache profiles: Torii
    admission crypto/public-key parsing, canonical signed-byte construction,
    residual dynamic `InstructionBox` framing, gossip materialization/decode,
    and overlay execution/cloning. Treat it as contended bottleneck evidence,
    not a clean latency baseline.
  - The earlier conservative-cache sampled 20k profile at
    `dist/izanami-profile-20k-conservative-cache-parallel-sampled-30s-20260501-181025`
    confirms the previous removals are still absent
    (`Queue::encode_gossip_payload=0`, `TxOverlay::byte_size=0`,
    `external_entrypoints_cloned=0`) and moves the next bottleneck set to
    Torii ingress signature/public-key work, canonical signed-byte construction
    in `AcceptedTransaction::from_external_with_hot_cache`, exact-length
    `InstructionBox` payload framing, gossip materialization during admission,
    and remaining overlay instruction clones.
  - The broader 20k bottleneck pass is focused-validation green as of
    2026-05-01. Lazy transaction-gossip materialization now preserves cached
    framed entrypoint bytes and skips semantic decode before route, plane, and
    known-duplicate filters; route-valid single-key Ed25519 gossip candidates
    use deterministic batch precheck through the existing signature-batch
    setting; overlay apply goes through the crate-private borrowed adapter while
    custom executors keep the owned path. The profile at
    `dist/izanami-profile-20k-postcache-tuned-bottleneck-30s-20260501-171955`
    is pre-broader-pass evidence; the fresh reruns are
    `dist/izanami-profile-20k-broader-pass-sampled-30s-20260501-194734` and
    `dist/izanami-prebuilt-20k-broader-pass-120s-20260501-194908`.
    The 120s gate kept final approved transactions flat against the previous
    gate (`28740` vs `28710`) but accepted fewer ingress submissions
    (`52291` vs `54574`), so treat the pass as bottleneck reshaping rather than
    a confirmed throughput win.
  - The fixed-runner follow-up sampled profile at
    `dist/izanami-profile-20k-broader-pass-rerun-sampled-30s-20260501-200527`
    completed with `sample_status=0` and sampled the actual Izanami runner plus
    all observed peer processes. It classifies the next bottlenecks as
    direct-peer Ed25519/curve25519 verification math first, then allocation /
    `memmove` and Norito compact/decode work, with ZK/BLS math and hashing as
    secondary costs. Queue mechanics and borrowed overlay apply are not primary
    CPU bottlenecks in that sample.
  - The latest clean rebuilt release 4-peer no-fault prebuilt `20k TPS` /
    `120s` gate is
    `dist/izanami-prebuilt-20k-direct-ingress-precheck-final-120s-20260501-212850`;
    it exited `0`, accepted `47,566` ingress transactions, and reached
    `20,499` strict approved transactions at strict height `7`. The contention
    snapshots only contain timestamps. Safety signals stayed clean, but the
    run still saturated the queue and ended with height skew `1` /
    approved-transaction skew `8,192`, so the 20k target remains open.
  - The latest fixed-runner sampled profile at
    `dist/izanami-profile-20k-rerun-release-sampled2-30s-20260501-211211`
    completed with `sample_status=0`, accepted `46,709` ingress transactions,
    and reached `4,125` strict approved transactions at strict height `3`.
    The current peer CPU stack is led by `iroha_zkp_halo2::poseidon` /
    `fastpq_isi::poseidon`, `memmove` and allocator paths, `sha2`/`blake2`
    hashing, Norito compact-length/decode/encode routines, and then
    `curve25519_dalek` / `ed25519_dalek` verification math. Direct ingress
    batch precheck remains visible but is not the dominant leaf in this sample;
    overlay clone and exact-length helpers are low-count residue.
  - The direct-ingress conservative cache and precheck slice is code-complete
    as of 2026-05-01: Torii signed transaction and batch submission now decode
    versioned signed payloads into a prepared core admission token and run
    deterministic single-Ed25519 batch precheck for eligible batch entries,
    reusing signed/entrypoint hashes, payload hash, exact signed length, and
    parsed single-Ed25519 key metadata without changing transaction wire/hash
    semantics, config knobs, dependencies, or `Cargo.lock`.
  - The exact-length `InstructionBox` cost is reduced without changing Norito
    wire: `encoded_len_exact` now counts the existing `(wire_id,
    framed_payload)` representation without re-framing the dynamic ISI payload.
  - The FASTPQ/Poseidon foreground pass is implemented: single-delta transfer
    transcript digests are finalized at block/witness drain instead of inside
    `Transfer::execute`, FASTPQ digest hashing streams bytes without a full
    preimage buffer, and decoded external entrypoint hashes now reuse the
    inbound versioned signed payload bytes.
  - The first FASTPQ BN254 Metal Poseidon batch path is implemented behind the
    existing `fastpq-gpu` feature and existing FASTPQ execution/poseidon modes.
    Later Metal and CUDA parity/performance closure evidence is recorded in
    `status.md`; this historical slice no longer carries open GPU validation
    work.
  - Carry the Norito sequence span planner through the remaining acceleration
    corridor: replace the length-prefixed helper's serial device parser with a
    tuned prefix-scan/chunked planner if profiling shows it is on the hot path,
    optimize proven transaction/admission/block-validation consumers directly
    instead of reviving the retired generic parallel decoder, then rerun the 30s
    sampled 20k profile and 120s gate with the target host's acceleration
    features.
  - The latest scalar release 4-peer no-fault prebuilt `20k TPS` / `120s` gate
    after the Norito span-planner pass is
    `dist/izanami-prebuilt-20k-rerun-release-norito-span-120s-20260502-015557`;
    it exited `0`, accepted `47,503` ingress transactions, reached
    strict/quorum height `10`, and approved `32,786` transactions. The latest
    matching scalar sampled profile is
    `dist/izanami-profile-20k-norito-span-sampled-30s-20260502-020217`; it
    shows Norito transaction/instruction codec as the current top active peer
    path, followed by Poseidon/Ed25519/Curve/hash work, Rayon proof/hash
    scheduling, allocation/copy churn, TLS/context lookup, and Torii admission
    queue routing. Use this artifact as the baseline before the next
    optimization pass.
  - Continue reducing Norito decode/allocation overhead on the direct and
    gossip admission corridors without changing wire bytes or canonical hashes.
    `InstructionBox::DecodeFromSlice` now uses the borrowed tuple parser
    directly and `ExecutionStep::DecodeFromSlice` now delegates its inner
    instruction list to `ConstVec<InstructionBox>`. `ConstVec<T>` slice decode
    now tries the scalar Norito sequence planner directly for non-`u8` elements
    before falling back to the canonical `Vec<T>` field path, removing the
    top-level archive/canonical-length pass from the hot instruction-vector
    route. `AcceptedTransaction` also now derives the cached signed frame and
    external entrypoint hash from one canonical signed payload in the hot-cache
    path, avoiding a second signed-transaction serialization. `SignedTransaction`
    and `TransactionPayload` slice decoders now walk AoS fields directly, and
    `Executable::Instructions` routes the instruction vector into the planned
    `ConstVec<InstructionBox>` decoder before falling back for other executable
    variants. A fresh WSL2 no-profiler validation run after this
    admission-decode pass is recorded in `status.md`:
    `dist/izanami-prebuilt-20k-admission-decode-unsampled-30s-20260506-020112`
    accepted/succeeded all `600,000` offered submissions, and
    `dist/izanami-prebuilt-20k-admission-decode-120s-20260506-020335`
    accepted/succeeded `2,379,055` submissions with no safety failures but only
    `20,553` strict-approved transactions. Treat these as fresh ingress/safety
    evidence, not a bottleneck profile: the host had neither `sample` nor
    `perf`, and the 2.4M prebuilt-buffer run consumed nearly all WSL2 memory.
    Individual instruction payload slice paths are now in place for `Log`,
    `RecordSccpMessage`, the canonical grouped instruction boxes
    (`RegisterBox`, `UnregisterBox`, `MintBox`, `BurnBox`, `TransferBox`,
    `SetKeyValueBox`, `RemoveKeyValueBox`, `GrantBox`, `RevokeBox`,
    `RwaInstructionBox`, `RepoInstructionBox`, and `SettlementInstructionBox`),
    transfer batches, account signatory/quorum changes, the stable core
    SetParameter/trigger/upgrade/custom ISIs, asset-definition
    alias/balance-policy instructions, asset transfer-control instructions,
    account alias binding/lease instructions, contract-alias instructions,
    account-recovery instructions, RAM-LFE program-policy instructions,
    hidden-identifier instructions, consensus-key lifecycle instructions,
    domain-endorsement instructions, verifying-key instructions, Offline
    note instructions, verified Nexus lane-relay/fee-budget instructions,
    native numeric asset escrow lifecycle instructions, Musubi
    package-registry instructions, smart-contract-code
    manifest/instance/bytecode instructions, the Space Directory manifest
    lifecycle instructions, SoraFS pin/capacity/replication/provider-owner plus
    pricing/credit instructions, oracle feed/observation/dispute/governance/
    Twitter binding instructions, bridge proof/receipt/SCCP instructions,
    Ministry citizen-agenda proposal submission, social Twitter reward/escrow
    instructions, registered public-lane staking instructions, invalid-
    instruction placeholders, SoraNet VPN lease open/settle/refund instructions,
    runtime-upgrade ISIs, SNS name ISIs, ZK proof/confidential/election ISIs,
    Kaigi session/relay ISIs, governance proposal/ballot/citizen ISIs,
    Soracloud service lifecycle, host/placement, agent, model/training,
    rollout, runtime-state, mailbox, and receipt ISIs, and Nexus
    emergency-validator override ISIs via an opt-in registry constructor. The
    default registry no longer exposes direct grouped generic wire forms such
    as `Register<Domain>`, concrete mint/burn/transfer variants,
    `Grant<Permission, Account>`, `RepoIsi`, or `DvpIsi`; canonical clients use
    the grouped boxes. Remaining targets are the standalone entries that still
    use the generic constructor, broader allocation/memmove churn around
    transaction admission material, and a sampled 30s profile plus clean 120s
    gate on a profiler-equipped host after the next scalar admission-decode
    pass.
  - The FASTPQ BN254 Metal validation was completed in later accelerator
    closure passes recorded in `status.md`; keep new profiling here focused on
    the remaining scalar admission/decode and Ed25519 authority costs.
  - Keep an Ed25519 parsed-public-key/signature verification cache or a
    deterministic batch corridor for the Torii/direct-ingress single-key
    Ed25519 authority path as the next crypto follow-up after the
    Poseidon/source-attribution and Norito allocation work. Gossip-side
    deterministic Ed25519 batch precheck is already implemented, and the
    crypto-layer direct/preparsed Ed25519 batch APIs now filter exact
    verify-cache hits before signature parsing; the thread-local exact
    verify-ok cache also keeps two colliding entries per slot. Peer-trust gossip
    entry signing now routes through `Signature::try_new` and skips logged
    per-entry failures instead of unwinding the broadcast loop; local Sumeragi
    consensus vote signing now routes through `Signature::try_new` and skips
    logged vote-emission failures instead of unwinding the commit/precommit
    path, while native AMX vote, merge committee, and RBC ready/deliver
    wire-message signing now share the same checked consensus preimage helper
    and skip logged local emission failures; the consensus-preimage signing
    regression now also derives its BLS fixture key through
    `KeyPair::try_from_seed`; contract
    manifest provenance signing now exposes `ContractManifest::try_signed`, and
    the CLI build/deploy, Torii app API deployment prep, and Connect Norito
    governance propose-deploy bridge paths propagate signing failures through
    existing `Result` surfaces; runtime-upgrade manifest provenance signing now
    exposes `RuntimeUpgradeManifest::try_signed` while preserving canonical
    payload stability after provenance attachment; queue-backed Soracloud
    runtime mutation submissions and Nexus fee relay worker submissions now use
    `TransactionBuilder::try_sign` helpers and return endpoint-specific `eyre`
    context before acceptance/enqueueing on backend signing failure; CLI
    contract simulation now
    signs its locally built transaction through `TransactionBuilder::try_sign`
    and returns a contextual command error on backend signing failure; Torii
    proof-record signed-query construction now uses
    `QueryRequestWithAuthority::try_sign`, data-model `BlockBuilder` now
    exposes `try_build_with_signature` so incremental block assembly can
    propagate `SignatureOf::try_from_hash` failures while keeping the
    compatibility block-signing helper, `SignedBlock` genesis assembly now
    exposes checked variants that return signing failures and reject empty
    transaction sets without panic-only construction, and default streaming key material in
    test/restored state construction uses nonzero deterministic seed material
    under the all-zero seed admission policy; client query request body assembly
    now uses `QueryRequestWithAuthority::try_sign` and returns a contextual
    `QueryError` before HTTP dispatch on backend signing failure; crypto
    `KeyPair::from_private_key` fixtures now use checked random key generation
    before Ed25519, secp256k1, ML-DSA, BLS, and GOST reconstruction regressions
    consume source key material; data-model
    `QuerySignature` roundtrip fixtures now use checked Ed25519 key generation
    plus `SignatureOf::try_new`, verifying typed query payload signatures before
    serialization; data-model Taikai segment signing manifest fixtures now use
    checked seeded Ed25519 key generation plus `SignatureOf::try_new`, verifying
    typed body signatures before Norito roundtrip; data-model moderation
    reproducibility manifest fixtures now use checked random Ed25519 key
    generation plus `SignatureOf::try_new`, verifying typed body signatures
    before validation consumes them; data-model RAM-LFE receipt and
    output-opening fixtures now use checked random Ed25519 key generation plus
    `SignatureOf::try_new`, verifying typed signatures before wrong-key and
    tamper regressions consume them; data-model governance parliament roster and
    enactment certificate fixtures now use checked random Ed25519 key generation
    plus `SignatureOf::try_new`, verifying typed enactment signatures before
    Norito roundtrips consume them; data-model escrow record roundtrip fixtures
    now use checked deterministic Ed25519 seed expansion for seller and buyer
    account keys; core native escrow custody account derivation now uses checked
    Ed25519 seed expansion and propagates seed rejection as an instruction
    invariant error; data-model oracle provider-account fixture helpers now use
    checked Ed25519 seed expansion before committee, report-cap, and aggregation
    tests consume them; data-model runtime-upgrade manifest provenance fixtures
    now use checked random Ed25519 key generation before signature-payload
    exclusion coverage consumes them; data-model formal verification snapshot
    fixtures now use checked random Ed25519 key generation before valid,
    inconsistent, and cross-domain owner regressions consume their account IDs;
    data-model identifier receipt fixtures now use checked random/seeded Ed25519
    key generation plus `SignatureOf::try_new`, verify output-opening
    signatures, and reject padded resolver-key/policy-id fixture mutations
    before canonical parsing;
    data-model hidden-identifier instruction receipt fixtures now use checked
    seeded Ed25519 key generation plus `SignatureOf::try_new`, verifying
    output-opening and receipt signatures before Norito instruction roundtrips
    consume them;
    data-model alias account, asset id literal, and transaction submission
    receipt fixtures now use checked random Ed25519 key generation before
    canonical formatting and receipt-signature coverage consumes them;
    data-model Kaigi host, participant, relay manifest, feedback, and allowlist
    fixtures now use checked random Ed25519 key generation before Norito and
    membership regressions consume them;
    data-model state-key, account JSON-key codec, and trigger authority fixtures
    now use checked random Ed25519 key generation before canonical state/JSON
    and trigger-filter regressions consume them;
    data-model block proof, block-header signature, and block-builder signature
    fixtures now use checked random/seeded key generation plus fallible
    transaction signing before Merkle receipt and block-signature regressions
    consume them;
    core transaction multisig bundle, fraud attester, and state-manifest quorum
    fixtures now use checked `SignatureOf::try_new` /
    `KeyPair::try_from_seed`, with mixed-curve quorum,
    missing/unknown/disallowed signer, insufficient weight, signature-limit,
    fraud-attester, and manifest-quorum regressions rerun;
    data-model consensus roster, fee receipt, reconfiguration, RBC leader, and
    censorship-evidence receipt fixtures now use checked random key generation
    and fallible receipt signing before consensus codec regressions consume
    them;
    data-model account, multisig, account JSON, and account-address vector
    fixtures now use checked random/seeded key generation, with the ADDR-2
    default vector moved off an all-zero Ed25519 seed before account/address
    regressions consume it;
    data-model consensus DTO checkpoint, commit-QC, and consensus-key liveness
    fixtures now use checked random BLS/default key generation before consensus
    roundtrip and liveness regressions consume them;
    data-model Kaigi relay event, lane-relay QC, and consensus-state QC
    fixtures now use checked random key generation before Norito event, lane
    envelope, and consensus persistence regressions consume relay or validator
    identities;
    data-model fraud risk-query and governance-export account fixtures now use
    checked random Ed25519 key generation before fraud governance regressions
    consume them;
    data-model Nexus relay fee-receipt and sponsor-account digest fixtures now
    use checked random Ed25519 key generation before relay claim and budget
    digest regressions consume them;
    data-model lightweight query, RWA, peer, ID-constructor, mutator,
    pointer-ABI, and signed-block roundtrip fixtures now use checked random key
    generation before Norito/JSON, constructor, and block-signature regressions
    consume generated identities;
    executor data-model multisig account fixtures now use checked deterministic
    Ed25519 seed expansion, with the sample registration helper moved off an
    all-zero registrar seed before multisig JSON and instruction regressions
    consume them;
    high-level `iroha` Rust SDK account-address I105 fixtures now use checked
    deterministic Ed25519 seed expansion before roundtrip, data-model parity,
    and parse error-code regressions consume them;
    high-level `iroha` user-config timeout helper fixtures now use checked
    deterministic Ed25519 seed expansion before config parse regressions consume
    them;
    high-level `iroha` config env-fallback and query accept-header fixtures now
    use checked random Ed25519 key generation before config parsing and signed
    query assembly regressions consume them;
    `iroha_config` NPoS timeout dummy peer fixtures now use checked random key
    generation before lane-catalog, trusted-peer, and timeout/default
    regressions consume peer identities;
    integration Norito Streaming publisher/viewer and Sumeragi collector-plan
    peer fixtures now use checked random key generation before key-update,
    feedback-loopback, manifest helper, and collector-routing regressions
    consume identities;
    integration sorting account-order fixtures now use checked random Ed25519
    key generation before metadata sorting regressions consume generated
    identities;
    integration CLI local config fixtures now use checked random Ed25519 key
    generation before client TOML/env regressions consume account material;
    integration transfer-domain negative-owner fixtures now use checked random
    Ed25519 key generation before four-peer genesis/domain-transfer regressions
    consume generated owner identities;
    integration address-canonicalisation alias-query fixtures now use checked
    random Ed25519 key generation before four-peer account-query regressions
    consume generated alias identities;
    integration by-call trigger permission-client fixtures now use checked
    random Ed25519 key generation before four-peer trigger-registration
    regressions consume generated authority identities;
    high-level `iroha` Nexus app facade wallet-signature, error-code,
    unsupported-key, and submit/status failure fixtures now use checked
    Ed25519/secp256k1 key generation before draft/finalize regressions consume
    them;
    high-level `iroha` client multisig, account-read, Sumeragi mismatch,
	    operator-header, and SoraFS repair transaction fixtures now use checked
	    random key generation plus checked transaction signatures before
    request/response regressions consume them;
    high-level `iroha` DA request-signing and rent-ledger account fixtures now
    use checked deterministic Ed25519 seed expansion before request digest and
    rent-transfer plan regressions consume them;
    core genesis bootstrap request fixtures now use checked random Ed25519 key
    generation before request roundtrip encoding consumes the expected public
    key;
    core queue regression transaction-authority fixtures now use checked random
    Ed25519 key generation before expiry and concurrent-drain regressions sign
    queued transactions;
    core queue stress transaction-authority fixtures now use checked random
    Ed25519 key generation before Arc-drain stress regressions sign expiring
    queued transactions;
    core IVM syscall admission transaction fixtures now use checked random
    Ed25519 key generation before unknown-syscall admission regressions sign
    IVM bytecode transactions;
    core ZK-STARK synthetic AIR admission fixtures now use checked random
    Ed25519 key generation before `IvmProved` admission regressions register
    accounts and build transactions;
    core contract-manifest trigger signer fixtures now use checked random
    Ed25519 key generation before manifest trigger activation regressions sign
    contract manifests;
    core governance minimum-duration, threshold, and protected-namespace
    fixtures now use checked random Ed25519 key generation before ballot,
    finalize, and manifest-provenance regressions consume signer material;
    core governance proposal-validation and unlock-sweep fixtures now use
    checked random Ed25519 key generation before proposal authority and
    lock-expiry regressions consume account key material;
    core contract-code registration and governance enact-deploy fixtures now use
    checked random Ed25519 key generation before code-byte storage, cap
    enforcement, and manifest enactment regressions consume account key
    material;
    core Sumeragi new-view stats fixtures now use checked random peer generation
    before deduplication, pruning, and poisoned-store recovery regressions consume
    peer IDs;
    core Sumeragi stake snapshot fixtures now use checked random keypair and peer
    generation before stake-map, fallback, quorum, and coverage regressions
    consume roster material;
    core confidential policy gate owner/recipient fixtures now use checked
    random Ed25519 key generation before transparent mint, transfer, and
    shielded-transition regressions consume account material;
    core ZK vote tally snapshot fixtures now use checked random Ed25519 key
    generation before verifier-key registration, election finalization, and
    tally syscall regressions consume account material;
    core ZK roots cap fixtures now use checked random Ed25519 key generation
    before authenticated confidential-state setup and roots-get syscall
    regressions consume account material;
    core ZK root-hint fixtures now use checked random Ed25519 key generation
    before stale/recent root-window regressions consume account material;
    core KAGEMUSHA audit fixtures now use checked random Ed25519 key generation
    before protocol-bound confidential-state regressions consume account
    material;
    core ZK asset verifier-key enforcement fixtures now use checked random
    Ed25519 key generation before offline top-up/redemption VK-role binding
    regressions consume account material;
    core fraud monitoring authority and attester fixtures now use checked
    random Ed25519 key generation before admission and attestation regressions
    consume signing material;
    core Sumeragi message fixtures now use checked random keypair and peer
    generation before block-message priority and certified fetch roundtrip
    regressions consume key material;
    core Sumeragi collector plan/routing fixtures now use checked random peer
    generation before PRF and fallback fanout regressions consume topology
    material;
    core Sumeragi vote duplicate and commit-vote block-sync fixtures now use
    checked BLS key generation before identity projection, PoP, and cached-vote
    regressions consume validator material;
    core Sumeragi consensus validator-set fixtures now use checked BLS key
    generation before fingerprint, handshake, QC bitmap, and consensus preimage
    regressions consume validator material;
    core Sumeragi block-sync snapshot, QC stake-root signer, proposal routing,
    vNext rechain/view-change, and evidence validation fixtures now use checked
    default/BLS key generation before snapshot, stake, transaction, certificate,
    and receipt regressions consume fixture material;
    core Sumeragi main-loop persisted-roster checkpoint and previous-block
    evidence block fixtures now use checked default/BLS key generation before
    fallback roster-selection regressions consume checkpoint and block material;
    core Sumeragi network-topology PRF collector, shared topology, role-filter,
    rotation, and shuffle fixtures now use checked default key generation before
    topology ordering and role-selection regressions consume peer material;
    core Sumeragi penalties censorship receipt, evidence roster, validator,
    escrow, and slashing fixtures now use checked default key/peer generation
    before penalty attribution and roster fallback regressions consume material;
    core Sumeragi status membership, RBC mismatch, vote-drop, validator
    checkpoint, consensus-key, availability, and precommit-signer fixtures now
    use checked default key/peer generation before telemetry history regressions
    consume peer material;
    core Sumeragi main-loop roster canonicalization, PoP, active-topology, NPoS
    lane, commit-topology, and local-validator fixtures now use checked BLS key
    generation before roster-selection regressions consume validator material;
    core Sumeragi block signing, trusted-roster PoP, roster adapter,
    requester/sender, RBC init, consensus-params, and direct block-sync permit
    fixtures now use checked default/BLS key generation before worker routing
    and admission regressions consume peer material;
    core Sumeragi main-loop commit genesis, worker, trusted topology, vote
    signing, block-sync target, cached-QC, commit-roster, and RBC payload
    fixtures now use checked default/BLS key generation before commit and
    recovery regressions consume peer material;
    the feature-gated core Sumeragi main-loop test harness peer-admin,
    block-sync cache, cached-QC, RBC rebuild, recovery, synthetic peer, and
    wrong-signature fixtures now use checked default, BLS, and
    algorithm-specific key generation before harness regressions consume
    account, peer, validator, and forged-signature material;
    core BLS batch PoP and adversarial block-rejection fixtures now use checked
    BLS key generation before PoP fallback, genesis, and block-history tamper
    regressions consume peer signing material;
    core bridge finality proof validator, quorum-subset, PoP, trusted-roster
    mismatch, and aggregate-signature fixtures now use checked BLS key
    generation before finality proof construction and verification regressions
    consume validator signing material;
    core admission-batching signature fixtures now use checked default and
    algorithm-specific key generation before Ed25519, Secp256k1, ML-DSA, and
    BLS batch-validation regressions consume signer material;
    core signature batch determinism account, bad-signature, genesis-leader,
    and block-leader fixtures now use checked Ed25519, Secp256k1, and BLS key
    generation before permutation-stability regressions consume signing
    material;
    core runtime-upgrade admission proposer, contract-admission signer, trusted
    provenance signer, and untrusted provenance signer fixtures now use checked
    default key generation before ABI, provenance, and admission regressions
    consume signing material;
    core IVM Corehost AXT replay block signer fixtures now use checked default
    key generation before Kura replay and apply-without-execution regressions
    consume block signing material;
    core Soracloud generated-HF primary validator, lease member, and primary
    peer fixtures now use checked default key generation before placement and
    primary-assignment regressions consume account and peer material;
    core bridge SCCP transaction, block, internal-entrypoint, and persisted-QC
    validator fixtures now use checked default/BLS key generation before
    message extraction and finality-proof regressions consume signing material;
    core Kiso common peer, genesis public key, network ACL allow/deny, and
    atomic-update replacement key fixtures now use checked default key
    generation before subscription and rollback regressions consume config key
    material;
    core smart contract code registry authority fixtures now use checked
    default key generation before manifest, bytecode, and protected activation
    regressions consume account signing material;
    core SNS genesis alias bootstrap genesis authority and registered account
    fixtures now use checked default key generation before domain and
    account-label bootstrap regressions consume account material;
    core pipeline overlay IVM, IVM-proved, STARK-proved, AXT, contract-binding,
    manifest-policy, and pre-execution authority fixtures now use checked
    default key generation before overlay construction regressions consume
    account signing material;
    core account-admission implicit receiver fixtures now use checked Ed25519
    key generation before mint, transfer, NFT, fee, role, and quota regressions
    consume account material;
    core content publish/retire authority fixtures now use checked default
    account generation before bundle manifest, chunk, stripe-layout, and
    retirement regressions consume publisher material;
    core repo custodian fixtures now use checked default account generation
    before initiation, participant-index, collateral-routing, and
    reverse-settlement regressions consume custodian material;
    core social UAID reward-account fixtures now use checked default key
    generation before UAID index selection regressions consume account
    material;
    core SoraDNS directory builder/release-signer fixtures now use checked
    Ed25519 key generation before draft submission and publish regressions
    consume signed directory material;
    core trigger dummy committed-block leader fixtures now use checked default
    key generation before trigger registration, metadata, activation, and
    retry-policy regressions consume block signing material;
    core specialized trigger loaded-action JSON authority fixtures now use
    checked default key generation before JSON roundtrip regressions consume
    action authority material;
    core ministry agenda proposal authority fixtures now use checked default
    account generation before persistence and duplicate-id regressions consume
    submission authority material;
    core RAM-LFE sample policy owner and resolver signer fixtures now use
    checked default key generation before receipt expiry, future-time,
    malformed-expiry, and proof-envelope regressions consume policy material;
    core query accepted-transaction signer and BLS/default block fixtures now
    use checked default, Ed25519, and BLS key generation before pagination,
    Kura lookup, and query-validation regressions consume signer material;
    core VPN voucher client, operator, custody, and escrow fixtures now use
    checked default key/account generation before voucher verification, tariff
    recomputation, overclaim rejection, and custody derivation regressions
    consume account and signing material;
    core Space Directory permission grantee, manifest authority, and
    UAID-bound account fixtures now use checked default key/account generation
    before manifest publish, revoke, expiry, and permission regressions consume
    account and signing material;
    core NFT dummy-block signer, permission holder, and transfer user fixtures
    now use checked default key/account generation before missing-domain,
    permission cleanup, transfer authorization, owner-index, and query-planner
    regressions consume account and signing material;
    core trigger-set JSON authority/account-replacement fixtures and DTO
    sample-set, active-index, repair, and retry authority fixtures now use
    checked default key/account generation before serialization, mutation, and
    active-trigger index regressions consume account and signing material;
    core RWA dummy-block signer, transfer recipient, controller, and query
    owner fixtures now use checked default key/account generation before
    register, split, full-transfer, control, owner-index, and query-planner
    regressions consume account and signing material;
    core account dummy-block signer, controller replacement, recovery owner,
    guardian, and replacement-controller fixtures now use checked default
    key/account generation before alias, controller migration, recovery
    timelock, quorum, and account query regressions consume account and signing
    material;
    core SoraFS council-envelope signer and missing provider-owner fixtures now
    use checked Ed25519/default key and account generation before manifest
    approval, digest/signature rejection, alias side-effect, provider-owner, and
    capacity regressions consume account and signing material;
    core staking dummy-block signers, admin multisig members, BLS peer PoP, and
    foreign/replacement validator peer fixtures now use checked default,
    Ed25519, and BLS key/peer generation before public-lane registration,
    rebind, topology, and stake-snapshot regressions consume account, peer, and
    signing material;
    core IVM host contract-management authority, peer registration, and
    signatory public-key fixtures now use checked default key/public-key
    generation before pointer-ABI syscall queueing regressions consume account,
    peer, and signing material;
    core telemetry commit-QC, tx-gossip, Sumeragi backpressure, online-peer,
    membership/RBC mismatch, BLS local-peer, and block payload fixtures now use
    checked default/BLS key and peer generation before metric/status
    regressions consume peer and signing material;
    core identifier policy owner, replacement account, resolver, and
    wrong-resolver fixtures now use checked default key/account generation
    before claim, revoke, signature, opening, expiry, and reclaim regressions
    consume account and signing material;
    core executor BLS peer, multisig-register account, transfer-permission
    account, heartbeat signer, and multisig direct-signing fixtures now use
    checked default, Ed25519, and BLS key/account generation before executor
    admission and permission regressions consume account, peer, and signing
    material;
    core Kura bench replica-advert, dummy block leader/signer, remote replica
    peer, BLS topology/roster, checkpoint replacement, and commit-manifest
    replacement fixtures now use checked default/BLS key and peer generation
    before storage, eviction, sidecar, checkpoint, and manifest regressions
    consume peer and signing material;
    core ISI module dummy block signer and contract-manifest signer fixtures
    now use checked default key generation before lane relay, fee-budget,
    metadata, trigger, contract-manifest, and stateless transaction regressions
    consume block and signing material;
    core world ISI dummy block leader/signer, lane relay sample block, role
    authority, multisig member, domain/account cleanup, lane emergency
    validator, domain endorsement signer, peer registration, and consensus-key
    lifecycle fixtures now use checked default, Ed25519, BLS-normal, and
    BLS-small key generation before world ISI regressions consume account,
    peer, block, endorsement, and consensus-key material, and the SCCP
    cross-lane route-canary replay regression now accepts the
    route-profile-first rejection path;
    core domain ISI owner-index, account-label, alias binding, multisig member,
    unregister guard, asset-definition cleanup, settlement/repo, offline
    escrow, and peer-based lane-emergency fixtures now use checked default,
    Secp256k1, and BLS-normal key generation before domain ISI regressions
    consume account, peer, multisig, and policy material;
    core multisig ISI owner, signer, missing signer, registrar, seed account,
    shared-subject, nested policy, proposal, quorum, rekey, materialization,
    and large-policy member fixtures now use checked default key generation
    before multisig registration, proposal, approval, cancellation, role, alias,
    and membership regressions consume account and signer material;
    core block sync peer IDs, seen/unknown-prev block chains, request/backoff
    peers, sample targets, QC/roster metadata, share-block runtime, candidate
    validation, block filtering, and trusted-recovery fixtures now use checked
    default, Ed25519, and BLS-normal key generation before block sync and
    Sumeragi block-sync regressions consume peer, block, signature, and QC
    material;
    core block builder, dummy/valid/committed block, genesis/topology,
    QC/commit-roster, heartbeat, NPoS effects, DA/SCCP/static-validation, and
    pending-block fixtures now use checked default, Ed25519, and BLS-normal key
    generation before block validation, commit, quorum, and pending-block
    regressions consume signer, block, and consensus material;
    core Soracloud state, FHE proof/policy/job, HF placement/model-host,
    shared-lease, uploaded-model, training, service rollout, and release-audit
    reviewer fixtures now use checked default key generation before Soracloud
    instruction regressions consume block headers, account IDs, provenance, and
    reviewer signatures;
    core state stake snapshot, storage migration, account/alias/directory,
    permission/replay validation, lane relay/merge/AXT, DA cursor, trigger,
    Soracloud visibility, tiered snapshot, transfer transcript, governance, and
    storage fixtures now use checked default, Ed25519, and BLS-normal key
    generation before state regressions consume account IDs, peer rosters,
    block signers, and consensus material;
    core queue multisig governance, committed-block detection, requeue,
    expired-transaction, block cleanup, and per-user limit fixtures now use
    checked default key generation before queue regressions consume signer,
    validator, multisig, and block-header material;
    core transaction multisig, mixed-curve, disallowed-algorithm,
    signatory-role, lane-validator, missing-authority approve, fast-path, and
    heartbeat fixtures now use checked default, Ed25519, and Secp256k1 key
    generation before transaction admission and state-validation regressions
    consume them;
    core snapshot default signer, Space Directory account, wrong-key signature,
    and BLS peer/QC fixtures now use checked key generation before snapshot
    write/read, legacy restore, Merkle, Kura block, and consensus-sidecar
    regressions consume them;
    core Sumeragi collector routing and IVM unknown-syscall admission fixtures
    now use checked random Ed25519 key generation before deterministic topology
    and admission-rejection regressions consume account and peer material;
    core commit roster journal certificate fixtures now use checked BLS key
    generation before journal persistence, retention, and stake-snapshot
    regressions consume validator checkpoints;
    core peers-gossiper Ed25519 seed and BLS topology fixtures now use checked
    key generation before gossip roundtrip, trust-score, topology update, and
    unknown-peer penalty regressions consume them;
    core transaction-gossiper RAM-LFE program-policy signer fixtures now use
    checked Ed25519 key generation before large-policy gossip roundtrips consume
    signer material;
    core streaming publisher/viewer, manifest, privacy-route, snapshot, and
    session-key fixtures now use checked default and Ed25519 key generation
    before control-frame, capability, privacy, and persistence regressions
    consume them;
    data-model streaming ticket event account fixtures now use checked
    deterministic Ed25519 seed expansion before privacy-route and ticket
    roundtrip regressions consume them;
    data-model consensus RBC init and BlockSignature derive repro fixtures now
    use checked hash-signature construction before consensus Norito roundtrip
    regressions consume them;
    Rust SDK SM2 deterministic signing fixtures now use checked signature
    construction before fixture-vector parity regressions consume them;
    `iroha_test_network` NPoS bootstrap gas, seeded peer streaming/BLS identity,
    and Sora profile PoP override fixtures now use checked deterministic seed
    expansion before test-network regressions consume them;
    JS host multihash and smart-contract-code JSON fixtures now use checked
    deterministic Ed25519 seed expansion before binding regressions consume them;
    connect-norito bridge KAGEMUSHA prover, Connect/crypto FFI, identifier
    receipt, account-address, ML-DSA signing, and signed-transaction fixtures now
    use checked deterministic Ed25519/ML-DSA seed and typed-signature
    construction before bridge FFI/KAGEMUSHA regressions consume them;
    feature-gated core ZK-ACE STARK account fixtures now use checked
    deterministic Ed25519 seed expansion before STARK prover regressions consume
    them;
    core ZK OpenVerify STARK prover and KAGEMUSHA guardrail/real-prover
    account plus one-use key-certificate fixtures now use checked deterministic
    Ed25519 seed expansion before STARK and offline recursive proof regressions
    consume them;
    the retired Torii council-persist and governance derive-VRF fixtures and
    regressions are removed with their unshipped surfaces;
    Torii account-activity unit-test account helpers now use checked
    deterministic Ed25519 seed expansion before activity extraction regressions
    consume them;
    Torii ISO 20022 account, config-signer, and account-address parser fixtures
    now use checked deterministic Ed25519 seed expansion before ISO bridge
    regressions consume them;
    Torii SoraFS API alias-proof and signed manifest-envelope fixture signers
    now use checked deterministic Ed25519 seed expansion before gateway
    capability regressions consume them;
    core lane-compliance policy account fixtures now use checked deterministic
    Ed25519 seed expansion before compliance policy regressions consume them;
    core tiered-state governance approval measured-bytes fixtures now use
    checked deterministic Ed25519 seed expansion before storage-size regressions
    consume them;
    core block-sync consensus-filter deterministic BLS key fixtures now use
    checked seed expansion before commit-role quorum regressions consume them;
    core Sumeragi evidence QC validator-set fixtures now use checked BLS seed
    expansion before invalid-QC evidence regressions consume them;
    core RBC store persisted-session peer fixtures now use checked deterministic
    Ed25519 seed expansion before session-roster roundtrip regressions consume
    them;
    core Sumeragi reschedule paced retransmit peer fixtures now use checked BLS
    seed expansion before retransmit target-order regressions consume them;
    core Sumeragi roster deterministic BLS key lists, permissioned roster
    sorting keys, and non-BLS active-topology fixtures now use checked seed
    expansion before roster/topology regressions consume them;
    core Sumeragi RBC rebroadcaster roster and outsider peer fixtures now use
    checked Ed25519 seed expansion before rebroadcaster selection regressions
    consume them;
    core Sumeragi public-key classification fixtures now use checked
    Ed25519/BLS seed expansion before BLS-normal validator identity regressions
    consume them;
    core Sumeragi message QC, certified-block fetch, block-created, priority,
    and compact-fetch fixtures now use checked Ed25519 seed expansion before
    message wire, certified-fetch, and compact RBC regressions consume them;
    feature-gated core Sumeragi main-loop deterministic, retransmit, seeded BLS
    peer, P2P refresh, NPoS canonicalization, and canonical payload fixtures now
    use checked seed expansion before main-loop
    regressions consume them;
    core state default streaming key material, ZK-ACE identity account helpers,
    and governance-stage decision fixtures now use checked Ed25519 seed
    expansion before streaming config, identity roundtrip, and quorum
    regressions consume them;
    executor multisig account and transaction helpers now use checked
    deterministic Ed25519 seed expansion before quorum reachability and
    proposer authorization regressions consume them;
    executor default instruction dispatch, metadata, permission, and
    dummy-executor helpers now use checked deterministic Ed25519 seed expansion
    before default executor regressions consume them;
    core account-admission implicit-controller, domain-controller multisig, and
    Musubi publisher fixtures now use checked deterministic Ed25519/Secp256k1
    seed expansion before algorithm-policy and release roundtrip regressions
    consume them;
    core IVM host fixture account helpers now use checked deterministic Ed25519
    seed expansion before pointer-ABI, alias-resolution, and subscription
    regressions consume them;
    core governance selector, citizen draw, and parliament account helpers now
    use checked deterministic Ed25519 seed expansion before selector, draw, and
    VRF/parliament regressions consume them;
    `iroha_cli` governance vote, council, and deploy fixtures now use checked
    deterministic Ed25519 seed expansion before public-input owner, candidate
    parsing, and manifest approver regressions consume them;
    `iroha_cli` address account and public-key literal fixtures now use checked
    deterministic Ed25519 seed expansion before I105 summary, public-key parsing,
    and canonical render regressions consume them;
    `iroha_cli` subscription private-key and account fixtures now use checked
    deterministic Ed25519 seed expansion before plan, subscription, and usage
    request-building regressions consume them;
    `iroha_cli` confidential and Nexus summary fixtures now use checked
    deterministic Ed25519 seed expansion before keyset output and governance
    summary formatting regressions consume them;
    `iroha_cli` Taira canary signer, receipt, alias, and runtime-config fixtures
    now use checked deterministic Ed25519 seed expansion before canary identity
    and redaction regressions consume them;
    `iroha_cli` governance-instruction config and DA rent-ledger account fixtures
    now use checked deterministic Ed25519 seed expansion before governance
    signing and rent-ledger transfer regressions consume them;
    `iroha_cli` contract simulation signer and contract test-context fixtures
    now use checked deterministic Ed25519 seed expansion before simulation
    metadata and private-key resolution regressions consume them;
    `iroha_cli` main shared asset-transfer, ISO DVP, account literal, ping
    capture, multisig, and query-harness fixtures now use checked deterministic
    Ed25519 seed expansion before those command regressions consume them;
    `iroha_cli` smoke account, governance council candidate, address conversion,
    and address audit fixtures now use checked deterministic Ed25519 seed
    expansion before binary smoke regressions consume them;
    SoraFS CLI manifest-submit, account-address parsing, authority literal, and
    pin-register payload fixtures now use checked deterministic Ed25519 seed
    expansion before CLI account parsing and payload regressions consume them;
    SoraFS treasury payout account helpers now use checked deterministic
    Ed25519 seed expansion before payout, reconciliation, and dispute
    regressions consume them; client
    transaction build/sign helpers now use `TransactionBuilder::try_sign` and
    return contextual `eyre` errors from fallible construction/submission paths
    while retaining compatibility wrappers for existing infallible callers;
    test-network genesis consensus metadata overrides and cached-genesis
    augmentation now use checked transaction signing and checked genesis block
    signature reconstruction;
    snapshot digest files now use `Signature::try_new` during snapshot writes,
    verify generated signatures against stored digests, and reject wrong-key
    signatures over matching digests in focused regressions;
    quarantined Sumeragi vNext re-chain and view-change votes now use
    `Signature::try_new`, verify canonical vote signatures, and reject
    wrong-mode consensus-domain preimages in focused regressions;
    quarantined Sumeragi vNext preaggregated aggregate-signature non-BLS signer
    fixtures now use checked Ed25519 seed expansion before unsupported-key
    rejection consumes them;
    peer trust gossip roundtrip and adversarial trust-record fixtures now share a
    checked `Signature::try_new` helper, matching the production trust-gossip
    signing path in focused regressions;
    SoraFS ISI council envelope and alias proof fixtures now sign through
    `Signature::try_new`, keeping approval and pending-manifest
    invalid-signature regressions on checked fixture signatures;
    `iroha` client SoraFS alias-proof bundle fixtures now sign through
    `Signature::try_new`, with fresh, stale, and send-builder alias-policy
    regressions covering checked council signatures; remaining direct `iroha`
    client transaction fixtures now use `TransactionBuilder::try_sign` across
    pipeline-status, committed-query/hash, block WebSocket, and prepared-payload
    regressions;
    SoraDNS resolver CLI directory-record fixtures now sign through
    `Signature::try_new`, with the directory fetch/verify CLI suite covering the
    checked builder signature;
    SoraDNS ISI directory-record fixtures now sign through `Signature::try_new`,
    with submit-draft and publish-directory instruction regressions covering the
    checked builder signature;
    SoraFS gateway conformance attestations now sign reports through
    `Signature::try_new`, with regression coverage that verifies the emitted
    envelope signature and rejects a wrong key, and the canonical conformance
    docs now show the checked signing helper instead of the compatibility
    signer;
    irohad Soracloud runtime provider advert/admission fixtures and recording
    mutation-sink heartbeat/Inrou provenance fixtures now use checked signing,
    with remote provider hydration and local heartbeat/Inrou regressions covering
    the paths;
    VPN usage vouchers now expose `VpnUsageVoucherV1::try_sign`, verify checked
    voucher signatures, and reject tampered or wrong-key voucher signatures in
    focused regressions;
    core VPN lease settlement fixtures now build settlement vouchers through
    `VpnUsageVoucherV1::try_sign`, covering tariff recomputation and relay
    overclaim rejection on checked voucher signatures; core VPN lease custody
    account derivation now uses checked Ed25519 seed expansion and propagates
    seed rejection as an instruction invariant error;
    Torii app-API VPN receipt fixtures now build client vouchers through
    `VpnUsageVoucherV1::try_sign`, with the filtered receipt suite covering
    WSV-grace success and wrong-key, tampered, malformed, replayed, and
    substituted receipt/voucher cases;
    Torii SoraFS repair transaction and discovery alias-proof fixtures now use
    checked `SignatureOf::try_new` / `Signature::try_new`, with repair positive,
    invalid-transaction-signature, fresh-alias, and expired-alias regressions rerun under
    `app_api`; Torii `lib.rs` routed-read escrow, push identity, EVM DA receipt
    signer, RAM-LFE output-opening, and SoraFS repair transaction auth fixtures now use
    checked seed derivation and `SignatureOf::try_new`, with push, identifier,
    repair, and routed-read regressions rerun;
    Torii grouped core/Nexus/governance test fixtures now use checked
    `Signature::try_new` and `KeyPair::try_from_seed`, with portfolio filtering,
    bridge finality, Nexus disabled/enabled lanes, and push rejection/success
    regressions rerun;
    Torii routing overlong multisig selector, contract bundle, repair native
    action transaction, and account transaction filter fixtures now use checked seed and
    signature constructors before selector, receipt, repair, and filter
    regressions consume them;
    integration App API canonical request and DA/Taikai ingest fixtures now use
    checked `Signature::try_new`, with canonical GET/POST auth, Taikai missing
    metadata/malformed-SSM rejection, replication/proof tags, and the DA
    retention manifest regression rerun;
    Torii hot-path benchmark account/authority fixtures now use checked
    `KeyPair::try_from_seed`, with the benchmark target checked and linted under
    `app_api`;
    `iroha_core` query and block benchmark account fixtures now use checked
    `KeyPair::try_from_seed`, with block benchmark account seeds domain-framed
    to keep seed zero deterministic without all-zero material;
    SoraFS gateway conformance wrong-key fixtures now use checked
    `KeyPair::try_from_seed`, with the attestation signature acceptance and
    wrong-key rejection regression rerun;
    Sumeragi negative-path double-vote evidence fixtures now use checked
    `Signature::try_new`, with valid evidence persistence and stale evidence
    non-persistence regressions rerun;
    Torii operator replay and content auth signed-header fixtures now use
    checked Ed25519 key generation plus `Signature::try_new`, with replay,
    role-gate, and sponsor regressions covering the verified canonical request
    signatures;
    `sora-vpn-helper` usage voucher control-cell envelopes now sign through
    `Signature::try_new`, propagate controller signing errors, and exercise the
    fallible envelope builder plus checked metering private-key seed derivation
    in the cumulative voucher signer regression;
    `soranet-vpn-settlement` request header signatures now use
    `Signature::try_new`, artifact signer seed derivation now uses
    `KeyPair::try_from_seed`, relay runtime usage-voucher fixtures now use
    `VpnUsageVoucherV1::try_sign`, and the relay DoS outcome labels classify
    inert admission-token signatures as invalid signature material;
    Offline v1/v2 vector issuer certificate signatures now use
    `Signature::try_new`, verify generated certificate signatures, and reject
    tampered signature or canonical payload bytes in binary regressions;
    Swift parity fixture generation and the standalone Norito fixture exporter
    now use checked transaction signing and verify regenerated fixture
    signatures in regressions; the exporter also uses `Signature::try_new` for
    hand-reencoded payload hashes, rejects malformed signed-envelope framing in
    adversarial tests, and pins standalone `time` resolution to the root-locked
    `0.3.47`;
    the confidential wallet fixture exporter now routes shield, ZK transfer, and
    unshield transactions through `TransactionBuilder::try_sign`, verifies
    regenerated fixture signatures, rejects tampered signatures, and validates
    proof backend identifiers in example regressions;
    the `iroha_core` transaction-size example now builds its measured transaction
    through `TransactionBuilder::try_sign` and verifies the checked signature in
    an example regression;
    the SoraFS pin snapshot fixture generator now signs alias proof and council
    envelope fixtures through `Signature::try_new` and verifies both generated
    signatures in example regressions;
    the `iroha_core` parity fixture generator now routes event fixture
    transactions and synthetic fixture block signing through checked signing
    helpers and verifies both paths in example regressions;
    the Nexus app transfer example wallet path now uses `Signature::try_new`
    and verifies the checked demo wallet signature while rejecting malformed
    payload hashes in example regressions;
    Nexus app facade wallet-signature regressions now share a checked
    `Signature::try_new` helper for Connect finalization, wallet flow,
    hash-mismatch, and submit/status error-code fixtures;
    split and IVM contract deploy CLI helpers now use
    `TransactionBuilder::try_sign` for deploy-envelope transaction construction
    and return contextual command errors on backend signing failure; CLI ZK
    verifier-key register/update helpers now use the same checked transaction
    signer before submitting governed verifier-key registry updates; governance
    CLI IVM execution VK registration and SCCP IVM-proved transaction
    construction now use a checked `TransactionBuilder::try_sign` helper and
    return contextual command errors on backend signing failure; Torii
    governance signable-payload drafts now use deterministic checked dummy
    signing instead of throwaway random compatibility signing before returning
    client-signable payload bytes; Torii ISO 20022 pacs.008 and pacs.009
    transfer transaction construction now uses checked
    `TransactionBuilder::try_sign` before returning signed bridge
    transactions; CLI Soracloud release-governance, provenance,
    uploaded-model, generated-HF, and mutation-auth header signatures now share
    a checked `Signature::try_new` helper and return contextual command errors
    on backend signing failure; the shared Connect Norito bridge transaction encoder now uses
    `TransactionBuilder::try_sign` and propagates a bridge transaction-signing
    error through transfer, shield/unshield, ZK, governance, mint/burn,
    multisig and identifier FFI exports; Torii App API
    transaction submissions now share a checked
    `TransactionBuilder::try_sign` helper across confidential relay, account
    onboarding/faucet/alias, space-directory manifests, contract
    call/deploy/alias, verifier-key registry, SoraFS, and subscription
    endpoints, and Torii contract-call, bridge proof/message, and multisig
    propose/approve/cancel signable scaffold and detached-signature routes now
    use checked scaffold key generation plus `TransactionBuilder::try_sign`
    before returning client signable payloads; JavaScript host transaction
    assembly and re-sign N-API paths now use a checked
    `TransactionBuilder::try_sign` helper and return N-API errors on backend
    signing failure; MOCHI transaction previews and readiness smoke transaction
    plans now use `TransactionBuilder::try_sign`, return explicit
    compose/readiness signing errors, and verify checked signatures in focused
    regressions; JavaScript host SM2 sign/fixture N-API paths now use
    `Sm2PrivateKey::try_sign`; Offline V1/V2 interop vector generator
    certificate issuer signatures now use `Signature::try_new`, and SCCP
    source-proof, Torii routing finality/evidence, data-model bridge finality,
    SoraFS manifest alias-proof, SoraFS node gateway, data-model
    endorsement/manifest/ISI fixture signatures, data-model block fixture
    signatures plus signed-block transparent API fixtures, and data-model
    transaction payload/multisig fixtures now use
    `Signature::try_new`/`SignatureOf::try_from_hash`; Soracloud
    canonical-request witness fixtures now use checked Ed25519 key generation
    and `Signature::try_new`, verifying the witness signature before Norito
    roundtrip;
    SoraFS CLI
    fallback manifest `/transaction` submissions now use a checked
    `TransactionBuilder::try_sign` helper and return contextual command errors
    before HTTP dispatch on backend signing
    failure; genesis batch transaction construction now uses
    `TransactionBuilder::try_sign` and returns contextual genesis-build errors
    on backend signing failure; `iroha_genesis` build/sign, topology, PoP,
    parse, roundtrip, example, and default-genesis fixtures now use checked
    default and BLS key generation before consuming signer, peer, PoP, or account
    public-key material; standalone `iroha_genesis` now enables the data-model
    BLS curve registry, decodes grouped genesis `RegisterBox` instructions in
    registry smoke coverage, and keeps shipped genesis `wire_proto_versions`
    aligned to first-release Sumeragi protocol `1`; xtask Norito RPC fixture generation now derives
    the fixture signer through `KeyPair::try_from_seed`, signs transaction
    fixtures through `TransactionBuilder::try_sign`, and verifies decoded
    signed fixture bytes in focused coverage; SoraFS admission and pin-registry
    fixture generation now derives fixture keys through `KeyPair::try_from_seed`,
    signs advert/council/alias/pin envelopes through `Signature::try_new`, and
    verifies generated signatures in focused coverage; Kagami profile bundles
    now derive deterministic genesis/peer keys through `KeyPair::try_from_seed`,
    propagate deterministic BLS PoP failures, and verify deterministic key
    signatures in focused coverage; Kagami genesis direct-manifest regression
    fixtures now derive expected signing keys through `KeyPair::try_from_seed`;
    Kagami genesis embed-pop topology peer fixtures now use checked default
    key generation before PoP embedding, duplicate-pop, non-canonical peer, and
    unused-pop regressions consume peer material;
    Kagami genesis signing topology, override, NPoS bootstrap, IVM-link, and
    private-key fixtures now use checked default, BLS, and Ed25519 key
    generation before consuming peer or signer material;
    Kagami wizard BLS fixtures now use checked BLS key generation before
    vanilla config and missing trusted-peer PoP regressions consume peer
    material;
    Sumeragi recovery-heartbeat transaction construction now uses a fallible
    `TransactionBuilder::try_sign` helper and returns contextual consensus
    errors on backend signing failure;
    transaction-gossip frame-size probing now uses `TransactionBuilder::try_sign`
    and falls back to a zero payload cap with a warning on dummy probe signing
    failure; Torii runtime-handler signed app-header, pipeline-status,
    block/header, commit-QC, and SCCP message-bundle fixtures now share checked
    `Signature::try_new`, `SignatureOf::try_from_hash`, and
    `TransactionBuilder::try_sign` helpers, with a wrong-key BLS block-signature
    regression covering adversarial verification failure;
    SCCP BSC, TON, Solana, Ethereum sync committee, Nexus finality, and
    EVM attestor fixture key families now share checked seed derivation before
    source-proof and submission-package regressions consume them; Kagami Kura
    block-store test fixtures now use checked transaction and block signing,
    verify the fixture transaction signature before append, and reject a wrong
    block-signature key in the focused regression; `iroha_crypto` packed
    signature alignment fixtures now use checked Ed25519 key generation,
    `Signature::try_new`, and `SignatureOf::try_from_hash`, with raw and typed
    signature wrong-key rejection coverage; `iroha_crypto` `SignatureOf` Norito
    layout fixtures now use checked Ed25519 key generation before typed-layout
    and diagnostic regressions consume signing material; `iroha_crypto`
    streaming handshake fixtures now use checked Ed25519/Secp256k1 key
    generation before HPKE, X25519, ML-KEM, snapshot, replay, and
    chunk-encryption regressions consume signing material; Ed25519 aggregate
    and deterministic batch verification fixtures now use checked Ed25519 key generation plus
    `Signature::try_new`, preserving tampered-signature, empty-input,
    invalid-member, order-binding, and wrong-key rejection coverage; ML-DSA
    keypair fixture signing now uses checked seeded key generation plus
    `Signature::try_new`, preserving modified-message, wrong-key,
    invalid-signature-length, mismatched-key, malformed-key, and inconsistent
    private-key-import negative coverage; internal `Signature`/`SignatureOf`
    fixtures now use checked random key generation plus `Signature::try_new` and
    `SignatureOf::try_from_hash`, with Ed25519, secp256k1, BLS normal/small,
    verify-cache, and typed roundtrip regressions rejecting wrong-key
    verification where applicable; top-level `iroha_crypto` private-key export,
    random keypair, ML-DSA parsed-key, keypair serialization, BLS aggregate/PoP,
    and public-key payload fixtures now use checked seed/random key generation
    plus `Signature::try_new`, with wrong-key Ed25519, secp256k1, and ML-DSA
    random-signature rejection plus existing BLS bad-signature, duplicate-key,
    canceling-key, malformed-PoP, unhashed-PoP, and malformed-public-key
    regressions on checked fixtures; BFV full-bootstrap release-audit reviewer
    fixtures now use checked seeded reviewer key derivation plus
    `SignatureOf::try_new` for the wrong-reviewer signoff negative path; Torii
    xtask SoraNet
    testnet drill bundle, FastPQ bench manifest, Taikai anchor bundle, and
    OpenAPI manifest signers now propagate `Signature::try_new` failures with
    command context, with the signing-focused xtask suite verifying the
    generated signature envelopes; xtask SoraNet rollout capture and SoraDNS
    release directory signers now use `Signature::try_new`, checked seeded
    fixture keypairs, and focused signature-verification regressions; xtask I3
    benchmark proof fixtures now use nonzero checked Ed25519 seed material,
    `Signature::try_new`, and immediate signature verification before benchmark
	    scenarios consume commit-certificate, attestation, or bridge proofs; native AMX BLS vote
		fixtures now use checked seeded/random key
		generation plus `Signature::try_new`, verifying each vote preimage
		signature before aggregate-QC ordering and rejection regressions consume it;
		`iroha_crypto` ML-DSA deterministic fixture tests and
		Ed25519/GOST/SM/SoraNet benchmarks now route fixture seeds/signatures
		through `KeyPair::try_from_seed` and `Signature::try_new`, with the lone
		direct ML-DSA `KeyPair::from_seed` call documented as the intentional
		legacy compatibility assertion and the ML-DSA suite plus feature-gated
		benches checked under `gost,sm`;
		Sumeragi vote-verifier checked BLS batch fixtures now use non-zero
		deterministic seed material accepted by `KeyPair::try_from_seed`, with
	wrong-validator, non-BLS public-key, pending-block, block-sync/QC,
	payload-availability, and P2P topology helper regressions rerun on checked
	Sumeragi fixture signatures; core signature-batch determinism adversarial
	wrong-key transaction signatures now use checked `SignatureOf::try_new`, with
	Ed25519, secp256k1, BLS multi-message, and BLS batch permutation regressions
	rerun; core admission-batching block-header and adversarial transaction
	signatures now use checked `SignatureOf::try_from_hash` / `SignatureOf::try_new`,
	with Ed25519, secp256k1, ML-DSA, BLS same/mixed/multi-message bisection,
	disallowed-algorithm, and TTL admission regressions rerun; core fraud
	monitoring attestation fixtures now use checked `SignatureOf::try_new`, with
	disabled monitoring, missing assessment, pipeline rejection, band threshold,
	missing attestation, tampered signature, and valid-attestation regressions
	rerun; the remaining core integration-test unchecked constructors now route
	deterministic keys and bridge/pin/social signatures through
	`KeyPair::try_from_seed`, `Signature::try_new`, and `SignatureOf::try_new`,
	with bridge finality, SCCP BSC/Solana source proof, parliament Sybil,
	IVM host mapping, implicit account, Kotodama, pin-registry, and social viral
	regressions rerun; the broad bridge filter still fails on unrelated dirty SCCP
	rollout/route-allowlist readiness helpers (`71` passed, `17` failed);
	core block/snapshot BLS validator and snapshot manifest/log/block fixtures
	now use checked `KeyPair::try_from_seed`, with BLS public-key,
	validator-signature, and space-directory snapshot regressions rerun under
	`bls`;
	Sumeragi main-loop
	RBC/QC fixtures now share
	checked `Signature::try_new` and `SignatureOf::try_from_hash` helpers for
	READY/DELIVER evidence, leader-signature mutations, aggregate vote/QC,
	checkpoint, and telemetry fuzz fixtures, with forged-leader, malformed-shape,
	invalid INIT/seed/frontier, NPoS rotated-signer, and mismatched-signer
	regressions rerun under `sumeragi-main-loop-tests` and the gated telemetry
	fuzz case rerun under `telemetry`; the remaining Sumeragi main-loop fixture
	constructors now route through the same checked helpers across commit-vote
	seeders, block-sync signature/QC fixtures, merge committee, manifest guard,
	vote-validation, and RBC READY/DELIVER malformed/stash cases, with the
	feature-gated compile gate plus focused block-sync/QC/RBC/merge/vote
	regressions rerun warning-free; block-sync QC aggregate, share-block sidecar,
	filter, wrong-key, and roster-metadata fixtures now also use local checked
	`Signature::try_new` / `SignatureOf::try_from_hash` helpers, with the
	adversarial bad-signature and tampered-block filters rerun under `bls`;
	Sumeragi evidence double-vote fixture signing now uses checked
	`Signature::try_new`, with canonicalization, validation, dedup, fuzz,
	invalid-signature, store-rejection, and stale-replay evidence regressions
	rerun under `bls`;
  bridge SCCP/finality block-signature fixtures now use checked
  `SignatureOf::try_from_hash`, with the full bridge unit-test filter rerun
  under `bls`;
  telemetry-gated block-payload fixture signatures now use checked
  `SignatureOf::try_new`, with transaction, genesis-empty, non-genesis-empty,
  and DA commitment classification regressions rerun under `telemetry`;
  network-message Sumeragi block topic fixtures now use checked
  key generation plus `SignatureOf::try_from_hash`, with the
  topic-classification regression rerun under `bls`;
	`irohad` network-relay RBC init fixtures now use checked
	`SignatureOf::try_from_hash`, with consensus-ingress critical bucket, penalty,
	byte-limit, and RBC session-limit regressions rerun;
	Torii consensus evidence-route double-vote fixtures now use checked
	`Signature::try_new`, with valid, mismatched-mode, stale-height, truncated,
	invalid-hex, structurally invalid, NPoS seed, and permissioned PRF-seed
	regressions rerun;
	Torii app-auth canonical request and multisig witness fixtures now use checked
	`Signature::try_new`, with valid account/alias, wrong-signature, replay,
	stale-timestamp, missing-freshness, path-mismatch, multisig rejection,
	duplicate-signer, below-threshold, and witness-replay regressions rerun;
	Torii DA alias-proof council and receipt-log fixtures now use checked
	`Signature::try_new`, with receipt signing, duplicate/conflicting receipt,
	invalid-signature, sequence-rebound, and Taikai SSM tamper regressions rerun;
	Torii DA Taikai segment-signing and deterministic ingest request fixtures now
	use checked `SignatureOf::try_new` and `KeyPair::try_from_seed`, with matching
	SSM, manifest mismatch, tampered-signature, manifest fixture, and receipt
	signing regressions rerun;
	Torii SoraFS API manifest-envelope and alias-proof fixtures now use checked
	`Signature::try_new`, with manifest-envelope required/malformed/stale/optional
	policy, alias-proof decode, and capability-enforced fetch regressions rerun;
	Torii Soracloud provenance and residual DA receipt fixtures now use checked
	`Signature::try_new`, with Soracloud signature-layout, uploaded-model
	tamper/swap/mismatch, mutation-signer, generated provenance, control-plane
	snapshot, and broad receipt regressions rerun; Torii sources now scan clean of
	raw `Signature::new` and `SignatureOf::from_hash` constructors;
	integration restart-peer Soracloud private-upload provenance and app-auth
	header fixtures now use checked `Signature::try_new`, with the four-peer
	uploaded-model receipt restart-recovery regression rerun;
	Torii identifier-resolution shared receipt and output-opening fixtures now
	use checked `KeyPair::try_from_seed` and `SignatureOf::try_new`, with shared
	fixture, signed receipt roundtrip, proof-mode/resolver mismatch, replay,
	tampered-signature, zero-hash, future/expired timestamp, wrong-verifier, and
	program-drift regressions rerun;
	core identifier ISI receipt and output-opening fixtures now use checked
	`SignatureOf::try_new`, with claim/revoke, missing-UAID, invalid receipt,
	invalid opening, mismatched opening, zero-hash, expired-receipt, and reclaim
	regressions rerun;
	core domain endorsement fixtures now use checked `Signature::try_new`, with
	accepted, missing, duplicate, expired, scoped, mismatched, and unregister
	cleanup endorsement regressions rerun;
	core state block-proof, replay-signature, commit-QC/roster, and merge-QC
	fixtures now use checked `SignatureOf::try_from_hash` and
	`Signature::try_new`, with block proof, replay topology, commit roster,
	explicit commit-QC, sidecar, noncanonical Kura height, lane-relay rejection,
	and merge-QC regressions rerun;
	Sumeragi block-ingress, queue-pressure, RBC-init, and worker-loop block
	fixtures now use checked `SignatureOf::try_from_hash`, with incoming-message
	routing/dedup, queue-full, commit-QC fetch, RBC-init, and worker timing
	regressions rerun;
	core block header-update, quorum, commit-signature tally, consensus-key
	expiry, DA pin-intent, and Native AMX attestation fixtures now use checked
	`SignatureOf::try_from_hash` and `Signature::try_new`, with quorum,
	duplicate/spoofed signer, rollback, trimmed-signature QC, malformed-QC, and
	key-expiry regressions rerun;
	core Soracloud provenance, FHE job, uploaded-model, training/model-weight,
	HF shared-lease, model-host, decryption, and agent fixtures now use checked
	`Signature::try_new`, with the broad Soracloud provenance/FHE/uploaded-model/
	HF/model-host/training/decryption/agent regressions rerun;
	JDG SDN seals and committee attestation fixtures now use checked random key
	generation, `SignatureOf::try_from_hash`, and `Signature::try_new`,
    verifying fixture signatures before SDN, simple-threshold, and BLS aggregate guard
    regressions consume them; data-model JDG SDN commitment fixtures now also
    use checked random key generation plus `SignatureOf::try_from_hash`,
    verifying sample seals before registry and attestation validation
    regressions consume them.
    The
    ML-DSA key
    path now rejects inconsistent imported secrets and exposes
    `KeyPair::try_from_seed`, `KeyPair::try_random`,
    `KeyPair::try_random_with_algorithm`, `PublicKey::try_to_*`,
    `ExposedPrivateKey::try_to_*`, `Signature::try_new`, plus typed
    `SignatureOf::try_*` constructors, so remaining crypto follow-ups should
    focus on hot verification boundaries rather than ML-DSA panic replacement.
  - Rerun 4-peer no-fault prebuilt `5k` and `10k TPS` rows as needed to locate
    the new knee after the conservative cache pass.
  - The targeted built-in overlay path now avoids the full `InstructionBox`
    clone before `Executor::Initial` dispatch; user-provided executors still
    use the owned fallback. Keep the broader borrowed-instruction execution
    rewrite separate unless a later post-crypto/decode profile again shows
    `Transfer::clone`, `WorldTransaction::apply`, or the concrete instruction
    handler clones as active costs.
  - Treat RBC authoritative-payload delays as symptoms of slow validation and
    materialization unless a later profile shows DA/RBC storage pressure,
    missing `BlockCreated`, or QC payload-missing counters.
  - Move FASTPQ worker budgeting and deterministic hardware-accelerated crypto
    investigation into the next tuning branch if the post-deferral profile
    still shows background prover Poseidon work competing with consensus. Keep
    the full borrowed-`Execute` executor API rewrite separate unless a later
    profile makes overlay execution dominant again.
- Turn the proposal-gap / queue-pressure investigation into a reproducible measurement pass.
  - Rerun the 7-peer load that previously advanced slowly or stalled under backlog.
  - Sample `/v1/sumeragi/status`, pending-block / commit-inflight metrics, and queue depths throughout the run.
  - Use a load generator that can actually sustain the target rate before changing worker/backlog tuning again.
- Rebaseline sorted asset-definition query performance.
  - Rerun `snapshot_ephemeral_sorted_asset_defs_first_batch` and `snapshot_stored_sorted_asset_defs_first_batch` on an isolated host.
  - If stored-mode still regresses, tune `stored_sorted_fast_start_params` / first-batch thresholds and keep the matching query tests aligned.
  - Restore a green `cargo test -p iroha_core` baseline for the query-performance branch after any tuning.

## Targeted follow-ups

- Migrate the remaining operator VPN workflows to submit the Torii-returned
  native `OpenVpnLeaseEscrow` and `SettleVpnLease` transactions, then retire
  the legacy in-memory receipt endpoint after a public relay/helper/Torii
  canary.
- Broaden Kura replay determinism beyond the current unit and consensus
  integration corridor.
  - Sidecar recovery semantics are now aligned with the memory-only WSV model:
    commit manifests and WSV checkpoints are optional verification metadata,
    while intact Kura blocks remain the recovery source of truth. Remaining
    work should prove replay equivalence from blocks, not make sidecars
    mandatory.
  - Commit-worker coverage now proves that injected WSV checkpoint and commit
    manifest write failures after state commit are reported as sidecar
    warnings, not ledger data loss or commit rollback.
  - The broad `integration_tests --test consensus_and_da` target is green after
    the memory-only WSV sidecar changes and the July 5 crypto-readiness
    corridor closure, including DA restart/rehydration, READY telemetry
    sampling, committed mode/status reconciliation, cached proposal marker
    cleanup, and the mode-cutover and vote-QC regressions exposed by the first
    workspace rerun.
  - The replay validation fixture now replays multiple route-sensitive legacy
    blocks into a fresh state and compares canonical WSV snapshot bytes against
    the originally committed WSV, covering account, domain, alias, and asset
    mutations on the replay-specific validation entrypoint even when the final
    optional WSV checkpoint sidecar is adversarially drifted.
  - The real 4-peer restart integration test now commits route-sensitive
    asset, account, alias, and domain-owned state, removes optional sidecar
    metadata, rebuilds from Kura, and compares the restarted peers' rebuilt
    query surface.
  - Keep the fixture on the replay-specific validation entrypoint so legacy
    blocks without embedded context remain covered separately from newly
    proposed blocks.
  - Add golden old-block Norito fixtures produced by a pre-context binary,
    rather than only synthesized absent-field decode tests.
  - Profile the post-commit canonical WSV checkpoint hash under sustained load
    and either record the accepted overhead or replace it with a cheaper
    committed state-root path.
  - If operators need a network-authenticated replay proof, promote the WSV root
    from a local Kura sidecar into block-committed or certificate-bound metadata.
- Carry alias auto-renew mutation coverage into the next broad Torii corridor.
  - Added focused Torii coverage proving a subscriber-signed disable update can mutate the onboarding-created account-alias auto-renew subscription NFT, mark it canceled, preserve auto-renew settings metadata, and unregister the billing trigger.
  - If a remaining non-onboarding mutation path still hits `Can't modify NFT from domain owned by another account`, capture the exact submitter, NFT id, and permission token shape before changing the permission model again.
- Carry the materialized-signatory multisig authoring coverage into the next broader integration corridor.
  - Added a 4-peer `integration_tests/tests/multisig.rs` regression where `MultisigRegister` materializes a previously unregistered signatory and that signatory successfully authors `MultisigPropose` on the network.
  - The same test asserts single-key proposal and approval transaction-authority shape, submits approval from an existing signatory, and waits for the proposed metadata write to execute after quorum.
- Carry Petal renderer-specific capture gates beyond the core PNG/Katakana
  encode, PNG `eval-capture`, PNG `simulate-realtime`, and
  `score-styles` report.
  - Added deterministic core capture scoring for Petal Stream payloads, with a
    default profile baseline of 12/12 successful decode attempts
    (`success_ratio_bps=10000`) against the `9500` basis-point production gate
    and an adversarial low-contrast profile pinned at 0/4 attempts.
  - Wired `iroha offline petal score-styles` to the scorer for the published
    `sora-temple-default` style set with explicit profile, seed,
    `--min-success-ratio-bps`, and `--target-effective-bps` report metadata.
  - Added the deterministic `sora-temple-expanded` style set, which scores the
    default `sora-temple` candidate and a `sora-temple-high-contrast` hardening
    candidate that widens dark/light luminance separation while preserving
    capture attempts and jitter.
  - Wired `iroha offline petal encode --format png --channel binary-grid` to
    render the decode-critical Petal grid as a deterministic single-frame PNG
    with an `iroha.offline.petal.encode.v1` manifest.
  - Wired `iroha offline petal encode --format png --channel katakana-base94
    --style sora-temple-command` to render deterministic RGB command tiles that
    preserve decode-critical center luminance and solid calibration cells.
  - Wired `iroha offline petal encode --format gif --channel binary-grid`
    behind the existing `offline-visual-codecs` feature to emit a deterministic
    GIF and the same encode manifest, while default builds fail closed with a
    feature-enable diagnostic.
  - Wired `iroha offline petal encode --format gif --channel katakana-base94
    --style sora-temple-command` behind the same feature to emit deterministic
    animated command tiles in a single GIF manifest entry.
  - Added bounded `encode --animation-frames` support: PNG writes one
    deterministic file per frame, and GIF writes a single animated file whose
    manifest entry records the internal encoded frame count.
  - Wired `iroha offline petal eval-capture` to replay binary-grid or
    Katakana-base94 PNG frames through deterministic cell-center sampling,
    decode them with the Petal sample decoder, and fail closed with early-abort
    accounting when the success gate becomes unreachable.
  - Wired feature-gated `iroha offline petal eval-capture` to replay GIF
    manifest internal frames for both binary-grid and Katakana-base94 channels,
    expanding `encoded_frame_count` into deterministic source attempts.
  - Added opt-in `eval-capture --perturb-capture` support, which re-renders the
    sampled binary grid through the deterministic capture profile for
    seed/profile-stable per-frame capture attempts.
  - Added bounded deterministic cell-grid capture models for downscale,
    box-blur, horizontal motion blur, seeded sensor noise, and exposure offset
    so aggressive capture assumptions can be replayed without host-dependent
    image-processing libraries.
  - Wired `iroha offline petal simulate-realtime` to replay binary-grid or
    Katakana-base94 PNG frames in deterministic loop/source order, report every
    attempt, and write the first recovered payload only after a successful
    decode.
  - Wired feature-gated `iroha offline petal simulate-realtime` to replay GIF
    manifest internal frames in deterministic loop/source-frame order and write
    the recovered payload only after a successful decode.
  - Added opt-in `simulate-realtime --perturb-capture` support, expanding
    replay attempts across loop, source-frame, and capture-attempt indices.
  - Wired `iroha offline petal encode --channel katakana-base94
    --katakana-preset balanced|distance-safe` for automatic grid selection:
    balanced is the default floor at grid size 41, distance-safe floors at grid
    size 33, and an explicit `--grid-size` overrides the preset floor.
  - Wired `iroha offline petal score-styles --channel katakana-base94` to score
    Katakana renderer candidates with top-level and per-style channel/preset
    report metadata. The expanded set now scores `sora-temple-command` plus
    `sora-temple-command-high-contrast` and recommends the high-contrast command
    candidate under the collapsed low-contrast adversarial profile.
  - Recorded the CLI JSON baseline in `status.md`: `recommended_style=sora-temple`,
    `capture_success_ratio_bps=10000`, `resolved_grid_size=33`,
    `effective_payload_bits_per_second=5376`, and `overall_score_bps=10000`.
  - No Petal renderer-specific capture-gate work remains tracked here; future
    scanner or renderer expansion should be opened as a separate backlog item.
