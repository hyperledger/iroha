# Compact SHA3/SHAKE candidate

The normal offline compact owner uses SHA3-256 opaque 32-byte commitments,
SHAKE256 atomic raw tapes, 77 initial queries, and 162/78 trace/quotient mask
coefficients. This is an implementation candidate, not release qualification or
production admission. Full native proofs, integrated tests, concrete resource
measurements and Keccak hardware parity remain required.

Every H/G input is the complete canonical `ProfileContextV1` frame followed by
one canonical `BodyV1` frame. The prefix binds the framing version, the
catalog, the name of the frozen transcript construction
(`fips202-atomic-whole-tape-transcript-v1`), the complete canonical bytes of
the typed profile descriptor and the full statement context. The
[DEEP contract](fastpq_deep_protocol_contract.md#frozen-transcript-profile)
lists what the descriptor binds and states the frozen profile's security
claims. The body binds its kind, oracle,
round, level, position, output length and exact ordered fields. SHA3's `0x06`
and SHAKE's `0x1f` suffixes separate the primitives. Cached absorbed prefixes
preserve every logical input byte; context hashes do not replace those bytes.

The ten raw tapes have byte extents `[32,29584,80,80,80,80,80,80,80,744]`.
Canonical field-word rejection never squeezes extra bytes. The final tape must
first supply all 87 accepted field candidates and then 77 distinct positions.
Every rejected and unused raw byte enters the next commitment chain. Wrong
phases, finite exhaustion and base-field OOD challenges permanently abort.
Raw buffers, encoded private bodies, sponge lanes and permutation scratch have
clearing owners. X509's separate Digest384 and unchanged public parameter
vectors are not redefined by this profile.

Each FRI fiber retains its fixed arity tag and transmits arity minus one Fp4
values. The verifier derives the omitted coordinate from the smallest known
incoming index. It reconstructs from authenticated rows/Q/R and the checked
DEEP expression, checks every incoming coordinate sharing that fiber, hashes
the complete original fiber, verifies its exact minimal Merkle frontier, and
folds. All 128 terminal values remain authenticated and degree checked. The
proof cannot select an omitted coordinate or a subset of incoming checks.

The linked maximum query geometry yields child envelope 500084 bytes, maximum
sequence length1283 and total sequence elements6182. These are derived bounds
pending native canonical-DTO validation. The existing 524288-byte child target,
1048576-byte total transport, 2147483648-byte payload and 2^42 work limits remain.
SHA3 nodes occupy32 bytes; structural hash-call counts distinguish ten atomic G
queries from their internal permutation work. Required-device execution runs Keccak readiness KATs before private callbacks or
entropy and refuses unsupported devices. The candidate includes paired NEON/SSE2
and Metal continuation implementations; native compilation, actual device parity,
cleanup/quarantine and complete proof parity are still required. CUDA remains
unimplemented and fails closed; no Poseidon kernel substitutes for Keccak.

The security claim is conditional on the explicitly framed joint SHA3/SHAKE
qROM model, the reviewed weighted RBR/FRI and compiler premises, and the complete
transcript hiding argument. Standard concrete primitive assumptions are not an
unconditional proof for a fixed hash, and local review is not external review.
The q375 proof, codec, replay and transcript modules are removed. Their relation,
wire, context, resource and mutation assertions are mapped to the sole q77 engine.
Frozen predecessor identity bytes remain only as rejection fixtures. Generic
Digest384 topology checks still cover their separate live noncompact callers.
Native compilation, all mapped controls and genuine reviewed profile/proof pins
remain mandatory; prepared source and independent vectors are not native evidence.
