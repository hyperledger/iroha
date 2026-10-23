# Ordinary crypto admission policy

This is the first-release contract for `CryptoAdmissionPolicyV1`, its State owner,
and signed genesis producers. The sole custom parameter is
`crypto_admission_policy_v1`; its value contains `allowed_algorithms`.

## Canonical value and identity

The algorithm list is nonempty, bounded by `Algorithm::ALL`, strictly increasing
in canonical algorithm-tag order, and duplicate-free. Constructors and canonical
Norito binary and JSON decoders enforce the same invariant. Producers preserve
the authored order and reject invalid input instead of sorting, deduplicating,
or inserting an algorithm. No implicit Ed25519 member exists.

All assigned algorithm and curve identities exist independently of optional
cryptographic implementations. Permitted controller curves are derived through
`CurveId::from_algorithm`; they are never separately authored or stored as policy.
Unknown identity, invalid cryptographic input, unavailable implementation, and an
unfinished local decoding/verification attempt remain distinct outcomes. A node
must not reinterpret its missing implementation or local refusal as evidence of
an invalid signed transaction.

## Signed initialization

A source genesis manifest requires `crypto_admission_policy`; `GenesisBuilder`
requires the same explicit value. The producer emits exactly one direct
`SetParameter` for `crypto_admission_policy_v1` into the signed instruction source.
A second assignment supplied in any source batch is rejected, including an equal
assignment. Validation occurs before parameter collection can collapse duplicates.
The retired `crypto` manifest field, `ManifestCrypto`, metadata injection, and
node-local signing/curve allowlists provide no alternate authority.

Core first authenticates genesis under the configured genesis root. It selects
the sole policy from that original signed source and retains its source coordinate,
header, and original parameter. Installation rechecks proposal commitments and
the original pristine State owner and generation before initializing Parameters.
The executing genesis block retains the authentication evidence; child
transactions borrow it. A height-one header or a current overlay value alone
cannot supply this authority. Later genesis effects cannot replace the initial
value, and a failed unpublished genesis does not publish any policy.

The genesis root signature and consensus validator-key/PoP rules have separate
purposes. They do not exempt an ordinary transaction or account controller from
the authored policy. Producers that create ordinary BLS validator accounts must
require an explicit BLS member rather than add one silently.

## Committed ownership and updates

`StateParameters` owns the original canonical Parameters and its validated policy
projection together. A successful update replaces both atomically; an original
Norito refusal leaves both unchanged. Once initialized, the policy cannot be
removed. Absence represents pre-genesis initialization only and supplies no
ordinary-admission default.

Ordinary block N admission borrows the original committed block preimage. A
policy update inside a pending transaction, an applied sibling, or a reverted
child cannot change admission for that block. The new policy becomes effective
at the next committed block boundary. Genesis uses its retained authenticated
initial owner because no committed predecessor exists yet.

Restoration validates current and retained predecessor parameter versions. When
MV reports no distinct predecessor for an unchanged value, the validated current
version is also that predecessor. A committed non-genesis State missing its
mandatory policy is inconsistent; local pre-genesis readiness must not be encoded
as a transaction rejection.

## Source owners and qualification

The model is `crates/iroha_data_model/src/crypto_admission_policy.rs`; the atomic
projection is `crates/iroha_core/src/pipeline_gas_policy.rs`. Genesis authentication
and retained evidence are in `crates/iroha_core/src/block/genesis_crypto_policy.rs`,
and ordinary State views are in `crates/iroha_core/src/state.rs`.

TODO(F.4): qualify the composed producer, ordinary transaction/controller, config,
startup, capability, fixture, and decoder-refusal migrations together. Component
owner tests do not establish whole-node acceptance, a complete proof relation,
other-platform readiness, or release qualification. The policy does not gate
mandatory ABI V1 SM syscalls; their deterministic semantics and gas remain part
of every IVM build.
