# PGC bootstrap signed attachment request (V1)

`BootstrapPrivacyPgcAccountsV1` has one first-release layout:
`{ bootstrap: PrivacyPgcAccountBootstrapV1, proof_ref: ActionAttachmentRefV1 }`.
The reference contains the exact `action_index` and `slot_index`. It is an
untrusted selector, not permission, a VM handle or proof acceptance. The old
embedded-proof record is rejected; there is no alternate decoder or sentinel.

The direct signed declaration names the registered native operation, the
`Administrative` role, its actual executable instruction position and authority,
and exactly one `Proof` / `ActionProof` slot at index zero. Its public-input
digest is the canonical bootstrap digest. The ordered intent retains the
complete bootstrap and reference; only the generated signed occurrence's proof
bytes, length and hash are removed by the shared normalizer.

The existing native N=16/32/64 relation binds the full ordered action statement,
including the global action ordinal. The privacy resource counter remains a
separate accounting value. Its charged bytes include the canonical request frame
and the original signed proof length. Rewrapping the same proof under a new
nonce, authority, instruction order or invocation context does not preserve the
proof transcript.

The executor borrows the original direct instruction object and proof occurrence
from the same signed owner. Initial and installed executor approval both precede
the single governed State handler. The handler retains current activation,
canonical account root, empty-State checks and atomic budget/publication. An
equal cloned instruction is not accepted as the original dispatch source.
Dropping the State transaction rolls back verified effects.

The native proof decoder, canonical public-input encoding and account-root
namespace encoding retain their original scoped resource refusal through the
bootstrap State handler. Namespace framing uses the existing counted canonical
encoder. This does not establish complete physical allocation coverage: bounded
public-input and account-update vectors retain their existing allocation behavior.

Admission remains closed in this staged source. TODO(I.3): execute actual
complete-route positive/negative, original-refusal retry and rollback tests,
regenerate and validate the canonical record frame, and only then replace the
operation-only refusal with an exact action/invocation-aware Direct PGC predicate.
Other operations and contract invocations must remain refused.

The canonical typed account-root function also owns current and successor
payment roots, pool snapshots and persisted-state validation. Its original local
namespace-encoding refusal reaches the State attempt boundary or the existing
Norito JSON scoped-resource projection without becoming malformed-state text.
Structural failures of trusted state remain invariant failures; malformed
submitted bootstrap data remains a completed rejection. The string-returning
root adapter is removed. TODO: execute the unchanged-input retry and restore
controls against this composed source; this migration does not qualify complete
physical allocation coverage, the native payment proof decoder or the ABI queue.

TODO(I.3, I.4): integrate the actual ABI V1 typed PendingAction queue with original
root/child path, effective actor, ordered consumption and finalized receipts.
No guest proof-byte copy or reusable verification token is permitted. Update the
native generated record frame and SDK/shared wire fixtures from the same source;
Kotlin remains the JVM implementation owner. Component source tests alone do not
establish task completion, native availability, network or release qualification.

Native bootstrap and payment proof readers share `AnonymousPgcReadError`. Both
authenticate canonical fixed-V1 framing against the borrowed input with a fallible
streaming comparison. The payment verifier and Core instruction boundary move the
original codec refusal into local execution deferral; intrinsic malformed wire or
failed relation remains rejection. No string adapter or bootstrap-only alias is
retained. This does not close the outstanding physical-allocation or ABI custody
work, and does not establish complete route qualification.
