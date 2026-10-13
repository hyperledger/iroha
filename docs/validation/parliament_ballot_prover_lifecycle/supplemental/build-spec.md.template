# Standalone prover cancellation and publication contract

Status, 2026-10-13: engineering contract for the synchronous experimental
prover; **not production SDK integration or phone/erasure qualification**.
The [B6 audit](parliament_ballot_b6_requirement_audit.md) identified undefined
cancellation semantics. This contract makes a finish-and-discard experiment
precise without adding cancellation branches to the cryptographic algorithm.

## Ownership and acknowledgement

A job owns its public statement, credential-secret object and fresh proving
tape. The existing public prover consumes the tape and borrows the secret;
the job must end that borrow and drop its owned secret before it exposes a
result. The experiment uses public deterministic fixture tapes solely for
reproducibility; a wallet must obtain fresh cryptographic randomness for every
real invocation and retain its own credential under its separate custody policy.

Cancellation has two distinct acknowledgements:

1. An accepted request irrevocably suppresses publication of that job's result.
2. Finishing or dropping the job joins its synchronous computation and, when
   cancellation won, drops its inputs and unpublished result before returning.
   A separate wait operation can join and confirm input-owner cleanup while
   retaining an unpublished proof; it does not acknowledge disposal of that
   proof until finish or drop.

A cancellation request alone is not proof of completed erasure, released
memory or a stopped CPU. The algorithm may continue to ordinary success or
error. There is no hard interruption, process termination, abandoned thread,
automatic retry or tape reuse. The CPU and memory costs of the work that
continues remain costs of the cancelled invocation.

## Publication boundary

Cancellation and publication use one synchronized decision. If cancellation
wins, no subsequent finish operation may return the proof. If publication
wins, cancellation reports that it is too late: the caller already owns the
result, and the job cannot revoke it. Repeated cancellation never restores
publication permission.

A successfully computed proof is held in an erasing owner until publication.
When cancellation wins, that owner clears and releases the proof buffer. The
proof is public data, but inspecting its disposal provides a useful check of
the publication/cleanup path. The job drops its credential-secret object and
the prover consumes/drops the tape independently of that result.

Dropping an unfinished job requests cancellation and joins the worker. It may
therefore block until the synchronous call returns. This is a standalone
lifecycle choice, not an instruction to block a mobile UI thread. A production
SDK must specify its asynchronous ownership and acknowledgement API after
selection. No panic-abort, native crash, process kill or power-loss cleanup
guarantee follows from Rust destructors.

## Meaningful evidence

An in-call cancellation test must observe a milestone inside the real public
prover before requesting cancellation. A sleep or a signal just before calling
the prover would not establish this. The diagnostic allocator probe uses the
source-defined witness allocation as that milestone and resumes the same call
after cancellation. Successful internal completion plus a discarded outward
result establishes that cancellation suppresses publication while ordinary
cleanup runs.

Test both roles and both rows, uncancelled fixture parity, cancellation after
computation but before publication, cancellation after publication, repeated
cancellation, ordinary errors, entropy-fill errors and unfinished-handle drop.
The selected-buffer probe records the actual addresses of the job's secret,
tape, witness and unpublished proof allocations, and reads them only while
they are still allocated, immediately before deallocation. It must not inspect
freed memory or use a live production secret.

Successful observations establish that those particular owned buffers contain
zero bytes at release in the tested build. They do not establish erasure of
all backend/provider scratch, compiler-created copies, registers, stack spills,
caller copies, kernel memory or earlier snapshots. Independent implementation
and constant-time review remain required.

## Remaining qualification

TODO: carry the lifecycle contract into the eventual approved wallet/SDK API,
then measure both proofs and supported roster sizes on the named phones,
including battery operation, sustained thermal load, cancellation completion
latency and peak memory. Finish-and-discard does not by itself establish an
acceptable cancellation latency or the existing phone limits.

TODO: independently review randomness, secret-dependent behavior, all erasing
owners and compiler/native-runtime effects. Preserve explicit failure and
cleanup semantics without weakening the cryptographic or hardware requirements.
Production schemas, Core/Torii/SDK integration and activation remain gated.
