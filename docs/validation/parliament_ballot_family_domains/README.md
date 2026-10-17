# B6 request-family domain audit

The [source audit](audit/README.md) establishes which typed public-input length
families need accounting, and distinguishes earlier entry failures that the
current simulator model does not price. It is a read-only requirement analysis,
not a resource maximum or qualification result.

REG independently permits body lengths 0..4096 and six context lengths 0..256,
including empty fields: 1,180,496,500,391,613,953 length tuples per row. Its private
constructor recomputes the body digest. Fixed commitment/authorization bytes do
not add an undocumented public-input restriction. Future production encodings
cannot be assumed to narrow this standalone domain before those schemas exist.

VOTE public validation admits actual list sizes 3..1000. Other constructible
typed list sizes are rejected, with vote-value errors taking precedence over
size errors. The fixed-size family descriptor must identify the same typed
request. Mathematical u64 descriptors do not by themselves prove native Vec
reachability, descriptor authenticity, or raw-decoder behavior.

Witness rejection occurs before simulator entry. Constructor bounds, test-codec
framing/descriptor failures, witness and application checks, and verification's
proof-length-first path are distinct upstream maps. The source theorem's bound
on valid requests does not bound arbitrary invalid invocations. A complete
driver needs explicit counts and costs for those paths; they are not free.

The [receipt](audit/receipt.json) binds 24 selected source identities. This package
preserves those exact bytes under `source/<original path>.template` and retains
the original audit manifest unchanged. `inventory.json` maps original and
packaged paths. The outer manifest checks the current package layout. No tests
or builds were executed as part of this read-only audit, and it establishes no
dependency closure, native resource contract or cryptographic review.

The audit's proposed next step was component envelope derivation. Subsequent
component or request-family evidence should be read under its own source and
proof scope; this historical audit is not retroactively relabeled as a bound.
TODO: price all upstream entry maps and invalid-invocation budgets, then connect
the legal families to the adaptive experiment and qualification requirements.
Production remains gated.
