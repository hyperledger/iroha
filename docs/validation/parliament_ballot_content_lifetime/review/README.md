# Independent review of the conditional ContentFamily ledger

The reviewed extension adds the four captured candidate/comparator VOTE cases
at list counts 3 and 1000 to the frozen lifetime ledger. No definite arithmetic,
ownership or refusal bug was found within this scope. The review does not prove
an adaptive execution theorem, all-family maximum, primitive bridge, native
workspace bound or cryptographic qualification.

## Evidence and current-source limitation

The isolated replay passed **55 owned tests and 72 independent controls** with
no failures, errors or skips. The independent controls rederive append/write
costs using a per-bit population-sum formula, check all 24 orderings of a mixed
four-event trace, preserve each original input/coin/output register, and check
shared-work maxima, retained purification, disjoint placements, common
interfaces, unobserved-shape refusals and global request/query caps. Boundary
controls include T=0 and T=2^64, b=23 and b=4096, and rejected-size descriptors
through 2^64-1. These mathematical descriptors do not attest physical Vec
reachability or the native usize/input-authentication boundary.

All **154 frozen catalog paths and seven execution inputs** stayed unchanged in
the isolated replay. The 154 paths were restored from the authenticated, already
published request-machine, lifetime-ledger and content-resource bundles. Their
published manifests were checked before restoration; every restored file was
checked against its expected digest. This is selected-source custody, not an
atomic filesystem attestation or a complete runtime dependency closure.

The current worktree cannot replay this frozen catalog directly: its
`crates/iroha_parliament_ballot_proof/Cargo.toml` has SHA-256
`3224f341475b4e60fb4e8d778c43971a94d77534670cd2c9bebad444e76de904`, while
the captured source requires
`f1b9e23aceb1039ff92b3d4dc2f9a94d63afa35842b5b3541b7c9e32b00f76d5`.
The live CLI correctly exited 1 with a source-drift message and **no JSON
report**. All other selected catalog files matched; the live selection was
stable during this review. No source was repinned or rewritten to hide this
difference. Passing isolated controls validate the historical selected-source
model, not the changed current native candidate.

The replay's ordinary CLI returned exit 0. `--require-qualified` returned exit
2 with byte-identical conditional JSON. Every qualification flag remains false
and every external resource term remains unknown.

## Request-count finding

The source deletion theorem bounds **valid requests** by T; that bound alone
does not cap invalid public requests, witness-check refusals, raw decoding or
application work. This extension instead explicitly requires T to cap **all
typed request events**, including bounded-content and size rejection. That is
an additional, stronger experiment premise. `generating` counts generator
invocations and can include invalid content; it is not the theorem's valid
request count. The report leaves `source_theorem_valid_request_bound` unknown
and sets `all_event_cap_is_additional_premise` true.

The implementation enforces this distinction: a size rejection consumes one
typed-request event, even though it reserves no append slots. A bounded-content
event consumes one event and reserves M+2 slots without accepting a caller
validity hint. Its gates and coins are fully charged for either canonical P0
outcome. The ledger never evaluates actual validity or actual occupancy. Thus
it cannot silently use an invalid-content assertion to reduce cost, and it
cannot substitute a valid-only theorem budget for a bound on all events.

The remaining domain obligations identified in
[the family audit](../parliament-family-domain-stage/README.md) remain open:
typed versus raw construction, witness/application entry checks, family
selection and authentication, intermediate request shapes, invalid invocation
budgets outside this additional premise, preparation, base-oracle implementation
and adversary resources. Their omission is explicit, not priced as zero.

## Retained records

- [Review capture receipt](capture/receipt.json): SHA-256
  `98b62bb5a26908854053acc21938070e4f233db5cfeecb5669ed06e386f01746`.
- [Original capture manifest](capture/SHA256SUMS): SHA-256
  `91182d3f21abe305ee686ced91a9f1de88becda58d7e0e2b0405de5df87db01f`.
- Reviewed extension SHA-256:
  `36a86383ad0cd91264fdc0ff7b5fe0587f20c964370b84ea2c2a259431c55560`.
- [Independent controls](test_independent_content_ledger.py): SHA-256
  `53b04ad262df360676c96fb283a22be171f351c3ac8a6c40b61a3bb7c3e437fc`.

The capture retains exact stdout, stderr, JUnit case identities and commands.
It executes metadata accounting and refusals only; it does not regenerate the
four expensive factory observations or expand their full elementary gate streams.
Frozen published sources and observations were not modified.
