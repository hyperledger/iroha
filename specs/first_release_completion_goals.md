# First-release completion goals

Overall goal: **Active**. This plan coordinates first-release privacy/ZK,
SoraFS V1, consensus, SDK and release qualification.

The component ledgers remain the detailed acceptance authorities:
[privacy](privacy_first_release_closure.md),
[SoraFS](sorafs/v1_implementation_goals.md), and
[consensus and multilane](sumeragi_goals.md) with the
[lane design](sumeragi_lanes.md). A source change,
compiled profile, historical receipt, or synthetic fixture does not close a
release goal.

## Fixed requirements

- Work only in `/Users/takemiyamakoto/dev/iroha` on `optimizations`.
- First release means **no backward compatibility**: one final V1 implementation
  and wire contract; delete retired aliases, shims, fallback decoders, and
  competing legacy execution paths. Canonical account aliases remain ordinary
  product functionality, not compatibility aliases.
- IVM is the only VM. Use Norito; retain mandatory signed RS16 availability,
  exact validator quorums, deterministic execution, and committed policy.
- Privacy STARK outer commitments/transcripts use SHA3-384. Execution STARK,
  FASTPQ, BFV, and inner relations retain their specified six-lane constructions.
  This explicitly replaces the former blanket six-lane requirement.
- Preserve X509 certificate coverage and existing production proof, work,
  resident-memory, spool, and I/O ceilings. Oversized fixtures do not qualify.
- Authenticated software signing is the SoraFS release contract. HSM access is
  not a prerequisite. Authorization, revocation, rotation, durable completion,
  and independent evidence remain mandatory.
- Standalone elections hide credential identity and ballot choices beyond what
  final totals imply. Relayers do not become voter authority. Ordinary ballots
  are immutable; conviction updates preserve the choice and only increase the
  bond or extend its lock. Count only the latest accepted weight.
- Conviction weight uses exact smallest asset units with a frozen asset scale,
  the quadratic/conviction formula, and checked integer/aggregate bounds.
- Elections allow bounded voter phases and require late-dropout completion.
  No decryption committee, master decryption key, voter-secret reconstruction,
  omission of accepted ballots, or extra subset tally may supply recovery.
  A protocol meeting these requirements is still a cryptographic design
  deliverable; no rejected trustee or voter-held recovery design is approved.
  The [standalone protocol contract](standalone_election_protocol_contract.md)
  defines the required fault, phase, disclosure and rejection boundaries.

## Ordered goals

| ID | State | Outcome and owner | Completion criteria |
| --- | --- | --- | --- |
| F01 | Active | Source reconciliation — integration owner | Preserve SoraFS tracked/untracked source and original Git identity; reconcile onto current source without overwriting newer owners; integrate software-custody changes and regenerate combined-source artifacts. |
| F02 | Active | Resource admission and retained execution — Core/storage owners | Reserve actual allocations and side effects before work; retain original State/Queue, journals and resource owners through validation, publication, refusal and restart; execute each accepted subject once. Complete State-pool charging, scratch allocations, aggregate admission and maximum-shape runtime bounds. |
| F03 | Active | Native lane cutover and lifecycle — consensus owner | Shared reducer, pre-payload timeout/replacement, exact frozen contexts, durable votes and signed RS16 availability. Complete the original Apply consumer and retire the old signer together; qualify P2P outage/restart, drain and recreation. Lifecycle qualification depends on F02 ownership and admission. |
| F04 | Active | Software signing and promotion authority — SoraFS/daemon owners | Production providers and finalized state sources for all signing purposes; exact role authorization, durable Reserve/Complete recovery, independently verified topology, inventory, resilience and foundational approvals. Complete independent floor authority, successor provenance, ambiguous restart reconciliation, funded replay and interface regeneration. |
| F05 | Active; production grant blocked | SoraFS service backends — service owners | Finalized-ledger ingest/reputation, quarantine, PoP, moderation/viewer/appeal, PoTR, DAG and transparency. Complete concrete supervised backends, native council enactment, pre-allocation signer bounds, governed policy lineage, bounded outboxes, finalized grants and crash/rotation recovery. |
| F06 | Active | Native40/MKHE/Vega — proof owners | Authenticated source replay, sole commitment/opening inventory, complete delta producers, consuming composite admission, governed full-shape keys and a source-bound qPCS redesign within unchanged whole-proof limits. |
| F07 | Open | FASTPQ/AXT/X509 — proof and Core owners | Bounded compact proof admission, complete successful-execution and authoritative-state binding, durable spend nonces, and full X509 coverage within existing ceilings. Independent cryptographic and current network qualification remain required; see the component proof specifications. |
| F08 | Open | BFV qualification — crypto and independent reviewers | Complete the full BFV-RNS relation, full-size/eight-party adversaries and measured bounds; obtain real governed parameter/lattice/noise/qROM evidence before production qualification. Private masked contributions, durable authority/replay, governed signer profiles, matching decoder ceilings and independent audits remain open. The separate 40-limb replay belongs to F06. |
| F09 | Open | Exact12 completion — engine owners | Complete engine-specific soundness/key/provenance work and every adversarial, maximum-shape, resource, native/SDK/hardware and deployment requirement in the privacy ledger. Complete integrated output-binding tamper controls. |
| F10 | Open | Product privacy integration — product/Core owners | Anonymous Parliament ballots (frozen credential root, nullifier and qualified PQ membership proof; public votes and tally) and complete Kaigi privacy semantics, with durable authority, restart and resource qualification. |
| F11 | Active; private protocol unresolved | Standalone elections — protocol and product owners | An anonymous credential-authorized, choice-preserving, dropout-resilient election protocol with only the final accepted aggregate disclosed. Establish its complete opening, soundness and privacy arguments before production admission. |
| F12 | Active; final regeneration after interfaces settle | Canonical APIs and SDK/native packages — SDK/release owners | Canonical Kotlin-owned JVM/Android delivery and maintained SDK consumers; qualify actual installed native execution, retained package/runtime custody, source-bound fixtures and final artifact delivery. |
| F13 | Active; final runs after implementation | Formal/runtime/hardware qualification — validation owners | Required formal bounds, current-Native four-validator scenarios, larger-network resilience/scaling, full-proof hardware parity and fault quarantine, and unchanged-candidate resource evidence. Network scaling must compare authenticated lane activation, throughput and commit latency against the single-lane baseline. |
| F14 | Queued after F01–F13 | Audit, candidate sealing and promotion — release/operators/reviewers | Resolve audit findings; qualify one exact-source candidate; collect genuine signed release/promotion evidence, authenticated publication/readback and rollback qualification. Code line-count gates are retired. |

Work on independent owners proceeds concurrently. Shared Core/State/Queue/Kura
changes are reconciled by one integration owner. Do not turn on Native ingress
or a proof engine before its complete authoritative production consumer exists.

## Candidate acceptance

- Privacy: all twelve protocols, genuine 48-stage/54-artifact evidence,
  independent review, native/SDK/hardware qualification, and four-validator
  lifecycle, restart, convergence and endpoint readback.
- SoraFS: four voting validators, multiple providers, two regional gateways,
  two DAG instances, 1,000 concurrent streams, corruption/load/recovery testing,
  diagnostic load observations, disaster recovery and all 17 fresh signed readiness summaries.
  No fixed-duration soak or full regression suite is a deployment prerequisite;
  on-chain governance owns deployment policy.
- Multilane: roadmap N12 on the [lane design](sumeragi_lanes.md): four-validator
  fixed and elastic lane node tests, simulator coverage of a lane next to the
  global instance and a four-peer network soak with elastic scale-out/in under
  load and restarts.
- Scaling: five fixed-workload one-/four-lane pairs, at least 1.5x throughput
  and at most 1.25x p95 latency, with complete resource maxima through drain.
- Release: locked workspace builds/tests, strict Clippy, formatting, codec
  guards, script suites, double fixture/OpenAPI regeneration, five-target native
  reproducibility/install smokes, provenance, SBOMs and dependency scans.
- One immutable source/lock/toolchain/configuration/artifact identity must join
  every required final receipt. Failed, timed-out, skipped, unavailable and
  historical runs are never passes for that candidate.

## Progress and evidence discipline

Update the corresponding goal and component ledger when an outcome is actually
implemented and verified. Record relevant commands, source scope, failures and remaining limitations in
the owning PR or CI result; keep only significant validation and incident evidence
in repository documentation. Keep `status.md` and
`roadmap.md` within their 300-line limits.

Independent audits, trusted operator signatures, runtime credentials and
physical test runners are external inputs. Their absence does not stop
independent source implementation, and synthetic replacements cannot close
their gates. If the required election construction is not established, retain
F11 and final release as open while completing the other workstreams.
