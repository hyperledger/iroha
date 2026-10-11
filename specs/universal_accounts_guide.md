<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Universal Account Guide

This guide packages the implemented UAID (Universal Account ID) surfaces into
an operator- and SDK-focused source reference.
It covers UAID derivation, portfolio/manifest inspection, regulator templates,
and the evidence that must accompany every `iroha app space-directory manifest
publish` run.

## 1. UAID quick reference

- UAIDs are `uaid:<hex>` literals where `<hex>` is a Blake2b-256 digest whose
  LSB is set to `1`. The canonical type lives in
  `crates/iroha_data_model/src/nexus/manifest.rs::UniversalAccountId`.
- Account records (`Account` and `AccountDetails`) now carry an optional `uaid`
  field so applications can learn the identifier without bespoke hashing.
- Hidden-function identifier policies can bind arbitrary normalized inputs
  (phone numbers, emails, account numbers, partner strings) to `opaque:` IDs
  under a UAID namespace. The on-chain pieces are `IdentifierPolicy`,
  `IdentifierClaimRecord`, and the `opaque_id -> uaid` index.
- Space Directory maintains a `World::uaid_dataspaces` map that ties each UAID
  to the dataspace accounts referenced by active manifests. Torii reuses that
  map for the `/portfolio` and `/uaids/*` APIs.
- Sponsored alias onboarding is an explicit three-stage, token-authenticated flow.
  `POST /v1/accounts/onboard/plan` accepts the typed account/alias intent and
  returns a stateless plan receipt without mutating state. The caller sends that
  receipt and one immutable public-reset binding to
  `POST /v1/accounts/onboard/prepare`, verifies the authority/network trust pins,
  receipt hash, exact signed transaction wire, fee intent, metadata, and outer
  server signature, and persists the authenticated envelope before explicitly
  submitting those same bytes to `POST /v1/accounts/onboard`. An authenticated
  `ProofRequired` result is nonterminal, has no transaction, and is never
  submitted. Every prepare or reopen instead sends exactly one closed request
  to `POST /v1/accounts/onboarding/current-state`; only one snapshot-bound
  response proving the exact account exists and exact alias targets it may be
  classified as applied. An absent or conflicting observation remains
  nonterminal. V1 request and receipt JSON is closed and field-exact: callers
  send `permissions: []` when no permissions are requested and encode absent
  pricing, quote, instruction-index, and owner-auto-renew slots as explicit
  `null`; omitting any of those fields is invalid. The
  credential token is supplied in an authentication header from a protected
  token file, never in the URL, command line, plan, or HTTP body; private keys
  never cross HTTP. Repairable derived state is repaired without reacquiring the
  lease, and drift returns a structured 409. This is the sole server-signing
  exception; operator setup plans are verified, signed locally, and submitted
  through the ordinary transaction endpoint.
- All SDKs expose helpers for validating UAID literals (e.g., `UaidLiteral` in
  the Android SDK). They accept only exact lower-case `uaid:<64-hex>` values,
  enforce the LSB marker, and re-use the same Norito codecs so the digest cannot
  drift across languages.

## 1.1 Hidden identifier policies

UAIDs are now the anchor for a second identity layer:

- A global `IdentifierPolicyId` (`<kind>#<business_rule>`) defines the
  namespace, public commitment metadata, resolver verification key, and the
  canonical input normalisation mode (`Exact`, `LowercaseTrimmed`,
  `PhoneE164`, `EmailAddress`, or `AccountNumber`).
- A claim binds one derived `opaque:` identifier to exactly one UAID and one
  canonical `AccountId` under that policy, but the chain only accepts the
  claim when it is accompanied by a signed `IdentifierResolutionReceipt`.
- The first-release phone namespace is exactly `phone#retail` with
  `PhoneE164` normalization and the signed programmed BFV `phone_retail`
  program. Its policy pins a canonicality-attestor public key. Each claim and
  resolution carries that attestor's signature over the network, encrypted
  input/output commitments, opened output, beneficiary, and a secret-keyed
  canonical E.164 nullifier. The nullifier determines the global `opaque:`
  handle, so a second ciphertext for the same phone cannot bind another UAID.
- Resolution remains a `resolve -> transfer` flow. Torii resolves the opaque
  handle and returns the canonical `AccountId`; transfers still target the
  canonical account, not `uaid:` or `opaque:` literals directly.
- Policies can now publish BFV input-encryption parameters through
  `PolicyCommitment.public_parameters`. When present, Torii advertises them on
  `GET /v1/identifier-policies`, and clients must submit BFV-wrapped input.
  Programmed policies wrap the BFV parameters in a canonical
  `BfvProgrammedPublicParameters` bundle that also publishes the public
  `ram_fhe_profile`; legacy raw BFV payloads are rejected for the first
  release.
- The identifier routes go through the same Torii access-token and rate-limit
  checks as other app-facing endpoints. They are not a bypass around normal
  API policy.

## 1.2 Terminology

The naming split is intentional:

- `ram_lfe` is the outer hidden-function abstraction. It covers policy
  registration, commitments, public metadata, execution receipts, and
  verification mode.
- `BFV` is the Brakerski/Fan-Vercauteren homomorphic encryption scheme used by
  some `ram_lfe` backends to evaluate encrypted input.
- `ram_fhe_profile` is BFV-specific metadata, not a second name for the whole
  feature. It describes the programmed BFV execution machine that wallets and
  verifiers must target when a policy uses the programmed backend.

In concrete terms:

- `RamLfeProgramPolicy` and `RamLfeExecutionReceipt` are LFE-layer types.
- `BfvParameters`, `BfvCiphertext`, `BfvProgrammedPublicParameters`, and
  `BfvRamProgramProfile` are FHE-layer types.
- `HiddenRamFheProgram` and `HiddenRamFheInstruction` are internal names for
  the hidden BFV program executed by the programmed backend. They stay on the
  FHE side because they describe the encrypted execution mechanism rather than
  the outer policy or receipt abstraction.

## 1.3 Account identity versus aliases

Universal-account rollout does not change the canonical account identity model:

- `AccountId` remains the canonical, domainless account subject.
- `AccountAlias` values are separate SNS bindings on top of that subject. A
  domain-qualified alias such as `merchant@banka.paynet` and a dataspace-root alias
  such as `merchant@paynet` can both resolve to the same canonical `AccountId`.
- Canonical account registration is always `Account::new(AccountId)` /
  `NewAccount::new(AccountId)`; there is no domain-qualified or domain-materialized
  registration path.
- Domain ownership, alias permissions, and other domain-scoped behaviors live
  in their own state and APIs rather than on the account identity itself.
- Canonical account identity remains a pure `AccountId`. Alias read visibility
  is derived from dataspace/lane policy: public-dataspace aliases may resolve
  unsigned, while restricted dataspaces require canonical request
  authentication and applicable resolve permission.

Implementation rule for operators, SDKs, and tests: start from the canonical
`AccountId`, then add alias leases, dataspace/domain permissions, and any
domain-owned state separately. Do not synthesize a fake alias-derived account
or expect any linked-domain field on account records just because an alias or
route carries a domain segment.

Current Torii routes:

| Route | Purpose |
|-------|---------|
| `GET /v1/ram-lfe/program-policies` | Lists active and inactive RAM-LFE program policies plus their public execution metadata, including optional BFV `input_encryption` parameters and the programmed-backend `ram_fhe_profile`. |
| `POST /v1/ram-lfe/programs/{program_id}/execute` | The current ledger program owner signs the exact POST URI and raw `{ normalized_input, input_nonce }` body. The production HKDF PRF returns `opaque_output` and a signed execution receipt. The input nonce must be 32 nonzero bytes of exact lowercase hex; it blinds the public input commitment without changing the identifier. |
| `POST /v1/ram-lfe/receipts/verify` | Statelessly validates a signed `RamLfeExecutionReceipt` against the published on-chain program policy and optionally checks that a caller-supplied output bytes in `output_hex` matches the receipt `output_hash`. Proof mode rejects until the [complete program-execution relation](ram_lfe_execution_proof.md) is implemented and qualified. |
| `GET /v1/identifier-policies` | Lists active and inactive hidden-function policy namespaces plus their public metadata, including optional BFV `input_encryption` parameters, the exact `normalization` mode for current canonical owner input, and `ram_fhe_profile` for programmed BFV policies. |
| `POST /v1/accounts/{account_id}/identifiers/claim-receipt` | The current identifier and program policy owner signs `{ phase, policy_id, normalized_input, input_nonce, output_opening?, phone_retail_canonicality? }`. `prepare` returns the actual pinned-key native opening and an unsigned beneficiary projection for an independent phone attestor. `claim` authenticates the exact original opening and phone proof before signing a prospective receipt for the selected existing beneficiary account and UAID. It does not admit the claim on-chain. |
| `POST /v1/identifiers/resolve` | The same policy owner signs the current schema with `phase: "claim"`. Native re-evaluation must match the original opening, nonce-blinded input commitment and independent phone signature. Resolution requires an existing active admitted claim. |
| `GET /v1/identifiers/receipts/{receipt_hash}` | Looks up the persisted `IdentifierClaimRecord` bound to a deterministic receipt hash so operators and SDKs can audit claim ownership or diagnose replay / mismatch failures without scanning the full identifier index. |

The three owner-input POST routes authenticate the exact genesis-derived NetworkId,
method, URI and raw bounded JSON body before decoding or private evaluation.
The authenticated account must be the current ledger program owner and, for
identifier requests, the exact identifier policy owner. The claim path selects
an existing beneficiary account and UAID; ownership authorization does not come
from that path account. API tokens do not replace the account signature.

Encrypted RAM-LFE and identifier execution are currently unavailable. Core
registration, activation, restoration and receipt admission reject both
`bfv-affine-v1` and `bfv-programmed-v1`, including signed mode. The diagnostic
exact-lift BFV construction exposes a noiseless public-key equation; signatures
and execution proofs cannot repair that encryption defect. The supported
`hkdf-sha3-512-prf-v1` primitive is not encrypted-input evaluation.

The retained configuration uses `torii.ram_lfe.programs[*]`, keyed by
`program_id`, with a validated clearing hidden-program owner. No configuration
setting enables the rejected BFV profile. The compiled initializer descriptor,
canonical program frame and relinearization-only program metadata remain
validation requirements for stored diagnostic material.

The current PRF transcript binds the actual network, exact program and normalized
owner input using canonical Norito. Its public input commitment additionally
binds a caller-retained random nonce. Only the genuine native opaque output is
returned; the generic evaluator's echoed input is immediately cleared. A claim
reuses its original signed opening time, signature and expiry (at most 120000ms)
without renewal. The exact `phone#retail`/`phone_retail` contract independently
pins an attestor distinct from the resolver and opener and binds network,
program, policy, input commitment, output/nullifier, beneficiary, UAID and lease.
Production signing still requires the actual configured runtime secret and
ledger-pinned signing key. Source/component controls do not establish operator,
device, Kagemusha monetary authority or release admission.

SDK policy/receipt decoders accept only the exact compiled backend names and
`signed`/`proof` metadata. Metadata decoding is not proof verification or feature
activation. Local plaintext-encryption helpers refuse with
`ram_lfe_encryption_unavailable`; caller-supplied seed overrides and shipped
exact-lift encryption implementations are being retired. Retired encrypted-input request DTOs are rejected. Current SDK callers of those
retired methods require a coordinated source port; no fallback decoder remains.

The instruction identities remain `RegisterIdentifierPolicy`,
`ActivateIdentifierPolicy`, receipt-bound `ClaimIdentifier` and `RevokeIdentifier`.
Private claim/revoke/rebind component tests preserve account, UAID, lifetime and
index constraints, while actual BFV entry points require refusal with unchanged
state. See [the execution contract](ram_lfe_execution_proof.md),
[remediation goals](zk_first_release_goals.md), and the public
[RAM-LFE availability guide](https://docs.iroha.tech/blockchain/ram-lfe).

## 2. Deriving and verifying UAIDs

There are three supported ways to obtain a UAID:

1. **Read it from world state or SDK models.** Any `Account`/`AccountDetails`
   payload queried via Torii now has the `uaid` field populated when the
   participant opted into universal accounts.
2. **Query the UAID registries.** Torii exposes
   `GET /v1/space-directory/uaids/{uaid}` which returns the dataspace bindings
   and manifest metadata the Space Directory host persists (see
   `specs/space_directory.md` §3 for payload samples).
3. **Derive it deterministically.** When bootstrapping new UAIDs offline, hash
   the canonical participant seed with Blake2b-256, set the final byte's least
   significant bit to `1`, and prefix the result with `uaid:`. The snippet
   below mirrors the helper documented in
   `specs/space_directory.md` §3.3:

   ```python
   import hashlib
   seed = b"participant@example"  # canonical address/domain seed
   digest = bytearray(hashlib.blake2b(seed, digest_size=32).digest())
   digest[-1] |= 1
   print(f"uaid:{digest.hex()}")
   ```

Always emit the exact lower-case `uaid:<64-hex>` literal. Whitespace, a missing
prefix, an upper-case prefix or digest, and a hash without the low bit are all
rejected by first-release CLI, SDK, and Torii parsers.

## 3. Inspecting UAID holdings and manifests

The deterministic portfolio aggregator in `iroha_core::nexus::portfolio`
surfaces every asset/dataspace pair that references the UAID. Operators and SDKs
can consume the data through the following surfaces:

| Surface | Usage |
|---------|-------|
| `GET /v1/accounts/{uaid}/portfolio` | Returns dataspace → asset → balance summaries; described in `specs/torii/portfolio_api.md`. |
| `GET /v1/space-directory/uaids/{uaid}` | Lists dataspace IDs + account literals tied to the UAID. |
| `GET /v1/space-directory/uaids/{uaid}/manifests` | Provides paginated `AssetPermissionManifest` history for audits. |
| `iroha app space-directory bindings fetch --uaid <literal>` | CLI shortcut that wraps the bindings endpoint and optionally writes the JSON to disk (`--json-out`). |
| `iroha app space-directory manifest fetch --uaid <literal> --json-out <path>` | Fetches the manifest JSON bundle for evidence packs. |

Example CLI session (Torii URL configured via `torii_api_url` in `iroha.json`):

```bash
iroha app space-directory bindings fetch \
  --uaid uaid:86e8ee39a3908460a0f4ee257bb25f340cd5b5de72735e9adefe07d5ef4bb0df \
  --json-out artifacts/uaid86/bindings.json

iroha app space-directory manifest fetch \
  --uaid uaid:86e8ee39a3908460a0f4ee257bb25f340cd5b5de72735e9adefe07d5ef4bb0df \
  --json-out artifacts/uaid86/manifests.json
```

Store the JSON snapshots alongside the manifest hash used during reviews; the
Space Directory watcher rebuilds the `uaid_dataspaces` map whenever manifests
activate, expire, or revoke, so these snapshots are the fastest way to prove
what bindings were active at a given epoch.

## 4. Publishing capability manifests with evidence

Use the CLI flow below whenever a new allowance is rolled out. Each step must
land in the evidence bundle recorded for governance sign-off.

1. **Encode the manifest JSON** so reviewers see the deterministic hash before
   submission:

   ```bash
   iroha app space-directory manifest encode \
     --json fixtures/space_directory/capability/eu_regulator_audit.manifest.json \
     --out artifacts/eu_regulator_audit.manifest.to \
     --hash-out artifacts/eu_regulator_audit.manifest.hash
   ```

2. **Publish the allowance** using either the Norito payload (`--manifest`) or
   the JSON description (`--manifest-json`). Record the Torii/CLI receipt plus
   the `PublishSpaceDirectoryManifest` instruction hash:

   ```bash
   iroha app space-directory manifest publish \
     --manifest artifacts/eu_regulator_audit.manifest.to \
     --reason "ESMA wave 2 onboarding"
   ```

3. **Capture SpaceDirectoryEvent evidence.** Subscribe to
   `SpaceDirectoryEvent::ManifestActivated` and include the event payload in
   the bundle so auditors can confirm when the change landed.

4. **Generate an audit bundle** tying the manifest to its dataspace profile and
   telemetry hooks:

   ```bash
   iroha app space-directory manifest audit-bundle \
     --manifest artifacts/eu_regulator_audit.manifest.to \
     --profile fixtures/space_directory/profile/cbdc_lane_profile.json \
     --out-dir artifacts/eu_regulator_audit_bundle
   ```

5. **Verify bindings via Torii** (`bindings fetch` and `manifests fetch`) and
   archive those JSON files with the hash + bundle above.

Evidence checklist:

- [ ] Manifest hash (`*.manifest.hash`) signed by the change approver.
- [ ] CLI/Torii receipt for the publish call (stdout or `--json-out` artefact).
- [ ] `SpaceDirectoryEvent` payload proving activation.
- [ ] Audit bundle directory with dataspace profile, hooks, and manifest copy.
- [ ] Bindings + manifest snapshots fetched from Torii post-activation.

This mirrors the requirements in `specs/space_directory.md` §3.2 while giving SDK
owners a single page to point to during release reviews.

## 5. Regulator/regional manifest templates

Use the in-repo fixtures as starting points when crafting capability manifests
for regulators or regional supervisors. They demonstrate how to scope allow/deny
rules and explain the policy notes reviewers expect.

| Fixture | Purpose | Highlights |
|---------|---------|------------|
| `fixtures/space_directory/capability/eu_regulator_audit.manifest.json` | ESMA/ESRB audit feed. | Read-only allowances for `compliance.audit::{stream_reports, request_snapshot}` with deny-wins on retail transfers to keep regulator UAIDs passive. |
| `fixtures/space_directory/capability/jp_regulator_supervision.manifest.json` | JFSA supervision lane. | Adds a capped `cbdc.supervision.issue_stop_order` allowance (PerDay window + `max_amount`) and an explicit deny on `force_liquidation` to enforce dual controls. |

When cloning these fixtures, update:

1. `uaid` and `dataspace` ids to match the participant and lane you’re enabling.
2. `activation_epoch`/`expiry_epoch` windows based on the governance schedule.
3. `notes` fields with the regulator’s policy references (MiCA article, JFSA
   circular, etc.).
4. Allowance windows (`PerSlot`, `PerMinute`, `PerDay`) and optional
   `max_amount` caps so SDKs enforce the same limits as the host.

## 6. Current SDK contract

The first-release SDK surface has one account model; it does not expose a legacy
domain-scoped account identity or migration overload.

- **Identity:** Construct `AccountId` from its public key only. Domain and
  dataspace context belongs to alias leases, routing, and domain-owned state,
  never to the canonical account identifier or address bytes.
- **API calls:** Query a UAID portfolio through
  `GET /v1/accounts/{uaid}/portfolio` and use the manifest/bindings endpoints.
  `GET /v1/accounts/{uaid}/portfolio` accepts an optional `asset_id` query
  parameter when wallets only need a single asset instance. Client helpers such
  as `ToriiClient.getUaidPortfolio` (JS) and the Android
  `SpaceDirectoryClient` wrap these routes.
- **Caching & telemetry:** Key contextual caches by UAID plus dataspace and emit
  telemetry showing the UAID literal so operations can
  line up logs with Space Directory evidence.
- **Error handling:** Endpoints return the strict UAID parsing errors
  documented in `specs/torii/portfolio_api.md`; surface those codes
  verbatim so support teams can triage issues without repro steps.
- **Testing:** Wire the fixtures mentioned above plus your own UAID manifests
  into SDK test suites to prove Norito round-trips and manifest evaluations
  match the host implementation.

## 7. References

- `specs/space_directory.md` — source-adjacent operator and lifecycle reference.
- `specs/torii/portfolio_api.md` — REST schema for UAID portfolio and
  manifest endpoints.
- `crates/iroha_cli/src/space_directory.rs` — CLI implementation referenced in
  this guide.
- `fixtures/space_directory/capability/*.manifest.json` — regulator, retail, and
  CBDC manifest templates ready for cloning.
