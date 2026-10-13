# TradFi ISO 20022 Interop Audit

This audit describes the repository-level ISO 20022 and TradFi interoperability
surface. It is a design and implementation map for broad interop readiness; it
does not claim direct live SWIFT, Fedwire, SEPA, or CSD network connectivity.

## Standards Baseline

- ISO 20022 message definitions, MDRs, schemas, examples, Business Application
  Header material, external code sets, and SupplementaryData material remain the
  canonical source of truth for message layout and versioning.[^iso_catalogue]
- Swift CBPR+ is now ISO 20022-first: Swift reports that the MT and ISO 20022
  coexistence period for cross-border payments and reporting ended on
  2025-11-22, after which ISO 20022 is required for payment instructions on that
  rail.[^swift_cbpr]
- Fedwire Funds completed its ISO 20022 migration on 2025-07-15, so any Fedwire
  profile must be strict about the selected message version, business service,
  participant identifiers, and USD minor units.[^fedwire_iso]
- CPMI harmonisation guidance is maintained through at least end-2027; the bridge
  should treat those requirements as profile input for cross-border payment
  data quality, not as a runtime network connection.[^cpmi_harmonisation]

## Current Repository Surface

- `ivm::iso20022` contains deterministic parsers and static schemas for payment,
  securities, cash-management, and collateral message families.
- Torii exposes `pacs.008` and `pacs.009` ingestion plus lifecycle/status
  submission for payment, securities, and collateral follow-up messages. The
  bridge builds signed transfer transactions from configured account aliases,
  currency bindings, and reference-data snapshots, and records non-ledger
  lifecycle messages durably for audit. Both payment routes use `GrpHdr/MsgId`
  as the primary lifecycle/replay key; `pacs.009` keeps the BAH `BizMsgIdr` as
  an independent secondary identity rather than collapsing the two fields.
- The JavaScript SDK contains builders for `pacs.*` and `camt.*` payloads and
  client helpers for Torii ISO submissions and polling. Its `pacs.009` builder
  binds any custom `messageDefinitionId` to both `MsgDefIdr` and the `Document`
  XSD namespace so SDK-generated XML satisfies the runtime declaration
  consistency check.
- The CLI can emit `sese.023` and `sese.025` settlement previews for DvP/PvP
  flows, with optional reference-data validation for delivery instrument IDs.
- Reference-data loaders ingest ISIN/CUSIP, BIC/LEI, and MIC snapshots from
  operator-provided files. No runtime remote fetch is performed.

## Implemented In This Pass

- Added a shared static profile catalog in `iroha_core::iso_bridge::profiles`
  for:
  - `generic-iso20022`
  - `swift-cbpr-plus`
  - `fedwire-funds`
  - `sepa-sct-inst`
  - `securities-csd`
- Extended `iso_bridge` config with:
  - `default_profile`
  - `profiles`
  - `store_dir`
  - `embedded_signature_policy`
  - per-profile required reference datasets and message profiles, with
    duplicate profile IDs, duplicate reference requirements, and duplicate
    message family/direction entries rejected at configuration load
  - non-empty trimmed profile identifiers, rail names, embedded signature
    policies, message types, directions, structured-address modes, required
    reference dataset names, amount minor-unit currency literals, X.509
    certificate-policy OIDs, and CRL/OCSP DER base64 material; duplicate OID,
    decoded CRL, and decoded OCSP entries fail closed instead of being silently
    de-duplicated; embedded catalog CRL/OCSP material must have CRL-like or
    successful Basic OCSP DER response shape; Torii runtime overrides reject
    malformed but base64-valid configured CRL/OCSP DER and over-limit
    revocation-material lists at configuration load; embedded catalog,
    offline-preflight, and runtime override CRL/OCSP material lists share the
    same `8`-entry cap; stale XMLDSig trust-pin alias fields are malformed, and
    current public-key, X.509 trust-anchor, and revoked-certificate pin roles
    cannot overlap; operator canary, trust-bundle, operator-evidence, and final
    readiness `provider`/`environment` context labels must be canonical
    lowercase IDs with hyphen separators; executed canaries reject placeholder
    context IDs before child execution, and trust-bundle plus production
    evidence/readiness replay rejects exact placeholder context IDs such as
    `example`, `sample`, `template`, `ci`, and `test` as well as
    hyphen-tokenized placeholder aliases such as `example-bank`,
    `sample-preprod`, and `test-preprod`
- Made Torii inbound validation profile-aware for existing `pacs.008` and
  `pacs.009` endpoints:
  - profile selected only by the signed canonical `?profile=...` query; the
    retired `X-Iroha-Iso-Profile` header is rejected
  - message definition version and business service checks
  - real-XML parser binding for all observed message-definition declarations:
    production routes call the real-XML-only entry point; the internal
    `<ISO20022>` and key/value formats remain developer/test APIs and cannot
    reach Torii admission. Parsing has deterministic limits for nesting depth,
    elements, per-element and total attributes, normalized path bytes, and
    materialized fields. Budget exhaustion fails before unbounded traversal or
    allocation.
    BAH/body `MsgDefIdr` values plus `Document` and immediate payload-root XSD
    namespaces must resolve through the current XML namespace scope and agree on
    the exact concrete MDR version. Valid default or prefixed ISO namespaces are
    accepted only when they use the exact
    `urn:iso:std:iso:20022:tech:xsd:` prefix; unqualified roots, spoofed
    prefixes/suffixes, and payload-root namespace rebinding fail before profile
    admission. The same parser path now requires closing tags to match the
    opened qualified name exactly and rejects extra, attributed, or unclosed
    tags before field extraction can succeed. XML attributes are now parsed
    fail-closed as well: unquoted or unterminated values, malformed trailing
    attributes, empty or unsupported names, and duplicate attribute names are
    rejected before namespace resolution. XML text and attribute values decode
    predefined and numeric XML character references before declaration matching
    or field storage, while unknown, unterminated, invalid numeric references and
    raw invalid XML characters or raw less-than characters in attributes fail
    closed. Simple element text is buffered until close, so comments or
    processing instructions inside simple content cannot overwrite earlier text
    chunks; structured elements reject mixed non-whitespace text before or after
    child elements, and XML inputs must have a single root with no trailing
    non-whitespace text. XML special markup is handled before normal tag
    parsing: well-formed comments and processing instructions are skipped
    deliberately, while malformed comments/processing instructions, CDATA,
    `DOCTYPE`, and other declarations fail closed. Exact versioned parser
    requests reject drift. `AppHdr` and `Document` establish exact semantic
    namespaces which every ordinary descendant must retain; transparent wrapper
    names, descendant namespace resets/rebinding, and multiple XML paths that
    collapse to one canonical bridge field are rejected. Supported element, attribute,
    namespace-declaration, and processing-instruction QNames are validated before
    local-name matching, so malformed names such as doubled namespace separators
    or digit-leading element names cannot satisfy `Document` or payload-root
    checks. Canonical family requests continue into profile allowlist validation
    only when the payload declarations are internally consistent. The internal
    deterministic `<ISO20022>` wrapper parser uses the same strict attribute
    parser and rejects spoofed attribute names, unsupported encodings, malformed
    field paths, ignored non-root markup, and raw nested field markup
  - config rejection for message profiles whose accepted ISO message-definition
    `versions` allowlist is empty, blank-padded, or duplicate
  - Business Application Header checks for live profiles, including fail-closed
    missing `BizMsgIdr`, `MsgDefIdr`, `CreDt`, missing/empty `BizSvc` coverage
    before live-rail admission, plus config rejection for required `BizSvc`
    profiles whose `business_services` allowlist is empty, blank-padded, or
    duplicate
  - UETR capture and replay detection
  - profile-required reference-data gates
  - amount minor-unit checks, including duplicate normalized currency override
    rejection and the ISO 4217 maximum minor-unit precision bound
  - structured address and SupplementaryData limits, including exact/key-path
    and live XML regressions for `PstlAdr/AdrLine` and oversized
    `SplmtryData`
  - embedded XMLDSig/XAdES markers recorded for generic ISO, rejected for live
    profiles that do not enable verification, and accepted for
    `require-verified` profiles only after P-256/SHA-256 verification plus
    profile-specific public-key, leaf-certificate, or linked certificate-chain
    SHA-256 pin matching with uncompressed P-256 SEC1 raw public-key
    validation, leaf `digitalSignature`, and issuer critical
    CA `basicConstraints`/`keyCertSign` policy checks, certificate-chain
    ECDSA-with-SHA256/secp256r1 plus uncompressed P-256 SEC1 SPKI enforcement,
    child issuer distinguished-name binding to parent subject distinguished
    names, issuer path-length constraint enforcement, unsupported-critical-extension
    rejection, and validity-at-signing checks using verified signed XAdES
    `SigningTime` or BAH `CreDt`. Unsigned
    signature-local `SigningTime` values are not trusted. ECDSA `SignatureValue`
    accepts fixed-width P-256 `r || s` and DER encodings only when `s` is
    canonical low-S.
    Reference URIs are limited to one empty URI or one unique same-document `#id`
    target that strictly encloses the verified signature carrier, with an
    enveloped-signature transform first, at most one final
    supported C14N transform that controls digest canonicalization, and SHA-256
    digest method. Real-XML parsing records the source SHA-256 and the owning
    source range for every materialized semantic field. Verification requires
    the exact submitted payload and requires every such field to lie inside the
    verified payload Reference, preventing a correctly signed inner subtree
    from authorizing unsigned header or sibling semantics. One optional XAdES `SignedProperties` Reference may target a
    local `#id` with the XAdES `SignedProperties` Type URI, exactly one supported
    C14N transform, and a SHA-256 digest; its enclosing `QualifyingProperties`
    target must bind to the enclosing `Signature` `Id`. Certificate-backed XAdES
    signatures must present a non-empty, duplicate-free ordered prefix of the
    verified XMLDSig certificate-chain SHA-256 digests, starting with the leaf
    certificate. The supported signed-property subset requires direct
    `Signature/Object/QualifyingProperties/SignedProperties/SignedSignatureProperties`
    structure; `QualifyingProperties` accepts only `Target`,
    `SigningCertificateV2` accepts only attribute-free direct `Cert` children
    with attribute-free direct `CertDigest` children, a `DigestMethod` carrying
    only `Algorithm`, and text-only digest values; signed `SigningTime` is a
    singleton attribute-free text leaf. Prefixed XAdES structural elements must
    resolve to the ETSI XAdES v1.3.2 namespace, and unprefixed XMLDSig/XAdES
    structural elements reject explicit conflicting default namespaces. Any
    `SignedProperties` element under the signature must be the verified
    referenced direct target; unreferenced, wrapped, or duplicate
    `SignedProperties` elements fail closed.
    Same-document targets carry ancestor namespace
    declarations into root canonicalization, constrained to a fail-closed
    supported canonical XML subset for empty-element expansion, attribute quote normalization, namespace
    declarations plus unprefixed, declared prefixed, and implicit `xml:`
    attribute sorting, legal `xmlns:xml` declaration omission, and
    predefined/numeric XML character-reference decoding.
    Supported XMLDSig method and transform elements are parameter-free and reject
    non-whitespace child content such as `InclusiveNamespaces`, XPath, HMAC, or
    digest parameters. Method, transform, digest, and Reference policy
    attributes are read by exact XML attribute name only, so namespace-qualified
    spoof attributes fail closed. Critical method elements must appear exactly once, and
    Reference transforms must be enclosed in exactly one attribute-free
    `Transforms` wrapper; only implemented ordinary attributes are accepted
    (`Algorithm`, payload Reference `URI`, and XAdES Reference `URI`/`Type`).
    Extra direct children under `Reference` or `Transforms` fail closed, and
    supported References must keep direct children ordered as `Transforms`,
    `DigestMethod`, then `DigestValue`.
    Top-level `Signature` and `SignedInfo` parsing accepts only implemented
    direct children in supported XMLDSig order, so reordered or wrapped
    `SignedInfo` or method nodes, unsupported direct children, and duplicate
    singleton signature nodes fail closed. The payload may contain exactly one
    supported signature carrier: either a bare XMLDSig `Signature` or an ISO
    `Sgntr` wrapper with exactly one direct XMLDSig `Signature` child. Any
    additional `Signature`/`Sgntr` element outside the verified carrier fails closed.
    Prefixed XMLDSig structural elements
    must resolve to the XMLDSig namespace in their inherited scope across
    `Signature`, `SignedInfo`, Reference transforms/digests, and public-key or
    X.509 `KeyInfo` material. Supported XML element spans require exact
    qualified-name matches between opening and closing tags.
    Required XMLDSig base64 fields reject duplicates and must be attribute-free
    text leaves without nested markup or comments, and `PublicKey`/
    `X509Certificate` credential leaves follow the same no-markup rule.
    Public-key material cannot be mixed with `X509Certificate` material in one `KeyInfo`; key
    material must be scoped to exactly one structured `KeyInfo` using either
    `KeyValue/ECKeyValue` with P-256 `NamedCurve` or one `X509Data` wrapper,
    with unsupported direct child elements, unsupported ordinary attributes, and
    non-whitespace wrapper text rejected.
    Valid XML comments are omitted for the supported no-comments C14N algorithms.
    Root namespace declarations inherited from the enclosing `Signature` are
    applied by C14N mode: all inherited root declarations for inclusive C14N and
    only visibly used inherited root declarations for exclusive C14N.
    `revoked_certificate_sha256` pins deny otherwise trusted chains
- Added durable ISO bridge state under `store_dir/messages/*.json`, including
  payload hash, profile metadata, UETR, transaction hash, status history, reason
  codes, context, reference snapshot id, and a deterministic `record_sha256`
  digest that binds the persisted JSON body.
- Serialized local admission, replay-index mutation, pruning, compaction, and
  persistence ordering under one re-entrant state lock. Concurrent admissions
  cannot both reserve the same payload digest, business message id, or UETR,
  and a retry of a definitely rejected identifier must retain the exact original
  metadata tuple. The exact signed transaction hash is bound before queue
  dispatch. When `store_dir` is configured, its record is written through a
  synced owner-only temporary file and atomic rename, and a known write failure
  prevents dispatch. An indeterminate plan-journal result remains pending and
  retention-pinned for exact-hash reconciliation instead of being marked
  rejected and retried as a replacement transfer.
- ISO admission now authenticates against a canonical participant catalog with
  unique participant IDs, operator keys, financial identities, allowed
  profiles, and lifecycle roles; audit-admin keys are configured separately.
  The authenticated participant must own an initial message's `From` identity.
  `IsoMessageRecordV2` immutably records originator, counterparty, admitting
  operator, pinned profile and signature policy, and replay identities.
- Lifecycle updates are authorized from the referenced record rather than a
  caller-selected profile: `pacs.002`, `pacs.004`, `sese.024`, and `sese.025`
  belong to the original counterparty, while `camt.056` belongs to the
  originator. Missing or cross-profile evidence fails closed, in-flight
  originals are not mutated, and rejected originals are terminal. A settling
  `pacs.002` additionally requires authenticated successful execution of the exact
  original transaction through the canonical outcome resolver also used by
  reconciliation. A rejected transaction's inclusion is insufficient; absent or
  conflicting canonical evidence refuses before reserving the notification identity,
  allowing the same notification to resume after evidence becomes available.
  Explicit `pacs.004` reports are separate journaled evidence; unresolved original
  outcomes remain pending through restart and retention, and a local notification
  wakes canonical reconciliation without later network traffic. Reports preserve
  the original successful status, transaction hash, and settlement evidence; other stale
  transitions remain ignored. Direct status mutators enforce the same terminal
  monotonicity.
- Either recorded party may read its own records; configured audit admins have
  global read-only access. Outbound ISO documents are signed. Prunable record
  details are separated from durable replay tombstones, so message ID, payload
  hash, business message ID, and UETR remain reserved for the full dedupe TTL.
- The exact append-only `status_history` is bounded in V1 to 256 entries and
  256 KiB of canonical compact JSON. Live lifecycle updates build a bounded
  candidate and reject the whole transition before changing memory, indexes, or
  durable files when either limit would be crossed; they never silently drop an
  older audit entry. The associated deduplicated `change_reason_codes` list is
  independently bounded to 64 entries and 16 KiB of canonical compact JSON, so
  distinct unknown lifecycle codes cannot grow behind an unchanged derived
  status. Startup likewise rejects rather than truncates either over-limit
  persisted collection.
- Added a deterministic local audit index at
  `store_dir/audit/messages.index.json`; it lists sorted durable message
  entries, links each entry to the message file's `record_sha256`, and carries
  its own `index_sha256` digest for external archival or notarization. Torii now
  serves the same deterministic manifest at
  `GET /v1/iso20022/audit/messages` after the normal access checks. The local
  V2 index is written atomically and capped at 32 MiB. On startup, an existing
  index must be a direct regular file with the exact V2 root/row schema,
  canonical ordering, count, and self-digest. Because the index is derived and
  is not transactionally committed with each record rename, a missing or
  schema-valid stale index is recoverable and is regenerated only after every
  persisted message and replay tombstone has passed validation.
- Added operator-controlled durable-store retention with
  `store_retention_secs` and `store_max_records`. Age retention remains disabled
  by default, while count retention defaults to 256 records and is fail-closed
  above the first-release hard maximum of 1024. Startup treats an existing
  non-directory store component, unreadable JSON, missing or nonnumeric schema
  version, non-V2 schema, bad digest, filename drift, or immutable-identity
  conflict as an incompatibility and stops without silently dropping a record.
  It reads each record through a stable 1 MiB-capped file handle and validates
  the complete store before applying retention. Compaction removes only replay-
  expired rich records, preserves unexpired replay identities even after an
  operator lowers the configured capacity, clears expired indexes, deletes the
  corresponding `store_dir/messages/*.json` files, and regenerates the audit
  index from survivors. Records with a prepared
  transaction hash and unknown queue outcome are not removed by TTL, age, or
  count compaction; admission fails closed when only such pinned records remain.
- The bounded durable cache is still node-local and optional, so it is not a
  permanent network-wide replay guarantee. Complete idempotency requires an
  on-ledger/consensus claim over the ISO message id, payload digest, business
  message id, UETR, and exact signed transaction hash, committed atomically with
  the resulting transfer.
- Added `audit_export_dir`, an operator-configured external audit spool. When
  durable persistence regenerates the audit index, Torii mirrors
  `messages.index.json` into that directory and writes a digest-addressed
  `anchors/{index_sha256}.notary.json` preimage plus `latest.notary.json`, each
  binding the exported `index_sha256`, record count, source `store_dir`, and
  embedded audit manifest with its own `anchor_sha256`.
- Added `scripts/iso_audit_notary_adapter.py`, an operator-side archival/notary
  adapter for the exported preimages. It verifies canonical nonzero anchor and
  embedded audit-index self-digests, the top-level `index_sha256`, and
  digest-addressed anchor filename, duplicate-free audit records, local
  `messages.index.json` equality, and record-count consistency before posting
  to HTTPS endpoints, requires non-empty anchors to expose
  `store_dir/messages` record sources by default, and verifies each indexed
  persisted record body against its `record_sha256`, row metadata, and monotonic
  current status history before network delivery. Anchor `anchor_sha256`,
  audit-index `index_sha256`, audit-index `record_sha256` and payload-hash
  fields, plus persisted record metadata payload hashes, must be canonical
  nonzero SHA-256 values before network delivery, while anchor `store_dir`
  values reject whitespace, leading dashes, leading-dash path segments,
  backslashes, semicolon path parameters, empty path segments, and dot/parent
  path segments; local
  HTTP is rejected unless explicitly
  enabled for tests, endpoint URLs must not contain credentials, params, query
  strings, fragments, surrounding or embedded whitespace, or control
  characters, and empty/zero/leading-zero/malformed/default ports plus non-canonical hosts are
  rejected along with reserved placeholder hosts, checked-in template hosts
  under `operator-canary.bank`, invalid DNS labels, percent-escaped hosts, numeric-host
  spoofing, traversal, encoded-separator, encoded-semicolon, encoded URL
  delimiters, encoded-percent, percent-encoded
  control/space bytes, malformed percent escapes, backslash, and embedded
  semicolon path smuggling, duplicate publication endpoints are rejected before
  network delivery without echoing the endpoint URL, remote redirects are not
  followed and are archived as failed receipts, bearer-token files must be
  regular non-symlink inputs
  capped at 8 KiB before decoding to exact UTF-8 with no surrounding
  whitespace, embedded whitespace, or unsafe control characters, including
  Unicode format controls, with token-file read/decode/size failures reported
  by input label instead of runtime path, and
  the export directory plus export inputs (`latest.notary.json`, the
  digest-addressed anchor peer, `messages.index.json`, and
  clean `store_dir/messages` record sources) must be non-symlink regular
  directories/files. The `--export-dir` and `--bearer-token-file` CLI paths
  reject raw control characters, whitespace, leading-dash segments,
  backslashes, semicolon parameters, secret-looking key/value material, empty
  segments, and dot/parent traversal before argparse `Path` normalization,
  embedded anchor `store_dir` paths reject the same secret-looking key/value
  material before record-source verification,
  and `--endpoint` rejects missing, empty, flag-looking, or leading-dash URL
  values before argparse parsing.
  Malformed `--timeout-secs` and `--response-limit-bytes` CLI values fail before
  argparse can echo raw operator input; parsed `--timeout-secs` values must be
  positive and finite, and `--response-limit-bytes` must be a positive integer
  no larger than 4 MiB.
  Anchor/index JSON input is capped at 64 MiB, persisted record-source JSON
  is capped at 1 MiB, and diagnostic `--allow-missing-record-sources` is
  rejected unless at least one validated anchor actually lacks its local record
  sources before publication, with non-dry-run coverage pinning that rejection
  before endpoint delivery or receipt output. Unused insecure-endpoint
  diagnostic overrides are likewise rejected before publication or receipt
  output. The adapter writes each bounded receipt without
  persisting bearer-token material, rejecting secret-looking or
  control-bearing successful remote response bodies before receipt persistence,
  rejecting boolean or string status aliases before coercion, normalizing
  non-standard, malformed, or oversized remote HTTP statuses into
  transport-failed receipts with `status_code=null` and a label-only error, and
  redacting failed remote
  response previews or transport errors before persistence. Transport error strings are capped at
  4096 printable ASCII characters and redacted when oversized, non-ASCII,
  secret/control-bearing, local-path-shaped, or unstringifiable. Plain transport open exceptions/failures,
  normal/HTTP-error response close failures, normal/HTTP-error response-body
  read exceptions/failures, and malformed non-byte remote response bodies are
  converted into bounded failed receipts with stable messages. Rejected
  endpoint URL validation errors, duplicate endpoint errors, and oversized
  response errors report the structural failure by field label without echoing
  raw URL strings that may contain query secrets or private topology.
  Explicit receipt output-directory ancestors are checked without creating
  directories before audit export loading, while receipt output directories and
  receipt leaves are preflighted before publication, reject control characters,
  whitespace, leading-dash segments,
  backslashes, semicolon parameters, empty segments, dot/parent traversal,
  symlinked existing ancestors, and hard-linked, symlink, or non-regular
  targets, reject receipt directories that reuse or symlink back to the audit
  export root or overlap the live `latest.notary.json`, `anchors/`, or
  `messages.index.json` source material, bearer-token file path, or a
  directory containing the bearer-token file, reject bearer-token file paths
  that overlap the audit export root before token loading, and receipts are written via
  exclusive same-directory
  owner-private temporary files with bounded digest-derived names that are
  descriptor-rechecked, fsynced, and atomically replaced where the platform
  supports it.
- Hardened durable ISO bridge reload so missing, malformed, or mismatched
  persisted-record digests fail closed and do not rebuild message status or
  replay indexes.
- Added richer JSON status fields to existing responses and exposed
  `/v1/iso20022/messages/{msg_id}` as an alias for message records.
- Added `/v1/iso20022/messages/{msg_id}/pacs002` to emit a current `pacs.002`
  status report XML from the same status record.
- Added `/v1/iso20022/colr012` to record `colr.012` collateral substitution
  confirmations with durable obligation, original/substitute collateral,
  effective-date, substitution-type, haircut, and reason-code context. The
  retired `colr.007` parser/route is not part of the first-release runtime
  surface; `colr.012` runtime fixtures remain parser coverage, but the first-release default
  profile catalog and production XSD manifest do not advertise collateral
  lifecycle versions until redistributable schemas are checked in.
- Hardened live securities profile admission so `sese.023`/`sese.025` reference
  fields fail closed when the loaded reference snapshots do not contain the
  settlement instrument ISIN/CUSIP, an active place-of-settlement MIC, or mapped
  delivering/receiving party BICs.
- Added securities ledger crosswalk snapshots for CSD venues, CSD settlement
  accounts, and securities cash legs. Live `securities-csd` `sese.023`
  admission now requires a mapped instrument asset, CSD ledger domain,
  delivering and receiving settlement accounts, and cash-leg asset definition
  before durable lifecycle recording.
- Added a checked-in `sese.024` securities status-advice XML fixture and Torii
  regressions covering known-original pending updates, unknown originals,
  wrong-family originals, and conflicting settlement references.
- Added checked-in `pacs.004` and `camt.056` XML fixtures and Torii lifecycle
  regressions proving payment returns reject only settled known originals,
  unsettled returns are ignored, and cancellation requests put known originals
  on hold without fabricating missing originals.
- Added a checked-in `pacs.002` XML fixture and Torii lifecycle regression
  proving an accepted status report settles a known original payment. Additional
  adversarial coverage pins `GrpHdr/MsgId` as the durable status-report id so
  `TxInfAndSts/StsId` cannot shadow lifecycle or audit identity.
- Added full Standards Editor XSD fixtures for `pacs.002.001.10`,
  `pacs.004.001.09`, `pacs.004.001.10`, `camt.056.001.08`, and
  `camt.056.001.09` to the offline MDR-derived schema set. The live-profile
  fixture matrix now admits BAH status, return, and cancellation reports,
  including profile-advertised `pacs.004.001.09` and `camt.056.001.09`
  variants, under the configured version/business-service controls for the rails
  that allow those exact versions.
- Added `fixtures/iso20022/xsd/fixture_manifest.json` plus
  `scripts/iso_xsd_fixture_verify.py`, an offline manifest preflight that binds
  checked-in XSDs to checked-in XML fixtures, verifies schema target namespaces
  and unambiguous `Document` payload roots with exactly one top-level
  `Document` element whose type is exactly the local `Document` type, one
  referenced `Document` complex type, one direct `Document` sequence, and one
  direct payload element with exact `name`/`type` attributes, no `ref`
  indirection, a local unprefixed type, and exactly one matching local payload
  complex type containing exactly one direct `xs:sequence`, rejects XSD
  composition (`xs:import`, `xs:include`, `xs:redefine`, `xs:override`) and
  foreign-namespace direct children under the schema, `Document`, and payload
  structures, and requires schema roots to declare exactly
  `elementFormDefault` and `targetNamespace` without external schema-location
  hints or other root attributes,
  verifies XML fixture namespaces and payload
  roots, requires fixture `Document` and immediate payload roots to be
  attribute-free, rejects DTD/entity declarations before parsing schemas or XML fixtures,
  parses and hashes each manifest/schema/fixture input from the same checked
  byte buffer, caps manifest JSON and profile catalog source at 4 MiB and
  schema/fixture XML inputs at 8 MiB before parsing, drains `xmllint`
  stdout/stderr through a 64 KiB cap and bounds validator runtime with positive
  finite `--xmllint-timeout-secs` capped at 300 seconds during optional schema validation, and
  accepts only empty successful output or the normal `<fixture> validates`
  success line so warning-bearing successful validator output fails closed,
  enforces canonical lowercase ISO message definition ids and path
  containment for schema/fixture entries, rejects manifest schema paths,
  fixture paths, and fixture schema references longer than 2048 characters or
  with non-ASCII characters, URI/drive prefixes, malformed percent escapes,
  percent-encoded control/space, dot/separator, semicolon, URL delimiter, or
  percent bytes, backslashes, embedded whitespace, leading-dash path segments,
  semicolon path parameters, empty segments, dot segments, or forbidden parent
  segments, rejects copied XML fixtures with duplicate fixture
  `message_def_id` or SHA-256 values, optionally validates schema-backed XML
  fixtures against their checked-in XSDs with `xmllint --nonet`, optionally
  parses the embedded default rail profile catalog and records which concrete
  advertised message versions are schema-backed, and the strict
  `--require-profile-schema-backed-versions` gate uses that default catalog when
  no `--profile-catalog` override is supplied, emits versioned digest-bound summaries,
  requires manifest `version` to be the exact integer `1` rather than a JSON
  boolean, recursively rejects secret-looking profile-catalog strings before
  rail, signature-policy, reference-dataset, address-mode, or version diagnostics
  can echo catalog-provided values, requires profile-catalog enum and list values
  such as rails, embedded signature policies, reference datasets,
  structured-address modes, and business services to be printable ASCII, applies
  runtime-equivalent ASCII-case duplicate detection to business-service lists,
  applies the same profile-catalog scanner and overlong-value caps to
  identifier-style strings such as profile ids and business-service entries, rejects
  secret-looking or non-ASCII schema and fixture `payload_root`
  values before namespace/root mismatch diagnostics can echo manifest-provided
  payload names, and rejects secret-looking or non-ASCII checked-in XSD
  `targetNamespace` attributes before schema namespace mismatch diagnostics can
  echo schema-provided attribute values, with the same label-only treatment for
  XSD/fixture payload identifiers, XML fixture namespace/name identifiers, and
  schema-root attribute names, caps those XSD/XML schema and fixture identifiers
  before schema/root mismatch diagnostics can print overlong ASCII spellings,
  scans XML fixture contents before optional
  `xmllint` validation, and redacts secret-looking, control-bearing, or
  non-ASCII validator output before composing XSD preflight diagnostics,
  records manifest, schema, fixture, profile source-file, and embedded catalog
  JSON SHA-256 provenance, requires exactly one active Rust
  `DEFAULT_PROFILES_JSON` raw-string declaration and ignores spoofed matches in
  comments or unrelated strings, requires each checked-in XSD to carry canonical
  repository, commit, source path, SPDX license, and source SHA-256 provenance
  that matches the checked-in bytes, caps source repository URLs and source
  provenance paths at 2048 characters, requires lowercase canonical GitHub
  owner/repository coordinates with owner names limited to lowercase
  alphanumerics and non-edge hyphens, requires repository names to start and
  end with a lowercase alphanumeric character, rejects all-zero Git commit and
  SHA-256 provenance placeholders, rejects placeholder repository
  owners or names such as `example`, `dummy`, `fake`, `sample`, or `template`, rejects source
  provenance paths with non-ASCII characters, embedded whitespace, leading-dash
  path segments, semicolon path parameters, or identifier-style secret-looking material, and
  rejects omitted `source` separately from explicit null source objects in both
  direct preflight and archived readiness replay,
  requires the `blocked_schema_sources` and `pending_schema_sources` review
  lists to be explicitly recorded even when empty, requires blocked-source and
  pending-source records to use unique `message_def_id` values, requires
  blocked records to carry audited restricted GitHub source provenance, and
  requires pending records to carry official ISO catalogue/archive coordinates
  plus the direct `/message/<id>/download` XSD URL from `www.iso20022.org`.
  Each record must match a current
  missing-schema fixture gap or, with a profile catalog, a current
  profile-version gap. The verifier rejects XML fixtures that claim a reviewed
  missing-schema gap for a message definition whose schema is already checked
  in,
  makes final production-readiness replay recompute profile-version
  `schema_backed` booleans from the schema-backed XML fixture
  message-definition IDs in the same digest-bound summary, and now requires
  reviewed missing-fixture/schema-only arrays to preserve fixture/schema order
  and profile missing-version arrays plus nested profile-catalog
  version/skipped-family arrays to preserve canonical profile/message/direction
  version order. XSD
  summary version 3 also carries a recomputed
  `missing_profile_schema_message_ids` aggregate so readiness can reject forged
  unique-message gap counts, reviewed-gap classifications, or non-canonical
  unique-message ordering, plus direct
  `unreviewed_profile_schema_message_id_count` and
  `unreviewed_profile_schema_message_ids` fields for the raw-derived unique
  message definitions that still have no reviewed gap evidence. Final
  readiness also emits a non-overridable
  `xsd.unreviewed_profile_schema_message_ids` blocker for unique
  profile-advertised message definitions that have no checked-in schema and no
  reviewed missing-schema, schema-only, blocked-source, or pending-source
  evidence, deriving that blocker from raw profile-version gaps and reviewed
  evidence rather than trusting the summary aggregate's reviewed flags. It
  verifies the direct unreviewed-profile count/list in each XSD summary and
  exposes the same raw-derived unique list in each public `xsd_summaries[]`
  rollup,
  rejects XSDs that contain
  known restricted Standards Editor redistribution terms even when those terms
  are line-wrapped, tab-separated, or zero-width obfuscated in the license
  header, rejects duplicate, malformed, or
  unknown-key profile catalog profile/message/direction/version entries, and
  allows only the exact message-family alias or concrete message definition
  ids in catalog `versions` lists so mistyped aliases cannot bypass
  schema-backed checks, rejects control-bearing manifest/profile-catalog strings
  before summary emission, and validates optional runtime catalog fields when
  present rather than accepting explicit `null`: runtime-required rails, embedded-signature policies, and
  structured-address modes; optional trust/revocation pins; required reference
  datasets; booleans; unsigned `u64`-bounded supplementary-data caps;
  business-service requirements;
  and amount minor-unit rows, including the same `4`-unit upper bound enforced
  by runtime profile loading. Trust-pin role fields must use the current
  `signature_public_key_sha256_pins` and `x509_trust_anchor_sha256_pins`
  names; stale alias fields are rejected as unknown keys. Public-key,
  trusted-certificate, and revoked-certificate pins cannot overlap in runtime
  loading, profile-catalog preflight, trust-bundle summaries, or operator
  evidence. Embedded catalog and offline
  preflight CRL/OCSP material must be bounded to eight canonical base64 entries
  with CRL-like or successful Basic OCSP response DER shape, Torii runtime
  override CRL/OCSP material must stay within the same count cap and parse as
  DER CRLs or OCSP responses before live admission, revocation flags must carry
  corresponding material, trust-bundle verifier summaries emit raw bundles in
  canonical `profile_id`/path/digest order and raw trust/revocation/CRL/OCSP
  DER material plus profile-override DER base64 in SHA-256/byte-length order,
  with profile-override SHA-256 pin and certificate-policy OID lists sorted
  canonically, and
  `require-verified` catalog profiles must carry at least one public-key or
  X.509 trust pin. It also makes missing-XSD fixture coverage explicit.
  All checked-in XSDs now have standalone XML fixtures, pass
  `--validate-xml-schema`, and the first-release default profile catalog
  advertises only schema-backed concrete versions. The checked-in
  manifest/catalog pair passes the strict schema-backed release gates with `7`
  schemas, `7` schema-backed XML fixtures, and `31` schema-backed
  profile-advertised concrete versions. Runtime parser fixtures for broader
  securities and collateral lifecycle families stay outside the production XSD
  manifest and default catalog until redistributable official schemas are
  checked in. Restricted public candidates such as `pacs.002.001.12`,
  `pacs.008.001.10`, and `pacs.009.001.10` are not imported and are not
  advertised by default profiles. Operator evidence and final readiness trust
  coverage now use the same first-release schema-backed rail-family map, so
  `sese.023`, `sese.024`, `sese.025`, and `colr.012` receipts remain
  runtime/custom-profile material and do not satisfy default `generic-iso20022`
  or `securities-csd` production trust coverage until official schema-backed
  profiles are added. The verifier/readiness code still supports
  reviewed blocked-source evidence for synthetic or future gaps and pins those
  first-release blocked message definitions to exact audited source provenance
  and marker lists. It also supports reviewed official ISO pending-source
  evidence for `colr.012.001.05`, `sese.023.001.09`,
  `sese.023.001.11`, `sese.024.001.09`, `sese.024.001.10`,
  `sese.025.001.08`, `sese.025.001.10`, and `sese.025.001.11` when those IDs
  are explicitly present as current reviewed gaps. Direct verifier and
  readiness replay pin those pending message definitions to their exact
  recorded ISO catalogue URLs, direct download URLs, download type, message
  names, and submitting organisations. They also reject reused pending direct download
  URLs, including cross-summary reuse, reject overlong or percent-escaped
  official ISO catalogue/download coordinates, and require archive catalogue
  URLs to use canonical raw `page=<nonzero decimal>` queries. Each pending
  source `message_name` must be unique and use canonical ISO-style CamelCase
  plus a `VNN` suffix matching the `message_def_id` version segment, and each pending source
  `submitting_organisation` must be a canonical comma-space-separated
  organisation label without URL/contact delimiters, semicolon path parameters,
  placeholder names, or slash/path smuggling.
- Updated OpenAPI and MCP submission surfaces to expose profile selection.
- Added `scripts/iso_rail_gateway_adapter.py`, an operator-side file-drop
  adapter for live rail gateway ingress. Each inbound `*.xml` must have a
  sibling `*.xml.json` sidecar that pins `message_type`, `profile`, and
  `payload_sha256`; the adapter verifies those values before posting to the
  matching Torii ISO endpoint, rejects plaintext HTTP unless explicitly enabled
  for local tests, rejects Torii base URLs with credentials, params, query
	  strings, fragments, surrounding or embedded whitespace, or control
	  characters, overlong URLs or DNS hosts, localhost/local-private IP literals,
	  known local/private rebinding hostnames, or IPv6 transition addresses embedding
	  non-global IPv4 addresses, reserved placeholder hosts such as `.example`,
	  `example.com`, `example.net`, `example.org`, or `example.invalid`, and
	  checked-in template hosts under `operator-canary.bank`,
	  empty/zero/leading-zero/malformed/default ports,
  non-canonical hosts, invalid host labels
  or numeric-host/legacy-IPv4 spoofing, percent-encoded control/space bytes, malformed
  percent escapes, and smuggled URL paths including encoded semicolon parameters,
  encoded URL delimiters, and repeated separators, keeps
  explicit `--message` paths inside the declared inbox, requires an explicit
  profile by default, rejects duplicate payload digests or duplicate
  `rail_message_id` values within one gateway run before network delivery,
  accepts only the Torii ISO message families in the adapter endpoint map
  (`pacs.008`, `pacs.009`, `pacs.002`, `pacs.004`, `camt.056`, `sese.023`,
  `sese.024`, `sese.025`, `colr.007`, and `colr.012`), rechecks that fixed
  endpoint map during Torii URL construction so internal callers that bypass
  sidecar validation fail with a label-only unsupported-message diagnostic,
  rejects sidecar `profile` and `rail_message_id` values
  that are explicitly `null` or carry surrounding whitespace, embedded
  whitespace, or control characters, rejects non-canonical sidecar profile IDs,
  rejects sidecar `rail_message_id` values that are longer than 128 characters
  or are not canonical ASCII rail-message identifiers, rejects secret-looking
  identifier-style profile or rail-message-id markers before receipt emission
  or network delivery, rejects secret-looking `message_type` markers and
  malformed secret-looking `payload_sha256` values plus all-zero payload digest
  placeholders before unsupported-type handling, and keeps payload digest
  mismatch diagnostics label-only instead of echoing compared hashes or local
  source XML paths, reports missing required source XML/sidecar files without
  echoing local paths, reports missing notary anchor/audit-index/audit-record
  source files without echoing local paths, keeps missing latest-anchor
  digest-peer diagnostics free of derived local peer paths, keeps notary anchor
  and digest-addressed peer symlink diagnostics free of embedded source paths,
  keeps exported audit-index mismatch diagnostics free of exported index paths
  in both receipt verification and audit-notary preflight, keeps live rail
  gateway sidecar JSON/XML read-limit/payload-digest mismatch diagnostics free
  of operator inbox paths before network delivery, keeps malformed live notary
  anchor JSON, exported-index JSON, store-directory, and persisted record-source
  diagnostics free of operator export/store paths before network delivery,
  reports audit-notary `--export-dir` discovery and empty `--all` anchor
  discovery failures with role labels instead of local export paths, reports
  audit-notary latest-anchor digest-peer missing/mismatch failures with the
  anchor source role instead of derived local peer paths, reports
  audit-notary receipt-output directory and preflighted receipt-file target
  failures with role labels instead of local output paths,
  reports malformed source sidecar JSON and source XML read-limit failures with
  receipt-relative labels instead of local source paths, reports rail gateway
  `--inbox-dir` discovery failures with the `inbox_dir` role label instead of
  local operator inbox paths, reports rail gateway receipt-output directory and
  preflighted receipt-file target failures with role labels instead of local
  output paths, wraps ISO `Path.resolve()` failures during XSD manifest/schema/
  fixture containment, trust/evidence/readiness summary input deduplication,
  canary output/artifact/config/verify receipt corridors, rail sidecar peer,
  duplicate receipt, message/receipt-directory overlap, and notary anchor/source
  overlap checks with role labels instead of local paths,
  omits hostile pending-source-probe `Content-Type` string metadata when header
  normalization fails instead of failing otherwise reachable official-XSD probes,
  rejects hostile archived pending-probe `content_type` and `error_kind` text
  normalization failures in final readiness with label-only diagnostics,
  coerces accepted pending-probe CLI selectors, live rail/notary adapter inputs,
  receipt-verification, canary, trust-bundle, XSD-fixture, operator-evidence,
  and final-readiness text fields and list entries to plain strings before
  receipt-kind, compact stage-name, preview, context, digest/OID, sidecar,
  endpoint, and secret-material replay checks so hostile Python `str`
  subclasses cannot leak exception text or remain in summary outputs,
  and recursive JSON object-key scans reject non-string keys and normalize
  hostile `str` subclass keys before secret/control-field checks so object-key
  payloads cannot leak exception text or remain in summaries, while unknown-key
  validators reject non-plain dict subclasses, non-string keys, and hostile
  `str` subclass keys before field-set comparison, with receipt/notary exact-key
  checks reusing the normalized key sets for missing-key checks, and forbidden
  receipt-metadata
  replay iterating normalized receipt-entry keys instead of direct dict-set
  intersections before rail/notary compatibility diagnostics or blockers are
  emitted; recursive surrogate and secret-material scans reject non-plain JSON
  list/dict subclasses before container method calls and normalize hostile
  `str` subclasses before surrogate scans; shared object/array and list-valued
  field helpers require exact plain JSON containers before semantic validation,
  and direct loaded-object checks for rail sidecars plus notary/receipt
  persisted records, audit indexes, anchors, source sidecars, and top-level
  receipt JSON reject non-plain object subclasses, while notary/receipt
  status-derivation helpers require exact plain `change_reason_codes` lists
  before classifying pending records as accepted-with-change, and
  trust-bundle public summaries, operator-evidence public canary summaries, and
  final-readiness public summary rendering copy only exact plain JSON containers
  before dropping private fields or scrubbing XSD strict flags, pending-probe
  response metadata, receipt summaries, receipt lists, receipt entries,
  unsupported response metadata, insecure endpoints, legacy message types, or
  default-profile metadata, and redact non-finite public numeric values before
  JSON rendering, while rail-gateway and audit-notary HTTP status predicates
  reject Python boolean values before receipt metadata is digested,
  rail/notary response-body bounding accepts only exact built-in `bytes`,
  `bytearray`, or `memoryview` containers before slicing or length checks,
  pending XSD probe body handling and bounded canary, receipt-verifier, and
  xmllint pipe readers apply the same exact bytes-like container rule,
  repeatable direct selector inputs for pending message IDs, notary endpoints,
  trust bundles, receipt selectors, evidence summaries, and readiness summaries
  require exact `list` or `tuple` containers before length checks or iteration,
  compact evidence/readiness role collectors and XSD material-path collectors
  also require exact plain nested summary objects before `.get()` or indexing
  can run,
  direct scalar and repeatable path arguments accept only sanitized strings or
  exact concrete stdlib `pathlib` path instances before filesystem loading,
  rejecting path subclasses before `__fspath__` or `__str__` can run,
  the rail gateway direct `message` selector rejects hostile path-like objects
  and list subclasses before inbox discovery,
  operator-evidence canary command arrays normalize child command entries to
  plain strings before flag, path, URL, and redaction scans,
  all ISO operator/probe/verifier direct `main(argv=...)` calls require exact
  plain argument lists and copy hostile string subclasses to plain strings
  before raw CLI preflights or `argparse`, including the `argv=None` path where
  ambient `sys.argv` containers are rejected before slicing and parser
  construction uses explicit program names,
  direct `run(args)` calls require exact `argparse.Namespace` values before
  caller-provided objects can service `getattr` or `setattr`,
  CLI-facing and JSON-summary numeric scalar helpers require exact built-in
  `int`/`float` values or sanitized numeric strings before conversion,
  comparison, freshness-budget, timeout, byte-limit, count, day, version, or
  status-code checks, so hostile numeric subclasses cannot run conversion or
  comparison hooks during direct API or replay helper use,
  and the remaining direct file-read limits, bounded child-command output
  limits, child return-code validators, verified-count summaries, freshness
  projections, and public response-metadata classifiers follow the same exact
  built-in integer boundary,
  operator-evidence and production-readiness direct text validators copy
  hostile `str` subclasses to plain strings before rail-message-id, CLI
  context/profile, artifact path, timestamp, XSD source/fixture path,
  reviewed-gap, pending-source URL, pending-probe text, and blocked-source
  restriction-marker checks,
  trust-bundle source timestamp parsing rejects non-string `source.retrieved_at`
  values and normalizes hostile `str` subclasses before canonical timestamp and
  freshness checks,
  reports top-level receipt file read, malformed JSON/UTF-8, object-shape,
  version, receipt-kind, symlink-ancestor, size-limit, and `--receipt-dir`
  discovery failures with indexed receipt labels instead of local operator
  receipt paths, reports direct receipt status, timestamp, endpoint
  policy/digest, response metadata, and rail source replay failures with the
  same indexed receipt labels,
  rejects
  unknown sidecar fields, rejects secret-looking material in known sidecar fields before
  unsupported-value diagnostics can echo message types, profiles, payload
  digests, or rail-message IDs, bounds sidecar JSON before parsing,
  rejects unsupported rail message types, including retired `colr.007`
  collateral drops, with no local override path,
  rejects unused `--allow-insecure-http` and `--allow-default-profile` flags
  unless the validated Torii URL or sidecars actually require the corresponding
  local diagnostic policy, with non-dry-run
  coverage pinning those rejections before submit or receipt output,
  requires operator private-key files to be regular non-symlink inputs capped
  at 8 KiB before exact ASCII decoding with no surrounding or embedded
  whitespace, binds each fresh operator signature to the configured NetworkId
  and exact method/path/sorted query/body, rejects bearer and precomputed auth
  shapes, and reports key-file read/decode/size failures by input label instead
  of runtime path, rejects raw `--inbox-dir`, explicit `--message`, and
  `--operator-private-key-file` CLI path smuggling before argparse `Path`
  normalization, rejects secret-looking key/value material in local paths before
  receipt output, rejects missing, empty, flag-looking, or leading-dash
  `--torii-base-url` values before argparse parsing, rejects malformed numeric CLI values before
  argparse can echo raw operator input, requires positive finite
  `--timeout-secs`, requires positive integer `--max-payload-bytes`, and caps
  `--response-limit-bytes` at 4 MiB,
  does not follow remote redirects, and writes bounded local receipts for
  successful and failed submissions
  without persisting private-key material, rejecting secret-looking or control-bearing
  successful remote response bodies before receipt persistence, rejecting
  boolean or string status aliases before coercion, normalizing
  non-standard, malformed, or oversized remote HTTP statuses into transport-failed receipts
  with `status_code=null` and a label-only error, and redacting failed remote response previews or
  transport errors before persistence. Transport error strings are capped at
  4096 printable ASCII characters and redacted when oversized, non-ASCII,
  secret/control-bearing, or unstringifiable. Plain transport open exceptions/failures,
  normal/HTTP-error response close failures, normal/HTTP-error response-body
  read exceptions/failures, and malformed non-byte remote response bodies are
  converted into bounded failed receipts with stable messages.
  Duplicate gateway payload and rail-message-id diagnostics report only field
  indexes, not the repeated digest or identifier value. Rejected Torii URL
  validation errors report the structural failure by field label without
  echoing raw URL strings that may contain query secrets. XML payload and sidecar inputs must be
  real files in the drop area and are read through bounded file caps:
  symlinked XML payloads or sidecar JSON files are rejected before network
  delivery. Explicit `--message` paths and discovered XML leaves reject
  whitespace, leading dashes, leading-dash path segments, backslashes,
  semicolon path parameters, empty path segments, and dot/parent path segments
  before sidecar or payload reads. Receipt output
  directories and receipt leaves are preflighted before
  Torii submission, with explicit receipt output-directory ancestors checked
  without creating directories before inbox loading. They reject control
  characters, whitespace, leading-dash segments, backslashes, semicolon
  parameters, empty segments, dot/parent
  traversal, symlinked existing ancestors, and hard-linked, symlink, or
  non-regular targets, reject receipt directories that reuse or symlink back
  to the rail inbox root or overlap explicit message XML/sidecar source
  material, operator private-key file path, or a directory containing the key
  file, reject operator private-key paths that overlap the rail inbox root
  before key loading, and are written via exclusive same-directory
  owner-private temporary files with bounded digest-derived names that are
  descriptor-rechecked, fsynced, and atomically replaced where available. The
  inbox directory and both
  discovered and explicit `--message` XML leaves preserve symlink boundaries so
  symlinked gateway inputs fail before network delivery.
- Added `scripts/iso_operator_receipt_verify.py`, a read-only canary verifier
  for rail/notary adapter receipts. It recomputes receipt digests, rejects
  all-zero receipt self-digest placeholders, requires successful 2xx receipts by
  default, rejects plaintext HTTP evidence unless explicitly enabled for local
  tests, rejects unused `--allow-failed`,
  `--allow-insecure-http`, and
  `--allow-default-profile` flags unless verified receipts actually carry failed
  status, an HTTP/local endpoint, or a missing rail profile,
  records version-2 compact `endpoint_requires_insecure_http` evidence per
  receipt so archived replay can bind insecure-HTTP policy without persisting raw
  endpoint URLs and rejects summaries that hide that endpoint evidence behind
  `allow_insecure_http=false`,
  rejects receipt endpoint URLs with
  credentials, params, fragments, malformed hosts, surrounding
  or embedded whitespace, control characters, empty/zero/leading-zero/malformed/default ports, or
  non-canonical host spelling, localhost/local-private IP literals, known
  local/private rebinding hostnames, IPv6 transition addresses embedding
  non-global IPv4 addresses, reserved placeholder hosts such as `.example`,
  `example.com`, `example.net`, `example.org`, or `example.invalid`, and
  checked-in template hosts under `operator-canary.bank`, invalid host labels,
  percent-escaped hosts, numeric-host/legacy-IPv4 spoofing, plus
  path traversal, encoded path separators, repeated path separators,
  encoded-semicolon parameters, encoded URL delimiters, encoded-percent path
  segments, or percent-encoded control/space bytes. Notary receipt queries and
  default-profile rail receipt queries are forbidden; an explicit-profile rail
  receipt must carry exactly one canonical `profile=<profile-id>` query matching
  its recorded profile, so duplicate, unknown, reordered, encoded, omitted, or
  substituted query values fail replay,
  detects leaked authorization/token material plus secret-looking allowed
  receipt string values, including malformed `receipt_kind`, before version or
  kind dispatch and without echoing those values, reports rejected endpoint
  URL structure and duplicate receipt digest failures without echoing raw URL
  strings or receipt paths that may contain query/path secrets, rechecks the
  supported receipt-kind boundary during endpoint reconstruction with a
  label-only unsupported-kind diagnostic if internal callers bypass receipt-kind
  validation, gives evidence-gate receipt metadata comparison the same
  label-only unsupported-kind fallback before direct-archive/canary metadata
  binding, and makes final readiness archive/canary metadata replay emit a
  structured metadata blocker instead of comparing only generic receipt fields
  for unsupported internal receipt kinds, closes the raw
	  receipt schemas for each receipt kind plus notary
	  anchor/audit-index source schemas, including an explicit `records[]` array
	  and duplicate-free nested audit records, binds
  audit record filenames to `sha256(message_id).json`, binds each indexed
  `record_sha256` to the persisted `store_dir/messages` body when source files
  are required or locally available, rejects row/source metadata drift and
  persisted-state-derived `pacs002_code` or status-history timestamp drift,
  binds recorded endpoint digests to the recorded endpoint URLs, requires
  timezone-aware adapter timestamps that do not require trimming, enforces
  `ok`/`status_code` consistency, requires HTTP response body digests for HTTP
  responses, requires `response_body_sha256=null` for `status_code=null`
  transport failures, rejects all-zero response-body, notary anchor/index, rail
  payload, audit-index record, and persisted payload-hash placeholders, keeps
  receipt, notary, and audit self-digest mismatch diagnostics label-only, requires
  failed-receipt error strings while rejecting secret/control/local-path-shaped
  error material, validates bounded response metadata, can
  cross-check referenced XML, rail sidecar, or notary-anchor source files,
  requires rail `xml_path` values to point at `.xml` leaves and rail sidecars
  to match the adapter's `xml_path + .json` convention,
  requires notary `anchor_path` values to keep the `latest.notary.json` or
  digest-addressed `anchors/<index_sha256>.notary.json` shape even when source
  files are not required,
  rejects raw notary `anchor_path` and `store_dir` values, raw rail receipt
  `message_type`, `xml_path`, and `sidecar_path` values that carry whitespace,
  control characters, leading dashes, leading-dash path segments, backslashes,
  semicolon path parameters, empty path segments, or dot/parent path segments,
  requires raw rail receipts and archived rail receipt summaries to record
  nullable `profile`/`rail_message_id` keys,
  plus receipt and source-sidecar rail
  `profile`/`rail_message_id` values when they carry surrounding whitespace or
  embedded whitespace or control characters, rejects source-sidecar explicit
  null optional metadata instead of treating it as omission, rejects non-canonical receipt or
  source-sidecar profile IDs, rejects overlong or non-canonical ASCII
  `rail_message_id` values, rejects archived receipt and source-sidecar
  profile or rail-message-id values that look like secret-bearing identifiers,
  rejects archived receipt `message_type` values that look like secret-bearing
  identifiers before receipt-summary emission, rejects malformed archived rail
  receipt `message_type` family IDs and Unicode digit confusables before
  allowlist checks, rejects archived
  rail receipt `message_type` values outside the same adapter endpoint map
  before receipt-summary emission, caps repeatable notary endpoint inputs at
  64 values before export loading, caps receipt/notary audit record arrays,
  status-history arrays, and change-reason arrays at 8192 items before replay,
  caps receipt JSON at 4 MiB, notary
  anchor/index JSON at 64 MiB, persisted notary record-source JSON at 1 MiB,
  rail source XML at 4 MiB, and source-sidecar JSON at 16 KiB before parsing or
  hashing, replays digest-addressed notary-anchor and
  `messages.index.json` checks while rejecting symlinked or non-regular notary
  anchor/index peers and rail XML/sidecar files, rejects retired `colr.007` rail
  source files as unsupported,
  rejects zero-record notary anchors before publication and during
  source-file/production evidence replay,
  rejects symlinked receipt archive directories before discovery, and rejects
  repeated receipt paths or copied receipts with duplicate `receipt_sha256`
  values before emitting a summary. Direct receipt and receipt-directory CLI
  paths reject secret-looking key/value material before those paths can be
  serialized into a
  digest-bound, versioned verifier summary with per-receipt file paths,
  `receipt_sha256` values, and policy flags.
- Added `scripts/iso_operator_canary.py`, a strict JSON-runbook runner that
  executes the rail file-drop adapter, audit notary adapter, and receipt
  verifier as subprocesses. It caps runbook JSON at 64 KiB before parsing,
  requires explicit provider/environment labels,
  rejects secret-looking identifier-style provider/environment labels before
  plan-only output or executed summaries can preserve them,
  rejects unknown runbook keys, rejects surrounding whitespace and control
  characters in runbook strings, rejects present `null` optional path and
  numeric limit fields instead of silently applying defaults, keeps relative
  paths inside the runbook directory, rejects endpoint URLs with credentials,
  params, query strings, fragments, malformed bracketed hosts, overlong URL
  strings, DNS hosts longer than 253 characters, localhost/local-private IP
  literals, known local/private rebinding hostnames, or legacy IPv4 numeric
  notation, or IPv6 transition addresses embedding non-global IPv4 addresses,
  accepts checked-in `operator-canary.bank` template endpoints only for
  `--plan-only` validation and rejects them before non-plan child execution,
  allows placeholder provider/environment context labels only for
  `--plan-only` validation and rejects them before non-plan child execution,
  rejects non-plan canary config, rail input/message/receipt-dir, notary
  export/receipt-dir, and explicit verifier receipt paths under checked-in
  `fixtures/iso20022/` artifacts before child execution,
  rejects duplicate endpoint lists and duplicate receipt inputs,
  caps notary endpoint, verifier receipt-directory, and verifier receipt string
  lists at 8192 items before entry parsing,
  requires list-valued notary and verify receipt-selector fields to be
  explicitly recorded as arrays under `--require-explicit-policy`, and
  production-policy runbooks must explicitly record rail/notary receipt
  directories that do not overlap the rail inbox or notary audit-export root,
  while the required rail operator-private-key file and any notary bearer-token
  file must stay outside the corresponding stage source root and receipt
  directory before child execution. Rail planning also requires a canonical
  checksummed genesis-derived `network_id`, rejects the retired rail
  `bearer_token_file`, emits exact `--network-id` and
  `--operator-private-key-file` adapter inputs, and redacts both rail key and
  notary token paths in its summary. It verifies generated
  receipts by default, bounds each child stage with positive finite
  `--stage-timeout-secs`, records `timed_out` for killed children, drains child
  stdout/stderr through a bounded preview cap instead of retaining unbounded
  output, marks the canary failed if any executed child stdout/stderr preview is
  truncated or if a successful child writes stderr, rejects secret-looking child
  output before any canary summary is written, and writes a single bounded versioned summary JSON for operator evidence
  archives. Evidence replay also requires executed rail/notary child stdout to
  parse as the live adapter summary shape with zero failures, receipt paths
  under the recorded stage receipt directory, and counts matching submitted
  messages or published anchors/endpoints. Rail stdout must report a single
  submitted message when the command used explicit `--message`; notary stdout
  `endpoint_count` must match the executed command's repeated `--endpoint`
  flags, and `published_anchors` must stay at one unless the command used
  `--all`. Notary receipt summaries must also use `latest.notary.json` without
  `--all` and digest-addressed `anchors/<index>.notary.json` with `--all`.
  Arbitrary printable child logs, dry-run summaries, inflated endpoint counts,
  forged multi-message claims, forged multi-anchor publication claims, or
  swapped latest/all-anchor modes cannot be archived as production canary
  evidence. Compact evidence carries sanitized `stage_command_modes` values
  (`rail_uses_message`, `rail_submitted_message_count`, `notary_uses_all`,
  `notary_endpoint_count`, and `notary_published_anchor_count`) so the
  final production-readiness gate can independently replay rail single-message,
  rail submitted-message-count, notary all-anchor, notary endpoint-count, and
  notary published-anchor-count bindings without storing raw commands or
  endpoint URLs. The
  verify-stage receipt-verifier JSON embedded in canary stdout must also keep
  every receipt path covered by the verify command's `--receipt-dir`/`--receipt`
  selectors, and every explicit `--receipt` selector must appear in the
  captured summary. For executed rail/notary stages, the receipt path set in
  adapter stdout must match the receipt-verifier summary paths for the same
  receipt kind before archive replay can use the canary evidence. Summary
  output paths are preflighted
  without creating missing parents before runbook JSON loading, then checked
  again before subprocess stages. They reject control characters, whitespace, leading-dash
  segments, backslashes, semicolon parameters, empty segments, dot/parent
  traversal, checked-in `fixtures/iso20022/` artifact destinations, symlinked
  existing ancestors, and hard-linked, symlink, or
  non-regular targets. Summary outputs also cannot reuse or hardlink the
  runbook config input, the planned rail operator-private-key file, planned
  notary bearer-token files, explicit rail
  message files, explicit verifier receipt files, or planned stage artifact
  directories before child execution, and are written via exclusive same-directory
  owner-private temporary files with bounded digest-derived names that are
  descriptor-rechecked, fsynced, and atomically replaced where available.
  `--plan-only`
  validates runbooks and prints redacted child commands without contacting Torii
  or notary endpoints.
- The ISO operator scripts reject duplicate JSON object keys, non-standard
  `NaN`/`Infinity` JSON constants, and lone UTF-16 surrogate escapes before
  semantic validation across rail sidecars, notary anchors/indexes/record
  sources, canary runbooks, receipts, trust bundles, XSD manifests/profile
  catalogs, evidence summaries, readiness summaries, receipt-verifier JSON
  embedded in canary stdout, rail/notary adapter summary JSON embedded in canary
  stdout, and direct archive receipt-verifier stdout. XSD
  manifests/profile catalogs, rail sidecars, notary anchors/indexes/record
  sources, direct receipt files, trust bundles, canary runbook,
  operator-evidence summary/stdout, and final readiness input JSON number tokens
  also reject non-canonical numeric spellings, including exponent-normalized
  floats, negative-zero integers/floats, and overflow exponents that would
  parse as non-finite floats, before Python can normalize
  fixture metadata, live adapter metadata, notary material, receipt fields,
  trust material, stage budgets, receipt-verifier summaries, or release summaries. This prevents shadowed keys, non-finite or
  non-canonical numeric values, or invalid Unicode strings from changing the
  release-evidence meaning after digest or policy checks.
  The same helpers now render canonical digest bytes, summaries, receipts, and
  emitted profile JSON with strict JSON serialization (`allow_nan=false`), so
  internal non-finite `NaN`/`Infinity` values fail before any digest-stamped
  evidence file or stdout summary is written.
  Recursive JSON surrogate and secret-material scanners also cap arrays at
  8192 items, JSON objects at 8192 members, and nesting at 128 levels before
  walking entries, so unsupported or unknown JSON shapes cannot force unbounded
  pre-semantic traversal. JSON loaders also translate parser recursion failures
  into the same label-only 128-level nesting diagnostic, so deeply nested input
  cannot echo local paths or attacker-controlled leaf values. Duplicate-key and non-finite
  numeric constant diagnostics now avoid echoing the repeated key name or
  `NaN`/`Infinity` spelling.
  Unknown JSON field names now get label-only unknown-key diagnostics across
  the ISO validators, including ordinary unknown-field typos that previously
  listed field names for operator debugging.
  Recursive trust-bundle, receipt, evidence, and readiness secret-material
  scanners likewise report only label-level forbidden-field failures, and
  receipt value secret checks no longer echo the receipt field label that
  carried the rejected material. The raw CLI, compact path/value, child-output,
  and recursive scanners cover bearer tokens, private keys,
  passwords/passphrases, API/access/session keys, client secrets, cookies, and
  Iroha signatures, including identifier-only and key/value
  whitespace/dot/underscore/hyphen/slash/backslash-separated key labels, and they now scan
  repeated percent-decoded plus separator-collapsed/stripped,
  Unicode-format-or-mark-character-normalized, and Unicode compatibility-normalized forms so encoded, double-encoded,
  zero-width-obfuscated, combining-mark-obfuscated, fullwidth/compatibility-form-obfuscated, path-separator-obfuscated, or repeated-separator secret-looking material is
  rejected in CLI paths, unknown JSON keys, recursive JSON values, compact
  summary paths, and archived or live response previews/errors. Live
  rail/notary successful response bodies fail before receipt write when previews
  contain such separator-obfuscated secret labels or regex-only bearer
  whitespace forms, invalid UTF-8, or non-ASCII text, and archived receipt replay rejects matching
  `response_body_preview` evidence instead of preserving it. Live rail/notary
  failed response preview emission is printable-ASCII only: invalid UTF-8 or
  non-ASCII preview text is redacted while the exact response-body digest
  remains bound to the receipt, and accepted newline/tab-bearing printable
  previews are folded to one line before receipt archival. Archived receipt
  replay rejects multiline or non-ASCII preview/error text. URL transport
  failures now record fixed rail/notary
  receipt error labels instead of upstream OS or library reason strings, and
  archived failed receipt errors must match those fixed labels or the matching
  `HTTP <status>` response label.
  Digest mismatch diagnostics across live rail payload checks, notary and
  receipt self-digests, archived evidence summaries, and final readiness
  summaries now report only the failing field/summary label and do not print
  expected or recomputed SHA-256 values.
  Unknown JSON keys with control characters
  also fail with label-only diagnostics across live adapters, operator
  receipts, trust bundles, XSD manifests/catalogs, and archive rollups, and
  recursive archive/operator JSON string scans, audit-notary persisted
  record-source clean-string replay, and receipt-verifier rail source sidecar
  replay reject unsafe control characters, including Unicode format controls
  such as bidi overrides, before field-specific replay.
  Rail and notary adapters reject successful
  remote response bodies with those markers, unsafe control characters, invalid
  UTF-8, or non-ASCII text before
  writing receipts, reject boolean or string status aliases before coercion,
  normalize non-standard remote HTTP statuses into transport-failed receipts
  with `status_code=null`, redact failed remote
  response previews when upstreams return those markers, unsafe control
  characters, invalid UTF-8, or non-ASCII text, record fixed URL transport
  receipt error labels, and the
  receipt verifier rejects archived successful receipts that carry the
  redacted response marker plus previews/errors that still contain
  secret-looking material, unsafe control characters, multiline preview text,
  or non-ASCII text, while failed receipt errors must match fixed live-adapter
  labels or `HTTP <status>`.
  Byte-like live
  response bodies (`bytes`, `bytearray`, or `memoryview`) are normalized by byte
  length before hashing or previewing, so wide-format `memoryview` responses
  cannot bypass configured response caps; non-byte response bodies still become
  stable transport-failed receipts without echoing the value. The shared HTTPS
  URL path validators also reject secret-looking key/value material in literal,
  percent-encoded, or double-encoded path segments before live rail/notary
  delivery, canary planning, receipt verification, trust/evidence ingestion, or readiness
  rollup, and reject raw URL delimiter characters in path segments with the
  same fail-closed posture used for encoded delimiters. They also require URL
  paths to stay printable ASCII, rejecting raw Unicode path characters and
  percent-encoded non-ASCII bytes before those URLs can be archived or used.
  The local
  path/raw CLI/summary-path/artifact-path validators use a
  narrow identifier-style path scanner for composite names such as
  `token-*-secret` and strong key markers. Those local path validators also
  reject raw URI or drive prefixes, malformed percent escapes, and
  percent-encoded control/space, dot/separator, semicolon, URL delimiter, and
  percent bytes before path expansion, summary emission, archive replay, or
  child command construction. Direct local CLI/output/artifact path strings are
  capped at 4096 characters with label-only diagnostics before secret scanning,
  filesystem expansion, summary emission, child command construction, or archive
  replay.
  Secret-looking field-name markers
  also cover hyphenated `private-key` and underscore-form `x_iroha_signature`
  spellings across ISO validators, and receipt JSON secret-field scans recurse
  through nested objects and arrays before receipt semantics are evaluated.
  Audit-notary anchor publication also rejects secret-looking audit-index
  identifiers and persisted record-source string values before network
  publication can preserve them in operator evidence, and direct receipt
  verification mirrors that rule when replaying archived notary sources.
  Archived receipt source paths, including rail XML/sidecar paths, notary anchor
  paths, and notary store directories, also reject narrow secret-looking
  identifiers before missing-source or mismatch diagnostics can echo them.
  Operator evidence verification and final readiness also block relabelled
  compact notary receipt entries within the same canary or archive receipt
  summary when they reuse `anchor_path`, `anchor_sha256`, `index_path`, or
  `index_sha256`; repeated `store_dir` values remain allowed for legitimate
  multi-anchor publication.
  Notary and receipt replay clean metadata strings from audit indexes,
  persisted records, nullable context/metadata/history fields, and rail sidecars
  are capped at 4096 characters with label-only diagnostics before mismatch,
  source replay, or sidecar validation can retain oversized operator evidence.
  Direct trust-bundle generic strings/OID lists, XSD profile-catalog generic
  strings/lists, canary runbook generic strings/lists, and evidence replay clean
  strings/lists plus production-readiness compact clean strings/lists share the
  same 4096-character label-only cap before trust preflight, XSD profile
  validation, runbook planning, archive validation, or readiness replay can
  preserve oversized metadata; embedded trust/profile DER base64 keeps its
  separate decoded-size guard.
  Direct canary runner, rail-gateway adapter, and audit-notary adapter
  `run(args)` calls also mirror their CLI path-smuggling guards for
  config/summary, inbox/message/receipt/token, and export/receipt/token paths
  before config, inbox, export, or network loading.
  Production-readiness replay also classifies summaries generated from the
  checked-in `fixtures/iso20022/xsd/fixture_manifest.json` corpus as
  `xsd.repository_fixture_manifest` blockers by default, and rejects XSD summary
  input files under checked-in ISO fixture coordinates as
  `xsd.repository_xsd_summary` blockers. Direct XSD `--profile-catalog` inputs
  under checked-in `fixtures/iso20022/` artifacts now fail before manifest
  loading, and archived `profile_catalog.path` values under those artifacts
  replay as `xsd.repository_profile_catalog` blockers. Local
  `--allow-reviewed-xsd-gaps`
  diagnostic runs can only downgrade reviewed missing-schema, schema-only, or
  blocked-source or pending-source gap warnings; repository fixture manifest
  blockers and truly unreviewed profile-catalog-only schema gaps remain
  production blockers, and the latter still makes the override unused. Blocked
  schema-source evidence also rejects candidate
  SHA-256 values that already identify checked-in schemas or fixture XML, and
  final readiness replays those overlaps as dedicated blockers so accepted
  schema or fixture material cannot be relabelled as blocked-source gap
  evidence. Direct XSD summaries now carry `ok: true` only when the verifier used
  all strict schema-backed, fixture-backed, profile-backed, and XML schema
  validation checks against a non-repository manifest with no reviewed or
  pending gaps; checked-in fixture manifests and local reviewed-gap runs record
  `ok: false`. Final readiness recomputes that verdict and emits
  `xsd.summary_not_ok` or `xsd.summary_ok_drift` blockers before accepting an
  XSD summary. Final readiness also rejects compact summaries whose manifest
  digest reuses schema, fixture, blocked-source, profile-catalog source, or
  profile-catalog JSON digests, whose fixture digest reuses a checked-in schema
  digest, whose fixtures repeat a message definition id or claim a
  missing-schema gap for a checked-in schema, or whose profile-catalog
  source/embedded JSON digests reuse schema, fixture, blocked-source, or
  each-other digest roles. Pending official ISO source evidence is
  catalogue/download URL and message-name provenance only and never substitutes
  for checked-in XSD bytes under strict schema-backed checks. The bounded
  `scripts/iso_pending_xsd_source_probe.py` helper records digest-stamped
  reachability summaries for those official pending-source download URLs,
  including a `sample_sha256` over exactly the capped downloaded bytes for
  nonzero samples after slicing bytes-like read outputs to the configured
  bounded window by byte length before digesting or classification even if a
  response over-returns or returns a wide-format `memoryview`, and `null` for
  zero-byte failures, without importing schema bytes. Only 2xx responses
  with positive bounded samples that look like the expected XSD, meaning the
  sample starts with a namespace-bound XML Schema root opening tag whose
  `targetNamespace` equals
  `urn:iso:std:iso:20022:tech:xsd:<message_def_id>` rather than only an XML
  declaration, embedded schema-looking text, or a generic schema root, are
  emitted as `reachable`; redirect-class or other non-2xx XSD-looking samples
  fail closed as `NetworkError` without archiving response samples. Non-XSD
  1xx/2xx/3xx samples are recorded as `unexpected` evidence, while
  malformed/missing status metadata and zero-byte success responses, malformed
  status accessor failures, opener/read runtime/type/value failures, response
  context failures, non-callable context hooks, malformed non-byte read output,
  and stream read failures are normalized to `NetworkError` without archiving
  response samples; response context-exit, close, and close-accessor failures
  are treated as cleanup-only after bounded classification succeeds, and
  HTTP-error response objects are closed best-effort before their bounded error
  row is archived. Remote
  `Content-Type` metadata is omitted before summary emission when
  it is overlong, non-ASCII, control-bearing, whitespace-padded, or
  secret-looking, and HTTP status metadata is recorded only for real integer
  100-599 statuses; final readiness replays the same omission policy and rejects
  forged archived `content_type` values that would not have been emitted by the
  probe helper; failed response header access omits `content_type` without
  archiving accessor exception text, and runtime read failures normalize to
  `NetworkError` without retaining exception text. Network failures are recorded with a stable `NetworkError`
  role instead of raw Python exception class names. It rejects malformed repeatable selectors plus
  non-ASCII, padded, or non-canonical numeric timeout/byte-cap values, such as
  `.5`, `01`, `1e01`, `1.`, `000512`, `+512`, or `512.0`, before network work,
  caps `--timeout-secs` at 300 seconds, and rejects raw secret-looking CLI
  arguments or malformed `--summary-out` path tokens before argparse can echo
  them, so failed public downloads can be archived as explicit operator
  evidence while redistributable packages are still pending.
  A bounded live recheck at `2026-06-28T09:59:15+00:00` with
  `--timeout-secs 3 --max-bytes 512` still timed out across all eight recorded
  official download URLs with `0` downloaded bytes; the summary digest was
  `afe0130f92b797563e12b45879a08e5edce724c69f839515803cd46ebabc7503`.
  Final readiness now accepts those probe summaries through
  `--pending-xsd-probe-summary`, rechecks their digest, freshness, pinned ISO
  metadata, probe counts, bounded sample digest shape, per-row
  `downloaded_bytes <= max_bytes`, the helper's 65,536-byte maximum sample cap,
  the helper's 300-second maximum timeout cap, truncation consistency, and
  failed-probe zero-byte/non-XSD-looking status shape, timeout/network-error
  null `content_type` shape, HTTP-error 4xx/5xx status codes, failed-probe
  `error_kind` role shape including exact `NetworkError` for network failures,
  `unexpected` status shape as a real 1xx/2xx/3xx HTTP response with positive
  sampled bytes and `looks_like_xsd=false`, and `reachable` status shape as a
  real 2xx HTTP response with positive bounded bytes, `looks_like_xsd=true`,
  and the expected schema-root `target_namespace`, rejecting redirect-class or
  wrong-target XSD-looking rows as forged reachability evidence, rejecting
  producer-omitted unsafe `content_type` or `target_namespace` metadata,
  recomputing summary `ok` before accepting claimed success, and
  requires matching probe
  coverage when reviewed
  pending-XSD gaps are allowed.
  If no pending official
  source gaps are recorded, supplied probe summaries become explicit
  unreferenced-evidence blockers; if only some official source gaps remain,
  extra probe rows for no-longer-pending message definitions are blocked the
  same way. It also rejects probe summary paths and summary digests replayed as
  XSD or operator-evidence material, so
  reachability evidence cannot be relabelled as schema-backed or live-evidence
  proof material.
  Operator evidence verification rejects canary summaries whose `config_path`
  still points at checked-in `fixtures/iso20022/operator_canary/` runbook
  templates, and final readiness replays the compact path as an
  `evidence.repository_canary_config` blocker if a forged aggregate summary
  reintroduces it. The canary runner itself also rejects non-plan
  config/stage/explicit verifier receipt paths under `fixtures/iso20022/`,
  while keeping those templates available for `--plan-only` validation.
  Evidence replay mirrors that rule for executed and planned canary child-command
  `--inbox-dir`, `--message`, `--export-dir`, `--receipt-dir`, and `--receipt`
  values so forged archived commands cannot reintroduce repository fixtures.
  Direct receipt verification and its parent evidence gate also reject
  `--receipt` and `--receipt-dir` selectors under checked-in
  `fixtures/iso20022/` artifacts before receipt discovery, child verifier
  launch, file loading, or digest-bound summary construction. Direct
  receipt-verifier `run(args)` calls mirror the CLI path-smuggling preflight for
  those selectors and require policy flags to be real booleans before discovery
  or file loading, including when programmatic callers omit the policy
  attributes entirely.
  Raw evidence verification also rejects `--canary-summary` and
  `--trust-summary` inputs under checked-in `fixtures/iso20022/` artifacts, and
  final readiness blocks forged compact XSD/evidence/canary/trust summary paths
  that point back to those artifacts.
  Operator evidence verification also preserves trust-bundle source paths in
  compact trust profiles and rejects checked-in
  `fixtures/iso20022/trust_bundles/` template paths; final readiness replays
  forged compact paths as `trust.repository_trust_bundle` blockers.
  Rail receipt verification preserves the source XML path as compact
  `source_path` evidence and rejects checked-in `fixtures/iso20022/*.xml`
  fixture paths; evidence and final-readiness replay reject forged compact
  receipt source paths that point back at repository XML fixtures, and the rail
  gateway adapter rejects checked-in ISO XML fixture inputs before network
  delivery or receipt output.
  Notary receipt verification also preserves compact `anchor_path`,
  `store_dir`, and `index_path` evidence, requires the anchor path to remain
  either `latest.notary.json` or `anchors/<index_sha256>.notary.json`, requires
  the index path to stay the `messages.index.json` peer of that anchor export,
  and evidence/readiness replay includes all three values in direct archive
  metadata matching so copied summaries cannot strip or drift the operator
  notary preimage path, source store, or exported audit index while keeping
  matching digests; raw receipts reject notary anchor/store paths under
  checked-in `fixtures/iso20022/` artifacts, and compact replay rejects
  anchor/store/index paths under those artifacts. The audit notary adapter
  rejects checked-in notary anchor/store fixture inputs before network delivery
  or receipt output. Malformed notary source replay diagnostics for anchor JSON,
  exported-index JSON, store directories, symlinked store-directory ancestors,
  and persisted record-source files use receipt-index/source labels rather than
  copying local receipt/archive/store paths into stderr.
  Canary runbooks,
  trust bundles, evidence/readiness summaries, XSD manifests, profile catalogs,
  schema files, XML fixtures, and receipt archive directories must reject
  symlinked existing ancestors plus symlink or non-regular leaves before digest,
  provenance, discovery, or policy checks run; checked file inputs are opened
  through no-follow file descriptors where available so the read uses the same
  regular file that was checked. Direct CLI artifact flags for live rail inbox
  roots, live notary export roots, rail operator-private-key files, notary
  bearer-token files, canary
  configs, trust bundles, XSD manifests/profile catalogs, receipt
  files/directories, canary/trust summaries, and XSD/evidence summaries also reject raw control
  characters, whitespace, leading-dash segments, backslashes, semicolon
  parameters, empty segments, and dot/parent traversal before argparse `Path`
  normalization or file discovery, and the canary, XSD, evidence, and readiness
  summary gates also reject secret-looking key/value or identifier-only material, including
  percent-decoded whitespace-separated key labels, in CLI summary
  input/output paths before those paths can be serialized into digest-bound
  rollups. Production-readiness direct `run(args)` calls now mirror the same
  path-smuggling guard for XSD summaries, evidence summaries, and summary
  outputs before input loading while preserving checked-in fixture summary
  inputs as structured release blockers; direct XSD and trust verifier
  `run(args)` calls do the same for manifest/profile-catalog, bundle,
  profile-output, and summary-output paths before manifest or bundle loading,
  and direct XSD summary outputs cannot reuse or hardlink the manifest or
  profile-catalog input path before loading, or any discovered schema or XML
  fixture path before writing. XSD summary-output existing ancestors and leaves are
  also preflighted without creating missing parents before manifest loading and
  optional `xmllint` subprocess execution. Direct
  trust-bundle summary/profile outputs
  likewise cannot reuse or hardlink bundle input paths, and summary/profile
  output paths cannot alias each other before bundle loading; their existing
  ancestors and leaves are also preflighted without creating missing parents
  before bundle validation. Direct evidence summary outputs also preflight
  symlinked existing ancestors plus symlink, hardlinked, or non-regular leaves
  without creating missing parents before summary loading or launching direct
  receipt-verifier subprocesses. Final readiness summary-output existing
  ancestors and leaves follow the same non-mutating preflight before XSD or
  evidence summary loading.
  Summary/profile outputs and rail/notary receipt output directories
  also reject checked-in `fixtures/iso20022/` artifact destinations during
  run-level preflight and again before creating parents or writing temporary
  output files, so those destinations fail before input loading, child stages,
  schema/trust validation, or network delivery. Live rail/notary adapter runs
  also reject receipt output directories that overlap direct source artifacts:
  rail explicit XML/sidecar inputs, rail operator-private-key files, notary
  bearer-token files, and notary
  `latest.notary.json`, `anchors/`, or `messages.index.json` inputs.
  Explicit rail/notary receipt-directory symlink ancestors are rejected before
  inbox/export source loading without creating missing output directories; the
  mutating directory creation pass remains after source validation and before
  network delivery.
  Direct canary summary-output existing ancestors and leaves are also preflighted
  without creating missing parents before runbook JSON loading, while parsed stage-artifact alias checks still
  run before child execution. Trust/XSD/canary/evidence/readiness summary writers now report output
  parent, leaf, and temporary-file failures with role labels rather than local
  output paths. ISO input readers, input-directory checks, ancestor inspection
  preflights, alias-comparison helpers, and summary/receipt writers also
  sanitize raw OS `strerror` text and hostile `strerror` accessor failures,
  including reader, input-directory, receipt-directory, receipt source-file,
  ancestor, output parent/leaf, and alias `lstat()`/`stat()`/`exists()`/
  `is_symlink()` inspection failures, output parent creation failures,
  rail/notary receipt-directory inspection and creation failures, input
  runtime/type/value handle failures, descriptor-close cleanup
  runtime/type/value failures plus temporary write/fsync/replace
  runtime/type/value failures and cleanup unlink/close runtime/type/value
  failures, before diagnostics, preserving
  ordinary short ASCII errors but collapsing path-like, secret-looking,
  control-bearing, non-ASCII, oversized, or unreadable error text to a stable
  `I/O error` role. JSON and XML parser
  failures across trust, XSD, rail/notary, canary, receipt, evidence, and
  readiness inputs now report category-only diagnostics such as
  `is not valid JSON` or `is not well-formed XML` without appending parser
  location payloads.
  Explicit rail `--message` containment failures, XSD manifest-relative
  containment failures, and canary runbook symlink-escape containment failures
  likewise report only stable role labels instead of resolved operator roots.
  Live rail/notary inbox and export roots also reject checked-in
  `fixtures/iso20022/` artifacts before directory discovery, anchor parsing,
  XML fixture parsing, child execution, or network delivery.
  Canary runbook artifact paths now apply the same narrow
  control-character plus key/value and identifier-style secret-material rejection
  before plan-only summaries or child command arguments are built, while
  rail operator-private-key and notary bearer-token paths remain runtime
  secret-file references and are redacted from planned command output. Canary
  child stdout/stderr previews
  also reject identifier-style secret-looking material and unsafe control
  characters before summary emission.
  Canary runbook path strings and archived child-command local path values must
  also remain printable ASCII and capped by the 4096-character local path limit
  before planning or evidence replay, while production-readiness compact
  summary/config/receipt path strings keep the stricter 2048-character archive
  cap before release archival.
  XSD `xmllint` diagnostics redact local schema/fixture paths, key/value secret
  material, identifier-style secret-looking validator output, unsafe control
  characters, and non-ASCII material before reporting schema-validation
  failures or unexpected successful validator output; accepted printable
  diagnostics are folded to one line before stderr composition so validator
  output cannot inject forged log lines.
  XSD `xmllint`, canary child-stage, and direct evidence receipt-verifier
  startup failures, including runtime/type/value launcher failures, also report
  only stable stage labels instead of argv, local paths, raw process-launch
  exception text, or chained traceback causes.
  Their stdout/stderr runtime/type/value pipe read or close failures, plus
  post-wait thread `join()`/`is_alive()` bookkeeping failures, use the same
  stage-output label-only diagnostics, and pipe chunks must be byte-like values
  capped by byte length before preview decoding, avoiding empty-output
  misclassification, raw thread tracebacks, or wide-memoryview byte-limit
  bypasses. Runtime/type/value wait failures, cleanup kill failures, and
  malformed child return codes also use label-only child-finish diagnostics.
  Direct evidence receipt-verifier failures also redact key/value and
  identifier-style secret-looking stderr plus unsafe control characters before
  reporting child verifier diagnostics, and accepted printable verifier stderr
  is folded to one line before failed or successful direct-verifier diagnostics
  are reported. Receipt-verifier source-sidecar replay
  also rejects Unicode format controls in rail `profile` and `rail_message_id`
  fields before source metadata comparison.
  Duplicate receipt, canary summary,
  evidence summary, and canary-runbook path errors report only the duplicate
  field labels, not the raw duplicated path values. Canary runbook endpoint URL
  and trust-bundle source URL validation errors also report field-label
  failures without echoing rejected secret-bearing URL values, and archived
  canary child commands that contain token-like URL material are rejected by the
  evidence secret scanner without reflecting the command value. Compact path
  strings in archived evidence/readiness rollups, including canary/trust
  summary paths, canary config paths, receipt paths, and XSD schema/fixture
  paths, reject secret-looking key/value material and path confusables before
  successful summaries can preserve those strings. Evidence and readiness replay
  also reject compact canary/trust summary paths that are replayed as canary
  config paths, canary-stage receipt paths, direct receipt-verification paths,
  or trust-bundle paths, including across relabelled evidence summaries.
  Compact trust-source URL validation inside
  archived evidence and readiness rollups follows the same label-only error
  pattern, and URL port parser failures now omit raw parser exception text so
  malformed operator-provided ports cannot be reflected. URL host validation now
  rejects secret-looking hostname labels and non-ASCII raw host labels, and
  non-port parser failures also use label-only diagnostics before malformed URL
  text can be echoed. Timestamp helpers for direct trust-bundle sources,
  operator evidence, archived receipts, and final readiness replay also reject
  Unicode format controls locally before timestamp parsing, then require
  parseable timezone-aware timestamps to use the canonical evidence shape
  `YYYY-MM-DDTHH:MM:SS.ffffffZ` (or the equivalent form with a numeric offset)
  rather than accepting
  space separators, lowercase separators, comma fractions, compact offsets, or
  the unknown-offset `-00:00` spelling.
  Compact canary
  provider/environment, evidence policy context,
  trust profile ID/rail/environment, trust embedded-signature policy,
  profile-override policy, trust source authority/version, and archived trust
  DER label values reject secret-looking identifier-style strings without
  echoing them. Direct trust-bundle material and archived evidence replay also
  require DER labels to be printable ASCII before summaries can preserve
  Unicode-confusable material. Trust embedded-signature policies also reject non-ASCII
  confusable spellings before unsupported-policy diagnostics or readiness
  blockers can preserve forged values, and trust source authority/version
  provenance must be printable ASCII before direct summaries, evidence replay,
  or readiness rollups can preserve it. Final readiness also scrubs
  non-production/unsupported trust policies and placeholder source provenance
  from normalized output after emitting label-only blockers. Trust-bundle, XSD fixture,
  operator-evidence, and final production-readiness required/optional
  clean-string helpers also reject Unicode format controls in direct source,
  source URL, policy, trust-material label, manifest, profile-catalog, archive,
  rail-message ID, reviewed reason, and string-list values, matching the
  recursive bundle, manifest, evidence, and readiness scans that catch those
  controls during CLI loading. Live rail/audit adapter raw CLI, URL, output,
  rail operator-key path, notary bearer-token path, and rail message-path
  helpers use the same
  control-character policy as XSD, operator-evidence, and final readiness raw
  CLI token, numeric/context/profile value, local path, source-path,
  fixture/schema relative-path, receipt-kind, child-command, stage-name, compact
  timestamp, and HTTP URL helpers. Receipt-verifier raw CLI, receipt path, and
  HTTP URL helpers plus canary raw CLI, URL, output/runbook path, runbook
  string, and numeric preflight helpers now use that policy too.
  Trust-bundle raw CLI, output path, and source-age integer preflight helpers
  also reject Unicode format controls at the raw guard layer.
  Trust-bundle SHA-256 pins, declared DER digests, and
  certificate policy OIDs, plus archived evidence/readiness SHA-256 fields for
  trust bundles, profile-override pins, and receipt payload/anchor/index digests,
  reject the same markers before canonical-format diagnostics. Canary runbook
  provider/environment labels enforce that
  identifier boundary before plan-only or executed summaries can persist those
  labels. Live rail sidecar `profile` and `rail_message_id` identifiers
  and archived rail receipt identifiers enforce the same no-echo check before
  receipt emission, network delivery, or summary rollup. Live rail sidecar
  `message_type` values must also remain printable ASCII and match the
  canonical lowercase ISO family-id shape before unsupported-type diagnostics
  can print a short unsupported family value, and rail sidecar
  `message_type`/`payload_sha256` plus archived rail receipt `message_type`
  values reject secret-looking markers before digest or summary diagnostics.
  Direct receipt replay, evidence replay, readiness replay, and XSD profile
  catalogs now use ASCII-only rail message-type digits, and evidence/readiness
  archive/canary kind, filename, or metadata mismatch blockers avoid printing
  receipt kind values, receipt leaf names, or full metadata tuples.
  XSD profile-catalog enum values such as rails, embedded signature policies,
  reference datasets, and structured-address modes now report unknown values by
  class without printing the supplied enum value.
  Profile-catalog profile IDs, family aliases, concrete version IDs, skipped
  family aliases, and strict missing-schema-version failures use label-only
  diagnostics for duplicate, mismatch, and schema-backed gate errors in both
  direct XSD verification and final readiness replay.
  XSD source filename, schema `targetNamespace`, schema payload-root, XML
  fixture namespace/payload-root, unknown schema-reference, and linked
  schema/fixture mismatch diagnostics likewise report only the mismatch class
  and affected label.
  XSD document/payload complex-type cardinality and direct-child diagnostics
  also report only the schema role rather than the concrete type names parsed
  from the schema.
  XSD blocked-source already-checked-in and missing-gap diagnostics also report
  only the affected class, keeping candidate message definition IDs out of
  direct verifier stderr and final readiness blocker text while preserving the
  normalized public blocked-source evidence.
  Profile-catalog business-service entries are capped before overlong service
  identifiers can be emitted or archived.
  XSD/XML schema and fixture identifiers are capped before schema/root mismatch
  diagnostics can print overlong ASCII payload names or namespace URIs.
  XSD profile-catalog `message_def_id` and version entries also require
  ASCII-only digits before missing-schema or skipped-version classification.
  Receipt verifier, evidence, and readiness `receipt_kind` values reject
  secret-looking identifier markers and non-ASCII confusable spellings before
  unsupported-kind diagnostics or blockers can preserve forged archive values,
  and archived canary stage names reject those markers plus non-ASCII confusable
  spellings before unsupported-stage, ordering, or stage-window diagnostics.
  Trust-bundle preflight, evidence replay, and production-readiness compact
  trust profile IDs, override IDs, embedded signature policy strings, and
  trust-source authority/version/timestamp provenance are capped before trust
  diagnostics can print or archive them.
  Top-level trust-bundle read, malformed JSON/UTF-8, symlink-ancestor, and
  semantic validation diagnostics now use bundle-index labels instead of local
  operator bundle paths, while successful summaries retain the path for audit
  evidence.
  Top-level XSD fixture manifest and profile-catalog read, malformed
  JSON/UTF-8, raw-string, symlink-ancestor, and size-limit diagnostics now use
  input role labels instead of local operator manifest/catalog paths, while
  accepted summaries retain the paths for audit evidence.
  Manifest-referenced XSD schema and XML fixture read, parse, DTD/entity,
  restricted-terms, structural-validation, symlink-ancestor, and size-limit
  diagnostics now use manifest entry labels instead of resolved local source
  paths, while accepted summaries retain the manifest-relative paths for audit
  evidence.
  Live rail/notary adapter timeouts must be
  positive finite numbers, response-body retention caps must be positive
  integers no larger than 4 MiB, and rail payload byte caps must be positive
  integers rather than JSON/Python boolean aliases before any local read or
  network delivery. Raw numeric CLI values across the ISO operator and release
  helper surface must also use printable ASCII and canonical decimal spelling,
  so padded, plus-signed, trailing-dot, dot-leading, or leading-zero exponent
  spellings, signed-zero aliases, or overflow exponents cannot reach argparse
  conversion as production budgets. The pending XSD source probe applies the
  same raw timeout/byte-limit preflight before argparse can reinterpret
  negative numeric spellings as options. All ISO
  helper regular-file byte caps, plus the rail
  payload bounded reader, reject boolean and non-integer limit aliases before
  file metadata is inspected. Operator receipt, summary,
  and emitted profile-override output paths also reject control characters, whitespace,
  leading-dash segments, backslashes, semicolon parameters, dot/parent
  traversal, empty segments, symlinked existing ancestors, and hard-linked,
  symlink, or non-regular targets before writing, then replace the target
  atomically from an owner-private descriptor-checked temporary file with a bounded
  digest-derived name.
  Direct ISO CLI path preflights treat bare path flags, empty separate values,
  empty equals-form values, separate values that begin with `--`, and
  equals-form values such as `--summary-out=--flag` as missing path values, so
  flag tokens cannot be misparsed as operator-local paths before file or network
  work starts. Required notary/rail URL values now also reject control-bearing,
  non-ASCII, whitespace-padded, or non-URL-shaped secret-looking values before
  unrelated file or directory requirements can mask the URL error. Direct numeric CLI preflights
  similarly reject malformed, empty, flag-looking, secret-looking, and non-ASCII
  numeric values before Python/argparse can accept Unicode digit confusables or
  echo raw operator input. All ISO operator entry
  points reject secret-looking raw CLI
  tokens, including percent-encoded forms, before argparse can echo unknown
  arguments, and reject control-bearing unknown CLI tokens before terminal
  control bytes can reach argparse diagnostics. Unknown raw CLI tokens must also
  be printable ASCII, so Unicode-confusable option spellings cannot reach
  argparse output. Because those tools do not accept positional operands, they also
  reject the `--` argument terminator in raw secret, boolean, path, context, and
  numeric preflights before any trailing flag/value material can bypass scanning
  and be echoed by argparse. The parsers also disable long-option abbreviation,
  so partial spellings such as `--summary-ou` cannot be accepted as exact
  production flags. Direct boolean CLI
  flags reject attached `--flag=value`
  spellings and separate non-option values before argparse can echo the value or
  reinterpret the option. Evidence and production-readiness
  provider/environment context flags reject missing, empty, flag-looking,
  leading-dash, secret-looking, or non-ASCII values before argparse or summary
  loading, while evidence default-profile context rejects leading-dash profile
  ids before argparse can reinterpret them as options. Canary and trust-bundle
  context summaries must keep provider/environment
  labels printable ASCII. Expected provider/environment mismatch diagnostics
  remain label-only and do not print observed or expected context values.
  Canary runbook config read, malformed JSON/UTF-8, symlink-ancestor, and
  size-limit failures use the `config` label rather than local operator runbook
  paths before planning or child command execution.
  Operator evidence canary/trust summary read, malformed JSON/UTF-8,
  symlink-ancestor, size-limit, and semantic validation failures use indexed
  summary labels rather than local archive paths, while accepted compact
  evidence still records the paths for audit traceability.
  Production readiness XSD/evidence summary read, malformed JSON/UTF-8,
  symlink-ancestor, and size-limit failures use indexed summary labels rather
  than local release input paths before blocker replay, while accepted summaries
  and blocker locations still preserve paths for audit traceability.
  Archived canary command replays reject unsupported secret-looking or
  non-ASCII flag names with label-only diagnostics before evidence summaries can
  echo the flag spelling.
  Unknown JSON field names are likewise reported with label-only diagnostics,
  including ordinary ASCII typos as well as secret-looking, control-bearing,
  non-ASCII, overlong, too numerous, or collectively oversized names.
  Non-finite JSON numeric constants are reported by class without echoing the
  `NaN`/`Infinity` spelling supplied in adapter, canary, or receipt inputs.
  Duplicate record, list, digest, OID, DER, compact-summary, archived
  receipt-reuse, and trust-material diagnostics now report label/index-only
  structural failures without echoing the rejected duplicate value.
  Version-bearing manifests, trust bundles, notary audit indexes, notary
  anchors, persisted record sources, and adapter receipts require exact integer
  version values and reject JSON booleans. Receipt `status_code` metadata also
  rejects JSON booleans and values outside the HTTP 100-599 range before
  success-policy checks, and the live rail/notary adapters accept only real
  integer upstream status values, reject boolean or string aliases before
  coercion, and normalize non-standard remote statuses into transport-failed
  receipts with `status_code=null` instead of archiving invalid HTTP evidence.
  Evidence and readiness replay accept those null-status entries only as failed
  receipts without response-body digests. Notary audit-index,
  anchor, and receipt `record_count` metadata reject JSON boolean aliases
  before count equality or source-binding checks. Notary audit-index records
  must carry canonical Torii lifecycle states (`Pending`, `Accepted`, or
  `Rejected`), state-compatible pacs.002 summary codes, and the complete
  summary key set emitted by Torii, including nullable fields such as
  `settled_at_ms`, `transaction_hash`, `uetr`, and `reference_snapshot_id`, so
  omission cannot be treated as intentional null evidence during source replay,
  and notary publication plus production receipt evidence must bind a positive
  notary `record_count` instead of an empty anchor. Persisted notary record
  sources must likewise
  carry the complete record, context, metadata, and status-history key sets
  emitted by Torii during source replay and Torii durable-store reload while
  still allowing intentional JSON nulls for nullable fields, requiring each
  history entry's pacs.002 code to match its lifecycle status, and requiring
  concrete persisted strings to be non-empty, unpadded, and free of unsafe
  controls including Unicode format controls; Torii
  reload binds every accepted record to the digest-addressed filename derived
  from its embedded `message_id` without following symlinked `messages`
  directories or record paths, or reading records larger than 1 MiB; Torii also
  omits oversized runtime records from durable files and regenerated audit
  indexes. Canary, evidence, and XSD
  bounded subprocess output limits reject boolean and non-integer aliases before
  child commands are run or plan summaries are emitted.
  Canary runbook paths reject embedded whitespace, leading-dash path segments,
  backslashes, semicolon path parameters, empty segments, and dot/parent
  traversal segments before path expansion or child-script planning.
  XSD manifest/profile optional fields are optional only when omitted; explicit
  `null` values for schema/fixture reviewed reasons, trust and revocation
  material lists, booleans, numeric caps, business-service arrays, and amount
  minor-unit arrays now fail before digest-bound XSD summaries are emitted.
  Reviewed XSD gap reasons and profile-catalog identity strings also reject
  ASCII control characters at preflight time. Reviewed gap reasons and
  blocked-source review reasons must also remain printable ASCII and
  secret-looking-free with a 1024-character cap in direct XSD summaries and
  production-readiness replay, and production readiness rejects digest-correct
  archived XSD summaries whose reviewed gap reasons are present but empty,
  non-string, or overlong, or whose copied missing-schema/schema-only gap-list
  entries carry non-canonical paths or reviewed reasons, or whose
  schema-backed fixtures still carry a missing-schema reason. Rejected XSD manifest and archived summary path
  validation errors report label-only failures without echoing raw path values
  that may contain secret-looking segments. Checked-in XSD source provenance
  now rejects placeholder GitHub repository coordinates, all-zero Git commit
  and SHA-256 provenance placeholders, separator-obfuscated or collapsed
  placeholder repository components, non-ASCII or overlong source paths, embedded whitespace,
  semicolon path parameters,
  identifier-style secret-looking path material, and secret-looking repository coordinates during preflight,
  and production readiness replays the same repository-coordinate rejection
  before emitting archived XSD summaries.
  Direct strict XSD preflight failures no longer echo reviewed
  `schema_only_reason` or `missing_schema_reason` text, and final readiness
  XSD gap blocker/warning entries now carry only the affected path and message
  definition id instead of archived free-form review rationale.
  The rail gateway adapter, receipt verifier, direct evidence verification, and
  final readiness now also reject unsupported receipt-kind and rail-message-type
  values with label-only diagnostics; stage receipt-kind mismatch blockers
  identify the mismatch class without printing the unexpected archived kind, and
  final readiness normalized receipt output scrubs unsupported receipt-kind and
  unsupported, malformed, or secret-looking rail `message_type`, `profile`,
  `rail_message_id`, and `source_path` values, plus malformed or unsupported
  notary `anchor_sha256`, `index_sha256`, `anchor_path`, `store_dir`,
  `index_path`, and `record_count` values, to `"unsupported"` instead of
  echoing them. Unsupported canary stage-name diagnostics no longer echo the
  unexpected stage label. Direct evidence replay and final readiness trust blockers also report
  non-production or unsupported embedded-signature policies without echoing the
  archived policy value, and final readiness normalized trust profile output
  scrubs non-production/unsupported policies plus placeholder trust-source
  authority/version/URL values to `"unsupported"` before emitting release JSON.
  Unsupported summary `version` values in XSD, pending-probe, canary, receipt,
  and trust summaries are similarly normalized to `"unsupported"` before final
  readiness JSON is emitted.
  Archived provider/environment context values from evidence policy, canary, and
  trust profile summaries are likewise normalized to `"unsupported"` when they
  do not match the release context.
  Release and archived freshness budgets are capped at 36,500 days; over-ceiling
  CLI, evidence policy, or compact trust source values fail without echoing the
  submitted number, and weaker archived budgets normalize to `"unsupported"` in
  final readiness output.
  Blocked compact trust verifier override flags and receipt verifier `allow_*`
  policy flags also normalize to `"unsupported"` in final readiness output, as
  does `require_source_files=false`.
  Receipt entries that preserve retired rail message types or default-profile
  fallback `profile=null` values, or
  `endpoint_requires_insecure_http=true` markers, likewise normalize to
  `"unsupported"` in public readiness summaries after their policy blockers are
  emitted.
  Diagnostic trust-source URLs that require `allow_insecure_source_url=true`,
  including `http://` and local/private endpoints, likewise normalize to
  `"unsupported"` in public readiness trust profiles after their override
  blocker is emitted.
  Missing compact trust source objects (`source=null`) likewise normalize to
  `"unsupported"` after source-missing blockers are emitted.
  Blocked canary `plan_only=true`, `require_explicit_policy=false`, per-stage
  `stage_dry_run=true`, and compact trust `profile_json_emitted=false` /
  `profile_json_emittable=false` states also normalize to `"unsupported"` in
  final readiness output. Compact trust `max_source_age_days=null` likewise
  normalizes to `"unsupported"` when profile JSON is not emittable after trust
  source blockers are emitted.
  Failed pending-XSD probe `ok=false` and per-probe `looks_like_xsd=false`
  states likewise normalize to `"unsupported"` in public readiness summaries and
  unreachable-probe blocker entries.
  Non-success pending-XSD probe response/sample fields (`http_status`,
  `content_type`, `downloaded_bytes`, `sample_sha256`, `truncated`, and
  `error_kind`) also normalize to `"unsupported"` in public readiness summaries
  after the existing unreachable-probe blocker is emitted.
  XSD strictness proof flags that remain `false` after replay,
  `require_schema_backed_fixtures`, `require_fixture_for_schema`,
  `require_profile_schema_backed_versions`, and `validate_xml_schema`, also
  normalize to `"unsupported"` in public readiness summaries after their
  existing blockers or warnings are emitted.
  Failed or malformed receipt entry `ok` values likewise normalize to
  `"unsupported"` in public readiness summaries after receipt status blockers
  are emitted.
  Receipt response metadata triplets (`ok`, `status_code`, and
  `response_body_sha256`) are preserved only for internally coherent successful
  proofs: `ok=true`, a 2xx integer HTTP status, and a canonical nonzero response
  digest. Failed, mismatched, incomplete, or malformed triplets normalize to
  `"unsupported"` in public readiness output after their existing blockers are
  emitted.
  Trust-bundle verification and direct evidence replay
  also report unsupported internal DER material kinds without echoing the
  supplied kind string. XSD profile-catalog rail, embedded-signature policy,
  reference-dataset, and structured-address-mode enum diagnostics also report
  the unknown class without echoing the supplied enum value; duplicate profile
  IDs, family aliases, concrete version mismatches, duplicate concrete
  versions, skipped-family mismatches, and strict schema-backed gate failures
  similarly avoid copying the supplied profile/version strings in direct XSD
  verification and final readiness replay. XSD source filename, schema
  `targetNamespace`, payload-root, fixture namespace, unknown schema-reference,
  and linked schema/fixture mismatch diagnostics also avoid copying the
  supplied values. Final readiness trust-profile source, pin, policy, and
  revocation-material blockers also avoid copying archived profile IDs. Direct
  evidence replay also rejects
  unsupported or local-only child command flags without echoing the archived
  flag text.
  Archived profile-catalog paths, including checked-in fixture coordinates, get
  the same readiness recheck when production readiness consumes archived XSD
  summaries.
- Added `scripts/iso_operator_evidence_verify.py`, an offline production
  evidence gate for archived canary and trust-bundle summaries. It caps each
  input JSON file at 4 MiB before parsing, rejects all-zero summary digest
  placeholders before mismatch checks, recomputes summary digests with
  label-only mismatch diagnostics, requires
  exact expected provider/environment CLI context,
  rejects missing or unsupported canary and trust-bundle summary versions,
  requires successful rail/notary/verify stages by default,
  requires the verify stage to carry digest-bound receipt-verifier JSON with
  rail and notary receipt kinds plus per-receipt digests, caps direct
  receipt-verifier `--receipt` and `--receipt-dir` selectors at 64 paths before
  discovery, caps direct
  receipt-verifier stdout/stderr at 4 MiB before JSON parsing, bounds direct
  receipt-verifier runtime with positive finite
  `--receipt-verifier-timeout-secs`, redacts secret-looking or control-bearing
  direct receipt-verifier stderr plus non-ASCII or local-path-shaped stderr
  before failed child verifier diagnostics report a detail, rejects missing or unsupported
  receipt-verifier summary versions, rejects plan-only
  or dry-run canaries, plaintext-HTTP overrides, default-profile fallbacks,
  stale retired `colr.007` receipt-summary fields, unredacted rail
  operator-private-key or notary bearer-token paths,
  non-canonical compact receipt paths with control characters, surrounding
  whitespace, dot or parent traversal segments, checked-in ISO fixture
  artifact coordinates, or non-`*.receipt.json` leaves, all-zero compact
  receipt digest placeholders,
  secret-looking output, non-canonical canary runbook `config_path` values with
  control characters, surrounding whitespace, traversal segments, or non-JSON
  leaves, control-bearing, whitespace-padded, or secret-looking provider, stage,
  receipt-kind, trust-profile, trust source, or archived trust DER label
  identity strings, unknown raw canary, receipt-verifier, or trust-bundle summary
  fields,
  smuggled trust-source URLs including repeated path separators, missing/malformed/future
	  trust-source retrieval timestamps, missing/malformed/future or padded
	  trust-summary `verified_at` timestamps, smuggled child command endpoint URLs
	  including overlong URLs, invalid or overlong hosts, repeated path separators,
	  localhost/local-private IP literals, known local/private rebinding hostnames,
	  legacy IPv4 numeric notation, IPv6 transition addresses embedding non-global
		  IPv4 addresses, reserved documentation hosts such as `.example`,
		  `example.com`, `example.net`, `example.org`, or `example.invalid`,
		  checked-in template hosts under `operator-canary.bank` in direct
		  receipt archive replay, and percent-escape smuggling, local-only
  child command flags in either `--flag` or `--flag=value` form, including the
  notary adapter's `--allow-missing-record-sources` diagnostic override,
  unsupported child command flags outside the expected rail/notary/receipt
  verifier CLI surfaces, duplicate singleton child command flags, boolean
  child command flags using attached or separate values, non-positive,
  non-finite, or non-canonical numeric child command flag values, Unicode
  digit confusables in floating timeout flags, value-taking child command flags whose separate or
  equals-form values are empty, another flag token, or a leading-dash
  rail/notary endpoint URL, rail operator-private-key placeholder, or notary
  bearer-token-file placeholder,
  child command arrays that do not start with a Python interpreter using
  ASCII-only numeric version suffixes plus the expected stage script path, or
  that contain extra positional arguments after that runner-emitted prefix,
  non-ASCII or non-canonical child command path values including leading-dash segments,
  control characters or surrounding whitespace in executed or plan-only child
  command arrays,
  and child command arrays that omit required stage inputs,
  non-canonical rail/notary `receipt_dir` values with control characters,
  surrounding or embedded whitespace, leading-dash path segments, semicolon path
  parameters, empty segments, raw backslashes, or traversal segments,
  rail/notary `receipt_dir`
  values that do not match the child command's single `--receipt-dir`,
  verify-stage commands that omit the rail/notary receipt directories generated by non-dry-run stages,
  reordered repeatable notary `--endpoint` values or verify-stage
  `--receipt-dir` / `--receipt` selectors,
  synthetic trust DER, record-only trust policy, and placeholder trust-source
  provenance such as `dummy`, `fake`, `placeholder`,
  `replace-before-production`, `sample`, `template`, or reserved hosts such as
  `.example`, `example.com`, `example.net`, `example.org`, and
  `example.invalid` before an archive is treated as production evidence.
  Direct evidence summary input/output CLI paths and compact archived path
  values reject secret-looking key/value material before an evidence summary is
  emitted, and repeatable canary, trust, receipt, and receipt-directory inputs
  are capped at 64 paths before loading, while final readiness emits top-level
  XSD, evidence, and pending-probe summary references, blockers/reviewed-gap
  warnings, and nested diagnostic entries in canonical order before digesting
  the release summary. The same canonical summary order is used before
  cross-summary blocker generation, so duplicate/replay diagnostics do not
  depend on operator input order. Receipt-summary entry order remains checked
  even when a replayed row has a malformed `receipt_sha256`, so digest-shape
  drift cannot mask noncanonical canary or archive receipt order. Unsupported
  receipt-kind and unsupported, malformed, or secret-looking rail
  `message_type`, `profile`, `rail_message_id`, and `source_path` values are
  scrubbed to `"unsupported"` in the normalized readiness output, and
  operator-local path strings cannot
  smuggle runtime tokens into release archives. Unsupported summary `version`
  values in XSD, pending-probe, canary, receipt, and trust summaries are
  similarly normalized to `"unsupported"` in final readiness output, and
  mismatched archived evidence policy, canary, and trust profile
  provider/environment context values are also normalized to `"unsupported"`.
  Release and archived freshness budgets are capped at 36,500 days, and weaker
  archived evidence/trust source budgets are normalized to `"unsupported"` in
  final readiness output.
  Blocked compact trust verifier override flags, receipt verifier `allow_*`
  policy flags, and `require_source_files=false` are also normalized to
  `"unsupported"` in final readiness output.
  Retired rail message types and default-profile fallback
  `profile=null` values, plus `endpoint_requires_insecure_http=true` markers,
  in compact receipt entries are also scrubbed to `"unsupported"` in normalized
  readiness output. Malformed or unsupported compact notary receipt metadata
  (`anchor_sha256`, `index_sha256`, `anchor_path`, `store_dir`, `index_path`,
  and `record_count`) is likewise scrubbed before public readiness JSON is
  emitted.
  Failed, mismatched, incomplete, or malformed receipt response metadata
  triplets (`ok`, `status_code`, and `response_body_sha256`) are likewise
  scrubbed to `"unsupported"` after the corresponding receipt blocker is
  emitted.
  Diagnostic trust-source URLs that require `allow_insecure_source_url=true`
  are also scrubbed to `"unsupported"` in normalized readiness trust profiles.
  Missing compact trust source objects (`source=null`) are also scrubbed to
  `"unsupported"` after source-missing blockers are emitted.
  Compact trust `max_source_age_days=null` is scrubbed to `"unsupported"` when
  profile JSON is not emittable after trust source blockers are emitted.
  Non-success pending-XSD probe response/sample fields are also scrubbed to
  `"unsupported"` in normalized readiness output after the corresponding
  unreachable-probe blocker is emitted.
  Direct
  operator evidence summary output also cannot reuse
  or hardlink any canary, trust, or direct receipt summary input path before
  those source summaries are loaded, and it cannot be written under a supplied
  receipt archive directory, so aggregate evidence publication cannot overwrite
  the compact evidence or direct receipt evidence it is validating. Existing
  summary-output parents and leaves are checked before any direct receipt
  verifier child process is invoked, so symlinked or hardlinked output targets
  cannot defer failure until after receipt archive replay.
  For archived trust-bundle summaries, it preserves the
  bundle-level `bundle_sha256`, rejects duplicate compact receipt paths/digests,
  duplicate bundle digests, and duplicate profile IDs with label-only
  diagnostics, requires emitted profile overrides to match the
  top-level profile id, rail, and signature policy, rechecks override pin/OID
  and CRL/OCSP material counts against the verifier's material summary, binds
  CRL/OCSP override DER back to recorded summary digests and byte lengths,
  replays the CRL-vs-OCSP material-class checks on the archived override DER,
  reports DER missing/extra/byte-length drift by material role without printing
  the DER SHA-256 value,
  rejects malformed policy OIDs or non-canonical, oversized, or non-SEQUENCE
  CRL/OCSP base64, and fails closed on same-count trusted/revoked pin overlap
  attacks.
- Added `scripts/iso_production_readiness.py`, an offline release-readiness
  rollup for versioned digest-bound XSD and operator evidence summaries. It requires
  XSD/evidence summary JSON inputs to stay within a 4 MiB pre-parse cap, rejects
  more than 64 repeatable XSD or evidence summary input paths before loading
  any summary files, caps untrusted XSD/evidence/readiness JSON arrays at
  8192 items before semantic replay, and rejects
  final `--summary-out` paths that reuse or hardlink XSD/evidence summary
  inputs before loading them, preflights final summary-output parents and leaves
  before summary loading, rejects
  all-zero summary digest placeholders and compact canary/trust summary
  reference placeholders before label-only mismatch diagnostics,
  exact provider/environment CLI context, strict schema-backed/fixture-backed
  XSD proof with canonical fixture schema references and reviewed-gap reason
  strings, production evidence policies,
  per-canary explicit-policy proof, full rail/notary/verify canary evidence,
  versioned digest-bound direct receipt-archive
  verification with per-receipt digests, rail/notary receipt kinds, no retired
  `colr.007` receipts, no default rail profile fallback, no forged
  `policy.default_rail_profile` without the matching default-profile policy,
  positive notary record-count proof, and
  `require-verified` trust profiles with at least one public-key or X.509
  trust pin plus required CRL/OCSP revocation
  checks and material before reporting the ISO corridor ready. Canary and
  archive rail receipts must also have their `message_type` covered by the
  matched trust profile's schema-backed first-release rail family, so custom or
  lifecycle profile evidence cannot satisfy production coverage with trust
  material for a different or non-advertised rail family. It also
  recursively rejects secret-looking fields or string values in archived XSD
  and evidence summaries, including compact path strings and compact
  provider/environment/trust-source identity values, before emitting the final
  readiness rollup, preserves normalized XSD blocked-source and pending-source
  evidence in the public readiness summary, rejects reviewed source records
  that no longer correspond to a current missing-schema fixture or
  profile-version gap, and rejects replayed blocked-source references,
  blocked-source candidate digests, or pending-source references across repeated
  XSD summaries.
  Diagnostic compact trust summaries with `allow_insecure_source_url=true` can
  still replay `http://` or local/private trust-source URLs so readiness emits
  production blockers rather than aborting before the blocker report is written,
  and normalized readiness output redacts those source URLs to `"unsupported"`.
  Readiness replay also rechecks that blocked-source marker lists contain
  explicit redistribution restriction evidence rather than copyright-only
  provenance, while the source XSD preflight normalizes whitespace and
  zero-width format characters before matching known restricted license
  phrases.
- Added checked-in operator canary runbook templates under
  `fixtures/iso20022/operator_canary/` for Swift CBPR+, Fedwire Funds, SEPA SCT
  Inst, and securities CSD profile families. They use
  `operator-canary.bank` template endpoints for plan-only validation; non-plan
  canary execution and archived production evidence both reject that template
  suffix before it can be treated as live evidence. Plan-only canary summaries
  record `ok: false`, so redacted planning output cannot be mistaken for an
  executed provider canary by consumers that check only the summary verdict.
  Executed direct canary summaries also report `ok: true` only when the run was
  produced with `--require-explicit-policy`, the planned policy records and
  executed results are the exact ordered rail/notary/verify records, no stage
  skipped or producer dry-run was used, local diagnostic allowances such as
  insecure HTTP, default profiles, or failed receipts were absent, and verifier
  source-file checks stayed enabled.
  Compact canary summaries inside aggregate evidence also carry a production
  `ok` verdict that is true only for executed, explicit-policy, non-dry-run
  canaries with all production stages and a production-complete receipt summary;
  final readiness recomputes that compact verdict and emits
  `evidence.canary_summary_not_ok` or `evidence.canary_summary_ok_drift` for
  diagnostic or relabelled canary evidence.
- Added `scripts/iso_trust_bundle_verify.py`, an offline XMLDSig/XAdES trust
  bundle preflight for operator rail PKI material. It caps bundle JSON at
  64 MiB and repeatable bundle input path lists at 64 entries before parsing,
  caps SHA-256, certificate-policy OID, and DER material lists at 8192 entries
  before per-entry parsing,
  verifies canonical nonzero pins,
  digest-bound base64 DER envelopes with at most eight entries per material
  list, a pre-decode 1 MiB DER-size cap, and lightweight semantic shape checks
  for X.509 certificates, X.509 CRLs, and OCSPResponse wrappers, duplicate and
  contradictory trust/revocation material, required CRL/OCSP material, HTTPS
  provenance without credentials, params, query strings, fragments, malformed
  bracket syntax, control characters, local/private IP literals, known
  local/private rebinding hostnames, legacy IPv4 numeric notation, or IPv6
  transition addresses embedding non-global IPv4 addresses, requires
  provenance URL and timezone-aware non-future retrieval timestamp fields before
  emitting a versioned trust summary, rejects repeated input paths without echoing the
  raw path value, rejects secret-looking bundle/output CLI path material before
  summary or profile-override emission, rejects JSON boolean bundle versions,
  copied bundles, and duplicate profile
  IDs, emits and de-duplicates bundle-level `bundle_sha256` values, enforces
  supported `embedded_signature_policy` values (`record-only`,
  `reject-unsupported`, or `require-verified`) before allowing local
  record-only diagnostic replay,
  unique DER labels per material class, requires
  nonzero DER-object `sha256` values before digest matching
  or profile override emission, omits absent DER labels from trust summaries,
  and rejects secret-looking fields or string values such as `token=...`,
  `Authorization: ...`, `private_key=...`, or `X-Iroha-Signature: ...` before
  emitting Torii profile trust overrides. Trust-bundle profile IDs,
  environments, source authority/version strings, DER labels, and recursively
  scanned field names also reject secret-looking identifier-style values before
  summary or profile-override emission. `--max-source-age-days` rejects
  missing, empty, flag-looking, malformed, or secret-looking freshness budgets
	before argparse or bundle reads.
- Trust-bundle local-audit overrides now fail closed unless they are actually
needed by the verified input: `--allow-record-only` requires a non-production
`embedded_signature_policy`, `--allow-insecure-source-url` requires an
  `http://` or local/private source URL, and `--allow-synthetic-der` requires DER material that
  fails the expected certificate/CRL/OCSP shape check. The private synthetic-DER
  usage marker is stripped from emitted summaries.
- Added checked-in trust-bundle templates under
  `fixtures/iso20022/trust_bundles/` for Swift CBPR+, Fedwire Funds, SEPA SCT
  Inst, and securities CSD profile families.
- Made JS `submitIsoMessage` require an explicit `creationDateTime`; the helper
  no longer injects wall-clock time.
- Added `profile` support to JS ISO submissions and extended response
  normalization for profile/status-history fields.
- Added explicit `--iso-settlement-date YYYY-MM-DD` to CLI ISO settlement
  previews so generated `sese.023`/`sese.025` XML can be deterministic.

## Operator Canary Runbook

Use `scripts/iso_operator_canary.py` for provider or environment canaries that
need both live-rail delivery evidence and external audit-spool publication
evidence:

```bash
python3 scripts/iso_operator_canary.py \
  --config fixtures/iso20022/operator_canary/swift_cbpr_plus.preprod.example.json \
  --plan-only \
  --require-explicit-policy

python3 scripts/iso_operator_canary.py \
  --config runbooks/iso/local-provider-canary.json \
  --require-explicit-policy \
  --summary-out run/iso/local-provider-canary.summary.json
```

The JSON runbook is intentionally strict. It must label `provider` and
`environment`, configure at least one of `rail` or `notary`, and enables receipt
  verification by default. Relative paths are resolved from the runbook location
  with their parent directories canonicalized and their final path leaf
  preserved for child script boundary checks; they must stay under that
  directory. Optional path and numeric limit fields are optional only when
  absent; a present `null` value is malformed. Use absolute paths for explicitly
  external operator directories.
Endpoint URLs must not contain embedded credentials,
params, query strings, or fragments. The rail stage requires the exact
genesis-derived checksummed `network_id` and a runtime-only
`operator_private_key_file`; it has no bearer-token fallback. Notary bearer
tokens remain separate runtime-only inputs. The runner does not read either
secret and redacts both secret-file arguments in the summary. Production canaries should use
`--require-explicit-policy`, which requires every runbook policy boolean and
the notary/verify list-valued receipt selector fields to be present, requires
rail/notary receipt directories to be explicitly recorded, and rejects
production-policy receipt directories that overlap the rail inbox or notary
audit-export root before any child script runs. Stage receipt directories also
must not overlap the configured rail operator-private-key or notary bearer-token
paths, so secret inputs cannot be placed inside generated receipt roots or vice
versa. The operator key must stay outside the rail inbox and the notary token
must stay outside the notary audit-export root. It then records
that proof in the summary for the evidence gate. Verify receipt selectors must be unique and
non-overlapping at planning time, including direct
`verify.receipts` files that are already covered by explicit or generated
`verify.receipt_dirs`; regression coverage removes each rail, notary, and
verifier policy boolean or explicit list in turn. Checked-in
templates for Swift CBPR+, Fedwire Funds, SEPA SCT Inst, and securities CSD
live-profile families live under
`fixtures/iso20022/operator_canary/`; copy them into an operator runbook area
before replacing the template NetworkId, endpoints, operator-key/notary-token
paths, inboxes, and `audit_export_dir` locations.

```json
{
  "provider": "banka-paynet",
  "environment": "preprod",
  "rail": {
    "inbox_dir": "inbox",
    "torii_base_url": "https://torii.example.internal",
    "receipt_dir": "receipts/rail",
    "network_id": "hash:0808080808080808080808080808080808080808080808080808080808080809#9F75",
    "operator_private_key_file": "secrets/torii.operator.key"
  },
  "notary": {
    "export_dir": "audit-export",
    "endpoints": ["https://notary.example.internal/iso-anchor"],
    "receipt_dir": "receipts/notary"
  },
  "verify": {
    "allow_insecure_http": false,
    "require_source_files": true
  }
}
```

## Trust Bundle Preflight

Use `scripts/iso_trust_bundle_verify.py` before merging rail PKI trust material
into an ISO bridge profile:

```bash
python3 scripts/iso_trust_bundle_verify.py \
  --bundle fixtures/iso20022/trust_bundles/swift_cbpr_plus.preprod.example.json \
  --allow-synthetic-der \
  --summary-out run/iso/swift-cbpr-plus-trust-summary.json
```

The verifier is offline. It does not replace Torii's semantic X.509, CRL, and
OCSP checks; it catches operator-package mistakes earlier by requiring
canonical lowercase trust profile IDs, rail values from the supported ISO rail
catalog (`generic-iso20022`, `swift-cbpr-plus`, `fedwire-funds`,
`sepa-sct-inst`, and `securities-csd`), lowercase nonzero SHA-256 pins, matching
DER digests, no duplicate DER within a material class, unique DER labels within
each material class, no trust anchor that is also revoked, CRL/OCSP material when
the corresponding profile flags are explicitly enabled, explicit CRL/OCSP
revocation policy booleans, clean HTTPS source URLs by default, including the
2048-character URL cap and DNS 253-character host limit,
legacy IPv4 numeric notation rejection, IPv6 transition embedded-IPv4 rejection,
timezone-aware non-future
`source.retrieved_at` values, required clean `source.authority`/`source.version`
provenance, explicit top-level `source` objects with omitted and null source
provenance rejected separately, non-placeholder production source metadata
with separator- or compatibility-obfuscated placeholder markers rejected by
trust preflight, evidence aggregation, and readiness replay, and source URLs that do
not use reserved placeholder hosts such as `.example`, `example.com`,
`example.net`, `example.org`, `example.invalid`, or
`operator-canary.bank` in production
evidence/readiness gates, and no runtime secret fields or secret-looking string values. DER-object `sha256`
values are mandatory, nonzero, and must match canonical decoded `der_base64` bytes for
trust anchors, revoked certificates, CRLs, and OCSP responses. DER labels are emitted
only when present and non-empty; archived summaries that explicitly carry
`label: null` fail production-evidence verification. Trust bundles must record
every list-typed material field as an array, including explicit `[]` values for
intentionally empty pin or DER collections, so omitted trust material cannot
silently change profile overrides. Production bundles
also need DER values that look like the expected material class; the checked-in
templates use synthetic DER envelopes only so CI can validate schema and
emitted-profile wiring, and require `--allow-synthetic-der`.
Synthetic-template validation is summary-only:
`--allow-synthetic-der` cannot be combined with `--emit-profile-json`. Replace
templates with the current rail PKI package before production use and omit that
flag before emitting profile overrides. Trust-bundle preflight also rejects
unused local-audit override flags: `--allow-record-only` must correspond to a
non-production `embedded_signature_policy`, `--allow-insecure-source-url` must
correspond to an `http://` or local/private source URL, and `--allow-synthetic-der` must
correspond to DER material that fails the expected certificate/CRL/OCSP shape
check. Trust summaries now record `ok: true` only when profile JSON was emitted,
the summary is emittable, and no local trust diagnostic override was used;
summary-only or synthetic-template validation records `ok: false`. The private
synthetic-DER usage marker is not emitted in summaries.
Profile emission also refuses
  `--allow-record-only`, `--allow-insecure-source-url`, placeholder
  authority/version strings including separator- or compatibility-obfuscated `dummy`, `fake`,
  `replace-before-production`, `sample`, or `template` variants,
  reserved placeholder source URLs such as `.example`, `example.com`,
  `example.net`, `example.org`, `example.invalid`, or
  `operator-canary.bank`, missing source freshness budgets, and
  stale source retrieval timestamps.
Trust bundles must carry an explicit `embedded_signature_policy`; the preflight
does not infer `require-verified` from an omitted policy field.
Example trust preflight command:

```bash
python3 scripts/iso_trust_bundle_verify.py \
  --bundle run/iso/provider-swift-cbpr-plus-trust-bundle.json \
  --summary-out run/iso/swift-cbpr-plus-trust-summary.json \
  --max-source-age-days 7 \
  --emit-profile-json run/iso/swift-cbpr-plus-profile-overrides.json
```

Production evidence requires the trust summary to prove both
`profile_json_emittable=true` and `profile_json_emitted=true`; a summary that
could emit profile overrides but did not write them is local-audit evidence only.
The aggregate evidence gate accepts `--allow-profile-json-not-emitted` only when
at least one archived trust summary actually records
`profile_json_emitted=false`, so an unused diagnostic override cannot be
preserved as a non-production policy bit beside otherwise emitted profile JSON.
Summaries that claim profile JSON was emitted while the archived source policy is
not emittable are rejected even under local-audit allowances.
When profile overrides are emitted, the trust summary is written only after the
profile JSON file write succeeds and carries `profile_json_sha256` for the exact
emitted body. The evidence gate recomputes that digest from the archived
`profile_overrides` before accepting the trust summary.

## Production Evidence Gate

After a live canary and trust preflight complete, archive only evidence that
passes `scripts/iso_operator_evidence_verify.py` with production defaults:

```bash
python3 scripts/iso_operator_evidence_verify.py \
  --canary-summary run/iso/local-provider-canary.summary.json \
  --trust-summary run/iso/swift-cbpr-plus-trust-summary.json \
  --receipt-dir run/iso/rail-receipts \
  --receipt-dir run/iso/notary-receipts \
  --provider banka-paynet \
  --environment preprod \
  --max-canary-age-days 1 \
  --max-trust-age-days 7 \
  --max-trust-source-age-days 7 \
  --summary-out run/iso/local-provider-evidence.summary.json
```

The gate is offline and fails closed. The command must name the expected
`--provider` and `--environment`, which are rechecked against canary and trust
evidence before an archive can be accepted and recorded in the digest-bound
evidence policy. It must also name explicit freshness budgets for canary
`finished_at`, trust-summary `verified_at`, and trust-source `retrieved_at`
timestamps; digest-correct stale archive inputs are rejected before archival.
Accepted trust profiles preserve their compact `bundle_sha256`, optional source
`authority`/`version`, source URL, `retrieved_at` timestamp, the trust verifier's
`max_source_age_days` emission budget, revoked-certificate pin count, required
certificate-policy OID count, and compact trust-anchor/revoked/CRL/OCSP DER
proof digests and byte lengths for the final readiness rollup. Evidence replay
rejects digest-correct raw trust summaries with reordered `bundles` or raw DER
proof, pin, or OID arrays, emits compact trust profiles in canonical `profile_id`
order, and final readiness rejects digest-correct compact summaries whose `profiles` or
trust DER proof arrays have been reordered after archival. The compact trust
summary also preserves the trust verifier's local-only
`allow_synthetic_der`, `allow_record_only`, and `allow_insecure_source_url`
flags, rechecks that `profile_json_emittable` matches those flags plus the
  archived trust source policy, rejects omitted compact `source` keys, preserves
  explicit diagnostic `source: null` profiles only when missing-source replay is
  allowed, and preserves
`profile_json_sha256` so release evidence names the exact profile override body
produced by the trust preflight; the evidence gate recomputes it from the
archived profile override objects before archival, and final readiness rejects
copied compact trust summaries that replay the same profile JSON digest after
relabeling the visible profile or bundle identifiers. All-zero trust bundle,
trust pin, trust DER summary, and emitted profile JSON digests are rejected as
placeholder evidence during archive verification or final readiness replay.
Repeated canary/trust summary paths or copied summaries with the same
`summary_sha256` are malformed input. By default it requires
digest-bound, successful canary summaries with rail, notary, and
receipt-verify stages in canary-runner order;
rejects forged canary summaries that carry both executed `stages` and
plan-only `planned_stages` branches before compacting stage evidence;
requires the canary summary to prove it was generated with
`--require-explicit-policy`;
requires the receipt-verify stage output to be digest-bound and contain
positive receipt counts, canonical sorted duplicate-free rail/notary
receipt-kind lists, canonical compact receipt entry order by receipt kind,
path, and digest, and top-level canary/trust compact summary order by path and
digest, and
per-receipt `receipt_sha256` and `response_body_sha256` entries with unique
receipt paths and unique receipt digests, explicit `ok=true` plus 2xx
`status_code` metadata on every receipt entry, kind-specific notary
anchor/index/count metadata or rail
message/profile/payload metadata whose rail message type is in the adapter
endpoint map, and explicit boolean receipt policy fields rather than omitted
defaults;
rejects timed-out stages, non-null successful-stage `reason` fields, truncated
child-process stdout/stderr previews, unsafe control-character or
identifier-style secret-looking preview content, and non-empty successful
stderr previews from every executed canary stage before
trusting the archived stage output;
requires timeout-bounded direct receipt archive verification from `--receipt` or
`--receipt-dir` before emitting an evidence summary, rejects successful direct
receipt-verifier stderr instead of dropping hidden diagnostics, and requires that direct archive's
`receipt_sha256` entries cover every canary receipt-summary digest with the same
receipt filename, receipt kind, successful status metadata, response-body
digest, endpoint-policy evidence, and kind-specific receipt metadata. Direct
archive coverage, kind, filename, metadata, and unreferenced-receipt
diagnostics report only receipt indexes and mismatch classes, not the raw
`receipt_sha256` values; the local canary-stage-only
diagnostic override is rejected
when any direct `--receipt` or `--receipt-dir` archive input is supplied, so
  direct replay evidence cannot carry that non-production policy bit; direct
  receipt verification rejects rail receipts that omitted
  an explicit profile unless `--allow-default-profile` is supplied, and that local
  override is preserved as an explicit receipt-summary policy flag; evidence
  replay must also name the configured `--default-rail-profile` so a
  `profile=null` rail receipt is checked against the same trust-coverage path
  as explicit profiles;
requires every supported `iso-rail-gateway` canary receipt profile, including
the configured default-profile fallback, to have matching compact trust material
for the same profile ID and environment before the archive is accepted;
built-in rail-named profiles must also bind to the same rail in the trust profile;
rejects plan-only, dry-run, insecure-HTTP,
default-profile, failed-receipt, retired `colr.007`, and missing-source-file
evidence; requires trust summaries produced without synthetic DER, record-only
policy, insecure provenance overrides, or malformed/future trust-source
retrieval timestamps, with trust-summary policy booleans present explicitly and
with profile override JSON actually emitted;
requires archived trust profile overrides to carry explicit CRL/OCSP revocation
policy booleans, unique canonical lowercase profile IDs, profile JSON digests,
and bundle digests across archived trust summaries, known rail IDs, matching profile/rail/policy
override identities, canonical OIDs, eight-entry-bounded canonical base64 DER
SEQUENCE blobs, override material counts, and CRL/OCSP DER material-class
checks plus digests and byte lengths that agree with the trust-bundle verifier
summary; and scans
archived commands/output for obvious secret leakage.
Plan-only diagnostic archives must still record each planned stage's `dry_run`
boolean, and that boolean must match the planned child command's `--dry-run`
flag. The evidence gate accepts `--allow-plan-only` only when at least one
archived canary summary records `plan_only=true`. Bearer-token arguments for
the notary stage and operator-private-key arguments for the rail
stage must be redacted in either separate-value or `--flag=<path>` form. Rail
commands containing the retired `--bearer-token-file` flag are rejected. Rail
commands must contain one canonical checksummed `--network-id` plus one redacted
`--operator-private-key-file`; missing values, a wrong checksum, a cleared Iroha
marker bit, duplicate flags, or an unredacted key path fail replay. The `--allow-*`
  flags, including
  `--allow-missing-record-sources`, `--allow-canary-stage-receipts-only`, and
  `--allow-profile-json-not-emitted`, are for local test audits only and should not
  be present in production evidence archives. Evidence summaries emitted with
  any non-production `allow_*` policy record `ok: false`, even when the local
  audit input is otherwise well formed; final readiness recomputes that
  top-level verdict from the archived evidence policy, emits
  `evidence.summary_ok_drift` for forged policy/verdict combinations, and
  preserves diagnostic policy flags as `"unsupported"` in normalized release
  output. The live rail and notary adapters
  reject unused local `--allow-insecure-http` and `--allow-default-profile`
  flags before dry-run summaries or network delivery,
  and the notary adapter rejects unused `--allow-missing-record-sources` unless
  at least one validated anchor actually lacks local record sources.
  The evidence gate also rejects
`--allow-partial-canary` unless at least one archived canary summary is missing
a rail or notary stage, rejects unused default-profile receipt overrides
unless compact rail receipts actually carry missing profile evidence, treats
stale `allow_legacy_colr007` receipt-summary fields as malformed input, and
rejects unused record-only/synthetic/missing-source trust
overrides unless compact trust summaries carry the corresponding diagnostic
trust material; compact record-only and insecure-source trust policy flags must
also bind to a non-production `embedded_signature_policy` or an `http://` or
local/private source URL in the same trust summary rather than a summary flag
alone. It also rejects
unused dry-run, failed-receipt, and
insecure-HTTP diagnostic overrides unless the archived canary command actually
targets HTTP or local/private routing, or the receipt summary or trust summary
actually carries that policy, and rejects unused receipt-source-missing
overrides unless a verified receipt summary records
`require_source_files=false`; failed-receipt policy must come from a receipt
summary with at least one failed receipt entry rather than planned command text
or a summary flag alone. Executed rail/notary child commands whose endpoint URL
needs insecure/local policy must carry `--allow-insecure-http` on that same
child command, and the captured receipt summary must carry
`endpoint_requires_insecure_http=true` for the matching compact receipt kind.
Executed rail commands that use `--allow-default-profile` must match compact
rail receipt evidence for a missing profile, and those compact receipt
conditions are rejected if the rail command omitted the corresponding flag; a
missing-profile receipt also requires an explicit `--default-rail-profile`
binding, and forged readiness summaries that preserve a fallback profile while
claiming `allow_default_profile=false` remain production blockers.
Executed canary stage names also bind to compact `receipt_kind` evidence:
rail/notary stages require matching `iso-rail-gateway` or `iso-audit-notary`
receipt kinds, and partial canary receipt summaries cannot include receipt kinds
for stages that were not present in the archived run or were recorded as
dry-run-only. Compact canary summaries now retain `stage_dry_run` booleans
aligned with `stage_names`, so readiness replay can reject stale producer
receipts attached to dry-run rail/notary stages. Direct receipt archive replay
uses the same binding: a dry-run producer may omit its own receipt kind, but
`--allow-dry-run` and `--allow-partial-canary` cannot mask a missing archive
receipt for any non-dry-run canary receipt digest, and final readiness replays
that digest binding from compact summaries rather than trusting the evidence
summary policy flags. The verify-stage
`--receipt-dir` list is scoped the same way for executed and plan-only canary
branches: every non-dry-run rail/notary receipt dir must be present, and extra
receipt dirs that do not belong to a recorded rail/notary stage are rejected;
direct `--receipt` files must likewise live under one of the recorded stage
receipt directories. Rail and notary stages must not share a receipt directory,
and the verify stage's own `receipt_dir` field must be null or omitted.
Verify-stage receipt selectors must also be unique and non-overlapping, so
duplicate `--receipt-dir` or `--receipt` values and direct receipt files already
covered by a selected receipt directory are rejected before receipt-verifier
stdout is trusted.
The canary runbook planner also fails before execution if generated non-dry-run
rail/notary receipts are not selected by the verify stage through
`include_stage_receipts=true` or explicit generated `verify.receipt_dirs`.
It also fails before execution when a rail/notary receipt directory overlaps
that stage's configured operator-key/notary-token path, when the operator key
overlaps the rail inbox, or when the notary token overlaps the audit-export root.
Selected generated receipt directories must use a matching verify policy: the
verify policy must carry the local overrides required by those producer commands,
such as `verify.allow_insecure_http` for rail/notary `allow_insecure_http` or
`verify.allow_default_profile` for rail `allow_default_profile`, and
`verify.require_source_files` must remain true.
Executed runbooks with `verify.enabled=false` record a skipped verify stage and
`ok=false`, so unverified non-plan canaries cannot be archived as successful
evidence.
The canary verify stage
must bind its recorded receipt-verifier command flags to the captured
receipt-verifier JSON policy booleans, so diagnostic policy cannot be hidden in
stdout or invented after execution. The production-readiness replay gate mirrors
those bindings for compact evidence summaries, so forged `allow_failed=true`,
retired `colr.007`, or default-profile policy flags without matching receipt
entries are reported as invalid diagnostic evidence, and a non-null
`policy.default_rail_profile` without `allow_default_profile=true` is reported
as an inconsistent evidence policy. Compact canary rail receipts with
`profile=null` are resolved through `policy.default_rail_profile` during
readiness replay, and missing or untrusted fallback profile material is reported
before the aggregate can pass. Even when local diagnostic
`--allow-insecure-http` replay is enabled, archived child-command URLs still
reject reserved documentation hosts and the checked-in `operator-canary.bank`
template suffix.

## Production Readiness Rollup

Use `scripts/iso_production_readiness.py` as the final offline release gate
after the XSD manifest preflight and operator evidence gate emit their
digest-bound summaries:

```bash
python3 scripts/iso_production_readiness.py \
  --xsd-summary run/iso/xsd-fixture-summary.json \
  --evidence-summary run/iso/local-provider-evidence.summary.json \
  --pending-xsd-probe-summary run/iso/pending-xsd-probe.summary.json \
  --provider banka-paynet \
  --environment preprod \
  --max-xsd-age-days 30 \
  --max-evidence-age-days 7 \
  --max-canary-age-days 1 \
  --max-trust-age-days 7 \
  --max-trust-source-age-days 7 \
  --summary-out run/iso/production-readiness.summary.json
```

The rollup exits `0` only when every supplied summary proves production posture.
The release command must name the expected `--provider` and `--environment`,
which are rechecked against canary and trust evidence instead of being inferred
from archived summaries. It must also name explicit freshness budgets for XSD
summaries, aggregate evidence summaries, canary `finished_at` timestamps, and
trust-summary `verified_at` timestamps, plus trust-source `retrieved_at`
timestamps captured by the evidence archive policy. Digest-correct but stale
inputs become production blockers instead of silently passing release posture.
If reviewed XSD gaps are allowed for a local audit and the XSD summary records
pending official ISO download sources, the rollup also requires
`--pending-xsd-probe-summary` evidence covering those message definitions.
Missing, stale, digest-mismatched, metadata-mismatched, or unreachable probe
evidence remains a blocker and still does not satisfy strict schema-backed
production closure. Any local final-readiness override remains a production
blocker in the aggregate verdict, so `ok: true` is reserved for evidence that
passes without `--allow-reviewed-xsd-gaps` or
`--allow-canary-stage-receipts-only`.
Input XSD summaries must also carry a production-complete `ok` verdict matching
the replayed strict flags, schema/profile counts, repository-manifest status,
and reviewed/pending gap lists; forged `ok` values are reported as
`xsd.summary_ok_drift`, and valid diagnostic XSD summaries remain blocked as
`xsd.summary_not_ok`.
The rollup also rechecks the digest-bound provider/environment and freshness
policy recorded by the evidence gate, rejects archive freshness budgets that
are weaker than the final release budgets, requires and revalidates each compact
trust profile's canonical lowercase profile ID, known rail ID, source
`authority`/`version`, source URL, and `retrieved_at` timestamp, rejects stale,
placeholder, or smuggled trust source provenance including separator-obfuscated
authority/version markers,
raw-whitespace and empty/zero/leading-zero/malformed-port URL smuggling plus non-canonical host spelling,
non-ASCII or invalid host labels, percent-host and percent-path smuggling including encoded
semicolon parameters and encoded URL delimiters, numeric-host
spoofing, repeated path separators, and path traversal, rejects omitted,
malformed, evidence-weaker, or release-weaker compact trust source freshness
budgets, rejects compact `profile_json_emittable` values that no longer match
the archived source provenance and freshness budget, rejects compact summaries
that report emitted profile JSON while not emittable, rejects compact
canary/trust summary paths,
canary config paths, receipt paths, and rail receipt `source_path` XML paths
with embedded whitespace, semicolon path
  parameters, leading dashes, leading-dash path segments, empty segments, raw
  backslashes, dot/parent traversal, or checked-in ISO fixture artifact
  coordinates, rejects repeated XSD/evidence
summary paths or copied summaries with the same `summary_sha256`, and rechecks
digest-bound XSD `schemas[]` and
`fixtures[]` arrays for canonical message-definition/path order, count consistency,
unique schema and fixture evidence
digests, cross-summary manifest and profile-catalog digest replay,
cross-summary manifest/schema/fixture/profile-catalog path replay, cross-summary
schema/fixture digest replay, and cross-summary schema/fixture/blocked-source
message-definition replay, cross-summary pending-source message-definition
replay, normalized blocked-source and pending-source evidence in canonical
message-definition/source-provenance order,
reviewed-source-to-current-gap consistency, plus blocked-source and
pending-source replay across repeated XSD summaries, blocked-source
redistribution marker strength, canonical relative schema paths whose filenames match
`message_def_id`, fixture paths that remain printable-ASCII relative
forward-slash XML paths no longer than 2048 characters and without leading
dashes, URI/drive prefixes, malformed or smuggled percent escapes, empty, dot,
or non-leading parent segments, schema `target_namespace` binding to
`message_def_id`, fixture schema-reference message-id and payload-root binding,
schema-backed/missing-schema consistency, and schema-backed fixture XML
schema-validation proof. It also rechecks archived schema/fixture XML
identifier strings with the same printable-ASCII, secret-looking-material, and
256-character caps as the direct XSD verifier, profile-catalog source digests,
version coverage counts, canonical profile ids, ISO family message types,
allowed directions, message-definition family binding, and missing-version
entries, canonical nested profile-catalog version/skipped-family order, plus
skipped family-version alias canonicality and profile-catalog
`profiles` count consistency against represented profile IDs. It also rejects
XSD summary, manifest, schema, fixture, blocked-source, and profile-catalog
digests that reuse evidence summary, receipt, canary, or trust material digest
roles, rejects XSD summary, manifest, schema, fixture, blocked-source, or
profile-catalog artifact paths replayed under another XSD material role or as
evidence summary, canary, trust, receipt, config, or bundle path material, and
rejects unknown
XSD summary fields across strict flags,
schema/fixture/gap/profile-catalog entries,
and the XSD preflight rejects unknown keys in source profile/message catalog
entries plus present-null optional manifest/profile fields before such fields
can reach the summary,
while readiness rejects archived XSD summaries that omit the emitted
`manifest` path or `profile_catalog` key; explicit `profile_catalog: null`
remains recorded diagnostic no-catalog evidence and cannot satisfy the strict
profile-schema-backed gate,
recomputes `profile_catalog.missing_schema_versions`, and cross-checks
schema-only flags and reviewed reasons against the schema/fixture relationship.
Reviewed `missing_schema_fixtures` and `schema_only_entries` must also match the
recomputed exact path, `message_def_id`, and reason tuples.
It blocks summaries that do not prove `--require-profile-schema-backed-versions`;
the direct XSD verifier uses the default profile catalog for that strict flag
when no override is supplied. The
rollup rechecks the direct receipt archive verification emitted by the evidence
gate from `--receipt` or `--receipt-dir`, not only the canary stage's captured
verifier stdout, and blocks digest-correct evidence summaries whose direct
archive receipt digests no longer cover the canary receipt-summary digests or
whose direct archive carries receipt digests that no canary references, or whose
canary entries relabel the archived receipt filename or kind, or drift from the
archived successful status, response-body digest, endpoint-policy evidence, or kind-specific receipt
metadata, while keeping the resulting blocker messages index-only and free of
raw `receipt_sha256` values. Final readiness also blocks compact receipt entries whose receipt,
response-body, notary anchor/index, or rail payload digests reuse another digest
role inside the same entry, and the evidence gate rejects the same role reuse in
receipt-verifier stdout before archiving compact evidence. Direct receipt
verification, evidence replay, and final readiness also require compact receipt
entries to stay in canonical receipt-kind/path/digest order, so digest-correct
receipt-summary reordering cannot satisfy release replay. Distinct canary summaries
must not reuse compact receipt paths or receipt digests. The evidence gate also
rejects rail/notary source paths or source digests replayed across distinct
canary summaries inside one aggregate evidence summary, and final readiness
aggregation blocks relabelled rail source XML path, payload-digest, or
`rail_message_id` replay within canary/archive receipt summaries while
preserving legitimate notary multi-endpoint publication of one anchor. Nullable
rail message IDs do not suppress the source XML path or payload-digest replay
checks, and final readiness blocks rail/notary
source-material replay across distinct evidence summaries even when the receipt
paths and receipt digests have been relabelled.
That
archive verification summary must carry its own
`summary_sha256`, production policy flags, and a `receipts[]` list binding each
unique canonical `*.receipt.json` path to its unique `receipt_sha256` and one
of the supported rail/notary receipt evidence kinds while preserving
`ok=true`, 2xx `status_code` success metadata, endpoint-policy evidence, and the corresponding
kind-specific notary or rail compact metadata. The direct receipt verifier
rejects unused local policy flags before that summary can be archived. Evidence
summaries that use the
local canary-stage-only diagnostic path must still record
`receipt_verification: null` and must retain
`policy.allow_canary_stage_receipts_only: true`; omitting the archive key or
forging the policy flag back to `false` remains a blocker even under local
readiness replay, the evidence gate rejects combining the policy flag with
direct receipt archive inputs, and the readiness policy flag is still blocked
when a forged direct receipt archive summary is present. XSD
strict-mode flags, evidence-level production policy flags, and nested
receipt-summary policy flags must all be present as booleans; evidence `ok`,
canary `plan_only`, and
per-canary `require_explicit_policy` status fields are also required booleans.
Direct evidence-gate and readiness `run(args)` calls reject non-boolean
production-policy flags before summary files are loaded, so programmatic callers
cannot use truthy strings or integers to enable diagnostic overrides.
Direct XSD fixture and trust-bundle `run(args)` calls also reject non-boolean
strict-mode or trust-policy flags before manifest or bundle files are loaded, so
truthy strings, integers, nulls, or containers cannot loosen fixture or trust
verification.
Direct operator-canary, rail-gateway, and audit-notary `run(args)` calls reject
non-boolean top-level policy flags before config, inbox, or export files are
loaded, so programmatic callers cannot use non-boolean values to alter plan-only
execution, anchor discovery, insecure HTTP, default-profile, legacy-message, or
missing-record-source behavior.
Direct repeatable path and endpoint `run(args)` arguments reject bare strings
and non-path/non-string entries before trust bundle, receipt, evidence,
readiness, or notary inputs are loaded, so programmatic callers cannot split
selector strings into character paths or endpoints.
Direct scalar path `run(args)` arguments normalize string/path-like values and
reject invalid path objects with label-only errors before XSD manifests, trust
bundles, canary configs, rail inboxes, audit exports, evidence summaries, or
readiness summaries are loaded, and direct rail gateway Torii URLs must be real
strings before URL validation or inbox loading. Direct evidence/readiness
provider/environment/default-profile context values must also be real strings
before summary loading. Missing direct `argparse.Namespace` attributes for
required ISO config/inbox/export paths, policy booleans, evidence/readiness
context strings, freshness budgets, canary output limits, rail payload limits,
and notary response limits now route through the same controlled validators
before file discovery, summary loading, network work, or child execution
instead of exposing raw `AttributeError`s; omitted optional trust source
freshness budgets and rail message selectors now take the same defaults as
their CLI forms.
Trust-summary verifier flags are enforced by the evidence gate before the rollup
accepts an archive, retained in the compact summary, and independently blocked
by readiness if a replayed summary still carries synthetic DER, record-only
policy, or insecure source-URL allowances. The rollup also rechecks compact trust-profile
`bundle_sha256`, bundle path identity, CRL/OCSP revocation booleans, material counts,
revoked and certificate-policy counts, compact DER proof shape, count binding, and
DER cross-role digest reuse, while the evidence gate now rejects bundle digests
that reuse compact DER material and duplicate bundle paths before archival. Direct trust-bundle verification,
profile-catalog validation, and operator evidence replay also reject public-key
pin digests that are reused as X.509 trust-anchor, trusted-certificate, or
revoked-certificate pin digests before profile overrides can become production
evidence, and reject trust pin digests that are reused as CRL or OCSP DER proof
digests. Final readiness also rechecks
profile-JSON/bundle digest role separation against compact DER material and each other, and
rejects compact canary/trust summary paths or `summary_sha256` values that
reuse each other or nested receipt-summary, receipt, receipt-material,
profile-JSON, bundle, or DER proof digests inside one aggregate evidence
summary or across multiple evidence summary inputs, including canary-summary
identities replayed as trust summary identities or trust material and
trust-summary identities replayed as receipt material, rejects compact
canary/trust summary paths that reuse canary config or trust-bundle material
paths inside one aggregate evidence summary or across multiple evidence-summary
inputs, while preserving
`verified_bundles` profile-count binding, canonical top-level canary/trust
summary order, and canonical `profile_id` order.
Omitted compact trust-profile
`source` keys remain malformed, while explicit `source: null` diagnostic replay
is retained and reported as `trust.source_missing` instead of aborting the
release report. Compact trust summaries must also
retain `profile_json_emitted=true`, `profile_json_emittable=true`, and a
lowercase `profile_json_sha256`; false values, missing or malformed profile JSON
digests, duplicated compact trust-profile IDs, duplicated bundle paths inside
one trust summary or across evidence-summary inputs, or duplicated bundle digests are
production blockers, copied profile JSON digests across relabelled compact trust
summaries or evidence summaries are replay blockers, all-zero compact trust
bundle, DER proof, or profile JSON digests are malformed placeholder evidence,
forged profile JSON digests that reuse bundle or DER proof digests and forged
bundle digests that reuse DER proof digests are production blockers, and
`profile_json_emittable` is recomputed from the compact source evidence
before the rollup is accepted.
The rollup also binds canary rail evidence to trust material by preserving each
rail receipt `source_path`,
blocking repository XML fixture sources, preserving notary receipt
`anchor_path`, `store_dir`, and `index_path` values in direct archive matching,
and requiring every `iso-rail-gateway` receipt profile exercised by a canary to
have a matching compact trust profile for the same profile ID and environment;
built-in rail-named profiles must also bind to the same rail in the trust
profile.
Evidence and readiness blockers for missing
trust coverage identify the canary receipt index without printing the compact
profile ID or canary environment label.
The rollup requires at least one XSD summary and at least
one evidence summary, and compact canary and trust summary entries must also
retain control-free, trim-free, leading-dash-free, traversal-free source paths
that point to `.json` files plus canonical nonzero lowercase `summary_sha256`
pointers;
nested canary, trust, archive-receipt, and
trust-profile material must not be replayed across distinct evidence summaries.
Canary-stage and direct-archive receipt-verifier summaries must also retain
their aggregate `ok` verdict. That verdict is true only when both production
receipt kinds are present, every receipt entry succeeded, source files were
required, and no local receipt override (`allow_failed`,
`allow_insecure_http`, or `allow_default_profile`) was used; evidence and final
readiness replay recompute the verdict and reject diagnostic or forged
summaries with receipt-summary-not-ok or receipt-summary-ok-drift blockers.
Compact canary entries also retain the validated
runbook `config_path`, which must remain control-free, trim-free, leading-dash-free, traversal-free, and point
to a `.json` file. Compact provider/environment, stage, receipt-kind,
and trust-profile identity strings also reject control characters and
surrounding whitespace instead of being trimmed. Unknown compact fields are malformed across evidence policy, canary,
stage-window, receipt-summary, receipt-entry, trust-summary, and trust-profile
objects. Compact trust summaries must retain timezone-aware, non-future
`verified_at` timestamps for the original trust-bundle preflight. Omitted inputs,
flags, or digest pointers are malformed, as are missing, timezone-less, or future
XSD/evidence/trust `verified_at` timestamps and malformed or reversed canary
`started_at`/`finished_at` windows. The canary runner also records per-stage
windows, and the evidence/readiness gates reject compact `stage_windows` when
they are missing for executed canaries, malformed, outside the canary window, or
name-mismatched; plan-only compact canaries must instead keep
`stage_windows: []` and explicitly recorded `receipt_summary: null`; omitting
that key is malformed replay input. This prevents forged plan-only evidence
from smuggling executed receipt evidence or execution windows. They also reject
reordered or overlapping stage windows and duplicate or unsupported compact
stage names, including compact stage-name sequences that do not follow
rail/notary/verify order. These conditions are malformed input, not implicit
production defaults. It exits `1` with a
digest-bound blocker report when summaries are valid but not production-ready,
and exits `2`
for malformed or digest-tampered inputs, including nested receipt-summary
tampering and stale `allow_legacy_colr007` fields. Canary summaries that do not
prove `--require-explicit-policy` are production blockers. Trust profiles that disable
CRL/OCSP revocation checks or carry zero required revocation material are also
production blockers, with blocker messages kept to role labels rather than
copying compact profile IDs. Compact trust profiles whose source authority/version still
contains template markers such as `dummy`, `fake`, `placeholder`,
`replace-before-production`, `sample`, or `template`, including
separator-obfuscated variants, or whose source URL still
points at reserved placeholder hosts such as `.example`, `example.com`,
`example.net`, `example.org`, or `example.invalid`, are production blockers even when the DER
material itself is real. Compact trust-source URLs also fail closed on overlong
URLs and DNS hosts instead of relying on downstream URL consumers.
`--allow-reviewed-xsd-gaps` and `--allow-canary-stage-receipts-only` exist for
local diagnostic audits of the current checked-in fixture corpus; production
release evidence should omit them and must make the strict XSD, profile-catalog,
and receipt-archive checks pass. The final readiness gate rejects those local
overrides when they are unused and also records a stable
`readiness.policy.*` blocker when they are used, so diagnostic rollups keep
`ok: false` even when all underlying evidence is well formed. The
`--allow-reviewed-xsd-gaps` override must correspond to at least one reviewed
missing-schema, schema-only, blocked-source, or pending-source XSD gap warning,
not just a repository fixture manifest or an unreviewed advertised
profile-version gap. It only downgrades profile-version gaps when the exact
message definition also has reviewed missing-schema, schema-only,
blocked-source, or pending-source evidence; repository fixture manifest blockers
are never downgraded out of the blocker set.
`--allow-canary-stage-receipts-only` must correspond to an evidence summary
with canary-stage-only receipt policy and missing direct receipt archive
verification.

## Gap Register

| Area | Current state | Target |
| --- | --- | --- |
| Rail connectivity | Local bridge endpoints plus `scripts/iso_rail_gateway_adapter.py`, an operator-side file-drop adapter that verifies sidecar-pinned message type/profile/payload digest and rejects unsupported rail message types, duplicate payload digests, or duplicate rail message ids before submitting to Torii and writing receipts outside consensus-critical code; `colr.012` is the first-release runtime collateral-substitution endpoint and retired `colr.007` receipts/summary fields are unsupported with no override; first-release production evidence only treats schema-backed default rail families as trust-covered until official lifecycle XSD/default-profile coverage is added; `scripts/iso_operator_receipt_verify.py` gates the resulting receipts, `scripts/iso_operator_canary.py` ties the adapter plus verifier into a reproducible provider runbook, `scripts/iso_operator_evidence_verify.py` rejects non-production archived summaries and canary/archive rail receipts whose message family is not covered by the matched trust profile rail, `scripts/iso_production_readiness.py` aggregates accepted summaries into one release gate and replays the same rail/message-family trust check, and checked-in Swift/Fedwire/SEPA/CSD templates plan successfully without network access | Run provider-specific live gateway canaries for selected SWIFT/Fedwire/SEPA/CSD operators and archive evidence summaries that pass the production-readiness gate |
| XMLDSig/XAdES | Supported P-256/SHA-256 enveloped subset is verified against profile public-key, leaf-certificate, and linked certificate-chain pins with non-CA XMLDSig leaf certificates carrying critical `keyUsage`/`digitalSignature`, deterministic child issuer distinguished-name binding to parent subject distinguished names, bounded duplicate-free `X509Data` certificate chains, certificate-chain ECDSA-with-SHA256/id-ecPublicKey-secp256r1 enforcement, critical issuer CA `basicConstraints` and `keyUsage`/`keyCertSign`, issuer path-length constraint enforcement, rejection for unknown, malformed, or unsupported parsed critical X.509 extensions, extension/validity checks against verified signed XAdES `SigningTime` or BAH `CreDt`, explicit certificate revocation pins, low-S fixed-width `r || s` or low-S DER ECDSA signature values, one empty or unique same-document `#id` payload Reference URI that strictly encloses the verified signature carrier with an enveloped-signature transform first, at most one final supported C14N transform, one optional XAdES `SignedProperties` Reference with a local `#id`, `QualifyingProperties` target bound to the enclosing `Signature` `Id`, exactly one supported bare `Signature` or direct-child `Sgntr`/`Signature` carrier, ordered direct `Signature`/`SignedInfo` child parsing, prefixed XMLDSig structure bound to the XMLDSig namespace, prefixed XAdES structure bound to the ETSI XAdES v1.3.2 namespace, exact QName opening/closing tag matching in supported XML spans, malformed structural QName rejection, direct `Signature/Object/QualifyingProperties/SignedProperties/SignedSignatureProperties` XAdES parsing, certificate-backed `SigningCertificateV2` ordered duplicate-free chain-prefix digest binding with direct `Cert`/`CertDigest` children only, no unreferenced, wrapped, or duplicate `SignedProperties` elements, parameter-free XMLDSig method/transform elements with exact-one critical methods, exact-name method/digest/Reference policy attribute lookup, exact-one attribute-free `Transforms` wrappers, implemented ordinary attributes only, and ordered direct `Reference` children, singleton required base64 values, unambiguous public-key-or-certificate key material scoped to exactly one structured `KeyInfo`, inherited namespace context for referenced roots, a fail-closed supported canonical XML subset for empty-element expansion, simple attribute normalization, namespace-aware attribute sorting, implicit `xml:` namespace attributes, legal `xmlns:xml` declaration omission, XML-character-reference decoding, no-comments C14N comment omission, and C14N-mode-specific root namespace declarations inherited from the enclosing `Signature`; `scripts/iso_trust_bundle_verify.py` preflights operator trust bundles, `scripts/iso_operator_evidence_verify.py` rejects synthetic/record-only trust summaries for production archives, `scripts/iso_production_readiness.py` rechecks production trust posture in the release rollup, and checked-in Swift/Fedwire/SEPA/CSD templates validate schema and emitted trust overrides | Replace synthetic trust-bundle templates with official profile-specific trust-anchor packages, add complete official canonical XML fixture coverage, add official CRL/OCSP or rail revocation-feed fixtures, and archive evidence summaries that pass the production-readiness gate |
| Follow-up messages | Inbound `pacs.002`, `pacs.004`, `camt.056`, `sese.023`, `sese.024`, `sese.025`, and `colr.012` lifecycle endpoints record durable messages, reject replay evidence, and update known referenced originals only; checked-in payment, securities, and collateral XML fixtures cover runtime parser/profile/lifecycle handling, while the production XSD manifest is first-release scoped to schema-backed payment/cash-management fixtures; the offline MDR/XSD fixture matrix now includes standalone fixtures for every checked-in production XSD, including `pacs.008.001.08`, `pacs.009.001.08`, `pacs.002.001.10`, `pacs.004.001.09`, `pacs.004.001.10`, `camt.056.001.08`, and `camt.056.001.09`; `scripts/iso_xsd_fixture_verify.py` prevents silent XSD/XML fixture namespace and payload-root drift while preserving reviewed-gap replay coverage for future schema additions | Add remaining redistributable official MDR/XSD lifecycle fixtures before expanding default profiles, and add live-rail gateway adapter coverage |
| Return/cancel lifecycle | Durable outbox helpers exist for `pacs.004`, `camt.029`, `sese.024`, and `sese.025`; known-original return and cancellation transitions have focused Torii coverage plus checked-in `pacs.004` and `camt.056` XML fixtures; full `pacs.004.001.09`, `pacs.004.001.10`, `camt.056.001.08`, and `camt.056.001.09` XSD fixtures now pin live-profile return/cancellation admission where the default rail profiles allow those versions | Add remaining official rail/profile return and cancellation fixture packs |
| Securities crosswalks | Reference snapshots load locally and live securities profile admission validates instrument, active venue MIC, delivering/receiving BIC lookups, configured CSD venue domain, delivering/receiving settlement-account mappings, and securities cash-leg asset mapping before durable lifecycle recording | Keep operator snapshots current and add live-rail adapter coverage around production CSD/account/cash-leg sources |
| Profile catalog | Static defaults plus config overrides; the embedded first-release defaults advertise only schema-backed concrete versions, and the XSD preflight reports `31` checked profile versions with `31` schema-backed | Add fixture coverage against official MDR/XSD releases before adding more concrete versions to default profiles |
| Persistence | Versioned, digest-bound local V2 JSON records and replay tombstones plus a deterministic local V2 audit index; any malformed, legacy, tampered, schema-incomplete, filename-mismatched, conflicting, symlinked, or oversized stored identity stops startup without silently dropping records or regenerating over the evidence. Existing audit indexes are strictly shape/digest/order checked, locally written atomically with a 32 MiB cap, and a missing or valid-stale derived index is regenerated only after the complete record store validates. Oversized runtime records are not written as durable files or audit-index entries, symlinked durable-output directories are not followed, the current manifest is exposed through `GET /v1/iso20022/audit/messages`, configured age/count retention preserves live replay identities while compacting replay-expired details, `audit_export_dir` mirrors digest-bound manifest/notary preimages to an operator-managed external spool, and the operator verification/readiness scripts gate publication and archived evidence | Run provider-specific production canaries against the selected archival/notary vendors and archive evidence summaries that pass the production-readiness gate |

## Public Interface Notes

- Submission/status endpoints:
  - `POST /v1/iso20022/pacs008`
  - `POST /v1/iso20022/pacs009`
  - `POST /v1/iso20022/pacs002`
  - `POST /v1/iso20022/pacs004`
  - `POST /v1/iso20022/camt056`
  - `POST /v1/iso20022/sese023`
  - `POST /v1/iso20022/sese024`
  - `POST /v1/iso20022/sese025`
  - `POST /v1/iso20022/colr012`
  - `GET /v1/iso20022/messages/{msg_id}`
- New/readable endpoints:
  - `GET /v1/iso20022/messages/{msg_id}`
  - `GET /v1/iso20022/audit/messages`
  - `GET /v1/iso20022/messages/{msg_id}/pacs002`
- Submission responses and status records now include `profile_id`,
  `message_type`, `business_service`, `business_message_id`, `uetr`,
  `payload_hash`, `reference_snapshot_id`, `embedded_signature_detected`, and
  `status_history`, plus lifecycle-family context such as securities settlement
  fields and collateral substitution fields when present.

[^iso_catalogue]: ISO 20022 Catalogue of messages. https://www.iso20022.org/catalogue-messages
[^swift_cbpr]: Swift, "ISO 20022: A new era for global payments", 25 November 2025. https://www.swift.com/news-events/news/iso-20022-new-era-global-payments
[^fedwire_iso]: Federal Reserve Financial Services, "Fedwire Funds Service Completes ISO 20022 Migration", 16 July 2025. https://www.frbservices.org/news/fed360/issues/071625/wires-iso-20022-implementation-complete-fedwire-funds-service
[^cpmi_harmonisation]: BIS CPMI, "Harmonised ISO 20022 data requirements for enhancing cross-border payments - updated report", 26 February 2026. https://www.bis.org/cpmi/publ/d230.htm
