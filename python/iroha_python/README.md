# Iroha Python SDK

`iroha-python` packages the client-side utilities Python developers need for
the first Hyperledger Iroha 3 release. It bundles Norito codecs, Torii client
helpers, typed builders, and cryptographic primitives aligned with the Rust
implementation. See [`DESIGN.md`](DESIGN.md) for the package architecture and
the [Python tutorial](https://docs.iroha.tech/guide/tutorials/python.html) for
public integration guidance.

The pure `iroha-python` wheel depends on the separate `iroha-native` wheel,
whose `iroha_native._crypto` extension owns all cryptographic identity admission.
Account constructors and exact I105 parsers require ABI 30 and preserve all eleven
key algorithms and complete weighted multisig policies. `AccountId` is always
domainless. Missing native validation fails explicitly, and canonical parsers
reject surrounding whitespace.

## Quickstart

Build and install the package from the same Iroha source revision as the node
you target:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r python/iroha_python/requirements-ci.lock
cd python/iroha_native
IROHA_PYTHON_SKIP_RUNTIME_LINK=1 maturin build --release --out ../../dist/python-native
cd ../..
python -m pip wheel --no-build-isolation --no-deps python/iroha_python -w dist/python-sdk
python -m pip install dist/python-native/*.whl dist/python-sdk/*.whl
```

```python
from iroha_python import (
    Instruction,
    NetworkId,
    ToriiClient,
    authority_fee_payment,
    derive_ed25519_keypair_from_seed,
)

pair = derive_ed25519_keypair_from_seed(b"demo-seed")
authority = pair.account_id()  # Canonical domainless I105 account id
network_id = NetworkId.parse(
    "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"
)

with ToriiClient("http://127.0.0.1:8080", auth_token="dev-token") as client:
    envelope, final = client.build_and_submit_transaction(
        network_id=network_id,
        authority=authority,
        private_key=pair.private_key,
        fee_payment=authority_fee_payment(charge_limits=[]),
        instructions=[Instruction.register_domain("wonderland")],
        wait=True,
    )

# `wait=True` returns only after the transaction is authoritatively applied;
# a rejected or expired transaction raises `TransactionStatusError`.
assert final["status"]["kind"] == "Applied"

# Config-aware client creation

import json
from iroha_python import create_torii_client, resolve_torii_client_config

with open("iroha_config.json", "r", encoding="utf-8") as handle:
    raw_config = json.load(handle)

resolved = resolve_torii_client_config(
    config=raw_config,
    overrides={"timeout_ms": 2_000, "max_retries": 5},
)
client = create_torii_client(
    raw_config.get("torii", {}).get("address", "http://127.0.0.1:8080"),
    resolved_config=resolved,
)
```

### First-release defaults

- Torii base URLs are origins, request paths stay on that origin, and redirects
  are disabled. Automatic retries are limited to idempotent methods by default;
  mutation helpers dispatch once.
- A client owns and closes only the HTTP session it creates. Prefer the context
  manager form shown above. Caller-supplied sessions remain caller-owned.
- Public configuration and network-time reads return validated dataclasses from
  their unsuffixed method names. There are no duplicate raw/`*_typed` variants
  for those routes; use the generic transport only when raw JSON is truly
  required.
- Resolved configuration and transaction configuration snapshot mutable inputs.
  Authentication tokens and private key material are omitted from object
  representations, and private keys require exact immutable bytes or canonical
  lowercase hex.
- The wheel ships a `py.typed` marker, so type checkers consume the SDK's inline
  annotations without extra stub packages.

Account onboarding uses a dedicated credential in addition to any global
`X-API-Token`. V1 is explicitly plan, prepare, then exact submit; there is no
one-shot mutation request. Retain the prepared envelope before submission so a
lost response can be reconciled against the exact retained transaction hash;
an ambiguous submit must not create a second submission attempt. A
proof-required current-state read takes explicit runtime-only canonical request
authentication so it also works for restricted dataspaces.

```python
plan = client.plan_account_onboarding(
    onboarding_token=route_token,
    alias="alice@universal",
    account_id=canonical_domainless_account_id,
    expected_authority=configured_onboarding_authority,
    network_id=network_id,
)
onboarding_request = {
    "version": 1,
    "alias": "alice@universal",
    "account_id": canonical_domainless_account_id,
    "permissions": [],
}  # persist this complete intent with the receipt
receipt = plan.json()
prepared_response = client.prepare_account_onboarding(
    onboarding_token=route_token,
    binding=public_reset_binding,
    receipt=receipt,
    expected_request=onboarding_request,
    expected_authority=configured_onboarding_authority,
    network_id=network_id,
)
prepared = prepared_response.json()  # persist before any mutating request
if prepared["schema"] == "iroha.accounts.onboard.prepare-proof-required.v1":
    # Authenticated but nonterminal. This one atomic snapshot must be read again
    # after every durable reopen; the ProofRequired bytes alone never prove success.
    current = client.prove_account_onboarding_current_state(
        proof_required=prepared,
        binding=public_reset_binding,
        receipt=receipt,
        expected_request=onboarding_request,
        expected_authority=configured_onboarding_authority,
        network_id=network_id,
        canonical_auth=application_canonical_auth,
    )
    if current.kind != "Applied":
        raise RuntimeError(f"onboarding remains nonterminal: {current.kind}")
else:
    response = client.submit_prepared_account_onboarding(
        onboarding_token=route_token,
        prepared=prepared,
        expected_request=onboarding_request,
        expected_authority=configured_onboarding_authority,
        network_id=network_id,
    )
```

## Collection queries

Every Torii collection is read with one query language
([`specs/torii/collection_queries.md`](../../specs/torii/collection_queries.md))
through one client surface: `client.domains`, `client.accounts`,
`client.asset_definitions`, `client.nfts`, `client.rwas`,
`client.transactions`, `client.repo_agreements`, `client.subscription_plans`,
`client.subscriptions`, `client.contract_activity`, `client.contract_events`,
`client.uaid_manifests(uaid)`, and the nested
`client.accounts.assets(account_id)`, `client.accounts.transactions(account_id)`,
`client.accounts.permissions(account_id)`, `client.accounts.history(account_id)`
and `client.asset_definitions.holders(definition_id)`. Each collection offers
`list` (one typed page), `iter` (every row, following `next_cursor`), `pages`,
`rows`/`iter_rows` (JSON objects; the calls that accept `select` and
`aggregate`) and `count`. Requests are signed when `canonical_request_auth` is
configured (a signature only widens visibility into restricted dataspaces) and
are anonymous otherwise.

Explorer uses the same surface through `client.explorer_accounts`,
`client.explorer_domains`, `client.explorer_asset_definitions`,
`client.explorer_assets`, `client.explorer_nfts`, `client.explorer_rwas`,
`client.explorer_blocks`, `client.explorer_transactions`,
`client.explorer_latest_transactions`, `client.explorer_instructions` and
`client.explorer_latest_instructions`. Explorer and history collections have a
fixed server order and reject `sort`, `include_total=True` and `aggregate`.
An empty page may carry a continuation cursor; the iterators follow it.

```python
from decimal import Decimal

from iroha_python import F, ListQuery, ListQueryError, ToriiClient, ToriiError

with ToriiClient("https://taira.sora.org") as client:
    # One page: build filters with F and Python operators (parenthesize comparisons).
    query = ListQuery(
        filter=(F.owned_by == owner) & F.metadata.tier.in_(1, 2),
        sort=["-alias_binding.bound_at_ms", "id"],   # "-field" sorts descending
        limit=50,
    )
    page = client.asset_definitions.list(query)
    for definition in page.items:
        print(definition.id, definition.alias)
    if page.has_more:  # a cursor only continues the query that produced it
        page = client.asset_definitions.list(query.next_page(page))

    # Every row, lazily, page by page; quantities are exact Decimal values.
    total = sum(bucket.quantity for bucket in client.accounts.assets(owner).iter(
        filter=F.quantity > Decimal("0"),
    ))

    # Text filters are accepted unchanged; Torii explains what is wrong.
    try:
        client.accounts.list(filter='owned_by == "x" && quantity > 1')
    except ListQueryError as error:            # client-side or HTTP 400 invalid_* errors
        print(error.code, error.parameter, error)
    except ToriiError as error:                # any other status: .status, .code, .details
        print(error.status, error.code)

    # Live events use the same grammar over event fields and decode to typed records.
    for event in client.stream_events(
        filter=(F.tx_hash == tx_hash) & F.tx_status.in_("Approved", "Rejected"),
    ):
        print(event.status, event.rejection_code)   # a TransactionEvent
        break
```

`filter.to_text()` is the canonical text form (`str(filter)` renders the same
text for display) and `filter.to_json()` the JSON form; `parse_filter(text)`
turns text into a `Filter`. Integers that fit `u64`/`i64` are JSON numbers,
decimals and wider integers are exact decimal strings, and `float` literals
are rejected. Object and array literals (`F.metadata.tags == ["a", "b"]`,
valid only against `metadata.<key>`) exist only in the JSON form: collection
queries send every `Filter` as JSON, while `to_text()`, `GET` parameters
(`ListQuery.to_query_pairs()`) and `stream_events` reject them with
`FilterError`/`invalid_filter`. Rows decode the fields that identify them
strictly (`id`; `account_id`, `asset`, `scope` and `quantity` for balances;
`entrypoint_hash`, `block_height` and `block_index` for transactions); every
other field may be null or absent and decodes as `None`.

Torii executes each collection query once over the caller-visible global state.
For collections that support totals and `POST` aggregates, visible rows contribute
exactly once even when they span several dataspace routes.

### Transaction history

`client.transactions` (every committed transaction) and
`client.accounts.transactions(account_id)` (transactions the account signed or
that reference it) are history collections of `CommittedTransaction` rows
(`entrypoint_hash`, `block_height`, `block_index`, `block_hash`, `authority`,
`timestamp_ms`, `entrypoint_kind`, `result_ok`, `asset_ids`,
`asset_definition_ids`, `metadata`):

- Rows come newest first by (`block_height`, `block_index`); cursors hold
  block coordinates, so transactions committed while paging never shift later
  pages.
- `sort`, `include_total` and `aggregate` would scan the whole history and are
  rejected before any request with `invalid_sort`, `invalid_include_total` and
  `invalid_aggregate`.
- Each page has a bounded scan budget, so a selective filter can return fewer
  than `limit` rows, even none, together with a `next_cursor`. `iter`,
  `pages`, `iter_rows` and `count` follow `next_cursor` until it is null; a
  short or empty page is not the end.
- `asset_ids` and `asset_definition_ids` match element-wise:
  `F.asset_definition_ids == definition_id` selects transactions that touched
  the definition.
- Bounds on `block_height` in the filter's top-level `and` also bound the
  server's scan: `(F.block_height >= 1200) & (F.result_ok == True)` reads only
  heights from 1200 up.

```python
for tx in client.accounts.transactions(owner).iter(
    filter=(F.block_height >= 1200) & (F.asset_definition_ids == definition_id),
):
    print(tx.block_height, tx.block_index, tx.entrypoint_hash, tx.result_ok)
```

## Exact Kotodama numbers

`KotodamaInt`, `KotodamaDecimal`, and `KotodamaQuantity` implement the
first-release Numeric V1 contract without host floating point. JSON boundaries
use canonical strings; `NumericV1Codec` also encodes and validates the
schema-bound Norito frames and pointer envelopes used by the IVM ABI.

```python
from iroha_python import KotodamaDecimal, KotodamaQuantity, NumericV1Codec

price = KotodamaDecimal("12.500")
quantity = NumericV1Codec.decode_quantity_json("3.25")
payload = NumericV1Codec.encode_quantity_envelope(quantity)

assert str(price) == "12.5"
assert NumericV1Codec.decode_quantity_envelope(payload) == KotodamaQuantity(
    "3.25"
)
```

`NumericV1Codec` rejects Python `float` and `decimal.Decimal` inputs. Use exact
strings or, for component construction, an arbitrary-precision integer
mantissa plus an explicit scale. Higher-level ledger helpers additionally
accept `Decimal` because it is a lossless host value and normalize it before
calling the codec.

## Petal Stream optical transport

Peer messages and other bounded payloads can travel over Petal Stream, the
animated Sakura-storm optical transport. Its stream encoder, renderer, camera decoder
and scan session live in the separate pure-standard-library package
[`iroha-petal`](../iroha_petal/README.md) (`python/iroha_petal`), which
`iroha_python` does not import.


## Native Privacy Bridge

The first-release native surface exposes local build metadata only:
`is_privacy_native_available()` and
`privacy_compiled_profile_catalog_v1()`. The latter returns this binary's
canonical Norito `PrivacyCompiledProfileCatalogV1` archive and contains no
committed height, governance activation, or readiness state. The distinct
`ToriiClient.privacy_capabilities_v1(canonical_auth=...)` method fetches the exact
canonical Norito `PrivacyExact12CapabilityManifestV1` through authenticated HTTPS
for its immutable local signing network. Native validation verifies the release
and deployment evidence before retaining a private origin and network binding.
Public `privacy_exact12_capability_manifest_v1(archive)` decoding is inspection-only;
re-decoding archived bytes cannot mint transaction admission. Both the draft and
native transaction builder reject missing origin or a different network. There is no
local `privacy_capabilities_v1()` alias, generic request/build/verify
dispatcher, or legacy algorithm alias.

The retained X509 preparation path checks the resolved intent-bound statement against
the effective governed activation and current consensus limits. Signing checks the
complete candidate envelope, proof size, and action size before using the signing key.
These checks do not enable an unavailable native engine or replace release qualification.

`PRIVACY_PROTOCOL_IDS_V1` contains exactly twelve identities in wire order:
`zk-ace-pq-authorization-v1`, `anonymous-pgc-k-out-of-n-v1`,
`verange-transparent-range-v1`, `iroha-zk-ams-v1`,
`vega-existing-credential-zk-v1`, `iroha-zk-x509-stark-p256-v1`,
`iroha-jindo-polynomial-commitment-v1`,
`iroha-bootle-lantern-anoncred-v1`, `orchard-halo2-actions-v1`,
`monero-fcmp-plus-plus-v1`, `iroha-ivm-private-note-stark-v1`, and
`pq-masp-stark-v1`. The parser rejects unknown fields, duplicate JSON keys,
non-finite numbers in native inspection projections, aliases, reordered or duplicate
rows, normalized labels, and malformed nested policy or profile data.

The eleven generic privacy protocols are constructed only by the admitted
Rust `iroha_privacy_wallet_worker`. `PrivacyWalletWorkerControllerV1` is the
top-level Python controller: it sends an owner-only credential path to Rust,
then uses only an opaque handle plus canonical public intent and execution-plan
bytes. Python and PyO3 expose no generic owner-bundle, witness, polynomial,
blinding, or secret constructor. ZK-X509 retains its separate authenticated
profile-owned transport.

Atomic private settlement uses a purpose-separated command family on that
same authenticated process boundary. Call
`import_private_settlement_credential()` with an owner-only native `APWB`
file, then `prove_private_settlement()` with only canonical public Norito
manifest, fixed-shape statement, encrypted audit capsule, governed audit
policy, genesis hash, authoritative height, and the public successor root from
the wallet's authenticated accumulator view. Rust derives the complete
fixed-shape delta after self-verifying the proof. Python receives only canonical
Norito statement, proof, delta, encrypted capsule, and binding digests; note
spending secrets, audit plaintext, and membership paths are decoded and wiped
in Rust and never cross the Python API or worker pipe. Settlement handles
occupy a separate opaque namespace and are consumed even when terminal native
proving fails.

Reserve-backed ZK-ACE, Orchard, and private-IVM actions always bind one exact
transparent balance bucket. Their worker-owned public action requires
`public_balance_scope`; its only accepted spellings are
`"global"` and `"dataspace:<id>"`, where `<id>` is a canonical positive decimal
`u64`. Dataspace zero is the universal coordinator route and is never a balance
partition. Whitespace, case variants, leading zeroes, aliases, and unknown JSON
fields fail before proving. Authenticated inspection returns
`public_balance_scope` in that same canonical spelling.

### Exact12 typed fixture bundles

`PrivacyExact12FixtureCodecV1` is the native-independent strict codec for
`fixtures/privacy/exact12_typed_fixture_bundle_v1.norito.b64`. It validates the
outer Norito frame and canonical Base64, bounded compact lengths and row order,
and every nested statement, proof envelope, submission instruction, intent
projection, unsigned payload, signed payload, and pipeline-hash binding. The
decoded models are frozen and snapshot mutable byte inputs.

```python
from pathlib import Path
from iroha_python import PrivacyExact12FixtureCodecV1

fixture_text = Path(
    "fixtures/privacy/exact12_typed_fixture_bundle_v1.norito.b64"
).read_text(encoding="ascii")
bundle = PrivacyExact12FixtureCodecV1.decode_canonical_base64_file(fixture_text)
assert PrivacyExact12FixtureCodecV1.encode_canonical_base64(bundle) == fixture_text[:-1]
```

Structural validation cannot authenticate a different well-formed signature
or opaque native proof. At release and test boundaries, call
`PrivacyExact12FixtureCodecV1.require_trusted_canonical(candidate, trusted)`
with an independently supplied Rust-derived archive; it validates both inputs
and then requires constant-time byte identity.

## Account addresses

The `iroha_python.address` module mirrors the Rust codecs so applications can
round-trip canonical bytes and canonical I105 account literals without bespoke conversions:

```python
from iroha_python.address import AccountAddress

# Account IDs are domainless; domain context belongs in aliases and other
# domain-owned state.
public_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
address = AccountAddress.from_account(public_key=public_key)
print(address.canonical_hex())
print(address.to_i105(753))

formats = address.display_formats(753)
print(formats["i105"])
print(formats["chain_discriminant"])
print(formats["i105_warning"])
```

> ℹ️ Use i105 literals consistently across SDK samples and operator tooling.
> For Sora network discriminant `753`, literals should start with the `sora` sentinel.

## Ledger reads and faucet bootstrap

`ToriiClient` includes convenience helpers for common ledger reads so
applications do not need to duplicate Torii pagination or account-asset
matching logic:

Caller-supplied IDs are sent only to their exact URL-encoded REST routes. The
client never substitutes a network prefix and never retries an alternate ID.
`find_account` and `account_exists` use only that exact account route. A `404`
reports absence; every other failure, including route unavailability or a
wrong-network-prefix rejection, propagates without fallback.
`asset_balance(account_id, definition, scope=None)` sums the exact quantities
of every matching balance bucket across all pages of the account-assets
collection (filtering on `asset` for Base58 definition ids and on
`asset_alias` for `name#domain.dataspace` aliases); pass `scope` to read one
bucket.

```python
from iroha_python import ToriiClient, account_faucet_claim_hash_v1, authority_fee_payment

client = ToriiClient("https://taira.sora.org")
account_id = "testuﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV"

exists = client.account_exists(account_id)
balance = client.asset_balance(account_id, "ds#wonderland.is")
definition = client.get_asset_definition("ds#wonderland.is")

puzzle = client.get_account_faucet_puzzle()
anchor_height, nonce_hex = ToriiClient.solve_account_faucet_pow(account_id, puzzle)
public_reset_binding = {
    **public_reset_binding,
    "semantic_hash_hex": account_faucet_claim_hash_v1(
        account_id, pow_anchor_height=anchor_height, pow_nonce_hex=nonce_hex
    ),
}
prepared_response = client.prepare_account_faucet(
    account_id,
    binding=public_reset_binding,
    fee_payment=selected_fee_payment,
    expected_asset_definition_id=configured_faucet_asset_definition_id,
    expected_amount=configured_faucet_amount,
    expected_authority=configured_faucet_authority,
    network_id=network_id,
    pow_anchor_height=anchor_height,
    pow_nonce_hex=nonce_hex,
)
prepared = prepared_response.json()  # persist before the mutating request
response = client.submit_prepared_account_faucet(
    prepared,
    expected_fee_payment=selected_fee_payment,
    expected_asset_definition_id=configured_faucet_asset_definition_id,
    expected_amount=configured_faucet_amount,
    expected_authority=configured_faucet_authority,
    network_id=network_id,
)
```

Load `configured_faucet_asset_definition_id` and `configured_faucet_amount`
from independent trusted configuration, never from the prepared response. Both
values are mandatory on prepare and submit, and the amount must be a canonical
positive quantity string.

Use `client.validate_prepared_account_faucet(prepared, ...)` with the same
independent fee, asset, amount, authority and network pins to authenticate and
copy a retained preparation without sending an HTTP request. Persist its exact
signed wire and transaction hash before submitting. After a lost submit response,
`allow_expired_for_recovery=True` permits authentication after the binding expires
so the original transaction's status and committed record can be recovered. It
does not refresh the preparation or authorize resubmission: submit always checks
an active binding again. Never solve another puzzle to replace an uncertain claim.

Compute the binding's `semantic_hash_hex` after solving PoW with
`account_faucet_claim_hash_v1`, then pass that exact solved claim to
`prepare_account_faucet`. The helper uses the same validated native claim and
Norito digest as prepared-transaction verification. It hashes the claim; Torii
still verifies that the nonce satisfies the current faucet puzzle.

The first-release faucet claim carries `pow_anchor_height` as a direct positive
integer and `pow_nonce_hex` as 1–32 bytes of canonical lowercase hexadecimal.
Neither field accepts `null`, and signed transcripts use those direct values
without optional-value wrappers.

Faucet puzzles use the first-release `scrypt-leading-zero-bits-v1` algorithm
and `iroha:accounts:faucet:pow:v1` challenge domain with mandatory positive
difficulty. The solver parses the puzzle's canonical checksummed `network_id`
as a typed `NetworkId` and hashes its raw 32 bytes into the challenge before
the exact canonical I105 account id and anchor, so a solution cannot be replayed
against a same-label network with a different genesis. It rejects non-integer
or oversized scrypt controls before hashing, caps ROMix memory at 64 MiB and
parallelization at 16, and accepts only the exact V1 puzzle fields. Pre-release
labels are rejected.

The same client owns the PoC-facing Torii application helpers for contract,
SNS, and ZK bootstrap flows:

```python
call = client.call_contract_and_wait(
    authority="adult@is",
    private_key="<multihash-private-key>",
    contract_alias="boi-lock::is",
    entrypoint="create_lock",
    payload={"amount": "10"},
    fee_payment=authority_fee_payment(
        # The app endpoint quotes this exact draft and replaces only the
        # charge maxima before signing.
        charge_limits=[],
        gas_limit=1_500_000,
    ),
)

policy = client.get_sns_policy(2)
registration = client.get_sns_name("domain", "wonderland.is")
vk_active = client.zk_verifying_key_active("halo2/ipa", "vk_transfer")
```

Contract deployment is performed by locally signing the native code-upload,
manifest-registration, and atomic `CommitContractDeployment` instructions;
the client does not expose a server-side deployment wrapper.

Binding-only IVM verifier labels are retired and rejected. Production proof-backed IVM invocation remains closed until the complete native execution relation and finalized State authority are implemented and qualified.

Verifying-key register/update helpers validate production backends, the
required `authority`, height ranges, and inline verifier-key commitments before
requesting an unsigned transaction draft from Torii:

```python
from iroha_python import LocalSigningContext, NetworkId, ToriiClient

network_id = NetworkId.parse(
    "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"
)

signing_client = ToriiClient(
    "https://taira.sora.org",
    # Immutable local-signing context. Read-only clients may omit this.
    local_signing_context=LocalSigningContext(network_id),
)

register_draft = signing_client.register_zk_verifying_key({
    "authority": "<canonical-i105-account-id>",
    "backend": "halo2/ipa",
    "name": "vk_transfer",
    "version": 1,
    "circuit_id": "halo2/ipa::transfer_v1",
    "public_inputs_schema_hash_hex": "a" * 64,
    "gas_schedule_id": "halo2_default",
    "vk_bytes": "AQID",
    "status": "Active",
})

update_draft = signing_client.update_zk_verifying_key({
    "authority": "<canonical-i105-account-id>",
    "backend": "halo2/ipa",
    "name": "vk_transfer",
    "version": 2,
    "circuit_id": "halo2/ipa::transfer_v1",
    "public_inputs_schema_hash_hex": "a" * 64,
    "vk_bytes": "AQID",
    "status": "Withdrawn",
})

assert register_draft["submitted"] is False
# Give transaction_payload_b64 and signing_message_b64 to the account's local
# wallet, then submit the assembled signed transaction through the pipeline.
```

These endpoints never accept private-key fields and never submit the
transaction. Both helpers return canonical padded-base64
`transaction_payload_b64` and `signing_message_b64` values so signing remains
entirely inside the client wallet. Draft validation caps the transaction
payload at 16 MiB and requires the 32-byte signing message to equal the
canonical marker-adjusted Blake2b-256 Iroha hash of that payload. The native
decoder then requires canonical Norito, the configured exact NetworkId, the requested
authority, exactly one requested register/update instruction, and exact
equality of all 17 verifying-key record fields. Register/update fail before the
request when `local_signing_context` is absent; there is no label, bare-hash,
per-call, or server-derived fallback.

Confidential assets can be registered without shelling out to JavaScript
tooling. The `register_fee_payment` below is the recommended intent returned by
`/v1/fees/quote` for that exact unsigned payload:

```python
signing_client.register_zk_asset_and_wait(
    authority="<asset-owner>",
    fee_payment=register_fee_payment,
    private_key_hex="<64-hex-private-key>",
    asset_definition_id="ds#wonderland.is",
    vk_unshield="halo2/ipa:vk_unshield",
)
```

Asset registration binds the optional confidential unshield verifier role.

For local confidential proofs, `ConfidentialProver` chooses the canonical key
and transfer/full-redemption/change relation internally. `ConfidentialInput`,
`ConfidentialOutput`, `ConfidentialChange` and `ConfidentialTree` provide the
typed inputs; supply one membership path per actual note or complete leaves.
No dummy note or unused empty-leaf path is needed, including at full capacity.
Securely retain each change opening before proving. Once its new leaf index and
root are authenticated, use `change.to_input(leaf_index)` to spend it; this uses
the native default change owner, independently of the consumed note's diversifier.
Use the prover as a context manager to close its clearing native key owner.
Methods release the GIL while proving; asynchronous applications can call them
with `asyncio.to_thread`. `ConfidentialProverError.code` separates closed-wallet,
input, key-preparation and proving failures. Python-owned bytes cannot promise
erasure. Returned `ConfidentialProof` material has been locally verified; it
does not submit a transaction or authorize a ledger change. See the runnable
[`examples/confidential_redemption.py`](examples/confidential_redemption.py).
After installing both SDK and native wheels, run
`python -I /absolute/path/to/tests/confidential_wallet_native_test.py -v` to check
the actual packaged proof, GIL progress, typed native preflight and owner closure.
This integration check requires the native extension and never substitutes a mock.

## Dataspace lifecycle helpers

SDK users can plan and check their own Nexus dataspaces without copying helper
scripts. Planning is pure Python: it returns the manifest, config snippet, and
rollout summary, and writing is explicit.

```python
from iroha_python import (
    DataspaceSpec,
    LocalSigningContext,
    NetworkId,
    ToriiCanonicalRequestAuth,
    ToriiClient,
    plan_dataspace,
    write_dataspace_plan,
)

network_id = NetworkId.parse(
    "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"
)

spec = DataspaceSpec(
    dataspace_alias="boi",
    dataspace_id=42,
    lane_alias="boi-payments",
    lane_id=7,
    governance_module="parliament",
    settlement_handle="xor_global",
    validators=["validator01"],
    route_instructions=["TransferAsset"],
)

plan = plan_dataspace(spec)
write_dataspace_plan(plan, "build/dataspaces", force=True)

client = ToriiClient(
    "http://127.0.0.1:8080",
    local_signing_context=LocalSigningContext(network_id),
    canonical_request_auth=ToriiCanonicalRequestAuth(
        network_id=network_id.literal,
        account_id="<authority-account>",
        signer=wallet.sign,
    ),
)
status = client.smoke_dataspace("boi")
print(status.dataspace_id, status.ready)
```

The same client exposes dataspace-oriented Space Directory wrappers:

```python
publish_draft = client.publish_dataspace_manifest(
    authority="<authority-account>",
    uaid="uaid:" + "11" * 32,
    dataspace=42,
    manifest={
        "version": "1",
        "entries": [{"effect": {"allow": True}}],
    },
)

revoke_draft = client.revoke_dataspace_manifest(
    authority="<authority-account>",
    uaid="uaid:" + "11" * 32,
    dataspace=42,
    revoked_epoch=10,
)
# Sign each returned draft locally and submit it through the normal transaction
# pipeline; Torii never accepts private signing material on these routes.
```

For dataspace-scoped balances, build the concrete asset bucket with
`compose_asset_id` and submit mutations through the SDK transaction helpers.
`mint_fee_payment` and `transfer_fee_payment` are recommended intents quoted
for their respective exact unsigned payloads:

```python
asset_id = client.compose_asset_id(
    "<canonical-asset-definition-id>",
    "<account-id>",
    scope="dataspace:42",
)

client.mint_asset_quantity_and_wait(
    authority="<asset-owner>",
    fee_payment=mint_fee_payment,
    private_key_hex="<64-hex-private-key>",
    asset_id=asset_id,
    quantity="100",
)

client.transfer_assets_quantity_and_wait(
    authority="<payer>",
    fee_payment=transfer_fee_payment,
    private_key_hex="<64-hex-private-key>",
    transfers=[
        {
            "asset_id": asset_id,
            "quantity": "10",
            "destination": "<payee>",
        }
    ],
)
```

Ledger quantity helpers accept `KotodamaQuantity`, canonical quantity strings,
Python integers, or finite `Decimal` values. `Decimal` inputs are normalized
losslessly; strings are treated as wire values and must already use canonical
spelling. Python `float`, JSON numbers on readback, negative quantities, and
alternate strings such as `"01"`, `"1.0"`, or `"1e0"` are rejected before a
transaction is encoded.

## RWA instructions

`TransactionDraft` now mirrors the dedicated RWA lot family, including
register/merge, lifecycle controls, and per-lot metadata updates.

```python
from decimal import Decimal

from iroha_python import NetworkId, TransactionConfig, TransactionDraft, authority_fee_payment

draft = TransactionDraft(
    TransactionConfig(
        network_id=NetworkId.parse(
            "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"
        ),
        authority="<canonical_i105_account_id>",
        # The payer and gas bound are fixed before quoting; Torii supplies the
        # exact charge maxima for this payload.
        fee_payment=authority_fee_payment(charge_limits=[]),
    )
)

draft.register_rwa(
    {
        "domain": "commodities",
        "quantity": "10.5",
        "spec": {"scale": 1},
        "primary_reference": "vault-cert-001",
        "status": None,
        "metadata": {"origin": "AE"},
        "parents": [],
        "controls": {
            "controller_accounts": [],
            "controller_roles": [],
            "freeze_enabled": False,
            "hold_enabled": False,
            "force_transfer_enabled": False,
            "redeem_enabled": False,
        },
    }
).set_rwa_key_value(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities",
    "grade",
    {"bucket": "A", "score": Decimal("9")},
).hold_rwa(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities",
    quantity=Decimal("2.500"),
)
```

`ToriiClient` also exposes the chain-state and explorer RWA read surfaces.
RWA lots are the `client.rwas` collection (see [Collection queries](#collection-queries));
the explorer keeps its own cursor pages:

```python
from decimal import Decimal

from iroha_python import F, ToriiClient

client = ToriiClient("https://torii.example")

lots = client.rwas.list(filter=(F.status == "active") & (F.quantity > Decimal("10")), sort="id")
for lot in client.rwas.iter(filter=F.owned_by == canonical_i105_account_id):
    print(lot.id, lot.quantity, lot.is_frozen)

detail_page = client.explorer_rwas.list(filter=F.domain == "commodities", limit=25)
if detail_page.next_cursor is not None:
    next_page = client.explorer_rwas.list(
        filter=F.domain == "commodities",
        limit=25,
        cursor=detail_page.next_cursor,
    )
detail = client.get_explorer_rwa_detail_typed("lot-001$commodities")
```

## CUDA helpers

The `iroha_python.gpu` module surfaces CUDA acceleration toggles and optional wrappers for
Poseidon permutations plus BN254 field arithmetic. These helpers return `None` when CUDA support is
unavailable or disabled so callers can fall back to the scalar implementations provided by the core
SDK.

## Subscriptions

Use the Torii subscription endpoints to publish plans, subscribe, and report usage. Set
`bill_for.period` to `previous_period` to bill in arrears (for example, charge on the first for the
previous month's usage). Fixed monthly plans use `pricing.kind = "fixed"` and
`bill_for.period = "next_period"`.

```python
from iroha_python import ToriiClient

client = ToriiClient("http://127.0.0.1:8080", auth_token="provider-token")

usage_plan = {
    "provider": "3oE9sLeRGP49Cu7mQ1nF4wtKAm29BG4TGLiRsaXe7mhbMP5WZ113nNW1N6RbqF",
    "billing": {
        "cadence": {
            "kind": "monthly_calendar",
            "detail": {"anchor_day": 1, "anchor_time_ms": 0},
        },
        "bill_for": {"period": "previous_period", "value": None},
        "retry_backoff_ms": 86_400_000,
        "max_failures": 3,
        "grace_ms": 604_800_000,
    },
    "pricing": {
        "kind": "usage",
        "detail": {
            "unit_price": "0.024",
            "unit_key": "compute_ms",
            "asset_definition": "usd#pay",
        },
    },
}

plan_draft = client.create_subscription_plan(
    authority="3oE9sLeRGP49Cu7mQ1nF4wtKAm29BG4TGLiRsaXe7mhbMP5WZ113nNW1N6RbqF",
    plan_id="aws_compute#commerce",
    plan=usage_plan,
)
# Sign ``plan_draft.signing_message_b64`` locally, then submit the signed
# transaction through the normal transaction pipeline.

subscription = client.create_subscription(
    authority="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
    private_key="subscriber-private-key-hex",
    subscription_id="sub-001",
    plan_id="aws_compute#commerce",
)

usage_draft = client.record_subscription_usage(
    "sub-001",
    authority="3oE9sLeRGP49Cu7mQ1nF4wtKAm29BG4TGLiRsaXe7mhbMP5WZ113nNW1N6RbqF",
    unit_key="compute_ms",
    delta="3600000",
)

client.charge_subscription_now(
    "sub-001",
    authority="3oE9sLeRGP49Cu7mQ1nF4wtKAm29BG4TGLiRsaXe7mhbMP5WZ113nNW1N6RbqF",
    private_key="provider-private-key-hex",
)
```

## Streaming events

All streaming helpers decode JSON payloads by default. Pass `with_metadata=True` to receive full
`SseEvent` objects (event name, id, retry hint, raw payload). The optional `on_event` callback
mirrors this behaviour: it receives a decoded payload when metadata is disabled and the full
`SseEvent` when metadata is requested.

`stream_events` decodes each `/v1/events/sse` payload (one JSON object with `category` and
`event`) into a typed record: `TransactionEvent` (`hash`, `status` of `Queued`, `Expired`,
`Approved` or `Rejected`, `lane_id`, `dataspace_id`, `block_height`, and `rejection_code` plus the
fixed public `rejection_reason` when rejected), `BlockEvent` (`status` of `Created`, `Approved`,
`Rejected`, `Committed` or `Applied`; `rejection_code` when rejected), `PipelineWarningEvent`,
`WitnessEvent`, `ProofVerifiedEvent`, `ProofRejectedEvent` and `ProofPrunedEvent`. Every other
kind (data events such as `Asset`, the `Other` category, and kinds newer than the SDK) decodes
as `GenericEvent(category, event, summary)`, so new server events never break a stream;
`summary` is diagnostic text without a stable format. Every record keeps the payload in `raw`.
A payload that is not such an object raises `ValueError`; `decode_json=False` yields the raw
`data` text instead, and `decode_event()` decodes a payload received elsewhere.

Event filters use the collection-query text grammar, restricted to what subscriptions can match:
`=` and `in [...]` over `tx_status`, `tx_hash`, `tx_block_height`, `tx_lane_id`,
`tx_dataspace_id`, `block_status`, `block_height`, `proof_backend`, `proof_call_hash` and
`proof_envelope_hash`, combined with `and`/`or`; `not` only over `tx_status = ...` or
`block_status = ...`; and `tx_block_height is null`. Torii rejects anything else with
`invalid_filter`, raised as `ToriiQueryError` when the stream opens.

The canonical `/v1/events/sse` feed is live-only: it emits no SSE ids and retains no replay log.
Its helpers therefore expose no cursor, resume flag, or `last_event_id` argument. A transport
reconnect establishes a new live subscription and can have a gap. Use `/v1/blocks/stream` from a
known height when complete ledger history is required. If an established SSE feed reports a
terminal `event: stream_error`, the iterator raises `SseStreamError` with the stable `code`,
`message`, `dropped_messages`, and `replay_available` fields. `EventCursor` remains available only
for explicitly replayable feeds such as the SoraFS event logs.

```python
import os

from iroha_python import (
    Ed25519KeyPair,
    F,
    NetworkId,
    OperatorSigningContext,
    ProofVerifiedEvent,
    SseStreamError,
    ToriiCanonicalRequestAuth,
    TransactionEvent,
    create_torii_client,
)

# Load these two values from runtime-only operator configuration or a secret manager.
network_id = NetworkId.parse(os.environ["IROHA_NETWORK_ID"])
operator_key_pair = Ed25519KeyPair.from_private_key(
    bytes.fromhex(os.environ["IROHA_OPERATOR_PRIVATE_KEY_HEX"])
)
client = create_torii_client(
    "http://127.0.0.1:8080",
    operator_signing_context=OperatorSigningContext(network_id, operator_key_pair),
)

# Event filters use the collection-query grammar over the event fields listed above.
proof_filter = (F.proof_backend == "halo2/ipa") & (F.proof_call_hash == "deadbeef" * 8)
try:
    for event in client.stream_events(filter=proof_filter):
        if isinstance(event, ProofVerifiedEvent):
            print("Proof verified", event.proof_hash, event.vk_ref)
except SseStreamError as error:
    print("Event stream terminated", error.code, error.dropped_messages)

for event in client.stream_events(filter=F.tx_status.in_("Approved", "Rejected")):
    if isinstance(event, TransactionEvent):
        print(event.hash, event.status, event.rejection_code)

# Text filters are sent unchanged.
for block_event in client.stream_events(filter='block_status = "Committed"'):
    print("Committed block", block_event.status)

# Framing metadata (SSE event name, id, raw frame) with the typed event in `data`.
for frame in client.stream_events(filter=proof_filter, with_metadata=True):
    print(frame.event, frame.data.event, frame.raw)

# Inspect the operator-only Connect aggregate with typed helpers.
status = client.get_connect_status_typed()
if status and status.enabled:
    for entry in status.per_ip_sessions:
        print(entry.ip, entry.sessions)

# Native protocol-1 observation from the canonical Torii client model.
snapshot = client.get_sumeragi_status_typed()
print(snapshot.protocol_version, snapshot.height, snapshot.view, snapshot.stage)
print(snapshot.committed_height, snapshot.applied_height, snapshot.halted)
# All 21 fields are mandatory; nullable values are explicit. This immutable
# bounded observation is not a finality proof. Global QC and grouped diagnostic
# DTOs and methods are removed. Native capture parity remains an open gate.

# Inspect physical-lane governance coverage from `/status`
status_snapshot = client.get_status_snapshot_typed()
for lane in status_snapshot.status.lane_governance:
    state = "ready" if lane.manifest_ready else "missing"
    print(f"lane {lane.alias} manifest {state}; validators={', '.join(lane.validator_ids)}")
if status_snapshot.status.lane_governance_sealed_total:
    print("sealed lanes remaining:", status_snapshot.status.lane_governance_sealed_total)
    if status_snapshot.status.lane_governance_sealed_aliases:
        print("sealed aliases:", ", ".join(status_snapshot.status.lane_governance_sealed_aliases))

# Inspect governed consensus parameters
params = client.get_sumeragi_params_typed()
print(params.block_cadence_ms, params.max_clock_drift_ms, params.chain_height)

# Manage triggers
trigger_payload = {
    "id": "notify-admins",
    "action": {"Mint": {"asset_id": "<base58-asset-definition-id>#<i105-account-id>", "value": 1}},
    "authority": "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
    "filter": {"ByTime": {"schedule_ms": 60_000}},
}
client.register_trigger(trigger_payload)
client.delete_trigger("notify-admins")

# Submit authenticated SoraFS PoR lifecycle evidence. Challenge issuance is
# owned by the coordinator scheduler; the client exposes no manual ingress.
proof_payload = b"...PorProofV1 bytes..."
verdict_payload = b"...AuditVerdictV1 bytes..."

proof = client.record_sorafs_por_proof(proof=proof_payload)
verdict = client.record_sorafs_por_verdict(verdict=verdict_payload)
status_bytes = client.get_sorafs_por_status(manifest_hex="ab" * 32, status="verified")
weekly_report = client.get_sorafs_por_weekly_report("2026-W05")
ingestion = client.get_sorafs_por_ingestion_status(manifest_hex="ab" * 32)
for provider in ingestion.providers:
    print(provider.provider_id_hex, provider.pending_challenges, provider.failures_total)

# Read exact-checkpoint SoraFS billing and hedging projections. These helpers
# require per-request canonical account authentication, never retry or follow
# redirects, and enforce the Torii 1 MiB JSON / 22 MiB statement response caps.
billing_auth = ToriiCanonicalRequestAuth(
    network_id=NetworkId.parse(os.environ["IROHA_NETWORK_ID"]).literal,
    account_id=os.environ["IROHA_ACCOUNT_ID"],
    signer=external_request_signer,
)
checkpoint = os.environ["SORAFS_BILLING_CHECKPOINT_HEX"]
statements = client.list_sorafs_billing_statements(
    expected_checkpoint_fingerprint_hex=checkpoint,
    limit=25,
    canonical_auth=billing_auth,
)
statement_id = statements["items"][0]["statement_id_hex"]
statement_norito = client.get_sorafs_billing_statement(
    statement_id,
    checkpoint,
    canonical_auth=billing_auth,
)
client.acknowledge_sorafs_billing_statement(
    statement_id,
    checkpoint,
    request_nonce_hex=secrets.token_hex(32),
    authentication_proof=external_owner_proof,
    canonical_auth=billing_auth,
)
exposure = client.get_sorafs_hedging_exposure(
    expected_checkpoint_fingerprint_hex=checkpoint,
    limit=100,
    canonical_auth=billing_auth,
)
# Reconciliation is billing-manager-only; exposure/intents require a treasury
# or hedging observer role. No automatic hedge-execution mutation is exposed.

# `status_bytes`, `weekly_report`, and the export helper all return Norito payloads.
# Decode them with the `norito` crate or via `norito.decode(...)` when the matching schema is available.

# Inspect finalized native SoraFS orderbook state at one coherent chain anchor.
orderbook = client.get_sorafs_orderbook(limit=25)
anchor = orderbook["orders"]["finalized_cursor"]
anchor_height = anchor["height"]
anchor_hash_hex = bytes(anchor["block_hash"]).hex()
trades = client.list_sorafs_orderbook_trades(
    expected_finalized_height=anchor_height,
    expected_finalized_block_hash_hex=anchor_hash_hex,
    limit=25,
)
events = client.list_sorafs_orderbook_events(
    expected_finalized_height=anchor_height,
    expected_finalized_block_hash_hex=anchor_hash_hex,
    limit=25,
    if_none_match='"cached-etag"',
)
print(
    orderbook["status"]["open_orders"],
    len(trades["trades"]["trades"]),
    0 if events is None else len(events["events"]["events"]),
)
for event in client.stream_sorafs_orderbook_events(limit=1, with_metadata=True):
    print(event.event, event.data)
    break
# WebSocket helpers require `websocket-client` (`pip install iroha-python[ws]`).
for event in client.stream_sorafs_orderbook_events_websocket(limit=1, with_metadata=True):
    print(event.event, event.data)
    break

# Mutation routes accept only a complete caller-signed, versioned native
# SignedTransaction. Each route validates that the transaction contains exactly
# one matching native ISI before normal transaction ingress:
# SubmitSorafsOrderbookOrder, CancelSorafsOrderbookOrder, or
# RecordSorafsOrderbookSettlementReceipt.
from iroha_python import build_signed_orderbook_order_request, sign_orderbook_payload

orderbook_private_key = bytes.fromhex("b7" * 32)
signed_order_request = sign_orderbook_payload(
    "order-request",
    b"...Norito OrderRequestV1 bytes...",
    orderbook_private_key,
)
signed_order_request_from_fields = build_signed_orderbook_order_request(
    {
        "side": "bid",
        "tier": "hot",
        "price_per_gib": "1.000000001",
        "quantity_gib": "12",
        "owner_account": b"merchant@paynet",
        "expiry_unix": "1700010000",
        "nonce": "7",
        "maker_fee_bps": "25",
        "taker_fee_bps": "30",
    },
    orderbook_private_key,
)
# XOR-denominated orderbook values are canonical decimal strings with at most
# nine fractional digits. Integer JSON numbers and retired micro-XOR fields are rejected.
# Embed `signed_order_request_from_fields` in a SubmitSorafsOrderbookOrder ISI,
# build and sign the native transaction, then encode its versioned Norito bytes.
# Configure `ToriiClient(chain_discriminant=...)` for the deployment before
# submitting (`369` for Taira); the default `753` is the Sora discriminant.
# Strict submission requires canonical HTTPS and uses an internally owned,
# zero-retry Requests adapter with only explicit headers/proxies/verify/cert.
# It ignores trust_env/netrc/environment proxy or CA discovery, hooks, cookies,
# persistence and elapsed timing, and rejects custom transport state. The
# configured positive timeout is connect/read inactivity, not an absolute
# deadline: a slow drip may exceed it; explicit None is rejected here.
signed_order_transaction = b"...versioned caller-signed SignedTransaction bytes..."
submission_receipt = client.submit_sorafs_orderbook_order(
    signed_order_transaction,
    expected_receipt_signer=torii_receipt_public_key,
)
print(submission_receipt["payload"]["signed_transaction_hash"])
# Catch SorafsOrderbookSubmissionAmbiguousError after dispatch, reconcile its
# expected_identity against finalized state, and never resubmit automatically.
client.submit_sorafs_orderbook_cancel(
    b"...versioned SignedTransaction with one CancelSorafsOrderbookOrder ISI...",
    expected_receipt_signer=torii_receipt_public_key,
)
client.submit_sorafs_orderbook_receipt(
    b"...versioned SignedTransaction with one RecordSorafsOrderbookSettlementReceipt ISI...",
    expected_receipt_signer=torii_receipt_public_key,
)

# Validate SoraFS reference payloads locally
from iroha_python import (
    SORAFS_ORDERBOOK_PAYLOAD_KINDS,
    SORAFS_PDP_PAYLOAD_KINDS,
    validate_orderbook_payload,
    validate_pdp_bundle,
)

order_outcome = validate_orderbook_payload(
    SORAFS_ORDERBOOK_PAYLOAD_KINDS["ORDER_REQUEST"],
    b"...Norito OrderRequestV1 bytes...",
    label="order_request.to",
)
pdp_outcome = validate_pdp_bundle(
    b"...Norito PdpCommitmentV1 bytes...",
    b"...Norito PdpChallengeV1 bytes...",
    b"...Norito PdpProofV1 bytes...",
)
print(order_outcome["status"], pdp_outcome["code"])

# Account listings (collection queries; see "Collection queries" above)
from iroha_python import F

account = "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6"
assets = client.accounts.assets(account).list(filter=F.asset_alias == "xor#wonderland", limit=10)
# History is newest first; a page may hold fewer rows than `limit` while next_cursor continues.
txs = client.accounts.transactions(account).list(filter=F.result_ok == True, limit=5)
projected = client.accounts.transactions(account).rows(
    filter=F.block_height >= 1200,
    select=["entrypoint_hash", "block_height", "timestamp_ms"],
    limit=3,
)
print(assets.items, txs.items, projected.items)

```

```python
# Create an exact-network Connect session with a type-safe response
import base64

from iroha_python import NetworkId, create_torii_client
from iroha_python.connect import create_connect_session_preview

client = create_torii_client("http://127.0.0.1:8080", auth_token="admin-token")
preview = create_connect_session_preview(
    network_id=NetworkId.from_bytes(bytes([0xA5]) * 32),
    node="node.example:443",
)
info = client.create_connect_session_info({
    "sid": preview.sid_base64url,
    "network_id": preview.network_id.literal,
    "app_pk": base64.urlsafe_b64encode(preview.app_key_pair.public_key).rstrip(b"=").decode(),
    "nonce": base64.urlsafe_b64encode(preview.nonce).rstrip(b"=").decode(),
    "node": preview.node,
})
print(info.app_uri)
print(info.wallet_token)
```
# Connect URI helpers
from iroha_python.connect import ConnectUri, build_connect_uri, parse_connect_uri

uri = build_connect_uri(ConnectUri(
    sid=preview.sid_base64url,
    network_id=preview.network_id,
    app_public_key=preview.app_key_pair.public_key,
    nonce=preview.nonce,
    node="node.example:443",
))
parsed = parse_connect_uri(uri)
assert parsed.sid == preview.sid_base64url


## Sora VPN native lease flow

Sora VPN sessions are quote-first and paid in XOR through the native
`OpenVpnLeaseEscrow` instruction returned by Torii. Python clients can sign the
app-facing Torii requests with a callback while keeping private keys in the
caller-owned wallet/keystore.

```python
import os

from iroha_python import (
    Ed25519KeyPair,
    NetworkId,
    ToriiCanonicalRequestAuth,
    VpnQuoteCreateRequest,
    VpnSessionCreateRequest,
    create_torii_client,
)

client = create_torii_client("https://torii.example")
wallet_key = Ed25519KeyPair.from_private_key_hex("<hex-private-key>")
auth = ToriiCanonicalRequestAuth(
    network_id=NetworkId.parse(os.environ["IROHA_NETWORK_ID"]).literal,
    account_id="merchant@paynet",
    signer=wallet_key.sign,
)

quote = client.create_vpn_quote(
    VpnQuoteCreateRequest(
        metering_public_key_hex="<32-byte-ed25519-metering-key-hex>",
        exit_class="standard",
    ),
    canonical_auth=auth,
)

# Submit quote.open_lease_instruction as a normal signed transaction that moves
# the XOR lease fee into native VPN escrow, then pass the committed transaction
# hash back to Torii.
session = client.create_vpn_session(
    VpnSessionCreateRequest(
        quote_id=quote.quote_id,
        payment_tx_hash="<committed-open-lease-transaction-hash>",
        metering_public_key_hex=quote.metering_public_key_hex,
        exit_class=quote.exit_class,
    ),
    canonical_auth=auth,
)
print(session.helper_ticket_hex)
```

Relay operators submit signed receipts with `submit_vpn_receipt`; the response
returns earned/refund XOR fields plus a `SettleVpnLease` instruction skeleton in
the optional `settle_lease_instruction` field. That submission response uses
`status == "settlement_pending"` until the instruction commits; only a receipt
read back from committed WSV state uses `status == "settled"`. Exact
`disconnected`, `expired`, and `replaced` lifecycle statuses remain valid.

## Transaction helpers

Build transactions with ergonomic helpers that wrap the low-level `Instruction` APIs:
Every signing configuration takes one typed, canonical `NetworkId` derived from
the genesis-header hash. Ordinary transaction APIs reject operator-selected
chain labels and bare hash bytes.

```python
from iroha_python import (
    Ed25519KeyPair,
    LocalSigningContext,
    NetworkId,
    ToriiClient,
    TransactionConfig,
    TransactionDraft,
    authority_fee_payment,
)

config = TransactionConfig(
    network_id=NetworkId.parse(
        "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"
    ),
    authority="sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
    fee_payment=authority_fee_payment(charge_limits=[]),
    ttl_ms=120_000,
)
client = ToriiClient(
    "http://127.0.0.1:8080",
    local_signing_context=LocalSigningContext(config.network_id),
)
draft = TransactionDraft(config)
draft.register_domain("wonderland") \
     .register_account("sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6", metadata={"role": "admin"}) \
     .register_asset_definition(
        "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
        owning_domain="wonderland",
        balance_scope_policy="Global",
        name="rose",
        scale=2,
        mintable="Infinitely",
        metadata={"sym": "ROS"},
     ) \
     .mint_asset_quantity(
        # Balance buckets are `<base58-definition-id>#<i105-account-id>[#dataspace:<id>]`.
        "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
        10,
     )

# The transaction authority in ``config`` owns the registered definition.

pair = Ed25519KeyPair.from_private_key(bytes([1] * 32))
envelope, fee_quote = draft.quote_and_sign(client, pair.private_key)
receipt = client.submit_transaction_envelope(envelope)
if isinstance(receipt, dict):
    print("Submitted tx:", receipt.get("payload", {}).get("tx_hash"))
```

Public pipeline status is metadata-only. `get_transaction_status(...)` returns exactly the
canonical hash, closed status kind, optional committed height, scope, and resolution source;
retired rejection, diagnostic, trigger, and batch fields are rejected. Raw reads may explicitly
select `local` or `global`. Every wait, submit-and-wait, and contract-and-wait helper is fixed to
`global`; only an exact `Applied` status resolved from `state` succeeds. State-resolved `Rejected`
and `Expired` always fail, while queue/cache and pre-Applied lifecycle observations remain
progress. Wait APIs expose no scope or configurable success-status override. Signed transaction
hashes must match `[0-9a-f]{63}[13579bdf]` (the canonical Iroha `HashOf` marker) and are never
trimmed, case-folded, prefix-stripped, or loosely rebound from embedded contract response aliases.
Status reads accept only an exact HTTP `200` envelope or `404` not-found response; `202` and `204`
are protocol errors. Polling intervals and timeouts must be finite and non-negative, and
`max_attempts` must be a positive integer; invalid values are rejected rather than coerced.
Nexus submission-and-wait bindings accept only the finalizer's exact `signed_transaction` and
`hash_hex` fields and the canonical receipt fields `payload.entrypoint_hash` and
`payload.signed_transaction_hash`; camel-case and alternate hash aliases are rejected.
An involved account or operator can
request the committed transaction and trigger completions with a canonical signed query:

```python
details = client.get_pipeline_transaction_details(
    transaction_hash,
    authority=authority_account_id,
    private_key=pair.private_key,
)
```

The client uses its immutable typed `NetworkId` for the signed query and sends
the nonce-bearing body once, with redirects and transport retries disabled. Torii verifies the
exact transaction predicate, signature, freshness, nonce, and involved-account/operator
authorization.

`get_verified_committed_transaction(...)` requires a typed `network_id`, an
independently selected chain label and complete canonical native checkpoint
bytes, and `native_finality_proof_chain_json` (a Norito JSON array of 1–4096
`SumeragiFinalityProof` values, at most 16 MiB UTF-8). The checkpoint is bounded
to 68 MiB. The array starts at the checkpoint height and extends consecutively
to the selected carrier. Obtain these trust inputs from approved deployment
configuration or a previously accepted checkpoint; the response cannot select
them.

The native verifier authenticates the entire page before joining the exact
original block wire and selected input/full-output proofs. The returned
`VerifiedCommittedTransaction` includes the authenticated carrier hash/height,
network, native `context_id`, execution commitment, executed wire hash/length,
full output hash and immutable `promoted_checkpoint` bytes. Retain that checkpoint
atomically with the accepted application result. The low-level
`verify_committed_transaction_inclusion(...)` accepts the same proof and trust
inputs with exact committed-query response bytes for offline consumers. Both
helpers authenticate rejected results; check `result_ok` before treating an
operation as successful. Header signatures alone do not authenticate outputs.
The ABI-30 native call returns projection JSON and checkpoint bytes separately.
An authenticated contract rejection includes a nullable `message` from the
contract's static error catalog, preserving its exact Unicode text and spacing.

Native instructions and deployed-contract calls can share one ordered, atomic
batch. Any batch containing a contract call must bind a positive `gas_limit`
in its fee intent:

```python
from iroha_python import Instruction, NetworkId, TransactionConfig, TransactionDraft, authority_fee_payment

mixed = TransactionDraft(TransactionConfig(
    network_id=NetworkId.parse(
        "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"
    ),
    authority=authority_account_id,
    fee_payment=authority_fee_payment(charge_limits=[], gas_limit=500_000),
))
mixed.add_instruction(Instruction.register_domain("before"))
mixed.add_contract_call(
    contract_address,
    expected_code_hash_hex,  # Exact 32-byte marked code hash as raw hex.
    "settle",
    canonical_argument_record,
)
mixed.add_instruction(Instruction.register_domain("after"))

# The signed Batch keeps the exact instruction → call → instruction order.
envelope = mixed.sign(pair.private_key)
```

To request sponsorship, bind the draft to one exact program and immutable
revision before quoting:

```python
from iroha_python import sponsor_fee_payment

program_id = f"{sponsor_account_id}/wallet_payments"
requested_fee_payment = sponsor_fee_payment(
    program_id,
    3,
    charge_limits=[],
)

config = TransactionConfig(
    network_id=NetworkId.parse(
        "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"
    ),
    authority=authority_account_id,
    fee_payment=requested_fee_payment,
    ttl_ms=120_000,
)
envelope, quote = TransactionDraft(config).register_domain("payments").quote_and_sign(
    client,
    pair.private_key,
)
```

`quote_and_sign` calls account-signed `POST /v1/fees/quote`, verifies that the
returned intent retained the payer, exact program/revision, and gas bound, and
replaces only the charge maxima. Use
`client.get_fee_sponsor_program(program_id, canonical_auth=auth)` to inspect the
exact lifecycle record before constructing a sponsored draft. Metadata keys
named `fee_sponsor`, `gas_asset_id`, or `gas_limit` are retired and rejected;
sponsor failure never falls back to the authority.

Apply metadata updates or transfer ownership without dropping to raw Norito:

```python
draft.set_account_key_value("nickname", "Queen Alice")
draft.transfer_domain("wonderland", destination="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE")
draft.transfer_asset_definition("62Fk4FPcMuLvW5QjDGNF2a4jAmjM", destination="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE")
draft.transfer_nft("nft#dataspace", destination="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE")
draft.transfer_rwa(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities",
    quantity="2.5",
    destination="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
)
```

Create and operate native asset locks for escrow-style conditional payments:

```python
client.open_asset_lock_and_wait(
    authority="<source-account-id>",
    private_key_hex="<source-private-key-hex>",
    escrow_id="merchant-lock-001",
    asset_definition_id="<asset-definition-base58>",
    destination="<destination-account-id>",
    amount="2500",
    release_authority="<trusted-release-account-id>",  # omit for 2-party locks
    expires_at_ms=1_704_000_000_000,
)
client.drawdown_asset_lock_and_wait(
    authority="<trusted-release-account-id>",
    private_key_hex="<trusted-release-private-key-hex>",
    escrow_id="merchant-lock-001",
    amount="1000",
    expected_remaining_amount="2500",
)
client.cancel_asset_lock_and_wait(
    authority="<source-account-id>",
    private_key_hex="<source-private-key-hex>",
    escrow_id="merchant-lock-001",
    expected_remaining_amount="1500",
)
```

For `CancelAssetLock`, the `escrow_id` convenience argument is the application
lock-ID preimage: it must be nonempty exact text without surrounding whitespace
or a BOM and is bounded by
`CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1` (4,096 UTF-8 bytes, not
characters). It is hashed before encoding, so the on-wire `EscrowId` remains
32 bytes.

`OpenAssetLock` moves source funds into deterministic native custody.
`DrawdownAssetLock` releases funds to the destination only when the committed
remaining amount still equals `expected_remaining_amount`; this prevents two
independently submitted stale drawdowns from both debiting custody. It is
signed either by the destination account for two-party locks or by
`release_authority` when one is configured. `CancelAssetLock` refunds the
opener while the lock is still active only when the committed remaining amount
equals `expected_remaining_amount`, preventing a stale cancel from racing a
drawdown. The precondition is mandatory: the helper never substitutes a
process-local query result when the caller omits it.
`ExpireAssetLock` refunds remaining custody after the optional expiry deadline.
Zero, negative, NaN, and infinite amounts and expected-remaining preconditions
are rejected by the SDK before transaction construction.

The appeal-finance fixture boundary also exposes a strict bare archive codec:

```python
from iroha_python import (
    decode_cancel_asset_lock_v1,
    encode_cancel_asset_lock_v1,
    validate_appeal_finance_cancel_asset_lock,
)

archive = encode_cancel_asset_lock_v1(
    "hash:73CCD4E0DD69AD434DB75056B600AA4F74C8FC5556B11BDC799DFDB7EA29851F#434B",
    "20",
)
fields = decode_cancel_asset_lock_v1(archive)
diagnostic = validate_appeal_finance_cancel_asset_lock(archive)
```

Only the canonical checksummed hash string, positive canonical quantity string,
and exact archive bytes are accepted. Hex/base64 aliases, nested identifiers,
padding, substituted schemas or flags, and trailing bytes fail closed. The
validation result is diagnostic and does not authorize settlement.

### Repo settlement helpers

Create repo instructions without hand-crafting Norito payloads:

```python
from iroha_python import RepoCashLeg, RepoCollateralLeg, RepoGovernance

cash = RepoCashLeg(asset_definition_id="<cash_asset_definition_base58>", quantity="1000")
collateral = RepoCollateralLeg(
    asset_definition_id="<bond_asset_definition_base58>",
    quantity="1050",
    metadata={"isin": "ABC123"},
)
governance = RepoGovernance(
    haircut_bps=1500, margin_frequency_secs=86_400, allow_early_repayment=True
)

draft.repo_initiate(
    agreement_id="daily_repo",
    initiator="sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
    counterparty="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
    cash_leg=cash,
    collateral_leg=collateral,
    rate_bps=250,
    maturity_timestamp_ms=1_704_000_000_000,
    governance=governance,
)
draft.repo_unwind(agreement_id="daily_repo")
```

Before the initiation transaction is submitted, the counterparty must grant the
initiator an exact `CanExecuteSettlement` permission for its cash balance and
the collateral holder must grant the phase-separated maturity permission for
its collateral balance. Both permissions bind the complete initiation terms,
including the agreement identifier, parties, asset definitions, quantities,
rate, maturity, governance (including `allow_early_repayment`), and custodian.
At or after the recorded maturity any participant may submit the unwind. Before
maturity it is accepted only when the agreement opted into early repayment and
the initiator (cash borrower) submits it; interest then accrues to the committed
block time. Every economic term and exact balance scope is loaded from the
immutable on-chain agreement.

Load repo agreements from a Torii response and compute the next margin checkpoint:

```python
from iroha_python import RepoAgreementRecord

agreement = RepoAgreementRecord.from_payload(repo_payload)
next_margin = agreement.next_margin_check_after(at_timestamp_ms=now_ms)

# Discover agreements directly from Torii
from iroha_python import F, ToriiClient

client = ToriiClient("http://localhost:8080")
page = client.repo_agreements.list(filter=F.status == "active", sort="-maturity_timestamp_ms", limit=10)
for agreement in page.items:  # RepoAgreementRecord values
    print(agreement.agreement_id, agreement.counterparty)
```

### DvP / PvP settlement helpers

Model bilateral settlements without hand-crafted Norito payloads:

```python
from iroha_python import (
    SettlementLeg,
    SettlementPlan,
    SettlementExecutionOrder,
    SettlementAtomicity,
)

delivery_leg = SettlementLeg(
    asset_definition_id="<bond_asset_definition_base58>",
    quantity="10",
    from_account="sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
    to_account="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
    metadata={"isin": "ABC123"},
)
payment_leg = SettlementLeg(
    asset_definition_id="<cash_asset_definition_base58>",
    quantity="1000",
    from_account="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
    to_account="sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
)
plan = SettlementPlan(
    order=SettlementExecutionOrder.PAYMENT_THEN_DELIVERY,
    atomicity=SettlementAtomicity.ALL_OR_NOTHING,
)

draft.settlement_dvp(
    settlement_id=f"trade_dvp${delivery_leg.from_account}",
    delivery_leg=delivery_leg,
    payment_leg=payment_leg,
    plan=plan,
    metadata={"desk": "rates"},
)

counter_leg = SettlementLeg(
    asset_definition_id="<counter_asset_definition_base58>",
    quantity="900",
    from_account="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
    to_account="sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
)
draft.settlement_pvp(
    settlement_id=f"trade_pvp${payment_leg.from_account}",
    primary_leg=payment_leg,
    counter_leg=counter_leg,
)
```

Settlement IDs use `reference$canonical_owner`: the owner is an actual debited
account, and the reference is unique within that account. Bare references are
rejected. Native JSON and Norito retain the owner and reference as separate fields.

`all_or_nothing` is the sole native settlement atomicity policy. Other names
and wire tags are invalid.

See `specs/finance/repo_runbook.md` for operator-facing CLI flows, determinism notes, and automation guidance covering both repo and settlement helpers.

Connect aggregate telemetry is operator-only. Application automation should use
the management token returned at session creation with
`GET /v1/connect/status?sid=...` when inspecting its own session; it must not
receive a node operator key.

## Typed Connect session helper
`create_connect_session_info` returns a `ConnectSessionInfo` dataclass. The
first-release session response does not advertise a wall-clock expiry, so
`expires_at` remains `None`; clients must not infer it from operator-only
aggregate policy.
The response also carries `management_token` for session deletion/per-session status and `relay_token` for wallet/app relay authentication; keep the management token out of launch links and QR payloads.
`ToriiClient.connect_websocket(...)` accepts only canonical 32-byte base64url
session IDs and role tokens. It keeps the token out of the URL and sends it
once as `Authorization: Bearer ...`; default, API-token, account, and operator
authentication headers are not inherited by the WebSocket upgrade.
When broadcast relay is enabled, Torii gossips session claims over authenticated
Iroha P2P so app and wallet WebSockets can rendezvous through different Torii
nodes. Claims expose token hashes and the relay MAC key to peers, not raw app,
wallet, or management tokens.

### CLI walkthrough
Run the end-to-end Connect CLI helper to stage a session and emit an Open control frame:

```bash
python -m iroha_python.examples.connect_flow \
  --base-url http://127.0.0.1:8080 \
  --network-id '<exact-checksummed-network-id>' \
  --sid '<derived-base64url-sid>' \
  --app-public-key '<32-byte-x25519-public-key-hex>' \
  --nonce '<16-byte-nonce-hex>' \
  --app-name "Demo App" \
  --app-url https://demo.example \
  --app-icon-hash deadbeef \
  --frame-output connect-open.hex \
  --frame-json-output connect-open.json \
  --send-open
```

The script prints the typed `ConnectSessionInfo` and encodes a
`ConnectControlOpen` frame that can be relayed over WebSocket.

Pass `--app-name` (optionally with `--app-url` and `--app-icon-hash`) to embed display metadata in the control frame so wallets can render the requesting application context. Alternatively, provide `--app-metadata-file metadata.json` with a JSON object containing `name` (and optional `url`, `icon_hash`) to keep CLI flags tidy. A starter template lives at `python/iroha_python/src/iroha_python/examples/connect_app_metadata.json`. Use `--frame-output <path>` (with optional `--frame-output-format binary`) to persist the encoded frame and `--frame-json-output <path>` for a base64-friendly JSON blob.

Run `python -m iroha_python.examples.connect_flow --write-app-metadata-template connect_app_metadata.json` to write the sample metadata file without contacting a node. The app-focused helper does not expose aggregate runtime telemetry because that endpoint requires a node operator signature.

```python
info = client.create_connect_session_info({
    "sid": preview.sid_base64url,
    "network_id": preview.network_id.literal,
    "app_pk": base64.urlsafe_b64encode(preview.app_key_pair.public_key).rstrip(b"=").decode(),
    "nonce": base64.urlsafe_b64encode(preview.nonce).rstrip(b"=").decode(),
})
print(info.expires_at)
```

### Connect administration
Manage Connect registry state and admission controls directly from the SDK:

```python
registry = client.list_connect_apps(limit=25)
for app in registry.items:
    print(app.app_id, app.display_name)

policy = client.get_connect_app_policy_controls()
client.update_connect_app_policy_controls({"relay_enabled": False})

manifest = client.get_connect_admission_manifest()
client.set_connect_admission_manifest(manifest)
```

- A step-by-step automation walk-through lives at `python/iroha_python/notebooks/connect_automation.ipynb`; the accompanying notebook runs against mocked Torii endpoints and is executed in CI to ensure the flow stays up to date.

### Transaction manifests
For details on choosing bundles vs. images, see `specs/release_artifact_selection.md`.

Export manifests without hand-crafted Norito JSON:

```python
import json
from pathlib import Path

manifest = draft.to_manifest_dict()
print(json.dumps(manifest, indent=2))

manifest_json = draft.to_manifest_json(indent=2)
Path("transaction_manifest.json").write_text(manifest_json, encoding="utf-8")
```
# Connect frames

```python
from iroha_python import (
    ConnectFrame,
    ConnectControlOpen,
    ConnectDirection,
    ConnectPermissions,
    NetworkId,
    create_connect_session_preview,
    encode_connect_frame,
    decode_connect_frame,
)

preview = create_connect_session_preview(
    network_id=NetworkId.from_bytes(bytes([0xA5]) * 32),
)
frame = ConnectFrame(
    sid=preview.sid_bytes,
    direction=ConnectDirection.APP_TO_WALLET,
    sequence=1,
    control=ConnectControlOpen(
        app_public_key=preview.app_key_pair.public_key,
        network_id=preview.network_id,
        permissions=ConnectPermissions(methods=["SIGN_REQUEST_TX"], events=[]),
    ),
)

payload = encode_connect_frame(frame)
restored = decode_connect_frame(payload)
assert restored == frame
```

Ciphertext frames can be represented via `ConnectCiphertext` when the encrypted
payload is already available:

```python
from iroha_python import ConnectCiphertext

ciphertext_frame = ConnectFrame(
    sid=b"\x03" * 32,
    direction=ConnectDirection.WALLET_TO_APP,
    sequence=10,
    ciphertext=ConnectCiphertext(
        direction=ConnectDirection.WALLET_TO_APP,
        aead=b"\xDE\xAD\xBE\xEF",
    ),
)

# Derive symmetric keys and approval preimage helpers
from iroha_python import (
    generate_connect_keypair,
    connect_public_key_from_private,
    derive_connect_direction_keys,
    build_connect_approve_preimage,
    ConnectPermissions,
    ConnectSignInProof,
)

pair = generate_connect_keypair()
assert connect_public_key_from_private(pair.private_key) == pair.public_key

app_key, wallet_key = derive_connect_direction_keys(
    local_private_key=b"\x11" * 32,
    peer_public_key=b"\x22" * 32,
    sid=b"\x33" * 32,
)
assert len(app_key) == len(wallet_key) == 32

preimage = build_connect_approve_preimage(
    network_id=preview.network_id,
    sid=preview.sid_bytes,
    app_public_key=preview.app_key_pair.public_key,
    nonce=preview.nonce,
    wallet_public_key=b"\xCC" * 32,
    account_id="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
    permissions=ConnectPermissions(methods=["SIGN_REQUEST_TX"], events=[]),
    proof=ConnectSignInProof(
        domain="example.org",
        uri="https://example.org/wallet",
        statement="Sign in",
        issued_at="2024-01-01T00:00:00Z",
        nonce="abcd",
    ),
    relay_token="exact-relay-token-from-session-registration",
)

# Post a control frame via the Torii client
from iroha_python import ConnectControlClose, create_torii_client

info = client.create_connect_session_info({
    "sid": preview.sid_base64url,
    "network_id": preview.network_id.literal,
    "app_pk": base64.urlsafe_b64encode(preview.app_key_pair.public_key).rstrip(b"=").decode(),
    "nonce": base64.urlsafe_b64encode(preview.nonce).rstrip(b"=").decode(),
})
print(info.sid, info.app_uri)
client = create_torii_client("http://localhost:8080", auth_token="admin-token")
client.send_connect_control_frame(
    "session-id",
    ConnectControlClose(role="App", code=4100, reason="finished", retryable=False),
)
# Binary fields (public keys, signatures) are base64-encoded automatically when the SDK
# serializes the control payload for Torii.

# Node operators may inspect the exact-network signed aggregate separately via
# `operator_client.get_connect_status()`. Do not give its signing key to apps.
```
```

```python
# Encrypt and decrypt payloads post-approval
from iroha_python import (
    ConnectSignRequestRawPayload,
    ConnectEnvelope,
    seal_connect_payload,
    open_connect_payload,
)

raw_payload = ConnectSignRequestRawPayload(domain_tag="SIGN", payload=b"hash")
frame = seal_connect_payload(
    app_key,
    sid=b"\x01" * 32,
    direction=ConnectDirection.APP_TO_WALLET,
    sequence=42,
    payload=raw_payload,
)
restored = open_connect_payload(app_key, frame)
assert isinstance(restored, ConnectEnvelope)
assert restored.payload.payload == b"hash"
```

For repeated messaging, use `ConnectSessionKeys.derive(...)` and `ConnectSession` to manage per-direction keys, sequence counters, and anti-replay checks while calling the sealing helpers. `ConnectSession.snapshot_state()` returns a `ConnectSessionState` snapshot (including the monotonic counters and last-seen values) that can be serialised via `to_dict()` and restored with `ConnectSession.from_state(...)`. Persist the snapshot after every successful decrypt so wallets can resume after crashes without reusing sequence numbers, satisfying the PY6-P1 anti-replay requirement.

Use `ToriiClient.get_pipeline_recovery_typed` to inspect pipeline recovery
sidecars with structured DAG and transaction summaries before streaming
pipeline events. This node-local helper requires the client's immutable
`OperatorSigningContext`; it signs the exact height-substituted `GET` path and
empty body, then dispatches once without redirects or retries.

Account inventories are the `client.accounts.assets(account_id)` and
`client.accounts.transactions(account_id)` collections: typed `AccountAsset` and
`CommittedTransaction` rows, filters such as `F.asset_alias == "xor#wonderland"`,
and cursor iteration (see [Collection queries](#collection-queries) and
[Transaction history](#transaction-history)).



## Governance helpers

Protected-namespace admission flows can be orchestrated directly from the SDK. Setter
endpoints require the Torii API token if the node enforces one.

```python
from iroha_python import (
    create_torii_client,
    GovernanceReferendumResult,
    GovernanceTally,
    ToriiCanonicalRequestAuth,
)

client = create_torii_client(
    "http://127.0.0.1:8080",
    auth_token="admin-token",
    api_token="torii-token",
)
canonical_auth = ToriiCanonicalRequestAuth(
    network_id=exact_network_id,
    account_id=canonical_i105_account_id,
    signer=wallet.sign,
)

client.set_protected_namespaces(["apps", "system"])
# Namespace labels are exact printable-ASCII tokens; whitespace and non-ASCII
# aliases are rejected before dispatch rather than trimmed.
protected = client.get_protected_namespaces(canonical_auth=canonical_auth)
governed_contract = client.get_governance_contract_typed(
    "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    canonical_auth=canonical_auth,
)
proposal = client.get_governance_proposal_typed(
    "ab" * 32, canonical_auth=canonical_auth
)
referendum = client.get_governance_referendum_typed(
    "ref-1", canonical_auth=canonical_auth
)
tally = client.get_governance_tally_typed("ref-1", canonical_auth=canonical_auth)
assert proposal.found is False
assert referendum == GovernanceReferendumResult(found=False, referendum=None)
locks = client.get_governance_locks_typed("ref-1", canonical_auth=canonical_auth)
unlock_stats_typed = client.get_governance_unlock_stats_typed(
    canonical_auth=canonical_auth
)
print("Referendum found:", referendum.found)
if tally is None:
    print("No tally: referendum not found")
else:
    print("Aye votes:", tally.approve)
    print("Evaluated block:", tally.evaluated_block_height, tally.evaluated_block_hash)
print("Lock owners:", list(locks.locks))
print("Expired locks:", unlock_stats_typed.expired_locks_now)
print("Governed contract:", governed_contract.contract_address, governed_contract.code_hash_hex)
print("Protected namespaces:", protected)
```

Governance mutation mappings are closed and validated before dispatch.
Parliament ballot decisions use only the exact lowercase labels `approve`,
`reject`, and `abstain`; case or whitespace aliases are rejected.
The raw and typed tally helpers share the low-level Torii client's exact
response reader and `GovernanceTally` model. Missing referenda return `None`;
successful responses retain all three `u128` totals and their evaluated block
height and hash without numeric coercion.

For an existing public standalone ballot, use
`TransactionDraft(config).update_plain_conviction("ref-1", config.authority, "2.5", 42)`.
The method appends the native `UpdatePlainConviction` instruction with exactly
`referendum_id`, `owner`, `amount`, and `duration_blocks`. It cannot carry a
new choice; Core retains the choice from the finalized ballot and checks the
bond and lock update. The amount is an exact canonical `Quantity`, interpreted
under the referendum asset's frozen smallest-unit scale by Core.

## Runtime upgrades and ABI helpers

```python
from iroha_python import NetworkId, OperatorSigningContext, ToriiClient

operator_context = OperatorSigningContext(
    NetworkId.parse(exact_network_id),
    runtime_operator_key_pair,
)
client = ToriiClient(
    "http://127.0.0.1:8080",
    operator_signing_context=operator_context,
)

# Inspect ABI policy advertised by the node
abi_state = client.get_runtime_abi_active()
abi_hash = client.get_runtime_abi_hash()
metrics = client.get_runtime_metrics()

# Draft a runtime upgrade manifest (ABI stays fixed to v1 in the first release)
manifest = {
    "name": "Refresh runtime provenance",
    "description": "Schedules a no-ABI-change runtime rollout.",
    "abi_version": 1,
    "abi_hash": "00" * 32,
    "added_syscalls": [],
    "added_pointer_types": [],
    "start_height": 1_500_000,
    "end_height": 1_500_256,
}
proposal = client.propose_runtime_upgrade(manifest)

# Later, coordinate activation/cancellation using the manifest id (hex string)
activation = client.activate_runtime_upgrade("deadbeef" * 4)
cancel = client.cancel_runtime_upgrade("0x" + "feedface" * 4)
```

## Peer inventory & Network Time Service

The client exposes typed access to `/v1/peers` and
`/v1/time/{now,status}` so operators can capture evidence without falling back
to `curl`. Peer inventory and time status are node-local, so use a separate
client with an immutable `OperatorSigningContext` for the exact genesis
`NetworkId`; bearer/API tokens are not a fallback. The same contract applies to
`get_pipeline_preflight` and `get_pipeline_recovery`:

```python
from iroha_python import NetworkId, OperatorSigningContext, ToriiClient

operator_context = OperatorSigningContext(
    NetworkId.parse(exact_genesis_network_id),
    operator_key_pair,
)
operator_client = ToriiClient(
    "http://127.0.0.1:8080",
    operator_signing_context=operator_context,
)

peers = operator_client.list_peers_typed()
for peer in peers:
    print(peer.address, peer.id.public_key, peer.metadata)

now = client.get_time_now()
print("cluster time:", now.now_ms, "offset", now.offset_ms)

status = operator_client.get_time_status()
for sample in status.samples:
    print(sample.peer, sample.last_offset_ms, sample.last_rtt_ms, sample.count)
print("RTT buckets:", status.rtt.buckets)
```

Pipeline preflight requires exactly the fields Torii serves, including the
current `ivm_max_cycles_upper_bound` and `ivm_admission_cycle_limit` fields, and
rejects any other field. Fee sink, sponsor custody, and fee-exempt authority
values must be exact canonical I105 account ids, never account aliases. Its
`sumeragi` section carries only `block_cadence_ms`, the signed-genesis target
block time. Torii serves no stall threshold, so `stall_threshold_ms` is derived
as `iroha_python.client.PIPELINE_STALL_BLOCK_CADENCES` (20) × `block_cadence_ms`;
`is_status_stalled(status)` reports a stall only when queued work exists and the
time since the last non-empty block (or since the last block, before the first
non-empty one) exceeds it. Call `status.is_queue_stalled(threshold_ms)` directly
when the deployment's local consensus timers are known.

Use these outputs when filing telemetry readiness notes or running the Connect
automation notebook. The typed DTOs mirror the current Rust payloads.

### Capture a full node-admin snapshot

The `capture_node_admin_snapshot()` helper records `/v1/configuration`,
`/v1/peers`, `/v1/time/{now,status}`, `/v1/telemetry/peers-info`, and
`/v1/node/capabilities` with one call so runbooks and tests can store a
deterministic evidence bundle. Use a client carrying the immutable
`operator_context` shown above; configuration, peer inventory, and time status
are fresh exact-network operator reads. Node capabilities still use the
explicit canonical account signer:

```python
from iroha_python import ToriiClient

operator_client = ToriiClient(
    "http://127.0.0.1:8080",
    operator_signing_context=operator_context,
)

snapshot = operator_client.capture_node_admin_snapshot(
    canonical_auth=canonical_auth,
)
print("queue capacity:", snapshot.configuration.queue.capacity)
print("time offset:", snapshot.time_now.offset_ms)
print("capabilities:", snapshot.node_capabilities.abi_version)
if snapshot.telemetry_peers:
    print("telemetry peers:", len(snapshot.telemetry_peers))
```

Pass ``include_peer_telemetry=False`` when the deployment does not expose
`/v1/telemetry/peers-info`; the helper still records the remaining endpoints for
the audit trail.

## Kaigi instruction identities

The typed builders in `iroha_python.kaigi` obtain canonical `AccountId`,
`DomainId`, and `Name` frames from the required native extension. Account inputs
retain their full controller, including multisig member keys, weights, and
threshold. Domain normalization and exact NFC name validation use the same
pinned profiles as the node. Identity comparisons use the domainless controller
bytes, so different I105 display prefixes cannot disguise duplicate accounts.
Use the SDK and extension from the same source revision; a missing canonical
identity encoder is an error. The resulting instruction archive is decoded and
checked again by the native transaction builder.

## Kaigi relay inventory

Operators can audit registered Kaigi relays, inspect per-domain metrics, and
capture health snapshots with typed Torii helpers:

```python
from iroha_python import OperatorSigningContext, ToriiClient

client = ToriiClient(
    "http://127.0.0.1:8080",
    operator_signing_context=OperatorSigningContext(
        network_id=exact_genesis_network_id,
        key_pair=operator_key_pair,
    ),
)

relays = client.list_kaigi_relays_typed()
for entry in relays.items:
    print(entry.relay_id, entry.domain, entry.status, entry.hpke_fingerprint_hex)

relay_id = relays.items[0].relay_id if relays.items else None
detail = client.get_kaigi_relay_typed(relay_id) if relay_id else None
if detail and detail.metrics:
    print("reported by:", detail.reported_by, "registrations:", detail.metrics.registrations_total)

health = client.get_kaigi_relays_health_typed()
print(
    "healthy relays:", health.healthy_total,
    "failovers:", health.failovers_total,
)
for domain in health.domains:
    print(domain.domain, "registrations", domain.registrations_total)
```

`KaigiRelaySummary`, `KaigiRelayDetail`, and `KaigiRelayHealthSnapshot` mirror
the current Rust payloads so dashboards and readiness scripts can validate the
same DTOs. The three snapshot calls require the immutable exact-network
context, generate fresh headers for the final encoded target and empty body,
and dispatch once with redirects and retries disabled. Tokens and precomputed
operator headers, session authentication, and cookies are rejected. Typed
responses require Torii's exact first-release fields and integer spellings;
relay details also verify that the decoded HPKE key hashes to the advertised
marked fingerprint. All three reads stream strict UTF-8 JSON objects through a
64 MiB post-transfer byte bound and close the response on every outcome. List
and health require canonical ordering and fail closed at Torii's hard relay
diagnostic cap rather than materializing an unbounded registry. Keep the
operator key runtime-only; the Kaigi SSE feed retains its separate streaming
authentication contract.

`/v1/configuration` is a read-only diagnostic snapshot. Runtime configuration
changes require editing the node configuration and restarting the node, so the
client intentionally exposes no mutation helper.

Configuration snapshots also expose the active Norito-RPC transport policy without
requiring callers to parse raw JSON:

```python
snapshot = client.get_configuration()
transport = snapshot.transport
if transport and transport.norito_rpc:
    print("Norito-RPC stage:", transport.norito_rpc.stage)
    print("mTLS required:", transport.norito_rpc.require_mtls)
```

## UAID portfolio and manifests

The Torii client exposes typed UAID-level portfolio, binding, and Space
Directory manifest helpers so wallets and automation scripts can use the
endpoints without bespoke parsing, including optional `asset_id` filtering for
portfolio reads:

```python
from iroha_python import ToriiClient

client = ToriiClient("http://127.0.0.1:8080", auth_token="admin-token")
uaid_literal = "uaid:" + "aabb" * 16  # exact lowercase literal; final nibble keeps LSB=1

portfolio = client.get_uaid_portfolio_typed(uaid_literal, asset_id="xor#wonderland")
print("UAID", portfolio.uaid, "positions", portfolio.total_positions)
for dataspace in portfolio.dataspaces:
    for account in dataspace.accounts:
        for asset in account.assets:
            print(dataspace.dataspace_alias, account.account_id, asset.asset_id, asset.quantity)

bindings = client.get_uaid_bindings_typed(uaid_literal)
for slice in bindings.dataspaces:
    print(slice.dataspace_alias, slice.accounts)

manifests = client.uaid_manifests(uaid_literal).list(
    filter=(F.dataspace_id == 11) & (F.status == "Active"),
    include_total=True,
)
print("total", manifests.total, "has more", manifests.has_more)
for record in manifests.items:
    print(record.dataspace_alias, record.status, record.manifest_hash)

# Torii returns canonical transaction drafts; the client must already have an
# immutable LocalSigningContext and matching canonical_request_auth configured.
publish_draft = client.publish_space_directory_manifest(
    {
        "authority": "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
        # Exact AssetPermissionManifest JSON: numeric version 1, mandatory
        # issued_ms/activation_epoch, and omitted (never null) optional fields.
        "manifest": manifest_payload,
        "reason": "CBDC onboarding wave",
    }
)
revoke_draft = client.revoke_space_directory_manifest(
    {
        "authority": "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
        "uaid": uaid_literal,
        "dataspace": 11,
        "revoked_epoch": 9216,
        "reason": "deny-wins drill",
    }
)
```

All helpers require exact lowercase `uaid:<64-hex>` literals with LSB=1, validate query parameters, and
return rich dataclasses (`UaidPortfolioSnapshot`, `UaidBindingsSnapshot`,
`Page[SpaceDirectoryManifestRecord]`) so callers can render dashboards or build evidence bundles for the
NX-16 rollout with deterministic parsing.

## Trigger lifecycle walkthrough

```python
from iroha_python import F, Instruction, NetworkId, ToriiClient, authority_fee_payment

client = ToriiClient("http://127.0.0.1:8080", auth_token="admin-token")
trigger_id = "hourly-reward"

# 1) Build the instruction with the high-level helper.
register = Instruction.register_time_trigger(
    trigger_id=trigger_id,
    authority="sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
    action=Instruction.mint_asset(
        asset_id="<base58-asset-definition-id>#<i105-account-id>",
        account_id="sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE",
        value=1,
    ),
    interval_ms=3_600_000,
    repeats=None,
)

# 2) Submit the transaction and wait for confirmation.
envelope, status = client.build_and_submit_transaction(
    network_id=NetworkId.parse(
        "hash:A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5#95D7"
    ),
    authority="sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6",
    private_key=bytes.fromhex("11" * 32),
    fee_payment=authority_fee_payment(charge_limits=[]),
    instructions=[register],
    wait=True,
)
assert status["status"]["kind"] == "Applied"  # rejection or expiry raises

# 3) Inspect the registered trigger via REST.
details = client.get_trigger(trigger_id)
print(details["status"])

# 4) Watch pipeline outcomes with the event-stream filter grammar.
for event in client.stream_events(filter=F.tx_status.in_("Approved", "Rejected")):
    print("Transaction outcome:", event.hash, event.status, event.rejection_code)
    break  # demonstration

# 5) Unregister the trigger when no longer needed.
client.delete_trigger(trigger_id)
```

## Pipeline monitoring & SSE playbook

```python
from iroha_python import F, ToriiClient

client = ToriiClient("http://127.0.0.1:8080", auth_token="admin-token")
operator_client = ToriiClient(
    "http://127.0.0.1:8080",
    operator_signing_context=operator_context,
)

# Batched history: inspect the latest committed blocks.
recent_blocks = client.explorer_blocks.list(limit=5)
print([row["height"] for row in recent_blocks.items])

# Detailed recovery snapshot for a specific height.
sidecar = operator_client.get_pipeline_recovery(height=42)
print(sidecar.get("transactions", []))

# Subscribe to live pipeline transaction events; the feed is live-only and cannot replay gaps.
for event in client.stream_events(filter=F.tx_status == "Queued"):
    print("Queued tx:", event.hash, event.lane_id, event.dataspace_id)
    break

# Watch committed blocks (event filters match `=`/`in`, not ranges).
for block_event in client.stream_events(filter=F.block_status == "Committed"):
    print("Committed block", block_event.status)
    break
```

Connect frame encoding and crypto helpers require the compiled
`iroha_native._crypto` extension. Build and install the matching
`iroha-native` wheel from `../iroha_native` before running tests that exercise Connect payloads.

From the repository root, the SoraFS V1 native parity lane uses exact Python
3.12 and rebuilds the ABI-30 extension from the current clean source revision:

```bash
SORAFS_PYTHON_SDK_PYTHON_BIN=/path/to/python3.12 \
  bash ci/check_sorafs_python_native_sdk.sh
```

Native extension files are build outputs and must remain untracked. The lane
rejects prebuilt `.so`, `.dylib`, `.pyd`, or `.dll` files in the package source
tree, authenticates the freshly built artifact, and fails if any required
native SDK test is skipped.

## Integration tests

The SDK ships an opt-in integration harness that exercises runtime and metadata
endpoints against a live Torii node. The Python helper spins up the single-node
docker-compose topology, waits for the API to become available, and runs
`pytest` with the `integration` marker:

```bash
export IROHA_GENESIS_SIGNED_FILE="$PWD/target/python-integration-genesis/genesis.signed.nrt"
export IROHA_GENESIS_PUBLIC_KEY_FILE="$PWD/target/python-integration-genesis/genesis.public_key"
export IROHA_GENESIS_EXPECTED_HASH_FILE="$PWD/target/python-integration-genesis/genesis.expected_hash"
python python/iroha_python/scripts/run_integration.py
```

The default stack is an explicitly seeded development fixture. Prepare those
artifacts for its exact validator roster with Kagami beforehand; do not reuse a
random localnet body. The stack contains no genesis signing key or runtime
signer, and the harness refuses to start it without all three read-only
trust-root inputs. Normal generated deployments use seedless `kagami docker`
prepared-bundle mode and embed validated artifact paths directly.

Use the shell wrapper for convenience:

```bash
python/iroha_python/scripts/run_integration.sh
```

Harness options are available as CLI flags (see `--help`). Common environment
variables follow. The compatibility-named `docker-compose.single.yml` fixture
starts a four-validator committee by default.

| Variable | Purpose |
|----------|---------|
| `START_TORII` | Set to `0` to reuse an existing node instead of starting docker compose. |
| `COMPOSE_FILE` | Override the compose file (defaults to `defaults/docker-compose.single.yml`). |
| `COMPOSE_SERVICE` | Optional service name to start instead of the default full four-validator stack. |
| `IROHA_TORII_URL` | Torii URL used by the tests (defaults to `http://127.0.0.1:8080`). |
| `IROHA_GENESIS_PUBLIC_KEY_FILE` | Runtime genesis verifier-key file required by the default Compose stack. |
| `IROHA_GENESIS_SIGNED_FILE` | Host-prepared signed genesis body required by the default Compose stack. |
| `IROHA_GENESIS_EXPECTED_HASH_FILE` | Independently approved canonical checked NetworkId encoding the exact genesis hash, required by the default Compose stack. |

When running against an external environment, set `--no-start`,
`--torii-url` (or `IROHA_TORII_URL`), and optional auth tokens
(`IROHA_TORII_AUTH_TOKEN`, `IROHA_TORII_API_TOKEN`) before invoking `pytest -m
integration`.

## Norito RPC helper

Use `NoritoRpcClient` to call Torii endpoints that speak the Norito RPC surface.
The helper is a bounded binary facade over the same fail-closed transport as
`ToriiClient`. It automatically attaches Norito headers, rejects cross-origin
targets and redirects, disables automatic retries, and closes every response.

```python
from iroha_python.norito_rpc import NoritoRpcClient, NoritoRpcConfig

config = NoritoRpcConfig(
    base_url="http://127.0.0.1:8080",
    max_response_bytes=8 * 1024 * 1024,
)
with NoritoRpcClient(config) as rpc:
    response_bytes = rpc.call("/v1/pipeline/transactions", payload_bytes)
```

Callers may supply non-authentication headers and query parameters, but every
route must be an origin-relative path. Pass bearer and API tokens explicitly
on `NoritoRpcConfig`; they are redacted from its representation. The pytest
suite (`tests/norito_rpc_test.py`) provides additional usage examples.

### Norito RPC smoke tests

Release automation and local workflows can run the targeted Norito RPC parity
suite (header/method coverage) with:

```bash
python/iroha_python/scripts/run_norito_rpc_smoke.sh
```

Set `PYTHON_BIN=/path/to/python` to exercise a specific interpreter (for
example, the virtualenv created by `scripts/release_smoke.sh`). The script
requires `pytest` and exits non-zero on any regression so Norito RPC helpers
stay aligned with Torii.

## Norito fixtures

The Rust xtask is the sole owner of the shared Norito RPC fixtures in
`fixtures/norito_rpc`. Python does not own or copy shared `.norito` payload blobs;
`python/iroha_python/tests/fixtures` is a generated descriptor-only mirror containing
`transaction_payloads.json` and `transaction_fixtures.manifest.json`.

Regenerate the canonical corpus and every SDK mirror with:

```bash
cargo run --locked -p xtask --features dev-tools --bin xtask -- \
  norito-rpc-fixtures --output-root /path/to/first-new-norito-rpc-publication
cargo run --locked -p xtask --features dev-tools --bin xtask -- \
  norito-rpc-fixtures --output-root /path/to/second-new-norito-rpc-publication
```

Both external output roots are create-only and must not already exist. Before
any tracked update, require identical exact path sets, entry types, modes,
completion manifests, and every file byte. Apply the reviewed identity-relative
patch from either sealed root, then verify both the tracked owner and Python
mirror with:

```bash
cargo run --locked -p xtask --features dev-tools --bin xtask -- norito-rpc-verify
python3 scripts/check_python_fixtures.py --quiet
```

The Python checker compares those two JSON files directly with the canonical
directory and rejects any shared `.norito` blob in the Python mirror. Its optional
`--source` and `--target` arguments are test/check inputs only; they do not create a
second fixture owner.

**Fixture regen SLA (<48h)**

1. When the Rust schema or fixture declarations change, run the canonical xtask owner.
2. Run `cargo run --locked -p xtask --features dev-tools --bin xtask -- norito-rpc-verify` and `python3 scripts/check_python_fixtures.py --quiet`.
3. Commit the canonical outputs and all generated SDK mirrors together; the Python slice contains descriptors only.
4. Before opening a PR, execute `./python/iroha_python/scripts/run_checks.sh` so lint/type/tests and the fixture parity guard all pass.

### Release smoke test

Before publishing, exercise the release smoke pipeline:

```bash
bash python/iroha_python/scripts/release_smoke.sh
```

(`make python-release-smoke` dispatches to the same script.)

The workflow now:

1. Builds exactly one wheel candidate with `python -m build` and seals and structurally preflights it before installation.
2. Installs the wheel into a fresh virtualenv, authenticates the complete installed package and native-extension provenance against that seal, and rejects path or file aliases.
3. Requires the installed native extension to expose bridge ABI 30 and a non-empty compiled-profile catalog accepted by its native validator, then runs the Norito RPC parity suite.
4. Runs `twine check` followed by a `twine upload --dry-run` call so PyPI metadata and credentials are validated ahead of time.

The smoke harness accepts no signing, provenance, key, or manifest-output
options and never produces signatures. It is deliberately limited to
build/seal/install/native-provenance/privacy/RPC/package-metadata checks; the
protected aggregate release workflow remains the authority for release
signing and provenance publication.

Set `PYTHON_RELEASE_SMOKE_KEEP_DIST=1` to preserve the built wheel and source
distribution under `dist/` after the smoke completes.

For details on choosing between binary bundles and container images, consult `specs/release_artifact_selection.md`.

For a production release, stage the reviewed package candidates and checksums
through the protected aggregate release workflow. Authentication happens
outside this harness with the external software Ed25519 signer and is
verified with:

```bash
python3 scripts/release_manifest_signing.py verify \
  --manifest release_manifest.json \
  --signature release_manifest.json.sig \
  --public-key release_manifest.json.pub \
  --trusted-signing-fingerprint "$TRUSTED_SIGNING_FINGERPRINT" \
  --release-manifest-verifier /opt/iroha/bin/iroha \
  --trusted-release-manifest-verifier-sha256 \
    "$TRUSTED_RELEASE_MANIFEST_VERIFIER_SHA256"
```

## Testing

Run the Python lint/type-check/test suite with:

```bash
./python/iroha_python/scripts/run_checks.sh
```

`make python-checks` is a convenience wrapper around the same script. Install
the development extras first with
`pip install -e python/iroha_python[dev]`. The command runs `ruff`, `mypy`,
`pytest`, and the fixture parity check so the SDK stays aligned with the
canonical Norito artifacts. Set `SKIP_LINT=1`, `SKIP_TESTS=1`, or
`SKIP_FIXTURES=1` to skip an individual phase while iterating locally.

Run the Rust unit tests for the bindings with:

```bash
PYO3_PYTHON=/absolute/path/to/python3 cargo test -p iroha_python_rs
```

The build reads `PYO3_PYTHON` to select the interpreter and discovers its shared
library through `sysconfig`. If discovery is unavailable, set
`IROHA_PYTHON_RUNTIME_PATH` to the exact CPython shared library or record that
path in the ignored
`python/iroha_python/iroha_python_rs/python-runtime-path` file.

### macOS runtime configuration

When running tests on macOS the binary embeds CPython directly. If your system
Python does not expose the shared library globally (for example, the
Xcode-provided interpreter), create a `python-runtime-path` file alongside
`python/iroha_python/iroha_python_rs/Cargo.toml` containing the absolute path to
the CPython dynamic library. The Rust build reads this file directly. Lines
starting with `#` are treated as comments, so the file can also include short
notes.

Example `python-runtime-path`:

```
# Path to Python3 shared library used by tests
/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Python3
```

You can auto-populate the file with the discovered shared library by running:

```bash
python python/iroha_python/scripts/update_python_runtime_path.py
```

The helper mirrors the discovery logic used in `build.rs`, consulting
`IROHA_PYTHON_RUNTIME_PATH` first and falling back to `sysconfig`.

## SoraFS replication-order instructions

`iroha_python.sorafs_replication` provides schema-closed typed wrappers for the
three native V1 variants:

```python
import base64
from iroha_python import (
    CompleteReplicationOrderInstruction,
    ExpireReplicationOrderInstruction,
    IssueReplicationOrderInstruction,
    ProviderIngestCompletionAuthorityV1,
    ProviderIngestCompletionSignerPolicyV1,
    ProviderIngestFinalizedAnchorV1,
)

issue = IssueReplicationOrderInstruction(
    order_id,
    base64.b64encode(replication_order_bytes).decode("ascii"),
    issued_epoch=20,
    deadline_epoch=28,
    musubi_archive=archive_id,  # omit for an ordinary non-Musubi order
)
complete = CompleteReplicationOrderInstruction(
    order_id,
    provider_id,
    completion_epoch=27,
    expected_authority=ProviderIngestCompletionAuthorityV1(
        provider_owner=provider_owner,
        completion_signer=completion_signer,
        signer_policy=ProviderIngestCompletionSignerPolicyV1(
            policy_id=policy_id,
            revision=2,
            predecessor_digest=predecessor_digest,
            policy_digest=policy_digest,
        ),
    ),
    expected_assignment_revision=3,
    finalized_anchor=ProviderIngestFinalizedAnchorV1(
        height=41,
        block_hash=block_hash,
    ),
)
expire = ExpireReplicationOrderInstruction(order_id, expiration_epoch=29)
```

IDs are exact non-zero lowercase 64-hex strings. Issue validates bounded,
canonical base64/Norito framing plus the embedded order ID, target, provider
ordering, and deadline. Its fifth `musubi_archive` option is always present in
the typed payload: `None` selects an ordinary order, while a non-zero ArchiveId
creates the immutable Musubi purpose binding. The retired four-field shape is
rejected. Completion always requires the exact six-field hard cut:
`order_id`, `provider_id`, `completion_epoch`, `expected_authority`,
`expected_assignment_revision`, and `finalized_anchor`. The authority retains
the provider owner, independently selected completion signer and four-part
signer-policy chain. Both accounts require exact canonical I105 identities. The
completion signer is required and is never inferred from the provider owner;
retired owner-only authorities, missing fields and unknown fields fail decoding. Call `.to_payload()` for the schema-closed SDK
JSON model or `.to_instruction()` for canonical Norito after rebuilding the
native extension from the same source revision.

## ISO 20022 operator requests

The existing pacs.008, pacs.009, and message-status methods require an
immutable signer bound to the node's exact genesis-derived `NetworkId`:

```python
from iroha_python import NetworkId, OperatorSigningContext, ToriiClient
from iroha_python.crypto import Ed25519KeyPair

operator_context = OperatorSigningContext(
    NetworkId.parse(exact_network_id),
    Ed25519KeyPair.from_private_key(operator_private_key),
)
client = ToriiClient(torii_url, operator_signing_context=operator_context)
result = client.submit_iso_pacs008(
    pacs008_xml,
    profile="swift-cbpr-plus",
)
```

Each submission and status poll generates a fresh timestamp and nonce and signs
the exact method, path, sorted query, and body hash. Requests are dispatched
once with transport retries and redirect following disabled. `profile` is a
signed query parameter; bearer/API tokens, application-account auth headers,
the retired `X-Iroha-Iso-Profile` header, and precomputed operator headers are
rejected before dispatch.

## Configuration & overrides

`resolve_torii_client_config` keeps Python clients aligned with the operational
policy embedded in `iroha_config`. It merges a parsed config file with explicit
inline overrides. Ambient process environment is deliberately ignored: pass an
`env` mapping when a development tool intentionally opts into environment
configuration. This keeps tests and production startup deterministic. The
following keys are recognized in that explicit mapping:

| Variable | Purpose |
|----------|---------|
| `IROHA_TORII_TIMEOUT_MS` | Request timeout in milliseconds |
| `IROHA_TORII_MAX_RETRIES` | Maximum retry attempts |
| `IROHA_TORII_BACKOFF_INITIAL_MS` | Initial retry backoff delay |
| `IROHA_TORII_BACKOFF_MULTIPLIER` | Exponential backoff multiplier |
| `IROHA_TORII_MAX_BACKOFF_MS` | Maximum backoff delay |
| `IROHA_TORII_RETRY_STATUSES` | Comma separated HTTP status codes that should be retried |
| `IROHA_TORII_RETRY_METHODS` | Comma separated HTTP methods eligible for retries |
| `IROHA_TORII_AUTH_TOKEN` | Default `Authorization: Bearer …` header |
| `IROHA_TORII_API_TOKEN` | Default `X-API-Token` header |

Environment overrides are meant for development convenience; production nodes
should rely on the canonical `iroha_config`. Explicit keyword arguments passed
to `create_torii_client` take precedence over a resolved configuration.

The test harness automatically loads this library when the file is present, so
no environment variables need to be exported.

## Current scope

- Re-export the maintained Norito codec (`iroha-norito`) so payload encoding and
  decoding stay consistent with Rust fixtures.
- Provide a convenient constructor for the Torii HTTP client used to manage
  attachments.
- Expose generic `CryptoKeyPair` helpers over every signature algorithm compiled
  into `iroha_crypto`: Ed25519, secp256k1, ML-DSA-65, the TC26 GOST R
  34.10-2012 parameter sets, BLS normal/small, and SM2. The helpers cover
  random and seeded key generation, private-key import, signing, verification,
  and bare or algorithm-prefixed multihash import/export.
- Provide algorithm-specific Ed25519 account-id helpers and raw SM2 helpers
  (`generate_sm2_keypair`, `derive_sm2_keypair_from_seed`, `load_sm2_keypair`,
  `sign_sm2`, `verify_sm2`, `sm2_public_key_multihash`) alongside the generic
  payload-based API. `sm2_fixture_from_seed` exercises the required native
  implementation so SDK parity tests assert the shared
  seed/distid/ZA/signature bytes without a bundled-vector fallback.
- Provide confidential key-derivation helpers (`derive_confidential_keyset`,
  hex variants, and a `ConfidentialKeyset` wrapper) so wallets can obtain
  `nk`/`ivk`/`ovk`/`fvk` alongside the spend key locally.
- Offer a `TransactionBuilder` wrapper for constructing and signing canonical
  transactions (bare + versioned Norito bytes) with signature/hash inspection
  helpers plus dict/JSON export/import helpers for envelopes.
- Provide Python-friendly instruction constructors (register domain/account,
  mint/transfer quantity assets) to assemble manifests without raw JSON, plus
  `Instruction.from_json`/`Instruction.to_json` helpers for full Norito
  coverage when bespoke wrappers are unnecessary.
- Expose typed wrappers for `DomainId`, `AccountId`, `AssetDefinitionId`, and
  `AssetId` so Python code can compose Norito payloads with on-chain
  identifiers while preserving Rust validation semantics.
- Extend the Torii client with configurable retries/auth headers, JSON helper
  methods for `/status`, `/v1/health`, `/v1/configuration`, `/v1/metrics`,
  and block queries, laying the groundwork for optional gRPC parity.
- Extend the Torii client with governance helpers (proposal deployment, ballot
  submission, referendum status) so clients can orchestrate governance flows
  without hand-crafted HTTP requests.
- Include `get_confidential_gas_schedule` so operators can inspect the
  confidential verification gas schedule. The schedule is startup configuration
  committed into the ZK policy hash and is not mutable through the runtime API.
- Expose administrative helpers for configuration updates, peer discovery
  (typed `PeerInfo` via `list_peers_typed`), network time introspection
  (`NetworkTimeSnapshot`/`NetworkTimeStatus`), and runtime metadata
  (`NodeCapabilities`, `RuntimeMetrics`, `RuntimeAbiActive`, `RuntimeAbiHash`) so
  operators can script parity checks without massaging raw JSON from
  `/v1/configuration`, `/v1/peers`, `/v1/time/{now,status}`, `/v1/node/capabilities`,
  and `/v1/runtime/*`.
- Add typed runtime upgrade helpers (`list_runtime_upgrades_typed`, the
  `RuntimeUpgrade*` dataclasses, and typed wrappers around `propose_runtime_upgrade`,
  `activate_runtime_upgrade`, `cancel_runtime_upgrade`) to inspect manifests and
  instruction bundles without hand-decoding JSON payloads.
- Provide trigger helpers for registering time/pre-commit actions, executing triggers, and
  minting/burning/unregistering repetitions so automation flows avoid manual Norito. Typed trigger
  listings (`TriggerRecord`, `TriggerListPage`) and mutation responses
  (`TriggerMutationResponse` via `register_trigger_typed`/`delete_trigger_typed`) surface structured results and
  governance drafts for `/v1/triggers`, `/v1/triggers/query`, and the lifecycle endpoints.
- Add Torii trigger lifecycle wrappers (`register_trigger`, `register_trigger_typed`,
  `delete_trigger`, `delete_trigger_typed`, `get_trigger`, `list_triggers`)
  so automation flows can manage schedules directly from Python while validating governance payloads when desired.
- Read every Torii collection (domains, accounts, asset definitions, NFTs, RWA lots,
  account assets, asset holders, account transactions, repo agreements) through one
  `Collection` surface (`list`, `iter`, `pages`, `rows`, `iter_rows`, `count`) built on the
  shared query core in `iroha_torii_client.list_query`: a typed filter builder (`F`),
  canonical text and JSON forms checked against the shared golden vectors, cursor pages
  and typed rows with exact `Decimal` quantities. Query errors raise `ToriiQueryError`
  (`code`, `parameter`, `details`); every other unexpected status raises a `ToriiError`
  subclass.
- Filter live `/v1/events/sse` events with the same text grammar and decode them into typed
  event records (`stream_events(filter=...)`, `decode_event`).
- Surface pipeline recovery sidecars (`/v1/pipeline/recovery/{height}`) and Sumeragi evidence
  listing/counting so Python operators can monitor ledger history without reimplementing
  the Rust toolchain.
  Evidence reads use the canonical closed `{kind, value}` envelope for
  `NativeSumeragiEvidence` and `SccpForgeryEvidence`; the SDK re-exports the shared
  model types and decodes through the Torii client's single current parser.
  Read typed payloads through `item.value`. They retain native root/lane scope or
  SCCP certificate bytes and generation attribution, a non-null admission height,
  and the `pending` or `applied` penalty lifecycle. Decoding offers DATA without
  authenticating signatures or historical authority. Missing, extra, retired flat
  fields and responses outside the requested kind filter are rejected. The
  authenticated reads retain the 1 KiB count and 1 MiB JSON-list ceilings.
- Extend the Torii client with transaction submission/status helpers so signed
  envelopes can be delivered directly to `/v1/pipeline/transactions`.
- Provide a `submit_transaction_envelope_and_wait` helper that submits a signed
  envelope and polls Torii until the transaction reaches a terminal status.
- Add `build_signed_transaction` so callers can assemble + sign a transaction
  in one step using high-level instruction helpers.
- Provide `ToriiClient.build_and_submit_transaction` to construct, submit, and
  optionally await transaction finalization with a single call, returning the
  envelope as an object, dict, or JSON string; `submit_transaction_json`
  accepts an envelope JSON payload directly.
- Ship a lightweight CLI helper (`python/iroha_python/bin/submit_envelope_json.py`)
  for replaying JSON envelopes from stdin or a file via the Torii client.
- Include structured account query envelopes plus Torii helpers for
  `/v1/accounts/query`, `/v1/accounts/{id}/assets`, and
  `/v1/accounts/{id}/transactions`, alongside a live-only SSE consumer for
  `/v1/events/sse` that surfaces terminal stream errors. A lightweight filter DSL
  (`Eq`, `Between`, `metadata_eq`, `metadata_exists`, `field_in`, …) keeps
  payloads deterministic without hand-crafted JSON.
- Offer a `wait_for_transaction_status` helper that polls pipeline status until
  exact global, state-resolved `Applied` finality. Intervals, timeouts, attempt
  bounds, and callbacks remain configurable; scope, success, and failure
  classifications are fixed by the first-release contract. Exact global,
  state-resolved `Rejected` and `Expired` fail; every other status is progress.
- Contracts API wrappers (`/v1/contracts/artifacts/{dataspace_id}/{code_hash}`,
  its `/bytes` resource, and `/v1/contracts/call`), SNS helpers, and
  ZK verifying-key helpers round out the Torii surface needed by PoC operators.
  Artifact reads take `ContractArtifactId` and canonical account authentication;
  responses must match the selected network and exact dataspace. Byte reads also
  verify the complete artifact digest. Manifest registration uses a signed native
  instruction in the shared deployment workflow.
- Ship optional Norito RPC helpers (`iroha_python.norito_rpc`) so callers can
  invoke Norito-encoded RPC endpoints without vendor-specific transports.

The `validator_staking` module exposes immutable `StakingMonetaryPlanV1`,
`StakingRewardClaimPlanV1`, `StakingValidatorGenerationV1` and
`StakingEpochAuthorizationV1` values with `from_norito` / `to_norito`. The sole
compact layout uses the existing Norito codec and mandatory native identity
validation. Monetary preconditions are typed; `fee_claim` binds one mandatory
automatic entitlement, its custody, beneficiary revision, and replay sequence.
Amounts use `KotodamaQuantity`. These
codecs do not authenticate preparation observations, the network's pinned XOR,
custody, signatures or finality; those remain execution/evidence checks.

### Staking preparation observations

The client exposes the canonical `/v1/nexus/staking/prepare` read as
`preparePublicLanePlan(request, xorAssetDefinitionId)` in JavaScript and
`prepare_public_lane_plan(request, xor_asset_definition_id)` in Python. It uses
the client's immutable local signing context only to pin the expected network;
the read signs and submits no transaction. Supply the network's genesis-pinned
XOR definition explicitly. All proposed balances must use that definition and
Global scope. The response is a server observation, including its reported
block identity; it is not an independently authenticated state proof.

Requests and responses use exact bounded Norito frames. The client checks the
echoed request, epoch cut, expiry, recipients, selected accruals, and complete
ordered balance set before returning the plan for review. There is one dispatch
with no retry or redirect. Execution must recompute all monetary effects and
preconditions before any signed plan changes ledger balances.

Python preparation uses one original absolute deadline, including request
preparation, worker startup, headers, body and validation. On POSIX, its owned
Requests worker prepares the request and resolves the original Session and
ambient authentication, proxy, TLS and certificate settings exactly once, so
NETRC reads and system proxy discovery share the same deadline. A bounded Norito
pipe returns the exact prepared request metadata and at most
256 KiB. Deadline expiry terminates and reaps only that worker. Cleanup allows
up to 1.2 seconds beyond the deadline. Before starting the worker, the parent
requires the exact ToriiClient and rejects relevant instance method overrides,
custom client/default-header storage and altered request graphs before parent
header copying, formatting or virtual dispatch. The original request graph is
admitted against the existing staking schemas before its sole canonical codec
runs. It requires exact standard Session and nested storage types and rejects custom
adapters, hooks, cookies, authentication callbacks, non-string Session parameter
mappings and modified pool settings without invoking their methods. Scalar and
collection bounds, including the 512 KiB IPC envelope, are checked before the
full encoder runs. The worker bounds the prepared URL before dispatch and rejects
compressed responses and response cookie mutation before reading their bodies.
The same worker runs the canonical native SoraFS alias-proof policy. Successful
outcomes retain the exact alias evaluation and increment the current client
counters once. Standard warning logging runs only in that worker, through owned
duplicates of the admitted stream descriptors; the parent never writes, flushes
or closes the original log stream. A blocked log sink shares the original
deadline. Timed-out operations do not publish a completed alias evaluation.
Custom warning callbacks, logger/handler/filter subclasses, nonstandard streams,
custom formatters and custom counter storage are rejected before dispatch. The
bounded route supports standard Logger/RootLogger chains, NullHandler and
StreamHandler with the default message formatter, including the standard
last-resort stderr handler. Other client routes retain their configured hooks.
Configured ordinary request headers (including API authorization) are preserved.
Other platforms are explicitly unsupported by this bounded owner. There are no
redirects, retries, transport fallback or credentials in IPC files/arguments.
