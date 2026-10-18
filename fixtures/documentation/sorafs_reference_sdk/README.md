# SoraFS Reference SDK Cookbook

This cookbook runs the committed SF-11 reference validator fixtures end to end.
It is intended for SDK authors, release smoke tests, and operator CI jobs that
need stable `ValidationOutcomeV1` examples without writing custom harness code.

Run it from the repository root:

```sh
CARGO_INCREMENTAL=0 \
CARGO_TARGET_DIR=/tmp/iroha-sorafs-reference-sdk \
fixtures/documentation/sorafs_reference_sdk/run_reference_sdk_cookbook.sh \
  --out /tmp/sorafs-reference-sdk-cookbook
```

The script writes one JSON outcome per scenario into the output directory and
fails if any outcome is not `Ok`.

A successful local replay verifies only the committed fixture and validator
surfaces. It is not evidence of clean ABI-30 builds for all five native release
targets, skip-free SDK parity, published packages, external software signing, a
qualified provider deployment, or L1/L2 promotion.

Covered scenarios:

- provider advert validation
- provider admission envelope, renewal, and revocation validation
- bare replication order validation
- signed replication order generation and validation
- orderbook settlement receipt validation
- PoR challenge/proof validation
- PoTR receipt validation
- repair task validation
- governance log node validation
- Ed25519 signing for advert/order/governance payloads
- fixture bundle cross-link validation
- trustless manifest/CAR replay via `soranet_trustless_verifier`

By default the script builds the local binaries with Cargo. To use prebuilt
release binaries instead, set:

```sh
IROHA_CLI_BIN=/path/to/iroha \
SORANET_TRUSTLESS_VERIFIER_BIN=/path/to/soranet_trustless_verifier \
fixtures/documentation/sorafs_reference_sdk/run_reference_sdk_cookbook.sh
```

The demo signing seeds are fixture-only values used to exercise the signing
surface. Production runs must pass runtime-managed keys instead of copying these
example values.
