//! SM Configuration Migration

# SM Configuration Migration

Rolling out the SM2/SM3/SM4 feature set requires more than compiling with the
`sm` feature flag. Nodes gate the functionality behind the layered
`iroha_config` profiles and expect the genesis manifest to carry matching
defaults. This note captures the recommended workflow when promoting an
existing network from “Ed25519-only” to “SM-enabled”.

## 1. Verify the Build Profile

- Compile the binaries with `--features sm`; add `sm-ffi-openssl` only when you
  plan to exercise the OpenSSL/Tongsuo preview path. Builds without the `sm`
  feature reject `sm2` signatures during admission even if the config enables
  them.
- Confirm CI publishes the `sm` artefacts and that all validation steps (`cargo
  test -p iroha_crypto --features sm`, integration fixtures, fuzz suites) pass
  on the exact binaries you intend to deploy.

## 2. Layer Configuration Overrides

`iroha_config` applies three tiers: `defaults` → `user` → `actual`. Ship the SM
overrides in the `actual` profile that operators distribute to validators and
leave `user` at Ed25519-only so the developer defaults remain unchanged.

```toml
# defaults/actual/config.toml
[crypto]
enable_sm_openssl_preview = false         # optional OpenSSL SM3/SM4; SM2 uses the portable relation
default_hash = "sm3-256"
allowed_signing = ["ed25519", "sm2"]      # keep sorted for deterministic manifests
sm2_distid_default = "CN12345678901234"   # organisation-specific distinguishing identifier
```

Copy the same block into the `defaults/genesis` manifest via `kagami genesis
generate …` (add `--allowed-signing sm2 --default-hash sm3-256` if you need
overrides) so the `parameters` block and injected metadata agree with the
runtime configuration. Peers refuse to start when the manifest and config
snapshots diverge.

## 3. Regenerate Genesis Manifests

- Run `kagami genesis generate --consensus-mode <mode> …` for every
  environment. Bind the final ordered validator BLS topology and proofs of
  possession before signing; the topology defines validator generation zero.
- Sign the manifest (`kagami genesis sign …`) and distribute the `.nrt` payload.
  Distribute its exact bound JSON alongside it; a `.template.json` source is
  incomplete and cannot be selected by a node.

## 4. Validate Before Traffic

- Provision a staging cluster with the new binaries and config, then verify:
  - `/status` exposes `crypto.sm_helpers_available = true` once peers restart.
  - Torii admission still rejects SM2 signatures while `sm2` is absent from
    `allowed_signing` and accepts mixed Ed25519/SM2 batches when the list
    includes both algorithms.
  - `iroha_cli tools crypto sm2 export …` round-trips key material seeded via the new
    defaults.
- Run the integration smoke scripts that cover SM2 deterministic signatures and
  SM3 hashing to confirm host/VM consistency.

## 5. Rollback Plan

- Document the reversal: remove `sm2` from `allowed_signing` and restore
  `default_hash = "blake2b-256"`. Push the change through the same `actual`
  profile pipeline so every validator flips monotonically.
- Keep the SM manifests on disk; peers that see mismatched config and genesis
  data refuse to start, which protects against partial rollbacks.
- If the OpenSSL/Tongsuo preview is involved, include the steps for disabling
  `crypto.enable_sm_openssl_preview` and removing the shared objects from the
  runtime environment.

## Reference Material

- [Public genesis reference](https://docs.iroha.tech/reference/genesis.html) –
  structure of the genesis manifest and the `crypto` block.
- [`specs/references/configuration.md`](../references/configuration.md) –
  overview of `iroha_config` sections and defaults.
- [`specs/crypto/sm_operator_rollout.md`](sm_operator_rollout.md) – end to
  end operator checklist for shipping SM cryptography.
