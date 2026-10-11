# Kagami Iroha3 Profiles

Kagami ships presets for Iroha 3 networks so operators can stamp deterministic
genesis manifests without juggling per-network knobs.

- Profiles: `iroha3-dev` uses chain `iroha3-dev.local` and derives its VRF seed
  from the chain id when NPoS is selected. `iroha3-taira` uses the live chain
  `fc56984b-2be7-431d-840e-21514d1883f0`; `iroha3-nexus` uses the public
  Minamoto/Nexus chain `00000000-0000-0000-0000-000000000753`. Both public profiles require NPoS and an explicit
  `--vrf-seed-hex`. Profile chain identities are immutable: an explicit
  `--chain-id` is accepted only when it exactly repeats the profile's pinned id.
- Consensus: Sora profile networks (Nexus + dataspaces) require NPoS and disallow staged cutovers; permissioned Iroha3 deployments must run without a Sora profile.
- Generation: `cargo run -p iroha_kagami -- genesis generate --profile <profile> --ivm-dir . --genesis-public-key <pk> --consensus-mode <npos|permissioned> [--vrf-seed-hex <hex>] [--xor-asset-definition-id <BASE58>]`. Use `--consensus-mode npos` for Taira and Nexus; `--vrf-seed-hex` is required for both public profiles. Public Taira defaults `xor#universal` to the live canonical XOR id `6TEAJqbb8oEPmLncoNiMRbLEK6tw`; public Nexus requires `--xor-asset-definition-id` because the canonical Nexus XOR id is operator-supplied.
- Verification: `cargo run -p iroha_kagami -- verify --profile <profile> --genesis <path> [--vrf-seed-hex <hex>]` replays profile expectations for chain id, cadence, consensus mode and VRF seed, PoP coverage, and the normalized consensus fingerprint. Supply `--vrf-seed-hex` only when verifying an NPoS manifest for taira/nexus.
- Signed fixture bundles pass an explicit `--creation-time-ms` to `kagami genesis sign`; this fixes transaction and block timestamps so repeated profile generation produces identical `genesis.signed.nrt` bytes.
- Every generated validator config renders only the node-local `[sumeragi]` role. Committee geometry, block limits, and payload limits come from signed genesis and committed state; the node rejects retired `sumeragi.queues` and `sumeragi.block` tables.
- Topology: the Nexus/Minamoto fixture renders `core`, `governance`, and `zk`
  lanes in the single `universal` dataspace. Namespace text remains a separate
  binding layer and is never promoted into either catalog.
- Disposable Taira: use
  `python3 scripts/taira_devnet.py up --inrou-canary-dir <owner-only-workspace>`, inspect it with
  `python3 scripts/taira_devnet.py check`, and remove it with
  `python3 scripts/taira_devnet.py down`. This is the only repository-owned
  disposable Taira deployment workflow.
- Profile sources: `defaults/kagami/iroha3-{dev,nexus}/` contains incomplete
  `genesis.template.json` sources plus non-secret topology/configuration scaffolding, not runnable
  signed bundles. Materialize complete operator-owned output with
  `cargo xtask kagami-profiles --xor-allocations-dir <ALLOCATIONS> --genesis-creation-time-ms <MILLISECONDS> [--profile <name>|all] [--out <private-dir>] [--kagami <bin>] [--nexus-xor-asset-definition-id <BASE58>]`. The Nexus flag is required when generating `iroha3-nexus` or `all`. The narrower `scripts/kagami_profile_owner.py` accepts only `iroha3-dev` and forwards the reviewed allocation directory and required creation time to the exact built xtask and Kagami.
- Mochi: `mochi [--workspace <DIRECTORY>]` opens the shared Kagami developer workspace. The desktop starts managed localnets without supplied TOML files; it accepts no genesis-profile or VRF-seed CLI arguments.

Generated bundles embed BLS PoPs alongside topology entries, so `kagami verify`
can validate the complete operator-owned output. Adjust the
trusted peers and ports before materialization when preparing a deployment.

The profile generator requires `--xor-allocations-dir <DIR>`. Each
`<profile>.json` allocation file contains
`version: 1`, the exact committed `asset_definition_id`, and `allocations` sorted
by canonical account identity, each with `account` and positive exact `amount`.
Every generated validator must be explicitly allocated at least its 10,000 XOR
genesis self bond. These are reviewed genesis allocations; neither genesis signing
nor localnet startup mints missing balances. Nexus requires its operator-provisioned
mainnet XOR identity and rejects the Taira definition.

The creation time is one canonical nonzero `u64` in milliseconds, supplied exactly
once, and fixes the signed genesis identity across repeated generations. Load uses
normal block transactions; profile generation provisions no separate publisher
service or issuer keys. Every generated peer configuration is parsed normally and
must reproduce the authenticated signed genesis before the bundle is published.
