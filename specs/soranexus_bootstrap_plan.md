---
title: Sora Nexus Bootstrap & Observability
summary: Operational plan for bringing the core Nexus validator cluster online before layering SoraFS and SoraNet services.
---

# Sora Nexus Bootstrap & Observability Plan

## Objectives
- Stand up the base Sora Nexus validator/observer network with governance keys, Torii APIs, and consensus monitoring.
- Validate core services (Torii, consensus, persistence) before enabling SoraFS/SoraNet piggyback deployments.
- Establish CI/CD workflows and observability dashboards/alerts to ensure network health.

## Prerequisites
- Governance key material (council multisig, committee keys) available through a qualified deployment-owned signer.
- Baseline infrastructure (Kubernetes clusters or bare-metal nodes) in primary/secondary regions.
- Reviewed mainnet and testnet profile fixtures (`configs/soranexus/nexus/config.toml` and `configs/soranexus/taira/config.toml`) reflecting the intended consensus parameters.

## Network Environments
- Operate two Nexus environments with distinct network prefixes:
- **Sora Nexus (mainnet)** – production network prefix `nexus`, hosting canonical governance and SoraFS/SoraNet piggyback services (chain ID `0x02F1` / UUID `00000000-0000-0000-0000-000000000753`).
- **Sora Taira (testnet)** – persistent public testnet with prefix `taira`, mirroring mainnet configuration for integration testing and pre-release validation (chain UUID `fc56984b-2be7-431d-840e-21514d1883f0`).
- Maintain separate genesis files, governance keys, and infrastructure footprints for each environment. Taira acts as the proving ground for all SoraFS/SoraNet rollouts before promotion to Nexus.
- Operator-owned release pipelines should deploy to Taira first, execute automated smoke tests, and require manual promotion to Nexus once checks pass. This repository ships the durable `iroha taira public-reset` coordinator for authorized reset mutations; ordinary public-node joining remains a separate signed-bootstrap workflow.
- Reference configuration bundles live under `configs/soranexus/nexus/` (mainnet) and `configs/soranexus/taira/` (testnet). Both contain `config.toml` and a non-signable `genesis.template.json`; Taira also retains `configs/soranexus/taira/sorafs_admission/`. Complete genesis manifests and Minamoto admission material remain operator-owned.

## Step 1 – Configuration Review
1. Audit existing documentation:
   - `specs/nexus.md` (consensus and Nexus architecture).
   - `specs/nexus_operations.md` (operational lifecycle and evidence requirements).
   - `specs/sora_nexus_operator_onboarding.md` (configuration, key custody, and onboarding checks).
2. Materialize `configs/soranexus/nexus/genesis.template.json` or `configs/soranexus/taira/genesis.template.json` with the network's explicit canonical XOR asset definition, inject the final ordered validator BLS topology and proofs of possession, and require exact identity, committee geometry, and staking-policy validation before signing.
3. Confirm network parameters:
   - Consensus committee size & quorum.
   - Block interval / finality thresholds.
   - Torii service ports and TLS certificates.

## Step 2 – Bootstrap Cluster Deployment
1. Provision validator nodes:
   - Deploy the Taira `iroha3d_taira` launcher (validators) with persistent volumes.
   - Ensure network firewall rules allow consensus & Torii traffic between nodes.
2. Start Torii services (REST/WebSocket) on each validator with TLS.
3. Deploy observer nodes (read-only) for extra resilience.
4. Use the operator-owned deployment pipeline to provision runtime secrets and the final signed genesis/topology, distribute per-node configs, and start `iroha3d_taira`. The dedicated permissionless-observer `iroha taira join` signed-bootstrap flow is tracked as first-release work; validator activation remains an on-chain staking and peer-lifecycle transition, not a separate admission-token bootstrap. `scripts/taira_devnet.py` is only for disposable local Taira-compatible networks and must never be presented as joining the public testnet.
5. Execute smoke tests:
   - Submit test transactions via Torii (`iroha tx submit`).
   - Verify block production/finality through telemetry.
   - Check ledger replication across validators/observers.

## Step 3 – Governance & Key Management
1. Load council multisig configuration; confirm governance proposals can be submitted and ratified.
2. Securely store consensus/committee keys; configure automatic backups with access logging.
3. Define and verify deployment-owned emergency key rotation procedures, following the change-management and evidence requirements in `specs/nexus_operations.md`.

## Step 4 – CI/CD Integration
1. Configure pipelines:
   - Build & publish validator/Torii images (GitHub Actions or GitLab CI).
   - Automated configuration validation (lint genesis, verify signatures).
   - Deployment pipelines (Helm/Kustomize) for staging & production clusters.
2. Implement smoke tests in CI (spin up ephemeral cluster, run canonical transaction suite).
3. Add rollback scripts for failed deployments and document runbooks.

## Step 5 – Observability & Alerts
1. Deploy monitoring stack (Prometheus + Grafana + Alertmanager) per region.
2. Collect core metrics:
  - `nexus_consensus_height`, `nexus_finality_lag`, `torii_request_duration_seconds`, `validator_peer_count`.
   - Logs via Loki/ELK for Torii & consensus services.
3. Dashboards:
   - Consensus health (block height, finality, peer status).
   - Torii API latency/error rates.
   - Governance transactions & proposal statuses.
4. Alerts:
   - Block production stall (>2 block intervals).
   - Peer count drop below quorum.
   - Torii error rate spikes.
   - Governance proposal queue backlog.

## Step 6 – Validation & Handoff
1. Run end-to-end validation:
   - Submit governance proposal (e.g., parameter change).
   - Process it through council approval to ensure governance pipeline works.
   - Run ledger state diff to ensure consistency.
2. Document runbook for on-call (incident response, failover, scaling).
3. Communicate readiness to SoraFS/SoraNet teams; confirm piggyback deployments can point to Nexus nodes.

## Implementation Checklist
- [ ] Genesis/configuration audit completed.
- [ ] Validator & observer nodes deployed with healthy consensus.
- [ ] Governance keys loaded, proposal tested.
- [ ] CI/CD pipelines running (build + deploy + smoke tests).
- [ ] Observability dashboards live with alerting.
- [ ] Handoff documentation delivered to downstream teams.
