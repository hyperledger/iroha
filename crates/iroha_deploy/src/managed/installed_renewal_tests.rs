//! Explicit long installed acceptance of the unchanged one-day generated custody policy.
//!
//! The first renewal is due after roughly twelve hours. This case is separate from startup,
//! deployment and deep-history gates. No clock, policy, worker or consensus shortcut is used.
//! Status samples can miss a transient; unavailable IPC is never reported as Ready.

use super::super::*;
use super::attachment_installed::{original_parent, source_for};
use crate::verify::http::HttpFinalitySource;
use crate::{
    localnet::service_authorities::{StreamTokenAuthorityManifest, StreamTokenAuthorityRole},
    verify::finality::{
        AttestationOutcome, FinalitySource, FinalityVerifier, GenesisAnchor, MAX_ADVANCE_PROOFS,
    },
};
use color_eyre::eyre::{Result as TestResult, ensure, eyre};
use iroha::{client::Client, config::Config};
use iroha_crypto::HashOf;
use iroha_data_model::{
    Level,
    isi::{Log, sorafs::MutateSorafsStreamTokenCustody},
    sorafs::{
        capacity::ProviderId,
        stream_token_custody::{
            SorafsStreamTokenCustodyActionV1, StreamTokenCustodyControlRecordV1,
        },
    },
    transaction::{Executable, TransactionEntrypoint},
};
use iroha_model_base::peer::PeerId;
use sorafs_manifest::signer::{
    custody::{SIGNER_CUSTODY_MAX_BYTES_V1, SignerCustodyRecordV1},
    custody_control::{SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1, SignerCustodyPolicyV1},
};
use std::{
    collections::BTreeMap,
    num::NonZeroU64,
    path::PathBuf,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const DAY_MS: u64 = 24 * 60 * 60 * 1_000;
const STARTUP: Duration = Duration::from_secs(30);
const READ: Duration = Duration::from_secs(20);
// Three sequential ordinary turns, each capped at 120 seconds by runtime::renewal.
// This observation window does not change any worker deadline or enrollment interval.
const THREE_TURNS: Duration = Duration::from_secs(3 * 120);
const HARNESS_MAXIMUM: Duration = Duration::from_secs(13 * 60 * 60);
const READY_LOG: &str = "managed localnet readiness ";

struct Harness {
    store: ManagedStore,
    stopped: bool,
}
impl Harness {
    fn stop(&mut self) -> TestResult<()> {
        let status = self.store.down("renewal")?;
        ensure!(
            status.phase == ManagedPhase::Stopped
                && status.running_peers == 0
                && status.failure.is_none(),
            "renewal fixture did not authenticate complete shutdown"
        );
        self.stopped = true;
        Ok(())
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        if !self.stopped
            && let Err(error) = self.stop()
        {
            eprintln!(
                "renewal fixture retains custody after failed authenticated cleanup at {}: {error}",
                self.store.root().display()
            );
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PaidReadiness {
    signed: Vec<u8>,
    fee: Vec<u8>,
    committed: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Enrollment {
    signed: SignerCustodyRecordV1,
    native: StreamTokenCustodyControlRecordV1,
}

/// Only a fully verified prefix populates this evidence. Native state proofs remain fresh.
struct Ledger {
    prepared: PreparedLocalnet,
    config: Config,
    peers: Vec<PeerId>,
    anchor: GenesisAnchor,
    verifier: FinalityVerifier,
    policies: BTreeMap<ProviderId, SignerCustodyPolicyV1>,
    readiness: BTreeMap<HashOf<TransactionEntrypoint>, PaidReadiness>,
}
impl Ledger {
    fn new(prepared: &PreparedLocalnet) -> TestResult<Self> {
        let config = prepared.context.load_client_config()?;
        let (anchor, _, peers) = original_parent(prepared)?;
        let scope = iroha_genesis::signed_genesis_consensus_metadata(&anchor.genesis)?
            .sumeragi_context
            .root_scope;
        let source = source_for(prepared, &config, &peers, 1, scope)?;
        let verifier = FinalityVerifier::from_genesis(
            &anchor,
            &source.finality_proof(NonZeroU64::new(1).unwrap())?,
        )?;
        Ok(Self {
            prepared: prepared.clone(),
            config,
            peers,
            anchor,
            verifier,
            policies: BTreeMap::new(),
            readiness: BTreeMap::new(),
        })
    }

    fn clients(&self, deadline: Instant) -> TestResult<Vec<Client>> {
        self.prepared
            .peers
            .iter()
            .map(|peer| {
                let mut config = self.config.clone();
                config.torii_api_url = peer.torii_url.parse()?;
                Ok(Client::builder(config)
                    .build()?
                    .with_request_deadline(deadline))
            })
            .collect()
    }

    fn observe(&mut self, manifest: &StreamTokenAuthorityManifest) -> TestResult<[Enrollment; 3]> {
        ensure!(
            manifest.manager == self.config.account && manifest.providers.len() == 3,
            "generated manager/provider inventory changed"
        );
        let deadline = Instant::now() + READ;
        let clients = self.clients(deadline)?;
        let source = HttpFinalitySource::new(
            self.config.network_id,
            NonZeroU64::new(self.verifier.checkpoint().height()).unwrap(),
            clients.clone(),
            self.peers
                .iter()
                .cloned()
                .zip(clients.iter().cloned())
                .collect(),
            deadline,
            self.verifier.root_scope()?,
        )?;
        let mut fresh = self.verifier.clone();
        let mut report = fresh.observe(&source, &rand::random())?;
        let end = fresh.checkpoint().height();
        ensure!(
            end >= self.verifier.checkpoint().height() && end <= MAX_ADVANCE_PROOFS as u64,
            "renewal fixture exceeds its bounded complete ledger census"
        );
        // A verified lagging attestation does not promise the latest-height state is applied.
        // Keep the first certified cut fixed, and wait only for four valid attestations at or
        // beyond it, under this same observation deadline. Errors never mean absence/success.
        loop {
            ensure!(
                report.verified() == 4,
                "renewal observation lacks four original committee attestations"
            );
            if report.peers.iter().all(|(_, outcome)| matches!(outcome, AttestationOutcome::Verified(tip) if tip.height.get() >= end)) { break; }
            ensure!(
                Instant::now() < deadline,
                "committee did not apply the selected certified cut before the read deadline"
            );
            thread::sleep(
                Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now())),
            );
            // Prefix admission retains only the prior cut's immediate predecessors. Starting
            // at the new highest tip would reject a legitimate peer still two blocks behind it.
            let mut converging = self.verifier.clone();
            report = converging.observe(&source, &rand::random())?;
        }
        for height in self.verifier.checkpoint().height() + 1..=end {
            ensure!(
                Instant::now() < deadline,
                "renewal evidence census exceeded its original read deadline"
            );
            let proof = source.finality_proof(NonZeroU64::new(height).unwrap())?;
            self.verifier.advance(&source, &proof)?;
            let verified = self.verifier.verified_tip()?;
            for signed in verified.block().external_transactions() {
                if signed.authority() != &manifest.manager {
                    continue;
                }
                let Executable::Instructions(instructions) = signed.instructions() else {
                    continue;
                };
                let readiness = instructions.len() == 1
                    && instructions[0]
                        .as_any()
                        .downcast_ref::<Log>()
                        .is_some_and(|log| {
                            log.level == Level::INFO
                                && log.msg.starts_with(READY_LOG)
                                && log.msg.len() > READY_LOG.len()
                        });
                let configure = instructions
                    .iter()
                    .filter_map(|instruction| {
                        instruction
                            .as_any()
                            .downcast_ref::<MutateSorafsStreamTokenCustody>()
                    })
                    .filter(|instruction| {
                        matches!(
                            &instruction.action,
                            SorafsStreamTokenCustodyActionV1::Configure(_)
                        )
                    })
                    .collect::<Vec<_>>();
                if !readiness && configure.is_empty() {
                    continue;
                }
                let expected = signed.encode_wire_v1()?;
                let mut retained_fee = None;
                let mut retained_committed = None;
                for client in &clients {
                    let details =
                        client.get_successful_transaction_details(signed.hash_as_entrypoint())?;
                    verified.verify_committed_transaction(
                        &self.config.network_id,
                        &details.transaction,
                    )?;
                    let iroha_data_model::transaction::TransactionEntrypoint::External(actual) =
                        details.transaction.entrypoint()
                    else {
                        return Err(eyre!(
                            "renewal evidence is not the original external transaction"
                        ));
                    };
                    ensure!(
                        actual.encode_wire_v1()? == expected,
                        "peer changed the original signed transaction"
                    );
                    if readiness {
                        let fee = details
                            .transaction
                            .result()
                            .nexus_fee_receipt()
                            .ok_or_else(|| {
                                eyre!("paid readiness has no authenticated fee receipt")
                            })?;
                        fee.validate_for_network_input(details.transaction.entrypoint(), height)
                            .map_err(|error| eyre!(error))?;
                        let committed = norito::encode_canonical(&details.transaction)?;
                        ensure!(
                            retained_committed
                                .as_ref()
                                .is_none_or(|first| first == &committed),
                            "peers disagree on the exact committed readiness input and output"
                        );
                        retained_committed = Some(committed);
                        let bytes = norito::encode_canonical(fee)?;
                        ensure!(
                            retained_fee.as_ref().is_none_or(|first| first == &bytes),
                            "peers disagree on the exact paid readiness receipt"
                        );
                        retained_fee = Some(bytes);
                    }
                }
                if readiness {
                    let evidence = PaidReadiness {
                        signed: expected,
                        fee: retained_fee.ok_or_else(|| eyre!("no readiness fee observation"))?,
                        committed: retained_committed
                            .ok_or_else(|| eyre!("no readiness inclusion observation"))?,
                    };
                    ensure!(
                        self.readiness
                            .insert(signed.hash_as_entrypoint(), evidence)
                            .is_none(),
                        "duplicate readiness entry in the certified prefix"
                    );
                }
                for instruction in configure {
                    ensure!(
                        instruction.expected_revision == 0
                            && instruction.expected_digest == [0; 32],
                        "Configure replaced an existing custody policy"
                    );
                    let inventory = manifest.provider(instruction.provider_id)?;
                    let SorafsStreamTokenCustodyActionV1::Configure(bytes) = &instruction.action
                    else {
                        unreachable!()
                    };
                    ensure!(
                        bytes.len() <= SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1,
                        "custody Configure frame exceeds its native bound"
                    );
                    let policy: SignerCustodyPolicyV1 = norito::decode_canonical_with_limits(
                        bytes,
                        norito::DecodeLimits::new(
                            4096,
                            SIGNER_CUSTODY_CONTROL_MAX_BYTES_V1,
                            8192,
                            256 * 1024,
                            32,
                        ),
                    )?;
                    policy.validate()?;
                    ensure!(
                        inventory
                            .authority(StreamTokenAuthorityRole::TokenSigner)?
                            .account
                            .try_signatory()
                            == Some(&policy.binding.public_key)
                            && inventory
                                .authority(StreamTokenAuthorityRole::CustodyAttester)?
                                .account
                                .try_signatory()
                                == Some(&policy.attester_public_key),
                        "configured custody keys differ from the signed-genesis provider roles"
                    );
                    ensure!(
                        policy.max_validity_ms == DAY_MS,
                        "installed renewal must exercise the unchanged one-day generated policy"
                    );
                    ensure!(
                        self.policies
                            .insert(instruction.provider_id, policy)
                            .is_none(),
                        "provider policy was configured again"
                    );
                }
            }
        }
        ensure!(
            self.verifier.checkpoint() == fresh.checkpoint(),
            "complete ledger census differs from fresh independently observed prefix"
        );
        // Re-read every retained paid input/output on every observation, including after restart.
        // Equality is against the entire record already authenticated at its certified height,
        // not merely a status or a newly decoded, unauthenticated fee-shaped response.
        for (hash, original) in &self.readiness {
            for client in &clients {
                let current = client.get_successful_transaction_details(*hash)?;
                ensure!(
                    norito::encode_canonical(&current.transaction)? == original.committed,
                    "retained paid readiness inclusion or execution output changed"
                );
            }
        }
        ensure!(
            self.policies.len() == 3,
            "three original native Configure policies are required"
        );
        let verified = fresh.verified_tip()?;
        let schema = iroha_core::state::State::native_world_schema_hash_v1()
            .map_err(|error| eyre!(error))?;
        let mut enrollments = Vec::new();
        for provider in &manifest.providers {
            let owner = &provider
                .authority(StreamTokenAuthorityRole::IssuerOperator)?
                .account;
            let policy = self
                .policies
                .get(&provider.provider_id)
                .ok_or_else(|| eyre!("provider Configure is absent"))?;
            let mut exact = None;
            for client in &clients {
                let state = client.get_stream_token_custody_state(
                    provider.provider_id,
                    owner,
                    &policy.binding,
                    schema,
                    &verified,
                )?;
                let current = state
                    .current()
                    .ok_or_else(|| eyre!("native custody disappeared"))?;
                ensure!(
                    current.control().policy == *policy
                        && !current.control().signer_revoked
                        && !current.control().attester_revoked,
                    "current native policy or revocation changed"
                );
                current
                    .record()
                    .validate_active_enrollment(current.control())?;
                let record = current.record();
                ensure!(
                    exact.as_ref().is_none_or(|original| original == record),
                    "providers' peers disagree on the complete native custody record"
                );
                exact = Some(record.clone());
            }
            let native = exact.ok_or_else(|| eyre!("no native enrollment observation"))?;
            let bytes = native
                .active_enrollment
                .as_ref()
                .ok_or_else(|| eyre!("native active enrollment is absent"))?;
            let record: SignerCustodyRecordV1 = norito::decode_canonical_with_limits(
                bytes,
                norito::DecodeLimits::new(4096, SIGNER_CUSTODY_MAX_BYTES_V1, 8192, 256 * 1024, 16),
            )?;
            ensure!(
                record.statement.binding == policy.binding
                    && record.statement.expires_at_unix_ms > unix_ms()?,
                "enrollment binding changed or expired"
            );
            enrollments.push(Enrollment {
                signed: record,
                native,
            });
        }
        ensure!(
            Instant::now() < deadline,
            "renewal evidence arrived after its original read deadline"
        );
        enrollments
            .try_into()
            .map_err(|_| eyre!("native enrollment cardinality differs"))
    }
}

fn unix_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn midpoint(issued: u64, expires: u64) -> TestResult<u64> {
    ensure!(
        expires.checked_sub(issued) == Some(DAY_MS),
        "initial installed enrollment did not retain its full generated one-day interval"
    );
    issued
        .checked_add((expires - issued).div_ceil(2))
        .ok_or_else(|| eyre!("enrollment midpoint overflows"))
}

fn require_cycle(initial: &[Enrollment; 3], renewed: &[Enrollment; 3]) -> TestResult<()> {
    for (old, new) in initial.iter().zip(renewed) {
        let before = &old.signed.statement;
        let after = &new.signed.statement;
        ensure!(
            before.sequence == 1 && after.sequence == 2,
            "automatic renewal did not advance exactly once"
        );
        ensure!(
            after.binding == before.binding
                && after.authority == before.authority
                && after.predecessor_digest == old.signed.canonical_digest()?
                && after.issued_at_unix_ms
                    >= midpoint(before.issued_at_unix_ms, before.expires_at_unix_ms)?
                && after.expires_at_unix_ms > before.expires_at_unix_ms
                && !after.revoked,
            "renewal replaced its exact original policy, enrollment predecessor or finite interval"
        );
        ensure!(
            new.native.provider_id == old.native.provider_id
                && new.native.authority == old.native.authority
                && old.native.revision.checked_add(1) == Some(new.native.revision)
                && new.native.predecessor_digest == old.native.canonical_digest()?
                && new.native.execution_height > old.native.execution_height,
            "renewal did not extend the exact native control predecessor once"
        );
    }
    Ok(())
}

fn require_ready(status: &ManagedStatus, expected: &ManagedContext) -> TestResult<()> {
    ensure!(
        &status.context == expected
            && status.phase == ManagedPhase::Ready
            && status.running_peers == 4
            && status.failure.is_none(),
        "installed renewal did not return to the exact Ready four-peer generation"
    );
    Ok(())
}

fn exercise(harness: &mut Harness, runtime: &InstalledRuntime) -> TestResult<()> {
    let began = Instant::now();
    let request = runtime.localnet_request("renewal", STARTUP);
    let initial_status = harness.store.up(&request)?;
    ensure!(
        began.elapsed() < STARTUP,
        "ordinary initial startup exceeded 30 seconds"
    );
    let prepared = harness.store.prepared("renewal")?;
    require_ready(&initial_status, &prepared.context)?;
    let manifest = prepared
        .stream_token_authorities()?
        .ok_or_else(|| eyre!("ordinary generated service profile is absent"))?;
    let mut ledger = Ledger::new(&prepared)?;
    let initial = ledger.observe(&manifest)?;
    ensure!(
        initial
            .iter()
            .all(|value| value.signed.statement.sequence == 1),
        "fresh installed custody is not sequence one"
    );
    ensure!(
        ledger.readiness.len() == 1,
        "fresh worker must retain exactly one paid readiness transaction"
    );
    let paid = ledger.readiness.clone();
    let midpoints = initial
        .iter()
        .map(|record| {
            midpoint(
                record.signed.statement.issued_at_unix_ms,
                record.signed.statement.expires_at_unix_ms,
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    let first = *midpoints.iter().min().unwrap();
    let last = *midpoints.iter().max().unwrap();
    let wait_ms = last
        .checked_sub(unix_ms()?)
        .ok_or_else(|| eyre!("initial enrollment midpoint already passed"))?;
    let observation_end = Instant::now()
        .checked_add(Duration::from_millis(wait_ms) + THREE_TURNS)
        .ok_or_else(|| eyre!("renewal observation deadline overflows"))?;
    ensure!(
        observation_end <= began + HARNESS_MAXIMUM,
        "generated ordinary renewal exceeds the explicit long acceptance ceiling"
    );
    let mut starting_samples = 0_u64;
    let mut unavailable_samples = 0_u64;
    while Instant::now() < observation_end {
        match harness.store.status("renewal") {
            Ok(status) => {
                ensure!(
                    status.context == prepared.context && status.failure.is_none(),
                    "renewal status lost original context or reported a failure"
                );
                match status.phase {
                    ManagedPhase::Ready => {
                        ensure!(status.running_peers == 4, "Ready lost a validator")
                    }
                    ManagedPhase::Starting => {
                        ensure!(
                            unix_ms()? >= first,
                            "Ready withdrew before ordinary renewal was due"
                        );
                        starting_samples += 1;
                    }
                    _ => {
                        return Err(eyre!(
                            "renewal stopped or failed before the original cycle completed"
                        ));
                    }
                }
            }
            Err(Error::Busy(name)) if name == "renewal" && unix_ms()? >= first => {
                unavailable_samples += 1
            }
            Err(error) => return Err(error.into()),
        }
        let now = unix_ms()?;
        let cadence = if now.saturating_add(30_000) < first {
            Duration::from_secs(30)
        } else {
            Duration::from_millis(50)
        };
        thread::sleep(cadence.min(observation_end.saturating_duration_since(Instant::now())));
    }
    require_ready(&harness.store.status("renewal")?, &prepared.context)?;
    let renewed = ledger.observe(&manifest)?;
    require_cycle(&initial, &renewed)?;
    ensure!(
        ledger.readiness == paid,
        "automatic renewal/restart added or changed a paid readiness transaction"
    );
    // These are sampled observations only: zero does not prove Ready stayed continuous.
    // The certified sequence/native predecessor and final Ready checks prove the actual cycle.
    eprintln!(
        "INSTALLED_RENEWAL sequence=2 providers=3 starting_samples={starting_samples} unavailable_samples={unavailable_samples}"
    );

    harness.stop()?;
    let stopped_prepared = harness.store.prepared("renewal")?;
    ensure!(
        stopped_prepared == prepared,
        "normal stop replaced the retained generation"
    );
    harness.stopped = false;
    let restart = Instant::now();
    let restarted = harness.store.up_retained(&request, &prepared.context)?;
    ensure!(
        restart.elapsed() < STARTUP,
        "ordinary retained restart exceeded 30 seconds"
    );
    require_ready(&restarted, &prepared.context)?;
    ensure!(
        harness.store.prepared("renewal")? == prepared,
        "normal restart replaced original generated identity"
    );
    let reopened = ledger.observe(&manifest)?;
    ensure!(
        reopened == renewed,
        "manual restart changed exact current enrollment bytes or sequence"
    );
    ensure!(
        ledger.readiness.len() == paid.len() + 1
            && paid
                .iter()
                .all(|(hash, original)| ledger.readiness.get(hash) == Some(original)),
        "new worker must preserve original paid evidence and create only its own one readiness transaction"
    );
    ensure!(
        ledger.anchor.network_id.to_string() == prepared.context.network_id,
        "restart changed genesis-bound network"
    );
    Ok(())
}

/// Wait for the ordinary default-policy midpoint; never shorten enrollment or move native time.
#[test]
#[ignore = "requires matching installed Kagami/iroha3d, four real validators and about 12 hours for the unchanged generated renewal policy"]
fn installed_default_custody_renews_three_providers_and_preserves_paid_restart_evidence() {
    let _resources = super::super::native_test_guard();
    let directory = PathBuf::from(
        std::env::var_os("IROHA_TEST_RUNTIME_DIRECTORY")
            .expect("set matching installed runtime directory"),
    );
    let runtime = InstalledRuntime::from_directory(&directory).unwrap();
    let root = tempfile::Builder::new()
        .prefix("iroha-installed-renewal-")
        .tempdir()
        .unwrap()
        .keep();
    let store = ManagedStore::open(&root.join("managed")).unwrap();
    let mut harness = Harness {
        store,
        stopped: false,
    };
    let result = exercise(&mut harness, &runtime);
    let cleanup = harness.stop();
    if let Err(error) = cleanup {
        panic!(
            "authenticated renewal cleanup failed; execution={result:?}; retained owner-private diagnostics at {}: {error}",
            root.display()
        );
    }
    result.unwrap_or_else(|error| {
        panic!(
            "installed renewal failed; retained owner-private diagnostics at {}: {error}",
            root.display()
        )
    });
    eprintln!("INSTALLED_RENEWAL_PASSED_STOPPED={}", root.display());
}

#[test]
fn ordinary_midpoint_requires_the_unchanged_finite_one_day_interval() {
    assert_eq!(midpoint(17, 17 + DAY_MS).unwrap(), 17 + DAY_MS / 2);
    for (issued, expires) in [
        (17, 17),
        (17, 16),
        (17, 17 + DAY_MS - 1),
        (17, 17 + DAY_MS + 1),
        (u64::MAX, u64::MAX),
    ] {
        assert!(midpoint(issued, expires).is_err());
    }
}

// Codec/comparison fixtures only. These signatures and canonical digests exercise the exact two
// predecessor domains; synthetic block anchors never become native finality or custody authority.
fn comparison_cycle() -> ([Enrollment; 3], [Enrollment; 3]) {
    use iroha_crypto::{Algorithm, KeyPair, Signature};
    use iroha_data_model::account::AccountId;
    use sorafs_manifest::signer::{
        custody::{
            SIGNER_CUSTODY_MAGIC_V1, SIGNER_CUSTODY_VERSION_V1, SignerCustodyActiveHeadV1,
            SignerCustodyAnchorV1, SignerCustodyAuthorityV1, SignerCustodyBindingV1,
            SignerCustodyStatementV1,
        },
        custody_control::SignerCustodyControlStateV1,
        protocol::{SignerKeyAlgorithmV1, SignerPurposeBindingV1, SignerRoleV1},
    };
    let signer = KeyPair::from_seed(vec![51; 32], Algorithm::Ed25519);
    let attester = KeyPair::from_seed(vec![52; 32], Algorithm::Ed25519);
    let manager = AccountId::new(
        KeyPair::from_seed(vec![53; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let make = |slot: usize| {
        let provider = [u8::try_from(slot + 1).unwrap(); 32];
        let policy = SignerCustodyPolicyV1 {
            binding: SignerCustodyBindingV1 {
                chain_id: "renewal-comparison".into(),
                network_id: [7; 32],
                runtime_handle: "software://comparison/runtime".into(),
                key_handle: "software://comparison/key".into(),
                service_id: "comparison-signer".into(),
                administrator_id: "comparison-signer-admin".into(),
                role: SignerRoleV1::StreamToken,
                purpose: SignerPurposeBindingV1::StreamToken {
                    provider_id: provider,
                },
                algorithm: SignerKeyAlgorithmV1::Ed25519,
                public_key: signer.public_key().clone(),
                key_revision: 1,
                policy_revision: 1,
                policy_digest: [4; 32],
            },
            attester_authority: SignerCustodyAuthorityV1 {
                service_id: "comparison-attester".into(),
                administrator_id: "comparison-attester-admin".into(),
                key_revision: 1,
                policy_revision: 1,
                policy_digest: [5; 32],
            },
            attester_public_key: attester.public_key().clone(),
            active_from_unix_ms: 1,
            active_until_unix_ms: 3 * DAY_MS,
            max_validity_ms: DAY_MS,
            max_anchor_age_ms: 300_000,
        };
        policy.validate().unwrap();
        let enrollment = |sequence: u64,
                          predecessor_digest: [u8; 32],
                          issued: u64,
                          native_predecessor: [u8; 32]| {
            let statement = SignerCustodyStatementV1 {
                magic: SIGNER_CUSTODY_MAGIC_V1,
                version: SIGNER_CUSTODY_VERSION_V1,
                binding: policy.binding.clone(),
                authority: policy.attester_authority.clone(),
                anchor: SignerCustodyAnchorV1 {
                    height: sequence + 2,
                    block_hash: [8; 32],
                    state_digest: native_predecessor,
                },
                sequence,
                predecessor_digest,
                issued_at_unix_ms: issued,
                expires_at_unix_ms: issued + DAY_MS,
                evidence_digest: [6; 32],
                revoked: false,
            };
            let attestation = Signature::new(
                attester.private_key(),
                &statement.signing_payload().unwrap(),
            )
            .payload()
            .try_into()
            .unwrap();
            let record = SignerCustodyRecordV1 {
                statement,
                attestation,
            };
            let digest = record.canonical_digest().unwrap();
            let control = SignerCustodyControlStateV1 {
                policy: policy.clone(),
                next_sequence: sequence + 1,
                predecessor_digest: digest,
                active_head: Some(SignerCustodyActiveHeadV1 {
                    sequence,
                    record_digest: digest,
                    approved_anchor: record.statement.anchor,
                    key_revision: policy.binding.key_revision,
                    policy_revision: policy.binding.policy_revision,
                    policy_digest: policy.binding.policy_digest,
                }),
                signer_revoked: false,
                attester_revoked: false,
            };
            control.validate().unwrap();
            let native = StreamTokenCustodyControlRecordV1 {
                provider_id: ProviderId::new(provider),
                revision: sequence + 1,
                predecessor_digest: native_predecessor,
                request_digest: [9; 32],
                execution_height: sequence + 3,
                ordinal: 0,
                recorded_at_unix_ms: issued + 1,
                authority: manager.clone(),
                control_state: norito::encode_canonical(&control).unwrap(),
                active_enrollment: Some(norito::encode_canonical(&record).unwrap()),
            };
            native.validate_active_enrollment(&control).unwrap();
            Enrollment {
                signed: record,
                native,
            }
        };
        let initial = enrollment(1, [0; 32], 1_000, [10; 32]);
        let renewed = enrollment(
            2,
            initial.signed.canonical_digest().unwrap(),
            1_000 + DAY_MS / 2,
            initial.native.canonical_digest().unwrap(),
        );
        (initial, renewed)
    };
    let pairs = std::array::from_fn::<_, 3, _>(make);
    (pairs.clone().map(|pair| pair.0), pairs.map(|pair| pair.1))
}

#[test]
fn renewal_comparison_accepts_exact_distinct_signed_and_native_predecessors() {
    let (initial, renewed) = comparison_cycle();
    for (old, new) in initial.iter().zip(&renewed) {
        assert_ne!(
            old.signed.canonical_digest().unwrap(),
            old.native.canonical_digest().unwrap()
        );
        assert_eq!(
            new.signed.statement.predecessor_digest,
            old.signed.canonical_digest().unwrap()
        );
        assert_eq!(
            new.native.predecessor_digest,
            old.native.canonical_digest().unwrap()
        );
    }
    require_cycle(&initial, &renewed).unwrap();
}

#[test]
fn renewal_comparison_refuses_each_predecessor_and_binding_substitution() {
    type Mutation = fn(&mut Enrollment);

    let (initial, renewed) = comparison_cycle();
    let mutations: [(Mutation, &str); 7] = [
        (
            |row| row.signed.statement.predecessor_digest[0] ^= 1,
            "enrollment predecessor",
        ),
        (
            |row| row.native.predecessor_digest[0] ^= 1,
            "native control predecessor",
        ),
        (
            |row| row.signed.statement.binding.policy_digest[0] ^= 1,
            "enrollment predecessor",
        ),
        (
            |row| row.signed.statement.binding.network_id[0] ^= 1,
            "enrollment predecessor",
        ),
        (
            |row| row.native.provider_id = ProviderId::new([99; 32]),
            "native control predecessor",
        ),
        (
            |row| row.signed.statement.sequence += 1,
            "advance exactly once",
        ),
        (|row| row.native.revision += 1, "native control predecessor"),
    ];
    for (mutate, expected) in mutations {
        let mut changed = renewed.clone();
        mutate(&mut changed[1]);
        let error = require_cycle(&initial, &changed).unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "wrong comparison refusal: {error}"
        );
        require_cycle(&initial, &renewed).unwrap();
    }
    // Swapping the two valid digest domains is also a failure, not merely a random bad digest.
    let mut signed_swapped = renewed.clone();
    signed_swapped[0].signed.statement.predecessor_digest =
        initial[0].native.canonical_digest().unwrap();
    assert!(
        require_cycle(&initial, &signed_swapped)
            .unwrap_err()
            .to_string()
            .contains("enrollment predecessor")
    );
    let mut native_swapped = renewed.clone();
    native_swapped[0].native.predecessor_digest = initial[0].signed.canonical_digest().unwrap();
    assert!(
        require_cycle(&initial, &native_swapped)
            .unwrap_err()
            .to_string()
            .contains("native control predecessor")
    );
}
