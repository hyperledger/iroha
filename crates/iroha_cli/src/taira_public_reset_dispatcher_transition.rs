//! Reversible replacement of the fixed dispatcher after a sealed occupied deployment.
//!
//! This Linux owner changes the guest dispatcher and its four validator guards.
//! The native Mac custodian remains independently admitted through the required
//! signed host-pair capture and candidate.
// The root transaction runs on Linux only; other platforms compile these items solely for their
// unit tests, which do not reach every Linux entry point.
#![cfg_attr(all(test, not(target_os = "linux")), allow(dead_code))]
#[cfg(any(target_os = "linux", test))]
use super::super::{Value, validate_absolute_normal_path, validate_lower_hex};
use super::*;

// Admission and storage own the root-only Linux transaction; `run` fails closed elsewhere.
#[cfg(any(target_os = "linux", test))]
#[path = "taira_public_reset_dispatcher_transition_admission.rs"]
mod admission;
#[path = "taira_public_reset_dispatcher_transition_prepare.rs"]
pub(in super::super) mod prepare;
#[cfg(any(target_os = "linux", test))]
#[path = "taira_public_reset_dispatcher_transition_storage.rs"]
mod storage;
#[cfg(test)]
#[path = "taira_public_reset_dispatcher_transition_tests.rs"]
mod tests;

#[cfg(any(target_os = "linux", test))]
const CONTROL: &str = "/var/lib/taira/.public-reset-control-v1";
#[cfg(any(target_os = "linux", test))]
const RUNTIME: &str = "/private/runtime/taira-public-reset";
#[cfg(any(target_os = "linux", test))]
const SCHEMA: &str = "iroha.taira.dispatcher-transition.v1";
#[cfg(any(target_os = "linux", test))]
const MAX_PROOF: u64 = 16 * 1024 * 1024;
#[cfg(any(target_os = "linux", test))]
const MAX_BINARY: u64 = 512 * 1024 * 1024;
#[cfg(any(target_os = "linux", test))]
const SLUGS: [&str; 4] = [
    "taira-validator-1",
    "taira-validator-2",
    "taira-validator-3",
    "taira-validator-4",
];

/// Inspect, apply, or reverse an exact root-owned dispatcher transition.
#[derive(clap::Args, Debug)]
pub(in super::super) struct DispatcherTransition {
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    expected_plan_sha256: String,
    #[arg(long, value_enum)]
    action: Action,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Action {
    Check,
    Apply,
    Rollback,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Pin {
    path: String,
    sha256: String,
    size: u64,
    mode: u32,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Candidate {
    commit: String,
    tree: String,
    signer_fingerprint: String,
    revision: super::super::RevisionV1,
    executable: Pin,
    native_edge_candidate: super::super::host_pair::SignedNativeEdgeCandidateV1,
    preparation: Pin,
    request: Pin,
    checks: Pin,
    capture: Pin,
    transfer_request: Pin,
    transfer_completed: Pin,
    binary_transfer: Pin,
    source_transfer: Pin,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct DirectoryIdentity {
    path: String,
    device: u64,
    inode: u64,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Selector {
    path: String,
    target: String,
    device: u64,
    inode: u64,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct OccupiedRole {
    slug: String,
    state: DirectoryIdentity,
    selector: Selector,
    /// Exact current daemon/configuration/genesis/hash/unit or edge CLI/config/unit files.
    files: Vec<Pin>,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Predecessor {
    inventory_sha256: String,
    authorization_sha256: String,
    authorization_nonce: String,
    /// Independently authenticated native Mac predecessor; never part of guest role files.
    native_edge_capture: super::super::host_pair::SignedNativeEdgeCaptureV1,
    /// The selected host session ended with a complete native rollback.
    rolled_back: bool,
    /// Explicit fresh-reset takeover retains the unresolved original journal verbatim.
    /// When present, `completed` pins the genuine deployment-proven boundary instead.
    #[norito(required)]
    unresolved_journal: Option<Pin>,
    completed_next_step: u16,
    sealed_forward_ordinal: u16,
    completed: Pin,
    lease: Pin,
    progress: Pin,
    dispatcher: Pin,
    guards: Vec<Pin>,
    occupied: Vec<OccupiedRole>,
}
#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct Plan {
    schema: String,
    operation_id: String,
    host_identity_sha256: String,
    hosts: super::super::host_pair::ResetHostPairV1,
    trusted_public_key: Pin,
    candidate: Candidate,
    predecessor: Predecessor,
}

#[cfg(any(target_os = "linux", test))]
fn need(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(eyre!("dispatcher transition: {message}"))
    }
}
#[cfg(any(target_os = "linux", test))]
fn operation_root(plan: &Plan) -> PathBuf {
    Path::new(RUNTIME)
        .join("dispatcher-transitions")
        .join(&plan.operation_id)
}
#[cfg(any(target_os = "linux", test))]
fn coordination_root(plan: &Plan) -> PathBuf {
    Path::new(CONTROL)
        .join("hosts")
        .join(&plan.host_identity_sha256)
}

impl DispatcherTransition {
    /// Run before loading any ledger credentials. No SSH or service mutation is performed.
    pub(in super::super) fn run<W: Write>(&self, output: &mut W) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = output;
            return Err(eyre!("dispatcher transition requires Linux"));
        }
        #[cfg(target_os = "linux")]
        {
            need(rustix::process::geteuid().as_raw() == 0, "root is required")?;
            require_lower_sha256(&self.expected_plan_sha256, "transition plan digest")?;
            let (plan, bytes) =
                read_private_json::<Plan>(&self.plan, "dispatcher transition plan")?;
            need(
                sha256_hex(&bytes) == self.expected_plan_sha256,
                "plan digest differs",
            )?;
            admission::validate_plan(&plan)?;
            let locks = admission::locks(&plan)?;
            let held = admission::admit(&plan)?;
            let root = operation_root(&plan);
            let new_guards = admission::new_guards(&plan, &root)?;
            if self.action != Action::Check {
                storage::transition(&plan, &bytes, &root, &new_guards, self.action, || {
                    locks.revalidate()?;
                    admission::revalidate(&plan, &held)
                })?;
            } else {
                storage::check(&plan, &bytes, &root, &new_guards)?;
            }
            locks.revalidate()?;
            admission::revalidate(&plan, &held)?;
            let guard_rows: Vec<Value> = SLUGS
                .iter()
                .zip(&new_guards)
                .enumerate()
                .map(|(index, (slug, bytes))| {
                    let upload_guard_sha256 = if self.action == Action::Rollback {
                        plan.predecessor.guards[index].sha256.clone()
                    } else {
                        sha256_hex(bytes)
                    };
                    norito::json!({
                        "host_slug": (*slug),
                        "upload_guard_sha256": upload_guard_sha256,
                    })
                })
                .collect();
            let action = match self.action {
                Action::Check => "check",
                Action::Apply => "apply",
                Action::Rollback => "rollback",
            };
            let guard_state = if self.action == Action::Check {
                "candidate_target"
            } else {
                "observed_result"
            };
            let result = norito::json!({
                "schema": "iroha.taira.dispatcher-transition-result.v1",
                "plan_sha256": (self.expected_plan_sha256),
                "operation_id": (plan.operation_id),
                "candidate_commit": (plan.candidate.commit),
                "action": action,
                "guards": guard_rows,
                "guard_state": guard_state,
                "runtime_and_history_preserved": true,
                "ledger_mutated": false,
            });
            writeln!(output, "{}", json::to_json(&result)?)?;
            Ok(())
        }
    }
}
