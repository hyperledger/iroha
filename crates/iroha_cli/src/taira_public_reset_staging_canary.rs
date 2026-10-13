//! Native private candidate canary with immutable operator identity and a durable journal.
//!
//! This command proves three ordered writes on a separate generated network. Its identity
//! is private operator custody, never a signed public deployment authorization or a release
//! qualification. It cannot invoke installed dispatchers, units, edge routes, or SSH.

#[cfg(any(target_os = "linux", all(test, unix)))]
use super::host::{CoreWriteIdentity, PreparedMutationLifetimeCheck, RetainedPreparedMutation};
#[cfg(target_os = "linux")]
use super::host::{CoreWriteTransport, PreparedMutationOutcome, ProcessOutput, RealProcessRunner};
use super::runtime_clients::StagedRuntimeArgs;
#[cfg(target_os = "linux")]
use super::runtime_clients::{StagedRuntimeLayout, StagedRuntimeRoot};
use super::*;
#[cfg(target_os = "linux")]
use iroha_data_model::NetworkId;
#[cfg(any(target_os = "linux", all(test, unix)))]
use iroha_data_model::transaction::FeePaymentIntent;
#[cfg(target_os = "linux")]
use std::{
    ffi::OsString,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
const ADMISSION_SCHEMA: &str = "iroha.taira.private-stage.canary-identity.v1";
#[cfg(any(target_os = "linux", all(test, unix)))]
const PREPARED_SCHEMA: &str = "iroha.taira.private-stage.prepared-mutation.v1";
#[cfg(any(target_os = "linux", all(test, unix)))]
const STATE_SCHEMA: &str = "iroha.taira.private-stage.prepared-mutation-state.v1";
#[cfg(any(target_os = "linux", all(test, unix)))]
const PHASE: &str = "pre_edge";
#[cfg(any(target_os = "linux", all(test, unix)))]
const KINDS: [&str; 3] = ["onboarding", "faucet", "write_canary"];

/// Coordinate three exact write children on one independent private candidate.
#[derive(clap::Args, Debug)]
pub(super) struct StageCanary {
    #[command(flatten)]
    staging: StagedRuntimeArgs,
    /// Exact native public-input bundle for this freshly generated candidate.
    #[arg(long, value_name = "DIR")]
    public_inputs_dir: PathBuf,
    /// Native generated private canary client, beneath the selected candidate root.
    #[arg(long, value_name = "PATH")]
    client_config: PathBuf,
    /// Runtime-only token; read-only recovery neither requires nor opens it.
    #[arg(long, value_name = "PATH", required_unless_present = "recover")]
    onboarding_token_file: Option<PathBuf>,
    /// Independently selected canonical faucet authority.
    #[arg(long)]
    faucet_authority: String,
    /// Independently selected canonical fee asset definition.
    #[arg(long)]
    faucet_asset_id: String,
    /// Independently selected exact positive faucet amount.
    #[arg(long)]
    faucet_amount: String,
    /// Explicit private-stage fee payer selection.
    #[arg(long, value_enum)]
    stage_fee_payer: crate::FeePayerArg,
    /// Exact immutable sponsor program when the stage fee payer is sponsor.
    #[arg(long)]
    stage_fee_program: Option<String>,
    /// Exact nonzero sponsor revision when the stage fee payer is sponsor.
    #[arg(long)]
    stage_fee_program_revision: Option<u64>,
    /// Immutable 32-character operator nonce; all retries use the same value.
    #[arg(long, value_parser = crate::taira::validate_authorization_nonce_argument)]
    stage_nonce: String,
    /// Immutable earliest transaction creation instant for this stage identity.
    #[arg(long)]
    execution_not_before_unix_ms: u64,
    /// Immutable execution expiry; expired envelopes remain available for read-only recovery.
    #[arg(long)]
    execution_expires_at_unix_ms: u64,
    /// Observe retained envelopes only; never prepare or dispatch another transaction.
    #[arg(long)]
    recover: bool,
    /// Per-operation observation budget; no fault or regression prerequisite.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..))]
    timeout_secs: u64,
    /// Emit one explicit private-stage result.
    #[arg(long)]
    json: bool,
}

#[cfg(any(target_os = "linux", all(test, unix)))]
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct FileIdentityV1 {
    path: String,
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    uid: u32,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(any(target_os = "linux", all(test, unix)))]
impl FileIdentityV1 {
    fn from_pin(input: &PinnedInput) -> Result<Self> {
        revalidate_pinned(input, "private-stage input")?;
        Ok(Self {
            path: input
                .path
                .to_str()
                .ok_or_else(|| eyre!("stage input path is not UTF-8"))?
                .into(),
            device: input.snapshot.dev,
            inode: input.snapshot.ino,
            length: input.snapshot.len,
            mode: input.snapshot.mode,
            uid: input.snapshot.uid,
            ctime: input.snapshot.ctime,
            ctime_nsec: input.snapshot.ctime_nsec,
        })
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct StageIdentityV1 {
    schema: String,
    staging_root: String,
    root_device: u64,
    root_inode: u64,
    journal_device: u64,
    journal_inode: u64,
    api_base_port: u16,
    p2p_base_port: u16,
    origin: String,
    public_inputs_dir: String,
    network_id: NetworkId,
    genesis_hash: String,
    signed_genesis_sha256: String,
    raw_manifest_sha256: String,
    genesis_public_key: PublicKey,
    canary_public_key: PublicKey,
    onboarding_request: AccountOnboardingPlanRequestV1,
    client: FileIdentityV1,
    onboarding_token: FileIdentityV1,
    executable: FileIdentityV1,
    journal_lock: FileIdentityV1,
    faucet_authority: String,
    faucet_asset_id: String,
    faucet_amount: String,
    fee_payment: FeePaymentIntent,
    nonce: String,
    not_before_unix_ms: u64,
    execution_expires_at_unix_ms: u64,
}

#[cfg(any(target_os = "linux", all(test, unix)))]
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct StagePreparedV1 {
    schema: String,
    stage_identity_sha256: String,
    kind: String,
    phase: String,
    idempotency_key: String,
    operation: String,
    prepared_base64: String,
    prepared_sha256: String,
    transaction_hash: String,
}

#[cfg(any(target_os = "linux", all(test, unix)))]
#[derive(Clone, Debug, PartialEq, Eq, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct StageStateV1 {
    schema: String,
    stage_identity_sha256: String,
    authorization_sha256: String,
    authorization_nonce: String,
    kind: String,
    phase: String,
    idempotency_key: String,
    prepared_sha256: String,
    transaction_hash: String,
    state: String,
    evidence_sha256: String,
}

/// A held owner-only directory; legitimate child publication does not change its identity.
#[cfg(any(target_os = "linux", all(test, unix)))]
struct StageDirectory {
    path: PathBuf,
    file: File,
    device: u64,
    inode: u64,
}

#[cfg(any(target_os = "linux", all(test, unix)))]
impl StageDirectory {
    fn open(path: &Path) -> Result<Self> {
        validate_owner_private_dir(path, "stage canary journal")?;
        let file = File::from(rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        let metadata = file.metadata()?;
        let held = Self {
            path: path.to_path_buf(),
            file,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        held.check()?;
        Ok(held)
    }
    fn check(&self) -> Result<()> {
        validate_owner_private_dir(&self.path, "stage canary journal")?;
        for metadata in [fs::symlink_metadata(&self.path)?, self.file.metadata()?] {
            if !metadata.is_dir()
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o7777 != 0o700
            {
                return Err(eyre!("stage canary journal directory was substituted"));
            }
        }
        Ok(())
    }
    fn publish(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.check()?;
        host::publish_private_noreplace(&self.path, name, bytes)?;
        self.check()
    }
    #[cfg(target_os = "linux")]
    fn clone_held(&self) -> Result<Self> {
        self.check()?;
        Ok(Self {
            path: self.path.clone(),
            file: self.file.try_clone()?,
            device: self.device,
            inode: self.inode,
        })
    }
}

#[cfg(any(target_os = "linux", all(test, unix)))]
struct StageLock(PinnedInput);
#[cfg(any(target_os = "linux", all(test, unix)))]
impl Drop for StageLock {
    fn drop(&mut self) {
        let _ = self.0.file.unlock();
    }
}

#[cfg(any(target_os = "linux", all(test, unix)))]
impl StageLock {
    fn open(directory: &StageDirectory) -> Result<Self> {
        directory.check()?;
        let path = directory.path.join("canary.lock");
        let file = File::from(rustix::fs::openat(
            &directory.file,
            "canary.lock",
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o600),
        )?);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(eyre!("stage journal lock has unsafe custody"));
        }
        file.try_lock()
            .wrap_err("another native stage canary holds this journal")?;
        let lock = Self(PinnedInput {
            path,
            snapshot: file_snapshot(&metadata)?,
            file,
        });
        revalidate_pinned(&lock.0, "stage journal lock")?;
        Ok(lock)
    }
    fn check(&self) -> Result<()> {
        revalidate_pinned(&self.0, "stage journal lock")
    }
}

#[cfg(target_os = "linux")]
struct NativeStageTransport {
    layout: StagedRuntimeLayout,
    root: StagedRuntimeRoot,
    journal: StageDirectory,
    _lock: StageLock,
    identity: CoreWriteIdentity,
    admission: StageIdentityV1,
    client: PinnedInput,
    token: Option<PinnedInput>,
    executable: PinnedInput,
    fee_args: Vec<OsString>,
    runner: RealProcessRunner,
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn json_line<T: JsonSerialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn stage_key(identity: &CoreWriteIdentity, kind: &str) -> String {
    host::child_mutation_idempotency_key(&identity.authorization_nonce, PHASE, kind)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn validate_child(identity: &CoreWriteIdentity, kind: &str, phase: &str, key: &str) -> Result<()> {
    if !KINDS.contains(&kind) || phase != PHASE || key != stage_key(identity, kind) {
        return Err(eyre!(
            "stage canary child is outside its exact three-operation identity"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_stage_prepared(
    directory: &StageDirectory,
    identity: &CoreWriteIdentity,
    kind: &str,
) -> Result<Option<(StagePreparedV1, RetainedPreparedMutation)>> {
    directory.check()?;
    let path = directory.path.join(format!("{kind}.prepared.json"));
    if !path.try_exists()? {
        return Ok(None);
    }
    let (record, bytes) = read_private_json::<StagePreparedV1>(&path, "stage prepared mutation")?;
    if bytes != json_line(&record)?
        || record.schema != PREPARED_SCHEMA
        || record.stage_identity_sha256 != identity.authorization_sha256
    {
        return Err(eyre!(
            "stage prepared record is not canonical or belongs to another stage"
        ));
    }
    validate_child(
        identity,
        &record.kind,
        &record.phase,
        &record.idempotency_key,
    )?;
    if record.kind != kind {
        return Err(eyre!("stage prepared record kind was substituted"));
    }
    use base64::Engine as _;
    let envelope = base64::engine::general_purpose::STANDARD
        .decode(&record.prepared_base64)
        .wrap_err("stage prepared envelope is not base64")?;
    let (digest, transaction_hash, operation) = host::validate_core_prepared_envelope(
        identity,
        &envelope,
        kind,
        PHASE,
        &record.idempotency_key,
        PreparedMutationLifetimeCheck::Structural,
    )?;
    if digest != record.prepared_sha256
        || transaction_hash != record.transaction_hash
        || operation != record.operation
    {
        return Err(eyre!("stage prepared envelope identity was substituted"));
    }
    let state = read_stage_state(directory, identity, &record)?.to_owned();
    directory.check()?;
    Ok(Some((
        record,
        RetainedPreparedMutation {
            state,
            bytes: envelope,
            sha256: digest,
            transaction_hash,
        },
    )))
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn read_stage_state(
    directory: &StageDirectory,
    identity: &CoreWriteIdentity,
    prepared: &StagePreparedV1,
) -> Result<&'static str> {
    for state in ["applied", "submitted"] {
        let path = directory
            .path
            .join(format!("{}.{}.json", prepared.kind, state));
        if !path.try_exists()? {
            continue;
        }
        let (marker, bytes) = read_private_json::<StageStateV1>(&path, "stage prepared state")?;
        if bytes != json_line(&marker)? {
            return Err(eyre!("stage state marker is not canonical"));
        }
        host::validate_core_state_marker(
            [
                &marker.schema,
                &marker.stage_identity_sha256,
                &marker.authorization_sha256,
                &marker.authorization_nonce,
                &marker.kind,
                &marker.phase,
                &marker.idempotency_key,
                &marker.prepared_sha256,
                &marker.transaction_hash,
                &marker.state,
            ],
            [
                STATE_SCHEMA,
                &identity.authorization_sha256,
                &identity.authorization_sha256,
                &identity.authorization_nonce,
                &prepared.kind,
                PHASE,
                &prepared.idempotency_key,
                &prepared.prepared_sha256,
                &prepared.transaction_hash,
                state,
            ],
            &marker.evidence_sha256,
        )?;
        if state == "applied" {
            let (value, evidence) = read_private_json::<norito::json::Value>(
                &directory
                    .path
                    .join(format!("{}.applied-evidence.json", prepared.kind)),
                "stage Applied evidence",
            )?;
            if evidence != json_line(&value)? || sha256_hex(&evidence) != marker.evidence_sha256 {
                return Err(eyre!(
                    "stage Applied evidence is missing, substituted, or noncanonical"
                ));
            }
            use base64::Engine as _;
            let envelope =
                base64::engine::general_purpose::STANDARD.decode(&prepared.prepared_base64)?;
            let retained = RetainedPreparedMutation {
                state: "applied".into(),
                bytes: envelope,
                sha256: prepared.prepared_sha256.clone(),
                transaction_hash: prepared.transaction_hash.clone(),
            };
            host::validate_core_write_report(
                &value,
                identity,
                PHASE,
                &prepared.kind,
                &prepared.idempotency_key,
                "Applied",
                Some(&retained),
            )?;
        }
        return Ok(state);
    }
    Ok("prepared")
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn publish_stage_state(
    directory: &StageDirectory,
    identity: &CoreWriteIdentity,
    prepared: &StagePreparedV1,
    state: &str,
    evidence: &str,
) -> Result<()> {
    let current = read_stage_state(directory, identity, prepared)?;
    if state == "submitted" && current == "applied" {
        return Err(eyre!("Applied stage mutation cannot be resubmitted"));
    }
    if state == "submitted" && prepared.transaction_hash.is_empty() {
        return Err(eyre!("transaction-free onboarding cannot be Submitted"));
    }
    if state == "applied" && current == "prepared" && !prepared.transaction_hash.is_empty() {
        return Err(eyre!(
            "stage mutation cannot become Applied before Submitted"
        ));
    }
    let marker = StageStateV1 {
        schema: STATE_SCHEMA.into(),
        stage_identity_sha256: identity.authorization_sha256.clone(),
        authorization_sha256: identity.authorization_sha256.clone(),
        authorization_nonce: identity.authorization_nonce.clone(),
        kind: prepared.kind.clone(),
        phase: PHASE.into(),
        idempotency_key: prepared.idempotency_key.clone(),
        prepared_sha256: prepared.prepared_sha256.clone(),
        transaction_hash: prepared.transaction_hash.clone(),
        state: state.into(),
        evidence_sha256: evidence.into(),
    };
    host::validate_core_state_marker(
        [
            &marker.schema,
            &marker.stage_identity_sha256,
            &marker.authorization_sha256,
            &marker.authorization_nonce,
            &marker.kind,
            &marker.phase,
            &marker.idempotency_key,
            &marker.prepared_sha256,
            &marker.transaction_hash,
            &marker.state,
        ],
        [
            STATE_SCHEMA,
            &identity.authorization_sha256,
            &identity.authorization_sha256,
            &identity.authorization_nonce,
            &prepared.kind,
            PHASE,
            &prepared.idempotency_key,
            &prepared.prepared_sha256,
            &prepared.transaction_hash,
            state,
        ],
        evidence,
    )?;
    directory.publish(
        &format!("{}.{}.json", prepared.kind, state),
        &json_line(&marker)?,
    )
}

#[cfg(target_os = "linux")]
impl NativeStageTransport {
    fn check(&self) -> Result<()> {
        self.root.check()?;
        self.journal.check()?;
        self._lock.check()?;
        revalidate_pinned(&self.client, "stage canary client")?;
        revalidate_pinned(&self.executable, "native candidate executable")?;
        let public = public_inputs::load(Path::new(&self.admission.public_inputs_dir))?;
        if public.genesis_hash != self.admission.genesis_hash
            || public.signed_genesis_sha256 != self.admission.signed_genesis_sha256
            || public.raw_manifest_sha256 != self.admission.raw_manifest_sha256
            || public.canary_public_key != self.admission.canary_public_key
        {
            return Err(eyre!("stage public genesis or canary identity changed"));
        }
        Ok(())
    }
    fn require_onboarding_current(&self, deadline: Instant) -> Result<()> {
        let Some((record, prepared)) =
            read_stage_prepared(&self.journal, &self.identity, "onboarding")?
        else {
            return Err(eyre!(
                "stage successor lacks its exact onboarding predecessor"
            ));
        };
        if prepared.state != "applied" {
            return Err(eyre!("stage onboarding predecessor is not Applied"));
        }
        if record.operation == "onboarding_proof_required" {
            let proof = host::prepared_onboarding_proof_required_result(&prepared.bytes)?;
            host::prove_core_onboarding_current_state(
                &self.identity,
                deadline,
                &proof.account_id,
                &proof.alias,
            )?;
        }
        Ok(())
    }
    fn require_predecessor(&self, kind: &str, deadline: Instant) -> Result<()> {
        let predecessor = match kind {
            "faucet" => "onboarding",
            "write_canary" => "faucet",
            _ => return Ok(()),
        };
        self.require_onboarding_current(deadline)?;
        let Some((_, prepared)) = read_stage_prepared(&self.journal, &self.identity, predecessor)?
        else {
            return Err(eyre!("stage exact predecessor envelope is absent"));
        };
        if prepared.state != "applied" {
            return Err(eyre!("stage exact predecessor has no Applied evidence"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl CoreWriteTransport for NativeStageTransport {
    fn core_write_identity(&self, phase: &str) -> Result<CoreWriteIdentity> {
        if phase != PHASE {
            return Err(eyre!("private stage has no public or restart phase"));
        }
        Ok(self.identity.clone())
    }
    fn core_receipt_root(&self) -> &Path {
        &self.journal.path
    }
    fn core_client_args(&self) -> Result<(Vec<OsString>, Vec<File>)> {
        self.check()?;
        let (mut args, file) =
            host::inherited_client_config_args(&self.client, "stage canary client")?;
        args.extend(self.fee_args.iter().cloned());
        Ok((args, vec![file]))
    }
    fn core_onboarding_token(&self) -> Result<File> {
        self.check()?;
        host::inherited_input_file(
            self.token
                .as_ref()
                .ok_or_else(|| eyre!("stage prepare/submit needs token custody"))?,
            "stage onboarding token",
        )
    }
    fn core_run_process(
        &mut self,
        args: Vec<OsString>,
        files: Vec<File>,
        deadline: Instant,
        recovery_only: bool,
    ) -> Result<ProcessOutput> {
        self.check()?;
        if !recovery_only
            && (now_unix_ms()? < self.identity.not_before_unix_ms
                || now_unix_ms()? >= self.identity.execution_expires_at_unix_ms)
        {
            return Err(eyre!("private stage execution window is not current"));
        }
        if deadline <= Instant::now() {
            return Err(eyre!("stage child deadline elapsed before dispatch"));
        }
        host::run_native_core_cli(
            &self.executable.file,
            args,
            files,
            deadline,
            &mut self.runner,
        )
    }
    fn core_publish_receipt(&self, name: &str, value: &norito::json::Value) -> Result<()> {
        self.check()?;
        let report = host::canonical_local_report(value)?;
        let receipt = norito::json!({ "schema": "iroha.taira.private-stage.canary-receipt.v1",
            "stage_identity_sha256": (self.identity.authorization_sha256), "report": report });
        self.journal.publish(name, &json_line(&receipt)?)
    }
    fn coordinate_shared_prepared_mutation(
        &mut self,
        operation: &str,
        kind: &str,
        phase: &str,
        key: &str,
        candidate: Option<&[u8]>,
        digest: &str,
        transaction_hash: &str,
        evidence: Option<&[u8]>,
        recovery_only: bool,
        timeout_secs: u64,
    ) -> Result<RetainedPreparedMutation> {
        self.check()?;
        validate_child(&self.identity, kind, phase, key)?;
        if !matches!(operation, "fetch" | "prepare" | "submitted" | "applied") {
            return Err(eyre!("stage prepared store operation is outside exact V1"));
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(timeout_secs))
            .ok_or_else(|| eyre!("stage store deadline overflow"))?;
        if matches!(operation, "prepare" | "submitted")
            && (recovery_only
                || now_unix_ms()? < self.identity.not_before_unix_ms
                || now_unix_ms()? >= self.identity.execution_expires_at_unix_ms)
        {
            return Err(eyre!("read-only or expired stage cannot prepare/submit"));
        }
        let mut retained = read_stage_prepared(&self.journal, &self.identity, kind)?;
        if operation == "prepare" {
            let bytes = candidate.ok_or_else(|| eyre!("stage prepare omits its envelope"))?;
            let (actual_digest, actual_hash, operation) = host::validate_core_prepared_envelope(
                &self.identity,
                bytes,
                kind,
                PHASE,
                key,
                PreparedMutationLifetimeCheck::LiveForward,
            )?;
            if actual_digest != digest || actual_hash != transaction_hash || evidence.is_some() {
                return Err(eyre!(
                    "stage preparation differs from its exact candidate envelope"
                ));
            }
            self.require_predecessor(kind, deadline)?;
            use base64::Engine as _;
            let record = StagePreparedV1 {
                schema: PREPARED_SCHEMA.into(),
                stage_identity_sha256: self.identity.authorization_sha256.clone(),
                kind: kind.into(),
                phase: PHASE.into(),
                idempotency_key: key.into(),
                operation,
                prepared_base64: base64::engine::general_purpose::STANDARD.encode(bytes),
                prepared_sha256: actual_digest,
                transaction_hash: actual_hash,
            };
            self.journal
                .publish(&format!("{kind}.prepared.json"), &json_line(&record)?)?;
            retained = read_stage_prepared(&self.journal, &self.identity, kind)?;
        }
        let Some((record, mut prepared)) = retained else {
            if operation != "fetch" {
                return Err(eyre!(
                    "stage operation lacks its immutable prepared envelope"
                ));
            }
            return Ok(RetainedPreparedMutation {
                state: "absent".into(),
                bytes: Vec::new(),
                sha256: String::new(),
                transaction_hash: String::new(),
            });
        };
        if kind != "onboarding" {
            self.require_onboarding_current(deadline)?;
        }
        match operation {
            "submitted" => {
                host::validate_core_prepared_envelope(
                    &self.identity,
                    &prepared.bytes,
                    kind,
                    PHASE,
                    key,
                    PreparedMutationLifetimeCheck::LiveForward,
                )?;
                publish_stage_state(&self.journal, &self.identity, &record, "submitted", "")?;
            }
            "applied" => {
                let evidence = evidence
                    .ok_or_else(|| eyre!("stage Applied marker omits exact child evidence"))?;
                let value: norito::json::Value = json::from_slice(evidence)?;
                if json_line(&value)? != evidence {
                    return Err(eyre!("stage Applied evidence is not canonical"));
                }
                host::validate_core_write_report(
                    &value,
                    &self.identity,
                    PHASE,
                    kind,
                    key,
                    "Applied",
                    Some(&prepared),
                )?;
                if prepared.transaction_hash.is_empty() {
                    let proof = host::prepared_onboarding_proof_required_result(&prepared.bytes)?;
                    host::prove_core_onboarding_current_state(
                        &self.identity,
                        deadline,
                        &proof.account_id,
                        &proof.alias,
                    )?;
                }
                self.journal
                    .publish(&format!("{kind}.applied-evidence.json"), evidence)?;
                publish_stage_state(
                    &self.journal,
                    &self.identity,
                    &record,
                    "applied",
                    &sha256_hex(evidence),
                )?;
            }
            _ => {}
        }
        prepared.state = read_stage_state(&self.journal, &self.identity, &record)?.into();
        self.check()?;
        Ok(prepared)
    }
}

#[cfg(target_os = "linux")]
struct StageProgress {
    directory: StageDirectory,
    identity: CoreWriteIdentity,
    index: usize,
}

#[cfg(target_os = "linux")]
impl executor_model::RecoveryProgress for StageProgress {
    fn mark_submitted(&mut self, index: usize) -> Result<()> {
        if index != self.index {
            return Err(eyre!("stage progress operation index was substituted"));
        }
        let kind = KINDS[index];
        let (record, prepared) = read_stage_prepared(&self.directory, &self.identity, kind)?
            .ok_or_else(|| eyre!("stage Submitted intent lacks its immutable envelope"))?;
        if prepared.state == "prepared" && !prepared.transaction_hash.is_empty() {
            // This durable exact marker precedes the shared driver's child dispatch.
            publish_stage_state(&self.directory, &self.identity, &record, "submitted", "")?;
        }
        Ok(())
    }
    fn mark_applied(&mut self, index: usize) -> Result<()> {
        if index != self.index {
            return Err(eyre!("stage Applied progress index was substituted"));
        }
        let (_, prepared) = read_stage_prepared(&self.directory, &self.identity, KINDS[index])?
            .ok_or_else(|| eyre!("stage Applied progress lacks its immutable envelope"))?;
        if prepared.state != "applied" {
            return Err(eyre!("stage child has no exact durable Applied marker"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn pin_candidate_executable(layout: &StagedRuntimeLayout) -> Result<PinnedInput> {
    let path = std::env::current_exe().wrap_err("locate current native candidate CLI")?;
    layout.validate_path(&path, "native candidate executable")?;
    let (file, snapshot) = open_pinned_regular(&path, "native candidate executable")?;
    if snapshot.uid != rustix::process::geteuid().as_raw()
        || snapshot.mode & 0o022 != 0
        || snapshot.mode & 0o100 == 0
    {
        return Err(eyre!("native candidate executable has unsafe custody"));
    }
    Ok(PinnedInput {
        path,
        file,
        snapshot,
    })
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn validate_native_client_shape(input: &PinnedInput) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(read_pinned_bytes(
        &input.path,
        "stage canary client",
        input.file.try_clone()?,
        &input.snapshot,
        iroha_config_base::toml::MAX_TOML_SOURCE_BYTES,
    )?);
    let mut table: toml::Table = toml::from_str(
        std::str::from_utf8(&bytes).map_err(|_| eyre!("stage canary client is not UTF-8"))?,
    )
    .map_err(|_| eyre!("stage canary client is not native TOML"))?;
    let result = (|| {
        let allowed = [
            "chain",
            "network_id",
            "torii_url",
            "transaction",
            "account",
            "basic_auth",
        ];
        if table.keys().any(|key| !allowed.contains(&key.as_str()))
            || ["chain", "network_id", "torii_url"]
                .iter()
                .any(|key| !table.get(*key).is_some_and(toml::Value::is_str))
        {
            return Err(eyre!(
                "stage client contains a foreign dependency or non-native field"
            ));
        }
        let account = table
            .get("account")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| eyre!("stage client omits its inline native account"))?;
        if account.len() != 3
            || ["chain_discriminant", "public_key", "private_key"]
                .iter()
                .any(|key| !account.contains_key(*key))
        {
            return Err(eyre!(
                "stage client account contains a foreign signer dependency"
            ));
        }
        Ok(())
    })();
    crate::soracloud::zeroize_taira_toml_table(&mut table);
    result
}

#[cfg(target_os = "linux")]
impl StageCanary {
    fn admit(&self) -> Result<NativeStageTransport> {
        let layout = self
            .staging
            .layout()?
            .ok_or_else(|| eyre!("stage-canary requires all three staging arguments"))?;
        let root = layout.hold_root()?;
        for (path, label) in [
            (&self.public_inputs_dir, "stage public inputs"),
            (&self.client_config, "stage canary client"),
        ] {
            layout.validate_path(path, label)?;
        }
        if let Some(path) = &self.onboarding_token_file {
            layout.validate_path(path, "stage onboarding token")?;
        }
        if self.execution_not_before_unix_ms == 0
            || self.execution_expires_at_unix_ms <= self.execution_not_before_unix_ms
        {
            return Err(eyre!(
                "stage execution window must be one exact positive interval"
            ));
        }
        let public = public_inputs::load(&self.public_inputs_dir)?;
        let client = pin_owner_private_file(&self.client_config, "stage canary client")?;
        validate_native_client_shape(&client)?;
        let config = host::load_client_config_for_reset_genesis(
            &client,
            "stage canary client",
            &public.genesis_hash,
        )?;
        let origin = layout.local_origin(0)?;
        if config.torii_api_url.as_str() != origin
            || config.account != AccountId::new(public.canary_public_key.clone())
            || config.key_pair.public_key() != &public.canary_public_key
        {
            return Err(eyre!(
                "stage client differs from the independently validated private origin or native canary"
            ));
        }
        let token = if self.recover {
            None
        } else {
            Some(pin_owner_private_file(
                self.onboarding_token_file
                    .as_deref()
                    .ok_or_else(|| eyre!("stage forward execution requires token"))?,
                "stage onboarding token",
            )?)
        };
        let executable = pin_candidate_executable(&layout)?;
        let journal_path = layout.root().join("stage-canary-v1");
        layout.validate_path(&journal_path, "stage canary journal")?;
        if !journal_path.try_exists()? {
            fs::create_dir(&journal_path)?;
            fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o700))?;
            File::open(layout.root())?.sync_all()?;
        }
        let journal = StageDirectory::open(&journal_path)?;
        let lock = StageLock::open(&journal)?;
        let retained_path = journal.path.join("identity.json");
        let retained = if retained_path.try_exists()? {
            let (identity, bytes) = read_private_json::<StageIdentityV1>(
                &retained_path,
                "private-stage operator identity",
            )?;
            if bytes != json_line(&identity)? {
                return Err(eyre!("stage operator identity is not canonical"));
            }
            Some(identity)
        } else {
            None
        };
        let token_identity = match (&token, &retained) {
            (Some(token), _) => FileIdentityV1::from_pin(token)?,
            (None, Some(retained)) if self.recover => retained.onboarding_token.clone(),
            _ => {
                return Err(eyre!(
                    "read-only stage recovery requires an existing immutable identity"
                ));
            }
        };
        layout.validate_path(Path::new(&token_identity.path), "retained stage token")?;
        let fee_payment = crate::FeePaymentArgs {
            fee_payer: Some(self.stage_fee_payer),
            fee_program: self.stage_fee_program.clone(),
            fee_program_revision: self.stage_fee_program_revision,
        }
        .selection()?;
        let faucet = crate::taira::parse_write_canary_faucet_policy(
            Some(&self.faucet_authority),
            Some(&self.faucet_asset_id),
            Some(&self.faucet_amount),
            "faucet",
        )?;
        if faucet.asset_definition_id().to_string() != crate::taira::DEFAULT_GAS_ASSET_ID {
            return Err(eyre!(
                "private stage faucet must fund the canonical Taira fee asset"
            ));
        }
        let root_metadata = fs::symlink_metadata(layout.root())?;
        let admission = StageIdentityV1 {
            schema: ADMISSION_SCHEMA.into(),
            staging_root: layout
                .root()
                .to_str()
                .ok_or_else(|| eyre!("stage root is not UTF-8"))?
                .into(),
            root_device: root_metadata.dev(),
            root_inode: root_metadata.ino(),
            journal_device: journal.device,
            journal_inode: journal.inode,
            api_base_port: layout.api_port(0)?,
            p2p_base_port: layout.p2p_port(0)?,
            origin: origin.trim_end_matches('/').into(),
            public_inputs_dir: self
                .public_inputs_dir
                .to_str()
                .ok_or_else(|| eyre!("public input path is not UTF-8"))?
                .into(),
            network_id: public.network_id,
            genesis_hash: public.genesis_hash,
            signed_genesis_sha256: public.signed_genesis_sha256,
            raw_manifest_sha256: public.raw_manifest_sha256,
            genesis_public_key: public.genesis_public_key,
            canary_public_key: public.canary_public_key,
            onboarding_request: public.canary_onboarding_request,
            client: FileIdentityV1::from_pin(&client)?,
            onboarding_token: token_identity,
            executable: FileIdentityV1::from_pin(&executable)?,
            journal_lock: FileIdentityV1::from_pin(&lock.0)?,
            faucet_authority: self.faucet_authority.clone(),
            faucet_asset_id: self.faucet_asset_id.clone(),
            faucet_amount: self.faucet_amount.clone(),
            fee_payment: fee_payment.clone(),
            nonce: self.stage_nonce.clone(),
            not_before_unix_ms: self.execution_not_before_unix_ms,
            execution_expires_at_unix_ms: self.execution_expires_at_unix_ms,
        };
        if retained.as_ref().is_some_and(|saved| saved != &admission) {
            return Err(eyre!(
                "stage operator identity or immutable input custody was substituted"
            ));
        }
        let bytes = json_line(&admission)?;
        journal.publish("identity.json", &bytes)?;
        let identity = CoreWriteIdentity {
            authorization_sha256: sha256_hex(&bytes),
            authorization_nonce: admission.nonce.clone(),
            not_before_unix_ms: admission.not_before_unix_ms,
            execution_expires_at_unix_ms: admission.execution_expires_at_unix_ms,
            origin: admission.origin.clone(),
            chain_id: CHAIN_ID.into(),
            genesis_hash: admission.genesis_hash.clone(),
            onboarding_request: admission.onboarding_request.clone(),
            fee_payment,
            faucet_policy: faucet,
        };
        let fee_args = match self.stage_fee_payer {
            crate::FeePayerArg::Authority => vec!["--fee-payer".into(), "authority".into()],
            crate::FeePayerArg::Sponsor => vec![
                "--fee-payer".into(),
                "sponsor".into(),
                "--fee-program".into(),
                self.stage_fee_program
                    .as_ref()
                    .ok_or_else(|| eyre!("stage sponsor program missing"))?
                    .into(),
                "--fee-program-revision".into(),
                self.stage_fee_program_revision
                    .ok_or_else(|| eyre!("stage sponsor revision missing"))?
                    .to_string()
                    .into(),
            ],
        };
        root.check()?;
        Ok(NativeStageTransport {
            layout,
            root,
            journal,
            _lock: lock,
            identity,
            admission,
            client,
            token,
            executable,
            fee_args,
            runner: RealProcessRunner,
        })
    }

    pub(super) fn run(&self, output: &mut impl Write) -> Result<()> {
        let _guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        let mut transport = self.admit()?;
        for (index, kind) in KINDS.into_iter().enumerate() {
            let existing = read_stage_prepared(&transport.journal, &transport.identity, kind)?;
            let requires_recovery = existing.as_ref().is_some_and(|(_, prepared)| {
                prepared.state != "prepared" || prepared.transaction_hash.is_empty()
            });
            if self.recover || requires_recovery {
                if existing.is_none() {
                    return Err(eyre!(
                        "private-stage read-only recovery has no prepared envelope for {kind}"
                    ));
                }
                let deadline = Instant::now()
                    .checked_add(Duration::from_secs(self.timeout_secs))
                    .ok_or_else(|| eyre!("stage recovery deadline overflow"))?;
                match transport.recover_core_write_child(deadline, PHASE, kind)? {
                    PreparedMutationOutcome::Applied { value, .. } => transport
                        .core_publish_receipt(
                            &format!("{}-{PHASE}.json", kind.replace('_', "-")),
                            &value,
                        )?,
                    PreparedMutationOutcome::Pending => {
                        return Err(eyre!(
                            "private-stage submitted intent remains pending; recover the same envelope"
                        ));
                    }
                    PreparedMutationOutcome::Rejected(class) => {
                        return Err(eyre!(
                            "private-stage exact envelope cannot proceed: {class}"
                        ));
                    }
                }
            } else {
                let mut progress = StageProgress {
                    directory: transport.journal.clone_held()?,
                    identity: transport.identity.clone(),
                    index,
                };
                transport.run_core_write_child(
                    &mut progress,
                    index,
                    self.timeout_secs,
                    PHASE,
                    kind,
                )?;
            }
        }
        transport.check()?;
        let report = norito::json!({ "schema": "iroha.taira.private-stage.canary-result.v1", "status": "ok",
            "stage_identity_sha256": (transport.identity.authorization_sha256), "origin": (transport.identity.origin),
            "staging_root": (transport.layout.root().to_str()), "operations": (KINDS.to_vec()),
            "read_only_recovery": (self.recover) });
        if self.json {
            output.write_all(&json_line(&report)?)?;
        } else {
            writeln!(
                output,
                "Private candidate canary Applied: onboarding, faucet, final canary"
            )?;
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn private_directory() -> tempfile::TempDir {
        super::super::private_custody_test_dir(".taira-stage-canary-test-")
    }

    #[test]
    fn stage_journal_excludes_another_executor_and_refuses_lock_replacement() {
        let root = private_directory();
        let directory = StageDirectory::open(root.path()).expect("journal");
        let lock = StageLock::open(&directory).expect("first executor");
        let _ = StageLock::open(&directory)
            .err()
            .expect("second executor must not enter");
        let before = FileIdentityV1::from_pin(&lock.0).expect("held lock identity");
        fs::rename(
            root.path().join("canary.lock"),
            root.path().join("retained-original.lock"),
        )
        .expect("simulate path replacement");
        let replacement = StageLock::open(&directory).expect("replacement inode is distinct");
        let _ = lock
            .check()
            .expect_err("active executor must reject its replaced lock path");
        assert_ne!(
            before,
            FileIdentityV1::from_pin(&replacement.0).expect("replacement identity"),
            "the immutable stage identity must also reject the replacement on reopen"
        );
    }

    #[test]
    fn stage_journal_publication_rejects_directory_substitution() {
        let root = private_directory();
        let active = root.path().join("journal");
        fs::create_dir(&active).expect("create journal");
        fs::set_permissions(&active, fs::Permissions::from_mode(0o700)).expect("protect journal");
        let journal = StageDirectory::open(&active).expect("hold journal");
        let retained = root.path().join("retained-journal");
        fs::rename(&active, &retained).expect("simulate displaced directory");
        fs::create_dir(&active).expect("replacement directory");
        fs::set_permissions(&active, fs::Permissions::from_mode(0o700))
            .expect("protect replacement");
        let _ = journal
            .publish("receipt.json", b"immutable receipt")
            .expect_err("replaced journal must not receive evidence");
        assert!(!active.join("receipt.json").exists());
        assert!(!retained.join("receipt.json").exists());
    }

    #[test]
    fn native_client_rejects_foreign_key_and_network_file_dependencies() {
        let root = private_directory();
        let path = root.path().join("client.toml");
        for dependency in [
            "network_id_file = '/var/lib/taira/genesis.hash'\n",
            "[account]\nchain_discriminant = 369\npublic_key = 'fixture-public'\nprivate_key_file = '/var/lib/taira/signer.key'\n",
        ] {
            let text = format!(
                "chain = '{CHAIN_ID}'\nnetwork_id = 'fixture-network'\ntorii_url = 'http://127.0.0.1:28080/'\n{dependency}"
            );
            fs::write(&path, text).expect("write native dependency fixture");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("protect client");
            let pin = pin_owner_private_file(&path, "fixture client").expect("pin client");
            let _ = validate_native_client_shape(&pin)
                .expect_err("native stage must refuse references to serving files");
        }
    }

    #[test]
    fn stage_child_selection_rejects_public_phase_and_other_nonce() {
        let _guard = ChainDiscriminantGuard::enter(CHAIN_DISCRIMINANT);
        let key =
            iroha_crypto::KeyPair::try_from_seed(vec![0x51; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("fixture key");
        let account = AccountId::new(key.public_key().clone());
        let identity = CoreWriteIdentity {
            authorization_sha256: "a1".repeat(32),
            authorization_nonce: "a".repeat(32),
            not_before_unix_ms: 1,
            execution_expires_at_unix_ms: u64::MAX,
            origin: "http://127.0.0.1:28080".into(),
            chain_id: CHAIN_ID.into(),
            genesis_hash: "b2".repeat(32),
            onboarding_request: AccountOnboardingPlanRequestV1::try_new(
                crate::taira::canary_alias(key.public_key()),
                &account,
                std::iter::empty(),
            )
            .expect("request"),
            fee_payment: FeePaymentIntent::authority(Vec::new(), None),
            faucet_policy: iroha::client::AccountFaucetPolicyV1::try_new(
                account,
                crate::taira::DEFAULT_GAS_ASSET_ID.parse().expect("asset"),
                "1".parse().expect("amount"),
            )
            .expect("policy"),
        };
        let exact = stage_key(&identity, "faucet");
        validate_child(&identity, "faucet", PHASE, &exact).expect("exact private child");
        let _ = validate_child(&identity, "faucet", "post_edge", &exact)
            .expect_err("private stage has no public phase");
        let _ = validate_child(&identity, "inrou_canary", PHASE, &exact)
            .expect_err("private stage has only core operations");
        let other = host::child_mutation_idempotency_key(&"b".repeat(32), PHASE, "faucet");
        let _ = validate_child(&identity, "faucet", PHASE, &other)
            .expect_err("another immutable nonce cannot replace a child");
    }

    #[test]
    fn stage_applied_marker_requires_retained_exact_evidence_and_semantic_hash() {
        let _guard = ChainDiscriminantGuard::enter(0x02f1);
        let (identity, envelope, evidence, key) =
            host::tests::core_proof_required_store_fixture("http://127.0.0.1:28080");
        let (digest, transaction_hash, operation) = host::validate_core_prepared_envelope(
            &identity,
            &envelope,
            "onboarding",
            PHASE,
            &key,
            PreparedMutationLifetimeCheck::Structural,
        )
        .expect("authenticated fixture");
        use base64::Engine as _;
        let prepared = StagePreparedV1 {
            schema: PREPARED_SCHEMA.into(),
            stage_identity_sha256: identity.authorization_sha256.clone(),
            kind: "onboarding".into(),
            phase: PHASE.into(),
            idempotency_key: key,
            operation,
            prepared_base64: base64::engine::general_purpose::STANDARD.encode(envelope),
            prepared_sha256: digest,
            transaction_hash,
        };

        let root = private_directory();
        let directory = StageDirectory::open(root.path()).expect("journal");
        publish_stage_state(
            &directory,
            &identity,
            &prepared,
            "applied",
            &sha256_hex(&evidence),
        )
        .expect("fixture marker");
        let _ = read_stage_state(&directory, &identity, &prepared)
            .expect_err("a digest-shaped marker cannot replace missing evidence");
        directory
            .publish("onboarding.applied-evidence.json", &evidence)
            .expect("retain exact evidence");
        assert_eq!(
            read_stage_state(&directory, &identity, &prepared).expect("exact retained evidence"),
            "applied"
        );

        let forged_root = private_directory();
        let forged_directory =
            StageDirectory::open(forged_root.path()).expect("second isolated journal");
        let mut forged: norito::json::Value = json::from_slice(&evidence).expect("evidence value");
        forged.as_object_mut().expect("report object").insert(
            "evidence".into(),
            norito::json::Value::from("44".repeat(32)),
        );
        let forged = json_line(&forged).expect("canonical forged report");
        forged_directory
            .publish("onboarding.applied-evidence.json", &forged)
            .expect("fixture forged evidence");
        publish_stage_state(
            &forged_directory,
            &identity,
            &prepared,
            "applied",
            &sha256_hex(&forged),
        )
        .expect("matching forged digest");
        let _ = read_stage_state(&forged_directory, &identity, &prepared).expect_err(
            "even a matching digest cannot substitute the authenticated semantic evidence",
        );
    }
}

#[cfg(not(target_os = "linux"))]
impl StageCanary {
    pub(super) fn run(&self, _output: &mut impl Write) -> Result<()> {
        Err(eyre!(
            "native stage-canary requires the held candidate CLI on the approved Linux guest"
        ))
    }
}
