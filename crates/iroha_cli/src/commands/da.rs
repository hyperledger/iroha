//! Generic data-availability CLI helpers (DA-8 roadmap workstream).
use super::{
    da_common::{
        DaManifestFetcher, DaPublisher, DaPublisherReceipt, load_metadata_from_path,
        parse_blob_class, parse_fec_scheme, parse_storage_class,
    },
    sorafs::FetchArgs,
};
use crate::cli_output::print_with_optional_text;
use crate::{CliOutputFormat, Run, RunContext};
use base64::{Engine, engine::general_purpose::STANDARD as Base64Standard};
use clap::{Args, Subcommand};
use eyre::{Result, WrapErr, eyre};
use iroha::da::{
    self, DaCommitmentListCursor, DaCommitmentListRequest, DaCommitmentProofRequest,
    DaIngestParams, DaPinIntentListCursor, DaPinIntentListRequest, DaPinIntentQueryRequest,
    DaRentLedgerPlan,
};
use iroha::data_model::{
    asset::AssetDefinitionId,
    da::{
        commitment::{DaCommitmentProof, DaProofPolicyBundle},
        ingest::{DaIngestReceipt, DaIngestRequest, DaPinScopeV1},
        manifest::DaManifestV1,
        pin_intent::DaPinIntentProof,
        types::{
            BlobCodec, BlobDigest, DaRentLedgerProjection, DaRentPolicyV1, DaRentQuote,
            ErasureProfile, ExtraMetadata, GovernanceTag, RetentionPolicy, StorageTicketId,
        },
    },
    sorafs::pin_registry::ManifestDigest,
};
use iroha_model_base::topology::LaneId;
use iroha_primitives::numeric::XorQuantity;
use iroha_storage_client::da::{
    ProofOrigin, ProofReport, build_car_plan_from_manifest, proof_to_json,
    validate_manifest_consistency, value_from_usize,
};
use norito::{
    decode_from_bytes,
    json::{self, Map, Number, Value},
    to_bytes,
};
use sorafs_car::{ChunkStore, FilePayload};
use std::{
    collections::HashSet,
    fmt::Write as _,
    fs,
    num::NonZeroU64,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Submit a raw blob to `/v1/da/ingest` and capture the signed receipt.
    Submit(SubmitArgs),
    /// Fetch blobs via the multi-source orchestrator (thin wrapper over `sorafs fetch`).
    Get(FetchArgs),
    /// Download manifest + chunk plan artifacts for an existing DA storage ticket.
    GetBlob(GetBlobArgs),
    /// Generate Proof-of-Retrievability witnesses for a manifest/payload pair.
    Prove(ProveArgs),
    /// Download + verify availability for a storage ticket using a Torii manifest.
    ProveAvailability(ProveAvailabilityArgs),
    /// Fetch the current DA proof-policy bundle from Torii.
    ProofPolicies(ProofPoliciesArgs),
    /// List DA commitments with optional filters.
    CommitmentsList(CommitmentQueryArgs),
    /// Build a DA commitment proof with optional filters.
    CommitmentsProve(CommitmentQueryArgs),
    /// Verify a DA commitment proof from a JSON file.
    CommitmentsVerify(CommitmentVerifyArgs),
    /// List DA pin intents with optional filters.
    PinIntentsList(PinIntentQueryArgs),
    /// Build a DA pin intent proof with optional filters.
    PinIntentsProve(PinIntentQueryArgs),
    /// Verify a DA pin intent proof from a JSON file.
    PinIntentsVerify(PinIntentVerifyArgs),
    /// Quote rent/incentive breakdown for a blob size/retention combo.
    RentQuote(RentQuoteArgs),
    /// Convert a rent quote into deterministic ledger transfer instructions.
    RentLedger(RentLedgerArgs),
}
impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Command::Submit(args) => args.run(context),
            Command::Get(args) => args.run(context),
            Command::GetBlob(args) => args.run(context),
            Command::Prove(args) => args.run(context),
            Command::ProveAvailability(args) => args.run(context),
            Command::ProofPolicies(args) => args.run(context),
            Command::CommitmentsList(args) => args.run_list(context),
            Command::CommitmentsProve(args) => args.run_prove(context),
            Command::CommitmentsVerify(args) => args.run(context),
            Command::PinIntentsList(args) => args.run_list(context),
            Command::PinIntentsProve(args) => args.run_prove(context),
            Command::PinIntentsVerify(args) => args.run(context),
            Command::RentQuote(args) => args.run(context),
            Command::RentLedger(args) => args.run(context),
        }
    }
}
#[derive(clap::Args, Debug)]
pub struct SubmitArgs {
    /// Path to the blob payload (CAR, manifest bundle, governance file, etc.).
    #[arg(long, value_name = "PATH")]
    pub payload: PathBuf,
    /// Lane identifier recorded in the DA request.
    #[arg(long, default_value_t = 0)]
    pub lane_id: u32,
    /// Epoch identifier recorded in the DA request.
    #[arg(long, default_value_t = 0)]
    pub epoch: u64,
    /// Monotonic sequence scoped to (lane, epoch).
    #[arg(long, default_value_t = 0)]
    pub sequence: u64,
    /// Blob-class label (`taikai_segment`, `nexus_lane_sidecar`, `governance_artifact`, `custom:<id>`).
    #[arg(long = "blob-class", default_value = "nexus_lane_sidecar")]
    pub blob_class: String,
    /// Codec label describing the payload.
    #[arg(long = "blob-codec", default_value = "custom.binary")]
    pub blob_codec: String,
    /// Chunk size in bytes used for DA chunking.
    #[arg(long = "chunk-size", default_value_t = 262_144)]
    pub chunk_size: u32,
    /// Number of data shards in the erasure profile.
    #[arg(long = "data-shards", default_value_t = 10)]
    pub data_shards: u16,
    /// Number of parity shards in the erasure profile.
    #[arg(long = "parity-shards", default_value_t = 4)]
    pub parity_shards: u16,
    /// Chunk alignment (chunks per availability slice).
    #[arg(long = "chunk-alignment", default_value_t = 10)]
    pub chunk_alignment: u16,
    /// FEC scheme label (`rs12_10`, `rswin14_10`, `rs18_14`, `custom:<id>`).
    #[arg(long = "fec-scheme", default_value = "rs12_10")]
    pub fec_scheme: String,
    /// Hot retention in seconds.
    #[arg(long = "hot-retention-secs", default_value_t = 604_800)]
    pub hot_retention_secs: u64,
    /// Cold retention in seconds.
    #[arg(long = "cold-retention-secs", default_value_t = 7_776_000)]
    pub cold_retention_secs: u64,
    /// Required replica count enforced by retention policy.
    #[arg(long = "required-replicas", default_value_t = 3)]
    pub required_replicas: u16,
    /// Storage-class label (`hot`, `warm`, `cold`).
    #[arg(long = "storage-class", default_value = "warm")]
    pub storage_class: String,
    /// Governance tag recorded in the retention policy.
    #[arg(long = "governance-tag", default_value = "da.generic")]
    pub governance_tag: String,
    /// Optional metadata JSON file providing string key/value pairs.
    #[arg(long = "metadata-json", value_name = "PATH")]
    pub metadata_json: Option<PathBuf>,
    /// Optional pre-generated Norito manifest to embed in the request.
    #[arg(long = "manifest", value_name = "PATH")]
    pub manifest_path: Option<PathBuf>,
    /// Override for the Torii DA ingest endpoint (defaults to `$TORII/v1/da/ingest`).
    #[arg(long = "endpoint", value_name = "URL")]
    pub endpoint: Option<String>,
    /// Override the caller-supplied blob identifier (hex). Defaults to BLAKE3(payload).
    #[arg(long = "client-blob-id", value_name = "HEX")]
    pub client_blob_id: Option<String>,
    /// Directory for storing Norito/JSON artefacts (defaults to `artifacts/da/submission_<timestamp>`).
    #[arg(long = "artifact-dir", value_name = "PATH")]
    pub artifact_dir: Option<PathBuf>,
    /// Skip HTTP submission and only emit the signed request artefacts.
    #[arg(long = "no-submit")]
    pub no_submit: bool,
    /// Fixture file providing a mocked DA receipt (test-only helper; bypasses HTTP submit).
    #[arg(long = "receipt-fixture", value_name = "PATH", hide = true)]
    pub receipt_fixture: Option<PathBuf>,
}
#[derive(Debug, Clone, norito::json::JsonSerialize)]
struct SubmitRequestOutput {
    client_blob_id: String,
    request_path: String,
    request_json_path: String,
    request_bytes: usize,
}
#[derive(Debug, Clone, norito::json::JsonSerialize)]
struct SubmitReceiptOutput {
    status: String,
    duplicate: bool,
    receipt: DaIngestReceipt,
    pin_scope: Option<DaPinScopeV1>,
    receipt_path: String,
    receipt_json_path: String,
    pdp_commitment_header: Option<String>,
}
#[derive(Debug, Clone, norito::json::JsonSerialize)]
struct SubmitOutput {
    submitted: bool,
    request: SubmitRequestOutput,
    receipt: Option<SubmitReceiptOutput>,
}
#[derive(Args, Debug)]
pub struct GetBlobArgs {
    /// Storage ticket identifier (hex string) issued by Torii.
    #[arg(long = "storage-ticket", value_name = "HEX")]
    pub storage_ticket: String,
    /// Optional Torii base URL for manifest reads (must end with `/`).
    #[arg(long = "torii-url", value_name = "URL")]
    pub torii_url: Option<String>,
    /// Directory for storing the fetched manifest + chunk plan artefacts.
    #[arg(long = "output-dir", value_name = "PATH")]
    pub output_dir: Option<PathBuf>,
}
impl GetBlobArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let normalized_ticket = normalize_ticket_hex(&self.storage_ticket)?;
        let fetcher = DaManifestFetcher::new(context.config(), self.torii_url.as_deref())?;
        let bundle = fetcher.fetch(&normalized_ticket)?;
        let manifest_label = bundle.manifest_hash_hex.to_ascii_lowercase();
        let persisted =
            persist_manifest_bundle(context, &bundle, self.output_dir, &manifest_label)?;
        let output = build_manifest_fetch_value(&bundle, &persisted);
        let text = render_manifest_fetch_text(&bundle, &persisted);
        print_with_optional_text(context, Some(text), &output)
    }
}
#[derive(Args, Debug, Default)]
pub struct ProofPoliciesArgs {}
impl ProofPoliciesArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let client = iroha::blocking::Client::from_client(context.client_from_config()?)?;
        let bundle = client.da().proof_policies()?;
        let text = render_da_proof_policies_text("DA proof policies", &bundle);
        print_with_optional_text(context, Some(text), &bundle)
    }
}
#[derive(Args, Debug)]
pub struct CommitmentQueryArgs {
    /// Optional manifest hash filter (32-byte hex).
    #[arg(long = "manifest-hash", value_name = "HEX")]
    pub manifest_hash: Option<String>,
    /// Optional lane id filter (requires epoch + sequence for direct lookup).
    #[arg(long = "lane-id", value_name = "U32")]
    pub lane_id: Option<u32>,
    /// Optional epoch filter (requires lane-id + sequence for direct lookup).
    #[arg(long = "epoch", value_name = "U64")]
    pub epoch: Option<u64>,
    /// Optional sequence filter (requires lane-id + epoch for direct lookup).
    #[arg(long = "sequence", value_name = "U64")]
    pub sequence: Option<u64>,
    /// Optional list limit (`>0`).
    #[arg(long = "limit", value_name = "U64")]
    pub limit: Option<u64>,
    /// Path to a JSON cursor returned by a preceding list page.
    #[arg(long = "cursor-json", value_name = "PATH")]
    pub cursor_json: Option<PathBuf>,
}
impl CommitmentQueryArgs {
    fn run_list<C: RunContext>(self, context: &mut C) -> Result<()> {
        let request = self.to_list_request()?;
        let client = iroha::blocking::Client::from_client(context.client_from_config()?)?;
        let response = client.da().commitments(&request)?;
        let text = render_da_commitments_list_text(&response);
        print_with_optional_text(context, Some(text), &response)
    }
    fn run_prove<C: RunContext>(self, context: &mut C) -> Result<()> {
        let request = self.to_proof_request()?;
        let client = iroha::blocking::AccountClient::from_client(
            context.client_from_config()?.account_client()?,
        )?;
        let response = client.da().prove_commitment(&request)?;
        let text = render_da_commitment_prove_text(&response);
        print_with_optional_text(context, Some(text), &response)
    }
    fn to_list_request(&self) -> Result<DaCommitmentListRequest> {
        if self.manifest_hash.is_some()
            || self.lane_id.is_some()
            || self.epoch.is_some()
            || self.sequence.is_some()
        {
            return Err(eyre!(
                "commitment selectors are only valid for `commitments-prove`"
            ));
        }
        let limit = self
            .limit
            .map(|value| {
                NonZeroU64::new(value).ok_or_else(|| eyre!("--limit must be greater than zero"))
            })
            .transpose()?;
        let cursor = self
            .cursor_json
            .as_deref()
            .map(|path| load_json_payload::<DaCommitmentListCursor>(path, "DA commitment cursor"))
            .transpose()?;
        Ok(DaCommitmentListRequest { limit, cursor })
    }
    fn to_proof_request(&self) -> Result<DaCommitmentProofRequest> {
        if self.limit.is_some() || self.cursor_json.is_some() {
            return Err(eyre!(
                "--limit and --cursor-json are only valid for `commitments-list`"
            ));
        }
        let manifest_hash = self
            .manifest_hash
            .as_deref()
            .map(|hash| parse_fixed_hex(hash, "manifest-hash").map(ManifestDigest::new))
            .transpose()?;
        Ok(DaCommitmentProofRequest {
            manifest_hash,
            lane_id: self.lane_id,
            epoch: self.epoch,
            sequence: self.sequence,
        })
    }
}
#[derive(Args, Debug)]
pub struct CommitmentVerifyArgs {
    /// Path to a JSON-encoded `DaCommitmentProof`.
    #[arg(long = "proof-json", value_name = "PATH")]
    pub proof_json: PathBuf,
}
impl CommitmentVerifyArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let proof =
            load_json_payload::<DaCommitmentProof>(&self.proof_json, "DA commitment proof")?;
        let client = iroha::blocking::AccountClient::from_client(
            context.client_from_config()?.account_client()?,
        )?;
        let response = client.da().verify_commitment(&proof)?;
        let text = render_da_verify_text(
            "DA commitment verification",
            response.valid,
            response.error.as_deref(),
        );
        print_with_optional_text(context, Some(text), &response)
    }
}
#[derive(Args, Debug)]
pub struct PinIntentQueryArgs {
    /// Optional manifest hash filter (32-byte hex).
    #[arg(long = "manifest-hash", value_name = "HEX")]
    pub manifest_hash: Option<String>,
    /// Optional storage ticket filter (32-byte hex).
    #[arg(long = "storage-ticket", value_name = "HEX")]
    pub storage_ticket: Option<String>,
    /// Optional alias filter.
    #[arg(long = "alias", value_name = "TEXT")]
    pub alias: Option<String>,
    /// Optional lane id filter (requires epoch + sequence for direct lookup).
    #[arg(long = "lane-id", value_name = "U32")]
    pub lane_id: Option<u32>,
    /// Optional epoch filter (requires lane-id + sequence for direct lookup).
    #[arg(long = "epoch", value_name = "U64")]
    pub epoch: Option<u64>,
    /// Optional sequence filter (requires lane-id + epoch for direct lookup).
    #[arg(long = "sequence", value_name = "U64")]
    pub sequence: Option<u64>,
    /// Optional list limit (`>0`).
    #[arg(long = "limit", value_name = "U64")]
    pub limit: Option<u64>,
    /// Path to a JSON cursor returned by a preceding list page.
    #[arg(long = "cursor-json", value_name = "PATH")]
    pub cursor_json: Option<PathBuf>,
}
impl PinIntentQueryArgs {
    fn run_list<C: RunContext>(self, context: &mut C) -> Result<()> {
        let request = self.to_list_request()?;
        let client = iroha::blocking::Client::from_client(context.client_from_config()?)?;
        let response = client.da().pin_intents(&request)?;
        let text = render_da_pin_intents_list_text(&response);
        print_with_optional_text(context, Some(text), &response)
    }
    fn run_prove<C: RunContext>(self, context: &mut C) -> Result<()> {
        let request = self.to_proof_request()?;
        let client = iroha::blocking::AccountClient::from_client(
            context.client_from_config()?.account_client()?,
        )?;
        let response = client.da().prove_pin_intent(&request)?;
        let text = render_da_pin_intent_prove_text(&response);
        print_with_optional_text(context, Some(text), &response)
    }
    fn to_list_request(&self) -> Result<DaPinIntentListRequest> {
        if self.manifest_hash.is_some()
            || self.storage_ticket.is_some()
            || self.alias.is_some()
            || self.lane_id.is_some()
            || self.epoch.is_some()
            || self.sequence.is_some()
        {
            return Err(eyre!(
                "pin-intent selectors are only valid for `pin-intents-prove`"
            ));
        }
        let limit = self
            .limit
            .map(|value| {
                NonZeroU64::new(value).ok_or_else(|| eyre!("--limit must be greater than zero"))
            })
            .transpose()?;
        let cursor = self
            .cursor_json
            .as_deref()
            .map(|path| load_json_payload::<DaPinIntentListCursor>(path, "DA pin-intent cursor"))
            .transpose()?;
        Ok(DaPinIntentListRequest { limit, cursor })
    }
    fn to_proof_request(&self) -> Result<DaPinIntentQueryRequest> {
        if self.limit.is_some() || self.cursor_json.is_some() {
            return Err(eyre!(
                "--limit and --cursor-json are only valid for `pin-intents-list`"
            ));
        }
        let manifest_hash = self
            .manifest_hash
            .as_deref()
            .map(|hash| parse_fixed_hex(hash, "manifest-hash").map(ManifestDigest::new))
            .transpose()?;
        let storage_ticket = self
            .storage_ticket
            .as_deref()
            .map(|ticket| parse_fixed_hex(ticket, "storage-ticket").map(StorageTicketId::new))
            .transpose()?;
        Ok(DaPinIntentQueryRequest {
            manifest_hash,
            storage_ticket,
            alias: self.alias.clone(),
            lane_id: self.lane_id,
            epoch: self.epoch,
            sequence: self.sequence,
        })
    }
}
#[derive(Args, Debug)]
pub struct PinIntentVerifyArgs {
    /// Path to a JSON-encoded `DaPinIntentProof`.
    #[arg(long = "proof-json", value_name = "PATH")]
    pub proof_json: PathBuf,
}
impl PinIntentVerifyArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let proof = load_json_payload::<DaPinIntentProof>(&self.proof_json, "DA pin intent proof")?;
        let client = iroha::blocking::AccountClient::from_client(
            context.client_from_config()?.account_client()?,
        )?;
        let response = client.da().verify_pin_intent(&proof)?;
        let text = render_da_verify_text(
            "DA pin intent verification",
            response.valid,
            response.error.as_deref(),
        );
        print_with_optional_text(context, Some(text), &response)
    }
}
impl SubmitArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let payload_bytes = fs::read(&self.payload)
            .wrap_err_with(|| format!("failed to read payload `{}`", self.payload.display()))?;
        let metadata = match &self.metadata_json {
            Some(path) => load_metadata_from_path(path)?,
            None => ExtraMetadata { items: Vec::new() },
        };
        let manifest_bytes = match &self.manifest_path {
            Some(path) => Some(
                fs::read(path)
                    .wrap_err_with(|| format!("failed to read manifest `{}`", path.display()))?,
            ),
            None => None,
        };
        let params = build_da_params(&self)?;
        let request = da::build_da_request(
            context.config().network_id,
            context.config().account.clone(),
            payload_bytes,
            &params,
            metadata,
            &context.config().key_pair,
            manifest_bytes,
        )?;
        let artifact_root = default_artifact_root(self.artifact_dir)?;
        fs::create_dir_all(&artifact_root).wrap_err_with(|| {
            format!(
                "failed to create artifact directory `{}`",
                artifact_root.display()
            )
        })?;
        // Persist the producer-signed prepare request before network I/O so a failed
        // submission still leaves a complete, replayable artifact.
        let mut request_output = persist_submit_request(&artifact_root, &request)?;
        if self.no_submit {
            if self.receipt_fixture.is_some() {
                return Err(eyre!(
                    "--receipt-fixture cannot be combined with --no-submit (fixture already skips HTTP)"
                ));
            }
            let output = SubmitOutput {
                submitted: false,
                request: request_output,
                receipt: None,
            };
            let text = render_submit_text(&output);
            return print_with_optional_text(context, Some(text), &output);
        }
        let receipt = if let Some(path) = &self.receipt_fixture {
            load_da_receipt_fixture(path, &request)?
        } else {
            let publisher = DaPublisher::new(context.config(), self.endpoint.as_deref())?;
            let request_bytes = to_bytes(&request)
                .map_err(|err| eyre!("failed to encode DA request as Norito: {err}"))?;
            publisher.publish(&request_bytes)?
        };
        // A pending prepare response causes the publisher to add the exact pin-scope
        // witness and retry once. Replace the prepare artifact with the exact request
        // that was submitted last so operators can inspect or gather more witnesses.
        request_output = persist_submit_request(&artifact_root, &receipt.submitted_request)?;
        let receipt_path = artifact_root.join("da_receipt.norito");
        let receipt_json_path = artifact_root.join("da_receipt.json");
        fs::write(&receipt_path, &receipt.bytes)
            .wrap_err_with(|| format!("failed to write DA receipt `{}`", receipt_path.display()))?;
        fs::write(&receipt_json_path, receipt.json.as_bytes()).wrap_err_with(|| {
            format!(
                "failed to write DA receipt JSON `{}`",
                receipt_json_path.display()
            )
        })?;
        if let Some(header_value) = &receipt.pdp_commitment_header {
            persist_receipt_headers(&artifact_root, header_value)?;
        }
        let receipt_record = receipt.receipt.clone();
        let receipt_output = SubmitReceiptOutput {
            status: receipt.status,
            duplicate: receipt.duplicate,
            receipt: receipt_record,
            pin_scope: receipt.pin_scope,
            receipt_path: receipt_path.display().to_string(),
            receipt_json_path: receipt_json_path.display().to_string(),
            pdp_commitment_header: receipt.pdp_commitment_header.clone(),
        };
        let output = SubmitOutput {
            submitted: true,
            request: request_output,
            receipt: Some(receipt_output),
        };
        let text = render_submit_text(&output);
        print_with_optional_text(context, Some(text), &output)
    }
}
#[derive(Args, Debug)]
pub struct ProveArgs {
    /// Path to the Norito-encoded manifest describing the chunk layout.
    #[arg(long, value_name = "PATH")]
    pub manifest: PathBuf,
    /// Path to the assembled payload bytes that match the manifest.
    #[arg(long, value_name = "PATH")]
    pub payload: PathBuf,
    /// Optional JSON output path; defaults to stdout only.
    #[arg(long = "json-out", value_name = "PATH")]
    pub json_out: Option<PathBuf>,
    /// Number of random leaves to sample for `PoR` proofs (0 disables sampling).
    #[arg(long = "sample-count", default_value_t = 8)]
    pub sample_count: usize,
    /// Seed used for deterministic `PoR` sampling.
    #[arg(long = "sample-seed", default_value_t = 0)]
    pub sample_seed: u64,
    /// Explicit `PoR` leaf indexes to prove (0-based flattened index).
    #[arg(long = "leaf-index", value_name = "INDEX")]
    pub leaf_indexes: Vec<usize>,
}
impl ProveArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let manifest = load_manifest(&self.manifest)?;
        let plan = build_car_plan_from_manifest(&manifest)?;
        let mut chunk_store = ChunkStore::with_profile(plan.chunk_profile);
        let mut ingest_source = FilePayload::open(&self.payload)
            .wrap_err_with(|| format!("failed to open payload `{}`", self.payload.display()))?;
        chunk_store
            .ingest_plan_source(&plan, &mut ingest_source)
            .wrap_err("failed to ingest payload for proof generation")?;
        validate_manifest_consistency(&manifest, &chunk_store)?;
        let mut proof_source = FilePayload::open(&self.payload).wrap_err_with(|| {
            format!(
                "failed to reopen payload `{}` for PoR sampling",
                self.payload.display()
            )
        })?;
        let sampling = ProofSampling {
            sample_count: self.sample_count,
            sample_seed: self.sample_seed,
        };
        let por_root = chunk_store.por_tree().root().to_owned();
        let root_hex = hex::encode(por_root);
        let leaf_total = chunk_store.por_tree().leaf_count();
        let segment_total = chunk_store.por_tree().segment_count();
        let chunk_total = chunk_store.por_tree().chunks().len();
        let proofs = self.collect_proofs(&sampling, &chunk_store, &mut proof_source, &por_root)?;
        let summary_inputs = ProofSummaryInputs {
            manifest: &manifest,
            manifest_path: &self.manifest,
            payload_path: &self.payload,
            por_root_hex: root_hex,
            leaf_total,
            segment_total,
            chunk_total,
            sample_count: sampling.sample_count,
            sample_seed: sampling.sample_seed,
        };
        let text = render_proof_summary_text(&summary_inputs, &proofs);
        let summary = build_proof_summary(summary_inputs, &proofs);
        print_with_optional_text(context, Some(text), &summary)?;
        if let Some(path) = &self.json_out {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).wrap_err_with(|| {
                    format!(
                        "failed to create proof output directory `{}`",
                        parent.display()
                    )
                })?;
            }
            let rendered = norito::json::to_json_pretty(&summary)
                .wrap_err("failed to render proof summary JSON")?;
            fs::write(path, rendered).wrap_err_with(|| {
                format!("failed to write proof summary to `{}`", path.display())
            })?;
        }
        Ok(())
    }
    fn collect_proofs(
        &self,
        sampling: &ProofSampling,
        chunk_store: &ChunkStore,
        proof_source: &mut FilePayload,
        por_root: &[u8; 32],
    ) -> Result<Vec<ProofReport>> {
        let mut proofs = Vec::new();
        let mut seen = HashSet::new();
        proofs.extend(Self::sampled_proofs(
            sampling.sample_count,
            sampling.sample_seed,
            chunk_store,
            proof_source,
            por_root,
            &mut seen,
        )?);
        proofs.extend(self.explicit_proofs(chunk_store, proof_source, por_root, &mut seen)?);
        if proofs.is_empty() {
            return Err(eyre!(
                "no proofs were generated; provide --sample-count or --leaf-index"
            ));
        }
        Ok(proofs)
    }
    fn sampled_proofs(
        sample_count: usize,
        sample_seed: u64,
        chunk_store: &ChunkStore,
        proof_source: &mut FilePayload,
        por_root: &[u8; 32],
        seen: &mut HashSet<usize>,
    ) -> Result<Vec<ProofReport>> {
        if sample_count == 0 {
            return Ok(Vec::new());
        }
        let sampled = chunk_store
            .sample_leaves_with(sample_count, sample_seed, proof_source)
            .wrap_err("failed to sample PoR leaves")?;
        let mut proofs = Vec::with_capacity(sampled.len());
        for (leaf_index, proof) in sampled {
            if !seen.insert(leaf_index) {
                continue;
            }
            let verified = proof.verify(por_root);
            proofs.push(ProofReport {
                origin: ProofOrigin::Sampled,
                leaf_index,
                proof,
                verified,
            });
        }
        Ok(proofs)
    }
    fn explicit_proofs(
        &self,
        chunk_store: &ChunkStore,
        proof_source: &mut FilePayload,
        por_root: &[u8; 32],
        seen: &mut HashSet<usize>,
    ) -> Result<Vec<ProofReport>> {
        if self.leaf_indexes.is_empty() {
            return Ok(Vec::new());
        }
        let tree = chunk_store.por_tree();
        let leaf_count = tree.leaf_count();
        let mut proofs = Vec::new();
        for &leaf_index in &self.leaf_indexes {
            if leaf_index >= leaf_count {
                return Err(eyre!(
                    "leaf-index {} out of range (tree tracks {leaf_count} leaves)",
                    leaf_index
                ));
            }
            if !seen.insert(leaf_index) {
                continue;
            }
            let (chunk_idx, segment_idx, inner_idx) = tree
                .leaf_path(leaf_index)
                .ok_or_else(|| eyre!("failed to resolve leaf-index {leaf_index}"))?;
            let proof = tree
                .prove_leaf_with(chunk_idx, segment_idx, inner_idx, proof_source)
                .wrap_err_with(|| format!("failed to build PoR proof for leaf-index {leaf_index}"))?
                .ok_or_else(|| eyre!("missing PoR proof for leaf-index {leaf_index}"))?;
            let verified = proof.verify(por_root);
            proofs.push(ProofReport {
                origin: ProofOrigin::Explicit,
                leaf_index,
                proof,
                verified,
            });
        }
        Ok(proofs)
    }
}
impl ProveAvailabilityArgs {
    #[allow(clippy::too_many_lines)]
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        if self.gateway_provider.is_empty() {
            return Err(eyre!("at least one --gateway-provider must be supplied"));
        }
        let normalized_ticket = normalize_ticket_hex(&self.storage_ticket)?;
        let artifact_root = default_prove_artifact_root(self.artifact_dir.clone())?;
        fs::create_dir_all(&artifact_root).wrap_err_with(|| {
            format!(
                "failed to create prove-availability artifact directory `{}`",
                artifact_root.display()
            )
        })?;
        let manifest_target_dir = self
            .manifest_cache_dir
            .clone()
            .unwrap_or_else(|| artifact_root.clone());
        let fetcher = DaManifestFetcher::new(context.config(), self.torii_url.as_deref())?;
        let bundle = fetcher.fetch(&normalized_ticket)?;
        let persisted = persist_manifest_bundle(
            context,
            &bundle,
            Some(manifest_target_dir.clone()),
            &normalized_ticket,
        )?;
        let payload_path = artifact_root.join("payload.car");
        let scoreboard_path = self
            .scoreboard_out
            .clone()
            .unwrap_or_else(|| artifact_root.join("scoreboard.json"));
        if let Some(parent) = scoreboard_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).wrap_err_with(|| {
                format!(
                    "failed to create scoreboard directory `{}`",
                    parent.display()
                )
            })?;
        }
        let fetch_args = FetchArgs {
            manifest: Some(persisted.manifest_raw.clone()),
            plan: Some(persisted.chunk_plan.clone()),
            manifest_id: Some(bundle.manifest_hash_hex.clone()),
            gateway_provider: self.gateway_provider.clone(),
            storage_ticket: None,
            torii_url: None,
            manifest_cache_dir: None,
            client_id: Some(format!("prove-availability:{normalized_ticket}")),
            manifest_envelope: None,
            manifest_cid: None,
            blinded_cid: None,
            salt_epoch: None,
            salt_hex: None,
            chunker_handle: None,
            max_peers: self.max_peers,
            retry_budget: None,
            transport_policy: None,
            anonymity_policy: None,
            write_mode: None,
            transport_policy_override: None,
            anonymity_policy_override: None,
            guard_cache: None,
            guard_cache_key_file: None,
            guard_directory: None,
            guard_directory_digest: None,
            guard_target: None,
            guard_retention_days: None,
            output: Some(payload_path.clone()),
            json_out: None,
            scoreboard_out: Some(scoreboard_path.clone()),
            scoreboard_now: None,
            telemetry_source_label: None,
            telemetry_region: None,
        };
        fetch_args.run(context)?;
        if matches!(context.output_format(), CliOutputFormat::Text) {
            context.println(format_args!(
                "downloaded payload to `{}`; scoreboard persisted at `{}`",
                payload_path.display(),
                scoreboard_path.display()
            ))?;
        }
        let prove_args = ProveArgs {
            manifest: persisted.manifest_raw,
            payload: payload_path,
            json_out: self.json_out,
            sample_count: self.sample_count,
            sample_seed: self.sample_seed,
            leaf_indexes: self.leaf_indexes,
        };
        prove_args.run(context)
    }
}
#[derive(Args, Debug)]
pub struct ProveAvailabilityArgs {
    /// Storage ticket issued by Torii (hex string).
    #[arg(long = "storage-ticket", value_name = "HEX")]
    pub storage_ticket: String,
    /// Gateway provider descriptor reused by `sorafs fetch` (name=... , provider-id=... , base-url=... , stream-token=...).
    #[arg(long = "gateway-provider", value_name = "SPEC", required = true)]
    pub gateway_provider: Vec<String>,
    /// Optional Torii base URL for manifest reads (must end with `/`).
    #[arg(long = "torii-url", value_name = "URL")]
    pub torii_url: Option<String>,
    /// Directory where manifests and plans downloaded from Torii are cached (defaults to `artifacts/da/fetch_<ts>`).
    #[arg(long = "manifest-cache-dir", value_name = "PATH")]
    pub manifest_cache_dir: Option<PathBuf>,
    /// JSON output path for the combined proof summary (defaults to stdout).
    #[arg(long = "json-out", value_name = "PATH")]
    pub json_out: Option<PathBuf>,
    /// Path to persist the orchestrator scoreboard (defaults to temp dir if omitted).
    #[arg(long = "scoreboard-out", value_name = "PATH")]
    pub scoreboard_out: Option<PathBuf>,
    /// Optional limit on concurrent provider downloads.
    #[arg(long = "max-peers", value_name = "COUNT")]
    pub max_peers: Option<usize>,
    /// Proof sampling count for `PoR` verification (defaults to 8, set 0 to disable random sampling).
    #[arg(long = "sample-count", default_value_t = 8)]
    pub sample_count: usize,
    /// Seed used for deterministic `PoR` sampling during verification.
    #[arg(long = "sample-seed", default_value_t = 0)]
    pub sample_seed: u64,
    /// Explicit `PoR` leaf indexes to verify in addition to sampled values.
    #[arg(long = "leaf-index", value_name = "INDEX")]
    pub leaf_indexes: Vec<usize>,
    /// Directory for storing assembled payload/artefacts (defaults to `artifacts/da/prove_availability_<ts>`).
    #[arg(long = "artifact-dir", value_name = "PATH")]
    pub artifact_dir: Option<PathBuf>,
}
#[derive(Args, Debug)]
pub struct RentQuoteArgs {
    /// Logical GiB stored in the blob (post-chunking).
    #[arg(long = "gib", value_name = "GIB")]
    pub gib: u64,
    /// Retention duration measured in months.
    #[arg(long = "months", value_name = "MONTHS")]
    pub months: u32,
    /// Optional path to a JSON-encoded `DaRentPolicyV1`.
    #[arg(long = "policy-json", value_name = "PATH")]
    pub policy_json: Option<PathBuf>,
    /// Optional path to a Norito-encoded `DaRentPolicyV1`.
    #[arg(long = "policy-norito", value_name = "PATH")]
    pub policy_norito: Option<PathBuf>,
    /// Optional human-readable label recorded in the quote metadata (defaults to source path).
    #[arg(long = "policy-label", value_name = "TEXT")]
    pub policy_label: Option<String>,
    /// Optional path for persisting the rendered quote JSON.
    #[arg(long = "quote-out", value_name = "PATH")]
    pub quote_out: Option<PathBuf>,
}
impl RentQuoteArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        if self.gib == 0 {
            return Err(eyre!("--gib must be greater than zero"));
        }
        if self.months == 0 {
            return Err(eyre!("--months must be greater than zero"));
        }
        let (policy, auto_label) = load_rent_policy_from_paths(
            self.policy_json.as_deref(),
            self.policy_norito.as_deref(),
        )?;
        let source_label = policy_label_or_default(self.policy_label.as_deref(), auto_label)?;
        let quote = policy
            .quote(self.gib, self.months)
            .wrap_err("failed to compute rent quote")?;
        let value = build_rent_quote_value(&policy, self.gib, self.months, &quote, &source_label)?;
        if let Some(path) = self.quote_out.as_deref() {
            write_rent_quote_artifact(path, &value)?;
        }
        let text = render_rent_quote_text(&quote, &source_label, self.quote_out.as_deref());
        print_with_optional_text(context, Some(text), &value)
    }
}
#[derive(clap::Args, Debug)]
pub struct RentLedgerArgs {
    /// Path to the rent quote JSON file (output of `iroha da rent-quote`).
    #[arg(long = "quote", value_name = "PATH")]
    pub quote_path: PathBuf,
    /// Account responsible for paying the rent and funding bonus pools.
    #[arg(long = "payer-account", value_name = "ACCOUNT_ID")]
    pub payer_account: String,
    /// Treasury or escrow account receiving the base rent before distribution.
    #[arg(long = "treasury-account", value_name = "ACCOUNT_ID")]
    pub treasury_account: String,
    /// Protocol reserve account that receives the configured reserve share.
    #[arg(long = "protocol-reserve-account", value_name = "ACCOUNT_ID")]
    pub protocol_reserve_account: String,
    /// Provider payout account that receives the base rent remainder.
    #[arg(long = "provider-account", value_name = "ACCOUNT_ID")]
    pub provider_account: String,
    /// Account earmarked for PDP bonus payouts.
    #[arg(long = "pdp-bonus-account", value_name = "ACCOUNT_ID")]
    pub pdp_bonus_account: String,
    /// Account earmarked for `PoTR` bonus payouts.
    #[arg(long = "potr-bonus-account", value_name = "ACCOUNT_ID")]
    pub potr_bonus_account: String,
    /// Asset definition identifier used for transfers (canonical unprefixed Base58 address).
    #[arg(long = "asset-definition", value_name = "AID")]
    pub asset_definition: String,
}
impl RentLedgerArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let quote_contents = fs::read_to_string(&self.quote_path).wrap_err_with(|| {
            format!("failed to read rent quote `{}`", self.quote_path.display())
        })?;
        let quote_value: Value =
            json::from_str(&quote_contents).wrap_err("failed to parse rent quote JSON")?;
        let projection = extract_rent_ledger_projection(&quote_value)?;
        let payer = crate::resolve_account_id(context, &self.payer_account)
            .wrap_err("failed to resolve --payer-account")?;
        let treasury = crate::resolve_account_id(context, &self.treasury_account)
            .wrap_err("failed to resolve --treasury-account")?;
        let protocol_reserve = crate::resolve_account_id(context, &self.protocol_reserve_account)
            .wrap_err("failed to resolve --protocol-reserve-account")?;
        let provider = crate::resolve_account_id(context, &self.provider_account)
            .wrap_err("failed to resolve --provider-account")?;
        let pdp_bonus = crate::resolve_account_id(context, &self.pdp_bonus_account)
            .wrap_err("failed to resolve --pdp-bonus-account")?;
        let potr_bonus = crate::resolve_account_id(context, &self.potr_bonus_account)
            .wrap_err("failed to resolve --potr-bonus-account")?;
        let asset_definition: AssetDefinitionId = self
            .asset_definition
            .parse()
            .wrap_err("failed to parse --asset-definition")?;
        let accounts = da::DaRentLedgerAccounts {
            payer: &payer,
            treasury: &treasury,
            protocol_reserve: &protocol_reserve,
            provider: &provider,
            pdp_bonus: &pdp_bonus,
            potr_bonus: &potr_bonus,
        };
        let plan =
            build_rent_ledger_plan(&self.quote_path, projection, accounts, &asset_definition)?;
        context.print_data(&plan)
    }
}
fn build_da_params(args: &SubmitArgs) -> Result<DaIngestParams> {
    let blob_class = parse_blob_class(&args.blob_class)?;
    let blob_codec = BlobCodec::new(args.blob_codec.clone());
    let fec_scheme = parse_fec_scheme(&args.fec_scheme)?;
    let erasure_profile = ErasureProfile {
        data_shards: args.data_shards,
        parity_shards: args.parity_shards,
        row_parity_stripes: 0,
        chunk_alignment: args.chunk_alignment,
        fec_scheme,
    };
    let storage_class = parse_storage_class(&args.storage_class)?;
    let retention_policy = RetentionPolicy {
        hot_retention_secs: args.hot_retention_secs,
        cold_retention_secs: args.cold_retention_secs,
        required_replicas: args.required_replicas,
        storage_class,
        governance_tag: GovernanceTag::new(args.governance_tag.clone()),
    };
    let client_blob_id = match &args.client_blob_id {
        Some(hex) => Some(BlobDigest::new(parse_fixed_hex(hex, "client-blob-id")?)),
        None => None,
    };
    Ok(DaIngestParams {
        lane_id: LaneId::new(args.lane_id),
        epoch: args.epoch,
        sequence: args.sequence,
        blob_class,
        blob_codec,
        erasure_profile,
        retention_policy,
        chunk_size: args.chunk_size,
        client_blob_id,
    })
}
fn default_artifact_root(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let mut root = std::env::current_dir().wrap_err("failed to determine current directory")?;
    root.push("artifacts");
    root.push("da");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| eyre!("clock drifted before UNIX_EPOCH: {err}"))?
        .as_secs();
    root.push(format!("submission_{stamp}"));
    Ok(root)
}
fn default_fetch_root(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let mut root = std::env::current_dir().wrap_err("failed to determine current directory")?;
    root.push("artifacts");
    root.push("da");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| eyre!("clock drifted before UNIX_EPOCH: {err}"))?
        .as_secs();
    root.push(format!("fetch_{stamp}"));
    Ok(root)
}
fn default_prove_artifact_root(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    let mut root = std::env::current_dir().wrap_err("failed to determine current directory")?;
    root.push("artifacts");
    root.push("da");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| eyre!("clock drifted before UNIX_EPOCH: {err}"))?
        .as_secs();
    root.push(format!("prove_availability_{stamp}"));
    Ok(root)
}
pub(super) fn normalize_ticket_hex(input: &str) -> Result<String> {
    if input.trim().is_empty() {
        return Err(eyre!("--storage-ticket must be provided"));
    }
    let trimmed = input
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if trimmed.len() != 64 {
        return Err(eyre!(
            "--storage-ticket must contain 64 hexadecimal characters (got {})",
            trimmed.len()
        ));
    }
    hex::decode(trimmed).map_err(|err| eyre!("invalid storage ticket hex: {err}"))?;
    Ok(trimmed.to_ascii_lowercase())
}
pub(super) fn persist_manifest_bundle<C: RunContext>(
    _context: &mut C,
    bundle: &iroha_storage_client::da::DaManifestBundle,
    output_dir: Option<PathBuf>,
    ticket_label: &str,
) -> Result<iroha_storage_client::da::DaManifestPersistedPaths> {
    bundle.persist_to_dir(default_fetch_root(output_dir)?, ticket_label)
}

fn build_manifest_fetch_value(
    bundle: &iroha_storage_client::da::DaManifestBundle,
    persisted: &iroha_storage_client::da::DaManifestPersistedPaths,
) -> Value {
    let mut map = Map::new();
    map.insert(
        "storage_ticket".into(),
        Value::from(bundle.storage_ticket_hex.clone()),
    );
    map.insert(
        "manifest_hash".into(),
        Value::from(bundle.manifest_hash_hex.clone()),
    );
    map.insert(
        "blob_hash".into(),
        Value::from(bundle.blob_hash_hex.clone()),
    );
    map.insert(
        "manifest_path".into(),
        Value::from(path_to_string(&persisted.manifest_raw)),
    );
    map.insert(
        "manifest_json_path".into(),
        Value::from(path_to_string(&persisted.manifest_json)),
    );
    map.insert(
        "chunk_plan_path".into(),
        Value::from(path_to_string(&persisted.chunk_plan)),
    );
    map.insert("manifest".into(), bundle.manifest_json.clone());
    map.insert("chunk_plan".into(), bundle.chunk_plan.clone());
    Value::Object(map)
}
fn render_manifest_fetch_text(
    bundle: &iroha_storage_client::da::DaManifestBundle,
    persisted: &iroha_storage_client::da::DaManifestPersistedPaths,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "DA manifest fetched");
    let _ = writeln!(out, "storage_ticket: {}", bundle.storage_ticket_hex);
    let _ = writeln!(out, "manifest_hash: {}", bundle.manifest_hash_hex);
    let _ = writeln!(out, "blob_hash: {}", bundle.blob_hash_hex);
    let _ = writeln!(out, "manifest: {}", persisted.manifest_raw.display());
    let _ = writeln!(out, "manifest_json: {}", persisted.manifest_json.display());
    let _ = writeln!(out, "chunk_plan: {}", persisted.chunk_plan.display());
    out
}
fn render_submit_text(output: &SubmitOutput) -> String {
    let mut out = String::new();
    if output.submitted {
        let _ = writeln!(out, "DA ingest submitted");
    } else {
        let _ = writeln!(out, "DA ingest request prepared (submission skipped)");
    }
    let _ = writeln!(out, "client_blob_id: {}", output.request.client_blob_id);
    let _ = writeln!(out, "request: {}", output.request.request_path);
    let _ = writeln!(out, "request_json: {}", output.request.request_json_path);
    let _ = writeln!(out, "request_bytes: {}", output.request.request_bytes);
    if let Some(receipt) = output.receipt.as_ref() {
        let _ = writeln!(out, "status: {}", receipt.status);
        let _ = writeln!(out, "duplicate: {}", receipt.duplicate);
        let _ = writeln!(out, "receipt: {}", receipt.receipt_path);
        let _ = writeln!(out, "receipt_json: {}", receipt.receipt_json_path);
        if let Some(header) = receipt.pdp_commitment_header.as_deref() {
            let _ = writeln!(out, "pdp_commitment_header: {}", header);
        }
    }
    out
}
fn render_da_proof_policies_text(title: &str, bundle: &DaProofPolicyBundle) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{title}");
    let _ = writeln!(out, "version: {}", bundle.version());
    let _ = writeln!(
        out,
        "policy_hash: {}",
        hex::encode(bundle.policy_hash().as_ref())
    );
    let _ = writeln!(out, "policy_count: {}", bundle.policies().len());
    out
}
fn render_da_commitments_list_text(response: &iroha::da::DaCommitmentListResponse) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "DA commitments");
    let _ = writeln!(out, "version: {}", response.policies.version());
    let _ = writeln!(
        out,
        "policy_hash: {}",
        hex::encode(response.policies.policy_hash().as_ref())
    );
    let _ = writeln!(out, "policy_count: {}", response.policies.policies().len());
    let _ = writeln!(out, "commitment_count: {}", response.commitments.len());
    let _ = writeln!(out, "has_next_cursor: {}", response.next_cursor.is_some());
    out
}
fn render_da_commitment_prove_text(
    response: &Option<iroha::da::DaCommitmentProofResponse>,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "DA commitment proof");
    match response {
        Some(payload) => {
            let _ = writeln!(out, "found: true");
            let _ = writeln!(
                out,
                "proof_scheme: {}",
                payload.proof.commitment.proof_scheme
            );
            let _ = writeln!(out, "bundle_len: {}", payload.proof.bundle_len);
        }
        None => {
            let _ = writeln!(out, "found: false");
        }
    }
    out
}
fn render_da_pin_intents_list_text(response: &iroha::da::DaPinIntentListResponse) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "DA pin intents");
    let _ = writeln!(out, "pin_intent_count: {}", response.intents.len());
    let _ = writeln!(out, "has_next_cursor: {}", response.next_cursor.is_some());
    out
}
fn render_da_pin_intent_prove_text(response: &Option<DaPinIntentProof>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "DA pin intent proof");
    match response {
        Some(record) => {
            let _ = writeln!(out, "found: true");
            let _ = writeln!(
                out,
                "storage_ticket: {}",
                hex::encode(record.intent.storage_ticket.as_ref())
            );
        }
        None => {
            let _ = writeln!(out, "found: false");
        }
    }
    out
}
fn render_da_verify_text(title: &str, valid: bool, error: Option<&str>) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{title}");
    let _ = writeln!(out, "valid: {valid}");
    if let Some(error) = error
        && !error.trim().is_empty()
    {
        let _ = writeln!(out, "error: {error}");
    }
    out
}
fn persist_receipt_headers(root: &Path, header_value: &str) -> Result<()> {
    let mut headers = Map::new();
    headers.insert(
        "sora-pdp-commitment".to_string(),
        Value::from(header_value.to_string()),
    );
    let rendered = norito::json::to_json_pretty(&Value::Object(headers))
        .map_err(|err| eyre!("failed to render DA response header JSON: {err}"))?;
    let headers_path = root.join("da_response_headers.json");
    fs::write(&headers_path, rendered).wrap_err_with(|| {
        format!(
            "failed to write DA response headers `{}`",
            headers_path.display()
        )
    })
}
fn persist_submit_request(root: &Path, request: &DaIngestRequest) -> Result<SubmitRequestOutput> {
    let request_bytes =
        to_bytes(request).map_err(|err| eyre!("failed to encode DA request as Norito: {err}"))?;
    let request_json = norito::json::to_json_pretty(request)
        .map_err(|err| eyre!("failed to render DA request JSON: {err}"))?;
    let request_path = root.join("da_request.norito");
    let request_json_path = root.join("da_request.json");
    fs::write(&request_path, &request_bytes)
        .wrap_err_with(|| format!("failed to write DA request `{}`", request_path.display()))?;
    fs::write(&request_json_path, request_json.as_bytes()).wrap_err_with(|| {
        format!(
            "failed to write DA request JSON `{}`",
            request_json_path.display()
        )
    })?;
    Ok(SubmitRequestOutput {
        client_blob_id: hex::encode(request.client_blob_id.as_bytes()),
        request_path: request_path.display().to_string(),
        request_json_path: request_json_path.display().to_string(),
        request_bytes: request_bytes.len(),
    })
}
fn load_da_receipt_fixture(
    path: &Path,
    submitted_request: &DaIngestRequest,
) -> Result<DaPublisherReceipt> {
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read DA receipt fixture `{}`", path.display()))?;
    let value: Value = norito::json::from_slice(&bytes).map_err(|err| {
        eyre!(
            "failed to parse DA receipt fixture `{}` as JSON: {err}",
            path.display()
        )
    })?;
    let receipt_b64 = value
        .get("receipt_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            eyre!(
                "receipt fixture `{}` is missing `receipt_base64` field",
                path.display()
            )
        })?;
    let receipt_bytes = Base64Standard
        .decode(receipt_b64.as_bytes())
        .map_err(|err| {
            eyre!(
                "receipt fixture `{}` contains invalid base64 payload: {err}",
                path.display()
            )
        })?;
    let receipt: DaIngestReceipt = decode_from_bytes(&receipt_bytes).map_err(|err| {
        eyre!(
            "failed to decode DA receipt from fixture `{}`: {err}",
            path.display()
        )
    })?;
    let json = norito::json::to_json_pretty(&receipt).map_err(|err| {
        eyre!(
            "failed to render DA receipt JSON from fixture `{}`: {err}",
            path.display()
        )
    })?;
    let header_value = value
        .get("headers")
        .and_then(Value::as_object)
        .and_then(|headers| headers.get("sora-pdp-commitment"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    Ok(DaPublisherReceipt {
        status: "accepted".to_owned(),
        duplicate: false,
        bytes: receipt_bytes,
        json,
        receipt,
        pin_scope: None,
        submitted_request: submitted_request.clone(),
        pdp_commitment_header: header_value,
    })
}
fn parse_fixed_hex(label: &str, field: &str) -> Result<[u8; 32]> {
    let trimmed = label.strip_prefix("0x").unwrap_or(label);
    let bytes =
        hex::decode(trimmed).map_err(|err| eyre!("invalid hex for `{field}` `{label}`: {err}"))?;
    let byte_len = bytes.len();
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| eyre!("`{field}` must decode to 32 bytes, got {byte_len}"))?;
    Ok(array)
}
fn load_json_payload<T>(path: &Path, label: &str) -> Result<T>
where
    T: norito::json::JsonDeserialize,
{
    let bytes = fs::read(path)
        .wrap_err_with(|| format!("failed to read {label} JSON `{}`", path.display()))?;
    norito::json::from_slice(&bytes).wrap_err_with(|| {
        format!(
            "failed to decode {label} JSON payload from `{}`",
            path.display()
        )
    })
}
fn load_manifest(path: &Path) -> Result<DaManifestV1> {
    let bytes =
        fs::read(path).wrap_err_with(|| format!("failed to read manifest `{}`", path.display()))?;
    decode_from_bytes(&bytes)
        .map_err(|err| eyre!("failed to decode manifest `{}`: {err}", path.display()))
}
#[derive(Clone, Copy)]
struct ProofSampling {
    sample_count: usize,
    sample_seed: u64,
}
struct ProofSummaryInputs<'a> {
    manifest: &'a DaManifestV1,
    manifest_path: &'a Path,
    payload_path: &'a Path,
    por_root_hex: String,
    leaf_total: usize,
    segment_total: usize,
    chunk_total: usize,
    sample_count: usize,
    sample_seed: u64,
}
fn render_proof_summary_text(inputs: &ProofSummaryInputs<'_>, proofs: &[ProofReport]) -> String {
    let verified = proofs.iter().filter(|report| report.verified).count();
    let mut out = String::new();
    let _ = writeln!(out, "DA proof summary");
    let _ = writeln!(out, "manifest: {}", inputs.manifest_path.display());
    let _ = writeln!(out, "payload: {}", inputs.payload_path.display());
    let _ = writeln!(
        out,
        "blob_hash: {}",
        hex::encode(inputs.manifest.blob_hash.as_ref())
    );
    let _ = writeln!(
        out,
        "chunk_root: {}",
        hex::encode(inputs.manifest.chunk_root.as_ref())
    );
    let _ = writeln!(out, "por_root: {}", inputs.por_root_hex);
    let _ = writeln!(out, "chunk_count: {}", inputs.chunk_total);
    let _ = writeln!(out, "segment_count: {}", inputs.segment_total);
    let _ = writeln!(out, "leaf_count: {}", inputs.leaf_total);
    let _ = writeln!(out, "sample_count: {}", inputs.sample_count);
    let _ = writeln!(out, "sample_seed: 0x{:016x}", inputs.sample_seed);
    let _ = writeln!(out, "proofs: {} (verified {})", proofs.len(), verified);
    out
}
fn build_proof_summary(inputs: ProofSummaryInputs<'_>, proofs: &[ProofReport]) -> Value {
    let mut map = Map::new();
    map.insert(
        "manifest_path".into(),
        Value::from(inputs.manifest_path.display().to_string()),
    );
    map.insert(
        "payload_path".into(),
        Value::from(inputs.payload_path.display().to_string()),
    );
    map.insert(
        "blob_hash".into(),
        Value::from(hex::encode(inputs.manifest.blob_hash.as_ref())),
    );
    map.insert(
        "chunk_root".into(),
        Value::from(hex::encode(inputs.manifest.chunk_root.as_ref())),
    );
    map.insert("por_root".into(), Value::from(inputs.por_root_hex));
    map.insert("leaf_count".into(), value_from_usize(inputs.leaf_total));
    map.insert(
        "segment_count".into(),
        value_from_usize(inputs.segment_total),
    );
    map.insert("chunk_count".into(), value_from_usize(inputs.chunk_total));
    map.insert("sample_count".into(), value_from_usize(inputs.sample_count));
    map.insert("sample_seed".into(), Value::from(inputs.sample_seed));
    map.insert("proof_count".into(), value_from_usize(proofs.len()));
    let proof_values = proofs.iter().map(proof_to_json).collect::<Vec<_>>();
    map.insert("proofs".into(), Value::Array(proof_values));
    Value::Object(map)
}
fn load_rent_policy_from_paths(
    json_path: Option<&Path>,
    norito_path: Option<&Path>,
) -> Result<(DaRentPolicyV1, String)> {
    match (json_path, norito_path) {
        (Some(_), Some(_)) => Err(eyre!(
            "only one of --policy-json or --policy-norito may be supplied"
        )),
        (Some(path), None) => {
            let contents = fs::read_to_string(path).wrap_err_with(|| {
                format!("failed to read rent policy JSON `{}`", path.display())
            })?;
            let policy: DaRentPolicyV1 =
                json::from_str(&contents).wrap_err("failed to parse rent policy JSON")?;
            Ok((policy, format!("policy JSON `{}`", path.display())))
        }
        (None, Some(path)) => {
            let bytes = fs::read(path).wrap_err_with(|| {
                format!("failed to read rent policy Norito `{}`", path.display())
            })?;
            let policy = decode_from_bytes::<DaRentPolicyV1>(&bytes)
                .wrap_err("failed to decode rent policy Norito bytes")?;
            Ok((policy, format!("policy Norito `{}`", path.display())))
        }
        (None, None) => Ok((
            DaRentPolicyV1::default(),
            "embedded default policy".to_string(),
        )),
    }
}
fn policy_label_or_default(custom: Option<&str>, default_label: String) -> Result<String> {
    custom.map_or_else(
        || Ok(default_label),
        |label| {
            let trimmed = label.trim();
            if trimmed.is_empty() {
                Err(eyre!("--policy-label must not be empty"))
            } else {
                Ok(trimmed.to_string())
            }
        },
    )
}
fn format_rent_quote_summary(quote: &DaRentQuote) -> String {
    format!(
        "rent_quote base={} reserve={} provider={} pdp_bonus={} potr_bonus={} egress_credit_per_gib={}",
        format_xor_amount(&quote.base_rent, "XOR"),
        format_xor_amount(&quote.protocol_reserve, "XOR"),
        format_xor_amount(&quote.provider_reward, "XOR"),
        format_xor_amount(&quote.pdp_bonus, "XOR"),
        format_xor_amount(&quote.potr_bonus, "XOR"),
        format_xor_amount(&quote.egress_credit_per_gib, "XOR/GiB"),
    )
}
fn render_rent_quote_text(
    quote: &DaRentQuote,
    source_label: &str,
    quote_out: Option<&Path>,
) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", format_rent_quote_summary(quote));
    let _ = writeln!(out, "policy_source: {}", source_label);
    if let Some(path) = quote_out {
        let _ = writeln!(out, "quote_out: {}", path.display());
    }
    out
}
fn format_xor_amount(amount: &XorQuantity, unit: &str) -> String {
    format!("{amount} {unit}")
}
fn build_rent_quote_value(
    policy: &DaRentPolicyV1,
    gib: u64,
    months: u32,
    quote: &DaRentQuote,
    source_label: &str,
) -> Result<Value> {
    let mut map = Map::new();
    map.insert(
        "policy_source".into(),
        Value::from(source_label.to_string()),
    );
    map.insert("gib".into(), Value::Number(Number::from(gib)));
    map.insert(
        "months".into(),
        Value::Number(Number::from(u64::from(months))),
    );
    let policy_value =
        json::to_value(policy).wrap_err("failed to serialize DA rent policy to JSON")?;
    map.insert("policy".into(), policy_value);
    let quote_value =
        json::to_value(quote).wrap_err("failed to serialize DA rent quote to JSON")?;
    map.insert("quote".into(), quote_value);
    let projection_value = json::to_value(&quote.ledger_projection())
        .wrap_err("failed to serialize DA rent ledger projection to JSON")?;
    map.insert("ledger_projection".into(), projection_value);
    Ok(Value::Object(map))
}
fn extract_rent_ledger_projection(value: &Value) -> Result<DaRentLedgerProjection> {
    let root = value
        .as_object()
        .ok_or_else(|| eyre!("rent quote must be a JSON object"))?;
    let ledger_value = root
        .get("ledger_projection")
        .ok_or_else(|| eyre!("rent quote missing `ledger_projection` block"))?;
    json::from_value(ledger_value.clone())
        .wrap_err("failed to decode DA rent ledger projection from quote")
}
fn build_rent_ledger_plan(
    quote_path: &Path,
    projection: DaRentLedgerProjection,
    accounts: da::DaRentLedgerAccounts<'_>,
    asset_definition: &AssetDefinitionId,
) -> Result<Value> {
    let plan = da::build_da_rent_ledger_plan(&projection, &accounts, asset_definition);
    render_rent_ledger_plan(quote_path, &plan)
}
fn render_rent_ledger_plan(quote_path: &Path, plan: &DaRentLedgerPlan) -> Result<Value> {
    let mut serialized_instructions = Vec::with_capacity(plan.instructions.len());
    for instruction in &plan.instructions {
        let rendered = norito::json::to_value(instruction)
            .wrap_err("failed to serialize rent ledger transfer instruction")?;
        serialized_instructions.push(rendered);
    }
    let mut map = Map::new();
    map.insert(
        "quote_path".into(),
        Value::from(quote_path.display().to_string()),
    );
    map.insert("rent_due".into(), ledger_quantity_value(&plan.rent_due));
    map.insert(
        "protocol_reserve_due".into(),
        ledger_quantity_value(&plan.protocol_reserve_due),
    );
    map.insert(
        "provider_reward_due".into(),
        ledger_quantity_value(&plan.provider_reward_due),
    );
    map.insert(
        "pdp_bonus_pool".into(),
        ledger_quantity_value(&plan.pdp_bonus_pool),
    );
    map.insert(
        "potr_bonus_pool".into(),
        ledger_quantity_value(&plan.potr_bonus_pool),
    );
    map.insert(
        "egress_credit_per_gib".into(),
        ledger_quantity_value(&plan.egress_credit_per_gib),
    );
    map.insert("instructions".into(), Value::Array(serialized_instructions));
    Ok(Value::Object(map))
}
fn ledger_quantity_value(amount: &XorQuantity) -> Value {
    Value::String(amount.to_string())
}
fn write_rent_quote_artifact(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).wrap_err_with(|| {
            format!(
                "failed to create rent quote artifact directory `{}`",
                parent.display()
            )
        })?;
    }
    let rendered = json::to_json_pretty(value).wrap_err("serialize rent quote artifact")?;
    fs::write(path, rendered)
        .wrap_err_with(|| format!("failed to write rent quote artifact `{}`", path.display()))
}
fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
#[cfg(test)]
mod tests {
    mod queries;
    use super::*;
    use iroha::{
        config::{self, Config},
        crypto::{Hash, HashOf, KeyPair},
        data_model::prelude::AccountId,
    };
    use iroha_crypto::Algorithm;
    use iroha_data_model::da::{
        commitment::DaProofPolicyBundle,
        ingest::{
            DaIngestAuthorizationV1, DaIngestSignatureV1, DaPinScopeAuthorizationV1, DaPinScopeV1,
        },
        manifest::{ChunkCommitment, ChunkRole},
        pin_intent::{DaPinIntent, DaPinIntentBundle},
        types::{
            BlobClass, BlobDigest, DaRentQuote, ErasureProfile, ExtraMetadata, FecScheme,
            GovernanceTag, MetadataEntry, MetadataVisibility, RetentionPolicy, StorageTicketId,
        },
    };
    use iroha_data_model::sorafs::pin_registry::StorageClass;
    use iroha_i18n::{Bundle, Language, Localizer};
    use iroha_model_base::chain::ChainId;
    use iroha_model_base::metadata::Metadata;
    use norito::{json::JsonSerialize, to_bytes};
    use sorafs_car::PorProof;
    use std::{
        fmt::Display,
        fs,
        path::{Path, PathBuf},
    };
    use tempfile::{NamedTempFile, tempdir};
    use url::Url;
    fn fixture_key_pair(seed: u8) -> KeyPair {
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("fixture seed must derive a valid keypair")
    }
    fn checked_da_context_key_fixture() -> KeyPair {
        KeyPair::try_random().expect("generate checked DA command fixture key")
    }
    #[test]
    fn da_context_fixture_uses_checked_default_key_generation() {
        let key_pair = checked_da_context_key_fixture();
        let actual = key_pair
            .public_key()
            .try_algorithm()
            .expect("DA command fixture key advertises a valid algorithm");
        assert_eq!(actual, Algorithm::default());
    }
    struct TestContext {
        cfg: Config,
        client_override: Option<iroha::client::Client>,
        printed: Vec<String>,
        i18n: Localizer,
        output_format: CliOutputFormat,
    }
    impl TestContext {
        fn new(output_format: CliOutputFormat) -> Self {
            let key_pair = checked_da_context_key_fixture();
            let account = AccountId::new(key_pair.public_key().clone());
            let cfg = Config {
                chain: ChainId::from("test-chain"),
                network_id:
                    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                        .parse()
                        .expect("network id"),
                account,
                account_chain_discriminant:
                    iroha_config::parameters::defaults::common::chain_discriminant(),
                key_pair,
                basic_auth: None,
                api_token: None,
                http_transport_policy: iroha::config::HttpTransportPolicy::Ordinary,
                torii_api_url: Url::parse("http://localhost/").expect("url"),
                torii_request_timeout: config::DEFAULT_TORII_REQUEST_TIMEOUT,
                transaction_ttl: config::DEFAULT_TRANSACTION_TIME_TO_LIVE,
                transaction_status_timeout: config::DEFAULT_TRANSACTION_STATUS_TIMEOUT,
                transaction_add_nonce: config::DEFAULT_TRANSACTION_NONCE,
                sorafs_alias_cache: crate::config_utils::default_alias_cache_policy(),
                sorafs_anonymity_policy: crate::config_utils::default_anonymity_policy(),
                sorafs_rollout_phase: crate::config_utils::default_rollout_phase(),
            };
            Self {
                cfg,
                client_override: None,
                printed: Vec::new(),
                i18n: Localizer::new(Bundle::Cli, Language::English),
                output_format,
            }
        }
    }
    impl RunContext for TestContext {
        fn client_from_config(&self) -> Result<iroha::client::Client> {
            if let Some(client) = &self.client_override {
                return Ok(client.clone());
            }
            Ok(iroha::client::Client::builder(self.cfg.clone()).build()?)
        }
        fn config(&self) -> &Config {
            &self.cfg
        }
        fn transaction_metadata(&self) -> Option<&Metadata> {
            None
        }
        fn input_instructions(&self) -> bool {
            false
        }
        fn output_instructions(&self) -> bool {
            false
        }
        fn i18n(&self) -> &Localizer {
            &self.i18n
        }
        fn output_format(&self) -> CliOutputFormat {
            self.output_format
        }
        fn print_data<T>(&mut self, data: &T) -> Result<()>
        where
            T: JsonSerialize + ?Sized,
        {
            let bytes = norito::json::to_vec(data)?;
            let out = String::from_utf8(bytes).map_err(|err| eyre!(err.to_string()))?;
            self.printed.push(out);
            Ok(())
        }
        fn println(&mut self, data: impl Display) -> Result<()> {
            self.printed.push(data.to_string());
            Ok(())
        }
    }
    #[test]
    fn parse_fixed_hex_rejects_short_values() {
        let err = parse_fixed_hex("00ff", "demo").expect_err("expected failure");
        assert!(
            err.to_string().contains("must decode to 32 bytes"),
            "{err:?}"
        );
    }
    #[test]
    fn default_artifact_root_builds_path() {
        let root = default_artifact_root(None).expect("root");
        let display = root.to_string_lossy();
        assert!(
            display.contains("artifacts/da") || display.contains("artifacts\\da"),
            "unexpected root: {root:?}"
        );
    }
    #[test]
    fn car_plan_matches_manifest_chunks() {
        let manifest = sample_manifest();
        let plan = build_car_plan_from_manifest(&manifest).expect("plan");
        assert_eq!(plan.chunks.len(), manifest.chunks.len());
        assert_eq!(plan.content_length, manifest.total_size);
        assert_eq!(plan.payload_digest.as_bytes(), manifest.blob_hash.as_ref());
    }
    #[test]
    fn proof_summary_renders_expected_fields() {
        let manifest = sample_manifest();
        let proof = ProofReport {
            origin: ProofOrigin::Sampled,
            leaf_index: 0,
            proof: dummy_proof(),
            verified: true,
        };
        let proofs = vec![proof];
        let summary_inputs = ProofSummaryInputs {
            manifest: &manifest,
            manifest_path: Path::new("manifest.to"),
            payload_path: Path::new("payload.bin"),
            por_root_hex: "abcd".into(),
            leaf_total: 1,
            segment_total: 1,
            chunk_total: 1,
            sample_count: 1,
            sample_seed: 42,
        };
        let summary = build_proof_summary(summary_inputs, &proofs);
        let map = summary
            .as_object()
            .expect("summary should be a JSON object");
        assert_eq!(map.get("proof_count").and_then(Value::as_u64), Some(1));
        assert_eq!(map.get("sample_seed").and_then(Value::as_u64), Some(42));
        let proofs = map
            .get("proofs")
            .and_then(Value::as_array)
            .expect("proofs array");
        assert_eq!(proofs.len(), 1);
    }
    #[test]
    fn prove_artifact_root_prefers_explicit_path() {
        let expected = PathBuf::from("/tmp/prove_root_custom");
        let actual = default_prove_artifact_root(Some(expected.clone())).expect("root");
        assert_eq!(actual, expected);
    }
    #[test]
    fn prove_artifact_root_generates_timestamped_directory() {
        let path = default_prove_artifact_root(None).expect("root");
        let rendered = path.to_string_lossy();
        assert!(
            rendered.contains("prove_availability_"),
            "unexpected prove root: {rendered}"
        );
    }
    #[test]
    fn rent_policy_json_source_loads() {
        let policy = DaRentPolicyV1::from_components(
            "0.5".parse().expect("canonical base rate"),
            1_000,
            250,
            125,
            "0.0025".parse().expect("canonical egress credit"),
        );
        let tmp = NamedTempFile::new().expect("temp file");
        let rendered = norito::json::to_json_pretty(&policy).expect("render JSON for rent policy");
        fs::write(tmp.path(), rendered).expect("write JSON");
        let (loaded, label) = load_rent_policy_from_paths(Some(tmp.path()), None).expect("policy");
        assert_eq!(loaded, policy);
        assert!(
            label.contains("policy JSON"),
            "expected JSON label, got {label}"
        );
    }
    #[test]
    fn rent_policy_norito_source_loads() {
        let policy = DaRentPolicyV1::from_components(
            "0.1".parse().expect("canonical base rate"),
            0,
            0,
            0,
            "0.001".parse().expect("canonical egress credit"),
        );
        let tmp = NamedTempFile::new().expect("temp file");
        let bytes = to_bytes(&policy).expect("encode policy");
        fs::write(tmp.path(), bytes).expect("write Norito");
        let (loaded, label) = load_rent_policy_from_paths(None, Some(tmp.path())).expect("policy");
        assert_eq!(loaded, policy);
        assert!(
            label.contains("policy Norito"),
            "expected Norito label, got {label}"
        );
    }
    #[test]
    fn rent_policy_rejects_dual_sources() {
        let tmp = NamedTempFile::new().expect("temp file");
        let err = load_rent_policy_from_paths(Some(tmp.path()), Some(tmp.path()))
            .expect_err("should fail");
        assert!(
            err.to_string()
                .contains("only one of --policy-json or --policy-norito"),
            "{err:?}"
        );
    }
    #[test]
    fn rent_quote_value_contains_expected_fields() {
        let policy = DaRentPolicyV1::default();
        let quote = policy.quote(2, 1).expect("quote");
        let value =
            build_rent_quote_value(&policy, 2, 1, &quote, "unit-test policy").expect("value");
        let obj = value.as_object().expect("object");
        assert_eq!(
            obj.get("policy_source").and_then(Value::as_str),
            Some("unit-test policy")
        );
        assert_eq!(obj.get("gib").and_then(Value::as_u64), Some(2));
        assert_eq!(obj.get("months").and_then(Value::as_u64), Some(1));
        assert!(obj.get("policy").is_some(), "policy missing");
        assert!(obj.get("quote").is_some(), "quote missing");
        let ledger = obj
            .get("ledger_projection")
            .and_then(Value::as_object)
            .expect("ledger projection missing");
        assert!(
            ledger.contains_key("rent_due"),
            "ledger projection must expose rent_due: {ledger:?}"
        );
    }
    #[test]
    fn rent_quote_writer_persists_json() {
        let policy = DaRentPolicyV1::default();
        let quote = policy.quote(8, 3).expect("quote");
        let value = build_rent_quote_value(&policy, 8, 3, &quote, "embedded default policy")
            .expect("value");
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("rent").join("quote.json");
        write_rent_quote_artifact(&path, &value).expect("write artifact");
        let contents = fs::read_to_string(&path).expect("rent quote contents");
        assert!(contents.contains("\"policy_source\""));
        assert!(contents.contains("embedded default policy"));
    }
    #[test]
    fn format_xor_amount_renders_canonical_exact_quantity() {
        let amount: XorQuantity = "1.234567891".parse().expect("canonical XOR quantity");
        let rendered = format_xor_amount(&amount, "XOR");
        assert_eq!(rendered, "1.234567891 XOR");
    }
    #[test]
    fn rent_quote_summary_includes_all_fields() {
        let quote = DaRentQuote {
            base_rent: "0.25".parse().expect("canonical quantity"),
            protocol_reserve: "0.05".parse().expect("canonical quantity"),
            provider_reward: "0.2".parse().expect("canonical quantity"),
            pdp_bonus: "0.01".parse().expect("canonical quantity"),
            potr_bonus: "0.005".parse().expect("canonical quantity"),
            egress_credit_per_gib: "0.0015".parse().expect("canonical quantity"),
        };
        let summary = format_rent_quote_summary(&quote);
        assert!(
            summary.contains("base=0.25 XOR"),
            "missing base rent text: {summary}"
        );
        assert!(
            summary.contains("egress_credit_per_gib=0.0015 XOR/GiB"),
            "missing egress credit text: {summary}"
        );
    }
    #[test]
    fn rent_quote_run_emits_text_in_text_mode() {
        let mut ctx = TestContext::new(CliOutputFormat::Text);
        let args = RentQuoteArgs {
            gib: 4,
            months: 2,
            policy_json: None,
            policy_norito: None,
            policy_label: Some("demo policy".to_string()),
            quote_out: None,
        };
        args.run(&mut ctx).expect("rent quote run");
        assert_eq!(ctx.printed.len(), 1, "expected text summary only");
        assert!(
            ctx.printed[0].starts_with("rent_quote base="),
            "summary should include rent base line: {}",
            ctx.printed[0]
        );
        assert!(
            ctx.printed[0].contains("policy_source: demo policy"),
            "summary should include policy source: {}",
            ctx.printed[0]
        );
    }
    #[test]
    fn rent_quote_run_emits_json_in_json_mode() {
        let mut ctx = TestContext::new(CliOutputFormat::Json);
        let args = RentQuoteArgs {
            gib: 4,
            months: 2,
            policy_json: None,
            policy_norito: None,
            policy_label: Some("demo policy".to_string()),
            quote_out: None,
        };
        args.run(&mut ctx).expect("rent quote run");
        assert_eq!(ctx.printed.len(), 1, "expected JSON output only");
        let root: Value = json::from_str(&ctx.printed[0]).expect("parse quote JSON");
        assert_eq!(
            root.get("policy_source"),
            Some(&Value::String("demo policy".into()))
        );
        assert_eq!(root.get("gib").and_then(Value::as_u64), Some(4));
        assert_eq!(root.get("months").and_then(Value::as_u64), Some(2));
    }
    #[test]
    fn rent_ledger_projection_extracts_values() {
        let policy = DaRentPolicyV1::default();
        let quote = policy.quote(6, 2).expect("quote");
        let value = build_rent_quote_value(&policy, 6, 2, &quote, "embedded default policy")
            .expect("value");
        let projection = extract_rent_ledger_projection(&value).expect("projection");
        assert_eq!(projection.rent_due, quote.base_rent);
        assert_eq!(projection.protocol_reserve_due, quote.protocol_reserve);
        assert_eq!(projection.provider_reward_due, quote.provider_reward);
    }
    #[test]
    fn rent_ledger_projection_rejects_non_string_and_noncanonical_quantities() {
        let policy = DaRentPolicyV1::default();
        let quote = policy.quote(6, 2).expect("quote");
        let valid = build_rent_quote_value(&policy, 6, 2, &quote, "embedded default policy")
            .expect("value");
        for invalid in [
            Value::Number(Number::from(1_u64)),
            Value::String("+1".into()),
            Value::String("01".into()),
            Value::String("1.0".into()),
            Value::String("-1".into()),
            Value::String("0.0000000001".into()),
            Value::String(
                "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048"
                    .into(),
            ),
        ] {
            let mut value = valid.clone();
            value
                .as_object_mut()
                .expect("quote object")
                .get_mut("ledger_projection")
                .expect("ledger projection")
                .as_object_mut()
                .expect("ledger object")
                .insert("rent_due".into(), invalid.clone());
            assert!(
                extract_rent_ledger_projection(&value).is_err(),
                "invalid exact quantity must be rejected: {invalid:?}"
            );
        }
    }
    #[test]
    fn ledger_quantity_value_preserves_sub_micro_and_wide_amounts() {
        for canonical in [
            "0.000000001",
            "340282366920938463463374607431768211456.000000001",
        ] {
            let amount: XorQuantity = canonical.parse().expect("canonical wide XOR quantity");
            assert_eq!(
                ledger_quantity_value(&amount),
                Value::String(canonical.into())
            );
        }
    }
    #[test]
    fn manifest_fetch_value_includes_paths() {
        let manifest = sample_manifest();
        let manifest_bytes = to_bytes(&manifest).expect("encode manifest");
        let manifest_json = norito::json::to_value(&manifest).expect("manifest JSON");
        let storage_ticket = "feedface".repeat(8);
        let bundle = iroha_storage_client::da::DaManifestBundle {
            client_blob_id_hex: hex::encode(manifest.client_blob_id.as_bytes()),
            chunk_root_hex: hex::encode(manifest.chunk_root.as_bytes()),
            lane_id: u64::from(manifest.lane_id.as_u32()),
            epoch: manifest.epoch,
            manifest_len: to_bytes(&manifest).unwrap().len() as u64,
            manifest_bytes,
            manifest_json,
            chunk_plan: sample_chunk_fetch_plan(&manifest),
            storage_ticket_hex: storage_ticket.clone(),
            manifest_hash_hex: "aa".repeat(32),
            blob_hash_hex: hex::encode(manifest.blob_hash.as_ref()),
        };
        let persisted = iroha_storage_client::da::DaManifestPersistedPaths {
            manifest_raw: PathBuf::from("/tmp/manifest.norito"),
            manifest_json: PathBuf::from("/tmp/manifest.json"),
            chunk_plan: PathBuf::from("/tmp/chunk_plan.json"),
        };
        let value = build_manifest_fetch_value(&bundle, &persisted);
        let obj = value.as_object().expect("manifest fetch value object");
        assert_eq!(
            obj.get("manifest_path").and_then(Value::as_str),
            Some("/tmp/manifest.norito")
        );
        assert_eq!(
            obj.get("manifest_json_path").and_then(Value::as_str),
            Some("/tmp/manifest.json")
        );
        assert_eq!(
            obj.get("chunk_plan_path").and_then(Value::as_str),
            Some("/tmp/chunk_plan.json")
        );
        assert_eq!(
            obj.get("storage_ticket").and_then(Value::as_str),
            Some(storage_ticket.as_str())
        );
    }
    #[test]
    fn manifest_fetch_text_includes_paths() {
        let manifest = sample_manifest();
        let bundle = iroha_storage_client::da::DaManifestBundle {
            client_blob_id_hex: hex::encode(manifest.client_blob_id.as_bytes()),
            chunk_root_hex: hex::encode(manifest.chunk_root.as_bytes()),
            lane_id: u64::from(manifest.lane_id.as_u32()),
            epoch: manifest.epoch,
            manifest_len: to_bytes(&manifest).unwrap().len() as u64,
            manifest_bytes: Vec::new(),
            manifest_json: norito::json::to_value(&manifest).expect("manifest JSON"),
            chunk_plan: sample_chunk_fetch_plan(&manifest),
            storage_ticket_hex: "feedface".repeat(8),
            manifest_hash_hex: "aa".repeat(32),
            blob_hash_hex: hex::encode(manifest.blob_hash.as_ref()),
        };
        let persisted = iroha_storage_client::da::DaManifestPersistedPaths {
            manifest_raw: PathBuf::from("/tmp/manifest.norito"),
            manifest_json: PathBuf::from("/tmp/manifest.json"),
            chunk_plan: PathBuf::from("/tmp/chunk_plan.json"),
        };
        let text = render_manifest_fetch_text(&bundle, &persisted);
        assert!(text.contains("manifest: /tmp/manifest.norito"));
        assert!(text.contains("chunk_plan: /tmp/chunk_plan.json"));
    }
    #[test]
    fn render_submit_text_includes_request_paths() {
        let output = SubmitOutput {
            submitted: false,
            request: SubmitRequestOutput {
                client_blob_id: "abcd".to_string(),
                request_path: "/tmp/request.norito".to_string(),
                request_json_path: "/tmp/request.json".to_string(),
                request_bytes: 128,
            },
            receipt: None,
        };
        let text = render_submit_text(&output);
        assert!(text.contains("client_blob_id: abcd"));
        assert!(text.contains("request: /tmp/request.norito"));
        assert!(text.contains("request_json: /tmp/request.json"));
    }

    #[test]
    fn persist_submit_request_replaces_prepare_with_pin_scope_witness() {
        let context = TestContext::new(CliOutputFormat::Json);
        let request = da::build_da_request(
            context.cfg.network_id,
            context.cfg.account.clone(),
            vec![0x51, 0x52, 0x53],
            &DaIngestParams::default(),
            ExtraMetadata::default(),
            &context.cfg.key_pair,
            None,
        )
        .expect("build DA submit persistence fixture");
        let scope = DaPinScopeV1::new(
            &request.authorization(),
            StorageTicketId::new([0x54; 32]),
            ManifestDigest::new([0x55; 32]),
            None,
        );
        let mut authorized = request.clone();
        authorized
            .try_add_pin_scope_signature(&scope, &context.cfg.key_pair)
            .expect("authorize exact DA pin scope");
        let dir = tempdir().expect("artifact directory");

        persist_submit_request(dir.path(), &request).expect("persist prepare request");
        let output = persist_submit_request(dir.path(), &authorized)
            .expect("replace prepare request with authorized request");

        let raw: DaIngestRequest = decode_from_bytes(
            &fs::read(dir.path().join("da_request.norito")).expect("read request Norito"),
        )
        .expect("decode persisted request Norito");
        let rendered: DaIngestRequest = norito::json::from_slice(
            &fs::read(dir.path().join("da_request.json")).expect("read request JSON"),
        )
        .expect("decode persisted request JSON");
        assert_eq!(raw, authorized);
        assert_eq!(rendered, authorized);
        assert_eq!(raw.signing_digest(), request.signing_digest());
        assert_eq!(raw.pin_scope_signatures.len(), 1);
        assert_eq!(output.request_bytes, to_bytes(&authorized).unwrap().len());
    }
    #[test]
    fn commitment_query_args_build_request() {
        let args = CommitmentQueryArgs {
            manifest_hash: Some("11".repeat(32)),
            lane_id: Some(7),
            epoch: Some(9),
            sequence: Some(11),
            limit: None,
            cursor_json: None,
        };
        let request = args.to_proof_request().expect("request");
        assert_eq!(request.manifest_hash, Some(ManifestDigest::new([0x11; 32])));
        assert_eq!(request.lane_id, Some(7));
        assert_eq!(request.epoch, Some(9));
        assert_eq!(request.sequence, Some(11));
    }
    #[test]
    fn commitment_query_args_reject_zero_limit() {
        let args = CommitmentQueryArgs {
            manifest_hash: None,
            lane_id: None,
            epoch: None,
            sequence: None,
            limit: Some(0),
            cursor_json: None,
        };
        let err = args.to_list_request().expect_err("expected failure");
        assert!(err.to_string().contains("--limit"));
    }
    #[test]
    fn pin_intent_query_args_build_request() {
        let args = PinIntentQueryArgs {
            manifest_hash: Some("22".repeat(32)),
            storage_ticket: Some("33".repeat(32)),
            alias: Some("demo/alias".to_string()),
            lane_id: Some(4),
            epoch: Some(8),
            sequence: Some(12),
            limit: None,
            cursor_json: None,
        };
        let request = args.to_proof_request().expect("request");
        assert_eq!(request.manifest_hash, Some(ManifestDigest::new([0x22; 32])));
        assert_eq!(
            request.storage_ticket,
            Some(StorageTicketId::new([0x33; 32]))
        );
        assert_eq!(request.alias.as_deref(), Some("demo/alias"));
        assert_eq!(request.lane_id, Some(4));
        assert_eq!(request.epoch, Some(8));
        assert_eq!(request.sequence, Some(12));
    }
    #[test]
    fn render_da_proof_policies_text_includes_hash_and_count() {
        let bundle = DaProofPolicyBundle::new(Vec::new());
        let text = render_da_proof_policies_text("DA proof policies", &bundle);
        assert!(text.contains("DA proof policies"));
        assert!(text.contains("policy_hash:"));
        assert!(text.contains("policy_count: 0"));
    }
    #[test]
    fn render_da_verify_text_includes_optional_error() {
        let text = render_da_verify_text("DA verification", false, Some("invalid bundle hash"));
        assert!(text.contains("DA verification"));
        assert!(text.contains("valid: false"));
        assert!(text.contains("error: invalid bundle hash"));
    }
    #[test]
    fn load_json_payload_decodes_pin_intent_proof() {
        let lane_id = LaneId::new(1);
        let key_pair = fixture_key_pair(0xE9);
        let mut authorization = DaIngestAuthorizationV1 {
            network_id: iroha_data_model::NetworkId::from_genesis_hash(HashOf::<
                iroha_data_model::block::BlockHeader,
            >::from_untyped_unchecked(
                Hash::prehashed([0xEA; 32]),
            )),
            owner: AccountId::new(key_pair.public_key().clone()),
            lane_id,
            epoch: 2,
            sequence: 3,
            payload_hash: BlobDigest::new([0xEB; 32]),
            payload_bytes: 1,
            request_content_hash: Hash::prehashed([0xEC; 32]),
            signatures: Vec::new(),
        };
        authorization.signatures.push(DaIngestSignatureV1 {
            signer: key_pair.public_key().clone(),
            signature: iroha_crypto::Signature::try_new(
                key_pair.private_key(),
                &authorization.signing_digest(),
            )
            .expect("sign deterministic CLI DA proof authorization"),
        });
        let scope = DaPinScopeV1::new(
            &authorization,
            StorageTicketId::new([0x44; 32]),
            ManifestDigest::new([0x55; 32]),
            None,
        );
        let scope_authorization = DaPinScopeAuthorizationV1::try_sign(scope, &key_pair)
            .expect("sign deterministic CLI DA pin scope");
        let intent = DaPinIntent::new(authorization, scope_authorization);
        let proof = DaPinIntentProof {
            intent,
            location: iroha::data_model::da::commitment::DaCommitmentLocation {
                block_height: 4,
                index_in_bundle: 1,
            },
            bundle_hash: HashOf::<DaPinIntentBundle>::from_untyped_unchecked(Hash::prehashed(
                [0x66; Hash::LENGTH],
            )),
            bundle_len: 2,
            root: Hash::prehashed([0x77; Hash::LENGTH]),
            path: Vec::new(),
        };
        let tmp = NamedTempFile::new().expect("temp file");
        fs::write(
            tmp.path(),
            norito::json::to_vec(&proof).expect("encode pin intent proof"),
        )
        .expect("write json payload");
        let decoded: DaPinIntentProof =
            load_json_payload(tmp.path(), "DA pin intent proof").expect("decode payload");
        assert_eq!(decoded, proof);
    }
    #[test]
    fn render_proof_summary_text_includes_counts() {
        let manifest = sample_manifest();
        let proof = ProofReport {
            origin: ProofOrigin::Sampled,
            leaf_index: 0,
            proof: dummy_proof(),
            verified: true,
        };
        let proofs = vec![proof];
        let inputs = ProofSummaryInputs {
            manifest: &manifest,
            manifest_path: Path::new("manifest.to"),
            payload_path: Path::new("payload.bin"),
            por_root_hex: "abcd".into(),
            leaf_total: 1,
            segment_total: 1,
            chunk_total: 1,
            sample_count: 1,
            sample_seed: 42,
        };
        let text = render_proof_summary_text(&inputs, &proofs);
        assert!(text.contains("proofs: 1 (verified 1)"));
        assert!(text.contains("sample_seed: 0x000000000000002a"));
    }
    #[test]
    fn fixture_key_pair_uses_checked_seed_derivation() {
        assert_eq!(fixture_key_pair(1).algorithm(), Algorithm::Ed25519);
        assert!(
            KeyPair::try_from_seed(vec![0; 32], Algorithm::Ed25519).is_err(),
            "checked Ed25519 seed derivation must reject weak all-zero fixture seeds"
        );
    }
    #[test]
    fn rent_ledger_plan_records_transfers() {
        let projection = DaRentLedgerProjection {
            rent_due: "1".parse().expect("canonical quantity"),
            protocol_reserve_due: "0.2".parse().expect("canonical quantity"),
            provider_reward_due: "0.8".parse().expect("canonical quantity"),
            pdp_bonus_pool: "0.05".parse().expect("canonical quantity"),
            potr_bonus_pool: "0.025".parse().expect("canonical quantity"),
            egress_credit_per_gib: "0.0015".parse().expect("canonical quantity"),
        };
        let payer_key = fixture_key_pair(1);
        let payer = AccountId::new(payer_key.public_key().clone());
        let treasury_key = fixture_key_pair(2);
        let treasury = AccountId::new(treasury_key.public_key().clone());
        let reserve_key = fixture_key_pair(3);
        let reserve = AccountId::new(reserve_key.public_key().clone());
        let provider_key = fixture_key_pair(4);
        let provider = AccountId::new(provider_key.public_key().clone());
        let pdp_key = fixture_key_pair(5);
        let pdp = AccountId::new(pdp_key.public_key().clone());
        let potr_key = fixture_key_pair(6);
        let potr = AccountId::new(potr_key.public_key().clone());
        let asset_definition: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::try_new("sora", "universal").unwrap(),
                "xor".parse().unwrap(),
            );
        let accounts = da::DaRentLedgerAccounts {
            payer: &payer,
            treasury: &treasury,
            protocol_reserve: &reserve,
            provider: &provider,
            pdp_bonus: &pdp,
            potr_bonus: &potr,
        };
        let plan = build_rent_ledger_plan(
            Path::new("quote.json"),
            projection,
            accounts,
            &asset_definition,
        )
        .expect("plan");
        let map = plan.as_object().expect("ledger plan must be a JSON object");
        assert_eq!(map.get("rent_due").and_then(Value::as_str), Some("1"));
        assert_eq!(
            map.get("pdp_bonus_pool").and_then(Value::as_str),
            Some("0.05")
        );
        assert!(!map.contains_key("rent_due_micro_xor"));
        let instructions = map
            .get("instructions")
            .and_then(Value::as_array)
            .expect("instructions array missing");
        assert_eq!(instructions.len(), 5);
    }
    #[test]
    fn policy_label_override_trims_and_applies_value() {
        let label = policy_label_or_default(Some("  treasury docket 42  "), "fallback".into())
            .expect("label");
        assert_eq!(label, "treasury docket 42");
    }
    #[test]
    fn policy_label_override_rejects_empty_string() {
        let err = policy_label_or_default(Some("   \t"), "fallback".into())
            .expect_err("expected failure");
        assert!(err.to_string().contains("--policy-label"));
    }
    #[test]
    fn policy_label_defaults_when_override_missing() {
        let label = policy_label_or_default(None, "embedded".into()).expect("label");
        assert_eq!(label, "embedded");
    }
    fn sample_manifest() -> DaManifestV1 {
        let chunk = ChunkCommitment::new_with_role(
            0,
            0,
            4,
            BlobDigest::new([0xAA; 32]),
            ChunkRole::Data,
            0,
        );
        DaManifestV1 {
            version: DaManifestV1::VERSION,
            client_blob_id: BlobDigest::new([0x11; 32]),
            lane_id: LaneId::new(0),
            epoch: 1,
            blob_class: BlobClass::TaikaiSegment,
            codec: BlobCodec::new("demo"),
            blob_hash: BlobDigest::new([0x22; 32]),
            chunk_root: BlobDigest::new([0x33; 32]),
            storage_ticket: StorageTicketId::new([0x44; 32]),
            total_size: 4,
            chunk_size: 4,
            total_stripes: 1,
            shards_per_stripe: 1,
            erasure_profile: ErasureProfile {
                data_shards: 1,
                parity_shards: 0,
                row_parity_stripes: 0,
                chunk_alignment: 1,
                fec_scheme: FecScheme::Rs12_10,
            },
            retention_policy: RetentionPolicy {
                hot_retention_secs: 60,
                cold_retention_secs: 60,
                required_replicas: 1,
                storage_class: StorageClass::Hot,
                governance_tag: GovernanceTag::new("da.test"),
            },
            rent_quote: DaRentQuote::default(),
            chunks: vec![chunk],
            ipa_commitment: BlobDigest::new([0x33; 32]),
            metadata: ExtraMetadata {
                items: vec![
                    MetadataEntry::new(
                        "taikai.event_id",
                        b"demo_event".to_vec(),
                        MetadataVisibility::Public,
                    ),
                    MetadataEntry::new(
                        "taikai.stream_id",
                        b"demo_stream".to_vec(),
                        MetadataVisibility::Public,
                    ),
                    MetadataEntry::new(
                        "taikai.rendition_id",
                        b"demo_rendition".to_vec(),
                        MetadataVisibility::Public,
                    ),
                    MetadataEntry::new(
                        "taikai.segment.sequence",
                        b"1".to_vec(),
                        MetadataVisibility::Public,
                    ),
                ],
            },
            issued_at_unix: 1,
        }
    }
    fn sample_chunk_fetch_plan(manifest: &DaManifestV1) -> Value {
        let plan =
            sorafs_car::build_plan_from_da_manifest(manifest).expect("build sample fetch plan");
        sorafs_car::fetch_plan::try_chunk_fetch_plan_to_json(&plan)
            .expect("render canonical sample fetch plan")
    }
    fn dummy_proof() -> PorProof {
        PorProof {
            payload_len: 4,
            leaf_count: 1,
            leaf_index_flat: 0,
            chunk_index: 0,
            chunk_offset: 0,
            chunk_length: 4,
            chunk_digest: [0xAA; 32],
            chunk_root: [0xBB; 32],
            segment_index: 0,
            segment_offset: 0,
            segment_length: 4,
            segment_digest: [0xCC; 32],
            leaf_index: 0,
            leaf_offset: 0,
            leaf_length: 4,
            leaf_bytes: vec![0xDD; 4],
            leaf_digest: [0xEE; 32],
            segment_leaves: vec![[0xEE; 32]],
            chunk_segments: vec![[0xCC; 32]],
            chunk_count: 1,
            chunk_merkle_path: Vec::new(),
        }
    }
}
