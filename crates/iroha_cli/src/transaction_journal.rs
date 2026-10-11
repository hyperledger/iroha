//! Durable instruction transactions: prepare once, dispatch once, then recover read-only.
//!
//! `tx prepare` consumes the existing `--emit-instructions` JSON format. The native journal
//! retains the canonical signed envelope before dispatch and its exact intent before the sole
//! transaction POST. Repeating `submit` after any attempt is read-only, including after a lost response or
//! a crash between recording intent and sending. `resume` never writes journal records or signs a
//! transaction; authenticated reads use the configured query signer.
//! An Applied result also requires the authenticated committed envelope to match byte for byte.
use crate::{Args, Command, RunContext};
use eyre::{Result, WrapErr as _, ensure, eyre};
use iroha::{
    blocking::Client as BlockingClient,
    client::{Client, PreparedTransactionPayload},
    config::Config,
};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    isi::InstructionBox,
    transaction::{Executable, SignedTransaction, signed::TransactionEntrypoint},
};
use iroha_operation_journal::{Journal, MAX_JOURNAL_BYTES, canonical_bytes};
use iroha_torii_shared::{
    FeeQuoteResponse, PipelineTransactionDetailsResponse, PipelineTransactionStatusResponse,
};
use iroha_version::codec::DecodeVersioned as _;
use norito::json::{JsonDeserialize, JsonSerialize};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const SCHEMA: &str = "iroha.cli.prepared-instruction-transaction.v1";

/// Exact private journal selected for preparation, submission, or read-only recovery.
#[derive(Debug, clap::Args)]
pub(crate) struct JournalArgs {
    /// Owner-private operation directory. Preparation refuses any existing directory.
    #[arg(long, value_name = "DIRECTORY")]
    journal: PathBuf,
}

#[derive(Clone, JsonSerialize, JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct PreparedOperation {
    schema: String,
    chain_id: String,
    network_id: NetworkId,
    authority: AccountId,
    chain_discriminant: u16,
    torii_url: String,
    transaction_hash: String,
    signed_transaction_wire_hex: String,
    fee_quote: FeeQuoteResponse,
}

impl PreparedOperation {
    fn new(
        config: &Config,
        transaction: &SignedTransaction,
        fee_quote: FeeQuoteResponse,
    ) -> Result<Self> {
        let operation = Self {
            schema: SCHEMA.to_owned(),
            chain_id: config.chain.to_string(),
            network_id: config.network_id,
            authority: config.account.clone(),
            chain_discriminant: config.account_chain_discriminant,
            torii_url: endpoint_identity(config)?,
            transaction_hash: transaction.hash().to_string(),
            signed_transaction_wire_hex: hex::encode(transaction.encode_wire_v1()?),
            fee_quote,
        };
        operation.validate(config)?;
        // Refuse an oversized record before publication; use the journal's native bound.
        canonical_bytes(&operation)?;
        Ok(operation)
    }

    fn validate(&self, config: &Config) -> Result<SignedTransaction> {
        ensure!(self.schema == SCHEMA, "unknown prepared transaction schema");
        ensure!(
            self.chain_id == config.chain.to_string()
                && self.network_id == config.network_id
                && self.authority == config.account
                && self.chain_discriminant == config.account_chain_discriminant
                && self.torii_url == endpoint_identity(config)?,
            "prepared transaction belongs to another configured network, authority, or endpoint"
        );
        ensure!(
            !self.signed_transaction_wire_hex.is_empty()
                && self.signed_transaction_wire_hex.len() <= MAX_JOURNAL_BYTES,
            "retained signed transaction exceeds the journal bound"
        );
        let wire = hex::decode(&self.signed_transaction_wire_hex)?;
        ensure!(
            hex::encode(&wire) == self.signed_transaction_wire_hex,
            "noncanonical transaction hex"
        );
        let transaction = SignedTransaction::decode_all_versioned(&wire)?;
        transaction.verify_signature()?;
        ensure!(
            transaction.encode_wire_v1()? == wire
                && transaction.hash().to_string() == self.transaction_hash
                && transaction.network_id() == Some(&self.network_id)
                && transaction.authority() == &self.authority
                && transaction.fee_payment_intent() == &self.fee_quote.intent
                && transaction.attachments().is_none()
                && transaction.multisig_signatures().is_none(),
            "retained transaction identity or canonical signed envelope differs"
        );
        ensure!(
            matches!(transaction.instructions(), Executable::Instructions(values) if !values.is_empty()),
            "prepared transaction must contain nonempty instruction input"
        );
        self.fee_quote
            .validate_for_signed_payload(transaction.payload())
            .map_err(|error| eyre!(error))?;
        execution_expiry(&transaction)?;
        Ok(transaction)
    }
}

fn endpoint_identity(config: &Config) -> Result<String> {
    let url = &config.torii_api_url;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "transaction journal requires a credential-free Torii endpoint URL"
    );
    Ok(url.as_str().to_owned())
}

/// Reject ignored transaction modifiers before loading runtime credentials.
pub(crate) fn validate_globals(args: &Args) -> Result<()> {
    use crate::transaction::Command as Tx;
    let preparing = match &args.command {
        Command::Tx(Tx::Prepare(_)) => true,
        Command::Tx(Tx::Submit(_) | Tx::Resume(_)) => false,
        _ => return Ok(()),
    };
    ensure!(
        !args.verbose,
        "journal commands reject --verbose; runtime credentials are never report data"
    );
    ensure!(
        !args.stdin_instructions && !args.emit_instructions,
        "journal commands reject --stdin-instructions and --emit-instructions; prepare reads its own stdin"
    );
    if preparing {
        args.fee_payment.selection()?;
    } else {
        ensure!(
            args.metadata.is_none()
                && args.fee_payment.fee_payer.is_none()
                && args.fee_payment.fee_program.is_none()
                && args.fee_payment.fee_program_revision.is_none(),
            "submit/resume reuse retained metadata and fee intent; transaction overrides are not accepted"
        );
    }
    Ok(())
}

/// Quote and sign one instruction transaction without making a submission request.
pub(crate) fn prepare<C: RunContext>(args: JournalArgs, context: &mut C) -> Result<()> {
    let instructions: Vec<InstructionBox> = crate::parse_json_stdin(context)?;
    ensure!(
        !instructions.is_empty(),
        "prepare requires at least one instruction"
    );
    endpoint_identity(context.config())?;
    let fee_payment = context.transaction_fee_payment()?;
    let metadata = context.transaction_metadata().cloned().unwrap_or_default();
    // Acquire a fresh journal before quotation/signing. A failed preparation remains visible and
    // cannot be overwritten or silently signed again. Nothing can dispatch without operation.json.
    let journal = Journal::create(&args.journal)?;
    let client = BlockingClient::from_client(context.client_from_config()?)?;
    let (transaction, quote) = crate::quote_and_sign_transaction(
        &client,
        Executable::from(instructions),
        fee_payment,
        metadata,
    )?;
    let operation = PreparedOperation::new(context.config(), &transaction, quote)?;
    journal.write_operation(&operation)?;
    require_same_original(&journal, &operation)?;
    print_report(
        context,
        &journal,
        &operation,
        Observation::new("Prepared", None),
        false,
        false,
    )
}

/// Dispatch only the original unattempted envelope; any previous attempt is recovered read-only.
pub(crate) fn submit<C: RunContext>(args: JournalArgs, context: &mut C) -> Result<()> {
    run_retained(args, context, true)
}

/// Observe the original envelope without signing/submitting transactions or writing journal records.
pub(crate) fn resume<C: RunContext>(args: JournalArgs, context: &mut C) -> Result<()> {
    run_retained(args, context, false)
}

fn run_retained<C: RunContext>(args: JournalArgs, context: &mut C, may_submit: bool) -> Result<()> {
    let journal = Journal::open(&args.journal)?;
    let operation: PreparedOperation = journal.read_operation()?;
    let transaction = operation.validate(context.config())?;
    let native = context.client_from_config()?;
    let mut submission_acknowledged_now = false;
    if may_submit {
        let client = BlockingClient::from_client(native.clone())?;
        let outcome = dispatch_once(&journal, &operation, &transaction, now_ms()?, || {
            let prepared = PreparedTransactionPayload::from_transaction(&transaction);
            ensure!(
                prepared.as_bytes() == transaction.encode_wire_v1()?,
                "SDK transport wire changed"
            );
            let hash = client.submit_prepared_transaction_payload(&prepared)?;
            ensure!(
                hash == transaction.hash(),
                "submission returned a different transaction hash"
            );
            Ok(())
        });
        match outcome {
            Ok(sent) => submission_acknowledged_now = sent,
            Err(error) => {
                let attempted = journal.submission_recorded(&operation)?;
                print_report(
                    context,
                    &journal,
                    &operation,
                    Observation::new(
                        if attempted {
                            "SubmissionUnresolved"
                        } else {
                            "NotDispatched"
                        },
                        None,
                    ),
                    attempted,
                    false,
                )?;
                return Err(error.wrap_err("retained transaction was not confirmed; use tx resume with this journal, never prepare a replacement"));
            }
        }
    }
    let observation = recover(&native, &operation, &transaction)?;
    require_same_original(&journal, &operation)?;
    let attempted = journal.submission_recorded(&operation)?;
    print_report(
        context,
        &journal,
        &operation,
        observation,
        attempted,
        submission_acknowledged_now,
    )?;
    ensure!(
        observation.state == "Applied",
        "transaction is {}; recover the same journal",
        observation.state
    );
    Ok(())
}

fn require_same_original(journal: &Journal, operation: &PreparedOperation) -> Result<()> {
    journal.verify_native_inventory()?;
    let retained: PreparedOperation = journal.read_operation()?;
    ensure!(
        canonical_bytes(&retained)? == canonical_bytes(operation)?,
        "prepared original changed"
    );
    Ok(())
}

fn execution_expiry(transaction: &SignedTransaction) -> Result<u64> {
    let payload = transaction.payload();
    let ttl = payload
        .time_to_live_ms
        .ok_or_else(|| eyre!("prepared transaction requires a finite TTL"))?;
    payload
        .creation_time_ms
        .checked_add(ttl.get())
        .ok_or_else(|| eyre!("transaction expiry overflows"))
}

fn now_ms() -> Result<u64> {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()).map_err(Into::into)
}

fn dispatch_once(
    journal: &Journal,
    operation: &PreparedOperation,
    transaction: &SignedTransaction,
    now: u64,
    submit: impl FnOnce() -> Result<()>,
) -> Result<bool> {
    require_same_original(journal, operation)?;
    if journal.submission_recorded(operation)? {
        return Ok(false);
    }
    ensure!(
        !journal.has_dispatch_evidence()?,
        "unrecognized retained dispatch evidence; submission is disabled"
    );
    ensure!(
        now < execution_expiry(transaction)?,
        "unattempted transaction has expired; it was not dispatched"
    );
    if !journal.record_submission(operation)? {
        return Ok(false);
    }
    // The immutable marker is durable before this check or any transport call. Failure or a crash
    // from this point onwards permanently disables submission from this journal.
    require_same_original(journal, operation)?;
    submit()?;
    Ok(true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Observation {
    state: &'static str,
    block_height: Option<u64>,
}
impl Observation {
    fn new(state: &'static str, block_height: Option<u64>) -> Self {
        Self {
            state,
            block_height,
        }
    }
}

fn classify_status(
    hash: &str,
    status: Option<&PipelineTransactionStatusResponse>,
) -> Result<Observation> {
    let Some(status) = status else {
        return Ok(Observation::new("Absent", None));
    };
    ensure!(
        status.hash == hash && status.scope == "global",
        "status differs from exact global transaction identity"
    );
    let state = match (status.status.kind.as_str(), status.resolved_from.as_str()) {
        ("Applied", "state") => {
            ensure!(
                status.status.block_height.is_some_and(|height| height > 0),
                "Applied status lacks positive height"
            );
            "Applied"
        }
        ("Rejected", "state") => "Rejected",
        ("Expired", "state") => "Expired",
        (
            "Queued" | "Approved" | "Committed" | "Applied" | "Rejected" | "Expired",
            "cache" | "queue" | "state",
        ) => "Pending",
        _ => return Err(eyre!("unsupported transaction status or resolution source")),
    };
    Ok(Observation::new(state, status.status.block_height))
}

fn recover(
    client: &Client,
    operation: &PreparedOperation,
    transaction: &SignedTransaction,
) -> Result<Observation> {
    let status = client.get_transaction_status_response_global(transaction.hash())?;
    let observation = classify_status(&operation.transaction_hash, status.as_ref())?;
    if observation.state == "Applied" {
        let details = client.get_transaction_details(transaction.hash_as_entrypoint())?;
        verify_committed(transaction, &details)?;
    }
    Ok(observation)
}

fn verify_committed(
    expected: &SignedTransaction,
    details: &PipelineTransactionDetailsResponse,
) -> Result<()> {
    ensure!(
        details.hash == expected.hash_as_entrypoint().to_string(),
        "committed detail locator differs"
    );
    ensure!(
        details.transaction.result().is_ok(),
        "Applied status resolves to rejected committed execution"
    );
    let TransactionEntrypoint::External(committed) = details.transaction.entrypoint() else {
        return Err(eyre!(
            "Applied status resolves to a non-external transaction"
        ));
    };
    ensure!(
        committed.hash() == expected.hash()
            && committed.hash_as_entrypoint() == expected.hash_as_entrypoint()
            && committed.encode_wire_v1()? == expected.encode_wire_v1()?,
        "committed transaction differs from the exact retained signed envelope"
    );
    Ok(())
}

fn print_report<C: RunContext>(
    context: &mut C,
    journal: &Journal,
    operation: &PreparedOperation,
    observation: Observation,
    submission_recorded: bool,
    submission_acknowledged_now: bool,
) -> Result<()> {
    context.print_data(&norito::json!({
        "schema": "iroha.cli.transaction-journal-report.v1",
        "journal": (journal.path().display().to_string()),
        "transaction_hash": (operation.transaction_hash.clone()),
        "network_id": (operation.network_id.to_string()),
        "state": (observation.state),
        "block_height": (observation.block_height),
        "submission_recorded": submission_recorded,
        "submission_acknowledged_now": submission_acknowledged_now,
        "exact_committed_envelope_verified": (observation.state == "Applied")
    }))
}

#[cfg(test)]
#[path = "transaction_journal_tests.rs"]
mod tests;
