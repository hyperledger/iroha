//! Authenticated selective Explorer evidence, without a finality authority claim.
use super::*;
use base64::Engine as _;
use iroha_data_model::{block::execution_output::ExecutionOutputV1, query::CommittedTransaction};

/// Maximum selective proof response size, including HTTP error bodies.
pub const EXPLORER_TRANSACTION_PROOF_MAX_BYTES: usize = 16 * 1024 * 1024;
const DECODE_LIMITS: norito::DecodeLimits = norito::DecodeLimits::new(
    100_000,
    EXPLORER_TRANSACTION_PROOF_MAX_BYTES,
    1_000_000,
    EXPLORER_TRANSACTION_PROOF_MAX_BYTES * 8,
    64,
);

/// Node-supplied evidence for one visible transaction, not independently verified finality.
///
/// Authenticate the certificate against an independently pinned network and validator context
/// before using the selected input/output proofs as settlement evidence.
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ExplorerTransactionProof {
    /// Selective evidence schema version (one).
    pub version: u8,
    /// Exact genesis-derived network identity.
    pub network_id: NetworkId,
    /// Non-genesis committed height supplied by the node.
    pub block_height: u64,
    /// Native consensus block header supplied by the node.
    pub block_header: BlockHeader,
    /// Only the selected input, corresponding output and their Merkle paths.
    pub transaction: CommittedTransaction,
    /// Original compact certificate carriers, encoded as canonical padded base64.
    pub certificate: ExplorerTransactionProofCertificate,
}

/// Original certificate carriers; decoding these strings does not authenticate the committee.
#[derive(Clone, Debug, norito::derive::JsonSerialize, norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
pub struct ExplorerTransactionProofCertificate {
    /// Original native consensus header bytes (at most 64 KiB).
    pub consensus_header: String,
    /// Original native commit quorum certificate bytes (at most 4 KiB).
    pub commit_qc: String,
    /// Original native result preimage bytes (at most 64 KiB).
    pub result_preimage: String,
}

impl Client {
    /// Read one transaction's node-supplied selective evidence with canonical account signing.
    ///
    /// Uses the configured native identity and network. Visibility remains subject to Torii's
    /// dataspace permissions. This performs one read, without retries, ledger writes or a fallback
    /// to whole-block disclosure. Local binding checks are not certificate/finality verification.
    ///
    /// # Errors
    /// Returns errors for transport/HTTP failures, oversized or malformed evidence, and any
    /// network, transaction, header or output binding mismatch. Hidden evidence stays an error.
    pub fn get_explorer_transaction_proof(
        &self,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
    ) -> Result<ExplorerTransactionProof> {
        let path = torii_routes::application_api::EXPLORER_TRANSACTIONS_BY_HASH_PROOF_GET
            .path()
            .replace("{hash}", &hex::encode(entrypoint_hash.as_ref()));
        let url = join_torii_url(&self.torii_url, &path);
        let response = self.send_builder(
            self.account_signed_request(HttpMethod::GET, url, Vec::new())?
                .replace_header(http::header::ACCEPT, APPLICATION_JSON)
                .max_response_bytes(EXPLORER_TRANSACTION_PROOF_MAX_BYTES),
        )?;
        // Also enforce the cap for injected transports before diagnostics or decoding allocate.
        if response.body().len() > EXPLORER_TRANSACTION_PROOF_MAX_BYTES {
            return Err(eyre!(
                "Explorer transaction proof response exceeds its size bound"
            ));
        }
        Self::ensure_response_status(
            &response,
            StatusCode::OK,
            "Failed to read Explorer transaction proof",
            " ",
        )?;
        if !dispatch::media_type("explorer.transaction_proof", &response)?
            .eq_ignore_ascii_case(APPLICATION_JSON)
        {
            return Err(eyre!(
                "Explorer transaction proof requires application/json"
            ));
        }
        norito::json::preflight_slice(
            response.body(),
            norito::json::JsonPreflightLimits::from_decode_limits(
                EXPLORER_TRANSACTION_PROOF_MAX_BYTES,
                DECODE_LIMITS,
            ),
        )
        .wrap_err("failed to admit Explorer transaction proof JSON")?;
        norito::with_decode_limits_scope(DECODE_LIMITS, || {
            let proof: ExplorerTransactionProof = norito::json::from_slice(response.body())
                .wrap_err("failed to decode Explorer transaction proof")?;
            proof.validate_bindings(&self.network_id, entrypoint_hash)?;
            Ok(proof)
        })
    }
}

impl ExplorerTransactionProof {
    fn validate_bindings(
        &self,
        network_id: &NetworkId,
        entrypoint_hash: HashOf<TransactionEntrypoint>,
    ) -> Result<()> {
        let selected = &self.transaction;
        if self.version != 1
            || &self.network_id != network_id
            || self.block_height < 2
            || self.block_height != self.block_header.height().get()
            || selected.block_hash != self.block_header.hash()
            || selected.entrypoint_hash != entrypoint_hash
            || selected.entrypoint.hash() != entrypoint_hash
            || selected.output_hash != HashOf::new(&selected.output)
            || selected.entrypoint_proof.audit_path().len() > 32
            || selected.output_proof.audit_path().len() > 32
        {
            return Err(eyre!(
                "Explorer transaction proof network/transaction/header binding differs"
            ));
        }
        let transaction = match &selected.entrypoint {
            TransactionEntrypoint::External(transaction) => transaction,
            TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
            TransactionEntrypoint::SealedCommitment(_)
            | TransactionEntrypoint::AnonymousBallot(_) => {
                return Err(eyre!(
                    "Explorer transaction proof requires a visible signed transaction"
                ));
            }
        };
        let ExecutionOutputV1::Network(output) = &selected.output else {
            return Err(eyre!(
                "Explorer transaction proof requires a Network output"
            ));
        };
        if transaction.network_id() != Some(network_id)
            || output.input_index != selected.entrypoint_proof.leaf_index()
        {
            return Err(eyre!(
                "Explorer transaction proof source/output binding differs"
            ));
        }
        for (encoded, maximum) in [
            (&self.certificate.consensus_header, 64_usize * 1024),
            (&self.certificate.commit_qc, 4 * 1024),
            (&self.certificate.result_preimage, 64 * 1024),
        ] {
            if encoded.is_empty() || encoded.len() > maximum.div_ceil(3) * 4 {
                return Err(eyre!(
                    "Explorer transaction proof certificate exceeds its size bound"
                ));
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .wrap_err("Explorer transaction proof certificate is not canonical base64")?;
            if bytes.is_empty()
                || bytes.len() > maximum
                || base64::engine::general_purpose::STANDARD.encode(&bytes) != *encoded
            {
                return Err(eyre!(
                    "Explorer transaction proof certificate is not canonical base64"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "explorer_transaction_proof_tests.rs"]
mod tests;
