//! Exact transaction attachment context owned by the canonical Rust payload decoder.
use iroha_data_model::transaction::TransactionBuilder;
use napi::bindgen_prelude::{Buffer, Uint8Array};
use napi_derive::napi;

/// Local SDK inspection bound, independent of the committed chain's admission parameters.
const MAX_INSPECTION_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

/// Canonical proof-free context derived from one complete unsigned transaction payload.
///
/// The original payload is structurally validated and bound to the requested network/authority.
/// This does not verify its proofs, execute native instructions, or establish state admission.
#[napi(object)]
pub struct JsTransactionAttachmentContextV1 {
    /// Iroha payload prehash; signatures cover the original generated proof bytes too.
    pub payload_hash: Buffer,
    /// Domain-separated ordered intent digest derived from the complete canonical payload.
    pub ordered_intent_digest: Buffer,
    /// Complete canonical frame of the normalized payload, including per-submission privacy normalization.
    pub ordered_intent_projection: Buffer,
    /// Complete canonical signed-attachment descriptor frame, when present.
    pub attachment_frame: Option<Buffer>,
    /// Derived action statement digests in action order.
    pub statement_digests: Vec<Buffer>,
}

/// Inspect canonical unsigned bytes and derive their actual attachment context.
///
/// The ordinary payload decoder enforces registered operations, invocation targets, execution
/// carrier uniqueness/suitability, canonical carrier metadata and all statement bindings. It also
/// rejects stale statements before this function returns any context. No parallel JS decoder or
/// caller-supplied intent substitutes for those checks. The local 10 MiB inspection bound is not a
/// claim about the current chain's configured transaction limit.
#[napi]
pub fn inspect_transaction_attachment_context_v1(
    payload_bytes: Uint8Array,
    network_id: Uint8Array,
    authority: String,
) -> napi::Result<JsTransactionAttachmentContextV1> {
    if payload_bytes.is_empty() || payload_bytes.len() > MAX_INSPECTION_PAYLOAD_BYTES {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "attachment context payload must contain 1..=10485760 bytes",
        ));
    }
    let _chain_guard = super::scoped_chain_discriminant_for_literal(&authority)?;
    let expected_authority = super::parse_account_id(&authority, "attachment context authority")?;
    let expected_network = super::parse_transaction_network_id_bytes(network_id.as_ref())?;
    let builder = norito::core::with_decode_limits(
        norito::canonical_decode_limits(payload_bytes.len()),
        || TransactionBuilder::decode_payload(payload_bytes.as_ref()),
    )
    .map_err(super::norito_to_napi)?;
    let payload = builder.payload();
    super::require_expected_transaction_network_id(
        payload.network_id(),
        &expected_network,
        "JavaScript attachment context",
    )?;
    if payload.authority != expected_authority {
        return Err(napi::Error::new(
            napi::Status::InvalidArg,
            "attachment context authority does not match payload",
        ));
    }
    let projection = payload
        .ordered_intent_projection_bytes_v1()
        .map_err(super::norito_to_napi)?;
    let intent = payload
        .ordered_intent_digest_v1()
        .map_err(super::norito_to_napi)?;
    let statements = payload
        .action_statement_digests_v1()
        .map_err(super::norito_to_napi)?;
    let attachment_frame = payload
        .attachments
        .as_ref()
        .map(norito::encode_canonical)
        .transpose()
        .map_err(super::norito_to_napi)?
        .map(Buffer::from);
    Ok(JsTransactionAttachmentContextV1 {
        payload_hash: Buffer::from(builder.payload_hash_bytes().to_vec()),
        ordered_intent_digest: Buffer::from(intent.as_bytes().to_vec()),
        ordered_intent_projection: Buffer::from(projection),
        attachment_frame,
        statement_digests: statements
            .into_iter()
            .map(|digest| Buffer::from(digest.as_bytes().to_vec()))
            .collect(),
    })
}

#[cfg(test)]
mod tests;
