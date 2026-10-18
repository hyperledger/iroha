//! Exact native construction and inspection of detached multisig participation.
//!
//! This module supplies codecs and cryptographic binding, not authorization.
//! Applications must independently admit the network, signer, multisig policy,
//! reviewed instructions, quoted fees and non-sliding action deadline. Preserve
//! the returned originals across retries; never regenerate timestamps silently.

use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use eyre::{Result, WrapErr as _, ensure, eyre};
use iroha_crypto::{Algorithm, HashOf, PublicKey, Signature};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    isi::InstructionBox,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_executor_data_model::isi::multisig::{
    MultisigApprove, MultisigCancel, MultisigProposalId, MultisigProposalNonce, MultisigPropose,
};
use norito::json::{Map, Value};

const MAX_BYTES: usize = 16 * 1024 * 1024;

/// Independently admitted native identities and requested fee payer.
#[derive(Clone, Debug)]
pub struct NativeMultisigContext {
    /// Installed ledger network.
    pub network_id: NetworkId,
    /// Live concrete multisig account selected by the application policy.
    pub multisig_account_id: AccountId,
    /// Individual authority that signs the participation transaction.
    pub signer_account_id: AccountId,
    /// Ed25519 key controlling the individual authority.
    pub signer_public_key: PublicKey,
    /// Requested payer, sponsor revision and gas bound.
    pub fee_payment: FeePaymentIntent,
    /// Exact reviewed proposal memo. Approval/cancellation must use `None`.
    pub memo: Option<String>,
}

/// Participation in the exact reviewed instruction batch.
#[derive(Clone, Copy, Debug)]
pub enum NativeMultisigAction {
    /// Propose the reviewed batch.
    Propose {
        /// Nonzero nonce persisted before preparing this intentional proposal.
        proposal_nonce: MultisigProposalNonce,
    },
    /// Approve the reviewed batch after matching its native hash.
    Approve {
        /// Exact occurrence selected for approval.
        proposal_id: MultisigProposalId,
        /// Hash supplied by the selected live proposal.
        instructions_hash: HashOf<Vec<InstructionBox>>,
    },
    /// Propose a cancellation occurrence. Further signers approve its explicit ID.
    Cancel {
        /// Nonce of the cancellation wrapper, retained across retries.
        proposal_nonce: MultisigProposalNonce,
        /// Exact occurrence to cancel.
        target_proposal_id: MultisigProposalId,
        /// Hash supplied by the selected live proposal.
        instructions_hash: HashOf<Vec<InstructionBox>>,
    },
}

/// Immutable reviewed native intent. Its constructors do not confer authority.
#[derive(Clone, Debug)]
pub struct NativeMultisigIntent {
    context: NativeMultisigContext,
    action: NativeMultisigAction,
    instructions: Vec<InstructionBox>,
    instructions_hash: HashOf<Vec<InstructionBox>>,
    request_bytes: Vec<u8>,
}

/// Exact unsigned payload admitted against a native intent.
#[derive(Clone, Debug)]
pub struct NativePreparedMultisig {
    intent: NativeMultisigIntent,
    builder: TransactionBuilder,
    payload_bytes: Vec<u8>,
    signing_message: [u8; 32],
    expires_at_ms: u64,
}

/// Verified detached signature and exact originals suitable for submission.
#[derive(Clone, Debug)]
pub struct NativeSignedMultisig {
    path: &'static str,
    submit_bytes: Vec<u8>,
    transaction_bytes: Vec<u8>,
    transaction_hash_hex: String,
    expires_at_ms: u64,
}

fn json_value<T: norito::json::JsonSerialize>(value: &T) -> Result<Value> {
    norito::json::to_value(value).wrap_err("serialize native multisig value")
}

fn exact_object<'a>(value: &'a Value, keys: &[&str]) -> Result<&'a Map> {
    let object = value
        .as_object()
        .ok_or_else(|| eyre!("expected JSON object"))?;
    ensure!(
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)),
        "native multisig JSON has unexpected fields"
    );
    Ok(object)
}

fn bounded_json(bytes: &[u8]) -> Result<Value> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_BYTES,
        "native multisig JSON length is invalid"
    );
    let text = std::str::from_utf8(bytes).wrap_err("native multisig JSON must be UTF-8")?;
    norito::json::validate_json(text).wrap_err("validate exact native multisig JSON")?;
    norito::json::from_slice(bytes).wrap_err("decode native multisig JSON")
}

fn decode_base64(value: &Value, maximum: usize) -> Result<Vec<u8>> {
    let text = value
        .as_str()
        .ok_or_else(|| eyre!("expected canonical base64 string"))?;
    ensure!(
        text.len() <= maximum.saturating_add(2) / 3 * 4,
        "base64 length exceeds limit"
    );
    let bytes = STANDARD
        .decode(text)
        .wrap_err("decode native multisig base64")?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum && STANDARD.encode(&bytes) == text,
        "noncanonical native multisig base64"
    );
    Ok(bytes)
}

impl NativeMultisigIntent {
    /// Bind an independently admitted context and complete reviewed instruction batch.
    ///
    /// # Errors
    /// Rejects an empty batch, invalid fee intent, non-Ed25519 or mismatched
    /// authority key, and an approval/cancellation hash for any other batch.
    pub fn new(
        context: NativeMultisigContext,
        action: NativeMultisigAction,
        instructions: Vec<InstructionBox>,
    ) -> Result<Self> {
        ensure!(
            !instructions.is_empty(),
            "reviewed instructions must not be empty"
        );
        ensure!(
            context.signer_public_key.algorithm() == Algorithm::Ed25519,
            "detached multisig authority must use Ed25519"
        );
        ensure!(
            context.signer_account_id.try_signatory() == Some(&context.signer_public_key),
            "detached multisig key does not control the exact signer"
        );
        context
            .fee_payment
            .validate()
            .map_err(|error| eyre!("invalid native fee intent: {error}"))?;
        if let Some(memo) = &context.memo {
            ensure!(
                matches!(action, NativeMultisigAction::Propose { .. })
                    && !memo.is_empty()
                    && memo.trim() == memo
                    && memo.len() <= 1024
                    && !memo.chars().any(char::is_control),
                "memo must be exact bounded proposal text"
            );
        }
        let instructions_hash = HashOf::new(&instructions);
        match &action {
            NativeMultisigAction::Propose { .. } => (),
            NativeMultisigAction::Approve {
                instructions_hash: expected,
                ..
            }
            | NativeMultisigAction::Cancel {
                instructions_hash: expected,
                ..
            } => {
                ensure!(
                    *expected == instructions_hash,
                    "reviewed instructions do not match the selected proposal"
                );
            }
        }
        let mut intent = Self {
            context,
            action,
            instructions,
            instructions_hash,
            request_bytes: Vec::new(),
        };
        intent.request_bytes = norito::json::to_vec(&intent.request_value(None, None)?)?;
        ensure!(
            intent.request_bytes.len() <= MAX_BYTES,
            "native multisig request exceeds limit"
        );
        Ok(intent)
    }

    /// Exact Torii path selected by the native action.
    #[must_use]
    pub fn path(&self) -> &'static str {
        match self.action {
            NativeMultisigAction::Propose { .. } => "/v1/multisig/propose",
            NativeMultisigAction::Approve { .. } => "/v1/multisig/approve",
            NativeMultisigAction::Cancel { .. } => "/v1/multisig/cancel",
        }
    }

    /// Native hash of the complete reviewed instruction batch.
    #[must_use]
    pub fn instructions_hash(&self) -> HashOf<Vec<InstructionBox>> {
        self.instructions_hash
    }

    /// Occurrence participated in by this action, including the cancellation wrapper.
    #[must_use]
    pub fn proposal_id(&self) -> MultisigProposalId {
        match self.action {
            NativeMultisigAction::Propose { proposal_nonce }
            | NativeMultisigAction::Cancel { proposal_nonce, .. } => MultisigProposalId::derive(
                &self.context.network_id,
                &self.context.multisig_account_id,
                &proposal_nonce,
            ),
            NativeMultisigAction::Approve { proposal_id, .. } => proposal_id,
        }
    }

    /// Commitment of the participated proposal, including cancellation's wrapper.
    #[must_use]
    pub fn participation_instructions_hash(&self) -> HashOf<Vec<InstructionBox>> {
        match self.action {
            NativeMultisigAction::Cancel {
                target_proposal_id, ..
            } => HashOf::new(&vec![InstructionBox::from(MultisigCancel::new(
                self.context.multisig_account_id.clone(),
                target_proposal_id,
                self.instructions_hash,
            ))]),
            _ => self.instructions_hash,
        }
    }

    /// Exact canonical unsigned Torii request original.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.request_bytes
    }

    fn request_value(
        &self,
        prepared: Option<&TransactionBuilder>,
        signature: Option<&str>,
    ) -> Result<Value> {
        let mut body = Map::new();
        body.insert(
            "multisig_account_id".into(),
            json_value(&self.context.multisig_account_id)?,
        );
        body.insert(
            "signer_account_id".into(),
            json_value(&self.context.signer_account_id)?,
        );
        body.insert(
            "fee_payment".into(),
            json_value(prepared.map_or(&self.context.fee_payment, |builder| {
                &builder.payload().fee_payment
            }))?,
        );
        if let Some(builder) = prepared {
            body.insert(
                "creation_time_ms".into(),
                Value::from(builder.payload().creation_time_ms),
            );
            body.insert(
                "public_key_hex".into(),
                Value::from(hex::encode(self.context.signer_public_key.to_bytes().1)),
            );
            body.insert(
                "signature_b64".into(),
                Value::from(signature.ok_or_else(|| eyre!("signature is required"))?),
            );
        }
        match self.action {
            NativeMultisigAction::Propose { proposal_nonce } => {
                body.insert(
                    "proposal_nonce".into(),
                    Value::from(proposal_nonce.to_string()),
                );
                if let Some(memo) = &self.context.memo {
                    body.insert("memo".into(), Value::from(memo.clone()));
                }
                body.insert("instructions".into(), json_value(&self.instructions)?);
            }
            NativeMultisigAction::Approve { proposal_id, .. } => {
                body.insert("proposal_id".into(), Value::from(proposal_id.to_string()));
                body.insert(
                    "instructions_hash".into(),
                    Value::from(hex::encode(self.instructions_hash.as_ref())),
                );
            }
            NativeMultisigAction::Cancel {
                proposal_nonce,
                target_proposal_id,
                ..
            } => {
                body.insert(
                    "proposal_nonce".into(),
                    Value::from(proposal_nonce.to_string()),
                );
                body.insert(
                    "target_proposal_id".into(),
                    Value::from(target_proposal_id.to_string()),
                );
                body.insert(
                    "target_instructions_hash".into(),
                    Value::from(hex::encode(self.instructions_hash.as_ref())),
                );
            }
        }
        Ok(Value::Object(body))
    }

    /// Inspect an exact prepare response and full native unsigned payload.
    ///
    /// # Errors
    /// Rejects changed request originals, substituted account/network/fees or
    /// instructions, extra fields, mismatched hashes, noncanonical archives,
    /// metadata/nonce/TTL changes, and expired or future-created transactions.
    pub fn inspect_prepare(
        &self,
        request_bytes: &[u8],
        prepare_bytes: &[u8],
        now_ms: u64,
    ) -> Result<NativePreparedMultisig> {
        ensure!(
            request_bytes == self.request_bytes,
            "request differs from the exact native original"
        );
        let response = bounded_json(prepare_bytes)?;
        let mut keys = vec![
            "ok",
            "resolved_multisig_account_id",
            "submitted",
            "tx_hash_hex",
            "executed_tx_hash_hex",
            "creation_time_ms",
            "fee_payment",
            "transaction_payload_b64",
            "signing_message_b64",
        ];
        if matches!(self.action, NativeMultisigAction::Cancel { .. }) {
            keys.extend([
                "target_proposal_id",
                "target_instructions_hash",
                "cancel_proposal_id",
                "cancel_instructions_hash",
            ]);
        } else {
            keys.extend(["proposal_id", "instructions_hash"]);
        }
        let object = exact_object(&response, &keys)?;
        ensure!(
            object["ok"] == Value::Bool(true)
                && object["submitted"] == Value::Bool(false)
                && object["tx_hash_hex"].is_null()
                && object["executed_tx_hash_hex"].is_null(),
            "prepare response is not an unsigned successful draft"
        );
        ensure!(
            object["resolved_multisig_account_id"]
                == json_value(&self.context.multisig_account_id)?,
            "prepare response selected a different multisig account"
        );
        let payload_bytes = decode_base64(&object["transaction_payload_b64"], MAX_BYTES)?;
        let builder = TransactionBuilder::decode_payload(&payload_bytes)
            .wrap_err("decode native multisig payload")?;
        let signing_message = builder.payload_hash_bytes();
        ensure!(
            decode_base64(&object["signing_message_b64"], 32)? == signing_message,
            "prepare response signing message differs from native payload"
        );
        ensure!(
            object["creation_time_ms"] == Value::from(builder.payload().creation_time_ms)
                && object["fee_payment"] == json_value(&builder.payload().fee_payment)?,
            "prepare response time or fee differs from native payload"
        );
        ensure!(
            self.context
                .fee_payment
                .has_same_payer_and_gas_bound(&builder.payload().fee_payment),
            "prepare response changed fee payer, sponsor revision, or gas bound"
        );
        let creation_time_ms = builder.payload().creation_time_ms;
        let ttl = builder
            .payload()
            .time_to_live_ms
            .ok_or_else(|| eyre!("payload TTL is required"))?
            .get();
        let expires_at_ms = creation_time_ms
            .checked_add(ttl)
            .ok_or_else(|| eyre!("payload expiry overflow"))?;
        ensure!(
            creation_time_ms <= now_ms && now_ms < expires_at_ms,
            "prepare payload is future-created or expired"
        );
        let mut expected = TransactionBuilder::new(
            self.context.network_id,
            self.context.signer_account_id.clone(),
            builder.payload().fee_payment.clone(),
        );
        expected.set_creation_time(Duration::from_millis(creation_time_ms));
        if let Some(memo) = &self.context.memo {
            let mut metadata = iroha_model_base::metadata::Metadata::default();
            metadata.insert(
                "memo".parse().expect("static memo key"),
                iroha_primitives::json::Json::new(memo.clone()),
            );
            expected = expected.with_metadata(metadata);
        }
        let hash = hex::encode(self.instructions_hash.as_ref());
        let account = self.context.multisig_account_id.clone();
        let proposal_id = self.proposal_id();
        let instructions: Vec<InstructionBox> = match self.action {
            NativeMultisigAction::Propose { proposal_nonce } => {
                ensure!(
                    object["proposal_id"].as_str() == Some(&proposal_id.to_string())
                        && object["instructions_hash"].as_str() == Some(&hash),
                    "prepare occurrence or content hash differs from reviewed intent"
                );
                let propose: InstructionBox = MultisigPropose::new(
                    account.clone(),
                    proposal_nonce,
                    self.instructions.clone(),
                    None,
                )
                .into();
                if expected
                    .clone()
                    .with_instructions([propose.clone()])
                    .payload()
                    == builder.payload()
                {
                    vec![propose]
                } else {
                    vec![
                        propose,
                        MultisigApprove::new(account, proposal_id, self.instructions_hash).into(),
                    ]
                }
            }
            NativeMultisigAction::Approve { .. } => {
                ensure!(
                    object["proposal_id"].as_str() == Some(&proposal_id.to_string())
                        && object["instructions_hash"].as_str() == Some(&hash),
                    "prepare approval occurrence or content hash differs from selected proposal"
                );
                vec![MultisigApprove::new(account, proposal_id, self.instructions_hash).into()]
            }
            NativeMultisigAction::Cancel {
                proposal_nonce,
                target_proposal_id,
                ..
            } => {
                let cancel_instructions = vec![InstructionBox::from(MultisigCancel::new(
                    account.clone(),
                    target_proposal_id,
                    self.instructions_hash,
                ))];
                let cancel_hash = HashOf::new(&cancel_instructions);
                ensure!(
                    object["target_proposal_id"].as_str() == Some(&target_proposal_id.to_string())
                        && object["target_instructions_hash"].as_str() == Some(&hash)
                        && object["cancel_proposal_id"].as_str() == Some(&proposal_id.to_string())
                        && object["cancel_instructions_hash"].as_str()
                            == Some(&hex::encode(cancel_hash.as_ref())),
                    "prepare cancellation occurrence or content commitment differs from reviewed intent"
                );
                let propose: InstructionBox = MultisigPropose::new(
                    account.clone(),
                    proposal_nonce,
                    cancel_instructions,
                    None,
                )
                .into();
                if expected
                    .clone()
                    .with_instructions([propose.clone()])
                    .payload()
                    == builder.payload()
                {
                    vec![propose]
                } else {
                    vec![
                        propose,
                        MultisigApprove::new(account, proposal_id, cancel_hash).into(),
                    ]
                }
            }
        };
        ensure!(
            expected.with_instructions(instructions).payload() == builder.payload(),
            "native payload differs from exact network, authority, instructions, metadata, nonce or TTL"
        );
        Ok(NativePreparedMultisig {
            intent: self.clone(),
            builder,
            payload_bytes,
            signing_message,
            expires_at_ms,
        })
    }
}

impl NativePreparedMultisig {
    /// Exact canonical unsigned payload archive.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload_bytes
    }
    /// Native transaction prehash to sign with the admitted authority key.
    #[must_use]
    pub fn signing_message(&self) -> &[u8; 32] {
        &self.signing_message
    }
    /// Signature-bound native creation timestamp.
    #[must_use]
    pub fn creation_time_ms(&self) -> u64 {
        self.builder.payload().creation_time_ms
    }
    /// Signature-bound native expiry, never a renewed inspection deadline.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    /// Native quoted fees that the application must admit against its installed limits.
    #[must_use]
    pub fn fee_payment(&self) -> &FeePaymentIntent {
        &self.builder.payload().fee_payment
    }

    /// Verify the signature and exact signed request against this prepared original.
    ///
    /// # Errors
    /// Rejects an expired original, altered request fields, changed signatures or
    /// payload context, extra JSON fields, and noncanonical signed request bytes.
    pub fn inspect_signed(
        &self,
        signed_request_bytes: &[u8],
        now_ms: u64,
    ) -> Result<NativeSignedMultisig> {
        ensure!(
            self.creation_time_ms() <= now_ms && now_ms < self.expires_at_ms,
            "prepared original is expired or future-created"
        );
        let request = bounded_json(signed_request_bytes)?;
        let signature_value = request
            .as_object()
            .and_then(|object| object.get("signature_b64"))
            .ok_or_else(|| eyre!("signed request is missing signature_b64"))?;
        let signature_bytes = decode_base64(signature_value, 64)?;
        ensure!(
            signature_bytes.len() == 64,
            "Ed25519 signature must contain 64 bytes"
        );
        let expected = self
            .intent
            .request_value(Some(&self.builder), signature_value.as_str())?;
        ensure!(
            request == expected && norito::json::to_vec(&expected)? == signed_request_bytes,
            "signed request differs from its exact prepared original"
        );
        let transaction = self
            .builder
            .clone()
            .build_with_signature(Signature::from_bytes(&signature_bytes));
        transaction
            .verify_signature()
            .wrap_err("verify exact detached multisig signature")?;
        Ok(NativeSignedMultisig {
            path: self.intent.path(),
            submit_bytes: signed_request_bytes.to_vec(),
            transaction_bytes: transaction
                .encode_wire_v1()
                .wrap_err("encode signed native transaction")?,
            transaction_hash_hex: hex::encode(transaction.hash().as_ref()),
            expires_at_ms: self.expires_at_ms,
        })
    }
}

impl NativeSignedMultisig {
    /// Bound Torii endpoint for the exact submitted bytes.
    #[must_use]
    pub fn path(&self) -> &'static str {
        self.path
    }
    /// Exact native-inspected signed Torii JSON request.
    #[must_use]
    pub fn submit_bytes(&self) -> &[u8] {
        &self.submit_bytes
    }
    /// Canonical signed transaction wire bytes for native finality verification.
    #[must_use]
    pub fn transaction_bytes(&self) -> &[u8] {
        &self.transaction_bytes
    }
    /// Canonical native transaction identity.
    #[must_use]
    pub fn transaction_hash_hex(&self) -> &str {
        &self.transaction_hash_hex
    }
    /// Original payload expiry.
    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::KeyPair;
    use iroha_data_model::{Level, isi::Log};

    fn nonce() -> MultisigProposalNonce {
        MultisigProposalNonce::new([7; 32]).expect("nonzero nonce")
    }

    fn selected_id() -> MultisigProposalId {
        "81".repeat(32).parse().expect("occurrence ID")
    }

    fn fixture(action: u8) -> (NativeMultisigIntent, KeyPair) {
        let key = KeyPair::try_from_seed(vec![37; 32], Algorithm::Ed25519).expect("fixture key");
        let account = AccountId::new(key.public_key().clone());
        let instructions =
            vec![Log::new(Level::INFO, "complete reviewed native batch".into()).into()];
        let hash = HashOf::new(&instructions);
        let action = match action {
            0 => NativeMultisigAction::Propose {
                proposal_nonce: nonce(),
            },
            1 => NativeMultisigAction::Approve {
                proposal_id: selected_id(),
                instructions_hash: hash,
            },
            _ => NativeMultisigAction::Cancel {
                proposal_nonce: nonce(),
                target_proposal_id: selected_id(),
                instructions_hash: hash,
            },
        };
        (
            NativeMultisigIntent::new(
                NativeMultisigContext {
                    network_id: super::super::test_network_id(),
                    multisig_account_id: account.clone(),
                    signer_account_id: account,
                    signer_public_key: key.public_key().clone(),
                    fee_payment: FeePaymentIntent::authority(Vec::new(), None),
                    memo: None,
                },
                action,
                instructions,
            )
            .expect("fixture intent"),
            key,
        )
    }

    fn draft(intent: &NativeMultisigIntent, second: bool) -> (TransactionBuilder, Value) {
        let account = intent.context.multisig_account_id.clone();
        let mut body = Map::new();
        body.insert("ok".into(), Value::Bool(true));
        body.insert("submitted".into(), Value::Bool(false));
        body.insert(
            "resolved_multisig_account_id".into(),
            json_value(&account).expect("account"),
        );
        body.insert("tx_hash_hex".into(), Value::Null);
        body.insert("executed_tx_hash_hex".into(), Value::Null);
        let hash = hex::encode(intent.instructions_hash.as_ref());
        let proposal_id = intent.proposal_id();
        let instructions: Vec<InstructionBox> = match intent.action {
            NativeMultisigAction::Propose { proposal_nonce } => {
                body.insert("proposal_id".into(), Value::from(proposal_id.to_string()));
                body.insert("instructions_hash".into(), Value::from(hash));
                let mut values = vec![
                    MultisigPropose::new(
                        account.clone(),
                        proposal_nonce,
                        intent.instructions.clone(),
                        None,
                    )
                    .into(),
                ];
                if second {
                    values.push(
                        MultisigApprove::new(account, proposal_id, intent.instructions_hash).into(),
                    );
                }
                values
            }
            NativeMultisigAction::Approve { .. } => {
                body.insert("proposal_id".into(), Value::from(proposal_id.to_string()));
                body.insert("instructions_hash".into(), Value::from(hash));
                vec![MultisigApprove::new(account, proposal_id, intent.instructions_hash).into()]
            }
            NativeMultisigAction::Cancel {
                proposal_nonce,
                target_proposal_id,
                ..
            } => {
                let cancel = vec![InstructionBox::from(MultisigCancel::new(
                    account.clone(),
                    target_proposal_id,
                    intent.instructions_hash,
                ))];
                let cancel_hash = HashOf::new(&cancel);
                body.insert(
                    "target_proposal_id".into(),
                    Value::from(target_proposal_id.to_string()),
                );
                body.insert("target_instructions_hash".into(), Value::from(hash));
                body.insert(
                    "cancel_proposal_id".into(),
                    Value::from(proposal_id.to_string()),
                );
                body.insert(
                    "cancel_instructions_hash".into(),
                    Value::from(hex::encode(cancel_hash.as_ref())),
                );
                let mut values = vec![
                    MultisigPropose::new(account.clone(), proposal_nonce, cancel, None).into(),
                ];
                if second {
                    values.push(MultisigApprove::new(account, proposal_id, cancel_hash).into());
                }
                values
            }
        };
        let mut builder = TransactionBuilder::new(
            intent.context.network_id,
            intent.context.signer_account_id.clone(),
            intent.context.fee_payment.clone(),
        );
        builder.set_creation_time(Duration::from_millis(1_000));
        if let Some(memo) = &intent.context.memo {
            let mut metadata = iroha_model_base::metadata::Metadata::default();
            metadata.insert(
                "memo".parse().expect("memo key"),
                iroha_primitives::json::Json::new(memo.clone()),
            );
            builder = builder.with_metadata(metadata);
        }
        let builder = builder.with_instructions(instructions);
        replace_payload(&mut body, &builder);
        (builder, Value::Object(body))
    }

    fn replace_payload(body: &mut Map, builder: &TransactionBuilder) {
        body.insert(
            "creation_time_ms".into(),
            Value::from(builder.payload().creation_time_ms),
        );
        body.insert(
            "fee_payment".into(),
            json_value(&builder.payload().fee_payment).expect("fee"),
        );
        body.insert(
            "transaction_payload_b64".into(),
            Value::from(STANDARD.encode(builder.encode_payload())),
        );
        body.insert(
            "signing_message_b64".into(),
            Value::from(STANDARD.encode(builder.payload_hash_bytes())),
        );
    }

    #[test]
    fn exact_proposal_memo_is_native_bound_and_other_actions_reject_it() {
        let (original, _) = fixture(0);
        let mut context = original.context.clone();
        context.memo = Some("School fees".to_owned());
        let intent = NativeMultisigIntent::new(
            context.clone(),
            NativeMultisigAction::Propose {
                proposal_nonce: nonce(),
            },
            original.instructions.clone(),
        )
        .expect("memo intent");
        let (_, response) = draft(&intent, false);
        let bytes = norito::json::to_vec(&response).expect("JSON");
        intent
            .inspect_prepare(intent.request_bytes(), &bytes, 1_001)
            .expect("exact memo");
        let (_, missing_memo) = draft(&original, false);
        assert!(
            intent
                .inspect_prepare(
                    intent.request_bytes(),
                    &norito::json::to_vec(&missing_memo).expect("JSON"),
                    1_001
                )
                .is_err()
        );
        for memo in ["", " padded", "line\nbreak", &"x".repeat(1025)] {
            context.memo = Some(memo.to_owned());
            assert!(
                NativeMultisigIntent::new(
                    context.clone(),
                    NativeMultisigAction::Propose {
                        proposal_nonce: nonce()
                    },
                    original.instructions.clone()
                )
                .is_err()
            );
        }
        context.memo = Some("School fees".to_owned());
        for action in [
            NativeMultisigAction::Approve {
                proposal_id: selected_id(),
                instructions_hash: original.instructions_hash,
            },
            NativeMultisigAction::Cancel {
                proposal_nonce: nonce(),
                target_proposal_id: selected_id(),
                instructions_hash: original.instructions_hash,
            },
        ] {
            assert!(
                NativeMultisigIntent::new(context.clone(), action, original.instructions.clone())
                    .is_err()
            );
        }
    }

    #[test]
    fn all_native_participation_forms_preserve_signed_originals() {
        for (action, second) in [(0, false), (0, true), (1, false), (2, false), (2, true)] {
            let (intent, key) = fixture(action);
            let (builder, response) = draft(&intent, second);
            let prepare_bytes = norito::json::to_vec(&response).expect("prepare JSON");
            let prepared = intent
                .inspect_prepare(intent.request_bytes(), &prepare_bytes, 1_001)
                .expect("inspect prepare");
            assert_eq!(prepared.payload_bytes(), builder.encode_payload());
            assert_eq!(prepared.signing_message(), &builder.payload_hash_bytes());
            assert_eq!(prepared.creation_time_ms(), 1_000);
            assert_eq!(prepared.fee_payment(), &builder.payload().fee_payment);
            let signature = Signature::try_new(key.private_key(), prepared.signing_message())
                .expect("sign payload");
            let body = intent
                .request_value(Some(&builder), Some(&STANDARD.encode(signature.payload())))
                .expect("signed body");
            let bytes = norito::json::to_vec(&body).expect("signed JSON");
            let signed = prepared
                .inspect_signed(&bytes, 1_002)
                .expect("inspect signature");
            let expected = builder.clone().build_with_signature(signature);
            assert_eq!(signed.path(), intent.path());
            assert_eq!(signed.submit_bytes(), bytes);
            assert_eq!(
                signed.transaction_bytes(),
                expected.encode_wire_v1().expect("wire")
            );
            assert_eq!(
                signed.transaction_hash_hex(),
                hex::encode(expected.hash().as_ref())
            );
            assert_eq!(signed.expires_at_ms(), prepared.expires_at_ms());
            assert!(
                prepared
                    .inspect_signed(&bytes, prepared.expires_at_ms())
                    .is_err()
            );
            let mut altered = body.clone();
            altered
                .as_object_mut()
                .expect("object")
                .insert("creation_time_ms".into(), Value::from(1_001_u64));
            assert!(
                prepared
                    .inspect_signed(&norito::json::to_vec(&altered).expect("JSON"), 1_002)
                    .is_err()
            );
            let other =
                KeyPair::try_from_seed(vec![91; 32], Algorithm::Ed25519).expect("other key");
            let bad_sig = Signature::try_new(other.private_key(), prepared.signing_message())
                .expect("bad signature");
            let wrong = intent
                .request_value(Some(&builder), Some(&STANDARD.encode(bad_sig.payload())))
                .expect("body");
            assert!(
                prepared
                    .inspect_signed(&norito::json::to_vec(&wrong).expect("JSON"), 1_002)
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_replaced_request_response_and_native_payload_fields() {
        let (intent, _) = fixture(0);
        let (builder, response) = draft(&intent, false);
        let original = norito::json::to_vec(&response).expect("JSON");
        assert!(bounded_json(br#"{"ok":true,"ok":true}"#).is_err());
        assert!(bounded_json(br#"{"nested":{"x":1,"x":2}}"#).is_err());
        let mut request = intent.request_bytes().to_vec();
        request.push(b' ');
        assert!(intent.inspect_prepare(&request, &original, 1_001).is_err());
        assert!(
            intent
                .inspect_prepare(intent.request_bytes(), &original, 999)
                .is_err()
        );
        assert!(
            intent
                .inspect_prepare(intent.request_bytes(), &original, 101_000)
                .is_err()
        );
        for (key, value) in [
            ("unexpected", Value::Null),
            ("submitted", Value::Bool(true)),
            ("instructions_hash", Value::from("00".repeat(32))),
            (
                "signing_message_b64",
                Value::from(STANDARD.encode([0_u8; 32])),
            ),
            ("resolved_multisig_account_id", Value::from("changed")),
        ] {
            let mut altered = response.clone();
            altered
                .as_object_mut()
                .expect("object")
                .insert(key.into(), value);
            assert!(
                intent
                    .inspect_prepare(
                        intent.request_bytes(),
                        &norito::json::to_vec(&altered).expect("JSON"),
                        1_001
                    )
                    .is_err(),
                "{key}"
            );
        }
        let mut nonce = builder.clone();
        nonce.set_nonce(std::num::NonZeroU32::new(2).expect("nonce"));
        let mut ttl = builder.clone();
        ttl.set_ttl(Duration::from_secs(99));
        let foreign = TransactionBuilder::new(
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([42; 32]),
            )),
            intent.context.signer_account_id.clone(),
            intent.context.fee_payment.clone(),
        );
        for changed in [
            nonce,
            ttl,
            foreign,
            builder
                .clone()
                .with_instructions([Log::new(Level::INFO, "substituted".into())]),
        ] {
            let mut altered = response.clone();
            replace_payload(altered.as_object_mut().expect("object"), &changed);
            assert!(
                intent
                    .inspect_prepare(
                        intent.request_bytes(),
                        &norito::json::to_vec(&altered).expect("JSON"),
                        1_001
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_changed_reviewed_batch_or_controller() {
        let (intent, _) = fixture(0);
        assert!(
            NativeMultisigIntent::new(
                intent.context.clone(),
                NativeMultisigAction::Propose {
                    proposal_nonce: nonce()
                },
                vec![]
            )
            .is_err()
        );
        let changed = vec![InstructionBox::from(Log::new(
            Level::INFO,
            "another batch".into(),
        ))];
        assert!(
            NativeMultisigIntent::new(
                intent.context.clone(),
                NativeMultisigAction::Approve {
                    proposal_id: selected_id(),
                    instructions_hash: intent.instructions_hash()
                },
                changed
            )
            .is_err()
        );
        let mut context = intent.context.clone();
        context.signer_public_key = KeyPair::try_from_seed(vec![81; 32], Algorithm::Ed25519)
            .expect("key")
            .public_key()
            .clone();
        assert!(
            NativeMultisigIntent::new(
                context,
                NativeMultisigAction::Propose {
                    proposal_nonce: nonce()
                },
                intent.instructions
            )
            .is_err()
        );
    }
    #[test]
    fn identical_content_has_independent_occurrences_and_cannot_reuse_prepared_originals() {
        let (first, _) = fixture(0);
        let second = NativeMultisigIntent::new(
            first.context.clone(),
            NativeMultisigAction::Propose {
                proposal_nonce: MultisigProposalNonce::new([8; 32]).unwrap(),
            },
            first.instructions.clone(),
        )
        .unwrap();
        assert_eq!(first.instructions_hash(), second.instructions_hash());
        assert_ne!(first.proposal_id(), second.proposal_id());
        assert_ne!(first.request_bytes(), second.request_bytes());
        let (_, response) = draft(&first, false);
        let response_bytes = norito::json::to_vec(&response).unwrap();
        assert!(
            second
                .inspect_prepare(second.request_bytes(), &response_bytes, 1_001)
                .is_err()
        );
        let mut forged = response;
        forged.as_object_mut().unwrap().insert(
            "proposal_id".into(),
            Value::from(second.proposal_id().to_string()),
        );
        assert!(
            second
                .inspect_prepare(
                    second.request_bytes(),
                    &norito::json::to_vec(&forged).unwrap(),
                    1_001
                )
                .is_err()
        );
    }

    #[test]
    fn approvals_and_cancellations_bind_occurrence_even_when_contents_match() {
        for action in [1, 2] {
            let (first, _) = fixture(action);
            let other_id = "82".repeat(32).parse().unwrap();
            let changed_action = if action == 1 {
                NativeMultisigAction::Approve {
                    proposal_id: other_id,
                    instructions_hash: first.instructions_hash(),
                }
            } else {
                NativeMultisigAction::Cancel {
                    proposal_nonce: nonce(),
                    target_proposal_id: other_id,
                    instructions_hash: first.instructions_hash(),
                }
            };
            let second = NativeMultisigIntent::new(
                first.context.clone(),
                changed_action,
                first.instructions.clone(),
            )
            .unwrap();
            let (_, response) = draft(&first, false);
            assert!(
                second
                    .inspect_prepare(
                        second.request_bytes(),
                        &norito::json::to_vec(&response).unwrap(),
                        1_001
                    )
                    .is_err()
            );
            assert_ne!(first.request_bytes(), second.request_bytes());
            if action == 2 {
                assert_ne!(
                    first.participation_instructions_hash(),
                    second.participation_instructions_hash()
                );
                // Same cancellation nonce reserves one occurrence even if its target is changed.
                assert_eq!(first.proposal_id(), second.proposal_id());
            }
        }
    }
}
