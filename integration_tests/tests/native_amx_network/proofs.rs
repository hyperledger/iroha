//! Independent destination finality, exact relay execution and complete World balance evidence.

use super::*;
use iroha::client::{
    canonical_network_request_signature_message, canonical_request_account_header_value,
    canonical_request_signature_header_value,
};
use iroha_data_model::{
    asset::AssetValue,
    block::SignedBlock,
    query::CommittedTransaction,
    sumeragi_amx::{
        AmxForeignInstanceV1, AmxRecordV1, approval_proof::MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1,
    },
    sumeragi_finality::{
        CertifiedResultScope, SumeragiFinalityProof, VerifiedSumeragiBlock, authenticated_genesis,
    },
    transaction::{Executable, TransactionEntrypoint},
};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct Observer {
    verifier: SumeragiFinalityVerifier,
    global: AmxForeignInstanceV1,
    pub decision: Option<AmxOutcomeV1>,
    pub delivery: Option<(
        u64,
        iroha_crypto::HashOf<iroha_data_model::transaction::SignedTransaction>,
    )>,
    pub decision_source: Option<iroha_data_model::sumeragi_amx::AmxCertifiedBlockV1>,
    pub tip: Option<VerifiedSumeragiBlock>,
    pub proof: Option<SumeragiFinalityProof>,
}
impl Observer {
    pub fn new(root: &Root, global: &Root) -> Result<Self> {
        Ok(Self {
            verifier: root.verifier()?,
            global: AmxForeignInstanceV1::new(
                global.instance,
                authenticated_genesis(&global.network.genesis().0)?
                    .into_parts()
                    .0,
                CertifiedResultScope::TairaGlobal,
            )?,
            decision: None,
            delivery: None,
            decision_source: None,
            tip: None,
            proof: None,
        })
    }
    pub async fn refresh(&mut self, root: &Root, tx: [u8; 32]) -> Result<()> {
        let client = root.client(&relay(root.index));
        let height = client.client().status().get().await?.blocks;
        let next = self.verifier.authenticated_height().unwrap_or(0) + 1;
        ensure!(
            height.saturating_sub(next) < 128,
            "unexpected unbounded source traffic"
        );
        for height in next..=height {
            let proof = client
                .client()
                .get_sumeragi_finality_proof_async(NonZeroU64::new(height).unwrap(), root.scope)
                .await?;
            let block = self.verifier.verify(&proof)?;
            for (index, entry) in block.block().network_entrypoints().enumerate() {
                let TransactionEntrypoint::External(signed) = entry else {
                    continue;
                };
                let Executable::Instructions(instructions) = signed.instructions() else {
                    continue;
                };
                for instruction in instructions {
                    let Some(settle) = instruction.as_any().downcast_ref::<SettleAmxV1>() else {
                        continue;
                    };
                    let AmxRecordV1::Decision(decision) = &settle.decision.record else {
                        continue;
                    };
                    if decision.tx != tx {
                        continue;
                    }
                    ensure!(settle.dataspace == root.scope.dataspace_id());
                    self.global.verify_record(&settle.decision)?;
                    let carrier = evidence(block.block(), index.try_into()?);
                    let carrier = carrier?;
                    block.verify_transaction_execution(&root.network.network_id(), &carrier)?;
                    if carrier.output.result().is_ok() {
                        ensure!(
                            signed.authority() == &account(&relay(root.index)),
                            "the actual funded service account must deliver the decision"
                        );
                        let fee = carrier.output.result().nexus_fee_receipt().ok_or_else(|| {
                            eyre!("successful service carrier has no authenticated fee receipt")
                        })?;
                        ensure!(
                            fee.debit_source
                                == iroha_data_model::nexus::FeeDebitSource::Account(account(
                                    &relay(root.index)
                                ))
                        );
                        ensure!(fee.fee_asset_id == fee_asset() && !fee.fee_amount.is_zero());
                        ensure!(
                            fee.dataspace_id == root.scope.dataspace_id()
                                && fee.block_height == block.height()
                        );
                        if let Some(original) = self.decision {
                            ensure!(original == decision.outcome, "conflicting Global decision");
                        }
                        self.decision = Some(decision.outcome);
                        if self.delivery.is_none() {
                            self.delivery = Some((block.height(), signed.hash()));
                            self.decision_source = Some(settle.decision.block.clone());
                        }
                    }
                }
            }
            self.tip = Some(block);
            self.proof = Some(proof);
        }
        Ok(())
    }
    pub async fn world(
        &self,
        root: &Root,
        approval: &AmxDebitApprovalV1,
    ) -> Result<AmxDebitApprovalProofV1> {
        let tip = self
            .tip
            .as_ref()
            .ok_or_else(|| eyre!("no authenticated private cut"))?;
        let proof = approval_proof(root, approval, tip.height()).await?;
        proof.verify(
            approval,
            &account(&relay(root.index)),
            iroha_core::state::State::native_world_schema_hash_v1().map_err(|e| eyre!(e))?,
            tip,
        )?;
        Ok(proof)
    }
    pub fn balances(
        &self,
        proof: &AmxDebitApprovalProofV1,
        bank: usize,
        payer_amount: u32,
        recipient_amount: u32,
        escrow_amount: u32,
    ) -> Result<()> {
        let tip = self
            .tip
            .as_ref()
            .ok_or_else(|| eyre!("no authenticated balance cut"))?;
        let world = proof.world.authenticate(tip)?;
        let custody = AccountId::new(iroha_crypto::derive_non_signing_ed25519_public_key(
            b"iroha-native-amx-custody-v1",
            &[tip.commitment().schedule.current.network_id.as_bytes()],
        ));
        for (owner, expected) in [
            (account(&payer(bank)), payer_amount),
            (account(&payer(1 - bank)), recipient_amount),
            (custody, escrow_amount),
        ] {
            let asset = AssetId::with_scope(
                currency(bank),
                owner,
                AssetBalanceScope::Dataspace(DATASPACES[bank]),
            );
            if expected == 0 {
                world.verify_asset_absent(&asset)?;
            } else {
                world.verify_table_value(
                    "world.assets",
                    &asset,
                    &AssetValue::new(Quantity::from(expected)),
                )?;
            }
        }
        Ok(())
    }
}

pub(super) fn evidence(block: &SignedBlock, index: u32) -> Result<CommittedTransaction> {
    let entrypoint = block
        .network_entrypoint_at(index as usize)
        .ok_or_else(|| eyre!("input absent"))?
        .clone();
    let (output_index, _) = block
        .network_output_at(index)
        .ok_or_else(|| eyre!("output absent"))?;
    let output = block.execution_outputs()[output_index as usize].clone();
    Ok(CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint,
        entrypoint_proof: block
            .network_input_proof(index)
            .ok_or_else(|| eyre!("input proof absent"))?,
        output_hash: iroha_crypto::HashOf::new(&output),
        output,
        output_proof: block
            .output_proof(output_index)
            .ok_or_else(|| eyre!("output proof absent"))?,
    })
}

// The SDK opaque permission result intentionally exposes no unauthenticated World DTO. This
// test also authenticates the complete response to verify monetary rows at that same cut.
async fn approval_proof(
    root: &Root,
    approval: &AmxDebitApprovalV1,
    height: u64,
) -> Result<AmxDebitApprovalProofV1> {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let body = norito::encode_canonical(approval)?;
    let url: reqwest::Url = format!(
        "{}/v1/amx/debit-approval/{height}",
        root.network.validators()[0]
            .torii_url()
            .trim_end_matches('/')
    )
    .parse()?;
    let timestamp = now_ms()?;
    let nonce = format!("amx-bank-cut-{}", NONCE.fetch_add(1, Ordering::Relaxed));
    let message = canonical_network_request_signature_message(
        &root.network.network_id(),
        &reqwest::Method::POST,
        &url,
        &body,
        timestamp,
        &nonce,
    )?;
    let signature = iroha_crypto::Signature::new(relay(root.index).private_key(), &message);
    let mut response = root
        .authenticate_http(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?
                .post(url),
        )
        .header("Content-Type", "application/x-norito")
        .header("Accept", "application/x-norito")
        .header(
            "x-iroha-account",
            canonical_request_account_header_value(&account(&relay(root.index)))?,
        )
        .header(
            "x-iroha-signature",
            canonical_request_signature_header_value(&signature)?,
        )
        .header("x-iroha-timestamp-ms", timestamp.to_string())
        .header("x-iroha-nonce", nonce)
        .body(body)
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "bank cut unavailable: {}",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            == Some("application/x-norito")
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes
                .len()
                .checked_add(chunk.len())
                .is_some_and(|len| len <= MAX_AMX_DEBIT_APPROVAL_PROOF_BYTES_V1)
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(AmxDebitApprovalProofV1::decode_frame(&bytes)?)
}
