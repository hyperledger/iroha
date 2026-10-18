//! Reconcile every paid carrier with authenticated fee-account balances and burned supply.

use super::*;
use iroha::client::{
    canonical_network_request_signature_message, canonical_request_account_header_value,
    canonical_request_signature_header_value,
};
use iroha_data_model::{
    asset::AssetValue, block::consensus::NexusFeeSettlementV1, nexus::FeeDebitSource,
    query::asset::FindAssetDefinitionById,
};
use iroha_torii_shared::resource_names_state::{
    NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1, NATIVE_RESOURCE_NAMES_STATE_ROUTE_PREFIX_V1,
    NativeResourceNamesStateV1, decode_unverified_native_resource_names_state_v1,
};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};

pub(crate) fn audit(root: &Root, height: u64, runtime: &tokio::runtime::Runtime) -> Result<()> {
    ensure!(
        (2..=128).contains(&height),
        "fee audit exceeded the fixture's finite history bound"
    );
    // The ordinary query supplies only an original value. It becomes evidence only
    // after its exact canonical preimage matches the independently authenticated cut.
    let definition = root
        .client(&genesis_key(root.index))
        .client()
        .query_single(FindAssetDefinitionById::new(fee_asset()))?;
    runtime.block_on(async {
        let cut = world_cut(root).await?;
        ensure!(
            cut.attestation
                .body
                .finality_proof
                .block_header
                .height()
                .get()
                == height,
            "fee audit requires the exact quiescent certified tip"
        );
        let mut verifier = root.verifier()?;
        let mut balances = BTreeMap::from([
            (
                account(&genesis_key(root.index)),
                Quantity::from(1_000_000_u32),
            ),
            (account(&relay(root.index)), Quantity::from(1_000_000_u32)),
        ]);
        let initial_supply = if root.index == 0 {
            // The one real H2 bootstrap transfer establishes the successor needed
            // by bank genesis. It conserves supply and precedes every AMX carrier.
            balances.insert(account(&genesis_key(0)), Quantity::from(999_999_u32));
            balances.insert(account(&relay(0)), Quantity::from(1_000_001_u32));
            2_000_000_u32
        } else {
            for bank in 0..2 {
                balances.insert(account(&payer(bank)), Quantity::from(1_000_000_u32));
            }
            4_000_000_u32
        };
        let mut burned = Quantity::zero();
        let mut tip = None;
        for next in verifier.authenticated_height().unwrap_or(0) + 1..=height {
            let proof = if next == height {
                cut.attestation.body.finality_proof.clone()
            } else {
                root.client(&genesis_key(root.index))
                    .client()
                    .get_sumeragi_finality_proof_async(NonZeroU64::new(next).unwrap(), root.scope)
                    .await?
            };
            let block = verifier.verify(&proof)?;
            if next > 1 {
                for (index, input) in block.block().network_entrypoints().enumerate() {
                    let TransactionEntrypoint::External(signed) = input else {
                        return Err(eyre!(
                            "fixture fee audit encountered an unexpected network input"
                        ));
                    };
                    ensure!(
                        signed.fee_payment_intent() == &fee_intent(),
                        "every fixture carrier must authorize exactly the Nexus-only fee profile"
                    );
                    let original = proofs::evidence(block.block(), index.try_into()?)?;
                    block.verify_transaction_execution(&root.network.network_id(), &original)?;
                    let fee = original
                        .output
                        .result()
                        .nexus_fee_receipt()
                        .ok_or_else(|| {
                            eyre!("finalized fixture carrier lacks its typed fee receipt at {next}")
                        })?;
                    fee.validate_for_network_input(&original.entrypoint, next)
                        .map_err(|error| eyre!(error))?;
                    ensure!(
                        fee.fee_asset_id == fee_asset()
                            && fee.dataspace_id == root.scope.dataspace_id()
                            && fee.settlement == NexusFeeSettlementV1::Burn
                    );
                    let FeeDebitSource::Account(owner) = &fee.debit_source else {
                        return Err(eyre!("fixture unexpectedly charged a sponsor vault"));
                    };
                    let balance = balances
                        .get_mut(owner)
                        .ok_or_else(|| eyre!("fee receipt debits an unseeded fixture account"))?;
                    *balance = balance.checked_sub(&fee.fee_amount)?;
                    burned = burned.checked_add(&fee.fee_amount)?;
                }
            }
            tip = Some(block);
        }
        ensure!(
            !burned.is_zero(),
            "actual service acceptance must pay positive fees"
        );
        let tip = tip.ok_or_else(|| eyre!("missing final authenticated fee cut"))?;
        let world = cut.world_snapshot.authenticate(&tip)?;
        ensure!(
            world.schema_hash()
                == iroha_core::state::State::native_world_schema_hash_v1().map_err(|e| eyre!(e))?
        );
        world.verify_table_value("world.asset_definitions", &fee_asset(), &definition)?;
        ensure!(
            definition.total_quantity() == &Quantity::from(initial_supply).checked_sub(&burned)?,
            "authenticated fee supply must equal genesis supply minus every typed Nexus burn"
        );
        let scope = if root.index == 0 {
            AssetBalanceScope::Global
        } else {
            AssetBalanceScope::Dataspace(DATASPACES[root.index - 1])
        };
        for (owner, amount) in balances {
            let asset = AssetId::with_scope(fee_asset(), owner, scope.clone());
            if amount.is_zero() {
                world.verify_asset_absent(&asset)?;
            } else {
                world.verify_table_value("world.assets", &asset, &AssetValue::new(amount))?;
            }
        }
        Ok(())
    })
}

// Reuse the existing signed full-ledger read owner. Only its complete World hash
// preimages are needed; neither the HTTP publisher nor its reported tip grants
// finality authority. The fixture deliberately grants this read capability in genesis.
pub(crate) async fn world_cut(root: &Root) -> Result<NativeResourceNamesStateV1> {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let nonce = format!("amx-fee-audit-{}", NONCE.fetch_add(1, Ordering::Relaxed));
    let challenge: [u8; 32] = Sha256::digest(nonce.as_bytes()).into();
    let challenge_hex = hex::encode(challenge);
    let url: reqwest::Url = format!(
        "{}{NATIVE_RESOURCE_NAMES_STATE_ROUTE_PREFIX_V1}{challenge_hex}",
        root.network.validators()[0]
            .torii_url()
            .trim_end_matches('/')
    )
    .parse()?;
    let timestamp = now_ms()?;
    let key = genesis_key(root.index);
    let message = canonical_network_request_signature_message(
        &root.network.network_id(),
        &reqwest::Method::GET,
        &url,
        &[],
        timestamp,
        &nonce,
    )?;
    let signature = iroha_crypto::Signature::new(key.private_key(), &message);
    let mut response = root
        .authenticate_http(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?
                .get(url),
        )
        .header("Accept", "application/x-norito")
        .header("X-Iroha-Finality-Challenge", challenge_hex)
        .header(
            "x-iroha-account",
            canonical_request_account_header_value(&account(&key))?,
        )
        .header(
            "x-iroha-signature",
            canonical_request_signature_header_value(&signature)?,
        )
        .header("x-iroha-timestamp-ms", timestamp.to_string())
        .header("x-iroha-nonce", nonce)
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "fee World cut unavailable: {}",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            == Some("application/x-norito")
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes
                .len()
                .checked_add(chunk.len())
                .is_some_and(|len| len <= NATIVE_RESOURCE_NAMES_STATE_MAX_BYTES_V1)
        );
        bytes.extend_from_slice(&chunk);
    }
    let cut = decode_unverified_native_resource_names_state_v1(&bytes)?;
    ensure!(
        cut.attestation.body.challenge == challenge
            && cut.attestation.body.network_id == root.network.network_id()
    );
    cut.attestation.verify(root.scope.into())?;
    Ok(cut)
}
