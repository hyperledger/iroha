//! Installed reset removes an executed instance and its observable state before fresh deployment.
//!
//! Only the CLI mutates the ledger. Successful account-signed reads on every validator distinguish
//! absent lifecycle state from deactivation, transport failure or a malformed response.

use super::{Harness, require_deployment, require_phase, require_same_context};
use iroha::client::Client;
use iroha_data_model::{
    account::address::ChainDiscriminantGuard,
    smart_contract::{ContractAddress, ContractAlias},
};
use iroha_deploy::managed::{ManagedContext, ManagedStore};
use norito::json::{self, Value};
use std::{
    error::Error,
    fs,
    time::{Duration, Instant},
};

const SOURCE: &str = "seiyaku ResetSmoke { state int value; hajimari(int next) { value = next; } view fn quote(int cups) authorize(anyone) -> int { return value * cups; } }";

pub(super) fn run(harness: &mut Harness) -> Result<(), Box<dyn Error>> {
    // The preceding context test restored the original local selection and proved its exact
    // deployment after down/up and resume without source. Keep those assertions intact.
    fs::write(harness.workspace.join("reset.ko"), SOURCE)?;
    let original = harness.command(&["localnet", "status", "local"])?;
    require_phase(&original, "ready", 4)?;
    let old_context = context(&original)?;
    let old = harness.command(&["contract", "deploy", "reset.ko", "--context", "local"])?;
    require_deployment(&old)?;
    let (old_alias, old_address) = contract(&old)?;
    initialize_value(harness, &old, &old_context, &old_alias, &old_address, "37")?;
    harness.execute_on_every_peer_in_context(&old, "111", Some("local"), None)?;
    observe_every_peer(harness, &old_context, &old_alias, &old_address, false)?;

    let stopped = harness.command(&["localnet", "down", "local"])?;
    require_phase(&stopped, "stopped", 0)?;
    super::require_zero_owned_resources(&stopped)?;
    // A retained restart must keep the actual nonzero mutable state, not just artifact bytes.
    let retained = harness.command(&["localnet", "up", "local"])?;
    require_phase(&retained, "ready", 4)?;
    require_same_context(&original, &retained)?;
    harness.execute_on_every_peer_in_context(&old, "111", Some("local"), None)?;
    let stopped = harness.command(&["localnet", "down", "local"])?;
    require_phase(&stopped, "stopped", 0)?;
    super::require_zero_owned_resources(&stopped)?;

    let reset = harness.command(&["localnet", "reset", "local"])?;
    if reset.get("name").and_then(Value::as_str) != Some("local")
        || reset.get("state").and_then(Value::as_str) != Some("reset")
    {
        return Err("reset did not report its exact named operation".into());
    }
    let fresh = harness.command(&["localnet", "up", "local"])?;
    require_phase(&fresh, "ready", 4)?;
    let fresh_context = context(&fresh)?;
    require_new_context(&old_context, &fresh_context)?;
    observe_every_peer(harness, &fresh_context, &old_alias, &old_address, true)?;

    let new = harness.command(&["contract", "deploy", "reset.ko", "--context", "local"])?;
    require_deployment(&new)?;
    let (new_alias, new_address) = contract(&new)?;
    if new_alias != old_alias
        || new_address == old_address
        || new.get("journal") == old.get("journal")
    {
        return Err(
            "fresh deployment did not bind the same alias to a new instance and journal".into(),
        );
    }
    super::receipt_artifact(&new, &fresh_context.network_id, fresh_context.dataspace_id)?;
    initialize_value(
        harness,
        &new,
        &fresh_context,
        &new_alias,
        &new_address,
        "11",
    )?;
    harness.execute_on_every_peer_in_context(&new, "33", Some("local"), None)?;
    eprintln!(
        "[developer-smoke] reset removed the executed old instance; fresh ledger deployed and executed independently"
    );
    Ok(())
}

fn context(status: &Value) -> Result<ManagedContext, Box<dyn Error>> {
    Ok(json::from_value(
        status
            .get("context")
            .cloned()
            .ok_or("status omitted context")?,
    )?)
}

fn contract(deployment: &Value) -> Result<(ContractAlias, ContractAddress), Box<dyn Error>> {
    let receipt = deployment
        .get("receipt")
        .ok_or("missing deployment receipt")?;
    Ok((
        json::from_value(
            receipt
                .get("contract_alias")
                .cloned()
                .ok_or("missing contract alias")?,
        )?,
        json::from_value(
            receipt
                .get("contract_address")
                .cloned()
                .ok_or("missing contract address")?,
        )?,
    ))
}

fn require_new_context(old: &ManagedContext, new: &ManagedContext) -> Result<(), Box<dyn Error>> {
    if old.name != "local"
        || new.name != old.name
        || new.network_id == old.network_id
        || new.account_id == old.account_id
        || new.dataspace_id != 0
        || old.dataspace_id != 0
    {
        return Err(
            "reset reused the old network or signing identity, or changed its intended scope"
                .into(),
        );
    }
    Ok(())
}

fn initialize_value(
    harness: &mut Harness,
    deployment: &Value,
    context: &ManagedContext,
    alias: &ContractAlias,
    address: &ContractAddress,
    value: &str,
) -> Result<(), Box<dyn Error>> {
    super::receipt_artifact(deployment, &context.network_id, context.dataspace_id)?;
    // Scalar state requires its declared lifecycle initializer. Deployment records that hook;
    // this explicit native call invokes it exactly once for each distinct new instance.
    let args = json::to_string(&norito::json!({"next": value}))?;
    let called = harness.command(&[
        "contract",
        "call",
        alias.as_ref(),
        "--context",
        "local",
        "--entrypoint",
        "hajimari",
        "--args",
        &args,
        "--max-fee",
        "1000",
    ])?;
    let receipt = called
        .get("receipt")
        .ok_or("mutable call omitted its Applied receipt")?;
    let call = receipt
        .get("call")
        .ok_or("mutable call omitted its native completion")?;
    if called.get("status").and_then(Value::as_str) != Some("applied")
        || called.get("context").and_then(Value::as_str) != Some(context.name.as_str())
        || receipt.get("network_id").and_then(Value::as_str) != Some(context.network_id.as_str())
        || receipt.get("authority").and_then(Value::as_str) != Some(context.account_id.as_str())
        || receipt.get("contract_alias") != Some(&json::to_value(alias)?)
        || receipt.get("contract_address") != Some(&json::to_value(address)?)
        || receipt.get("entrypoint").and_then(Value::as_str) != Some("hajimari")
        || call.get("terminal_kind").and_then(Value::as_str) != Some("Applied")
        || call.get("resolved_from").and_then(Value::as_str) != Some("state")
        || call.get("scope").and_then(Value::as_str) != Some("global")
        || call
            .get("block_height")
            .and_then(Value::as_u64)
            .is_none_or(|height| height <= 1)
    {
        return Err("mutable reset fixture call lacks its exact native Applied evidence".into());
    }
    // This presentation check does not establish the write. The following real view on each
    // validator must execute the original artifact and read the newly stored nonzero value.
    Ok(())
}

fn observe_every_peer(
    harness: &Harness,
    expected: &ManagedContext,
    alias: &ContractAlias,
    address: &ContractAddress,
    absent: bool,
) -> Result<(), Box<dyn Error>> {
    let store = ManagedStore::open(&harness.state)?;
    let prepared = store.prepared("local")?;
    if &prepared.context != expected || prepared.peers.len() != 4 {
        return Err("reset observation lost its exact four-validator context".into());
    }
    let original = expected.load_client_config()?;
    let _profile = ChainDiscriminantGuard::enter(original.account_chain_discriminant);
    for peer in &prepared.peers {
        let mut config = original.clone();
        config.torii_api_url = peer.torii_url.parse()?;
        let client = Client::builder(config.clone())
            .build()?
            .with_request_deadline(Instant::now() + Duration::from_secs(10));
        let response = client.get_gov_contract_response(address)?;
        if response.status().as_u16() != 200 || response.body().len() as u64 > super::MAX_OUTPUT {
            return Err(
                "reset lifecycle observation requires bounded successful native data".into(),
            );
        }
        require_lifecycle(&json::from_slice(response.body())?, address, absent)?;
        let response = client.post_contract_deployment_state(alias)?;
        if response.status().as_u16() != 200 || response.body().len() as u64 > super::MAX_OUTPUT {
            return Err("reset deployment state requires bounded successful native data".into());
        }
        let state: DeploymentState = json::from_slice(response.body())?;
        state.require(
            &config.account.to_string(),
            config.account_chain_discriminant,
            alias,
            address,
            absent,
        )?;
    }
    Ok(())
}

fn require_lifecycle(
    value: &Value,
    address: &ContractAddress,
    absent: bool,
) -> Result<(), Box<dyn Error>> {
    if value.get("contract_address") != Some(&json::to_value(address)?)
        || value.get("dataspace").and_then(Value::as_str) != Some("universal")
        || value.get("found").and_then(Value::as_bool) != Some(!absent)
    {
        return Err(
            "native lifecycle response does not bind exact requested instance and presence".into(),
        );
    }
    if absent {
        let object = value
            .as_object()
            .ok_or("lifecycle observation is not an object")?;
        if object.len() != 3 {
            return Err("missing instance carried retained lifecycle or unknown fields".into());
        }
    } else if value.get("active").and_then(Value::as_bool) != Some(true)
        || value
            .get("contract_subject_account")
            .and_then(Value::as_str)
            != Some(address.subject_id().to_string().as_str())
    {
        return Err("original contract is not a live exact native instance".into());
    }
    Ok(())
}

#[derive(norito::derive::JsonDeserialize)]
#[norito(deny_unknown_fields)]
struct DeploymentState {
    authority: String,
    contract_alias: String,
    deploy_nonce: String,
    dataspace_alias: String,
    dataspace_id: String,
    previous_contract_address: Option<String>,
    observed_block_height: String,
    observed_block_hash: String,
    ledger_time_ms: String,
    chain_discriminant: String,
}

impl DeploymentState {
    fn require(
        &self,
        authority: &str,
        chain_discriminant: u16,
        alias: &ContractAlias,
        address: &ContractAddress,
        absent: bool,
    ) -> Result<(), Box<dyn Error>> {
        let nonce = decimal(&self.deploy_nonce)?;
        let height = decimal(&self.observed_block_height)?;
        let _: u64 = decimal(&self.ledger_time_ms)?;
        let hash: iroha_crypto::HashOf<iroha_data_model::block::BlockHeader> =
            self.observed_block_hash.parse()?;
        if self.authority != authority
            || self.contract_alias != alias.as_ref()
            || self.dataspace_alias != "universal"
            || self.dataspace_id != "0"
            || self.chain_discriminant != chain_discriminant.to_string()
            || height == 0
            || hash.to_string() != self.observed_block_hash
            || (absent && (nonce != 0 || self.previous_contract_address.is_some()))
            || (!absent
                && (nonce == 0
                    || self.previous_contract_address.as_deref() != Some(address.as_ref())))
        {
            return Err(
                "native deployment state did not establish exact alias and fresh nonce after reset"
                    .into(),
            );
        }
        Ok(())
    }
}

fn decimal(value: &str) -> Result<u64, Box<dyn Error>> {
    let parsed: u64 = value.parse()?;
    if parsed.to_string() != value {
        return Err("noncanonical deployment-state decimal".into());
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{NetworkId, account::AccountId};
    use iroha_model_base::topology::DataSpaceId;

    fn identities() -> (ManagedContext, ContractAlias, ContractAddress) {
        let network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"reset smoke unit network",
        )));
        let account = AccountId::new(
            KeyPair::from_seed(vec![19; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let address =
            ContractAddress::derive(&network, &account, 1, DataSpaceId::UNIVERSAL).unwrap();
        (
            ManagedContext {
                name: "local".into(),
                chain_id: "local".into(),
                network_id: network.to_string(),
                account_id: account.to_string(),
                dataspace_id: 0,
                dataspace_alias: "universal".into(),
                torii_url: "http://127.0.0.1:18080/".into(),
                client_config: std::path::PathBuf::from("/not-read/client.toml"),
            },
            "ResetSmoke::universal".parse().unwrap(),
            address,
        )
    }

    #[test]
    fn reset_fixture_compiles_a_real_mutable_state_and_public_view() {
        let (artifact, _) = kotodama_lang::compiler::Compiler::new()
            .compile_source_with_manifest(SOURCE)
            .expect("canonical stateful reset fixture");
        assert!(!artifact.is_empty());
    }

    #[test]
    fn missing_lifecycle_requires_exact_success_shape_not_inactive_or_foreign_data() {
        let (_, _, address) = identities();
        let absent =
            norito::json!({"found": false, "contract_address": address, "dataspace": "universal"});
        require_lifecycle(&absent, &address, true).unwrap();
        assert!(require_lifecycle(&absent, &address, false).is_err());
        for (key, value) in [
            ("found", Value::Bool(true)),
            ("contract_address", Value::Null),
            ("dataspace", Value::from("foreign")),
            ("active", Value::Bool(false)),
            ("lifecycle", Value::Null),
            ("unrecognized", Value::Bool(true)),
        ] {
            let mut changed = absent.clone();
            changed.as_object_mut().unwrap().insert(key.into(), value);
            assert!(
                require_lifecycle(&changed, &address, true).is_err(),
                "{key}"
            );
        }
        let present = norito::json!({"found": true, "contract_address": address, "dataspace": "universal", "active": true, "contract_subject_account": (address.subject_id().to_string())});
        require_lifecycle(&present, &address, false).unwrap();
        assert!(require_lifecycle(&present, &address, true).is_err());
    }

    #[test]
    fn reset_deployment_state_requires_fresh_nonce_exact_alias_and_committed_view() {
        let (context, alias, address) = identities();
        let hash: HashOf<iroha_data_model::block::BlockHeader> =
            HashOf::from_untyped_unchecked(Hash::new(b"reset smoke observed block"));
        let absent = norito::json!({
            "authority": (context.account_id.clone()), "contract_alias": (alias.to_string()),
            "deploy_nonce": "0", "dataspace_alias": "universal", "dataspace_id": "0",
            "previous_contract_address": null, "observed_block_height": "5",
            "observed_block_hash": (hash.to_string()), "ledger_time_ms": "1000", "chain_discriminant": "753",
        });
        let check = |value: Value, missing| -> Result<(), Box<dyn Error>> {
            let state: DeploymentState = json::from_value(value)?;
            state.require(&context.account_id, 753, &alias, &address, missing)
        };
        check(absent.clone(), true).unwrap();
        assert!(check(absent.clone(), false).is_err());
        for (key, value) in [
            ("authority", Value::from("foreign")),
            ("contract_alias", Value::from("Other::universal")),
            ("deploy_nonce", Value::from("1")),
            ("deploy_nonce", Value::from("00")),
            ("dataspace_alias", Value::from("foreign")),
            ("dataspace_id", Value::from("1")),
            (
                "previous_contract_address",
                Value::from(address.to_string()),
            ),
            ("observed_block_height", Value::from("0")),
            ("observed_block_hash", Value::from("invalid")),
            ("ledger_time_ms", Value::from("01000")),
            ("chain_discriminant", Value::from("754")),
            ("unknown", Value::Bool(true)),
        ] {
            let mut changed = absent.clone();
            changed.as_object_mut().unwrap().insert(key.into(), value);
            assert!(check(changed, true).is_err(), "{key}");
        }
        let mut present = absent;
        present
            .as_object_mut()
            .unwrap()
            .insert("deploy_nonce".into(), "2".into());
        present.as_object_mut().unwrap().insert(
            "previous_contract_address".into(),
            address.to_string().into(),
        );
        check(present.clone(), false).unwrap();
        assert!(check(present, true).is_err());
    }

    #[test]
    fn reset_requires_both_network_and_signer_to_change_without_switching_context() {
        let (old, _, _) = identities();
        assert!(require_new_context(&old, &old).is_err());
        let mut new = old.clone();
        new.network_id = "new network".into();
        assert!(require_new_context(&old, &new).is_err());
        new.account_id = "new signer".into();
        require_new_context(&old, &new).unwrap();
        let mut wrong = new.clone();
        wrong.network_id.clone_from(&old.network_id);
        assert!(require_new_context(&old, &wrong).is_err());
        new.name = "secondary".into();
        assert!(require_new_context(&old, &new).is_err());
    }
}
