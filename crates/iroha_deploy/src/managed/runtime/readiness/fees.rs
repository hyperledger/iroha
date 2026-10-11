//! Bounded readiness authorization from all four original generated execution policies.

use super::*;
use crate::managed::{Result, native_operation::invalid};
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    account::address::ChainDiscriminantGuard,
    asset::AssetDefinitionId,
    block::{BlockHeader, consensus::SumeragiRootScope},
    sumeragi_finality::authenticated_genesis,
    transaction::{FeeChargeKind, FeeChargeLimit},
};
use iroha_model_base::peer::PeerId;
use iroha_primitives::numeric::Quantity;
use std::collections::BTreeSet;

pub(super) struct Selection {
    pub payment: FeePaymentIntent,
    pub genesis_hash: HashOf<BlockHeader>,
}

pub(super) fn select(
    prepared: &PreparedLocalnet,
    client: &iroha::config::Config,
) -> Result<Selection> {
    let invalid = || invalid("original readiness fee configuration differs from signed genesis");
    iroha_genesis::init_instruction_registry();
    if prepared.peers.len() != 4
        || prepared.context.client_config.file_name() != Some(std::ffi::OsStr::new("client.toml"))
    {
        return Err(invalid());
    }
    let root = iroha_fs::PrivateDirectory::open_exact(
        prepared
            .context
            .client_config
            .parent()
            .ok_or_else(invalid)?,
    )?;
    let _profile = ChainDiscriminantGuard::enter(client.account_chain_discriminant);
    let bytes_signed = root.read(
        "genesis.signed.nrt",
        iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1,
    )?;
    let block = iroha_data_model::block::decode_framed_signed_block(&bytes_signed)
        .map_err(|_| invalid())?;
    let manifest_bytes = root.read(
        "genesis.json",
        iroha_genesis::GENESIS_MANIFEST_JSON_MAX_BYTES_V1,
    )?;
    iroha_genesis::validate_genesis_manifest_json(&manifest_bytes).map_err(|_| invalid())?;
    let manifest = iroha_genesis::RawGenesisTransaction::from_json_slice_at_path(
        &manifest_bytes,
        root.path().join("genesis.json"),
    )
    .map_err(|_| invalid())?;
    if manifest.chain_id() != &client.chain
        || manifest.chain_discriminant() != client.account_chain_discriminant
    {
        return Err(invalid());
    }
    let authenticated = authenticated_genesis(&block).map_err(|_| invalid())?;
    let metadata = authenticated.metadata();
    let epoch = authenticated.into_parts().0;
    if NetworkId::from_genesis_hash(block.hash()) != client.network_id
        || epoch.network_id != client.network_id
    {
        return Err(invalid());
    }
    let private = match metadata.sumeragi_context.root_scope {
        SumeragiRootScope::Global if prepared.context.dataspace_id == 0 => false,
        SumeragiRootScope::Dataspace { dataspace_id, .. }
            if dataspace_id.as_u64() == prepared.context.dataspace_id
                && prepared.context.dataspace_id != 0 =>
        {
            true
        }
        _ => return Err(invalid()),
    };
    let committee: BTreeSet<_> = epoch
        .committee
        .iter()
        .map(|member| member.validator.clone())
        .collect();
    let mut seen = BTreeSet::new();
    let expected_policy = Hash::prehashed(metadata.sumeragi_context.execution_policy_hash);
    let mut selected_asset = None;
    for (index, peer) in prepared.peers.iter().enumerate() {
        if peer.config_path != root.path().join(format!("peer{index}.toml")) {
            return Err(invalid());
        }
        let bytes = root.read(&format!("peer{index}.toml"), 1024 * 1024)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
        // Generated originals are flattened. Reject indirection before the shared parser
        // could read an `extends` source; the original private handles own these inputs.
        let table = crate::secret_toml::Table::new(
            crate::secret_toml::parse_table(text, "readiness original validator")
                .map_err(|_| invalid())?,
        );
        if table.contains_key("extends") {
            return Err(invalid());
        }
        let mut config = crate::localnet::parse_localnet_peer_config(text, Some(&peer.config_path))
            .map_err(|_| invalid())?;
        if private {
            // Match native --sora source selection, preserving explicit even-default geometry.
            iroha_config::sora_profile::SoraProfileSelection::from_table(&table).apply(&mut config);
        }
        if index == 0 {
            iroha_genesis::validate_prepared_genesis_bundle(
                &bytes_signed,
                &manifest,
                &config.genesis.public_key,
                config.genesis.expected_hash,
            )
            .map_err(|_| invalid())?;
        }
        if block
            .external_transactions()
            .next()
            .and_then(|transaction| transaction.authority().try_signatory())
            != Some(&config.genesis.public_key)
        {
            return Err(invalid());
        }
        let validator = PeerId::new(config.common.key_pair.public_key().clone());
        if config.genesis.expected_hash != block.hash()
            || config.common.chain != client.chain
            || *config.common.chain_discriminant.value() != client.account_chain_discriminant
            || !committee.contains(&validator)
            || !seen.insert(validator)
            || crate::localnet::service_authorities::configured_execution_policy(&config)
                .map_err(|_| invalid())?
                != expected_policy
        {
            return Err(invalid());
        }
        let asset = AssetDefinitionId::parse_address_literal(&config.nexus.fees.fee_asset_id)
            .map_err(|_| invalid())?;
        if selected_asset
            .as_ref()
            .is_some_and(|selected| selected != &asset)
        {
            return Err(invalid());
        }
        selected_asset = Some(asset);
    }
    if seen != committee {
        return Err(invalid());
    }
    root.revalidate()?;
    Ok(Selection {
        // A local smoke Log may charge only this authenticated asset/component, up to one
        // unit. Native fee computation stays authoritative and refuses a larger actual bound.
        payment: FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                selected_asset.ok_or_else(invalid)?,
                Quantity::from(1u64),
            )],
            None,
        ),
        genesis_hash: block.hash(),
    })
}
