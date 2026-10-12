//! Explicit native AMX participant assembly from the selected parent's real G1 and H2.
//!
//! This offline owner authenticates source artifacts with Core's sole native prefix verifier.
//! It does not execute a new global block, grant authority, or replace the private signer.
//! Core staging still executes the appended instruction and binds the private genesis policy.
//! TODO: full nested offline verifier funding, global participant registration and durable
//! validator relaying remain separate production owners. Managed source custody is independent
//! of runtime readiness and does not qualify whole-network bootstrap or settlement.

use color_eyre::eyre::{WrapErr, eyre};
use iroha_allocation::AllocationBudget;
use iroha_core::sumeragi::certified_chain::CertifiedPrefix;
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    block::{SharedSignedBlock, SignedBlock, consensus::SumeragiRootScope},
    isi::sumeragi_amx::RegisterAmxParticipantV1,
    sumeragi_finality::MAX_FINALITY_BLOCK_BYTES,
};
use iroha_genesis::{
    RawGenesisTransaction, SIGNED_GENESIS_MAX_BYTES_V1, decode_signed_genesis,
    signed_genesis_consensus_metadata,
};
use iroha_model_base::chain::ChainId;

fn canonical_source(bytes: &[u8], maximum: usize) -> color_eyre::Result<SignedBlock> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(eyre!(
            "AMX global source must be a complete bounded canonical block frame"
        ));
    }
    let decoded = decode_signed_genesis(bytes).wrap_err("decode canonical AMX global source")?;
    let expected = (u64::try_from(bytes.len())?, Hash::new(bytes));
    if decoded.canonical_wire_identity()? != expected {
        return Err(eyre!(
            "AMX global source differs from the exact canonical SignedBlockWire"
        ));
    }
    Ok(decoded)
}

/// Append exactly one native participant transaction before normal private genesis staging.
///
/// The manifest's selected private root independently pins the parent network and dataspace.
/// Both original frames are moved into the instruction after their complete G1/H2 relation is
/// authenticated. No result-only genesis artifact is treated as a committed execution receipt.
/// Existing transactions and all policy/topology/trigger fields are preserved exactly.
///
/// The finite offline pool here funds the two actual immutable block controls. Existing fixed
/// codec limits bound decoded inputs; this is not a claim that nested decoding or verification
/// allocations are completely charged, or that a local source is whole-network qualification.
///
/// # Errors
/// Refuses a non-private or malformed selected root, an existing participant instruction,
/// incomplete/noncanonical sources, a foreign chain/parent/root or invalid H2 finality.
/// No signing or output publication occurs on refusal.
pub fn append_amx_participant(
    manifest: RawGenesisTransaction,
    global_chain_id: ChainId,
    global_genesis: Vec<u8>,
    global_successor: Vec<u8>,
) -> color_eyre::Result<RawGenesisTransaction> {
    let context = manifest.sumeragi_context_parameters();
    context
        .validate()
        .wrap_err("validate selected private genesis scope")?;
    let SumeragiRootScope::Dataspace {
        parent_network_id,
        dataspace_id,
    } = context.root_scope
    else {
        return Err(eyre!(
            "AMX participant bootstrap requires a selected private dataspace root"
        ));
    };
    if manifest.instructions().any(|instruction| {
        instruction
            .as_any()
            .downcast_ref::<RegisterAmxParticipantV1>()
            .is_some()
    }) {
        return Err(eyre!(
            "private genesis already contains a native AMX participant instruction"
        ));
    }
    authenticate_global_sources(
        &global_chain_id,
        parent_network_id,
        &global_genesis,
        &global_successor,
    )?;
    manifest.append_instruction_transaction(RegisterAmxParticipantV1 {
        dataspace: dataspace_id,
        global_chain_id,
        global_genesis,
        global_successor,
    })
}

/// Authenticate original global sources through the same sole verifier used by assembly.
/// This exposes no receipt or authority and performs no signing or publication.
pub(crate) fn authenticate_global_sources(
    global_chain_id: &ChainId,
    parent_network_id: NetworkId,
    global_genesis: &[u8],
    global_successor: &[u8],
) -> color_eyre::Result<()> {
    // Prepay both exact control shells before allocating or consuming either decoded source.
    // The operational offline pool is separate from every runtime State/attempt pool.
    let control_bytes = SharedSignedBlock::allocation_layout()
        .size()
        .checked_mul(2)
        .ok_or_else(|| eyre!("AMX source-control layout overflow"))?;
    let pool = AllocationBudget::new(control_bytes);
    let genesis_shell = SharedSignedBlock::reserve(&pool)?;
    let successor_shell = SharedSignedBlock::reserve(&pool)?;
    let genesis = canonical_source(global_genesis, SIGNED_GENESIS_MAX_BYTES_V1)?;
    if NetworkId::from_genesis_hash(genesis.hash()) != parent_network_id {
        return Err(eyre!(
            "global genesis differs from the private root's selected parent network"
        ));
    }
    if signed_genesis_consensus_metadata(&genesis)?
        .sumeragi_context
        .root_scope
        != SumeragiRootScope::Global
    {
        return Err(eyre!(
            "AMX parent source must be a signed global root genesis"
        ));
    }
    let mut prefix = CertifiedPrefix::new(
        global_chain_id,
        parent_network_id,
        genesis_shell.initialize(genesis),
    )
    .wrap_err("authenticate original global genesis")?;
    let successor = canonical_source(global_successor, MAX_FINALITY_BLOCK_BYTES)?;
    let (_, genesis_anchor) = prefix
        .push(successor_shell.initialize(successor))
        .wrap_err("authenticate genuine global H2 successor")?
        .into_parts();
    if genesis_anchor.is_none() {
        return Err(eyre!(
            "global source pair did not authenticate the genesis execution through H2"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::{
        state::World,
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::transaction::Executable;
    use iroha_data_model::{
        block::consensus::SumeragiGenesisContextParameters,
        block::{BlockSignature, BlockSignatures, CommitCertificate},
        isi::Log,
        level::Level,
    };
    use iroha_genesis::{GenesisBuilder, GenesisTopologyEntry};
    use iroha_model_base::topology::DataSpaceId;
    use std::path::PathBuf;

    const DATASPACE: DataSpaceId = DataSpaceId::new((1_u64 << 40) + 741);

    // Every positive source comes from real original genesis execution and a nonempty H2
    // committed by the native test chain. No QC, result or availability row is manufactured.
    fn sources() -> (ChainId, CertifiedTestChain) {
        let config = TestChainConfig::new(World::new(), 1_000);
        let chain_id = config.chain_id.clone();
        let signer = config.genesis_key.clone();
        let mut chain = CertifiedTestChain::start(config).unwrap();
        let transaction = chain.sign(
            &signer,
            [Log::new(Level::INFO, "genuine AMX bootstrap H2".into()).into()],
            1_499,
        );
        assert_eq!(chain.commit_at(1_500, vec![transaction]), vec![true]);
        assert!(chain.committed(1).block().has_results());
        assert!(chain.committed(2).block().has_results());
        (chain_id, chain)
    }

    fn private_manifest(parent_network_id: NetworkId) -> RawGenesisTransaction {
        let mut context = SumeragiGenesisContextParameters::recommended();
        context.root_scope = SumeragiRootScope::Dataspace {
            parent_network_id,
            dataspace_id: DATASPACE,
        };
        GenesisBuilder::new_without_executor(
            ChainId::from("explicit-private-amx"),
            PathBuf::from("."),
        )
        .with_sumeragi_context_parameters(context)
        .append_instruction(Log::new(Level::INFO, "original private instruction".into()))
        .set_topology(
            iroha_core::sumeragi::test_chain::fixture_validators()
                .into_iter()
                .map(|(peer, pop)| GenesisTopologyEntry::new(peer, pop))
                .collect(),
        )
        .build_raw()
        .unwrap()
        .with_chain_discriminant(1337)
    }

    fn wire(chain: &CertifiedTestChain, height: u64) -> Vec<u8> {
        chain.committed(height).block().encode_wire().unwrap()
    }

    #[test]
    fn explicit_participant_assembly_preserves_original_manifest_and_genuine_g1_h2() {
        let (chain_id, chain) = sources();
        let manifest = private_manifest(chain.network_id());
        let before = norito::json::to_value(&manifest).unwrap();
        let g1 = wire(&chain, 1);
        let h2 = wire(&chain, 2);
        let g1_pointer = g1.as_ptr();
        let h2_pointer = h2.as_ptr();
        let assembled = append_amx_participant(manifest, chain_id.clone(), g1, h2).unwrap();
        let appended = assembled.transactions().last().unwrap().instructions();
        assert_eq!(appended.len(), 1);
        let registration = appended[0]
            .as_any()
            .downcast_ref::<RegisterAmxParticipantV1>()
            .unwrap();
        assert_eq!(registration.dataspace, DATASPACE);
        assert_eq!(registration.global_chain_id, chain_id);
        assert_eq!(registration.global_genesis, wire(&chain, 1));
        assert_eq!(registration.global_successor, wire(&chain, 2));
        assert_eq!(registration.global_genesis.as_ptr(), g1_pointer);
        assert_eq!(registration.global_successor.as_ptr(), h2_pointer);
        let mut after = norito::json::to_value(&assembled).unwrap();
        after
            .as_object_mut()
            .unwrap()
            .get_mut("transactions")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            after, before,
            "no original policy or transaction may be rewritten"
        );
        // The same ordinary signing API signs the assembled source; this is not a claim
        // of private execution or a substitute for Kagami's required native staging.
        let key = KeyPair::from_seed(vec![0x79; 32], Algorithm::Ed25519);
        let signed = assembled
            .clone()
            .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
                &key,
                None,
                Some(iroha_core::state::default_genesis_confidential_policy_hash()),
                1_700_000_000_000,
            )
            .unwrap();
        assert!(signed.0.signatures().next().is_some());
        for signature in signed.0.signatures() {
            signature
                .signature()
                .verify_hash(key.public_key(), signed.0.hash())
                .unwrap();
        }
        assert_eq!(
            signed_genesis_consensus_metadata(&signed.0)
                .unwrap()
                .sumeragi_context
                .root_scope,
            assembled.sumeragi_context_parameters().root_scope
        );
        assert!(signed.0.external_transactions().any(|transaction| {
            if let Executable::Instructions(instructions) = transaction.instructions() {
                instructions
                    .iter()
                    .any(|instruction| instruction.as_any().is::<RegisterAmxParticipantV1>())
            } else {
                false
            }
        }));
        for transaction in signed.0.external_transactions() {
            transaction.verify_signature().unwrap();
        }
    }

    #[test]
    fn explicit_participant_assembly_executes_through_production_genesis_staging() {
        let (chain_id, chain) = sources();
        let _guard = crate::managed::native_test_guard();
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("private-root");
        let alias = "amxbootstrap";
        let name = iroha_data_model::sns::NameSelectorV1::new(
            iroha_data_model::sns::DATASPACE_ALIAS_SUFFIX_ID,
            alias,
        )
        .unwrap();
        let spec = crate::localnet::PrivateRootSpec {
            parent_network_id: chain.network_id(),
            dataspace_id: DataSpaceId::from_hash(&name.name_hash()),
            dataspace_alias: alias.into(),
        };
        let ports = crate::managed::LocalnetPorts::reserve().unwrap();
        let prepared = crate::localnet::prepare_private_root("amx-bootstrap", &root, &ports, &spec)
            .expect("generate the complete original private fee, SNS and validator policy");
        let original = RawGenesisTransaction::from_path(&root.join("genesis.json")).unwrap();
        let client = prepared.context.load_client_config().unwrap();
        let key = &client.key_pair;
        let config_path = &prepared.peers[0].config_path;
        let config_bytes = iroha_fs::read_private(config_path, 1024 * 1024).unwrap();
        let rendered = std::str::from_utf8(&config_bytes).unwrap();
        let mut config =
            crate::localnet::parse_localnet_peer_config(rendered, Some(config_path)).unwrap();
        let table = crate::secret_toml::Table::new(
            crate::secret_toml::parse_table(rendered, "original private AMX bootstrap fixture")
                .unwrap(),
        );
        iroha_config::sora_profile::SoraProfileSelection::from_table(&table).apply(&mut config);
        let selected_scope = original.sumeragi_context_parameters().root_scope;
        let assembled =
            append_amx_participant(original, chain_id, wire(&chain, 1), wire(&chain, 2)).unwrap();
        let (bound, signed) = crate::genesis::staging::bind_and_sign_staged_sumeragi_context(
            assembled,
            key,
            Some(&config),
            Some(iroha_core::da::proof_policy_bundle(
                &config.nexus.lane_config,
            )),
            iroha_core::state::default_genesis_confidential_policy_hash(),
            Some(1_700_000_000_000),
        )
        .expect("the original participant must execute in normal private genesis staging");
        assert!(signed.0.has_results());
        assert!(
            signed
                .0
                .output_results()
                .all(|result| result.as_ref().is_ok())
        );
        signed.0.validate_output_merkle_cache().unwrap();
        assert_eq!(
            bound.sumeragi_context_parameters().root_scope,
            selected_scope
        );
        let mut registrations = bound.instructions().filter_map(|instruction| {
            instruction
                .as_any()
                .downcast_ref::<RegisterAmxParticipantV1>()
        });
        let registration = registrations.next().unwrap();
        assert_eq!(registration.global_genesis, wire(&chain, 1));
        assert_eq!(registration.global_successor, wire(&chain, 2));
        assert!(registrations.next().is_none());
        assert_eq!(signed.0.signatures().count(), 1);
        for signature in signed.0.signatures() {
            signature
                .signature()
                .verify_hash(key.public_key(), signed.0.hash())
                .unwrap();
        }
        let restaged = crate::genesis::staging::restage_signed_sumeragi_context_hashes(
            &bound,
            Some(&config),
            &signed.0,
        )
        .expect("the exact final private identity must reproduce its authenticated result");
        assert_eq!(restaged.executed_block.hash(), signed.0.hash());
    }

    #[test]
    fn explicit_participant_assembly_refuses_wrong_parent_chain_and_incomplete_pair() {
        let (chain_id, chain) = sources();
        let foreign = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            Hash::new(b"foreign independently selected parent"),
        ));
        assert!(
            append_amx_participant(
                private_manifest(foreign),
                chain_id.clone(),
                wire(&chain, 1),
                wire(&chain, 2)
            )
            .is_err()
        );
        assert!(
            append_amx_participant(
                private_manifest(chain.network_id()),
                ChainId::from("wrong-global-label"),
                wire(&chain, 1),
                wire(&chain, 2)
            )
            .is_err()
        );
        assert!(
            append_amx_participant(
                private_manifest(chain.network_id()),
                chain_id.clone(),
                Vec::new(),
                wire(&chain, 2)
            )
            .is_err()
        );
        assert!(
            append_amx_participant(
                private_manifest(chain.network_id()),
                chain_id.clone(),
                wire(&chain, 1),
                Vec::new()
            )
            .is_err()
        );
        assert!(
            append_amx_participant(
                private_manifest(chain.network_id()),
                chain_id,
                wire(&chain, 1),
                wire(&chain, 1)
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_participant_assembly_refuses_global_target_and_duplicate_registration() {
        let (chain_id, chain) = sources();
        let selected = private_manifest(chain.network_id());
        let global = selected
            .clone()
            .with_sumeragi_context_parameters(SumeragiGenesisContextParameters::recommended());
        assert!(
            append_amx_participant(global, chain_id.clone(), wire(&chain, 1), wire(&chain, 2))
                .is_err()
        );
        let assembled =
            append_amx_participant(selected, chain_id.clone(), wire(&chain, 1), wire(&chain, 2))
                .unwrap();
        assert!(
            append_amx_participant(assembled, chain_id, wire(&chain, 1), wire(&chain, 2)).is_err()
        );
    }

    #[test]
    fn explicit_participant_assembly_refuses_bad_genesis_and_successor_signatures() {
        let (chain_id, chain) = sources();
        let mut bad_genesis = (**chain.committed(1).block()).clone();
        let key = KeyPair::from_seed(vec![0x7a; 32], Algorithm::Ed25519);
        bad_genesis
            .replace_signatures(
                BlockSignatures::try_from_iter([BlockSignature::new(
                    0,
                    iroha_crypto::SignatureOf::try_from_hash(key.private_key(), bad_genesis.hash())
                        .unwrap(),
                )])
                .unwrap(),
            )
            .unwrap();
        assert!(
            append_amx_participant(
                private_manifest(chain.network_id()),
                chain_id.clone(),
                bad_genesis.encode_wire().unwrap(),
                wire(&chain, 2)
            )
            .is_err()
        );
        let h2 = (**chain.committed(2).block()).clone();
        let certificate = h2.commit_certificate().unwrap();
        let mut qc: iroha_sumeragi::message::Qc =
            norito::decode_canonical(certificate.commit_qc()).unwrap();
        qc.agg_sig.0[0] ^= 1;
        let h2 = h2
            .clone()
            .with_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
                certificate.consensus_header().to_vec(),
                norito::encode_canonical(&qc).unwrap(),
                certificate.result_preimage().to_vec(),
                certificate.availability().to_vec(),
            )));
        assert!(
            append_amx_participant(
                private_manifest(chain.network_id()),
                chain_id,
                wire(&chain, 1),
                h2.encode_wire().unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_participant_assembly_refuses_a_signed_non_global_parent_root() {
        let (_, chain) = sources();
        let manifest = private_manifest(chain.network_id());
        let chain_id = manifest.chain_id().clone();
        let key = KeyPair::from_seed(vec![0x7b; 32], Algorithm::Ed25519);
        // This deliberately signed private proposal is a negative root-kind input, not H2 proof.
        let source = manifest.build_and_sign(&key).unwrap().0;
        let parent = NetworkId::from_genesis_hash(source.hash());
        assert!(
            append_amx_participant(
                private_manifest(parent),
                chain_id,
                source.encode_wire().unwrap(),
                wire(&chain, 2)
            )
            .is_err()
        );
    }
}
