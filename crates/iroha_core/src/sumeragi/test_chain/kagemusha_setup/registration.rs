//! Actual Register execution, ordinary exact-quorum finality and universal selection.
//! The existing fixture executes all accounts, permissions and asset state from signed genesis.

use super::*;
mod export;
use iroha_core_zk::kagemusha_wallet_registration_v1::verify_finalized_kagemusha_wallet_registration_v1;
use iroha_crypto::HashOf;
use iroha_data_model::{
    asset::AssetBalanceScope,
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1 as Action, KagemushaWalletLedgerV1},
    kagemusha::{
        KagemushaDevicePublicKeyV1, KagemushaWalletSchemeV1, kagemusha_wallet_provider_contract_v1,
    },
    query::CommittedTransaction,
    sumeragi_finality::VerifiedSumeragiBlock,
};

fn scheme(setup: &ExecutedKagemushaSetup) -> KagemushaWalletSchemeV1 {
    let key = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *setup.chain.network_id().as_bytes(),
        scheme_root_key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
            key.verifying_key().to_encoded_point(false).as_bytes(),
        )
        .unwrap(),
        relation_id: [9; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    }
}

fn committed(block: &VerifiedSumeragiBlock) -> CommittedTransaction {
    let block = block.block();
    let entrypoint = block.network_entrypoint_at(0).unwrap().clone();
    let (output_index, _) = block.network_output_at(0).unwrap();
    let output = block.execution_outputs()[output_index as usize].clone();
    CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block.network_input_proof(0).unwrap(),
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block.output_proof(output_index).unwrap(),
        output,
    }
}

fn balance(setup: &ExecutedKagemushaSetup, account: &AccountId) -> Quantity {
    setup
        .chain
        .state()
        .view()
        .world()
        .assets()
        .get(&AssetId::of(setup.asset.asset.clone(), account.clone()))
        .map_or_else(Quantity::zero, |value| value.as_ref().clone())
}

struct ExecutedRegistration {
    setup: ExecutedKagemushaSetup,
    scheme: KagemushaWalletSchemeV1,
    proofs: Vec<SumeragiFinalityProof>,
    committed: CommittedTransaction,
}

// Both the regression and exporter execute identical refusals and successful Register
// through StateExecutor. No execution output, World row or finality verdict is injected.
fn execute_registration(
    mut setup: ExecutedKagemushaSetup,
    scheme: KagemushaWalletSchemeV1,
) -> ExecutedRegistration {
    scheme.validate().unwrap();
    assert_eq!(scheme.network_id, *setup.chain.network_id().as_bytes());
    let scheme_original = scheme.to_canonical_bytes().unwrap();
    let asset_original = norito::encode_canonical(&setup.asset).unwrap();
    let registration = KagemushaWalletLedgerV1::new(
        scheme.scheme_id(),
        Action::Register {
            scheme: scheme_original.clone(),
            asset: asset_original.clone(),
            reserve: setup.reserve.clone(),
            balance_scope: AssetBalanceScope::Global,
        },
    );
    let mut verifier = native(&setup);
    let mut proofs = registration_proofs(&setup).to_vec();
    for proof in &proofs {
        verifier.verify(proof).unwrap();
    }
    let mut terminal = None;
    // Both failures are actual ordinary execution results, never injected output rows.
    for change in 0..3 {
        let mut instruction = registration.clone();
        let signer = if change == 0 { 41 } else { 95 };
        if change == 1 {
            let Action::Register { asset, .. } = &mut instruction.action else {
                unreachable!()
            };
            let mut wrong_scale = setup.asset.clone();
            wrong_scale.scale += 1;
            *asset = norito::encode_canonical(&wrong_scale).unwrap();
        }
        let now = 3_000 + change * 1_000;
        let transaction = setup
            .chain
            .sign(&key(signer), [instruction.into()], now - 1);
        let transaction_hash = transaction.hash();
        assert_eq!(setup.chain.commit_at(now, vec![transaction]), [change == 2],);
        let height = setup.chain.height();
        let proof =
            crate::sumeragi::finality::build_proof(&setup.chain.state().view(), height).unwrap();
        let verified = verifier.verify(&proof).unwrap();
        proofs.push(proof);
        let committed = committed(&verified);
        let selected = verify_finalized_kagemusha_wallet_registration_v1(
            &verified,
            &committed,
            setup.chain.network_id(),
            CHAIN,
            &scheme,
            setup.asset.asset_digest(),
            0,
        );
        if change < 2 {
            assert!(selected.is_err());
            assert!(
                setup
                    .chain
                    .state()
                    .view()
                    .world()
                    .kagemusha_wallet_ledger()
                    .iter()
                    .next()
                    .is_none()
            );
        } else {
            let selected = selected.unwrap();
            assert_eq!(selected.scheme(), &scheme);
            assert_eq!(selected.asset(), &setup.asset);
            assert_eq!(selected.reserve(), &setup.reserve);
            assert_eq!(selected.scheme_original(), scheme_original);
            assert_eq!(selected.asset_original(), asset_original);
            assert_eq!(selected.height(), height);
            assert_eq!(selected.transaction_hash(), *transaction_hash.as_ref());
            assert_eq!(selected.instruction_index(), 0);
            assert_eq!(selected.block_hash(), *committed.block_hash().as_ref());
            terminal = Some(committed);
        }
        assert_eq!(
            balance(&setup, &setup.account),
            Quantity::from_canonical_numeric(Numeric::new(SUPPLY, SCALE)).unwrap()
        );
        assert_eq!(balance(&setup, &setup.reserve), Quantity::zero());
    }
    assert_eq!(proofs.len(), 5);
    assert_eq!(setup.chain.height(), 5);
    ExecutedRegistration {
        setup,
        scheme,
        proofs,
        committed: terminal.expect("actual successful terminal Register"),
    }
}

#[test]
fn executed_universal_registration_authenticates_exact_asset_without_parliament() {
    let setup = start();
    let selected = scheme(&setup);
    let executed = execute_registration(setup, selected);
    assert_eq!(
        *executed.committed.block_hash(),
        executed.setup.chain.committed(5).block().hash()
    );
}
