//! Pinned executed-ledger inputs; no fixture asset or account fallback.
use super::*;
use iroha_data_model::{
    NetworkId,
    block::decode_framed_signed_block,
    sumeragi_finality::{SumeragiFinalityProof, authenticated_genesis},
};

const NAMES: [&str; 9] = [
    "account.norito",
    "account-b.norito",
    "account-c.norito",
    "reserve.norito",
    "asset.norito",
    "signed-genesis.wire",
    "genesis-manifest.json",
    "registration-proof.norito",
    "capture.json",
];

pub(super) struct LedgerSetup {
    pub(super) accounts: [AccountId; 3],
    pub(super) asset: KagemushaWalletAssetScopeV1,
    pub(super) manifest_sha256: String,
}
impl LedgerSetup {
    pub(super) fn read(sources: &Sources) -> Self {
        let path = selected_path("KAGEMUSHA_NATIVE_LEDGER_SETUP");
        let manifest_sha256 = env_pin("KAGEMUSHA_NATIVE_LEDGER_SETUP_SHA256");
        let raw = read_pin(&path, TARGET_MAX, &manifest_sha256);
        let manifest: norito::json::Value = norito::json::from_slice(&raw).unwrap();
        assert_eq!(
            manifest["schema"].as_str(),
            Some("iroha.kagemusha.executed-ledger-setup.v1")
        );
        assert_eq!(
            manifest["chain_id"].as_str(),
            Some(sources.genesis.chain_id())
        );
        assert_eq!(manifest["registration_height"].as_u64(), Some(1));
        assert_eq!(manifest["certified_height"].as_u64(), Some(2));
        assert_eq!(
            manifest["initial_supply_atomic_units"].as_str(),
            Some("1000")
        );
        let rows = manifest["originals"].as_array().unwrap();
        assert_eq!(rows.len(), NAMES.len());
        // Every original is bounded and pinned before decoding, including originals whose
        // authority is independently asserted by the executed-setup producer receipt.
        let originals = NAMES.map(|name| {
            let mut selected = rows.iter().filter(|row| row["name"].as_str() == Some(name));
            let row = selected.next().unwrap();
            assert!(selected.next().is_none());
            let bytes = read_pin(
                &path.parent().unwrap().join(name),
                16 << 20,
                row["sha256"].as_str().unwrap(),
            );
            assert_eq!(Some(bytes.len() as u64), row["bytes"].as_u64());
            bytes
        });
        assert_eq!(
            sha(&originals[8]),
            env_pin("KAGEMUSHA_SIGNED_GENESIS_FIXTURE_SHA256")
        );
        let capture: norito::json::Value = norito::json::from_slice(&originals[8]).unwrap();
        assert_eq!(
            capture["chain_id"].as_str(),
            Some(sources.genesis.chain_id())
        );
        assert_eq!(
            hex::decode(capture["signed_genesis_wire_hex"].as_str().unwrap()).unwrap(),
            originals[5]
        );
        let genesis = decode_framed_signed_block(&originals[5]).unwrap();
        let network = NetworkId::from_genesis_hash(genesis.hash());
        assert_eq!(network, sources.genesis.initial_epoch().network_id);
        assert_eq!(
            *network.as_bytes(),
            sources.installed.verifier().scheme().network_id
        );
        assert_eq!(
            authenticated_genesis(&genesis)
                .map(|genesis| genesis.into_parts().0)
                .unwrap(),
            *sources.genesis.initial_epoch()
        );
        assert_eq!(
            manifest["network_hex"].as_str(),
            Some(hex::encode(network.as_bytes()).as_str())
        );
        assert_eq!(
            manifest["instance_hex"].as_str(),
            Some(hex::encode(sources.genesis.instance().0).as_str())
        );
        let proofs: [SumeragiFinalityProof; 2] = decode(&originals[7]);
        assert_eq!([proofs[0].height(), proofs[1].height()], [1, 2]);
        let mut verifier = sources.genesis.as_ref().clone();
        for proof in &proofs {
            verifier.verify(proof).unwrap();
        }
        // This is finality of the selected executed setup, not an invented asset-row proof.
        // The independently pinned setup producer owns registration/supply assertions.
        let accounts: [AccountId; 3] = std::array::from_fn(|i| decode(&originals[i]));
        for (account, seed) in accounts.iter().zip([41, 42, 43]) {
            require_account_key(account, seed);
        }
        assert_ne!(accounts[0], accounts[1]);
        assert_ne!(accounts[1], accounts[2]);
        assert_ne!(accounts[0], accounts[2]);
        let reserve: AccountId = decode(&originals[3]);
        require_account_key(&reserve, 95);
        let asset: KagemushaWalletAssetScopeV1 = decode(&originals[4]);
        asset.validate().unwrap();
        assert_eq!(
            manifest["asset_digest_hex"].as_str(),
            Some(hex::encode(asset.asset_digest()).as_str())
        );
        Self {
            accounts,
            asset,
            manifest_sha256,
        }
    }
}

fn require_account_key(account: &AccountId, seed: u8) -> KeyPair {
    let key = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
    assert_eq!(account, &AccountId::new(key.public_key().clone()));
    key
}

pub(super) fn bind_identity(
    f: &mut Fixture,
    account: AccountId,
    asset: KagemushaWalletAssetScopeV1,
    seed: u8,
) {
    f.account_key = require_account_key(&account, seed);
    f.account = account;
    f.asset = asset;
    // This is an explicit authenticated actor fixture, independently bound for each account.
    f.config.actor = norito::encode_canonical(&f.account).unwrap();
    f.config.policy.asset_digest = f.asset.asset_digest();
    f.challenge.account_digest = kagemusha_wallet_account_digest_v1(&f.account).unwrap();
    f.challenge.asset_digest = f.asset.asset_digest();
    f.challenge.enrollment_policy = f.config.policy.policy_digest().unwrap();
}

#[test]
fn distinct_account_identity_binds_challenge_actor_and_signature() {
    let asset = fixture().asset;
    let mut fixtures = [fixture(), fixture(), fixture()];
    for (f, seed) in fixtures.iter_mut().zip([41, 42, 43]) {
        let account = AccountId::new(
            KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        bind_identity(f, account, asset.clone(), seed);
        assert_eq!(
            f.challenge.account_digest,
            kagemusha_wallet_account_digest_v1(&f.account).unwrap()
        );
        assert_eq!(
            f.config.actor,
            norito::encode_canonical(&f.account).unwrap()
        );
    }
    for pair in fixtures.windows(2) {
        assert_ne!(pair[0].account, pair[1].account);
        assert_ne!(
            pair[0].challenge.account_digest,
            pair[1].challenge.account_digest
        );
        assert_ne!(pair[0].config.actor, pair[1].config.actor);
        assert_ne!(
            sign(&pair[0], b"native account challenge"),
            sign(&pair[1], b"native account challenge")
        );
    }
}
