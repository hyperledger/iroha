//! Verifies that the genesis block signatures match the expected public key.

//! Skipped by default; enable with `IROHA_RUN_IGNORED=1`.
use iroha_crypto::{PublicKey, SignatureOf};
use iroha_data_model::block::{BlockHeader, decode_framed_signed_block};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
#[test]
fn check_genesis_signature() {
    if std::env::var("IROHA_RUN_IGNORED").ok().as_deref() != Some("1") {
        eprintln!("Skipping: genesis signature check is gated. Set IROHA_RUN_IGNORED=1 to run.");
        return;
    }
    let genesis_path = std::env::var("IROHA_GENESIS_FILE")
        .unwrap_or_else(|_| "/tmp/iroha-localnet-7peer/genesis.signed.nrt".to_owned());
    let pub_key_str = std::env::var("IROHA_GENESIS_PUBLIC_KEY").unwrap_or_else(|_| {
        "ed0120EEF765223920C4D7D7ED4E204DCBDF3DAFE37F53B11F155D78206F24BC232646".to_owned()
    });
    if !Path::new(&genesis_path).exists() {
        eprintln!(
            "Skipping: genesis file not found at `{genesis_path}`. \
Set IROHA_GENESIS_FILE to point at a signed genesis payload."
        );
        return;
    }
    let mut file = File::open(&genesis_path).expect("open genesis");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).expect("read genesis");
    let block = decode_framed_signed_block(&bytes).expect("decode genesis block");
    let pub_key = PublicKey::from_str(&pub_key_str).expect("parse pub key");
    println!("Genesis hash: {:?}", block.hash());
    println!("Signatures: {:?}", block.signatures().count());
    for sig in block.signatures() {
        println!("Verifying signature against {pub_key:?}");
        let signature: &SignatureOf<BlockHeader> = sig.signature();
        signature
            .verify_hash(&pub_key, block.hash())
            .expect("verify signature");
    }
}
