use iroha_crypto::KeyPair;
use iroha_data_model::prelude::*;

#[test]
fn transfer_isi_should_be_valid() {
    let _instruction = Transfer::asset_numeric(
        format!("btc##{}@crypto", KeyPair::random().public_key())
            .parse()
            .unwrap(),
        12u32,
        format!("{}@crypto", KeyPair::random().public_key())
            .parse()
            .unwrap(),
    );
}
