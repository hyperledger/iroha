//! Shared NPoS genesis overrides for nexus localnet integration tests.
use iroha::data_model::isi::{InstructionBox, SetParameter};
use iroha_crypto::Hash as CryptoHash;
use iroha_data_model::parameter::{Parameter, system::SumeragiNposParameters};
use iroha_test_network::chain_id;
use std::num::NonZeroU64;
const LOCALNET_NPOS_EPOCH_LENGTH_BLOCKS: u64 = 3_600;
pub(super) fn npos_override_instruction(max_validators: usize) -> InstructionBox {
    let mut npos = SumeragiNposParameters::default();
    let chain_hash = CryptoHash::new(chain_id().into_inner().as_bytes());
    npos.epoch_seed = <[u8; 32]>::from(chain_hash);
    npos.epoch_length_blocks = NonZeroU64::new(LOCALNET_NPOS_EPOCH_LENGTH_BLOCKS)
        .expect("localnet NPoS epoch length must be nonzero");
    npos.max_validators =
        u32::try_from(max_validators).expect("localnet max_validators exceeds u32");
    InstructionBox::from(SetParameter::new(Parameter::Custom(
        npos.into_custom_parameter(),
    )))
}
pub(super) fn npos_override_transactions(max_validators: usize) -> Vec<Vec<InstructionBox>> {
    vec![vec![npos_override_instruction(max_validators)]]
}
#[test]
fn npos_override_transactions_publish_expected_schedule() {
    let txs = npos_override_transactions(4);
    let [tx] = txs.as_slice() else {
        panic!("expected a single override transaction");
    };
    let [instruction] = tx.as_slice() else {
        panic!("expected a single override instruction");
    };
    let Some(set_param) = instruction.as_any().downcast_ref::<SetParameter>() else {
        panic!("expected SetParameter instruction");
    };
    let Parameter::Custom(custom) = set_param.inner() else {
        panic!("expected custom parameter payload");
    };
    let Some(npos) = SumeragiNposParameters::from_custom_parameter(custom)
        .expect("valid fixture NPoS parameters")
    else {
        panic!("expected sumeragi_npos_parameters payload");
    };
    assert_eq!(npos.max_validators(), 4);
    assert_eq!(
        npos.epoch_length_blocks().get(),
        LOCALNET_NPOS_EPOCH_LENGTH_BLOCKS
    );
    assert_ne!(
        npos.epoch_seed(),
        [0; 32],
        "localnet overrides should use a chain-derived epoch seed"
    );
}
