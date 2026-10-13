//! The locked EVM creation code and nine-word constructor of §5.2.1 and P4.

use std::sync::LazyLock;

use super::{AbiToken, SccpCommitteePinV1, SccpNetworkV1, encode_tokens, word_u64, word_u128};
use crate::v1::{hashes::keccak256, network::tag};

/// Canonical keyless CREATE2 proxy, identical on Ethereum and BSC.
pub const SCCP_EVM_DEPLOYER: [u8; 20] = [
    0x4e, 0x59, 0xb4, 0x48, 0x47, 0xb3, 0x79, 0x57, 0x85, 0x88, 0x92, 0x0c, 0xa7, 0x8f, 0xbf, 0x26,
    0xc0, 0xb4, 0x95, 0x6c,
];
/// The only SCCP deployment salt.
pub const SCCP_EVM_SALT: [u8; 32] = [0; 32];

const ARTIFACT_LOCK: &str =
    include_str!("../../../../../scripts/contract_tooling/artifact-lock.json");
const CONTRACT: &str = "contracts/evm/sccp/SccpTairaXor.sol:SccpTairaXor";

/// Exact creation bytes embedded from the reviewed artifact lock, with no runtime file access.
pub static SCCP_EVM_CREATION_CODE: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let lock: norito::json::Value =
        norito::json::from_str(ARTIFACT_LOCK).expect("embedded contract artifact lock parses");
    let text = lock
        .get("targets")
        .and_then(|value| value.get("evm"))
        .and_then(|value| value.get("contracts"))
        .and_then(|value| value.get(CONTRACT))
        .and_then(|value| value.get("creation_bytecode_hex"))
        .and_then(norito::json::Value::as_str)
        .expect("embedded lock pins SCCP EVM creation bytecode");
    let digits = text
        .strip_prefix("0x")
        .expect("locked bytecode is prefixed");
    assert!(!digits.is_empty() && digits.len().is_multiple_of(2));
    (0..digits.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&digits[offset..offset + 2], 16).expect("locked bytecode is hex")
        })
        .collect()
});

/// The nine constructor arguments of §5.2.1, including the native committee pin.
/// Encoding does not authenticate the pin or validate time-dependent deployment bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConstructorArgsV1 {
    /// Taira chain identity.
    pub taira_network_id: [u8; 32],
    /// Native consensus identity.
    pub consensus_instance: [u8; 32],
    /// Destination profile; the constructor rejects profiles other than Ethereum and BSC.
    pub network: SccpNetworkV1,
    /// Nonzero route revision.
    pub route_revision: u32,
    /// Nonzero wrapped-supply cap, strictly below `2^128`.
    pub max_wrapped_supply: u128,
    /// Authenticated separately by deployment admission.
    pub pin: SccpCommitteePinV1,
}

impl ConstructorArgsV1 {
    /// Canonical ABI encoding in the constructor's exact argument order.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_tokens(&[
            AbiToken::Word(self.taira_network_id),
            AbiToken::Word(self.consensus_instance),
            AbiToken::Word(word_u64(u64::from(tag(self.network)))),
            AbiToken::Word(word_u64(u64::from(self.route_revision))),
            AbiToken::Word(word_u128(self.max_wrapped_supply)),
            AbiToken::Word(word_u64(self.pin.generation)),
            AbiToken::Word(self.pin.committee_root),
            AbiToken::Word(word_u64(self.pin.start_height)),
            AbiToken::Word(word_u64(self.pin.until_ms)),
        ])
    }

    /// Locked creation code followed by the nine ABI words.
    #[must_use]
    pub fn init_code(&self) -> Vec<u8> {
        let mut code = SCCP_EVM_CREATION_CODE.clone();
        code.extend(self.encode());
        code
    }

    /// P4 address under the canonical proxy and zero salt.
    #[must_use]
    pub fn address(&self) -> [u8; 20] {
        create2_address(&SCCP_EVM_DEPLOYER, &SCCP_EVM_SALT, &self.init_code())
    }
}

/// EIP-1014: the low 20 bytes of `keccak256(0xff ‖ deployer ‖ salt ‖ keccak256(init_code))`.
#[must_use]
pub fn create2_address(deployer: &[u8; 20], salt: &[u8; 32], init_code: &[u8]) -> [u8; 20] {
    let code_hash = keccak256(&[init_code]);
    let hash = keccak256(&[&[0xff], deployer, salt, &code_hash]);
    hash[12..].try_into().expect("20-byte address suffix")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::hashes::to_hex;

    #[test]
    fn deployment_matches_the_lock_and_binds_every_constructor_word() {
        let args = ConstructorArgsV1 {
            taira_network_id: [7; 32],
            consensus_instance: [8; 32],
            network: SccpNetworkV1::EthereumMainnet,
            route_revision: 1,
            max_wrapped_supply: 1000,
            pin: SccpCommitteePinV1 {
                generation: 2,
                committee_root: [3; 32],
                start_height: 4,
                until_ms: 5,
            },
        };
        assert_eq!(
            args.encode(),
            [
                [7; 32],
                [8; 32],
                word_u64(0x41),
                word_u64(1),
                word_u128(1000),
                word_u64(2),
                [3; 32],
                word_u64(4),
                word_u64(5)
            ]
            .concat()
        );
        let lock: norito::json::Value = norito::json::from_str(ARTIFACT_LOCK).unwrap();
        let contract = &lock["targets"]["evm"]["contracts"][CONTRACT];
        assert_eq!(
            format!("0x{}", to_hex(&SCCP_EVM_CREATION_CODE)),
            contract["creation_bytecode_hex"].as_str().unwrap()
        );
        assert_eq!(
            to_hex(&keccak256(&[&SCCP_EVM_CREATION_CODE])),
            contract["creation_bytecode_keccak256_hex"]
                .as_str()
                .unwrap()
        );
        let code = args.init_code();
        assert_eq!(
            &code[..SCCP_EVM_CREATION_CODE.len()],
            SCCP_EVM_CREATION_CODE.as_slice()
        );
        assert_eq!(&code[SCCP_EVM_CREATION_CODE.len()..], args.encode());
        assert_eq!(
            args.address(),
            create2_address(&SCCP_EVM_DEPLOYER, &SCCP_EVM_SALT, &code)
        );
        for index in 0..9 {
            let mut changed = code.clone();
            changed[SCCP_EVM_CREATION_CODE.len() + index * 32 + 31] ^= 1;
            assert_ne!(
                args.address(),
                create2_address(&SCCP_EVM_DEPLOYER, &SCCP_EVM_SALT, &changed)
            );
        }
    }

    #[test]
    fn create2_matches_eip1014_example_zero() {
        assert_eq!(
            to_hex(&create2_address(&[0; 20], &[0; 32], &[0])),
            "4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38"
        );
    }
}
