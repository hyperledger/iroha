//! Runtime-upgrade wire interoperability authenticated by the canonical IVM ABI owner.

#[path = "../../iroha_data_model/tests/fixtures/abi_v1_hash.rs"]
mod abi_v1_fixture;

use iroha_data_model::{
    isi::governance::ProposeRuntimeUpgradeProposal, runtime::RuntimeUpgradeManifest,
};
use ivm_abi::{SyscallPolicy, syscalls::compute_abi_hash};
use norito::codec::{Decode, Encode};

#[test]
fn canonical_abi_v1_fixture_matches_the_owning_surface() {
    let current = compute_abi_hash(SyscallPolicy::AbiV1);
    assert_eq!(abi_v1_fixture::abi_v1_hash(), current);
    assert_eq!(hex::encode(current), abi_v1_fixture::ABI_V1_HASH_GOLDEN);
}

#[test]
fn runtime_upgrade_instruction_preserves_the_current_abi_v1_hash() {
    let current = compute_abi_hash(SyscallPolicy::AbiV1);
    let instruction = ProposeRuntimeUpgradeProposal {
        manifest: RuntimeUpgradeManifest {
            name: "runtime-upgrade".to_owned(),
            description: "canonical ABI wire interoperability".to_owned(),
            abi_version: 1,
            abi_hash: current,
            added_syscalls: Vec::new(),
            added_pointer_types: Vec::new(),
            start_height: 100,
            end_height: 200,
            sbom_digests: Vec::new(),
            slsa_attestation: Vec::new(),
            provenance: Vec::new(),
        },
    };
    let encoded = instruction.encode();
    let mut input = encoded.as_slice();
    let decoded = ProposeRuntimeUpgradeProposal::decode(&mut input)
        .expect("decode current ABI-v1 runtime-upgrade instruction");
    assert!(
        input.is_empty(),
        "consume the complete original instruction"
    );
    assert_eq!(decoded.manifest.abi_hash, abi_v1_fixture::abi_v1_hash());
    assert_eq!(decoded.manifest.abi_hash, current);
    assert_eq!(decoded, instruction);
}
