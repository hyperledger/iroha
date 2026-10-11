//! Canonical decoder for unsigned verifying-key transaction drafts.
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    confidential::ConfidentialStatus,
    isi::verifying_keys::{RegisterVerifyingKey, UpdateVerifyingKey},
    proof::{VerifyingKeyId, VerifyingKeyRecord},
    transaction::{Executable, TransactionBuilder},
};
use pyo3::{
    Bound, Py, PyResult, Python,
    exceptions::PyValueError,
    pyfunction,
    types::{PyBytes, PyDict, PyDictMethods},
};
use std::str::FromStr;
#[derive(Clone, Copy)]
enum VerifyingKeyOperation {
    Register,
    Update,
}
impl FromStr for VerifyingKeyOperation {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "register" => Ok(Self::Register),
            "update" => Ok(Self::Update),
            _ => Err("operation must be exactly `register` or `update`".to_owned()),
        }
    }
}
#[derive(Debug)]
struct DecodedVerifyingKeyInstruction {
    id: VerifyingKeyId,
    record: VerifyingKeyRecord,
}
fn decode_bound_verifying_key_instruction(
    payload: &[u8],
    expected_network: &NetworkId,
    expected_authority: &str,
    operation: VerifyingKeyOperation,
) -> Result<DecodedVerifyingKeyInstruction, String> {
    let parsed_expected_authority = AccountId::parse_encoded(expected_authority)
        .map_err(|error| format!("invalid requested authority: {error}"))?;
    if parsed_expected_authority.to_string() != expected_authority {
        return Err("requested authority must be exact canonical I105".to_owned());
    }
    let expected_authority = parsed_expected_authority;
    let builder = TransactionBuilder::decode_payload(payload)
        .map_err(|error| format!("invalid canonical transaction payload: {error}"))?;
    if builder.payload().network_id() != Some(expected_network) {
        return Err("transaction payload changed the configured network ID".to_owned());
    }
    if builder.payload().authority != expected_authority {
        return Err("transaction payload changed the requested authority".to_owned());
    }
    if builder.payload().attachments.is_some() {
        return Err(
            "verifying-key transaction payload must not contain proof attachments".to_owned(),
        );
    }
    let Executable::Instructions(instructions) = &builder.payload().instructions else {
        return Err(
            "verifying-key transaction payload must contain native instructions".to_owned(),
        );
    };
    if instructions.len() != 1 {
        return Err(
            "verifying-key transaction payload must contain exactly one instruction".to_owned(),
        );
    }
    match operation {
        VerifyingKeyOperation::Register => instructions[0]
            .as_any()
            .downcast_ref::<RegisterVerifyingKey>()
            .map(|instruction| DecodedVerifyingKeyInstruction {
                id: instruction.id.clone(),
                record: instruction.record.clone(),
            })
            .ok_or_else(|| {
                "verifying-key transaction payload must contain RegisterVerifyingKey".to_owned()
            }),
        VerifyingKeyOperation::Update => instructions[0]
            .as_any()
            .downcast_ref::<UpdateVerifyingKey>()
            .map(|instruction| DecodedVerifyingKeyInstruction {
                id: instruction.id.clone(),
                record: instruction.record.clone(),
            })
            .ok_or_else(|| {
                "verifying-key transaction payload must contain UpdateVerifyingKey".to_owned()
            }),
    }
}
fn set_optional_string(
    py: Python<'_>,
    mapping: &Bound<'_, PyDict>,
    key: &str,
    value: Option<String>,
) -> PyResult<()> {
    match value {
        Some(value) => mapping.set_item(key, value),
        None => mapping.set_item(key, py.None()),
    }
}
fn set_optional_u64(
    py: Python<'_>,
    mapping: &Bound<'_, PyDict>,
    key: &str,
    value: Option<u64>,
) -> PyResult<()> {
    match value {
        Some(value) => mapping.set_item(key, value),
        None => mapping.set_item(key, py.None()),
    }
}
fn record_to_python(py: Python<'_>, record: VerifyingKeyRecord) -> PyResult<Py<PyDict>> {
    let mapping = PyDict::new(py);
    mapping.set_item("version", record.version)?;
    mapping.set_item("circuit_id", record.circuit_id)?;
    set_optional_string(py, &mapping, "owner_manifest_id", record.owner_manifest_id)?;
    mapping.set_item("namespace", record.namespace)?;
    mapping.set_item("backend", record.backend.canonical_label())?;
    mapping.set_item("curve", record.curve)?;
    mapping.set_item(
        "public_inputs_schema_hash",
        PyBytes::new(py, &record.public_inputs_schema_hash),
    )?;
    mapping.set_item("commitment", PyBytes::new(py, &record.commitment))?;
    mapping.set_item("vk_len", record.vk_len)?;
    mapping.set_item("max_proof_bytes", record.max_proof_bytes)?;
    set_optional_string(py, &mapping, "gas_schedule_id", record.gas_schedule_id)?;
    set_optional_string(py, &mapping, "metadata_uri_cid", record.metadata_uri_cid)?;
    set_optional_string(py, &mapping, "vk_bytes_cid", record.vk_bytes_cid)?;
    set_optional_u64(py, &mapping, "activation_height", record.activation_height)?;
    set_optional_u64(py, &mapping, "withdraw_height", record.withdraw_height)?;
    if let Some(key) = record.key {
        let key_mapping = PyDict::new(py);
        key_mapping.set_item("backend", key.backend.as_str())?;
        key_mapping.set_item("bytes", PyBytes::new(py, &key.bytes))?;
        mapping.set_item("key", key_mapping)?;
    } else {
        mapping.set_item("key", py.None())?;
    }
    mapping.set_item(
        "status",
        match record.status {
            ConfidentialStatus::Proposed => "Proposed",
            ConfidentialStatus::Active => "Active",
            ConfidentialStatus::Withdrawn => "Withdrawn",
        },
    )?;
    Ok(mapping.unbind())
}
/// Decode one exact canonical unsigned VK transaction and bind its immutable
/// network, authority, and requested operation before returning registry data.
#[pyfunction]
#[pyo3(name = "decode_zk_vk_transaction_payload")]
pub(crate) fn decode_zk_vk_transaction_payload_py(
    py: Python<'_>,
    payload: &[u8],
    network_id: &super::PyNetworkId,
    expected_authority: &str,
    operation: &str,
) -> PyResult<Py<PyDict>> {
    let operation = operation
        .parse::<VerifyingKeyOperation>()
        .map_err(PyValueError::new_err)?;
    let decoded = decode_bound_verifying_key_instruction(
        payload,
        network_id.as_inner(),
        expected_authority,
        operation,
    )
    .map_err(PyValueError::new_err)?;
    let result = PyDict::new(py);
    let id = PyDict::new(py);
    id.set_item("backend", decoded.id.backend.as_str())?;
    id.set_item("name", decoded.id.name)?;
    result.set_item("id", id)?;
    result.set_item("record", record_to_python(py, decoded.record)?)?;
    Ok(result.unbind())
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
    use iroha_data_model::{
        block::BlockHeader, proof::VerifyingKeyBox, transaction::FeePaymentIntent, zk::BackendTag,
    };
    const CANONICAL_GENESIS_HASH: [u8; 32] = [0xA5; 32];
    fn network_id() -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed(CANONICAL_GENESIS_HASH),
        ))
    }
    fn authority(seed: u8) -> AccountId {
        let keypair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("valid deterministic key");
        AccountId::new(keypair.public_key().clone())
    }
    fn record() -> VerifyingKeyRecord {
        let mut record = VerifyingKeyRecord::new(
            1,
            "transfer-v1",
            BackendTag::NativePipaRPasta,
            "pasta",
            [0x11; 32],
            [0x22; 32],
        );
        record.vk_len = 3;
        record.max_proof_bytes = 4096;
        record.gas_schedule_id = Some("default".to_owned());
        record.key = Some(VerifyingKeyBox::new(
            "pipa-r/pasta".parse().expect("valid backend identifier"),
            vec![1, 2, 3],
        ));
        record.status = ConfidentialStatus::Active;
        record
    }
    fn register() -> RegisterVerifyingKey {
        RegisterVerifyingKey {
            id: VerifyingKeyId::new("pipa-r/pasta", "vk-transfer"),
            record: record(),
        }
    }
    fn update() -> UpdateVerifyingKey {
        UpdateVerifyingKey {
            id: VerifyingKeyId::new("pipa-r/pasta", "vk-transfer"),
            record: record(),
        }
    }
    fn payload(
        authority: AccountId,
        instructions: impl IntoIterator<Item = RegisterVerifyingKey>,
    ) -> Vec<u8> {
        TransactionBuilder::new(
            network_id(),
            authority,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(instructions)
        .encode_payload()
    }
    #[test]
    fn accepts_exact_canonical_bound_register_transaction() {
        let authority = authority(7);
        let bytes = payload(authority.clone(), [register()]);
        let decoded = decode_bound_verifying_key_instruction(
            &bytes,
            &network_id(),
            &authority.to_string(),
            VerifyingKeyOperation::Register,
        )
        .expect("valid draft");
        assert_eq!(decoded.id.name, "vk-transfer");
        assert_eq!(decoded.record, record());
    }
    #[test]
    fn accepts_exact_canonical_bound_update_transaction() {
        let authority = authority(7);
        let bytes = TransactionBuilder::new(
            network_id(),
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([update()])
        .encode_payload();
        let decoded = decode_bound_verifying_key_instruction(
            &bytes,
            &network_id(),
            &authority.to_string(),
            VerifyingKeyOperation::Update,
        )
        .expect("valid update draft");
        assert_eq!(decoded.id.name, "vk-transfer");
        assert_eq!(decoded.record, record());
    }
    #[test]
    fn rejects_wrong_network_authority_operation_and_instruction_count() {
        let expected_authority = authority(7);
        let bytes = payload(expected_authority.clone(), [register()]);
        let wrong_network = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xA7; 32])),
        );
        assert!(
            decode_bound_verifying_key_instruction(
                &bytes,
                &wrong_network,
                &expected_authority.to_string(),
                VerifyingKeyOperation::Register,
            )
            .unwrap_err()
            .contains("network ID")
        );
        assert!(
            decode_bound_verifying_key_instruction(
                &bytes,
                &network_id(),
                &format!(" {} ", expected_authority),
                VerifyingKeyOperation::Register,
            )
            .unwrap_err()
            .contains("invalid requested authority")
        );
        assert!(
            decode_bound_verifying_key_instruction(
                &bytes,
                &network_id(),
                &authority(8).to_string(),
                VerifyingKeyOperation::Register,
            )
            .unwrap_err()
            .contains("authority")
        );
        assert!(
            decode_bound_verifying_key_instruction(
                &bytes,
                &network_id(),
                &expected_authority.to_string(),
                VerifyingKeyOperation::Update,
            )
            .unwrap_err()
            .contains("UpdateVerifyingKey")
        );
        let extra = payload(expected_authority.clone(), [register(), register()]);
        assert!(
            decode_bound_verifying_key_instruction(
                &extra,
                &network_id(),
                &expected_authority.to_string(),
                VerifyingKeyOperation::Register,
            )
            .unwrap_err()
            .contains("exactly one")
        );
    }
    #[test]
    fn rejects_noncanonical_transaction_payload() {
        let authority = authority(7);
        let mut bytes = payload(authority.clone(), [register()]);
        bytes.push(0);
        assert!(
            decode_bound_verifying_key_instruction(
                &bytes,
                &network_id(),
                &authority.to_string(),
                VerifyingKeyOperation::Register,
            )
            .unwrap_err()
            .contains("canonical")
        );
    }
}
