//! Authenticated native contract event definitions and committed emissions.

use iroha_crypto::Hash;
use iroha_model_base::name::Name;

use super::{
    ContractAddress,
    entrypoint::{
        EntrypointReturnRecordV1, EntrypointValueKindV1, EntrypointValueTypeNodeV1,
        EntrypointValueTypeV1, is_canonical_kotodama_identifier,
    },
};
use crate::account::AccountId;

mod custody;
pub use custody::{
    ContractEmissionAdmissionErrorV1, ContractEmissionsV1, PreparedContractEmissionsV1,
};

/// Maximum number of event definitions in one authenticated contract interface.
pub const MAX_CONTRACT_EVENT_DECLARATIONS_V1: usize = 256;
/// Maximum canonical framed size of the complete event declaration table.
pub const MAX_CONTRACT_EVENT_DECLARATION_BYTES_V1: usize = 64 * 1024;

/// One source-declared event and its complete public payload schema.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
    crate::DeriveFastJson,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::smart_contract::event::ContractEventDescriptorV1")]
#[norito(no_fast_from_json, deny_unknown_fields)]
pub struct ContractEventDescriptorV1 {
    /// Canonical source event name, unique within its declaring contract.
    pub name: Name,
    /// Named public struct whose qualified root identity ends with the event name.
    pub payload_type: EntrypointValueTypeV1,
}

impl ContractEventDescriptorV1 {
    /// Check the named public struct and every recursively contained value type.
    ///
    /// Arbitrary JSON and live state cursors are not durable event values. Empty
    /// structs are valid; all other canonical public schema limits still apply.
    #[must_use]
    pub fn validate(&self) -> bool {
        is_canonical_kotodama_identifier(self.name.as_ref())
            && self.payload_type.validate()
            && matches!(self.payload_type.nodes.first(),
                Some(EntrypointValueTypeNodeV1::Struct(node))
                    if node.name.rsplit_once("::").is_some_and(|(_, name)| name == self.name.as_ref()))
            && self.payload_type.nodes.iter().all(|node| {
                !matches!(
                    node,
                    EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Json)
                        | EntrypointValueTypeNodeV1::StateCursor(_)
                )
            })
    }
}

/// Validate the required sorted unique event table before admitting an artifact.
#[must_use]
pub fn validate_contract_event_table(events: &[ContractEventDescriptorV1]) -> bool {
    events.len() <= MAX_CONTRACT_EVENT_DECLARATIONS_V1
        && events.iter().all(ContractEventDescriptorV1::validate)
        && events.windows(2).all(|pair| pair[0].name < pair[1].name)
        && super::declaration_table::canonical_len(events)
            .is_ok_and(|bytes| bytes <= MAX_CONTRACT_EVENT_DECLARATION_BYTES_V1)
}

/// One committed native event with immutable host-authenticated provenance.
///
/// The definition is copied from the authenticated artifact, so readers need no
/// mutable registry lookup or retained artifact to interpret historical payloads.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    norito::Encode,
    norito::Decode,
    iroha_schema::IntoSchema,
    norito::NoritoSchema,
    crate::DeriveFastJson,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
)]
#[norito_schema(name = "iroha_data_model::smart_contract::event::ContractEmissionV1")]
#[norito(no_fast_from_json, deny_unknown_fields)]
pub struct ContractEmissionV1 {
    /// Deployed contract instance executing the emission.
    pub contract: ContractAddress,
    /// Complete authenticated artifact hash for the executing instance.
    pub code_hash: Hash,
    /// Ordinal in the authenticated entrypoint table.
    pub entrypoint: u32,
    /// Ordinal in the authenticated event declaration table.
    pub event: u32,
    /// Caller of this invocation, retained across nested execution boundaries.
    pub caller: AccountId,
    /// Host-copied immutable source declaration.
    pub definition: ContractEventDescriptorV1,
    /// Canonical schema-bound value captured from the guest's public value table.
    pub payload: EntrypointReturnRecordV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(
        name: &str,
        fields: &[&str],
        children: Vec<EntrypointValueTypeNodeV1>,
    ) -> ContractEventDescriptorV1 {
        let mut nodes = vec![EntrypointValueTypeNodeV1::Struct(
            super::super::entrypoint::EntrypointStructTypeNodeV1 {
                name: format!("Fixture::{name}"),
                fields: fields.iter().map(|field| (*field).to_owned()).collect(),
            },
        )];
        nodes.extend(children);
        ContractEventDescriptorV1 {
            name: name.parse().unwrap(),
            payload_type: EntrypointValueTypeV1 { nodes },
        }
    }

    #[test]
    fn event_table_requires_named_public_sorted_unique_structs() {
        let empty = descriptor("Accepted", &[], vec![]);
        assert!(empty.validate());
        assert!(validate_contract_event_table(&[]));
        assert!(validate_contract_event_table(std::slice::from_ref(&empty)));
        assert!(!validate_contract_event_table(&[
            empty.clone(),
            empty.clone()
        ]));
        let mut mismatched = empty.clone();
        mismatched.name = "Other".parse().unwrap();
        assert!(!mismatched.validate());
        let mut unqualified = empty.clone();
        let EntrypointValueTypeNodeV1::Struct(root) = &mut unqualified.payload_type.nodes[0] else {
            unreachable!()
        };
        root.name = "Accepted".to_owned();
        assert!(!unqualified.validate());
        for forbidden in [
            EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Json),
            EntrypointValueTypeNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)] }),
        ] {
            assert!(!descriptor("Accepted", &["value"], vec![forbidden]).validate());
        }
        let json = norito::json::to_json(&empty).unwrap();
        assert_eq!(
            norito::json::from_str::<ContractEventDescriptorV1>(&json).unwrap(),
            empty
        );
        let bytes = norito::encode_canonical(&empty).unwrap();
        assert_eq!(
            norito::decode_canonical::<ContractEventDescriptorV1>(&bytes).unwrap(),
            empty
        );
    }
}
