//! Refusal, exact bytes and inherited depth for original State snapshot leaf writers.

use crate::{
    account::AccountId,
    parameter::{
        custom::{CustomParameter, CustomParameters},
        system::{
            BlockParameter, BlockParameters, Parameter, Parameters, SmartContractParameter,
            SmartContractParameters, SumeragiNposParameters, SumeragiParameter, SumeragiParameters,
            TransactionParameter, TransactionParameters,
        },
    },
    role::Role,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_primitives::json::Json;
use norito::json::{self, BoundedJsonError, JsonSerialize, JsonWriteSink};
use std::num::NonZeroU64;

const ORIGINAL_DEPTH: usize = 5;
struct OriginalSink {
    text: String,
    cap: usize,
    depth: usize,
    depth_ceiling: Option<usize>,
}
impl OriginalSink {
    fn new(cap: usize) -> Self {
        Self {
            text: String::new(),
            cap,
            depth: ORIGINAL_DEPTH,
            depth_ceiling: None,
        }
    }
}
impl JsonWriteSink for OriginalSink {
    fn push(&mut self, value: char) -> Result<(), BoundedJsonError> {
        self.push_str(value.encode_utf8(&mut [0; 4]))
    }
    fn push_str(&mut self, value: &str) -> Result<(), BoundedJsonError> {
        if self
            .text
            .len()
            .checked_add(value.len())
            .is_none_or(|n| n > self.cap)
        {
            return Err(BoundedJsonError::BodyTooLarge);
        }
        self.text.push_str(value);
        Ok(())
    }
    fn begin_container(&mut self) -> Result<(), BoundedJsonError> {
        let next = self
            .depth
            .checked_add(1)
            .ok_or(BoundedJsonError::Unsupported)?;
        if self.depth_ceiling.is_some_and(|ceiling| next > ceiling) {
            return Err(BoundedJsonError::Unsupported);
        }
        self.depth = next;
        Ok(())
    }
    fn end_container(&mut self) {
        assert!(
            self.depth > ORIGINAL_DEPTH,
            "a leaf cannot release an inherited level"
        );
        self.depth -= 1;
    }
}
fn audit_writer(
    expected: &str,
    write: impl Fn(&mut dyn JsonWriteSink) -> Result<(), BoundedJsonError>,
) {
    for cap in 0..expected.len() {
        let mut original = OriginalSink::new(cap);
        assert_eq!(write(&mut original), Err(BoundedJsonError::BodyTooLarge));
        assert_eq!(
            original.depth, ORIGINAL_DEPTH,
            "original State leaf byte refusal must restore its inherited depth at cap {cap}"
        );
        assert!(
            expected.starts_with(&original.text),
            "refusal keeps the exact canonical prefix"
        );
    }
    let mut original = OriginalSink::new(expected.len());
    assert_eq!(write(&mut original), Ok(()));
    assert_eq!(original.text, expected);
    assert_eq!(original.depth, ORIGINAL_DEPTH);
    let mut original = OriginalSink::new(usize::MAX);
    original.depth_ceiling = Some(ORIGINAL_DEPTH);
    assert_eq!(write(&mut original), Err(BoundedJsonError::Unsupported));
    assert!(original.text.is_empty());
    assert_eq!(original.depth, ORIGINAL_DEPTH);
}
fn audit(value: &impl JsonSerialize) {
    let pointer = std::ptr::from_ref(value);
    let expected = json::to_json(value).expect("sole ordinary original JSON bytes");
    audit_writer(&expected, |out| value.json_serialize_to(out));
    assert_eq!(std::ptr::from_ref(value), pointer);
}
fn custom() -> CustomParameter {
    CustomParameter::new("nested_limit".parse().unwrap(), Json::new(vec![1_u64, 2]))
}
fn grant_owner() -> AccountId {
    let key = KeyPair::from_seed(vec![0x73; 32], Algorithm::Ed25519);
    AccountId::new(key.public_key().clone())
}

#[test]
fn original_fixed_bytes_checked_refusals_preserve_depth_and_exact_bytes() {
    let values = [0_u8, 127, 255];
    let mut expected = String::new();
    crate::json_helpers::fixed_bytes::serialize(&values, &mut expected);
    audit_writer(&expected, |out| {
        crate::json_helpers::fixed_bytes::serialize_bounded(&values, out)
    });
}
#[test]
fn original_nested_fixed_bytes_checked_refusals_preserve_depth_and_exact_bytes() {
    let values = [[0_u8, 255], [17, 63]];
    let mut expected = String::new();
    crate::json_helpers::fixed_bytes::vec::serialize(&values, &mut expected);
    audit_writer(&expected, |out| {
        crate::json_helpers::fixed_bytes::vec::serialize_bounded(&values, out)
    });
    let mut original = OriginalSink::new(usize::MAX);
    original.depth_ceiling = Some(ORIGINAL_DEPTH + 1);
    assert_eq!(
        crate::json_helpers::fixed_bytes::vec::serialize_bounded(&values, &mut original),
        Err(BoundedJsonError::Unsupported)
    );
    assert_eq!(original.depth, ORIGINAL_DEPTH);
    assert_eq!(original.text, "[");
}
#[test]
fn original_custom_parameter_checked_refusals_preserve_depth_and_exact_bytes() {
    audit(&custom());
}
#[test]
fn original_custom_parameter_map_checked_refusals_preserve_depth_and_exact_bytes() {
    let parameter = custom();
    let mut values = CustomParameters::new();
    values.insert(crate::Identifiable::id(&parameter).clone(), parameter);
    let mut expected = String::new();
    crate::parameter::custom::json_helpers::serialize(&values, &mut expected);
    audit_writer(&expected, |out| {
        crate::parameter::custom::json_helpers::serialize_bounded(&values, out)
    });
}
#[test]
fn original_role_checked_refusals_preserve_depth_and_exact_bytes() {
    use crate::Registrable as _;
    let owner = grant_owner();
    let role = Role::new("bounded_role".parse().unwrap(), owner.clone()).build(&owner);
    audit(&role);
}
#[test]
fn original_new_role_checked_refusals_preserve_depth_and_exact_bytes() {
    audit(&Role::new(
        "bounded_new_role".parse().unwrap(),
        grant_owner(),
    ));
}
#[test]
fn original_npos_parameters_checked_refusals_preserve_depth_and_exact_bytes() {
    audit(&SumeragiNposParameters::default());
}
#[test]
fn original_parameter_checked_refusals_preserve_depth_and_exact_bytes() {
    for parameter in Parameters::default().parameters() {
        audit(&parameter);
    }
    audit(&Parameter::Custom(custom()));
}
#[test]
fn original_sumeragi_parameter_checked_refusals_preserve_depth_and_exact_bytes() {
    for parameter in SumeragiParameters::default().parameters() {
        audit(&parameter);
    }
    audit(&SumeragiParameter::MaxClockDriftMs(19));
}
#[test]
fn original_block_parameter_checked_refusals_preserve_depth_and_exact_bytes() {
    for parameter in BlockParameters::default().parameters() {
        audit(&parameter);
    }
    audit(&BlockParameter::MaxTransactions(
        NonZeroU64::new(7).unwrap(),
    ));
}
#[test]
fn original_transaction_parameter_checked_refusals_preserve_depth_and_exact_bytes() {
    for parameter in TransactionParameters::default().parameters() {
        audit(&parameter);
    }
    audit(&TransactionParameter::RequireSequence(true));
}
#[test]
fn original_smart_contract_parameter_checked_refusals_preserve_depth_and_exact_bytes() {
    for parameter in SmartContractParameters::default().parameters() {
        audit(&parameter);
    }
    audit(&SmartContractParameter::ExecutionDepth(3));
}
#[test]
fn original_sumeragi_parameters_checked_refusals_preserve_depth_and_exact_bytes() {
    audit(&SumeragiParameters::default());
}
#[test]
fn original_block_parameters_checked_refusals_preserve_depth_and_exact_bytes() {
    audit(&BlockParameters::default());
}
#[test]
fn original_transaction_parameters_checked_refusals_preserve_depth_and_exact_bytes() {
    audit(&TransactionParameters::default());
}
#[test]
fn original_smart_contract_parameters_checked_refusals_preserve_depth_and_exact_bytes() {
    audit(&SmartContractParameters::default());
}
#[test]
fn original_complete_parameter_leaf_checked_refusals_preserve_depth_and_exact_bytes() {
    let mut value = Parameters::default();
    value.set_parameter(Parameter::Custom(custom()));
    audit(&value);
}
