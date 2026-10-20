//! Typed construction of an isolated, retryable scheduled contract invocation.
//!
//! A trigger's direct ContractCall executable binds arguments from its event.
//! A scheduled time event has no business argument record. The explicit Batch
//! form instead owns one exact invocation, which is validated against the live
//! pinned code and canonical ABI on each firing.

use super::*;
use iroha_data_model::{
    smart_contract::entrypoint::EntrypointArgumentRecordV1, trigger::action::TimeTriggerRetryPolicy,
};

pub(super) struct ScheduledContractCall<'a> {
    pub trigger_id: &'a str,
    pub authority: AccountId,
    pub contract_address: &'a str,
    pub expected_code_hash_hex: &'a str,
    pub entrypoint: &'a str,
    pub arguments: &'a [u8],
    pub start_ms: u64,
    pub period_ms: u64,
    pub max_retries: u32,
    pub retry_after_ms: u64,
}

pub(super) fn positive_u64(value: &Bound<'_, PyAny>) -> PyResult<u64> {
    if !value.is_exact_instance_of::<pyo3::types::PyInt>() {
        return Err(PyTypeError::new_err(
            "schedule fields must be exact integers",
        ));
    }
    value
        .extract::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| PyValueError::new_err("schedule fields must be positive u64 integers"))
}

pub(super) fn positive_u32(value: &Bound<'_, PyAny>) -> PyResult<u32> {
    u32::try_from(positive_u64(value)?)
        .map_err(|_| PyValueError::new_err("max_retries must be a positive u32 integer"))
}

pub(super) fn build(input: ScheduledContractCall<'_>) -> Result<InstructionBox, String> {
    let trigger_id: TriggerId = input.trigger_id.parse().map_err(|e| format!("{e}"))?;
    let address: ContractAddress = input.contract_address.parse().map_err(|e| format!("{e}"))?;
    if address.to_string() != input.contract_address {
        return Err("contract_address must be canonical".into());
    }
    if input.expected_code_hash_hex.len() != 64
        || !input
            .expected_code_hash_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected_code_hash_hex must be lowercase 32-byte hex".into());
    }
    let code_hash: Hash = input
        .expected_code_hash_hex
        .parse()
        .map_err(|e| format!("{e}"))?;
    if hex_encode(code_hash.as_ref()) != input.expected_code_hash_hex {
        return Err("expected_code_hash_hex must preserve the exact native hash".into());
    }
    if input.entrypoint.is_empty()
        || input.entrypoint.trim() != input.entrypoint
        || input.entrypoint.len() > 255
    {
        return Err("entrypoint must contain 1..255 unpadded UTF-8 bytes".into());
    }
    if input.arguments.is_empty() || input.arguments.len() > MAX_CONTRACT_ARGUMENT_RECORD_BYTES {
        return Err("arguments must contain a bounded canonical argument record".into());
    }
    // Structural validation here never asserts schema or live permission. Those
    // checks belong to the pinned deployed contract during native execution.
    let _: EntrypointArgumentRecordV1 = norito::decode_canonical_for_admission(
        input.arguments,
        norito::canonical_decode_limits(input.arguments.len()),
    )
    .map_err(|e| format!("invalid canonical argument record: {e}"))?;
    if input.start_ms == 0 {
        return Err("start_ms must be greater than zero".into());
    }
    let period = NonZeroU64::new(input.period_ms).ok_or("period_ms must be greater than zero")?;
    let max_retries =
        NonZeroU32::new(input.max_retries).ok_or("max_retries must be greater than zero")?;
    let retry_after_ms =
        NonZeroU64::new(input.retry_after_ms).ok_or("retry_after_ms must be greater than zero")?;
    let arguments =
        ContractArgumentRecord::try_new(input.arguments.to_vec()).map_err(|e| e.to_string())?;
    let executable = Executable::Batch(
        vec![ExecutableBatchItem::ContractCall(ContractInvocation {
            contract_address: address,
            expected_code_hash: code_hash,
            entrypoint: input.entrypoint.to_owned(),
            arguments: Some(arguments),
        })]
        .into(),
    );
    let action = TriggerAction::new(
        executable,
        Repeats::Exactly(1),
        input.authority,
        TimeEventFilter::new(ExecutionTime::Schedule(
            TimeSchedule::starting_at(Duration::from_millis(input.start_ms))
                .with_period(Duration::from_millis(period.get())),
        )),
    )
    .map_err(|e| e.to_string())?
    .with_retry_policy(TimeTriggerRetryPolicy {
        max_retries,
        retry_after_ms,
    })
    .map_err(|e| e.to_string())?;
    Ok(Register::trigger(Trigger::new(trigger_id, action)).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{isi::RegisterBox, smart_contract::entrypoint::EntrypointValueAtomV1};

    fn fixture_arguments() -> Vec<u8> {
        norito::to_bytes(&EntrypointArgumentRecordV1 {
            schema_hash: [7; 32],
            atoms: vec![EntrypointValueAtomV1::Unit],
        })
        .expect("encode canonical fixture arguments")
    }

    fn fixture<'a>(arguments: &'a [u8]) -> ScheduledContractCall<'a> {
        let key = KeyPair::from_seed(vec![0x71; 32], Algorithm::Ed25519);
        ScheduledContractCall {
            trigger_id: "scheduled_payment",
            authority: AccountId::new(key.public_key().clone()),
            contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh",
            expected_code_hash_hex: "0101010101010101010101010101010101010101010101010101010101010101",
            entrypoint: "execute_scheduled_payment",
            arguments,
            start_ms: 10_000,
            period_ms: 5_000,
            max_retries: 3,
            retry_after_ms: 5_000,
        }
    }

    #[test]
    fn scheduled_call_preserves_one_exact_invocation_and_native_retry_policy() {
        let arguments = fixture_arguments();
        let instruction = build(fixture(&arguments)).expect("build native trigger");
        let register = instruction
            .as_any()
            .downcast_ref::<RegisterBox>()
            .expect("register family");
        let RegisterBox::Trigger(register) = register else {
            panic!("expected trigger registration");
        };
        let action = register.object.action();
        assert_eq!(action.repeats(), Repeats::Exactly(1));
        assert_eq!(
            action
                .retry_policy()
                .expect("bounded retry")
                .max_retries
                .get(),
            3
        );
        let Executable::Batch(items) = action.executable() else {
            panic!("fixed arguments need explicit batch");
        };
        assert_eq!(items.len(), 1);
        let ExecutableBatchItem::ContractCall(call) = &items[0] else {
            panic!("expected contract call");
        };
        assert_eq!(
            call.arguments.as_ref().expect("arguments").as_ref(),
            arguments
        );
        assert_eq!(call.entrypoint, "execute_scheduled_payment");
        let wire = norito::to_bytes(&instruction).expect("encode instruction");
        let decoded: InstructionBox = norito::decode_canonical(&wire).expect("round trip");
        assert_eq!(norito::to_bytes(&decoded).unwrap(), wire);
    }

    #[test]
    fn scheduled_call_rejects_malformed_or_unbounded_inputs() {
        let arguments = fixture_arguments();
        for bytes in [&[][..], &[1, 2, 3][..]] {
            assert!(build(fixture(bytes)).is_err());
        }
        let mut trailing = arguments.clone();
        trailing.push(0);
        assert!(build(fixture(&trailing)).is_err());
        for field in ["start", "period", "retries", "retry_after"] {
            let mut input = fixture(&arguments);
            match field {
                "start" => input.start_ms = 0,
                "period" => input.period_ms = 0,
                "retries" => input.max_retries = 0,
                _ => input.retry_after_ms = 0,
            }
            assert!(build(input).is_err(), "{field}");
        }
        let mut input = fixture(&arguments);
        input.entrypoint = " execute_scheduled_payment ";
        assert!(build(input).is_err());
        let mut input = fixture(&arguments);
        input.expected_code_hash_hex = "0x01";
        assert!(build(input).is_err());
    }

    #[test]
    fn schedule_integer_extractors_reject_bool_float_zero_and_overflow() {
        Python::initialize();
        Python::attach(|py| {
            let values = PyDict::new(py);
            values.set_item("valid", 3_u64).unwrap();
            values.set_item("zero", 0_u64).unwrap();
            values.set_item("negative", -1_i64).unwrap();
            values.set_item("bool", true).unwrap();
            values.set_item("float", 3.0).unwrap();
            values.set_item("wide", u64::from(u32::MAX) + 1).unwrap();
            assert_eq!(
                positive_u64(&values.get_item("valid").unwrap().unwrap()).unwrap(),
                3
            );
            assert_eq!(
                positive_u32(&values.get_item("valid").unwrap().unwrap()).unwrap(),
                3
            );
            for key in ["zero", "negative", "bool", "float"] {
                assert!(
                    positive_u64(&values.get_item(key).unwrap().unwrap()).is_err(),
                    "{key}"
                );
                assert!(
                    positive_u32(&values.get_item(key).unwrap().unwrap()).is_err(),
                    "{key}"
                );
            }
            assert!(positive_u32(&values.get_item("wide").unwrap().unwrap()).is_err());
        });
    }
}
