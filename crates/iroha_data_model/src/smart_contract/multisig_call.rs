//! Canonical platform-independent construction of one exact contract multisig call.
//!
//! Callers must independently authenticate the contract code/schema and approval
//! authority. Construction is not proof of deployment, authorization or finality.
//! Freeze a positive Propose creation timestamp before constructing or signing
//! the call. The exact attempt timestamp is part of the trigger instruction and
//! metadata. Retrying a retired attempt requires a fresh timestamp and fresh
//! consent; an Approve transaction retains the original proposal hash. Terminal
//! proposal identities and their original controller history are immutable.
use crate::{
    HasMetadata,
    account::AccountId,
    events::execute_trigger::ExecuteTriggerEventFilter,
    isi::{ExecuteTrigger, InstructionBox, Register, RegisterBox},
    smart_contract::{ContractAddress, ContractAlias},
    transaction::{
        Executable,
        executable::{ContractArgumentRecord, ContractInvocation},
    },
    trigger::{
        Trigger, TriggerId,
        action::{Action, Repeats},
    },
};
use iroha_crypto::{Hash, HashOf};
use iroha_model_base::{metadata::Metadata, name::Name};
use iroha_primitives::json::Json;
use std::{num::NonZeroU64, str::FromStr};

/// Native call material to be incorporated into the caller's complete signed transaction.
pub struct CanonicalMultisigContractCall {
    /// Exactly `RegisterTrigger` followed by `ExecuteTrigger`.
    pub instructions: Vec<InstructionBox>,
    /// Hash of the exact native instruction vector, including target, code and arguments.
    pub instructions_hash: HashOf<Vec<InstructionBox>>,
    /// Reserved metadata on the constructed trigger action.
    pub metadata: Metadata,
}

/// Construct trigger metadata without application-specific policy or event claims.
pub fn contract_call_metadata(
    address: &ContractAddress,
    code_hash: &Hash,
    alias: &ContractAlias,
    entrypoint: &str,
    payload: &Json,
    attempt_created_at_ms: NonZeroU64,
) -> Metadata {
    let mut metadata = Metadata::default();
    for (key, value) in [
        ("contract_address", Json::new(address.to_string())),
        ("contract_code_hash", Json::new(code_hash.to_string())),
    ] {
        metadata.insert(Name::from_str(key).expect("static metadata key"), value);
    }
    metadata.insert(
        Name::from_str("contract_alias").expect("static metadata key"),
        Json::new(alias.to_string()),
    );
    metadata.insert(
        Name::from_str("contract_entrypoint").expect("static metadata key"),
        Json::new(entrypoint.to_owned()),
    );
    metadata.insert(
        Name::from_str("contract_payload").expect("static metadata key"),
        payload.clone(),
    );
    metadata.insert(
        Name::from_str("contract_attempt_created_at_ms").expect("static metadata key"),
        Json::new(attempt_created_at_ms.get()),
    );
    metadata
}

/// Derive the sole current trigger identifier from typed, canonical native material.
/// Delimiter-separated text and serialization-error placeholders are not accepted.
///
/// # Errors
/// Returns an error if the typed material cannot be canonically encoded or the
/// derived trigger name is invalid.
pub fn derive_multisig_contract_call_trigger_id(
    authority: &AccountId,
    address: &ContractAddress,
    entrypoint: &str,
    payload: &Json,
    code_hash: &Hash,
    attempt_created_at_ms: NonZeroU64,
) -> Result<TriggerId, String> {
    derive_trigger_id_checked(
        authority,
        address,
        entrypoint,
        payload,
        code_hash,
        attempt_created_at_ms,
    )
    .map_err(|error| error.to_string())
}

fn derive_trigger_id_checked(
    authority: &AccountId,
    address: &ContractAddress,
    entrypoint: &str,
    payload: &Json,
    code_hash: &Hash,
    attempt_created_at_ms: NonZeroU64,
) -> Result<TriggerId, norito::Error> {
    let material = (
        authority.clone(),
        address.clone(),
        entrypoint.to_owned(),
        payload.clone(),
        *code_hash,
        attempt_created_at_ms.get(),
    );
    let wire = norito::encode_canonical(&material)?;
    let hash = Hash::new_from_chunks(&[b"iroha:multisig-contract-trigger:v2\0", &wire]);
    let name = Name::from_str(&format!("msig_cc_{}", hex::encode(hash.as_ref())))
        .map_err(|error| norito::Error::Message(error.to_string()))?;
    Ok(TriggerId::new(name))
}

/// Construct the exact current proposal from independently reviewed typed inputs.
/// No ledger I/O, signature, alias resolution, or application authority inference occurs.
/// The positive attempt timestamp must equal the frozen Propose transaction's
/// creation time. A fresh retry receives a distinct real instruction identity;
/// approvals continue to bind the original attempt's exact instruction hash.
///
/// # Errors
/// Rejects an empty, overlong, or whitespace-padded entrypoint, a payload that is
/// not a JSON object, or a failure to derive the trigger ID or construct its action.
#[expect(
    clippy::too_many_arguments,
    reason = "keep the independently reviewed signing inputs explicit at the canonical construction boundary"
)]
pub fn build_multisig_contract_call(
    authority: &AccountId,
    address: &ContractAddress,
    alias: &ContractAlias,
    entrypoint: &str,
    payload: &Json,
    arguments: Option<ContractArgumentRecord>,
    code_hash: &Hash,
    attempt_created_at_ms: NonZeroU64,
) -> Result<CanonicalMultisigContractCall, String> {
    if entrypoint.is_empty() || entrypoint.len() > 128 || entrypoint.trim() != entrypoint {
        return Err("exact bounded contract entrypoint required".to_owned());
    }
    if !matches!(
        payload.try_into_any_norito::<norito::json::Value>(),
        Ok(norito::json::Value::Object(_))
    ) {
        return Err("exact contract object payload required".to_owned());
    }
    let trigger_id = derive_multisig_contract_call_trigger_id(
        authority,
        address,
        entrypoint,
        payload,
        code_hash,
        attempt_created_at_ms,
    )?;
    let metadata = contract_call_metadata(
        address,
        code_hash,
        alias,
        entrypoint,
        payload,
        attempt_created_at_ms,
    );
    let invocation = ContractInvocation {
        contract_address: address.clone(),
        expected_code_hash: *code_hash,
        entrypoint: entrypoint.to_owned(),
        arguments,
    };
    let (trigger, execute) =
        contract_call_pair(authority, invocation, payload, trigger_id, metadata.clone())?;
    let instructions = vec![
        InstructionBox::from(Register::trigger(trigger)),
        InstructionBox::from(execute),
    ];
    Ok(CanonicalMultisigContractCall {
        instructions_hash: HashOf::new(&instructions),
        instructions,
        metadata,
    })
}

// The builder and recognizer share the typed action constructor. In particular,
// neither can accept arbitrary instructions in place of the ContractCall body.
fn contract_call_pair(
    authority: &AccountId,
    invocation: ContractInvocation,
    payload: &Json,
    trigger_id: TriggerId,
    metadata: Metadata,
) -> Result<(Trigger, ExecuteTrigger), String> {
    let action = Action::new(
        Executable::ContractCall(invocation),
        Repeats::Exactly(1),
        authority.clone(),
        ExecuteTriggerEventFilter::new().for_trigger(trigger_id.clone()),
    )
    .map_err(|error| error.to_string())?
    .with_metadata(metadata);
    let execute = ExecuteTrigger::new(trigger_id.clone()).with_args(payload.clone());
    Ok((Trigger::new(trigger_id, action), execute))
}

/// Typed contents of the exact canonical two-instruction contract envelope.
/// Recognition alone does not authenticate deployment, fees or execution authority.
#[derive(Debug)]
pub struct RecognizedMultisigContractCall {
    /// Canonical alias declared by the envelope, still requiring current world binding.
    pub alias: ContractAlias,
    /// Exact contract invocation, still requiring current address/code validation.
    pub invocation: ContractInvocation,
    /// Original positive Propose timestamp, to be joined to that signed transaction.
    pub attempt_created_at_ms: NonZeroU64,
}

/// Original local inspection failure; callers must not treat refusal as nonmatching policy.
#[derive(Debug)]
pub enum MultisigContractCallRecognitionError {
    /// The JSON reader could not complete within its active resource allowance.
    Json(norito::json::Error),
    /// Canonical trigger material could not be encoded or retained.
    Encoding(norito::Error),
}

fn read_recognition_json<T: norito::json::JsonDeserialize>(
    value: &Json,
) -> Result<Option<T>, MultisigContractCallRecognitionError> {
    match norito::json::from_str(value.get()) {
        Ok(value) => Ok(Some(value)),
        Err(error @ norito::json::Error::ScopedDecodeResource(_))
            if !cfg!(all(test, sumeragi_model_mutation = "DM20")) =>
        {
            Err(MultisigContractCallRecognitionError::Json(error))
        }
        Err(
            error @ (norito::json::Error::DecodeResourceLimit
            | norito::json::Error::DecodeResource(_)
            | norito::json::Error::AllocationFailed),
        ) => Err(MultisigContractCallRecognitionError::Json(error)),
        Err(_) => Ok(None),
    }
}

/// Recognize only the exact envelope emitted by [`build_multisig_contract_call`].
///
/// All six reserved metadata values, positive attempt timestamp, derived trigger
/// identity, exact action and execute payload are checked. Extra instructions or
/// metadata, nested native instructions and IVM executables are not recognized.
/// The whole typed pair is compared without `InstructionBox::eq` (which invokes
/// an infallible encoder) or `Trigger::eq` (which compares identifiers only).
///
/// # Errors
/// Preserves original JSON resource and canonical encoding failures so a caller
/// can defer local admission instead of recording an authoritative policy denial.
pub fn recognize_multisig_contract_call(
    authority: &AccountId,
    instructions: &[InstructionBox],
) -> Result<Option<RecognizedMultisigContractCall>, MultisigContractCallRecognitionError> {
    let [register, execute] = instructions else {
        return Ok(None);
    };
    let Some(RegisterBox::Trigger(register)) = register.as_any().downcast_ref::<RegisterBox>()
    else {
        return Ok(None);
    };
    let Some(execute) = execute.as_any().downcast_ref::<ExecuteTrigger>() else {
        return Ok(None);
    };
    let trigger = register.object();
    let Executable::ContractCall(invocation) = trigger.action().executable() else {
        return Ok(None);
    };
    let metadata = trigger.action().metadata();
    if metadata.iter().len() != 6
        || invocation.entrypoint.is_empty()
        || invocation.entrypoint.len() > 128
        || invocation.entrypoint.trim() != invocation.entrypoint
    {
        return Ok(None);
    }
    let field = |key: &str| {
        metadata
            .iter()
            .find_map(|(name, value)| (name.as_ref() == key).then_some(value))
    };
    let (Some(alias), Some(address), Some(code), Some(entrypoint), Some(payload), Some(attempt)) = (
        field("contract_alias"),
        field("contract_address"),
        field("contract_code_hash"),
        field("contract_entrypoint"),
        field("contract_payload"),
        field("contract_attempt_created_at_ms"),
    ) else {
        return Ok(None);
    };
    let Some(alias_literal) = read_recognition_json::<String>(alias)? else {
        return Ok(None);
    };
    let Ok(alias) = alias_literal.parse::<ContractAlias>() else {
        return Ok(None);
    };
    if alias.to_string() != alias_literal {
        return Ok(None);
    }
    let (Some(address), Some(code), Some(entrypoint), Some(attempt)) = (
        read_recognition_json::<String>(address)?,
        read_recognition_json::<String>(code)?,
        read_recognition_json::<String>(entrypoint)?,
        read_recognition_json::<u64>(attempt)?,
    ) else {
        return Ok(None);
    };
    let Some(attempt_created_at_ms) = NonZeroU64::new(attempt) else {
        return Ok(None);
    };
    if address != invocation.contract_address.to_string()
        || code != invocation.expected_code_hash.to_string()
        || entrypoint != invocation.entrypoint
        || payload != &execute.args
    {
        return Ok(None);
    }
    if !matches!(
        read_recognition_json::<norito::json::Value>(payload)?,
        Some(norito::json::Value::Object(_))
    ) {
        return Ok(None);
    }
    let trigger_id = derive_trigger_id_checked(
        authority,
        &invocation.contract_address,
        &invocation.entrypoint,
        payload,
        &invocation.expected_code_hash,
        attempt_created_at_ms,
    )
    .map_err(MultisigContractCallRecognitionError::Encoding)?;
    let metadata = metadata
        .try_clone_for_admission()
        .map_err(MultisigContractCallRecognitionError::Encoding)?;
    let Ok((expected_trigger, expected_execute)) =
        contract_call_pair(authority, invocation.clone(), payload, trigger_id, metadata)
    else {
        return Ok(None);
    };
    if trigger.id() != expected_trigger.id()
        || trigger.action() != expected_trigger.action()
        || execute != &expected_execute
    {
        return Ok(None);
    }
    Ok(Some(RecognizedMultisigContractCall {
        alias,
        invocation: invocation.clone(),
        attempt_created_at_ms,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::NetworkId;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_model_base::topology::DataSpaceId;
    fn fixture() -> (AccountId, ContractAddress, ContractAlias, Hash) {
        let key = KeyPair::try_from_seed(vec![7; 32], Algorithm::Ed25519).expect("fixture key");
        let owner = AccountId::new(key.public_key().clone());
        let network: NetworkId =
            "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
                .parse()
                .expect("network");
        let address =
            ContractAddress::derive(&network, &owner, 7, DataSpaceId::new(9)).expect("address");
        let alias = "reviewed_artifact::universal".parse().expect("alias");
        (owner, address, alias, Hash::new(b"reviewed-artifact"))
    }
    #[test]
    fn exact_call_binds_arguments_target_code_and_instruction_order() {
        let (owner, address, alias, code) = fixture();
        let payload = Json::new(norito::json!({"proposal_id":"case-1", "finalized_at_ms":12}));
        let build = |args, code| {
            build_multisig_contract_call(
                &owner,
                &address,
                &alias,
                "finalize_mint_request",
                &payload,
                Some(ContractArgumentRecord::try_new(args).expect("args")),
                code,
                NonZeroU64::new(1).unwrap(),
            )
            .expect("call")
        };
        let original = build(vec![1, 2, 3], &code);
        assert_ne!(
            original.instructions_hash,
            build(vec![1, 2, 4], &code).instructions_hash
        );
        assert_ne!(
            original.instructions_hash,
            build(vec![1, 2, 3], &Hash::new(b"different-artifact")).instructions_hash
        );
        let mut reordered = original.instructions.clone();
        reordered.reverse();
        assert_ne!(original.instructions_hash, HashOf::new(&reordered));
        assert_eq!(original.instructions.len(), 2);
        assert_eq!(
            original.metadata,
            contract_call_metadata(
                &address,
                &code,
                &alias,
                "finalize_mint_request",
                &payload,
                NonZeroU64::new(1).unwrap()
            )
        );
        assert!(
            build_multisig_contract_call(
                &owner,
                &address,
                &alias,
                "finalize_mint_request",
                &Json::new("scalar"),
                None,
                &code,
                NonZeroU64::new(1).unwrap(),
            )
            .is_err()
        );
    }
    #[test]
    fn entrypoint_and_payload_cannot_collide_through_text_delimiters() {
        let (owner, address, alias, code) = fixture();
        let first = derive_multisig_contract_call_trigger_id(
            &owner,
            &address,
            "a|b",
            &Json::new(norito::json!({"value":"c"})),
            &code,
            NonZeroU64::new(1).unwrap(),
        )
        .expect("first");
        let second = derive_multisig_contract_call_trigger_id(
            &owner,
            &address,
            "a",
            &Json::new(norito::json!({"value":"b|c"})),
            &code,
            NonZeroU64::new(1).unwrap(),
        )
        .expect("second");
        assert_ne!(first, second);
        assert!(
            build_multisig_contract_call(
                &owner,
                &address,
                &alias,
                " ",
                &Json::new(norito::json!({})),
                None,
                &code,
                NonZeroU64::new(1).unwrap(),
            )
            .is_err()
        );
    }
    #[test]
    fn frozen_propose_attempt_is_reproducible_and_retry_has_distinct_instruction_identity() {
        let (owner, address, alias, code) = fixture();
        let payload = Json::new(norito::json!({"proposal_id": "unchanged-economic-intent"}));
        let build = |attempt| {
            build_multisig_contract_call(
                &owner,
                &address,
                &alias,
                "finalize_mint_request",
                &payload,
                None,
                &code,
                NonZeroU64::new(attempt).unwrap(),
            )
            .unwrap()
        };
        let original = build(1_700_000_000_001);
        let reproduced = build(1_700_000_000_001);
        let retry = build(1_700_000_000_002);
        assert_eq!(original.instructions, reproduced.instructions);
        assert_eq!(original.metadata, reproduced.metadata);
        assert_eq!(original.instructions_hash, reproduced.instructions_hash);
        assert_ne!(original.instructions_hash, retry.instructions_hash);
        assert_ne!(original.instructions, retry.instructions);
        assert_eq!(
            original
                .metadata
                .get(&Name::from_str("contract_payload").unwrap()),
            retry
                .metadata
                .get(&Name::from_str("contract_payload").unwrap())
        );
        assert_eq!(
            original
                .metadata
                .get(&Name::from_str("contract_attempt_created_at_ms").unwrap()),
            Some(&Json::new(1_700_000_000_001_u64))
        );
        let retained_approval_hash = original.instructions_hash;
        assert_eq!(retained_approval_hash, reproduced.instructions_hash);
        assert_ne!(
            retained_approval_hash, retry.instructions_hash,
            "old consent cannot authorize a fresh attempt"
        );
    }
    fn recognition_fixture() -> (AccountId, CanonicalMultisigContractCall) {
        let (owner, address, alias, code) = fixture();
        let call = build_multisig_contract_call(
            &owner,
            &address,
            &alias,
            "issue_dpn",
            &Json::new(norito::json!({"invoice_id":"invoice-7"})),
            Some(ContractArgumentRecord::try_new(vec![1, 2, 3]).unwrap()),
            &code,
            NonZeroU64::new(1_700_000_000_001).unwrap(),
        )
        .unwrap();
        (owner, call)
    }

    fn replace_recognition_action(
        instructions: &mut [InstructionBox],
        change: impl FnOnce(&Trigger) -> Action,
    ) {
        let RegisterBox::Trigger(register) = instructions[0]
            .as_any()
            .downcast_ref::<RegisterBox>()
            .unwrap()
        else {
            panic!("fixture trigger")
        };
        let trigger = register.object();
        instructions[0] =
            Register::trigger(Trigger::new(trigger.id().clone(), change(trigger))).into();
    }

    #[test]
    fn canonical_recognition_roundtrips_the_exact_typed_pair() {
        let (owner, call) = recognition_fixture();
        let recognized = recognize_multisig_contract_call(&owner, &call.instructions)
            .unwrap()
            .unwrap();
        let (_, address, alias, code) = fixture();
        assert_eq!(recognized.alias, alias);
        assert_eq!(recognized.invocation.contract_address, address);
        assert_eq!(recognized.invocation.expected_code_hash, code);
        assert_eq!(recognized.invocation.entrypoint, "issue_dpn");
        assert_eq!(
            recognized.invocation.arguments.as_ref().unwrap().as_bytes(),
            &[1, 2, 3]
        );
        assert_eq!(recognized.attempt_created_at_ms.get(), 1_700_000_000_001);
        let encoded = norito::encode_canonical(&call.instructions).unwrap();
        let decoded = norito::decode_canonical::<Vec<InstructionBox>>(&encoded).unwrap();
        assert!(
            recognize_multisig_contract_call(&owner, &decoded)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn canonical_recognition_rejects_extra_reordered_and_wrong_execute_instructions() {
        let (owner, call) = recognition_fixture();
        for instructions in [
            Vec::new(),
            call.instructions[..1].to_vec(),
            vec![call.instructions[1].clone(), call.instructions[0].clone()],
            vec![
                call.instructions[0].clone(),
                call.instructions[1].clone(),
                call.instructions[1].clone(),
            ],
            vec![call.instructions[0].clone(), call.instructions[0].clone()],
        ] {
            assert!(
                recognize_multisig_contract_call(&owner, &instructions)
                    .unwrap()
                    .is_none()
            );
        }
        let mut instructions = call.instructions.clone();
        instructions[1] = ExecuteTrigger::new("unrelated_trigger".parse().unwrap())
            .with_args(Json::new(norito::json!({"invoice_id":"invoice-7"})))
            .into();
        assert!(
            recognize_multisig_contract_call(&owner, &instructions)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn canonical_recognition_rejects_metadata_changes_and_zero_or_malformed_attempt() {
        let (owner, call) = recognition_fixture();
        for (key, value) in [
            ("extra", Json::new(true)),
            ("contract_address", Json::new("different")),
            ("contract_code_hash", Json::new("different")),
            ("contract_entrypoint", Json::new("different")),
            ("contract_alias", Json::new(" invalid ")),
            ("contract_alias", Json::new(4)),
            (
                "contract_payload",
                Json::new(norito::json!({"invoice_id":"other"})),
            ),
            ("contract_attempt_created_at_ms", Json::new(0_u64)),
            ("contract_attempt_created_at_ms", Json::new("1700000000001")),
            (
                "contract_attempt_created_at_ms",
                Json::new(1_700_000_000_002_u64),
            ),
        ] {
            let mut instructions = call.instructions.clone();
            replace_recognition_action(&mut instructions, |trigger| {
                let mut metadata = trigger.action().metadata().clone();
                metadata.insert(key.parse().unwrap(), value);
                trigger.action().clone().with_metadata(metadata)
            });
            assert!(
                recognize_multisig_contract_call(&owner, &instructions)
                    .unwrap()
                    .is_none(),
                "{key}"
            );
        }
    }

    #[test]
    fn canonical_recognition_rejects_changed_action_despite_equal_trigger_identity() {
        let (owner, call) = recognition_fixture();
        let other = KeyPair::try_from_seed(vec![9; 32], Algorithm::Ed25519).unwrap();
        let other = AccountId::new(other.public_key().clone());
        assert!(
            recognize_multisig_contract_call(&other, &call.instructions)
                .unwrap()
                .is_none()
        );
        for repeats in [Repeats::Exactly(2), Repeats::Indefinitely] {
            let mut instructions = call.instructions.clone();
            replace_recognition_action(&mut instructions, |trigger| {
                Action::new(
                    trigger.action().executable().clone(),
                    repeats,
                    owner.clone(),
                    ExecuteTriggerEventFilter::new().for_trigger(trigger.id().clone()),
                )
                .unwrap()
                .with_metadata(trigger.action().metadata().clone())
            });
            assert!(
                recognize_multisig_contract_call(&owner, &instructions)
                    .unwrap()
                    .is_none()
            );
        }
        let mut instructions = call.instructions.clone();
        replace_recognition_action(&mut instructions, |trigger| {
            Action::new(
                trigger.action().executable().clone(),
                Repeats::Exactly(1),
                owner.clone(),
                ExecuteTriggerEventFilter::new().for_trigger("unrelated_trigger".parse().unwrap()),
            )
            .unwrap()
            .with_metadata(trigger.action().metadata().clone())
        });
        assert!(
            recognize_multisig_contract_call(&owner, &instructions)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn canonical_recognition_rejects_nested_native_and_ivm_executables() {
        let (owner, call) = recognition_fixture();
        for executable in [
            Executable::from(call.instructions.clone()),
            Executable::Ivm(crate::transaction::IvmBytecode::from_compiled(vec![
                1, 2, 3,
            ])),
        ] {
            let mut instructions = call.instructions.clone();
            replace_recognition_action(&mut instructions, |trigger| {
                Action::new(
                    executable,
                    Repeats::Exactly(1),
                    owner.clone(),
                    ExecuteTriggerEventFilter::new().for_trigger(trigger.id().clone()),
                )
                .unwrap()
                .with_metadata(trigger.action().metadata().clone())
            });
            assert!(
                recognize_multisig_contract_call(&owner, &instructions)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn canonical_recognition_preserves_original_scoped_refusal_and_same_envelope_retry() {
        use norito::core::{DecodeAttemptErrorKind, classify_decode_attempt};

        let (owner, call) = recognition_fixture();
        let original_wire = norito::encode_canonical(&call.instructions).unwrap();
        let original_pointer = call.instructions.as_ptr();
        let mut malformed = call.instructions.clone();
        replace_recognition_action(&mut malformed, |trigger| {
            let mut metadata = trigger.action().metadata().clone();
            metadata.insert("contract_alias".parse().unwrap(), Json::new(4));
            trigger.action().clone().with_metadata(metadata)
        });
        let pool = iroha_allocation::AllocationBudget::new(65_536);
        let original = norito::core::DecodeBudgetContext::try_new_owned(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX),
            &pool,
        )
        .unwrap();
        let baseline = pool.reserved_bytes();
        let mut observed = None;
        let refusal = original.with(|| {
            norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || {
                    classify_decode_attempt(|| {
                        match recognize_multisig_contract_call(&owner, &call.instructions) {
                            Err(MultisigContractCallRecognitionError::Json(error)) => {
                                let norito::json::Error::ScopedDecodeResource(origin) = &error else {
                                    panic!("the original observed JSON refusal must retain its scope");
                                };
                                observed = Some(origin.clone());
                                Err::<(), _>(error.into_core_error())
                            }
                            Err(MultisigContractCallRecognitionError::Encoding(error)) => {
                                panic!("the original refusal must remain JSON: {error}");
                            }
                            Ok(_) => panic!(
                                "a genuine scoped refusal must not become a nonmatching multisig envelope"
                            ),
                        }
                    })
                },
            )
        })
        .unwrap_err();
        assert_eq!(refusal.kind(), DecodeAttemptErrorKind::EnclosingLimit);
        let norito::Error::ScopedDecodeResource(returned) = refusal.into_error() else {
            panic!("recognition must return the original JSON observer identity");
        };
        let observed = observed.unwrap();
        assert_eq!(returned, observed);
        assert!(matches!(
            norito::Error::ScopedDecodeResource(returned.clone()).decode_resource_error(),
            Some(norito::core::DecodeResourceError::TotalAllocationExceeded {
                attempted,
                limit: 0,
            }) if attempted > 0
        ));
        drop(returned);
        drop(observed);
        assert_eq!(pool.reserved_bytes(), baseline);
        let recognized = original
            .with(|| recognize_multisig_contract_call(&owner, &call.instructions))
            .unwrap()
            .unwrap();
        let (_, address, alias, code) = fixture();
        assert_eq!(recognized.alias, alias);
        assert_eq!(recognized.invocation.contract_address, address);
        assert_eq!(recognized.invocation.expected_code_hash, code);
        assert_eq!(recognized.invocation.entrypoint, "issue_dpn");
        assert_eq!(recognized.attempt_created_at_ms.get(), 1_700_000_000_001);
        drop(recognized);
        assert_eq!(pool.reserved_bytes(), baseline);
        assert!(
            original
                .with(|| recognize_multisig_contract_call(&owner, &malformed))
                .unwrap()
                .is_none()
        );
        assert!(
            original
                .with(|| recognize_multisig_contract_call(&owner, &call.instructions[..1]))
                .unwrap()
                .is_none()
        );
        assert_eq!(call.instructions.as_ptr(), original_pointer);
        assert_eq!(
            norito::encode_canonical(&call.instructions).unwrap(),
            original_wire
        );
        drop(original);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn canonical_recognition_preserves_local_json_refusal() {
        let (owner, call) = recognition_fixture();
        let result = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || recognize_multisig_contract_call(&owner, &call.instructions),
        );
        assert!(matches!(
            result,
            Err(MultisigContractCallRecognitionError::Json(
                norito::json::Error::DecodeResource(
                    norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
                )
            ))
        ));
        assert!(
            recognize_multisig_contract_call(&owner, &call.instructions)
                .unwrap()
                .is_some()
        );
    }
}
