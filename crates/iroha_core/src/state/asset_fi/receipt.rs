//! Immutable linked-FI occurrence capture inside the native movement boundary.
//!
//! These records use the existing transactional World storage owner. The frozen
//! output policy bounds encoding; it does not reserve receipt or whole-World
//! allocation. TODO: expose bounded certified historical reads and SDK verification
//! through the existing native proof owner before enabling application defunding.

use super::*;
use crate::executor::ContractRuntimeExecutionContext;
use iroha_data_model::{
    asset::{
        fi_link::{AssetFiTransferControllerV1, AssetFiTransferReceiptV1},
        uid::AssetUidPolicyV1,
    },
    isi::{InstructionBox, asset_fi::TransferToLinkedFiV1},
};

/// Source-owned admitted snapshots carried only with the private movement capability.
/// This value neither debits funds nor independently authorizes execution.
pub(crate) struct Capture {
    instruction: TransferToLinkedFiV1,
    instruction_hash: Hash,
    authority: AccountId,
    controller: Option<AssetFiTransferControllerV1>,
    fi: AssetFiV1,
    attestation: AssetFiLinkAttestationV1,
    link: AssetFiLinkV1,
    uid: [u8; 32],
    policy_revision: u64,
    policy_hash: Hash,
    asset_incarnation: iroha_data_model::nexus::AxtAssetIncarnationV1,
}

fn bounded_encoding<T: norito::NoritoSerialize>(value: &T, limit: u64) -> Result<Vec<u8>, Error> {
    let size = norito::canonical_frame_len(value)
        .map_err(|_| reject("cannot measure linked FI capture"))?;
    if u64::try_from(size).map_or(true, |size| size > limit) {
        return Err(reject(
            "linked FI capture exceeds the frozen encoding ceiling",
        ));
    }
    super::super::asset_uid::encode(value)
}

impl Capture {
    /// Retain the exact snapshots after the FI instruction's ordinary admission.
    pub(crate) fn admitted(
        tx: &StateTransaction<'_, '_>,
        instruction: &TransferToLinkedFiV1,
        authority: &AccountId,
        context: Option<&ContractRuntimeExecutionContext>,
        link: AssetFiLinkV1,
        policy: &AssetUidPolicyV1,
    ) -> Result<Self, Error> {
        let asset_incarnation = tx.world().axt_asset_incarnations()
            .get(&instruction.asset_definition_id).copied()
            .ok_or_else(|| reject("admitted FI capture requires its exact asset incarnation"))?;
        asset_incarnation.validate().map_err(|_| reject("admitted FI capture has an invalid asset incarnation"))?;
        let fi = fi(
            tx.world(),
            &instruction.asset_definition_id,
            &link.fi_account_id,
        )?
        .ok_or_else(|| reject("admitted FI capture lost its eligibility"))?;
        let attestation = attestation(
            tx.world(),
            &instruction.asset_definition_id,
            &instruction.account_id,
            &link.fi_account_id,
            &link.reference_digest,
        )?
        .ok_or_else(|| reject("admitted FI capture lost its attestation"))?;
        let controller = if authority == &instruction.account_id {
            None
        } else {
            let frame =
                context.ok_or_else(|| reject("FI capture requires its admitted contract frame"))?;
            Some(AssetFiTransferControllerV1 {
                address: frame.contract_address.clone(),
                subject: frame.contract_subject.clone(),
                entrypoint: frame.entrypoint.clone(),
            })
        };
        let ceiling = tx.fastpq_source_policy.1.max_output_bytes;
        let policy_hash = Hash::new(bounded_encoding(policy, ceiling)?);
        let instruction_hash = Hash::new(bounded_encoding(
            &InstructionBox::from(instruction.clone()),
            ceiling,
        )?);
        Ok(Self {
            instruction: instruction.clone(),
            instruction_hash,
            authority: authority.clone(),
            controller,
            fi,
            attestation,
            link,
            uid: policy.uid,
            policy_revision: policy.revision,
            policy_hash,
            asset_incarnation,
        })
    }

    /// Insert before debit within the existing prepared-occurrence callback.
    /// Any error must propagate out of that callback so its original poison and
    /// rollback owner refuses application of all provisional World writes.
    pub(crate) fn insert_before_movement(
        self,
        tx: &mut StateTransaction<'_, '_>,
        call: Hash,
        delta: &TransferDeltaTranscript,
    ) -> Result<(), Error> {
        if delta.from_account != self.instruction.account_id
            || delta.to_account != self.link.fi_account_id
            || delta.asset_definition != self.instruction.asset_definition_id
            || delta.amount != self.instruction.amount
        {
            return Err(reject(
                "linked FI capture differs from the prepared movement",
            ));
        }
        // The enclosing prepared-occurrence owner has flushed prior native fees
        // and reserved its exact transcript, but has not yet staged it.
        let transcript_index = tx.next_transfer_transcript_index(&call)?;
        let receipt = AssetFiTransferReceiptV1 {
            asset_incarnation: self.asset_incarnation,
            network: tx.network_id().clone(),
            execution_call_hash: call,
            instruction_hash: self.instruction_hash,
            instruction: self.instruction,
            authority: self.authority,
            controller: self.controller,
            fi: self.fi,
            attestation: self.attestation,
            link: self.link,
            uid: self.uid,
            uid_policy_revision: self.policy_revision,
            uid_policy_hash: self.policy_hash,
            execution_height: tx.block_height(),
            execution_time_ms: tx.block_unix_timestamp_ms(),
            transcript_index,
        };
        validate(&receipt)?;
        let key = key(
            &receipt.instruction.asset_definition_id,
            &receipt.instruction.account_id,
            &call,
            transcript_index,
        );
        if tx.world.smart_contract_state.get(&key).is_some() {
            return Err(reject("linked FI receipt occurrence is immutable"));
        }
        let bytes = bounded_encoding(&receipt, tx.fastpq_source_policy.1.max_output_bytes)?;
        // Ordinary World insert retains the original rollback checkpoints. There
        // is no fallible receipt write after the balance movement succeeds.
        tx.world.smart_contract_state.insert(key, bytes);
        Ok(())
    }
}

pub(crate) fn key(
    definition: &AssetDefinitionId,
    account: &AccountId,
    call: &Hash,
    index: u64,
) -> StatePath {
    let text = key_text(definition, &account.to_string(), call, index)
        .expect("fixed native FI occurrence path fits its stack buffer");
    let text = core::str::from_utf8(&text.get_ref()[..text.position() as usize])
        .expect("fixed native FI occurrence path is ASCII");
    path(text.to_owned())
}

/// One shared spelling; every formatting buffer is fixed and stack-owned.
fn key_text(
    definition: &AssetDefinitionId, account_text: &str, call: &Hash, index: u64,
) -> std::io::Result<std::io::Cursor<[u8; 256]>> {
    use std::io::Write as _;
    let mut definition_text = std::io::Cursor::new([0_u8; 64]);
    // AssetDefinitionId::Display also keeps its Base58 workspace on the stack.
    write!(&mut definition_text, "{definition}")?;
    let definition_hash = Hash::new(&definition_text.get_ref()[..definition_text.position() as usize]);
    let account_hash = Hash::new(account_text.as_bytes());
    let mut definition_hex = [0_u8; 64];
    let mut account_hex = [0_u8; 64];
    let mut call_hex = [0_u8; 64];
    hex::encode_to_slice(definition_hash.as_ref(), &mut definition_hex).expect("exact hash hex buffer");
    hex::encode_to_slice(account_hash.as_ref(), &mut account_hex).expect("exact hash hex buffer");
    hex::encode_to_slice(call.as_ref(), &mut call_hex).expect("exact hash hex buffer");
    let mut text = std::io::Cursor::new([0_u8; 256]);
    write!(&mut text, "{RECEIPT_ROOT}{}/{}/{}/{index}",
        core::str::from_utf8(&definition_hex).expect("hex ASCII"),
        core::str::from_utf8(&account_hex).expect("hex ASCII"),
        core::str::from_utf8(&call_hex).expect("hex ASCII"))?;
    Ok(text)
}

/// Exact key using caller-admitted canonical I105 text and the existing
/// fallible, resource-scoped StatePath owner. No external text enters this helper.
pub(crate) fn key_for_admission(
    definition: &AssetDefinitionId, account_text: &str, call: &Hash, index: u64,
) -> Result<StatePath, norito::json::Error> {
    let text = key_text(definition, account_text, call, index)
        .map_err(|_| norito::json::Error::Message("invalid fixed FI receipt key".into()))?;
    let text = core::str::from_utf8(&text.get_ref()[..text.position() as usize])
        .expect("fixed native FI occurrence path is ASCII");
    <StatePath as norito::json::JsonObjectKeyOwned>::from_json_key_text(text)
}

/// Internal historical consistency only; no current relationship may replace a snapshot.
pub(crate) fn validate(value: &AssetFiTransferReceiptV1) -> Result<(), Error> {
    validate_fields(value)?;
    if Hash::new(super::super::asset_uid::encode(&InstructionBox::from(value.instruction.clone()))?) != value.instruction_hash
        || value.controller.as_ref().is_some_and(|frame| frame.address.subject_id() != frame.subject)
    {
        return Err(reject("inconsistent linked FI instruction hash or controller subject"));
    }
    Ok(())
}

/// Allocation-free historical field relationships. Callers must separately check
/// the exact instruction hash and derive any actual controller subject.
pub(crate) fn validate_fields(value: &AssetFiTransferReceiptV1) -> Result<(), Error> {
    value.asset_incarnation.validate().map_err(|_| reject("invalid captured FI asset incarnation"))?;
    validate_link_shape(&value.link)?;
    let i = &value.instruction;
    let link = &value.link;
    if i.amount.is_zero()
        || i.expected_link_revision != link.revision
        || i.expected_policy_revision != value.uid_policy_revision
        || value.uid_policy_revision == 0
        || value.uid == [0; 32]
        || value.execution_height == 0
        || i.asset_definition_id != link.asset_definition_id
        || i.account_id != link.account_id
        || !link.enabled
        || !value.fi.enabled
        || !value.attestation.enabled
        || value.fi.asset_definition_id != i.asset_definition_id
        || value.fi.fi_account_id != link.fi_account_id
        || value.fi.revision != link.fi_revision
        || value.attestation.asset_definition_id != i.asset_definition_id
        || value.attestation.account_id != i.account_id
        || value.attestation.fi_account_id != link.fi_account_id
        || value.attestation.reference_digest != link.reference_digest
        || value.attestation.revision != link.attestation_revision
    {
        return Err(reject("inconsistent immutable linked FI execution receipt"));
    }
    match &value.controller {
        None if value.authority == i.account_id => {}
        Some(frame)
            if value.authority != i.account_id
                && link.waterfall
                && link.controller.as_ref() == Some(&frame.address)
                && frame.subject == value.authority
                && !frame.entrypoint.is_empty() => {}
        _ => {
            return Err(reject(
                "linked FI receipt has an inconsistent actual authority",
            ));
        }
    }
    Ok(())
}

pub(crate) fn read_record(
    world: &impl WorldReadOnly,
    record_key: &StatePath,
) -> Result<AssetFiTransferReceiptV1, Error> {
    let value: AssetFiTransferReceiptV1 =
        read(world, record_key)?.ok_or_else(|| reject("missing immutable linked FI receipt"))?;
    validate(&value)?;
    if record_key
        != &key(
            &value.instruction.asset_definition_id,
            &value.instruction.account_id,
            &value.execution_call_hash,
            value.transcript_index,
        )
    {
        return Err(reject(
            "linked FI receipt differs from its immutable occurrence key",
        ));
    }
    Ok(value)
}

pub(crate) fn referenced_accounts(value: &AssetFiTransferReceiptV1) -> Vec<AccountId> {
    let mut accounts = vec![
        value.instruction.account_id.clone(),
        value.fi.fi_account_id.clone(),
        value.authority.clone(),
    ];
    if let Some(controller) = &value.link.controller {
        accounts.push(controller.subject_id());
    }
    if let Some(controller) = &value.controller {
        accounts.push(controller.subject.clone());
    }
    accounts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fi_receipt_key_preserves_stored_spelling_and_local_decode_refusal() {
        let definition: AssetDefinitionId = "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().unwrap();
        let call = Hash::new("exact-FI-occurrence-key");
        for account in [iroha_test_samples::ALICE_ID.clone(), iroha_test_samples::BOB_ID.clone()] {
            let account_text = account.to_string();
            for index in [0, u64::MAX] {
                let expected = format!("{RECEIPT_ROOT}{}/{}/{}/{index}",
                    hex::encode(Hash::new(definition.to_string()).as_ref()),
                    hex::encode(Hash::new(&account_text).as_ref()), hex::encode(call.as_ref()));
                assert_eq!(key(&definition, &account, &call, index).as_ref(), expected);
                assert_eq!(key_for_admission(&definition, &account_text, &call, index).unwrap().as_ref(), expected);
            }
            let refused = norito::core::with_decode_limits_scope(norito::DecodeLimits::new(0,0,0,0,0), || {
                norito::core::classify_decode_attempt(|| key_for_admission(&definition, &account_text, &call, 0)
                    .map_err(norito::json::Error::into_core_error))
            });
            assert!(refused.unwrap_err().into_local_refusal().is_ok(), "the bounded key keeps the original local capacity owner");
        }
    }

    #[test]
    fn linked_fi_capture_encoding_accepts_exact_frame_limit_and_refuses_one_byte_less() {
        let value = vec![0xa5_u8; 41];
        let canonical = super::super::super::asset_uid::encode(&value).unwrap();
        let exact = u64::try_from(canonical.len()).unwrap();
        assert_eq!(
            bounded_encoding(&value, exact).unwrap(),
            canonical,
            "the ceiling covers the entire canonical frame, including its header",
        );
        let error = bounded_encoding(&value, exact.checked_sub(1).unwrap())
            .expect_err("one byte below the canonical frame must refuse before encoding");
        assert!(error.to_string().contains("frozen encoding ceiling"));
    }
}
