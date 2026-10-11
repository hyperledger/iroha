//! Source/charge shape checks for receipt-bearing canonical execution outputs.
//! These checks do not authenticate execution, a fee policy, or finality.

use super::{NexusFeeReceipt, NexusFeeSettlementV1};
use crate::{
    nexus::FeeDebitSource,
    transaction::{FeeChargeKind, TransactionEntrypoint},
};
use iroha_crypto::Hash;
use iroha_primitives::numeric::{Numeric, Quantity};

/// Hard portable bound on one actual Nexus receipt's canonical frame.
/// It includes the typed payer/program and every schedule field.
pub const MAX_NEXUS_FEE_RECEIPT_BYTES: usize = 16 * 1024;

impl NexusFeeReceipt {
    /// Bind public receipt structure to the exact network input and applying height.
    /// Consensus execution/finality must independently authenticate the charge.
    ///
    /// # Errors
    /// Rejects foreign source, payer/revision/caps, invalid arithmetic or oversized data.
    pub fn validate_for_network_input(
        &self,
        input: &TransactionEntrypoint,
        height: u64,
    ) -> Result<(), String> {
        let transaction = match input {
            TransactionEntrypoint::External(transaction) => transaction,
            TransactionEntrypoint::SealedReveal(reveal) => reveal.signed_transaction(),
            TransactionEntrypoint::SealedCommitment(_) => {
                return Err("Nexus receipt source has no executed signed payload".into());
            }
        };
        if self.version != Self::VERSION
            || self.source_id != *Hash::from(input.hash()).as_ref()
            || self.block_height != height
            || height == 0
            || self.fee_amount.is_zero()
            || self.lease_id.is_some()
            || self.settlement != NexusFeeSettlementV1::Burn
            || norito::canonical_frame_len(self).map_err(|error| error.to_string())?
                > MAX_NEXUS_FEE_RECEIPT_BYTES
        {
            return Err("Nexus receipt source, direct settlement or size differs".into());
        }
        let intent = transaction.fee_payment_intent();
        let selected = match intent.sponsor_program() {
            Some((program, revision)) => {
                self.debit_source == FeeDebitSource::SponsorProgram(program.clone())
                    && self.program_revision == Some(revision)
            }
            None => {
                self.debit_source == FeeDebitSource::Account(transaction.authority().clone())
                    && self.program_revision.is_none()
            }
        };
        let limit = intent
            .charge_limits()
            .iter()
            .find(|limit| limit.kind == FeeChargeKind::Nexus);
        if !selected
            || !limit.is_some_and(|limit| {
                limit.asset_definition_id == self.fee_asset_id
                    && limit.max_amount >= self.fee_amount
            })
            || self.schedule.tx_bytes_len
                != u64::try_from(
                    norito::canonical_frame_len(transaction.payload())
                        .map_err(|error| error.to_string())?,
                )
                .map_err(|_| "Nexus payload length exceeds u64")?
        {
            return Err("Nexus receipt differs from its original signed fee intent".into());
        }
        let mut amount = self.schedule.base_fee.clone();
        for (unit, count) in [
            (&self.schedule.per_byte_fee, self.schedule.tx_bytes_len),
            (
                &self.schedule.per_instruction_fee,
                self.schedule.instruction_count,
            ),
            (&self.schedule.per_gas_unit_fee, self.schedule.gas_used),
        ] {
            let component: Quantity = unit
                .try_mul_decimal(&Numeric::from(count))
                .map_err(|_| "Nexus receipt arithmetic exceeds numeric bounds")?;
            amount = amount
                .checked_add(&component)
                .map_err(|_| "Nexus receipt arithmetic exceeds numeric bounds")?;
        }
        if amount != self.fee_amount {
            return Err("Nexus receipt amount differs from actual schedule inputs".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        NetworkId,
        account::AccountId,
        block::{
            BlockHeader,
            execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
            output_budget::{
                ExecutionOutputBudget, ExecutionOutputLimits, ExecutionOutputPhaseReservation,
            },
        },
        nexus::FeeSponsorProgramId,
        transaction::{
            FeeChargeLimit, FeePaymentIntent, TransactionBuilder, TransactionResult,
            error::{TransactionLimitError, TransactionRejectionReason},
        },
    };
    use iroha_crypto::{Algorithm, HashOf, KeyPair};

    fn fixture(sponsored: bool) -> (TransactionEntrypoint, NexusFeeReceipt) {
        let key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
        let authority = AccountId::new(key.public_key().clone());
        let asset: crate::asset::AssetDefinitionId =
            "66owaQmAQMuHxPzxUN3bqZ6FJfDa".parse().unwrap();
        let limits = vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            asset.clone(),
            Quantity::from(10_u32),
        )];
        let program = FeeSponsorProgramId::new(authority.clone(), "receipt".parse().unwrap());
        let intent = if sponsored {
            FeePaymentIntent::sponsor(program.clone(), 7, limits, None)
        } else {
            FeePaymentIntent::authority(limits, None)
        };
        let network = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::new(b"public receipt fixture"),
        ));
        let mut builder = TransactionBuilder::new(network, authority.clone(), intent);
        builder.set_creation_time(std::time::Duration::from_millis(123));
        let signed = builder.sign(key.private_key());
        let bytes = norito::canonical_frame_len(signed.payload()).unwrap() as u64;
        let input = TransactionEntrypoint::External(signed);
        let receipt = NexusFeeReceipt {
            version: NexusFeeReceipt::VERSION,
            source_id: *Hash::from(input.hash()).as_ref(),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
            lane_id: iroha_model_base::topology::LaneId::new(1),
            block_height: 42,
            debit_source: if sponsored {
                FeeDebitSource::SponsorProgram(program)
            } else {
                FeeDebitSource::Account(authority)
            },
            fee_asset_id: asset,
            program_revision: sponsored.then_some(7),
            lease_id: None,
            fee_amount: Quantity::from(2_u32),
            settlement: NexusFeeSettlementV1::Burn,
            schedule: super::super::NexusFeeScheduleInputs {
                tx_bytes_len: bytes,
                instruction_count: 0,
                gas_used: 0,
                base_fee: Quantity::from(2_u32),
                per_byte_fee: Quantity::zero(),
                per_instruction_fee: Quantity::zero(),
                per_gas_unit_fee: Quantity::zero(),
            },
        };
        (input, receipt)
    }

    fn row(receipt: Option<NexusFeeReceipt>, reason_bytes: Option<usize>) -> ExecutionOutputV1 {
        let inner = reason_bytes.map_or_else(
            || Ok(Vec::new()),
            |bytes| {
                Err(TransactionRejectionReason::LimitCheck(
                    TransactionLimitError {
                        reason: "x".repeat(bytes),
                    },
                ))
            },
        );
        let mut result = TransactionResult::new(inner);
        result.set_nexus_fee_receipt(receipt);
        ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
            input_index: 0,
            result,
            completions: Vec::new(),
        })
    }

    #[test]
    fn actual_receipt_is_required_nullable_and_changes_the_result_leaf() {
        let (input, receipt) = fixture(false);
        let plain = row(None, None);
        let charged = row(Some(receipt), None);
        charged.validate_structure(42, &[input]).unwrap();
        assert_ne!(plain.result().hash(), charged.result().hash());
        assert_ne!(
            norito::encode_canonical(&plain).unwrap(),
            norito::encode_canonical(&charged).unwrap()
        );
        for row in [plain, charged] {
            let bytes = norito::encode_canonical(&row).unwrap();
            assert_eq!(
                norito::decode_canonical::<ExecutionOutputV1>(&bytes).unwrap(),
                row
            );
            let value = norito::json::to_value(row.result()).unwrap();
            assert_eq!(
                norito::json::from_value::<TransactionResult>(value.clone()).unwrap(),
                *row.result()
            );
            let mut omitted = value;
            omitted.as_object_mut().unwrap().remove("nexus_fee_receipt");
            assert!(norito::json::from_value::<TransactionResult>(omitted).is_err());
        }
    }

    #[test]
    fn canonical_result_without_nullable_receipt_slot_is_rejected() {
        #[derive(norito::NoritoSerialize, norito::NoritoSchema)]
        #[norito_schema(name = "iroha_data_model::transaction::signed::model::TransactionResult")]
        struct MissingReceiptSlot(
            crate::transaction::TransactionResultInner,
            Vec<crate::events::data::prelude::AssetBatchTransferOutcome>,
            crate::smart_contract::event::ContractEmissionsV1,
        );
        // The intentionally incomplete frame advertises the actual result identity.
        assert_eq!(
            norito::schema::identity::frame_hash::<MissingReceiptSlot>(),
            norito::schema::identity::frame_hash::<TransactionResult>(),
        );
        let bytes = norito::encode_canonical(&MissingReceiptSlot(
            Ok(Vec::new()),
            Vec::new(),
            crate::smart_contract::event::ContractEmissionsV1::default(),
        ))
        .unwrap();
        assert!(norito::decode_canonical::<TransactionResult>(&bytes).is_err());

        // Derive malformed bare payloads from successful same-type controls, so
        // neither a root-frame identity nor a checksum can explain rejection.
        let (_, receipt) = fixture(false);
        for output in [row(None, None), row(Some(receipt), None)] {
            let result = output.result();
            let flags = norito::core::default_encode_flags();
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let mut payload = Vec::new();
            let mut encoder = norito::core::Encoder::for_buffer(&mut payload);
            norito::SerializePayload::serialize(result, &mut encoder).unwrap();
            let (decoded, used) =
                norito::core::decode_field_canonical::<TransactionResult>(&payload).unwrap();
            assert_eq!(used, payload.len());
            assert_eq!(decoded, *result);

            let mut receipt_offset = 0;
            for _ in 0..2 {
                let (length, header) =
                    norito::core::read_len_from_slice_with_flags(&payload[receipt_offset..], flags)
                        .unwrap();
                receipt_offset += header + length;
            }
            let (length, header) =
                norito::core::read_len_from_slice_with_flags(&payload[receipt_offset..], flags)
                    .unwrap();
            assert!(length > 0, "the present Option must encode an explicit tag");
            let receipt_end = receipt_offset + header + length;
            let receipt_payload = &payload[receipt_offset + header..receipt_end];
            let (decoded_receipt, used) =
                norito::core::decode_field_canonical::<Option<NexusFeeReceipt>>(receipt_payload)
                    .unwrap();
            assert_eq!(used, receipt_payload.len());
            assert_eq!(decoded_receipt.as_ref(), result.nexus_fee_receipt());
            if result.nexus_fee_receipt().is_none() {
                assert_eq!(receipt_payload, &[0]);
            }

            // The required event field follows the receipt in the current tuple.
            // Keep it byte-for-byte in both mutations so only the receipt differs.
            let tail = &payload[receipt_end..];
            let (event_length, event_header) =
                norito::core::read_len_from_slice_with_flags(tail, flags).unwrap();
            assert_eq!(event_header + event_length, tail.len());
            let (events, used) = norito::core::decode_field_canonical::<
                crate::smart_contract::event::ContractEmissionsV1,
            >(&tail[event_header..])
            .unwrap();
            assert_eq!(used, event_length);
            assert_eq!(&events, result.contract_events());

            let mut missing_slot = payload[..receipt_offset].to_vec();
            missing_slot.extend_from_slice(tail);
            assert!(
                norito::core::decode_field_canonical::<TransactionResult>(&missing_slot).is_err()
            );
            let mut missing_option_tag = payload[..receipt_offset].to_vec();
            norito::core::write_len_to_vec_with_flags(&mut missing_option_tag, 0, flags);
            missing_option_tag.extend_from_slice(tail);
            assert!(
                norito::core::decode_field_canonical::<TransactionResult>(&missing_option_tag)
                    .is_err()
            );
        }
    }

    #[test]
    fn receipt_rejects_foreign_source_height_asset_revision_payer_amount_and_meter() {
        for sponsored in [false, true] {
            let (input, receipt) = fixture(sponsored);
            receipt.validate_for_network_input(&input, 42).unwrap();
            let mut variants = Vec::new();
            let mut changed = receipt.clone();
            changed.source_id[0] ^= 1;
            variants.push(changed);
            let mut changed = receipt.clone();
            changed.block_height += 1;
            variants.push(changed);
            let mut changed = receipt.clone();
            changed.program_revision = Some(8);
            variants.push(changed);
            let mut changed = receipt.clone();
            changed.lease_id = Some(Hash::new(b"unsupported lease"));
            variants.push(changed);
            let mut changed = receipt.clone();
            changed.fee_amount = Quantity::zero();
            variants.push(changed);
            let mut changed = receipt.clone();
            changed.fee_amount = Quantity::from(11_u32);
            variants.push(changed);
            let mut changed = receipt.clone();
            changed.schedule.tx_bytes_len += 1;
            variants.push(changed);
            let mut changed = receipt.clone();
            changed.schedule.base_fee = Quantity::from(3_u32);
            variants.push(changed);
            let mut changed = receipt.clone();
            changed.debit_source = FeeDebitSource::Account(AccountId::new(
                KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            ));
            variants.push(changed);
            let mut changed = receipt.clone();
            changed.fee_asset_id = crate::asset::AssetDefinitionId::derive_from_components(
                iroha_model_base::domain::DomainId::try_new("fee", "universal").unwrap(),
                "other".parse().unwrap(),
            );
            variants.push(changed);
            for variant in variants {
                assert!(variant.validate_for_network_input(&input, 42).is_err());
            }
        }
    }

    #[test]
    fn oversized_rejection_preserves_actual_charge_and_later_terminal_budget() {
        let (_, receipt) = fixture(false);
        let terminal = ExecutionOutputV1::network_output_limit_rejection(0);
        let unit = norito::canonical_frame_len(&terminal).unwrap() as u64;
        let maximum =
            norito::canonical_frame_len(&row(Some(receipt.clone()), Some(256))).unwrap() as u64;
        let limits = ExecutionOutputLimits {
            max_outputs: 2,
            max_output_bytes: maximum,
            max_total_output_bytes: maximum + unit,
            max_executed_wire_bytes: 1024 * 1024,
        };
        let mut budget = ExecutionOutputBudget::new(
            limits,
            [
                ExecutionOutputPhaseReservation {
                    count: 2,
                    terminal_bytes_per_output: unit,
                },
                ExecutionOutputPhaseReservation {
                    count: 0,
                    terminal_bytes_per_output: 0,
                },
                ExecutionOutputPhaseReservation {
                    count: 0,
                    terminal_bytes_per_output: 0,
                },
            ],
        )
        .unwrap();
        let retained = budget
            .begin(terminal.clone())
            .unwrap()
            .finish_network_rejection(row(Some(receipt.clone()), Some(32_768)))
            .unwrap();
        assert_eq!(retained.result().nexus_fee_receipt(), Some(&receipt));
        assert!(!retained.is_output_limit_rejection());
        assert!(norito::canonical_frame_len(&retained).unwrap() as u64 <= maximum);
        budget
            .begin(ExecutionOutputV1::network_output_limit_rejection(1))
            .unwrap()
            .finish(ExecutionOutputV1::network_output_limit_rejection(1))
            .unwrap();
        assert_eq!(budget.finish().unwrap().0, 2);
    }

    #[test]
    fn unfunded_paid_rejection_refuses_carrier_instead_of_losing_fee_evidence() {
        let (_, receipt) = fixture(false);
        let terminal = ExecutionOutputV1::network_output_limit_rejection(0);
        let unit = norito::canonical_frame_len(&terminal).unwrap() as u64;
        let limits = ExecutionOutputLimits {
            max_outputs: 1,
            max_output_bytes: unit,
            max_total_output_bytes: unit,
            max_executed_wire_bytes: 1024 * 1024,
        };
        let mut budget = ExecutionOutputBudget::new(
            limits,
            [
                ExecutionOutputPhaseReservation {
                    count: 1,
                    terminal_bytes_per_output: unit,
                },
                ExecutionOutputPhaseReservation {
                    count: 0,
                    terminal_bytes_per_output: 0,
                },
                ExecutionOutputPhaseReservation {
                    count: 0,
                    terminal_bytes_per_output: 0,
                },
            ],
        )
        .unwrap();
        assert!(
            budget
                .begin(terminal)
                .unwrap()
                .finish_network_rejection(row(Some(receipt), Some(32_768)))
                .is_err()
        );
        assert!(budget.finish().is_err());
    }
}
