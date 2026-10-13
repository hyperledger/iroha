//! Every coordinator operation has the same authenticated global execution owner.

use super::*;
use iroha_data_model::{
    isi::sumeragi_amx::{
        BeginAmxV1, RegisterAmxDataspaceV1, RelayAmxHandoffV1, RelayAmxPreparedV1,
    },
    sumeragi_amx::{
        AmxCertifiedBlockV1, AmxHandoffProofV1, AmxLegV1, AmxPreparedV1, AmxRecordProofV1,
        AmxRecordV1, AmxTransactionV1, AmxVoteV1, AmxWriteProofV1,
    },
};

#[test]
fn every_amx_coordinator_instruction_rejects_private_execution_before_proof_decoding() {
    let (state, ds) = private_state();
    let mut block = state.block(header(2));
    let mut tx = block.transaction();
    bind_scope(&mut tx, ds);
    // Intentionally undecodable certificates establish that role rejection precedes
    // proof parsing. The signed-genesis test separately exercises genuine authority.
    let certificate = AmxCertifiedBlockV1 {
        consensus_header: Vec::new(),
        commit_qc: Vec::new(),
        result_preimage: Vec::new(),
    };
    let instructions: [InstructionBox; 4] = [
        RegisterAmxDataspaceV1 {
            dataspace: ds,
            instance: [1; 32],
            anchor: Vec::new(),
        }
        .into(),
        BeginAmxV1 {
            transaction: AmxTransactionV1 {
                legs: [21, 22]
                    .into_iter()
                    .map(|id| AmxLegV1 {
                        dataspace: DataSpaceId::new(id),
                        payload: vec![1],
                    })
                    .collect(),
                deadline: 8,
                expires_at_ms: 1_000_000,
                nonce: [2; 32],
            },
        }
        .into(),
        RelayAmxPreparedV1 {
            proof: AmxRecordProofV1 {
                block: certificate.clone(),
                record: AmxRecordV1::Prepared(AmxPreparedV1 {
                    tx: [3; 32],
                    participant: ds,
                    vote: AmxVoteV1::No,
                }),
                write: AmxWriteProofV1 {
                    present: [0; 32],
                    siblings: Vec::new(),
                },
            },
        }
        .into(),
        RelayAmxHandoffV1 {
            dataspace: ds,
            proof: AmxHandoffProofV1 { block: certificate },
        }
        .into(),
    ];
    let before = tx.world.sumeragi_amx.get().clone();
    for instruction in instructions {
        let expected = "AMX coordinator requires the authenticated global root";
        let result = Executor::Initial.execute_instruction(&mut tx, &ALICE_ID, instruction.clone());
        assert!(matches!(result, Err(ValidationFail::NotPermitted(reason)) if reason == expected));
        let result = Executor::Initial.execute_borrowed_overlay_instruction(
            &mut tx,
            &ALICE_ID,
            &instruction,
            None,
        );
        assert!(matches!(result, Err(ValidationFail::NotPermitted(reason)) if reason == expected));
        let error = instruction.execute(&ALICE_ID, &mut tx).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(tx.world.sumeragi_amx.get(), &before);
        assert!(tx.require_storage_admission().is_ok());
    }
}
