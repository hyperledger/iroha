//! Closed native/SCCP audit DATA display; transport decoding grants no authority.
use super::commands::{EvidenceCountArgs, EvidenceKindArg, EvidenceListArgs};
use crate::{CliOutputFormat, RunContext};
use eyre::Result;
use iroha::client::{
    SccpForgeryEvidenceAuditRecord, SumeragiEvidenceAuditRecord, SumeragiEvidencePenaltyStatus,
    SumeragiNativeEvidenceAuditRecord,
};

pub(crate) fn list<C: RunContext>(context: &mut C, args: EvidenceListArgs) -> Result<()> {
    let client = context.client_from_config()?;
    let filter = iroha::client::SumeragiEvidenceListFilter {
        limit: args.limit,
        offset: args.offset,
        kind: args.kind.map(EvidenceKindArg::into_client),
    };
    let response = client.get_sumeragi_evidence_list(filter)?;
    if matches!(context.output_format(), CliOutputFormat::Text) {
        context.println(format!("total={}", response.total))?;
        for (idx, item) in response.items.iter().enumerate() {
            context.println(format_evidence_summary(idx, item))?;
        }
    } else {
        context.print_data(&response)?;
    }
    Ok(())
}

pub(crate) fn count<C: RunContext>(context: &mut C, _args: EvidenceCountArgs) -> Result<()> {
    let client = context.client_from_config()?;
    let response = client.get_sumeragi_evidence_count()?;
    if matches!(context.output_format(), CliOutputFormat::Text) {
        context.println(format!("count={}", response.count))?;
    } else {
        context.print_data(&response)?;
    }
    Ok(())
}

fn format_evidence_summary(idx: usize, item: &SumeragiEvidenceAuditRecord) -> String {
    match item {
        SumeragiEvidenceAuditRecord::NativeSumeragiEvidence(native) => {
            format_native_evidence_summary(idx, native)
        }
        SumeragiEvidenceAuditRecord::SccpForgeryEvidence(forgery) => {
            format_sccp_evidence_summary(idx, forgery)
        }
    }
}

fn format_native_evidence_summary(idx: usize, item: &SumeragiNativeEvidenceAuditRecord) -> String {
    let ordinal = idx + 1;
    let (penalty_status, penalty_height) = match item.penalty_status {
        SumeragiEvidencePenaltyStatus::Pending => ("pending", None),
        SumeragiEvidencePenaltyStatus::Applied { height } => ("applied", Some(height)),
    };
    let offenders = item
        .offenders
        .iter()
        .map(|offender| format!("{}:{}", offender.signer, offender.peer_id))
        .collect::<Vec<_>>()
        .join(",");
    let mut summary = format!(
        "{ordinal}: kind=NativeSumeragiEvidence scope={:?} class={} instance={} height={} epoch={} context_id={} authority_generation={} offenders=[{offenders}] safety_violation={} native_frame_hash={} recorded_height={} recorded_view={} recorded_ms={} consensus_admitted_height={} penalty_status={penalty_status}",
        item.scope,
        item.class,
        item.instance,
        item.height,
        item.epoch,
        item.context_id,
        item.authority_generation,
        item.safety_violation,
        item.native_frame_hash,
        item.recorded_height,
        item.recorded_view,
        item.recorded_ms,
        item.consensus_admitted_height,
    );
    if let Some(height) = penalty_height {
        summary.push_str(&format!(" penalty_height={height}"));
    }
    summary
}

fn format_sccp_evidence_summary(idx: usize, item: &SccpForgeryEvidenceAuditRecord) -> String {
    let record = &item.record;
    let offenders = record
        .offenders
        .iter()
        .map(|offender| {
            format!(
                "{}:{}:{}:{}",
                offender.signer,
                offender.lane_id.as_u32(),
                offender.validator,
                offender.activation_height
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let (status, applied) = match item.penalty_status {
        SumeragiEvidencePenaltyStatus::Pending => ("pending", None),
        SumeragiEvidencePenaltyStatus::Applied { height } => ("applied", Some(height)),
    };
    let mut text = format!(
        "{}: kind=SccpForgeryEvidence data_only=true scope={:?} rule={:?} generation={} liability_start_height={} offenders=[{}] qc={} header={} aggregate_signature={} recorded_height={} recorded_view={} recorded_ms={} consensus_admitted_height={} penalty_status={}",
        idx + 1,
        item.attribution.scope,
        record.rule,
        record.generation,
        record.start_height,
        offenders,
        hex::encode(record.evidence.qc),
        hex::encode(record.evidence.header),
        hex::encode(record.evidence.aggregate_signature),
        item.recorded_height,
        item.recorded_view,
        item.recorded_ms,
        item.consensus_admitted_height,
        status
    );
    if let Some(anchor) = &record.evidence.anchor {
        text.push_str(&format!(
            " anchor_core_hash={} anchor_raw_result={} anchor_path=[{}]",
            hex::encode(anchor.core_hash),
            hex::encode(anchor.result),
            anchor
                .path
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>()
                .join(",")
        ));
    } else {
        text.push_str(" anchor=none");
    }
    if let Some(height) = applied {
        text.push_str(&format!(" penalty_height={height}"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(penalty_status: SumeragiEvidencePenaltyStatus) -> SumeragiEvidenceAuditRecord {
        SumeragiEvidenceAuditRecord::NativeSumeragiEvidence(SumeragiNativeEvidenceAuditRecord {
            scope: iroha::data_model::block::consensus::EvidenceScope::Root,
            class: iroha::client::SumeragiEvidenceClass::PhaseVote,
            height: 42,
            epoch: 1,
            context_id: iroha::client::SumeragiEvidenceHash::from_bytes([0xAA; 32]),
            instance: iroha::client::SumeragiEvidenceHash::from_bytes([0xBB; 32]),
            authority_generation: iroha::client::SumeragiEvidenceHash::from_bytes([0xCC; 32]),
            native_frame_hash: iroha::client::SumeragiEvidenceHash::from_bytes([0xDD; 32]),
            offenders: vec![iroha::client::SumeragiEvidenceOffender {
                signer: 3,
                peer_id: iroha_model_base::peer::PeerId::new(
                    iroha_crypto::KeyPair::try_from_seed(
                        vec![0x31; 32],
                        iroha_crypto::Algorithm::BlsNormal,
                    )
                    .expect("evidence offender key")
                    .public_key()
                    .clone(),
                ),
            }],
            safety_violation: false,
            recorded_height: 43,
            recorded_view: 8,
            recorded_ms: 1234,
            consensus_admitted_height: 43,
            penalty_status,
        })
    }

    // Syntax-only transport DATA: no signature or historical-authority acceptance is asserted.
    fn sccp_data_record() -> iroha::data_model::block::consensus::EvidenceRecord {
        use iroha::data_model::{
            account::AccountId,
            block::consensus::{
                EvidenceAttribution, EvidenceOffender, EvidencePenaltyStatus, EvidenceRecord,
                EvidenceScope, RecordedEvidenceV1,
            },
            isi::sccp::SubmitSccpForgeryEvidenceV1,
            sccp::native::{
                SccpAnchorWitnessV1, SccpForgeryOffenderV1, SccpForgeryRecordV1, SccpForgeryRuleV1,
            },
        };
        let key =
            iroha_crypto::KeyPair::try_from_seed(vec![43; 32], iroha_crypto::Algorithm::Ed25519)
                .unwrap();
        let peer =
            iroha_crypto::KeyPair::try_from_seed(vec![44; 32], iroha_crypto::Algorithm::BlsNormal)
                .unwrap();
        EvidenceRecord {
            evidence: RecordedEvidenceV1::SccpForgery(Box::new(SccpForgeryRecordV1 {
                evidence: SubmitSccpForgeryEvidenceV1 {
                    qc: [0xa1; 116],
                    header: [0xb2; 221],
                    aggregate_signature: [0xc3; 96],
                    anchor: Some(SccpAnchorWitnessV1 {
                        core_hash: [0; 32],
                        result: [0; 32],
                        path: [[7; 32]; 12],
                    }),
                },
                rule: SccpForgeryRuleV1::E4,
                generation: 7,
                start_height: 23,
                offenders: vec![SccpForgeryOffenderV1 {
                    signer: 0,
                    lane_id: iroha_model_base::topology::LaneId::new(1),
                    validator: AccountId::new(key.public_key().clone()),
                    activation_height: 19,
                }],
            })),
            attribution: EvidenceAttribution {
                scope: EvidenceScope::SccpGeneration { generation: 7 },
                instance: [1; 32],
                height: 23,
                epoch: 99,
                context_id: [2; 32],
                authority_generation: [3; 32],
                offenders: vec![EvidenceOffender {
                    signer: 0,
                    peer_id: iroha_model_base::peer::PeerId::new(peer.public_key().clone()),
                    lane_stake: None,
                }],
                safety_violation: false,
            },
            recorded_at_height: 42,
            recorded_at_view: 5,
            recorded_at_ms: 1234,
            penalty_status: EvidencePenaltyStatus::Pending,
        }
    }
    #[test]
    fn sccp_summary_retains_raw_certificate_and_liability_scope_without_claiming_verification() {
        let record = sccp_data_record();
        let iroha::data_model::block::consensus::RecordedEvidenceV1::SccpForgery(forgery) =
            record.evidence
        else {
            panic!("SCCP DATA")
        };
        let mut audit = SccpForgeryEvidenceAuditRecord {
            record: forgery,
            attribution: record.attribution,
            recorded_height: 42,
            recorded_view: 5,
            recorded_ms: 1234,
            consensus_admitted_height: 42,
            penalty_status: record.penalty_status,
        };
        let text = format_evidence_summary(
            2,
            &SumeragiEvidenceAuditRecord::SccpForgeryEvidence(audit.clone()),
        );
        for expected in [
            "3: kind=SccpForgeryEvidence",
            "data_only=true",
            "SccpGeneration",
            "generation=7",
            "liability_start_height=23",
            "rule=E4",
            "recorded_height=42",
            "penalty_status=pending",
        ] {
            assert!(text.contains(expected), "{expected}");
        }
        assert!(text.contains(&format!("qc={}", "a1".repeat(116))));
        assert!(text.contains(&format!("header={}", "b2".repeat(221))));
        assert!(text.contains(&format!("aggregate_signature={}", "c3".repeat(96))));
        assert!(text.contains(&format!("anchor_raw_result={}", "00".repeat(32))));
        assert!(!text.contains("native_frame_hash="));
        audit.record.evidence.anchor = None;
        audit.penalty_status = SumeragiEvidencePenaltyStatus::Applied { height: 50 };
        let text =
            format_evidence_summary(0, &SumeragiEvidenceAuditRecord::SccpForgeryEvidence(audit));
        assert!(text.contains("anchor=none"));
        assert!(text.contains("penalty_status=applied"));
        assert!(text.contains("penalty_height=50"));
    }
    #[test]
    fn format_evidence_summary_includes_every_typed_field_and_pending_status() {
        let summary = format_evidence_summary(0, &record(SumeragiEvidencePenaltyStatus::Pending));
        assert!(summary.contains("1: kind=NativeSumeragiEvidence"));
        assert!(summary.contains("scope=Root"));
        assert!(summary.contains("height=42"));
        assert!(summary.contains("recorded_view=8"));
        assert!(summary.contains("epoch=1"));
        assert!(summary.contains("offenders=[3:ea0130"));
        assert!(summary.contains("instance="));
        assert!(summary.contains("authority_generation="));
        assert!(summary.contains("safety_violation=false"));
        assert!(summary.contains("native_frame_hash="));
        assert!(summary.contains("class=phase_vote"));
        assert!(summary.contains("context_id="));
        assert!(summary.contains("consensus_admitted_height=43"));
        assert!(summary.contains("recorded_ms=1234"));
        assert!(summary.contains("penalty_status=pending"));
        assert!(!summary.contains("penalty_height="));
    }

    #[test]
    fn format_evidence_summary_uses_index_offset_and_terminal_penalty_height() {
        let summary = format_evidence_summary(
            5,
            &record(SumeragiEvidencePenaltyStatus::Applied { height: 44 }),
        );
        assert!(
            summary.starts_with("6: kind=NativeSumeragiEvidence"),
            "unexpected summary: {summary}"
        );
        assert!(summary.contains("penalty_status=applied"));
        assert!(summary.contains("penalty_height=44"));
    }
}
