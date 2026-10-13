//! Finalized-state adapter for the production SFM-4b3 evidence viewer.
use iroha_core::{
    smartcontracts::ValidSingularQuery,
    state::{State, StateReadOnly, WorldReadOnly},
};
use iroha_data_model::{
    account::AccountId, query::sorafs::prelude::FindSorafsModerationCase, role::RoleId,
    sorafs::moderation_ledger::ModerationCaseStatusV1,
};
use sorafs_node::evidence_viewer::{
    EvidenceViewerAuthorizationErrorV1, EvidenceViewerFinalizedAuthorizationReaderV1,
    EvidenceViewerFinalizedAuthorizationV1, EvidenceViewerRoleV1,
};
use std::{fmt, sync::Arc};
const EVIDENCE_AUDITOR_ROLE_V1: &str = "sorafs_evidence_auditor";
const LEGAL_REVIEWER_ROLE_V1: &str = "sorafs_legal_reviewer";
/// Reads one exact case, role assignment, and finalized block anchor from a
/// single immutable state view.
pub struct ToriiEvidenceViewerFinalizedAuthorizationReaderV1 {
    state: Arc<State>,
    auditor_role: RoleId,
    legal_role: RoleId,
}
impl fmt::Debug for ToriiEvidenceViewerFinalizedAuthorizationReaderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToriiEvidenceViewerFinalizedAuthorizationReaderV1")
            .field("state", &"<authoritative-finalized-state>")
            .field("auditor_role", &self.auditor_role)
            .field("legal_role", &self.legal_role)
            .finish()
    }
}
impl ToriiEvidenceViewerFinalizedAuthorizationReaderV1 {
    /// Construct the reader with the fixed V1 explicit role identifiers.
    pub(crate) fn new(state: Arc<State>) -> Self {
        Self {
            state,
            auditor_role: EVIDENCE_AUDITOR_ROLE_V1
                .parse()
                .expect("SoraFS evidence auditor role id is valid"),
            legal_role: LEGAL_REVIEWER_ROLE_V1
                .parse()
                .expect("SoraFS legal reviewer role id is valid"),
        }
    }
}
impl EvidenceViewerFinalizedAuthorizationReaderV1
    for ToriiEvidenceViewerFinalizedAuthorizationReaderV1
{
    fn authorize(
        &self,
        case_id: &str,
        round_id: &str,
        viewer_account: &str,
        role: EvidenceViewerRoleV1,
        evidence_bundle_digest: [u8; 32],
    ) -> Result<EvidenceViewerFinalizedAuthorizationV1, EvidenceViewerAuthorizationErrorV1> {
        let parsed = AccountId::parse_encoded(viewer_account)
            .map_err(|_| EvidenceViewerAuthorizationErrorV1::Denied)?;
        if parsed.to_string() != viewer_account {
            return Err(EvidenceViewerAuthorizationErrorV1::Denied);
        }
        let account = parsed;
        let view = self.state.query_view();
        let case = FindSorafsModerationCase::new(case_id.to_owned(), round_id.to_owned())
            .execute(&view)
            .map_err(|_| EvidenceViewerAuthorizationErrorV1::Denied)?;
        if case.spec.context.case_id != case_id
            || case.spec.round_id != round_id
            || case.spec.context.evidence_bundle_digest != evidence_bundle_digest
        {
            return Err(EvidenceViewerAuthorizationErrorV1::Denied);
        }
        let explicitly_authorized = match role {
            EvidenceViewerRoleV1::Juror => {
                case.status == ModerationCaseStatusV1::Open
                    && case.spec.jurors.iter().any(|juror| juror == &account)
            }
            EvidenceViewerRoleV1::Auditor => view
                .world()
                .account_roles_iter(&account)
                .any(|candidate| candidate == &self.auditor_role),
            EvidenceViewerRoleV1::Legal => view
                .world()
                .account_roles_iter(&account)
                .any(|candidate| candidate == &self.legal_role),
        };
        if !explicitly_authorized {
            return Err(EvidenceViewerAuthorizationErrorV1::Denied);
        }
        let finalized_height = u64::try_from(view.height())
            .map_err(|_| EvidenceViewerAuthorizationErrorV1::Unavailable)?;
        let finalized_block_hash = *view
            .latest_block_hash()
            .ok_or(EvidenceViewerAuthorizationErrorV1::Unavailable)?
            .as_ref();
        let finalized_at_unix_ms = view
            .authenticated_query_ledger_time_ms()
            .ok_or(EvidenceViewerAuthorizationErrorV1::Unavailable)?;
        if finalized_height == 0 || finalized_block_hash == [0; 32] || finalized_at_unix_ms == 0 {
            return Err(EvidenceViewerAuthorizationErrorV1::Unavailable);
        }
        Ok(EvidenceViewerFinalizedAuthorizationV1 {
            case_id: case_id.to_owned(),
            round_id: round_id.to_owned(),
            viewer_account: viewer_account.to_owned(),
            role,
            evidence_bundle_digest,
            policy_digest: case.spec.policy_digest,
            finalized_height,
            finalized_block_hash,
            finalized_at_unix_ms,
        })
    }
}
