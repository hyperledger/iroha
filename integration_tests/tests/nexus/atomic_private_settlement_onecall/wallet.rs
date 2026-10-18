//! Deterministic original fixture wallet, with public reservation metadata in existing custody.
//!
//! The original fixture seeds reproduce actual activated notes after child-process exit.
//! No wallet witness, signing key, plaintext audit opening or membership path is serialized.
//! This is a test provider, not a production deterministic-key recommendation.
use super::*;
use iroha::client::{
    OneCallPrivateSettlementError, PrivateSettlementBusinessTerms,
    PrivateSettlementRestrictedOpening, PrivateSettlementWallet,
};
use iroha::workflow::{Digest32, FileWorkflowStorage, WorkflowId, WorkflowStorage, domain_digest};
use iroha_core_privacy::privacy_engines::atomic_private_settlement::{
    AtomicPrivateSettlementAuthorizedWalletLegV1, plan_atomic_private_settlement_initial_inputs_v1,
    prepare_atomic_private_settlement_authorization_inputs_v1,
};
use iroha_data_model::nexus::PrivateSettlementProofIntentV1;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(super) struct OriginalWallet {
    governed: std::sync::OnceLock<std::result::Result<Vec<GovernedLeg>, String>>,
    routes: Vec<PrivateSettlementRouteV1>,
    activation_height: u64,
    expiry: u64,
    reservations: FileWorkflowStorage,
    enabled: AtomicBool,
    pub(super) openings: AtomicUsize,
    pub(super) reservations_called: AtomicUsize,
}
impl OriginalWallet {
    pub(super) fn open(
        routes: &[PrivateSettlementRouteV1],
        activation_height: u64,
        expiry: u64,
        path: &std::path::Path,
    ) -> Result<Self> {
        Ok(Self {
            governed: std::sync::OnceLock::new(),
            routes: routes.to_vec(),
            activation_height,
            expiry,
            reservations: FileWorkflowStorage::open_or_create(path)?,
            enabled: AtomicBool::new(false),
            openings: AtomicUsize::new(0),
            reservations_called: AtomicUsize::new(0),
        })
    }
    pub(super) fn enable_explicit_continuation(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }
    fn terms(
        &self,
        intent: &PrivateSettlementProofIntentV1,
        ordinal: u8,
        terms: &PrivateSettlementBusinessTerms,
    ) -> Result<(&GovernedLeg, PrivateSettlementLegPrivateData)> {
        ensure!(
            self.enabled.load(Ordering::SeqCst),
            "read-only recovery called the wallet"
        );
        let governed = self
            .governed
            .get_or_init(|| {
                governed_legs(&self.routes, self.activation_height, self.expiry)
                    .map_err(|error| error.to_string())
            })
            .as_ref()
            .map_err(|error| eyre!(error.clone()))?
            .get(usize::from(ordinal))
            .ok_or_else(|| eyre!("wallet leg absent"))?;
        let data = default_private_settlement_leg_data(usize::from(ordinal));
        ensure!(
            terms.asset == governed.governance.body.asset_definition_id
                && terms.payer == AccountId::new(data.payer.public_key().clone())
                && terms.recipient == AccountId::new(data.recipient.public_key().clone())
                && terms.amount == data.amount
                && terms.reimbursement
                    == if ordinal == intent.reimbursement_leg_ordinal {
                        5
                    } else {
                        0
                    }
                && terms.memo == data.memo,
            "independent original wallet terms changed"
        );
        Ok((governed, data))
    }
    fn reserve_original(
        &self,
        round: Digest32,
        intent: &PrivateSettlementProofIntentV1,
        ordinal: u8,
        original: PrivacyCommitmentV1,
    ) -> Result<()> {
        let id = WorkflowId::from_bytes(domain_digest(
            b"iroha:n3:onecall:original-note:v1\0",
            &[
                intent.network_id.as_bytes(),
                intent.legs[usize::from(ordinal)].pool_id.as_bytes(),
                original.as_bytes(),
            ],
        ));
        let _lease = self.reservations.acquire_runner(&id)?;
        // Existing durable CAS owns publication. These are public identifiers only. Another
        // intent cannot reopen this note, even after every original process owner has died.
        let exact = norito::encode_canonical(&(round, intent.bundle_id, ordinal, original))?;
        match self.reservations.load(&id)? {
            Some(original) => ensure!(
                original == exact,
                "original note already belongs to another round/intent"
            ),
            None => self.reservations.compare_and_store(&id, None, &exact)?,
        }
        Ok(())
    }
}
impl PrivateSettlementWallet for OriginalWallet {
    fn open_policy(
        &self,
        intent: &PrivateSettlementProofIntentV1,
        ordinal: u8,
        terms: &PrivateSettlementBusinessTerms,
    ) -> std::result::Result<PrivateSettlementRestrictedOpening, OneCallPrivateSettlementError>
    {
        self.openings.fetch_add(1, Ordering::SeqCst);
        let (governed, _) = self
            .terms(intent, ordinal, terms)
            .map_err(OneCallPrivateSettlementError::Provider)?;
        Ok(PrivateSettlementRestrictedOpening {
            governance: governed.governance.clone(),
            policy: governed.policy.clone(),
        })
    }
    fn reserve_or_reopen(
        &self,
        round: Digest32,
        intent: &PrivateSettlementProofIntentV1,
        ordinal: u8,
        terms: &PrivateSettlementBusinessTerms,
    ) -> std::result::Result<
        AtomicPrivateSettlementAuthorizedWalletLegV1,
        OneCallPrivateSettlementError,
    > {
        self.reservations_called.fetch_add(1, Ordering::SeqCst);
        (|| {
            let (governed, data) = self.terms(intent, ordinal, terms)?;
            let funding = private_settlement_funding(
                intent.network_id,
                governed,
                usize::from(ordinal),
                &data,
            )?;
            self.reserve_original(round, intent, ordinal, funding.input_commitments[0])?;
            authorize_original(intent, usize::from(ordinal), governed, &data, funding)
        })()
        .map_err(OneCallPrivateSettlementError::Provider)
    }
}
fn authorize_original(
    intent: &PrivateSettlementProofIntentV1,
    ordinal: usize,
    governed: &GovernedLeg,
    data: &PrivateSettlementLegPrivateData,
    funding: PrivateSettlementFunding,
) -> Result<AtomicPrivateSettlementAuthorizedWalletLegV1> {
    let material = |index, purpose: &[u8]| {
        private_settlement_leg_private_material_for_bundle(
            intent.bundle_id,
            governed,
            ordinal,
            index,
            purpose,
        )
    };
    let note = |purpose: &[u8], index: usize, active, value, spending_authority| {
        let field = |offset| material(index * 6 + offset, purpose);
        PrivateSettlementAuditNoteOpeningV1 {
            active,
            // This is private note construction state. The canonical input/output owner
            // replaces the commitment before it can enter a signed body or proof statement.
            commitment: PrivacyCommitmentV1::new([0; 32]),
            value,
            spending_authority,
            rho: field(2),
            blinding: field(3),
            memo_digest: field(4),
            dummy_domain: (!active).then(|| Hash::prehashed(field(5))),
        }
    };
    let spending_secrets = [
        funding.spending_secret,
        material(1, b"input-spending-secret"),
    ];
    let mut input_openings = vec![
        funding.opening,
        note(
            b"input-note",
            1,
            false,
            0,
            derive_note_authority_v1(&spending_secrets[1])?,
        ),
    ];
    let nullifiers = prepare_atomic_private_settlement_authorization_inputs_v1(
        intent,
        ordinal as u8,
        &mut input_openings,
        &spending_secrets,
    )?;
    ensure!(
        input_openings[0].commitment == funding.input_commitments[0],
        "cold wallet replaced the already funded positive note"
    );
    let payer = AccountId::new(data.payer.public_key().clone());
    let recipient = AccountId::new(data.recipient.public_key().clone());
    let payer_body = PrivateSettlementAuditPayerAuthorizationBodyV1::from_openings(
        intent.network_id,
        intent.bundle_id,
        ordinal as u8,
        governed.route,
        &payer,
        intent.expiry_height,
        &input_openings,
        &nullifiers,
    )?;
    let payer_authorization = PrivateSettlementAuditPayerAuthorizationV1::new(
        payer_body.clone(),
        vec![PrivateSettlementAuditPayerSignatureV1::new(
            data.payer.public_key().clone(),
            SignatureOf::try_new(data.payer.private_key(), &payer_body)?,
        )],
    );
    let reimbursement = if ordinal == usize::from(intent.reimbursement_leg_ordinal) {
        5
    } else {
        0
    };
    let mut outputs = Vec::with_capacity(3);
    for (index, (signer, active, amount, role)) in [
        (
            &data.recipient,
            true,
            data.amount,
            PrivateSettlementAuditOutputRoleV1::SettlementRecipient,
        ),
        (
            &data.payer,
            true,
            7,
            PrivateSettlementAuditOutputRoleV1::PayerChange,
        ),
        (
            &*ALICE_KEYPAIR,
            reimbursement != 0,
            reimbursement,
            PrivateSettlementAuditOutputRoleV1::SponsorReimbursement,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let opening = note(
            b"output-note",
            index,
            active,
            amount,
            derive_note_authority_v1(&material(index, b"output-spending-secret"))?,
        );
        let view = ivm_private_recipient_public_key_v1(&material(index, b"output-view-secret"))?;
        let body = PrivateSettlementAuditViewKeyAuthorizationBodyV1::from_output(
            intent.network_id,
            intent.bundle_id,
            ordinal as u8,
            governed.route,
            intent.expiry_height,
            &recipient,
            &payer,
            &intent.sponsor,
            index,
            view,
            &opening,
        )?;
        outputs.push(PrivateSettlementAuditOutputV1 {
            role,
            recipient_view_key: view,
            view_key_authorization: PrivateSettlementAuditViewKeyAuthorizationV1::new(
                body.clone(),
                vec![PrivateSettlementAuditViewKeySignatureV1::new(
                    signer.public_key().clone(),
                    SignatureOf::try_new(signer.private_key(), &body)?,
                )],
            ),
            encryption_opening: PrivateSettlementAuditEncryptionOpeningV1 {
                ephemeral_secret: material(index, b"output-ephemeral-secret"),
            },
            note: opening,
        });
    }
    let plaintext = PrivateSettlementAuditPlaintextV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        network_id: intent.network_id,
        bundle_id: intent.bundle_id,
        leg_ordinal: ordinal as u8,
        route: governed.route,
        pool_id: governed.governance.body.pool_id,
        payer,
        payer_authorization,
        recipient,
        sponsor: intent.sponsor.clone(),
        asset_definition_id: governed.governance.body.asset_definition_id.clone(),
        asset_binding_salt: governed.governance.body.asset_binding_salt,
        amount: data.amount,
        sponsor_reimbursement_amount: reimbursement,
        fee_intent_digest: intent.fee_intent_digest,
        settlement_expiry_height: intent.expiry_height,
        reimbursement_terms_salt: private_settlement_reimbursement_terms_salt_for_terms(
            intent.network_id,
            intent.authority_context_height,
            intent.expiry_height,
            intent.fee_intent_digest,
            governed,
        ),
        memo: data.memo.clone(),
        policy_references: vec![governed.governance.governance_digest],
        inputs: input_openings,
        outputs,
    };
    let inputs = plan_atomic_private_settlement_initial_inputs_v1(
        governed.governance.body.pool_id,
        funding.input_commitments,
        spending_secrets,
    )?;
    Ok(AtomicPrivateSettlementAuthorizedWalletLegV1::new(
        plaintext, inputs,
    ))
}

#[test]
fn cold_wallet_original_note_cas_reopens_only_the_original_round_and_intent() {
    let routes = (0..PARTICIPANT_COUNT)
        .map(|ordinal| PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(ordinal as u64 + 1),
            lane_id: LaneId::new(ordinal as u32 + 1),
            lane_incarnation: hash(0xE0 + ordinal as u8),
        })
        .collect::<Vec<_>>();
    let network = iroha_data_model::NetworkId::from_genesis_hash(
        HashOf::<BlockHeader>::from_untyped_unchecked(hash(0xF8)),
    );
    let governed = governed_legs(&routes, 301, 401).unwrap();
    let intent = super::intent(network, 301, 401, &governed).unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("original-wallet");
    let original_note = PrivacyCommitmentV1::new([17; 32]);
    let wallet = OriginalWallet::open(&routes, 301, 401, &path).unwrap();
    wallet
        .reserve_original([23; 32], &intent, 0, original_note)
        .unwrap();
    drop(wallet);
    let reopened = OriginalWallet::open(&routes, 301, 401, &path).unwrap();
    reopened
        .reserve_original([23; 32], &intent, 0, original_note)
        .unwrap();
    assert!(
        reopened
            .reserve_original([24; 32], &intent, 0, original_note)
            .is_err()
    );
    let mut substituted = intent;
    substituted.bundle_id = hash(0x21);
    assert!(
        reopened
            .reserve_original([23; 32], &substituted, 0, original_note)
            .is_err()
    );
    assert_eq!(reopened.openings.load(Ordering::SeqCst), 0);
    assert_eq!(reopened.reservations_called.load(Ordering::SeqCst), 0);
}
