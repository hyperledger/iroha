//! Peer message, envelope and `kgm1:` text tests.
//!
//! The fixtures are visible to the custody, ledger, vector and size test modules, which build
//! capsules, completion records, fee claims and worst cases from the same Payment.

use p256::ecdsa::SigningKey;

use super::*;
use crate::kagemusha::kagemusha_wallet_v1::{
    KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1, KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_SESSION_TEXT_MAX_BYTES_V1, KagemushaWalletBlacklistBodyV1,
    KagemushaWalletBlacklistEntryV1, KagemushaWalletBlacklistHistoryLeafV1,
    KagemushaWalletCredentialBodyV1, KagemushaWalletEvidenceKindV1, KagemushaWalletFeeRoundingV1,
    KagemushaWalletFeeScheduleBodyV1, KagemushaWalletLifecycleV1, KagemushaWalletPolicyUpdateV1,
    KagemushaWalletRegulatoryPolicyV1, KagemushaWalletSchemePolicyBodyV1,
    KagemushaWalletStatementV1,
    codec_tests::{assert_every_flip_rejected_or_rebound, norito_tag, payload_range},
    digest::{kagemusha_wallet_field_from_u128_v1, kagemusha_wallet_is_canonical_field_v1},
    identity::identity_tests::{
        IdentityFixture, identity_fixture, public_key, raw_output, signing_key, test_account,
        test_certificate,
    },
    kagemusha_wallet_account_digest_v1, kagemusha_wallet_blacklist_root_v1,
    kagemusha_wallet_enrollment_id_v1, kagemusha_wallet_id_v1, kagemusha_wallet_integer_cmp_v1,
    kagemusha_wallet_unload_nullifier_v1,
    poseidon::{
        KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1, KagemushaWalletIndexedTreeV1,
        kagemusha_wallet_poseidon_v1,
    },
    state::{
        KagemushaWalletLineageSlotV1, KagemushaWalletReceiptBodyV1,
        KagemushaWalletStateCommitmentV1, kagemusha_wallet_proof_digest_v1,
        state_tests::{
            CAPSULE, CREDIT_DIGEST_ROOT, LINEAGE_PENDING_ROOT, commitment, field_value,
            lineage_with_len, signed_package_with, stand_in_bytes, stand_in_proof,
            transition_statement,
        },
    },
};

/// One mutation of an Offer body.
type OfferBodyMutation = fn(&mut KagemushaWalletOfferBodyV1);
/// One mutation of a Request body.
type RequestBodyMutation = fn(&mut KagemushaWalletRequestBodyV1);
/// One mutation of a Send effect.
type EffectMutation = fn(&mut KagemushaWalletEffectV1);
/// One mutation of a session control.
type ControlMutation = fn(&mut KagemushaWalletSessionControlV1);

/// Receiver's authenticated accepted time of the fixture Request.
pub(in crate::kagemusha::kagemusha_wallet_v1) const ACCEPTED_MS: u64 = 1_790_000_100_000;
/// Stand-in Ω transport proof length of the fixture Payment.
pub(in crate::kagemusha::kagemusha_wallet_v1) const PAYMENT_LINEAGE_LEN: usize = 48;
/// Other credits recorded before the fixture credit in the `CreditStatus` credit-digest tree;
/// the fixture credit sits at slot `OPENING_OTHER_CREDITS + 1`.
pub(in crate::kagemusha::kagemusha_wallet_v1) const OPENING_OTHER_CREDITS: usize = 3;
const SESSION_NONCE: [u8; 32] = [0x5e; 32];

/// Payer and receiver wallets of one scheme with distinct issuers, and a fee signer.
pub(in crate::kagemusha::kagemusha_wallet_v1) struct MessageFixture {
    /// Payer; its enrollment signer and certificate are the payer's own issuer.
    pub(in crate::kagemusha::kagemusha_wallet_v1) payer: IdentityFixture,
    /// Receiver under the shared fixture issuer.
    pub(in crate::kagemusha::kagemusha_wallet_v1) receiver: IdentityFixture,
    /// `RegulatoryPolicy`-role signer.
    pub(in crate::kagemusha::kagemusha_wallet_v1) regulator: SigningKey,
    /// `RegulatoryPolicy`-role certificate.
    pub(in crate::kagemusha::kagemusha_wallet_v1) regulator_certificate:
        KagemushaWalletSignerCertificateV1,
}

/// Fixture whose payer issuer differs from the receiver issuer.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn message_fixture() -> MessageFixture {
    let base = identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x51);
    let payer_signer = signing_key(0x26);
    let payer_issuer = test_certificate(
        &base.scheme,
        &base.root,
        KagemushaWalletSignerRoleV1::Enrollment,
        &payer_signer,
        9,
    );
    let mut body = base.credential.body;
    body.issuer_certificate = payer_issuer.certificate_digest();
    let credential = KagemushaWalletCredentialV1::sign(
        body,
        &payer_issuer,
        raw_output(&payer_signer, &body.signing_message()),
    )
    .expect("payer credential");
    let payer = IdentityFixture {
        enrollment_signer: payer_signer,
        enrollment_certificate: payer_issuer,
        credential,
        ..base
    };
    let receiver = identity_fixture(KagemushaWalletEvidenceKindV1::AppleAppAttest, 0x52);
    let regulator = signing_key(0x33);
    let regulator_certificate = test_certificate(
        &payer.scheme,
        &payer.root,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
        &regulator,
        2,
    );
    MessageFixture {
        payer,
        receiver,
        regulator,
        regulator_certificate,
    }
}

/// Receiver head state under its current `credential`, holding no blacklist.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn receiver_head_state(
    credential: &KagemushaWalletCredentialV1,
) -> KagemushaWalletStateV1 {
    KagemushaWalletStateV1::bootstrap(credential, field_value(0x5e)).expect("receiver state")
}

/// Other credit `index` of the fixture credit-digest tree: a stand-in credit identifier and
/// Payment digest.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn neighbour_credit(
    index: usize,
) -> KagemushaWalletCreditDigestLeafV1 {
    let seed = u8::try_from(index % 60 + 2).expect("seed");
    KagemushaWalletCreditDigestLeafV1 {
        credit_id: field_value(seed),
        payment_digest: field_value(seed.wrapping_add(0x40)),
        burned: false,
    }
}

/// The lineage-level credit-digest tree (owner answer A2) that recorded `others` other credits
/// ([`neighbour_credit`]) and then `leaf`, at slot `others + 1`.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn credit_digest_tree(
    leaf: &KagemushaWalletCreditDigestLeafV1,
    others: usize,
) -> KagemushaWalletIndexedTreeV1 {
    let mut tree = KagemushaWalletIndexedTreeV1::new();
    for index in 0..others {
        let other = neighbour_credit(index);
        tree.insert(other.key(), other.leaf_value().expect("other value"))
            .expect("insert other credit");
    }
    tree.insert(leaf.key(), leaf.leaf_value().expect("credit value"))
        .expect("insert credit");
    tree
}

/// 32-sibling membership opening of `leaf` in `tree`.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn credit_opening_in(
    tree: &KagemushaWalletIndexedTreeV1,
    leaf: &KagemushaWalletCreditDigestLeafV1,
) -> KagemushaWalletCreditOpeningV1 {
    let (indexed, opening) = tree.membership(&leaf.credit_id).expect("membership");
    KagemushaWalletCreditOpeningV1::new(leaf, &indexed, &opening).expect("credit opening")
}

impl MessageFixture {
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn scheme_id(&self) -> [u8; 32] {
        self.payer.scheme.scheme_id()
    }

    pub(in crate::kagemusha::kagemusha_wallet_v1) fn asset_digest(&self) -> [u8; 32] {
        self.payer.credential.body.asset_digest
    }

    /// Fee schedule body: 25 bp rounded up, fixed 3, clamped to `[5, 1000]`.
    fn fee_body(&self) -> KagemushaWalletFeeScheduleBodyV1 {
        KagemushaWalletFeeScheduleBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.asset_digest(),
            schedule_id: 7,
            beneficiary_account_digest: kagemusha_wallet_account_digest_v1(&test_account(0x5b))
                .expect("beneficiary"),
            basis_points: 25,
            fixed: 3,
            minimum: 5,
            maximum: 1_000,
            rounding: KagemushaWalletFeeRoundingV1::Up,
            signer_certificate: self.regulator_certificate.certificate_digest(),
        }
    }

    fn sign_fee_schedule(
        &self,
        body: KagemushaWalletFeeScheduleBodyV1,
    ) -> KagemushaWalletFeeScheduleV1 {
        KagemushaWalletFeeScheduleV1::sign(
            body,
            &self.regulator_certificate,
            raw_output(&self.regulator, &body.signing_message()),
        )
        .expect("fee schedule")
    }

    /// Signed fixture fee schedule.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn fee_schedule(
        &self,
    ) -> KagemushaWalletFeeScheduleV1 {
        self.sign_fee_schedule(self.fee_body())
    }

    /// Epoch-`epoch` scheme policy naming `fee_schedule`.
    fn scheme_policy(
        &self,
        epoch: u64,
        enabled_controls: u32,
        fee_schedule: [u8; 32],
    ) -> KagemushaWalletSchemePolicyV1 {
        let body = KagemushaWalletSchemePolicyBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.asset_digest(),
            policy_epoch: epoch,
            enabled_controls,
            fee_schedule,
            signer_certificate: self.regulator_certificate.certificate_digest(),
        };
        KagemushaWalletSchemePolicyV1::sign(
            body,
            &self.regulator_certificate,
            raw_output(&self.regulator, &body.signing_message()),
        )
        .expect("scheme policy")
    }

    /// Unsigned Request parts for `amount`, with or without the fixture fee schedule.
    fn request_parts(
        &self,
        fee: bool,
        amount: u128,
    ) -> (
        KagemushaWalletRequestBodyV1,
        KagemushaWalletFeeScheduleSlotV1,
        KagemushaWalletCertificateSetV1,
    ) {
        let slot = if fee {
            KagemushaWalletFeeScheduleSlotV1::Present {
                schedule: self.fee_schedule(),
            }
        } else {
            KagemushaWalletFeeScheduleSlotV1::None
        };
        let mut certificates = vec![self.receiver.enrollment_certificate];
        if fee {
            certificates.push(self.regulator_certificate);
        }
        let certificates = KagemushaWalletCertificateSetV1::new(certificates).expect("set");
        let policy = self.scheme_policy(1, 0, slot.fee_schedule_digest());
        let body = KagemushaWalletRequestBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.asset_digest(),
            payer_wallet_id: self.payer.credential.body.wallet_id,
            payer_account_digest: self.payer.credential.body.account_digest,
            receiver_wallet_id: self.receiver.credential.body.wallet_id,
            receiver_account_digest: self.receiver.credential.body.account_digest,
            send_ordinal: 4,
            receiver_credential_digest: self.receiver.credential.credential_digest(),
            amount,
            fee_schedule: slot.fee_schedule_digest(),
            fee: slot
                .schedule()
                .map_or(0, |schedule| schedule.fee(amount).expect("fee")),
            policy_epoch: 1,
            scheme_policy: policy.scheme_policy_digest(),
            receiver_accepted_time_ms: ACCEPTED_MS,
            receiver_blacklist_version: 0,
            receiver_blacklist_root: [0; 32],
            certificates: certificates.digest().expect("set digest"),
            nonce: [0x6e; 32],
        };
        (body, slot, certificates)
    }

    fn sign_request(
        &self,
        body: &KagemushaWalletRequestBodyV1,
        slot: KagemushaWalletFeeScheduleSlotV1,
        certificates: KagemushaWalletCertificateSetV1,
    ) -> WalletResult<KagemushaWalletRequestV1> {
        KagemushaWalletRequestV1::sign(
            &self.payer.scheme,
            &self.offer(),
            *body,
            self.receiver.credential,
            slot,
            certificates,
            raw_output(&self.receiver.payment, &body.signing_message()),
        )
    }

    /// Signed Request of 1,000 units.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn request(
        &self,
        fee: bool,
    ) -> KagemushaWalletRequestV1 {
        let (body, slot, certificates) = self.request_parts(fee, 1_000);
        self.sign_request(&body, slot, certificates)
            .expect("request")
    }

    /// Payer statement at sequence 3 carrying `effect`.
    fn payer_statement(&self, effect: KagemushaWalletEffectV1) -> KagemushaWalletStatementV1 {
        transition_statement(
            &self.payer,
            3,
            0,
            KagemushaWalletLifecycleV1::Active,
            effect,
        )
    }

    /// Payer Ω(pred) of `statement` (policy epoch 1) with a `lineage_len`-byte transport
    /// proof.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn payer_lineage(
        &self,
        statement: &KagemushaWalletStatementV1,
        lineage_len: usize,
    ) -> KagemushaWalletLineageV1 {
        let mut lineage = lineage_with_len(&self.payer.credential, statement, lineage_len);
        lineage.public.policy_epoch = 1;
        lineage
    }

    /// Committed Send package of `request` signed over `statement` with Ω(pred) and σ of the
    /// given lengths.
    fn send_package_for(
        &self,
        statement: &KagemushaWalletStatementV1,
        lineage_len: usize,
        proof_len: usize,
    ) -> KagemushaWalletPackageV1 {
        signed_package_with(
            &self.payer,
            &self.payer.credential,
            statement,
            KagemushaWalletLineageSlotV1::Present {
                lineage: self.payer_lineage(statement, lineage_len),
            },
            stand_in_proof(proof_len),
            [0; 32],
        )
    }

    /// Committed Send package of `request` with Ω(pred) and σ of the given lengths.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn send_package(
        &self,
        request: &KagemushaWalletRequestV1,
        lineage_len: usize,
        proof_len: usize,
    ) -> KagemushaWalletPackageV1 {
        let interval =
            KagemushaWalletTimeIntervalV1::new(ACCEPTED_MS, ACCEPTED_MS + 4_000).expect("interval");
        let effect = request
            .send_effect(&self.payer.credential, &interval)
            .expect("send effect");
        self.send_package_for(&self.payer_statement(effect), lineage_len, proof_len)
    }

    /// Complete compact Payment of 1,000 units with Ω(pred) and σ of the given lengths.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn payment_with(
        &self,
        fee: bool,
        lineage_len: usize,
        proof_len: usize,
    ) -> KagemushaWalletPaymentV1 {
        let request = self.request(fee);
        let send = self.send_package(&request, lineage_len, proof_len);
        KagemushaWalletPaymentV1::assemble(&request, &self.payer.credential, send).expect("payment")
    }

    /// Complete compact Payment of 1,000 units with a `proof_len`-byte σ.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn payment(
        &self,
        fee: bool,
        proof_len: usize,
    ) -> KagemushaWalletPaymentV1 {
        self.payment_with(fee, PAYMENT_LINEAGE_LEN, proof_len)
    }

    /// The receiver's held Request of `payment`, a Payment of this fixture.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn held_request(
        &self,
        payment: &KagemushaWalletPaymentV1,
    ) -> KagemushaWalletRequestV1 {
        let request = self.request(!is_zero_v1(&payment.request.body.fee_schedule));
        assert_eq!(request.signed(), payment.request, "the fixture's Request");
        request
    }

    /// Receive statement of `payment` at sequence 5 under the receiver's `credential`.
    fn receive_statement(
        &self,
        payment: &KagemushaWalletPaymentV1,
        credential: &KagemushaWalletCredentialV1,
    ) -> KagemushaWalletStatementV1 {
        let effect = payment
            .receive_effect(
                &self.held_request(payment),
                credential,
                &receiver_head_state(credential),
                None,
            )
            .expect("receive effect");
        KagemushaWalletStatementV1 {
            credential_digest: credential.credential_digest(),
            ..transition_statement(
                &self.receiver,
                5,
                0,
                KagemushaWalletLifecycleV1::Active,
                effect,
            )
        }
    }

    /// Receiver's Receive package of `payment` at sequence 5 under `credential` (the receiver's
    /// current credential), binding its Payment digest.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn receive_package_under(
        &self,
        payment: &KagemushaWalletPaymentV1,
        credential: &KagemushaWalletCredentialV1,
        proof_len: usize,
    ) -> KagemushaWalletPackageV1 {
        signed_package_with(
            &self.receiver,
            credential,
            &self.receive_statement(payment, credential),
            KagemushaWalletLineageSlotV1::None,
            stand_in_proof(proof_len),
            payment.payment_digest().expect("payment digest"),
        )
    }

    /// Receiver's Receive package of `payment` at sequence 5, binding its Payment digest.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn receive_package(
        &self,
        payment: &KagemushaWalletPaymentV1,
        proof_len: usize,
    ) -> KagemushaWalletPackageV1 {
        self.receive_package_under(payment, &self.receiver.credential, proof_len)
    }

    /// Credited evidence from the Receive package.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn credited_receive(
        &self,
        payment: &KagemushaWalletPaymentV1,
        proof_len: usize,
    ) -> KagemushaWalletCreditedV1 {
        KagemushaWalletCreditedV1::from_receive(self.receive_package(payment, proof_len))
            .expect("credited receive")
    }

    /// `CreditStatus` of the folded crediting head `h` (the receiver's Receive of `payment` at
    /// sequence 5) whose statement runs under `credential` and whose τ(h) is signed by
    /// `signer`, with Ω(h) naming `credential`'s wallet and `signer`'s key, an Ω(h) proof of
    /// `lineage_len` bytes and a credit-digest root that records `leaf` after `others` other
    /// credits. Returns the status and its credit-digest tree.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn credit_status_under(
        &self,
        payment: &KagemushaWalletPaymentV1,
        lineage_len: usize,
        leaf: &KagemushaWalletCreditDigestLeafV1,
        others: usize,
        credential: &KagemushaWalletCredentialV1,
        signer: &SigningKey,
    ) -> (KagemushaWalletCreditStatusV1, KagemushaWalletIndexedTreeV1) {
        let statement = self.receive_statement(payment, credential);
        let step_proof = stand_in_proof(32);
        let proof_digest = kagemusha_wallet_proof_digest_v1(
            KagemushaWalletOperationKindV1::Receive,
            None,
            &step_proof,
        )
        .expect("proof digest");
        let payment_digest = payment.payment_digest().expect("payment digest");
        let receipt_signer = KagemushaWalletReceiptSignerV1 {
            payment_key: public_key(signer),
            ..KagemushaWalletReceiptSignerV1::from_credential(credential).expect("signer")
        };
        let body = KagemushaWalletReceiptBodyV1::derive(
            &receipt_signer,
            &statement,
            &proof_digest,
            CAPSULE,
            payment_digest,
        )
        .expect("receipt body");
        let receipt = KagemushaWalletReceiptV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            operation_id: body.operation_id,
            capsule_digest: CAPSULE,
            payment_digest,
            signature: kagemusha_wallet_freeze_signature_v1(
                &receipt_signer.payment_key,
                Domain::Receipt,
                &body.signing_message(),
                raw_output(signer, &body.signing_message()),
            )
            .expect("receipt signature"),
        };
        let tree = credit_digest_tree(leaf, others);
        let status = KagemushaWalletCreditStatusV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            statement,
            proof_digest,
            receipt,
            lineage: KagemushaWalletLineageV1 {
                public: KagemushaWalletLineagePublicV1 {
                    version: KAGEMUSHA_WALLET_VERSION_V1,
                    scheme_id: statement.scheme_id,
                    relation_id: statement.relation_id,
                    head: statement.successor,
                    wallet_id: credential.body.wallet_id,
                    credential_digest: statement.credential_digest,
                    payment_key: receipt_signer.payment_key,
                    lifecycle: statement.lifecycle,
                    policy_epoch: 1,
                    enabled_controls: 0,
                    burned_total: if leaf.burned { 1_000 } else { 0 },
                    pending_outgoing_root: LINEAGE_PENDING_ROOT,
                    credit_digest_root: tree.root(),
                },
                proof: stand_in_bytes(lineage_len, 11),
            },
            opening: credit_opening_in(&tree, leaf),
        };
        (status, tree)
    }

    /// Credit-digest leaf of `payment` with the burn flag `burned`.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn credit_leaf(
        payment: &KagemushaWalletPaymentV1,
        burned: bool,
    ) -> KagemushaWalletCreditDigestLeafV1 {
        let digests = payment.digests().expect("payment digests");
        KagemushaWalletCreditDigestLeafV1 {
            credit_id: digests.credit_id,
            payment_digest: digests.payment,
            burned,
        }
    }

    /// `CreditStatus` of `payment` against the folded crediting head `h` (the receiver's
    /// Receive at sequence 5), with an Ω(h) of `lineage_len` proof bytes and a credit-digest
    /// tree that recorded `others` other credits first.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn credit_status(
        &self,
        payment: &KagemushaWalletPaymentV1,
        lineage_len: usize,
        others: usize,
        burned: bool,
    ) -> KagemushaWalletCreditStatusV1 {
        self.credit_status_under(
            payment,
            lineage_len,
            &Self::credit_leaf(payment, burned),
            others,
            &self.receiver.credential,
            &self.receiver.payment,
        )
        .0
    }

    /// Credited evidence from a `CreditStatus` of the folded crediting head.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn credited_status(
        &self,
        payment: &KagemushaWalletPaymentV1,
        lineage_len: usize,
        others: usize,
    ) -> KagemushaWalletCreditedV1 {
        KagemushaWalletCreditedV1::from_status(self.credit_status(
            payment,
            lineage_len,
            others,
            false,
        ))
        .expect("credited status")
    }

    /// Payer state holding the epoch-1 scheme policy of `request`'s fee schedule.
    fn payer_state(&self, request: &KagemushaWalletRequestV1) -> KagemushaWalletStateV1 {
        let mut state =
            KagemushaWalletStateV1::bootstrap(&self.payer.credential, field_value(0x5d))
                .expect("bootstrap");
        let policy = self.scheme_policy(1, 0, request.body.fee_schedule);
        let refresh = state
            .refresh_policy(KagemushaWalletPolicyUpdateV1::SchemePolicy { policy: &policy })
            .expect("refresh");
        state.core = refresh.core;
        state.rest = refresh.rest;
        state.core.balance = 10_000;
        state.core.next_send = request.body.send_ordinal;
        state
    }

    /// Ω recorded for the folded head `state`: its head is the state's computed commitment.
    fn payer_omega(&self, state: &KagemushaWalletStateV1) -> KagemushaWalletLineagePublicV1 {
        KagemushaWalletLineagePublicV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: state.core.scheme_id,
            relation_id: self.payer.scheme.relation_id,
            head: state.commitment().expect("head commitment"),
            wallet_id: state.core.wallet_id,
            credential_digest: state.core.credential_digest,
            payment_key: self.payer.credential.body.payment_key,
            lifecycle: state.core.lifecycle,
            policy_epoch: state.core.policy_epoch,
            enabled_controls: state.core.enabled_controls,
            burned_total: state.core.burned_total,
            pending_outgoing_root: state.core.pending_outgoing_root,
            credit_digest_root: CREDIT_DIGEST_ROOT,
        }
    }

    pub(in crate::kagemusha::kagemusha_wallet_v1) fn offer_body(
        &self,
    ) -> KagemushaWalletOfferBodyV1 {
        KagemushaWalletOfferBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.asset_digest(),
            payer_wallet_id: self.payer.credential.body.wallet_id,
            payer_credential_digest: self.payer.credential.credential_digest(),
            next_send: 4,
            amount: 1_000,
            session_nonce: SESSION_NONCE,
        }
    }

    fn sign_offer(&self, body: KagemushaWalletOfferBodyV1) -> WalletResult<KagemushaWalletOfferV1> {
        KagemushaWalletOfferV1::sign(
            body,
            self.payer.credential,
            &self.payer.enrollment_certificate,
            raw_output(&self.payer.payment, &body.signing_message()),
        )
    }

    pub(in crate::kagemusha::kagemusha_wallet_v1) fn offer(&self) -> KagemushaWalletOfferV1 {
        self.sign_offer(self.offer_body()).expect("offer")
    }

    /// Lineage message carrying the exact Ω(pred) bytes of `payment`, a Payment of this
    /// fixture's payer.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn lineage_message(
        &self,
        payment: &KagemushaWalletPaymentV1,
    ) -> KagemushaWalletLineageMessageV1 {
        let lineage = payment
            .send
            .lineage
            .lineage()
            .expect("payment lineage")
            .clone();
        assert_eq!(
            lineage.public.wallet_id, self.payer.credential.body.wallet_id,
            "the payer's Ω"
        );
        KagemushaWalletLineageMessageV1::new(lineage)
    }

    fn control(
        &self,
        kind: KagemushaWalletSessionControlKindV1,
    ) -> KagemushaWalletSessionControlV1 {
        let reason = match kind {
            KagemushaWalletSessionControlKindV1::SetupDeclined
            | KagemushaWalletSessionControlKindV1::ReceiveDeferred => 7,
            _ => 0,
        };
        let credit_id = if kind == KagemushaWalletSessionControlKindV1::ReceiveDeferred {
            field_value(0x71)
        } else {
            [0; 32]
        };
        KagemushaWalletSessionControlV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.asset_digest(),
            sender_wallet_id: self.payer.credential.body.wallet_id,
            peer_wallet_id: self.receiver.credential.body.wallet_id,
            session_nonce: SESSION_NONCE,
            kind,
            reason,
            credit_id,
            auth: KagemushaWalletSessionAuthV1::Unsigned,
        }
    }

    fn signed_control(
        &self,
        kind: KagemushaWalletSessionControlKindV1,
    ) -> KagemushaWalletSessionControlV1 {
        let control = self.control(kind);
        control
            .sign(
                &self.payer.credential,
                raw_output(&self.payer.payment, &control.signing_message()),
            )
            .expect("signed control")
    }

    fn policy_data(&self, item: KagemushaWalletPolicyDataItemV1) -> KagemushaWalletPolicyDataV1 {
        KagemushaWalletPolicyDataV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.asset_digest(),
            item,
        }
    }
}

/// Credential of a different wallet that reuses `f`'s payment key (another enrollment).
fn same_key_credential(f: &IdentityFixture) -> KagemushaWalletCredentialV1 {
    let mut body = f.credential.body;
    body.enrollment_id = kagemusha_wallet_enrollment_id_v1(&[0x3c; 32], &body.payment_key);
    body.wallet_id = kagemusha_wallet_id_v1(
        &body.scheme_id,
        &body.asset_digest,
        &body.payment_key,
        &body.enrollment_id,
    );
    f.issue(&body).expect("same-key credential")
}

/// Renewed credential of `f`: renewal sequence 1 with fresh evidence.
fn renewed_credential(f: &IdentityFixture) -> KagemushaWalletCredentialV1 {
    let mut body = f.credential.body;
    body.renewal_sequence = 1;
    body.issued_at_ms += 60_000;
    body.fresh_evidence.time_ms = body.issued_at_ms - 500;
    f.issue(&body).expect("renewed credential")
}

#[track_caller]
fn assert_invalid<T: core::fmt::Debug>(result: WalletResult<T>, expected: &str) {
    match result {
        Err(KagemushaWalletValidationErrorV1::InvalidField { field }) if field == expected => {}
        other => panic!("expected invalid `{expected}`, got {other:?}"),
    }
}

#[track_caller]
fn assert_mismatch<T: core::fmt::Debug>(result: WalletResult<T>, expected: &str) {
    match result {
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { field }) if field == expected => {}
        other => panic!("expected scheme mismatch `{expected}`, got {other:?}"),
    }
}

#[track_caller]
fn assert_signature<T: core::fmt::Debug>(result: WalletResult<T>, expected: Domain) {
    match result {
        Err(KagemushaWalletValidationErrorV1::InvalidSignature { domain })
            if domain == expected => {}
        other => panic!(
            "expected invalid `{}` signature, got {other:?}",
            expected.as_str()
        ),
    }
}

#[track_caller]
fn assert_too_large<T: core::fmt::Debug>(result: WalletResult<T>, expected_max: usize) {
    match result {
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { max, .. })
            if max == expected_max => {}
        other => panic!("expected frame bound {expected_max}, got {other:?}"),
    }
}

/// One message of every kind, in tag order.
fn sample_messages(f: &MessageFixture) -> [KagemushaWalletMessageV1; 7] {
    let payment = f.payment(true, 128);
    [
        KagemushaWalletMessageV1::Offer { offer: f.offer() },
        KagemushaWalletMessageV1::Request {
            request: f.request(true),
        },
        KagemushaWalletMessageV1::Payment {
            payment: payment.clone(),
        },
        KagemushaWalletMessageV1::Credited {
            credited: f.credited_receive(&payment, 96),
        },
        KagemushaWalletMessageV1::SessionControl {
            control: f.signed_control(KagemushaWalletSessionControlKindV1::Close),
        },
        KagemushaWalletMessageV1::PolicyData {
            data: f.policy_data(KagemushaWalletPolicyDataItemV1::SchemePolicy {
                policy: f.scheme_policy(2, 0, [0; 32]),
            }),
        },
        KagemushaWalletMessageV1::Lineage {
            lineage: f.lineage_message(&payment),
        },
    ]
}

#[test]
fn kagemusha_wallet_v1_message_transcript_lengths_are_pinned() {
    assert_eq!(KAGEMUSHA_WALLET_OFFER_BODY_TRANSCRIPT_BYTES_V1, 194);
    assert_eq!(KAGEMUSHA_WALLET_REQUEST_BODY_TRANSCRIPT_BYTES_V1, 458);
    assert_eq!(KAGEMUSHA_WALLET_PAYMENT_TRANSCRIPT_BYTES_V1, 163);
    assert_eq!(KAGEMUSHA_WALLET_CREDIT_STATUS_TRANSCRIPT_BYTES_V1, 162);
    assert_eq!(KAGEMUSHA_WALLET_CREDITED_TRANSCRIPT_BYTES_V1, 99);
    assert_eq!(KAGEMUSHA_WALLET_CREDIT_OPENING_TRANSCRIPT_BYTES_V1, 1_125);
    assert_eq!(KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1, 32);
    assert_eq!(KAGEMUSHA_WALLET_SESSION_CONTROL_UNION_BYTES_V1, 34);
    assert_eq!(
        KAGEMUSHA_WALLET_SESSION_CONTROL_BODY_TRANSCRIPT_BYTES_V1,
        197
    );
    assert_eq!(max_width_v1(&[3, 9, 1]), 9);
    assert_eq!(max_width_v1(&[]), 0);
    for kind in KagemushaWalletSessionControlKindV1::ALL {
        assert!(kind.fields_bytes() <= KAGEMUSHA_WALLET_SESSION_CONTROL_UNION_BYTES_V1);
    }
    assert_eq!(
        KagemushaWalletSessionControlKindV1::ReceiveDeferred.fields_bytes(),
        KAGEMUSHA_WALLET_SESSION_CONTROL_UNION_BYTES_V1
    );

    let f = message_fixture();
    let offer = f.offer();
    assert_eq!(
        offer.body.transcript().len(),
        KAGEMUSHA_WALLET_OFFER_BODY_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(
        offer.body.signing_message(),
        kagemusha_wallet_signing_message_v1(Domain::Offer, &offer.body.transcript())
    );
    assert_eq!(KAGEMUSHA_WALLET_REQUEST_BODY_TRANSCRIPT_BYTES_V1, 458);
    assert_eq!(KAGEMUSHA_WALLET_REQUEST_BODY_FIELD_ITEMS_V1, 26);
    let request = f.request(true);
    let transcript = request.body.transcript();
    assert_eq!(
        transcript.len(),
        KAGEMUSHA_WALLET_REQUEST_BODY_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(&transcript[..2], &[1, 0]);
    // The account digests follow their wallets (owner answer A5).
    assert_eq!(&transcript[66..98], &request.body.payer_wallet_id);
    assert_eq!(&transcript[98..130], &request.body.payer_account_digest);
    assert_eq!(&transcript[130..162], &request.body.receiver_wallet_id);
    assert_eq!(&transcript[162..194], &request.body.receiver_account_digest);
    assert_eq!(
        &transcript[354..362],
        &request.body.receiver_blacklist_version.to_le_bytes()
    );
    assert_eq!(&transcript[362..394], &request.body.receiver_blacklist_root);
    assert_eq!(&transcript[394..426], &request.body.certificates);
    assert_eq!(&transcript[426..458], &request.body.nonce);
    assert_eq!(
        request.body.payer_account_digest,
        f.payer.credential.body.account_digest
    );
    assert_eq!(
        request.body.receiver_account_digest,
        f.receiver.credential.body.account_digest
    );
    // credit_id binds the 26 current Request elements, including the recorded decision.
    let items = request.body.field_items();
    assert_eq!(items.len(), KAGEMUSHA_WALLET_REQUEST_BODY_FIELD_ITEMS_V1);
    assert_eq!(items[0], kagemusha_wallet_field_from_u128_v1(1));
    let limbs = |digest: &[u8; 32]| {
        let mut low = [0_u8; 32];
        let mut high = [0_u8; 32];
        low[..16].copy_from_slice(&digest[..16]);
        high[..16].copy_from_slice(&digest[16..]);
        [low, high]
    };
    assert_eq!(items[7..9], limbs(&request.body.payer_account_digest));
    assert_eq!(items[11..13], limbs(&request.body.receiver_account_digest));
    assert_eq!(
        items[13],
        kagemusha_wallet_field_from_u128_v1(request.body.send_ordinal)
    );
    assert_eq!(items[14], request.body.receiver_credential_digest);
    assert_eq!(items[15], kagemusha_wallet_field_from_u128_v1(1_000));
    assert_eq!(items[16], request.body.fee_schedule);
    assert_eq!(items[19], request.body.scheme_policy);
    assert_eq!(
        items[20],
        kagemusha_wallet_field_from_u128_v1(u128::from(ACCEPTED_MS))
    );
    assert_eq!(items[21], kagemusha_wallet_field_from_u128_v1(0));
    assert_eq!(items[22], request.body.receiver_blacklist_root);
    assert_eq!(items[23], request.body.certificates);
    assert_eq!(items[24..26], limbs(&request.body.nonce));
    for (index, account) in [(7, 0), (11, 1)] {
        let mut other = request.body;
        if account == 0 {
            other.payer_account_digest[0] ^= 1;
        } else {
            other.receiver_account_digest[31] ^= 1;
        }
        assert_ne!(other.credit_id(), request.credit_id(), "element {index}");
    }
    assert_eq!(
        Some(request.credit_id()),
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_CREDIT_DOMAIN_V1, &items).ok()
    );
    assert!(kagemusha_wallet_is_canonical_field_v1(&request.credit_id()));
    assert_ne!(request.credit_id(), request.body.signing_message());
    let mut other = request.body;
    other.nonce[31] ^= 1;
    assert_ne!(other.credit_id(), request.credit_id());
    assert_eq!(
        request.request_digest(),
        kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::Request,
            &request.body.signing_message(),
            &request.signature
        )
    );
    let mut recorded = request.body;
    recorded.receiver_blacklist_version = 1;
    recorded.receiver_blacklist_root = field_value(0x39);
    recorded.validate().expect("recorded pair");
    assert_ne!(recorded.credit_id(), request.credit_id());
    assert_ne!(recorded.signing_message(), request.body.signing_message());
    let mut changed_record = request.signed();
    changed_record.body = recorded;
    assert!(matches!(
        changed_record.verify(&request.receiver_credential),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature {
            domain: Domain::Request
        })
    ));
    assert_eq!(request.signed().request_digest(), request.request_digest());
    assert_eq!(request.signed().credit_id(), request.credit_id());

    let control = f.control(KagemushaWalletSessionControlKindV1::ReceiveDeferred);
    let transcript = control.transcript();
    assert_eq!(
        transcript.len(),
        KAGEMUSHA_WALLET_SESSION_CONTROL_BODY_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(transcript[162], 3);
    assert_eq!(&transcript[163..165], &7_u16.to_le_bytes());
    assert_eq!(&transcript[165..], &field_value(0x71));

    let payment = f.payment(true, 64);
    let digests = payment.digests().expect("payment");
    assert_eq!(
        kagemusha_wallet_payment_transcript_v1(
            &digests.request,
            &payment.payer_payment_key,
            &digests.payer_credential,
            &digests.package.package,
        )
        .len(),
        KAGEMUSHA_WALLET_PAYMENT_TRANSCRIPT_BYTES_V1
    );
    let opening = f
        .credit_status(&payment, 32, OPENING_OTHER_CREDITS, false)
        .opening;
    assert_eq!(
        opening.transcript().expect("opening").len(),
        KAGEMUSHA_WALLET_CREDIT_OPENING_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(KAGEMUSHA_WALLET_CREDIT_OPENING_TRANSCRIPT_BYTES_V1, 1_125);
}

#[test]
fn kagemusha_wallet_v1_message_enum_tags_equal_norito_tags() {
    for kind in KagemushaWalletSessionControlKindV1::ALL {
        assert_eq!(norito_tag(&kind), u32::from(kind.tag()));
    }
    let f = message_fixture();
    let slots = [
        KagemushaWalletFeeScheduleSlotV1::None,
        KagemushaWalletFeeScheduleSlotV1::Present {
            schedule: f.fee_schedule(),
        },
    ];
    for (tag, slot) in slots.iter().enumerate() {
        assert_eq!(usize::from(slot.tag()), tag);
        assert_eq!(norito_tag(slot), u32::from(slot.tag()));
    }
    let auths = [
        KagemushaWalletSessionAuthV1::Unsigned,
        KagemushaWalletSessionAuthV1::Signed {
            signature: f.offer().signature,
        },
    ];
    for (tag, auth) in auths.iter().enumerate() {
        assert_eq!(usize::from(auth.tag()), tag);
        assert_eq!(norito_tag(auth), u32::from(auth.tag()));
    }
    let payment = f.payment(false, 32);
    let receive = f.credited_receive(&payment, 32).evidence;
    let status = f.credited_status(&payment, 32, 2).evidence;
    assert_eq!((receive.tag(), status.tag()), (1, 2));
    assert_eq!(norito_tag(&receive), 1);
    assert_eq!(norito_tag(&status), 2);
    let items = [
        KagemushaWalletPolicyDataItemV1::SchemePolicy {
            policy: f.scheme_policy(1, 0, [0; 32]),
        },
        KagemushaWalletPolicyDataItemV1::FeeSchedule {
            schedule: f.fee_schedule(),
        },
        KagemushaWalletPolicyDataItemV1::Certificates {
            certificates: KagemushaWalletCertificateSetV1::new(vec![f.regulator_certificate])
                .expect("set"),
        },
    ];
    for (index, item) in items.iter().enumerate() {
        assert_eq!(usize::from(item.tag()), index + 1);
        assert_eq!(norito_tag(item), u32::from(item.tag()));
    }
    for (index, message) in sample_messages(&f).iter().enumerate() {
        assert_eq!(usize::from(message.tag()), index + 1);
        assert_eq!(norito_tag(message), u32::from(message.tag()));
    }
}

#[test]
fn kagemusha_wallet_v1_offer_binds_the_payer() {
    let f = message_fixture();
    let offer = f.offer();
    offer.validate().expect("offer");
    offer.verify(&f.payer.scheme).expect("verify");
    // The carried credential is bounded like a standalone credential frame (§5.1).
    assert!(
        offer
            .payer_credential
            .to_canonical_bytes()
            .expect("credential frame")
            .len()
            <= KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1
    );
    let mut bad_credential = offer.clone();
    bad_credential.payer_credential.body.wallet_id = [0; 32];
    assert!(bad_credential.validate().is_err());
    let other = identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x5f);
    let mut foreign_root = other.scheme;
    foreign_root.scheme_root_key = other.credential.body.payment_key;
    assert_mismatch(offer.verify(&foreign_root), "certificate.scheme_id");

    let mutations: [(OfferBodyMutation, &str); 5] = [
        (|body| body.amount = 0, "offer.amount"),
        (
            |body| body.payer_wallet_id = [0x0c; 32],
            "offer.payer_wallet_id",
        ),
        (
            |body| body.payer_credential_digest = [0x0d; 32],
            "offer.payer_credential_digest",
        ),
        (|body| body.asset_digest = [0x0e; 32], "offer.asset_digest"),
        (|body| body.session_nonce = [0; 32], "offer.session_nonce"),
    ];
    for (mutate, field) in mutations {
        let mut body = f.offer_body();
        mutate(&mut body);
        assert_invalid(f.sign_offer(body), field);
    }
    let mut body = f.offer_body();
    body.scheme_id = [0x0f; 32];
    assert_mismatch(f.sign_offer(body), "offer.scheme_id");

    // The certificate set is exactly the payer issuer certificate.
    let mut extra = offer.clone();
    extra.certificates = KagemushaWalletCertificateSetV1::new(vec![
        f.payer.enrollment_certificate,
        f.regulator_certificate,
    ])
    .expect("set");
    assert_invalid(extra.validate(), "certificates.set");
    let mut other_issuer = offer.clone();
    other_issuer.certificates =
        KagemushaWalletCertificateSetV1::new(vec![f.receiver.enrollment_certificate]).expect("set");
    assert_invalid(other_issuer.validate(), "certificates.set");

    let mut tampered = offer.clone();
    tampered.body.next_send += 1;
    assert_signature(tampered.validate(), Domain::Offer);
    assert_signature(
        KagemushaWalletOfferV1::sign(
            f.offer_body(),
            f.payer.credential,
            &f.payer.enrollment_certificate,
            raw_output(&f.receiver.payment, &f.offer_body().signing_message()),
        ),
        Domain::Offer,
    );

    let frame = norito::encode_canonical(&offer).expect("encode");
    assert_every_flip_rejected_or_rebound(&frame, offer.body.signing_message(), |bytes| {
        let offer: KagemushaWalletOfferV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1).ok()?;
        offer.validate().ok()?;
        Some(offer.body.signing_message())
    });
}

#[test]
fn kagemusha_wallet_v1_request_fee_and_certificate_rules() {
    let f = message_fixture();
    for fee in [false, true] {
        let request = f.request(fee);
        request.validate().expect("request");
        request.verify(&f.payer.scheme).expect("verify");
        assert_eq!(request.body.fee, if fee { 6 } else { 0 });
        assert_eq!(request.certificates.len(), if fee { 2 } else { 1 });
    }
    // 25 bp of 1,000 is 2.5, rounded up to 3, plus the fixed 3.
    assert_eq!(f.fee_schedule().fee(1_000).expect("fee"), 6);

    let body_mutations: [(RequestBodyMutation, &str); 13] = [
        (|body| body.amount = 0, "request.amount"),
        (
            |body| body.payer_wallet_id = body.receiver_wallet_id,
            "request.payer_wallet_id",
        ),
        (|body| body.fee = u128::MAX, "request.gross"),
        (|body| body.policy_epoch = 0, "request.scheme_policy"),
        (|body| body.nonce = [0; 32], "request.nonce"),
        (
            |body| body.receiver_blacklist_version = 1,
            "request.receiver_blacklist",
        ),
        (
            |body| body.receiver_blacklist_root = field_value(0x39),
            "request.receiver_blacklist",
        ),
        (
            |body| body.receiver_blacklist_root = [0xff; 32],
            "request.receiver_blacklist_root",
        ),
        (
            |body| body.receiver_wallet_id = [0x0c; 32],
            "request.receiver_wallet_id",
        ),
        (
            |body| body.receiver_credential_digest = [0x0d; 32],
            "request.receiver_credential_digest",
        ),
        (
            |body| body.asset_digest = [0x0e; 32],
            "request.asset_digest",
        ),
        (|body| body.fee += 1, "request.fee"),
        (
            |body| body.certificates = [0x0f; 32],
            "request.certificates",
        ),
    ];
    for (mutate, field) in body_mutations {
        let (mut body, slot, certificates) = f.request_parts(true, 1_000);
        mutate(&mut body);
        let result = f.sign_request(&body, slot, certificates);
        if field == "request.gross" {
            assert!(matches!(
                result,
                Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow {
                    field: "request.gross"
                })
            ));
        } else {
            assert_invalid(result, field);
        }
    }
    let (mut body, slot, certificates) = f.request_parts(true, 1_000);
    body.scheme_id = [0x10; 32];
    assert_mismatch(
        f.sign_request(&body, slot, certificates),
        "request.scheme_id",
    );

    // A fee without a schedule, and a schedule slot that disagrees with the body.
    let (mut body, _, _) = f.request_parts(false, 1_000);
    body.fee = 6;
    let (_, none, certificates) = f.request_parts(false, 1_000);
    assert_invalid(f.sign_request(&body, none, certificates), "request.fee");
    let (mut body, none, certificates) = f.request_parts(false, 1_000);
    body.fee_schedule = [0x12; 32];
    assert_invalid(
        f.sign_request(&body, none, certificates),
        "request.fee_schedule",
    );
    let (mut body, slot, certificates) = f.request_parts(true, 1_000);
    body.fee_schedule = [0x13; 32];
    assert_invalid(
        f.sign_request(&body, slot, certificates),
        "request.fee_schedule",
    );
    let mut foreign_asset = f.fee_body();
    foreign_asset.asset_digest = [0x14; 32];
    let (body, _, certificates) = f.request_parts(true, 1_000);
    assert_invalid(
        f.sign_request(
            &body,
            KagemushaWalletFeeScheduleSlotV1::Present {
                schedule: f.sign_fee_schedule(foreign_asset),
            },
            certificates,
        ),
        "fee_schedule.asset_digest",
    );
    // A schedule whose signer certificate has another role.
    let (mut body, _, _) = f.request_parts(true, 1_000);
    let mut wrong_role = f.fee_schedule();
    wrong_role.body.signer_certificate = f.receiver.enrollment_certificate.certificate_digest();
    let wrong_slot = KagemushaWalletFeeScheduleSlotV1::Present {
        schedule: wrong_role,
    };
    body.fee_schedule = wrong_slot.fee_schedule_digest();
    let wrong_set =
        KagemushaWalletCertificateSetV1::new(vec![f.receiver.enrollment_certificate]).expect("set");
    body.certificates = wrong_set.digest().expect("digest");
    assert_invalid(
        f.sign_request(&body, wrong_slot, wrong_set),
        "certificate.role",
    );

    // The certificate set is exactly the receiver issuer and the fee signer.
    let (body, slot, _) = f.request_parts(true, 1_000);
    let missing =
        KagemushaWalletCertificateSetV1::new(vec![f.receiver.enrollment_certificate]).expect("set");
    let mut missing_body = body;
    missing_body.certificates = missing.digest().expect("digest");
    assert_invalid(
        f.sign_request(&missing_body, slot, missing),
        "certificates.set",
    );
    let (body, none, _) = f.request_parts(false, 1_000);
    let extra = KagemushaWalletCertificateSetV1::new(vec![
        f.receiver.enrollment_certificate,
        f.regulator_certificate,
    ])
    .expect("set");
    let mut extra_body = body;
    extra_body.certificates = extra.digest().expect("digest");
    assert_invalid(f.sign_request(&extra_body, none, extra), "certificates.set");

    let mut tampered = f.request(true);
    tampered.body.receiver_accepted_time_ms += 1;
    assert_signature(tampered.validate(), Domain::Request);

    let request = f.request(true);
    let frame = norito::encode_canonical(&request).expect("encode");
    assert_every_flip_rejected_or_rebound(&frame, request.request_digest(), |bytes| {
        let request: KagemushaWalletRequestV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).ok()?;
        request.validate().ok()?;
        Some(request.request_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_signed_request_body() {
    let f = message_fixture();
    let request = f.request(true);
    let signed = request.signed();
    signed.validate().expect("signed body");
    signed
        .verify(&f.receiver.credential)
        .expect("receiver signature");
    // Another credential, even of the same receiver key, is not the bound one.
    assert_invalid(
        signed.verify(&renewed_credential(&f.receiver)),
        "request.receiver_credential_digest",
    );
    assert_invalid(
        signed.verify(&f.payer.credential),
        "request.receiver_credential_digest",
    );
    let mut tampered = signed;
    tampered.body.amount += 1;
    assert_signature(tampered.verify(&f.receiver.credential), Domain::Request);
    let mut zero = signed;
    zero.body.nonce = [0; 32];
    assert_invalid(zero.validate(), "request.nonce");
    let frame = norito::encode_canonical(&signed).expect("encode");
    let decoded: KagemushaWalletSignedRequestV1 =
        decode_frame_v1(&frame, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).expect("decode");
    assert_eq!(decoded, signed);
}

#[test]
fn kagemusha_wallet_v1_send_rule_and_send_effect() {
    let f = message_fixture();
    let request = f.request(true);
    let state = f.payer_state(&request);
    let omega = f.payer_omega(&state);
    // Ω is the one recorded for this head: its head is the payer state's computed commitment.
    request
        .check_send_rule(&f.payer.credential, &state, &omega)
        .expect("send rule");
    let rule = |state: &KagemushaWalletStateV1| {
        request.check_send_rule(&f.payer.credential, state, &f.payer_omega(state))
    };

    let mut no_policy = state;
    let bootstrap = KagemushaWalletStateV1::bootstrap(&f.payer.credential, field_value(0x5d))
        .expect("bootstrap");
    no_policy.core.policy_epoch = 0;
    no_policy.core.enabled_controls = 0;
    no_policy.rest = bootstrap.rest;
    assert_invalid(rule(&no_policy), "request.policy_epoch");
    let refreshed = |epoch: u64, enabled: u32, fee_schedule: [u8; 32]| {
        let mut payer = no_policy;
        let policy = f.scheme_policy(epoch, enabled, fee_schedule);
        let refresh = payer
            .refresh_policy(KagemushaWalletPolicyUpdateV1::SchemePolicy { policy: &policy })
            .expect("refresh");
        payer.core = refresh.core;
        payer.rest = refresh.rest;
        payer.core.balance = state.core.balance;
        payer.core.next_send = state.core.next_send;
        payer
    };
    // Same epoch, another policy object.
    assert_invalid(
        rule(&refreshed(1, 1, request.body.fee_schedule)),
        "request.scheme_policy",
    );
    // A newer payer epoch with the same fee schedule is accepted.
    rule(&refreshed(2, 1, request.body.fee_schedule)).expect("newer epoch");
    assert_invalid(rule(&refreshed(2, 0, [0; 32])), "request.fee_schedule");
    let mut ordinal = state;
    ordinal.core.next_send += 1;
    assert_invalid(rule(&ordinal), "request.send_ordinal");
    // The spendable value is balance − Ω(pred).burned_total (§3.2).
    let mut poor = state;
    poor.core.balance = 1_005;
    assert_invalid(rule(&poor), "state.spendable");
    poor.core.balance = 1_006;
    rule(&poor).expect("exact gross balance");
    let mut burned = f.payer_omega(&poor);
    burned.burned_total = 1;
    assert_invalid(
        request.check_send_rule(&f.payer.credential, &poor, &burned),
        "state.spendable",
    );
    // Ω must be the one recorded for this head, this wallet's, under this credential and key.
    assert_invalid(
        request.check_send_rule(&f.payer.credential, &poor, &omega),
        "lineage.head",
    );
    let mut foreign = omega;
    foreign.wallet_id = [0x41; 32];
    assert_invalid(
        request.check_send_rule(&f.payer.credential, &state, &foreign),
        "lineage.wallet_id",
    );
    let mut other_key = omega;
    other_key.payment_key = f.receiver.credential.body.payment_key;
    assert_invalid(
        request.check_send_rule(&f.payer.credential, &state, &other_key),
        "lineage.payment_key",
    );

    // A wallet that reuses the receiver's payment key cannot pay it.
    let same_key = same_key_credential(&f.receiver);
    let (mut body, slot, certificates) = f.request_parts(true, 1_000);
    body.payer_wallet_id = same_key.body.wallet_id;
    body.payer_account_digest = same_key.body.account_digest;
    // The ordinary fixture Offer names another payer, so canonical construction refuses it.
    assert_invalid(
        f.sign_request(&body, slot, certificates.clone()),
        "request.payer_wallet_id",
    );
    // Even an authenticated Offer naming this payer cannot reuse the receiver payment key.
    let mut offer_body = f.offer().body;
    offer_body.payer_wallet_id = same_key.body.wallet_id;
    offer_body.payer_credential_digest = same_key.credential_digest();
    let same_key_offer = KagemushaWalletOfferV1::sign(
        offer_body,
        same_key,
        &f.receiver.enrollment_certificate,
        raw_output(&f.receiver.payment, &offer_body.signing_message()),
    )
    .expect("authenticated same-key Offer");
    same_key_offer
        .verify(&f.payer.scheme)
        .expect("same-key issuer");
    assert_invalid(
        KagemushaWalletRequestV1::sign(
            &f.payer.scheme,
            &same_key_offer,
            body,
            f.receiver.credential,
            slot,
            certificates.clone(),
            raw_output(&f.receiver.payment, &body.signing_message()),
        ),
        "request.payment_key",
    );
    // Build a receiver-signed adversarial object directly in this test: no canonical constructor
    // is bypassed in production, and the retained Send rule must independently refuse it.
    let same_key_request = KagemushaWalletRequestV1 {
        body,
        receiver_credential: f.receiver.credential,
        fee_schedule: slot,
        certificates,
        signature: kagemusha_wallet_freeze_signature_v1(
            &f.receiver.credential.body.payment_key,
            Domain::Request,
            &body.signing_message(),
            raw_output(&f.receiver.payment, &body.signing_message()),
        )
        .expect("adversarial receiver signature"),
    };
    same_key_request
        .validate()
        .expect("receiver-authenticated shape");
    let mut same_key_state =
        KagemushaWalletStateV1::bootstrap(&same_key, field_value(0x5d)).expect("state");
    same_key_state.core.policy_epoch = state.core.policy_epoch;
    same_key_state.rest.scheme_policy = state.rest.scheme_policy;
    same_key_state.rest.fee_schedule = state.rest.fee_schedule;
    same_key_state.core.balance = state.core.balance;
    same_key_state.core.next_send = state.core.next_send;
    let mut same_key_omega = f.payer_omega(&same_key_state);
    same_key_omega.payment_key = same_key.body.payment_key;
    assert_invalid(
        same_key_request.check_send_rule(&same_key, &same_key_state, &same_key_omega),
        "request.payment_key",
    );
    // The receiver's own state is not the payer.
    let receiver_state =
        KagemushaWalletStateV1::bootstrap(&f.receiver.credential, field_value(0x5d))
            .expect("state");
    let mut receiver_omega = f.payer_omega(&receiver_state);
    receiver_omega.payment_key = f.receiver.credential.body.payment_key;
    assert_invalid(
        request.check_send_rule(&f.receiver.credential, &receiver_state, &receiver_omega),
        "request.payer_wallet_id",
    );

    let interval =
        KagemushaWalletTimeIntervalV1::new(ACCEPTED_MS + 1, ACCEPTED_MS + 9).expect("interval");
    let effect = request
        .send_effect(&f.payer.credential, &interval)
        .expect("effect");
    // The Send binds the exact signed Request by digest, which binds its dependencies (§8).
    assert_eq!(
        effect,
        KagemushaWalletEffectV1::Send {
            credit_id: request.credit_id(),
            receiver_wallet_id: f.receiver.credential.body.wallet_id,
            send_ordinal: 4,
            amount: 1_000,
            fee: 6,
            request: request.request_digest(),
            accepted_lower_ms: ACCEPTED_MS + 1,
            accepted_upper_ms: ACCEPTED_MS + 9,
        }
    );
    let early = KagemushaWalletTimeIntervalV1::new(ACCEPTED_MS - 1, ACCEPTED_MS).expect("interval");
    assert_invalid(
        request.send_effect(&f.payer.credential, &early),
        "effect.accepted_time",
    );
    let inverted = KagemushaWalletTimeIntervalV1 {
        lower_ms: ACCEPTED_MS + 2,
        upper_ms: ACCEPTED_MS + 1,
    };
    assert_invalid(
        request.send_effect(&f.payer.credential, &inverted),
        "effect.accepted_time",
    );

    // Only the payer the Request names can build its irreversible Send effect.
    assert_invalid(
        request.send_effect(&f.receiver.credential, &interval),
        "request.payer_wallet_id",
    );
    let stranger = identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox, 0x5f);
    assert_invalid(
        request.send_effect(&stranger.credential, &interval),
        "request.payer_wallet_id",
    );
    let mut body = f.payer.credential.body;
    body.asset_digest = [0x77; 32];
    body.wallet_id = kagemusha_wallet_id_v1(
        &body.scheme_id,
        &body.asset_digest,
        &body.payment_key,
        &body.enrollment_id,
    );
    let other_asset = f.payer.issue(&body).expect("other asset credential");
    assert_invalid(
        request.send_effect(&other_asset, &interval),
        "request.payer_credential.asset_digest",
    );
    assert_invalid(
        same_key_request.send_effect(&same_key, &interval),
        "request.payment_key",
    );
}

#[test]
fn kagemusha_wallet_v1_payment_digests_and_bindings() {
    let f = message_fixture();
    for fee in [false, true] {
        let payment = f.payment(fee, 64);
        let request = f.request(fee);
        let digests = payment.digests().expect("payment");
        assert_eq!(
            payment
                .verify(
                    &f.payer.scheme,
                    &f.payer.credential,
                    &KagemushaWalletCertificateSetV1::new(vec![f.payer.enrollment_certificate])
                        .expect("set"),
                    &request,
                )
                .expect("verify"),
            digests
        );
        assert_eq!(payment.request, request.signed());
        assert_eq!(
            payment.payer_payment_key,
            f.payer.credential.body.payment_key
        );
        assert_eq!(digests.credit_id, request.credit_id());
        assert_eq!(digests.request, request.request_digest());
        assert_eq!(
            digests.payer_credential,
            f.payer.credential.credential_digest()
        );
        assert_eq!(
            digests.package,
            payment.send.verify(&f.payer.credential).expect("package")
        );
        let mut transcript = vec![1, 0];
        transcript.extend_from_slice(&digests.request);
        transcript.extend_from_slice(payment.payer_payment_key.as_sec1_bytes());
        transcript.extend_from_slice(&digests.payer_credential);
        transcript.extend_from_slice(&digests.package.package);
        assert_eq!(
            transcript,
            kagemusha_wallet_payment_transcript_v1(
                &digests.request,
                &payment.payer_payment_key,
                &digests.payer_credential,
                &digests.package.package,
            )
        );
        // The Payment digest is P_bytes(kgwpay_1, transcript): one canonical σ-field value
        // (owner answer Q9).
        assert_eq!(
            digests.payment,
            kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_PAYMENT_DOMAIN_V1, &transcript)
        );
        assert!(kagemusha_wallet_is_canonical_field_v1(&digests.payment));
        assert_eq!(payment.payment_digest().expect("digest"), digests.payment);
        payment.validate().expect("validate");

        let pending = payment.pending_outgoing_leaf().expect("leaf");
        assert_eq!(
            pending,
            KagemushaWalletPendingOutgoingLeafV1 {
                credit_id: digests.credit_id,
                receiver_wallet_id: f.receiver.credential.body.wallet_id,
                send_ordinal: 4,
                amount: 1_000,
                fee: request.body.fee,
                request_digest: digests.request,
            }
        );
        assert_eq!(
            payment
                .send_chain_entry()
                .expect("send chain")
                .field_items()
                .ok(),
            pending.field_items().ok()
        );
        // The receiver's leaf and chain entry contain no Payment digest (§3).
        assert_eq!(
            payment.consumed_credit_leaf(6).expect("leaf"),
            KagemushaWalletConsumedCreditLeafV1 {
                credit_id: digests.credit_id,
                amount: 1_000,
                receive_sequence: 6,
            }
        );
        assert_invalid(
            payment.consumed_credit_leaf(0),
            "consumed_credit.receive_sequence",
        );
        assert_eq!(
            payment.recv_chain_entry().expect("recv chain"),
            KagemushaWalletRecvChainEntryV1 {
                credit_id: digests.credit_id,
                payer_wallet_id: f.payer.credential.body.wallet_id,
                amount: 1_000,
            }
        );
        let fee_leaf = payment.fee_claim_leaf().expect("fee leaf");
        assert_eq!(fee_leaf.is_some(), fee);
        if let Some(leaf) = fee_leaf {
            assert_eq!(leaf.fee, 6);
            assert_eq!(leaf.fee_schedule_digest, request.body.fee_schedule);
        }
        assert_eq!(
            payment
                .receive_effect(
                    &request,
                    &f.receiver.credential,
                    &receiver_head_state(&f.receiver.credential),
                    None,
                )
                .expect("receive"),
            KagemushaWalletEffectV1::Receive {
                credit_id: digests.credit_id,
                payer_wallet_id: f.payer.credential.body.wallet_id,
                amount: 1_000,
            }
        );
        let frame = payment.to_canonical_bytes().expect("frame");
        assert_eq!(
            KagemushaWalletPaymentV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
            payment
        );
        assert_mismatch(
            KagemushaWalletPaymentV1::decode_canonical(&frame, &[0x22; 32]),
            "payment.scheme_id",
        );
    }

    let payment = f.payment(true, 64);
    let request = f.request(true);
    let payer_set =
        KagemushaWalletCertificateSetV1::new(vec![f.payer.enrollment_certificate]).expect("set");
    // The receiver is matched by the Request's receiver wallet and its receiver credential's
    // payment key, never by credential digest: a Request quoted before a renewal stays
    // receivable after it (owner answer Q8).
    let renewed = renewed_credential(&f.receiver);
    assert_ne!(
        renewed.credential_digest(),
        request.body.receiver_credential_digest
    );
    let receiver_state = receiver_head_state(&f.receiver.credential);
    assert_eq!(
        payment
            .receive_effect(&request, &renewed, &receiver_head_state(&renewed), None)
            .expect("renewed receiver"),
        payment
            .receive_effect(&request, &f.receiver.credential, &receiver_state, None)
            .expect("receiver")
    );
    assert_invalid(
        payment.receive_effect(
            &request,
            &f.payer.credential,
            &receiver_head_state(&f.payer.credential),
            None,
        ),
        "payment.receiver_wallet_id",
    );
    assert_invalid(
        payment.receive_effect(
            &f.request(false),
            &f.receiver.credential,
            &receiver_state,
            None,
        ),
        "payment.request",
    );
    // The receiver state must be the receiver credential's own head.
    assert_invalid(
        payment.receive_effect(&request, &renewed, &receiver_state, None),
        "state.core.credential_digest",
    );

    let mut version = payment.clone();
    version.version = 2;
    assert!(matches!(
        version.digests(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "payment.version",
            version: 2
        })
    ));

    // §3.2 Payment consumer checks: a Request payer other than Ω.wallet_id, and a
    // relay-rewritten payment key or credential digest (§11).
    let mut wrong_payer = payment.clone();
    wrong_payer.request.body.payer_wallet_id = [0x44; 32];
    assert_invalid(wrong_payer.validate(), "payment.payer_wallet_id");
    let mut rewritten_credential = payment.clone();
    rewritten_credential.payer_credential_digest = [0x45; 32];
    assert_invalid(
        rewritten_credential.validate(),
        "payment.payer_credential_digest",
    );
    let mut rewritten_key = payment.clone();
    rewritten_key.payer_payment_key = f.receiver.credential.body.payment_key;
    assert_invalid(rewritten_key.validate(), "payment.payer_payment_key");
    let mut no_lineage = payment.clone();
    no_lineage.send.lineage = KagemushaWalletLineageSlotV1::None;
    assert_invalid(no_lineage.validate(), "lineage.slot");
    let mut stale_epoch = payment.clone();
    let statement = stale_epoch.send.statement;
    let mut lineage = f.payer_lineage(&statement, PAYMENT_LINEAGE_LEN);
    lineage.public.policy_epoch = 0;
    stale_epoch.send = signed_package_with(
        &f.payer,
        &f.payer.credential,
        &statement,
        KagemushaWalletLineageSlotV1::Present { lineage },
        stand_in_proof(64),
        [0; 32],
    );
    assert_invalid(stale_epoch.validate(), "payment.policy_epoch");

    // Session verification: the held Request, the payer credential from the Offer.
    assert_invalid(
        payment.verify(
            &f.payer.scheme,
            &f.payer.credential,
            &payer_set,
            &f.request(false),
        ),
        "payment.request",
    );
    assert_invalid(
        payment.verify(
            &f.payer.scheme,
            &f.receiver.credential,
            &payer_set,
            &request,
        ),
        "request.payer_wallet_id",
    );
    assert_invalid(
        payment.verify(
            &f.payer.scheme,
            &renewed_credential(&f.payer),
            &payer_set,
            &request,
        ),
        "payment.payer_credential_digest",
    );
    assert!(
        payment
            .verify(
                &f.payer.scheme,
                &f.payer.credential,
                &KagemushaWalletCertificateSetV1::new(vec![f.receiver.enrollment_certificate])
                    .expect("set"),
                &request,
            )
            .is_err()
    );
    let mut foreign = f.payer.scheme;
    foreign.relation_id = [0x35; 32];
    assert!(
        payment
            .verify(&foreign, &f.payer.credential, &payer_set, &request)
            .is_err()
    );

    // Every Send effect field is bound to the Request.
    let base = payment.send.statement.effect;
    assert!(matches!(base, KagemushaWalletEffectV1::Send { .. }));
    let send_with = |effect: KagemushaWalletEffectV1| {
        let mut mutated = payment.clone();
        mutated.send = f.send_package_for(&f.payer_statement(effect), PAYMENT_LINEAGE_LEN, 64);
        mutated.validate()
    };
    let mutations: [(EffectMutation, &str); 7] = [
        (
            |effect| {
                if let KagemushaWalletEffectV1::Send { credit_id, .. } = effect {
                    *credit_id = [0x31; 32];
                }
            },
            "payment.effect.credit_id",
        ),
        (
            |effect| {
                if let KagemushaWalletEffectV1::Send {
                    receiver_wallet_id, ..
                } = effect
                {
                    *receiver_wallet_id = [0x32; 32];
                }
            },
            "payment.effect.receiver_wallet_id",
        ),
        (
            |effect| {
                if let KagemushaWalletEffectV1::Send { send_ordinal, .. } = effect {
                    *send_ordinal += 1;
                }
            },
            "payment.effect.send_ordinal",
        ),
        (
            |effect| {
                if let KagemushaWalletEffectV1::Send { amount, .. } = effect {
                    *amount += 1;
                }
            },
            "payment.effect.amount",
        ),
        (
            |effect| {
                if let KagemushaWalletEffectV1::Send { fee, .. } = effect {
                    *fee += 1;
                }
            },
            "payment.effect.fee",
        ),
        (
            |effect| {
                if let KagemushaWalletEffectV1::Send { request, .. } = effect {
                    *request = [0x33; 32];
                }
            },
            "payment.effect.request",
        ),
        (
            |effect| {
                if let KagemushaWalletEffectV1::Send {
                    accepted_lower_ms, ..
                } = effect
                {
                    *accepted_lower_ms = ACCEPTED_MS - 1;
                }
            },
            "payment.effect.accepted_time",
        ),
    ];
    for (mutate, field) in mutations {
        let mut effect = base;
        mutate(&mut effect);
        assert_invalid(send_with(effect), field);
    }
    let body = &f.payer.credential.body;
    assert_invalid(
        send_with(KagemushaWalletEffectV1::Unload {
            nullifier: kagemusha_wallet_unload_nullifier_v1(&body.scheme_id, &body.wallet_id, 0),
            redeem_ordinal: 0,
            amount: 1,
            online_charge: 0,
            charge_quote: [0; 32],
        }),
        "payment.effect",
    );

    // A tampered receipt-bound statement and a tampered Request are rejected.
    let mut receipt = payment.clone();
    receipt.send.statement.successor.value[0] ^= 1;
    assert_signature(receipt.validate(), Domain::Receipt);
    let mut request_body = payment.clone();
    request_body.request.body.receiver_accepted_time_ms += 1;
    assert_invalid(request_body.validate(), "payment.effect.credit_id");
    let mut request_signature = payment.clone();
    request_signature.request.signature = f.offer().signature;
    assert_invalid(request_signature.validate(), "payment.effect.request");
    // A Payment consistent with a forged Request signature is structurally valid; the receiver
    // rejects it when it verifies its own held Request.
    let forged_request = KagemushaWalletRequestV1 {
        signature: f.offer().signature,
        ..request.clone()
    };
    let mut forged = payment.clone();
    forged.request = forged_request.signed();
    let mut effect = payment.send.statement.effect;
    if let KagemushaWalletEffectV1::Send { request, .. } = &mut effect {
        *request = forged_request.request_digest();
    }
    forged.send = f.send_package_for(&f.payer_statement(effect), PAYMENT_LINEAGE_LEN, 64);
    forged.validate().expect("structurally valid");
    assert_signature(
        forged.verify(
            &f.payer.scheme,
            &f.payer.credential,
            &payer_set,
            &forged_request,
        ),
        Domain::Request,
    );
}

#[test]
fn kagemusha_wallet_v1_payment_binds_every_byte() {
    let f = message_fixture();
    let payment = f.payment_with(true, 1_200, 1_600);
    let digest = payment.payment_digest().expect("digest");
    let frame = norito::encode_canonical(&payment).expect("encode");
    assert!(frame.len() <= KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1);
    assert_every_flip_rejected_or_rebound(&frame, digest, |bytes| {
        let payment: KagemushaWalletPaymentV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).ok()?;
        payment.payment_digest().ok()
    });
}

#[test]
fn kagemusha_wallet_v1_lineage_message_matches_the_offer() {
    let f = message_fixture();
    let payment = f.payment(false, 32);
    let message = f.lineage_message(&payment);
    message.validate().expect("lineage message");
    message.verify_for_offer(&f.offer()).expect("offer match");
    // Byte-identity reuse compares the lineage digest with the Payment's Ω(pred).
    assert_eq!(
        message.lineage_digest(),
        payment
            .send
            .lineage
            .lineage()
            .expect("lineage")
            .lineage_digest()
    );
    let reject = |mutate: &dyn Fn(&mut KagemushaWalletLineageMessageV1), field: &str| {
        let mut message = message.clone();
        mutate(&mut message);
        assert_invalid(message.verify_for_offer(&f.offer()), field);
    };
    reject(
        &|m| m.lineage.public.wallet_id = [0x46; 32],
        "lineage.wallet_id",
    );
    reject(
        &|m| m.lineage.public.credential_digest = [0x47; 32],
        "lineage.credential_digest",
    );
    reject(
        &|m| m.lineage.public.payment_key = f.receiver.credential.body.payment_key,
        "lineage.payment_key",
    );
    reject(&|m| m.lineage.proof.clear(), "lineage.proof");
    let mut scheme = message.clone();
    scheme.lineage.public.scheme_id = [0x48; 32];
    assert_mismatch(scheme.verify_for_offer(&f.offer()), "lineage.scheme_id");
    let mut version = message.clone();
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "lineage_message.version",
            ..
        })
    ));
    let mut tampered_offer = f.offer();
    tampered_offer.body.amount += 1;
    assert_signature(message.verify_for_offer(&tampered_offer), Domain::Offer);
}

#[test]
fn kagemusha_wallet_v1_credit_opening_layout() {
    let f = message_fixture();
    let payment = f.payment(false, 32);
    let status = f.credit_status(&payment, 32, OPENING_OTHER_CREDITS, true);
    let opening = status.opening.clone();
    opening.validate().expect("opening");
    let digests = payment.digests().expect("digests");
    // The fixture credit was recorded after the other credits, at the next free slot.
    assert_eq!(
        opening.slot,
        u32::try_from(OPENING_OTHER_CREDITS + 1).expect("slot")
    );
    assert_eq!(
        opening.siblings.len(),
        32 * KAGEMUSHA_WALLET_INDEXED_TREE_DEPTH_V1
    );
    let mut expected = digests.credit_id.to_vec();
    expected.extend_from_slice(&digests.payment);
    expected.push(1);
    expected.extend_from_slice(&opening.next_key);
    expected.extend_from_slice(&opening.slot.to_le_bytes());
    expected.extend_from_slice(&opening.siblings);
    assert_eq!(
        expected.len(),
        KAGEMUSHA_WALLET_CREDIT_OPENING_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(opening.transcript().expect("transcript"), expected);
    assert_eq!(
        opening.opening_digest().expect("digest"),
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_CREDIT_OPENING_DOMAIN_V1, &expected)
    );
    assert_eq!(
        opening.leaf(),
        KagemushaWalletCreditDigestLeafV1 {
            credit_id: digests.credit_id,
            payment_digest: digests.payment,
            burned: true,
        }
    );
    // The opening is the indexed tree's membership opening and recomputes Ω(h)'s credit-digest
    // root (owner answer A2).
    let tree = credit_digest_tree(&opening.leaf(), OPENING_OTHER_CREDITS);
    let (indexed, indexed_opening) = tree.membership(&digests.credit_id).expect("member");
    assert_eq!(opening.next_key, indexed.next_key);
    assert_eq!(indexed.value, opening.leaf().leaf_value().expect("value"));
    assert_eq!(opening.indexed_opening().ok(), Some(indexed_opening));
    assert_eq!(tree.root(), status.lineage.public.credit_digest_root);
    assert_eq!(
        opening.root().ok(),
        Some(status.lineage.public.credit_digest_root)
    );
    assert_invalid(
        KagemushaWalletCreditOpeningV1::new(
            &KagemushaWalletCreditDigestLeafV1 {
                burned: false,
                ..opening.leaf()
            },
            &indexed,
            &indexed_opening,
        ),
        "credit_opening.leaf",
    );
    // Exactly 32 canonical siblings, slot at least 1, next key zero or above the credit.
    let mut short = opening.clone();
    short.siblings.truncate(short.siblings.len() - 32);
    assert_invalid(short.validate(), "credit_opening.siblings");
    let mut long = opening.clone();
    long.siblings.extend_from_slice(&[0; 32]);
    assert_invalid(long.validate(), "credit_opening.siblings");
    let mut ragged = opening.clone();
    ragged.siblings.push(0);
    assert_invalid(ragged.validate(), "credit_opening.siblings");
    let mut wide = opening.clone();
    wide.siblings[..32].copy_from_slice(&[0xff; 32]);
    assert_invalid(wide.validate(), "credit_opening.siblings");
    let mut sentinel_slot = opening.clone();
    sentinel_slot.slot = 0;
    assert_invalid(sentinel_slot.validate(), "credit_opening.slot");
    for next_key in [digests.credit_id, [0xff; 32]] {
        let mut bad_next = opening.clone();
        bad_next.next_key = next_key;
        assert_invalid(bad_next.validate(), "credit_opening.next_key");
    }
    let mut zero = opening.clone();
    zero.credit_id = [0; 32];
    assert_invalid(zero.validate(), "credit_opening.credit_id");
    let mut noncanonical = opening.clone();
    noncanonical.credit_id = [0xff; 32];
    assert_invalid(noncanonical.validate(), "credit_opening.credit_id");
    let mut wide_payment = opening.clone();
    wide_payment.payment_digest = [0xff; 32];
    assert_invalid(wide_payment.validate(), "credit_opening.payment_digest");
    // Tampered openings recompute other roots.
    let mut swapped = opening.siblings.clone();
    swapped[..64].rotate_left(32);
    for tampered in [
        KagemushaWalletCreditOpeningV1 {
            burned: false,
            ..opening.clone()
        },
        KagemushaWalletCreditOpeningV1 {
            payment_digest: field_value(0x4d),
            ..opening.clone()
        },
        KagemushaWalletCreditOpeningV1 {
            siblings: swapped,
            ..opening.clone()
        },
        KagemushaWalletCreditOpeningV1 {
            slot: opening.slot ^ 1,
            ..opening.clone()
        },
        KagemushaWalletCreditOpeningV1 {
            next_key: [0; 32],
            ..opening.clone()
        },
    ] {
        if tampered == opening {
            continue;
        }
        assert_ne!(tampered.root().ok(), opening.root().ok());
    }
    // Only a membership opening is evidence: the low-leaf opening of an absent credit, posed as
    // that credit's leaf, recomputes another root.
    let absent = field_value(0x3a);
    assert!(tree.get(&absent).is_none());
    let (low, low_opening) = tree.non_membership(&absent).expect("absent credit");
    let posed = KagemushaWalletCreditOpeningV1 {
        credit_id: absent,
        next_key: low.next_key,
        slot: low_opening.slot.max(1),
        siblings: low_opening.sibling_bytes(),
        ..opening.clone()
    };
    if posed.validate().is_ok() {
        assert_ne!(posed.root().ok(), Some(tree.root()));
    }
    // A non-boolean burned flag does not decode.
    let frame = norito::encode_canonical(&opening).expect("encode");
    let decoded: KagemushaWalletCreditOpeningV1 =
        decode_frame_v1(&frame, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).expect("decode");
    assert_eq!(decoded, opening);
    let unburned = norito::encode_canonical(&KagemushaWalletCreditOpeningV1 {
        burned: false,
        ..opening.clone()
    })
    .expect("encode");
    let flag = payload_range(&frame)
        .find(|index| frame[*index] != unburned[*index])
        .expect("flag byte");
    assert_eq!((frame[flag], unburned[flag]), (1, 0));
    let mut two = frame.clone();
    two[flag] = 2;
    let payload = payload_range(&two);
    let checksum = norito::crc64_fallback(&two[payload]);
    two[31..39].copy_from_slice(&checksum.to_le_bytes());
    assert!(
        decode_frame_v1::<KagemushaWalletCreditOpeningV1>(
            &two,
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
        )
        .is_err()
    );
}

#[test]
fn kagemusha_wallet_v1_credit_status_of_a_folded_head() {
    let f = message_fixture();
    let payment = f.payment(false, 64);
    let request = f.request(false);
    let digests = payment.digests().expect("digests");
    let status = f.credit_status(&payment, 40, OPENING_OTHER_CREDITS, false);
    let digest = status.credit_status_digest().expect("status");
    let receipt = status
        .receipt
        .verify(
            &KagemushaWalletReceiptSignerV1::from_credential(&f.receiver.credential)
                .expect("signer"),
            &status.statement,
            &status.proof_digest,
        )
        .expect("receipt");
    let mut transcript = vec![1, 0];
    transcript.extend_from_slice(
        &status
            .statement
            .statement_digest()
            .expect("statement digest"),
    );
    transcript.extend_from_slice(&status.proof_digest);
    transcript.extend_from_slice(&receipt);
    transcript.extend_from_slice(&status.lineage.lineage_digest());
    transcript.extend_from_slice(&status.opening.opening_digest().expect("opening"));
    assert_eq!(
        digest,
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_CREDIT_STATUS_DOMAIN_V1, &transcript)
    );
    assert_eq!(
        status
            .check_for(&request, &digests.payment)
            .expect("credited"),
        KagemushaWalletDeliveryStatusV1::Credited
    );
    assert_eq!(
        f.credit_status(&payment, 40, OPENING_OTHER_CREDITS, true)
            .check_for(&request, &digests.payment)
            .expect("burned"),
        KagemushaWalletDeliveryStatusV1::Burned
    );

    let reject = |mutate: &dyn Fn(&mut KagemushaWalletCreditStatusV1), field: &str| {
        let mut status = status.clone();
        mutate(&mut status);
        assert_invalid(status.credit_status_digest(), field);
    };
    reject(
        &|s| s.lineage.public.head = commitment(9),
        "credit_status.head",
    );
    // Keep the noncanonical-value refusal distinct from the original credential binding.
    reject(
        &|s| s.lineage.public.credential_digest = [0x49; 32],
        "lineage.credential_digest",
    );
    reject(
        &|s| s.lineage.public.credential_digest = field_value(0x49),
        "credit_status.credential_digest",
    );
    reject(
        &|s| s.lineage.public.lifecycle = KagemushaWalletLifecycleV1::Retiring,
        "credit_status.lifecycle",
    );
    reject(&|s| s.proof_digest = [0; 32], "credit_status.proof_digest");
    reject(
        &|s| s.proof_digest = [0xff; 32],
        "credit_status.proof_digest",
    );
    reject(&|s| s.opening.siblings.clear(), "credit_opening.siblings");
    reject(&|s| s.lineage.proof.clear(), "lineage.proof");
    // The opening is recomputed natively against Ω(h)'s credit-digest root.
    reject(
        &|s| s.lineage.public.credit_digest_root = CREDIT_DIGEST_ROOT,
        "credit_status.opening",
    );
    reject(
        &|s| s.opening.payment_digest = field_value(0x4d),
        "credit_status.opening",
    );
    reject(&|s| s.opening.burned = true, "credit_status.opening");
    reject(
        &|s| s.opening.siblings[..32].copy_from_slice(&field_value(0x4e)),
        "credit_status.opening",
    );
    reject(
        &|s| s.opening.credit_id = field_value(0x4c),
        "credit_status.opening",
    );
    let mut relation = status.clone();
    relation.lineage.public.relation_id = [0x4a; 32];
    assert_mismatch(relation.credit_status_digest(), "credit_status.relation_id");
    // τ(h) verifies under Ω(h).payment_key over the carried statement and proof digest.
    let mut other_key = status.clone();
    other_key.lineage.public.payment_key = f.payer.credential.body.payment_key;
    assert_signature(other_key.credit_status_digest(), Domain::Receipt);
    let mut other_proof = status.clone();
    other_proof.proof_digest = field_value(0x4b);
    assert_signature(other_proof.credit_status_digest(), Domain::Receipt);
    let mut zero_payment = status.clone();
    zero_payment.receipt.payment_digest = [0; 32];
    assert_invalid(
        zero_payment.credit_status_digest(),
        "receipt.payment_digest",
    );

    // Against the payer's held Request and retained Payment.
    let (_, tree) = f.credit_status_under(
        &payment,
        40,
        &MessageFixture::credit_leaf(&payment, false),
        OPENING_OTHER_CREDITS,
        &f.receiver.credential,
        &f.receiver.payment,
    );
    let neighbour = neighbour_credit(1);
    let mut another_credit = status.clone();
    another_credit.opening = credit_opening_in(&tree, &neighbour);
    another_credit
        .validate()
        .expect("a valid opening of another credit");
    assert_invalid(
        another_credit.check_for(&request, &digests.payment),
        "credit_status.credit_id",
    );
    // The recorded Payment digest differs from the retained Payment's.
    let other_record = KagemushaWalletCreditDigestLeafV1 {
        payment_digest: field_value(0x4d),
        ..MessageFixture::credit_leaf(&payment, false)
    };
    let (recorded_other, _) = f.credit_status_under(
        &payment,
        40,
        &other_record,
        OPENING_OTHER_CREDITS,
        &f.receiver.credential,
        &f.receiver.payment,
    );
    assert_invalid(
        recorded_other.check_for(&request, &digests.payment),
        "credit_status.payment_digest",
    );
    assert_invalid(
        status.check_for(&request, &field_value(0x4e)),
        "credit_status.payment_digest",
    );
    let mut other_receiver = request.clone();
    other_receiver.body.receiver_wallet_id = [0x4f; 32];
    assert_invalid(
        status.check_for(&other_receiver, &digests.payment),
        "credit_status.receiver_wallet_id",
    );
    // An absent credit has no opening against Ω(h)'s root: a proof of absence is not evidence.
    // Its low leaf's slot and siblings, posed as the absent credit's leaf, do not recompute it.
    let absent = KagemushaWalletCreditDigestLeafV1 {
        credit_id: field_value(0x3a),
        ..MessageFixture::credit_leaf(&payment, false)
    };
    let (low, low_opening) = tree.non_membership(&absent.credit_id).expect("absent");
    let mut absence = status.clone();
    absence.opening = KagemushaWalletCreditOpeningV1 {
        credit_id: absent.credit_id,
        next_key: low.next_key,
        slot: low_opening.slot.max(1),
        siblings: low_opening.sibling_bytes(),
        ..status.opening.clone()
    };
    if absence.opening.validate().is_ok() {
        assert_invalid(absence.credit_status_digest(), "credit_status.opening");
    }
}

/// Owner answer Q8: a Request quoted before the receiver's credential renewal is received and
/// credited after it; `CreditStatus` matches the receiver by `wallet_id` and `payment_key`, and
/// a receiver Ω with another `payment_key` is rejected.
#[test]
fn kagemusha_wallet_v1_receiver_matching_survives_credential_renewal() {
    let f = message_fixture();
    let payment = f.payment(true, 64);
    let request = f.request(true);
    let digests = payment.digests().expect("digests");
    let renewed = renewed_credential(&f.receiver);
    renewed
        .validate_replacement_of(&f.receiver.credential)
        .expect("renewal");
    assert_eq!(
        renewed.body.payment_key,
        f.receiver.credential.body.payment_key
    );
    assert_eq!(
        request.body.receiver_credential_digest,
        f.receiver.credential.credential_digest()
    );

    // Receive after the renewal: the statement runs under the renewed credential.
    let effect = payment
        .receive_effect(&request, &renewed, &receiver_head_state(&renewed), None)
        .expect("receivable after renewal");
    let receive = f.receive_package_under(&payment, &renewed, 48);
    assert_eq!(receive.statement.effect, effect);
    assert_eq!(
        receive.statement.credential_digest,
        renewed.credential_digest()
    );
    receive
        .verify(&renewed)
        .expect("renewed receiver's package");
    let credited = KagemushaWalletCreditedV1::from_receive(receive).expect("credited");
    let (_, status) = credited
        .verify_for(&f.payer.scheme, &request, &payment)
        .expect("Receive evidence under the renewed credential");
    assert_eq!(status, KagemushaWalletDeliveryStatusV1::CreditedUnfolded);

    // CreditStatus of a folded head under the renewed credential.
    let leaf = MessageFixture::credit_leaf(&payment, false);
    let (renewed_status, _) = f.credit_status_under(
        &payment,
        40,
        &leaf,
        OPENING_OTHER_CREDITS,
        &renewed,
        &f.receiver.payment,
    );
    assert_eq!(
        renewed_status.lineage.public.credential_digest,
        renewed.credential_digest()
    );
    assert_eq!(
        renewed_status.check_for(&request, &digests.payment).ok(),
        Some(KagemushaWalletDeliveryStatusV1::Credited)
    );
    KagemushaWalletCreditedV1::from_status(renewed_status)
        .expect("credited status")
        .verify_for(&f.payer.scheme, &request, &payment)
        .expect("Status evidence under the renewed credential");

    // An Ω(h) of the receiver's wallet under another payment key, with τ(h) signed by that key.
    let (other_key, _) = f.credit_status_under(
        &payment,
        40,
        &leaf,
        OPENING_OTHER_CREDITS,
        &f.receiver.credential,
        &f.payer.payment,
    );
    other_key
        .credit_status_digest()
        .expect("self-consistent under its own key");
    assert_invalid(
        other_key.check_for(&request, &digests.payment),
        "credit_status.receiver_payment_key",
    );
    let other_key_credited =
        KagemushaWalletCreditedV1::from_status(other_key).expect("structurally valid");
    assert_invalid(
        other_key_credited.verify_for(&f.payer.scheme, &request, &payment),
        "credit_status.receiver_payment_key",
    );
    // A Receive package signed by another key does not verify under the Request credential's.
    let mut foreign = f.receive_package(&payment, 48);
    let foreign_body = foreign
        .receipt
        .body(
            &KagemushaWalletReceiptSignerV1::from_credential(&f.receiver.credential)
                .expect("signer"),
            &foreign.statement,
            &foreign.proof_digest().expect("proof digest"),
        )
        .expect("body");
    foreign.receipt.signature = kagemusha_wallet_freeze_signature_v1(
        &f.payer.credential.body.payment_key,
        Domain::Receipt,
        &foreign_body.signing_message(),
        raw_output(&f.payer.payment, &foreign_body.signing_message()),
    )
    .expect("signature by another key");
    let foreign = KagemushaWalletCreditedV1::from_receive(foreign).expect("structure");
    assert_signature(
        foreign.verify_for(&f.payer.scheme, &request, &payment),
        Domain::Receipt,
    );
}

#[test]
fn kagemusha_wallet_v1_credited_receive_evidence() {
    let f = message_fixture();
    let payment = f.payment(true, 64);
    let request = f.request(true);
    let digests = payment.digests().expect("payment");
    let credited = f.credited_receive(&payment, 48);
    credited.validate().expect("structure");
    assert_eq!(credited.scheme_id, f.scheme_id());
    let (digest, status) = credited
        .verify_for(&f.payer.scheme, &request, &payment)
        .expect("verify");
    assert_eq!(status, KagemushaWalletDeliveryStatusV1::CreditedUnfolded);
    let KagemushaWalletCreditedEvidenceV1::Receive { package } = &credited.evidence else {
        panic!("receive evidence");
    };
    assert_eq!(package.receipt.payment_digest, digests.payment);
    let package_digest = package
        .verify(&f.receiver.credential)
        .expect("package")
        .package;
    let mut transcript = vec![1, 0, 1];
    transcript.extend_from_slice(&digests.credit_id);
    transcript.extend_from_slice(&digests.payment);
    transcript.extend_from_slice(&package_digest);
    assert_eq!(
        digest,
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1, &transcript)
    );

    let other_payment = f.payment(false, 64);
    assert_invalid(
        credited.verify_for(&f.payer.scheme, &f.request(false), &other_payment),
        "credited.receive.credit_id",
    );
    assert_invalid(
        credited.verify_for(&f.payer.scheme, &f.request(false), &payment),
        "credited.payment.request",
    );
    let mut not_receive = credited.clone();
    not_receive.evidence = KagemushaWalletCreditedEvidenceV1::Receive {
        package: payment.send.clone(),
    };
    assert_invalid(not_receive.validate(), "credited.evidence");
    assert_invalid(
        KagemushaWalletCreditedV1::from_receive(payment.send.clone()),
        "credited.evidence",
    );
    let mut other_scheme = credited.clone();
    other_scheme.scheme_id = [0x51; 32];
    assert_mismatch(other_scheme.validate(), "credited.scheme_id");
    let mut version = credited.clone();
    version.version = 0;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
    // A Receive package binding another Payment digest does not match.
    let mut other_digest = credited.clone();
    if let KagemushaWalletCreditedEvidenceV1::Receive { package } = &mut other_digest.evidence {
        package.receipt.payment_digest = field_value(0x52);
    }
    assert_invalid(
        other_digest.verify_for(&f.payer.scheme, &request, &payment),
        "credited.receive.payment_digest",
    );
    // A receipt that does not verify under the held Request's receiver key.
    let mut forged = credited.clone();
    if let KagemushaWalletCreditedEvidenceV1::Receive { package } = &mut forged.evidence {
        package.receipt.signature = f.offer().signature;
    }
    forged.validate().expect("structurally valid");
    assert_signature(
        forged.verify_for(&f.payer.scheme, &request, &payment),
        Domain::Receipt,
    );

    let frame = norito::encode_canonical(&credited).expect("encode");
    assert_every_flip_rejected_or_rebound(&frame, digest, |bytes| {
        let credited: KagemushaWalletCreditedV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).ok()?;
        credited
            .verify_for(&f.payer.scheme, &request, &payment)
            .ok()
            .map(|(d, _)| d)
    });
}

#[test]
fn kagemusha_wallet_v1_credited_status_evidence() {
    let f = message_fixture();
    let payment = f.payment(false, 64);
    let request = f.request(false);
    let credited = f.credited_status(&payment, 40, OPENING_OTHER_CREDITS);
    credited.validate().expect("structure");
    let (digest, status) = credited
        .verify_for(&f.payer.scheme, &request, &payment)
        .expect("verify");
    assert_eq!(status, KagemushaWalletDeliveryStatusV1::Credited);
    let KagemushaWalletCreditedEvidenceV1::Status { status } = &credited.evidence else {
        panic!("status evidence");
    };
    let digests = payment.digests().expect("digests");
    let mut transcript = vec![1, 0, 2];
    transcript.extend_from_slice(&digests.credit_id);
    transcript.extend_from_slice(&digests.payment);
    transcript.extend_from_slice(&status.credit_status_digest().expect("status"));
    assert_eq!(
        digest,
        kagemusha_wallet_poseidon_bytes_v1(KAGEMUSHA_WALLET_CREDITED_DOMAIN_V1, &transcript)
    );
    let burned = KagemushaWalletCreditedV1::from_status(f.credit_status(
        &payment,
        40,
        OPENING_OTHER_CREDITS,
        true,
    ))
    .expect("burned");
    let (burned_digest, burned_status) = burned
        .verify_for(&f.payer.scheme, &request, &payment)
        .expect("burned");
    assert_eq!(burned_status, KagemushaWalletDeliveryStatusV1::Burned);
    assert_ne!(burned_digest, digest);
    let mut tampered = credited.clone();
    if let KagemushaWalletCreditedEvidenceV1::Status { status } = &mut tampered.evidence {
        status.lineage.public.head = commitment(9);
    }
    assert_invalid(tampered.validate(), "credit_status.head");
    let mut other_scheme = credited.clone();
    other_scheme.scheme_id = [0x53; 32];
    assert_mismatch(other_scheme.validate(), "credited.scheme_id");

    let frame = norito::encode_canonical(&credited).expect("encode");
    assert_every_flip_rejected_or_rebound(&frame, digest, |bytes| {
        let credited: KagemushaWalletCreditedV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1).ok()?;
        credited
            .verify_for(&f.payer.scheme, &request, &payment)
            .ok()
            .map(|(d, _)| d)
    });
}

#[test]
fn kagemusha_wallet_v1_credited_evidence_names_the_payer_scheme_and_relation() {
    // §8: a mismatched relation identity is rejected before the ArchiveSent mutation, as
    // Λ_archive rejects it in-circuit (§3.2); structural validation alone cannot see it.
    let f = message_fixture();
    let payment = f.payment(true, 64);
    let request = f.request(true);
    let digests = payment.digests().expect("payment");
    let mut statement = f.receive_package(&payment, 32).statement;
    statement.relation_id = [0x5c; 32];
    let receive = signed_package_with(
        &f.receiver,
        &f.receiver.credential,
        &statement,
        KagemushaWalletLineageSlotV1::None,
        stand_in_proof(32),
        digests.payment,
    );
    let mut status = f.credit_status(&payment, 40, OPENING_OTHER_CREDITS, false);
    status.statement = statement;
    status.proof_digest = receive.proof_digest().expect("proof digest");
    status.receipt = receive.receipt;
    status.lineage.public.relation_id = statement.relation_id;
    let pending = payment.pending_outgoing_leaf().expect("pending");
    for credited in [
        KagemushaWalletCreditedV1::from_receive(receive).expect("structurally valid receive"),
        KagemushaWalletCreditedV1::from_status(status).expect("structurally valid status"),
    ] {
        assert_mismatch(
            credited.verify_for(&f.payer.scheme, &request, &payment),
            "statement.relation_id",
        );
        assert_mismatch(
            credited.archive_sent_effect(&f.payer.scheme, &request, &payment, &pending),
            "statement.relation_id",
        );
    }
    // Valid evidence verified under another scheme names the wrong scheme.
    let mut other = f.payer.scheme;
    other.relation_id = [0x5d; 32];
    for credited in [
        f.credited_receive(&payment, 32),
        f.credited_status(&payment, 32, 2),
    ] {
        credited
            .verify_for(&f.payer.scheme, &request, &payment)
            .expect("payer scheme");
        assert_mismatch(
            credited.verify_for(&other, &request, &payment),
            "statement.scheme_id",
        );
    }
}

#[test]
fn kagemusha_wallet_v1_archive_sent_for_credited_or_burned_evidence() {
    let f = message_fixture();
    let payment = f.payment(true, 64);
    let request = f.request(true);
    let pending = payment.pending_outgoing_leaf().expect("pending");
    for credited in [
        f.credited_receive(&payment, 32),
        f.credited_status(&payment, 32, 2),
        KagemushaWalletCreditedV1::from_status(f.credit_status(&payment, 32, 2, true))
            .expect("burned"),
    ] {
        let (digest, _) = credited
            .verify_for(&f.payer.scheme, &request, &payment)
            .expect("verify");
        assert_eq!(
            credited
                .archive_sent_effect(&f.payer.scheme, &request, &payment, &pending)
                .expect("archive"),
            KagemushaWalletEffectV1::ArchiveSent {
                credit_id: pending.credit_id,
                credited: digest,
            }
        );
        let mut wrong_leaf = pending;
        wrong_leaf.amount += 1;
        assert_invalid(
            credited.archive_sent_effect(&f.payer.scheme, &request, &payment, &wrong_leaf),
            "pending_outgoing",
        );
        let other = f.payment(false, 64);
        assert!(
            credited
                .archive_sent_effect(
                    &f.payer.scheme,
                    &f.request(false),
                    &other,
                    &other.pending_outgoing_leaf().expect("leaf")
                )
                .is_err()
        );
    }
}

#[test]
fn kagemusha_wallet_v1_session_controls() {
    use KagemushaWalletSessionControlKindV1 as Kind;
    let f = message_fixture();
    for kind in [Kind::SetupDeclined, Kind::ReceiveDeferred, Kind::Close] {
        let control = f.signed_control(kind);
        control.validate().expect("valid");
        control
            .verify(Some(&f.payer.credential))
            .expect("signed control");
        assert_invalid(control.verify(None), "session_control.sender_key");
        assert!(control.verify(Some(&f.receiver.credential)).is_err());
        let mut tampered = control;
        tampered.session_nonce = [0x60; 32];
        assert_signature(
            tampered.verify(Some(&f.payer.credential)),
            Domain::SessionControl,
        );
    }
    assert_eq!(
        f.signed_control(Kind::Close).signing_message(),
        kagemusha_wallet_signing_message_v1(
            Domain::SessionControl,
            &f.control(Kind::Close).transcript()
        )
    );

    // Unsigned controls: UnsupportedScheme always, SetupDeclined only before the sender's key
    // is known in the session.
    let declined = f.control(Kind::SetupDeclined);
    declined.verify(None).expect("early decline");
    assert_invalid(
        declined.verify(Some(&f.payer.credential)),
        "session_control.auth",
    );
    assert_invalid(f.control(Kind::Close).verify(None), "session_control.auth");
    let mut unsupported = f.control(Kind::UnsupportedScheme);
    unsupported.sender_wallet_id = [0; 32];
    unsupported.verify(None).expect("unsupported scheme");
    unsupported
        .verify(Some(&f.payer.credential))
        .expect("unsupported scheme stays unsigned");
    assert_invalid(
        f.control(Kind::UnsupportedScheme).sign(
            &f.payer.credential,
            raw_output(&f.payer.payment, &unsupported.signing_message()),
        ),
        "session_control.auth",
    );
    let mut signed_unsupported = f.control(Kind::UnsupportedScheme);
    signed_unsupported.auth = f.signed_control(Kind::Close).auth;
    assert_invalid(signed_unsupported.validate(), "session_control.auth");

    let mutations: [(ControlMutation, &str); 6] = [
        (|control| control.reason = 1, "session_control.reason"),
        (
            |control| control.credit_id = [1; 32],
            "session_control.credit_id",
        ),
        (
            |control| control.peer_wallet_id = control.sender_wallet_id,
            "session_control.peer_wallet_id",
        ),
        (
            |control| control.session_nonce = [0; 32],
            "session_control.session_nonce",
        ),
        (
            |control| control.sender_wallet_id = [0; 32],
            "session_control.sender_wallet_id",
        ),
        (
            |control| control.asset_digest = [0; 32],
            "session_control.asset_digest",
        ),
    ];
    for (mutate, field) in mutations {
        let mut control = f.control(Kind::Close);
        mutate(&mut control);
        assert_invalid(control.validate(), field);
    }
    let mut deferred = f.control(Kind::ReceiveDeferred);
    deferred.credit_id = [0; 32];
    assert_invalid(deferred.validate(), "session_control.credit_id");
    let mut unknown_peer = f.control(Kind::Close);
    unknown_peer.peer_wallet_id = [0; 32];
    unknown_peer.validate().expect("unknown peer");
    let mut foreign = f.control(Kind::Close);
    foreign.sender_wallet_id = f.receiver.credential.body.wallet_id;
    foreign.peer_wallet_id = [0; 32];
    assert_invalid(
        foreign.sign(
            &f.payer.credential,
            raw_output(&f.payer.payment, &foreign.signing_message()),
        ),
        "session_control.sender_wallet_id",
    );

    let control = f.signed_control(Kind::ReceiveDeferred);
    let frame = norito::encode_canonical(&control).expect("encode");
    assert_every_flip_rejected_or_rebound(&frame, control.signing_message(), |bytes| {
        let control: KagemushaWalletSessionControlV1 =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1).ok()?;
        control.verify(Some(&f.payer.credential)).ok()?;
        Some(control.signing_message())
    });
}

#[test]
fn kagemusha_wallet_v1_policy_data_items() {
    let f = message_fixture();
    let known = [f.regulator_certificate];
    let policy = f.policy_data(KagemushaWalletPolicyDataItemV1::SchemePolicy {
        policy: f.scheme_policy(2, 0, [0; 32]),
    });
    policy
        .verify(&f.payer.scheme, &known)
        .expect("scheme policy");
    assert_invalid(policy.verify(&f.payer.scheme, &[]), "certificates.missing");
    let schedule = f.policy_data(KagemushaWalletPolicyDataItemV1::FeeSchedule {
        schedule: f.fee_schedule(),
    });
    schedule
        .verify(&f.payer.scheme, &known)
        .expect("fee schedule");
    let certificates = f.policy_data(KagemushaWalletPolicyDataItemV1::Certificates {
        certificates: KagemushaWalletCertificateSetV1::new(vec![
            f.regulator_certificate,
            f.payer.enrollment_certificate,
        ])
        .expect("set"),
    });
    certificates
        .verify(&f.payer.scheme, &[])
        .expect("certificates");

    let mut other_asset = schedule.clone();
    other_asset.asset_digest = [0x61; 32];
    assert_invalid(other_asset.validate(), "policy_data.asset_digest");
    let mut other_scheme = policy.clone();
    other_scheme.scheme_id = [0x62; 32];
    assert_mismatch(other_scheme.validate(), "policy_data.scheme_id");
    assert_invalid(
        f.policy_data(KagemushaWalletPolicyDataItemV1::Certificates {
            certificates: KagemushaWalletCertificateSetV1::default(),
        })
        .validate(),
        "policy_data.certificates",
    );
    let other = identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x63);
    let mut foreign_root = other.scheme;
    foreign_root.scheme_root_key = other.credential.body.payment_key;
    let foreign_certificate = test_certificate(
        &foreign_root,
        &other.payment,
        KagemushaWalletSignerRoleV1::TimeAnchor,
        &other.payment,
        1,
    );
    assert_mismatch(
        f.policy_data(KagemushaWalletPolicyDataItemV1::Certificates {
            certificates: KagemushaWalletCertificateSetV1::new(vec![foreign_certificate])
                .expect("set"),
        })
        .validate(),
        "policy_data.scheme_id",
    );
    let mut version = policy.clone();
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
}

#[test]
fn kagemusha_wallet_v1_envelope_round_trips_every_kind() {
    let f = message_fixture();
    assert_eq!(
        norito::core::archived_payload_align::<KagemushaWalletEnvelopeV1>(),
        16
    );
    for message in sample_messages(&f) {
        let envelope = KagemushaWalletEnvelopeV1::new(message.clone());
        let frame = envelope.to_canonical_bytes().expect("frame");
        assert_eq!(payload_range(&frame).start, 48);
        assert!(frame.len() <= message.max_bytes());
        assert_eq!(
            KagemushaWalletEnvelopeV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
            envelope
        );
        let text = envelope.to_text().expect("text");
        assert!(text.starts_with(KAGEMUSHA_WALLET_TEXT_PREFIX_V1));
        assert_eq!(text, kagemusha_wallet_text_encode_v1(&frame));
        assert_eq!(kagemusha_wallet_text_decode_v1(&text).expect("raw"), frame);
        assert_eq!(
            KagemushaWalletEnvelopeV1::from_text(&text, &f.scheme_id()).expect("from text"),
            envelope
        );
        let text_max = if message.max_bytes() == KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1 {
            KAGEMUSHA_WALLET_SESSION_TEXT_MAX_BYTES_V1
        } else {
            KAGEMUSHA_WALLET_MESSAGE_TEXT_MAX_BYTES_V1
        };
        assert!(text.len() <= text_max);
        assert_eq!(message.version(), KAGEMUSHA_WALLET_VERSION_V1);
        assert_eq!(message.scheme_id(), &f.scheme_id());
    }
}

#[test]
fn kagemusha_wallet_v1_envelope_bounds_per_kind() {
    let f = message_fixture();
    for message in sample_messages(&f) {
        let max = message.max_bytes();
        let expected = match message {
            KagemushaWalletMessageV1::Offer { .. }
            | KagemushaWalletMessageV1::SessionControl { .. } => 2_048,
            _ => 10_000,
        };
        assert_eq!(max, expected);
        require_message_bound_v1(&message, max).expect("at the bound");
        assert!(matches!(
            require_message_bound_v1(&message, max + 1),
            Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { actual, max: limit })
                if actual == max + 1 && limit == max
        ));
    }

    // A decodable Offer above the session bound is rejected after decode, before validation.
    let mut offer = f.offer();
    offer.certificates = KagemushaWalletCertificateSetV1 {
        certificates: vec![f.payer.enrollment_certificate; 12],
    };
    let oversized = KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Offer { offer });
    let frame = norito::encode_canonical(&oversized).expect("encode");
    assert!(frame.len() > KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1);
    assert!(frame.len() <= KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1);
    assert_too_large(
        KagemushaWalletEnvelopeV1::decode_canonical(&frame, &[0x77; 32]),
        KAGEMUSHA_WALLET_SESSION_MAX_BYTES_V1,
    );
    // A Payment whose Ω and σ exceed the message bound is rejected at encode.
    let payment = f.payment_with(true, 4_000, 6_000);
    assert_too_large(
        KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Payment { payment })
            .to_canonical_bytes(),
        KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1,
    );
}

#[test]
fn kagemusha_wallet_v1_envelope_decode_order() {
    let f = message_fixture();
    let envelope =
        KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Offer { offer: f.offer() });
    let frame = envelope.to_canonical_bytes().expect("frame");
    let scheme_id = f.scheme_id();

    // The byte cap applies before any parsing.
    let garbage = vec![0xa5; KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 1];
    assert!(matches!(
        KagemushaWalletEnvelopeV1::decode_canonical(&garbage, &scheme_id),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded {
            actual: 10_001,
            max: 10_000
        })
    ));
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(matches!(
        KagemushaWalletEnvelopeV1::decode_canonical(&trailing, &scheme_id),
        Err(KagemushaWalletValidationErrorV1::Codec(_))
    ));
    assert!(matches!(
        KagemushaWalletEnvelopeV1::decode_canonical(&frame[..frame.len() - 1], &scheme_id),
        Err(KagemushaWalletValidationErrorV1::Codec(_))
    ));

    // Versions are checked before the scheme.
    let mut version = envelope.clone();
    version.version = 2;
    assert!(matches!(
        KagemushaWalletEnvelopeV1::decode_canonical(
            &norito::encode_canonical(&version).expect("encode"),
            &[0x78; 32]
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "envelope.version",
            version: 2
        })
    ));
    let mut message_version = envelope.clone();
    if let KagemushaWalletMessageV1::Offer { offer } = &mut message_version.message {
        offer.body.version = 3;
    }
    assert!(matches!(
        KagemushaWalletEnvelopeV1::decode_canonical(
            &norito::encode_canonical(&message_version).expect("encode"),
            &[0x78; 32]
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "message.version",
            version: 3
        })
    ));
    assert_mismatch(
        KagemushaWalletEnvelopeV1::decode_canonical(&frame, &[0x78; 32]),
        "envelope.scheme_id",
    );
    // Every nested version precedes the per-kind bound and the scheme, including the version
    // of the nested body that supplies the checked scheme (design §0).
    let payment = f.payment(true, 64);
    let mut nested = payment.clone();
    nested.request.body.version = 2;
    nested.request.body.scheme_id = [0x78; 32];
    let nested_frame = norito::encode_canonical(&nested).expect("encode");
    assert!(matches!(
        KagemushaWalletPaymentV1::decode_canonical(&nested_frame, &scheme_id),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "request.version",
            version: 2
        })
    ));
    let nested_envelope =
        KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Payment { payment: nested });
    assert!(matches!(
        KagemushaWalletEnvelopeV1::decode_canonical(
            &norito::encode_canonical(&nested_envelope).expect("encode"),
            &scheme_id
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "request.version",
            version: 2
        })
    ));
    let mut receipt_version = payment.clone();
    receipt_version.send.receipt.version = 4;
    assert!(matches!(
        KagemushaWalletPaymentV1::decode_canonical(
            &norito::encode_canonical(&receipt_version).expect("encode"),
            &[0x78; 32]
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "receipt.version",
            version: 4
        })
    ));
    let mut lineage_version = payment.clone();
    if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut lineage_version.send.lineage {
        lineage.public.version = 5;
    }
    assert!(matches!(
        KagemushaWalletPaymentV1::decode_canonical(
            &norito::encode_canonical(&lineage_version).expect("encode"),
            &[0x78; 32]
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "lineage.version",
            version: 5
        })
    ));
    let mut status_version = f.credited_status(&payment, 32, 1);
    if let KagemushaWalletCreditedEvidenceV1::Status { status } = &mut status_version.evidence {
        status.lineage.public.version = 2;
    }
    status_version.scheme_id = [0x78; 32];
    assert!(matches!(
        KagemushaWalletEnvelopeV1::decode_canonical(
            &norito::encode_canonical(&KagemushaWalletEnvelopeV1::new(
                KagemushaWalletMessageV1::Credited {
                    credited: status_version
                }
            ))
            .expect("encode"),
            &scheme_id
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "lineage.version",
            version: 2
        })
    ));
    let mut tampered = envelope.clone();
    if let KagemushaWalletMessageV1::Offer { offer } = &mut tampered.message {
        offer.body.amount += 1;
    }
    assert_signature(
        KagemushaWalletEnvelopeV1::decode_canonical(
            &norito::encode_canonical(&tampered).expect("encode"),
            &scheme_id,
        ),
        Domain::Offer,
    );
    assert_signature(tampered.to_canonical_bytes(), Domain::Offer);

    // The scheme field per kind (design §6.7).
    let credited = f.credited_receive(&payment, 32);
    let lineage = f.lineage_message(&payment);
    assert_eq!(
        KagemushaWalletMessageV1::Payment {
            payment: payment.clone()
        }
        .scheme_id(),
        &payment.request.body.scheme_id
    );
    assert_eq!(
        KagemushaWalletMessageV1::Credited {
            credited: credited.clone()
        }
        .scheme_id(),
        &credited.scheme_id
    );
    assert_eq!(
        KagemushaWalletMessageV1::Lineage {
            lineage: lineage.clone()
        }
        .scheme_id(),
        &lineage.lineage.public.scheme_id
    );
    let lineage_frame =
        KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Lineage { lineage })
            .to_canonical_bytes()
            .expect("lineage frame");
    assert_mismatch(
        KagemushaWalletEnvelopeV1::decode_canonical(&lineage_frame, &[0x78; 32]),
        "envelope.scheme_id",
    );
}

#[test]
fn kagemusha_wallet_v1_unsupported_scheme_reply_to_an_offer() {
    let f = message_fixture();
    let offer = f.offer();
    let envelope = KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Offer {
        offer: offer.clone(),
    });
    let frame = envelope.to_canonical_bytes().expect("frame");
    // A receiver without this scheme cannot decode the Offer for its own scheme...
    assert_mismatch(
        KagemushaWalletEnvelopeV1::decode_canonical(&frame, &[0x78; 32]),
        "envelope.scheme_id",
    );
    // ...but learns the offered scheme through the bounded path and declines it (§8).
    let offered = KagemushaWalletEnvelopeV1::decode_offered_scheme(&frame).expect("offered");
    assert_eq!(offered, offer.body);
    assert_eq!(
        KagemushaWalletEnvelopeV1::offered_scheme_from_text(&envelope.to_text().expect("text"))
            .expect("offered text"),
        offer.body
    );
    let reply = KagemushaWalletSessionControlV1::unsupported_scheme(&offered).expect("reply");
    assert_eq!(
        reply,
        KagemushaWalletSessionControlV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: offer.body.scheme_id,
            asset_digest: offer.body.asset_digest,
            sender_wallet_id: [0; 32],
            peer_wallet_id: offer.body.payer_wallet_id,
            session_nonce: offer.body.session_nonce,
            kind: KagemushaWalletSessionControlKindV1::UnsupportedScheme,
            reason: 0,
            credit_id: [0; 32],
            auth: KagemushaWalletSessionAuthV1::Unsigned,
        }
    );
    // The payer decodes the reply under its own scheme and accepts it unsigned.
    let reply_frame =
        KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::SessionControl { control: reply })
            .to_canonical_bytes()
            .expect("reply frame");
    let decoded =
        KagemushaWalletEnvelopeV1::decode_canonical(&reply_frame, &f.scheme_id()).expect("reply");
    assert_eq!(
        decoded.message,
        KagemushaWalletMessageV1::SessionControl { control: reply }
    );
    reply.verify(None).expect("unsigned UnsupportedScheme");
    // The returned body is unauthenticated: a broken signature does not stop the decline.
    let mut tampered = envelope.clone();
    if let KagemushaWalletMessageV1::Offer { offer } = &mut tampered.message {
        offer.body.amount += 1;
    }
    assert_eq!(
        KagemushaWalletEnvelopeV1::decode_offered_scheme(
            &norito::encode_canonical(&tampered).expect("encode")
        )
        .expect("unauthenticated body")
        .amount,
        offer.body.amount + 1
    );
    // Only an Offer is accepted, in the bounded decode order.
    let request_frame = KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::Request {
        request: f.request(true),
    })
    .to_canonical_bytes()
    .expect("request frame");
    assert_invalid(
        KagemushaWalletEnvelopeV1::decode_offered_scheme(&request_frame),
        "envelope.message",
    );
    assert!(matches!(
        KagemushaWalletEnvelopeV1::decode_offered_scheme(&vec![
            0xa5;
            KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
                + 1
        ]),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
    let mut version = envelope.clone();
    if let KagemushaWalletMessageV1::Offer { offer } = &mut version.message {
        offer.body.version = 2;
    }
    assert!(matches!(
        KagemushaWalletEnvelopeV1::decode_offered_scheme(
            &norito::encode_canonical(&version).expect("encode")
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "message.version",
            version: 2
        })
    ));
    let mut padded = frame.clone();
    padded.push(0);
    assert!(matches!(
        KagemushaWalletEnvelopeV1::decode_offered_scheme(&padded),
        Err(KagemushaWalletValidationErrorV1::Codec(_))
    ));
    let mut zero_nonce = offer.body;
    zero_nonce.session_nonce = [0; 32];
    assert_invalid(
        KagemushaWalletSessionControlV1::unsupported_scheme(&zero_nonce),
        "offer.session_nonce",
    );
    let mut zero_nonce_offer = envelope;
    if let KagemushaWalletMessageV1::Offer { offer } = &mut zero_nonce_offer.message {
        offer.body.session_nonce = [0; 32];
    }
    assert_invalid(
        KagemushaWalletEnvelopeV1::decode_offered_scheme(
            &norito::encode_canonical(&zero_nonce_offer).expect("encode"),
        ),
        "offer.session_nonce",
    );
}

#[test]
fn kagemusha_wallet_v1_text_codec_is_strict() {
    let f = message_fixture();
    let envelope = KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::SessionControl {
        control: f.signed_control(KagemushaWalletSessionControlKindV1::Close),
    });
    let text = envelope.to_text().expect("text");
    let body = &text[KAGEMUSHA_WALLET_TEXT_PREFIX_V1.len()..];
    assert!(!body.contains('='));

    let cases: [(String, &str); 7] = [
        (body.to_owned(), "text.prefix"),
        (format!("kgm2:{body}"), "text.prefix"),
        ("KGM1:AA".to_owned(), "text.prefix"),
        ("kgm1:".to_owned(), "text.body"),
        (format!("{text}="), "text.alphabet"),
        (format!("{text}\n"), "text.alphabet"),
        (format!("{text}+"), "text.alphabet"),
    ];
    for (input, field) in cases {
        assert_invalid(kagemusha_wallet_text_decode_v1(&input), field);
    }
    assert_invalid(
        kagemusha_wallet_text_decode_v1("kgm1:AA/A"),
        "text.alphabet",
    );
    // Lengths of 1 mod 4 are rejected before decoding.
    let one_mod_four = format!("kgm1:{}", "A".repeat(5));
    assert_invalid(
        kagemusha_wallet_text_decode_v1(&one_mod_four),
        "text.length",
    );
    // Nonzero trailing bits do not round-trip.
    let noncanonical = "kgm1:AB";
    assert_invalid(
        kagemusha_wallet_text_decode_v1(noncanonical),
        "text.base64url",
    );
    assert_eq!(
        kagemusha_wallet_text_decode_v1("kgm1:AA").expect("canonical"),
        vec![0]
    );
    let oversized = format!(
        "kgm1:{}",
        "A".repeat(KAGEMUSHA_WALLET_MESSAGE_TEXT_MAX_BYTES_V1)
    );
    assert_too_large(
        kagemusha_wallet_text_decode_v1(&oversized),
        KAGEMUSHA_WALLET_MESSAGE_TEXT_MAX_BYTES_V1,
    );
    // Valid text of an invalid frame fails in the frame decoder.
    assert!(matches!(
        KagemushaWalletEnvelopeV1::from_text("kgm1:AAAA", &f.scheme_id()),
        Err(KagemushaWalletValidationErrorV1::Codec(_))
    ));
}

#[test]
fn kagemusha_wallet_v1_stand_in_helpers() {
    // Other credits are distinct canonical stand-ins, recorded before the fixture credit.
    let others: Vec<_> = (0..60)
        .map(|index| neighbour_credit(index).credit_id)
        .collect();
    let mut unique = others.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), others.len());
    let leaf = KagemushaWalletCreditDigestLeafV1 {
        credit_id: field_value(0x3f),
        payment_digest: field_value(0x3e),
        burned: false,
    };
    let tree = credit_digest_tree(&leaf, 3);
    assert_eq!(tree.len(), 4);
    assert_eq!(credit_opening_in(&tree, &leaf).slot, 4);
    assert_eq!(
        KagemushaWalletStateCommitmentV1::default(),
        KagemushaWalletStateCommitmentV1::ZERO
    );
}

/// `identity`'s credential reissued with the BLACKLIST control permitted (no list-age rule).
fn blacklist_permitted(identity: &IdentityFixture) -> KagemushaWalletCredentialV1 {
    let mut body = identity.credential.body;
    body.regulatory_policy = KagemushaWalletRegulatoryPolicyV1 {
        permitted_controls: KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1,
        blacklist_max_age_ms: 0,
        time_anchor_max_response_ms: 0,
    };
    identity
        .issue(&body)
        .expect("blacklist-permitted credential")
}

impl MessageFixture {
    /// Signed blacklist of `accounts`, sorted in limb order (owner answer A4).
    fn signed_blacklist(
        &self,
        list_version: u64,
        accounts: &[[u8; 32]],
    ) -> KagemushaWalletBlacklistV1 {
        let mut entries: Vec<KagemushaWalletBlacklistEntryV1> = accounts
            .iter()
            .map(|account_digest| KagemushaWalletBlacklistEntryV1 {
                account_digest: *account_digest,
            })
            .collect();
        entries.sort_by(|left, right| {
            kagemusha_wallet_integer_cmp_v1(&left.account_digest, &right.account_digest)
        });
        let body = KagemushaWalletBlacklistBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            list_version,
            issued_at_ms: ACCEPTED_MS - 10_000,
            entry_count: u32::try_from(entries.len()).expect("count"),
            entries_root: kagemusha_wallet_blacklist_root_v1(&entries).expect("root"),
            signer_certificate: self.regulator_certificate.certificate_digest(),
        };
        KagemushaWalletBlacklistV1::sign(
            body,
            entries,
            &self.regulator_certificate,
            raw_output(&self.regulator, &body.signing_message()),
        )
        .expect("blacklist")
    }

    /// `state` with BLACKLIST enabled and the optional signed list installed in real history.
    fn with_blacklist(
        &self,
        mut state: KagemushaWalletStateV1,
        fee_schedule: [u8; 32],
        list: Option<&KagemushaWalletBlacklistV1>,
    ) -> (KagemushaWalletStateV1, KagemushaWalletIndexedTreeV1) {
        let policy = self.scheme_policy(2, KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1, fee_schedule);
        policy
            .verify(&self.payer.scheme, &self.regulator_certificate)
            .expect("policy signature");
        let refresh = state
            .refresh_policy(KagemushaWalletPolicyUpdateV1::SchemePolicy { policy: &policy })
            .expect("refresh policy");
        state.core = refresh.core;
        state.rest = refresh.rest;
        let mut history = KagemushaWalletIndexedTreeV1::new();
        assert_eq!(state.rest.blacklist_history_root, history.root());
        if let Some(list) = list {
            state = self.commit_blacklist(state, &mut history, list);
        }
        assert!(state.is_active(KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1));
        (state, history)
    }

    /// Install a verified newer list with its original predecessor-history insertion witness.
    fn commit_blacklist(
        &self,
        mut state: KagemushaWalletStateV1,
        history: &mut KagemushaWalletIndexedTreeV1,
        list: &KagemushaWalletBlacklistV1,
    ) -> KagemushaWalletStateV1 {
        assert_eq!(state.rest.blacklist_history_root, history.root());
        list.verify(&self.payer.scheme, &self.regulator_certificate)
            .expect("list signature");
        let insertion = KagemushaWalletBlacklistHistoryLeafV1 {
            list_version: list.body.list_version,
            entries_root: list.body.entries_root,
        }
        .insert_into(history)
        .expect("history insertion");
        let refresh = state
            .refresh_policy(KagemushaWalletPolicyUpdateV1::Blacklist {
                list,
                history: &insertion,
            })
            .expect("newer list");
        state.core = refresh.core;
        state.rest = refresh.rest;
        assert_eq!(state.rest.blacklist_history_root, history.root());
        state
    }

    /// Candidate body records exactly the receiver's current decision before Request issuance.
    fn request_body_at(&self, receiver: &KagemushaWalletStateV1) -> KagemushaWalletRequestBodyV1 {
        let (mut body, _, _) = self.request_parts(true, 1_000);
        (
            body.receiver_blacklist_version,
            body.receiver_blacklist_root,
        ) = receiver.request_blacklist_decision();
        body
    }

    /// Issue only after the actual Request rule; retain its payer gap for later Receive.
    fn issue_request_at(
        &self,
        receiver: &KagemushaWalletStateV1,
        list: Option<&KagemushaWalletBlacklistV1>,
    ) -> WalletResult<(
        KagemushaWalletRequestV1,
        Option<KagemushaWalletBlacklistGapOpeningV1>,
    )> {
        let (_, slot, certificates) = self.request_parts(true, 1_000);
        let body = self.request_body_at(receiver);
        let gap = body.check_request_rule(
            &self.payer.scheme,
            &self.offer(),
            &self.receiver.credential,
            receiver,
            list,
        )?;
        let request = self.sign_request(&body, slot, certificates)?;
        Ok((request, gap))
    }

    /// Run the current complete public Send path for these blacklist-only fixture heads.
    fn checked_send_at(
        &self,
        request: &KagemushaWalletRequestV1,
        payer: &KagemushaWalletStateV1,
        list: Option<&KagemushaWalletBlacklistV1>,
    ) -> WalletResult<KagemushaWalletSendCheckV1> {
        let omega = self.payer_omega(payer);
        let usage = KagemushaWalletQuotaUsageArrayV1::empty();
        request.check_send(&KagemushaWalletSendInputsV1 {
            payer_credential: &self.payer.credential,
            payer_state: payer,
            omega: &omega,
            anchored: None,
            now: None,
            blacklist: list,
            quota_share: None,
            quota_usage: &usage,
        })
    }
}

/// Retained Request gap joined to a fresh opening in the receiver head's real history store.
fn recorded_blacklist_proof(
    request: &KagemushaWalletRequestV1,
    history: &KagemushaWalletIndexedTreeV1,
    gap: &KagemushaWalletBlacklistGapOpeningV1,
) -> KagemushaWalletRecordedBlacklistProofV1 {
    let key =
        kagemusha_wallet_field_from_u128_v1(u128::from(request.body.receiver_blacklist_version));
    let (history_leaf, history_opening) = history.membership(&key).expect("recorded history");
    KagemushaWalletRecordedBlacklistProofV1 {
        history_leaf,
        history_opening,
        gap: *gap,
    }
}

/// Each phone enforces its own list at Request/Send. Receive authenticates the signed
/// Request's original decision through the receiving head's history and retained payer gap.
#[test]
fn kagemusha_wallet_v1_two_sided_blacklist_at_request_send_and_recorded_receive() {
    let mut f = message_fixture();
    f.payer.credential = blacklist_permitted(&f.payer);
    f.receiver.credential = blacklist_permitted(&f.receiver);
    let payer_account = f.payer.credential.body.account_digest;
    let receiver_account = f.receiver.credential.body.account_digest;
    let other_account = kagemusha_wallet_account_digest_v1(&test_account(0x77)).expect("other");
    let scheme = f.payer.scheme;
    let offer = f.offer();
    let baseline = f.request(true);
    assert_eq!(baseline.body.payer_account_digest, payer_account);
    assert_eq!(baseline.body.receiver_account_digest, receiver_account);
    let fee_schedule = baseline.body.fee_schedule;
    let receiver_credential = f.receiver.credential;
    let receiver_base = receiver_head_state(&receiver_credential);
    let lists_payer = f.signed_blacklist(1, &[payer_account, other_account]);
    let lists_receiver = f.signed_blacklist(1, &[receiver_account, other_account]);
    let lists_other = f.signed_blacklist(1, &[other_account]);
    let (receiver_listing_payer, foreign_history) =
        f.with_blacklist(receiver_base, fee_schedule, Some(&lists_payer));
    assert_invalid(
        f.issue_request_at(&receiver_listing_payer, Some(&lists_payer)),
        "blacklist.listed",
    );
    assert_invalid(
        f.issue_request_at(&receiver_listing_payer, None),
        "blacklist.missing",
    );
    let (mut receiver_listing_other, mut history) =
        f.with_blacklist(receiver_base, fee_schedule, Some(&lists_other));
    let (request, gap) = f
        .issue_request_at(&receiver_listing_other, Some(&lists_other))
        .expect("allowed Request");
    let gap = gap.expect("enforced");
    gap.verify(&receiver_listing_other.core.blacklist_root, &payer_account)
        .expect("payer gap");
    let (receiver_no_list, _) = f.with_blacklist(receiver_base, fee_schedule, None);
    assert_eq!(
        f.issue_request_at(&receiver_no_list, None)
            .expect("no held list")
            .1,
        None
    );
    assert_invalid(
        baseline.body.check_request_rule(
            &scheme,
            &offer,
            &receiver_credential,
            &receiver_listing_other,
            Some(&lists_other),
        ),
        "request.receiver_blacklist",
    );
    let mutations: [(RequestBodyMutation, &str); 3] = [
        (
            |body| body.payer_account_digest = [0x45; 32],
            "request.payer_account_digest",
        ),
        (
            |body| body.receiver_account_digest = [0x46; 32],
            "request.receiver_account_digest",
        ),
        (
            |body| body.payer_wallet_id = [0x47; 32],
            "request.payer_wallet_id",
        ),
    ];
    for (mutate, field) in mutations {
        let mut body = baseline.body;
        mutate(&mut body);
        assert_invalid(
            body.check_request_rule(
                &scheme,
                &offer,
                &receiver_credential,
                &receiver_no_list,
                None,
            ),
            field,
        );
    }
    assert_invalid(
        baseline.body.check_request_rule(
            &scheme,
            &offer,
            &receiver_credential,
            &f.payer_state(&baseline),
            None,
        ),
        "state.core.wallet_id",
    );

    let payer_state = f.payer_state(&request);
    let interval =
        KagemushaWalletTimeIntervalV1::new(ACCEPTED_MS, ACCEPTED_MS + 4_000).expect("interval");
    let (payer_listing_receiver, _) =
        f.with_blacklist(payer_state, fee_schedule, Some(&lists_receiver));
    assert_invalid(
        f.checked_send_at(&request, &payer_listing_receiver, Some(&lists_receiver)),
        "blacklist.listed",
    );
    let (payer_listing_other, _) = f.with_blacklist(payer_state, fee_schedule, Some(&lists_other));
    let checked = f
        .checked_send_at(&request, &payer_listing_other, Some(&lists_other))
        .expect("Send allowed");
    checked
        .blacklist_gap
        .expect("enforced")
        .verify(&payer_listing_other.core.blacklist_root, &receiver_account)
        .expect("receiver gap");
    let (payer_no_list, _) = f.with_blacklist(payer_state, fee_schedule, None);
    assert_eq!(
        f.checked_send_at(&request, &payer_no_list, None)
            .expect("no held list")
            .blacklist_gap,
        None
    );
    request
        .check_send_rule(
            &f.payer.credential,
            &payer_listing_other,
            &f.payer_omega(&payer_listing_other),
        )
        .expect("send rule");
    let (mut body, slot, certificates) = f.request_parts(true, 1_000);
    body.payer_account_digest = other_account;
    assert_invalid(
        f.sign_request(&body, slot, certificates.clone()),
        "request.payer_account_digest",
    );
    // A malicious receiver can still provide a signed wire object outside the constructor;
    // Send must independently enforce the payer account binding.
    let foreign = KagemushaWalletRequestV1 {
        body,
        receiver_credential: f.receiver.credential,
        fee_schedule: slot,
        certificates,
        signature: kagemusha_wallet_freeze_signature_v1(
            &f.receiver.credential.body.payment_key,
            Domain::Request,
            &body.signing_message(),
            raw_output(&f.receiver.payment, &body.signing_message()),
        )
        .expect("adversarial receiver signature"),
    };
    assert_invalid(
        foreign.check_send_rule(
            &f.payer.credential,
            &payer_listing_other,
            &f.payer_omega(&payer_listing_other),
        ),
        "request.payer_account_digest",
    );
    assert_invalid(
        foreign.send_effect(&f.payer.credential, &interval),
        "request.payer_account_digest",
    );
    let (mut body, slot, certificates) = f.request_parts(true, 1_000);
    body.receiver_account_digest = other_account;
    assert_invalid(
        f.sign_request(&body, slot, certificates),
        "request.receiver_account_digest",
    );

    let payment = KagemushaWalletPaymentV1::assemble(
        &request,
        &f.payer.credential,
        f.send_package(&request, PAYMENT_LINEAGE_LEN, 64),
    )
    .expect("recorded Payment");
    let proof = recorded_blacklist_proof(&request, &history, &gap);
    let payer_set = KagemushaWalletCertificateSetV1::new(vec![f.payer.enrollment_certificate])
        .expect("payer set");
    let payment_bytes = payment
        .to_canonical_bytes()
        .expect("original Payment bytes");
    let original_receiver = receiver_listing_other;
    assert_invalid(
        payment.prepare_receive(
            &scheme,
            &f.payer.credential,
            &payer_set,
            &request,
            &receiver_credential,
            &receiver_listing_other,
            None,
        ),
        "blacklist.recorded",
    );
    let mut wrong_version = proof;
    wrong_version.history_leaf.key = kagemusha_wallet_field_from_u128_v1(2);
    assert_invalid(
        payment.prepare_receive(
            &scheme,
            &f.payer.credential,
            &payer_set,
            &request,
            &receiver_credential,
            &receiver_listing_other,
            Some(&wrong_version),
        ),
        "blacklist_history.leaf",
    );
    let mut wrong_root = proof;
    wrong_root.history_leaf.value[0] ^= 1;
    assert_invalid(
        payment.prepare_receive(
            &scheme,
            &f.payer.credential,
            &payer_set,
            &request,
            &receiver_credential,
            &receiver_listing_other,
            Some(&wrong_root),
        ),
        "blacklist_history.leaf",
    );
    let mut foreign_head = receiver_listing_other;
    foreign_head.rest.blacklist_history_root = foreign_history.root();
    assert_invalid(
        payment.prepare_receive(
            &scheme,
            &f.payer.credential,
            &payer_set,
            &request,
            &receiver_credential,
            &foreign_head,
            Some(&proof),
        ),
        "blacklist_history.opening",
    );
    let mut listed_gap = proof;
    listed_gap.gap.lower = payer_account;
    assert_invalid(
        payment.prepare_receive(
            &scheme,
            &f.payer.credential,
            &payer_set,
            &request,
            &receiver_credential,
            &receiver_listing_other,
            Some(&listed_gap),
        ),
        "blacklist.listed",
    );
    let mut changed_gap = proof;
    changed_gap.gap.siblings[0] = field_value(0x39);
    assert_invalid(
        payment.prepare_receive(
            &scheme,
            &f.payer.credential,
            &payer_set,
            &request,
            &receiver_credential,
            &receiver_listing_other,
            Some(&changed_gap),
        ),
        "blacklist.opening",
    );
    assert_eq!(receiver_listing_other, original_receiver);
    assert_eq!(
        payment
            .to_canonical_bytes()
            .expect("retained Payment bytes"),
        payment_bytes
    );
    let prepared = payment
        .prepare_receive(
            &scheme,
            &f.payer.credential,
            &payer_set,
            &request,
            &receiver_credential,
            &receiver_listing_other,
            Some(&proof),
        )
        .expect("original proof retry");
    receiver_listing_other
        .check_recorded_blacklist(
            request.body.receiver_blacklist_version,
            &request.body.receiver_blacklist_root,
            &payer_account,
            Some(&proof),
        )
        .expect("recorded rule");

    // Turning the current control off never excuses a recorded nonzero decision.
    let off = f.scheme_policy(3, 0, fee_schedule);
    off.verify(&scheme, &f.regulator_certificate)
        .expect("off policy signature");
    let refresh = receiver_listing_other
        .refresh_policy(KagemushaWalletPolicyUpdateV1::SchemePolicy { policy: &off })
        .expect("control off");
    let mut disabled = receiver_listing_other;
    disabled.core = refresh.core;
    disabled.rest = refresh.rest;
    assert_eq!(
        payment
            .prepare_receive(
                &scheme,
                &f.payer.credential,
                &payer_set,
                &request,
                &receiver_credential,
                &disabled,
                Some(&proof)
            )
            .expect("original recorded check")
            .effect,
        prepared.effect
    );
    assert_invalid(
        payment.prepare_receive(
            &scheme,
            &f.payer.credential,
            &payer_set,
            &request,
            &receiver_credential,
            &disabled,
            None,
        ),
        "blacklist.recorded",
    );

    // A newer list naming the payer cannot strand already committed original Payment bytes.
    let later_list = f.signed_blacklist(2, &[payer_account, other_account]);
    receiver_listing_other = f.commit_blacklist(receiver_listing_other, &mut history, &later_list);
    let later_proof = recorded_blacklist_proof(&request, &history, &gap);
    assert_eq!(later_proof.gap, proof.gap);
    assert_invalid(
        f.issue_request_at(&receiver_listing_other, Some(&later_list)),
        "blacklist.listed",
    );
    assert_eq!(
        payment
            .prepare_receive(
                &scheme,
                &f.payer.credential,
                &payer_set,
                &request,
                &receiver_credential,
                &receiver_listing_other,
                Some(&later_proof)
            )
            .expect("original Payment after newer list")
            .effect,
        prepared.effect
    );
    assert_eq!(
        payment.to_canonical_bytes().expect("same original bytes"),
        payment_bytes
    );
    let mut other_body = f.payer.credential.body;
    other_body.account_digest = other_account;
    let other_payer = f
        .payer
        .issue(&other_body)
        .expect("other account credential");
    assert_invalid(
        payment.verify(&scheme, &other_payer, &payer_set, &request),
        "request.payer_account_digest",
    );
    payment
        .verify(&scheme, &f.payer.credential, &payer_set, &request)
        .expect("payment");
    payment
        .request
        .verify(&receiver_credential)
        .expect("signed Request");
    let renamed = KagemushaWalletCredentialV1 {
        body: KagemushaWalletCredentialBodyV1 {
            account_digest: other_account,
            ..receiver_credential.body
        },
        ..receiver_credential
    };
    assert!(payment.request.verify(&renamed).is_err());

    // Each row authenticates its own candidate decision before signing. Send enforces its
    // payer's list independently. The already committed original Payment requires the actual
    // version-1 history entry; a different receiving history never substitutes its current list.
    for (payer_list, receiver_list, request_ok, send_ok) in [
        (&lists_receiver, &lists_other, true, false),
        (&lists_other, &lists_payer, false, true),
        (&lists_other, &lists_other, true, true),
    ] {
        let (receiver, history) =
            f.with_blacklist(receiver_base, fee_schedule, Some(receiver_list));
        let (payer, _) = f.with_blacklist(payer_state, fee_schedule, Some(payer_list));
        let issued = f.issue_request_at(&receiver, Some(receiver_list));
        assert_eq!(issued.is_ok(), request_ok);
        assert_eq!(
            f.checked_send_at(&request, &payer, Some(payer_list))
                .is_ok(),
            send_ok
        );
        let matrix_proof = recorded_blacklist_proof(&request, &history, &gap);
        let outcome = payment.prepare_receive(
            &scheme,
            &f.payer.credential,
            &payer_set,
            &request,
            &receiver_credential,
            &receiver,
            Some(&matrix_proof),
        );
        assert_eq!(outcome.is_ok(), request_ok);
    }
}

/// A Payment issued with no recorded blacklist remains receivable after later lists are
/// installed. Later lists refuse new Request/Send attempts; completed evidence still verifies.
#[test]
fn kagemusha_wallet_v1_later_blacklists_preserve_original_payment_and_evidence() {
    let mut f = message_fixture();
    f.payer.credential = blacklist_permitted(&f.payer);
    f.receiver.credential = blacklist_permitted(&f.receiver);
    let payer_account = f.payer.credential.body.account_digest;
    let receiver_account = f.receiver.credential.body.account_digest;
    let other_account = kagemusha_wallet_account_digest_v1(&test_account(0x77)).expect("other");
    let scheme = f.payer.scheme;
    let request = f.request(true);
    let receiver_credential = f.receiver.credential;
    request
        .body
        .check_request_rule(
            &scheme,
            &f.offer(),
            &receiver_credential,
            &receiver_head_state(&receiver_credential),
            None,
        )
        .expect("Request issued before any held list");
    assert_eq!(
        (
            request.body.receiver_blacklist_version,
            request.body.receiver_blacklist_root
        ),
        (0, [0; 32])
    );
    let fee_schedule = request.body.fee_schedule;
    let earlier = f.signed_blacklist(1, &[other_account]);
    let (receiver_state, mut receiver_history) = f.with_blacklist(
        receiver_head_state(&receiver_credential),
        fee_schedule,
        Some(&earlier),
    );
    let (payer_state, mut payer_history) =
        f.with_blacklist(f.payer_state(&request), fee_schedule, Some(&earlier));
    f.checked_send_at(&request, &payer_state, Some(&earlier))
        .expect("Send allowed");
    let payment = f.payment(true, 64);
    let effect = payment
        .receive_effect(&request, &receiver_credential, &receiver_state, None)
        .expect("recorded no-list Receive");
    let payment_bytes = payment
        .to_canonical_bytes()
        .expect("original Payment bytes");
    let credited_receive = f.credited_receive(&payment, 48);
    let credited_status = f.credited_status(&payment, PAYMENT_LINEAGE_LEN, OPENING_OTHER_CREDITS);
    let receiver_list = f.signed_blacklist(2, &[payer_account, other_account]);
    let payer_list = f.signed_blacklist(2, &[receiver_account, other_account]);
    let receiver_later = f.commit_blacklist(receiver_state, &mut receiver_history, &receiver_list);
    let payer_later = f.commit_blacklist(payer_state, &mut payer_history, &payer_list);
    assert_eq!(receiver_later.core.blacklist_version, 2);
    assert_eq!(payer_later.core.blacklist_version, 2);
    assert_invalid(
        f.issue_request_at(&receiver_later, Some(&receiver_list)),
        "blacklist.listed",
    );
    assert_invalid(
        f.checked_send_at(&request, &payer_later, Some(&payer_list)),
        "blacklist.listed",
    );
    assert_eq!(
        payment
            .receive_effect(&request, &receiver_credential, &receiver_later, None)
            .expect("original no-list decision"),
        effect
    );
    assert_eq!(
        payment
            .to_canonical_bytes()
            .expect("same original Payment bytes"),
        payment_bytes
    );
    let pending = payment.pending_outgoing_leaf().expect("pending leaf");
    for credited in [&credited_receive, &credited_status] {
        credited
            .verify_for(&scheme, &request, &payment)
            .expect("Credited evidence after later lists");
        credited
            .archive_sent_effect(&scheme, &request, &payment, &pending)
            .expect("ArchiveSent after later lists");
    }
    let payer_set =
        KagemushaWalletCertificateSetV1::new(vec![f.payer.enrollment_certificate]).expect("set");
    payment
        .verify(&scheme, &f.payer.credential, &payer_set, &request)
        .expect("fee claim after later lists");
}

#[test]
fn kagemusha_wallet_v1_request_binds_both_credential_accounts() {
    let f = message_fixture();
    let request = f.request(true);
    let items = request.body.field_items();
    let limbs = |value: &[u8; 32]| {
        let mut low = [0; 32];
        let mut high = [0; 32];
        low[..16].copy_from_slice(&value[..16]);
        high[..16].copy_from_slice(&value[16..]);
        [low, high]
    };
    assert_eq!(
        &items[7..9],
        &limbs(&f.payer.credential.body.account_digest)
    );
    assert_eq!(
        &items[11..13],
        &limbs(&f.receiver.credential.body.account_digest)
    );
    let mutations: [(&str, RequestBodyMutation); 2] = [
        ("request.payer_account_digest", |body| {
            body.payer_account_digest = [0; 32]
        }),
        ("request.receiver_account_digest", |body| {
            body.receiver_account_digest = [0; 32]
        }),
    ];
    for (field, mutation) in mutations {
        let mut body = request.body;
        mutation(&mut body);
        assert_invalid(body.validate(), field);
        assert_ne!(body.credit_id(), request.credit_id());
        assert_ne!(body.signing_message(), request.body.signing_message());
    }
    let (mut receiver_body, slot, certificates) = f.request_parts(true, 1_000);
    receiver_body.receiver_account_digest = f.payer.credential.body.account_digest;
    assert_invalid(
        f.sign_request(&receiver_body, slot, certificates),
        "request.receiver_account_digest",
    );
    // A valid receiver signature must not grant Send authority for another payer account.
    let (mut payer_body, slot, certificates) = f.request_parts(true, 1_000);
    payer_body.payer_account_digest = f.receiver.credential.body.account_digest;
    assert_invalid(
        f.sign_request(&payer_body, slot, certificates.clone()),
        "request.payer_account_digest",
    );
    // Even a raw adversarial receiver-signed Request outside the canonical constructor must
    // fail the retained Send and Payment account checks.
    let wrong_payer = KagemushaWalletRequestV1 {
        body: payer_body,
        receiver_credential: f.receiver.credential,
        fee_schedule: slot,
        certificates,
        signature: kagemusha_wallet_freeze_signature_v1(
            &f.receiver.credential.body.payment_key,
            Domain::Request,
            &payer_body.signing_message(),
            raw_output(&f.receiver.payment, &payer_body.signing_message()),
        )
        .expect("raw fixture signature"),
    };
    let interval =
        KagemushaWalletTimeIntervalV1::new(ACCEPTED_MS, ACCEPTED_MS + 1).expect("interval");
    assert_invalid(
        wrong_payer.send_effect(&f.payer.credential, &interval),
        "request.payer_account_digest",
    );
    let state = f.payer_state(&request);
    let omega = f.payer_omega(&state);
    assert_invalid(
        wrong_payer.check_send_rule(&f.payer.credential, &state, &omega),
        "request.payer_account_digest",
    );
}

#[test]
fn kagemusha_wallet_v1_request_signing_authenticates_offer_before_freezing() {
    let f = message_fixture();
    let (body, slot, certificates) = f.request_parts(true, 1_000);
    let offer = f.offer();
    let sign = |offer: &KagemushaWalletOfferV1, output| {
        KagemushaWalletRequestV1::sign(
            &f.payer.scheme,
            offer,
            body,
            f.receiver.credential,
            slot,
            certificates.clone(),
            output,
        )
    };
    sign(
        &offer,
        raw_output(&f.receiver.payment, &body.signing_message()),
    )
    .expect("authenticated payer context");
    let mut unauthenticated = offer.clone();
    unauthenticated.body.session_nonce[0] ^= 1;
    assert_signature(
        sign(
            &unauthenticated,
            KagemushaWalletSignerOutputV1::Raw([0; 64]),
        ),
        Domain::Offer,
    );
    // An issuer-authenticated Offer with the same payer key/wallet but another canonical
    // account is still the wrong Request context.
    let mut credential_body = f.payer.credential.body;
    credential_body.account_digest = f.receiver.credential.body.account_digest;
    let credential = KagemushaWalletCredentialV1::sign(
        credential_body,
        &f.payer.enrollment_certificate,
        raw_output(
            &f.payer.enrollment_signer,
            &credential_body.signing_message(),
        ),
    )
    .expect("issuer-signed context");
    let altered_body = KagemushaWalletOfferBodyV1 {
        payer_credential_digest: credential.credential_digest(),
        ..offer.body
    };
    let other_account = KagemushaWalletOfferV1::sign(
        altered_body,
        credential,
        &f.payer.enrollment_certificate,
        raw_output(&f.payer.payment, &altered_body.signing_message()),
    )
    .expect("signed Offer");
    other_account
        .verify(&f.payer.scheme)
        .expect("authenticated Offer");
    assert_invalid(
        sign(&other_account, KagemushaWalletSignerOutputV1::Raw([0; 64])),
        "request.payer_account_digest",
    );
}
