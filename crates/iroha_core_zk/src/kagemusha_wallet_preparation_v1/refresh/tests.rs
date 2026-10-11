//! Signed-original and successor-custody tests, not installed proof acceptance.
//!
//! Capsules supply component fields only; their stand-in proofs never reach the
//! public converter, which still requires full retained proof/receipt verification.

use p256::ecdsa::{Signature, SigningKey, signature::Signer};

use super::*;
use KagemushaWalletPolicyUpdateKindV1 as Kind;

fn vectors() -> norito::json::Value {
    norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap()
}

fn fixture<T>(name: &str) -> T
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    let all = vectors();
    let row = all["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["type"].as_str() == Some(name))
        .unwrap();
    let original = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    norito::decode_canonical_with_limits(&original, norito::canonical_decode_limits(original.len()))
        .unwrap()
}

fn request() -> KagemushaWalletRequestV1 {
    let all = vectors();
    let row = all["envelopes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["kind"].as_str() == Some("Request"))
        .unwrap();
    let original = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
    let envelope: KagemushaWalletEnvelopeV1 = norito::decode_canonical_with_limits(
        &original,
        norito::canonical_decode_limits(original.len()),
    )
    .unwrap();
    let KagemushaWalletMessageV1::Request { request } = envelope.message else {
        panic!("fixture must retain its original Request");
    };
    request
}

fn root() -> SigningKey {
    let all = vectors();
    let row = all["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"].as_str() == Some("scheme_root"))
        .unwrap();
    SigningKey::from_slice(&hex::decode(row["scalar_hex"].as_str().unwrap()).unwrap()).unwrap()
}

fn sign(key: &SigningKey, message: &[u8]) -> KagemushaWalletSignerOutputV1<'static> {
    let signature: Signature = key.sign(message);
    KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into())
}

struct Source {
    scheme: KagemushaWalletSchemeV1,
    current: KagemushaWalletCredentialV1,
    successor: KagemushaWalletCredentialV1,
    state: KagemushaWalletStateV1,
    capsule: KagemushaWalletRecoveryCapsuleV1,
    certificate: KagemushaWalletSignerCertificateV1,
    signing: SigningKey,
    complete_blacklist: Option<Vec<u8>>,
}

impl Source {
    fn complete_original(&self) -> &[u8] {
        if let Some(original) = &self.complete_blacklist {
            original
        } else {
            self.capsule
                .retained_inputs
                .iter()
                .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::PolicyUpdate)
                .map_or(&[], |input| input.bytes.as_slice())
        }
    }

    fn originals(&self) -> RefreshOriginalsV1<'_> {
        let KagemushaWalletEffectV1::RefreshPolicy { update_kind, .. } =
            self.capsule.statement.effect
        else {
            panic!("Refresh fixture required");
        };
        RefreshOriginalsV1 {
            kind: update_kind,
            update: self.complete_original(),
            certificates: retained_original(
                &self.capsule.retained_inputs,
                KagemushaWalletRetainedInputRoleV1::CertificateSet,
            )
            .unwrap(),
            openings: &self.capsule.map_openings,
            quota: self
                .capsule
                .retained_inputs
                .iter()
                .find(|input| input.role == KagemushaWalletRetainedInputRoleV1::QuotaRefreshWitness)
                .map(|input| input.bytes.as_slice()),
        }
    }

    fn new(kind: Kind) -> Self {
        let scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
        let request = request();
        let current = request.receiver_credential;
        let current_certificate = request
            .certificates
            .certificate(&current.body.issuer_certificate, Role::Enrollment)
            .unwrap();
        current.verify(&scheme, current_certificate).unwrap();
        let state = KagemushaWalletStateV1::bootstrap(&current, Fp::from(101).to_repr()).unwrap();
        let signing = SigningKey::from_slice(&[19; 32]).unwrap();
        let body = KagemushaWalletSignerCertificateBodyV1 {
            version: 1,
            scheme_id: scheme.scheme_id(),
            role: match kind {
                Kind::Credential => Role::Enrollment,
                Kind::TimeAnchor => Role::TimeAnchor,
                _ => Role::RegulatoryPolicy,
            },
            key: KagemushaDevicePublicKeyV1::from_sec1_bytes(
                signing.verifying_key().to_encoded_point(false).as_bytes(),
            )
            .unwrap(),
            serial: 99,
        };
        let certificate = KagemushaWalletSignerCertificateV1::sign(
            body,
            &scheme,
            sign(&root(), &body.signing_message()),
        )
        .unwrap();
        let mut capsule: KagemushaWalletRecoveryCapsuleV1 =
            fixture("KagemushaWalletRecoveryCapsuleV1");
        capsule.kind = KagemushaWalletOperationKindV1::RefreshPolicy;
        capsule.map_openings.clear();
        let set = KagemushaWalletCertificateSetV1::new(vec![certificate]).unwrap();
        capsule.retained_inputs = vec![KagemushaWalletRetainedInputV1 {
            role: KagemushaWalletRetainedInputRoleV1::CertificateSet,
            bytes: norito::to_bytes(&set).unwrap(),
        }];
        Self {
            scheme,
            current,
            successor: current,
            state,
            capsule,
            certificate,
            signing,
            complete_blacklist: None,
        }
    }

    fn install(&mut self, kind: Kind, digest: [u8; 32], signed_time: u64, original: Vec<u8>) {
        self.capsule.statement.effect = KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: kind,
            update: digest,
            accepted_time_floor_ms: self.state.core.accepted_time_floor_ms.max(signed_time),
        };
        let retained = if kind == Kind::Blacklist {
            let reference =
                crate::kagemusha_wallet_state_v1::BlacklistOriginalReferenceV1::for_original(
                    &self.scheme.scheme_id(),
                    &original,
                )
                .unwrap()
                .to_canonical_bytes()
                .unwrap();
            self.complete_blacklist = Some(original);
            reference
        } else {
            original
        };
        self.capsule
            .retained_inputs
            .push(KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::PolicyUpdate,
                bytes: retained,
            });
    }

    fn credential() -> Self {
        let mut source = Self::new(Kind::Credential);
        let mut body = source.current.body;
        body.issuer_certificate = source.certificate.certificate_digest();
        body.renewal_sequence += 1;
        body.issued_at_ms += 10;
        if body.lease_expires_at_ms != 0 {
            body.lease_expires_at_ms += 10;
        }
        let update = KagemushaWalletCredentialV1::sign(
            body,
            &source.certificate,
            sign(&source.signing, &body.signing_message()),
        )
        .unwrap();
        source.successor = update;
        source.install(
            Kind::Credential,
            update.credential_digest(),
            body.issued_at_ms,
            update.to_canonical_bytes().unwrap(),
        );
        source
    }

    fn policy() -> Self {
        let mut source = Self::new(Kind::SchemePolicy);
        let body = KagemushaWalletSchemePolicyBodyV1 {
            version: 1,
            scheme_id: source.scheme.scheme_id(),
            asset_digest: source.current.body.asset_digest,
            policy_epoch: 1,
            enabled_controls: 7,
            fee_schedule: [0; 32],
            signer_certificate: source.certificate.certificate_digest(),
        };
        let update = KagemushaWalletSchemePolicyV1::sign(
            body,
            &source.certificate,
            sign(&source.signing, &body.signing_message()),
        )
        .unwrap();
        source.install(
            Kind::SchemePolicy,
            update.scheme_policy_digest(),
            0,
            update.to_canonical_bytes().unwrap(),
        );
        source
    }

    fn anchor() -> Self {
        let mut source = Self::new(Kind::TimeAnchor);
        let body = KagemushaWalletTimeAnchorBodyV1 {
            version: 1,
            scheme_id: source.scheme.scheme_id(),
            wallet_id: source.current.body.wallet_id,
            nonce: [31; 32],
            issuer_time_ms: 107,
            signer_certificate: source.certificate.certificate_digest(),
        };
        let update = KagemushaWalletTimeAnchorV1::sign(
            body,
            &source.certificate,
            sign(&source.signing, &body.signing_message()),
        )
        .unwrap();
        source.install(
            Kind::TimeAnchor,
            update.time_anchor_digest(),
            body.issuer_time_ms,
            update.to_canonical_bytes().unwrap(),
        );
        source
    }

    fn retain_quota(
        &mut self,
        windows: Vec<KagemushaWalletQuotaWindowV1>,
        usage: &KagemushaWalletQuotaUsageArrayV1,
        share_id: u64,
    ) {
        let body = KagemushaWalletQuotaShareBodyV1 {
            version: 1,
            scheme_id: self.scheme.scheme_id(),
            asset_digest: self.current.body.asset_digest,
            wallet_id: self.current.body.wallet_id,
            share_id,
            issued_at_ms: windows[0].start_ms,
            expires_at_ms: windows.last().unwrap().end_ms,
            windows_root: kagemusha_wallet_quota_windows_root_v1(&windows).unwrap(),
            window_count: u32::try_from(windows.len()).unwrap(),
            signer_certificate: self.certificate.certificate_digest(),
        };
        let update = KagemushaWalletQuotaShareV1::sign(
            body,
            windows,
            &self.certificate,
            sign(&self.signing, &body.signing_message()),
        )
        .unwrap();
        self.capsule
            .retained_inputs
            .retain(|input| input.role == KagemushaWalletRetainedInputRoleV1::CertificateSet);
        self.install(
            Kind::QuotaShare,
            update.quota_share_digest(),
            body.issued_at_ms,
            update.to_canonical_bytes().unwrap(),
        );
        self.capsule
            .retained_inputs
            .push(KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::QuotaRefreshWitness,
                bytes: KagemushaWalletQuotaRefreshWitnessV1::from_usage(usage)
                    .unwrap()
                    .to_canonical_bytes()
                    .unwrap(),
            });
    }

    fn quota() -> Self {
        let mut source = Self::new(Kind::QuotaShare);
        let issued = source.state.core.accepted_time_floor_ms.max(1_000);
        let length = source.state.core.time_anchor_max_response_ms + 10;
        let windows = (0..64)
            .map(|i| {
                let start = issued + u64::try_from(i).unwrap() * length;
                KagemushaWalletQuotaWindowV1 {
                    kind: KagemushaWalletQuotaWindowKindV1::Daily,
                    start_ms: start,
                    end_ms: start + length,
                    limit: 100,
                }
            })
            .collect();
        source.retain_quota(windows, &KagemushaWalletQuotaUsageArrayV1::empty(), 1);
        source
    }

    fn blacklist() -> Self {
        let mut source = Self::new(Kind::Blacklist);
        let body = KagemushaWalletBlacklistBodyV1 {
            version: 1,
            scheme_id: source.scheme.scheme_id(),
            list_version: 1,
            issued_at_ms: 109,
            entry_count: 0,
            entries_root: kagemusha_wallet_blacklist_root_v1(&[]).unwrap(),
            signer_certificate: source.certificate.certificate_digest(),
        };
        let update = KagemushaWalletBlacklistV1::sign(
            body,
            vec![],
            &source.certificate,
            sign(&source.signing, &body.signing_message()),
        )
        .unwrap();
        let entry = KagemushaWalletBlacklistHistoryLeafV1 {
            list_version: body.list_version,
            entries_root: body.entries_root,
        };
        let mut tree = KagemushaWalletIndexedTreeV1::new();
        assert_eq!(tree.root(), source.state.rest.blacklist_history_root);
        let history = entry.insert_into(&mut tree).unwrap();
        source.capsule.map_openings = vec![
            history.low_opening.leaf_transcript(&history.low),
            history.slot_opening.empty_transcript(),
        ];
        source.install(
            Kind::Blacklist,
            update.blacklist_digest(),
            body.issued_at_ms,
            update.to_canonical_bytes().unwrap(),
        );
        source
    }

    fn decode(&self) -> Result<DecodedRefresh, Error> {
        decode_update(
            &self.scheme,
            &self.current,
            &self.successor,
            &self.state,
            &self.capsule,
            self.complete_original(),
        )
    }

    fn original(&mut self) -> &mut Vec<u8> {
        &mut self
            .capsule
            .retained_inputs
            .iter_mut()
            .find(|item| item.role == KagemushaWalletRetainedInputRoleV1::PolicyUpdate)
            .unwrap()
            .bytes
    }
}

#[test]
fn signed_renewal_keeps_distinct_old_and_new_credential_custody() {
    let source = Source::credential();
    let decoded = source.decode().unwrap();
    assert_ne!(source.current, source.successor);
    assert_eq!(decoded.projection.kind, RefreshKind::Credential);
    assert_eq!(
        decoded.projection.digest.to_repr(),
        source.successor.credential_digest()
    );
    assert_eq!(
        decoded.core.credential_digest,
        source.successor.credential_digest()
    );
    assert_eq!(
        decoded.core.lease_expires_at_ms,
        source.successor.body.lease_expires_at_ms
    );
    assert_eq!(
        decoded.objects[1],
        signed_tape(
            source.successor.body.transcript(),
            &source.successor.signature
        )
    );
    assert_ne!(
        decoded.objects[1],
        signed_tape(source.current.body.transcript(), &source.current.signature)
    );
    assert_eq!(
        decoded.objects[0],
        signed_tape(
            source.certificate.body.transcript(),
            &source.certificate.signature
        )
    );
    assert_eq!(decoded.projection.scheme, [Fp::ZERO; 2]);
    assert_eq!(decoded.projection.asset, [Fp::ZERO; 2]);
    assert_eq!(decoded.projection.wallet, [Fp::ZERO; 2]);
    for value in [
        decoded.projection.counter,
        decoded.projection.root,
        decoded.projection.controls,
        decoded.projection.fee_schedule,
    ] {
        assert_eq!(value, Fp::ZERO);
    }
    assert!(decoded.blacklist.is_none());
}

#[test]
fn renewal_rejects_replaced_source_owner_replay_and_resigned_identity_changes() {
    let mut source = Source::credential();
    assert!(
        decode_update(
            &source.scheme,
            &source.successor,
            &source.successor,
            &source.state,
            &source.capsule,
            source.complete_original(),
        )
        .is_err()
    );
    assert!(
        decode_update(
            &source.scheme,
            &source.current,
            &source.current,
            &source.state,
            &source.capsule,
            source.complete_original(),
        )
        .is_err()
    );
    for changed in 0..4 {
        let mut body = source.successor.body;
        match changed {
            0 => body.renewal_sequence -= 1,
            1 => body.renewal_sequence += 1,
            2 => body.account_digest[0] ^= 1,
            _ => {
                body.payment_key = source.certificate.body.key;
                body.wallet_id = kagemusha_wallet_id_v1(
                    &body.scheme_id,
                    &body.asset_digest,
                    &body.payment_key,
                    &body.enrollment_id,
                );
            }
        }
        // A valid issuer signature cannot authorize a foreign incarnation or skipped renewal.
        let update = KagemushaWalletCredentialV1::sign(
            body,
            &source.certificate,
            sign(&source.signing, &body.signing_message()),
        )
        .unwrap();
        let mut capsule = source.capsule.clone();
        capsule
            .retained_inputs
            .iter_mut()
            .find(|item| item.role == KagemushaWalletRetainedInputRoleV1::PolicyUpdate)
            .unwrap()
            .bytes = update.to_canonical_bytes().unwrap();
        capsule.statement.effect = KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: Kind::Credential,
            update: update.credential_digest(),
            accepted_time_floor_ms: body.issued_at_ms,
        };
        assert!(
            decode_update(
                &source.scheme,
                &source.current,
                &update,
                &source.state,
                &capsule,
                retained_original(
                    &capsule.retained_inputs,
                    KagemushaWalletRetainedInputRoleV1::PolicyUpdate
                )
                .unwrap(),
            )
            .is_err()
        );
    }
    // Changing a signed body without changing the signature is also rejected.
    source.successor.body.issued_at_ms += 1;
    let changed = source.successor.to_canonical_bytes().unwrap();
    *source.original() = changed;
    assert!(source.decode().is_err());
}

#[test]
fn all_available_updates_have_exact_typed_projections_and_preserve_other_fields() {
    for source in [
        Source::credential(),
        Source::policy(),
        Source::anchor(),
        Source::blacklist(),
        Source::quota(),
    ] {
        let decoded = source.decode().unwrap();
        assert_eq!(decoded.effect, source.capsule.statement.effect);
        let mut successor = KagemushaWalletStateV1 {
            version: source.state.version,
            core: decoded.core,
            rest: decoded.rest,
        };
        successor.core.sequence += 1;
        successor.core.state_nonce = Fp::from(127).to_repr();
        exact_successor(&source.state, &successor, &decoded).unwrap();
        for changed in 0..8 {
            let mut rebound = successor;
            match changed {
                0 => rebound.core.balance += 1,
                1 => rebound.core.next_send += 1,
                2 => rebound.core.next_load += 1,
                3 => rebound.core.next_redeem += 1,
                4 => rebound.core.sequence += 1,
                5 => rebound.core.send_chain = Fp::ONE.to_repr(),
                6 => rebound.core.load_redeem_recovery_root = Fp::ONE.to_repr(),
                _ => rebound.rest.quota_share = Fp::ONE.to_repr(),
            }
            assert_eq!(
                exact_successor(&source.state, &rebound, &decoded),
                Err(Error::Authority)
            );
        }
        if decoded.projection.kind != RefreshKind::Credential {
            assert_eq!(decoded.projection.scheme, limbs(&source.scheme.scheme_id()));
            assert_eq!(
                decoded.core.credential_digest,
                source.current.credential_digest()
            );
        }
        if decoded.projection.kind == RefreshKind::Blacklist {
            assert!(decoded.blacklist.is_some());
            assert_ne!(
                decoded.rest.blacklist_history_root,
                source.state.rest.blacklist_history_root
            );
        }
    }
}

#[test]
fn original_role_signature_effect_and_map_substitutions_fail() {
    for mut source in [
        Source::credential(),
        Source::policy(),
        Source::anchor(),
        Source::blacklist(),
        Source::quota(),
    ] {
        let originals = source.capsule.retained_inputs.clone();
        for role in 0..2 {
            source.capsule.retained_inputs = originals.clone();
            source.capsule.retained_inputs.remove(role);
            assert!(source.decode().is_err());
            source.capsule.retained_inputs = originals.clone();
            source.capsule.retained_inputs.push(originals[role].clone());
            assert!(source.decode().is_err());
        }
        source.capsule.retained_inputs = originals.clone();
        source.original().push(0);
        assert!(source.decode().is_err());
        source.capsule.retained_inputs = originals;
        let effect = source.capsule.statement.effect;
        let KagemushaWalletEffectV1::RefreshPolicy {
            accepted_time_floor_ms,
            ..
        } = &mut source.capsule.statement.effect
        else {
            unreachable!()
        };
        *accepted_time_floor_ms += 1;
        assert!(source.decode().is_err());
        source.capsule.statement.effect = effect;
        source.capsule.map_openings.push(vec![0]);
        assert!(source.decode().is_err());
    }
    let mut blacklist = Source::blacklist();
    blacklist.capsule.map_openings[1][4] ^= 1;
    assert!(blacklist.decode().is_err());
    let mut policy = Source::policy();
    policy.successor = Source::credential().successor;
    assert!(policy.decode().is_err());
}

#[test]
fn quota_has_no_unchecked_array_fallback_and_canonical_certificates_are_bounded() {
    let mut source = Source::policy();
    let KagemushaWalletEffectV1::RefreshPolicy { update_kind, .. } =
        &mut source.capsule.statement.effect
    else {
        unreachable!()
    };
    *update_kind = Kind::QuotaShare;
    assert!(source.decode().is_err());
    assert!(certificates(&[], &source.scheme).is_err());
    assert!(
        certificates(
            &vec![0; KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 + 1],
            &source.scheme
        )
        .is_err()
    );
    let mut bad = source.certificate;
    bad.body.serial += 1;
    let original =
        norito::to_bytes(&KagemushaWalletCertificateSetV1::new(vec![bad]).unwrap()).unwrap();
    assert!(certificates(&original, &source.scheme).is_err());
    assert!(projection(RefreshKind::Credential, [0xff; 32]).is_err());
}

#[test]
fn quota_retains_all64_predecessor_slots_and_derives_every_successor_usage() {
    let mut source = Source::quota();
    let first = source.decode().unwrap();
    let q = first.quota.as_ref().unwrap();
    assert_eq!(q.old, [[Fp::ZERO; 4]; 64]);
    assert_eq!(q.used, [Fp::ZERO; 64]);
    assert_eq!(q.window_count, Fp::from(64));
    let scheme_id = source.scheme.scheme_id();
    let old_share =
        KagemushaWalletQuotaShareV1::decode_canonical(source.original(), &scheme_id).unwrap();
    let usage = KagemushaWalletQuotaUsageArrayV1::from_slots(core::array::from_fn(|i| {
        Some(KagemushaWalletQuotaUsageLeafV1::for_window(
            &old_share.windows[i],
            200 + u128::try_from(i).unwrap(),
        ))
    }))
    .unwrap();
    source.state.core = first.core;
    source.state.rest = first.rest;
    source.state.core.quota_usage_root = usage.root();
    source.retain_quota(old_share.windows.clone(), &usage, 2);
    let renewed = source.decode().unwrap();
    let quota = renewed.quota.unwrap();
    for i in 0..64 {
        let leaf = usage.slots()[i].unwrap();
        assert_eq!(
            quota.old[i],
            [
                Fp::ONE,
                Fp::from(leaf.window_start_ms),
                Fp::from(leaf.window_end_ms),
                Fp::from_u128(leaf.used)
            ]
        );
        assert_eq!(quota.used[i], Fp::from_u128(leaf.used));
        assert_eq!(quota.windows[i][3], Fp::from(100));
    }
    assert_eq!(
        renewed.core.quota_usage_root,
        usage.root(),
        "renewal never replenishes spent quota"
    );
    assert_eq!(renewed.rest.quota_share_id, 2);
    let mut omitted_live = old_share.windows.clone();
    omitted_live.pop();
    source.retain_quota(omitted_live, &usage, 3);
    assert!(
        source.decode().is_err(),
        "live charged key cannot disappear"
    );
}

#[test]
fn quota_custody_root_originals_and_typed_role_substitutions_fail() {
    let source = Source::quota();
    for changed in 0..5 {
        let mut capsule = source.capsule.clone();
        let index = capsule
            .retained_inputs
            .iter()
            .position(|input| input.role == KagemushaWalletRetainedInputRoleV1::QuotaRefreshWitness)
            .unwrap();
        match changed {
            0 => {
                capsule.retained_inputs.remove(index);
            }
            1 => capsule
                .retained_inputs
                .push(capsule.retained_inputs[index].clone()),
            2 => capsule.retained_inputs[index].bytes.push(0),
            3 => {
                let mut witness = capsule.quota_refresh_witness().unwrap().unwrap();
                witness.predecessor_usage[0] = Some(KagemushaWalletQuotaUsageLeafV1 {
                    window_kind: KagemushaWalletQuotaWindowKindV1::Daily,
                    window_start_ms: 1_000,
                    window_end_ms: 2_000,
                    used: 1,
                });
                capsule.retained_inputs[index].bytes = witness.to_canonical_bytes().unwrap();
            }
            _ => capsule.retained_inputs[index].role = KagemushaWalletRetainedInputRoleV1::Payment,
        }
        assert!(
            decode_update(
                &source.scheme,
                &source.current,
                &source.successor,
                &source.state,
                &capsule,
                source.complete_original(),
            )
            .is_err()
        );
    }
    let mut unrelated = Source::policy();
    unrelated
        .capsule
        .retained_inputs
        .push(source.capsule.retained_inputs.last().unwrap().clone());
    assert!(unrelated.decode().is_err());
}

#[test]
fn pre_advance_refresh_uses_signed_originals_and_all_five_real_sigma_relations() {
    use iroha_kagemusha_proof::admin_sigma::RefreshCircuit;
    use iroha_plonk::check::{CheckMode, check_circuit};
    for source in [
        Source::credential(),
        Source::policy(),
        Source::blacklist(),
        Source::quota(),
        Source::anchor(),
    ] {
        let originals = source.originals();
        let decoded = decode_originals(
            &source.scheme,
            &source.current,
            &source.successor,
            &source.state,
            originals,
        )
        .unwrap();
        let retained = source.decode().unwrap();
        assert_eq!(decoded.core, retained.core);
        assert_eq!(decoded.rest, retained.rest);
        assert_eq!(decoded.effect, retained.effect);
        assert_eq!(decoded.objects, retained.objects);
        let (state, statement, witness) = prepare::transition(
            &source.current,
            &source.successor,
            &source.state,
            &decoded,
            Fp::from(211).to_repr(),
            source.scheme.relation_id,
            Fp::from(223).to_repr(),
        )
        .unwrap();
        exact_successor(&source.state, &state, &decoded).unwrap();
        statement.validate_for_scheme(&source.scheme).unwrap();
        statement
            .validate_for_credential(&source.successor)
            .unwrap();
        assert_eq!(statement.effect, source.capsule.statement.effect);
        assert_eq!(statement.predecessor, source.state.commitment().unwrap());
        assert_eq!(statement.successor, state.commitment().unwrap());
        assert_eq!(state.core.sequence, source.state.core.sequence + 1);
        let circuit = RefreshCircuit::new(&witness);
        assert!(
            check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "{:?}",
            originals.kind
        );
        // Rehashing the public statement does not authorize a changed effect.
        let mut wrong = witness;
        wrong.statement[18] += Fp::ONE;
        let circuit = RefreshCircuit::new(&wrong);
        assert!(
            !check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        // A local projection carries the current core; it cannot invent burned value.
        let mut wrong = witness;
        wrong.successor.lineage[14] += Fp::ONE;
        let circuit = RefreshCircuit::new(&wrong);
        assert!(
            !check_circuit(&circuit, 12, &circuit.instances(), CheckMode::Strict)
                .unwrap()
                .is_satisfied()
        );
        for nonce in [[0; 32], [0xff; 32]] {
            assert!(
                prepare::transition(
                    &source.current,
                    &source.successor,
                    &source.state,
                    &decoded,
                    nonce,
                    source.scheme.relation_id,
                    Fp::ONE.to_repr(),
                )
                .is_err()
            );
        }
    }
}

#[test]
fn pre_advance_refresh_rejects_extra_missing_or_changed_custody() {
    let quota = Source::quota();
    let policy = Source::policy();
    for source in [&quota, &policy] {
        let mut originals = source.originals();
        originals.quota = if originals.kind == Kind::QuotaShare {
            None
        } else {
            quota.originals().quota
        };
        assert!(
            decode_originals(
                &source.scheme,
                &source.current,
                &source.successor,
                &source.state,
                originals,
            )
            .is_err()
        );
    }
    let blacklist = Source::blacklist();
    let mut originals = policy.originals();
    originals.openings = blacklist.originals().openings;
    assert!(
        decode_originals(
            &policy.scheme,
            &policy.current,
            &policy.successor,
            &policy.state,
            originals,
        )
        .is_err()
    );
    let mut original = policy.originals().update.to_vec();
    original.push(0);
    originals = policy.originals();
    originals.update = &original;
    assert!(
        decode_originals(
            &policy.scheme,
            &policy.current,
            &policy.successor,
            &policy.state,
            originals,
        )
        .is_err()
    );
    // A plausible signed update cannot authenticate a different retained usage root.
    let mut source = quota.state;
    source.core.quota_usage_root = Fp::from(227).to_repr();
    assert!(
        decode_originals(
            &quota.scheme,
            &quota.current,
            &quota.successor,
            &source,
            quota.originals(),
        )
        .is_err()
    );
}

#[path = "installed_tests.rs"]
mod installed_tests;

#[test]
fn blacklist_reference_binds_full_original_and_rejects_inline_or_changed_complete_update() {
    let mut source = Source::blacklist();
    source.decode().unwrap();
    let complete = source.complete_original().to_vec();
    let retained = source.original().clone();
    assert_ne!(retained, complete);
    assert!(retained.len() <= 512);
    *source.original() = complete.clone();
    assert!(source.decode().is_err(), "no old inline Blacklist fallback");
    *source.original() = retained;
    source.complete_blacklist.as_mut().unwrap().push(0);
    assert!(
        source.decode().is_err(),
        "complete original remains exact despite a valid reference frame"
    );
    source.complete_blacklist = Some(complete);
    source.decode().unwrap();
}
