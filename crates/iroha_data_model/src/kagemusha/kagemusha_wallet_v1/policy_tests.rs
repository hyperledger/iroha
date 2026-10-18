//! Scheme policy, fee schedule, blacklist, quota share, time anchor and charge quote tests.

use p256::ecdsa::SigningKey;

use super::*;
use crate::kagemusha::kagemusha_wallet_v1::{
    KAGEMUSHA_WALLET_VERSION_V1, KagemushaWalletValidationErrorV1,
    codec_tests::{assert_every_flip_rejected_or_rebound, norito_tag},
    identity::{
        KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1, KagemushaWalletEvidenceKindV1,
        KagemushaWalletRegulatoryPolicyV1,
        identity_tests::{
            IdentityFixture, identity_fixture, raw_output, signing_key, test_certificate,
        },
    },
    poseidon::kagemusha_wallet_poseidon_v1,
    state::{KagemushaWalletLifecycleV1, state_tests::field_value},
};

const T0_MS: u64 = 1_790_000_000_000;
const DAY_MS: u64 = 86_400_000;
const LEASE_MS: u64 = T0_MS + 30 * DAY_MS;
const MAX_RESPONSE_MS: u64 = 5_000;
const BOOT: [u8; 32] = [0xb0; 32];

/// Wallet whose credential permits every control, with its policy signers.
struct PolicyFixture {
    identity: IdentityFixture,
    regulator: SigningKey,
    regulator_certificate: KagemushaWalletSignerCertificateV1,
    time_signer: SigningKey,
    time_certificate: KagemushaWalletSignerCertificateV1,
    credential: KagemushaWalletCredentialV1,
}

fn policy_fixture() -> PolicyFixture {
    let identity = identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x4b);
    let regulator = signing_key(0x33);
    let regulator_certificate = test_certificate(
        &identity.scheme,
        &identity.root,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
        &regulator,
        2,
    );
    let time_signer = signing_key(0x34);
    let time_certificate = test_certificate(
        &identity.scheme,
        &identity.root,
        KagemushaWalletSignerRoleV1::TimeAnchor,
        &time_signer,
        3,
    );
    let mut body = identity.credential.body;
    body.regulatory_policy = KagemushaWalletRegulatoryPolicyV1 {
        permitted_controls: KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1,
        time_anchor_max_response_ms: MAX_RESPONSE_MS,
    };
    body.lease_expires_at_ms = LEASE_MS;
    let credential = identity.issue(&body).expect("controlled credential");
    PolicyFixture {
        identity,
        regulator,
        regulator_certificate,
        time_signer,
        time_certificate,
        credential,
    }
}

impl PolicyFixture {
    fn scheme(&self) -> &KagemushaWalletSchemeV1 {
        &self.identity.scheme
    }

    fn scheme_id(&self) -> [u8; 32] {
        self.credential.body.scheme_id
    }

    fn wallet_id(&self) -> [u8; 32] {
        self.credential.body.wallet_id
    }

    fn state(&self) -> KagemushaWalletStateV1 {
        KagemushaWalletStateV1::bootstrap(&self.credential, field_value(0x5d))
            .expect("bootstrap state")
    }

    fn scheme_policy(
        &self,
        epoch: u64,
        enabled_controls: u32,
        fee_schedule: [u8; 32],
    ) -> KagemushaWalletSchemePolicyV1 {
        let body = KagemushaWalletSchemePolicyBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.credential.body.asset_digest,
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

    fn fee_body(&self) -> KagemushaWalletFeeScheduleBodyV1 {
        KagemushaWalletFeeScheduleBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.credential.body.asset_digest,
            schedule_id: 7,
            beneficiary_account_digest: [0xbe; 32],
            basis_points: 25,
            fixed: 3,
            minimum: 5,
            maximum: 1_000,
            rounding: KagemushaWalletFeeRoundingV1::Up,
            signer_certificate: self.regulator_certificate.certificate_digest(),
        }
    }

    fn fee_schedule(&self, body: KagemushaWalletFeeScheduleBodyV1) -> KagemushaWalletFeeScheduleV1 {
        KagemushaWalletFeeScheduleV1::sign(
            body,
            &self.regulator_certificate,
            raw_output(&self.regulator, &body.signing_message()),
        )
        .expect("fee schedule")
    }

    fn blacklist(
        &self,
        list_version: u64,
        issued_at_ms: u64,
        entries: Vec<KagemushaWalletBlacklistEntryV1>,
    ) -> KagemushaWalletBlacklistV1 {
        let body = KagemushaWalletBlacklistBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            list_version,
            issued_at_ms,
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

    fn share_body(
        &self,
        share_id: u64,
        windows: &[KagemushaWalletQuotaWindowV1],
    ) -> KagemushaWalletQuotaShareBodyV1 {
        KagemushaWalletQuotaShareBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.credential.body.asset_digest,
            wallet_id: self.wallet_id(),
            share_id,
            issued_at_ms: T0_MS,
            expires_at_ms: T0_MS + 40 * DAY_MS,
            windows_root: kagemusha_wallet_quota_windows_root_v1(windows).expect("root"),
            window_count: u32::try_from(windows.len()).expect("count"),
            signer_certificate: self.regulator_certificate.certificate_digest(),
        }
    }

    fn quota_share(
        &self,
        share_id: u64,
        windows: Vec<KagemushaWalletQuotaWindowV1>,
    ) -> KagemushaWalletQuotaShareV1 {
        let body = self.share_body(share_id, &windows);
        KagemushaWalletQuotaShareV1::sign(
            body,
            windows,
            &self.regulator_certificate,
            raw_output(&self.regulator, &body.signing_message()),
        )
        .expect("quota share")
    }

    fn time_anchor(&self, issuer_time_ms: u64) -> KagemushaWalletTimeAnchorV1 {
        let body = KagemushaWalletTimeAnchorBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            wallet_id: self.wallet_id(),
            nonce: [0x4e; 32],
            issuer_time_ms,
            signer_certificate: self.time_certificate.certificate_digest(),
        };
        KagemushaWalletTimeAnchorV1::sign(
            body,
            &self.time_certificate,
            raw_output(&self.time_signer, &body.signing_message()),
        )
        .expect("time anchor")
    }

    fn charge_body(
        &self,
        kind: KagemushaWalletChargeKindV1,
        net_amount: u128,
        online_charge: u128,
    ) -> KagemushaWalletChargeQuoteBodyV1 {
        KagemushaWalletChargeQuoteBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: self.scheme_id(),
            asset_digest: self.credential.body.asset_digest,
            wallet_id: self.wallet_id(),
            kind,
            ordinal: 2,
            net_amount,
            online_charge,
            beneficiary_account_digest: [0xbf; 32],
            issued_at_ms: T0_MS,
            signer_certificate: self.regulator_certificate.certificate_digest(),
        }
    }

    fn charge_quote(&self, body: KagemushaWalletChargeQuoteBodyV1) -> KagemushaWalletChargeQuoteV1 {
        KagemushaWalletChargeQuoteV1::sign(
            body,
            &self.regulator_certificate,
            raw_output(&self.regulator, &body.signing_message()),
        )
        .expect("charge quote")
    }

    /// State with every control enabled and the given objects committed by `RefreshPolicy`.
    fn controlled_state(
        &self,
        share: Option<&KagemushaWalletQuotaShareV1>,
        anchor: Option<&KagemushaWalletTimeAnchorV1>,
    ) -> KagemushaWalletStateV1 {
        let mut state = self.state();
        let policy = self.scheme_policy(1, KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1, [0; 32]);
        let refresh = state
            .refresh_policy(KagemushaWalletPolicyUpdateV1::SchemePolicy { policy: &policy })
            .expect("scheme policy");
        state.core = refresh.core;
        state.rest = refresh.rest;
        if let Some(share) = share {
            let usage = KagemushaWalletQuotaUsageArrayV1::empty();
            assert_eq!(usage.root(), state.core.quota_usage_root);
            let refresh = state
                .refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
                    share,
                    usage: &usage,
                })
                .expect("quota share");
            let rebuilt = refresh.quota_usage.expect("installed native usage array");
            assert_eq!(rebuilt.root(), refresh.core.quota_usage_root);
            state.core = refresh.core;
            state.rest = refresh.rest;
        }
        if let Some(anchor) = anchor {
            let refresh = state
                .refresh_policy(KagemushaWalletPolicyUpdateV1::TimeAnchor { anchor })
                .expect("time anchor");
            state.core = refresh.core;
            state.rest = refresh.rest;
        }
        state
    }
}

/// One mutation of a quota share body.
type ShareBodyMutation = fn(&mut KagemushaWalletQuotaShareBodyV1);

fn entry(byte: u8) -> KagemushaWalletBlacklistEntryV1 {
    KagemushaWalletBlacklistEntryV1 {
        account_digest: [byte; 32],
    }
}

fn window(
    kind: KagemushaWalletQuotaWindowKindV1,
    start_ms: u64,
    end_ms: u64,
    limit: u128,
) -> KagemushaWalletQuotaWindowV1 {
    KagemushaWalletQuotaWindowV1 {
        kind,
        start_ms,
        end_ms,
        limit,
    }
}

/// Two daily windows and one monthly window starting at `T0_MS`.
fn sample_windows() -> Vec<KagemushaWalletQuotaWindowV1> {
    vec![
        window(
            KagemushaWalletQuotaWindowKindV1::Daily,
            T0_MS,
            T0_MS + DAY_MS,
            1_000,
        ),
        window(
            KagemushaWalletQuotaWindowKindV1::Daily,
            T0_MS + DAY_MS,
            T0_MS + 2 * DAY_MS,
            1_000,
        ),
        window(
            KagemushaWalletQuotaWindowKindV1::Monthly,
            T0_MS,
            T0_MS + 30 * DAY_MS,
            5_000,
        ),
    ]
}

fn interval(lower_ms: u64, upper_ms: u64) -> KagemushaWalletTimeIntervalV1 {
    KagemushaWalletTimeIntervalV1::new(lower_ms, upper_ms).expect("interval")
}

fn is_invalid<T>(result: WalletResult<T>, expected: &str) -> bool {
    matches!(
        result.err(),
        Some(KagemushaWalletValidationErrorV1::InvalidField { field }) if field == expected
    )
}

/// Naive full-width blacklist root over all 65,536 leaves.
fn naive_blacklist_root(entries: &[KagemushaWalletBlacklistEntryV1]) -> [u8; 32] {
    let mut sentinels = vec![KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_LOW_V1];
    sentinels.extend(entries.iter().map(|entry| entry.account_digest));
    sentinels.push(KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1);
    let padding = kagemusha_wallet_blacklist_leaf_v1(
        &KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1,
        &KAGEMUSHA_WALLET_BLACKLIST_SENTINEL_HIGH_V1,
    );
    let mut level: Vec<[u8; 32]> = (0..KAGEMUSHA_WALLET_BLACKLIST_LEAVES_V1 as usize)
        .map(
            |index| match (sentinels.get(index), sentinels.get(index + 1)) {
                (Some(lower), Some(upper)) => kagemusha_wallet_blacklist_leaf_v1(lower, upper),
                _ => padding,
            },
        )
        .collect();
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| kagemusha_wallet_blacklist_node_v1(&pair[0], &pair[1]).expect("node"))
            .collect();
    }
    level[0]
}

#[test]
fn kagemusha_wallet_v1_policy_transcript_lengths_are_pinned() {
    let f = policy_fixture();
    for (constant, expected) in [
        (KAGEMUSHA_WALLET_SCHEME_POLICY_BODY_TRANSCRIPT_BYTES_V1, 142),
        (KAGEMUSHA_WALLET_FEE_SCHEDULE_BODY_TRANSCRIPT_BYTES_V1, 191),
        (KAGEMUSHA_WALLET_BLACKLIST_BODY_TRANSCRIPT_BYTES_V1, 118),
        (KAGEMUSHA_WALLET_QUOTA_SHARE_BODY_TRANSCRIPT_BYTES_V1, 190),
        (KAGEMUSHA_WALLET_TIME_ANCHOR_BODY_TRANSCRIPT_BYTES_V1, 138),
        (KAGEMUSHA_WALLET_CHARGE_QUOTE_BODY_TRANSCRIPT_BYTES_V1, 219),
        (KAGEMUSHA_WALLET_BLACKLIST_TREE_DEPTH_V1, 16),
        (KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1, 6),
        (KAGEMUSHA_WALLET_QUOTA_WINDOWS_MAX_V1, 64),
    ] {
        assert_eq!(constant, expected);
    }
    assert_eq!(KAGEMUSHA_WALLET_BLACKLIST_LEAVES_V1, 65_536);
    assert_eq!(KAGEMUSHA_WALLET_BLACKLIST_ENTRIES_MAX_V1, 65_535);
    assert_eq!(KAGEMUSHA_WALLET_FEE_BASIS_POINTS_DENOMINATOR_V1, 10_000);
    let policy = f.scheme_policy(1, 0, [0; 32]);
    assert_eq!(
        policy.body.transcript().len(),
        KAGEMUSHA_WALLET_SCHEME_POLICY_BODY_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(
        f.fee_body().transcript().len(),
        KAGEMUSHA_WALLET_FEE_SCHEDULE_BODY_TRANSCRIPT_BYTES_V1
    );
    let list = f.blacklist(1, T0_MS, vec![entry(3)]);
    assert_eq!(
        list.body.transcript().len(),
        KAGEMUSHA_WALLET_BLACKLIST_BODY_TRANSCRIPT_BYTES_V1
    );
    let windows = sample_windows();
    assert_eq!(windows[0].field_items().len(), 4);
    assert_eq!(
        f.share_body(1, &windows).transcript().len(),
        KAGEMUSHA_WALLET_QUOTA_SHARE_BODY_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(
        f.time_anchor(T0_MS).body.transcript().len(),
        KAGEMUSHA_WALLET_TIME_ANCHOR_BODY_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(
        f.charge_body(KagemushaWalletChargeKindV1::Load, 1, 1)
            .transcript()
            .len(),
        KAGEMUSHA_WALLET_CHARGE_QUOTE_BODY_TRANSCRIPT_BYTES_V1
    );
}

#[test]
fn kagemusha_wallet_v1_policy_enum_tags_equal_norito_tags() {
    for rounding in KagemushaWalletFeeRoundingV1::ALL {
        assert_eq!(norito_tag(&rounding), u32::from(rounding.tag()));
    }
    for kind in KagemushaWalletQuotaWindowKindV1::ALL {
        assert_eq!(norito_tag(&kind), u32::from(kind.tag()));
    }
    for kind in KagemushaWalletChargeKindV1::ALL {
        assert_eq!(norito_tag(&kind), u32::from(kind.tag()));
    }
    let f = policy_fixture();
    let anchor = f.time_anchor(T0_MS);
    let update_kinds = [
        KagemushaWalletPolicyUpdateV1::Credential {
            previous: &f.credential,
            replacement: &f.credential,
        }
        .kind(),
        KagemushaWalletPolicyUpdateV1::TimeAnchor { anchor: &anchor }.kind(),
    ];
    assert_eq!(
        update_kinds,
        [
            KagemushaWalletPolicyUpdateKindV1::Credential,
            KagemushaWalletPolicyUpdateKindV1::TimeAnchor
        ]
    );
}

#[test]
fn kagemusha_wallet_v1_scheme_policy_sign_verify_decode() {
    let f = policy_fixture();
    let policy = f.scheme_policy(3, KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1, [0x0f; 32]);
    policy
        .verify(f.scheme(), &f.regulator_certificate)
        .expect("verify");
    let mut expected = 1_u16.to_le_bytes().to_vec();
    expected.extend_from_slice(&f.scheme_id());
    expected.extend_from_slice(&f.credential.body.asset_digest);
    expected.extend_from_slice(&3_u64.to_le_bytes());
    expected.extend_from_slice(&KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1.to_le_bytes());
    expected.extend_from_slice(&[0x0f; 32]);
    expected.extend_from_slice(&f.regulator_certificate.certificate_digest());
    assert_eq!(policy.body.transcript(), expected);
    assert_eq!(
        policy.scheme_policy_digest(),
        kagemusha_wallet_signed_object_digest_v1(
            ObjectDomain::SchemePolicy,
            &kagemusha_wallet_signing_message_v1(Domain::SchemePolicy, &expected),
            &policy.signature
        )
    );

    let frame = policy.to_canonical_bytes().expect("encode");
    assert_eq!(
        KagemushaWalletSchemePolicyV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        policy
    );
    assert!(matches!(
        KagemushaWalletSchemePolicyV1::decode_canonical(&frame, &[0x01; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    assert!(matches!(
        KagemushaWalletSchemePolicyV1::decode_canonical(&vec![0; 1_025], &f.scheme_id()),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
    assert_every_flip_rejected_or_rebound(&frame, policy.scheme_policy_digest(), |bytes| {
        let policy = KagemushaWalletSchemePolicyV1::decode_canonical(bytes, &f.scheme_id()).ok()?;
        policy.verify(f.scheme(), &f.regulator_certificate).ok()?;
        Some(policy.scheme_policy_digest())
    });

    let mut body = policy.body;
    body.policy_epoch = 0;
    assert!(is_invalid(body.validate(), "scheme_policy.policy_epoch"));
    body.policy_epoch = 1;
    // Only the quota and lease bits are defined.
    assert_eq!(KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1, 0b11);
    for undefined in [1 << 2, 1 << 3] {
        body.enabled_controls = undefined;
        assert!(is_invalid(
            body.validate(),
            "scheme_policy.enabled_controls"
        ));
    }
    // The Enrollment-role certificate cannot sign policy.
    let body = policy.body;
    assert!(is_invalid(
        KagemushaWalletSchemePolicyV1::sign(
            KagemushaWalletSchemePolicyBodyV1 {
                signer_certificate: f.identity.enrollment_certificate.certificate_digest(),
                ..body
            },
            &f.identity.enrollment_certificate,
            raw_output(&f.identity.enrollment_signer, &body.signing_message()),
        ),
        "certificate.role"
    ));
    assert!(is_invalid(
        policy.verify(f.scheme(), &f.time_certificate),
        "scheme_policy.signer_certificate"
    ));
    assert!(matches!(
        KagemushaWalletSchemePolicyV1::sign(
            body,
            &f.regulator_certificate,
            raw_output(&f.time_signer, &body.signing_message()),
        ),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature {
            domain: Domain::SchemePolicy
        })
    ));
}

#[test]
fn kagemusha_wallet_v1_fee_schedule_exact_fee() {
    let f = policy_fixture();
    let schedule = f.fee_schedule(f.fee_body());
    schedule
        .verify(f.scheme(), &f.regulator_certificate)
        .expect("verify");
    // fixed 3 + ceil(a * 25 / 10_000), clamped to [5, 1_000].
    for (amount, expected) in [
        (0_u128, 5_u128),
        (1, 5),
        (800, 5),
        (801, 6),
        (10_000, 28),
        (10_001, 29),
        (u128::MAX, 1_000),
    ] {
        assert_eq!(schedule.fee(amount).expect("fee"), expected, "{amount}");
    }
    let terms =
        |basis_points, fixed, minimum, maximum, rounding| KagemushaWalletFeeScheduleBodyV1 {
            basis_points,
            fixed,
            minimum,
            maximum,
            rounding,
            ..f.fee_body()
        };
    // Brute-force agreement where `a * bp` fits u128.
    for rounding in KagemushaWalletFeeRoundingV1::ALL {
        for basis_points in [0_u32, 1, 25, 9_999, 10_000] {
            let body = terms(basis_points, 7, 0, u128::MAX, rounding);
            for amount in [
                0_u128,
                1,
                9_999,
                10_000,
                10_001,
                123_456_789,
                u128::MAX / 10_000,
            ] {
                let product = amount * u128::from(basis_points);
                let mut proportional = product / 10_000;
                if rounding == KagemushaWalletFeeRoundingV1::Up && product % 10_000 != 0 {
                    proportional += 1;
                }
                assert_eq!(
                    body.fee(amount).expect("fee"),
                    7 + proportional,
                    "{rounding:?} {basis_points} {amount}"
                );
            }
        }
    }
    // The exact split never overflows before the true result does.
    let full = terms(10_000, 0, 0, u128::MAX, KagemushaWalletFeeRoundingV1::Down);
    assert_eq!(full.fee(u128::MAX).expect("fee"), u128::MAX);
    let fixed = terms(10_000, 1, 0, u128::MAX, KagemushaWalletFeeRoundingV1::Down);
    assert!(matches!(
        fixed.fee(u128::MAX),
        Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow {
            field: "fee_schedule.fee"
        })
    ));
    let up = terms(9_999, 0, 0, u128::MAX, KagemushaWalletFeeRoundingV1::Up);
    assert_eq!(
        up.fee(u128::MAX).expect("fee"),
        (u128::MAX / 10_000) * 9_999 + ((u128::MAX % 10_000) * 9_999).div_ceil(10_000)
    );
    assert!(is_invalid(
        terms(10_001, 0, 0, 1, KagemushaWalletFeeRoundingV1::Down).fee(1),
        "fee_schedule.basis_points"
    ));
    assert!(is_invalid(
        terms(1, 0, 2, 1, KagemushaWalletFeeRoundingV1::Down).validate(),
        "fee_schedule.maximum"
    ));
    let mut zero_beneficiary = f.fee_body();
    zero_beneficiary.beneficiary_account_digest = [0; 32];
    assert!(is_invalid(
        zero_beneficiary.validate(),
        "fee_schedule.beneficiary_account_digest"
    ));

    let frame = schedule.to_canonical_bytes().expect("encode");
    assert_eq!(
        KagemushaWalletFeeScheduleV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        schedule
    );
    assert_every_flip_rejected_or_rebound(&frame, schedule.fee_schedule_digest(), |bytes| {
        let schedule =
            KagemushaWalletFeeScheduleV1::decode_canonical(bytes, &f.scheme_id()).ok()?;
        schedule.verify(f.scheme(), &f.regulator_certificate).ok()?;
        Some(schedule.fee_schedule_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_blacklist_root_matches_the_full_tree() {
    let entries = vec![entry(0x10), entry(0x20), entry(0x30)];
    assert_eq!(
        kagemusha_wallet_blacklist_root_v1(&entries).expect("root"),
        naive_blacklist_root(&entries)
    );
    assert_eq!(
        kagemusha_wallet_blacklist_root_v1(&[]).expect("empty root"),
        naive_blacklist_root(&[])
    );
    // Poseidon trees (§7): a gap leaf over the four limbs of `lower || upper`, a node over its
    // two children.
    let limb = |value: u8| {
        let mut item = [0_u8; 32];
        item[..16].copy_from_slice(&[value; 16]);
        item
    };
    assert_eq!(
        Some(kagemusha_wallet_blacklist_leaf_v1(&[0x10; 32], &[0x20; 32])),
        kagemusha_wallet_poseidon_v1(
            KAGEMUSHA_WALLET_BLACKLIST_LEAF_DOMAIN_V1,
            &[limb(0x10), limb(0x10), limb(0x20), limb(0x20)]
        )
        .ok()
    );
    assert_eq!(
        kagemusha_wallet_blacklist_node_v1(&[0x10; 32], &[0x20; 32]).ok(),
        kagemusha_wallet_poseidon_v1(
            KAGEMUSHA_WALLET_BLACKLIST_NODE_DOMAIN_V1,
            &[[0x10; 32], [0x20; 32]]
        )
        .ok()
    );
    assert!(is_invalid(
        kagemusha_wallet_blacklist_node_v1(&[0x10; 32], &[0xff; 32]),
        "blacklist.node"
    ));
    let root = kagemusha_wallet_blacklist_root_v1(&entries).expect("root");
    assert!(super::super::digest::kagemusha_wallet_is_canonical_field_v1(&root));
    for (entries, field) in [
        (vec![entry(0x20), entry(0x10)], "blacklist.order"),
        (vec![entry(0x10), entry(0x10)], "blacklist.order"),
        (vec![entry(0x00)], "blacklist.sentinel"),
        (vec![entry(0x10), entry(0xff)], "blacklist.sentinel"),
    ] {
        assert!(
            is_invalid(kagemusha_wallet_blacklist_root_v1(&entries), field),
            "{field}"
        );
    }
}

#[track_caller]
fn assert_blocked<T: core::fmt::Debug>(result: WalletResult<T>, expected: &str) {
    match result {
        Err(KagemushaWalletValidationErrorV1::BlockedAccount { field }) if field == expected => {}
        other => panic!("expected blocked `{expected}`, got {other:?}"),
    }
}

/// The local blacklist (owner decision 2026-10-17): a held, authenticated list refuses exactly
/// its listed accounts under the caller's field label, and with no list held nothing is
/// refused.
#[test]
fn kagemusha_wallet_v1_local_block_refuses_only_listed_accounts() {
    let f = policy_fixture();
    let list = f.blacklist(1, T0_MS, vec![entry(0x10), entry(0x20), entry(0x30)]);
    list.verify(f.scheme(), &f.regulator_certificate)
        .expect("verify list");
    let empty = f.blacklist(2, T0_MS, Vec::new());
    for field in [
        "request.payer_account_digest",
        "request.receiver_account_digest",
    ] {
        for listed in [entry(0x10), entry(0x20), entry(0x30)] {
            assert!(list.contains(&listed.account_digest));
            assert_blocked(
                kagemusha_wallet_local_block_v1(Some(&list), field, &listed.account_digest),
                field,
            );
            kagemusha_wallet_local_block_v1(None, field, &listed.account_digest)
                .expect("no list held");
            kagemusha_wallet_local_block_v1(Some(&empty), field, &listed.account_digest)
                .expect("empty list");
        }
        for unlisted in [[0x01; 32], [0x15; 32], [0x2f; 32], [0xfe; 32]] {
            assert!(!list.contains(&unlisted));
            kagemusha_wallet_local_block_v1(Some(&list), field, &unlisted)
                .expect("unlisted account");
            kagemusha_wallet_local_block_v1(None, field, &unlisted).expect("no list held");
        }
    }
    let rendered =
        kagemusha_wallet_local_block_v1(Some(&list), "request.payer_account_digest", &[0x20; 32])
            .expect_err("listed account")
            .to_string();
    assert_eq!(
        rendered,
        "KAGEMUSHA wallet V1 `request.payer_account_digest` is on the local blacklist"
    );
}

/// A digest of `fill` bytes with byte `index` set to `value`.
fn digest_with(fill: u8, index: usize, value: u8) -> [u8; 32] {
    let mut digest = [fill; 32];
    digest[index] = value;
    digest
}

/// Entries whose unsigned byte order and limb order differ (owner answer A4): the list is
/// sorted, the tree built and membership decided in limb order `hi · 2^128 + lo`.
#[test]
fn kagemusha_wallet_v1_blacklist_order_is_the_limb_order() {
    // small_high has the larger byte 0 (byte order) but the smaller high limb (limb order).
    let small_high = digest_with(0x10, 0, 0xf0);
    let large_high = digest_with(0x10, 31, 0x11);
    // At the limb boundary: full_low has the largest low limb, next_high the next high limb.
    let mut full_low = [0x20_u8; 32];
    full_low[..16].copy_from_slice(&[0xff; 16]);
    let mut next_high = [0x20_u8; 32];
    next_high[..16].copy_from_slice(&[0x00; 16]);
    next_high[16] = 0x21;
    assert!(
        small_high > large_high && full_low > next_high,
        "byte order puts them the other way"
    );
    let sorted = vec![
        KagemushaWalletBlacklistEntryV1 {
            account_digest: small_high,
        },
        KagemushaWalletBlacklistEntryV1 {
            account_digest: large_high,
        },
        KagemushaWalletBlacklistEntryV1 {
            account_digest: full_low,
        },
        KagemushaWalletBlacklistEntryV1 {
            account_digest: next_high,
        },
    ];
    let root = kagemusha_wallet_blacklist_root_v1(&sorted).expect("limb-ordered list");
    assert_eq!(root, naive_blacklist_root(&sorted));
    let mut byte_ordered = sorted.clone();
    byte_ordered.sort_by_key(|entry| entry.account_digest);
    assert!(is_invalid(
        kagemusha_wallet_blacklist_root_v1(&byte_ordered),
        "blacklist.order"
    ));
    let fixture = policy_fixture();
    let list = fixture.blacklist(1, T0_MS, sorted);
    assert_eq!(list.body.entries_root, root);
    for listed in [small_high, large_high, full_low, next_high] {
        assert!(list.contains(&listed));
        assert_blocked(
            kagemusha_wallet_local_block_v1(
                Some(&list),
                "request.receiver_account_digest",
                &listed,
            ),
            "request.receiver_account_digest",
        );
    }
    // `between` lies between small_high and large_high in limb order but above both in byte
    // order. Just below full_low (in its low limb) and just above next_high are unlisted,
    // although byte 0 orders them the other way.
    let between = digest_with(0x10, 0, 0xf1);
    assert!(between > small_high && between > large_high);
    let mut below = full_low;
    below[0] = 0xfe;
    assert!(below > next_high);
    let mut beyond = next_high;
    beyond[0] = 0x01;
    for unlisted in [between, digest_with(0x10, 31, 0x12), below, beyond] {
        assert!(!list.contains(&unlisted));
        kagemusha_wallet_local_block_v1(Some(&list), "request.receiver_account_digest", &unlisted)
            .expect("unlisted account");
    }
}

#[test]
fn kagemusha_wallet_v1_blacklist_uses_little_endian_integer_order() {
    let digest = |low: u8, high: u8| {
        let mut digest = [0; 32];
        digest[0] = low;
        digest[31] = high;
        digest
    };
    let entries = [
        KagemushaWalletBlacklistEntryV1 {
            account_digest: digest(0xff, 0x80),
        },
        KagemushaWalletBlacklistEntryV1 {
            account_digest: digest(0x01, 0x90),
        },
        KagemushaWalletBlacklistEntryV1 {
            account_digest: digest(0x00, 0xa0),
        },
    ];
    // These stand-in account digests exceed the sigma field, and their byte order
    // is the reverse of their integer order. Neither field canonicality nor
    // array comparison is a valid account-ordering rule.
    for entry in &entries {
        assert!(
            !super::super::digest::kagemusha_wallet_is_canonical_field_v1(&entry.account_digest)
        );
    }
    for pair in entries.windows(2) {
        assert!(pair[0].account_digest > pair[1].account_digest);
        assert_eq!(pair[0].cmp(&pair[1]), Ordering::Less);
        assert_eq!(pair[0].partial_cmp(&pair[1]), Some(Ordering::Less));
    }
    validate_blacklist_entries_v1(&entries).expect("integer-ordered entries");
    let mut reversed = entries.to_vec();
    reversed.reverse();
    assert!(is_invalid(
        validate_blacklist_entries_v1(&reversed),
        "blacklist.order"
    ));
    reversed.sort();
    assert_eq!(reversed, entries);
    assert!(is_invalid(
        validate_blacklist_entries_v1(&[entries[0], entries[0]]),
        "blacklist.order"
    ));

    let f = policy_fixture();
    let list = f.blacklist(1, T0_MS, entries.to_vec());
    list.validate().expect("integer-ordered blacklist");
    list.verify(f.scheme(), &f.regulator_certificate)
        .expect("verify list");
    let frame = norito::encode_canonical(&list).expect("encode");
    let decoded = KagemushaWalletBlacklistV1::decode_canonical(&frame, &f.scheme_id())
        .expect("decode integer-ordered list");
    assert_eq!(decoded, list);
    for listed in entries {
        assert!(decoded.contains(&listed.account_digest));
        assert_blocked(
            kagemusha_wallet_local_block_v1(
                Some(&decoded),
                "request.payer_account_digest",
                &listed.account_digest,
            ),
            "request.payer_account_digest",
        );
    }
    // Accounts in each integer gap, including below the first and above the last entry.
    for account in [
        digest(0x10, 0x70),
        digest(0x02, 0x85),
        digest(0xfe, 0x95),
        digest(0x03, 0xb0),
    ] {
        assert!(!decoded.contains(&account));
        kagemusha_wallet_local_block_v1(Some(&decoded), "request.payer_account_digest", &account)
            .expect("unlisted account");
    }
}

#[test]
fn kagemusha_wallet_v1_blacklist_sign_verify_decode() {
    let f = policy_fixture();
    let list = f.blacklist(4, T0_MS, vec![entry(0x10), entry(0x20)]);
    list.verify(f.scheme(), &f.regulator_certificate)
        .expect("verify");
    let frame = list.to_canonical_bytes().expect("encode");
    assert_eq!(
        KagemushaWalletBlacklistV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        list
    );
    assert_every_flip_rejected_or_rebound(&frame, list.blacklist_digest(), |bytes| {
        let list = KagemushaWalletBlacklistV1::decode_canonical(bytes, &f.scheme_id()).ok()?;
        list.verify(f.scheme(), &f.regulator_certificate).ok()?;
        Some(list.blacklist_digest())
    });

    let mut extra = list.clone();
    extra.entries.push(entry(0x30));
    assert!(is_invalid(extra.validate(), "blacklist.entry_count"));
    let mut swapped = list.clone();
    swapped.entries[1] = entry(0x21);
    assert!(is_invalid(swapped.validate(), "blacklist.entries_root"));
    let mut version = list.body;
    version.list_version = 0;
    assert!(is_invalid(version.validate(), "blacklist.list_version"));
    let mut count = list.body;
    count.entry_count = KAGEMUSHA_WALLET_BLACKLIST_ENTRIES_MAX_V1 + 1;
    assert!(is_invalid(count.validate(), "blacklist.entry_count"));
    assert!(is_invalid(
        KagemushaWalletBlacklistV1::sign(
            list.body,
            vec![entry(0x10)],
            &f.regulator_certificate,
            raw_output(&f.regulator, &list.body.signing_message()),
        ),
        "blacklist.entry_count"
    ));
}

#[test]
fn kagemusha_wallet_v1_maximum_blacklist_fits_its_frame_cap() {
    let f = policy_fixture();
    let entries: Vec<KagemushaWalletBlacklistEntryV1> = (1
        ..=KAGEMUSHA_WALLET_BLACKLIST_ENTRIES_MAX_V1)
        .map(|index| {
            // Limb order reads the 32 bytes as one little-endian integer, so the index goes
            // little-endian into the least significant bytes.
            let mut account_digest = [0x01; 32];
            account_digest[..4].copy_from_slice(&index.to_le_bytes());
            KagemushaWalletBlacklistEntryV1 { account_digest }
        })
        .collect();
    let list = f.blacklist(1, T0_MS, entries);
    let frame = norito::encode_canonical(&list).expect("encode");
    println!(
        "KAGEMUSHA wallet V1 maximum blacklist: {} bytes (cap {})",
        frame.len(),
        KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1
    );
    assert!(frame.len() <= KAGEMUSHA_WALLET_BLACKLIST_MAX_BYTES_V1);
    let decoded =
        KagemushaWalletBlacklistV1::decode_canonical(&frame, &f.scheme_id()).expect("decode");
    assert_eq!(
        decoded.body.entry_count,
        KAGEMUSHA_WALLET_BLACKLIST_ENTRIES_MAX_V1
    );
    let highest = decoded.entries.last().expect("last entry").account_digest;
    assert!(decoded.contains(&highest));
    assert!(!decoded.contains(&[0x02; 32]), "above every entry");
    let mut too_many = decoded.entries.clone();
    too_many.push(entry(0x03));
    assert!(is_invalid(
        kagemusha_wallet_blacklist_root_v1(&too_many),
        "blacklist.entries"
    ));
}

#[test]
fn kagemusha_wallet_v1_quota_windows_root_and_share_rules() {
    let f = policy_fixture();
    let windows = sample_windows();
    // Poseidon trees (§7): the window leaf over its four fields, the empty slot over zeros.
    let int = |value: u128| {
        let mut item = [0_u8; 32];
        item[..16].copy_from_slice(&value.to_le_bytes());
        item
    };
    let empty = kagemusha_wallet_quota_empty_window_leaf_v1();
    assert_eq!(
        Some(empty),
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1, &[int(0); 4]).ok()
    );
    let expected = vec![
        int(u128::from(windows[0].kind.tag())),
        int(u128::from(T0_MS)),
        int(u128::from(T0_MS + DAY_MS)),
        int(1_000),
    ];
    assert_eq!(windows[0].field_items(), expected);
    assert_eq!(
        Some(windows[0].leaf_value()),
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_QUOTA_WINDOW_DOMAIN_V1, &expected).ok()
    );
    let mut level: Vec<[u8; 32]> = (0..64)
        .map(|slot| {
            windows
                .get(slot)
                .map_or(empty, KagemushaWalletQuotaWindowV1::leaf_value)
        })
        .collect();
    for _ in 0..KAGEMUSHA_WALLET_QUOTA_TREE_DEPTH_V1 {
        level = level
            .chunks_exact(2)
            .map(|pair| kagemusha_wallet_quota_node_v1(&pair[0], &pair[1]).expect("node"))
            .collect();
    }
    assert_eq!(level.len(), 1);
    assert_eq!(
        kagemusha_wallet_quota_windows_root_v1(&windows).expect("root"),
        level[0]
    );
    assert_eq!(
        kagemusha_wallet_quota_node_v1(&[1; 32], &[2; 32]).ok(),
        kagemusha_wallet_poseidon_v1(KAGEMUSHA_WALLET_QUOTA_NODE_DOMAIN_V1, &[[1; 32], [2; 32]])
            .ok()
    );
    assert!(is_invalid(
        kagemusha_wallet_quota_node_v1(&[0xff; 32], &[2; 32]),
        "quota_share.node"
    ));
    assert!(is_invalid(
        kagemusha_wallet_quota_windows_root_v1(&vec![windows[0]; 65]),
        "quota_share.windows"
    ));

    let share = f.quota_share(1, windows.clone());
    share
        .verify(f.scheme(), &f.regulator_certificate)
        .expect("verify");
    share
        .require_wallet(
            &f.scheme_id(),
            &f.credential.body.asset_digest,
            &f.wallet_id(),
        )
        .expect("wallet");
    assert!(is_invalid(
        share.require_wallet(&f.scheme_id(), &f.credential.body.asset_digest, &[1; 32]),
        "quota_share.wallet_id"
    ));
    let frame = share.to_canonical_bytes().expect("encode");
    assert_eq!(
        KagemushaWalletQuotaShareV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        share
    );
    assert_every_flip_rejected_or_rebound(&frame, share.quota_share_digest(), |bytes| {
        let share = KagemushaWalletQuotaShareV1::decode_canonical(bytes, &f.scheme_id()).ok()?;
        share.verify(f.scheme(), &f.regulator_certificate).ok()?;
        Some(share.quota_share_digest())
    });
    let full: Vec<_> = (0..64)
        .map(|index| {
            window(
                KagemushaWalletQuotaWindowKindV1::Daily,
                T0_MS + index * DAY_MS / 2,
                T0_MS + (index + 1) * DAY_MS / 2,
                u128::MAX,
            )
        })
        .collect();
    let mut body = f.share_body(2, &full);
    body.expires_at_ms = T0_MS + 40 * DAY_MS;
    let maximum = KagemushaWalletQuotaShareV1::sign(
        body,
        full,
        &f.regulator_certificate,
        raw_output(&f.regulator, &body.signing_message()),
    )
    .expect("64 windows");
    let bytes = maximum.to_canonical_bytes().expect("maximum share fits");
    println!(
        "KAGEMUSHA wallet V1 64-window quota share: {} bytes",
        bytes.len()
    );

    let check = |windows: Vec<KagemushaWalletQuotaWindowV1>, field: &str| {
        let body = f.share_body(1, &windows);
        assert!(
            is_invalid(body.validate_windows(&windows), field),
            "{field}"
        );
    };
    let daily = KagemushaWalletQuotaWindowKindV1::Daily;
    let monthly = KagemushaWalletQuotaWindowKindV1::Monthly;
    check(
        vec![windows[1], windows[0], windows[2]],
        "quota_share.window_order",
    );
    check(vec![windows[2], windows[0]], "quota_share.window_order");
    check(
        vec![
            window(daily, T0_MS, T0_MS + DAY_MS + 1, 1),
            window(daily, T0_MS + DAY_MS, T0_MS + 2 * DAY_MS, 1),
        ],
        "quota_share.window_overlap",
    );
    check(
        vec![window(monthly, T0_MS - 1, T0_MS + DAY_MS, 1)],
        "quota_share.window_bounds",
    );
    check(
        vec![window(monthly, T0_MS, T0_MS + 41 * DAY_MS, 1)],
        "quota_share.window_bounds",
    );
    check(
        vec![window(daily, T0_MS + 5, T0_MS + 5, 1)],
        "quota_window.end_ms",
    );
    // Different kinds may overlap.
    let body = f.share_body(1, &windows);
    body.validate_windows(&windows).expect("kinds overlap");
    assert!(is_invalid(
        body.validate_windows(&windows[..2]),
        "quota_share.window_count"
    ));
    let mut other_root = body;
    other_root.windows_root = [9; 32];
    assert!(is_invalid(
        other_root.validate_windows(&windows),
        "quota_share.windows_root"
    ));
    let mutations: [(ShareBodyMutation, &str); 5] = [
        (|b| b.share_id = 0, "quota_share.share_id"),
        (
            |b| b.expires_at_ms = b.issued_at_ms,
            "quota_share.expires_at_ms",
        ),
        (|b| b.window_count = 0, "quota_share.window_count"),
        (|b| b.window_count = 65, "quota_share.window_count"),
        (|b| b.wallet_id = [0; 32], "quota_share.wallet_id"),
    ];
    for (mutate, field) in mutations {
        let mut body = f.share_body(1, &windows);
        mutate(&mut body);
        assert!(is_invalid(body.validate(), field), "{field}");
    }
}

#[test]
fn kagemusha_wallet_v1_quota_intersections_and_charges() {
    let f = policy_fixture();
    let windows = sample_windows();
    let day = &windows[0];
    // Half-open window [start, end) against the closed interval [L, U].
    assert!(day.intersects(&interval(T0_MS - 10, T0_MS)));
    assert!(day.intersects(&interval(T0_MS + DAY_MS - 1, T0_MS + DAY_MS + 5)));
    assert!(!day.intersects(&interval(T0_MS + DAY_MS, T0_MS + DAY_MS + 5)));
    assert!(!day.intersects(&interval(T0_MS - 10, T0_MS - 1)));
    assert_eq!(day.charge(400, 600).expect("charge"), 1_000);
    assert!(is_invalid(day.charge(401, 600), "quota_window.limit"));
    assert!(matches!(
        day.charge(u128::MAX, 1),
        Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow { .. })
    ));

    let share = f.quota_share(1, windows.clone());
    let mut state = f.controlled_state(Some(&share), None);
    let mut usage = KagemushaWalletQuotaUsageArrayV1::zero_for(&windows).expect("usage");
    assert_eq!(usage.root(), state.core.quota_usage_root);
    usage
        .charge(0, 900, windows[0].limit)
        .expect("prior charge");
    // This component test selects the exact predecessor array with its matching head root.
    // It tests the native pre-check and openings, not a folded monetary proof.
    state.core.quota_usage_root = usage.root();
    state.validate().expect("selected charged head");
    // An interval spanning midnight is charged in both daily windows and the month.
    let spanning = interval(T0_MS + DAY_MS - 5, T0_MS + DAY_MS + 5);
    let original = state;
    let (charges, next_usage) = state
        .check_send_quota(Some(&share), &usage, &spanning, 100)
        .expect("charge");
    assert_eq!(charges.len(), 3);
    assert_eq!(
        next_usage
            .slots()
            .iter()
            .flatten()
            .map(|leaf| leaf.used)
            .collect::<Vec<_>>(),
        [1_000, 100, 100]
    );
    assert!(
        next_usage
            .leaf(1)
            .expect("daily leaf")
            .matches_window(&windows[1])
    );
    assert_eq!(
        kagemusha_wallet_verify_quota_charges_v1(
            &share.body.windows_root,
            &usage.root(),
            &charges,
            100,
        )
        .expect("exact sequential native openings"),
        next_usage.root()
    );
    assert_eq!(state, original);
    assert!(is_invalid(
        state.check_send_quota(Some(&share), &usage, &spanning, 101),
        "quota_window.limit"
    ));
    assert_eq!(state, original);
    // A leaf with another end is not aligned with its authenticated window slot.
    let mut moved_slots = *usage.slots();
    moved_slots[0].as_mut().expect("daily usage").window_end_ms += 1;
    let moved_end = KagemushaWalletQuotaUsageArrayV1::from_slots(moved_slots).expect("array");
    assert!(is_invalid(
        moved_end.validate_aligned(&windows),
        "quota_usage.alignment"
    ));
    let mut moved_head = state;
    moved_head.core.quota_usage_root = moved_end.root();
    assert!(is_invalid(
        moved_head.check_send_quota(Some(&share), &moved_end, &spanning, 1),
        "quota_usage.alignment"
    ));
    // Sparse keyed usage is retired. Duplicate window identity cannot occupy another slot,
    // and a repeated charge cannot reuse its opening to charge twice.
    let mut repeated_slots = *usage.slots();
    repeated_slots[1] = repeated_slots[0];
    let repeated = KagemushaWalletQuotaUsageArrayV1::from_slots(repeated_slots).expect("array");
    let mut repeated_head = state;
    repeated_head.core.quota_usage_root = repeated.root();
    assert!(is_invalid(
        repeated_head.check_send_quota(Some(&share), &repeated, &spanning, 1),
        "quota_usage.alignment"
    ));
    assert!(is_invalid(
        kagemusha_wallet_verify_quota_charges_v1(
            &share.body.windows_root,
            &usage.root(),
            &[charges[0], charges[0]],
            100,
        ),
        "quota_charge.order"
    ));
    // After the last daily window no daily window intersects, so Send is refused.
    let late = interval(T0_MS + 3 * DAY_MS, T0_MS + 3 * DAY_MS);
    assert!(is_invalid(
        state.check_send_quota(Some(&share), &usage, &late, 1),
        "quota_share.no_window"
    ));
    let expired = interval(T0_MS, T0_MS + 40 * DAY_MS);
    assert!(is_invalid(
        state.check_send_quota(Some(&share), &usage, &expired, 1),
        "quota_share.expired"
    ));
    usage.validate_aligned(&windows).expect("same window end");
    assert!(is_invalid(
        moved_end.validate_aligned(&windows),
        "quota_usage.alignment"
    ));
    assert!(is_invalid(
        state.check_send_quota(Some(&share), &next_usage, &spanning, 1),
        "state.core.quota_usage_root"
    ));
}

#[test]
fn kagemusha_wallet_v1_time_anchor_and_anchored_interval() {
    let f = policy_fixture();
    let anchor = f.time_anchor(T0_MS);
    anchor
        .verify(f.scheme(), &f.time_certificate)
        .expect("verify");
    assert!(is_invalid(
        anchor.verify(f.scheme(), &f.regulator_certificate),
        "time_anchor.signer_certificate"
    ));
    let frame = anchor.to_canonical_bytes().expect("encode");
    assert!(frame.len() <= KAGEMUSHA_WALLET_TIME_ANCHOR_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletTimeAnchorV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        anchor
    );
    assert_every_flip_rejected_or_rebound(&frame, anchor.time_anchor_digest(), |bytes| {
        let anchor = KagemushaWalletTimeAnchorV1::decode_canonical(bytes, &f.scheme_id()).ok()?;
        anchor.verify(f.scheme(), &f.time_certificate).ok()?;
        Some(anchor.time_anchor_digest())
    });
    let mut body = anchor.body;
    body.nonce = [0; 32];
    assert!(is_invalid(body.validate(), "time_anchor.nonce"));

    let anchored = KagemushaWalletAnchoredTimeV1::new(anchor, BOOT, 1_000, 1_400, MAX_RESPONSE_MS)
        .expect("anchored");
    assert_eq!(anchored.response_width_ms().expect("width"), 400);
    let now = KagemushaWalletMonotonicReadingV1 {
        boot_id: BOOT,
        monotonic_ms: 11_400,
    };
    assert_eq!(
        anchored
            .interval_at(&now, MAX_RESPONSE_MS)
            .expect("interval"),
        interval(T0_MS + 10_000, T0_MS + 10_400)
    );
    let at_receive = KagemushaWalletMonotonicReadingV1 {
        monotonic_ms: 1_400,
        ..now
    };
    assert_eq!(
        anchored
            .interval_at(&at_receive, MAX_RESPONSE_MS)
            .expect("interval"),
        interval(T0_MS, T0_MS + 400)
    );
    let before = KagemushaWalletMonotonicReadingV1 {
        monotonic_ms: 1_399,
        ..now
    };
    assert!(is_invalid(
        anchored.interval_at(&before, MAX_RESPONSE_MS),
        "anchored_time.monotonic"
    ));
    let other_boot = KagemushaWalletMonotonicReadingV1 {
        boot_id: [0xb1; 32],
        ..now
    };
    assert!(is_invalid(
        anchored.interval_at(&other_boot, MAX_RESPONSE_MS),
        "anchored_time.boot_id"
    ));
    assert!(is_invalid(
        anchored.interval_at(&now, 399),
        "anchored_time.response_age"
    ));
    assert!(is_invalid(
        KagemushaWalletAnchoredTimeV1::new(anchor, BOOT, 1_400, 1_000, MAX_RESPONSE_MS),
        "anchored_time.monotonic"
    ));
    assert!(is_invalid(
        KagemushaWalletAnchoredTimeV1::new(anchor, [0; 32], 1_000, 1_000, MAX_RESPONSE_MS),
        "anchored_time.boot_id"
    ));
    let overflowing = KagemushaWalletAnchoredTimeV1::new(
        f.time_anchor(u64::MAX - 10),
        BOOT,
        0,
        0,
        MAX_RESPONSE_MS,
    )
    .expect("anchored");
    assert!(matches!(
        overflowing.interval_at(
            &KagemushaWalletMonotonicReadingV1 {
                boot_id: BOOT,
                monotonic_ms: 11
            },
            MAX_RESPONSE_MS
        ),
        Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow { .. })
    ));
    let local = norito::encode_canonical(&anchored).expect("encode");
    let decoded: KagemushaWalletAnchoredTimeV1 =
        crate::kagemusha::kagemusha_wallet_v1::decode_frame_v1(&local, 1_024).expect("decode");
    assert_eq!(decoded, anchored);

    let window = interval(10, 20);
    assert!(window.deadline_passed(20));
    assert!(!window.deadline_passed(21));
    assert!(window.start_reached(10));
    assert!(!window.start_reached(11));
    assert!(is_invalid(
        KagemushaWalletTimeIntervalV1::new(2, 1),
        "time_interval"
    ));
}

#[test]
fn kagemusha_wallet_v1_effective_accepted_time() {
    let f = policy_fixture();
    let now = KagemushaWalletMonotonicReadingV1 {
        boot_id: BOOT,
        monotonic_ms: 6_000,
    };
    // With no control active, no clock condition blocks Send.
    let mut idle = f.state();
    idle.core.accepted_time_floor_ms = 50;
    assert_eq!(
        idle.effective_accepted_time(None, None, 40).expect("idle"),
        interval(50, 50)
    );
    assert_eq!(
        idle.effective_accepted_time(None, None, 70).expect("idle"),
        interval(70, 70)
    );

    let anchor = f.time_anchor(T0_MS);
    let anchored = KagemushaWalletAnchoredTimeV1::new(anchor, BOOT, 1_000, 1_300, MAX_RESPONSE_MS)
        .expect("anchored");
    let state = f.controlled_state(None, Some(&anchor));
    assert!(state.send_requires_time_anchor());
    assert!(is_invalid(
        state.effective_accepted_time(None, None, 0),
        "time_anchor.missing"
    ));
    assert!(is_invalid(
        state.effective_accepted_time(Some(&anchored), None, 0),
        "time_anchor.observation_missing"
    ));
    // A held anchor still requires its observation with all controls disabled.
    let mut idle_with_anchor = state;
    idle_with_anchor.core.enabled_controls = 0;
    assert!(is_invalid(
        idle_with_anchor.effective_accepted_time(Some(&anchored), None, 0),
        "time_anchor.observation_missing"
    ));
    // Anchor interval at m = 6_000 is [T + 4_700, T + 5_000].
    assert_eq!(
        state
            .effective_accepted_time(Some(&anchored), Some(&now), 0)
            .expect("anchored"),
        interval(T0_MS + 4_700, T0_MS + 5_000)
    );
    // The receiver's authenticated time raises L, and U never falls below L.
    assert_eq!(
        state
            .effective_accepted_time(Some(&anchored), Some(&now), T0_MS + 4_900)
            .expect("receiver time"),
        interval(T0_MS + 4_900, T0_MS + 5_000)
    );
    assert_eq!(
        state
            .effective_accepted_time(Some(&anchored), Some(&now), T0_MS + 9_000)
            .expect("receiver time"),
        interval(T0_MS + 9_000, T0_MS + 9_000)
    );
    // The committed floor (the anchor's T) also bounds L from below.
    assert_eq!(state.core.accepted_time_floor_ms, T0_MS);
    let uncommitted = KagemushaWalletAnchoredTimeV1::new(
        f.time_anchor(T0_MS + 1),
        BOOT,
        1_000,
        1_300,
        MAX_RESPONSE_MS,
    )
    .expect("anchored");
    assert!(is_invalid(
        state.effective_accepted_time(Some(&uncommitted), Some(&now), 0),
        "state.rest.time_anchor"
    ));
    let mut foreign = f.state();
    foreign.core.wallet_id = [0x0f; 32];
    assert!(is_invalid(
        foreign.effective_accepted_time(Some(&anchored), Some(&now), 0),
        "time_anchor.wallet_id"
    ));
}

#[test]
fn kagemusha_wallet_v1_refresh_policy_rules() {
    let f = policy_fixture();
    let state = f.state();
    // Scheme policy: enabled ∧ permitted; the floor is unchanged.
    let policy = f.scheme_policy(2, KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1, [0x0f; 32]);
    let refresh = state
        .refresh_policy(KagemushaWalletPolicyUpdateV1::SchemePolicy { policy: &policy })
        .expect("scheme policy");
    assert_eq!(refresh.core.policy_epoch, 2);
    assert_eq!(
        refresh.core.enabled_controls,
        KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1
    );
    assert_eq!(refresh.rest.fee_schedule, [0x0f; 32]);
    assert_eq!(refresh.core.accepted_time_floor_ms, 0);
    assert_eq!(refresh.credential_digest, state.core.credential_digest);
    assert_eq!(
        refresh.effect,
        KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
            update: policy.scheme_policy_digest(),
            accepted_time_floor_ms: 0,
        }
    );
    let mut epoch_two = state;
    epoch_two.core = refresh.core;
    epoch_two.rest = refresh.rest;
    assert!(is_invalid(
        epoch_two.refresh_policy(KagemushaWalletPolicyUpdateV1::SchemePolicy { policy: &policy }),
        "scheme_policy.policy_epoch"
    ));
    // A credential that permits nothing activates nothing.
    let plain =
        KagemushaWalletStateV1::bootstrap(&f.identity.credential, [1; 32]).expect("plain state");
    let all = f.scheme_policy(1, KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1, [0; 32]);
    assert_eq!(
        plain
            .refresh_policy(KagemushaWalletPolicyUpdateV1::SchemePolicy { policy: &all })
            .expect("refresh")
            .core
            .enabled_controls,
        0
    );

    // Quota share and time anchor raise the floor to their signed time.
    let share = f.quota_share(1, sample_windows());
    let mut slots = *KagemushaWalletQuotaUsageArrayV1::zero_for(&share.windows)
        .expect("native usage array")
        .slots();
    let leaf = slots[0].as_mut().expect("daily usage");
    leaf.window_end_ms += 1;
    leaf.used = 1;
    let usage = KagemushaWalletQuotaUsageArrayV1::from_slots(slots).expect("native array");
    assert!(is_invalid(
        state.refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &share,
            usage: &usage,
        }),
        "state.core.quota_usage_root"
    ));
    // The original wrong-end control remains at the exact current rebuild relation;
    // foreign predecessor bytes are independently refused by the head-root gate above.
    assert!(is_invalid(
        usage.rebuild_for_share(false, &share.windows, T0_MS, MAX_RESPONSE_MS),
        "quota_usage.window_end_ms"
    ));
    let empty = KagemushaWalletQuotaUsageArrayV1::empty();
    let refresh = state
        .refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &share,
            usage: &empty,
        })
        .expect("share");
    assert_eq!(refresh.rest.quota_share_id, 1);
    let installed_usage = refresh.quota_usage.expect("installed array");
    assert_eq!(refresh.core.quota_usage_root, installed_usage.root());
    assert_eq!(
        installed_usage,
        KagemushaWalletQuotaUsageArrayV1::zero_for(&share.windows).expect("zero array")
    );
    assert_ne!(refresh.core.quota_usage_root, state.core.quota_usage_root);
    assert_eq!(
        refresh.core.quota_share_expires_at_ms,
        share.body.expires_at_ms
    );
    assert_eq!(refresh.core.accepted_time_floor_ms, T0_MS);
    let mut other_wallet = f.state();
    other_wallet.core.wallet_id = [0x0e; 32];
    assert!(is_invalid(
        other_wallet.refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &share,
            usage: &empty,
        }),
        "quota_share.wallet_id"
    ));

    let anchor = f.time_anchor(T0_MS + 99);
    let refresh = state
        .refresh_policy(KagemushaWalletPolicyUpdateV1::TimeAnchor { anchor: &anchor })
        .expect("anchor");
    assert_eq!(refresh.rest.time_anchor, anchor.time_anchor_digest());
    assert_eq!(refresh.core.accepted_time_floor_ms, T0_MS + 99);
    // Re-committing the held anchor would repeat the earlier operation ID.
    let mut anchored = state;
    anchored.core = refresh.core;
    anchored.rest = refresh.rest;
    assert!(is_invalid(
        anchored.refresh_policy(KagemushaWalletPolicyUpdateV1::TimeAnchor { anchor: &anchor }),
        "time_anchor.unchanged"
    ));
    // An older signed time never lowers the floor.
    assert_eq!(
        anchored
            .refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
                share: &share,
                usage: &empty,
            })
            .expect("older issuance never lowers the floor")
            .core
            .accepted_time_floor_ms,
        T0_MS + 99
    );
    let later = f.time_anchor(T0_MS + 100);
    let refresh = anchored
        .refresh_policy(KagemushaWalletPolicyUpdateV1::TimeAnchor { anchor: &later })
        .expect("a new anchor after the next boot");
    assert_eq!(refresh.rest.time_anchor, later.time_anchor_digest());

    // Replacement credential: lease renewal under the same incarnation (design C5).
    let mut body = f.credential.body;
    body.renewal_sequence = 1;
    body.issued_at_ms = T0_MS + 500;
    body.fresh_evidence.time_ms = T0_MS + 400;
    body.lease_expires_at_ms = LEASE_MS + DAY_MS;
    let replacement = f.identity.issue(&body).expect("replacement");
    let refresh = state
        .refresh_policy(KagemushaWalletPolicyUpdateV1::Credential {
            previous: &f.credential,
            replacement: &replacement,
        })
        .expect("credential");
    assert_eq!(refresh.credential_digest, replacement.credential_digest());
    assert_eq!(refresh.core.lease_expires_at_ms, LEASE_MS + DAY_MS);
    assert_eq!(refresh.core.accepted_time_floor_ms, T0_MS + 500);
    assert_eq!(
        refresh.effect,
        KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: KagemushaWalletPolicyUpdateKindV1::Credential,
            update: replacement.credential_digest(),
            accepted_time_floor_ms: T0_MS + 500,
        }
    );
    assert!(is_invalid(
        state.refresh_policy(KagemushaWalletPolicyUpdateV1::Credential {
            previous: &f.credential,
            replacement: &f.credential,
        }),
        "credential.renewal_sequence"
    ));
    assert!(is_invalid(
        state.refresh_policy(KagemushaWalletPolicyUpdateV1::Credential {
            previous: &replacement,
            replacement: &replacement,
        }),
        "state.core.credential_digest"
    ));
}

#[test]
fn kagemusha_wallet_v1_send_control_checks() {
    let f = policy_fixture();
    let anchor = f.time_anchor(T0_MS);
    let share = f.quota_share(1, sample_windows());
    let state = f.controlled_state(Some(&share), Some(&anchor));
    assert_eq!(state.core.lifecycle, KagemushaWalletLifecycleV1::Active);
    let early = interval(T0_MS + 10, T0_MS + 20);

    // Lease: refused once U reaches the expiry.
    state.check_lease(&early).expect("lease");
    assert!(is_invalid(
        state.check_lease(&interval(LEASE_MS - 1, LEASE_MS)),
        "state.lease_expired"
    ));
    let idle = f.state();
    idle.check_lease(&interval(LEASE_MS, LEASE_MS))
        .expect("inactive lease never blocks");

    // Quotas: the exact native array must open the payer head before any charge.
    let predecessor = KagemushaWalletQuotaUsageArrayV1::zero_for(&share.windows).expect("usage");
    assert_eq!(predecessor.root(), state.core.quota_usage_root);
    let (charges, usage) = state
        .check_send_quota(Some(&share), &predecessor, &early, 1_000)
        .expect("quota");
    assert_eq!(charges.len(), 2);
    assert_eq!(
        kagemusha_wallet_verify_quota_charges_v1(
            &state.core.quota_windows_root,
            &predecessor.root(),
            &charges,
            1_000,
        )
        .expect("quota witnesses"),
        usage.root()
    );
    let mut successor_head = state;
    successor_head.core.quota_usage_root = usage.root();
    successor_head
        .validate()
        .expect("selected successor usage head");
    assert!(is_invalid(
        successor_head.check_send_quota(Some(&share), &usage, &early, 1),
        "quota_window.limit"
    ));
    assert!(is_invalid(
        state.check_send_quota(None, &predecessor, &early, 1),
        "quota_share.missing"
    ));
    let other_share = f.quota_share(2, sample_windows());
    assert!(is_invalid(
        state.check_send_quota(Some(&other_share), &predecessor, &early, 1),
        "state.rest.quota_share"
    ));
    let empty = KagemushaWalletQuotaUsageArrayV1::empty();
    let (inactive_charges, inactive_usage) = idle
        .check_send_quota(None, &empty, &early, u128::MAX)
        .expect("inactive quota");
    assert!(inactive_charges.is_empty());
    assert_eq!(inactive_usage, empty);
    assert!(is_invalid(
        idle.check_send_quota(None, &predecessor, &early, 1),
        "state.core.quota_usage_root"
    ));

    // The committed digest binds body and signature; the signed windows root also binds
    // every slot. Mutating windows under their original signed body fails before charging.
    let mut raised = share.clone();
    raised.windows[0].limit = u128::MAX;
    assert_eq!(raised.quota_share_digest(), share.quota_share_digest());
    assert!(is_invalid(
        state.check_send_quota(Some(&raised), &predecessor, &early, 1_001),
        "quota_share.windows_root"
    ));
    // The former partial share entry points are retired. Test their source checks directly
    // at the current canonical body/window and native-slot relations as well.
    assert!(is_invalid(raised.validate(), "quota_share.windows_root"));
    assert!(is_invalid(
        raised.body.validate_windows(&raised.windows),
        "quota_share.windows_root"
    ));
    assert!(is_invalid(
        state.check_send_quota(Some(&raised), &predecessor, &early, 0),
        "quota_share.windows_root"
    ));
    let mut swapped = share.clone();
    swapped.windows[2] = window(
        KagemushaWalletQuotaWindowKindV1::Daily,
        T0_MS + 2 * DAY_MS,
        T0_MS + 3 * DAY_MS,
        1_000,
    );
    assert!(is_invalid(
        state.check_send_quota(Some(&swapped), &predecessor, &early, 1),
        "quota_share.windows_root"
    ));
    let mut dropped = share.clone();
    dropped
        .windows
        .retain(|window| window.kind != KagemushaWalletQuotaWindowKindV1::Monthly);
    assert!(is_invalid(
        state.check_send_quota(Some(&dropped), &predecessor, &early, 1),
        "quota_share.window_count"
    ));
    let mut emptied = share.clone();
    emptied.windows.clear();
    assert!(is_invalid(
        state.check_send_quota(Some(&emptied), &predecessor, &early, 1),
        "quota_share.window_count"
    ));
    assert!(is_invalid(
        state.check_send_quota(
            Some(&share),
            &predecessor,
            &interval(T0_MS, T0_MS + MAX_RESPONSE_MS + 1),
            1,
        ),
        "quota_share.time_span"
    ));
}

/// Quota refresh carries consumed usage by window identity, with original floor and response
/// bounds. These are exact native component pre-checks, not a claim of folded σ authentication.
#[test]
fn kagemusha_wallet_v1_quota_refresh_preserves_consumption_and_original_bounds() {
    let f = policy_fixture();
    let windows = sample_windows();
    let share = f.quota_share(1, windows.clone());
    let mut state = f.controlled_state(Some(&share), None);
    let usage = KagemushaWalletQuotaUsageArrayV1::zero_for(&windows).expect("usage");
    assert_eq!(usage.root(), state.core.quota_usage_root);
    let (charges, next_usage) = state
        .check_send_quota(Some(&share), &usage, &interval(T0_MS, T0_MS + 10), 400)
        .expect("original quota charges");
    assert_eq!(
        kagemusha_wallet_verify_quota_charges_v1(
            &share.body.windows_root,
            &usage.root(),
            &charges,
            400
        )
        .expect("authentic window and usage openings"),
        next_usage.root()
    );
    state.core.quota_usage_root = next_usage.root();
    let original = state;
    let mut lowered = windows.clone();
    lowered[0].limit = 399;
    let lower_share = f.quota_share(2, lowered);
    let refresh = state
        .refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &lower_share,
            usage: &next_usage,
        })
        .expect("lowering a cap never restores consumed quota");
    let kept = refresh.quota_usage.expect("rebuilt array");
    assert_eq!(kept, next_usage);
    assert_eq!(refresh.core.quota_usage_root, next_usage.root());
    assert_eq!(refresh.core.time_anchor_max_response_ms, MAX_RESPONSE_MS);
    let mut lower_head = state;
    lower_head.core = refresh.core;
    lower_head.rest = refresh.rest;
    assert!(is_invalid(
        lower_head.check_send_quota(Some(&lower_share), &kept, &interval(T0_MS, T0_MS + 10), 1),
        "quota_window.limit"
    ));
    let mut changed_end = windows.clone();
    changed_end[0].end_ms -= 1;
    let changed_share = f.quota_share(2, changed_end);
    assert!(is_invalid(
        state.refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &changed_share,
            usage: &next_usage,
        }),
        "quota_usage.window_end_ms"
    ));
    let omitted_share = f.quota_share(2, windows[1..].to_vec());
    assert!(is_invalid(
        state.refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &omitted_share,
            usage: &next_usage,
        }),
        "quota_usage.dropped"
    ));
    let mut short = windows.clone();
    short[0].end_ms = T0_MS + MAX_RESPONSE_MS;
    let short_share = f.quota_share(2, short);
    assert!(is_invalid(
        state.refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &short_share,
            usage: &next_usage,
        }),
        "quota_share.window_length"
    ));
    let mut past = vec![window(
        KagemushaWalletQuotaWindowKindV1::Daily,
        T0_MS - 10_000,
        T0_MS,
        1_000,
    )];
    past.extend_from_slice(&windows);
    let mut past_body = f.share_body(2, &past);
    past_body.issued_at_ms = T0_MS - 10_000;
    let past_share = KagemushaWalletQuotaShareV1::sign(
        past_body,
        past,
        &f.regulator_certificate,
        raw_output(&f.regulator, &past_body.signing_message()),
    )
    .expect("signed past window");
    assert!(is_invalid(
        state.refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &past_share,
            usage: &next_usage,
        }),
        "quota_share.window_start_ms"
    ));
    assert!(is_invalid(
        state.refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &omitted_share,
            usage: &usage,
        }),
        "state.core.quota_usage_root"
    ));
    assert_eq!(state, original);
    let anchor = f.time_anchor(T0_MS + DAY_MS);
    let floor_refresh = state
        .refresh_policy(KagemushaWalletPolicyUpdateV1::TimeAnchor { anchor: &anchor })
        .expect("signed later accepted floor");
    let mut ended = state;
    ended.core = floor_refresh.core;
    ended.rest = floor_refresh.rest;
    let refresh = ended
        .refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &omitted_share,
            usage: &next_usage,
        })
        .expect("ended charged key may leave the array");
    let ended_usage = refresh.quota_usage.expect("rebuilt ended array");
    assert_eq!(refresh.core.accepted_time_floor_ms, T0_MS + DAY_MS);
    assert_eq!(
        ended_usage.leaf(1).expect("retained monthly window").used,
        400
    );
    let mut readd_head = ended;
    readd_head.core = refresh.core;
    readd_head.rest = refresh.rest;
    let readd = f.quota_share(3, windows);
    assert!(is_invalid(
        readd_head.refresh_policy(KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &readd,
            usage: &ended_usage,
        }),
        "quota_share.window_start_ms"
    ));
}

#[test]
fn kagemusha_wallet_v1_charge_quotes() {
    let f = policy_fixture();
    let unload = f.charge_quote(f.charge_body(KagemushaWalletChargeKindV1::Unload, 700, 7));
    unload
        .verify(f.scheme(), &f.regulator_certificate)
        .expect("verify");
    let frame = unload.to_canonical_bytes().expect("encode");
    assert_eq!(
        KagemushaWalletChargeQuoteV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        unload
    );
    assert_every_flip_rejected_or_rebound(&frame, unload.charge_quote_digest(), |bytes| {
        let quote = KagemushaWalletChargeQuoteV1::decode_canonical(bytes, &f.scheme_id()).ok()?;
        quote.verify(f.scheme(), &f.regulator_certificate).ok()?;
        Some(quote.charge_quote_digest())
    });

    let wallet_id = f.wallet_id();
    unload
        .require_terms(KagemushaWalletChargeKindV1::Unload, &wallet_id, 2, 700, 7)
        .expect("terms");
    for (kind, wallet, ordinal, net, charge, field) in [
        (
            KagemushaWalletChargeKindV1::Load,
            wallet_id,
            2,
            700,
            7,
            "charge_quote.kind",
        ),
        (
            KagemushaWalletChargeKindV1::Unload,
            [1; 32],
            2,
            700,
            7,
            "charge_quote.wallet_id",
        ),
        (
            KagemushaWalletChargeKindV1::Unload,
            wallet_id,
            3,
            700,
            7,
            "charge_quote.ordinal",
        ),
        (
            KagemushaWalletChargeKindV1::Unload,
            wallet_id,
            2,
            701,
            7,
            "charge_quote.net_amount",
        ),
        (
            KagemushaWalletChargeKindV1::Unload,
            wallet_id,
            2,
            700,
            8,
            "charge_quote.online_charge",
        ),
    ] {
        assert!(
            is_invalid(
                unload.require_terms(kind, &wallet, ordinal, net, charge),
                field
            ),
            "{field}"
        );
    }
    let effect = |charge_quote| KagemushaWalletEffectV1::Unload {
        nullifier: [1; 32],
        redeem_ordinal: 2,
        amount: 700,
        online_charge: 7,
        charge_quote,
    };
    unload
        .require_unload_effect(&effect(unload.charge_quote_digest()), &wallet_id)
        .expect("effect");
    assert!(is_invalid(
        unload.require_unload_effect(&effect([9; 32]), &wallet_id),
        "effect.charge_quote"
    ));
    assert!(is_invalid(
        unload.require_unload_effect(&KagemushaWalletEffectV1::Retiring, &wallet_id),
        "effect.kind"
    ));

    let load = f.charge_quote(f.charge_body(KagemushaWalletChargeKindV1::Load, 5_000, 25));
    load.validate().expect("load quote");
    assert_eq!(
        kagemusha_wallet_load_ledger_debit_v1(5_000, 25).expect("debit"),
        5_025
    );
    assert!(matches!(
        kagemusha_wallet_load_ledger_debit_v1(u128::MAX, 1),
        Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow { .. })
    ));
    assert_eq!(
        kagemusha_wallet_unload_account_payout_v1(700, 7).expect("payout"),
        693
    );
    assert_eq!(
        kagemusha_wallet_unload_account_payout_v1(700, 700).expect("payout"),
        0
    );
    assert!(is_invalid(
        kagemusha_wallet_unload_account_payout_v1(700, 701),
        "charge.online_charge"
    ));
    for (body, field) in [
        (
            f.charge_body(KagemushaWalletChargeKindV1::Unload, 700, 0),
            "charge_quote.online_charge",
        ),
        (
            f.charge_body(KagemushaWalletChargeKindV1::Unload, 0, 1),
            "charge_quote.net_amount",
        ),
        (
            f.charge_body(KagemushaWalletChargeKindV1::Unload, 7, 8),
            "charge.online_charge",
        ),
    ] {
        assert!(is_invalid(body.validate(), field), "{field}");
    }
    assert!(matches!(
        f.charge_body(KagemushaWalletChargeKindV1::Load, u128::MAX, 1)
            .validate(),
        Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow { .. })
    ));
}

#[test]
fn kagemusha_wallet_v1_speculative_send_recheck_keeps_charge_only_inside_same_windows() {
    let f = policy_fixture();
    let anchor = f.time_anchor(T0_MS);
    let share = f.quota_share(1, sample_windows());
    let state = f.controlled_state(Some(&share), Some(&anchor));
    let usage = KagemushaWalletQuotaUsageArrayV1::zero_for(&share.windows).unwrap();
    let original = state
        .check_send_quota(Some(&share), &usage, &interval(T0_MS + 10, T0_MS + 20), 10)
        .unwrap();
    let later = state
        .check_send_quota(Some(&share), &usage, &interval(T0_MS + 30, T0_MS + 40), 10)
        .unwrap();
    assert_eq!(
        original, later,
        "elapsed time alone must not invalidate the retained charge"
    );
    let crossed = state
        .check_send_quota(
            Some(&share),
            &usage,
            &interval(T0_MS + DAY_MS + 10, T0_MS + DAY_MS + 20),
            10,
        )
        .unwrap();
    assert_ne!(
        original.0, crossed.0,
        "the original sigma cannot authorize different touched slots"
    );
    assert_ne!(original.1, crossed.1);
    assert!(is_invalid(
        state.check_send_quota(
            Some(&share),
            &usage,
            &interval(share.body.expires_at_ms - 1, share.body.expires_at_ms),
            10
        ),
        "quota_share.expired"
    ));
    assert!(is_invalid(
        state.check_lease(&interval(LEASE_MS - 1, LEASE_MS)),
        "state.lease_expired"
    ));
}
