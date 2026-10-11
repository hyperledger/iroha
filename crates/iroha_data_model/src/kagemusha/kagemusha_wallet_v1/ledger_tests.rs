//! Load voucher, unload and fee claim, ledger control, activation, closure and abandonment
//! tests.

use p256::ecdsa::SigningKey;

use super::*;
use crate::kagemusha::kagemusha_wallet_v1::digest::kagemusha_wallet_digest_v1;
use crate::kagemusha::kagemusha_wallet_v1::{
    KagemushaWalletChargeQuoteBodyV1, KagemushaWalletEvidenceKindV1, KagemushaWalletStatementV1,
    KagemushaWalletValidationErrorV1,
    codec_tests::{assert_every_flip_rejected_or_rebound, norito_tag},
    identity::identity_tests::{
        IdentityFixture, identity_fixture, raw_output, signing_key, test_account, test_certificate,
    },
    kagemusha_wallet_unload_nullifier_v1,
    messages::messages_tests::message_fixture,
    state::{
        KagemushaWalletLineageSlotV1,
        state_tests::{
            bootstrap_statement, field_value, send_effect, signed_package, stand_in_proof,
            transition_statement,
        },
    },
};

const NONCE: [u8; 32] = [0x4c; 32];
const ISSUED_AT_MS: u64 = 1_790_000_200_000;
/// Ed25519 seed of the charge beneficiary account.
const BENEFICIARY_SEED: u8 = 0x5b;

/// Wallet with its `LoadAuthorization` and `RegulatoryPolicy` signers.
struct LedgerFixture {
    identity: IdentityFixture,
    authorizer: SigningKey,
    authorizer_certificate: KagemushaWalletSignerCertificateV1,
    regulator: SigningKey,
    regulator_certificate: KagemushaWalletSignerCertificateV1,
}

fn ledger_fixture() -> LedgerFixture {
    let identity = identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x67);
    let authorizer = signing_key(0x35);
    let authorizer_certificate = test_certificate(
        &identity.scheme,
        &identity.root,
        KagemushaWalletSignerRoleV1::LoadAuthorization,
        &authorizer,
        4,
    );
    let regulator = signing_key(0x36);
    let regulator_certificate = test_certificate(
        &identity.scheme,
        &identity.root,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
        &regulator,
        5,
    );
    LedgerFixture {
        identity,
        authorizer,
        authorizer_certificate,
        regulator,
        regulator_certificate,
    }
}

impl LedgerFixture {
    fn credential(&self) -> &KagemushaWalletCredentialV1 {
        &self.identity.credential
    }

    fn scheme_id(&self) -> [u8; 32] {
        self.credential().body.scheme_id
    }

    fn voucher_body(
        &self,
        online_charge: u128,
        charge_quote: [u8; 32],
    ) -> KagemushaWalletLoadVoucherBodyV1 {
        let body = &self.credential().body;
        KagemushaWalletLoadVoucherBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: body.scheme_id,
            asset_digest: body.asset_digest,
            wallet_id: body.wallet_id,
            ordinal: 0,
            amount: 5_000,
            online_charge,
            charge_quote,
            transaction_hash: [0x7a; 32],
            block_height: 42,
            authorizer_certificate: self.authorizer_certificate.certificate_digest(),
        }
    }

    fn sign_voucher(
        &self,
        body: KagemushaWalletLoadVoucherBodyV1,
    ) -> WalletResult<KagemushaWalletLoadVoucherV1> {
        KagemushaWalletLoadVoucherV1::sign(
            body,
            &self.authorizer_certificate,
            raw_output(&self.authorizer, &body.signing_message()),
        )
    }

    fn charge_quote(
        &self,
        kind: KagemushaWalletChargeKindV1,
        ordinal: u128,
        net_amount: u128,
        online_charge: u128,
    ) -> KagemushaWalletChargeQuoteV1 {
        let wallet = &self.credential().body;
        let body = KagemushaWalletChargeQuoteBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: wallet.scheme_id,
            asset_digest: wallet.asset_digest,
            wallet_id: wallet.wallet_id,
            kind,
            ordinal,
            net_amount,
            online_charge,
            beneficiary_account_digest: kagemusha_wallet_account_digest_v1(&test_account(
                BENEFICIARY_SEED,
            ))
            .expect("beneficiary"),
            issued_at_ms: ISSUED_AT_MS,
            signer_certificate: self.regulator_certificate.certificate_digest(),
        };
        KagemushaWalletChargeQuoteV1::sign(
            body,
            &self.regulator_certificate,
            raw_output(&self.regulator, &body.signing_message()),
        )
        .expect("charge quote")
    }

    fn control_body(
        &self,
        action: KagemushaWalletLedgerControlActionV1,
    ) -> KagemushaWalletLedgerControlBodyV1 {
        let wallet = &self.credential().body;
        KagemushaWalletLedgerControlBodyV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: wallet.scheme_id,
            asset_digest: wallet.asset_digest,
            wallet_id: wallet.wallet_id,
            action,
            nonce: NONCE,
        }
    }

    fn control(&self, body: KagemushaWalletLedgerControlBodyV1) -> KagemushaWalletLedgerControlV1 {
        KagemushaWalletLedgerControlV1::sign(
            body,
            &self.credential().body.payment_key,
            raw_output(&self.identity.payment, &body.signing_message()),
        )
        .expect("ledger control")
    }

    fn package(&self, statement: &KagemushaWalletStatementV1) -> KagemushaWalletPackageV1 {
        signed_package(
            &self.identity,
            self.credential(),
            statement,
            stand_in_proof(64),
        )
    }

    fn issuer_set(&self) -> KagemushaWalletCertificateSetV1 {
        KagemushaWalletCertificateSetV1::new(vec![self.identity.enrollment_certificate])
            .expect("issuer set")
    }

    fn activation(&self) -> KagemushaWalletActivationV1 {
        let bootstrap = self.package(&bootstrap_statement(&self.identity));
        let digest = bootstrap.package_digest(self.credential()).expect("digest");
        KagemushaWalletActivationV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            control: self.control(self.control_body(
                KagemushaWalletLedgerControlActionV1::Activate {
                    package_digest: digest,
                },
            )),
            credential: *self.credential(),
            bootstrap,
            asset: self.identity.asset.clone(),
            certificates: self.issuer_set(),
        }
    }

    fn retiring_package(&self, next_load: u128) -> KagemushaWalletPackageV1 {
        self.package(&transition_statement(
            &self.identity,
            4,
            next_load,
            KagemushaWalletLifecycleV1::Retiring,
            KagemushaWalletEffectV1::Retiring,
        ))
    }

    fn close_loads(
        &self,
        package: KagemushaWalletPackageV1,
        next_load: u128,
    ) -> KagemushaWalletCloseLoadsV1 {
        let digest = package.package_digest(self.credential()).expect("digest");
        KagemushaWalletCloseLoadsV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            control: self.control(self.control_body(
                KagemushaWalletLedgerControlActionV1::CloseLoads {
                    package_digest: digest,
                    next_load,
                },
            )),
            credential: *self.credential(),
            package,
            certificates: self.issuer_set(),
        }
    }

    fn unload_package(
        &self,
        online_charge: u128,
        charge_quote: [u8; 32],
    ) -> KagemushaWalletPackageV1 {
        let wallet = &self.credential().body;
        self.package(&transition_statement(
            &self.identity,
            6,
            0,
            KagemushaWalletLifecycleV1::Active,
            KagemushaWalletEffectV1::Unload {
                nullifier: kagemusha_wallet_unload_nullifier_v1(
                    &wallet.scheme_id,
                    &wallet.wallet_id,
                    2,
                ),
                redeem_ordinal: 2,
                amount: 700,
                online_charge,
                charge_quote,
            },
        ))
    }

    fn unload_claim(&self, package: KagemushaWalletPackageV1) -> KagemushaWalletUnloadClaimV1 {
        KagemushaWalletUnloadClaimV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            credential: *self.credential(),
            package,
            account: test_account(0x67),
            charge: KagemushaWalletUnloadChargeV1::None,
            certificates: self.issuer_set(),
        }
    }

    /// Unload claim carrying `quote` and `beneficiary` with the quote signer's certificate.
    fn quoted_unload_claim(
        &self,
        package: KagemushaWalletPackageV1,
        quote: &KagemushaWalletChargeQuoteV1,
        beneficiary: AccountId,
    ) -> KagemushaWalletUnloadClaimV1 {
        KagemushaWalletUnloadClaimV1 {
            charge: KagemushaWalletUnloadChargeV1::Quoted {
                quote: *quote,
                beneficiary,
            },
            certificates: KagemushaWalletCertificateSetV1::new(vec![
                self.identity.enrollment_certificate,
                self.regulator_certificate,
            ])
            .expect("issuer and quote signer"),
            ..self.unload_claim(package)
        }
    }

    fn terminal_marker(&self) -> KagemushaWalletMarkerV1 {
        KagemushaWalletMarkerV1::enrollment(
            &self.identity.challenge,
            self.credential().body.payment_key,
        )
        .expect("enrollment marker")
        .successor(KagemushaWalletMarkerStateV1::Terminal {
            reason: KagemushaWalletTerminalReasonV1::Abandoned,
            last_capsule_digest: [0; 32],
        })
        .expect("terminal marker")
    }

    fn abandonment(&self) -> KagemushaWalletAbandonmentV1 {
        let terminal = self.terminal_marker();
        let challenge_digest = self.identity.challenge.challenge_digest();
        let body = KagemushaWalletAbandonmentV1::control_body(&terminal, &challenge_digest, NONCE)
            .expect("body");
        KagemushaWalletAbandonmentV1::sign(
            &terminal,
            challenge_digest,
            NONCE,
            raw_output(&self.identity.payment, &body.signing_message()),
        )
        .expect("abandonment")
    }
}

/// One mutation of a load voucher body.
type VoucherBodyMutation = fn(&mut KagemushaWalletLoadVoucherBodyV1);
/// One mutation of a ledger control body.
type ControlBodyMutation = fn(&mut KagemushaWalletLedgerControlBodyV1);

#[track_caller]
fn assert_invalid<T: core::fmt::Debug>(result: WalletResult<T>, expected: &str) {
    match result {
        Err(KagemushaWalletValidationErrorV1::InvalidField { field }) if field == expected => {}
        other => panic!("expected invalid `{expected}`, got {other:?}"),
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

#[test]
fn kagemusha_wallet_v1_ledger_layouts_and_tags() {
    assert_eq!(KAGEMUSHA_WALLET_LOAD_VOUCHER_BODY_TRANSCRIPT_BYTES_V1, 250);
    assert_eq!(KAGEMUSHA_WALLET_LEDGER_CONTROL_UNION_BYTES_V1, 80);
    assert_eq!(
        KAGEMUSHA_WALLET_LEDGER_CONTROL_BODY_TRANSCRIPT_BYTES_V1,
        211
    );
    assert_eq!(
        max_width_v1(&LEDGER_CONTROL_FIELDS_BYTES),
        ABANDON_FIELDS_BYTES
    );
    assert_eq!(max_width_v1(&[]), 0);
    let f = ledger_fixture();
    let body = f.voucher_body(0, [0; 32]);
    let transcript = body.transcript();
    assert_eq!(
        transcript.len(),
        KAGEMUSHA_WALLET_LOAD_VOUCHER_BODY_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(&transcript[146..178], &[0; 32]);
    assert_eq!(&transcript[178..210], &[0x7a; 32]);
    assert_eq!(&transcript[210..218], &42_u64.to_le_bytes());
    assert_eq!(
        body.signing_message(),
        kagemusha_wallet_signing_message_v1(Domain::Voucher, &transcript)
    );
    assert_eq!(
        body.signing_message(),
        kagemusha_wallet_signing_message_v1(Domain::Voucher, &transcript)
    );

    let actions = [
        KagemushaWalletLedgerControlActionV1::Activate {
            package_digest: [1; 32],
        },
        KagemushaWalletLedgerControlActionV1::CloseLoads {
            package_digest: [2; 32],
            next_load: 7,
        },
        KagemushaWalletLedgerControlActionV1::Abandon {
            enrollment_id: [3; 32],
            marker_generation: 1,
            terminal_marker_digest: [4; 32],
        },
    ];
    for (index, action) in actions.into_iter().enumerate() {
        assert_eq!(usize::from(action.tag()), index + 1);
        assert_eq!(norito_tag(&action), u32::from(action.tag()));
        let transcript = f.control_body(action).transcript();
        assert_eq!(
            transcript.len(),
            KAGEMUSHA_WALLET_LEDGER_CONTROL_BODY_TRANSCRIPT_BYTES_V1
        );
        assert_eq!(transcript[98], action.tag());
        let fields = 99 + action.fields_bytes();
        assert!(transcript[fields..179].iter().all(|byte| *byte == 0));
        assert_eq!(&transcript[179..], &NONCE);
    }
    let close = f.control_body(actions[1]).transcript();
    assert_eq!(&close[99..131], &[2; 32]);
    assert_eq!(&close[131..147], &7_u128.to_le_bytes());
}

#[test]
fn kagemusha_wallet_v1_load_voucher_sign_verify_and_effect() {
    let f = ledger_fixture();
    let voucher = f.sign_voucher(f.voucher_body(0, [0; 32])).expect("voucher");
    voucher
        .verify(&f.identity.scheme, &f.authorizer_certificate)
        .expect("verify");
    let mut signed = voucher.body.signing_message().to_vec();
    signed.extend_from_slice(voucher.signature.as_raw_bytes());
    assert_eq!(
        voucher.voucher_digest(),
        kagemusha_wallet_digest_v1(Role::Voucher, &signed)
    );
    let effect = voucher.load_effect().expect("effect");
    assert_eq!(
        effect,
        KagemushaWalletEffectV1::Load {
            voucher: voucher.voucher_digest(),
            load_ordinal: 0,
            amount: 5_000,
            online_charge: 0,
        }
    );
    transition_statement(
        &f.identity,
        3,
        1,
        KagemushaWalletLifecycleV1::Active,
        effect,
    )
    .validate_for_credential(f.credential())
    .expect("load statement");
    assert_eq!(voucher.ledger_debit().expect("debit"), 5_000);
    voucher.require_charge_quote(None).expect("no quote");
    let quote = f.charge_quote(KagemushaWalletChargeKindV1::Load, 0, 5_000, 25);
    assert_invalid(
        voucher.require_charge_quote(Some(&quote)),
        "voucher.charge_quote",
    );
    let state =
        KagemushaWalletStateV1::bootstrap(f.credential(), field_value(0x5d)).expect("state");
    voucher.require_next_for(&state).expect("next voucher");
    let mut later = state;
    later.core.next_load = 1;
    assert_invalid(voucher.require_next_for(&later), "voucher.ordinal");

    // A charged load names its quote and carries its exact terms (design C7).
    let charged = f
        .sign_voucher(f.voucher_body(25, quote.charge_quote_digest()))
        .expect("charged voucher");
    charged.require_charge_quote(Some(&quote)).expect("quote");
    assert_eq!(charged.ledger_debit().expect("debit"), 5_025);
    assert_invalid(charged.require_charge_quote(None), "voucher.charge_quote");
    let other_ordinal = f.charge_quote(KagemushaWalletChargeKindV1::Load, 1, 5_000, 25);
    let mismatched = f
        .sign_voucher(f.voucher_body(25, other_ordinal.charge_quote_digest()))
        .expect("voucher");
    assert_invalid(
        mismatched.require_charge_quote(Some(&other_ordinal)),
        "charge_quote.ordinal",
    );
    let unload_quote = f.charge_quote(KagemushaWalletChargeKindV1::Unload, 0, 5_000, 25);
    let unload_voucher = f
        .sign_voucher(f.voucher_body(25, unload_quote.charge_quote_digest()))
        .expect("voucher");
    assert_invalid(
        unload_voucher.require_charge_quote(Some(&unload_quote)),
        "charge_quote.kind",
    );
    assert_invalid(
        charged.require_charge_quote(Some(&other_ordinal)),
        "voucher.charge_quote",
    );

    let mutations: [(VoucherBodyMutation, &str); 6] = [
        (|body| body.amount = 0, "voucher.amount"),
        (|body| body.block_height = 0, "voucher.block_height"),
        (|body| body.online_charge = 1, "voucher.charge_quote"),
        (
            |body| body.charge_quote = [0x31; 32],
            "voucher.charge_quote",
        ),
        (
            |body| body.transaction_hash = [0; 32],
            "voucher.transaction_hash",
        ),
        (|body| body.wallet_id = [0; 32], "voucher.wallet_id"),
    ];
    for (mutate, field) in mutations {
        let mut body = f.voucher_body(0, [0; 32]);
        mutate(&mut body);
        assert_invalid(f.sign_voucher(body), field);
    }
    let mut overflow = f.voucher_body(1, [0x32; 32]);
    overflow.amount = u128::MAX;
    assert!(matches!(
        f.sign_voucher(overflow),
        Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow { .. })
    ));
    let body = f.voucher_body(0, [0; 32]);
    assert_invalid(
        KagemushaWalletLoadVoucherV1::sign(
            body,
            &f.regulator_certificate,
            raw_output(&f.regulator, &body.signing_message()),
        ),
        "voucher.authorizer_certificate",
    );
    let mut wrong_role = body;
    wrong_role.authorizer_certificate = f.regulator_certificate.certificate_digest();
    assert_invalid(
        KagemushaWalletLoadVoucherV1::sign(
            wrong_role,
            &f.regulator_certificate,
            raw_output(&f.regulator, &wrong_role.signing_message()),
        ),
        "certificate.role",
    );

    let frame = voucher.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_LOAD_VOUCHER_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletLoadVoucherV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        voucher
    );
    assert!(matches!(
        KagemushaWalletLoadVoucherV1::decode_canonical(&frame, &[0x33; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    assert!(matches!(
        KagemushaWalletLoadVoucherV1::decode_canonical(
            &vec![0; KAGEMUSHA_WALLET_LOAD_VOUCHER_MAX_BYTES_V1 + 1],
            &f.scheme_id()
        ),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
    assert_every_flip_rejected_or_rebound(&frame, voucher.voucher_digest(), |bytes| {
        let voucher = KagemushaWalletLoadVoucherV1::decode_canonical(bytes, &f.scheme_id()).ok()?;
        voucher
            .verify(&f.identity.scheme, &f.authorizer_certificate)
            .ok()?;
        Some(voucher.voucher_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_ledger_control_sign_verify_and_flips() {
    let f = ledger_fixture();
    let key = f.credential().body.payment_key;
    let control = f.control(
        f.control_body(KagemushaWalletLedgerControlActionV1::CloseLoads {
            package_digest: [0x41; 32],
            next_load: 3,
        }),
    );
    control.verify(&key).expect("verify");
    assert_eq!(
        control.body.signing_message(),
        kagemusha_wallet_signing_message_v1(Domain::LedgerControl, &control.body.transcript())
    );
    let other = identity_fixture(KagemushaWalletEvidenceKindV1::AppleAppAttest, 0x68);
    assert_signature(
        control.verify(&other.credential.body.payment_key),
        Domain::LedgerControl,
    );
    assert_signature(
        KagemushaWalletLedgerControlV1::sign(
            control.body,
            &key,
            raw_output(&other.payment, &control.body.signing_message()),
        ),
        Domain::LedgerControl,
    );

    let mutations: [(ControlBodyMutation, &str); 6] = [
        (|body| body.nonce = [0; 32], "ledger_control.nonce"),
        (|body| body.wallet_id = [0; 32], "ledger_control.wallet_id"),
        (
            |body| {
                body.action = KagemushaWalletLedgerControlActionV1::Activate {
                    package_digest: [0; 32],
                };
            },
            "ledger_control.package_digest",
        ),
        (
            |body| {
                body.action = KagemushaWalletLedgerControlActionV1::Abandon {
                    enrollment_id: [1; 32],
                    marker_generation: 0,
                    terminal_marker_digest: [2; 32],
                };
            },
            "ledger_control.marker_generation",
        ),
        (
            |body| {
                body.action = KagemushaWalletLedgerControlActionV1::Abandon {
                    enrollment_id: [0; 32],
                    marker_generation: 1,
                    terminal_marker_digest: [2; 32],
                };
            },
            "ledger_control.enrollment_id",
        ),
        (
            |body| {
                body.action = KagemushaWalletLedgerControlActionV1::Abandon {
                    enrollment_id: [1; 32],
                    marker_generation: 1,
                    terminal_marker_digest: [0; 32],
                };
            },
            "ledger_control.terminal_marker_digest",
        ),
    ];
    for (mutate, field) in mutations {
        let mut body = control.body;
        mutate(&mut body);
        assert_invalid(body.validate(), field);
    }
    let mut version = control;
    version.body.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));

    let frame = control.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_LEDGER_CONTROL_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletLedgerControlV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        control
    );
    assert!(matches!(
        KagemushaWalletLedgerControlV1::decode_canonical(&frame, &[0x42; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    assert_every_flip_rejected_or_rebound(&frame, control.body.signing_message(), |bytes| {
        let control =
            KagemushaWalletLedgerControlV1::decode_canonical(bytes, &f.scheme_id()).ok()?;
        control.verify(&key).ok()?;
        Some(control.body.signing_message())
    });
}

#[test]
fn kagemusha_wallet_v1_activation_records_the_bootstrap_package() {
    let f = ledger_fixture();
    let activation = f.activation();
    activation.validate().expect("activation");
    activation.verify(&f.identity.scheme).expect("verify");
    let frame = activation.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_ACTIVATION_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletActivationV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        activation
    );

    let mut digest = activation.clone();
    digest.control = f.control(
        f.control_body(KagemushaWalletLedgerControlActionV1::Activate {
            package_digest: [0x51; 32],
        }),
    );
    assert_invalid(digest.validate(), "activation.package_digest");
    let mut not_bootstrap = activation.clone();
    not_bootstrap.bootstrap = f.package(&transition_statement(
        &f.identity,
        3,
        0,
        KagemushaWalletLifecycleV1::Active,
        send_effect(),
    ));
    assert_invalid(not_bootstrap.validate(), "activation.bootstrap");
    let mut action = activation.clone();
    action.control = f.control(
        f.control_body(KagemushaWalletLedgerControlActionV1::CloseLoads {
            package_digest: [0x52; 32],
            next_load: 0,
        }),
    );
    assert_invalid(action.validate(), "activation.action");
    let mut asset = activation.clone();
    asset.asset.scale += 1;
    assert_invalid(asset.validate(), "activation.asset");
    let mut wallet = activation.clone();
    let mut body = activation.control.body;
    body.wallet_id = [0x53; 32];
    wallet.control = f.control(body);
    assert_invalid(wallet.validate(), "ledger_control.wallet_id");
    let mut forged = activation.clone();
    let other = identity_fixture(KagemushaWalletEvidenceKindV1::AppleAppAttest, 0x69);
    forged.control = KagemushaWalletLedgerControlV1 {
        body: activation.control.body,
        signature: KagemushaWalletLedgerControlV1::sign(
            activation.control.body,
            &other.credential.body.payment_key,
            raw_output(&other.payment, &activation.control.body.signing_message()),
        )
        .expect("other control")
        .signature,
    };
    assert_signature(forged.validate(), Domain::LedgerControl);
    let mut certificates = activation.clone();
    certificates.certificates =
        KagemushaWalletCertificateSetV1::new(vec![f.regulator_certificate]).expect("set");
    assert_invalid(certificates.validate(), "certificates.set");
    let mut version = activation;
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
}

#[test]
fn kagemusha_wallet_v1_close_loads_requires_a_retiring_package() {
    let f = ledger_fixture();
    let close = f.close_loads(f.retiring_package(7), 7);
    close.validate().expect("close loads");
    close.verify(&f.identity.scheme).expect("verify");
    let frame = close.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_CLOSE_LOADS_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletCloseLoadsV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        close
    );
    // A later package proving the Retiring lifecycle also closes loads.
    let later = f.package(&transition_statement(
        &f.identity,
        8,
        7,
        KagemushaWalletLifecycleV1::Retiring,
        send_effect(),
    ));
    f.close_loads(later, 7).validate().expect("later package");

    assert_invalid(
        f.close_loads(f.retiring_package(7), 6).validate(),
        "close_loads.next_load",
    );
    let active = f.package(&transition_statement(
        &f.identity,
        8,
        7,
        KagemushaWalletLifecycleV1::Active,
        send_effect(),
    ));
    assert_invalid(f.close_loads(active, 7).validate(), "close_loads.lifecycle");
    // Only a package that commits from a folded head with its Ω(pred) closes loads (§6.3).
    let receive = f.package(&transition_statement(
        &f.identity,
        8,
        7,
        KagemushaWalletLifecycleV1::Retiring,
        KagemushaWalletEffectV1::Receive {
            credit_id: field_value(0x62),
            payer_wallet_id: [0x63; 32],
            amount: 1,
        },
    ));
    assert_invalid(f.close_loads(receive, 7).validate(), "close_loads.effect");
    let mut no_lineage = f.retiring_package(7);
    no_lineage.lineage = KagemushaWalletLineageSlotV1::None;
    assert_invalid(no_lineage.validate(), "lineage.slot");
    let mut digest = close.clone();
    digest.control = f.control(
        f.control_body(KagemushaWalletLedgerControlActionV1::CloseLoads {
            package_digest: [0x61; 32],
            next_load: 7,
        }),
    );
    assert_invalid(digest.validate(), "close_loads.package_digest");
    let mut action = close.clone();
    action.control = f.activation().control;
    assert_invalid(action.validate(), "close_loads.action");
    let mut certificates = close;
    certificates.certificates = KagemushaWalletCertificateSetV1::default();
    assert_invalid(certificates.validate(), "certificates.set");
}

#[test]
fn kagemusha_wallet_v1_abandonment_recomputes_the_incarnation() {
    let f = ledger_fixture();
    let abandonment = f.abandonment();
    abandonment.validate().expect("abandonment");
    let terminal = f.terminal_marker();
    abandonment
        .require_terminal_marker(&terminal)
        .expect("terminal marker");
    let KagemushaWalletLedgerControlActionV1::Abandon {
        enrollment_id,
        marker_generation,
        terminal_marker_digest,
    } = abandonment.control.body.action
    else {
        panic!("abandon action");
    };
    assert_eq!(enrollment_id, f.credential().body.enrollment_id);
    assert_eq!(marker_generation, 1);
    assert_eq!(
        terminal_marker_digest,
        terminal.marker_digest().expect("digest")
    );
    assert_eq!(
        abandonment.control.body.wallet_id,
        f.credential().body.wallet_id
    );
    let frame = abandonment.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletAbandonmentV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        abandonment
    );
    assert!(matches!(
        KagemushaWalletAbandonmentV1::decode_canonical(&frame, &[0x71; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));

    let mut challenge = abandonment;
    challenge.challenge_digest = [0x72; 32];
    assert_invalid(challenge.validate(), "abandonment.enrollment_id");
    let mut wallet_body = abandonment.control.body;
    wallet_body.wallet_id = [0x73; 32];
    let wallet = KagemushaWalletAbandonmentV1 {
        control: f.control(wallet_body),
        ..abandonment
    };
    assert_invalid(wallet.validate(), "abandonment.wallet_id");
    let action = KagemushaWalletAbandonmentV1 {
        control: f.activation().control,
        ..abandonment
    };
    assert_invalid(action.validate(), "abandonment.action");
    let other = identity_fixture(KagemushaWalletEvidenceKindV1::AppleAppAttest, 0x6a);
    let forged = KagemushaWalletAbandonmentV1 {
        control: KagemushaWalletLedgerControlV1 {
            body: abandonment.control.body,
            signature: KagemushaWalletLedgerControlV1::sign(
                abandonment.control.body,
                &other.credential.body.payment_key,
                raw_output(&other.payment, &abandonment.control.body.signing_message()),
            )
            .expect("other control")
            .signature,
        },
        ..abandonment
    };
    assert_signature(forged.validate(), Domain::LedgerControl);

    // The control names exactly the durable abandonment terminal marker.
    let enrollment =
        KagemushaWalletMarkerV1::enrollment(&f.identity.challenge, f.credential().body.payment_key)
            .expect("enrollment");
    assert_invalid(
        abandonment.require_terminal_marker(&enrollment),
        "marker.state",
    );
    assert_invalid(
        KagemushaWalletAbandonmentV1::sign(
            &enrollment,
            f.identity.challenge.challenge_digest(),
            NONCE,
            raw_output(&f.identity.payment, b"unused"),
        ),
        "ledger_control.marker_generation",
    );
    let mut renamed_body = abandonment.control.body;
    if let KagemushaWalletLedgerControlActionV1::Abandon {
        terminal_marker_digest,
        ..
    } = &mut renamed_body.action
    {
        *terminal_marker_digest = [0x74; 32];
    }
    let renamed = KagemushaWalletAbandonmentV1 {
        control: f.control(renamed_body),
        ..abandonment
    };
    renamed.validate().expect("structurally valid");
    assert_invalid(
        renamed.require_terminal_marker(&terminal),
        "abandonment.terminal_marker_digest",
    );
    let mut generation_body = abandonment.control.body;
    if let KagemushaWalletLedgerControlActionV1::Abandon {
        marker_generation, ..
    } = &mut generation_body.action
    {
        *marker_generation = 2;
    }
    let generation = KagemushaWalletAbandonmentV1 {
        control: f.control(generation_body),
        ..abandonment
    };
    assert_invalid(
        generation.require_terminal_marker(&terminal),
        "abandonment.marker_generation",
    );
}

#[test]
fn kagemusha_wallet_v1_unload_claim_pays_the_bound_account() {
    let f = ledger_fixture();
    let claim = f.unload_claim(f.unload_package(0, [0; 32]));
    let payout = claim.payout().expect("payout");
    let wallet = &f.credential().body;
    assert_eq!(
        payout,
        KagemushaWalletUnloadPayoutV1 {
            nullifier: kagemusha_wallet_unload_nullifier_v1(
                &wallet.scheme_id,
                &wallet.wallet_id,
                2
            ),
            redeem_ordinal: 2,
            amount: 700,
            online_charge: 0,
            account_payout: 700,
            charge_quote: [0; 32],
            beneficiary_account_digest: [0; 32],
            package: claim
                .package
                .package_digest(f.credential())
                .expect("package"),
        }
    );
    assert_eq!(claim.verify(&f.identity.scheme).expect("verify"), payout);
    assert_eq!(claim.charge.tag(), 0);
    assert!(claim.charge.quote().is_none() && claim.charge.beneficiary().is_none());
    let frame = claim.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletUnloadClaimV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        claim
    );

    // A charged unload pays the net amount minus the charge to the account and the charge to
    // the quote's beneficiary, both carried by the claim (design C7).
    let quote = f.charge_quote(KagemushaWalletChargeKindV1::Unload, 2, 700, 7);
    let beneficiary = test_account(BENEFICIARY_SEED);
    let charged_package = f.unload_package(7, quote.charge_quote_digest());
    let charged = f.quoted_unload_claim(charged_package.clone(), &quote, beneficiary.clone());
    let payout = charged.payout().expect("payout");
    assert_eq!(payout.account_payout, 693);
    assert_eq!(payout.online_charge, 7);
    assert_eq!(payout.charge_quote, quote.charge_quote_digest());
    assert_eq!(
        payout.beneficiary_account_digest,
        quote.body.beneficiary_account_digest
    );
    assert_eq!(charged.verify(&f.identity.scheme).expect("verify"), payout);
    assert_eq!(charged.charge.tag(), 1);
    assert_eq!(charged.charge.quote(), Some(&quote));
    assert_eq!(charged.charge.beneficiary(), Some(&beneficiary));
    assert_eq!(norito_tag(&charged.charge), u32::from(charged.charge.tag()));
    let frame = charged.to_canonical_bytes().expect("charged frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_UNLOAD_CLAIM_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletUnloadClaimV1::decode_canonical(&frame, &f.scheme_id()).expect("decode"),
        charged
    );
    // The quote is present exactly when the effect names one.
    let mut missing = charged.clone();
    missing.charge = KagemushaWalletUnloadChargeV1::None;
    missing.certificates = f.issuer_set();
    assert_invalid(missing.validate(), "unload_claim.charge");
    let unexpected =
        f.quoted_unload_claim(f.unload_package(0, [0; 32]), &quote, beneficiary.clone());
    assert_invalid(unexpected.validate(), "unload_claim.charge");
    let other_quote = f.charge_quote(KagemushaWalletChargeKindV1::Unload, 3, 700, 7);
    let other = f.quoted_unload_claim(charged_package.clone(), &other_quote, beneficiary.clone());
    assert_invalid(other.validate(), "effect.charge_quote");
    let stranger = f.quoted_unload_claim(charged_package, &quote, test_account(0x5c));
    assert_invalid(stranger.validate(), "unload_claim.beneficiary");
    // The quote signer certificate is required with a quote and only with one.
    let mut unsigned = charged.clone();
    unsigned.certificates = f.issuer_set();
    assert_invalid(unsigned.validate(), "certificates.set");
    let mut extra = claim.clone();
    extra.certificates = KagemushaWalletCertificateSetV1::new(vec![
        f.identity.enrollment_certificate,
        f.regulator_certificate,
    ])
    .expect("set");
    assert_invalid(extra.validate(), "certificates.set");
    // Every nested version is checked before the scheme.
    let mut nested = charged.clone();
    if let KagemushaWalletUnloadChargeV1::Quoted { quote, .. } = &mut nested.charge {
        quote.body.version = 2;
    }
    assert!(matches!(
        KagemushaWalletUnloadClaimV1::decode_canonical(
            &norito::encode_canonical(&nested).expect("encode"),
            &[0x78; 32]
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion {
            field: "charge_quote.version",
            version: 2
        })
    ));

    let mut account = claim.clone();
    account.account = test_account(0x6b);
    assert_invalid(account.validate(), "unload_claim.account");
    let mut effect = claim.clone();
    effect.package = f.retiring_package(0);
    assert_invalid(effect.validate(), "unload_claim.effect");
    // The package carries Ω of its predecessor and passes the §3.2 consumer checks (§6.1).
    let mut no_lineage = claim.clone();
    no_lineage.package.lineage = KagemushaWalletLineageSlotV1::None;
    assert_invalid(no_lineage.validate(), "lineage.slot");
    let mut foreign_key = claim.clone();
    if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut foreign_key.package.lineage {
        lineage.public.payment_key =
            identity_fixture(KagemushaWalletEvidenceKindV1::AppleAppAttest, 0x6d)
                .credential
                .body
                .payment_key;
    }
    assert_invalid(foreign_key.validate(), "lineage.payment_key");
    let mut stale_burn = claim.clone();
    if let KagemushaWalletLineageSlotV1::Present { lineage } = &mut stale_burn.package.lineage {
        lineage.public.burned_total = 1;
    }
    assert_invalid(stale_burn.validate(), "lineage.burned_total");
    let mut certificates = claim.clone();
    certificates.certificates = KagemushaWalletCertificateSetV1::default();
    assert_invalid(certificates.validate(), "certificates.set");
    let other = identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x6c);
    let mut foreign = claim.clone();
    foreign.credential = other.credential;
    foreign.account = test_account(0x6c);
    assert_invalid(foreign.validate(), "statement.credential_digest");
    let mut version = claim;
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
}

#[test]
fn kagemusha_wallet_v1_fee_claim_pays_the_schedule_beneficiary() {
    let m = message_fixture();
    let payment = m.payment(true, 64);
    let request = m.request(true);
    let schedule = m.fee_schedule();
    let payer_set =
        KagemushaWalletCertificateSetV1::new(vec![m.payer.enrollment_certificate]).expect("set");
    let digests = payment.digests().expect("payment");
    let claim = KagemushaWalletFeeClaimV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        payment: payment.clone(),
        beneficiary: test_account(0x5b),
    };
    claim.validate().expect("structure");
    // The ledger takes the schedule and credentials from its own records by the digests the
    // Payment binds (§6.2).
    let payout = claim.payout(&schedule).expect("payout");
    assert_eq!(
        payout,
        KagemushaWalletFeePayoutV1 {
            credit_id: digests.credit_id,
            fee: 6,
            fee_schedule: payment.request.body.fee_schedule,
            beneficiary_account_digest: kagemusha_wallet_account_digest_v1(&test_account(0x5b))
                .expect("beneficiary"),
            payment: digests.payment,
        }
    );
    assert_eq!(
        claim
            .verify(&m.payer.scheme, &request, &m.payer.credential, &payer_set)
            .expect("verify"),
        payout
    );
    let frame = claim.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_FEE_CLAIM_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletFeeClaimV1::decode_canonical(&frame, &m.scheme_id()).expect("decode"),
        claim
    );

    let mut beneficiary = claim.clone();
    beneficiary.beneficiary = test_account(0x5c);
    assert_invalid(beneficiary.payout(&schedule), "fee_claim.beneficiary");
    let mut other_schedule = schedule;
    other_schedule.body.schedule_id += 1;
    assert_invalid(claim.payout(&other_schedule), "fee_claim.fee_schedule");
    let free = KagemushaWalletFeeClaimV1 {
        payment: m.payment(false, 64),
        ..claim.clone()
    };
    assert_invalid(free.validate(), "fee_claim.fee_schedule");
    assert_invalid(
        free.verify(
            &m.payer.scheme,
            &m.request(false),
            &m.payer.credential,
            &payer_set,
        ),
        "fee_claim.fee_schedule",
    );
    assert!(
        claim
            .verify(
                &m.payer.scheme,
                &m.request(false),
                &m.payer.credential,
                &payer_set
            )
            .is_err()
    );
    let mut tampered = claim.clone();
    tampered.payment.send.step_proof = stand_in_proof(65);
    assert_signature(tampered.validate(), Domain::Receipt);
    let mut version = claim;
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
}
