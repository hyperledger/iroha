//! Source-bound nonmonetary setup signing through the exclusive provider.

use super::{
    advance::KagemushaWalletAdvanceCapsuleV1, completion::KagemushaWalletCompletionFrameV1, *,
};
use iroha_data_model::kagemusha::{
    KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1, KagemushaWalletLedgerControlActionV1,
    KagemushaWalletLedgerControlBodyV1, KagemushaWalletSigningDomainV1,
};

impl<
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
> KagemushaWalletProviderV1<F, P, C, R>
{
    /// Typed native Activate signer. Other ledger controls cannot enter this path.
    pub(crate) fn sign_activation(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        source: [u8; 32],
        key: &KagemushaDevicePublicKeyV1,
        body: &KagemushaWalletLedgerControlBodyV1,
    ) -> Result<KagemushaDeviceSignatureV1, KagemushaWalletProviderErrorV1> {
        if !matches!(
            body.action,
            KagemushaWalletLedgerControlActionV1::Activate { .. }
        ) {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "activation.action",
            });
        }
        self.sign_ledger_control(slot, source, key, body)
    }

    /// Typed native closure signer; the coordinator derives the exact Retiring package.
    pub(crate) fn sign_close_loads(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        source: [u8; 32],
        key: &KagemushaDevicePublicKeyV1,
        body: &KagemushaWalletLedgerControlBodyV1,
    ) -> Result<KagemushaDeviceSignatureV1, KagemushaWalletProviderErrorV1> {
        if !matches!(
            body.action,
            KagemushaWalletLedgerControlActionV1::CloseLoads { .. }
        ) {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "close_loads.action",
            });
        }
        self.sign_ledger_control(slot, source, key, body)
    }

    fn sign_ledger_control(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        source: [u8; 32],
        key: &KagemushaDevicePublicKeyV1,
        body: &KagemushaWalletLedgerControlBodyV1,
    ) -> Result<KagemushaDeviceSignatureV1, KagemushaWalletProviderErrorV1> {
        body.validate()
            .map_err(|_| KagemushaWalletProviderErrorV1::Invalid {
                field: "ledger_control.body",
            })?;
        let KagemushaWalletSlotStatusV1::Released(marker) = self.status(slot)? else {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "ledger_control.requires_released",
            });
        };
        if marker.head().map(|(_, _, capsule)| capsule) != Some(source)
            || marker.payment_key() != key
            || marker.marker().scheme_id != body.scheme_id
            || marker.marker().asset_digest != body.asset_digest
            || marker.marker().wallet_id != body.wallet_id
        {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "ledger_control.source",
            });
        }
        self.require_storage()?;
        let result = kagemusha_wallet_sign_domain_v1(
            &self.platform,
            slot,
            key,
            KagemushaWalletSigningDomainV1::LedgerControl,
            &body.transcript(),
        )
        .map_err(Into::into);
        self.require_storage().and(result)
    }

    /// Native setup owner has authenticated and derived this exact body from its selected head.
    /// This private path grants neither receipt signing nor foreign signing access.
    pub(crate) fn sign_setup(
        &mut self,
        slot: &KagemushaWalletSlotIdV1,
        source: [u8; 32],
        key: &KagemushaDevicePublicKeyV1,
        domain: KagemushaWalletSigningDomainV1,
        body: &[u8],
    ) -> Result<KagemushaDeviceSignatureV1, KagemushaWalletProviderErrorV1> {
        if !matches!(
            domain,
            KagemushaWalletSigningDomainV1::Offer | KagemushaWalletSigningDomainV1::Request
        ) {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "setup.domain",
            });
        }
        let KagemushaWalletSlotStatusV1::Released(marker) = self.status(slot)? else {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "setup.requires_released",
            });
        };
        if marker.head().map(|(_, _, capsule)| capsule) != Some(source)
            || marker.payment_key() != key
        {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "setup.source",
            });
        }
        self.require_storage()?;
        let result = kagemusha_wallet_sign_domain_v1(&self.platform, slot, key, domain, body)
            .map_err(Into::into);
        self.require_storage().and(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kagemusha_wallet_advance_v1::test_support::{bootstrapped_device, enrolled_device};
    #[test]
    fn activation_signer_accepts_only_activate_for_exact_released_identity() {
        let (device, fixture, slot, _) =
            bootstrapped_device(KagemushaWalletAnchorPolicyV1::NotRequired, 0x38);
        let mut provider = device.open();
        let marker = provider.status(&slot).unwrap().marker().unwrap().clone();
        let source = marker.head().unwrap().2;
        let body = KagemushaWalletLedgerControlBodyV1 {
            version: 1,
            scheme_id: marker.marker().scheme_id,
            asset_digest: marker.marker().asset_digest,
            wallet_id: marker.marker().wallet_id,
            action: KagemushaWalletLedgerControlActionV1::Activate {
                package_digest: {
                    let mut f = [0; 32];
                    f[0] = 7;
                    f
                },
            },
            nonce: [9; 32],
        };
        let before = device.platform.with(|p| p.sign_calls);
        for changed in [
            KagemushaWalletLedgerControlBodyV1 {
                wallet_id: [8; 32],
                ..body
            },
            KagemushaWalletLedgerControlBodyV1 {
                asset_digest: [8; 32],
                ..body
            },
            KagemushaWalletLedgerControlBodyV1 {
                scheme_id: [8; 32],
                ..body
            },
        ] {
            assert!(
                provider
                    .sign_activation(&slot, source, &fixture.payment_key, &changed)
                    .is_err()
            );
        }
        assert!(
            provider
                .sign_activation(&slot, [7; 32], &fixture.payment_key, &body)
                .is_err()
        );
        let other_action = KagemushaWalletLedgerControlBodyV1 {
            action: KagemushaWalletLedgerControlActionV1::CloseLoads {
                package_digest: {
                    let mut f = [0; 32];
                    f[0] = 7;
                    f
                },
                next_load: 0,
            },
            ..body
        };
        assert!(
            provider
                .sign_activation(&slot, source, &fixture.payment_key, &other_action)
                .is_err()
        );
        assert_eq!(device.platform.with(|p| p.sign_calls), before);
        provider
            .sign_activation(&slot, source, &fixture.payment_key, &body)
            .unwrap();
        assert_eq!(device.platform.with(|p| p.sign_calls), before + 1);
    }

    #[test]
    fn closure_signer_rejects_foreign_identity_and_other_control_actions() {
        let (device, fixture, slot, _) =
            bootstrapped_device(KagemushaWalletAnchorPolicyV1::NotRequired, 0x39);
        let mut provider = device.open();
        let marker = provider.status(&slot).unwrap().marker().unwrap().clone();
        let source = marker.head().unwrap().2;
        let body = KagemushaWalletLedgerControlBodyV1 {
            version: 1,
            scheme_id: marker.marker().scheme_id,
            asset_digest: marker.marker().asset_digest,
            wallet_id: marker.marker().wallet_id,
            action: KagemushaWalletLedgerControlActionV1::CloseLoads {
                package_digest: {
                    let mut f = [0; 32];
                    f[0] = 7;
                    f
                },
                next_load: 9,
            },
            nonce: [9; 32],
        };
        let before = device.platform.with(|p| p.sign_calls);
        let mut wrong = body;
        wrong.wallet_id = [8; 32];
        assert!(
            provider
                .sign_close_loads(&slot, source, &fixture.payment_key, &wrong)
                .is_err()
        );
        assert!(
            provider
                .sign_close_loads(&slot, [7; 32], &fixture.payment_key, &body)
                .is_err()
        );
        wrong = body;
        wrong.action = KagemushaWalletLedgerControlActionV1::Activate {
            package_digest: {
                let mut f = [0; 32];
                f[0] = 7;
                f
            },
        };
        assert!(
            provider
                .sign_close_loads(&slot, source, &fixture.payment_key, &wrong)
                .is_err()
        );
        assert_eq!(device.platform.with(|p| p.sign_calls), before);
        provider
            .sign_close_loads(&slot, source, &fixture.payment_key, &body)
            .unwrap();
        assert_eq!(device.platform.with(|p| p.sign_calls), before + 1);
    }

    #[test]
    fn setup_signing_requires_exact_released_source_key_domain_and_available_storage() {
        let (device, fixture, slot, _) =
            bootstrapped_device(KagemushaWalletAnchorPolicyV1::NotRequired, 0x37);
        let mut provider = device.open();
        let source = provider
            .status(&slot)
            .unwrap()
            .marker()
            .unwrap()
            .head()
            .unwrap()
            .2;
        let body = vec![0; KagemushaWalletSigningDomainV1::Offer.transcript_bytes()];
        let before = device.platform.with(|p| p.sign_calls);
        assert!(
            provider
                .sign_setup(
                    &slot,
                    [99; 32],
                    &fixture.payment_key,
                    KagemushaWalletSigningDomainV1::Offer,
                    &body
                )
                .is_err()
        );
        assert!(
            provider
                .sign_setup(
                    &slot,
                    source,
                    &fixture.payment_key,
                    KagemushaWalletSigningDomainV1::Receipt,
                    &body
                )
                .is_err()
        );
        assert_eq!(device.platform.with(|p| p.sign_calls), before);
        provider
            .sign_setup(
                &slot,
                source,
                &fixture.payment_key,
                KagemushaWalletSigningDomainV1::Offer,
                &body,
            )
            .unwrap();
        assert_eq!(device.platform.with(|p| p.sign_calls), before + 1);
        device
            .platform
            .with(|p| p.storage = Err(KagemushaWalletUnavailableV1::Locked));
        assert!(matches!(
            provider.sign_setup(
                &slot,
                source,
                &fixture.payment_key,
                KagemushaWalletSigningDomainV1::Offer,
                &body
            ),
            Err(KagemushaWalletProviderErrorV1::Unavailable(
                KagemushaWalletUnavailableV1::Locked
            ))
        ));
        assert_eq!(device.platform.with(|p| p.sign_calls), before + 1);
    }
    #[test]
    fn setup_signing_never_uses_an_enrollment_as_a_released_head() {
        let (device, fixture, slot) =
            enrolled_device(KagemushaWalletAnchorPolicyV1::NotRequired, 0x38);
        let mut provider = device.open();
        assert!(
            provider
                .sign_setup(
                    &slot,
                    [1; 32],
                    &fixture.payment_key,
                    KagemushaWalletSigningDomainV1::Request,
                    &vec![0; KagemushaWalletSigningDomainV1::Request.transcript_bytes()]
                )
                .is_err()
        );
        assert_eq!(device.platform.with(|p| p.sign_calls), 0);
    }
}
