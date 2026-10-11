//! Bounded peer-carried fee DATA feeding the one durable Native Request implementation.

use super::*;

fn fee_policy(
    scheme: &KagemushaWalletSchemeV1,
    schedule_frame: &[u8],
    certificates_frame: &[u8],
) -> Result<
    (
        KagemushaWalletFeeScheduleV1,
        KagemushaWalletSignerCertificateV1,
    ),
    Error,
> {
    fn item(bytes: &[u8], scheme: &[u8; 32]) -> Result<KagemushaWalletPolicyDataV1, Error> {
        if bytes.is_empty() || bytes.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
            return Err(Error::Invalid("Request fee PolicyData bound"));
        }
        match valid(KagemushaWalletEnvelopeV1::decode_canonical(bytes, scheme))?.message {
            KagemushaWalletMessageV1::PolicyData { data } => Ok(data),
            _ => Err(Error::Invalid("Request fee PolicyData kind")),
        }
    }
    let schedule_data = item(schedule_frame, &scheme.scheme_id())?;
    let certificates_data = item(certificates_frame, &scheme.scheme_id())?;
    if schedule_data.asset_digest != certificates_data.asset_digest {
        return Err(Error::Invalid("Request fee PolicyData asset"));
    }
    let KagemushaWalletPolicyDataItemV1::FeeSchedule { schedule } = schedule_data.item else {
        return Err(Error::Invalid("Request fee schedule item"));
    };
    let KagemushaWalletPolicyDataItemV1::Certificates { certificates } = certificates_data.item
    else {
        return Err(Error::Invalid("Request fee certificates item"));
    };
    valid(certificates.verify(scheme))?;
    let issuer = *valid(certificates.certificate(
        &schedule.body.signer_certificate,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
    ))?;
    valid(schedule.verify(scheme, &issuer))?;
    Ok((schedule, issuer))
}

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>
{
    /// Read the currently selected asset and fee-schedule digest for local DATA lookup.
    /// Zero schedule means the Native state selects no fee; this grants no Request authority.
    ///
    /// # Errors
    /// Unavailable custody, changed source, missing witnesses or invalid snapshot proofs.
    pub fn request_fee_selection(&mut self) -> Result<([u8; 32], [u8; 32]), Error> {
        let before = self.snapshot()?;
        let (_, manifest) = self.manifest()?;
        let source = self.indexed_step(&manifest, before.sequence)?;
        let state = source.frozen.capsule.successor_state;
        self.source_custody(&manifest, &source)?;
        if valid(state.commitment())?.value != before.head || self.snapshot()? != before {
            return Err(Error::WitnessLost("Request fee selection changed"));
        }
        Ok((state.core.asset_digest, state.rest.fee_schedule))
    }

    /// Authenticate the exact pair of public PolicyData envelopes against selected local policy.
    /// The projection is cache DATA only and does not refresh policy or accept money.
    ///
    /// # Errors
    /// Invalid envelopes, signatures, certificate role, scheme, asset or selected fee digest.
    pub fn validate_request_fee_policy(
        &mut self,
        schedule: &[u8],
        certificates: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), Error> {
        let selected = self.request_fee_selection()?;
        let (schedule, _) = fee_policy(
            self.proofs.installed.verifier().scheme(),
            schedule,
            certificates,
        )?;
        if (schedule.body.asset_digest, schedule.fee_schedule_digest()) != selected {
            return Err(Error::Invalid("Request selected fee PolicyData"));
        }
        if self.request_fee_selection()? != selected {
            return Err(Error::WitnessLost("Request fee selection changed"));
        }
        Ok(selected)
    }

    /// Extract authentic fee originals and invoke the ordinary exact-retry Request owner.
    /// An absent pair is accepted only when Native selects zero fee. A retained pair remains
    /// usable for exact completed retries after local policy changes; `request` owns that check.
    ///
    /// # Errors
    /// Invalid or unpaired PolicyData and all ordinary Request authentication/custody errors.
    pub fn request_with_fee_policy(
        &mut self,
        id: [u8; 32],
        offer: &[u8],
        schedule: &[u8],
        certificates: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let fee = match (schedule.is_empty(), certificates.is_empty()) {
            (true, true) => None,
            (false, false) => Some(fee_policy(
                self.proofs.installed.verifier().scheme(),
                schedule,
                certificates,
            )?),
            _ => return Err(Error::Invalid("Request fee PolicyData pair")),
        };
        self.request(id, offer, fee)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kagemusha_wallet_state_v1::tests::fixture;

    fn originals() -> (
        KagemushaWalletSchemeV1,
        KagemushaWalletFeeScheduleV1,
        KagemushaWalletCertificateSetV1,
    ) {
        let vectors: norito::json::Value = norito::json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/kagemusha/wallet_v1_vectors.json"
        )))
        .unwrap();
        let row = vectors["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["kind"].as_str() == Some("Request"))
            .unwrap();
        let envelope: KagemushaWalletEnvelopeV1 =
            archive::decode(&hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap()).unwrap();
        let KagemushaWalletMessageV1::Request { request } = envelope.message else {
            panic!("Request fixture")
        };
        let KagemushaWalletFeeScheduleSlotV1::Present { schedule } = request.fee_schedule else {
            panic!("nonzero fee fixture")
        };
        (
            fixture("KagemushaWalletSchemeV1"),
            schedule,
            request.certificates,
        )
    }
    fn frame(scheme: [u8; 32], asset: [u8; 32], item: KagemushaWalletPolicyDataItemV1) -> Vec<u8> {
        KagemushaWalletEnvelopeV1::new(KagemushaWalletMessageV1::PolicyData {
            data: KagemushaWalletPolicyDataV1 {
                version: 1,
                scheme_id: scheme,
                asset_digest: asset,
                item,
            },
        })
        .to_canonical_bytes()
        .unwrap()
    }
    #[test]
    fn exact_signed_nonzero_fee_pair_is_extracted_with_digest_selected_signer() {
        let (scheme, schedule, certificates) = originals();
        let a = frame(
            scheme.scheme_id(),
            schedule.body.asset_digest,
            KagemushaWalletPolicyDataItemV1::FeeSchedule { schedule },
        );
        let b = frame(
            scheme.scheme_id(),
            schedule.body.asset_digest,
            KagemushaWalletPolicyDataItemV1::Certificates { certificates },
        );
        let (actual, issuer) = fee_policy(&scheme, &a, &b).unwrap();
        assert_eq!(actual, schedule);
        assert_eq!(
            issuer.certificate_digest(),
            schedule.body.signer_certificate
        );
        assert!(schedule.fee(100_000).unwrap() > 0);
        assert_eq!(fee_policy(&scheme, &a, &b).unwrap(), (actual, issuer));
    }
    #[test]
    fn fee_pair_refuses_wrong_items_assets_signatures_missing_signer_and_noncanonical_bounds() {
        let (scheme, schedule, certificates) = originals();
        let a = frame(
            scheme.scheme_id(),
            schedule.body.asset_digest,
            KagemushaWalletPolicyDataItemV1::FeeSchedule { schedule },
        );
        let b = frame(
            scheme.scheme_id(),
            schedule.body.asset_digest,
            KagemushaWalletPolicyDataItemV1::Certificates {
                certificates: certificates.clone(),
            },
        );
        assert!(fee_policy(&scheme, &b, &a).is_err());
        let foreign_asset = frame(
            scheme.scheme_id(),
            [9; 32],
            KagemushaWalletPolicyDataItemV1::Certificates {
                certificates: certificates.clone(),
            },
        );
        assert!(fee_policy(&scheme, &a, &foreign_asset).is_err());
        let mut altered = schedule;
        altered.body.schedule_id += 1;
        let bad_signature = frame(
            scheme.scheme_id(),
            schedule.body.asset_digest,
            KagemushaWalletPolicyDataItemV1::FeeSchedule { schedule: altered },
        );
        assert!(fee_policy(&scheme, &bad_signature, &b).is_err());
        let missing = KagemushaWalletCertificateSetV1::new(
            certificates
                .certificates
                .into_iter()
                .filter(|cert| cert.certificate_digest() != schedule.body.signer_certificate)
                .collect(),
        )
        .unwrap();
        let missing = frame(
            scheme.scheme_id(),
            schedule.body.asset_digest,
            KagemushaWalletPolicyDataItemV1::Certificates {
                certificates: missing,
            },
        );
        assert!(fee_policy(&scheme, &a, &missing).is_err());
        for malformed in [vec![], vec![0; 10_001], [a.as_slice(), &[0]].concat()] {
            assert!(fee_policy(&scheme, &malformed, &b).is_err());
        }
    }
}
