//! Asset-independent DATA selected by authenticated application and issuer policy owners.
//! Derivation never authenticates a token: the caller separately requires finalized Global
//! registration, then binds its exact incarnation/scale through the existing concrete policy.
use super::super::identity::KagemushaWalletAssetScopeV1;
use super::*;

/// Universal-dataspace enrollment policy without a token allowlist.
///
/// The independent release/configuration owner authenticates this complete original.
/// A decoded template grants no registration, eligibility, attestation or signing authority.
/// Concrete policies remain bound to one exact asset; no wildcard enters a credential or proof.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEnrollmentPolicyTemplateV1"
)]
pub struct KagemushaWalletEnrollmentPolicyTemplateV1 {
    /// Exactly version one.
    pub version: u16,
    /// Exact authenticated scheme identity.
    pub scheme_id: [u8; 32],
    /// Exact selected app-policy digest.
    pub app_policy: [u8; 32],
    /// Mandatory platform verifier inputs: the Android root set or the Apple root pin.
    pub platform: KagemushaWalletEnrollmentPlatformV1,
    /// Selected controls, unchanged for every derived concrete asset policy.
    pub regulatory_policy: KagemushaWalletRegulatoryPolicyV1,
    /// Positive server-owned challenge lifetime.
    pub challenge_lifetime_ms: u64,
    /// Exact selected lease lifetime; zero precisely when leases are disabled.
    pub attestation_lease_lifetime_ms: u64,
}
impl KagemushaWalletEnrollmentPolicyTemplateV1 {
    /// Validate self-contained policy DATA without granting approval.
    /// # Errors
    /// Rejects unsupported version, zero identities or invalid platform/lease/control inputs.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("enrollment_policy.version", self.version)?;
        require_nonzero_v1("enrollment_policy.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("enrollment_policy.app_policy", &self.app_policy)?;
        self.regulatory_policy.validate()?;
        if self.challenge_lifetime_ms == 0 {
            return Err(invalid_v1("enrollment_policy.challenge_lifetime_ms"));
        }
        if (self.attestation_lease_lifetime_ms > 0)
            != self
                .regulatory_policy
                .permits(KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1)
        {
            return Err(invalid_v1(
                "enrollment_policy.attestation_lease_lifetime_ms",
            ));
        }
        self.platform.validate()?;
        Ok(())
    }

    /// Require the exact app, scheme and platform pairing selected by the policy owner.
    /// # Errors
    /// Rejects invalid DATA or a changed app/scheme/platform.
    pub fn validate_for_app(&self, app: &KagemushaWalletAppPolicyV1) -> WalletResult<()> {
        self.validate()?;
        app.validate()?;
        require_scheme_v1(
            "enrollment_policy.scheme_id",
            &self.scheme_id,
            &app.scheme_id,
        )?;
        if self.app_policy != app.policy_digest()? {
            return Err(invalid_v1("enrollment_policy.app_policy"));
        }
        if !matches!(
            (&app.identity, &self.platform),
            (
                KagemushaWalletAppIdentityV1::Android { .. },
                KagemushaWalletEnrollmentPlatformV1::Android { .. }
            ) | (
                KagemushaWalletAppIdentityV1::Apple { .. },
                KagemushaWalletEnrollmentPlatformV1::Apple { .. }
            )
        ) {
            return Err(invalid_v1("enrollment_policy.platform"));
        }
        Ok(())
    }
    /// Derive existing concrete policy DATA for one exact asset original.
    /// The caller must independently authenticate registration and this template selection.
    /// # Errors
    /// Rejects invalid template or asset scope; never substitutes defaults or another asset.
    pub fn for_asset(
        &self,
        asset: &KagemushaWalletAssetScopeV1,
    ) -> WalletResult<KagemushaWalletEnrollmentPolicyV1> {
        self.validate()?;
        asset.validate()?;
        Ok(KagemushaWalletEnrollmentPolicyV1 {
            version: self.version,
            scheme_id: self.scheme_id,
            asset_digest: asset.asset_digest(),
            app_policy: self.app_policy,
            platform: self.platform.clone(),
            regulatory_policy: self.regulatory_policy,
            challenge_lifetime_ms: self.challenge_lifetime_ms,
            attestation_lease_lifetime_ms: self.attestation_lease_lifetime_ms,
        })
    }
    /// Encode one validated bounded canonical template original.
    /// # Errors
    /// Rejects invalid DATA or a frame beyond the enrollment-policy cap.
    pub fn encode_canonical(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1)
    }
    /// Decode exactly one bounded original under its independently expected scheme.
    /// # Errors
    /// Rejects altered layout, trailing bytes, version, scheme or invalid policy DATA.
    pub fn decode_canonical(bytes: &[u8], expected_scheme: &[u8; 32]) -> WalletResult<Self> {
        let value: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1)?;
        require_version_v1("enrollment_policy.version", value.version)?;
        require_scheme_v1(
            "enrollment_policy.scheme_id",
            &value.scheme_id,
            expected_scheme,
        )?;
        value.validate()?;
        Ok(value)
    }
}
#[cfg(test)]
mod tests;
