//! Original enrollment carrier. Parsing never certifies hardware, policy approval or liveness.

use iroha_crypto::{Algorithm, Signature};
use iroha_data_model::{account::AccountId, kagemusha::*};

/// Existing E5 custody limit, shared with the credential-request record.
pub const REQUEST_MAX_BYTES: usize =
    crate::kagemusha_wallet_advance_v1::KAGEMUSHA_WALLET_ENROLLMENT_REQUEST_MAX_BYTES_V1;
/// Bounded exact platform evidence; the issuer must authenticate every contained original.
pub const EVIDENCE_MAX_BYTES: usize = 118_784;
/// Android `KeyMint` chain shape (enrollment policy, Android admission step 1): 2–8 DER
/// certificates, leaf first, each 1–16,384 bytes and at most 65,536 bytes in total.
pub const ANDROID_CHAIN_MIN: usize = 2;
/// Most certificates in one Android chain.
pub const ANDROID_CHAIN_MAX: usize = 8;
/// Largest single Android chain certificate.
pub const ANDROID_CERTIFICATE_MAX_BYTES: usize = 16_384;
/// Largest Android chain in total.
pub const ANDROID_CHAIN_MAX_BYTES: usize = 65_536;

/// Whether `certificates` has the exact Android admission step 1 shape.
pub(crate) fn android_chain_shape<T: AsRef<[u8]>>(certificates: &[T]) -> bool {
    (ANDROID_CHAIN_MIN..=ANDROID_CHAIN_MAX).contains(&certificates.len())
        && certificates.iter().all(|der| {
            !der.as_ref().is_empty() && der.as_ref().len() <= ANDROID_CERTIFICATE_MAX_BYTES
        })
        && certificates
            .iter()
            .try_fold(0_usize, |total, der| total.checked_add(der.as_ref().len()))
            .is_some_and(|total| total <= ANDROID_CHAIN_MAX_BYTES)
}

/// Exact originals sent to the configured issuer, with no attestation verdict fields.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_enrollment_v1::PlatformEvidenceV1")]
pub enum PlatformEvidenceV1 {
    /// Leaf-first `KeyMint` DER chain, including its root. It is the whole Android evidence:
    /// no vendor online verdict, token or second attested key accompanies it.
    Android {
        /// Original certificate bytes; no decoded extension substitutes.
        certificates: Vec<Vec<u8>>,
    },
    /// Original App Attest enrollment and fresh first key-binding assertion.
    Apple {
        /// Exact decoded 32-byte App Attest key identity.
        key_id: [u8; 32],
        /// Original `attestKey(challenge_digest)` object.
        attestation: Vec<u8>,
        /// Original first assertion over challenge/payment-key binding.
        key_binding_assertion: Vec<u8>,
    },
}
impl PlatformEvidenceV1 {
    fn require(&self, policy: &KagemushaWalletEnrollmentPolicyV1) -> Result<(), &'static str> {
        match (self, &policy.platform) {
            (
                Self::Android { certificates },
                KagemushaWalletEnrollmentPlatformV1::Android { .. },
            ) if android_chain_shape(certificates) => Ok(()),
            (
                Self::Apple {
                    key_id,
                    attestation,
                    key_binding_assertion,
                },
                KagemushaWalletEnrollmentPlatformV1::Apple { .. },
            ) if *key_id != [0; 32]
                && !attestation.is_empty()
                && attestation.len() <= 65_536
                && !key_binding_assertion.is_empty()
                && key_binding_assertion.len() <= 4_096 =>
            {
                Ok(())
            }
            _ => Err("platform evidence shape"),
        }
    }
    /// Decode canonical bounded originals. This makes no hardware or freshness claim.
    pub fn decode(
        bytes: &[u8],
        policy: &KagemushaWalletEnrollmentPolicyV1,
    ) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > EVIDENCE_MAX_BYTES {
            return Err("platform evidence bound");
        }
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(EVIDENCE_MAX_BYTES),
        )
        .map_err(|_| "platform evidence encoding")?;
        value.require(policy)?;
        Ok(value)
    }
}

/// Canonical E5 originals selected by the native provider before account authorization.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_enrollment_v1::RequestBodyV1")]
pub struct RequestBodyV1 {
    /// Exactly one first-release layout.
    pub version: u16,
    /// Exact issuer challenge; this carrier does not grant it approval or current liveness.
    pub challenge: KagemushaWalletEnrollmentChallengeV1,
    /// Native generation-zero marker of the selected slot/key.
    pub marker: KagemushaWalletMarkerV1,
    /// Operator-selected policy preimage.
    pub app: KagemushaWalletAppPolicyV1,
    /// Operator-selected enrollment preimage.
    pub policy: KagemushaWalletEnrollmentPolicyV1,
    /// Existing account identity; the final request carries its exact signature.
    pub account: AccountId,
    /// Asset scope from original account request, matching policy/challenge.
    pub asset: KagemushaWalletAssetScopeV1,
    /// Exact canonical PlatformEvidenceV1 bytes, retained without rewriting.
    pub evidence: Vec<u8>,
}
impl RequestBodyV1 {
    /// Check structure and bindings only; the issuer still decides policy, challenge and evidence.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.policy
            .verify_challenge(&self.app, &self.challenge)
            .map_err(|_| "challenge policy bindings")?;
        self.asset.validate().map_err(|_| "asset scope")?;
        self.marker.validate().map_err(|_| "enrollment marker")?;
        self.account
            .try_signatory()
            .filter(|key| key.algorithm() == Algorithm::Ed25519)
            .ok_or("existing account")?;
        let expected =
            KagemushaWalletMarkerV1::enrollment(&self.challenge, self.marker.payment_key)
                .map_err(|_| "enrollment marker derivation")?;
        if self.version != 1
            || self.marker != expected
            || self.marker.scheme_id != self.challenge.scheme_id
            || self.marker.asset_digest != self.challenge.asset_digest
            || self.marker.wallet_id != self.challenge.wallet_id(&self.marker.payment_key)
            || self.asset.asset_digest() != self.challenge.asset_digest
            || kagemusha_wallet_account_digest_v1(&self.account).map_err(|_| "account digest")?
                != self.challenge.account_digest
        {
            return Err("enrollment original binding");
        }
        PlatformEvidenceV1::decode(&self.evidence, &self.policy)?;
        Ok(())
    }
    /// Exact domain-separated account message over all originals including generated payment key.
    pub fn account_challenge(&self) -> Result<[u8; 32], &'static str> {
        self.validate()?;
        let bytes = norito::encode_canonical(self).map_err(|_| "enrollment encoding")?;
        if bytes.len() > REQUEST_MAX_BYTES - 128 {
            return Err("enrollment request bound");
        }
        Ok(
            crate::kagemusha_wallet_advance_v1::kagemusha_wallet_provider_digest_v1(
                "enrollment-e5-account",
                &bytes,
            ),
        )
    }
}

/// Exact E5 request; issuer validation must authenticate E1 state and platform originals anew.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_enrollment_v1::RequestV1")]
pub struct RequestV1 {
    /// Signed originals.
    pub body: RequestBodyV1,
    /// Original existing-account Ed25519 signature, no authorization verdict.
    pub account_signature: [u8; 64],
}
impl RequestV1 {
    /// Verify the existing account's exact-key/evidence binding, not issuer enrollment approval.
    pub fn validate(&self) -> Result<(), &'static str> {
        let message = self.body.account_challenge()?;
        let key = self
            .body
            .account
            .try_signatory()
            .ok_or("existing account")?;
        Signature::from_bytes(&self.account_signature)
            .verify(key, &message)
            .map_err(|_| "enrollment account signature")
    }
    /// Canonical request with the provider's E5 bound.
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.validate()?;
        let bytes = norito::encode_canonical(self).map_err(|_| "request encoding")?;
        if bytes.len() > REQUEST_MAX_BYTES {
            return Err("request bound");
        }
        Ok(bytes)
    }
    /// Decode and verify the exact retained E5 originals.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > REQUEST_MAX_BYTES {
            return Err("request bound");
        }
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(REQUEST_MAX_BYTES),
        )
        .map_err(|_| "request encoding")?;
        value.validate()?;
        Ok(value)
    }
}

/// Full issuer result bound, independent of the 10,000-byte Payment envelope limit.
pub const RESULT_MAX_BYTES: usize = 262_144;

/// Exact originals retained by the issuer before it signs the initial credential.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_enrollment_v1::IssuerEvidenceV1")]
pub enum IssuerEvidenceV1 {
    /// The exact E5 `KeyMint` chain, leaf first; nothing else is Android evidence.
    Android {
        /// Exact E5 chain, leaf first.
        certificates: Vec<Vec<u8>>,
    },
    /// Original Apple attestation and fresh first key-binding assertion.
    Apple {
        /// Exact E5 attestation object.
        attestation: Vec<u8>,
        /// Exact E5 key-binding assertion.
        key_binding_assertion: Vec<u8>,
    },
}
impl IssuerEvidenceV1 {
    /// Reconstruct the signed credential digest while requiring unchanged mobile originals.
    /// The Android digest items are the chain only. This checks bytes, not attestation validity.
    pub fn digest(
        &self,
        request: &RequestBodyV1,
        kind: KagemushaWalletEvidenceKindV1,
    ) -> Result<[u8; 32], &'static str> {
        let mobile = PlatformEvidenceV1::decode(&request.evidence, &request.policy)?;
        let items = match (self, &mobile, kind) {
            (
                Self::Android { certificates },
                PlatformEvidenceV1::Android {
                    certificates: requested,
                },
                KagemushaWalletEvidenceKindV1::AndroidKeyMintTee
                | KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox,
            ) if certificates == requested && android_chain_shape(certificates) => {
                certificates.iter().map(Vec::as_slice).collect::<Vec<_>>()
            }
            (
                Self::Apple {
                    attestation,
                    key_binding_assertion,
                },
                PlatformEvidenceV1::Apple {
                    attestation: requested_attestation,
                    key_binding_assertion: requested_assertion,
                    ..
                },
                KagemushaWalletEvidenceKindV1::AppleAppAttest,
            ) if attestation == requested_attestation
                && key_binding_assertion == requested_assertion =>
            {
                vec![attestation.as_slice(), key_binding_assertion.as_slice()]
            }
            _ => return Err("issuer evidence originals"),
        };
        kagemusha_wallet_evidence_digest_v1(kind, &items).map_err(|_| "issuer evidence digest")
    }
}

/// Exact E6 delivery; authorization comes from the original scheme-rooted credential signature.
#[derive(Debug, Clone, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_enrollment_v1::ResultV1")]
pub struct ResultV1 {
    /// First-release layout.
    pub version: u16,
    /// Original signed initial credential frame.
    pub credential: Vec<u8>,
    /// Original signer CertificateSet frame, including the Enrollment issuer.
    pub certificates: Vec<u8>,
    /// Exact issuer-retained original evidence.
    pub evidence: IssuerEvidenceV1,
}
impl ResultV1 {
    /// Authenticate E6 against the independently selected scheme/Enrollment certificate and
    /// exact account-authorized E5. This checks bindings and signatures, not issuer eligibility
    /// or provenance of its attestation-worker response; the server must verify those separately.
    /// # Errors
    /// Rejects foreign issuers, altered requests, signatures, policy, lease or evidence originals.
    pub fn verify_for(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        selected_issuer: &KagemushaWalletSignerCertificateV1,
        request: &RequestV1,
    ) -> Result<KagemushaWalletCredentialV1, &'static str> {
        self.shape()?;
        request.validate()?;
        selected_issuer
            .verify_role(scheme, KagemushaWalletSignerRoleV1::Enrollment)
            .map_err(|_| "selected enrollment issuer")?;
        let credential_value =
            KagemushaWalletCredentialV1::decode_canonical(&self.credential, &scheme.scheme_id())
                .map_err(|_| "issuer credential")?;
        let set: KagemushaWalletCertificateSetV1 = norito::decode_canonical_with_limits(
            &self.certificates,
            norito::canonical_decode_limits(KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1),
        )
        .map_err(|_| "issuer certificate set")?;
        let issuer = set
            .certificate(
                &credential_value.body.issuer_certificate,
                KagemushaWalletSignerRoleV1::Enrollment,
            )
            .map_err(|_| "issuer certificate")?;
        if issuer != selected_issuer {
            return Err("issuer differs from selected pre-key permit");
        }
        credential_value
            .verify_enrollment(
                scheme,
                selected_issuer,
                &request.body.challenge,
                &request.body.marker.payment_key,
            )
            .map_err(|_| "issuer enrollment credential")?;
        let c = &credential_value.body;
        // The attested security level, never a policy selector, chooses the Android kind.
        let kind_matches = matches!(
            (&request.body.policy.platform, c.evidence_kind),
            (
                KagemushaWalletEnrollmentPlatformV1::Apple { .. },
                KagemushaWalletEvidenceKindV1::AppleAppAttest
            ) | (
                KagemushaWalletEnrollmentPlatformV1::Android { .. },
                KagemushaWalletEvidenceKindV1::AndroidKeyMintTee
                    | KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox
            )
        );
        if !kind_matches
            || c.regulatory_policy != request.body.policy.regulatory_policy
            || c.lease_expires_at_ms
                != request
                    .body
                    .policy
                    .lease_expires_at(c.issued_at_ms)
                    .map_err(|_| "issuer lease")?
            || c.enrollment_evidence.digest
                != self.evidence.digest(&request.body, c.evidence_kind)?
        {
            return Err("issuer enrollment policy/evidence");
        }
        Ok(credential_value)
    }

    fn shape(&self) -> Result<(), &'static str> {
        if self.version != 1
            || self.credential.is_empty()
            || self.credential.len() > KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1
            || self.certificates.is_empty()
            || self.certificates.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
        {
            return Err("issuer result shape");
        }
        Ok(())
    }
    /// Encode bounded originals, without asserting issuer or hardware acceptance.
    pub fn encode(&self) -> Result<Vec<u8>, &'static str> {
        self.shape()?;
        let bytes = norito::encode_canonical(self).map_err(|_| "issuer result encoding")?;
        if bytes.len() > RESULT_MAX_BYTES {
            return Err("issuer result bound");
        }
        Ok(bytes)
    }
    /// Decode exact bounded issuer originals, without substituting an admission verdict.
    pub fn decode(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > RESULT_MAX_BYTES {
            return Err("issuer result bound");
        }
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(RESULT_MAX_BYTES),
        )
        .map_err(|_| "issuer result encoding")?;
        value.shape()?;
        Ok(value)
    }
}
