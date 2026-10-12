//! Closed E1 refusal reasons (design §2.4). Every component reports and relays the same `u16`
//! code unchanged; zero and unknown codes are protocol errors, never admission. A refusal
//! never states that a phone is compromised; it names the first admission check that failed.

/// One closed E1 refusal reason. The discriminant is the stable wire code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
pub enum KagemushaWalletEnrollmentRefusalV1 {
    /// The attestation or `KeyMint` security level is Software, the two levels differ, or
    /// attestation version 2 is not TEE.
    KeyNotInSecureHardware = 1,
    /// The attestation carries no application identity (attestation version 1, Keymaster 2,
    /// or a later attestation without `attestationApplicationId`).
    AttestationWithoutAppIdentity = 2,
    /// The `RootOfTrust` records an unlocked bootloader.
    BootloaderUnlocked = 3,
    /// Boot state is not Verified, the verified-boot key is zero, or a `KeyMint` boot hash is
    /// not 32 nonzero bytes.
    BootNotVerified = 4,
    /// The chain does not validate under its root's adapter profile to a root of the policy's
    /// root set (Android), or not to Apple's App Attestation root (Apple).
    UntrustedAttestationRoot = 5,
    /// A chain certificate is listed by its root's revocation source or the operator denylist.
    AttestationRevoked = 6,
    /// The package, a signer, the App ID or the App Attest environment differs from the policy.
    AppIdentityMismatch = 7,
    /// The attested package version is below the app policy minimum.
    AppVersionBelowMinimum = 8,
    /// The evidence is malformed or does not match this attempt.
    EvidenceInvalid = 9,
    /// E5 verification began after the E1 challenge lifetime.
    ChallengeExpired = 10,
    /// The eligibility provider reports `NotApproved`.
    AccountNotApproved = 11,
    /// The eligibility provider reports `Frozen`.
    AccountFrozen = 12,
}

/// Platforms on which a refusal reason can occur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletEnrollmentRefusalPlatformV1 {
    /// Android `KeyMint` evidence only.
    Android,
    /// Both Android and Apple evidence.
    Both,
}

/// What the holder can do about a refusal; the app owns the wording (design §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KagemushaWalletEnrollmentRefusalClassV1 {
    /// This phone cannot hold offline value; online payments are unaffected.
    Phone,
    /// Install or update the released app from an official channel, then start again.
    App,
    /// Abandon and start again with a new challenge; a repeat is a defect report.
    Attempt,
    /// The account's status, not the phone, blocks enrollment.
    Account,
}

impl KagemushaWalletEnrollmentRefusalV1 {
    /// Every reason in code order.
    pub const ALL: [Self; 12] = [
        Self::KeyNotInSecureHardware,
        Self::AttestationWithoutAppIdentity,
        Self::BootloaderUnlocked,
        Self::BootNotVerified,
        Self::UntrustedAttestationRoot,
        Self::AttestationRevoked,
        Self::AppIdentityMismatch,
        Self::AppVersionBelowMinimum,
        Self::EvidenceInvalid,
        Self::ChallengeExpired,
        Self::AccountNotApproved,
        Self::AccountFrozen,
    ];

    /// Stable `u16` wire code, 1–12.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Reason of a wire code; zero and unknown codes have none.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            1 => Self::KeyNotInSecureHardware,
            2 => Self::AttestationWithoutAppIdentity,
            3 => Self::BootloaderUnlocked,
            4 => Self::BootNotVerified,
            5 => Self::UntrustedAttestationRoot,
            6 => Self::AttestationRevoked,
            7 => Self::AppIdentityMismatch,
            8 => Self::AppVersionBelowMinimum,
            9 => Self::EvidenceInvalid,
            10 => Self::ChallengeExpired,
            11 => Self::AccountNotApproved,
            12 => Self::AccountFrozen,
            _ => return None,
        })
    }

    /// Platforms on which this reason can occur.
    #[must_use]
    pub const fn platform(self) -> KagemushaWalletEnrollmentRefusalPlatformV1 {
        match self {
            Self::KeyNotInSecureHardware
            | Self::AttestationWithoutAppIdentity
            | Self::BootloaderUnlocked
            | Self::BootNotVerified
            | Self::AttestationRevoked
            | Self::AppVersionBelowMinimum => KagemushaWalletEnrollmentRefusalPlatformV1::Android,
            Self::UntrustedAttestationRoot
            | Self::AppIdentityMismatch
            | Self::EvidenceInvalid
            | Self::ChallengeExpired
            | Self::AccountNotApproved
            | Self::AccountFrozen => KagemushaWalletEnrollmentRefusalPlatformV1::Both,
        }
    }

    /// Whether this reason can occur for evidence of the given platform.
    #[must_use]
    pub const fn applies_to(self, android: bool) -> bool {
        android
            || matches!(
                self.platform(),
                KagemushaWalletEnrollmentRefusalPlatformV1::Both
            )
    }

    /// Holder-facing class of this reason.
    #[must_use]
    pub const fn class(self) -> KagemushaWalletEnrollmentRefusalClassV1 {
        match self {
            Self::KeyNotInSecureHardware
            | Self::AttestationWithoutAppIdentity
            | Self::BootloaderUnlocked
            | Self::BootNotVerified
            | Self::UntrustedAttestationRoot
            | Self::AttestationRevoked => KagemushaWalletEnrollmentRefusalClassV1::Phone,
            Self::AppIdentityMismatch | Self::AppVersionBelowMinimum => {
                KagemushaWalletEnrollmentRefusalClassV1::App
            }
            Self::EvidenceInvalid | Self::ChallengeExpired => {
                KagemushaWalletEnrollmentRefusalClassV1::Attempt
            }
            Self::AccountNotApproved | Self::AccountFrozen => {
                KagemushaWalletEnrollmentRefusalClassV1::Account
            }
        }
    }

    /// Whether the eligibility provider, rather than platform evidence verification, decides
    /// this reason (codes 11 and 12). After issuance these only withhold E6 delivery.
    #[must_use]
    pub const fn is_eligibility(self) -> bool {
        matches!(self, Self::AccountNotApproved | Self::AccountFrozen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_codes_are_the_closed_stable_design_table() {
        let codes: Vec<u16> = KagemushaWalletEnrollmentRefusalV1::ALL
            .iter()
            .map(|reason| reason.code())
            .collect();
        assert_eq!(codes, (1..=12).collect::<Vec<u16>>());
        for reason in KagemushaWalletEnrollmentRefusalV1::ALL {
            assert_eq!(
                KagemushaWalletEnrollmentRefusalV1::from_code(reason.code()),
                Some(reason)
            );
        }
        for code in [0, 13, 255, u16::MAX] {
            assert_eq!(KagemushaWalletEnrollmentRefusalV1::from_code(code), None);
        }
        use KagemushaWalletEnrollmentRefusalClassV1 as Class;
        use KagemushaWalletEnrollmentRefusalV1 as Reason;
        let expected = [
            (Reason::KeyNotInSecureHardware, false, Class::Phone),
            (Reason::AttestationWithoutAppIdentity, false, Class::Phone),
            (Reason::BootloaderUnlocked, false, Class::Phone),
            (Reason::BootNotVerified, false, Class::Phone),
            (Reason::UntrustedAttestationRoot, true, Class::Phone),
            (Reason::AttestationRevoked, false, Class::Phone),
            (Reason::AppIdentityMismatch, true, Class::App),
            (Reason::AppVersionBelowMinimum, false, Class::App),
            (Reason::EvidenceInvalid, true, Class::Attempt),
            (Reason::ChallengeExpired, true, Class::Attempt),
            (Reason::AccountNotApproved, true, Class::Account),
            (Reason::AccountFrozen, true, Class::Account),
        ];
        for (reason, apple, class) in expected {
            assert!(reason.applies_to(true), "{reason:?}");
            assert_eq!(reason.applies_to(false), apple, "{reason:?}");
            assert_eq!(reason.class(), class, "{reason:?}");
            assert_eq!(reason.is_eligibility(), class == Class::Account);
        }
    }
}
