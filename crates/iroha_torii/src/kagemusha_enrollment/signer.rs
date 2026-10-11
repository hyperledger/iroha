//! Exact Enrollment-role software signer under retained private descriptor custody.
//!
//! The credential is exactly one 32-byte big-endian P-256 scalar in `1..n`. It is not
//! generated or repaired during startup. This owner supplies signing custody only; the
//! issuer service still consumes current provider eligibility and its durable signing plan.

use iroha_config::parameters::actual::KagemushaEnrollmentProvider;
use iroha_core::kagemusha_wallet_v1::enrollment_issuer::EnrollmentIssuerErrorV1 as Error;
use iroha_data_model::kagemusha::KagemushaWalletSignerRoleV1;
use iroha_fs::{FileSnapshot, RetainedFile};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use std::{
    io::{self, Read as _},
    path::{Component, Path},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Error>;

/// A single selected Enrollment signer. Private scalar owners zeroize on every exit path.
pub(super) struct EnrollmentSigner {
    original: RetainedFile,
    snapshot: FileSnapshot,
    key: SigningKey,
    selected: KagemushaEnrollmentProvider,
}

impl EnrollmentSigner {
    /// Open existing private custody and bind its scalar to the exact rooted certificate.
    pub(super) fn open(
        private_key_path: &Path,
        provider: &KagemushaEnrollmentProvider,
    ) -> Result<Self> {
        validate_certificate(provider)?;
        if private_key_path != provider.signer_private_key
            || !private_key_path.is_absolute()
            || private_key_path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(Error::Selection);
        }
        let mut original = RetainedFile::open_private(private_key_path).map_err(custody)?;
        if original.file().metadata().map_err(custody)?.len() != 32 {
            return Err(Error::Invalid);
        }
        let snapshot = original.snapshot().map_err(custody)?;
        let mut secret = Zeroizing::new([0_u8; 32]);
        original
            .file_mut()
            .read_exact(secret.as_mut())
            .map_err(custody)?;
        let mut extra = Zeroizing::new([0_u8; 1]);
        if original.file_mut().read(extra.as_mut()).map_err(custody)? != 0 {
            return Err(Error::Invalid);
        }
        original.revalidate().map_err(custody)?;
        let key = SigningKey::from_slice(secret.as_ref()).map_err(|_| Error::Invalid)?;
        let owner = Self {
            original,
            snapshot,
            key,
            selected: provider.clone(),
        };
        owner.revalidate(provider)?;
        Ok(owner)
    }

    /// Reject changed selected originals, delegated roles, keys or credential custody.
    pub(super) fn revalidate(&self, provider: &KagemushaEnrollmentProvider) -> Result<()> {
        if &self.selected != provider {
            return Err(Error::Selection);
        }
        validate_certificate(provider)?;
        if self.key.verifying_key().to_encoded_point(false).as_bytes()
            != provider.certificate.body.key.as_sec1_bytes()
        {
            return Err(Error::Selection);
        }
        self.original.revalidate().map_err(custody)?;
        if self.original.snapshot().map_err(custody)? != self.snapshot {
            return Err(Error::Selection);
        }
        Ok(())
    }

    /// Sign the protocol's 32-byte message with ECDSA-P256-SHA256, returning canonical DER.
    /// A failed final custody check discards the signature; no unvalidated result escapes.
    pub(super) fn sign(
        &self,
        provider: &KagemushaEnrollmentProvider,
        message: &[u8; 32],
    ) -> Result<Vec<u8>> {
        self.revalidate(provider)?;
        // Protocol messages are the input to SHA256, not prehashed ECDSA digests.
        let signature: Signature = self.key.try_sign(message).map_err(|_| Error::Unavailable)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        self.revalidate(provider)?;
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

fn validate_certificate(provider: &KagemushaEnrollmentProvider) -> Result<()> {
    provider.scheme.validate().map_err(|_| Error::Selection)?;
    provider
        .certificate
        .verify_role(&provider.scheme, KagemushaWalletSignerRoleV1::Enrollment)
        .map_err(|_| Error::Selection)
}

fn custody(error: io::Error) -> Error {
    match error.kind() {
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => Error::Invalid,
        io::ErrorKind::PermissionDenied => Error::Selection,
        // This credential is required. Missing custody, including a later NotFound,
        // is never an absent optional key, a replacement lookup or a generation request.
        _ => Error::Unavailable,
    }
}

#[cfg(test)]
mod tests;
