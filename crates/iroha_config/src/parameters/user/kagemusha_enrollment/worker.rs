//! Bounded concrete verifier installation parsing; no process authority comes from a digest.

use super::*;

/// Existing operator-selected private verifier installation; no default programs or stores.
#[derive(Clone, ReadConfig, norito::JsonDeserialize)]
pub struct KagemushaEnrollmentWorker {
    /// Existing Python executable original.
    pub python_executable: PathBuf,
    /// Nonzero exact interpreter SHA-256, canonical lowercase hex.
    pub python_sha256_hex: String,
    /// Existing sole wallet E1 verifier zipapp original.
    pub verifier_archive: PathBuf,
    /// Nonzero exact zipapp SHA-256, canonical lowercase hex.
    pub verifier_sha256_hex: String,
    /// Existing public OpenSSL executable original.
    pub openssl_executable: PathBuf,
    /// Nonzero exact OpenSSL SHA-256, canonical lowercase hex.
    pub openssl_sha256_hex: String,
    /// Existing public Apple App Attestation root original; Apple routes only. Android
    /// routes omit it: a `KeyMint` chain carries its root, matched by SPKI against the
    /// policy's root set.
    pub attestation_root: Option<PathBuf>,
    /// Existing private journal initialized by an explicit installation action.
    pub store_directory: PathBuf,
    /// Whole private exchange timeout, between one millisecond and five minutes.
    #[config(default = "defaults::torii::kagemusha_enrollment::WORKER_EXCHANGE_TIMEOUT_MS")]
    pub exchange_timeout_ms: u64,
}

impl KagemushaEnrollmentWorker {
    pub(super) fn checked(
        self,
        platform: &KagemushaWalletEnrollmentPlatformV1,
    ) -> Result<actual::KagemushaEnrollmentWorker, &'static str> {
        if !(1..=300_000).contains(&self.exchange_timeout_ms) {
            return Err("private verifier exchange timeout is outside its bound");
        }
        for path in [
            &self.python_executable,
            &self.verifier_archive,
            &self.openssl_executable,
            &self.store_directory,
        ] {
            absolute_path(path)?;
        }
        let attestation_root = match (platform, self.attestation_root) {
            (KagemushaWalletEnrollmentPlatformV1::Apple { .. }, Some(root)) => {
                absolute_path(&root)?;
                Some(root)
            }
            (KagemushaWalletEnrollmentPlatformV1::Android { .. }, None) => None,
            _ => return Err("attestation root custody must match the selected platform"),
        };
        Ok(actual::KagemushaEnrollmentWorker {
            python_executable: self.python_executable,
            python_sha256: digest(&self.python_sha256_hex)?,
            verifier_archive: self.verifier_archive,
            verifier_sha256: digest(&self.verifier_sha256_hex)?,
            openssl_executable: self.openssl_executable,
            openssl_sha256: digest(&self.openssl_sha256_hex)?,
            attestation_root,
            store_directory: self.store_directory,
            exchange_timeout: Duration::from_millis(self.exchange_timeout_ms),
        })
    }
}
impl std::fmt::Debug for KagemushaEnrollmentWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KagemushaEnrollmentWorker")
            .field("exchange_timeout_ms", &self.exchange_timeout_ms)
            .field(
                "attestation_root_selected",
                &self.attestation_root.is_some(),
            )
            .finish_non_exhaustive()
    }
}
