//! Immutable ledger-governed native verifier originals. The world row pins authority;
//! it is never obtained from a received package, local node flag or foreign verdict.
use super::*;
use crate::state::StateTransaction;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::{
    InstallationV1, InstalledVerifierPackV1, VERIFIER_PACK_MAX_BYTES_V1, VerifierPackV1,
};
use mv::storage::StorageReadOnly as _;

pub(super) const KIND: u8 = 14;
pub(super) const CAP: usize = VERIFIER_PACK_MAX_BYTES_V1 + 1024;

/// Exact original install retained after reserve consent, asset governance permission
/// and complete native authentication. Construction alone confers no ledger authority.
#[derive(Clone, Encode, Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::kagemusha_wallet_v1::VerifierInstallation")]
pub(super) struct VerifierInstallation {
    version: u16,
    pub(super) scheme: Digest,
    pub(super) authorizing_asset: Digest,
    manifest: Digest,
    original: Vec<u8>,
}

pub(super) fn key(scheme: Digest) -> KagemushaWalletLedgerKeyV1 {
    storage::key(KIND, scheme, scheme)
}

impl VerifierInstallation {
    /// Used only after the WSV owner checks the real registering reserve's permission.
    pub(super) fn authenticate(
        registration: &Registration,
        manifest: Digest,
        original: Vec<u8>,
    ) -> Result<Self> {
        let value = Self {
            version: 1,
            scheme: registration.scheme.scheme_id(),
            authorizing_asset: registration.asset.asset_digest(),
            manifest,
            original,
        };
        let installed = value.mount()?;
        if installed.verifier().scheme() != &registration.scheme {
            return Err(Error::Binding);
        }
        Ok(value)
    }

    /// Bounded canonical original and cheap signed authority checks for restored rows.
    /// The finalized snapshot owner separately checks the authorizing registration.
    pub(super) fn validate(&self, row: &KagemushaWalletLedgerKeyV1) -> Result<()> {
        if self.version != 1
            || self.scheme == [0; 32]
            || self.authorizing_asset == [0; 32]
            || self.manifest == [0; 32]
            || *row != key(self.scheme)
        {
            return Err(Error::Binding);
        }
        let pack = VerifierPackV1::decode_canonical(&self.original).map_err(|_| Error::Proof)?;
        let scheme = KagemushaWalletSchemeV1::decode_canonical(&pack.scheme, &self.scheme)?;
        let signer = KagemushaWalletSignerCertificateV1::decode_canonical(
            &pack.signer_certificate,
            &scheme,
        )?;
        let manifest =
            KagemushaWalletArtifactManifestV1::decode_canonical(&pack.manifest, &scheme)?;
        manifest.verify(&scheme, &signer)?;
        if manifest.manifest_digest() != self.manifest {
            return Err(Error::Binding);
        }
        Ok(())
    }

    fn mount(&self) -> Result<InstalledVerifierPackV1> {
        self.validate(&key(self.scheme))?;
        InstalledVerifierPackV1::load(
            &self.original,
            InstallationV1 {
                scheme_id: self.scheme,
                manifest_digest: self.manifest,
            },
        )
        .map_err(|_| Error::Proof)
    }

    pub(super) fn require_registration(&self, registration: &Registration) -> Result<()> {
        registration.require(&self.scheme, &self.authorizing_asset)?;
        let pack = VerifierPackV1::decode_canonical(&self.original).map_err(|_| Error::Proof)?;
        if KagemushaWalletSchemeV1::decode_canonical(&pack.scheme, &self.scheme)?
            != registration.scheme
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

/// Same-overlay original snapshot, captured before the instruction mutably borrows WSV.
/// No missing installation prevents non-proof retirement/recovery actions.
pub(crate) struct LedgerVerifier {
    scheme: Digest,
    original: Option<Result<Vec<u8>>>,
}
impl LedgerVerifier {
    pub(crate) fn from_state(state: &StateTransaction<'_, '_>, scheme: Digest) -> Self {
        Self {
            scheme,
            original: state
                .world
                .kagemusha_wallet_ledger
                .get(&key(scheme))
                .map(|bytes| {
                    if bytes.len() > CAP {
                        Err(Error::Proof)
                    } else {
                        Ok(bytes.clone())
                    }
                }),
        }
    }
}
impl NativePackageVerifier for LedgerVerifier {
    fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        credential: &KagemushaWalletCredentialV1,
        package: &KagemushaWalletPackageV1,
    ) -> Result<()> {
        if scheme.scheme_id() != self.scheme || credential.body.scheme_id != self.scheme {
            return Err(Error::Binding);
        }
        let original = self
            .original
            .as_ref()
            .ok_or(Error::ArtifactsUnavailable)?
            .as_ref()
            .map_err(|_| Error::Proof)?;
        let value: VerifierInstallation = storage::decode(original, CAP)?;
        value.validate(&key(self.scheme))?;
        let installed = value.mount()?;
        if installed.verifier().scheme() != scheme {
            return Err(Error::Binding);
        }
        // Check exact current credential/receipt/wallet/key binding before proof verification.
        // Ledger proof-consuming actions are Bootstrap, Retiring, Send and Unload;
        // none admits a Receive selector without its separately retained Request.
        package.verify(credential)?;
        installed
            .verifier()
            .verify_package_proofs(package, None, Default::default())
            .map_err(|_| Error::Proof)
    }
}
