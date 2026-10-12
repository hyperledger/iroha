//! Concrete private Linux verifier process with retained original and journal custody.
//!
//! Operator configuration selects the installed interpreter and frozen archive. The host OS,
//! interpreter standard library, dynamic loader, TLS roots and OpenSSL dependencies remain
//! trusted deployment components: checking these originals is not a complete closure attestation.
//! The worker has no public listener or caller-selected executable/configuration. Missing stores
//! are never initialized by serving startup. Transport failure leaves the attempt consumed.

use iroha_config::parameters::actual::KagemushaEnrollmentProvider;
use iroha_core::kagemusha_wallet_v1::enrollment_issuer::EnrollmentIssuerErrorV1 as Error;
use iroha_core_zk::kagemusha_wallet_enrollment_v1::issuer_worker::{
    VerifierConfigurationV1, VerifierExchangeV1, VerifierRuntimeSelectionV1,
};
use iroha_data_model::kagemusha::KagemushaWalletAssetScopeV1;
use iroha_fs::{FileSnapshot, PrivateDirectory, RetainedFile};
use sha2::{Digest as _, Sha256};
use std::{io, path::Path};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Error>;
const MAX_EXECUTABLE: usize = 256 * 1024 * 1024;
const MAX_ARCHIVE: usize = 8 * 1024 * 1024;
const MAX_ROOT: usize = 16 * 1024;
const MAX_FRAME: usize = 768 * 1024;

struct Original {
    file: RetainedFile,
    snapshot: FileSnapshot,
}
impl Original {
    fn open(
        path: &Path,
        private: bool,
        limit: usize,
        pin: Option<[u8; 32]>,
    ) -> Result<(Self, Zeroizing<Vec<u8>>)> {
        let file = if private {
            RetainedFile::open_private(path)
        } else {
            RetainedFile::open_regular(path)
        }
        .map_err(|_| Error::Unavailable)?;
        let snapshot = file.snapshot().map_err(|_| Error::Unavailable)?;
        let length = usize::try_from(
            file.file()
                .metadata()
                .map_err(|_| Error::Unavailable)?
                .len(),
        )
        .map_err(|_| Error::Unavailable)?;
        if length == 0 || length > limit {
            return Err(Error::Unavailable);
        }
        let mut bytes = Zeroizing::new(vec![0; length]);
        iroha_fs::read_exact_at(file.file(), &mut bytes, 0).map_err(|_| Error::Unavailable)?;
        if pin.is_some_and(|pin| pin == [0; 32] || <[u8; 32]>::from(Sha256::digest(&*bytes)) != pin)
        {
            return Err(Error::Selection);
        }
        let owner = Self { file, snapshot };
        owner.revalidate()?;
        Ok((owner, bytes))
    }
    fn revalidate(&self) -> Result<()> {
        self.file.revalidate().map_err(|_| Error::Unavailable)?;
        if self.file.snapshot().map_err(|_| Error::Unavailable)? != self.snapshot {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
}

/// One exclusive journal/process owner. Never constructable from a wire verdict.
pub(super) struct PrivateVerifier {
    selected: KagemushaEnrollmentProvider,
    python: Original,
    archive: Original,
    openssl: Original,
    /// Apple App Attestation root original; Android chains carry their own root.
    apple_root: Option<(Original, Zeroizing<Vec<u8>>)>,
    directory: PrivateDirectory,
    generation: Original,
    configuration: Option<(Original, [u8; 32])>,
    #[cfg(unix)]
    process: Option<process::Process>,
}
impl PrivateVerifier {
    /// Admit exact configured installation and existing exclusive journal. Non-Linux hosts
    /// refuse: their process/descriptor semantics have not been implemented for this worker.
    pub(super) fn open(provider: &KagemushaEnrollmentProvider) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            return Err(Error::Unavailable);
        }
        let selected = &provider.worker;
        let (python, _) = Original::open(
            &selected.python_executable,
            false,
            MAX_EXECUTABLE,
            Some(selected.python_sha256),
        )?;
        let (archive, _) = Original::open(
            &selected.verifier_archive,
            false,
            MAX_ARCHIVE,
            Some(selected.verifier_sha256),
        )?;
        let (openssl, _) = Original::open(
            &selected.openssl_executable,
            false,
            MAX_EXECUTABLE,
            Some(selected.openssl_sha256),
        )?;
        let apple_root = match (&provider.enrollment.platform, &selected.attestation_root) {
            (
                iroha_data_model::kagemusha::KagemushaWalletEnrollmentPlatformV1::Apple {
                    attestation_root_sha256,
                },
                Some(path),
            ) => Some(Original::open(
                path,
                false,
                MAX_ROOT,
                Some(*attestation_root_sha256),
            )?),
            (
                iroha_data_model::kagemusha::KagemushaWalletEnrollmentPlatformV1::Android {
                    ..
                },
                None,
            ) => None,
            _ => return Err(Error::Selection),
        };
        let directory =
            PrivateDirectory::open(&selected.store_directory).map_err(|_| Error::Unavailable)?;
        // Lock an existing initialized generation, never a newly created substitute lock.
        let (generation, _) = Original::open(
            &selected.store_directory.join("wallet-e1.generation"),
            true,
            128,
            None,
        )?;
        generation
            .file
            .file()
            .try_lock()
            .map_err(|_| Error::Unavailable)?;
        let owner = Self {
            selected: provider.clone(),
            python,
            archive,
            openssl,
            apple_root,
            directory,
            generation,
            configuration: None,
            #[cfg(unix)]
            process: None,
        };
        owner.revalidate(provider)?;
        Ok(owner)
    }
    pub(super) fn revalidate(&self, provider: &KagemushaEnrollmentProvider) -> Result<()> {
        if &self.selected != provider {
            return Err(Error::Selection);
        }
        self.directory
            .revalidate()
            .map_err(|_| Error::Unavailable)?;
        for original in [&self.python, &self.archive, &self.openssl, &self.generation] {
            original.revalidate()?;
        }
        if let Some((original, _)) = &self.apple_root {
            original.revalidate()?;
        }
        if let Some((original, _)) = &self.configuration {
            original.revalidate()?;
        }
        Ok(())
    }
    pub(super) fn configuration(
        &mut self,
        provider: &KagemushaEnrollmentProvider,
        asset: &KagemushaWalletAssetScopeV1,
    ) -> Result<VerifierConfigurationV1> {
        self.revalidate(provider)?;
        let config = derive_configuration(
            provider,
            asset,
            self.apple_root.as_ref().map(|(_, bytes)| bytes.as_slice()),
        )?;
        if self
            .configuration
            .as_ref()
            .is_none_or(|(_, digest)| *digest != config.digest())
        {
            // The sole issuer thread serializes all calls. Join the old exact child before
            // replacing its configuration, while retaining the same generation lock/store.
            #[cfg(unix)]
            drop(self.process.take());
            self.configuration = None;
            let name = format!("native-config-{}.json", hex::encode(config.digest()));
            match self
                .directory
                .read_optional(&name, 128 * 1024)
                .map_err(|_| Error::Unavailable)?
            {
                Some(original) if original.as_slice() == config.original() => (),
                Some(_) => return Err(Error::Selection),
                None => self
                    .directory
                    .write_atomic(&name, config.original(), iroha_fs::PublishMode::CreateNew)
                    .map_err(|_| Error::Unavailable)?,
            }
            let (original, _) = Original::open(
                &provider.worker.store_directory.join(name),
                true,
                128 * 1024,
                Some(config.digest()),
            )?;
            self.configuration = Some((original, config.digest()));
        }
        self.revalidate(provider)?;
        Ok(config)
    }
    pub(super) fn exchange(
        &mut self,
        provider: &KagemushaEnrollmentProvider,
        configuration: &VerifierConfigurationV1,
        exchange: &VerifierExchangeV1,
    ) -> Result<Vec<u8>> {
        if let Err(error) = self.revalidate(provider) {
            #[cfg(unix)]
            drop(self.process.take());
            return Err(error);
        }
        if self
            .configuration
            .as_ref()
            .is_none_or(|(_, digest)| configuration.digest() != *digest)
            || exchange.frame().len() > MAX_FRAME + 4
        {
            return Err(Error::Selection);
        }
        #[cfg(unix)]
        {
            if self.process.is_none() {
                self.process = Some(process::Process::spawn(self)?);
            }
            let result = self
                .process
                .as_mut()
                .ok_or(Error::Unavailable)?
                .exchange(exchange.frame(), provider.worker.exchange_timeout);
            // On uncertainty retire this process/channel before permitting any later recovery.
            // Its own ordinary child is supervised; no outside process is signalled.
            if result.is_err() {
                self.process.take();
            }
            if let Err(error) = self.revalidate(provider) {
                self.process.take();
                return Err(error);
            }
            result
        }
        #[cfg(not(unix))]
        {
            let _ = exchange;
            Err(Error::Unavailable)
        }
    }
}
impl Drop for PrivateVerifier {
    fn drop(&mut self) {
        // Join the exclusively owned child before releasing originals or generation custody.
        #[cfg(unix)]
        drop(self.process.take());
    }
}
fn derive_configuration(
    provider: &KagemushaEnrollmentProvider,
    asset: &KagemushaWalletAssetScopeV1,
    apple_root: Option<&[u8]>,
) -> Result<VerifierConfigurationV1> {
    let worker = &provider.worker;
    VerifierConfigurationV1::from_selected(
        &provider.app,
        &provider
            .enrollment
            .for_asset(asset)
            .map_err(|_| Error::Selection)?,
        apple_root,
        VerifierRuntimeSelectionV1 {
            openssl_path: worker.openssl_executable.to_str().ok_or(Error::Selection)?,
            openssl_sha256: worker.openssl_sha256,
            store_directory: worker.store_directory.to_str().ok_or(Error::Selection)?,
        },
    )
    .map_err(|_| Error::Selection)
}
#[cfg(unix)]
mod process;
#[cfg(test)]
mod tests;
