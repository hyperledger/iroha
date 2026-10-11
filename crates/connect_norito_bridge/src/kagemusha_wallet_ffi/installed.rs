//! Original installation intake for the existing move-only Native runtime owner.
//! No foreign original can select a trust key, slot or monetary engine.

use super::*;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::{
    InstallationV1, InstalledVerifierPackV1, VERIFIER_PACK_MAX_BYTES_V1,
    producer_inventory::{
        BlobV1, CATALOG_MAX_BYTES_V1, PROVING_KEY_MAX_BYTES_V1, QualifiedWalletSourcesV1,
    },
};
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk::keys::{CosetCachePolicy, pk::artifact::ReadConfig};

mod attempt;
mod exports;
#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    target_os = "windows"
))]
mod jni;
mod originals;
mod registration;
mod selection;
pub use attempt::WalletInstallationAttempt;
pub use exports::*;
use originals::CatalogOriginals;
pub(crate) use registration::relocate_registration_source;
use selection::Selection;
pub(super) use selection::Session;

pub(crate) const APP_MANIFEST_MAX: usize = 8 * 1024 * 1024;
pub(crate) const ENVELOPE_MAX: usize = 2048;
pub(crate) const WALLET_RUNTIME_MAX: usize = 128 * 1024;
pub(crate) const GENESIS_MAX: usize = iroha_genesis::SIGNED_GENESIS_MAX_BYTES_V1;
pub(crate) const ROOT_MAX: usize = 4096;
pub(crate) const REGISTRATION_MAX: usize =
    iroha_core_zk::kagemusha_wallet_registration_v1::REGISTRATION_SOURCE_MAX_BYTES_V1;
pub(crate) const RUNTIME_BOUNDS: [usize; 8] = [
    APP_MANIFEST_MAX,
    ENVELOPE_MAX,
    WALLET_RUNTIME_MAX,
    VERIFIER_PACK_MAX_BYTES_V1,
    CATALOG_MAX_BYTES_V1,
    GENESIS_MAX,
    ROOT_MAX,
    REGISTRATION_MAX,
];

pub(crate) struct RuntimeOriginals<'a> {
    pub app_manifest: &'a [u8],
    pub envelope: &'a [u8],
    pub wallet_runtime: &'a [u8],
    pub verifier_pack: &'a [u8],
    pub producer_inventory: &'a [u8],
    pub signed_genesis: &'a [u8],
    pub originals_root: &'a [u8],
    pub registration_source: &'a [u8],
}
impl RuntimeOriginals<'_> {
    pub(crate) fn validate_bounds(&self) -> Result<()> {
        for (original, maximum) in [
            self.app_manifest,
            self.envelope,
            self.wallet_runtime,
            self.verifier_pack,
            self.producer_inventory,
            self.signed_genesis,
            self.originals_root,
            self.registration_source,
        ]
        .into_iter()
        .zip(RUNTIME_BOUNDS)
        {
            if original.len() > maximum {
                return Err(Failure::code(INVALID));
            }
        }
        for original in [
            self.app_manifest,
            self.envelope,
            self.wallet_runtime,
            self.signed_genesis,
        ] {
            if original.is_empty() {
                return Err(Failure::code(INVALID));
            }
        }
        let financial = [
            self.verifier_pack,
            self.producer_inventory,
            self.originals_root,
        ];
        if financial.iter().any(|original| original.is_empty())
            && financial.iter().any(|original| !original.is_empty())
        {
            return Err(Failure::code(INVALID));
        }
        Ok(())
    }
}
/// Called only after Selection authenticates the whole signed base and native genesis.
fn financial_offer(input: &RuntimeOriginals<'_>) -> Result<()> {
    let absent = [
        input.verifier_pack.is_empty(),
        input.producer_inventory.is_empty(),
        input.originals_root.is_empty(),
    ];
    if absent.iter().all(|value| *value) {
        return Err(Failure::code(ARTIFACTS_UNAVAILABLE));
    }
    if absent.iter().any(|value| *value) {
        return Err(Failure::code(INVALID));
    }
    Ok(())
}
fn read_config() -> ReadConfig {
    ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}
/// The independent build root authenticated all retained originals. This private owner
/// is retained by both account admission and the actual Native proof source, so exact
/// installation originals survive successful admission without a second wallet registry.
pub(super) struct BoundOriginals {
    selected: Arc<Selection>,
    android: bool,
}
impl BoundOriginals {
    pub(super) fn enrollment_session(&self, originals: [&[u8]; 3]) -> Result<Session> {
        self.selected.enrollment_session(self.android, originals)
    }
    pub(super) fn enrollment_projection(&self) -> Vec<u8> {
        let mut bytes = self.selected.asset.scale.to_be_bytes().to_vec();
        bytes.extend_from_slice(&self.selected.asset_original);
        bytes
    }
    pub(super) fn asset_original(&self) -> &[u8] {
        &self.selected.asset_original
    }

    pub(super) fn require(&self, originals: [&[u8]; 4]) -> Result<()> {
        let [credential, _, _, asset] = originals;
        if asset != self.selected.asset_original {
            return Err(Failure::code(INVALID));
        }
        let credential = KagemushaWalletCredentialV1::decode_canonical(
            credential,
            &self.selected.scheme.scheme_id(),
        )
        .map_err(|_| Failure::code(INVALID))?;
        let policy = if self.android {
            self.selected.android_app_policy
        } else {
            self.selected.apple_app_policy
        };
        if credential.body.asset_digest != self.selected.asset.asset_digest()
            || credential.body.app_policy != policy
            || credential.body.evidence_kind.is_android() != self.android
        {
            return Err(Failure::code(INVALID));
        }
        // The ordinary original intake authenticates the actual retained/renewed issuer
        // certificate set. It is not replaced by the current Core issuer certificate.
        Ok(())
    }
}

struct PreparedInstallation {
    selected: Arc<Selection>,
    installed: Arc<InstalledVerifierPackV1>,
    sources: Arc<QualifiedWalletSourcesV1>,
    originals: CatalogOriginals,
}
impl PreparedInstallation {
    fn load(input: RuntimeOriginals<'_>) -> Result<Self> {
        input.validate_bounds()?;
        let selected = Arc::new(Selection::installed(&input)?);
        Self::from_selected(input, selected)
    }
    fn from_selected(input: RuntimeOriginals<'_>, selected: Arc<Selection>) -> Result<Self> {
        // Both closed application adapters have authenticated their whole base here.
        // Complete financial absence never acquires a platform, custody root or owner.
        input.validate_bounds()?;
        match (selected.financial.as_ref(), input.verifier_pack.is_empty()) {
            (None, true) => return Err(Failure::code(ARTIFACTS_UNAVAILABLE)),
            (Some(financial), false)
                if financial.pack_identity == BlobV1::of(input.verifier_pack)
                    && financial.catalog_identity == BlobV1::of(input.producer_inventory) => {}
            _ => return Err(Failure::code(INVALID)),
        }
        financial_offer(&input)?;
        let installed = InstalledVerifierPackV1::load(input.verifier_pack, selected.installation)
            .map_err(|_| Failure::code(INVALID))?;
        if installed.originals().scheme.to_vec()
            != selected
                .scheme
                .to_canonical_bytes()
                .map_err(|_| Failure::code(INVALID))?
            || installed.originals().signer_certificate != selected.artifact_certificate
            || installed.originals().manifest != selected.artifact_manifest
        {
            return Err(Failure::code(INVALID));
        }
        let base = selected.authenticated_base()?;
        base.require_producer_selection(&installed)?;
        let inventory = installed
            .authenticate_producer_inventory(input.producer_inventory)
            .map_err(|_| Failure::code(INVALID))?;
        let mut originals = CatalogOriginals::from_authenticated(
            &inventory,
            input.originals_root,
            input.verifier_pack,
            input.producer_inventory,
            base,
        )?;
        let sources = inventory
            .qualify_wallet(&installed, &selected.genesis, &mut originals, read_config())
            .map_err(|error| {
                Failure::code(if error.is_unavailable() {
                    ARTIFACTS_UNAVAILABLE
                } else {
                    INVALID
                })
            })?;
        Ok(Self {
            selected,
            installed: Arc::new(installed),
            sources: Arc::new(sources),
            originals,
        })
    }
    fn runtime<P: advance::KagemushaWalletPlatformV1 + 'static>(
        self,
        platform: P,
        custody_root: std::path::PathBuf,
        android: bool,
    ) -> Result<Arc<open::RuntimeOwner>> {
        let fs = advance::KagemushaWalletStdFsV1::open(custody_root)
            .map_err(|error| Failure::unavailable(UNAVAILABLE, error))?;
        let provider = advance::KagemushaWalletProviderV1::open(
            fs,
            platform,
            self.selected.scheme.scheme_id(),
            advance::KagemushaWalletProviderOptionsV1::default(),
        )?;
        let runtime = state::NativeWalletRuntimeV1::new(
            provider,
            self.installed,
            self.sources,
            Arc::clone(&self.selected.genesis),
            self.originals,
            read_config(),
            MemoryBudget::DEFAULT,
        );
        let binding = BoundOriginals {
            selected: self.selected,
            android,
        };
        Ok(open::bound_runtime_owner(runtime, binding))
    }
}

#[cfg(test)]
mod tests;
