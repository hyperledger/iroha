//! Original installation intake for the existing move-only Native runtime owner.
//! No foreign original can select a trust key, slot or monetary engine.

use super::*;
use iroha_core_zk::kagemusha_wallet_artifacts_v1::{
    InstallationV1, InstalledVerifierPackV1, VERIFIER_PACK_MAX_BYTES_V1,
    producer_inventory::{
        BlobV1, CATALOG_MAX_BYTES_V1, OpeningMetricsV1, PROVING_KEY_MAX_BYTES_V1,
        QualifiedWalletSourcesV1,
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
mod memo;
mod originals;
mod registration;
mod selection;
pub use attempt::WalletInstallationAttempt;
pub use exports::*;
use originals::{CatalogMetadata, CatalogOriginals};
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

/// Public objects of one complete admission, shared by its runtime and, after the whole
/// attempt succeeds, by the process-local memo (design §9.1). No provider, platform,
/// custody root, key, enrollment or account state is part of it.
#[derive(Clone)]
struct AdmittedGraph {
    installed: Arc<InstalledVerifierPackV1>,
    sources: Arc<QualifiedWalletSourcesV1>,
    originals: CatalogOriginals,
}
/// An admitted graph with the exact key it may be memoized under.
type Memoized = (memo::MemoKey, AdmittedGraph);

/// The process's single admitted graph (see `memo`).
static ADMITTED: memo::Memo<AdmittedGraph> = memo::Memo::new();

/// One installation attempt: complete admission, which reuses the memoized graph only after
/// every check of a fresh load has passed, then a fresh platform, custody root, provider and
/// owner. Complete success memoizes its graph; an INVALID or CUSTODY_LOST result evicts it.
fn install<P: advance::KagemushaWalletPlatformV1 + 'static>(
    input: RuntimeOriginals<'_>,
    android: bool,
    platform: impl FnOnce() -> Result<(P, std::path::PathBuf)>,
) -> Result<Box<WalletInstallationAttempt>> {
    ADMITTED.settle(installation(input, android, platform))
}
fn installation<P: advance::KagemushaWalletPlatformV1 + 'static>(
    input: RuntimeOriginals<'_>,
    android: bool,
    platform: impl FnOnce() -> Result<(P, std::path::PathBuf)>,
) -> Result<(Box<WalletInstallationAttempt>, Memoized)> {
    let prepared = PreparedInstallation::load(input)?;
    let (platform, root) = platform()?;
    let (owner, opening, admitted) = prepared.runtime(platform, root, android)?;
    Ok((
        Box::new(WalletInstallationAttempt::new(owner, opening)),
        admitted,
    ))
}

/// The installed pack carries exactly the scheme, artifact signer and manifest originals of
/// the authenticated selection.
fn require_installed(
    installed: &InstalledVerifierPackV1,
    selected: &selection::AuthenticatedBase,
) -> Result<()> {
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
    Ok(())
}

struct PreparedInstallation {
    selected: Arc<Selection>,
    admitted: AdmittedGraph,
    // The exact originals and carrier root under which `admitted` may be memoized.
    key: memo::MemoKey,
    // Observation only: public phase durations and counts; no decision reads them.
    opening: OpeningMetricsV1,
}
impl PreparedInstallation {
    fn load(input: RuntimeOriginals<'_>) -> Result<Self> {
        input.validate_bounds()?;
        let mut opening = OpeningMetricsV1::start();
        let selected = Arc::new(Selection::installed(&input)?);
        opening.lap("selection");
        Self::from_selected(input, selected, opening)
    }
    fn from_selected(
        input: RuntimeOriginals<'_>,
        selected: Arc<Selection>,
        mut opening: OpeningMetricsV1,
    ) -> Result<Self> {
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
        let base = selected.authenticated_base()?;
        // Every carrier metadata, layout and transport-selection check runs on every attempt,
        // before the memoized admitted graph can be consulted (design §9.1).
        let metadata = CatalogMetadata::open(
            input.originals_root,
            input.verifier_pack,
            input.producer_inventory,
            &base,
        )?;
        let key = memo::MemoKey::new(&input, metadata.identity()?);
        opening.lap("catalog_metadata");
        if let Some(admitted) = ADMITTED.reuse(&key, |admitted| {
            Self::reuse(&input, &selected, &base, &metadata, admitted, &mut opening)
        }) {
            return Ok(Self {
                selected,
                admitted,
                key,
                opening,
            });
        }
        let installed = InstalledVerifierPackV1::load(input.verifier_pack, selected.installation)
            .map_err(|_| Failure::code(INVALID))?;
        require_installed(&installed, &selected)?;
        opening.lap("verifier_pack");
        base.require_producer_selection(&installed)?;
        let inventory = installed
            .authenticate_producer_inventory(input.producer_inventory)
            .map_err(|_| Failure::code(INVALID))?;
        let originals = CatalogOriginals::from_authenticated(&inventory, metadata, base)?;
        opening.lap("catalog_intake");
        let sources = originals
            .with_snapshot(|snapshot| {
                opening.lap("snapshot_capture");
                let sources = inventory.qualify_wallet_builtin(
                    &installed,
                    &selected.genesis,
                    snapshot,
                    read_config(),
                );
                // The qualified owner reports its own stage split below.
                opening.restart();
                sources
            })
            .map_err(|error| {
                Failure::code(if error.is_unavailable() {
                    ARTIFACTS_UNAVAILABLE
                } else {
                    INVALID
                })
            })?;
        opening.qualification(sources.qualification_metrics());
        opening.lap("closing");
        Ok(Self {
            selected,
            admitted: AdmittedGraph {
                installed: Arc::new(installed),
                sources: Arc::new(sources),
                originals,
            },
            key,
            opening,
        })
    }
    /// Reuse the memoized graph admitted for these exact originals under the same carrier
    /// root (design §9.1). The fresh selection and every carrier metadata check have already
    /// passed. This repeats each check a fresh load makes against the installed pack, then
    /// closes custody over the memo's observed originals and re-hashes every stored frame.
    /// The caller builds a fresh provider, custody root and owner, exactly as after a load.
    fn reuse(
        input: &RuntimeOriginals<'_>,
        selected: &Selection,
        base: &Arc<selection::AuthenticatedBase>,
        metadata: &CatalogMetadata<'_>,
        admitted: AdmittedGraph,
        opening: &mut OpeningMetricsV1,
    ) -> Result<AdmittedGraph> {
        let AdmittedGraph {
            installed,
            sources,
            originals,
        } = admitted;
        let verifier = installed.verifier();
        if installed.original() != input.verifier_pack
            || verifier.scheme().scheme_id() != selected.installation.scheme_id
            || verifier.manifest_digest() != selected.installation.manifest_digest
        {
            return Err(Failure::code(INVALID));
        }
        require_installed(&installed, selected)?;
        base.require_producer_selection(&installed)?;
        let inventory = installed
            .authenticate_producer_inventory(input.producer_inventory)
            .map_err(|_| Failure::code(INVALID))?;
        opening.lap("admitted_intake");
        let originals = originals.reuse(&inventory, metadata, Arc::clone(base));
        // Recorded on refusal too, so a fresh load after it reports only its own work.
        opening.lap("admitted_graph");
        let originals = originals?;
        Ok(AdmittedGraph {
            installed,
            sources,
            originals,
        })
    }
    /// Returns the runtime owner with the complete observation-only opening record, and the
    /// admitted graph with its key for the memo once the whole attempt has succeeded.
    fn runtime<P: advance::KagemushaWalletPlatformV1 + 'static>(
        self,
        platform: P,
        custody_root: std::path::PathBuf,
        android: bool,
    ) -> Result<(Arc<open::RuntimeOwner>, OpeningMetricsV1, Memoized)> {
        let Self {
            selected,
            admitted,
            key,
            mut opening,
        } = self;
        let fs = advance::KagemushaWalletStdFsV1::open(custody_root)
            .map_err(|error| Failure::unavailable(UNAVAILABLE, error))?;
        let provider = advance::KagemushaWalletProviderV1::open(
            fs,
            platform,
            selected.scheme.scheme_id(),
            advance::KagemushaWalletProviderOptionsV1::default(),
        )?;
        // Each owner gets its own provider and custody root; only public DATA is shared.
        let runtime = state::NativeWalletRuntimeV1::new(
            provider,
            Arc::clone(&admitted.installed),
            Arc::clone(&admitted.sources),
            Arc::clone(&selected.genesis),
            admitted.originals.clone(),
            read_config(),
            MemoryBudget::DEFAULT,
        );
        let binding = BoundOriginals { selected, android };
        let owner = open::bound_runtime_owner(runtime, binding);
        opening.lap("runtime");
        opening.finish();
        Ok((owner, opening, (key, admitted)))
    }
}

#[cfg(test)]
mod tests;
