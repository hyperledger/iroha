//! One complete authenticated source grant for native wallet proving.
//!
//! Metadata, compact source-admission seals and installed public generators remain
//! resident; each sigma/Q/A/W/Omega acquisition streams all three exact signed originals.
//! There is no constructor from an Omega-only grant, readiness flag or subset.

use iroha_data_model::sumeragi_finality::SumeragiFinalityVerifier;
use iroha_kagemusha_proof::a_relation::schedule::compiled::OperationRoute;
use iroha_plonk::{
    keys::{SourceBoundViewV2, pk::artifact::ReadConfig},
    pcs::ipa::PinnedParams,
};
use std::sync::Arc;

use super::*;

/// A complete wallet source graph or one bounded active import was rejected.
#[derive(Debug, thiserror::Error)]
pub enum WalletSourcesErrorV1 {
    /// The exact complete profile is absent, stale or inconsistent with this build.
    #[error(transparent)]
    Builtin(#[from] iroha_plonk::keys::BuiltinSourceErrorV1),
    /// Wrong installation, route, member or original content address.
    #[error(transparent)]
    Original(#[from] Error),
    /// One of the eleven compiled sigma sources did not qualify.
    #[error(transparent)]
    Sigma(#[from] SigmaQualificationErrorV1),
    /// The native signed genesis does not authorize this wallet installation.
    #[error(transparent)]
    Finality(#[from] FinalityQualificationErrorV1),
    /// A Q source or exact signature policy did not qualify.
    #[error(transparent)]
    Q(#[from] QQualificationErrorV1),
    /// One logical operation route or stage did not qualify.
    #[error(transparent)]
    Operation(#[from] OperationQualificationErrorV1),
    /// The sole final Omega source failed complete terminal-catalog closure.
    #[error(transparent)]
    Omega(#[from] OmegaQualificationErrorV1),
}

impl WalletSourcesErrorV1 {
    /// Whether caller cancellation interrupted source work without a proof verdict.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        match self {
            Self::Builtin(error) => error.is_cancelled(),
            Self::Original(error) => error.is_cancelled(),
            Self::Sigma(error) => match error {
                SigmaQualificationErrorV1::Original(error) => error.is_cancelled(),
                SigmaQualificationErrorV1::Monetary(error) => error.is_cancelled(),
                SigmaQualificationErrorV1::Administrative(error) => error.is_cancelled(),
                SigmaQualificationErrorV1::Parameters | SigmaQualificationErrorV1::Metadata(_) => {
                    false
                }
            },
            Self::Finality(_) => false,
            Self::Q(error) => match error {
                QQualificationErrorV1::Original(error) => error.is_cancelled(),
                QQualificationErrorV1::Sigma(error) => error.is_cancelled(),
                QQualificationErrorV1::Signature(error) => error.is_cancelled(),
                QQualificationErrorV1::Source | QQualificationErrorV1::Metadata(_) => false,
            },
            Self::Operation(error) => match error {
                OperationQualificationErrorV1::Cancelled => true,
                OperationQualificationErrorV1::Original(error) => error.is_cancelled(),
                OperationQualificationErrorV1::Bootstrap(error) => match error {
                    BootstrapQualificationErrorV1::Original(error) => error.is_cancelled(),
                    BootstrapQualificationErrorV1::Native(error) => error.is_cancelled(),
                    BootstrapQualificationErrorV1::Source => false,
                },
                OperationQualificationErrorV1::Source
                | OperationQualificationErrorV1::A(_)
                | OperationQualificationErrorV1::W(_) => false,
            },
            Self::Omega(error) => match error {
                OmegaQualificationErrorV1::Original(error) => error.is_cancelled(),
                OmegaQualificationErrorV1::Native(error) => error.is_cancelled(),
                OmegaQualificationErrorV1::Routes | OmegaQualificationErrorV1::Catalog => false,
            },
        }
    }

    /// Whether the failure is missing or unreadable reinstallable source material.
    /// Cryptographic, length, hash, installation and source mismatches remain false.
    pub const fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Original(Error::Unavailable)
                | Self::Sigma(SigmaQualificationErrorV1::Original(Error::Unavailable))
                | Self::Q(QQualificationErrorV1::Original(Error::Unavailable))
                | Self::Operation(
                    OperationQualificationErrorV1::Original(Error::Unavailable)
                        | OperationQualificationErrorV1::Bootstrap(
                            BootstrapQualificationErrorV1::Original(Error::Unavailable)
                        )
                )
                | Self::Omega(OmegaQualificationErrorV1::Original(Error::Unavailable))
        )
    }
}

/// Complete source-qualified wallet graph under one authenticated installation.
/// This owns every exact sigma, native receipt verifier, Q, logical operation and final Omega
/// source. No original PK or proving polynomial is retained between imports.
/// Custody admission and durable wallet orchestration remain separate owners.
pub struct QualifiedWalletSourcesV1 {
    authenticated: AuthenticatedProducerInventoryV1,
    scope: SourceScopeV1,
    sigmas: QualifiedSigmasV1,
    finality: QualifiedReceiptSourceV1,
    q: Vec<QualifiedQProgramV1>,
    routes: Vec<QualifiedOperationRouteV1>,
    omega: QualifiedOmegaProgramV1,
    sigma_parameters: [Arc<PinnedParams<Eq>>; 2],
    q_parameters: Arc<PinnedParams<Ep>>,
    // Observation only: no capability, check or returned verdict reads this split.
    qualification: QualificationMetricsV1,
}

fn route_index(route: OperationRoute) -> Result<usize, Error> {
    compiled_routes()
        .iter()
        .position(|candidate| *candidate == route)
        .ok_or(Error::Inventory)
}

fn require_installation(
    selected: ([u8; 32], [u8; 32]),
    installed: ([u8; 32], [u8; 32]),
) -> Result<(), Error> {
    if selected != installed {
        return Err(Error::Authority);
    }
    Ok(())
}

impl AuthenticatedProducerInventoryV1 {
    /// Qualify the exact finite graph checked by this build's strict generator.
    ///
    /// Every original, native plan, route and terminal closure is checked before
    /// a complete owner returns. Unknown or stale profiles fail explicitly; this
    /// method never starts an implicit strict reconstruction of another graph.
    /// Independent signed installation and native-genesis checks remain required.
    /// When `originals` is an immutable snapshot, routes qualify on bounded workers
    /// with the result, error and counted work of the one-worker index order.
    ///
    /// # Errors
    /// Unsupported/stale compiled profile, wrong installation/genesis, or any
    /// bounded original, current plan, complete graph or cancellation failure.
    pub fn qualify_wallet_builtin(
        self,
        installed: &InstalledVerifierPackV1,
        native_finality: &SumeragiFinalityVerifier,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<QualifiedWalletSourcesV1, WalletSourcesErrorV1> {
        let mut clock = OpeningClockV1::start();
        require_installation(
            self.installation(),
            (
                installed.verifier().scheme().scheme_id(),
                installed.verifier().manifest_digest(),
            ),
        )?;
        let finality = self.qualify_finality(installed, native_finality)?;
        let profile = iroha_plonk::keys::BuiltinSourceProfileV1::match_actual(
            &super::builtin::profile_bytes(self.inventory(), installed.verifier().scheme())?,
            None,
        )?;
        let admission = super::builtin::Admission::Builtin(&profile);
        let scope = SourceScopeV1::from_scheme(installed.verifier().scheme())?;
        let sigma_parameters = [
            Arc::clone(installed.verifier().vesta_parameters(12)?),
            Arc::clone(installed.verifier().vesta_parameters(14)?),
        ];
        let q_parameters = Arc::clone(installed.verifier().pallas_parameters());
        let binding = clock.lap();
        let sigmas = self.qualify_sigmas_with_admission(
            originals,
            config,
            &sigma_parameters[0],
            &sigma_parameters[1],
            admission,
        )?;
        let sigma = clock.lap();
        let q = self.qualify_q_programs_with_admission(
            installed,
            &sigmas,
            originals,
            config,
            |_| {},
            admission,
        )?;
        let q_stage = clock.lap();
        // Batch-local: dropped when this qualification returns, never retained.
        let descriptors = DescriptorMemo::default();
        let routes = self.qualify_operation_routes_with_admission(
            installed,
            &q,
            originals,
            config,
            |_| {},
            admission,
            &descriptors,
        )?;
        let routes_stage = clock.lap();
        let omega = self.qualify_omega_with_admission(
            installed,
            &routes,
            originals,
            config,
            admission,
            &descriptors,
        )?;
        let qualification = QualificationMetricsV1 {
            binding,
            sigma,
            q: q_stage,
            routes: routes_stage,
            omega: clock.lap(),
        };
        Ok(QualifiedWalletSourcesV1 {
            authenticated: self,
            scope,
            sigmas,
            finality,
            q,
            routes,
            omega,
            sigma_parameters,
            q_parameters,
            qualification,
        })
    }

    /// Consume this authenticated inventory only after every compiled source has
    /// been reconstructed and every selected wallet PK strictly imported.
    /// Ordinary finality uses native BLS commit certificates and needs no circuit artifacts.
    /// The native finality verifier must be independently selected from signed genesis.
    /// All imports are sequential; only exact descriptor/VK metadata survives each.
    /// Repeated signature-Q members share strict metadata within one Q batch only
    /// after matching every ordered slot and rereading all exact signed originals.
    /// Same-program Receive aliases share a strict source owner within the route
    /// batch, with every alias rereading all exact signed originals.
    /// # Errors
    /// Another installation/native genesis, any incomplete route or source graph,
    /// changed source/context/key, unavailable original, or a resource bound failure.
    pub fn qualify_wallet(
        self,
        installed: &InstalledVerifierPackV1,
        native_finality: &SumeragiFinalityVerifier,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<QualifiedWalletSourcesV1, WalletSourcesErrorV1> {
        let mut clock = OpeningClockV1::start();
        require_installation(
            self.installation(),
            (
                installed.verifier().scheme().scheme_id(),
                installed.verifier().manifest_digest(),
            ),
        )?;
        let scope = SourceScopeV1::from_scheme(installed.verifier().scheme())?;
        // These transparent generators already belong to the exact authenticated
        // installation. Retain shared ownership for the grant's complete lifetime.
        let sigma_parameters = [
            Arc::clone(installed.verifier().vesta_parameters(12)?),
            Arc::clone(installed.verifier().vesta_parameters(14)?),
        ];
        let q_parameters = Arc::clone(installed.verifier().pallas_parameters());
        // Native genesis binding happens before any source-original read.
        let finality = self.qualify_finality(installed, native_finality)?;
        let binding = clock.lap();
        let sigmas = self.qualify_sigmas_for_installation(installed, originals, config)?;
        let sigma = clock.lap();
        let q = self.qualify_q_programs(installed, &sigmas, originals, config, |_| {})?;
        let q_stage = clock.lap();
        let routes = self.qualify_operation_routes(installed, &q, originals, config, |_| {})?;
        let routes_stage = clock.lap();
        let omega = self.qualify_omega(installed, &routes, originals, config)?;
        let qualification = QualificationMetricsV1 {
            binding,
            sigma,
            q: q_stage,
            routes: routes_stage,
            omega: clock.lap(),
        };
        Ok(QualifiedWalletSourcesV1 {
            authenticated: self,
            scope,
            sigmas,
            finality,
            q,
            routes,
            omega,
            sigma_parameters,
            q_parameters,
            qualification,
        })
    }
}

impl QualifiedWalletSourcesV1 {
    pub(super) const fn authenticated_inventory(&self) -> &AuthenticatedProducerInventoryV1 {
        &self.authenticated
    }
    /// Exact scheme and manifest identities of this complete graph.
    pub const fn installation(&self) -> ([u8; 32], [u8; 32]) {
        self.authenticated.installation()
    }
    /// Compiled provider and scheme-root source policy.
    pub const fn scope(&self) -> SourceScopeV1 {
        self.scope
    }
    /// Signed immutable references for this fully qualified graph.
    pub const fn inventory(&self) -> &ProducerInventoryV1 {
        self.authenticated.inventory()
    }
    /// Every exact sigma verifier in the global selector order.
    pub const fn sigmas(&self) -> &QualifiedSigmasV1 {
        &self.sigmas
    }
    /// Direct certificate verifier bound to independently authenticated native genesis.
    pub const fn finality(&self) -> &QualifiedReceiptSourceV1 {
        &self.finality
    }
    /// Complete sole Omega source; partial owners cannot construct this grant.
    pub const fn omega(&self) -> &QualifiedOmegaProgramV1 {
        &self.omega
    }
    /// Observation-only stage durations and work of the qualification that built this
    /// graph. Public counts only; it grants nothing and nothing may branch on it.
    pub const fn qualification_metrics(&self) -> &QualificationMetricsV1 {
        &self.qualification
    }
    /// Design §5.3: the largest peak proving memory over every installed relation the wallet
    /// proves, namely each σ, every Q key, every route's A and W stages, and Ω. One prover
    /// runs at a time, so this bounds any step and the lineage fold that follows it.
    /// # Errors
    /// A descriptor whose bound cannot be computed.
    pub fn peak_proving_memory_bytes(&self) -> Result<u64, Error> {
        let mut peak = peak_proving_memory(self.sigmas.metadata())?
            .max(peak_proving_memory([self.omega.key()])?);
        for program in &self.q {
            peak = peak.max(peak_proving_memory(program.keys())?);
        }
        for route in &self.routes {
            peak = peak.max(route.stage_memory_bytes());
        }
        Ok(peak)
    }
    /// The exact qualified owner selected by operation and both sigma selectors.
    /// # Errors
    /// Undefined or incompatible own/incoming selector for the requested operation.
    pub fn route(&self, route: OperationRoute) -> Result<&QualifiedOperationRouteV1, Error> {
        self.routes.get(route_index(route)?).ok_or(Error::Inventory)
    }
    /// Ordered Q sources for the exact selected logical route.
    /// # Errors
    /// Undefined route or an unavailable program index.
    pub fn q(&self, route: OperationRoute) -> Result<&QualifiedQProgramV1, Error> {
        let (_, _, program) = self.route(route)?.identity();
        self.q
            .get(usize::try_from(program).map_err(|_| Error::Inventory)?)
            .ok_or(Error::Inventory)
    }
    fn record(&self, route: OperationRoute) -> Result<&OperationV1, Error> {
        let (_, _, program) = self.route(route)?.identity();
        self.inventory()
            .operations
            .get(usize::try_from(program).map_err(|_| Error::Inventory)?)
            .ok_or(Error::Inventory)
    }
    /// Rebuild exactly one selected sigma's proving key from its qualified admission seal
    /// and compiled native source, after revalidating its exact signed originals.
    /// Drop the returned prover before importing the next stage to bound resident tables.
    /// # Errors
    /// Undefined selector, changed seal/source identity, bounded original failure or a
    /// rebuilt source that differs from the sealed source.
    pub fn import_sigma(
        &self,
        selector: u8,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<ImportedSigmaV1, WalletSourcesErrorV1> {
        self.import_sigma_cancellable(selector, originals, config, None)
    }

    /// Rebuild the same sealed source with a caller-owned cancellation signal.
    /// # Errors
    /// The ordinary source errors, or cancellation without a rebuilt key.
    pub fn import_sigma_cancellable(
        &self,
        selector: u8,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<ImportedSigmaV1, WalletSourcesErrorV1> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let index = *self
            .inventory()
            .sigma
            .get(usize::from(selector))
            .ok_or(Error::Inventory)?;
        // Bind the exact retained seal before any source I/O. A seal is authority
        // only inside this already-qualified immutable installation and selector.
        let view = self.sigmas.bind(selector, index, cancellation)?;
        let view = revalidate_stage(
            &self.authenticated,
            index,
            view,
            originals,
            config,
            cancellation,
        )?;
        Ok(sigma::rebuild_prover(
            usize::from(selector),
            view,
            &self.sigma_parameters[0],
            &self.sigma_parameters[1],
            config.coset_cache,
            cancellation,
        )?)
    }
    /// Revalidate one selected sigma's exact signed originals without rebuilding its key.
    /// A wallet's speculative Send checks them under the wallet owner and then rebuilds the
    /// same sealed source through [`Self::bind_sigma_cancellable`] without that owner.
    /// # Errors
    /// Undefined selector, changed seal/source identity, the local row cap, bounded original
    /// failure or cancellation.
    pub(crate) fn revalidate_sigma_cancellable(
        &self,
        selector: u8,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<(), WalletSourcesErrorV1> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let index = *self
            .inventory()
            .sigma
            .get(usize::from(selector))
            .ok_or(Error::Inventory)?;
        let view = self.sigmas.bind(selector, index, cancellation)?;
        revalidate_stage(
            &self.authenticated,
            index,
            view,
            originals,
            config,
            cancellation,
        )?;
        Ok(())
    }
    /// The sealed sigma source of [`Self::import_sigma_cancellable`] without reading any
    /// original. A wallet's speculative Send binds it to prove without the wallet owner,
    /// after [`Self::revalidate_sigma_cancellable`] checked the same originals in that
    /// speculation's locked prepare; it grants nothing more.
    /// # Errors
    /// Undefined selector, changed seal/source identity, the local row cap, a rebuilt source
    /// that differs from the sealed source, or cancellation.
    pub(crate) fn bind_sigma_cancellable(
        &self,
        selector: u8,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<ImportedSigmaV1, WalletSourcesErrorV1> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let index = *self
            .inventory()
            .sigma
            .get(usize::from(selector))
            .ok_or(Error::Inventory)?;
        let view = self.sigmas.bind(selector, index, cancellation)?;
        if view.binding().n() > config.maximum_rows {
            return Err(Error::Inventory.into());
        }
        Ok(sigma::rebuild_prover(
            usize::from(selector),
            view,
            &self.sigma_parameters[0],
            &self.sigma_parameters[1],
            config.coset_cache,
            cancellation,
        )?)
    }
    /// Revalidate one sealed Q source and borrow its installed signature policy and metadata.
    /// # Errors
    /// Undefined route/stage, bounded original failure or a changed source/key identity.
    pub fn import_q(
        &self,
        route: OperationRoute,
        stage: usize,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<ImportedQV1<'_>, WalletSourcesErrorV1> {
        self.import_q_cancellable(route, stage, originals, config, None)
    }

    /// Import the same exact source with a caller-owned cancellation signal.
    /// # Errors
    /// The ordinary source errors, or cancellation without an imported key.
    pub fn import_q_cancellable(
        &self,
        route: OperationRoute,
        stage: usize,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<ImportedQV1<'_>, WalletSourcesErrorV1> {
        let owner = self.bind_q_cancellable(route, stage, config, cancellation)?;
        self.authenticated.revalidate_original_cancellable(
            *self.record(route)?.q.get(stage).ok_or(Error::Inventory)?,
            originals,
            config.maximum_bytes,
            cancellation,
        )?;
        Ok(owner)
    }
    /// The already-admitted source of [`Self::import_q_cancellable`] without reading any
    /// original. A wallet fold binds it to prove without the wallet owner, after that import
    /// revalidated the same stage's originals in the same locked turn; it grants nothing more.
    /// # Errors
    /// Undefined route/stage, a changed source identity, the local row cap or cancellation.
    pub(crate) fn bind_q_cancellable(
        &self,
        route: OperationRoute,
        stage: usize,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<ImportedQV1<'_>, WalletSourcesErrorV1> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let record = self.record(route)?;
        let index = *record.q.get(stage).ok_or(Error::Inventory)?;
        let owner =
            self.q(route)?
                .borrow_cancellable(stage, index, &self.q_parameters, cancellation)?;
        if owner.binding().n() > config.maximum_rows {
            return Err(Error::Inventory.into());
        }
        Ok(owner)
    }
    /// Revalidate the selected A originals and borrow their already-admitted source view.
    /// # Errors
    /// Undefined route/stage, bounded read or any strict source/context/key mismatch.
    pub fn import_a(
        &self,
        route: OperationRoute,
        stage: usize,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<SourceBoundViewV2<'_, Eq>, WalletSourcesErrorV1> {
        self.import_a_cancellable(route, stage, originals, config, None)
    }

    /// Import the same exact source with a caller-owned cancellation signal.
    /// # Errors
    /// The ordinary source errors, or cancellation without admitted metadata.
    pub fn import_a_cancellable(
        &self,
        route: OperationRoute,
        stage: usize,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceBoundViewV2<'_, Eq>, WalletSourcesErrorV1> {
        // Bind the exact retained role before any source I/O. A seal is authority
        // only inside this already-qualified immutable installation and stage.
        let view = self.bind_a_cancellable(route, stage, config, cancellation)?;
        revalidate_stage(
            &self.authenticated,
            *self.record(route)?.a.get(stage).ok_or(Error::Inventory)?,
            view,
            originals,
            config,
            cancellation,
        )
    }
    /// The already-admitted source of [`Self::import_a_cancellable`] without reading any
    /// original. A wallet fold binds it to prove without the wallet owner, after that import
    /// revalidated the same stage's originals in the same locked turn; it grants nothing more.
    /// # Errors
    /// Undefined route/stage, a changed source identity, the local row cap or cancellation.
    pub(crate) fn bind_a_cancellable(
        &self,
        route: OperationRoute,
        stage: usize,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceBoundViewV2<'_, Eq>, WalletSourcesErrorV1> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let index = *self.record(route)?.a.get(stage).ok_or(Error::Inventory)?;
        let view = self.route(route)?.bind_a(stage, index, cancellation)?;
        if view.binding().n() > config.maximum_rows {
            return Err(Error::Inventory.into());
        }
        Ok(view)
    }
    /// Revalidate selected W originals and borrow their already-admitted source view.
    /// # Errors
    /// Undefined route/stage, bounded read or any strict source/context/key mismatch.
    pub fn import_w(
        &self,
        route: OperationRoute,
        stage: usize,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<SourceBoundViewV2<'_, Ep>, WalletSourcesErrorV1> {
        self.import_w_cancellable(route, stage, originals, config, None)
    }

    /// Import the same exact source with a caller-owned cancellation signal.
    /// # Errors
    /// The ordinary source errors, or cancellation without admitted metadata.
    pub fn import_w_cancellable(
        &self,
        route: OperationRoute,
        stage: usize,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceBoundViewV2<'_, Ep>, WalletSourcesErrorV1> {
        // Bind the exact retained role before any source I/O. A seal is authority
        // only inside this already-qualified immutable installation and stage.
        let view = self.bind_w_cancellable(route, stage, config, cancellation)?;
        revalidate_stage(
            &self.authenticated,
            *self.record(route)?.w.get(stage).ok_or(Error::Inventory)?,
            view,
            originals,
            config,
            cancellation,
        )
    }
    /// The already-admitted source of [`Self::import_w_cancellable`] without reading any
    /// original. A wallet fold binds it to prove without the wallet owner, after that import
    /// revalidated the same stage's originals in the same locked turn; it grants nothing more.
    /// # Errors
    /// Undefined route/stage, a changed source identity, the local row cap or cancellation.
    pub(crate) fn bind_w_cancellable(
        &self,
        route: OperationRoute,
        stage: usize,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<SourceBoundViewV2<'_, Ep>, WalletSourcesErrorV1> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        let index = *self.record(route)?.w.get(stage).ok_or(Error::Inventory)?;
        let view = self.route(route)?.bind_w(stage, index, cancellation)?;
        if view.binding().n() > config.maximum_rows {
            return Err(Error::Inventory.into());
        }
        Ok(view)
    }
    /// Revalidate the sole final Omega originals and borrow its exact installed metadata.
    /// # Errors
    /// Bounded read failure or changed original/source/verifier identity.
    pub fn import_omega(
        &self,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<iroha_kagemusha_proof::omega::native::ProverView<'_>, WalletSourcesErrorV1> {
        self.import_omega_cancellable(originals, config, None)
    }

    /// Import the same exact source with a caller-owned cancellation signal.
    /// # Errors
    /// The ordinary source errors, or cancellation without an imported key.
    pub fn import_omega_cancellable(
        &self,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<iroha_kagemusha_proof::omega::native::ProverView<'_>, WalletSourcesErrorV1> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        Ok(self.omega.import_prover_cancellable(
            &self.authenticated,
            originals,
            config,
            cancellation,
        )?)
    }
    /// The strict Omega source of [`Self::import_omega_cancellable`] without reading any
    /// original. A wallet fold binds it to prove without the wallet owner, after that import
    /// revalidated the same originals in the same locked turn; it grants nothing more.
    /// # Errors
    /// A changed source identity, the local row cap or cancellation.
    pub(crate) fn bind_omega_cancellable(
        &self,
        config: ReadConfig,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<iroha_kagemusha_proof::omega::native::ProverView<'_>, WalletSourcesErrorV1> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        Ok(self
            .omega
            .bind_prover_cancellable(&self.authenticated, config, cancellation)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_typed_original_outages_are_reinstallable() {
        for error in [
            Error::Unavailable,
            Error::Inventory,
            Error::Profile,
            Error::Authority,
            Error::Proof,
        ] {
            let expected = error == Error::Unavailable;
            for nested in [
                WalletSourcesErrorV1::Original(error.clone()),
                WalletSourcesErrorV1::Sigma(SigmaQualificationErrorV1::Original(error.clone())),
                WalletSourcesErrorV1::Q(QQualificationErrorV1::Original(error.clone())),
                WalletSourcesErrorV1::Operation(OperationQualificationErrorV1::Original(
                    error.clone(),
                )),
                WalletSourcesErrorV1::Operation(OperationQualificationErrorV1::Bootstrap(
                    BootstrapQualificationErrorV1::Original(error.clone()),
                )),
                WalletSourcesErrorV1::Omega(OmegaQualificationErrorV1::Original(error)),
            ] {
                assert_eq!(nested.is_unavailable(), expected);
            }
        }
    }

    #[test]
    fn dispatch_uses_all_three_fields_and_rejects_every_uncompiled_combination() {
        let routes = compiled_routes();
        for (index, route) in routes.iter().enumerate() {
            assert_eq!(route_index(*route), Ok(index));
        }
        for variant in Variant::ALL {
            for own in 0..=16 {
                for incoming in core::iter::once(None).chain((0..=16).map(Some)) {
                    let route = OperationRoute {
                        variant,
                        own,
                        incoming,
                    };
                    assert_eq!(
                        route_index(route).ok(),
                        routes.iter().position(|r| *r == route)
                    );
                }
            }
        }
    }

    #[test]
    fn complete_grant_requires_both_exact_installation_identities() {
        let installation = ([1; 32], [2; 32]);
        require_installation(installation, installation).unwrap();
        for field in 0..2 {
            for byte in 0..32 {
                let mut changed = installation;
                if field == 0 {
                    changed.0[byte] ^= 1;
                } else {
                    changed.1[byte] ^= 1;
                }
                assert_eq!(
                    require_installation(installation, changed),
                    Err(Error::Authority)
                );
            }
        }
    }
}

impl crate::kagemusha_wallet_proofs_v1::NativeProofError for WalletSourcesErrorV1 {
    fn is_cancelled(&self) -> bool {
        WalletSourcesErrorV1::is_cancelled(self)
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use iroha_kagemusha_proof::{SigmaError, admin_sigma::native::AdminSigmaError};
    use iroha_plonk::{KeyError, keys::RebuildError};
    #[test]
    fn source_cancellation_never_becomes_invalid_or_unavailable_material() {
        let rebuild = || RebuildError::Key(KeyError::Cancelled);
        let cases = [
            WalletSourcesErrorV1::Original(Error::Cancelled),
            WalletSourcesErrorV1::Operation(OperationQualificationErrorV1::Cancelled),
            WalletSourcesErrorV1::Q(QQualificationErrorV1::Original(Error::Cancelled)),
            WalletSourcesErrorV1::Omega(OmegaQualificationErrorV1::Original(Error::Cancelled)),
            WalletSourcesErrorV1::Sigma(SigmaQualificationErrorV1::Original(Error::Cancelled)),
            WalletSourcesErrorV1::Sigma(SigmaQualificationErrorV1::Monetary(SigmaError::Rebuild(
                rebuild(),
            ))),
            WalletSourcesErrorV1::Sigma(SigmaQualificationErrorV1::Administrative(
                AdminSigmaError::Rebuild(rebuild()),
            )),
        ];
        for error in cases {
            assert!(error.is_cancelled());
            assert!(!error.is_unavailable());
        }
        assert!(!WalletSourcesErrorV1::Original(Error::Unavailable).is_cancelled());
        assert!(!WalletSourcesErrorV1::Original(Error::Proof).is_cancelled());
        // A rebuilt source that differs from its seal is a hard proof failure.
        assert!(
            !WalletSourcesErrorV1::Sigma(SigmaQualificationErrorV1::Monetary(SigmaError::Rebuild(
                RebuildError::Source
            )))
            .is_cancelled()
        );
    }
}

// The view can only be produced by the exact qualified stage owner above. This
// common acquisition path enforces current policy before opening any original;
// no retained seal freezes the row/byte limits used during initial admission.
pub(super) fn revalidate_stage<'a, C: iroha_pasta::PastaCurve>(
    authenticated: &AuthenticatedProducerInventoryV1,
    member: u32,
    view: SourceBoundViewV2<'a, C>,
    originals: &mut dyn OriginalSourceV1,
    config: ReadConfig,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<SourceBoundViewV2<'a, C>, WalletSourcesErrorV1> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
    if view.binding().n() > config.maximum_rows {
        return Err(Error::Inventory.into());
    }
    authenticated.revalidate_original_cancellable(
        member,
        originals,
        config.maximum_bytes,
        cancellation,
    )?;
    Ok(view)
}
