//! Move-only native installation and account-admission ownership.

use super::*;
use crate::kagemusha_wallet_enrollment_v1 as enrollment;
use crate::kagemusha_wallet_intake_v1::{
    self as intake, PendingWalletOpenV1, WalletOpenBeginFailureV1,
};

/// Authenticated installation and sole original store retained across account retries.
/// Only native provisioning can construct its installed-source capabilities.
pub struct NativeWalletRuntimeV1<F: KagemushaWalletFsV1, P, S> {
    custody: RuntimeCustodyV1<F, P>,
    installed: Arc<InstalledVerifierPackV1>,
    sources: Arc<QualifiedWalletSourcesV1>,
    genesis: Arc<SumeragiFinalityVerifier>,
    originals: S,
    read: ReadConfig,
    budget: MemoryBudget,
}

pub(super) enum RuntimeCustodyV1<F: KagemushaWalletFsV1, P> {
    Exclusive(crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderV1<F, P>),
    // Enrollment retains the same installed proof graph and original source owner.
    Enrollment(Box<enrollment::EnrollmentOwnerV1<F, P>>),
    // Unexpected native references retain custody and cannot confer admission.
    Shared(AdvanceHandle<F, P>),
    // An ordinary begin refusal owns the exact bounded originals and selected-source pin.
    BeginFailed(WalletOpenBeginFailureV1<F, P>),
    // An ordinary account-finish refusal retains the SAME actual Pending/challenge.
    Pending(PendingWalletOpenV1<F, P>),
}

/// Failure of original admission or native state recovery.
#[derive(Debug, thiserror::Error)]
pub enum NativeOpenErrorV1 {
    /// Original/account/source admission did not complete.
    #[error(transparent)]
    Intake(#[from] intake::Error),
    /// Native state/proof initialization did not complete.
    #[error(transparent)]
    State(#[from] Error),
}

/// Failed admission retaining the exact runtime phase and every actual custody/source owner.
/// Ordinary retries keep the original begin DATA and any already-issued account challenge.
pub struct NativeOpenFailureV1<F: KagemushaWalletFsV1, P, S> {
    runtime: NativeWalletRuntimeV1<F, P, S>,
    error: NativeOpenErrorV1,
}
impl<F: KagemushaWalletFsV1, P, S> std::fmt::Debug for NativeOpenFailureV1<F, P, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeOpenFailureV1")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<F: KagemushaWalletFsV1, P, S> NativeOpenFailureV1<F, P, S> {
    /// Recover the same unadmitted runtime and its precise failure.
    #[must_use]
    pub fn into_parts(self) -> (NativeWalletRuntimeV1<F, P, S>, NativeOpenErrorV1) {
        (self.runtime, self.error)
    }
}

/// One native account challenge. Ordinary finish refusal retains it; explicit abandonment
/// alone relinquishes it without replacing the actual payment key or custody provider.
pub struct PendingNativeWalletOpenV1<F: KagemushaWalletFsV1, P, S> {
    pending: PendingWalletOpenV1<F, P>,
    installed: Arc<InstalledVerifierPackV1>,
    sources: Arc<QualifiedWalletSourcesV1>,
    genesis: Arc<SumeragiFinalityVerifier>,
    originals: S,
    read: ReadConfig,
    budget: MemoryBudget,
}

/// Concrete coordinator admitted from actual originals and an existing account signature.
pub type NativeWalletCoordinatorV1<F, P, S> =
    Coordinator<AdvanceHandle<F, P>, ProviderArchive<F, P>, NativeWalletProofsV1<F, P, S>>;

impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    NativeWalletRuntimeV1<F, P, S>
{
    /// Retain native-provisioned capabilities and the sole original store before account intake.
    /// This is not account admission and performs no payment-key or monetary operation.
    #[must_use]
    pub fn new(
        provider: crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderV1<F, P>,
        installed: Arc<InstalledVerifierPackV1>,
        sources: Arc<QualifiedWalletSourcesV1>,
        genesis: Arc<SumeragiFinalityVerifier>,
        originals: S,
        read: ReadConfig,
        budget: MemoryBudget,
    ) -> Self {
        Self {
            custody: RuntimeCustodyV1::Exclusive(provider),
            installed,
            sources,
            genesis,
            originals,
            read,
            budget,
        }
    }

    /// Move exclusive custody into authenticated enrollment without rebuilding installed sources.
    /// Refusal returns the same runtime, including every provider and original-source owner.
    pub fn start_enrollment(
        self,
        config: enrollment::EnrollmentConfigV1,
    ) -> Result<Self, (Self, enrollment::Error)> {
        let Self {
            custody,
            installed,
            sources,
            genesis,
            originals,
            read,
            budget,
        } = self;
        let restore = |custody| Self {
            custody,
            installed,
            sources,
            genesis,
            originals,
            read,
            budget,
        };
        let RuntimeCustodyV1::Exclusive(provider) = custody else {
            return Err((restore(custody), enrollment::Error::Phase));
        };
        match enrollment::EnrollmentOwnerV1::new(provider, config) {
            Ok(owner) => Ok(restore(RuntimeCustodyV1::Enrollment(Box::new(owner)))),
            Err((provider, error)) => Err((restore(RuntimeCustodyV1::Exclusive(provider)), error)),
        }
    }

    /// Borrow only the actual retained enrollment phase; no handle or DATA creates this owner.
    pub fn enrollment(
        &mut self,
    ) -> Result<&mut enrollment::EnrollmentOwnerV1<F, P>, enrollment::Error> {
        match &mut self.custody {
            RuntimeCustodyV1::Enrollment(owner) => Ok(owner),
            _ => Err(enrollment::Error::Phase),
        }
    }

    /// Preserve an actual returned enrollment effect before releasing this provider.
    /// Cleanup refusal retains the same runtime and pending original bytes.
    pub fn prepare_close(&mut self) -> Result<(), enrollment::Error> {
        if let RuntimeCustodyV1::Enrollment(owner) = &mut self.custody {
            owner.flush_apple_returned()?;
        }
        Ok(())
    }
    /// Complete a genuine retained E6 and restore the same installed runtime for account open.
    /// Missing or unavailable originals retain the entire enrollment phase for an exact retry.
    pub fn finish_enrollment(mut self) -> Result<(Self, [Vec<u8>; 4]), (Self, enrollment::Error)> {
        let selected = match self.enrollment().and_then(|owner| owner.open_originals()) {
            Ok(originals) => originals,
            Err(error) => return Err((self, error)),
        };
        let Self {
            custody,
            installed,
            sources,
            genesis,
            originals,
            read,
            budget,
        } = self;
        let RuntimeCustodyV1::Enrollment(owner) = custody else {
            unreachable!("enrollment phase was borrowed above")
        };
        Ok((
            Self {
                custody: RuntimeCustodyV1::Exclusive(owner.into_provider()),
                installed,
                sources,
                genesis,
                originals,
                read,
                budget,
            },
            selected,
        ))
    }

    /// Admit originals or recover the SAME retained original intake/account challenge.
    /// A new nonce is sampled only for an actual first successful begin. Retained failed
    /// begin and pending phases accept exactly their original DATA, never a replacement.
    /// # Errors
    /// Returns the exact runtime phase and its actual provider/source/original store.
    pub fn begin(
        self,
        credential: &[u8],
        certificates: &[u8],
        account: &[u8],
        asset: &[u8],
    ) -> Result<PendingNativeWalletOpenV1<F, P, S>, NativeOpenFailureV1<F, P, S>> {
        let Self {
            custody,
            installed,
            sources,
            genesis,
            originals,
            read,
            budget,
        } = self;
        let proposed = [credential, certificates, account, asset];
        let pending =
            match custody {
                RuntimeCustodyV1::BeginFailed(failed) => {
                    if !failed.matches_originals(proposed) {
                        return Err(NativeOpenFailureV1 {
                            runtime: Self {
                                custody: RuntimeCustodyV1::BeginFailed(failed),
                                installed,
                                sources,
                                genesis,
                                originals,
                                read,
                                budget,
                            },
                            error: intake::Error::Authority("retained original intake changed")
                                .into(),
                        });
                    }
                    failed.retry()
                }
                RuntimeCustodyV1::Pending(pending) => {
                    if !pending.matches_originals(proposed) {
                        return Err(NativeOpenFailureV1 {
                            runtime: Self {
                                custody: RuntimeCustodyV1::Pending(pending),
                                installed,
                                sources,
                                genesis,
                                originals,
                                read,
                                budget,
                            },
                            error: intake::Error::Authority("pending original intake changed")
                                .into(),
                        });
                    }
                    Ok(pending)
                }
                custody @ RuntimeCustodyV1::Enrollment(_) => {
                    return Err(NativeOpenFailureV1 {
                        runtime: Self {
                            custody,
                            installed,
                            sources,
                            genesis,
                            originals,
                            read,
                            budget,
                        },
                        error: intake::Error::Authority(
                            "enrollment has not handed off verified originals",
                        )
                        .into(),
                    });
                }
                RuntimeCustodyV1::Exclusive(provider) => PendingWalletOpenV1::begin(
                    provider,
                    Arc::clone(&installed),
                    Arc::clone(&sources),
                    credential,
                    certificates,
                    account,
                    asset,
                ),
                RuntimeCustodyV1::Shared(handle) => {
                    let provider = match handle.try_into_provider() {
                    Ok(provider) => provider,
                    Err(handle) => return Err(NativeOpenFailureV1 {
                        runtime: Self { custody: RuntimeCustodyV1::Shared(handle),
                            installed, sources, genesis, originals, read, budget },
                        error: Error::Provider(ProviderError::Unavailable(
                            crate::kagemusha_wallet_advance_v1::KagemushaWalletUnavailableV1::Busy,
                        )).into(),
                    }),
                };
                    PendingWalletOpenV1::begin(
                        provider,
                        Arc::clone(&installed),
                        Arc::clone(&sources),
                        credential,
                        certificates,
                        account,
                        asset,
                    )
                }
            };
        let pending = match pending {
            Ok(pending) => pending,
            Err(failed) => {
                let error = failed.error();
                return Err(NativeOpenFailureV1 {
                    runtime: Self {
                        custody: RuntimeCustodyV1::BeginFailed(failed),
                        installed,
                        sources,
                        genesis,
                        originals,
                        read,
                        budget,
                    },
                    error: error.into(),
                });
            }
        };
        Ok(PendingNativeWalletOpenV1 {
            pending,
            installed,
            sources,
            genesis,
            originals,
            read,
            budget,
        })
    }

    /// Recover only an ACTUAL retained Pending after ordinary finish refusal.
    /// This owns the same original challenge and provider; no DATA or identifier creates it.
    /// A runtime in another phase is returned unchanged without sampling or side effects.
    pub fn recover_pending(self) -> Result<PendingNativeWalletOpenV1<F, P, S>, Self> {
        let Self {
            custody,
            installed,
            sources,
            genesis,
            originals,
            read,
            budget,
        } = self;
        match custody {
            RuntimeCustodyV1::Pending(pending) => Ok(PendingNativeWalletOpenV1 {
                pending,
                installed,
                sources,
                genesis,
                originals,
                read,
                budget,
            }),
            custody => Err(Self {
                custody,
                installed,
                sources,
                genesis,
                originals,
                read,
                budget,
            }),
        }
    }
}
impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    PendingNativeWalletOpenV1<F, P, S>
{
    /// Exact fresh native message for the existing Ed25519 account to sign.
    #[must_use]
    pub fn challenge(&self) -> &[u8] {
        self.pending.challenge()
    }

    /// Compare original transport DATA without changing this actual challenge/source.
    #[must_use]
    pub fn matches_originals(&self, proposed: [&[u8]; 4]) -> bool {
        self.pending.matches_originals(proposed)
    }

    /// Explicitly abandon this challenge and preserve custody for a fresh begin.
    /// This deliberate cancellation is never the response to ordinary Result refusal.
    #[must_use]
    pub fn abandon(self) -> NativeWalletRuntimeV1<F, P, S> {
        NativeWalletRuntimeV1 {
            custody: RuntimeCustodyV1::Exclusive(self.pending.abandon()),
            installed: self.installed,
            sources: self.sources,
            genesis: self.genesis,
            originals: self.originals,
            read: self.read,
            budget: self.budget,
        }
    }

    /// Consume the account challenge and initialize the actual native operation owner.
    /// # Errors
    /// An account/source refusal retains the SAME Pending/challenge and original store.
    /// Later coordinator initialization failures retain current custody/source ownership;
    /// their admitted/partial activation metadata recovery remains a separate contract.
    pub fn finish(
        self,
        signature: &[u8],
    ) -> Result<NativeWalletCoordinatorV1<F, P, S>, NativeOpenFailureV1<F, P, S>> {
        let Self {
            pending,
            installed,
            sources,
            genesis,
            originals,
            read,
            budget,
        } = self;
        let admitted = match pending.finish(signature) {
            Ok(admitted) => admitted,
            Err(failure) => {
                let (pending, error) = failure.into_parts();
                return Err(NativeOpenFailureV1 {
                    runtime: NativeWalletRuntimeV1 {
                        custody: RuntimeCustodyV1::Pending(pending),
                        installed,
                        sources,
                        genesis,
                        originals,
                        read,
                        budget,
                    },
                    error: error.into(),
                });
            }
        };
        match admitted.into_coordinator(&genesis, originals, read, budget) {
            Ok(wallet) => Ok(wallet),
            Err((custody, originals, error)) => Err(NativeOpenFailureV1 {
                runtime: NativeWalletRuntimeV1 {
                    custody,
                    installed,
                    sources,
                    genesis,
                    originals,
                    read,
                    budget,
                },
                error: error.into(),
            }),
        }
    }
}

/// Independently provisioned native deployment authority and fixed resource limits.
/// No foreign open request or received Payment may supply these trust selections.
pub struct NativeInstallationConfigV1 {
    /// Exact installed scheme and signed manifest selected by native deployment.
    pub installation: crate::kagemusha_wallet_artifacts_v1::InstallationV1,
    /// Already authenticated native genesis and its exact finality committee.
    pub genesis: Arc<SumeragiFinalityVerifier>,
    /// Bounded strict original-key importer policy.
    pub read: ReadConfig,
    /// Native process-wide proving memory budget.
    pub budget: MemoryBudget,
}

/// Failed native startup retains the actual provider and sole original source for retry.
pub struct NativeStartupFailureV1<F: KagemushaWalletFsV1, P, S> {
    provider: crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderV1<F, P>,
    originals: S,
    error: Error,
}
impl<F: KagemushaWalletFsV1, P, S> std::fmt::Debug for NativeStartupFailureV1<F, P, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeStartupFailureV1")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}
impl<F: KagemushaWalletFsV1, P, S> NativeStartupFailureV1<F, P, S> {
    /// Recover exact exclusive custody, source ownership and failure without any admission grant.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderV1<F, P>,
        S,
        Error,
    ) {
        (self.provider, self.originals, self.error)
    }
}
impl<F: KagemushaWalletFsV1, P: KagemushaWalletPlatformV1, S: OriginalSourceV1 + Send>
    NativeWalletRuntimeV1<F, P, S>
{
    /// Native startup loader for the signed complete wallet graph and real custody provider.
    ///
    /// The embedding app calls this from trusted native initialization, using independently
    /// deployed pins and authenticated genesis. It authenticates the complete signed verifier
    /// pack, inventory, all 52 source routes and every original proving key before retaining
    /// a runtime. Missing deployment material is unavailable, never a default trust root.
    /// # Errors
    /// Invalid signatures, mismatched native configuration, incomplete source graphs or I/O.
    /// The exclusive provider and original source are returned on every failure.
    pub fn load(
        config: &NativeInstallationConfigV1,
        provider: crate::kagemusha_wallet_advance_v1::KagemushaWalletProviderV1<F, P>,
        verifier_pack: &[u8],
        producer_inventory: &[u8],
        mut originals: S,
    ) -> Result<Self, NativeStartupFailureV1<F, P, S>> {
        let qualified = (|| -> Result<_, Error> {
            if provider.scheme_id() != &config.installation.scheme_id {
                return Err(Error::Proof("native configured custody scheme"));
            }
            let installed = proof(InstalledVerifierPackV1::load(
                verifier_pack,
                config.installation,
            ))?;
            let authenticated =
                proof(installed.authenticate_producer_inventory(producer_inventory))?;
            let sources = authenticated
                .qualify_wallet(&installed, &config.genesis, &mut originals, config.read)
                .map_err(|error| {
                    if error.is_unavailable() {
                        Error::ArtifactsUnavailable("native startup original source")
                    } else {
                        Error::Proof("native startup complete source graph")
                    }
                })?;
            Ok((Arc::new(installed), Arc::new(sources)))
        })();
        match qualified {
            Ok((installed, sources)) => Ok(Self::new(
                provider,
                installed,
                sources,
                Arc::clone(&config.genesis),
                originals,
                config.read,
                config.budget,
            )),
            Err(error) => Err(NativeStartupFailureV1 {
                provider,
                originals,
                error,
            }),
        }
    }
}
