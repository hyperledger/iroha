//! Explicit offline source compilation, with bounded originals and no installed grants.
//!
//! Every key uses the same source factory as authenticated intake. Only one PK is
//! resident in this owner; source synthesis and key generation still need separate
//! process-memory qualification. Partial originals remain useful after a failure.

#[path = "compiler/pack.rs"]
mod pack;
pub use pack::{WalletArtifactDraftV1, WalletArtifactOriginalsV1};

use std::collections::BTreeMap;

use iroha_kagemusha_proof::{
    SigmaCircuit,
    a_relation::{native::artifact::KeyArtifact, schedule::compiled::OperationRoute, split::WKey},
    admin_sigma::{BootstrapCircuit, native::*},
    omega::{OmegaPlan, native as outer},
    q_sigma::QSigmaPlan,
    q_signature::QSignaturePlan,
};
use iroha_plonk::{
    ProvingKey,
    frontend::Circuit,
    keys::{CosetCachePolicy, KeyError, KeygenConfigV2, keygen_pk_v2, pk::artifact::ReadConfig},
    pcs::ipa::PinnedParams,
};

use super::*;

/// Offline content-addressed publication; no operation here signs or installs a catalog.
pub trait OriginalSinkV1: OriginalSourceV1 {
    /// Store the exact bytes atomically and refuse a changed existing content address.
    /// The compiler independently rereads the bounded original before strict import.
    /// # Errors
    /// Storage failure, changed original or a refused local storage budget.
    fn store(&mut self, identity: BlobV1, bytes: &[u8]) -> Result<(), Error>;
}

/// Exact compiled owner where an offline construction failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompilationPhaseV1 {
    /// Key identity.
    KeyIdentity,
    /// Original encoding.
    OriginalEncoding,
    /// Strict original import.
    StrictOriginalImport,
    /// Imported identity.
    ImportedIdentity,
    /// Sigma parameters.
    SigmaParameters,
    /// Q recipe.
    QRecipe,
    /// Q parameters.
    QParameters,
    /// Sigma Q source.
    SigmaQSource,
    /// Signature Q source.
    SignatureQSource,
    /// Q metadata.
    QMetadata,
    /// Route classes.
    RouteClasses,
    /// A parameters.
    AParameters,
    /// W parameters.
    WParameters,
    /// A source.
    ASource,
    /// W source.
    WSource,
    /// W identity.
    WIdentity,
    /// Bootstrap recipe.
    BootstrapRecipe,
    /// Operation recipe.
    OperationRecipe,
    /// Omega parameters.
    OmegaParameters,
    /// Omega layout.
    OmegaLayout,
    /// Omega source.
    OmegaSource,
}

/// Offline source, original, storage or complete-catalog failure.
#[derive(Clone, Debug, thiserror::Error)]
pub enum CompilationErrorV1 {
    /// A bounded original or immutable storage identity failed.
    #[error(transparent)]
    Original(#[from] Error),
    /// The fixed source or its complete original import failed at this owner.
    #[error("offline source compilation failed: {0:?}")]
    Source(CompilationPhaseV1),
    /// Typed source-key construction failure; it contains no witness values.
    #[error("offline key generation failed: {0}")]
    KeyGeneration(#[from] KeyError),
    /// Public fixed operation and stage where source-key construction failed.
    #[error("offline {route:?} stage {stage} wrapper={wrapper} key generation failed: {source}")]
    OperationKeyGeneration {
        /// Compiled logical operation and sigma selectors.
        route: OperationRoute,
        /// Zero-based A/W stage.
        stage: usize,
        /// Whether the failed source was its W continuation.
        wrapper: bool,
        /// Exact typed key error, including a synthesis or resource refusal.
        source: KeyError,
    },
    /// A canonical original failed source lookup or complete strict import.
    #[error(transparent)]
    ProvingKey(#[from] iroha_plonk::keys::pk::artifact::Error),
    /// The supplied partial graph cannot close into this exact complete catalog.
    #[error("offline catalog is incomplete or has a different dependency")]
    Closure,
}

/// Raw compiled key identity. This contains no PK and grants no installation authority.
#[derive(Clone, Debug)]
pub struct CompiledKeyV1<C: PastaCurve> {
    original: OriginalV1,
    metadata: KeyArtifact<C>,
}
impl<C: PastaCurve> CompiledKeyV1<C> {
    /// Exact original content addresses, ready for eventual signed packaging.
    pub const fn original(&self) -> OriginalV1 {
        self.original
    }
    /// Exact descriptor/VK from source generation followed by strict original import.
    pub const fn metadata(&self) -> &KeyArtifact<C> {
        &self.metadata
    }
}

/// Fixed global selector order established only by the compiled sigma constructors.
pub struct CompiledSigmasV1 {
    keys: [CompiledKeyV1<Eq>; 16],
}
impl CompiledSigmasV1 {
    /// The exact ordered sixteen source originals; callers cannot reorder this owner.
    pub const fn keys(&self) -> &[CompiledKeyV1<Eq>; 16] {
        &self.keys
    }
}

/// Raw Q recipe and emitted originals, independent of any scheme/manifest identity.
pub struct CompiledQV1 {
    scope: SourceScopeV1,
    variant: Variant,
    own: Vec<u8>,
    incoming: Vec<u8>,
    keys: Vec<CompiledKeyV1<Ep>>,
    recipe: QProgramRecipeV1,
}
impl CompiledQV1 {
    /// Exact raw source recipe; this is deliberately not a qualified Q grant.
    pub const fn recipe(&self) -> &QProgramRecipeV1 {
        &self.recipe
    }
    /// Source-compiled Q originals in their exact ordered roles.
    pub fn keys(&self) -> &[CompiledKeyV1<Ep>] {
        &self.keys
    }
}

/// One reconstructed route with all strict A/W originals, without admission authority.
#[derive(Clone)]
pub struct CompiledOperationV1 {
    scope: SourceScopeV1,
    route: OperationRoute,
    own: Vec<u8>,
    incoming: Vec<u8>,
    context: Vec<[u8; 32]>,
    q: Vec<CompiledKeyV1<Ep>>,
    a: Vec<CompiledKeyV1<Eq>>,
    w: Vec<CompiledKeyV1<Ep>>,
    predecessor: Option<KeyArtifact<Ep>>,
}
impl CompiledOperationV1 {
    /// Exact source-compiled terminal identity, with no final catalog authority.
    pub fn terminal(&self) -> &CompiledKeyV1<Eq> {
        &self.a[self.a.len() - 1]
    }
    /// Number of sequential A originals actually imported.
    pub fn stages(&self) -> usize {
        self.a.len()
    }
}

/// Canonical compact Omega source built from the supplied exact ordered catalog.
pub struct CompiledOmegaV1 {
    key: CompiledKeyV1<Ep>,
    terminals: Vec<KeyArtifact<Eq>>,
}
impl CompiledOmegaV1 {
    /// Exact candidate dependency for a subsequent complete route reconstruction.
    pub const fn key(&self) -> &CompiledKeyV1<Ep> {
        &self.key
    }
}

/// Explicit offline compiler. It never synthesizes an authenticated marker, signs an
/// intermediate inventory, selects a live witness layout or opens a wallet.
pub struct OfflineCompilerV1<'a> {
    scope: SourceScopeV1,
    sink: &'a mut dyn OriginalSinkV1,
    config: ReadConfig,
    maximum_total_bytes: u64,
    bytes: u64,
    blobs: BTreeMap<[u8; 32], u64>,
    candidates: BTreeMap<[u8; 32], OriginalV1>,
}

fn source<T, E>(result: Result<T, E>, phase: CompilationPhaseV1) -> Result<T, CompilationErrorV1> {
    result.map_err(|_| CompilationErrorV1::Source(phase))
}
fn stage_error(
    error: CompilationErrorV1,
    route: OperationRoute,
    stage: usize,
    wrapper: bool,
) -> CompilationErrorV1 {
    match error {
        CompilationErrorV1::KeyGeneration(source) => CompilationErrorV1::OperationKeyGeneration {
            route,
            stage,
            wrapper,
            source,
        },
        other => other,
    }
}
fn equal<C: PastaCurve>(a: &KeyArtifact<C>, b: &KeyArtifact<C>) -> bool {
    a.binding() == b.binding() && a.key().to_bytes() == b.key().to_bytes()
}
fn config(types: Vec<InstanceType>, compress: bool, read: ReadConfig) -> KeygenConfigV2 {
    let mut cfg = KeygenConfigV2::pipa_r(types);
    cfg.compress_selectors = compress;
    cfg.coset_cache = CosetCachePolicy::OnDemand;
    cfg.msm_budget = read.msm_budget;
    cfg
}

impl<'a> OfflineCompilerV1<'a> {
    /// Set explicit local storage/import bounds. These are not process RSS limits.
    /// # Errors
    /// Zero/oversized original cap, insufficient row cap, eager cache or zero disk cap.
    pub fn new(
        scope: SourceScopeV1,
        sink: &'a mut dyn OriginalSinkV1,
        config: ReadConfig,
        maximum_total_bytes: u64,
    ) -> Result<Self, CompilationErrorV1> {
        if config.maximum_bytes == 0
            || config.maximum_bytes > PROVING_KEY_MAX_BYTES_V1
            || config.maximum_rows != 1 << 16
            || config.coset_cache != CosetCachePolicy::OnDemand
            || maximum_total_bytes == 0
        {
            return Err(Error::Inventory.into());
        }
        Ok(Self {
            scope,
            sink,
            config,
            maximum_total_bytes,
            bytes: 0,
            blobs: BTreeMap::new(),
            candidates: BTreeMap::new(),
        })
    }

    fn publish(&mut self, bytes: &[u8], cap: usize) -> Result<BlobV1, CompilationErrorV1> {
        let blob = BlobV1::of(bytes);
        blob.length(cap)?;
        if let Some(length) = self.blobs.get(&blob.sha256) {
            if *length != blob.bytes {
                return Err(Error::Inventory.into());
            }
        } else {
            let total = self.bytes.checked_add(blob.bytes).ok_or(Error::Inventory)?;
            if total > self.maximum_total_bytes {
                return Err(Error::Inventory.into());
            }
            self.sink.store(blob, bytes)?;
            self.blobs.insert(blob.sha256, blob.bytes);
            self.bytes = total;
        }
        Ok(blob)
    }

    fn key<C: PastaCurve, S: Circuit<C::ScalarExt>>(
        &mut self,
        circuit: &S,
        params: &PinnedParams<C>,
        cfg: &KeygenConfigV2,
    ) -> Result<CompiledKeyV1<C>, CompilationErrorV1> {
        let fingerprint = iroha_plonk::keys::source_fingerprint_v2(params, circuit, cfg, None)?;
        if let Some(&original) = self.candidates.get(fingerprint.digest()) {
            return self.import_candidate(original, &fingerprint, circuit, params);
        }
        let key = keygen_pk_v2(params, circuit, cfg)?;
        let d = key.binding().descriptor();
        let expected = (d.num_fixed_columns as usize)
            .checked_add(d.permutation.len())
            .and_then(|n| n.checked_mul(key.binding().n()))
            .and_then(|n| n.checked_mul(32))
            .and_then(|n| n.checked_add(76 + key.vk().to_bytes().len()))
            .ok_or(Error::Inventory)?;
        if expected > self.config.maximum_bytes {
            return Err(Error::Inventory.into());
        }
        let metadata = source(
            KeyArtifact::new(key.binding().clone(), key.vk().clone()),
            CompilationPhaseV1::KeyIdentity,
        )?;
        let original = source(
            key.artifact_bytes_v2(),
            CompilationPhaseV1::OriginalEncoding,
        )?;
        drop(key);
        let record = OriginalV1 {
            descriptor: self.publish(metadata.binding().encoded(), DESCRIPTOR_MAX_BYTES_V1)?,
            verifying_key: self.publish(metadata.key().to_bytes(), VERIFYING_KEY_MAX_BYTES_V1)?,
            proving_key: self.publish(&original, self.config.maximum_bytes)?,
        };
        drop(original);
        // Storage is not trusted even immediately after publication.
        drop(read(self.sink, record.descriptor, DESCRIPTOR_MAX_BYTES_V1)?);
        drop(read(
            self.sink,
            record.verifying_key,
            VERIFYING_KEY_MAX_BYTES_V1,
        )?);
        let original = read(self.sink, record.proving_key, self.config.maximum_bytes)?;
        let imported = source(
            ProvingKey::from_artifact_v2(
                &original,
                metadata.binding(),
                params,
                circuit,
                self.config,
            ),
            CompilationPhaseV1::StrictOriginalImport,
        )?;
        source(
            metadata.require_prover(&imported),
            CompilationPhaseV1::ImportedIdentity,
        )?;
        drop(imported);
        drop(original);
        self.remember_candidate(*fingerprint.digest(), record)?;
        Ok(CompiledKeyV1 {
            original: record,
            metadata,
        })
    }

    fn import<C: PastaCurve, S: Circuit<C::ScalarExt>>(
        &mut self,
        expected: &CompiledKeyV1<C>,
        circuit: &S,
        params: &PinnedParams<C>,
    ) -> Result<CompiledKeyV1<C>, CompilationErrorV1> {
        let record = expected.original;
        let descriptor = read(self.sink, record.descriptor, DESCRIPTOR_MAX_BYTES_V1)?;
        let verifying_key = read(self.sink, record.verifying_key, VERIFYING_KEY_MAX_BYTES_V1)?;
        if descriptor != expected.metadata.binding().encoded()
            || verifying_key != expected.metadata.key().to_bytes()
        {
            return Err(CompilationErrorV1::Closure);
        }
        let original = read(self.sink, record.proving_key, self.config.maximum_bytes)?;
        let imported = source(
            ProvingKey::from_artifact_v2(
                &original,
                expected.metadata.binding(),
                params,
                circuit,
                self.config,
            ),
            CompilationPhaseV1::StrictOriginalImport,
        )?;
        source(
            expected.metadata.require_prover(&imported),
            CompilationPhaseV1::ImportedIdentity,
        )?;
        Ok(expected.clone())
    }

    /// Build and reimport the fixed sixteen sigma sources, one original at a time.
    /// # Errors
    /// Any fixed source capacity, publication, key generation or exact import failure.
    pub fn sigmas(&mut self) -> Result<CompiledSigmasV1, CompilationErrorV1> {
        let p12 = source(
            PinnedParams::derive(12),
            CompilationPhaseV1::SigmaParameters,
        )?;
        let p14 = source(
            PinnedParams::derive(14),
            CompilationPhaseV1::SigmaParameters,
        )?;
        let cfg = config(
            BootstrapCircuit::instance_types().to_vec(),
            true,
            self.config,
        );
        let mut keys = Vec::with_capacity(16);
        for selector in 0..16 {
            let key = match selector {
                0 => self.key(&BootstrapProver::source_circuit(), &p12, &cfg)?,
                1 => self.key(&LoadProver::source_circuit(), &p12, &cfg)?,
                12 => self.key(&ArchiveProver::source_circuit(), &p12, &cfg)?,
                13 => self.key(&UnloadProver::source_circuit(), &p12, &cfg)?,
                14 => self.key(&RefreshProver::source_circuit(), &p12, &cfg)?,
                15 => self.key(&RetiringProver::source_circuit(), &p12, &cfg)?,
                _ => {
                    let shape = sigma::monetary_shape(selector)?;
                    self.key(
                        &SigmaCircuit::<Fp>::keygen(shape.params),
                        if shape.k == 12 { &p12 } else { &p14 },
                        &cfg,
                    )?
                }
            };
            keys.push(key);
        }
        Ok(CompiledSigmasV1 {
            keys: keys.try_into().map_err(|_| CompilationErrorV1::Closure)?,
        })
    }

    /// Build exact Q sources without a signed or qualified installation placeholder.
    /// # Errors
    /// Incompatible classes, fixed source overflow, storage failure or strict import failure.
    pub fn q(
        &mut self,
        variant: Variant,
        own: &[u8],
        incoming: &[u8],
        sigmas: &CompiledSigmasV1,
    ) -> Result<CompiledQV1, CompilationErrorV1> {
        let metadata = core::array::from_fn(|i| sigmas.keys[i].metadata.clone());
        let (q, signatures) = source(
            q_source_recipe(self.scope, variant, own, incoming, &metadata),
            CompilationPhaseV1::QRecipe,
        )?;
        let params = source(PinnedParams::derive(16), CompilationPhaseV1::QParameters)?;
        let circuit = source(q.source_circuit(), CompilationPhaseV1::SigmaQSource)?;
        let mut keys = vec![self.key(
            &circuit,
            &params,
            &config(QSigmaPlan::instance_types().to_vec(), true, self.config),
        )?];
        for signature in &signatures {
            keys.push(self.key(
                &source(
                    signature.source_circuit(),
                    CompilationPhaseV1::SignatureQSource,
                )?,
                &params,
                &config(QSignaturePlan::instance_types().to_vec(), true, self.config),
            )?);
        }
        let recipe = source(
            QProgramRecipeV1::from_metadata(
                q.plan().clone(),
                signatures,
                keys.iter().map(|k| k.metadata.clone()).collect(),
            ),
            CompilationPhaseV1::QMetadata,
        )?;
        Ok(CompiledQV1 {
            scope: self.scope,
            variant,
            own: own.to_vec(),
            incoming: incoming.to_vec(),
            keys,
            recipe,
        })
    }

    /// Compile one exact logical route under a raw candidate Omega dependency.
    /// Source compilation does not authorize that candidate; final closure must compare it.
    /// # Errors
    /// Foreign scope/class or any stage source/import failure.
    pub fn operation(
        &mut self,
        route: OperationRoute,
        q: &CompiledQV1,
        omega: Option<&CompiledKeyV1<Ep>>,
    ) -> Result<CompiledOperationV1, CompilationErrorV1> {
        self.operation_source(route, q, omega, None)
    }

    /// Reconstruct a route under the final exact Omega key without regenerating its
    /// originals. Omega keys are witnessed by A, while their descriptor is fixed.
    /// Every original is reread and strict-imported under the final source; the
    /// complete context and all A/W identities must remain unchanged. No old-key
    /// alias or compatibility acceptance is introduced.
    /// # Errors
    /// Foreign route/recipe/scope, changed descriptor/source/context, missing or
    /// altered originals, or any strict original import failure.
    pub fn close_operation(
        &mut self,
        operation: &CompiledOperationV1,
        q: &CompiledQV1,
        omega: &CompiledOmegaV1,
    ) -> Result<CompiledOperationV1, CompilationErrorV1> {
        if operation.scope != self.scope
            || operation.own != q.own
            || operation.incoming != q.incoming
            || operation.q.len() != q.keys.len()
            || operation
                .q
                .iter()
                .zip(&q.keys)
                .any(|(a, b)| a.original != b.original || !equal(&a.metadata, &b.metadata))
        {
            return Err(CompilationErrorV1::Closure);
        }
        let predecessor = if operation.route.variant == Variant::Bootstrap {
            None
        } else {
            Some(omega.key())
        };
        let closed = self.operation_source(operation.route, q, predecessor, Some(operation))?;
        if closed.context != operation.context {
            return Err(CompilationErrorV1::Closure);
        }
        Ok(closed)
    }

    fn operation_source(
        &mut self,
        route: OperationRoute,
        q: &CompiledQV1,
        omega: Option<&CompiledKeyV1<Ep>>,
        originals: Option<&CompiledOperationV1>,
    ) -> Result<CompiledOperationV1, CompilationErrorV1> {
        if q.scope != self.scope || q.variant != route.variant {
            return Err(CompilationErrorV1::Closure);
        }
        let template = OperationV1 {
            variant: u8::try_from(
                Variant::ALL
                    .iter()
                    .position(|v| *v == route.variant)
                    .ok_or(Error::Inventory)?
                    + 1,
            )
            .map_err(|_| Error::Inventory)?,
            own_class: q.own.clone(),
            incoming_class: q.incoming.clone(),
            context: Vec::new(),
            q: Vec::new(),
            a: Vec::new(),
            w: Vec::new(),
        };
        source(
            operation::require_route(&template, route),
            CompilationPhaseV1::RouteClasses,
        )?;
        let eq = source(PinnedParams::derive(16), CompilationPhaseV1::AParameters)?;
        let ep = source(PinnedParams::derive(16), CompilationPhaseV1::WParameters)?;
        let acfg = config(vec![InstanceType::Bounded], false, self.config);
        let wcfg = config(OmegaPlan::instance_types().to_vec(), true, self.config);
        macro_rules! stages {
            ($plan:expr) => {{
                let plan = $plan;
                if originals.is_some_and(|old| {
                    old.a.len() != plan.context().stage_count()
                        || old.w.len() + 1 != plan.context().stage_count()
                }) {
                    return Err(CompilationErrorV1::Closure);
                }
                let mut previous = None;
                let mut a = Vec::new();
                let mut w = Vec::new();
                for stage in 0..plan.context().stage_count() {
                    let circuit = source(
                        plan.source_circuit(stage, previous.take()),
                        CompilationPhaseV1::ASource,
                    )?;
                    let key = if let Some(old) = originals {
                        self.import(&old.a[stage], &circuit, &eq)?
                    } else {
                        self.key(&circuit, &eq, &acfg)
                            .map_err(|error| stage_error(error, route, stage, false))?
                    };
                    if stage + 1 < plan.context().stage_count() {
                        let circuit = source(
                            plan.wrapper_source(stage, key.metadata.binding(), key.metadata.key()),
                            CompilationPhaseV1::WSource,
                        )?;
                        let wrapper = if let Some(old) = originals {
                            self.import(&old.w[stage], &circuit, &ep)?
                        } else {
                            self.key(&circuit, &ep, &wcfg)
                                .map_err(|error| stage_error(error, route, stage, true))?
                        };
                        previous = Some(source(
                            WKey::from_artifact(
                                plan.context(),
                                stage,
                                wrapper.metadata.binding().clone(),
                                ep.clone(),
                                wrapper.metadata.key().clone(),
                            ),
                            CompilationPhaseV1::WIdentity,
                        )?);
                        w.push(wrapper);
                    }
                    a.push(key);
                }
                (
                    plan.context()
                        .schema()
                        .iter()
                        .map(PrimeField::to_repr)
                        .collect(),
                    a,
                    w,
                )
            }};
        }
        let (context, a, w) = if route.variant == Variant::Bootstrap {
            if omega.is_some() {
                return Err(CompilationErrorV1::Closure);
            }
            stages!(source(
                bootstrap::plan(self.scope, &q.recipe),
                CompilationPhaseV1::BootstrapRecipe
            )?)
        } else {
            let key = omega.ok_or(CompilationErrorV1::Closure)?;
            let plan = source(
                operation::plan(route, self.scope, &q.recipe, &key.metadata),
                CompilationPhaseV1::OperationRecipe,
            )?;
            match plan {
                operation::Plan::Load(p) => stages!(p),
                operation::Plan::Send(p) => stages!(p),
                operation::Plan::Receive(p) => stages!(p),
                operation::Plan::Archive(p) => stages!(p),
                operation::Plan::Consuming(p) => stages!(p),
                operation::Plan::Refresh(p) => stages!(p),
            }
        };
        Ok(CompiledOperationV1 {
            scope: self.scope,
            route,
            own: q.own.clone(),
            incoming: q.incoming.clone(),
            context,
            q: q.keys.clone(),
            a,
            w,
            predecessor: omega.map(|k| k.metadata.clone()),
        })
    }

    /// Build the one compiled compact Omega source from exact ordered terminal keys.
    /// # Errors
    /// Nonuniform/duplicate/over-capacity catalog or any original import failure.
    pub fn omega(
        &mut self,
        terminals: &[&CompiledKeyV1<Eq>],
    ) -> Result<CompiledOmegaV1, CompilationErrorV1> {
        let first = terminals.first().ok_or(CompilationErrorV1::Closure)?;
        if terminals.len() > 32
            || terminals.iter().enumerate().any(|(i, k)| {
                k.metadata.binding() != first.metadata.binding()
                    || terminals[..i]
                        .iter()
                        .any(|old| equal(&old.metadata, &k.metadata))
            })
        {
            return Err(CompilationErrorV1::Closure);
        }
        let ep = source(
            PinnedParams::derive(16),
            CompilationPhaseV1::OmegaParameters,
        )?;
        let eq = source(
            PinnedParams::derive(16),
            CompilationPhaseV1::OmegaParameters,
        )?;
        let program = source(
            outer::Program::for_compiled_catalog(
                first.metadata.binding().encoded(),
                &terminals
                    .iter()
                    .map(|k| k.metadata.key().to_bytes().to_vec())
                    .collect::<Vec<_>>(),
                eq,
                ep.clone(),
            ),
            CompilationPhaseV1::OmegaLayout,
        )?;
        let key = self.key(
            &source(program.source_circuit(), CompilationPhaseV1::OmegaSource)?,
            &ep,
            &config(OmegaPlan::instance_types().to_vec(), true, self.config),
        )?;
        Ok(CompiledOmegaV1 {
            key,
            terminals: terminals.iter().map(|k| k.metadata.clone()).collect(),
        })
    }
}

#[path = "compiler/classes.rs"]
mod classes;
pub use classes::{QClassesV1, q_classes};
#[path = "compiler/closure.rs"]
mod closure;
#[path = "compiler/complete.rs"]
mod complete;

#[cfg(test)]
#[path = "compiler/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "compiler/full_catalog.rs"]
mod full_catalog;
#[cfg(test)]
pub(crate) use full_catalog::{
    open_pinned_engineering_finality_sources, open_pinned_engineering_wallet_sources,
};

#[path = "compiler/reuse.rs"]
mod reuse;
