//! Bounded storage failures and real offline construction without signed placeholders.

use super::*;
use ff::Field;
use iroha_pasta::{PastaField, msm::MemoryBudget};
use iroha_plonk::{
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Error as LayoutError, Layouter, SimpleFloorPlanner},
};
use iroha_plonk_gadgets::{GlueChip, GlueConfig, p256::native::Affine};
use std::io::Cursor;

#[derive(Default)]
struct Memory {
    blobs: BTreeMap<[u8; 32], Vec<u8>>,
    corrupt: bool,
    reads: usize,
}
impl OriginalSourceV1 for Memory {
    fn open(&mut self, sha256: [u8; 32]) -> Result<Box<dyn std::io::Read + '_>, Error> {
        self.reads += 1;
        let mut bytes = self.blobs.get(&sha256).ok_or(Error::Inventory)?.clone();
        if self.corrupt {
            bytes[0] ^= 1;
        }
        Ok(Box::new(Cursor::new(bytes)))
    }
}
impl OriginalSinkV1 for Memory {
    fn store(&mut self, identity: BlobV1, bytes: &[u8]) -> Result<(), Error> {
        if BlobV1::of(bytes) != identity
            || self
                .blobs
                .get(&identity.sha256)
                .is_some_and(|old| old != bytes)
        {
            return Err(Error::Inventory);
        }
        self.blobs.insert(identity.sha256, bytes.to_vec());
        Ok(())
    }
}
pub(super) fn limits() -> ReadConfig {
    ReadConfig {
        maximum_bytes: 1 << 28,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    }
}
fn scope() -> SourceScopeV1 {
    SourceScopeV1::new([1, 2], Affine::GENERATOR).unwrap()
}

#[test]
fn compiler_parameter_owners_reuse_exact_bases_and_keep_domains_separate() {
    let mut cache = BTreeMap::<u32, PinnedParams<Ep>>::new();
    let first = parameters(&mut cache, 6, CompilationPhaseV1::QParameters).unwrap();
    let again = parameters(&mut cache, 6, CompilationPhaseV1::WParameters).unwrap();
    assert!(core::ptr::eq(
        first.params().g_lagrange().as_ptr(),
        again.params().g_lagrange().as_ptr()
    ));
    let larger = parameters(&mut cache, 7, CompilationPhaseV1::WParameters).unwrap();
    assert_eq!(first.k(), 6);
    assert_eq!(larger.k(), 7);
    assert_ne!(first.digest(), larger.digest());
    assert!(parameters(&mut cache, u32::MAX, CompilationPhaseV1::QParameters).is_err());
    assert_eq!(cache.len(), 2);
}

#[derive(Clone)]
pub(super) struct Tiny<F: PastaField>(pub(super) F);
impl<F: PastaField> Circuit<F> for Tiny<F> {
    type Config = (GlueConfig, Column<Instance>);
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advice = core::array::from_fn(|_| meta.advice_column());
        let fixed = meta.fixed_column();
        let glue = GlueConfig::configure(meta, advice, fixed);
        let public = meta.instance_column(1);
        meta.enable_equality(public);
        (glue, public)
    }
    fn synthesize(
        &self,
        (glue, public): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), LayoutError> {
        let word = layouter.assign_region(
            || "offline original identity",
            |mut region| GlueChip::new(glue).constant(&mut region, self.0),
        )?;
        layouter.constrain_instance(word.cell(), public, 0)
    }
}

#[test]
fn offline_publication_checks_limits_hashes_and_exact_source_after_storage() {
    let mut disk = Memory::default();
    let mut cfg = limits();
    cfg.maximum_bytes = 0;
    assert!(OfflineCompilerV1::new(scope(), &mut disk, cfg, 1 << 30).is_err());
    cfg = limits();
    cfg.maximum_rows = 1 << 15;
    assert!(OfflineCompilerV1::new(scope(), &mut disk, cfg, 1 << 30).is_err());
    cfg = limits();
    cfg.coset_cache = CosetCachePolicy::Eager;
    assert!(OfflineCompilerV1::new(scope(), &mut disk, cfg, 1 << 30).is_err());
    assert!(OfflineCompilerV1::new(scope(), &mut disk, limits(), 0).is_err());
    let params = PinnedParams::<Ep>::derive(8).unwrap();
    let key_config = config(vec![InstanceType::Bounded], false, limits());
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 1 << 30).unwrap();
    let a = compiler.key(&Tiny(Fq::ONE), &params, &key_config).unwrap();
    let total = compiler.bytes;
    let again = compiler.key(&Tiny(Fq::ONE), &params, &key_config).unwrap();
    assert_eq!(a.original, again.original);
    assert_eq!(compiler.bytes, total);
    let other = compiler
        .key(&Tiny(Fq::from(2)), &params, &key_config)
        .unwrap();
    assert_eq!(a.metadata.binding(), other.metadata.binding());
    assert!(!equal(&a.metadata, &other.metadata));
    assert!(compiler.bytes > total);
    drop(compiler);
    assert_eq!(disk.reads, 9);
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 1 << 30).unwrap();
    assert_eq!(
        compiler
            .import(&a, &Tiny(Fq::ONE), &params)
            .unwrap()
            .original,
        a.original
    );
    assert!(compiler.import(&a, &Tiny(Fq::from(2)), &params).is_err());
    drop(compiler);
    disk.corrupt = true;
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 1 << 30).unwrap();
    assert!(compiler.key(&Tiny(Fq::ONE), &params, &key_config).is_err());
    drop(compiler);
    disk.corrupt = false;
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 1).unwrap();
    assert!(compiler.key(&Tiny(Fq::ONE), &params, &key_config).is_err());
    assert_eq!(compiler.bytes, 0);
}

#[test]
fn offline_publication_uses_compact_original_byte_limit() {
    let params = PinnedParams::<Ep>::derive(8).unwrap();
    let source = Tiny(Fq::ONE);
    let key_config = config(vec![InstanceType::Bounded], false, limits());
    let generated = keygen_pk_v2(&params, &source, &key_config).unwrap();
    let original = generated.artifact_bytes_v2().unwrap();
    assert_eq!(original.len(), 108 + generated.vk().to_bytes().len());
    let mut read = limits();
    read.maximum_bytes = original.len();
    let mut disk = Memory::default();
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, read, 1 << 30).unwrap();
    let compiled = compiler.key(&source, &params, &key_config).unwrap();
    assert_eq!(compiled.original.proving_key, BlobV1::of(&original));
    assert_eq!(
        compiled.metadata.key().to_bytes(),
        generated.vk().to_bytes()
    );
    drop(compiler);
    read.maximum_bytes -= 1;
    let mut rejected = Memory::default();
    let mut compiler = OfflineCompilerV1::new(scope(), &mut rejected, read, 1 << 30).unwrap();
    assert!(compiler.key(&source, &params, &key_config).is_err());
    assert_eq!(compiler.bytes, 0);
    assert!(compiler.blobs.is_empty());
}

struct Disk(tempfile::TempDir);
impl OriginalSourceV1 for Disk {
    fn open(&mut self, sha256: [u8; 32]) -> Result<Box<dyn std::io::Read + '_>, Error> {
        Ok(Box::new(
            std::fs::File::open(self.0.path().join(hex::encode(sha256)))
                .map_err(|_| Error::Inventory)?,
        ))
    }
}
impl OriginalSinkV1 for Disk {
    fn store(&mut self, identity: BlobV1, bytes: &[u8]) -> Result<(), Error> {
        if BlobV1::of(bytes) != identity {
            return Err(Error::Inventory);
        }
        let path = self.0.path().join(hex::encode(identity.sha256));
        if path.exists() {
            if std::fs::read(path).map_err(|_| Error::Inventory)? != bytes {
                return Err(Error::Inventory);
            }
        } else {
            std::fs::write(path, bytes).map_err(|_| Error::Inventory)?;
        }
        Ok(())
    }
}

#[test]
fn monetary_descriptor_classes_keep_complete_routes_within_terminal_capacity() {
    // Use the compiler's actual monetary recipe and compressed descriptors, without
    // generating any keys. Equal dimensions alone would not establish a Q class.
    let descriptors: BTreeMap<_, _> = (2_u8..7)
        .map(|selector| {
            let shape = sigma::monetary_shape(usize::from(selector)).unwrap();
            (selector, shape.descriptor::<Eq>().unwrap())
        })
        .collect();
    let groups = |selectors: std::ops::RangeInclusive<u8>| {
        let mut groups: Vec<Vec<u8>> = Vec::new();
        for selector in selectors {
            if let Some(group) = groups
                .iter_mut()
                .find(|group| descriptors[&group[0]] == descriptors[&selector])
            {
                group.push(selector);
            } else {
                groups.push(vec![selector]);
            }
        }
        groups
    };
    let send = groups(2..=5);
    let receive = groups(6..=6);
    // The quota control selects k14; the lease adds no source structure.
    assert_eq!(send, [vec![2, 4], vec![3, 5]]);
    assert_eq!(receive, [vec![6]]);

    let representative = |selector| {
        send.iter()
            .chain(&receive)
            .find(|group| group.contains(&selector))
            .map_or(selector, |group| group[0])
    };
    let routes = compiled_routes();
    assert_eq!(routes.len(), 22);
    let mut classes = Vec::new();
    for route in routes {
        let class = (
            route.variant,
            representative(route.own),
            route.incoming.map(representative),
        );
        if !classes.contains(&class) {
            classes.push(class);
        }
    }
    // A fixed variant/Q class shares its blank A/W sources. Send's route mask
    // selects native witness checks, but is absent from those source circuits.
    // Thus one terminal per class is an upper bound, not a count of proven keys.
    // Receive and ReceiveRenewed remain separate variants in the actual product.
    assert_eq!(
        classes.len(),
        9 + send.len() + 2 * receive.len() * send.len() + receive.len()
    );
    assert!(classes.len() <= 32, "complete routes exceed Omega capacity");
}

#[test]
#[ignore = "real11 sigma +Q +Bootstrap A +Omega original construction; optimized explicit component run"]
fn real_bootstrap_offline_construction_needs_no_signed_placeholder_or_qualified_marker() {
    let mut disk = Disk(tempfile::tempdir().unwrap());
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 4 << 30).unwrap();
    let sigmas = compiler.sigmas().unwrap();
    let classes = q_classes(Variant::Send, &sigmas);
    assert!(
        classes.len() >= 2,
        "actual k12/k14 descriptors remain distinct"
    );
    for class in &classes {
        let first = sigmas.keys()[usize::from(class.own[0])].metadata.binding();
        assert!(
            class
                .own
                .iter()
                .all(|s| sigmas.keys()[usize::from(*s)].metadata.binding() == first)
        );
    }
    for variant in Variant::ALL {
        let classes = q_classes(variant, &sigmas);
        for route in compiled_routes()
            .into_iter()
            .filter(|r| r.variant == variant)
        {
            assert_eq!(
                classes
                    .iter()
                    .filter(|c| c.own.contains(&route.own)
                        && route.incoming.is_none_or(|i| c.incoming.contains(&i)))
                    .count(),
                1
            );
        }
    }
    // Lean Bootstrap proves its own step inline: one signature Q and one unsplit A.
    let q = compiler.q(Variant::Bootstrap, &[0], &[], &sigmas).unwrap();
    assert_eq!(q.keys().len(), 1);
    let route = compiled_routes()[0];
    let operation = compiler.operation(route, &q, None).unwrap();
    assert_eq!(operation.stages(), 1);
    assert!(operation.w.is_empty());
    let omega = compiler.omega(&[operation.terminal()]).unwrap();
    let closed = compiler.close_operation(&operation, &q, &omega).unwrap();
    assert_eq!(closed.context, operation.context);
    assert_eq!(closed.terminal().original, operation.terminal().original);
    let mut changed = operation.clone();
    changed.context[0][0] ^= 1;
    assert!(compiler.close_operation(&changed, &q, &omega).is_err());
    let mut changed = operation.clone();
    changed.a.push(changed.a[0].clone());
    assert!(compiler.close_operation(&changed, &q, &omega).is_err());
    let retiring_q = compiler.q(Variant::Retiring, &[10], &[], &sigmas).unwrap();
    let retiring_route = compiled_routes()
        .into_iter()
        .find(|route| route.variant == Variant::Retiring)
        .unwrap();
    let retiring = compiler
        .operation(retiring_route, &retiring_q, Some(omega.key()))
        .unwrap();
    // Lean Retiring is one terminal A beside the hard predecessor; no W follows it.
    assert_eq!(retiring.stages(), 1);
    assert!(retiring.w.is_empty());
    let final_omega = compiler
        .omega(&[operation.terminal(), retiring.terminal()])
        .unwrap();
    assert_eq!(
        omega.key.metadata.binding(),
        final_omega.key.metadata.binding()
    );
    assert!(!equal(&omega.key.metadata, &final_omega.key.metadata));
    let closed_retiring = compiler
        .close_operation(&retiring, &retiring_q, &final_omega)
        .unwrap();
    assert!(equal(
        closed_retiring.predecessor.as_ref().unwrap(),
        &final_omega.key.metadata
    ));
    assert_eq!(closed_retiring.context, retiring.context);
    assert_eq!(closed_retiring.a.len(), retiring.a.len());
    assert_eq!(closed_retiring.w.len(), retiring.w.len());
    for (old, new) in retiring.a.iter().zip(&closed_retiring.a) {
        assert_eq!(old.original, new.original);
        assert!(equal(&old.metadata, &new.metadata));
    }
    for (old, new) in retiring.w.iter().zip(&closed_retiring.w) {
        assert_eq!(old.original, new.original);
        assert!(equal(&old.metadata, &new.metadata));
    }
    let closed_bootstrap = compiler
        .close_operation(&operation, &q, &final_omega)
        .unwrap();
    assert!(closed_bootstrap.predecessor.is_none());
    eprintln!(
        "OFFLINE_FINAL_OMEGA_REBIND terminals=2 RetiringA=1 RetiringW=0 exact_originals=true changed_omega_key=true context_unchanged=true complete_catalog=false"
    );
    assert!(
        compiler
            .inventory(&sigmas, std::slice::from_ref(&operation), &omega)
            .is_err(),
        "one genuine route cannot become the complete unsigned catalog"
    );
    assert!(
        compiler
            .omega(&[operation.terminal(), operation.terminal()])
            .is_err()
    );
    let mut foreign = q;
    foreign.scope = SourceScopeV1::new([2, 3], Affine::GENERATOR).unwrap();
    assert!(compiler.operation(route, &foreign, None).is_err());
    assert!(
        compiler
            .operation(route, &foreign, Some(omega.key()))
            .is_err()
    );
    eprintln!(
        "OFFLINE_BOOTSTRAP_SOURCE sigma=11 Q=1 A=1 W=0 Omega=1 signed_placeholder=false original_imports=true complete_catalog=false"
    );
}

fn indexed_original_reuse<C: PastaCurve>() {
    let mut disk = Memory::default();
    let params = PinnedParams::<C>::derive(8).unwrap();
    let cfg = config(vec![InstanceType::Bounded], false, limits());
    let circuit = Tiny(C::ScalarExt::ONE);
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 1 << 30).unwrap();
    let first = compiler.key(&circuit, &params, &cfg).unwrap();
    let changed = compiler
        .key(&Tiny(C::ScalarExt::from(2)), &params, &cfg)
        .unwrap();
    let total = compiler.bytes;
    drop(compiler);
    let short_vk = first.metadata.key().to_bytes()[..16].to_vec();
    let short_blob = BlobV1::of(&short_vk);
    disk.store(short_blob, &short_vk).unwrap();
    let retained_count = disk.blobs.len();
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 1 << 30).unwrap();
    let mut truncated = first.original;
    truncated.verifying_key = short_blob;
    assert!(compiler.index_original(truncated).is_err());
    compiler.index_original(first.original).unwrap();
    compiler.index_original(changed.original).unwrap();
    assert_eq!(
        compiler.bytes, 0,
        "index alone admits and accounts no selected source"
    );
    let imported = compiler.key(&circuit, &params, &cfg).unwrap();
    assert_eq!(imported.original, first.original);
    assert!(equal(&imported.metadata, &first.metadata));
    let selected = compiler.bytes;
    assert_eq!(
        compiler.key(&circuit, &params, &cfg).unwrap().original,
        first.original
    );
    assert_eq!(compiler.bytes, selected);
    assert_eq!(
        compiler
            .key(&Tiny(C::ScalarExt::from(2)), &params, &cfg)
            .unwrap()
            .original,
        changed.original
    );
    assert_eq!(compiler.bytes, total);
    // An adversarial lookup result cannot substitute another fixed-table source
    // even when its descriptor is identical and all its own hashes are valid.
    assert_eq!(first.metadata.binding(), changed.metadata.binding());
    let identity = iroha_plonk::keys::source_fingerprint_v2(&params, &circuit, &cfg, None).unwrap();
    compiler
        .candidates
        .insert(*identity.digest(), changed.original);
    assert!(compiler.key(&circuit, &params, &cfg).is_err());
    drop(compiler);
    assert_eq!(disk.blobs.len(), retained_count);
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 1).unwrap();
    compiler.index_original(first.original).unwrap();
    assert!(compiler.key(&circuit, &params, &cfg).is_err());
    assert_eq!(compiler.bytes, 0);
    assert!(compiler.blobs.is_empty());
    let indexed = compiler.candidates.clone();
    drop(compiler);
    disk.corrupt = true;
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 1 << 30).unwrap();
    compiler.candidates = indexed;
    assert!(compiler.key(&circuit, &params, &cfg).is_err());
    assert_eq!(compiler.bytes, 0);
    assert!(compiler.index_original(first.original).is_err());
}

#[test]
fn indexed_original_reuse_requires_complete_source_import_on_both_curves() {
    indexed_original_reuse::<Ep>();
    indexed_original_reuse::<Eq>();
}

fn changed_source_regenerates<C: PastaCurve>() {
    let mut disk = Memory::default();
    let params = PinnedParams::<C>::derive(8).unwrap();
    let cfg = config(vec![InstanceType::Bounded], false, limits());
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 1 << 30).unwrap();
    let previous = compiler
        .key(&Tiny(C::ScalarExt::ONE), &params, &cfg)
        .unwrap();
    drop(compiler);
    let count = disk.blobs.len();
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 1 << 30).unwrap();
    compiler.index_original(previous.original).unwrap();
    let changed = compiler
        .key(&Tiny(C::ScalarExt::from(3)), &params, &cfg)
        .unwrap();
    assert_ne!(changed.original, previous.original);
    drop(compiler);
    assert!(disk.blobs.len() > count);
}

#[test]
fn indexed_original_reuse_regenerates_changed_source_on_both_curves() {
    changed_source_regenerates::<Ep>();
    changed_source_regenerates::<Eq>();
}

/// Rows of the most-used advice column and that column, laid out at k18 so an
/// overflowing stage still reports its size.
fn advice_rows<F: PastaField, C: Circuit<F>>(circuit: &C) -> (usize, usize) {
    let assigned = iroha_plonk::frontend::synthesize(circuit, 18, None).unwrap();
    assigned
        .tables
        .advice_assigned()
        .iter()
        .map(|column| {
            column
                .iter()
                .rposition(|assigned| *assigned)
                .map_or(0, |row| row + 1)
        })
        .enumerate()
        .max_by_key(|(_, rows)| *rows)
        .map(|(column, rows)| (rows, column))
        .unwrap()
}

#[test]
#[ignore = "real11 sigma, one Q per class, Bootstrap A and a one-key Omega; lays out every class's predecessor stage at k18; optimized explicit run"]
fn every_predecessor_stage_fits_k16_against_the_real_omega() {
    // The A stage that binds the hard predecessor witnesses the Omega key and verifies
    // its proof in circuit, so its size depends on the real Omega descriptor. A
    // layout-only stand-in undercounts it: the two-stage Send A1 fit against one and
    // overflowed production key generation. Omega's descriptor does not depend on its
    // catalog, so one Bootstrap terminal suffices.
    const USABLE: usize = 65_529;
    let mut disk = Disk(tempfile::tempdir().unwrap());
    let mut compiler = OfflineCompilerV1::new(scope(), &mut disk, limits(), 4 << 30).unwrap();
    let sigmas = compiler.sigmas().unwrap();
    let q = compiler.q(Variant::Bootstrap, &[0], &[], &sigmas).unwrap();
    let bootstrap = compiler.operation(compiled_routes()[0], &q, None).unwrap();
    let omega = compiler.omega(&[bootstrap.terminal()]).unwrap();
    let pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta = PinnedParams::<Eq>::derive(16).unwrap();
    let mut overflowing = Vec::new();
    for variant in Variant::ALL {
        if variant == Variant::Bootstrap {
            continue;
        }
        // One route per Q class: a class shares its A/W sources.
        for class in q_classes(variant, &sigmas) {
            let route = compiled_routes()
                .into_iter()
                .find(|route| {
                    route.variant == variant
                        && class.own.contains(&route.own)
                        && route
                            .incoming
                            .is_none_or(|incoming| class.incoming.contains(&incoming))
                })
                .unwrap();
            let q = compiler
                .q(variant, &class.own, &class.incoming, &sigmas)
                .unwrap();
            let plan = operation::plan_with_parameters(
                route,
                scope(),
                q.recipe(),
                omega.key().metadata(),
                pallas.clone(),
                vesta.clone(),
            )
            .unwrap();
            let (rows, column) = match &plan {
                operation::Plan::Load(plan) => advice_rows(&plan.source_circuit().unwrap()),
                operation::Plan::Consuming(plan) => advice_rows(&plan.source_circuit().unwrap()),
                operation::Plan::Send(plan) => advice_rows(&plan.source_circuit(0, None).unwrap()),
                operation::Plan::Receive(plan) => {
                    advice_rows(&plan.source_circuit(0, None).unwrap())
                }
                operation::Plan::Archive(plan) => {
                    advice_rows(&plan.source_circuit(0, None).unwrap())
                }
                operation::Plan::Refresh(plan) => {
                    advice_rows(&plan.source_circuit(0, None).unwrap())
                }
            };
            eprintln!(
                "REAL_OMEGA_PREDECESSOR_STAGE {route:?} stages={} rows={rows} column={column} usable={USABLE} margin={} over={}",
                plan.context().stage_count(),
                USABLE.saturating_sub(rows),
                rows.saturating_sub(USABLE),
            );
            if rows >= USABLE {
                overflowing.push((route, rows));
            }
        }
    }
    assert!(
        overflowing.is_empty(),
        "predecessor stages exceed k16: {overflowing:?}"
    );
}
