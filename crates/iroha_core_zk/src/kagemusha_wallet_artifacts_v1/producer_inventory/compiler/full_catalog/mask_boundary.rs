//! Exact mask predicates on strictly imported Omega/sigma and private Q/A/W originals.
//!
//! Strict import enforces the sole native `keys::masking` predicate. This
//! diagnostic binds captured rows to exact originals and delegates every mask,
//! rank and pivot check to that owner. It does not establish recursive security
//! or the full causal wallet privacy statement.

use std::collections::{BTreeMap, BTreeSet};

use ff::PrimeField;
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaCurve, PastaField};
use iroha_plonk::{
    DescriptorBinding, Protocol,
    cs::{
        CircuitDescriptorV1, CircuitDescriptorV2, DescriptorConfig, InstanceType, TranscriptV1,
        descriptor::{CurveV1, InstanceModeV1, ProofSuffixV1},
        descriptor_v2::{ProtocolDescriptor, TranscriptV2},
    },
    frontend::{Circuit, synthesize},
    keys::{ProvingKey, SourceBoundVerifyingKeyV2, VerifyingKey, pk::artifact::ReadConfig},
    pcs::{curve_v1, ipa::PinnedParams},
};

use super::{
    ARTIFACT_MAX_COUNT_V1, BlobV1, DESCRIPTOR_MAX_BYTES_V1, OriginalSourceV1, OriginalV1,
    ProducerInventoryV1, VERIFYING_KEY_MAX_BYTES_V1, read,
};

type Check<T> = Result<T, String>;

trait MaskField: PastaField {
    const NAME: &'static str;
    const CURVE: CurveV1;
}
impl MaskField for Fp {
    const NAME: &'static str = "Fp";
    const CURVE: CurveV1 = CurveV1::Vesta;
}
impl MaskField for Fq {
    const NAME: &'static str = "Fq";
    const CURVE: CurveV1 = CurveV1::Pallas;
}

type Row<F = Fq> = iroha_plonk::keys::masking::PublicRow<F>;

fn canonical<F: MaskField>(bytes: [u8; 32]) -> Check<F> {
    Option::from(F::from_repr(bytes)).ok_or_else(|| format!("noncanonical {}", F::NAME))
}

fn dimensions<F: MaskField>(descriptor: &ProtocolDescriptor) -> Check<(usize, usize)> {
    if descriptor.curve != F::CURVE {
        return Err("mask scalar field differs from descriptor".into());
    }
    let n = 1_usize
        .checked_shl(u32::from(descriptor.k))
        .ok_or("domain size")?;
    let usable = n
        .checked_sub(usize::from(descriptor.blinding_factors) + 1)
        .filter(|usable| *usable > 1)
        .ok_or("usable rows")?;
    if u32::from(descriptor.k) > F::S {
        return Err("field domain size".into());
    }
    Ok((n, usable))
}

// The collector is reachable only in cfg(test) compiler builds and is explicitly
// enabled by the complete-catalogue test. It holds at most 64 MiB of scalar cells
// and at most 262,144 rows, with the inventory's original count cap. These are
// retained-cell/count limits, not total process RSS. No proving key is retained.
const MAX_CAPTURE_BYTES: usize = 64 << 20;
const MAX_CAPTURE_ROWS: usize = 1 << 18;

#[derive(Debug)]
struct EncodedRow {
    fixed: Vec<[u8; 32]>,
    sigma: Vec<[u8; 32]>,
}

struct CapturedOriginal {
    identity: OriginalV1,
    rows: BTreeMap<usize, EncodedRow>,
}

#[derive(Default)]
pub(in super::super) struct ImportedRows {
    originals: BTreeMap<[u8; 32], CapturedOriginal>,
    bytes: usize,
    rows: usize,
}

impl ImportedRows {
    pub(in super::super) fn contains(&self, original: OriginalV1) -> bool {
        self.originals
            .get(&original.proving_key.sha256)
            .is_some_and(|captured| captured.identity == original)
    }

    pub(in super::super) fn import<C: PastaCurve, S: Circuit<C::ScalarExt>>(
        &mut self,
        original: OriginalV1,
        bytes: &[u8],
        binding: &DescriptorBinding,
        params: &PinnedParams<C>,
        circuit: &S,
        config: ReadConfig,
    ) -> Check<SourceBoundVerifyingKeyV2<C>> {
        if original.descriptor != BlobV1::of(binding.encoded())
            || original.proving_key != BlobV1::of(bytes)
            || self.originals.contains_key(&original.proving_key.sha256)
            || self.originals.len() >= ARTIFACT_MAX_COUNT_V1
            || bytes.len() > config.maximum_bytes
            || binding.n() > config.maximum_rows
        {
            return Err("compact source capture identity/count".into());
        }
        let d = binding.descriptor();
        let selected = iroha_plonk::keys::masking::required_rows(binding)
            .map_err(|error| error.to_string())?
            .public;
        let total_rows = self
            .rows
            .checked_add(selected.len())
            .filter(|count| *count <= MAX_CAPTURE_ROWS)
            .ok_or("capture row budget")?;
        let columns = (d.num_fixed_columns as usize)
            .checked_add(d.permutation.len())
            .ok_or("capture columns")?;
        let size = selected
            .len()
            .checked_mul(columns)
            .and_then(|cells| cells.checked_mul(32))
            .ok_or("capture extent")?;
        let total = self
            .bytes
            .checked_add(size)
            .filter(|v| *v <= MAX_CAPTURE_BYTES)
            .ok_or("capture byte budget")?;
        // This is the ordinary strict source and commitment importer. It is the
        // only authority for reconstructed evaluations; compact bytes contain no
        // tables. Metadata is derived from this same admitted key, avoiding a
        // second commitment import. The owned PK retires at this call's end.
        let key = ProvingKey::from_masked_artifact_v2(bytes, binding, params, circuit, config)
            .map_err(|error| error.to_string())?;
        if original.verifying_key != BlobV1::of(&key.vk().to_bytes()) {
            return Err("compact source capture exact VK".into());
        }
        let rows = selected
            .into_iter()
            .map(|row| {
                (
                    row,
                    EncodedRow {
                        fixed: key
                            .fixed_values()
                            .iter()
                            .map(|column| column[row].to_repr())
                            .collect(),
                        sigma: key
                            .permutation_values()
                            .iter()
                            .map(|column| column[row].to_repr())
                            .collect(),
                    },
                )
            })
            .collect();
        let admitted = SourceBoundVerifyingKeyV2::from_proving_key(&key, None)
            .map_err(|error| error.to_string())?;
        self.originals.insert(
            original.proving_key.sha256,
            CapturedOriginal {
                identity: original,
                rows,
            },
        );
        self.bytes = total;
        self.rows = total_rows;
        Ok(admitted)
    }

    pub(super) fn require_inventory(&self, inventory: &ProducerInventoryV1) -> Check<()> {
        if inventory
            .originals
            .iter()
            .any(|original| !self.contains(*original))
        {
            return Err("missing exact inventory source rows".into());
        }
        Ok(())
    }

    fn artifact_rows<F: MaskField>(
        &self,
        original: &[u8],
        binding: &DescriptorBinding,
        verifying_key: &[u8],
    ) -> Check<BTreeMap<usize, Row<F>>> {
        let descriptor = binding.descriptor();
        let _ = dimensions::<F>(descriptor)?;
        let identity = OriginalV1 {
            descriptor: BlobV1::of(binding.encoded()),
            verifying_key: BlobV1::of(verifying_key),
            proving_key: BlobV1::of(original),
        };
        let captured = self
            .originals
            .get(&identity.proving_key.sha256)
            .filter(|captured| captured.identity == identity)
            .ok_or("missing exact compact source capture")?;
        let expected = iroha_plonk::keys::masking::required_rows(binding)
            .map_err(|error| error.to_string())?
            .public;
        if captured.rows.keys().copied().collect::<BTreeSet<_>>() != expected {
            return Err("missing or substituted public closure rows".into());
        }
        captured
            .rows
            .iter()
            .map(|(&row, values)| {
                if values.fixed.len() != descriptor.num_fixed_columns as usize
                    || values.sigma.len() != descriptor.permutation.len()
                {
                    return Err("captured row column extent".into());
                }
                Ok((
                    row,
                    Row {
                        fixed: values
                            .fixed
                            .iter()
                            .copied()
                            .map(canonical)
                            .collect::<Check<_>>()?,
                        sigma: values
                            .sigma
                            .iter()
                            .copied()
                            .map(canonical)
                            .collect::<Check<_>>()?,
                    },
                ))
            })
            .collect()
    }
}

fn assert_opening_mask(binding: &DescriptorBinding, role: &str) {
    let protocol = Protocol::new(binding.descriptor()).expect("actual protocol");
    let shape = protocol.shape();
    let rows = iroha_plonk::keys::masking::report(binding).expect("mandatory native masking plan");
    for row in rows {
        eprintln!("PUBLIC_MASK_PLAN role={role} {row}");
    }
    let fresh_scalar_draw_cap = 2 * shape.n
        + shape.num_advice * (shape.blinding_factors + 2)
        + 2 * shape.lookups * (shape.blinding_factors + 2)
        + (shape.permutation_sets + shape.lookups) * (shape.blinding_factors + 1)
        + shape.quotient_pieces
        + 2 * shape.k as usize
        + 3;
    let fresh_blinded_points = shape.num_advice
        + 3 * shape.lookups
        + shape.permutation_sets
        + shape.quotient_pieces
        + 2 * shape.k as usize
        + 3;
    eprintln!(
        "PUBLIC_MASK_SHAPE role={role} n={} b={} degree={} proof_bytes={} groups={} fresh_scalar_draw_cap={fresh_scalar_draw_cap} fresh_blinded_points={fresh_blinded_points} total_challenge_map=true support_and_rank_checked=true C12_closed=false",
        shape.n,
        shape.blinding_factors,
        shape.degree,
        protocol.proof_length(),
        protocol.plan().sets().len()
    );
}

// Derive the complete expected descriptor from the maintained source, including
// actual selector activations/compression. Historical degree/column counts do not
// identify a source. This does no key generation and grants no source authority.
fn source_descriptor<C: PastaCurve, S: Circuit<C::ScalarExt>>(
    circuit: &S,
    k: u32,
    instance_types: Vec<InstanceType>,
) -> Check<DescriptorBinding> {
    let synthesized = synthesize(circuit, k, None).map_err(|error| error.to_string())?;
    let finalized = synthesized
        .cs
        .finalize(synthesized.tables.selectors(), true)
        .map_err(|error| error.to_string())?;
    let layout = CircuitDescriptorV1::from_constraint_system(
        &finalized,
        DescriptorConfig {
            curve: curve_v1::<C>().ok_or("unsupported source curve")?,
            k,
            transcript: TranscriptV1::Blake2bChallenge255,
            instance_mode: InstanceModeV1::Direct,
            proof_suffix: ProofSuffixV1::FoldedGenerator,
        },
    )
    .map_err(|error| error.to_string())?;
    let descriptor = CircuitDescriptorV2::from_layout(
        layout,
        TranscriptV2::KagemushaPoseidonRp57Base,
        instance_types,
    )
    .map_err(|error| error.to_string())?;
    DescriptorBinding::new_v2(descriptor).map_err(|error| error.to_string())
}

fn require_source_descriptor(
    actual: &DescriptorBinding,
    expected: &DescriptorBinding,
) -> Check<()> {
    if actual.encoded() != expected.encoded() {
        return Err("descriptor differs from current source".into());
    }
    Ok(())
}

fn sigma_source_descriptor(selector: usize) -> Check<DescriptorBinding> {
    use iroha_kagemusha_proof::{
        SigmaCircuit,
        admin_sigma::{BootstrapCircuit, native::*},
    };
    let types = BootstrapCircuit::instance_types().to_vec();
    macro_rules! administrative {
        ($owner:ty) => {
            source_descriptor::<Eq, _>(&<$owner>::source_circuit(), 12, types)
        };
    }
    match selector {
        0 => administrative!(BootstrapProver),
        1 => administrative!(LoadProver),
        12 => administrative!(ArchiveProver),
        13 => administrative!(UnloadProver),
        14 => administrative!(RefreshProver),
        15 => administrative!(RetiringProver),
        2..=11 => {
            let shape =
                super::super::sigma::monetary_shape(selector).map_err(|error| error.to_string())?;
            source_descriptor::<Eq, _>(&SigmaCircuit::<Fp>::keygen(shape.params), shape.k, types)
        }
        _ => Err("unknown sigma selector".into()),
    }
}

fn omega_source_descriptor(
    inventory: &ProducerInventoryV1,
    source: &mut dyn OriginalSourceV1,
) -> Check<DescriptorBinding> {
    use iroha_kagemusha_proof::omega::{OmegaPlan, native::Program};
    let mut descriptor = None;
    let mut keys = Vec::new();
    for &index in &inventory.terminals {
        let original = inventory.member(index).map_err(|error| error.to_string())?;
        let bytes = read(source, original.descriptor, DESCRIPTOR_MAX_BYTES_V1)
            .map_err(|error| error.to_string())?;
        if descriptor
            .as_ref()
            .is_some_and(|expected| *expected != bytes)
        {
            return Err("nonuniform terminal descriptor".into());
        }
        descriptor = Some(bytes);
        keys.push(
            read(source, original.verifying_key, VERIFYING_KEY_MAX_BYTES_V1)
                .map_err(|error| error.to_string())?,
        );
    }
    let program = Program::for_compiled_catalog(
        &descriptor.ok_or("empty terminal catalog")?,
        &keys,
        PinnedParams::<Eq>::derive(16).map_err(|error| error.to_string())?,
        PinnedParams::<Ep>::derive(16).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    source_descriptor::<Ep, _>(
        &program
            .source_circuit()
            .map_err(|error| error.to_string())?,
        16,
        OmegaPlan::instance_types().to_vec(),
    )
}

/// Check every public sigma selector after the same mandatory strict import.
/// This consumes public PK tables only and gives no source-admission shortcut.
pub(super) fn assert_public_sigmas(
    inventory: &ProducerInventoryV1,
    source: &mut dyn OriginalSourceV1,
    captured: &ImportedRows,
) {
    for (selector, index) in inventory.sigma.iter().copied().enumerate() {
        let original = inventory.member(index).expect("public sigma role");
        let bytes = read(source, original.descriptor, DESCRIPTOR_MAX_BYTES_V1).unwrap();
        let binding = DescriptorBinding::decode_v2(&bytes).unwrap();
        let d = binding.descriptor();
        assert_eq!(d.curve, CurveV1::Vesta);
        assert_eq!(d.transcript, TranscriptV2::KagemushaPoseidonRp57Base);
        assert_eq!(d.instance_mode, InstanceModeV1::Direct);
        assert_eq!(d.proof_suffix, ProofSuffixV1::FoldedGenerator);
        assert_eq!(d.instance_lengths, [1]);
        require_source_descriptor(&binding, &sigma_source_descriptor(selector).unwrap()).unwrap();
        assert_eq!(d.blinding_factors, 5);
        let expected_k = if matches!(selector, 4 | 5 | 8 | 9) {
            14
        } else {
            12
        };
        assert_eq!(d.k, expected_k);
        let key = read(source, original.verifying_key, VERIFYING_KEY_MAX_BYTES_V1).unwrap();
        VerifyingKey::<Eq>::read(&key, &binding).unwrap();
        let expected_bytes = key
            .len()
            .checked_add(108)
            .expect("compact public PK extent");
        let proving_key = read(source, original.proving_key, expected_bytes).unwrap();
        let rows = captured
            .artifact_rows::<Fp>(&proving_key, &binding, &key)
            .unwrap();
        iroha_plonk::keys::masking::validate_public_rows(&binding, &rows, None).unwrap();
        assert_opening_mask(&binding, &format!("sigma.{selector}"));
        eprintln!(
            "SIGMA_MASK_BOUNDARY selector={selector} role={index} descriptor_sha256={} vk_sha256={} pk_sha256={} rows={} exact_fp=true passed=true C12_closed=false",
            hex::encode(original.descriptor.sha256),
            hex::encode(original.verifying_key.sha256),
            hex::encode(original.proving_key.sha256),
            rows.len()
        );
        // All owned bytes retire here before the next role is read.
    }
}

/// Check the exact final role after the compiler's mandatory source import.
pub(super) fn assert_final_omega(
    inventory: &ProducerInventoryV1,
    source: &mut dyn OriginalSourceV1,
    captured: &ImportedRows,
) {
    let original = inventory.member(inventory.omega).expect("final Omega role");
    let descriptor = read(source, original.descriptor, DESCRIPTOR_MAX_BYTES_V1).unwrap();
    // Explicit V2 decoding validates all expression tags and canonical framing.
    let binding = DescriptorBinding::decode_v2(&descriptor).unwrap();
    let d = binding.descriptor();
    assert_eq!(d.curve, CurveV1::Pallas);
    assert_eq!(d.transcript, TranscriptV2::KagemushaPoseidonRp57Base);
    assert_eq!(d.instance_mode, InstanceModeV1::Direct);
    assert_eq!(d.proof_suffix, ProofSuffixV1::FoldedGenerator);
    require_source_descriptor(
        &binding,
        &omega_source_descriptor(inventory, source).unwrap(),
    )
    .unwrap();
    assert_eq!((d.k, d.blinding_factors), (16, 5));
    let key = read(source, original.verifying_key, VERIFYING_KEY_MAX_BYTES_V1).unwrap();
    VerifyingKey::<Ep>::read(&key, &binding).unwrap();
    let expected_bytes = key.len().checked_add(108).expect("compact Omega PK extent");
    let proving_key = read(source, original.proving_key, expected_bytes).unwrap();
    let rows = captured
        .artifact_rows::<Fq>(&proving_key, &binding, &key)
        .unwrap();
    iroha_plonk::keys::masking::validate_public_rows(&binding, &rows, None).unwrap();
    assert_opening_mask(&binding, "Omega");
    eprintln!(
        "OMEGA_MASK_BOUNDARY final_role={} descriptor_sha256={} vk_sha256={} pk_sha256={} rows={} exact_fq=true passed=true C12_closed=false",
        inventory.omega,
        hex::encode(original.descriptor.sha256),
        hex::encode(original.verifying_key.sha256),
        hex::encode(original.proving_key.sha256),
        rows.len(),
    );
}

/// Check every distinct private Q/A/W original after mandatory strict import.
/// Deduplication is by original index, never just the descriptor: equal circuit
/// shape does not establish equality of the public preprocessing tables.
pub(super) fn assert_private_roles(
    inventory: &ProducerInventoryV1,
    source: &mut dyn OriginalSourceV1,
    captured: &ImportedRows,
) {
    let mut members = BTreeMap::new();
    for operation in &inventory.operations {
        for (role, indices, curve) in [
            ("Q", &operation.q, CurveV1::Pallas),
            ("A", &operation.a, CurveV1::Vesta),
            ("W", &operation.w, CurveV1::Pallas),
        ] {
            for index in indices {
                if let Some(previous) = members.insert(*index, (role, curve)) {
                    assert_eq!(previous, (role, curve), "private original role alias");
                }
            }
        }
    }
    assert!(!members.is_empty(), "private original coverage");
    let count = members.len();
    for (index, (role, curve)) in members {
        let original = inventory.member(index).expect("private role original");
        let bytes = read(source, original.descriptor, DESCRIPTOR_MAX_BYTES_V1).unwrap();
        let binding = DescriptorBinding::decode_v2(&bytes).unwrap();
        let d = binding.descriptor();
        assert_eq!(d.curve, curve);
        assert_eq!(d.transcript, TranscriptV2::KagemushaPoseidonRp57Base);
        assert_eq!(d.instance_mode, InstanceModeV1::Direct);
        assert_eq!(d.proof_suffix, ProofSuffixV1::FoldedGenerator);
        assert!(d.num_advice_columns > 0, "fresh first advice commitment");
        let key = read(source, original.verifying_key, VERIFYING_KEY_MAX_BYTES_V1).unwrap();
        match curve {
            CurveV1::Pallas => {
                VerifyingKey::<Ep>::read(&key, &binding).unwrap();
            }
            CurveV1::Vesta => {
                VerifyingKey::<Eq>::read(&key, &binding).unwrap();
            }
        }
        let expected_bytes = key
            .len()
            .checked_add(108)
            .expect("compact private PK extent");
        let proving_key = read(source, original.proving_key, expected_bytes).unwrap();
        let rows = match curve {
            CurveV1::Pallas => {
                let rows = captured
                    .artifact_rows::<Fq>(&proving_key, &binding, &key)
                    .unwrap();
                iroha_plonk::keys::masking::validate_public_rows(&binding, &rows, None).unwrap();
                rows.len()
            }
            CurveV1::Vesta => {
                let rows = captured
                    .artifact_rows::<Fp>(&proving_key, &binding, &key)
                    .unwrap();
                iroha_plonk::keys::masking::validate_public_rows(&binding, &rows, None).unwrap();
                rows.len()
            }
        };
        assert_opening_mask(&binding, &format!("private.{role}.{index}"));
        eprintln!(
            "PRIVATE_MASK_BOUNDARY role={role} original={index} curve={curve:?} descriptor_sha256={} vk_sha256={} pk_sha256={} rows={rows} passed=true C12_closed=false",
            hex::encode(original.descriptor.sha256),
            hex::encode(original.verifying_key.sha256),
            hex::encode(original.proving_key.sha256),
        );
        // This original's owned bytes retire before the next member is read.
    }
    eprintln!("PRIVATE_MASK_COVERAGE originals={count} passed=true C12_closed=false");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone, Copy)]
    struct CompactSource {
        fixed: u64,
        copy: bool,
    }

    impl<F: iroha_pasta::PastaField> Circuit<F> for CompactSource {
        type Config = (
            iroha_plonk::cs::Column<iroha_plonk::cs::Advice>,
            iroha_plonk::cs::Column<iroha_plonk::cs::Advice>,
            iroha_plonk::cs::Column<iroha_plonk::cs::Fixed>,
            iroha_plonk::cs::Selector,
        );
        type FloorPlanner = iroha_plonk::frontend::SimpleFloorPlanner;
        type Params = ();

        fn without_witnesses(&self) -> Self {
            *self
        }

        fn configure(meta: &mut iroha_plonk::cs::ConstraintSystem<F>) -> Self::Config {
            use iroha_plonk::cs::Rotation;
            let a = meta.advice_column();
            let b = meta.advice_column();
            let fixed = meta.fixed_column();
            let selector = meta.selector();
            meta.enable_equality(a);
            meta.enable_equality(b);
            meta.create_gate("compact mask source", |cells| {
                vec![
                    cells.query_selector(selector)
                        * (cells.query_advice(a, Rotation(2))
                            * cells.query_fixed(fixed, Rotation(-1))
                            - cells.query_advice(b, Rotation::cur())),
                ]
            });
            (a, b, fixed, selector)
        }

        fn synthesize(
            &self,
            (a, b, fixed, selector): Self::Config,
            mut layouter: impl iroha_plonk::frontend::Layouter<F>,
        ) -> Result<(), iroha_plonk::frontend::Error> {
            use iroha_plonk::frontend::Value;
            layouter.assign_region(
                || "compact source",
                |mut region| {
                    let a = region.assign_advice(a, 0, Value::<F>::unknown())?.cell();
                    let b = region.assign_advice(b, 0, Value::<F>::unknown())?.cell();
                    region.assign_fixed(fixed, 0, F::from(self.fixed))?;
                    selector.enable(&mut region, 0)?;
                    if self.copy {
                        region.constrain_equal(a, b)?;
                    }
                    Ok(())
                },
            )
        }
    }

    fn compact_source_rows<C: PastaCurve>()
    where
        C::ScalarExt: MaskField,
    {
        use super::super::super::{OfflineCompilerV1, config};
        use super::super::{Originals, fixture_scope};
        use iroha_plonk::keys::CosetCachePolicy;
        let directory = tempfile::tempdir().unwrap();
        let mut originals = Originals {
            root: directory.path().to_owned(),
            bytes: 0,
            count: 0,
            new_write_remaining: 1 << 20,
        };
        let read_config = ReadConfig {
            maximum_bytes: 1 << 20,
            maximum_rows: 1 << 16,
            coset_cache: CosetCachePolicy::OnDemand,
            msm_budget: iroha_pasta::msm::MemoryBudget::DEFAULT,
        };
        let params = PinnedParams::<C>::derive(6).unwrap();
        let circuit = CompactSource {
            fixed: 7,
            copy: true,
        };
        let mut compiler =
            OfflineCompilerV1::new(fixture_scope(), &mut originals, read_config, 1 << 20).unwrap();
        compiler.mask_rows = Some(ImportedRows::default());
        let key = compiler
            .key(&circuit, &params, &config(vec![], true, read_config))
            .unwrap();
        // Exercise fresh publication, indexed reuse, and final closure imports.
        let reused = compiler
            .key(&circuit, &params, &config(vec![], true, read_config))
            .unwrap();
        assert_eq!(key.original(), reused.original());
        assert_eq!(compiler.mask_rows.as_ref().unwrap().originals.len(), 1);
        assert_eq!(
            compiler.import(&key, &circuit, &params).unwrap().original(),
            key.original()
        );
        // Existing collected cells cannot bypass a changed exact native source.
        for changed in [
            CompactSource {
                fixed: 8,
                ..circuit
            },
            CompactSource {
                copy: false,
                ..circuit
            },
        ] {
            assert!(compiler.import(&key, &changed, &params).is_err());
        }
        let mut captured = compiler.mask_rows.take().unwrap();
        drop(compiler);
        let record = key.original();
        let descriptor = read(&mut originals, record.descriptor, DESCRIPTOR_MAX_BYTES_V1).unwrap();
        let binding = DescriptorBinding::decode_v2(&descriptor).unwrap();
        let vk = read(
            &mut originals,
            record.verifying_key,
            VERIFYING_KEY_MAX_BYTES_V1,
        )
        .unwrap();
        let bytes = read(
            &mut originals,
            record.proving_key,
            read_config.maximum_bytes,
        )
        .unwrap();
        assert_eq!(&bytes[..8], b"PIPACPK1");
        assert_eq!(bytes.len(), 108 + vk.len());
        let typed =
            ProvingKey::from_artifact_v2(&bytes, &binding, &params, &circuit, read_config).unwrap();
        let rows = captured
            .artifact_rows::<C::ScalarExt>(&bytes, &binding, &vk)
            .unwrap();
        let sets = iroha_plonk::keys::masking::required_rows(&binding).unwrap();
        let closure = sets.public;
        assert_eq!(rows.keys().copied().collect::<BTreeSet<_>>(), closure);
        assert!(!closure.is_subset(&sets.evaluation));
        for (&row, values) in &rows {
            assert_eq!(
                values.fixed,
                typed
                    .fixed_values()
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                values.sigma,
                typed
                    .permutation_values()
                    .iter()
                    .map(|column| column[row])
                    .collect::<Vec<_>>()
            );
        }
        iroha_plonk::keys::masking::validate_public_rows(&binding, &rows, None).unwrap();
        assert!(
            ImportedRows::default()
                .artifact_rows::<C::ScalarExt>(&bytes, &binding, &vk)
                .is_err()
        );
        let mut wrong = record;
        wrong.descriptor.sha256[0] ^= 1;
        assert!(!captured.contains(wrong));
        assert!(
            ImportedRows::default()
                .import(wrong, &bytes, &binding, &params, &circuit, read_config)
                .is_err()
        );
        wrong = record;
        wrong.verifying_key.sha256[0] ^= 1;
        assert!(!captured.contains(wrong));
        assert!(
            ImportedRows::default()
                .import(wrong, &bytes, &binding, &params, &circuit, read_config)
                .is_err()
        );
        let mut altered_vk = vk.clone();
        altered_vk[0] ^= 1;
        assert!(
            captured
                .artifact_rows::<C::ScalarExt>(&bytes, &binding, &altered_vk)
                .is_err()
        );
        for index in [0, 8, 40, 44, bytes.len() - 33, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[index] ^= 1;
            let changed_record = OriginalV1 {
                proving_key: BlobV1::of(&changed),
                ..record
            };
            assert!(
                ImportedRows::default()
                    .import(
                        changed_record,
                        &changed,
                        &binding,
                        &params,
                        &circuit,
                        read_config
                    )
                    .is_err()
            );
            assert!(
                captured
                    .artifact_rows::<C::ScalarExt>(&changed, &binding, &vk)
                    .is_err()
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        let mut dense = bytes.clone();
        dense[..8].copy_from_slice(b"PIPAPK01");
        for changed in [bytes[..bytes.len() - 1].to_vec(), trailing, dense] {
            let changed_record = OriginalV1 {
                proving_key: BlobV1::of(&changed),
                ..record
            };
            assert!(
                ImportedRows::default()
                    .import(
                        changed_record,
                        &changed,
                        &binding,
                        &params,
                        &circuit,
                        read_config
                    )
                    .is_err()
            );
            assert!(
                captured
                    .artifact_rows::<C::ScalarExt>(&changed, &binding, &vk)
                    .is_err()
            );
        }
        let mut bounded = ImportedRows {
            bytes: MAX_CAPTURE_BYTES,
            ..ImportedRows::default()
        };
        assert!(
            bounded
                .import(record, &bytes, &binding, &params, &circuit, read_config)
                .unwrap_err()
                .contains("budget")
        );
        let entry = captured
            .originals
            .get_mut(&record.proving_key.sha256)
            .unwrap();
        let first = *entry.rows.keys().next().unwrap();
        let missing = entry.rows.remove(&first).unwrap();
        assert!(
            captured
                .artifact_rows::<C::ScalarExt>(&bytes, &binding, &vk)
                .unwrap_err()
                .contains("closure rows")
        );
        let entry = captured
            .originals
            .get_mut(&record.proving_key.sha256)
            .unwrap();
        entry.rows.insert(first, missing);
        entry.rows.get_mut(&first).unwrap().fixed[0] = [255; 32];
        assert!(
            captured
                .artifact_rows::<C::ScalarExt>(&bytes, &binding, &vk)
                .unwrap_err()
                .contains("noncanonical")
        );
        // Storage remains untrusted after collection: all final role assertions
        // use read() again, which refuses replacement and extent changes.
        let stored = directory
            .path()
            .join(hex::encode(record.proving_key.sha256));
        for changed in [
            bytes[..bytes.len() - 1].to_vec(),
            [bytes.as_slice(), &[0]].concat(),
        ] {
            std::fs::write(&stored, changed).unwrap();
            assert!(
                read(
                    &mut originals,
                    record.proving_key,
                    read_config.maximum_bytes
                )
                .is_err()
            );
        }
    }

    #[test]
    fn compact_source_capture_preserves_exact_rows_and_refuses_substitution_on_both_curves() {
        compact_source_rows::<Ep>();
        compact_source_rows::<Eq>();
    }

    #[test]
    fn source_descriptor_uses_exact_source_and_rejects_changed_metadata() {
        let source = CompactSource {
            fixed: 3,
            copy: true,
        };
        let expected = source_descriptor::<Eq, _>(&source, 6, vec![]).unwrap();
        require_source_descriptor(&expected, &expected).unwrap();
        let pallas = source_descriptor::<Ep, _>(&source, 6, vec![]).unwrap();
        assert!(require_source_descriptor(&pallas, &expected).is_err());
        let different_domain = source_descriptor::<Eq, _>(&source, 7, vec![]).unwrap();
        assert!(require_source_descriptor(&different_domain, &expected).is_err());
        for change in 0..5 {
            let mut changed = CircuitDescriptorV2::decode(expected.encoded()).unwrap();
            match change {
                0 => changed.degree += 1,
                1 => changed.num_fixed_columns += 1,
                2 => changed.num_advice_columns += 1,
                3 => changed.permutation_chunk_len += 1,
                _ => changed.quotient_pieces += 1,
            }
            if let Ok(changed) = DescriptorBinding::new_v2(changed) {
                assert!(require_source_descriptor(&changed, &expected).is_err());
            }
        }
        assert!(sigma_source_descriptor(16).is_err());
    }
}
