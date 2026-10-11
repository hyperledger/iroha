//! Test-only retention of a current completed Bootstrap Omega, without generating proofs.

#[path = "omega_hard_fixture.rs"]
pub(crate) mod codec;
use codec::{
    CAPS, FilePin, FixtureManifest, NAMES, bounded, decode_manifest, encode_manifest, hex, pin,
    retain, sha, words_bytes,
};
use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{a_relation::LINEAGE_DOMAIN, omega::OmegaPlan};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaAffine, msm::MemoryBudget, poseidon::hash_with_domain};
use iroha_plonk::{
    DescriptorBinding, VerifyingKey,
    cs::{CurveV1, InstanceModeV1, ProofSuffixV1, TranscriptV2},
    pcs::ipa::PinnedParams,
    verifier::{accumulate_generator, verify_full},
};
use iroha_plonk_gadgets::statement::foreign_limbs;
use iroha_plonk_recursion::{AccumulatorT, FoldInput};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Borrow only values from the already completed genuine current owner.
pub(crate) struct NativeBundle<'a> {
    pub(crate) descriptor: &'a [u8],
    pub(crate) key: &'a [u8],
    pub(crate) proof: &'a [u8],
    pub(crate) public: &'a [Fp; 18],
    pub(crate) pallas: &'a AccumulatorT<Ep>,
    pub(crate) vesta: &'a AccumulatorT<Eq>,
    pub(crate) instances: &'a [Vec<Fq>],
}
/// Preflight before the existing proof producer runs; publication stays create-new.
pub(crate) struct ExportRequest {
    output: PathBuf,
    provenance_path: PathBuf,
    provenance: Vec<u8>,
    provenance_sha: [u8; 32],
}
fn absent(path: &Path) {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => panic!("fresh absent output required"),
    }
}
impl ExportRequest {
    /// Read developer-only output/provenance selection; no environment option ships.
    pub(crate) fn from_env() -> Self {
        let path = |name| {
            PathBuf::from(
                std::env::var_os(name).expect("explicit current fixture export selection"),
            )
        };
        let output = path("KAGEMUSHA_OMEGA_FIXTURE_OUTPUT");
        let provenance_path = path("KAGEMUSHA_OMEGA_FIXTURE_PROVENANCE");
        let provenance_sha = pin(&std::env::var("KAGEMUSHA_OMEGA_FIXTURE_PROVENANCE_SHA256")
            .expect("independent source/binary receipt pin"));
        Self::new(output, provenance_path, provenance_sha)
    }
    fn new(output: PathBuf, provenance_path: PathBuf, provenance_sha: [u8; 32]) -> Self {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        assert!(output.is_absolute() && output.starts_with(&repository));
        let parent = output.parent().unwrap();
        assert_eq!(
            parent.canonicalize().unwrap(),
            parent,
            "canonical parent without symlink aliases"
        );
        absent(&output);
        let provenance = bounded(&provenance_path, 65_536);
        assert_eq!(sha(&provenance), provenance_sha);
        assert_ne!(provenance_sha, [0; 32]);
        Self {
            output,
            provenance_path,
            provenance,
            provenance_sha,
        }
    }
    /// Verify and retain exactly one already generated proof and its original claims.
    /// This calls no prover or key generator and never supplies historical defaults.
    pub(crate) fn export(self, input: NativeBundle<'_>) {
        assert!(!input.descriptor.is_empty() && input.descriptor.len() <= CAPS[0]);
        assert!(!input.key.is_empty() && input.key.len() <= CAPS[1]);
        assert!(!input.proof.is_empty() && input.proof.len() <= CAPS[2]);
        let binding = DescriptorBinding::decode_v2(input.descriptor).unwrap();
        assert_eq!(binding.encoded(), input.descriptor);
        let d = binding.descriptor();
        assert_eq!(d.curve, CurveV1::Pallas);
        assert_eq!(d.k, 16);
        assert_eq!(d.transcript, TranscriptV2::KagemushaPoseidonRp57Base);
        assert_eq!(d.instance_mode, InstanceModeV1::Direct);
        assert_eq!(d.proof_suffix, ProofSuffixV1::FoldedGenerator);
        assert_eq!(d.instance_lengths, [1, 2, 16]);
        assert_eq!(
            d.instance_types.as_deref(),
            Some(OmegaPlan::instance_types().as_slice())
        );
        let key = VerifyingKey::<Ep>::read(input.key, &binding).unwrap();
        assert_eq!(key.to_bytes(), input.key);
        assert_eq!(input.public[0], Fp::ONE);
        for i in [1, 2, 3, 4, 6, 7, 9, 10, 11, 12, 14] {
            assert!(input.public[i].to_repr()[16..].iter().all(|b| *b == 0));
        }
        assert!(input.public[13].to_repr()[13..].iter().all(|b| *b == 0));
        assert_eq!(input.public[17], key.kagemusha_digest(&binding).unwrap());
        let pbytes = input.pallas.to_bytes();
        let vbytes = input.vesta.to_bytes();
        assert_eq!(
            AccumulatorT::<Ep>::from_bytes(&pbytes).unwrap(),
            *input.pallas
        );
        assert_eq!(
            AccumulatorT::<Eq>::from_bytes(&vbytes).unwrap(),
            *input.vesta
        );
        let mut words = input.public.to_vec();
        let (x, y) = Option::<(Fp, Fp)>::from(input.pallas.g().coordinates()).unwrap();
        words.extend([x, y]);
        for u in input.pallas.challenges() {
            words.extend(foreign_limbs(u).map(Fp::from_u128));
        }
        assert_eq!(words.len(), 52);
        let digest = hash_with_domain(LINEAGE_DOMAIN, &words);
        let (x, y) = Option::<(Fq, Fq)>::from(input.vesta.g().coordinates()).unwrap();
        let fq = |value: Fp| Option::<Fq>::from(Fq::from_repr(value.to_repr())).unwrap();
        let instances = vec![
            vec![fq(digest)],
            vec![x, y],
            input.vesta.challenges().iter().copied().map(fq).collect(),
        ];
        assert_eq!(
            instances, input.instances,
            "public18/original P/V must bind exact producer instances"
        );
        let p = PinnedParams::<Ep>::derive(16).unwrap();
        let v = PinnedParams::<Eq>::derive(16).unwrap();
        verify_full(
            &p,
            &binding,
            &key,
            &instances,
            input.proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        input.pallas.decide(&p, MemoryBudget::DEFAULT).unwrap();
        input.vesta.decide(&v, MemoryBudget::DEFAULT).unwrap();
        let claim = accumulate_generator(
            &p,
            &binding,
            &key,
            &instances,
            input.proof,
            MemoryBudget::DEFAULT,
        )
        .unwrap();
        let opening = FoldInput::from_opening(*claim.g(), claim.challenges()).unwrap();
        opening.decide(&p, MemoryBudget::DEFAULT).unwrap();
        let public = words_bytes(input.public);
        let originals = [
            input.descriptor,
            input.key,
            input.proof,
            public.as_slice(),
            pbytes.as_slice(),
            vbytes.as_slice(),
        ];
        let manifest = FixtureManifest {
            version: 1,
            producer_receipt_sha256: self.provenance_sha,
            files: originals.map(|b| FilePin {
                bytes: b.len() as u64,
                sha256: sha(b),
            }),
        };
        let manifest_bytes = encode_manifest(&manifest);
        assert_eq!(decode_manifest(&manifest_bytes), manifest);
        assert_eq!(bounded(&self.provenance_path, 65_536), self.provenance);
        absent(&self.output);
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&self.output).unwrap();
        retain(&self.output, "producer-receipt.json", &self.provenance);
        for (name, bytes) in NAMES.iter().zip(originals) {
            retain(&self.output, name, bytes);
        }
        retain(&self.output, "fixture.norito", &manifest_bytes);
        let instance_bytes = instances
            .iter()
            .flatten()
            .flat_map(|w| w.to_repr())
            .collect::<Vec<_>>();
        retain(&self.output, "native-omega-instances.bin", &instance_bytes);
        let mut opening_bytes = Vec::from(iroha_plonk::transcript::encode_point::<Ep>(opening.g()));
        for u in opening.challenges() {
            opening_bytes.extend_from_slice(&u.to_repr());
        }
        retain(&self.output, "native-omega-opening.bin", &opening_bytes);
        for ((name, bytes), cap) in NAMES.iter().zip(originals).zip(CAPS) {
            assert_eq!(bounded(&self.output.join(name), cap), bytes);
        }
        assert_eq!(
            bounded(&self.output.join("fixture.norito"), 8192),
            manifest_bytes
        );
        assert_eq!(
            bounded(&self.output.join("producer-receipt.json"), 65_536),
            self.provenance
        );
        assert_eq!(
            bounded(&self.output.join("native-omega-instances.bin"), 19 * 32),
            instance_bytes
        );
        assert_eq!(
            bounded(&self.output.join("native-omega-opening.bin"), 17 * 32),
            opening_bytes
        );
        assert_eq!(bounded(&self.provenance_path, 65_536), self.provenance);
        retain(&self.output,"result.json",&norito::json::to_vec(&norito::json!({
            "schema":"kagemusha.current-omega-fixture.export.v1","proofs_generated_by_export":0,
            "native_full_proof_and_three_decisions":true,"exact_public18_P_V_instance_binding":true,
            "fixture_manifest_sha256":(hex(&sha(&manifest_bytes))),"descriptor_sha256":(hex(&manifest.files[0].sha256)),"key_sha256":(hex(&manifest.files[1].sha256)),
            "producer_receipt_sha256":(hex(&self.provenance_sha)),"descriptor_bytes":(input.descriptor.len()),"key_bytes":(input.key.len()),"proof_bytes":(input.proof.len()),
            "source_qualified":false,"scope":"current one-terminal Bootstrap component fixture; no complete catalog, source/binary admission, monetary, privacy or release qualification; external exact fixture/D/V selection required"
        })).unwrap());
        eprintln!(
            "CURRENT_BOOTSTRAP_OMEGA_FIXTURE path={} manifest={} descriptor={} key={} native_full=true extra_proofs=0 source_qualified=false",
            self.output.display(),
            hex(&sha(&manifest_bytes)),
            hex(&manifest.files[0].sha256),
            hex(&manifest.files[1].sha256)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fresh_output_preflight_refuses_existing_or_bad_provenance_before_proof_work() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/qualification");
        fs::create_dir_all(&parent).unwrap();
        let root = parent.canonicalize().unwrap().join(format!(
            "omega-export-test-{}-{}-{}",
            module_path!().replace("::", "-"),
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let receipt = root.join("provenance.json");
        fs::write(&receipt, b"test DATA provenance").unwrap();
        let output = root.join("output");
        let expected = sha(b"test DATA provenance");
        let request = ExportRequest::new(output.clone(), receipt.clone(), expected);
        assert!(!output.exists());
        drop(request);
        assert!(
            std::panic::catch_unwind(|| ExportRequest::new(
                output.clone(),
                receipt.clone(),
                [1; 32]
            ))
            .is_err()
        );
        assert!(!output.exists());
        fs::create_dir(&output).unwrap();
        fs::write(output.join("old"), b"prior").unwrap();
        assert!(
            std::panic::catch_unwind(|| ExportRequest::new(
                output.clone(),
                receipt.clone(),
                expected
            ))
            .is_err()
        );
        assert_eq!(fs::read(output.join("old")).unwrap(), b"prior");
        fs::remove_dir_all(root).unwrap();
    }
}
