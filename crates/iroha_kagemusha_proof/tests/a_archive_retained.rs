//! Retained Archive bytes and pending descriptor; no Load or lineage admission.

#[path = "common/bootstrap.rs"]
mod bootstrap;
#[path = "common/bootstrap_objects.rs"]
#[allow(dead_code)]
mod bootstrap_objects;
#[path = "common/send_objects.rs"]
#[allow(dead_code)]
mod send_objects;

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::{
    a_relation::{
        archive::incoming::ArchiveIncomingObjects,
        archive::retained::{
            ArchiveRetainedInputs, ArchiveRetainedPayment, ArchiveRetainedSources,
        },
        own::OwnPolicy,
    },
    admin_sigma::StateWitness,
    operation_relation::objects::ObjectKind,
};
use iroha_pasta::{Ep, Fp, poseidon::hash_with_domain};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    bytes::{
        p_bytes_native,
        tape::{BytesChip, BytesConfig},
        variable::ActiveBytes,
    },
    statement::STATEMENT_DOMAIN,
};
use iroha_plonk_recursion::verifier::{VerifierChip, VerifierConfig};

fn frame(raw: &[u8]) -> Vec<u8> {
    [
        u32::try_from(raw.len()).unwrap().to_le_bytes().as_slice(),
        raw,
    ]
    .concat()
}
fn digest(kind: ObjectKind, raw: &[u8]) -> Fp {
    let end = kind.body_len();
    let mut words = vec![p_bytes_native(kind.signing_domain(), &raw[..end])];
    for offset in [16, 0, 48, 32] {
        words.push(Fp::from_u128(u128::from_be_bytes(
            raw[end + offset..end + offset + 16].try_into().unwrap(),
        )));
    }
    hash_with_domain(kind.object_domain(), &words)
}
fn internal(tag: u64, words: &[Fp]) -> Fp {
    hash_with_domain(
        u64::from_le_bytes(*b"kgwciw_1"),
        &[
            vec![Fp::from(tag), Fp::from(u64::try_from(words.len()).unwrap())],
            words.to_vec(),
        ]
        .concat(),
    )
}

#[derive(Clone)]
struct Retained {
    signed: [Vec<u8>; 4],
    payment: Vec<u8>,
    statement: [Fp; 26],
    omega: Vec<u8>,
    sigma: Vec<u8>,
    capacities: [usize; 2],
    known: bool,
}
impl Retained {
    fn fixture() -> Self {
        let (mut before, _, _) = bootstrap_objects::enrollment();
        // Component-only funded state: this test does not prove a Load or ancestry.
        before.core[8] = Fp::from(100);
        bootstrap::rebind(&mut before);
        let send = send_objects::from_load(&StateWitness::from(&before));
        // Opaque historical proofs are deliberately not presented as valid proofs.
        let omega = (0..63)
            .map(|i| u8::try_from(i).unwrap())
            .collect::<Vec<_>>();
        let sigma = (0..35)
            .map(|i| 255 - u8::try_from(i).unwrap())
            .collect::<Vec<_>>();
        let proof = p_bytes_native(
            u64::from_le_bytes(*b"kgwprf_1"),
            &[frame(&omega), frame(&sigma)].concat(),
        );
        let f = &send.statement;
        let wallet = &send.before.lineage[6..8];
        let operation = hash_with_domain(
            u64::from_le_bytes(*b"kgwopid1"),
            &[wallet[0], wallet[1], f[16], f[17]],
        );
        let mut body = 1u16.to_le_bytes().to_vec();
        body.extend(bootstrap_objects::id(f[3], f[4]));
        body.extend(bootstrap_objects::id(wallet[0], wallet[1]));
        body.extend(bootstrap_objects::small_id(31, 32));
        body.extend(&f[9].to_repr()[..16]);
        for word in [
            operation,
            f[14],
            f[15],
            hash_with_domain(STATEMENT_DOMAIN, f),
            proof,
        ] {
            body.extend(word.to_repr());
        }
        body.extend(bootstrap_objects::small_id(501, 502));
        body.extend(Fp::ZERO.to_repr());
        let receipt = bootstrap_objects::sign(ObjectKind::Receipt, body, 29, 71);
        let package = hash_with_domain(
            u64::from_le_bytes(*b"kgwpkg_1"),
            &[
                hash_with_domain(STATEMENT_DOMAIN, f),
                proof,
                receipt.digest(),
            ],
        );
        let mut payment = 1u16.to_le_bytes().to_vec();
        payment.extend(digest(ObjectKind::Request, &send.objects[1]).to_repr());
        payment.extend(&send.objects[0][130..195]);
        payment.extend(digest(ObjectKind::Credential, &send.objects[0]).to_repr());
        payment.extend(package.to_repr());
        Self {
            signed: [
                send.objects[1].clone(),
                send.objects[0].clone(),
                receipt.bytes,
                send_objects::receiver_credential().bytes,
            ],
            payment,
            statement: *f,
            omega,
            sigma,
            capacities: [65; 2],
            known: true,
        }
    }
    fn rebind_proofs(&mut self) {
        let proof: Fp = p_bytes_native(
            u64::from_le_bytes(*b"kgwprf_1"),
            &[frame(&self.omega), frame(&self.sigma)].concat(),
        );
        let mut body = self.signed[2][..ObjectKind::Receipt.body_len()].to_vec();
        body[242..274].copy_from_slice(&proof.to_repr());
        let receipt = bootstrap_objects::sign(ObjectKind::Receipt, body, 29, 73);
        let package = hash_with_domain(
            u64::from_le_bytes(*b"kgwpkg_1"),
            &[
                hash_with_domain(STATEMENT_DOMAIN, &self.statement),
                proof,
                receipt.digest(),
            ],
        );
        self.signed[2] = receipt.bytes;
        self.payment[131..163].copy_from_slice(&package.to_repr());
    }
    fn public(&self) -> Vec<Fp> {
        let proof = p_bytes_native(
            u64::from_le_bytes(*b"kgwprf_1"),
            &[frame(&self.omega), frame(&self.sigma)].concat(),
        );
        vec![
            digest(ObjectKind::Request, &self.signed[0]),
            digest(ObjectKind::Credential, &self.signed[1]),
            digest(ObjectKind::Receipt, &self.signed[2]),
            digest(ObjectKind::Credential, &self.signed[3]),
            p_bytes_native(u64::from_le_bytes(*b"kgwpay_1"), &self.payment),
            internal(9, &self.statement),
            proof,
            proof,
            internal(12, &self.statement[17..24]),
        ]
    }
    fn accepts(&self, public: &[Fp]) -> bool {
        check_circuit(self, 16, &[public.to_vec()], CheckMode::Strict)
            .is_ok_and(|r| r.is_satisfied())
    }
}

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl Circuit<Fp> for Retained {
    type Config = Config;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let z = meta.advice_column();
        let w = meta.advice_column();
        let bytes = BytesConfig::configure(meta, z, w);
        let public = meta.instance_column(9);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(&self, c: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(c.verifier);
        let mut bytes = BytesChip::new(c.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "retained Archive Payment",
            |mut region| {
                let raw = |v: &Vec<u8>| {
                    if self.known {
                        Value::known(v.clone())
                    } else {
                        Value::unknown()
                    }
                };
                let omega = ActiveBytes::assign(
                    &mut chip.uint(),
                    &mut bytes,
                    &mut region,
                    self.capacities[0],
                    &raw(&self.omega),
                    &[],
                )?;
                let sigma = ActiveBytes::assign(
                    &mut chip.uint(),
                    &mut bytes,
                    &mut region,
                    self.capacities[1],
                    &raw(&self.sigma),
                    &[],
                )?;
                let statement = chip
                    .uint()
                    .glue()
                    .witnesses(
                        &mut region,
                        &self.statement.map(|v| {
                            if self.known {
                                Value::known(v)
                            } else {
                                Value::unknown()
                            }
                        }),
                    )?
                    .try_into()
                    .map_err(|_| Error::Synthesis)?;
                let values = |raw: &[u8]| {
                    raw.iter()
                        .map(|b| {
                            if self.known {
                                Value::known(*b)
                            } else {
                                Value::unknown()
                            }
                        })
                        .collect::<Vec<_>>()
                };
                let signed = self.signed.each_ref().map(|v| values(v));
                let payment = values(&self.payment);
                let retained = ArchiveRetainedPayment::from_sources(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    OwnPolicy::new([31, 32], bootstrap_objects::key(23)).unwrap(),
                    ArchiveRetainedSources {
                        signed: signed.each_ref().map(Vec::as_slice),
                        payment: &payment,
                    },
                    ArchiveRetainedInputs {
                        statement: &statement,
                        omega: &omega,
                        sigma: &sigma,
                    },
                )?;
                Ok(retained
                    .context()
                    .iter()
                    .map(|c| c.authenticated_digest().clone())
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), c.public, i)?;
        }
        Ok(())
    }
}

#[test]
fn retained_payment_binds_original_bytes_lengths_credential_field_and_send_descriptor() {
    let c = Retained::fixture();
    assert_ne!(&c.signed[0][210..242], &c.signed[0][394..426]);
    let public = c.public();
    assert!(c.accepts(&public));
    for mutation in 0..13 {
        let mut wrong = c.clone();
        match mutation {
            0 => wrong.omega[62] ^= 1,
            1 => {
                wrong.omega.push(0);
            }
            2 => wrong.sigma[34] ^= 1,
            3 => {
                wrong.sigma.push(0);
            }
            4..=7 => {
                let i = mutation - 4;
                let n = wrong.signed[i].len();
                wrong.signed[i][n - 1] ^= 1;
            }
            8 => wrong.statement[17] += Fp::ONE,
            9 => wrong.statement[23] += Fp::ONE,
            10 => wrong.payment[2] ^= 1,
            11 => wrong.payment[131] ^= 1,
            _ => {
                let credential = wrong.signed[0][210..242].to_vec();
                wrong.signed[0][394..426].copy_from_slice(&credential);
                wrong.signed[0][210] ^= 1;
            }
        }
        // Recompute all proposed public digests: rejection comes from the
        // source relations, not a stale external expected hash.
        assert!(!wrong.accepts(&wrong.public()), "mutation{mutation}");
    }
    let known = synthesize(&c, 16, None).unwrap();
    let unknown = synthesize(&c.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}

#[test]
fn retained_payment_joint_limit_rejects_resigned_and_rehashed_oversize() {
    use iroha_kagemusha_proof::a_relation::receive::MAX_OMEGA_RAW_BYTES;
    let mut exact = Retained::fixture();
    exact.capacities = [5_000; 2];
    exact.omega = vec![41; 4_000];
    exact.sigma = vec![79; MAX_OMEGA_RAW_BYTES - exact.omega.len()];
    exact.rebind_proofs();
    assert!(exact.accepts(&exact.public()), "inclusive joint bound");
    let known = synthesize(&exact, 16, None).unwrap();
    let unknown = synthesize(&exact.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    for slot in 0..2 {
        let mut oversized = exact.clone();
        if slot == 0 {
            oversized.omega.push(0);
        } else {
            oversized.sigma.push(0);
        }
        oversized.rebind_proofs();
        assert!(
            !oversized.accepts(&oversized.public()),
            "joint cap+1 must reject after re-signing receipt and rehashing Payment; slot{slot}"
        );
    }
}

#[test]
fn retained_full_payment_capacities_have_witness_independent_layout() {
    use iroha_kagemusha_proof::a_relation::receive::{MAX_OMEGA_RAW_BYTES, MAX_SIGMA_RAW_BYTES};
    let mut source = Retained::fixture();
    source.capacities = [MAX_OMEGA_RAW_BYTES, MAX_SIGMA_RAW_BYTES];
    source.sigma = vec![79; MAX_SIGMA_RAW_BYTES];
    source.omega = vec![41; MAX_OMEGA_RAW_BYTES - MAX_SIGMA_RAW_BYTES];
    source.rebind_proofs();
    let public = vec![source.public()];
    // Full carrier capacities are fixed by the admitted envelope domain, even
    // when the original proof tapes are short or invalid. This checks this
    // owner in isolation; recursive A/W composition needs its own layout gate.
    let (known, k) = match synthesize(&source, 16, Some(&public)) {
        Ok(layout) => (layout, 16),
        Err(error) => {
            eprintln!("full retained owner k16 error {error:?}; k18 diagnostic only");
            (synthesize(&source, 18, Some(&public)).unwrap(), 18)
        }
    };
    let rows: Vec<_> = known
        .tables
        .advice_assigned()
        .iter()
        .map(|column| {
            column
                .iter()
                .rposition(|assigned| *assigned)
                .map_or(0, |i| i + 1)
        })
        .collect();
    eprintln!(
        "full retained owner capacities={:?} max_rows={} lanes={rows:?} k16_fit={}",
        source.capacities,
        rows.iter().max().unwrap(),
        k == 16
    );
    let report = iroha_plonk::check::check(&known.cs, &known.tables, CheckMode::Strict).unwrap();
    assert!(report.is_satisfied(), "{:?}", report.failures().first());
    let unknown = synthesize(&source.without_witnesses(), k, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
    assert_eq!(
        known.tables.advice_assigned(),
        unknown.tables.advice_assigned()
    );
    assert_eq!(
        k, 16,
        "full retained owner exceeds the hard circuit capacity"
    );
}

#[test]
fn retained_schema_pins_all_nine_original_categories_and_capacities() {
    let specs = ArchiveRetainedPayment::context_specs(65, 97).unwrap();
    assert_eq!(specs.map(|s| s.tag), [4, 5, 6, 7, 8, 9, 10, 11, 12]);
    assert_eq!(specs[4].capacity, 163);
    assert_eq!(specs[5].capacity, 26 * 32);
    assert_eq!(specs[6].capacity, 65);
    assert_eq!(specs[7].capacity, 97);
    assert_eq!(specs[8].capacity, 7 * 32);
    assert!(ArchiveRetainedPayment::context_specs(0, 1).is_err());
    assert!(ArchiveRetainedPayment::context_specs(1, 0).is_err());
    assert!(ArchiveRetainedPayment::context_specs(usize::MAX, 1).is_err());
}

#[derive(Clone)]
struct Incoming {
    signed: [Vec<u8>; 3],
    known: bool,
}
impl Incoming {
    fn public(&self, valid: bool) -> Vec<Fp> {
        let mut out = self
            .signed
            .iter()
            .zip([
                ObjectKind::Request,
                ObjectKind::Credential,
                ObjectKind::Receipt,
            ])
            .map(|(raw, kind)| digest(kind, raw))
            .collect::<Vec<_>>();
        out.push(Fp::from(u64::from(valid)));
        out
    }
    fn accepts(&self, public: &[Fp]) -> bool {
        check_circuit(self, 16, &[public.to_vec()], CheckMode::Strict)
            .is_ok_and(|r| r.is_satisfied())
    }
}
impl Circuit<Fp> for Incoming {
    type Config = Config;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 3).unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(4);
        meta.enable_equality(public);
        Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(&self, c: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(c.verifier);
        let mut bytes = BytesChip::new(c.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let out = layouter.assign_region(
            || "Archive original incoming receipt",
            |mut region| {
                let raw = self.signed.each_ref().map(|raw| {
                    raw.iter()
                        .map(|b| {
                            if self.known {
                                Value::known(*b)
                            } else {
                                Value::unknown()
                            }
                        })
                        .collect::<Vec<_>>()
                });
                let objects = ArchiveIncomingObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    raw.each_ref().map(Vec::as_slice),
                )?;
                let mut out = objects
                    .context()
                    .iter()
                    .map(|c| c.authenticated_digest().clone())
                    .collect::<Vec<_>>();
                out.push(objects.receipt().structural_valid().word().clone());
                Ok(out)
            },
        )?;
        for (i, word) in out.iter().enumerate() {
            layouter.constrain_instance(word.cell(), c.public, i)?;
        }
        Ok(())
    }
}

#[test]
fn incoming_sources_pin_quoted_credential_and_preserve_malformed_receipt() {
    let retained = Retained::fixture();
    let incoming = Incoming {
        signed: [
            retained.signed[0].clone(),
            retained.signed[3].clone(),
            retained.signed[2].clone(),
        ],
        known: true,
    };
    assert!(incoming.accepts(&incoming.public(true)));
    let specs = ArchiveIncomingObjects::context_specs().unwrap();
    assert_eq!(specs.map(|s| s.tag), [4, 7, 13]);
    assert_eq!(specs.map(|s| s.capacity), [522, 540, 402]);
    // Incoming evidence is soft, including noncanonical original fields. Its
    // digest must still be derived from the complete original bytes.
    for mutation in 0..4 {
        let mut changed = incoming.clone();
        match mutation {
            0 => changed.signed[2][0] ^= 2,
            1 => changed.signed[2][114..146].fill(255),
            2 => changed.signed[2][146..178].fill(255),
            _ => changed.signed[2][210..242].fill(255),
        }
        assert!(
            changed.accepts(&changed.public(false)),
            "soft body{mutation}"
        );
        assert!(
            !changed.accepts(&changed.public(true)),
            "forged verdict{mutation}"
        );
        assert!(
            !changed.accepts(&incoming.public(false)),
            "lost original{mutation}"
        );
    }
    for index in [0, 1] {
        let mut changed = incoming.clone();
        changed.signed[index][0] ^= 2;
        assert!(
            !changed.accepts(&changed.public(false)),
            "hard source{index}"
        );
    }
    for (index, offset) in [(0, 210), (1, 66), (1, 447)] {
        let mut changed = incoming.clone();
        changed.signed[index][offset] ^= 1;
        assert!(
            !changed.accepts(&changed.public(true)),
            "quote{index}:{offset}"
        );
    }
    // The receipt signature remains an opaque original here. Only mandatory
    // Q2 can derive its signature verdict; decoding may not reject it early.
    let mut signature = incoming.clone();
    signature.signed[2][ObjectKind::Receipt.body_len()..].fill(0);
    assert!(signature.accepts(&signature.public(true)));
    assert!(!signature.accepts(&incoming.public(true)));
    let known = synthesize(&incoming, 16, None).unwrap();
    let unknown = synthesize(&incoming.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}
