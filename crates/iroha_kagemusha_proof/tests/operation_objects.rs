//! Canonical signed-object tapes, shared Rust vectors and total malformed decoding.

use ff::{Field, PrimeField};
use iroha_kagemusha_proof::operation_relation::objects::{ObjectKind, SignedObjectCells};

#[path = "operation_objects/credit_opening.rs"]
mod credit_opening;
#[path = "operation_objects/payment.rs"]
mod payment;
#[path = "operation_objects/semantics.rs"]
mod semantics;
#[path = "operation_objects/send.rs"]
mod send;
#[path = "operation_objects/status.rs"]
mod status;
use iroha_pasta::{Fp, poseidon::hash_with_domain};
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::{Column, ConstraintSystem, Instance},
    frontend::{Circuit, Error, Layouter, SimpleFloorPlanner, Value, synthesize},
};
use iroha_plonk_gadgets::{
    GlueChip, GlueConfig, LimbBits, Pow5Columns, RoundConstantColumns, RunningSumChip,
    RunningSumConfig, SpongeChip, SpongeConfig, UintChip,
    bytes::{
        p_bytes_native,
        tape::{BytesChip, BytesConfig},
    },
};
use norito::json::Value as Json;

#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyCheck {
    Structural,
    Semantic,
}

#[derive(Clone)]
struct ObjectCircuit {
    kind: ObjectKind,
    bytes: Vec<u8>,
    soft: bool,
    valid: bool,
    known: bool,
    body_check: BodyCheck,
}
#[derive(Clone, Debug)]
struct Config {
    glue: GlueConfig,
    range: RunningSumConfig,
    hash: SpongeConfig<Fp>,
    bytes: BytesConfig,
    public: Column<Instance>,
}
impl Circuit<Fp> for ObjectCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Config {
        let columns = core::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let glue = GlueConfig::configure(meta, columns, constants);
        let range_col = meta.advice_column();
        let range = RunningSumConfig::configure(meta, range_col, LimbBits::new(9).expect("limb"));
        let columns = Pow5Columns::allocate(meta);
        let constants = RoundConstantColumns::allocate(meta);
        let hash = SpongeConfig::configure(meta, columns, constants, &[]);
        let z = meta.advice_column();
        let w = meta.advice_column();
        let bytes = BytesConfig::configure(meta, z, w);
        let public = meta.instance_column(8);
        meta.enable_equality(public);
        Config {
            glue,
            range,
            hash,
            bytes,
            public,
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut glue = GlueChip::new(config.glue);
        let mut range = RunningSumChip::new(config.range);
        let mut hash = SpongeChip::new(config.hash);
        let mut bytes = BytesChip::new(config.bytes);
        range.load_table(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "signed object",
            |mut region| {
                let values: Vec<_> = self
                    .bytes
                    .iter()
                    .map(|b| {
                        if self.known {
                            Value::known(*b)
                        } else {
                            Value::unknown()
                        }
                    })
                    .collect();
                let run = bytes.run(
                    &mut region,
                    &values,
                    &self.kind.primary_segments(),
                    &self.kind.secondary_segments(),
                )?;
                let mut uint = UintChip::new(&mut glue, &mut range);
                let (object, valid) = if self.soft {
                    SignedObjectCells::decode_soft(
                        &mut uint,
                        &mut hash,
                        &mut region,
                        self.kind,
                        &run,
                    )?
                } else {
                    let object = SignedObjectCells::from_run(
                        &mut uint,
                        &mut hash,
                        &mut region,
                        self.kind,
                        &run,
                    )?;
                    let one = uint.glue().constant(&mut region, Fp::ONE)?;
                    (object, uint.glue().assert_bool(&mut region, &one)?)
                };
                let valid = if self.body_check == BodyCheck::Semantic {
                    match self.kind {
                        ObjectKind::Credential => iroha_kagemusha_proof::operation_relation::objects::credential::CredentialCells::check(
                            &mut uint, &mut region, &object,
                        )?.valid().clone(),
                        ObjectKind::Request => iroha_kagemusha_proof::operation_relation::objects::request::RequestCells::check(
                            &mut uint, &mut hash, &mut region, &object,
                        )?.valid().clone(),
                        _ => iroha_kagemusha_proof::operation_relation::objects::policy::PolicyCells::check(
                            &mut uint, &mut region, &object,
                        )?.valid().clone(),
                    }
                } else { valid };
                assert_eq!(object.kind(), self.kind);
                assert!(object.word(1).is_err(), "identifier is not a reduced field");
                let mut outputs = vec![object.message().clone(), object.digest().clone()];
                outputs.extend_from_slice(object.signature());
                outputs.push(valid.word().clone());
                let credit = if self.kind == ObjectKind::Request {
                    let fields: Vec<_> = object.fields().iter().flatten().cloned().collect();
                    assert_eq!(fields.len(), 26);
                    hash.hash_words(&mut region, u64::from_le_bytes(*b"kgwcrdt1"), &fields)?
                } else {
                    uint.glue().constant(&mut region, Fp::ZERO)?
                };
                outputs.push(credit);
                Ok(outputs)
            },
        )?;
        for (i, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}

fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(core::str::from_utf8(b).expect("hex"), 16).expect("byte"))
        .collect()
}
fn field(hex: &str) -> Fp {
    Fp::from_repr(decode(hex).try_into().expect("32"))
        .into_option()
        .expect("canonical")
}
fn fixture() -> Json {
    norito::json::from_str(include_str!(
        "../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .expect("fixture")
}

impl ObjectCircuit {
    fn public(&self, credit: Fp) -> Vec<Fp> {
        let end = self.kind.body_len();
        let message = p_bytes_native(self.kind.signing_domain(), &self.bytes[..end]);
        let signature = &self.bytes[end..];
        let halves: Vec<_> = [16, 0, 48, 32]
            .map(|i| {
                Fp::from_u128(u128::from_be_bytes(
                    signature[i..i + 16].try_into().expect("half"),
                ))
            })
            .to_vec();
        let mut items = vec![message];
        items.extend(&halves);
        let digest = hash_with_domain(self.kind.object_domain(), &items);
        let mut public = vec![message, digest];
        public.extend(halves);
        public.extend([Fp::from(u64::from(self.valid)), credit]);
        public
    }
    fn accepts(&self, credit: Fp) -> bool {
        check_circuit(self, 12, &[self.public(credit)], CheckMode::Strict)
            .is_ok_and(|r| r.is_satisfied())
    }
}

fn cases() -> Vec<(ObjectCircuit, Fp, String, Option<Fp>)> {
    let json = fixture();
    let mut result = Vec::new();
    for row in json["signatures"].as_array().expect("signatures") {
        let domain = row["domain"].as_str().expect("domain");
        let Some(kind) = ObjectKind::ALL
            .into_iter()
            .find(|kind| kind.signing_domain().to_le_bytes() == domain.as_bytes())
        else {
            continue;
        };
        let name = row["object"].as_str().expect("name");
        let object = json["object_digests"]
            .as_array()
            .expect("objects")
            .iter()
            .find(|item| item["object"].as_str() == Some(name));
        let mut body = decode(row["transcript_hex"].as_str().expect("body"));
        assert_eq!(body.len(), kind.body_len(), "{kind:?}");
        body.extend(decode(row["signature_hex"].as_str().expect("signature")));
        let credit = if kind == ObjectKind::Request {
            // Filled by the native shared Request body field vector.
            let credit = &json["poseidon"]["credit_id"];
            field(
                credit["poseidon"]["digest_hex"]
                    .as_str()
                    .expect("credit digest"),
            )
        } else {
            Fp::ZERO
        };
        result.push((
            ObjectCircuit {
                kind,
                bytes: body,
                soft: false,
                valid: true,
                known: true,
                body_check: BodyCheck::Structural,
            },
            credit,
            name.to_owned(),
            object.map(|object| field(object["digest_hex"].as_str().expect("digest"))),
        ));
    }
    result
}

#[test]
fn all_signed_object_schemas_match_rust_vectors_and_same_tape_fields() {
    let mut covered = Vec::new();
    for (c, credit, name, digest) in cases() {
        assert!(c.accepts(credit), "{name}");
        if let Some(digest) = digest {
            assert_eq!(c.public(credit)[1], digest, "object digest {name}");
        }
        let known = synthesize(&c, 12, Some(&[c.public(credit)])).expect("known");
        let unknown = synthesize(&c.without_witnesses(), 12, None).expect("unknown");
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.selectors(), unknown.tables.selectors());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        covered.push(c.kind);
        for i in 0..7 {
            let mut wrong = c.public(credit);
            wrong[i] += Fp::ONE;
            assert!(
                !check_circuit(&c, 12, &[wrong], CheckMode::Strict)
                    .expect("wrong public")
                    .is_satisfied()
            );
        }
    }
    assert!(ObjectKind::ALL.iter().all(|kind| covered.contains(kind)));
}

#[test]
fn malformed_bodies_decode_totally_without_canonical_field_aliases() {
    for (mut c, credit, _, _) in cases() {
        c.soft = true;
        assert!(c.accepts(credit));
        if c.kind == ObjectKind::Request {
            continue;
        }
        c.bytes[0] = 2;
        c.valid = false;
        assert!(c.accepts(credit));
        c.valid = true;
        assert!(!c.accepts(credit));
        c.soft = false;
        assert!(!c.accepts(credit));
    }
    let (mut c, _, _, _) = cases()
        .into_iter()
        .find(|(c, ..)| c.kind == ObjectKind::TimeAnchor)
        .expect("anchor");
    // Replace its canonical signer-certificate field with p, not its alias0.
    let mut modulus = (-Fp::ONE).to_repr();
    for byte in &mut modulus {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    let start = c.kind.body_len() - 32;
    c.bytes[start..start + 32].copy_from_slice(&modulus);
    c.soft = true;
    c.valid = false;
    assert!(c.accepts(Fp::ZERO));
    c.valid = true;
    assert!(!c.accepts(Fp::ZERO));
    c.soft = false;
    assert!(!c.accepts(Fp::ZERO));
    let (mut c, _, _, _) = cases()
        .into_iter()
        .find(|(c, ..)| c.kind == ObjectKind::Certificate)
        .expect("certificate");
    c.bytes[35] = 2; // SEC1 prefix, after version/scheme/role.
    c.soft = true;
    c.valid = false;
    assert!(c.accepts(Fp::ZERO));
    c.valid = true;
    assert!(!c.accepts(Fp::ZERO));
}
