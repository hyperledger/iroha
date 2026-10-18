//! Content-address ownership and unique credential deduplication, without Q admission.

use super::*;
use crate::a_relation::receive::tests::{decode, object_digest};
use ff::PrimeField;
use iroha_plonk::{
    check::{CheckMode, check_circuit},
    cs::ConstraintSystem,
    frontend::{Circuit, Layouter, SimpleFloorPlanner, synthesize},
};
use iroha_plonk_gadgets::bytes::tape::BytesConfig;
use iroha_plonk_recursion::verifier::VerifierConfig;

#[derive(Clone, Debug)]
struct Config {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
}

#[derive(Clone)]
struct Sources {
    request: Vec<u8>,
    /// The receiver's current credential, carried by the state as its digest.
    current: Vec<u8>,
    /// Own receipt, quoted credential and quoted certificate.
    objects: [Vec<u8>; 3],
    variant: Variant,
    known: bool,
}

impl Circuit<Fp> for Sources {
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
        let verifier = VerifierConfig::configure_serialized_foreign(meta, 4).unwrap();
        let columns = [meta.advice_column(), meta.advice_column()];
        Config {
            verifier,
            bytes: BytesConfig::configure(meta, columns[0], columns[1]),
        }
    }
    fn synthesize(&self, config: Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        layouter.assign_region(
            || "quoted content addresses",
            |mut region| {
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
                let objects = self.objects.each_ref().map(|raw| values(raw));
                let sources = ReceiveAuthorizationSources {
                    receipt: &objects[0],
                    quoted: [&objects[1], &objects[2]],
                };
                let auth = ReceiveAuthorizationObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    self.variant,
                    sources,
                )?;
                let run = bytes.run(
                    &mut region,
                    &values(&self.request),
                    &ObjectKind::Request.primary_segments(),
                    &ObjectKind::Request.secondary_segments(),
                )?;
                let lanes = chip.operation_lanes()?;
                let mut uint = UintChip::new(lanes.glue, lanes.range);
                let request = SignedObjectCells::decode_soft(
                    &mut uint,
                    lanes.hash,
                    &mut region,
                    ObjectKind::Request,
                    &run,
                )?
                .0;
                let request = RequestCells::check(&mut uint, lanes.hash, &mut region, &request)?;
                let current = object_digest(ObjectKind::Credential, &self.current);
                let current = uint.glue().witness(
                    &mut region,
                    if self.known {
                        Value::known(current)
                    } else {
                        Value::unknown()
                    },
                )?;
                auth.bind_quoted_sources(&mut uint, &mut region, &request, &current)
            },
        )
    }
}

impl Sources {
    fn fixture() -> Self {
        let j: norito::json::Value = norito::json::from_str(include_str!(
            "../../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
        ))
        .unwrap();
        let signed = |name: &str| {
            let row = j["signatures"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["object"].as_str() == Some(name))
                .unwrap();
            let mut bytes = decode(row["transcript_hex"].as_str().unwrap());
            bytes.extend(decode(row["signature_hex"].as_str().unwrap()));
            bytes
        };
        let credential = signed("payer credential");
        let certificate = signed("payer issuer certificate");
        let mut request = signed("Request");
        // This is only the content-address/dedup component: changing the
        // quoted identity does not claim this Request's signature verifies.
        request[210..242]
            .copy_from_slice(&object_digest(ObjectKind::Credential, &credential).to_repr());
        Self {
            request,
            current: credential.clone(),
            objects: [
                signed("Receive receipt binding the Payment digest"),
                credential,
                certificate,
            ],
            variant: Variant::Receive,
            known: true,
        }
    }
    fn accepts(&self) -> bool {
        check_circuit(self, 16, &[], CheckMode::Strict).is_ok_and(|r| r.is_satisfied())
    }
    fn rebind_quoted(&mut self) {
        let digest = object_digest(ObjectKind::Credential, &self.objects[1]);
        self.request[210..242].copy_from_slice(&digest.to_repr());
    }
}

#[test]
fn quoted_preimages_and_ordinary_renewed_choice_are_hard_bound() {
    let c = Sources::fixture();
    assert!(c.accepts());
    // Ordinary Receive quotes exactly the state's current credential.
    let mut other = c.clone();
    other.current[ObjectKind::Credential.body_len()] ^= 1;
    assert!(
        !other.accepts(),
        "quoted credential must be the current one"
    );
    for (object, offset) in [
        (1, 0),
        (1, 130),
        (1, 300),
        (1, 507),
        (2, 0),
        (2, 35),
        (2, 105),
    ] {
        let mut wrong = c.clone();
        wrong.objects[object][offset] ^= 1;
        assert!(!wrong.accepts(), "substituted object {object}/{offset}");
    }
    let mut wrong = c.clone();
    wrong.variant = Variant::ReceiveRenewed;
    assert!(
        !wrong.accepts(),
        "cannot opt out of equal-digest deduplication"
    );
    let mut renewed = c.clone();
    renewed.objects[1][ObjectKind::Credential.body_len()] ^= 1;
    renewed.rebind_quoted();
    assert!(
        !renewed.accepts(),
        "cannot use ordinary key for a different quoted digest"
    );
    renewed.variant = Variant::ReceiveRenewed;
    assert!(
        renewed.accepts(),
        "exact changed signature remains for the soft Q owner"
    );
    let known = synthesize(&renewed, 16, None).unwrap();
    let unknown = synthesize(&renewed.without_witnesses(), 16, None).unwrap();
    assert_eq!(known.tables.fixed(), unknown.tables.fixed());
    assert_eq!(known.tables.permutation(), unknown.tables.permutation());
}

#[test]
fn quoted_certificate_cannot_change_even_with_rebound_credential() {
    let c = Sources::fixture();
    let mut wrong = c.clone();
    wrong.objects[2][ObjectKind::Certificate.body_len()] ^= 1;
    // Rebinding the Request alone cannot authorize another certificate.
    wrong.rebind_quoted();
    assert!(!wrong.accepts());
    // A truly different credential that commits to the changed certificate
    // remains a total signature-verification input, never ordinary dedup.
    let certificate = object_digest(ObjectKind::Certificate, &wrong.objects[2]);
    let end = ObjectKind::Credential.body_len();
    wrong.objects[1][end - 32..end].copy_from_slice(&certificate.to_repr());
    wrong.rebind_quoted();
    wrong.variant = Variant::ReceiveRenewed;
    assert!(wrong.accepts());
    assert_ne!(wrong.request, c.request);
}
