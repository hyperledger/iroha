//! Controls over genuine admitted Receive owners from complete-catalog acceptance.

use std::{collections::BTreeMap, io::Cursor};

use super::*;

#[test]
fn complete_q_identity_preflight_rejects_missing_foreign_duplicate_and_reordered_programs() {
    let installation = ([1; 32], [2; 32]);
    let expected: Vec<_> = (0..3).map(|program| (installation, program)).collect();
    require_program_identities(installation, 3, expected.clone().into_iter()).unwrap();
    for count in [0, 1, 2, 4] {
        let values: Vec<_> = (0..count).map(|program| (installation, program)).collect();
        assert!(matches!(
            require_program_identities(installation, 3, values.into_iter()),
            Err(Error::Inventory)
        ));
    }
    for changed in 0..expected.len() {
        let mut values = expected.clone();
        values[changed].0.0[0] ^= 1;
        assert!(matches!(
            require_program_identities(installation, 3, values.into_iter()),
            Err(Error::Authority)
        ));
        let mut values = expected.clone();
        values[changed].0.1[0] ^= 1;
        assert!(matches!(
            require_program_identities(installation, 3, values.into_iter()),
            Err(Error::Authority)
        ));
        let mut values = expected.clone();
        values[changed].1 = (values[changed].1 + 1) % 3;
        assert!(matches!(
            require_program_identities(installation, 3, values.into_iter()),
            Err(Error::Authority)
        ));
    }
    let mut reordered = expected;
    reordered.swap(0, 2);
    assert!(matches!(
        require_program_identities(installation, 3, reordered.into_iter()),
        Err(Error::Authority)
    ));
}

#[derive(Clone, Copy)]
enum Fault {
    Missing,
    Changed,
    Truncated,
    Extended,
    Cancelled,
}

struct Observed<'a> {
    source: &'a mut dyn OriginalSourceV1,
    fault: Option<(BlobV1, Fault)>,
    opens: Vec<[u8; 32]>,
}

struct ChangedReader<'a> {
    original: Box<dyn Read + 'a>,
    changed: bool,
}

impl Read for ChangedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let count = self.original.read(output)?;
        if count > 0 && !self.changed {
            output[0] ^= 1;
            self.changed = true;
        }
        Ok(count)
    }
}

impl OriginalSourceV1 for Observed<'_> {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.opens.push(digest);
        match self.fault.filter(|(blob, _)| blob.sha256 == digest) {
            Some((_, Fault::Missing)) => Err(Error::Unavailable),
            Some((_, Fault::Cancelled)) => Err(Error::Cancelled),
            Some((_, Fault::Changed)) => Ok(Box::new(ChangedReader {
                original: self.source.open(digest)?,
                changed: false,
            })),
            Some((blob, Fault::Truncated)) => Ok(Box::new(
                self.source
                    .open(digest)?
                    .take(blob.bytes.checked_sub(1).unwrap()),
            )),
            Some((_, Fault::Extended)) => {
                Ok(Box::new(self.source.open(digest)?.chain(Cursor::new([0]))))
            }
            None => self.source.open(digest),
        }
    }
}

fn same_route(actual: &QualifiedOperationRouteV1, expected: &QualifiedOperationRouteV1) {
    assert_eq!(actual.identity(), expected.identity());
    assert_eq!(actual.stage_memory_bytes(), expected.stage_memory_bytes());
    assert_eq!(actual.terminal().binding(), expected.terminal().binding());
    assert_eq!(
        actual.terminal().key().to_bytes(),
        expected.terminal().key().to_bytes()
    );
    let actual_omega = actual.candidate_omega().unwrap();
    let expected_omega = expected.candidate_omega().unwrap();
    assert_eq!(actual_omega.binding(), expected_omega.binding());
    assert_eq!(
        actual_omega.key().to_bytes(),
        expected_omega.key().to_bytes()
    );
    let (QualifiedOperationOwnerV1::Receive(actual), QualifiedOperationOwnerV1::Receive(expected)) =
        (actual.owner(), expected.owner())
    else {
        panic!("genuine Receive owners only")
    };
    assert!(Arc::ptr_eq(actual, expected));
}

fn expected_reads(inventory: &ProducerInventoryV1, record: &OperationV1) -> Vec<BlobV1> {
    let omega = inventory.member(inventory.omega).unwrap();
    let mut blobs = vec![omega.descriptor, omega.verifying_key];
    for (stage, member) in record.a.iter().enumerate() {
        let original = inventory.member(*member).unwrap();
        blobs.extend([
            original.descriptor,
            original.verifying_key,
            original.proving_key,
        ]);
        if let Some(member) = record.w.get(stage) {
            let original = inventory.member(*member).unwrap();
            blobs.extend([
                original.descriptor,
                original.verifying_key,
                original.proving_key,
            ]);
        }
    }
    blobs
}

/// Exercise source reuse only after the public whole-wallet constructor succeeded.
/// No production cache can be seeded by this cfg(test)-private helper.
pub(crate) fn assert_receive_alias_controls(
    qualified: &QualifiedWalletSourcesV1,
    installed: &InstalledVerifierPackV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
) -> usize {
    assert_alias_controls(
        qualified,
        installed,
        source,
        config,
        super::super::super::builtin::Admission::Strict,
    )
}

pub(crate) fn assert_builtin_receive_alias_controls(
    qualified: &QualifiedWalletSourcesV1,
    installed: &InstalledVerifierPackV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
    profile: &iroha_plonk::keys::BuiltinSourceProfileV1,
) -> usize {
    assert_alias_controls(
        qualified,
        installed,
        source,
        config,
        super::super::super::builtin::Admission::Builtin(profile),
    )
}

fn assert_alias_controls(
    qualified: &QualifiedWalletSourcesV1,
    installed: &InstalledVerifierPackV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
    admission: super::super::super::builtin::Admission<'_>,
) -> usize {
    let inventory = qualified.inventory();
    let authenticated = installed
        .authenticate_producer_inventory(&inventory.to_canonical_bytes().unwrap())
        .unwrap();
    let compiled = compiled_routes();
    let q: Vec<_> = (0..inventory.operations.len())
        .map(|program| {
            let route = inventory
                .routes
                .iter()
                .position(|index| usize::try_from(*index).unwrap() == program)
                .unwrap();
            qualified.q(compiled[route]).unwrap().clone()
        })
        .collect();
    let inputs = QualificationInputs {
        inventory: &authenticated,
        installed,
        qualified_q: &q,
        config,
        admission,
    };
    // The complete public batch rejects foreign/missing/reordered Q metadata
    // before progress or original I/O, even after another batch qualified it.
    for invalid in [Vec::new(), q[..q.len() - 1].to_vec(), {
        let mut reordered = q.clone();
        reordered.swap(0, 1);
        reordered
    }] {
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        let mut events = Vec::new();
        assert!(
            authenticated
                .qualify_operation_routes_with_admission(
                    installed,
                    &invalid,
                    &mut observed,
                    config,
                    |event| { events.push(event) },
                    admission
                )
                .is_err()
        );
        assert!(observed.opens.is_empty());
        assert!(events.is_empty());
    }
    let mut wrong_installation = installed
        .authenticate_producer_inventory(&inventory.to_canonical_bytes().unwrap())
        .unwrap();
    wrong_installation.scheme_id[0] ^= 1;
    let mut observed = Observed {
        source,
        fault: None,
        opens: Vec::new(),
    };
    let mut events = Vec::new();
    assert!(matches!(
        wrong_installation.qualify_operation_routes_with_admission(
            installed,
            &q,
            &mut observed,
            config,
            |event| events.push(event),
            admission,
        ),
        Err(OperationQualificationErrorV1::Original(Error::Authority))
    ));
    assert!(observed.opens.is_empty());
    assert!(events.is_empty());
    drop(observed);
    struct Unavailable {
        opens: usize,
    }
    impl OriginalSourceV1 for Unavailable {
        fn open(&mut self, _: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
            self.opens += 1;
            Err(Error::Unavailable)
        }
    }
    let mut unavailable = Unavailable { opens: 0 };
    let mut events = Vec::new();
    assert!(
        authenticated
            .qualify_operation_routes_with_admission(
                installed,
                &q,
                &mut unavailable,
                config,
                |event| events.push(event),
                admission
            )
            .is_err()
    );
    assert_eq!(unavailable.opens, 1);
    assert_eq!(
        events,
        [OperationQualificationProgressV1::Started { route_index: 0 }]
    );
    // No result or private cache escapes the failed batch, and no Completed
    // observation was emitted for the failing route.
    let mut programs: BTreeMap<u32, &QualifiedOperationRouteV1> = BTreeMap::new();
    let mut duplicate_count = 0;
    let mut pairs = Vec::new();
    for (index, route) in compiled.iter().copied().enumerate() {
        let owner = qualified.route(route).unwrap();
        assert_eq!(owner.identity().1, u32::try_from(index).unwrap());
        if !matches!(route.variant, Variant::Receive | Variant::ReceiveRenewed) {
            continue;
        }
        let program = owner.identity().2;
        if let Some(&first) = programs.get(&program) {
            let (QualifiedOperationOwnerV1::Receive(a), QualifiedOperationOwnerV1::Receive(b)) =
                (first.owner(), owner.owner())
            else {
                panic!("Receive route must retain its native owner")
            };
            assert!(
                Arc::ptr_eq(a, b),
                "public batch must share the exact strict native owner"
            );
            assert_ne!(first.identity().1, owner.identity().1);
            duplicate_count += 1;
            // One genuine program per variant is enough for all hit mutations.
            if !pairs
                .iter()
                .any(|(variant, _, _)| *variant == route.variant)
            {
                pairs.push((route.variant, first, owner));
            }
        } else {
            for &previous in programs.values() {
                let (QualifiedOperationOwnerV1::Receive(a), QualifiedOperationOwnerV1::Receive(b)) =
                    (previous.owner(), owner.owner())
                else {
                    panic!("Receive route must retain its native owner")
                };
                assert!(
                    !Arc::ptr_eq(a, b),
                    "different programs cannot share source authority"
                );
            }
            programs.insert(program, owner);
        }
    }
    assert_eq!(duplicate_count, 16);
    assert_eq!(pairs.len(), 2);
    let mut cases = 5;
    for (_, first, second) in pairs {
        let program = usize::try_from(first.identity().2).unwrap();
        let record = &inventory.operations[program];
        let mut admitted = AdmittedReceive::from_qualified_route(first, record).unwrap();
        let reads = expected_reads(inventory, record);
        if let super::super::super::builtin::Admission::Builtin(profile) = admission {
            let route = second.identity().1;
            assert!(profile.member(&[3, route, u32::MAX]).is_err());
            assert!(profile.member(&[4, route, u32::MAX]).is_err());
            assert_ne!(record.a[0], record.a[1]);
            assert_ne!(record.w[0], record.w[1]);
            let a_original = authenticated
                .read_original(record.a[0], source, config.maximum_bytes)
                .unwrap();
            let a_seal = admitted.a_seals[0].seal(record.a[0]).unwrap();
            let a_view = admitted.owner.bind_a(0, a_seal, None).unwrap();
            assert!(
                super::super::super::builtin::require_member_source(
                    profile.member(&[3, route, 1]).unwrap(),
                    &a_original,
                    installed.verifier().vesta_parameters(16).unwrap().as_ref(),
                    config,
                    a_view,
                    a_seal,
                )
                .is_err()
            );
            let w_original = authenticated
                .read_original(record.w[0], source, config.maximum_bytes)
                .unwrap();
            let w_seal = admitted.w_seals[0].seal(record.w[0]).unwrap();
            let w_view = admitted.owner.bind_w(0, w_seal, None).unwrap();
            assert!(
                super::super::super::builtin::require_member_source(
                    profile.member(&[4, route, 1]).unwrap(),
                    &w_original,
                    installed.verifier().pallas_parameters().as_ref(),
                    config,
                    w_view,
                    w_seal,
                )
                .is_err()
            );
            cases += 4;
        }
        for expected in [second, first] {
            let mut observed = Observed {
                source,
                fault: None,
                opens: Vec::new(),
            };
            let actual = admitted
                .qualify_alias(&inputs, expected.identity().1, &mut observed)
                .unwrap();
            same_route(&actual, expected);
            assert_eq!(
                observed.opens,
                reads.iter().map(|blob| blob.sha256).collect::<Vec<_>>()
            );
            cases += 1;
        }
        // An alias presented first in another local qualification order still
        // refers to the same previously admitted source, never an individual mask.
        let reversed = AdmittedReceive::from_qualified_route(second, record).unwrap();
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        same_route(
            &reversed
                .qualify_alias(&inputs, first.identity().1, &mut observed)
                .unwrap(),
            first,
        );
        cases += 1;
        drop(observed);
        let foreign = inventory
            .routes
            .iter()
            .position(|index| *index != first.identity().2)
            .unwrap();
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(matches!(
            admitted.qualify_alias(&inputs, u32::try_from(foreign).unwrap(), &mut observed),
            Err(OperationQualificationErrorV1::Original(Error::Authority))
        ));
        assert!(observed.opens.is_empty());
        cases += 1;
        drop(observed);
        // Private-state mutation tests confirm that the common hit path binds
        // the first source-checked context and the exact member of each seal.
        admitted.record.context[0][0] ^= 1;
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(matches!(
            admitted.qualify_alias(&inputs, second.identity().1, &mut observed),
            Err(OperationQualificationErrorV1::Source)
        ));
        assert!(observed.opens.is_empty());
        admitted.record.context[0][0] ^= 1;
        cases += 1;
        drop(observed);
        admitted.a_seals.swap(0, 1);
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(
            admitted
                .qualify_alias(&inputs, second.identity().1, &mut observed)
                .is_err()
        );
        assert!(observed.opens.is_empty());
        admitted.a_seals.swap(0, 1);
        cases += 1;
        drop(observed);
        admitted.w_seals.swap(0, 1);
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(
            admitted
                .qualify_alias(&inputs, second.identity().1, &mut observed)
                .is_err()
        );
        assert!(observed.opens.is_empty());
        admitted.w_seals.swap(0, 1);
        cases += 1;
        drop(observed);
        for blob in &reads {
            // Every role, including repeated content addresses, remains mandatory.
            let mut observed = Observed {
                source,
                fault: Some((*blob, Fault::Changed)),
                opens: Vec::new(),
            };
            let result = admitted.qualify_alias(&inputs, second.identity().1, &mut observed);
            assert!(matches!(
                result,
                Err(OperationQualificationErrorV1::Original(Error::Inventory))
            ));
            assert!(observed.opens.contains(&blob.sha256));
            cases += 1;
        }
        // Both Omega metadata originals and a compact PK exercise length/outage/
        // cancellation controls without buffering the original or changing custody.
        let pk = inventory.member(record.a[0]).unwrap().proving_key;
        for blob in [reads[0], reads[1], pk] {
            for fault in [
                Fault::Missing,
                Fault::Truncated,
                Fault::Extended,
                Fault::Cancelled,
            ] {
                let mut observed = Observed {
                    source,
                    fault: Some((blob, fault)),
                    opens: Vec::new(),
                };
                let result = admitted.qualify_alias(&inputs, second.identity().1, &mut observed);
                match fault {
                    Fault::Missing => assert!(matches!(
                        result,
                        Err(OperationQualificationErrorV1::Original(Error::Unavailable))
                    )),
                    Fault::Cancelled => assert!(matches!(
                        result,
                        Err(OperationQualificationErrorV1::Original(Error::Cancelled))
                    )),
                    _ => assert!(matches!(
                        result,
                        Err(OperationQualificationErrorV1::Original(Error::Inventory))
                    )),
                }
                assert_eq!(observed.opens.last(), Some(&blob.sha256));
                cases += 1;
            }
        }
        let max_pk = record
            .a
            .iter()
            .chain(&record.w)
            .map(|member| inventory.member(*member).unwrap().proving_key.bytes)
            .max()
            .unwrap();
        let mut exact = config;
        exact.maximum_bytes = usize::try_from(max_pk).unwrap();
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        same_route(
            &admitted
                .qualify_alias(
                    &QualificationInputs {
                        config: exact,
                        ..inputs
                    },
                    second.identity().1,
                    &mut observed,
                )
                .unwrap(),
            second,
        );
        cases += 1;
        let mut bytes_limited = exact;
        bytes_limited.maximum_bytes -= 1;
        let mut rows_limited = config;
        rows_limited.maximum_rows = (1 << 16) - 1;
        for limited in [bytes_limited, rows_limited] {
            let mut observed = Observed {
                source,
                fault: None,
                opens: Vec::new(),
            };
            assert!(
                admitted
                    .qualify_alias(
                        &QualificationInputs {
                            config: limited,
                            ..inputs
                        },
                        second.identity().1,
                        &mut observed
                    )
                    .is_err()
            );
            assert!(observed.opens.is_empty());
            cases += 1;
        }
    }
    cases
}
