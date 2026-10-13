//! Exact signature reuse controls over genuinely source-qualified catalog keys.

use std::io::Cursor;

use super::*;

#[test]
fn q_batch_rejects_either_foreign_owner_identity() {
    let identity = ([1; 32], [2; 32]);
    require_installation_identities(identity, identity, identity).unwrap();
    for foreign in [([3; 32], identity.1), (identity.0, [4; 32])] {
        assert!(matches!(
            require_installation_identities(identity, foreign, identity),
            Err(Error::Authority)
        ));
        assert!(matches!(
            require_installation_identities(identity, identity, foreign),
            Err(Error::Authority)
        ));
        assert!(matches!(
            require_installation_identities(foreign, identity, identity),
            Err(Error::Authority)
        ));
    }
}

#[derive(Clone, Copy)]
enum Fault {
    Changed,
    Missing,
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

fn same_key(actual: &KeyArtifact<Ep>, expected: &KeyArtifact<Ep>) {
    assert_eq!(actual.binding(), expected.binding());
    assert_eq!(actual.key().to_bytes(), expected.key().to_bytes());
}

fn expect_fault<T>(result: Result<T, QQualificationErrorV1>, fault: Fault) {
    match fault {
        Fault::Missing => assert!(matches!(
            result,
            Err(QQualificationErrorV1::Original(Error::Unavailable))
        )),
        Fault::Cancelled => assert!(matches!(
            result,
            Err(QQualificationErrorV1::Original(Error::Cancelled))
        )),
        _ => assert!(matches!(
            result,
            Err(QQualificationErrorV1::Original(Error::Inventory))
        )),
    }
}

/// Check genuine first admissions and hits without repeating the complete cold graph.
/// The cache is private and is populated only by its real native signature importer.
pub(crate) fn assert_signature_reuse_controls(
    qualified: &QualifiedWalletSourcesV1,
    installed: &InstalledVerifierPackV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
) -> usize {
    let inventory = qualified.inventory();
    let authenticated = installed
        .authenticate_producer_inventory(&inventory.to_canonical_bytes().unwrap())
        .unwrap();
    let inputs = QualificationInputs {
        inventory: &authenticated,
        installed,
        sigmas: qualified.sigmas(),
        config,
    };
    let compiled = compiled_routes();
    let programs: Vec<_> = (0..inventory.operations.len())
        .map(|program| {
            let route = inventory
                .routes
                .iter()
                .position(|index| usize::try_from(*index).unwrap() == program)
                .unwrap();
            let q = qualified.q(compiled[route]).unwrap();
            assert_eq!(
                q.identity(),
                (qualified.installation(), u32::try_from(program).unwrap())
            );
            q
        })
        .collect();
    let mut cases = 0;
    let mut admitted = SignatureAdmissions::default();
    let mut hits = 0;
    let mut references = 0;
    for (program, record) in inventory.operations.iter().enumerate() {
        let q = programs[program];
        let scope = SourceScopeV1::from_scheme(installed.verifier().scheme()).unwrap();
        let plans = signature_plans(
            variant(record.variant).unwrap(),
            scope.own().unwrap(),
            scope.root(),
        )
        .unwrap();
        assert_eq!(plans.len(), q.signatures().len());
        for (index, plan) in plans.iter().enumerate() {
            assert_eq!(plan.slots(), q.signatures()[index].slots());
            let member = record.q[index + 1];
            let original = inventory.member(member).unwrap();
            let before = admitted.entries.len();
            let mut observed = Observed {
                source,
                fault: None,
                opens: Vec::new(),
            };
            let (key, seal) = admitted
                .qualify(&inputs, member, plan, &mut observed)
                .unwrap();
            same_key(&key, &q.keys()[index + 1]);
            seal.bind(member, &key, None).unwrap();
            assert_eq!(
                observed.opens,
                [
                    original.descriptor.sha256,
                    original.verifying_key.sha256,
                    original.proving_key.sha256
                ]
            );
            if before == admitted.entries.len() {
                hits += 1;
            } else {
                assert_eq!(admitted.entries.len(), before + 1);
            }
            references += 1;
            cases += 1;
        }
    }
    assert_eq!(references, 57);
    assert_eq!(admitted.entries.len(), 6);
    assert_eq!(hits, 51);

    let member = admitted.entries[0].member;
    let plan = admitted.entries[0].plan.clone();
    let original = admitted.entries[0].original;
    let roles = [
        original.descriptor,
        original.verifying_key,
        original.proving_key,
    ];
    for blob in roles {
        for fault in [
            Fault::Changed,
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
            expect_fault(
                admitted.qualify(&inputs, member, &plan, &mut observed),
                fault,
            );
            assert_eq!(observed.opens.last(), Some(&blob.sha256));
            assert_eq!(admitted.entries.len(), 6);
            cases += 1;
            // A failure before any strict source was admitted cannot populate a cache.
            let mut empty = SignatureAdmissions::default();
            let mut observed = Observed {
                source,
                fault: Some((blob, fault)),
                opens: Vec::new(),
            };
            expect_fault(empty.qualify(&inputs, member, &plan, &mut observed), fault);
            assert!(empty.entries.is_empty());
            cases += 1;
        }
    }

    let mut mode = plan.slots().to_vec();
    mode[0].mode = match mode[0].mode {
        VerifyMode::Hard => VerifyMode::Soft,
        VerifyMode::Soft => VerifyMode::Hard,
    };
    let mut order = plan.slots().to_vec();
    order.swap(0, 2);
    let mut root = plan.slots().to_vec();
    let SignatureKey::Fixed(point) = &mut root[2].key else {
        panic!("first schema has fixed root")
    };
    *point = point.neg();
    for slots in [mode.clone(), order, root] {
        let changed = QSignaturePlan::new(slots).unwrap();
        assert_eq!(changed.instance_length(), plan.instance_length());
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(matches!(
            admitted.qualify(&inputs, member, &changed, &mut observed),
            Err(QQualificationErrorV1::Source)
        ));
        assert!(
            observed.opens.is_empty(),
            "same member and changed plan must reject, never miss"
        );
        cases += 1;
    }
    let mut empty = SignatureAdmissions::default();
    assert!(
        empty
            .qualify(&inputs, member, &QSignaturePlan::new(mode).unwrap(), source)
            .is_err()
    );
    assert!(
        empty.entries.is_empty(),
        "failed strict source import cannot mint a cache entry"
    );
    empty.qualify(&inputs, member, &plan, source).unwrap();
    assert_eq!(
        empty.entries.len(),
        1,
        "exact retry still runs real source admission"
    );
    cases += 2;

    let mut exact = config;
    exact.maximum_bytes = usize::try_from(original.proving_key.bytes).unwrap();
    exact.maximum_rows = admitted.entries[0].key.binding().n();
    let (key, seal) = admitted
        .qualify(
            &QualificationInputs {
                config: exact,
                ..inputs
            },
            member,
            &plan,
            source,
        )
        .unwrap();
    same_key(&key, &admitted.entries[0].key);
    seal.bind(member, &key, None).unwrap();
    cases += 1;
    let mut bytes_limited = exact;
    bytes_limited.maximum_bytes -= 1;
    let mut rows_limited = exact;
    rows_limited.maximum_rows -= 1;
    for limited in [bytes_limited, rows_limited] {
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(
            admitted
                .qualify(
                    &QualificationInputs {
                        config: limited,
                        ..inputs
                    },
                    member,
                    &plan,
                    &mut observed
                )
                .is_err()
        );
        assert!(observed.opens.is_empty());
        cases += 1;
    }

    let entry = &mut admitted.entries[0];
    let mut observed = Observed {
        source,
        fault: None,
        opens: Vec::new(),
    };
    assert!(
        entry
            .revalidate(&inputs, member + 1, &plan, &mut observed)
            .is_err()
    );
    assert!(observed.opens.is_empty());
    cases += 1;
    drop(observed);
    for role in 0..3 {
        match role {
            0 => entry.original.descriptor.sha256[0] ^= 1,
            1 => entry.original.verifying_key.sha256[0] ^= 1,
            _ => entry.original.proving_key.sha256[0] ^= 1,
        }
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(
            entry
                .revalidate(&inputs, member, &plan, &mut observed)
                .is_err()
        );
        assert!(observed.opens.is_empty());
        entry.original = original;
        cases += 1;
    }
    entry.installation.0[0] ^= 1;
    let mut observed = Observed {
        source,
        fault: None,
        opens: Vec::new(),
    };
    assert!(matches!(
        entry.revalidate(&inputs, member, &plan, &mut observed),
        Err(QQualificationErrorV1::Original(Error::Authority))
    ));
    assert!(observed.opens.is_empty());
    entry.installation.0[0] ^= 1;
    cases += 1;
    drop(observed);

    // Existing genuine QSigma authority is not signature-source authority, even
    // when a private-state mutation makes member/original/seal agree with it.
    let sigma_member = inventory.operations[0].q[0];
    let saved_key = entry.key.clone();
    let saved_seal = entry.seal.clone();
    entry.key = programs[0].keys()[0].clone();
    entry.seal = programs[0].seals[0].clone();
    let mut observed = Observed {
        source,
        fault: None,
        opens: Vec::new(),
    };
    assert!(
        entry
            .revalidate(&inputs, member, &plan, &mut observed)
            .is_err(),
        "foreign key/seal pairing must reject"
    );
    assert!(observed.opens.is_empty());
    drop(observed);
    entry.member = sigma_member;
    entry.original = *inventory.member(sigma_member).unwrap();
    let mut observed = Observed {
        source,
        fault: None,
        opens: Vec::new(),
    };
    assert!(matches!(
        entry.revalidate(&inputs, sigma_member, &plan, &mut observed),
        Err(QQualificationErrorV1::Signature(QSignatureError::Profile))
    ));
    assert!(observed.opens.is_empty());
    entry.member = member;
    entry.original = original;
    entry.key = saved_key;
    entry.seal = saved_seal;
    cases += 2;
    drop(observed);

    // Public batch authority preflight precedes progress and all I/O.
    let mut wrong = installed
        .authenticate_producer_inventory(&inventory.to_canonical_bytes().unwrap())
        .unwrap();
    wrong.scheme_id[0] ^= 1;
    let mut observed = Observed {
        source,
        fault: None,
        opens: Vec::new(),
    };
    let mut events = Vec::new();
    assert!(matches!(
        wrong.qualify_q_programs(
            installed,
            qualified.sigmas(),
            &mut observed,
            config,
            |event| events.push(event)
        ),
        Err(QQualificationErrorV1::Original(Error::Authority))
    ));
    assert!(observed.opens.is_empty());
    assert!(events.is_empty());
    cases += 1;
    drop(observed);
    // Failure of the first selected source produces no success observation or
    // partial returned program vector. Marked cancellation remains cancellation.
    let first_blob = inventory
        .member(inventory.operations[0].q[0])
        .unwrap()
        .descriptor;
    for fault in [Fault::Missing, Fault::Cancelled] {
        let mut observed = Observed {
            source,
            fault: Some((first_blob, fault)),
            opens: Vec::new(),
        };
        let mut events = Vec::new();
        expect_fault(
            authenticated.qualify_q_programs(
                installed,
                qualified.sigmas(),
                &mut observed,
                config,
                |event| events.push(event),
            ),
            fault,
        );
        assert_eq!(observed.opens, [first_blob.sha256]);
        assert_eq!(
            events,
            [QQualificationProgressV1::Started { program_index: 0 }]
        );
        cases += 1;
    }
    cases
}

/// Exercise every compiled signature role, including the 51 same-source hits.
/// All entries originate from the real typed compiled-member importer.
pub(crate) fn assert_builtin_signature_reuse_controls(
    qualified: &QualifiedWalletSourcesV1,
    installed: &InstalledVerifierPackV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
    profile: &iroha_plonk::keys::BuiltinSourceProfileV1,
) -> usize {
    let inventory = qualified.inventory();
    let authenticated = installed
        .authenticate_producer_inventory(&inventory.to_canonical_bytes().unwrap())
        .unwrap();
    let inputs = QualificationInputs {
        inventory: &authenticated,
        installed,
        sigmas: qualified.sigmas(),
        config,
    };
    let routes = compiled_routes();
    let mut admitted = SignatureAdmissions::default();
    let mut hits = 0;
    let mut cases = 0;
    for (program, record) in inventory.operations.iter().enumerate() {
        let route = inventory
            .routes
            .iter()
            .position(|index| usize::try_from(*index).unwrap() == program)
            .unwrap();
        let q = qualified.q(routes[route]).unwrap();
        for (index, plan) in q.signatures().iter().enumerate() {
            let stage = u32::try_from(index + 1).unwrap();
            let compiled = profile
                .member(&[2, u32::try_from(program).unwrap(), stage])
                .unwrap();
            let member = record.q[index + 1];
            let original = inventory.member(member).unwrap();
            let before = admitted.entries.len();
            let mut observed = Observed {
                source,
                fault: None,
                opens: Vec::new(),
            };
            let (key, seal) = admitted
                .qualify_with_member(&inputs, member, plan, &mut observed, Some(compiled))
                .unwrap();
            same_key(&key, &q.keys()[index + 1]);
            assert!(
                seal.seal(member)
                    .unwrap()
                    .same_source(q.seals[index + 1].seal(member).unwrap())
            );
            assert_eq!(
                observed.opens,
                [
                    original.descriptor.sha256,
                    original.verifying_key.sha256,
                    original.proving_key.sha256
                ]
            );
            if before == admitted.entries.len() {
                hits += 1;
            }
            cases += 1;
        }
    }
    assert_eq!(cases, 57);
    assert_eq!(admitted.entries.len(), 6);
    assert_eq!(hits, 51);

    let member = admitted.entries[0].member;
    let plan = admitted.entries[0].plan.clone();
    let original = admitted.entries[0].original;
    let (program, stage) = inventory
        .operations
        .iter()
        .enumerate()
        .find_map(|(program, record)| {
            record
                .q
                .iter()
                .position(|value| *value == member)
                .map(|stage| {
                    (
                        u32::try_from(program).unwrap(),
                        u32::try_from(stage).unwrap(),
                    )
                })
        })
        .unwrap();
    let compiled = profile.member(&[2, program, stage]).unwrap();
    assert!(profile.member(&[2, program, u32::MAX]).is_err());
    let foreign = profile.member(&[2, program, 0]).unwrap();
    for warm in [false, true] {
        let mut empty = SignatureAdmissions::default();
        let cache = if warm { &mut admitted } else { &mut empty };
        let before = cache.entries.len();
        assert!(
            cache
                .qualify_with_member(&inputs, member, &plan, source, Some(foreign))
                .is_err()
        );
        assert_eq!(
            cache.entries.len(),
            before,
            "wrong current compiled role cannot admit or replace an entry"
        );
        cases += 1;
    }
    cases += 1;
    for blob in [
        original.descriptor,
        original.verifying_key,
        original.proving_key,
    ] {
        for fault in [
            Fault::Changed,
            Fault::Missing,
            Fault::Truncated,
            Fault::Extended,
            Fault::Cancelled,
        ] {
            for warm in [false, true] {
                let mut empty = SignatureAdmissions::default();
                let cache = if warm { &mut admitted } else { &mut empty };
                let before = cache.entries.len();
                let mut observed = Observed {
                    source,
                    fault: Some((blob, fault)),
                    opens: Vec::new(),
                };
                expect_fault(
                    cache.qualify_with_member(
                        &inputs,
                        member,
                        &plan,
                        &mut observed,
                        Some(compiled),
                    ),
                    fault,
                );
                assert_eq!(observed.opens.last(), Some(&blob.sha256));
                assert_eq!(cache.entries.len(), before);
                cases += 1;
            }
        }
    }
    // Same-member cache hits still reject a different ordered signature policy
    // before original I/O, even though its instance schema has the same size.
    let mut slots = plan.slots().to_vec();
    slots[0].mode = match slots[0].mode {
        VerifyMode::Hard => VerifyMode::Soft,
        VerifyMode::Soft => VerifyMode::Hard,
    };
    let changed = QSignaturePlan::new(slots).unwrap();
    let mut observed = Observed {
        source,
        fault: None,
        opens: Vec::new(),
    };
    assert!(
        admitted
            .qualify_with_member(&inputs, member, &changed, &mut observed, Some(compiled))
            .is_err()
    );
    assert!(observed.opens.is_empty());
    cases += 1;
    for maximum_rows in [0, admitted.entries[0].key.binding().n() - 1] {
        let mut limited = config;
        limited.maximum_rows = maximum_rows;
        let mut observed = Observed {
            source,
            fault: None,
            opens: Vec::new(),
        };
        assert!(
            admitted
                .qualify_with_member(
                    &QualificationInputs {
                        config: limited,
                        ..inputs
                    },
                    member,
                    &plan,
                    &mut observed,
                    Some(compiled)
                )
                .is_err()
        );
        assert!(observed.opens.is_empty());
        cases += 1;
    }
    // A successful retry after every refusal still compares the same exact seal.
    let (key, seal) = admitted
        .qualify_with_member(&inputs, member, &plan, source, Some(compiled))
        .unwrap();
    same_key(&key, &admitted.entries[0].key);
    assert!(
        seal.seal(member)
            .unwrap()
            .same_source(admitted.entries[0].seal.seal(member).unwrap())
    );
    cases + 1
}
