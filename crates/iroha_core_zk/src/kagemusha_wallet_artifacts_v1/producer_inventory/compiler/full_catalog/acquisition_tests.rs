//! Genuine complete-catalog Q/Omega acquisition controls, without additional proofs.
//!
//! This child runs only after the production complete-source qualifier returned its
//! opaque grant. Faults wrap original streams; they never mutate retained files,
//! change signed metadata, manufacture source authority or allocate a whole PK.

use std::{cell::Cell, io};

use super::*;
use iroha_kagemusha_proof::a_relation::schedule::compiled::OperationRoute;
use iroha_pasta::CancellationToken;

#[derive(Clone, Copy)]
enum Selection {
    Q(OperationRoute, usize),
    Omega,
}

impl Selection {
    fn original(self, qualified: &QualifiedWalletSourcesV1) -> OriginalV1 {
        let index = match self {
            Self::Q(route, stage) => {
                let (_, _, program) = qualified.route(route).unwrap().identity();
                qualified.inventory().operations[usize::try_from(program).unwrap()].q[stage]
            }
            Self::Omega => qualified.inventory().omega,
        };
        *qualified.inventory().member(index).unwrap()
    }

    fn rows(self, qualified: &QualifiedWalletSourcesV1) -> usize {
        match self {
            Self::Q(route, stage) => qualified.q(route).unwrap().keys()[stage].binding().n(),
            Self::Omega => qualified.omega().key().binding().n(),
        }
    }

    fn acquire(
        self,
        qualified: &QualifiedWalletSourcesV1,
        source: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        cancellation: Option<&CancellationToken>,
    ) -> Result<(), WalletSourcesErrorV1> {
        match self {
            Self::Q(route, stage) => {
                let owner =
                    qualified.import_q_cancellable(route, stage, source, config, cancellation)?;
                let expected = &qualified.q(route).unwrap().keys()[stage];
                assert!(std::ptr::eq(owner.binding(), expected.binding()));
                let key = match &owner {
                    ImportedQV1::Sigma(owner) => {
                        assert_eq!(stage, 0, "Q0 must use its actual sigma owner");
                        owner.verifying_key()
                    }
                    ImportedQV1::Signature(owner) => {
                        assert!(stage > 0, "later Q must use its actual signature owner");
                        owner.verifying_key()
                    }
                };
                assert!(std::ptr::eq(key, expected.key()));
            }
            Self::Omega => {
                let owner = qualified.import_omega_cancellable(source, config, cancellation)?;
                let expected = qualified.omega();
                assert!(std::ptr::eq(owner.binding(), expected.key().binding()));
                assert!(std::ptr::eq(owner.verifying_key(), expected.key().key()));
                assert_eq!(
                    owner
                        .verifying_key()
                        .kagemusha_digest(owner.binding())
                        .unwrap(),
                    expected
                        .key()
                        .key()
                        .kagemusha_digest(expected.key().binding())
                        .unwrap()
                );
            }
        }
        Ok(())
    }

    fn require_inventory(self, error: WalletSourcesErrorV1) {
        assert!(!error.is_cancelled());
        assert!(!error.is_unavailable());
        match self {
            Self::Q(..) => assert!(matches!(
                error,
                WalletSourcesErrorV1::Original(Error::Inventory)
            )),
            Self::Omega => assert!(matches!(
                error,
                WalletSourcesErrorV1::Omega(OmegaQualificationErrorV1::Original(Error::Inventory))
            )),
        }
    }

    fn require_unavailable(self, error: WalletSourcesErrorV1) {
        assert!(!error.is_cancelled());
        assert!(error.is_unavailable());
        match self {
            Self::Q(..) => assert!(matches!(
                error,
                WalletSourcesErrorV1::Original(Error::Unavailable)
            )),
            Self::Omega => assert!(matches!(
                error,
                WalletSourcesErrorV1::Omega(OmegaQualificationErrorV1::Original(
                    Error::Unavailable
                ))
            )),
        }
    }
}

#[derive(Clone, Copy)]
enum Fault {
    Missing,
    Changed,
}

struct Observed<'a> {
    source: &'a mut dyn OriginalSourceV1,
    fault: Option<([u8; 32], Fault)>,
    opens: Vec<[u8; 32]>,
    flipped: Cell<bool>,
}
impl<'a> Observed<'a> {
    fn new(source: &'a mut dyn OriginalSourceV1, fault: Option<([u8; 32], Fault)>) -> Self {
        Self {
            source,
            fault,
            opens: Vec::new(),
            flipped: Cell::new(false),
        }
    }
}

struct ChangedReader<'a> {
    original: Box<dyn Read + 'a>,
    flipped: &'a Cell<bool>,
}
impl Read for ChangedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.original.read(output)?;
        if count > 0 && !self.flipped.replace(true) {
            output[0] ^= 1;
        }
        Ok(count)
    }
}
impl OriginalSourceV1 for Observed<'_> {
    fn open(&mut self, digest: [u8; 32]) -> Result<Box<dyn Read + '_>, Error> {
        self.opens.push(digest);
        match self.fault.filter(|(selected, _)| *selected == digest) {
            Some((_, Fault::Missing)) => Err(Error::Unavailable),
            Some((_, Fault::Changed)) => Ok(Box::new(ChangedReader {
                original: self.source.open(digest)?,
                flipped: &self.flipped,
            })),
            None => self.source.open(digest),
        }
    }
}

fn exercise(
    selected: Selection,
    qualified: &QualifiedWalletSourcesV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
) {
    let original = selected.original(qualified);
    let roles = [
        original.descriptor,
        original.verifying_key,
        original.proving_key,
    ];
    let hashes = roles.map(|role| role.sha256);
    for (index, digest) in hashes.iter().enumerate() {
        assert!(!hashes[..index].contains(digest), "distinct original roles");
    }
    let rows = selected.rows(qualified);
    let extent = usize::try_from(roles.iter().map(|role| role.bytes).max().unwrap()).unwrap();
    assert!(rows > 0 && config.maximum_rows >= rows);
    assert!(extent > 0 && config.maximum_bytes >= extent);

    // Establish successful acquisition of these exact originals before faults.
    let mut observed = Observed::new(source, None);
    selected
        .acquire(qualified, &mut observed, config, None)
        .unwrap();
    assert_eq!(observed.opens, hashes);
    assert!(!observed.flipped.get());
    drop(observed);

    let mut row_cap = config;
    row_cap.maximum_rows = rows - 1;
    let mut byte_cap = config;
    byte_cap.maximum_bytes = extent - 1;
    for cap in [row_cap, byte_cap] {
        let mut observed = Observed::new(source, None);
        selected.require_inventory(
            selected
                .acquire(qualified, &mut observed, cap, None)
                .unwrap_err(),
        );
        assert!(
            observed.opens.is_empty(),
            "current caps precede all source I/O"
        );
    }
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let mut observed = Observed::new(source, None);
    assert!(
        selected
            .acquire(qualified, &mut observed, config, Some(&cancellation))
            .is_err_and(|error| error.is_cancelled())
    );
    assert!(
        observed.opens.is_empty(),
        "pre-cancelled acquisition opens nothing"
    );
    drop(observed);

    for (role, digest) in hashes.iter().enumerate() {
        for fault in [Fault::Missing, Fault::Changed] {
            let mut observed = Observed::new(source, Some((*digest, fault)));
            let error = selected
                .acquire(qualified, &mut observed, config, None)
                .unwrap_err();
            match fault {
                Fault::Missing => {
                    selected.require_unavailable(error);
                    assert!(!observed.flipped.get());
                }
                Fault::Changed => {
                    selected.require_inventory(error);
                    assert!(observed.flipped.get(), "actual selected stream changed");
                }
            }
            assert_eq!(
                observed.opens,
                hashes[..=role],
                "stop at the failed role; no fallback"
            );
        }
    }
    // All faults were reader-only. The same admitted owner must revalidate and
    // return its original borrowed metadata again, rather than cache a refusal.
    let mut observed = Observed::new(source, None);
    selected
        .acquire(qualified, &mut observed, config, None)
        .unwrap();
    assert_eq!(observed.opens, hashes);
    assert!(!observed.flipped.get());
}

pub(super) fn run(
    qualified: &QualifiedWalletSourcesV1,
    source: &mut dyn OriginalSourceV1,
    config: ReadConfig,
) -> usize {
    let route = compiled_routes()
        .into_iter()
        .next()
        .expect("complete canonical routes");
    assert!(qualified.q(route).unwrap().keys().len() >= 2);
    // Canonical Q0/Q1 exercise the two actual dispatcher variants, and the sole
    // complete-catalog Omega uses its separately qualified terminal graph.
    for selected in [
        Selection::Q(route, 0),
        Selection::Q(route, 1),
        Selection::Omega,
    ] {
        exercise(selected, qualified, source, config);
    }
    3
}
