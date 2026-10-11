//! Genuine generated-chain receipts seed only missing child cursors and never fresh authority.

use super::*;
use crate::managed::{
    native_operation::{
        retain_carrier_progress,
        test_support::native_fixture::{NativeFixture, quote_instructions},
    },
    service_authority::{
        NetworkPurpose, ProviderPurpose,
        creating_original_tests::{fixture, limits},
    },
};
use crate::verify::finality::{FinalityAttestation, FinalitySource};
use iroha_data_model::{
    NetworkId,
    isi::{InstructionBox, Log},
    sumeragi_finality::SumeragiFinalityProof,
    transaction::SignedTransaction,
};
use iroha_fs::PublishMode;
use iroha_model_base::peer::PeerId;
use norito::core::DecodeBudgetContext;
use std::{
    cell::{Cell, RefCell},
    io,
    num::NonZeroU64,
    time::{Duration, Instant},
};

#[derive(Default)]
struct Reads {
    factories: RefCell<Vec<u64>>,
    proofs: RefCell<Vec<u64>>,
    challenges: RefCell<Vec<[u8; 32]>>,
}
struct Counted<'a> {
    native: &'a NativeFixture,
    reads: &'a Reads,
    fail: bool,
    after: Option<&'a dyn Fn()>,
}
impl FinalitySource for Counted<'_> {
    type Error = io::Error;
    fn finality_proof(&self, height: NonZeroU64) -> io::Result<SumeragiFinalityProof> {
        self.reads.proofs.borrow_mut().push(height.get());
        if self.fail {
            return Err(io::Error::other("selected source unavailable"));
        }
        self.native.finality_proof(height)
    }
    fn latest_attestation(
        &self,
        peer: &PeerId,
        challenge: &[u8; 32],
    ) -> io::Result<FinalityAttestation> {
        self.reads.challenges.borrow_mut().push(*challenge);
        if self.fail {
            return Err(io::Error::other("selected source unavailable"));
        }
        let result = self.native.latest_attestation(peer, challenge);
        if self.reads.challenges.borrow().len() == 1 {
            if let Some(after) = self.after {
                after();
            }
        }
        result
    }
}
fn observe(
    authority: &ServiceAuthority,
    native: &NativeFixture,
    reads: &Reads,
    fail: bool,
    after: Option<&dyn Fn()>,
) -> crate::managed::Result<FinalityVerifier> {
    authority
        .observe_finality_with_source(Instant::now() + Duration::from_secs(120), |height, _| {
            reads.factories.borrow_mut().push(height);
            Ok(Counted {
                native,
                reads,
                fail,
                after,
            })
        })
        .map(|(verifier, count)| {
            assert_eq!(count, 4);
            verifier
        })
}
#[inline(never)]
fn append(
    native: &mut NativeFixture,
    authority: &ServiceAuthority,
    message: &str,
) -> SignedTransaction {
    let transaction = quote_instructions(
        native,
        &authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            message.into(),
        ))],
    );
    assert_eq!(native.chain.commit(vec![transaction.clone()]), vec![true]);
    transaction
}
fn original_genesis(native: &NativeFixture, authority: &ServiceAuthority) -> FinalityVerifier {
    FinalityVerifier::from_genesis(
        &authority.genesis,
        &native.finality_proof(NonZeroU64::new(1).unwrap()).unwrap(),
    )
    .unwrap()
}
#[inline(never)]
fn retain_receipt(
    native: &NativeFixture,
    authority: &ServiceAuthority,
    transaction: &SignedTransaction,
) -> (PrivateDirectory, FinalityVerifier) {
    let directory = authority.directory.ensure_child("native-carrier").unwrap();
    let mut verifier = original_genesis(native, authority);
    let height = native.chain.height();
    let receipt = retain_carrier_progress(&directory, transaction, &mut verifier, height, native)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.height, height);
    assert_eq!(receipt.transaction_hash, transaction.hash());
    authority
        .remember_certificate(&directory, &verifier)
        .unwrap();
    (directory, verifier)
}
fn assert_new_challenge(reads: &Reads, previous: Option<[u8; 32]>) -> [u8; 32] {
    let challenges = reads.challenges.borrow();
    assert_eq!(challenges.len(), 4);
    let challenge = challenges[0];
    assert_ne!(challenge, [0; 32]);
    assert!(challenges.iter().all(|actual| *actual == challenge));
    assert_ne!(previous, Some(challenge));
    challenge
}

#[test]
fn native_receipt_seed_avoids_genesis_replay_but_keeps_each_fresh_quorum_and_retained_cursor() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let mut native = NativeFixture::from_generated(&parent.prepared, &parent);
    let scope = parent.begin_certificate_scope().unwrap();
    assert!(parent.begin_certificate_scope().is_err());
    let first =
        ServiceAuthority::open_network_from_original(&parent, NetworkPurpose::InitialReservePolicy)
            .unwrap();
    for index in 0..3 {
        append(&mut native, &parent, &format!("certified prefix {index}"));
    }
    let transaction = append(&mut native, &parent, "certified receipt");
    assert_eq!(native.chain.height(), 5);
    let (_carrier, _certified) = retain_receipt(&native, &first, &transaction);
    append(&mut native, &parent, "fresh successor");
    let second = ServiceAuthority::open_network_from_original(
        &parent,
        NetworkPurpose::InitialReputationPolicy,
    )
    .unwrap();
    assert!(
        !second
            .directory
            .path()
            .join("current-checkpoint.nrt")
            .exists()
    );
    let seeded = Reads::default();
    assert_eq!(
        observe(&second, &native, &seeded, false, None)
            .unwrap()
            .checkpoint()
            .height(),
        6
    );
    assert_eq!(*seeded.factories.borrow(), vec![5]);
    assert!(
        seeded.proofs.borrow().is_empty(),
        "only the attested H6 successor is needed"
    );
    let challenge = assert_new_challenge(&seeded, None);

    let standalone =
        ServiceAuthority::open_network(&parent.prepared, NetworkPurpose::GeneratedRuntime).unwrap();
    let original = Reads::default();
    assert_eq!(
        observe(&standalone, &native, &original, false, None)
            .unwrap()
            .checkpoint()
            .height(),
        6
    );
    assert_eq!(*original.proofs.borrow(), vec![1, 2, 3, 4, 5]);
    assert_new_challenge(&original, Some(challenge));

    // An existing earlier child cursor wins even when a newer shared certificate exists.
    let genesis = checkpoint_bytes(&original_genesis(&native, &parent)).unwrap();
    second
        .directory
        .write_atomic("current-checkpoint.nrt", &genesis, PublishMode::Replace)
        .unwrap();
    let retained = Reads::default();
    observe(&second, &native, &retained, false, None).unwrap();
    assert_eq!(*retained.factories.borrow(), vec![1]);
    assert_eq!(*retained.proofs.borrow(), vec![2, 3, 4, 5]);
    second
        .directory
        .write_atomic(
            "current-checkpoint.nrt",
            b"changed native cursor",
            PublishMode::Replace,
        )
        .unwrap();
    let malformed = Reads::default();
    assert!(observe(&second, &native, &malformed, false, None).is_err());
    assert!(
        malformed.factories.borrow().is_empty(),
        "bad retained bytes cannot fall back to the seed"
    );

    // An enclosing codec retains the original physical producer and allocation refusals.
    second
        .directory
        .remove_private("current-checkpoint.nrt")
        .unwrap();
    standalone
        .directory
        .remove_private("current-checkpoint.nrt")
        .unwrap();
    for allocated in [0, 1] {
        let baseline = DecodeBudgetContext::new(limits(allocated));
        let baseline_reads = Reads::default();
        let expected = baseline
            .with(|| observe(&standalone, &native, &baseline_reads, false, None))
            .err()
            .unwrap();
        let inherited = DecodeBudgetContext::new(limits(allocated));
        let inherited_reads = Reads::default();
        let actual = inherited
            .with(|| {
                assert!(second.certificate_seed().unwrap().is_none());
                let guard = second.begin_certificate_scope().unwrap();
                assert!(guard.progress.is_none());
                observe(&second, &native, &inherited_reads, false, None)
            })
            .err()
            .unwrap();
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(
            *inherited_reads.factories.borrow(),
            *baseline_reads.factories.borrow()
        );
        assert_eq!(
            *inherited_reads.proofs.borrow(),
            *baseline_reads.proofs.borrow()
        );
        assert_eq!(
            inherited.consumed_allocated_bytes(),
            baseline.consumed_allocated_bytes()
        );
    }
    let lease = second.certificate_seed().unwrap().unwrap();
    drop(scope);
    assert!(lease.revalidate().is_err());
    assert!(second.certificate_seed().unwrap().is_none());
    let closed = Reads::default();
    observe(&second, &native, &closed, false, None).unwrap();
    assert_eq!(*closed.proofs.borrow(), vec![1, 2, 3, 4, 5]);
    assert!(parent.certificate_scope.current().unwrap().is_none());
    assert!(parent.begin_certificate_scope().unwrap().progress.is_some());
}

#[test]
fn native_receipt_seed_refuses_unavailable_sources_foreign_networks_and_changed_custody() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let mut native = NativeFixture::from_generated(&parent.prepared, &parent);
    let scope = parent.begin_certificate_scope().unwrap();
    let first =
        ServiceAuthority::open_network_from_original(&parent, NetworkPurpose::InitialReservePolicy)
            .unwrap();
    let transaction = append(&mut native, &parent, "native source receipt");
    let (carrier, certified) = retain_receipt(&native, &first, &transaction);
    let provider = parent.manifest.providers[0].provider_id;
    let mut second =
        ServiceAuthority::open_provider_from_original(&parent, provider, ProviderPurpose::Custody)
            .unwrap();
    let absent = Reads::default();
    assert!(observe(&second, &native, &absent, true, None).is_err());
    assert_eq!(*absent.factories.borrow(), vec![2]);
    assert_eq!(absent.challenges.borrow().len(), 4);
    assert!(
        !second
            .directory
            .path()
            .join("current-checkpoint.nrt")
            .exists()
    );

    let wrong_carrier = first
        .directory
        .ensure_child("wrong-native-carrier")
        .unwrap();
    wrong_carrier
        .write_atomic(
            "carrier.nrt",
            b"different immutable record",
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(
        first
            .remember_certificate(&wrong_carrier, &certified)
            .is_err()
    );
    assert_eq!(
        second
            .certificate_seed()
            .unwrap()
            .unwrap()
            .verifier()
            .checkpoint()
            .height(),
        2
    );
    let entered = Cell::new(false);
    assert!(
        second
            .observe_finality_with_source::<Counted<'_>>(Instant::now(), |_, _| {
                entered.set(true);
                Err(invalid("expired source factory"))
            })
            .is_err()
    );
    assert!(
        !entered.get(),
        "a warmed certificate cannot extend the original deadline"
    );

    let original_network = second.config.network_id;
    second.config.network_id = NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(Hash::new(b"foreign certificate network")),
    );
    let foreign = Reads::default();
    assert!(observe(&second, &native, &foreign, false, None).is_err());
    assert!(foreign.factories.borrow().is_empty());
    assert!(second.remember_certificate(&carrier, &certified).is_err());
    second.config.network_id = original_network;
    // Same network bytes with a separately captured original are not the selected owner.
    let independent =
        ServiceAuthority::open_network(&parent.prepared, NetworkPurpose::GeneratedRuntime).unwrap();
    independent
        .certificate_scope
        .inherit(&parent.certificate_scope)
        .unwrap();
    assert!(independent.certificate_seed().is_err());

    let original = carrier.read("carrier.nrt", MAX_CHECKPOINT_BYTES).unwrap();
    // Unix detects replacement on exit; Windows keeps the native read handle nonreplaceable.
    let mutate = || {
        let replaced = carrier.write_atomic("carrier.nrt", &original, PublishMode::Replace);
        #[cfg(unix)]
        replaced.unwrap();
        #[cfg(windows)]
        assert!(
            replaced.is_err(),
            "retained Windows carrier excludes replacement"
        );
    };
    let replaced = Reads::default();
    let result = observe(&second, &native, &replaced, false, Some(&mutate));
    assert_eq!(replaced.challenges.borrow().len(), 4);
    #[cfg(unix)]
    {
        assert!(result.is_err());
        assert!(
            !second
                .directory
                .path()
                .join("current-checkpoint.nrt")
                .exists()
        );
        let changed = Reads::default();
        assert!(observe(&second, &native, &changed, false, None).is_err());
        assert!(
            changed.factories.borrow().is_empty(),
            "identical replacement bytes do not restore native custody"
        );
    }
    #[cfg(windows)]
    {
        assert_eq!(result.unwrap().checkpoint().height(), 2);
        second
            .directory
            .remove_private("current-checkpoint.nrt")
            .unwrap();
    }
    // A separate joined advance captures the still-genuine certificate under fresh custody.
    drop(scope);
    let _next_scope = parent.begin_certificate_scope().unwrap();
    first
        .certificate_scope
        .inherit(&parent.certificate_scope)
        .unwrap();
    second
        .certificate_scope
        .inherit(&parent.certificate_scope)
        .unwrap();
    first.remember_certificate(&carrier, &certified).unwrap();
    let called = Cell::new(false);
    let source_error = invalid("source factory refused").to_string();
    let failed_factory = second
        .observe_finality_with_source::<Counted<'_>>(
            Instant::now() + Duration::from_secs(120),
            |_, _| {
                called.set(true);
                mutate();
                Err(invalid("source factory refused"))
            },
        )
        .err()
        .unwrap();
    assert!(
        called.get(),
        "the ordinary source constructor error was reached"
    );
    #[cfg(unix)]
    assert_ne!(
        failed_factory.to_string(),
        source_error,
        "native exit custody failure supersedes an ordinary source error"
    );
    #[cfg(windows)]
    assert_eq!(failed_factory.to_string(), source_error);
    assert!(
        !second
            .directory
            .path()
            .join("current-checkpoint.nrt")
            .exists()
    );
}

// Original generated validator custody signs another exact-quorum witness. The conflicting
// branch is an explicit negative certificate claim: Core did not execute its altered World
// result. It exercises rejection of mutually inconsistent, genuinely signed decision evidence.
#[inline(never)]
fn alternate_certificate(
    native: &NativeFixture,
    authority: &ServiceAuthority,
    original: &FinalityVerifier,
    conflicting_result: bool,
) -> FinalityVerifier {
    use iroha_core::sumeragi::test_chain::Signers;
    use iroha_data_model::block::{CommitCertificate, decode_framed_signed_block};

    let verified = original.verified_tip_ref().unwrap();
    let mut proof = original.checkpoint().tip().clone();
    let mut block = decode_framed_signed_block(&proof.block_wire).unwrap();
    let old = block.commit_certificate().unwrap();
    let header = old.consensus_header().to_vec();
    let availability = old.availability().to_vec();
    let mut commitment = verified.commitment().clone();
    if conflicting_result {
        commitment.execution.world_state_root = Hash::new(b"conflicting native certificate claim");
        assert_ne!(
            commitment.execution.world_state_root,
            verified.execution().world_state_root
        );
    }
    let qc = native.chain.commit_qc(
        verified.height(),
        verified.core_hash(),
        commitment.result().unwrap(),
        Signers::LastThree,
    );
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        header,
        norito::encode_canonical(&qc).unwrap(),
        commitment.preimage().unwrap(),
        availability,
    )));
    proof.block_wire = block.encode_wire().unwrap();
    assert_eq!(proof.block_header, original.checkpoint().tip().block_header);
    assert_ne!(proof.block_wire, original.checkpoint().tip().block_wire);
    // Independently authenticate the candidate from the original generated genesis; a decoded
    // or caller-supplied result never manufactures the opaque identity used by the selector.
    let mut candidate = original_genesis(native, authority);
    candidate.advance(native, &proof).unwrap();
    candidate
}
fn retain_alternate(
    authority: &ServiceAuthority,
    name: &str,
    candidate: &FinalityVerifier,
    transaction: &SignedTransaction,
) -> PrivateDirectory {
    crate::managed::native_operation::verify_carrier(candidate, transaction).unwrap();
    let directory = authority.directory.ensure_child(name).unwrap();
    directory
        .write_atomic(
            "carrier.nrt",
            &checkpoint_bytes(candidate).unwrap(),
            PublishMode::CreateNew,
        )
        .unwrap();
    directory
}

#[test]
fn certificate_selection_binds_native_execution_and_accepts_alternate_quorum_witnesses() {
    let _resources = crate::managed::native_test_guard();
    let (_temporary, parent) = fixture();
    let mut native = NativeFixture::from_generated(&parent.prepared, &parent);
    let _scope = parent.begin_certificate_scope().unwrap();
    let first =
        ServiceAuthority::open_network_from_original(&parent, NetworkPurpose::InitialReservePolicy)
            .unwrap();
    let transaction = append(&mut native, &parent, "certified decision identity");
    let (_directory, original) = retain_receipt(&native, &first, &transaction);
    let original_decision = original.verified_tip_ref().unwrap().context_id();

    let alternate = alternate_certificate(&native, &first, &original, false);
    assert_eq!(
        alternate.verified_tip_ref().unwrap().context_id(),
        original_decision
    );
    let alternate_directory =
        retain_alternate(&first, "alternate-witness", &alternate, &transaction);
    first
        .remember_certificate(&alternate_directory, &alternate)
        .unwrap();
    let retained = parent.certificate_seed().unwrap().unwrap();
    assert_eq!(retained.verifier().checkpoint(), original.checkpoint());

    let conflict = alternate_certificate(&native, &first, &original, true);
    assert_eq!(
        conflict.verified_tip_ref().unwrap().header(),
        original.verified_tip_ref().unwrap().header()
    );
    assert_eq!(
        conflict.verified_tip_ref().unwrap().core_hash(),
        original.verified_tip_ref().unwrap().core_hash()
    );
    assert_ne!(
        conflict.verified_tip_ref().unwrap().context_id(),
        original_decision
    );
    let conflicting_directory =
        retain_alternate(&first, "conflicting-result", &conflict, &transaction);
    assert!(
        first
            .remember_certificate(&conflicting_directory, &conflict)
            .is_err(),
        "identical Iroha headers cannot hide a different certified execution result"
    );
    assert_eq!(
        parent
            .certificate_seed()
            .unwrap()
            .unwrap()
            .verifier()
            .verified_tip_ref()
            .unwrap()
            .context_id(),
        original_decision
    );

    let next = append(&mut native, &parent, "new certified successor");
    let second = ServiceAuthority::open_network_from_original(
        &parent,
        NetworkPurpose::InitialReputationPolicy,
    )
    .unwrap();
    let (_next_directory, successor) = retain_receipt(&native, &second, &next);
    assert_eq!(
        parent
            .certificate_seed()
            .unwrap()
            .unwrap()
            .verifier()
            .checkpoint()
            .height(),
        3
    );
    assert_eq!(
        parent
            .certificate_seed()
            .unwrap()
            .unwrap()
            .verifier()
            .verified_tip_ref()
            .unwrap()
            .context_id(),
        successor.verified_tip_ref().unwrap().context_id()
    );
    first
        .remember_certificate(&alternate_directory, &alternate)
        .unwrap();
    assert_eq!(
        parent
            .certificate_seed()
            .unwrap()
            .unwrap()
            .verifier()
            .checkpoint()
            .height(),
        3,
        "an older valid receipt cannot move the shared prefix backwards"
    );
    // The previous immutable native lease remains valid while its own observation is live.
    retained.revalidate().unwrap();
}
