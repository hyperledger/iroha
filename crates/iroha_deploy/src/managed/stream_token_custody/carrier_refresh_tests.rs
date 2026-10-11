//! Post-Applied decision coverage with the existing real native Configure H2-to-H3 fixture.
//! This exercises the shared decision and native proof owners, not coordinator HTTP integration.

use super::*;
use crate::{
    managed::native_operation::{CarrierTarget, MAX_CHECKPOINT_BYTES},
    verify::finality::{FinalityAttestation, FinalitySource},
};
use iroha_data_model::sumeragi_finality::SumeragiFinalityProof;
use iroha_model_base::peer::PeerId;
use iroha_wallet::operations::OperationReport;
use std::{cell::Cell, io};

struct CountedProof<'a> {
    native: Option<&'a NativeFixture>,
    reads: &'a Cell<usize>,
}
impl FinalitySource for CountedProof<'_> {
    type Error = io::Error;

    fn finality_proof(&self, height: NonZeroU64) -> io::Result<SumeragiFinalityProof> {
        self.reads.set(self.reads.get() + 1);
        match self.native {
            Some(native) => native.finality_proof(height),
            None => Err(io::Error::other("native proof unavailable")),
        }
    }

    fn latest_attestation(&self, _: &PeerId, _: &[u8; 32]) -> io::Result<FinalityAttestation> {
        Err(io::Error::other(
            "carrier replay cannot replace the fresh quorum",
        ))
    }
}
fn clear_carrier(directory: &PrivateDirectory) {
    directory.remove_private("replay.nrt").unwrap();
    directory.remove_private("carrier.nrt").unwrap();
}
fn limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64)
}

pub(super) fn retain_after_applied(
    owner: &mut ManagedStreamTokenCustody,
    original: &Selected<Original>,
    signed: &SignedTransaction,
    native: &NativeFixture,
    before: &FinalityVerifier,
    deadline: Instant,
    expected: ManagedTransactionFinality,
) {
    let directory = original.directory();
    let authorization = directory.read("authorization.nrt", 64 * 1024).unwrap();
    let wire = signed.encode_wire_v1().unwrap();
    assert_eq!(before.checkpoint().height(), 2);
    assert_eq!(native.chain.height(), 3);
    assert_eq!(expected.height, 3);
    assert!(!directory.path().join("carrier.nrt").exists());
    // The hint comes from the fixture's actual successful native commit. As in production,
    // Applied is only a replay lookup hint and cannot supply successful inclusion itself.
    let report = OperationReport {
        status: OperationStatus::Applied,
        data: norito::json!({ "evidence": { "block_height": (native.chain.height()) } }),
    };
    // This is exactly the old production call: its pre-submission H2 frontier refuses H3
    // before reading any source, so repeating that bound cannot retain this carrier.
    assert!(
        owner
            .authority
            .advance_carrier(
                directory,
                &original.checkpoint,
                signed,
                &report,
                before,
                deadline,
            )
            .unwrap()
            .is_none()
    );

    assert!(
        applied_carrier(
            &mut owner.authority,
            OperationStatus::Pending,
            deadline,
            |_, _| panic!("pending is not an Applied carrier request"),
            |_, _, _| panic!("pending cannot replay"),
        )
        .unwrap()
        .is_none()
    );
    assert!(
        applied_carrier(
            &mut owner.authority,
            report.status,
            deadline,
            |_, passed| {
                assert_eq!(passed, deadline);
                Err(invalid("fresh finality unavailable"))
            },
            |_, _, _| panic!("an Applied hint cannot replace a fresh observation"),
        )
        .unwrap()
        .is_none()
    );
    // The real observation owner rejects the original expired deadline before source access.
    let elapsed = Instant::now() - Duration::from_secs(1);
    assert!(
        applied_carrier(
            &mut owner.authority,
            report.status,
            elapsed,
            ServiceAuthority::observe_finality,
            |_, _, _| panic!("an elapsed original budget cannot replay"),
        )
        .unwrap()
        .is_none()
    );
    assert!(!directory.path().join("carrier.nrt").exists());

    let observations = Cell::new(0);
    let fresh = |authority: &mut ServiceAuthority, passed: Instant| {
        assert_eq!(passed, deadline, "no replacement operation budget");
        require_deadline(passed).unwrap();
        observations.set(observations.get() + 1);
        // Fresh independent node signatures, full native prefix verification and exact tip;
        // this never promotes the wallet's Applied report into authenticated finality.
        Ok(native.observe(authority))
    };
    let proof_reads = Cell::new(0);
    let constructors = Cell::new(0);
    let advance = |authority: &ServiceAuthority,
                   observed: &FinalityVerifier,
                   selected: &SignedTransaction,
                   original_checkpoint: &[u8],
                   height: u64,
                   replay_only: bool,
                   source: Option<&NativeFixture>,
                   passed: Instant| {
        authority.advance_carrier_with_source(
            directory,
            original_checkpoint,
            selected,
            CarrierTarget {
                height,
                observed_height: observed.checkpoint().height(),
                observed: (!replay_only).then_some(observed),
                deadline: passed,
            },
            |_, source_deadline| {
                constructors.set(constructors.get() + 1);
                assert_eq!(source_deadline, passed);
                require_deadline(source_deadline)?;
                Ok(CountedProof {
                    native: source,
                    reads: &proof_reads,
                })
            },
        )
    };
    let observed = fresh(&mut owner.authority, deadline).unwrap();
    let checkpoint = checkpoint_bytes(&observed).unwrap();
    // The full replay remains the native byte/result oracle and requests exactly H3.
    let expected_replay = advance(
        &owner.authority,
        &observed,
        signed,
        &original.checkpoint,
        3,
        true,
        Some(native),
        deadline,
    )
    .unwrap();
    assert_eq!(expected_replay, Some(expected));
    assert_eq!(proof_reads.replace(0), 1);
    assert_eq!(constructors.replace(0), 1);
    let replay_bytes = directory.read("carrier.nrt", MAX_CHECKPOINT_BYTES).unwrap();
    assert_eq!(replay_bytes.as_slice(), checkpoint.as_slice());
    clear_carrier(directory);

    // This is the intentional contract change: the complete fresh native quorum receipt
    // supplies its exact immediately succeeding block without a redundant proof response.
    // The source constructor still runs under the original deadline and profile custody.
    let prior_observations = observations.get();
    let finalized = applied_carrier(
        &mut owner.authority,
        report.status,
        deadline,
        fresh,
        |authority, observed, passed| {
            advance(
                authority,
                observed,
                signed,
                &original.checkpoint,
                3,
                false,
                None,
                passed,
            )
        },
    )
    .unwrap();
    assert_eq!(observations.get(), prior_observations + 1);
    assert_eq!(finalized, Some(expected));
    assert_eq!(proof_reads.replace(0), 0);
    assert_eq!(constructors.replace(0), 1);
    assert_eq!(
        directory.read("carrier.nrt", MAX_CHECKPOINT_BYTES).unwrap(),
        replay_bytes
    );
    clear_carrier(directory);
    // The selected transport constructor is still a required boundary on eligible reuse.
    let construction = owner.authority.advance_carrier_with_source(
        directory,
        &original.checkpoint,
        signed,
        CarrierTarget {
            height: 3,
            observed_height: 3,
            observed: Some(&observed),
            deadline,
        },
        |_, _| -> Result<CountedProof<'_>> { Err(invalid("original carrier source refused")) },
    );
    assert_eq!(
        construction.unwrap_err().to_string(),
        invalid("original carrier source refused").to_string()
    );
    assert!(!directory.path().join("carrier.nrt").exists());
    assert!(!directory.path().join("replay.nrt").exists());

    // Existing progress, even its original H2, retains its independently read replay owner.
    directory
        .write_atomic("replay.nrt", &original.checkpoint, PublishMode::CreateNew)
        .unwrap();
    assert!(
        advance(
            &owner.authority,
            &observed,
            signed,
            &original.checkpoint,
            3,
            false,
            None,
            deadline,
        )
        .is_err()
    );
    assert_eq!(proof_reads.replace(0), 1);
    assert_eq!(constructors.replace(0), 1);
    assert!(!directory.path().join("carrier.nrt").exists());
    clear_carrier(directory);
    directory
        .write_atomic(
            "replay.nrt",
            b"changed original replay",
            PublishMode::CreateNew,
        )
        .unwrap();
    assert!(
        advance(
            &owner.authority,
            &observed,
            signed,
            &original.checkpoint,
            3,
            false,
            Some(native),
            deadline,
        )
        .is_err()
    );
    assert_eq!(proof_reads.replace(0), 0);
    assert_eq!(constructors.replace(0), 0);
    clear_carrier(directory);

    // Wrong heights cannot borrow the observed decision. A genuine larger gap still reads
    // every successor from the original selected genesis checkpoint and fails if unavailable.
    for height in [1, 2] {
        assert!(
            advance(
                &owner.authority,
                &observed,
                signed,
                &original.checkpoint,
                height,
                false,
                None,
                deadline,
            )
            .is_err()
        );
    }
    assert!(
        advance(
            &owner.authority,
            &observed,
            signed,
            &original.checkpoint,
            4,
            false,
            None,
            deadline,
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(constructors.replace(0), 0);
    let genesis = native.finality_proof(NonZeroU64::new(1).unwrap()).unwrap();
    let genesis = FinalityVerifier::from_genesis(&owner.authority.genesis, &genesis).unwrap();
    let genesis_bytes = checkpoint_bytes(&genesis).unwrap();
    // H1 is not an opaque certified Global execution parent; even an exact H2 observation
    // retains its original source replay rather than attempting the non-genesis handoff.
    assert!(
        advance(
            &owner.authority,
            before,
            signed,
            &genesis_bytes,
            2,
            false,
            None,
            deadline,
        )
        .is_err()
    );
    assert_eq!(proof_reads.replace(0), 1);
    assert_eq!(constructors.replace(0), 1);
    clear_carrier(directory);
    for height in [2, 3] {
        assert!(
            advance(
                &owner.authority,
                &observed,
                signed,
                &genesis_bytes,
                height,
                false,
                None,
                deadline,
            )
            .is_err()
        );
        assert_eq!(proof_reads.replace(0), 1);
        assert_eq!(constructors.replace(0), 1);
        clear_carrier(directory);
    }
    let mut corrupt = original.checkpoint.clone();
    corrupt[0] ^= 1;
    assert!(
        advance(
            &owner.authority,
            &observed,
            signed,
            &corrupt,
            3,
            false,
            None,
            deadline,
        )
        .is_err()
    );
    assert_eq!(constructors.replace(0), 0);

    // Even genuine fresh H3 finality cannot retain another correctly signed envelope.
    // Keep replay publication before membership verification, exactly as the original path.
    let other = quote_instructions(
        native,
        &owner.authority.config,
        [InstructionBox::from(Log::new(
            iroha_data_model::Level::INFO,
            "not the retained custody operation".into(),
        ))],
    );
    assert_ne!(other.hash(), signed.hash());
    assert!(
        advance(
            &owner.authority,
            &observed,
            &other,
            &original.checkpoint,
            3,
            false,
            None,
            deadline,
        )
        .is_err()
    );
    assert_eq!(proof_reads.replace(0), 0);
    assert_eq!(constructors.replace(0), 1);
    assert_eq!(
        directory
            .read("replay.nrt", MAX_CHECKPOINT_BYTES)
            .unwrap()
            .as_slice(),
        checkpoint.as_slice()
    );
    assert!(!directory.path().join("carrier.nrt").exists());
    clear_carrier(directory);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        struct RestoreMode(std::path::PathBuf, std::fs::Permissions);
        impl Drop for RestoreMode {
            fn drop(&mut self) {
                std::fs::set_permissions(&self.0, self.1.clone()).unwrap();
            }
        }
        let path = owner.authority.directory.path().to_path_buf();
        let mode = std::fs::metadata(&path).unwrap().permissions();
        let restore = RestoreMode(path.clone(), mode);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            advance(
                &owner.authority,
                &observed,
                signed,
                &original.checkpoint,
                3,
                false,
                None,
                deadline,
            )
            .is_err()
        );
        assert!(!directory.path().join("carrier.nrt").exists());
        drop(restore);
        proof_reads.set(0);
        constructors.set(0);
    }
    assert!(
        advance(
            &owner.authority,
            &observed,
            signed,
            &original.checkpoint,
            3,
            false,
            None,
            elapsed,
        )
        .is_err()
    );
    assert_eq!(proof_reads.replace(0), 0);
    assert_eq!(constructors.replace(0), 1);
    assert!(!directory.path().join("carrier.nrt").exists());

    // Active Norito callers keep the complete original replay and physical charge recipe,
    // even when the same fresh observed owner would qualify outside their inherited scope.
    assert!(
        norito::with_decode_limits_scope(limits(usize::MAX), || advance(
            &owner.authority,
            &observed,
            signed,
            &original.checkpoint,
            3,
            false,
            None,
            deadline,
        ))
        .is_err()
    );
    assert_eq!(proof_reads.replace(0), 1);
    assert_eq!(constructors.replace(0), 1);
    let (baseline, old_usage) =
        norito::core::with_decode_limits_measured(limits(usize::MAX), || {
            advance(
                &owner.authority,
                &observed,
                signed,
                &original.checkpoint,
                3,
                true,
                Some(native),
                deadline,
            )
        });
    assert_eq!(baseline.unwrap(), Some(expected));
    assert_eq!(proof_reads.replace(0), 1);
    assert_eq!(constructors.replace(0), 1);
    clear_carrier(directory);
    let (actual, new_usage) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
        advance(
            &owner.authority,
            &observed,
            signed,
            &original.checkpoint,
            3,
            false,
            Some(native),
            deadline,
        )
    });
    assert_eq!(actual.unwrap(), Some(expected));
    assert_eq!(new_usage, old_usage);
    assert_eq!(proof_reads.replace(0), 1);
    assert_eq!(constructors.replace(0), 1);
    clear_carrier(directory);
    let exact = old_usage.total_allocated_bytes();
    assert!(exact > 1);
    for allocation in [0, 1, exact - 1] {
        let old = norito::with_decode_limits_scope(limits(allocation), || {
            advance(
                &owner.authority,
                &observed,
                signed,
                &original.checkpoint,
                3,
                true,
                Some(native),
                deadline,
            )
        })
        .err()
        .expect("original active budget refuses");
        let old_reads = proof_reads.replace(0);
        let old_constructors = constructors.replace(0);
        clear_carrier(directory);
        let new = norito::with_decode_limits_scope(limits(allocation), || {
            advance(
                &owner.authority,
                &observed,
                signed,
                &original.checkpoint,
                3,
                false,
                Some(native),
                deadline,
            )
        })
        .err()
        .expect("observed active budget refuses");
        assert_eq!(new.to_string(), old.to_string());
        assert_eq!(proof_reads.replace(0), old_reads);
        assert_eq!(constructors.replace(0), old_constructors);
        clear_carrier(directory);
    }
    let (retried, usage) = norito::core::with_decode_limits_measured(limits(exact), || {
        advance(
            &owner.authority,
            &observed,
            signed,
            &original.checkpoint,
            3,
            false,
            Some(native),
            deadline,
        )
    });
    assert_eq!(retried.unwrap(), Some(expected));
    assert_eq!(usage, old_usage);
    assert_eq!(proof_reads.replace(0), 1);
    assert_eq!(constructors.replace(0), 1);
    assert_eq!(
        owner
            .authority
            .retained_finality(directory, signed)
            .unwrap(),
        Some(expected)
    );
    assert_eq!(
        directory.read("authorization.nrt", 64 * 1024).unwrap(),
        authorization
    );
    assert_eq!(signed.encode_wire_v1().unwrap(), wire);
    assert!(
        !directory
            .path()
            .join("transaction/submission.json")
            .exists(),
        "read-only evidence retention never acquires another dispatch authorization"
    );
}
