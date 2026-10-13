mod axt_unanchored_admission_tests {
    //! Local FASTPQ allocation failure is an operational deferral, not a proof rejection.

    use super::*;

    #[test]
    fn local_fastpq_allocation_refusal_does_not_record_axt_rejection() {
        let mut host = CoreHost::new(ALICE_ID.clone());
        let dsid = DataSpaceId::new(113);
        let lane = LaneId::new(1);
        host.clear_axt_reject();
        let deferred = host.map_axt_fastpq_error(
            fastpq_prover::Error::LocalAllocationUnavailable {
                context: "axt test allocation",
            },
            "FASTPQ verification failed",
            dsid,
            lane,
        );
        assert!(
            matches!((&(deferred), &(VMError::ExecutionDeferred(ivm::error::ExecutionDeferral::AllocationUnavailable))), (VMError::ExecutionDeferred(__actual_0), VMError::ExecutionDeferred(__expected_0)) if __actual_0 == __expected_0)
        );
        assert!(host.take_axt_reject_for_tests().is_none());
        assert!(matches!(
            (
                &(host.map_axt_fastpq_error(
                    fastpq_prover::Error::CommitmentMismatch,
                    "FASTPQ verification failed",
                    dsid,
                    lane,
                )),
                &(VMError::PermissionDenied)
            ),
            (VMError::PermissionDenied, VMError::PermissionDenied)
        ));
        assert_eq!(
            host.take_axt_reject_for_tests()
                .expect("invalid proof records rejection")
                .reason,
            AxtRejectReason::Proof
        );
    }
}
