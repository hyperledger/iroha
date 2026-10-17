//! Keep local custody failures distinct from unavailable heights and malformed peer references.

use super::*;
use iroha_data_model::{
    parameter::system::SumeragiParameters,
    sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneRecord},
};
use iroha_model_base::topology::DataSpaceId;
use std::io;

#[derive(Debug, thiserror::Error)]
#[error("exact original lane I/O failure")]
struct OriginalFailure;
struct Source {
    wait_error: bool,
    read_error: bool,
    available: bool,
    block: bool,
    kind: io::ErrorKind,
}
impl LaneBlockSource for Source {
    fn tip(
        &self,
        _: LaneId,
        _: &[u8; 32],
    ) -> Result<Option<u64>, crate::execution_attempt::ExecutionAttemptError<io::Error>> {
        Ok(Some(1))
    }
    fn block(
        &self,
        _: LaneId,
        _: &[u8; 32],
        _: u64,
    ) -> Result<
        Option<CommittedLaneBlock>,
        crate::execution_attempt::ExecutionAttemptError<io::Error>,
    > {
        if self.read_error {
            return Err(io::Error::new(self.kind, OriginalFailure).into());
        }
        Ok(self.block.then_some(CommittedLaneBlock {
            block_hash: Hash32([1; 32]),
            result: Hash32([2; 32]),
            batch: None,
        }))
    }
    fn wait_for(
        &self,
        _: LaneId,
        _: &[u8; 32],
        _: u64,
        _: Duration,
    ) -> Result<bool, crate::execution_attempt::ExecutionAttemptError<io::Error>> {
        if self.wait_error {
            return Err(io::Error::new(self.kind, OriginalFailure).into());
        }
        Ok(self.available)
    }
}
fn inputs() -> (SumeragiLaneMerge, SumeragiLaneState, SumeragiLanePolicy) {
    let lane = LaneId::new(2);
    let incarnation = [9; 32];
    let merge = SumeragiLaneMerge {
        lane,
        incarnation,
        from: 1,
        to: 1,
        tip_hash: [1; 32],
        tip_result: [2; 32],
    };
    let record = SumeragiLaneRecord {
        lane,
        dataspace: DataSpaceId::new(0),
        incarnation,
        params: SumeragiParameters::default(),
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        committee: Vec::new(),
        created_at: 0,
        active_from: 2,
        closing: None,
        anchor_freshness: 16,
        merged: SumeragiLaneFrontier {
            height: 0,
            block_hash: [0; 32],
            result: [0; 32],
        },
        merged_at: 2,
        rescued: 0,
    };
    (
        merge,
        SumeragiLaneState {
            lanes: vec![record],
            ..Default::default()
        },
        SumeragiLanePolicy::for_chain(
            SumeragiParameters::default(),
            iroha_sumeragi::availability::recommended_data_availability_layout(),
        ),
    )
}
#[test]
fn wait_and_read_errors_preserve_original_io_source_including_would_block() {
    let (merge, lanes, policy) = inputs();
    for kind in [
        io::ErrorKind::InvalidData,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::WouldBlock,
    ] {
        for wait_error in [true, false] {
            let source = Source {
                wait_error,
                read_error: !wait_error,
                available: true,
                block: true,
                kind,
            };
            let MergeError::Storage(Attempt::Rejected(error)) =
                load(&[merge], &lanes, &policy, 3, &source, Duration::ZERO).unwrap_err()
            else {
                panic!("storage is neither malformed consensus nor absent")
            };
            assert_eq!(error.kind(), kind);
            assert!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<OriginalFailure>()
                    .is_some()
            );
        }
    }
}
#[test]
fn absence_invalid_reference_and_byzantine_certified_batch_remain_distinct() {
    let (merge, lanes, policy) = inputs();
    let source = Source {
        wait_error: false,
        read_error: false,
        available: false,
        block: false,
        kind: io::ErrorKind::Other,
    };
    assert!(matches!(
        load(&[merge], &lanes, &policy, 3, &source, Duration::ZERO),
        Err(MergeError::Pending(_))
    ));
    let source = Source {
        available: true,
        ..source
    };
    assert!(matches!(
        load(&[merge], &lanes, &policy, 3, &source, Duration::ZERO),
        Err(MergeError::Pending(_))
    ));
    let source = Source {
        block: true,
        ..source
    };
    let blocks = load(&[merge], &lanes, &policy, 3, &source, Duration::ZERO).unwrap();
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].1);
    assert!(blocks[0].2.batch.is_none());
    assert!(matches!(
        load(
            &[SumeragiLaneMerge {
                tip_hash: [7; 32],
                ..merge
            }],
            &lanes,
            &policy,
            3,
            &source,
            Duration::ZERO
        ),
        Err(MergeError::Invalid(_))
    ));
    assert_eq!(NoLanes.tip(merge.lane, &merge.incarnation).unwrap(), None);
    assert!(
        NoLanes
            .block(merge.lane, &merge.incarnation, 1)
            .unwrap()
            .is_none()
    );
    assert!(
        !NoLanes
            .wait_for(merge.lane, &merge.incarnation, 1, Duration::ZERO)
            .unwrap()
    );
}
