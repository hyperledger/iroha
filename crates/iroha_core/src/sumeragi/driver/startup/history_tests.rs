//! History refusal does not consume installed inputs or replace its original source.

use super::*;
use crate::{
    execution_attempt::{ExecutionAttemptError as Attempt, ExecutionDeferred},
    sumeragi::{
        driver::tests::{block, commit_qc, fakes::FakeBlocks},
        durable_artifact::{BodyReadError, BodyReadJob, BodyReader},
    },
};
use iroha_sumeragi::{
    availability::{AvailabilitySource, AvailableBody},
    message::{Qc, SyncEntry},
};

struct RefusingHistory {
    blocks: FakeBlocks,
    refusal: Mutex<Option<ExecutionDeferred>>,
}
impl BodyReader for RefusingHistory {
    fn begin_read(
        &self,
        source: AvailabilitySource,
    ) -> Result<Box<dyn BodyReadJob>, BodyReadError> {
        self.blocks.begin_read(source)
    }
}
impl BlockStore for RefusingHistory {
    fn retired_publication(self: Arc<Self>) -> Option<Arc<dyn traits::RetiredPublication>> {
        None
    }
    fn height(&self) -> u64 {
        self.blocks.height()
    }
    fn committed_body(
        &self,
        height: u64,
    ) -> Result<Option<(AvailableBody, Qc)>, Attempt<std::io::Error>> {
        self.blocks.committed_body(height)
    }
    fn entry(&self, height: u64) -> Result<Option<SyncEntry>, Attempt<std::io::Error>> {
        let original = { self.refusal.lock().take() };
        if let Some(original) = original {
            return Err(Attempt::Deferred(original));
        }
        self.blocks.entry(height)
    }
    fn availability_source(
        &self,
        height: u64,
        hash: Hash32,
    ) -> Result<Option<AvailabilitySource>, Attempt<std::io::Error>> {
        self.blocks.availability_source(height, hash)
    }
    fn append(&self, body: &AvailableBody, qc: &Qc) -> Result<(), Attempt<std::io::Error>> {
        self.blocks.append(body, qc)
    }
}

#[test]
fn startup_history_refusal_retains_installed_vectors_and_exact_original_release_source() {
    use iroha_allocation::{AllocationBudget, release::ReleaseRegistration};
    let budget = AllocationBudget::new(1);
    let held = budget.try_reserve_bytes(1).unwrap();
    let refusal = budget.try_reserve_bytes(1).unwrap_err();
    let original = RefusingHistory {
        blocks: FakeBlocks::default(),
        refusal: Mutex::new(Some(refusal.into())),
    };
    let genesis = (Hash32([1; 32]), Hash32([2; 32]));
    let body = block(1, genesis.0, genesis.1, vec![9]);
    let qc = commit_qc(&body, Hash32([3; 32]));
    original.append(&body, &qc).unwrap();
    let records = vec![(
        PublicKey::new(vec![4; 32]).unwrap(),
        RecordState::Absent,
        false,
    )];
    let configs = vec![(1, ConfigSlot::Ready(body.source().config().clone()))];
    let record_pointer = records.as_ptr();
    let config_pointer = configs.as_ptr();
    let result = assemble_startup_history(&original, 0, genesis, 1);
    let Err(Attempt::Deferred(refused)) = result else {
        panic!("startup history must return its original local refusal");
    };
    assert_eq!(records.as_ptr(), record_pointer);
    assert_eq!(configs.as_ptr(), config_pointer);
    let Some(AllocationRefusal::Capacity { release, .. }) = refused.allocation_refusal() else {
        panic!("the exact original pool release source survives history");
    };
    let watcher = AllocationBudget::new(ReleaseRegistration::allocation_layout().size());
    let mut registration = ReleaseRegistration::from_reservation(
        &mut watcher
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap(),
    )
    .unwrap();
    assert!(
        registration
            .poll_wait(release, &mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(held);
    assert!(
        registration
            .poll_wait(release, &mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    registration.cancel();
    let history = assemble_startup_history(&original, 0, genesis, 1)
        .unwrap_or_else(|error| panic!("same original history retry: {error}"));
    let init = Init {
        instance: body.header().instance,
        records,
        genesis_height: 0,
        demotion_window: 1,
        nonce: 9,
        tip: history.tip,
        configs,
        recent_headers: history.recent_headers,
    };
    assert_eq!(init.records.as_ptr(), record_pointer);
    assert_eq!(init.configs.as_ptr(), config_pointer);
    assert_eq!(init.tip.height, 1);
    assert_eq!(init.tip.commit_qc.as_ref(), Some(&qc));
    assert_eq!(init.recent_headers, vec![body.header().clone()]);
    assert_eq!(budget.reserved_bytes(), 0);
    drop(registration);
    assert_eq!(watcher.reserved_bytes(), 0);
}
