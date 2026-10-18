//! Final original authority destruction must run after registry map release.

use super::*;

#[derive(Default)]
struct DestructionProbe {
    armed: AtomicBool,
    calls: AtomicUsize,
    registry_free: AtomicBool,
    reentered: AtomicBool,
}

struct DestructionSchedule {
    original: Arc<dyn AvailabilitySchedule>,
    fixture: std::sync::Weak<Fixture>,
    probe: Arc<DestructionProbe>,
}

impl AvailabilitySchedule for DestructionSchedule {
    fn instance(&self) -> Hash32 {
        self.original.instance()
    }

    fn height_config(&self, height: u64) -> Result<Option<HeightConfig>, Attempt<io::Error>> {
        self.original.height_config(height)
    }
}

impl Drop for DestructionSchedule {
    fn drop(&mut self) {
        if !self.probe.armed.load(Ordering::SeqCst) {
            return;
        }
        let Some(fixture) = self.fixture.upgrade() else {
            return;
        };
        self.probe.calls.fetch_add(1, Ordering::SeqCst);
        // A failed implementation records its lock state without blocking cleanup.
        let guard = fixture.stores.stores.try_lock();
        let free = guard.is_some();
        let removed = guard
            .as_ref()
            .is_some_and(|stores| !stores.contains_key(&(LANE, INCARNATION)));
        drop(guard);
        self.probe.registry_free.store(free, Ordering::SeqCst);
        if removed {
            fixture.stores.release(LANE, &INCARNATION);
            self.probe.reentered.store(true, Ordering::SeqCst);
        }
    }
}

struct DestructionAuthorities {
    original: Arc<dyn LaneStoreAuthorities>,
    fixture: std::sync::Weak<Fixture>,
    probe: Arc<DestructionProbe>,
}

impl LaneStoreAuthorities for DestructionAuthorities {
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<Option<LaneStoreAuthority>, Attempt<io::Error>> {
        self.original
            .authority(lane, incarnation, instance)
            .map(|authority| {
                authority.map(|authority| LaneStoreAuthority {
                    schedule: Arc::new(DestructionSchedule {
                        original: authority.schedule,
                        fixture: self.fixture.clone(),
                        probe: Arc::clone(&self.probe),
                    }),
                })
            })
    }
}

fn final_authority_destruction_control(opening: bool, explicit_release: bool) {
    let probe = Arc::new(DestructionProbe::default());
    let fixture = Arc::new_cyclic(|weak| {
        let mut fixture = Fixture::new(true);
        fixture.stores.authorities = Arc::new(DestructionAuthorities {
            original: Arc::clone(&fixture.stores.authorities),
            fixture: weak.clone(),
            probe: Arc::clone(&probe),
        });
        fixture
    });
    fixture.publish();
    let original = fs::read(fixture.path()).unwrap();
    let baseline = fixture.stores.budget.reserved_bytes();
    let ceiling = fixture.stores.budget.limit_bytes();
    if opening {
        fixture.stores.release(LANE, &INCARNATION);
        fixture
            .stores
            .budget
            .set_limit_bytes(baseline + original.len());
        assert_eq!(
            fixture
                .stores
                .runtime_store(LANE, &INCARNATION)
                .unwrap_err()
                .io_kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(matches!(
            fixture.stores.stores.lock().get(&(LANE, INCARNATION)),
            Some(StoreSlot::Opening(_, false))
        ));
        assert_eq!(
            fixture.stores.budget.reserved_bytes(),
            baseline + original.len()
        );
    } else {
        assert!(matches!(
            fixture.stores.stores.lock().get(&(LANE, INCARNATION)),
            Some(StoreSlot::Ready(_))
        ));
    }
    probe.armed.store(true, Ordering::SeqCst);
    retire_exact_ready_owner(&fixture.stores, explicit_release);
    probe.armed.store(false, Ordering::SeqCst);
    fixture.stores.budget.set_limit_bytes(ceiling);
    assert!(fixture.stores.stores.lock().is_empty());
    assert_eq!(fixture.stores.budget.reserved_bytes(), baseline);
    assert_eq!(fs::read(fixture.path()).unwrap(), original);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert!(
        probe.registry_free.load(Ordering::SeqCst),
        "final original lane authority destructor must run after registry unlock"
    );
    assert!(
        probe.reentered.load(Ordering::SeqCst),
        "final original lane authority can reenter the released registry"
    );
    // Retirement releases only the original in-memory owner. Its actual signed
    // frame still reopens through the independent authority and authenticates.
    assert_eq!(fixture.stores.tip(LANE, &INCARNATION).unwrap(), Some(1));
    fixture.stores.release(LANE, &INCARNATION);
    assert_eq!(fixture.stores.budget.reserved_bytes(), baseline);
    assert_eq!(fs::read(fixture.path()).unwrap(), original);
}

#[test]
fn explicit_ready_retirement_destroys_original_authority_after_registry_unlock() {
    final_authority_destruction_control(false, true);
}

#[test]
fn applied_ready_retirement_destroys_original_authority_after_registry_unlock() {
    final_authority_destruction_control(false, false);
}

#[test]
fn explicit_opening_retirement_destroys_original_authority_after_registry_unlock() {
    final_authority_destruction_control(true, true);
}

#[test]
fn applied_opening_retirement_destroys_original_authority_after_registry_unlock() {
    final_authority_destruction_control(true, false);
}
