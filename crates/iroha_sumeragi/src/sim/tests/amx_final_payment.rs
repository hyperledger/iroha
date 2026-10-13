//! Final AMX obligations with no unrelated workload or artificial height advancement.

use super::*;
use crate::sim::{
    amx::{AmxConfig, Outcome, Vote},
    byz::NetRule,
    scenario::Fault,
};

fn last_payment(seed: u64) -> Scenario {
    let mut scenario = scenarios::smoke(seed, 4);
    scenario.name = "F31-final-payment".into();
    scenario.instances = 3;
    scenario.workload = None;
    scenario.duration = 60_000;
    scenario.heal_at = scenario.duration;
    // Idle roots have no generic height-progress obligation. The assertions below
    // require this exact payment's outcome and escrow release instead.
    scenario.checks.liveness = false;
    scenario.checks.progress = 0;
    scenario.clock_guard = Some(crate::sim::scenario::ClockGuard {
        max_clock_drift_ms: 500,
        due_work_max_lag_ms: 5_000,
        ..Default::default()
    });
    scenario.amx = Some(AmxConfig {
        relayers: vec![0],
        client: (2_000, 2_000),
        every: (1_000, 1_000),
        prepare_delay: 0,
        settle_delay: 10_000,
        submit_loss_ppm: 0,
        short_ppm: 0,
        long: (20, 20),
        max_amount: 1,
        ..AmxConfig::default()
    });
    scenario
}

#[test]
fn amx_final_payment_recovers_lost_relayer_jobs_without_unrelated_work() {
    let mut scenario = last_payment(0);
    scenario.script.push((5_000, Fault::Crash(0)));
    scenario.script.push((15_000, Fault::Restart(0)));
    let world = run(scenario).unwrap_or_else(|failure| panic!("{failure}"));
    assert!(world.workload_every().is_none());
    let amx = world.amx.as_ref().unwrap();
    assert_eq!(amx.seen.begun.len(), 1, "one final payment only");
    let (&tx, (participants, _, _)) = amx.seen.begun.first_key_value().unwrap();
    assert_eq!(
        amx.seen.decided.get(&tx).map(|value| value.0),
        Some(Outcome::Commit)
    );
    for participant in participants {
        assert!(matches!(
            amx.seen.votes.get(&(*participant, tx)),
            Some(Vote::Yes(_))
        ));
        assert_eq!(
            amx.seen
                .settled
                .get(&(*participant, tx))
                .map(|value| value.0),
            Some(Outcome::Commit)
        );
    }
    assert_eq!(world.machines[0].crashes, 1);
    assert!(world.machines[0].up);
}

#[test]
fn amx_final_payment_silent_participant_requires_actionable_abort() {
    let mut scenario = last_payment(0);
    scenario.net_rules.push(NetRule::StallInstance {
        inst: 2,
        from: 0,
        until: scenario.duration,
    });
    // The silent participant cannot be required to consume the decision while
    // unavailable. The healthy global root and participant must close their work.
    scenario.amx.as_mut().unwrap().settle_window = scenario.duration + 1;
    let world = run(scenario).unwrap_or_else(|failure| panic!("{failure}"));
    assert!(world.workload_every().is_none());
    let amx = world.amx.as_ref().unwrap();
    assert_eq!(amx.seen.begun.len(), 1, "one final payment only");
    let (&tx, _) = amx.seen.begun.first_key_value().unwrap();
    assert!(
        matches!(amx.seen.votes.get(&(1, tx)), Some(Vote::Yes(_))),
        "healthy participant really holds Yes escrow"
    );
    assert!(
        !amx.seen.votes.contains_key(&(2, tx)),
        "silent participant submitted no vote"
    );
    assert_eq!(
        amx.seen.decided.get(&tx).map(|value| value.0),
        Some(Outcome::Abort),
        "healthy global root must resolve the due final obligation without unrelated height advancement",
    );
    assert_eq!(
        amx.seen.settled.get(&(1, tx)).map(|value| value.0),
        Some(Outcome::Abort)
    );
}

#[test]
fn amx_final_payment_due_job_rebuilds_after_relayer_restart_without_background_work() {
    let mut scenario = last_payment(1);
    scenario.net_rules.push(NetRule::StallInstance {
        inst: 2,
        from: 0,
        until: scenario.duration,
    });
    scenario.amx.as_mut().unwrap().settle_window = scenario.duration + 1;
    // The relayer loses the expiry job before the due time and returns after it.
    scenario.script.push((10_000, Fault::Crash(0)));
    scenario.script.push((30_000, Fault::Restart(0)));
    let world = run(scenario).unwrap_or_else(|failure| panic!("{failure}"));
    assert!(world.workload_every().is_none());
    assert!(world.clock_guard.is_some());
    let amx = world.amx.as_ref().unwrap();
    assert_eq!(amx.seen.begun.len(), 1);
    let (&tx, (_, _, expires_at_ms)) = amx.seen.begun.first_key_value().unwrap();
    let &(outcome, decision_height, decided_at) = amx
        .seen
        .decided
        .get(&tx)
        .expect("reconstructed original expiry work must close the final obligation");
    assert_eq!(outcome, Outcome::Abort);
    let certified_time = world
        .clock_guard
        .as_ref()
        .unwrap()
        .certified
        .iter()
        .find(|block| block.inst == 0 && block.height == decision_height)
        .expect("the Abort has an authenticated block timestamp");
    assert!(certified_time.t >= *expires_at_ms && decided_at >= 30_000);
    assert_eq!(
        amx.seen.settled.get(&(1, tx)).map(|value| value.0),
        Some(Outcome::Abort)
    );
    assert_eq!(world.machines[0].crashes, 1);
}

#[test]
fn amx_final_payment_certified_abort_delivery_rebuilds_after_relayer_restart() {
    let mut scenario = last_payment(2);
    scenario.duration = 90_000;
    scenario.heal_at = scenario.duration;
    scenario.net_rules.push(NetRule::StallInstance {
        inst: 2,
        from: 0,
        until: scenario.duration,
    });
    let config = scenario.amx.as_mut().unwrap();
    config.settle_window = scenario.duration + 1;
    config.settle_delay = 40_000;
    let mut world = World::new(scenario);

    // Stop on the actual certified decision, rather than guessing a crash time.
    // The deterministic delivery delay leaves the original decision job pending.
    while world.now < 40_000 && world.amx.as_ref().unwrap().seen.decided.is_empty() {
        world.run_until(world.now + 25);
        assert!(world.failure.is_none(), "{:?}", world.failure);
    }
    let amx = world.amx.as_ref().unwrap();
    assert_eq!(amx.seen.begun.len(), 1);
    let (&tx, &(outcome, decision_height, decided_at)) = amx
        .seen
        .decided
        .first_key_value()
        .expect("expiry must first produce a certified Abort");
    assert_eq!(outcome, Outcome::Abort);
    let delivery_delay = amx.config.settle_delay * u64::from(tx.0[1]) / u64::from(u8::MAX);
    assert!(world.now - decided_at < delivery_delay);
    assert!(!amx.seen.settled.contains_key(&(1, tx)));
    assert!(matches!(amx.seen.votes.get(&(1, tx)), Some(Vote::Yes(_))));

    world.crash(0);
    world.run_until(world.now + 3_000);
    assert!(world.failure.is_none(), "{:?}", world.failure);
    assert!(
        !world
            .amx
            .as_ref()
            .unwrap()
            .seen
            .settled
            .contains_key(&(1, tx)),
        "escrow cannot release merely because local time passes or the relayer crashes"
    );
    world.restart(0);
    world.run().unwrap_or_else(|failure| panic!("{failure}"));

    assert!(world.workload_every().is_none());
    let amx = world.amx.as_ref().unwrap();
    assert_eq!(amx.seen.begun.len(), 1);
    assert_eq!(
        amx.seen.decided.get(&tx),
        Some(&(outcome, decision_height, decided_at))
    );
    assert_eq!(
        amx.seen.settled.get(&(1, tx)).map(|value| value.0),
        Some(Outcome::Abort),
        "restart must reconstruct and deliver the original certified Abort"
    );
    assert_eq!(world.machines[0].crashes, 1);
}
