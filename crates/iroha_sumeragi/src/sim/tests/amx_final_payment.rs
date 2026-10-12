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
    let (&tx, (participants, _)) = amx.seen.begun.first_key_value().unwrap();
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
