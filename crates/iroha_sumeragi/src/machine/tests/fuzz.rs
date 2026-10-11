//! Fuzz-style test of `handle` (§12.5, §13.4): thousands of arbitrary, mutated and genuine
//! events from a seeded PRNG. The core must never panic, its footprint must stay within the
//! §8.4 bounds after every event, and a `Tick` must consume every due deadline.

use super::*;
use crate::message::{Echo, PayloadRequest, Status, SyncEntry, SyncRequest, SyncResponse};

/// xorshift64* (no external crates).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> T {
        items[usize::try_from(self.below(items.len() as u64)).unwrap()].clone()
    }
}

fn view_near(h: &H, rng: &mut Rng) -> u64 {
    let view = h.core.view;
    match rng.below(6) {
        0 => view.saturating_sub(1),
        1 => view + 1,
        2 => rng.below(8),
        3 => u64::MAX - rng.below(2),
        _ => view,
    }
}

fn member(h: &H, rng: &mut Rng) -> ValidatorIndex {
    u32::try_from(rng.below(h.committee().n() as u64)).unwrap()
}

/// A genuine (harness-signed) message for the current round, or a certificate that commits.
fn genuine(h: &mut H, rng: &mut Rng) -> WireMessage {
    let view = view_near(h, rng);
    let small_view = view.min(h.core.view + 1);
    let payload = [u8::try_from(rng.below(4)).unwrap()];
    let block = h.block(small_view, &payload);
    let signers = h.others(h.q(), &[]);
    match rng.below(9) {
        0 | 1 => {
            let justify = (small_view > 0).then(|| {
                let entries: Vec<_> = signers.iter().map(|s| (*s, None)).collect();
                h.tc(small_view - 1, &entries)
            });
            let p = h.proposal(small_view, &block, justify);
            if rng.chance(20) {
                h.withheld_rows.insert(h.bh(&block));
            }
            WireMessage::Proposal(Box::new(p))
        }
        2 | 3 => {
            let kind = if rng.chance(50) {
                VoteKind::Prepare
            } else {
                VoteKind::Commit
            };
            WireMessage::Vote(h.vote(kind, member(h, rng), view, &block))
        }
        4 => WireMessage::Qc(h.qc(VoteKind::Prepare, small_view, &block, &signers)),
        5 => WireMessage::Qc(h.qc(VoteKind::Commit, small_view, &block, &signers)),
        6 => {
            let lock = rng.chance(30).then(|| {
                h.qc(
                    VoteKind::Prepare,
                    small_view.saturating_sub(1),
                    &block,
                    &signers,
                )
            });
            WireMessage::Timeout(Box::new(h.timeout(member(h, rng), small_view, lock)))
        }
        7 => {
            let entries: Vec<_> = signers.iter().map(|s| (*s, None)).collect();
            WireMessage::Tc(Box::new(h.tc(small_view, &entries)))
        }
        _ => {
            let height = h.height() + rng.below(3);
            let echo = rng.chance(30).then(|| {
                let from = member(h, rng);
                let nonce = if rng.chance(70) { h.nonce } else { rng.next() };
                let msg =
                    preimage::echo_preimage(&I, &crate::testing::TEST_EPOCH.id, nonce, height);
                Echo {
                    epoch: crate::testing::TEST_EPOCH.id,
                    nonce,
                    key: h.key_at(from),
                    sig: h.signer_of(&h.key_at(member(h, rng))).sign(&msg),
                }
            });
            WireMessage::Status(Box::new(Status {
                instance: I,
                height,
                view,
                committed_qc: h.core.tip.commit_qc.clone(),
                high_pqc: rng
                    .chance(50)
                    .then(|| h.qc(VoteKind::Prepare, small_view, &block, &signers)),
                high_tc: None,
                proposal_hash: rng.chance(50).then(|| h.bh(&block)),
                want_proposal: rng.chance(30),
                probe: rng.chance(20).then(|| rng.next()),
                echo,
            }))
        }
    }
}

/// Service and off-height messages.
fn service(h: &H, rng: &mut Rng) -> WireMessage {
    let block = h.block(0, &[7]);
    match rng.below(5) {
        0 => WireMessage::SyncRequest(SyncRequest {
            instance: I,
            from_height: rng.below(10),
            max_count: u16::try_from(rng.below(5000)).unwrap(),
            max_bytes: u32::try_from(rng.below(1 << 30)).unwrap(),
        }),
        1 => WireMessage::SyncResponse(SyncResponse {
            instance: I,
            blocks: vec![SyncEntry {
                manifest: manifest(&block),
                commit_qc: h.qc_q(VoteKind::Commit, 0, &block),
            }],
        }),
        2 => WireMessage::PayloadRequest(PayloadRequest {
            instance: I,
            height: rng.below(10),
            block_hash: h.bh(&block),
        }),
        3 => WireMessage::PayloadManifest(manifest(&block)),
        _ => {
            // A certificate of a far height (sync hint) or a committed one (monitor).
            let mut qc = h.qc_q(VoteKind::Commit, 0, &block);
            qc.height = h.height() + rng.below(5);
            qc.height = qc.height.saturating_sub(rng.below(4));
            WireMessage::Qc(qc)
        }
    }
}

/// Mutate a message: structural tweaks, or byte flips through the codec.
fn mutate(msg: &WireMessage, rng: &mut Rng) -> Option<WireMessage> {
    let mut bytes = msg.encode().ok()?;
    let flips = 1 + rng.below(4);
    for _ in 0..flips {
        if bytes.is_empty() {
            break;
        }
        let at = usize::try_from(rng.below(bytes.len() as u64)).unwrap();
        bytes[at] ^= u8::try_from(1 + rng.below(255)).unwrap();
    }
    if rng.chance(10) {
        bytes.truncate(usize::try_from(rng.below(bytes.len() as u64 + 1)).unwrap());
    }
    WireMessage::decode(&bytes, 1 << 24).ok()
}

#[allow(clippy::too_many_lines)] // one arm per event kind
fn step(h: &mut H, rng: &mut Rng, stored: &mut Vec<AvailableBody>) {
    let event = match rng.below(100) {
        0..=29 => {
            let msg = genuine(h, rng);
            let msg = if rng.chance(15) {
                mutate(&msg, rng)
            } else {
                Some(msg)
            };
            let Some(msg) = msg else { return };
            let from = if rng.chance(90) {
                h.key_at(member(h, rng))
            } else {
                PublicKey::new(rng.next().to_be_bytes().to_vec()).unwrap()
            };
            Event::Message { from, msg }
        }
        30..=39 => {
            let msg = service(h, rng);
            let msg = if rng.chance(20) {
                mutate(&msg, rng)
            } else {
                Some(msg)
            };
            let Some(msg) = msg else { return };
            Event::Message {
                from: h.key_at(member(h, rng)),
                msg,
            }
        }
        40..=59 => {
            h.now += rng.below(3_000);
            if rng.chance(5) {
                h.now += 60_000;
            }
            Event::Tick
        }
        60..=71 => {
            if h.pending_exec.is_empty() || rng.chance(10) {
                Event::Executed {
                    block_hash: Hash32([u8::try_from(rng.below(3)).unwrap(); 32]),
                    req: rng.below(50),
                    outcome: ExecOutcome::Invalid,
                }
            } else {
                let i = usize::try_from(rng.below(h.pending_exec.len() as u64)).unwrap();
                let (bh, req, block) = h.pending_exec.remove(i);
                let outcome = match rng.below(10) {
                    0 => ExecOutcome::Invalid,
                    1 => ExecOutcome::Failed("fuzz".into()),
                    2 => ExecOutcome::Cancelled,
                    3 => ExecOutcome::Valid(Hash32([9; 32])),
                    _ => ExecOutcome::Valid(result_of(&block)),
                };
                stored.push(block);
                Event::Executed {
                    block_hash: bh,
                    req,
                    outcome,
                }
            }
        }
        72..=77 => {
            let req = h.last_build.unwrap_or(0) + rng.below(2);
            if rng.chance(50) {
                Event::PayloadReady { req }
            } else {
                Event::PayloadBuilt {
                    req,
                    payload: h.payload(&vec![1; usize::try_from(rng.below(64)).unwrap()]),
                }
            }
        }
        78..=85 => {
            // Genuine commits keep the heights moving.
            let block = h.block(h.core.view, &[u8::try_from(rng.below(250)).unwrap()]);
            h.bodies.insert(h.bh(&block), block.clone());
            Event::Message {
                from: h.key_at(member(h, rng)),
                msg: WireMessage::Qc(h.qc_q(VoteKind::Commit, h.core.view, &block)),
            }
        }
        86..=91 => {
            let block = if !stored.is_empty() && rng.chance(60) {
                rng.pick(stored)
            } else {
                h.block(0, &[u8::try_from(rng.below(250)).unwrap()])
            };
            Event::BodyAvailable { block }
        }
        // (A `BlockApplied` the core did not commit halts it by design, §6.13; the harness
        // applies every committed block itself.)
        92..=98 => {
            h.now += rng.below(100);
            Event::Tick
        }
        _ => {
            if rng.chance(2) {
                Event::ApplyDiverged {
                    height: h.core.tip.height,
                    block_hash: Hash32([2; 32]),
                    local_result: Hash32([3; 32]),
                }
            } else {
                Event::Tick
            }
        }
    };
    let is_tick = matches!(event, Event::Tick);
    h.fire(event);
    let status = h.core.status();
    let bound = h.core.footprint_bound();
    assert!(
        status.footprint.within(&bound),
        "footprint {:?} exceeds {:?}",
        status.footprint,
        bound
    );
    if is_tick {
        assert!(
            h.core.next_wakeup() > h.now,
            "a Tick consumes every due deadline: now {} {:?} awaiting {} stage {} view {} tv {:?}",
            h.now,
            h.core.deadlines(),
            h.core.awaiting,
            h.core.stage,
            h.core.view,
            h.core.timeout_view
        );
    }
    if stored.len() > 16 {
        stored.remove(0);
    }
}

#[test]
fn fuzz_handle_never_panics_and_stays_bounded() {
    let seeds: u64 = std::env::var("SUMERAGI_FUZZ_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    let mut max_height = 0;
    for seed in 1..=seeds {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let n = rng.pick(&[1usize, 4, 5, 7]);
        let me = u32::try_from(rng.below(n as u64)).unwrap();
        let mut h = H::new(n, move |_| me);
        let mut stored = Vec::new();
        for _ in 0..3_000 {
            step(&mut h, &mut rng, &mut stored);
        }
        max_height = max_height.max(h.core.tip.height);
    }
    assert!(
        max_height > 5,
        "the fuzzer reaches later heights ({max_height})"
    );
}
