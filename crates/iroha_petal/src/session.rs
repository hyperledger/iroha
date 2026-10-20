//! The receive-side object an app holds while its camera is open.
//!
//! After a frame decodes, the next frames are first read by [`track`]ing the
//! code from its last pose, which skips the finder search; a full [`decode`]
//! runs when tracking fails or the last pose is older than
//! [`TRACK_WINDOW_MS`].
//!
//! A camera sees each shown frame three or four times, and noise, display
//! banding or hand shake can cost every one of those captures a tile lane. When
//! a capture reads some lane but not both tile lanes, the session keeps its
//! [`TileEvidence`] under the shown frame its decoded lane headers name, for the
//! last [`MERGE_WINDOW`] shown frames. From the second such capture on, it
//! merges them ([`merge_tiles`]) and offers a recovered lane only when that
//! lane's own header names the same frame.

use std::collections::VecDeque;

use crate::decode::{
    DecodeError, DecodeOptions, DecodedFrame, TileEvidence, decode, merge_tiles, tile_evidence,
    track,
};
use crate::image::Luma;
use crate::lanes::Lane;
use crate::stream::{
    AssemblerLimits, Completed, LaneHeader, Progress, StreamAssembler, parse_atom_lane,
};

/// How long a decoded pose stays usable for tracking the next frames.
pub const TRACK_WINDOW_MS: u64 = 500;
/// Shown frames whose captures are held for merging.
pub const MERGE_WINDOW: usize = 6;
/// Captures held per shown frame; a further capture replaces the oldest.
pub const MERGE_CAPTURES: usize = 4;

/// Limits of a scan session.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScanLimits {
    /// Forget a half-received stream after this long without progress.
    pub idle_timeout_ms: u64,
    /// Forget a stream that has not finished this long after it started.
    pub absolute_timeout_ms: u64,
    /// Assembler memory and size limits.
    pub assembler: AssemblerLimits,
    /// Image decoder options.
    pub decode: DecodeOptions,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            idle_timeout_ms: 30_000,
            absolute_timeout_ms: 180_000,
            assembler: AssemblerLimits::default(),
            decode: DecodeOptions::default(),
        }
    }
}

/// Counters for diagnostics and UI hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScanStats {
    /// Camera frames offered.
    pub frames: u32,
    /// Frames in which a code was located, whether or not a lane could be read.
    pub located: u32,
    /// Frames in which at least one lane decoded.
    pub readable: u32,
    /// Lane `P` successes.
    pub lane_p: u32,
    /// Lane `K` successes.
    pub lane_k: u32,
    /// Lane `D` successes.
    pub lane_d: u32,
    /// Frames read by tracking the previous pose instead of a full search.
    pub tracked: u32,
    /// Frames read with one corner finder hidden and inferred.
    pub inferred: u32,
    /// Merges of two or more captures of one shown frame.
    pub merges: u32,
    /// Lane `P` reads recovered by merging captures.
    pub merged_p: u32,
    /// Lane `K` reads recovered by merging captures.
    pub merged_k: u32,
}

/// The result of offering one camera frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutcome {
    /// Why the frame produced nothing, when it did not. `NoOrientation` means a
    /// code was located but no lane could be read (too far, too blurry).
    pub error: Option<DecodeError>,
    /// Lanes that decoded in this capture alone, as letters from `"PKD"`.
    pub lanes: String,
    /// Lanes recovered by merging this capture with earlier captures of its shown
    /// frame, as letters from `"PK"`.
    pub merged: String,
    /// Receive progress after this frame.
    pub progress: Progress,
    /// The finished payload, delivered exactly once.
    pub completed: Option<Completed>,
}

/// The captures of one shown frame held for merging.
struct Held {
    shown: LaneHeader,
    evidence: VecDeque<TileEvidence>,
    p_done: bool,
    k_done: bool,
}

/// The header every lane starts with.
fn lane_header(data: &[u8]) -> Option<LaneHeader> {
    match *data {
        [tag, high, low, ..] => Some(LaneHeader {
            tag,
            frame: u16::from_be_bytes([high, low]),
        }),
        _ => None,
    }
}

/// The shown frame every decoded lane header of `frame` names; `None` when no lane
/// decoded or the lanes of a torn capture name different frames.
fn shown_frame(frame: &DecodedFrame) -> Option<LaneHeader> {
    let mut shown = None;
    for lane in [&frame.d, &frame.p, &frame.k].into_iter().flatten() {
        let header = lane_header(&lane.data)?;
        if shown.is_some_and(|s| s != header) {
            return None;
        }
        shown = Some(header);
    }
    shown
}

/// Decodes camera frames and reassembles the stream they carry.
pub struct ScanSession {
    limits: ScanLimits,
    assembler: StreamAssembler,
    stats: ScanStats,
    started_ms: Option<u64>,
    progress_ms: u64,
    last_rank: usize,
    last_pose: Option<(DecodedFrame, u64)>,
    held: VecDeque<Held>,
}

impl ScanSession {
    /// Creates a session.
    #[must_use]
    pub fn new(limits: ScanLimits) -> Self {
        Self {
            assembler: StreamAssembler::new(limits.assembler),
            limits,
            stats: ScanStats::default(),
            started_ms: None,
            progress_ms: 0,
            last_rank: 0,
            last_pose: None,
            held: VecDeque::new(),
        }
    }

    /// Diagnostic counters.
    #[must_use]
    pub fn stats(&self) -> ScanStats {
        self.stats
    }

    /// Current progress.
    #[must_use]
    pub fn progress(&self) -> Progress {
        self.assembler.progress()
    }

    /// Drops all partial state.
    pub fn reset(&mut self) {
        self.assembler.reset();
        self.started_ms = None;
        self.last_rank = 0;
        self.last_pose = None;
        self.held.clear();
    }

    /// Offers one camera luma plane captured at monotonic time `now_ms`.
    pub fn push(&mut self, image: &Luma, now_ms: u64) -> ScanOutcome {
        if let Some(start) = self.started_ms
            && (now_ms.saturating_sub(self.progress_ms) > self.limits.idle_timeout_ms
                || now_ms.saturating_sub(start) > self.limits.absolute_timeout_ms)
        {
            self.reset();
        }
        self.stats.frames += 1;
        let tracked = self
            .last_pose
            .as_ref()
            .filter(|(_, at)| now_ms.saturating_sub(*at) <= TRACK_WINDOW_MS)
            .and_then(|(previous, _)| track(image, previous, &self.limits.decode));
        if tracked.is_some() {
            self.stats.tracked += 1;
        }
        let result = tracked
            .ok_or(())
            .or_else(|()| decode(image, &self.limits.decode));
        let (error, lanes, merged) = match &result {
            Ok(frame) => {
                if frame.inferred_corner.is_some() {
                    self.stats.inferred += 1;
                }
                self.last_pose = Some((frame.clone(), now_ms));
                let lanes = self.absorb(frame, now_ms);
                (None, lanes, self.merge(image, frame))
            }
            Err(error) => (Some(*error), String::new(), String::new()),
        };
        if !matches!(
            error,
            Some(DecodeError::NoFinders | DecodeError::UnsupportedImage)
        ) {
            self.stats.located += 1;
        }
        let progress = self.assembler.progress();
        if progress.rank > self.last_rank || (progress.meta.is_some() && self.started_ms.is_none())
        {
            self.progress_ms = now_ms;
            self.started_ms.get_or_insert(now_ms);
        }
        self.last_rank = progress.rank;
        ScanOutcome {
            error,
            lanes,
            merged,
            progress,
            completed: self.assembler.take_completed(),
        }
    }

    fn absorb(&mut self, frame: &DecodedFrame, _now_ms: u64) -> String {
        let mut lanes = String::new();
        for (letter, present, counter) in [
            ('P', frame.p.is_some(), &mut self.stats.lane_p),
            ('K', frame.k.is_some(), &mut self.stats.lane_k),
            ('D', frame.d.is_some(), &mut self.stats.lane_d),
        ] {
            if present {
                lanes.push(letter);
                *counter += 1;
            }
        }
        if !lanes.is_empty() {
            self.stats.readable += 1;
        }
        let previous_meta = self.assembler.progress().meta;
        frame.feed(&mut self.assembler);
        if previous_meta.is_some() && self.assembler.progress().meta != previous_meta {
            self.held.clear();
        }
        lanes
    }

    /// Holds this capture's tile evidence under its shown frame and, from the second
    /// capture on, merges the held captures of that frame.
    fn merge(&mut self, image: &Luma, frame: &DecodedFrame) -> String {
        let Some(shown) = shown_frame(frame) else {
            return String::new();
        };
        let index = if let Some(index) = self.held.iter().position(|h| h.shown == shown) {
            index
        } else {
            if self.held.len() == MERGE_WINDOW {
                self.held.pop_front();
            }
            self.held.push_back(Held {
                shown,
                evidence: VecDeque::new(),
                p_done: false,
                k_done: false,
            });
            self.held.len() - 1
        };
        let held = &mut self.held[index];
        held.p_done |= frame.p.is_some();
        held.k_done |= frame.k.is_some();
        if held.p_done && held.k_done {
            held.evidence.clear();
            return String::new();
        }
        let Some(evidence) = tile_evidence(image, frame, &self.limits.decode) else {
            return String::new();
        };
        if held.evidence.len() == MERGE_CAPTURES {
            held.evidence.pop_front();
        }
        held.evidence.push_back(evidence);
        if held.evidence.len() < 2 {
            return String::new();
        }
        self.stats.merges += 1;
        let (p, k) = merge_tiles(held.evidence.make_contiguous(), &self.limits.decode);
        let mut merged = String::new();
        for (letter, lane, result) in [('P', Lane::P, p), ('K', Lane::K, k)] {
            let done = if lane == Lane::P {
                &mut held.p_done
            } else {
                &mut held.k_done
            };
            let Some(packet) = result.and_then(|r| parse_atom_lane(lane, &r.data)) else {
                continue;
            };
            // a merge offers only atoms of the shown frame it was made for
            if *done || packet.header != shown {
                continue;
            }
            *done = true;
            self.assembler.push_atoms(&packet);
            if lane == Lane::P {
                self.stats.merged_p += 1;
            } else {
                self.stats.merged_k += 1;
            }
            merged.push(letter);
        }
        if held.p_done && held.k_done {
            held.evidence.clear();
        }
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::LaneResult;
    use crate::image::Rgb;
    use crate::lanes::FrameCells;
    use crate::render::{RenderOptions, render};
    use crate::sim::{CaptureConfig, capture, fit_to_frame};
    use crate::stream::StreamEncoder;

    fn payload(len: usize) -> Vec<u8> {
        let mut rng = crate::prng::Xorshift32::new(3);
        (0..len).map(|_| rng.next_byte()).collect()
    }

    #[test]
    fn a_steady_camera_is_tracked_after_the_first_frame() {
        let data = payload(300);
        let encoder = StreamEncoder::new(&data, 2).unwrap();
        let config = fit_to_frame(
            &CaptureConfig {
                width: 640,
                height: 480,
                rotation_deg: 8.0,
                ..CaptureConfig::modern()
            },
            4.0,
        );
        let mut session = ScanSession::new(ScanLimits::default());
        for frame in 0..6u16 {
            let source = render(
                &encoder.cells(frame),
                &RenderOptions {
                    size: 512,
                    supersample: 2,
                    ..RenderOptions::default()
                },
            );
            let outcome = session.push(&capture(&source, &config), u64::from(frame) * 125);
            assert!(outcome.error.is_none(), "frame {frame}");
        }
        let stats = session.stats();
        assert_eq!(stats.readable, 6);
        assert_eq!(
            stats.tracked, 5,
            "every frame after the first follows the pose"
        );
        // a pause longer than the tracking window forces a full search again
        let source = render(
            &encoder.cells(6),
            &RenderOptions {
                size: 512,
                supersample: 2,
                ..RenderOptions::default()
            },
        );
        session.push(&capture(&source, &config), 5 * 125 + TRACK_WINDOW_MS + 1);
        assert_eq!(session.stats().tracked, 5);
        assert_eq!(session.stats().readable, 7);
    }

    #[test]
    fn a_session_receives_a_payload_from_simulated_captures() {
        let data = payload(500);
        let encoder = StreamEncoder::new(&data, 2).unwrap();
        let config = fit_to_frame(
            &CaptureConfig {
                width: 640,
                height: 480,
                rotation_deg: 20.0,
                ..CaptureConfig::modern()
            },
            4.0,
        );
        let mut session = ScanSession::new(ScanLimits::default());
        let mut done = None;
        for frame in 0..40u16 {
            let source = render(
                &encoder.cells(frame),
                &RenderOptions {
                    size: 512,
                    supersample: 2,
                    ..RenderOptions::default()
                },
            );
            let outcome = session.push(&capture(&source, &config), u64::from(frame) * 125);
            if outcome.completed.is_some() {
                done = outcome.completed;
                break;
            }
        }
        let done = done.expect("completed");
        assert_eq!(done.payload, data);
        assert_eq!(done.meta.kind, 2);
        assert!(session.stats().readable > 0 && session.stats().lane_d > 0);
    }

    #[test]
    fn idle_sessions_forget_partial_streams() {
        let encoder = StreamEncoder::new(&payload(4000), 1).unwrap();
        let config = fit_to_frame(
            &CaptureConfig {
                width: 640,
                height: 480,
                ..CaptureConfig::modern()
            },
            4.0,
        );
        let limits = ScanLimits {
            idle_timeout_ms: 1_000,
            ..ScanLimits::default()
        };
        let mut session = ScanSession::new(limits);
        let render_frame = |frame: u16| {
            let source = render(
                &encoder.cells(frame),
                &RenderOptions {
                    size: 512,
                    supersample: 2,
                    ..RenderOptions::default()
                },
            );
            capture(&source, &config)
        };
        session.push(&render_frame(0), 0);
        assert!(session.progress().rank > 0);
        // a frame much later with nothing readable resets the session first
        let blank = Luma::new(640, 480);
        let outcome = session.push(&blank, 60_000);
        assert_eq!(outcome.error, Some(DecodeError::NoFinders));
        assert_eq!(outcome.progress.rank, 0);
    }

    #[test]
    fn located_counts_codes_that_were_seen_but_could_not_be_read() {
        let encoder = StreamEncoder::new(&payload(100), 1).unwrap();
        let mut frame = render(
            &encoder.cells(1),
            &RenderOptions {
                size: 512,
                supersample: 2,
                ..RenderOptions::default()
            },
        );
        // keep only the four blossoms: finders are located, no lane can be read
        let scale = 512.0 / 1024.0;
        for y in 0..512usize {
            for x in 0..512usize {
                let near_finder = crate::layout::FINDER_CENTERS.iter().any(|&(fx, fy)| {
                    ((x as f64 - f64::from(fx) * scale).powi(2)
                        + (y as f64 - f64::from(fy) * scale).powi(2))
                    .sqrt()
                        < 34.0
                });
                if !near_finder {
                    frame.data[(y * 512 + x) * 3..(y * 512 + x) * 3 + 3].fill(0);
                }
            }
        }
        let mut session = ScanSession::new(ScanLimits::default());
        let outcome = session.push(&frame.to_luma(), 0);
        assert_eq!(outcome.error, Some(DecodeError::NoOrientation));
        assert_eq!(session.stats().located, 1);
        assert_eq!(session.stats().readable, 0);
        // a frame with no code at all is not "located"
        session.push(&Luma::new(320, 240), 100);
        assert_eq!(session.stats().located, 1);
        assert_eq!(session.stats().frames, 2);
    }

    #[test]
    fn unreadable_frames_do_not_disturb_progress() {
        let mut session = ScanSession::new(ScanLimits::default());
        let outcome = session.push(&Luma::new(320, 240), 5);
        assert!(outcome.completed.is_none() && outcome.lanes.is_empty());
        assert_eq!(session.stats().frames, 1);
        assert_eq!(session.stats().located, 0);
    }

    /// The `one-pass` stream of the golden captures.
    fn one_pass() -> StreamEncoder {
        let mut rng = crate::prng::Xorshift32::new(2);
        let data: Vec<u8> = (0..700).map(|_| rng.next_byte()).collect();
        StreamEncoder::new(&data, 2).unwrap()
    }

    fn source(cells: &FrameCells) -> Rgb {
        render(
            cells,
            &RenderOptions {
                size: 512,
                supersample: 2,
                ..RenderOptions::default()
            },
        )
    }

    #[test]
    fn merging_recovers_lane_k_that_no_single_capture_reads() {
        let encoder = one_pass();
        let (_, k_data, _) = encoder.lane_data(5);
        let source = source(&encoder.cells(5));
        // a soft 480p camera in dim light: every capture loses lane K to sensor noise
        let config = fit_to_frame(
            &CaptureConfig {
                width: 640,
                height: 480,
                fill: 0.85,
                rotation_deg: 319.938_684_617_778_5,
                tilt_x_deg: -7.243_522_205_931_878,
                tilt_y_deg: 0.836_276_336_767_998_2,
                shift: (-0.019_880_103_806_137_21, 0.014_984_588_231_223_464),
                blur_sigma: 0.958_382_539_421_904_8,
                noise: 16.2,
                ..CaptureConfig::modern()
            },
            4.0,
        );
        let options = DecodeOptions::default();
        let mut session = ScanSession::new(ScanLimits::default());
        let mut evidence = Vec::new();
        let mut merged = String::new();
        for (i, seed) in (1201..=1203).enumerate() {
            let image = capture(&source, &CaptureConfig { seed, ..config });
            let single = decode(&image, &options).expect("lanes P and D read");
            assert!(single.k.is_none(), "capture {i} reads lane K alone");
            evidence.push(tile_evidence(&image, &single, &options).expect("evidence"));
            merged.push_str(&session.push(&image, 33 * i as u64).merged);
        }
        assert_eq!(
            merge_tiles(&evidence, &options).1.map(|l| l.data),
            Some(k_data)
        );
        assert_eq!(merged, "K");
        let stats = session.stats();
        assert_eq!(
            (stats.lane_k, stats.merges, stats.merged_k, stats.merged_p),
            (0, 2, 1, 0)
        );
        // the shown frame is complete: its evidence is released
        assert!(session.held.iter().all(|h| h.evidence.is_empty()));
    }

    /// Clean captures of frame `tiles` whose decoded lanes are replaced by lane `D` of
    /// frame `rings`, as if the rings showed another frame than the tile field.
    fn rings_of_another_frame(
        encoder: &StreamEncoder,
        tiles: u16,
        rings: u16,
        seed: u64,
    ) -> (Luma, DecodedFrame) {
        let config = fit_to_frame(
            &CaptureConfig {
                width: 640,
                height: 480,
                rotation_deg: 25.0,
                seed,
                ..CaptureConfig::modern()
            },
            4.0,
        );
        let image = capture(&source(&encoder.cells(tiles)), &config);
        let mut frame = decode(&image, &DecodeOptions::default()).expect("decodes");
        assert!(frame.p.is_some() && frame.k.is_some());
        frame.p = None;
        frame.k = None;
        frame.d = Some(LaneResult {
            data: encoder.lane_data(rings).2,
            corrected: 0,
            erasures: 0,
        });
        (image, frame)
    }

    #[test]
    fn a_merge_never_offers_atoms_of_another_shown_frame() {
        let encoder = one_pass();
        let mut session = ScanSession::new(ScanLimits::default());
        for seed in 1..=3 {
            let (image, frame) = rings_of_another_frame(&encoder, 11, 10, seed);
            assert_eq!(session.merge(&image, &frame), "", "capture {seed}");
        }
        let stats = session.stats();
        assert_eq!((stats.merges, stats.merged_p, stats.merged_k), (2, 0, 0));
        assert_eq!(session.progress().atoms_received, 0);
        // what was refused: the merged tile lanes name frame 11, not frame 10
        let held = &mut session.held[0];
        assert_eq!(held.shown.frame, 10);
        let (p, k) = merge_tiles(held.evidence.make_contiguous(), &DecodeOptions::default());
        let (p_data, k_data, _) = encoder.lane_data(11);
        assert_eq!(
            (p.map(|l| l.data), k.map(|l| l.data)),
            (Some(p_data), Some(k_data))
        );
    }

    #[test]
    fn torn_captures_whose_lanes_name_different_frames_are_not_held() {
        let encoder = one_pass();
        let mut session = ScanSession::new(ScanLimits::default());
        let (image, mut frame) = rings_of_another_frame(&encoder, 11, 10, 1);
        let (p_data, _, _) = encoder.lane_data(11);
        frame.p = Some(LaneResult {
            data: p_data,
            corrected: 0,
            erasures: 0,
        });
        assert_eq!(session.merge(&image, &frame), "");
        assert!(session.held.is_empty());
    }

    #[test]
    fn the_session_holds_at_most_four_captures_of_six_shown_frames() {
        let encoder = one_pass();
        let mut session = ScanSession::new(ScanLimits::default());
        // refused merges never finish a shown frame, so its captures stay held
        for seed in 1..=MERGE_CAPTURES as u64 + 2 {
            let (image, frame) = rings_of_another_frame(&encoder, 11, 10, seed);
            session.merge(&image, &frame);
        }
        assert_eq!(session.held.len(), 1);
        assert_eq!(session.held[0].evidence.len(), MERGE_CAPTURES);
        assert_eq!(session.stats().merges, MERGE_CAPTURES as u32 + 1);
        let (image, _) = rings_of_another_frame(&encoder, 11, 10, 1);
        for rings in 12..12 + MERGE_WINDOW as u16 {
            let (_, frame) = rings_of_another_frame(&encoder, 11, rings, 1);
            session.merge(&image, &frame);
        }
        assert_eq!(session.held.len(), MERGE_WINDOW);
        assert!(session.held.iter().all(|h| h.shown.frame >= 12));
        session.reset();
        assert!(session.held.is_empty());
    }

    #[test]
    fn switching_streams_with_the_same_short_tag_discards_old_merge_state() {
        let encoder = |last| {
            let mut payload = vec![0u8; 100];
            payload[3] = last;
            StreamEncoder::new(&payload, 2).unwrap()
        };
        let old = encoder(49);
        let new = encoder(128);
        assert_eq!((old.meta().tag(), new.meta().tag()), (61, 61));
        assert_ne!(old.meta(), new.meta());
        let old_image = source(&old.cells(0)).to_luma();
        let new_image = source(&new.cells(0)).to_luma();
        let old_full = decode(&old_image, &DecodeOptions::default()).unwrap();
        let mut new_partial = decode(&new_image, &DecodeOptions::default()).unwrap();
        new_partial.p = None;
        new_partial.k = None;
        for was_complete in [false, true] {
            let mut session = ScanSession::new(ScanLimits::default());
            let mut previous = old_full.clone();
            if !was_complete {
                previous.p = None;
                previous.k = None;
            }
            session.absorb(&previous, 0);
            session.merge(&old_image, &previous);
            assert!(!session.held.is_empty());
            session.absorb(&new_partial, 33);
            session.absorb(&new_partial, 66);
            assert_eq!(session.progress().meta, Some(new.meta()));
            assert!(session.held.is_empty());
            assert_eq!(session.merge(&new_image, &new_partial), "");
            assert_eq!(session.held[0].evidence.len(), 1);
            assert!(!session.held[0].p_done && !session.held[0].k_done);
            assert_eq!(session.merge(&new_image, &new_partial), "PK");
        }
    }

    #[test]
    fn the_first_beacon_preserves_evidence_received_before_it() {
        let encoder = one_pass();
        let image = source(&encoder.cells(1)).to_luma();
        let mut partial = decode(&image, &DecodeOptions::default()).unwrap();
        partial.p = None;
        partial.k = None;
        let mut session = ScanSession::new(ScanLimits::default());
        session.absorb(&partial, 0);
        session.merge(&image, &partial);
        assert!(session.progress().meta.is_none());
        assert_eq!(session.held[0].evidence.len(), 1);
        let beacon_image = source(&encoder.cells(0)).to_luma();
        let mut beacon = decode(&beacon_image, &DecodeOptions::default()).unwrap();
        beacon.p = None;
        beacon.k = None;
        session.absorb(&beacon, 33);
        assert_eq!(session.progress().meta, Some(encoder.meta()));
        assert_eq!(session.held[0].evidence.len(), 1);
        assert_eq!(session.merge(&image, &partial), "PK");
    }
}
