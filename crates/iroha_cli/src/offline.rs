//! Offline commands: finalized registration packaging and Petal Stream optical handoff.
//!
//! Petal Stream is the animated `天` / katakana / dotted-ring transport
//! specified in `specs/petal_stream.md` and implemented by `iroha_petal`.
// Report fields mix byte counts, frame counts and floating-point timings that
// are bounded by the command-line limits above.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]
use crate::{Run, RunContext, cli_output::print_with_optional_text};
use clap::{Args, Subcommand, ValueEnum};
use eyre::{Result, WrapErr, eyre};
use iroha_petal::{
    decode::{DecodeOptions, decode},
    image::Luma,
    qualify::{CameraModel, StreamTrial, TrialOutcome, run_stream_trial},
    render::{RenderOptions, render},
    session::{ScanLimits, ScanSession},
    stream::{AssemblerLimits, DEFAULT_MAX_PAYLOAD_LEN, DLane, MAX_PAYLOAD_LEN, StreamEncoder},
};
use norito::derive::JsonSerialize;
use std::{
    fs,
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
};

const ENCODE_SCHEMA: &str = "iroha.offline.petal.encode.v1";
const DECODE_SCHEMA: &str = "iroha.offline.petal.decode.v1";
const INSPECT_SCHEMA: &str = "iroha.offline.petal.inspect.v1";
const SIMULATE_SCHEMA: &str = "iroha.offline.petal.simulate.v1";
const DEFAULT_SIZE: u32 = 1_024;
const MIN_SIZE: u32 = 256;
const MAX_SIZE: u32 = 4_096;
const DEFAULT_FPS: u16 = 8;
const MAX_FPS: u16 = 30;
const MAX_RENDERED_FRAMES: u16 = 4_096;
const MAX_SIMULATION_TRIALS: u32 = 1_000;

mod registration;

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Verify and package finalized universal-token registration originals for wallet import.
    RegistrationPackage(registration::RegistrationPackageArgs),
    /// Petal Stream optical handoff tooling.
    #[command(subcommand)]
    Petal(PetalCommand),
}

impl Command {
    pub(crate) fn allows_fallback_config(&self) -> bool {
        match self {
            Self::Petal(_) | Self::RegistrationPackage(_) => true,
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn preflight_before_operator_key_load(&self) -> Result<()> {
        match self {
            Self::Petal(_) => Ok(()),
            Self::RegistrationPackage(args) => args.preflight(),
        }
    }
}

impl Run for Command {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Petal(command) => Run::run(command, context),
            Self::RegistrationPackage(args) => args.run(context),
        }
    }
}

#[derive(Subcommand, Debug)]
pub(crate) enum PetalCommand {
    /// Encode a payload into a stream of Petal frames (PNG sequence or animated GIF).
    Encode(EncodeArgs),
    /// Reassemble a payload from a directory of rendered or captured PNG frames.
    Decode(DecodeArgs),
    /// Report which lanes of one PNG frame decode.
    Inspect(InspectArgs),
    /// Play a stream on a simulated screen and camera and report completion times.
    Simulate(SimulateArgs),
}

impl Run for PetalCommand {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        match self {
            Self::Encode(args) => args.run(context),
            Self::Decode(args) => args.run(context),
            Self::Inspect(args) => args.run(context),
            Self::Simulate(args) => args.run(context),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum EncodeFormat {
    /// One PNG per frame (`frame_0000.png`, …).
    Png,
    /// One looping animated GIF (`stream.gif`); requires the `offline-visual-codecs` feature.
    Gif,
}

impl std::fmt::Display for EncodeFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Png => f.write_str("png"),
            Self::Gif => f.write_str("gif"),
        }
    }
}

#[derive(Args, Debug, Clone)]
pub(crate) struct EncodeArgs {
    /// Payload file to stream.
    #[arg(long, value_name = "PATH")]
    input: PathBuf,
    /// Output directory for the frames and `manifest.json`.
    #[arg(long, value_name = "DIR")]
    output: PathBuf,
    /// Payload kind byte carried in the beacon (KAGEMUSHA wallet V1 envelope tags: 1 Offer,
    /// 2 Request, 3 Payment, 4 Credited, 5 SessionControl, 6 PolicyData, 7 Lineage).
    #[arg(long, default_value_t = 0)]
    kind: u8,
    /// Frames to render. Zero renders one systematic pass plus 25 % repair (at least four extra frames).
    #[arg(long, default_value_t = 0)]
    frames: u16,
    /// Frame counter of the first rendered frame; later frames use consecutive counters.
    #[arg(long = "first-frame", default_value_t = 0)]
    first_frame: u16,
    /// Square frame size in pixels.
    #[arg(long, default_value_t = DEFAULT_SIZE)]
    size: u32,
    /// Playback rate in frames per second (recommended 6–12; used for the GIF delay and the manifest).
    #[arg(long, default_value_t = DEFAULT_FPS)]
    fps: u16,
    /// Output format.
    #[arg(long, value_enum, default_value_t = EncodeFormat::Png)]
    format: EncodeFormat,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct DecodeArgs {
    /// Directory of PNG frames, read in file-name order.
    #[arg(long = "input-dir", value_name = "DIR")]
    input_dir: PathBuf,
    /// File that receives the reassembled payload.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
    /// Capture rate of the frames, used for the session timeouts.
    #[arg(long, default_value_t = DEFAULT_FPS)]
    fps: u16,
    /// Largest payload accepted.
    #[arg(long = "max-payload", default_value_t = DEFAULT_MAX_PAYLOAD_LEN)]
    max_payload: usize,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct InspectArgs {
    /// PNG frame to inspect.
    #[arg(long, value_name = "PATH")]
    input: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct SimulateArgs {
    /// Payload file; omit to use pseudo-random bytes of `--bytes` length.
    #[arg(long, value_name = "PATH")]
    input: Option<PathBuf>,
    /// Payload length when no input file is given.
    #[arg(long, default_value_t = 2_048)]
    bytes: usize,
    /// Camera model: modern, legacy, soft or worst.
    #[arg(long, default_value = "modern")]
    camera: String,
    /// Frames per second shown on the simulated screen.
    #[arg(long, default_value_t = DEFAULT_FPS)]
    fps: u16,
    /// Number of independent trials (random pose and phase each).
    #[arg(long, default_value_t = 4)]
    trials: u32,
    /// Give up on a trial after this many simulated seconds.
    #[arg(long = "horizon-seconds", default_value_t = 90)]
    horizon_seconds: u32,
    /// Seed of the first trial.
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Payload kind byte.
    #[arg(long, default_value_t = 0)]
    kind: u8,
}

#[derive(Clone, Debug, JsonSerialize)]
struct EncodeReport {
    schema: String,
    input_path: String,
    output_dir: String,
    payload_bytes: u64,
    kind: u8,
    payload_crc32c: String,
    stream_tag: u8,
    source_atoms: u64,
    systematic_frames: u64,
    format: String,
    size: u32,
    fps: u16,
    first_frame: u16,
    rendered_frames: u16,
    estimated_payload_bytes_per_second: u64,
    files: Vec<String>,
}

#[derive(Clone, Debug, JsonSerialize)]
struct DecodeReport {
    schema: String,
    input_dir: String,
    output_path: Option<String>,
    frames_read: u64,
    frames_located: u64,
    frames_readable: u64,
    /// Frames read by following the previous pose instead of a full search.
    frames_tracked: u64,
    /// Frames read with one corner blossom hidden and inferred.
    frames_inferred: u64,
    lane_p_frames: u64,
    lane_k_frames: u64,
    lane_d_frames: u64,
    completed_at_frame: Option<u64>,
    payload_bytes: Option<u64>,
    kind: Option<u8>,
    payload_crc32c: Option<String>,
    rank: u64,
    source_atoms: u64,
}

#[derive(Clone, Debug, JsonSerialize)]
struct LaneReport {
    corrected_bytes: u64,
    erased_bytes: u64,
}

#[derive(Clone, Debug, JsonSerialize)]
struct InspectReport {
    schema: String,
    input_path: String,
    width: u32,
    height: u32,
    error: Option<String>,
    rotation_quarter_turns: Option<u8>,
    mirrored: Option<bool>,
    /// Canonical index of a corner blossom that was hidden and inferred (0 top-left, clockwise).
    inferred_corner: Option<u8>,
    lane_p: Option<LaneReport>,
    lane_k: Option<LaneReport>,
    lane_d: Option<LaneReport>,
    frame_counter: Option<u16>,
    beacon_kind: Option<u8>,
    beacon_payload_bytes: Option<u64>,
    beacon_payload_crc32c: Option<String>,
}

#[derive(Clone, Debug, JsonSerialize)]
struct SimulateReport {
    schema: String,
    camera: String,
    payload_bytes: u64,
    display_fps: u16,
    trials: u64,
    completed: u64,
    wrong_payloads: u64,
    completion_seconds_mean: Option<f64>,
    completion_seconds_median: Option<f64>,
    completion_seconds_worst: Option<f64>,
    effective_payload_bytes_per_second: Option<f64>,
    lane_k_frame_share: f64,
    mean_decode_milliseconds: f64,
}

impl Run for EncodeArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let report = self.encode()?;
        let text = format!(
            "encoded {} bytes into {} {} frame(s) ({} systematic) at {}px → {}",
            report.payload_bytes,
            report.rendered_frames,
            report.format,
            report.systematic_frames,
            report.size,
            report.output_dir
        );
        print_with_optional_text(context, Some(text), &report)
    }
}

impl EncodeArgs {
    fn encode(&self) -> Result<EncodeReport> {
        if !(MIN_SIZE..=MAX_SIZE).contains(&self.size) {
            return Err(eyre!(
                "--size must be between {MIN_SIZE} and {MAX_SIZE} pixels"
            ));
        }
        if self.fps == 0 || self.fps > MAX_FPS {
            return Err(eyre!("--fps must be between 1 and {MAX_FPS}"));
        }
        let payload = fs::read(&self.input)
            .wrap_err_with(|| format!("failed to read payload {}", self.input.display()))?;
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(eyre!(
                "payload of {} bytes exceeds the stream limit of {MAX_PAYLOAD_LEN}",
                payload.len()
            ));
        }
        let encoder = StreamEncoder::new(&payload, self.kind)
            .map_err(|error| eyre!("cannot stream this payload: {error}"))?;
        let meta = encoder.meta();
        let systematic = encoder.systematic_frames();
        let requested = if self.frames == 0 {
            systematic + (systematic / 4).max(4)
        } else {
            usize::from(self.frames)
        };
        let frames = u16::try_from(requested)
            .ok()
            .filter(|n| *n <= MAX_RENDERED_FRAMES)
            .ok_or_else(|| {
                eyre!(
                    "{requested} frames exceed the limit of {MAX_RENDERED_FRAMES}; lower --frames"
                )
            })?;
        if self.format == EncodeFormat::Gif {
            validate_gif_available()?;
        }
        fs::create_dir_all(&self.output)
            .wrap_err_with(|| format!("failed to create {}", self.output.display()))?;
        let options = RenderOptions {
            size: self.size as usize,
            ..RenderOptions::default()
        };
        let mut files = Vec::new();
        let mut gif_frames = Vec::new();
        for index in 0..frames {
            let frame = self.first_frame.wrapping_add(index);
            let image = render(&encoder.cells(frame), &options);
            match self.format {
                EncodeFormat::Png => {
                    let name = format!("frame_{index:04}.png");
                    write_png_rgb(&self.output.join(&name), &image.data, self.size)?;
                    files.push(name);
                }
                EncodeFormat::Gif => gif_frames.push(image.data),
            }
        }
        if self.format == EncodeFormat::Gif {
            write_gif(
                &self.output.join("stream.gif"),
                &gif_frames,
                self.size,
                self.fps,
            )?;
            files.push("stream.gif".to_owned());
        }
        let seconds_per_pass = systematic as f64 / f64::from(self.fps);
        let report = EncodeReport {
            schema: ENCODE_SCHEMA.to_owned(),
            input_path: self.input.display().to_string(),
            output_dir: self.output.display().to_string(),
            payload_bytes: payload.len() as u64,
            kind: self.kind,
            payload_crc32c: format!("{:08x}", meta.crc),
            stream_tag: meta.tag(),
            source_atoms: meta.source_atoms() as u64,
            systematic_frames: systematic as u64,
            format: self.format.to_string(),
            size: self.size,
            fps: self.fps,
            first_frame: self.first_frame,
            rendered_frames: frames,
            estimated_payload_bytes_per_second: (payload.len() as f64 / seconds_per_pass).round()
                as u64,
            files,
        };
        let manifest =
            norito::json::to_vec_pretty(&report).wrap_err("failed to serialise the manifest")?;
        fs::write(self.output.join("manifest.json"), manifest)
            .wrap_err_with(|| format!("failed to write {}/manifest.json", self.output.display()))?;
        Ok(report)
    }
}

impl Run for DecodeArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let report = self.decode()?;
        let text = match (&report.completed_at_frame, &report.payload_bytes) {
            (Some(at), Some(bytes)) => format!(
                "reassembled {bytes} bytes after {} frame(s) (lane P/K/D read in {}/{}/{} frames)",
                at + 1,
                report.lane_p_frames,
                report.lane_k_frames,
                report.lane_d_frames
            ),
            _ => format!(
                "incomplete: collected {}/{} independent atoms",
                report.rank, report.source_atoms
            ),
        };
        print_with_optional_text(context, Some(text), &report)?;
        if report.completed_at_frame.is_none() {
            return Err(eyre!(
                "the frames in {} did not carry a complete payload ({}/{} atoms)",
                report.input_dir,
                report.rank,
                report.source_atoms
            ));
        }
        Ok(())
    }
}

impl DecodeArgs {
    fn decode(&self) -> Result<DecodeReport> {
        if self.fps == 0 || self.fps > 240 {
            return Err(eyre!("--fps must be between 1 and 240"));
        }
        let mut frames: Vec<PathBuf> = fs::read_dir(&self.input_dir)
            .wrap_err_with(|| format!("failed to read {}", self.input_dir.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("png"))
            })
            .collect();
        frames.sort();
        if frames.is_empty() {
            return Err(eyre!("no PNG frames found in {}", self.input_dir.display()));
        }
        let limits = ScanLimits {
            assembler: AssemblerLimits {
                max_payload_len: self.max_payload,
                ..AssemblerLimits::default()
            },
            ..ScanLimits::default()
        };
        let mut session = ScanSession::new(limits);
        let mut report = DecodeReport {
            schema: DECODE_SCHEMA.to_owned(),
            input_dir: self.input_dir.display().to_string(),
            output_path: None,
            frames_read: 0,
            frames_located: 0,
            frames_readable: 0,
            frames_tracked: 0,
            frames_inferred: 0,
            lane_p_frames: 0,
            lane_k_frames: 0,
            lane_d_frames: 0,
            completed_at_frame: None,
            payload_bytes: None,
            kind: None,
            payload_crc32c: None,
            rank: 0,
            source_atoms: 0,
        };
        for (index, path) in frames.iter().enumerate() {
            let luma = read_png_luma(path)?;
            let now_ms = index as u64 * 1_000 / u64::from(self.fps);
            let outcome = session.push(&luma, now_ms);
            report.frames_read += 1;
            report.rank = outcome.progress.rank as u64;
            report.source_atoms = outcome.progress.source_atoms as u64;
            if let Some(done) = outcome.completed {
                fs::write(&self.output, &done.payload)
                    .wrap_err_with(|| format!("failed to write {}", self.output.display()))?;
                report.output_path = Some(self.output.display().to_string());
                report.completed_at_frame = Some(index as u64);
                report.payload_bytes = Some(done.payload.len() as u64);
                report.kind = Some(done.meta.kind);
                report.payload_crc32c = Some(format!("{:08x}", done.meta.crc));
                break;
            }
        }
        let stats = session.stats();
        report.frames_located = u64::from(stats.located);
        report.frames_readable = u64::from(stats.readable);
        report.frames_tracked = u64::from(stats.tracked);
        report.frames_inferred = u64::from(stats.inferred);
        report.lane_p_frames = u64::from(stats.lane_p);
        report.lane_k_frames = u64::from(stats.lane_k);
        report.lane_d_frames = u64::from(stats.lane_d);
        Ok(report)
    }
}

impl Run for InspectArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let report = self.inspect()?;
        let lanes: String = [
            ("P", &report.lane_p),
            ("K", &report.lane_k),
            ("D", &report.lane_d),
        ]
        .iter()
        .filter(|(_, lane)| lane.is_some())
        .map(|(letter, _)| *letter)
        .collect();
        let text = match &report.error {
            Some(error) => format!("no lane decoded: {error}"),
            None => format!("lanes decoded: {lanes}"),
        };
        let readable = !lanes.is_empty();
        print_with_optional_text(context, Some(text), &report)?;
        if readable {
            Ok(())
        } else {
            Err(eyre!(
                "no Petal lane could be decoded from {}",
                self.input.display()
            ))
        }
    }
}

impl InspectArgs {
    fn inspect(&self) -> Result<InspectReport> {
        let luma = read_png_luma(&self.input)?;
        let mut report = InspectReport {
            schema: INSPECT_SCHEMA.to_owned(),
            input_path: self.input.display().to_string(),
            width: luma.width as u32,
            height: luma.height as u32,
            error: None,
            rotation_quarter_turns: None,
            mirrored: None,
            inferred_corner: None,
            lane_p: None,
            lane_k: None,
            lane_d: None,
            frame_counter: None,
            beacon_kind: None,
            beacon_payload_bytes: None,
            beacon_payload_crc32c: None,
        };
        match decode(&luma, &DecodeOptions::default()) {
            Err(error) => report.error = Some(error.to_string()),
            Ok(frame) => {
                let lane = |result: &Option<iroha_petal::decode::LaneResult>| {
                    result.as_ref().map(|r| LaneReport {
                        corrected_bytes: r.corrected as u64,
                        erased_bytes: r.erasures as u64,
                    })
                };
                report.rotation_quarter_turns = Some(frame.rotation);
                report.mirrored = Some(frame.mirrored);
                report.inferred_corner = frame.inferred_corner;
                report.lane_p = lane(&frame.p);
                report.lane_k = lane(&frame.k);
                report.lane_d = lane(&frame.d);
                match frame.d_lane() {
                    Some(DLane::Beacon(beacon)) => {
                        report.frame_counter = Some(beacon.header.frame);
                        report.beacon_kind = Some(beacon.meta.kind);
                        report.beacon_payload_bytes = Some(u64::from(beacon.meta.len));
                        report.beacon_payload_crc32c = Some(format!("{:08x}", beacon.meta.crc));
                    }
                    Some(DLane::Atoms(packet)) => report.frame_counter = Some(packet.header.frame),
                    None => {
                        report.frame_counter = frame
                            .atom_packets()
                            .first()
                            .map(|packet| packet.header.frame);
                    }
                }
                if frame.lanes_ok() == 0 {
                    report.error = Some(
                        "a code was located but no lane passed its Reed-Solomon check".to_owned(),
                    );
                }
            }
        }
        Ok(report)
    }
}

impl Run for SimulateArgs {
    fn run<C: RunContext>(self, context: &mut C) -> Result<()> {
        let report = self.simulate()?;
        let text = match report.completion_seconds_mean {
            Some(mean) => format!(
                "{}: {}/{} trials completed {} bytes in {:.1} s on average ({:.0} B/s, lane K in {:.0} % of frames)",
                report.camera,
                report.completed,
                report.trials,
                report.payload_bytes,
                mean,
                report.effective_payload_bytes_per_second.unwrap_or(0.0),
                report.lane_k_frame_share * 100.0
            ),
            None => format!("{}: no trial completed within the horizon", report.camera),
        };
        print_with_optional_text(context, Some(text), &report)
    }
}

impl SimulateArgs {
    fn simulate(&self) -> Result<SimulateReport> {
        if self.trials == 0 || self.trials > MAX_SIMULATION_TRIALS {
            return Err(eyre!(
                "--trials must be between 1 and {MAX_SIMULATION_TRIALS}"
            ));
        }
        if self.fps == 0 || self.fps > MAX_FPS {
            return Err(eyre!("--fps must be between 1 and {MAX_FPS}"));
        }
        let camera = CameraModel::named(&self.camera).ok_or_else(|| {
            eyre!(
                "unknown camera '{}', expected one of: {}",
                self.camera,
                CameraModel::NAMES.join(", ")
            )
        })?;
        let payload = if let Some(path) = &self.input {
            fs::read(path).wrap_err_with(|| format!("failed to read payload {}", path.display()))?
        } else {
            let mut rng = iroha_petal::prng::Xorshift32::new(0x5EED_0001);
            (0..self.bytes).map(|_| rng.next_byte()).collect()
        };
        if payload.is_empty() || payload.len() > MAX_PAYLOAD_LEN {
            return Err(eyre!(
                "payload length {} is outside 1..={MAX_PAYLOAD_LEN}",
                payload.len()
            ));
        }
        let threads = std::thread::available_parallelism()
            .map_or(2, usize::from)
            .min(self.trials as usize);
        let next = std::sync::atomic::AtomicU32::new(0);
        let outcomes = std::sync::Mutex::new(Vec::<TrialOutcome>::new());
        std::thread::scope(|scope| {
            for _ in 0..threads {
                scope.spawn(|| {
                    loop {
                        let trial = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if trial >= self.trials {
                            break;
                        }
                        let spec = StreamTrial {
                            display_fps: f64::from(self.fps),
                            horizon_s: f64::from(self.horizon_seconds),
                            ..StreamTrial::typical(camera, self.seed.wrapping_add(u64::from(trial)))
                        };
                        let outcome = run_stream_trial(&payload, self.kind, &spec);
                        outcomes
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(outcome);
                    }
                });
            }
        });
        let outcomes = outcomes
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut times: Vec<f64> = outcomes
            .iter()
            .filter(|o| o.payload_matches)
            .filter_map(|o| o.completed_at_s)
            .collect();
        times.sort_by(f64::total_cmp);
        let mean = (!times.is_empty()).then(|| times.iter().sum::<f64>() / times.len() as f64);
        let frames: u64 = outcomes.iter().map(|o| u64::from(o.frames)).sum();
        let k_frames: u64 = outcomes.iter().map(|o| u64::from(o.lanes[1])).sum();
        Ok(SimulateReport {
            schema: SIMULATE_SCHEMA.to_owned(),
            camera: self.camera.clone(),
            payload_bytes: payload.len() as u64,
            display_fps: self.fps,
            trials: outcomes.len() as u64,
            completed: times.len() as u64,
            wrong_payloads: outcomes
                .iter()
                .filter(|o| o.completed_at_s.is_some() && !o.payload_matches)
                .count() as u64,
            completion_seconds_mean: mean,
            completion_seconds_median: times.get(times.len().saturating_sub(1) / 2).copied(),
            completion_seconds_worst: times.last().copied(),
            effective_payload_bytes_per_second: mean.map(|m| payload.len() as f64 / m),
            lane_k_frame_share: k_frames as f64 / frames.max(1) as f64,
            mean_decode_milliseconds: outcomes.iter().map(|o| o.mean_decode_ms).sum::<f64>()
                / outcomes.len().max(1) as f64,
        })
    }
}

fn write_png_rgb(path: &Path, pixels: &[u8], size: u32) -> Result<()> {
    let file = fs::File::create(path)
        .wrap_err_with(|| format!("failed to create PNG {}", path.display()))?;
    let mut encoder = png::Encoder::new(BufWriter::new(file), size, size);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.set_compression(png::Compression::Fast);
    let mut writer = encoder
        .write_header()
        .wrap_err_with(|| format!("failed to write PNG header {}", path.display()))?;
    writer
        .write_image_data(pixels)
        .wrap_err_with(|| format!("failed to write PNG pixels {}", path.display()))
}

/// Reads an 8-bit PNG (gray, gray+alpha, RGB or RGBA; palettes are expanded)
/// as a Rec. 601 luma plane.
fn read_png_luma(path: &Path) -> Result<Luma> {
    let file =
        fs::File::open(path).wrap_err_with(|| format!("failed to open PNG {}", path.display()))?;
    let mut decoder = png::Decoder::new(BufReader::new(file));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder
        .read_info()
        .wrap_err_with(|| format!("failed to read PNG info {}", path.display()))?;
    let size = reader
        .output_buffer_size()
        .ok_or_else(|| eyre!("PNG output buffer size unavailable"))?;
    let mut buffer = vec![0; size];
    let info = reader
        .next_frame(&mut buffer)
        .wrap_err_with(|| format!("failed to decode PNG {}", path.display()))?;
    let bytes = &buffer[..info.buffer_size()];
    let (channels, is_color) = match info.color_type {
        png::ColorType::Grayscale => (1, false),
        png::ColorType::GrayscaleAlpha => (2, false),
        png::ColorType::Rgb => (3, true),
        png::ColorType::Rgba => (4, true),
        png::ColorType::Indexed => return Err(eyre!("indexed PNG was not expanded")),
    };
    let data: Vec<u8> = bytes
        .chunks_exact(channels)
        .map(|px| {
            if is_color {
                ((299 * u32::from(px[0]) + 587 * u32::from(px[1]) + 114 * u32::from(px[2]) + 500)
                    / 1_000) as u8
            } else {
                px[0]
            }
        })
        .collect();
    Luma::from_raw(info.width as usize, info.height as usize, data)
        .ok_or_else(|| eyre!("PNG pixel buffer does not match its dimensions"))
}

#[cfg(feature = "offline-visual-codecs")]
#[allow(clippy::unnecessary_wraps)]
fn validate_gif_available() -> Result<()> {
    Ok(())
}

#[cfg(not(feature = "offline-visual-codecs"))]
fn validate_gif_available() -> Result<()> {
    Err(eyre!(
        "--format gif requires building iroha_cli with --features offline-visual-codecs"
    ))
}

#[cfg(feature = "offline-visual-codecs")]
fn write_gif(path: &Path, frames: &[Vec<u8>], size: u32, fps: u16) -> Result<()> {
    use image::{
        Delay, Frame, RgbaImage,
        codecs::gif::{GifEncoder, Repeat},
    };
    let delay_ms = (1_000u32 / u32::from(fps)).max(1);
    let file = fs::File::create(path)
        .wrap_err_with(|| format!("failed to create GIF {}", path.display()))?;
    let mut encoder = GifEncoder::new(BufWriter::new(file));
    encoder
        .set_repeat(Repeat::Infinite)
        .wrap_err_with(|| format!("failed to set GIF repeat {}", path.display()))?;
    for rgb in frames {
        let rgba: Vec<u8> = rgb
            .chunks_exact(3)
            .flat_map(|px| [px[0], px[1], px[2], 255])
            .collect();
        let image = RgbaImage::from_raw(size, size, rgba)
            .ok_or_else(|| eyre!("failed to build GIF frame buffer"))?;
        encoder
            .encode_frame(Frame::from_parts(
                image,
                0,
                0,
                Delay::from_numer_denom_ms(delay_ms, 1),
            ))
            .wrap_err_with(|| format!("failed to write GIF frame {}", path.display()))?;
    }
    Ok(())
}

#[cfg(not(feature = "offline-visual-codecs"))]
fn write_gif(_path: &Path, _frames: &[Vec<u8>], _size: u32, _fps: u16) -> Result<()> {
    validate_gif_available()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_petal::crc::crc32c;
    use tempfile::tempdir;

    fn sample_payload(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i.wrapping_mul(31) ^ (i >> 3)) as u8)
            .collect()
    }

    fn encode_args(input: &Path, output: &Path) -> EncodeArgs {
        EncodeArgs {
            input: input.to_path_buf(),
            output: output.to_path_buf(),
            kind: 2,
            frames: 0,
            first_frame: 0,
            size: 512,
            fps: 8,
            format: EncodeFormat::Png,
        }
    }

    #[test]
    fn encode_then_decode_roundtrips_a_payload() {
        let dir = tempdir().expect("tempdir");
        let payload = sample_payload(300);
        let input = dir.path().join("payload.bin");
        fs::write(&input, &payload).expect("write payload");
        let frames = dir.path().join("frames");
        let report = encode_args(&input, &frames).encode().expect("encode");
        assert_eq!(report.schema, ENCODE_SCHEMA);
        assert_eq!(report.payload_bytes, 300);
        assert_eq!(report.kind, 2);
        assert!(u64::from(report.rendered_frames) >= report.systematic_frames);
        assert_eq!(report.files.len(), usize::from(report.rendered_frames));
        assert!(frames.join("manifest.json").exists());
        let output = dir.path().join("decoded.bin");
        let decoded = DecodeArgs {
            input_dir: frames,
            output: output.clone(),
            fps: 8,
            max_payload: DEFAULT_MAX_PAYLOAD_LEN,
        }
        .decode()
        .expect("decode");
        assert!(decoded.completed_at_frame.is_some());
        assert_eq!(decoded.payload_bytes, Some(300));
        assert_eq!(decoded.kind, Some(2));
        assert_eq!(fs::read(output).expect("payload out"), payload);
        assert_eq!(
            decoded.payload_crc32c,
            Some(format!("{:08x}", crc32c(&payload)))
        );
    }

    #[test]
    fn decode_reports_incomplete_streams() {
        let dir = tempdir().expect("tempdir");
        let input = dir.path().join("payload.bin");
        fs::write(&input, sample_payload(900)).expect("write payload");
        let frames = dir.path().join("frames");
        let mut args = encode_args(&input, &frames);
        args.frames = 3;
        args.encode().expect("encode");
        let report = DecodeArgs {
            input_dir: frames,
            output: dir.path().join("out.bin"),
            fps: 8,
            max_payload: DEFAULT_MAX_PAYLOAD_LEN,
        }
        .decode()
        .expect("decode runs");
        assert!(report.completed_at_frame.is_none());
        assert!(report.rank > 0 && report.rank < report.source_atoms);
    }

    #[test]
    fn inspect_reads_lanes_and_the_beacon() {
        let dir = tempdir().expect("tempdir");
        let input = dir.path().join("payload.bin");
        fs::write(&input, sample_payload(100)).expect("write payload");
        let frames = dir.path().join("frames");
        encode_args(&input, &frames).encode().expect("encode");
        let report = InspectArgs {
            input: frames.join("frame_0000.png"),
        }
        .inspect()
        .expect("inspect");
        assert!(report.error.is_none(), "{:?}", report.error);
        assert!(report.lane_p.is_some() && report.lane_k.is_some() && report.lane_d.is_some());
        assert_eq!(report.frame_counter, Some(0));
        assert_eq!(report.beacon_kind, Some(2));
        assert_eq!(report.beacon_payload_bytes, Some(100));
        assert_eq!(report.mirrored, Some(false));
        assert_eq!(report.inferred_corner, None);
    }

    #[test]
    fn inspect_reports_blank_images_without_panicking() {
        let dir = tempdir().expect("tempdir");
        let blank = dir.path().join("blank.png");
        write_png_rgb(&blank, &vec![0u8; 128 * 128 * 3], 128).expect("png");
        let report = InspectArgs { input: blank }.inspect().expect("inspect");
        assert!(report.error.is_some());
        assert!(report.lane_p.is_none() && report.lane_d.is_none());
    }

    #[test]
    fn simulate_reports_a_completed_trial() {
        let report = SimulateArgs {
            input: None,
            bytes: 60,
            camera: "modern".to_owned(),
            fps: 12,
            trials: 1,
            horizon_seconds: 30,
            seed: 3,
            kind: 1,
        }
        .simulate()
        .expect("simulate");
        assert_eq!(report.schema, SIMULATE_SCHEMA);
        assert_eq!(report.completed, 1);
        assert_eq!(report.wrong_payloads, 0);
        assert!(report.completion_seconds_mean.is_some());
    }

    #[test]
    fn invalid_arguments_are_rejected() {
        let dir = tempdir().expect("tempdir");
        let input = dir.path().join("payload.bin");
        fs::write(&input, [1u8, 2, 3]).expect("write payload");
        let mut args = encode_args(&input, &dir.path().join("out"));
        args.size = 100;
        assert!(args.encode().unwrap_err().to_string().contains("--size"));
        let mut args = encode_args(&input, &dir.path().join("out"));
        args.fps = 0;
        assert!(args.encode().unwrap_err().to_string().contains("--fps"));
        let empty = dir.path().join("empty.bin");
        fs::write(&empty, []).expect("write empty");
        assert!(
            encode_args(&empty, &dir.path().join("out"))
                .encode()
                .is_err()
        );
        let unknown = SimulateArgs {
            input: None,
            bytes: 10,
            camera: "potato".to_owned(),
            fps: 8,
            trials: 1,
            horizon_seconds: 5,
            seed: 1,
            kind: 0,
        };
        assert!(
            unknown
                .simulate()
                .unwrap_err()
                .to_string()
                .contains("unknown camera")
        );
        assert!(
            DecodeArgs {
                input_dir: dir.path().join("missing"),
                output: dir.path().join("o"),
                fps: 8,
                max_payload: 1
            }
            .decode()
            .is_err()
        );
    }

    #[cfg(not(feature = "offline-visual-codecs"))]
    #[test]
    fn gif_requires_the_visual_codecs_feature() {
        let dir = tempdir().expect("tempdir");
        let input = dir.path().join("payload.bin");
        fs::write(&input, [7u8; 20]).expect("write payload");
        let mut args = encode_args(&input, &dir.path().join("out"));
        args.format = EncodeFormat::Gif;
        assert!(
            args.encode()
                .unwrap_err()
                .to_string()
                .contains("offline-visual-codecs")
        );
    }

    #[cfg(feature = "offline-visual-codecs")]
    #[test]
    fn gif_output_is_a_single_looping_animation() {
        let dir = tempdir().expect("tempdir");
        let input = dir.path().join("payload.bin");
        fs::write(&input, sample_payload(80)).expect("write payload");
        let mut args = encode_args(&input, &dir.path().join("out"));
        args.format = EncodeFormat::Gif;
        args.size = 256;
        let report = args.encode().expect("encode gif");
        assert_eq!(report.files, vec!["stream.gif".to_owned()]);
        let bytes = fs::read(dir.path().join("out/stream.gif")).expect("gif");
        assert_eq!(&bytes[..6], b"GIF89a");
    }
}
