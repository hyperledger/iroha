//! Local, credential-free native racing prover, verifier, and parity-fixture generator.
//! Run with `cargo iroha-fast -- run -p iroha_core --example race_prover -- <command>`.

use iroha_core_privacy::execution_proofs::*;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    block::BlockHeader,
    execution_proofs::*,
    game::{GameAdmissionBodyV1, GameAdmissionParticipantV1, game_roster_hash_v1},
};
use norito::codec::{Decode, Encode};
use std::{error::Error, fs, path::Path, time::Instant};

fn read_exact<T: Decode + Encode>(path: &str) -> Result<T, Box<dyn Error>> {
    if fs::metadata(path)?.len() > RACE_MAX_PROOF_BYTES_V1 as u64 {
        return Err("input exceeds native proof cap".into());
    }
    let bytes = fs::read(path)?;
    let mut remaining = bytes.as_slice();
    let value = T::decode(&mut remaining)?;
    if !remaining.is_empty() || value.encode() != bytes {
        return Err("noncanonical Norito input".into());
    }
    Ok(value)
}

fn sample_replay(
    track: RaceTrackV1,
    players: u8,
    ticks: u32,
) -> Result<RaceReplayV1, Box<dyn Error>> {
    let mut replay = RaceReplayV1 {
        track,
        player_count: players,
        frames: vec![],
        dnf_events: vec![],
    };
    let mut state = initial_race_state_v1(track, players)?;
    for tick in 0..ticks {
        if tick % 6 == 0 && state.cars.iter().all(|car| car.finish_tick.is_some()) {
            break;
        }
        let controls = state
            .cars
            .iter()
            .enumerate()
            .map(|(slot, car)| {
                let target = if slot % 2 == 0 { -1_600 } else { 1_600 };
                let steer = if car.lateral_mm + car.lateral_velocity_mm_per_tick * 8 > target + 150
                {
                    4
                } else if car.lateral_mm + car.lateral_velocity_mm_per_tick * 8 < target - 150 {
                    8
                } else {
                    0
                };
                1 | 16
                    | steer
                    | if (tick + u32::try_from(slot).expect("fixture value fits u32") * 11) % 90
                        < 25
                    {
                        32
                    } else {
                        0
                    }
            })
            .collect();
        let frame = RaceInputFrameV1 { tick, controls };
        step_race_v1(&mut state, &frame)?;
        replay.frames.push(frame);
    }
    if replay.frames.len() < RACE_MAX_TICKS_V1 as usize
        && !state.cars.iter().all(|car| car.finish_tick.is_some())
    {
        replay.dnf_events.push(RaceDnfEventV1 {
            tick: state.tick,
            slots: (0..players)
                .filter(|slot| state.cars[usize::from(*slot)].finish_tick.is_none())
                .collect(),
        });
    }
    Ok(replay)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str){
        Some("prove") if args.len()==3=>{
            let request:RaceProverRequestV1=read_exact(&args[1])?;let start=Instant::now();let proof=prove_race_v1(request)?;
            let bytes=proof.encode();fs::write(&args[2],&bytes)?;
            println!("native proof verified; bytes={} elapsed_seconds={:.3}",bytes.len(),start.elapsed().as_secs_f64());
        },
        Some("verify") if args.len()==2=>{
            let proof:ExecutionProofEnvelopeV1=read_exact(&args[1])?;let start=Instant::now();verify_race_proof_v1(&proof)?;
            println!("native execution verified; elapsed_seconds={:.3}",start.elapsed().as_secs_f64());
        },
        Some("sample") if args.len()==4=>{
            let players=args[1].parse::<u8>()?;let ticks=args[2].parse::<u32>()?;
            if !(2..=8).contains(&players)||ticks==0||ticks>5400||ticks%6!=0{return Err("ticks must be a positive multiple of six, at most 5400".into());}
            let replay=sample_replay(RaceTrackV1::NeonTokyo,players,ticks)?;let final_state=replay_race_v1(&replay)?;
            let network_id=NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"race-prover-local-fixture-network")));
            let manifest=iroha_data_model::game::GameManifestV1{version:1,application_id:Hash::new(b"local-racing-game"),profile_id:race_profile_id_v1(),application_parameters:replay.track.encode(),min_participants:2,max_participants:players,batch_ticks:6,max_ticks:5400,max_input_bytes:12,max_participant_data_bytes:1,access:iroha_data_model::game::GameAccessV1::Public,payout_policy:iroha_data_model::game::GamePayoutPolicyV1::NoPayout};
            let result=race_result_v1(&final_state)?;
            let outcome=iroha_data_model::game::GameOutcomeV1{terminal_tick:final_state.tick,winner_slots:result.winners.clone(),result:result.encode()};
            // Public deterministic sample identities only; this command never funds a session.
            let admission=GameAdmissionBodyV1{version:1,participants:(0..players).map(|slot| {
                let wallet=KeyPair::try_from_seed(vec![slot+1;32],Algorithm::Ed25519).expect("fixture wallet");
                let input=KeyPair::try_from_seed(vec![slot+65;32],Algorithm::Ed25519).expect("fixture input key");
                GameAdmissionParticipantV1{account:AccountId::new(wallet.public_key().clone()),input_key:input.public_key().clone(),application_data:vec![slot%RACE_SKIN_COUNT_V1]}
            }).collect(),wagers:vec![],resources:vec![]};
            let session_id=Hash::new(b"race-prover-local-fixture");
            let request=RaceProverRequestV1{statement:ExecutionPublicInputsV1{network_id,session_id,manifest_hash:iroha_data_model::game::game_message_hash_v1(&network_id,"session-manifest",&manifest),roster_hash:game_roster_hash_v1(&network_id,&session_id,&admission),transcript_root:race_transcript_root_v1(&network_id,&replay),dispute_root:Hash::new(b"local-fixture-history"),outcome_hash:iroha_data_model::game::game_message_hash_v1(&network_id,"session-outcome",&outcome)},manifest,admission,replay,checkpoint_state:None};
            fs::write(&args[3],request.encode())?;println!("wrote local prover request {}: players={} ticks={}",args[3],request.replay.player_count,request.replay.frames.len());
        },
        Some("fixtures") if args.len()==2=>{
            let fixtures=export_race_parity_json_v1()?;
            if let Some(parent)=Path::new(&args[1]).parent(){fs::create_dir_all(parent)?;}
            fs::write(&args[1],norito::json::to_json_pretty(&fixtures)?)?;println!("wrote all 21 native parity fixtures");
        },
        _=>return Err("usage: race_prover prove request.nrt proof.nrt | verify proof.nrt | sample <players> <ticks> request.nrt | fixtures output.json".into()),
    }
    Ok(())
}
