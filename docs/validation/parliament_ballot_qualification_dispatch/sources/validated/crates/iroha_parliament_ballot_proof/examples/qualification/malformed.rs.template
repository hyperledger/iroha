//! Bounded malformed-encoding observations through the cold test-record path.
//! Inputs and fixed test proofs are constructed outside timed phases. This is
//! engineering evidence, not a production envelope or hardware qualification.

use std::ops::Range;

use iroha_parliament_ballot_proof::framing::frame_bytes;
use iroha_zkp_vole::{bavc, codec::CodecError};

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mutation {
    Empty,
    Truncated,
    Trailing,
    RecordLength,
    ProofLength,
    Tag,
    FieldCount,
    FieldLength,
    Descriptor,
    StatementTrailing,
    Counter,
    Grinding,
    OpeningPadding,
    OpeningOverflow,
    BodyOversized,
    BodyDigest,
    NullifierLength,
    AuthorizationLength,
    Choice,
    ListAlignment,
    ListDuplicate,
    ListOrder,
    ListDigest,
    ListSize,
}

impl Mutation {
    fn all(case: Case) -> Vec<Self> {
        use Mutation::*;
        let mut values = vec![
            Empty,
            Truncated,
            Trailing,
            RecordLength,
            ProofLength,
            Tag,
            FieldCount,
            FieldLength,
            Descriptor,
            StatementTrailing,
            Counter,
            Grinding,
            OpeningPadding,
            OpeningOverflow,
        ];
        values.extend(match case {
            Case::Registration => vec![BodyOversized, BodyDigest],
            Case::Vote(_) => vec![
                NullifierLength,
                AuthorizationLength,
                Choice,
                ListAlignment,
                ListDuplicate,
                ListOrder,
                ListDigest,
                ListSize,
            ],
        });
        values
    }

    fn name(self) -> &'static str {
        match self {
            Self::Empty => "empty_record",
            Self::Truncated => "truncated_record",
            Self::Trailing => "trailing_record_byte",
            Self::RecordLength => "record_statement_length_u32_max",
            Self::ProofLength => "record_proof_length_zero",
            Self::Tag => "wrong_statement_tag",
            Self::FieldCount => "wrong_statement_field_count",
            Self::FieldLength => "statement_field_length_u32_max",
            Self::Descriptor => "wrong_descriptor_digest",
            Self::StatementTrailing => "trailing_statement_byte",
            Self::Counter => "proof_counter_above_limit",
            Self::Grinding => "proof_grinding_bit_set",
            Self::OpeningPadding => "proof_nonzero_opening_padding",
            Self::OpeningOverflow => "proof_opening_above_capacity",
            Self::BodyOversized => "registration_body_above_limit",
            Self::BodyDigest => "registration_body_digest_mismatch",
            Self::NullifierLength => "vote_nullifier_length_127",
            Self::AuthorizationLength => "vote_authorization_length_63",
            Self::Choice => "vote_choice_outside_enum",
            Self::ListAlignment => "list_partial_entry",
            Self::ListDuplicate => "list_duplicate_entry",
            Self::ListOrder => "list_reversed_pair",
            Self::ListDigest => "list_digest_mismatch",
            Self::ListSize => "list_size_mismatch",
        }
    }

    fn outcome(self) -> &'static str {
        match self {
            Self::Counter | Self::Grinding | Self::OpeningPadding | Self::OpeningOverflow => {
                "verification_rejected"
            }
            _ => "decode_rejected",
        }
    }

    fn matches_codec_error(self, error: &ProofError) -> bool {
        matches!(
            (self, error),
            (
                Self::Counter,
                ProofError::Codec(CodecError::CounterOutOfRange { .. })
            ) | (
                Self::Grinding,
                ProofError::Codec(CodecError::Challenge(bavc::BavcError::GrindingBitsSet))
            ) | (
                Self::OpeningPadding,
                ProofError::Codec(CodecError::NonZeroPadding {
                    field: iroha_zkp_vole::codec::Field::Decommitment
                })
            ) | (
                Self::OpeningOverflow,
                ProofError::Codec(CodecError::Challenge(
                    bavc::BavcError::OpeningTooLarge { .. }
                ))
            )
        )
    }
}

/// Locate fields in our already bounded canonical test statement.
fn field_ranges(statement: &[u8]) -> Result<Vec<Range<usize>>> {
    let tag_len = usize::from(u16::from_le_bytes(
        statement.get(..2).ok_or("missing tag length")?.try_into()?,
    ));
    let mut position = 2 + tag_len;
    let count = usize::from(u16::from_le_bytes(
        statement
            .get(position..position + 2)
            .ok_or("missing field count")?
            .try_into()?,
    ));
    position += 2;
    let mut fields = Vec::new();
    for _ in 0..count {
        let length = usize::try_from(u32::from_le_bytes(
            statement
                .get(position..position + 4)
                .ok_or("missing field length")?
                .try_into()?,
        ))?;
        position += 4;
        let end = position
            .checked_add(length)
            .ok_or("field length overflow")?;
        statement.get(position..end).ok_or("truncated field")?;
        fields.push(position..end);
        position = end;
    }
    if position != statement.len() {
        return Err("trailing frame data".into());
    }
    Ok(fields)
}

fn mutant(row: Row, case: Case, mutation: Mutation, record: &[u8]) -> Result<Vec<u8>> {
    let profile = Profile::new(row)?;
    let (statement, proof) = test_codec::decode_record(&profile, case.role(), record)?;
    match mutation {
        Mutation::Empty => return Ok(Vec::new()),
        Mutation::Truncated => return Ok(record[..record.len() - 1].to_vec()),
        Mutation::Trailing => return Ok([record, &[1]].concat()),
        Mutation::RecordLength => {
            let mut result = record.to_vec();
            result[..4].copy_from_slice(&u32::MAX.to_le_bytes());
            return Ok(result);
        }
        Mutation::ProofLength => {
            let mut result = record.to_vec();
            result[4 + statement.len()..8 + statement.len()].fill(0);
            return Ok(result);
        }
        _ => {}
    }
    let mut statement = statement.to_vec();
    let mut proof = proof.to_vec();
    let fields = field_ranges(&statement)?;
    match mutation {
        Mutation::Tag => statement[2] ^= 1,
        Mutation::FieldCount => statement[fields[0].start - 6] ^= 1,
        Mutation::FieldLength => {
            statement[fields[0].start - 4..fields[0].start]
                .copy_from_slice(&u32::MAX.to_le_bytes());
        }
        Mutation::Descriptor => statement[fields[0].start] ^= 1,
        Mutation::StatementTrailing => statement.push(1),
        Mutation::Counter => {
            let start = field_offset(row, case.role(), ProofField::Counter);
            proof[start..start + 4].copy_from_slice(&0x0010_0000_u32.to_le_bytes());
        }
        Mutation::Grinding => {
            let start = field_offset(row, case.role(), ProofField::Challenge);
            proof[start + 31] |= 0x80;
        }
        Mutation::OpeningPadding => {
            // Zero hidden indices need fewer opening nodes on both frozen rows.
            // Make the final seed slot padding explicitly nonzero.
            let start = field_offset(row, case.role(), ProofField::Challenge);
            proof[start..start + 32].fill(0);
            let hidden = bavc::decode_challenge(&row.vole(), &proof[start..start + 32])?;
            if bavc::opening_nodes(&row.vole(), &hidden)? >= row.vole().t_open() {
                return Err("zero challenge has no opening padding".into());
            }
            proof[start - 1] = 1;
        }
        Mutation::OpeningOverflow => {
            let start = field_offset(row, case.role(), ProofField::Challenge);
            let mut found = false;
            for nonce in 0..10_000 {
                let mut challenge = derive::<32>(&format!("malformed-opening/{nonce}"));
                challenge[31] &= u8::try_from(0xff_u16 >> row.vole().w_grind())
                    .expect("the grinding mask fits a byte");
                let hidden = bavc::decode_challenge(&row.vole(), &challenge)?;
                if bavc::opening_nodes(&row.vole(), &hidden)? > row.vole().t_open() {
                    proof[start..start + 32].copy_from_slice(&challenge);
                    found = true;
                    break;
                }
            }
            if !found {
                return Err("bounded opening-overflow search found no input".into());
            }
        }
        other => {
            let mut values: Vec<Vec<u8>> = fields
                .iter()
                .map(|range| statement[range.clone()].to_vec())
                .collect();
            match other {
                Mutation::BodyOversized => values[1].push(0),
                Mutation::BodyDigest => values[8][0] ^= 1,
                Mutation::NullifierLength => {
                    values[6].pop();
                }
                Mutation::AuthorizationLength => {
                    values[7].pop();
                }
                Mutation::Choice => values[8][0] = 0xff,
                Mutation::ListAlignment => {
                    values[5].pop();
                }
                Mutation::ListDuplicate => {
                    let first = values[5][..128].to_vec();
                    values[5][128..256].copy_from_slice(&first);
                }
                Mutation::ListOrder => {
                    for index in 0..128 {
                        values[5].swap(index, index + 128);
                    }
                }
                Mutation::ListDigest => values[3][0] ^= 1,
                Mutation::ListSize => {
                    let size = if case.seats() == 1000 {
                        999
                    } else {
                        case.seats() + 1
                    };
                    values[4].copy_from_slice(&u16::try_from(size)?.to_le_bytes());
                }
                _ => unreachable!("record/proof mutations handled above"),
            }
            let tag = match case {
                Case::Registration => test_codec::REGISTRATION_TAG,
                Case::Vote(_) => test_codec::VOTE_TAG,
            };
            statement = frame_bytes(tag, &values.iter().map(Vec::as_slice).collect::<Vec<_>>())?;
        }
    }
    Ok(test_codec::encode_record(&statement, &proof)?)
}

fn outcome(result: &Result<std::result::Result<(), VerifyError>>) -> &'static str {
    match result {
        Ok(Ok(())) => "accepted",
        Ok(Err(_)) => "verification_rejected",
        Err(_) => "decode_rejected",
    }
}

#[derive(JsonSerialize)]
struct MalformedSample<'a> {
    kind: &'static str,
    row: &'static str,
    case: &'static str,
    mutation: &'static str,
    sample_index: usize,
    record_bytes: usize,
    record_shake256_32: &'a str,
    outcome: &'static str,
    metric: Metric,
}

#[derive(JsonSerialize)]
struct MalformedSummary<'a> {
    kind: &'static str,
    row: &'static str,
    case: &'static str,
    mutation: &'static str,
    diagnostic: &'a str,
    metrics: PhaseSummary,
}

fn summarize_metrics(name: &'static str, samples: &[Metric]) -> PhaseSummary {
    let collect = |field: fn(&Metric) -> usize| {
        distribution(
            samples
                .iter()
                .map(|m| u64::try_from(field(m)).unwrap_or(u64::MAX))
                .collect(),
        )
    };
    PhaseSummary {
        name,
        elapsed_ns: distribution(samples.iter().map(|m| m.elapsed_ns).collect()),
        total_peak_live_bytes: collect(|m| m.total_peak_live_bytes),
        incremental_peak_bytes: collect(|m| m.incremental_peak_bytes),
        live_at_entry_bytes: collect(|m| m.live_at_entry_bytes),
        allocation_calls: collect(|m| m.allocation_calls),
        allocated_bytes: collect(|m| m.allocated_bytes),
    }
}

fn run_case(row: Row, case: Case, count: usize, output: &mut impl Write) -> Result<()> {
    let prepared = prepare(row, case)?;
    let tape = ProvingTape::from_bytes(&derive(&format!(
        "malformed-tape/{}/{}",
        row_name(row),
        case.name()
    )));
    let proof = prepared
        .statement
        .prove(row, &prepared.secret, prepared.position, tape)?;
    let statement = prepared.statement.encode(&prepared.profile)?;
    let record = test_codec::encode_record(&statement, &proof)?;
    drop(proof);
    drop(statement);
    drop(prepared);
    cold_verify(row, case, &record)??;
    for mutation in Mutation::all(case) {
        let bytes = mutant(row, case, mutation, &record)?;
        let digest = proof_digest(&bytes);
        let preflight = cold_verify(row, case, &bytes);
        if outcome(&preflight) != mutation.outcome() {
            return Err(format!(
                "unexpected preflight for {}: {preflight:?}",
                mutation.name()
            )
            .into());
        }
        let diagnostic = if mutation.outcome() == "verification_rejected" {
            let profile = Profile::new(row)?;
            let (statement, proof) = decode_record(row, case, &bytes)?;
            let error = statement.backend_diagnostic(&profile, proof)?;
            if !mutation.matches_codec_error(&error) {
                return Err(
                    format!("expected malformed proof codec rejection, got {error:?}").into(),
                );
            }
            format!("{error:?}")
        } else {
            format!("{}", preflight.expect_err("classified decode rejection"))
        };
        let mut samples = Vec::with_capacity(count);
        for sample_index in 0..count {
            let (result, metric) =
                measured(|| cold_verify(row, case, std::hint::black_box(&bytes)));
            let actual = outcome(&result);
            if actual != mutation.outcome() {
                return Err(format!(
                    "unexpected measured outcome for {}: {result:?}",
                    mutation.name()
                )
                .into());
            }
            emit(
                output,
                &MalformedSample {
                    kind: "malformed_sample",
                    row: row_name(row),
                    case: case.name(),
                    mutation: mutation.name(),
                    sample_index,
                    record_bytes: bytes.len(),
                    record_shake256_32: &digest,
                    outcome: actual,
                    metric,
                },
            )?;
            samples.push(metric);
        }
        emit(
            output,
            &MalformedSummary {
                kind: "malformed_summary",
                row: row_name(row),
                case: case.name(),
                mutation: mutation.name(),
                diagnostic: &diagnostic,
                metrics: summarize_metrics(mutation.name(), &samples),
            },
        )?;
    }
    Ok(())
}

/// Measure bounded malformed classes using the ordinary cold-input path.
///
/// Arguments use the same options as `qualify`, after its `malformed` command.
/// # Errors
/// Rejects invalid options, unexpected acceptance/error classes, failed proof
/// setup or output failures. Prior JSON records are retained on failure.
pub fn run(arguments: &[String], output: &mut impl Write) -> Result<()> {
    let Some(options) = options(arguments)? else {
        output.write_all(b"Use: qualify malformed [the qualify options below]\n")?;
        output.write_all(HELP.as_bytes())?;
        output.flush()?;
        return Ok(());
    };
    emit(
        output,
        &Header {
            kind: "run_header",
            schema: "parliament-ballot-malformed-observations-b6-v1",
            source_id: &options.source_id,
            run_id: &options.run_id,
            accel_feature: cfg!(feature = "accel"),
            debug_assertions: cfg!(debug_assertions),
            target_arch: std::env::consts::ARCH,
            target_os: std::env::consts::OS,
            samples_per_case: options.samples,
            rows: options.rows.iter().map(|row| row_name(*row)).collect(),
            cases: options.cases.iter().map(|case| case.name()).collect(),
            profile_qualified: false,
            production_norito_mapping: false,
            hardware_qualification: false,
            body_context_bytes: BODY_CONTEXT_MAX_BYTES,
            registration_opaque_field_count: 6,
            registration_opaque_field_bytes: OPAQUE_FIELD_MAX_BYTES,
            method: vec![
                "One fixed deterministic test-only proof per row/case; untimed honest acceptance precedes mutation. Mutation construction and diagnostics are outside timing.",
                "Every sample starts from encoded bytes and runs fresh profile compilation, record/statement decode and ordinary verification as far as the malformed input permits.",
                "Four malformed proof classes additionally require their specific untimed backend Codec error. Other classes must fail record or statement decoding. Any different measured outcome fails the run.",
                "Each mutant is repeated in a warm process after an untimed classification; these are cold-input observations, not cold-process/cache or fresh-randomness trials.",
                "Requested live Rust heap includes the canonical record, one mutant, diagnostics and bounded harness bookkeeping. Incremental peak, allocation counts/traffic and time distributions are reported.",
                "Stack, allocator overhead, native heaps, concurrency isolation, RSS, production schemas and named-baseline qualification are excluded.",
                "Samples and summaries use nearest-rank median/p95 and retain maximum values. JSON formatting/output occurs outside measured phases.",
            ],
        },
    )?;
    for &row in &options.rows {
        for &case in &options.cases {
            if let Err(error) = run_case(row, case, options.samples, output) {
                emit(
                    output,
                    &Failure {
                        kind: "malformed_case_error",
                        row: row_name(row),
                        case: case.name(),
                        sample_index: 0,
                        error: &error.to_string(),
                        profile_qualified: false,
                    },
                )?;
                return Err(error);
            }
        }
    }
    emit(
        output,
        &Complete {
            kind: "run_complete",
            profile_qualified: false,
        },
    )
}

#[cfg(test)]
mod tests;
