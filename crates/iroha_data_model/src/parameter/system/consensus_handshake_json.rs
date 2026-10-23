//! Shared signed-handshake record grammar with original-pool temporary text.

use super::{ConsensusFingerprint, ConsensusHandshakeMetadata, SumeragiConsensusMode};
use crate::block::consensus::SumeragiGenesisContextParameters;
use iroha_allocation::AllocationBudget;
use norito::json::{
    self, JsonDeserialize,
    scratch::{AdmittedScratch, OrdinaryScratch, ScratchDestination, key_text},
};
use std::num::NonZeroU64;

/// Original parser/decoder refusal or original finite-pool scratch refusal.
pub use norito::json::scratch::ScratchAdmissionError as HandshakeJsonAdmissionError;

/// A scalar handshake read with temporary storage funded by the original pool.
///
/// Every field is Copy, including the nested signed context. There is no retained
/// heap backing and no invented payload charge. This handle records the actual
/// pool used for decoding scratch; it is not authenticated genesis authority.
pub struct AdmittedConsensusHandshakeMetadata {
    value: ConsensusHandshakeMetadata,
    original: AllocationBudget,
}
impl AdmittedConsensusHandshakeMetadata {
    /// Read directly from the caller's original parser and original pool.
    ///
    /// The caller retains its decoder context, performs document preflight and
    /// checks completion. Nested types share their ordinary owner kernels; no
    /// Value tree, formatted document or parser replay is used. Intrinsic and
    /// State-dependent validation remains the caller's explicit next step.
    /// # Errors
    /// Preserves original JSON, scoped decoder, finite-pool and physical failures.
    pub fn try_decode_json(
        parser: &mut json::Parser<'_>,
        budget: &AllocationBudget,
    ) -> Result<Self, HandshakeJsonAdmissionError> {
        let value = metadata(parser, &AdmittedScratch::new(budget))?;
        Ok(Self {
            value,
            original: budget.clone(),
        })
    }
    /// Borrow the decoded scalar value.
    #[must_use]
    pub fn get(&self) -> &ConsensusHandshakeMetadata {
        &self.value
    }
    /// Whether the actual temporary decoding storage used this exact pool.
    #[must_use]
    pub fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.original.same_pool(budget)
    }
}

fn invalid(message: &'static str) -> json::Error {
    json::Error::WithPos {
        msg: message,
        byte: 0,
        line: 1,
        col: 1,
    }
}

pub(super) fn mode<D: ScratchDestination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<SumeragiConsensusMode, D::Error> {
    let text = destination.string(parser)?;
    match text.as_ref() {
        "Permissioned" => Ok(SumeragiConsensusMode::Permissioned),
        "Npos" => Ok(SumeragiConsensusMode::Npos),
        _ => Err(invalid("unknown signed consensus mode").into()),
    }
}
pub(super) fn fingerprint<D: ScratchDestination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<ConsensusFingerprint, D::Error> {
    let text = destination.string(parser)?;
    let body = text
        .as_ref()
        .strip_prefix("0x")
        .ok_or_else(|| invalid("expected lowercase 0x-prefixed 32-byte consensus fingerprint"))?;
    if body.len() != 64
        || !body
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid("expected lowercase 0x-prefixed 32-byte consensus fingerprint").into());
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(body, &mut bytes)
        .map_err(|_| invalid("invalid consensus fingerprint hexadecimal"))?;
    Ok(ConsensusFingerprint::new(bytes))
}
fn metadata<D: ScratchDestination>(
    parser: &mut json::Parser<'_>,
    destination: &D,
) -> Result<ConsensusHandshakeMetadata, D::Error> {
    let mut mode = None;
    let mut block_cadence_ms = None;
    let mut wire_protocol_version = None;
    let mut consensus_fingerprint = None;
    let mut sumeragi_context = None;
    let mut object = json::MapVisitor::new(parser)?;
    while let Some(key) = destination.key(&mut object)? {
        macro_rules! field {
            ($field:ident,$read:expr) => {{
                if $field.is_some() {
                    return Err(invalid(concat!(
                        "duplicate handshake field: ",
                        stringify!($field)
                    ))
                    .into());
                }
                $field = Some(object.parse_value_with_parser_typed($read)?);
            }};
        }
        match key_text(&key) {
            "mode" => field!(mode, |parser| self::mode(parser, destination)),
            "block_cadence_ms" => field!(
                block_cadence_ms,
                |parser: &mut json::Parser<'_>| -> Result<_, D::Error> {
                    Ok(NonZeroU64::new(parser.parse_u64()?)
                        .ok_or_else(|| invalid("expected nonzero block cadence"))?)
                }
            ),
            "wire_protocol_version" => field!(
                wire_protocol_version,
                |parser: &mut json::Parser<'_>| -> Result<_, D::Error> {
                    Ok(u32::try_from(parser.parse_u64()?)
                        .map_err(|_| invalid("wire protocol version overflow"))?)
                }
            ),
            "consensus_fingerprint" => field!(consensus_fingerprint, |parser| fingerprint(
                parser,
                destination
            )),
            "sumeragi_context" => field!(sumeragi_context, |parser| {
                SumeragiGenesisContextParameters::json_decode_with(parser, destination)
            }),
            _ => return Err(invalid("unknown signed handshake field").into()),
        }
    }
    object.finish()?;
    macro_rules! required {
        ($field:ident) => {
            $field
                .ok_or_else(|| invalid(concat!("missing handshake field: ", stringify!($field))))?
        };
    }
    Ok(ConsensusHandshakeMetadata {
        mode: required!(mode),
        block_cadence_ms: required!(block_cadence_ms),
        wire_protocol_version: required!(wire_protocol_version),
        consensus_fingerprint: required!(consensus_fingerprint),
        sumeragi_context: required!(sumeragi_context),
    })
}
impl JsonDeserialize for ConsensusHandshakeMetadata {
    fn json_deserialize(parser: &mut json::Parser<'_>) -> Result<Self, json::Error> {
        metadata(parser, &OrdinaryScratch)
    }
}

// Tape reads delegate to the same ordinary typed kernel, as the former derive did.
impl<'a> json::FastFromJson<'a> for ConsensusHandshakeMetadata {
    fn parse(
        walker: &mut json::TapeWalker<'a>,
        _arena: &mut json::Arena,
    ) -> Result<Self, norito::Error> {
        walker.ensure_document_depth()?;
        let mut parser = json::Parser::new_at(walker.input(), walker.raw_pos());
        let value = Self::json_deserialize(&mut parser).map_err(norito::Error::from)?;
        walker.sync_to_raw(parser.position());
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
