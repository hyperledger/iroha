//! Typed original-pool restoration of canonical attribution claims, without authority.
use super::*;
use crate::sumeragi::evidence::record::EvidenceRecordRestoreError as Error;
use iroha_crypto::PreparedPublicKeyDecode;
use iroha_model_base::peer::PeerId;
use norito::json::{self, MapVisitor, Parser, SeqVisitor};

fn required<T>(value: Option<T>, field: &str) -> Result<T, Error> {
    value.ok_or_else(|| json::Error::missing_field(field).into())
}
fn duplicate(field: &str) -> Error {
    json::Error::duplicate_field(field).into()
}

fn offender(
    parser: &mut Parser<'_>,
    budget: &AllocationBudget,
) -> Result<(u32, ChargedPublicKey, Option<SumeragiLaneStakeBinding>), Error> {
    let mut map = MapVisitor::new(parser)?;
    let mut signer = None;
    let mut peer = None;
    let mut binding = None;
    while let Some(key) = map.next_key()? {
        match key.as_str() {
            "signer" => {
                if signer.is_some() {
                    return Err(duplicate("signer"));
                }
                signer = Some(map.parse_value::<u32>()?);
            }
            "peer_id" => {
                if peer.is_some() {
                    return Err(duplicate("peer_id"));
                }
                peer = Some(map.parse_value_with_parser_typed(|parser| {
                    PreparedPublicKeyDecode::try_from_json(parser, budget).map_err(Error::from)
                })?);
            }
            "lane_stake" => {
                if binding.is_some() {
                    return Err(duplicate("lane_stake"));
                }
                binding = Some(map.parse_value::<Option<SumeragiLaneStakeBinding>>()?);
            }
            other => return Err(json::Error::unknown_field(other).into()),
        }
    }
    map.finish()?;
    Ok((
        required(signer, "signer")?,
        required(peer, "peer_id")?,
        binding.unwrap_or(None),
    ))
}

#[allow(unsafe_code)]
fn offenders(parser: &mut Parser<'_>, budget: &AllocationBudget) -> Result<FundedOffenders, Error> {
    let mut sequence = SeqVisitor::new(parser)?;
    let count = sequence.total_entries();
    let vector_layout = std::alloc::Layout::array::<EvidenceOffender>(count).map_err(|_| {
        EvidencePreparationError::Admission(iroha_allocation::AllocationRefusal::DemandOverflow)
    })?;
    // The canonical Vec logical demand precedes every child field/key, exactly
    // as ordinary JSON sequence construction. Physical ledger admission is separate.
    norito::core::reserve_decode_allocation(vector_layout.size())
        .map_err(json::Error::from_decode_resource)?;
    let ledger_count = if count == 0 {
        0
    } else {
        count
            .checked_add(1)
            .ok_or(EvidencePreparationError::Admission(
                iroha_allocation::AllocationRefusal::DemandOverflow,
            ))?
    };
    let mut charges = ChargedBuffer::<AllocationCharge>::new(ledger_count, budget)?;
    let mut values = ChargedBuffer::<EvidenceOffender>::new(count, budget)?;
    while let Some((signer, key, binding)) =
        sequence.next_element_with_parser_typed(|parser| offender(parser, budget))?
    {
        if !key.belongs_to(budget) || values.as_slice().len() == values.capacity() {
            return Err(EvidencePreparationError::Invariant.into());
        }
        // SAFETY: both fixed slots are available. No fallible work follows the
        // compact-box extraction; its exact charge immediately joins this ledger.
        let (key, charge) = unsafe { key.into_allocation_parts() };
        charges.push_reserved(charge);
        values.push_reserved(EvidenceOffender {
            signer,
            peer_id: PeerId::new(key),
            lane_stake: binding,
        });
    }
    sequence.finish()?;
    if values.as_slice().len() != count || charges.as_slice().len() != count {
        return Err(EvidencePreparationError::Invariant.into());
    }
    // SAFETY: the exact fixed Vec and all compact boxes immediately bind to one
    // move-only immutable owner. Partial values are declared after their ledger.
    let (values, backing) = unsafe { values.into_allocation_parts() };
    if count == 0 {
        drop(backing);
    } else {
        charges.push_reserved(backing);
    }
    match unsafe { RetainedPayload::try_new(values, charges, budget) } {
        Ok(owner) => Ok(FundedOffenders(owner)),
        Err((values, charges, _)) => {
            drop(values);
            drop(charges);
            Err(EvidencePreparationError::Invariant.into())
        }
    }
}

/// Restore canonical fields from the original borrowed JSON stream. Pool funding
/// never establishes historical attribution; the existing verifier reauthenticates it.
pub(crate) fn restore_attribution(
    parser: &mut Parser<'_>,
    budget: &AllocationBudget,
) -> Result<FundedEvidenceAttribution, Error> {
    let mut map = MapVisitor::new(parser)?;
    let (
        mut scope,
        mut instance,
        mut height,
        mut epoch,
        mut context,
        mut generation,
        mut graph,
        mut safety,
    ) = (None, None, None, None, None, None, None, None);
    while let Some(key) = map.next_key()? {
        match key.as_str() {
            "scope" => {
                if scope.is_some() {
                    return Err(duplicate("scope"));
                }
                scope = Some(map.parse_value::<EvidenceScope>()?);
            }
            "instance" => {
                if instance.is_some() {
                    return Err(duplicate("instance"));
                }
                instance = Some(map.parse_value::<[u8; 32]>()?);
            }
            "height" => {
                if height.is_some() {
                    return Err(duplicate("height"));
                }
                height = Some(map.parse_value::<u64>()?);
            }
            "epoch" => {
                if epoch.is_some() {
                    return Err(duplicate("epoch"));
                }
                epoch = Some(map.parse_value::<u64>()?);
            }
            "context_id" => {
                if context.is_some() {
                    return Err(duplicate("context_id"));
                }
                context = Some(map.parse_value::<[u8; 32]>()?);
            }
            "authority_generation" => {
                if generation.is_some() {
                    return Err(duplicate("authority_generation"));
                }
                generation = Some(map.parse_value::<[u8; 32]>()?);
            }
            "offenders" => {
                if graph.is_some() {
                    return Err(duplicate("offenders"));
                }
                graph =
                    Some(map.parse_value_with_parser_typed(|parser| offenders(parser, budget))?);
            }
            "safety_violation" => {
                if safety.is_some() {
                    return Err(duplicate("safety_violation"));
                }
                safety = Some(map.parse_value::<bool>()?);
            }
            other => return Err(json::Error::unknown_field(other).into()),
        }
    }
    map.finish()?;
    let scope = required(scope, "scope")?;
    let instance = required(instance, "instance")?;
    let height = required(height, "height")?;
    let epoch = required(epoch, "epoch")?;
    let context = required(context, "context_id")?;
    let generation = required(generation, "authority_generation")?;
    let graph = required(graph, "offenders")?;
    let fields = AttributionFields {
        scope,
        instance,
        height,
        epoch,
        context_id: context,
        authority_generation: generation,
        safety_violation: required(safety, "safety_violation")?,
    };
    Ok(graph.into_attribution(fields))
}
