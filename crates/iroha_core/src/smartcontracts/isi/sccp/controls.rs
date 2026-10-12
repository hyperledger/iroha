//! Native destination controls (`specs/sccp.md` §4.14.6).
//!
//! The caller changes its own pause state inside the isolated certified-effect transaction.
//! Recording consumes the revision's control nonce and captures the complete resulting state;
//! it never changes a pause flag. Controls precede transfer leaves, are recorded even when SCCP
//! is disabled for non-retired revisions, and are never pruned.

use super::{Error, leaves, store};
use crate::state::{StateReadOnly, StateTransaction};
use iroha_data_model::{
    bridge::SccpNetworkV1,
    governance::types::{GovernanceCertificateId, GovernanceCertificateV1},
    sccp::{
        control::{SccpControlLeafRefV1, SccpControlRecordV1, SccpLeafRefV1},
        events::{SccpControlRecordedV1, SccpEvent},
        registry::SccpRouteActivationV1,
    },
};
use iroha_sccp::v1::control::{ControlLeafV1, TRACK_PARLIAMENT, control_leaf};

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP: destination control refused: {reason}").into())
}

/// Exact cause retained from the original certified-effect context.
///
/// Fields are private so a caller cannot substitute a proposal identifier or supply a
/// fast-pause cause without its native authority owner.
#[derive(Clone, Copy, Debug)]
pub struct ControlCauseV1 {
    track: u8,
    certificate_id: [u8; 32],
    effect_hash: [u8; 32],
}

impl ControlCauseV1 {
    /// Bind the exact Parliament certificate selected by the due-effect executor.
    ///
    /// This constructor does not establish authorization by itself. Its caller must retain
    /// the executor's exact due-height, attempt, proposal/effect and expected-head checks.
    ///
    /// # Errors
    /// Refuses malformed certificates or zero native authority bindings.
    pub(in crate::smartcontracts::isi) fn from_parliament_certificate(
        certificate: &GovernanceCertificateV1,
    ) -> Result<Self, Error> {
        certificate
            .validate()
            .map_err(|error| refuse(format_args!("certificate: {error}")))?;
        let cause = Self {
            track: TRACK_PARLIAMENT,
            certificate_id: *GovernanceCertificateId::derive_v1(certificate).as_bytes(),
            effect_hash: certificate.effect_preimage_hash,
        };
        cause.require_supported()?;
        Ok(cause)
    }

    fn require_supported(self) -> Result<(), Error> {
        // TODO: implement the canonical fast-pause certificate/state/enactment owner before
        // admitting track 2. A raw claimed certificate ID is not that authority.
        if self.track != TRACK_PARLIAMENT {
            return Err(refuse("native fast-pause authority is unavailable"));
        }
        if self.certificate_id == [0; 32] || self.effect_hash == [0; 32] {
            return Err(refuse("native certificate/effect binding is zero"));
        }
        Ok(())
    }

    /// Synthetic authority DATA for component tests; never a production certificate source.
    #[cfg(test)]
    pub(crate) fn for_test(certificate_id: [u8; 32], effect_hash: [u8; 32]) -> Self {
        Self {
            track: TRACK_PARLIAMENT,
            certificate_id,
            effect_hash,
        }
    }
}

/// Record the post-update destination state and return its control nonce.
///
/// The caller must execute inside the original rollback-isolated effect transaction and
/// discard it on any failure or local resource deferral, including a leaf-cap refusal.
///
/// # Errors
/// Refuses missing/retired revisions, unsupported authority, nonce exhaustion, invalid native
/// fields or a full/non-dense block leaf sequence. Does not authorize a supplied certificate.
pub fn record_control(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
    cause: ControlCauseV1,
) -> Result<u64, Error> {
    cause.require_supported()?;
    let mut route = store::routes::get(&*state_transaction.world, &network)
        .cloned()
        .ok_or_else(|| refuse(format_args!("no route to {}", network.profile_key())))?;
    let record = route
        .revisions
        .get_mut(&revision)
        .filter(|record| record.activation != SccpRouteActivationV1::Retired)
        .ok_or_else(|| refuse(format_args!("revision {revision} is absent or retired")))?;
    let control_nonce = record.next_control_nonce;
    let parliament_paused = record.destination_paused;
    // TODO: when the native fast-pause owner is implemented, read its canonical post-update
    // record here: expiry iff revision belongs and block time is strictly before until_ms.
    // Current World has no fast-pause state or enactment path. Track 2 is explicitly refused;
    // zero describes that supported state, not a fallback for a missing/corrupt future record.
    let fast_pause_until_ms = 0;
    let fields = ControlLeafV1 {
        route_revision: revision,
        control_nonce,
        track: cause.track,
        parliament_paused: u8::from(parliament_paused),
        fast_pause_until_ms,
        certificate_id: cause.certificate_id,
        effect_hash: cause.effect_hash,
    };
    let leaf = control_leaf(
        state_transaction.network_id().as_bytes(),
        network,
        &record.destination_word,
        &fields,
    )
    .map_err(|error| refuse(format_args!("control leaf: {error}")))?;
    record.next_control_nonce = control_nonce
        .checked_add(1)
        .ok_or_else(|| refuse("the control nonce is exhausted"))?;
    store::routes::insert(state_transaction, network, route)?;
    let height = state_transaction._curr_block.height().get();
    let commitment_index = leaves::allocate_leaf(
        state_transaction,
        SccpLeafRefV1::Control(SccpControlLeafRefV1 {
            network,
            revision,
            control_nonce,
        }),
    )?;
    store::control_messages::insert(
        state_transaction,
        (network, revision, control_nonce),
        SccpControlRecordV1 {
            track: cause.track,
            parliament_paused,
            fast_pause_until_ms,
            certificate_id: cause.certificate_id,
            effect_hash: cause.effect_hash,
            height,
            commitment_index,
            leaf,
        },
    )?;
    state_transaction
        .world
        .emit_events(Some(SccpEvent::ControlRecorded(SccpControlRecordedV1 {
            network,
            revision,
            control_nonce,
            track: cause.track,
            parliament_paused,
            fast_pause_until_ms,
            certificate_id: cause.certificate_id,
            height,
            commitment_index,
        })));
    Ok(control_nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header, sample_route};

    fn cause(seed: u8) -> ControlCauseV1 {
        ControlCauseV1::for_test([seed; 32], [seed.wrapping_add(16); 32])
    }

    fn set_pause(stx: &mut StateTransaction<'_, '_>, network: SccpNetworkV1, paused: bool) {
        let mut route = store::routes::get(&*stx.world, &network)
            .cloned()
            .expect("route");
        route
            .revisions
            .get_mut(&1)
            .expect("revision")
            .destination_paused = paused;
        store::routes::insert(stx, network, route).expect("pause state");
    }

    #[test]
    fn controls_consume_nonces_and_leaves_and_skip_retired_revisions() {
        let state = blank_state();
        let mut block = state.block(header(7));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::TonMainnet;
        record_control(&mut stx, network, 1, cause(1)).expect_err("no route");
        store::routes::insert(&mut stx, network, sample_route(network)).expect("route");
        set_pause(&mut stx, network, true);
        let first = record_control(&mut stx, network, 1, cause(1)).expect("pause");
        set_pause(&mut stx, network, false);
        let second = record_control(&mut stx, network, 1, cause(2)).expect("resume");
        assert_eq!(second, first + 1);
        let revision = store::routes::get(&*stx.world, &network)
            .and_then(|route| route.revisions.get(&1))
            .expect("revision");
        assert!(!revision.destination_paused);
        assert_eq!(revision.next_control_nonce, second + 1);
        let record =
            store::control_messages::get(&*stx.world, &(network, 1, first)).expect("record");
        assert!(record.parliament_paused);
        assert_eq!((record.height, record.commitment_index), (7, 0));
        assert_eq!(record.certificate_id, [1; 32]);
        assert_eq!(
            record.leaf,
            control_leaf(
                stx.network_id().as_bytes(),
                network,
                &revision.destination_word,
                &ControlLeafV1 {
                    route_revision: 1,
                    control_nonce: first,
                    track: 1,
                    parliament_paused: 1,
                    fast_pause_until_ms: 0,
                    certificate_id: [1; 32],
                    effect_hash: [17; 32],
                }
            )
            .expect("leaf")
        );
        assert_eq!(leaves::leaf_count_at(&*stx.world, 7), 2);
        record_control(&mut stx, network, 2, cause(3)).expect_err("unknown revision");

        let mut route = store::routes::get(&*stx.world, &network)
            .cloned()
            .expect("route");
        route.revisions.get_mut(&1).expect("revision").activation = SccpRouteActivationV1::Retired;
        store::routes::insert(&mut stx, network, route).expect("route");
        let error = record_control(&mut stx, network, 1, cause(4)).expect_err("retired");
        assert!(error.to_string().contains("retired"), "{error}");
    }
    #[test]
    fn native_authority_refusal_does_not_consume_nonce_leaf_or_event() {
        let state = blank_state();
        let mut block = state.block(header(7));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::TonMainnet;
        store::routes::insert(&mut stx, network, sample_route(network)).expect("route");
        let before = store::routes::get(&*stx.world, &network)
            .cloned()
            .expect("route");
        let events = stx.world.internal_event_buf.len();
        for invalid in [
            ControlCauseV1 {
                track: 2,
                ..cause(1)
            },
            ControlCauseV1 {
                track: 0,
                ..cause(1)
            },
            ControlCauseV1::for_test([0; 32], [1; 32]),
            ControlCauseV1::for_test([1; 32], [0; 32]),
        ] {
            record_control(&mut stx, network, 1, invalid)
                .expect_err("authority unavailable/invalid");
            assert_eq!(store::routes::get(&*stx.world, &network), Some(&before));
            assert!(store::control_messages::is_empty(&*stx.world));
            assert_eq!(leaves::leaf_count_at(&*stx.world, 7), 0);
            assert_eq!(stx.world.internal_event_buf.len(), events);
        }
    }

    #[test]
    fn post_update_snapshot_preserves_staged_disabled_pause_state_and_full_cause() {
        let state = blank_state();
        let mut block = state.block(header(7));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::TonMainnet;
        let mut route = sample_route(network);
        route.revisions.get_mut(&1).expect("revision").activation = SccpRouteActivationV1::Staged;
        store::routes::insert(&mut stx, network, route).expect("route");
        let mut params = iroha_data_model::sccp::params::SccpParametersV1::taira_default();
        params.enabled = false;
        store::parameters::set(&mut stx, Some(params));
        for pause in [false, true] {
            set_pause(&mut stx, network, pause);
            let nonce =
                record_control(&mut stx, network, 1, cause(7)).expect("record disabled staged");
            let record =
                store::control_messages::get(&*stx.world, &(network, 1, nonce)).expect("record");
            assert_eq!(record.track, 1);
            assert_eq!(record.parliament_paused, pause);
            assert_eq!(record.fast_pause_until_ms, 0);
            assert_eq!(record.certificate_id, [7; 32]);
            assert_eq!(record.effect_hash, [23; 32]);
            let revision = &store::routes::get(&*stx.world, &network)
                .expect("route")
                .revisions[&1];
            assert_eq!(revision.destination_paused, pause);
            assert_eq!(revision.activation, SccpRouteActivationV1::Staged);
            assert_eq!(
                record.leaf,
                control_leaf(
                    stx.network_id().as_bytes(),
                    network,
                    &revision.destination_word,
                    &ControlLeafV1 {
                        route_revision: 1,
                        control_nonce: nonce,
                        track: 1,
                        parliament_paused: u8::from(pause),
                        fast_pause_until_ms: 0,
                        certificate_id: [7; 32],
                        effect_hash: [23; 32],
                    }
                )
                .expect("exact native leaf")
            );
        }
    }

    #[test]
    fn failed_effect_drop_restores_pause_nonce_records_leaves_and_events() {
        for full in [false, true] {
            let state = blank_state();
            let mut block = state.block(header(7));
            let network = SccpNetworkV1::TonMainnet;
            let original = {
                let mut seed = block.transaction();
                let mut route = sample_route(network);
                route
                    .revisions
                    .get_mut(&1)
                    .expect("revision")
                    .destination_paused = false;
                if !full {
                    route
                        .revisions
                        .get_mut(&1)
                        .expect("revision")
                        .next_control_nonce = u64::MAX;
                }
                store::routes::insert(&mut seed, network, route.clone()).expect("route");
                if full {
                    for n in 0..leaves::MAX_LEAVES_PER_BLOCK {
                        let mut id = [0; 32];
                        id[..4].copy_from_slice(&n.to_le_bytes());
                        leaves::allocate_leaf(&mut seed, SccpLeafRefV1::transfer(id))
                            .expect("fill");
                    }
                }
                seed.apply();
                route
            };
            {
                let mut failed = block.transaction();
                set_pause(&mut failed, network, true);
                let error =
                    record_control(&mut failed, network, 1, cause(1)).expect_err("bounded refusal");
                assert!(
                    error
                        .to_string()
                        .contains(if full { "maximum" } else { "exhausted" })
                );
                // The due-certificate executor drops this whole effect overlay on failure.
            }
            let stx = block.transaction();
            assert_eq!(store::routes::get(&*stx.world, &network), Some(&original));
            assert!(store::control_messages::is_empty(&*stx.world));
            assert_eq!(
                leaves::leaf_count_at(&*stx.world, 7),
                if full { 512 } else { 0 }
            );
            assert!(stx.world.internal_event_buf.is_empty());
        }
    }
}
