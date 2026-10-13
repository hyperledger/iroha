//! Current destination controls capture both pause tracks and their exact enacting cause.
//!
//! Callers first update their own Parliament flag or fast-pause record inside the isolated
//! effect transaction. This recorder only allocates the next nonce and leaf; it never changes
//! either pause state. Controls exist even while SCCP is disabled and are never pruned.

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
use iroha_sccp::v1::control::{ControlLeafV1, control_leaf};

/// Exact cause supplied by the owning authenticated certificate effect (§4.14.6).
/// This data carries no independent authority to enact an effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlCauseV1 {
    /// Parliament (1) or fast pause (2).
    pub(super) track: u8,
    /// Identity derived from the actual enacting certificate.
    pub(super) certificate_id: [u8; 32],
    /// The same certificate's canonical effect-preimage hash.
    pub(super) effect_hash: [u8; 32],
}

impl ControlCauseV1 {
    /// Exact emergency certificate, only after its native same-pass enactment rechecks.
    pub(super) fn from_fast_pause(
        effect: &super::fast_pause::certification::EnactingPause,
    ) -> Self {
        let (certificate_id, effect_hash) = effect.cause();
        Self {
            track: iroha_sccp::v1::control::TRACK_FAST_PAUSE,
            certificate_id,
            effect_hash,
        }
    }

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
            track: iroha_sccp::v1::control::TRACK_PARLIAMENT,
            certificate_id: *GovernanceCertificateId::derive_v1(certificate).as_bytes(),
            effect_hash: certificate.effect_preimage_hash,
        };
        cause.require_supported()?;
        Ok(cause)
    }

    fn require_supported(self) -> Result<(), Error> {
        // This validation belongs to the Parliament constructor. Track two is
        // issued only by the separate source-bound EnactingPause constructor.
        if self.track != iroha_sccp::v1::control::TRACK_PARLIAMENT {
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
            track: iroha_sccp::v1::control::TRACK_PARLIAMENT,
            certificate_id,
            effect_hash,
        }
    }
}

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP: destination control refused: {reason}").into())
}

/// Record the complete current pause state and exact cause of `(network, revision)`.
/// The caller has already changed its own pause state and owns effect rollback.
///
/// # Errors
/// Refuses absent/retired revisions, malformed causes, nonce overflow, or exhausted/non-dense
/// block leaves. Neither pause track is changed by this function.
pub fn record_control(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
    cause: ControlCauseV1,
) -> Result<u64, Error> {
    let mut route = store::routes::get(&*state_transaction.world, &network)
        .cloned()
        .ok_or_else(|| refuse(format_args!("no route to {}", network.profile_key())))?;
    let record = route
        .revisions
        .get_mut(&revision)
        .filter(|record| record.activation != SccpRouteActivationV1::Retired)
        .ok_or_else(|| refuse(format_args!("revision {revision} is absent or retired")))?;
    let control_nonce = record.next_control_nonce;
    let next_nonce = control_nonce
        .checked_add(1)
        .ok_or_else(|| refuse("the control nonce is exhausted"))?;
    let parliament_paused = record.destination_paused;
    let fast_pause_until_ms = if cfg!(all(test, sumeragi_core_mutation = "HC238")) {
        0
    } else {
        store::fast_pauses::get(&*state_transaction.world, &network).map_or(0, |pause| {
            pause.destination_expiry(revision, state_transaction.block_unix_timestamp_ms())
        })
    };
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
    record.next_control_nonce = next_nonce;
    if !store::routes::valid_entry(&network, &route) {
        return Err(refuse("the current route breaks its stored invariant"));
    }
    let height = state_transaction._curr_block.height().get();
    let commitment_index = leaves::allocate_leaf(
        state_transaction,
        SccpLeafRefV1::Control(SccpControlLeafRefV1 {
            network,
            revision,
            control_nonce,
        }),
    )?;
    store::routes::insert(state_transaction, network, route)?;
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
    use crate::smartcontracts::isi::sccp::{
        pause_record::RetainedSccpFastPause,
        test_support::{blank_state, header, sample_fast_pause, sample_route},
    };
    use iroha_sccp::v1::control::{TRACK_FAST_PAUSE, TRACK_PARLIAMENT};

    fn cause(track: u8, seed: u8) -> ControlCauseV1 {
        ControlCauseV1 {
            track,
            certificate_id: [seed; 32],
            effect_hash: [seed + 10; 32],
        }
    }
    fn parliament_flag(stx: &mut StateTransaction<'_, '_>, network: SccpNetworkV1, paused: bool) {
        let mut route = store::routes::get(&*stx.world, &network).unwrap().clone();
        route.revisions.get_mut(&1).unwrap().destination_paused = paused;
        store::routes::insert(stx, network, route).unwrap();
    }

    #[test]
    fn controls_consume_nonces_and_leaves_and_skip_retired_revisions() {
        let state = blank_state();
        let mut block = state.block(header(7));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::TonMainnet;
        record_control(&mut stx, network, 1, cause(TRACK_PARLIAMENT, 1)).expect_err("no route");
        store::routes::insert(&mut stx, network, sample_route(network)).unwrap();
        parliament_flag(&mut stx, network, true);
        let first = record_control(&mut stx, network, 1, cause(TRACK_PARLIAMENT, 1)).unwrap();
        parliament_flag(&mut stx, network, false);
        let second = record_control(&mut stx, network, 1, cause(TRACK_PARLIAMENT, 2)).unwrap();
        assert_eq!(second, first + 1);
        let revision = store::routes::get(&*stx.world, &network)
            .unwrap()
            .revisions
            .get(&1)
            .unwrap();
        assert!(!revision.destination_paused);
        assert_eq!(revision.next_control_nonce, second + 1);
        let record = store::control_messages::get(&*stx.world, &(network, 1, first)).unwrap();
        assert!(record.parliament_paused);
        assert_eq!((record.height, record.commitment_index), (7, 0));
        assert_eq!(
            (record.track, record.certificate_id, record.effect_hash),
            (1, [1; 32], [11; 32])
        );
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
                    effect_hash: [11; 32],
                }
            )
            .unwrap()
        );
        assert_eq!(leaves::leaf_count_at(&*stx.world, 7), 2);
        record_control(&mut stx, network, 2, cause(1, 3)).expect_err("unknown revision");
        let mut route = store::routes::get(&*stx.world, &network).unwrap().clone();
        route.revisions.get_mut(&1).unwrap().activation = SccpRouteActivationV1::Retired;
        store::routes::insert(&mut stx, network, route).unwrap();
        let error = record_control(&mut stx, network, 1, cause(1, 4)).expect_err("retired");
        assert!(error.to_string().contains("retired"), "{error}");
    }

    #[test]
    fn controls_capture_both_tracks_without_modifying_pause_owners_and_expire_by_time() {
        let state = blank_state();
        let budget = state.ivm_execution_budget();
        let mut block = state.block(header(7));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::EthereumMainnet;
        let now = stx.block_unix_timestamp_ms();
        store::routes::insert(&mut stx, network, sample_route(network)).unwrap();
        parliament_flag(&mut stx, network, true);
        let mut pause = sample_fast_pause(1);
        pause.until_ms = now + 1;
        let original = RetainedSccpFastPause::admit(&pause, &budget).unwrap();
        store::fast_pauses::insert(&mut stx, network, original.clone()).unwrap();
        let first = record_control(&mut stx, network, 1, cause(TRACK_FAST_PAUSE, 5)).unwrap();
        let row = store::control_messages::get(&*stx.world, &(network, 1, first)).unwrap();
        assert_eq!(
            (row.track, row.parliament_paused, row.fast_pause_until_ms),
            (2, true, now + 1)
        );
        assert_eq!(
            store::fast_pauses::get(&*stx.world, &network),
            Some(&original)
        );
        parliament_flag(&mut stx, network, false);
        let second = record_control(&mut stx, network, 1, cause(TRACK_PARLIAMENT, 6)).unwrap();
        let row = store::control_messages::get(&*stx.world, &(network, 1, second)).unwrap();
        assert_eq!(
            (row.parliament_paused, row.fast_pause_until_ms),
            (false, now + 1)
        );
        assert_eq!(
            store::fast_pauses::get(&*stx.world, &network),
            Some(&original)
        );
        pause.until_ms = now;
        let expired = RetainedSccpFastPause::admit(&pause, &budget).unwrap();
        store::fast_pauses::insert(&mut stx, network, expired.clone()).unwrap();
        let third = record_control(&mut stx, network, 1, cause(TRACK_PARLIAMENT, 7)).unwrap();
        let row = store::control_messages::get(&*stx.world, &(network, 1, third)).unwrap();
        assert_eq!(row.fast_pause_until_ms, 0);
        assert_eq!(
            store::fast_pauses::get(&*stx.world, &network),
            Some(&expired),
            "recording never cleans up the fast-pause owner"
        );
        assert_eq!(leaves::leaf_count_at(&*stx.world, 7), 3);
        // Parameters remain absent: recording has no enabled-only gate.
        assert!(store::parameters::get(&*stx.world).is_none());
    }

    #[test]
    fn malformed_cause_or_full_block_does_not_consume_control_nonce() {
        let state = blank_state();
        let mut block = state.block(header(7));
        let mut stx = block.transaction();
        let network = SccpNetworkV1::BscMainnet;
        store::routes::insert(&mut stx, network, sample_route(network)).unwrap();
        let original = store::routes::get(&*stx.world, &network).unwrap().clone();
        for cause in [
            cause(0, 1),
            cause(3, 1),
            cause(2, 1),
            ControlCauseV1 {
                certificate_id: [0; 32],
                ..cause(1, 1)
            },
            ControlCauseV1 {
                effect_hash: [0; 32],
                ..cause(1, 1)
            },
        ] {
            record_control(&mut stx, network, 1, cause)
                .expect_err("invalid cause or missing active fast part");
            assert_eq!(store::routes::get(&*stx.world, &network), Some(&original));
            assert!(store::control_messages::is_empty(&*stx.world));
            assert_eq!(leaves::leaf_count_at(&*stx.world, 7), 0);
        }
        for index in 0..leaves::MAX_LEAVES_PER_BLOCK {
            leaves::allocate_leaf(
                &mut stx,
                SccpLeafRefV1::transfer([index.to_le_bytes()[0]; 32]),
            )
            .unwrap();
        }
        record_control(&mut stx, network, 1, cause(1, 1)).expect_err("full block");
        assert_eq!(store::routes::get(&*stx.world, &network), Some(&original));
        assert!(store::control_messages::is_empty(&*stx.world));
        assert_eq!(
            leaves::leaf_count_at(&*stx.world, 7),
            leaves::MAX_LEAVES_PER_BLOCK as usize
        );
    }
}
