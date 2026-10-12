//! SCCP control leaf v1: the 199-byte layout of `specs/sccp.md` §3.4 (revision 5).
//!
//! A control leaf carries the complete pause state of one `(network, route revision)` after a
//! Parliament or fast-pause change, plus the authority that made it:
//!
//! ```text
//! control_leaf = keccak256(
//!       "SCCP/CONTROL/V1"                  //  15 bytes
//!     ‖ lane_bytes(sora-taira, target)     //  66 bytes
//!     ‖ destination_word                   //  32 bytes
//!     ‖ u32 route_revision                 //   4 bytes, nonzero
//!     ‖ u64 control_nonce                  //   8 bytes, ≥ 1
//!     ‖ u8  track                          //   1 byte: 1 PARLIAMENT, 2 FAST_PAUSE
//!     ‖ u8  parliament_paused              //   1 byte
//!     ‖ u64 fast_pause_until_ms            //   8 bytes
//!     ‖ certificate_id                     //  32 bytes
//!     ‖ effect_hash)                       //  32 bytes; 199 bytes in all
//! ```
//!
//! `certificate_id` and `effect_hash` are opaque here: the Parliament or fast-pause
//! certificate that enacted the change derives them, and this module only binds them.
//!
//! A destination that applies a leaf stores its fast-pause expiry clamped to
//! [`MAX_FAST_PAUSE_MS`] from its own clock ([`applied_fast_pause_until_ms`], §5.1.6).

use iroha_data_model::bridge::SccpNetworkV1;

use super::{constants::CONTROL_TAG, hashes::keccak256, network::lane_bytes};

/// Length of the control-leaf preimage (15 + 66 + 32 + 4 + 8 + 1 + 1 + 8 + 32 + 32 bytes).
pub const CONTROL_LEAF_PREIMAGE_BYTES: usize = 199;
/// Length of TON's first `HASHEXT` builder `b1`: tag ‖ lane ‖ destination word ‖ revision ‖
/// nonce.
pub const CONTROL_TON_B1_BYTES: usize = 125;
/// Length of TON's second `HASHEXT` builder `b2`: track ‖ `parliament_paused` ‖
/// `fast_pause_until_ms` ‖ `certificate_id` ‖ `effect_hash`.
pub const CONTROL_TON_B2_BYTES: usize = CONTROL_LEAF_PREIMAGE_BYTES - CONTROL_TON_B1_BYTES;
/// `track` of a change enacted by a Parliament certificate.
pub const TRACK_PARLIAMENT: u8 = 1;
/// `track` of a change enacted by a fast-pause certificate.
pub const TRACK_FAST_PAUSE: u8 = 2;
/// Longest fast pause a destination keeps, counted from its own clock when it applies the
/// control (30 days): an immutable of every destination (`specs/sccp.md` §3.9).
pub const MAX_FAST_PAUSE_MS: u64 = 2_592_000_000;

// Field offsets of the preimage. Every integer is big-endian.
const OFFSET_LANE: usize = 15;
const OFFSET_DESTINATION_WORD: usize = 81;
const OFFSET_ROUTE_REVISION: usize = 113;
const OFFSET_CONTROL_NONCE: usize = 117;
const OFFSET_TRACK: usize = 125;
const OFFSET_PARLIAMENT_PAUSED: usize = 126;
const OFFSET_FAST_PAUSE_UNTIL_MS: usize = 127;
const OFFSET_CERTIFICATE_ID: usize = 135;
const OFFSET_EFFECT_HASH: usize = 167;

const _: () = assert!(CONTROL_TAG.len() == OFFSET_LANE);
const _: () = assert!(OFFSET_EFFECT_HASH + 32 == CONTROL_LEAF_PREIMAGE_BYTES);
const _: () = assert!(OFFSET_TRACK == CONTROL_TON_B1_BYTES && CONTROL_TON_B2_BYTES == 74);

unit_error! {
    /// Why control fields have no leaf.
    ///
    /// `BadControl` is the §3.4 constraint error, which a destination reports too. The other
    /// three are labels of this reference for Taira's recording rules (§3.4, §4.14.6: a
    /// route targets a first-release external network, and revisions and control nonces
    /// start at 1). No contract reports them, and `control_v1.json` pins them under
    /// `rejected[].error`.
    pub enum ControlLeafError {
        /// The target is not a first-release external profile (Ethereum, BSC or TON), so
        /// there is no Taira → target lane for a control.
        TargetNotExternal => "control leaf target must be an external network",
        /// `route_revision` is zero.
        ZeroRevision => "route revision must be nonzero",
        /// `control_nonce` is zero.
        ZeroControlNonce => "control nonce must be at least 1",
        /// A §3.4 constraint fails: `track ∉ {1, 2}`, `parliament_paused ∉ {0, 1}`, a
        /// fast-pause change without an expiry, a zero `certificate_id` or a zero
        /// `effect_hash`.
        BadControl => "control fields violate the control-leaf constraints",
    }
}

impl ControlLeafError {
    /// The name the shared vectors give this failure (`rejected[].error` of
    /// `control_v1.json`). `specs/sccp.md` §3.4 names `BadControl` and lists the other three
    /// as reference labels of the recording rules.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TargetNotExternal => "TargetNotExternal",
            Self::ZeroRevision => "ZeroRevision",
            Self::ZeroControlNonce => "ZeroControlNonce",
            Self::BadControl => "BadControl",
        }
    }
}

/// The fields of a control leaf that the lane and the destination word do not fix.
///
/// This is plain data: `track` and `parliament_paused` are the raw bytes of the layout, so a
/// value can describe fields that [`check_control_constraints`] refuses. A destination
/// computes the leaf from the fields a proof supplies and only then applies the constraints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ControlLeafV1 {
    /// Route revision the pause state belongs to; nonzero.
    pub route_revision: u32,
    /// Nonce of the change, at least 1 and strictly increasing per `(network, revision)`.
    pub control_nonce: u64,
    /// [`TRACK_PARLIAMENT`] or [`TRACK_FAST_PAUSE`]: the authority that made the change.
    pub track: u8,
    /// The revision's Parliament pause flag after the change: 0 or 1.
    pub parliament_paused: u8,
    /// Expiry of the revision's active fast pause after the change, or 0 for none.
    pub fast_pause_until_ms: u64,
    /// Identity of the enacting Parliament or fast-pause certificate; nonzero.
    pub certificate_id: [u8; 32],
    /// That certificate's effect preimage hash; nonzero.
    pub effect_hash: [u8; 32],
}

/// The §3.4 constraints that Taira and destinations both check.
///
/// # Errors
/// [`ControlLeafError::BadControl`] unless `track ∈ {1, 2}`, `parliament_paused ∈ {0, 1}`,
/// a fast-pause change (`track = 2`) carries a nonzero expiry, and neither `certificate_id`
/// nor `effect_hash` is zero.
pub fn check_control_constraints(leaf: &ControlLeafV1) -> Result<(), ControlLeafError> {
    let track_is_known = matches!(leaf.track, TRACK_PARLIAMENT | TRACK_FAST_PAUSE);
    let expiry_is_present = leaf.track != TRACK_FAST_PAUSE || leaf.fast_pause_until_ms != 0;
    if track_is_known
        && leaf.parliament_paused <= 1
        && expiry_is_present
        && leaf.certificate_id != [0; 32]
        && leaf.effect_hash != [0; 32]
    {
        Ok(())
    } else {
        Err(ControlLeafError::BadControl)
    }
}

/// Whether `target` is a profile a revision-5 control can address: Ethereum, BSC or TON.
///
/// Taira has no lane to itself. The TRON profile was removed from the first release: its
/// tag `0x43` is unassigned and every decoder rejects it (`specs/sccp.md` §2.1).
const fn is_control_target(target: SccpNetworkV1) -> bool {
    matches!(
        target,
        SccpNetworkV1::EthereumMainnet | SccpNetworkV1::BscMainnet | SccpNetworkV1::TonMainnet
    )
}

/// The 199-byte control-leaf preimage, laid out field by field with no validity check.
///
/// # Errors
/// [`ControlLeafError::TargetNotExternal`] when `target` is not Ethereum, BSC or TON: the
/// lane does not exist.
pub fn control_leaf_preimage(
    taira_network_id: &[u8; 32],
    target: SccpNetworkV1,
    destination_word: &[u8; 32],
    leaf: &ControlLeafV1,
) -> Result<[u8; CONTROL_LEAF_PREIMAGE_BYTES], ControlLeafError> {
    let lane = lane_bytes(SccpNetworkV1::SoraTaira, target, taira_network_id)
        .filter(|_| is_control_target(target))
        .ok_or(ControlLeafError::TargetNotExternal)?;
    let mut out = [0_u8; CONTROL_LEAF_PREIMAGE_BYTES];
    out[..OFFSET_LANE].copy_from_slice(CONTROL_TAG);
    out[OFFSET_LANE..OFFSET_DESTINATION_WORD].copy_from_slice(&lane);
    out[OFFSET_DESTINATION_WORD..OFFSET_ROUTE_REVISION].copy_from_slice(destination_word);
    out[OFFSET_ROUTE_REVISION..OFFSET_CONTROL_NONCE]
        .copy_from_slice(&leaf.route_revision.to_be_bytes());
    out[OFFSET_CONTROL_NONCE..OFFSET_TRACK].copy_from_slice(&leaf.control_nonce.to_be_bytes());
    out[OFFSET_TRACK] = leaf.track;
    out[OFFSET_PARLIAMENT_PAUSED] = leaf.parliament_paused;
    out[OFFSET_FAST_PAUSE_UNTIL_MS..OFFSET_CERTIFICATE_ID]
        .copy_from_slice(&leaf.fast_pause_until_ms.to_be_bytes());
    out[OFFSET_CERTIFICATE_ID..OFFSET_EFFECT_HASH].copy_from_slice(&leaf.certificate_id);
    out[OFFSET_EFFECT_HASH..].copy_from_slice(&leaf.effect_hash);
    Ok(out)
}

/// `control_leaf` of §3.4 as Taira records it: the recording rules first, then the
/// constraints, then the hash.
///
/// # Errors
/// In this order: [`ControlLeafError::TargetNotExternal`], [`ControlLeafError::ZeroRevision`],
/// [`ControlLeafError::ZeroControlNonce`], then [`ControlLeafError::BadControl`] as
/// [`check_control_constraints`] reports it.
pub fn control_leaf(
    taira_network_id: &[u8; 32],
    target: SccpNetworkV1,
    destination_word: &[u8; 32],
    leaf: &ControlLeafV1,
) -> Result<[u8; 32], ControlLeafError> {
    if !is_control_target(target) {
        return Err(ControlLeafError::TargetNotExternal);
    }
    if leaf.route_revision == 0 {
        return Err(ControlLeafError::ZeroRevision);
    }
    if leaf.control_nonce == 0 {
        return Err(ControlLeafError::ZeroControlNonce);
    }
    check_control_constraints(leaf)?;
    control_leaf_unchecked(taira_network_id, target, destination_word, leaf)
}

/// The hash of [`control_leaf_preimage`] for any field values.
///
/// A destination computes the leaf of the fields a proof supplies this way: a leaf of
/// refused fields is still a leaf of the tree, and the destination answers the constraints
/// separately (`BadControl`).
///
/// # Errors
/// [`ControlLeafError::TargetNotExternal`] when `target` is not Ethereum, BSC or TON.
pub fn control_leaf_unchecked(
    taira_network_id: &[u8; 32],
    target: SccpNetworkV1,
    destination_word: &[u8; 32],
    leaf: &ControlLeafV1,
) -> Result<[u8; 32], ControlLeafError> {
    let preimage = control_leaf_preimage(taira_network_id, target, destination_word, leaf)?;
    Ok(keccak256(&[&preimage]))
}

/// `fastPauseUntilMs` a destination stores when it applies a control at `now_ms`
/// (`specs/sccp.md` §5.1.6 step 5):
/// `min(leaf.fast_pause_until_ms, min(now_ms + MAX_FAST_PAUSE_MS, 2^64 − 1))`.
///
/// The bound saturates, so applying a control never aborts for arithmetic. The clamp is
/// defence in depth against a Byzantine Taira time; an expiry at or below `now_ms` is stored
/// as it is and pauses nothing.
#[must_use]
pub const fn applied_fast_pause_until_ms(fast_pause_until_ms: u64, now_ms: u64) -> u64 {
    let bound = now_ms.saturating_add(MAX_FAST_PAUSE_MS);
    if fast_pause_until_ms < bound {
        fast_pause_until_ms
    } else {
        bound
    }
}

/// The two byte-aligned builders a TON contract hashes with `HASHEXT`: 199 bytes exceed one
/// cell, so `b1` is the first 125 bytes of the preimage and `b2` the last 74.
#[must_use]
pub fn ton_builders(
    preimage: &[u8; CONTROL_LEAF_PREIMAGE_BYTES],
) -> ([u8; CONTROL_TON_B1_BYTES], [u8; CONTROL_TON_B2_BYTES]) {
    let (b1, b2) = preimage.split_at(CONTROL_TON_B1_BYTES);
    let mut first = [0_u8; CONTROL_TON_B1_BYTES];
    let mut second = [0_u8; CONTROL_TON_B2_BYTES];
    first.copy_from_slice(b1);
    second.copy_from_slice(b2);
    (first, second)
}

#[cfg(test)]
mod tests {
    use norito::json::Value;

    use super::{
        super::{
            finality::vectors::{bytes, field, hex, number, reference, rows, text, word},
            hashes::word_address,
        },
        *,
    };

    const NETWORK: [u8; 32] = [0x11; 32];
    /// Expiry of the spec's fast-pause examples.
    const UNTIL_MS: u64 = 1_700_604_800_000;

    fn destination() -> [u8; 32] {
        word_address(&[0x22; 20])
    }

    /// Row `nonce` of the §3.4 example table.
    fn example(nonce: u64) -> ControlLeafV1 {
        let (track, parliament_paused, fast_pause_until_ms, id, effect) = match nonce {
            1 => (TRACK_PARLIAMENT, 1, 0, 0x33, 0x44),
            2 => (TRACK_FAST_PAUSE, 0, UNTIL_MS, 0x55, 0x66),
            3 => (TRACK_PARLIAMENT, 1, UNTIL_MS, 0x77, 0x88),
            4 => (TRACK_PARLIAMENT, 0, 0, 0x99, 0xaa),
            other => panic!("the spec has no example for nonce {other}"),
        };
        ControlLeafV1 {
            route_revision: 1,
            control_nonce: nonce,
            track,
            parliament_paused,
            fast_pause_until_ms,
            certificate_id: [id; 32],
            effect_hash: [effect; 32],
        }
    }

    fn ethereum_leaf(leaf: &ControlLeafV1) -> Result<[u8; 32], ControlLeafError> {
        control_leaf(
            &NETWORK,
            SccpNetworkV1::EthereumMainnet,
            &destination(),
            leaf,
        )
    }

    fn target_of(name: &str) -> SccpNetworkV1 {
        match name {
            "sora-taira" => SccpNetworkV1::SoraTaira,
            "ethereum-mainnet" => SccpNetworkV1::EthereumMainnet,
            "bsc-mainnet" => SccpNetworkV1::BscMainnet,
            "ton-mainnet" => SccpNetworkV1::TonMainnet,
            other => panic!("unknown reference target `{other}`"),
        }
    }

    fn leaf_of(row: &Value) -> ControlLeafV1 {
        ControlLeafV1 {
            route_revision: u32::try_from(number(row, "route_revision")).unwrap(),
            control_nonce: number(row, "control_nonce"),
            track: u8::try_from(number(row, "track")).unwrap(),
            parliament_paused: u8::try_from(number(row, "parliament_paused")).unwrap(),
            fast_pause_until_ms: number(row, "fast_pause_until_ms"),
            certificate_id: word(row, "certificate_id"),
            effect_hash: word(row, "effect_hash"),
        }
    }

    #[test]
    fn control_leaf_spec_examples() {
        let expected = [
            "d9be284f6412d8e310b35afa921f8244f8d56cc64fbfc795d58701c11dce4d77",
            "fbdf5c5743292897ecf43c3d74fe0a3d3946aa73219bdab2f0a3e33bc0b988e0",
            "8afcebc533342cb86836b0195edc6a55e8e998d8e52d85f1fbf2c2707193c518",
            "b52aafb5bd2fcc77db32e1dfb8a92890b97adc2b9e81dd30f63dba3c059c8df3",
        ];
        for (nonce, leaf) in (1_u64..).zip(expected) {
            assert_eq!(
                hex(&ethereum_leaf(&example(nonce)).unwrap()),
                leaf,
                "nonce {nonce}"
            );
        }
        // The preimage of nonce 2, as the spec spells it out.
        let preimage = control_leaf_preimage(
            &NETWORK,
            SccpNetworkV1::EthereumMainnet,
            &destination(),
            &example(2),
        )
        .unwrap();
        let spelled = [
            "534343502f434f4e54524f4c2f5631",
            "40",
            &"11".repeat(32),
            "41",
            &"00".repeat(31),
            "01",
            &"00".repeat(12),
            &"22".repeat(20),
            "00000001",
            "0000000000000002",
            "02",
            "00",
            "0000018bf3f1ec00",
            &"55".repeat(32),
            &"66".repeat(32),
        ]
        .concat();
        assert_eq!(hex(&preimage), spelled);
    }

    #[test]
    fn control_leaf_preimage_is_199_bytes_with_ton_builders_125_74() {
        let leaf = ControlLeafV1 {
            route_revision: 0x0102_0304,
            control_nonce: 0x0506_0708_090a_0b0c,
            track: TRACK_FAST_PAUSE,
            parliament_paused: 1,
            fast_pause_until_ms: 0x0d0e_0f10_1112_1314,
            certificate_id: [0xc1; 32],
            effect_hash: [0xe2; 32],
        };
        let preimage =
            control_leaf_preimage(&NETWORK, SccpNetworkV1::TonMainnet, &[0x35; 32], &leaf).unwrap();
        assert_eq!(preimage.len(), 199);
        assert_eq!(&preimage[..15], b"SCCP/CONTROL/V1");
        // lane_bytes(sora-taira, ton-mainnet): 0x40 ‖ NetworkId ‖ 0x44 ‖ int256(−239).
        assert_eq!(preimage[15], 0x40);
        assert_eq!(preimage[16..48], NETWORK);
        assert_eq!(preimage[48], 0x44);
        assert_eq!(preimage[49..80], [0xff; 31]);
        assert_eq!(preimage[80], 0x11);
        assert_eq!(preimage[81..113], [0x35; 32]);
        assert_eq!(preimage[113..117], [1, 2, 3, 4]);
        assert_eq!(preimage[117..125], [5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(preimage[125], 2);
        assert_eq!(preimage[126], 1);
        assert_eq!(
            preimage[127..135],
            [0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14]
        );
        assert_eq!(preimage[135..167], [0xc1; 32]);
        assert_eq!(preimage[167..199], [0xe2; 32]);

        let (b1, b2) = ton_builders(&preimage);
        assert_eq!((b1.len(), b2.len()), (125, 74));
        assert_eq!(b1[..], preimage[..125]);
        assert_eq!(b2[..], preimage[125..]);
        // `b1` ends with the nonce and `b2` starts with the track.
        assert_eq!(b1[117..], [5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(b2[0], 2);
        // Hashing the two builders in order is hashing the preimage.
        assert_eq!(
            keccak256(&[&b1, &b2]),
            control_leaf(&NETWORK, SccpNetworkV1::TonMainnet, &[0x35; 32], &leaf).unwrap()
        );
    }

    #[test]
    fn control_constraints_reject_bad_track_pause_expiry_and_zero_ids() {
        for nonce in 1..=4 {
            assert_eq!(check_control_constraints(&example(nonce)), Ok(()));
        }
        // A Parliament change may carry an active fast pause or none; a fast-pause change
        // may leave the Parliament flag either way.
        let both = ControlLeafV1 {
            parliament_paused: 1,
            ..example(2)
        };
        assert_eq!(check_control_constraints(&both), Ok(()));

        let base = example(1);
        let refused = [
            ControlLeafV1 { track: 0, ..base },
            ControlLeafV1 { track: 3, ..base },
            ControlLeafV1 {
                track: 0xff,
                ..base
            },
            ControlLeafV1 {
                parliament_paused: 2,
                ..base
            },
            ControlLeafV1 {
                parliament_paused: 0xff,
                ..base
            },
            ControlLeafV1 {
                track: TRACK_FAST_PAUSE,
                parliament_paused: 0,
                fast_pause_until_ms: 0,
                ..base
            },
            ControlLeafV1 {
                certificate_id: [0; 32],
                ..base
            },
            ControlLeafV1 {
                effect_hash: [0; 32],
                ..base
            },
        ];
        for leaf in refused {
            assert_eq!(
                check_control_constraints(&leaf),
                Err(ControlLeafError::BadControl),
                "{leaf:?}"
            );
            assert_eq!(ethereum_leaf(&leaf), Err(ControlLeafError::BadControl));
            // The fields still have a leaf: a destination computes it before it refuses them.
            let unchecked = control_leaf_unchecked(
                &NETWORK,
                SccpNetworkV1::EthereumMainnet,
                &destination(),
                &leaf,
            )
            .unwrap();
            assert_ne!(unchecked, ethereum_leaf(&base).unwrap());
        }
    }

    #[test]
    fn control_leaf_recording_rules_precede_the_constraints() {
        let dest = destination();
        // Every rule is violated at once: the first in the documented order is reported.
        let nothing_valid = ControlLeafV1::default();
        assert_eq!(
            control_leaf(&NETWORK, SccpNetworkV1::SoraTaira, &dest, &nothing_valid),
            Err(ControlLeafError::TargetNotExternal)
        );
        assert_eq!(
            ethereum_leaf(&nothing_valid),
            Err(ControlLeafError::ZeroRevision)
        );
        let with_revision = ControlLeafV1 {
            route_revision: 1,
            ..nothing_valid
        };
        assert_eq!(
            ethereum_leaf(&with_revision),
            Err(ControlLeafError::ZeroControlNonce)
        );
        let with_nonce = ControlLeafV1 {
            control_nonce: 1,
            ..with_revision
        };
        assert_eq!(
            ethereum_leaf(&with_nonce),
            Err(ControlLeafError::BadControl)
        );

        // Taira has no lane to itself: that target has no leaf and no preimage.
        let taira = SccpNetworkV1::SoraTaira;
        assert!(!is_control_target(taira));
        assert_eq!(
            control_leaf(&NETWORK, taira, &dest, &example(1)),
            Err(ControlLeafError::TargetNotExternal)
        );
        assert_eq!(
            control_leaf_preimage(&NETWORK, taira, &dest, &example(1)),
            Err(ControlLeafError::TargetNotExternal)
        );
        assert_eq!(
            control_leaf_unchecked(&NETWORK, taira, &dest, &example(1)),
            Err(ControlLeafError::TargetNotExternal)
        );
        for target in [
            SccpNetworkV1::EthereumMainnet,
            SccpNetworkV1::BscMainnet,
            SccpNetworkV1::TonMainnet,
        ] {
            assert!(is_control_target(target));
            assert!(control_leaf(&NETWORK, target, &dest, &example(1)).is_ok());
        }
        // The leaf binds the target and the destination word.
        let ethereum = ethereum_leaf(&example(1)).unwrap();
        let bsc = control_leaf(&NETWORK, SccpNetworkV1::BscMainnet, &dest, &example(1)).unwrap();
        let other_word = control_leaf(
            &NETWORK,
            SccpNetworkV1::EthereumMainnet,
            &[0x23; 32],
            &example(1),
        )
        .unwrap();
        assert_ne!(ethereum, bsc);
        assert_ne!(ethereum, other_word);
    }

    #[test]
    fn control_leaf_error_names_and_messages() {
        let names = [
            (ControlLeafError::TargetNotExternal, "TargetNotExternal"),
            (ControlLeafError::ZeroRevision, "ZeroRevision"),
            (ControlLeafError::ZeroControlNonce, "ZeroControlNonce"),
            (ControlLeafError::BadControl, "BadControl"),
        ];
        for (error, name) in names {
            assert_eq!(error.name(), name);
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn applied_fast_pause_is_clamped_with_a_saturating_bound() {
        const T0: u64 = 1_800_000_000_000;
        assert_eq!(MAX_FAST_PAUSE_MS, 30 * 24 * 60 * 60 * 1000);
        // Below the bound, at it and above it.
        assert_eq!(applied_fast_pause_until_ms(0, T0), 0);
        assert_eq!(applied_fast_pause_until_ms(T0 - 1, T0), T0 - 1);
        assert_eq!(
            applied_fast_pause_until_ms(T0 + MAX_FAST_PAUSE_MS - 1, T0),
            T0 + MAX_FAST_PAUSE_MS - 1
        );
        for until in [T0 + MAX_FAST_PAUSE_MS, T0 + MAX_FAST_PAUSE_MS + 1, u64::MAX] {
            assert_eq!(
                applied_fast_pause_until_ms(until, T0),
                T0 + MAX_FAST_PAUSE_MS
            );
        }
        // A clock within the clamp of 2^64 ms: the bound saturates and nothing aborts.
        let edge = u64::MAX - MAX_FAST_PAUSE_MS;
        assert_eq!(
            applied_fast_pause_until_ms(u64::MAX, edge - 1),
            u64::MAX - 1
        );
        assert_eq!(applied_fast_pause_until_ms(u64::MAX, edge), u64::MAX);
        assert_eq!(applied_fast_pause_until_ms(u64::MAX, edge + 1), u64::MAX);
        assert_eq!(applied_fast_pause_until_ms(u64::MAX, u64::MAX), u64::MAX);
        assert_eq!(
            applied_fast_pause_until_ms(u64::MAX - 1, u64::MAX),
            u64::MAX - 1
        );
        assert_eq!(applied_fast_pause_until_ms(7, u64::MAX), 7);

        // Every applied control of the reference scenarios stores the clamped expiry.
        let control = reference("control_v1.json", "iroha.sccp.control.v1");
        assert_eq!(number(&control, "max_fast_pause_ms"), MAX_FAST_PAUSE_MS);
        let transitions = reference(
            "committee_transitions_v1.json",
            "iroha.sccp.committee-transitions.v1",
        );
        let scenarios = rows(&control, "destination_effects")
            .iter()
            .chain(rows(&transitions, "scenarios"));
        let (mut applied, mut clamped, mut sub_second) = (0, 0, 0);
        for scenario in scenarios {
            for step in rows(scenario, "steps") {
                let expected = field(step, "expected");
                let is_control = text(step, "call").starts_with("applyControl");
                if !is_control || expected.get("outcome").and_then(Value::as_str) != Some("ok") {
                    continue;
                }
                let now_ms = number(step, "now_ms");
                let supplied = number(field(step, "proof"), "fastPauseUntilMs");
                let stored = applied_fast_pause_until_ms(supplied, now_ms);
                let events = field(expected, "events").as_array().expect("events");
                let event = events
                    .iter()
                    .find(|event| text(event, "event") == "SccpControlApplied")
                    .expect("an applied control emits its event");
                assert_eq!(number(event, "fastPauseUntilMs"), stored);
                let pause = field(field(step, "state_after"), "pause");
                assert_eq!(number(pause, "fast_pause_until_ms"), stored);
                applied += 1;
                clamped += usize::from(stored != supplied);
                sub_second += usize::from(stored % 1000 == 1);
            }
        }
        // Including the `MAX_FAST_PAUSE_MS` clamp row and the expiry ending in 001 ms.
        assert!(applied >= 14, "{applied} applied controls");
        assert_eq!(clamped, 1);
        assert_eq!(sub_second, 1);
    }

    /// Every leaf row of `fixtures/sccp/control_v1.json`: the §3.4 examples and the grid over
    /// targets, revisions, nonces, tracks and pause values.
    #[test]
    fn control_leaves_match_the_reference_vectors() {
        let reference = reference("control_v1.json", "iroha.sccp.control.v1");
        let network = word(&reference, "taira_network_id");
        let mut checked = 0;
        for key in ["spec_examples", "controls"] {
            for row in rows(&reference, key) {
                let target = target_of(text(row, "target"));
                let destination_word = word(row, "destination_word");
                let leaf = leaf_of(row);
                let preimage =
                    control_leaf_preimage(&network, target, &destination_word, &leaf).unwrap();
                assert_eq!(preimage[..], bytes(text(row, "preimage"))[..]);
                assert_eq!(preimage[15..81], bytes(text(row, "lane_bytes"))[..]);
                let (b1, b2) = ton_builders(&preimage);
                assert_eq!(b1[..], bytes(text(row, "ton_b1"))[..]);
                assert_eq!(b2[..], bytes(text(row, "ton_b2"))[..]);
                assert_eq!(
                    control_leaf(&network, target, &destination_word, &leaf),
                    Ok(word(row, "leaf"))
                );
                checked += 1;
            }
        }
        // Four spec examples and 3 targets × 2 (revision, nonce) pairs × 6 pause states.
        assert_eq!(checked, 4 + 36);
    }

    /// The `rejected` rows: Taira's recording answer and, where the fields still have a
    /// preimage, the leaf a destination computes before it refuses them.
    #[test]
    fn control_rejections_match_the_reference_vectors() {
        let reference = reference("control_v1.json", "iroha.sccp.control.v1");
        let network = word(&reference, "taira_network_id");
        let words = field(&reference, "destination_words");
        let mut errors = std::collections::BTreeSet::new();
        for row in rows(&reference, "rejected") {
            let label = text(row, "label");
            let target = target_of(text(row, "target"));
            // Taira has no destination word; any word gives the same refusal.
            let destination_word = if target.is_external() {
                word(words, text(row, "target"))
            } else {
                [0; 32]
            };
            let leaf = leaf_of(row);
            let error = control_leaf(&network, target, &destination_word, &leaf)
                .expect_err("a rejected row has no recorded leaf");
            assert_eq!(error.name(), text(row, "error"), "{label}");
            errors.insert(error.name());
            let unchecked = control_leaf_unchecked(&network, target, &destination_word, &leaf);
            match row.get("unchecked_leaf") {
                Some(expected) => {
                    let expected = bytes(expected.as_str().expect("a hex string"));
                    assert_eq!(unchecked.unwrap()[..], expected[..], "{label}");
                }
                None => assert_eq!(
                    unchecked,
                    Err(ControlLeafError::TargetNotExternal),
                    "{label}"
                ),
            }
            // A destination answers `BadControl` exactly for the constraint failures.
            let constraints = check_control_constraints(&leaf);
            let destination = field(row, "destination").as_str();
            assert_eq!(
                constraints.is_err(),
                destination == Some("BadControl"),
                "{label}"
            );
        }
        assert_eq!(
            errors.into_iter().collect::<Vec<_>>(),
            [
                "BadControl",
                "TargetNotExternal",
                "ZeroControlNonce",
                "ZeroRevision"
            ]
        );
    }
}
