//! Original lane values and ordinary writes retained for native historical proof construction.
use iroha_crypto::HashOf;
use iroha_data_model::{block::BlockHeader, sumeragi_lanes::SumeragiLaneState};

/// Exact complete lane state and original ordered writes from one native execution.
/// These values confer no authority until matched to the independently certified native R.
#[derive(Debug, Clone, norito::Encode, norito::Decode)]
#[norito(deny_unknown_fields)]
pub struct NativeExecutionProjectionV1 {
    /// Exact carrier whose canonical native R commits these values.
    pub carrier_height: u64,
    /// Iroha carrier identity; the native header and result remain in its sole certificate.
    pub carrier_hash: HashOf<BlockHeader>,
    /// Complete ordered lane state, including explicit emptiness.
    pub lanes: SumeragiLaneState,
    /// Original ordered ordinary writes; repeated ordinary keys retain execution order.
    /// Query proof construction must authenticate their last-write-wins root against R.
    pub ordinary_writes: Vec<iroha_data_model::block::consensus::ExecKv>,
    /// Complete original casting leaves, authenticated by the snapshot in ordinary writes.
    pub casting_bindings:
        Vec<iroha_data_model::parliament_casting::ParliamentTimedOvnCastingContextBindingV1>,
    /// Exact canonical SCCP write delta; empty iff its synthetic write is absent.
    /// Values remain DATA until their hash joins the certified ordinary-write root.
    pub sccp_delta: Vec<u8>,
}

impl norito::NoritoSchema for NativeExecutionProjectionV1 {
    fn nominal_name() -> String {
        "iroha_core::state::NativeExecutionProjectionV1".to_owned()
    }
    fn static_frame_name() -> Option<&'static str> {
        Some("iroha_core::state::NativeExecutionProjectionV1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_preserves_exact_identity_and_rejects_noncanonical_suffix() {
        let projection = NativeExecutionProjectionV1 {
            carrier_height: 2,
            carrier_hash: HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                b"native original carrier",
            )),
            lanes: SumeragiLaneState::default(),
            casting_bindings: vec![],
            sccp_delta: vec![1, 2, 3],
            ordinary_writes: vec![iroha_data_model::block::consensus::ExecKv {
                key: vec![1],
                value: vec![2, 3],
            }],
        };
        let bytes = norito::encode_canonical(&projection).unwrap();
        let decoded: NativeExecutionProjectionV1 = norito::decode_canonical_with_limits(
            &bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .unwrap();
        assert_eq!(decoded.carrier_height, projection.carrier_height);
        assert_eq!(decoded.carrier_hash, projection.carrier_hash);
        assert_eq!(decoded.lanes, projection.lanes);
        assert_eq!(decoded.ordinary_writes, projection.ordinary_writes);
        assert_eq!(decoded.casting_bindings, projection.casting_bindings);
        assert_eq!(decoded.sccp_delta, projection.sccp_delta);
        assert_eq!(norito::encode_canonical(&decoded).unwrap(), bytes);
        let mut suffix = bytes;
        suffix.push(0);
        assert!(
            norito::decode_canonical_with_limits::<NativeExecutionProjectionV1>(
                &suffix,
                norito::canonical_decode_limits(suffix.len())
            )
            .is_err()
        );
    }
}
