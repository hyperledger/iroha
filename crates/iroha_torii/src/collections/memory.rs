//! Byte ceilings for the collection producer, retained rows and JSON response.
use super::CollectionError;
use norito::json::{JsonSerialize, Map, Value};

/// Independent collection phases covered by the existing routed-read lease.
#[derive(Clone, Copy, Debug)]
#[expect(
    clippy::struct_field_names,
    reason = "Byte units distinguish independent source, retained, scratch and response allocation bounds."
)]
pub struct BytePolicy {
    /// Maximum canonical JSON bytes before a borrowed source becomes owned.
    pub(crate) source_frame_bytes: usize,
    /// Complete allocation ceiling for one decoded source row.
    pub(crate) row_bytes: usize,
    /// Complete retained rows, ordering keys and aggregate state.
    pub(crate) retained_bytes: usize,
    /// Temporary keys and projected row graphs.
    pub(crate) scratch_bytes: usize,
    /// Maximum authoritative response body.
    pub(crate) response_bytes: usize,
}

impl BytePolicy {
    /// Write a stack-owned borrowed row without cloning its ledger fields.
    pub(crate) fn row_fields<const N: usize>(
        self,
        fields: [(&'static str, &dyn JsonSerialize); N],
    ) -> Result<Map, CollectionError> {
        self.row(&BorrowedRow { fields })
    }
    /// Derive collection ceilings from the complete reservation already owned by Torii.
    pub(crate) fn for_routed_read(
        working_set_bytes: usize,
        configured_response_bytes: usize,
    ) -> Result<Self, CollectionError> {
        let envelope = crate::QueryFanoutMemoryEnvelope::for_body_admission(working_set_bytes)
            .map_err(|_| capacity("working set"))?;
        Ok(Self::for_admitted_read(envelope, configured_response_bytes))
    }

    /// Use the geometry carried by the actual owner instead of static app limits.
    pub(crate) fn for_admitted_read(
        envelope: crate::QueryFanoutMemoryEnvelope,
        configured_response_bytes: usize,
    ) -> Self {
        Self {
            source_frame_bytes: envelope.route_body_bytes,
            row_bytes: envelope.decode_allocated_bytes,
            retained_bytes: envelope.accumulator_retained_bytes,
            scratch_bytes: envelope.candidate_allocation_bytes,
            // The coordinator collects a successful authoritative response into
            // its route-body phase before decoding it. The source must obey that
            // smaller phase even when the final public-body phase is larger.
            response_bytes: envelope.route_body_bytes.min(configured_response_bytes),
        }
    }

    /// Canonical ceilings for local engine users without a routed Torii instance.
    pub(crate) fn canonical() -> Self {
        let defaults = iroha_config::parameters::defaults::torii::QUERY_FANOUT_MAX_RETAINED_BYTES.0;
        let aggregate = usize::try_from(defaults).expect("canonical query memory fits usize");
        let pool = aggregate - aggregate / 4;
        let ceiling = usize::try_from(
            iroha_config::parameters::defaults::torii::QUERY_FANOUT_MAX_WORKING_SET_BYTES.0,
        )
        .expect("canonical query working set fits usize");
        let working_set = pool.min(ceiling);
        Self::for_routed_read(working_set, working_set).expect("canonical collection phases fit")
    }

    /// Materialize a borrowed source only after both frame and allocation admission.
    pub(crate) fn row<T: JsonSerialize + ?Sized>(self, source: &T) -> Result<Map, CollectionError> {
        let body = norito::json::to_json_bounded_boxed(source, self.source_frame_bytes)
            .map_err(|_| capacity("source frame"))?;
        let limits = norito::DecodeLimits::new(
            self.source_frame_bytes,
            self.row_bytes,
            self.row_bytes,
            self.row_bytes,
            norito::core::MAX_VALUE_NESTING_DEPTH,
        );
        norito::json::preflight_slice(
            &body,
            norito::json::JsonPreflightLimits::from_decode_limits(body.len(), limits),
        )
        .map_err(|_| capacity("source JSON graph"))?;
        let (row, usage) = norito::core::with_decode_limits_measured(limits, || {
            norito::json::from_slice::<Map>(&body)
        });
        let row = row.map_err(|_| capacity("source decode"))?;
        ensure(
            usage.total_allocated_bytes(),
            self.row_bytes,
            "source decode",
        )?;
        ensure(map_heap_bytes(&row)?, self.row_bytes, "source row")?;
        Ok(row)
    }

    /// Encode a scratch key without an unbounded intermediate string.
    pub(crate) fn key<T: JsonSerialize + ?Sized>(
        self,
        value: &T,
    ) -> Result<String, CollectionError> {
        let encoded = norito::json::to_json_bounded_boxed(value, self.scratch_bytes)
            .map_err(|_| capacity("ordering key"))?;
        // Box<[u8]>::into_vec keeps the exact admitted layout; UTF-8 conversion
        // moves it again without a second allocation or spare String capacity.
        String::from_utf8(encoded.into_vec()).map_err(|_| capacity("ordering key"))
    }

    /// Count and stream display text into one exact admitted layout.
    pub(crate) fn display<T: core::fmt::Display + ?Sized>(
        self,
        value: &T,
    ) -> Result<String, CollectionError> {
        let mut length = 0usize;
        norito::json::visit_json_display_text(value, |text| {
            length = length
                .checked_add(text.len())
                .filter(|length| *length <= self.scratch_bytes)
                .ok_or(norito::json::BoundedJsonError::BodyTooLarge)?;
            Ok(())
        })
        .map_err(|_| capacity("display text"))?;
        let mut output = vector::<u8>(length, self.scratch_bytes, "display text")?;
        norito::json::visit_json_display_text(value, |text| {
            let next = output
                .len()
                .checked_add(text.len())
                .filter(|next| *next <= length)
                .ok_or(norito::json::BoundedJsonError::LengthMismatch)?;
            output.extend_from_slice(text.as_bytes());
            debug_assert_eq!(output.len(), next);
            Ok(())
        })
        .map_err(|_| capacity("display text"))?;
        if output.len() != length {
            return Err(capacity("display text"));
        }
        String::from_utf8(output).map_err(|_| capacity("display text"))
    }
}

struct BorrowedRow<'a, const N: usize> {
    fields: [(&'static str, &'a dyn JsonSerialize); N],
}

impl<const N: usize> JsonSerialize for BorrowedRow<'_, N> {
    fn json_serialize(&self, out: &mut String) {
        out.push('{');
        for (index, (name, value)) in self.fields.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            name.json_serialize(out);
            out.push(':');
            value.json_serialize(out);
        }
        out.push('}');
    }

    fn json_serialize_to(
        &self,
        out: &mut dyn norito::json::JsonWriteSink,
    ) -> Result<(), norito::json::BoundedJsonError> {
        out.begin_container()?;
        let result = (|| -> Result<(), norito::json::BoundedJsonError> {
            out.push('{')?;
            for (index, (name, value)) in self.fields.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                name.json_serialize_to(out)?;
                out.push(':')?;
                value.json_serialize_to(out)?;
            }
            out.push('}')?;
            Ok(())
        })();
        out.end_container();
        result?;
        Ok(())
    }
}

/// Refuse a memory phase before its corresponding allocation or mutation.
pub fn ensure(
    attempted: usize,
    ceiling: usize,
    phase: &'static str,
) -> Result<(), CollectionError> {
    if attempted > ceiling {
        return Err(capacity(phase));
    }
    Ok(())
}

/// Checked logical sum used for byte accounting.
pub fn add(left: usize, right: usize) -> Result<usize, CollectionError> {
    left.checked_add(right)
        .ok_or_else(|| capacity("accounting"))
}

/// Checked allocation size for a collection container.
pub fn slots<T>(capacity: usize) -> Result<usize, CollectionError> {
    capacity
        .checked_mul(core::mem::size_of::<T>())
        .ok_or_else(capacity_error)
}

/// Allocate the exact element layout after admitting its complete byte charge.
pub fn vector<T>(
    count: usize,
    ceiling: usize,
    phase: &'static str,
) -> Result<Vec<T>, CollectionError> {
    let charge = slots::<T>(count)?;
    ensure(charge, ceiling, phase)?;
    crate::torii_routed_read_exact_vec(count, phase, charge).map_err(|_| capacity(phase))
}

/// Heap charge of a cloned value, using source capacities as a conservative bound.
pub fn path_copy_bytes(name: &str, value: Option<&Value>) -> Result<usize, CollectionError> {
    let mut bytes = value.map(value_heap_bytes).transpose()?.unwrap_or(0);
    for segment in name.split('.') {
        bytes = add(
            bytes,
            norito::core::owned_btree_allocation_bytes::<String, Value>(1)
                .map_err(|_| capacity("projection containers"))?,
        )?;
        bytes = add(bytes, segment.len())?;
    }
    Ok(bytes)
}

fn capacity_error() -> CollectionError {
    capacity("accounting")
}

/// Stable, bounded diagnostic that never formats a ledger value.
pub fn capacity(phase: &'static str) -> CollectionError {
    CollectionError::new(
        "query_capacity_exceeded",
        "query",
        format!("the collection read exceeds its admitted {phase} byte budget"),
    )
    .with_hint("use a smaller page or a more selective query")
}

/// Conservative heap charge for a native JSON row, without copying its graph.
pub fn map_heap_bytes(map: &Map) -> Result<usize, CollectionError> {
    map_heap_bytes_at_depth(map, 0)
}

fn map_heap_bytes_at_depth(map: &Map, depth: usize) -> Result<usize, CollectionError> {
    let tree = norito::core::owned_btree_allocation_bytes::<String, Value>(map.len())
        .map_err(|_| capacity("row containers"))?;
    map.iter().try_fold(tree, |bytes, (key, value)| {
        add(
            add(bytes, key.capacity())?,
            value_heap_bytes_at_depth(value, depth + 1)?,
        )
    })
}

/// Conservative heap charge for a value before cloning it.
pub fn value_heap_bytes(value: &Value) -> Result<usize, CollectionError> {
    value_heap_bytes_at_depth(value, 0)
}

fn value_heap_bytes_at_depth(value: &Value, depth: usize) -> Result<usize, CollectionError> {
    if depth > norito::core::MAX_VALUE_NESTING_DEPTH {
        return Err(capacity("row nesting"));
    }
    match value {
        Value::String(text) => Ok(text.capacity()),
        Value::Array(values) => values
            .iter()
            .try_fold(slots::<Value>(values.capacity())?, |bytes, value| {
                add(bytes, value_heap_bytes_at_depth(value, depth + 1)?)
            }),
        Value::Object(map) => map_heap_bytes_at_depth(map, depth),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(bytes: usize) -> BytePolicy {
        BytePolicy {
            source_frame_bytes: bytes,
            row_bytes: bytes,
            retained_bytes: bytes,
            scratch_bytes: bytes,
            response_bytes: bytes,
        }
    }

    #[test]
    fn borrowed_source_refuses_exact_frame_plus_one_before_decode() {
        let row = Map::from_iter([("id".to_owned(), Value::from("account"))]);
        let bytes = norito::json::to_json(&row).unwrap().len();
        let mut limits = policy(16 * 1024);
        limits.source_frame_bytes = bytes;
        assert_eq!(limits.row(&row).unwrap(), row);
        limits.source_frame_bytes -= 1;
        assert_eq!(
            limits.row(&row).unwrap_err().code,
            "query_capacity_exceeded"
        );
    }

    #[test]
    fn small_encoded_metadata_cannot_expand_past_graph_admission() {
        let row = Map::from_iter([("metadata".to_owned(), Value::Array(vec![Value::Null; 1024]))]);
        let mut limits = policy(16 * 1024);
        limits.row_bytes = 1024;
        assert_eq!(
            limits.row(&row).unwrap_err().code,
            "query_capacity_exceeded"
        );
    }

    #[test]
    fn resident_charge_counts_capacity_and_every_separate_object() {
        let text = String::with_capacity(512);
        assert_eq!(value_heap_bytes(&Value::String(text)).unwrap(), 512);
        let empty_leaf = Map::from_iter([("key".to_owned(), Value::Null)]);
        let pair = Value::Array(vec![
            Value::Object(empty_leaf.clone()),
            Value::Object(empty_leaf.clone()),
        ]);
        assert!(value_heap_bytes(&pair).unwrap() >= 2 * map_heap_bytes(&empty_leaf).unwrap());
    }
}

#[cfg(test)]
mod service_depth_tests {
    //! Owning checked service writers keep the caller depth on exact refusals.
    use super::*;
    use crate::service_checked_writer_test_support::{RefusingLeaf, audit, byte_refusal, error};
    use norito::json::{BoundedJsonError, JsonSerialize};

    #[test]
    fn original_borrowed_row_keeps_exact_field_refs_and_manual_leaf_refusal_depth() {
        let text = "é";
        let number = 7_u64;
        let source = BorrowedRow {
            fields: [("name", &text), ("count", &number)],
        };
        let mut expected = String::new();
        source.json_serialize(&mut expected);
        audit(&expected, |sink| source.json_serialize_to(sink));
        let manual = RefusingLeaf {
            visits: std::cell::Cell::new(0),
        };
        let source = BorrowedRow {
            fields: [("manual", &manual)],
        };
        byte_refusal(|sink| source.json_serialize_to(sink));
        assert_eq!(manual.visits.get(), 0);
        error(BoundedJsonError::Unsupported, |sink| {
            source.json_serialize_to(sink)
        });
        assert_eq!(manual.visits.get(), 1);
    }
}
