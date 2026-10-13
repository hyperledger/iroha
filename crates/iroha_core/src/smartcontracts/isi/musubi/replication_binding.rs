//! Borrowed lifecycle evidence from the same immutable World source.
//!
//! Validation preserves archive, binding and identity error order. A retired
//! provider set remains with the original row; no authority payload is copied.
//! Static semantic reasons remain borrowed until an instruction caller renders
//! its completed invariant failure.

use super::*;
use iroha_model_base::error::ParseError;

/// Check the complete binding before borrowing its existing lifecycle.
pub fn validate_replication_order_archive_binding<'world>(
    archive: &MusubiArchiveRecordV1,
    replication_order: &iroha_data_model::sorafs::pin_registry::ReplicationOrderId,
    world: &'world impl MusubiSourceReadOnly,
) -> Result<&'world MusubiReplicationOrderLocationLifecycleV1, ParseError> {
    archive.validate()?;
    let reference = world
        .source_musubi_locations_by_replication_order()
        .get(replication_order)
        .ok_or_else(|| {
            ParseError::new("Musubi replication order has no consensus archive binding")
        })?;
    reference.validate()?;
    if reference.binding.replication_order != *replication_order
        || reference.binding.archive_id != archive.archive_id
        || reference.binding.commitment != archive.commitment
    {
        return Err(ParseError::new(
            "Musubi replication-order binding does not match the authoritative archive commitment",
        ));
    }
    Ok(&reference.lifecycle)
}
