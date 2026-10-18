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
    try_validate_replication_order_archive_binding::<_, ()>(archive, replication_order, world)
        .map_err(ReadFailure::into_predicate)
}

/// Run the same predicate while preserving an original physical read refusal.
pub(crate) fn try_validate_replication_order_archive_binding<
    'world,
    W: MusubiEvidenceRead<Q>,
    Q: Default,
>(
    archive: &MusubiArchiveRecordV1,
    replication_order: &iroha_data_model::sorafs::pin_registry::ReplicationOrderId,
    world: &'world W,
) -> Result<&'world MusubiReplicationOrderLocationLifecycleV1, ReadFailure<W::Error, ParseError>> {
    ReplicationBindingValidation::<Q>::new().advance(archive, replication_order, world)
}

/// Retains the successful archive predicate across the original binding lookup refusal.
pub(crate) struct ReplicationBindingValidation<Q> {
    queries: [Q; 1],
    archive_validated: bool,
}
impl<Q: Default> ReplicationBindingValidation<Q> {
    /// Begin one unchanged original archive/order binding check.
    pub(crate) fn new() -> Self {
        Self {
            archive_validated: false,
            queries: [Q::default()],
        }
    }
    /// Return the actual borrowed lifecycle after the same checks, retaining progress.
    pub(crate) fn advance<'world, W: MusubiEvidenceRead<Q>>(
        &mut self,
        archive: &MusubiArchiveRecordV1,
        replication_order: &iroha_data_model::sorafs::pin_registry::ReplicationOrderId,
        world: &'world W,
    ) -> Result<&'world MusubiReplicationOrderLocationLifecycleV1, ReadFailure<W::Error, ParseError>>
    {
        if !self.archive_validated {
            archive.validate()?;
            self.archive_validated = true;
        }
        let reference = world
            .musubi_locations_by_replication_order_get_retained(
                replication_order,
                &mut self.queries[0],
            )
            .map_err(ReadFailure::Source)?
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
        )
        .into());
        }
        Ok(&reference.lifecycle)
    }
}
