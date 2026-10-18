//! Original World inventory; the existing field macro owns exhaustive coverage.

use super::*;
use crate::state::authority_registry::world::{
    musubi_availability_policy::MusubiAvailabilityAuthorityV1,
    musubi_universal_policy::{MusubiDirectoryAuthorityV1, MusubiResolverAuthorityV1},
};
use crate::state::{World, WorldBlock};

trait AppendNative {
    type Target;
    fn append(
        &self,
        expected: &Self::Target,
        id: &'static str,
        mode: mv::BlockMode,
        output: &mut Collector,
    ) -> Result<(), CaptureError>;
}
impl<K: Key + Encode, V: Value + Encode, M: mv::storage::StorageMode<K, V>> AppendNative
    for StorageField<'_, K, V, M>
{
    type Target = mv::storage::Storage<K, V, M>;
    fn append(
        &self,
        expected: &Self::Target,
        id: &'static str,
        mode: mv::BlockMode,
        output: &mut Collector,
    ) -> Result<(), CaptureError> {
        output.storage(id, self, expected, mode, bare)
    }
}
impl<V: Value + Encode, C: Send + Sync + 'static> AppendNative for CellField<'_, V, C> {
    type Target = mv::cell::Cell<V, C>;
    fn append(
        &self,
        expected: &Self::Target,
        id: &'static str,
        mode: mv::BlockMode,
        output: &mut Collector,
    ) -> Result<(), CaptureError> {
        output.cell(id, self, expected, mode, bare)
    }
}

macro_rules! append_field {
    ($world:ident, $expected:ident, $mode:ident, $output:ident, triggers) => {
        $world
            .triggers
            .append_original_state_bytes(&$expected.triggers, $mode, $output)?;
    };
    ($world:ident, $expected:ident, $mode:ident, $output:ident, executor) => {
        $output.cell(
            "world.executor",
            &$world.executor,
            &$expected.executor,
            $mode,
            crate::executor::executor_norito::encode_state_authority,
        )?;
    };
    ($world:ident, $expected:ident, $mode:ident, $output:ident, musubi_archive_availability) => {
        $output.storage(
            "world.musubi_archive_availability",
            &$world.musubi_archive_availability,
            &$expected.musubi_archive_availability,
            $mode,
            |value, writer| bare(&MusubiAvailabilityAuthorityV1::from_record(value), writer),
        )?;
    };
    ($world:ident, $expected:ident, $mode:ident, $output:ident, musubi_resolver_index) => {
        $output.storage(
            "world.musubi_resolver_index",
            &$world.musubi_resolver_index,
            &$expected.musubi_resolver_index,
            $mode,
            |value, writer| bare(&MusubiResolverAuthorityV1::from_record(value), writer),
        )?;
    };
    ($world:ident, $expected:ident, $mode:ident, $output:ident, musubi_public_directory) => {
        $output.storage(
            "world.musubi_public_directory",
            &$world.musubi_public_directory,
            &$expected.musubi_public_directory,
            $mode,
            |value, writer| bare(&MusubiDirectoryAuthorityV1::from_record(value), writer),
        )?;
    };
    ($world:ident, $expected:ident, $mode:ident, $output:ident, $field:ident) => {
        $world.$field.append(
            &$expected.$field,
            concat!("world.", stringify!($field)),
            $mode,
            $output,
        )?;
    };
}
macro_rules! append_fields {
    ($world:ident, $expected:ident, $mode:ident, $output:ident; [$($prefix:ident),* $(,)?]
        [$($privacy:ident),* $(,)?] [$($suffix:ident),* $(,)?]) => {
        $(append_field!($world, $expected, $mode, $output, $prefix);)*
        $(append_field!($world, $expected, $mode, $output, $privacy);)*
        $(append_field!($world, $expected, $mode, $output, $suffix);)*
    };
}

pub(super) fn append(block: &StateBlock<'_>, output: &mut Collector) -> Result<(), CaptureError> {
    let fields = block.fields.as_ref().ok_or(CaptureError::NotFrozen)?;
    append_world(&fields.world, &fields.state_ref.world, output)
}
fn append_world(
    world: &WorldBlock<'_>,
    expected: &World,
    output: &mut Collector,
) -> Result<(), CaptureError> {
    if world.publication != AggregatePublication::Frozen {
        return Err(CaptureError::NotFrozen);
    }
    let mode = world.parameters.mode();
    with_world_overlay_fields!(append_fields, world, expected, mode, output);
    Ok(())
}
