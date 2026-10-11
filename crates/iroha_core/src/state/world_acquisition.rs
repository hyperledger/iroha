//! Caller-owned World acquisition and retirement from the sole field inventory.
//!
//! All inert field slots exist before the first writer is acquired. A callee
//! that unwinds leaves its original partial state in its slot; aggregate Drop
//! releases every physical writer before any slot destroys values or notifies.

use super::{
    WorldBlock,
    block_field::{BlockField, OriginalPublicationBlock},
};
use mv::storage::AdmittedStorageError;
use mv::{BlockAcquisition, BlockMode, BlockRetirement};

mod original_control;
#[cfg(test)]
pub(super) use original_control::OriginalControlSource;
pub(super) use original_control::{
    OriginalWorldFields, WorldPlacement, add_original_control_demand, initialize_original_field,
    original_cell,
};

/// Acquisition adapters retain actual slots and forward physical or policy refusal.
pub(super) trait WorldFieldAcquisition {
    type Block;
    fn try_initialize(&mut self, mode: BlockMode) -> Result<(), AdmittedStorageError>;
    fn release(&mut self);
    fn take_block(&mut self) -> Self::Block;
    fn into_block(self) -> Self::Block;
}
pub(super) struct OrdinaryAcquisition<A: BlockAcquisition>(pub(super) A);
impl<A: BlockAcquisition> WorldFieldAcquisition for OrdinaryAcquisition<A> {
    type Block = A::Block;
    fn try_initialize(&mut self, mode: BlockMode) -> Result<(), AdmittedStorageError> {
        self.0.initialize(mode);
        Ok(())
    }
    fn release(&mut self) {
        self.0.release();
    }
    fn take_block(&mut self) -> Self::Block {
        self.0.take_block()
    }
    fn into_block(self) -> Self::Block {
        self.0.into_block()
    }
}
/// Cells retain their original partial pair on nonblocking acquisition refusal.
pub(super) struct CellAcquisition<
    'a,
    V: mv::Value,
    C: Send + Sync + 'static = concread::ebrcell::Untracked,
>(pub(super) mv::cell::BlockAcquisitionSlot<'a, V, C>);
impl<'a, V: mv::Value, C: Send + Sync + 'static> WorldFieldAcquisition
    for CellAcquisition<'a, V, C>
{
    type Block = mv::cell::Block<'a, V, C>;
    fn try_initialize(&mut self, mode: BlockMode) -> Result<(), AdmittedStorageError> {
        #[cfg(all(test, sumeragi_core_mutation = "HC71"))]
        {
            self.0.initialize(mode);
            return Ok(());
        }
        self.0.try_initialize(mode)
    }
    fn release(&mut self) {
        self.0.release();
    }
    fn take_block(&mut self) -> Self::Block {
        self.0.take_block()
    }
    fn into_block(self) -> Self::Block {
        self.0.into_block()
    }
}

pub(super) trait IntoWorldField {
    type Field;
    fn into_world_field(self) -> Self::Field;
}
impl<B: OriginalPublicationBlock> IntoWorldField for B {
    type Field = BlockField<B>;
    fn into_world_field(self) -> Self::Field {
        BlockField::new(self)
    }
}
impl IntoWorldField for super::TriggerSetBlock<'_> {
    type Field = Self;
    fn into_world_field(self) -> Self {
        self
    }
}

macro_rules! declare_world_acquisition {
    (; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {
        // Generic parameter names deliberately follow the single field census.
        #[allow(non_camel_case_types)]
        pub(super) struct WorldAcquisition<
            $($prefix: WorldFieldAcquisition,)*
            $($privacy: WorldFieldAcquisition,)*
            $($suffix: WorldFieldAcquisition,)*
        > {
            $(pub(super) $prefix: Option<$prefix>,)*
            $(pub(super) $privacy: Option<$privacy>,)*
            $(pub(super) $suffix: Option<$suffix>,)*
        }

        #[allow(non_camel_case_types)]
        impl<$($prefix: WorldFieldAcquisition,)* $($privacy: WorldFieldAcquisition,)* $($suffix: WorldFieldAcquisition,)*>
            WorldAcquisition<$($prefix,)* $($privacy,)* $($suffix,)*>
        {
            pub(super) fn release_all(&mut self) {
                $(if let Some(field) = self.$prefix.as_mut() { field.release(); })*
                $(if let Some(field) = self.$privacy.as_mut() { field.release(); })*
                $(if let Some(field) = self.$suffix.as_mut() { field.release(); })*
            }

            pub(super) fn try_initialize(&mut self, mode: BlockMode) -> Result<(), AdmittedStorageError> {
                $(self.$prefix.as_mut().expect("original field acquisition").try_initialize(mode)?;)*
                $(self.$privacy.as_mut().expect("original field acquisition").try_initialize(mode)?;)*
                $(self.$suffix.as_mut().expect("original field acquisition").try_initialize(mode)?;)*
                Ok(())
            }
        }

        #[allow(non_camel_case_types)]
        impl<$($prefix: WorldFieldAcquisition,)* $($privacy: WorldFieldAcquisition,)* $($suffix: WorldFieldAcquisition,)*>
            Drop for WorldAcquisition<$($prefix,)* $($privacy,)* $($suffix,)*>
        {
            fn drop(&mut self) {
                self.release_all();
                // Automatic field drop now reclaims payloads/charges and wakes
                // original waiters only after all acquired writers are free.
            }
        }

        #[allow(non_camel_case_types)]
        impl<$($prefix: WorldFieldAcquisition,)* $($privacy: WorldFieldAcquisition,)* $($suffix: WorldFieldAcquisition,)*>
            original_control::ReleaseWorldAcquisition for WorldAcquisition<$($prefix,)* $($privacy,)* $($suffix,)*>
        {
            fn release_all(&mut self) { WorldAcquisition::release_all(self); }
        }

        impl<'world> WorldBlock<'world> {
            /// Install every original field before any physical writer releases.
            pub(super) fn begin_freeze(&mut self) {
                self.publication.begin_freeze();
                let fields = self.fields.as_mut().expect("original World block fields");
                $(fields.$prefix.begin_freeze();)*
                $(fields.$privacy.begin_freeze();)*
                $(fields.$suffix.begin_freeze();)*
            }
            pub(super) fn finish_freeze(&mut self) {
                let fields = self.fields.as_mut().expect("original World block fields");
                $(fields.$prefix.finish_freeze();)*
                $(fields.$privacy.finish_freeze();)*
                $(fields.$suffix.finish_freeze();)*
                self.publication.finish_freeze();
            }
            /// Keep the original typed shell while binding each exact source.
            pub(super) fn install_frozen_publication(
                &mut self, target: &'world super::World,
            ) -> Result<(), AdmittedStorageError> {
                self.publication.begin_reacquisition();
                let fields: &mut super::WorldBlockFields<'world> = self.fields.as_mut().expect("original World block fields");
                $(fields.$prefix.install_frozen_publication(&target.$prefix)?;)*
                $(fields.$privacy.install_frozen_publication(&target.$privacy)?;)*
                $(fields.$suffix.install_frozen_publication(&target.$suffix)?;)*
                Ok(())
            }
            pub(super) fn try_prepare_frozen_publication(&mut self)
                -> Result<(), mv::PublicationPreparationError<core::convert::Infallible>> {
                let fields = self.fields.as_mut().expect("original World block fields");
                $(fields.$prefix.try_prepare_frozen_publication()?;)*
                $(fields.$privacy.try_prepare_frozen_publication()?;)*
                $(fields.$suffix.try_prepare_frozen_publication()?;)*
                self.publication.finish_reacquisition();
                Ok(())
            }
            pub(super) fn recover_installed_frozen_publication(&mut self) {
                let fields = self.fields.as_mut().expect("original World block fields");
                $(fields.$prefix.recover_installed_frozen_publication();)*
                $(fields.$privacy.recover_installed_frozen_publication();)*
                $(fields.$suffix.recover_installed_frozen_publication();)*
                self.publication.recover_reacquisition();
            }
            /// Call only after all State participants and fences are unlocked.
            pub(super) fn retire_frozen_cleanup(&mut self) {
                self.publication.assert_frozen();
                let fields = self.fields.as_mut().expect("original World block fields");
                $(fields.$prefix.retire_frozen_cleanup();)*
                $(fields.$privacy.retire_frozen_cleanup();)*
                $(fields.$suffix.retire_frozen_cleanup();)*
            }
            pub(super) fn prepare_publication(&mut self) {
                self.publication.begin_preparation();
                let fields = self.fields.as_mut().expect("original World block fields");
                $(fields.$prefix.prepare_publication();)*
                $(fields.$privacy.prepare_publication();)*
                $(fields.$suffix.prepare_publication();)*
                self.publication.finish_preparation();
            }
            pub(super) fn publish_prepared(&mut self) {
                self.publication.begin_publication();
                let fields = self.fields.as_mut().expect("original World block fields");
                $(fields.$prefix.publish_prepared();)*
                $(fields.$privacy.publish_prepared();)*
                $(fields.$suffix.publish_prepared();)*
                self.publication.finish_publication();
            }
        }

        impl BlockRetirement for WorldBlock<'_> {
            fn release_writers(&mut self) {
                self.publication.release();
                if let Some(fields) = self.fields.as_mut() {
                    $(fields.$prefix.release_writers();)*
                    $(fields.$privacy.release_writers();)*
                    $(fields.$suffix.release_writers();)*
                }
            }
        }
    };
}

with_world_overlay_fields!(declare_world_acquisition);

// Populate inert slots through a borrowed closure before native initialization.
// Per-field constructor temporaries must leave the stack before payload work;
// the enclosing acquisition owner itself stays in its caller throughout.
#[inline(never)]
pub(super) fn fill_world_acquisition<R>(fill: impl FnOnce() -> R) -> R {
    fill()
}

impl Drop for WorldBlock<'_> {
    fn drop(&mut self) {
        self.release_writers();
    }
}

macro_rules! build_world_block_from_fields {
    ($state:expr, $mode:expr, $budget:expr;
        [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {{
        let budget = $budget;
        let mut demand = world_acquisition::OriginalWorldFields::layout().size();
        // End the complete read-only census frame, including each propagated
        // error temporary, before allocating controls or acquiring any writer.
        world_acquisition::fill_world_acquisition(|| -> Result<(), mv::storage::AdmittedStorageError> {
            $(world_acquisition::add_original_control_demand(&$state.$prefix, &mut demand)?;)*
            $(world_acquisition::add_original_control_demand(&$state.$privacy, &mut demand)?;)*
            $(world_acquisition::add_original_control_demand(&$state.$suffix, &mut demand)?;)*
            Ok(())
        })?;
        // Admit the complete concrete control demand atomically before any
        // allocation or physical World writer, from the caller's original pool.
        let mut reservation = budget.try_reserve_bytes(demand).map_err(mv::storage::AdmittedStorageError::Allocation)?;
        let mut fields = world_acquisition::OriginalWorldFields::reserve(&mut reservation)?;
        let mut pending = world_acquisition::WorldAcquisition {
            $($prefix: None,)*
            $($privacy: None,)*
            $($suffix: None,)*
        };
        // Fill the same caller-owned slots one at a time before acquiring any
        // writer, without retaining a full composite initializer temporary.
        world_acquisition::fill_world_acquisition(|| -> Result<(), mv::storage::AdmittedStorageError> {
            $(world_acquisition::initialize_original_field(&mut pending.$prefix, &$state.$prefix, budget, &mut reservation)?;)*
            $(world_acquisition::initialize_original_field(&mut pending.$privacy, &$state.$privacy, budget, &mut reservation)?;)*
            $(world_acquisition::initialize_original_field(&mut pending.$suffix, &$state.$suffix, budget, &mut reservation)?;)*
            Ok(())
        })?;
        assert_eq!(reservation.remaining_bytes(), 0, "complete original World control inventory");
        pending.try_initialize($mode)?;
        world_acquisition::fill_world_acquisition(|| {
            let mut initialization = world_acquisition::WorldPlacement::new(&mut fields, &mut pending);
            let (fields, pending) = initialization.parts();
            let target = fields.uninitialized_pointer();
            // SAFETY: the one original prepaid slot is still length zero. The
            // exhaustive census writes each distinct field exactly once. Its
            // initialized prefix is recorded after each infallible pointer write.
            // The placement guard releases every moved/unmoved writer on unwind
            // before the original owner drops this initialized prefix.
            #[allow(unsafe_code)]
            unsafe {
                fields.write_next(std::ptr::addr_of_mut!((*target).dataspace_catalog), iroha_data_model::nexus::DataSpaceCatalog::default());
                $(fields.take_next(std::ptr::addr_of_mut!((*target).$prefix), pending.$prefix.as_mut().expect("original field acquisition"));)*
                $(fields.take_next(std::ptr::addr_of_mut!((*target).$privacy), pending.$privacy.as_mut().expect("original field acquisition"));)*
                $(fields.take_next(std::ptr::addr_of_mut!((*target).$suffix), pending.$suffix.as_mut().expect("original field acquisition"));)*
                fields.write_next(std::ptr::addr_of_mut!((*target).external_event_buf), Vec::new());
            }
            initialization.finish();
        });
        Ok(WorldBlock {
            publication: block_field::AggregatePublication::Executing,
            fields: Some(fields),
        })
    }};
}

macro_rules! build_world_block {
    ($state:expr, $mode:expr, $budget:expr) => {
        with_world_overlay_fields!(build_world_block_from_fields, $state, ($mode), ($budget))
    };
}

#[cfg(test)]
#[path = "world_acquisition/original_control_tests.rs"]
mod original_control_tests;

/// Test accounting follows the same complete inventory as actual acquisition.
#[cfg(test)]
pub(super) fn original_world_cell_control_bytes(world: &super::World) -> usize {
    macro_rules! sum_successors {
        ($owner:ident; [$($prefix:ident,)*] [$($privacy:ident,)*] [$($suffix:ident,)*]) => {{
            let mut bytes = 0;
            $(bytes += $owner.$prefix.generation_layouts().into_iter().chain([$owner.$prefix.successor_layout()]).flatten().map(|layout| layout.size()).sum::<usize>();)*
            $(bytes += $owner.$privacy.generation_layouts().into_iter().chain([$owner.$privacy.successor_layout()]).flatten().map(|layout| layout.size()).sum::<usize>();)*
            $(bytes += $owner.$suffix.generation_layouts().into_iter().chain([$owner.$suffix.successor_layout()]).flatten().map(|layout| layout.size()).sum::<usize>();)*
            bytes
        }};
    }
    with_world_overlay_fields!(sum_successors, world)
}
