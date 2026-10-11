//! Joint custody of partial and complete original trigger writers.

use super::*;
use mv::{BlockAcquisition, BlockMode, BlockRetirement};

macro_rules! trigger_acquisition {
    ($($field:ident: ($key:ty, $value:ty)),+ $(,)?) => {
        /// Inert original field slots retained across all fallible initialization.
        pub(crate) struct SetBlockAcquisition<'set> {
            $($field: Option<mv::storage::BlockAcquisitionSlot<'set, $key, $value>>,)+
        }

        impl<'set> SetBlockAcquisition<'set> {
            pub(super) fn new(target: &'set Set) -> Self {
                Self { $($field: Some(target.$field.block_acquisition()),)+ }
            }
        }

        impl<'set> BlockAcquisition for SetBlockAcquisition<'set> {
            type Block = SetBlock<'set>;

            fn initialize(&mut self, mode: BlockMode) {
                $(self.$field.as_mut().expect("original trigger slot").initialize(mode);)+
            }

            fn release(&mut self) {
                $(if let Some(field) = self.$field.as_mut() { field.release(); })+
            }

            fn is_initialized(&self) -> bool {
                true $(&& self.$field.as_ref().is_some_and(BlockAcquisition::is_initialized))+
            }

            fn into_block(mut self) -> Self::Block { self.take_block() }

            fn take_block(&mut self) -> Self::Block {
                // Validate every original slot before the first inert field move.
                // A refusal leaves all custody here for aggregate release.
                assert!(self.is_initialized(), "complete original trigger acquisition");
                SetBlock { publication: AggregatePublication::Executing, fields: Some(SetBlockFields {
                    $($field: BlockField::new(self.$field.as_mut().expect("original trigger slot").take_block()),)+
                }) }
            }
        }

        impl Drop for SetBlockAcquisition<'_> {
            fn drop(&mut self) {
                self.release();
            }
        }

        impl<'set> SetBlock<'set> {
            pub(crate) fn begin_freeze(&mut self) {
                self.publication.begin_freeze();
                let fields = self.fields.as_mut().expect("original trigger block fields");
                $(fields.$field.begin_freeze();)+
            }
            pub(crate) fn finish_freeze(&mut self) {
                let fields = self.fields.as_mut().expect("original trigger block fields");
                $(fields.$field.finish_freeze();)+
                self.publication.finish_freeze();
            }
            pub(crate) fn install_frozen_publication(
                &mut self, target: &'set Set,
            ) -> Result<(), mv::storage::AdmittedStorageError> {
                self.publication.begin_reacquisition();
                let fields = self.fields.as_mut().expect("original trigger block fields");
                $(fields.$field.install_frozen_publication(&target.$field)?;)+
                Ok(())
            }
            pub(crate) fn try_prepare_frozen_publication(&mut self)
                -> Result<(), mv::PublicationPreparationError<core::convert::Infallible>> {
                let fields = self.fields.as_mut().expect("original trigger block fields");
                $(fields.$field.try_prepare_frozen_publication()?;)+
                self.publication.finish_reacquisition();
                Ok(())
            }
            pub(crate) fn recover_installed_frozen_publication(&mut self) {
                let fields = self.fields.as_mut().expect("original trigger block fields");
                $(fields.$field.recover_installed_frozen_publication();)+
                self.publication.recover_reacquisition();
            }
            pub(crate) fn retire_frozen_cleanup(&mut self) {
                self.publication.assert_frozen();
                let fields = self.fields.as_mut().expect("original trigger block fields");
                $(fields.$field.retire_frozen_cleanup();)+
            }
            pub(crate) fn prepare_publication(&mut self) {
                self.publication.begin_preparation();
                let fields = self.fields.as_mut().expect("original trigger block fields");
                $(fields.$field.prepare_publication();)+
                self.publication.finish_preparation();
            }
            pub(crate) fn publish_prepared(&mut self) {
                self.publication.begin_publication();
                let fields = self.fields.as_mut().expect("original trigger block fields");
                $(fields.$field.publish_prepared();)+
                self.publication.finish_publication();
            }
        }

        impl BlockRetirement for SetBlock<'_> {
            fn release_writers(&mut self) {
                self.publication.release();
                if let Some(fields) = self.fields.as_mut() {
                    $(fields.$field.release_writers();)+
                }
            }
        }
    };
}

trigger_acquisition! {
    data_triggers: (TriggerId, LoadedAction<DataEventFilter>),
    pipeline_triggers: (TriggerId, LoadedAction<PipelineEventFilterBox>),
    time_triggers: (TriggerId, LoadedAction<TimeEventFilter>),
    by_call_triggers: (TriggerId, LoadedAction<ExecuteTriggerEventFilter>),
    ids: (TriggerId, TriggeringEventType),
    active_data_trigger_ids: (TriggerId, ()),
    active_pipeline_trigger_ids: (TriggerId, ()),
    active_time_trigger_ids: (TriggerId, ()),
    active_by_call_trigger_ids: (TriggerId, ()),
    contracts: (HashOf<IvmBytecode>, IvmBytecodeEntry),
}

impl<'set> SetBlock<'set> {
    pub(super) fn into_fields(mut self) -> SetBlockFields<'set> {
        self.publication.assert_executing();
        self.fields.take().expect("original trigger block fields")
    }
}

impl Drop for SetBlock<'_> {
    fn drop(&mut self) {
        self.release_writers();
    }
}
