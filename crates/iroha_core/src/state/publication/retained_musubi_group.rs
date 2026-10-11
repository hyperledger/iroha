//! Retain all fourteen original Musubi physical map pairs in StatePublication.
//!
//! This closed structural stage retains actual current/undo work, metadata and
//! original scope through partial backing/work refusal and reader-held retirement.
//! Raw undo is not a complete predecessor. The revision retains its exact original
//! current/undo EBR allocations in the same CellField and charged group control.
//! TODO: connect ordered predecessor descriptors to admitted semantic query/resolve
//! work and materialized nodes. Exact structural custody does not authenticate
//! the full Musubi aggregate or authorize complete State/publication.

use super::{
    retained_musubi::{PackageReadProgress, RetainedPackageReadError},
    retained_rows::{OriginalTableRead, PredecessorReadProgress},
    *,
};
use iroha_allocation::{ChargedBuffer, OwnedAllocationScope};
use iroha_data_model::{
    account::AccountId,
    sorafs::{
        capacity::ProviderId,
        pin_registry::{
            ManifestDigest, PinManifestRecord, ReplicationOrderId, ReplicationOrderRecord,
        },
    },
};

/// Exact local group/source or original field refusal; no physical wait is forged.
#[derive(Debug)]
pub(crate) enum RetainedMusubiGroupReadError {
    /// Complete original frozen publication required; terminal phases refuse.
    NotFrozen,
    /// The original State or original paired work/predecessor has changed.
    SourceChanged,
    /// Original refund scope must belong to the original State execution pool.
    ScopeIdentity,
    /// Physical/control admission retains its exact original allocation cause.
    Control(iroha_allocation::ChargedBufferError),
    /// Preserve which original field and its unchanged typed local cause.
    Field {
        field: &'static str,
        original: RetainedPackageReadError,
    },
    /// No complete structural projection is exposed before every map finishes.
    Incomplete,
    /// Actual original readers remain; no mutex-release event exists here.
    ReadersRetained { field: &'static str },
}

/// Publicly observable structural stage; no semantic-completion authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MusubiGroupReadProgress {
    pub(crate) tables: [PackageReadProgress; 14],
    pub(crate) work: usize,
    pub(crate) complete: bool,
    pub(crate) retired_tables: usize,
    pub(crate) retired: bool,
}

/// Observation of retained ordered predecessor descriptors in the same group.
/// These counts establish no semantic verification or complete-State authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MusubiGroupPredecessorProgress {
    pub(crate) tables: [PredecessorReadProgress; 14],
    pub(crate) work: usize,
    pub(crate) complete: bool,
}

pub(super) struct RetainedMusubiGroupRead {
    data: Option<ChargedBuffer<MusubiGroupReadData>>,
    // The cut is retained beside its exact original staged allocations in data.
    // After reader retirement it remains only a physical installation precondition.
    revision_predecessor: mv::BlockPublicationIdentity,
    scope: OwnedAllocationScope,
    generation: u64,
    work: usize,
    complete: bool,
    final_progress: Option<[PackageReadProgress; 14]>,
    retired_tables: usize,
    pub(super) retired: bool,
}
/// Immutable exact original revision pair, borrowed inside the State-owned callback.
/// Its actual staged allocations are retained; no semantic verification is implied.
pub(crate) struct OriginalMusubiRevision<'read> {
    current: &'read MusubiResolverIndexRevisionV1,
    predecessor: &'read MusubiResolverIndexRevisionV1,
}
impl OriginalMusubiRevision<'_> {
    /// Borrow the actual frozen current revision value.
    pub(crate) fn current(&self) -> &MusubiResolverIndexRevisionV1 {
        self.current
    }
    /// Borrow the actual frozen before-block revision value.
    pub(crate) fn predecessor(&self) -> &MusubiResolverIndexRevisionV1 {
        self.predecessor
    }
}

// One closed inventory generates the actual typed owner and existing State APIs.
// It is not an externally implementable storage/capture interface. Every emitted
// branch touches the original named World field and its exact source/pool owner.
macro_rules! define_original_musubi_group {
    ($(($index:literal, $field:ident, $key:ty, $value:ty, $current:ident, $undo:ident, $predecessor:ident)),+ $(,)?) => {
        // All positions/cursors/readers drop before the outer original scope.
        // MV current/undo metadata/admission stays in the exact Reading field.
        struct MusubiGroupReadData {
            $($field: Option<OriginalTableRead<$key,$value>>,)+
            revision: Option<mv::cell::FrozenDetachedRead<MusubiResolverIndexRevisionV1>>,
        }
        impl MusubiGroupReadData {
            fn progress(&self,work:usize)->[PackageReadProgress;14] {
                [$(self.$field.as_ref().map_or(PackageReadProgress {
                    current:0,undo:0,work,complete:false,retired:false
                },|table|table.observe(work,false))),+]
            }
        }
        impl RetainedMusubiGroupRead {
            fn predecessor_progress(&self)->Option<MusubiGroupPredecessorProgress> {
                let data=&self.data.as_ref()?.as_slice()[0];
                let tables=[$(data.$field.as_ref()?.predecessor_progress()),+];
                Some(MusubiGroupPredecessorProgress { complete:tables.iter().all(|table|table.complete),tables,work:self.work })
            }
            fn advance_predecessor(&mut self,limit:usize)->Result<MusubiGroupPredecessorProgress,RetainedMusubiGroupReadError> {
                if !self.complete || self.retired {return Err(RetainedMusubiGroupReadError::Incomplete);}
                let data=&mut self.data.as_mut().ok_or(RetainedMusubiGroupReadError::NotFrozen)?.as_mut_slice()[0];
                $(data.$field.as_mut().expect(concat!("original ",stringify!($field)))
                    .advance_predecessor(self.scope.allocation_budget(),&mut self.work,limit)
                    .map_err(|original|RetainedMusubiGroupReadError::Field {field:stringify!($field),original})?;)+
                self.predecessor_progress().ok_or(RetainedMusubiGroupReadError::NotFrozen)
            }
            fn observe(&self)->MusubiGroupReadProgress {
                let mut tables=if let Some(data)=&self.data {data.as_slice()[0].progress(self.work)}
                    else {self.final_progress.expect("positions retired only after full capture")};
                for (index,table) in tables.iter_mut().enumerate() {table.retired=index<self.retired_tables;}
                MusubiGroupReadProgress {tables,work:self.work,complete:self.complete,
                    retired_tables:self.retired_tables,retired:self.retired}
            }
            fn advance(&mut self,limit:usize)->Result<MusubiGroupReadProgress,RetainedMusubiGroupReadError> {
                if self.retired {return Ok(self.observe());}
                let data=&mut self.data.as_mut().ok_or(RetainedMusubiGroupReadError::NotFrozen)?.as_mut_slice()[0];
                $(data.$field.as_mut().expect(concat!("original ",stringify!($field)))
                    .advance(self.scope.allocation_budget(),&mut self.work,limit)
                    .map_err(|original|RetainedMusubiGroupReadError::Field {field:stringify!($field),original})?;)+
                self.complete=true;
                Ok(self.observe())
            }
        }
        /// Closed physical rows, with fallible finite structural resolve admission.
        /// Raw undo is not a predecessor; this implements no checked marker/trait.
        /// Ordered predecessor rows have a retained descriptor stage. Their
        /// finite structural resolves stay fallible under the original work.
        /// TODO: semantic query/accumulator/sort admission and materialized nodes
        /// must precede the infallible semantic StorageReadOnly boundary.
        pub(crate) struct OriginalMusubiRows<'read> {
            data:&'read MusubiGroupReadData,
            work:&'read mut usize,
            limit:usize,
        }
        impl OriginalMusubiRows<'_> {
            $(
                #[doc=concat!("Resolve ordered original predecessor ",stringify!($field)," only after complete descriptor admission.")]
                pub(crate) fn $predecessor(&mut self,index:usize)->Result<(&$key,&$value),RetainedMusubiGroupReadError> {
                    self.data.$field.as_ref().expect(concat!("original ",stringify!($field)))
                        .predecessor_row(index,self.work,self.limit)
                        .map_err(|original|RetainedMusubiGroupReadError::Field {field:stringify!($field),original})
                }
                #[doc=concat!("Resolve original current ",stringify!($field)," after finite structural admission.")]
                pub(crate) fn $current(&mut self,index:usize)->Result<(&$key,&$value),RetainedMusubiGroupReadError> {
                    self.data.$field.as_ref().expect(concat!("original ",stringify!($field)))
                        .current_row(index,self.work,self.limit)
                        .map_err(|original|RetainedMusubiGroupReadError::Field {field:stringify!($field),original})
                }
                #[doc=concat!("Resolve original raw undo ",stringify!($field),"; this is not a complete predecessor.")]
                pub(crate) fn $undo(&mut self,index:usize)->Result<(&$key,&Option<$value>),RetainedMusubiGroupReadError> {
                    self.data.$field.as_ref().expect(concat!("original ",stringify!($field)))
                        .undo_row(index,self.work,self.limit)
                        .map_err(|original|RetainedMusubiGroupReadError::Field {field:stringify!($field),original})
                }
            )+
        }
        impl StateBlock<'_> {
            /// Retain fourteen original paired map readers once under the same scope.
            /// Every pre-installation failure returns the unchanged move-only scope.
            #[expect(clippy::result_large_err,reason="refusal returns the original move-only scope without allocating an error wrapper")]
            pub(crate) fn start_original_musubi_group_read(&mut self,scope:OwnedAllocationScope)
                ->Result<(),(OwnedAllocationScope,RetainedMusubiGroupReadError)> {
                let fields=self.fields.as_mut().expect("original State fields");
                let state=fields.state_ref;
                let Some(publication)=self.publication.as_mut() else {return Err((scope,RetainedMusubiGroupReadError::NotFrozen));};
                if !publication.fields_frozen || publication.irreversible || publication.published || publication.poisoned
                    || publication.package_read.is_some() || publication.musubi_group_read.is_some() {
                    return Err((scope,RetainedMusubiGroupReadError::NotFrozen));
                }
                if !scope.belongs_to(&state.ivm_execution_budget()) {return Err((scope,RetainedMusubiGroupReadError::ScopeIdentity));}
                if publication.predecessor_generation!=Some(state.state_view_generation()) {
                    return Err((scope,RetainedMusubiGroupReadError::SourceChanged));
                }
                let revision=&fields.world.musubi_resolver_index_revision;
                if revision.frozen_values().is_none() {return Err((scope,RetainedMusubiGroupReadError::NotFrozen));}
                if !revision.belongs_to(&state.world.musubi_resolver_index_revision)
                    || revision.retained_read_matches_current(&state.world.musubi_resolver_index_revision)!=Some(true) {
                    return Err((scope,RetainedMusubiGroupReadError::SourceChanged));
                }
                let mode=revision.mode();
                let revision_predecessor=revision.publication_identity();
                // Original stored cursor lengths are O(1), never a row prepass.
                let counts=[$({
                    let Some(images)=fields.world.$field.frozen_images() else {return Err((scope,RetainedMusubiGroupReadError::NotFrozen));};
                    if images.mode()!=mode || !images.belongs_to(&state.world.$field)
                        || fields.world.$field.retained_read_matches_current(&state.world.$field)!=Some(true) {
                        return Err((scope,RetainedMusubiGroupReadError::SourceChanged));
                    }
                    (images.current_entries().len(),images.undo_entries().len())
                }),+];
                let mut data=match ChargedBuffer::new(1,scope.allocation_budget()) {
                    Ok(data)=>data,
                    Err(error)=>return Err((scope,RetainedMusubiGroupReadError::Control(error))),
                };
                data.push_reserved(MusubiGroupReadData {$($field:None,)+ revision:None});
                publication.musubi_group_read=Some(RetainedMusubiGroupRead {
                    data:Some(data),revision_predecessor,scope,generation:state.state_view_generation(),
                    work:0,complete:false,final_progress:None,retired_tables:0,retired:false,
                });
                // No callback or concurrent mutation occurs between preflight and
                // these allocation-free moves. Install scope first: an unexpected
                // unwind retains it and every captured sibling in the publisher.
                let data=&mut publication.musubi_group_read.as_mut().expect("installed original plan")
                    .data.as_mut().expect("admitted original shell").as_mut_slice()[0];
                $(
                    let source=fields.world.$field.retain_original_readers()
                        .expect(concat!("complete original ",stringify!($field)," preflight"));
                    data.$field=Some(OriginalTableRead::new(source,counts[$index].0,counts[$index].1));
                )+
                data.revision=Some(fields.world.musubi_resolver_index_revision.retain_original_readers()
                    .expect("complete original revision preflight"));
                Ok(())
            }
            fn check_original_musubi_group_read(&self)->Result<(),RetainedMusubiGroupReadError> {
                let publication=self.publication.as_ref().ok_or(RetainedMusubiGroupReadError::NotFrozen)?;
                let plan=publication.musubi_group_read.as_ref().ok_or(RetainedMusubiGroupReadError::NotFrozen)?;
                if publication.published || publication.poisoned || publication.irreversible || !publication.fields_frozen {
                    return Err(RetainedMusubiGroupReadError::NotFrozen);
                }
                let fields=self.fields.as_ref().expect("original State fields");
                let state=fields.state_ref;
                if !plan.scope.belongs_to(&state.ivm_execution_budget()) {return Err(RetainedMusubiGroupReadError::ScopeIdentity);}
                if plan.generation!=state.state_view_generation() {return Err(RetainedMusubiGroupReadError::SourceChanged);}
                let revision=&fields.world.musubi_resolver_index_revision;
                // Target/predecessor and actual staged pair are independent checks.
                if revision.frozen_values().is_none() {return Err(RetainedMusubiGroupReadError::NotFrozen);}
                if !revision.belongs_to(&state.world.musubi_resolver_index_revision)
                    || revision.publication_identity()!=plan.revision_predecessor
                    || revision.retained_read_matches_current(&state.world.musubi_resolver_index_revision)!=Some(true) {
                    return Err(RetainedMusubiGroupReadError::SourceChanged);
                }
                if let Some(data)=&plan.data {
                    let source=data.as_slice()[0].revision.as_ref().ok_or(RetainedMusubiGroupReadError::NotFrozen)?;
                    #[cfg(not(all(test, sumeragi_core_mutation = "HC172")))]
                    if !revision.retained_read_matches_source(source) {
                        return Err(RetainedMusubiGroupReadError::SourceChanged);
                    }
                    #[cfg(all(test, sumeragi_core_mutation = "HC172"))]
                    let _=source; // Mutation: equal predecessor/value replaces the actual staged revision pair.
                }
                $(
                    if fields.world.$field.retained_read_matches_current(&state.world.$field)!=Some(true) {
                        return Err(RetainedMusubiGroupReadError::SourceChanged);
                    }
                    if let Some(data)=&plan.data {
                        if !fields.world.$field.retained_read_matches_source(&data.as_slice()[0].$field
                            .as_ref().ok_or(RetainedMusubiGroupReadError::NotFrozen)?.source) {
                            return Err(RetainedMusubiGroupReadError::SourceChanged);
                        }
                    }
                )+
                Ok(())
            }
            /// Resume original positions/stages without rebuilding completed work.
            pub(crate) fn advance_original_musubi_group_read(&mut self,limit:usize)
                ->Result<MusubiGroupReadProgress,RetainedMusubiGroupReadError> {
                self.check_original_musubi_group_read()?;
                self.publication.as_mut().expect("original publication").musubi_group_read.as_mut().expect("original plan").advance(limit)
            }
            /// Resume ordered predecessor descriptors of the same fourteen pairs.
            /// Successful comparison heads/frontiers/work remain through refusal.
            /// This prerequisite does not admit the infallible semantic verifier.
            pub(crate) fn advance_original_musubi_group_predecessor_read(&mut self,limit:usize)
                ->Result<MusubiGroupPredecessorProgress,RetainedMusubiGroupReadError> {
                self.check_original_musubi_group_read()?;
                self.publication.as_mut().expect("original publication").musubi_group_read.as_mut().expect("original plan").advance_predecessor(limit)
            }
            /// Observe descriptors without rebuilding or scanning any original row.
            /// None after actual index/source retirement; no old authority survives.
            pub(crate) fn original_musubi_group_predecessor_progress(&self)->Option<MusubiGroupPredecessorProgress> {
                self.publication.as_ref()?.musubi_group_read.as_ref()?.predecessor_progress()
            }
            /// Observe existing counts/work without scans or replenished admission.
            pub(crate) fn original_musubi_group_read_progress(&self)->Option<MusubiGroupReadProgress> {
                self.publication.as_ref()?.musubi_group_read.as_ref().map(RetainedMusubiGroupRead::observe)
            }
            /// Borrow exact physical map rows and the actual frozen revision values.
            /// The same original source is checked before and after the callback.
            /// Refusal drops its exact returned value and retains all original
            /// indexes/readers, refund scope and successful work.
            /// An equal revision staged under the same predecessor cannot replace
            /// either original allocation. No semantic authority marker or infallible
            /// StorageReadOnly implementation is exposed by this callback.
            pub(crate) fn with_original_musubi_rows<R>(&mut self,limit:usize,
                callback:impl for<'read> FnOnce(OriginalMusubiRows<'read>,OriginalMusubiRevision<'read>)->R)
                ->Result<R,RetainedMusubiGroupReadError> {
                self.check_original_musubi_group_read()?;
                let plan=self.publication.as_mut().expect("original publication").musubi_group_read.as_mut().expect("original plan");
                if !plan.complete || plan.retired || plan.data.is_none() {return Err(RetainedMusubiGroupReadError::Incomplete);}
                let data=&plan.data.as_ref().expect("complete original data").as_slice()[0];
                let revision=data.revision.as_ref().ok_or(RetainedMusubiGroupReadError::NotFrozen)?;
                let current=&**revision.current();
                let predecessor=revision.get_before_block();
                let result=callback(OriginalMusubiRows {data,work:&mut plan.work,limit},OriginalMusubiRevision {current,predecessor});
                // Detached immutable rows stay valid if the shared State advances,
                // but a result computed across that change cannot name the original
                // State cut. Drop that exact result on refusal; retained work/readers
                // and their original scope remain owned by this publication.
                #[cfg(not(all(test, sumeragi_core_mutation = "HC171")))]
                self.check_original_musubi_group_read()?;
                Ok(result)
            }
            /// Retire actual indexes/readers before original writer installation.
            /// Later reader refusal keeps completed thaw stages and the exact scope.
            /// A reader-held refusal has no physical mutex ReleaseWait event.
            pub(crate) fn retire_original_musubi_group_read(&mut self)->Result<(),RetainedMusubiGroupReadError> {
                self.check_original_musubi_group_read()?;
                let plan=self.publication.as_mut().expect("original publication").musubi_group_read.as_mut().expect("original plan");
                if !plan.complete {return Err(RetainedMusubiGroupReadError::Incomplete);}
                if plan.retired {return Ok(());}
                if plan.data.is_some() {
                    plan.final_progress=Some(plan.observe().tables);
                    drop(plan.data.take());
                }
                let world=&mut self.fields.as_mut().expect("original State fields").world;
                $(
                    if plan.retired_tables==$index {
                        world.$field.try_retire_original_readers().map_err(|error|match error {
                            block_field::RetainedReadPhaseError::NotFrozen=>RetainedMusubiGroupReadError::NotFrozen,
                            block_field::RetainedReadPhaseError::ReadersRetained=>RetainedMusubiGroupReadError::ReadersRetained {field:stringify!($field)},
                        })?;
                        plan.retired_tables+=1;
                    }
                )+
                world.musubi_resolver_index_revision.try_retire_original_readers().map_err(|error|match error {
                    block_field::RetainedReadPhaseError::NotFrozen=>RetainedMusubiGroupReadError::NotFrozen,
                    block_field::RetainedReadPhaseError::ReadersRetained=>RetainedMusubiGroupReadError::ReadersRetained {field:"musubi_resolver_index_revision"},
                })?;
                plan.retired=true;
                Ok(())
            }
        }
    }
}

define_original_musubi_group! {
    (0,musubi_archives,ArchiveId,MusubiArchiveRecordV1,musubi_archives_current_row,musubi_archives_undo_row,musubi_archives_predecessor_row),
    (1,musubi_archive_availability,ArchiveId,MusubiArchiveAvailabilityV1,musubi_archive_availability_current_row,musubi_archive_availability_undo_row,musubi_archive_availability_predecessor_row),
    (2,musubi_archive_locations,MusubiArchiveLocationKeyV1,MusubiArchiveLocationV1,musubi_archive_locations_current_row,musubi_archive_locations_undo_row,musubi_archive_locations_predecessor_row),
    (3,musubi_locations_by_pin,ManifestDigest,MusubiPinLocationReferenceV1,musubi_locations_by_pin_current_row,musubi_locations_by_pin_undo_row,musubi_locations_by_pin_predecessor_row),
    (4,musubi_locations_by_provider,MusubiProviderLocationKeyV1,(),musubi_locations_by_provider_current_row,musubi_locations_by_provider_undo_row,musubi_locations_by_provider_predecessor_row),
    (5,musubi_locations_by_replication_order,ReplicationOrderId,MusubiReplicationOrderLocationReferenceV1,musubi_locations_by_replication_order_current_row,musubi_locations_by_replication_order_undo_row,musubi_locations_by_replication_order_predecessor_row),
    (6,musubi_packages,MusubiPackageIdV1,MusubiPackageRecordV1,musubi_packages_current_row,musubi_packages_undo_row,musubi_packages_predecessor_row),
    (7,musubi_provider_bundle_attestations,MusubiProviderBundleAttestationKeyV1,MusubiProviderBundleAttestationRecordV1,musubi_provider_bundle_attestations_current_row,musubi_provider_bundle_attestations_undo_row,musubi_provider_bundle_attestations_predecessor_row),
    (8,musubi_public_directory,MusubiPackageSelectorV1,MusubiOrderedPackageEntryV1,musubi_public_directory_current_row,musubi_public_directory_undo_row,musubi_public_directory_predecessor_row),
    (9,musubi_releases,MusubiReleaseIdV1,MusubiReleaseRecordV1,musubi_releases_current_row,musubi_releases_undo_row,musubi_releases_predecessor_row),
    (10,musubi_resolver_index,MusubiReleaseIdV1,MusubiResolverReleaseRowV1,musubi_resolver_index_current_row,musubi_resolver_index_undo_row,musubi_resolver_index_predecessor_row),
    (11,pin_manifests,ManifestDigest,PinManifestRecord,pin_manifests_current_row,pin_manifests_undo_row,pin_manifests_predecessor_row),
    (12,provider_owners,ProviderId,AccountId,provider_owners_current_row,provider_owners_undo_row,provider_owners_predecessor_row),
    (13,replication_orders,ReplicationOrderId,ReplicationOrderRecord,replication_orders_current_row,replication_orders_undo_row,replication_orders_predecessor_row),
}

#[cfg(test)]
pub(in crate::state) fn retained_musubi_group_control_layout_for_test() -> std::alloc::Layout {
    std::alloc::Layout::array::<MusubiGroupReadData>(1).expect("actual group control layout")
}
/// Actual original paired read and scope used by the adversarial retirement test.
#[cfg(test)]
pub(in crate::state) struct RetainedMusubiGroupReaderForTest {
    _reader: mv::storage::FrozenDetachedRead<MusubiPackageIdV1, MusubiPackageRecordV1>,
    _scope: OwnedAllocationScope,
}
#[cfg(test)]
impl StateBlock<'_> {
    pub(in crate::state) fn retain_group_package_reader_for_test(
        &mut self,
    ) -> Result<RetainedMusubiGroupReaderForTest, RetainedMusubiGroupReadError> {
        self.check_original_musubi_group_read()?;
        let scope = self
            .publication
            .as_ref()
            .expect("original publication")
            .musubi_group_read
            .as_ref()
            .expect("original group")
            .scope
            .clone();
        let reader = self
            .fields
            .as_mut()
            .expect("original State fields")
            .world
            .musubi_packages
            .retain_original_readers()
            .ok_or(RetainedMusubiGroupReadError::NotFrozen)?;
        Ok(RetainedMusubiGroupReaderForTest {
            _reader: reader,
            _scope: scope,
        })
    }
}

/// Actual single-allocation revision reader and original scope for retirement controls.
#[cfg(test)]
pub(in crate::state) struct RetainedMusubiRevisionReaderForTest {
    _current: Option<concread::ebrcell::EbrCellFrozenRead<MusubiResolverIndexRevisionV1>>,
    _undo: Option<concread::ebrcell::EbrCellFrozenRead<Option<MusubiResolverIndexRevisionV1>>>,
    _scope: OwnedAllocationScope,
}
#[cfg(test)]
impl RetainedMusubiRevisionReaderForTest {
    /// Inspect the retained original scope without replacing its owner.
    pub(in crate::state) fn scope_belongs_to(
        &self,
        budget: &iroha_allocation::AllocationBudget,
    ) -> bool {
        let Self { _scope: scope, .. } = self;
        scope.belongs_to(budget)
    }
}
#[cfg(test)]
impl StateBlock<'_> {
    pub(in crate::state) fn retain_group_revision_reader_for_test(
        &mut self,
        current: bool,
    ) -> Result<RetainedMusubiRevisionReaderForTest, RetainedMusubiGroupReadError> {
        self.check_original_musubi_group_read()?;
        let scope = self
            .publication
            .as_ref()
            .expect("original publication")
            .musubi_group_read
            .as_ref()
            .expect("original group")
            .scope
            .clone();
        let source = self
            .fields
            .as_mut()
            .expect("original State fields")
            .world
            .musubi_resolver_index_revision
            .retain_original_readers()
            .ok_or(RetainedMusubiGroupReadError::NotFrozen)?;
        Ok(RetainedMusubiRevisionReaderForTest {
            _current: current.then(|| source.current().clone()),
            _undo: (!current).then(|| source.undo().clone()),
            _scope: scope,
        })
    }
}
