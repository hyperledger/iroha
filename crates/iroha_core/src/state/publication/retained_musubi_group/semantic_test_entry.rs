//! Native tests enter the production retained capture through the actual State owner.
use super::*;
#[cfg(test)]
impl StateBlock<'_> {
    pub(in crate::state) fn start_configured_original_musubi_source_admission(
        &mut self,
    ) -> Result<(), RetainedMusubiGroupReadError> {
        self.original_musubi_capture()?
            .start_configured_original_musubi_source_admission()
    }
    pub(in crate::state) fn start_original_musubi_source_admission(
        &mut self,
        limits: SourceWorkLimits,
    ) -> Result<(), RetainedMusubiGroupReadError> {
        self.original_musubi_capture()?
            .start_original_musubi_source_admission(limits)
    }
    pub(in crate::state) fn advance_original_musubi_source_admission(
        &mut self,
        image: OriginalMusubiImage,
        work_limit: usize,
    ) -> Result<musubi_source_work::AdmissionProgress, OriginalMusubiValidationError> {
        self.original_musubi_capture()
            .map_err(ReadFailure::Source)?
            .advance_original_musubi_source_admission(image, work_limit)
    }
    pub(in crate::state) fn original_musubi_source_admission_progress(
        &self,
        image: OriginalMusubiImage,
    ) -> Option<musubi_source_work::AdmissionProgress> {
        let plan = self.publication.as_ref()?.musubi_group_read.as_ref()?;
        Some(plan.admission.as_ref()?.as_slice()[0].images[image.index()].progress())
    }
    pub(in crate::state) fn advance_original_musubi_live(
        &mut self,
        image: OriginalMusubiImage,
        work_limit: usize,
    ) -> Result<LiveProgress, OriginalMusubiValidationError> {
        self.original_musubi_capture()
            .map_err(ReadFailure::Source)?
            .advance_original_musubi_live(image, work_limit)
    }
    pub(in crate::state) fn advance_original_musubi_universal(
        &mut self,
        image: OriginalMusubiImage,
        work_limit: usize,
    ) -> Result<UniversalProgress, OriginalMusubiValidationError> {
        self.original_musubi_capture()
            .map_err(ReadFailure::Source)?
            .advance_original_musubi_universal(image, work_limit)
    }
    pub(in crate::state) fn advance_original_musubi_directory_revisions(
        &mut self,
        image: OriginalMusubiImage,
        work_limit: usize,
    ) -> Result<DirectoryProgress, OriginalMusubiValidationError> {
        self.original_musubi_capture()
            .map_err(ReadFailure::Source)?
            .advance_original_musubi_directory_revisions(image, work_limit)
    }
    pub(in crate::state) fn original_musubi_universal_progress(
        &self,
        image: OriginalMusubiImage,
    ) -> Option<UniversalProgress> {
        let plan = self.publication.as_ref()?.musubi_group_read.as_ref()?;
        Some(plan.admission.as_ref()?.as_slice()[0].universal[image.index()].progress())
    }
    pub(in crate::state) fn original_musubi_directory_progress(
        &self,
        image: OriginalMusubiImage,
    ) -> Option<DirectoryProgress> {
        let plan = self.publication.as_ref()?.musubi_group_read.as_ref()?;
        Some(plan.admission.as_ref()?.as_slice()[0].directory[image.index()].progress())
    }
    pub(in crate::state) fn original_musubi_live_progress(
        &self,
        image: OriginalMusubiImage,
    ) -> Option<LiveProgress> {
        let original = self
            .publication
            .as_ref()?
            .musubi_group_read
            .as_ref()?
            .admission
            .as_ref()?;
        Some(original.as_slice()[0].live.as_slice()[image.index()].progress())
    }
    pub(in crate::state) fn grant_original_musubi_capture_attempt(
        &mut self,
    ) -> Result<usize, RetainedMusubiGroupReadError> {
        self.original_musubi_capture()?
            .grant_original_musubi_capture_attempt()
    }
    pub(in crate::state) fn advance_configured_original_musubi_validation(
        &mut self,
    ) -> Result<(), OriginalMusubiValidationError> {
        self.original_musubi_capture()
            .map_err(ReadFailure::Source)?
            .advance_configured_original_musubi_validation()
    }
    pub(in crate::state) fn with_validated_original_musubi_materializers<R>(
        &mut self,
        limit: usize,
        callback: impl for<'read> FnOnce(
            OriginalMusubiRows<'read>,
            OriginalMusubiRevision<'read>,
            &'read mut Option<crate::state::authority_registry::OriginalMusubiMaterializers>,
        ) -> R,
    ) -> Result<R, RetainedMusubiGroupReadError> {
        self.original_musubi_capture()?
            .with_validated_original_musubi_materializers(limit, callback)
    }
}
