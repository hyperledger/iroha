//! Per-package facts over original borrowed identities or frozen ordinal tokens.

pub(super) struct PackageRevision<P, V> {
    pub(super) package: P,
    pub(super) latest: Option<V>,
    pub(super) maximum: Option<u64>,
    pub(super) directory_present: bool,
}
impl<P, V> PackageRevision<P, V> {
    pub(super) fn new(package: P) -> Self {
        Self {
            package,
            latest: None,
            maximum: None,
            directory_present: false,
        }
    }
    pub(super) fn observe(
        &mut self,
        version: V,
        row: &iroha_data_model::musubi::MusubiResolverReleaseRowV1,
        newer: bool,
    ) {
        self.maximum = Some(self.maximum.map_or(row.index_revision, |previous| {
            previous.max(row.index_revision)
        }));
        if row.selection.fresh_selectable() && newer {
            self.latest = Some(version);
        }
    }
}
