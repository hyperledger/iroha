//! Static semantic rejection custody for borrowed Musubi projection validation.
//!
//! The shared validators retain no allocated diagnostic strings. Restore and
//! publication render their existing diagnostics only after semantic validation
//! has completed. This does not fund Unicode, codec, or cryptographic workspaces.

use norito::json;

/// Canonical projection source table; names cannot come from untrusted input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionTable {
    Archives,
    ArchiveLocations,
    ProviderBundleAttestations,
    ArchiveAvailability,
    ResolverIndex,
    PublicDirectory,
}

impl ProjectionTable {
    /// Borrow the complete canonical field spelling without allocating a prefix.
    pub(crate) const fn field(self) -> &'static str {
        match self {
            Self::Archives => "world.musubi_archives",
            Self::ArchiveLocations => "world.musubi_archive_locations",
            Self::ProviderBundleAttestations => "world.musubi_provider_bundle_attestations",
            Self::ArchiveAvailability => "world.musubi_archive_availability",
            Self::ResolverIndex => "world.musubi_resolver_index",
            Self::PublicDirectory => "world.musubi_public_directory",
        }
    }
}

/// Existing diagnostic context for the exact borrowed World being checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionCut {
    Current,
    Predecessor,
    Capture,
    Candidate,
}

impl ProjectionCut {
    const fn label(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Predecessor => "predecessor",
            Self::Capture => "capture",
            Self::Candidate => "candidate",
        }
    }
}

/// Completed semantic failure whose entire payload has static lifetime.
///
/// Local resource refusal remains `ExecutionAttemptError::Deferred`; there is
/// deliberately no conversion from an allocation error into this descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProjectionRejection {
    table: ProjectionTable,
    reason: &'static str,
    cut: Option<ProjectionCut>,
}

impl ProjectionRejection {
    /// Preserve a static predicate or model parse reason without formatting it.
    pub(crate) const fn new(table: ProjectionTable, reason: &'static str) -> Self {
        Self {
            table,
            reason,
            cut: None,
        }
    }

    /// Attach the already-known observation context without copying diagnostic text.
    pub(crate) const fn with_cut(mut self, cut: ProjectionCut) -> Self {
        self.cut = Some(cut);
        self
    }

    /// Borrow the canonical field for typed semantic assertions and diagnostics.
    pub(crate) const fn field(self) -> &'static str {
        self.table.field()
    }

    /// Borrow the original static reason without creating a replacement error.
    #[cfg(test)]
    pub(crate) const fn reason(self) -> &'static str {
        self.reason
    }

    fn fmt_message(self, formatter: &mut impl std::fmt::Write) -> std::fmt::Result {
        if let Some(cut) = self.cut {
            write!(formatter, "{} World cut: ", cut.label())?;
        }
        formatter.write_str(self.reason)
    }

    /// Render only at the existing owned snapshot-error boundary.
    ///
    /// These boundary-owned strings are not a funded capture error. Capture must
    /// retain the static descriptor, and publication can format it directly.
    pub(crate) fn into_json(self) -> json::Error {
        let mut message = String::new();
        self.fmt_message(&mut message)
            .expect("writing to String cannot fail");
        json::Error::InvalidField {
            field: self.field().to_owned(),
            message,
        }
    }
}

impl std::fmt::Display for ProjectionRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "JSON error: invalid field `{}`: ", self.field())?;
        self.fmt_message(formatter)
    }
}
impl std::error::Error for ProjectionRejection {}
