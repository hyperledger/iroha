//! Exact recovered State/Kura boundaries shared by finalized-archive query adapters.

/// Authenticated startup boundary of one finalized archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveStartupBoundaryV1 {
    Bootstrap,
    Qualified,
}
/// Require a fully replayed State at the exact durable current-consensus Kura tip.
pub fn classify_archive_startup_boundary(
    state_height: u64,
    kura_height: u64,
) -> Result<ArchiveStartupBoundaryV1, &'static str> {
    if state_height != kura_height {
        return Err("recovered State and durable Kura heights differ");
    }
    Ok(if state_height == 0 {
        ArchiveStartupBoundaryV1::Bootstrap
    } else {
        ArchiveStartupBoundaryV1::Qualified
    })
}
/// Live visibility gate before an archive starts serving queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveActivationGateV1 {
    StrictLive,
    AwaitingGenesis,
}
