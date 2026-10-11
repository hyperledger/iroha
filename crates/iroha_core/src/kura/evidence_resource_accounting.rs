// Included at Kura module scope. File-key counts never confer evidence authority.

/// Immutable limits owned by the configured Kura instance.
#[derive(Clone, Copy)]
struct EvidenceResourceLimits {
    fastpq_artifacts: iroha_config::parameters::actual::KuraFastpqArtifactPolicy,
}

impl Kura {
    fn evidence_resource_limits(&self) -> EvidenceResourceLimits {
        EvidenceResourceLimits {
            fastpq_artifacts: self.fastpq_artifact_policy,
        }
    }
}

fn evidence_resource_hex(text: &str, bytes: usize) -> bool {
    text.len() == bytes * 2
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Classify exact existing standalone record formats, with no payload decoding.
///
/// The caller separately binds the path to the complete authenticated Kura scope.
/// An occupied reserved namespace with an unknown filename is an error, never a
/// zero contribution. Main and temporary names remain separate physical records.
fn evidence_resource_kind(
    path: &Path,
    limits: EvidenceResourceLimits,
) -> std::result::Result<Option<(IndexResourceFormat, bool)>, resource_inventory::Unavailable> {
    use resource_inventory::Unavailable as Missing;
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(Missing::OwnerMismatch)?;
    let directory = path
        .parent()
        .and_then(Path::file_name)
        .and_then(std::ffi::OsStr::to_str);
    let singleton =
        |maximum, temporary| Ok(Some((IndexResourceFormat::Singleton(maximum), temporary)));
    let (stable, temporary) = name
        .strip_suffix(".tmp")
        .map_or((name, false), |stable| (stable, true));

    // Reserved namespace ownership wins over generic known marker basenames.
    if directory == Some(fastpq_artifact_store::DIRECTORY) {
        limits
            .fastpq_artifacts
            .validate()
            .map_err(|_| Missing::InvalidInventory)?;
        let maximum = limits.fastpq_artifacts.max_artifact_bytes.get() as u64;
        if name == fastpq_artifact_store::TEMPORARY {
            return Ok(Some((
                IndexResourceFormat::TemporarySingleton(maximum),
                true,
            )));
        }
        if name
            .strip_suffix(".norito")
            .is_some_and(|hash| evidence_resource_hex(hash, Hash::LENGTH))
        {
            return singleton(maximum, false);
        }
        return Err(Missing::OwnerMismatch);
    }

    let fixed = match stable {
        COUNT_FILE_NAME => Some(MAX_BLOCK_COMMIT_MARKER_BYTES as u64),
        DA_BLOCK_REWRITE_STAGE_FILE_NAME => Some(MAX_DA_BLOCK_REWRITE_STAGE_BYTES),
        EVICTION_COMPACTION_STAGE_FILE_NAME => Some(MAX_EVICTION_COMPACTION_STAGE_BYTES),
        _ => None,
    };
    if let Some(maximum) = fixed {
        return singleton(maximum, temporary);
    }
    if let Some((maximum, temporary)) = lane_geometry::resource_evidence_file_kind(name) {
        return singleton(maximum, temporary);
    }
    for (prefix, maximum) in [
        (".kura-eviction-stage-", MAX_EVICTION_COMPACTION_STAGE_BYTES),
        (".kura-da-rewrite-", MAX_DA_BLOCK_REWRITE_STAGE_BYTES),
    ] {
        if name.starts_with(prefix) && name.len() > prefix.len() {
            return singleton(maximum, true);
        }
    }
    for suffix in [".append.build.tmp", ".append.intent.tmp"] {
        if let Some(index_name) = name.strip_suffix(suffix) {
            if matches!(
                index_resource_kind(&path.with_file_name(index_name)),
                Some((_, IndexResourceFormat::SidecarV1, false))
            ) {
                return singleton(BOUND_PROGRESS_APPEND_INTENT_DECODE_MAX_BYTES as u64, true);
            }
            return Err(Missing::OwnerMismatch);
        }
    }
    if directory == Some("lane_artifacts") {
        return Err(Missing::OwnerMismatch);
    }
    if [
        COUNT_FILE_NAME,
        DA_BLOCK_REWRITE_STAGE_FILE_NAME,
        EVICTION_COMPACTION_STAGE_FILE_NAME,
        "canonical_association_stage.norito",
        "prune_intent.norito",
        "lane_geometry_journal.norito",
        ".lane-incarnation.norito",
    ]
    .iter()
    .any(|reserved| name.starts_with(reserved))
    {
        return Err(Missing::OwnerMismatch);
    }
    Ok(None)
}

#[cfg(test)]
mod evidence_resource_tests {
    use super::*;

    fn limits() -> EvidenceResourceLimits {
        EvidenceResourceLimits {
            fastpq_artifacts: iroha_config::parameters::defaults::kura::FASTPQ_ARTIFACT_POLICY,
        }
    }

    #[test]
    fn fastpq_reserved_names_and_empty_temporary_preserve_exact_configured_geometry() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let namespace = root.join(fastpq_artifact_store::DIRECTORY);
        std::fs::create_dir(&namespace).unwrap();
        let mut configured = limits();
        configured.fastpq_artifacts = iroha_config::parameters::actual::KuraFastpqArtifactPolicy {
            max_artifact_bytes: std::num::NonZeroUsize::new(8).unwrap(),
            max_artifacts: std::num::NonZeroUsize::new(1).unwrap(),
            max_total_bytes: std::num::NonZeroU64::new(8).unwrap(),
        };
        let temporary = namespace.join(fastpq_artifact_store::TEMPORARY);
        std::fs::write(&temporary, []).unwrap();
        let (format, is_temporary) = evidence_resource_kind(&temporary, configured)
            .unwrap()
            .unwrap();
        assert!(is_temporary);
        let empty = index_resource_file_usage(&temporary, format, is_temporary).unwrap();
        assert_eq!(empty.persisted_entries, 1);
        assert_eq!(empty.index_bytes, 0);
        assert_eq!(empty.temporary_index_bytes, 0);
        assert!(
            index_resource_file_usage(&temporary, format, false).is_err(),
            "emptyable format is restricted to a real temporary owner"
        );
        std::fs::write(&temporary, [1_u8; 8]).unwrap();
        assert_eq!(
            index_resource_file_usage(&temporary, format, true)
                .unwrap()
                .temporary_index_bytes,
            8
        );
        std::fs::write(&temporary, [1_u8; 9]).unwrap();
        assert!(index_resource_file_usage(&temporary, format, true).is_err());
        let hash = Kura::fixed_bytes_path_component(Hash::new(b"FASTPQ resource file").as_ref());
        let stable = namespace.join(format!("{hash}.norito"));
        std::fs::write(&stable, []).unwrap();
        let (stable_format, is_temporary) = evidence_resource_kind(&stable, configured)
            .unwrap()
            .unwrap();
        assert!(!is_temporary);
        assert!(
            index_resource_file_usage(&stable, stable_format, false).is_err(),
            "a stable artifact cannot be empty"
        );
        for name in [
            COUNT_FILE_NAME.to_owned(),
            format!("{hash}.norito.tmp"),
            format!("{}.norito", hash.to_uppercase()),
            "unowned.norito".to_owned(),
        ] {
            assert!(evidence_resource_kind(&namespace.join(name), configured).is_err());
        }
    }
}
