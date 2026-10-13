// Indexed-sidecar retention and crash-safe rewrite support.
impl Kura {
    fn prune_indexed_sidecars(
        data_path: &Path,
        index_path: &Path,
        retention: NonZeroUsize,
        kind: &str,
    ) -> bool {
        Self::prune_indexed_sidecars_with_pinned_height(
            data_path, index_path, retention, None, kind,
        )
    }
    fn prune_indexed_sidecars_with_pinned_height(
        data_path: &Path,
        index_path: &Path,
        retention: NonZeroUsize,
        pinned_height: Option<u64>,
        kind: &str,
    ) -> bool {
        Self::rewrite_indexed_sidecars(
            data_path,
            index_path,
            IndexedSidecarRewrite::Newest {
                retention,
                pinned_height,
            },
            kind,
        )
    }
    #[cfg(test)]
    fn prune_indexed_sidecars_to_retention_window(
        data_path: &Path,
        index_path: &Path,
        retention: NonZeroUsize,
        kind: &str,
    ) -> bool {
        if !data_path.exists() && !index_path.exists() {
            return true;
        }
        if !Self::recover_indexed_sidecar_artifacts(data_path, index_path, kind) {
            return false;
        }
        Self::rewrite_indexed_sidecars(
            data_path,
            index_path,
            IndexedSidecarRewrite::NewestWindow { retention },
            kind,
        )
    }
    #[cfg(test)]
    fn prune_indexed_sidecars_through_terminal_frontier_with_required_heights(
        data_path: &Path,
        index_path: &Path,
        terminal_height: u64,
        retention: NonZeroUsize,
        required_heights: &BTreeSet<u64>,
        kind: &str,
    ) -> bool {
        if !data_path.exists() && !index_path.exists() {
            return required_heights.is_empty();
        }
        if !Self::recover_indexed_sidecar_artifacts_with_required_heights(
            data_path,
            index_path,
            required_heights,
            kind,
        ) {
            return false;
        }
        Self::rewrite_indexed_sidecars(
            data_path,
            index_path,
            IndexedSidecarRewrite::AfterTerminalFrontier {
                terminal_height,
                retention,
                required_heights,
            },
            kind,
        )
    }
    #[cfg(test)]
    fn prune_indexed_sidecars_through_terminal_frontier(
        data_path: &Path,
        index_path: &Path,
        terminal_height: u64,
        retention: NonZeroUsize,
        kind: &str,
    ) -> bool {
        Self::prune_indexed_sidecars_through_terminal_frontier_with_required_heights(
            data_path,
            index_path,
            terminal_height,
            retention,
            &BTreeSet::new(),
            kind,
        )
    }
    #[allow(clippy::too_many_lines)] // Rewriting covers many edge cases in one pass; keep consolidated.
    fn rewrite_indexed_sidecars(
        data_path: &Path,
        index_path: &Path,
        rewrite: IndexedSidecarRewrite<'_>,
        kind: &str,
    ) -> bool {
        let mut index = match std::fs::File::open(index_path) {
            Ok(file) => file,
            Err(err) => {
                iroha_logger::warn!(?err, ?index_path, kind, "failed to open sidecar index");
                return false;
            }
        };
        let index_meta = match index.metadata() {
            Ok(meta) => meta,
            Err(err) => {
                iroha_logger::warn!(?err, ?index_path, kind, "failed to stat sidecar index");
                return false;
            }
        };
        let index_len = index_meta.len();
        let layout = match SidecarIndexLayout::read_from(&mut index, index_len) {
            Ok(layout) => layout,
            Err(reason) => {
                iroha_logger::warn!(
                    reason,
                    len = index_len,
                    ?index_path,
                    kind,
                    "refusing malformed sidecar index during prune"
                );
                return false;
            }
        };
        let strict_retained_rewrite =
            matches!(rewrite, IndexedSidecarRewrite::AfterTerminalFrontier { .. });
        if index_len != layout.aligned_len {
            iroha_logger::warn!(
                len = index_len,
                aligned_len = layout.aligned_len,
                ?index_path,
                kind,
                "sidecar index length misaligned; ignoring trailing bytes"
            );
            if strict_retained_rewrite {
                return false;
            }
        }
        let total_entries = layout.entry_count;
        let compacted_prefix_rewrite =
            matches!(rewrite, IndexedSidecarRewrite::AfterTerminalFrontier { .. });
        let (
            mut keep_from,
            mut source_start,
            mut output_entries,
            mut output_base_height,
            pinned_height,
            required_heights,
            operation,
            window_data_byte_limit,
        ) = match rewrite {
            IndexedSidecarRewrite::Newest {
                retention,
                pinned_height,
            } => {
                let retention_u64 = retention.get() as u64;
                if total_entries <= retention_u64 {
                    return true;
                }
                (
                    total_entries.saturating_sub(retention_u64),
                    0,
                    total_entries,
                    layout.base_height,
                    pinned_height,
                    None,
                    "retention prune",
                    None,
                )
            }
            #[cfg(test)]
            IndexedSidecarRewrite::NewestWindow { retention } => {
                let retention_u64 = retention.get() as u64;
                let source_start = total_entries.saturating_sub(retention_u64);
                let Some(output_base_height) = layout.base_height.checked_add(source_start) else {
                    iroha_logger::warn!(
                        base_height = layout.base_height,
                        source_start,
                        ?index_path,
                        kind,
                        "sidecar retention-window base height overflows"
                    );
                    return false;
                };
                (
                    source_start,
                    source_start,
                    retention_u64,
                    output_base_height,
                    None,
                    None,
                    "retention-window prune",
                    Some(256 * 1024 * 1024),
                )
            }
            IndexedSidecarRewrite::AfterTerminalFrontier {
                terminal_height,
                retention,
                required_heights,
            } => {
                let first_retained_height = terminal_height
                    .saturating_sub(retention.get() as u64)
                    .saturating_add(1);
                if required_heights.is_empty() && layout.base_height >= first_retained_height {
                    return true;
                }
                let output_base_target = required_heights
                    .first()
                    .copied()
                    .map_or(first_retained_height, |height| {
                        first_retained_height.min(height)
                    });
                let source_start = output_base_target
                    .saturating_sub(layout.base_height)
                    .min(total_entries);
                let Some(output_base_height) = layout.base_height.checked_add(source_start) else {
                    iroha_logger::warn!(
                        base_height = layout.base_height,
                        source_start,
                        ?index_path,
                        kind,
                        "terminal sidecar retention base height overflows"
                    );
                    return false;
                };
                (
                    first_retained_height
                        .saturating_sub(layout.base_height)
                        .min(total_entries),
                    source_start,
                    total_entries.saturating_sub(source_start),
                    output_base_height,
                    None,
                    Some(required_heights),
                    "terminal-frontier prune",
                    None,
                )
            }
        };
        let entries_to_read = if compacted_prefix_rewrite {
            output_entries
        } else {
            total_entries
        };
        let entries_capacity = match usize::try_from(entries_to_read) {
            Ok(capacity) => capacity,
            Err(err) => {
                iroha_logger::warn!(
                    ?err,
                    entries_to_read,
                    ?index_path,
                    kind,
                    "sidecar retained entry count exceeds usize during prune"
                );
                return false;
            }
        };
        let vector_base = if compacted_prefix_rewrite {
            source_start
        } else {
            0
        };
        let Some(entries_offset) = vector_base
            .checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64)
            .and_then(|offset| layout.entries_offset.checked_add(offset))
        else {
            iroha_logger::warn!(
                vector_base,
                ?index_path,
                kind,
                "sidecar retained index offset overflows during prune"
            );
            return false;
        };
        if let Err(err) = index.seek(SeekFrom::Start(entries_offset)) {
            iroha_logger::warn!(
                ?err,
                ?index_path,
                kind,
                "failed to seek to sidecar index entries during prune"
            );
            return false;
        }
        let mut entries = Vec::with_capacity(entries_capacity);
        let mut entry_buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
        for _ in 0..entries_to_read {
            if let Err(err) = index.read_exact(&mut entry_buf) {
                iroha_logger::warn!(?err, ?index_path, kind, "failed to read sidecar index");
                return false;
            }
            entries.push(SidecarIndexEntry::from_bytes(entry_buf));
        }
        if let Some(required_heights) = required_heights {
            for required_height in required_heights {
                let Some(relative) = required_height.checked_sub(layout.base_height) else {
                    iroha_logger::warn!(
                        required_height,
                        base_height = layout.base_height,
                        ?index_path,
                        kind,
                        "required terminal evidence predates the retained sidecar index"
                    );
                    return false;
                };
                if relative >= total_entries {
                    iroha_logger::warn!(
                        required_height,
                        base_height = layout.base_height,
                        total_entries,
                        ?index_path,
                        kind,
                        "required terminal evidence is outside the retained sidecar index"
                    );
                    return false;
                }
                let Some(vector_index) = relative
                    .checked_sub(vector_base)
                    .and_then(|index| usize::try_from(index).ok())
                else {
                    iroha_logger::warn!(
                        required_height,
                        vector_base,
                        ?index_path,
                        kind,
                        "required terminal evidence is outside the rewrite input window"
                    );
                    return false;
                };
                if entries.get(vector_index).is_none_or(|entry| entry.len == 0) {
                    iroha_logger::warn!(
                        required_height,
                        ?index_path,
                        kind,
                        "required terminal evidence has no indexed sidecar payload"
                    );
                    return false;
                }
            }
            if source_start == 0 && keep_from == 0 {
                return true;
            }
        }
        if let Some(byte_limit) = window_data_byte_limit {
            let Ok(count_start) = usize::try_from(source_start.saturating_sub(vector_base)) else {
                return false;
            };
            let mut byte_start = entries.len();
            let mut retained_bytes = 0_u64;
            for idx in (count_start..entries.len()).rev() {
                let Some(next_bytes) = retained_bytes.checked_add(entries[idx].len) else {
                    return false;
                };
                if next_bytes > byte_limit {
                    break;
                }
                retained_bytes = next_bytes;
                byte_start = idx;
            }
            if entries
                .get(byte_start..)
                .is_none_or(|retained| retained.iter().all(|entry| entry.len == 0))
                && entries
                    .get(count_start..)
                    .is_some_and(|window| window.iter().any(|entry| entry.len > 0))
            {
                iroha_logger::warn!(
                    byte_limit,
                    ?index_path,
                    kind,
                    "newest Native AMX evidence payload does not fit its aggregate retention budget"
                );
                return false;
            }
            let Ok(byte_start) = u64::try_from(byte_start) else {
                iroha_logger::warn!(
                    ?index_path,
                    kind,
                    "Native AMX evidence retention-window start exceeds u64"
                );
                return false;
            };
            source_start = vector_base.saturating_add(byte_start);
            keep_from = source_start;
            output_entries = total_entries.saturating_sub(source_start);
            let Some(window_base_height) = layout.base_height.checked_add(source_start) else {
                return false;
            };
            output_base_height = window_base_height;
            // The test-only retained-window mode deliberately materializes an
            // unchanged window too, so crash controls reach the real temporary
            // write and promotion barriers rather than an earlier no-op.
        }
        let mut data = match std::fs::File::open(data_path) {
            Ok(file) => file,
            Err(err) => {
                iroha_logger::warn!(?err, ?data_path, kind, "failed to open sidecar store");
                return false;
            }
        };
        let data_len = match data.metadata() {
            Ok(meta) => meta.len(),
            Err(err) => {
                iroha_logger::warn!(?err, ?data_path, kind, "failed to stat sidecar store");
                return false;
            }
        };
        if strict_retained_rewrite {
            let skip =
                usize::try_from(source_start.saturating_sub(vector_base)).unwrap_or(usize::MAX);
            let take = usize::try_from(output_entries).unwrap_or(usize::MAX);
            let mut prior_payload_end = None;
            for entry in entries.iter().skip(skip).take(take) {
                if entry.len == 0 {
                    continue;
                }
                if entry.len > STRICT_INIT_MAX_BLOCK_BYTES
                    || usize::try_from(entry.len).is_err()
                    || entry
                        .offset
                        .checked_add(entry.len)
                        .is_none_or(|end| end > data_len)
                {
                    iroha_logger::warn!(
                        offset = entry.offset,
                        len = entry.len,
                        data_len,
                        ?index_path,
                        kind,
                        "refusing terminal compaction with a malformed retained sidecar entry"
                    );
                    return false;
                }
                if prior_payload_end.is_some_and(|prior_end| entry.offset < prior_end) {
                    iroha_logger::warn!(
                        offset = entry.offset,
                        ?prior_payload_end,
                        ?index_path,
                        kind,
                        "refusing strict compaction with overlapping or out-of-order retained sidecar entries"
                    );
                    return false;
                }
                prior_payload_end = entry.offset.checked_add(entry.len);
            }
        }
        // Keep temp paths distinct: `.with_extension("tmp")` would collapse
        // `*.norito` and `*.index` into the same `*.tmp` filename.
        let temp_data_path = data_path.with_extension("norito.tmp");
        let temp_index_path = index_path.with_extension("index.tmp");
        let mut new_data = match std::fs::File::create(&temp_data_path) {
            Ok(file) => BufWriter::new(file),
            Err(err) => {
                iroha_logger::warn!(
                    ?err,
                    ?temp_data_path,
                    kind,
                    "failed to create temp sidecar store"
                );
                return false;
            }
        };
        let mut new_index = match std::fs::File::create(&temp_index_path) {
            Ok(file) => BufWriter::new(file),
            Err(err) => {
                iroha_logger::warn!(
                    ?err,
                    ?temp_index_path,
                    kind,
                    "failed to create temp sidecar index"
                );
                return false;
            }
        };
        if let Err(err) = new_index.write_all(&SidecarIndexLayout::base_header(output_base_height))
        {
            iroha_logger::warn!(
                ?err,
                ?temp_index_path,
                kind,
                "failed to persist sidecar base-height header during prune"
            );
            return false;
        }
        let mut new_offset = 0u64;
        let empty_entry = SidecarIndexEntry { offset: 0, len: 0 }.to_bytes();
        for (vector_idx, entry) in entries
            .iter()
            .enumerate()
            .skip(usize::try_from(source_start.saturating_sub(vector_base)).unwrap_or(usize::MAX))
            .take(usize::try_from(output_entries).unwrap_or(usize::MAX))
        {
            let absolute_idx =
                vector_base.saturating_add(u64::try_from(vector_idx).unwrap_or(u64::MAX));
            let entry_height = layout.base_height.saturating_add(absolute_idx);
            let retained_by_policy = absolute_idx >= keep_from
                || pinned_height.is_some_and(|height| height == entry_height)
                || required_heights.is_some_and(|heights| heights.contains(&entry_height));
            if !retained_by_policy || entry.len == 0 {
                if let Err(err) = new_index.write_all(&empty_entry) {
                    iroha_logger::warn!(
                        ?err,
                        ?temp_index_path,
                        kind,
                        "failed to write pruned sidecar index entry"
                    );
                    return false;
                }
                continue;
            }
            if entry.len > STRICT_INIT_MAX_BLOCK_BYTES {
                iroha_logger::warn!(
                    len = entry.len,
                    limit = STRICT_INIT_MAX_BLOCK_BYTES,
                    kind,
                    "sidecar payload length exceeds limit during prune; dropping entry"
                );
                if strict_retained_rewrite {
                    iroha_logger::warn!(
                        ?index_path,
                        kind,
                        "refusing terminal compaction that would drop a retained sidecar entry"
                    );
                    return false;
                }
                if let Err(err) = new_index.write_all(&empty_entry) {
                    iroha_logger::warn!(
                        ?err,
                        ?temp_index_path,
                        kind,
                        "failed to write pruned sidecar index entry"
                    );
                    return false;
                }
                continue;
            }
            let len = if let Ok(len) = usize::try_from(entry.len) {
                len
            } else {
                iroha_logger::warn!(
                    len = entry.len,
                    kind,
                    "sidecar payload length exceeds usize during prune; dropping entry"
                );
                if strict_retained_rewrite {
                    iroha_logger::warn!(
                        ?index_path,
                        kind,
                        "refusing terminal compaction that would drop a retained sidecar entry"
                    );
                    return false;
                }
                if let Err(err) = new_index.write_all(&empty_entry) {
                    iroha_logger::warn!(
                        ?err,
                        ?temp_index_path,
                        kind,
                        "failed to write pruned sidecar index entry"
                    );
                    return false;
                }
                continue;
            };
            let entry_end = if let Some(end) = entry.offset.checked_add(entry.len) {
                end
            } else {
                iroha_logger::warn!(
                    offset = entry.offset,
                    len = entry.len,
                    kind,
                    "sidecar payload range overflow during prune; dropping entry"
                );
                if strict_retained_rewrite {
                    iroha_logger::warn!(
                        ?index_path,
                        kind,
                        "refusing terminal compaction that would drop a retained sidecar entry"
                    );
                    return false;
                }
                if let Err(err) = new_index.write_all(&empty_entry) {
                    iroha_logger::warn!(
                        ?err,
                        ?temp_index_path,
                        kind,
                        "failed to write pruned sidecar index entry"
                    );
                    return false;
                }
                continue;
            };
            if entry_end > data_len {
                iroha_logger::warn!(
                    offset = entry.offset,
                    len = entry.len,
                    data_len,
                    kind,
                    "sidecar payload past data file during prune; dropping entry"
                );
                if strict_retained_rewrite {
                    iroha_logger::warn!(
                        ?index_path,
                        kind,
                        "refusing terminal compaction that would drop a retained sidecar entry"
                    );
                    return false;
                }
                if let Err(err) = new_index.write_all(&empty_entry) {
                    iroha_logger::warn!(
                        ?err,
                        ?temp_index_path,
                        kind,
                        "failed to write pruned sidecar index entry"
                    );
                    return false;
                }
                continue;
            }
            if let Err(err) = data.seek(SeekFrom::Start(entry.offset)) {
                iroha_logger::warn!(
                    ?err,
                    offset = entry.offset,
                    ?data_path,
                    kind,
                    "failed to seek to pruned sidecar payload"
                );
                return false;
            }
            let mut buf = vec![0u8; len];
            if let Err(err) = data.read_exact(&mut buf) {
                iroha_logger::warn!(
                    ?err,
                    offset = entry.offset,
                    len = entry.len,
                    ?data_path,
                    kind,
                    "failed to read pruned sidecar payload"
                );
                return false;
            }
            if let Err(err) = new_data.write_all(&buf) {
                iroha_logger::warn!(
                    ?err,
                    ?temp_data_path,
                    len = entry.len,
                    kind,
                    "failed to persist pruned sidecar payload"
                );
                return false;
            }
            let new_entry = SidecarIndexEntry {
                offset: new_offset,
                len: entry.len,
            };
            if let Err(err) = new_index.write_all(&new_entry.to_bytes()) {
                iroha_logger::warn!(
                    ?err,
                    ?temp_index_path,
                    kind,
                    "failed to persist pruned sidecar index entry"
                );
                return false;
            }
            new_offset = new_offset.saturating_add(entry.len);
        }
        if let Err(err) = new_data.flush() {
            iroha_logger::warn!(
                ?err,
                ?temp_data_path,
                kind,
                "failed to flush pruned sidecar store"
            );
            return false;
        }
        if let Err(err) = new_index.flush() {
            iroha_logger::warn!(
                ?err,
                ?temp_index_path,
                kind,
                "failed to flush pruned sidecar index"
            );
            return false;
        }
        if let Err(err) = new_data.get_ref().sync_data() {
            iroha_logger::warn!(
                ?err,
                ?temp_data_path,
                kind,
                "failed to sync pruned sidecar store"
            );
            return false;
        }
        if let Err(err) = new_index.get_ref().sync_data() {
            iroha_logger::warn!(
                ?err,
                ?temp_index_path,
                kind,
                "failed to sync pruned sidecar index"
            );
            return false;
        }
        drop(new_data);
        drop(new_index);
        drop(data);
        drop(index);
        // Make both temp directory entries durable before the first promotion. The temp index is
        // the recovery marker if the process crashes after publishing the new data file but before
        // publishing its matching index.
        let Some(data_parent) = temp_data_path.parent() else {
            iroha_logger::warn!(?temp_data_path, kind, "sidecar temp data has no parent");
            return false;
        };
        if let Err(err) = sync_sidecar_temp_marker_dir(data_parent) {
            iroha_logger::warn!(
                ?err,
                ?data_parent,
                kind,
                "failed to sync sidecar temp recovery marker before prune promotion"
            );
            return false;
        }
        if let Some(index_parent) = temp_index_path.parent()
            && index_parent != data_parent
            && let Err(err) = sync_sidecar_temp_marker_dir(index_parent)
        {
            iroha_logger::warn!(
                ?err,
                ?index_parent,
                kind,
                "failed to sync sidecar temp index recovery marker before prune promotion"
            );
            return false;
        }
        if let Err(err) = std::fs::rename(&temp_data_path, data_path) {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                if let Err(remove_err) = std::fs::remove_file(data_path) {
                    iroha_logger::warn!(
                        ?remove_err,
                        ?data_path,
                        kind,
                        "failed to remove sidecar store before pruned replace"
                    );
                    return false;
                }
                if let Err(rename_err) = std::fs::rename(&temp_data_path, data_path) {
                    iroha_logger::warn!(
                        ?rename_err,
                        ?temp_data_path,
                        ?data_path,
                        kind,
                        "failed to replace sidecar store after removal"
                    );
                    return false;
                }
            } else {
                iroha_logger::warn!(
                    ?err,
                    ?temp_data_path,
                    ?data_path,
                    kind,
                    "failed to replace sidecar store with pruned data"
                );
                let _ = std::fs::remove_file(&temp_data_path);
                let _ = std::fs::remove_file(&temp_index_path);
                return false;
            }
        }
        // The data rename must be stable before the index rename can become visible. This barrier
        // rules out a recovered state with a new index pointing into the old data file.
        if let Err(err) = sync_sidecar_promotion_dir(data_parent) {
            iroha_logger::warn!(
                ?err,
                ?data_parent,
                kind,
                "failed to sync pruned sidecar data before index promotion"
            );
            return false;
        }
        if let Err(err) = std::fs::rename(&temp_index_path, index_path) {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                if let Err(remove_err) = std::fs::remove_file(index_path) {
                    iroha_logger::warn!(
                        ?remove_err,
                        ?index_path,
                        kind,
                        "failed to remove sidecar index before pruned replace"
                    );
                    return false;
                }
                if let Err(rename_err) = std::fs::rename(&temp_index_path, index_path) {
                    iroha_logger::warn!(
                        ?rename_err,
                        ?temp_index_path,
                        ?index_path,
                        kind,
                        "failed to replace sidecar index after removal"
                    );
                    iroha_logger::warn!(
                        ?temp_index_path,
                        kind,
                        "leaving temp index for sidecar recovery"
                    );
                    return false;
                }
            } else {
                iroha_logger::warn!(
                    ?err,
                    ?temp_index_path,
                    ?index_path,
                    kind,
                    "failed to replace sidecar index with pruned entries"
                );
                let _ = std::fs::remove_file(&temp_data_path);
                iroha_logger::warn!(
                    ?temp_index_path,
                    kind,
                    "leaving temp index for sidecar recovery"
                );
                return false;
            }
        }
        if let Some(parent) = data_path.parent() {
            if let Err(err) = sync_dir(parent) {
                iroha_logger::warn!(
                    ?err,
                    ?parent,
                    kind,
                    "failed to sync sidecar parent directory after prune"
                );
                return false;
            }
        }
        if let Some(parent) = index_path.parent() {
            if let Err(err) = sync_dir(parent) {
                iroha_logger::warn!(
                    ?err,
                    ?parent,
                    kind,
                    "failed to sync sidecar parent directory after prune"
                );
                return false;
            }
        }
        let retained = match rewrite {
            #[cfg(test)]
            IndexedSidecarRewrite::NewestWindow { .. } => output_entries,
            IndexedSidecarRewrite::Newest { .. } => output_entries
                .saturating_sub(keep_from)
                .saturating_add(u64::from(pinned_height.is_some_and(|height| {
                    height
                        .checked_sub(layout.base_height)
                        .is_some_and(|relative| relative < output_entries && relative < keep_from)
                }))),
            IndexedSidecarRewrite::AfterTerminalFrontier { .. } => {
                let output_end = source_start.saturating_add(output_entries);
                output_end
                    .saturating_sub(keep_from.max(source_start))
                    .saturating_add(required_heights.map_or(0, |heights| {
                        u64::try_from(
                            heights
                                .iter()
                                .filter(|height| {
                                    height
                                        .checked_sub(layout.base_height)
                                        .is_some_and(|relative| {
                                            relative >= source_start
                                                && relative < keep_from
                                                && relative
                                                    < source_start.saturating_add(output_entries)
                                        })
                                })
                                .count(),
                        )
                        .unwrap_or(u64::MAX)
                    }))
            }
        };
        let pruned = total_entries.saturating_sub(retained);
        iroha_logger::debug!(
            kind,
            operation,
            total_entries,
            retained,
            pruned,
            "rewrote indexed sidecars"
        );
        true
    }
}
