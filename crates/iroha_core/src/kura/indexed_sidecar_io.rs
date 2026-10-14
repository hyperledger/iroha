// Pipeline recovery metadata and strict indexed-sidecar persistence primitives.
impl Kura {
    /// Enqueue pipeline recovery metadata for asynchronous persistence.
    ///
    /// This avoids consensus-path I/O; the Kura writer thread flushes the queue.
    /// If the queue is full, the sidecar is rejected because pipeline recovery
    /// metadata is best-effort diagnostic state. An active or interrupted canonical
    /// prune also rejects immediately without waiting for disk mutation locks.
    pub fn enqueue_pipeline_metadata(
        &self,
        sidecar: PipelineRecoverySidecar,
    ) -> PipelineSidecarEnqueueResult {
        if self.emergency_fast_startup_enabled() {
            return PipelineSidecarEnqueueResult::RejectedEmergencyFast;
        }
        if self.durable_mutation_authorized().is_err() {
            return PipelineSidecarEnqueueResult::RejectedUnauthorized;
        }
        if self.prune_blocks_sidecar_enqueue() {
            return PipelineSidecarEnqueueResult::RejectedPruneRecovery;
        }
        let cap = self
            .pipeline_sidecar_queue_cap
            .load(Ordering::Relaxed)
            .max(1);
        let (should_notify, queue_depth) = {
            let mut queue = self.pipeline_sidecar_queue.lock();
            if self.prune_blocks_sidecar_enqueue() {
                return PipelineSidecarEnqueueResult::RejectedPruneRecovery;
            }
            if queue.len() >= cap {
                return PipelineSidecarEnqueueResult::RejectedQueueFull { cap };
            }
            let should_notify = queue.is_empty();
            queue.push_back(sidecar);
            (should_notify, queue.len())
        };
        if should_notify {
            self.notify_block_writer(BlockNotify::NewBlock, "pipeline sidecar");
        }
        PipelineSidecarEnqueueResult::Enqueued { queue_depth }
    }
    fn flush_pipeline_sidecars(&self) -> usize {
        if let Err(error) = self.durable_mutation_authorized() {
            iroha_logger::warn!(
                ?error,
                "refusing queued pipeline sidecar mutation while Kura output is unauthorized"
            );
            return 0;
        }
        let sidecars = {
            let mut queue = self.pipeline_sidecar_queue.lock();
            if queue.is_empty() {
                return 0;
            }
            queue.drain(..).collect::<Vec<_>>()
        };
        let count = sidecars.len();
        for sidecar in sidecars {
            self.write_pipeline_metadata_unlocked(&sidecar);
        }
        count
    }
    /// Enqueue a FASTPQ proof attachment for asynchronous persistence in the block sidecar.
    ///
    /// An active or interrupted canonical prune rejects immediately without waiting for disk
    /// mutation locks.
    pub fn enqueue_fastpq_proof_snapshot(
        &self,
        snapshot: FastpqProofSnapshot,
    ) -> FastpqProofEnqueueResult {
        self.enqueue_fastpq_proof_snapshot_unless(snapshot, || false)
    }
    /// Enqueue a FASTPQ proof attachment unless `cancelled` observes shutdown.
    ///
    /// Both admission checks run while holding the proof queue lock. If shutdown
    /// becomes visible after insertion, the just-inserted tail is removed before
    /// the lock is released or the block writer is notified. The predicate must
    /// therefore remain non-blocking and must not call back into Kura.
    pub(crate) fn enqueue_fastpq_proof_snapshot_unless(
        &self,
        snapshot: FastpqProofSnapshot,
        mut cancelled: impl FnMut() -> bool,
    ) -> FastpqProofEnqueueResult {
        if self.emergency_fast_startup_enabled() {
            return FastpqProofEnqueueResult::RejectedEmergencyFast;
        }
        if self.durable_mutation_authorized().is_err() {
            return FastpqProofEnqueueResult::RejectedUnauthorized;
        }
        if self.prune_blocks_sidecar_enqueue() {
            return FastpqProofEnqueueResult::RejectedPruneRecovery;
        }
        let telemetry = FastpqProofSidecarTelemetry;
        let max_bytes = self
            .fastpq_proof_sidecar_max_bytes
            .load(Ordering::Relaxed)
            .max(1);
        let actual = match norito::encode_canonical(&snapshot) {
            Ok(bytes) => bytes.len(),
            Err(err) => {
                telemetry.record_event("rejected_encode");
                iroha_logger::warn!(
                    ?err,
                    "failed to encode FASTPQ proof snapshot before enqueue"
                );
                return FastpqProofEnqueueResult::RejectedEncode {
                    reason: format!("{err:?}"),
                };
            }
        };
        if actual > max_bytes {
            telemetry.record_event("rejected_too_large");
            return FastpqProofEnqueueResult::RejectedTooLarge {
                actual,
                max: max_bytes,
            };
        }
        let cap = self
            .fastpq_proof_sidecar_queue_cap
            .load(Ordering::Relaxed)
            .max(1);
        let (queue_depth, should_notify) = {
            let mut queue = self.fastpq_proof_queue.lock();
            if self.prune_blocks_sidecar_enqueue() {
                return FastpqProofEnqueueResult::RejectedPruneRecovery;
            }
            if queue.len() >= cap {
                telemetry.record_event("rejected_queue_full");
                telemetry.set_queue_depth(queue.len());
                return FastpqProofEnqueueResult::RejectedQueueFull { cap };
            }
            if cancelled() {
                telemetry.record_event("rejected_shutdown");
                telemetry.set_queue_depth(queue.len());
                return FastpqProofEnqueueResult::RejectedShutdown;
            }
            let should_notify = queue.is_empty();
            queue.push_back(QueuedFastpqProofSnapshot {
                snapshot,
                retries: 0,
            });
            if cancelled() {
                let removed = queue.pop_back();
                debug_assert!(
                    removed.is_some(),
                    "inserted FASTPQ proof snapshot disappeared"
                );
                telemetry.record_event("rejected_shutdown");
                telemetry.set_queue_depth(queue.len());
                return FastpqProofEnqueueResult::RejectedShutdown;
            }
            (queue.len(), should_notify)
        };
        telemetry.record_event("enqueued");
        telemetry.set_queue_depth(queue_depth);
        if should_notify {
            self.notify_block_writer(BlockNotify::NewBlock, "FASTPQ proof sidecar");
        }
        FastpqProofEnqueueResult::Enqueued { queue_depth }
    }
    fn flush_fastpq_proof_snapshots(&self) -> usize {
        let telemetry = FastpqProofSidecarTelemetry;
        if let Err(error) = self.durable_mutation_authorized() {
            iroha_logger::warn!(
                ?error,
                "refusing queued FASTPQ sidecar mutation while Kura output is unauthorized"
            );
            telemetry.set_queue_depth(self.fastpq_proof_queue.lock().len());
            return 0;
        }
        let snapshots = {
            let mut queue = self.fastpq_proof_queue.lock();
            if queue.is_empty() {
                telemetry.set_queue_depth(0);
                return 0;
            }
            queue.drain(..).collect::<Vec<_>>()
        };
        let mut groups: Vec<Vec<QueuedFastpqProofSnapshot>> = Vec::new();
        for snapshot in snapshots {
            if let Some(group) = groups.iter_mut().find(|group| {
                group.first().is_some_and(|queued| {
                    queued.snapshot.height == snapshot.snapshot.height
                        && queued.snapshot.block_hash == snapshot.snapshot.block_hash
                })
            }) {
                group.push(snapshot);
            } else {
                groups.push(vec![snapshot]);
            }
        }
        let mut written = 0usize;
        let mut retry = VecDeque::new();
        let max_retries = self
            .fastpq_proof_sidecar_max_retries
            .load(Ordering::Relaxed)
            .max(1);
        for group in groups {
            let snapshots = group
                .iter()
                .map(|queued| &queued.snapshot)
                .collect::<Vec<_>>();
            match self.write_fastpq_proof_snapshots(&snapshots) {
                FastpqProofWriteResult::Written => {
                    telemetry.record_event("written");
                    written = written.saturating_add(group.len());
                }
                FastpqProofWriteResult::Retry => {
                    for mut queued in group {
                        let next_retries = queued.retries.saturating_add(1);
                        if next_retries >= max_retries {
                            telemetry.record_event("dropped");
                            iroha_logger::warn!(
                                height = queued.snapshot.height,
                                retries = next_retries,
                                max_retries,
                                "dropping FASTPQ proof snapshot after retry limit"
                            );
                        } else {
                            queued.retries = next_retries;
                            retry.push_back(queued);
                        }
                    }
                }
                FastpqProofWriteResult::Drop => {
                    for _ in group {
                        telemetry.record_event("dropped");
                    }
                }
            }
        }
        let cap = self
            .fastpq_proof_sidecar_queue_cap
            .load(Ordering::Relaxed)
            .max(1);
        let (queue_depth, requeued, dropped_for_capacity) = {
            let mut queue = self.fastpq_proof_queue.lock();
            let requeued = retry.len().min(cap.saturating_sub(queue.len()));
            queue.extend(retry.drain(..requeued));
            let dropped_for_capacity = retry.len();
            if dropped_for_capacity != 0 {
                retry.clear();
            }
            (queue.len(), requeued, dropped_for_capacity)
        };
        for _ in 0..requeued {
            telemetry.record_event("retried");
        }
        for _ in 0..dropped_for_capacity {
            telemetry.record_event("dropped");
        }
        if dropped_for_capacity != 0 {
            iroha_logger::warn!(
                dropped = dropped_for_capacity,
                cap,
                queue_depth,
                "dropping FASTPQ proof retries because concurrent enqueues filled the queue"
            );
        }
        telemetry.set_queue_depth(queue_depth);
        written
    }
    /// Write per-block pipeline recovery metadata sidecar under the store dir. Best-effort: errors
    /// are logged and ignored.
    pub fn write_pipeline_metadata(&self, sidecar: &PipelineRecoverySidecar) {
        let _prune_guard = self.prune_lock.lock();
        #[cfg(test)]
        original_queued_sidecar_release_tests::fence_boundary(1);
        if self.prune_recovery_is_required() {
            warn!(
                height = sidecar.height,
                "refusing pipeline sidecar write until prune recovery completes after restart"
            );
            return;
        }
        if let Err(error) = self.durable_mutation_authorized() {
            iroha_logger::warn!(
                ?error,
                height = sidecar.height,
                "refusing pipeline sidecar mutation while Kura output is unauthorized"
            );
            return;
        }
        self.write_pipeline_metadata_unlocked(sidecar);
    }
    fn write_pipeline_metadata_unlocked(&self, sidecar: &PipelineRecoverySidecar) {
        if let Some(mut dir) = self.store_dir() {
            let _guard = self.sidecar_lock.lock();
            #[cfg(test)]
            original_queued_sidecar_release_tests::fence_boundary(2);
            dir.push(PIPELINE_DIR_NAME);
            if let Err(e) = std::fs::create_dir_all(&dir) {
                iroha_logger::warn!(?e, ?dir, "failed to create pipeline dir");
                return;
            }
            let data_path = dir.join(PIPELINE_SIDECARS_DATA_FILE);
            let index_path = dir.join(PIPELINE_SIDECARS_INDEX_FILE);
            let before_bytes = match Self::sidecar_tracked_bytes(&data_path, &index_path) {
                Ok(bytes) => Some(bytes),
                Err(err) => {
                    iroha_logger::warn!(
                        ?err,
                        ?dir,
                        "failed to measure pipeline sidecar bytes before write"
                    );
                    None
                }
            };
            let fsync_mode = self.sidecar_fsync_mode();
            let accounting_mutation = self.begin_total_disk_usage_mutation().with_resource_paths(
                Self::sidecar_physical_resource_paths(&data_path, &index_path),
            );
            let wrote = match sidecar.encode_framed() {
                Ok(buf) => Self::append_indexed_sidecar(
                    &data_path,
                    &index_path,
                    sidecar.height,
                    &buf,
                    "pipeline sidecar",
                    fsync_mode,
                    None,
                ),
                Err(err) => {
                    iroha_logger::warn!(
                        ?err,
                        height = sidecar.height,
                        "failed to encode pipeline metadata"
                    );
                    false
                }
            };
            if !wrote {
                self.resource_inventory.invalidate(
                    physical_resource_mask(),
                    resource_inventory::Unavailable::Interrupted,
                );
            }
            let mut accounting_complete = before_bytes.is_some();
            if let Some(before_bytes) = before_bytes {
                match Self::sidecar_tracked_bytes(&data_path, &index_path) {
                    Ok(after_bytes) => self.update_disk_usage_delta(before_bytes, after_bytes),
                    Err(err) => {
                        accounting_complete = false;
                        iroha_logger::warn!(
                            ?err,
                            ?dir,
                            "failed to measure pipeline sidecar bytes after write"
                        );
                    }
                }
            }
            if accounting_complete {
                accounting_mutation.finish();
            }
        }
    }
    fn write_fastpq_proof_snapshots(
        &self,
        snapshots: &[&FastpqProofSnapshot],
    ) -> FastpqProofWriteResult {
        if let Err(error) = self.durable_mutation_authorized() {
            iroha_logger::warn!(
                ?error,
                "refusing FASTPQ proof sidecar mutation while Kura output is unauthorized"
            );
            return FastpqProofWriteResult::Drop;
        }
        let Some(first_snapshot) = snapshots.first().copied() else {
            return FastpqProofWriteResult::Written;
        };
        let height = first_snapshot.height;
        let block_hash = first_snapshot.block_hash;
        if height == 0 {
            iroha_logger::warn!("refusing to store FASTPQ proof snapshot for zero height");
            return FastpqProofWriteResult::Drop;
        }
        let Some(mut dir) = self.store_dir() else {
            iroha_logger::warn!("FASTPQ proof snapshot has no Kura store directory");
            return FastpqProofWriteResult::Drop;
        };
        let _guard = self.sidecar_lock.lock();
        #[cfg(test)]
        original_queued_sidecar_release_tests::fence_boundary(3);
        dir.push(PIPELINE_DIR_NAME);
        if let Err(err) = std::fs::create_dir_all(&dir) {
            iroha_logger::warn!(?err, ?dir, "failed to create pipeline dir for FASTPQ proof");
            return FastpqProofWriteResult::Retry;
        }
        let data_path = dir.join(PIPELINE_SIDECARS_DATA_FILE);
        let index_path = dir.join(PIPELINE_SIDECARS_INDEX_FILE);
        let Some(mut sidecar) = self.read_pipeline_sidecar(
            height,
            PIPELINE_SIDECARS_DATA_FILE,
            PIPELINE_SIDECARS_INDEX_FILE,
            norito::decode_canonical::<PipelineRecoverySidecar>,
            "pipeline sidecar",
        ) else {
            iroha_logger::debug!(
                height,
                "pipeline sidecar not ready for FASTPQ proof attachment"
            );
            return FastpqProofWriteResult::Retry;
        };
        if sidecar.block_hash != block_hash {
            iroha_logger::warn!(
                height,
                expected = %sidecar.block_hash,
                actual = %block_hash,
                "dropping FASTPQ proof snapshot for mismatched block hash"
            );
            return FastpqProofWriteResult::Drop;
        }
        let mut added = 0usize;
        for snapshot in snapshots {
            if snapshot.height != height || snapshot.block_hash != block_hash {
                iroha_logger::warn!(
                    height = snapshot.height,
                    expected_height = height,
                    expected_hash = %block_hash,
                    actual_hash = %snapshot.block_hash,
                    "dropping FASTPQ proof snapshot grouped with a different block"
                );
                continue;
            }
            if sidecar
                .fastpq_proofs
                .iter()
                .any(|existing| existing.same_attachment(snapshot))
            {
                continue;
            }
            sidecar.fastpq_proofs.push((*snapshot).clone());
            added = added.saturating_add(1);
        }
        if added == 0 {
            return FastpqProofWriteResult::Written;
        }
        let accounting_mutation = self.begin_total_disk_usage_mutation().with_resource_paths(
            Self::sidecar_physical_resource_paths(&data_path, &index_path),
        );
        let before_bytes = match Self::sidecar_tracked_bytes(&data_path, &index_path) {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                iroha_logger::warn!(
                    ?err,
                    ?dir,
                    "failed to measure pipeline sidecar bytes before FASTPQ proof write"
                );
                None
            }
        };
        let payload = match sidecar.encode_framed() {
            Ok(payload) => payload,
            Err(err) => {
                iroha_logger::warn!(?err, height, "failed to encode FASTPQ proof sidecar update");
                return FastpqProofWriteResult::Retry;
            }
        };
        let wrote = Self::append_indexed_sidecar(
            &data_path,
            &index_path,
            height,
            &payload,
            "pipeline sidecar",
            self.sidecar_fsync_mode(),
            None,
        );
        if wrote {
            let mut accounting_complete = before_bytes.is_some();
            if let Some(before_bytes) = before_bytes {
                match Self::sidecar_tracked_bytes(&data_path, &index_path) {
                    Ok(after_bytes) => self.update_disk_usage_delta(before_bytes, after_bytes),
                    Err(err) => {
                        accounting_complete = false;
                        iroha_logger::warn!(
                            ?err,
                            ?dir,
                            "failed to measure pipeline sidecar bytes after FASTPQ proof write"
                        );
                    }
                }
            }
            if accounting_complete {
                accounting_mutation.finish();
            }
            FastpqProofWriteResult::Written
        } else {
            FastpqProofWriteResult::Retry
        }
    }
    /// Decode pipeline recovery metadata without assigning it canonical block authority.
    ///
    /// Callers must validate the returned sidecar against either Kura's canonical block hash or
    /// an explicit candidate block hash before using it. Keeping this helper private prevents an
    /// identity-unchecked sidecar from escaping the storage boundary.
    fn read_pipeline_metadata_payload(&self, height: u64) -> Option<PipelineRecoverySidecar> {
        if self.prune_recovery_is_required() {
            return None;
        }
        let sidecar = {
            let _guard = self.sidecar_lock.lock();
            if self.prune_recovery_is_required() {
                return None;
            }
            self.read_pipeline_sidecar(
                height,
                PIPELINE_SIDECARS_DATA_FILE,
                PIPELINE_SIDECARS_INDEX_FILE,
                norito::decode_canonical::<PipelineRecoverySidecar>,
                "pipeline sidecar",
            )
        }?;
        if sidecar.height != height {
            iroha_logger::warn!(
                height,
                sidecar_height = sidecar.height,
                "pipeline sidecar height mismatch"
            );
            return None;
        }
        Some(sidecar)
    }
    /// Read per-block pipeline recovery metadata if present. Returns `None` on errors.
    ///
    /// This canonical reader exposes a sidecar only when its block hash agrees with Kura's
    /// canonical or durable block identity for `height`.
    pub fn read_pipeline_metadata(&self, height: u64) -> Option<PipelineRecoverySidecar> {
        let sidecar = self.read_pipeline_metadata_payload(height)?;
        let expected = usize::try_from(height)
            .ok()
            .and_then(NonZeroUsize::new)
            .and_then(|height| {
                self.get_block_hash(height)
                    .or_else(|| self.get_durable_block_hash(height))
            });
        if expected != Some(sidecar.block_hash) {
            iroha_logger::warn!(
                height,
                expected = ?expected,
                actual = %sidecar.block_hash,
                "pipeline sidecar block hash mismatch"
            );
            return None;
        }
        if self.prune_recovery_is_required() {
            return None;
        }
        Some(sidecar)
    }
    /// Read pipeline recovery metadata for an explicitly identified candidate block.
    ///
    /// This is an execution-cache boundary, not a source of canonical block authority. It permits
    /// a speculative executor to reuse metadata that it previously persisted for the same exact
    /// block while rejecting metadata from a competing candidate at the same height.
    #[cfg(test)]
    pub(crate) fn read_pipeline_metadata_for_block(
        &self,
        height: u64,
        expected_block_hash: HashOf<BlockHeader>,
    ) -> Option<PipelineRecoverySidecar> {
        let sidecar = self.read_pipeline_metadata_payload(height)?;
        if sidecar.block_hash != expected_block_hash {
            iroha_logger::debug!(
                height,
                expected = %expected_block_hash,
                actual = %sidecar.block_hash,
                "pipeline sidecar candidate block hash mismatch"
            );
            return None;
        }
        if self.prune_recovery_is_required() {
            return None;
        }
        Some(sidecar)
    }
    /// Read persisted FASTPQ proof snapshots for a committed block.
    #[must_use]
    pub fn fastpq_proofs_for_block(&self, height: u64) -> Vec<FastpqProofSnapshot> {
        self.read_pipeline_metadata(height)
            .map(|sidecar| sidecar.fastpq_proofs)
            .unwrap_or_default()
    }
    fn bound_progress_index_layout_classified(
        index: &mut std::fs::File,
        index_len: u64,
    ) -> std::result::Result<SidecarIndexLayout, BoundProgressRecoveryFailure> {
        SidecarIndexLayout::read_from(index, index_len)
            .map_err(|_| BoundProgressRecoveryFailure::InvalidData)
    }
    fn bound_sidecar_index_snapshot(
        index: &mut std::fs::File,
        index_path: &Path,
        data_len: u64,
        kind: &str,
        label: &str,
    ) -> Option<BoundSidecarIndexSnapshot> {
        Self::bound_sidecar_index_snapshot_classified(index, index_path, data_len, kind, label).ok()
    }
    fn bound_sidecar_index_snapshot_classified(
        index: &mut std::fs::File,
        index_path: &Path,
        data_len: u64,
        kind: &str,
        label: &str,
    ) -> std::result::Result<BoundSidecarIndexSnapshot, BoundProgressRecoveryFailure> {
        let index_len = index
            .metadata()
            .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?
            .len();
        let layout = match Self::bound_progress_index_layout_classified(index, index_len) {
            Ok(layout) => layout,
            Err(failure) => {
                warn!(
                    ?failure,
                    len = index_len,
                    ?index_path,
                    kind,
                    label,
                    "failed to classify bound sidecar index layout"
                );
                return Err(failure);
            }
        };
        if layout.aligned_len != index_len {
            warn!(
                len = index_len,
                aligned_len = layout.aligned_len,
                ?index_path,
                kind,
                label,
                "bound sidecar index length is misaligned"
            );
            return Err(BoundProgressRecoveryFailure::InvalidData);
        }
        let capacity = usize::try_from(layout.entry_count)
            .map_err(|_| BoundProgressRecoveryFailure::InvalidData)?;
        index
            .seek(SeekFrom::Start(layout.entries_offset))
            .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?;
        let mut entries = Vec::new();
        if entries.try_reserve_exact(capacity).is_err() {
            warn!(
                entry_count = layout.entry_count,
                ?index_path,
                kind,
                label,
                "bound sidecar recovery index exceeds available memory"
            );
            return Err(BoundProgressRecoveryFailure::RetryableIo);
        }
        let mut ranges = Vec::new();
        if ranges.try_reserve_exact(capacity.min(4_096)).is_err() {
            return Err(BoundProgressRecoveryFailure::RetryableIo);
        }
        let mut indexed_end = 0_u64;
        let mut encoded = [0_u8; PIPELINE_INDEX_ENTRY_SIZE];
        for _ in 0..layout.entry_count {
            index
                .read_exact(&mut encoded)
                .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?;
            let entry = SidecarIndexEntry::from_bytes(encoded);
            if entry.len == 0 {
                if entry.offset != 0 {
                    warn!(
                        offset = entry.offset,
                        ?index_path,
                        kind,
                        label,
                        "zero-length bound sidecar index entry has a non-zero offset"
                    );
                    return Err(BoundProgressRecoveryFailure::InvalidData);
                }
            } else {
                let Some(end) = entry.offset.checked_add(entry.len) else {
                    warn!(
                        offset = entry.offset,
                        len = entry.len,
                        ?index_path,
                        kind,
                        label,
                        "bound sidecar index entry overflows"
                    );
                    return Err(BoundProgressRecoveryFailure::InvalidData);
                };
                if entry.len > STRICT_INIT_MAX_BLOCK_BYTES || end > data_len {
                    warn!(
                        offset = entry.offset,
                        len = entry.len,
                        data_len,
                        ?index_path,
                        kind,
                        label,
                        "bound sidecar index entry has an invalid payload range"
                    );
                    return Err(BoundProgressRecoveryFailure::InvalidData);
                }
                indexed_end = indexed_end.max(end);
                if ranges.try_reserve(1).is_err() {
                    return Err(BoundProgressRecoveryFailure::RetryableIo);
                }
                ranges.push((entry.offset, end));
            }
            entries.push(entry);
        }
        ranges.sort_unstable_by_key(|&(start, end)| (start, end));
        if ranges.windows(2).any(|pair| pair[1].0 < pair[0].1) {
            warn!(
                ?index_path,
                kind, label, "bound sidecar recovery index contains overlapping payload ranges"
            );
            return Err(BoundProgressRecoveryFailure::InvalidData);
        }
        Ok(BoundSidecarIndexSnapshot {
            layout,
            entries,
            indexed_end,
        })
    }
    fn decode_bound_progress_append_intent(
        intent_file: &mut std::fs::File,
        intent_path: &Path,
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        kind: &str,
    ) -> std::result::Result<BoundProgressAppendIntentV1, BoundProgressRecoveryFailure> {
        let intent_len = match intent_file.metadata() {
            Ok(metadata) => usize::try_from(metadata.len())
                .map_err(|_| BoundProgressRecoveryFailure::InvalidData)?,
            Err(error) => {
                warn!(
                    ?error,
                    ?intent_path,
                    kind,
                    "failed to stat progress append intent"
                );
                return Err(BoundProgressRecoveryFailure::from_io(&error));
            }
        };
        if intent_len == 0 || intent_len > BOUND_PROGRESS_APPEND_INTENT_DECODE_MAX_BYTES {
            warn!(
                intent_len,
                ?intent_path,
                kind,
                "progress append intent has an invalid byte length"
            );
            return Err(BoundProgressRecoveryFailure::InvalidData);
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(intent_len).is_err() {
            warn!(
                intent_len,
                ?intent_path,
                kind,
                "failed to reserve progress append-intent bytes"
            );
            return Err(BoundProgressRecoveryFailure::RetryableIo);
        }
        bytes.resize(intent_len, 0);
        if let Err(error) = intent_file
            .seek(SeekFrom::Start(0))
            .and_then(|_| intent_file.read_exact(&mut bytes))
        {
            warn!(
                ?error,
                ?intent_path,
                kind,
                "failed to read progress append intent"
            );
            return Err(BoundProgressRecoveryFailure::from_io(&error));
        }
        // The schema retains two byte windows and shallow namespace strings;
        // do not inherit a generic 64x allocation multiplier for the larger
        // prepend frame. Both windows are bounded before their later hashing.
        let limits = norito::DecodeLimits::new(
            BOUND_PROGRESS_PREPEND_INDEX_MAX_BYTES,
            BOUND_PROGRESS_APPEND_INTENT_DECODE_MAX_BYTES,
            BOUND_PROGRESS_APPEND_INTENT_DECODE_MAX_BYTES,
            4 * BOUND_PROGRESS_APPEND_INTENT_DECODE_MAX_BYTES,
            RECOVERY_CONTROL_DECODE_DEPTH_V1,
        );
        let intent = match norito::decode_canonical_with_limits::<BoundProgressAppendIntentV1>(
            &bytes, limits,
        ) {
            Ok(intent) => intent,
            Err(error) => {
                warn!(
                    ?error,
                    ?intent_path,
                    kind,
                    "failed to decode progress append intent"
                );
                return Err(BoundProgressRecoveryFailure::InvalidData);
            }
        };
        if intent_len > intent.encoded_byte_limit() {
            return Err(BoundProgressRecoveryFailure::InvalidData);
        }
        if let Err(reason) = intent.validate_for(namespace, data_path, index_path) {
            warn!(
                reason,
                ?intent_path,
                kind,
                "progress append intent is invalid"
            );
            return Err(BoundProgressRecoveryFailure::InvalidData);
        }
        Ok(intent)
    }
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn recover_bound_progress_append_intent(
        &self,
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        build_path: &Path,
        build: Option<std::fs::File>,
        intent_path: &Path,
        mut intent_file: std::fs::File,
        kind: &str,
    ) -> bool {
        let Ok(intent) = Self::decode_bound_progress_append_intent(
            &mut intent_file,
            intent_path,
            namespace,
            data_path,
            index_path,
            kind,
        ) else {
            return false;
        };
        let accounting = self
            .begin_total_disk_usage_mutation()
            .with_resource_paths(Self::sidecar_physical_resource_paths(data_path, index_path));
        if let Some(build) = build {
            drop(build);
            if let Err(error) = Self::remove_bound_progress_temp_if_present(namespace, build_path) {
                warn!(
                    ?error,
                    ?build_path,
                    kind,
                    "failed to discard superseded append-intent build"
                );
                return false;
            }
            if let Err(error) = Self::sync_bound_progress_intent_directories(namespace) {
                warn!(
                    ?error,
                    ?build_path,
                    kind,
                    "failed to sync append-intent build cleanup"
                );
                return false;
            }
        }
        let mut data = match self.open_optional_bound_progress_file(namespace, data_path) {
            Ok(data) => data,
            Err(error) => {
                warn!(
                    ?error,
                    ?data_path,
                    kind,
                    "failed to bind progress data during append recovery"
                );
                return false;
            }
        };
        let mut index = match self.open_optional_bound_progress_file(namespace, index_path) {
            Ok(index) => index,
            Err(error) => {
                warn!(
                    ?error,
                    ?index_path,
                    kind,
                    "failed to bind progress index during append recovery"
                );
                return false;
            }
        };
        if intent.pair_was_present && (data.is_none() || index.is_none()) {
            warn!(
                ?data_path,
                ?index_path,
                kind,
                "a previously present progress pair lost one of its main files"
            );
            return false;
        }
        let data_len = match data.as_ref() {
            Some(data) => match data.metadata() {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    warn!(
                        ?error,
                        ?data_path,
                        kind,
                        "failed to stat progress append-recovery data"
                    );
                    return false;
                }
            },
            None => 0,
        };
        if data_len < intent.old_data_len || data_len > intent.new_data_len {
            warn!(
                data_len,
                old_data_len = intent.old_data_len,
                new_data_len = intent.new_data_len,
                ?data_path,
                kind,
                "progress append-recovery data length is outside the journaled range"
            );
            return false;
        }
        let roll_forward = if data_len == intent.new_data_len {
            let payload_len = intent
                .payload_len()
                .expect("validated progress intent has a payload length");
            let Ok(payload_len) = usize::try_from(payload_len) else {
                return false;
            };
            let mut payload = Vec::new();
            if payload.try_reserve_exact(payload_len).is_err() {
                return false;
            }
            payload.resize(payload_len, 0);
            let Some(data) = data.as_mut() else {
                return false;
            };
            if data
                .seek(SeekFrom::Start(intent.old_data_len))
                .and_then(|_| data.read_exact(&mut payload))
                .is_err()
            {
                return false;
            }
            BoundProgressAppendIntentV1::payload_digest(&payload) == intent.payload_hash
        } else {
            false
        };
        if let Some(index) = index.as_mut() {
            let index_len = match index.metadata() {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    warn!(
                        ?error,
                        ?index_path,
                        kind,
                        "failed to stat progress append-recovery index"
                    );
                    return false;
                }
            };
            if index_len > intent.old_index_len.max(intent.new_index_len)
                || (intent.pair_was_present && index_len < intent.old_index_len)
            {
                warn!(
                    index_len,
                    old_index_len = intent.old_index_len,
                    new_index_len = intent.new_index_len,
                    ?index_path,
                    kind,
                    "progress append-recovery index length is outside the journaled range"
                );
                return false;
            }
            let old_layout = if intent.old_index_len == 0 {
                None
            } else if intent.is_prepend() {
                match intent.prepend_old_layout() {
                    Ok(layout) => Some(layout),
                    Err(reason) => {
                        warn!(
                            reason,
                            ?index_path,
                            kind,
                            "invalid durable prepend preimage"
                        );
                        return false;
                    }
                }
            } else {
                match SidecarIndexLayout::read_from(index, intent.old_index_len) {
                    Ok(layout) => Some(layout),
                    Err(reason) => {
                        warn!(
                            reason,
                            ?index_path,
                            kind,
                            "failed to validate the append-intent old index layout"
                        );
                        return false;
                    }
                }
            };
            if let Err(reason) = intent.validate_against_old_layout(old_layout) {
                warn!(
                    reason,
                    ?intent_path,
                    kind,
                    "progress append intent is inconsistent with its old index layout"
                );
                return false;
            }
            if !intent.old_index_bytes.is_empty()
                && index
                    .seek(SeekFrom::Start(intent.index_write_offset))
                    .and_then(|_| index.write_all(&intent.old_index_bytes))
                    .is_err()
            {
                return false;
            }
            if index.set_len(intent.old_index_len).is_err() || index.flush().is_err() {
                return false;
            }
        } else {
            if intent.pair_was_present {
                return false;
            }
            if let Err(reason) = intent.validate_against_old_layout(None) {
                warn!(
                    reason,
                    ?intent_path,
                    kind,
                    "initial progress append intent has an invalid index layout"
                );
                return false;
            }
        }
        if intent.pair_was_present {
            let Some(index) = index.as_mut() else {
                return false;
            };
            let Some(snapshot) = Self::bound_sidecar_index_snapshot(
                index,
                index_path,
                intent.old_data_len,
                kind,
                "append-intent preimage",
            ) else {
                return false;
            };
            if snapshot.indexed_end != intent.old_data_len {
                warn!(
                    indexed_end = snapshot.indexed_end,
                    old_data_len = intent.old_data_len,
                    ?index_path,
                    kind,
                    "progress append intent does not reconstruct the exact old pair"
                );
                return false;
            }
        }
        if roll_forward {
            if index.is_none() {
                index = match Self::open_direct_sidecar_file_in_namespace(
                    index_path,
                    true,
                    false,
                    Some(namespace),
                ) {
                    Ok(index) => Some(index),
                    Err(error) => {
                        warn!(
                            ?error,
                            ?index_path,
                            kind,
                            "failed to create progress index during append recovery"
                        );
                        return false;
                    }
                };
            }
            let Some(index) = index.as_mut() else {
                return false;
            };
            if index
                .seek(SeekFrom::Start(intent.index_write_offset))
                .and_then(|_| index.write_all(&intent.new_index_bytes))
                .and_then(|_| index.set_len(intent.new_index_len))
                .and_then(|_| index.flush())
                .and_then(|_| index.sync_data())
                .is_err()
            {
                return false;
            }
            let Some(snapshot) = Self::bound_sidecar_index_snapshot(
                index,
                index_path,
                intent.new_data_len,
                kind,
                "append-intent result",
            ) else {
                return false;
            };
            let Some(relative_height) = intent.height.checked_sub(snapshot.layout.base_height)
            else {
                return false;
            };
            let Some(entry) = usize::try_from(relative_height)
                .ok()
                .and_then(|position| snapshot.entries.get(position))
            else {
                return false;
            };
            let expected_entry = SidecarIndexEntry {
                offset: intent.old_data_len,
                len: intent
                    .payload_len()
                    .expect("validated progress intent has a payload length"),
            };
            if (*entry, snapshot.indexed_end) != (expected_entry, intent.new_data_len) {
                warn!(
                    height = intent.height,
                    ?index_path,
                    kind,
                    "progress append intent does not reconstruct its exact target entry"
                );
                return false;
            }
            let Some(data) = data.as_ref() else {
                return false;
            };
            if !Self::sync_indexed_sidecar_bound_mutation(data, index, namespace, kind) {
                return false;
            }
        } else if intent.pair_was_present {
            let (Some(data), Some(index)) = (data.as_ref(), index.as_ref()) else {
                return false;
            };
            if data.set_len(intent.old_data_len).is_err()
                || !Self::sync_indexed_sidecar_bound_mutation(data, index, namespace, kind)
            {
                return false;
            }
        } else {
            if let Some(mut index_file) = index.take() {
                if index_file
                    .seek(SeekFrom::Start(0))
                    .and_then(|_| {
                        index_file.write_all(&SidecarIndexLayout::base_header(intent.height))
                    })
                    .and_then(|_| index_file.set_len(INDEXED_SIDECAR_BASE_HEADER_SIZE_U64))
                    .and_then(|_| index_file.sync_data())
                    .is_err()
                {
                    return false;
                }
                drop(index_file);
                if let Err(error) =
                    Self::remove_bound_progress_temp_if_present(namespace, index_path)
                {
                    warn!(
                        ?error,
                        ?index_path,
                        kind,
                        "failed to remove rolled-back progress index"
                    );
                    return false;
                }
            }
            if let Some(data_file) = data.take() {
                if data_file.set_len(0).is_err() || data_file.sync_data().is_err() {
                    return false;
                }
                drop(data_file);
                if let Err(error) =
                    Self::remove_bound_progress_temp_if_present(namespace, data_path)
                {
                    warn!(
                        ?error,
                        ?data_path,
                        kind,
                        "failed to remove rolled-back progress data"
                    );
                    return false;
                }
            }
            if let Err(error) = Self::sync_bound_progress_intent_directories(namespace) {
                warn!(?error, kind, "failed to sync absent progress-pair rollback");
                return false;
            }
        }
        drop(index);
        drop(data);
        drop(intent_file);
        if let Err(error) = Self::remove_bound_progress_temp_if_present(namespace, intent_path) {
            warn!(
                ?error,
                ?intent_path,
                kind,
                "failed to clear recovered progress append intent"
            );
            return false;
        }
        if let Err(error) = Self::sync_bound_progress_intent_directories(namespace) {
            warn!(
                ?error,
                ?intent_path,
                kind,
                "failed to sync recovered append-intent cleanup"
            );
            return false;
        }
        if !Self::progress_mutation_namespace_unchanged(namespace) {
            return false;
        }
        accounting.finish_resources_before_disk_rescan();
        true
    }
    #[must_use]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect descriptor-bound progress publication; preserve crash recovery, namespace authentication and exact physical admission"
        )
    )]
    fn recover_bound_progress_sidecar_artifacts(
        &self,
        data_path: &Path,
        index_path: &Path,
        kind: &str,
    ) -> bool {
        let namespace = match self.open_bound_progress_namespace(data_path, index_path) {
            Ok(namespace) => namespace,
            Err(error) => {
                warn!(
                    ?error,
                    ?data_path,
                    ?index_path,
                    kind,
                    "failed to bind progress sidecar recovery namespace"
                );
                return false;
            }
        };
        self.recover_bound_progress_sidecar_artifacts_in_namespace(
            &namespace, data_path, index_path, kind,
        )
    }
    /// A terminal rewrite can retire every indexed slot. Its empty image is
    /// complete only with the full canonical V1 header and an empty data file;
    /// a zero-byte or truncated index is never a rewrite commit marker.
    fn bound_sidecar_rewrite_image_is_complete(
        snapshot: &BoundSidecarIndexSnapshot,
        data_len: u64,
    ) -> bool {
        let canonical_empty = data_len == 0
            && snapshot.layout.entries_offset == INDEXED_SIDECAR_BASE_HEADER_SIZE_U64
            && snapshot.layout.aligned_len == INDEXED_SIDECAR_BASE_HEADER_SIZE_U64;
        (snapshot.layout.entry_count > 0 || canonical_empty) && snapshot.indexed_end == data_len
    }

    fn recover_bound_progress_sidecar_artifacts_in_namespace(
        &self,
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        kind: &str,
    ) -> bool {
        self.recover_bound_progress_sidecar_artifacts_in_namespace_classified(
            namespace, data_path, index_path, kind,
        )
        .is_ok()
    }
    /// Recover a descriptor-bound progress pair and distinguish transient
    /// durability failure from malformed or ambiguous protocol state.
    fn recover_bound_progress_sidecar_artifacts_in_namespace_classified(
        &self,
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        kind: &str,
    ) -> std::result::Result<(), BoundProgressRecoveryFailure> {
        if self.recover_bound_progress_sidecar_artifacts_in_namespace_impl(
            namespace, data_path, index_path, kind,
        ) {
            Ok(())
        } else {
            Err(self
                .classify_bound_progress_recovery_failure(namespace, data_path, index_path, kind))
        }
    }
    #[allow(clippy::too_many_lines)]
    fn recover_bound_progress_sidecar_artifacts_in_namespace_impl(
        &self,
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        kind: &str,
    ) -> bool {
        let temp_data_path = data_path.with_extension("norito.tmp");
        let temp_index_path = index_path.with_extension("index.tmp");
        let prepend_index_path = index_path.with_extension("index.prepend.tmp");
        let append_build_path = Self::bound_progress_append_build_path(index_path);
        let append_intent_path = Self::bound_progress_append_intent_path(index_path);
        let open_optional =
            |path: &Path| match self.open_optional_bound_progress_file(namespace, path) {
                Ok(file) => Some(file),
                Err(error) => {
                    warn!(
                        ?error,
                        ?path,
                        kind,
                        "failed to bind progress sidecar recovery file"
                    );
                    None
                }
            };
        let Some(temp_data) = open_optional(&temp_data_path) else {
            return false;
        };
        let Some(temp_index) = open_optional(&temp_index_path) else {
            return false;
        };
        let Some(prepend_index) = open_optional(&prepend_index_path) else {
            return false;
        };
        if prepend_index.is_some() {
            warn!(
                ?prepend_index_path,
                kind, "bound prepend requires its authenticated append intent"
            );
            return false;
        }
        let Some(append_build) = open_optional(&append_build_path) else {
            return false;
        };
        let Some(append_intent) = open_optional(&append_intent_path) else {
            return false;
        };
        if append_intent.is_some()
            && (temp_data.is_some() || temp_index.is_some() || prepend_index.is_some())
        {
            warn!(
                ?data_path,
                ?index_path,
                kind,
                "progress sidecar has conflicting append and rewrite recovery artifacts"
            );
            return false;
        }
        if let Some(append_intent) = append_intent {
            return self.recover_bound_progress_append_intent(
                namespace,
                data_path,
                index_path,
                &append_build_path,
                append_build,
                &append_intent_path,
                append_intent,
                kind,
            );
        }
        if let Some(append_build) = append_build {
            // Main-file mutation is forbidden until the build is atomically
            // renamed to the durable intent name, so a build alone is always
            // safe to discard.
            drop(append_build);
            if !Self::discard_bound_progress_temps(namespace, &[append_build_path.as_path()], kind)
            {
                return false;
            }
        }
        let Some(mut temp_index) = temp_index else {
            if let Some(temp_data) = temp_data {
                // The temp index is the rewrite commit marker. A lone data temp
                // therefore precedes publication and is safe to discard.
                drop(temp_data);
                return Self::discard_bound_progress_temps(
                    namespace,
                    &[temp_data_path.as_path()],
                    kind,
                );
            }
            return self.repair_bound_progress_main_tail(namespace, data_path, index_path, kind);
        };
        let temp_data_was_present = temp_data.is_some();
        let recovery_data = if let Some(temp_data) = temp_data {
            temp_data
        } else {
            match self.open_optional_bound_progress_file(namespace, data_path) {
                Ok(Some(data)) => data,
                Ok(None) => {
                    warn!(
                        ?data_path,
                        ?temp_index_path,
                        kind,
                        "progress temp index has no recovery payload"
                    );
                    return false;
                }
                Err(error) => {
                    warn!(
                        ?error,
                        ?data_path,
                        kind,
                        "failed to bind progress recovery payload"
                    );
                    return false;
                }
            }
        };
        let data_len = match recovery_data.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                warn!(
                    ?error,
                    ?data_path,
                    kind,
                    "failed to stat progress recovery payload"
                );
                return false;
            }
        };
        let temp_snapshot = Self::bound_sidecar_index_snapshot(
            &mut temp_index,
            &temp_index_path,
            data_len,
            kind,
            "rewrite temp",
        );
        let temp_is_complete = temp_snapshot.as_ref().is_some_and(|snapshot| {
            Self::bound_sidecar_rewrite_image_is_complete(snapshot, data_len)
        });
        if !temp_is_complete {
            if temp_data_was_present {
                // Neither main file has been published while both temp names
                // still exist. Discard the incomplete rewrite and retain the
                // authoritative main pair.
                drop(temp_index);
                drop(recovery_data);
                if !Self::discard_bound_progress_temps(
                    namespace,
                    &[temp_index_path.as_path()],
                    kind,
                ) {
                    return false;
                }
                return Self::discard_bound_progress_temps(
                    namespace,
                    &[temp_data_path.as_path()],
                    kind,
                );
            }
            let indexed_end = temp_snapshot
                .as_ref()
                .map_or(0, |snapshot| snapshot.indexed_end);
            warn!(
                indexed_end,
                data_len,
                ?temp_index_path,
                kind,
                "index-only progress rewrite temp does not cover its exact published payload"
            );
            return false;
        }
        if let Err(error) = sync_indexed_sidecar_data(&recovery_data) {
            warn!(
                ?error,
                ?data_path,
                kind,
                "failed to sync progress recovery payload"
            );
            return false;
        }
        if let Err(error) = sync_indexed_sidecar_index(&temp_index) {
            warn!(
                ?error,
                ?temp_index_path,
                kind,
                "failed to sync progress recovery index"
            );
            return false;
        }
        if !Self::sync_bound_progress_mutation_directories(namespace, kind) {
            return false;
        }
        if temp_data_was_present {
            if let Err(error) = Self::promote_bound_progress_temp(
                namespace,
                &temp_data_path,
                data_path,
                &recovery_data,
            ) {
                warn!(
                    source = ?error.source,
                    published = error.published,
                    ?temp_data_path,
                    ?data_path,
                    kind,
                    "failed to promote bound progress temp data"
                );
                return false;
            }
            if !Self::sync_bound_progress_mutation_directories(namespace, kind) {
                return false;
            }
        }
        if let Err(error) =
            Self::promote_bound_progress_temp(namespace, &temp_index_path, index_path, &temp_index)
        {
            warn!(
                source = ?error.source,
                published = error.published,
                ?temp_index_path,
                ?index_path,
                kind,
                "failed to promote bound progress temp index"
            );
            return false;
        }
        Self::sync_indexed_sidecar_bound_mutation(&recovery_data, &temp_index, namespace, kind)
    }
    #[allow(clippy::too_many_lines)]
    fn classify_bound_progress_recovery_failure(
        &self,
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        kind: &str,
    ) -> BoundProgressRecoveryFailure {
        if namespace.data_path != data_path || namespace.index_path != index_path {
            return BoundProgressRecoveryFailure::InvalidData;
        }
        if let Err(failure) = Self::progress_mutation_namespace_classified(namespace) {
            return failure;
        }
        let classification = (|| {
            let temp_data_path = data_path.with_extension("norito.tmp");
            let temp_index_path = index_path.with_extension("index.tmp");
            let prepend_index_path = index_path.with_extension("index.prepend.tmp");
            let append_build_path = Self::bound_progress_append_build_path(index_path);
            let append_intent_path = Self::bound_progress_append_intent_path(index_path);
            let open = |path: &Path| {
                self.open_optional_bound_progress_file(namespace, path)
                    .map_err(|error| BoundProgressRecoveryFailure::from_kura(&error))
            };
            let temp_data = open(&temp_data_path)?;
            let mut temp_index = open(&temp_index_path)?;
            let prepend_index = open(&prepend_index_path)?;
            let _append_build = open(&append_build_path)?;
            let mut append_intent = open(&append_intent_path)?;
            if append_intent.is_some()
                && (temp_data.is_some() || temp_index.is_some() || prepend_index.is_some())
            {
                return Err(BoundProgressRecoveryFailure::InvalidData);
            }
            if let Some(intent_file) = append_intent.as_mut() {
                let intent = Self::decode_bound_progress_append_intent(
                    intent_file,
                    &append_intent_path,
                    namespace,
                    data_path,
                    index_path,
                    kind,
                )?;
                let data = open(data_path)?;
                let mut index = open(index_path)?;
                if intent.pair_was_present && (data.is_none() || index.is_none()) {
                    return Err(BoundProgressRecoveryFailure::InvalidData);
                }
                let data_len = match data.as_ref() {
                    Some(file) => file
                        .metadata()
                        .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?
                        .len(),
                    None => 0,
                };
                let index_len = match index.as_ref() {
                    Some(file) => file
                        .metadata()
                        .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?
                        .len(),
                    None => 0,
                };
                if data_len < intent.old_data_len
                    || data_len > intent.new_data_len
                    || index_len > intent.old_index_len.max(intent.new_index_len)
                    || (intent.pair_was_present && index_len < intent.old_index_len)
                {
                    return Err(BoundProgressRecoveryFailure::InvalidData);
                }
                let old_layout = match index.as_mut() {
                    Some(index) if intent.old_index_len != 0 => Some(
                        Self::bound_progress_index_layout_classified(index, intent.old_index_len)?,
                    ),
                    _ => None,
                };
                intent
                    .validate_against_old_layout(old_layout)
                    .map_err(|_| BoundProgressRecoveryFailure::InvalidData)?;
                return Ok(BoundProgressRecoveryFailure::RetryableIo);
            }
            if prepend_index.is_some() && (temp_data.is_some() || temp_index.is_some()) {
                return Err(BoundProgressRecoveryFailure::InvalidData);
            }
            if prepend_index.is_some() {
                let data = open(data_path)?.ok_or(BoundProgressRecoveryFailure::InvalidData)?;
                let mut index =
                    open(index_path)?.ok_or(BoundProgressRecoveryFailure::InvalidData)?;
                let data_len = data
                    .metadata()
                    .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?
                    .len();
                Self::bound_sidecar_index_snapshot_classified(
                    &mut index,
                    index_path,
                    data_len,
                    kind,
                    "recovery classification prepend main",
                )?;
                return Ok(BoundProgressRecoveryFailure::RetryableIo);
            }
            if let Some(temp_index) = temp_index.as_mut() {
                let main_data = if temp_data.is_none() {
                    Some(open(data_path)?)
                } else {
                    None
                };
                let recovery_data = temp_data
                    .as_ref()
                    .or_else(|| main_data.as_ref().and_then(Option::as_ref))
                    .ok_or(BoundProgressRecoveryFailure::InvalidData)?;
                let data_len = recovery_data
                    .metadata()
                    .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?
                    .len();
                let complete = Self::bound_sidecar_index_snapshot_classified(
                    temp_index,
                    &temp_index_path,
                    data_len,
                    kind,
                    "recovery classification rewrite temp",
                )
                .map(|snapshot| {
                    Self::bound_sidecar_rewrite_image_is_complete(&snapshot, data_len)
                })?;
                if temp_data.is_none() && !complete {
                    return Err(BoundProgressRecoveryFailure::InvalidData);
                }
                return Ok(BoundProgressRecoveryFailure::RetryableIo);
            }
            if temp_data.is_some() {
                return Ok(BoundProgressRecoveryFailure::RetryableIo);
            }
            let data = open(data_path)?;
            let mut index = open(index_path)?;
            match (data, index.as_mut()) {
                (None, None) => Ok(BoundProgressRecoveryFailure::RetryableIo),
                (Some(_), None) | (None, Some(_)) => Err(BoundProgressRecoveryFailure::InvalidData),
                (Some(data), Some(index)) => {
                    let data_len = data
                        .metadata()
                        .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?
                        .len();
                    let index_len = index
                        .metadata()
                        .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?
                        .len();
                    let layout = Self::bound_progress_index_layout_classified(index, index_len)?;
                    if layout.aligned_len != index_len {
                        return Err(BoundProgressRecoveryFailure::InvalidData);
                    }
                    let snapshot = Self::bound_sidecar_index_snapshot_classified(
                        index,
                        index_path,
                        data_len,
                        kind,
                        "recovery classification main",
                    )?;
                    if snapshot.indexed_end != data_len {
                        return Err(BoundProgressRecoveryFailure::InvalidData);
                    }
                    Ok(BoundProgressRecoveryFailure::RetryableIo)
                }
            }
        })()
        .unwrap_or_else(|failure| failure);
        match Self::progress_mutation_namespace_classified(namespace) {
            Ok(()) => classification,
            Err(failure) => failure,
        }
    }
    fn repair_bound_progress_main_tail(
        &self,
        namespace: &BoundProgressNamespace,
        data_path: &Path,
        index_path: &Path,
        kind: &str,
    ) -> bool {
        let data = match self.open_optional_bound_progress_file(namespace, data_path) {
            Ok(data) => data,
            Err(error) => {
                warn!(
                    ?error,
                    ?data_path,
                    kind,
                    "failed to bind progress main payload"
                );
                return false;
            }
        };
        let index = match self.open_optional_bound_progress_file(namespace, index_path) {
            Ok(index) => index,
            Err(error) => {
                warn!(
                    ?error,
                    ?index_path,
                    kind,
                    "failed to bind progress main index"
                );
                return false;
            }
        };
        let (data, mut index) = match (data, index) {
            (Some(data), Some(index)) => (data, index),
            (None, None) => return Self::progress_mutation_namespace_unchanged(namespace),
            (None, Some(_)) | (Some(_), None) => {
                warn!(
                    ?data_path,
                    ?index_path,
                    kind,
                    "progress main data and index are only partially present"
                );
                return false;
            }
        };
        let data_len = match data.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                warn!(
                    ?error,
                    ?data_path,
                    kind,
                    "failed to stat progress main payload"
                );
                return false;
            }
        };
        let index_len = match index.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                warn!(
                    ?error,
                    ?index_path,
                    kind,
                    "failed to stat progress main index"
                );
                return false;
            }
        };
        let layout = match SidecarIndexLayout::read_from(&mut index, index_len) {
            Ok(layout) => layout,
            Err(reason) => {
                warn!(
                    reason,
                    ?index_path,
                    kind,
                    "progress main index layout is malformed"
                );
                return false;
            }
        };
        if layout.aligned_len != index_len {
            warn!(
                ?index_path,
                kind, "progress main index has an unauthenticated partial entry"
            );
            return false;
        }
        let Some(snapshot) = Self::bound_sidecar_index_snapshot(
            &mut index,
            index_path,
            data_len,
            kind,
            "main tail repair",
        ) else {
            return false;
        };
        if snapshot.indexed_end == data_len {
            return Self::progress_mutation_namespace_unchanged(namespace);
        }
        warn!(
            ?data_path,
            ?index_path,
            indexed_end = snapshot.indexed_end,
            data_len,
            kind,
            "progress main pair has an unauthenticated unindexed data suffix"
        );
        false
    }
    fn discard_bound_progress_temps(
        namespace: &BoundProgressNamespace,
        paths: &[&Path],
        kind: &str,
    ) -> bool {
        for path in paths {
            if let Err(error) = Self::remove_bound_progress_temp_if_present(namespace, path) {
                warn!(
                    ?error,
                    ?path,
                    kind,
                    "failed to discard an unpublished bound progress temp"
                );
                return false;
            }
        }
        Self::sync_bound_progress_mutation_directories(namespace, kind)
    }
    #[must_use]
    fn recover_indexed_sidecar_artifacts(data_path: &Path, index_path: &Path, kind: &str) -> bool {
        let required_heights = BTreeSet::new();
        Self::recover_indexed_sidecar_artifacts_with_required_heights(
            data_path,
            index_path,
            &required_heights,
            kind,
        )
    }
    #[must_use]
    fn recover_indexed_sidecar_artifacts_with_required_heights(
        data_path: &Path,
        index_path: &Path,
        required_heights: &BTreeSet<u64>,
        kind: &str,
    ) -> bool {
        let temp_data_path = data_path.with_extension("norito.tmp");
        let temp_index_path = index_path.with_extension("index.tmp");
        let temp_index_exists = temp_index_path.exists();
        let temp_data_exists = temp_data_path.exists();
        if !temp_index_exists {
            if temp_data_exists {
                warn!(
                    ?temp_data_path,
                    kind, "sidecar temp data exists without temp index; failing closed"
                );
                return false;
            }
            if required_heights.is_empty() {
                return true;
            }
            let data_len = match std::fs::metadata(data_path).map(|metadata| metadata.len()) {
                Ok(data_len) => data_len,
                Err(error) => {
                    warn!(
                        ?error,
                        ?data_path,
                        kind,
                        "required terminal evidence has no readable canonical sidecar data"
                    );
                    return false;
                }
            };
            return Self::sidecar_index_contains_required_heights(
                index_path,
                data_len,
                required_heights,
                kind,
                "canonical",
            );
        }
        // A temp index is the durable commit marker for a prune rewrite. When both files remain,
        // validate them as a pair. When only the index remains, the crash happened after data
        // promotion, so validate it against main data. Never publish an index before the payload
        // it references is in its final location.
        let recovery_data_path = if temp_data_exists {
            &temp_data_path
        } else {
            data_path
        };
        let data_len = match std::fs::metadata(recovery_data_path).map(|meta| meta.len()) {
            Ok(data_len) => data_len,
            Err(err) => {
                warn!(
                    ?err,
                    ?temp_index_path,
                    ?recovery_data_path,
                    kind,
                    "failed to read sidecar data length for temp index validation"
                );
                return false;
            }
        };
        if !Self::sidecar_index_sane_with_label(&temp_index_path, data_len, kind, "temp") {
            warn!(
                ?temp_index_path,
                kind, "refusing to promote invalid sidecar temp index"
            );
            return false;
        }
        if !Self::sidecar_index_contains_required_heights(
            &temp_index_path,
            data_len,
            required_heights,
            kind,
            "temp",
        ) {
            warn!(
                ?temp_index_path,
                kind, "refusing to promote a sidecar temp that omits required terminal evidence"
            );
            return false;
        }
        if temp_data_exists && !Self::promote_sidecar_temp(&temp_data_path, data_path, kind, "data")
        {
            warn!(
                ?temp_data_path,
                kind, "sidecar temp data promotion failed; leaving temp index unpublished"
            );
            return false;
        }
        if !Self::promote_sidecar_temp(&temp_index_path, index_path, kind, "index") {
            warn!(
                ?temp_index_path,
                kind,
                "sidecar temp index promotion failed after data promotion; leaving it for recovery"
            );
            return false;
        }
        Self::sidecar_index_contains_required_heights(
            index_path,
            data_len,
            required_heights,
            kind,
            "recovered canonical",
        )
    }
    #[must_use]
    fn promote_sidecar_temp(temp_path: &Path, main_path: &Path, kind: &str, label: &str) -> bool {
        if !temp_path.exists() {
            return false;
        }
        if let Err(err) = std::fs::rename(temp_path, main_path) {
            if main_path.exists() {
                if let Err(remove_err) = std::fs::remove_file(main_path) {
                    warn!(
                        ?remove_err,
                        ?main_path,
                        kind,
                        label,
                        "failed to remove sidecar file before promoting temp"
                    );
                    return false;
                }
                if let Err(err) = std::fs::rename(temp_path, main_path) {
                    warn!(
                        ?err,
                        ?temp_path,
                        ?main_path,
                        kind,
                        label,
                        "failed to promote sidecar temp file after removal"
                    );
                    return false;
                }
            } else {
                warn!(
                    ?err,
                    ?temp_path,
                    ?main_path,
                    kind,
                    label,
                    "failed to promote sidecar temp file"
                );
                return false;
            }
        }
        if let Some(parent) = main_path.parent() {
            if let Err(err) = sync_sidecar_promotion_dir(parent) {
                warn!(
                    ?err,
                    ?parent,
                    kind,
                    label,
                    "failed to sync sidecar parent after temp promotion"
                );
                return false;
            }
        }
        true
    }
    fn sidecar_index_sane_with_label(
        index_path: &Path,
        data_len: u64,
        kind: &str,
        label: &str,
    ) -> bool {
        let mut index = match std::fs::File::open(index_path) {
            Ok(file) => file,
            Err(err) => {
                warn!(
                    ?err,
                    ?index_path,
                    kind,
                    label,
                    "failed to open sidecar index"
                );
                return false;
            }
        };
        let index_len = match index.metadata() {
            Ok(meta) => meta.len(),
            Err(err) => {
                warn!(
                    ?err,
                    ?index_path,
                    kind,
                    label,
                    "failed to stat sidecar index"
                );
                return false;
            }
        };
        if index_len == 0 {
            warn!(?index_path, kind, label, "sidecar index is empty");
            return false;
        }
        let layout = match SidecarIndexLayout::read_from(&mut index, index_len) {
            Ok(layout) => layout,
            Err(reason) => {
                warn!(
                    reason,
                    len = index_len,
                    ?index_path,
                    kind,
                    label,
                    "sidecar index layout is malformed"
                );
                return false;
            }
        };
        if index_len != layout.aligned_len {
            warn!(
                len = index_len,
                aligned_len = layout.aligned_len,
                ?index_path,
                kind,
                label,
                "sidecar index length misaligned"
            );
            return false;
        }
        if layout.entry_count == 0 {
            if data_len == 0 {
                return true;
            }
            warn!(
                data_len,
                ?index_path,
                kind,
                label,
                "header-only sidecar index retains unindexed payload bytes"
            );
            return false;
        }
        if index.seek(SeekFrom::Start(layout.entries_offset)).is_err() {
            warn!(
                ?index_path,
                kind, label, "failed to seek to sidecar index entries"
            );
            return false;
        }
        let mut buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
        for _ in 0..layout.entry_count {
            if let Err(err) = index.read_exact(&mut buf) {
                warn!(
                    ?err,
                    ?index_path,
                    kind,
                    label,
                    "failed to read sidecar index entry"
                );
                return false;
            }
            let entry = SidecarIndexEntry::from_bytes(buf);
            if entry.len == 0 {
                continue;
            }
            if entry.len > STRICT_INIT_MAX_BLOCK_BYTES {
                warn!(
                    len = entry.len,
                    limit = STRICT_INIT_MAX_BLOCK_BYTES,
                    ?index_path,
                    kind,
                    label,
                    "sidecar index entry length exceeds limit"
                );
                return false;
            }
            let entry_end = if let Some(end) = entry.offset.checked_add(entry.len) {
                end
            } else {
                warn!(
                    offset = entry.offset,
                    len = entry.len,
                    ?index_path,
                    kind,
                    label,
                    "sidecar index entry overflows offset"
                );
                return false;
            };
            if entry_end > data_len {
                warn!(
                    offset = entry.offset,
                    len = entry.len,
                    data_len,
                    ?index_path,
                    kind,
                    label,
                    "sidecar index entry points past data file"
                );
                return false;
            }
        }
        true
    }

    fn sidecar_index_contains_required_heights(
        index_path: &Path,
        data_len: u64,
        required_heights: &BTreeSet<u64>,
        kind: &str,
        label: &str,
    ) -> bool {
        if required_heights.is_empty() {
            return true;
        }
        let mut index = match std::fs::File::open(index_path) {
            Ok(file) => file,
            Err(error) => {
                warn!(
                    ?error,
                    ?index_path,
                    kind,
                    label,
                    "failed to open sidecar index while checking required terminal evidence"
                );
                return false;
            }
        };
        let index_len = match index.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                warn!(
                    ?error,
                    ?index_path,
                    kind,
                    label,
                    "failed to stat sidecar index while checking required terminal evidence"
                );
                return false;
            }
        };
        let layout = match SidecarIndexLayout::read_from(&mut index, index_len) {
            Ok(layout) if index_len == layout.aligned_len => layout,
            Ok(_) => {
                warn!(
                    ?index_path,
                    kind,
                    label,
                    "required terminal evidence index has trailing or misaligned bytes"
                );
                return false;
            }
            Err(reason) => {
                warn!(
                    reason,
                    ?index_path,
                    kind,
                    label,
                    "required terminal evidence index layout is malformed"
                );
                return false;
            }
        };
        for height in required_heights {
            let Some(relative) = height.checked_sub(layout.base_height) else {
                warn!(
                    height,
                    base_height = layout.base_height,
                    ?index_path,
                    kind,
                    label,
                    "required terminal evidence predates the sidecar index"
                );
                return false;
            };
            if relative >= layout.entry_count {
                warn!(
                    height,
                    base_height = layout.base_height,
                    entry_count = layout.entry_count,
                    ?index_path,
                    kind,
                    label,
                    "required terminal evidence is outside the sidecar index"
                );
                return false;
            }
            let Some(offset) = relative
                .checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64)
                .and_then(|offset| layout.entries_offset.checked_add(offset))
            else {
                return false;
            };
            if index.seek(SeekFrom::Start(offset)).is_err() {
                return false;
            }
            let mut entry_bytes = [0_u8; PIPELINE_INDEX_ENTRY_SIZE];
            if index.read_exact(&mut entry_bytes).is_err() {
                return false;
            }
            let entry = SidecarIndexEntry::from_bytes(entry_bytes);
            if entry.len == 0
                || entry
                    .offset
                    .checked_add(entry.len)
                    .is_none_or(|end| end > data_len)
            {
                warn!(
                    height,
                    offset = entry.offset,
                    len = entry.len,
                    data_len,
                    ?index_path,
                    kind,
                    label,
                    "required terminal evidence sidecar entry is absent or out of bounds"
                );
                return false;
            }
        }
        true
    }
    #[cfg(test)]
    fn indexed_sidecar_height_range(
        index_path: &Path,
        kind: &str,
    ) -> Option<core::ops::RangeInclusive<u64>> {
        let mut index = match std::fs::File::open(index_path) {
            Ok(index) => index,
            Err(err) => {
                iroha_logger::debug!(?err, ?index_path, kind, "sidecar index is unavailable");
                return None;
            }
        };
        let index_len = match index.metadata() {
            Ok(meta) => meta.len(),
            Err(err) => {
                iroha_logger::warn!(?err, ?index_path, kind, "failed to stat sidecar index");
                return None;
            }
        };
        let layout = match SidecarIndexLayout::read_from(&mut index, index_len) {
            Ok(layout) => layout,
            Err(reason) => {
                iroha_logger::warn!(
                    reason,
                    len = index_len,
                    ?index_path,
                    kind,
                    "refusing malformed sidecar index"
                );
                return None;
            }
        };
        if index_len != layout.aligned_len {
            iroha_logger::warn!(
                len = index_len,
                aligned_len = layout.aligned_len,
                ?index_path,
                kind,
                "sidecar index length misaligned; ignoring trailing bytes"
            );
        }
        layout.height_range()
    }
    fn repair_unindexed_sidecar_tail(
        data: &std::fs::File,
        index: &mut std::fs::File,
        layout: SidecarIndexLayout,
        data_path: &Path,
        index_path: &Path,
        kind: &str,
    ) -> bool {
        let data_len = match data.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                iroha_logger::warn!(?error, ?data_path, kind, "failed to stat sidecar payload");
                return false;
            }
        };
        if index.seek(SeekFrom::Start(layout.entries_offset)).is_err() {
            iroha_logger::warn!(
                ?index_path,
                kind,
                "failed to seek sidecar index for tail repair"
            );
            return false;
        }
        let Ok(entry_capacity) = usize::try_from(layout.entry_count) else {
            iroha_logger::warn!(?index_path, kind, "sidecar index entry count exceeds usize");
            return false;
        };
        let mut ranges = Vec::with_capacity(entry_capacity.min(4096));
        let mut encoded = [0_u8; PIPELINE_INDEX_ENTRY_SIZE];
        for _ in 0..layout.entry_count {
            if let Err(error) = index.read_exact(&mut encoded) {
                iroha_logger::warn!(
                    ?error,
                    ?index_path,
                    kind,
                    "failed to read sidecar index during tail repair"
                );
                return false;
            }
            let entry = SidecarIndexEntry::from_bytes(encoded);
            if entry.len == 0 {
                if entry.offset != 0 {
                    iroha_logger::warn!(
                        offset = entry.offset,
                        ?index_path,
                        kind,
                        "zero-length sidecar index entry has a non-zero offset"
                    );
                    return false;
                }
                continue;
            }
            if entry.len > STRICT_INIT_MAX_BLOCK_BYTES {
                iroha_logger::warn!(
                    len = entry.len,
                    limit = STRICT_INIT_MAX_BLOCK_BYTES,
                    ?index_path,
                    kind,
                    "sidecar index entry exceeds the payload limit during tail repair"
                );
                return false;
            }
            let Some(end) = entry.offset.checked_add(entry.len) else {
                iroha_logger::warn!(
                    offset = entry.offset,
                    len = entry.len,
                    ?index_path,
                    kind,
                    "sidecar index entry overflows during tail repair"
                );
                return false;
            };
            if end > data_len {
                iroha_logger::warn!(
                    offset = entry.offset,
                    len = entry.len,
                    data_len,
                    ?index_path,
                    kind,
                    "sidecar index points past the payload during tail repair"
                );
                return false;
            }
            ranges.push((entry.offset, end));
        }
        ranges.sort_unstable_by_key(|&(start, end)| (start, end));
        if ranges.windows(2).any(|pair| pair[1].0 < pair[0].1) {
            iroha_logger::warn!(
                ?index_path,
                kind,
                "sidecar index contains overlapping active payload ranges"
            );
            return false;
        }
        let indexed_end = ranges.iter().map(|&(_, end)| end).max().unwrap_or(0);
        if data_len == indexed_end {
            return true;
        }
        if let Err(error) = data.set_len(indexed_end) {
            iroha_logger::warn!(
                ?error,
                ?data_path,
                data_len,
                indexed_end,
                kind,
                "failed to truncate unindexed sidecar crash residue"
            );
            return false;
        }
        if let Err(error) = data.sync_data() {
            iroha_logger::warn!(
                ?error,
                ?data_path,
                indexed_end,
                kind,
                "failed to durably repair unindexed sidecar crash residue"
            );
            return false;
        }
        true
    }
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn append_preceding_indexed_sidecar(
        data_path: &Path,
        index_path: &Path,
        height: u64,
        payload: &[u8],
        kind: &str,
        should_sync: bool,
        retention: Option<NonZeroUsize>,
        layout: SidecarIndexLayout,
        namespace: Option<&BoundProgressNamespace>,
    ) -> bool {
        debug_assert!(height < layout.base_height);
        let prepend = layout.base_height - height;
        if prepend > MAX_INDEXED_SIDECAR_GAP_ENTRIES {
            iroha_logger::warn!(
                height,
                base_height = layout.base_height,
                prepend,
                limit = MAX_INDEXED_SIDECAR_GAP_ENTRIES,
                ?index_path,
                kind,
                "refusing oversized backward sidecar index gap"
            );
            return false;
        }
        let Some(old_entries_len) = layout
            .entry_count
            .checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64)
        else {
            iroha_logger::warn!(?index_path, kind, "sidecar entry byte length overflows");
            return false;
        };
        let Some(new_entry_count) = prepend.checked_add(layout.entry_count) else {
            iroha_logger::warn!(?index_path, kind, "sidecar entry count overflows");
            return false;
        };
        let new_entries_offset = INDEXED_SIDECAR_BASE_HEADER_SIZE_U64;
        let Some(projected_index_len) = new_entry_count
            .checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64)
            .and_then(|entries_len| new_entries_offset.checked_add(entries_len))
        else {
            iroha_logger::warn!(?index_path, kind, "sidecar prepend length overflows");
            return false;
        };
        let data_existed = data_path.exists();
        let mut data =
            match Self::open_direct_sidecar_file_in_namespace(data_path, true, false, namespace) {
                Ok(file) => file,
                Err(err) => {
                    iroha_logger::warn!(?err, ?data_path, kind, "failed to open sidecar store");
                    return false;
                }
            };
        let mut repair_index = match Self::open_direct_sidecar_file_in_namespace(
            index_path, false, false, namespace,
        ) {
            Ok(file) => file,
            Err(err) => {
                iroha_logger::warn!(?err, ?index_path, kind, "failed to open sidecar index");
                return false;
            }
        };
        if !Self::repair_unindexed_sidecar_tail(
            &data,
            &mut repair_index,
            layout,
            data_path,
            index_path,
            kind,
        ) {
            return false;
        }
        drop(repair_index);
        let data_len = match data.metadata() {
            Ok(meta) => meta.len(),
            Err(err) => {
                iroha_logger::warn!(?err, ?data_path, kind, "failed to stat sidecar store");
                return false;
            }
        };
        let payload_len = match u64::try_from(payload.len()) {
            Ok(len) => len,
            Err(_) => {
                iroha_logger::warn!(
                    len = payload.len(),
                    kind,
                    "sidecar payload length exceeds u64"
                );
                return false;
            }
        };
        let Some(projected_data_len) = data_len.checked_add(payload_len) else {
            iroha_logger::warn!(data_len, payload_len, kind, "sidecar data length overflows");
            return false;
        };
        let temp_index_path = index_path.with_extension("index.prepend.tmp");
        let remove_temp = || match namespace {
            Some(namespace) => {
                Self::remove_bound_progress_temp_if_present(namespace, &temp_index_path)
            }
            None => match std::fs::remove_file(&temp_index_path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            },
        };
        if let Err(err) = remove_temp() {
            iroha_logger::warn!(
                ?err,
                ?temp_index_path,
                kind,
                "failed to remove stale sidecar prepend temp index"
            );
            return false;
        }
        let mut source_index = match Self::open_direct_sidecar_file_in_namespace(
            index_path, false, false, namespace,
        ) {
            Ok(file) => file,
            Err(err) => {
                iroha_logger::warn!(?err, ?index_path, kind, "failed to reopen sidecar index");
                return false;
            }
        };
        let mut temp_index = match match namespace {
            Some(namespace) => Self::create_new_bound_progress_temp(namespace, &temp_index_path),
            None => std::fs::OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&temp_index_path),
        } {
            Ok(file) => file,
            Err(err) => {
                iroha_logger::warn!(
                    ?err,
                    ?temp_index_path,
                    kind,
                    "failed to create sidecar prepend temp index"
                );
                return false;
            }
        };
        let entry = SidecarIndexEntry {
            offset: data_len,
            len: payload_len,
        };
        let build_result = (|| -> std::io::Result<()> {
            temp_index.write_all(&SidecarIndexLayout::base_header(height))?;
            temp_index.write_all(&entry.to_bytes())?;
            let filler_entries = prepend.saturating_sub(1);
            let filler_len = filler_entries
                .checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64)
                .and_then(|len| usize::try_from(len).ok())
                .ok_or_else(|| std::io::Error::other("sidecar prepend filler is too large"))?;
            temp_index.write_all(&vec![0_u8; filler_len])?;
            source_index.seek(SeekFrom::Start(layout.entries_offset))?;
            let copied = std::io::copy(
                &mut (&mut source_index).take(old_entries_len),
                &mut temp_index,
            )?;
            if copied != old_entries_len {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "sidecar source index ended during prepend",
                ));
            }
            temp_index.flush()?;
            if should_sync {
                temp_index.sync_data()?;
            }
            Ok(())
        })();
        if let Err(err) = build_result {
            iroha_logger::warn!(
                ?err,
                ?temp_index_path,
                kind,
                "failed to build sidecar prepend temp index"
            );
            drop(temp_index);
            let _ = remove_temp();
            return false;
        }
        let temp_index_len = temp_index.metadata().map(|meta| meta.len());
        if !matches!(temp_index_len, Ok(len) if len == projected_index_len) {
            iroha_logger::warn!(
                projected_index_len,
                ?temp_index_path,
                kind,
                "sidecar prepend temp index has unexpected length"
            );
            drop(temp_index);
            let _ = remove_temp();
            return false;
        }
        drop(source_index);
        if let Err(err) = data
            .seek(SeekFrom::Start(data_len))
            .and_then(|_| data.write_all(payload))
            .and_then(|_| data.flush())
        {
            iroha_logger::warn!(?err, ?data_path, kind, "failed to append sidecar payload");
            let _ = rollback_unindexed_sidecar_payload(&data, data_len, data_path, kind);
            drop(data);
            if !data_existed && namespace.is_none() {
                let _ = std::fs::remove_file(data_path);
            }
            drop(temp_index);
            let _ = remove_temp();
            return false;
        }
        if should_sync && let Err(err) = sync_indexed_sidecar_initial_data(&data) {
            iroha_logger::warn!(?err, ?data_path, kind, "failed to sync sidecar payload");
            let _ = rollback_unindexed_sidecar_payload(&data, data_len, data_path, kind);
            drop(data);
            if !data_existed && namespace.is_none() {
                let _ = std::fs::remove_file(data_path);
            }
            drop(temp_index);
            let _ = remove_temp();
            return false;
        }
        let mut index_was_published = false;
        let promoted = if let Some(namespace) = namespace {
            let temp_layout = temp_index.metadata().ok().and_then(|metadata| {
                SidecarIndexLayout::read_from(&mut temp_index, metadata.len()).ok()
            });
            if temp_layout.is_some_and(|temp_layout| {
                temp_layout.entry_count > 0
                    && temp_layout.aligned_len == projected_index_len
                    && Self::repair_unindexed_sidecar_tail(
                        &data,
                        &mut temp_index,
                        temp_layout,
                        data_path,
                        &temp_index_path,
                        kind,
                    )
            }) {
                match Self::promote_bound_progress_temp(
                    namespace,
                    &temp_index_path,
                    index_path,
                    &temp_index,
                ) {
                    Ok(()) => {
                        index_was_published = true;
                        Self::sync_indexed_sidecar_bound_mutation(
                            &data,
                            &temp_index,
                            namespace,
                            kind,
                        )
                    }
                    Err(error) => {
                        index_was_published = error.published;
                        iroha_logger::warn!(
                            source = ?error.source,
                            published = error.published,
                            ?temp_index_path,
                            ?index_path,
                            kind,
                            "failed to promote bound progress prepend index"
                        );
                        false
                    }
                }
            } else {
                false
            }
        } else {
            Self::sidecar_index_sane_with_label(
                &temp_index_path,
                projected_data_len,
                kind,
                "prepend temp",
            ) && Self::promote_sidecar_temp(&temp_index_path, index_path, kind, "prepend index")
        };
        if !promoted {
            // Once rename publishes the new index, its new entry owns the
            // appended payload even if a later directory barrier fails. Keep
            // that consistent pair intact so an exact retry can reissue the
            // complete barrier sequence; truncating now would leave the main
            // index pointing past EOF.
            if !index_was_published
                && rollback_unindexed_sidecar_payload(&data, data_len, data_path, kind)
                && !data_existed
                && namespace.is_none()
            {
                drop(data);
                let _ = std::fs::remove_file(data_path);
            }
            drop(temp_index);
            let _ = remove_temp();
            return false;
        }
        drop(temp_index);
        drop(data);
        if let Some(retention) = retention
            && !Self::prune_indexed_sidecars(data_path, index_path, retention, kind)
        {
            return false;
        }
        true
    }
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn append_indexed_sidecar(
        data_path: &Path,
        index_path: &Path,
        height: u64,
        payload: &[u8],
        kind: &str,
        fsync_mode: FsyncMode,
        retention: Option<NonZeroUsize>,
    ) -> bool {
        Self::append_indexed_sidecar_with_pinned_height(
            data_path, index_path, height, payload, kind, fsync_mode, retention, None, None,
        )
    }
    /// Account the exact larger journal only for a backward prepend. Ordinary
    /// writes retain their existing fixed envelope. The caller holds sidecar
    /// ownership through this read-only admission and the subsequent write.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect descriptor-bound progress publication; preserve crash recovery, namespace authentication and exact physical admission"
        )
    )]
    fn bound_progress_publication_peak_locked(
        &self,
        namespace: &BoundProgressNamespace,
        height: u64,
        payload_len: u64,
    ) -> Result<u64> {
        self.ensure_bound_progress_pair_has_no_recovery_artifacts_locked(
            namespace,
            &namespace.data_path,
            &namespace.index_path,
            "bound publication peak",
        )?;
        let mut pair =
            self.open_bound_progress_pair(&namespace.data_path, &namespace.index_path)?;
        let prepend = match &mut pair {
            BoundProgressPair::Absent(_) => None,
            BoundProgressPair::Present(bound) => {
                let index_len = bound
                    .index
                    .metadata()
                    .map_err(|error| Error::IO(error, namespace.index_path.clone()))?
                    .len();
                let layout = SidecarIndexLayout::read_from(&mut bound.index, index_len).map_err(
                    |reason| {
                        Self::invalid_lane_artifact_error(namespace.index_path.clone(), reason)
                    },
                )?;
                if layout.aligned_len != index_len {
                    return Err(Self::invalid_lane_artifact_error(
                        namespace.index_path.clone(),
                        "publication peak index is partially aligned",
                    ));
                }
                let result = if height < layout.base_height {
                    let new = BoundProgressAppendIntentV1::prepend_layout(layout, height).map_err(
                        |reason| {
                            Self::invalid_lane_artifact_error(namespace.index_path.clone(), reason)
                        },
                    )?;
                    let data_len = bound
                        .data
                        .metadata()
                        .map_err(|error| Error::IO(error, namespace.data_path.clone()))?
                        .len();
                    let intent_len = BoundProgressAppendIntentV1::prepend_encoded_len(
                        namespace,
                        &namespace.data_path,
                        &namespace.index_path,
                        height,
                        layout,
                        data_len,
                        payload_len,
                    )
                    .map_err(|reason| {
                        Self::invalid_lane_artifact_error(namespace.index_path.clone(), reason)
                    })?;
                    Some((
                        new.aligned_len - layout.aligned_len,
                        u64::try_from(intent_len)?,
                    ))
                } else {
                    None
                };
                if !self.bound_progress_sidecar_unchanged(bound) {
                    return Err(Self::invalid_lane_artifact_error(
                        namespace.index_path.clone(),
                        "publication peak pair changed during observation",
                    ));
                }
                result
            }
        };
        if !Self::progress_mutation_namespace_unchanged(namespace) {
            return Err(Self::invalid_lane_artifact_error(
                namespace.data_path.clone(),
                "publication peak namespace changed during observation",
            ));
        }
        let (growth, transient) = prepend.unwrap_or((
            Self::maximum_index_growth_for_unresolved_sidecar_write(height),
            u64::try_from(BOUND_PROGRESS_APPEND_INTENT_MAX_BYTES)?,
        ));
        payload_len
            .checked_add(growth)
            .and_then(|bytes| bytes.checked_add(transient))
            .ok_or_else(|| {
                Self::invalid_lane_artifact_error(
                    namespace.data_path.clone(),
                    "bound publication peak overflowed",
                )
            })
    }
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "TODO: connect descriptor-bound progress publication; preserve crash recovery, namespace authentication and exact physical admission"
        )
    )]
    fn append_indexed_bound_progress_sidecar(
        data_path: &Path,
        index_path: &Path,
        height: u64,
        initial_base_height: u64,
        payload: &[u8],
        kind: &str,
        namespace: &BoundProgressNamespace,
    ) -> bool {
        let Ok(payload_len) = u64::try_from(payload.len()) else {
            warn!(
                len = payload.len(),
                kind, "progress payload length exceeds u64"
            );
            return false;
        };
        if namespace.data_path != data_path
            || namespace.index_path != index_path
            || height == 0
            || height == u64::MAX
            || initial_base_height == 0
            || initial_base_height > height
            || payload_len == 0
            || payload_len > STRICT_INIT_MAX_BLOCK_BYTES
            || !Self::progress_mutation_namespace_unchanged(namespace)
        {
            warn!(
                height,
                len = payload.len(),
                ?data_path,
                ?index_path,
                kind,
                "refusing invalid bound progress sidecar append"
            );
            return false;
        }
        let namespace_components = match namespace.stable_relative_components(data_path, index_path)
        {
            Ok(components) => components,
            Err(reason) => {
                warn!(
                    reason,
                    ?data_path,
                    ?index_path,
                    kind,
                    "failed to derive the bound progress namespace identity"
                );
                return false;
            }
        };
        let build_path = Self::bound_progress_append_build_path(index_path);
        let intent_path = Self::bound_progress_append_intent_path(index_path);
        for artifact_path in [&build_path, &intent_path] {
            match std::fs::symlink_metadata(artifact_path) {
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Ok(_) => {
                    warn!(
                        ?artifact_path,
                        kind, "progress append recovery artifact must be resolved before mutation"
                    );
                    return false;
                }
                Err(error) => {
                    warn!(
                        ?error,
                        ?artifact_path,
                        kind,
                        "failed to inspect progress append artifact"
                    );
                    return false;
                }
            }
        }
        let opened_data =
            Self::open_direct_sidecar_file_in_namespace(data_path, false, false, Some(namespace));
        let opened_index =
            Self::open_direct_sidecar_file_in_namespace(index_path, false, false, Some(namespace));
        let (pair_was_present, mut data, mut index) = match (opened_data, opened_index) {
            (Ok(data), Ok(index)) => (true, Some(data), Some(index)),
            (Err(data_error), Err(index_error))
                if data_error.kind() == ErrorKind::NotFound
                    && index_error.kind() == ErrorKind::NotFound =>
            {
                (false, None, None)
            }
            (data, index) => {
                warn!(
                    data_error = ?data.err(),
                    index_error = ?index.err(),
                    ?data_path,
                    ?index_path,
                    kind,
                    "progress main data and index are only partially present or unsafe"
                );
                return false;
            }
        };
        let old_data_len = match data.as_ref() {
            Some(data) => match data.metadata() {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    warn!(
                        ?error,
                        ?data_path,
                        kind,
                        "failed to stat bound progress data"
                    );
                    return false;
                }
            },
            None => 0,
        };
        // Production callers run full recovery while holding `sidecar_lock`
        // immediately before binding this namespace. Re-read only the bounded
        // layout and target entry here instead of allocating and sorting the
        // entire historical index a second time on every consensus write.
        let (layout, old_index_len) = match index.as_mut() {
            Some(index) => {
                let old_index_len = match index.metadata() {
                    Ok(metadata) => metadata.len(),
                    Err(error) => {
                        warn!(
                            ?error,
                            ?index_path,
                            kind,
                            "failed to stat bound progress index"
                        );
                        return false;
                    }
                };
                let layout = match SidecarIndexLayout::read_from(index, old_index_len) {
                    Ok(layout) if layout.aligned_len == old_index_len => layout,
                    Ok(_) => {
                        warn!(
                            ?index_path,
                            kind, "bound progress index has a partial trailing entry"
                        );
                        return false;
                    }
                    Err(reason) => {
                        warn!(
                            reason,
                            ?index_path,
                            kind,
                            "failed to read the recovered progress index layout"
                        );
                        return false;
                    }
                };
                (Some(layout), old_index_len)
            }
            None => (None, 0),
        };
        if let Some(entry_pos) = layout.and_then(|layout| layout.entry_position(height)) {
            let Some(index_file) = index.as_mut() else {
                return false;
            };
            let mut entry_bytes = [0_u8; PIPELINE_INDEX_ENTRY_SIZE];
            if let Err(error) = index_file
                .seek(SeekFrom::Start(entry_pos))
                .and_then(|_| index_file.read_exact(&mut entry_bytes))
            {
                warn!(
                    ?error,
                    height,
                    ?index_path,
                    kind,
                    "failed to read the recovered progress target entry"
                );
                return false;
            }
            let entry = SidecarIndexEntry::from_bytes(entry_bytes);
            if entry.len > 0 {
                let Some(end) = entry.offset.checked_add(entry.len) else {
                    return false;
                };
                let Ok(existing_len) = usize::try_from(entry.len) else {
                    return false;
                };
                let mut existing = Vec::new();
                if existing.try_reserve_exact(existing_len).is_err() {
                    return false;
                }
                existing.resize(existing_len, 0);
                let Some(data_file) = data.as_mut() else {
                    return false;
                };
                if end > old_data_len {
                    warn!(
                        height,
                        ?data_path,
                        kind,
                        "progress index entry extends beyond the recovered data file"
                    );
                    return false;
                }
                if let Err(error) = data_file
                    .seek(SeekFrom::Start(entry.offset))
                    .and_then(|_| data_file.read_exact(&mut existing))
                {
                    warn!(
                        ?error,
                        height,
                        ?data_path,
                        kind,
                        "failed to read the existing progress payload"
                    );
                    return false;
                }
                if existing == payload {
                    let Some(index_file) = index.as_ref() else {
                        return false;
                    };
                    return Self::sync_indexed_sidecar_bound_mutation(
                        data_file, index_file, namespace, kind,
                    ) && Self::progress_mutation_namespace_unchanged(namespace);
                }
            }
            let Some(new_data_len) = old_data_len.checked_add(payload_len) else {
                return false;
            };
            let new_entry = SidecarIndexEntry {
                offset: old_data_len,
                len: payload_len,
            };
            let intent = BoundProgressAppendIntentV1 {
                version: BOUND_PROGRESS_APPEND_INTENT_VERSION,
                namespace_components: namespace_components.clone(),
                data_file: match data_path.file_name().and_then(std::ffi::OsStr::to_str) {
                    Some(name) => name.to_owned(),
                    None => return false,
                },
                index_file: match index_path.file_name().and_then(std::ffi::OsStr::to_str) {
                    Some(name) => name.to_owned(),
                    None => return false,
                },
                height,
                pair_was_present,
                old_data_len,
                new_data_len,
                payload_hash: BoundProgressAppendIntentV1::payload_digest(payload),
                old_index_len,
                new_index_len: old_index_len,
                index_write_offset: entry_pos,
                old_index_bytes: entry.to_bytes().to_vec(),
                new_index_bytes: new_entry.to_bytes().to_vec(),
                integrity_hash: Hash::prehashed([0; Hash::LENGTH]),
            }
            .seal();
            return Self::execute_bound_progress_append(
                data_path, index_path, payload, kind, namespace, intent, data, index,
            );
        }
        if let Some(layout) = layout
            && height < layout.base_height
        {
            let Some(index_file) = index.as_mut() else {
                return false;
            };
            let intent = match BoundProgressAppendIntentV1::for_prepend(
                namespace,
                data_path,
                index_path,
                height,
                old_data_len,
                payload,
                index_file,
            ) {
                Ok(intent) => intent,
                Err(reason) => {
                    warn!(
                        reason,
                        ?index_path,
                        kind,
                        "cannot admit bounded progress prepend"
                    );
                    return false;
                }
            };
            return Self::execute_bound_progress_append(
                data_path, index_path, payload, kind, namespace, intent, data, index,
            );
        }
        let mut new_index_bytes = Vec::new();
        let (layout, index_write_offset) = match layout {
            Some(layout) => (layout, old_index_len),
            None => {
                new_index_bytes
                    .extend_from_slice(&SidecarIndexLayout::base_header(initial_base_height));
                let layout = match SidecarIndexLayout::based(
                    initial_base_height,
                    INDEXED_SIDECAR_BASE_HEADER_SIZE_U64,
                ) {
                    Ok(layout) => layout,
                    Err(reason) => {
                        warn!(
                            reason,
                            height,
                            ?index_path,
                            kind,
                            "invalid initial progress index base"
                        );
                        return false;
                    }
                };
                (layout, 0)
            }
        };
        let Some(expected_height) = layout.next_height() else {
            return false;
        };
        if height < expected_height {
            warn!(
                height,
                expected_height,
                base_height = layout.base_height,
                ?index_path,
                kind,
                "progress height precedes the compact index base"
            );
            return false;
        }
        let missing = height - expected_height;
        if missing > MAX_INDEXED_SIDECAR_GAP_ENTRIES {
            warn!(
                height,
                expected_height,
                missing,
                limit = MAX_INDEXED_SIDECAR_GAP_ENTRIES,
                ?index_path,
                kind,
                "refusing oversized progress index gap"
            );
            return false;
        }
        let Some(filler_len) = missing
            .checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64)
            .and_then(|len| usize::try_from(len).ok())
        else {
            return false;
        };
        if new_index_bytes
            .try_reserve(filler_len + PIPELINE_INDEX_ENTRY_SIZE)
            .is_err()
        {
            return false;
        }
        new_index_bytes.resize(new_index_bytes.len() + filler_len, 0);
        let Some(new_data_len) = old_data_len.checked_add(payload_len) else {
            return false;
        };
        new_index_bytes.extend_from_slice(
            &SidecarIndexEntry {
                offset: old_data_len,
                len: payload_len,
            }
            .to_bytes(),
        );
        let Some(new_index_len) = index_write_offset
            .checked_add(u64::try_from(new_index_bytes.len()).expect("bounded index window"))
        else {
            return false;
        };
        let intent = BoundProgressAppendIntentV1 {
            version: BOUND_PROGRESS_APPEND_INTENT_VERSION,
            namespace_components,
            data_file: match data_path.file_name().and_then(std::ffi::OsStr::to_str) {
                Some(name) => name.to_owned(),
                None => return false,
            },
            index_file: match index_path.file_name().and_then(std::ffi::OsStr::to_str) {
                Some(name) => name.to_owned(),
                None => return false,
            },
            height,
            pair_was_present,
            old_data_len,
            new_data_len,
            payload_hash: BoundProgressAppendIntentV1::payload_digest(payload),
            old_index_len,
            new_index_len,
            index_write_offset,
            old_index_bytes: Vec::new(),
            new_index_bytes,
            integrity_hash: Hash::prehashed([0; Hash::LENGTH]),
        }
        .seal();
        Self::execute_bound_progress_append(
            data_path, index_path, payload, kind, namespace, intent, data, index,
        )
    }
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn execute_bound_progress_append(
        data_path: &Path,
        index_path: &Path,
        payload: &[u8],
        kind: &str,
        namespace: &BoundProgressNamespace,
        intent: BoundProgressAppendIntentV1,
        mut data: Option<std::fs::File>,
        mut index: Option<std::fs::File>,
    ) -> bool {
        let intent_path = Self::bound_progress_append_intent_path(index_path);
        if let Err(reason) = intent.validate_for(namespace, data_path, index_path) {
            warn!(
                reason,
                ?data_path,
                ?index_path,
                kind,
                "refusing invalid progress append plan"
            );
            return false;
        }
        let old_layout = match index.as_mut() {
            Some(index) if intent.old_index_len != 0 => {
                match SidecarIndexLayout::read_from(index, intent.old_index_len) {
                    Ok(layout) => Some(layout),
                    Err(reason) => {
                        warn!(
                            reason,
                            ?index_path,
                            kind,
                            "refusing progress append with an unreadable old index layout"
                        );
                        return false;
                    }
                }
            }
            _ => None,
        };
        if let Err(reason) = intent.validate_against_old_layout(old_layout) {
            warn!(
                reason,
                ?data_path,
                ?index_path,
                kind,
                "refusing progress append inconsistent with the old index layout"
            );
            return false;
        }
        let Some(intent_file) =
            Self::publish_bound_progress_append_intent(namespace, index_path, &intent, kind)
        else {
            return false;
        };
        if !Self::progress_mutation_namespace_unchanged(namespace) {
            return false;
        }
        if data.is_none() {
            data = match Self::open_direct_sidecar_file_in_namespace(
                data_path,
                true,
                false,
                Some(namespace),
            ) {
                Ok(data) => Some(data),
                Err(error) => {
                    warn!(
                        ?error,
                        ?data_path,
                        kind,
                        "failed to create bound progress data"
                    );
                    return false;
                }
            };
        }
        if index.is_none() {
            index = match Self::open_direct_sidecar_file_in_namespace(
                index_path,
                true,
                false,
                Some(namespace),
            ) {
                Ok(index) => Some(index),
                Err(error) => {
                    warn!(
                        ?error,
                        ?index_path,
                        kind,
                        "failed to create bound progress index"
                    );
                    return false;
                }
            };
        }
        let (Some(data), Some(index)) = (data.as_mut(), index.as_mut()) else {
            return false;
        };
        if !data
            .metadata()
            .is_ok_and(|metadata| metadata.len() == intent.old_data_len)
            || !index
                .metadata()
                .is_ok_and(|metadata| metadata.len() == intent.old_index_len)
        {
            warn!(
                ?data_path,
                ?index_path,
                kind,
                "progress pair changed after intent publication"
            );
            return false;
        }
        if let Err(error) = data
            .seek(SeekFrom::Start(intent.old_data_len))
            .and_then(|_| data.write_all(payload))
            .and_then(|_| data.flush())
            .and_then(|_| sync_bound_progress_append_data(data))
        {
            warn!(
                ?error,
                ?data_path,
                kind,
                "failed to append journaled progress payload"
            );
            return false;
        }
        if let Err(error) = index
            .seek(SeekFrom::Start(intent.index_write_offset))
            .and_then(|_| index.write_all(&intent.new_index_bytes))
            .and_then(|_| index.set_len(intent.new_index_len))
            .and_then(|_| index.flush())
            .and_then(|_| sync_bound_progress_append_index(index))
        {
            warn!(
                ?error,
                ?index_path,
                kind,
                "failed to apply journaled progress index mutation"
            );
            return false;
        }
        let Some(snapshot) = Self::bound_sidecar_index_snapshot(
            index,
            index_path,
            intent.new_data_len,
            kind,
            "journaled progress append result",
        ) else {
            return false;
        };
        let Some(relative_height) = intent.height.checked_sub(snapshot.layout.base_height) else {
            return false;
        };
        let Some(entry) = usize::try_from(relative_height)
            .ok()
            .and_then(|position| snapshot.entries.get(position))
        else {
            return false;
        };
        let expected_entry = SidecarIndexEntry {
            offset: intent.old_data_len,
            len: intent
                .payload_len()
                .expect("validated progress intent has a payload length"),
        };
        if (*entry, snapshot.indexed_end) != (expected_entry, intent.new_data_len) {
            warn!(
                height = intent.height,
                ?index_path,
                kind,
                "journaled progress append produced the wrong target entry"
            );
            return false;
        }
        if !Self::sync_indexed_sidecar_bound_mutation(data, index, namespace, kind) {
            return false;
        }
        drop(intent_file);
        if let Err(error) = Self::remove_bound_progress_temp_if_present(namespace, &intent_path) {
            warn!(
                ?error,
                ?intent_path,
                kind,
                "failed to clear completed progress append intent"
            );
            return false;
        }
        if let Err(error) = Self::sync_bound_progress_intent_directories(namespace) {
            warn!(
                ?error,
                ?intent_path,
                kind,
                "failed to sync completed append-intent cleanup"
            );
            return false;
        }
        Self::progress_mutation_namespace_unchanged(namespace)
    }
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    fn append_indexed_progress_sidecar(
        data_path: &Path,
        index_path: &Path,
        height: u64,
        payload: &[u8],
        kind: &str,
        retention: Option<NonZeroUsize>,
        namespace: &BoundProgressNamespace,
    ) -> bool {
        if retention.is_some() || !Self::progress_mutation_namespace_unchanged(namespace) {
            warn!(
                kind,
                "progress sidecar retention must be handled outside strict append"
            );
            return false;
        }
        let wrote = Self::append_indexed_bound_progress_sidecar(
            data_path, index_path, height, height, payload, kind, namespace,
        );
        wrote && Self::progress_mutation_namespace_unchanged(namespace)
    }
    fn progress_mutation_namespace_unchanged(namespace: &BoundProgressNamespace) -> bool {
        Self::progress_mutation_namespace_classified(namespace).is_ok()
    }
    fn progress_mutation_namespace_classified(
        namespace: &BoundProgressNamespace,
    ) -> std::result::Result<(), BoundProgressRecoveryFailure> {
        for directory in &namespace.directories {
            let opened = secure_file_metadata::from_file(&directory.file)
                .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?;
            let current = secure_file_metadata::from_path(&directory.expected_path)
                .map_err(|error| BoundProgressRecoveryFailure::from_io(&error))?;
            if !opened.is_dir()
                || !current.is_dir()
                || current.file_type().is_symlink()
                || !Self::sidecar_metadata_same_object(&directory.metadata, &opened)
                || !Self::sidecar_metadata_same_object(&directory.metadata, &current)
            {
                return Err(BoundProgressRecoveryFailure::InvalidData);
            }
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn append_indexed_sidecar_with_pinned_height(
        data_path: &Path,
        index_path: &Path,
        height: u64,
        payload: &[u8],
        kind: &str,
        fsync_mode: FsyncMode,
        retention: Option<NonZeroUsize>,
        pinned_height: Option<u64>,
        namespace: Option<&BoundProgressNamespace>,
    ) -> bool {
        // Sidecars are best-effort; only fsync when strict durability is requested.
        let should_sync = matches!(fsync_mode, FsyncMode::Always);
        if height == 0 || height == u64::MAX {
            iroha_logger::warn!(
                height,
                kind,
                "refusing to store sidecar for unrepresentable height"
            );
            return false;
        }
        if namespace.is_none()
            && !Self::recover_indexed_sidecar_artifacts(data_path, index_path, kind)
        {
            return false;
        }
        let data_was_absent = !data_path.exists();
        let index_was_absent = !index_path.exists();
        if data_was_absent != index_was_absent {
            iroha_logger::warn!(
                ?data_path,
                ?index_path,
                kind,
                "sidecar main data and index are only partially present"
            );
            return false;
        }
        let pair_was_absent = data_was_absent;
        let mut index =
            match Self::open_direct_sidecar_file_in_namespace(index_path, true, false, namespace) {
                Ok(file) => file,
                Err(err) => {
                    iroha_logger::warn!(?err, ?index_path, kind, "failed to open sidecar index");
                    return false;
                }
            };
        let mut index_len = match index.metadata() {
            Ok(meta) => meta.len(),
            Err(err) => {
                iroha_logger::warn!(?err, ?index_path, kind, "failed to stat sidecar index");
                return false;
            }
        };
        let layout = if pair_was_absent {
            if index_len != 0 {
                return false;
            }
            let header = SidecarIndexLayout::base_header(height);
            if let Err(err) = index.write_all(&header) {
                iroha_logger::warn!(
                    ?err,
                    height,
                    ?index_path,
                    kind,
                    "failed to initialize sidecar V1 index"
                );
                return false;
            }
            index_len = INDEXED_SIDECAR_BASE_HEADER_SIZE_U64;
            SidecarIndexLayout::based(height, INDEXED_SIDECAR_BASE_HEADER_SIZE_U64)
                .expect("validated sidecar height produces a canonical V1 layout")
        } else {
            match SidecarIndexLayout::read_from(&mut index, index_len) {
                Ok(layout) => layout,
                Err(reason) => {
                    iroha_logger::warn!(
                        reason,
                        len = index_len,
                        ?index_path,
                        kind,
                        "refusing malformed sidecar index"
                    );
                    return false;
                }
            }
        };
        if index_len != layout.aligned_len {
            iroha_logger::warn!(
                len = index_len,
                aligned_len = layout.aligned_len,
                ?index_path,
                kind,
                "sidecar index length misaligned; truncating trailing bytes"
            );
            if let Err(err) = index.set_len(layout.aligned_len) {
                iroha_logger::warn!(
                    ?err,
                    ?index_path,
                    kind,
                    "failed to truncate misaligned sidecar index"
                );
                return false;
            }
        }
        if height < layout.base_height {
            drop(index);
            return Self::append_preceding_indexed_sidecar(
                data_path,
                index_path,
                height,
                payload,
                kind,
                should_sync,
                retention,
                layout,
                namespace,
            );
        }
        let mut data =
            match Self::open_direct_sidecar_file_in_namespace(data_path, true, false, namespace) {
                Ok(file) => file,
                Err(err) => {
                    iroha_logger::warn!(?err, ?data_path, kind, "failed to open sidecar store");
                    return false;
                }
            };
        if !Self::repair_unindexed_sidecar_tail(
            &data, &mut index, layout, data_path, index_path, kind,
        ) {
            return false;
        }
        let expected_height = match layout.next_height() {
            Some(height) => height,
            None => {
                iroha_logger::warn!(
                    base_height = layout.base_height,
                    entries = layout.entry_count,
                    ?index_path,
                    kind,
                    "sidecar index height range overflows"
                );
                return false;
            }
        };
        if let Some(entry_pos) = layout.entry_position(height) {
            let mut entry_buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
            if index
                .seek(SeekFrom::Start(entry_pos))
                .and_then(|_| index.read_exact(&mut entry_buf))
                .is_err()
            {
                iroha_logger::warn!(
                    height,
                    ?index_path,
                    kind,
                    "failed to read sidecar index entry for update"
                );
                return false;
            }
            let entry = SidecarIndexEntry::from_bytes(entry_buf);
            let mut matches_existing = false;
            if entry.len > 0 {
                if entry.len > STRICT_INIT_MAX_BLOCK_BYTES {
                    iroha_logger::warn!(
                        height,
                        len = entry.len,
                        limit = STRICT_INIT_MAX_BLOCK_BYTES,
                        kind,
                        "existing sidecar payload length exceeds limit"
                    );
                    return false;
                }
                let len_usize = if let Ok(len) = usize::try_from(entry.len) {
                    len
                } else {
                    iroha_logger::warn!(
                        len = entry.len,
                        kind,
                        "sidecar payload length exceeds usize"
                    );
                    return false;
                };
                let data_len = match data.metadata() {
                    Ok(meta) => meta.len(),
                    Err(err) => {
                        iroha_logger::warn!(?err, ?data_path, kind, "failed to stat sidecar store");
                        return false;
                    }
                };
                if entry
                    .offset
                    .checked_add(entry.len)
                    .is_some_and(|end| end <= data_len)
                {
                    let mut existing = vec![0u8; len_usize];
                    if data
                        .seek(SeekFrom::Start(entry.offset))
                        .and_then(|_| data.read_exact(&mut existing))
                        .is_ok()
                    {
                        matches_existing = existing == payload;
                    } else {
                        iroha_logger::debug!(
                            height,
                            ?data_path,
                            kind,
                            "failed to read existing sidecar payload; overwriting entry"
                        );
                    }
                } else {
                    iroha_logger::debug!(
                        height,
                        offset = entry.offset,
                        len = entry.len,
                        data_len,
                        ?data_path,
                        kind,
                        "sidecar entry points past data file; overwriting entry"
                    );
                }
            }
            if matches_existing {
                iroha_logger::debug!(
                    height,
                    index_entries = layout.entry_count,
                    ?index_path,
                    kind,
                    "sidecar already recorded; revalidating strict durability"
                );
                if should_sync
                    && let Some(namespace) = namespace
                    && !Self::sync_indexed_sidecar_bound_mutation(&data, &index, namespace, kind)
                {
                    return false;
                }
                drop(index);
                drop(data);
                if let Some(retention) = retention {
                    if !Self::prune_indexed_sidecars_with_pinned_height(
                        data_path,
                        index_path,
                        retention,
                        pinned_height,
                        kind,
                    ) {
                        return false;
                    }
                }
                if should_sync
                    && namespace.is_none()
                    && !Self::sync_indexed_sidecar_barriers(data_path, index_path, kind)
                {
                    return false;
                }
                return true;
            }
            let offset = match data.metadata() {
                Ok(meta) => meta.len(),
                Err(err) => {
                    iroha_logger::warn!(?err, ?data_path, kind, "failed to stat sidecar store");
                    return false;
                }
            };
            let len_u64 = if let Ok(len) = u64::try_from(payload.len()) {
                len
            } else {
                iroha_logger::warn!(
                    len = payload.len(),
                    kind,
                    "sidecar payload length exceeds u64"
                );
                return false;
            };
            if let Err(err) = data
                .seek(SeekFrom::Start(offset))
                .and_then(|_| data.write_all(payload))
            {
                iroha_logger::warn!(?err, ?data_path, kind, "failed to append sidecar payload");
                let _ = rollback_unindexed_sidecar_payload(&data, offset, data_path, kind);
                return false;
            }
            if should_sync {
                if let Err(err) = sync_indexed_sidecar_initial_data(&data) {
                    iroha_logger::warn!(?err, ?data_path, kind, "failed to sync sidecar payload");
                    let _ = rollback_unindexed_sidecar_payload(&data, offset, data_path, kind);
                    return false;
                }
            }
            let new_entry = SidecarIndexEntry {
                offset,
                len: len_u64,
            };
            if let Err(err) = index
                .seek(SeekFrom::Start(entry_pos))
                .and_then(|_| index.write_all(&new_entry.to_bytes()))
            {
                iroha_logger::warn!(?err, ?index_path, kind, "failed to update sidecar index");
                let _ = rollback_unindexed_sidecar_payload(&data, offset, data_path, kind);
                return false;
            }
            if should_sync
                && let Some(namespace) = namespace
                && !Self::sync_indexed_sidecar_bound_mutation(&data, &index, namespace, kind)
            {
                return false;
            }
            drop(index);
            drop(data);
            if let Some(retention) = retention {
                if !Self::prune_indexed_sidecars_with_pinned_height(
                    data_path,
                    index_path,
                    retention,
                    pinned_height,
                    kind,
                ) {
                    return false;
                }
            }
            if should_sync
                && namespace.is_none()
                && !Self::sync_indexed_sidecar_barriers(data_path, index_path, kind)
            {
                return false;
            }
            return true;
        }
        if height < expected_height {
            iroha_logger::warn!(
                height,
                base_height = layout.base_height,
                expected_height,
                ?index_path,
                kind,
                "sidecar height precedes the compact index base"
            );
            return false;
        }
        let missing = height - expected_height;
        if missing > MAX_INDEXED_SIDECAR_GAP_ENTRIES {
            iroha_logger::warn!(
                height,
                expected_height,
                missing,
                limit = MAX_INDEXED_SIDECAR_GAP_ENTRIES,
                ?index_path,
                kind,
                "refusing oversized sidecar index gap"
            );
            return false;
        }
        let Some(projected_index_len) = missing
            .checked_add(1)
            .and_then(|entries| entries.checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64))
            .and_then(|growth| layout.aligned_len.checked_add(growth))
        else {
            iroha_logger::warn!(
                height,
                expected_height,
                ?index_path,
                kind,
                "sidecar index growth overflows file offsets"
            );
            return false;
        };
        if height > expected_height {
            iroha_logger::warn!(
                height,
                missing,
                kind,
                "sidecar gap detected; filling index placeholders"
            );
            let Some(filler_len_u64) = missing.checked_mul(PIPELINE_INDEX_ENTRY_SIZE_U64) else {
                iroha_logger::warn!(
                    height,
                    missing,
                    ?index_path,
                    kind,
                    "sidecar placeholder byte length overflows"
                );
                return false;
            };
            let Ok(filler_len) = usize::try_from(filler_len_u64) else {
                iroha_logger::warn!(
                    height,
                    filler_len = filler_len_u64,
                    ?index_path,
                    kind,
                    "sidecar placeholder byte length exceeds usize"
                );
                return false;
            };
            let filler = vec![0u8; filler_len];
            if let Err(err) = index
                .seek(SeekFrom::Start(layout.aligned_len))
                .and_then(|_| index.write_all(&filler))
            {
                iroha_logger::warn!(
                    ?err,
                    ?index_path,
                    kind,
                    "failed to append placeholder sidecar index entries"
                );
                return false;
            }
        }
        let offset = match data.metadata() {
            Ok(meta) => meta.len(),
            Err(err) => {
                iroha_logger::warn!(?err, ?data_path, kind, "failed to stat sidecar store");
                return false;
            }
        };
        let len_u64 = if let Ok(len) = u64::try_from(payload.len()) {
            len
        } else {
            iroha_logger::warn!(
                len = payload.len(),
                kind,
                "sidecar payload length exceeds u64"
            );
            return false;
        };
        if let Err(err) = data
            .seek(SeekFrom::Start(offset))
            .and_then(|_| data.write_all(payload))
        {
            iroha_logger::warn!(?err, ?data_path, kind, "failed to append sidecar payload");
            let _ = rollback_unindexed_sidecar_payload(&data, offset, data_path, kind);
            return false;
        }
        if should_sync {
            if let Err(err) = sync_indexed_sidecar_initial_data(&data) {
                iroha_logger::warn!(?err, ?data_path, kind, "failed to sync sidecar payload");
                let _ = rollback_unindexed_sidecar_payload(&data, offset, data_path, kind);
                return false;
            }
        }
        let entry = SidecarIndexEntry {
            offset,
            len: len_u64,
        };
        let Some(entry_pos) = projected_index_len.checked_sub(PIPELINE_INDEX_ENTRY_SIZE_U64) else {
            iroha_logger::warn!(
                projected_index_len,
                ?index_path,
                kind,
                "sidecar index entry position underflows"
            );
            let _ = rollback_unindexed_sidecar_payload(&data, offset, data_path, kind);
            return false;
        };
        if let Err(err) = index
            .seek(SeekFrom::Start(entry_pos))
            .and_then(|_| index.write_all(&entry.to_bytes()))
        {
            iroha_logger::warn!(?err, ?index_path, kind, "failed to append sidecar index");
            let _ = rollback_unindexed_sidecar_payload(&data, offset, data_path, kind);
            return false;
        }
        if should_sync
            && let Some(namespace) = namespace
            && !Self::sync_indexed_sidecar_bound_mutation(&data, &index, namespace, kind)
        {
            return false;
        }
        drop(index);
        drop(data);
        if let Some(retention) = retention {
            if !Self::prune_indexed_sidecars_with_pinned_height(
                data_path,
                index_path,
                retention,
                pinned_height,
                kind,
            ) {
                return false;
            }
        }
        if should_sync
            && namespace.is_none()
            && !Self::sync_indexed_sidecar_barriers(data_path, index_path, kind)
        {
            return false;
        }
        true
    }
    fn sync_indexed_sidecar_bound_mutation(
        data: &std::fs::File,
        index: &std::fs::File,
        namespace: &BoundProgressNamespace,
        kind: &str,
    ) -> bool {
        if let Err(error) = sync_indexed_sidecar_data(data) {
            iroha_logger::warn!(
                ?error,
                kind,
                "failed to sync bound sidecar payload mutation"
            );
            return false;
        }
        if let Err(error) = sync_indexed_sidecar_index(index) {
            iroha_logger::warn!(?error, kind, "failed to sync bound sidecar index mutation");
            return false;
        }
        Self::sync_bound_progress_mutation_directories(namespace, kind)
    }
    fn sync_bound_progress_mutation_directories(
        namespace: &BoundProgressNamespace,
        kind: &str,
    ) -> bool {
        for (position, directory) in namespace.directories.iter().enumerate() {
            let result = if position == 0 {
                sync_indexed_sidecar_dir_handle(&directory.file)
            } else {
                sync_progress_sidecar_ancestor_dir_handle(&directory.file)
            };
            if let Err(error) = result {
                iroha_logger::warn!(
                    ?error,
                    path = ?directory.expected_path,
                    kind,
                    "failed to sync bound sidecar mutation directory"
                );
                return false;
            }
        }
        Self::progress_mutation_namespace_unchanged(namespace)
    }
    /// Reissue the complete strict sidecar durability sequence in dependency order.
    ///
    /// Calling this for an exact existing payload is intentional: a prior attempt may have made
    /// both files readable through the page cache while failing the index or directory barrier.
    fn sync_indexed_sidecar_barriers(data_path: &Path, index_path: &Path, kind: &str) -> bool {
        let data = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(data_path)
        {
            Ok(file) => file,
            Err(err) => {
                iroha_logger::warn!(
                    ?err,
                    ?data_path,
                    kind,
                    "failed to open sidecar store for sync"
                );
                return false;
            }
        };
        if let Err(err) = sync_indexed_sidecar_data(&data) {
            iroha_logger::warn!(?err, ?data_path, kind, "failed to sync sidecar payload");
            return false;
        }
        let index = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(index_path)
        {
            Ok(file) => file,
            Err(err) => {
                iroha_logger::warn!(
                    ?err,
                    ?index_path,
                    kind,
                    "failed to open sidecar index for sync"
                );
                return false;
            }
        };
        if let Err(err) = sync_indexed_sidecar_index(&index) {
            iroha_logger::warn!(?err, ?index_path, kind, "failed to sync sidecar index");
            return false;
        }
        if let Some(parent) = data_path.parent()
            && let Err(err) = sync_indexed_sidecar_dir(parent)
        {
            iroha_logger::warn!(
                ?err,
                ?parent,
                kind,
                "failed to sync sidecar parent directory"
            );
            return false;
        }
        if let Some(parent) = index_path.parent()
            && Some(parent) != data_path.parent()
            && let Err(err) = sync_indexed_sidecar_dir(parent)
        {
            iroha_logger::warn!(
                ?err,
                ?parent,
                kind,
                "failed to sync sidecar index parent directory"
            );
            return false;
        }
        true
    }
    #[allow(clippy::too_many_lines)]
    fn read_pipeline_sidecar<T, F>(
        &self,
        height: u64,
        data_file: &str,
        index_file: &str,
        decoder: F,
        kind: &str,
    ) -> Option<T>
    where
        F: Fn(&[u8]) -> Result<T, norito::Error>,
    {
        let mut dir = self.store_dir()?;
        dir.push(PIPELINE_DIR_NAME);
        let data_path = dir.join(data_file);
        let index_path = dir.join(index_file);
        let entry_byte_limit =
            u64::try_from(MAX_PIPELINE_RECOVERY_SIDECAR_BYTES).unwrap_or(u64::MAX);
        let recover = !self.emergency_fast_startup_enabled();
        if recover
            && !self.recover_indexed_sidecar_with_physical_resources(&data_path, &index_path, kind)
        {
            return None;
        }
        Self::read_indexed_sidecar_from_paths_with_recovery_and_limit(
            height,
            &data_path,
            &index_path,
            decoder,
            kind,
            false,
            entry_byte_limit,
        )
    }
    #[cfg(test)]
    #[allow(clippy::too_many_lines)]
    fn read_indexed_sidecar_from_paths<T, F>(
        height: u64,
        data_path: &Path,
        index_path: &Path,
        decoder: F,
        kind: &str,
    ) -> Option<T>
    where
        F: Fn(&[u8]) -> Result<T, norito::Error>,
    {
        Self::read_indexed_sidecar_from_paths_with_recovery(
            height, data_path, index_path, decoder, kind, true,
        )
    }
    #[allow(clippy::too_many_lines)]
    #[cfg(test)]
    fn read_indexed_sidecar_from_paths_with_recovery<T, F>(
        height: u64,
        data_path: &Path,
        index_path: &Path,
        decoder: F,
        kind: &str,
        recover: bool,
    ) -> Option<T>
    where
        F: Fn(&[u8]) -> Result<T, norito::Error>,
    {
        Self::read_indexed_sidecar_from_paths_with_recovery_and_limit(
            height,
            data_path,
            index_path,
            decoder,
            kind,
            recover,
            STRICT_INIT_MAX_BLOCK_BYTES,
        )
    }
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn read_indexed_sidecar_from_paths_with_recovery_and_limit<T, F>(
        height: u64,
        data_path: &Path,
        index_path: &Path,
        decoder: F,
        kind: &str,
        recover: bool,
        entry_byte_limit: u64,
    ) -> Option<T>
    where
        F: Fn(&[u8]) -> Result<T, norito::Error>,
    {
        if height == 0 {
            return None;
        }
        if recover && !Self::recover_indexed_sidecar_artifacts(data_path, index_path, kind) {
            return None;
        }
        let mut index = open_read_only_regular_file(index_path, "indexed sidecar index").ok()?;
        let mut data = open_read_only_regular_file(data_path, "indexed sidecar data").ok()?;
        Self::read_indexed_sidecar_from_open_files_with_limit(
            height,
            &mut data,
            &mut index,
            data_path,
            index_path,
            decoder,
            kind,
            entry_byte_limit,
        )
    }
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn read_indexed_sidecar_from_open_files_with_limit<T, F>(
        height: u64,
        data: &mut std::fs::File,
        index: &mut std::fs::File,
        data_path: &Path,
        index_path: &Path,
        decoder: F,
        kind: &str,
        entry_byte_limit: u64,
    ) -> Option<T>
    where
        F: Fn(&[u8]) -> Result<T, norito::Error>,
    {
        let index_meta = index.metadata().ok()?;
        let index_len = index_meta.len();
        let layout = match SidecarIndexLayout::read_from(index, index_len) {
            Ok(layout) => layout,
            Err(reason) => {
                iroha_logger::warn!(
                    reason,
                    len = index_len,
                    ?index_path,
                    kind,
                    "refusing malformed sidecar index"
                );
                return None;
            }
        };
        if index_len != layout.aligned_len {
            iroha_logger::warn!(
                len = index_len,
                aligned_len = layout.aligned_len,
                ?index_path,
                kind,
                "sidecar index length misaligned; ignoring trailing bytes"
            );
        }
        let seek_pos = layout.entry_position(height)?;
        let mut entry_buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
        if index
            .seek(SeekFrom::Start(seek_pos))
            .and_then(|_| index.read_exact(&mut entry_buf))
            .is_err()
        {
            iroha_logger::warn!(
                height,
                ?index_path,
                kind,
                "failed to read sidecar index entry"
            );
            return None;
        }
        let entry = SidecarIndexEntry::from_bytes(entry_buf);
        if entry.len == 0 {
            iroha_logger::debug!(height, ?index_path, kind, "empty sidecar length; skipping");
            return None;
        }
        if entry.len > entry_byte_limit {
            iroha_logger::warn!(
                height,
                len = entry.len,
                limit = entry_byte_limit,
                ?index_path,
                kind,
                "sidecar length exceeds limit; skipping"
            );
            return None;
        }
        let len_usize = if let Ok(len) = usize::try_from(entry.len) {
            len
        } else {
            iroha_logger::warn!(
                len = entry.len,
                ?index_path,
                kind,
                "sidecar length exceeds usize; skipping"
            );
            return None;
        };
        let data_len = data.metadata().ok()?.len();
        let entry_end = match entry.offset.checked_add(entry.len) {
            Some(end) => end,
            None => {
                iroha_logger::warn!(
                    height,
                    offset = entry.offset,
                    len = entry.len,
                    ?data_path,
                    kind,
                    "sidecar payload range overflows"
                );
                return None;
            }
        };
        if entry_end > data_len {
            iroha_logger::warn!(
                height,
                offset = entry.offset,
                len = entry.len,
                data_len,
                ?data_path,
                kind,
                "sidecar entry points past data file"
            );
            return None;
        }
        if height > layout.base_height {
            let prev_height = height - 1;
            let Some(prev_pos) = layout.entry_position(prev_height) else {
                iroha_logger::warn!(
                    height,
                    prev_height,
                    ?index_path,
                    kind,
                    "sidecar previous index position is unrepresentable"
                );
                return None;
            };
            let mut prev_buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
            if index
                .seek(SeekFrom::Start(prev_pos))
                .and_then(|_| index.read_exact(&mut prev_buf))
                .is_err()
            {
                iroha_logger::warn!(
                    height,
                    ?index_path,
                    kind,
                    "failed to read previous sidecar index entry"
                );
                return None;
            }
            let prev = SidecarIndexEntry::from_bytes(prev_buf);
            if prev.len > 0 {
                let Some(prev_end) = prev.offset.checked_add(prev.len) else {
                    iroha_logger::warn!(
                        height,
                        prev_offset = prev.offset,
                        prev_len = prev.len,
                        ?index_path,
                        kind,
                        "previous sidecar payload range overflows"
                    );
                    return None;
                };
                if prev_end <= data_len && entry.offset < prev_end && entry_end > prev.offset {
                    iroha_logger::warn!(
                        height,
                        prev_offset = prev.offset,
                        prev_len = prev.len,
                        offset = entry.offset,
                        len = entry.len,
                        ?index_path,
                        kind,
                        "sidecar index entry overlaps previous payload; skipping"
                    );
                    return None;
                }
            }
        }
        let mut payload = vec![0u8; len_usize];
        if data
            .seek(SeekFrom::Start(entry.offset))
            .and_then(|_| data.read_exact(&mut payload))
            .is_err()
        {
            iroha_logger::warn!(height, ?data_path, kind, "failed to read sidecar payload");
            return None;
        }
        match decoder(&payload) {
            Ok(sidecar) => Some(sidecar),
            Err(err) => {
                iroha_logger::warn!(?err, height, ?data_path, kind, "failed to decode sidecar");
                None
            }
        }
    }
}

/// Original notification custody through queued diagnostic writers.
#[cfg(test)]
mod original_queued_sidecar_release_tests {
    include!("queued_sidecar_release_tests.rs");
}
