impl State {
    /// Return a handle to the original State-owned execution allocation pool.
    ///
    /// Cloning this handle preserves pool identity across pipeline reloads;
    /// observed counters do not grant an execution reservation. Accessing the
    /// immutable owner acquires no cache lock or notifying reader.
    pub fn ivm_execution_budget(&self) -> iroha_allocation::AllocationBudget {
        self.ivm_execution_budget.clone()
    }

    /// Install complete pipeline settings, validity values included.
    ///
    /// Test and fixture builds only: the caller owns the whole policy of an
    /// isolated State. A node has no way to call this; it uses
    /// [`Self::install_node_pipeline`], which takes local resource settings
    /// only. A committed pipeline validity policy still overrides the validity
    /// values installed here in every view and block.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn set_pipeline(&mut self, pipeline: iroha_config::parameters::actual::Pipeline) {
        self.install_pipeline_settings(pipeline);
    }

    /// Edit the installed pipeline settings of a fixture State in place.
    ///
    /// Test and fixture builds only. The edited value is installed through
    /// [`Self::set_pipeline`], so the caches and pools that follow the
    /// settings are sized again; the settings field itself has no other
    /// writer.
    #[cfg(any(test, feature = "iroha-core-tests"))]
    pub fn edit_pipeline_for_testing(
        &mut self,
        edit: impl FnOnce(&mut iroha_config::parameters::actual::Pipeline),
    ) {
        let mut pipeline = self.pipeline.clone();
        edit(&mut pipeline);
        self.set_pipeline(pipeline);
    }

    /// Install the pipeline settings of this node's own configuration.
    ///
    /// Only local resource settings (workers, caches, tracing, accelerator
    /// selection, signature batching and the default cursor mode) are taken from
    /// `node`. Fee policy comes only from committed parameters. Every execution
    /// limit is the committed pipeline validity policy
    /// ([`crate::pipeline_validity_policy::PipelineValidityPolicyV1`]) when
    /// the restored World already holds one, and the protocol default
    /// otherwise; a policy committed later governs the blocks after it. A node
    /// configuration therefore cannot change which transaction, program or
    /// query this validator accepts. Returns the names of the validity fields
    /// `node` held with a non-default value, which were ignored.
    ///
    /// # Errors
    ///
    /// Returns an error if the typed committed execution limits fail validation.
    /// The parameter owner already validates raw fee/limit bytes during mutation
    /// and restore; this installation performs no resource-sensitive decoding.
    pub fn install_node_pipeline(
        &mut self,
        node: iroha_config::parameters::actual::Pipeline,
    ) -> core::result::Result<
        Vec<&'static str>,
        crate::pipeline_validity_policy::PipelineValidityPolicyError,
    > {
        self.world.parameters.view().pipeline_policy().validate()?;
        let ignored = crate::pipeline_validity_policy::node_validity_overrides(&node);
        self.install_pipeline_settings(crate::pipeline_validity_policy::node_local_resources(node));
        Ok(ignored)
    }

    /// Store `pipeline` and size the caches and pools that follow it.
    fn install_pipeline_settings(&mut self, pipeline: iroha_config::parameters::actual::Pipeline) {
        let execution_budget = self.ivm_execution_budget();
        self.pipeline = pipeline;
        self.pipeline_parallelism = PipelineParallelism::new(&self.pipeline);
        self.stateless_validation_cache
            .lock()
            .set_cap(self.pipeline.stateless_cache_cap);
        // Keep all former borrowers and fresh caches on the same original
        // budget. A reload may shrink below already reserved bytes; that only
        // defers new local admission until the final old borrower releases.
        // The scope holds refund wakes until all physical cache guards drop.
        execution_budget.with_deferred_refund_notifications(|_| {
            execution_budget.set_limit_bytes(self.pipeline.ivm_execution_max_bytes);
            *self.trigger_ivm_cache.lock() = IvmCache::with_prepared_contract_cache(
                self.pipeline.cache_size,
                PreparedContractCache::with_execution_budget(
                    self.pipeline.cache_size,
                    execution_budget.clone(),
                ),
            );
            *self.contract_query_ivm_cache.lock() = IvmCache::with_prepared_contract_cache(
                self.pipeline.cache_size,
                PreparedContractCache::with_execution_budget(
                    self.pipeline.cache_size,
                    execution_budget.clone(),
                ),
            );
            *self.pipeline_ivm_prepared_cache.write() =
                PreparedContractCache::with_execution_budget(
                    self.pipeline.cache_size,
                    execution_budget.clone(),
                );
        });
        // Configure the IVM global pre-decode cache from pipeline settings.
        ivm::ivm_cache::configure_limits(ivm::ivm_cache::CacheLimits {
            capacity: self.pipeline.cache_size,
            max_bytes: self.pipeline.ivm_cache_max_bytes,
            max_decoded_ops: self.pipeline.ivm_cache_max_decoded_ops,
        });
        ivm::zk::set_prover_threads(self.pipeline.ivm_prover_threads);
    }

    #[inline]
    pub(crate) fn stateless_validation_cache(
        &self,
    ) -> &parking_lot::Mutex<StatelessValidationCache> {
        &self.stateless_validation_cache
    }

    /// Update oracle aggregation preferences.
    pub fn set_oracle(&mut self, oracle: iroha_config::parameters::actual::Oracle) {
        self.oracle = oracle;
    }

    /// Update settlement configuration snapshot and rebuild the router engine.
    pub fn set_settlement(&mut self, settlement: iroha_config::parameters::actual::Settlement) {
        self.settlement = settlement;
        self.settlement_engine = SettlementEngine::from_router_config(&self.settlement.router);
    }

    /// Current settlement configuration snapshot.
    #[must_use]
    pub fn settlement(&self) -> &iroha_config::parameters::actual::Settlement {
        &self.settlement
    }

    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Update Nexus configuration snapshot.
    ///
    /// # Errors
    ///
    /// Returns a `LaneLifecycleError` if lanes reference unknown dataspaces,
    /// routing policy targets cannot resolve, or geometry updates cannot be
    /// applied to the current state. A textual dataspace namespace also cannot
    /// be retired until all asset-definition alias bindings in that namespace
    /// are explicitly cleared. Configured catalog baselines are retained; effective
    /// dataspaces must equal that baseline plus protected runtime additions. Establish
    /// a pre-genesis baseline through [`Self::set_nexus_from_config`].
    pub fn set_nexus(
        &mut self,
        mut nexus: iroha_config::parameters::actual::Nexus,
    ) -> Result<(), LaneLifecycleError> {
        self.ensure_config_catalog_mutation_is_pre_genesis(&nexus.lane_catalog, false)?;
        let installed = self.nexus_snapshot();
        // Evidence preparation is process-local configured custody. Runtime
        // catalog updates cannot replace its finite pool or reset live credits.
        nexus.storage.consensus_evidence_preparation_bytes =
            installed.storage.consensus_evidence_preparation_bytes;
        nexus.storage.consensus_stake_index_bytes = installed.storage.consensus_stake_index_bytes;
        nexus.configured_dataspace_catalog = installed.configured_dataspace_catalog.clone();
        let runtime = runtime_catalog_from_world(&self.world.view())?;
        if let Some(runtime) = runtime.as_ref() {
            let expected =
                runtime_catalog_dataspaces(&nexus.configured_dataspace_catalog, Some(runtime))?;
            if nexus.dataspace_catalog != expected {
                return Err(runtime_catalog_invalid(
                    "runtime Nexus setter cannot change committed physical dataspaces",
                ));
            }
        } else if nexus.dataspace_catalog != nexus.configured_dataspace_catalog {
            // Reject before geometry or any runtime publication: this setter
            // cannot establish a second physical catalog authority even at H0.
            return Err(runtime_catalog_invalid(
                "ordinary Nexus setter cannot change the physical dataspace baseline; use set_nexus_from_config before genesis",
            ));
        }
        let configured_lane_catalog = installed.configured_lane_catalog;
        self.set_nexus_with_configured_lane_catalog(nexus, configured_lane_catalog, None)
    }
}

#[cfg(test)]
mod runtime_configuration_tests {
    use super::*;
    include!("runtime_configuration_tests.rs");
}
