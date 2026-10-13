impl ValidQueryRequest {
    /// Validate a query for an API client by calling the executor.
    ///
    /// # Errors
    ///
    /// Returns an error if the query validation fails or request limits are exceeded.
    pub(crate) fn validate_for_client_parts(
        request: QueryRequest,
        authority: &AccountId,
        state_ro: &impl StateReadOnly,
        limits: QueryLimits,
    ) -> Result<Self, ValidationFail> {
        let latest_block = state_ro
            .latest_block()
            .map_err(|error| match error {
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
                    ValidationFail::QueryFailed(
                        iroha_data_model::query::error::QueryExecutionFail::CanonicalHistory(error),
                    )
                }
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    ValidationFail::InternalError(format!("query execution unavailable: {reason}"))
                }
            })?
            .map(|block| block.header());
        Self::validate_for_client_world_parts(
            request,
            authority,
            state_ro.world(),
            latest_block.as_ref(),
            limits,
            &state_ro.execution_budget(),
        )
    }
    /// Validate a query for an API client using world-state and latest committed block header.
    ///
    /// # Errors
    ///
    /// Returns an error if the query validation fails or request limits are exceeded.
    pub(crate) fn validate_for_client_world_parts(
        request: QueryRequest,
        authority: &AccountId,
        world_ro: &impl WorldReadOnly,
        latest_block: Option<&BlockHeader>,
        limits: QueryLimits,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Self, ValidationFail> {
        validate_query_request_limits(&request, limits)?;
        world_ro
            .executor()
            .validate_query_with_world_parts(world_ro, latest_block, authority, &request, budget)
            .map_err(|error| match error {
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                // API-client queries have no transaction output. Report an operational
                // internal error here; the IVM path below keeps the typed retry reason.
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    ValidationFail::InternalError(format!("query execution unavailable: {reason}"))
                }
            })?;
        Ok(Self { request, limits })
    }
    /// Validate a query for an IVM program.
    ///
    /// The host validator binds the query to the current authority and rejects
    /// continuation cursors, which are unavailable during IVM execution.
    ///
    /// # Errors
    /// Returns a validation error if the request is rejected by the IVM validator.
    pub(crate) fn validate_for_ivm(
        query: QueryRequest,
        state: &mut impl IvmQueryValidator,
        limits: QueryLimits,
    ) -> Result<Self, crate::execution_attempt::ExecutionAttemptError<ValidationFail>> {
        if matches!(&query, QueryRequest::Continue(_)) {
            return Err(ValidationFail::NotPermitted(
                "QueryRequest::Continue is not supported in IVM".to_string(),
            )
            .into());
        }
        validate_query_request_limits(&query, limits)?;
        let authority = state.authority().clone();
        state.validate_query(&authority, &query)?;
        Ok(Self {
            request: query,
            limits,
        })
    }
    /// Execute a validated query request.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    pub(crate) fn execute(
        self,
        live_query_store: &LiveQueryStoreHandle,
        state: &impl StateReadOnly,
        authority: &AccountId,
    ) -> Result<QueryResponse, Error> {
        self.execute_stored_and_bind_revalidation(live_query_store, state, authority, None, None)
    }
    /// Execute a validated query request with an optional state handle for
    /// bounded stored cursors that can replay one continuation page at a time.
    ///
    /// # Errors
    ///
    /// Returns an error if the query execution fails.
    #[cfg(test)]
    pub(crate) fn execute_with_replay_state(
        self,
        live_query_store: &LiveQueryStoreHandle,
        state: &impl StateReadOnly,
        authority: &AccountId,
        replay_state: Weak<State>,
    ) -> Result<QueryResponse, Error> {
        self.execute_stored_and_bind_revalidation(
            live_query_store,
            state,
            authority,
            Some(replay_state),
            None,
        )
    }
    /// Execute a validated stored query with an owning replay state and the
    /// client-provided budget for the initial `Start` request.
    ///
    /// # Errors
    ///
    /// Returns an error if query execution or budgeted projection fails.
    pub(crate) fn execute_with_replay_state_and_start_budget(
        self,
        live_query_store: &LiveQueryStoreHandle,
        state: &impl StateReadOnly,
        authority: &AccountId,
        replay_state: Weak<State>,
        stored_start_budget: Option<u64>,
    ) -> Result<QueryResponse, Error> {
        self.execute_stored_and_bind_revalidation(
            live_query_store,
            state,
            authority,
            Some(replay_state),
            stored_start_budget,
        )
    }
    fn execute_stored_and_bind_revalidation(
        self,
        live_query_store: &LiveQueryStoreHandle,
        state: &impl StateReadOnly,
        authority: &AccountId,
        replay_state: Option<Weak<State>>,
        stored_start_budget: Option<u64>,
    ) -> Result<QueryResponse, Error> {
        if let Some(ordinary_limits) = self.limits.ordinary_execution_limits {
            ordinary_memory::ensure_request_admitted(
                &self.request,
                ordinary_memory::OrdinaryCursorMode::Stored,
                self.limits,
                ordinary_limits,
            )?;
        }
        let revalidation_limit = self
            .limits
            .ordinary_execution_limits
            .map(OrdinaryQueryExecutionLimits::max_revalidation_archive_bytes);
        let revalidation_archive = matches!(&self.request, QueryRequest::Start(_))
            .then(|| encode_stored_query_revalidation_request(&self.request, revalidation_limit))
            .transpose()?;
        let response = self.execute_stored_inner(
            live_query_store,
            state,
            authority,
            replay_state,
            stored_start_budget,
        )?;
        if let (
            Some(archive),
            QueryResponse::Iterable(QueryOutput {
                continue_cursor: Some(cursor),
                ..
            }),
        ) = (revalidation_archive, &response)
            && let Err(error) =
                live_query_store.bind_revalidation_request(cursor, authority, archive)
        {
            live_query_store.drop_query(&cursor.query);
            return Err(error);
        }
        Ok(response)
    }
    #[allow(clippy::too_many_lines)] // Dispatch must enumerate every canonical item/query variant.
    fn execute_stored_inner(
        self,
        live_query_store: &LiveQueryStoreHandle,
        state: &impl StateReadOnly,
        authority: &AccountId,
        replay_state: Option<Weak<State>>,
        stored_start_budget: Option<u64>,
    ) -> Result<QueryResponse, Error> {
        let Self { request, limits } = self;
        match request {
            QueryRequest::Singular(singular_query) => {
                let output = singular_query
                    .execute(state)
                    .map_err(query_transport_error)?;
                Ok(QueryResponse::Singular(output))
            }
            QueryRequest::Start(iter_query) => {
                use iroha_data_model::query::QueryItemKind;
                let params = iter_query.params();
                let (item, predicate_bytes, selector_bytes, query_payload) = iter_query.parts();
                let stored_cursor_budget = {
                    let min = state.pipeline().query_stored_min_gas_units;
                    stored_start_budget.or_else(|| (min > 0).then_some(min))
                };
                // Canonical path: reconstruct typed components from the item kind and
                // encoded query, predicate, and selector payloads.
                let mut decoder = FastIterComponentDecoder::new(
                    limits,
                    [query_payload, predicate_bytes, selector_bytes],
                )?;
                macro_rules! run_query {
                    ($itemty:ty, $find:ty, $decoder:ident, $predicate_bytes:ident, $selector_bytes:ident, $query_payload:ident, $params:ident, $stored_cursor_budget:ident) => {{
                        let pred: iroha_data_model::query::dsl::CompoundPredicate<$itemty> =
                            $decoder.decode($predicate_bytes)?;
                        let sel: iroha_data_model::query::dsl::SelectorTuple<$itemty> =
                            $decoder.decode($selector_bytes)?;
                        let concrete: $find = $decoder.decode($query_payload)?;
                        let (iter, source_stats) = execute_iterable_source(
                            concrete,
                            pred,
                            $params,
                            limits,
                            ordinary_memory::OrdinaryCursorMode::Stored,
                            state,
                        )
                        .map_err(query_transport_error)?;
                        let output = handle_iter_start_stored_replayable(
                            iter,
                            sel,
                            $params,
                            limits,
                            live_query_store,
                            authority,
                            $stored_cursor_budget,
                            replay_state.clone(),
                            source_stats,
                        )?;
                        return Ok(QueryResponse::Iterable(output));
                    }};
                }
                match item {
                    QueryItemKind::Domain => {
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::domain::Domain,
                                iroha_data_model::query::domain::prelude::FindDomainsByAccountId,
                                decoder,
                                predicate_bytes,
                                selector_bytes,
                                query_payload,
                                params,
                                stored_cursor_budget
                            )
                        }
                        run_query!(
                            iroha_data_model::domain::Domain,
                            iroha_data_model::query::domain::prelude::FindDomains,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params,
                            stored_cursor_budget
                        )
                    }
                    QueryItemKind::Account => {
                        // Prefer parameterized query when payload is present; otherwise default.
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::account::Account,
                                iroha_data_model::query::account::prelude::FindAccountsWithAsset,
                                decoder,
                                predicate_bytes,
                                selector_bytes,
                                query_payload,
                                params,
                                stored_cursor_budget
                            )
                        }
                        run_query!(
                            iroha_data_model::account::Account,
                            iroha_data_model::query::account::prelude::FindAccounts,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params,
                            stored_cursor_budget
                        )
                    }
                    QueryItemKind::AccountId => run_query!(
                        iroha_data_model::account::AccountId,
                        iroha_data_model::query::account::prelude::FindAccountIds,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::Asset => {
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::asset::value::Asset,
                                iroha_data_model::query::asset::prelude::FindAssetsByAccountId,
                                decoder,
                                predicate_bytes,
                                selector_bytes,
                                query_payload,
                                params,
                                stored_cursor_budget
                            )
                        }
                        run_query!(
                            iroha_data_model::asset::value::Asset,
                            iroha_data_model::query::asset::prelude::FindAssets,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params,
                            stored_cursor_budget
                        )
                    }
                    QueryItemKind::AssetDefinition => run_query!(
                        iroha_data_model::asset::definition::AssetDefinition,
                        iroha_data_model::query::asset::prelude::FindAssetDefinitions,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::RepoAgreement => run_query!(
                        iroha_data_model::repo::RepoAgreement,
                        iroha_data_model::query::repo::prelude::FindRepoAgreements,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::Nft => {
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::nft::Nft,
                                iroha_data_model::query::nft::prelude::FindNftsByAccountId,
                                decoder,
                                predicate_bytes,
                                selector_bytes,
                                query_payload,
                                params,
                                stored_cursor_budget
                            )
                        }
                        run_query!(
                            iroha_data_model::nft::Nft,
                            iroha_data_model::query::nft::prelude::FindNfts,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params,
                            stored_cursor_budget
                        )
                    }
                    QueryItemKind::Rwa => run_query!(
                        iroha_data_model::rwa::Rwa,
                        iroha_data_model::query::rwa::prelude::FindRwas,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::Role => run_query!(
                        iroha_data_model::role::Role,
                        iroha_data_model::query::role::prelude::FindRoles,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::RoleId => {
                        // If payload present, it's a parameterized FindRolesByAccountId; otherwise use FindRoleIds.
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::role::RoleId,
                                iroha_data_model::query::role::prelude::FindRolesByAccountId,
                                decoder,
                                predicate_bytes,
                                selector_bytes,
                                query_payload,
                                params,
                                stored_cursor_budget
                            )
                        }
                        run_query!(
                            iroha_data_model::role::RoleId,
                            iroha_data_model::query::role::prelude::FindRoleIds,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params,
                            stored_cursor_budget
                        )
                    }
                    QueryItemKind::PeerId => run_query!(
                        iroha_model_base::peer::PeerId,
                        iroha_data_model::query::peer::prelude::FindPeers,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::TriggerId => run_query!(
                        iroha_data_model::trigger::TriggerId,
                        iroha_data_model::query::trigger::prelude::FindActiveTriggerIds,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::Trigger => run_query!(
                        iroha_data_model::trigger::Trigger,
                        iroha_data_model::query::trigger::prelude::FindTriggers,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::CommittedTransaction => {
                        let _concrete = decoder.decode::<
                                    iroha_data_model::query::transaction::prelude::FindTransactions,
                                >(query_payload)
                                ?;
                        let pred = decoder
                            .decode::<CompoundPredicate<CommittedTransaction>>(predicate_bytes)?;
                        let sel = decoder
                            .decode::<SelectorTuple<CommittedTransaction>>(selector_bytes)?;
                        let output = handle_find_transactions_stored(
                            state,
                            pred,
                            sel,
                            params,
                            limits,
                            live_query_store,
                            authority,
                            stored_cursor_budget,
                            replay_state.clone(),
                        )?;
                        return Ok(QueryResponse::Iterable(output));
                    }
                    QueryItemKind::SignedBlock => run_query!(
                        iroha_data_model::block::SignedBlock,
                        iroha_data_model::query::block::prelude::FindBlocks,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::BlockHeader => run_query!(
                        iroha_data_model::block::BlockHeader,
                        iroha_data_model::query::block::prelude::FindBlockHeaders,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::ProofRecord => {
                        if limits.canonical_output_limits.is_some() {
                            return Err(Error::Conversion(
                                        "canonical fanout rejects proof queries before source execution because their implementations are not protocol-bounded"
                                            .to_owned(),
                                    ));
                        }
                        let pred = decoder
                            .decode::<iroha_data_model::query::dsl::CompoundPredicate<
                                iroha_data_model::proof::ProofRecord,
                            >>(predicate_bytes)?;
                        let sel = decoder.decode::<iroha_data_model::query::dsl::SelectorTuple<
                            iroha_data_model::proof::ProofRecord,
                        >>(selector_bytes)?;
                        macro_rules! try_proof_query {
                            ($find:ty, $pred:ident, $sel:ident) => {{
                                if let Some(concrete) =
                                    decoder.try_decode::<$find>(query_payload)?
                                {
                                    let (iter, source_stats) = execute_iterable_source(
                                        concrete,
                                        $pred,
                                        params,
                                        limits,
                                        ordinary_memory::OrdinaryCursorMode::Stored,
                                        state,
                                    )
                                    .map_err(query_transport_error)?;
                                    let output = handle_iter_start_stored_replayable(
                                        iter,
                                        $sel,
                                        params,
                                        limits,
                                        live_query_store,
                                        authority,
                                        stored_cursor_budget,
                                        replay_state.clone(),
                                        source_stats,
                                    )?;
                                    return Ok(QueryResponse::Iterable(output));
                                }
                            }};
                        }
                        if !query_payload.is_empty() {
                            try_proof_query!(
                                iroha_data_model::query::proof::prelude::FindProofRecordsByBackend,
                                pred,
                                sel
                            );
                            try_proof_query!(
                                iroha_data_model::query::proof::prelude::FindProofRecordsByStatus,
                                pred,
                                sel
                            );
                            return Err(Error::Conversion(
                                "failed to decode proof query payload".into(),
                            ));
                        }
                        let concrete = decoder
                            .decode::<iroha_data_model::query::proof::prelude::FindProofRecords>(
                            query_payload,
                        )?;
                        let (iter, source_stats) = execute_iterable_source(
                            concrete,
                            pred,
                            params,
                            limits,
                            ordinary_memory::OrdinaryCursorMode::Stored,
                            state,
                        )
                        .map_err(query_transport_error)?;
                        let output = handle_iter_start_stored_replayable(
                            iter,
                            sel,
                            params,
                            limits,
                            live_query_store,
                            authority,
                            stored_cursor_budget,
                            replay_state.clone(),
                            source_stats,
                        )?;
                        return Ok(QueryResponse::Iterable(output));
                    }
                    QueryItemKind::AssetEscrowRecord => run_query!(
                        iroha_data_model::escrow::AssetEscrowRecord,
                        iroha_data_model::query::escrow::prelude::FindAssetEscrows,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::AssetEscrowsBySeller => run_query!(
                        iroha_data_model::escrow::AssetEscrowRecord,
                        iroha_data_model::query::escrow::prelude::FindAssetEscrowsBySeller,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::AssetEscrowsByBuyer => run_query!(
                        iroha_data_model::escrow::AssetEscrowRecord,
                        iroha_data_model::query::escrow::prelude::FindAssetEscrowsByBuyer,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::AssetEscrowsByStatus => run_query!(
                        iroha_data_model::escrow::AssetEscrowRecord,
                        iroha_data_model::query::escrow::prelude::FindAssetEscrowsByStatus,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::OracleFeedConfig => run_query!(
                        iroha_data_model::oracle::FeedConfig,
                        iroha_data_model::query::oracle::prelude::FindOracleFeeds,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::OracleFeedEventRecord => {
                        run_query!(
                            iroha_data_model::events::data::oracle::FeedEventRecord,
                            iroha_data_model::query::oracle::prelude::FindOracleHistoryByFeedId,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params,
                            stored_cursor_budget
                        )
                    }
                    QueryItemKind::OracleProviderStatsRecord => {
                        run_query!(iroha_data_model::oracle::OracleProviderStatsRecord, iroha_data_model::query::oracle::prelude::FindOracleProviderStatsByFeedId, decoder, predicate_bytes, selector_bytes, query_payload, params, stored_cursor_budget)
                    }
                    QueryItemKind::OracleDispute => {
                        if !query_payload.is_empty() {
                            run_query!(
                                        iroha_data_model::oracle::OracleDispute,
                                        iroha_data_model::query::oracle::prelude::FindOracleDisputesByFeedId, decoder, predicate_bytes, selector_bytes, query_payload, params, stored_cursor_budget)
                        }
                        run_query!(
                            iroha_data_model::oracle::OracleDispute,
                            iroha_data_model::query::oracle::prelude::FindOracleDisputes,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params,
                            stored_cursor_budget
                        )
                    }
                    QueryItemKind::OracleChangeProposal => run_query!(
                        iroha_data_model::oracle::OracleChangeProposal,
                        iroha_data_model::query::oracle::prelude::FindOracleChanges,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                    QueryItemKind::TwitterBindingRecord => {
                        run_query!(
                            iroha_data_model::oracle::TwitterBindingRecord,
                            iroha_data_model::query::oracle::prelude::FindTwitterBindingsByUaid,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params,
                            stored_cursor_budget
                        )
                    }
                    QueryItemKind::DefiOracleAttestation => {
                        run_query!(iroha_data_model::oracle::DefiOracleAttestation, iroha_data_model::query::oracle::prelude::FindDefiOracleAttestationsByKey, decoder, predicate_bytes, selector_bytes, query_payload, params, stored_cursor_budget)
                    }
                    QueryItemKind::Permission => {
                        run_query!(iroha_data_model::permission::Permission, iroha_data_model::query::permission::prelude::FindPermissionsByAccountId, decoder, predicate_bytes, selector_bytes, query_payload, params, stored_cursor_budget)
                    }
                    QueryItemKind::FeeSponsorProgram => {
                        if !query_payload.is_empty() {
                            run_query!(iroha_data_model::nexus::FeeSponsorProgram, iroha_data_model::query::nexus::prelude::FindFeeSponsorProgramsBySponsor, decoder, predicate_bytes, selector_bytes, query_payload, params, stored_cursor_budget)
                        }
                        run_query!(
                            iroha_data_model::nexus::FeeSponsorProgram,
                            iroha_data_model::query::nexus::prelude::FindFeeSponsorPrograms,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params,
                            stored_cursor_budget
                        )
                    }
                    QueryItemKind::FeeSponsorProgramId => run_query!(
                        iroha_data_model::nexus::FeeSponsorProgramId,
                        iroha_data_model::query::nexus::prelude::FindFeeSponsorProgramIds,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params,
                        stored_cursor_budget
                    ),
                }
            }
            QueryRequest::Continue(cursor) => Ok(QueryResponse::Iterable(
                live_query_store.handle_iter_continue(cursor, authority)?,
            )),
        }
    }
    /// Execute a validated query request using an ephemeral iterator for iterable queries.
    ///
    /// Iterable queries return only the first batch and do not allocate a
    /// reusable cursor in the [`LiveQueryStore`]. Suitable for snapshot-bound
    /// contexts where queries must not outlive the captured view.
    ///
    /// # Errors
    /// Returns an error if the query execution fails.
    pub(crate) fn execute_ephemeral(
        self,
        live_query_store: &LiveQueryStoreHandle,
        state: &impl StateReadOnly,
        authority: &AccountId,
    ) -> Result<QueryResponse, Error> {
        self.execute_ephemeral_with_stats(live_query_store, state, authority, None)
            .map(|(response, _)| response)
            .map_err(query_transport_error)
    }
    pub(crate) fn execute_ephemeral_with_stats(
        self,
        live_query_store: &LiveQueryStoreHandle,
        state: &impl StateReadOnly,
        authority: &AccountId,
        budget: Option<QueryExecutionBudget>,
    ) -> Result<(QueryResponse, QueryExecutionStats), QueryAttemptError> {
        let effective_budget = self
            .limits
            .ordinary_execution_limits
            .map(OrdinaryQueryExecutionLimits::execution_budget)
            .or(budget);
        let (response, mut execution_stats) =
            self.execute_ephemeral_inner_with_stats(live_query_store, state, authority, budget)?;
        execution_stats.record_response(&response, effective_budget)?;
        Ok((response, execution_stats))
    }
    #[allow(clippy::too_many_lines)]
    fn execute_ephemeral_inner_with_stats(
        self,
        _live_query_store: &LiveQueryStoreHandle,
        state: &impl StateReadOnly,
        _authority: &AccountId,
        budget: Option<QueryExecutionBudget>,
    ) -> Result<(QueryResponse, QueryExecutionStats), QueryAttemptError> {
        let Self { request, limits } = self;
        if let Some(ordinary_limits) = limits.ordinary_execution_limits {
            ordinary_memory::ensure_request_admitted(
                &request,
                ordinary_memory::OrdinaryCursorMode::Ephemeral,
                limits,
                ordinary_limits,
            )?;
        }
        let budget = limits
            .ordinary_execution_limits
            .map(OrdinaryQueryExecutionLimits::execution_budget)
            .or(budget);
        let budget_items = budget;
        match request {
            QueryRequest::Singular(singular_query) => {
                let mut execution_stats = QueryExecutionStats::default();
                let output =
                    singular_memory::execute_with_limits(limits.singular_output_limits, || {
                        // Install the singular allocation guard before source
                        // preflight. Some source adapters validate persisted
                        // records while measuring them, and those decodes must
                        // receive the same resident D ceiling as execution.
                        if limits.server_memory_budget
                            && let Some(server_budget) = budget
                        {
                            let source_bytes =
                                ordinary_memory::preflight_server_singular_source_materialization(
                                    &singular_query,
                                    state,
                                    server_budget,
                                    limits.singular_output_limits.is_some(),
                                )?;
                            execution_stats
                                .record_preflighted_item(source_bytes, Some(server_budget))?;
                        }
                        singular_query.execute(state)
                    })?;
                execution_stats.record_value_bytes(&output, budget)?;
                Ok((QueryResponse::Singular(output), execution_stats))
            }
            QueryRequest::Start(iter_query) => {
                use iroha_data_model::query::QueryItemKind;
                let params = iter_query.params();
                // Canonical path: reconstruct the typed query from the item kind and
                // encoded query, predicate, and selector components.
                if limits.canonical_output_limits.is_some() {
                    return Err(Error::Conversion(
                        "canonical fanout rejects opaque canonical starts before nested payload, predicate, or selector decoding"
                            .to_owned(),
                    ).into());
                }
                let (item, predicate_bytes, selector_bytes, query_payload) = iter_query.parts();
                let mut decoder = FastIterComponentDecoder::new(
                    limits,
                    [query_payload, predicate_bytes, selector_bytes],
                )?;
                macro_rules! run_query {
                    ($itemty:ty, $find:ty, $decoder:ident, $predicate_bytes:ident, $selector_bytes:ident, $query_payload:ident, $params:ident) => {{
                        let concrete: $find = $decoder.decode($query_payload)?;
                        let pred: iroha_data_model::query::dsl::CompoundPredicate<$itemty> =
                            $decoder.decode($predicate_bytes)?;
                        let sel: iroha_data_model::query::dsl::SelectorTuple<$itemty> =
                            $decoder.decode($selector_bytes)?;
                        let (iter, source_stats) = execute_iterable_source(
                            concrete,
                            pred,
                            $params,
                            limits,
                            ordinary_memory::OrdinaryCursorMode::Ephemeral,
                            state,
                        )?;
                        let (output, processed_items) =
                            apply_query_postprocessing_ephemeral_with_budget_from_stats(
                                iter,
                                sel,
                                $params,
                                limits,
                                budget_items,
                                source_stats,
                            )?;
                        return Ok((QueryResponse::Iterable(output), processed_items));
                    }};
                }
                match item {
                    QueryItemKind::Domain => {
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::domain::Domain,
                                iroha_data_model::query::domain::prelude::FindDomainsByAccountId,
                                decoder,
                                predicate_bytes,
                                selector_bytes,
                                query_payload,
                                params
                            )
                        }
                        run_query!(
                            iroha_data_model::domain::Domain,
                            iroha_data_model::query::domain::prelude::FindDomains,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params
                        )
                    }
                    QueryItemKind::Account => {
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::account::Account,
                                iroha_data_model::query::account::prelude::FindAccountsWithAsset,
                                decoder,
                                predicate_bytes,
                                selector_bytes,
                                query_payload,
                                params
                            )
                        }
                        run_query!(
                            iroha_data_model::account::Account,
                            iroha_data_model::query::account::prelude::FindAccounts,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params
                        )
                    }
                    QueryItemKind::AccountId => run_query!(
                        iroha_data_model::account::AccountId,
                        iroha_data_model::query::account::prelude::FindAccountIds,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::Asset => {
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::asset::value::Asset,
                                iroha_data_model::query::asset::prelude::FindAssetsByAccountId,
                                decoder,
                                predicate_bytes,
                                selector_bytes,
                                query_payload,
                                params
                            )
                        }
                        run_query!(
                            iroha_data_model::asset::value::Asset,
                            iroha_data_model::query::asset::prelude::FindAssets,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params
                        )
                    }
                    QueryItemKind::AssetDefinition => run_query!(
                        iroha_data_model::asset::definition::AssetDefinition,
                        iroha_data_model::query::asset::prelude::FindAssetDefinitions,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::RepoAgreement => run_query!(
                        iroha_data_model::repo::RepoAgreement,
                        iroha_data_model::query::repo::prelude::FindRepoAgreements,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::Nft => {
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::nft::Nft,
                                iroha_data_model::query::nft::prelude::FindNftsByAccountId,
                                decoder,
                                predicate_bytes,
                                selector_bytes,
                                query_payload,
                                params
                            )
                        }
                        run_query!(
                            iroha_data_model::nft::Nft,
                            iroha_data_model::query::nft::prelude::FindNfts,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params
                        )
                    }
                    QueryItemKind::Rwa => run_query!(
                        iroha_data_model::rwa::Rwa,
                        iroha_data_model::query::rwa::prelude::FindRwas,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::Role => run_query!(
                        iroha_data_model::role::Role,
                        iroha_data_model::query::role::prelude::FindRoles,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::RoleId => {
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::role::RoleId,
                                iroha_data_model::query::role::prelude::FindRolesByAccountId,
                                decoder,
                                predicate_bytes,
                                selector_bytes,
                                query_payload,
                                params
                            )
                        }
                        run_query!(
                            iroha_data_model::role::RoleId,
                            iroha_data_model::query::role::prelude::FindRoleIds,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params
                        )
                    }
                    QueryItemKind::PeerId => run_query!(
                        iroha_model_base::peer::PeerId,
                        iroha_data_model::query::peer::prelude::FindPeers,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::TriggerId => run_query!(
                        iroha_data_model::trigger::TriggerId,
                        iroha_data_model::query::trigger::prelude::FindActiveTriggerIds,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::Trigger => run_query!(
                        iroha_data_model::trigger::Trigger,
                        iroha_data_model::query::trigger::prelude::FindTriggers,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::CommittedTransaction => {
                        let _concrete = decoder.decode::<
                                    iroha_data_model::query::transaction::prelude::FindTransactions,
                                >(query_payload)
                                ?;
                        let pred = decoder
                            .decode::<CompoundPredicate<CommittedTransaction>>(predicate_bytes)?;
                        let sel = decoder
                            .decode::<SelectorTuple<CommittedTransaction>>(selector_bytes)?;
                        let (output, processed_items) = handle_find_transactions_ephemeral(
                            state,
                            pred,
                            sel,
                            params,
                            limits,
                            budget_items,
                        )?;
                        return Ok((QueryResponse::Iterable(output), processed_items));
                    }
                    QueryItemKind::SignedBlock => run_query!(
                        iroha_data_model::block::SignedBlock,
                        iroha_data_model::query::block::prelude::FindBlocks,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::BlockHeader => run_query!(
                        iroha_data_model::block::BlockHeader,
                        iroha_data_model::query::block::prelude::FindBlockHeaders,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::ProofRecord => {
                        let pred = decoder
                            .decode::<iroha_data_model::query::dsl::CompoundPredicate<
                                iroha_data_model::proof::ProofRecord,
                            >>(predicate_bytes)?;
                        let sel = decoder.decode::<iroha_data_model::query::dsl::SelectorTuple<
                            iroha_data_model::proof::ProofRecord,
                        >>(selector_bytes)?;
                        macro_rules! try_proof_query {
                                    ($find:ty, $pred:ident, $sel:ident) => {{
                                        if let Some(concrete) = decoder
                                            .try_decode::<$find>(query_payload)?
                                        {
                                            let (iter, source_stats) = execute_iterable_source(
                                                concrete,
                                                $pred,
                                                params,
                                                limits,
                                                ordinary_memory::OrdinaryCursorMode::Ephemeral,
                                                state,
                                            )?;
                                            let (output, processed_items) =
                                                apply_query_postprocessing_ephemeral_with_budget_from_stats(
                                                    iter,
                                                    $sel,
                                                    params,
                                                    limits,
                                                    budget_items,
                                                    source_stats,
                                                )?;
                                            return Ok((
                                                QueryResponse::Iterable(output),
                                                processed_items,
                                            ));
                                        }
                                    }};
                                }
                        if !query_payload.is_empty() {
                            try_proof_query!(
                                iroha_data_model::query::proof::prelude::FindProofRecordsByBackend,
                                pred,
                                sel
                            );
                            try_proof_query!(
                                iroha_data_model::query::proof::prelude::FindProofRecordsByStatus,
                                pred,
                                sel
                            );
                            return Err(Error::Conversion(
                                "failed to decode proof query payload".into(),
                            )
                            .into());
                        }
                        let concrete = decoder
                            .decode::<iroha_data_model::query::proof::prelude::FindProofRecords>(
                            query_payload,
                        )?;
                        let (iter, source_stats) = execute_iterable_source(
                            concrete,
                            pred,
                            params,
                            limits,
                            ordinary_memory::OrdinaryCursorMode::Ephemeral,
                            state,
                        )?;
                        let (output, processed_items) =
                            apply_query_postprocessing_ephemeral_with_budget_from_stats(
                                iter,
                                sel,
                                params,
                                limits,
                                budget_items,
                                source_stats,
                            )?;
                        return Ok((QueryResponse::Iterable(output), processed_items));
                    }
                    QueryItemKind::AssetEscrowRecord => run_query!(
                        iroha_data_model::escrow::AssetEscrowRecord,
                        iroha_data_model::query::escrow::prelude::FindAssetEscrows,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::AssetEscrowsBySeller => run_query!(
                        iroha_data_model::escrow::AssetEscrowRecord,
                        iroha_data_model::query::escrow::prelude::FindAssetEscrowsBySeller,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::AssetEscrowsByBuyer => run_query!(
                        iroha_data_model::escrow::AssetEscrowRecord,
                        iroha_data_model::query::escrow::prelude::FindAssetEscrowsByBuyer,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::AssetEscrowsByStatus => run_query!(
                        iroha_data_model::escrow::AssetEscrowRecord,
                        iroha_data_model::query::escrow::prelude::FindAssetEscrowsByStatus,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::OracleFeedConfig => run_query!(
                        iroha_data_model::oracle::FeedConfig,
                        iroha_data_model::query::oracle::prelude::FindOracleFeeds,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::OracleFeedEventRecord => {
                        run_query!(
                            iroha_data_model::events::data::oracle::FeedEventRecord,
                            iroha_data_model::query::oracle::prelude::FindOracleHistoryByFeedId,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params
                        )
                    }
                    QueryItemKind::OracleProviderStatsRecord => {
                        run_query!(iroha_data_model::oracle::OracleProviderStatsRecord, iroha_data_model::query::oracle::prelude::FindOracleProviderStatsByFeedId, decoder, predicate_bytes, selector_bytes, query_payload, params)
                    }
                    QueryItemKind::OracleDispute => {
                        if !query_payload.is_empty() {
                            run_query!(
                                iroha_data_model::oracle::OracleDispute,
                                iroha_data_model::query::oracle::prelude::FindOracleDisputesByFeedId, decoder, predicate_bytes, selector_bytes, query_payload, params)
                        }
                        run_query!(
                            iroha_data_model::oracle::OracleDispute,
                            iroha_data_model::query::oracle::prelude::FindOracleDisputes,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params
                        )
                    }
                    QueryItemKind::OracleChangeProposal => run_query!(
                        iroha_data_model::oracle::OracleChangeProposal,
                        iroha_data_model::query::oracle::prelude::FindOracleChanges,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                    QueryItemKind::TwitterBindingRecord => {
                        run_query!(
                            iroha_data_model::oracle::TwitterBindingRecord,
                            iroha_data_model::query::oracle::prelude::FindTwitterBindingsByUaid,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params
                        )
                    }
                    QueryItemKind::DefiOracleAttestation => {
                        run_query!(iroha_data_model::oracle::DefiOracleAttestation, iroha_data_model::query::oracle::prelude::FindDefiOracleAttestationsByKey, decoder, predicate_bytes, selector_bytes, query_payload, params)
                    }
                    QueryItemKind::Permission => {
                        run_query!(iroha_data_model::permission::Permission, iroha_data_model::query::permission::prelude::FindPermissionsByAccountId, decoder, predicate_bytes, selector_bytes, query_payload, params)
                    }
                    QueryItemKind::FeeSponsorProgram => {
                        if !query_payload.is_empty() {
                            run_query!(iroha_data_model::nexus::FeeSponsorProgram, iroha_data_model::query::nexus::prelude::FindFeeSponsorProgramsBySponsor, decoder, predicate_bytes, selector_bytes, query_payload, params)
                        }
                        run_query!(
                            iroha_data_model::nexus::FeeSponsorProgram,
                            iroha_data_model::query::nexus::prelude::FindFeeSponsorPrograms,
                            decoder,
                            predicate_bytes,
                            selector_bytes,
                            query_payload,
                            params
                        )
                    }
                    QueryItemKind::FeeSponsorProgramId => run_query!(
                        iroha_data_model::nexus::FeeSponsorProgramId,
                        iroha_data_model::query::nexus::prelude::FindFeeSponsorProgramIds,
                        decoder,
                        predicate_bytes,
                        selector_bytes,
                        query_payload,
                        params
                    ),
                }
            }
            QueryRequest::Continue(_cursor) => Err(Error::Conversion(
                "ephemeral execution does not support continuation".into(),
            )
            .into()),
        }
    }
}
