/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/impl/command_service_impl.hpp"

#include "ametsuchi/block_query.hpp"
#include "common/byteutils.hpp"
#include "common/visitor.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/transaction.hpp"
#include "interfaces/transaction_responses/not_received_tx_response.hpp"
#include "logger/logger.hpp"
#include "torii/impl/final_status_value.hpp"

using iroha::torii::CommandServiceImpl;

CommandServiceImpl::CommandServiceImpl(
    std::shared_ptr<iroha::torii::TransactionProcessor> tx_processor,
    std::shared_ptr<iroha::torii::StatusBus> status_bus,
    std::shared_ptr<shared_model::interface::TxStatusFactory> status_factory,
    std::shared_ptr<iroha::torii::CommandServiceImpl::CacheType> cache,
    std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache,
    logger::LoggerPtr log)
    : tx_processor_(std::move(tx_processor)),
      status_bus_(std::move(status_bus)),
      cache_(std::move(cache)),
      status_factory_(std::move(status_factory)),
      tx_presence_cache_(std::move(tx_presence_cache)),
      log_(std::move(log)) {}

void CommandServiceImpl::handleTransactionBatch(
    std::shared_ptr<shared_model::interface::TransactionBatch> batch) {
  processBatch(batch);
}

std::shared_ptr<shared_model::interface::TransactionResponse>
CommandServiceImpl::getStatus(const shared_model::crypto::Hash &request) {
  auto cached = cache_->findItem(request);
  if (cached) {
    return cached.value();
  }

  auto status = tx_presence_cache_->check(request);
  if (not status) {
    // TODO andrei 30.11.18 IR-51 Handle database error
    log_->warn("Check hash presence database error. Tx: {}", request);
    return status_factory_->makeNotReceived(request);
  }

  return std::visit(
      make_visitor(
          [this, &request](
              const iroha::ametsuchi::tx_cache_status_responses::Missing &)
              -> std::shared_ptr<shared_model::interface::TransactionResponse> {
            log_->warn("Asked non-existing tx: {}", request);
            return status_factory_->makeNotReceived(request);
          },
          [this, &request](
              const iroha::ametsuchi::tx_cache_status_responses::Rejected &) {
            std::shared_ptr<shared_model::interface::TransactionResponse>
                response = status_factory_->makeRejected(request);
            cache_->addItem(request, response);
            return response;
          },
          [this, &request](
              const iroha::ametsuchi::tx_cache_status_responses::Committed &) {
            std::shared_ptr<shared_model::interface::TransactionResponse>
                response = status_factory_->makeCommitted(request);
            cache_->addItem(request, response);
            return response;
          }),
      *status);
}

void CommandServiceImpl::processTransactionResponse(
    std::shared_ptr<shared_model::interface::TransactionResponse> response) {
  // find response for this tx in cache; if status of received
  // response isn't "greater" than cached one, dismiss received one
  auto tx_hash = response->transactionHash();
  auto cached_tx_state = cache_->findItem(tx_hash);
  if (cached_tx_state
      and response->comparePriorities(**cached_tx_state)
          != shared_model::interface::TransactionResponse::
                 PrioritiesComparisonResult::kGreater) {
    return;
  }
  cache_->addItem(tx_hash, response);
}

void CommandServiceImpl::pushStatus(
    const std::string &who,
    std::shared_ptr<shared_model::interface::TransactionResponse> response) {
  log_->debug("{}: adding item to cache: {}", who, *response);
  status_bus_->publish(response);
}

void CommandServiceImpl::processBatch(
    std::shared_ptr<shared_model::interface::TransactionBatch> batch) {
  const auto status_issuer = "ToriiBatchProcessor";
  const auto &txs = batch->transactions();

  bool has_final_status{false};

  for (auto tx : txs) {
    const auto &tx_hash = tx->hash();
    if (auto found = cache_->findItem(tx_hash)) {
      log_->debug("Found in cache: {}", **found);
      has_final_status = iroha::visit_in_place(
          (*found)->get(),
          [](const auto &final_responses)
              -> std::enable_if_t<FinalStatusValue<decltype(final_responses)>,
                                  bool> { return true; },
          [](const auto &rest_responses)
              -> std::enable_if_t<
                  not FinalStatusValue<decltype(rest_responses)>,
                  bool> { return false; });
    }

    if (has_final_status) {
      break;
    }
  }

  if (has_final_status) {
    // presence of the transaction or batch in the cache with final status
    // guarantees that the transaction was passed to consensus before
    log_->warn("Replayed batch would not be served - present in cache. {}",
               *batch);
    return;
  }

  auto cache_presence = tx_presence_cache_->check(*batch);
  if (not cache_presence) {
    // TODO andrei 30.11.18 IR-51 Handle database error
    log_->warn("Check tx presence database error. {}", *batch);
    return;
  }
  auto is_replay = std::any_of(
      cache_presence->begin(),
      cache_presence->end(),
      [this, &status_issuer](const auto &tx_status) {
        return std::visit(
            make_visitor(
                [this, &status_issuer](
                    const iroha::ametsuchi::tx_cache_status_responses::Missing
                        &status) {
                  this->pushStatus(
                      status_issuer,
                      status_factory_->makeStatelessValid(status.hash));
                  return false;
                },
                [this, &status_issuer](
                    const iroha::ametsuchi::tx_cache_status_responses::Committed
                        &status) {
                  this->pushStatus(status_issuer,
                                   status_factory_->makeCommitted(status.hash));
                  return true;
                },
                [this, &status_issuer](
                    const iroha::ametsuchi::tx_cache_status_responses::Rejected
                        &status) {
                  this->pushStatus(status_issuer,
                                   status_factory_->makeRejected(status.hash));
                  return true;
                }),
            tx_status);
      });
  if (is_replay) {
    log_->warn("Replayed batch would not be served - present in database. {}",
               *batch);
    return;
  }

  tx_processor_->batchHandle(batch);
}
