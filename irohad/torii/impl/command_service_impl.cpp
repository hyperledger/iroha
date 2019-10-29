/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/impl/command_service_impl.hpp"

#include <rxcpp/operators/rx-filter.hpp>
#include <rxcpp/operators/rx-start_with.hpp>
#include "ametsuchi/block_query.hpp"
#include "common/byteutils.hpp"
#include "common/is_any.hpp"
#include "common/visitor.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/transaction.hpp"
#include "interfaces/transaction_responses/not_received_tx_response.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace torii {

    CommandServiceImpl::CommandServiceImpl(
        std::shared_ptr<iroha::torii::TransactionProcessor> tx_processor,
        std::shared_ptr<iroha::ametsuchi::Storage> storage,
        std::shared_ptr<iroha::torii::StatusBus> status_bus,
        std::shared_ptr<shared_model::interface::TxStatusFactory>
            status_factory,
        std::shared_ptr<iroha::torii::CommandServiceImpl::CacheType> cache,
        std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache,
        logger::LoggerPtr log)
        : tx_processor_(std::move(tx_processor)),
          storage_(std::move(storage)),
          status_bus_(std::move(status_bus)),
          cache_(std::move(cache)),
          status_factory_(std::move(status_factory)),
          tx_presence_cache_(std::move(tx_presence_cache)),
          log_(std::move(log)) {
      // Notifier for all clients
      status_subscription_ = status_bus_->statuses().subscribe(
          // TODO mboldyrev IR-426 research approaches to the problem of member
          // observer lifetime.
          [cache = cache_](auto response) {
            // find response for this tx in cache; if status of received
            // response isn't "greater" than cached one, dismiss received one
            auto tx_hash = response->transactionHash();
            auto cached_tx_state = cache->findItem(tx_hash);
            if (cached_tx_state
                and response->comparePriorities(**cached_tx_state)
                    != shared_model::interface::TransactionResponse::
                           PrioritiesComparisonResult::kGreater) {
              return;
            }
            cache->addItem(tx_hash, response);
          });
    }

    CommandServiceImpl::~CommandServiceImpl() {
      status_subscription_.unsubscribe();
    }

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

      auto block_query = storage_->getBlockQuery();
      if (not block_query) {
        // TODO andrei 30.11.18 IR-51 Handle database error
        log_->warn("Could not create block query. Tx: {}", request.hex());
        return status_factory_->makeNotReceived(request);
      }

      auto status = block_query->checkTxPresence(request);
      if (not status) {
        // TODO andrei 30.11.18 IR-51 Handle database error
        log_->warn("Check tx presence database error. Tx: {}", request.hex());
        return status_factory_->makeNotReceived(request);
      }

      return iroha::visit_in_place(
          *status,
          [this, &request](
              const iroha::ametsuchi::tx_cache_status_responses::Missing &)
              -> std::shared_ptr<shared_model::interface::TransactionResponse> {
            log_->warn("Asked non-existing tx: {}", request.hex());
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
          });
    }

    /**
     * Statuses considered final for streaming. Observable stops value emission
     * after receiving a value of one of the following types
     * @tparam T concrete response type
     *
     * StatefulFailedTxResponse and MstExpiredResponse were removed from the
     * list of final statuses.
     *
     * StatefulFailedTxResponse is not a final status because the node might be
     * in non-synchronized state and the transaction may be stateful valid from
     * the viewpoint of up to date nodes.
     *
     * MstExpiredResponse is not a final status in general case because it will
     * depend on MST expiration timeout. The transaction might expire in MST,
     * but remain valid in terms of Iroha validation rules. Thus, it may be
     * resent and committed successfully. As the result the final status may
     * differ from MstExpiredResponse.
     */
    template <typename T>
    constexpr bool FinalStatusValue =
        iroha::is_any<std::decay_t<T>,
                      shared_model::interface::StatelessFailedTxResponse,
                      shared_model::interface::CommittedTxResponse,
                      shared_model::interface::RejectedTxResponse>::value;

    rxcpp::observable<
        std::shared_ptr<shared_model::interface::TransactionResponse>>
    CommandServiceImpl::getStatusStream(
        const shared_model::crypto::Hash &hash) {
      using ResponsePtrType =
          std::shared_ptr<shared_model::interface::TransactionResponse>;
      auto initial_status = cache_->findItem(hash).value_or([&] {
        // if cache_ doesn't contain some status there is required to check
        // persistent cache

        log_->debug("tx {} isn't present in cache", hash);
        auto from_persistent_cache = tx_presence_cache_->check(hash);
        if (not from_persistent_cache) {
          // TODO andrei 30.11.18 IR-51 Handle database error
          log_->warn("Check hash presence database error. {}", hash);
          return status_factory_->makeNotReceived(hash);
        }
        return iroha::visit_in_place(
            *from_persistent_cache,
            [this,
             &hash](const iroha::ametsuchi::tx_cache_status_responses::Committed
                        &) { return status_factory_->makeCommitted(hash); },
            [this, &hash](
                const iroha::ametsuchi::tx_cache_status_responses::Rejected &) {
              return status_factory_->makeRejected(hash);
            },
            [this, &hash](
                const iroha::ametsuchi::tx_cache_status_responses::Missing &) {
              return status_factory_->makeNotReceived(hash);
            });
      }());
      return status_bus_
          ->statuses()
          // prepend initial status
          .start_with(initial_status)
          // select statuses with requested hash
          .filter([hash](auto response) {
            return response->transactionHash() == hash;
          })
          // successfully complete the observable if final status is received.
          // final status is included in the observable
          .template lift<ResponsePtrType>(
              [](rxcpp::subscriber<ResponsePtrType> dest) {
                return rxcpp::make_subscriber<ResponsePtrType>(
                    dest, [=](ResponsePtrType response) {
                      dest.on_next(response);
                      iroha::visit_in_place(
                          response->get(),
                          [dest](const auto &resp)
                              -> std::enable_if_t<
                                  FinalStatusValue<decltype(resp)>> {
                            dest.on_completed();
                          },
                          [](const auto &resp)
                              -> std::enable_if_t<
                                  not FinalStatusValue<decltype(resp)>>{});
                    });
              });
    }

    void CommandServiceImpl::pushStatus(
        const std::string &who,
        std::shared_ptr<shared_model::interface::TransactionResponse>
            response) {
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
                  -> std::enable_if_t<
                      FinalStatusValue<decltype(final_responses)>,
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
            return iroha::visit_in_place(
                tx_status,
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
                });
          });
      if (is_replay) {
        log_->warn(
            "Replayed batch would not be served - present in database. {}",
            *batch);
        return;
      }

      tx_processor_->batchHandle(batch);
    }

  }  // namespace torii
}  // namespace iroha
