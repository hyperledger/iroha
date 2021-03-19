/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/mst_processor_impl.hpp"

#include <utility>

#include <rxcpp/operators/rx-filter.hpp>
#include <rxcpp/operators/rx-flat_map.hpp>
#include <rxcpp/operators/rx-map.hpp>
#include <rxcpp/operators/rx-take.hpp>
#include "logger/logger.hpp"
#include "main/subscription.hpp"

using shared_model::interface::types::PublicKeyHexStringView;

namespace {
  using namespace iroha;

  auto sendState(std::weak_ptr<logger::Logger> log,
                 std::weak_ptr<network::MstTransport> transport,
                 std::weak_ptr<MstStorage> storage,
                 std::weak_ptr<MstTimeProvider> time_provider) {
    return
        [log_ = std::move(log),
         transport_ = std::move(transport),
         storage_ = std::move(storage),
         time_provider_ = std::move(time_provider)](auto tpl)
            -> rxcpp::observable<std::tuple<  // sent successfully
                std::shared_ptr<shared_model::interface::Peer>,  // to this peer
                MstState                                         // this state
                >> {
          auto &[dst_peer, size] = tpl;

          auto log = log_.lock();
          auto transport = transport_.lock();
          auto storage = storage_.lock();
          auto time_provider = time_provider_.lock();

          if (log and transport and storage and time_provider) {
            auto current_time = time_provider->getCurrentTime();
            auto diff = storage->getDiffState(
                PublicKeyHexStringView{dst_peer->pubkey()}, current_time);
            if (not diff.isEmpty()) {
              log->info("Propagate new data[{}]", size);
              return transport->sendState(dst_peer, diff)
                  .take(1)
                  .filter([](auto is_ok) { return is_ok; })
                  .map([dst_peer = std::move(dst_peer),
                        diff = std::move(diff)](auto) {
                    return std::make_tuple(std::move(dst_peer),
                                           std::move(diff));
                  });
            }
          }

          return rxcpp::observable<>::empty<
              std::tuple<std::shared_ptr<shared_model::interface::Peer>,
                         MstState>>();
        };
  }

  auto onSendStateResponse(std::weak_ptr<MstStorage> storage) {
    return [storage_ = std::move(storage)](auto tpl) {
      auto &[dst_peer, diff] = tpl;

      auto storage = storage_.lock();
      if (storage) {
        storage->apply(PublicKeyHexStringView{dst_peer->pubkey()}, diff);
      }
    };
  }
}  // namespace

namespace iroha {

  FairMstProcessor::FairMstProcessor(
      std::shared_ptr<network::MstTransport> transport,
      std::shared_ptr<MstStorage> storage,
      std::shared_ptr<PropagationStrategy> strategy,
      std::shared_ptr<MstTimeProvider> time_provider,
      logger::LoggerPtr log)
      : MstProcessor(log),  // use the same logger in base class
        log_(std::move(log)),
        transport_(std::move(transport)),
        storage_(std::move(storage)),
        strategy_(std::move(strategy)),
        time_provider_(std::move(time_provider)),
        propagation_subscriber_(
            strategy_->emitter()
                .flat_map([](auto data) {
                  return rxcpp::observable<>::iterate(data).map(
                      [size = data.size()](auto dst_peer) {
                        return std::make_tuple(std::move(dst_peer), size);
                      });
                })
                .flat_map(sendState(log_, transport_, storage_, time_provider_))
                .subscribe(onSendStateResponse(storage_))) {}

  FairMstProcessor::~FairMstProcessor() {
    propagation_subscriber_.unsubscribe();
  }

  // -------------------------| MstProcessor override |-------------------------

  auto FairMstProcessor::propagateBatchImpl(const iroha::DataType &batch)
      -> decltype(propagateBatch(batch)) {
    auto state_update = storage_->updateOwnState(batch);
    completedBatchesNotify(*state_update.completed_state_);
    updatedBatchesNotify(*state_update.updated_state_);
    expiredBatchesNotify(
        storage_->extractExpiredTransactions(time_provider_->getCurrentTime()));
  }

  bool FairMstProcessor::batchInStorageImpl(const DataType &batch) const {
    return storage_->batchInStorage(batch);
  }

  // -------------------| MstTransportNotification override |-------------------

  void FairMstProcessor::onNewState(PublicKeyHexStringView from,
                                    MstState &&new_state) {
    log_->info("Applying new state");
    auto current_time = time_provider_->getCurrentTime();

    // no need to add already expired batches to local state
    new_state.eraseExpired(current_time);
    auto state_update = storage_->apply(from, new_state);

    // updated batches
    updatedBatchesNotify(*state_update.updated_state_);
    log_->info("New batches size: {}",
               state_update.updated_state_->getBatches().size());

    // completed batches
    completedBatchesNotify(*state_update.completed_state_);

    // expired batches
    // not nesessary to do it right here, just use the occasion to clean storage
    expiredBatchesNotify(storage_->extractExpiredTransactions(current_time));
  }

  // -----------------------------| private api |-----------------------------

  // TODO [IR-1687] Akvinikym 10.09.18: three methods below should be one
  void FairMstProcessor::completedBatchesNotify(ConstRefState state) const {
    if (not state.isEmpty()) {
      state.iterateBatches([](const DataType &batch) {
        getSubscription()->notify(EventTypes::kOnPreparedBatches, batch);
      });
    }
  }

  void FairMstProcessor::updatedBatchesNotify(ConstRefState state) const {
    if (not state.isEmpty()) {
      getSubscription()->notify(EventTypes::kOnStateUpdate,
                                std::make_shared<MstState>(state));
    }
  }

  void FairMstProcessor::expiredBatchesNotify(ConstRefState state) const {
    if (not state.isEmpty()) {
      state.iterateBatches([](const DataType &batch) {
        getSubscription()->notify(EventTypes::kOnExpiredBatches, batch);
      });
    }
  }

}  // namespace iroha
