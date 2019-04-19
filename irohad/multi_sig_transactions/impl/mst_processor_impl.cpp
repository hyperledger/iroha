/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/mst_processor_impl.hpp"

#include <utility>

#include "logger/logger.hpp"

namespace iroha {

  FairMstProcessor::FairMstProcessor(
      std::shared_ptr<iroha::network::MstTransport> transport,
      std::shared_ptr<MstStorage> storage,
      std::shared_ptr<PropagationStrategy> strategy,
      std::shared_ptr<MstTimeProvider> time_provider,
      logger::LoggerPtr log)
      : MstProcessor(log),  // use the same logger in base class
        transport_(std::move(transport)),
        storage_(std::move(storage)),
        strategy_(std::move(strategy)),
        time_provider_(std::move(time_provider)),
        propagation_subscriber_(strategy_->emitter().subscribe(
            [this](auto data) { this->onPropagate(data); })),
        log_(std::move(log)) {}

  FairMstProcessor::~FairMstProcessor() {
    propagation_subscriber_.unsubscribe();
  }

  // -------------------------| MstProcessor override |-------------------------

  auto FairMstProcessor::propagateBatchImpl(const iroha::DataType &batch)
      -> decltype(propagateBatch(batch)) {
    auto state_update = storage_->updateOwnState(batch);
    const bool batch_is_accepted = not state_update.updated_state_->isEmpty()
        or not state_update.completed_state_.empty();
    completedBatchesNotify(state_update.completed_state_);
    updatedBatchesNotify(state_update.updated_state_);
    expiredBatchesNotify(
        storage_->extractExpiredTransactions(time_provider_->getCurrentTime()));
    return batch_is_accepted;
  }

  auto FairMstProcessor::onStateUpdateImpl() const
      -> decltype(onStateUpdate()) {
    return state_subject_.get_observable();
  }

  auto FairMstProcessor::onPreparedBatchesImpl() const
      -> decltype(onPreparedBatches()) {
    return batches_subject_.get_observable();
  }

  auto FairMstProcessor::onExpiredBatchesImpl() const
      -> decltype(onExpiredBatches()) {
    return expired_subject_.get_observable();
  }

  // TODO [IR-1687] Akvinikym 10.09.18: three methods below should be one
  void FairMstProcessor::completedBatchesNotify(
      std::vector<std::shared_ptr<MovedBatch>> completed) const {
    std::for_each(
        completed.begin(), completed.end(), [this](const auto &batch) {
          batches_subject_.get_subscriber().on_next(batch);
        });
  }

  void FairMstProcessor::updatedBatchesNotify(
      std::shared_ptr<const MstState> state) const {
    if (not state->isEmpty()) {
      state_subject_.get_subscriber().on_next(state);
    }
  }

  void FairMstProcessor::expiredBatchesNotify(ConstRefState state) const {
    if (not state.isEmpty()) {
      state.iterateBatches([this](const auto &batch) {
        expired_subject_.get_subscriber().on_next(batch);
      });
    }
  }

  bool FairMstProcessor::batchInStorageImpl(const DataType &batch) const {
    return storage_->batchInStorage(batch);
  }

  // -------------------| MstTransportNotification override |-------------------

  void FairMstProcessor::onNewState(const shared_model::crypto::PublicKey &from,
                                    MstState new_state) {
    log_->info("Applying new state");
    auto current_time = time_provider_->getCurrentTime();

    auto state_update = storage_->apply(from, new_state);

    // updated batches
    updatedBatchesNotify(state_update.updated_state_);
    log_->info("New state has {} batches and {} transactions.",
               state_update.updated_state_->batchesQuantity(),
               state_update.updated_state_->transactionsQuantity());

    // completed batches
    completedBatchesNotify(state_update.completed_state_);

    // expired batches
    expiredBatchesNotify(storage_->getDiffState(from, current_time));
  }

  // -----------------------------| private api |-----------------------------

  void FairMstProcessor::onPropagate(
      const PropagationStrategy::PropagationData &data) {
    auto current_time = time_provider_->getCurrentTime();
    auto size = data.size();
    std::for_each(data.begin(),
                  data.end(),
                  [this, &current_time, size](const auto &dst_peer) {
                    auto diff = storage_->getDiffState(dst_peer->pubkey(),
                                                       current_time);
                    if (not diff.isEmpty()) {
                      log_->info("Propagate new data[{}]", size);
                      transport_->sendState(*dst_peer, diff);
                    }
                  });
  }

}  // namespace iroha
