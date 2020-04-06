/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <utility>

#include "logger/logger.hpp"
#include "multi_sig_transactions/mst_processor_impl.hpp"

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
    completedBatchesNotify(*state_update.completed_state_);
    updatedBatchesNotify(*state_update.updated_state_);
    expiredBatchesNotify(
        storage_->extractExpiredTransactions(time_provider_->getCurrentTime()));
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
  void FairMstProcessor::completedBatchesNotify(ConstRefState state) const {
    if (not state.isEmpty()) {
      state.iterateBatches([this](const auto &batch) {
        batches_subject_.get_subscriber().on_next(batch);
      });
    }
  }

  void FairMstProcessor::updatedBatchesNotify(ConstRefState state) const {
    if (not state.isEmpty()) {
      state_subject_.get_subscriber().on_next(
          std::make_shared<MstState>(state));
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

  void FairMstProcessor::onNewState(
      shared_model::interface::types::PublicKeyHexStringView from,
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

  void FairMstProcessor::onPropagate(
      const PropagationStrategy::PropagationData &data) {
    auto current_time = time_provider_->getCurrentTime();
    auto size = data.size();
    for (auto const &dst_peer : data) {
      auto diff = storage_->getDiffState(
          shared_model::interface::types::PublicKeyHexStringView{
              dst_peer->pubkey()},
          current_time);
      if (not diff.isEmpty()) {
        log_->info("Propagate new data[{}]", size);
        transport_->sendState(*dst_peer, diff);
      }
    }
  }

}  // namespace iroha
