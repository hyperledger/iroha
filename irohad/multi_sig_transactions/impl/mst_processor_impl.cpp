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
      logger::LoggerPtr log)
      : MstProcessor(log),  // use the same logger in base class
        transport_(std::move(transport)),
        storage_(std::move(storage)),
        strategy_(std::move(strategy)),
        propagation_subscriber_(
            strategy_->emitter().subscribe([this](auto data) {
              this->storage_->clearStalledPeerStates();
              this->onPropagate(data);
            })),
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
    expiredBatchesNotify(storage_->extractExpiredTransactions());
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

  void FairMstProcessor::onNewState(const shared_model::crypto::PublicKey &from,
                                    MstState new_state) {
    log_->info("Applying new state");

    auto state_update = storage_->apply(from, std::move(new_state));

    // updated batches
    updatedBatchesNotify(*state_update.updated_state_);
    log_->info("New batches size: {}",
               state_update.updated_state_->getBatches().size());

    // completed batches
    completedBatchesNotify(*state_update.completed_state_);

    // expired batches
    // not nesessary to do it right here, just use the occasion to clean storage
    expiredBatchesNotify(storage_->extractExpiredTransactions());
  }

  // -----------------------------| private api |-----------------------------

  void FairMstProcessor::onPropagate(
      const PropagationStrategy::PropagationData &data) {
    auto size = data.size();
    std::for_each(data.begin(), data.end(), [this, size](const auto &dst_peer) {
      auto diff = storage_->getDiffState(dst_peer->pubkey());
      if (not diff.isEmpty()) {
        log_->info("Propagate new data[{}]", size);
        transport_->sendState(*dst_peer, diff);
        storage_->apply(dst_peer->pubkey(), std::move(diff));
      }
    });
  }

}  // namespace iroha
