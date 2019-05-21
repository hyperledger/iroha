/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/state/mst_state.hpp"

#include <utility>
#include <vector>

#include <boost/algorithm/cxx11/all_of.hpp>
#include <boost/algorithm/minmax_element.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/find.hpp>
#include <boost/range/combine.hpp>
#include "common/set.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"

namespace {
  shared_model::interface::types::TimestampType oldestTimestamp(
      const iroha::BatchPtr &batch) {
    const bool batch_is_empty = boost::empty(batch->transactions());
    assert(not batch_is_empty);
    if (batch_is_empty) {
      return 0;
    }
    auto timestamps =
        batch->transactions()
        | boost::adaptors::transformed(
              +[](const std::shared_ptr<shared_model::interface::Transaction>
                      &tx) { return tx->createdTime(); });
    const auto min_it =
        boost::first_min_element(timestamps.begin(), timestamps.end());
    assert(min_it != timestamps.end());
    return min_it == timestamps.end() ? 0 : *min_it;
  }
}  // namespace

namespace iroha {

  bool BatchHashEquality::operator()(const DataType &left_tx,
                                     const DataType &right_tx) const {
    return left_tx->reducedHash() == right_tx->reducedHash();
  }

  DefaultCompleter::DefaultCompleter(std::chrono::minutes expiration_time)
      : expiration_time_(expiration_time) {}

  bool DefaultCompleter::isCompleted(const DataType &batch) const {
    return std::all_of(batch->transactions().begin(),
                       batch->transactions().end(),
                       [](const auto &tx) {
                         return boost::size(tx->signatures()) >= tx->quorum();
                       });
  }

  bool DefaultCompleter::isExpired(const DataType &batch,
                                   const TimeType &current_time) const {
    return oldestTimestamp(batch)
        + expiration_time_ / std::chrono::milliseconds(1)
        < current_time;
  }

  // ------------------------------| public api |-------------------------------

  MstState MstState::empty(logger::LoggerPtr log,
                           const CompleterType &completer) {
    return MstState(completer, std::move(log));
  }

  StateUpdateResult MstState::operator+=(const DataType &rhs) {
    auto state_update = StateUpdateResult{
        std::make_shared<MstState>(MstState::empty(log_, completer_)),
        std::make_shared<MstState>(MstState::empty(log_, completer_))};
    insertOne(state_update, rhs);
    return state_update;
  }

  StateUpdateResult MstState::operator+=(const MstState &rhs) {
    auto state_update = StateUpdateResult{
        std::make_shared<MstState>(MstState::empty(log_, completer_)),
        std::make_shared<MstState>(MstState::empty(log_, completer_))};
    for (auto &&rhs_tx : rhs.batches_.right | boost::adaptors::map_keys) {
      insertOne(state_update, rhs_tx);
    }
    return state_update;
  }

  MstState MstState::operator-(const MstState &rhs) const {
    const auto &my_batches = batches_.right | boost::adaptors::map_keys;
    std::vector<DataType> difference;
    difference.reserve(boost::size(batches_));
    for (const auto &batch : my_batches) {
      if (rhs.batches_.right.find(batch) == rhs.batches_.right.end()) {
        difference.push_back(batch);
      }
    }
    return MstState(this->completer_, difference, log_);
  }

  bool MstState::isEmpty() const {
    return batches_.empty();
  }

  std::unordered_set<DataType,
                     iroha::model::PointerBatchHasher,
                     BatchHashEquality>
  MstState::getBatches() const {
    const auto batches_range = batches_.right | boost::adaptors::map_keys;
    return {batches_range.begin(), batches_range.end()};
  }

  MstState MstState::extractExpired(const TimeType &current_time) {
    MstState out = MstState::empty(log_, completer_);
    extractExpiredImpl(current_time, out);
    return out;
  }

  void MstState::eraseExpired(const TimeType &current_time) {
    extractExpiredImpl(current_time, boost::none);
  }

  // ------------------------------| private api |------------------------------

  /**
   * Merge signatures in batches
   * @param target - batch for inserting
   * @param donor - batch with transactions to copy signatures from
   * @return return if at least one new signature was inserted
   */
  bool mergeSignaturesInBatch(DataType &target, const DataType &donor) {
    auto inserted_new_signatures = false;
    for (auto zip :
         boost::combine(target->transactions(), donor->transactions())) {
      const auto &target_tx = zip.get<0>();
      const auto &donor_tx = zip.get<1>();
      inserted_new_signatures = std::accumulate(
          std::begin(donor_tx->signatures()),
          std::end(donor_tx->signatures()),
          inserted_new_signatures,
          [&target_tx](bool accumulator, const auto &signature) {
            return target_tx->addSignature(signature.signedData(),
                                           signature.publicKey())
                or accumulator;
          });
    }
    return inserted_new_signatures;
  }

  MstState::MstState(const CompleterType &completer, logger::LoggerPtr log)
      : MstState(completer, std::vector<DataType>{}, std::move(log)) {}

  MstState::MstState(const CompleterType &completer,
                     const BatchesForwardCollectionType &batches,
                     logger::LoggerPtr log)
      : completer_(completer), log_(std::move(log)) {
    for (const auto &batch : batches) {
      batches_.insert({oldestTimestamp(batch), batch});
    }
  }

  void MstState::insertOne(StateUpdateResult &state_update,
                           const DataType &rhs_batch) {
    log_->info("batch: {}", *rhs_batch);
    auto corresponding = batches_.right.find(rhs_batch);
    if (corresponding == batches_.right.end()) {
      // when state does not contain transaction
      rawInsert(rhs_batch);
      state_update.updated_state_->rawInsert(rhs_batch);
      return;
    }

    DataType found = corresponding->first;
    // Append new signatures to the existing state
    auto inserted_new_signatures = mergeSignaturesInBatch(found, rhs_batch);

    if (completer_->isCompleted(found)) {
      // state already has completed transaction,
      // remove from state and return it
      batches_.right.erase(found);
      state_update.completed_state_->rawInsert(found);
      return;
    }

    // if batch still isn't completed, return it, if new signatures were
    // inserted
    if (inserted_new_signatures) {
      state_update.updated_state_->rawInsert(found);
    }
  }

  void MstState::rawInsert(const DataType &rhs_batch) {
    batches_.insert({oldestTimestamp(rhs_batch), rhs_batch});
  }

  bool MstState::contains(const DataType &element) const {
    return batches_.right.find(element) != batches_.right.end();
  }

  void MstState::extractExpiredImpl(const TimeType &current_time,
                                    boost::optional<MstState &> extracted) {
    for (auto it = batches_.left.begin(); it != batches_.left.end()
         and completer_->isExpired(it->second, current_time);) {
      if (extracted) {
        *extracted += it->second;
      }
      it = batches_.left.erase(it);
      assert(it == batches_.left.begin());
    }
  }

}  // namespace iroha
