/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "multi_sig_transactions/state/mst_state.hpp"

#include <algorithm>
#include <utility>
#include <vector>

#include <boost/algorithm/cxx11/all_of.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/algorithm/find.hpp>
#include <boost/range/combine.hpp>
#include "common/set.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"

namespace {
  template <class T>
  size_t countTxsInBatches(const T &batches) {
    size_t size = 0;
    for (const auto &batch : batches) {
      size += boost::size(batch->transactions());
    }
    return size;
  }

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
    const auto min_it = std::min_element(timestamps.begin(), timestamps.end());
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

  MstState::MstState(MstState &&other)
      : batches_(std::move(other.batches_)),
        txs_quantity_(other.txs_quantity_),
        log_(std::move(other.log_)) {}

  MstState MstState::empty(const CompleterType &completer,
                           std::shared_ptr<BatchStorageLimit> storage_limit,
                           logger::LoggerPtr log) {
    return MstState(completer, std::move(storage_limit), std::move(log));
  }

  StateUpdateResult MstState::operator+=(const DataType &rhs) {
    auto state_update = StateUpdateResult{completer_, log_};
    insertOne(state_update, rhs);
    return state_update;
  }

  StateUpdateResult MstState::operator+=(const MstState &rhs) {
    auto state_update = StateUpdateResult{completer_, log_};
    return rhs.batches_.access([this, &state_update](const auto &storage) {
      for (auto &&rhs_tx : storage.batches.right | boost::adaptors::map_keys) {
        this->insertOne(state_update, rhs_tx);
      }
      return state_update;
    });
  }

  MstState MstState::operator-(const MstState &rhs) const {
    std::vector<DataType> difference;
    batches_.access([&difference, &rhs](const auto &storage) {
      difference.reserve(boost::size(storage.batches));
      rhs.batches_.access(
          [&difference,
           my_batches = storage.batches.right
               | boost::adaptors::map_keys](const auto &storage) {
            for (const auto &batch : my_batches) {
              if (storage.batches.right.find(batch)
                  == storage.batches.right.end()) {
                difference.push_back(batch);
              }
            }
          });
    });
    return MstState(this->completer_, batches_.sharedLimit(), difference, log_);
  }

  bool MstState::isEmpty() const {
    return batches_.access(
        [](const auto &storage) { return storage.batches.empty(); });
  }

  std::unordered_set<DataType,
                     iroha::model::PointerBatchHasher,
                     BatchHashEquality>
  MstState::getBatches() const {
    return batches_.access([](const auto &storage) {
      const auto batches_range =
          storage.batches.right | boost::adaptors::map_keys;
      return std::unordered_set<DataType,
                                iroha::model::PointerBatchHasher,
                                BatchHashEquality>{batches_range.begin(),
                                                   batches_range.end()};
    });
  }

  MstState MstState::extractExpired(const TimeType &current_time) {
    MstState out = empty(completer_, batches_.sharedLimit(), log_);
    extractExpiredImpl(current_time, out);
    return out;
  }

  void MstState::eraseExpired(const TimeType &current_time) {
    extractExpiredImpl(current_time, boost::none);
  }

  size_t MstState::transactionsQuantity() const {
    assert(txs_quantity_ == batches_.access([](const auto &storage) {
      return countTxsInBatches(storage.batches.right
                               | boost::adaptors::map_keys);
    }));
    return txs_quantity_;
  }

  size_t MstState::batchesQuantity() const {
    return batches_.itemsQuantity();
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

  MstState::MstState(const CompleterType &completer,
                     std::shared_ptr<BatchStorageLimit> storage_limit,
                     logger::LoggerPtr log)
      : MstState(completer,
                 std::move(storage_limit),
                 std::vector<DataType>{},
                 std::move(log)) {}

  MstState::MstState(const CompleterType &completer,
                     std::shared_ptr<BatchStorageLimit> storage_limit,
                     const BatchesForwardCollectionType &batches,
                     logger::LoggerPtr log)
      : completer_(completer),
        batches_(std::move(storage_limit), std::make_unique<InternalStorage>()),
        txs_quantity_(0),
        log_(std::move(log)) {
    for (const auto &batch : batches) {
      batches_.insert(batch);
      txs_quantity_ += batch->transactions().size();
    }
  }

  void MstState::insertOne(StateUpdateResult &state_update,
                           const DataType &rhs_batch) {
    log_->info("batch: {}", *rhs_batch);
    auto completed_batches = batches_.move([this, &state_update, &rhs_batch](
                                               auto &storage)
                                               -> std::vector<BatchPtr> {
      auto corresponding = storage.batches.right.find(rhs_batch);
      if (corresponding == storage.batches.right.end()) {
        // when state does not contain transaction
        if (this->rawInsert(rhs_batch)) {
          // there is enough room for the new batch
          BOOST_VERIFY_MSG(state_update.updated_state_->rawInsert(rhs_batch),
                           "Could not insert new MST batch to state update.");
        } else {
          // there is not enough room for the new batch
          log_->info("Dropped a batch because it did not fit into storage: {}",
                     *rhs_batch);
        }
        return {};
      }

      DataType found = corresponding->first;
      // Append new signatures to the existing state
      auto inserted_new_signatures = mergeSignaturesInBatch(found, rhs_batch);

      if (completer_->isCompleted(found)) {
        // state already has completed transaction,
        // remove from state and return it
        assert(txs_quantity_ >= boost::size(found->transactions()));
        txs_quantity_ -= boost::size(found->transactions());
        storage.batches.right.erase(found);
        return {found};
      }

      // if batch still isn't completed, return it, if new signatures
      // were inserted
      if (inserted_new_signatures) {
        state_update.updated_state_->rawInsert(found);
      }
      return {};
    });
    for (auto &batch : completed_batches) {
      state_update.completed_state_.emplace_back(std::move(batch));
    }
  }

  bool MstState::rawInsert(const DataType &rhs_batch) {
    if (batches_.insert(rhs_batch)) {
      txs_quantity_ += boost::size(rhs_batch->transactions());
      return true;
    }
    return false;
  }

  bool MstState::contains(const DataType &element) const {
    return batches_.access([&element](const auto &storage) {
      return storage.batches.right.find(element) != storage.batches.right.end();
    });
  }

  void MstState::extractExpiredImpl(const TimeType &current_time,
                                    boost::optional<MstState &> opt_extracted) {
    auto extracted = batches_.extract([this, &current_time, &opt_extracted](
                                          auto &storage) {
      std::vector<BatchPtr> extracted;
      for (auto it = storage.batches.left.begin();
           it != storage.batches.left.end()
           and completer_->isExpired(it->second, current_time);) {
        assert(txs_quantity_ >= boost::size(it->second->transactions()));
        txs_quantity_ -= boost::size(it->second->transactions());
        if (opt_extracted) {
          *opt_extracted += it->second;
        }
        extracted.emplace_back(it->second);
        it = storage.batches.left.erase(it);
        assert(it == storage.batches.left.begin());
      }
      return extracted;
    });
  }

  bool MstState::InternalStorage::insert(BatchPtr batch) {
    return batches.insert({oldestTimestamp(batch), batch}).second;
  }

}  // namespace iroha
