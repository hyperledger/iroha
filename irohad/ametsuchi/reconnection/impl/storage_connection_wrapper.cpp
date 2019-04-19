/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/reconnection/storage_connection_wrapper.hpp"

#include <type_traits>
#include <utility>

#include "ametsuchi/mutable_storage.hpp"
#include "ametsuchi/temporary_wsv.hpp"

using namespace iroha::ametsuchi;

template <typename ReturnValue, typename Invoker>
ReturnValue StorageConnectionWrapper::reconnectionLoop(
    Invoker function_call,
    ReturnValue failure_value,
    const std::string &tag) const {
  while (recall_strategy_->canInvoke(tag)) {
    {
      auto local_ref_to_storage = unsafe_storage_;
      if (local_ref_to_storage) {
        should_initialize_.store(true);
        auto returned_value = function_call(local_ref_to_storage);
        if (returned_value) {
          recall_strategy_->reset(tag);
          return *returned_value;
        }
      }
    }
    std::unique_lock<std::shared_timed_mutex> guard(lock_);
    // if statement prevents double initialization
    if (not unsafe_storage_ or should_initialize_.load()) {
      unsafe_storage_ = storage_creator_();
    }
    recall_strategy_->reset(tag);
    should_initialize_.store(false);
  }
  recall_strategy_->reset(tag);
  return failure_value;
}

StorageConnectionWrapper::StorageConnectionWrapper(
    std::function<std::shared_ptr<UnsafeStorage>()> storage_creator,
    std::shared_ptr<ReconnectionStorageStrategy> recall_strategy)
    : storage_creator_(std::move(storage_creator)),
      unsafe_storage_(storage_creator_()),
      recall_strategy_(std::move(recall_strategy)) {}

// ------------------------- | Storage | ---------------------------------

std::shared_ptr<WsvQuery> StorageConnectionWrapper::getWsvQuery() const {
  auto call = [](auto &storage) { return storage->getWsvQuery(); };
  using ReturnType = std::remove_reference_t<decltype(*call(unsafe_storage_))>;
  return reconnectionLoop<ReturnType>(
      call, nullptr, recall_strategy_->makeTag("getWsvQuery"));
}

std::shared_ptr<BlockQuery> StorageConnectionWrapper::getBlockQuery() const {
  auto call = [](auto &storage) { return storage->getBlockQuery(); };
  using ReturnType = std::remove_reference_t<decltype(*call(unsafe_storage_))>;
  return reconnectionLoop<ReturnType>(
      call, nullptr, recall_strategy_->makeTag("getBlockQuery"));
}

bool StorageConnectionWrapper::insertBlock(
    std::shared_ptr<const shared_model::interface::Block> block) {
  auto call = [&block](auto &storage) { return storage->insertBlock(block); };
  return reconnectionLoop<bool>(
      call, false, recall_strategy_->makeTag("getBlockQuery"));
}

bool StorageConnectionWrapper::insertBlocks(
    const std::vector<std::shared_ptr<shared_model::interface::Block>>
        &blocks) {
  auto call = [&blocks](auto &storage) {
    return storage->insertBlocks(blocks);
  };
  return reconnectionLoop<bool>(
      call, false, recall_strategy_->makeTag("insertBlocks"));
}

rxcpp::observable<std::shared_ptr<const shared_model::interface::Block>>
StorageConnectionWrapper::on_commit() {
  return unsafe_storage_->on_commit();
}

void StorageConnectionWrapper::reset() {
  auto storage_copy = unsafe_storage_;
  storage_copy->reset();
}

void StorageConnectionWrapper::dropStorage() {
  auto storage_copy = unsafe_storage_;
  storage_copy->dropStorage();
}

void StorageConnectionWrapper::freeConnections() {
  auto storage_copy = unsafe_storage_;
  storage_copy->freeConnections();
}

// ------------------------- | TemporaryFactory | ------------------------

iroha::expected::Result<std::unique_ptr<TemporaryWsv>, std::string>
StorageConnectionWrapper::createTemporaryWsv() {
  // // TODO: 2019-04-15 @muratovv this and further methods are not safe.
  // Methods must be reworked with reconnectionLoop.
  auto storage_copy = unsafe_storage_;
  return storage_copy->createTemporaryWsv();
}

void StorageConnectionWrapper::prepareBlock(std::unique_ptr<TemporaryWsv> wsv) {
  auto storage_copy = unsafe_storage_;
  return storage_copy->prepareBlock(std::move(wsv));
}

// ------------------------- | MutableFactory | --------------------------

iroha::expected::Result<std::unique_ptr<MutableStorage>, std::string>
StorageConnectionWrapper::createMutableStorage() {
  auto storage_copy = unsafe_storage_;
  return storage_copy->createMutableStorage();
}

boost::optional<std::unique_ptr<iroha::LedgerState>>
StorageConnectionWrapper::commit(
    std::unique_ptr<MutableStorage> mutable_storage) {
  auto storage_copy = unsafe_storage_;
  return storage_copy->commit(std::move(mutable_storage));
}

boost::optional<std::unique_ptr<iroha::LedgerState>>
StorageConnectionWrapper::commitPrepared(
    std::shared_ptr<const shared_model::interface::Block> block) {
  auto storage_copy = unsafe_storage_;
  return storage_copy->commitPrepared(block);
}

// ------------------------- | PeerQueryFactory | ------------------------

boost::optional<std::shared_ptr<PeerQuery>>
StorageConnectionWrapper::createPeerQuery() const {
  auto storage_copy = unsafe_storage_;
  return storage_copy->createPeerQuery();
}

// ------------------------- | BlockQueryFactory | -----------------------

boost::optional<std::shared_ptr<BlockQuery>>
StorageConnectionWrapper::createBlockQuery() const {
  auto storage_copy = unsafe_storage_;
  return storage_copy->createBlockQuery();
}

// ------------------------- | QueryExecutorFactory | --------------------

boost::optional<std::shared_ptr<QueryExecutor>>
StorageConnectionWrapper::createQueryExecutor(
    std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
    std::shared_ptr<shared_model::interface::QueryResponseFactory>
        response_factory) const {
  auto storage_copy = unsafe_storage_;
  return storage_copy->createQueryExecutor(pending_txs_storage,
                                           response_factory);
}
