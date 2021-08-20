/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture_param_rocksdb.hpp"

#include <boost/filesystem.hpp>

#include "ametsuchi/impl/block_index_impl.hpp"
#include "ametsuchi/impl/rocksdb_command_executor.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "ametsuchi/impl/rocksdb_indexer.hpp"
#include "ametsuchi/impl/rocksdb_specific_query_executor.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "common/result.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "module/irohad/ametsuchi/mock_block_storage.hpp"
#include "module/irohad/ametsuchi/mock_vm_caller.hpp"
#include "module/irohad/pending_txs_storage/pending_txs_storage_mock.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace executor_testing;
using namespace iroha;
using namespace iroha::ametsuchi;
using namespace iroha::expected;
using namespace iroha::integration_framework;

namespace fs = boost::filesystem;

namespace {
  ExecutorItfTarget createRocksDBExecutorItfTarget(
      std::shared_ptr<iroha::ametsuchi::RocksDBPort> db_port, VmCaller &);
}  // namespace

RocksDBExecutorTestParam::RocksDBExecutorTestParam() {
  db_name_ = (fs::temp_directory_path() / fs::unique_path()).string();
  db_port_ = std::make_shared<RocksDBPort>();
  db_port_->initialize(db_name_);

  executor_itf_target_ = createRocksDBExecutorItfTarget(db_port_, *vm_caller_);

  block_indexer_ = std::make_shared<BlockIndexImpl>(
      std::make_unique<RocksDBIndexer>(
          std::make_shared<RocksDBContext>(db_port_)),
      getTestLogger("RocksDBIndexer"));
}

RocksDBExecutorTestParam::~RocksDBExecutorTestParam() = default;

void RocksDBExecutorTestParam::clearBackendState() {
  db_port_.reset();
  executor_itf_target_.query_executor.reset();
  executor_itf_target_.command_executor.reset();
  block_indexer_.reset();
  fs::remove_all(db_name_);

  db_name_ = (fs::temp_directory_path() / fs::unique_path()).string();
  db_port_ = std::make_shared<RocksDBPort>();
  db_port_->initialize(db_name_);

  executor_itf_target_ = createRocksDBExecutorItfTarget(db_port_, *vm_caller_);

  block_indexer_ = std::make_shared<BlockIndexImpl>(
      std::make_unique<RocksDBIndexer>(
          std::make_shared<RocksDBContext>(db_port_)),
      getTestLogger("RocksDBIndexer"));
}

ExecutorItfTarget RocksDBExecutorTestParam::getExecutorItfParam() const {
  return executor_itf_target_;
}

std::unique_ptr<iroha::ametsuchi::BurrowStorage>
RocksDBExecutorTestParam::makeBurrowStorage(
    std::string const &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index) const {
  return std::unique_ptr<iroha::ametsuchi::BurrowStorage>{};
}

std::shared_ptr<iroha::ametsuchi::BlockIndex>
RocksDBExecutorTestParam::getBlockIndexer() const {
  return block_indexer_;
}

std::string RocksDBExecutorTestParam::toString() const {
  return "RocksDB";
}

std::reference_wrapper<ExecutorTestParam>
executor_testing::getExecutorTestParamRocksDB() {
  static RocksDBExecutorTestParam param;
  return param;
}

namespace {
  class RocksDBSpecificQueryExecutorWrapper
      : public RocksDbSpecificQueryExecutor {
   public:
    RocksDBSpecificQueryExecutorWrapper(
        std::shared_ptr<iroha::ametsuchi::RocksDBContext> db_context,
        std::unique_ptr<BlockStorage> block_storage,
        std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter)
        : RocksDbSpecificQueryExecutor(db_context,
                                       *block_storage,
                                       std::move(pending_txs_storage),
                                       std::move(response_factory),
                                       std::move(perm_converter)),
          block_storage_(std::move(block_storage)) {}

   private:
    std::unique_ptr<BlockStorage> block_storage_;
  };

  ExecutorItfTarget createRocksDBExecutorItfTarget(
      std::shared_ptr<iroha::ametsuchi::RocksDBPort> db_port,
      VmCaller &vm_caller) {
    ExecutorItfTarget target;
    auto db_context = std::make_shared<RocksDBContext>(db_port);
    auto query_executor = std::make_shared<RocksDBSpecificQueryExecutorWrapper>(
        db_context,
        std::make_unique<MockBlockStorage>(),
        std::make_shared<MockPendingTransactionStorage>(),
        std::make_shared<shared_model::proto::ProtoQueryResponseFactory>(),
        std::make_shared<shared_model::proto::ProtoPermissionToString>());
    target.command_executor = std::make_shared<RocksDbCommandExecutor>(
        db_context,
        std::make_shared<shared_model::proto::ProtoPermissionToString>(),
        vm_caller);
    target.query_executor = std::move(query_executor);
    return target;
  }

}  // namespace
