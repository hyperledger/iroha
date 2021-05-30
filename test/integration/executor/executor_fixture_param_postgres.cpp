/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture_param_postgres.hpp"

#include <soci/soci.h>
#include "ametsuchi/impl/block_index_impl.hpp"
#include "ametsuchi/impl/postgres_burrow_storage.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_indexer.hpp"
#include "ametsuchi/impl/postgres_query_executor.hpp"
#include "ametsuchi/impl/postgres_specific_query_executor.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "common/result.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_db_manager.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "module/irohad/ametsuchi/mock_block_storage.hpp"
#include "module/irohad/ametsuchi/mock_vm_caller.hpp"
#include "module/irohad/ametsuchi/truncate_postgres_wsv.hpp"
#include "module/irohad/pending_txs_storage/pending_txs_storage_mock.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace executor_testing;
using namespace iroha;
using namespace iroha::ametsuchi;
using namespace iroha::expected;
using namespace iroha::integration_framework;

namespace {
  constexpr size_t kDataBaseSessionPoolSize = 5;  // sessions for:
                                                  // - burrow storage
                                                  // - command executor
                                                  // - query executor
                                                  // - resetWsv
                                                  // - tx data indexer

  ExecutorItfTarget createPostgresExecutorItfTarget(TestDbManager &db_manager,
                                                    VmCaller &);
}  // namespace

PostgresExecutorTestParam::PostgresExecutorTestParam() {
  auto db_manager_result = TestDbManager::createWithRandomDbName(
      kDataBaseSessionPoolSize,
      getTestLoggerManager()->getChild("TestDbManager"));
  if (auto e = resultToOptionalError(db_manager_result)) {
    throw std::runtime_error(e.value());
  }
  db_manager_ = std::move(db_manager_result).assumeValue();

  executor_itf_target_ =
      createPostgresExecutorItfTarget(*db_manager_, *vm_caller_);
  burrow_storage_session_ = db_manager_->getSession();

  block_indexer_session_ = db_manager_->getSession();
  block_indexer_ = std::make_shared<BlockIndexImpl>(
      std::make_unique<PostgresIndexer>(*block_indexer_session_),
      getTestLogger("PostgresIndexer"));
}

PostgresExecutorTestParam::~PostgresExecutorTestParam() = default;

void PostgresExecutorTestParam::clearBackendState() {
  auto session = db_manager_->getSession();
  assert(session);
  iroha::ametsuchi::truncateWsv(*session);
}

ExecutorItfTarget PostgresExecutorTestParam::getExecutorItfParam() const {
  return executor_itf_target_;
}

std::unique_ptr<iroha::ametsuchi::BurrowStorage>
PostgresExecutorTestParam::makeBurrowStorage(
    std::string const &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index) const {
  return std::make_unique<PostgresBurrowStorage>(
      *burrow_storage_session_, tx_hash, cmd_index);
}

std::shared_ptr<iroha::ametsuchi::BlockIndex>
PostgresExecutorTestParam::getBlockIndexer() const {
  return block_indexer_;
}

std::string PostgresExecutorTestParam::toString() const {
  return "PostgreSQL";
}

std::reference_wrapper<ExecutorTestParam>
executor_testing::getExecutorTestParamPostgres() {
  static PostgresExecutorTestParam param;
  return param;
}

namespace {
  struct SessionHolder {
    SessionHolder(std::unique_ptr<soci::session> session)
        : session(std::move(session)) {}
    std::unique_ptr<soci::session> session;
  };

  class PostgresSpecificQueryExecutorWrapper
      : private SessionHolder,
        public PostgresSpecificQueryExecutor {
   public:
    PostgresSpecificQueryExecutorWrapper(
        std::unique_ptr<soci::session> &&session,
        std::unique_ptr<BlockStorage> block_storage,
        std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        logger::LoggerPtr log)
        : SessionHolder(std::move(session)),
          PostgresSpecificQueryExecutor(*SessionHolder::session,
                                        *block_storage,
                                        std::move(pending_txs_storage),
                                        std::move(response_factory),
                                        std::move(perm_converter),
                                        std::move(log)),
          block_storage_(std::move(block_storage)) {}

   private:
    std::unique_ptr<BlockStorage> block_storage_;
  };

  ExecutorItfTarget createPostgresExecutorItfTarget(TestDbManager &db_manager,
                                                    VmCaller &vm_caller) {
    ExecutorItfTarget target;
    auto postgres_query_executor =
        std::make_shared<PostgresSpecificQueryExecutorWrapper>(
            db_manager.getSession(),
            std::make_unique<MockBlockStorage>(),
            std::make_shared<MockPendingTransactionStorage>(),
            std::make_shared<shared_model::proto::ProtoQueryResponseFactory>(),
            std::make_shared<shared_model::proto::ProtoPermissionToString>(),
            getTestLoggerManager()
                ->getChild("SpecificQueryExecutor")
                ->getLogger());
    target.command_executor = std::make_shared<PostgresCommandExecutor>(
        db_manager.getSession(),
        std::make_shared<shared_model::proto::ProtoPermissionToString>(),
        postgres_query_executor,
        vm_caller);
    target.query_executor = std::move(postgres_query_executor);
    return target;
  }

}  // namespace
