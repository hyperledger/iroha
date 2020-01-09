/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture_param_postgres.hpp"

#include <soci/soci.h>
#include "ametsuchi/impl/postgres_command_executor.hpp"
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
#include "module/irohad/ametsuchi/truncate_postgres_wsv.hpp"
#include "module/irohad/pending_txs_storage/pending_txs_storage_mock.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace executor_testing;
using namespace iroha;
using namespace iroha::ametsuchi;
using namespace iroha::expected;
using namespace iroha::integration_framework;

namespace {
  constexpr size_t kDataBaseSessionPoolSize = 3;  // sessions for:
                                                  // - command executor
                                                  // - query executor
                                                  // - resetWsv

  ExecutorItfTarget createPostgresExecutorItfTarget(TestDbManager &db_manager);
}  // namespace

PostgresExecutorTestParam::PostgresExecutorTestParam() {
  auto db_manager_result = TestDbManager::createWithRandomDbName(
      kDataBaseSessionPoolSize,
      getTestLoggerManager()->getChild("TestDbManager"));
  if (auto e = resultToOptionalError(db_manager_result)) {
    throw std::runtime_error(e.value());
  }
  db_manager_ = std::move(db_manager_result).assumeValue();

  executor_itf_target_ = createPostgresExecutorItfTarget(*db_manager_);
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

std::string PostgresExecutorTestParam::toString() const {
  return "PostgreSQL";
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

  ExecutorItfTarget createPostgresExecutorItfTarget(TestDbManager &db_manager) {
    ExecutorItfTarget target;
    target.command_executor = std::make_shared<PostgresCommandExecutor>(
        db_manager.getSession(),
        std::make_shared<shared_model::proto::ProtoPermissionToString>());
    target.query_executor =
        std::make_unique<PostgresSpecificQueryExecutorWrapper>(
            db_manager.getSession(),
            std::make_unique<MockBlockStorage>(),
            std::make_shared<MockPendingTransactionStorage>(),
            std::make_shared<shared_model::proto::ProtoQueryResponseFactory>(),
            std::make_shared<shared_model::proto::ProtoPermissionToString>(),
            getTestLoggerManager()
                ->getChild("SpecificQueryExecutor")
                ->getLogger());
    return target;
  }

}  // namespace
