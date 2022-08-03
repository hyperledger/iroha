/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_ROCKSDB_HPP
#define TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_ROCKSDB_HPP

#include "integration/executor/executor_fixture_param.hpp"
#include "integration/executor/executor_fixture_param_provider.hpp"

namespace iroha::ametsuchi {
  struct RocksDBPort;
  struct RocksDBContext;
  class RocksDbCommon;
}  // namespace iroha::ametsuchi

namespace executor_testing {

  /**
   * RocksDB backend parameter for ExecutorTest.
   * Creates and holds a test database manager object that:
   * - creates a new working database with a random name
   * - drops the working database when the test suite is complete
   */
  class RocksDBExecutorTestParam final : public ExecutorTestParam {
   public:
    RocksDBExecutorTestParam();
    virtual ~RocksDBExecutorTestParam();

    void clearBackendState() override;

    ExecutorType getType() const override {
      return ExecutorType::kRocksDb;
    }

    iroha::integration_framework::ExecutorItfTarget getExecutorItfParam()
        const override;

    std::unique_ptr<iroha::ametsuchi::BurrowStorage> makeBurrowStorage(
        std::string const &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index)
        const override;

    std::shared_ptr<iroha::ametsuchi::BlockIndex> getBlockIndexer()
        const override;

    std::string toString() const override;

   private:
    std::string db_name_;
    std::shared_ptr<iroha::ametsuchi::RocksDBPort> db_port_;
    std::shared_ptr<iroha::ametsuchi::RocksDBContext> db_context_;
    std::unique_ptr<iroha::ametsuchi::RocksDbCommon> common_;

    iroha::integration_framework::ExecutorItfTarget executor_itf_target_;
    std::shared_ptr<iroha::ametsuchi::BlockIndex> block_indexer_;
  };

  std::reference_wrapper<ExecutorTestParam> getExecutorTestParamRocksDB();
}  // namespace executor_testing

#endif /* TEST_INTEGRATION_EXECUTOR_FIXTURE_PARAM_ROCKSDB_HPP */
