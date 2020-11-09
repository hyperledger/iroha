/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_storage.hpp"
#include "ametsuchi/impl/postgres_block_storage_factory.hpp"

#include "ametsuchi/impl/k_times_reconnection_strategy.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "common/result.hpp"
#include "framework/config_helper.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"
#include "generator/generator.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "module/shared_model/validators/validators.hpp"

using namespace iroha::ametsuchi;
using namespace shared_model::validation;

using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

using MockBlockIValidator = MockValidator<shared_model::interface::Block>;
using MockBlockPValidator = MockValidator<iroha::protocol::Block>;

class PostgresBlockStorageTest : public ::testing::Test {
 public:
  PostgresBlockStorageTest() {
    ON_CALL(*mock_block_, height()).WillByDefault(Return(height_));
    ON_CALL(*mock_block_, blob()).WillByDefault(ReturnRef(blob_));
    ON_CALL(*mock_other_block_, height()).WillByDefault(Return(height_ + 2));
    ON_CALL(*mock_other_block_, blob()).WillByDefault(ReturnRef(blob_));
  }

 protected:
  void SetUp() override {
    IROHA_ASSERT_RESULT_VALUE(PgConnectionInit::prepareWorkingDatabase(
        iroha::StartupWsvDataPolicy::kDrop, options_));

    auto reconnection_strategy_factory =
        std::make_unique<iroha::ametsuchi::KTimesReconnectionStrategyFactory>(
            0);

    auto pool = PgConnectionInit::prepareConnectionPool(
        *reconnection_strategy_factory,
        options_,
        pool_size_,
        getTestLoggerManager()->getChild("Storage"));

    if (auto e = boost::get<iroha::expected::Error<std::string>>(&pool)) {
      storage_logger_->error("Pool initialization error: {}", e->error);
      std::terminate();
    }

    pool_wrapper_ = std::move(
        boost::get<iroha::expected::Value<std::shared_ptr<PoolWrapper>>>(pool)
            .value);

    auto validator = std::make_unique<MockBlockIValidator>();
    auto proto_validator = std::make_unique<MockBlockPValidator>();

    block_factory_ = std::make_shared<shared_model::proto::ProtoBlockFactory>(
        std::move(validator), std::move(proto_validator));

    block_storage_ =
        PostgresBlockStorageFactory(pool_wrapper_,
                                    block_factory_,
                                    [&]() { return test_table_; },
                                    getTestLogger("PostgresBlockStorage"))
            .create()
            .assumeValue();
  }

  void TearDown() override {
    block_storage_ = nullptr;
    pool_wrapper_ = nullptr;
    IROHA_ASSERT_RESULT_VALUE(PgConnectionInit::dropWorkingDatabase(options_));
  }

  std::shared_ptr<shared_model::proto::ProtoBlockFactory> block_factory_;
  std::shared_ptr<MockBlock> mock_block_ =
      std::make_shared<NiceMock<MockBlock>>();
  std::shared_ptr<MockBlock> mock_other_block_ =
      std::make_shared<NiceMock<MockBlock>>();
  shared_model::interface::types::HeightType height_ = 6;
  shared_model::crypto::Blob blob_ = shared_model::crypto::Blob(
      shared_model::crypto::Blob::Bytes{0, 1, 5, 17, 66, 255});
  std::string creator_ = "user1@test";
  std::string test_table_ = "abc";
  int pool_size_ = 10;
  std::shared_ptr<iroha::ametsuchi::PoolWrapper> pool_wrapper_;
  std::unique_ptr<BlockStorage> block_storage_;
  logger::LoggerPtr storage_logger_ = getTestLogger("Storage");
  std::string dbname_ = integration_framework::getRandomDbName();
  std::string pgopt_ = "dbname=" + dbname_ + " "
      + integration_framework::getPostgresCredsOrDefault();
  PostgresOptions options_{pgopt_, dbname_, storage_logger_};
};

/**
 * @given initialized block storage, single block with height_ inserted
 * @when another block with height_ is inserted
 * @then second insertion fails
 */
TEST_F(PostgresBlockStorageTest, InsertTest) {
  ASSERT_TRUE(block_storage_->insert(mock_block_));
  ASSERT_FALSE(block_storage_->insert(mock_block_));
}

/**
 * @given initialized block storage, single block with height_ inserted
 * @when another block with height_+2 is inserted
 * @then second insertion fails
 */
TEST_F(PostgresBlockStorageTest, InsertNonSequentialTest) {
  ASSERT_TRUE(block_storage_->insert(mock_block_));
  ASSERT_FALSE(block_storage_->insert(mock_other_block_));
}

/**
 * @given initialized block storage, single block with height_ inserted
 * @when block with height_ is fetched
 * @then it is returned
 */
TEST_F(PostgresBlockStorageTest, FetchExisting) {
  auto tx = TestTransactionBuilder().creatorAccountId(creator_).build();
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(std::move(tx));
  auto block = TestBlockBuilder().height(height_).transactions(txs).build();

  ASSERT_TRUE(block_storage_->insert(clone(block)));

  auto block_var = *(block_storage_->fetch(block.height()));
  ASSERT_EQ(block.blob(), block_var->blob());
}

/**
 * @given initialized block storage without blocks
 * @when block with height_ is fetched
 * @then nothing is returned
 */
TEST_F(PostgresBlockStorageTest, FetchNonexistent) {
  ASSERT_FALSE(block_storage_->fetch(height_));
}

/**
 * @given initialized block storage, single block with height_ inserted
 * @when size is fetched
 * @then 1 is returned
 */
TEST_F(PostgresBlockStorageTest, Size) {
  ASSERT_TRUE(block_storage_->insert(mock_block_));
  ASSERT_EQ(1, block_storage_->size());
}

/**
 * @given initialized block storage, single block with height_ inserted
 * @when storage is cleared with clear
 * @then no blocks are left in storage
 */
TEST_F(PostgresBlockStorageTest, Clear) {
  ASSERT_TRUE(block_storage_->insert(mock_block_));
  block_storage_->clear();
  ASSERT_FALSE(block_storage_->fetch(height_));
  ASSERT_EQ(0, block_storage_->size());
}

/**
 * @given initialized block storage, two blocks with height_ and height_+1 are
 * inserted
 * @when forEach is called
 * @then both blocks are visited, lambda is invoked twice
 */
TEST_F(PostgresBlockStorageTest, ForEach) {
  auto tx = TestTransactionBuilder().creatorAccountId(creator_).build();
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(std::move(tx));
  auto block = TestBlockBuilder().height(height_).transactions(txs).build();
  auto another_block =
      TestBlockBuilder().height(height_ + 1).transactions(txs).build();

  ASSERT_TRUE(block_storage_->insert(clone(block)));
  ASSERT_TRUE(block_storage_->insert(clone(another_block)));

  size_t count = 0;

  block_storage_->forEach([&count, &block, &another_block](const auto &b)
                              -> iroha::expected::Result<void, std::string> {
    [&] {
      ++count;
      if (b->height() == block.height()) {
        ASSERT_EQ(b->blob(), block.blob());
      } else if (b->height() == another_block.height()) {
        ASSERT_EQ(b->blob(), another_block.blob());
      } else {
        FAIL() << "Unexpected block height returned: " << b->height();
      }
    }();
    return {};
  });

  ASSERT_EQ(2, count);
}
