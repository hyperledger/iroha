/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_block_storage.hpp"
#include "ametsuchi/impl/rocksdb_block_storage_factory.hpp"
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
#include <gtest/gtest.h>
#include "backend/protobuf/block.hpp"

using namespace iroha::ametsuchi;
using namespace shared_model::validation;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;

using MockBlockIValidator = MockValidator<shared_model::interface::Block>;
using MockBlockPValidator = MockValidator<iroha::protocol::Block>;

class RocksdbBlockStorageTest : public ::testing::Test {
    public:
     RocksdbBlockStorageTest() {
         block_ = std::make_shared<shared_model::proto::Block>(
             TestBlockBuilder().height(height_).build());
    }
    protected:
     void TearDown() override {
         block_storage_.clear();
    }

    RocksdbBlockStorage block_storage_;
    std::shared_ptr<shared_model::interface::Block> block_;
    shared_model::interface::types::HeightType height_ = 1;
};

/**
 * @given block storage factory
 * @when create is called
 * @then block storage is created
 */
TEST(RocksdbBlockStorageFactoryTest, Creation) {
  RocksdbBlockStorageFactory factory;

  ASSERT_TRUE(factory.create());
}

/**
 * @given initialized block storage, single block with height_ inserted
 * @when another block with height_ is inserted
 * @then second insertion fails
 */
TEST_F(RocksdbBlockStorageTest, Insert) {
  ASSERT_TRUE(block_storage_.insert(block_));
  ASSERT_FALSE(block_storage_.insert(block_));
}

/**
 * @given initialized block storage without blocks
 * @when block with height_ is fetched
 * @then nothing is returned
 */
TEST_F(RocksdbBlockStorageTest, FetchNonexistent) {
  auto block_var = block_storage_.fetch(height_);

  ASSERT_FALSE(block_var);
}

/**
 * @given initialized block storage, single block with height_ inserted
 * @when size is fetched
 * @then 1 is returned
 */
TEST_F(RocksdbBlockStorageTest, Size) {
  ASSERT_TRUE(block_storage_.insert(block_));

  ASSERT_EQ(1, block_storage_.size());
}

/**
 * @given initialized block storage, single block with height_ inserted
 * @when storage is cleared with clear
 * @then no blocks are left in storage
 */
TEST_F(RocksdbBlockStorageTest, Clear) {
  ASSERT_TRUE(block_storage_.insert(block_));

  block_storage_.clear();

  auto block_var = block_storage_.fetch(height_);

  ASSERT_FALSE(block_var);
}

/**
 * @given initialized block storage, single block with height_ inserted
 * @when forEach is called
 * @then block with height_ is visited, lambda is invoked once
 */
TEST_F(RocksdbBlockStorageTest, ForEach) {
  ASSERT_TRUE(block_storage_.insert(block_));

  size_t count = 0;

  block_storage_.forEach([this, &count](const auto &block) {
    ++count;
    ASSERT_TRUE(block);
    ASSERT_EQ(*block_, *block);
  });

  ASSERT_EQ(1, count);
}
