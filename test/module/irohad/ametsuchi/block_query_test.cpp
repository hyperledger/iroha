/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_block_query.hpp"

#include <boost/filesystem.hpp>
#include "ametsuchi/impl/block_index_impl.hpp"
#include "ametsuchi/impl/flat_file/flat_file.hpp"
#include "ametsuchi/impl/flat_file_block_storage_factory.hpp"
#include "ametsuchi/impl/postgres_indexer.hpp"
#include "backend/protobuf/proto_block_json_converter.hpp"
#include "common/byteutils.hpp"
#include "converters/protobuf/json_proto_converter.hpp"
#include "datetime/time.hpp"
#include "framework/result_fixture.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"
#include "module/irohad/ametsuchi/mock_block_storage.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"

using namespace iroha::ametsuchi;

using testing::Return;

class BlockQueryTest : public AmetsuchiTest {
 protected:
  void SetUp() override {
    AmetsuchiTest::SetUp();

    auto tmp = FlatFile::create(block_store_path, getTestLogger("FlatFile"));
    IROHA_ASSERT_RESULT_VALUE(tmp);
    file = std::move(tmp).assumeValue();
    mock_block_storage = std::make_shared<MockBlockStorage>();
    sql = std::make_unique<soci::session>(*soci::factory_postgresql(), pgopt_);

    index = std::make_shared<BlockIndexImpl>(
        std::make_unique<PostgresIndexer>(*sql), getTestLogger("BlockIndex"));
    auto converter =
        std::make_shared<shared_model::proto::ProtoBlockJsonConverter>();
    auto block_storage_factory = std::make_unique<FlatFileBlockStorageFactory>(
        []() { return block_store_path; }, converter, getTestLoggerManager());
    block_storage = block_storage_factory->create().assumeValue();
    blocks = std::make_shared<PostgresBlockQuery>(
        *sql, *block_storage, getTestLogger("BlockQuery"));
    empty_blocks = std::make_shared<PostgresBlockQuery>(
        *sql, *mock_block_storage, getTestLogger("PostgresBlockQueryEmpty"));

    auto make_tx = [created_time =
                        iroha::time::now()](const auto &creator) mutable {
      return TestTransactionBuilder()
          .creatorAccountId(creator)
          .createdTime(created_time++)
          .build();
    };

    // First transaction in block1
    auto txn1_1 = make_tx(creator1);
    tx_hashes.push_back(txn1_1.hash());

    // Second transaction in block1
    auto txn1_2 = make_tx(creator1);
    tx_hashes.push_back(txn1_2.hash());

    std::vector<shared_model::proto::Transaction> txs1;
    txs1.push_back(std::move(txn1_1));
    txs1.push_back(std::move(txn1_2));

    auto block1 =
        TestBlockBuilder()
            .height(1)
            .transactions(txs1)
            .prevHash(shared_model::crypto::Hash(zero_string))
            .rejectedTransactions(
                std::vector<shared_model::crypto::Hash>{rejected_hash})
            .build();

    // First tx in block 1
    auto txn2_1 = make_tx(creator1);
    tx_hashes.push_back(txn2_1.hash());

    // Second tx in block 2
    auto txn2_2 = make_tx(creator2);
    tx_hashes.push_back(txn2_2.hash());

    std::vector<shared_model::proto::Transaction> txs2;
    txs2.push_back(std::move(txn2_1));
    txs2.push_back(std::move(txn2_2));

    auto block2 = TestBlockBuilder()
                      .height(2)
                      .transactions(txs2)
                      .prevHash(block1.hash())
                      .build();

    for (const auto &b : {std::move(block1), std::move(block2)}) {
      converter->serialize(b).match(
          [this, &b](const auto &json) {
            file->add(b.height(), iroha::stringToBytes(json.value));
            index->index(b);
            blocks_total++;
          },
          [](const auto &error) { FAIL() << error.error; });
    }
  }

  void TearDown() override {
    sql->close();
    AmetsuchiTest::TearDown();
  }

  std::unique_ptr<soci::session> sql;
  std::vector<shared_model::crypto::Hash> tx_hashes;
  std::shared_ptr<BlockQuery> blocks;
  std::shared_ptr<BlockQuery> empty_blocks;
  std::shared_ptr<BlockIndex> index;
  std::unique_ptr<BlockStorage> block_storage;
  std::shared_ptr<MockBlockStorage> mock_block_storage;
  std::unique_ptr<FlatFile> file;
  std::string creator1 = "user1@test";
  std::string creator2 = "user2@test";
  std::size_t blocks_total{0};
  std::string zero_string = std::string(32, '0');
  shared_model::crypto::Hash rejected_hash{"rejected_tx_hash"};
};

/**
 * @given block store with 2 blocks totally containing 3 txs created by
 * user1@test AND 1 tx created by user2@test
 * @when get non-existent 1000th block
 * @then nothing is returned
 */
TEST_F(BlockQueryTest, GetNonExistentBlock) {
  auto stored_block = blocks->getBlock(1000);
  stored_block.match(
      [](auto &&v) {
        FAIL() << "Nonexistent block request matched value "
               << v.value->toString();
      },
      [](auto &&e) {
        EXPECT_EQ(e.error.code, BlockQuery::GetBlockError::Code::kNoBlock);
      });
}

/**
 * @given block store with 2 blocks totally containing 3 txs created by
 * user1@test AND 1 tx created by user2@test
 * @when height=1
 * @then returned exactly 1 block
 */
TEST_F(BlockQueryTest, GetExactlyOneBlock) {
  auto stored_block = blocks->getBlock(1);
  stored_block.match([](auto &&v) { SUCCEED(); },
                     [](auto &&e) {
                       FAIL() << "Existing block request failed: "
                              << e.error.message;
                     });
}

/**
 * @given block store with 2 blocks totally containing 3 txs created by
 * user1@test AND 1 tx created by user2@test
 * @when get zero block
 * @then no blocks returned
 */
TEST_F(BlockQueryTest, GetZeroBlock) {
  auto stored_block = blocks->getBlock(0);
  stored_block.match(
      [](auto &&v) {
        FAIL() << "Nonexistent block request matched value "
               << v.value->toString();
      },
      [](auto &&e) {
        EXPECT_EQ(e.error.code, BlockQuery::GetBlockError::Code::kNoBlock);
      });
}

// TODO: luckychess 05.08.2019 IR-595 Unit tests for ProtoBlockJsonConverter
/**
 * @given block store with 2 blocks totally containing 3 txs created by
 * user1@test AND 1 tx created by user2@test. Block #1 is filled with trash data
 * (NOT JSON).
 * @when read block #1
 * @then get no blocks
 */
TEST_F(BlockQueryTest, GetBlockButItIsNotJSON) {
  namespace fs = boost::filesystem;
  size_t block_n = 1;

  // write something that is NOT JSON to block #1
  auto block_path = fs::path{block_store_path} / FlatFile::id_to_name(block_n);
  fs::ofstream block_file(block_path);
  std::string content = R"(this is definitely not json)";
  block_file << content;
  block_file.close();

  auto stored_block = blocks->getBlock(block_n);
  stored_block.match(
      [](auto &&v) {
        FAIL() << "Nonexistent block request matched value "
               << v.value->toString();
      },
      [](auto &&e) {
        EXPECT_EQ(e.error.code, BlockQuery::GetBlockError::Code::kNoBlock);
      });
}

/**
 * @given block store with 2 blocks totally containing 3 txs created by
 * user1@test AND 1 tx created by user2@test. Block #1 is filled with trash data
 * (NOT JSON).
 * @when read block #1
 * @then get no blocks
 */
TEST_F(BlockQueryTest, GetBlockButItIsInvalidBlock) {
  namespace fs = boost::filesystem;
  size_t block_n = 1;

  // write bad block instead of block #1
  auto block_path = fs::path{block_store_path} / FlatFile::id_to_name(block_n);
  fs::ofstream block_file(block_path);
  std::string content = R"({
  "testcase": [],
  "description": "make sure this is valid json, but definitely not a block"
})";
  block_file << content;
  block_file.close();

  auto stored_block = blocks->getBlock(block_n);
  stored_block.match(
      [](auto &&v) {
        FAIL() << "Nonexistent block request matched value "
               << v.value->toString();
      },
      [](auto &&e) {
        EXPECT_EQ(e.error.code, BlockQuery::GetBlockError::Code::kNoBlock);
      });
}

/**
 * @given block store with preinserted blocks
 * @when checkTxPresence is invoked on existing transaction hash
 * @then Committed status is returned
 */
TEST_F(BlockQueryTest, HasTxWithExistingHash) {
  for (const auto &hash : tx_hashes) {
    ASSERT_NO_THROW({
      auto status = std::get<tx_cache_status_responses::Committed>(
          *blocks->checkTxPresence(hash));
      ASSERT_EQ(status.hash, hash);
    });
  }
}

/**
 * @given block store with preinserted blocks
 * user1@test AND 1 tx created by user2@test
 * @when checkTxPresence is invoked on non-existing hash
 * @then Missing status is returned
 */
TEST_F(BlockQueryTest, HasTxWithMissingHash) {
  shared_model::crypto::Hash missing_tx_hash(zero_string);
  ASSERT_NO_THROW({
    auto status = std::get<tx_cache_status_responses::Missing>(
        *blocks->checkTxPresence(missing_tx_hash));
    ASSERT_EQ(status.hash, missing_tx_hash);
  });
}

/**
 * @given block store with preinserted blocks containing rejected_hash1 in one
 * of the block
 * @when checkTxPresence is invoked on existing rejected hash
 * @then Rejected is returned
 */
TEST_F(BlockQueryTest, HasTxWithRejectedHash) {
  ASSERT_NO_THROW({
    auto status = std::get<tx_cache_status_responses::Rejected>(
        *blocks->checkTxPresence(rejected_hash));
    ASSERT_EQ(status.hash, rejected_hash);
  });
}

/**
 * @given block store with preinserted blocks
 * @when getTopBlock is invoked on this block store
 * @then returned top block's height is equal to the inserted one's
 */
TEST_F(BlockQueryTest, GetTopBlockSuccess) {
  auto top_block_opt =
      framework::expected::val(blocks->getBlock(blocks->getTopBlockHeight()));
  ASSERT_TRUE(top_block_opt);
  ASSERT_EQ(top_block_opt.value().value->height(), 2);
}

/**
 * @given empty block store
 * @when getTopBlock is invoked on this block store
 * @then result must be a kNoBlock error, because no block was fetched
 */
TEST_F(BlockQueryTest, GetTopBlockFail) {
  EXPECT_CALL(*mock_block_storage, size()).WillRepeatedly(Return(0));
  ASSERT_EQ(mock_block_storage->fetch(mock_block_storage->size()), boost::none);

  auto top_block_error = iroha::expected::resultToOptionalError(
      empty_blocks->getBlock(empty_blocks->getTopBlockHeight()));
  ASSERT_TRUE(top_block_error);
  ASSERT_EQ(top_block_error.value().code,
            BlockQuery::GetBlockError::Code::kNoBlock);
}
