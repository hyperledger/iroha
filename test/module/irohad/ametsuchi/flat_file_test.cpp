/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/flat_file/flat_file.hpp"

#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include "common/byteutils.hpp"
#include "common/files.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;
namespace fs = boost::filesystem;
using Identifier = FlatFile::Identifier;

class BlStore_Test : public ::testing::Test {
 protected:
  void SetUp() override {
    fs::create_directory(block_store_path);
    block = std::vector<uint8_t>(100000, 5);
  }
  void TearDown() override {
    fs::remove_all(block_store_path);
  }
  std::string block_store_path =
      (fs::temp_directory_path() / fs::unique_path()).string();

  std::vector<uint8_t> block;
  logger::LoggerPtr flat_file_log_ = getTestLogger("FlatFile");
  logger::LoggerPtr log_ = getTestLogger("BlockStoreTest");
};

TEST_F(BlStore_Test, Read_Write_Test) {
  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store = std::move(store).assumeValue();
  auto id = 1u;

  bl_store->add(id, block);
  auto id2 = 2u;
  bl_store->add(id2, block);

  auto res = bl_store->get(id);
  ASSERT_TRUE(res);
  ASSERT_FALSE(res->empty());

  ASSERT_EQ(res->size(), block.size());
  ASSERT_EQ(*res, block);
}

/**
 * @given initialized FlatFile storage and 3 blocks are inserted into it
 * @when storage removed, file for a second block removed and new storage is
 * created on the same directory
 * @then last block id is still 3
 */
TEST_F(BlStore_Test, BlockStoreWhenRemoveBlock) {
  log_->info("----------| Simulate removal of the block |----------");
  // Remove file in the middle of the block store
  {
    log_->info(
        "----------| create blockstore and insert 3 elements "
        "|----------");

    auto store = FlatFile::create(block_store_path, flat_file_log_);
    IROHA_ASSERT_RESULT_VALUE(store);
    auto bl_store = std::move(store).assumeValue();

    // Adding three blocks
    auto id = 1u;
    bl_store->add(id, block);
    auto id2 = 2u;
    bl_store->add(id2, block);
    auto id3 = 3u;
    bl_store->add(id3, block);
  }

  log_->info("----------| remove second and init new storage |----------");
  fs::remove(fs::path(block_store_path) / "0000000000000002");
  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store = std::move(store).assumeValue();
  auto res = bl_store->last_id();
  ASSERT_EQ(res, 3);
}

TEST_F(BlStore_Test, BlockStoreWhenAbsentFolder) {
  log_->info(
      "----------| Check that folder is absent => create => "
      "make storage => remove storage |----------");
  fs::remove_all(block_store_path);
  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store = std::move(store).assumeValue();
  auto id = 1u;
  bl_store->add(id, block);
  auto res = bl_store->last_id();
  ASSERT_EQ(res, 1);
  fs::remove_all(block_store_path);
}

/**
 * @given non-empty folder from previous block store
 * @when new block storage is initialized
 * @then new block storage has all blocks from the folder
 */
TEST_F(BlStore_Test, BlockStoreInitializationFromNonemptyFolder) {
  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store1 = std::move(store).assumeValue();

  // Add two blocks to storage
  bl_store1->add(1u, std::vector<uint8_t>(1000, 5));
  bl_store1->add(2u, std::vector<uint8_t>(1000, 5));

  // create second block storage from the same folder
  auto store2 = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store2);
  auto bl_store2 = std::move(store2).assumeValue();

  // check that last ids of both block storages are the same
  ASSERT_EQ(bl_store1->last_id(), bl_store2->last_id());
}

/**
 * @given empty folder with block store
 * @when block id does not exist
 * @then get() fails
 */
TEST_F(BlStore_Test, GetNonExistingFile) {
  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store = std::move(store).assumeValue();
  Identifier id = 98759385;  // random number that does not exist
  auto res = bl_store->get(id);
  ASSERT_FALSE(res);
}

/**
 * @given empty folder with block store
 * @when FlatFile was created
 * @then directory() returns bock store path
 */
TEST_F(BlStore_Test, GetDirectory) {
  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store = std::move(store).assumeValue();
  ASSERT_EQ(bl_store->directory(), block_store_path);
}

/**
 * @given block store with one entry
 * @when user has not enough permissions
 * @then get() fails
 */
TEST_F(BlStore_Test, GetDeniedBlock) {
  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store = std::move(store).assumeValue();
  auto id = 1u;
  bl_store->add(id, block);

  auto filename = fs::path(block_store_path) / FlatFile::id_to_name(id);

  fs::remove(filename);
  auto res = bl_store->get(id);
  ASSERT_FALSE(res);
}

/**
 * @given empty folder with one entry
 * @when tries to add an entry with an existing id
 * @then add() fails
 */
TEST_F(BlStore_Test, AddExistingId) {
  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store = std::move(store).assumeValue();
  auto id = 1u;
  const auto file_name = fs::path(block_store_path) / FlatFile::id_to_name(id);
  std::ofstream fout(file_name.string());
  fout.close();

  auto res = bl_store->add(id, block);
  ASSERT_FALSE(res);
}

/**
 * @given empty folder
 * @when tries to create FlatFile with empty path
 * @then FlatFile creation fails
 */
TEST_F(BlStore_Test, WriteEmptyFolder) {
  auto bl_store = FlatFile::create("", flat_file_log_);
  IROHA_ASSERT_RESULT_ERROR(bl_store);
}

/**
 * @given empty folder with block store
 * @when tries do add an entry having not enough permissions
 * @then add() fails
 */
TEST_F(BlStore_Test, WriteDeniedFolder) {
  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store = std::move(store).assumeValue();
  auto id = 1u;

  fs::remove(fs::path(block_store_path));
  auto res = bl_store->add(id, block);
  ASSERT_FALSE(res);
}

/**
 * @given initialized FlatFile storage
 * @when several blocks with non-consecutive ids are inserted
 * @then all inserted blocks are available, block 1 is not available
 */
TEST_F(BlStore_Test, RandomNumbers) {
  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store = std::move(store).assumeValue();
  bl_store->add(5, block);
  bl_store->add(22, block);
  bl_store->add(11, block);
  ASSERT_TRUE(bl_store->get(5));
  ASSERT_TRUE(bl_store->get(22));
  ASSERT_TRUE(bl_store->get(11));
  ASSERT_FALSE(bl_store->get(1));
}

/**
 * @given initialized FlatFile storage
 * @when 3 blocks with non-consecutive ids are inserted, storage removed, and
 * new storage is created on the same directory
 * @then only blocks with inserted ids are available
 */
TEST_F(BlStore_Test, RemoveAndCreateNew) {
  {
    auto store = FlatFile::create(block_store_path, flat_file_log_);
    IROHA_ASSERT_RESULT_VALUE(store);
    auto bl_store = std::move(store).assumeValue();

    bl_store->add(4, block);
    bl_store->add(17, block);
    bl_store->add(7, block);
  }

  auto store = FlatFile::create(block_store_path, flat_file_log_);
  IROHA_ASSERT_RESULT_VALUE(store);
  auto bl_store = std::move(store).assumeValue();

  ASSERT_TRUE(bl_store->get(4));
  ASSERT_TRUE(bl_store->get(17));
  ASSERT_TRUE(bl_store->get(7));
  ASSERT_FALSE(bl_store->get(1));
}
