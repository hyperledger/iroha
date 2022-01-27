/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

#include <boost/filesystem.hpp>
#include <string>
#include <unordered_map>

#include "ametsuchi/impl/executor_common.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "common/result.hpp"
#include "cryptography/hash.hpp"

namespace fs = boost::filesystem;
using namespace iroha::ametsuchi;

class RocksDBIndexerTest : public ::testing::Test {
 public:
  void SetUp() override {
    db_name_ = (fs::temp_directory_path() / fs::unique_path()).string();
    auto db_port = std::make_shared<RocksDBPort>();
    db_port->initialize(db_name_);
    tx_context_ = std::make_shared<RocksDBContext>(db_port);
  }

  void TearDown() override {
    tx_context_.reset();
    fs::remove_all(db_name_);
  }

  void initDB(RocksDbCommon &common) {
    common.valueBuffer() = hash_1_;
    forTransactionByTimestamp<kDbOperation::kPut>(
        common, account_1_, ts_1_, 1, 1);

    common.valueBuffer() = hash_2_;
    forTransactionByTimestamp<kDbOperation::kPut>(
        common, account_1_, ts_2_, 2, 1);

    common.valueBuffer() = hash_3_;
    forTransactionByTimestamp<kDbOperation::kPut>(
        common, account_2_, ts_1_, 1, 2);

    common.valueBuffer().assign(
        fmt::format("{}#{}#{}", "asset", ts_1_, hash_1_));
    forTransactionByPosition<kDbOperation::kPut>(
        common, account_1_, ts_1_, 1, 1);

    common.valueBuffer().assign(fmt::format("{}#{}#{}", "", ts_2_, hash_2_));
    forTransactionByPosition<kDbOperation::kPut>(
        common, account_1_, ts_2_, 2, 1);

    common.valueBuffer().assign(fmt::format("{}#{}#{}", "", ts_1_, hash_3_));
    forTransactionByPosition<kDbOperation::kPut>(
        common, account_2_, ts_1_, 1, 2);

    common.valueBuffer().assign("TRUE");
    forTransactionStatus<kDbOperation::kPut>(common, h_1_);

    common.valueBuffer().assign("FALSE");
    forTransactionStatus<kDbOperation::kPut>(common, h_2_);

    common.valueBuffer().assign("TRUE");
    forTransactionStatus<kDbOperation::kPut>(common, h_3_);

    common.commit();
  }

  std::string db_name_;
  std::shared_ptr<RocksDBContext> tx_context_;

  std::string account_1_ = "account1#test";
  std::string account_2_ = "account2#test";

  shared_model::crypto::Hash h_1_ =
      shared_model::crypto::Hash::fromHexString("0102030405");
  shared_model::crypto::Hash h_2_ =
      shared_model::crypto::Hash::fromHexString("1112131415");
  shared_model::crypto::Hash h_3_ =
      shared_model::crypto::Hash::fromHexString("2122232425");

  std::string hash_1_ = "hash1";
  std::string hash_2_ = "hash2";
  std::string hash_3_ = "hash3";

  uint64_t ts_1_ = 1001;
  uint64_t ts_2_ = 1002;
};

/**
 * @given database with transactions
 * @when enumeration transactions from a valid account executes
 * @then correct transactions are present
 */
TEST_F(RocksDBIndexerTest, SimpleInsertTxByTs) {
  RocksDbCommon common(tx_context_);
  initDB(common);

  std::unordered_map<uint64_t, std::string> items;
  auto status = enumerateKeysAndValues(
      common,
      [&](auto ts, auto hash) {
        items[std::stoull(std::string(ts.ToStringView()))] =
            hash.ToStringView();
        return true;
      },
      RocksDBPort::ColumnFamilyType::kWsv,
      fmtstrings::kPathTransactionByTs,
      account_1_);
  ASSERT_TRUE(status.ok());
  ASSERT_TRUE(items.find(ts_1_) != items.end());
  ASSERT_TRUE(items.find(ts_2_) != items.end());

  ASSERT_TRUE(items[ts_1_] == hash_1_);
  ASSERT_TRUE(items[ts_2_] == hash_2_);

  items.clear();
  status = enumerateKeysAndValues(
      common,
      [&](auto ts, auto hash) {
        items[std::stoull(std::string(ts.ToStringView()))] =
            hash.ToStringView();
        return true;
      },
      RocksDBPort::ColumnFamilyType::kWsv,
      fmtstrings::kPathTransactionByTs,
      account_2_);
  ASSERT_TRUE(status.ok());
  ASSERT_TRUE(items.find(ts_1_) != items.end());
  ASSERT_TRUE(items[ts_1_] == hash_3_);
}

/**
 * @given database with transactions
 * @when request each transactions by a timestamp executes
 * @then correct transactions are present
 */
TEST_F(RocksDBIndexerTest, SimpleCheckTxByTs) {
  RocksDbCommon common(tx_context_);
  initDB(common);

  auto result =
      forTransactionByTimestamp<kDbOperation::kGet, kDbEntry::kMustExist>(
          common, account_1_, ts_1_, 1, 1);
  ASSERT_TRUE(iroha::expected::hasValue(result));
  ASSERT_TRUE(result.assumeValue());
  ASSERT_EQ(*result.assumeValue(), hash_1_);

  result = forTransactionByTimestamp<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, account_1_, ts_2_, 2, 1);
  ASSERT_TRUE(iroha::expected::hasValue(result));
  ASSERT_TRUE(result.assumeValue());
  ASSERT_EQ(*result.assumeValue(), hash_2_);

  result = forTransactionByTimestamp<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, account_2_, ts_1_, 1, 2);
  ASSERT_TRUE(iroha::expected::hasValue(result));
  ASSERT_TRUE(result.assumeValue());
  ASSERT_EQ(*result.assumeValue(), hash_3_);
}

/**
 * @given database with transactions
 * @when request transaction by a correct hash
 * @then correct transactions are present
 * @and if the hash is incorrect
 * @then error or empty value is present depends on kDbEntry argument
 */
TEST_F(RocksDBIndexerTest, SimpleCheckTxStatus) {
  RocksDbCommon common(tx_context_);
  initDB(common);

  auto result = forTransactionStatus<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, shared_model::crypto::Hash::fromHexString("1234"));
  ASSERT_TRUE(iroha::expected::hasError(result));

  result = forTransactionStatus<kDbOperation::kGet, kDbEntry::kMustNotExist>(
      common, shared_model::crypto::Hash::fromHexString("1234"));
  ASSERT_TRUE(iroha::expected::hasValue(result));

  result = forTransactionStatus<kDbOperation::kGet, kDbEntry::kCanExist>(
      common, shared_model::crypto::Hash::fromHexString("1234"));
  ASSERT_TRUE(iroha::expected::hasValue(result));
  ASSERT_FALSE(result.assumeValue());

  result = forTransactionStatus<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, h_1_);
  ASSERT_TRUE(iroha::expected::hasValue(result));
  ASSERT_TRUE(result.assumeValue());
  ASSERT_EQ(*result.assumeValue(), "TRUE");

  result = forTransactionStatus<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, h_2_);
  ASSERT_TRUE(iroha::expected::hasValue(result));
  ASSERT_TRUE(result.assumeValue());
  ASSERT_EQ(*result.assumeValue(), "FALSE");

  result = forTransactionStatus<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, h_3_);
  ASSERT_TRUE(iroha::expected::hasValue(result));
  ASSERT_TRUE(result.assumeValue());
  ASSERT_EQ(*result.assumeValue(), "TRUE");
}

/**
 * @given database with transactions
 * @when enumerate keys and values for a valid account
 * @then correct transactions data are present
 */
TEST_F(RocksDBIndexerTest, SimpleCheckTxByPos) {
  RocksDbCommon common(tx_context_);
  initDB(common);

  std::map<std::string, std::string> items;
  auto status = enumerateKeysAndValues(
      common,
      [&](auto position, auto data) {
        items[std::string(position.ToStringView())] = data.ToStringView();
        return true;
      },
      RocksDBPort::ColumnFamilyType::kWsv,
      fmtstrings::kPathTransactionByPosition,
      account_1_);

  ASSERT_EQ(items.size(), 2ull);
  for (auto &it : items) {
    auto position = iroha::ametsuchi::staticSplitId<5>(it.first, "/");
    ASSERT_TRUE(position.at(0) == "1" || position.at(0) == "2");
    ASSERT_TRUE(position.at(2) == "1");

    auto data = iroha::ametsuchi::staticSplitId<3>(it.second);
    ASSERT_TRUE(data.at(0) == "asset" || data.at(0) == "");
    ASSERT_TRUE(data.at(1) == std::to_string(ts_1_)
                || data.at(1) == std::to_string(ts_2_));
    ASSERT_TRUE(data.at(2) == hash_1_ || data.at(2) == hash_2_);
  }

  items.clear();
  status = enumerateKeysAndValues(
      common,
      [&](auto position, auto data) {
        items[std::string(position.ToStringView())] = data.ToStringView();
        return true;
      },
      RocksDBPort::ColumnFamilyType::kWsv,
      fmtstrings::kPathTransactionByPosition,
      account_2_);

  ASSERT_EQ(items.size(), 1ull);
  for (auto &it : items) {
    auto position = iroha::ametsuchi::staticSplitId<5>(it.first, "/");
    ASSERT_TRUE(position.at(0) == "1");
    ASSERT_TRUE(position.at(2) == "2");

    auto data = iroha::ametsuchi::staticSplitId<3>(it.second);
    ASSERT_TRUE(data.at(0) == "");
    ASSERT_TRUE(data.at(1) == std::to_string(ts_1_));
    ASSERT_TRUE(data.at(2) == hash_3_);
  }
}
