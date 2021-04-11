/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <rocksdb/db.h>

#include <gtest/gtest.h>
#include <boost/filesystem.hpp>

#include "ametsuchi/impl/rocksdb_common.hpp"

namespace fs = boost::filesystem;
using namespace iroha::ametsuchi;

class RocksDBTest : public ::testing::Test {
 public:
  void SetUp() override {
    db_name_ = (fs::temp_directory_path() / fs::unique_path()).string();
    db_port_ = std::make_shared<RocksDBPort>();
    db_port_->initialize(db_name_);
    tx_context_ = std::make_shared<RocksDBContext>();
    db_port_->prepareTransaction(*tx_context_);

    insertDb(key1_, value1_);
    insertDb(key2_, value2_);
    insertDb(key3_, value3_);
    insertDb(key4_, value4_);
    insertDb(key5_, value5_);
  }

  void TearDown() override {
    tx_context_.reset();
    db_port_.reset();
    fs::remove_all(db_name_);
  }

  void insertDb(std::string_view key, std::string_view value) {
    RocksDbCommon common(tx_context_);
    common.valueBuffer() = value;
    common.put(key);
  }

  std::string_view readDb(std::string_view key) {
    RocksDbCommon common(tx_context_);
    common.get(key);
    return common.valueBuffer();
  }

  std::string db_name_;
  std::shared_ptr<RocksDBPort> db_port_;
  std::shared_ptr<RocksDBContext> tx_context_;

  std::string const key1_ = "keY";
  std::string const key2_ = "keYY";
  std::string const key3_ = "ke1Y";
  std::string const key4_ = "keyY";
  std::string const key5_ = "ke";

  std::string const value1_ = "vaLUe";
  std::string const value2_ = "vaLUe2";
  std::string const value3_ = "vaLUe3";
  std::string const value4_ = "vaLUe4";
  std::string const value5_ = "vaLUe5";
};

TEST_F(RocksDBTest, SimpleOperation) {
  ASSERT_TRUE(readDb(key1_) == value1_);
  ASSERT_TRUE(readDb(key2_) == value2_);
  ASSERT_TRUE(readDb(key3_) == value3_);
  ASSERT_TRUE(readDb(key4_) == value4_);
  ASSERT_TRUE(readDb(key5_) == value5_);
}

TEST_F(RocksDBTest, SimpleDelete) {
  RocksDbCommon common(tx_context_);
  common.del(key3_);

  auto status = common.get(key3_);
  ASSERT_TRUE(status.IsNotFound());
}

TEST_F(RocksDBTest, SimpleSeek) {
  RocksDbCommon common(tx_context_);
  auto it = common.seek("key");
  ASSERT_TRUE(it->status().ok());

  ASSERT_TRUE(it->key().ToStringView() == key4_);
  ASSERT_TRUE(it->value().ToStringView() == value4_);

  it = common.seek("ke1");
  ASSERT_TRUE(it->status().ok());

  ASSERT_TRUE(it->key().ToStringView() == key3_);
  ASSERT_TRUE(it->value().ToStringView() == value3_);
}

TEST_F(RocksDBTest, SimpleEnumerateKeys) {
  RocksDbCommon common(tx_context_);
  int counter = 0;
  common.enumerate(
      [&](auto const &it, auto key_size) mutable {
        ++counter;
        if (it->key().ToStringView() != key1_
            && it->key().ToStringView() != key2_)
          throw;
        return true;
      },
      "keY");
  ASSERT_EQ(counter, 2);
}

TEST_F(RocksDBTest, SimpleEnumerateKeys2) {
  RocksDbCommon common(tx_context_);
  int counter = 0;
  common.enumerate(
      [&](auto const &it, auto key_size) mutable {
        ++counter;
        if (it->key().ToStringView() != key4_)
          throw;
        return true;
      },
      "key");
  ASSERT_EQ(counter, 1);
}

TEST_F(RocksDBTest, SimpleEnumerateKeys3) {
  RocksDbCommon common(tx_context_);
  common.enumerate(
      [&](auto const &it, auto key_size) mutable {
        throw;
        return false;
      },
      "keyT");
  common.enumerate(
      [&](auto const &it, auto key_size) mutable {
        throw;
        return false;
      },
      "ko");
}

TEST_F(RocksDBTest, SimpleRewrite) {
  insertDb(key3_, value1_);
  ASSERT_TRUE(readDb(key3_) == value1_);
}

TEST_F(RocksDBTest, NumberRewrite) {
  {
    RocksDbCommon common(tx_context_);
    common.encode(55ull);
    common.put("{}", "123");
  }
  uint64_t value;
  {
    RocksDbCommon common(tx_context_);
    common.get("{}", "123");
    common.decode(value);
  }
  ASSERT_TRUE(value == 55ull);
}

TEST_F(RocksDBTest, Quorum) {
  RocksDbCommon common(tx_context_);
  forQuorum<kDbOperation::kCheck, kDbEntry::kMustNotExist>(
      common,
      "dom",
      "acc",
      [](auto /*account*/, auto /*domain*/, auto /*opt_quorum*/) {});

  common.encode(5);
  forQuorum<kDbOperation::kPut>(
      common,
      "dom",
      "acc",
      [](auto /*account*/, auto /*domain*/, auto /*opt_quorum*/) {});

  forQuorum<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, "dom", "acc", [](auto account, auto domain, auto opt_quorum) {
        ASSERT_EQ(account, "acc");
        ASSERT_EQ(domain, "dom");
        ASSERT_TRUE(opt_quorum);
        ASSERT_EQ(*opt_quorum, 5);
      });
}

TEST_F(RocksDBTest, Signatories) {
  RocksDbCommon common(tx_context_);
  auto cmd_check = [&](std::string_view pk) {
    forSignatory<kDbOperation::kCheck, kDbEntry::kMustNotExist>(
        common,
        "dom",
        "acc",
        pk,
        [](auto /*account*/, auto /*domain*/, auto /*opt_quorum*/) {});
  };

  auto cmd_put = [&](std::string_view pk) {
    common.valueBuffer() = pk;
    common.valueBuffer() += std::string_view{"_test"};
    forSignatory<kDbOperation::kPut>(
        common,
        "dom",
        "acc",
        pk,
        [](auto /*account*/, auto /*domain*/, auto /*opt_quorum*/) {});
  };

  cmd_check("pubkey1");
  cmd_check("pubkey2");
  cmd_check("pubkey3");

  cmd_put("pubkey1");
  cmd_put("pubkey2");
  cmd_put("pubkey3");

  int counter = 0;
  enumerateKeysAndValues(common,
                         [&](auto key, auto value) {
                           if (key.ToStringView() != "pubkey1"
                               && key.ToStringView() != "pubkey2"
                               && key.ToStringView() != "pubkey3")
                             throw;

                           if (key.ToStringView() == "pubkey1"
                               && value.ToStringView() != "pubkey1_test")
                             throw;
                           if (key.ToStringView() == "pubkey2"
                               && value.ToStringView() != "pubkey2_test")
                             throw;
                           if (key.ToStringView() == "pubkey2"
                               && value.ToStringView() != "pubkey2_test")
                             throw;

                           ++counter;
                           return true;
                         },
                         fmtstrings::kPathSignatories,
                         "dom",
                         "acc");

  ASSERT_EQ(counter, 3);
}

TEST(RocksDBTestCommon, Usage) {
  std::string const name = (boost::filesystem::temp_directory_path()
                            / boost::filesystem::unique_path())
                               .string();

  rocksdb::DB *db;
  rocksdb::Options options;
  options.create_if_missing = true;
  options.error_if_exists = true;
  auto status = rocksdb::DB::Open(options, name, &db);
  ASSERT_TRUE(status.ok()) << status.ToString();

  std::string const key{"key"};
  std::string const value{"key"};
  status = db->Put(rocksdb::WriteOptions(), key, value);
  ASSERT_TRUE(status.ok()) << status.ToString();
  std::string read_value;
  status = db->Get(rocksdb::ReadOptions(), key, &read_value);
  ASSERT_TRUE(status.ok()) << status.ToString();
  ASSERT_EQ(read_value, value);

  delete db;

  rocksdb::DestroyDB(name, options);
}
