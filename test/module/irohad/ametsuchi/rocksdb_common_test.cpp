/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <gtest/gtest.h>
#include <boost/filesystem.hpp>
#include <iostream>
#include <set>

#include "ametsuchi/impl/database_cache/cache.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "common/radix_tree.hpp"

namespace fs = boost::filesystem;
using namespace iroha::ametsuchi;

struct QQQ {
  std::string s;
  QQQ(std::string const &p) : s(p) {
    std::cout << "CTOR" << std::endl;
  }
  QQQ(char const *p) : s(p) {
    std::cout << "CTOR" << std::endl;
  }
  ~QQQ() {
    std::cout << "~CTOR" << std::endl;
  }
};

class RocksDBTest : public ::testing::Test {
 public:
  void SetUp() override {
    db_name_ = (fs::temp_directory_path() / fs::unique_path()).string();
    db_port_ = std::make_shared<RocksDBPort>();
    db_port_->initialize(db_name_);

    auto dbc = std::make_shared<DatabaseCache<std::string>>();
    dbc->addCacheblePath("k");
    tx_context_ = std::make_shared<RocksDBContext>(db_port_, std::move(dbc));

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
    common.commit();
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

TEST_F(RocksDBTest, DatabaseCacheTest) {
  iroha::ametsuchi::DatabaseCache<std::string> dbc;
  dbc.addCacheblePath("wSc");
  dbc.addCacheblePath("wScq");
  dbc.addCacheblePath("bps");
  dbc.addCacheblePath("bps");
  dbc.addCacheblePath("bpsQ");
  dbc.addCacheblePath("bpsQ0");
  dbc.addCacheblePath("bpm");

  dbc.addCacheblePath("12");
  dbc.addCacheblePath("1");

  std::string src[] = {"bps1", "1jg", "0pp", "2"};

  {
    size_t counter = 0ull;
    for (auto &s : src)
      if (dbc.isCacheable(s)) {
        dbc.set(s, s + "_value");
        ++counter;
      }
    ASSERT_EQ(counter, 2ull);
  }

  auto check = [](auto const &str1, auto const &str2) {
    ASSERT_EQ(str1, str2);
  };

  size_t counter = 0ull;
  for (auto &s : src)
    if (dbc.get(s, [&](auto const &str) {
          check(str, s + "_value");
          return true;
        }))
      ++counter;
  ASSERT_EQ(counter, 2ull);
}

TEST_F(RocksDBTest, RadixTreeFilterEnum2) {
  iroha::RadixTree<QQQ, iroha::Alphabet, char, 2ul> rt;
  std::set<std::string> expect;
  auto insert = [&](std::string_view data, bool do_expected_insert) {
    rt.insert(data.data(), data.size(), data.data());
    if (do_expected_insert)
      expect.insert(std::string{data});
  };

  insert("1", true);
  insert("12578", true);
  insert("125789", true);
  insert("1257890000", true);
  insert("123", true);
  insert("124", true);

  auto filter = [&](std::string_view key, QQQ *data) {
    ASSERT_NE(data, nullptr);
    ASSERT_FALSE(data->s.empty());
    ASSERT_TRUE(key == data->s);

    auto it = expect.find(data->s);
    ASSERT_NE(it, expect.end());

    expect.erase(it);
  };

  rt.filterEnumerate(nullptr, 0ul, filter);
  ASSERT_TRUE(expect.empty());
}

TEST_F(RocksDBTest, RadixTreeFilterEnum) {
  iroha::RadixTree<QQQ, iroha::Alphabet, char, 2ul> rt;
  std::set<std::string> expect;
  auto insert = [&](std::string_view data, bool do_expected_insert) {
    rt.insert(data.data(), data.size(), data.data());
    if (do_expected_insert)
      expect.insert(std::string{data});
  };

  auto filter = [&](std::string_view key, QQQ *data) {
    ASSERT_NE(data, nullptr);
    ASSERT_FALSE(data->s.empty());
    ASSERT_TRUE(key == data->s);

    auto it = expect.find(data->s);
    ASSERT_NE(it, expect.end());

    expect.erase(it);
  };

  insert("1", true);
  rt.filterEnumerate("1", 1, filter);
  ASSERT_TRUE(expect.empty());

  insert("12", true);
  insert("123", true);
  insert("124", true);
  rt.filterEnumerate("12", 2, filter);
  ASSERT_TRUE(expect.empty());

  insert("1256", true);
  insert("1257", true);
  rt.filterEnumerate("125", 3, filter);
  ASSERT_TRUE(expect.empty());

  insert("12578", true);
  insert("125789", true);
  insert("1257890000", true);
  expect.insert("1257");
  rt.filterEnumerate("1257", 4, filter);
  ASSERT_TRUE(expect.empty());
}

TEST_F(RocksDBTest, RadixTreeTest) {
  iroha::RadixTree<QQQ, iroha::Alphabet, char, 2ul> rt;

  rt.insert("1234", 4, "9");
  rt.filterDelete("123", 3);
  ASSERT_TRUE(rt.find("1", 1) == nullptr);
  ASSERT_TRUE(rt.find("12", 2) == nullptr);
  ASSERT_TRUE(rt.find("123", 3) == nullptr);
  ASSERT_TRUE(rt.find("1234", 4) == nullptr);

  rt.insert("123", 3, "d");
  rt.filterDelete("12", 2);
  ASSERT_TRUE(rt.find("1", 1) == nullptr);
  ASSERT_TRUE(rt.find("12", 2) == nullptr);
  ASSERT_TRUE(rt.find("123", 3) == nullptr);

  rt.insert("123", 3, "d");
  rt.filterDelete("1", 1);
  ASSERT_TRUE(rt.find("1", 1) == nullptr);
  ASSERT_TRUE(rt.find("12", 2) == nullptr);
  ASSERT_TRUE(rt.find("123", 3) == nullptr);

  rt.insert("123", 3, "d");
  rt.filterDelete("123", 3);
  ASSERT_TRUE(rt.find("1", 1) == nullptr);
  ASSERT_TRUE(rt.find("12", 2) == nullptr);
  ASSERT_TRUE(rt.find("123", 3) == nullptr);

  rt.insert("123", 3, "q");
  rt.filterDelete("1234", 4);
  ASSERT_TRUE(rt.find("1", 1) == nullptr);
  ASSERT_TRUE(rt.find("12", 2) == nullptr);
  ASSERT_TRUE(rt.find("123", 3)->s == "q");

  rt.insert("123", 3, "q");
  rt.insert("11", 2, "1");
  rt.filterDelete("12", 2);
  ASSERT_TRUE(rt.find("123", 3) == nullptr);
  ASSERT_TRUE(rt.find("11", 2)->s == "1");

  rt.insert("123", 3, "q");
  rt.insert("11", 2, "1");
  rt.filterDelete("1", 1);
  ASSERT_TRUE(rt.find("123", 3) == nullptr);
  ASSERT_TRUE(rt.find("11", 2) == nullptr);

  rt.insert("123", 3, "q");
  rt.insert("11", 2, "1");
  rt.insert("124", 3, "d");

  rt.filterDelete("123", 3);
  ASSERT_TRUE(rt.find("123", 3) == nullptr);
  ASSERT_TRUE(rt.find("124", 3)->s == "d");
  ASSERT_TRUE(rt.find("11", 2)->s == "1");

  rt.filterDelete("12", 2);
  ASSERT_TRUE(rt.find("123", 3) == nullptr);
  ASSERT_TRUE(rt.find("124", 3) == nullptr);
  ASSERT_TRUE(rt.find("11", 2)->s == "1");

  rt.insert("7123", 4, "d");
  rt.insert("711", 3, "q");
  rt.insert("7124", 4, "a");

  ASSERT_TRUE(rt.find("7123", 4)->s == "d");
  ASSERT_TRUE(rt.find("711", 3)->s == "q");
  ASSERT_TRUE(rt.find("7124", 4)->s == "a");
  ASSERT_TRUE(rt.find("7", 1) == nullptr);
  ASSERT_TRUE(rt.find("71", 2) == nullptr);
  ASSERT_TRUE(rt.find("72", 2) == nullptr);

  ASSERT_EQ(rt.erase("7123", 4), 1ull);
  ASSERT_TRUE(rt.find("7123", 4) == nullptr);
  ASSERT_TRUE(rt.find("711", 3)->s == "q");
  ASSERT_TRUE(rt.find("7124", 4)->s == "a");

  ASSERT_EQ(rt.erase("7124", 4), 1ull);
  ASSERT_TRUE(rt.find("711", 3)->s == "q");
  ASSERT_TRUE(rt.find("7124", 4) == nullptr);

  ASSERT_EQ(rt.erase("7123", 4), 0ull);
  ASSERT_TRUE(rt.find("711", 3)->s == "q");
  ASSERT_TRUE(rt.find("7123", 4) == nullptr);

  ASSERT_EQ(rt.erase("711", 3), 1ull);
  ASSERT_TRUE(rt.find("711", 3) == nullptr);

  rt.insert("1345", 4, "l");
  rt.insert("1346", 4, "lll");
  rt.insert("1444", 4, "ll");

  ASSERT_TRUE(rt.find("1345", 4)->s == "l");
  ASSERT_TRUE(rt.find("1346", 4)->s == "lll");
  ASSERT_TRUE(rt.find("1444", 4)->s == "ll");

  rt.insert("1444", 4, "dd");
  ASSERT_TRUE(rt.find("1444", 4)->s == "dd");

  ASSERT_EQ(rt.erase("1444", 4), 1ull);
  ASSERT_TRUE(rt.find("1444", 4) == nullptr);

  rt.insert("1444", 4, "m");
  ASSERT_TRUE(rt.find("1444", 4)->s == "m");
  ASSERT_TRUE(rt.find("1345", 4)->s == "l");
  ASSERT_TRUE(rt.find("1346", 4)->s == "lll");

  rt.insert("1100123", 7, "123");
  ASSERT_TRUE(rt.find("1100123", 7)->s == "123");

  ASSERT_EQ(rt.erase("110", 3), 0ull);
  ASSERT_TRUE(rt.find("110", 3) == nullptr);
  ASSERT_TRUE(rt.find("1100123", 7)->s == "123");

  rt.insert("1100123456", 10, "123456");
  rt.insert("110012345", 9, "12345");
  rt.insert("11001234567", 11, "1234567");
  rt.insert("1100123455", 10, "123455");
  rt.insert("1100123456", 10, "111");
  rt.insert("1100120", 7, "120");
  rt.insert("0011890", 7, "890");
  rt.insert("0011897", 7, "897");
  rt.insert("00118", 5, "8");

  ASSERT_TRUE(rt.find("1100123456", 10)->s == "111");
  ASSERT_TRUE(rt.find("110012345", 9)->s == "12345");
  ASSERT_TRUE(rt.find("11001234567", 11)->s == "1234567");
  ASSERT_TRUE(rt.find("1100123455", 10)->s == "123455");
  ASSERT_TRUE(rt.find("1100120", 7)->s == "120");
  ASSERT_TRUE(rt.find("0011890", 7)->s == "890");
  ASSERT_TRUE(rt.find("0011897", 7)->s == "897");
  ASSERT_TRUE(rt.find("00118", 5)->s == "8");

  ASSERT_EQ(rt.erase("1100123456", 10), 1ull);
  ASSERT_EQ(rt.erase("11001234567", 11), 1ull);
  ASSERT_EQ(rt.erase("1100120", 7), 1ull);
  ASSERT_EQ(rt.erase("0011890", 7), 1ull);
  ASSERT_EQ(rt.erase("1100sg3456", 10), 0ull);
  ASSERT_EQ(rt.erase("1103242556#", 11), 0ull);
  ASSERT_EQ(rt.erase("1d100120", 8), 0ull);
  ASSERT_EQ(rt.erase("1100123456", 10), 0ull);
  ASSERT_EQ(rt.erase("11001234567", 11), 0ull);
  ASSERT_EQ(rt.erase("1100120", 7), 0ull);

  ASSERT_TRUE(rt.find("1100123456", 10) == nullptr);
  ASSERT_TRUE(rt.find("11001234567", 11) == nullptr);
  ASSERT_TRUE(rt.find("1100120", 7) == nullptr);
  ASSERT_TRUE(rt.find("0011890", 7) == nullptr);
  ASSERT_TRUE(rt.find("110012345", 9)->s == "12345");
  ASSERT_TRUE(rt.find("1100123455", 10)->s == "123455");
  ASSERT_TRUE(rt.find("0011897", 7)->s == "897");
  ASSERT_TRUE(rt.find("00118", 5)->s == "8");
  ASSERT_TRUE(rt.find("1444", 4)->s == "m");
  ASSERT_TRUE(rt.find("1345", 4)->s == "l");
  ASSERT_TRUE(rt.find("1346", 4)->s == "lll");
  ASSERT_TRUE(rt.find("1100123", 7)->s == "123");
  ASSERT_TRUE(rt.find("110", 3) == nullptr);
  ASSERT_TRUE(rt.find("7123", 4) == nullptr);
  ASSERT_TRUE(rt.find("711", 3) == nullptr);
  ASSERT_TRUE(rt.find("7124", 4) == nullptr);

  rt.filterDelete("11", 2);
  ASSERT_TRUE(rt.find("110012345", 9) == nullptr);
  ASSERT_TRUE(rt.find("1100123455", 10) == nullptr);
  ASSERT_TRUE(rt.find("0011897", 7)->s == "897");
  ASSERT_TRUE(rt.find("00118", 5)->s == "8");
  ASSERT_TRUE(rt.find("1444", 4)->s == "m");
  ASSERT_TRUE(rt.find("1345", 4)->s == "l");
  ASSERT_TRUE(rt.find("1346", 4)->s == "lll");
  ASSERT_TRUE(rt.find("1100123", 7) == nullptr);
}

TEST_F(RocksDBTest, SimpleOperation) {
  ASSERT_TRUE(readDb(key1_) == value1_);
  ASSERT_TRUE(readDb(key2_) == value2_);
  ASSERT_TRUE(readDb(key3_) == value3_);
  ASSERT_TRUE(readDb(key4_) == value4_);
  ASSERT_TRUE(readDb(key5_) == value5_);
}

TEST_F(RocksDBTest, SimpleDelete) {
  RocksDbCommon common(tx_context_);
  ASSERT_TRUE(common.del(key3_).ok());

  auto status = common.get(key3_);
  ASSERT_TRUE(status.IsNotFound());
}

TEST_F(RocksDBTest, SimpleInsert) {
  RocksDbCommon common(tx_context_);

  common.valueBuffer() = "k777";
  common.put("k777");

  common.valueBuffer().clear();
  auto status = common.get("k777");
  ASSERT_TRUE(status.ok());
  ASSERT_TRUE(common.valueBuffer() == "k777");
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
  auto status = common.enumerate(
      [&](auto const &it, auto key_size) mutable {
        ++counter;
        if (it->key().ToStringView() != key1_
            && it->key().ToStringView() != key2_)
          throw;
        return true;
      },
      "keY");
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(counter, 2);
}

TEST_F(RocksDBTest, FilterDelete) {
  {
    RocksDbCommon common(tx_context_);
    insertDb("ab", "ab");
    insertDb("k", "121");
    ASSERT_TRUE(common.filterDelete(2ull, "keY").second.ok());
    ASSERT_TRUE(common.commit().ok());
  }
  {
    RocksDbCommon common(tx_context_);
    ASSERT_TRUE(common.get(key1_).IsNotFound());
    ASSERT_TRUE(common.get(key2_).IsNotFound());
  }
  {
    ASSERT_TRUE(readDb(key3_) == value3_);
    ASSERT_TRUE(readDb(key4_) == value4_);
    ASSERT_TRUE(readDb(key5_) == value5_);
  }
}

TEST_F(RocksDBTest, FilterDelete2) {
  {
    RocksDbCommon common(tx_context_);
    ASSERT_TRUE(common.filterDelete(1ull, "keY").second.ok());
    ASSERT_TRUE(common.commit().ok());
  }
  {
    RocksDbCommon common(tx_context_);
    ASSERT_TRUE(common.get(key1_).IsNotFound());
  }
  {
    ASSERT_TRUE(readDb(key2_) == value2_);
    ASSERT_TRUE(readDb(key3_) == value3_);
    ASSERT_TRUE(readDb(key4_) == value4_);
    ASSERT_TRUE(readDb(key5_) == value5_);
  }
}

TEST_F(RocksDBTest, FilterDelete3) {
  {
    RocksDbCommon common(tx_context_);
    ASSERT_TRUE(common.filterDelete(1000ull, "keY").second.ok());
    ASSERT_TRUE(common.commit().ok());
  }
  {
    RocksDbCommon common(tx_context_);
    ASSERT_TRUE(common.get(key1_).IsNotFound());
    ASSERT_TRUE(common.get(key2_).IsNotFound());
  }
  {
    ASSERT_TRUE(readDb(key3_) == value3_);
    ASSERT_TRUE(readDb(key4_) == value4_);
    ASSERT_TRUE(readDb(key5_) == value5_);
  }
}

TEST_F(RocksDBTest, SimpleEnumerateKeys2) {
  RocksDbCommon common(tx_context_);
  int counter = 0;
  auto status = common.enumerate(
      [&](auto const &it, auto key_size) {
        ++counter;
        if (it->key().ToStringView() != key4_)
          throw;
        return true;
      },
      "key");
  ASSERT_TRUE(status.ok());
  ASSERT_EQ(counter, 1);
}

TEST_F(RocksDBTest, SimpleEnumerateKeys3) {
  RocksDbCommon common(tx_context_);
  ASSERT_TRUE(common
                  .enumerate(
                      [&](auto const &it, auto key_size) mutable {
                        throw;
                        return false;
                      },
                      "keyT")
                  .ok());
  ASSERT_TRUE(common
                  .enumerate(
                      [&](auto const &it, auto key_size) mutable {
                        throw;
                        return false;
                      },
                      "ko")
                  .ok());
}

TEST_F(RocksDBTest, SimpleRewrite) {
  insertDb(key3_, value1_);
  ASSERT_TRUE(readDb(key3_) == value1_);
}

TEST_F(RocksDBTest, NumberRewrite) {
  {
    RocksDbCommon common(tx_context_);
    common.encode(55ull);
    ASSERT_TRUE(common.put("{}", "123").ok());
    ASSERT_TRUE(common.commit().ok());
  }
  uint64_t value;
  {
    RocksDbCommon common(tx_context_);
    ASSERT_TRUE(common.get("{}", "123").ok());
    common.decode(value);
  }
  ASSERT_TRUE(value == 55ull);
}

TEST_F(RocksDBTest, Skip) {
  {
    RocksDbCommon common(tx_context_);
    common.encode(55ull);
    ASSERT_TRUE(common.put("123").ok());
    common.skip();
  }
  {
    RocksDbCommon common(tx_context_);
    ASSERT_FALSE(common.get("123").ok());
    ASSERT_TRUE(common.get("123").IsNotFound());
  }
}

TEST_F(RocksDBTest, Quorum) {
  RocksDbCommon common(tx_context_);

  {
    auto q = forQuorum<kDbOperation::kCheck, kDbEntry::kMustNotExist>(
        common, "acc", "dom");
    ASSERT_FALSE(iroha::expected::hasError(q));
  }

  {
    auto q = forQuorum<kDbOperation::kCheck, kDbEntry::kMustExist>(
        common, "acc", "dom");
    ASSERT_TRUE(iroha::expected::hasError(q));
  }

  {
    common.encode(5);
    auto q = forQuorum<kDbOperation::kPut>(common, "acc", "dom");
    ASSERT_FALSE(iroha::expected::hasError(q));
  }

  {
    auto q = forQuorum<kDbOperation::kGet, kDbEntry::kMustExist>(
        common, "acc", "dom");
    ASSERT_FALSE(iroha::expected::hasError(q));
    ASSERT_TRUE(iroha::expected::hasValue(q));

    ASSERT_TRUE(q.assumeValue());
    ASSERT_EQ(q.assumeValue(), 5);
  }
}

TEST_F(RocksDBTest, SortingOrder) {
  RocksDbCommon common(tx_context_);
  common.filterDelete(1ull, "");

  common.valueBuffer().clear();
  ASSERT_TRUE(common.put("5").ok());
  ASSERT_TRUE(common.put("3").ok());
  ASSERT_TRUE(common.put("11").ok());
  ASSERT_TRUE(common.put("6").ok());
  ASSERT_TRUE(common.put("27").ok());
  ASSERT_TRUE(common.put("1").ok());
  ASSERT_TRUE(common.put("144").ok());
  ASSERT_TRUE(common.put("2").ok());

  std::vector<std::string> s;
  common.enumerate(
      [&s](auto const &it, auto const prefix_size) mutable {
        assert(it->Valid());
        auto const key = it->key();
        s.push_back(std::string(key.ToStringView()));
        return true;
      },
      "");

  ASSERT_EQ(s[0], "1");
  ASSERT_EQ(s[1], "11");
  ASSERT_EQ(s[2], "144");
  ASSERT_EQ(s[3], "2");
  ASSERT_EQ(s[4], "27");
  ASSERT_EQ(s[5], "3");
  ASSERT_EQ(s[6], "5");
  ASSERT_EQ(s[7], "6");
}

TEST_F(RocksDBTest, LowerBoundSearch) {
  RocksDbCommon common(tx_context_);
  common.filterDelete(1ull, "");

  char const *target = "wta1234569#1#2";
  char const *target2 = "wta1234367#1#1";

  common.valueBuffer().clear();
  ASSERT_TRUE(common.put(target2).ok());
  ASSERT_TRUE(common.put(target).ok());
  ASSERT_TRUE(common.put("wta1234570#2#1").ok());

  {
    auto it = common.seek("wta0");
    ASSERT_TRUE(it->Valid());
    ASSERT_TRUE(it->key().ToStringView() == target2);
  }

  {
    auto it = common.seek("wta1234411#0#0");
    ASSERT_TRUE(it->Valid());
    ASSERT_TRUE(it->key().ToStringView() == target);
  }

  {
    auto it = common.seek("wta1234411");
    ASSERT_TRUE(it->Valid());
    ASSERT_TRUE(it->key().ToStringView() == target);
  }

  {
    auto it = common.seek("wta1239411");
    ASSERT_FALSE(it->Valid());
  }
}

TEST_F(RocksDBTest, Signatories) {
  RocksDbCommon common(tx_context_);
  auto cmd_check = [&](std::string_view pk) {
    return forSignatory<kDbOperation::kCheck, kDbEntry::kMustNotExist>(
        common, "acc", "dom", pk);
  };

  auto cmd_put = [&](std::string_view pk) {
    common.valueBuffer() = pk;
    common.valueBuffer() += std::string_view{"_test"};
    return forSignatory<kDbOperation::kPut>(common, "acc", "dom", pk);
  };

  auto pkeys = {"pubkey1", "pubkey2", "pubkey3"};
  for (auto &pk : pkeys) {
    {
      auto result = cmd_check(pk);
      ASSERT_FALSE(iroha::expected::hasError(result));
    }
    {
      auto result = cmd_put(pk);
      ASSERT_FALSE(iroha::expected::hasError(result));
    }
  }

  int counter = 0;
  auto status = enumerateKeysAndValues(
      common,
      [&](auto key, auto value) {
        if (key.ToStringView() != "pubkey1" && key.ToStringView() != "pubkey2"
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

  ASSERT_TRUE(status.ok());
  ASSERT_EQ(counter, 3);
}
