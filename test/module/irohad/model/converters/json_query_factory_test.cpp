/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/json_query_factory.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "framework/test_logger.hpp"
#include "model/converters/json_common.hpp"
#include "model/generators/query_generator.hpp"
#include "model/generators/signature_generator.hpp"
#include "model/queries/get_asset_info.hpp"
#include "model/queries/get_roles.hpp"
#include "model/sha3_hash.hpp"

using namespace iroha;
using namespace iroha::model;
using namespace iroha::model::converters;
using namespace iroha::model::generators;

const auto json_query_factory_logger = getTestLogger("JsonQueryFactory");

void runQueryTest(std::shared_ptr<Query> val) {
  JsonQueryFactory queryFactory(json_query_factory_logger);
  auto json = queryFactory.serialize(val);
  auto ser_val = queryFactory.deserialize(json);
  ASSERT_TRUE(ser_val);
  ASSERT_EQ(iroha::hash(*val), iroha::hash(*ser_val.value()));
  ASSERT_EQ(val->signature.signature, ser_val.value()->signature.signature);
}

TEST(QuerySerializerTest, ClassHandlerTest) {
  JsonQueryFactory factory(json_query_factory_logger);
  std::vector<std::shared_ptr<Query>> commands = {
      std::make_shared<GetAccount>(),
      std::make_shared<GetAccountAssets>(),
      std::make_shared<GetSignatories>(),
      std::make_shared<GetAccountAssetTransactions>(),
      std::make_shared<GetAccountTransactions>()};
  for (const auto &command : commands) {
    auto ser = factory.serialize(command);
    auto des = factory.deserialize(ser);
    ASSERT_TRUE(des);
  }
}

TEST(QuerySerializerTest, DeserializeGetAccountWhenValid) {
  JsonQueryFactory querySerializer(json_query_factory_logger);

  auto json_query = R"({
    "signature":{
        "pubkey":"2323232323232323232323232323232323232323232323232323232323232323",
        "signature":"23232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323"
    },
    "created_ts":0,
    "creator_account_id":"123",
    "query_counter":0,
    "query_type":"GetAccount",
    "account_id":"test@test"
  })";
  auto res = querySerializer.deserialize(json_query);
  ASSERT_TRUE(res);
  ASSERT_EQ("123", (*res)->creator_account_id);
}

TEST(QuerySerializerTest, DeserializeGetAccountWhenInvalid) {
  JsonQueryFactory querySerializer(json_query_factory_logger);
  auto json_query = R"({
    "created_ts":0,
    "creator_account_id":"123",
    "query_counter":0,
    "query_type":"GetAccount"
  })";
  auto res = querySerializer.deserialize(json_query);
  ASSERT_FALSE(res);
}

TEST(QuerySerializerTest, DeserializeGetAccountAssetsWhenValid) {
  JsonQueryFactory querySerializer(json_query_factory_logger);
  auto json_query = R"({
    "signature":{
        "pubkey":"2323232323232323232323232323232323232323232323232323232323232323",
        "signature":"23232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323"
    },
    "created_ts":0,
    "creator_account_id":"123",
    "query_counter":0,
    "query_type":"GetAccountAssets",
    "account_id":"test@test"
  })";
  auto res = querySerializer.deserialize(json_query);
  ASSERT_TRUE(res);
  auto casted = std::static_pointer_cast<iroha::model::GetAccountAssets>(*res);
  ASSERT_EQ("test@test", casted->account_id);
}

/**
 * @given The json transaction that has valid and invalid hashes.
 * @when Deserialize the json transaction.
 * @then Validate the invalid hash is skipped and the only valid deserialized.
 */
TEST(QuerySerializerTest, DeserializeGetAccountDetailWhenValid) {
  JsonQueryFactory querySerializer(json_query_factory_logger);
  auto json_query = R"({
    "signature":{
        "pubkey":"2323232323232323232323232323232323232323232323232323232323232323",
        "signature":"23232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323"
    },
    "created_ts":0,
    "creator_account_id":"123",
    "query_counter":0,
    "query_type":"GetAccountDetail",
    "account_id":"test@test"
  })";
  auto res = querySerializer.deserialize(json_query);
  ASSERT_TRUE(res);
  auto casted = std::static_pointer_cast<iroha::model::GetAccountDetail>(*res);
  ASSERT_EQ("test@test", casted->account_id);
}

TEST(QuerySerializerTest, DeserializeWhenUnknownType) {
  JsonQueryFactory querySerializer(json_query_factory_logger);
  auto json_query = R"(
    "signature":{
        "pubkey":"2323232323232323232323232323232323232323232323232323232323232323",
        "signature":"23232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323"
    },
    "created_ts":0,
    "creator_account_id":"123",
    "query_counter":0,
    "query_type":"GetSomething",
    "account_id":"test@test",
    "asset_id":"coin#test"
  })";
  auto res = querySerializer.deserialize(json_query);
  ASSERT_FALSE(res);
}

/**
 * @given The json transaction that has valid and invalid hashes.
 * @when Deserialize the json transaction.
 * @then Validate the invalid hash is skipped and the only valid deserialized.
 */
TEST(QuerySerialzierTest, DeserializeGetTransactionsWithInvalidHash) {
  JsonQueryFactory queryFactory(json_query_factory_logger);
  iroha::hash256_t valid_size_hash{};
  valid_size_hash[0] = 1;
  QueryGenerator queryGenerator;
  const auto val =
      queryGenerator.generateGetTransactions(0, "123", 0, {valid_size_hash});
  const auto json = queryFactory.serialize(val);
  auto json_doc_opt = iroha::model::converters::stringToJson(json);
  ASSERT_TRUE(json_doc_opt);

  auto &json_doc = *json_doc_opt;
  auto &allocator = json_doc.GetAllocator();

  rapidjson::Value tx_hashes;
  tx_hashes.SetArray();
  rapidjson::Value invalid_size_hash;
  invalid_size_hash.SetString("123", 3, allocator);
  tx_hashes.PushBack(invalid_size_hash, allocator);
  for (auto &e : json_doc["tx_hashes"].GetArray()) {
    rapidjson::Value value;
    const std::string str = e.GetString();
    value.Set(str, allocator);
    tx_hashes.PushBack(value, allocator);
  }
  json_doc["tx_hashes"].Swap(tx_hashes);
  auto res = queryFactory.deserialize(
      iroha::model::converters::jsonToString(json_doc));
  ASSERT_TRUE(res);
  auto casted = std::static_pointer_cast<GetTransactions>(*res);
  ASSERT_EQ(1, casted->tx_hashes.size());
  ASSERT_EQ(valid_size_hash, casted->tx_hashes[0]);
}

TEST(QuerySerializerTest, SerializeGetAccount) {
  JsonQueryFactory queryFactory(json_query_factory_logger);
  QueryGenerator queryGenerator;
  auto val = queryGenerator.generateGetAccount(0, "123", 0, "test");
  auto json = queryFactory.serialize(val);
  auto ser_val = queryFactory.deserialize(json);
  ASSERT_TRUE(ser_val);
  ASSERT_EQ(iroha::hash(*val), iroha::hash(*(*ser_val)));
  ASSERT_EQ(val->signature.signature, (*ser_val)->signature.signature);
}

TEST(QuerySerializerTest, SerializeGetAccountAssets) {
  JsonQueryFactory queryFactory(json_query_factory_logger);
  QueryGenerator queryGenerator;
  auto val =
      queryGenerator.generateGetAccountAssets(0, "123", 0, "test", "coin");
  auto json = queryFactory.serialize(val);
  auto ser_val = queryFactory.deserialize(json);
  ASSERT_TRUE(ser_val);
  ASSERT_EQ(iroha::hash(*val), iroha::hash(*(*ser_val)));
  ASSERT_EQ(val->signature.signature, (*ser_val)->signature.signature);
}

TEST(QuerySerializerTest, SerializeGetAccountTransactions) {
  JsonQueryFactory queryFactory(json_query_factory_logger);
  QueryGenerator queryGenerator;
  auto val = queryGenerator.generateGetAccountTransactions(0, "123", 0, "test");
  auto json = queryFactory.serialize(val);
  auto ser_val = queryFactory.deserialize(json);
  ASSERT_TRUE(ser_val);
  ASSERT_EQ(iroha::hash(*val), iroha::hash(*(*ser_val)));
  ASSERT_EQ(val->signature.signature, (*ser_val)->signature.signature);
}

TEST(QuerySerializerTest, SerialiizeGetTransactions) {
  QueryGenerator queryGenerator;
  iroha::hash256_t hash1, hash2;
  hash1[0] = 1, hash2[0] = 2;
  auto val =
      queryGenerator.generateGetTransactions(0, "admin", 0, {hash1, hash2});
  runQueryTest(val);
}

TEST(QuerySerializerTest, SerializeGetSignatories) {
  JsonQueryFactory queryFactory(json_query_factory_logger);
  QueryGenerator queryGenerator;
  auto val = queryGenerator.generateGetSignatories(0, "123", 0, "test");
  auto json = queryFactory.serialize(val);
  auto ser_val = queryFactory.deserialize(json);
  ASSERT_TRUE(ser_val);
  ASSERT_EQ(iroha::hash(*val), iroha::hash(*(*ser_val)));
  ASSERT_EQ(val->signature.signature, (*ser_val)->signature.signature);
}

TEST(QuerySerializerTest, get_asset_info) {
  QueryGenerator queryGenerator;
  auto val = queryGenerator.generateGetAssetInfo();
  runQueryTest(val);
}

TEST(QuerySerializerTest, get_roles) {
  QueryGenerator queryGenerator;
  auto val = queryGenerator.generateGetRoles();
  runQueryTest(val);
}

TEST(QuerySerializerTest, get_role_permissions) {
  QueryGenerator queryGenerator;
  auto val = queryGenerator.generateGetRolePermissions();
  runQueryTest(val);
}
