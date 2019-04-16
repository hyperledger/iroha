/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "framework/test_logger.hpp"
#include "model/converters/pb_query_factory.hpp"
#include "model/converters/pb_transaction_factory.hpp"
#include "model/generators/query_generator.hpp"
#include "model/queries/get_asset_info.hpp"
#include "model/queries/get_roles.hpp"
#include "model/sha3_hash.hpp"

using namespace iroha::model::converters;
using namespace iroha::model::generators;
using namespace iroha::model;

const auto pb_query_factory_logger = getTestLogger("PbQueryFactory");

void runQueryTest(std::shared_ptr<Query> query) {
  PbQueryFactory query_factory(pb_query_factory_logger);
  auto pb_query = query_factory.serialize(query);
  ASSERT_TRUE(pb_query);
  auto res_query = query_factory.deserialize(pb_query.value());
  ASSERT_TRUE(res_query);
  // TODO 26/09/17 grimadas: overload operator == for queries and replace with
  // it IR-512 #goodfirstissue
  ASSERT_EQ(iroha::hash(*(*res_query)), iroha::hash(*query));
}

TEST(PbQueryFactoryTest, SerializeGetAccount) {
  auto created_time = 111u;
  auto creator_account_id = "creator";
  auto query_counter = 222u;
  auto account_id = "test";
  PbQueryFactory query_factory(pb_query_factory_logger);
  QueryGenerator query_generator;
  auto query = query_generator.generateGetAccount(
      created_time, creator_account_id, query_counter, account_id);
  auto pb_query = query_factory.serialize(query);
  ASSERT_TRUE(pb_query);
  auto &pl = pb_query.value().payload();
  auto &pb_cast = pb_query.value().payload().get_account();
  ASSERT_EQ(pl.meta().created_time(), created_time);
  ASSERT_EQ(pl.meta().creator_account_id(), creator_account_id);
  ASSERT_EQ(pl.meta().query_counter(), query_counter);
  ASSERT_EQ(pb_cast.account_id(), account_id);
  auto res_query_opt = query_factory.deserialize(pb_query.value());
  ASSERT_TRUE(res_query_opt);
  auto res_query = *res_query_opt;
  ASSERT_EQ(res_query->created_ts, created_time);
  ASSERT_EQ(res_query->creator_account_id, creator_account_id);
  ASSERT_EQ(res_query->query_counter, query_counter);
  ASSERT_EQ(std::static_pointer_cast<GetAccount>(res_query)->account_id,
            account_id);
  // TODO 26/09/17 grimadas: overload operator == for queries and replace with
  // it IR-512 #goodfirstissue
  ASSERT_EQ(iroha::hash(*res_query), iroha::hash(*query));
}

TEST(PbQueryFactoryTest, SerializeGetAccountAssets) {
  PbQueryFactory query_factory(pb_query_factory_logger);
  QueryGenerator query_generator;
  auto query =
      query_generator.generateGetAccountAssets(0, "123", 0, "test", "coin");
  auto pb_query = query_factory.serialize(query);
  ASSERT_TRUE(pb_query);
  auto res_query = query_factory.deserialize(*pb_query);
  ASSERT_TRUE(res_query);
  // TODO 26/09/17 grimadas: overload operator == for queries and replace with
  // it IR-512 #goodfirstissue
  ASSERT_EQ(iroha::hash(*(*res_query)), iroha::hash(*query));
}

/**
 * @given GetAccountDetail
 * @when Set all data
 * @then Return Protobuf Data
 */
TEST(PbQueryFactoryTest, SerializeGetAccountDetail) {
  PbQueryFactory query_factory(pb_query_factory_logger);
  QueryGenerator query_generator;
  auto query =
      query_generator.generateGetAccountDetail(0, "123", 0, "test", "test2");
  auto pb_query = query_factory.serialize(query);
  ASSERT_TRUE(pb_query);
  auto res_query = query_factory.deserialize(*pb_query);
  ASSERT_TRUE(res_query);
  ASSERT_EQ(iroha::hash(*(*res_query)), iroha::hash(*query));
}

TEST(PbQueryFactoryTest, SerializeGetAccountTransactions) {
  PbQueryFactory query_factory(pb_query_factory_logger);
  QueryGenerator query_generator;
  auto query =
      query_generator.generateGetAccountTransactions(0, "123", 0, "test");
  auto pb_query = query_factory.serialize(query);
  ASSERT_TRUE(pb_query);
  auto res_query = query_factory.deserialize(*pb_query);
  ASSERT_TRUE(res_query);
  // TODO 26/09/17 grimadas: overload operator == for queries and replace with
  // it IR-512 #goodfirstissue
  ASSERT_EQ(iroha::hash(*(*res_query)), iroha::hash(*query));
}

TEST(PbQueryFactoryTest, SerializeGetTransactions) {
  iroha::hash256_t hash1, hash2;
  hash1[0] = 1;
  hash2[1] = 2;
  auto query =
      QueryGenerator{}.generateGetTransactions(0, "admin", 1, {hash1, hash2});
  runQueryTest(query);
}

TEST(PbQueryFactoryTest, SerializeGetSignatories) {
  PbQueryFactory query_factory(pb_query_factory_logger);
  QueryGenerator query_generator;
  auto query = query_generator.generateGetSignatories(0, "123", 0, "test");
  auto pb_query = query_factory.serialize(query);
  ASSERT_TRUE(pb_query);
  auto res_query = query_factory.deserialize(*pb_query);
  ASSERT_TRUE(res_query);
  // TODO 26/09/17 grimadas: overload operator == for queries and replace with
  // it IR-512 #goodfirstissue
  ASSERT_EQ(iroha::hash(*(*res_query)), iroha::hash(*query));
}

TEST(PbQueryFactoryTest, get_roles) {
  auto query = QueryGenerator{}.generateGetRoles();
  runQueryTest(query);
}

TEST(PbQueryFactoryTest, get_role_permissions) {
  auto query = QueryGenerator{}.generateGetRolePermissions();
  runQueryTest(query);
}

TEST(PbQueryFactoryTest, get_asset_info) {
  auto query = QueryGenerator{}.generateGetAssetInfo();
  runQueryTest(query);
}
