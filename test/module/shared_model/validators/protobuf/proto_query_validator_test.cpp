/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_query_validator.hpp"

#include <gmock/gmock-matchers.h>
#include "module/shared_model/validators/validators_fixture.hpp"
#include "queries.pb.h"

using testing::HasSubstr;

class ProtoQueryValidatorTest : public ValidatorsTest {
 public:
  shared_model::validation::ProtoQueryValidator validator;
};

/**
 * @given Protobuf query object with unset query
 * @when validate is called
 * @then there is an error returned
 */
TEST_F(ProtoQueryValidatorTest, UnsetQuery) {
  iroha::protocol::Query qry;
  qry.mutable_payload()->mutable_meta()->set_created_time(created_time);
  qry.mutable_payload()->mutable_meta()->set_creator_account_id(account_id);
  qry.mutable_payload()->mutable_meta()->set_query_counter(counter);

  auto answer = validator.validate(qry);
  ASSERT_TRUE(answer.hasErrors());
  ASSERT_THAT(answer.reason(), HasSubstr("undefined"));
}

/**
 * @given well-formed protobuf query object
 * @when validated is called
 * @then validation is passed
 */
TEST_F(ProtoQueryValidatorTest, SetQuery) {
  iroha::protocol::Query qry;
  qry.mutable_payload()->mutable_get_account()->set_account_id(account_id);

  auto answer = validator.validate(qry);
  ASSERT_FALSE(answer.hasErrors());
}

iroha::protocol::Query generateGetAccountAssetTransactionsQuery(
    const std::string &first_tx_hash) {
  iroha::protocol::Query result;
  result.mutable_payload()
      ->mutable_get_account_asset_transactions()
      ->mutable_pagination_meta()
      ->set_first_tx_hash(first_tx_hash);
  return result;
}

iroha::protocol::Query generateGetAccountTransactionsQuery(
    const std::string &first_tx_hash) {
  iroha::protocol::Query result;
  result.mutable_payload()
      ->mutable_get_account_transactions()
      ->mutable_pagination_meta()
      ->set_first_tx_hash(first_tx_hash);
  return result;
}

static std::string valid_tx_hash("123abc");
static std::string invalid_tx_hash("not_hex");

// valid pagination query tests

class ValidProtoPaginationQueryValidatorTest
    : public ProtoQueryValidatorTest,
      public ::testing::WithParamInterface<iroha::protocol::Query> {};

TEST_P(ValidProtoPaginationQueryValidatorTest, ValidPaginationQuery) {
  auto answer = validator.validate(GetParam());
  ASSERT_FALSE(answer.hasErrors()) << GetParam().DebugString() << std::endl
                                   << answer.reason();
}

INSTANTIATE_TEST_CASE_P(
    ProtoPaginationQueryTest,
    ValidProtoPaginationQueryValidatorTest,
    ::testing::Values(generateGetAccountAssetTransactionsQuery(valid_tx_hash),
                      generateGetAccountTransactionsQuery(valid_tx_hash)), );

// invalid pagination query tests

class InvalidProtoPaginationQueryTest
    : public ProtoQueryValidatorTest,
      public ::testing::WithParamInterface<iroha::protocol::Query> {};

TEST_P(InvalidProtoPaginationQueryTest, InvalidPaginationQuery) {
  auto answer = validator.validate(GetParam());
  ASSERT_TRUE(answer.hasErrors()) << GetParam().DebugString();
}

INSTANTIATE_TEST_CASE_P(
    InvalidProtoPaginationQueryTest,
    InvalidProtoPaginationQueryTest,
    ::testing::Values(generateGetAccountAssetTransactionsQuery(invalid_tx_hash),
                      generateGetAccountTransactionsQuery(invalid_tx_hash)), );
