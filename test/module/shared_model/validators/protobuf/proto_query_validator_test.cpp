/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/protobuf/proto_query_validator.hpp"

#include <gmock/gmock-matchers.h>
#include <google/protobuf/util/time_util.h>

#include <optional>

#include "module/shared_model/validators/validators_fixture.hpp"
#include "queries.pb.h"
#include "validators/validation_error_output.hpp"

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

  auto error = validator.validate(qry);
  ASSERT_TRUE(error);
  ASSERT_THAT(error->toString(), HasSubstr("undefined"));
}

/**
 * @given well-formed protobuf query object
 * @when validated is called
 * @then validation is passed
 */
TEST_F(ProtoQueryValidatorTest, SetQuery) {
  iroha::protocol::Query qry;
  qry.mutable_payload()->mutable_get_account()->set_account_id(account_id);

  ASSERT_EQ(validator.validate(qry), std::nullopt);
}

iroha::protocol::Query generateGetAccountAssetTransactionsQuery(
    const std::optional<std::string> &first_tx_hash = std::nullopt,
    const std::optional<int64_t> &first_tx_time = std::nullopt,
    const std::optional<int64_t> &last_tx_time = std::nullopt,
    const std::optional<uint64_t> &first_tx_height = std::nullopt,
    const std::optional<uint64_t> &last_tx_height = std::nullopt) {
  iroha::protocol::Query result;
  if (first_tx_hash) {
    result.mutable_payload()
        ->mutable_get_account_asset_transactions()
        ->mutable_pagination_meta()
        ->set_first_tx_hash(first_tx_hash.value());
  }
  if (first_tx_time) {
    auto first_time = new google::protobuf::Timestamp(
        google::protobuf::util::TimeUtil::MillisecondsToTimestamp(
            first_tx_time.value()));
    result.mutable_payload()
        ->mutable_get_account_asset_transactions()
        ->mutable_pagination_meta()
        ->set_allocated_first_tx_time(first_time);
  }
  if (last_tx_time) {
    auto last_time = new google::protobuf::Timestamp(
        google::protobuf::util::TimeUtil::MillisecondsToTimestamp(
            last_tx_time.value()));
    result.mutable_payload()
        ->mutable_get_account_asset_transactions()
        ->mutable_pagination_meta()
        ->set_allocated_last_tx_time(last_time);
  }
  if (first_tx_height) {
    result.mutable_payload()
        ->mutable_get_account_asset_transactions()
        ->mutable_pagination_meta()
        ->set_first_tx_height(first_tx_height.value());
  }
  if (last_tx_height) {
    result.mutable_payload()
        ->mutable_get_account_asset_transactions()
        ->mutable_pagination_meta()
        ->set_last_tx_height(last_tx_height.value());
  }
  return result;
}

iroha::protocol::Query generateGetAccountTransactionsQuery(
    const std::optional<std::string> &first_tx_hash = std::nullopt,
    const std::optional<int64_t> &first_tx_time = std::nullopt,
    const std::optional<int64_t> &last_tx_time = std::nullopt,
    const std::optional<uint64_t> &first_tx_height = std::nullopt,
    const std::optional<uint64_t> &last_tx_height = std::nullopt) {
  iroha::protocol::Query result;
  if (first_tx_hash) {
    result.mutable_payload()
        ->mutable_get_account_transactions()
        ->mutable_pagination_meta()
        ->set_first_tx_hash(first_tx_hash.value());
  }
  if (first_tx_time) {
    auto first_time = new google::protobuf::Timestamp(
        google::protobuf::util::TimeUtil::MillisecondsToTimestamp(
            first_tx_time.value()));
    result.mutable_payload()
        ->mutable_get_account_transactions()
        ->mutable_pagination_meta()
        ->set_allocated_first_tx_time(first_time);
  }
  if (last_tx_time) {
    auto last_time = new google::protobuf::Timestamp(
        google::protobuf::util::TimeUtil::MillisecondsToTimestamp(
            last_tx_time.value()));
    result.mutable_payload()
        ->mutable_get_account_transactions()
        ->mutable_pagination_meta()
        ->set_allocated_last_tx_time(last_time);
  }
  if (first_tx_height) {
    result.mutable_payload()
        ->mutable_get_account_transactions()
        ->mutable_pagination_meta()
        ->set_first_tx_height(first_tx_height.value());
  }
  if (last_tx_height) {
    result.mutable_payload()
        ->mutable_get_account_transactions()
        ->mutable_pagination_meta()
        ->set_last_tx_height(last_tx_height.value());
  }
  return result;
}

static std::string valid_tx_hash("123abc");
static std::string invalid_tx_hash("not_hex");
static int64_t valid_timestamp =
    google::protobuf::util::TimeUtil::kTimestampMinSeconds + 1234;
static uint64_t valid_height = 12;
static uint64_t invalid_height = 0;
static uint64_t height_2 = 2;
static uint64_t height_5 = 5;
static int64_t timestamp_123 =
    google::protobuf::util::TimeUtil::kTimestampMinSeconds + 123;
static int64_t timestamp_100 =
    google::protobuf::util::TimeUtil::kTimestampMinSeconds + 100;
// valid pagination query tests

class ValidProtoPaginationQueryValidatorTest
    : public ProtoQueryValidatorTest,
      public ::testing::WithParamInterface<iroha::protocol::Query> {};

TEST_P(ValidProtoPaginationQueryValidatorTest, ValidPaginationQuery) {
  ASSERT_EQ(validator.validate(GetParam()), std::nullopt)
      << GetParam().DebugString();
}

INSTANTIATE_TEST_SUITE_P(
    ProtoPaginationQueryTest,
    ValidProtoPaginationQueryValidatorTest,
    ::testing::Values(
        generateGetAccountAssetTransactionsQuery(valid_tx_hash),
        generateGetAccountTransactionsQuery(valid_tx_hash),
        generateGetAccountAssetTransactionsQuery(std::nullopt, valid_timestamp),
        generateGetAccountTransactionsQuery(std::nullopt, valid_timestamp),
        generateGetAccountAssetTransactionsQuery(std::nullopt,
                                                 std::nullopt,
                                                 valid_timestamp),
        generateGetAccountTransactionsQuery(std::nullopt,
                                            std::nullopt,
                                            valid_timestamp),
        generateGetAccountAssetTransactionsQuery(
            std::nullopt, std::nullopt, std::nullopt, valid_height),
        generateGetAccountTransactionsQuery(
            std::nullopt, std::nullopt, std::nullopt, valid_height),
        generateGetAccountAssetTransactionsQuery(std::nullopt,
                                                 std::nullopt,
                                                 std::nullopt,
                                                 std::nullopt,
                                                 valid_height),
        generateGetAccountTransactionsQuery(std::nullopt,
                                            std::nullopt,
                                            std::nullopt,
                                            std::nullopt,
                                            valid_height),
        generateGetAccountTransactionsQuery(
            std::nullopt, std::nullopt, std::nullopt, height_2, height_5),
        generateGetAccountTransactionsQuery(std::nullopt,
                                            timestamp_100,
                                            timestamp_123)));

// invalid pagination query tests

class InvalidProtoPaginationQueryTest
    : public ProtoQueryValidatorTest,
      public ::testing::WithParamInterface<iroha::protocol::Query> {};

TEST_P(InvalidProtoPaginationQueryTest, InvalidPaginationQuery) {
  ASSERT_TRUE(validator.validate(GetParam())) << GetParam().DebugString();
}

INSTANTIATE_TEST_SUITE_P(
    InvalidProtoPaginationQueryTest,
    InvalidProtoPaginationQueryTest,
    ::testing::Values(
        generateGetAccountAssetTransactionsQuery(invalid_tx_hash),
        generateGetAccountTransactionsQuery(invalid_tx_hash),
        generateGetAccountAssetTransactionsQuery(
            std::nullopt, std::nullopt, std::nullopt, invalid_height),
        generateGetAccountTransactionsQuery(
            std::nullopt, std::nullopt, std::nullopt, invalid_height),
        generateGetAccountAssetTransactionsQuery(std::nullopt,
                                                 std::nullopt,
                                                 std::nullopt,
                                                 std::nullopt,
                                                 invalid_height),
        generateGetAccountTransactionsQuery(std::nullopt,
                                            std::nullopt,
                                            std::nullopt,
                                            std::nullopt,
                                            invalid_height),
        generateGetAccountTransactionsQuery(
            std::nullopt, timestamp_123, timestamp_100),
        generateGetAccountTransactionsQuery(
            std::nullopt, std::nullopt, std::nullopt, height_5, height_2)));
