/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/validators/validators_fixture.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/optional/optional_io.hpp>
#include "builders/protobuf/queries.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "validators/validation_error_output.hpp"

using shared_model::validation::ValidationError;

class QueryValidatorTest : public ValidatorsTest {
 public:
  QueryValidatorTest() : query_validator(iroha::test::kTestsValidatorsConfig) {}

  void validate(iroha::protocol::Query proto,
                ::testing::Matcher<boost::optional<ValidationError>> matcher) {
    auto result = shared_model::proto::Query::create(std::move(proto));
    IROHA_ASSERT_RESULT_VALUE(result) << "Could not build query.";
    auto model = std::move(result).assumeValue();
    auto opt_error = query_validator.validate(*model);
    EXPECT_THAT(opt_error, matcher);
  }

  shared_model::validation::DefaultUnsignedQueryValidator query_validator;
};

using namespace shared_model;

/**
 * @given Protobuf query object
 * @when Each query type created with valid fields
 * @then there are no validation errors
 */
TEST_F(QueryValidatorTest, StatelessValidTest) {
  iroha::protocol::Query qry;
  auto *meta = new iroha::protocol::QueryPayloadMeta();
  meta->set_created_time(created_time);
  meta->set_creator_account_id(account_id);
  meta->set_query_counter(counter);
  qry.mutable_payload()->set_allocated_meta(meta);
  auto payload = qry.mutable_payload();

  // Iterate through all query types, filling query fields with valid values
  iterateContainer(
      [] {
        return iroha::protocol::Query::Payload::descriptor()->FindOneofByName(
            "query");
      },
      [&](auto field) {
        // Set concrete type for new query
        return payload->GetReflection()->MutableMessage(payload, field);
      },
      [this](auto field, auto query) {
        // Will throw key exception in case new field is added
        try {
          field_setters.at(field->full_name())(
              query->GetReflection(), query, field);
        } catch (const std::out_of_range &e) {
          FAIL() << "Missing field setter: " << field->full_name();
        }
      },
      [&] { validate(qry, ::testing::Eq(boost::none)); });
}

/**
 * @given Protobuf query object
 * @when Query has no fields set, and each query type has no fields set
 * @then there is a validation error
 */
TEST_F(QueryValidatorTest, StatelessInvalidTest) {
  iroha::protocol::Query qry;
  auto payload = qry.mutable_payload();
  payload->set_allocated_meta(new iroha::protocol::QueryPayloadMeta());

  auto refl = iroha::protocol::Query::Payload::GetReflection();
  auto desc = iroha::protocol::Query::Payload::GetDescriptor();

  boost::for_each(boost::irange(0, desc->field_count()), [&](auto i) {
    if (i == iroha::protocol::Query::Payload::QUERY_NOT_SET) {
      return;
    }
    auto field = desc->field(i);
    auto *msg = refl->GetMessage(*payload, field).New();
    refl->SetAllocatedMessage(payload, msg, field);
    validate(qry, ::testing::Ne(boost::none));
  });
}
