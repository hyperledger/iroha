/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/validators/validators_fixture.hpp"

#include <optional>
#include "builders/protobuf/queries.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "validators/validation_error_output.hpp"

class QueryValidatorTest : public ValidatorsTest {
 public:
  QueryValidatorTest() : query_validator(iroha::test::kTestsValidatorsConfig) {}

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
      [&] {
        auto result = proto::Query(iroha::protocol::Query(qry));
        auto error = query_validator.validate(result);

        ASSERT_EQ(error, std::nullopt);
      });
}

/**
 * @given Protobuf query object
 * @when Query has no fields set, and each query type has no fields set
 * @then there is a validation error
 */
TEST_F(QueryValidatorTest, StatelessInvalidTest) {
  iroha::protocol::Query qry;
  auto payload = qry.mutable_payload();

  // create queries from default constructors, which will have empty, therefore
  // invalid values
  iterateContainer(
      [] {
        return iroha::protocol::Query::Payload::descriptor()->FindOneofByName(
            "query");
      },
      [&](auto field) {
        // Set concrete type for new query
        return payload->GetReflection()->MutableMessage(payload, field);
      },
      [](auto, auto) {
        // Note that no fields are set
      },
      [&] {
        auto result = proto::Query(iroha::protocol::Query(qry));
        auto error = query_validator.validate(result);

        ASSERT_TRUE(error);
      });
}
