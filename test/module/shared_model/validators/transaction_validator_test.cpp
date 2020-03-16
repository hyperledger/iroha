/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/validators/validators_fixture.hpp"

#include <type_traits>

#include <gtest/gtest.h>
#include <boost/range/irange.hpp>
#include <optional>
#include "builders/protobuf/transaction.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "validators/validation_error_output.hpp"

using namespace shared_model;

class TransactionValidatorTest : public ValidatorsTest {
 public:
  TransactionValidatorTest()
      : transaction_validator(iroha::test::kTestsValidatorsConfig) {}

  auto getCountIgnoredFields() {
    return ignored_fields_.size();
  }

 protected:
  iroha::protocol::Transaction generateEmptyTransaction() {
    std::string creator_account_id = "admin@test";

    TestTransactionBuilder builder;
    auto tx = builder.creatorAccountId(creator_account_id)
                  .createdTime(created_time)
                  .quorum(1)
                  .build()
                  .getTransport();
    return tx;
  }
  shared_model::validation::DefaultUnsignedTransactionValidator
      transaction_validator;
};

/**
 * @given transaction without any commands
 * @when commands validator is invoked
 * @then answer has error about empty transaction
 */
TEST_F(TransactionValidatorTest, EmptyTransactionTest) {
  auto tx = generateEmptyTransaction();
  tx.mutable_payload()->mutable_reduced_payload()->set_created_time(
      created_time);
  auto result = proto::Transaction(iroha::protocol::Transaction(tx));
  auto error = transaction_validator.validate(result);
  ASSERT_TRUE(error);
  ASSERT_THAT(
      error->my_errors,
      ::testing::ElementsAre("Transaction must contain at least one command."));
}

/**
 * @given transaction made of commands with valid fields
 * @when commands validation is invoked
 * @then answer has no errors
 */
TEST_F(TransactionValidatorTest, StatelessValidTest) {
  iroha::protocol::Transaction tx = generateEmptyTransaction();
  tx.mutable_payload()->mutable_reduced_payload()->set_creator_account_id(
      account_id);
  tx.mutable_payload()->mutable_reduced_payload()->set_created_time(
      created_time);
  auto payload = tx.mutable_payload();

  // Iterate through all command types, filling command fields with valid values
  iterateContainer(
      [] { return iroha::protocol::Command::descriptor(); },
      [&](auto field) {
        // Add new command to transaction
        auto command = payload->mutable_reduced_payload()->add_commands();
        // Set concrete type for new command
        return command->GetReflection()->MutableMessage(command, field);
      },
      [this](auto field, auto command) {
        // Will throw key exception in case new field is added
        try {
          field_setters.at(field->full_name())(
              command->GetReflection(), command, field);
        } catch (const std::out_of_range &e) {
          FAIL() << "Missing field setter: " << field->full_name();
        }
      },
      [] {});

  auto result = proto::Transaction(iroha::protocol::Transaction(tx));
  ASSERT_EQ(transaction_validator.validate(result), std::nullopt);
}

/**
 * @given Protobuf transaction object with unset command
 * @when validate is called
 * @then there is a error returned
 */
TEST_F(TransactionValidatorTest, UnsetCommand) {
  iroha::protocol::Transaction tx = generateEmptyTransaction();
  tx.mutable_payload()->mutable_reduced_payload()->set_creator_account_id(
      account_id);
  tx.mutable_payload()->mutable_reduced_payload()->set_created_time(
      created_time);
  auto error = transaction_validator.validate(proto::Transaction(tx));
  tx.mutable_payload()->mutable_reduced_payload()->add_commands();
  ASSERT_TRUE(error);
}

/**
 * @given transaction made of commands with invalid fields
 * @when commands validation is invoked
 * @then answer has errors and number of errors in answer is the same as the
 * number of commands in tx
 */
TEST_F(TransactionValidatorTest, StatelessInvalidTest) {
  iroha::protocol::Transaction tx = generateEmptyTransaction();
  auto payload = tx.mutable_payload();

  iroha::ts64_t invalid_time = 10000000000ull;
  payload->mutable_reduced_payload()->set_created_time(invalid_time);

  // create commands from default constructors, which will have empty, therefore
  // invalid values
  iterateContainer(
      [] { return iroha::protocol::Command::descriptor(); },
      [&](auto field) {
        // Add new command to transaction
        auto command = payload->mutable_reduced_payload()->add_commands();
        // Set concrete type for new command
        return command->GetReflection()->MutableMessage(command, field);
      },
      [](auto, auto) {
        // Note that no fields are set
      },
      [] {});

  auto result = proto::Transaction(iroha::protocol::Transaction(tx));
  auto error = transaction_validator.validate(result);
  ASSERT_TRUE(error);

  // in total there should be number_of_commands + 1 reasons of bad answer:
  // number_of_commands for each command + 1 for transaction metadata
  EXPECT_EQ(error->child_errors.size() + getCountIgnoredFields(),
            iroha::protocol::Command::descriptor()->field_count() + 1);
}
/**
 * @given transaction made of commands with valid fields
 * @when commands validation is invoked
 * @then answer has no errors
 */
TEST_F(TransactionValidatorTest, BatchValidTest) {
  std::string creator_account_id = "admin@test";

  TestTransactionBuilder builder;
  auto tx = builder.creatorAccountId(creator_account_id)
                .createdTime(created_time)
                .quorum(1)
                .batchMeta(interface::types::BatchType::ATOMIC,
                           std::vector<interface::types::HashType>())
                .createDomain("test", "test")
                .build()
                .getTransport();
  shared_model::validation::DefaultUnsignedTransactionValidator
      transaction_validator(iroha::test::kTestsValidatorsConfig);
  auto result = proto::Transaction(iroha::protocol::Transaction(tx));

  ASSERT_EQ(transaction_validator.validate(result), std::nullopt);
  ASSERT_EQ(tx.payload().batch().type(),
            static_cast<int>(interface::types::BatchType::ATOMIC));
}
