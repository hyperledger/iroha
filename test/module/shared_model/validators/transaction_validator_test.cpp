/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/validators/validators_fixture.hpp"

#include <type_traits>

#include <gtest/gtest.h>
#include <boost/optional/optional_io.hpp>
#include <boost/range/irange.hpp>
#include "builders/protobuf/transaction.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/backend_proto/common.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "validators/validation_error_output.hpp"

using namespace shared_model;

using shared_model::validation::ValidationError;

class TransactionValidatorTest : public ValidatorsTest {
 public:
  TransactionValidatorTest()
      : transaction_validator(iroha::test::kTestsValidatorsConfig) {}

  auto getCountIgnoredFields() {
    return ignored_fields_.size();
  }

  void validate(iroha::protocol::Transaction proto,
                ::testing::Matcher<boost::optional<ValidationError>> matcher) {
    auto result = shared_model::proto::Transaction::create(std::move(proto));
    IROHA_ASSERT_RESULT_VALUE(result) << "Could not build transaction.";
    auto model = std::move(result).assumeValue();
    auto opt_error = transaction_validator.validate(*model);
    EXPECT_THAT(opt_error, matcher);
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
  using namespace testing;
  validate(std::move(tx),
           Optional(Field(
               &ValidationError::my_errors,
               ElementsAre("Transaction must contain at least one command."))));
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

  validate(std::move(tx), ::testing::Eq(boost::none));
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
  validate(std::move(tx), ::testing::Ne(boost::none));
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

  auto refl = iroha::protocol::Command::GetReflection();
  auto desc = iroha::protocol::Command::GetDescriptor();

  boost::for_each(boost::irange(0, desc->field_count()), [&](auto i) {
    if (i == iroha::protocol::Command::COMMAND_NOT_SET) {
      return;
    }
    auto new_command = payload->mutable_reduced_payload()->add_commands();
    auto field = desc->field(i);
    auto *msg = refl->GetMessage(*new_command, field).New();
    iroha::setDummyFieldValues(msg);
    refl->SetAllocatedMessage(new_command, msg, field);
  });

  const size_t expected_number_of_child_errors =
      // an error for:
      iroha::protocol::Command::descriptor()->field_count()  // each command
      - getCountIgnoredFields()  // that is not ignored
      + 1;                       // and for transaction metadata

  using namespace testing;
  validate(std::move(tx),
           Optional(Field(&ValidationError::child_errors,
                          SizeIs(expected_number_of_child_errors))));
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
  validate(std::move(tx), ::testing::Eq(boost::none));
  ASSERT_EQ(tx.payload().batch().type(),
            static_cast<int>(interface::types::BatchType::ATOMIC));
}
