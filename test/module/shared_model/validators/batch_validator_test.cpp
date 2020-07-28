/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/transaction_batch_validator.hpp"

#include <gtest/gtest.h>
#include <optional>
#include "framework/batch_helper.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "validators/default_validator.hpp"
#include "validators/validation_error_output.hpp"

struct BatchValidatorFixture : public ::testing::Test {
  auto getValidator(bool allow_partial_ordered_batches) {
    auto config = std::make_shared<shared_model::validation::ValidatorsConfig>(
        iroha::test::getTestsMaxBatchSize(), allow_partial_ordered_batches);
    auto validator =
        std::make_shared<shared_model::validation::DefaultBatchValidator>(
            config);
    return validator;
  }
};

/**
 * @given a batch validator with allowed partial ordered batches
 * @when an ordered batch with some transactions missing arrives
 * @then the batch passes validation
 */
TEST_F(BatchValidatorFixture, PartialOrderedWhenPartialsAllowed) {
  auto validator = getValidator(true);
  auto txs = framework::batch::createBatchOneSignTransactions(
      shared_model::interface::types::BatchType::ORDERED,
      {"alice@iroha", "bob@iroha", "donna@iroha"});
  txs.pop_back();
  auto batch =
      std::make_unique<shared_model::interface::TransactionBatchImpl>(txs);
  ASSERT_EQ(validator->validate(*batch), std::nullopt);
}

/**
 * @given a batch validator with disallowed partial ordered batches
 * @when an atomic batch with some transactions missing arrives
 * @then the batch fails validation
 */
TEST_F(BatchValidatorFixture, AtomicBatchWithMissingTransactions) {
  auto validator = getValidator(false);
  auto txs = framework::batch::createBatchOneSignTransactions(
      shared_model::interface::types::BatchType::ATOMIC,
      {"alice@iroha", "bob@iroha", "donna@iroha"});
  txs.pop_back();
  auto batch =
      std::make_unique<shared_model::interface::TransactionBatchImpl>(txs);
  auto error = validator->validate(*batch);
  ASSERT_TRUE(error);
  EXPECT_THAT(
      error->toString(),
      ::testing::HasSubstr(
          "Sizes of batch_meta and provided transactions are different"));
}

/**
 * @given a batch validator with disallowed partial ordered batches
 * @when an ordered batch with complete set of transactions arrives
 * @then the batch passes validation
 */
TEST_F(BatchValidatorFixture, ComleteOrderedWhenPartialsDisallowed) {
  auto validator = getValidator(false);
  auto txs = framework::batch::createBatchOneSignTransactions(
      shared_model::interface::types::BatchType::ORDERED,
      {"alice@iroha", "bob@iroha", "donna@iroha"});
  auto batch =
      std::make_unique<shared_model::interface::TransactionBatchImpl>(txs);
  ASSERT_EQ(validator->validate(*batch), std::nullopt);
}

/**
 * @given a batch validator with allowed partial ordered batches
 * @when an ordered batch with some transactions missing and the rest of
 * transactions are reordered arrives
 * @then the batch fails validation
 */
TEST_F(BatchValidatorFixture,
       PartialOrderedWithMessedHashesWhenPartialsAllowed) {
  auto validator = getValidator(true);
  auto txs = framework::batch::createBatchOneSignTransactions(
      shared_model::interface::types::BatchType::ORDERED,
      {"alice@iroha", "bob@iroha", "donna@iroha"});
  txs.pop_back();
  ASSERT_EQ(txs.size(), 2);
  std::swap(txs[0], txs[1]);
  auto batch =
      std::make_unique<shared_model::interface::TransactionBatchImpl>(txs);
  auto error = validator->validate(*batch);
  ASSERT_TRUE(error);
  ASSERT_THAT(error->toString(),
              ::testing::HasSubstr(
                  "The corresponding hash in batch meta is out of order."));
}

/**
 * @given a batch validator with allowed partial ordered batches
 * @when an ordered batch with duplicate transactions arrives
 * @then the batch fails validation
 */
TEST_F(BatchValidatorFixture, DuplicateTransactions) {
  auto validator = getValidator(false);
  auto txs = framework::batch::createBatchOneSignTransactions(
      shared_model::interface::types::BatchType::ORDERED,
      {"alice@iroha", "bob@iroha", "alice@iroha"});
  auto batch =
      std::make_unique<shared_model::interface::TransactionBatchImpl>(txs);
  auto error = validator->validate(*batch);
  ASSERT_TRUE(error);
  ASSERT_THAT(error->toString(), ::testing::HasSubstr("Duplicates hash #1"));
}
