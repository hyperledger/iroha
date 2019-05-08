/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/transaction_batch_validator.hpp"

#include <gtest/gtest.h>
#include "framework/batch_helper.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "module/irohad/common/validators_config.hpp"

struct BatchValidatorFixture : public ::testing::Test {
  auto getValidator(bool allow_partial_ordered_batches) {
    auto config = std::make_shared<shared_model::validation::ValidatorsConfig>(
        iroha::test::getTestsMaxBatchSize(), allow_partial_ordered_batches);
    auto validator =
        std::make_shared<shared_model::validation::BatchValidator>(config);
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
  auto result = validator->validate(*batch);
  ASSERT_FALSE(result.hasErrors());
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
  auto result = validator->validate(*batch);
  ASSERT_TRUE(result.hasErrors());
  ASSERT_THAT(
      result.reason(),
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
  auto result = validator->validate(*batch);
  ASSERT_FALSE(result.hasErrors());
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
  auto result = validator->validate(*batch);
  ASSERT_TRUE(result.hasErrors());
  ASSERT_THAT(result.reason(),
              ::testing::HasSubstr("Hashes of provided transactions and ones "
                                   "in batch_meta are different"));
}
