/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <optional>
#include "cryptography/default_hash_provider.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_proposal_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "validators/default_validator.hpp"
#include "validators/validation_error_output.hpp"

using ::testing::HasSubstr;

struct ContainerValidatorTest : public ::testing::Test {
  void SetUp() override {
    current_timestamp = iroha::time::now();
  }

  auto makeTransaction(
      shared_model::interface::types::TimestampType timestamp) {
    return TestUnsignedTransactionBuilder()
        .creatorAccountId("user@domain")
        .createdTime(timestamp)
        .createDomain("domain", "role")
        .quorum(1)
        .build()
        .signAndAddSignature(keypair)
        .finish();
  }

  auto makeProposal(shared_model::interface::types::TimestampType timestamp,
                    shared_model::proto::Transaction transaction) {
    std::vector<shared_model::proto::Transaction> txs;
    txs.push_back(std::move(transaction));
    return TestProposalBuilder()
        .height(1)
        .createdTime(timestamp)
        .transactions(txs)
        .build();
  }

  auto makeBlock(shared_model::interface::types::TimestampType timestamp,
                 shared_model::proto::Transaction transaction) {
    std::vector<shared_model::proto::Transaction> txs;
    txs.push_back(std::move(transaction));
    return TestUnsignedBlockBuilder()
        .transactions(txs)
        .height(1)
        .prevHash(shared_model::crypto::DefaultHashProvider::makeHash(
            shared_model::crypto::Blob("")))
        .createdTime(timestamp)
        .build()
        .signAndAddSignature(keypair)
        .finish();
  }

  shared_model::crypto::Keypair keypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  shared_model::interface::types::TimestampType old_timestamp =
      iroha::time::now(std::chrono::hours(-100));
  shared_model::interface::types::TimestampType current_timestamp;
};

/**
 * @given an old proposal with an old transaction
 * @when proposal validator is applied to the given proposal
 * @then no errors are returned
 */
TEST_F(ContainerValidatorTest, OldProposal) {
  shared_model::validation::DefaultProposalValidator validator(
      iroha::test::kTestsValidatorsConfig);
  auto proposal = makeProposal(old_timestamp, makeTransaction(old_timestamp));

  ASSERT_EQ(validator.validate(proposal), std::nullopt);
}

/**
 * @given an old block with an old transaction
 * @when block validator is applied to the given block
 * @then no errors are returned
 */
TEST_F(ContainerValidatorTest, OldBlock) {
  shared_model::validation::DefaultSignedBlockValidator validator(
      iroha::test::kTestsValidatorsConfig);
  auto block = makeBlock(old_timestamp, makeTransaction(old_timestamp));

  ASSERT_EQ(validator.validate(block), std::nullopt);
}

/**
 * @given an old proposal with a new transaction
 * @when proposal validator is applied to the given proposal
 * @then an error with "sent from future" is returned
 */
TEST_F(ContainerValidatorTest, OldProposalNewTransaction) {
  shared_model::validation::DefaultProposalValidator validator(
      iroha::test::kTestsValidatorsConfig);
  auto proposal =
      makeProposal(old_timestamp, makeTransaction(current_timestamp));

  auto error = validator.validate(proposal);

  ASSERT_TRUE(error);
  ASSERT_THAT(error->toString(), HasSubstr("sent from future"));
}

/**
 * @given an old block with a new transaction
 * @when block validator is applied to the given block
 * @then an error with "sent from future" is returned
 */
TEST_F(ContainerValidatorTest, OldBlockNewTransaction) {
  shared_model::validation::DefaultSignedBlockValidator validator(
      iroha::test::kTestsValidatorsConfig);
  auto block = makeBlock(old_timestamp, makeTransaction(current_timestamp));

  auto error = validator.validate(block);

  ASSERT_TRUE(error);
  ASSERT_THAT(error->toString(), HasSubstr("sent from future"));
}
