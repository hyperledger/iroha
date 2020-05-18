/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/validators/validators_fixture.hpp"

#include <gtest/gtest.h>

#include <optional>
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "validators/default_validator.hpp"
#include "validators/validation_error_output.hpp"

using namespace shared_model::crypto;
using namespace shared_model::validation;

class BlockValidatorTest : public ValidatorsTest {
 public:
  BlockValidatorTest() : validator_(iroha::test::kTestsValidatorsConfig) {}

  /**
   * Create a simple transaction
   * @param valid - transaction will be valid, if this flag is set to true,
   * invalid otherwise
   * @return created transaction
   */
  auto generateTx(bool valid) {
    std::string creator;
    if (valid) {
      creator = "account@domain";
    } else {
      creator = "account_sobaka_domain";
    }
    return TestUnsignedTransactionBuilder()
        .creatorAccountId(creator)
        .setAccountQuorum("account@domain", 1)
        .createdTime(iroha::time::now())
        .quorum(1)
        .build()
        .signAndAddSignature(kDefaultKey)
        .finish();
  }

  /**
   * Create a block
   * @param txs to be placed inside
   * @return created block
   */
  auto generateBlock(
      const std::vector<shared_model::proto::Transaction> &txs,
      const std::vector<shared_model::crypto::Hash> &rejected_hashes) {
    return shared_model::proto::TemplateBlockBuilder<
               (1 << shared_model::proto::TemplateBlockBuilder<>::total) - 1,
               shared_model::validation::AlwaysValidValidator,
               shared_model::proto::UnsignedWrapper<
                   shared_model::proto::Block>>()
        .height(1)
        .prevHash(kPrevHash)
        .createdTime(iroha::time::now())
        .rejectedTransactions(rejected_hashes)
        .transactions(txs)
        .build()
        .signAndAddSignature(kDefaultKey)
        .finish();
  }

  DefaultUnsignedBlockValidator validator_;
  const Hash kPrevHash =
      Hash(std::string(DefaultCryptoAlgorithmType::kHashLength, '0'));
  const Keypair kDefaultKey = DefaultCryptoAlgorithmType::generateKeypair();
};

/**
 * @given block validator @and valid non-empty block
 * @when block is validated
 * @then result is OK
 */
TEST_F(BlockValidatorTest, ValidBlock) {
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(generateTx(true));
  auto valid_block =
      generateBlock(txs, std::vector<shared_model::crypto::Hash>{});

  ASSERT_EQ(validator_.validate(valid_block), std::nullopt);
}

/**
 * @given block validator @and empty block
 * @when block is validated
 * @then result is OK
 */
TEST_F(BlockValidatorTest, EmptyBlock) {
  auto empty_block =
      generateBlock(std::vector<shared_model::proto::Transaction>{},
                    std::vector<shared_model::crypto::Hash>{});

  ASSERT_EQ(validator_.validate(empty_block), std::nullopt);
}

/**
 * @given block validator @and invalid block
 * @when block is validated
 * @then error appears after validation
 */
TEST_F(BlockValidatorTest, InvalidBlock) {
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(generateTx(false));
  auto invalid_block =
      generateBlock(txs, std::vector<shared_model::crypto::Hash>{});

  ASSERT_TRUE(validator_.validate(invalid_block));
}

/**
 * @given block validator @and invalid block with two duplicate rejected hashes
 * @when block is validated
 * @then error appears after validation
 */
TEST_F(BlockValidatorTest, DuplicateRejectedHash) {
  std::vector<shared_model::proto::Transaction> txs;
  std::vector<shared_model::crypto::Hash> rejected_hashes;
  shared_model::proto::Transaction tx = generateTx(true);
  rejected_hashes.push_back(tx.hash());
  rejected_hashes.push_back(tx.hash());
  auto invalid_block = generateBlock(txs, rejected_hashes);

  auto error = validator_.validate(invalid_block);
  ASSERT_TRUE(error);
  EXPECT_THAT(error->toString(),
              testing::HasSubstr("Rejected transaction hash"));
  EXPECT_THAT(error->toString(), testing::HasSubstr("Duplicates hash"));
}

/**
 * @given block validator @and invalid block with committed transaction which
 * hash in rejected hashes
 * @when block is validated
 * @then error appears after validation
 */
TEST_F(BlockValidatorTest, CommitedHashInRejectedHash) {
  std::vector<shared_model::proto::Transaction> txs;
  std::vector<shared_model::crypto::Hash> rejected_hashes;
  shared_model::proto::Transaction tx = generateTx(true);
  txs.push_back(tx);
  rejected_hashes.push_back(tx.hash());
  auto invalid_block = generateBlock(txs, rejected_hashes);

  auto error = validator_.validate(invalid_block);
  ASSERT_TRUE(error);
  ASSERT_THAT(error->toString(),
              testing::HasSubstr("has already appeared in rejected hashes"));
}

/**
 * @given block validator @and invalid block with duplicate
 * transactions
 * @when block is validated
 * @then error appears after validation
 */
TEST_F(BlockValidatorTest, DuplicateTransactionsInBlock) {
  std::vector<shared_model::proto::Transaction> txs;
  shared_model::proto::Transaction tx = generateTx(true);
  txs.push_back(tx);
  txs.push_back(tx);
  auto invalid_block =
      generateBlock(txs, std::vector<shared_model::crypto::Hash>{});

  auto error = validator_.validate(invalid_block);
  ASSERT_TRUE(error);
  ASSERT_THAT(error->toString(), testing::HasSubstr("Duplicates transaction"));
}
