/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "module/shared_model/validators/validators_fixture.hpp"

#include <gtest/gtest.h>

#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "validators/default_validator.hpp"

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
  auto generateBlock(const std::vector<shared_model::proto::Transaction> &txs) {
    return shared_model::proto::TemplateBlockBuilder<
               (1 << shared_model::proto::TemplateBlockBuilder<>::total) - 1,
               shared_model::validation::AlwaysValidValidator,
               shared_model::proto::UnsignedWrapper<
                   shared_model::proto::Block>>()
        .height(1)
        .prevHash(kPrevHash)
        .createdTime(iroha::time::now())
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
  auto valid_block = generateBlock(txs);

  auto validation_result = validator_.validate(valid_block);
  ASSERT_FALSE(validation_result.hasErrors());
}

/**
 * @given block validator @and empty block
 * @when block is validated
 * @then result is OK
 */
TEST_F(BlockValidatorTest, EmptyBlock) {
  auto empty_block =
      generateBlock(std::vector<shared_model::proto::Transaction>{});

  auto validation_result = validator_.validate(empty_block);
  ASSERT_FALSE(validation_result.hasErrors());
}

/**
 * @given block validator @and invalid block
 * @when block is validated
 * @then error appears after validation
 */
TEST_F(BlockValidatorTest, InvalidBlock) {
  std::vector<shared_model::proto::Transaction> txs;
  txs.push_back(generateTx(false));
  auto invalid_block = generateBlock(txs);

  auto validation_result = validator_.validate(invalid_block);
  ASSERT_TRUE(validation_result.hasErrors());
}
