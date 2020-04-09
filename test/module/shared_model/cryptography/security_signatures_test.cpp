/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <string>

#include "framework/crypto_literals.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/interface_mocks.hpp"

/**
 * @given Two signatures with same pub key but different signed
 * @when  Invoke operator==
 * @then  Expect true
 */
TEST(SecuritySignature, SignatureOperatorEqual) {
  auto first_signature = std::make_unique<MockSignature>();
  auto second_signature = std::make_unique<MockSignature>();

  EXPECT_CALL(*first_signature, publicKey())
      .WillRepeatedly(testing::ReturnRefOfCopy(std::string{"one"}));
  EXPECT_CALL(*second_signature, publicKey())
      .WillRepeatedly(testing::ReturnRefOfCopy(std::string{"one"}));
  EXPECT_CALL(*first_signature, signedData())
      .WillRepeatedly(testing::ReturnRefOfCopy(std::string{"signed_one"}));
  EXPECT_CALL(*second_signature, signedData())
      .WillRepeatedly(testing::ReturnRefOfCopy(std::string{"signed_two"}));

  ASSERT_TRUE(*first_signature == *second_signature);
}

/**
 * @given Transaction with given signature
 * @when  Invoke ::addSignature with same public key but different signed
 * @then  Expect that second signature wasn't added
 */
TEST(SecuritySignature, TransactionAddsignature) {
  auto tx = TestTransactionBuilder().build();
  auto public_key{"same_pubkey"_hex_pubkey};
  ASSERT_TRUE(tx.addSignature("signature 1"_hex_sig, public_key));
  ASSERT_FALSE(tx.addSignature("signature 2"_hex_sig, public_key));
}

/**
 * @given Block with given signature
 * @when  Invoke ::addSignature with same public key but different signed
 * @then  Expect that second signature wasn't added
 */
TEST(SecuritySignature, BlockAddSignature) {
  auto block = TestBlockBuilder().build();
  auto public_key{"same_pubkey"_hex_pubkey};
  ASSERT_TRUE(block.addSignature("signature 1"_hex_sig, public_key));
  ASSERT_FALSE(block.addSignature("signature 2"_hex_sig, public_key));
}
