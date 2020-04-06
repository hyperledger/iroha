/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/interface_mocks.hpp"

/**
 * @given Two signatures with same pub key but different signed
 * @when  Invoke operator==
 * @then  Expect true
 */
TEST(SecuritySignature, SignatureOperatorEqual) {
  shared_model::crypto::PublicKey pk1("one"), pk2("one");
  shared_model::crypto::Signed data1("signed_one"), data2("signed_two");
  auto first_signature = std::make_unique<MockSignature>();
  auto second_signature = std::make_unique<MockSignature>();

  EXPECT_CALL(*first_signature, publicKey())
      .WillRepeatedly(testing::ReturnRef(pk1.hex()));
  EXPECT_CALL(*second_signature, publicKey())
      .WillRepeatedly(testing::ReturnRef(pk2.hex()));
  EXPECT_CALL(*first_signature, signedData())
      .WillRepeatedly(testing::ReturnRef(data1.hex()));
  EXPECT_CALL(*second_signature, signedData())
      .WillRepeatedly(testing::ReturnRef(data2.hex()));

  ASSERT_TRUE(*first_signature == *second_signature);
}

/**
 * @given Transaction with given signature
 * @when  Invoke ::addSignature with same public key but different signed
 * @then  Expect that second signature wasn't added
 */
TEST(SecuritySignature, TransactionAddsignature) {
  using namespace std::literals;
  auto tx = TestTransactionBuilder().build();
  shared_model::interface::types::PublicKeyHexStringView public_key{"0B"sv};
  ASSERT_TRUE(tx.addSignature(
      shared_model::interface::types::SignedHexStringView{"0A"sv}, public_key));
  ASSERT_FALSE(tx.addSignature(
      shared_model::interface::types::SignedHexStringView{"0C"sv}, public_key));
}

/**
 * @given Block with given signature
 * @when  Invoke ::addSignature with same public key but different signed
 * @then  Expect that second signature wasn't added
 */
TEST(SecuritySignature, BlockAddSignature) {
  using namespace std::literals;
  auto block = TestBlockBuilder().build();
  shared_model::interface::types::PublicKeyHexStringView public_key{"0B"sv};
  ASSERT_TRUE(block.addSignature(
      shared_model::interface::types::SignedHexStringView{"0A"sv}, public_key));
  ASSERT_FALSE(block.addSignature(
      shared_model::interface::types::SignedHexStringView{"0C"sv}, public_key));
}
