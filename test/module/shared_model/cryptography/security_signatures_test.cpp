/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "framework/crypto_dummies.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/interface_mocks.hpp"

shared_model::crypto::PublicKey public_key_1(
    iroha::createPublicKey("public key 1"));
shared_model::crypto::Signed signed_1(iroha::createSigned("signed 1"));
shared_model::crypto::Signed signed_2(iroha::createSigned("signed 2"));

/**
 * @given Two signatures with same pub key but different signed
 * @when  Invoke operator==
 * @then  Expect true
 */
TEST(SecuritySignature, SignatureOperatorEqual) {
  auto first_signature = std::make_unique<MockSignature>();
  auto second_signature = std::make_unique<MockSignature>();

  EXPECT_CALL(*first_signature, publicKey())
      .WillRepeatedly(testing::ReturnRef(public_key_1));
  EXPECT_CALL(*second_signature, publicKey())
      .WillRepeatedly(testing::ReturnRefOfCopy(public_key_1));
  EXPECT_CALL(*first_signature, signedData())
      .WillRepeatedly(testing::ReturnRef(signed_1));
  EXPECT_CALL(*second_signature, signedData())
      .WillRepeatedly(testing::ReturnRef(signed_2));

  ASSERT_TRUE(*first_signature == *second_signature);
}

/**
 * @given Transaction with given signature
 * @when  Invoke ::addSignature with same public key but different signed
 * @then  Expect that second signature wasn't added
 */
TEST(SecuritySignature, TransactionAddsignature) {
  auto tx = TestTransactionBuilder().build();
  ASSERT_TRUE(tx.addSignature(signed_1, public_key_1));
  ASSERT_FALSE(tx.addSignature(signed_2, public_key_1));
}

/**
 * @given Block with given signature
 * @when  Invoke ::addSignature with same public key but different signed
 * @then  Expect that second signature wasn't added
 */
TEST(SecuritySignature, BlockAddSignature) {
  auto block = TestBlockBuilder().prevHash(iroha::createHash()).build();
  ASSERT_TRUE(block.addSignature(signed_1, public_key_1));
  ASSERT_FALSE(block.addSignature(signed_2, public_key_1));
}
