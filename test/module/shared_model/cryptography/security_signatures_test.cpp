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

  EXPECT_CALL(*first_signature, publicKey()).WillRepeatedly(testing::ReturnRef(pk1));
  EXPECT_CALL(*second_signature, publicKey()).WillRepeatedly(testing::ReturnRef(pk2));
  EXPECT_CALL(*first_signature, signedData()).WillRepeatedly(testing::ReturnRef(data1));
  EXPECT_CALL(*second_signature, signedData()).WillRepeatedly(testing::ReturnRef(data2));

  ASSERT_TRUE(*first_signature == *second_signature);
}

/**
 * @given Transaction with given signature
 * @when  Invoke ::addSignature with same public key but different signed
 * @then  Expect that second signature wasn't added
 */
TEST(SecuritySignature, TransactionAddsignature) {
  auto tx = TestTransactionBuilder().build();
  ASSERT_TRUE(tx.addSignature(shared_model::crypto::Signed("sign_one"),
                              shared_model::crypto::PublicKey("key_one")));
  ASSERT_FALSE(tx.addSignature(shared_model::crypto::Signed("sign_two"),
                               shared_model::crypto::PublicKey("key_one")));
}

/**
 * @given Block with given signature
 * @when  Invoke ::addSignature with same public key but different signed
 * @then  Expect that second signature wasn't added
 */
TEST(SecuritySignature, BlockAddSignature) {
  auto block = TestBlockBuilder().build();
  ASSERT_TRUE(block.addSignature(shared_model::crypto::Signed("sign_one"),
                                 shared_model::crypto::PublicKey("key_one")));
  ASSERT_FALSE(block.addSignature(shared_model::crypto::Signed("sign_two"),
                                  shared_model::crypto::PublicKey("key_one")));
}
