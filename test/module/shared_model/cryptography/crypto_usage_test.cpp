/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memory>

#include <gtest/gtest.h>

#include "cryptography/crypto_provider/crypto_model_signer.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_query_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"

using namespace shared_model::crypto;

class CryptoUsageTest : public ::testing::Test {
 public:
  virtual void SetUp() {
    auto creator = "a@domain";
    auto account_id = "b@domain";

    // initialize block
    block = createBlock({}, 1);

    // initialize query
    query = std::make_unique<shared_model::proto::Query>(
        TestQueryBuilder()
            .creatorAccountId(creator)
            .queryCounter(1)
            .getAccount(account_id)
            .build());

    // initialize transaction
    transaction = std::make_unique<shared_model::proto::Transaction>(
        TestTransactionBuilder()
            .creatorAccountId(account_id)
            .setAccountQuorum(account_id, 2)
            .build());
  }

  template <typename T>
  void signIncorrect(T &signable) {
    // initialize wrong signature
    auto signedBlob = shared_model::crypto::DefaultCryptoAlgorithmType::sign(
        *shared_model::crypto::Blob::fromBinaryString("wrong payload"),
        keypair);
    signable.addSignature(signedBlob, keypair.publicKey());
  }

  template <typename T>
  bool verify(const T &signable) const {
    return boost::size(signable.signatures()) > 0
        and std::all_of(signable.signatures().begin(),
                        signable.signatures().end(),
                        [&signable](const auto &signature) {
                          return shared_model::crypto::CryptoVerifier<>::verify(
                              signature.signedData(),
                              signable.payload(),
                              signature.publicKey());
                        });
  }

  std::unique_ptr<Blob> data{Blob::fromBinaryString("raw data for signing")};
  shared_model::crypto::Keypair keypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();

  shared_model::crypto::CryptoModelSigner<> signer =
      shared_model::crypto::CryptoModelSigner<>(keypair);

  std::shared_ptr<shared_model::interface::Block> block;
  std::unique_ptr<shared_model::proto::Query> query;
  std::unique_ptr<shared_model::proto::Transaction> transaction;
};

/**
 * @given Initialized keypiar with _concrete_ algorithm
 * @when sign date without knowledge of cryptography algorithm
 * @then check that siganture valid without clarification of algorithm
 */
TEST_F(CryptoUsageTest, RawSignAndVerifyTest) {
  auto signed_blob =
      shared_model::crypto::DefaultCryptoAlgorithmType::sign(*data, keypair);
  auto verified = DefaultCryptoAlgorithmType::verify(
      signed_blob, *data, keypair.publicKey());
  ASSERT_TRUE(verified);
}

/**
 * @given unsigned block
 * @when verify block
 * @then block is not verified
 */
TEST_F(CryptoUsageTest, UnsignedBlock) {
  ASSERT_FALSE(verify(*block));
}

/**
 * @given properly signed block
 * @when verify block
 * @then block is verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyBlock) {
  signer.sign(*block);

  ASSERT_TRUE(verify(*block));
}

/**
 * @given block with inctorrect sign
 * @when verify block
 * @then block is not verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyBlockWithWrongSignature) {
  signIncorrect(*block);

  ASSERT_FALSE(verify(*block));
}

/**
 * @given unsigned query
 * @when verify query
 * @then query is not verified
 */
TEST_F(CryptoUsageTest, UnsignedQuery) {
  ASSERT_FALSE(verify(*query));
}

/**
 * @given properly signed query
 * @when verify query
 * @then query is verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyQuery) {
  signer.sign(*query);

  ASSERT_TRUE(verify(*query));
}

/**
 * @given query with incorrect sign
 * @when verify query
 * @then query is not verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyQuerykWithWrongSignature) {
  signIncorrect(*query);

  ASSERT_FALSE(verify(*query));
}

/**
 * @given query hash
 * @when sign query
 * @then query hash doesn't change
 */
TEST_F(CryptoUsageTest, SameQueryHashAfterSign) {
  auto hash_before = query->hash();
  signer.sign(*query);
  auto hash_signed = query->hash();

  ASSERT_EQ(hash_signed, hash_before);
}

/**
 * @given unsigned transaction
 * @when verify transaction
 * @then transaction is not verified
 */
TEST_F(CryptoUsageTest, UnsignedTransaction) {
  ASSERT_FALSE(verify(*transaction));
}

/**
 * @given properly signed transaction
 * @when verify transaction
 * @then transaction is verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyTransaction) {
  signer.sign(*transaction);

  ASSERT_TRUE(verify(*transaction));
}

/**
 * @given transaction with incorrect sign
 * @when verify transaction
 * @then transaction is not verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyTransactionkWithWrongSignature) {
  signIncorrect(*transaction);

  ASSERT_FALSE(verify(*transaction));
}
