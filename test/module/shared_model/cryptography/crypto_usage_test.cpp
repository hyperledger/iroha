/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <memory>

#include "validators/validation_error_output.hpp"

#include <gtest/gtest.h>

#include "cryptography/crypto_provider/crypto_signer_internal.hpp"
#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_query_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "module/shared_model/cryptography/make_default_crypto_signer.hpp"
#include "validators/field_validator.hpp"

using namespace common_constants;
using namespace shared_model::crypto;
using namespace shared_model::interface::types;

using shared_model::validation::ValidationError;

static const auto kBadSignatureMatcher{::testing::Optional(::testing::Property(
    &ValidationError::toString, ::testing::HasSubstr("Bad signature")))};
static const auto kNoSignatureMatcher{::testing::Optional(::testing::Property(
    &ValidationError::toString, ::testing::HasSubstr("Signatures are empty")))};

class CryptoUsageTest : public ::testing::Test {
 public:
  virtual void SetUp() {
    auto creator = "a@domain";
    auto account_id = "b@domain";

    // initialize block
    block = std::make_unique<shared_model::proto::Block>(
        TestBlockBuilder().height(1).build());

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

    data = Blob("raw data for signing");
  }

  template <typename T>
  void signIncorrect(T &signable) {
    // initialize wrong signature
    auto signature_hex =
        signer_->sign(shared_model::crypto::Blob{"wrong payload"});
    signable.addSignature(SignedHexStringView{signature_hex},
                          signer_->publicKey());
  }

  template <typename T>
  std::optional<ValidationError> verify(const T &signable) const {
    return field_validator_.validateSignatures(signable.signatures(),
                                               signable.payload());
  }

  Blob data;
  std::shared_ptr<shared_model::crypto::CryptoSigner> signer_ =
      shared_model::crypto::makeDefaultSigner();

  template <typename T>
  void sign(T &o) {
    o.addSignature(SignedHexStringView{signer_->sign(o.payload())},
                   signer_->publicKey());
  }

  shared_model::validation::FieldValidator field_validator_{
      iroha::test::kTestsValidatorsConfig};

  std::unique_ptr<shared_model::proto::Block> block;
  std::unique_ptr<shared_model::proto::Query> query;
  std::unique_ptr<shared_model::proto::Transaction> transaction;
};

/**
 * @given Initialized keypiar with _concrete_ algorithm
 * @when sign date without knowledge of cryptography algorithm
 * @then check that siganture valid without clarification of algorithm
 */
TEST_F(CryptoUsageTest, RawSignAndVerifyTest) {
  auto signature_hex = signer_->sign(data);
  using namespace shared_model::interface::types;
  auto verified = CryptoVerifier::verify(
      SignedHexStringView{signature_hex}, data, signer_->publicKey());
  IROHA_ASSERT_RESULT_VALUE(verified);
}

/**
 * @given unsigned block
 * @when verify block
 * @then block is not verified
 */
TEST_F(CryptoUsageTest, UnsignedBlock) {
  ASSERT_THAT(verify(*block), kNoSignatureMatcher);
}

/**
 * @given properly signed block
 * @when verify block
 * @then block is verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyBlock) {
  sign(*block);

  EXPECT_EQ(verify(*block), std::nullopt);
}

/**
 * @given block with inctorrect sign
 * @when verify block
 * @then block is not verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyBlockWithWrongSignature) {
  signIncorrect(*block);

  EXPECT_THAT(verify(*block), kBadSignatureMatcher);
}

/**
 * @given unsigned query
 * @when verify query
 * @then query is not verified
 */
TEST_F(CryptoUsageTest, UnsignedQuery) {
  ASSERT_THAT(verify(*query), kNoSignatureMatcher);
}

/**
 * @given properly signed query
 * @when verify query
 * @then query is verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyQuery) {
  sign(*query);

  EXPECT_EQ(verify(*query), std::nullopt);
}

/**
 * @given query with incorrect sign
 * @when verify query
 * @then query is not verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyQuerykWithWrongSignature) {
  signIncorrect(*query);

  EXPECT_THAT(verify(*query), kBadSignatureMatcher);
}

/**
 * @given query hash
 * @when sign query
 * @then query hash doesn't change
 */
TEST_F(CryptoUsageTest, SameQueryHashAfterSign) {
  auto hash_before = query->hash();
  sign(*query);
  auto hash_signed = query->hash();

  ASSERT_EQ(hash_signed, hash_before);
}

/**
 * @given unsigned transaction
 * @when verify transaction
 * @then transaction is not verified
 */
TEST_F(CryptoUsageTest, UnsignedTransaction) {
  ASSERT_THAT(verify(*transaction), kNoSignatureMatcher);
}

/**
 * @given properly signed transaction
 * @when verify transaction
 * @then transaction is verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyTransaction) {
  sign(*transaction);

  EXPECT_EQ(verify(*transaction), std::nullopt);
}

/**
 * @given transaction with incorrect sign
 * @when verify transaction
 * @then transaction is not verified
 */
TEST_F(CryptoUsageTest, SignAndVerifyTransactionkWithWrongSignature) {
  signIncorrect(*transaction);

  EXPECT_THAT(verify(*transaction), kBadSignatureMatcher);
}
