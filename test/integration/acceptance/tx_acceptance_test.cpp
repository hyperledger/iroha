/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <boost/variant.hpp>

#include "framework/crypto_literals.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "instantiate_test_suite.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace common_constants;
using namespace integration_framework;

using shared_model::interface::types::PublicKeyHexStringView;

struct AcceptanceTest : AcceptanceFixture,
                        ::testing::WithParamInterface<StorageType> {
  const std::function<void(const shared_model::proto::TransactionResponse &)>
      checkStatelessValidStatus = [](auto &status) {
        ASSERT_NO_THROW(
            boost::get<const shared_model::interface::StatelessValidTxResponse
                           &>(status.get()))
            << status.toString();
      };
  const std::function<void(
      const std::shared_ptr<const shared_model::interface::Proposal> &)>
      checkProposal =
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 1); };
  const std::function<void(
      const std::shared_ptr<const shared_model::interface::Block> &)>
      checkStatefulValid =
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); };

  template <typename Builder = TestUnsignedTransactionBuilder>
  auto baseTx() {
    return Builder()
        .createdTime(getUniqueTime())
        .creatorAccountId(kAdminId)
        .addAssetQuantity(kAssetId, "1.0")
        .quorum(1);
  }
};

// ToDo burrow with rocksdb
INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes_list(
    AcceptanceTest, testing::Values(StorageType::kPostgres));

/**
 * TODO mboldyrev 18.01.2019 IR-227 convert to a separate status test
 * and a SFV integration test of non existing tx creator account
 * (seems not covered in postgres_executor_test or transaction_processor_test)
 *
 * @given non existent user
 * @when sending  transaction to the ledger
 * @then receive ENOUGH_SIGNATURES_COLLECTED status
 *       @and verified proposal is empty for that transaction
 */
TEST_P(AcceptanceTest, NonExistentCreatorAccountId) {
  const std::string kNonUser = "nonuser@test";
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(complete(baseTx<>().creatorAccountId(kNonUser), kAdminKeypair),
              checkStatelessValidStatus)
      .checkProposal(checkProposal)
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 remove, covered by field validator test
 *
 * @given some user
 * @when sending transactions with an 1 hour old UNIX time
 * @then receive ENOUGH_SIGNATURES_COLLECTED status
 *       AND STATEFUL_VALIDATION_SUCCESS on that tx
 */
TEST_P(AcceptanceTest, Transaction1HourOld) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(complete(baseTx<>().createdTime(
                           iroha::time::now(std::chrono::hours(-1))),
                       kAdminKeypair),
              checkStatelessValidStatus)
      .skipProposal()
      .skipVerifiedProposal()
      .checkBlock(checkStatefulValid);
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 remove, covered by field validator test
 *
 * @given some user
 * @when sending transactions with an less than 24 hour old UNIX time
 * @then receive ENOUGH_SIGNATURES_COLLECTED status
 *       AND STATEFUL_VALIDATION_SUCCESS on that tx
 */
TEST_P(AcceptanceTest, DISABLED_TransactionLess24HourOld) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(complete(baseTx<>().createdTime(iroha::time::now(
                           std::chrono::hours(24) - std::chrono::minutes(1))),
                       kAdminKeypair),
              checkStatelessValidStatus)
      .skipProposal()
      .skipVerifiedProposal()
      .checkBlock(checkStatefulValid);
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 remove, covered by field validator test
 *
 * @given some user
 * @when sending transactions with an more than 24 hour old UNIX time
 * @then receive STATELESS_VALIDATION_FAILED status
 */
TEST_P(AcceptanceTest, TransactionMore24HourOld) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(complete(baseTx<>().createdTime(iroha::time::now(
                           std::chrono::hours(24) + std::chrono::minutes(1))),
                       kAdminKeypair),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 remove, covered by field validator test
 *
 * @given some user
 * @when sending transactions with an less that 5 minutes from future UNIX time
 * @then receive ENOUGH_SIGNATURES_COLLECTED status
 *       AND STATEFUL_VALIDATION_SUCCESS on that tx
 */
TEST_P(AcceptanceTest, Transaction5MinutesFromFuture) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(complete(baseTx<>().createdTime(iroha::time::now(
                           std::chrono::minutes(5) - std::chrono::seconds(10))),
                       kAdminKeypair),
              checkStatelessValidStatus)
      .skipProposal()
      .skipVerifiedProposal()
      .checkBlock(checkStatefulValid);
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 remove, covered by field validator test
 *
 * @given some user
 * @when sending transactions with an 10 minutes from future UNIX time
 * @then receive STATELESS_VALIDATION_FAILED status
 */
TEST_P(AcceptanceTest, Transaction10MinutesFromFuture) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(complete(baseTx<>().createdTime(
                           iroha::time::now(std::chrono::minutes(10))),
                       kAdminKeypair),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 remove, covered by field validator test
 *
 * @given some user
 * @when sending transactions with an empty public Key
 * @then receive STATELESS_VALIDATION_FAILED status
 */
TEST_P(AcceptanceTest, TransactionEmptyPubKey) {
  using namespace std::literals;
  shared_model::proto::Transaction tx =
      baseTx<TestTransactionBuilder>().build();

  auto signedBlob = shared_model::crypto::CryptoSigner::sign(
      shared_model::crypto::Blob(tx.payload()), kAdminKeypair);
  tx.addSignature(
      shared_model::interface::types::SignedHexStringView{signedBlob},
      ""_hex_pubkey);
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(tx, CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 convert to a crypto provider unit test.
 * Also make a single SVL integration test including SignableModelValidator or
 * even whole torii::CommandServiceTransportGrpc and the crypto provider
 *
 * @given some user
 * @when sending transactions with an empty signedBlob
 * @then receive STATELESS_VALIDATION_FAILED status
 */
TEST_P(AcceptanceTest, TransactionEmptySignedblob) {
  using namespace std::literals;
  shared_model::proto::Transaction tx =
      baseTx<TestTransactionBuilder>().build();
  tx.addSignature(shared_model::interface::types::SignedHexStringView{""sv},
                  PublicKeyHexStringView{kAdminKeypair.publicKey()});
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(tx, CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 convert to a crypto provider unit test
 *
 * @given some user
 * @when sending transactions with correctly formed invalid PublicKey
 * @then receive STATELESS_VALIDATION_FAILED status
 */
TEST_P(AcceptanceTest, TransactionInvalidPublicKey) {
  shared_model::proto::Transaction tx =
      baseTx<TestTransactionBuilder>().build();
  auto signedBlob = shared_model::crypto::CryptoSigner::sign(
      shared_model::crypto::Blob(tx.payload()), kAdminKeypair);
  std::string public_key{
      shared_model::crypto::DefaultCryptoAlgorithmType::kPublicKeyLength, 'a'};
  tx.addSignature(
      shared_model::interface::types::SignedHexStringView{signedBlob},
      shared_model::interface::types::PublicKeyHexStringView{public_key});
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(tx, CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 convert to a crypto provider unit test
 *
 * @given some user
 * @when sending transactions with Invalid SignedBlock
 * @then receive STATELESS_VALIDATION_FAILED status
 */
TEST_P(AcceptanceTest, TransactionInvalidSignedBlob) {
  shared_model::proto::Transaction tx =
      baseTx<TestTransactionBuilder>().build();

  auto wrong_signature = shared_model::crypto::CryptoSigner::sign(
      shared_model::crypto::Blob(tx.payload()), kUserKeypair);

  tx.addSignature(
      shared_model::interface::types::SignedHexStringView{wrong_signature},
      PublicKeyHexStringView{kAdminKeypair.publicKey()});

  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(tx, CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 remove, successful case covered by
 * higher-level tests
 *
 * @given some user
 * @when sending transactions with valid signature
 * @then receive ENOUGH_SIGNATURES_COLLECTED status
 *       AND STATEFUL_VALIDATION_SUCCESS on that tx
 */
TEST_P(AcceptanceTest, TransactionValidSignedBlob) {
  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(complete(baseTx<>(), kAdminKeypair), checkStatelessValidStatus)
      .skipProposal()
      .skipVerifiedProposal()
      .checkBlock(checkStatefulValid);
}

/**
 * TODO mboldyrev 18.01.2019 IR-227 convert to a SignableModelValidator test
 *
 * @given some user
 * @when sending transaction without any signature
 * @then the response is STATELESS_VALIDATION_FAILED
 */
TEST_P(AcceptanceTest, EmptySignatures) {
  auto proto_tx = baseTx<TestTransactionBuilder>().build().getTransport();
  proto_tx.clear_signatures();
  auto tx = shared_model::proto::Transaction(proto_tx);

  IntegrationTestFramework(1, GetParam())
      .setInitialState(kAdminKeypair)
      .sendTx(tx, CHECK_STATELESS_INVALID);
}
