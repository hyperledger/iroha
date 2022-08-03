/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <boost/variant.hpp>
#include <chrono>
#include <thread>

#include "builders/protobuf/transaction.hpp"
#include "framework/batch_helper.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/iroha_internal/transaction_sequence.hpp"
#include "interfaces/iroha_internal/transaction_sequence_factory.hpp"
#include "interfaces/permissions.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "test/integration/acceptance/instantiate_test_suite.hpp"

using namespace shared_model;
using namespace common_constants;
using namespace integration_framework;
using namespace iroha;
using interface::permissions::Role;
using ::testing::ElementsAre;
using ::testing::get;
using ::testing::IsEmpty;
using ::testing::Pointwise;
using ::testing::Truly;
using ::testing::Values;
using ::testing::WithParamInterface;

using shared_model::interface::types::PublicKeyHexStringView;

template <typename Batch, typename... KeyPairs>
auto addSignaturesFromKeyPairs(Batch &&batch,
                               int tx_number,
                               KeyPairs... keypairs) {
  auto create_signature = [&](auto &&key_pair) {
    auto &payload = batch->transactions().at(tx_number)->payload();
    auto signed_blob = shared_model::crypto::CryptoSigner::sign(
        shared_model::crypto::Blob(payload), key_pair);
    using namespace shared_model::interface::types;
    batch->addSignature(tx_number,
                        SignedHexStringView{signed_blob},
                        PublicKeyHexStringView{key_pair.publicKey()});
  };

  // pack expansion trick:
  // an ellipsis operator applies insert_signatures to each signature, operator
  // comma returns the rightmost argument, which is 0
  int temp[] = {(create_signature(std::forward<KeyPairs>(keypairs)), 0)...};
  // use unused variable
  (void)temp;

  return std::forward<Batch>(batch);
}

struct BatchPipelineTestBase : AcceptanceFixture {
  /**
   * Create transaction to create first user
   * @return transaction to create first user
   */
  auto createFirstUser() {
    return AcceptanceFixture::createUser(
               kFirstUser,
               PublicKeyHexStringView{kFirstUserKeypair.publicKey()})
        .build()
        .signAndAddSignature(kAdminKeypair)
        .finish();
  }

  /**
   * Create transaction to add one more signatory and set account quorum equal 2
   */
  auto raiseFirstUserQuorum() {
    return AcceptanceFixture::complete(
        AcceptanceFixture::baseTx(kFirstUserId)
            .addSignatory(
                kFirstUserId,
                PublicKeyHexStringView{kFirstUserSecondKeypair.publicKey()})
            .setAccountQuorum(kFirstUserId, 2),
        kFirstUserKeypair);
  }

  /**
   * @return transaction to create second user
   */
  auto createSecondUser() {
    return AcceptanceFixture::createUser(
               kSecondUser,
               PublicKeyHexStringView{kSecondUserKeypair.publicKey()})
        .build()
        .signAndAddSignature(kAdminKeypair)
        .finish();
  }

  /**
   * @return transaction to create the role for the two users
   */
  auto createRole() {
    return AcceptanceFixture::baseTx(kAdminId)
        .createRole(kRole,
                    {Role::kReceive,
                     Role::kTransfer,
                     Role::kAddAssetQty,
                     Role::kSubtractAssetQty,
                     Role::kCreateAsset,
                     Role::kAddSignatory,
                     Role::kSetQuorum})
        .build()
        .signAndAddSignature(kAdminKeypair)
        .finish();
  }

  /**
   * @return transaction to add the role to the two users
   */
  auto addRoleToUsers() {
    return AcceptanceFixture::baseTx(kAdminId)
        .appendRole(kFirstUserId, kRole)
        .appendRole(kSecondUserId, kRole)
        .build()
        .signAndAddSignature(kAdminKeypair)
        .finish();
  }

  /**
   * Create transaction to create asset and add its given amount to given user
   * @param account_id account for which amount of asset is added
   * @param asset_name name of the asset to be created and added to the account
   * @param amount amount of the asset to be added to the account
   * @param keypair is used to sign transaction
   * @return transaction with create asset and add asset quantity commands
   */
  auto createAndAddAssets(const interface::types::AccountIdType &account_id,
                          const interface::types::AssetNameType &asset_name,
                          const std::string &amount,
                          const crypto::Keypair &keypair) {
    return proto::TransactionBuilder()
        .creatorAccountId(account_id)
        .quorum(1)
        .createdTime(iroha::time::now())
        .createAsset(asset_name, kDomain, 2)
        .addAssetQuantity(asset_name + "#" + kDomain, amount)
        .build()
        .signAndAddSignature(keypair)
        .finish();
  }

  /**
   * Create builder for transaction to do transfer between given users with
   * given amount of given asset
   * @param src_account_id source accound id
   * @param dest_account_id destination account id
   * @param asset_name name of the asset (without domain) to be transferred
   * @param amount amount of asset to be transferred
   * @param quorum for the transaction
   * @return transaction builder with transfer asset command
   */
  auto prepareTransferAssetBuilder(
      const interface::types::AccountIdType &src_account_id,
      const interface::types::AccountIdType &dest_account_id,
      const interface::types::AssetNameType &asset_name,
      const std::string &amount,
      const interface::types::QuorumType &quorum = 1) {
    return TestTransactionBuilder()
        .creatorAccountId(src_account_id)
        .quorum(quorum)
        .createdTime(iroha::time::now())
        .transferAsset(src_account_id,
                       dest_account_id,
                       asset_name + "#" + kDomain,
                       "",
                       amount);
  }

  /**
   * Take transaction and sign it with provided signature
   * @param tx to be signed
   * @param keypair to sign
   * @return signed transaction
   */
  auto signedTx(std::shared_ptr<interface::Transaction> tx,
                const crypto::Keypair &keypair) {
    auto signed_blob =
        crypto::DefaultCryptoAlgorithmType::sign(tx->payload(), keypair);
    auto clone_tx = clone(tx.get());
    clone_tx->addSignature(
        shared_model::interface::types::SignedHexStringView{signed_blob},
        PublicKeyHexStringView{keypair.publicKey()});
    return std::shared_ptr<interface::Transaction>(std::move(clone_tx));
  }

  auto createTransactionSequence(
      const interface::types::SharedTxsCollectionType &txs) {
    auto transaction_sequence_result =
        interface::TransactionSequenceFactory::createTransactionSequence(
            txs,
            shared_model::validation::DefaultUnsignedTransactionsValidator(
                iroha::test::kTestsValidatorsConfig),
            shared_model::validation::FieldValidator(
                iroha::test::kTestsValidatorsConfig));

    auto transaction_sequence_value =
        framework::expected::val(transaction_sequence_result);
    EXPECT_TRUE(transaction_sequence_value)
        << framework::expected::err(transaction_sequence_result).value().error;

    return transaction_sequence_value.value().value;
  }

  auto batchToSequence(
      const std::shared_ptr<interface::TransactionBatch> &batch) {
    return interface::TransactionSequence(
        std::vector<std::shared_ptr<shared_model::interface::TransactionBatch>>{
            batch});
  };

  IntegrationTestFramework &prepareState(IntegrationTestFramework &itf,
                                         const std::string &amount1,
                                         const std::string &amount2) {
    return itf.setInitialState(kAdminKeypair)
        .sendTxAwait(createFirstUser(), CHECK_TXS_QUANTITY(1))
        .sendTxAwait(createSecondUser(), CHECK_TXS_QUANTITY(1))
        .sendTxAwait(createRole(), CHECK_TXS_QUANTITY(1))
        .sendTxAwait(addRoleToUsers(), CHECK_TXS_QUANTITY(1))
        .sendTxAwait(createAndAddAssets(
                         kFirstUserId, kAssetA, amount1, kFirstUserKeypair),
                     CHECK_TXS_QUANTITY(1))
        .sendTxAwait(createAndAddAssets(
                         kSecondUserId, kAssetB, amount2, kSecondUserKeypair),
                     CHECK_TXS_QUANTITY(1));
  }

 protected:
  const std::string kAdmin = "admin";
  const std::string kFirstUser = "first";
  const std::string kSecondUser = "second";

  const std::string kFirstUserId = kFirstUser + "@" + kDomain;
  const std::string kSecondUserId = kSecondUser + "@" + kDomain;

  const crypto::Keypair kFirstUserKeypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  const crypto::Keypair kFirstUserSecondKeypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  const crypto::Keypair kSecondUserKeypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();

  const std::string kAssetA = "usd";
  const std::string kAssetB = "euro";
};

using interface::types::BatchType;
using namespace ::testing;

inline static const char *BatchTypeToString(BatchType const &bt) {
  switch (bt) {
    case BatchType::ATOMIC:
      return "ATOMIC";
    case BatchType::ORDERED:
      return "ORDERED";
    default:
      return "UNKNOWN";
  }
}

struct BatchPipelineTest
    : BatchPipelineTestBase,
      ::testing::WithParamInterface<std::tuple<iroha::StorageType>> {};

struct BatchPipelineTestByDatabaseAndBatchType
    : BatchPipelineTestBase,
      ::testing::WithParamInterface<
          std::tuple<iroha::StorageType, interface::types::BatchType>> {};

INSTANTIATE_TEST_SUITE_P(
    DifferentStorageTypes,
    BatchPipelineTest,
    Values(StorageType::kPostgres, StorageType::kRocksDb),
    [](const testing::TestParamInfo<std::tuple<StorageType>> &info) {
      std::string name;
      name += StorageTypeToString(std::get<StorageType>(info.param));
      return name;
    });

INSTANTIATE_TEST_SUITE_P(
    DifferentBatchAndStorageTypes,
    BatchPipelineTestByDatabaseAndBatchType,
    Combine(Values(BatchType::ATOMIC, BatchType::ORDERED),
            Values(StorageType::kPostgres, StorageType::kRocksDb)),
    [](const testing::TestParamInfo<std::tuple<iroha::StorageType, BatchType>>
           &info) {
      std::string name;
      name += StorageTypeToString(std::get<StorageType>(info.param));
      name += "_";
      name += BatchTypeToString(std::get<BatchType>(info.param));
      return name;
    });

/**
 * Matchers to compare references against pointers
 */
MATCHER(RefAndPointerEq, "") {
  return get<0>(arg) == *get<1>(arg);
}

MATCHER_P(RefAndPointerEq, arg1, "") {
  return arg == *arg1;
}

/**
 * @given any type of batch (ordered or atomic) with two transactions
 * @when transactions are sent to iroha
 * @then both transactions are committed
 */
TEST_P(BatchPipelineTestByDatabaseAndBatchType, ValidBatch) {
  auto batch_transactions = framework::batch::makeTestBatchTransactions(
      std::get<BatchType>(GetParam()),
      prepareTransferAssetBuilder(kFirstUserId, kSecondUserId, kAssetA, "1.0"),
      prepareTransferAssetBuilder(kSecondUserId, kFirstUserId, kAssetB, "1.0"));

  SCOPED_TRACE("From valid batch test");
  auto transaction_sequence = createTransactionSequence(
      {signedTx(batch_transactions[0], kFirstUserKeypair),
       signedTx(batch_transactions[1], kSecondUserKeypair)});
  IntegrationTestFramework itf(2, std::get<StorageType>(GetParam()));
  prepareState(itf, "1.0", "1.0")
      .sendTxSequenceAwait(
          transaction_sequence, [&transaction_sequence](const auto &block) {
            // check that transactions from block are the same as transactions
            // from transaction sequence
            ASSERT_THAT(block->transactions(),
                        Pointwise(RefAndPointerEq(),
                                  transaction_sequence.transactions()));
          });
}

/**
 * @given atomic batch of two transactions, with one transaction being
 * stateful invalid
 * @when batch is sent to iroha
 * @then no transaction is committed
 */
TEST_P(BatchPipelineTest, InvalidAtomicBatch) {
  auto batch_transactions = framework::batch::makeTestBatchTransactions(
      interface::types::BatchType::ATOMIC,
      prepareTransferAssetBuilder(kFirstUserId, kSecondUserId, kAssetA, "1.0"),
      prepareTransferAssetBuilder(kSecondUserId,
                                  kFirstUserId,
                                  kAssetB,
                                  "2.0")  // invalid tx due to too big transfer
  );

  SCOPED_TRACE("From invalid atomic batch test");
  auto transaction_sequence = createTransactionSequence(
      {signedTx(batch_transactions[0], kFirstUserKeypair),
       signedTx(batch_transactions[1], kSecondUserKeypair)});

  IntegrationTestFramework itf(2,
                               std::get<StorageType>(GetParam()),
                               boost::none,
                               iroha::StartupWsvDataPolicy::kDrop,
                               true,
                               false,
                               boost::none,
                               milliseconds(20000),
                               milliseconds(20000),
                               milliseconds(20000));
  prepareState(itf, "1.0", "1.0")
      .sendTxSequenceAwait(transaction_sequence, [](const auto block) {
        ASSERT_THAT(block->transactions(), IsEmpty());
      });
}

/**
 * @given ordered batch of three transactions, with one transaction being
 * stateful invalid
 * @when batch is sent to iroha
 * @then all transactions except stateful invalid one are committed
 */
TEST_P(BatchPipelineTest, InvalidOrderedBatch) {
  auto batch_transactions = framework::batch::makeTestBatchTransactions(
      interface::types::BatchType::ORDERED,
      prepareTransferAssetBuilder(kFirstUserId, kSecondUserId, kAssetA, "0.3"),
      prepareTransferAssetBuilder(
          kSecondUserId,
          kFirstUserId,
          kAssetB,
          "2.0"),  // stateful invalid tx due to too big transfer
      prepareTransferAssetBuilder(kFirstUserId, kSecondUserId, kAssetA, "0.7"));

  SCOPED_TRACE("From InvalidOrderedBatch");
  auto transaction_sequence = createTransactionSequence(
      {signedTx(batch_transactions[0], kFirstUserKeypair),
       signedTx(batch_transactions[1], kSecondUserKeypair),
       signedTx(batch_transactions[2], kFirstUserKeypair)});

  IntegrationTestFramework itf(3, std::get<StorageType>(GetParam()));
  prepareState(itf, "1.0", "1.0")
      .sendTxSequenceAwait(transaction_sequence, [&](const auto block) {
        ASSERT_THAT(
            block->transactions(),
            ElementsAre(
                RefAndPointerEq(transaction_sequence.transactions()[0]),
                RefAndPointerEq(transaction_sequence.transactions()[2])));
      });
}

/**
 * Test that a batch would not be passed to stateful validation when one
 * transaction is fully signed and another is not signed at all.
 * @given
 *   two users - the first user has quorum two
 *   an atomic batch with two transactions
 *   the first transaction is signed with only one valid signature
 *   the second transaciton is not signed
 *   the batch is sent to Iroha and in a pending state
 * @when
 *   the first transaction acquires the second valid signature
 *   and the batch is sent again to Iroha
 * @then
 *   the batch is sill in a pending state
 *   because the second transaction has no signatures
 */
TEST_P(BatchPipelineTest, SemisignedAtomicBatch) {
  auto batch = framework::batch::makeTestBatch(
      prepareTransferAssetBuilder(
          kFirstUserId, kSecondUserId, kAssetA, "1.0", 2),
      prepareTransferAssetBuilder(kSecondUserId, kFirstUserId, kAssetB, "1.0"));

  batch = addSignaturesFromKeyPairs(batch, 0, kFirstUserKeypair);
  auto firstTxHash = batch->transactions()[0]->hash();

  IntegrationTestFramework itf(2, std::get<StorageType>(GetParam()));
  prepareState(itf, "10.0", "20.0")
      .sendTxAwait(raiseFirstUserQuorum(), CHECK_TXS_QUANTITY(1))
      .sendTxSequence(batchToSequence(batch))
      .checkStatus(firstTxHash, CHECK_STATELESS_VALID)
      .checkStatus(firstTxHash, CHECK_MST_PENDING);

  batch = addSignaturesFromKeyPairs(batch, 0, kFirstUserSecondKeypair);
  itf.sendTxSequence(batchToSequence(batch))
      .checkStatus(firstTxHash, CHECK_STATELESS_VALID)
      .checkStatus(firstTxHash, CHECK_MST_PENDING);
}

/**
 * Test that the batch goes to the stateful validation only when all the
 * signatures are collected. Signatures are added sequentially by one.
 * @given
 *   two users - the first user has quorum two
 *   an atomic batch with two transactions
 *   the first transaction is signed with only one valid signature
 *   the second transaciton is not signed
 *   the batch is sent to Iroha and in a pending state
 * @when
 *   signatures are added sequentially
 * @then
 *   batch remains pending till all signatures are collected
 */
TEST_P(BatchPipelineTest, CommitAtomicBatchStepByStepSigning) {
  auto batch = framework::batch::makeTestBatch(
      prepareTransferAssetBuilder(
          kFirstUserId, kSecondUserId, kAssetA, "1.0", 2),
      prepareTransferAssetBuilder(kSecondUserId, kFirstUserId, kAssetB, "1.0"));

  auto batch1 = addSignaturesFromKeyPairs(batch, 0, kFirstUserKeypair);
  auto firstTxHash = batch->transactions()[0]->hash();

  IntegrationTestFramework itf(2, std::get<StorageType>(GetParam()));
  prepareState(itf, "10.0", "20.0")
      .sendTxAwait(raiseFirstUserQuorum(), CHECK_TXS_QUANTITY(1))
      .sendTxSequence(batchToSequence(batch1))
      .checkStatus(firstTxHash, CHECK_STATELESS_VALID)
      .checkStatus(firstTxHash, CHECK_MST_PENDING);

  auto batch2 = addSignaturesFromKeyPairs(batch, 0, kFirstUserSecondKeypair);
  itf.sendTxSequence(batchToSequence(batch2))
      .checkStatus(firstTxHash, CHECK_STATELESS_VALID)
      .checkStatus(firstTxHash, CHECK_MST_PENDING);

  auto batch3 = addSignaturesFromKeyPairs(batch, 1, kSecondUserKeypair);
  itf.sendTxSequence(batchToSequence(batch3))
      .checkStatus(firstTxHash, CHECK_STATELESS_VALID)
      .checkStatus(firstTxHash, CHECK_ENOUGH_SIGNATURES)
      .checkStatus(firstTxHash, CHECK_STATEFUL_VALID)
      .checkStatus(firstTxHash, CHECK_COMMITTED);
}
