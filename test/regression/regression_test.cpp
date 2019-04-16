/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "builders/protobuf/queries.hpp"
#include "builders/protobuf/transaction.hpp"
#include "common/files.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/common_constants.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/query_responses/transactions_response.hpp"

using namespace common_constants;
using shared_model::interface::permissions::Role;

static logger::LoggerPtr log_ = getTestLogger("RegressionTest");

/**
 * @given ITF instance with Iroha
 * @when existing ITF instance was not gracefully shutdown
 * @then following ITF instantiation should not cause any errors
 */
TEST(RegressionTest, SequentialInitialization) {
  auto tx = shared_model::proto::TransactionBuilder()
                .createdTime(iroha::time::now())
                .creatorAccountId(kAdminId)
                .addAssetQuantity(kAssetId, "1.0")
                .quorum(1)
                .build()
                .signAndAddSignature(
                    shared_model::crypto::DefaultCryptoAlgorithmType::
                        generateKeypair())
                .finish();

  auto check_stateless_valid_status = [](auto &status) {
    ASSERT_NO_THROW(
        boost::get<const shared_model::interface::StatelessValidTxResponse &>(
            status.get()));
  };
  auto checkProposal = [](auto &proposal) {
    ASSERT_EQ(proposal->transactions().size(), 1);
  };

  auto path = (boost::filesystem::temp_directory_path()
               / boost::filesystem::unique_path())
                  .string();
  const std::string dbname = "d"
      + boost::uuids::to_string(boost::uuids::random_generator()())
            .substr(0, 8);
  {
    integration_framework::IntegrationTestFramework(
        1, dbname, false, false, path)
        .setInitialState(kAdminKeypair)
        .sendTx(tx, check_stateless_valid_status)
        .skipProposal()
        .checkVerifiedProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 0);
        })
        .checkBlock(
            [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
  }
  {
    integration_framework::IntegrationTestFramework(
        1, dbname, true, false, path)
        .setInitialState(kAdminKeypair)
        .sendTx(tx, check_stateless_valid_status)
        .checkProposal(checkProposal)
        .checkVerifiedProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 0);
        })
        .checkBlock(
            [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
  }
}

/**
 * @given ITF instance
 * @when instance is shutdown without blocks erase
 * @then another ITF instance can restore WSV from blockstore
 */
TEST(RegressionTest, StateRecovery) {
  auto userKeypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  auto tx = shared_model::proto::TransactionBuilder()
                .createdTime(iroha::time::now())
                .creatorAccountId(kAdminId)
                .createAccount(kUser, kDomain, userKeypair.publicKey())
                .createRole(kRole, {Role::kReceive})
                .appendRole(kUserId, kRole)
                .addAssetQuantity(kAssetId, "133.0")
                .transferAsset(kAdminId, kUserId, kAssetId, "descrs", "97.8")
                .quorum(1)
                .build()
                .signAndAddSignature(kAdminKeypair)
                .finish();
  auto hash = tx.hash();
  auto makeQuery = [&hash](int query_counter, auto kAdminKeypair) {
    return shared_model::proto::QueryBuilder()
        .createdTime(iroha::time::now())
        .creatorAccountId(kAdminId)
        .queryCounter(query_counter)
        .getTransactions(std::vector<shared_model::crypto::Hash>{hash})
        .build()
        .signAndAddSignature(kAdminKeypair)
        .finish();
  };
  auto checkOne = [](auto &res) { ASSERT_EQ(res->transactions().size(), 1); };
  auto checkQuery = [&tx](auto &status) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const shared_model::interface::TransactionsResponse &>(
              status.get());
      ASSERT_EQ(resp.transactions().size(), 1);
      ASSERT_EQ(resp.transactions().front(), tx);
    });
  };
  auto path = (boost::filesystem::temp_directory_path()
               / boost::filesystem::unique_path())
                  .string();
  const std::string dbname = "d"
      + boost::uuids::to_string(boost::uuids::random_generator()())
            .substr(0, 8);

  // Cleanup blockstore directory, because it may contain blocks from previous
  // test launch if ITF was failed for some reason. If there are some blocks,
  // then checkProposal will fail with "missed proposal" error, because of
  // incorrect calculation of chain height.
  iroha::remove_dir_contents(path, log_);

  {
    integration_framework::IntegrationTestFramework(
        1, dbname, false, false, path)
        .setInitialState(kAdminKeypair)
        .sendTx(tx)
        .checkProposal(checkOne)
        .checkVerifiedProposal(checkOne)
        .checkBlock(checkOne)
        .sendQuery(makeQuery(1, kAdminKeypair), checkQuery);
  }
  {
    integration_framework::IntegrationTestFramework(
        1, dbname, true, false, path)
        .recoverState(kAdminKeypair)
        .sendQuery(makeQuery(2, kAdminKeypair), checkQuery);
  }
}

/**
 * @given ITF instance with Iroha
 * @when done method is called twice
 * @then no errors are caused as the result
 */
TEST(RegressionTest, DoubleCallOfDone) {
  integration_framework::IntegrationTestFramework itf(1);
  itf.setInitialState(kAdminKeypair).done();
  itf.done();
}

/**
 * @given non initialized ITF instance
 * @when done method is called inside destructor
 * @then no exceptions are risen
 */
TEST(RegressionTest, DestructionOfNonInitializedItf) {
  integration_framework::IntegrationTestFramework itf(1, {}, true);
}
