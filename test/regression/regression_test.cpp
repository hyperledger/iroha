/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/variant.hpp>
#include "ametsuchi/impl/flat_file/flat_file.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"
#include "builders/protobuf/queries.hpp"
#include "builders/protobuf/transaction.hpp"
#include "common/files.hpp"
#include "framework/common_constants.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/query_responses/transactions_response.hpp"
#include "main/subscription.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace common_constants;
using shared_model::interface::permissions::Role;
using shared_model::interface::types::PublicKeyHexStringView;

static logger::LoggerPtr log_ = getTestLogger("RegressionTest");

/**
 * @given ITF instance with Iroha
 * @when existing ITF instance was not gracefully shutdown
 * @then following ITF instantiation should not cause any errors
 */
TEST(RegressionTest, SequentialInitialization) {
  auto subscription_engine = iroha::getSubscription();

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

  const std::string dbname = "d"
      + boost::uuids::to_string(boost::uuids::random_generator()())
            .substr(0, 8);
  {
    integration_framework::IntegrationTestFramework(
        1, dbname, iroha::StartupWsvDataPolicy::kDrop, false, false)
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
        1, dbname, iroha::StartupWsvDataPolicy::kReuse, true, false)
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
  auto subscription_engine = iroha::getSubscription();

  auto userKeypair =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
  auto tx =
      shared_model::proto::TransactionBuilder()
          .createdTime(iroha::time::now())
          .creatorAccountId(kAdminId)
          .createAccount(
              kUser, kDomain, PublicKeyHexStringView{userKeypair.publicKey()})
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
  const std::string dbname = "d"
      + boost::uuids::to_string(boost::uuids::random_generator()())
            .substr(0, 8);

  {
    integration_framework::IntegrationTestFramework(
        1, dbname, iroha::StartupWsvDataPolicy::kDrop, false)
        .setInitialState(kAdminKeypair)
        .sendTx(tx)
        .checkProposal(checkOne)
        .checkVerifiedProposal(checkOne)
        .checkBlock(checkOne)
        .sendQuery(makeQuery(1, kAdminKeypair), checkQuery);
  }
  {
    integration_framework::IntegrationTestFramework(
        1, dbname, iroha::StartupWsvDataPolicy::kReuse, false)
        .recoverState(kAdminKeypair)
        .sendQuery(makeQuery(2, kAdminKeypair), checkQuery);
  }
}

/**
 * @given ITF instance
 * @when instance is shutdown without blocks erase, block is modified
 * @then another ITF instance fails to start up
 */
TEST(RegressionTest, PoisonedBlock) {
  auto subscription_engine = iroha::getSubscription();

  auto time_now = iroha::time::now();
  auto tx1 = shared_model::proto::TransactionBuilder()
                 .createdTime(time_now)
                 .creatorAccountId(kAdminId)
                 .addAssetQuantity(kAssetId, "133.0")
                 .quorum(1)
                 .build()
                 .signAndAddSignature(kAdminKeypair)
                 .finish();
  auto hash1 = tx1.hash();
  auto tx2 = shared_model::proto::TransactionBuilder()
                 .createdTime(time_now + 1)
                 .creatorAccountId(kAdminId)
                 .subtractAssetQuantity(kAssetId, "1.0")
                 .quorum(1)
                 .build()
                 .signAndAddSignature(kAdminKeypair)
                 .finish();
  auto hash2 = tx2.hash();
  auto check_one = [](auto &res) { ASSERT_EQ(res->transactions().size(), 1); };
  const std::string dbname = "d"
      + boost::uuids::to_string(boost::uuids::random_generator()())
            .substr(0, 8);
  std::string const block_store_path = (boost::filesystem::temp_directory_path()
                                        / boost::filesystem::unique_path())
                                           .string();
  {
    integration_framework::IntegrationTestFramework(
        1,
        dbname,
        iroha::StartupWsvDataPolicy::kDrop,
        false,
        false,
        block_store_path)
        .setInitialState(kAdminKeypair)
        .sendTx(tx1)
        .checkProposal(check_one)
        .checkVerifiedProposal(check_one)
        .checkBlock(check_one)
        .sendTx(tx2)
        .checkProposal(check_one)
        .checkVerifiedProposal(check_one)
        .checkBlock(check_one);
  }
  size_t block_n = 2;

  auto block_path = boost::filesystem::path{block_store_path}
      / iroha::ametsuchi::FlatFile::id_to_name(block_n);
  auto content = iroha::readTextFile(block_path).assumeValue();
  boost::replace_first(content, "133.0", "266.0");

  boost::filesystem::ofstream block_file(block_path);
  block_file << content;
  block_file.close();
  {
    try {
      integration_framework::IntegrationTestFramework(
          1,
          dbname,
          iroha::StartupWsvDataPolicy::kDrop,
          false,
          false,
          block_store_path)
          .recoverState(kAdminKeypair);
      ADD_FAILURE() << "No exception thrown";
    } catch (std::runtime_error const &e) {
      using ::testing::HasSubstr;
      EXPECT_THAT(e.what(), HasSubstr("Cannot validate and apply blocks"));
    } catch (...) {
      ADD_FAILURE() << "Unexpected exception thrown";
    }
  }
  boost::filesystem::remove_all(block_store_path);
}

/**
 * @given ITF instance with Iroha
 * @when done method is called twice
 * @then no errors are caused as the result
 */
TEST(RegressionTest, DoubleCallOfDone) {
  auto subscription_engine = iroha::getSubscription();

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
  auto subscription_engine = iroha::getSubscription();

  integration_framework::IntegrationTestFramework itf(
      1, {}, iroha::StartupWsvDataPolicy::kDrop, true);
}
