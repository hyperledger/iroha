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
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"
#include "builders/protobuf/queries.hpp"
#include "builders/protobuf/transaction.hpp"
#include "common/files.hpp"
#include "framework/common_constants.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/query_responses/transactions_response.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "test/integration/acceptance/instantiate_test_suite.hpp"

using namespace common_constants;
using namespace integration_framework;
using shared_model::interface::permissions::Role;
using shared_model::interface::types::PublicKeyHexStringView;

static logger::LoggerPtr log_ = getTestLogger("RegressionTest");

struct RegressionTest : ::testing::Test,
                        ::testing::WithParamInterface<StorageType> {};

INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes(RegressionTest);

template <size_t N>
void checkBlockHasNTxs(
    const std::shared_ptr<const shared_model::interface::Block> &block) {
  ASSERT_EQ(block->transactions().size(), N);
}

/**
 * @given ITF instance with Iroha
 * @when existing ITF instance was not gracefully shutdown
 * @then following ITF instantiation should not cause any errors
 */
TEST_P(RegressionTest, SequentialInitialization) {
  using namespace std::chrono;

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

  const std::string dbname = "d"
      + boost::uuids::to_string(boost::uuids::random_generator()())
            .substr(0, 8);

  IntegrationTestFramework(1,
                           GetParam(),
                           dbname,
                           iroha::StartupWsvDataPolicy::kDrop,
                           false,
                           false,
                           boost::none,
                           milliseconds(20000),
                           milliseconds(20000),
                           milliseconds(10000),
                           getDefaultItfLogManager())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(tx, checkBlockHasNTxs<0>);

  IntegrationTestFramework(1,
                           GetParam(),
                           dbname,
                           iroha::StartupWsvDataPolicy::kReuse,
                           true,
                           false,
                           boost::none,
                           milliseconds(20000),
                           milliseconds(20000),
                           milliseconds(10000),
                           getDefaultItfLogManager())
      .setInitialState(kAdminKeypair)
      .sendTxAwait(tx, checkBlockHasNTxs<0>);
}

/**
 * @given ITF instance
 * @when instance is shutdown without blocks erase
 * @then another ITF instance can restore WSV from blockstore
 */
TEST_P(RegressionTest, StateRecovery) {
  auto const wsv_path = (boost::filesystem::temp_directory_path()
                         / boost::filesystem::unique_path())
                            .string();
  auto const store_path = (boost::filesystem::temp_directory_path()
                           / boost::filesystem::unique_path())
                              .string();

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

  using namespace std::chrono;
  IntegrationTestFramework(1,
                           GetParam(),
                           dbname,
                           iroha::StartupWsvDataPolicy::kDrop,
                           false,
                           false,
                           boost::none,
                           milliseconds(20000),
                           milliseconds(20000),
                           milliseconds(10000),
                           getDefaultItfLogManager(),
                           wsv_path,
                           store_path)
      .setInitialState(kAdminKeypair)
      .sendTx(tx)
      .checkProposal(checkOne)
      .checkVerifiedProposal(checkOne)
      .checkBlock(checkOne)
      .sendQuery(makeQuery(1, kAdminKeypair), checkQuery);
  IntegrationTestFramework(1,
                           GetParam(),
                           dbname,
                           iroha::StartupWsvDataPolicy::kReuse,
                           false,
                           false,
                           boost::none,
                           milliseconds(20000),
                           milliseconds(20000),
                           milliseconds(10000),
                           getDefaultItfLogManager(),
                           wsv_path,
                           store_path)
      .recoverState(kAdminKeypair)
      .sendQuery(makeQuery(2, kAdminKeypair), checkQuery);

  boost::filesystem::remove_all(wsv_path);
  boost::filesystem::remove_all(store_path);
}

/**
 * @given ITF instance
 * @when instance is shutdown without blocks erase, block is modified
 * @then another ITF instance fails to start up
 */
TEST_P(RegressionTest, PoisonedBlock) {
  using namespace std::chrono;
  auto const wsv_path = (boost::filesystem::temp_directory_path()
                         / boost::filesystem::unique_path())
                            .string();
  auto const store_path = (boost::filesystem::temp_directory_path()
                           / boost::filesystem::unique_path())
                              .string();

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
  IntegrationTestFramework(1,
                           GetParam(),
                           dbname,
                           iroha::StartupWsvDataPolicy::kDrop,
                           false,
                           false,
                           block_store_path,
                           milliseconds(20000),
                           milliseconds(20000),
                           milliseconds(10000),
                           getDefaultItfLogManager(),
                           wsv_path,
                           store_path)
      .setInitialState(kAdminKeypair)
      .sendTx(tx1)
      .checkProposal(check_one)
      .checkVerifiedProposal(check_one)
      .checkBlock(check_one)
      .sendTx(tx2)
      .checkProposal(check_one)
      .checkVerifiedProposal(check_one)
      .checkBlock(check_one);
  size_t block_n = 2;

  switch (GetParam()) {
    case StorageType::kRocksDb: {
      using namespace iroha::ametsuchi;
      auto db_port = std::make_shared<RocksDBPort>();
      db_port->initialize(wsv_path);

      RocksDbCommon common(std::make_shared<RocksDBContext>(db_port));
      auto result =
          forBlock<kDbOperation::kGet, kDbEntry::kMustExist>(common, block_n);
      ASSERT_FALSE(iroha::expected::hasError(result));

      std::string block(*result.assumeValue());
      auto const pos = block.find("133");
      ASSERT_TRUE(pos != std::string::npos);

      common.valueBuffer() = block.replace(pos, 3, "266");
      result = forBlock<kDbOperation::kPut>(common, block_n);
      ASSERT_FALSE(iroha::expected::hasError(result));

      common.commit();
    } break;
    case StorageType::kPostgres: {
      auto block_path = boost::filesystem::path{block_store_path}
          / iroha::ametsuchi::FlatFile::id_to_name(block_n);
      auto content = iroha::readTextFile(block_path).assumeValue();
      boost::replace_first(content, "133.0", "266.0");

      boost::filesystem::ofstream block_file(block_path);
      block_file << content;
      block_file.close();
    } break;
    default:
      ASSERT_FALSE("Unexpected branch");
  }

  try {
    IntegrationTestFramework(1,
                             GetParam(),
                             dbname,
                             iroha::StartupWsvDataPolicy::kDrop,
                             false,
                             false,
                             block_store_path,
                             milliseconds(20000),
                             milliseconds(20000),
                             milliseconds(10000),
                             getDefaultItfLogManager(),
                             wsv_path,
                             store_path)
        .recoverState(kAdminKeypair);
    ADD_FAILURE() << "No exception thrown";
  } catch (std::runtime_error const &e) {
    using ::testing::HasSubstr;
    EXPECT_THAT(e.what(), HasSubstr("Bad signature"));
  } catch (...) {
    ADD_FAILURE() << "Unexpected exception thrown";
  }

  boost::filesystem::remove_all(wsv_path);
  boost::filesystem::remove_all(store_path);
  boost::filesystem::remove_all(block_store_path);
}

/**
 * @given ITF instance with Iroha
 * @when done method is called twice
 * @then no errors are caused as the result
 */
TEST_P(RegressionTest, DoubleCallOfDone) {
  IntegrationTestFramework itf(1, GetParam());
  itf.setInitialState(kAdminKeypair).done();
  itf.done();
}

/**
 * @given non initialized ITF instance
 * @when done method is called inside destructor
 * @then no exceptions are risen
 */
TEST_P(RegressionTest, DestructionOfNonInitializedItf) {
  IntegrationTestFramework itf(
      1, GetParam(), {}, iroha::StartupWsvDataPolicy::kDrop, true);
}
