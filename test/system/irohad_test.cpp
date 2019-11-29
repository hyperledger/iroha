/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fstream>
#include <sstream>

#include <gtest/gtest.h>
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <soci/postgresql/soci-postgresql.h>
#include <soci/soci.h>
#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <boost/process.hpp>
#include <boost/variant.hpp>

#include "ametsuchi/impl/postgres_options.hpp"
#include "backend/protobuf/proto_block_json_converter.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "builders/protobuf/transaction.hpp"
#include "common/bind.hpp"
#include "common/files.hpp"
#include "crypto/keys_manager_impl.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/default_hash_provider.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/query_responses/roles_response.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "main/iroha_conf_literals.hpp"
#include "main/iroha_conf_loader.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"
#include "network/impl/grpc_channel_builder.hpp"
#include "torii/command_client.hpp"
#include "torii/query_client.hpp"

// workaround for redefining -WERROR problem
#undef RAPIDJSON_HAS_STDSTRING

#include "framework/config_helper.hpp"

using namespace boost::process;
using namespace boost::filesystem;
using namespace std::chrono_literals;
using namespace common_constants;
using iroha::operator|;
using iroha::expected::resultToValue;

static logger::LoggerManagerTreePtr getIrohadTestLoggerManager() {
  static logger::LoggerManagerTreePtr irohad_test_logger_manager;
  if (!irohad_test_logger_manager) {
    irohad_test_logger_manager =
        std::make_shared<logger::LoggerManagerTree>(logger::LoggerConfig{
            logger::LogLevel::kInfo, logger::getDefaultLogPatterns()});
  }
  return irohad_test_logger_manager->getChild("IrohadTest");
}

class IrohadTest : public AcceptanceFixture {
 public:
  IrohadTest()
      : kAddress("127.0.0.1"),
        kPort(50051),
        kSecurePort(55552),
        test_data_path_(boost::filesystem::path(PATHTESTDATA)),
        keys_manager_node_(
            "node0",
            test_data_path_,
            getIrohadTestLoggerManager()->getChild("KeysManager")->getLogger()),
        keys_manager_admin_(
            kAdminId,
            test_data_path_,
            getIrohadTestLoggerManager()->getChild("KeysManager")->getLogger()),
        keys_manager_testuser_(
            "test@test",
            test_data_path_,
            getIrohadTestLoggerManager()->getChild("KeysManager")->getLogger()),
        log_(getIrohadTestLoggerManager()->getLogger()) {}

  void SetUp() override {
    setPaths();
    root_ca_ =
        resultToValue(iroha::readTextFile(path_root_certificate_.string()));

    rapidjson::Document doc;
    std::ifstream ifs_iroha(path_config_.string());
    rapidjson::IStreamWrapper isw(ifs_iroha);
    doc.ParseStream(isw);
    ASSERT_FALSE(doc.HasParseError())
        << "Failed to parse irohad config at " << path_config_.string();
    db_name_ = integration_framework::getRandomDbName();
    pgopts_ = "dbname=" + db_name_ + " "
        + integration_framework::getPostgresCredsFromEnv().value_or(
              doc[config_members::PgOpt].GetString());
    // we need a separate file here in case if target environment
    // has custom database connection options set
    // via environment variables
    doc[config_members::PgOpt].SetString(pgopts_.data(), pgopts_.size());
    doc[config_members::ToriiTlsParams]
        .GetObject()[config_members::KeyPairPath]
        .SetString(path_tls_keypair_.string().data(),
                   path_tls_keypair_.string().size());
    rapidjson::StringBuffer sb;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
    doc.Accept(writer);
    std::string config_copy_string = sb.GetString();
    std::ofstream copy_file(config_copy_);
    copy_file.write(config_copy_string.data(), config_copy_string.size());

    prepareTestData();
  }

  void launchIroha() {
    launchIroha(setDefaultParams());
  }

  void waitForChannelReady(std::shared_ptr<grpc::Channel> channel) {
    auto state = channel->GetState(true);
    auto deadline = std::chrono::system_clock::now() + kTimeout;
    while (state != grpc_connectivity_state::GRPC_CHANNEL_READY
           and deadline > std::chrono::system_clock::now()) {
      channel->WaitForStateChange(state, deadline);
      state = channel->GetState(true);
    }
    ASSERT_EQ(state, grpc_connectivity_state::GRPC_CHANNEL_READY);
  }

  void waitForServersReady() {
    waitForChannelReady(
        grpc::CreateChannel(kAddress + ":" + std::to_string(kPort),
                            grpc::InsecureChannelCredentials()));
    grpc::SslCredentialsOptions ssl_options;
    ssl_options.pem_root_certs = root_ca_;
    waitForChannelReady(
        grpc::CreateChannel(kAddress + ":" + std::to_string(kSecurePort),
                            grpc::SslCredentials(ssl_options)));
  }

  void launchIroha(const std::string &parameters) {
    iroha_process_.emplace(irohad_executable.string() + parameters);
    waitForServersReady();
    ASSERT_TRUE(iroha_process_->running());
  }

  void launchIroha(const boost::optional<std::string> &config_path,
                   const boost::optional<std::string> &genesis_block,
                   const boost::optional<std::string> &keypair_path,
                   const boost::optional<std::string> &additional_params) {
    launchIroha(
        params(config_path, genesis_block, keypair_path, additional_params));
  }

  int getBlockCount() {
    int block_count = 0;
    auto sql =
        std::make_unique<soci::session>(*soci::factory_postgresql(), pgopts_);
    *sql << "SELECT COUNT(*) FROM blocks;", soci::into(block_count);
    return block_count;
  }

  void TearDown() override {
    if (iroha_process_) {
      iroha_process_->terminate();
    }

    IROHA_ASSERT_RESULT_VALUE(
        iroha::ametsuchi::PgConnectionInit::dropWorkingDatabase(
            iroha::ametsuchi::PostgresOptions{pgopts_, db_name_, log_}));

    boost::filesystem::remove_all(test_data_path_);
    boost::filesystem::remove(config_copy_);
  }

  std::string params(const boost::optional<std::string> &config_path,
                     const boost::optional<std::string> &genesis_block,
                     const boost::optional<std::string> &keypair_path,
                     const boost::optional<std::string> &additional_params) {
    std::string res;
    config_path | [&res](auto &&s) { res += " --config " + s; };
    genesis_block | [&res](auto &&s) { res += " --genesis_block " + s; };
    keypair_path | [&res](auto &&s) { res += " --keypair_name " + s; };
    additional_params | [&res](auto &&s) { res += " " + s; };
    return res;
  }

  std::string setDefaultParams() {
    return params(
        config_copy_, path_genesis_.string(), path_keypair_node_.string(), {});
  }

  torii::CommandSyncClient createToriiClient(
      bool enable_tls = false,
      const boost::optional<uint16_t> override_port = {}) {
    uint16_t port = override_port.value_or(enable_tls ? kSecurePort : kPort);

    std::unique_ptr<iroha::protocol::CommandService_v1::Stub> stub;
    if (enable_tls) {
      stub = iroha::network::createSecureClient<
          iroha::protocol::CommandService_v1>(
          kAddress + ":" + std::to_string(port), root_ca_);
    } else {
      stub = iroha::network::createClient<iroha::protocol::CommandService_v1>(
          kAddress + ":" + std::to_string(port));
    }

    return torii::CommandSyncClient(
        std::move(stub),
        getIrohadTestLoggerManager()->getChild("CommandClient")->getLogger());
  }

  auto createDefaultTx(const shared_model::crypto::Keypair &key_pair) {
    return complete(baseTx(kAdminId).setAccountQuorum(kAdminId, 1), key_pair);
  }

  void prepareTestData() {
    ASSERT_TRUE(boost::filesystem::create_directory(test_data_path_))
        << "Could not create directory " << test_data_path_ << ".";

    ASSERT_TRUE(keys_manager_admin_.createKeys(boost::none));
    ASSERT_TRUE(keys_manager_node_.createKeys(boost::none));
    ASSERT_TRUE(keys_manager_testuser_.createKeys(boost::none));

    auto admin_keys_result = keys_manager_admin_.loadKeys(boost::none);
    IROHA_ASSERT_RESULT_VALUE(admin_keys_result);
    auto admin_keys = resultToValue(std::move(admin_keys_result));

    auto node0_keys_result = keys_manager_node_.loadKeys(boost::none);
    IROHA_ASSERT_RESULT_VALUE(node0_keys_result);
    auto node0_keys = resultToValue(std::move(node0_keys_result));

    auto user_keys_result = keys_manager_testuser_.loadKeys(boost::none);
    IROHA_ASSERT_RESULT_VALUE(user_keys_result);
    auto user_keys = resultToValue(std::move(user_keys_result));

    shared_model::interface::RolePermissionSet admin_perms{
        shared_model::interface::permissions::Role::kAddPeer,
        shared_model::interface::permissions::Role::kAddSignatory,
        shared_model::interface::permissions::Role::kCreateAccount,
        shared_model::interface::permissions::Role::kCreateDomain,
        shared_model::interface::permissions::Role::kGetAllAccAst,
        shared_model::interface::permissions::Role::kGetAllAccAstTxs,
        shared_model::interface::permissions::Role::kGetAllAccDetail,
        shared_model::interface::permissions::Role::kGetAllAccTxs,
        shared_model::interface::permissions::Role::kGetAllAccounts,
        shared_model::interface::permissions::Role::kGetAllSignatories,
        shared_model::interface::permissions::Role::kGetAllTxs,
        shared_model::interface::permissions::Role::kGetBlocks,
        shared_model::interface::permissions::Role::kGetRoles,
        shared_model::interface::permissions::Role::kReadAssets,
        shared_model::interface::permissions::Role::kRemoveSignatory,
        shared_model::interface::permissions::Role::kSetQuorum};

    shared_model::interface::RolePermissionSet default_perms{
        shared_model::interface::permissions::Role::kAddSignatory,
        shared_model::interface::permissions::Role::kGetMyAccAst,
        shared_model::interface::permissions::Role::kGetMyAccAstTxs,
        shared_model::interface::permissions::Role::kGetMyAccDetail,
        shared_model::interface::permissions::Role::kGetMyAccTxs,
        shared_model::interface::permissions::Role::kGetMyAccount,
        shared_model::interface::permissions::Role::kGetMySignatories,
        shared_model::interface::permissions::Role::kGetMyTxs,
        shared_model::interface::permissions::Role::kReceive,
        shared_model::interface::permissions::Role::kRemoveSignatory,
        shared_model::interface::permissions::Role::kSetQuorum,
        shared_model::interface::permissions::Role::kTransfer};

    shared_model::interface::RolePermissionSet money_perms{
        shared_model::interface::permissions::Role::kAddAssetQty,
        shared_model::interface::permissions::Role::kCreateAsset,
        shared_model::interface::permissions::Role::kReceive,
        shared_model::interface::permissions::Role::kTransfer};

    auto genesis_tx =
        shared_model::proto::TransactionBuilder()
            .creatorAccountId(kAdminId)
            .createdTime(iroha::time::now())
            .addPeer("0.0.0.0:10001", node0_keys.publicKey())
            .createRole(kAdminName, admin_perms)
            .createRole(kDefaultRole, default_perms)
            .createRole(kMoneyCreator, money_perms)
            .createDomain(kDomain, kDefaultRole)
            .createAsset(kAssetName, kDomain, 2)
            .createAccount(kAdminName, kDomain, admin_keys.publicKey())
            .createAccount(kUser, kDomain, user_keys.publicKey())
            .appendRole(kAdminId, kAdminName)
            .appendRole(kAdminId, kMoneyCreator)
            .quorum(1)
            .build()
            .signAndAddSignature(node0_keys)
            .finish();

    auto genesis_block =
        shared_model::proto::BlockBuilder()
            .transactions(
                std::vector<shared_model::proto::Transaction>{genesis_tx})
            .height(1)
            .prevHash(shared_model::crypto::DefaultHashProvider::makeHash(
                shared_model::crypto::Blob("")))
            .createdTime(iroha::time::now())
            .build()
            .signAndAddSignature(node0_keys)
            .finish();

    std::ofstream output_file(path_genesis_.string());
    ASSERT_TRUE(output_file);

    shared_model::proto::ProtoBlockJsonConverter()
        .serialize(genesis_block)
        .match([&output_file](
                   auto &&json) { output_file << std::move(json.value); },
               [](const auto &error) {
                 // should not get here
                 FAIL() << "Failed to write genesis block: " << error.error;
               });

    ASSERT_TRUE(output_file.good());
  }

  /**
   * Send default transaction with given key pair.
   * Method will wait until transaction reach COMMITTED status
   * OR until limit of attempts is exceeded.
   * @param key_pair Key pair for signing transaction
   * @param enable_tls use TLS to send the transaction
   * @return Response object from Torii
   */
  iroha::protocol::ToriiResponse sendDefaultTx(
      const shared_model::crypto::Keypair &key_pair, bool enable_tls = false) {
    iroha::protocol::TxStatusRequest tx_request;
    iroha::protocol::ToriiResponse torii_response;

    auto tx = createDefaultTx(key_pair);
    tx_request.set_tx_hash(tx.hash().hex());

    auto client = createToriiClient(enable_tls);
    client.Torii(tx.getTransport());

    auto resub_counter(resubscribe_attempts);
    constexpr auto committed_status = iroha::protocol::TxStatus::COMMITTED;
    do {
      std::this_thread::sleep_for(resubscribe_timeout);
      client.Status(tx_request, torii_response);
    } while (torii_response.tx_status() != committed_status
             and --resub_counter);

    return torii_response;
  }

  /**
   * Sending default transaction and assert that it was finished with
   * COMMITED status.
   * Method will wait until transaction reach COMMITTED status
   * OR until limit of attempts is exceeded.
   * @param key_pair Key pair for signing transaction
   * @param enable_tls use TLS to send the transaction
   */
  void sendDefaultTxAndCheck(const shared_model::crypto::Keypair &key_pair,
                             bool enable_tls = false) {
    auto response = sendDefaultTx(key_pair, enable_tls);
    ASSERT_EQ(response.tx_status(), iroha::protocol::TxStatus::COMMITTED);
  }

 private:
  void setPaths() {
    path_irohad_ = boost::filesystem::path(PATHIROHAD);
    irohad_executable = path_irohad_ / "irohad";
    path_config_ = test_data_path_.parent_path() / "config.sample";
    path_genesis_ = test_data_path_ / "genesis.block";
    path_keypair_node_ = test_data_path_ / "node0";
    path_tls_keypair_ = test_data_path_.parent_path() / "tls" / "correct";
    // example certificate with CN=localhost and subjectAltName=IP:127.0.0.1
    path_root_certificate_ =
        test_data_path_.parent_path() / "tls" / "correct.crt";
    config_copy_ = path_config_.string() + std::string(".copy");
  }

 public:
  boost::filesystem::path irohad_executable;
  const std::chrono::milliseconds kTimeout = 30s;
  const std::string kAddress;
  const uint16_t kPort;
  const uint16_t kSecurePort;

  boost::optional<child> iroha_process_;

  /**
   * Command client resubscription settings
   *
   * The do-while loop imitates client resubscription to the stream. Stream
   * "expiration" is a valid designed case (see pr #1615 for the details).
   *
   * The number of attempts (5) is a magic constant here. The idea behind this
   * number is the following: five resubscription with 3 seconds timeout is
   * usually enough to pass the test; if not - most likely there is another bug.
   */
  const uint32_t resubscribe_attempts = 5;
  const std::chrono::seconds resubscribe_timeout = std::chrono::seconds(3);

 protected:
  boost::filesystem::path path_irohad_;
  boost::filesystem::path test_data_path_;
  boost::filesystem::path path_config_;
  boost::filesystem::path path_genesis_;
  boost::filesystem::path path_keypair_node_;
  boost::filesystem::path path_tls_keypair_;
  boost::filesystem::path path_root_certificate_;
  std::string db_name_;
  std::string pgopts_;
  std::string config_copy_;
  iroha::KeysManagerImpl keys_manager_node_;
  iroha::KeysManagerImpl keys_manager_admin_;
  iroha::KeysManagerImpl keys_manager_testuser_;
  std::string root_ca_;

  logger::LoggerPtr log_;
};

/**
 * @given path to irohad executable and paths to files irohad is needed to be
 * run (config, genesis block, keypair)
 * @when run irohad with all parameters it needs to operate as a full node
 * @then irohad should be started and running until timeout expired
 */
TEST_F(IrohadTest, RunIrohad) {
  launchIroha();
}

/**
 * Test verifies that a transaction can be sent to running iroha and committed
 * @given running Iroha
 * @when a client sends a transaction to Iroha
 * @then the transaction is committed
 */
TEST_F(IrohadTest, SendTx) {
  launchIroha();

  auto key_pair = keys_manager_admin_.loadKeys(boost::none);
  IROHA_ASSERT_RESULT_VALUE(key_pair);

  SCOPED_TRACE("From send transaction test");
  sendDefaultTxAndCheck(resultToValue(std::move(key_pair)));
}

/**
 * Test verifies that a transaction can be sent to running iroha and commited,
 * through a TLS port
 * @given running Iroha with an open TLS port
 * @when a client sends a transaction to Iroha AND the server's certificate
 *       is valid
 * @then the transaction is committed
 */
TEST_F(IrohadTest, SendTxSecure) {
  launchIroha();

  auto key_pair = keys_manager_admin_.loadKeys(boost::none);
  IROHA_ASSERT_RESULT_VALUE(key_pair);

  SCOPED_TRACE("From secure send transaction test");
  sendDefaultTxAndCheck(resultToValue(std::move(key_pair)), true);
}

/**
 * Test verifies that you could not connect to the TLS port and send plaintext
 * data. (well you surely can, but it will not be processed)
 * @given running Iroha with an open TLS port
 * @when a client sends a transaction to Iroha without using TLS
 * @then client request fails with UNAVAILABLE status code
 */
TEST_F(IrohadTest, SendTxInsecureWithTls) {
  launchIroha();

  auto key_pair = keys_manager_admin_.loadKeys(boost::none);
  IROHA_ASSERT_RESULT_VALUE(key_pair);

  auto tx = createDefaultTx(resultToValue(std::move(key_pair)));

  auto client = createToriiClient(false, kSecurePort);
  auto response = client.Torii(tx.getTransport());

  // gRPC will close the socket with status code UNAVAILABLE, and
  // message "Socket closed" so, this seems to be a good enough way to
  // test this behaviour
  ASSERT_EQ(grpc::StatusCode::UNAVAILABLE, response.error_code());
}

/**
 * Test verifies that a query can be sent to and served by running Iroha
 * @given running Iroha
 * @when a client sends a query to Iroha
 * @then the query is served and query response is received
 */
TEST_F(IrohadTest, SendQuery) {
  launchIroha();

  auto key_pair = keys_manager_admin_.loadKeys(boost::none);
  IROHA_ASSERT_RESULT_VALUE(key_pair);

  iroha::protocol::QueryResponse response;
  auto query = complete(baseQry(kAdminId).getRoles(),
                        resultToValue(std::move(key_pair)));
  auto client = torii_utils::QuerySyncClient(kAddress, kPort);
  client.Find(query.getTransport(), response);
  shared_model::proto::QueryResponse resp{std::move(response)};

  ASSERT_NO_THROW(
      boost::get<const shared_model::interface::RolesResponse &>(resp.get()));
}

/**
 * Test verifies that after restarting with --overwrite-ledger flag Iroha
 * contain single genesis block in storage and Iroha can accept and serve
 * transactions
 * @given an Iroha with some transactions commited ontop of the genesis
 * block
 * @when the Iroha is restarted with --overwrite-ledger flag
 * @then the Iroha started with single genesis block in storage
 *  AND the Iroha accepts and able to commit new transactions
 */
TEST_F(IrohadTest, RestartWithOverwriteLedger) {
  launchIroha();

  auto key_pair_result = keys_manager_admin_.loadKeys(boost::none);
  IROHA_ASSERT_RESULT_VALUE(key_pair_result);
  auto key_pair = resultToValue(std::move(key_pair_result));

  SCOPED_TRACE("From restart with --overwrite-ledger flag test");
  sendDefaultTxAndCheck(key_pair);

  iroha_process_->terminate();

  launchIroha(config_copy_,
              path_genesis_.string(),
              path_keypair_node_.string(),
              std::string("--overwrite-ledger"));

  ASSERT_EQ(getBlockCount(), 1);

  SCOPED_TRACE("From restart with --overwrite-ledger flag test");
  sendDefaultTxAndCheck(key_pair);
}

/**
 * Test verifies that Iroha can accept and serve transactions after usual
 * restart
 * @given an Iroha with some transactions commited ontop of the genesis
 * block
 * @when the Iroha is restarted without --overwrite-ledger flag
 * @then the state is successfully restored
 *  AND the Iroha accepts and able to commit new transactions
 */
TEST_F(IrohadTest, RestartWithoutResetting) {
  launchIroha();

  auto key_pair_result = keys_manager_admin_.loadKeys(boost::none);
  IROHA_ASSERT_RESULT_VALUE(key_pair_result);
  auto key_pair = resultToValue(std::move(key_pair_result));

  SCOPED_TRACE("From restart without resetting test");
  sendDefaultTxAndCheck(key_pair);

  int height = getBlockCount();

  iroha_process_->terminate();

  launchIroha(config_copy_, {}, path_keypair_node_.string(), {});

  ASSERT_EQ(getBlockCount(), height);

  SCOPED_TRACE("From restart without resetting test");
  sendDefaultTxAndCheck(key_pair);
}
