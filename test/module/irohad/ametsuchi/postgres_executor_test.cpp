/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_query_executor.hpp"
#include "ametsuchi/impl/postgres_specific_query_executor.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "framework/common_constants.hpp"
#include "framework/result_fixture.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/pending_txs_storage/pending_txs_storage_mock.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"

using namespace std::literals;
using namespace common_constants;

using shared_model::interface::types::PublicKeyHexStringView;

namespace iroha {
  namespace ametsuchi {

    using ::testing::HasSubstr;

    using namespace framework::expected;
    using namespace common_constants;

    static const PublicKeyHexStringView kPublicKey{"public key"sv};
    static const PublicKeyHexStringView kPublicKey2{"another public key"sv};
    static const std::string domain_id{"domain"};

    class CommandExecutorTest : public AmetsuchiTest {
      // TODO [IR-1831] Akvinikym 31.10.18: rework the CommandExecutorTest
     public:
      CommandExecutorTest() {
        name = "id";
        account_id = name + "@" + domain_id;

        role_permissions.set(
            shared_model::interface::permissions::Role::kAddMySignatory);
        grantable_permission =
            shared_model::interface::permissions::Grantable::kAddMySignatory;

        query_response_factory =
            std::make_shared<shared_model::proto::ProtoQueryResponseFactory>();
      }

      void SetUp() override {
        AmetsuchiTest::SetUp();

        wsv_query =
            std::make_unique<PostgresWsvQuery>(*sql, getTestLogger("WsvQuery"));

        pending_txs_storage = std::make_shared<MockPendingTransactionStorage>();
        executor = std::make_unique<PostgresCommandExecutor>(
            std::make_unique<soci::session>(*soci::factory_postgresql(),
                                            pgopt_),
            perm_converter,
            std::make_shared<PostgresSpecificQueryExecutor>(
                *sql,
                *block_storage_,
                pending_txs_storage,
                query_response_factory,
                perm_converter,
                getTestLoggerManager()
                    ->getChild("SpecificQueryExecutor")
                    ->getLogger()),
            std::nullopt);
      }

      void TearDown() override {
        AmetsuchiTest::TearDown();
      }

      /**
       * Execute a given command and optionally check its result
       * @tparam CommandType - type of the command
       * @param command - the command to CHECK_SUCCESSFUL_RESULT(execute
       * @param do_validation - of the command should be validated
       * @param creator - creator of the command
       * @return result of command execution
       */
      template <typename CommandType>
      CommandResult execute(CommandType &&command,
                            bool do_validation = false,
                            const shared_model::interface::types::AccountIdType
                                &creator = "id@domain") {
        // TODO igor-egorov 15.04.2019 IR-446 Refactor postgres_executor_test
        shared_model::interface::Command::CommandVariantType variant{
            std::forward<CommandType>(command)};
        shared_model::interface::MockCommand cmd;
        EXPECT_CALL(cmd, get()).WillRepeatedly(::testing::ReturnRef(variant));
        return executor->execute(cmd, creator, "", 0, not do_validation);
      }

      /**
       * Check that passed result contains value and not an error
       * @param result to be checked
       */
#define CHECK_SUCCESSFUL_RESULT(result) \
  { ASSERT_TRUE(val(result)) << err(result)->error; }

      /**
       * Check that command result contains specific error code and error
       * message
       * @param cmd_result to be checked
       * @param expected_code to be in the result
       * @param expected_substrings - collection of strings, which are expected
       * to be in command error
       */
#define CHECK_ERROR_CODE_AND_MESSAGE(                \
    cmd_result, expected_code, expected_substrings)  \
  auto error = err(cmd_result);                      \
  ASSERT_TRUE(error);                                \
  EXPECT_EQ(error->error.error_code, expected_code); \
  auto str_error = error->error.error_extra;         \
  for (auto substring : expected_substrings) {       \
    EXPECT_THAT(str_error, HasSubstr(substring));    \
  }

      void addAllPerms(
          const shared_model::interface::types::AccountIdType &account_id =
              "id@domain",
          const shared_model::interface::types::RoleIdType &role_id = "all") {
        shared_model::interface::RolePermissionSet permissions;
        permissions.setAll();

        CHECK_SUCCESSFUL_RESULT(execute(
            *mock_command_factory->constructCreateRole(role_id, permissions),
            true));
        CHECK_SUCCESSFUL_RESULT(execute(
            *mock_command_factory->constructAppendRole(account_id, role_id),
            true));
      }

      void addAllPermsWithoutRoot(
          const shared_model::interface::types::AccountIdType &account_id =
              "id@domain",
          const shared_model::interface::types::RoleIdType &role_id =
              "allWithoutRoot") {
        shared_model::interface::RolePermissionSet permissions;
        permissions.setAll();
        permissions.unset(shared_model::interface::permissions::Role::kRoot);

        CHECK_SUCCESSFUL_RESULT(execute(
            *mock_command_factory->constructCreateRole(role_id, permissions),
            true));
        CHECK_SUCCESSFUL_RESULT(execute(
            *mock_command_factory->constructAppendRole(account_id, role_id),
            true));
      }

      /**
       * Add one specific permission for account
       * @param perm - role permission to add
       * @param account_id - tester account_id, by default "id@domain"
       * @param role_id - name of the role for tester, by default "all"
       */
      void addOnePerm(
          const shared_model::interface::permissions::Role perm,
          const shared_model::interface::types::AccountIdType account_id =
              "id@domain",
          const shared_model::interface::types::RoleIdType role_id = "all") {
        shared_model::interface::RolePermissionSet permissions;
        permissions.set(perm);
        CHECK_SUCCESSFUL_RESULT(execute(
            *mock_command_factory->constructCreateRole(role_id, permissions),
            true));
        CHECK_SUCCESSFUL_RESULT(execute(
            *mock_command_factory->constructAppendRole(account_id, role_id),
            true));
      }

      /**
       * Add an asset and check command success
       */
      void addAsset(const std::string &name = "coin",
                    const std::string &domain = domain_id,
                    size_t precision = 1) {
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructCreateAsset(
                        name, domain, precision),
                    true));
      }

      /*
       * The functions below create common objects with default parameters
       * without any validation - specifically for SetUp methods
       */
      void createDefaultRole() {
        CHECK_SUCCESSFUL_RESULT(execute(
            *mock_command_factory->constructCreateRole(role, role_permissions),
            true));
      }

      void createDefaultDomain() {
        CHECK_SUCCESSFUL_RESULT(execute(
            *mock_command_factory->constructCreateDomain(domain_id, role),
            true));
      }

      void createDefaultAccount() {
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructCreateAccount(
                        name, domain_id, pubkey),
                    true));
      }

      const std::string role = "role";
      const std::string another_role = "role2";
      shared_model::interface::RolePermissionSet role_permissions;
      shared_model::interface::permissions::Grantable grantable_permission;
      shared_model::interface::types::AccountIdType account_id, name;
      PublicKeyHexStringView pubkey{"pubkey"sv};

      std::unique_ptr<shared_model::interface::Command> command;

      std::unique_ptr<CommandExecutor> executor;
      std::unique_ptr<WsvQuery> wsv_query;
      std::shared_ptr<MockPendingTransactionStorage> pending_txs_storage;

      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          query_response_factory;

      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter =
              std::make_shared<shared_model::proto::ProtoPermissionToString>();

      const shared_model::interface::Amount asset_amount_one_zero{"1.0"};

      std::unique_ptr<shared_model::interface::MockCommandFactory>
          mock_command_factory =
              std::make_unique<shared_model::interface::MockCommandFactory>();
    };

    class AddPeer : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        peer = makePeer("", kPublicKey);
        peer_with_cert = makePeer("", kPublicKey, "");
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
      }

      std::unique_ptr<MockPeer> peer;
      std::unique_ptr<MockPeer> peer_with_cert;
    };

    /**
     * @given command
     * @when trying to add peer
     * @then peer is successfully added
     */
    TEST_F(AddPeer, Valid) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddPeer(*peer_with_cert)));
    }

    /**
     * @given command
     * @when trying to add peer with a TLS cert
     * @then peer is successfully added
     */
    TEST_F(AddPeer, ValidWithCertificate) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddPeer(*peer)));
    }

    /**
     * @given command
     * @when trying to add peer without perms
     * @then peer is not added
     */
    TEST_F(AddPeer, NoPerms) {
      auto cmd_result = execute(*mock_command_factory->constructAddPeer(*peer));

      std::vector<std::string> query_args{peer->address(), peer->pubkey()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command, root permission
     * @when trying to add peer
     * @then peer is successfully added
     */
    TEST_F(AddPeer, ValidWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddPeer(*peer)));
    }

    class RemovePeer : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        peer = makePeer("address", kPublicKey);
        another_peer = makePeer("another_address", kPublicKey2);
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructAddPeer(*peer), true));
      }

      std::unique_ptr<MockPeer> peer, another_peer;
    };

    /**
     * @given command
     * @when trying to remove peer
     * @then peer is successfully removed
     */
    TEST_F(RemovePeer, Valid) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddPeer(*another_peer), true));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructRemovePeer(kPublicKey)));

      auto peers = wsv_query->getPeers(false);
      ASSERT_TRUE(peers);
      ASSERT_TRUE(std::find_if(peers->begin(),
                               peers->end(),
                               [this](const auto &peer) {
                                 return this->peer->address() == peer->address()
                                     and this->peer->pubkey() == peer->pubkey();
                               })
                  == peers->end());
    }

    /**
     * @given command
     * @when trying to remove peer without perms
     * @then peer is not removed
     */
    TEST_F(RemovePeer, NoPerms) {
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddPeer(*another_peer), true));
      auto cmd_result =
          execute(*mock_command_factory->constructRemovePeer(kPublicKey));

      std::vector<std::string> query_args{peer->pubkey()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command
     * @when trying to remove nonexistent peer
     * @then peer is not removed
     */
    TEST_F(RemovePeer, NoPeer) {
      addAllPermsWithoutRoot();
      auto cmd_result =
          execute(*mock_command_factory->constructRemovePeer(kPublicKey2));

      std::vector<std::string> query_args{another_peer->pubkey()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command
     * @when trying to remove nonexistent peer without validation
     * @then peer is not removed
     */
    TEST_F(RemovePeer, NoPeerWithoutValidation) {
      addAllPermsWithoutRoot();
      auto cmd_result = execute(
          *mock_command_factory->constructRemovePeer(kPublicKey2), true);

      std::vector<std::string> query_args{another_peer->pubkey()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 1, query_args);
    }

    /**
     * @given command
     * @when trying to remove the only peer in the list
     * @then peer is not removed
     */
    TEST_F(RemovePeer, LastPeer) {
      addAllPermsWithoutRoot();
      auto cmd_result =
          execute(*mock_command_factory->constructRemovePeer(kPublicKey));

      std::vector<std::string> query_args{peer->pubkey()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    /**
     * @given command, root permission
     * @when trying to remove peer
     * @then peer is successfully removed
     */
    TEST_F(RemovePeer, ValidWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddPeer(*another_peer), true));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructRemovePeer(kPublicKey)));

      auto peers = wsv_query->getPeers(false);
      ASSERT_TRUE(peers);
      ASSERT_TRUE(std::find_if(peers->begin(),
                               peers->end(),
                               [this](const auto &peer) {
                                 return this->peer->address() == peer->address()
                                     and this->peer->pubkey() == peer->pubkey();
                               })
                  == peers->end());
    }

    TEST_F(RemovePeer, ValidWithAddPerm) {
      addOnePerm(shared_model::interface::permissions::Role::kAddPeer);
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddPeer(*another_peer), true));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructRemovePeer(kPublicKey)));

      auto peers = wsv_query->getPeers(false);
      ASSERT_TRUE(peers);
      ASSERT_TRUE(std::find_if(peers->begin(),
                               peers->end(),
                               [this](const auto &peer) {
                                 return this->peer->address() == peer->address()
                                     and this->peer->pubkey() == peer->pubkey();
                               })
                  == peers->end());
    }

    class AppendRole : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
      }
      shared_model::interface::RolePermissionSet role_permissions2;
    };

    /**
     * @given command
     * @when trying to append role
     * @then role is appended
     */
    TEST_F(AppendRole, Valid) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateRole(another_role,
                                                             role_permissions),
                  true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAppendRole(account_id,
                                                             another_role)));
      auto roles = sql_query->getAccountRoles(account_id);
      ASSERT_TRUE(roles);
      ASSERT_TRUE(std::find(roles->begin(), roles->end(), another_role)
                  != roles->end());
    }

    /**
     * @given command
     * @when trying append role, which does not have any permissions
     * @then role is appended
     */
    TEST_F(AppendRole, ValidEmptyPerms) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateRole(another_role, {}), true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAppendRole(account_id,
                                                             another_role)));
      auto roles = sql_query->getAccountRoles(account_id);
      ASSERT_TRUE(roles);
      ASSERT_TRUE(std::find(roles->begin(), roles->end(), another_role)
                  != roles->end());
    }

    /**
     * @given command
     * @when trying to append role with perms that creator does not have but in
     * genesis block
     * @then role is appended
     */
    TEST_F(AppendRole, AccountDoesNotHavePermsGenesis) {
      role_permissions2.set(
          shared_model::interface::permissions::Role::kRemoveMySignatory);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateRole(another_role,
                                                             role_permissions2),
                  true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAppendRole(account_id, another_role),
          true));
      auto roles = sql_query->getAccountRoles(account_id);
      ASSERT_TRUE(roles);
      ASSERT_TRUE(std::find(roles->begin(), roles->end(), another_role)
                  != roles->end());
    }

    /**
     * @given command
     * @when trying to append role having no permission to do so
     * @then role is not appended
     */
    TEST_F(AppendRole, NoPerms) {
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateRole(another_role,
                                                             role_permissions),
                  true));
      auto cmd_result = execute(
          *mock_command_factory->constructAppendRole(account_id, another_role));

      std::vector<std::string> query_args{account_id, another_role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);

      auto roles = sql_query->getAccountRoles(account_id);
      ASSERT_TRUE(roles);
      ASSERT_TRUE(std::find(roles->begin(), roles->end(), another_role)
                  == roles->end());
    }

    /**
     * @given command
     * @when trying to append role with perms that creator does not have
     * @then role is not appended
     */
    TEST_F(AppendRole, NoRolePermsInAccount) {
      role_permissions2.set(
          shared_model::interface::permissions::Role::kRemoveMySignatory);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateRole(another_role,
                                                             role_permissions2),
                  true));
      auto cmd_result = execute(
          *mock_command_factory->constructAppendRole(account_id, another_role));

      std::vector<std::string> query_args{account_id, another_role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command
     * @when trying to append role to non-existing account
     * @then role is not appended
     */
    TEST_F(AppendRole, NoAccount) {
      addAllPermsWithoutRoot();
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateRole(another_role, {}), true));
      auto cmd_result = execute(*mock_command_factory->constructAppendRole(
          "doge@noaccount", another_role));

      std::vector<std::string> query_args{"doge@noaccount", another_role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command
     * @when trying to append non-existing role
     * @then role is not appended
     */
    TEST_F(AppendRole, NoRole) {
      addAllPermsWithoutRoot();
      auto cmd_result = execute(
          *mock_command_factory->constructAppendRole(account_id, another_role));

      std::vector<std::string> query_args{account_id, another_role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    /**
     * @given command, root permission
     * @when trying to append role
     * @then role is appended
     */
    TEST_F(AppendRole, ValidWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateRole(another_role,
                                                             role_permissions),
                  true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAppendRole(account_id,
                                                             another_role)));
      auto roles = sql_query->getAccountRoles(account_id);
      ASSERT_TRUE(roles);
      ASSERT_TRUE(std::find(roles->begin(), roles->end(), another_role)
                  != roles->end());
    }

    /**
     * @given command, root permission
     * @when trying to append role with perms that creator does not have
     * @then role is appended
     */
    TEST_F(AppendRole, NoRolePermsInAccountWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);
      role_permissions2.set(
          shared_model::interface::permissions::Role::kRemoveMySignatory);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateRole(another_role,
                                                             role_permissions2),
                  true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAppendRole(account_id,
                                                             another_role)));
      auto roles = sql_query->getAccountRoles(account_id);
      ASSERT_TRUE(roles);
      ASSERT_TRUE(std::find(roles->begin(), roles->end(), another_role)
                  != roles->end());
    }

    class CreateAsset : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
      }
      shared_model::interface::types::AssetIdType asset_name = "coin";
      shared_model::interface::types::AssetIdType asset_id =
          "coin#" + domain_id;
    };

    /**
     * @given command
     * @when trying to create asset
     * @then asset is created
     */
    TEST_F(CreateAsset, Valid) {
      role_permissions.set(
          shared_model::interface::permissions::Role::kCreateAsset);
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateRole(role, role_permissions),
          true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateDomain(domain_id, role), true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateAccount(
                      name, domain_id, pubkey),
                  true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateAsset("coin", domain_id, 1)));
      auto asset = sql_query->getAsset(asset_id);
      ASSERT_TRUE(asset);
      ASSERT_EQ(asset_id, asset.get()->assetId());
    }

    /**
     * @given command
     * @when trying to create asset without permission
     * @then asset is not created
     */
    TEST_F(CreateAsset, NoPerms) {
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateRole(role, role_permissions),
          true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateDomain(domain_id, role), true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateAccount(
                      name, domain_id, pubkey),
                  true));
      auto cmd_result = execute(
          *mock_command_factory->constructCreateAsset("coin", domain_id, 1));
      auto asset = sql_query->getAsset(asset_id);
      ASSERT_FALSE(asset);

      std::vector<std::string> query_args{domain_id, "coin", "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command and no target domain in ledger
     * @when trying to create asset
     * @then asset is not created
     */
    TEST_F(CreateAsset, NoDomain) {
      role_permissions.set(
          shared_model::interface::permissions::Role::kCreateAsset);
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateRole(role, role_permissions),
          true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateDomain(domain_id, role), true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateAccount(
                      name, domain_id, pubkey),
                  true));
      auto cmd_result = execute(*mock_command_factory->constructCreateAsset(
          asset_name, "no_domain", 1));

      std::vector<std::string> query_args{asset_name, "no_domain", "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command
     * @when trying to create asset with an occupied name
     * @then asset is not created
     */
    TEST_F(CreateAsset, NameNotUnique) {
      role_permissions.set(
          shared_model::interface::permissions::Role::kCreateAsset);
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateRole(role, role_permissions),
          true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateDomain(domain_id, role), true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateAccount(
                      name, domain_id, pubkey),
                  true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateAsset("coin", domain_id, 1)));
      auto cmd_result = execute(
          *mock_command_factory->constructCreateAsset("coin", domain_id, 1));

      std::vector<std::string> query_args{"coin", domain_id, "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    /**
     * @given command, root permission
     * @when trying to create asset
     * @then asset is created
     */
    TEST_F(CreateAsset, ValidWithRoot) {
      role_permissions.set(shared_model::interface::permissions::Role::kRoot);
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateRole(role, role_permissions),
          true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateDomain(domain_id, role), true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateAccount(
                      name, domain_id, pubkey),
                  true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateAsset("coin", domain_id, 1)));
      auto asset = sql_query->getAsset(asset_id);
      ASSERT_TRUE(asset);
      ASSERT_EQ(asset_id, asset.get()->assetId());
    }

    class CreateDomain : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        domain2_id = "domain2";
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
      }

      shared_model::interface::types::DomainIdType domain2_id;
    };

    /**
     * @given command
     * @when trying to create domain
     * @then domain is created
     */
    TEST_F(CreateDomain, Valid) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateDomain(domain2_id, role)));
      auto dom = sql_query->getDomain(domain2_id);
      ASSERT_TRUE(dom);
      ASSERT_EQ(dom.get()->domainId(), domain2_id);
    }

    /**
     * @given command when there is no perms
     * @when trying to create domain
     * @then domain is not created
     */
    TEST_F(CreateDomain, NoPerms) {
      auto cmd_result = execute(
          *mock_command_factory->constructCreateDomain(domain2_id, role));
      auto dom = sql_query->getDomain(domain2_id);
      ASSERT_FALSE(dom);

      std::vector<std::string> query_args{domain2_id, role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command
     * @when trying to create domain with an occupied name
     * @then domain is not created
     */
    TEST_F(CreateDomain, NameNotUnique) {
      addAllPermsWithoutRoot();
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateDomain(domain2_id, role)));
      auto cmd_result = execute(
          *mock_command_factory->constructCreateDomain(domain2_id, role));

      std::vector<std::string> query_args{domain2_id, role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command when there is no default role
     * @when trying to create domain
     * @then domain is not created
     */
    TEST_F(CreateDomain, NoDefaultRole) {
      addAllPermsWithoutRoot();
      auto cmd_result = execute(*mock_command_factory->constructCreateDomain(
          domain2_id, another_role));

      std::vector<std::string> query_args{domain2_id, another_role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    /**
     * @given command, root permission
     * @when trying to create domain
     * @then domain is created
     */
    TEST_F(CreateDomain, ValidWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateDomain(domain2_id, role)));
      auto dom = sql_query->getDomain(domain2_id);
      ASSERT_TRUE(dom);
      ASSERT_EQ(dom.get()->domainId(), domain2_id);
    }

    class DetachRole : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();

        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructCreateRole(
                        another_role, role_permissions),
                    true));
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructAppendRole(account_id,
                                                               another_role),
                    true));
      }
    };

    /**
     * @given command
     * @when trying to detach role
     * @then role is detached
     */
    TEST_F(DetachRole, Valid) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructDetachRole(account_id,
                                                             another_role)));
      auto roles = sql_query->getAccountRoles(account_id);
      ASSERT_TRUE(roles);
      ASSERT_TRUE(std::find(roles->begin(), roles->end(), another_role)
                  == roles->end());
    }

    /**
     * @given command
     * @when trying to detach role without permission
     * @then role is detached
     */
    TEST_F(DetachRole, NoPerms) {
      auto cmd_result = execute(
          *mock_command_factory->constructDetachRole(account_id, another_role));

      std::vector<std::string> query_args{account_id, another_role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);

      auto roles = sql_query->getAccountRoles(account_id);
      ASSERT_TRUE(roles);
      ASSERT_TRUE(std::find(roles->begin(), roles->end(), another_role)
                  != roles->end());
    }

    /**
     * @given command
     * @when trying to detach role from non-existing account
     * @then correspondent error code is returned
     */
    TEST_F(DetachRole, NoAccount) {
      addAllPermsWithoutRoot();
      auto cmd_result = execute(*mock_command_factory->constructDetachRole(
          "doge@noaccount", another_role));

      std::vector<std::string> query_args{"doge@noaccount", another_role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command
     * @when trying to detach role, which the account does not have
     * @then correspondent error code is returned
     */
    TEST_F(DetachRole, NoSuchRoleInAccount) {
      addAllPermsWithoutRoot();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructDetachRole(account_id,
                                                             another_role)));
      auto cmd_result = execute(
          *mock_command_factory->constructDetachRole(account_id, another_role));

      std::vector<std::string> query_args{account_id, another_role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    /**
     * @given command
     * @when trying to detach a non-existing role
     * @then correspondent error code is returned
     */
    TEST_F(DetachRole, NoRole) {
      addAllPermsWithoutRoot();
      auto cmd_result = execute(*mock_command_factory->constructDetachRole(
          account_id, "not_existing_role"));

      std::vector<std::string> query_args{account_id, "not_existing_role"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 5, query_args);
    }

    /**
     * @given command, root permission
     * @when trying to detach role
     * @then role is detached
     */
    TEST_F(DetachRole, ValidWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructDetachRole(account_id,
                                                             another_role)));
      auto roles = sql_query->getAccountRoles(account_id);
      ASSERT_TRUE(roles);
      ASSERT_TRUE(std::find(roles->begin(), roles->end(), another_role)
                  == roles->end());
    }

    class GrantPermission : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructCreateRole(
                        another_role, role_permissions),
                    true));
      }
    };

    /**
     * @given command
     * @when trying to grant permission
     * @then permission is granted
     */
    TEST_F(GrantPermission, Valid) {
      addAllPerms();
      auto perm = shared_model::interface::permissions::Grantable::kSetMyQuorum;
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructGrantPermission(account_id, perm)));
      auto has_perm = sql_query->hasAccountGrantablePermission(
          account_id, account_id, perm);
      ASSERT_TRUE(has_perm);
    }

    /**
     * @given command
     * @when trying to grant permission without permission
     * @then permission is not granted
     */
    TEST_F(GrantPermission, NoPerms) {
      auto perm = shared_model::interface::permissions::Grantable::kSetMyQuorum;
      auto cmd_result = execute(
          *mock_command_factory->constructGrantPermission(account_id, perm));
      auto has_perm = sql_query->hasAccountGrantablePermission(
          account_id, account_id, perm);
      ASSERT_FALSE(has_perm);

      std::vector<std::string> query_args{account_id,
                                          perm_converter->toString(perm)};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command
     * @when trying to grant permission to non-existent account
     * @then corresponding error code is returned
     */
    TEST_F(GrantPermission, NoAccount) {
      addAllPermsWithoutRoot();
      auto perm = shared_model::interface::permissions::Grantable::kSetMyQuorum;
      auto cmd_result = execute(*mock_command_factory->constructGrantPermission(
          "doge@noaccount", perm));

      std::vector<std::string> query_args{"doge@noaccount",
                                          perm_converter->toString(perm)};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command, root permission
     * @when trying to grant permission
     * @then permission is granted
     */
    TEST_F(GrantPermission, ValidWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);
      auto perm = shared_model::interface::permissions::Grantable::kSetMyQuorum;
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructGrantPermission(account_id, perm)));
      auto has_perm = sql_query->hasAccountGrantablePermission(
          account_id, account_id, perm);
      ASSERT_TRUE(has_perm);
    }

    class RevokePermission : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructGrantPermission(
                        account_id, grantable_permission),
                    true));
      }
    };

    /**
     * @given command
     * @when trying to revoke permission
     * @then permission is revoked
     */
    TEST_F(RevokePermission, Valid) {
      auto perm =
          shared_model::interface::permissions::Grantable::kRemoveMySignatory;
      ASSERT_TRUE(sql_query->hasAccountGrantablePermission(
          account_id, account_id, grantable_permission));

      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructGrantPermission(account_id, perm),
          true));
      ASSERT_TRUE(sql_query->hasAccountGrantablePermission(
          account_id, account_id, grantable_permission));
      ASSERT_TRUE(sql_query->hasAccountGrantablePermission(
          account_id, account_id, perm));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructRevokePermission(
              account_id, grantable_permission)));
      ASSERT_FALSE(sql_query->hasAccountGrantablePermission(
          account_id, account_id, grantable_permission));
      ASSERT_TRUE(sql_query->hasAccountGrantablePermission(
          account_id, account_id, perm));
    }

    /**
     * @given command
     * @when trying to revoke permission without permission
     * @then permission is revoked
     */
    TEST_F(RevokePermission, NoPerms) {
      auto perm =
          shared_model::interface::permissions::Grantable::kRemoveMySignatory;
      auto cmd_result = execute(
          *mock_command_factory->constructRevokePermission(account_id, perm));

      std::vector<std::string> query_args{account_id,
                                          perm_converter->toString(perm)};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    class SetQuorum : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructAddSignatory(kPublicKey2,
                                                                 account_id),
                    true));
      }
    };

    /**
     * @given command
     * @when trying to set quorum
     * @then quorum is set
     */
    TEST_F(SetQuorum, Valid) {
      addAllPerms();

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSetQuorum(account_id, 2)));
    }

    /**
     * @given command
     * @when trying to set quorum
     * @then quorum is set
     */
    TEST_F(SetQuorum, ValidGrantablePerms) {
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateAccount(
                      "id2", domain_id, pubkey),
                  true));
      auto perm = shared_model::interface::permissions::Grantable::kSetMyQuorum;
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructGrantPermission(account_id, perm),
          true,
          "id2@domain"));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddSignatory(kPublicKey2,
                                                               "id2@domain"),
                  true,
                  "id2@domain"));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSetQuorum("id2@domain", 2)));
    }

    /**
     * @given command
     * @when trying to set quorum without perms
     * @then quorum is not set
     */
    TEST_F(SetQuorum, NoPerms) {
      auto cmd_result =
          execute(*mock_command_factory->constructSetQuorum(account_id, 3));

      std::vector<std::string> query_args{account_id, "3"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command
     * @when trying to set quorum more than amount of signatories
     * @then quorum is not set
     */
    TEST_F(SetQuorum, LessSignatoriesThanNewQuorum) {
      addAllPermsWithoutRoot();
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(kPublicKey, account_id),
          true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSetQuorum(account_id, 3)));

      auto cmd_result =
          execute(*mock_command_factory->constructSetQuorum(account_id, 5));

      std::vector<std::string> query_args{account_id, "5"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 5, query_args);
    }

    /**
     * @given command, root permission
     * @when trying to set quorum
     * @then quorum is set
     */
    TEST_F(SetQuorum, ValidWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSetQuorum(account_id, 2)));
    }

    class SubtractAccountAssetTest : public CommandExecutorTest {
      void SetUp() override {
        CommandExecutorTest::SetUp();
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
      }

     public:
      shared_model::interface::types::AssetIdType asset_id =
          "coin#" + domain_id;
    };

    /**
     * @given command
     * @when trying to subtract account asset
     * @then account asset is successfully subtracted
     */
    TEST_F(SubtractAccountAssetTest, Valid) {
      addAllPerms();
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ("2.0", account_asset.get()->balance().toStringRepr());
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSubtractAssetQuantity(
              asset_id, asset_amount_one_zero)));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
    }

    /**
     * @given command
     * @when trying to subtract account asset without permissions
     * @then corresponding error code is returned
     */
    TEST_F(SubtractAccountAssetTest, NoPerms) {
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());

      auto cmd_result =
          execute(*mock_command_factory->constructSubtractAssetQuantity(
              asset_id, asset_amount_one_zero));

      std::vector<std::string> query_args{
          account_id, asset_id, asset_amount_one_zero.toStringRepr(), "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);

      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
    }

    /**
     * @given command and domain permission
     * @when trying to subtract account asset
     * @then account asset is successfully subtracted
     */
    TEST_F(SubtractAccountAssetTest, DomainPermValid) {
      addAsset();
      addOnePerm(
          shared_model::interface::permissions::Role::kSubtractDomainAssetQty);

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));

      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));

      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ("2.0", account_asset.get()->balance().toStringRepr());

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSubtractAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));

      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
    }

    /**
     * @given command and invalid domain permission/ permission in other domain
     * @when trying to subtract asset
     * @then no account asset is subtracted
     */
    TEST_F(SubtractAccountAssetTest, DomainPermInvalid) {
      shared_model::interface::types::DomainIdType domain2_id = "domain2";
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateDomain(domain2_id, role),
          true));
      addAsset("coin", domain2_id, 1);
      addOnePerm(
          shared_model::interface::permissions::Role::kSubtractDomainAssetQty);

      auto asset2_id = "coin#" + domain2_id;
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset2_id, asset_amount_one_zero),
                  true));
      auto account_asset = sql_query->getAccountAsset(account_id, asset2_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());

      auto cmd_result =
          execute(*mock_command_factory->constructSubtractAssetQuantity(
              asset2_id, asset_amount_one_zero));

      std::vector<std::string> query_args{
          account_id, asset2_id, asset_amount_one_zero.toStringRepr(), "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);

      account_asset = sql_query->getAccountAsset(account_id, asset2_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
    }

    /**
     * @given command
     * @when trying to subtract account asset with non-existing asset
     * @then account asset fails to be subtracted
     */
    TEST_F(SubtractAccountAssetTest, NoAsset) {
      addAllPermsWithoutRoot();
      auto cmd_result =
          execute(*mock_command_factory->constructSubtractAssetQuantity(
              asset_id, asset_amount_one_zero));

      std::vector<std::string> query_args{
          account_id, asset_id, asset_amount_one_zero.toStringRepr(), "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command
     * @when trying to add account asset with wrong precision
     * @then account asset fails to be added
     */
    TEST_F(SubtractAccountAssetTest, InvalidPrecision) {
      addAllPermsWithoutRoot();
      addAsset();
      auto cmd_result =
          execute(*mock_command_factory->constructSubtractAssetQuantity(
              asset_id, shared_model::interface::Amount{"1.0000"}));

      std::vector<std::string> query_args{account_id, asset_id, "1.0000", "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command
     * @when trying to subtract more account asset than account has
     * @then account asset fails to be subtracted
     */
    TEST_F(SubtractAccountAssetTest, NotEnoughAsset) {
      addAllPermsWithoutRoot();
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      auto cmd_result =
          execute(*mock_command_factory->constructSubtractAssetQuantity(
              asset_id, shared_model::interface::Amount{"2.0"}));

      std::vector<std::string> query_args{account_id, asset_id, "2.0", "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    /**
     * @given command, root permission
     * @when trying to subtract account asset
     * @then account asset is successfully subtracted
     */
    TEST_F(SubtractAccountAssetTest, ValidWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ("2.0", account_asset.get()->balance().toStringRepr());
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSubtractAssetQuantity(
              asset_id, asset_amount_one_zero)));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
    }

    class TransferAccountAssetTest : public CommandExecutorTest {
      void SetUp() override {
        CommandExecutorTest::SetUp();

        account2_id = "id2@" + domain_id;

        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructCreateAccount(
                        "id2", domain_id, pubkey),
                    true));
      }

     public:
      using Amount = shared_model::interface::Amount;

      void transferAndCheckError(const std::string &from,
                                 const std::string &to,
                                 const std::string &quantity,
                                 CommandError::ErrorCodeType code) {
        static const std::string tx_description("some description");
        auto cmd = mock_command_factory->constructTransferAsset(
            from, to, asset_id, tx_description, Amount{quantity});
        auto result = execute(*cmd, true);
        std::vector<std::string> query_args{
            from, to, asset_id, quantity, quantity};
        CHECK_ERROR_CODE_AND_MESSAGE(result, code, query_args);
      }

      shared_model::interface::types::AssetIdType asset_id =
          "coin#" + domain_id;
      shared_model::interface::types::AccountIdType account2_id;
    };

    /**
     * @given command
     * @when trying to add transfer asset
     * @then account asset is successfully transferred
     */
    TEST_F(TransferAccountAssetTest, Valid) {
      addAllPerms();
      addAllPerms(account2_id, "all2");
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ("2.0", account_asset.get()->balance().toStringRepr());
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructTransferAsset(
              account_id,
              account2_id,
              asset_id,
              "desc",
              asset_amount_one_zero)));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
      account_asset = sql_query->getAccountAsset(account2_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
    }

    /**
     * @given command
     * @when trying to add transfer asset
     * @then account asset is successfully transferred
     */
    TEST_F(TransferAccountAssetTest, ValidGrantablePerms) {
      addAllPermsWithoutRoot(account2_id, "all2");
      addAsset();
      auto perm =
          shared_model::interface::permissions::Grantable::kTransferMyAssets;
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructGrantPermission(account2_id, perm),
          true,
          account_id));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, shared_model::interface::Amount{"2.0"}),
                  true));
      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ("2.0", account_asset.get()->balance().toStringRepr());
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructTransferAsset(
              account_id, account2_id, asset_id, "desc", asset_amount_one_zero),
          false,
          account2_id));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
      account_asset = sql_query->getAccountAsset(account2_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
    }

    /**
     * @given command
     * @when trying to transfer account asset with no permissions
     * @then account asset fails to be transferred
     */
    TEST_F(TransferAccountAssetTest, NoPerms) {
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());

      auto cmd_result = execute(*mock_command_factory->constructTransferAsset(
          account_id, account2_id, asset_id, "desc", asset_amount_one_zero));

      std::vector<std::string> query_args{account_id,
                                          account2_id,
                                          asset_id,
                                          asset_amount_one_zero.toStringRepr(),
                                          "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command
     * @when trying to transfer asset back and forth with non-existing account
     * @then account asset fails to be transferred
     */
    TEST_F(TransferAccountAssetTest, NoAccount) {
      addAllPermsWithoutRoot();
      addAllPermsWithoutRoot(account2_id, "all2");
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, shared_model::interface::Amount{"0.1"}),
                  true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      auto cmd_result = execute(
          *mock_command_factory->constructTransferAsset("some@domain",
                                                        account2_id,
                                                        asset_id,
                                                        "desc",
                                                        asset_amount_one_zero),
          true);

      {
        std::vector<std::string> query_args{
            "some@domain",
            account2_id,
            asset_id,
            asset_amount_one_zero.toStringRepr(),
            "1"};
        CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
      }

      cmd_result = execute(
          *mock_command_factory->constructTransferAsset(account_id,
                                                        "some@domain",
                                                        asset_id,
                                                        "desc",
                                                        asset_amount_one_zero),
          true);

      {
        std::vector<std::string> query_args{
            account_id,
            "some@domain",
            asset_id,
            asset_amount_one_zero.toStringRepr(),
            "1"};
        CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
      }
    }

    /**
     * @given command
     * @when trying to transfer account asset with non-existing asset
     * @then account asset fails to be transferred
     */
    TEST_F(TransferAccountAssetTest, NoAsset) {
      addAllPermsWithoutRoot();
      addAllPermsWithoutRoot(account2_id, "all2");
      auto cmd_result = execute(*mock_command_factory->constructTransferAsset(
          account_id, account2_id, asset_id, "desc", asset_amount_one_zero));

      std::vector<std::string> query_args{account_id,
                                          account2_id,
                                          asset_id,
                                          asset_amount_one_zero.toStringRepr(),
                                          "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 5, query_args);
    }

    /**
     * @given command
     * @when trying to transfer asset that the transmitter does not posess
     * @then account asset fails to be transferred
     */
    TEST_F(TransferAccountAssetTest, NoSrcAsset) {
      addAllPermsWithoutRoot();
      addAllPermsWithoutRoot(account2_id, "all2");
      addAsset();
      auto cmd_result = execute(*mock_command_factory->constructTransferAsset(
          account_id, account2_id, asset_id, "desc", asset_amount_one_zero));

      std::vector<std::string> query_args{account_id,
                                          account2_id,
                                          asset_id,
                                          asset_amount_one_zero.toStringRepr(),
                                          "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 6, query_args);
    }

    /**
     * @given command
     * @when transfer an asset which the receiver already has
     * @then account asset is successfully transferred
     */
    TEST_F(TransferAccountAssetTest, DestHasAsset) {
      addAllPermsWithoutRoot();
      addAllPermsWithoutRoot(account2_id, "all2");
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, shared_model::interface::Amount{"0.1"}),
                  true,
                  account2_id));
      auto cmd_result = execute(*mock_command_factory->constructTransferAsset(
          account_id, account2_id, asset_id, "desc", asset_amount_one_zero));

      auto account_asset = sql_query->getAccountAsset(account2_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(account_asset.get()->balance(),
                shared_model::interface::Amount{"1.1"});
    }

    /**
     * @given command
     * @when trying to transfer account asset, but has insufficient amount of it
     * @then account asset fails to be transferred
     */
    TEST_F(TransferAccountAssetTest, Overdraft) {
      addAllPermsWithoutRoot();
      addAllPermsWithoutRoot(account2_id, "all2");
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      auto cmd_result = execute(*mock_command_factory->constructTransferAsset(
          account_id,
          account2_id,
          asset_id,
          "desc",
          shared_model::interface::Amount{"2.0"}));

      std::vector<std::string> query_args{
          account_id, account2_id, asset_id, "2.0", "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 6, query_args);
    }

    /**
     * @given two users with all required permissions, one having the maximum
     * allowed quantity of an asset with precision 1
     * @when execute a tx from another user with TransferAsset command for that
     * asset with the smallest possible quantity and then with a lower one
     * @then the last 2 transactions are not committed
     */
    TEST_F(TransferAccountAssetTest, DestOverflowPrecision1) {
      addAllPermsWithoutRoot();
      addAllPermsWithoutRoot(account2_id, "all2");
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, Amount{"10"}),
                  true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, kAmountPrec1Max),
                  false,
                  account2_id));

      transferAndCheckError(account_id, account2_id, "0.1", 7);
      transferAndCheckError(account_id, account2_id, "1", 7);
    }

    /**
     * @given two users with all required permissions, one having the maximum
     * allowed quantity of an asset with precision 2
     * @when execute a tx from another user with TransferAsset command for that
     * asset with the smallest possible quantity and then with a lower one
     * @then last 2 transactions are not committed
     */
    TEST_F(TransferAccountAssetTest, DestOverflowPrecision2) {
      addAllPermsWithoutRoot();
      addAllPermsWithoutRoot(account2_id, "all2");
      addAsset("coin", domain_id, 2);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, Amount{"1.0"}),
                  true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, kAmountPrec2Max),
                  false,
                  account2_id));

      transferAndCheckError(account_id, account2_id, "0.01", 7);
      transferAndCheckError(account_id, account2_id, "0.1", 7);
    }

    /**
     * @given command, root permission
     * @when trying to add transfer asset
     * @then account asset is successfully transferred
     */
    TEST_F(TransferAccountAssetTest, ValidWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);
      addAllPermsWithoutRoot(account2_id, "all2");
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ("2.0", account_asset.get()->balance().toStringRepr());
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructTransferAsset(
              account_id,
              account2_id,
              asset_id,
              "desc",
              asset_amount_one_zero)));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
      account_asset = sql_query->getAccountAsset(account2_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
    }

    /**
     * @given command
     * @when trying to add transfer asset to account with root permission
     * @then account asset is successfully transferred
     */
    TEST_F(TransferAccountAssetTest, DestWithRoot) {
      addAllPermsWithoutRoot();
      addOnePerm(shared_model::interface::permissions::Role::kRoot,
                 account2_id,
                 "all2");
      addAsset();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ("2.0", account_asset.get()->balance().toStringRepr());
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructTransferAsset(
              account_id,
              account2_id,
              asset_id,
              "desc",
              asset_amount_one_zero)));
      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
      account_asset = sql_query->getAccountAsset(account2_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());
    }

    class CompareAndSetAccountDetail : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
        account2_id = "id2@" + domain_id;
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructCreateAccount(
                        "id2", domain_id, kPublicKey2),
                    true));
      }
      shared_model::interface::types::AccountIdType account2_id;
    };

    /**
     * @given command
     * @when trying to set kv
     * @then kv is set
     */
    TEST_F(CompareAndSetAccountDetail, Valid) {
      addOnePerm(shared_model::interface::permissions::Role::kGetMyAccDetail);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id, "key", "value", std::nullopt, true)));
      auto kv = sql_query->getAccountDetail(account_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), R"({"id@domain": {"key": "value"}})");
    }

    /**
     * @given command
     * @when trying to set kv when has grantable permission
     * @then kv is set
     */
    TEST_F(CompareAndSetAccountDetail, ValidGrantablePerm) {
      addOnePerm(
          shared_model::interface::permissions::Role::kGetDomainAccDetail);
      auto perm =
          shared_model::interface::permissions::Grantable::kSetMyAccountDetail;
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructGrantPermission(account_id, perm),
          true,
          account2_id));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
                      account2_id, "key", "value", std::nullopt, true),
                  false,
                  account_id));
      auto kv = sql_query->getAccountDetail(account2_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), R"({"id@domain": {"key": "value"}})");
    }

    /**
     * @given command
     * @when trying to set kv when has role permission
     * @then kv is set
     */
    TEST_F(CompareAndSetAccountDetail, ValidRolePerm) {
      addAllPermsWithoutRoot();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
                      account2_id, "key", "value", std::nullopt, true),
                  false,
                  account_id));
      auto kv = sql_query->getAccountDetail(account2_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), R"({"id@domain": {"key": "value"}})");
    }

    /**
     * @given command
     * @when trying to set kv while having no permissions
     * @then corresponding error code is returned
     */
    TEST_F(CompareAndSetAccountDetail, NoPerms) {
      auto cmd_result =
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
                      account2_id, "key", "value", std::nullopt, true),
                  false,
                  account_id);

      std::vector<std::string> query_args{account2_id, "key", "value"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);

      auto kv = sql_query->getAccountDetail(account2_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), "{}");
    }

    /**
     * @given command
     * @when trying to set kv to non-existing account
     * @then corresponding error code is returned
     */
    TEST_F(CompareAndSetAccountDetail, NoAccount) {
      addAllPermsWithoutRoot();
      auto cmd_result =
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
                      "doge@noaccount", "key", "value", std::nullopt, true),
                  false,
                  account_id);

      std::vector<std::string> query_args{"doge@noaccount", "key", "value"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command
     * @when trying to set kv and then set kv1 with correct old value
     * @then kv1 is set
     */
    TEST_F(CompareAndSetAccountDetail, ValidOldValue) {
      addOnePerm(shared_model::interface::permissions::Role::kGetMyAccDetail);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id, "key", "value", std::nullopt, true)));

      auto kv = sql_query->getAccountDetail(account_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), R"({"id@domain": {"key": "value"}})");

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id,
              "key",
              "value1",
              std::optional<
                  shared_model::interface::types::AccountDetailValueType>(
                  "value"),
              true)));
      auto kv1 = sql_query->getAccountDetail(account_id);
      ASSERT_TRUE(kv1);
      ASSERT_EQ(kv1.get(), R"({"id@domain": {"key": "value1"}})");
    }

    /**
     * @given command
     * @when trying to set kv and then set kv1 with incorrect old value
     * @then corresponding error code is returned
     */
    TEST_F(CompareAndSetAccountDetail, InvalidOldValue) {
      addOnePerm(shared_model::interface::permissions::Role::kGetMyAccDetail);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id, "key", "value", std::nullopt, true)));

      auto kv = sql_query->getAccountDetail(account_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), R"({"id@domain": {"key": "value"}})");

      auto cmd_result =
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id,
              "key",
              "value1",
              std::optional<
                  shared_model::interface::types::AccountDetailValueType>(
                  "oldValue"),
              true));

      std::vector<std::string> query_args{
          account_id, "key", "value1", "oldValue"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    /**
     * @given Two commands
     * @when trying to set kv and then set k1v1
     * @then kv and k1v1 are set
     */
    TEST_F(CompareAndSetAccountDetail, DifferentKeys) {
      addOnePerm(shared_model::interface::permissions::Role::kGetMyAccDetail);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id, "key", "value", std::nullopt, true)));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id, "key1", "value1", std::nullopt, true)));

      auto ad = sql_query->getAccountDetail(account_id);
      ASSERT_TRUE(ad);
      ASSERT_EQ(ad.get(),
                R"({"id@domain": {"key": "value", "key1": "value1"}})");
    }

    /**
     * @given commands
     * @when trying to set kv without oldValue where v is empty string
     * @then corresponding error code is returned
     */
    TEST_F(CompareAndSetAccountDetail, EmptyDetail) {
      addOnePerm(shared_model::interface::permissions::Role::kGetMyAccDetail);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id, "key", "", std::nullopt, true)));

      auto cmd_result =
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id, "key", "value", std::nullopt, true));

      std::vector<std::string> query_args{account_id, "key", "value"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    /**
     * @given commands
     * @when trying to set new kv with not empty oldValue
     * @then corresponding error code is returned
     */
    TEST_F(CompareAndSetAccountDetail, NewDetailWithNotEmptyOldValue) {
      addOnePerm(shared_model::interface::permissions::Role::kGetMyAccDetail);

      auto cmd_result =
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id,
              "key",
              "value",
              std::optional<
                  shared_model::interface::types::AccountDetailValueType>(
                  "notEmptyOldValue"),
              true));

      std::vector<std::string> query_args{
          account_id, "key", "value", "notEmptyOldValue"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    /**
     * @given no old account detail value
     * @when trying to set new kv with not empty oldValue in legacy mode
     * @then the new value is set despite expected old value does not match
     */
    TEST_F(CompareAndSetAccountDetail, NewDetailWithNotEmptyOldValueLegacy) {
      addOnePerm(shared_model::interface::permissions::Role::kGetMyAccDetail);

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id,
              "key",
              "value",
              std::optional<
                  shared_model::interface::types::AccountDetailValueType>(
                  "notEmptyOldValue"),
              false)));

      auto kv1 = sql_query->getAccountDetail(account_id);
      ASSERT_TRUE(kv1);
      ASSERT_EQ(kv1.get(), R"({"id@domain": {"key": "value"}})");
    }

    /**
     * @given command, root permission
     * @when trying to set kv
     * @then kv is set
     */
    TEST_F(CompareAndSetAccountDetail, ValidWithRoot) {
      addOnePerm(shared_model::interface::permissions::Role::kRoot);
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id, "key", "value", std::nullopt, true)));
      auto kv = sql_query->getAccountDetail(account_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), R"({"id@domain": {"key": "value"}})");
    }

    class SetSettingValueTest : public CommandExecutorTest {};

    /**
     * @given command
     * @when trying to insert the setting value by the key
     * @then record with the key has the value
     */
    TEST_F(SetSettingValueTest, InsertSettingValue) {
      std::string key = "maxDesc";
      std::string value = "255";
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructSetSettingValue(key, value), true));

      auto setting_value = sql_query->getSettingValue(key);
      ASSERT_TRUE(setting_value);
      ASSERT_EQ(setting_value.get(), value);
    }

    /**
     * @given command
     * @when trying to update the setting value by the key
     * @then record with the key has the new value
     */
    TEST_F(SetSettingValueTest, UpdateSettingValue) {
      std::string key = "maxDesc";
      std::string value = "255";
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructSetSettingValue(key, value), true));

      auto setting_value = sql_query->getSettingValue(key);
      ASSERT_TRUE(setting_value);
      ASSERT_EQ(setting_value.get(), value);

      value = "512";
      ASSERT_NE(setting_value.get(), value);
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructSetSettingValue(key, value), true));

      setting_value = sql_query->getSettingValue(key);
      ASSERT_TRUE(setting_value);
      ASSERT_EQ(setting_value.get(), value);
    }

  }  // namespace ametsuchi
}  // namespace iroha
