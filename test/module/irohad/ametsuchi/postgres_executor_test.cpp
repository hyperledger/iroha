/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_query_executor.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "backend/protobuf/proto_permission_to_string.hpp"
#include "framework/common_constants.hpp"
#include "framework/result_fixture.hpp"
#include "framework/test_logger.hpp"
#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"
#include "module/irohad/ametsuchi/ametsuchi_mocks.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/interface_mocks.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"

using namespace common_constants;

namespace iroha {
  namespace ametsuchi {

    using ::testing::HasSubstr;

    using namespace framework::expected;

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
        pubkey = std::make_unique<shared_model::interface::types::PubkeyType>(
            std::string('1', 32));
      }

      void SetUp() override {
        AmetsuchiTest::SetUp();
        sql = std::make_unique<soci::session>(*soci::factory_postgresql(),
                                              pgopt_);

        wsv_query =
            std::make_unique<PostgresWsvQuery>(*sql, getTestLogger("WcvQuery"));
        PostgresCommandExecutor::prepareStatements(*sql);
        executor =
            std::make_unique<PostgresCommandExecutor>(*sql, perm_converter);

        *sql << init_;
      }

      void TearDown() override {
        sql->close();
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
        executor->doValidation(not do_validation);
        executor->setCreatorAccountId(creator);
        return executor->operator()(std::forward<CommandType>(command));
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
                        name, domain_id, *pubkey),
                    true));
      }

      const std::string role = "role";
      const std::string another_role = "role2";
      shared_model::interface::RolePermissionSet role_permissions;
      shared_model::interface::permissions::Grantable grantable_permission;
      shared_model::interface::types::AccountIdType account_id, name;
      std::unique_ptr<shared_model::interface::types::PubkeyType> pubkey;
      std::unique_ptr<soci::session> sql;

      std::unique_ptr<shared_model::interface::Command> command;

      std::unique_ptr<WsvQuery> wsv_query;
      std::unique_ptr<CommandExecutor> executor;

      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter =
              std::make_shared<shared_model::proto::ProtoPermissionToString>();

      const shared_model::interface::Amount asset_amount_one_zero{"1.0"};

      std::unique_ptr<shared_model::interface::MockCommandFactory>
          mock_command_factory =
              std::make_unique<shared_model::interface::MockCommandFactory>();
    };

    class AddAccountAssetTest : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();

        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
      }

      void addAssetAndCheckError(const std::string &quantity,
                                 CommandError::ErrorCodeType code) {
        auto cmd = mock_command_factory->constructAddAssetQuantity(
            asset_id, shared_model::interface::Amount{quantity});
        auto result = execute(*cmd, true);
        std::vector<std::string> query_args{account_id, quantity, asset_id};
        CHECK_ERROR_CODE_AND_MESSAGE(result, code, query_args);
      }

      shared_model::interface::types::AssetIdType asset_id =
          "coin#" + domain_id;
    };

    /**
     * @given addAccountAsset command
     * @when trying to add asset to account
     * @then account asset is successfully added
     */
    TEST_F(AddAccountAssetTest, Valid) {
      addAsset();
      addAllPerms();

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
              asset_id, asset_amount_one_zero)));

      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
              asset_id, asset_amount_one_zero)));

      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ("2.0", account_asset.get()->balance().toStringRepr());
    }

    /**
     * @given addAccountAsset command
     * @when trying to add asset to account with a domain permission
     * @then account asset is successfully added
     */
    TEST_F(AddAccountAssetTest, DomainPermValid) {
      addAsset();
      addOnePerm(
          shared_model::interface::permissions::Role::kAddDomainAssetQty);

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
              asset_id, asset_amount_one_zero)));

      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
              asset_id, asset_amount_one_zero)));

      account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ("2.0", account_asset.get()->balance().toStringRepr());
    }

    /**
     * @given addAccountAsset command and invalid domain permission
     * @when trying to add asset
     * @then account asset is not added
     */
    TEST_F(AddAccountAssetTest, DomainPermInvalid) {
      shared_model::interface::types::DomainIdType domain2_id = "domain2";
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateDomain(domain2_id, role),
          true));
      addAsset("coin", domain2_id, 1);
      addOnePerm(
          shared_model::interface::permissions::Role::kAddDomainAssetQty);

      auto asset2_id = "coin#" + domain2_id;

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset2_id, asset_amount_one_zero),
                  true));

      auto account_asset = sql_query->getAccountAsset(account_id, asset2_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());

      auto cmd_result =
          execute(*mock_command_factory->constructAddAssetQuantity(
              asset2_id, asset_amount_one_zero));

      std::vector<std::string> query_args{
          account_id, asset_amount_one_zero.toStringRepr(), asset2_id, "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command
     * @when trying to add account asset without permission
     * @then account asset not added
     */
    TEST_F(AddAccountAssetTest, NoPerms) {
      addAsset();

      auto add_asset = mock_command_factory->constructAddAssetQuantity(
          asset_id, asset_amount_one_zero);
      CHECK_SUCCESSFUL_RESULT(execute(*add_asset, true));

      auto account_asset = sql_query->getAccountAsset(account_id, asset_id);
      ASSERT_TRUE(account_asset);
      ASSERT_EQ(asset_amount_one_zero, account_asset.get()->balance());

      auto cmd_result = execute(*add_asset);

      std::vector<std::string> query_args{
          account_id, asset_amount_one_zero.toStringRepr(), asset_id, "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command
     * @when trying to add account asset with non-existing asset
     * @then account asset fails to be added
     */
    TEST_F(AddAccountAssetTest, InvalidAsset) {
      auto cmd_result =
          execute(*mock_command_factory->constructAddAssetQuantity(
                      asset_id, asset_amount_one_zero),
                  true);

      std::vector<std::string> query_args{
          account_id, asset_amount_one_zero.toStringRepr(), asset_id, "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given a user with all required permissions having the maximum allowed
     * quantity of an asset with precision 1
     * @when execute a tx with AddAssetQuantity command for that asset with the
     * smallest possible quantity with the same precision and then with a lower
     * precision
     * @then the last two transactions are not committed
     */
    TEST_F(AddAccountAssetTest, DestOverflowPrecision1) {
      addAsset();

      auto add_max = mock_command_factory->constructAddAssetQuantity(
          asset_id, kAmountPrec1Max);
      CHECK_SUCCESSFUL_RESULT(execute(*add_max, true));

      addAssetAndCheckError("0.1", 4);
      addAssetAndCheckError("1", 4);
    }

    /**
     * @given a user with all required permissions having the maximum allowed
     * quantity of an asset with precision 2
     * @when execute a tx with AddAssetQuantity command for that asset with the
     * smallest possible quantity with the same precision and then with a lower
     * precision
     * @then the last two transactions are not committed
     */
    TEST_F(AddAccountAssetTest, DestOverflowPrecision2) {
      addAsset("coin", domain_id, 2);

      auto add_max = mock_command_factory->constructAddAssetQuantity(
          asset_id, kAmountPrec2Max);
      CHECK_SUCCESSFUL_RESULT(execute(*add_max, true));

      addAssetAndCheckError("0.01", 4);
      addAssetAndCheckError("0.1", 4);
    }

    class AddPeer : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        address =
            std::make_unique<shared_model::interface::types::AddressType>("");
        pk = std::make_unique<shared_model::interface::types::PubkeyType>("");
        peer = std::make_unique<MockPeer>();
        EXPECT_CALL(*peer, address())
            .WillRepeatedly(testing::ReturnRef(*address));
        EXPECT_CALL(*peer, pubkey()).WillRepeatedly(testing::ReturnRef(*pk));
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
      }

      std::unique_ptr<shared_model::interface::types::AddressType> address;
      std::unique_ptr<shared_model::interface::types::PubkeyType> pk;
      std::unique_ptr<MockPeer> peer;
    };

    /**
     * @given command
     * @when trying to add peer
     * @then peer is successfully added
     */
    TEST_F(AddPeer, Valid) {
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

      std::vector<std::string> query_args{peer->toString()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    class RemovePeer : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        peer = makePeer("address",
                        shared_model::interface::types::PubkeyType{"pubkey"});
        another_peer = makePeer(
            "another_address",
            shared_model::interface::types::PubkeyType{"another_pubkey"});
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
          execute(*mock_command_factory->constructRemovePeer(peer->pubkey())));

      auto peers = wsv_query->getPeers();
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
          execute(*mock_command_factory->constructRemovePeer(peer->pubkey()));

      std::vector<std::string> query_args{peer->pubkey().toString()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command
     * @when trying to remove nonexistent peer
     * @then peer is not removed
     */
    TEST_F(RemovePeer, NoPeer) {
      addAllPerms();
      auto cmd_result = execute(
          *mock_command_factory->constructRemovePeer(another_peer->pubkey()));

      std::vector<std::string> query_args{another_peer->pubkey().toString()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command
     * @when trying to remove nonexistent peer without validation
     * @then peer is not removed
     */
    TEST_F(RemovePeer, NoPeerWithoutValidation) {
      addAllPerms();
      auto cmd_result = execute(
          *mock_command_factory->constructRemovePeer(another_peer->pubkey()),
          true);

      std::vector<std::string> query_args{another_peer->pubkey().toString()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 1, query_args);
    }

    /**
     * @given command
     * @when trying to remove the only peer in the list
     * @then peer is not removed
     */
    TEST_F(RemovePeer, LastPeer) {
      addAllPerms();
      auto cmd_result =
          execute(*mock_command_factory->constructRemovePeer(peer->pubkey()));

      std::vector<std::string> query_args{peer->pubkey().toString()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    class AddSignatory : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        createDefaultRole();
        createDefaultDomain();
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructCreateAccount(
                        name,
                        domain_id,
                        shared_model::interface::types::PubkeyType(
                            std::string('5', 32))),
                    true));
      }
    };

    /**
     * @given command
     * @when trying to add signatory with role permission
     * @then signatory is successfully added
     */
    TEST_F(AddSignatory, Valid) {
      addAllPerms();

      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(*pubkey, account_id)));

      auto signatories = wsv_query->getSignatories(account_id);
      ASSERT_TRUE(signatories);
      ASSERT_TRUE(std::find(signatories->begin(), signatories->end(), *pubkey)
                  != signatories->end());
    }

    /**
     * @given command
     * @when trying to add signatory with grantable permission
     * @then signatory is successfully added
     */
    TEST_F(AddSignatory, ValidGrantablePerms) {
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateAccount(
              "id2",
              domain_id,
              shared_model::interface::types::PubkeyType(std::string('2', 32))),
          true));
      auto perm =
          shared_model::interface::permissions::Grantable::kAddMySignatory;
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructGrantPermission(account_id, perm),
          true,
          "id2@domain"));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(*pubkey, "id2@domain")));
      auto signatories = wsv_query->getSignatories("id2@domain");
      ASSERT_TRUE(signatories);
      ASSERT_TRUE(std::find(signatories->begin(), signatories->end(), *pubkey)
                  != signatories->end());
    }

    /**
     * @given command
     * @when trying to add signatory without permissions
     * @then signatory is not added
     */
    TEST_F(AddSignatory, NoPerms) {
      auto cmd_result = execute(
          *mock_command_factory->constructAddSignatory(*pubkey, account_id));

      std::vector<std::string> query_args{account_id, pubkey->hex()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);

      auto signatories = wsv_query->getSignatories(account_id);
      ASSERT_TRUE(signatories);
      ASSERT_TRUE(std::find(signatories->begin(), signatories->end(), *pubkey)
                  == signatories->end());
    }

    /**
     * @given command
     * @when successfully adding signatory to the account @and trying to add the
     * same signatory again
     * @then signatory is not added
     */
    TEST_F(AddSignatory, ExistingPubKey) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(*pubkey, account_id)));

      auto cmd_result = execute(
          *mock_command_factory->constructAddSignatory(*pubkey, account_id));

      std::vector<std::string> query_args{account_id, pubkey->hex()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
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
      addAllPerms();
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
      addAllPerms();
      auto cmd_result = execute(
          *mock_command_factory->constructAppendRole(account_id, another_role));

      std::vector<std::string> query_args{account_id, another_role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    class CreateAccount : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        account2_id = "id2@" + domain_id;
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
      }

      shared_model::interface::types::AccountIdType account2_id;
    };

    /**
     * @given command
     * @when trying to create account
     * @then account is created
     */
    TEST_F(CreateAccount, Valid) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateAccount(
              "id2", domain_id, *pubkey)));
      auto acc = sql_query->getAccount(account2_id);
      ASSERT_TRUE(acc);
      ASSERT_EQ(account2_id, acc.get()->accountId());
    }

    /**
     * @given command
     * @when trying to create account without permission to do so
     * @then account is not created
     */
    TEST_F(CreateAccount, NoPerms) {
      auto cmd_result = execute(*mock_command_factory->constructCreateAccount(
          account2_id, domain_id, *pubkey));
      auto acc = sql_query->getAccount(account2_id);
      ASSERT_FALSE(acc);

      std::vector<std::string> query_args{
          account2_id, domain_id, pubkey->hex()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command @and no target domain in ledger
     * @when trying to create account
     * @then account is not created
     */
    TEST_F(CreateAccount, NoDomain) {
      addAllPerms();
      auto cmd_result = execute(*mock_command_factory->constructCreateAccount(
          "doge", "domain6", *pubkey));

      std::vector<std::string> query_args{"doge", "domain6", pubkey->hex()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command
     * @when trying to create with an occupied name
     * @then account is not created
     */
    TEST_F(CreateAccount, NameExists) {
      addAllPerms();
      auto cmd_result = execute(*mock_command_factory->constructCreateAccount(
          name, domain_id, *pubkey));

      std::vector<std::string> query_args{name, domain_id, pubkey->hex()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
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
                      name, domain_id, *pubkey),
                  true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateAsset("coin", domain_id, 1)));
      auto ass = sql_query->getAsset(asset_id);
      ASSERT_TRUE(ass);
      ASSERT_EQ(asset_id, ass.get()->assetId());
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
                      name, domain_id, *pubkey),
                  true));
      auto cmd_result = execute(
          *mock_command_factory->constructCreateAsset("coin", domain_id, 1));
      auto ass = sql_query->getAsset(asset_id);
      ASSERT_FALSE(ass);

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
                      name, domain_id, *pubkey),
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
                      name, domain_id, *pubkey),
                  true));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructCreateAsset("coin", domain_id, 1)));
      auto cmd_result = execute(
          *mock_command_factory->constructCreateAsset("coin", domain_id, 1));

      std::vector<std::string> query_args{"coin", domain_id, "1"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
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
      addAllPerms();
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
      addAllPerms();
      auto cmd_result = execute(*mock_command_factory->constructCreateDomain(
          domain2_id, another_role));

      std::vector<std::string> query_args{domain2_id, another_role};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    class CreateRole : public CommandExecutorTest {
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
     * @when trying to create role
     * @then role is created
     */
    TEST_F(CreateRole, Valid) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateRole(
              another_role, role_permissions)));
      auto rl = sql_query->getRolePermissions(role);
      ASSERT_TRUE(rl);
      ASSERT_EQ(rl.get(), role_permissions);
    }

    /**
     * @given command
     * @when trying to create role when creator doesn't have all permissions
     * @then role is not created
     */
    TEST_F(CreateRole, NoPerms) {
      role_permissions2.set(
          shared_model::interface::permissions::Role::kRemoveMySignatory);
      auto cmd_result = execute(*mock_command_factory->constructCreateRole(
          another_role, role_permissions2));
      auto rl = sql_query->getRolePermissions(another_role);
      ASSERT_TRUE(rl);
      ASSERT_TRUE(rl->isEmpty());

      std::vector<std::string> query_args{another_role,
                                          role_permissions2.toBitstring()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);
    }

    /**
     * @given command
     * @when trying to create role with an occupied name
     * @then role is not created
     */
    TEST_F(CreateRole, NameNotUnique) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateRole(
              another_role, role_permissions)));
      auto cmd_result = execute(*mock_command_factory->constructCreateRole(
          another_role, role_permissions));

      std::vector<std::string> query_args{another_role,
                                          role_permissions.toBitstring()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
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
      addAllPerms();
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
      addAllPerms();
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
      addAllPerms();
      auto cmd_result = execute(*mock_command_factory->constructDetachRole(
          account_id, "not_existing_role"));

      std::vector<std::string> query_args{account_id, "not_existing_role"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 5, query_args);
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
      addAllPerms();
      auto perm = shared_model::interface::permissions::Grantable::kSetMyQuorum;
      auto cmd_result = execute(*mock_command_factory->constructGrantPermission(
          "doge@noaccount", perm));

      std::vector<std::string> query_args{"doge@noaccount",
                                          perm_converter->toString(perm)};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    class RemoveSignatory : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        pubkey = std::make_unique<shared_model::interface::types::PubkeyType>(
            std::string('1', 32));
        another_pubkey =
            std::make_unique<shared_model::interface::types::PubkeyType>(
                std::string('7', 32));
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
      }
      std::unique_ptr<shared_model::interface::types::PubkeyType> pubkey;
      std::unique_ptr<shared_model::interface::types::PubkeyType>
          another_pubkey;
    };

    /**
     * @given command
     * @when trying to remove signatory
     * @then signatory is successfully removed
     */
    TEST_F(RemoveSignatory, Valid) {
      addAllPerms();
      shared_model::interface::types::PubkeyType pk(std::string('5', 32));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(pk, account_id), true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructRemoveSignatory(account_id,
                                                                  *pubkey)));
      auto signatories = wsv_query->getSignatories(account_id);
      ASSERT_TRUE(signatories);
      ASSERT_TRUE(std::find(signatories->begin(), signatories->end(), *pubkey)
                  == signatories->end());
      ASSERT_TRUE(std::find(signatories->begin(), signatories->end(), pk)
                  != signatories->end());
    }

    /**
     * @given command
     * @when trying to remove signatory
     * @then signatory is successfully removed
     */
    TEST_F(RemoveSignatory, ValidGrantablePerm) {
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCreateAccount(
                      "id2", domain_id, *pubkey),
                  true));
      auto perm =
          shared_model::interface::permissions::Grantable::kRemoveMySignatory;
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructGrantPermission(account_id, perm),
          true,
          "id2@domain"));
      shared_model::interface::types::PubkeyType pk(std::string('5', 32));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(pk, "id2@domain"),
          true));
      auto signatories = wsv_query->getSignatories("id2@domain");
      ASSERT_TRUE(signatories);
      ASSERT_TRUE(std::find(signatories->begin(), signatories->end(), pk)
                  != signatories->end());
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructRemoveSignatory("id2@domain", pk)));
      signatories = wsv_query->getSignatories("id2@domain");
      ASSERT_TRUE(signatories);
      ASSERT_TRUE(std::find(signatories->begin(), signatories->end(), *pubkey)
                  != signatories->end());
      ASSERT_TRUE(std::find(signatories->begin(), signatories->end(), pk)
                  == signatories->end());
    }

    /**
     * @given command
     * @when trying to remove signatory without permission
     * @then signatory is not removed
     */
    TEST_F(RemoveSignatory, NoPerms) {
      shared_model::interface::types::PubkeyType pk(std::string('5', 32));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(pk, account_id), true));
      auto cmd_result = execute(
          *mock_command_factory->constructRemoveSignatory(account_id, *pubkey));

      std::vector<std::string> query_args{account_id, pubkey->hex()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 2, query_args);

      auto signatories = wsv_query->getSignatories(account_id);
      ASSERT_TRUE(signatories);
      ASSERT_TRUE(std::find(signatories->begin(), signatories->end(), *pubkey)
                  != signatories->end());
      ASSERT_TRUE(std::find(signatories->begin(), signatories->end(), pk)
                  != signatories->end());
    }

    /**
     * @given command
     * @when trying to remove signatory from a non existing account
     * @then corresponding error code is returned
     */
    TEST_F(RemoveSignatory, NoAccount) {
      addAllPerms();
      shared_model::interface::types::PubkeyType pk(std::string('5', 32));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(pk, account_id), true));

      auto cmd_result = execute(
          *mock_command_factory->constructRemoveSignatory("hello", *pubkey));

      std::vector<std::string> query_args{"hello", pubkey->hex()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    /**
     * @given command
     * @when trying to remove signatory, which is not attached to this account
     * @then corresponding error code is returned
     */
    TEST_F(RemoveSignatory, NoSuchSignatory) {
      addAllPerms();
      shared_model::interface::types::PubkeyType pk(std::string('5', 32));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(pk, account_id), true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddSignatory(*another_pubkey,
                                                               account_id),
                  true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructRemoveSignatory(
                      account_id, *another_pubkey),
                  true));

      auto cmd_result = execute(*mock_command_factory->constructRemoveSignatory(
          account_id, *another_pubkey));

      std::vector<std::string> query_args{account_id, another_pubkey->hex()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

    /**
     * @given command
     * @when trying to remove signatory from an account, after which it will
     * have signatories less, than its quorum
     * @then signatory is not removed
     */
    TEST_F(RemoveSignatory, SignatoriesLessThanQuorum) {
      addAllPerms();
      shared_model::interface::types::PubkeyType pk(std::string('5', 32));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(pk, account_id), true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructRemoveSignatory(account_id,
                                                                  *pubkey)));
      auto cmd_result = execute(
          *mock_command_factory->constructRemoveSignatory(account_id, pk));

      std::vector<std::string> query_args{account_id, pk.hex()};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 5, query_args);
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

    class SetAccountDetail : public CommandExecutorTest {
     public:
      void SetUp() override {
        CommandExecutorTest::SetUp();
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
        account2_id = "id2@" + domain_id;
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructCreateAccount(
                        "id2",
                        domain_id,
                        shared_model::interface::types::PubkeyType(
                            std::string('2', 32))),
                    true));
      }
      shared_model::interface::types::AccountIdType account2_id;
    };

    /**
     * @given command
     * @when trying to set kv
     * @then kv is set
     */
    TEST_F(SetAccountDetail, Valid) {
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSetAccountDetail(
              account_id, "key", "value")));
      auto kv = sql_query->getAccountDetail(account_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), "{\"id@domain\": {\"key\": \"value\"}}");
    }

    /**
     * @given command
     * @when trying to set kv when has grantable permission
     * @then kv is set
     */
    TEST_F(SetAccountDetail, ValidGrantablePerm) {
      auto perm =
          shared_model::interface::permissions::Grantable::kSetMyAccountDetail;
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructGrantPermission(account_id, perm),
          true,
          "id2@domain"));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSetAccountDetail(
                      account2_id, "key", "value"),
                  false,
                  account_id));
      auto kv = sql_query->getAccountDetail(account2_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), "{\"id@domain\": {\"key\": \"value\"}}");
    }

    /**
     * @given command
     * @when trying to set kv when has role permission
     * @then kv is set
     */
    TEST_F(SetAccountDetail, ValidRolePerm) {
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSetAccountDetail(
                      account2_id, "key", "value"),
                  false,
                  account_id));
      auto kv = sql_query->getAccountDetail(account2_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), "{\"id@domain\": {\"key\": \"value\"}}");
    }

    /**
     * @given command
     * @when trying to set kv while having no permissions
     * @then corresponding error code is returned
     */
    TEST_F(SetAccountDetail, NoPerms) {
      auto cmd_result =
          execute(*mock_command_factory->constructSetAccountDetail(
                      account2_id, "key", "value"),
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
    TEST_F(SetAccountDetail, NoAccount) {
      addAllPerms();
      auto cmd_result =
          execute(*mock_command_factory->constructSetAccountDetail(
                      "doge@noaccount", "key", "value"),
                  false,
                  account_id);

      std::vector<std::string> query_args{"doge@noaccount", "key", "value"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 3, query_args);
    }

    class SetQuorum : public CommandExecutorTest {
     public:
      SetQuorum() : additional_pubkey_{std::string('9', 32)} {}

      void SetUp() override {
        CommandExecutorTest::SetUp();
        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructAddSignatory(
                        additional_pubkey_, account_id),
                    true));
      }
      shared_model::interface::types::PubkeyType additional_pubkey_;
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
                      "id2", domain_id, *pubkey),
                  true));
      auto perm = shared_model::interface::permissions::Grantable::kSetMyQuorum;
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructGrantPermission(account_id, perm),
          true,
          "id2@domain"));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructAddSignatory(
                      additional_pubkey_, "id2@domain"),
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
      addAllPerms();
      shared_model::interface::types::PubkeyType pk(std::string('5', 32));
      CHECK_SUCCESSFUL_RESULT(execute(
          *mock_command_factory->constructAddSignatory(pk, account_id), true));
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructSetQuorum(account_id, 3)));

      auto cmd_result =
          execute(*mock_command_factory->constructSetQuorum(account_id, 5));

      std::vector<std::string> query_args{account_id, "5"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 5, query_args);
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
      addAllPerms();
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
      addAllPerms();
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
      addAllPerms();
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

    class TransferAccountAssetTest : public CommandExecutorTest {
      void SetUp() override {
        CommandExecutorTest::SetUp();

        account2_id = "id2@" + domain_id;

        createDefaultRole();
        createDefaultDomain();
        createDefaultAccount();
        CHECK_SUCCESSFUL_RESULT(
            execute(*mock_command_factory->constructCreateAccount(
                        "id2", domain_id, *pubkey),
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
      addAllPerms(account2_id, "all2");
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
      addAllPerms();
      addAllPerms(account2_id, "all2");
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
      addAllPerms();
      addAllPerms(account2_id, "all2");
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
      addAllPerms();
      addAllPerms(account2_id, "all2");
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
      addAllPerms();
      addAllPerms(account2_id, "all2");
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
      addAllPerms();
      addAllPerms(account2_id, "all2");
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
      addAllPerms();
      addAllPerms(account2_id, "all2");
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
      addAllPerms();
      addAllPerms(account2_id, "all2");
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
                        "id2",
                        domain_id,
                        shared_model::interface::types::PubkeyType(
                            std::string('2', 32))),
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
              account_id, "key", "value", boost::none)));
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
                      account2_id, "key", "value", boost::none),
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
      addAllPerms();
      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
                      account2_id, "key", "value", boost::none),
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
                      account2_id, "key", "value", boost::none),
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
      addAllPerms();
      auto cmd_result =
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
                      "doge@noaccount", "key", "value", boost::none),
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
              account_id, "key", "value", boost::none)));

      auto kv = sql_query->getAccountDetail(account_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), R"({"id@domain": {"key": "value"}})");

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id,
              "key",
              "value1",
              boost::optional<
                  shared_model::interface::types::AccountDetailValueType>(
                  "value"))));
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
              account_id, "key", "value", boost::none)));

      auto kv = sql_query->getAccountDetail(account_id);
      ASSERT_TRUE(kv);
      ASSERT_EQ(kv.get(), R"({"id@domain": {"key": "value"}})");

      auto cmd_result =
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id,
              "key",
              "value1",
              boost::optional<
                  shared_model::interface::types::AccountDetailValueType>(
                  "oldValue")));

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
              account_id, "key", "value", boost::none)));

      CHECK_SUCCESSFUL_RESULT(
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id, "key1", "value1", boost::none)));

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
              account_id, "key", "", boost::none)));

      auto cmd_result =
          execute(*mock_command_factory->constructCompareAndSetAccountDetail(
              account_id, "key", "value", boost::none));

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
              boost::optional<
                  shared_model::interface::types::AccountDetailValueType>(
                  "notEmptyOldValue")));

      std::vector<std::string> query_args{
          account_id, "key", "value", "notEmptyOldValue"};
      CHECK_ERROR_CODE_AND_MESSAGE(cmd_result, 4, query_args);
    }

  }  // namespace ametsuchi
}  // namespace iroha
