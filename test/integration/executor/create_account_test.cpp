/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "common/result.hpp"
#include "framework/common_constants.hpp"
#include "framework/crypto_literals.hpp"
#include "integration/executor/command_permission_test.hpp"
#include "integration/executor/executor_fixture_param_provider.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;

static const AccountNameType kNewName{"new_account"};
const auto kNewPubkey{"hey im new here"_hex_pubkey};

/// do not call during static init!
const AccountIdType &getNewId() {
  static const AccountIdType kNewId{kNewName + "@" + kSecondDomain};
  return kNewId;
}

class CreateAccountTest : public ExecutorTestBase {
 public:
  void checkAccount(
      const boost::optional<AccountIdType> &account_id = boost::none,
      PublicKeyHexStringView pubkey = kNewPubkey) {
    auto account_id_val = account_id.value_or(getNewId());
    ASSERT_NO_FATAL_FAILURE(checkSignatories(account_id_val, {pubkey}););
  }

  void checkNoSuchAccount(
      const boost::optional<AccountIdType> &account_id = boost::none) {
    auto account_id_val = account_id.value_or(getNewId());
    checkQueryError<shared_model::interface::NoAccountErrorResponse>(
        getItf().executeQuery(
            *getItf().getMockQueryFactory()->constructGetAccount(
                account_id_val)),
        0);
  }

  iroha::ametsuchi::CommandResult createAccount(
      const AccountIdType &issuer,
      const AccountNameType &target_name = kNewName,
      const DomainIdType &target_domain = kSecondDomain,
      PublicKeyHexStringView pubkey = kNewPubkey,
      bool validation_enabled = true) {
    return getItf().executeCommandAsAccount(
        *getItf().getMockCommandFactory()->constructCreateAccount(
            target_name, target_domain, pubkey),
        issuer,
        validation_enabled);
  }

  iroha::ametsuchi::CommandResult createDefaultAccount(
      const AccountIdType &issuer, bool validation_enabled = true) {
    return createAccount(
        issuer, kNewName, kSecondDomain, kNewPubkey, validation_enabled);
  }
};

using CreateAccountBasicTest = BasicExecutorTest<CreateAccountTest>;

/**
 * @given a user with all related permissions
 * @when executes CreateAccount command with nonexistent domain
 * @then the command does not succeed and the account is not added
 */
TEST_P(CreateAccountBasicTest, NoDomain) {
  checkCommandError(createAccount(kAdminId, kNewName, "no_such_domain"), 3);
  checkNoSuchAccount(kNewName + "@no_such_domain");
}

/**
 * @given a user with all related permissions
 * @when executes CreateAccount command with occupied name and another public
 * key
 * @then the command does not succeed and the original account is not changed
 */
TEST_P(CreateAccountBasicTest, NameExists) {
  ASSERT_NO_FATAL_FAILURE(
      getItf().createUserWithPerms(kNewName, kSecondDomain, kNewPubkey, {}));
  ASSERT_NO_FATAL_FAILURE(checkAccount());

  checkCommandError(createDefaultAccount(kAdminId), 4);
  checkAccount();
}

/**
 * Checks that there is no privilege elevation issue via CreateAccount
 *
 * @given an account with can_create_account permission, but without
 * can_set_detail permission
 * @and a domain that has a default role that contains can_set_detail permission
 * @when the user tries to create an account in that domain
 * @then the command does not succeed and the account is not added
 */
TEST_P(CreateAccountBasicTest, PrivelegeElevation) {
  ASSERT_NO_FATAL_FAILURE(getItf().createUserWithPerms(
      kUser,
      kDomain,
      PublicKeyHexStringView{kUserKeypair.publicKey()},
      {Role::kCreateAccount}));
  ASSERT_NO_FATAL_FAILURE(
      getItf().createRoleWithPerms("target_role", {Role::kSetDetail}));
  IROHA_ASSERT_RESULT_VALUE(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructCreateDomain(kSecondDomain,
                                                               "target_role")));

  checkCommandError(createDefaultAccount(kUserId), 2);
  checkNoSuchAccount();
}

/**
 * @given a user with root permission, but without can_set_detail permission
 * @and a domain that has a default role that contains can_set_detail permission
 * @when the user tries to create an account in that domain
 * @then the command succeeds
 */
TEST_P(CreateAccountBasicTest, RootWithNoPermSubset) {
  ASSERT_NO_FATAL_FAILURE(
      getItf().createRoleWithPerms("target_role", {Role::kSetDetail}));
  IROHA_ASSERT_RESULT_VALUE(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructCreateDomain(kSecondDomain,
                                                               "target_role")));
  ASSERT_NO_FATAL_FAILURE(getItf().createUserWithPerms(
      kUser,
      kDomain,
      PublicKeyHexStringView{kUserKeypair.publicKey()},
      {Role::kRoot}));

  framework::expected::expectResultValue(createDefaultAccount(kUserId));
  checkAccount();
}

INSTANTIATE_TEST_SUITE_P(Base,
                         CreateAccountBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using CreateAccountPermissionTest =
    command_permission_test::CommandPermissionTest<CreateAccountTest>;

TEST_P(CreateAccountPermissionTest, CommandPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(getItf().createDomain(kSecondDomain));
  ASSERT_NO_FATAL_FAILURE(prepareState({}));

  if (checkResponse(createDefaultAccount(getActor(), getValidationEnabled()))) {
    checkAccount();
  } else {
    checkNoSuchAccount();
  }
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    CreateAccountPermissionTest,
    command_permission_test::getParams(
        boost::none, boost::none, Role::kCreateAccount, boost::none),
    command_permission_test::paramToString);
