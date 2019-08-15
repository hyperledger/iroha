/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "common/result.hpp"
#include "framework/common_constants.hpp"
#include "integration/executor/query_permission_test.hpp"
#include "interfaces/query_responses/account_detail_response.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;

static const AccountDetailKeyType kKey{"key"};
static const AccountDetailValueType kVal{"value"};

class CreateAccountTest : public BasicExecutorTest<ExecutorTestBase> {
 public:
  void checkAccount(const AccountIdType &account_id, const PubkeyType &pubkey) {
    ASSERT_NO_FATAL_FAILURE(checkSignatories(account_id, {pubkey}););
  }

  void checkNoSuchAccount(const AccountIdType &account_id) {
    checkQueryError<shared_model::interface::NoAccountErrorResponse>(
        getItf().executeQuery(
            *getItf().getMockQueryFactory()->constructGetAccount(account_id)),
        0);
  }
};

/**
 * @given a user with all related permissions
 * @when executes CreateAccount command
 * @then the command succeeds and the account is created
 */
TEST_P(CreateAccountTest, Valid) {
  assertResultValue(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructCreateAccount(
          kUser, kDomain, kUserKeypair.publicKey())));
  checkAccount(kUserId, kUserKeypair.publicKey());
}

/**
 * @given a user with no permissions
 * @when executes CreateAccount command
 * @then the command does not succeed and the account is not added
 */
TEST_P(CreateAccountTest, NoPerms) {
  getItf().createUserWithPerms(kUser, kDomain, kUserKeypair.publicKey(), {});
  checkCommandError(
      getItf().executeCommandAsAccount(
          *getItf().getMockCommandFactory()->constructCreateAccount(
              kAnotherUser, kDomain, kSameDomainUserKeypair.publicKey()),
          kUserId,
          true),
      2);
  checkNoSuchAccount(kSameDomainUserId);
}

/**
 * @given a user with all related permissions
 * @when executes CreateAccount command with nonexistent domain
 * @then the command does not succeed and the account is not added
 */
TEST_P(CreateAccountTest, NoDomain) {
  checkCommandError(
      getItf().executeMaintenanceCommand(
          *getItf().getMockCommandFactory()->constructCreateAccount(
              kAnotherUser,
              "no_such_domain",
              kSameDomainUserKeypair.publicKey())),
      3);
  checkNoSuchAccount(kAnotherUser + "@no_such_domain");
}

/**
 * @given a user with all related permissions
 * @when executes CreateAccount command with occupied name and another public
 * key
 * @then the command does not succeed and the original account is not changed
 */
TEST_P(CreateAccountTest, NameExists) {
  getItf().createUserWithPerms(kUser, kDomain, kUserKeypair.publicKey(), {});
  checkCommandError(
      getItf().executeMaintenanceCommand(
          *getItf().getMockCommandFactory()->constructCreateAccount(
              kUser, kDomain, kSameDomainUserKeypair.publicKey())),
      4);
  checkAccount(kUserId, kUserKeypair.publicKey());
}

/**
 * Checks that there is no privelege elevation issue via CreateAccount
 *
 * @given an account with can_create_account permission, but without
 * can_set_detail permission
 * @and a domain that has a default role that contains can_set_detail permission
 * @when the user tries to create an account in that domain
 * @then the command does not succeed and the account is not added
 */
TEST_P(CreateAccountTest, PrivelegeElevation) {
  getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {Role::kCreateAccount});
  getItf().createRoleWithPerms("target_role", {Role::kSetDetail});
  assertResultValue(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructCreateDomain(kSecondDomain,
                                                               "target_role")));
  checkCommandError(
      getItf().executeCommandAsAccount(
          *getItf().getMockCommandFactory()->constructCreateAccount(
              kAnotherUser,
              kSecondDomain,
              kAnotherDomainUserKeypair.publicKey()),
          kUserId,
          true),
      2);
  checkNoSuchAccount(kSameDomainUserId);
}

INSTANTIATE_TEST_CASE_P(Base,
                        CreateAccountTest,
                        executor_testing::getExecutorTestParams(),
                        executor_testing::paramToString);
