/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "framework/common_constants.hpp"
#include "framework/crypto_literals.hpp"
#include "framework/result_gtest_checkers.hpp"
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

const auto kNewPubkey{"hey im new here"_hex_pubkey};

class AddSignatoryTest : public ExecutorTestBase {
 public:
  iroha::ametsuchi::CommandResult addSignatory(
      const AccountIdType &issuer,
      const AccountIdType &target = kUserId,
      PublicKeyHexStringView pubkey = kNewPubkey,
      bool validation_enabled = true) {
    return getItf().executeCommandAsAccount(
        *getItf().getMockCommandFactory()->constructAddSignatory(pubkey,
                                                                 target),
        issuer,
        validation_enabled);
  }
};

using AddSignatoryBasicTest = BasicExecutorTest<AddSignatoryTest>;

/**
 * C222 Add signatory to non-existing account ID
 * @given a user with CanAddMySignatory permission
 * @when execute AddSignatory command with nonexistent target user
 * @then the command fails
 */
TEST_P(AddSignatoryBasicTest, NonExistentUser) {
  checkCommandError(addSignatory(kAdminId), 3);
}

/**
 * @given a user
 * @when execute AddSignatory command for the user with his public key
 * @then the command fails
 * @and signatory is not added
 */
TEST_P(AddSignatoryBasicTest, ExistingPubKey) {
  IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
      kUser, kDomain, PublicKeyHexStringView{kUserKeypair.publicKey()}, {}));

  checkCommandError(
      addSignatory(
          kAdminId, kUserId, PublicKeyHexStringView{kUserKeypair.publicKey()}),
      4);

  checkSignatories(kUserId, {PublicKeyHexStringView{kUserKeypair.publicKey()}});
}

INSTANTIATE_TEST_SUITE_P(Base,
                         AddSignatoryBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using AddSignatoryPermissionTest =
    command_permission_test::CommandPermissionTest<AddSignatoryTest>;

TEST_P(AddSignatoryPermissionTest, CommandPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(getItf().createDomain(kSecondDomain));
  ASSERT_NO_FATAL_FAILURE(prepareState({}));
  ASSERT_NO_FATAL_FAILURE(checkSignatories(
      kUserId, {PublicKeyHexStringView{kUserKeypair.publicKey()}}));

  if (checkResponse(addSignatory(
          getActor(), kUserId, kNewPubkey, getValidationEnabled()))) {
    checkSignatories(
        kUserId,
        {PublicKeyHexStringView{kUserKeypair.publicKey()}, kNewPubkey});
  } else {
    checkSignatories(kUserId,
                     {PublicKeyHexStringView{kUserKeypair.publicKey()}});
  }
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    AddSignatoryPermissionTest,
    command_permission_test::getParams(Role::kAddSignatory,
                                       boost::none,
                                       boost::none,
                                       Grantable::kAddMySignatory),
    command_permission_test::paramToString);
