/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/common_constants.hpp"
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

const auto kNewPubkey =
    shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair()
        .publicKey();

class AddSignatoryTest : public ExecutorTestBase {
 public:
  iroha::ametsuchi::CommandResult addSignatory(
      const AccountIdType &issuer,
      const AccountIdType &target = kUserId,
      const PubkeyType &pubkey = kNewPubkey) {
    return getItf().executeCommandAsAccount(
        *getItf().getMockCommandFactory()->constructAddSignatory(pubkey,
                                                                 target),
        issuer,
        true);
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
  ASSERT_NO_FATAL_FAILURE(assertResultValue(getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {})));

  checkCommandError(addSignatory(kAdminId, kUserId, kUserKeypair.publicKey()),
                    4);

  checkSignatories(kUserId, {kUserKeypair.publicKey()});
}

INSTANTIATE_TEST_CASE_P(Base,
                        AddSignatoryBasicTest,
                        executor_testing::getExecutorTestParams(),
                        executor_testing::paramToString);

using AddSignatoryPermissionTest =
    command_permission_test::CommandPermissionTest<AddSignatoryTest>;

TEST_P(AddSignatoryPermissionTest, CommandPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(getItf().createDomain(kSecondDomain));
  ASSERT_NO_FATAL_FAILURE(prepareState({}));
  ASSERT_NO_FATAL_FAILURE(
      checkSignatories(kUserId, {kUserKeypair.publicKey()}));

  if (checkResponse(addSignatory(getActor()))) {
    checkSignatories(kUserId, {kUserKeypair.publicKey(), kNewPubkey});
  } else {
    checkSignatories(kUserId, {kUserKeypair.publicKey()});
  }
}

INSTANTIATE_TEST_CASE_P(
    Common,
    AddSignatoryPermissionTest,
    command_permission_test::getParams(Role::kAddSignatory,
                                       boost::none,
                                       boost::none,
                                       Grantable::kAddMySignatory),
    command_permission_test::paramToString);
