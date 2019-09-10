/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/common_constants.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "integration/executor/executor_fixture_param_provider.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;

using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;

struct AddSignatoryTest : public ExecutorTestBase {
  const shared_model::crypto::Keypair new_keypair_ =
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair();
};

using AddSignatoryBasicTest = BasicExecutorTest<AddSignatoryTest>;

/**
 * C224 Add existing public key of other user
 * @given some user with CanAddSignatory permission and a second user
 * @when the first executes AddSignatory command that adds the second a
 *       new signatory
 * @then the signatories contain two keys: the original and the newly added
 */
TEST_P(AddSignatoryBasicTest, Basic) {
  assertResultValue(getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {}));

  expectResultValue(getItf().executeMaintenanceCommand(
      *getItf().getMockCommandFactory()->constructAddSignatory(
          new_keypair_.publicKey(), kUserId)));

  checkSignatories(kUserId,
                   {kUserKeypair.publicKey(), new_keypair_.publicKey()});
}

/**
 * C228 AddSignatory without such permissions
 * @given some user without CanAddSignatory permission and a second user
 * @when the first executes AddSignatory command that adds the second a
 *       new signatory
 * @then the command fails @and the signatories contain only the original key
 */
TEST_P(AddSignatoryBasicTest, NoPermission) {
  assertResultValue(getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {}));
  assertResultValue(getItf().createUserWithPerms(
      kSecondUser, kDomain, kSameDomainUserKeypair.publicKey(), {}));

  checkCommandError(
      getItf().executeCommandAsAccount(
          *getItf().getMockCommandFactory()->constructAddSignatory(
              new_keypair_.publicKey(), kSameDomainUserId),
          kUserId,
          true),
      2);

  checkSignatories(kSameDomainUserId, {kSameDomainUserKeypair.publicKey()});
}

/**
 * C225 Add signatory to other user
 * C227 Add signatory to an account, which granted permission to add it, and add
 *      the same public key
 * @given one user with CanAddMySignatory permission and another with granted
 *        CanAddMySignatory
 * @when execute AddSignatory command from the second user
 * @then the command succeeds
 *       @and the signatories contain both the original and the newly added key
 */
TEST_P(AddSignatoryBasicTest, GrantedPermission) {
  assertResultValue(getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {Role::kAddMySignatory}));
  assertResultValue(getItf().createUserWithPerms(
      kSecondUser, kDomain, kSameDomainUserKeypair.publicKey(), {}));

  // kUser grants kSecondUser permission to add him a signatory
  assertResultValue(getItf().executeCommandAsAccount(
      *getItf().getMockCommandFactory()->constructGrantPermission(
          kSameDomainUserId, Grantable::kAddMySignatory),
      kUserId,
      true));

  // kSecondUser adds kUser a signatory
  expectResultValue(getItf().executeCommandAsAccount(
      *getItf().getMockCommandFactory()->constructAddSignatory(
          new_keypair_.publicKey(), kUserId),
      kSameDomainUserId,
      true));

  checkSignatories(kUserId,
                   {kUserKeypair.publicKey(), new_keypair_.publicKey()});
}

/**
 * @given some user with root permission and a second user
 * @when the first executes AddSignatory command that adds the second a
 *       new signatory
 * @then the command fails @and the signatories contain only the original key
 */
TEST_P(AddSignatoryBasicTest, RootPermission) {
  assertResultValue(getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {Role::kRoot}));
  assertResultValue(getItf().createUserWithPerms(
      kSecondUser, kDomain, kSameDomainUserKeypair.publicKey(), {}));

  assertResultValue(getItf().executeCommandAsAccount(
      *getItf().getMockCommandFactory()->constructAddSignatory(
          new_keypair_.publicKey(), kSameDomainUserId),
      kUserId,
      true));

  checkSignatories(
      kSameDomainUserId,
      {kSameDomainUserKeypair.publicKey(), new_keypair_.publicKey()});
}

/**
 * C222 Add signatory to non-existing account ID
 * @given a user with CanAddMySignatory permission
 * @when execute AddSignatory command with nonexistent target user
 * @then the command fails
 */
TEST_P(AddSignatoryBasicTest, NonExistentUser) {
  checkCommandError(
      getItf().executeMaintenanceCommand(
          *getItf().getMockCommandFactory()->constructAddSignatory(
              new_keypair_.publicKey(), kUserId)),
      3);
}

/**
 * @given a user
 * @when execute AddSignatory command for the user with his public key
 * @then the command fails
 * @and signatory is not added
 */
TEST_P(AddSignatoryBasicTest, ExistingPubKey) {
  assertResultValue(getItf().createUserWithPerms(
      kUser, kDomain, kUserKeypair.publicKey(), {}));

  checkCommandError(
      getItf().executeMaintenanceCommand(
          *getItf().getMockCommandFactory()->constructAddSignatory(
              kUserKeypair.publicKey(), kUserId)),
      4);

  checkSignatories(kUserId, {kUserKeypair.publicKey()});
}

INSTANTIATE_TEST_CASE_P(Base,
                        AddSignatoryBasicTest,
                        executor_testing::getExecutorTestParams(),
                        executor_testing::paramToString);
