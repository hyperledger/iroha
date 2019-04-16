/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

class RemoveSignatory : public AcceptanceFixture {
 public:
  auto makeFirstUser(const interface::RolePermissionSet &perms = {
                         interface::permissions::Role::kRemoveSignatory}) {
    auto new_perms = perms;
    new_perms.set(interface::permissions::Role::kAddSignatory);
    return AcceptanceFixture::makeUserWithPerms(new_perms);
  }

  auto makeSecondUser(const interface::RolePermissionSet &perms = {
                          interface::permissions::Role::kReceive}) {
    return complete(
        createUserWithPerms(kUser2, kUser2Keypair.publicKey(), kRole2, perms)
            .creatorAccountId(kAdminId),
        kAdminKeypair);
  }

  const std::string kRole2 = "roletwo";
  const std::string kUser2 = "usertwo";
  const std::string kUser2Id = kUser2 + "@" + kDomain;
  const crypto::Keypair kUser2Keypair =
      crypto::DefaultCryptoAlgorithmType::generateKeypair();
};

/**
 * TODO mboldyrev 18.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 * the second part of the test is covered by
 * postgres_executor_test RemoveSignatory.NoSuchSignatory
 *
 * C264 Remove signatory from own account
 * C267 Remove signatory more than once
 * @given some user with CanRemoveSignatory permission and its signatory
 * @when execute tx with RemoveSignatory where the first is a creator and the
 *       second's key is removed as a signatory
 * @then the first such tx is committed,
         the same transaction afterward shouldn't pass stateful validation
 */
TEST_F(RemoveSignatory, Basic) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(
          complete(baseTx().addSignatory(kUserId, kUser2Keypair.publicKey())),
          CHECK_TXS_QUANTITY(1))
      .sendTxAwait(complete(baseTx().removeSignatory(
                       kUserId, kUser2Keypair.publicKey())),
                   CHECK_TXS_QUANTITY(1))
      .sendTx(complete(
          baseTx().removeSignatory(kUserId, kUser2Keypair.publicKey())))
      .checkVerifiedProposal(CHECK_TXS_QUANTITY(0))
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-221 remove, covered by
 * postgres_executor_test RemoveSignatory.NoPerms
 *
 * C263 RemoveSignatory without such permissions
 * @given some user without CanRemoveSignatory permission and its signatory
 * @when execute tx with RemoveSignatory where the first is a creator and the
 *       second's key is removed as a signatory
 * @then there is the no tx in proposal
 */
TEST_F(RemoveSignatory, NoPermission) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser({}), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(
          complete(baseTx().addSignatory(kUserId, kUser2Keypair.publicKey()),
                   kUserKeypair),
          CHECK_TXS_QUANTITY(1))
      .sendTx(complete(
          baseTx().removeSignatory(kUserId, kUser2Keypair.publicKey())))
      .checkVerifiedProposal(CHECK_TXS_QUANTITY(0))
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-221 remove, covered by
 * postgres_executor_test RemoveSignatory.ValidGrantablePerm
 *
 * C265 Remove signatory from granted account
 * @given some user with CanRemoveMySignatory permission and its signatory with
 *        granted CanRemoveMySignatory
 * @when execute tx with RemoveSignatory where the second is a creator and the
 *       second's key is removed as a signatory
 * @then there is the tx in proposal
 */
TEST_F(RemoveSignatory, GrantedPermission) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTxAwait(
          makeFirstUser({interface::permissions::Role::kRemoveMySignatory}),
          CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(
          complete(baseTx().addSignatory(kUserId, kUser2Keypair.publicKey()),
                   kUserKeypair),
          CHECK_TXS_QUANTITY(1))
      .sendTxAwait(
          complete(baseTx().grantPermission(
              kUser2Id, interface::permissions::Grantable::kRemoveMySignatory)),
          CHECK_TXS_QUANTITY(1))
      .sendTxAwait(complete(baseTx().creatorAccountId(kUser2Id).removeSignatory(
                                kUserId, kUser2Keypair.publicKey()),
                            kUser2Keypair),
                   CHECK_TXS_QUANTITY(1));
}

/**
 * TODO mboldyrev 18.01.2019 IR-221 remove, covered by
 * postgres_executor_test RemoveSignatory.NoPerms
 *
 * @given first user with CanRemoveMySignatory permission and second without it
 *        second user's key is added to first user's signatories
 * @when second user executes RemoveSignatory to remove his key from the first
 *       user's signatories
 * @then there is no tx in proposal
 */
TEST_F(RemoveSignatory, NonGrantedPermission) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTxAwait(
          makeFirstUser({interface::permissions::Role::kRemoveMySignatory}),
          CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(
          complete(baseTx().addSignatory(kUserId, kUser2Keypair.publicKey()),
                   kUserKeypair),
          CHECK_TXS_QUANTITY(1))
      .sendTx(complete(baseTx().creatorAccountId(kUser2Id).removeSignatory(
                           kUserId, kUser2Keypair.publicKey()),
                       kUser2Keypair))
      .checkVerifiedProposal(CHECK_TXS_QUANTITY(0))
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-221 remove, covered by
 * postgres_executor_test RemoveSignatory.NoAccount
 *
 * @given some user with CanRemoveSignatory permission
 * @when execute tx with RemoveSignatory with inexistent user
 * @then there is no tx in proposal
 */
TEST_F(RemoveSignatory, NonExistentUser) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTx(complete(baseTx().removeSignatory("inexistent@" + kDomain,
                                                kUserKeypair.publicKey()),
                       kUser2Keypair))
      .checkVerifiedProposal(CHECK_TXS_QUANTITY(0))
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-221 remove, covered by field validator test
 *
 * C266 Remove signatory with an incorrectly formed public key
 * @given some user with CanRemoveSignatory permission
 * @when execute tx with RemoveSignatory with invalid public key
 * @then the tx is stateless invalid
 */
TEST_F(RemoveSignatory, InvalidKey) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTx(complete(baseTx().removeSignatory(
                  kUserId,
                  shared_model::crypto::PublicKey(std::string(1337, 'a')))),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-221 remove, covered by
 * postgres_executor_test RemoveSignatory.NoSuchSignatory
 *
 * @given some user with CanRemoveSignatory permission
 * @when execute tx with RemoveSignatory with a key which isn't associated with
 *       any user
 * @then there is no tx in proposal
 */
TEST_F(RemoveSignatory, NonExistedKey) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTx(complete(baseTx().removeSignatory(
          kUserId, shared_model::crypto::PublicKey(std::string(32, 'a')))))
      .checkVerifiedProposal(CHECK_TXS_QUANTITY(0))
      .checkBlock(CHECK_TXS_QUANTITY(0));
}

/**
 * TODO mboldyrev 18.01.2019 IR-221 remove, covered by
 * postgres_executor_test RemoveSignatory.SignatoriesLessThanQuorum
 *
 * C268 Remove signatory so that account may have less signatories than the
 *      quorum
 * @given some user with CanRemoveSignatory permission, which account quorum is
 * 2 AND its signatory
 * @when execute tx with RemoveSignatory where the first is a creator and the
 *       second's key is removed as a signatory
 * @then there is no tx in proposal
 * TODO: SetQuroum permission issue, enable after IR-920
 */
TEST_F(RemoveSignatory, DISABLED_SignatoriesLesserThanQuorum) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTxAwait(makeFirstUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(makeSecondUser(), CHECK_TXS_QUANTITY(1))
      .sendTxAwait(
          complete(baseTx().addSignatory(kUserId, kUser2Keypair.publicKey())),
          CHECK_TXS_QUANTITY(1))
      .sendTxAwait(
          complete(
              baseTx().creatorAccountId(kAdminId).setAccountQuorum(kUserId, 2),
              kAdminKeypair),
          CHECK_TXS_QUANTITY(1))
      .sendTx(complete(
          baseTx().removeSignatory(kUserId, kUser2Keypair.publicKey())))
      .checkVerifiedProposal(CHECK_TXS_QUANTITY(0))
      .checkBlock(CHECK_TXS_QUANTITY(0));
}
