/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "backend/protobuf/transaction.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "datetime/time.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

class CreateRole : public AcceptanceFixture {
 public:
  auto makeUserWithPerms(const interface::RolePermissionSet &perms = {
                             interface::permissions::Role::kGetMyTxs,
                             interface::permissions::Role::kCreateRole}) {
    return AcceptanceFixture::makeUserWithPerms(kNewRole, perms);
  }

  auto baseTx(const interface::RolePermissionSet &perms,
              const std::string &role_name) {
    return AcceptanceFixture::baseTx().createRole(role_name, perms);
  }

  auto baseTx(const interface::RolePermissionSet &perms = {
                  interface::permissions::Role::kGetMyTxs}) {
    return baseTx(perms, kRole);
  }

  const std::string kNewRole = "rl";
};

/**
 * TODO mboldyrev 18.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 *
 * @given some user with can_create_role permission
 * @when execute tx with CreateRole command
 * @then there is the tx in proposal
 */
TEST_F(CreateRole, Basic) {
  auto tx = makeUserWithPerms();
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(tx)
      .checkStatus(tx.hash(), CHECK_STATELESS_VALID)
      .checkStatus(tx.hash(), CHECK_ENOUGH_SIGNATURES)
      .checkStatus(tx.hash(), CHECK_STATEFUL_VALID)
      .checkStatus(tx.hash(), CHECK_COMMITTED)
      .sendTxAwait(complete(baseTx()), [](auto &block) {
        ASSERT_EQ(block->transactions().size(), 1);
      });
}

/**
 * TODO mboldyrev 18.01.2019 IR-208 remove, SFV covered by CreateRole.NoPerms
 *
 * @given some user without can_create_role permission
 * @when execute tx with CreateRole command
 * @then there is an empty verified proposal
 */
TEST_F(CreateRole, HaveNoPerms) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms({interface::permissions::Role::kGetMyTxs}))
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx()))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-208 remove, covered by field validator test
 *
 * @given some user with can_create_role permission
 * @when execute tx with CreateRole command with empty role
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_F(CreateRole, EmptyRole) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx({interface::permissions::Role::kGetMyTxs}, "")),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-208 remove, covered by field validator test
 *
 * @given some user with can_create_role permission
 * @when execute tx with CreateRole command with empty permission
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_F(CreateRole, EmptyPerms) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTxAwait(complete(baseTx({})), [](auto &block) {
        ASSERT_EQ(block->transactions().size(), 1);
      });
}

/**
 * TODO mboldyrev 18.01.2019 IR-208 remove, covered by field validator test
 *
 * @given some user with can_create_role permission
 * @when execute tx with CreateRole command with too long role name
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_F(CreateRole, LongRoleName) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx({interface::permissions::Role::kGetMyTxs},
                              std::string(33, 'a'))),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-208 remove, covered by field validator test
 *
 * @given some user with can_create_role permission
 * @when execute tx with CreateRole command with maximal role name size
 * @then the tx is comitted
 */
TEST_F(CreateRole, MaxLenRoleName) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipBlock()
      .sendTxAwait(
          complete(baseTx({interface::permissions::Role::kGetMyTxs},
                          std::string(32, 'a'))),
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-208 remove, covered by field validator test
 *
 * TODO 15/05/2018 andrei: IR-1267 fix builders setting default value for
 * nonexisting permissions
 * @given some user with can_create_role permission
 * @when execute tx with CreateRole command with nonexistent permission name
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_F(CreateRole, DISABLED_NonexistentPerm) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(complete(baseTx({static_cast<interface::permissions::Role>(-1)})),
              CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-208 remove, SFV covered by
 * CreateRole.NameNotUnique
 *
 * @given some user with can_create_role permission
 * @when execute tx with CreateRole command with existing role name
 * @then there is an empty verified proposal
 */
TEST_F(CreateRole, ExistingRole) {
  IntegrationTestFramework(1)
      .setInitialState(kAdminKeypair)
      .sendTx(makeUserWithPerms())
      .skipProposal()
      .skipVerifiedProposal()
      .skipBlock()
      .sendTx(
          complete(baseTx({interface::permissions::Role::kGetMyTxs}, kNewRole)))
      .skipProposal()
      .checkVerifiedProposal(
          [](auto &proposal) { ASSERT_EQ(proposal->transactions().size(), 0); })
      .checkBlock(
          [](auto &block) { ASSERT_EQ(block->transactions().size(), 0); });
}
