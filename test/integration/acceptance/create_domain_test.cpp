/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "instantiate_test_suite.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace common_constants;

using iroha::StorageType;

struct CreateDomain : AcceptanceFixture, ::testing::WithParamInterface<StorageType> {
  auto makeUserWithPerms(const interface::RolePermissionSet &perms = {
                             interface::permissions::Role::kCreateDomain}) {
    return AcceptanceFixture::makeUserWithPerms(perms);
  }

  const std::string kNewDomain = "newdomain";
};

INSTANTIATE_TEST_SUITE_P_DifferentStorageTypes(CreateDomain);

/**
 * TODO mboldyrev 18.01.2019 IR-228 "Basic" tests should be replaced with a
 * common acceptance test
 *
 * @given some user with can_create_domain permission
 * @when execute tx with CreateDomain command
 * @then there is the tx in proposal
 */
TEST_P(CreateDomain, Basic) {
    IntegrationTestFramework(1, GetParam())
        .setInitialState(kAdminKeypair)
        .sendTx(makeUserWithPerms())
        .skipProposal()
        .skipBlock()
        .sendTxAwait(
            complete(baseTx().createDomain(kNewDomain, kRole)),
            [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-207 remove, covered by
 * postgres_executor_test CreateDomain.NoPerms
 *
 * @given some user without can_create_domain permission
 * @when execute tx with CreateDomain command
 * @then verified proposal is empty
 */
TEST_P(CreateDomain, NoPermissions) {
    IntegrationTestFramework(1, GetParam())
        .setInitialState(kAdminKeypair)
        .sendTx(makeUserWithPerms({interface::permissions::Role::kGetMyTxs}))
        .skipProposal()
        .skipVerifiedProposal()
        .skipBlock()
        .sendTx(complete(baseTx().createDomain(kNewDomain, kRole)))
        .skipProposal()
        .checkVerifiedProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 0);
        })
        .checkBlock(
            [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-207 remove, covered by
 * postgres_executor_test CreateDomain.NoDefaultRole
 *
 * @given some user with can_create_domain permission
 * @when execute tx with CreateDomain command with nonexistent role
 * @then verified proposal is empty
 */
TEST_P(CreateDomain, NoRole) {
  const std::string nonexistent_role = "asdf";
    IntegrationTestFramework(1, GetParam())
        .setInitialState(kAdminKeypair)
        .sendTx(makeUserWithPerms())
        .skipProposal()
        .skipVerifiedProposal()
        .skipBlock()
        .sendTx(complete(baseTx().createDomain(kNewDomain, nonexistent_role)))
        .skipProposal()
        .checkVerifiedProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 0);
        })
        .checkBlock(
            [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-207 remove, covered by
 * postgres_executor_test CreateDomain.NameNotUnique
 *
 * @given some user with can_create_domain permission
 * @when execute tx with CreateDomain command with already existing domain
 * @then verified proposal is empty
 */
TEST_P(CreateDomain, ExistingName) {
    IntegrationTestFramework(1, GetParam())
        .setInitialState(kAdminKeypair)
        .sendTx(makeUserWithPerms())
        .skipProposal()
        .skipVerifiedProposal()
        .skipBlock()
        .sendTx(complete(baseTx().createDomain(kDomain, kRole)))
        .skipProposal()
        .checkVerifiedProposal([](auto &proposal) {
          ASSERT_EQ(proposal->transactions().size(), 0);
        })
        .checkBlock(
            [](auto block) { ASSERT_EQ(block->transactions().size(), 0); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-207 remove, covered by field validator test
 *
 * @given some user with can_create_domain permission
 * @when execute tx with CreateDomain command with maximum available length
 * @then there is the tx in proposal
 */
TEST_P(CreateDomain, MaxLenName) {
  std::string maxLongDomain =
      // 255 characters string
      "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
      "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
      "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad."
      "maxLabelLengthIs63paddingPaddingPaddingPaddingPaddingPaddingPad";
    IntegrationTestFramework(1, GetParam())
        .setInitialState(kAdminKeypair)
        .sendTx(makeUserWithPerms())
        .skipProposal()
        .skipBlock()
        .sendTxAwait(
            complete(baseTx().createDomain(maxLongDomain, kRole)),
            [](auto &block) { ASSERT_EQ(block->transactions().size(), 1); });
}

/**
 * TODO mboldyrev 18.01.2019 IR-207 remove, covered by field validator test
 *
 * @given some user with can_create_domain permission
 * @when execute tx with CreateDomain command with too long length
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_P(CreateDomain, TooLongName) {
    IntegrationTestFramework(1, GetParam())
        .setInitialState(kAdminKeypair)
        .sendTx(makeUserWithPerms())
        .skipProposal()
        .skipBlock()
        .sendTx(complete(baseTx().createDomain(std::string(257, 'a'), kRole)),
                CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-207 remove, covered by field validator test
 *
 * @given some user with can_create_domain permission
 * @when execute tx with CreateDomain command with empty domain name
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_P(CreateDomain, EmptyName) {
  std::string empty_name = "";
    IntegrationTestFramework(1, GetParam())
        .setInitialState(kAdminKeypair)
        .sendTx(makeUserWithPerms())
        .skipProposal()
        .skipBlock()
        .sendTx(complete(baseTx().createDomain(empty_name, kRole)),
                CHECK_STATELESS_INVALID);
}

/**
 * TODO mboldyrev 18.01.2019 IR-207 remove, covered by field validator test
 *
 * @given some user with can_create_domain permission
 * @when execute tx with CreateDomain command with empty role name
 * @then the tx hasn't passed stateless validation
 *       (aka skipProposal throws)
 */
TEST_P(CreateDomain, DISABLED_EmptyRoleName) {
  std::string empty_name = "";
    IntegrationTestFramework(1, GetParam())
        .setInitialState(kAdminKeypair)
        .sendTx(makeUserWithPerms())
        .skipProposal()
        .skipBlock()
        .sendTx(complete(baseTx().createDomain(kNewDomain, empty_name)),
                CHECK_STATELESS_INVALID);
}
