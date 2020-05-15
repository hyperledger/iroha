/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include "common/result.hpp"
#include "framework/common_constants.hpp"
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

static const RoleIdType kAnotherRole("another_role");

class CreateRoleTest : public ExecutorTestBase {
 public:
  iroha::ametsuchi::CommandResult createRole(
      const AccountIdType &issuer,
      const shared_model::interface::RolePermissionSet &permissions,
      bool validation_enabled = true) {
    return getItf().executeCommandAsAccount(
        *getItf().getMockCommandFactory()->constructCreateRole(kAnotherRole,
                                                               permissions),
        issuer,
        validation_enabled);
  }

  auto getRolePerms(const RoleIdType &role) {
    return getItf().executeQueryAndConvertResult(
        *getItf().getMockQueryFactory()->constructGetRolePermissions(role));
  }

  void checkRole(
      const RoleIdType &role,
      const shared_model::interface::RolePermissionSet &ref_permissions) {
    getRolePerms(role).specific_response.match(
        [&](const auto &test_permissions) {
          EXPECT_EQ(test_permissions.value.rolePermissions(), ref_permissions)
              << "Wrong set of permissions for role " << role;
        },
        [](const auto &e) { ADD_FAILURE() << e.error->toString(); });
  }

  void checkNoSuchRole(const RoleIdType &role) {
    IROHA_ASSERT_RESULT_ERROR(getRolePerms(role).specific_response);
  }
};

using CreateRoleBasicTest = BasicExecutorTest<CreateRoleTest>;

/**
 * @given a user with all kCreateRole permission
 * @when executes CreateRole command with empty permission set
 * @then the command succeeds and the role is created
 */
TEST_P(CreateRoleBasicTest, ValidEmptyPerms) {
  getItf().createUserWithPerms(kUser,
                               kDomain,
                               PublicKeyHexStringView{kUserKeypair.publicKey()},
                               {Role::kCreateRole});
  IROHA_ASSERT_RESULT_VALUE(createRole(kUserId, {}));
  checkRole(kAnotherRole, {});
}

/**
 * @given a user with all related permissions
 * @when executes CreateRole command with occupied name and other permissions
 * @then the command does not succeed and the existing role is not changed
 */
TEST_P(CreateRoleBasicTest, NameExists) {
  getItf().createUserWithPerms(kUser,
                               kDomain,
                               PublicKeyHexStringView{kUserKeypair.publicKey()},
                               {Role::kCreateRole, Role::kCreateAsset});
  IROHA_ASSERT_RESULT_VALUE(createRole(kUserId, {Role::kCreateRole}));
  ASSERT_NO_FATAL_FAILURE(checkRole(kAnotherRole, {Role::kCreateRole}));
  checkCommandError(createRole(kUserId, {Role::kCreateAsset}), 3);
  checkRole(kAnotherRole, {Role::kCreateRole});
}

INSTANTIATE_TEST_SUITE_P(Base,
                         CreateRoleBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using CreateRolePermissionTest =
    command_permission_test::CommandPermissionTest<CreateRoleTest>;

TEST_P(CreateRolePermissionTest, CommandPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(getItf().createDomain(kSecondDomain));
  ASSERT_NO_FATAL_FAILURE(prepareState({}, {Role::kCreateAsset}));

  if (checkResponse(createRole(
          getActor(), {Role::kCreateAsset}, getValidationEnabled()))) {
    checkRole(kAnotherRole, {Role::kCreateAsset});
  } else {
    checkNoSuchRole(kAnotherRole);
  }
}

INSTANTIATE_TEST_SUITE_P(Common,
                         CreateRolePermissionTest,
                         command_permission_test::getParams(boost::none,
                                                            boost::none,
                                                            Role::kCreateRole,
                                                            boost::none),
                         command_permission_test::paramToString);
