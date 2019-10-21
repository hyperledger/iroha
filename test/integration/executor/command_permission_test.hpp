/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EXECUTOR_COMMAND_PERMISSION_TEST_HPP
#define EXECUTOR_COMMAND_PERMISSION_TEST_HPP

#include "framework/common_constants.hpp"
#include "framework/executor_itf/executor_itf.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "integration/executor/executor_fixture.hpp"
#include "integration/executor/executor_fixture_param_provider.hpp"
#include "interfaces/permissions.hpp"

namespace executor_testing {
  namespace command_permission_test {

    struct SpecificCommandPermissionTestData {
      shared_model::interface::RolePermissionSet actor_role_permissions;
      boost::optional<shared_model::interface::permissions::Grantable>
          actor_grantable_permission;
      shared_model::interface::types::AccountIdType actor;
      bool enough_permissions;
      std::string description;
    };

    decltype(::testing::Combine(
        executor_testing::getExecutorTestParams(),
        ::testing::ValuesIn({SpecificCommandPermissionTestData{}})))
    getParams(boost::optional<shared_model::interface::permissions::Role>
                  permission_for_myself,
              boost::optional<shared_model::interface::permissions::Role>
                  permission_for_my_domain,
              boost::optional<shared_model::interface::permissions::Role>
                  permission_for_everyone,
              boost::optional<shared_model::interface::permissions::Grantable>
                  grantable_permission,
              bool always_allowed_for_myself = false);

    template <typename SpecificCommandFixture>
    struct CommandPermissionTest
        : public SpecificCommandFixture,
          public ::testing::WithParamInterface<
              std::tuple<std::shared_ptr<ExecutorTestParam>,
                         SpecificCommandPermissionTestData>> {
      CommandPermissionTest()
          : backend_param_(std::get<0>(GetParam())),
            permissions_param_(std::get<1>(GetParam())) {}

      iroha::integration_framework::ExecutorItf &getItf() {
        return SpecificCommandFixture::getItf();
      }

      /**
       * Prepare state of ledger:
       * - create accounts of target user and actor.
       *
       * @param target_permissions - set of additional role permissions for
       * target user
       */
      void prepareState(
          shared_model::interface::RolePermissionSet target_permissions) {
        using namespace common_constants;
        using namespace framework::expected;

        // target user role permissions
        target_permissions |= permissions_param_.actor_role_permissions;
        if (permissions_param_.actor_grantable_permission) {
          target_permissions.set(
              shared_model::interface::permissions::permissionFor(
                  permissions_param_.actor_grantable_permission.value()));
        }

        // create target user
        assertResultValue(getItf().createUserWithPerms(
            kUser, kDomain, kUserKeypair.publicKey(), target_permissions));

        // create other actors
        assertResultValue(getItf().createUserWithPerms(
            kSecondUser,
            kDomain,
            kSameDomainUserKeypair.publicKey(),
            permissions_param_.actor_role_permissions));
        assertResultValue(getItf().createUserWithPerms(
            kSecondUser,
            kSecondDomain,
            kSecondDomainUserKeypair.publicKey(),
            permissions_param_.actor_role_permissions));

        // grant current actor the permissions
        if (permissions_param_.actor_grantable_permission) {
          assertResultValue(getItf().executeCommandAsAccount(
              *getItf().getMockCommandFactory()->constructGrantPermission(
                  permissions_param_.actor,
                  permissions_param_.actor_grantable_permission.value()),
              kUserId,
              true));
        }
      }

      const shared_model::interface::types::AccountIdType &getActor() const {
        return permissions_param_.actor;
      }

      /**
       * Check a response.
       * @return whether response is success or error.
       */
      bool checkResponse(const iroha::ametsuchi::CommandResult &response) {
        if (permissions_param_.enough_permissions) {
          if (auto e = iroha::expected::resultToOptionalError(response)) {
            ADD_FAILURE()
                << "The command has failed despite having enough permissions: "
                << e.value().toString();
          }
        } else {
          checkCommandError(response, error_codes::kNoPermissions);
        }
        return iroha::expected::hasValue(response);
      }

     protected:
      virtual std::shared_ptr<ExecutorTestParam> getBackendParam() {
        return backend_param_;
      }

     private:
      const std::shared_ptr<ExecutorTestParam> &backend_param_;
      const SpecificCommandPermissionTestData &permissions_param_;
    };

    std::string paramToString(
        testing::TestParamInfo<std::tuple<std::shared_ptr<ExecutorTestParam>,
                                          SpecificCommandPermissionTestData>>
            param);

  }  // namespace command_permission_test
}  // namespace executor_testing

#endif /* EXECUTOR_COMMAND_PERMISSION_TEST_HPP */
