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
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/permissions.hpp"

namespace executor_testing {
  namespace command_permission_test {

    struct SpecificCommandPermissionTestData {
      shared_model::interface::RolePermissionSet actor_role_permissions;
      boost::optional<shared_model::interface::permissions::Grantable>
          actor_grantable_permission;
      bool validation_enabled;
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
              std::tuple<ExecutorTestParamProvider,
                         SpecificCommandPermissionTestData>> {
      CommandPermissionTest()
          : backend_param_(std::get<0>(GetParam())()),
            permissions_param_(std::get<1>(GetParam())) {}

      iroha::integration_framework::ExecutorItf &getItf() {
        return SpecificCommandFixture::getItf();
      }

      /**
       * Prepare state of ledger:
       * - create accounts of target user and actor.
       *
       * @param additional_target_permissions - set of additional role
       * permissions for target user
       * @param additional_actor_permissions - set of additional role
       * permissions for actor user (the tested command author)
       */
      void prepareState(shared_model::interface::RolePermissionSet
                            additional_target_permissions = {},
                        shared_model::interface::RolePermissionSet
                            additional_actor_permissions = {}) {
        using namespace common_constants;
        using namespace framework::expected;
        using shared_model::interface::types::PublicKeyHexStringView;

        auto &target_permissions = additional_target_permissions;
        if (getActor() == kUserId) {
          target_permissions |= additional_actor_permissions;
        }
        // target user role permissions
        target_permissions |= permissions_param_.actor_role_permissions;
        if (permissions_param_.actor_grantable_permission) {
          target_permissions.set(
              shared_model::interface::permissions::permissionFor(
                  permissions_param_.actor_grantable_permission.value()));
        }

        // create target user
        IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
            kUser,
            kDomain,
            PublicKeyHexStringView{kUserKeypair.publicKey()},
            target_permissions));

        if (getActor() != kUserId) {
          auto &actor_permissions = additional_actor_permissions;
          actor_permissions |= permissions_param_.actor_role_permissions;
          auto split_actor_id = splitAccountId(getActor());
          IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
              split_actor_id.first,
              split_actor_id.second,
              PublicKeyHexStringView{kSameDomainUserKeypair.publicKey()},
              actor_permissions));
        }

        // grant current actor the permissions
        if (permissions_param_.actor_grantable_permission) {
          IROHA_ASSERT_RESULT_VALUE(getItf().executeCommandAsAccount(
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

      bool getValidationEnabled() const {
        return permissions_param_.validation_enabled;
      }

      bool isEnoughPermissions() const {
        return permissions_param_.enough_permissions;
      }

      /**
       * Check a response.
       * @return whether response is success or error.
       */
      bool checkResponse(const iroha::ametsuchi::CommandResult &response) {
        if (isEnoughPermissions()) {
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
      virtual ExecutorTestParam &getBackendParam() {
        return backend_param_;
      }

     private:
      ExecutorTestParam &backend_param_;
      const SpecificCommandPermissionTestData &permissions_param_;
    };

    std::string paramToString(
        testing::TestParamInfo<std::tuple<ExecutorTestParamProvider,
                                          SpecificCommandPermissionTestData>>
            param);

  }  // namespace command_permission_test
}  // namespace executor_testing

#endif /* EXECUTOR_COMMAND_PERMISSION_TEST_HPP */
