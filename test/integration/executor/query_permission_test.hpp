/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef EXECUTOR_QUERY_PERMISSION_TEST_HPP
#define EXECUTOR_QUERY_PERMISSION_TEST_HPP

#include "framework/common_constants.hpp"
#include "framework/executor_itf/executor_itf.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "integration/executor/executor_fixture.hpp"
#include "integration/executor/executor_fixture_param_provider.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/permissions.hpp"

namespace executor_testing {
  namespace query_permission_test {

    struct SpecificQueryPermissionTestData {
      shared_model::interface::RolePermissionSet spectator_permissions;
      shared_model::interface::types::AccountIdType spectator;
      bool enough_permissions;
      std::string description;
    };

    decltype(::testing::Combine(
        executor_testing::getExecutorTestParams(),
        ::testing::ValuesIn({SpecificQueryPermissionTestData{}})))
    getParams(boost::optional<shared_model::interface::permissions::Role>
                  permission_to_query_myself,
              boost::optional<shared_model::interface::permissions::Role>
                  permission_to_query_my_domain,
              boost::optional<shared_model::interface::permissions::Role>
                  permission_to_query_everyone);

    template <typename SpecificQueryFixture>
    struct QueryPermissionTest
        : public SpecificQueryFixture,
          public ::testing::WithParamInterface<
              std::tuple<ExecutorTestParamProvider,
                         SpecificQueryPermissionTestData>> {
      QueryPermissionTest()
          : backend_param_(std::get<0>(GetParam())()),
            permissions_param_(std::get<1>(GetParam())) {}

      iroha::integration_framework::ExecutorItf &getItf() {
        return SpecificQueryFixture::getItf();
      }

      /**
       * Prepare state of ledger:
       * - create accounts of target user, close and remote spectators. Close
       *   spectator is another user from the same domain as the domain of
       * target user account, remote - a user from domain different to domain
       * of target user account.
       *
       * @param target_permissions - set of permissions for target user
       */
      void prepareState(
          shared_model::interface::RolePermissionSet target_permissions) {
        using namespace common_constants;
        using namespace framework::expected;
        using shared_model::interface::types::PublicKeyHexStringView;
        // create target user
        target_permissions |= permissions_param_.spectator_permissions;
        IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
            kUser,
            kDomain,
            PublicKeyHexStringView{kUserKeypair.publicKey()},
            target_permissions));
        // create spectators
        IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
            kSecondUser,
            kDomain,
            PublicKeyHexStringView{kSameDomainUserKeypair.publicKey()},
            permissions_param_.spectator_permissions));
        IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
            kSecondUser,
            kSecondDomain,
            PublicKeyHexStringView{kSecondDomainUserKeypair.publicKey()},
            permissions_param_.spectator_permissions));
      }

      const shared_model::interface::types::AccountIdType &getSpectator()
          const {
        return permissions_param_.spectator;
      }

      /// Check a response.
      template <typename SpecificQueryResponse,
                typename SpecificQueryResponseChecker>
      void checkResponse(const iroha::ametsuchi::QueryExecutorResult &response,
                         SpecificQueryResponseChecker checker) {
        if (permissions_param_.enough_permissions) {
          checkSuccessfulResult<SpecificQueryResponse>(response, checker);
        } else {
          checkQueryError<shared_model::interface::StatefulFailedErrorResponse>(
              response, error_codes::kNoPermissions);
        }
      }

     protected:
      virtual ExecutorTestParam &getBackendParam() {
        return backend_param_;
      }

     private:
      ExecutorTestParam &backend_param_;
      const SpecificQueryPermissionTestData &permissions_param_;
    };

    std::string paramToString(
        testing::TestParamInfo<std::tuple<ExecutorTestParamProvider,
                                          SpecificQueryPermissionTestData>>
            param);

  }  // namespace query_permission_test
}  // namespace executor_testing

#endif /* EXECUTOR_QUERY_PERMISSION_TEST_HPP */
