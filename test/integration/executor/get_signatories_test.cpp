/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <vector>

#include <fmt/format.h>
#include <gtest/gtest.h>
#include "framework/common_constants.hpp"
#include "integration/executor/query_permission_test.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using iroha::ametsuchi::QueryExecutorResult;
using shared_model::interface::SignatoriesResponse;
using shared_model::interface::permissions::Role;

struct GetSignatoriesTest : public ExecutorTestBase {
  /**
   * Generate a public key in format `public_key_NNNN', where NNNN is
   * a zero-padded serial number.
   */
  std::string makePubKey(size_t n) {
    return fmt::format("public_key_{:04}", n);
  }

  /**
   * Add the given number of signatories to the default account.
   * Signatories' public keys are generated with @see makePubKey with the number
   * in the order of creation.
   */
  void addSignatories(size_t n) {
    SCOPED_TRACE("addSignatories");
    for (size_t i = 0; i < n; ++i) {
      signatories_.emplace_back(makePubKey(i));
      IROHA_ASSERT_RESULT_VALUE(getItf().executeMaintenanceCommand(
          *getItf().getMockCommandFactory()->constructAddSignatory(
              shared_model::interface::types::PublicKeyHexStringView{
                  signatories_.back()},
              kUserId)));
    }
  }

  void prepareState(size_t n) {
    SCOPED_TRACE("prepareState");
    getItf().createDomain(kSecondDomain);
    using shared_model::interface::types::PublicKeyHexStringView;
    IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
        kUser, kDomain, PublicKeyHexStringView{kUserKeypair.publicKey()}, {}));
    addSignatories(n);
  }

  /// Check the response.
  void validateResponse(const SignatoriesResponse &response) {
    EXPECT_THAT(response.keys(),
                ::testing::UnorderedElementsAreArray(signatories_));
  }

  /// Query account signatories.
  QueryExecutorResult query(AccountIdType command_issuer = kAdminId) {
    return getItf().executeQuery(
        *getItf().getMockQueryFactory()->constructGetSignatories(kUserId),
        command_issuer);
  }

  /// The signatories of the default account.
  std::vector<std::string> signatories_{kUserKeypair.publicKey()};
};

using GetSignatoriesBasicTest = BasicExecutorTest<GetSignatoriesTest>;

/**
 * @given a user with all related permissions
 * @when GetSignatories is queried on a nonexistent user
 * @then there is an error
 */
TEST_P(GetSignatoriesBasicTest, InvalidNoAccount) {
  checkQueryError<shared_model::interface::NoSignatoriesErrorResponse>(
      getItf().executeQuery(
          *getItf().getMockQueryFactory()->constructGetSignatories(kUserId)),
      error_codes::kNoStatefulError);
}

INSTANTIATE_TEST_SUITE_P(Base,
                         GetSignatoriesBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using GetSignatoriesPermissionTest =
    query_permission_test::QueryPermissionTest<GetSignatoriesTest>;

TEST_P(GetSignatoriesPermissionTest, QueryPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(prepareState({}));
  addSignatories(2);
  checkResponse<SignatoriesResponse>(
      query(getSpectator()), [this](const SignatoriesResponse &response) {
        this->validateResponse(response);
      });
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    GetSignatoriesPermissionTest,
    query_permission_test::getParams({Role::kGetMySignatories},
                                     {Role::kGetDomainSignatories},
                                     {Role::kGetAllSignatories}),
    query_permission_test::paramToString);
