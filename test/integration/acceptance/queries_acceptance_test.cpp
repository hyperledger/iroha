/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/query_responses/roles_response.hpp"
#include "utils/query_error_response_visitor.hpp"

using namespace integration_framework;
using namespace shared_model;
using namespace shared_model::interface::types;
using namespace common_constants;

class QueriesAcceptanceTest : public AcceptanceFixture {
 public:
  void SetUp() {
    itf.setInitialState(kAdminSigner)
        .sendTxAwait(
            makeUserWithPerms({interface::permissions::Role::kGetRoles}),
            [](auto &block) {
              ASSERT_EQ(boost::size(block->transactions()), 1);
            });
  };

  static void checkRolesResponse(const proto::QueryResponse &response) {
    ASSERT_NO_THROW({
      const auto &resp =
          boost::get<const shared_model::interface::RolesResponse &>(
              response.get());
      ASSERT_NE(resp.roles().size(), 0);
    });
  }

  IntegrationTestFramework itf{1};
  const std::string NonExistentUserId = "aaaa@aaaa";
};

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a SFV integration test
 * (possibly including torii query processor)
 *
 * @given query with a non-existent creator_account_id
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateful validation
 */
TEST_F(QueriesAcceptanceTest, NonExistentCreatorId) {
  auto query = complete(baseQry(NonExistentUserId).getRoles());

  itf.sendQuery(
      query, checkQueryErrorResponse<interface::StatefulFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with an 1 hour old UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query returns list of roles
 */
TEST_F(QueriesAcceptanceTest, OneHourOldTime) {
  auto query =
      complete(baseQry()
                   .createdTime(iroha::time::now(std::chrono::hours(-1)))
                   .getRoles());

  itf.sendQuery(query, checkRolesResponse);
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with more than 24 hour old UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, More24HourOldTime) {
  auto query =
      complete(baseQry()
                   .createdTime(iroha::time::now(std::chrono::hours(-24)
                                                 - std::chrono::seconds(1)))
                   .getRoles());

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with less than 24 hour old UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query returns list of roles
 */
TEST_F(QueriesAcceptanceTest, Less24HourOldTime) {
  auto query =
      complete(baseQry()
                   .createdTime(iroha::time::now(std::chrono::hours(-24)
                                                 + std::chrono::seconds(1)))
                   .getRoles());

  itf.sendQuery(query, checkRolesResponse);
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with less than 5 minutes from future UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query returns list of roles
 */
TEST_F(QueriesAcceptanceTest, LessFiveMinutesFromFuture) {
  auto query =
      complete(baseQry()
                   .createdTime(iroha::time::now(std::chrono::minutes(5)
                                                 - std::chrono::seconds(1)))
                   .getRoles());

  itf.sendQuery(query, checkRolesResponse);
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with 5 minutes from future UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query returns list of roles
 */
TEST_F(QueriesAcceptanceTest, FiveMinutesFromFuture) {
  auto query =
      complete(baseQry()
                   .createdTime(iroha::time::now(std::chrono::minutes(5)))
                   .getRoles());

  itf.sendQuery(query, checkRolesResponse);
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with more than 5 minutes from future UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, MoreFiveMinutesFromFuture) {
  auto query =
      complete(baseQry()
                   .createdTime(iroha::time::now(std::chrono::minutes(5)
                                                 + std::chrono::seconds(1)))
                   .getRoles());

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with 10 minutes from future UNIX time
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, TenMinutesFromFuture) {
  auto query =
      complete(baseQry()
                   .createdTime(iroha::time::now(std::chrono::minutes(10)))
                   .getRoles());

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a crypto provider unit test
 * Note a similar test: AcceptanceTest.TransactionInvalidPublicKey
 *
 * @given query with Keypair which contains invalid signature but valid public
 * key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, InvalidSignValidPubKeypair) {
  auto proto_query = complete(baseQry().getRoles()).getTransport();

  proto_query.mutable_signature()->set_signature("BAAD");
  auto query = proto::Query(proto_query);

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a crypto provider unit test
 *
 * @given query with Keypair which contains valid signature but invalid public
 * key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, ValidSignInvalidPubKeypair) {
  auto proto_query = complete(baseQry().getRoles()).getTransport();

  proto_query.mutable_signature()->set_public_key("BAAD");
  auto query = proto::Query(proto_query);

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a SFV integration test
 *
 * @given query with Keypair which contains invalid signature and invalid public
 * key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, FullyInvalidKeypair) {
  auto proto_query = complete(baseQry().getRoles()).getTransport();

  proto_query.mutable_signature()->set_signature("BAD1");
  proto_query.mutable_signature()->set_public_key("BAD2");
  auto query = proto::Query(proto_query);

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a crypto provider unit test
 * Note a similar test: AcceptanceTest.EmptySignatures
 *
 * @given query with Keypair which contains empty signature and valid public key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, EmptySignValidPubKeypair) {
  auto proto_query = complete(baseQry().getRoles()).getTransport();

  proto_query.clear_signature();
  auto query = proto::Query(proto_query);

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 remove, covered by field validator test
 *
 * @given query with Keypair which contains valid signature and empty public key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, ValidSignEmptyPubKeypair) {
  auto proto_query = complete(baseQry().getRoles()).getTransport();

  proto_query.mutable_signature()->clear_public_key();
  auto query = proto::Query(proto_query);

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a crypto provider unit test
 *
 * @given query with Keypair which contains empty signature and empty public key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, FullyEmptyPubKeypair) {
  auto proto_query = complete(baseQry().getRoles()).getTransport();

  proto_query.clear_signature();
  proto_query.mutable_signature()->clear_public_key();
  auto query = proto::Query(proto_query);

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a crypto provider unit test
 *
 * @given query with Keypair which contains invalid signature and empty public
 * key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, InvalidSignEmptyPubKeypair) {
  auto proto_query = complete(baseQry().getRoles()).getTransport();

  proto_query.mutable_signature()->set_signature("BAAD");
  proto_query.mutable_signature()->clear_public_key();
  auto query = proto::Query(proto_query);

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}

/**
 * TODO mboldyrev 18.01.2019 IR-218 convert to a SFV integration test
 * including SignableModelValidator or even whole torii::QueryService
 * and the crypto provider, that verifies that a transaction failing the
 * crypto provider check is rejected.
 *
 *
 * @given query with Keypair which contains empty signature and invalid public
 * key
 * @when execute any correct query with kGetRoles permissions
 * @then the query should not pass stateless validation
 */
TEST_F(QueriesAcceptanceTest, EmptySignInvalidPubKeypair) {
  auto proto_query = complete(baseQry().getRoles()).getTransport();

  proto_query.clear_signature();
  proto_query.mutable_signature()->set_public_key("BAAD");
  auto query = proto::Query(proto_query);

  itf.sendQuery(
      query,
      checkQueryErrorResponse<interface::StatelessFailedErrorResponse>());
}
