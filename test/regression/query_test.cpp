/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <boost/variant.hpp>
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "builders/protobuf/queries.hpp"
#include "framework/common_constants.hpp"
#include "framework/crypto_literals.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "interfaces/query_responses/error_responses/stateless_failed_error_response.hpp"
#include "module/shared_model/builders/protobuf/test_query_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"

using namespace common_constants;
using namespace shared_model::interface::types;

using shared_model::interface::types::PublicKeyHexStringView;

template <typename BaseType>
auto makeQuery() {
  return BaseType()
      .createdTime(iroha::time::now())
      .creatorAccountId("admin@test")
      .queryCounter(1)
      .getAccount("admin@test")
      .build();
}

/**
 * @given itf instance
 * @when  pass query with invalid signature
 * @then  assure that query with invalid signature is failed with stateless
 * error
 */
TEST(QueryTest, FailedQueryTest) {
  auto query_with_broken_signature = makeQuery<TestQueryBuilder>();
  query_with_broken_signature.addSignature("1715BAD"_hex_sig,
                                           kAdminSigner->publicKey());
  auto stateless_invalid_query_response = [](auto &status) {
    auto &resp =
        boost::get<const shared_model::interface::ErrorQueryResponse &>(
            status.get());
    boost::get<const shared_model::interface::StatelessFailedErrorResponse &>(
        resp.get());
  };

  integration_framework::IntegrationTestFramework itf(1);

  itf.setInitialState(kAdminSigner)
      .sendQuery(query_with_broken_signature, stateless_invalid_query_response);
}

/**
 * @given itf instance
 * @when  pass block query with invalid signature
 * @then  assure that query with invalid signature is failed with stateless
 * error
 */
TEST(QueryTest, FailedBlockQueryTest) {
  // TODO: 01/08/2018 @muratovv Implement test since IR-1569 will be completed
}
