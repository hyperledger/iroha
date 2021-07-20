/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef QUERY_PERMISSION_FIXTURE_HPP_
#define QUERY_PERMISSION_FIXTURE_HPP_

#include "framework/integration_framework/integration_test_framework.hpp"
#include "integration/acceptance/acceptance_fixture.hpp"

using namespace shared_model;
using namespace integration_framework;
using namespace shared_model::interface::permissions;

template <class QueryPermissionTest>
class QueryPermissionFixture : public AcceptanceFixture {
 public:
  using ParamType = QueryPermissionTest;
  QueryPermissionTest impl_;

 protected:
  void SetUp() override {
    impl_.itf_ = std::make_unique<IntegrationTestFramework>(
        1, iroha::StorageType::kRocksDb);
    impl_.itf_->setInitialState(common_constants::kAdminKeypair);
  }
};

#endif /* QUERY_PERMISSION_FIXTURE_HPP_ */
