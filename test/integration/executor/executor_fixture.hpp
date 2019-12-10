/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_INTEGRATION_EXECUTOR_FIXTURE_HPP
#define TEST_INTEGRATION_EXECUTOR_FIXTURE_HPP

#include "framework/executor_itf/executor_itf.hpp"

#include <gtest/gtest.h>
#include "common/result.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "framework/common_constants.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "integration/executor/executor_fixture_param.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"
#include "utils/query_error_response_checker.hpp"

namespace executor_testing {

  namespace error_codes {
    using shared_model::interface::ErrorQueryResponse;

    // TODO [IR-1816] Akvinikym 06.12.18: remove these constants after
    // introducing a uniform way to use them in code
    static constexpr ErrorQueryResponse::ErrorCodeType kNoStatefulError = 0;
    static constexpr ErrorQueryResponse::ErrorCodeType kNoPermissions = 2;
    static constexpr ErrorQueryResponse::ErrorCodeType kInvalidPagination = 4;
    static constexpr ErrorQueryResponse::ErrorCodeType kInvalidAccountId = 5;
    static constexpr ErrorQueryResponse::ErrorCodeType kInvalidAssetId = 6;
    static constexpr ErrorQueryResponse::ErrorCodeType kInvalidHeight = 3;
  }  // namespace error_codes

  std::pair<std::string, std::string> splitAssetId(const std::string &id);

  std::pair<std::string, std::string> splitAccountId(const std::string &id);

  /**
   * Check that general query response contains a specific result type and
   * execute a callback on it.
   * @tparam SpecificQueryResponse - Expected specific query response.
   * @tparam Callback - Type of callback.
   * @param response - The response to be checked.
   * @param callback - The callback to be executed on specific result.
   */
  template <typename SpecificQueryResponse, typename Callback>
  void checkSuccessfulResult(
      const iroha::ametsuchi::QueryExecutorResult &response,
      Callback callback) {
    auto specific_result =
        boost::strict_get<const SpecificQueryResponse &>(&response->get());
    if (not specific_result) {
      ADD_FAILURE() << "Wrong query response type: " << response->toString();
      return;
    }
    std::forward<Callback>(callback)(*specific_result);
  }

  /**
   * Check that general command response contains an error with a specific error
   * code.
   * @param command_result - The response to be checked.
   * @param error_code - The expected error code.
   */
  void checkCommandError(
      const iroha::ametsuchi::CommandResult &command_result,
      iroha::ametsuchi::CommandError::ErrorCodeType error_code);

  /**
   * Check that general query response contains a specific error type and
   * execute a callback on it.
   * @param response - The response to be checked.
   * @param error_type - Expected specific query error type.
   * @param error_code - The expected error code.
   */
  void checkQueryError(
      const iroha::ametsuchi::QueryExecutorResult &response,
      shared_model::interface::QueryErrorType error_type,
      shared_model::interface::ErrorQueryResponse::ErrorCodeType error_code);

  /// Base class for Executor ITF tests.
  class ExecutorTestBase : public ::testing::Test {
   public:
    void SetUp();

    iroha::integration_framework::ExecutorItf &getItf() const;

    //  ---------------- ledger populators --------------

    void createAsset(
        const std::string &name,
        const std::string &domain,
        shared_model::interface::types::PrecisionType precision) const;

    void addAsset(
        const shared_model::interface::types::AccountIdType &dest_account_id,
        const shared_model::interface::types::AssetIdType &asset_id,
        const shared_model::interface::Amount &quantity);

    //  ---------------- checkers -----------------

    /// A plain representation of an asset quantity.
    struct AssetQuantity {
      AssetQuantity(std::string asset_id,
                    shared_model::interface::Amount balance)
          : asset_id(std::move(asset_id)), balance(std::move(balance)) {}
      std::string asset_id;
      shared_model::interface::Amount balance;
    };

    /**
     * Check that the given account assets collection contains the reference
     * assets and quantities.
     */
    static void checkAssetQuantities(
        const shared_model::interface::types::AccountAssetCollectionType
            &test_quantities,
        const std::vector<AssetQuantity> &reference_quantities);

    /**
     * Check that the given account contains the exact provided assets and
     * quantities.
     */
    void checkAssetQuantities(const std::string &account_id,
                              const std::vector<AssetQuantity> &quantities);

    /// Check that the given account contains the exact provided signatures.
    void checkSignatories(
        const std::string &account_id,
        const std::vector<shared_model::crypto::PublicKey> &keys);

   protected:
    virtual std::shared_ptr<ExecutorTestParam> getBackendParam() = 0;

   private:
    std::unique_ptr<iroha::integration_framework::ExecutorItf> executor_itf_;
  };

  /**
   * A class that provides the backend parameter from GTest parametric test.
   * @tparam SpecificQueryFixture Is supposed to be either ExecutorTestBase or
   * its derivative.
   *
   * When different test cases require different parameters, users are supposed
   * to implement the required logic in a class derived from ExecutorTestBase,
   * and then derive from it helper classes like this to instantiate different
   * parametric cases.
   */
  template <typename SpecificQueryFixture>
  class BasicExecutorTest : public SpecificQueryFixture,
                            public ::testing::WithParamInterface<
                                std::shared_ptr<ExecutorTestParam>> {
   protected:
    virtual std::shared_ptr<ExecutorTestParam> getBackendParam() {
      return GetParam();
    }
  };

}  // namespace executor_testing

#endif /* TEST_INTEGRATION_EXECUTOR_FIXTURE_HPP */
