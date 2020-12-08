/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <gtest/gtest.h>
#include <boost/format.hpp>
#include "backend/protobuf/queries/proto_query.hpp"
#include "framework/common_constants.hpp"
#include "integration/executor/query_permission_test.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using iroha::ametsuchi::QueryExecutorResult;
using shared_model::interface::Amount;
using shared_model::interface::permissions::Role;

struct GetAccountAssetsTest : public ExecutorTestBase {
  std::string makeAssetName(size_t i) {
    return (boost::format("asset_%03d") % i).str();
  }

  std::string makeAssetDomain(size_t i) {
    return i % 2 ? kDomain : kSecondDomain;
  }

  AssetIdType makeAssetId(size_t i) {
    return makeAssetName(i) + "#" + makeAssetDomain(i);
  }

  Amount makeAssetQuantity(size_t n) {
    return Amount{(boost::format("%d.0") % n).str()};
  }

  /**
   * Create new assets and add some quantity to the default account.
   * Asset names are `asset_NNN`, where NNN is zero-padded number in the
   * order of creation. Asset precision is 1. The quantity added equals the
   * asset number.
   */
  void createAndAddAssets(size_t n) {
    SCOPED_TRACE("createAndAddAssets");
    for (size_t i = 0; i < n; ++i) {
      createAsset(makeAssetName(i), makeAssetDomain(i), 1);
      auto asset_id = makeAssetId(i);
      auto quantity = makeAssetQuantity(i);
      addAsset(kUserId, asset_id, quantity);
      ++assets_added_;
    }
  }

  void prepareState(size_t n) {
    SCOPED_TRACE("prepareState");
    getItf().createDomain(kSecondDomain);
    IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
        kUser,
        kDomain,
        PublicKeyHexStringView{kUserKeypair.publicKey()},
        {Role::kReceive}));
    createAndAddAssets(n);
  }

  /**
   * Check the page response.
   * @param response the response of GetAccountAssets query
   * @param requested_page_start requested first asset (according to the order
   * of addition)
   * @param page_size requested page size
   */
  void validatePageResponse(
      const shared_model::interface::AccountAssetResponse &response,
      boost::optional<size_t> requested_page_start,
      size_t page_size) {
    size_t page_start = requested_page_start.value_or(0);
    ASSERT_LE(page_start, assets_added_) << "Bad test.";
    const bool is_last_page = page_start + page_size >= assets_added_;
    const size_t expected_page_size =
        is_last_page ? assets_added_ - page_start : page_size;
    EXPECT_EQ(response.accountAssets().size(), expected_page_size);
    EXPECT_EQ(response.totalAccountAssetsNumber(), assets_added_);
    if (is_last_page) {
      EXPECT_FALSE(response.nextAssetId());
    } else {
      if (not response.nextAssetId()) {
        ADD_FAILURE() << "nextAssetId not set!";
      } else {
        EXPECT_EQ(*response.nextAssetId(),
                  this->makeAssetId(page_start + page_size));
      }
    }
    for (size_t i = 0; i < response.accountAssets().size(); ++i) {
      EXPECT_EQ(response.accountAssets()[i].assetId(),
                this->makeAssetId(page_start + i));
      EXPECT_EQ(response.accountAssets()[i].balance(),
                this->makeAssetQuantity(page_start + i));
      EXPECT_EQ(response.accountAssets()[i].accountId(), kUserId);
    }
  }

  void validatePageResponse(const QueryExecutorResult &response,
                            boost::optional<size_t> page_start,
                            size_t page_size) {
    checkSuccessfulResult<shared_model::interface::AccountAssetResponse>(
        response, [&, this](const auto &response) {
          this->validatePageResponse(response, page_start, page_size);
        });
  }

  std::unique_ptr<shared_model::interface::MockAssetPaginationMeta>
  makePaginationMeta(TransactionsNumberType page_size,
                     std::optional<AssetIdType> first_asset_id) {
    return getItf().getMockQueryFactory()->constructAssetPaginationMeta(
        page_size, std::move(first_asset_id));
  }

  /**
   * Query account assets.
   */
  QueryExecutorResult queryPage(boost::optional<size_t> page_start,
                                size_t page_size,
                                AccountIdType command_issuer = kAdminId) {
    std::optional<AssetIdType> first_asset_id;
    if (page_start) {
      first_asset_id = makeAssetId(page_start.value());
    }
    auto pagination_meta = makePaginationMeta(page_size, first_asset_id);
    return getItf().executeQuery(
        *getItf().getMockQueryFactory()->constructGetAccountAssets(
            kUserId, *pagination_meta),
        command_issuer);
  }

  /**
   * Query account assets and validate the response.
   */
  QueryExecutorResult queryPageAndValidateResponse(
      boost::optional<size_t> page_start, size_t page_size) {
    auto response = queryPage(page_start, page_size);
    validatePageResponse(response, page_start, page_size);
    return response;
  }

  /// The number of assets added to the default account.
  size_t assets_added_{0};
};

using GetAccountAssetsBasicTest = BasicExecutorTest<GetAccountAssetsTest>;

/**
 * @given two users with all related permissions
 * @when GetAccountAssets is queried on the user with no assets
 * @then there is an AccountAssetResponse reporting no asset presence
 */
TEST_P(GetAccountAssetsBasicTest, NoAssets) {
  IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
      kUser, kDomain, PublicKeyHexStringView{kUserKeypair.publicKey()}, {}));

  checkAssetQuantities(kUserId, {});
}

/**
 * @given a user with all related permissions
 * @when GetAccountAssets is queried on a nonexistent user
 * @then there is an error
 */
TEST_P(GetAccountAssetsBasicTest, InvalidNoAccount) {
  checkAssetQuantities(kUserId, {});
}

/**
 * @given account with all related permissions and 10 assets
 * @when queried assets with page metadata not set
 * @then all 10 asset values are returned and are valid
 */
TEST_P(GetAccountAssetsBasicTest, NoPageMetaData) {
  prepareState(10);
  QueryExecutorResult response = getItf().executeQuery(
      *getItf().getMockQueryFactory()->constructGetAccountAssets(kUserId,
                                                                 std::nullopt));
  validatePageResponse(response, boost::none, 10);
}

/**
 * @given account with all related permissions and 10 assets
 * @when queried assets first page of size 5
 * @then first 5 asset values are returned and are valid
 */
TEST_P(GetAccountAssetsBasicTest, FirstPage) {
  ASSERT_NO_FATAL_FAILURE(prepareState(10));
  queryPageAndValidateResponse(boost::none, 5);
}

/**
 * @given account with all related permissions and 10 assets
 * @when queried assets page of size 5 starting from 3rd asset
 * @then assets' #3 to #7 values are returned and are valid
 */
TEST_P(GetAccountAssetsBasicTest, MiddlePage) {
  ASSERT_NO_FATAL_FAILURE(prepareState(10));
  queryPageAndValidateResponse(3, 5);
}

/**
 * @given account with all related permissions and 10 assets
 * @when queried assets page of size 5 starting from 5th asset
 * @then assets' #5 to #9 values are returned and are valid
 */
TEST_P(GetAccountAssetsBasicTest, LastPage) {
  ASSERT_NO_FATAL_FAILURE(prepareState(10));
  queryPageAndValidateResponse(5, 5);
}

/**
 * @given account with all related permissions and 10 assets
 * @when queried assets page of size 5 starting from 8th asset
 * @then assets' #8 to #9 values are returned and are valid
 */
TEST_P(GetAccountAssetsBasicTest, PastLastPage) {
  ASSERT_NO_FATAL_FAILURE(prepareState(10));
  queryPageAndValidateResponse(8, 5);
}

/**
 * @given account with all related permissions and 10 assets
 * @when queried assets page of size 5 starting from unknown asset
 * @then error response is returned
 */
TEST_P(GetAccountAssetsBasicTest, NonexistentStartTx) {
  ASSERT_NO_FATAL_FAILURE(prepareState(10));
  auto response = queryPage(10, 5);
  checkQueryError<shared_model::interface::StatefulFailedErrorResponse>(
      response, error_codes::kInvalidPagination);
}

INSTANTIATE_TEST_SUITE_P(Base,
                         GetAccountAssetsBasicTest,
                         executor_testing::getExecutorTestParams(),
                         executor_testing::paramToString);

using GetAccountAssetsPermissionTest =
    query_permission_test::QueryPermissionTest<GetAccountAssetsTest>;

TEST_P(GetAccountAssetsPermissionTest, QueryPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(prepareState({Role::kReceive}));
  createAndAddAssets(2);
  auto pagination_meta = makePaginationMeta(assets_added_, std::nullopt);
  checkResponse<shared_model::interface::AccountAssetResponse>(
      queryPage(boost::none, assets_added_, getSpectator()),
      [this](const shared_model::interface::AccountAssetResponse &response) {
        this->validatePageResponse(response, boost::none, assets_added_);
      });
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    GetAccountAssetsPermissionTest,
    query_permission_test::getParams({Role::kGetMyAccAst},
                                     {Role::kGetDomainAccAst},
                                     {Role::kGetAllAccAst}),
    query_permission_test::paramToString);
