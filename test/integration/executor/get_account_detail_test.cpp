/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "integration/executor/executor_fixture.hpp"

#include <map>

#include <fmt/core.h>
#include <gtest/gtest.h>
#include "backend/plain/account_detail_record_id.hpp"
#include "framework/common_constants.hpp"
#include "integration/executor/account_detail_checker.hpp"
#include "integration/executor/query_permission_test.hpp"
#include "interfaces/query_responses/account_detail_response.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"
#include "module/shared_model/mock_objects_factories/mock_query_factory.hpp"

using namespace common_constants;
using namespace executor_testing;
using namespace framework::expected;
using namespace shared_model::interface::types;

using iroha::ametsuchi::QueryExecutorResult;
using shared_model::interface::AccountDetailResponse;
using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;
using shared_model::interface::types::PublicKeyHexStringView;
using shared_model::plain::AccountDetailRecordId;

struct GetAccountDetailTest : public ExecutorTestBase {
  std::string makeAccountName(size_t i) const {
    return fmt::format("account_{:02}", i);
  }

  AccountIdType makeAccountId(size_t i) const {
    return makeAccountName(i) + "@" + kDomain;
  }

  std::string makeKey(size_t i) const {
    return fmt::format("key_{:02}", i);
  }

  std::string makeValue(size_t writer, size_t key) const {
    return fmt::format("value_w{:02}_k{:02}", writer, key);
  }

  /**
   * Add details to kUserId.
   * @param num_accounts are created and each adds
   * @param num_keys_per_account detail pieces to kUserId.
   */
  void addDetails(const size_t num_accounts,
                  const size_t num_keys_per_account) {
    SCOPED_TRACE("addDetails");
    for (size_t acc = 0; acc < num_accounts; ++acc) {
      IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
          makeAccountName(acc),
          kDomain,
          PublicKeyHexStringView{kSameDomainUserKeypair.publicKey()},
          {}));
      IROHA_ASSERT_RESULT_VALUE(getItf().executeCommandAsAccount(
          *getItf().getMockCommandFactory()->constructGrantPermission(
              makeAccountId(acc), Grantable::kSetMyAccountDetail),
          kUserId,
          true));
      auto &added_writer = added_data_[makeAccountId(acc)];
      for (size_t key = 0; key < num_keys_per_account; ++key) {
        IROHA_ASSERT_RESULT_VALUE(getItf().executeCommandAsAccount(
            *getItf().getMockCommandFactory()->constructSetAccountDetail(
                kUserId, makeKey(key), makeValue(acc, key)),
            makeAccountId(acc),
            true));
        added_writer[makeKey(key)] = makeValue(acc, key);
      }
    }
  }

  std::unique_ptr<shared_model::interface::MockAccountDetailPaginationMeta>
  makePaginationMeta(
      TransactionsNumberType page_size,
      const std::optional<AccountDetailRecordId> &requested_first_record_id) {
    std::optional<std::reference_wrapper<
        const shared_model::interface::AccountDetailRecordId>>
        first_record_id;
    if (requested_first_record_id) {
      first_record_id =
          std::cref<shared_model::interface::AccountDetailRecordId>(
              requested_first_record_id.value());
    }  // convert to optional ctor?
    return getItf().getMockQueryFactory()->constructAccountDetailPaginationMeta(
        page_size, first_record_id);
  }

  /// Query account details.
  QueryExecutorResult queryPage(
      std::optional<std::string> writer,
      std::optional<std::string> key,
      std::optional<AccountDetailRecordId> first_record_id,
      size_t page_size,
      const AccountIdType &command_issuer = kAdminId) {
    auto page_meta = makePaginationMeta(page_size, first_record_id);
    return getItf().executeQuery(
        *getItf().getMockQueryFactory()->constructGetAccountDetail(
            kUserId, std::move(key), std::move(writer), *page_meta),
        command_issuer);
  }

  void prepareState(const size_t num_accounts,
                    const size_t num_keys_per_account) {
    SCOPED_TRACE("prepareState");
    getItf().createDomain(kSecondDomain);
    IROHA_ASSERT_RESULT_VALUE(getItf().createUserWithPerms(
        kUser,
        kDomain,
        PublicKeyHexStringView{kUserKeypair.publicKey()},
        {Role::kSetMyAccountDetail}));
    addDetails(num_accounts, num_keys_per_account);
  }

  void validatePageResponse(
      const QueryExecutorResult &response,
      std::optional<std::string> writer,
      std::optional<std::string> key,
      std::optional<shared_model::plain::AccountDetailRecordId> first_record_id,
      size_t page_size) {
    checkSuccessfulResult<shared_model::interface::AccountDetailResponse>(
        response, [&, this](const auto &response) {
          this->validatePageResponse(
              response, writer, key, first_record_id, page_size);
        });
  }

  /**
   * Query account assets and validate the response.
   */
  template <typename... Types>
  QueryExecutorResult queryPageAndValidateResponse(Types &&... args) {
    auto response = queryPage(args...);
    validatePageResponse(response, std::forward<Types>(args)...);
    return response;
  }

 protected:
  struct Response {
    size_t total_number{0};
    std::optional<shared_model::plain::AccountDetailRecordId> next_record;
    DetailsByKeyByWriter details;
  };

  /**
   * Exhaustive check of the page response.
   * @param response the response of GetAccountDetail query
   * @param expected_response the reference to compare with
   */
  void validatePageResponse(const AccountDetailResponse &response,
                            const Response &expected_response) {
    EXPECT_EQ(response.totalNumber(), expected_response.total_number);
    if (expected_response.next_record) {
      if (not response.nextRecordId()) {
        ADD_FAILURE() << "nextRecordId not set!";
      } else {
        EXPECT_EQ(response.nextRecordId()->get().writer(),
                  expected_response.next_record->writer());
        EXPECT_EQ(response.nextRecordId()->get().key(),
                  expected_response.next_record->key());
      }
    } else {
      EXPECT_FALSE(response.nextRecordId());
    }
    checkJsonData(response.detail(), expected_response.details);
  }

  /**
   * Exhaustive check of the page response.
   * @param response the response of GetAccountDetail query
   * @param writer requested data writer
   * @param key requested data key
   * @param first_record_id requested first record id
   * @param page_size requested page size
   */
  void validatePageResponse(
      const AccountDetailResponse &response,
      std::optional<std::string> writer,
      std::optional<std::string> key,
      std::optional<AccountDetailRecordId> first_record_id,
      size_t page_size) {
    Response expected_response = this->getExpectedResponse(
        writer, key, std::move(first_record_id), page_size);
    validatePageResponse(response, expected_response);
  }

  /**
   * @return an internal representation of expected correct response for the
   * given parameters.
   */
  Response getExpectedResponse(
      const std::optional<std::string> &req_writer,
      const std::optional<std::string> &req_key,
      const std::optional<shared_model::plain::AccountDetailRecordId>
          &first_record_id,
      size_t page_size) {
    auto optional_match = [](const auto &opt, const auto &val) {
      return not opt or opt.value() == val;
    };

    Response expected_response;
    size_t expected_page_size = 0;
    bool page_started = false;
    bool page_ended = false;
    for (const auto &added_writer_and_data : this->added_data_) {
      const auto &writer = added_writer_and_data.first;
      const auto &added_data_by_writer = added_writer_and_data.second;

      // check if writer matches query
      if (optional_match(req_writer, writer)) {
        for (const auto &key_and_value : added_data_by_writer) {
          const auto &key = key_and_value.first;
          const auto &val = key_and_value.second;

          // check if key matches query
          if (optional_match(req_key, key)) {
            ++expected_response.total_number;
            page_started = page_started
                or optional_match(first_record_id,
                                  shared_model::plain::AccountDetailRecordId{
                                      writer, key});
            if (page_started) {
              if (page_ended) {
                if (not expected_response.next_record) {
                  expected_response.next_record =
                      shared_model::plain::AccountDetailRecordId{writer, key};
                }
              } else {
                expected_response.details[writer][key] = val;
                ++expected_page_size;
                page_ended |= expected_page_size >= page_size;
              }
            }
          }
        }
      }
    }
    return expected_response;
  }

  // added account details
  DetailsByKeyByWriter added_data_;
};

enum GetAccountDetailRecordIdVariant {
  kAllDetails,
  kDetailsByWriter,
  kDetailsByKey,
  kSingleDetail,
};

struct GetAccountDetailRecordIdTest
    : public GetAccountDetailTest,
      public ::testing::WithParamInterface<
          std::tuple<ExecutorTestParamProvider,
                     GetAccountDetailRecordIdVariant>> {
  GetAccountDetailRecordIdTest()
      : backend_param_(std::get<0>(GetParam())()),
        record_id_param_(std::get<1>(GetParam())) {}

  static std::string paramToString(testing::TestParamInfo<ParamType> param) {
    static const std::map<GetAccountDetailRecordIdVariant, std::string>
        record_id_param_names{{kAllDetails, "AllDetails"},
                              {kDetailsByWriter, "DetailsByWriter"},
                              {kDetailsByKey, "DetailsByKey"},
                              {kSingleDetail, "SingleDetail"}};
    return std::get<0>(param.param)().get().toString()
        + record_id_param_names.at(std::get<1>(param.param));
  }

  std::optional<std::string> requestedWriter() const {
    if (record_id_param_ == kDetailsByWriter
        or record_id_param_ == kSingleDetail) {
      return makeAccountId(0);
    }
    return std::nullopt;
  }

  std::optional<std::string> requestedKey() const {
    if (record_id_param_ == kDetailsByKey
        or record_id_param_ == kSingleDetail) {
      return makeKey(0);
    }
    return std::nullopt;
  }

  shared_model::plain::AccountDetailRecordId makeFirstRecordId(
      std::string writer, std::string key) {
    return shared_model::plain::AccountDetailRecordId{
        requestedWriter().value_or(std::move(writer)),
        requestedKey().value_or(std::move(key))};
  }

  QueryExecutorResult queryPage(
      std::optional<shared_model::plain::AccountDetailRecordId> first_record_id,
      size_t page_size) {
    return GetAccountDetailTest::queryPage(requestedWriter(),
                                           requestedKey(),
                                           std::move(first_record_id),
                                           page_size);
  }

  QueryExecutorResult queryPage(size_t page_size) {
    return GetAccountDetailTest::queryPage(
        requestedWriter(), requestedKey(), std::nullopt, page_size);
  }

  using GetAccountDetailTest::validatePageResponse;

  void validatePageResponse(
      const QueryExecutorResult &response,
      std::optional<shared_model::plain::AccountDetailRecordId> first_record_id,
      size_t page_size) {
    checkSuccessfulResult<shared_model::interface::AccountDetailResponse>(
        response, [&, this](const auto &response) {
          Response expected_response =
              this->getExpectedResponse(this->requestedWriter(),
                                        this->requestedKey(),
                                        std::move(first_record_id),
                                        page_size);
          this->validatePageResponse(response, expected_response);
        });
  }

  template <typename... Args>
  auto queryPageAndValidateResponse(Args... args)
      -> decltype(queryPage(std::declval<Args>()...)) {
    auto response = queryPage(args...);
    validatePageResponse(response, args...);
    return response;
  }

  template <typename... Args>
  auto validatePageResponse(Args &&... args)
      -> decltype(GetAccountDetailTest::validatePageResponse(args...)) {
    return GetAccountDetailTest::validatePageResponse(
        std::forward<Args>(args)...);
  }

 protected:
  virtual ExecutorTestParam &getBackendParam() {
    return backend_param_;
  }

 private:
  ExecutorTestParam &backend_param_;
  const GetAccountDetailRecordIdVariant record_id_param_;
};

/**
 * @given two users with all related permissions
 * @when GetAccountDetail is queried on the user with no details
 * @then there is an empty AccountDetailResponse
 */
TEST_P(GetAccountDetailRecordIdTest, NoDetail) {
  prepareState(0, 0);
  queryPageAndValidateResponse(makeFirstRecordId(makeAccountId(1), makeKey(1)),
                               1);
}

/**
 * @given a user with all related permissions
 * @when GetAccountDetail is queried on a nonexistent user
 * @then there is an error
 */
TEST_P(GetAccountDetailRecordIdTest, InvalidNoAccount) {
  checkQueryError<shared_model::interface::NoAccountDetailErrorResponse>(
      GetAccountDetailTest::queryPage(
          makeAccountId(1), makeKey(1), std::nullopt, 1),
      error_codes::kNoStatefulError);
}

/**
 * @given account with all related permissions
 * @when GetAccountDetail is queried without page metadata
 * @then all details are returned and are valid
 */
TEST_P(GetAccountDetailRecordIdTest, NoPageMetaData) {
  ASSERT_NO_FATAL_FAILURE(prepareState(3, 3));
  QueryExecutorResult response = getItf().executeQuery(
      *getItf().getMockQueryFactory()->constructGetAccountDetail(
          kUserId, requestedKey(), requestedWriter(), std::nullopt));
  validatePageResponse(response, std::nullopt, 9);
}

/**
 * @given account with all related permissions and 10 assets
 * @when queried assets page of size 5 starting from unknown asset
 * @then error response is returned
 */
TEST_P(GetAccountDetailRecordIdTest, NonexistentFirstRecordId) {
  ASSERT_NO_FATAL_FAILURE(prepareState(1, 1));
  auto response =
      queryPage(AccountDetailRecordId{makeAccountId(2), makeKey(2)}, 5);
  checkQueryError<shared_model::interface::StatefulFailedErrorResponse>(
      response, error_codes::kInvalidPagination);
}

/**
 * @given account with 9 details from 3 writers, 3 unique keys from each,
 * and all related permissions
 * @when queried account details with page size of 2 and first record unset
 * @then the appropriate detail records are returned and are valid
 */
TEST_P(GetAccountDetailRecordIdTest, FirstPage) {
  ASSERT_NO_FATAL_FAILURE(prepareState(3, 3));
  queryPageAndValidateResponse(std::nullopt, 2);
}

/**
 * @given account with 8 details from 4 writers, 2 unique keys from each,
 * and all related permissions
 * @when queried account details with page size of 3 and first record set to
 * the last key of the second writer
 * @then the appropriate detail records are returned and are valid
 */
TEST_P(GetAccountDetailRecordIdTest, MiddlePageAcrossWriters) {
  ASSERT_NO_FATAL_FAILURE(prepareState(4, 2));
  queryPageAndValidateResponse(makeFirstRecordId(makeAccountId(1), makeKey(1)),
                               3);
}

/**
 * @given account with 8 details from 2 writers, 4 unique keys from each,
 * and all related permissions
 * @when queried account details with page size of 2 and first record set to
 * the second key of the second writer
 * @then the appropriate detail records are returned and are valid
 */
TEST_P(GetAccountDetailRecordIdTest, MiddlePageAcrossKeys) {
  ASSERT_NO_FATAL_FAILURE(prepareState(2, 4));
  queryPageAndValidateResponse(makeFirstRecordId(makeAccountId(1), makeKey(1)),
                               3);
}
/**
 * @given account with 9 details from 3 writers, 3 unique keys from each,
 * and all related permissions
 * @when queried account details with page size of 2 and first record set to
 * the last key of the last writer
 * @then the appropriate detail records are returned and are valid
 */
TEST_P(GetAccountDetailRecordIdTest, LastPage) {
  ASSERT_NO_FATAL_FAILURE(prepareState(3, 3));
  queryPageAndValidateResponse(makeFirstRecordId(makeAccountId(2), makeKey(2)),
                               2);
}

INSTANTIATE_TEST_SUITE_P(
    Base,
    GetAccountDetailRecordIdTest,
    ::testing::Combine(executor_testing::getExecutorTestParams(),
                       ::testing::ValuesIn({kAllDetails,
                                            kDetailsByWriter,
                                            kDetailsByKey,
                                            kSingleDetail})),
    GetAccountDetailRecordIdTest::paramToString);

using GetAccountDetailPermissionTest =
    query_permission_test::QueryPermissionTest<GetAccountDetailTest>;

TEST_P(GetAccountDetailPermissionTest, QueryPermissionTest) {
  ASSERT_NO_FATAL_FAILURE(prepareState({Role::kSetMyAccountDetail}));
  addDetails(1, 1);
  checkResponse<shared_model::interface::AccountDetailResponse>(
      queryPage(makeAccountId(0), makeKey(0), std::nullopt, 1, getSpectator()),
      [this](const shared_model::interface::AccountDetailResponse &response) {
        this->validatePageResponse(
            response, makeAccountId(0), makeKey(0), std::nullopt, 1);
      });
}

INSTANTIATE_TEST_SUITE_P(
    Common,
    GetAccountDetailPermissionTest,
    query_permission_test::getParams({Role::kGetMyAccDetail},
                                     {Role::kGetDomainAccDetail},
                                     {Role::kGetAllAccDetail}),
    query_permission_test::paramToString);
