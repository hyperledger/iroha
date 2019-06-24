/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_query_executor.hpp"

#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <type_traits>

#define RAPIDJSON_HAS_STDSTRING 1

#include <rapidjson/document.h>
#include <rapidjson/rapidjson.h>
#include <boost/format.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/size.hpp>
#include "ametsuchi/impl/flat_file/flat_file.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "backend/plain/peer.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "common/result.hpp"
#include "datetime/time.hpp"
#include "framework/common_constants.hpp"
#include "framework/result_fixture.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/query_responses/account_asset_response.hpp"
#include "interfaces/query_responses/account_detail_response.hpp"
#include "interfaces/query_responses/account_response.hpp"
#include "interfaces/query_responses/asset_response.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "interfaces/query_responses/peers_response.hpp"
#include "interfaces/query_responses/role_permissions.hpp"
#include "interfaces/query_responses/roles_response.hpp"
#include "interfaces/query_responses/signatories_response.hpp"
#include "interfaces/query_responses/transactions_page_response.hpp"
#include "interfaces/query_responses/transactions_response.hpp"
#include "module/irohad/ametsuchi/ametsuchi_fixture.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/irohad/pending_txs_storage/pending_txs_storage_mock.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_query_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/mock_objects_factories/mock_command_factory.hpp"

using namespace framework::expected;
using namespace shared_model::interface;

namespace shared_model {
  namespace crypto {
    void PrintTo(const shared_model::crypto::Hash &hash, std::ostream *os) {
      *os << hash.toString();
    }
  }  // namespace crypto
}  // namespace shared_model

namespace {
  constexpr types::TransactionsNumberType kTxPageSize(10);
  constexpr types::PrecisionType kAssetPrecision(1);
  // TODO mboldyrev 05.12.2018 IR-57 unify the common constants.
  constexpr size_t kHashLength = 32;
  const std::string zero_string(kHashLength, '0');
  const std::string asset_id = "coin#domain";
  const std::string role = "role";
  const shared_model::interface::types::DomainIdType domain_id = "domain";
  const shared_model::interface::types::DomainIdType another_domain_id =
      "andomain";
  const shared_model::interface::types::AccountIdType account_id =
      "id@" + domain_id;
  const shared_model::interface::types::AccountIdType another_account_id =
      "id@" + another_domain_id;
  const shared_model::interface::types::AccountIdType account_id2 =
      "id2@" + domain_id;
}  // namespace

namespace iroha {
  namespace ametsuchi {

    /**
     * Check that query response meets defined requirements
     * @tparam ExpectedQueryResponseType - expected type of that query
     * response
     * @tparam QueryResultCheckCallable - type of callable, which checks query
     * response
     * @param exec_result to be checked
     * @param check_callable - that check callable
     */
    template <typename ExpectedQueryResponseType,
              typename QueryResultCheckCallable>
    void checkSuccessfulResult(const QueryExecutorResult &exec_result,
                               QueryResultCheckCallable check_callable) {
      ASSERT_NO_THROW({
        const auto &cast_resp =
            boost::get<const ExpectedQueryResponseType &>(exec_result->get());
        check_callable(cast_resp);
      }) << exec_result->toString();
    }

    /**
     * Check that stateful error in query response is the one expected
     * @tparam ExpectedQueryErrorType - expected sub-type of that query
     * response
     * @param exec_result to be checked
     * @param expected_code, which is to be in the query response
     */
    template <typename ExpectedQueryErrorType>
    void checkStatefulError(
        const QueryExecutorResult &exec_result,
        shared_model::interface::ErrorQueryResponse::ErrorCodeType
            expected_code) {
      const shared_model::interface::ErrorQueryResponse *error_query_response =
          boost::get<const shared_model::interface::ErrorQueryResponse &>(
              &exec_result->get());
      if (not error_query_response) {
        ADD_FAILURE() << "Result is not an error as it is supposed to be! "
                         "Actual result is: "
                      << exec_result->toString();
        return;
      }
      EXPECT_EQ(error_query_response->errorCode(), expected_code);
      EXPECT_TRUE(boost::get<const ExpectedQueryErrorType &>(
          &error_query_response->get()))
          << "Result has wrong error type! Actual result is: "
          << exec_result->toString();
    }

    class QueryExecutorTest : public AmetsuchiTest {
     public:
      QueryExecutorTest()
          : peer{"127.0.0.1",
                 shared_model::interface::types::PubkeyType{
                     shared_model::crypto::Blob::fromHexString(
                         "fa6ce0e0c21ce1ceaf4ba38538c1868185e9feefeafff3e42d94f"
                         "21800"
                         "0a5533")}} {
        role_permissions.set(
            shared_model::interface::permissions::Role::kAddMySignatory);
        grantable_permission =
            shared_model::interface::permissions::Grantable::kAddMySignatory;
        pubkey = std::make_unique<shared_model::interface::types::PubkeyType>(
            std::string('1', 32));
        pubkey2 = std::make_unique<shared_model::interface::types::PubkeyType>(
            std::string('2', 32));

        query_response_factory =
            std::make_shared<shared_model::proto::ProtoQueryResponseFactory>();
      }

      void SetUp() override {
        AmetsuchiTest::SetUp();
        sql = std::make_unique<soci::session>(*soci::factory_postgresql(),
                                              pgopt_);

        auto factory =
            std::make_shared<shared_model::proto::ProtoCommonObjectsFactory<
                shared_model::validation::FieldValidator>>(
                iroha::test::kTestsValidatorsConfig);
        query_executor = storage;
        PostgresCommandExecutor::prepareStatements(*sql);
        executor =
            std::make_unique<PostgresCommandExecutor>(*sql, perm_converter);
        pending_txs_storage = std::make_shared<MockPendingTransactionStorage>();

        execute(
            *mock_command_factory->constructCreateRole(role, role_permissions),
            true);
        execute(*mock_command_factory->constructAddPeer(peer), true);
        execute(*mock_command_factory->constructCreateDomain(domain_id, role),
                true);
        execute(*mock_command_factory->constructCreateAccount(
                    "id", domain_id, *pubkey),
                true);

        execute(*mock_command_factory->constructCreateDomain(another_domain_id,
                                                             role),
                true);
        execute(*mock_command_factory->constructCreateAccount(
                    "id", another_domain_id, *pubkey),
                true);
      }

      void TearDown() override {
        sql->close();
        AmetsuchiTest::TearDown();
      }

      auto executeQuery(shared_model::interface::Query &query) {
        return query_executor->createQueryExecutor(pending_txs_storage,
                                                   query_response_factory)
            | [&query](const auto &executor) {
                return executor->validateAndExecute(query, false);
              };
      }

      template <typename CommandType>
      void execute(CommandType &&command,
                   bool do_validation = false,
                   const shared_model::interface::types::AccountIdType
                       &creator = "id@domain") {
        executor->doValidation(not do_validation);
        executor->setCreatorAccountId(creator);
        ASSERT_TRUE(
            val(executor->operator()(std::forward<CommandType>(command))));
      }

      void addPerms(
          shared_model::interface::RolePermissionSet set,
          const shared_model::interface::types::AccountIdType account_id =
              "id@domain",
          const shared_model::interface::types::RoleIdType role_id = "perms") {
        execute(*mock_command_factory->constructCreateRole(role_id, set), true);
        execute(*mock_command_factory->constructAppendRole(account_id, role_id),
                true);
      }

      void addAllPerms(
          const shared_model::interface::types::AccountIdType account_id =
              "id@domain",
          const shared_model::interface::types::RoleIdType role_id = "all") {
        shared_model::interface::RolePermissionSet permissions;
        permissions.setAll();
        execute(
            *mock_command_factory->constructCreateRole(role_id, permissions),
            true);
        execute(*mock_command_factory->constructAppendRole(account_id, role_id),
                true);
      }

      // TODO [IR-1816] Akvinikym 06.12.18: remove these constants after
      // introducing a uniform way to use them in code
      static constexpr shared_model::interface::ErrorQueryResponse::
          ErrorCodeType kNoStatefulError = 0;
      static constexpr shared_model::interface::ErrorQueryResponse::
          ErrorCodeType kNoPermissions = 2;
      static constexpr shared_model::interface::ErrorQueryResponse::
          ErrorCodeType kInvalidPagination = 4;
      static constexpr shared_model::interface::ErrorQueryResponse::
          ErrorCodeType kInvalidAccountId = 5;
      static constexpr shared_model::interface::ErrorQueryResponse::
          ErrorCodeType kInvalidAssetId = 6;
      static constexpr shared_model::interface::ErrorQueryResponse::
          ErrorCodeType kInvalidHeight = 3;

      void createDefaultAccount() {
        execute(*mock_command_factory->constructCreateAccount(
                    "id2", domain_id, *pubkey2),
                true);
      }

      void createDefaultAsset() {
        execute(
            *mock_command_factory->constructCreateAsset("coin", domain_id, 1),
            true);
      }

      std::string role = "role";
      shared_model::interface::RolePermissionSet role_permissions;
      shared_model::interface::permissions::Grantable grantable_permission;

      std::unique_ptr<shared_model::interface::types::PubkeyType> pubkey;
      std::unique_ptr<shared_model::interface::types::PubkeyType> pubkey2;

      std::unique_ptr<soci::session> sql;

      std::unique_ptr<shared_model::interface::Command> command;

      std::shared_ptr<QueryExecutorFactory> query_executor;
      std::unique_ptr<CommandExecutor> executor;
      std::shared_ptr<MockPendingTransactionStorage> pending_txs_storage;

      std::unique_ptr<BlockStorage> block_store;

      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          query_response_factory;

      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter =
              std::make_shared<shared_model::proto::ProtoPermissionToString>();

      std::unique_ptr<shared_model::interface::MockCommandFactory>
          mock_command_factory =
              std::make_unique<shared_model::interface::MockCommandFactory>();

      shared_model::plain::Peer peer;
    };

    class BlocksQueryExecutorTest : public QueryExecutorTest {};

    /**
     * @given permissions to get blocks
     * @when get blocks query is validated
     * @then result is successful
     */
    TEST_F(BlocksQueryExecutorTest, BlocksQueryExecutorTestValid) {
      addAllPerms();
      auto blocks_query =
          TestBlocksQueryBuilder().creatorAccountId(account_id).build();
      ASSERT_TRUE(query_executor->createQueryExecutor(pending_txs_storage,
                                                      query_response_factory)
                  | [&blocks_query](const auto &executor) {
                      return executor->validate(blocks_query, false);
                    });
    }

    /**
     * @given no permissions to get blocks given
     * @when get blocks query is validated
     * @then result is error
     */
    TEST_F(BlocksQueryExecutorTest, BlocksQueryExecutorTestInvalid) {
      auto blocks_query =
          TestBlocksQueryBuilder().creatorAccountId(account_id).build();
      ASSERT_FALSE(query_executor->createQueryExecutor(pending_txs_storage,
                                                       query_response_factory)
                   | [&blocks_query](const auto &executor) {
                       return executor->validate(blocks_query, false);
                     });
    }

    class GetAccountExecutorTest : public QueryExecutorTest {
     public:
      void SetUp() override {
        QueryExecutorTest::SetUp();
        createDefaultAccount();
      }
    };

    /**
     * @given initialized storage, permission to his/her account
     * @when get account information
     * @then Return account
     */
    TEST_F(GetAccountExecutorTest, ValidMyAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetMyAccount});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccount(account_id)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.account().accountId(), account_id);
          });
    }

    /**
     * @given initialized storage, global permission
     * @when get account information about other user
     * @then Return account
     */
    TEST_F(GetAccountExecutorTest, ValidAllAccounts) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccounts});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccount(another_account_id)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.account().accountId(), another_account_id);
          });
    }

    /**
     * @given initialized storage, domain permission
     * @when get account information about other user in the same domain
     * @then Return account
     */
    TEST_F(GetAccountExecutorTest, ValidDomainAccount) {
      addPerms(
          {shared_model::interface::permissions::Role::kGetDomainAccounts});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccount(account_id2)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.account().accountId(), account_id2);
          });
    }

    /**
     * @given initialized storage, domain permission
     * @when get account information about other user in the other domain
     * @then Return error
     */
    TEST_F(GetAccountExecutorTest, InvalidDifferentDomain) {
      addPerms(
          {shared_model::interface::permissions::Role::kGetDomainAccounts});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccount(another_account_id)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

    /**
     * @given initialized storage, permission
     * @when get account information about non existing account
     * @then Return error
     */
    TEST_F(GetAccountExecutorTest, InvalidNoAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccounts});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccount("some@domain")
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::NoAccountErrorResponse>(
          std::move(result), kNoStatefulError);
    }

    class GetSignatoriesExecutorTest : public QueryExecutorTest {
     public:
      void SetUp() override {
        QueryExecutorTest::SetUp();
        createDefaultAccount();
      }
    };

    /**
     * @given initialized storage, permission to his/her account
     * @when get signatories
     * @then Return signatories of user
     */
    TEST_F(GetSignatoriesExecutorTest, ValidMyAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetMySignatories});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getSignatories(account_id)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::SignatoriesResponse>(
          std::move(result),
          [](const auto &cast_resp) { ASSERT_EQ(cast_resp.keys().size(), 1); });
    }

    /**
     * @given initialized storage, global permission
     * @when get signatories of other user
     * @then Return signatories
     */
    TEST_F(GetSignatoriesExecutorTest, ValidAllAccounts) {
      addPerms(
          {shared_model::interface::permissions::Role::kGetAllSignatories});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getSignatories(another_account_id)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::SignatoriesResponse>(
          std::move(result),
          [](const auto &cast_resp) { ASSERT_EQ(cast_resp.keys().size(), 1); });
    }

    /**
     * @given initialized storage, domain permission
     * @when get signatories of other user in the same domain
     * @then Return signatories
     */
    TEST_F(GetSignatoriesExecutorTest, ValidDomainAccount) {
      addPerms(
          {shared_model::interface::permissions::Role::kGetDomainSignatories});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getSignatories(account_id2)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::SignatoriesResponse>(
          std::move(result),
          [](const auto &cast_resp) { ASSERT_EQ(cast_resp.keys().size(), 1); });
    }

    /**
     * @given initialized storage, domain permission
     * @when get signatories of other user in the other domain
     * @then Return error
     */
    TEST_F(GetSignatoriesExecutorTest, InvalidDifferentDomain) {
      addPerms(
          {shared_model::interface::permissions::Role::kGetDomainAccounts});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getSignatories(another_account_id)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

    /**
     * @given initialized storage, permission
     * @when get signatories of non existing account
     * @then Return error
     */
    TEST_F(GetSignatoriesExecutorTest, InvalidNoAccount) {
      addPerms(
          {shared_model::interface::permissions::Role::kGetAllSignatories});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getSignatories("some@domain")
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::NoSignatoriesErrorResponse>(
          std::move(result), kNoStatefulError);
    }

    class GetAccountAssetExecutorTest : public QueryExecutorTest {
     public:
      void SetUp() override {
        QueryExecutorTest::SetUp();

        createDefaultAccount();
        createDefaultAsset();

        execute(*mock_command_factory->constructAddAssetQuantity(
                    asset_id, shared_model::interface::Amount{"1.0"}),
                true);
        execute(*mock_command_factory->constructAddAssetQuantity(
                    asset_id, shared_model::interface::Amount{"1.0"}),
                true,
                account_id2);
      }
    };

    /**
     * @given initialized storage, permission to his/her account
     * @when get account assets
     * @then Return account asset of user
     */
    TEST_F(GetAccountAssetExecutorTest, ValidMyAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetMyAccAst});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountAssets(account_id, kMaxPageSize, boost::none)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountAssetResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.accountAssets()[0].accountId(), account_id);
            ASSERT_EQ(cast_resp.accountAssets()[0].assetId(), asset_id);
          });
    }

    /**
     * @given initialized storage, global permission
     * @when get account assets of other user
     * @then Return account asset
     */
    TEST_F(GetAccountAssetExecutorTest, ValidAllAccounts) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccAst});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountAssets(account_id2, kMaxPageSize, boost::none)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountAssetResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.accountAssets()[0].accountId(), account_id2);
            ASSERT_EQ(cast_resp.accountAssets()[0].assetId(), asset_id);
          });
    }

    /**
     * @given initialized storage, domain permission
     * @when get account assets of other user in the same domain
     * @then Return account asset
     */
    TEST_F(GetAccountAssetExecutorTest, ValidDomainAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetDomainAccAst});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountAssets(account_id2, kMaxPageSize, boost::none)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountAssetResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.accountAssets()[0].accountId(), account_id2);
            ASSERT_EQ(cast_resp.accountAssets()[0].assetId(), asset_id);
          });
    }

    /**
     * @given initialized storage, domain permission
     * @when get account assets of other user in the other domain
     * @then Return error
     */
    TEST_F(GetAccountAssetExecutorTest, InvalidDifferentDomain) {
      addPerms({shared_model::interface::permissions::Role::kGetDomainAccAst});
      auto query =
          TestQueryBuilder()
              .creatorAccountId(account_id)
              .getAccountAssets(another_account_id, kMaxPageSize, boost::none)
              .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

    /**
     * @given initialized storage, permission
     * @when get account assets of non existing account
     * @then Return error
     */
    TEST_F(GetAccountAssetExecutorTest, DISABLED_InvalidNoAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccAst});
      auto query =
          TestQueryBuilder()
              .creatorAccountId(account_id)
              .getAccountAssets("some@domain", kMaxPageSize, boost::none)
              .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::NoAccountAssetsErrorResponse>(
          std::move(result), kNoStatefulError);
    }

    class GetAccountAssetPaginationExecutorTest : public QueryExecutorTest {
     public:
      void SetUp() override {
        QueryExecutorTest::SetUp();
        using shared_model::interface::permissions::Role;
        addPerms({Role::kGetMyAccAst, Role::kAddAssetQty, Role::kCreateAsset});
      }

      std::string makeAssetName(size_t i) {
        return (boost::format("asset_%03d") % i).str();
      }

      shared_model::interface::types::AssetIdType makeAssetId(size_t i) {
        return makeAssetName(i) + "#" + domain_id;
      }

      shared_model::interface::Amount makeAssetQuantity(size_t n) {
        return shared_model::interface::Amount{
            (boost::format("%d.0") % n).str()};
      }

      /**
       * Create new assets and add some quantity to the default account.
       * Asset names are `asset_NNN`, where NNN is zero-padded number in the
       * order of creation. Asset precision is 1. The quantity added equals the
       * asset number.
       */
      void createAccountAssets(size_t n) {
        for (size_t i = 0; i < n; ++i) {
          // create the asset
          execute(*mock_command_factory->constructCreateAsset(
                      makeAssetName(assets_added_), domain_id, 1),
                  true);

          // add asset quantity to default account
          execute(
              *mock_command_factory->constructAddAssetQuantity(
                  makeAssetId(assets_added_), makeAssetQuantity(assets_added_)),
              true);

          ++assets_added_;
        }
      }

      /**
       * Check the page response.
       * @param response the response of GetAccountAssets query
       * @param page_start requested first asset (according to the order of
       *        addition)
       * @param page_size requested page size
       */
      void validatePageResponse(const QueryExecutorResult &response,
                                boost::optional<size_t> page_start,
                                size_t page_size) {
        checkSuccessfulResult<shared_model::interface::AccountAssetResponse>(
            response,
            [this, page_start = page_start.value_or(0), page_size](
                const auto &response) {
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
                EXPECT_EQ(response.accountAssets()[i].accountId(), account_id);
              }
            });
      }

      /**
       * Query account assets.
       */
      QueryExecutorResult queryPage(boost::optional<size_t> page_start,
                                    size_t page_size) {
        boost::optional<shared_model::interface::types::AssetIdType>
            first_asset_id;
        if (page_start) {
          first_asset_id = makeAssetId(page_start.value());
        }
        auto query =
            TestQueryBuilder()
                .creatorAccountId(account_id)
                .getAccountAssets(account_id, page_size, first_asset_id)
                .build();
        return executeQuery(query);
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

    /**
     * @given account with all related permissions and 10 assets
     * @when queried assets with page metadata not set
     * @then all 10 asset values are returned and are valid
     */
    TEST_F(GetAccountAssetPaginationExecutorTest, NoPageMetaData) {
      createAccountAssets(10);

      shared_model::proto::Query query{[] {
        iroha::protocol::Query query;

        // set creator account
        query.mutable_payload()->mutable_meta()->set_creator_account_id(
            account_id);

        // make a getAccountAssets query
        query.mutable_payload()->mutable_get_account_assets()->set_account_id(
            account_id);

        return shared_model::proto::Query{query};
      }()};

      // send the query
      QueryExecutorResult response = executeQuery(query);

      // validate result
      validatePageResponse(response, boost::none, 10);
    }

    /**
     * @given account with all related permissions and 10 assets
     * @when queried assets first page of size 5
     * @then first 5 asset values are returned and are valid
     */
    TEST_F(GetAccountAssetPaginationExecutorTest, FirstPage) {
      createAccountAssets(10);
      queryPageAndValidateResponse(boost::none, 5);
    }

    /**
     * @given account with all related permissions and 10 assets
     * @when queried assets page of size 5 starting from 3rd asset
     * @then assets' #3 to #7 values are returned and are valid
     */
    TEST_F(GetAccountAssetPaginationExecutorTest, MiddlePage) {
      createAccountAssets(10);
      queryPageAndValidateResponse(3, 5);
    }

    /**
     * @given account with all related permissions and 10 assets
     * @when queried assets page of size 5 starting from 5th asset
     * @then assets' #5 to #9 values are returned and are valid
     */
    TEST_F(GetAccountAssetPaginationExecutorTest, LastPage) {
      createAccountAssets(10);
      queryPageAndValidateResponse(5, 5);
    }

    /**
     * @given account with all related permissions and 10 assets
     * @when queried assets page of size 5 starting from 8th asset
     * @then assets' #8 to #9 values are returned and are valid
     */
    TEST_F(GetAccountAssetPaginationExecutorTest, PastLastPage) {
      createAccountAssets(10);
      queryPageAndValidateResponse(8, 5);
    }

    /**
     * @given account with all related permissions and 10 assets
     * @when queried assets page of size 5 starting from unknown asset
     * @then error response is returned
     */
    TEST_F(GetAccountAssetPaginationExecutorTest, NonexistentStartTx) {
      createAccountAssets(10);
      auto response = queryPage(10, 5);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          response, kInvalidPagination);
    }

    class GetAccountDetailExecutorTest : public QueryExecutorTest {
     public:
      void SetUp() override {
        QueryExecutorTest::SetUp();
        detail =
            "{ \"id2@domain\" : { \"key\" : \"value\", "
            "\"key2\" : \"value2\" }, "
            "\"id@domain\" : { \"key\" : \"value\", "
            "\"key2\" : \"value2\" } }";
        createDefaultAccount();
        createDefaultAsset();

        execute(*mock_command_factory->constructSetAccountDetail(
                    account_id2, "key", "value"),
                true,
                account_id);
        execute(*mock_command_factory->constructSetAccountDetail(
                    account_id2, "key2", "value2"),
                true,
                account_id);
        execute(*mock_command_factory->constructSetAccountDetail(
                    account_id2, "key", "value"),
                true,
                account_id2);
        execute(*mock_command_factory->constructSetAccountDetail(
                    account_id2, "key2", "value2"),
                true,
                account_id2);
      }

      shared_model::interface::types::DetailType detail;
    };

    /**
     * @given initialized storage, permission to his/her account
     * @when get account detail
     * @then Return account detail
     */
    TEST_F(GetAccountDetailExecutorTest, ValidMyAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetMyAccDetail});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountDetail(kMaxPageSize, account_id)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountDetailResponse>(
          std::move(result),
          [](const auto &cast_resp) { ASSERT_EQ(cast_resp.detail(), "{}"); });
    }

    /**
     * @given initialized storage, global permission
     * @when get account detail of other user
     * @then Return account detail
     */
    TEST_F(GetAccountDetailExecutorTest, ValidAllAccounts) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccDetail});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountDetail(kMaxPageSize, account_id2)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountDetailResponse>(
          std::move(result), [this](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.detail(), detail);
          });
    }

    /**
     * @given initialized storage, domain permission
     * @when get account detail of other user in the same domain
     * @then Return account detail
     */
    TEST_F(GetAccountDetailExecutorTest, ValidDomainAccount) {
      addPerms(
          {shared_model::interface::permissions::Role::kGetDomainAccDetail});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountDetail(kMaxPageSize, account_id2)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountDetailResponse>(
          std::move(result), [this](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.detail(), detail);
          });
    }

    /**
     * @given initialized storage, domain permission
     * @when get account detail of other user in the other domain
     * @then Return error
     */
    TEST_F(GetAccountDetailExecutorTest, InvalidDifferentDomain) {
      addPerms(
          {shared_model::interface::permissions::Role::kGetDomainAccDetail});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountDetail(kMaxPageSize, another_account_id)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

    /**
     * @given initialized storage, permission
     * @when get account detail of non existing account
     * @then Return error
     */
    TEST_F(GetAccountDetailExecutorTest, InvalidNoAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccDetail});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountDetail(kMaxPageSize, "some@domain")
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::NoAccountDetailErrorResponse>(
          std::move(result), kNoStatefulError);
    }

    /**
     * @given details, inserted into one account by two writers, with one of the
     * keys repeated
     * @when performing query to retrieve details under this key
     * @then getAccountDetail will return details from both writers under the
     * specified key
     */
    TEST_F(GetAccountDetailExecutorTest, ValidKey) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccDetail});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountDetail(kMaxPageSize, account_id2, "key")
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountDetailResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.detail(),
                      R"({ "id2@domain" : { "key" : "value" }, )"
                      R"("id@domain" : { "key" : "value" } })");
          });
    }

    /**
     * @given details, inserted into one account by two writers
     * @when performing query to retrieve details, added by one of the writers
     * @then getAccountDetail will return only details, added by the specified
     * writer
     */
    TEST_F(GetAccountDetailExecutorTest, ValidWriter) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccDetail});
      auto query =
          TestQueryBuilder()
              .creatorAccountId(account_id)
              .getAccountDetail(kMaxPageSize, account_id2, "", account_id)
              .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountDetailResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(
                cast_resp.detail(),
                R"({ "id@domain" : { "key" : "value", "key2" : "value2" } })");
          });
    }

    /**
     * @given details, inserted into one account by two writers, with one of the
     * keys repeated
     * @when performing query to retrieve details under this key and added by
     * one of the writers
     * @then getAccountDetail will return only details, which are under the
     * specified key and added by the specified writer
     */
    TEST_F(GetAccountDetailExecutorTest, ValidKeyWriter) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccDetail});
      auto query =
          TestQueryBuilder()
              .creatorAccountId(account_id)
              .getAccountDetail(kMaxPageSize, account_id2, "key", account_id)
              .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AccountDetailResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.detail(),
                      R"({ "id@domain" : { "key" : "value" } })");
          });
    }

    // --------| GetAccountDetail - pagination tests |------------------>8 -----

    class GetAccountDetailPagedExecutorTest : public QueryExecutorTest {
     public:
      // account details, {writer -> {key -> value}}
      using DetailsByKeyByWriter = std::map<
          types::AccountIdType,
          std::map<types::AccountDetailKeyType, types::AccountDetailValueType>>;

      // added account details
      DetailsByKeyByWriter added_data_;

      void SetUp() override {
        QueryExecutorTest::SetUp();
        addPerms({shared_model::interface::permissions::Role::kGetMyAccDetail});
      }

      std::string makeAccountName(size_t i) const {
        return (boost::format("account_%02d") % i).str();
      }

      shared_model::interface::types::AccountIdType makeAccountId(
          size_t i) const {
        return makeAccountName(i) + "@" + domain_id;
      }

      std::string makeKey(size_t i) const {
        return (boost::format("key_%02d") % i).str();
      }

      std::string makeValue(size_t writer, size_t key) const {
        return (boost::format("value_w%02d_k%02d") % writer % key).str();
      }

      /**
       * Add details to account_id.
       * @param num_accounts are created and each adds
       * @param num_keys_per_account detail pieces to account_id.
       */
      void addDetails(const size_t num_accounts,
                      const size_t num_keys_per_account) {
        for (size_t acc = 0; acc < num_accounts; ++acc) {
          execute(*mock_command_factory->constructCreateAccount(
                      makeAccountName(acc), domain_id, *pubkey2),
                  true);
          execute(*mock_command_factory->constructGrantPermission(
                      makeAccountId(acc),
                      shared_model::interface::permissions::Grantable::
                          kSetMyAccountDetail),
                  true);
          auto &added_writer = added_data_[makeAccountId(acc)];
          for (size_t key = 0; key < num_keys_per_account; ++key) {
            execute(*mock_command_factory->constructSetAccountDetail(
                        account_id, makeKey(key), makeValue(acc, key)),
                    true,
                    makeAccountId(acc));
            added_writer[makeKey(key)] = makeValue(acc, key);
          }
        }
      }

      /**
       * Query account details.
       */
      QueryExecutorResult queryPage(
          boost::optional<std::string> writer,
          boost::optional<std::string> key,
          boost::optional<types::AccountDetailRecordId> first_record_id,
          size_t page_size) {
        auto query = TestQueryBuilder()
                         .creatorAccountId(account_id)
                         .getAccountDetail(page_size,
                                           account_id,
                                           key.value_or(""),
                                           writer.value_or(""),
                                           std::move(first_record_id))
                         .build();
        return executeQuery(query);
      }

      /**
       * Exhaustive check of response.
       * @param response the response of GetAccountDetail query
       * @param writer requested data writer
       * @param key requested data key
       * @param first_record_id requested first record id
       * @param page_size requested page size
       */
      void validatePageResponse(
          const QueryExecutorResult &response,
          boost::optional<std::string> writer,
          boost::optional<std::string> key,
          boost::optional<types::AccountDetailRecordId> first_record_id,
          size_t page_size) {
        checkSuccessfulResult<shared_model::interface::AccountDetailResponse>(
            response, [&, this](const auto &response) {
              Response expected_response = this->getExpectedResponse(
                  writer, key, std::move(first_record_id), page_size);
              this->validatePageResponse(response, expected_response);
            });
      }

     protected:
      struct Response {
        size_t total_number{0};
        boost::optional<types::AccountDetailRecordId> next_record;
        DetailsByKeyByWriter details;
      };

      /**
       * @return an internal representation of expected correct response for the
       * given parameters.
       */
      Response getExpectedResponse(
          const boost::optional<std::string> &req_writer,
          const boost::optional<std::string> &req_key,
          const boost::optional<types::AccountDetailRecordId> &first_record_id,
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
                    or optional_match(
                                   first_record_id,
                                   types::AccountDetailRecordId{writer, key});
                if (page_started) {
                  if (page_ended) {
                    if (not expected_response.next_record) {
                      expected_response.next_record =
                          types::AccountDetailRecordId{writer, key};
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

      /**
       * Compare actual response to the reference one.
       */
      void validatePageResponse(
          const shared_model::interface::AccountDetailResponse &response,
          const Response &expected_response) {
        EXPECT_EQ(response.totalNumber(), expected_response.total_number);
        if (expected_response.next_record) {
          if (not response.nextRecordId()) {
            ADD_FAILURE() << "nextRecordId not set!";
          } else {
            EXPECT_EQ(response.nextRecordId()->writer(),
                      expected_response.next_record->writer);
            EXPECT_EQ(response.nextRecordId()->key(),
                      expected_response.next_record->key);
          }
        } else {
          EXPECT_FALSE(response.nextRecordId());
        }
      }

      /**
       * Check JSON data of paged response.
       */
      void checkJsonData(const std::string &test_data,
                         const DetailsByKeyByWriter &reference_data) {
        rapidjson::Document doc;
        if (doc.Parse(test_data).HasParseError()) {
          ADD_FAILURE() << "Malformed JSON!";
          return;
        }
        if (not doc.IsObject()) {
          ADD_FAILURE() << "JSON top entity must be an object!";
          return;
        }
        const auto top_obj = doc.GetObject();

        EXPECT_EQ(top_obj.MemberEnd() - top_obj.MemberBegin(),
                  reference_data.size())
            << "Wrong number of writers!";

        for (const auto &ref_writer_and_data : reference_data) {
          const auto &ref_writer = ref_writer_and_data.first;
          const auto &ref_data_by_writer = ref_writer_and_data.second;

          // get the writer in JSON
          const auto json_writer_it = top_obj.FindMember(ref_writer);
          if (json_writer_it == top_obj.MemberEnd()) {
            ADD_FAILURE() << ref_writer << " not present in JSON!";
            continue;
          }
          const rapidjson::Value &json_data_by_writer = json_writer_it->value;
          if (not json_data_by_writer.IsObject()) {
            ADD_FAILURE() << "JSON entity for writer " << ref_writer
                          << " must be an object!";
            continue;
          }
          const auto json_data_by_writer_obj = json_data_by_writer.GetObject();

          EXPECT_EQ(json_data_by_writer_obj.MemberEnd()
                        - json_data_by_writer_obj.MemberBegin(),
                    ref_data_by_writer.size())
              << "Wrong number of keys!";

          // check the values
          for (const auto &key_and_value : ref_data_by_writer) {
            const auto &ref_key = key_and_value.first;
            const auto &ref_val = key_and_value.second;

            const auto it = json_data_by_writer_obj.FindMember(ref_key);
            if (it == top_obj.MemberEnd()) {
              ADD_FAILURE() << ref_key << " for writer " << ref_writer
                            << " not present in JSON!";
            } else {
              const rapidjson::Value &data_by_key = it->value;
              if (not data_by_key.IsString()) {
                ADD_FAILURE() << "JSON entity for writer " << ref_writer
                              << ", key " << ref_key << " must be a string!";
              } else {
                EXPECT_EQ(data_by_key.GetString(), ref_val);
              }
            }
          }
        }
      }

      /**
       * Query account details and validate the response.
       */
      template <typename... Args>
      auto queryPageAndValidateResponse(Args... args)
          -> decltype(queryPage(std::declval<Args>()...)) {
        auto response = queryPage(args...);
        validatePageResponse(response, args...);
        return response;
      }
    };

    /**
     * @given account with 9 details from 3 writers, 3 unique keys from each,
     * and all related permissions
     * @when queried account details with page metadata not set
     * @then all 9 detail records are returned and are valid
     */
    TEST_F(GetAccountDetailPagedExecutorTest, NoPageMetaData) {
      addDetails(3, 3);

      shared_model::proto::Query query{[] {
        iroha::protocol::Query query;

        // set creator account
        query.mutable_payload()->mutable_meta()->set_creator_account_id(
            account_id);

        // make a getAccountDetail query
        query.mutable_payload()->mutable_get_account_detail()->set_account_id(
            account_id);

        return shared_model::proto::Query{query};
      }()};

      // send the query
      QueryExecutorResult response = executeQuery(query);

      // validate result
      validatePageResponse(
          response, boost::none, boost::none, boost::none, 3 * 3);
    }

    /**
     * @given account with single detail record and all related permissions
     * @when queried account details with nonexistent page start
     * @then error corresponding to invalid pagination meta is returned
     */
    TEST_F(GetAccountDetailPagedExecutorTest, NonExistentFirstRecord) {
      addDetails(1, 1);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          queryPage(boost::none,
                    boost::none,
                    types::AccountDetailRecordId{makeAccountId(2), makeKey(2)},
                    2),
          kInvalidPagination);
    }

    // --------| GetAccountDetail - parametric pagination tests |------->8 -----

    enum class GetAccountDetailPagedExecutorTestVariant {
      kAllDetails,
      kDetailsByWriter,
      kDetailsByKey,
      kSingleDetail,
    };

    class GetAccountDetailPagedExecutorTestParametric
        : public GetAccountDetailPagedExecutorTest,
          public ::testing::WithParamInterface<
              GetAccountDetailPagedExecutorTestVariant> {
     public:
      boost::optional<std::string> requestedWriter() const {
        if (GetParam()
                == GetAccountDetailPagedExecutorTestVariant::kDetailsByWriter
            or GetParam()
                == GetAccountDetailPagedExecutorTestVariant::kSingleDetail) {
          return makeAccountId(0);
        }
        return boost::none;
      }

      boost::optional<std::string> requestedKey() const {
        if (GetParam()
                == GetAccountDetailPagedExecutorTestVariant::kDetailsByKey
            or GetParam()
                == GetAccountDetailPagedExecutorTestVariant::kSingleDetail) {
          return makeKey(0);
        }
        return boost::none;
      }

      types::AccountDetailRecordId makeFirstRecordId(std::string writer,
                                                     std::string key) {
        return types::AccountDetailRecordId{
            requestedWriter().value_or(std::move(writer)),
            requestedKey().value_or(std::move(key))};
      }

      QueryExecutorResult queryPage(
          boost::optional<types::AccountDetailRecordId> first_record_id,
          size_t page_size) {
        return GetAccountDetailPagedExecutorTest::queryPage(
            requestedWriter(),
            requestedKey(),
            std::move(first_record_id),
            page_size);
      }

      QueryExecutorResult queryPage(size_t page_size) {
        return GetAccountDetailPagedExecutorTest::queryPage(
            requestedWriter(), requestedKey(), boost::none, page_size);
      }

      void validatePageResponse(
          const QueryExecutorResult &response,
          boost::optional<types::AccountDetailRecordId> first_record_id,
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

     protected:
      template <typename... Args>
      auto validatePageResponse(Args &&... args) -> decltype(
          GetAccountDetailPagedExecutorTest::validatePageResponse(args...)) {
        return GetAccountDetailPagedExecutorTest::validatePageResponse(
            std::forward<Args>(args)...);
      }
    };

    /**
     * @given account with 9 details from 3 writers, 3 unique keys from each,
     * and all related permissions
     * @when queried account details with page size of 2 and first record unset
     * @then the appropriate detail records are returned and are valid
     */
    TEST_P(GetAccountDetailPagedExecutorTestParametric, FirstPage) {
      addDetails(3, 3);
      queryPageAndValidateResponse(boost::none, 2);
    }

    /**
     * @given account with 8 details from 4 writers, 2 unique keys from each,
     * and all related permissions
     * @when queried account details with page size of 3 and first record set to
     * the last key of the second writer
     * @then the appropriate detail records are returned and are valid
     */
    TEST_P(GetAccountDetailPagedExecutorTestParametric,
           MiddlePageAcrossWriters) {
      addDetails(4, 2);
      queryPageAndValidateResponse(
          makeFirstRecordId(makeAccountId(1), makeKey(1)), 3);
    }

    /**
     * @given account with 8 details from 2 writers, 4 unique keys from each,
     * and all related permissions
     * @when queried account details with page size of 2 and first record set to
     * the second key of the second writer
     * @then the appropriate detail records are returned and are valid
     */
    TEST_P(GetAccountDetailPagedExecutorTestParametric, MiddlePageAcrossKeys) {
      addDetails(2, 4);
      queryPageAndValidateResponse(
          makeFirstRecordId(makeAccountId(1), makeKey(1)), 2);
    }

    /**
     * @given account with 9 details from 3 writers, 3 unique keys from each,
     * and all related permissions
     * @when queried account details with page size of 2 and first record set to
     * the last key of the last writer
     * @then the appropriate detail records are returned and are valid
     */
    TEST_P(GetAccountDetailPagedExecutorTestParametric, LastPage) {
      addDetails(3, 3);
      queryPageAndValidateResponse(
          makeFirstRecordId(makeAccountId(2), makeKey(2)), 2);
    }

    INSTANTIATE_TEST_CASE_P(
        AllVariants,
        GetAccountDetailPagedExecutorTestParametric,
        ::testing::Values(
            GetAccountDetailPagedExecutorTestVariant::kAllDetails,
            GetAccountDetailPagedExecutorTestVariant::kDetailsByWriter,
            GetAccountDetailPagedExecutorTestVariant::kDetailsByKey,
            GetAccountDetailPagedExecutorTestVariant::kSingleDetail), );

    // --------------| GetBlock tests |---------------------------->8 ----------

    class GetBlockExecutorTest : public QueryExecutorTest {
     public:
      // TODO [IR-257] Akvinikym 30.01.19: remove the method and use mocks
      /**
       * Commit some number of blocks to the storage
       * @param blocks_amount - number of blocks to be committed
       */
      void commitBlocks(shared_model::interface::types::HeightType
                            number_of_blocks = kLedgerHeight) {
        std::unique_ptr<MutableStorage> ms;
        storage->createMutableStorage().match(
            [&ms](auto &&storage) { ms = std::move(storage.value); },
            [](const auto &error) {
              FAIL() << "MutableStorage: " << error.error;
            });

        auto prev_hash = shared_model::crypto::Hash(zero_string);
        for (decltype(number_of_blocks) i = 1; i < number_of_blocks; ++i) {
          auto block =
              createBlock({TestTransactionBuilder()
                               .creatorAccountId(account_id)
                               .createAsset(std::to_string(i), domain_id, 1)
                               .build()},
                          i,
                          prev_hash);
          prev_hash = block->hash();

          if (not ms->apply(block)) {
            FAIL() << "could not apply block to the storage";
          }
        }
        ASSERT_TRUE(val(storage->commit(std::move(ms))));
      }

      static constexpr shared_model::interface::types::HeightType
          kLedgerHeight = 3;
    };

    /**
     * @given initialized storage @and permission to get block
     * @when get block of valid height
     * @then return block
     */
    TEST_F(GetBlockExecutorTest, Valid) {
      const shared_model::interface::types::HeightType valid_height = 2;

      addPerms({shared_model::interface::permissions::Role::kGetBlocks});
      commitBlocks();
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getBlock(valid_height)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::BlockResponse>(
          std::move(result), [valid_height](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.block().height(), valid_height);
          });
    }

    /**
     * @given initialized storage @and permission to get block
     * @when get block of height, greater than supposed ledger's one
     * @then return error
     */
    TEST_F(GetBlockExecutorTest, InvalidHeight) {
      const shared_model::interface::types::HeightType invalid_height = 123;

      commitBlocks();
      addPerms({shared_model::interface::permissions::Role::kGetBlocks});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getBlock(invalid_height)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kInvalidHeight);
    }

    /**
     * @given initialized storage @and no permission to get block
     * @when get block
     * @then return error
     */
    TEST_F(GetBlockExecutorTest, NoPermission) {
      const shared_model::interface::types::HeightType height = 123;

      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getBlock(height)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

    class GetRolesExecutorTest : public QueryExecutorTest {
     public:
      void SetUp() override {
        QueryExecutorTest::SetUp();
      }
    };

    /**
     * @given initialized storage, permission to read all roles
     * @when get system roles
     * @then Return roles
     */
    TEST_F(GetRolesExecutorTest, Valid) {
      addPerms({shared_model::interface::permissions::Role::kGetRoles});
      auto query =
          TestQueryBuilder().creatorAccountId(account_id).getRoles().build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::RolesResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.roles().size(), 2);
            ASSERT_EQ(cast_resp.roles()[0], "role");
            ASSERT_EQ(cast_resp.roles()[1], "perms");
          });
    }

    /**
     * @given initialized storage, no permission to read all roles
     * @when get system roles
     * @then Return Error
     */
    TEST_F(GetRolesExecutorTest, Invalid) {
      auto query =
          TestQueryBuilder().creatorAccountId(account_id).getRoles().build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

    class GetRolePermsExecutorTest : public QueryExecutorTest {
     public:
      void SetUp() override {
        QueryExecutorTest::SetUp();
      }
    };

    /**
     * @given initialized storage, permission to read all roles
     * @when get role permissions
     * @then Return role permissions
     */
    TEST_F(GetRolePermsExecutorTest, Valid) {
      addPerms({shared_model::interface::permissions::Role::kGetRoles});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getRolePermissions("perms")
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::RolePermissionsResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_TRUE(cast_resp.rolePermissions().isSet(
                shared_model::interface::permissions::Role::kGetRoles));
          });
    }

    /**
     * @given initialized storage, permission to read all roles, role does not
     * exist
     * @when get role permissions
     * @then Return error
     */
    TEST_F(GetRolePermsExecutorTest, InvalidNoRole) {
      addPerms({shared_model::interface::permissions::Role::kGetRoles});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getRolePermissions("some")
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::NoRolesErrorResponse>(
          std::move(result), kNoStatefulError);
    }

    /**
     * @given initialized storage, no permission to read all roles
     * @when get role permissions
     * @then Return error
     */
    TEST_F(GetRolePermsExecutorTest, Invalid) {
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getRolePermissions("role")
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

    class GetAssetInfoExecutorTest : public QueryExecutorTest {
     public:
      void SetUp() override {
        QueryExecutorTest::SetUp();
      }

      void createAsset() {
        execute(
            *mock_command_factory->constructCreateAsset("coin", domain_id, 1),
            true);
      }
      const std::string asset_id = "coin#domain";
    };

    /**
     * @given initialized storage, permission to read all system assets
     * @when get asset info
     * @then Return asset
     */
    TEST_F(GetAssetInfoExecutorTest, Valid) {
      addPerms({shared_model::interface::permissions::Role::kReadAssets});
      createAsset();
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAssetInfo(asset_id)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::AssetResponse>(
          std::move(result), [this](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.asset().assetId(), asset_id);
            ASSERT_EQ(cast_resp.asset().domainId(), domain_id);
            ASSERT_EQ(cast_resp.asset().precision(), 1);
          });
    }

    /**
     * @given initialized storage, all permissions
     * @when get asset info of non existing asset
     * @then Error
     */
    TEST_F(GetAssetInfoExecutorTest, InvalidNoAsset) {
      addPerms({shared_model::interface::permissions::Role::kReadAssets});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAssetInfo("some#domain")
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::NoAssetErrorResponse>(
          std::move(result), kNoStatefulError);
    }

    /**
     * @given initialized storage, no permissions
     * @when get asset info
     * @then Error
     */
    TEST_F(GetAssetInfoExecutorTest, Invalid) {
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAssetInfo(asset_id)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

    class GetTransactionsExecutorTest : public QueryExecutorTest {
     public:
      void SetUp() override {
        QueryExecutorTest::SetUp();
        auto block_storage_persistent_factory =
            std::make_unique<InMemoryBlockStorageFactory>();
        auto block_store = block_storage_persistent_factory->create();
        ASSERT_TRUE(block_store);
        this->block_store = std::move(block_store);
        createDefaultAccount();
        createDefaultAsset();
      }

      /**
       * Apply block to given storage
       * @tparam S storage type
       * @param storage storage object
       * @param block to apply
       */
      template <typename S>
      void apply(S &&storage,
                 std::shared_ptr<const shared_model::interface::Block> block) {
        std::unique_ptr<MutableStorage> ms;
        storage->createMutableStorage().match(
            [&](auto &&_storage) { ms = std::move(_storage.value); },
            [](const auto &error) {
              FAIL() << "MutableStorage: " << error.error;
            });
        ms->apply(block);
        ASSERT_TRUE(val(storage->commit(std::move(ms))));
      }

      void commitBlocks() {
        auto fake_pubkey = shared_model::crypto::PublicKey(zero_string);

        std::vector<shared_model::proto::Transaction> txs1;
        txs1.push_back(TestTransactionBuilder()
                           .creatorAccountId(account_id)
                           .createRole("user", {})
                           .build());
        txs1.push_back(
            TestTransactionBuilder()
                .creatorAccountId(account_id)
                .addAssetQuantity(asset_id, "2.0")
                .transferAsset(account_id, account_id2, asset_id, "", "1.0")
                .build());
        txs1.push_back(TestTransactionBuilder()
                           .creatorAccountId(account_id2)
                           .createRole("user2", {})
                           .build());

        auto block1 = createBlock(txs1, 1);

        apply(storage, block1);

        std::vector<shared_model::proto::Transaction> txs2;
        txs2.push_back(
            TestTransactionBuilder()
                .creatorAccountId(account_id2)
                .transferAsset(account_id, account_id2, asset_id, "", "1.0")
                .build());
        txs2.push_back(TestTransactionBuilder()
                           .creatorAccountId(account_id)
                           .createRole("user3", {})
                           .build());

        auto block2 = createBlock(txs2, 2, block1->hash());
        second_block_hash = block2->hash();

        apply(storage, block2);

        hash1 = txs1.at(0).hash();
        hash2 = txs1.at(1).hash();
        hash3 = txs2.at(0).hash();
      }

      std::vector<shared_model::crypto::Hash> commitAdditionalBlocks(
          const size_t amount) {
        std::vector<shared_model::crypto::Hash> hashes;
        shared_model::crypto::Hash prev_block_hash = second_block_hash;
        size_t starting_height = 3;
        for (size_t i = 0; i < amount; ++i) {
          std::vector<shared_model::proto::Transaction> txs;
          std::string role_name = "test_role_" + std::to_string(i);
          txs.push_back(TestTransactionBuilder()
                            .creatorAccountId(account_id)
                            .createRole(role_name, {})
                            .build());
          auto block = createBlock(txs, starting_height + i, prev_block_hash);
          prev_block_hash = block->hash();
          apply(storage, block);
          hashes.push_back(txs.at(0).hash());
        }
        return hashes;
      }

      const std::string asset_id = "coin#domain";
      shared_model::crypto::PublicKey fake_pubkey{zero_string};
      shared_model::crypto::Hash hash1;
      shared_model::crypto::Hash hash2;
      shared_model::crypto::Hash hash3;
      shared_model::crypto::Hash second_block_hash;
    };

    template <typename QueryTxPaginationTest>
    class GetPagedTransactionsExecutorTest
        : public GetTransactionsExecutorTest {
     protected:
      using Impl = QueryTxPaginationTest;

      // create valid transactions and commit them
      void createTransactionsAndCommit(size_t transactions_amount) {
        addPerms(Impl::getUserPermissions());

        auto initial_txs = Impl::makeInitialTransactions(transactions_amount);
        auto target_txs = Impl::makeTargetTransactions(transactions_amount);

        tx_hashes_.reserve(target_txs.size());
        initial_txs.reserve(initial_txs.size() + target_txs.size());
        for (auto &tx : target_txs) {
          tx_hashes_.emplace_back(tx.hash());
          initial_txs.emplace_back(std::move(tx));
        }

        auto block = createBlock(initial_txs, 1);

        apply(storage, block);
      }

      auto queryPage(
          types::TransactionsNumberType page_size,
          const boost::optional<types::HashType> &first_hash = boost::none) {
        auto query = Impl::makeQuery(page_size, first_hash);
        return executeQuery(query);
      }

      /**
       * Check the transactions pagination response compliance to general rules:
       * - total transactions number is equal to the number of target
       * transactions
       * - the number of transactions in response is equal to the requested
       * amount if there are enough, otherwie equal to the available amount
       * - the returned transactions' and the target transactions' hashes match
       * - next transaction hash in response is unset if the last transaction is
       * in the response, otherwise it matches the next target transaction hash
       */
      void generalTransactionsPageResponseCheck(
          const TransactionsPageResponse &tx_page_response,
          types::TransactionsNumberType page_size,
          const boost::optional<types::HashType> &first_hash =
              boost::none) const {
        EXPECT_EQ(tx_page_response.allTransactionsSize(), tx_hashes_.size())
            << "Wrong `total transactions' number.";
        auto resp_tx_hashes = tx_page_response.transactions()
            | boost::adaptors::transformed(
                                  [](const auto &tx) { return tx.hash(); });
        const auto page_start = first_hash
            ? std::find(tx_hashes_.cbegin(), tx_hashes_.cend(), *first_hash)
            : tx_hashes_.cbegin();
        if (first_hash and page_start == tx_hashes_.cend()) {
          // Should never reach here as a non-existing first_hash in the
          // pagination metadata must cause an error query response instead of
          // transaction page response. If we get here, it is a problem of wrong
          // test logic.
          BOOST_THROW_EXCEPTION(
              std::runtime_error("Checking response that does not match "
                                 "the provided query pagination data."));
          return;
        }
        const auto expected_txs_amount =
            std::min<size_t>(page_size, tx_hashes_.cend() - page_start);
        const auto response_txs_amount = boost::size(resp_tx_hashes);
        EXPECT_EQ(response_txs_amount, expected_txs_amount)
            << "Wrong number of transactions returned.";
        auto expected_hash = page_start;
        auto response_hash = resp_tx_hashes.begin();
        const auto page_end =
            page_start + std::min(response_txs_amount, expected_txs_amount);
        while (expected_hash != page_end) {
          EXPECT_EQ(*expected_hash++, *response_hash++)
              << "Wrong transaction returned.";
        }
        if (page_end == tx_hashes_.cend()) {
          EXPECT_EQ(tx_page_response.nextTxHash(), boost::none)
              << "Next transaction hash value must be unset.";
        } else {
          EXPECT_TRUE(tx_page_response.nextTxHash());
          if (tx_page_response.nextTxHash()) {
            EXPECT_EQ(*tx_page_response.nextTxHash(), *page_end)
                << "Wrong next transaction hash value.";
          }
        }
      }

      std::vector<types::HashType> tx_hashes_;
    };

    struct GetAccountTxPaginationImpl {
      static shared_model::interface::RolePermissionSet getUserPermissions() {
        return {permissions::Role::kSetDetail, permissions::Role::kGetMyAccTxs};
      }

      static std::vector<shared_model::proto::Transaction>
      makeInitialTransactions(size_t transactions_amount) {
        return {};
      }

      static auto makeTargetTransactions(size_t transactions_amount) {
        std::vector<shared_model::proto::Transaction> transactions;
        transactions.reserve(transactions_amount);
        for (size_t i = 0; i < transactions_amount; ++i) {
          transactions.emplace_back(
              TestTransactionBuilder()
                  .creatorAccountId(account_id)
                  .createdTime(iroha::time::now(std::chrono::milliseconds(i)))
                  .setAccountDetail(account_id,
                                    "key_" + std::to_string(i),
                                    "val_" + std::to_string(i))
                  .build());
        }
        return transactions;
      }

      static shared_model::proto::Query makeQuery(
          types::TransactionsNumberType page_size,
          const boost::optional<types::HashType> &first_hash = boost::none) {
        return TestQueryBuilder()
            .creatorAccountId(account_id)
            .createdTime(iroha::time::now())
            .getAccountTransactions(account_id, page_size, first_hash)
            .build();
      }
    };

    template <typename T>
    static std::string assetAmount(T mantissa, types::PrecisionType precision) {
      std::stringstream ss;
      ss << std::setprecision(precision) << mantissa;
      return ss.str();
    }

    struct GetAccountAssetTxPaginationImpl {
      static shared_model::interface::RolePermissionSet getUserPermissions() {
        return {permissions::Role::kReceive,
                permissions::Role::kGetMyAccAstTxs};
      }

      static std::vector<shared_model::proto::Transaction>
      makeInitialTransactions(size_t transactions_amount) {
        return {
            TestTransactionBuilder()
                .creatorAccountId(account_id)
                .createdTime(iroha::time::now())
                .addAssetQuantity(
                    asset_id, assetAmount(transactions_amount, kAssetPrecision))
                .build()};
      }

      static auto makeTargetTransactions(size_t transactions_amount) {
        std::vector<shared_model::proto::Transaction> transactions;
        transactions.reserve(transactions_amount);
        for (size_t i = 0; i < transactions_amount; ++i) {
          transactions.emplace_back(
              TestTransactionBuilder()
                  .creatorAccountId(account_id)
                  .createdTime(iroha::time::now(std::chrono::milliseconds(i)))
                  .transferAsset(account_id,
                                 another_account_id,
                                 asset_id,
                                 "tx #" + std::to_string(i),
                                 assetAmount(1, kAssetPrecision))
                  .build());
        }
        return transactions;
      }

      static shared_model::proto::Query makeQuery(
          types::TransactionsNumberType page_size,
          const boost::optional<types::HashType> &first_hash = boost::none) {
        return TestQueryBuilder()
            .creatorAccountId(account_id)
            .createdTime(iroha::time::now())
            .getAccountAssetTransactions(
                account_id, asset_id, page_size, first_hash)
            .build();
      }
    };

    using GetAccountTransactionsExecutorTest =
        GetPagedTransactionsExecutorTest<GetAccountTxPaginationImpl>;

    /**
     * @given initialized storage, permission to his/her account
     * @when get account transactions
     * @then Return account transactions of user
     */
    TEST_F(GetAccountTransactionsExecutorTest, ValidMyAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetMyAccTxs});

      commitBlocks();

      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountTransactions(account_id, kTxPageSize)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::TransactionsPageResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.transactions().size(), 3);
            for (const auto &tx : cast_resp.transactions()) {
              static size_t i = 0;
              EXPECT_EQ(account_id, tx.creatorAccountId())
                  << tx.toString() << " ~~ " << i;
              ++i;
            }
          });
    }

    /**
     * This test checks that tables data is sorted as integrals and not as text
     * @given initialized storage with 10 blocks, permissioned account
     * @when get account transactions with first_tx_hash offset to get the last
     * tx when page_size is more than one
     * @then Return only one (the last) transaction
     */
    TEST_F(GetAccountTransactionsExecutorTest, ValidPaginationOrder) {
      addPerms({shared_model::interface::permissions::Role::kGetMyAccTxs});

      commitBlocks();
      auto hashes = commitAdditionalBlocks(kTxPageSize);

      auto query =
          TestQueryBuilder()
              .creatorAccountId(account_id)
              .getAccountTransactions(account_id, kTxPageSize, hashes.back())
              .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::TransactionsPageResponse>(
          std::move(result), [&hashes](const auto &cast_resp) {
            EXPECT_EQ(cast_resp.transactions().size(), 1);
            for (const auto &tx : cast_resp.transactions()) {
              // we put a loop here with EXPECT inside to get the trace when
              // more than one transaction is returned
              static size_t i = 0;
              EXPECT_EQ(hashes.back(), tx.hash())
                  << tx.toString() << " ~~ " << i;
              ++i;
            }
          });
    }

    /**
     * @given initialized storage, global permission
     * @when get account transactions of other user
     * @then Return account transactions
     */
    TEST_F(GetAccountTransactionsExecutorTest, ValidAllAccounts) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccTxs});

      commitBlocks();

      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountTransactions(account_id2, kTxPageSize)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::TransactionsPageResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.transactions().size(), 2);
            for (const auto &tx : cast_resp.transactions()) {
              EXPECT_EQ(account_id2, tx.creatorAccountId()) << tx.toString();
            }
          });
    }

    /**
     * @given initialized storage, domain permission
     * @when get account transactions of other user in the same domain
     * @then Return account transactions
     */
    TEST_F(GetAccountTransactionsExecutorTest, ValidDomainAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetDomainAccTxs});

      commitBlocks();

      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountTransactions(account_id2, kTxPageSize)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::TransactionsPageResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.transactions().size(), 2);
            for (const auto &tx : cast_resp.transactions()) {
              EXPECT_EQ(account_id2, tx.creatorAccountId()) << tx.toString();
            }
          });
    }

    /**
     * @given initialized storage, domain permission
     * @when get account transactions of other user in the other domain
     * @then Return error
     */
    TEST_F(GetAccountTransactionsExecutorTest, InvalidDifferentDomain) {
      addPerms({shared_model::interface::permissions::Role::kGetDomainAccTxs});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountTransactions(another_account_id, kTxPageSize)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

    /**
     * @given initialized storage, all permissions
     * @when get account transactions of non existing account
     * @then return error
     */
    TEST_F(GetAccountTransactionsExecutorTest, InvalidNoAccount) {
      addAllPerms();

      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountTransactions("some@domain", kTxPageSize)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kInvalidAccountId);
    }

    // ------------------------/ tx pagination tests \----------------------- //

    using QueryTxPaginationTestingTypes =
        ::testing::Types<GetAccountTxPaginationImpl,
                         GetAccountAssetTxPaginationImpl>;
    TYPED_TEST_CASE(GetPagedTransactionsExecutorTest,
                    QueryTxPaginationTestingTypes, );

    /**
     * @given initialized storage, user has 3 transactions committed
     * @when query contains second transaction as a starting
     * hash @and 2 transactions page size
     * @then response contains exactly 2 transaction
     * @and list of transactions starts from second transaction
     * @and next transaction hash is not present
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, ValidPagination) {
      this->createTransactionsAndCommit(3);
      auto &hash = this->tx_hashes_.at(1);
      auto size = 2;
      auto query_response = this->queryPage(size, hash);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response),
          [this, &hash, size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().begin()->hash(), hash);
            EXPECT_FALSE(tx_page_response.nextTxHash());
            this->generalTransactionsPageResponseCheck(
                tx_page_response, size, hash);
          });
    }

    /**
     * @given initialized storage, user has 3 transactions committed
     * @when query contains 2 transactions page size without starting hash
     * @then response contains exactly 2 transactions
     * @and starts from the first one
     * @and next transaction hash is equal to last committed transaction
     * @and total number of transactions equal to 3
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, ValidPaginationNoHash) {
      this->createTransactionsAndCommit(3);
      auto size = 2;
      auto query_response = this->queryPage(size);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response),
          [this, size](const auto &tx_page_response) {
            ASSERT_FALSE(tx_page_response.transactions().empty());
            EXPECT_EQ(tx_page_response.transactions().begin()->hash(),
                      this->tx_hashes_.at(0));
            EXPECT_TRUE(tx_page_response.nextTxHash());
            this->generalTransactionsPageResponseCheck(tx_page_response, size);
          });
    }

    /**
     * @given initialized storage, user has 3 transactions committed
     * @when query contains 10 page size
     * @then response contains only 3 committed transactions
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest,
               PaginationPageBiggerThanTotal) {
      this->createTransactionsAndCommit(3);
      auto size = 10;
      auto query_response = this->queryPage(size);

      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response),
          [this, size](const auto &tx_page_response) {
            this->generalTransactionsPageResponseCheck(tx_page_response, size);
          });
    }

    /**
     * @given initialized storage, user has 3 transactions committed
     * @when query contains non-existent starting hash
     * @then error response is returned
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, InvalidHashInPagination) {
      this->createTransactionsAndCommit(3);
      auto size = 2;
      char unknown_hash_string[kHashLength];
      zero_string.copy(unknown_hash_string, kHashLength);
      std::strcpy(unknown_hash_string, "no such hash!");
      auto query_response =
          this->queryPage(size, types::HashType(unknown_hash_string));

      checkStatefulError<StatefulFailedErrorResponse>(
          std::move(query_response),
          BlocksQueryExecutorTest::kInvalidPagination);
    }

    /**
     * @given initialized storage, user has no committed transactions
     * @when query contains 2 transactions page size
     * @then response does not contain any transactions
     * @and total size is 0
     * @and next hash is not present
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, PaginationNoTransactions) {
      this->createTransactionsAndCommit(0);
      auto size = 2;
      auto query_response = this->queryPage(size);

      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response),
          [this, size](const auto &tx_page_response) {
            this->generalTransactionsPageResponseCheck(tx_page_response, size);
          });
    }

    // --------------------\ end of tx pagination tests /-------------------- //

    class GetTransactionsHashExecutorTest : public GetTransactionsExecutorTest {
    };

    /**
     * @given initialized storage, global permission
     * @when get transactions of other user
     * @then Return transactions
     */
    TEST_F(GetTransactionsHashExecutorTest, ValidAllAccounts) {
      addPerms({shared_model::interface::permissions::Role::kGetAllTxs});

      commitBlocks();

      std::vector<decltype(hash3)> hashes;
      hashes.push_back(hash3);

      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getTransactions(hashes)
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::TransactionsResponse>(
          std::move(result), [this](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.transactions().size(), 1);
            ASSERT_EQ(cast_resp.transactions()[0].hash(), hash3);
          });
    }

    /**
     * @given initialized storage @and global permission
     * @when get transactions with two valid @and one invalid hashes in query
     * @then error is returned
     */
    TEST_F(GetTransactionsHashExecutorTest, BadHash) {
      addPerms({shared_model::interface::permissions::Role::kGetAllTxs});

      commitBlocks();

      std::vector<decltype(hash1)> hashes;
      hashes.push_back(hash1);
      hashes.emplace_back("AbsolutelyInvalidHash");
      hashes.push_back(hash2);

      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getTransactions(hashes)
                       .build();
      auto result = executeQuery(query);
      // TODO [IR-1816] Akvinikym 03.12.18: replace magic number 4
      // with a named constant
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), 4);
    }

    using GetAccountAssetTransactionsExecutorTest =
        GetPagedTransactionsExecutorTest<GetAccountAssetTxPaginationImpl>;

    /**
     * @given initialized storage, permission to his/her account
     * @when get account asset transactions
     * @then Return account asset transactions of user
     */
    TEST_F(GetAccountAssetTransactionsExecutorTest, ValidMyAccount) {
      addPerms({shared_model::interface::permissions::Role::kGetMyAccAstTxs});

      commitBlocks();

      auto query =
          TestQueryBuilder()
              .creatorAccountId(account_id)
              .getAccountAssetTransactions(account_id, asset_id, kTxPageSize)
              .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::TransactionsPageResponse>(
          std::move(result), [this](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.transactions().size(), 2);
            ASSERT_EQ(cast_resp.transactions()[0].hash(), hash2);
            ASSERT_EQ(cast_resp.transactions()[1].hash(), hash3);
          });
    }

    /**
     * @given initialized storage, global permission
     * @when get account asset transactions of other user
     * @then Return account asset transactions
     */
    TEST_F(GetAccountAssetTransactionsExecutorTest, ValidAllAccounts) {
      addPerms({shared_model::interface::permissions::Role::kGetAllAccAstTxs});

      commitBlocks();

      auto query =
          TestQueryBuilder()
              .creatorAccountId(account_id)
              .getAccountAssetTransactions(account_id2, asset_id, kTxPageSize)
              .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::TransactionsPageResponse>(
          std::move(result), [this](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.transactions().size(), 2);
            ASSERT_EQ(cast_resp.transactions()[0].hash(), hash2);
            ASSERT_EQ(cast_resp.transactions()[1].hash(), hash3);
          });
    }

    /**
     * @given initialized storage, domain permission
     * @when get account asset transactions of other user in the same domain
     * @then Return account asset transactions
     */
    TEST_F(GetAccountAssetTransactionsExecutorTest, ValidDomainAccount) {
      addPerms(
          {shared_model::interface::permissions::Role::kGetDomainAccAstTxs});

      commitBlocks();

      auto query =
          TestQueryBuilder()
              .creatorAccountId(account_id)
              .getAccountAssetTransactions(account_id2, asset_id, kTxPageSize)
              .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::TransactionsPageResponse>(
          std::move(result), [this](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.transactions().size(), 2);
            ASSERT_EQ(cast_resp.transactions()[0].hash(), hash2);
            ASSERT_EQ(cast_resp.transactions()[1].hash(), hash3);
          });
    }

    /**
     * @given initialized storage, domain permission
     * @when get account asset transactions of other user in the other domain
     * @then Return error
     */
    TEST_F(GetAccountAssetTransactionsExecutorTest, InvalidDifferentDomain) {
      addPerms(
          {shared_model::interface::permissions::Role::kGetDomainAccAstTxs});

      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountAssetTransactions(
                           another_account_id, asset_id, kTxPageSize)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

    /**
     * @given initialized storage, all permissions
     * @when get account asset transactions of non-existing user
     * @then corresponding error is returned
     */
    TEST_F(GetAccountAssetTransactionsExecutorTest, InvalidAccountId) {
      addAllPerms();

      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountAssetTransactions(
                           "doge@noaccount", asset_id, kTxPageSize)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kInvalidAccountId);
    }

    /**
     * @given initialized storage, all permissions
     * @when get account asset transactions of non-existing asset
     * @then corresponding error is returned
     */
    TEST_F(GetAccountAssetTransactionsExecutorTest, InvalidAssetId) {
      addAllPerms();

      auto query =
          TestQueryBuilder()
              .creatorAccountId(account_id)
              .getAccountAssetTransactions(account_id, "doge#coin", kTxPageSize)
              .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kInvalidAssetId);
    }

    /**
     * TODO 2019-06-13 igor-egorov IR-516 Remove the test
     * @given initialized storage
     * @when get pending transactions
     * @then pending txs storage will be requested for query creator account
     */
    TEST_F(QueryExecutorTest, OldTransactionsStorageIsAccessedOnGetPendingTxs) {
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getPendingTransactions()
                       .build();

      EXPECT_CALL(*pending_txs_storage, getPendingTransactions(account_id))
          .Times(1);

      executeQuery(query);
    }

    /**
     * @given initialized storage
     * @when get pending transactions
     * @then pending txs storage will be requested for query creator account
     */
    TEST_F(QueryExecutorTest, TransactionsStorageIsAccessedOnGetPendingTxs) {
      const auto kPageSize = 100u;
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getPendingTransactions(kPageSize)
                       .build();

      EXPECT_CALL(*pending_txs_storage,
                  getPendingTransactions(account_id, kPageSize, ::testing::_))
          .Times(1);

      executeQuery(query);
    }

    /**
     * @given some pending txs storage
     * @when a query is submitted and the storage responds with NOT_FOUND error
     * @then query execturor produces correct stateful failed error
     */
    TEST_F(QueryExecutorTest, PendingTxsStorageWrongTxHash) {
      const auto kPageSize = 100u;
      const auto kFirstTxHash = shared_model::crypto::Hash(zero_string);
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getPendingTransactions(kPageSize, kFirstTxHash)
                       .build();

      EXPECT_CALL(*pending_txs_storage,
                  getPendingTransactions(account_id, kPageSize, ::testing::_))
          .WillOnce(Return(iroha::expected::makeError(
              PendingTransactionStorage::ErrorCode::kNotFound)));

      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          executeQuery(query), 4);
    }

    class GetPeersExecutorTest : public QueryExecutorTest {};

    /**
     * @given initialized storage, permission to get peers
     * @when get peers query issued
     * @then return peers
     */
    TEST_F(GetPeersExecutorTest, Valid) {
      addPerms({shared_model::interface::permissions::Role::kGetPeers});
      auto query =
          TestQueryBuilder().creatorAccountId(account_id).getPeers().build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::PeersResponse>(
          std::move(result), [&expected_peer = peer](const auto &cast_resp) {
            ASSERT_EQ(boost::size(cast_resp.peers()), 1);
            auto &peer = cast_resp.peers().front();
            ASSERT_EQ(peer.address(), expected_peer.address());
            ASSERT_EQ(peer.pubkey(), expected_peer.pubkey());
          });
    }

    /**
     * @given initialized storage, no permission to get peers
     * @when get peers query issued
     * @then return missing permission error
     */
    TEST_F(GetPeersExecutorTest, Invalid) {
      auto query =
          TestQueryBuilder().creatorAccountId(account_id).getPeers().build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kNoPermissions);
    }

  }  // namespace ametsuchi
}  // namespace iroha
