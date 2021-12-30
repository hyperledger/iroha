/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_query_executor.hpp"

#include <rapidjson/document.h>
#include <rapidjson/rapidjson.h>

#include <boost/format.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/size.hpp>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <thread>
#include <type_traits>

#include "ametsuchi/impl/flat_file/flat_file.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_specific_query_executor.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "backend/plain/peer.hpp"
#include "backend/protobuf/proto_query_response_factory.hpp"
#include "backend/protobuf/queries/proto_ordering.hpp"
#include "common/result.hpp"
#include "datetime/time.hpp"
#include "framework/common_constants.hpp"
#include "framework/result_fixture.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/permissions.hpp"
#include "interfaces/query_responses/account_asset_response.hpp"
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

using namespace std::literals;
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
  const types::PublicKeyHexStringView kPublicKey{"public key"sv};
  const types::PublicKeyHexStringView kPublicKey2{"another public key"sv};
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
                 "fa6ce0e0c21ce1ceaf4ba38538c1868185e9feefeafff3e42d94f218000a5"
                 "533",
                 std::nullopt,
                 false} {
        role_permissions.set(
            shared_model::interface::permissions::Role::kAddMySignatory);
        grantable_permission =
            shared_model::interface::permissions::Grantable::kAddMySignatory;

        query_response_factory =
            std::make_shared<shared_model::proto::ProtoQueryResponseFactory>();
      }

      void SetUp() override {
        AmetsuchiTest::SetUp();

        pending_txs_storage = std::make_shared<MockPendingTransactionStorage>();

        auto query_executor_result = storage->createQueryExecutor(
            pending_txs_storage, query_response_factory);
        IROHA_ASSERT_RESULT_VALUE(query_executor_result)
            << "Failed to create a QueryExecutor.";
        query_executor_ = std::move(query_executor_result).assumeValue();

        execute(
            *mock_command_factory->constructCreateRole(role, role_permissions),
            true);
        execute(*mock_command_factory->constructAddPeer(peer), true);
        execute(*mock_command_factory->constructCreateDomain(domain_id, role),
                true);
        execute(*mock_command_factory->constructCreateAccount(
                    "id", domain_id, kPublicKey),
                true);

        execute(*mock_command_factory->constructCreateDomain(another_domain_id,
                                                             role),
                true);
        execute(*mock_command_factory->constructCreateAccount(
                    "id", another_domain_id, kPublicKey),
                true);
      }

      void TearDown() override {
        query_executor_.reset();
        AmetsuchiTest::TearDown();
      }

      auto executeQuery(shared_model::interface::Query &query) {
        return query_executor_->validateAndExecute(query, false);
      }

      template <typename CommandType>
      void execute(CommandType &&command,
                   bool do_validation = false,
                   const shared_model::interface::types::AccountIdType
                       &creator = "id@domain") {
        shared_model::interface::Command::CommandVariantType variant{
            std::forward<CommandType>(command)};
        shared_model::interface::MockCommand cmd;
        EXPECT_CALL(cmd, get()).WillRepeatedly(::testing::ReturnRef(variant));
        IROHA_ASSERT_RESULT_VALUE(
            command_executor->execute(cmd, creator, "", 0, not do_validation));
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

      void addAllPermsWithoutRoot(
          const shared_model::interface::types::AccountIdType account_id =
              "id@domain",
          const shared_model::interface::types::RoleIdType role_id = "all") {
        shared_model::interface::RolePermissionSet permissions;
        permissions.setAll();
        permissions.unset(shared_model::interface::permissions::Role::kRoot);

        execute(
            *mock_command_factory->constructCreateRole(role_id, permissions),
            true);
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

      void removeAllPerms(
          const shared_model::interface::types::AccountIdType account_id =
              "id@domain",
          const shared_model::interface::types::RoleIdType role_id = "none") {
        shared_model::interface::RolePermissionSet permissions;
        permissions.unsetAll();
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
                    "id2", domain_id, kPublicKey2),
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

      std::unique_ptr<shared_model::interface::Command> command;

      std::shared_ptr<QueryExecutor> query_executor_;
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
      addAllPermsWithoutRoot();
      auto blocks_query =
          TestBlocksQueryBuilder().creatorAccountId(account_id).build();
      ASSERT_TRUE(query_executor_->validate(blocks_query, false));
    }

    /**
     * @given no permissions to get blocks given
     * @when get blocks query is validated
     * @then result is error
     */
    TEST_F(BlocksQueryExecutorTest, BlocksQueryExecutorTestInvalid) {
      auto blocks_query =
          TestBlocksQueryBuilder().creatorAccountId(account_id).build();
      ASSERT_FALSE(query_executor_->validate(blocks_query, false));
    }

    /**
     * @given root permissions
     * @when get blocks query is validated
     * @then result is successful
     */
    TEST_F(BlocksQueryExecutorTest, BlocksQueryExecutorTestValidWithRoot) {
      addPerms({shared_model::interface::permissions::Role::kRoot});
      auto blocks_query =
          TestBlocksQueryBuilder().creatorAccountId(account_id).build();
      ASSERT_TRUE(query_executor_->validate(blocks_query, false));
    }

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
        auto ms = createMutableStorage();

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

    /**
     * @given initialized storage @and root permission
     * @when get block of valid height
     * @then return block
     */
    TEST_F(GetBlockExecutorTest, ValidWithRoot) {
      const shared_model::interface::types::HeightType valid_height = 2;

      addPerms({shared_model::interface::permissions::Role::kRoot});
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

    /**
     * @given initialized storage, root permission
     * @when get system roles
     * @then Return roles
     */
    TEST_F(GetRolesExecutorTest, ValidWithRoot) {
      addPerms({shared_model::interface::permissions::Role::kRoot});
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

    /**
     * @given initialized storage, root permission
     * @when get role permissions
     * @then Return role permissions
     */
    TEST_F(GetRolePermsExecutorTest, ValidWithRoot) {
      addPerms({shared_model::interface::permissions::Role::kRoot});
      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getRolePermissions("perms")
                       .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::RolePermissionsResponse>(
          std::move(result), [](const auto &cast_resp) {
            ASSERT_TRUE(cast_resp.rolePermissions().isSet(
                shared_model::interface::permissions::Role::kRoot));
          });
    }

    class GetTransactionsExecutorTest : public QueryExecutorTest {
     public:
      void SetUp() override {
        QueryExecutorTest::SetUp();
        auto block_storage_persistent_factory =
            std::make_unique<InMemoryBlockStorageFactory>();
        auto block_store = block_storage_persistent_factory->create();
        IROHA_ASSERT_RESULT_VALUE(block_store);
        this->block_store = std::move(block_store).assumeValue();
        createDefaultAccount();
        createDefaultAsset();
      }

      void commitBlocks() {
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

      void commitTransactionsBlock(
          const std::vector<shared_model::proto::Transaction> txs,
          size_t height) {
        auto block = createBlock(txs, height);
        apply(storage, block);
      }

      void commitEachTransactionBlock(
          const std::vector<shared_model::proto::Transaction> txs,
          size_t first,
          size_t last,
          size_t offset) {
        for (size_t i = first; i < last; i++) {
          commitTransactionsBlock(
              std::vector<shared_model::proto::Transaction>{txs[i]},
              i + offset);
        }
      }
      void createTransactionsAndCommitGetTime(size_t transactions_amount,
                                              size_t first_tx_no,
                                              size_t last_tx_no,
                                              uint64_t &first_tx_time,
                                              uint64_t &last_tx_time) {
        addPerms(Impl::getUserPermissions());
        auto initial_txs = Impl::makeInitialTransactions(transactions_amount);
        std::vector<shared_model::proto::Transaction> target_txs;
        for (size_t i = 0; i < transactions_amount; i++) {
          auto tx = Impl::makeTargetTransactions(1).at(0);
          target_txs.emplace_back(tx);
          if (i == first_tx_no) {
            first_tx_time = tx.createdTime();
          }
          if (i == last_tx_no) {
            last_tx_time = tx.createdTime();
          }
        }
        tx_hashes_.reserve(target_txs.size());
        initial_txs.reserve(initial_txs.size() + target_txs.size());
        for (auto &tx : target_txs) {
          tx_hashes_.emplace_back(tx.hash());
          initial_txs.emplace_back(std::move(tx));
        }
        commitTransactionsBlock(initial_txs, 1);
      }
      // create valid transactions and commit them
      void createTransactionsAndCommit(size_t transactions_amount,
                                       bool build_blocks = false) {
        addPerms(Impl::getUserPermissions());

        auto initial_txs = Impl::makeInitialTransactions(transactions_amount);
        auto target_txs = Impl::makeTargetTransactions(transactions_amount);
        auto size_diff = initial_txs.size();
        tx_hashes_.reserve(target_txs.size());
        initial_txs.reserve(initial_txs.size() + target_txs.size());
        for (auto &tx : target_txs) {
          tx_hashes_.emplace_back(tx.hash());
          initial_txs.emplace_back(std::move(tx));
        }
        if (build_blocks) {
          if (size_diff != 0) {
            commitTransactionsBlock(
                std::vector<shared_model::proto::Transaction>(
                    initial_txs.begin(), initial_txs.begin() + size_diff + 1),
                1);
            commitEachTransactionBlock(
                initial_txs, size_diff + 1, initial_txs.size(), 0);
          } else {
            commitEachTransactionBlock(
                initial_txs, size_diff, initial_txs.size(), 1);
          }
        } else {
          commitTransactionsBlock(initial_txs, 1);
        }
      }

      auto queryPage(
          types::TransactionsNumberType page_size,
          const std::optional<types::HashType> &first_hash = std::nullopt,
          const shared_model::interface::Ordering *ordering = nullptr,
          const std::optional<types::TimestampType> &first_tx_time =
              std::nullopt,
          const std::optional<types::TimestampType> &last_tx_time =
              std::nullopt,
          const std::optional<types::HeightType> &first_tx_height =
              std::nullopt,
          const std::optional<types::HeightType> &last_tx_height =
              std::nullopt) {
        auto query = Impl::makeQuery(page_size,
                                     first_hash,
                                     ordering,
                                     first_tx_time,
                                     last_tx_time,
                                     first_tx_height,
                                     last_tx_height);
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
          const std::optional<types::HashType> &first_hash =
              std::nullopt) const {
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
          EXPECT_EQ(tx_page_response.nextTxHash(), std::nullopt)
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
                  .createdTime(1000ull + i)
                  .setAccountDetail(account_id,
                                    "key_" + std::to_string(i),
                                    "val_" + std::to_string(i))
                  .build());
        }
        return transactions;
      }
      static shared_model::proto::Query makeQuery(
          types::TransactionsNumberType page_size,
          const std::optional<types::HashType> &first_hash = std::nullopt,
          const shared_model::interface::Ordering *ordering = nullptr,
          const std::optional<types::TimestampType> &first_tx_time =
              std::nullopt,
          const std::optional<types::TimestampType> &last_tx_time =
              std::nullopt,
          const std::optional<types::HeightType> &first_tx_height =
              std::nullopt,
          const std::optional<types::HeightType> &last_tx_height =
              std::nullopt) {
        return TestQueryBuilder()
            .creatorAccountId(account_id)
            .createdTime(iroha::time::now())
            .getAccountTransactions(account_id,
                                    page_size,
                                    first_hash,
                                    ordering,
                                    first_tx_time,
                                    last_tx_time,
                                    first_tx_height,
                                    last_tx_height)
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
                  .createdTime(1000ull + i)
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
          const std::optional<types::HashType> &first_hash = std::nullopt,
          const shared_model::interface::Ordering *ordering = nullptr,
          const std::optional<types::TimestampType> &first_tx_time =
              std::nullopt,
          const std::optional<types::TimestampType> &last_tx_time =
              std::nullopt,
          const std::optional<types::HeightType> &first_tx_height =
              std::nullopt,
          const std::optional<types::HeightType> &last_tx_height =
              std::nullopt) {
        return TestQueryBuilder()
            .creatorAccountId(account_id)
            .createdTime(iroha::time::now())
            .getAccountAssetTransactions(account_id,
                                         asset_id,
                                         page_size,
                                         first_hash,
                                         ordering,
                                         first_tx_time,
                                         last_tx_time,
                                         first_tx_height,
                                         last_tx_height)
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
      addAllPermsWithoutRoot();

      auto query = TestQueryBuilder()
                       .creatorAccountId(account_id)
                       .getAccountTransactions("some@domain", kTxPageSize)
                       .build();
      auto result = executeQuery(query);
      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          std::move(result), kInvalidAccountId);
    }

    /**
     * @given initialized storage, root permission
     * @when get account transactions
     * @then Return account transactions of user
     */
    TEST_F(GetAccountTransactionsExecutorTest, ValidMyAccountWithRoot) {
      addPerms({shared_model::interface::permissions::Role::kRoot});

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
     * @given initialized storage, root permission
     * @when get account transactions of other user
     * @then Return account transactions
     */
    TEST_F(GetAccountTransactionsExecutorTest, ValidAllAccountsWithRoot) {
      addPerms({shared_model::interface::permissions::Role::kRoot});

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
     * @given initialized storage, root permission
     * @when get account transactions of other user in the same domain
     * @then Return account transactions
     */
    TEST_F(GetAccountTransactionsExecutorTest, ValidDomainAccountWithRoot) {
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

    // ------------------------/ tx pagination tests \----------------------- //
    using QueryTxPaginationTestingTypes =
        ::testing::Types<GetAccountTxPaginationImpl,
                         GetAccountAssetTxPaginationImpl>;
    TYPED_TEST_SUITE(GetPagedTransactionsExecutorTest,
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
     * @when query contains descending ordering by creation time
     * @then response contains exactly 3 transactions
     * @and they are in reverse order
     * @and next transaction hash is not present
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, ValidCreatedTimeRevOrdering) {
      this->createTransactionsAndCommit(3);
      types::HashType *hashes[] = {&this->tx_hashes_.at(2),
                                   &this->tx_hashes_.at(1),
                                   &this->tx_hashes_.at(0)};

      size_t size = 3;
      using Ordering = shared_model::interface::Ordering;

      shared_model::proto::OrderingImpl ordering;
      ordering.append(Ordering::Field::kCreatedTime,
                      Ordering::Direction::kDescending);

      auto query_response = this->queryPage(size, std::nullopt, &ordering);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response),
          [&hashes, size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
            for (size_t ix = 0; ix < size; ++ix) {
              EXPECT_EQ(tx_page_response.transactions()[ix].hash(),
                        *(hashes[ix]));
            }
            EXPECT_FALSE(tx_page_response.nextTxHash());
          });
    }

    /**
     * @given initialized storage, user has 3 transactions committed in one
     * block
     * @when query contains descending ordering by creation time, following
     * ascending creation time following position desc, following asc creation
     * time
     * @then response contains exactly 3 transactions
     * @and they are in reverse creation time order(because the first will have
     * the priority and height is eq)
     * @and next transaction hash is not present
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest,
               ValidCreatedTimeWithStrangeDataOrdering) {
      this->createTransactionsAndCommit(3);
      types::HashType *hashes[] = {&this->tx_hashes_.at(2),
                                   &this->tx_hashes_.at(1),
                                   &this->tx_hashes_.at(0)};

      size_t size = 3;
      using Ordering = shared_model::interface::Ordering;

      shared_model::proto::OrderingImpl ordering;
      ordering.append(Ordering::Field::kCreatedTime,
                      Ordering::Direction::kDescending);
      ordering.append(Ordering::Field::kPosition,
                      Ordering::Direction::kAscending);

      auto query_response = this->queryPage(size, std::nullopt, &ordering);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response),
          [&hashes, size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
            for (size_t ix = 0; ix < size; ++ix) {
              EXPECT_EQ(tx_page_response.transactions()[ix].hash(),
                        *(hashes[ix]));
            }
            EXPECT_FALSE(tx_page_response.nextTxHash());
          });
    }

    /**
     * @given initialized storage, user has 3 transactions committed
     * @when query contains ascending ordering by creation time
     * @then response contains exactly 3 transactions
     * @and they are in straight order
     * @and next transaction hash is not present
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, ValidCreatedTimeOrdering) {
      this->createTransactionsAndCommit(3);
      types::HashType *hashes[] = {&this->tx_hashes_.at(0),
                                   &this->tx_hashes_.at(1),
                                   &this->tx_hashes_.at(2)};

      size_t size = 3;
      using Ordering = shared_model::interface::Ordering;

      shared_model::proto::OrderingImpl ordering;
      ordering.append(Ordering::Field::kCreatedTime,
                      Ordering::Direction::kAscending);

      auto query_response = this->queryPage(size, std::nullopt, &ordering);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response),
          [&hashes, size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
            for (size_t ix = 0; ix < size; ++ix) {
              EXPECT_EQ(tx_page_response.transactions()[ix].hash(),
                        *(hashes[ix]));
            }
            EXPECT_FALSE(tx_page_response.nextTxHash());
          });
    }

    /**
     * @given initialized storage, user has 3 transactions committed
     * @when query contains second transaction as a starting
     * hash @and ascending ordering by creation time
     * @then response contains exactly 1 transaction
     * @and this transaction is second
     * @and next transaction hash is not present
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest,
               ValidCreatedTimeFromLastTxOrdering) {
      this->createTransactionsAndCommit(3);
      auto &hash = this->tx_hashes_.at(2);
      auto size = 3;

      using Ordering = shared_model::interface::Ordering;

      shared_model::proto::OrderingImpl ordering;
      ordering.append(Ordering::Field::kCreatedTime,
                      Ordering::Direction::kAscending);

      auto query_response = this->queryPage(size, hash, &ordering);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [&hash](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), 1);
            EXPECT_EQ(tx_page_response.transactions().begin()->hash(), hash);
            EXPECT_FALSE(tx_page_response.nextTxHash());
          });
    }

    /**
     * @given initialized storage, user has 3 transactions committed
     * @when query contains second transaction as a starting
     * hash @and descending ordering by creation time
     * @then response contains exactly 3 transactions
     * @and the list is starts from second transaction
     * @and next transaction hash is not present
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest,
               ValidCreatedTimeLastTxRevOrdering) {
      this->createTransactionsAndCommit(3);
      auto &hash = this->tx_hashes_.at(2);
      auto size = 3;

      using Ordering = shared_model::interface::Ordering;

      shared_model::proto::OrderingImpl ordering;
      ordering.append(Ordering::Field::kCreatedTime,
                      Ordering::Direction::kDescending);

      auto query_response = this->queryPage(size, hash, &ordering);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response),
          [&hash, size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
            EXPECT_EQ(tx_page_response.transactions().begin()->hash(), hash);
            EXPECT_FALSE(tx_page_response.nextTxHash());
          });
    }

    /**
     * @given initialized storage, user has 3 transactions committed
     * @when query contains second transaction as a starting
     * hash @and ordering with unexpected values, they will be skipped and
     * default ordering take place(Postion ascending)
     * @then response contains exactly 1 transaction
     * @and the list is starts from second transaction
     * @and next transaction hash is not present
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, InvalidOrderingValues) {
      this->createTransactionsAndCommit(3);
      auto &hash = this->tx_hashes_.at(2);
      auto size = 3;

      shared_model::proto::OrderingImpl ordering;
      ordering.append((Ordering::Field)500, (Ordering::Direction)500);

      auto query_response = this->queryPage(size, hash, &ordering);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [&hash](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), 1);
            EXPECT_EQ(tx_page_response.transactions().begin()->hash(), hash);
            EXPECT_FALSE(tx_page_response.nextTxHash());
          });
    }

    /**
     * @given initialized storage, user has 3 transactions committed
     * @when query contains second transaction as a starting
     * hash @and default ordering(Postion ascending)
     * @then response contains exactly 1 transaction
     * @and the list is starts from second transaction
     * @and next transaction hash is not present
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, ValidDefaultOrdering) {
      this->createTransactionsAndCommit(3);
      auto &hash = this->tx_hashes_.at(2);
      auto size = 3;

      auto query_response = this->queryPage(size, hash);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [&hash](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), 1);
            EXPECT_EQ(tx_page_response.transactions().begin()->hash(), hash);
            EXPECT_FALSE(tx_page_response.nextTxHash());
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

    /**
     * @given initialized storage, user has 10 transactions committed
     * @when query contains 10 page size
     * @and first transaction time is before creating transactions
     * @and last transaction time is after creating transactions
     * @then response contains all 10 committed transactions
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, ValidTimeRange) {
      auto size = 10;
      this->createTransactionsAndCommit(size);
      auto first_tx_time = 900ull;
      auto last_tx_time = 10'000ull;
      auto query_response = this->queryPage(
          size, std::nullopt, nullptr, first_tx_time, last_tx_time);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
          });
    }
    /**
     * @given initialized storage, user has 10 transactions committed
     * @when query contains 2 page size
     * @and first tx time is after 2nd transaction
     * @and last tx time is after 5th transaction
     * @then response contains 3 committed transactions
     */

    TYPED_TEST(GetPagedTransactionsExecutorTest,
               FirstAndLastTimeSpecifiedInside) {
      size_t size = 2ull;
      uint64_t first_tx_time = 1005ull;
      uint64_t last_tx_time = first_tx_time + size;
      this->createTransactionsAndCommit(10ull);
      auto query_response = this->queryPage(
          size, std::nullopt, nullptr, first_tx_time, last_tx_time);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
          });
    }
    /**
     * @given initialized storage, user has 10 transactions committed
     * @when query contains 10 page size
     * @and first transaction time is before commiting transactions
     * @then response contains 10 committed transactions
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, TimeRangeNoEnd) {
      auto size = 10;
      this->createTransactionsAndCommit(size);
      auto first_tx_time = 1000ull;
      auto query_response =
          this->queryPage(size, std::nullopt, nullptr, first_tx_time);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
          });
    }

    /**
     * @given initialized storage, user has 10 transactions committed
     * @when query contains 10 page size
     * @and last transaction time is after creating last transaction
     * @then response contains 10 committed transactions
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, LastTimeSpecified) {
      auto size = 10;
      this->createTransactionsAndCommit(size);
      auto first_tx_time = 1000ull;
      auto last_tx_time = first_tx_time + size;
      auto query_response = this->queryPage(
          size, std::nullopt, nullptr, std::nullopt, last_tx_time);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
          });
    }

    /**
     * @given initialized storage, user has 3 transactions committed
     * @when query contains 2 page size
     * @and first block height is 1
     * @and last block height is not specified
     * @then response contains 2 committed transactions
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, FirstHeightSpecified) {
      this->createTransactionsAndCommit(3, true);
      auto size = 2;
      auto query_response = this->queryPage(
          size, std::nullopt, nullptr, std::nullopt, std::nullopt, 1);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
          });
    }
    /**
     * @given initialized storage, user has 10 transactions committed
     * @when query contains 4 page size
     * @and last block height is 5
     * @then response contains 4 committed transactions
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, LastHeightSpecified) {
      this->createTransactionsAndCommit(10, true);
      auto size = 4;
      auto query_response = this->queryPage(size,
                                            std::nullopt,
                                            nullptr,
                                            std::nullopt,
                                            std::nullopt,
                                            std::nullopt,
                                            5);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
          });
    }
    /**
     * @given initialized storage, user has 10 transactions committed
     * @when query contains 2 page size
     * @and first block time is before transactions
     * @and last block time is after transactions
     * @and first block height is 2
     * @and last block height is 5
     * @then response contains 2 committed transactions
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest,
               FirstTimeLastTimeFirstHeightLastHeightSpecified) {
      auto first_tx_time = 900ull;
      this->createTransactionsAndCommit(10, true);
      auto last_tx_time = 10'000ull;
      auto size = 2;
      auto query_response = this->queryPage(
          size, std::nullopt, nullptr, first_tx_time, last_tx_time, 2, 5);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
          });
    }
    /**
     * @given initialized storage, user has 10 transactions committed
     * @when query contains 2 page size
     * @and first block height is 2
     * @and last block height is 5
     * @then response contains 2 committed transactions
     */
    TYPED_TEST(GetPagedTransactionsExecutorTest, FirstAndLastHeightSpecified) {
      this->createTransactionsAndCommit(10, true);
      auto size = 2;
      auto query_response = this->queryPage(
          size, std::nullopt, nullptr, std::nullopt, std::nullopt, 2, 5);
      checkSuccessfulResult<TransactionsPageResponse>(
          std::move(query_response), [size](const auto &tx_page_response) {
            EXPECT_EQ(tx_page_response.transactions().size(), size);
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

    /**
     * @given initialized storage, root permission
     * @when get transactions of other user
     * @then Return transactions
     */
    TEST_F(GetTransactionsHashExecutorTest, ValidAllAccountsWithRoot) {
      addPerms({shared_model::interface::permissions::Role::kRoot});

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

    using GetAccountAssetTransactionsExecutorTest =
        GetPagedTransactionsExecutorTest<GetAccountAssetTxPaginationImpl>;

    /**
     * @given initialized storage, permission to his/her account
     * AND the user does granted transfer from id2 to user in another domain
     * @when get account asset transactions
     * @then Return account asset transactions of user
     */
    TEST_F(GetAccountAssetTransactionsExecutorTest, ValidGranted) {
      addPerms({shared_model::interface::permissions::Role::kGetMyAccAstTxs});

      commitBlocks();

      std::vector<shared_model::proto::Transaction> txs;
      txs.push_back(
          TestTransactionBuilder()
              .creatorAccountId(account_id)
              .transferAsset(
                  account_id2, another_account_id, asset_id, "", "1.0")
              .build());

      auto block = createBlock(txs, 3, second_block_hash);

      apply(storage, block);

      auto hash4 = txs.at(0).hash();

      auto query =
          TestQueryBuilder()
              .creatorAccountId(account_id)
              .getAccountAssetTransactions(account_id, asset_id, kTxPageSize)
              .build();
      auto result = executeQuery(query);
      checkSuccessfulResult<shared_model::interface::TransactionsPageResponse>(
          std::move(result), [this, &hash4](const auto &cast_resp) {
            ASSERT_EQ(cast_resp.transactions().size(), 3);
            ASSERT_EQ(cast_resp.transactions()[0].hash(), hash2);
            ASSERT_EQ(cast_resp.transactions()[1].hash(), hash3);
            ASSERT_EQ(cast_resp.transactions()[2].hash(), hash4);
          });
    }

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
      addAllPermsWithoutRoot();

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
      addAllPermsWithoutRoot();

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

      EXPECT_CALL(
          *pending_txs_storage,
          getPendingTransactions(
              account_id, kPageSize, ::testing::_, ::testing::_, ::testing::_))
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

      EXPECT_CALL(
          *pending_txs_storage,
          getPendingTransactions(
              account_id, kPageSize, ::testing::_, ::testing::_, ::testing::_))
          .WillOnce(Return(iroha::expected::makeError(
              PendingTransactionStorage::ErrorCode::kNotFound)));

      checkStatefulError<shared_model::interface::StatefulFailedErrorResponse>(
          executeQuery(query), 4);
    }

    /**
     * @given initialized storage, root permission
     * @when get account asset transactions
     * @then Return account asset transactions of user
     */
    TEST_F(GetAccountAssetTransactionsExecutorTest, ValidMyAccountWithRoot) {
      addPerms({shared_model::interface::permissions::Role::kRoot});

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
     * @given initialized storage, root permission
     * @when get account asset transactions of other user
     * @then Return account asset transactions
     */
    TEST_F(GetAccountAssetTransactionsExecutorTest, ValidAllAccountsWithRoot) {
      addPerms({shared_model::interface::permissions::Role::kRoot});

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
     * @given initialized storage, root permission
     * @when get account asset transactions of other user in the same domain
     * @then Return account asset transactions
     */
    TEST_F(GetAccountAssetTransactionsExecutorTest,
           ValidDomainAccountWithRoot) {
      addPerms({shared_model::interface::permissions::Role::kRoot});

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
            ASSERT_EQ(peer, expected_peer);
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

    /**
     * @given initialized storage, root permission
     * @when get peers query issued
     * @then return peers
     */
    TEST_F(GetPeersExecutorTest, ValidWithRoot) {
      addPerms({shared_model::interface::permissions::Role::kRoot});
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

  }  // namespace ametsuchi
}  // namespace iroha
