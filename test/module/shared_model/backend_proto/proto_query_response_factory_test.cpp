/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/proto_query_response_factory.hpp"

#include <gtest/gtest.h>

#include <optional>

#include "backend/plain/account_detail_record_id.hpp"
#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "interfaces/query_responses/account_asset_response.hpp"
#include "interfaces/query_responses/account_detail_response.hpp"
#include "interfaces/query_responses/account_response.hpp"
#include "interfaces/query_responses/asset_response.hpp"
#include "interfaces/query_responses/block_error_response.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "interfaces/query_responses/role_permissions.hpp"
#include "interfaces/query_responses/roles_response.hpp"
#include "interfaces/query_responses/signatories_response.hpp"
#include "interfaces/query_responses/transactions_page_response.hpp"
#include "interfaces/query_responses/transactions_response.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"
#include "module/shared_model/cryptography/crypto_defaults.hpp"
#include "validators/field_validator.hpp"

using namespace shared_model::proto;
using namespace iroha::expected;
using namespace shared_model::interface::types;

using shared_model::crypto::Blob;
using shared_model::validation::FieldValidator;

class ProtoQueryResponseFactoryTest : public ::testing::Test {
 public:
  std::shared_ptr<ProtoQueryResponseFactory> response_factory =
      std::make_shared<ProtoQueryResponseFactory>();
  std::shared_ptr<ProtoCommonObjectsFactory<FieldValidator>> objects_factory =
      std::make_shared<ProtoCommonObjectsFactory<FieldValidator>>(
          iroha::test::kTestsValidatorsConfig);

  /**
   * Get value of Result<unique_ptr<_>, _>; throws exception, if there's error
   * inside of result
   * @tparam ResultType - type of result value inside a unique_ptr
   * @tparam ErrorType - type of result error
   * @param res - result to be unwrapped
   * @return shared_ptr to result value
   */
  template <typename ResultType, typename ErrorType>
  std::unique_ptr<ResultType> unwrapResult(
      Result<std::unique_ptr<ResultType>, ErrorType> &&res) {
    return boost::get<iroha::expected::Value<std::unique_ptr<ResultType>>>(
               std::move(res))
        .value;
  }
};

/**
 * Checks createAccountAssetResponse method of QueryResponseFactory
 * @given collection of account assets
 * @when creating account asset query response via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateAccountAssetResponse) {
  const HashType kQueryHash{std::string("my_super_hash")};

  constexpr int kAccountAssetsNumber = 5;
  const std::string kAccountId = "doge@meme";
  const std::string kAssetId = "dogecoin#iroha";

  std::vector<std::unique_ptr<shared_model::interface::QueryResponse>>
      query_responses;
  std::vector<std::unique_ptr<shared_model::interface::AccountAsset>>
      assets_test_copy;
  std::vector<std::tuple<shared_model::interface::types::AccountIdType,
                         shared_model::interface::types::AssetIdType,
                         shared_model::interface::Amount>>
      assets;
  for (auto i = 1; i < kAccountAssetsNumber; ++i) {
    ASSERT_NO_THROW({
      auto asset_copy = unwrapResult(objects_factory->createAccountAsset(
          kAccountId,
          kAssetId,
          shared_model::interface::Amount(std::to_string(i))));
      assets_test_copy.push_back(std::move(asset_copy));
    });
    assets.push_back(
        std::make_tuple(kAccountId,
                        kAssetId,
                        shared_model::interface::Amount(std::to_string(i))));
  }

  query_responses.push_back(response_factory->createAccountAssetResponse(
      assets, assets.size(), std::nullopt, kQueryHash));

  for (auto &query_response : query_responses) {
    ASSERT_TRUE(query_response);
    ASSERT_EQ(query_response->queryHash(), kQueryHash);
    ASSERT_NO_THROW({
      const auto &response =
          boost::get<const shared_model::interface::AccountAssetResponse &>(
              query_response->get());
      ASSERT_EQ(response.accountAssets().front().accountId(), kAccountId);
      ASSERT_EQ(response.accountAssets().front().assetId(), kAssetId);
      for (auto i = 1; i < kAccountAssetsNumber; i++) {
        ASSERT_EQ(response.accountAssets()[i - 1].balance(),
                  assets_test_copy[i - 1]->balance());
      }
    });
  }
}

/**
 * Checks createAccountDetailResponse method of QueryResponseFactory
 * @given account details
 * @when creating account detail query response via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateAccountDetailResponse) {
  const HashType kQueryHash{std::string("my_super_hash")};

  const DetailType account_details = "{ fav_meme : doge }";
  const size_t total_number = 999;
  const shared_model::plain::AccountDetailRecordId next_record_id{"pepe@uganda",
                                                                  "fav_chan"};
  auto query_response = response_factory->createAccountDetailResponse(
      account_details, total_number, next_record_id, kQueryHash);

  ASSERT_TRUE(query_response);
  ASSERT_EQ(query_response->queryHash(), kQueryHash);
  ASSERT_NO_THROW({
    const auto &response =
        boost::get<const shared_model::interface::AccountDetailResponse &>(
            query_response->get());
    EXPECT_EQ(response.detail(), account_details);
    EXPECT_EQ(response.totalNumber(), total_number);
    ASSERT_TRUE(response.nextRecordId());
    EXPECT_EQ(response.nextRecordId().value().get(), next_record_id);
  });
}

/**
 * Checks createAccountResponse method of QueryResponseFactory
 * @given account
 * @when creating account query response via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateAccountResponse) {
  const HashType kQueryHash{std::string("my_super_hash")};

  const AccountIdType kAccountId = "doge@meme";
  const DomainIdType kDomainId = "meme";
  const QuorumType kQuorum = 1;
  const JsonType kJson = "{ fav_meme : doge }";
  const std::vector<RoleIdType> kRoles{"admin", "user"};

  std::unique_ptr<shared_model::interface::Account> account;
  std::vector<std::unique_ptr<shared_model::interface::QueryResponse>>
      query_responses;

  query_responses.push_back(response_factory->createAccountResponse(
      kAccountId, kDomainId, kQuorum, kJson, kRoles, kQueryHash));

  for (auto &query_response : query_responses) {
    ASSERT_TRUE(query_response);
    ASSERT_EQ(query_response->queryHash(), kQueryHash);
    ASSERT_NO_THROW({
      const auto &response =
          boost::get<const shared_model::interface::AccountResponse &>(
              query_response->get());

      ASSERT_EQ(response.account().accountId(), kAccountId);
      ASSERT_EQ(response.account().domainId(), kDomainId);
      ASSERT_EQ(response.account().quorum(), 1);
      ASSERT_EQ(response.account().jsonData(), kJson);
      ASSERT_EQ(response.roles(), kRoles);
    });
  }
}

/**
 * Checks createErrorQueryResponse method of QueryResponseFactory
 * @given
 * @when creating error query responses for a couple of cases via factory
 * @then that responses are created @and are well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateErrorQueryResponse) {
  using ErrorTypes =
      shared_model::interface::QueryResponseFactory::ErrorQueryType;
  const HashType kQueryHash{std::string("my_super_hash")};

  const auto kStatelessErrorMsg = "stateless failed";
  const auto kStatefulFailedErrorMsg = "stateful failed";
  const auto kNoSigsErrorMsg = "no signatories";

  auto stateless_invalid_response = response_factory->createErrorQueryResponse(
      ErrorTypes::kStatelessFailed, kStatelessErrorMsg, 0, kQueryHash);
  auto stateful_failed_response = response_factory->createErrorQueryResponse(
      ErrorTypes::kStatefulFailed, kStatefulFailedErrorMsg, 1, kQueryHash);
  auto no_signatories_response = response_factory->createErrorQueryResponse(
      ErrorTypes::kNoSignatories, kNoSigsErrorMsg, 0, kQueryHash);

  ASSERT_TRUE(stateless_invalid_response);
  ASSERT_EQ(stateless_invalid_response->queryHash(), kQueryHash);
  ASSERT_NO_THROW({
    const auto &general_resp =
        boost::get<const shared_model::interface::ErrorQueryResponse &>(
            stateless_invalid_response->get());

    ASSERT_EQ(general_resp.errorMessage(), kStatelessErrorMsg);
    ASSERT_EQ(general_resp.errorCode(), 0);
    (void)boost::get<
        const shared_model::interface::StatelessFailedErrorResponse &>(
        general_resp.get());
  });

  ASSERT_TRUE(stateful_failed_response);
  ASSERT_EQ(stateful_failed_response->queryHash(), kQueryHash);
  ASSERT_NO_THROW({
    const auto &general_resp =
        boost::get<const shared_model::interface::ErrorQueryResponse &>(
            stateful_failed_response->get());

    ASSERT_EQ(general_resp.errorMessage(), kStatefulFailedErrorMsg);
    ASSERT_EQ(general_resp.errorCode(), 1);
    (void)boost::get<
        const shared_model::interface::StatefulFailedErrorResponse &>(
        general_resp.get());
  });

  ASSERT_TRUE(no_signatories_response);
  ASSERT_EQ(no_signatories_response->queryHash(), kQueryHash);
  ASSERT_NO_THROW({
    const auto &general_resp =
        boost::get<const shared_model::interface::ErrorQueryResponse &>(
            no_signatories_response->get());

    ASSERT_EQ(general_resp.errorMessage(), kNoSigsErrorMsg);
    ASSERT_EQ(general_resp.errorCode(), 0);
    (void)
        boost::get<const shared_model::interface::NoSignatoriesErrorResponse &>(
            general_resp.get());
  });
}

/**
 * Checks createSignatoriesResponse method of QueryResponseFactory
 * @given signatories
 * @when creating signatories query response via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateSignatoriesResponse) {
  const HashType kQueryHash{std::string("my_super_hash")};

  std::vector<std::string> signatories;
  signatories.emplace_back(
      shared_model::crypto::DefaultCryptoAlgorithmType::generateKeypair()
          .publicKey());
  auto query_response =
      response_factory->createSignatoriesResponse(signatories, kQueryHash);

  ASSERT_TRUE(query_response);
  ASSERT_EQ(query_response->queryHash(), kQueryHash);
  ASSERT_NO_THROW({
    const auto &response =
        boost::get<const shared_model::interface::SignatoriesResponse &>(
            query_response->get());

    ASSERT_EQ(response.keys(), signatories);
  });
}

/**
 * Checks createTransactionsResponse method of QueryResponseFactory
 * @given collection of transactions
 * @when creating transactions query response via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateTransactionsResponse) {
  const HashType kQueryHash{std::string("my_super_hash")};

  constexpr int kTransactionsNumber = 5;

  std::vector<std::unique_ptr<shared_model::interface::Transaction>>
      transactions, transactions_test_copy;
  for (auto i = 0; i < kTransactionsNumber; ++i) {
    auto tx = std::make_unique<shared_model::proto::Transaction>(
        TestTransactionBuilder().creatorAccountId(std::to_string(i)).build());
    auto tx_copy = std::make_unique<shared_model::proto::Transaction>(
        TestTransactionBuilder().creatorAccountId(std::to_string(i)).build());
    transactions.push_back(std::move(tx));
    transactions_test_copy.push_back(std::move(tx_copy));
  }
  auto query_response = response_factory->createTransactionsResponse(
      std::move(transactions), kQueryHash);

  ASSERT_TRUE(query_response);
  ASSERT_EQ(query_response->queryHash(), kQueryHash);
  ASSERT_NO_THROW({
    const auto &response =
        boost::get<const shared_model::interface::TransactionsResponse &>(
            query_response->get());

    for (auto i = 0; i < kTransactionsNumber; ++i) {
      ASSERT_EQ(response.transactions()[i].creatorAccountId(),
                transactions_test_copy[i]->creatorAccountId());
    }
  });
}

/**
 * Checks createTransactionsPageResponse method of QueryResponseFactory
 * @given collection of transactions, next tx hash and transactions number
 * @when creating transactions page response via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateTransactionsPageResponse) {
  const HashType kQueryHash{std::string("my_super_hash")};
  const HashType kNextTxHash{std::string("next_tx_hash")};

  constexpr int kTransactionsNumber = 5;

  std::vector<std::unique_ptr<shared_model::interface::Transaction>>
      transactions, transactions_test_copy;
  for (auto i = 0; i < kTransactionsNumber; ++i) {
    auto tx = std::make_unique<shared_model::proto::Transaction>(
        TestTransactionBuilder().creatorAccountId(std::to_string(i)).build());
    auto tx_copy = std::make_unique<shared_model::proto::Transaction>(
        TestTransactionBuilder().creatorAccountId(std::to_string(i)).build());
    transactions.push_back(std::move(tx));
    transactions_test_copy.push_back(std::move(tx_copy));
  }
  auto query_response = response_factory->createTransactionsPageResponse(
      std::move(transactions), kNextTxHash, kTransactionsNumber, kQueryHash);

  ASSERT_TRUE(query_response);
  EXPECT_EQ(query_response->queryHash(), kQueryHash);
  EXPECT_NO_THROW({
    const auto &response =
        boost::get<const shared_model::interface::TransactionsPageResponse &>(
            query_response->get());

    EXPECT_EQ(response.allTransactionsSize(), kTransactionsNumber);
    for (auto i = 0; i < kTransactionsNumber; ++i) {
      EXPECT_EQ(response.transactions()[i].creatorAccountId(),
                transactions_test_copy[i]->creatorAccountId());
    }
    ASSERT_TRUE(response.nextTxHash());
    EXPECT_EQ(response.nextTxHash().value(), kNextTxHash);
  });
}

/**
 * Checks createTransactionsPageResponse method of QueryResponseFactory
 * @given collection of transactions, next tx hash and transactions number
 * @when creating transactions page response via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest,
       CreateTransactionsPageResponseWithoutNextTxHash) {
  const HashType kQueryHash{std::string("my_super_hash")};

  constexpr int kTransactionsNumber = 5;

  std::vector<std::unique_ptr<shared_model::interface::Transaction>>
      transactions, transactions_test_copy;
  for (auto i = 0; i < kTransactionsNumber; ++i) {
    auto tx = std::make_unique<shared_model::proto::Transaction>(
        TestTransactionBuilder().creatorAccountId(std::to_string(i)).build());
    auto tx_copy = std::make_unique<shared_model::proto::Transaction>(
        TestTransactionBuilder().creatorAccountId(std::to_string(i)).build());
    transactions.push_back(std::move(tx));
    transactions_test_copy.push_back(std::move(tx_copy));
  }
  auto query_response = response_factory->createTransactionsPageResponse(
      std::move(transactions), std::nullopt, kTransactionsNumber, kQueryHash);

  ASSERT_TRUE(query_response);
  EXPECT_EQ(query_response->queryHash(), kQueryHash);
  EXPECT_NO_THROW({
    const auto &response =
        boost::get<const shared_model::interface::TransactionsPageResponse &>(
            query_response->get());

    ASSERT_EQ(response.allTransactionsSize(), kTransactionsNumber);
    for (auto i = 0; i < kTransactionsNumber; ++i) {
      EXPECT_EQ(response.transactions()[i].creatorAccountId(),
                transactions_test_copy[i]->creatorAccountId());
    }
    EXPECT_FALSE(response.nextTxHash());
  });
}

/**
 * Checks createAssetResponse method of QueryResponseFactory
 * @given asset
 * @when creating asset query response via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateAssetResponse) {
  const HashType kQueryHash{std::string("my_super_hash")};

  const AssetIdType kAssetId = "doge#coin";
  const DomainIdType kDomainId = "coin";
  const PrecisionType kPrecision = 2;

  std::vector<std::unique_ptr<shared_model::interface::QueryResponse>>
      query_responses;
  query_responses.push_back(response_factory->createAssetResponse(
      kAssetId, kDomainId, kPrecision, kQueryHash));

  for (auto &query_response : query_responses) {
    ASSERT_TRUE(query_response);
    ASSERT_EQ(query_response->queryHash(), kQueryHash);
    ASSERT_NO_THROW({
      const auto &response =
          boost::get<const shared_model::interface::AssetResponse &>(
              query_response->get());

      ASSERT_EQ(response.asset().assetId(), kAssetId);
      ASSERT_EQ(response.asset().domainId(), kDomainId);
      ASSERT_EQ(response.asset().precision(), kPrecision);
    });
  }
}

/**
 * Checks createRolesResponse method of QueryResponseFactory
 * @given collection of roles
 * @when creating roles query response via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateRolesResponse) {
  const HashType kQueryHash{std::string("my_super_hash")};

  const std::vector<RoleIdType> roles{"admin", "user"};
  auto query_response =
      response_factory->createRolesResponse(roles, kQueryHash);

  ASSERT_TRUE(query_response);
  ASSERT_EQ(query_response->queryHash(), kQueryHash);
  ASSERT_NO_THROW({
    const auto &response =
        boost::get<const shared_model::interface::RolesResponse &>(
            query_response->get());

    ASSERT_EQ(response.roles(), roles);
  });
}

/**
 * Checks createRolePermissionsResponse method of QueryResponseFactory
 * @given collection of role permissions
 * @when creating role permissions query response via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateRolePermissionsResponse) {
  const HashType kQueryHash{std::string("my_super_hash")};

  const shared_model::interface::RolePermissionSet perms{
      shared_model::interface::permissions::Role::kGetMyAccount,
      shared_model::interface::permissions::Role::kAddSignatory};
  auto query_response =
      response_factory->createRolePermissionsResponse(perms, kQueryHash);

  ASSERT_TRUE(query_response);
  ASSERT_EQ(query_response->queryHash(), kQueryHash);
  ASSERT_NO_THROW({
    const auto &response =
        boost::get<const shared_model::interface::RolePermissionsResponse &>(
            query_response->get());

    ASSERT_EQ(response.rolePermissions(), perms);
  });
}

/**
 * Checks createBlockQueryResponse method of QueryResponseFactory
 * @given block
 * @when creating block query query response with block via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateBlockQueryResponseWithBlock) {
  constexpr HeightType kBlockHeight = 42;
  const auto kCreatedTime = iroha::time::now();

  auto block =
      TestBlockBuilder().height(kBlockHeight).createdTime(kCreatedTime).build();
  auto response = response_factory->createBlockQueryResponse(
      std::make_unique<Block>(std::move(block)));

  ASSERT_TRUE(response);
  ASSERT_NO_THROW({
    const auto &block_resp =
        boost::get<const shared_model::interface::BlockResponse &>(
            response->get());

    ASSERT_EQ(block_resp.block().height(), kBlockHeight);
    ASSERT_EQ(block_resp.block().createdTime(), kCreatedTime);
  });
}

/**
 * Checks createBlockQueryResponse method of QueryResponseFactory
 * @given error
 * @when creating block query query response with error via factory
 * @then that response is created @and is well-formed
 */
TEST_F(ProtoQueryResponseFactoryTest, CreateBlockQueryResponseWithError) {
  const std::string kErrorMsg = "something's wrong!";
  auto response = response_factory->createBlockQueryResponse(kErrorMsg);

  ASSERT_TRUE(response);
  ASSERT_NO_THROW({
    const auto &error_resp =
        boost::get<const shared_model::interface::BlockErrorResponse &>(
            response->get());

    ASSERT_EQ(error_resp.message(), kErrorMsg);
  });
}
