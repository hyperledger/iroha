/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "model/converters/pb_query_response_factory.hpp"

using namespace iroha;

TEST(QueryResponseTest, AccountTest) {
  model::converters::PbQueryResponseFactory pb_factory;
  model::Account account;
  account.account_id = "123";
  account.domain_id = "domain";
  account.quorum = 32;

  auto pb_account = pb_factory.serializeAccount(account);
  auto des_account = pb_factory.deserializeAccount(pb_account);

  ASSERT_EQ(account.account_id, des_account.account_id);
  ASSERT_EQ(account.domain_id, des_account.domain_id);
  ASSERT_EQ(account.quorum, account.quorum);
}

TEST(QueryResponseTest, AccountResponseTest) {
  model::converters::PbQueryResponseFactory pb_factory;

  model::Account account;
  account.account_id = "123";
  account.domain_id = "domain";
  account.quorum = 32;

  model::AccountResponse accountResponse;
  accountResponse.account = account;

  auto pb_account_response =
      pb_factory.serializeAccountResponse(accountResponse);
  auto des_account_response =
      pb_factory.deserializeAccountResponse(pb_account_response);

  ASSERT_EQ(accountResponse.account.account_id,
            des_account_response.account.account_id);
  ASSERT_EQ(accountResponse.account.domain_id,
            des_account_response.account.domain_id);
  ASSERT_EQ(accountResponse.account.quorum, account.quorum);
}

TEST(QueryResponseTest, AccountAsset) {
  model::converters::PbQueryResponseFactory pb_factory;

  model::AccountAsset account_asset;
  account_asset.account_id = "123";
  account_asset.asset_id = "123";
  account_asset.balance = "1";

  auto pb_account_asset = pb_factory.serializeAccountAsset(account_asset);
  auto des_account_asset = pb_factory.deserializeAccountAsset(pb_account_asset);

  ASSERT_EQ(account_asset.balance, des_account_asset.balance);
  ASSERT_EQ(account_asset.asset_id, des_account_asset.asset_id);
  ASSERT_EQ(account_asset.account_id, des_account_asset.account_id);

  model::AccountAssetResponse account_asset_response;
  account_asset_response.acct_assets = {account_asset};

  auto shrd_aar = std::make_shared<decltype(account_asset_response)>(
      account_asset_response);
  auto query_response = *pb_factory.serialize(shrd_aar);

  auto des_account_asset_response = pb_factory.deserializeAccountAssetResponse(
      query_response.account_assets_response());

  ASSERT_EQ(des_account_asset_response.acct_assets[0].balance,
            des_account_asset.balance);
  ASSERT_EQ(des_account_asset_response.acct_assets[0].asset_id,
            des_account_asset.asset_id);
  ASSERT_EQ(des_account_asset_response.acct_assets[0].account_id,
            des_account_asset.account_id);
}

/**
 * @given AccountDetailResponse
 * @when Set all data
 * @then Return Protobuf Data
 */
TEST(QueryResponseTest, AccountDetailResponse) {
  model::converters::PbQueryResponseFactory pb_factory;

  std::string detail = "{}";

  model::AccountDetailResponse account_detail_response;
  account_detail_response.detail = detail;

  auto shrd_acc_detail_res =
      std::make_shared<decltype(account_detail_response)>(
          account_detail_response);
  auto query_response = *pb_factory.serialize(shrd_acc_detail_res);

  auto des_account_detail_response =
      pb_factory.deserializeAccountDetailResponse(
          query_response.account_detail_response());

  ASSERT_EQ(des_account_detail_response.detail, account_detail_response.detail);
}

TEST(QueryResponseTest, SignatoriesTest) {
  model::converters::PbQueryResponseFactory pb_factory;

  model::SignatoriesResponse signatories_response{};
  pubkey_t pubkey;
  std::fill(pubkey.begin(), pubkey.end(), 0x1);
  signatories_response.keys.push_back(pubkey);

  auto shrd_sr =
      std::make_shared<decltype(signatories_response)>(signatories_response);
  auto query_response = *pb_factory.serialize(shrd_sr);
  auto des_signatories_response = pb_factory.deserializeSignatoriesResponse(
      query_response.signatories_response());

  ASSERT_EQ(signatories_response.keys, des_signatories_response.keys);
}

TEST(QueryResponseTest, TransactionsResponseTest) {
  model::converters::PbQueryResponseFactory pb_factory;

  model::TransactionsResponse txs_response{};

  txs_response.transactions = rxcpp::observable<>::iterate([] {
    std::vector<model::Transaction> result;
    for (size_t i = 0; i < 3; ++i) {
      model::Transaction current;
      result.push_back(current);
    }
    return result;
  }());

  auto shrd_tr = std::make_shared<decltype(txs_response)>(txs_response);
  auto query_response = *pb_factory.serialize(shrd_tr);

  ASSERT_EQ(query_response.transactions_response().transactions().size(), 3);
}

TEST(QueryResponseTest, roles_response) {
  model::converters::PbQueryResponseFactory pb_factory;

  model::RolesResponse response{};
  response.roles = {"master", "padawan", "council"};

  auto shrd_resp = std::make_shared<decltype(response)>(response);
  auto query_response = *pb_factory.serialize(shrd_resp);

  ASSERT_EQ(response.roles.size(),
            query_response.roles_response().roles().size());
  for (size_t i = 0; i < response.roles.size(); i++) {
    ASSERT_EQ(query_response.roles_response().roles().Get(i),
              response.roles.at(i));
  }
}

TEST(QueryResponseTest, role_permissions) {
  model::converters::PbQueryResponseFactory pb_factory;

  model::RolePermissionsResponse response{};
  response.role_permissions = {1, 2};

  auto shrd_resp = std::make_shared<decltype(response)>(response);
  auto query_response = *pb_factory.serialize(shrd_resp);

  ASSERT_EQ(response.role_permissions.size(),
            query_response.role_permissions_response().permissions().size());
  for (size_t i = 0; i < response.role_permissions.size(); i++) {
    ASSERT_EQ(query_response.role_permissions_response().permissions().Get(i),
              response.role_permissions.at(i));
  }
}

TEST(QueryResponseTest, asset_response) {
  model::converters::PbQueryResponseFactory pb_factory;

  model::AssetResponse response{};
  response.asset.asset_id = "coin#test";
  response.asset.domain_id = "test";
  response.asset.precision = 2;

  auto shrd_resp = std::make_shared<decltype(response)>(response);
  auto query_response = *pb_factory.serialize(shrd_resp);

  ASSERT_EQ(response.asset.asset_id,
            query_response.asset_response().asset().asset_id());
  ASSERT_EQ(response.asset.domain_id,
            query_response.asset_response().asset().domain_id());
  ASSERT_EQ(response.asset.precision,
            query_response.asset_response().asset().precision());
}
