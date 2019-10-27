/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/query_response_factory.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include "backend/plain/account_detail_record_id.hpp"
#include "backend/plain/common_objects/account_asset.hpp"
#include "backend/plain/query_responses/account_asset_response.hpp"
#include "backend/plain/query_responses/account_detail_response.hpp"
#include "backend/plain/query_responses/error_query_response.hpp"
#include "backend/plain/query_responses/query_response.hpp"
#include "backend/plain/query_responses/signatories_response.hpp"
#include "common/bind.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/query_responses/account_response.hpp"
#include "interfaces/query_responses/asset_response.hpp"
#include "interfaces/query_responses/block_error_response.hpp"
#include "interfaces/query_responses/block_query_response.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "interfaces/query_responses/peers_response.hpp"
#include "interfaces/query_responses/pending_transactions_page_response.hpp"
#include "interfaces/query_responses/query_response.hpp"
#include "interfaces/query_responses/query_response_variant.hpp"
#include "interfaces/query_responses/role_permissions.hpp"
#include "interfaces/query_responses/roles_response.hpp"
#include "interfaces/query_responses/transactions_page_response.hpp"
#include "interfaces/query_responses/transactions_response.hpp"
#include "interfaces/transaction.hpp"

using namespace shared_model::interface::types;

using shared_model::interface::QueryResponse;
using shared_model::plain::QueryResponseFactory;
using iroha::operator|;

namespace {
  void unimplimented() {
    BOOST_ASSERT_MSG(false, "unimplimented");
  }

  template <typename SpecificQueryResponse, typename... Args>
  std::unique_ptr<QueryResponse> makeQueryResponse(
      const shared_model::crypto::Hash query_hash, Args &&... args) {
    auto specific_response =
        std::make_unique<SpecificQueryResponse>(std::forward<Args>(args)...);
    return std::make_unique<shared_model::plain::QueryResponse>(
        std::move(specific_response), query_hash);
  }

  shared_model::plain::ErrorQueryResponse::VariantHolder makeSpecificError(
      QueryResponseFactory::ErrorQueryType error_type) {
    switch (error_type) {
      case QueryResponseFactory::ErrorQueryType::kStatelessFailed:
        return std::make_unique<
            shared_model::interface::StatelessFailedErrorResponse>();
      case QueryResponseFactory::ErrorQueryType::kStatefulFailed:
        return std::make_unique<
            shared_model::interface::StatefulFailedErrorResponse>();
      case QueryResponseFactory::ErrorQueryType::kNoAccount:
        return std::make_unique<
            shared_model::interface::NoAccountErrorResponse>();
      case QueryResponseFactory::ErrorQueryType::kNoAccountAssets:
        return std::make_unique<
            shared_model::interface::NoAccountAssetsErrorResponse>();
      case QueryResponseFactory::ErrorQueryType::kNoAccountDetail:
        return std::make_unique<
            shared_model::interface::NoAccountDetailErrorResponse>();
      case QueryResponseFactory::ErrorQueryType::kNoSignatories:
        return std::make_unique<
            shared_model::interface::NoSignatoriesErrorResponse>();
      case QueryResponseFactory::ErrorQueryType::kNotSupported:
        return std::make_unique<
            shared_model::interface::NotSupportedErrorResponse>();
      case QueryResponseFactory::ErrorQueryType::kNoAsset:
        return std::make_unique<
            shared_model::interface::NoAssetErrorResponse>();
      case QueryResponseFactory::ErrorQueryType::kNoRoles:
        return std::make_unique<
            shared_model::interface::NoRolesErrorResponse>();
      default:
        BOOST_ASSERT_MSG(false, "Unimplemented specific error response!");
        return std::make_unique<
            shared_model::interface::NotSupportedErrorResponse>();
    }
  }
}  // namespace

std::unique_ptr<QueryResponse> QueryResponseFactory::createAccountAssetResponse(
    std::vector<
        std::tuple<AccountIdType, AssetIdType, shared_model::interface::Amount>>
        assets,
    size_t total_assets_number,
    boost::optional<AssetIdType> next_asset_id,
    const crypto::Hash &query_hash) const {
  static const auto make_account_asset = [](auto &&asset_tuple)
      -> std::unique_ptr<shared_model::interface::AccountAsset> {
    return std::make_unique<shared_model::plain::AccountAsset>(
        std::get<0>(asset_tuple),
        std::get<1>(asset_tuple),
        std::get<2>(asset_tuple));
  };
  return makeQueryResponse<shared_model::plain::AccountAssetResponse>(
      query_hash,
      boost::copy_range<
          shared_model::plain::AccountAssetResponse::AssetsHolder>(
          assets | boost::adaptors::transformed(make_account_asset)),
      std::move(next_asset_id),
      total_assets_number);
}

std::unique_ptr<QueryResponse>
QueryResponseFactory::createAccountDetailResponse(
    DetailType account_detail,
    size_t total_number,
    boost::optional<const shared_model::interface::AccountDetailRecordId &>
        next_record_id,
    const crypto::Hash &query_hash) const {
  return makeQueryResponse<shared_model::plain::AccountDetailResponse>(
      query_hash,
      std::move(account_detail),
      total_number,
      next_record_id | [](const auto &next_record_id) {
        return std::unique_ptr<shared_model::interface::AccountDetailRecordId>(
            std::make_unique<shared_model::plain::AccountDetailRecordId>(
                next_record_id.writer(), next_record_id.key()));
      });
}

std::unique_ptr<QueryResponse> QueryResponseFactory::createAccountResponse(
    AccountIdType account_id,
    DomainIdType domain_id,
    QuorumType quorum,
    JsonType jsonData,
    std::vector<std::string> roles,
    const crypto::Hash &query_hash) const {
  unimplimented();
  return {};
}

std::unique_ptr<QueryResponse> QueryResponseFactory::createBlockResponse(
    std::unique_ptr<interface::Block> block,
    const crypto::Hash &query_hash) const {
  unimplimented();
  return {};
}

std::unique_ptr<QueryResponse> QueryResponseFactory::createErrorQueryResponse(
    ErrorQueryType error_type,
    interface::ErrorQueryResponse::ErrorMessageType error_msg,
    interface::ErrorQueryResponse::ErrorCodeType error_code,
    const crypto::Hash &query_hash) const {
  return makeQueryResponse<shared_model::plain::ErrorQueryResponse>(
      query_hash,
      makeSpecificError(error_type),
      std::move(error_msg),
      error_code);
}

std::unique_ptr<QueryResponse> QueryResponseFactory::createSignatoriesResponse(
    std::vector<PubkeyType> signatories, const crypto::Hash &query_hash) const {
  return makeQueryResponse<shared_model::plain::SignatoriesResponse>(
      query_hash, std::move(signatories));
}

std::unique_ptr<QueryResponse> QueryResponseFactory::createTransactionsResponse(
    std::vector<std::unique_ptr<shared_model::interface::Transaction>>
        transactions,
    const crypto::Hash &query_hash) const {
  unimplimented();
  return {};
}

std::unique_ptr<QueryResponse>
QueryResponseFactory::createTransactionsPageResponse(
    std::vector<std::unique_ptr<shared_model::interface::Transaction>>
        transactions,
    boost::optional<const crypto::Hash &> next_tx_hash,
    TransactionsNumberType all_transactions_size,
    const crypto::Hash &query_hash) const {
  unimplimented();
  return {};
}

std::unique_ptr<QueryResponse>
QueryResponseFactory::createPendingTransactionsPageResponse(
    std::vector<std::unique_ptr<shared_model::interface::Transaction>>
        transactions,
    TransactionsNumberType all_transactions_size,
    boost::optional<interface::PendingTransactionsPageResponse::BatchInfo>
        next_batch_info,
    const crypto::Hash &query_hash) const {
  unimplimented();
  return {};
}

std::unique_ptr<QueryResponse> QueryResponseFactory::createAssetResponse(
    AssetIdType asset_id,
    DomainIdType domain_id,
    PrecisionType precision,
    const crypto::Hash &query_hash) const {
  unimplimented();
  return {};
}

std::unique_ptr<QueryResponse> QueryResponseFactory::createRolesResponse(
    std::vector<RoleIdType> roles, const crypto::Hash &query_hash) const {
  unimplimented();
  return {};
}

std::unique_ptr<QueryResponse>
QueryResponseFactory::createRolePermissionsResponse(
    interface::RolePermissionSet role_permissions,
    const crypto::Hash &query_hash) const {
  unimplimented();
  return {};
}

std::unique_ptr<QueryResponse> QueryResponseFactory::createPeersResponse(
    PeerList peers, const crypto::Hash &query_hash) const {
  unimplimented();
  return {};
}

std::unique_ptr<shared_model::interface::BlockQueryResponse>
QueryResponseFactory::createBlockQueryResponse(
    std::shared_ptr<const interface::Block> block) const {
  unimplimented();
  return {};
}

std::unique_ptr<shared_model::interface::BlockQueryResponse>
QueryResponseFactory::createBlockQueryResponse(
    std::string error_message) const {
  unimplimented();
  return {};
}
