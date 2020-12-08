/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_QUERY_RESPONSE_FACTORY_HPP
#define IROHA_PROTO_QUERY_RESPONSE_FACTORY_HPP

#include "interfaces/iroha_internal/query_response_factory.hpp"

namespace shared_model {
  namespace proto {

    class ProtoQueryResponseFactory : public interface::QueryResponseFactory {
     public:
      std::unique_ptr<interface::QueryResponse> createAccountAssetResponse(
          std::vector<std::tuple<interface::types::AccountIdType,
                                 interface::types::AssetIdType,
                                 shared_model::interface::Amount>> assets,
          size_t total_assets_number,
          std::optional<shared_model::interface::types::AssetIdType>
              next_asset_id,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createAccountDetailResponse(
          interface::types::DetailType account_detail,
          size_t total_number,
          std::optional<std::reference_wrapper<
              const shared_model::interface::AccountDetailRecordId>>
              next_record_id,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createAccountResponse(
          interface::types::AccountIdType account_id,
          interface::types::DomainIdType domain_id,
          interface::types::QuorumType quorum,
          interface::types::JsonType jsonData,
          std::vector<std::string> roles,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createBlockResponse(
          std::unique_ptr<interface::Block> block,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createErrorQueryResponse(
          ErrorQueryType error_type,
          interface::ErrorQueryResponse::ErrorMessageType error_msg,
          interface::ErrorQueryResponse::ErrorCodeType error_code,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createSignatoriesResponse(
          std::vector<std::string> signatories,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createTransactionsResponse(
          std::vector<std::unique_ptr<shared_model::interface::Transaction>>
              transactions,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createTransactionsPageResponse(
          std::vector<std::unique_ptr<shared_model::interface::Transaction>>
              transactions,
          std::optional<std::reference_wrapper<const crypto::Hash>>
              next_tx_hash,
          interface::types::TransactionsNumberType all_transactions_size,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse>
      createPendingTransactionsPageResponse(
          std::vector<std::unique_ptr<shared_model::interface::Transaction>>
              transactions,
          interface::types::TransactionsNumberType all_transactions_size,
          std::optional<interface::PendingTransactionsPageResponse::BatchInfo>
              next_batch_info,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createAssetResponse(
          interface::types::AssetIdType asset_id,
          interface::types::DomainIdType domain_id,
          interface::types::PrecisionType precision,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createRolesResponse(
          std::vector<interface::types::RoleIdType> roles,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createRolePermissionsResponse(
          interface::RolePermissionSet role_permissions,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createPeersResponse(
          interface::types::PeerList peers,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::QueryResponse> createEngineReceiptsResponse(
          const std::vector<std::unique_ptr<interface::EngineReceipt>>
              &engine_response_records,
          const crypto::Hash &query_hash) const override;

      std::unique_ptr<interface::BlockQueryResponse> createBlockQueryResponse(
          std::shared_ptr<const interface::Block> block) const override;

      std::unique_ptr<interface::BlockQueryResponse> createBlockQueryResponse(
          std::string error_message) const override;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_QUERY_RESPONSE_FACTORY_HPP
