/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_query_response.hpp"

#include "backend/protobuf/query_responses/proto_account_asset_response.hpp"
#include "backend/protobuf/query_responses/proto_account_detail_response.hpp"
#include "backend/protobuf/query_responses/proto_account_response.hpp"
#include "backend/protobuf/query_responses/proto_asset_response.hpp"
#include "backend/protobuf/query_responses/proto_engine_receipts_response.hpp"
#include "backend/protobuf/query_responses/proto_error_query_response.hpp"
#include "backend/protobuf/query_responses/proto_get_block_response.hpp"
#include "backend/protobuf/query_responses/proto_peers_response.hpp"
#include "backend/protobuf/query_responses/proto_pending_transactions_page_response.hpp"
#include "backend/protobuf/query_responses/proto_role_permissions_response.hpp"
#include "backend/protobuf/query_responses/proto_roles_response.hpp"
#include "backend/protobuf/query_responses/proto_signatories_response.hpp"
#include "backend/protobuf/query_responses/proto_transaction_response.hpp"
#include "backend/protobuf/query_responses/proto_transactions_page_response.hpp"
#include "common/byteutils.hpp"
#include "common/report_abort.h"

namespace {
  /// type of proto variant
  using ProtoQueryResponseVariantType =
      boost::variant<shared_model::proto::AccountAssetResponse,
                     shared_model::proto::AccountDetailResponse,
                     shared_model::proto::AccountResponse,
                     shared_model::proto::ErrorQueryResponse,
                     shared_model::proto::SignatoriesResponse,
                     shared_model::proto::TransactionsResponse,
                     shared_model::proto::AssetResponse,
                     shared_model::proto::RolesResponse,
                     shared_model::proto::RolePermissionsResponse,
                     shared_model::proto::TransactionsPageResponse,
                     shared_model::proto::PendingTransactionsPageResponse,
                     shared_model::proto::GetBlockResponse,
                     shared_model::proto::PeersResponse,
                     shared_model::proto::EngineReceiptsResponse>;
}  // namespace

namespace shared_model::proto {

  struct QueryResponse::Impl {
    explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}

    TransportType proto_;

    const ProtoQueryResponseVariantType variant_{
        [this]() -> ProtoQueryResponseVariantType {
          using iroha::protocol::QueryResponse;
          switch (proto_.response_case()) {
            // clang-format off
            case QueryResponse::ResponseCase::kAccountAssetsResponse: return AccountAssetResponse(proto_);
            case QueryResponse::ResponseCase::kAccountDetailResponse: return AccountDetailResponse(proto_);
            case QueryResponse::ResponseCase::kAccountResponse: return AccountResponse(proto_);
            case QueryResponse::ResponseCase::kErrorResponse: return ErrorQueryResponse(proto_);
            case QueryResponse::ResponseCase::kSignatoriesResponse: return SignatoriesResponse(proto_);
            case QueryResponse::ResponseCase::kTransactionsResponse: return TransactionsResponse(proto_);
            case QueryResponse::ResponseCase::kAssetResponse: return AssetResponse(proto_);
            case QueryResponse::ResponseCase::kRolesResponse: return RolesResponse(proto_);
            case QueryResponse::ResponseCase::kRolePermissionsResponse: return RolePermissionsResponse(proto_);
            case QueryResponse::ResponseCase::kTransactionsPageResponse: return TransactionsPageResponse(proto_);
            case QueryResponse::ResponseCase::kPendingTransactionsPageResponse: return PendingTransactionsPageResponse(proto_);
            case QueryResponse::ResponseCase::kBlockResponse: return GetBlockResponse(proto_);
            case QueryResponse::ResponseCase::kPeersResponse: return PeersResponse(proto_);
            case QueryResponse::ResponseCase::kEngineReceiptsResponse: return EngineReceiptsResponse(proto_);
            // clang-format on
            default:
            case iroha::protocol::QueryResponse::ResponseCase::RESPONSE_NOT_SET:
              report_abort("Unexpected query response case.");
          }
        }()};

    const QueryResponseVariantType ivariant_{variant_};

    const crypto::Hash hash_{
        iroha::hexstringToBytestring(proto_.query_hash()).get()};
  };

  QueryResponse::QueryResponse(TransportType &&ref) {
    impl_ = std::make_unique<Impl>(std::move(ref));
  }

  QueryResponse::~QueryResponse() = default;

  const QueryResponse::QueryResponseVariantType &QueryResponse::get() const {
    return impl_->ivariant_;
  }

  const interface::types::HashType &QueryResponse::queryHash() const {
    return impl_->hash_;
  }

  const QueryResponse::TransportType &QueryResponse::getTransport() const {
    return impl_->proto_;
  }

}  // namespace shared_model::proto

#undef IROHA_BIND_TYPE
