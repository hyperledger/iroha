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

#ifdef IROHA_BIND_TYPE
#error IROHA_BIND_TYPE defined.
#endif  // IROHA_BIND_TYPE
#define IROHA_BIND_TYPE(val, type, ...)                   \
  case iroha::protocol::QueryResponse::ResponseCase::val: \
    return ProtoQueryResponseVariantType(shared_model::proto::type(__VA_ARGS__))

namespace shared_model::proto {

  struct QueryResponse::Impl {
    explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}

    TransportType proto_;

    const ProtoQueryResponseVariantType variant_{[this]() -> decltype(
                                                              variant_) {
      auto &ar = proto_;
      switch (ar.response_case()) {
        IROHA_BIND_TYPE(kAccountAssetsResponse, AccountAssetResponse, ar);
        IROHA_BIND_TYPE(kAccountDetailResponse, AccountDetailResponse, ar);
        IROHA_BIND_TYPE(kAccountResponse, AccountResponse, ar);
        IROHA_BIND_TYPE(kErrorResponse, ErrorQueryResponse, ar);
        IROHA_BIND_TYPE(kSignatoriesResponse, SignatoriesResponse, ar);
        IROHA_BIND_TYPE(kTransactionsResponse, TransactionsResponse, ar);
        IROHA_BIND_TYPE(kAssetResponse, AssetResponse, ar);
        IROHA_BIND_TYPE(kRolesResponse, RolesResponse, ar);
        IROHA_BIND_TYPE(kRolePermissionsResponse, RolePermissionsResponse, ar);
        IROHA_BIND_TYPE(
            kTransactionsPageResponse, TransactionsPageResponse, ar);
        IROHA_BIND_TYPE(kPendingTransactionsPageResponse,
                        PendingTransactionsPageResponse,
                        ar);
        IROHA_BIND_TYPE(kBlockResponse, GetBlockResponse, ar);
        IROHA_BIND_TYPE(kPeersResponse, PeersResponse, ar);
        IROHA_BIND_TYPE(kEngineReceiptsResponse, EngineReceiptsResponse, ar);

        default:
        case iroha::protocol::QueryResponse::ResponseCase::RESPONSE_NOT_SET:
          assert(!"Unexpected query response case.");
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
