/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_query_response.hpp"

#include "backend/protobuf/query_responses/proto_account_asset_response.hpp"
#include "backend/protobuf/query_responses/proto_account_detail_response.hpp"
#include "backend/protobuf/query_responses/proto_account_response.hpp"
#include "backend/protobuf/query_responses/proto_asset_response.hpp"
#include "backend/protobuf/query_responses/proto_get_block_response.hpp"
#include "backend/protobuf/query_responses/proto_error_query_response.hpp"
#include "backend/protobuf/query_responses/proto_role_permissions_response.hpp"
#include "backend/protobuf/query_responses/proto_roles_response.hpp"
#include "backend/protobuf/query_responses/proto_signatories_response.hpp"
#include "backend/protobuf/query_responses/proto_transaction_response.hpp"
#include "backend/protobuf/query_responses/proto_transactions_page_response.hpp"
#include "common/byteutils.hpp"
#include "utils/variant_deserializer.hpp"

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
                     shared_model::proto::GetBlockResponse>;

  /// list of types in variant
  using ProtoQueryResponseListType = ProtoQueryResponseVariantType::types;
}  // namespace

namespace shared_model {
  namespace proto {

    struct QueryResponse::Impl {
      explicit Impl(const TransportType &ref) : proto_{ref} {}
      explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}

      TransportType proto_;

      const ProtoQueryResponseVariantType variant_{[this] {
        const auto &ar = proto_;
        int which =
            ar.GetDescriptor()->FindFieldByNumber(ar.response_case())->index();
        return shared_model::detail::variant_impl<ProtoQueryResponseListType>::
            template load<ProtoQueryResponseVariantType>(
                std::forward<decltype(ar)>(ar), which);
      }()};

      const QueryResponseVariantType ivariant_{variant_};

      const crypto::Hash hash_{
          iroha::hexstringToBytestring(proto_.query_hash()).get()};
    };

    QueryResponse::QueryResponse(const QueryResponse &o)
        : QueryResponse(o.impl_->proto_) {}
    QueryResponse::QueryResponse(QueryResponse &&o) noexcept = default;

    QueryResponse::QueryResponse(const TransportType &ref) {
      impl_ = std::make_unique<Impl>(ref);
    }
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

    QueryResponse *QueryResponse::clone() const {
      return new QueryResponse(impl_->proto_);
    }

  }  // namespace proto
}  // namespace shared_model
