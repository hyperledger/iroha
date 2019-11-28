/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_query_response.hpp"

#include "backend/protobuf/query_responses/proto_account_asset_response.hpp"
#include "backend/protobuf/query_responses/proto_account_detail_response.hpp"
#include "backend/protobuf/query_responses/proto_account_response.hpp"
#include "backend/protobuf/query_responses/proto_asset_response.hpp"
#include "backend/protobuf/query_responses/proto_block_response.hpp"
#include "backend/protobuf/query_responses/proto_error_query_response.hpp"
#include "backend/protobuf/query_responses/proto_peers_response.hpp"
#include "backend/protobuf/query_responses/proto_pending_transactions_page_response.hpp"
#include "backend/protobuf/query_responses/proto_role_permissions_response.hpp"
#include "backend/protobuf/query_responses/proto_roles_response.hpp"
#include "backend/protobuf/query_responses/proto_signatories_response.hpp"
#include "backend/protobuf/query_responses/proto_transaction_response.hpp"
#include "backend/protobuf/query_responses/proto_transactions_page_response.hpp"
#include "common/result.hpp"
#include "common/variant_transform.hpp"
#include "cryptography/blob.hpp"
#include "qry_responses.pb.h"

using namespace shared_model::proto;

using PbQueryResponse = iroha::protocol::QueryResponse;

namespace {
  using ProtoResponseVariantType =
      iroha::VariantOfUniquePtr<AccountAssetResponse,
                                AccountDetailResponse,
                                AccountResponse,
                                ErrorQueryResponse,
                                SignatoriesResponse,
                                TransactionsResponse,
                                AssetResponse,
                                RolesResponse,
                                RolePermissionsResponse,
                                TransactionsPageResponse,
                                PendingTransactionsPageResponse,
                                BlockResponse,
                                PeersResponse>;

  iroha::AggregateValueResult<ProtoResponseVariantType::types, std::string>
  loadAggregateResult(PbQueryResponse &proto) {
    switch (proto.response_case()) {
      case PbQueryResponse::kAccountAssetsResponse:
        return std::make_unique<AccountAssetResponse>(proto);
      case PbQueryResponse::kAccountDetailResponse:
        return std::make_unique<AccountDetailResponse>(proto);
      case PbQueryResponse::kAccountResponse:
        return std::make_unique<AccountResponse>(proto);
      case PbQueryResponse::kErrorResponse:
        return ErrorQueryResponse::create(proto).variant();
      case PbQueryResponse::kSignatoriesResponse:
        return SignatoriesResponse::create(proto).variant();
      case PbQueryResponse::kTransactionsResponse:
        return TransactionsResponse::create(proto).variant();
      case PbQueryResponse::kAssetResponse:
        return std::make_unique<AssetResponse>(proto);
      case PbQueryResponse::kRolesResponse:
        return std::make_unique<RolesResponse>(proto);
      case PbQueryResponse::kRolePermissionsResponse:
        return std::make_unique<RolePermissionsResponse>(proto);
      case PbQueryResponse::kTransactionsPageResponse:
        return TransactionsPageResponse::create(proto).variant();
      case PbQueryResponse::kPendingTransactionsPageResponse:
        return PendingTransactionsPageResponse::create(proto).variant();
      case PbQueryResponse::kBlockResponse:
        return BlockResponse::create(proto.block_response()).variant();
      case PbQueryResponse::kPeersResponse:
        return PeersResponse::create(proto).variant();
      default:
        return "Unknown response.";
    };
  }

  iroha::expected::Result<ProtoResponseVariantType, std::string> load(
      PbQueryResponse &proto) {
    return loadAggregateResult(proto);
  }
}  // namespace

struct QueryResponse::Impl {
  explicit Impl(std::unique_ptr<TransportType> &&proto,
                ProtoResponseVariantType response_holder,
                shared_model::crypto::Hash &&hash)
      : proto_(std::move(proto)),
        response_holder_(std::move(response_holder)),
        response_constref_(boost::apply_visitor(
            iroha::indirecting_visitor<QueryResponseVariantType>,
            response_holder_)),
        hash_(std::move(hash)) {}

  std::unique_ptr<TransportType> proto_;
  ProtoResponseVariantType response_holder_;
  QueryResponseVariantType response_constref_;
  const shared_model::crypto::Hash hash_;
};

iroha::expected::Result<std::unique_ptr<QueryResponse>, std::string>
QueryResponse::create(TransportType proto) {
  // load(TransportType&) keeps the reference to proto, so it must stay valid
  auto proto_ptr = std::make_unique<TransportType>(std::move(proto));
  return load(*proto_ptr) | [&](auto &&response) {
    return shared_model::crypto::Blob::fromHexString(proto_ptr->query_hash()) |
        [&](auto &&hash) {
          return std::unique_ptr<QueryResponse>(
              new QueryResponse(std::make_unique<Impl>(
                  std::move(proto_ptr),
                  std::move(response),
                  shared_model::crypto::Hash{std::move(hash)})));
        };
  };
}

QueryResponse::QueryResponse(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

QueryResponse::~QueryResponse() = default;

const QueryResponse::QueryResponseVariantType &QueryResponse::get() const {
  return impl_->response_constref_;
}

const shared_model::interface::types::HashType &QueryResponse::queryHash()
    const {
  return impl_->hash_;
}

const QueryResponse::TransportType &QueryResponse::getTransport() const {
  return *impl_->proto_;
}
