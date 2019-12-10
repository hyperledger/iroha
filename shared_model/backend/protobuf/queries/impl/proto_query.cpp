/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_query.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include "backend/protobuf/common_objects/signature.hpp"
#include "backend/protobuf/queries/proto_get_account.hpp"
#include "backend/protobuf/queries/proto_get_account_asset_transactions.hpp"
#include "backend/protobuf/queries/proto_get_account_assets.hpp"
#include "backend/protobuf/queries/proto_get_account_detail.hpp"
#include "backend/protobuf/queries/proto_get_account_transactions.hpp"
#include "backend/protobuf/queries/proto_get_asset_info.hpp"
#include "backend/protobuf/queries/proto_get_block.hpp"
#include "backend/protobuf/queries/proto_get_peers.hpp"
#include "backend/protobuf/queries/proto_get_pending_transactions.hpp"
#include "backend/protobuf/queries/proto_get_role_permissions.hpp"
#include "backend/protobuf/queries/proto_get_roles.hpp"
#include "backend/protobuf/queries/proto_get_signatories.hpp"
#include "backend/protobuf/queries/proto_get_transactions.hpp"
#include "backend/protobuf/util.hpp"
#include "common/result.hpp"
#include "common/variant_transform.hpp"
#include "queries.pb.h"

using namespace shared_model::proto;
using namespace shared_model::interface::types;

using iroha::expected::Result;
using iroha::expected::ResultException;

using PbQuery = iroha::protocol::Query;

namespace {
  /// type of proto variant
  using ProtoQueryVariantType =
      iroha::VariantOfUniquePtr<GetAccount,
                                GetSignatories,
                                GetAccountTransactions,
                                GetAccountAssetTransactions,
                                GetTransactions,
                                GetAccountAssets,
                                GetAccountDetail,
                                GetRoles,
                                GetRolePermissions,
                                GetAssetInfo,
                                GetPendingTransactions,
                                GetBlock,
                                GetPeers>;

  iroha::AggregateValueResult<ProtoQueryVariantType::types, std::string>
  loadAggregateResult(PbQuery &pb_query) {
    switch (pb_query.payload().query_case()) {
      case PbQuery::Payload::kGetAccount:
        return std::make_unique<GetAccount>(pb_query);
      case PbQuery::Payload::kGetSignatories:
        return std::make_unique<GetSignatories>(pb_query);
      case PbQuery::Payload::kGetAccountTransactions:
        return GetAccountTransactions::create(pb_query).variant();
      case PbQuery::Payload::kGetAccountAssetTransactions:
        return GetAccountAssetTransactions::create(pb_query).variant();
      case PbQuery::Payload::kGetTransactions:
        return GetTransactions::create(pb_query).variant();
      case PbQuery::Payload::kGetAccountAssets:
        return std::make_unique<GetAccountAssets>(pb_query);
      case PbQuery::Payload::kGetAccountDetail:
        return std::make_unique<GetAccountDetail>(pb_query);
      case PbQuery::Payload::kGetRoles:
        return std::make_unique<GetRoles>();
      case PbQuery::Payload::kGetRolePermissions:
        return std::make_unique<GetRolePermissions>(pb_query);
      case PbQuery::Payload::kGetAssetInfo:
        return std::make_unique<GetAssetInfo>(pb_query);
      case PbQuery::Payload::kGetPendingTransactions:
        return GetPendingTransactions::create(pb_query).variant();
      case PbQuery::Payload::kGetBlock:
        return std::make_unique<GetBlock>(pb_query);
      case PbQuery::Payload::kGetPeers:
        return std::make_unique<GetPeers>();
      default:
        return "Unknown query";
    };
  }

  iroha::expected::Result<ProtoQueryVariantType, std::string> load(
      PbQuery &pb_query) {
    return loadAggregateResult(pb_query);
  }
}  // namespace

struct Query::Impl {
  explicit Impl(std::unique_ptr<TransportType> &&proto,
                ProtoQueryVariantType query_holder,
                SignatureSet signatures)
      : proto_(std::move(proto)),
        query_holder_(std::move(query_holder)),
        query_constref_(boost::apply_visitor(
            iroha::indirecting_visitor<QueryVariantType>, query_holder_)),
        signatures_(std::move(signatures)) {}

  std::unique_ptr<TransportType> proto_;
  ProtoQueryVariantType query_holder_;
  QueryVariantType query_constref_;
  SignatureSet signatures_;

  shared_model::crypto::Blob blob_{makeBlob(*proto_)};
  shared_model::crypto::Blob payload_{makeBlob(proto_->payload())};
  shared_model::crypto::Hash hash_ = makeHash(payload_);
};

iroha::expected::Result<std::unique_ptr<Query>, std::string> Query::create(
    TransportType proto) {
  SignatureSet signatures;
  if (proto.has_signature()) {
    auto signature = Signature::create(proto.signature());
    if (auto e = iroha::expected::resultToOptionalError(signature)) {
      return e.value();
    }
    signatures.emplace(std::move(signature).assumeValue());
  }
  // load(TransportType&) keeps the reference to proto, so it must stay valid
  auto proto_ptr = std::make_unique<TransportType>(std::move(proto));
  return load(*proto_ptr) | [&](auto &&query) {
    return std::unique_ptr<Query>(new Query(std::make_unique<Impl>(
        std::move(proto_ptr), std::move(query), std::move(signatures))));
  };
}

Query::Query(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Query::Query(Query &&o) noexcept = default;

Query::~Query() = default;

const Query::QueryVariantType &Query::get() const {
  return impl_->query_constref_;
}

const AccountIdType &Query::creatorAccountId() const {
  return impl_->proto_->payload().meta().creator_account_id();
}

CounterType Query::queryCounter() const {
  return impl_->proto_->payload().meta().query_counter();
}

const BlobType &Query::blob() const {
  return impl_->blob_;
}

const BlobType &Query::payload() const {
  return impl_->payload_;
}

SignatureRangeType Query::signatures() const {
  return impl_->signatures_ | boost::adaptors::indirected;
}

bool Query::addSignature(const shared_model::crypto::Signed &signed_blob,
                         const shared_model::crypto::PublicKey &public_key) {
  if (impl_->proto_->has_signature()) {
    return false;
  }

  auto sig = impl_->proto_->mutable_signature();
  sig->set_signature(signed_blob.hex());
  sig->set_public_key(public_key.hex());

  return Signature::create(*sig).match(
      [this](auto &&val) {
        impl_->signatures_.emplace(std::move(val.value));
        impl_->blob_ = makeBlob(*impl_->proto_);
        return true;
      },
      [](const auto &err) { return false; });
}

const HashType &Query::hash() const {
  return impl_->hash_;
}

TimestampType Query::createdTime() const {
  return impl_->proto_->payload().meta().created_time();
}

const Query::TransportType &Query::getTransport() const {
  return *impl_->proto_;
}
