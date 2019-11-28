/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_query_response.hpp"

#include "backend/protobuf/query_responses/proto_block_error_response.hpp"
#include "backend/protobuf/query_responses/proto_block_response.hpp"
//#include "common/hexutils.hpp"
#include "common/result.hpp"
#include "common/variant_transform.hpp"
#include "qry_responses.pb.h"

using namespace shared_model::proto;

namespace {
  using ProtoBlockQueryResponse = iroha::protocol::BlockQueryResponse;
  using ProtoResponseVariantType =
      iroha::VariantOfUniquePtr<shared_model::proto::BlockResponse,
                                shared_model::proto::BlockErrorResponse>;

  iroha::AggregateValueResult<ProtoResponseVariantType::types, std::string>
  loadAggregateResult(const ProtoBlockQueryResponse &proto) {
    switch (proto.response_case()) {
      case ProtoBlockQueryResponse::kBlockResponse:
        return BlockResponse::create(proto).variant();
      case ProtoBlockQueryResponse::kBlockErrorResponse:
        return std::make_unique<BlockErrorResponse>(proto);
      default:
        return "Unknown response.";
    };
  }

  iroha::expected::Result<ProtoResponseVariantType, std::string> load(
      const ProtoBlockQueryResponse &proto) {
    return loadAggregateResult(proto);
  }
}  // namespace

struct BlockQueryResponse::Impl {
  explicit Impl(std::unique_ptr<TransportType> &&proto,
                ProtoResponseVariantType response_holder)
      : proto_(std::move(proto)),
        response_holder_(std::move(response_holder)),
        response_constref_(boost::apply_visitor(
            iroha::indirecting_visitor<QueryResponseVariantType>,
            response_holder_)) {}

  std::unique_ptr<TransportType> proto_;
  ProtoResponseVariantType response_holder_;
  QueryResponseVariantType response_constref_;
};

iroha::expected::Result<std::unique_ptr<BlockQueryResponse>, std::string>
BlockQueryResponse::create(TransportType proto) {
  // load(TransportType&) keeps the reference to proto, so it must stay valid
  auto proto_ptr = std::make_unique<TransportType>(std::move(proto));
  return load(*proto_ptr) | [&](auto &&response) {
    return std::unique_ptr<BlockQueryResponse>(new BlockQueryResponse(
        std::make_unique<Impl>(std::move(proto_ptr), std::move(response))));
  };
}

BlockQueryResponse::BlockQueryResponse(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

BlockQueryResponse::~BlockQueryResponse() = default;

const BlockQueryResponse::QueryResponseVariantType &BlockQueryResponse::get()
    const {
  return impl_->response_constref_;
}

const BlockQueryResponse::TransportType &BlockQueryResponse::getTransport()
    const {
  return *impl_->proto_;
}
