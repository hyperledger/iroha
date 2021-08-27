/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_query_response.hpp"

#include "backend/protobuf/query_responses/proto_block_error_response.hpp"
#include "backend/protobuf/query_responses/proto_block_response.hpp"
#include "common/hexutils.hpp"
#include "common/report_abort.h"

namespace {
  /// type of proto variant
  using ProtoQueryResponseVariantType =
      boost::variant<shared_model::proto::BlockResponse,
                     shared_model::proto::BlockErrorResponse>;
}  // namespace

namespace shared_model::proto {

  struct BlockQueryResponse::Impl {
    explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}

    TransportType proto_;

    const ProtoQueryResponseVariantType variant_{
        [this]() -> ProtoQueryResponseVariantType {
          using iroha::protocol::BlockQueryResponse;
          using namespace shared_model::proto;
          switch (proto_.response_case()) {
            case BlockQueryResponse::ResponseCase::kBlockErrorResponse:
              return BlockErrorResponse(proto_);
            case BlockQueryResponse::ResponseCase::kBlockResponse:
              return BlockResponse(proto_);
            default:
            case iroha::protocol::BlockQueryResponse::ResponseCase::
                RESPONSE_NOT_SET:
              report_abort("Unexpected response case.");
          };
        }()};

    const QueryResponseVariantType ivariant_{variant_};
  };

  BlockQueryResponse::BlockQueryResponse(TransportType &&ref) {
    impl_ = std::make_unique<Impl>(std::move(ref));
  }

  BlockQueryResponse::~BlockQueryResponse() = default;

  const BlockQueryResponse::QueryResponseVariantType &BlockQueryResponse::get()
      const {
    return impl_->ivariant_;
  }

  const BlockQueryResponse::TransportType &BlockQueryResponse::getTransport()
      const {
    return impl_->proto_;
  }

}  // namespace shared_model::proto

#undef IROHA_BIND_TYPE
