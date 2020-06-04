/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_query_response.hpp"

#include "backend/protobuf/query_responses/proto_block_error_response.hpp"
#include "backend/protobuf/query_responses/proto_block_response.hpp"
#include "common/hexutils.hpp"

namespace {
  /// type of proto variant
  using ProtoQueryResponseVariantType =
      boost::variant<shared_model::proto::BlockResponse,
                     shared_model::proto::BlockErrorResponse>;
}  // namespace

#ifdef IROHA_BIND_TYPE
#error IROHA_BIND_TYPE defined.
#endif  // IROHA_BIND_TYPE
#define IROHA_BIND_TYPE(val, type, ...)                        \
  case iroha::protocol::BlockQueryResponse::ResponseCase::val: \
    return ProtoQueryResponseVariantType(shared_model::proto::type(__VA_ARGS__))

namespace shared_model::proto {

  struct BlockQueryResponse::Impl {
    explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}

    TransportType proto_;

    const ProtoQueryResponseVariantType variant_{
        [this]() -> decltype(variant_) {
          auto &ar = proto_;

          switch (ar.response_case()) {
            IROHA_BIND_TYPE(kBlockErrorResponse, BlockErrorResponse, ar);
            IROHA_BIND_TYPE(kBlockResponse, BlockResponse, ar);

            default:
            case iroha::protocol::BlockQueryResponse::ResponseCase::
                RESPONSE_NOT_SET:
              assert(!"Unexpected response case.");
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
