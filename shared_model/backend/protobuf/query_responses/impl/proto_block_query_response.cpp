/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_query_response.hpp"

#include "backend/protobuf/query_responses/proto_block_error_response.hpp"
#include "backend/protobuf/query_responses/proto_block_response.hpp"
#include "common/hexutils.hpp"
#include "utils/variant_deserializer.hpp"

namespace {
  /// type of proto variant
  using ProtoQueryResponseVariantType =
      boost::variant<shared_model::proto::BlockResponse,
                     shared_model::proto::BlockErrorResponse>;
}  // namespace

namespace shared_model {
  namespace proto {

    struct BlockQueryResponse::Impl {
      explicit Impl(TransportType &&ref) : proto_{std::move(ref)} {}

      TransportType proto_;

      const ProtoQueryResponseVariantType variant_{[this] {
        auto &ar = proto_;
        int which =
            ar.GetDescriptor()->FindFieldByNumber(ar.response_case())->index();
        return shared_model::detail::
            variant_impl<ProtoQueryResponseVariantType::types>::template load<
                ProtoQueryResponseVariantType>(ar, which);
      }()};

      const QueryResponseVariantType ivariant_{variant_};
    };

    BlockQueryResponse::BlockQueryResponse(TransportType &&ref) {
      impl_ = std::make_unique<Impl>(std::move(ref));
    }

    BlockQueryResponse::~BlockQueryResponse() = default;

    const BlockQueryResponse::QueryResponseVariantType &
    BlockQueryResponse::get() const {
      return impl_->ivariant_;
    }

    const BlockQueryResponse::TransportType &BlockQueryResponse::getTransport()
        const {
      return impl_->proto_;
    }

  }  // namespace proto
}  // namespace shared_model
