/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_query_response.hpp"

#include "utils/variant_deserializer.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    BlockQueryResponse::BlockQueryResponse(QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          variant_{[this] {
            auto &&ar = *proto_;
            int which = ar.GetDescriptor()
                            ->FindFieldByNumber(ar.response_case())
                            ->index();
            return shared_model::detail::variant_impl<
                ProtoQueryResponseVariantType::types>::
                template load<ProtoQueryResponseVariantType>(
                    std::forward<decltype(ar)>(ar), which);
          }()},
          ivariant_{variant_} {}

    template BlockQueryResponse::BlockQueryResponse(
        BlockQueryResponse::TransportType &);
    template BlockQueryResponse::BlockQueryResponse(
        const BlockQueryResponse::TransportType &);
    template BlockQueryResponse::BlockQueryResponse(
        BlockQueryResponse::TransportType &&);

    BlockQueryResponse::BlockQueryResponse(const BlockQueryResponse &o)
        : BlockQueryResponse(o.proto_) {}

    BlockQueryResponse::BlockQueryResponse(BlockQueryResponse &&o) noexcept
        : BlockQueryResponse(std::move(o.proto_)) {}

    const BlockQueryResponse::QueryResponseVariantType &
    BlockQueryResponse::get() const {
      return ivariant_;
    }

  }  // namespace proto
}  // namespace shared_model
