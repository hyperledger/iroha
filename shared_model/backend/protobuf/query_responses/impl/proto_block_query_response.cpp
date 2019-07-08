/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_query_response.hpp"

#include "utils/variant_deserializer.hpp"

namespace shared_model {
  namespace proto {

    BlockQueryResponse::BlockQueryResponse(TransportType &&block_query_response)
        : proto_(std::move(block_query_response)),
          variant_{[this] {
            auto &ar = proto_;
            int which = ar.GetDescriptor()
                            ->FindFieldByNumber(ar.response_case())
                            ->index();
            return shared_model::detail::variant_impl<
                ProtoQueryResponseVariantType::types>::
                template load<ProtoQueryResponseVariantType>(ar, which);
          }()},
          ivariant_{variant_} {}

    const BlockQueryResponse::QueryResponseVariantType &
    BlockQueryResponse::get() const {
      return ivariant_;
    }

    const BlockQueryResponse::TransportType &BlockQueryResponse::getTransport()
        const {
      return proto_;
    }

  }  // namespace proto
}  // namespace shared_model
