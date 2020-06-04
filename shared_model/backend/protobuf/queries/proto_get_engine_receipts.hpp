/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ENGINE_RESPONSE_H
#define IROHA_PROTO_GET_ENGINE_RESPONSE_H

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/queries/get_engine_receipts.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetEngineReceipts final
        : public TrivialProto<interface::GetEngineReceipts,
                              iroha::protocol::Query> {
     public:
      template <typename QueryType>
      explicit GetEngineReceipts(QueryType &&query);

      GetEngineReceipts(const GetEngineReceipts &o);

      GetEngineReceipts(GetEngineReceipts &&o) noexcept;

      const std::string &txHash() const override;

     private:
      // ------------------------------| fields |-------------------------------
      const iroha::protocol::GetEngineReceipts &get_engine_response_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ENGINE_RESPONSE_H
