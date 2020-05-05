/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_PROTO_MODEL_ENGINE_RECEIPT_HPP
#define IROHA_SHARED_PROTO_MODEL_ENGINE_RECEIPT_HPP

#include "interfaces/query_responses/engine_response_record.hpp"

#include "cryptography/hash.hpp"
#include "interfaces/common_objects/types.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {

    class EngineReceipt final : public interface::EngineReceipt {
     public:
      using TransportType = iroha::protocol::EngineReceipt;

      explicit EngineReceipt(const TransportType &proto);

      explicit EngineReceipt(const EngineReceipt &o);

      shared_model::interface::types::AccountIdType getCaller() const override;
      shared_model::interface::EngineReceipt::PayloadType getPayloadType() const override;
      shared_model::interface::types::EvmAddressHexString const &getPayload() const override;
      shared_model::interface::EngineReceipt::EngineLogsCollectionType const &getEngineLogs() const override;

     private:
      const TransportType &proto_;
      shared_model::interface::EngineReceipt::EngineLogsCollectionType engine_logs_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_PROTO_MODEL_ENGINE_RECEIPT_HPP
