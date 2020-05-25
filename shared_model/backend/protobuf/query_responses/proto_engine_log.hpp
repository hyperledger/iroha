/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_PROTO_MODEL_ENGINE_LOG_HPP
#define IROHA_SHARED_PROTO_MODEL_ENGINE_LOG_HPP

#include "interfaces/query_responses/engine_log.hpp"

#include "interfaces/common_objects/types.hpp"
#include "primitive.pb.h"

namespace shared_model {
  namespace proto {

    class EngineLog final : public interface::EngineLog {
     public:
      using TransportType = iroha::protocol::EngineLog;

      explicit EngineLog(TransportType const &proto);
      explicit EngineLog(EngineLog const &o);

      shared_model::interface::types::EvmAddressHexString const &getAddress()
          const override;
      shared_model::interface::types::EvmDataHexString const &getData()
          const override;
      shared_model::interface::EngineLog::TopicsCollectionType const &
      getTopics() const override;

     private:
      const TransportType &proto_;
      shared_model::interface::EngineLog::TopicsCollectionType topics_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_PROTO_MODEL_ENGINE_LOG_HPP
