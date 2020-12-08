/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PLAIN_ENGINE_LOG_HPP
#define IROHA_SHARED_MODEL_PLAIN_ENGINE_LOG_HPP

#include "interfaces/query_responses/engine_log.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace plain {

    class EngineLog final : public interface::EngineLog {
     public:
      EngineLog() = delete;
      EngineLog(EngineLog const &) = delete;
      EngineLog &operator=(EngineLog const &) = delete;

      EngineLog(interface::types::EvmAddressHexString const &address,
                interface::types::EvmDataHexString const &data)
          : address_(address), data_(data) {}

      EngineLog(interface::types::EvmAddressHexString &&address,
                interface::types::EvmDataHexString &&data)
          : address_(std::move(address)), data_(std::move(data)) {}

      interface::types::EvmAddressHexString const &getAddress() const {
        return address_;
      }

      interface::types::EvmDataHexString const &getData() const {
        return data_;
      }

      interface::EngineLog::TopicsCollectionType const &getTopics() const {
        return topics_;
      }

      void addTopic(interface::types::EvmTopicsHexString &&topic) {
        topics_.emplace_back(std::move(topic));
      }

      void addTopic(interface::types::EvmTopicsHexString const &topic) {
        topics_.emplace_back(topic);
      }

     private:
      interface::types::EvmAddressHexString const address_;
      interface::types::EvmDataHexString const data_;
      interface::EngineLog::TopicsCollectionType topics_;
    };

  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PLAIN_ENGINE_LOG_HPP
