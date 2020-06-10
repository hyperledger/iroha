/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_INTERFACE_ENGINE_LOG_HPP
#define IROHA_SHARED_MODEL_INTERFACE_ENGINE_LOG_HPP

#include <boost/optional.hpp>
#include <vector>
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /// Provides an engine log data
    class EngineLog : public ModelPrimitive<EngineLog> {
     public:
      using TopicsCollectionType = std::vector<types::EvmTopicsHexString>;

      /// Contract address
      virtual types::EvmAddressHexString const &getAddress() const = 0;

      /// Contract data
      virtual types::EvmDataHexString const &getData() const = 0;

      /// Topics collection
      virtual TopicsCollectionType const &getTopics() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_INTERFACE_ENGINE_LOG_HPP
