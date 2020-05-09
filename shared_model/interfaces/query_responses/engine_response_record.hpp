/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_INTERFACE_ENGINE_RECEIPT_HPP
#define IROHA_SHARED_MODEL_INTERFACE_ENGINE_RECEIPT_HPP

#include <boost/optional.hpp>
#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/query_responses/engine_log.hpp"

namespace shared_model {
  namespace interface {

    /// Provides a response for a single corresponding EngineCall command
    class EngineReceipt : public ModelPrimitive<EngineReceipt> {
     public:

      enum struct PayloadType {
        kPayloadTypeUnk,
        kPayloadTypeCallee,
        kPayloadTypeContractAddress
      };

      static char const *payloadTypeToStr(PayloadType pt) {
        switch(pt) {
          case PayloadType::kPayloadTypeCallee: return "Callee";
          case PayloadType::kPayloadTypeContractAddress: return "Contract address";
          default: return "Unknown";
        }
      }

      using EngineLogsPtr = std::unique_ptr<interface::EngineLog>;
      using EngineLogsCollectionType = std::vector<EngineLogsPtr>;

      /// Get command index
      virtual int32_t getCommandIndex() const = 0;

      /// Get sender account id
      virtual types::AccountIdType getCaller() const = 0;

      /// Returns the payload data type.
      virtual PayloadType getPayloadType() const = 0;

      /// Returns payload data
      virtual types::EvmAddressHexString const &getPayload() const = 0;

      /// Return engine logs collection.
      virtual EngineLogsCollectionType const &getEngineLogs() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_INTERFACE_ENGINE_RECEIPT_HPP
