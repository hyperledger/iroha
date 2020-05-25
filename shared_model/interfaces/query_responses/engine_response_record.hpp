/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_INTERFACE_ENGINE_RECEIPT_HPP
#define IROHA_SHARED_MODEL_INTERFACE_ENGINE_RECEIPT_HPP

#include <iosfwd>

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
        kPayloadTypeCallResult,
        kPayloadTypeContractAddress
      };

      struct CallResult {
        types::EvmDataHexString const &callee;
        std::optional<types::EvmDataHexString> const &response_data;

        bool operator==(CallResult const &c) const {
          return c.callee == callee && c.response_data == response_data;
        }

        std::string toString() const;
      };

      static char const *payloadTypeToStr(PayloadType pt) {
        switch (pt) {
          case PayloadType::kPayloadTypeCallResult:
            return "Call result";
          case PayloadType::kPayloadTypeContractAddress:
            return "Contract address";
          default:
            return "Unknown";
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

      /// [optional] Get engine response data(output). Enable if
      /// getPayloadType() == kPayloadTypeCallResult.
      virtual std::optional<CallResult> const &getResponseData() const = 0;

      /// Returns payload data
      virtual std::optional<types::EvmAddressHexString> const &
      getContractAddress() const = 0;

      /// Return engine logs collection.
      virtual EngineLogsCollectionType const &getEngineLogs() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };

    std::ostream &operator<<(std::ostream &os, EngineReceipt const &);

    std::ostream &operator<<(std::ostream &os,
                             EngineReceipt::CallResult const &);

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_INTERFACE_ENGINE_RECEIPT_HPP
