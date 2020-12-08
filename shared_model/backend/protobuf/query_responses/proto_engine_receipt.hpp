/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_PROTO_MODEL_ENGINE_RECEIPT_HPP
#define IROHA_SHARED_PROTO_MODEL_ENGINE_RECEIPT_HPP

#include "interfaces/query_responses/engine_receipt.hpp"

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

      int32_t getCommandIndex() const override;
      shared_model::interface::types::AccountIdType getCaller() const override;
      shared_model::interface::EngineReceipt::PayloadType getPayloadType()
          const override;
      shared_model::interface::EngineReceipt::EngineLogsCollectionType const &
      getEngineLogs() const override;
      std::optional<shared_model::interface::EngineReceipt::CallResult> const &
      getResponseData() const override;
      std::optional<shared_model::interface::types::EvmAddressHexString> const &
      getContractAddress() const override;

     private:
      const TransportType &proto_;
      shared_model::interface::EngineReceipt::EngineLogsCollectionType
          engine_logs_;
      std::optional<shared_model::interface::types::EvmDataHexString> const
          response_data_;
      std::optional<shared_model::interface::EngineReceipt::CallResult> const
          call_result_;
      std::optional<shared_model::interface::types::EvmAddressHexString> const
          contact_address_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_PROTO_MODEL_ENGINE_RECEIPT_HPP
