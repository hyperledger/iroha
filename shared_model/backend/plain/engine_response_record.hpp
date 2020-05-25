/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PLAIN_ENGINE_RECEIPTS_RESPONSE_RECORD_HPP
#define IROHA_SHARED_MODEL_PLAIN_ENGINE_RECEIPTS_RESPONSE_RECORD_HPP

#include "interfaces/query_responses/engine_response_record.hpp"

#include "backend/plain/engine_log.hpp"
#include "cryptography/hash.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace plain {

    class EngineReceipt final : public interface::EngineReceipt {
     public:
      EngineReceipt(
          interface::types::CommandIndexType cmd_index,
          interface::types::AccountIdType const &caller,
          interface::EngineReceipt::PayloadType payload_type,
          interface::types::EvmAddressHexString const &payload,
          std::optional<interface::types::EvmDataHexString> const &e_response);

      int32_t getCommandIndex() const override;
      interface::types::AccountIdType getCaller() const override;
      interface::EngineReceipt::PayloadType getPayloadType() const override;
      interface::EngineReceipt::EngineLogsCollectionType const &getEngineLogs()
          const override;
      interface::EngineReceipt::EngineLogsCollectionType &getMutableLogs();
      std::optional<interface::EngineReceipt::CallResult> const &
      getResponseData() const override;
      std::optional<interface::types::EvmAddressHexString> const &
      getContractAddress() const override;

     private:
      interface::types::CommandIndexType const cmd_index_;
      interface::types::AccountIdType const caller_;
      interface::EngineReceipt::PayloadType const payload_type_;
      interface::EngineReceipt::EngineLogsCollectionType engine_logs_;
      std::optional<interface::types::EvmDataHexString> const callee_;
      std::optional<interface::types::EvmDataHexString> const contract_address_;
      std::optional<interface::types::EvmDataHexString> const e_response_;
      std::optional<interface::EngineReceipt::CallResult> const call_result_;
    };
  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PLAIN_ENGINE_RECEIPTS_RESPONSE_RECORD_HPP
