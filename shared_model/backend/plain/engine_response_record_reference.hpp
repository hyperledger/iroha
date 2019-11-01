/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PLAIN_ENGINE_RESPONSE_RECORD_REFERENCE_HPP
#define IROHA_SHARED_MODEL_PLAIN_ENGINE_RESPONSE_RECORD_REFERENCE_HPP

#include "interfaces/query_responses/engine_response_record.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace plain {

    class EngineResponseRecordReference final
        : public interface::EngineResponseRecord {
     public:
      EngineResponseRecordReference(
          interface::types::CommandIndexType cmd_index,
          const interface::types::SmartContractCodeType &response);

      interface::types::CommandIndexType commandIndex() const override;

      const interface::types::SmartContractCodeType &response() const override;

     private:
      interface::types::CommandIndexType cmd_index_;
      const interface::types::SmartContractCodeType &response_;
    };
  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PLAIN_ENGINE_RESPONSE_RECORD_REFERENCE_HPP
