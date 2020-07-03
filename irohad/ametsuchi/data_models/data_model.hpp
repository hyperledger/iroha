/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_DATA_MODEL_HPP
#define IROHA_AMETSUCHI_DATA_MODEL_HPP

#include <vector>

#include "ametsuchi/command_executor.hpp"
#include "backend/protobuf/commands/proto_call_model.hpp"
#include "interfaces/common_objects/data_model_id.hpp"

namespace iroha::ametsuchi {

  class DataModel {
   public:
    virtual ~DataModel() = default;

    virtual CommandResult execute(
        shared_model::proto::CallModel const &cmd) = 0;

    virtual void commitTransaction() = 0;

    virtual void commitBlock() = 0;

    virtual void rollbackTransaction() = 0;

    virtual void rollbackBlock() = 0;

    virtual std::vector<shared_model::interface::DataModelId>
    getSupportedDataModelIds() const = 0;
  };

}  // namespace iroha::ametsuchi

#endif
