/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_DATA_MODEL_PYTHON_HPP
#define IROHA_AMETSUCHI_DATA_MODEL_PYTHON_HPP

#include "ametsuchi/data_models/data_model.hpp"

#include <memory>
#include <string>
#include <vector>

namespace iroha::ametsuchi {

  class DataModelPython : public DataModel {
   public:
    // throws std::runtime_error
    DataModelPython(std::vector<std::string> python_paths,
                    std::string const &module_name,
                    std::string const &initialization_argument);

    ~DataModelPython();

    CommandResult execute(shared_model::proto::CallModel const &cmd) override;

    void commitTransaction() override;

    void commitBlock() override;

    void rollbackTransaction() override;

    void rollbackBlock() override;

    std::vector<shared_model::interface::DataModelId> getSupportedDataModelIds()
        const override;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::vector<shared_model::interface::DataModelId> supported_dm_ids_;
  };

}  // namespace iroha::ametsuchi

#endif
