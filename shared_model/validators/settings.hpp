/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SETTINGS_HPP
#define IROHA_SHARED_MODEL_SETTINGS_HPP

#include "interfaces/common_objects/types.hpp"

namespace shared_model {

  namespace validation {

    /**
     * Structure that holds configurable ledger settings
     */
    struct Settings {
      size_t max_description_size;
    };

    const size_t kDefaultDescriptionSize = 64;

    std::unique_ptr<shared_model::validation::Settings> getDefaultSettings();

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_SETTINGS_HPP
