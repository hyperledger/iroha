/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/settings.hpp"

namespace shared_model {

  namespace validation {

    std::unique_ptr<shared_model::validation::Settings> getDefaultSettings() {
      shared_model::validation::Settings default_settings{};
      default_settings.max_description_size = kDefaultDescriptionSize;
      return std::make_unique<shared_model::validation::Settings>(
          std::move(default_settings));
    }
  }  // namespace validation
}  // namespace shared_model
