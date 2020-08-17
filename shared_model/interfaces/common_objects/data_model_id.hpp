/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DATA_SHARED_MODEL_COMMON_MODEL_ID_HPP
#define DATA_SHARED_MODEL_COMMON_MODEL_ID_HPP

#include <cstddef>
#include <string>

namespace shared_model::interface {

  struct DataModelId {
    std::string name;
    std::string version;

    bool operator==(DataModelId const &) const;
    struct Hasher {
      std::size_t operator()(DataModelId const &h) const;
    };
  };

}  // namespace shared_model::interface

#endif
