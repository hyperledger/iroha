/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/common_objects/data_model_id.hpp"

#include <ciso646>
#include <functional>

using namespace shared_model::interface;

bool DataModelId::operator==(DataModelId const &rhs) const {
  return name == rhs.name and version == rhs.version;
}

std::size_t DataModelId::Hasher::operator()(DataModelId const &id) const {
  std::hash<std::string> hasher;
  // TODO rework without addition
  return hasher(id.name) + hasher(id.version);
}
