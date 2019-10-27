/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PLAIN_PERMISSION_TO_STRING_HPP
#define PLAIN_PERMISSION_TO_STRING_HPP

#include "interfaces/permission_to_string.hpp"

namespace shared_model {
  namespace plain {
    class PermissionToString : public interface::PermissionToString {
     public:
      std::string toString(interface::permissions::Role p) const override;
      std::string toString(interface::permissions::Grantable p) const override;
    };
  }  // namespace plain
}  // namespace shared_model

#endif  // PLAIN_PERMISSION_TO_STRING_HPP
