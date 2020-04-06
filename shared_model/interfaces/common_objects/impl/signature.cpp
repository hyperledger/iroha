/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/common_objects/signature.hpp"

#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {
    bool Signature::operator==(const Signature &rhs) const {
      return publicKey() == rhs.publicKey();
    }

    std::string Signature::toString() const {
      return detail::PrettyStringBuilder()
          .init("Signature")
          .appendNamed("publicKey", publicKey())
          .appendNamed("signedData", signedData())
          .finalize();
    }
  }  // namespace interface
}  // namespace shared_model
