/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PLAIN_SIGNATURE_HPP
#define IROHA_SHARED_MODEL_PLAIN_SIGNATURE_HPP

#include "interfaces/common_objects/signature.hpp"

#include "interfaces/common_objects/string_view_types.hpp"

namespace shared_model {

  namespace plain {

    class Signature final : public interface::Signature {
     public:
      Signature(
          shared_model::interface::types::SignedHexStringView signed_data_hex,
          shared_model::interface::types::PublicKeyHexStringView
              public_key_hex);

      const std::string &publicKey() const override;

      const std::string &signedData() const override;

     protected:
      interface::Signature *clone() const override;

     private:
      const std::string signed_data_hex_;
      const std::string public_key_hex_;
    };

  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PLAIN_SIGNATURE_HPP
