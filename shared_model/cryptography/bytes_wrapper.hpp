/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_BYTES_WRAPPER_HPP
#define IROHA_SHARED_MODEL_BYTES_WRAPPER_HPP

#include <cstddef>
#include <memory>
#include <string>

namespace shared_model {
  namespace crypto {

    class BytesView;

    /**
     * A special class for storing public keys.
     */
    class BytesWrapper {
     public:
      explicit BytesWrapper(std::shared_ptr<BytesView> blob);

      const BytesView &blob() const;

      /**
       * Calculates hash from the bytes.
       */
      struct Hasher {
        std::size_t operator()(const BytesWrapper &o) const;
      };

     private:
      std::shared_ptr<BytesView> blob_;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif
