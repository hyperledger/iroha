/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_BLOB_HPP
#define IROHA_SHARED_MODEL_BLOB_HPP

#include "cryptography/bytes_view.hpp"

#include <string>
#include <vector>

#include <boost/optional/optional_fwd.hpp>
#include "common/cloneable.hpp"
#include "common/result_fwd.hpp"

namespace shared_model {
  namespace crypto {

    /**
     * Blob class owns a binary blob and provides a BytesView interface to it.
     */
    class Blob : public BytesView, public Cloneable<Blob> {
     public:
      using Bytes = std::vector<shared_model::interface::types::ByteType>;

      /// Create an empty blob.
      Blob() noexcept;

      /**
       * Create blob from a vector
       * @param blob - vector to create blob from
       */
      explicit Blob(Bytes blob) noexcept;

      Blob(const Blob &) noexcept;
      Blob(Blob &&) noexcept;

      Blob &operator=(Blob &&);

      /**
       * Create blob from a bytes range
       * @param blob - range to create blob from
       */
      explicit Blob(interface::types::ConstByteRange blob) noexcept;

      /**
       * Create blob from a binary string.
       * @param blob - string to create blob from
       */
      static std::unique_ptr<Blob> fromBinaryString(const std::string &binary);

      /**
       * Creates new Blob object from provided hex string
       * @param hex - string in hex format to create Blob from
       * @return Blob from provided hex string if it was correct or
       * boost::none otherwise
       */
      static iroha::expected::Result<std::unique_ptr<Blob>, std::string>
      fromHexString(const std::string &hex);

     protected:
      void updateRange();

      Blob *clone() const override;

     private:
      Bytes blob_;
    };

  }  // namespace crypto
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_BLOB_HPP
