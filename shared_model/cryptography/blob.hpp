/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_BLOB_HPP
#define IROHA_SHARED_MODEL_BLOB_HPP

#include <string>
#include <vector>

#include "common/cloneable.hpp"
#include "interfaces/base/model_primitive.hpp"

namespace shared_model {
  namespace crypto {

    class Blob;
    std::string toBinaryString(const Blob &b);

    /**
     * Blob class present user-friendly blob for working with low-level
     * binary stuff. Its length is not fixed in compile time.
     */
    class Blob : public interface::ModelPrimitive<Blob>,
                 public Cloneable<Blob> {
     public:
      using Bytes = std::vector<uint8_t>;

      Blob() = default;
      /**
       * Create blob from a string
       * @param blob - string to create blob from
       */
      explicit Blob(const std::string &blob);

      /**
       * Create blob from a vector
       * @param blob - vector to create blob from
       */
      explicit Blob(const Bytes &blob);

      explicit Blob(Bytes &&blob) noexcept;

      /**
       * Creates new Blob object from provided hex string
       * @param hex - string in hex format to create Blob from
       * @return Blob from provided hex string if it was correct or
       * Blob from empty string if provided string was not a correct hex string
       */
      static Blob fromHexString(const std::string &hex);

      /**
       * @return provides raw representation of blob
       */
      virtual const Bytes &blob() const;

      /**
       * @return provides human-readable representation of blob without leading
       * 0x
       */
      virtual const std::string &hex() const;

      /**
       * @return size of raw representation of blob
       */
      virtual size_t size() const;

      std::string toString() const override;

      bool operator==(const Blob &rhs) const override;

     protected:
      Blob *clone() const override;

     private:
      Bytes blob_;
      std::string hex_;
    };

  }  // namespace crypto
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_BLOB_HPP
