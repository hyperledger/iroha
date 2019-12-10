/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_BYTES_VIEW_HPP
#define IROHA_SHARED_MODEL_BYTES_VIEW_HPP

#include <cstddef>
#include <string>

#include <boost/optional/optional.hpp>
#include "interfaces/common_objects/range_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace crypto {

    /**
     * BytesView is a wrapper over a const byte range.
     */
    class BytesView {
     public:
      BytesView(shared_model::interface::types::ByteRange byte_range);

      BytesView(shared_model::interface::types::ConstByteRange byte_range);

      BytesView(const shared_model::interface::types::ByteType *begin,
                size_t length);

      BytesView(const char *begin, size_t length);

      virtual ~BytesView();

      /**
       * @return provides raw representation of blob
       */
      const shared_model::interface::types::ConstByteRange &byteRange() const;

      /**
       * @return provides hex representation of blob without leading 0x
       */
      const std::string &hex() const;

      /// @return pointer to the first byte.
      const shared_model::interface::types::ByteType *data() const;

      /// @return pointer to the first byte cast to char.
      const char *char_data() const;

      /**
       * @return number of bytes in the blob
       */
      size_t size() const;

      std::string toString() const;

      bool operator==(const BytesView &rhs) const;

     protected:
      /// Users of this constructor must initialize range_ themselves.
      BytesView() = default;

      std::size_t getSizeTHash() const;

      shared_model::interface::types::ConstByteRange range_;

     private:
      friend class BytesViewHasher;

      mutable boost::optional<std::string> hex_repr_cache_;
      mutable boost::optional<std::size_t> hash_cache_;
    };

    class BytesViewHasher {
     public:
      std::size_t operator()(const BytesView &blob) const;
    };

  }  // namespace crypto
}  // namespace shared_model
#endif
