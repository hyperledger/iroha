/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_BYTES_VIEW_HPP
#define IROHA_SHARED_MODEL_BYTES_VIEW_HPP

#include <string>

#include <boost/optional/optional.hpp>
#include "interfaces/common_objects/range_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace crypto {

    /**
     * BytesView is a wrapper over a byte range with some helper functions.
     */
    class BytesView {
     public:
      BytesView(shared_model::interface::types::ByteRange byte_range);

      BytesView(shared_model::interface::types::ConstByteRange byte_range);

      BytesView(const shared_model::interface::types::ByteType *begin,
                size_t length);

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

      /**
       * @return number of bytes in the blob
       */
      size_t size() const;

      std::string toString() const;

      bool operator==(const BytesView &rhs) const;

     protected:
      /// Users of this constructor must initialize range_ themselves.
      BytesView() = default;

      shared_model::interface::types::ConstByteRange range_;

     private:
      mutable boost::optional<std::string> hex_repr_cache_;
    };

  }  // namespace crypto
}  // namespace shared_model
#endif
