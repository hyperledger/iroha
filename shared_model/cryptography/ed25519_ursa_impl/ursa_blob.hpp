/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_URSA_BLOB_HPP
#define IROHA_SHARED_MODEL_URSA_BLOB_HPP

#include "cryptography/bytes_view.hpp"

struct ByteBuffer;

namespace shared_model {
  namespace crypto {

    /**
     * Wrapper around Ursa blob type (ByteBuffer). Manages deallocation.
     */
    class UrsaBlob : public BytesView {
     public:
      UrsaBlob(const ByteBuffer &buf);

      virtual ~UrsaBlob();
    };

  }  // namespace crypto
}  // namespace shared_model
#endif
