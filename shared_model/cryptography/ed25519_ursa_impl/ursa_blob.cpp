/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_ursa_impl/ursa_blob.hpp"

#include "ursa_crypto.h"

using shared_model::crypto::UrsaBlob;

UrsaBlob::UrsaBlob(const ByteBuffer &buf) : BytesView(buf.data, buf.len) {}

UrsaBlob::~UrsaBlob() {
  ursa_ed25519_bytebuffer_free(
      ByteBuffer{static_cast<int64_t>(size()), const_cast<uint8_t *>(data())});
}
