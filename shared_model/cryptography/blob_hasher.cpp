/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/blob_hasher.hpp"

#include <boost/functional/hash.hpp>
#include "cryptography/blob.hpp"

using namespace shared_model::crypto;

std::size_t BlobHasher::operator()(const Blob &blob) const {
  return boost::hash_value(blob.blob());
}
