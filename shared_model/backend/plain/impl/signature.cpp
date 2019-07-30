/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/signature.hpp"

using namespace shared_model::plain;

Signature::Signature(const Signature::SignedType &signedData,
                     const Signature::PublicKeyType &publicKey)
    : signed_data_(signedData), public_key_(publicKey) {}

const Signature::PublicKeyType &Signature::publicKey() const {
  return public_key_;
}

const Signature::SignedType &Signature::signedData() const {
  return signed_data_;
}

shared_model::interface::Signature *Signature::clone() const {
  return new Signature(signed_data_, public_key_);
}
