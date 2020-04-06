/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/signature.hpp"

using namespace shared_model::plain;

Signature::Signature(std::string signed_data_hex, std::string public_key_hex)
    : signed_data_hex_(std::move(signed_data_hex)),
      public_key_hex_(std::move(public_key_hex)) {}

const std::string &Signature::publicKey() const {
  return public_key_hex_;
}

const std::string &Signature::signedData() const {
  return signed_data_hex_;
}

shared_model::interface::Signature *Signature::clone() const {
  return new Signature(signed_data_hex_, public_key_hex_);
}
