/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATION_UTILS
#define IROHA_VALIDATION_UTILS

#include <string>
#include <vector>

#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/any_range.hpp>

#include "cryptography/public_key.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  namespace validation {
    /**
     * Checks if signatures' public keys are present in vector of pubkeys
     * @param signatures - collection of signatures
     * @param public_keys - collection of public keys
     * @return true, if all public keys of signatures are present in vector of
     * pubkeys
     */
    inline bool signaturesSubset(
        const shared_model::interface::types::SignatureRangeType &signatures,
        const boost::any_range<shared_model::crypto::PublicKey,
                               boost::forward_traversal_tag> &public_keys) {
      return std::all_of(
          signatures.begin(),
          signatures.end(),
          [&public_keys](const auto &signature) {
            return std::find_if(public_keys.begin(),
                                public_keys.end(),
                                [&signature](const auto &public_key) {
                                  return signature.publicKey() == public_key;
                                })
                != public_keys.end();
          });
    }

    /**
     * Checks if `signatures' is a subset of signatures of `peers'
     * @param signatures to check
     * @param peers with signatures
     * @return true if is a subset or false otherwise
     */
    template <typename Peers>
    inline bool peersSubset(
        const shared_model::interface::types::SignatureRangeType &signatures,
        const Peers &peers) {
      return signaturesSubset(signatures,
                              peers
                                  | boost::adaptors::transformed(
                                        [](const auto &p) -> decltype(auto) {
                                          return p->pubkey();
                                        }));
    }

  }  // namespace validation
}  // namespace iroha

#endif  // IROHA_VALIDATION_UTILS
