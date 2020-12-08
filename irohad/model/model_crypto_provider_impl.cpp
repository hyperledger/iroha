/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/model_crypto_provider_impl.hpp"

#include <algorithm>

#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "model/queries/get_account.hpp"
#include "model/queries/get_account_assets.hpp"
#include "model/queries/get_asset_info.hpp"
#include "model/queries/get_roles.hpp"
#include "model/queries/get_signatories.hpp"
#include "model/queries/get_transactions.hpp"
#include "model/sha3_hash.hpp"

using shared_model::interface::types::makeByteRange;
using shared_model::interface::types::PublicKeyByteRangeView;
using shared_model::interface::types::SignatureByteRangeView;

namespace iroha {
  namespace model {
    ModelCryptoProviderImpl::ModelCryptoProviderImpl(const keypair_t &keypair)
        : keypair_(keypair) {}

    bool ModelCryptoProviderImpl::verify(const Transaction &tx) const {
      return std::all_of(
          tx.signatures.begin(),
          tx.signatures.end(),
          [tx](const Signature &sig) {
            return iroha::verify(
                iroha::hash(tx).to_string(),
                PublicKeyByteRangeView{makeByteRange(sig.pubkey)},
                SignatureByteRangeView{makeByteRange(sig.signature)});
          });
    }

    bool ModelCryptoProviderImpl::verify(const Query &query) const {
      return iroha::verify(
          iroha::hash(query).to_string(),
          PublicKeyByteRangeView{makeByteRange(query.signature.pubkey)},
          SignatureByteRangeView{makeByteRange(query.signature.signature)});
    }

    bool ModelCryptoProviderImpl::verify(const Block &block) const {
      return std::all_of(
          block.sigs.begin(), block.sigs.end(), [block](const Signature &sig) {
            return iroha::verify(
                iroha::hash(block).to_string(),
                PublicKeyByteRangeView{makeByteRange(sig.pubkey)},
                SignatureByteRangeView{makeByteRange(sig.signature)});
          });
    }

    void ModelCryptoProviderImpl::sign(Block &block) const {
      auto signature = iroha::sign(
          iroha::hash(block).to_string(), keypair_.pubkey, keypair_.privkey);

      block.sigs.emplace_back(signature, keypair_.pubkey);
    }

    void ModelCryptoProviderImpl::sign(Transaction &transaction) const {
      auto signature = iroha::sign(iroha::hash(transaction).to_string(),
                                   keypair_.pubkey,
                                   keypair_.privkey);

      transaction.signatures.emplace_back(signature, keypair_.pubkey);
    }

    void ModelCryptoProviderImpl::sign(Query &query) const {
      auto signature = iroha::sign(
          iroha::hash(query).to_string(), keypair_.pubkey, keypair_.privkey);

      query.signature = Signature{signature, keypair_.pubkey};
    }
  }  // namespace model
}  // namespace iroha
