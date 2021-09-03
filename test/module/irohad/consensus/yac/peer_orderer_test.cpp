/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/peer_orderer_impl.hpp"

#include <iostream>
#include <unordered_map>

#include <boost/accumulators/accumulators.hpp>
#include <boost/math/distributions/chi_squared.hpp>
#include <boost/range/adaptors.hpp>
#include <boost/range/counting_range.hpp>
#include <boost/range/numeric.hpp>
#include "consensus/yac/storage/yac_proposal_storage.hpp"
#include "framework/crypto_literals.hpp"
#include "module/irohad/consensus/yac/yac_test_util.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace boost::adaptors;
using namespace iroha::consensus::yac;

using namespace std;
using shared_model::interface::types::PublicKeyHexStringView;
using ::testing::Return;
using ::testing::ReturnRefOfCopy;

const size_t kPeersQuantity = 4;

class YacPeerOrdererTest : public ::testing::Test {
 public:
  std::vector<std::shared_ptr<shared_model::interface::Peer>> peers = [] {
    std::vector<std::shared_ptr<shared_model::interface::Peer>> result;
    for (size_t i = 1; i <= kPeersQuantity; ++i) {
      auto peer = makePeer(std::to_string(i), "public key"_hex_pubkey);
      result.push_back(std::move(peer));
    }
    return result;
  }();

  std::vector<std::shared_ptr<shared_model::interface::Peer>> s_peers = [] {
    std::vector<std::shared_ptr<shared_model::interface::Peer>> result;
    for (size_t i = 1; i <= kPeersQuantity; ++i) {
      auto tmp = iroha::consensus::yac::makePeer(std::to_string(i));
      auto peer =
          makePeer(tmp->address(), PublicKeyHexStringView{tmp->pubkey()});

      result.emplace_back(std::move(peer));
    }
    return result;
  }();

  PeerOrdererImpl orderer;
};

TEST_F(YacPeerOrdererTest, PeerOrdererOrderingWhenInvokeNormalCase) {
  auto order = orderer.getOrdering(YacHash(), s_peers);
  ASSERT_EQ(order.value().getPeers().size(), peers.size());
}

TEST_F(YacPeerOrdererTest, PeerOrdererOrderingWhenEmptyPeerList) {
  auto order = orderer.getOrdering(YacHash(), {});
  ASSERT_EQ(order, std::nullopt);
}

/**
 * @given initial peer list in the ledger
 * @when calling ordering function on hash ["1" to "N"] k times
 * @test histogram must be from uniform distibution
 */
TEST_F(YacPeerOrdererTest, FairnessTest) {
  // Calculate number of permutations of peers
  double comb = std::tgamma(kPeersQuantity + 1);
  // Run experiments N times for each combination
  double exp_val = 30;
  int times = comb * exp_val;
  std::unordered_map<std::string, int> histogram;

  auto peers_set =
      transform(boost::counting_range(1, times + 1), [this](const auto &i) {
        std::string hash = std::to_string(i);
        return orderer
            .getOrdering(YacHash(iroha::consensus::Round{1, 1}, hash, hash),
                         s_peers)
            .value()
            .getPeers();
      });
  for (const auto &peers : peers_set) {
    std::string res = std::accumulate(peers.begin(),
                                      peers.end(),
                                      std::string(),
                                      [](std::string res, const auto &peer) {
                                        return res + " " + peer->address();
                                      });
    histogram[res]++;
  }
  // chi square goodness of fit test
  auto chi_square = boost::accumulate(
      histogram | map_values, 0.0, [&exp_val](auto stat, const auto &val) {
        return stat + (val - exp_val) * (val - exp_val) / exp_val;
      });
  boost::math::chi_squared chi_dist(comb - 1);
  auto p = boost::math::cdf(chi_dist, chi_square);
  // Significance level 0.05 is used
  ASSERT_LT(0.05, p) << "The distibution is not uniform, p = "
                     << std::to_string(p);
  ASSERT_EQ(comb, histogram.size());
}
