/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/fake_peer.hpp"

#include <atomic>
#include <boost/assert.hpp>

#include "backend/protobuf/transaction.hpp"
#include "common/common.hpp"
#include "consensus/yac/impl/yac_crypto_provider_impl.hpp"
#include "consensus/yac/outcome_messages.hpp"
#include "consensus/yac/transport/impl/network_impl.hpp"
#include "consensus/yac/transport/yac_network_interface.hpp"
#include "consensus/yac/yac_crypto_provider.hpp"
#include "cryptography/default_hash_provider.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "cryptography/keypair.hpp"
#include "framework/integration_framework/fake_peer/behaviour/behaviour.hpp"
#include "framework/integration_framework/fake_peer/block_storage.hpp"
#include "framework/integration_framework/fake_peer/network/loader_grpc.hpp"
#include "framework/integration_framework/fake_peer/network/on_demand_os_network_notifier.hpp"
#include "framework/integration_framework/fake_peer/network/ordering_gate_network_notifier.hpp"
#include "framework/integration_framework/fake_peer/network/ordering_service_network_notifier.hpp"
#include "framework/integration_framework/fake_peer/network/yac_network_notifier.hpp"
#include "framework/integration_framework/fake_peer/proposal_storage.hpp"
#include "framework/result_fixture.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_client_factory.hpp"
#include "interfaces/common_objects/common_objects_factory.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/server_runner.hpp"
#include "network/impl/async_grpc_client.hpp"
#include "network/impl/client_factory.hpp"
#include "ordering/impl/on_demand_os_client_grpc.hpp"
#include "ordering/impl/on_demand_os_server_grpc.hpp"

using namespace iroha::expected;
using namespace shared_model::crypto;
using namespace framework::expected;

using shared_model::interface::types::PublicKeyHexStringView;
using shared_model::interface::types::SignedHexStringView;

static std::shared_ptr<shared_model::interface::Peer> createPeer(
    const std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        &common_objects_factory,
    const std::string &address,
    PublicKeyHexStringView key) {
  std::shared_ptr<shared_model::interface::Peer> peer;
  common_objects_factory->createPeer(address, key)
      .match([&peer](auto &&result) { peer = std::move(result.value); },
             [&address](const auto &error) {
               BOOST_THROW_EXCEPTION(
                   std::runtime_error("Failed to create peer object for peer "
                                      + address + ". " + error.error));
             });
  return peer;
}

using integration_framework::fake_peer::FakePeer;

FakePeer::FakePeer(
    HideCtor,
    const std::string &listen_ip,
    size_t internal_port,
    const boost::optional<Keypair> &key,
    std::shared_ptr<shared_model::interface::Peer> real_peer,
    const std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        &common_objects_factory,
    std::shared_ptr<TransportFactoryType> transaction_factory,
    std::shared_ptr<shared_model::interface::TransactionBatchParser>
        batch_parser,
    std::shared_ptr<shared_model::interface::TransactionBatchFactory>
        transaction_batch_factory,
    std::shared_ptr<
        iroha::ordering::transport::OnDemandOsClientGrpc::TransportFactoryType>
        proposal_factory,
    std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache,
    logger::LoggerManagerTreePtr log_manager)
    : log_(log_manager->getLogger()),
      log_manager_(std::move(log_manager)),
      consensus_log_manager_(log_manager_->getChild("Consensus")),
      mst_log_manager_(log_manager_->getChild("MultiSignatureTransactions")),
      ordering_log_manager_(log_manager_->getChild("Ordering")),
      common_objects_factory_(common_objects_factory),
      transaction_factory_(transaction_factory),
      transaction_batch_factory_(transaction_batch_factory),
      proposal_factory_(std::move(proposal_factory)),
      batch_parser_(batch_parser),
      listen_ip_(listen_ip),
      internal_port_(internal_port),
      keypair_(std::make_unique<Keypair>(
          key.value_or(CryptoProviderEd25519Sha3::generateKeypair()))),
      this_peer_(createPeer(common_objects_factory,
                            getAddress(),
                            PublicKeyHexStringView{keypair_->publicKey()})),
      real_peer_(std::move(real_peer)),
      async_call_(std::make_shared<AsyncCall>(
          log_manager_->getChild("AsyncNetworkClient")->getLogger())),
      client_factory_(
          iroha::network::getTestInsecureClientFactory(std::nullopt)),
      yac_transport_client_(std::make_shared<YacTransportClient>(
          iroha::network::makeTransportClientFactory<YacTransportClient>(
              client_factory_),
          consensus_log_manager_->getChild("Transport")->getLogger())),
      yac_network_notifier_(std::make_shared<YacNetworkNotifier>()),
      os_network_notifier_(std::make_shared<OsNetworkNotifier>()),
      og_network_notifier_(std::make_shared<OgNetworkNotifier>()),
      yac_transport_server_(std::make_shared<YacTransportServer>(
          consensus_log_manager_->getChild("Server")->getLogger(),
          [yac_network_notifier(
              iroha::utils::make_weak(yac_network_notifier_))](
              std::vector<iroha::consensus::yac::VoteMessage> state) {
            auto maybe_yac_network_notifier = yac_network_notifier.lock();
            if (not maybe_yac_network_notifier) {
              return;
            }
            maybe_yac_network_notifier->onState(std::move(state));
          })),
      yac_crypto_(std::make_shared<iroha::consensus::yac::CryptoProviderImpl>(
          *keypair_, consensus_log_manager_->getChild("Crypto")->getLogger())) {
}

FakePeer::~FakePeer() {
  auto behaviour = getBehaviour();
  if (behaviour) {
    behaviour->absolve();
  }
}

FakePeer &FakePeer::initialize() {
  BOOST_VERIFY_MSG(not initialized_, "Already initialized!");
  // here comes the initialization of members requiring shared_from_this()
  synchronizer_transport_ =
      std::make_shared<LoaderGrpc>(shared_from_this(),
                                   log_manager_->getChild("Synchronizer")
                                       ->getChild("Transport")
                                       ->getLogger(),
                                   client_factory_);
  od_os_network_notifier_ =
      std::make_shared<OnDemandOsNetworkNotifier>(shared_from_this());
  od_os_transport_ = std::make_shared<OdOsTransport>(
      od_os_network_notifier_,
      transaction_factory_,
      batch_parser_,
      transaction_batch_factory_,
      ordering_log_manager_->getChild("Transport")->getLogger(),
      std::chrono::seconds(0));

  initialized_ = true;
  return *this;
}

FakePeer &FakePeer::setBehaviour(const std::shared_ptr<Behaviour> &behaviour) {
  ensureInitialized();
  std::atomic_store(&behaviour_, behaviour);
  behaviour_->setup(shared_from_this(),
                    log_manager_->getChild("Behaviour")->getLogger());
  return *this;
}

std::shared_ptr<integration_framework::fake_peer::Behaviour>
FakePeer::getBehaviour() const {
  return std::atomic_load(&behaviour_);
}

FakePeer &FakePeer::setBlockStorage(
    const std::shared_ptr<BlockStorage> &block_storage) {
  ensureInitialized();
  block_storage_ = block_storage;
  return *this;
}

FakePeer &FakePeer::removeBlockStorage() {
  ensureInitialized();
  block_storage_.reset();
  return *this;
}

boost::optional<const integration_framework::fake_peer::BlockStorage &>
FakePeer::getBlockStorage() const {
  if (block_storage_) {
    return *block_storage_;
  }
  return boost::none;
}

integration_framework::fake_peer::ProposalStorage &
FakePeer::getProposalStorage() {
  return proposal_storage_;
}

std::unique_ptr<iroha::network::ServerRunner> FakePeer::run(bool reuse_port) {
  ensureInitialized();
  log_->info("starting listening server");
  auto internal_server = std::make_unique<iroha::network::ServerRunner>(
      getAddress(),
      log_manager_->getChild("InternalServer")->getLogger(),
      reuse_port);
  internal_server->append(yac_transport_server_)
      .append(od_os_transport_)
      .append(synchronizer_transport_)
      .run()
      .match(
          [this](const auto &val) {
            const size_t bound_port = val.value;
            BOOST_VERIFY_MSG(
                bound_port == internal_port_,
                ("Server started on port " + std::to_string(bound_port)
                 + " instead of requested " + std::to_string(internal_port_)
                 + "!")
                    .c_str());
          },
          [this](const auto &err) {
            log_->error("could not start server on port {}!", getPort());
            throw std::runtime_error("could not start server!");
          });
  return internal_server;
}

std::string FakePeer::getAddress() const {
  return listen_ip_ + ":" + std::to_string(internal_port_);
}

const Keypair &FakePeer::getKeypair() const {
  return *keypair_;
}

std::shared_ptr<shared_model::interface::Peer> FakePeer::getThisPeer() const {
  return this_peer_;
}

rxcpp::observable<
    std::shared_ptr<const integration_framework::fake_peer::YacMessage>>
FakePeer::getYacStatesObservable() {
  return yac_network_notifier_->getObservable();
}

rxcpp::observable<std::shared_ptr<shared_model::interface::TransactionBatch>>
FakePeer::getOsBatchesObservable() {
  return os_network_notifier_->getObservable();
}

rxcpp::observable<std::shared_ptr<shared_model::interface::Proposal>>
FakePeer::getOgProposalsObservable() {
  return og_network_notifier_->getObservable();
}

rxcpp::observable<integration_framework::fake_peer::LoaderBlockRequest>
FakePeer::getLoaderBlockRequestObservable() {
  ensureInitialized();
  return synchronizer_transport_->getLoaderBlockRequestObservable();
}

rxcpp::observable<integration_framework::fake_peer::LoaderBlocksRequest>
FakePeer::getLoaderBlocksRequestObservable() {
  ensureInitialized();
  return synchronizer_transport_->getLoaderBlocksRequestObservable();
}

rxcpp::observable<iroha::consensus::Round>
FakePeer::getProposalRequestsObservable() {
  ensureInitialized();
  return od_os_network_notifier_->getProposalRequestsObservable();
}

rxcpp::observable<
    std::shared_ptr<integration_framework::fake_peer::BatchesCollection>>
FakePeer::getBatchesObservable() {
  ensureInitialized();
  return od_os_network_notifier_->getBatchesObservable();
}

std::shared_ptr<shared_model::interface::Signature> FakePeer::makeSignature(
    const shared_model::crypto::Blob &hash) const {
  auto bare_signature = CryptoProviderEd25519Sha3::sign(hash, *keypair_);
  std::shared_ptr<shared_model::interface::Signature> signature_with_pubkey;
  common_objects_factory_
      ->createSignature(PublicKeyHexStringView{keypair_->publicKey()},
                        SignedHexStringView{bare_signature})
      .match([&signature_with_pubkey](
                 auto &&sig) { signature_with_pubkey = std::move(sig.value); },
             [](const auto &reason) {
               BOOST_THROW_EXCEPTION(std::runtime_error(
                   "Cannot build signature: " + reason.error));
             });
  return signature_with_pubkey;
}

iroha::consensus::yac::VoteMessage FakePeer::makeVote(
    iroha::consensus::yac::YacHash yac_hash) {
  iroha::consensus::yac::YacHash my_yac_hash = yac_hash;
  my_yac_hash.block_signature = makeSignature(
      shared_model::crypto::Blob(yac_hash.vote_hashes.block_hash));
  return yac_crypto_->getVote(my_yac_hash);
}

void FakePeer::sendYacState(
    const std::vector<iroha::consensus::yac::VoteMessage> &state) {
  yac_transport_client_->sendState(*real_peer_, state);
}

void FakePeer::voteForTheSame(
    const std::shared_ptr<const YacMessage> &incoming_votes) {
  using iroha::consensus::yac::VoteMessage;
  log_->debug("Got a YAC state message with {} votes.", incoming_votes->size());
  if (incoming_votes->size() > 1) {
    // TODO mboldyrev 24/10/2018 IR-1821: rework ignoring states for
    //                                    accepted commits
    log_->debug(
        "Ignoring state with multiple votes, "
        "because it probably refers to an accepted commit.");
    return;
  }
  std::vector<VoteMessage> my_votes;
  my_votes.reserve(incoming_votes->size());
  std::transform(incoming_votes->cbegin(),
                 incoming_votes->cend(),
                 std::back_inserter(my_votes),
                 [this](const VoteMessage &incoming_vote) {
                   log_->debug(
                       "Sending agreement for proposal ({}, hash ({}, {})).",
                       incoming_vote.hash.vote_round,
                       incoming_vote.hash.vote_hashes.proposal_hash,
                       incoming_vote.hash.vote_hashes.block_hash);
                   return makeVote(incoming_vote.hash);
                 });
  sendYacState(my_votes);
}

Result<void, std::string> FakePeer::sendBlockRequest(
    const LoaderBlockRequest &request) {
  return synchronizer_transport_->sendBlockRequest(*real_peer_, request);
}

Result<size_t, std::string> FakePeer::sendBlocksRequest(
    const LoaderBlocksRequest &request) {
  return synchronizer_transport_->sendBlocksRequest(*real_peer_, request);
}

Result<void, std::string> FakePeer::proposeBatches(BatchesCollection batches) {
  std::vector<std::shared_ptr<shared_model::interface::Transaction>>
      transactions;
  for (auto &batch : batches) {
    std::copy(batch->transactions().begin(),
              batch->transactions().end(),
              std::back_inserter(transactions));
  }
  return proposeTransactions(std::move(transactions));
}

Result<void, std::string> FakePeer::proposeTransactions(
    std::vector<std::shared_ptr<shared_model::interface::Transaction>>
        transactions) {
  return client_factory_
                 ->createClient<iroha::ordering::proto::OnDemandOrdering>(
                     *real_peer_)
             | [&transactions](auto client) -> Result<void, std::string> {
    iroha::ordering::proto::BatchesRequest request;
    for (auto &transaction : transactions) {
      *request.add_transactions() =
          static_cast<shared_model::proto::Transaction *>(transaction.get())
              ->getTransport();
    }

    grpc::ClientContext context;
    google::protobuf::Empty result;
    client->SendBatches(&context, request, &result);
    return {};
  };
}

void FakePeer::ensureInitialized() {
  BOOST_VERIFY_MSG(initialized_, "Instance not initialized!");
}
