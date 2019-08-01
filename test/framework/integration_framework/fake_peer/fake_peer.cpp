/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/fake_peer/fake_peer.hpp"

#include <atomic>

#include <boost/assert.hpp>
#include "backend/protobuf/transaction.hpp"
#include "consensus/yac/impl/yac_crypto_provider_impl.hpp"
#include "consensus/yac/transport/impl/network_impl.hpp"
#include "consensus/yac/transport/yac_network_interface.hpp"
#include "consensus/yac/yac_crypto_provider.hpp"
#include "cryptography/crypto_provider/crypto_defaults.hpp"
#include "cryptography/default_hash_provider.hpp"
#include "cryptography/keypair.hpp"
#include "framework/integration_framework/fake_peer/behaviour/behaviour.hpp"
#include "framework/integration_framework/fake_peer/block_storage.hpp"
#include "framework/integration_framework/fake_peer/network/loader_grpc.hpp"
#include "framework/integration_framework/fake_peer/network/mst_network_notifier.hpp"
#include "framework/integration_framework/fake_peer/network/on_demand_os_network_notifier.hpp"
#include "framework/integration_framework/fake_peer/network/ordering_gate_network_notifier.hpp"
#include "framework/integration_framework/fake_peer/network/ordering_service_network_notifier.hpp"
#include "framework/integration_framework/fake_peer/network/yac_network_notifier.hpp"
#include "framework/integration_framework/fake_peer/proposal_storage.hpp"
#include "framework/result_fixture.hpp"
#include "interfaces/common_objects/common_objects_factory.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/server_runner.hpp"
#include "multi_sig_transactions/transport/mst_transport_grpc.hpp"
#include "network/impl/async_grpc_client.hpp"
#include "network/impl/grpc_channel_builder.hpp"
#include "ordering/impl/on_demand_os_client_grpc.hpp"
#include "ordering/impl/on_demand_os_server_grpc.hpp"

using namespace shared_model::crypto;
using namespace framework::expected;

static std::shared_ptr<shared_model::interface::Peer> createPeer(
    const std::shared_ptr<shared_model::interface::CommonObjectsFactory>
        &common_objects_factory,
    const std::string &address,
    const PublicKey &key) {
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

namespace integration_framework {
  namespace fake_peer {

    FakePeer::FakePeer(
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
        std::shared_ptr<iroha::ordering::transport::OnDemandOsClientGrpc::
                            TransportFactoryType> proposal_factory,
        std::shared_ptr<iroha::ametsuchi::TxPresenceCache> tx_presence_cache,
        logger::LoggerManagerTreePtr log_manager)
        : log_(log_manager->getLogger()),
          log_manager_(std::move(log_manager)),
          consensus_log_manager_(log_manager_->getChild("Consensus")),
          mst_log_manager_(
              log_manager_->getChild("MultiSignatureTransactions")),
          ordering_log_manager_(log_manager_->getChild("Ordering")),
          common_objects_factory_(common_objects_factory),
          transaction_factory_(transaction_factory),
          transaction_batch_factory_(transaction_batch_factory),
          proposal_factory_(std::move(proposal_factory)),
          batch_parser_(batch_parser),
          listen_ip_(listen_ip),
          internal_port_(internal_port),
          keypair_(std::make_unique<Keypair>(
              key.value_or(DefaultCryptoAlgorithmType::generateKeypair()))),
          this_peer_(createPeer(
              common_objects_factory, getAddress(), keypair_->publicKey())),
          real_peer_(std::move(real_peer)),
          async_call_(std::make_shared<AsyncCall>(
              log_manager_->getChild("AsyncNetworkClient")->getLogger())),
          mst_transport_(std::make_shared<MstTransport>(
              async_call_,
              transaction_factory,
              batch_parser,
              transaction_batch_factory,
              tx_presence_cache,
              std::make_shared<iroha::DefaultCompleter>(
                  std::chrono::minutes(0)),
              keypair_->publicKey(),
              mst_log_manager_->getChild("State")->getLogger(),
              mst_log_manager_->getChild("Transport")->getLogger())),
          yac_transport_(std::make_shared<YacTransport>(
              async_call_,
              [](const shared_model::interface::Peer &peer) {
                return iroha::network::createClient<
                    iroha::consensus::yac::proto::Yac>(peer.address());
              },
              consensus_log_manager_->getChild("Transport")->getLogger())),
          mst_network_notifier_(std::make_shared<MstNetworkNotifier>()),
          yac_network_notifier_(std::make_shared<YacNetworkNotifier>()),
          os_network_notifier_(std::make_shared<OsNetworkNotifier>()),
          og_network_notifier_(std::make_shared<OgNetworkNotifier>()),
          yac_crypto_(
              std::make_shared<iroha::consensus::yac::CryptoProviderImpl>(
                  *keypair_)) {
      mst_transport_->subscribe(mst_network_notifier_);
      yac_transport_->subscribe(yac_network_notifier_);
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
                                           ->getLogger());
      od_os_network_notifier_ =
          std::make_shared<OnDemandOsNetworkNotifier>(shared_from_this());
      od_os_transport_ = std::make_shared<OdOsTransport>(
          od_os_network_notifier_,
          transaction_factory_,
          batch_parser_,
          transaction_batch_factory_,
          ordering_log_manager_->getChild("Transport")->getLogger());

      initialized_ = true;
      return *this;
    }

    FakePeer &FakePeer::setBehaviour(
        const std::shared_ptr<Behaviour> &behaviour) {
      ensureInitialized();
      std::atomic_store(&behaviour_, behaviour);
      behaviour_->setup(shared_from_this(),
                        log_manager_->getChild("Behaviour")->getLogger());
      return *this;
    }

    std::shared_ptr<Behaviour> FakePeer::getBehaviour() const {
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

    boost::optional<const BlockStorage &> FakePeer::getBlockStorage() const {
      if (block_storage_) {
        return *block_storage_;
      }
      return boost::none;
    }

    ProposalStorage &FakePeer::getProposalStorage() {
      return proposal_storage_;
    }

    std::unique_ptr<ServerRunner> FakePeer::run() {
      ensureInitialized();
      // start instance
      log_->info("starting listening server");
      auto internal_server = std::make_unique<ServerRunner>(
          getAddress(),
          log_manager_->getChild("InternalServer")->getLogger(),
          false);
      internal_server->append(yac_transport_)
          .append(mst_transport_)
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
                log_->error("could not start server!");
              });
      return internal_server;
    }

    std::string FakePeer::getAddress() const {
      return listen_ip_ + ":" + std::to_string(internal_port_);
    }

    const Keypair &FakePeer::getKeypair() const {
      return *keypair_;
    }

    std::shared_ptr<shared_model::interface::Peer> FakePeer::getThisPeer()
        const {
      return this_peer_;
    }

    rxcpp::observable<std::shared_ptr<MstMessage>>
    FakePeer::getMstStatesObservable() {
      return mst_network_notifier_->getObservable();
    }

    rxcpp::observable<std::shared_ptr<const YacMessage>>
    FakePeer::getYacStatesObservable() {
      return yac_network_notifier_->getObservable();
    }

    rxcpp::observable<
        std::shared_ptr<shared_model::interface::TransactionBatch>>
    FakePeer::getOsBatchesObservable() {
      return os_network_notifier_->getObservable();
    }

    rxcpp::observable<std::shared_ptr<shared_model::interface::Proposal>>
    FakePeer::getOgProposalsObservable() {
      return og_network_notifier_->getObservable();
    }

    rxcpp::observable<LoaderBlockRequest>
    FakePeer::getLoaderBlockRequestObservable() {
      ensureInitialized();
      return synchronizer_transport_->getLoaderBlockRequestObservable();
    }

    rxcpp::observable<LoaderBlocksRequest>
    FakePeer::getLoaderBlocksRequestObservable() {
      ensureInitialized();
      return synchronizer_transport_->getLoaderBlocksRequestObservable();
    }

    rxcpp::observable<iroha::consensus::Round>
    FakePeer::getProposalRequestsObservable() {
      ensureInitialized();
      return od_os_network_notifier_->getProposalRequestsObservable();
    }

    rxcpp::observable<std::shared_ptr<BatchesCollection>>
    FakePeer::getBatchesObservable() {
      ensureInitialized();
      return od_os_network_notifier_->getBatchesObservable();
    }

    std::shared_ptr<shared_model::interface::Signature> FakePeer::makeSignature(
        const shared_model::crypto::Blob &hash) const {
      auto bare_signature =
          shared_model::crypto::DefaultCryptoAlgorithmType::sign(hash,
                                                                 *keypair_);
      std::shared_ptr<shared_model::interface::Signature> signature_with_pubkey;
      common_objects_factory_
          ->createSignature(keypair_->publicKey(), bare_signature)
          .match(
              [&signature_with_pubkey](auto &&sig) {
                signature_with_pubkey = std::move(sig.value);
              },
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

    void FakePeer::sendMstState(const iroha::MstState &state) {
      mst_transport_->sendState(*real_peer_, state);
    }

    void FakePeer::sendYacState(
        const std::vector<iroha::consensus::yac::VoteMessage> &state) {
      yac_transport_->sendState(*real_peer_, state);
    }

    void FakePeer::voteForTheSame(
        const std::shared_ptr<const YacMessage> &incoming_votes) {
      using iroha::consensus::yac::VoteMessage;
      log_->debug("Got a YAC state message with {} votes.",
                  incoming_votes->size());
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
      std::transform(
          incoming_votes->cbegin(),
          incoming_votes->cend(),
          std::back_inserter(my_votes),
          [this](const VoteMessage &incoming_vote) {
            log_->debug("Sending agreement for proposal ({}, hash ({}, {})).",
                        incoming_vote.hash.vote_round,
                        incoming_vote.hash.vote_hashes.proposal_hash,
                        incoming_vote.hash.vote_hashes.block_hash);
            return makeVote(incoming_vote.hash);
          });
      sendYacState(my_votes);
    }

    bool FakePeer::sendBlockRequest(const LoaderBlockRequest &request) {
      return synchronizer_transport_->sendBlockRequest(real_peer_->address(),
                                                       request);
    }

    size_t FakePeer::sendBlocksRequest(const LoaderBlocksRequest &request) {
      return synchronizer_transport_->sendBlocksRequest(real_peer_->address(),
                                                        request);
    }

    void FakePeer::proposeBatches(BatchesCollection batches) {
      std::vector<std::shared_ptr<shared_model::interface::Transaction>>
          transactions;
      for (auto &batch : batches) {
        std::copy(batch->transactions().begin(),
                  batch->transactions().end(),
                  std::back_inserter(transactions));
      }
      proposeTransactions(std::move(transactions));
    }

    void FakePeer::proposeTransactions(
        std::vector<std::shared_ptr<shared_model::interface::Transaction>>
            transactions) {
      iroha::ordering::proto::BatchesRequest request;
      for (auto &transaction : transactions) {
        *request.add_transactions() =
            static_cast<shared_model::proto::Transaction *>(transaction.get())
                ->getTransport();
      }

      auto client = iroha::network::createClient<
          iroha::ordering::proto::OnDemandOrdering>(real_peer_->address());
      grpc::ClientContext context;
      google::protobuf::Empty result;
      client->SendBatches(&context, request, &result);
    }

    boost::optional<std::shared_ptr<const shared_model::interface::Proposal>>
    FakePeer::sendProposalRequest(iroha::consensus::Round round,
                                  std::chrono::milliseconds timeout) const {
      auto on_demand_os_transport =
          iroha::ordering::transport::OnDemandOsClientGrpcFactory(
              async_call_,
              proposal_factory_,
              [] { return std::chrono::system_clock::now(); },
              timeout,
              ordering_log_manager_->getChild("NetworkClient")->getLogger())
              .create(*real_peer_);
      return on_demand_os_transport->onRequestProposal(round);
    }

    void FakePeer::ensureInitialized() {
      BOOST_VERIFY_MSG(initialized_, "Instance not initialized!");
    }

  }  // namespace fake_peer
}  // namespace integration_framework
