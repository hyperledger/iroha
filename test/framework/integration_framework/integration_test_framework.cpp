/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/integration_test_framework.hpp"

#include <boost/assert.hpp>
#include <boost/thread/barrier.hpp>
#include <limits>
#include <memory>
#include <rxcpp/operators/rx-filter.hpp>
#include <rxcpp/operators/rx-flat_map.hpp>
#include <rxcpp/operators/rx-take.hpp>
#include <rxcpp/operators/rx-zip.hpp>

#include "ametsuchi/storage.hpp"
#include "backend/protobuf/block.hpp"
#include "backend/protobuf/common_objects/proto_common_objects_factory.hpp"
#include "backend/protobuf/proto_transport_factory.hpp"
#include "backend/protobuf/queries/proto_query.hpp"
#include "backend/protobuf/query_responses/proto_query_response.hpp"
#include "backend/protobuf/transaction.hpp"
#include "backend/protobuf/transaction_responses/proto_tx_response.hpp"
#include "builders/protobuf/transaction.hpp"
#include "builders/protobuf/transaction_sequence_builder.hpp"
#include "consensus/yac/transport/impl/network_impl.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/default_hash_provider.hpp"
#include "datetime/time.hpp"
#include "endpoint.grpc.pb.h"
#include "framework/common_constants.hpp"
#include "framework/integration_framework/fake_peer/behaviour/honest.hpp"
#include "framework/integration_framework/fake_peer/fake_peer.hpp"
#include "framework/integration_framework/iroha_instance.hpp"
#include "framework/integration_framework/port_guard.hpp"
#include "framework/integration_framework/test_irohad.hpp"
#include "framework/result_fixture.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "framework/test_client_factory.hpp"
#include "framework/test_logger.hpp"
#include "interfaces/iroha_internal/transaction_batch_factory_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "interfaces/permissions.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/subscription.hpp"
#include "module/irohad/ametsuchi/tx_presence_cache_stub.hpp"
#include "module/irohad/common/validators_config.hpp"
#include "module/shared_model/builders/protobuf/block.hpp"
#include "module/shared_model/builders/protobuf/proposal.hpp"
#include "module/shared_model/validators/always_valid_validators.hpp"
#include "multi_sig_transactions/mst_processor.hpp"
#include "multi_sig_transactions/transport/mst_transport_grpc.hpp"
#include "network/consensus_gate.hpp"
#include "network/impl/async_grpc_client.hpp"
#include "network/impl/channel_factory.hpp"
#include "network/impl/client_factory.hpp"
#include "network/peer_communication_service.hpp"
#include "ordering/impl/on_demand_os_client_grpc.hpp"
#include "synchronizer/synchronizer_common.hpp"
#include "torii/command_client.hpp"
#include "torii/query_client.hpp"
#include "torii/status_bus.hpp"
#include "validators/default_validator.hpp"
#include "validators/protobuf/proto_proposal_validator.hpp"

using namespace shared_model::crypto;
using namespace std::literals::string_literals;
using namespace common_constants;

using shared_model::interface::types::PublicKeyHexStringView;

using AlwaysValidProtoCommonObjectsFactory =
    shared_model::proto::ProtoCommonObjectsFactory<
        shared_model::validation::AlwaysValidFieldValidator>;
using ProtoTransactionFactory = shared_model::proto::ProtoTransportFactory<
    shared_model::interface::Transaction,
    shared_model::proto::Transaction>;
using AbstractTransactionValidator =
    shared_model::validation::AbstractValidator<
        shared_model::interface::Transaction>;
using AlwaysValidInterfaceTransactionValidator =
    shared_model::validation::AlwaysValidModelValidator<
        shared_model::interface::Transaction>;
using AlwaysValidProtoTransactionValidator =
    shared_model::validation::AlwaysValidModelValidator<
        iroha::protocol::Transaction>;
using AlwaysValidProtoProposalValidator =
    shared_model::validation::AlwaysValidModelValidator<
        shared_model::interface::Proposal>;
using AlwaysMissingTxPresenceCache = iroha::ametsuchi::TxPresenceCacheStub<
    iroha::ametsuchi::tx_cache_status_responses::Missing>;
using FakePeer = integration_framework::fake_peer::FakePeer;
using iroha::network::makeTransportClientFactory;

namespace {
  std::string kLocalHost = "127.0.0.1";
  constexpr size_t kDefaultToriiPort = 11501;
  constexpr size_t kDefaultInternalPort = 50541;

  static const std::shared_ptr<iroha::network::GrpcChannelParams>
      kChannelParams = iroha::network::getDefaultTestChannelParams();

  std::string format_address(std::string ip,
                             integration_framework::PortGuard::PortType port) {
    ip.append(":");
    ip.append(std::to_string(port));
    return ip;
  }

}  // namespace

namespace integration_framework {

  template <typename T>
  class IntegrationTestFramework::CheckerQueue {
   public:
    CheckerQueue(std::chrono::milliseconds timeout) : timeout_(timeout) {}

    void push(T obj) {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      queue_.push(std::move(obj));
      cv_.notify_one();
    }

    boost::optional<T> try_pop() {
      std::unique_lock<std::mutex> lock(queue_mutex_);
      if (queue_.empty()) {
        if (not cv_.wait_for(
                lock, timeout_, [this] { return not queue_.empty(); })) {
          return boost::none;
        }
      }
      T obj(std::move(queue_.front()));
      queue_.pop();
      return obj;
    }

   private:
    std::chrono::milliseconds timeout_;
    std::queue<T> queue_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
  };

  IntegrationTestFramework::IntegrationTestFramework(
      size_t maximum_proposal_size,
      const boost::optional<std::string> &dbname,
      iroha::StartupWsvDataPolicy startup_wsv_data_policy,
      bool cleanup_on_exit,
      bool mst_support,
      const boost::optional<std::string> block_store_path,
      milliseconds proposal_waiting,
      milliseconds block_waiting,
      milliseconds tx_response_waiting,
      logger::LoggerManagerTreePtr log_manager)
      : log_(log_manager->getLogger()),
        log_manager_(std::move(log_manager)),
        proposal_queue_(
            std::make_unique<CheckerQueue<
                std::shared_ptr<const shared_model::interface::Proposal>>>(
                proposal_waiting)),
        verified_proposal_queue_(
            std::make_unique<CheckerQueue<VerifiedProposalType>>(
                proposal_waiting)),
        block_queue_(std::make_unique<CheckerQueue<BlockType>>(block_waiting)),
        port_guard_(std::make_unique<PortGuard>()),
        torii_port_(port_guard_->getPort(kDefaultToriiPort)),
        command_client_(std::make_unique<torii::CommandSyncClient>(
            iroha::network::createInsecureClient<
                torii::CommandSyncClient::Service>(
                kLocalHost, torii_port_, *kChannelParams),
            log_manager_->getChild("CommandClient")->getLogger())),
        query_client_(std::make_unique<torii_utils::QuerySyncClient>(
            iroha::network::createInsecureClient<
                torii_utils::QuerySyncClient::Service>(
                kLocalHost, torii_port_, *kChannelParams))),
        async_call_(std::make_shared<AsyncCall>(
            log_manager_->getChild("AsyncCall")->getLogger())),
        tx_response_waiting(tx_response_waiting),
        maximum_proposal_size_(maximum_proposal_size),
        common_objects_factory_(
            std::make_shared<AlwaysValidProtoCommonObjectsFactory>(
                iroha::test::kTestsValidatorsConfig)),
        transaction_factory_(std::make_shared<ProtoTransactionFactory>(
            std::make_unique<AlwaysValidInterfaceTransactionValidator>(),
            std::make_unique<AlwaysValidProtoTransactionValidator>())),
        batch_parser_(std::make_shared<
                      shared_model::interface::TransactionBatchParserImpl>()),
        batch_validator_(
            std::make_shared<shared_model::validation::DefaultBatchValidator>(
                iroha::test::kTestsValidatorsConfig)),
        transaction_batch_factory_(
            std::make_shared<
                shared_model::interface::TransactionBatchFactoryImpl>(
                batch_validator_)),
        proposal_factory_([] {
          std::shared_ptr<shared_model::validation::AbstractValidator<
              iroha::protocol::Transaction>>
              proto_transaction_validator =
                  std::make_shared<AlwaysValidProtoTransactionValidator>();
          std::unique_ptr<shared_model::validation::AbstractValidator<
              shared_model::interface::Proposal>>
              proposal_validator =
                  std::make_unique<AlwaysValidProtoProposalValidator>();
          std::unique_ptr<shared_model::validation::AbstractValidator<
              iroha::protocol::Proposal>>
              proto_proposal_validator = std::make_unique<
                  shared_model::validation::ProtoProposalValidator>(
                  std::move(proto_transaction_validator));
          return std::make_shared<shared_model::proto::ProtoTransportFactory<
              shared_model::interface::Proposal,
              shared_model::proto::Proposal>>(
              std::move(proposal_validator),
              std::move(proto_proposal_validator));
        }()),
        tx_presence_cache_(std::make_shared<AlwaysMissingTxPresenceCache>()),
        client_factory_(
            iroha::network::getTestInsecureClientFactory(kChannelParams)),
        yac_transport_(std::make_shared<iroha::consensus::yac::NetworkImpl>(
            async_call_,
            makeTransportClientFactory<iroha::consensus::yac::NetworkImpl>(
                client_factory_),
            log_manager_->getChild("ConsensusTransport")->getLogger())),
        cleanup_on_exit_(cleanup_on_exit) {
    // 1 h proposal_timeout results in non-deterministic behavior due to thread
    // scheduling and network
    config_.proposal_delay = 3600000;
    // 100 ms is small delay to avoid unnecessary messages due to eternal voting
    // and to allow scheduler to switch threads
    config_.vote_delay = 100;
    // amount of minutes in a day
    config_.mst_expiration_time = 24 * 60;
    config_.max_round_delay_ms = 0;
    config_.stale_stream_max_rounds = 2;
    config_.max_proposal_size = 10;
    config_.mst_support = mst_support;
    config_.block_store_path = block_store_path;
    config_.torii_port = torii_port_;
    config_.internal_port = port_guard_->getPort(kDefaultInternalPort);
    iroha_instance_ =
        std::make_shared<IrohaInstance>(config_,
                                        kLocalHost,
                                        log_manager_->getChild("Irohad"),
                                        log_,
                                        startup_wsv_data_policy,
                                        dbname);

    mst_state_update_ =
        SubscriberCreatorType<std::shared_ptr<iroha::MstState>>::create<
            iroha::EventTypes::kOnStateUpdate,
            iroha::SubscriptionEngineHandlers::kYac>(
            [](auto &subj, auto ev) { subj.get_subscriber().on_next(ev); });

    mst_prepared_batches_ = SubscriberCreatorType<iroha::BatchPtr>::create<
        iroha::EventTypes::kOnPreparedBatches,
        iroha::SubscriptionEngineHandlers::kYac>(
        [](auto &subj, auto ev) { subj.get_subscriber().on_next(ev); });

    mst_expired_batches_ = SubscriberCreatorType<iroha::BatchPtr>::create<
        iroha::EventTypes::kOnExpiredBatches,
        iroha::SubscriptionEngineHandlers::kYac>(
        [](auto &subj, auto ev) { subj.get_subscriber().on_next(ev); });

    yac_gate_outcome_ =
        SubscriberCreatorType<iroha::consensus::GateObject>::create<
            iroha::EventTypes::kOnOutcome,
            iroha::SubscriptionEngineHandlers::kYac>(
            [](auto &subj, auto ev) { subj.get_subscriber().on_next(ev); });

    pcs_synchronization_ =
        SubscriberCreatorType<iroha::synchronizer::SynchronizationEvent>::
            create<iroha::EventTypes::kOnSynchronization,
                   iroha::SubscriptionEngineHandlers::kYac>(
                [](auto &subj, auto ev) { subj.get_subscriber().on_next(ev); });

    storage_commit_ = SubscriberCreatorType<
        std::shared_ptr<const shared_model::interface::Block>>::
        create<iroha::EventTypes::kOnBlock,
               iroha::SubscriptionEngineHandlers::kYac>(
            [](auto &subj, auto ev) { subj.get_subscriber().on_next(ev); });
  }

  IntegrationTestFramework::~IntegrationTestFramework() {
    if (cleanup_on_exit_) {
      iroha_instance_->terminateAndCleanup();
    }
    for (auto &server : fake_peers_servers_) {
      server->shutdown(std::chrono::system_clock::now());
    }
    // the code below should be executed anyway in order to prevent app hang
    if (iroha_instance_ and iroha_instance_->getIrohaInstance()) {
      iroha_instance_->getIrohaInstance()->terminate(
          std::chrono::system_clock::now());
    }

    se_->dispose();
  }

  std::shared_ptr<FakePeer> IntegrationTestFramework::addFakePeer(
      const boost::optional<Keypair> &key) {
    BOOST_ASSERT_MSG(this_peer_, "Need to set the ITF peer key first!");
    const auto port = port_guard_->getPort(kDefaultInternalPort);
    auto fake_peer = std::make_shared<FakePeer>(
        kLocalHost,
        port,
        key,
        this_peer_,
        common_objects_factory_,
        transaction_factory_,
        batch_parser_,
        transaction_batch_factory_,
        proposal_factory_,
        tx_presence_cache_,
        log_manager_->getChild("FakePeer")
            ->getChild("at " + format_address(kLocalHost, port)));
    fake_peer->initialize();
    fake_peers_.emplace_back(fake_peer);
    log_->debug("Added a fake peer at {} with {}.",
                fake_peer->getAddress(),
                fake_peer->getKeypair().publicKey());
    return fake_peer;
  }

  std::vector<std::shared_ptr<fake_peer::FakePeer>>
  IntegrationTestFramework::addFakePeers(size_t amount) {
    std::vector<std::shared_ptr<fake_peer::FakePeer>> fake_peers;
    std::generate_n(std::back_inserter(fake_peers), amount, [this] {
      auto fake_peer = addFakePeer({});
      fake_peer->setBehaviour(std::make_shared<fake_peer::HonestBehaviour>());
      return fake_peer;
    });
    return fake_peers;
  }

  shared_model::proto::Block IntegrationTestFramework::defaultBlock(
      const shared_model::crypto::Keypair &key) const {
    shared_model::interface::RolePermissionSet all_perms{};
    for (size_t i = 0; i < all_perms.size(); ++i) {
      auto perm = static_cast<shared_model::interface::permissions::Role>(i);
      all_perms.set(perm);
    }
    auto genesis_tx_builder =
        shared_model::proto::TransactionBuilder()
            .creatorAccountId(kAdminId)
            .createdTime(iroha::time::now())
            .addPeer(getAddress(), PublicKeyHexStringView{key.publicKey()})
            .createRole(kAdminRole, all_perms)
            .createRole(kDefaultRole, {})
            .createDomain(kDomain, kDefaultRole)
            .createAccount(
                kAdminName, kDomain, PublicKeyHexStringView{key.publicKey()})
            .detachRole(kAdminId, kDefaultRole)
            .appendRole(kAdminId, kAdminRole)
            .createAsset(kAssetName, kDomain, 1)
            .quorum(1);
    // add fake peers
    for (const auto &fake_peer : fake_peers_) {
      genesis_tx_builder = genesis_tx_builder.addPeer(
          fake_peer->getAddress(),
          PublicKeyHexStringView{fake_peer->getKeypair().publicKey()});
    };
    auto genesis_tx =
        genesis_tx_builder.build().signAndAddSignature(key).finish();
    auto genesis_block =
        shared_model::proto::BlockBuilder()
            .transactions(
                std::vector<shared_model::proto::Transaction>{genesis_tx})
            .height(1)
            .prevHash(DefaultHashProvider::makeHash(Blob("")))
            .createdTime(iroha::time::now())
            .build()
            .signAndAddSignature(key)
            .finish();
    return genesis_block;
  }

  shared_model::proto::Block IntegrationTestFramework::defaultBlock() const {
    BOOST_ASSERT_MSG(my_key_, "Need to set the ITF peer key first!");
    return defaultBlock(*my_key_);
  }

  IntegrationTestFramework &IntegrationTestFramework::setGenesisBlock(
      const shared_model::interface::Block &block) {
    iroha_instance_->makeGenesis(clone(block));
    iroha_instance_->init();
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::setInitialState(
      const Keypair &keypair) {
    initPipeline(keypair);
    setGenesisBlock(defaultBlock(keypair));
    log_->info("added genesis block");
    subscribeQueuesAndRun();
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::setMstGossipParams(
      std::chrono::milliseconds mst_gossip_emitting_period,
      uint32_t mst_gossip_amount_per_once) {
    iroha_instance_->setMstGossipParams(mst_gossip_emitting_period,
                                        mst_gossip_amount_per_once);
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::setInitialState(
      const Keypair &keypair, const shared_model::interface::Block &block) {
    initPipeline(keypair);
    setGenesisBlock(block);
    log_->info("added genesis block");
    subscribeQueuesAndRun();
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::recoverState(
      const Keypair &keypair) {
    initPipeline(keypair);
    iroha_instance_->init();
    subscribeQueuesAndRun();
    return *this;
  }

  void IntegrationTestFramework::initPipeline(
      const shared_model::crypto::Keypair &keypair) {
    log_->info("init state");
    my_key_ = keypair;
    this_peer_ =
        framework::expected::val(
            common_objects_factory_->createPeer(
                getAddress(), PublicKeyHexStringView{keypair.publicKey()}))
            .value()
            .value;
    iroha_instance_->initPipeline(keypair, maximum_proposal_size_);
    log_->info("created pipeline");
  }

  void IntegrationTestFramework::subscribeQueuesAndRun() {
    // subscribing for components
    requested_proposals_ =
        SubscriberCreatorType<iroha::network::OrderingEvent>::create<
            iroha::EventTypes::kOnProposal,
            iroha::SubscriptionEngineHandlers::kYac>(
            [](auto &requested_proposals_subject, auto orderingEvent) {
              requested_proposals_subject.get_subscriber().on_next(
                  orderingEvent);
            });

    verified_proposals_ =
        SubscriberCreatorType<iroha::simulator::VerifiedProposalCreatorEvent>::
            create<iroha::EventTypes::kOnVerifiedProposal,
                   iroha::SubscriptionEngineHandlers::kYac>(
                [](auto &verified_proposals_subject,
                   auto verified_proposal_event) {
                  verified_proposals_subject.get_subscriber().on_next(
                      verified_proposal_event);
                });

    committed_blocks_ = iroha::SubscriberCreator<
        bool,
        std::shared_ptr<const shared_model::interface::Block>>::
        create<iroha::EventTypes::kOnBlock,
               iroha::SubscriptionEngineHandlers::kYac>(
            [&](auto &, auto committed_block) {
              block_queue_->push(committed_block);
              log_->info("block commit");
            });

    rxcpp::observable<iroha::network::OrderingEvent> received_proposals =
        requested_proposals_->get().get_observable().filter(
            [](const auto &event) { return event.proposal; });

    received_proposals.subscribe([this](const auto &event) {
      proposal_queue_->push(getProposalUnsafe(event));
      log_->info("proposal");
    });

    auto proposal_flat_map =
        [](auto t) -> rxcpp::observable<std::tuple_element_t<0, decltype(t)>> {
      if (std::get<1>(t).proposal) {
        return rxcpp::observable<>::just(std::get<0>(t));
      }
      return rxcpp::observable<>::empty<std::tuple_element_t<0, decltype(t)>>();
    };

    rxcpp::observable<std::tuple<iroha::simulator::VerifiedProposalCreatorEvent,
                                 iroha::network::OrderingEvent>>
        verified_proposals_with_events =
            verified_proposals_->get().get_observable().zip(
                requested_proposals_->get().get_observable());
    rxcpp::observable<iroha::simulator::VerifiedProposalCreatorEvent>
        nonempty_proposals =
            verified_proposals_with_events.flat_map(proposal_flat_map);
    nonempty_proposals.subscribe([this](auto verified_proposal_and_errors) {
      verified_proposal_queue_->push(
          getVerifiedProposalUnsafe(verified_proposal_and_errors));
      log_->info("verified proposal");
    });

    iroha_instance_->getIrohaInstance()->getStatusBus()->statuses().subscribe(
        [this](auto response) {
          const auto hash = response->transactionHash().hex();
          auto it = responses_queues_.find(hash);
          if (it == responses_queues_.end()) {
            it = responses_queues_
                     .emplace(hash,
                              std::make_unique<CheckerQueue<TxResponseType>>(
                                  tx_response_waiting))
                     .first;
          }
          it->second->push(response);
          log_->info("response added to status queue: {}",
                     response->toString());
        });

    if (fake_peers_.size() > 0) {
      log_->info("starting fake iroha peers");
      for (auto &fake_peer : fake_peers_) {
        fake_peers_servers_.push_back(fake_peer->run());
      }
    }
    // start instance
    log_->info("starting main iroha instance");
    iroha_instance_->run();
  }

  std::shared_ptr<shared_model::interface::Peer>
  IntegrationTestFramework::getThisPeer() const {
    return this_peer_;
  }

  std::string IntegrationTestFramework::getAddress() const {
    return format_address(kLocalHost, config_.internal_port);
  }

  rxcpp::observable<std::shared_ptr<iroha::MstState>>
  IntegrationTestFramework::getMstStateUpdateObservable() {
    assert(mst_state_update_);
    return mst_state_update_->get().get_observable();
  }

  rxcpp::observable<iroha::BatchPtr>
  IntegrationTestFramework::getMstPreparedBatchesObservable() {
    assert(mst_prepared_batches_);
    return mst_prepared_batches_->get().get_observable();
  }

  rxcpp::observable<iroha::BatchPtr>
  IntegrationTestFramework::getMstExpiredBatchesObservable() {
    assert(mst_expired_batches_);
    return mst_expired_batches_->get().get_observable();
  }

  rxcpp::observable<iroha::consensus::GateObject>
  IntegrationTestFramework::getYacOnCommitObservable() {
    assert(yac_gate_outcome_);
    return yac_gate_outcome_->get().get_observable();
  }

  rxcpp::observable<iroha::synchronizer::SynchronizationEvent>
  IntegrationTestFramework::getPcsOnCommitObservable() {
    assert(pcs_synchronization_);
    return pcs_synchronization_->get().get_observable();
  }

  rxcpp::observable<std::shared_ptr<const shared_model::interface::Block>>
  IntegrationTestFramework::getCommitObservable() {
    assert(storage_commit_);
    return storage_commit_->get().get_observable();
  }

  std::shared_ptr<iroha::ametsuchi::BlockQuery>
  IntegrationTestFramework::getBlockQuery() {
    return getIrohaInstance().getIrohaInstance()->getStorage()->getBlockQuery();
  }

  IntegrationTestFramework &IntegrationTestFramework::getTxStatus(
      const shared_model::crypto::Hash &hash,
      std::function<void(const shared_model::proto::TransactionResponse &)>
          validation) {
    iroha::protocol::TxStatusRequest request;
    request.set_tx_hash(hash.hex());
    iroha::protocol::ToriiResponse response;
    command_client_->Status(request, response);
    validation(shared_model::proto::TransactionResponse(std::move(response)));
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::sendTxWithoutValidation(
      const shared_model::proto::Transaction &tx) {
    log_->info("sending transaction");
    log_->debug("{}", tx);

    command_client_->Torii(tx.getTransport());
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::sendTx(
      const shared_model::proto::Transaction &tx,
      std::function<void(const shared_model::proto::TransactionResponse &)>
          validation) {
    // Required for StatusBus synchronization
    boost::barrier bar1(2);
    auto bar2 = std::make_shared<boost::barrier>(2);
    rxcpp::observable<
        std::shared_ptr<shared_model::interface::TransactionResponse>>
        statuses =
            iroha_instance_->getIrohaInstance()->getStatusBus()->statuses();
    rxcpp::observable<
        std::shared_ptr<shared_model::interface::TransactionResponse>>
        filtered_statuses = statuses.filter(
            [&](auto s) { return s->transactionHash() == tx.hash(); });
    rxcpp::observable<
        std::shared_ptr<shared_model::interface::TransactionResponse>>
        first_status = filtered_statuses.take(1);
    first_status.subscribe(
        [&bar1, b2 = std::weak_ptr<boost::barrier>(bar2)](auto s) {
          bar1.wait();
          if (auto lock = b2.lock()) {
            lock->wait();
          }
        });

    sendTxWithoutValidation(tx);
    // make sure that the first (stateless) status has come
    bar1.wait();
    // fetch status of transaction
    getTxStatus(tx.hash(), [&validation, &bar2](auto &status) {
      // make sure that the following statuses (stateful/committed)
      // haven't reached the bus yet
      bar2->wait();

      // check validation function
      validation(status);
    });
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::sendTx(
      const shared_model::proto::Transaction &tx) {
    sendTx(tx, [this](const auto &status) {
      if (!status.statelessErrorOrCommandName().empty()) {
        log_->debug("Got error while sending transaction: "
                    + status.statelessErrorOrCommandName());
      }
    });
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::sendTxAwait(
      const shared_model::proto::Transaction &tx) {
    return sendTxAwait(tx, [](const auto &) {});
  }

  IntegrationTestFramework &IntegrationTestFramework::sendTxAwait(
      const shared_model::proto::Transaction &tx,
      std::function<void(const BlockType &)> check) {
    sendTx(tx).skipProposal().skipVerifiedProposal().checkBlock(check);
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::sendTxSequence(
      const shared_model::interface::TransactionSequence &tx_sequence,
      std::function<void(std::vector<shared_model::proto::TransactionResponse>
                             &)> validation) {
    log_->info("send transactions");
    const auto &transactions = tx_sequence.transactions();

    std::mutex m;
    std::condition_variable cv;
    bool processed = false;

    // subscribe on status bus and save all stateless statuses into a vector
    std::vector<shared_model::proto::TransactionResponse> observed_statuses;
    rxcpp::observable<
        std::shared_ptr<shared_model::interface::TransactionResponse>>
        statuses =
            iroha_instance_->getIrohaInstance()->getStatusBus()->statuses();
    rxcpp::observable<
        std::shared_ptr<shared_model::interface::TransactionResponse>>
        filtered_statuses = statuses.filter([&transactions](auto s) {
          // filter statuses for transactions from sequence
          auto it = std::find_if(
              transactions.begin(), transactions.end(), [&s](const auto tx) {
                // check if status is either stateless valid or failed
                bool is_stateless_status = iroha::visit_in_place(
                    s->get(),
                    [](const shared_model::interface::StatelessFailedTxResponse
                           &stateless_failed_response) { return true; },
                    [](const shared_model::interface::StatelessValidTxResponse
                           &stateless_valid_response) { return true; },
                    [](const auto &other_responses) { return false; });
                return is_stateless_status
                    and s->transactionHash() == tx->hash();
              });
          return it != transactions.end();
        });
    rxcpp::observable<
        std::shared_ptr<shared_model::interface::TransactionResponse>>
        first_statuses = filtered_statuses.take(transactions.size());
    first_statuses.subscribe(
        [&observed_statuses](auto s) {
          observed_statuses.push_back(
              *std::static_pointer_cast<
                  shared_model::proto::TransactionResponse>(s));
        },
        [&cv, &m, &processed] {
          std::lock_guard<std::mutex> lock(m);
          processed = true;
          cv.notify_all();
        });

    // put all transactions to the TxList and send them to iroha
    iroha::protocol::TxList tx_list;
    for (const auto &tx : transactions) {
      auto proto_tx =
          std::static_pointer_cast<shared_model::proto::Transaction>(tx)
              ->getTransport();
      *tx_list.add_transactions() = proto_tx;
    }
    command_client_->ListTorii(tx_list);

    std::unique_lock<std::mutex> lk(m);
    cv.wait(lk, [&] { return processed; });

    validation(observed_statuses);
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::sendTxSequenceAwait(
      const shared_model::interface::TransactionSequence &tx_sequence,
      std::function<void(const BlockType &)> check) {
    sendTxSequence(tx_sequence)
        .skipProposal()
        .skipVerifiedProposal()
        .checkBlock(check);
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::sendQuery(
      const shared_model::proto::Query &qry,
      std::function<void(const shared_model::proto::QueryResponse &)>
          validation) {
    log_->info("send query");
    log_->debug("{}", qry);

    iroha::protocol::QueryResponse response;
    query_client_->Find(qry.getTransport(), response);
    shared_model::proto::QueryResponse query_response{std::move(response)};

    validation(query_response);
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::sendQuery(
      const shared_model::proto::Query &qry) {
    sendQuery(qry, [](const auto &) {});
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::sendBatches(
      const std::vector<TransactionBatchSPtr> &batches) {
    auto on_demand_os_transport =
        iroha::ordering::transport::OnDemandOsClientGrpcFactory(
            async_call_,
            proposal_factory_,
            [] { return std::chrono::system_clock::now(); },
            // the proposal waiting timeout is only used when waiting a response
            // for a proposal request, which our client does not do
            std::chrono::milliseconds(0),
            log_manager_->getChild("OrderingClientTransport")->getLogger(),
            makeTransportClientFactory<
                iroha::ordering::transport::OnDemandOsClientGrpcFactory>(
                client_factory_))
            .create(*this_peer_)
            .assumeValue();
    on_demand_os_transport->onBatches(batches);
    return *this;
  }

  boost::optional<std::shared_ptr<const shared_model::interface::Proposal>>
  IntegrationTestFramework::requestProposal(
      const iroha::consensus::Round &round, std::chrono::milliseconds timeout) {
    auto on_demand_os_transport =
        iroha::ordering::transport::OnDemandOsClientGrpcFactory(
            async_call_,
            proposal_factory_,
            [] { return std::chrono::system_clock::now(); },
            timeout,
            log_manager_->getChild("OrderingClientTransport")->getLogger(),
            makeTransportClientFactory<
                iroha::ordering::transport::OnDemandOsClientGrpcFactory>(
                client_factory_))
            .create(*this_peer_)
            .assumeValue();
    return on_demand_os_transport->onRequestProposal(round);
  }

  IntegrationTestFramework &IntegrationTestFramework::sendMstState(
      PublicKeyHexStringView src_key, const iroha::MstState &mst_state) {
    auto client = makeTransportClientFactory<iroha::network::MstTransportGrpc>(
                      client_factory_)
                      ->createClient(*this_peer_)
                      .assumeValue();
    iroha::network::sendStateAsync(mst_state, src_key, *client, *async_call_);
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::sendYacState(
      const std::vector<iroha::consensus::yac::VoteMessage> &yac_state) {
    yac_transport_->sendState(*this_peer_, yac_state);
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::checkProposal(
      std::function<void(
          const std::shared_ptr<const shared_model::interface::Proposal> &)>
          validation) {
    log_->info("check proposal");
    // fetch first proposal from proposal queue
    auto opt_proposal = proposal_queue_->try_pop();
    if (not opt_proposal) {
      throw std::runtime_error("missed proposal");
    }
    validation(*opt_proposal);
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::skipProposal() {
    checkProposal([](const auto &) {});
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::checkVerifiedProposal(
      std::function<void(
          const std::shared_ptr<const shared_model::interface::Proposal> &)>
          validation) {
    log_->info("check verified proposal");
    // fetch first proposal from proposal queue
    auto opt_verified_proposal_and_errors = verified_proposal_queue_->try_pop();
    if (not opt_verified_proposal_and_errors) {
      throw std::runtime_error("missed verified proposal");
    }
    validation(opt_verified_proposal_and_errors.value()->verified_proposal);
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::skipVerifiedProposal() {
    checkVerifiedProposal([](const auto &) {});
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::checkBlock(
      std::function<void(const BlockType &)> validation) {
    // fetch first from block queue
    log_->info("check block");
    auto opt_block = block_queue_->try_pop();
    if (not opt_block) {
      throw std::runtime_error("missed block");
    }
    validation(*opt_block);
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::skipBlock() {
    checkBlock([](const auto &) {});
    return *this;
  }

  IntegrationTestFramework &IntegrationTestFramework::checkStatus(
      const shared_model::interface::types::HashType &tx_hash,
      std::function<void(const shared_model::proto::TransactionResponse &)>
          validation) {
    // fetch first response associated with the tx from related queue
    boost::optional<TxResponseType> opt_response;
    const auto it = responses_queues_.find(tx_hash.hex());
    if (it != responses_queues_.end()) {
      opt_response = it->second->try_pop();
    }
    if (not opt_response) {
      throw std::runtime_error("missed status");
    }
    validation(static_cast<const shared_model::proto::TransactionResponse &>(
        *opt_response.value()));
    return *this;
  }

  size_t IntegrationTestFramework::internalPort() const {
    return config_.internal_port;
  }

  void IntegrationTestFramework::done() {
    log_->info("done");
    iroha_instance_->terminateAndCleanup();
  }

  IrohaInstance &IntegrationTestFramework::getIrohaInstance() {
    return *iroha_instance_;
  }

  logger::LoggerManagerTreePtr getDefaultItfLogManager() {
    return getTestLoggerManager()->getChild("IntegrationFramework");
  }

}  // namespace integration_framework
