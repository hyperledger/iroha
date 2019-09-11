/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * When passing through the pipeline, we need to form proposal
 * out of transactions and then make blocks out of it. This results in several
 * transformations of underlying transport implementation,
 * which can be visibly slow.
 *
 * The purpose of this benchmark is to keep track of performance costs related
 * to blocks and proposals copying/moving.
 *
 * Each benchmark runs transaction() and commands() call to
 * initialize possibly lazy fields.
 */

#include <benchmark/benchmark.h>

#include "backend/protobuf/block.hpp"
#include "datetime/time.hpp"
#include "module/shared_model/builders/protobuf/test_block_builder.hpp"
#include "module/shared_model/builders/protobuf/test_proposal_builder.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"

/// number of commands in a single transaction
constexpr int number_of_commands = 5;

/// number of transactions in a single block
constexpr int number_of_txs = 100;

class BlockBenchmark : public benchmark::Fixture {
 public:
  // Block cannot be copy-assigned, that's why the state is kept in a builder
  TestBlockBuilder complete_builder;

  /**
   * Initialize block builder for benchmarks
   */
  void SetUp(benchmark::State &st) override {
    TestBlockBuilder builder;
    TestTransactionBuilder txbuilder;

    auto base_tx = txbuilder.createdTime(iroha::time::now()).quorum(1);

    for (int i = 0; i < number_of_commands; i++) {
      base_tx.transferAsset("player@one", "player@two", "coin", "", "5.00");
    }

    std::vector<shared_model::proto::Transaction> txs;

    for (int i = 0; i < number_of_txs; i++) {
      txs.push_back(base_tx.build());
    }

    complete_builder =
        builder.createdTime(iroha::time::now()).height(1).transactions(txs);
  }
};

class ProposalBenchmark : public benchmark::Fixture {
 public:
  // Block cannot be copy-assigned, that's why state is kept in a builder
  TestProposalBuilder complete_builder;

  void SetUp(benchmark::State &st) override {
    TestProposalBuilder builder;
    TestTransactionBuilder txbuilder;

    auto base_tx = txbuilder.createdTime(iroha::time::now()).quorum(1);

    for (int i = 0; i < number_of_commands; i++) {
      base_tx.transferAsset("player@one", "player@two", "coin", "", "5.00");
    }

    std::vector<shared_model::proto::Transaction> txs;

    for (int i = 0; i < number_of_txs; i++) {
      txs.push_back(base_tx.build());
    }

    complete_builder =
        builder.createdTime(iroha::time::now()).height(1).transactions(txs);
  }
};

/**
 * calls getters of a given object (block or proposal),
 * so that lazy fields are initialized.
 * @param obj - Block or Proposal
 */
template <typename T>
void checkLoop(const T &obj) {
  for (const auto &tx : obj.transactions()) {
    benchmark::DoNotOptimize(tx.commands());
  }
}

/**
 * Runs a function and updates timer of the given state
 */
template <typename Func>
void runBenchmark(benchmark::State &st, Func &&f) {
  auto start = std::chrono::high_resolution_clock::now();
  f();
  auto end = std::chrono::high_resolution_clock::now();

  auto elapsed_seconds =
      std::chrono::duration_cast<std::chrono::duration<double>>(end - start);

  st.SetIterationTime(elapsed_seconds.count());
}

/**
 * Benchmark block creation by copying protobuf object
 */
BENCHMARK_DEFINE_F(BlockBenchmark, TransportCopyTest)(benchmark::State &st) {
  while (st.KeepRunning()) {
    auto block = complete_builder.build();

    runBenchmark(st, [&block] {
      shared_model::proto::Block copy(block.getTransport());
      checkLoop(copy);
    });
  }
}

/**
 * Benchmark block creation by moving protobuf object
 */
BENCHMARK_DEFINE_F(BlockBenchmark, TransportMoveTest)(benchmark::State &st) {
  while (st.KeepRunning()) {
    auto block = complete_builder.build();
    auto proto_block = block.getTransport();

    runBenchmark(st, [&proto_block] {
      shared_model::proto::Block copy(std::move(proto_block));
      checkLoop(copy);
    });
  }
}

/**
 * Benchmark block creation by moving another block
 */
BENCHMARK_DEFINE_F(BlockBenchmark, MoveTest)(benchmark::State &st) {
  while (st.KeepRunning()) {
    auto block = complete_builder.build();

    runBenchmark(st, [&block] {
      shared_model::proto::Block copy = std::move(block);
      checkLoop(copy);
    });
  }
}

/**
 * Benchmark block creation by cloning another block
 */
BENCHMARK_DEFINE_F(BlockBenchmark, CloneTest)(benchmark::State &st) {
  while (st.KeepRunning()) {
    auto block = complete_builder.build();

    runBenchmark(st, [&block] {
      auto copy = clone(block);
      checkLoop(*copy);
    });
  }
}

/**
 * Benchmark proposal creation by copying protobuf object
 */
BENCHMARK_DEFINE_F(ProposalBenchmark, TransportCopyTest)(benchmark::State &st) {
  while (st.KeepRunning()) {
    auto proposal = complete_builder.build();

    runBenchmark(st, [&proposal] {
      shared_model::proto::Proposal copy(proposal.getTransport());
      checkLoop(copy);
    });
  }
}

/**
 * Benchmark proposal creation by moving protobuf object
 */
BENCHMARK_DEFINE_F(ProposalBenchmark, TransportMoveTest)(benchmark::State &st) {
  while (st.KeepRunning()) {
    auto proposal = complete_builder.build();
    iroha::protocol::Proposal proto_proposal = proposal.getTransport();

    runBenchmark(st, [&proto_proposal] {
      shared_model::proto::Proposal copy(std::move(proto_proposal));
      checkLoop(copy);
    });
  }
}

/**
 * Benchmark proposal creation by moving another proposal
 */
BENCHMARK_DEFINE_F(ProposalBenchmark, MoveTest)(benchmark::State &st) {
  while (st.KeepRunning()) {
    auto proposal = complete_builder.build();

    runBenchmark(st, [&] {
      shared_model::proto::Proposal copy(std::move(proposal));
      checkLoop(copy);
    });
  }
}

BENCHMARK_REGISTER_F(BlockBenchmark, MoveTest)->UseManualTime();
BENCHMARK_REGISTER_F(BlockBenchmark, CloneTest)->UseManualTime();
BENCHMARK_REGISTER_F(BlockBenchmark, TransportMoveTest)->UseManualTime();
BENCHMARK_REGISTER_F(BlockBenchmark, TransportCopyTest)->UseManualTime();
BENCHMARK_REGISTER_F(ProposalBenchmark, MoveTest)->UseManualTime();
BENCHMARK_REGISTER_F(ProposalBenchmark, TransportMoveTest)->UseManualTime();
BENCHMARK_REGISTER_F(ProposalBenchmark, TransportCopyTest)->UseManualTime();

BENCHMARK_MAIN();
