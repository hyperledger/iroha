/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ursa_crypto.h"

#include <cstdlib>
#include <vector>

#include <benchmark/benchmark.h>

auto ConstructRandomVector(size_t size) {
  using T = std::remove_pointer_t<decltype(ByteBuffer::data)>;
  std::vector<T> v;
  v.reserve(size);
  for (size_t i = 0; i < size; ++i) {
    v.push_back(static_cast<T>(std::rand() % size));
  }
  return v;
}

static void BM_KeypairNew(benchmark::State &state) {
  ByteBuffer pub{}, priv{};
  ExternError err{};

  while (state.KeepRunning()) {
    ursa_ed25519_keypair_new(&pub, &priv, &err);

    ursa_ed25519_bytebuffer_free(pub);
    ursa_ed25519_bytebuffer_free(priv);
    ursa_ed25519_string_free(err.message);
  }
}
BENCHMARK(BM_KeypairNew);

static void BM_Sign(benchmark::State &state) {
  ByteBuffer pub{}, priv{}, sig{}, msg{};
  ExternError err{};

  ursa_ed25519_keypair_new(&pub, &priv, &err);

  while (state.KeepRunning()) {
    state.PauseTiming();
    auto data = ConstructRandomVector(state.range(0));
    msg.data = data.data();
    msg.len = data.size();
    state.ResumeTiming();

    ursa_ed25519_sign(&msg, &priv, &sig, &err);

    ursa_ed25519_bytebuffer_free(sig);
    ursa_ed25519_string_free(err.message);
  }

  ursa_ed25519_bytebuffer_free(pub);
  ursa_ed25519_bytebuffer_free(priv);
}
BENCHMARK(BM_Sign)->RangeMultiplier(2)->Range(1 << 10, 1 << 18);

static void BM_Verify(benchmark::State &state) {
  ByteBuffer pub{}, priv{}, sig{}, msg{};
  ExternError err{};

  ursa_ed25519_keypair_new(&pub, &priv, &err);

  while (state.KeepRunning()) {
    state.PauseTiming();
    auto data = ConstructRandomVector(state.range(0));
    msg.data = data.data();
    msg.len = data.size();
    ursa_ed25519_sign(&msg, &priv, &sig, &err);
    state.ResumeTiming();

    ursa_ed25519_verify(&msg, &sig, &pub, &err);

    ursa_ed25519_bytebuffer_free(sig);
    ursa_ed25519_string_free(err.message);
  }

  ursa_ed25519_bytebuffer_free(pub);
  ursa_ed25519_bytebuffer_free(priv);
}
BENCHMARK(BM_Verify)->RangeMultiplier(2)->Range(1 << 10, 1 << 18);

BENCHMARK_MAIN();
