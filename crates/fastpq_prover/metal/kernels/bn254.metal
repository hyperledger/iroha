#include <metal_stdlib>
using namespace metal;

// BN254 modulus (little-endian 64-bit limbs).
// p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
constant ulong BN254_MODULUS[4] = {
    0x43e1f593f0000001UL,
    0x2833e84879b97091UL,
    0xb85045b68181585dUL,
    0x30644e72e131a029UL,
};
// Montgomery helper: -p^{-1} mod 2^64.
constant ulong BN254_MODULUS_INV = 0xc2e1f593efffffffUL;
// R^2 mod p (little-endian limbs) for Montgomery encoding.
constant ulong BN254_R2[4] = {
    0x1bb8e645ae216da7UL,
    0x53fe3ab1e35c59e3UL,
    0x8c49833d53bb8085UL,
    0x0216d0b17f4e44a5UL,
};

struct Bn254 {
    ulong4 limbs; // little-endian 256-bit value.
};

inline Bn254 bn254_from_limbs(ulong4 raw) {
    return Bn254{raw};
}

inline Bn254 bn254_zero() {
    return bn254_from_limbs(ulong4(0UL, 0UL, 0UL, 0UL));
}

inline bool bn254_ge_modulus(Bn254 value) {
    if (value.limbs.w != BN254_MODULUS[3]) {
        return value.limbs.w > BN254_MODULUS[3];
    }
    if (value.limbs.z != BN254_MODULUS[2]) {
        return value.limbs.z > BN254_MODULUS[2];
    }
    if (value.limbs.y != BN254_MODULUS[1]) {
        return value.limbs.y > BN254_MODULUS[1];
    }
    return value.limbs.x >= BN254_MODULUS[0];
}

inline ulong add_with_carry(ulong lhs, ulong rhs, thread ulong &carry) {
    ulong sum = lhs + rhs;
    bool carry0 = sum < lhs;
    ulong result = sum + carry;
    bool carry1 = result < sum;
    carry = (carry0 || carry1) ? 1UL : 0UL;
    return result;
}

inline ulong sub_with_borrow(ulong lhs, ulong rhs, thread ulong &borrow) {
    ulong diff = lhs - rhs;
    bool borrow0 = lhs < rhs;
    ulong result = diff - borrow;
    bool borrow1 = diff < borrow;
    borrow = (borrow0 || borrow1) ? 1UL : 0UL;
    return result;
}

inline Bn254 bn254_sub_modulus(Bn254 value) {
    ulong borrow = 0UL;
    ulong x0 = sub_with_borrow(value.limbs.x, BN254_MODULUS[0], borrow);
    ulong x1 = sub_with_borrow(value.limbs.y, BN254_MODULUS[1], borrow);
    ulong x2 = sub_with_borrow(value.limbs.z, BN254_MODULUS[2], borrow);
    ulong x3 = sub_with_borrow(value.limbs.w, BN254_MODULUS[3], borrow);
    return bn254_from_limbs(ulong4(x0, x1, x2, x3));
}

inline Bn254 bn254_add(Bn254 a, Bn254 b) {
    ulong carry = 0UL;
    ulong x0 = add_with_carry(a.limbs.x, b.limbs.x, carry);
    ulong x1 = add_with_carry(a.limbs.y, b.limbs.y, carry);
    ulong x2 = add_with_carry(a.limbs.z, b.limbs.z, carry);
    ulong x3 = add_with_carry(a.limbs.w, b.limbs.w, carry);
    Bn254 sum = bn254_from_limbs(ulong4(x0, x1, x2, x3));
    if (carry != 0UL || bn254_ge_modulus(sum)) {
        sum = bn254_sub_modulus(sum);
    }
    return sum;
}

inline ulong bn254_add_small(thread ulong (&limbs)[9], uint idx, ulong value) {
    if (value == 0UL) {
        return 0UL;
    }
    ulong prior = limbs[idx];
    limbs[idx] += value;
    return limbs[idx] < prior ? 1UL : 0UL;
}

inline void bn254_add_carry_to_limbs(thread ulong (&limbs)[9], uint idx, ulong value) {
    ulong carry = bn254_add_small(limbs, idx, value);
    ++idx;
    while (carry != 0UL && idx < 9U) {
        carry = bn254_add_small(limbs, idx, carry);
        ++idx;
    }
}

inline Bn254 bn254_sub(Bn254 a, Bn254 b) {
    ulong borrow = 0UL;
    ulong x0 = sub_with_borrow(a.limbs.x, b.limbs.x, borrow);
    ulong x1 = sub_with_borrow(a.limbs.y, b.limbs.y, borrow);
    ulong x2 = sub_with_borrow(a.limbs.z, b.limbs.z, borrow);
    ulong x3 = sub_with_borrow(a.limbs.w, b.limbs.w, borrow);
    if (borrow != 0UL) {
        ulong carry = 0UL;
        x0 = add_with_carry(x0, BN254_MODULUS[0], carry);
        x1 = add_with_carry(x1, BN254_MODULUS[1], carry);
        x2 = add_with_carry(x2, BN254_MODULUS[2], carry);
        x3 = add_with_carry(x3, BN254_MODULUS[3], carry);
    }
    return bn254_from_limbs(ulong4(x0, x1, x2, x3));
}

inline void bn254_mul_add(
    ulong x,
    ulong y,
    thread ulong &acc,
    thread ulong &carry,
    thread ulong &carry_hi
) {
    ulong lo = x * y;
    ulong hi = mulhi(x, y);

    ulong sum = acc + lo;
    ulong carry0 = sum < acc ? 1UL : 0UL;
    sum += carry;
    ulong carry1 = sum < carry ? 1UL : 0UL;

    acc = sum;
    ulong next_carry = hi;
    ulong overflow = 0UL;
    ulong prior = next_carry;
    next_carry += carry0;
    overflow += next_carry < prior ? 1UL : 0UL;
    prior = next_carry;
    next_carry += carry1;
    overflow += next_carry < prior ? 1UL : 0UL;
    prior = next_carry;
    next_carry += carry_hi;
    overflow += next_carry < prior ? 1UL : 0UL;
    carry = next_carry;
    carry_hi = overflow;
}

inline void bn254_montgomery_reduce(thread ulong (&t)[9], thread ulong (&out)[4]) {
    for (uint i = 0U; i < 4U; ++i) {
        ulong m = t[i] * BN254_MODULUS_INV;
        ulong carry = 0UL;
        ulong carry_hi = 0UL;

        bn254_mul_add(m, BN254_MODULUS[0], t[i + 0], carry, carry_hi);
        bn254_mul_add(m, BN254_MODULUS[1], t[i + 1], carry, carry_hi);
        bn254_mul_add(m, BN254_MODULUS[2], t[i + 2], carry, carry_hi);
        bn254_mul_add(m, BN254_MODULUS[3], t[i + 3], carry, carry_hi);

        bn254_add_carry_to_limbs(t, i + 4U, carry);
        bn254_add_carry_to_limbs(t, i + 5U, carry_hi);
    }

    out[0] = t[4];
    out[1] = t[5];
    out[2] = t[6];
    out[3] = t[7];

    Bn254 candidate = bn254_from_limbs(ulong4(out[0], out[1], out[2], out[3]));
    if (bn254_ge_modulus(candidate)) {
        candidate = bn254_sub_modulus(candidate);
        out[0] = candidate.limbs.x;
        out[1] = candidate.limbs.y;
        out[2] = candidate.limbs.z;
        out[3] = candidate.limbs.w;
    }
}

inline Bn254 bn254_montgomery_mul(Bn254 a, Bn254 b) {
    thread ulong t[9] = {0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL};
    ulong a_words[4] = {a.limbs.x, a.limbs.y, a.limbs.z, a.limbs.w};
    ulong b_words[4] = {b.limbs.x, b.limbs.y, b.limbs.z, b.limbs.w};

    for (uint i = 0U; i < 4U; ++i) {
        ulong carry = 0UL;
        ulong carry_hi = 0UL;
        for (uint j = 0U; j < 4U; ++j) {
            bn254_mul_add(a_words[i], b_words[j], t[i + j], carry, carry_hi);
        }
        bn254_add_carry_to_limbs(t, i + 4U, carry);
        bn254_add_carry_to_limbs(t, i + 5U, carry_hi);
    }

    thread ulong reduced[4];
    bn254_montgomery_reduce(t, reduced);
    return bn254_from_limbs(ulong4(reduced[0], reduced[1], reduced[2], reduced[3]));
}

inline Bn254 bn254_r2() {
    return bn254_from_limbs(ulong4(BN254_R2[0], BN254_R2[1], BN254_R2[2], BN254_R2[3]));
}

inline Bn254 bn254_from_canonical(ulong4 raw) {
    return bn254_montgomery_mul(bn254_from_limbs(raw), bn254_r2());
}

inline Bn254 bn254_from_canonical_value(Bn254 value) {
    return bn254_from_canonical(value.limbs);
}

inline Bn254 bn254_to_canonical(Bn254 value) {
    thread ulong t[9] = {
        value.limbs.x,
        value.limbs.y,
        value.limbs.z,
        value.limbs.w,
        0UL,
        0UL,
        0UL,
        0UL,
        0UL,
    };
    thread ulong out_limbs[4];
    bn254_montgomery_reduce(t, out_limbs);
    return bn254_from_limbs(ulong4(out_limbs[0], out_limbs[1], out_limbs[2], out_limbs[3]));
}

inline Bn254 bn254_one_montgomery() {
    return bn254_from_canonical(ulong4(1UL, 0UL, 0UL, 0UL));
}

inline Bn254 bn254_pow_u64(Bn254 base, ulong exponent) {
    Bn254 result = bn254_one_montgomery();
    Bn254 power = base;
    ulong exp = exponent;
    while (exp != 0UL) {
        if ((exp & 1UL) != 0UL) {
            result = bn254_montgomery_mul(result, power);
        }
        power = bn254_montgomery_mul(power, power);
        exp >>= 1UL;
    }
    return result;
}

inline ulong bn254_bit_reverse_index(ulong index, uint log_size) {
    ulong reversed = 0UL;
    for (uint bit = 0U; bit < log_size; ++bit) {
        reversed = (reversed << 1UL) | (index & 1UL);
        index >>= 1UL;
    }
    return reversed;
}

kernel void bn254_fft_columns(
    device Bn254 *columns [[buffer(0)]],
    constant uint &log_size [[buffer(1)]],
    device const Bn254 *stage_twiddles [[buffer(2)]],
    uint tid [[thread_index_in_threadgroup]],
    uint threads_per_group [[threads_per_threadgroup]]
) {
    ulong n = 1UL << log_size;
    if (n == 0UL || stage_twiddles == nullptr) {
        return;
    }

    for (ulong idx = tid; idx < n; idx += threads_per_group) {
        columns[idx] = bn254_from_canonical_value(columns[idx]);
    }
    threadgroup_barrier(mem_flags::mem_device);

    for (ulong idx = tid; idx < n; idx += threads_per_group) {
        ulong reversed = bn254_bit_reverse_index(idx, log_size);
        if (idx < reversed) {
            Bn254 value = columns[idx];
            columns[idx] = columns[reversed];
            columns[reversed] = value;
        }
    }
    threadgroup_barrier(mem_flags::mem_device);

    ulong stage_span = n >> 1UL;
    for (uint stage = 0U; stage < log_size; ++stage) {
        ulong len = 1UL << (stage + 1U);
        ulong half_len = len >> 1UL;
        ulong stage_offset = (1UL << stage) - 1UL;
        for (ulong pair_idx = tid; pair_idx < stage_span; pair_idx += threads_per_group) {
            ulong block = pair_idx / half_len;
            ulong pair = pair_idx % half_len;
            ulong idx = block * len + pair;
            if (idx + half_len >= n) {
                continue;
            }
            Bn254 twiddle = bn254_from_canonical_value(stage_twiddles[stage_offset + pair]);
            Bn254 u = columns[idx];
            Bn254 v = bn254_montgomery_mul(columns[idx + half_len], twiddle);
            columns[idx] = bn254_add(u, v);
            columns[idx + half_len] = bn254_sub(u, v);
        }
        threadgroup_barrier(mem_flags::mem_device);
    }

    for (ulong idx = tid; idx < n; idx += threads_per_group) {
        columns[idx] = bn254_to_canonical(columns[idx]);
    }
}

kernel void bn254_lde_columns(
    device const Bn254 *coeffs [[buffer(0)]],
    device Bn254 *out [[buffer(1)]],
    constant uint &trace_log [[buffer(2)]],
    constant uint &blowup_log [[buffer(3)]],
    constant Bn254 &coset [[buffer(4)]],
    device const Bn254 *stage_twiddles [[buffer(5)]],
    uint tid [[thread_index_in_threadgroup]],
    uint threads_per_group [[threads_per_threadgroup]]
) {
    ulong trace_len = 1UL << trace_log;
    ulong eval_len = trace_len << blowup_log;
    if (eval_len == 0UL || stage_twiddles == nullptr) {
        return;
    }

    for (ulong idx = tid; idx < trace_len; idx += threads_per_group) {
        out[idx] = bn254_from_canonical_value(coeffs[idx]);
    }
    for (ulong idx = tid + trace_len; idx < eval_len; idx += threads_per_group) {
        out[idx] = bn254_zero();
    }
    threadgroup_barrier(mem_flags::mem_device);

    uint log_len = trace_log + blowup_log;
    ulong stage_span = eval_len >> 1UL;
    Bn254 coset_mont = bn254_from_canonical_value(coset);
    Bn254 coset_stride = bn254_pow_u64(coset_mont, (ulong)threads_per_group);
    Bn254 coset_power = bn254_pow_u64(coset_mont, (ulong)tid);

    for (ulong idx = tid; idx < trace_len; idx += threads_per_group) {
        out[idx] = bn254_montgomery_mul(out[idx], coset_power);
        coset_power = bn254_montgomery_mul(coset_power, coset_stride);
    }
    threadgroup_barrier(mem_flags::mem_device);

    for (ulong idx = tid; idx < eval_len; idx += threads_per_group) {
        ulong reversed = bn254_bit_reverse_index(idx, log_len);
        if (idx < reversed) {
            Bn254 value = out[idx];
            out[idx] = out[reversed];
            out[reversed] = value;
        }
    }
    threadgroup_barrier(mem_flags::mem_device);

    for (uint stage = 0U; stage < log_len; ++stage) {
        ulong len = 1UL << (stage + 1U);
        ulong half_len = len >> 1UL;
        ulong stage_offset = (1UL << stage) - 1UL;
        for (ulong pair_idx = tid; pair_idx < stage_span; pair_idx += threads_per_group) {
            ulong block = pair_idx / half_len;
            ulong pair = pair_idx % half_len;
            ulong idx = block * len + pair;
            if (idx + half_len >= eval_len) {
                continue;
            }
            Bn254 twiddle = bn254_from_canonical_value(stage_twiddles[stage_offset + pair]);
            Bn254 u = out[idx];
            Bn254 v = bn254_montgomery_mul(out[idx + half_len], twiddle);
            out[idx] = bn254_add(u, v);
            out[idx + half_len] = bn254_sub(u, v);
        }
        threadgroup_barrier(mem_flags::mem_device);
    }

    for (ulong idx = tid; idx < eval_len; idx += threads_per_group) {
        out[idx] = bn254_to_canonical(out[idx]);
    }
}

struct Bn254PoseidonArgs {
    uint batch_count;
    uint states_per_lane;
    uint round_count;
    uint reserved;
};

struct Bn254PoseidonSlice {
    uint offset;
    uint len;
};

constant uint BN254_POSEIDON_WIDTH = 3U;
constant uint BN254_POSEIDON_FULL_ROUNDS_HALF = 4U;
constant uint BN254_POSEIDON_PARTIAL_ROUNDS = 57U;
constant uint BN254_POSEIDON_TOTAL_ROUNDS =
    BN254_POSEIDON_FULL_ROUNDS_HALF * 2U + BN254_POSEIDON_PARTIAL_ROUNDS;

inline Bn254 bn254_from_u64(ulong value) {
    return bn254_from_canonical(ulong4(value, 0UL, 0UL, 0UL));
}

inline Bn254 bn254_one() {
    return bn254_from_u64(1UL);
}

inline Bn254 bn254_pow5(Bn254 value) {
    Bn254 squared = bn254_montgomery_mul(value, value);
    Bn254 fourth = bn254_montgomery_mul(squared, squared);
    return bn254_montgomery_mul(fourth, value);
}

inline Bn254 bn254_load_limb_value(device const ulong *limbs, ulong index) {
    ulong base = index * 4UL;
    return bn254_from_limbs(ulong4(
        limbs[base],
        limbs[base + 1U],
        limbs[base + 2U],
        limbs[base + 3U]));
}

inline void bn254_store_limb_value(device ulong *limbs, ulong index, Bn254 value) {
    ulong base = index * 4UL;
    limbs[base] = value.limbs.x;
    limbs[base + 1U] = value.limbs.y;
    limbs[base + 2U] = value.limbs.z;
    limbs[base + 3U] = value.limbs.w;
}

inline Bn254 bn254_poseidon_round_constant(
    device const ulong *round_constants,
    uint round,
    uint word
) {
    return bn254_from_canonical_value(
        bn254_load_limb_value(round_constants, round * BN254_POSEIDON_WIDTH + word));
}

inline Bn254 bn254_poseidon_mds_coeff(device const ulong *mds, uint row, uint col) {
    return bn254_from_canonical_value(
        bn254_load_limb_value(mds, row * BN254_POSEIDON_WIDTH + col));
}

inline void bn254_poseidon_apply_mds(thread Bn254 (&state)[3], device const ulong *mds) {
    thread Bn254 next[3] = {bn254_zero(), bn254_zero(), bn254_zero()};
    for (uint row = 0U; row < BN254_POSEIDON_WIDTH; ++row) {
        Bn254 acc = bn254_zero();
        for (uint col = 0U; col < BN254_POSEIDON_WIDTH; ++col) {
            Bn254 coeff = bn254_poseidon_mds_coeff(mds, row, col);
            acc = bn254_add(acc, bn254_montgomery_mul(coeff, state[col]));
        }
        next[row] = acc;
    }
    state[0] = next[0];
    state[1] = next[1];
    state[2] = next[2];
}

inline void bn254_poseidon_permute(
    thread Bn254 (&state)[3],
    device const ulong *round_constants,
    device const ulong *mds
) {
    for (uint round = 0U; round < BN254_POSEIDON_FULL_ROUNDS_HALF; ++round) {
        for (uint word = 0U; word < BN254_POSEIDON_WIDTH; ++word) {
            state[word] = bn254_pow5(bn254_add(
                state[word],
                bn254_poseidon_round_constant(round_constants, round, word)));
        }
        bn254_poseidon_apply_mds(state, mds);
    }

    for (uint idx = 0U; idx < BN254_POSEIDON_PARTIAL_ROUNDS; ++idx) {
        uint round = BN254_POSEIDON_FULL_ROUNDS_HALF + idx;
        for (uint word = 0U; word < BN254_POSEIDON_WIDTH; ++word) {
            state[word] = bn254_add(
                state[word],
                bn254_poseidon_round_constant(round_constants, round, word));
        }
        state[0] = bn254_pow5(state[0]);
        bn254_poseidon_apply_mds(state, mds);
    }

    uint tail_start = BN254_POSEIDON_FULL_ROUNDS_HALF + BN254_POSEIDON_PARTIAL_ROUNDS;
    for (uint idx = 0U; idx < BN254_POSEIDON_FULL_ROUNDS_HALF; ++idx) {
        uint round = tail_start + idx;
        for (uint word = 0U; word < BN254_POSEIDON_WIDTH; ++word) {
            state[word] = bn254_pow5(bn254_add(
                state[word],
                bn254_poseidon_round_constant(round_constants, round, word)));
        }
        bn254_poseidon_apply_mds(state, mds);
    }
}

inline void bn254_poseidon_absorb_pair(
    thread Bn254 (&state)[3],
    Bn254 first,
    Bn254 second,
    device const ulong *round_constants,
    device const ulong *mds
) {
    state[0] = bn254_add(state[0], first);
    state[1] = bn254_add(state[1], second);
    bn254_poseidon_permute(state, round_constants, mds);
}

inline Bn254 bn254_poseidon_hash_slice(
    device const ulong *words,
    Bn254PoseidonSlice slice,
    device const ulong *round_constants,
    device const ulong *mds
) {
    thread Bn254 state[3] = {bn254_zero(), bn254_zero(), bn254_zero()};
    uint cursor = 0U;
    while (cursor + 1U < slice.len) {
        ulong word_index = (ulong)slice.offset + (ulong)cursor;
        Bn254 first = bn254_from_u64(words[word_index]);
        Bn254 second = bn254_from_u64(words[word_index + 1UL]);
        bn254_poseidon_absorb_pair(state, first, second, round_constants, mds);
        cursor += 2U;
    }
    if (cursor < slice.len) {
        Bn254 first = bn254_from_u64(words[(ulong)slice.offset + (ulong)cursor]);
        bn254_poseidon_absorb_pair(state, first, bn254_one(), round_constants, mds);
    } else {
        bn254_poseidon_absorb_pair(state, bn254_one(), bn254_zero(), round_constants, mds);
    }
    return bn254_to_canonical(state[0]);
}

kernel void bn254_poseidon_hash_words(
    device const ulong *words [[ buffer(0) ]],
    device const Bn254PoseidonSlice *slices [[ buffer(1) ]],
    device ulong *outputs [[ buffer(2) ]],
    device const ulong *round_constants [[ buffer(3) ]],
    device const ulong *mds [[ buffer(4) ]],
    constant Bn254PoseidonArgs &args [[ buffer(5) ]],
    uint3 grid_pos [[ thread_position_in_grid ]]
) {
    if (args.batch_count == 0U || args.round_count != BN254_POSEIDON_TOTAL_ROUNDS) {
        return;
    }
    uint states_per_lane = max(args.states_per_lane, 1U);
    uint processed = 0U;
    ulong start = (ulong)grid_pos.x * (ulong)states_per_lane;
    while (processed < states_per_lane) {
        ulong index = start + (ulong)processed;
        if (index >= (ulong)args.batch_count) {
            break;
        }
        Bn254 digest = bn254_poseidon_hash_slice(words, slices[index], round_constants, mds);
        bn254_store_limb_value(outputs, index, digest);
        ++processed;
    }
}
