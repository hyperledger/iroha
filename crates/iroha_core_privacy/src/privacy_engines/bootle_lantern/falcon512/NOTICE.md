# Falcon-512 implementation provenance

This directory selectively adapts portable scalar code from the
[`rust-fn-dsa`](https://github.com/pornin/rust-fn-dsa) version 0.3 workspace
at exact commit `daf14859b5aa3f8d75c42966ba7de83e6eb59997`. The upstream
workspace is released under the Unlicense; the complete upstream license text
is reproduced in [`LICENSE`](LICENSE).

Imported implementation sources:

- `fn-dsa-comm/src/mq.rs` and `fn-dsa-comm/src/shake.rs`;
- `fn-dsa-kgen/src/{fxp,gauss,mp31,ntru,poly,vect,zint31}.rs` and the
  degree-512 key-generation orchestration from `fn-dsa-kgen/src/lib.rs`;
- `fn-dsa-sign/src/{flr,flr_emu,poly,sampler}.rs`, the portable signing
  orchestration from `fn-dsa-sign/src/lib.rs`, and that file's test-only
  ChaCha20 PRNG and `KAT_512` vector.

Intentional semantic deltas from upstream:

- only the portable scalar Falcon-512 path is retained; runtime SIMD dispatch,
  AVX2 modules, native floating point, other degrees, codecs, message handling,
  legacy Falcon modes, and verification orchestration are not compiled;
- key generation returns raw `(f, g, F, G, h)` material and has explicit
  candidate and parity-sampling exhaustion limits;
- reduced-degree keygen sampling (`logn` 1 through 5) rejects an entire
  polynomial candidate when a coefficient exceeds `[-127, 127]`, consuming
  one existing attempt instead of retrying that coefficient without a bound;
  degree-512 and degree-1024 draw streams are unchanged because their
  coefficients cannot reach this refusal;
- signing is specialized to an externally supplied canonical polynomial target
  and returns both short preimage halves for `s1 + h*s2 = target mod 12289`;
- the signing PRNG retains the pinned eight-block, word-major ChaCha20 stream
  layout, while secret state and working words are explicitly zeroized;
- Gaussian sampling has explicit per-coefficient and total proposal caps;
- conditional big-integer negation propagates addition carry through zero limbs;
- the integer Bezout solver preserves its exact relation when the second
  operand is one, where modular reduction alone erases the required coefficient;
- depth-one keygen subtraction retains the Montgomery factor when restoring
  its multiplier between prime passes at scales divisible by 32; the fixed
  Falcon-512 reduction schedule already avoids those two-prime scale cases;
- the emulated exponential helper handles its documented unit scale exactly
  at the polynomial endpoint, without signed-conversion or fixed-point
  overflow; factors below one retain the original rounding;
- the sampler preserves a zero probability threshold instead of wrapping it
  to the maximum threshold; positive thresholds retain their original bytes;
- every returned preimage is rejected unless the exact ring equation and the
  Falcon-512 squared-norm bound both hold;
- secret-bearing buffers are wrapped in zeroizing storage, and no `unsafe`
  or SIMD code is present in this directory.

This is the concrete one-key Falcon-512 specialization of the Bootle/Lantern
`[1 | h]` relation. It is not an implementation of the full BLNS main
security reduction.
