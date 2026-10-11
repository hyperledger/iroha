---
title: QR Stream Transport
---

This document defines the QR stream framing used to move opaque binary payloads between
devices using animated QR codes. The format is deterministic, simple, and designed to be
implemented across Swift, Android, and JavaScript with consistent results.

## 1. Overview

QR stream splits a binary payload into fixed-size chunks, adds optional XOR parity frames, and
wraps each chunk in a CRC32-protected frame. A header frame carries the envelope metadata
needed to reassemble the payload and verify its hash. The payload bytes are opaque to the
stream; the `payload_kind` tag is reserved for a future typed payload registry.

Key properties:

- **Deterministic framing:** fixed byte layout with little-endian integers.
- **Out-of-order tolerant:** frames may arrive in any order; duplicates are ignored.
- **Parity recovery:** one missing data chunk per group can be recovered via XOR parity.
- **Binary-first:** QR codes should embed raw bytes (byte mode). When scanners only return text,
  use the Base64 text wrapper described in §6.

## 2. Envelope (`QrStreamEnvelope`)

The envelope is encoded as a fixed 47-byte structure and is carried inside the header frame.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `flags` | Reserved flags (set to `0`). |
| 1 | 1 | `encoding` | Payload encoding (`0` = binary). |
| 2 | 1 | `parity_group` | Parity group size (`0` disables parity). |
| 3 | 2 | `chunk_size` | Data chunk size in bytes (LE `u16`). |
| 5 | 2 | `data_chunks` | Number of data chunks (LE `u16`). |
| 7 | 2 | `parity_chunks` | Number of parity chunks (LE `u16`). |
| 9 | 2 | `payload_kind` | Payload kind tag (LE `u16`). |
| 11 | 4 | `payload_length` | Payload length in bytes (LE `u32`). |
| 15 | 32 | `payload_hash` | Blake2b-256 of the payload (raw bytes, no LSB forcing). |

`stream_id = payload_hash[0..16]` (first 16 bytes).

### 2.1 Payload kind tags

| Value | Meaning |
|-------|---------|
| `0` | `unspecified` |

This is the `IQ` envelope's little-endian `u16` registry. Encoders emit `0`; decoders read
every other value as `unspecified`. The retired KAGEMUSHA V1 peer-message tags `1` to `3`
are not assigned. The tag is distinct from the one-byte kind field inside an `IPM1` message,
which the [wallet wire](kagemusha_wallet_wire_v1.md) carriers own.

## 3. Frame (`QrStreamFrame`)

Each frame is encoded as:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 2 | `magic` | ASCII `IQ` (`0x49 0x51`). |
| 2 | 1 | `kind` | `0=header`, `1=data`, `2=parity`. |
| 3 | 16 | `stream_id` | First 16 bytes of payload hash. |
| 19 | 2 | `index` | Frame index (LE `u16`). |
| 21 | 2 | `total` | Total frame count for this kind (LE `u16`). |
| 23 | 2 | `payload_len` | Frame payload length (LE `u16`). |
| 25 | N | `payload` | Frame payload bytes. |
| 25+N | 4 | `crc32` | CRC32 over bytes `[kind..payload]` (LE `u32`). |

The CRC32 uses the standard IEEE polynomial (`0xEDB88320`), initial value `0xFFFF_FFFF`,
and final XOR `0xFFFF_FFFF`.

### 3.1 Replay guards

- Assemblers track a single `stream_id` (first 16 bytes of `payload_hash`) and ignore frames
  from other streams once a header is accepted.
- Once a payload is completed and verified, discard any additional frames with the same
  `stream_id` to avoid replaying stale payloads into the same session.

## 4. Chunking and parity

Let:

```
data_chunks = ceil(payload_length / chunk_size)
parity_chunks = parity_group > 0 ? ceil(data_chunks / parity_group) : 0
```

Parity frames are XORs of each parity group. For group `g`:

```
start = g * parity_group
end = min(data_chunks, start + parity_group)
parity = xor(data_chunks[start..end])
```

Parity payloads are always `chunk_size` bytes (data chunks shorter than `chunk_size` are
zero-padded before XOR). Recovery succeeds when **exactly one** data chunk in a group is missing.

## 5. Frame scheduling

Recommended schedule for streaming playback:

1. Emit the header frame.
2. Emit each data chunk in order.
3. Emit parity frames (if enabled).
4. Loop: re-emit the header at least once per loop and at least once per second.

For low-latency recovery, interleave parity immediately after each group:

```
header,
data[0..parity_group-1], parity[0],
data[parity_group..2*parity_group-1], parity[1],
...
```

Assemblers accept out-of-order delivery and duplicate frames; duplicates are ignored.

## 6. QR encoding modes

### 6.1 Binary QR mode (preferred)

Encode the frame bytes directly as QR byte-mode payloads. This yields the smallest symbols and
avoids text conversion overhead.

### 6.2 Text QR fallback

Some scanners only expose decoded text. For those, wrap frame bytes as:

```
iroha:qr:<base64(frame_bytes)>
```

SDKs and the CLI accept this prefix and decode the base64 payload automatically.

## 7. Capacity profile & scanner compatibility

| Platform | Binary QR support | Text fallback |
|----------|-------------------|---------------|
| iOS Vision (`payloadData`) | ✅ | ✅ |
| iOS AVFoundation (`stringValue`) | ❌ | ✅ |
| Android ZXing (raw bytes) | ✅ | ✅ |
| Browser `BarcodeDetector` | ❌ | ✅ |

Recommended defaults:

- `chunk_size`: 180–360 bytes
- ECC: `M` (balanced) or `Q` for noisy environments
- FPS: 10–12 for standard devices, 6–8 for reduced-motion/low-power modes

Reliable ~3 KB/s profile (with parity enabled):

- `chunk_size=336`
- `parity_group=3`
- `fps=12`
- Effective payload rate: around `3` KB/s on medium/large payloads (recorded in CLI manifests as `estimated_payload_bytes_per_second`, computed from payload bytes and rendered frame count)

## 8. Assembler limits

The default assembler limits enforced by `iroha_data_model::qr_stream`:

- Max payload bytes: 2 MiB
- Max chunk size: 1024 bytes
- Max frames: 8192
- Timeout: 120 seconds since the first frame

Override these in clients if a tighter budget is required.

## 9. Fixtures and verification

Fixtures live under `fixtures/qr_stream/`:

- `qr_stream_basic.json`
- `qr_stream_parity.json`

The focused `iroha_data_model` QR stream tests reconstruct every envelope and
frame with the production encoder and compare the resulting bytes with these
fixtures.

## 10. CLI helpers

Encode payloads into frames + images:

```
iroha offline qr encode --input payload.bin --output ./qr_out --format gif --ecc q --fps 12 --chunk-size 336 --parity-group 4 --style sakura-storm
```

Decode raw frame bytes:

```
iroha offline qr decode --input-dir ./qr_out/frames --output payload.bin
```
