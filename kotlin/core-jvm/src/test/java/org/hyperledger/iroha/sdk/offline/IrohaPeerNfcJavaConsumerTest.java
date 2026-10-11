// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * Java consumers use the Kotlin NFC APDU vocabulary and the IPM1 wallet message kinds directly.
 *
 * <p>These assertions moved here from the retired Java duplicate
 * {@code java/iroha_android/.../IrohaPeerNfcV1AdversarialTests}.
 */
final class IrohaPeerNfcJavaConsumerTest {
  @Test
  void javaRoundTripsTheDirectApduVocabulary() {
    final IrohaPeerNfcCommandV1 request = IrohaPeerNfcCommandV1.readRequest(17, 23);
    final IrohaPeerNfcCommandV1 decodedRequest =
        IrohaPeerNfcAPDUCodecV1.decode(IrohaPeerNfcAPDUCodecV1.encode(request));
    assertEquals(IrohaPeerNfcCommandTypeV1.READ_REQUEST, decodedRequest.type);
    assertEquals(17, decodedRequest.offset);
    assertEquals(23, decodedRequest.length);

    final IrohaPeerNfcCommandV1 payment =
        IrohaPeerNfcCommandV1.writePayment(29, new byte[] {0x55, 0x66});
    final IrohaPeerNfcCommandV1 decodedPayment =
        IrohaPeerNfcAPDUCodecV1.decode(IrohaPeerNfcAPDUCodecV1.encode(payment));
    assertEquals(IrohaPeerNfcCommandTypeV1.WRITE_PAYMENT, decodedPayment.type);
    assertEquals(29, decodedPayment.offset);
    assertArrayEquals(new byte[] {0x55, 0x66}, decodedPayment.bytes());

    for (final IrohaPeerNfcCommandV1 command : new IrohaPeerNfcCommandV1[] {
        IrohaPeerNfcCommandV1.GET_INFO,
        IrohaPeerNfcCommandV1.readRequest(0, 64),
        IrohaPeerNfcCommandV1.COMMIT_PAYMENT,
        IrohaPeerNfcCommandV1.readAcknowledgement(0, 32),
        IrohaPeerNfcCommandV1.CONFIRM_ACKNOWLEDGEMENT,
        IrohaPeerNfcCommandV1.GET_STATUS,
        IrohaPeerNfcCommandV1.RESET_SESSION,
    }) {
      final byte[] encoded = IrohaPeerNfcAPDUCodecV1.encode(command);
      assertArrayEquals(
          encoded, IrohaPeerNfcAPDUCodecV1.encode(IrohaPeerNfcAPDUCodecV1.decode(encoded)));
    }
  }

  @Test
  void javaRejectsNonCanonicalExtendedApduAliases() {
    final byte[] aliasedGetInfo = new byte[] {(byte) 0x80, 0x10, 0, 0, 0, 0, 0x62};
    assertThrows(
        IllegalArgumentException.class, () -> IrohaPeerNfcAPDUCodecV1.decode(aliasedGetInfo));
  }

  @Test
  void noDataCommandHasOneCanonicalEncoding() {
    assertArrayEquals(
        new byte[] {(byte) 0x80, 0x10, 0, 0, 0, 0, 0},
        IrohaPeerNfcAPDUCodecV1.encode(IrohaPeerNfcCommandV1.GET_INFO));
  }

  @Test
  void peerMessageKindsAreExactlyTheWalletEnvelopeTags() {
    assertEquals(7, IrohaPeerPayloadKind.values().length);
    assertEquals(10_000, KagemushaWalletWireV1.MESSAGE_MAX_BYTES);
    assertEquals(16 + 10_000 + 4_096, IrohaPeerWalletRequestV1.MAXIMUM_BYTES);
    for (final IrohaPeerPayloadKind kind : IrohaPeerPayloadKind.values()) {
      assertEquals(kind.getWalletMessageKind().wireTag, kind.getCode());
      final int expectedMaximum = kind == IrohaPeerPayloadKind.REQUEST
          ? IrohaPeerWalletRequestV1.MAXIMUM_BYTES
          : kind.getWalletMessageKind().maximumFrameBytes;
      assertEquals(expectedMaximum, kind.getMaximumWalletFrameBytes());
      assertSame(kind, IrohaPeerPayloadKind.fromCode(kind.getCode()));
      assertSame(kind, IrohaPeerPayloadKind.of(kind.getWalletMessageKind()));
    }
    assertNull(IrohaPeerPayloadKind.fromCode(0));
    assertNull(IrohaPeerPayloadKind.fromCode(8));
    assertNull(IrohaPeerPayloadKind.fromCode(255));
    assertSame(
        IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1, IrohaPeerPayloadProfile.fromCode(1));
    assertNull(IrohaPeerPayloadProfile.fromCode(0));
    assertNull(IrohaPeerPayloadProfile.fromCode(2));
  }
}
