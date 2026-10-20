// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * Java consumers use the Kotlin NFC command vocabulary, its strict APDU codec, application
 * identifiers and the IPM1 wallet message kinds directly.
 *
 * <p>These assertions moved here from the retired Java duplicate
 * {@code java/iroha_android/.../IrohaPeerNfcV1AdversarialTests}.
 */
final class IrohaPeerNfcJavaConsumerTest {
  private static final IrohaPeerNfcApplicationIdentifierV1 BPNG =
      IrohaPeerNfcApplicationIdentifierV1.fromHex("F05047444B4E464301");
  private static final byte[] SESSION = filled(16, 0x11);
  private static final byte[] REQUEST_HASH = filled(32, 0x22);
  private static final byte[] PAYMENT_HASH = filled(32, 0x44);

  @Test
  void javaRoundTripsTheCommandVocabulary() {
    final IrohaPeerNfcCommandV1 request =
        new IrohaPeerNfcCommandV1.ReadRequest(SESSION, REQUEST_HASH, 17L, 23);
    final IrohaPeerNfcCommandV1 decodedRequest =
        IrohaPeerNfcAPDUCodecV1.decode(IrohaPeerNfcAPDUCodecV1.encode(request), BPNG);
    assertEquals(request, decodedRequest);
    assertEquals(IrohaPeerNfcOperationV1.READ_REQUEST, decodedRequest.getOperation());
    final IrohaPeerNfcCommandV1.ReadRequest typedRequest =
        (IrohaPeerNfcCommandV1.ReadRequest) decodedRequest;
    assertEquals(17L, typedRequest.offset);
    assertEquals(23, typedRequest.length);
    assertArrayEquals(SESSION, typedRequest.getSessionId());

    final IrohaPeerNfcCommandV1 payment =
        new IrohaPeerNfcCommandV1.Write(SESSION, PAYMENT_HASH, 29L, new byte[] {0x55, 0x66});
    final IrohaPeerNfcCommandV1.Write decodedPayment =
        (IrohaPeerNfcCommandV1.Write)
            IrohaPeerNfcAPDUCodecV1.decode(IrohaPeerNfcAPDUCodecV1.encode(payment), BPNG);
    assertEquals(29L, decodedPayment.offset);
    assertArrayEquals(new byte[] {0x55, 0x66}, decodedPayment.getBytes());

    for (final IrohaPeerNfcCommandV1 command :
        Arrays.asList(
            new IrohaPeerNfcCommandV1.SelectApplication(BPNG),
            IrohaPeerNfcCommandV1.GetIntake.INSTANCE,
            IrohaPeerNfcCommandV1.GetInfo.INSTANCE,
            new IrohaPeerNfcCommandV1.ReadRequest(SESSION, REQUEST_HASH, 0L, 64),
            new IrohaPeerNfcCommandV1.Commit(SESSION, REQUEST_HASH, PAYMENT_HASH),
            new IrohaPeerNfcCommandV1.ReadAcknowledgement(SESSION, PAYMENT_HASH, 0L, 32),
            new IrohaPeerNfcCommandV1.ConfirmAcknowledgement(
                SESSION, PAYMENT_HASH, filled(32, 0x55)),
            new IrohaPeerNfcCommandV1.GetStatus(SESSION, REQUEST_HASH))) {
      final byte[] encoded = IrohaPeerNfcAPDUCodecV1.encode(command);
      assertArrayEquals(
          encoded,
          IrohaPeerNfcAPDUCodecV1.encode(IrohaPeerNfcAPDUCodecV1.decode(encoded, BPNG)));
    }
  }

  @Test
  void javaRejectsNonCanonicalExtendedApduAliases() {
    final byte[] aliasedGetInfo = new byte[] {(byte) 0x80, 0x10, 0, 0, 0, 0, 0x62};
    final IrohaPeerNfcExceptionV1 failure =
        assertThrows(
            IrohaPeerNfcExceptionV1.class,
            () -> IrohaPeerNfcAPDUCodecV1.decode(aliasedGetInfo, BPNG));
    assertEquals(IrohaPeerNfcErrorV1.INVALID_APDU, failure.error);
    assertEquals(
        IrohaPeerNfcStatusWordV1.WRONG_DATA, IrohaPeerNfcStatusWordV1.forError(failure.error));
  }

  @Test
  void noDataCommandsHaveOneCanonicalEncoding() {
    assertArrayEquals(
        new byte[] {(byte) 0x80, 0x10, 0, 0, 0x62},
        IrohaPeerNfcAPDUCodecV1.encode(IrohaPeerNfcCommandV1.GetInfo.INSTANCE));
    assertArrayEquals(
        new byte[] {(byte) 0x80, 0x30, 0, 0, 0x44},
        IrohaPeerNfcAPDUCodecV1.encode(IrohaPeerNfcCommandV1.GetIntake.INSTANCE));
  }

  @Test
  void javaCardAnswersOnlyItsOwnApplicationIdentifier() {
    final IrohaPeerNfcCardEndpointV1 card =
        IrohaPeerNfcCardEndpointV1.direct(BPNG,
            new IrohaPeerNfcReceiverSessionV1(SESSION,
                IrohaPeerNfcTestFixturesV1.INSTANCE.getRequest().encode()));
    final byte[] selectBpng =
        IrohaPeerNfcAPDUCodecV1.encode(new IrohaPeerNfcCommandV1.SelectApplication(BPNG));
    final byte[] selectProtocol =
        IrohaPeerNfcAPDUCodecV1.encode(
            new IrohaPeerNfcCommandV1.SelectApplication(
                IrohaPeerNfcApplicationIdentifierV1.PROTOCOL));
    assertEquals(IrohaPeerNfcStatusWordV1.SUCCESS, card.process(selectBpng).statusWord);
    assertEquals(IrohaPeerNfcStatusWordV1.NOT_FOUND, card.process(selectProtocol).statusWord);
    final IrohaPeerNfcIntakeRecordV1 intake =
        IrohaPeerNfcIntakeRecordV1.decode(
            card.process(
                    IrohaPeerNfcAPDUCodecV1.encode(IrohaPeerNfcCommandV1.GetIntake.INSTANCE))
                .data());
    assertEquals(IrohaPeerNfcIntakeStateV1.REQUEST_READY, intake.state);
    assertArrayEquals(card.getSessionId(), intake.getSessionId());
    assertEquals(
        IrohaPeerNfcStatusWordV1.SUCCESS,
        card.process(IrohaPeerNfcAPDUCodecV1.encode(IrohaPeerNfcCommandV1.GetInfo.INSTANCE))
            .statusWord);
    assertEquals("F0504B45504B524E464301", IrohaPeerNfcApplicationIdentifierV1.PROTOCOL.hex());
  }

  @Test
  void peerMessageKindsAreExactlyTheWalletEnvelopeTags() {
    assertEquals(5, IrohaPeerPayloadKind.values().length);
    assertEquals(10_000, KagemushaWalletWireV1.MESSAGE_MAX_BYTES);
    assertEquals(16 + 10_000 + 4_096, IrohaPeerWalletRequestV1.MAXIMUM_BYTES);
    for (final IrohaPeerPayloadKind kind : IrohaPeerPayloadKind.values()) {
      assertEquals(kind.getWalletMessageKind().wireTag, kind.getCode());
      final int expectedMaximum = kind == IrohaPeerPayloadKind.REQUEST
          ? IrohaPeerWalletRequestV1.MAXIMUM_BYTES
          : kind == IrohaPeerPayloadKind.PAYMENT ? IrohaPeerWalletPaymentV1.MAXIMUM_BYTES
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
    assertEquals(84 + 14_112, IrohaPeerNfcV1.MAXIMUM_MESSAGE_BYTES);
    assertEquals(16 + 10_000 + 2_048, IrohaPeerWalletPaymentV1.MAXIMUM_BYTES);
    assertNull(IrohaPeerPayloadKind.fromCode(1));
    assertNull(IrohaPeerPayloadKind.fromCode(7));
  }

  @Test
  void retiredOfferAndAskCommandsNeverDecode() {
    for (final int instruction : new int[] {0x31, 0x32, 0x33, 0x34}) {
      final byte[] retired = new byte[] {(byte) 0x80, (byte) instruction, 0, 0, 0};
      assertThrows(IrohaPeerNfcExceptionV1.class,
          () -> IrohaPeerNfcAPDUCodecV1.decode(retired, BPNG));
    }
  }

  private static byte[] filled(final int size, final int value) {
    final byte[] bytes = new byte[size];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }
}
