// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.sdk.offline;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Java uses the canonical Kotlin QR scanner and shared wallet fixtures, without another codec. */
final class IrohaPeerQRJavaConsumerTest {
  @Test
  void reorderedDuplicateAndLostFramesPreserveExactSharedWalletOriginals() {
    for (final IrohaPeerWireMessageV1 original : Arrays.asList(
        IrohaPeerNfcTestFixturesV1.INSTANCE.getRequest(),
        IrohaPeerNfcTestFixturesV1.INSTANCE.getPayment(),
        IrohaPeerNfcTestFixturesV1.INSTANCE.getCredited())) {
      final List<String> texts = IrohaPeerQRCodecV1.animatedFrameTexts(original);
      final List<String> retained = new ArrayList<>();
      String header = null;
      for (final String text : texts) {
        final IrohaPeerQRFrameV1 frame = IrohaPeerQRCodecV1.decodeFrame(text);
        if (frame.getFrameKind() == IrohaPeerQRFrameKindV1.HEADER) {
          header = text;
        } else if (frame.getFrameKind() != IrohaPeerQRFrameKindV1.DATA || frame.getIndex() != 0) {
          retained.add(text);
        }
      }
      assertNotNull(header);
      Collections.reverse(retained);
      final IrohaPeerQRScanSessionV1 session = new IrohaPeerQRScanSessionV1(
          IrohaPeerPayloadProfile.KAGEMUSHA_WALLET_V1, original.getCanonicalPayload().getKind(), 1);
      assertNull(session.ingestAt(header, 0).getMessage());
      IrohaPeerQRScanResultV1 completed = null;
      for (final String text : retained) {
        final IrohaPeerQRScanResultV1 first = session.ingestAt(text, 0);
        if (first.isComplete()) {
          completed = first;
          break;
        }
        final IrohaPeerQRScanResultV1 duplicate = session.ingestAt(text, 0);
        assertNull(duplicate.getMessage());
        assertEquals(first.getUsableFrames(), duplicate.getUsableFrames());
      }
      assertNotNull(completed);
      assertTrue(completed.getRecoveredDataFrames() >= 1);
      assertEquals(0, session.getActiveStreamCount());
      final IrohaPeerWireMessageV1 decoded = completed.getMessage();
      assertNotNull(decoded);
      assertArrayEquals(original.encode(), decoded.encode());
      assertArrayEquals(IrohaPeerKagemushaWalletAdapterV1.decode(original),
          IrohaPeerKagemushaWalletAdapterV1.decode(decoded));
      assertEquals(texts, IrohaPeerQRCodecV1.animatedFrameTexts(decoded));
      // The byte-equal IPM1 includes both Request/Payment companions. Transport does not
      // establish proof admission, debit/credit counts or permanent monetary replay protection.
    }
  }

  @Test
  void aChecksumValidSameIndexConflictQuarantinesTheStream() {
    final IrohaPeerQRFrameV1 frame = IrohaPeerQRCodecV1.animatedFrameTexts(
        IrohaPeerNfcTestFixturesV1.INSTANCE.getPayment()).stream()
        .map(IrohaPeerQRCodecV1::decodeFrame)
        .filter(item -> item.getFrameKind() == IrohaPeerQRFrameKindV1.DATA)
        .findFirst().get();
    final byte[] stream = frame.getStreamId();
    final byte[] payload = frame.getPayload();
    payload[0] ^= 1;
    final IrohaPeerQRFrameV1 conflicting = new IrohaPeerQRFrameV1(
        frame.getFrameKind(), frame.getProfile(), frame.getPayloadKind(), stream,
        frame.getIndex(), frame.getTotal(), payload);
    final String conflictText = IrohaPeerQRCodecV1.encodeFrame(conflicting);
    // Constructor/getter ownership prevents Java arrays from changing retained frames.
    Arrays.fill(stream, (byte) 0);
    Arrays.fill(payload, (byte) 0);
    Arrays.fill(conflicting.getPayload(), (byte) 0);
    assertEquals(conflictText, IrohaPeerQRCodecV1.encodeFrame(conflicting));
    assertEquals(conflicting, IrohaPeerQRCodecV1.decodeFrame(conflictText));
    final IrohaPeerQRScanSessionV1 session = new IrohaPeerQRScanSessionV1();
    assertNull(session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(frame), 0).getMessage());
    assertEquals("Conflicting duplicate IRQR frame", assertThrows(IllegalArgumentException.class,
        () -> session.ingestAt(conflictText, 0)).getMessage());
    assertEquals(0, session.getActiveStreamCount());
    assertEquals("IRQR stream is quarantined", assertThrows(IllegalArgumentException.class,
        () -> session.ingestAt(IrohaPeerQRCodecV1.encodeFrame(frame), 0)).getMessage());
  }

  @Test
  void configuredStreamCapacityIsEnforcedThroughTheJavaConstructor() {
    assertThrows(IllegalArgumentException.class, () -> new IrohaPeerQRScanLimitsV1(4));
    final IrohaPeerQRScanSessionV1 session = new IrohaPeerQRScanSessionV1(
        null, null, null, new IrohaPeerQRScanLimitsV1(1));
    final List<String> payment = IrohaPeerQRCodecV1.animatedFrameTexts(
        IrohaPeerNfcTestFixturesV1.INSTANCE.getPayment());
    final List<String> request = IrohaPeerQRCodecV1.animatedFrameTexts(
        IrohaPeerNfcTestFixturesV1.INSTANCE.getRequest());
    assertNull(session.ingestAt(payment.get(0), 0).getMessage());
    assertEquals("Too many active IRQR streams", assertThrows(IllegalArgumentException.class,
        () -> session.ingestAt(request.get(0), 0)).getMessage());
    assertEquals(1, session.getActiveStreamCount());
    final IrohaPeerQRScanResultV1 completed = payment.stream()
        .map(text -> session.ingestAt(text, 0)).filter(IrohaPeerQRScanResultV1::isComplete)
        .findFirst().get();
    assertArrayEquals(IrohaPeerNfcTestFixturesV1.INSTANCE.getPayment().encode(),
        completed.getMessage().encode());
    assertEquals(0, session.getActiveStreamCount());
    assertNull(session.ingestAt(request.get(0), 0).getMessage());
    assertEquals(1, session.getActiveStreamCount());
  }
}
