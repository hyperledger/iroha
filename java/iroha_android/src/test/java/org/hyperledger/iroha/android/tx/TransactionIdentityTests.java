// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.android.tx;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.hyperledger.iroha.android.address.AccountAddress;
import org.hyperledger.iroha.android.model.FeePaymentIntent;
import org.hyperledger.iroha.android.model.JsonValue;
import org.hyperledger.iroha.android.model.TransactionPayload;
import org.hyperledger.iroha.android.model.instructions.ProofAttachment;
import org.hyperledger.iroha.android.model.instructions.ProofVerifierKeyRef;
import org.hyperledger.iroha.android.norito.NoritoException;
import org.hyperledger.iroha.android.norito.NoritoJavaCodecAdapter;
import org.hyperledger.iroha.android.norito.SignedTransactionEncoder;
import org.hyperledger.iroha.android.testing.TestAccountIds;
import org.hyperledger.iroha.norito.NoritoCodec;
import org.hyperledger.iroha.norito.NoritoDecoder;
import org.junit.Test;

/** First-release transaction wire and canonical identity regression coverage. */
public final class TransactionIdentityTests {
  private static final NoritoJavaCodecAdapter CODEC =
      new NoritoJavaCodecAdapter(AccountAddress.DEFAULT_I105_DISCRIMINANT);

  @Test
  public void authorizationProofChangesDoNotChangeTransactionIdentity() throws Exception {
    final byte[] encodedPayload = CODEC.encodeTransaction(samplePayload(Collections.emptyMap(), null));
    final SignedTransaction first = signed(encodedPayload, (byte) 0x11);
    final SignedTransaction second = signed(encodedPayload, (byte) 0x22);

    assertFalse(
        "Authorization proof must remain part of the submission wire",
        Arrays.equals(
            SignedTransactionEncoder.encode(first), SignedTransactionEncoder.encode(second)));
    assertEquals(
        "Authorization proof changes must not create a second transaction identity",
        SignedTransactionHasher.hashHex(first),
        SignedTransactionHasher.hashHex(second));
    assertArrayEquals(
        SignedTransactionHasher.canonicalBytes(first),
        SignedTransactionHasher.canonicalBytes(second));
  }

  @Test
  public void payloadAndProofAttachmentChangesAlterTransactionIdentity() throws Exception {
    final SignedTransaction base =
        signed(CODEC.encodeTransaction(samplePayload(Collections.emptyMap(), null)), (byte) 0x33);
    final SignedTransaction changedMetadata =
        signed(
            CODEC.encodeTransaction(
                samplePayload(
                    Collections.singletonMap("purpose", JsonValue.string("changed")), null)),
            (byte) 0x33);
    final ProofAttachment attachment =
        new ProofAttachment(
            "halo2",
            new byte[] {0x01, 0x02, 0x03},
            new ProofVerifierKeyRef("halo2", "vk1"));

    assertNotEquals(
        SignedTransactionHasher.hashHex(base), SignedTransactionHasher.hashHex(changedMetadata));
    // The wire field is SignedAttachmentsV1, which this codec does not implement: a payload with
    // attachments is refused instead of being encoded in the retired list layout.
    try {
      CODEC.encodeTransaction(
          samplePayload(Collections.emptyMap(), Collections.singletonList(attachment)));
      throw new AssertionError("a payload with attachments must be refused");
    } catch (final NoritoException refusal) {
      Throwable cause = refusal;
      while (cause.getCause() != null) {
        cause = cause.getCause();
      }
      assertEquals(
          true, String.valueOf(cause.getMessage()).contains("SignedAttachmentsV1"));
    }
  }

  @Test
  public void transactionWireFieldCountsMatchRustFirstReleaseLayout() throws Exception {
    final SignedTransaction transaction =
        signed(CODEC.encodeTransaction(samplePayload(Collections.emptyMap(), null)), (byte) 0x44);

    assertEquals(9, countSizedFields(transaction.encodedPayload()));
    assertEquals(3, countSizedFields(SignedTransactionEncoder.encode(transaction)));
  }

  private static TransactionPayload samplePayload(
      final Map<String, JsonValue> metadata, final List<ProofAttachment> attachments) {
    return TransactionPayload.builder()
        .setFeePayment(FeePaymentIntent.authority(Collections.emptyList(), 1L))
        .setNetworkId(org.hyperledger.iroha.android.testing.TestNetworkIds.fromSeed(1L))
        .setAuthority(TestAccountIds.ed25519Authority(0x2C))
        .setCreationTimeMs(1_735_369_000_000L)
        .setInstructionBytes(new byte[] {0x01, 0x02})
        .setMetadata(metadata)
        .setAttachments(attachments)
        .build();
  }

  private static SignedTransaction signed(
      final byte[] encodedPayload, final byte signatureSeed) {
    final byte[] signature = new byte[64];
    Arrays.fill(signature, signatureSeed);
    return new SignedTransaction(
        encodedPayload, signature, new byte[32], CODEC.schemaName());
  }

  private static int countSizedFields(final byte[] bytes) throws NoritoException {
    try {
      final NoritoDecoder decoder = new NoritoDecoder(bytes, NoritoCodec.DEFAULT_FLAGS);
      int count = 0;
      while (decoder.remaining() != 0) {
        final long length = decoder.readLength(decoder.compactLenActive());
        if (length > Integer.MAX_VALUE) {
          throw new IllegalArgumentException("field is too large");
        }
        decoder.readBytes((int) length);
        count++;
      }
      return count;
    } catch (final IllegalArgumentException ex) {
      throw new NoritoException("invalid sized-field layout", ex);
    }
  }
}
