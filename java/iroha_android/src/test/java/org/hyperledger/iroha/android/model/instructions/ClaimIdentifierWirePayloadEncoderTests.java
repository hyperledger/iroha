package org.hyperledger.iroha.android.model.instructions;

import java.util.Locale;
import org.hyperledger.iroha.android.address.AccountAddress;
import org.hyperledger.iroha.android.address.PublicKeyCodec;
import org.hyperledger.iroha.sdk.client.IdentifierOwnerInputV1;
import org.hyperledger.iroha.sdk.client.IdentifierReceiptAttestation;
import org.hyperledger.iroha.sdk.client.IdentifierReceiptCanonicalEncoder;
import org.hyperledger.iroha.sdk.client.IdentifierResolutionExecutionPayload;
import org.hyperledger.iroha.sdk.client.IdentifierResolutionPayload;
import org.hyperledger.iroha.sdk.client.IdentifierResolutionReceipt;
import org.hyperledger.iroha.sdk.client.RamLfeOutputOpening;
import org.hyperledger.iroha.sdk.client.RamLfeOutputOpeningPayload;
import org.hyperledger.iroha.sdk.core.model.InstructionBox;
import org.hyperledger.iroha.sdk.core.model.NetworkId;
import org.hyperledger.iroha.sdk.core.model.instructions.ClaimIdentifierWirePayloadEncoder;
import org.hyperledger.iroha.android.test.FixtureGeneratorRunner;
import org.hyperledger.iroha.norito.CRC64;
import org.hyperledger.iroha.norito.NoritoDecoder;
import org.hyperledger.iroha.norito.NoritoHeader;

public final class ClaimIdentifierWirePayloadEncoderTests {
  private static final String ACCOUNT_ID = canonicalAccountId();
  private static final String PARITY_ACCOUNT_MULTIHASH =
      "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03";
  private static final String PARITY_SIGNATURE_HEX = "CD".repeat(64);
  private static final String PARITY_HASH_HEX =
      "C6A23EC291940DF33EF948BCE1DF0FC42B8108661529A4E4CD6E084D3BD944C3";
  private static final NetworkId NETWORK_ID =
      NetworkId.parse("hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0");

  public static void main(String[] args) throws Exception {
    claimIdentifierEncodesExpectedWirePayload();
    claimIdentifierMatchesRustCanonicalFixture();
    claimIdentifierRejectsAccountMismatchBeforeEncoding();
    claimIdentifierDecoderRejectsTrailingPayloadBytes();
    claimIdentifierDecoderRejectsEmptyAccountPayload();
    claimIdentifierRejectsPhoneRetailWithoutCanonicalityEvidence();
    printClaimIdentifierWirePayloadHex();
  }

  private static void claimIdentifierEncodesExpectedWirePayload() {
    final IdentifierResolutionReceipt receipt = sampleReceipt(ACCOUNT_ID, "A1B2C3D4");

    final InstructionBox instruction = ClaimIdentifierWirePayloadEncoder.encode(ACCOUNT_ID, receipt);
    assert ClaimIdentifierWirePayloadEncoder.WIRE_NAME.equals(instruction.getName())
        : "ClaimIdentifier wire name mismatch";
    assert instruction.getPayload() instanceof org.hyperledger.iroha.sdk.core.model.WirePayload
        : "ClaimIdentifier must use a wire payload";

    final org.hyperledger.iroha.sdk.core.model.WirePayload wirePayload = (org.hyperledger.iroha.sdk.core.model.WirePayload) instruction.getPayload();
    final NoritoHeader.DecodeResult decoded =
        NoritoHeader.decode(wirePayload.getPayloadBytes(), null);
    decoded.header().validateChecksum(decoded.payload());

    final NoritoDecoder claimDecoder = new NoritoDecoder(decoded.payload(), decoded.header().flags());
    final byte[] encodedAccount = readSizedField(claimDecoder);
    final byte[] encodedReceipt = readSizedField(claimDecoder);
    assert claimDecoder.remaining() == 0 : "ClaimIdentifier must not contain trailing bytes";
    assert java.util.Arrays.equals(
            encodedAccount, TransferWirePayloadEncoder.encodeAccountIdPayload(ACCOUNT_ID))
        : "AccountId field mismatch";

    final NoritoDecoder receiptDecoder = new NoritoDecoder(encodedReceipt, decoded.header().flags());
    final byte[] embeddedPayload = readSizedField(receiptDecoder);
    final byte[] embeddedAttestation = readSizedField(receiptDecoder);
    final byte[] absentPhoneCanonicality = readSizedField(receiptDecoder);
    assert java.util.Arrays.equals(new byte[] {0}, absentPhoneCanonicality)
        : "Receipt must encode the mandatory absent phone-retail canonicality option";
    assert receiptDecoder.remaining() == 0 : "Receipt payload must not contain trailing bytes";
    assert java.util.Arrays.equals(
            embeddedPayload, IdentifierReceiptCanonicalEncoder.encodePayload(receipt.payload))
        : "Receipt payload bytes mismatch";
    assert java.util.Arrays.equals(
            embeddedAttestation,
            IdentifierReceiptCanonicalEncoder.encodeAttestation(receipt.attestation))
        : "Receipt attestation bytes mismatch";

    final ClaimIdentifierWirePayloadEncoder.DecodedClaimIdentifierPayload roundTrip =
        ClaimIdentifierWirePayloadEncoder.decodePayload(
            wirePayload.getPayloadBytes(), AccountAddress.DEFAULT_I105_DISCRIMINANT);
    assert ACCOUNT_ID.equals(roundTrip.getAccountId()) : "decoded ClaimIdentifier account mismatch";
    assert java.util.Arrays.equals(embeddedPayload, roundTrip.getReceiptPayloadBytes())
        : "decoded ClaimIdentifier receipt payload mismatch";
    assert java.util.Arrays.equals(embeddedAttestation, roundTrip.getAttestationPayloadBytes())
        : "decoded ClaimIdentifier attestation mismatch";
    roundTrip.getReceiptPayloadBytes()[0] ^= 1;
    roundTrip.getAttestationPayloadBytes()[0] ^= 1;
    assert java.util.Arrays.equals(embeddedPayload, roundTrip.getReceiptPayloadBytes())
        : "decoded ClaimIdentifier receipt payload must preserve owned bytes";
    assert java.util.Arrays.equals(embeddedAttestation, roundTrip.getAttestationPayloadBytes())
        : "decoded ClaimIdentifier attestation must preserve owned bytes";
  }

  private static void printClaimIdentifierWirePayloadHex() {
    final IdentifierResolutionReceipt receipt = sampleReceipt(ACCOUNT_ID, "AB".repeat(64));

    final InstructionBox instruction = ClaimIdentifierWirePayloadEncoder.encode(ACCOUNT_ID, receipt);
    final org.hyperledger.iroha.sdk.core.model.WirePayload wirePayload = (org.hyperledger.iroha.sdk.core.model.WirePayload) instruction.getPayload();
    final NoritoHeader.DecodeResult decoded =
        NoritoHeader.decode(wirePayload.getPayloadBytes(), null);
    decoded.header().validateChecksum(decoded.payload());

    System.out.println("JAVA_CLAIM_WIRE_NAME=" + instruction.getName());
    System.out.println("JAVA_CLAIM_BARE_HEX=" + toHex(decoded.payload()));
    System.out.println("JAVA_CLAIM_FRAMED_HEX=" + toHex(wirePayload.getPayloadBytes()));
  }

  private static void claimIdentifierMatchesRustCanonicalFixture() throws Exception {
    final java.util.List<String> lines = FixtureGeneratorRunner.run("claim-identifier");
    final String rustFramedHex = lines.get(0).toUpperCase(Locale.ROOT);
    final String liveAccountId = canonicalI105AccountId(PARITY_ACCOUNT_MULTIHASH);
    final IdentifierResolutionPayload payload =
        new IdentifierResolutionPayload(
            IdentifierOwnerInputV1.INSTANCE.rawNetworkId(lines.get(4)),
            "email#retail",
            new IdentifierResolutionExecutionPayload(
                "parity_test",
                PARITY_HASH_HEX,
                "hkdf-sha3-512-prf-v1",
                "signed",
                PARITY_HASH_HEX,
                PARITY_HASH_HEX,
                PARITY_HASH_HEX,
                PARITY_HASH_HEX,
                PARITY_HASH_HEX,
                PARITY_HASH_HEX,
                1_735_000_000_000L,
                1_735_000_120_000L),
            parityOpening(),
            "opaque:" + PARITY_HASH_HEX,
            PARITY_HASH_HEX,
            "uaid:" + PARITY_HASH_HEX.toLowerCase(Locale.ROOT),
            liveAccountId);
    final IdentifierResolutionReceipt receipt =
        new IdentifierResolutionReceipt(
            payload,
            new IdentifierReceiptAttestation("signed", PARITY_SIGNATURE_HEX, null, null),
            null);

    final InstructionBox instruction =
        ClaimIdentifierWirePayloadEncoder.encode(liveAccountId, receipt);
    final org.hyperledger.iroha.sdk.core.model.WirePayload wirePayload = (org.hyperledger.iroha.sdk.core.model.WirePayload) instruction.getPayload();
    final NoritoHeader.DecodeResult decoded =
        NoritoHeader.decode(wirePayload.getPayloadBytes(), null);
    decoded.header().validateChecksum(decoded.payload());

    assert ClaimIdentifierWirePayloadEncoder.WIRE_NAME.equals(instruction.getName())
        : "ClaimIdentifier parity wire name mismatch";
    final String actualFramedHex = toHex(wirePayload.getPayloadBytes());
    assert rustFramedHex.equals(actualFramedHex)
        : "ClaimIdentifier parity framed payload drifted from Rust\nexpected="
            + rustFramedHex
            + "\nactual="
            + actualFramedHex;
  }

  private static void claimIdentifierRejectsAccountMismatchBeforeEncoding() {
    final IdentifierResolutionReceipt receipt = sampleReceipt(ACCOUNT_ID, "A1B2C3D4");

    boolean threw = false;
    try {
      ClaimIdentifierWirePayloadEncoder.encode(ACCOUNT_ID + "x", receipt);
    } catch (final IllegalArgumentException ex) {
      threw =
          ex.getMessage() != null
              && ex.getMessage().contains("ClaimIdentifier accountId must match receipt.accountId");
    }
    assert threw : "mismatched ClaimIdentifier account must fail before encoding";

    threw = false;
    try {
      ClaimIdentifierWirePayloadEncoder.encode(" " + ACCOUNT_ID + " ", receipt);
    } catch (final IllegalArgumentException ex) {
      threw =
          ex.getMessage() != null
              && ex.getMessage().contains("accountId must not contain surrounding whitespace");
    }
    assert threw : "padded ClaimIdentifier account must fail before encoding";
  }

  private static void claimIdentifierDecoderRejectsTrailingPayloadBytes() {
    final InstructionBox instruction =
        ClaimIdentifierWirePayloadEncoder.encode(ACCOUNT_ID, sampleReceipt(ACCOUNT_ID, "A1B2C3D4"));
    final org.hyperledger.iroha.sdk.core.model.WirePayload wirePayload = (org.hyperledger.iroha.sdk.core.model.WirePayload) instruction.getPayload();
    final NoritoHeader.DecodeResult decoded =
        NoritoHeader.decode(wirePayload.getPayloadBytes(), null);
    decoded.header().validateChecksum(decoded.payload());
    final byte[] mutated = java.util.Arrays.copyOf(decoded.payload(), decoded.payload().length + 1);

    boolean threw = false;
    try {
      ClaimIdentifierWirePayloadEncoder.decodePayload(
          reframe(decoded.header(), mutated), AccountAddress.DEFAULT_I105_DISCRIMINANT);
    } catch (final IllegalArgumentException ex) {
      threw = ex.getMessage() != null && ex.getMessage().contains("Trailing bytes");
    }
    assert threw : "ClaimIdentifier decoder must reject trailing payload bytes";
  }

  private static void claimIdentifierDecoderRejectsEmptyAccountPayload() {
    final InstructionBox instruction =
        ClaimIdentifierWirePayloadEncoder.encode(ACCOUNT_ID, sampleReceipt(ACCOUNT_ID, "A1B2C3D4"));
    final org.hyperledger.iroha.sdk.core.model.WirePayload wirePayload = (org.hyperledger.iroha.sdk.core.model.WirePayload) instruction.getPayload();
    final NoritoHeader.DecodeResult decoded =
        NoritoHeader.decode(wirePayload.getPayloadBytes(), null);
    decoded.header().validateChecksum(decoded.payload());
    final byte[] mutated = decoded.payload().clone();
    mutated[0] = 0;

    boolean threw = false;
    try {
      ClaimIdentifierWirePayloadEncoder.decodePayload(
          reframe(decoded.header(), mutated), AccountAddress.DEFAULT_I105_DISCRIMINANT);
    } catch (final IllegalArgumentException ex) {
      threw = ex.getMessage() != null && ex.getMessage().contains("payload bytes must not be empty");
    }
    assert threw : "ClaimIdentifier decoder must reject empty AccountId payloads";
  }

  private static void claimIdentifierRejectsPhoneRetailWithoutCanonicalityEvidence() {
    final IdentifierResolutionReceipt ordinary = sampleReceipt(ACCOUNT_ID, "A1B2C3D4");
    final IdentifierResolutionPayload source = ordinary.payload;
    final IdentifierResolutionReceipt phone =
        new IdentifierResolutionReceipt(
            new IdentifierResolutionPayload(
                source.networkId, "phone#retail", source.execution, source.opening,
                source.opaqueId, source.receiptHash, source.uaid, source.accountId),
            ordinary.attestation,
            null);
    boolean threw = false;
    try {
      ClaimIdentifierWirePayloadEncoder.encode(ACCOUNT_ID, phone);
    } catch (final IllegalArgumentException ex) {
      threw =
          ex.getMessage() != null
              && ex.getMessage().contains("original independent signed canonicality");
    }
    assert threw : "phone#retail claim without signed canonicality evidence must fail closed";
  }

  /** The Rust fixture's opening: one lease of exactly 120 s, as the owner input requires. */
  private static RamLfeOutputOpening parityOpening() {
    return new RamLfeOutputOpening(
        new RamLfeOutputOpeningPayload(
            "parity_test",
            PARITY_HASH_HEX,
            PARITY_HASH_HEX,
            PARITY_HASH_HEX,
            PARITY_HASH_HEX,
            PARITY_HASH_HEX,
            1_735_000_000_000L,
            1_735_000_120_000L),
        PARITY_SIGNATURE_HEX);
  }

  /** Current signed HKDF receipt; mirrors the Kotlin parity test's sample payload. */
  private static IdentifierResolutionReceipt sampleReceipt(
      final String accountId, final String signatureHex) {
    final IdentifierResolutionPayload payload =
        new IdentifierResolutionPayload(
            NETWORK_ID,
            "email#retail",
            new IdentifierResolutionExecutionPayload(
                "identifier_lookup_retail",
                "11".repeat(32),
                IdentifierOwnerInputV1.BACKEND,
                "signed",
                "aa".repeat(31) + "ab",
                "bb".repeat(32),
                "cc".repeat(31) + "cd",
                "dd".repeat(32),
                "22".repeat(31) + "23",
                "33".repeat(32),
                42L,
                142L),
            new RamLfeOutputOpening(
                new RamLfeOutputOpeningPayload(
                    "identifier_lookup_retail",
                    "ee".repeat(31) + "ef",
                    "ee".repeat(31) + "ef",
                    "ee".repeat(31) + "ef",
                    "ee".repeat(31) + "ef",
                    "ee".repeat(31) + "ef",
                    84L,
                    184L),
                signatureHex),
            "opaque:" + "44".repeat(31) + "45",
            "55".repeat(32),
            "uaid:" + "66".repeat(31) + "67",
            accountId);
    return new IdentifierResolutionReceipt(
        payload, new IdentifierReceiptAttestation("signed", signatureHex, null, null), null);
  }

  private static byte[] readSizedField(final NoritoDecoder decoder) {
    final long length = decoder.readLength(decoder.compactLenActive());
    return decoder.readBytes(Math.toIntExact(length));
  }

  private static String toHex(final byte[] value) {
    final StringBuilder out = new StringBuilder(value.length * 2);
    for (final byte current : value) {
      out.append(String.format("%02X", current));
    }
    return out.toString();
  }

  private static byte[] reframe(final NoritoHeader header, final byte[] payload) {
    final NoritoHeader reframed =
        new NoritoHeader(
            header.schemaHash(),
            payload.length,
            CRC64.compute(payload),
            header.flags(),
            NoritoHeader.COMPRESSION_NONE,
            header.minor());
    final byte[] headerBytes = reframed.encode();
    final byte[] out = new byte[headerBytes.length + payload.length];
    System.arraycopy(headerBytes, 0, out, 0, headerBytes.length);
    System.arraycopy(payload, 0, out, headerBytes.length, payload.length);
    return out;
  }

  private static String canonicalAccountId() {
    return canonicalI105AccountId(
        "ed0120CE7FA46C9DCE7EA4B125E2E36BDB63EA33073E7590AC92816AE1E861B7048B03");
  }

  private static String canonicalI105AccountId(final String multihash) {
    final PublicKeyCodec.PublicKeyPayload payload =
        PublicKeyCodec.decodePublicKeyLiteral(multihash);
    if (payload == null) {
      throw new IllegalStateException("expected valid ED25519 fixture");
    }
    try {
      return AccountAddress.fromAccount(
              payload.keyBytes(), PublicKeyCodec.algorithmForCurveId(payload.curveId()))
          .toI105(AccountAddress.DEFAULT_I105_DISCRIMINANT);
    } catch (final Exception ex) {
      throw new IllegalStateException("failed to build canonical account fixture", ex);
    }
  }
}
