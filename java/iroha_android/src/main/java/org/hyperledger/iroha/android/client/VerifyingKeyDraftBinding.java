package org.hyperledger.iroha.android.client;

import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.hyperledger.iroha.android.address.AccountAddress;
import org.hyperledger.iroha.android.model.Executable;
import org.hyperledger.iroha.android.model.InstructionBox;
import org.hyperledger.iroha.android.model.NetworkId;
import org.hyperledger.iroha.android.model.TransactionPayload;
import org.hyperledger.iroha.android.model.zk.VerifyingKeyBackendTag;
import org.hyperledger.iroha.android.norito.NoritoJavaCodecAdapter;
import org.hyperledger.iroha.norito.NoritoAdapters;
import org.hyperledger.iroha.norito.NoritoCodec;
import org.hyperledger.iroha.norito.NoritoDecoder;
import org.hyperledger.iroha.norito.NoritoEncoder;
import org.hyperledger.iroha.norito.NoritoHeader;
import org.hyperledger.iroha.norito.TypeAdapter;

/** Exact transaction and instruction binding for unsigned verifying-key mutation drafts. */
final class VerifyingKeyDraftBinding {
  enum Operation {
    REGISTER(
        "iroha.instruction.v1::verifying_keys::RegisterVerifyingKey",
        "iroha_data_model::isi::verifying_keys::RegisterVerifyingKey"),
    UPDATE(
        "iroha.instruction.v1::verifying_keys::UpdateVerifyingKey",
        "iroha_data_model::isi::verifying_keys::UpdateVerifyingKey");

    private final String wireName;
    private final String schemaPath;

    Operation(final String wireName, final String schemaPath) {
      this.wireName = wireName;
      this.schemaPath = schemaPath;
    }

    String wireName() {
      return wireName;
    }

    String schemaPath() {
      return schemaPath;
    }
  }

  private static final long U32_MAX = 0xffff_ffffL;
  private static final String CORE_NAMESPACE = "core";
  private static final TypeAdapter<String> STRING = NoritoAdapters.stringAdapter();
  private static final TypeAdapter<byte[]> RAW_BYTES = NoritoAdapters.rawByteVecAdapter();
  private static final TypeAdapter<Optional<String>> OPTIONAL_STRING =
      NoritoAdapters.option(STRING);
  private static final TypeAdapter<Optional<Long>> OPTIONAL_U64 =
      NoritoAdapters.option(NoritoAdapters.uint(64));
  private static final TypeAdapter<Optional<ExpectedKey>> OPTIONAL_KEY =
      NoritoAdapters.option(new ExpectedKeyAdapter());
  private static final TypeAdapter<ExpectedInstruction> EXPECTED_INSTRUCTION_ADAPTER =
      new ExpectedInstructionAdapter();

  private VerifyingKeyDraftBinding() {}

  static void validate(
      final byte[] transactionPayload,
      final NetworkId expectedNetworkId,
      final Map<String, Object> request,
      final Operation operation) {
    java.util.Objects.requireNonNull(expectedNetworkId, "expectedNetworkId");
    final String authority = requiredString(request, "authority");
    final Integer discriminant = AccountAddress.detectI105Discriminant(authority);
    if (discriminant == null) {
      throw new IllegalArgumentException(
          "verifying-key draft request authority must be a canonical I105 account literal");
    }

    final TransactionPayload payload;
    try {
      payload = new NoritoJavaCodecAdapter(discriminant).decodeTransaction(transactionPayload);
    } catch (final Exception ex) {
      throw new IllegalArgumentException(
          "transaction_payload_b64 must contain one canonical transaction payload", ex);
    }
    if (!expectedNetworkId.equals(payload.networkId()) || !authority.equals(payload.authority())) {
      throw new IllegalArgumentException(
          "verifying-key draft transaction payload changed the requested network or authority");
    }
    final Executable executable = payload.executable();
    if (!executable.isInstructions()) {
      throw new IllegalArgumentException(
          "verifying-key draft transaction payload must contain native instructions");
    }
    final List<InstructionBox> instructions = executable.instructions();
    if (instructions.size() != 1) {
      throw new IllegalArgumentException(
          "verifying-key draft transaction payload must contain exactly one instruction");
    }
    if (!(instructions.get(0).payload() instanceof InstructionBox.WirePayload)) {
      throw new IllegalArgumentException(
          "verifying-key draft transaction payload must contain a wire-framed instruction");
    }
    final InstructionBox.WirePayload actual =
        (InstructionBox.WirePayload) instructions.get(0).payload();
    final InstructionBox.WirePayload expected =
        (InstructionBox.WirePayload) expectedInstruction(request, operation).payload();
    if (!actual.wireName().equals(expected.wireName())
        || !Arrays.equals(actual.payloadBytes(), expected.payloadBytes())) {
      throw new IllegalArgumentException(
          "verifying-key draft transaction payload does not contain the requested registry operation");
    }
  }

  static InstructionBox expectedInstruction(
      final Map<String, Object> request, final Operation operation) {
    final ExpectedInstruction expected = ExpectedInstruction.fromRequest(request);
    return InstructionBox.fromWirePayload(
        operation.wireName(),
        NoritoCodec.encode(
            expected, operation.schemaPath(), EXPECTED_INSTRUCTION_ADAPTER));
  }

  private static final class ExpectedInstruction {
    private final String backend;
    private final String name;
    private final long version;
    private final String circuitId;
    private final long backendTag;
    private final String curve;
    private final byte[] publicInputsSchemaHash;
    private final byte[] commitment;
    private final long verifyingKeyLength;
    private final long maxProofBytes;
    private final String gasScheduleId;
    private final String metadataUriCid;
    private final String verifyingKeyBytesCid;
    private final Long activationHeight;
    private final Long withdrawHeight;
    private final byte[] verifyingKeyBytes;
    private final long status;

    private ExpectedInstruction(
        final String backend,
        final String name,
        final long version,
        final String circuitId,
        final long backendTag,
        final String curve,
        final byte[] publicInputsSchemaHash,
        final byte[] commitment,
        final long verifyingKeyLength,
        final long maxProofBytes,
        final String gasScheduleId,
        final String metadataUriCid,
        final String verifyingKeyBytesCid,
        final Long activationHeight,
        final Long withdrawHeight,
        final byte[] verifyingKeyBytes,
        final long status) {
      this.backend = backend;
      this.name = name;
      this.version = version;
      this.circuitId = circuitId;
      this.backendTag = backendTag;
      this.curve = curve;
      this.publicInputsSchemaHash = publicInputsSchemaHash;
      this.commitment = commitment;
      this.verifyingKeyLength = verifyingKeyLength;
      this.maxProofBytes = maxProofBytes;
      this.gasScheduleId = gasScheduleId;
      this.metadataUriCid = metadataUriCid;
      this.verifyingKeyBytesCid = verifyingKeyBytesCid;
      this.activationHeight = activationHeight;
      this.withdrawHeight = withdrawHeight;
      this.verifyingKeyBytes = verifyingKeyBytes;
      this.status = status;
    }

    private static ExpectedInstruction fromRequest(final Map<String, Object> request) {
      final String backend = requiredString(request, "backend");
      final VerifyingKeyBackendTag resolved =
          VerifyingKeyBackendTag.verifierBackendRegistryTagV1(backend);
      if (resolved == null) {
        throw new IllegalArgumentException(
            "verifying-key draft request uses an unsupported backend");
      }
      final long backendTag =
          resolved == VerifyingKeyBackendTag.HALO2_IPA_PASTA ? 0L : 1L;
      final byte[] keyBytes = optionalCanonicalBase64(request, "vk_bytes");
      final byte[] commitment =
          keyBytes != null
              ? hex32(
                  HttpClientTransport.verifyingKeyCommitmentHex(backend, keyBytes),
                  "computed commitment")
              : hex32(requiredString(request, "commitment_hex"), "commitment_hex");
      final long keyLength =
          keyBytes != null
              ? keyBytes.length
              : requiredU32(request, "vk_len", true);
      final String statusText = optionalString(request, "status");
      final long status;
      if (statusText == null || "Active".equals(statusText)) {
        status = 1L;
      } else if ("Proposed".equals(statusText)) {
        status = 0L;
      } else if ("Withdrawn".equals(statusText)) {
        status = 2L;
      } else {
        throw new IllegalArgumentException(
            "verifying-key draft request uses an invalid status");
      }
      final String curve = optionalString(request, "curve");
      return new ExpectedInstruction(
          backend,
          requiredString(request, "name"),
          requiredU32(request, "version", true),
          requiredString(request, "circuit_id"),
          backendTag,
          curve == null ? "unknown" : curve,
          hex32(
              requiredString(request, "public_inputs_schema_hash_hex"),
              "public_inputs_schema_hash_hex"),
          commitment,
          keyLength,
          optionalU32(request, "max_proof_bytes", false, 0L),
          optionalString(request, "gas_schedule_id"),
          optionalString(request, "metadata_uri_cid"),
          optionalString(request, "vk_bytes_cid"),
          optionalU64(request, "activation_height"),
          optionalU64(request, "withdraw_height"),
          keyBytes,
          status);
    }
  }

  private static final class ExpectedInstructionAdapter
      implements TypeAdapter<ExpectedInstruction> {
    @Override
    public void encode(final NoritoEncoder encoder, final ExpectedInstruction value) {
      encodeSized(
          encoder,
          id -> {
            encodeSized(id, field -> STRING.encode(field, value.backend));
            encodeSized(id, field -> STRING.encode(field, value.name));
          });
      encodeSized(
          encoder,
          record -> {
            encodeSized(record, field -> field.writeUInt(value.version, 32));
            encodeSized(record, field -> STRING.encode(field, value.circuitId));
            encodeSized(record, field -> OPTIONAL_STRING.encode(field, Optional.empty()));
            encodeSized(record, field -> STRING.encode(field, CORE_NAMESPACE));
            encodeSized(record, field -> field.writeUInt(value.backendTag, 32));
            encodeSized(record, field -> STRING.encode(field, value.curve));
            encodeSized(record, field -> field.writeBytes(value.publicInputsSchemaHash));
            encodeSized(record, field -> field.writeBytes(value.commitment));
            encodeSized(record, field -> field.writeUInt(value.verifyingKeyLength, 32));
            encodeSized(record, field -> field.writeUInt(value.maxProofBytes, 32));
            encodeSized(
                record,
                field ->
                    OPTIONAL_STRING.encode(
                        field, Optional.ofNullable(value.gasScheduleId)));
            encodeSized(
                record,
                field ->
                    OPTIONAL_STRING.encode(
                        field, Optional.ofNullable(value.metadataUriCid)));
            encodeSized(
                record,
                field ->
                    OPTIONAL_STRING.encode(
                        field, Optional.ofNullable(value.verifyingKeyBytesCid)));
            encodeSized(
                record,
                field ->
                    OPTIONAL_U64.encode(
                        field, Optional.ofNullable(value.activationHeight)));
            encodeSized(
                record,
                field ->
                    OPTIONAL_U64.encode(
                        field, Optional.ofNullable(value.withdrawHeight)));
            encodeSized(
                record,
                field ->
                    OPTIONAL_KEY.encode(
                        field,
                        value.verifyingKeyBytes == null
                            ? Optional.empty()
                            : Optional.of(
                                new ExpectedKey(
                                    value.backend, value.verifyingKeyBytes))));
            encodeSized(record, field -> field.writeUInt(value.status, 32));
          });
    }

    @Override
    public ExpectedInstruction decode(final NoritoDecoder decoder) {
      throw new UnsupportedOperationException(
          "verifying-key expectation is encode-only");
    }
  }

  private static final class ExpectedKey {
    private final String backend;
    private final byte[] bytes;

    private ExpectedKey(final String backend, final byte[] bytes) {
      this.backend = backend;
      this.bytes = bytes;
    }
  }

  private static final class ExpectedKeyAdapter implements TypeAdapter<ExpectedKey> {
    @Override
    public void encode(final NoritoEncoder encoder, final ExpectedKey value) {
      encodeSized(encoder, field -> STRING.encode(field, value.backend));
      encodeSized(encoder, field -> RAW_BYTES.encode(field, value.bytes));
    }

    @Override
    public ExpectedKey decode(final NoritoDecoder decoder) {
      throw new UnsupportedOperationException(
          "verifying-key expectation is encode-only");
    }
  }

  private interface EncoderAction {
    void encode(NoritoEncoder encoder);
  }

  private static void encodeSized(
      final NoritoEncoder encoder, final EncoderAction action) {
    final NoritoEncoder child = encoder.childEncoder();
    action.encode(child);
    final byte[] bytes = child.toByteArray();
    encoder.writeLength(
        bytes.length, (encoder.flags() & NoritoHeader.COMPACT_LEN) != 0);
    encoder.writeBytes(bytes);
  }

  private static String requiredString(
      final Map<String, Object> request, final String field) {
    final Object value = request.get(field);
    if (!(value instanceof String)) {
      throw new IllegalArgumentException(
          "verifying-key draft request." + field + " must be a string");
    }
    return (String) value;
  }

  private static String optionalString(
      final Map<String, Object> request, final String field) {
    final Object value = request.get(field);
    if (value == null) {
      return null;
    }
    if (!(value instanceof String)) {
      throw new IllegalArgumentException(
          "verifying-key draft request." + field + " must be a string");
    }
    return (String) value;
  }

  private static long requiredU32(
      final Map<String, Object> request,
      final String field,
      final boolean positive) {
    final Object value = request.get(field);
    if (value == null) {
      throw new IllegalArgumentException(
          "verifying-key draft request." + field + " is required");
    }
    return checkedU32(value, field, positive);
  }

  private static long optionalU32(
      final Map<String, Object> request,
      final String field,
      final boolean positive,
      final long defaultValue) {
    final Object value = request.get(field);
    return value == null ? defaultValue : checkedU32(value, field, positive);
  }

  private static long checkedU32(
      final Object value, final String field, final boolean positive) {
    final long number = exactLong(value, field);
    if (number < (positive ? 1L : 0L) || number > U32_MAX) {
      throw new IllegalArgumentException(
          "verifying-key draft request." + field + " must fit in u32");
    }
    return number;
  }

  private static Long optionalU64(
      final Map<String, Object> request, final String field) {
    final Object value = request.get(field);
    if (value == null) {
      return null;
    }
    final long number = exactLong(value, field);
    if (number < 0L) {
      throw new IllegalArgumentException(
          "verifying-key draft request." + field + " must be a non-negative u64");
    }
    return number;
  }

  private static long exactLong(final Object value, final String field) {
    if (!(value instanceof Number)) {
      throw new IllegalArgumentException(
          "verifying-key draft request." + field + " must be an integer");
    }
    final long number = ((Number) value).longValue();
    if (!value.toString().equals(Long.toString(number))) {
      throw new IllegalArgumentException(
          "verifying-key draft request." + field + " must be an exact integer");
    }
    return number;
  }

  private static byte[] optionalCanonicalBase64(
      final Map<String, Object> request, final String field) {
    final String encoded = optionalString(request, field);
    if (encoded == null) {
      return null;
    }
    final byte[] bytes;
    try {
      bytes = Base64.getDecoder().decode(encoded);
    } catch (final IllegalArgumentException ex) {
      throw new IllegalArgumentException(
          "verifying-key draft request." + field + " must be canonical base64", ex);
    }
    if (bytes.length == 0
        || !Base64.getEncoder().encodeToString(bytes).equals(encoded)) {
      throw new IllegalArgumentException(
          "verifying-key draft request."
              + field
              + " must be canonical non-empty base64");
    }
    return bytes;
  }

  private static byte[] hex32(final String value, final String field) {
    if (value.length() != 64) {
      throw new IllegalArgumentException(
          "verifying-key draft request."
              + field
              + " must contain 64 lowercase hex characters");
    }
    final byte[] bytes = new byte[32];
    for (int index = 0; index < bytes.length; index++) {
      final char highChar = value.charAt(index * 2);
      final char lowChar = value.charAt(index * 2 + 1);
      final int high = Character.digit(highChar, 16);
      final int low = Character.digit(lowChar, 16);
      if (high < 0
          || low < 0
          || (highChar >= 'A' && highChar <= 'F')
          || (lowChar >= 'A' && lowChar <= 'F')) {
        throw new IllegalArgumentException(
            "verifying-key draft request."
                + field
                + " must contain 64 lowercase hex characters");
      }
      bytes[index] = (byte) ((high << 4) | low);
    }
    return bytes;
  }
}
