// Copyright 2026 Hyperledger Iroha Contributors
// SPDX-License-Identifier: Apache-2.0

package org.hyperledger.iroha.android.governance;

import android.content.Context;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import org.hyperledger.iroha.sdk.governance.ParliamentTimedOvnCastingTrustAnchorV1;
import org.hyperledger.iroha.sdk.governance.ParliamentTimedOvnPublicRecordV1;
import org.hyperledger.iroha.sdk.client.ParliamentTimedOvnCastingProofPageVerificationV1;

/**
 * Java Android facade for secret-local Parliament timed-OVN record generation.
 *
 * <p>The canonical implementation is the Kotlin {@code client-android} wallet. It generates the
 * 32-byte seed locally, persists only an AES-GCM envelope protected by a non-exportable
 * AndroidKeyStore key, verifies a consensus-authenticated proof against an immutable external
 * trust anchor before borrowing the seed for one ABI-29 JNI call, and returns only the fixed-width
 * public registration or masked-ballot record together with its authenticated promoted checkpoint.
 * This facade deliberately adds no raw seed
 * constructor, getter, serializer, logging path, global-network fallback, or software proof path.
 */
public final class ParliamentTimedOvnWalletV1 {
  /** Exact connect_norito_bridge ABI required by the first-release wallet boundary. */
  public static final int REQUIRED_BRIDGE_ABI_VERSION = 29;

  /** Maximum complete framed {@code ParliamentTimedOvnCastingProofResponseV1}. */
  public static final int MAXIMUM_CASTING_PROOF_RESPONSE_BYTES = 8 * 1024 * 1024;

  /** Exact native page-verification result width. */
  public static final int CASTING_PROOF_PAGE_VERIFICATION_BYTES = 41;

  /** Exact public registration-record width. */
  public static final int REGISTRATION_RECORD_BYTES = 3_624;

  /** Exact public masked-ballot width. */
  public static final int BALLOT_RECORD_BYTES = 2_858;

  private static final int MAXIMUM_AUTHORITY_BYTES = 8 * 1024;
  private static final int MAXIMUM_ALIAS_CHARS = 128;
  private static final String NATIVE_UNAVAILABLE_MESSAGE =
      "ABI-29 connect_norito_bridge with proof-gated Parliament wallet symbols is required";
  private static final String NATIVE_REJECTED_MESSAGE =
      "Parliament timed-OVN native wallet rejected the operation";

  private final Backend backend;

  private ParliamentTimedOvnWalletV1(final Backend backend) {
    this.backend = Objects.requireNonNull(backend, "backend");
  }

  /** Create the Java facade over the packaged Kotlin AndroidKeyStore/JNI implementation. */
  public static ParliamentTimedOvnWalletV1 production(final Context context) {
    final Context requiredContext = Objects.requireNonNull(context, "context");
    final Context applicationContext = requiredContext.getApplicationContext();
    return new ParliamentTimedOvnWalletV1(
        new KotlinBackend(
            org.hyperledger.iroha.sdk.governance.ParliamentTimedOvnWalletV1.production(
                applicationContext == null ? requiredContext : applicationContext)));
  }

  /** Whether the exact ABI-29 proof-gated native record builders are available. */
  public boolean isAvailable() {
    return backend.isAvailable();
  }

  /** Generate and persist one independently random AndroidKeyStore-protected seed. */
  public ParliamentTimedOvnSeedHandleV1 createSeedHandle(final String alias) {
    final String validatedAlias = validateAlias(alias);
    return new ParliamentTimedOvnSeedHandleV1(
        validatedAlias,
        Objects.requireNonNull(backend.createSeedHandle(validatedAlias), "seed handle"));
  }

  /** Reopen an existing opaque handle, or return {@code null} when it is absent. */
  public ParliamentTimedOvnSeedHandleV1 seedHandle(final String alias) {
    final String validatedAlias = validateAlias(alias);
    final Object handle = backend.seedHandle(validatedAlias);
    return handle == null ? null : new ParliamentTimedOvnSeedHandleV1(validatedAlias, handle);
  }

  /** Delete the encrypted seed referenced by {@code handle}. */
  public boolean deleteSeedHandle(final ParliamentTimedOvnSeedHandleV1 handle) {
    return backend.deleteSeedHandle(Objects.requireNonNull(handle, "handle").delegate());
  }

  /** Generate the exact public registration from one authenticated proof response. */
  public ParliamentTimedOvnPublicRecordV1 registrationFromProofV1(
      final byte[] castingProofResponseNorito,
      final ParliamentTimedOvnCastingTrustAnchorV1 trustAnchor,
      final String authority,
      final ParliamentTimedOvnSeedHandleV1 handle) {
    return publicRecord(castingProofResponseNorito, trustAnchor, authority, handle, null);
  }

  /** Generate one survivor-bound 2,858-byte public masked-ballot record. */
  public ParliamentTimedOvnPublicRecordV1 ballotFromProofV1(
      final byte[] castingProofResponseNorito,
      final ParliamentTimedOvnCastingTrustAnchorV1 trustAnchor,
      final String authority,
      final ParliamentTimedOvnSeedHandleV1 handle,
      final ParliamentTimedOvnBallotChoiceV1 choice) {
    return publicRecord(
        castingProofResponseNorito,
        trustAnchor,
        authority,
        handle,
        Objects.requireNonNull(choice, "choice"));
  }

  /** Authenticates one bounded proof page without opening a seed handle. */
  public ParliamentTimedOvnCastingProofPageVerificationV1 verifyCastingProofPageV1(
      final byte[] castingProofResponseNorito,
      final ParliamentTimedOvnCastingTrustAnchorV1 trustAnchor) {
    if (!backend.isAvailable()) {
      throw new IllegalStateException(NATIVE_UNAVAILABLE_MESSAGE);
    }
    final byte[] proof =
        Objects.requireNonNull(castingProofResponseNorito, "castingProofResponseNorito");
    if (proof.length == 0 || proof.length > MAXIMUM_CASTING_PROOF_RESPONSE_BYTES) {
      throw new IllegalArgumentException(
          "castingProofResponseNorito must contain 1.."
              + MAXIMUM_CASTING_PROOF_RESPONSE_BYTES
              + " bytes");
    }
    final byte[] proofCopy = proof.clone();
    try {
      final ParliamentTimedOvnCastingProofPageVerificationV1 verification =
          backend.verifyCastingProofPage(
              proofCopy,
              Objects.requireNonNull(trustAnchor, "trustAnchor"));
      if (verification == null) {
        throw new IllegalStateException(
            "Parliament timed-OVN casting-proof page was rejected");
      }
      return verification;
    } catch (final LinkageError error) {
      throw new IllegalStateException(NATIVE_UNAVAILABLE_MESSAGE);
    } catch (final IllegalStateException error) {
      throw error;
    } catch (final RuntimeException error) {
      throw new IllegalStateException(
          "Parliament timed-OVN casting-proof page was rejected");
    } finally {
      Arrays.fill(proofCopy, (byte) 0);
    }
  }

  private ParliamentTimedOvnPublicRecordV1 publicRecord(
      final byte[] castingProofResponseNorito,
      final ParliamentTimedOvnCastingTrustAnchorV1 trustAnchor,
      final String authority,
      final ParliamentTimedOvnSeedHandleV1 handle,
      final ParliamentTimedOvnBallotChoiceV1 choice) {
    if (!backend.isAvailable()) {
      throw new IllegalStateException(NATIVE_UNAVAILABLE_MESSAGE);
    }
    final byte[] proof =
        Objects.requireNonNull(castingProofResponseNorito, "castingProofResponseNorito");
    if (proof.length == 0 || proof.length > MAXIMUM_CASTING_PROOF_RESPONSE_BYTES) {
      throw new IllegalArgumentException(
          "castingProofResponseNorito must contain 1.."
              + MAXIMUM_CASTING_PROOF_RESPONSE_BYTES
              + " bytes");
    }
    final ParliamentTimedOvnCastingTrustAnchorV1 requiredTrustAnchor =
        Objects.requireNonNull(trustAnchor, "trustAnchor");
    final String requiredAuthority = Objects.requireNonNull(authority, "authority");
    final byte[] authorityBytes = requiredAuthority.getBytes(StandardCharsets.UTF_8);
    try {
      if (authorityBytes.length == 0 || authorityBytes.length > MAXIMUM_AUTHORITY_BYTES) {
        throw new IllegalArgumentException(
            "authority must contain 1.." + MAXIMUM_AUTHORITY_BYTES + " UTF-8 bytes");
      }
      for (final byte value : authorityBytes) {
        if (value == 0) {
          throw new IllegalArgumentException("authority must not contain NUL");
        }
      }
    } finally {
      Arrays.fill(authorityBytes, (byte) 0);
    }

    final Object opaqueHandle = Objects.requireNonNull(handle, "handle").delegate();
    final byte[] proofCopy = proof.clone();
    byte[] record = null;
    try {
      final ParliamentTimedOvnPublicRecordV1 output =
          choice == null
              ? backend.registration(
                  proofCopy, requiredTrustAnchor, requiredAuthority, opaqueHandle)
              : backend.ballot(
                  proofCopy, requiredTrustAnchor, requiredAuthority, opaqueHandle, choice);
      if (output == null) {
        throw new IllegalStateException(NATIVE_REJECTED_MESSAGE);
      }
      final int expectedBytes =
          choice == null ? REGISTRATION_RECORD_BYTES : BALLOT_RECORD_BYTES;
      record = output.record();
      if (record.length != expectedBytes) {
        throw new IllegalStateException(
            "Parliament timed-OVN native wallet returned a noncanonical public record");
      }
      return output;
    } catch (final LinkageError | RuntimeException error) {
      if (error instanceof IllegalStateException
          && (NATIVE_REJECTED_MESSAGE.equals(error.getMessage())
              || "Parliament timed-OVN native wallet returned a noncanonical public record"
                  .equals(error.getMessage()))) {
        throw (IllegalStateException) error;
      }
      throw new IllegalStateException(NATIVE_REJECTED_MESSAGE);
    } finally {
      Arrays.fill(proofCopy, (byte) 0);
      if (record != null) {
        Arrays.fill(record, (byte) 0);
      }
    }
  }

  private static String validateAlias(final String alias) {
    final String requiredAlias = Objects.requireNonNull(alias, "alias");
    boolean hasNonWhitespace = false;
    for (int index = 0; index < requiredAlias.length(); index++) {
      final char value = requiredAlias.charAt(index);
      if (value == 0) {
        throw new IllegalArgumentException(
            "seed handle alias must contain 1.." + MAXIMUM_ALIAS_CHARS + " non-NUL characters");
      }
      hasNonWhitespace |= !Character.isWhitespace(value);
    }
    if (!hasNonWhitespace || requiredAlias.length() > MAXIMUM_ALIAS_CHARS) {
      throw new IllegalArgumentException(
          "seed handle alias must contain 1.." + MAXIMUM_ALIAS_CHARS + " non-NUL characters");
    }
    return requiredAlias;
  }

  interface Backend {
    boolean isAvailable();

    Object createSeedHandle(String alias);

    Object seedHandle(String alias);

    boolean deleteSeedHandle(Object handle);

    default ParliamentTimedOvnCastingProofPageVerificationV1 verifyCastingProofPage(
        final byte[] proofResponse,
        final ParliamentTimedOvnCastingTrustAnchorV1 trustAnchor) {
      return null;
    }

    ParliamentTimedOvnPublicRecordV1 registration(
        byte[] proofResponse,
        ParliamentTimedOvnCastingTrustAnchorV1 trustAnchor,
        String authority,
        Object handle);

    ParliamentTimedOvnPublicRecordV1 ballot(
        byte[] proofResponse,
        ParliamentTimedOvnCastingTrustAnchorV1 trustAnchor,
        String authority,
        Object handle,
        ParliamentTimedOvnBallotChoiceV1 choice);
  }

  static ParliamentTimedOvnWalletV1 withBackendForTests(final Backend backend) {
    return new ParliamentTimedOvnWalletV1(backend);
  }

  private static final class KotlinBackend implements Backend {
    private final org.hyperledger.iroha.sdk.governance.ParliamentTimedOvnWalletV1 delegate;

    private KotlinBackend(
        final org.hyperledger.iroha.sdk.governance.ParliamentTimedOvnWalletV1 delegate) {
      this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    @Override
    public boolean isAvailable() {
      return delegate.isAvailable();
    }

    @Override
    public Object createSeedHandle(final String alias) {
      return delegate.createSeedHandle(alias);
    }

    @Override
    public Object seedHandle(final String alias) {
      return delegate.seedHandle(alias);
    }

    @Override
    public boolean deleteSeedHandle(final Object handle) {
      return delegate.deleteSeedHandle(kotlinHandle(handle));
    }

    @Override
    public ParliamentTimedOvnCastingProofPageVerificationV1 verifyCastingProofPage(
        final byte[] proofResponse,
        final ParliamentTimedOvnCastingTrustAnchorV1 trustAnchor) {
      return delegate.verifyCastingProofPageV1(proofResponse, trustAnchor);
    }

    @Override
    public ParliamentTimedOvnPublicRecordV1 registration(
        final byte[] proofResponse,
        final ParliamentTimedOvnCastingTrustAnchorV1 trustAnchor,
        final String authority,
        final Object handle) {
      return delegate.registrationFromProofV1(
          proofResponse, trustAnchor, authority, kotlinHandle(handle));
    }

    @Override
    public ParliamentTimedOvnPublicRecordV1 ballot(
        final byte[] proofResponse,
        final ParliamentTimedOvnCastingTrustAnchorV1 trustAnchor,
        final String authority,
        final Object handle,
        final ParliamentTimedOvnBallotChoiceV1 choice) {
      return delegate.ballotFromProofV1(
          proofResponse,
          trustAnchor,
          authority,
          kotlinHandle(handle),
          org.hyperledger.iroha.sdk.governance.ParliamentTimedOvnBallotChoiceV1.valueOf(
              choice.name()));
    }

    private static org.hyperledger.iroha.sdk.governance.ParliamentTimedOvnSeedHandleV1
        kotlinHandle(final Object handle) {
      return (org.hyperledger.iroha.sdk.governance.ParliamentTimedOvnSeedHandleV1)
          Objects.requireNonNull(handle, "handle");
    }
  }
}
