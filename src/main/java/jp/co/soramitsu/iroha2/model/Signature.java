package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class Signature {

  @NonNull
  private PublicKey publicKey;
  @NonNull
  private byte[] signature;
}
