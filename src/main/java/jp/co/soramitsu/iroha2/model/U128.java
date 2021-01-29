package jp.co.soramitsu.iroha2.model;

import java.math.BigInteger;
import lombok.Data;
import lombok.NonNull;

@Data
public class U128 {

  @NonNull
  private BigInteger value;
}
