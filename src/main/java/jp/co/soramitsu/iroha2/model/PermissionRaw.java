package jp.co.soramitsu.iroha2.model;

import lombok.Data;
import lombok.NonNull;

@Data
public class PermissionRaw {

  @NonNull
  private byte[] value;
}
