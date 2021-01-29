package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.UnionValue;
import jp.co.soramitsu.iroha2.model.Enumeration;

public class EnumerationUnionValue<T extends Enumeration> extends UnionValue<T> {

  public EnumerationUnionValue(T value) {
    super(value.getIndex(), value);
  }
}
