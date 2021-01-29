package jp.co.soramitsu.iroha2.model;

public class U32 implements ValueBox {

  private long value;

  public U32(long value) {
    this.value = value;
  }

  @Override
  public int getIndex() {
    return 0;
  }

  public long getValue() {
    return value;
  }

  public void setValue(long value) {
    this.value = value;
  }

  @Override
  public String toString() {
    return "U32{" +
        "value=" + value +
        '}';
  }
}
