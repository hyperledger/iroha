package jp.co.soramitsu.iroha2.model;

public class Bool implements ValueBox {

  private boolean value;

  public Bool(boolean value) {
    this.value = value;
  }

  @Override
  public int getIndex() {
    return 1;
  }

  public boolean getValue() {
    return value;
  }

  public void setValue(boolean value) {
    this.value = value;
  }
}
