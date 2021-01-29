package jp.co.soramitsu.iroha2.model.query;

// 0 index in tagged-union
public class FindAllParameters implements Query {

  @Override
  public int getIndex() {
    return 18;
  }
}
