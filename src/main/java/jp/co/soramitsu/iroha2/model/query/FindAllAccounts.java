package jp.co.soramitsu.iroha2.model.query;

// 0 index in tagged-union
public class FindAllAccounts implements Query {

  @Override
  public int getIndex() {
    return 0;
  }
}
