package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.AccountId;

public class AccountIdReader implements ScaleReader<AccountId> {

  @Override
  public AccountId read(ScaleCodecReader reader) {
    return new AccountId(reader.readString(), reader.readString());
  }

}
