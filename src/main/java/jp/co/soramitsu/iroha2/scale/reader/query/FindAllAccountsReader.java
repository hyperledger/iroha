package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAllAccounts;

public class FindAllAccountsReader implements ScaleReader<FindAllAccounts> {

  @Override
  public FindAllAccounts read(ScaleCodecReader scaleCodecReader) {
    return new FindAllAccounts();
  }
}
