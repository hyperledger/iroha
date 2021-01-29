package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAccountsByName;

public class FindAccountsByNameReader implements ScaleReader<FindAccountsByName> {

  @Override
  public FindAccountsByName read(ScaleCodecReader reader) {
    return new FindAccountsByName(reader.readString());
  }
}
