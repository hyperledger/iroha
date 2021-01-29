package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAccountsByDomainName;

public class FindAccountsByDomainNameReader implements ScaleReader<FindAccountsByDomainName> {

  @Override
  public FindAccountsByDomainName read(ScaleCodecReader reader) {
    return new FindAccountsByDomainName(reader.readString());
  }
}
