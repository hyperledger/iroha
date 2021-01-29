package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.DomainName;

public class DomainNameReader implements ScaleReader<DomainName> {

  @Override
  public DomainName read(ScaleCodecReader reader) {
    return new DomainName(reader.readString());
  }

}
