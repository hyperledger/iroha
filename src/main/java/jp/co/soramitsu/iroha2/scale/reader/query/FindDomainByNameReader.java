package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindDomainByName;

public class FindDomainByNameReader implements ScaleReader<FindDomainByName> {

  @Override
  public FindDomainByName read(ScaleCodecReader reader) {
    return new FindDomainByName(reader.readString());
  }
}
