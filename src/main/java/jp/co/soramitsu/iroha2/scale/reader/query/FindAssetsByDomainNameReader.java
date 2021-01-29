package jp.co.soramitsu.iroha2.scale.reader.query;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import jp.co.soramitsu.iroha2.model.query.FindAssetsByDomainName;

public class FindAssetsByDomainNameReader implements ScaleReader<FindAssetsByDomainName> {

  @Override
  public FindAssetsByDomainName read(ScaleCodecReader reader) {
    return new FindAssetsByDomainName(reader.readString());
  }
}
