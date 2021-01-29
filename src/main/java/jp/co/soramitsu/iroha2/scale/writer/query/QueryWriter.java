package jp.co.soramitsu.iroha2.scale.writer.query;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.UnionWriter;
import java.io.IOException;
import jp.co.soramitsu.iroha2.model.query.Query;
import jp.co.soramitsu.iroha2.scale.writer.EnumerationUnionValue;
import jp.co.soramitsu.iroha2.scale.writer.NopWriter;

public class QueryWriter implements ScaleWriter<Query> {

  private static final NopWriter<Query> NOP_WRITER = new NopWriter<>();

  /**
   * Scale writers for queries, position in list must be an id in union value.
   */
  private static UnionWriter<Query> QUERY_WRITER = new UnionWriter<>(
      NOP_WRITER, // 0 FindAllAccounts
      new FindAccountByIdWriter(), // 1
      new FindAccountsByNameWriter(), // 2
      new FindAccountsByDomainNameWriter(), // 3
      NOP_WRITER, // 4 FindAllAssets
      NOP_WRITER, // 5 FindAllAssetsDefinitions
      new FindAssetByIdWriter(), // 6
      new FindAssetsByNameWriter(), // 7
      new FindAssetByAccountIdWriter(), // 8
      new FindAssetsByAssetDefinitionIdWriter(), // 9
      new FindAssetsByDomainNameWriter(), // 10
      new FindAssetsByAccountIdAndAssetDefinitionIdWriter(), // 11
      new FindAssetsByDomainNameAndAssetDefinitionIdWriter(), // 12
      new FindAssetQuantityByIdWriter(), // 13 FindAssetQuantityById
      NOP_WRITER, // 14 FindAllDomains
      new FindDomainByNameWriter(), // 15 FindDomainByName
      NOP_WRITER, // 16 FindAllPeers
      new FindPeerByIdWriter(), // 17 FindPeerById
      NOP_WRITER // 18 FindAllParameters
  );

  @Override
  public void write(ScaleCodecWriter writer, Query value) throws IOException {
    writer.write(QUERY_WRITER, new EnumerationUnionValue<>(value));
  }

}
