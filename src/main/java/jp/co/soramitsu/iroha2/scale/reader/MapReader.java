package jp.co.soramitsu.iroha2.scale.reader;

import io.emeraldpay.polkaj.scale.ScaleCodecReader;
import io.emeraldpay.polkaj.scale.ScaleReader;
import io.emeraldpay.polkaj.scale.reader.ListReader;
import java.util.AbstractMap.SimpleEntry;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

public class MapReader<K, V> implements ScaleReader<Map<K, V>> {

  private static class EntryReader<K, V> implements ScaleReader<Entry<K, V>> {

    private ScaleReader<K> keyReader;
    private ScaleReader<V> valueReader;

    public EntryReader(ScaleReader<K> keyReader, ScaleReader<V> valueReader) {
      this.keyReader = keyReader;
      this.valueReader = valueReader;
    }

    @Override
    public Entry<K, V> read(ScaleCodecReader reader) {
      return new SimpleEntry<>(reader.read(keyReader), reader.read(valueReader));
    }
  }

  private ListReader<Entry<K, V>> listReader;

  public MapReader(ScaleReader<K> keyReader, ScaleReader<V> valueReader) {
    listReader = new ListReader<>(new EntryReader<>(keyReader, valueReader));
  }

  @Override
  public Map<K, V> read(ScaleCodecReader reader) {
    return reader.read(listReader).stream()
        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
  }

}
