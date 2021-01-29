package jp.co.soramitsu.iroha2.scale.writer;

import io.emeraldpay.polkaj.scale.ScaleCodecWriter;
import io.emeraldpay.polkaj.scale.ScaleWriter;
import io.emeraldpay.polkaj.scale.writer.ListWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Map.Entry;

public class MapWriter<K, V> implements ScaleWriter<Map<K, V>> {

  private static class EntryWriter<K, V> implements ScaleWriter<Entry<K, V>> {

    private ScaleWriter<K> keyWriter;
    private ScaleWriter<V> valueWriter;

    public EntryWriter(ScaleWriter<K> keyWriter, ScaleWriter<V> valueWriter) {
      this.keyWriter = keyWriter;
      this.valueWriter = valueWriter;
    }

    public void write(ScaleCodecWriter writer, Entry<K, V> value) throws IOException {
      keyWriter.write(writer, value.getKey());
      valueWriter.write(writer, value.getValue());
    }
  }

  private ListWriter<Entry<K, V>> listWriter;

  public MapWriter(ScaleWriter<K> keyWriter, ScaleWriter<V> valueWriter) {
    listWriter = new ListWriter<>(new EntryWriter<K, V>(keyWriter, valueWriter));
  }

  public void write(ScaleCodecWriter writer, Map<K, V> value) throws IOException {
    listWriter.write(writer, new ArrayList<>(value.entrySet()));
  }

}
