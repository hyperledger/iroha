package jp.co.soramitsu.iroha2.json.reader;

public interface JsonReader<T> {

  T read(String json);
}
