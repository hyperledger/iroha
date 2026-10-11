package org.hyperledger.iroha.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Java consumers use the Kotlin-owned exact nominal manifest parser and immutable models. */
final class ContractManifestJavaConsumerTest {
  private static final class ManifestFixture {
    final ContractManifest manifest;
    ManifestFixture(ContractManifest manifest) { this.manifest = manifest; }
  }

  @SuppressWarnings("unchecked")
  private static ManifestFixture parseManifestFixture(byte[] bytes) {
    java.util.Map<String, Object> root = (java.util.Map<String, Object>) JsonParser.parse(new String(bytes, StandardCharsets.UTF_8));
    return new ManifestFixture(ContractManifestJsonParser.parseManifest((java.util.Map<String, Object>) root.get("manifest")));
  }

  @Test
  void assetDefinitionPrecisionUsesTheKotlinOwnedSevenFieldSchema() {
    String prefix = "{\"kind\":\"Struct\",\"value\":{\"name\":\"kotodama::AssetDefinitionView\","
        + "\"fields\":[\"id\",\"name\",\"description\",\"owned_by\",\"total_quantity\",\"numeric_scale\",\"metadata\"]}},";
    String option = "{\"kind\":\"Option\",\"value\":null},";
    String children = leaf("AssetDefinitionId") + "," + leaf("String") + ","
        + option + leaf("String") + "," + leaf("AccountId") + "," + leaf("Quantity") + ",";
    String nodes = prefix + children + option + leaf("Int") + "," + leaf("Json");
    EntrypointValueTypeV1 schema = parseDefinitionSchema(nodes);
    assertEquals("AssetDefinitionView", schema.canonicalTypeName);
    assertEquals(10, schema.nodes.size());
    assertEquals(7, schema.wordCount);
    assertEquals(EntrypointValueTypeNodeKindV1.OPTION, schema.nodes.get(7).kind);
    assertEquals(EntrypointValueKindV1.INT, schema.nodes.get(8).leafKind);
    String retired = prefix.replace("\"numeric_scale\",", "") + children + leaf("Json");
    assertThrows(IllegalStateException.class, () -> parseDefinitionSchema(retired));
    assertThrows(IllegalStateException.class, () -> parseDefinitionSchema(
        prefix + children + leaf("Int") + "," + leaf("Json")));
    assertThrows(IllegalStateException.class, () -> parseDefinitionSchema(
        prefix + children + option + leaf("Decimal") + "," + leaf("Json")));
  }

  private static String leaf(String kind) {
    return "{\"kind\":\"Leaf\",\"value\":{\"kind\":\"" + kind + "\",\"value\":null}}";
  }

  private static EntrypointValueTypeV1 parseDefinitionSchema(String nodes) {
    String payload = "{\"manifest\":{\"permissions\":[],\"events\":[],\"enum_types\":[],\"entrypoints\":[{\"name\":\"inspect\","
        + "\"kind\":{\"kind\":\"View\",\"value\":null},\"authorization\":{\"kind\":\"Anyone\",\"value\":null},\"params\":[],"
        + "\"return_type\":\"AssetDefinitionView\",\"return_schema\":{\"nodes\":[" + nodes + "]}}]}}";
    return parseManifestFixture(payload.getBytes(StandardCharsets.UTF_8))
        .manifest.entrypoints.get(0).returnSchema;
  }

  @Test
  void sharedNominalErrorsPreserveJapaneseIdentityAndUnit() throws Exception {
    File directory = new File(".").getAbsoluteFile();
    File fixture = null;
    while (directory != null) {
      File candidate = new File(directory, "fixtures/kotodama/nominal_errors_v1.json");
      if (candidate.isFile()) { fixture = candidate; break; }
      directory = directory.getParentFile();
    }
    if (fixture == null) throw new AssertionError("missing shared nominal fixture");
    String payload = new String(Files.readAllBytes(fixture.toPath()), StandardCharsets.UTF_8);
    ContractManifest manifest = parseManifestFixture(payload.getBytes(StandardCharsets.UTF_8)).manifest;
    EntrypointValueTypeV1 schema = manifest.entrypoints.get(0).returnSchema;
    assertEquals("Result<(), example/vault@1.0.0::金庫::拒否>", schema.canonicalTypeName);
    assertEquals(EntrypointValueTypeNodeKindV1.UNIT, schema.nodes.get(1).kind);
    assertEquals("不足", schema.nodes.get(2).errorType.variants.get(0).name);
    assertEquals(2, manifest.errorTypes.size());
    EntrypointValueTypeV1 cursor = manifest.entrypoints.get(1).returnSchema;
    assertEquals("Option<StateCursor<int>>", cursor.canonicalTypeName);
    assertEquals(EntrypointValueTypeNodeKindV1.STATE_CURSOR, cursor.nodes.get(1).kind);
    assertEquals(EntrypointValueKindV1.INT, cursor.nodes.get(1).cursorKeySchema.nodes.get(0).leafKind);
    assertEquals(1, cursor.wordCount);
    assertEquals("StatePage<int, bool, 8>", manifest.entrypoints.get(2).returnSchema.canonicalTypeName);
    assertEquals(2, manifest.entrypoints.get(2).returnSchema.wordCount);
    assertThrows(UnsupportedOperationException.class, () -> manifest.errorTypes.clear());
    assertThrows(IllegalStateException.class, () -> parseManifestFixture(
        payload.replaceFirst("CapacityExceeded", "DifferentMeaning").getBytes(StandardCharsets.UTF_8)));
    String stateOnlyUnknown = payload.replace(
        "\"type_name\": \"Result<(), example/vault@1.0.0::金庫::拒否>\"",
        "\"type_name\": \"Result<(), missing/vault@1.0.0::金庫::拒否>\"");
    assertThrows(IllegalStateException.class, () -> parseManifestFixture(
        stateOnlyUnknown.getBytes(StandardCharsets.UTF_8)));
    for (String forged : new String[] {"kotodama::StatePage{anything: int}", "kotodama::StatePage{items: List<(int, bool), 8>, next: Option<StateCursor<bool>>}"}) {
      assertThrows(IllegalStateException.class, () -> parseManifestFixture(payload.replace(
          "kotodama::StatePage{items: List<(int, bool), 8>, next: Option<StateCursor<int>>}", forged).getBytes(StandardCharsets.UTF_8)));
    }
  }

  @Test
  void javaConsumerUsesTheV1CallTableWithoutTheRetiredRegisterWindow() {
    List<String> parameters = new ArrayList<>();
    List<String> fields = new ArrayList<>();
    List<String> resultNodes = new ArrayList<>();
    resultNodes.add("{\"kind\":\"Tuple\",\"value\":14}");
    String intNode = "{\"kind\":\"Leaf\",\"value\":{\"kind\":\"Int\",\"value\":null}}";
    for (int index = 0; index < 14; index++) {
      String name = "p" + index;
      parameters.add("{\"name\":\"" + name + "\",\"type_name\":\"int\"}");
      fields.add("{\"name\":\"" + name + "\",\"ty\":{\"nodes\":[" + intNode + "]}}");
      resultNodes.add(intNode);
    }
    String tupleType = "(" + String.join(", ", Collections.nCopies(14, "int")) + ")";
    String payload = "{\"manifest\":{\"permissions\":[],\"events\":[],\"enum_types\":[],\"entrypoints\":[{\"name\":\"wide\",\"kind\":{\"kind\":\"View\",\"value\":null},\"authorization\":{\"kind\":\"Anyone\",\"value\":null},\"params\":["
        + String.join(",", parameters) + "],\"argument_schema\":{\"fields\":["
        + String.join(",", fields) + "]},\"return_type\":\"" + tupleType
        + "\",\"return_schema\":{\"nodes\":[" + String.join(",", resultNodes) + "]}}]}}";
    ContractEntrypointDescriptor entrypoint = parseManifestFixture(
        payload.getBytes(StandardCharsets.UTF_8)).manifest.entrypoints.get(0);
    assertEquals(14, entrypoint.parameters.size());
    assertEquals(14, entrypoint.argumentSchema.wordCount);
    assertEquals(14, entrypoint.returnSchema.wordCount);

    StringBuilder overLimitParameters = new StringBuilder(8_193 * 36);
    for (int index = 0; index < 8_193; index++) {
      if (index > 0) overLimitParameters.append(',');
      overLimitParameters.append("{\"name\":\"p").append(index).append("\",\"type_name\":\"int\"}");
    }
    String overLimit = "{\"manifest\":{\"permissions\":[],\"events\":[],\"enum_types\":[],\"entrypoints\":[{\"name\":\"wide\",\"kind\":{\"kind\":\"View\",\"value\":null},\"authorization\":{\"kind\":\"Anyone\",\"value\":null},\"params\":["
        + overLimitParameters + "],\"return_type\":\"()\",\"return_schema\":{\"nodes\":[{\"kind\":\"Unit\",\"value\":null}]}}]}}";
    IllegalStateException error = assertThrows(IllegalStateException.class, () ->
        parseManifestFixture(overLimit.getBytes(StandardCharsets.UTF_8)));
    assertTrue(error.getMessage().contains("V1 argument limit"));
  }

  @Test
  void javaConsumerUsesExactDynamicHintsAndEmptyProductGrammar() {
    String hint = "{\"base_key\":\"state:Balances\",\"key_type\":\"AccountId\","
        + "\"bound_kind\":\"take\",\"max_keys\":1}";
    String prefix = "{\"manifest\":{\"permissions\":[],\"events\":[],\"enum_types\":[],\"access_set_hints\":{\"read_keys\":[],\"write_keys\":[],"
        + "\"dynamic_reads\":[";
    String suffix = "],\"dynamic_writes\":[]},\"states\":[{\"name\":\"Balances\","
        + "\"type_name\":\"StateMap<AccountId, quantity>\"}]}}";
    ContractManifest manifest = parseManifestFixture(
        (prefix + hint + suffix).getBytes(StandardCharsets.UTF_8)).manifest;
    assertEquals("state:Balances", manifest.accessSetHints.dynamicReads.get(0).baseKey);
    assertEquals(1L, manifest.accessSetHints.dynamicReads.get(0).maxKeys);
    assertThrows(IllegalStateException.class, () -> parseManifestFixture(
        (prefix + hint + "," + hint + suffix).getBytes(StandardCharsets.UTF_8)));
    assertThrows(IllegalStateException.class, () -> parseManifestFixture(
        (prefix + hint.replace("state:Balances", "state:Missing") + suffix)
            .getBytes(StandardCharsets.UTF_8)));

    String statePrefix = "{\"manifest\":{\"permissions\":[],\"events\":[],\"enum_types\":[],\"states\":[{\"name\":\"Stored\",\"type_name\":\"";
    String stateSuffix = "\"}]}}";
    ContractManifest emptyProduct = parseManifestFixture(
        (statePrefix + "Fixture::Transfer{}" + stateSuffix).getBytes(StandardCharsets.UTF_8)).manifest;
    assertEquals("Fixture::Transfer{}", emptyProduct.states.get(0).typeName);
    assertThrows(IllegalStateException.class, () -> parseManifestFixture(
        (statePrefix + "Fixture::Transfer{ }" + stateSuffix).getBytes(StandardCharsets.UTF_8)));
  }
}
