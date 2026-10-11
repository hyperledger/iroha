"use strict";
// Tokenizes Kotodama with the shipped TextMate grammar through the same engine VS Code
// uses. Run `KOTODAMA_UPDATE_SNAPSHOT=1 npm test` after an intentional grammar change.
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const oniguruma = require("vscode-oniguruma");
const textmate = require("vscode-textmate");

const root = path.resolve(__dirname, "..");
const grammarPath = path.join(root, "syntaxes", "kotodama.tmLanguage.json");
const samplesDirectory = path.resolve(root, "..", "samples");
const snapshotPath = path.join(root, "test", "grammar.snapshot.txt");

let grammarPromise;
function loadGrammar() {
  grammarPromise ??= (async () => {
    const wasm = fs.readFileSync(require.resolve("vscode-oniguruma/release/onig.wasm"));
    await oniguruma.loadWASM(wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength));
    const registry = new textmate.Registry({
      onigLib: Promise.resolve({
        createOnigScanner: patterns => new oniguruma.OnigScanner(patterns),
        createOnigString: text => new oniguruma.OnigString(text),
      }),
      loadGrammar: async scope => scope === "source.kotodama"
        ? textmate.parseRawGrammar(fs.readFileSync(grammarPath, "utf8"), grammarPath)
        : null,
    });
    return registry.loadGrammar("source.kotodama");
  })();
  return grammarPromise;
}

/** Non-whitespace tokens of `source` as `{ text, scope }`, where scope omits the root. */
async function tokenize(source) {
  const grammar = await loadGrammar();
  const tokens = [];
  let stack = textmate.INITIAL;
  for (const line of source.split("\n")) {
    const result = grammar.tokenizeLine(line, stack);
    for (const token of result.tokens) {
      const text = line.slice(token.startIndex, token.endIndex);
      if (!text.trim()) continue;
      tokens.push({ text: text.trim(), scope: token.scopes.slice(1).join(" ") || "-" });
    }
    stack = result.ruleStack;
  }
  return tokens;
}
function scopeOf(tokens, text, occurrence = 0) {
  const matches = tokens.filter(token => token.text === text);
  assert.ok(matches[occurrence], `no token ${JSON.stringify(text)} #${occurrence}`);
  return matches[occurrence].scope;
}

test("types, namespaces, sum variants and labels keep distinct scopes", async () => {
  const tokens = await tokenize([
    "seiyaku Demo {",
    "    kotoage fn pay(AccountId who) authorize(CanPay) {",
    "        let account = AccountId::parse(\"alice\");",
    "        let maybe = Option::some(1);",
    "        let mode = Rounding::floor;",
    "        let ready = true;",
    "        ledger::asset::transfer(source: account, amount: 1);",
    "        for index in 0..3 {}",
    "    }",
    "}",
  ].join("\n"));
  assert.equal(scopeOf(tokens, "AccountId", 1), "support.type.kotodama");
  assert.equal(scopeOf(tokens, "Option::some"), "support.constant.variant.kotodama");
  assert.equal(scopeOf(tokens, "Rounding::floor"), "support.constant.variant.rounding.kotodama");
  assert.equal(scopeOf(tokens, "ledger"), "-");
  assert.equal(scopeOf(tokens, "transfer"), "support.function.kotodama");
  assert.equal(scopeOf(tokens, "source"), "variable.parameter.named.kotodama");
  assert.equal(scopeOf(tokens, "true"), "constant.language.boolean.kotodama");
  assert.equal(scopeOf(tokens, "let"), "storage.type.kotodama");
  assert.equal(scopeOf(tokens, "for"), "keyword.control.kotodama");
  assert.equal(scopeOf(tokens, "authorize"), "storage.modifier.authorization.kotodama");
  assert.equal(scopeOf(tokens, "{"), "punctuation.section.braces.kotodama");
  assert.equal(scopeOf(tokens, ";"), "punctuation.terminator.statement.kotodama");
  assert.equal(scopeOf(tokens, "::"), "punctuation.separator.namespace.kotodama");
  assert.equal(scopeOf(tokens, ".."), "keyword.operator.kotodama");
  assert.equal(scopeOf(tokens, "="), "keyword.operator.kotodama");
});

test("conditional branches are values, not named labels", async () => {
  const tokens = await tokenize("        let quoted = ready ? amount : pick(a: 1, b: 2);");
  assert.equal(scopeOf(tokens, "amount"), "-");
  assert.equal(scopeOf(tokens, "a"), "variable.parameter.named.kotodama");
  assert.equal(scopeOf(tokens, "?"), "keyword.operator.kotodama");
});

test("both spellings of every branded keyword share one scope in every layout", async () => {
  const layouts = [
    keyword => `${keyword} Demo {\n}`,
    keyword => `    ${keyword} fn bump() authorize(P) {}`,
    keyword => `    ${keyword}\n    fn bump() authorize(P) {}`,
    keyword => `    ${keyword}() {}`,
    keyword => `        test::invoke_kotoage(${keyword}: "bump");`,
  ];
  const pairs = [["seiyaku", "誓約"], ["kotoage", "言挙げ"], ["hajimari", "始まり"], ["kaizen", "改善"]];
  for (const [romaji, kanji] of pairs) {
    for (const layout of layouts) {
      const romajiScope = scopeOf(await tokenize(layout(romaji)), romaji);
      const kanjiScope = scopeOf(await tokenize(layout(kanji)), kanji);
      assert.equal(kanjiScope, romajiScope, `${romaji}/${kanji} in ${JSON.stringify(layout("KEYWORD"))}`);
      assert.notEqual(romajiScope, "-");
    }
  }
});

test("trigger bodies highlight their contextual words only inside the trigger", async () => {
  const tokens = await tokenize([
    "    trigger settle -> sweep {",
    "        on pipeline block approved;",
    "        repeats indefinitely;",
    "        metadata {",
    "            tag: \"treasury\";",
    "        }",
    "    }",
    "    kotoage fn sweep() authorize(Admin) {",
    "        let block = 1;",
    "    }",
  ].join("\n"));
  for (const word of ["on", "pipeline", "approved", "repeats", "indefinitely", "metadata"]) {
    assert.equal(scopeOf(tokens, word), "meta.trigger.kotodama keyword.other.trigger.kotodama", word);
  }
  assert.equal(scopeOf(tokens, "settle"), "meta.trigger.kotodama entity.name.function.trigger.kotodama");
  assert.equal(scopeOf(tokens, "sweep"), "meta.trigger.kotodama variable.function.callback.kotodama");
  assert.equal(scopeOf(tokens, "tag"), "meta.trigger.kotodama variable.parameter.named.kotodama");
  assert.equal(scopeOf(tokens, "block", 1), "-");
  assert.equal(scopeOf(tokens, "kotoage"), "storage.modifier.kotodama");
});

test("attributes highlight the real attribute names", async () => {
  const tokens = await tokenize([
    "error enum Failure {",
    "    #[message(\"Too large\")]",
    "    TooLarge = 1,",
    "}",
    "#[test(fixture = alice)]",
    "fn checks() {}",
  ].join("\n"));
  for (const name of ["message", "test", "fixture"]) {
    assert.match(scopeOf(tokens, name), /keyword\.annotation\.kotodama$/);
  }
});

test("shipped samples tokenize exactly as the reviewed snapshot", async () => {
  const samples = fs.readdirSync(samplesDirectory).filter(name => name.endsWith(".ko")).sort();
  assert.ok(samples.some(name => /(?:誓約|言挙げ|始まり|改善)/.test(fs.readFileSync(path.join(samplesDirectory, name), "utf8"))),
    "at least one sample must use the Japanese keyword spellings");
  let rendered = "";
  for (const name of samples) {
    rendered += `## ${name}\n`;
    for (const token of await tokenize(fs.readFileSync(path.join(samplesDirectory, name), "utf8"))) {
      rendered += `${token.text}\t${token.scope}\n`;
    }
  }
  if (process.env.KOTODAMA_UPDATE_SNAPSHOT === "1") {
    fs.mkdirSync(path.dirname(snapshotPath), { recursive: true });
    fs.writeFileSync(snapshotPath, rendered);
  }
  assert.equal(rendered, fs.readFileSync(snapshotPath, "utf8"));
});

// Trigger schedule labels are contextual; ordinary local names stay ordinary.
test("trigger schedules highlight labelled milliseconds contextually", async () => {
  const tokens = await tokenize([
    "seiyaku Clock {",
    "    trigger tick -> run {",
    "        on time schedule(start_ms: 0, period_ms: 60 * 1_000);",
    "    }",
    "    fn helper(int start_ms) -> int { start_ms }",
    "}",
  ].join("\n"));
  for (const word of ["schedule", "start_ms", "period_ms"]) {
    assert.equal(scopeOf(tokens, word), "meta.trigger.kotodama keyword.other.trigger.kotodama", word);
  }
  assert.equal(scopeOf(tokens, "start_ms", 1), "-");
});

test("ordinary enums are data declarations and error enums retain error scope", async () => {
  const tokens = await tokenize("module Data { enum Status { Active = 1 } error enum Failure { Missing = 1 } }");
  assert.equal(scopeOf(tokens, "enum"), "keyword.declaration.enum.kotodama");
  assert.equal(scopeOf(tokens, "Status"), "entity.name.type.enum.kotodama");
  assert.equal(scopeOf(tokens, "error"), "keyword.declaration.error.kotodama");
  assert.equal(scopeOf(tokens, "enum", 1), "keyword.declaration.error.kotodama");
});
