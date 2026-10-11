import assert from "node:assert/strict";
import test from "node:test";
import { normalizeCompilerResult } from "../src/kotodamaCompiler/normalize.js";
import { makeNativeTest, nativeBinding } from "./helpers/native.js";

const nativeTest = makeNativeTest(test, { require: "compileKotodama" });

nativeTest("native state schemas preserve exact nested products, nominal types, and tuple keys", async () => {
  const source = `seiyaku StateShapes {
  enum Status { Open = 1; Closed = 7; }
  error enum Failure { Rejected = 1; }
  struct Payload { int amount; Status status; }
  state int scalar;
  state () marker;
  state (int, bool) pair;
  state Payload product;
  state Option<int> optional;
  state Result<int, Failure> result;
  state List<int, 3> bounded;
  state Option<StateCursor<(int, Name)>> cursor;
  state StateMap<(int, Name), List<Payload, 2>> values;
  hajimari() {
    scalar = 1;
    marker = ();
    pair = (1, true);
    product = Payload { amount: 1, status: Status::Open };
    optional = Option::none;
    result = Result::ok(1);
    bounded = [1, 2];
    cursor = Option::none;
  }
  view fn read() authorize(anyone) -> int { scalar }
}
`;
  const raw = await nativeBinding.compileKotodama({ artifacts: [], source, zk: false });
  assert.equal(raw.ok, true, raw.diagnosticsJson);
  const result = normalizeCompilerResult(raw);
  assert.equal(result.ok, true);
  assert.deepEqual(result.output.manifest.states, [
    { name: "scalar", type_name: "int" },
    { name: "marker", type_name: "()" },
    { name: "pair", type_name: "(int, bool)" },
    { name: "product", type_name: "StateShapes::Payload{amount: int, status: StateShapes::Status}" },
    { name: "optional", type_name: "Option<int>" },
    { name: "result", type_name: "Result<int, StateShapes::Failure>" },
    { name: "bounded", type_name: "List<int, 3>" },
    { name: "cursor", type_name: "Option<StateCursor<(int, Name)>>" },
    { name: "values", type_name: "StateMap<(int, Name), List<StateShapes::Payload{amount: int, status: StateShapes::Status}, 2>>" },
  ]);
});
