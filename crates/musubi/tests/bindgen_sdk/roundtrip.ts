// Compile next to the Sample.ts emitted by bindgen::tests with the actual JavaScript SDK.
import { NumericV1 } from "@iroha/iroha-js";
import { ksampleBindings as B } from "./Sample.js";
import type { KotoageRequest } from "./Sample.js";
function check(value: unknown): asserts value { if (!value) throw new Error("binding assertion"); }
function rejects(run: () => unknown): void { let failed = false; try { run(); } catch { failed = true; } check(failed); }
const wide = (1n << 200n).toString();
const int = NumericV1.decodeIntJson(wide);
const payload = new B.T1_kPayload(int, NumericV1.decodeDecimalJson("1.25"), NumericV1.decodeQuantityJson("2.5"), true, "東京", "0x00ff", { valid: true }, Number.MAX_SAFE_INTEGER, { some: { none: true } }, { err: B.T13_kFailure.v0_kInvalid }, [int], B.T15_kStatus.v1_kComplete, [int, false], "0x00");
const view = B.entry2_kinspect({ f0_kinput: payload });
const call = B.entry3_kupdate({ f0_kinput: payload });
check(view.kind === "View" && call.kind === "Kotoage");
check(B.entry0_khajimari({}).kind === "Hajimari" && B.entry1_kkaizen({}).kind === "Kaizen");
// @ts-expect-error A view cannot be routed as a mutating request.
const incorrect: KotoageRequest<B.T1_kPayload> = view;
void incorrect;
const wire = JSON.parse(JSON.stringify(view.payload)).input;
check(wire.amount === wide && wire.price === "1.25" && wire.total === "2.5");
const decoded = view.decodeResult(wire);
check(NumericV1.encodeIntJson(decoded.f0_kamount) === wide && decoded.f11_kstatus === B.T15_kStatus.v1_kComplete);
check("some" in decoded.f8_koptional && "none" in decoded.f8_koptional.some);
check(JSON.stringify(B.entry2_kinspect({ f0_kinput: decoded }).payload) === JSON.stringify(view.payload));
for (const [key, value] of [["amount", 1], ["amount", "01"], ["amount", (1n << 511n).toString()], ["status", "Invented"], ["pair", ["1"]], ["items", ["1", "2", "3", "4", "5"]], ["optional", { some: { none: true }, none: true }], ["note", "\ud800"], ["data", "0xAA"]] as const) rejects(() => view.decodeResult({ ...wire, [key]: value }));
rejects(() => view.decodeResult({ ...wire, extra: true }));
const missing = { ...wire }; delete missing.amount; rejects(() => view.decodeResult(missing));
console.log("TypeScript generated bindings: wide numerics, nested sums, enums, strict decoding, and kind separation passed");
