//! TypeScript models using the JavaScript SDK's lossless numeric codecs.
use super::*;

pub(super) fn render(model: &Model) -> String {
    let mut out = String::from(include_str!("typescript_runtime.txt"));
    writeln!(out, "\nexport namespace {} {{", model.namespace).unwrap();
    writeln!(out, "export const codeHash = {};", quoted(&model.code_hash)).unwrap();
    for (id, ty) in model.types.iter().enumerate() {
        if let Some(identity) = &ty.identity {
            writeln!(out, "/** Exact signed nominal identity: {identity} */").unwrap();
        }
        let name = &ty.name;
        match &ty.kind {
            Kind::Struct(fields) => {
                writeln!(
                    out,
                    "export class {name} {{\n  private readonly identity{id} = undefined;"
                )
                .unwrap();
                let parameters = fields
                    .iter()
                    .enumerate()
                    .map(|(i, (name, child))| {
                        format!("readonly {}: {}", field(i, name), model.ty(*child))
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(out, "  constructor({parameters}) {{}}\n}}").unwrap();
            }
            Kind::Enum(variants) => {
                writeln!(out, "export enum {name} {{").unwrap();
                for (i, variant) in variants.iter().enumerate() {
                    writeln!(out, "  v{i}_{} = {},", identifier(variant), quoted(variant)).unwrap();
                }
                writeln!(out, "}}").unwrap();
            }
            kind => {
                writeln!(
                    out,
                    "export type {name} = {};",
                    type_expression(model, kind)
                )
                .unwrap();
            }
        }
        let decode = decode_body(model, &ty.kind, id);
        let encode = encode_body(&ty.kind, id);
        writeln!(out, "function decode{id}(value: unknown): {name} {{ {decode} }}\nfunction encode{id}(value: {name}): JsonValue {{ {encode} }}").unwrap();
    }
    for (ordinal, entry) in model.entries.iter().enumerate() {
        let name = &entry.symbol;
        let result = model.ty(entry.result);
        writeln!(
            out,
            "\n/** {} entrypoint {}; signed ordinal {ordinal}. */",
            entry.kind,
            quoted(&entry.name)
        )
        .unwrap();
        writeln!(out, "export interface {name}Args {{").unwrap();
        for (i, (wire_name, child)) in entry.args.iter().enumerate() {
            writeln!(
                out,
                "  /** Wire parameter {}. */ readonly {}: {};",
                quoted(wire_name),
                field(i, wire_name),
                model.ty(*child)
            )
            .unwrap();
        }
        writeln!(out, "}}").unwrap();
        let pairs = entry
            .args
            .iter()
            .enumerate()
            .map(|(i, (wire, child))| {
                format!("[{}, encode{child}(args.{})]", quoted(wire), field(i, wire))
            })
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(out, "export function {name}(args: {name}Args): {}Request<{result}> {{\n  return Object.freeze<{}Request<{result}>>({{ kind: {}, codeHash, ordinal: {ordinal}, entrypoint: {}, payload: object([{pairs}]), argumentSchema: {}, returnSchema: {}, decodeResult: decode{} }});\n}}", entry.kind, entry.kind, quoted(entry.kind), quoted(&entry.name), entry.schema_json, entry.result_schema_json, entry.result).unwrap();
    }
    out.push_str("}\n");
    out
}

fn type_expression(model: &Model, kind: &Kind) -> String {
    match kind {
        Kind::Tuple(children) => format!(
            "readonly [{}]",
            children
                .iter()
                .map(|id| model.ty(*id))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Kind::Option(child) => format!("OptionValue<{}>", model.ty(*child)),
        Kind::Result(ok, err) => format!("ResultValue<{}, {}>", model.ty(*ok), model.ty(*err)),
        Kind::List(child, _) => format!("ReadonlyArray<{}>", model.ty(*child)),
        Kind::Leaf(kind) => match kind {
            EntrypointValueKindV1::Int => "KotodamaInt",
            EntrypointValueKindV1::Decimal => "KotodamaDecimal",
            EntrypointValueKindV1::Quantity => "KotodamaQuantity",
            EntrypointValueKindV1::Bool => "boolean",
            EntrypointValueKindV1::Json => "JsonValue",
            EntrypointValueKindV1::DataSpaceId => "number",
            _ => "string",
        }
        .into(),
        Kind::Unit => "null".into(),
        Kind::Cursor => "string".into(),
        Kind::Struct(_) | Kind::Enum(_) => unreachable!(),
    }
}

fn decode_body(model: &Model, kind: &Kind, id: usize) -> String {
    match kind {
        Kind::Struct(fields) => {
            let keys = fields
                .iter()
                .map(|(name, _)| quoted(name))
                .collect::<Vec<_>>()
                .join(", ");
            let values = fields
                .iter()
                .map(|(name, child)| format!("decode{child}(fields.get({}))", quoted(name)))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "const fields = record(value, [{keys}]); return new {}({values});",
                model.ty(id)
            )
        }
        Kind::Tuple(children) => {
            let values = children
                .iter()
                .enumerate()
                .map(|(i, child)| format!("decode{child}(items[{i}])"))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "const items = array(value, {}, true); return [{values}];",
                children.len()
            )
        }
        Kind::Option(child) => format!(
            "const fields = record(value); if (fields.size !== 1) return fail(); if (fields.has('some')) return {{some: decode{child}(fields.get('some'))}}; if (fields.get('none') === true) return {{none: true}}; return fail();"
        ),
        Kind::Result(ok, err) => format!(
            "const fields = record(value); if (fields.size !== 1) return fail(); if (fields.has('ok')) return {{ok: decode{ok}(fields.get('ok'))}}; if (fields.has('err')) return {{err: decode{err}(fields.get('err'))}}; return fail();"
        ),
        Kind::List(child, capacity) => {
            format!("return array(value, {capacity}, false).map(decode{child});")
        }
        Kind::Leaf(leaf) => format!(
            "return {};",
            match leaf {
                EntrypointValueKindV1::Int => "NumericV1.decodeIntJson(string(value))",
                EntrypointValueKindV1::Decimal => "NumericV1.decodeDecimalJson(string(value))",
                EntrypointValueKindV1::Quantity => "NumericV1.decodeQuantityJson(string(value))",
                EntrypointValueKindV1::Bool => "boolean(value)",
                EntrypointValueKindV1::Json => "json(value)",
                EntrypointValueKindV1::DataSpaceId => "dataspace(value)",
                EntrypointValueKindV1::Blob => "bytes(value)",
                _ => "string(value)",
            }
        ),
        Kind::Unit => "if (value !== null) return fail(); return null;".into(),
        Kind::Cursor => "return bytes(value);".into(),
        Kind::Enum(variants) => {
            let cases = variants
                .iter()
                .enumerate()
                .map(|(i, variant)| {
                    format!(
                        "case {}: return {}.v{i}_{};",
                        quoted(variant),
                        model.ty(id),
                        identifier(variant)
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!("switch (string(value)) {{ {cases} default: return fail(); }}")
        }
    }
}

fn encode_body(kind: &Kind, id: usize) -> String {
    match kind {
        Kind::Struct(fields) => format!(
            "return object([{}]);",
            fields
                .iter()
                .enumerate()
                .map(|(i, (name, child))| format!(
                    "[{}, encode{child}(value.{})]",
                    quoted(name),
                    field(i, name)
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Kind::Tuple(children) => format!(
            "array(value, {}, true); return [{}];",
            children.len(),
            children
                .iter()
                .enumerate()
                .map(|(i, child)| format!("encode{child}(value[{i}])"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Kind::Option(child) => format!(
            "if ('some' in value && Object.keys(value).length === 1) return {{some: encode{child}(value.some)}}; if ('none' in value && value.none === true && Object.keys(value).length === 1) return {{none: true}}; return fail();"
        ),
        Kind::Result(ok, err) => format!(
            "if ('ok' in value && Object.keys(value).length === 1) return {{ok: encode{ok}(value.ok)}}; if ('err' in value && Object.keys(value).length === 1) return {{err: encode{err}(value.err)}}; return fail();"
        ),
        Kind::List(child, capacity) => {
            format!("array(value, {capacity}, false); return value.map(encode{child});")
        }
        Kind::Leaf(leaf) => format!(
            "return {};",
            match leaf {
                EntrypointValueKindV1::Int => "NumericV1.encodeIntJson(value)",
                EntrypointValueKindV1::Decimal => "NumericV1.encodeDecimalJson(value)",
                EntrypointValueKindV1::Quantity => "NumericV1.encodeQuantityJson(value)",
                EntrypointValueKindV1::Bool => "boolean(value)",
                EntrypointValueKindV1::Json => "json(value)",
                EntrypointValueKindV1::DataSpaceId => "dataspace(value)",
                EntrypointValueKindV1::Blob => "bytes(value)",
                _ => "string(value)",
            }
        ),
        Kind::Unit => "if (value !== null) return fail(); return null;".into(),
        Kind::Cursor => "return bytes(value);".into(),
        Kind::Enum(_) => format!("return decode{id}(value);"),
    }
}
