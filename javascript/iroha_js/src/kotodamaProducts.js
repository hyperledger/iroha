/** Exact compiler-owned query product layouts shared by boundary validators. */
export const CORE_QUERY_VIEWS = new Map([
  ["kotodama::AccountView", { fields: ["id", "metadata"], children: ["AccountId", "Json"] }],
  ["kotodama::AssetView", { fields: ["id", "amount"], children: ["AssetId", "quantity"] }],
  [
    "kotodama::AssetDefinitionView",
    {
      fields: ["id", "name", "description", "owned_by", "total_quantity", "numeric_scale", "metadata"],
      children: [
        "AssetDefinitionId",
        "string",
        "Option<string>",
        "AccountId",
        "quantity",
        "Option<int>",
        "Json",
      ],
    },
  ],
  [
    "kotodama::DomainView",
    { fields: ["id", "owned_by", "metadata"], children: ["DomainId", "AccountId", "Json"] },
  ],
  [
    "kotodama::NftView",
    { fields: ["id", "owned_by", "content"], children: ["NftId", "AccountId", "Json"] },
  ],
]);

/** Validate a durable product after recursively validating each field type. */
export function isExactDurableBuiltinProduct(name, fields, types) {
  const product = CORE_QUERY_VIEWS.get(name);
  if (product) return fields.length === product.fields.length && fields.every((field, index) => field === product.fields[index] && types[index] === product.children[index]);
  if (name !== "kotodama::QueryPage") return !name.startsWith("kotodama::");
  if (fields.length !== 2 || fields[0] !== "items" || fields[1] !== "next_offset" || types[1] !== "Option<int>") return false;
  return [...CORE_QUERY_VIEWS].some(([view, shape]) => types[0] === `List<${view}{${shape.fields.map((field, index) => `${field}: ${shape.children[index]}`).join(", ")}}, 64>`);
}
