import { buildRegisterDataspaceAssetDefinitionInstruction } from "./instructionBuilders.js";
import { normalizeAssetDefinitionName } from "./instructionBuilderPrimitives.js";

export function createRegisterAssetDefinitionInstructionBuilder({
  normalizeTransactionAssetDefinitionId,
  buildMintAssetInstruction,
}) {
  function buildRegisterAssetDefinitionInstructions({
    assetDefinition,
    mints = [],
  }) {
    const instructions = [];
    const directDataspace = assetDefinition.owningDataspace ?? assetDefinition.owning_dataspace;
    if (directDataspace !== undefined && directDataspace !== null) {
      if (assetDefinition.owningDataspace !== undefined && assetDefinition.owning_dataspace !== undefined &&
          String(assetDefinition.owningDataspace) !== String(assetDefinition.owning_dataspace)) {
        throw new TypeError("assetDefinition dataspace home aliases disagree");
      }
      instructions.push(buildRegisterDataspaceAssetDefinitionInstruction({
        ...assetDefinition,
        assetDefinitionId: normalizeTransactionAssetDefinitionId(assetDefinition.assetDefinitionId, "assetDefinition.assetDefinitionId"),
        dataspaceId: directDataspace,
        scale: assetDefinition.spec?.scale ?? null,
      }));
      mints.forEach((mint) => instructions.push(buildMintAssetInstruction({
        assetHoldingId: mint.assetHoldingId ?? mint.assetId,
        quantity: mint.quantity,
      })));
      return instructions;
    }
    const hasOwningDomain = Object.prototype.hasOwnProperty.call(
      assetDefinition,
      "owningDomain",
    );
    const hasSnakeOwningDomain = Object.prototype.hasOwnProperty.call(
      assetDefinition,
      "owning_domain",
    );
    if (!hasOwningDomain && !hasSnakeOwningDomain) {
      throw new TypeError(
        "assetDefinition.owningDomain is required; use null for an intentionally unowned global definition",
      );
    }
    const owningDomain = hasOwningDomain
      ? assetDefinition.owningDomain
      : assetDefinition.owning_domain;
    if (owningDomain !== null && typeof owningDomain !== "string") {
      throw new TypeError("assetDefinition.owningDomain must be a domain identifier or null");
    }
    if (
      hasOwningDomain &&
      hasSnakeOwningDomain &&
      assetDefinition.owningDomain !== assetDefinition.owning_domain
    ) {
      throw new TypeError("assetDefinition ownership aliases disagree");
    }
    const hasBalanceScopePolicy = Object.prototype.hasOwnProperty.call(
      assetDefinition,
      "balanceScopePolicy",
    );
    const hasSnakeBalanceScopePolicy = Object.prototype.hasOwnProperty.call(
      assetDefinition,
      "balance_scope_policy",
    );
    if (!hasBalanceScopePolicy && !hasSnakeBalanceScopePolicy) {
      throw new TypeError("assetDefinition.balanceScopePolicy is required");
    }
    if (
      hasBalanceScopePolicy &&
      hasSnakeBalanceScopePolicy &&
      assetDefinition.balanceScopePolicy !== assetDefinition.balance_scope_policy
    ) {
      throw new TypeError("assetDefinition balance-scope policy aliases disagree");
    }
    const balanceScopePolicy = hasBalanceScopePolicy
      ? assetDefinition.balanceScopePolicy
      : assetDefinition.balance_scope_policy;
    if (balanceScopePolicy !== "Global" && balanceScopePolicy !== "DataspaceRestricted") {
      throw new TypeError(
        "assetDefinition.balanceScopePolicy must be Global or DataspaceRestricted",
      );
    }
    if (balanceScopePolicy === "DataspaceRestricted" && owningDomain === null) {
      throw new TypeError(
        "assetDefinition.owningDomain is required for DataspaceRestricted balances",
      );
    }
    const name = normalizeAssetDefinitionName(assetDefinition.name, "assetDefinition.name");
    const assetDefinitionId = normalizeTransactionAssetDefinitionId(
      assetDefinition.assetDefinitionId,
      "assetDefinition.assetDefinitionId",
    );
    if (
      Object.prototype.hasOwnProperty.call(assetDefinition, "confidentialPolicy") ||
      Object.prototype.hasOwnProperty.call(assetDefinition, "confidential_policy")
    ) {
      throw new TypeError(
        "assetDefinition cannot carry confidential policy; use RegisterZkAsset with canonical verifier bindings",
      );
    }
    instructions.push({
      Register: {
        AssetDefinition: {
          id: assetDefinitionId,
          name,
          logo: assetDefinition.logo ?? null,
          metadata: assetDefinition.metadata ?? {},
          mintable: assetDefinition.mintable ?? "Infinitely",
          spec: assetDefinition.spec ?? { scale: null },
          balance_scope_policy: balanceScopePolicy,
          owning_domain: owningDomain,
        },
      },
    });
    mints.forEach((mint) => {
      instructions.push(
        buildMintAssetInstruction({
          assetHoldingId: mint.assetHoldingId ?? mint.assetId,
          quantity: mint.quantity,
        }),
      );
    });
    return instructions;
  }

  return buildRegisterAssetDefinitionInstructions;
}
