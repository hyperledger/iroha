/** Shared runtime configuration for the ISO recipe examples. */
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { NetworkId, OperatorSigningContext, ToriiClient } from "../dist/index.js";

/** No business identity or expiry is generated from the local clock. */
export function nativeIntentFromEnvironment(environment = process.env) {
  return {
    uetr: environment.ISO_UETR,
    nexusSettlement: {
      networkId: environment.ISO_NETWORK_ID,
      expiresAtHeight: environment.ISO_EXPIRES_AT_HEIGHT,
      sourceAccountId: environment.ISO_SOURCE_ACCOUNT_ID,
      targetAccountId: environment.ISO_TARGET_ACCOUNT_ID,
      assetDefinitionId: environment.ISO_ASSET_DEFINITION_ID,
    },
  };
}

/** JSON configuration carries the exact canonical NetworkId literal. */
export function parseConfiguredNativeIntent(options) {
  return {
    ...options,
    nexusSettlement: {
      ...options.nexusSettlement,
      networkId: NetworkId.parse(options.nexusSettlement?.networkId),
    },
  };
}

/** Load a runtime-only signer supplied by the operator; never store signing keys. */
export async function createIsoOperatorClient(baseUrl, networkId, environment = process.env) {
  const modulePath = environment.ISO_OPERATOR_SIGNER_MODULE;
  if (typeof modulePath !== "string" || modulePath.length === 0) {
    throw new TypeError("ISO_OPERATOR_SIGNER_MODULE must name a runtime signer module");
  }
  const { default: signer } = await import(pathToFileURL(resolve(modulePath)).href);
  return new ToriiClient(baseUrl, {
    operatorSigningContext: new OperatorSigningContext(networkId, signer),
  });
}
