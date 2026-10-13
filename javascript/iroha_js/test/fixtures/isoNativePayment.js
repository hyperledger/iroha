/** Exact payer-selected ISO payment terms shared by builder and transport tests. */
import { NetworkId } from "../../src/networkId.js";

export const ISO_PAYMENT_INTENT = Object.freeze({
  uetr: "123e4567-e89b-42d3-a456-426614174000",
  nexusSettlement: Object.freeze({
    networkId: NetworkId.parse("hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"),
    expiresAtHeight: 100n,
    sourceAccountId: "sorauﾛ1P5ﾁXEｴﾕGjgﾕﾚﾎﾕｸﾁEtﾀ3ﾂｺ2gALｺﾒefﾍ8DLgｾoCVGUYHS5",
    targetAccountId: "sorauﾛ1PﾜdﾎｼﾋﾉNｸdﾁﾑkiﾇ3ｵﾓaPBQDTｲKqｼqｵrﾗｶwSQ1ﾌﾅQU61Y7",
    assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
  }),
});
