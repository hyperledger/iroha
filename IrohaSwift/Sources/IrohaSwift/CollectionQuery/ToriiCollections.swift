import Foundation

/// A JSON object row, used for projections (`select`) and aggregate rows.
public typealias ToriiJSONObject = [String: ToriiJSONValue]

/// Where a collection lives on Torii.
enum ToriiCollectionRoute: Sendable, Equatable {
    /// A top-level collection such as `/v1/domains`.
    case fixed(String)
    /// `/v1/space-directory/uaids/{uaid}/manifests`.
    case uaid(String)
    /// `/v1/accounts/{account_id}/<suffix>`.
    case account(String, suffix: String)
    /// `/v1/assets/{definition_id}/<suffix>`.
    case assetDefinition(String, suffix: String)
}

/// One Torii collection, read with the collection-query language
/// (`specs/torii/collection_queries.md`).
///
/// Every call sends `POST <collection>/query` with the canonical JSON body.
/// When the client has a canonical request signer the request is signed,
/// which only widens visibility into restricted dataspaces; reads never
/// require credentials.
///
/// ```swift
/// let query = ToriiListQuery(
///     filter: ToriiAssetDefinition.Fields.ownedBy == alice,
///     sort: [.ascending("id")],
///     limit: 50
/// )
/// let first = try await torii.assetDefinitions.page(query)       // one page
/// for try await definition in torii.assetDefinitions.items(query) {  // every row, page by page
///     print(definition.id)
/// }
/// ```
///
/// History collections (`transactions`, `accountTransactions(of:)`) are read
/// newest first and reject `sort`, `includeTotal` and `aggregate` before
/// anything is sent. Their pages can hold fewer rows than `limit`, or none,
/// and still carry a `nextCursor`; `pages(_:)` and `items(_:)` keep following
/// it until Torii returns `nil`.
public struct ToriiCollection<Row: Decodable & Sendable>: Sendable {
    let client: ToriiClient
    let route: ToriiCollectionRoute
    /// Read in history order; `sort`, `include_total` and `aggregate` are rejected.
    let isHistory: Bool

    init(client: ToriiClient, route: ToriiCollectionRoute, isHistory: Bool = false) {
        self.client = client
        self.route = route
        self.isHistory = isHistory
    }

    /// Read one page of full rows.
    ///
    /// - Throws: `ToriiClientError.invalidQuery` when a control is invalid
    ///   (including `select`/`aggregate`, which change the row shape: read
    ///   those with `page(_:as:)`), `ToriiClientError.api` when Torii rejects
    ///   the request, and transport or decoding errors.
    public func page(_ query: ToriiListQuery = ToriiListQuery()) async throws -> ToriiPage<Row> {
        try await fetch(query, as: Row.self, fullRows: true)
    }

    /// Read one page, decoding each item as `Item` (for example
    /// `ToriiJSONObject` for projections and aggregates).
    public func page<Item: Decodable & Sendable>(_ query: ToriiListQuery,
                                                  as itemType: Item.Type) async throws -> ToriiPage<Item> {
        try await fetch(query, as: itemType, fullRows: false)
    }

    /// Every page of full rows, fetched on demand by following `nextCursor`.
    public func pages(_ query: ToriiListQuery = ToriiListQuery()) -> ToriiPageSequence<Row> {
        let collection = self
        return ToriiPageSequence(query: query) { query in
            try await collection.fetch(query, as: Row.self, fullRows: true)
        }
    }

    /// Every page, decoding each item as `Item`.
    public func pages<Item: Decodable & Sendable>(_ query: ToriiListQuery,
                                                   as itemType: Item.Type) -> ToriiPageSequence<Item> {
        let collection = self
        return ToriiPageSequence(query: query) { query in
            try await collection.fetch(query, as: itemType, fullRows: false)
        }
    }

    /// Every row across all pages, fetching each page only when it is needed.
    public func items(_ query: ToriiListQuery = ToriiListQuery()) -> ToriiItemSequence<Row> {
        ToriiItemSequence(pages: pages(query))
    }

    /// Every item across all pages, decoded as `Item`.
    public func items<Item: Decodable & Sendable>(_ query: ToriiListQuery,
                                                   as itemType: Item.Type) -> ToriiItemSequence<Item> {
        ToriiItemSequence(pages: pages(query, as: itemType))
    }

    private func fetch<Item: Decodable & Sendable>(_ query: ToriiListQuery,
                                                   as itemType: Item.Type,
                                                   fullRows: Bool) async throws -> ToriiPage<Item> {
        if isHistory {
            try Self.requireHistoryControls(query)
        }
        if fullRows {
            try Self.requireFullRows(query)
        }
        return try await client.fetchCollectionPage(route: route, query: query, as: itemType)
    }

    private static func requireFullRows(_ query: ToriiListQuery) throws {
        guard Row.self != ToriiJSONObject.self else {
            return
        }
        let control: String
        if query.select != nil {
            control = "select"
        } else if query.aggregate != nil {
            control = "aggregate"
        } else {
            return
        }
        throw ToriiClientError.invalidQuery(
            ToriiListQueryError(
                parameter: control,
                message: "`\(control)` changes the item shape; read it with `page(_:as: ToriiJSONObject.self)`"
            )
        )
    }

    /// History collections reject every control that would need a scan of the whole history.
    private static func requireHistoryControls(_ query: ToriiListQuery) throws {
        let control: String
        if !query.sort.isEmpty {
            control = "sort"
        } else if query.includeTotal {
            control = "include_total"
        } else if query.aggregate != nil {
            control = "aggregate"
        } else {
            return
        }
        throw ToriiClientError.invalidQuery(
            ToriiListQueryError(
                parameter: control,
                message: "transaction history is read newest first and does not accept `\(control)`, which would need a scan of the whole history"
            )
        )
    }
}

/// A collection row keyed by a unique `id` field.
public protocol ToriiIdentifiedRow: Decodable, Sendable {
    /// The row's unique identifier.
    var id: String { get }
}

extension ToriiCollection where Row: ToriiIdentifiedRow {
    /// The row whose `id` equals `id`, or `nil` when it does not exist or is not visible.
    public func get(_ id: String) async throws -> Row? {
        try await page(ToriiListQuery(filter: ToriiField("id") == id, limit: 1)).items.first
    }
}

extension ToriiCollection where Row == ToriiAccount {
    /// The account with the canonical I105 `accountId`, or `nil` when it does
    /// not exist or is not visible.
    public func get(_ accountId: String) async throws -> ToriiAccount? {
        let canonical = try client.canonicalAccountIdLiteral(accountId, field: "accountId")
        return try await page(ToriiListQuery(filter: ToriiField("id") == canonical, limit: 1)).items.first
    }
}

// MARK: - Collections

extension ToriiClient {
    /// Domains (`/v1/domains`).
    public var domains: ToriiCollection<ToriiDomain> {
        ToriiCollection(client: self, route: .fixed("/v1/domains"))
    }

    /// Accounts (`/v1/accounts`).
    public var accounts: ToriiCollection<ToriiAccount> {
        ToriiCollection(client: self, route: .fixed("/v1/accounts"))
    }

    /// Asset definitions (`/v1/assets/definitions`).
    public var assetDefinitions: ToriiCollection<ToriiAssetDefinition> {
        ToriiCollection(client: self, route: .fixed("/v1/assets/definitions"))
    }

    /// NFTs (`/v1/nfts`).
    public var nfts: ToriiCollection<ToriiNft> {
        ToriiCollection(client: self, route: .fixed("/v1/nfts"))
    }

    /// RWA lots (`/v1/rwas`).
    public var rwas: ToriiCollection<ToriiRwa> {
        ToriiCollection(client: self, route: .fixed("/v1/rwas"))
    }

    /// Repo agreements (`/v1/repo/agreements`).
    public var repoAgreements: ToriiCollection<ToriiRepoAgreement> {
        ToriiCollection(client: self, route: .fixed("/v1/repo/agreements"))
    }

    /// Explorer accounts in bounded server order.
    public var explorerAccounts: ToriiCollection<ToriiJSONObject> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/accounts"), isHistory: true)
    }

    /// Explorer domains in bounded server order.
    public var explorerDomains: ToriiCollection<ToriiJSONObject> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/domains"), isHistory: true)
    }

    /// Explorer asset definitions in bounded server order.
    public var explorerAssetDefinitions: ToriiCollection<ToriiJSONObject> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/asset-definitions"), isHistory: true)
    }

    /// Explorer assets in bounded server order.
    public var explorerAssets: ToriiCollection<ToriiJSONObject> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/assets"), isHistory: true)
    }

    /// Explorer nfts in bounded server order.
    public var explorerNfts: ToriiCollection<ToriiJSONObject> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/nfts"), isHistory: true)
    }

    /// Explorer rwas in bounded server order.
    public var explorerRwas: ToriiCollection<ToriiExplorerRwaRecord> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/rwas"), isHistory: true)
    }

    /// Explorer blocks in bounded server order.
    public var explorerBlocks: ToriiCollection<ToriiJSONObject> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/blocks"), isHistory: true)
    }

    /// Explorer transactions in bounded server order.
    public var explorerTransactions: ToriiCollection<ToriiExplorerTransactionItem> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/transactions"), isHistory: true)
    }

    /// Explorer transactions/latest in bounded server order.
    public var explorerLatestTransactions: ToriiCollection<ToriiExplorerTransactionItem> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/transactions/latest"), isHistory: true)
    }

    /// Explorer instructions in bounded server order.
    public var explorerInstructions: ToriiCollection<ToriiExplorerInstructionItem> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/instructions"), isHistory: true)
    }

    /// Explorer instructions/latest in bounded server order.
    public var explorerLatestInstructions: ToriiCollection<ToriiExplorerInstructionItem> {
        ToriiCollection(client: self, route: .fixed("/v1/explorer/instructions/latest"), isHistory: true)
    }

    /// Effective direct and role permissions, keyed by name and payload.
    public func accountPermissions(of accountId: String) -> ToriiCollection<ToriiAccountPermission> {
        ToriiCollection(client: self, route: .account(accountId, suffix: "permissions"))
    }

    /// Subscription plans, in canonical identifier order.
    public var subscriptionPlans: ToriiCollection<ToriiSubscriptionPlanRow> {
        ToriiCollection(client: self, route: .fixed("/v1/subscriptions/plans"))
    }

    /// Subscriptions with their flat current state.
    public var subscriptions: ToriiCollection<ToriiSubscriptionRow> {
        ToriiCollection(client: self, route: .fixed("/v1/subscriptions"))
    }

    /// Manifest inventory scoped to a canonical UAID.
    public func uaidManifests(of uaid: String) -> ToriiCollection<ToriiUaidManifestRecord> {
        ToriiCollection(client: self, route: .uaid(uaid))
    }

    /// Contract calls, newest first; supports filter, select, limit and cursor.
    public var contractActivity: ToriiCollection<ToriiContractActivityItem> {
        ToriiCollection(client: self, route: .fixed("/v1/contracts/activity"), isHistory: true)
    }

    /// Contract events, newest first; supports filter, select, limit and cursor.
    public var contractEvents: ToriiCollection<ToriiContractEventItem> {
        ToriiCollection(client: self, route: .fixed("/v1/contracts/events"), isHistory: true)
    }

    /// Account movements, newest first; supports filter, select, limit and cursor.
    public func accountHistory(of accountId: String) -> ToriiCollection<ToriiAccountHistoryRow> {
        ToriiCollection(client: self, route: .account(accountId, suffix: "history"), isHistory: true)
    }

    /// Balances held by one account (`/v1/accounts/{account_id}/assets`).
    public func accountAssets(of accountId: String) -> ToriiCollection<ToriiAccountAsset> {
        ToriiCollection(client: self, route: .account(accountId, suffix: "assets"))
    }

    /// Accounts holding one asset definition (`/v1/assets/{definition_id}/holders`).
    public func assetHolders(of assetDefinitionId: String) -> ToriiCollection<ToriiAssetHolder> {
        ToriiCollection(client: self, route: .assetDefinition(assetDefinitionId, suffix: "holders"))
    }

    /// Every committed transaction, newest first (`POST /v1/transactions/query`).
    ///
    /// A history collection: `sort`, `includeTotal` and `aggregate` are
    /// rejected, and a page may hold fewer rows than `limit` while still
    /// carrying a `nextCursor`.
    public var transactions: ToriiCollection<ToriiTransaction> {
        ToriiCollection(client: self, route: .fixed("/v1/transactions"), isHistory: true)
    }

    /// Committed transactions the account signed or that reference it, newest
    /// first (`/v1/accounts/{account_id}/transactions`). A history collection,
    /// like `transactions`.
    public func accountTransactions(of accountId: String) -> ToriiCollection<ToriiTransaction> {
        ToriiCollection(client: self, route: .account(accountId, suffix: "transactions"), isHistory: true)
    }
}

// MARK: - Rows
//
// The fields that identify a row (`id`; `account_id`, `asset`, `scope` and
// `quantity` for balances; `entrypoint_hash`, `block_height` and
// `block_index` for transactions) are always present. Every other field may
// be null or absent, so it is optional here; unknown fields are ignored.

private func decodeMetadata<Key: CodingKey>(_ container: KeyedDecodingContainer<Key>,
                                            forKey key: Key) throws -> ToriiJSONObject {
    try container.decodeIfPresent(ToriiJSONObject.self, forKey: key) ?? [:]
}

private func decodeStringList<Key: CodingKey>(_ container: KeyedDecodingContainer<Key>,
                                              forKey key: Key) throws -> [String] {
    try container.decodeIfPresent([String].self, forKey: key) ?? []
}

private func decodeQuantity<Key: CodingKey>(_ container: KeyedDecodingContainer<Key>,
                                            forKey key: Key) throws -> KotodamaQuantity {
    let text = try container.decode(String.self, forKey: key)
    do {
        return try KotodamaNumericV1Codec.decodeQuantityJSON(text)
    } catch {
        throw DecodingError.dataCorruptedError(
            forKey: key,
            in: container,
            debugDescription: "`\(key.stringValue)` must be a canonical non-negative decimal string, got `\(text)`"
        )
    }
}

private func decodeQuantityIfPresent<Key: CodingKey>(_ container: KeyedDecodingContainer<Key>,
                                                     forKey key: Key) throws -> KotodamaQuantity? {
    guard container.contains(key), try !container.decodeNil(forKey: key) else {
        return nil
    }
    return try decodeQuantity(container, forKey: key)
}

/// A domain row.
public struct ToriiDomain: ToriiIdentifiedRow, Equatable {
    public let id: String
    public let ownedBy: String?
    public let logo: String?
    public let metadata: ToriiJSONObject

    private enum CodingKeys: String, CodingKey {
        case id
        case ownedBy = "owned_by"
        case logo
        case metadata
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        ownedBy = try container.decodeIfPresent(String.self, forKey: .ownedBy)
        logo = try container.decodeIfPresent(String.self, forKey: .logo)
        metadata = try decodeMetadata(container, forKey: .metadata)
    }

    /// Filterable fields; `id` and `ownedBy` are sortable.
    public enum Fields {
        public static let id = ToriiField("id")
        public static let ownedBy = ToriiField("owned_by")
        public static let logo = ToriiField("logo")
        public static func metadata(_ key: String) -> ToriiField { .metadata(key) }
    }
}

/// An account row.
public struct ToriiAccount: Decodable, Sendable, Equatable {
    /// Canonical I105 account id.
    public let id: String
    public let label: String?
    public let uaid: String?
    public let metadata: ToriiJSONObject

    private enum CodingKeys: String, CodingKey {
        case id
        case label
        case uaid
        case metadata
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        label = try container.decodeIfPresent(String.self, forKey: .label)
        uaid = try container.decodeIfPresent(String.self, forKey: .uaid)
        metadata = try decodeMetadata(container, forKey: .metadata)
    }

    /// Filterable fields; `id`, `label` and `uaid` are sortable.
    public enum Fields {
        public static let id = ToriiField("id")
        public static let label = ToriiField("label")
        public static let uaid = ToriiField("uaid")
        public static func metadata(_ key: String) -> ToriiField { .metadata(key) }
    }
}

/// An asset definition row: the complete definition record plus its alias binding.
public struct ToriiAssetDefinition: ToriiIdentifiedRow, Equatable {
    /// The alias bound to the definition.
    public struct AliasBinding: Decodable, Sendable, Equatable {
        public let alias: String?
        public let status: String?
        public let leaseExpiryMs: UInt64?
        public let graceUntilMs: UInt64?
        public let boundAtMs: UInt64?

        private enum CodingKeys: String, CodingKey {
            case alias
            case status
            case leaseExpiryMs = "lease_expiry_ms"
            case graceUntilMs = "grace_until_ms"
            case boundAtMs = "bound_at_ms"
        }
    }

    /// Base58 asset definition id.
    public let id: String
    public let name: String?
    public let alias: String?
    public let ownedBy: String?
    public let owningDomain: String?
    /// Immutable direct definition home, kept as exact decimal text independently of balance scope.
    public let owningDataspace: String?
    public let mintable: String?
    public let description: String?
    public let logo: String?
    /// Numeric specification of the asset, as received.
    public let spec: ToriiJSONValue?
    /// Balance-scope policy of the asset, as received.
    public let balanceScopePolicy: ToriiJSONValue?
    /// Present when an alias is bound.
    public let aliasBinding: AliasBinding?
    public let metadata: ToriiJSONObject

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case alias
        case ownedBy = "owned_by"
        case owningDomain = "owning_domain"
        case owningDataspace = "owning_dataspace"
        case mintable
        case description
        case logo
        case spec
        case balanceScopePolicy = "balance_scope_policy"
        case aliasBinding = "alias_binding"
        case metadata
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = try container.decodeIfPresent(String.self, forKey: .name)
        alias = try container.decodeIfPresent(String.self, forKey: .alias)
        ownedBy = try container.decodeIfPresent(String.self, forKey: .ownedBy)
        owningDomain = try container.decodeIfPresent(String.self, forKey: .owningDomain)
        owningDataspace = try container.decodeIfPresent(String.self, forKey: .owningDataspace)
        if let home = owningDataspace {
            guard owningDomain == nil, let value = UInt64(home), value != 0, String(value) == home else {
                throw DecodingError.dataCorruptedError(forKey: .owningDataspace, in: container,
                    debugDescription: "direct dataspace home must be canonical nonzero u64 text and exclude owning_domain")
            }
        }
        mintable = try container.decodeIfPresent(String.self, forKey: .mintable)
        description = try container.decodeIfPresent(String.self, forKey: .description)
        logo = try container.decodeIfPresent(String.self, forKey: .logo)
        spec = try container.decodeIfPresent(ToriiJSONValue.self, forKey: .spec)
        balanceScopePolicy = try container.decodeIfPresent(ToriiJSONValue.self, forKey: .balanceScopePolicy)
        aliasBinding = try container.decodeIfPresent(AliasBinding.self, forKey: .aliasBinding)
        metadata = try decodeMetadata(container, forKey: .metadata)
    }

    /// Filterable fields; the string fields and alias-binding timestamps are sortable.
    public enum Fields {
        public static let id = ToriiField("id")
        public static let name = ToriiField("name")
        public static let alias = ToriiField("alias")
        public static let ownedBy = ToriiField("owned_by")
        public static let owningDomain = ToriiField("owning_domain")
        public static let owningDataspace = ToriiField("owning_dataspace")
        public static let mintable = ToriiField("mintable")
        public static let aliasBindingAlias = ToriiField("alias_binding.alias")
        public static let aliasBindingStatus = ToriiField("alias_binding.status")
        public static let aliasBindingLeaseExpiryMs = ToriiField("alias_binding.lease_expiry_ms")
        public static let aliasBindingGraceUntilMs = ToriiField("alias_binding.grace_until_ms")
        public static let aliasBindingBoundAtMs = ToriiField("alias_binding.bound_at_ms")
        public static func metadata(_ key: String) -> ToriiField { .metadata(key) }
    }
}

/// An NFT row; `metadata` is the NFT content.
public struct ToriiNft: ToriiIdentifiedRow, Equatable {
    public let id: String
    public let ownedBy: String?
    public let metadata: ToriiJSONObject

    private enum CodingKeys: String, CodingKey {
        case id
        case ownedBy = "owned_by"
        case metadata
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        ownedBy = try container.decodeIfPresent(String.self, forKey: .ownedBy)
        metadata = try decodeMetadata(container, forKey: .metadata)
    }

    /// Filterable fields; `id` and `ownedBy` are sortable.
    public enum Fields {
        public static let id = ToriiField("id")
        public static let ownedBy = ToriiField("owned_by")
        public static func metadata(_ key: String) -> ToriiField { .metadata(key) }
    }
}

/// An RWA lot row.
public struct ToriiRwa: ToriiIdentifiedRow, Equatable {
    public let id: String
    public let ownedBy: String?
    public let primaryReference: String?
    public let status: String?
    public let quantity: KotodamaQuantity?
    public let isFrozen: Bool?
    public let metadata: ToriiJSONObject

    private enum CodingKeys: String, CodingKey {
        case id
        case ownedBy = "owned_by"
        case primaryReference = "primary_reference"
        case status
        case quantity
        case isFrozen = "is_frozen"
        case metadata
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        ownedBy = try container.decodeIfPresent(String.self, forKey: .ownedBy)
        primaryReference = try container.decodeIfPresent(String.self, forKey: .primaryReference)
        status = try container.decodeIfPresent(String.self, forKey: .status)
        quantity = try decodeQuantityIfPresent(container, forKey: .quantity)
        isFrozen = try container.decodeIfPresent(Bool.self, forKey: .isFrozen)
        metadata = try decodeMetadata(container, forKey: .metadata)
    }

    /// Filterable fields; all but `isFrozen` and metadata are sortable.
    public enum Fields {
        public static let id = ToriiField("id")
        public static let ownedBy = ToriiField("owned_by")
        public static let primaryReference = ToriiField("primary_reference")
        public static let status = ToriiField("status")
        public static let quantity = ToriiField("quantity")
        public static let isFrozen = ToriiField("is_frozen")
        public static func metadata(_ key: String) -> ToriiField { .metadata(key) }
    }
}

/// One balance held by an account.
public struct ToriiAccountAsset: Decodable, Sendable, Equatable {
    /// Asset definition id.
    public let asset: String
    public let assetName: String?
    public let assetAlias: String?
    /// Balance scope: `global` or `dataspace:<id>`.
    public let scope: String
    public let accountId: String
    public let quantity: KotodamaQuantity

    private enum CodingKeys: String, CodingKey {
        case asset
        case assetName = "asset_name"
        case assetAlias = "asset_alias"
        case scope
        case accountId = "account_id"
        case quantity
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        asset = try container.decode(String.self, forKey: .asset)
        assetName = try container.decodeIfPresent(String.self, forKey: .assetName)
        assetAlias = try container.decodeIfPresent(String.self, forKey: .assetAlias)
        scope = try container.decode(String.self, forKey: .scope)
        accountId = try container.decode(String.self, forKey: .accountId)
        quantity = try decodeQuantity(container, forKey: .quantity)
    }

    /// Filterable and sortable fields.
    public enum Fields {
        public static let asset = ToriiField("asset")
        public static let assetName = ToriiField("asset_name")
        public static let assetAlias = ToriiField("asset_alias")
        public static let scope = ToriiField("scope")
        public static let accountId = ToriiField("account_id")
        public static let quantity = ToriiField("quantity")
    }
}

/// One account holding an asset definition.
public struct ToriiAssetHolder: Decodable, Sendable, Equatable {
    public let accountId: String
    /// Asset definition id.
    public let asset: String
    public let assetAlias: String?
    /// Balance scope: `global` or `dataspace:<id>`.
    public let scope: String
    public let quantity: KotodamaQuantity

    private enum CodingKeys: String, CodingKey {
        case accountId = "account_id"
        case asset
        case assetAlias = "asset_alias"
        case scope
        case quantity
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accountId = try container.decode(String.self, forKey: .accountId)
        asset = try container.decode(String.self, forKey: .asset)
        assetAlias = try container.decodeIfPresent(String.self, forKey: .assetAlias)
        scope = try container.decode(String.self, forKey: .scope)
        quantity = try decodeQuantity(container, forKey: .quantity)
    }

    /// Filterable and sortable fields.
    public enum Fields {
        public static let accountId = ToriiField("account_id")
        public static let asset = ToriiField("asset")
        public static let assetAlias = ToriiField("asset_alias")
        public static let scope = ToriiField("scope")
        public static let quantity = ToriiField("quantity")
    }
}

/// One committed transaction, as listed by `transactions` and
/// `accountTransactions(of:)` in history order (newest first by
/// `blockHeight`, then `blockIndex`).
public struct ToriiTransaction: Decodable, Sendable, Equatable {
    /// Hash of the transaction's entrypoint.
    public let entrypointHash: String
    /// Height of the block that committed the transaction.
    public let blockHeight: UInt64
    /// Position of the transaction within its block.
    public let blockIndex: UInt64
    public let blockHash: String?
    /// Signing account, when the entrypoint has one.
    public let authority: String?
    public let timestampMs: UInt64?
    public let entrypointKind: String?
    public let resultOk: Bool?
    /// Assets the transaction touched (empty when Torii lists none).
    public let assetIds: [String]
    /// Asset definitions the transaction touched (empty when Torii lists none).
    public let assetDefinitionIds: [String]
    public let metadata: ToriiJSONObject

    private enum CodingKeys: String, CodingKey {
        case entrypointHash = "entrypoint_hash"
        case blockHeight = "block_height"
        case blockIndex = "block_index"
        case blockHash = "block_hash"
        case authority
        case timestampMs = "timestamp_ms"
        case entrypointKind = "entrypoint_kind"
        case resultOk = "result_ok"
        case assetIds = "asset_ids"
        case assetDefinitionIds = "asset_definition_ids"
        case metadata
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        entrypointHash = try container.decode(String.self, forKey: .entrypointHash)
        blockHeight = try container.decode(UInt64.self, forKey: .blockHeight)
        blockIndex = try container.decode(UInt64.self, forKey: .blockIndex)
        blockHash = try container.decodeIfPresent(String.self, forKey: .blockHash)
        authority = try container.decodeIfPresent(String.self, forKey: .authority)
        timestampMs = try container.decodeIfPresent(UInt64.self, forKey: .timestampMs)
        entrypointKind = try container.decodeIfPresent(String.self, forKey: .entrypointKind)
        resultOk = try container.decodeIfPresent(Bool.self, forKey: .resultOk)
        assetIds = try decodeStringList(container, forKey: .assetIds)
        assetDefinitionIds = try decodeStringList(container, forKey: .assetDefinitionIds)
        metadata = try decodeMetadata(container, forKey: .metadata)
    }

    /// Filterable fields. History collections cannot be sorted. `assetIds` and
    /// `assetDefinitionIds` are lists that match element-wise: `==`/`in` keep
    /// rows where any element matches, `!=`/`notIn` rows where none does.
    /// Bounds on `blockHeight` in the filter's top-level conjunction also
    /// bound Torii's history scan.
    public enum Fields {
        public static let entrypointHash = ToriiField("entrypoint_hash")
        public static let blockHeight = ToriiField("block_height")
        public static let blockIndex = ToriiField("block_index")
        public static let blockHash = ToriiField("block_hash")
        public static let authority = ToriiField("authority")
        public static let timestampMs = ToriiField("timestamp_ms")
        public static let entrypointKind = ToriiField("entrypoint_kind")
        public static let resultOk = ToriiField("result_ok")
        public static let assetIds = ToriiField("asset_ids")
        public static let assetDefinitionIds = ToriiField("asset_definition_ids")
        public static func metadata(_ key: String) -> ToriiField { .metadata(key) }
    }
}

/// A repo agreement row.
public struct ToriiRepoAgreement: ToriiIdentifiedRow, Equatable {
    /// One leg of the agreement.
    public struct Leg: Decodable, Sendable, Equatable {
        public let assetDefinitionId: String?
        public let quantity: KotodamaQuantity?
        public let metadata: ToriiJSONObject

        private enum CodingKeys: String, CodingKey {
            case assetDefinitionId = "asset_definition_id"
            case quantity
            case metadata
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            assetDefinitionId = try container.decodeIfPresent(String.self, forKey: .assetDefinitionId)
            quantity = try decodeQuantityIfPresent(container, forKey: .quantity)
            metadata = try decodeMetadata(container, forKey: .metadata)
        }
    }

    /// Margin governance of the agreement.
    public struct Governance: Decodable, Sendable, Equatable {
        public let haircutBps: UInt16?
        public let marginFrequencySecs: UInt64?

        private enum CodingKeys: String, CodingKey {
            case haircutBps = "haircut_bps"
            case marginFrequencySecs = "margin_frequency_secs"
        }
    }

    public let id: String
    public let initiator: String?
    public let counterparty: String?
    public let custodian: String?
    public let status: String?
    public let cashSource: String?
    public let cashLeg: Leg?
    public let collateralLeg: Leg?
    public let collateralCustodyAsset: String?
    public let rateBps: UInt16?
    public let maturityTimestampMs: UInt64?
    public let initiatedTimestampMs: UInt64?
    public let lastMarginCheckTimestampMs: UInt64?
    public let settlementTimestampMs: UInt64?
    public let governance: Governance?

    private enum CodingKeys: String, CodingKey {
        case id
        case initiator
        case counterparty
        case custodian
        case status
        case cashSource = "cash_source"
        case cashLeg = "cash_leg"
        case collateralLeg = "collateral_leg"
        case collateralCustodyAsset = "collateral_custody_asset"
        case rateBps = "rate_bps"
        case maturityTimestampMs = "maturity_timestamp_ms"
        case initiatedTimestampMs = "initiated_timestamp_ms"
        case lastMarginCheckTimestampMs = "last_margin_check_timestamp_ms"
        case settlementTimestampMs = "settlement_timestamp_ms"
        case governance
    }

    /// Filterable fields; all of them are sortable.
    public enum Fields {
        public static let id = ToriiField("id")
        public static let initiator = ToriiField("initiator")
        public static let counterparty = ToriiField("counterparty")
        public static let custodian = ToriiField("custodian")
        public static let status = ToriiField("status")
        public static let cashSource = ToriiField("cash_source")
        public static let cashLegAssetDefinitionId = ToriiField("cash_leg.asset_definition_id")
        public static let cashLegQuantity = ToriiField("cash_leg.quantity")
        public static let collateralLegAssetDefinitionId = ToriiField("collateral_leg.asset_definition_id")
        public static let collateralLegQuantity = ToriiField("collateral_leg.quantity")
        public static let collateralCustodyAsset = ToriiField("collateral_custody_asset")
        public static let rateBps = ToriiField("rate_bps")
        public static let maturityTimestampMs = ToriiField("maturity_timestamp_ms")
        public static let initiatedTimestampMs = ToriiField("initiated_timestamp_ms")
        public static let lastMarginCheckTimestampMs = ToriiField("last_margin_check_timestamp_ms")
        public static let settlementTimestampMs = ToriiField("settlement_timestamp_ms")
        public static let governanceHaircutBps = ToriiField("governance.haircut_bps")
        public static let governanceMarginFrequencySecs = ToriiField("governance.margin_frequency_secs")
    }
}

// MARK: - Event-stream fields

/// Fields accepted by the `/v1/events/sse` text filter.
///
/// Event filters use `==` and `in`, combined with `&&` and `||`; `!` only
/// over `txStatus == …` or `blockStatus == …`; and `txBlockHeight.isNull`.
/// Transaction statuses are `Queued`, `Expired`, `Approved` and `Rejected`;
/// block statuses are `Created`, `Approved`, `Rejected`, `Committed` and `Applied`.
///
/// ```swift
/// let filter = ToriiEventFields.txHash == hash
///     && ToriiEventFields.txStatus.in(["Approved", "Rejected"])
/// ```
public enum ToriiEventFields {
    public static let txHash = ToriiField("tx_hash")
    public static let txStatus = ToriiField("tx_status")
    public static let txBlockHeight = ToriiField("tx_block_height")
    public static let txLaneId = ToriiField("tx_lane_id")
    public static let txDataspaceId = ToriiField("tx_dataspace_id")
    public static let blockStatus = ToriiField("block_status")
    public static let blockHeight = ToriiField("block_height")
    public static let proofBackend = ToriiField("proof_backend")
    public static let proofCallHash = ToriiField("proof_call_hash")
    public static let proofEnvelopeHash = ToriiField("proof_envelope_hash")
}

/// An effective permission, including any inherited role grant.
public struct ToriiAccountPermission: Decodable, Sendable, Equatable {
    public let name: String
    public let payload: ToriiJSONValue
}

/// A subscription plan collection row.
public struct ToriiSubscriptionPlanRow: ToriiIdentifiedRow, Equatable {
    public let id: String
    public let provider: String?
    public let billing: ToriiJSONValue?
    public let pricing: ToriiJSONValue?
}

/// A subscription collection row with state fields directly on the row.
public struct ToriiSubscriptionRow: ToriiIdentifiedRow, Equatable {
    public let id: String
    public let ownedBy: String?
    public let planId: String?
    public let provider: String?
    public let subscriber: String?
    public let status: ToriiSubscriptionStatus?
    public let currentPeriodStartMs: UInt64?
    public let currentPeriodEndMs: UInt64?
    public let nextChargeMs: UInt64?
    public let cancelAtPeriodEnd: Bool?
    public let cancelAtMs: UInt64?
    public let failureCount: UInt32?
    public let usageAccumulated: ToriiJSONObject?
    public let billingTriggerId: String?
    public let invoice: ToriiSubscriptionInvoice?
    public let plan: ToriiSubscriptionPlan?

    private enum CodingKeys: String, CodingKey {
        case id, provider, subscriber, status, invoice, plan
        case ownedBy = "owned_by", planId = "plan_id"
        case currentPeriodStartMs = "current_period_start_ms", currentPeriodEndMs = "current_period_end_ms"
        case nextChargeMs = "next_charge_ms", cancelAtPeriodEnd = "cancel_at_period_end"
        case cancelAtMs = "cancel_at_ms", failureCount = "failure_count"
        case usageAccumulated = "usage_accumulated", billingTriggerId = "billing_trigger_id"
    }
}

/// One account movement and its committed ledger position.
public struct ToriiAccountHistoryRow: ToriiIdentifiedRow, Equatable {
    public let id: String
    public let blockHeight: UInt64
    public let blockIndex: UInt64
    public let movementIndex: UInt64
    public let source: String?
    public let type: String?
    public let status: String?
    public let direction: String?
    public let accountId: String?
    public let counterpartyAccountId: String?
    public let assetId: String?
    public let assetDefinitionId: String?
    public let amount: String?
    public let txHash: String?
    public let timestampMs: UInt64?
    public let resultOk: Bool?

    private enum CodingKeys: String, CodingKey {
        case id, source, type, status, direction, amount
        case blockHeight = "block_height", blockIndex = "block_index", movementIndex = "movement_index"
        case accountId = "account_id", counterpartyAccountId = "counterparty_account_id"
        case assetId = "asset_id", assetDefinitionId = "asset_definition_id"
        case txHash = "tx_hash", timestampMs = "timestamp_ms", resultOk = "result_ok"
    }
}
