// Golden vectors of the layers below the entry points: the constants of §3.9
// and their layout mirrors, the asm wrappers of §5.3.7 for `GLOBALID` and
// keccak, the canonical cell shapes of §5.3.2 (`KeyChunk`, `HashChunk`,
// `SnakeBytes`) with their negatives, and the §3 encodings (commitment tree,
// history accumulator, payloads, control leaves) against the committed
// fixtures as `sccp-test-vectors.gen.tolk` renders them. The BLS, SHA-256 and
// certificate vectors are in `sccp-bls.test.tolk`.

import "@stdlib/exotic-cells"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-crypto"
import "@contracts/sccp-errors"
import "@contracts/sccp-finality"
import "@contracts/sccp-messages"
import "@contracts/sccp-verify"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

/// Hashes of the `^KeyChunk` lists of the committees `n4` and `n31`, as
/// `fixtures/sccp/ton_stateinit_v1.json` records them (`initial_data.keys` of
/// its two vectors) and the Rust `ton_cell` builder reproduces them.
// TODO: WP-TON (builder): render these two hashes into
// `sccp-test-vectors.gen.tolk` from the fixture instead of pinning them here.
const KEYS_N4_CELL_HASH = 0xe2cb5ace57ca6670cfa6680b2d16c9dbda5185e4b1d344f11c0df5a22a6ddf46
const KEYS_N31_CELL_HASH = 0x09f03ec9d28f430aeb0f7a8bf8374b53046f3aca9e1fcb1234deff670f2c44d8
/// Rows of the fixtures this suite walks.
const PINNED_CONTROL_LEAVES = 12
const PINNED_TREE_ROOTS = 17
const PINNED_HISTORY_LEAVES = 40

/// The bytes of an ASCII tag as a hash, to compare a tag constant with its text.
fun textHash(text: slice): int {
    return beginCell().storeSlice(text).endCell().hash();
}

/// The hash of a tag constant stored at its width.
fun tagHash(tag: int, bits: int): int {
    return beginCell().storeUint(tag, bits).endCell().hash();
}

/// The canonical keys of the fixture committee whose members are the test
/// keys `indices`.
fun committeeKeys(indices: array<int>): array<slice> {
    val publics = vecKeyPublics();
    var keys: array<slice> = [];
    var i = 0;
    repeat (indices.size()) {
        keys.push(publics.get(indices.get(i)));
        i += 1;
    }
    return keys;
}

/// The exit code of `sccpLoadKeys(list, n)`, or 0 when it returns.
fun loadKeysExit(list: cell, n: int): int {
    try {
        sccpLoadKeys(list, n);
        return 0;
    } catch (e) {
        return e;
    }
}

/// The exit code of `sccpLoadKeysCounted(list)`, or 0 when it returns.
fun loadKeysCountedExit(list: cell): int {
    try {
        sccpLoadKeysCounted(list);
        return 0;
    } catch (e) {
        return e;
    }
}

/// The exit code of `sccpRequireSuccessorKeys(nextKeys, root)`, or 0.
fun successorKeysExit(nextKeys: cell?, root: int): int {
    try {
        sccpRequireSuccessorKeys(nextKeys, root);
        return 0;
    } catch (e) {
        return e;
    }
}

/// The exit code of `sccpRequireStoredCommittee(keys, n, root)`, or 0.
fun storedCommitteeExit(keys: cell, n: int, root: int): int {
    try {
        sccpRequireStoredCommittee(keys, n, root);
        return 0;
    } catch (e) {
        return e;
    }
}

get fun `test globalid is ton mainnet in the emulator`() {
    expect(sccpGlobalId()).toEqual(SCCP_TON_GLOBAL_ID);
}

get fun `test constants are the values of the specification and of the fixtures`() {
    // §3.9 and the layout constants of §3.6–§3.7, as the fixtures state them
    expect(SCCP_MAX_VALIDITY_MS).toEqual(VEC_MAX_VALIDITY_MS);
    expect(SCCP_MAX_FAST_PAUSE_MS).toEqual(VEC_MAX_FAST_PAUSE_MS);
    expect(SCCP_MAX_INIT_SLACK_MS).toEqual(VEC_MAX_INIT_SLACK_MS);
    expect(SCCP_CHECKPOINT_SLOTS).toEqual(VEC_CHECKPOINT_SLOTS);
    expect(SCCP_MAX_VOID_FROZEN_RANGE).toEqual(VEC_MAX_VOID_FROZEN_RANGE);
    expect(SCCP_MAX_HISTORY_SIZE).toEqual(VEC_MAX_HISTORY_SIZE);
    expect(SCCP_X_HEAD_BITS).toEqual(VEC_X_HEAD_BYTES * 8);
    expect(SCCP_X_TAIL_BITS).toEqual(VEC_X_TAIL_BYTES * 8);
    expect(SCCP_X_HEAD_BITS + SCCP_X_TAIL_BITS).toEqual(VEC_X_BYTES * 8);
    // `QC_FIXED` is 116 bytes; its last 4 are the `signers` word of `TairaCert`
    expect(SCCP_QC_FIXED_CELL_BITS).toEqual((VEC_QC_FIXED_BYTES - 4) * 8);
    expect(SCCP_TAIRA_CERT_BITS).toEqual(SCCP_SIGNATURE_BITS + 32);
    expect(SCCP_X_MAGIC).toEqual(VEC_X_MAGIC);
    expect(SCCP_RESULT_TAG).toEqual(VEC_RESULT_TAG);
    expect(SCCP_SIG_TAG).toEqual(VEC_SIG_TAG);
    expect(SCCP_TAG_COMMITTEE_V1).toEqual(VEC_COMMITTEE_TAG);
    // the height is bytes 48..56 of `X`: after the magic and the network id
    expect(SCCP_X_HEIGHT_OFFSET_BITS).toEqual(128 + 256);
    // the domain tags are their ASCII text (§3.3–§3.7)
    expect(tagHash(SCCP_X_MAGIC, 128)).toEqual(textHash("SCCP/FINALITY/V1".literalSlice()));
    expect(
        tagHash(SCCP_TAG_COMMITTEE_V1, SCCP_TAG_COMMITTEE_V1_BITS),
    ).toEqual(textHash("SCCP/COMMITTEE/V1".literalSlice()));
    expect(
        tagHash(SCCP_TAG_LEAF_V1, SCCP_TAG_LEAF_V1_BITS),
    ).toEqual(textHash("SCCP/LEAF/V1".literalSlice()));
    expect(
        tagHash(SCCP_TAG_CONTROL_V1, SCCP_TAG_CONTROL_V1_BITS),
    ).toEqual(textHash("SCCP/CONTROL/V1".literalSlice()));
    expect(
        tagHash(SCCP_TAG_NODE_V1, SCCP_TAG_NODE_V1_BITS),
    ).toEqual(textHash("SCCP/NODE/V1".literalSlice()));
    expect(
        tagHash(SCCP_TAG_HISTORY_V1, SCCP_TAG_HISTORY_V1_BITS),
    ).toEqual(textHash("SCCP/HISTORY/V1".literalSlice()));
    expect(
        tagHash(SCCP_TAG_PAYLOAD_V1, SCCP_TAG_PAYLOAD_V1_BITS),
    ).toEqual(textHash("SCCP/PAYLOAD/V1".literalSlice()));
    expect(
        tagHash(SCCP_TAG_MESSAGE_V1, SCCP_TAG_MESSAGE_V1_BITS),
    ).toEqual(textHash("SCCP/MESSAGE/V1".literalSlice()));
    expect(
        tagHash(SCCP_RESULT_TAG, SCCP_RESULT_TAG_BITS),
    ).toEqual(textHash("iroha/sumeragi/result/v1".literalSlice()));
    expect(
        tagHash(SCCP_SIG_TAG, SCCP_SIG_TAG_BITS),
    ).toEqual(textHash("sumeragi/sig".literalSlice()));
    expect(
        tagHash(SCCP_ASSET_ID_XOR, SCCP_ASSET_ID_XOR_LEN * 8),
    ).toEqual(textHash("xor".literalSlice()));
    expect(
        tagHash(SCCP_ROUTE_ID_TON, SCCP_ROUTE_ID_TON_LEN * 8),
    ).toEqual(textHash("taira_ton_xor".literalSlice()));
    // identity_word(ton-mainnet) = int256(−239), amounts below 2^96, u64 bounds
    expect(SCCP_TON_GLOBAL_ID).toEqual(-239);
    expect(
        SCCP_TON_IDENTITY_WORD,
    ).toEqual(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff - 238);
    expect(SCCP_TON_AMOUNT_LIMIT).toEqual(1 << 96);
    expect(SCCP_MAX_U64).toEqual((1 << 64) - 1);
    expect(SCCP_MAX_ROTATION_FIELD).toEqual((1 << 64) - 2);
    // buckets, snakes and chunked lists
    expect(SCCP_BUCKET_BITS).toEqual(1 << SCCP_BUCKET_SHIFT);
    expect(SCCP_BUCKET_MASK).toEqual(SCCP_BUCKET_BITS - 1);
    expect(SCCP_MAX_VOID_FROZEN_RANGE).toEqual(SCCP_BUCKET_BITS);
    expect(SCCP_SNAKE_CHUNK_BITS).toEqual(SCCP_SNAKE_CHUNK_BYTES * 8);
    expect(SCCP_MAX_BLOCK_LEAVES).toEqual(1 << SCCP_MAX_BLOCK_PATH);
    expect(SCCP_MAX_HISTORY_SIZE).toEqual(1 << SCCP_MAX_HISTORY_PATH);
    expect(SCCP_KEYS_PER_CHUNK * SCCP_KEY_BITS + 1 <= 1023).toBeTrue();
    expect(SCCP_HASHES_PER_CHUNK * 256 + 1 <= 1023).toBeTrue();
    expect(
        SCCP_MAX_KEY_CHUNKS,
    ).toEqual((SCCP_MAX_COMMITTEE_SIZE + SCCP_KEYS_PER_CHUNK - 1) / SCCP_KEYS_PER_CHUNK);
    // the data bits of the proof cells of §5.3.2
    expect(SCCP_BLOCK_REF_BITS).toEqual(64 + 256 + 32 + 64 + 8 + 1);
    expect(SCCP_MESSAGE_PROOF_BITS).toEqual(32 + 8 + 1);
    expect(SCCP_CONTROL_PROOF_BITS).toEqual(64 + 8 + 1 + 64 + 256 + 256 + 32 + 8 + 1);
}

get fun `test keccak256 wrappers match ethereum keccak`() {
    expect(
        keccak256Parts([]),
    ).toEqual(0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470);
    // node(l, r) = keccak256("SCCP/NODE/V1" ‖ l ‖ r) of `commitment_tree_v1.json`
    // through every wrapper, however the 76 bytes are split
    val whole = beginCell()
        .storeSlice("SCCP/NODE/V1".literalSlice())
        .storeUint(VEC_NODE_LEFT, 256)
        .storeUint(VEC_NODE_RIGHT, 256);
    expect(keccak256Builder(whole)).toEqual(VEC_NODE);
    val head = beginCell().storeSlice("SCCP/NODE/V1".literalSlice()).storeUint(VEC_NODE_LEFT, 256);
    val tail = beginCell().storeUint(VEC_NODE_RIGHT, 256);
    expect(keccak256Builders2(head, tail)).toEqual(VEC_NODE);
    expect(
        keccak256Slices2(head.endCell().beginParse(), tail.endCell().beginParse()),
    ).toEqual(VEC_NODE);
    expect(
        keccak256Parts(
            [
                "SCCP/".literalSlice(),
                beginCell().storeSlice("NODE/V1".literalSlice()),
                beginCell().storeUint(VEC_NODE_LEFT, 256).endCell().beginParse(),
                tail,
            ],
        ),
    ).toEqual(VEC_NODE);
    expect(sccpNode(VEC_NODE_LEFT, VEC_NODE_RIGHT)).toEqual(VEC_NODE);
    // the order of the children matters
    expect(sccpNode(VEC_NODE_RIGHT, VEC_NODE_LEFT) == VEC_NODE).toBeFalse();
}

// ---------------------------------------------------------------------------
// `KeyChunk` lists (§5.3.1, §3.7).

get fun `test key chunks of the fixture committees are the canonical lists`() {
    val committees: array<[array<slice>, int]> = [
        [committeeKeys(vecCommitteeN4()), VEC_COMMITTEE_N4_ROOT],
        [committeeKeys(vecCommitteeN4Other()), VEC_COMMITTEE_N4_OTHER_ROOT],
        [committeeKeys(vecCommitteeN7()), VEC_COMMITTEE_N7_ROOT],
        [committeeKeys(vecCommitteeN31()), VEC_COMMITTEE_N31_ROOT],
    ];
    var c = 0;
    repeat (committees.size()) {
        val [keys, root] = committees.get(c);
        val n = keys.size();
        val list = sccpBuildKeys(keys);
        // two keys per chunk, the last chunk one or two, linked by a Maybe ref
        val chunks = (n + 1) / 2;
        expect(list.depth()).toEqual(chunks - 1);
        var cs = list.beginParse();
        var walked = 0;
        var key = 0;
        repeat (chunks) {
            val isLast = walked == chunks - 1;
            val held = isLast ? n - 2 * walked : 2;
            expect(cs.remainingBitsCount()).toEqual(held * SCCP_KEY_BITS + 1);
            expect(cs.remainingRefsCount()).toEqual(isLast ? 0 : 1);
            repeat (held) {
                expect(cs.loadBits(SCCP_KEY_BITS).hash()).toEqual(keys.get(key).hash());
                key += 1;
            }
            expect(cs.loadUint(1)).toEqual(isLast ? 0 : 1);
            if (!isLast) {
                cs = cs.preloadRef().beginParse();
            }
            walked += 1;
        }
        expect(key).toEqual(n);
        // both parsers read the list back: the keys as 384-bit slices and the
        // data bits of each chunk, which are the root preimage after its head
        val parsed = sccpLoadKeys(list, n);
        expect(parsed.keys.size()).toEqual(n);
        expect(parsed.parts.size()).toEqual(chunks);
        expect(sccpBuildKeys(parsed.keys).hash()).toEqual(list.hash());
        expect(sccpCommitteeRoot(n, parsed.parts)).toEqual(root);
        val (counted, count) = sccpLoadKeysCounted(list);
        expect(count).toEqual(n);
        expect(sccpCommitteeRoot(count, counted.parts)).toEqual(root);
        expect(parsed.keys.get(n - 1).remainingBitsCount()).toEqual(SCCP_KEY_BITS);
        // the committee rules hold for it: size, strict order and root
        sccpRequireCommittee(parsed, n, root);
        sccpRequireStoredCommittee(list, n, root);
        expect(sccpRequireSuccessorKeys(list, root)).toEqual(n);
        c += 1;
    }
    expect(c).toEqual(4);
    // the cells are the ones the StateInit golden and the Rust builder pin
    expect(sccpBuildKeys(committeeKeys(vecCommitteeN4())).hash()).toEqual(KEYS_N4_CELL_HASH);
    expect(sccpBuildKeys(committeeKeys(vecCommitteeN31())).hash()).toEqual(KEYS_N31_CELL_HASH);
    expect(sccpBuildKeys(committeeKeys(vecCommitteeN31())).depth()).toEqual(
        SCCP_MAX_KEY_CHUNKS - 1,
    );
    // the synthetic committee of the §3.7 example has its root too
    val synthetic = vecSyntheticCommitteeKeys();
    expect(
        sccpCommitteeRoot(
            synthetic.size(),
            sccpLoadKeys(sccpBuildKeys(synthetic), synthetic.size()).parts,
        ),
    ).toEqual(VEC_SYNTHETIC_COMMITTEE_ROOT);
}

/// A `KeyChunk` with the test keys `first .. first + count − 1` and `next`.
fun keyChunk(first: int, count: int, next: cell?): cell {
    val publics = vecKeyPublics();
    var b = beginCell();
    var i = 0;
    repeat (count) {
        b.storeSlice(publics.get(first + i));
        i += 1;
    }
    return b.storeMaybeRef(next).endCell();
}

get fun `test key chunk lists accept only the canonical shape`() {
    // the canonical list of five keys: 2 + 2 + 1
    val canonical = keyChunk(0, 2, keyChunk(2, 2, keyChunk(4, 1, null)));
    expect(sccpLoadKeys(canonical, 5).keys.size()).toEqual(5);
    expect(sccpLoadKeysCounted(canonical).1).toEqual(5);
    // a list read for another length
    expect(loadKeysExit(canonical, 4)).toEqual(SccpErrors.BadSnake as int);
    expect(loadKeysExit(canonical, 6)).toEqual(SccpErrors.BadSnake as int);
    expect(loadKeysExit(canonical, 7)).toEqual(SccpErrors.BadSnake as int);
    val publics = vecKeyPublics();
    val shapes: array<cell> = [
        // a chunk of one key that is not the last: 1 + 2 + 2
        keyChunk(0, 1, keyChunk(1, 2, keyChunk(3, 2, null))),
        // a last chunk without a key
        keyChunk(0, 2, keyChunk(2, 2, keyChunk(4, 0, null))),
        // a key of 383 bits
        beginCell()
            .storeSlice(publics.get(0))
            .storeUint(0, 255)
            .storeUint(0, 128)
            .storeUint(0, 1)
            .endCell(),
        // a key with a byte after it
        beginCell().storeSlice(publics.get(0)).storeUint(0, 8).storeUint(0, 1).endCell(),
        // the Maybe bit set without a next chunk
        beginCell().storeSlice(publics.get(0)).storeSlice(publics.get(1)).storeUint(1, 1).endCell(),
        // a next chunk without the Maybe bit
        beginCell()
            .storeSlice(publics.get(0))
            .storeSlice(publics.get(1))
            .storeUint(0, 1)
            .storeRef(keyChunk(2, 1, null))
            .endCell(),
        // a second reference
        beginCell()
            .storeSlice(publics.get(0))
            .storeSlice(publics.get(1))
            .storeUint(1, 1)
            .storeRef(keyChunk(2, 1, null))
            .storeRef(createEmptyCell())
            .endCell(),
        // no key at all
        createEmptyCell(),
    ];
    var i = 0;
    repeat (shapes.size()) {
        val shape = shapes.get(i);
        expect(loadKeysExit(shape, 5)).toEqual(SccpErrors.BadSnake as int);
        expect(loadKeysCountedExit(shape)).toEqual(SccpErrors.BadSnake as int);
        // `next_keys` in such a shape never becomes a committee
        expect(successorKeysExit(shape, 1)).toEqual(SccpErrors.BadSnake as int);
        i += 1;
    }
    expect(i).toEqual(8);
}

get fun `test a key chunk list of more than 16 chunks is BadCommittee`() {
    val publics = vecKeyPublics();
    // 16 chunks hold at most 32 keys and are walked to their end
    var list: cell? = null;
    var chunk = SCCP_MAX_KEY_CHUNKS - 1;
    repeat (SCCP_MAX_KEY_CHUNKS) {
        list = keyChunk(2 * chunk, 2, list);
        chunk -= 1;
    }
    val (parsed, n) = sccpLoadKeysCounted(list!);
    expect(n).toEqual(2 * SCCP_MAX_KEY_CHUNKS);
    expect(parsed.parts.size()).toEqual(SCCP_MAX_KEY_CHUNKS);
    // 32 keys are no committee size
    expect(sccpIsCommitteeSize(n)).toBeFalse();
    expect(successorKeysExit(list, 1)).toEqual(SccpErrors.BadCommittee as int);
    // a 17th chunk is refused before it is loaded, whatever it holds
    val longer = beginCell()
        .storeSlice(publics.get(33))
        .storeSlice(publics.get(34))
        .storeUint(1, 1)
        .storeRef(list!)
        .endCell();
    expect(longer.depth()).toEqual(SCCP_MAX_KEY_CHUNKS);
    expect(loadKeysCountedExit(longer)).toEqual(SccpErrors.BadCommittee as int);
    var endless: cell = beginCell().storeUint(1, 4).endCell();
    repeat (SCCP_MAX_KEY_CHUNKS) {
        endless = keyChunk(0, 2, endless);
    }
    expect(loadKeysCountedExit(endless)).toEqual(SccpErrors.BadCommittee as int);
    expect(successorKeysExit(endless, 1)).toEqual(SccpErrors.BadCommittee as int);
}

get fun `test committee rules refuse a bad size, order or root`() {
    val keys = committeeKeys(vecCommitteeN4());
    val list = sccpBuildKeys(keys);
    val root = VEC_COMMITTEE_N4_ROOT;
    // another root, and the list read under the root of another committee
    expect(storedCommitteeExit(list, 4, root + 1)).toEqual(SccpErrors.BadCommittee as int);
    expect(
        successorKeysExit(list, VEC_COMMITTEE_N4_OTHER_ROOT),
    ).toEqual(SccpErrors.BadCommittee as int);
    // the stored size must be the size of the list
    expect(storedCommitteeExit(list, 7, root)).toEqual(SccpErrors.BadSnake as int);
    // a missing list
    expect(successorKeysExit(null, root)).toEqual(SccpErrors.BadCommittee as int);
    // sizes that are not 3f + 1 between 4 and 31: canonical keys under their own root
    val sizes: array<int> = [
        1,
        2,
        3,
        5,
        6,
        8,
        30,
        32,
    ];
    var i = 0;
    repeat (sizes.size()) {
        val n = sizes.get(i);
        val sized = sccpBuildKeys(testCommittee(n, 0).keys);
        val own = sccpCommitteeRoot(n, sccpLoadKeys(sized, n).parts);
        expect(sccpIsCommitteeSize(n)).toBeFalse();
        expect(successorKeysExit(sized, own)).toEqual(SccpErrors.BadCommittee as int);
        expect(storedCommitteeExit(sized, n, own)).toEqual(SccpErrors.BadCommittee as int);
        i += 1;
    }
    // every size 3f + 1 from 4 to 31 is one
    var f = 1;
    repeat (10) {
        val n = 3 * f + 1;
        val sized = sccpBuildKeys(testCommittee(n, 0).keys);
        expect(sccpIsCommitteeSize(n)).toBeTrue();
        expect(
            successorKeysExit(sized, sccpCommitteeRoot(n, sccpLoadKeys(sized, n).parts)),
        ).toEqual(0);
        f += 1;
    }
    expect(3 * (f - 1) + 1).toEqual(SCCP_MAX_COMMITTEE_SIZE);
    // descending and duplicate keys under the root of the keys as listed
    val orders: array<array<slice>> = [
        [keys.get(1), keys.get(0), keys.get(2), keys.get(3)],
        [keys.get(0), keys.get(1), keys.get(3), keys.get(2)],
        [keys.get(0), keys.get(0), keys.get(2), keys.get(3)],
        [keys.get(0), keys.get(1), keys.get(2), keys.get(2)],
    ];
    i = 0;
    repeat (orders.size()) {
        val listed = orders.get(i);
        val unordered = sccpBuildKeys(listed);
        val own = sccpCommitteeRoot(4, sccpLoadKeys(unordered, 4).parts);
        expect(sccpKeysAscend(listed)).toBeFalse();
        expect(storedCommitteeExit(unordered, 4, own)).toEqual(SccpErrors.BadCommittee as int);
        expect(successorKeysExit(unordered, own)).toEqual(SccpErrors.BadCommittee as int);
        i += 1;
    }
    expect(sccpKeysAscend(keys)).toBeTrue();
}

get fun `test canonical parsers reject library cells with canonical content`() {
    // the ordinary encodings parse
    val keys4 = sccpBuildKeys(committeeKeys(vecCommitteeN4()));
    expect(sccpLoadKeys(keys4, 4).keys.size()).toEqual(4);
    val hashes: array<int> = [1, 2, 3, 4];
    val path = sccpBuildHashPath(hashes)!;
    expect(sccpLoadHashPath(path, 4, 9)).toEqual(hashes);
    val snake = snakeOfLength(200);
    expect(sccpParseSnakeBytes(snake, 4096, SccpErrors.BadPayload).1).toEqual(200);
    // a published library with the same content is refused at every depth
    testing.registerLibrary(keys4);
    testing.registerLibrary(path);
    testing.registerLibrary(snake);
    val keysTail = keys4.beginParse().preloadRef();
    testing.registerLibrary(keysTail);
    val pathTail = path.beginParse().preloadRef();
    testing.registerLibrary(pathTail);
    val snakeTail = snake.beginParse().preloadRef();
    testing.registerLibrary(snakeTail);
    // `CTOS` alone would resolve the library reference to the canonical list
    val keyCases: array<cell> = [
        keys4.toLibraryReference(),
        beginCell()
            .storeSlice(keys4.beginParse().preloadBits(2 * SCCP_KEY_BITS))
            .storeMaybeRef(keysTail.toLibraryReference())
            .endCell(),
    ];
    var i = 0;
    while (i < keyCases.size()) {
        expect(loadKeysExit(keyCases.get(i), 4)).toEqual(SccpErrors.BadSnake as int);
        expect(loadKeysCountedExit(keyCases.get(i))).toEqual(SccpErrors.BadSnake as int);
        expect(
            storedCommitteeExit(keyCases.get(i), 4, VEC_COMMITTEE_N4_ROOT),
        ).toEqual(SccpErrors.BadSnake as int);
        expect(
            successorKeysExit(keyCases.get(i), VEC_COMMITTEE_N4_ROOT),
        ).toEqual(SccpErrors.BadSnake as int);
        i += 1;
    }
    val pathCases: array<cell> = [
        path.toLibraryReference(),
        beginCell()
            .storeUint(1, 256)
            .storeUint(2, 256)
            .storeUint(3, 256)
            .storeMaybeRef(pathTail.toLibraryReference())
            .endCell(),
    ];
    i = 0;
    while (i < pathCases.size()) {
        try {
            sccpLoadHashPath(pathCases.get(i), 4, 9);
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadSnake as int);
        }
        i += 1;
    }
    val snakeCases: array<cell> = [
        snake.toLibraryReference(),
        beginCell()
            .storeSlice(snake.beginParse().preloadBits(SCCP_SNAKE_CHUNK_BITS))
            .storeRef(snakeTail.toLibraryReference())
            .endCell(),
    ];
    i = 0;
    while (i < snakeCases.size()) {
        try {
            sccpParseSnakeBytes(snakeCases.get(i), 4096, SccpErrors.BadPayload);
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadSnake as int);
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// Control leaves (§3.4).

get fun `test the control leaf preimage of every fixture row has the layout of the specification`() {
    expect(VEC_CONTROL_LEAF_COUNT).toEqual(PINNED_CONTROL_LEAVES);
    var row = 0;
    repeat (VEC_CONTROL_LEAF_COUNT) {
        val leaf = vecControlLeaf(row);
        // b1 (125 bytes): tag ‖ lane_bytes(sora-taira, ton-mainnet) ‖
        // destination_word ‖ be32 revision ‖ be64 nonce
        var b1 = leaf.b1;
        expect(b1.remainingBitsCount()).toEqual(125 * 8);
        expect(b1.loadUint(SCCP_TAG_CONTROL_V1_BITS)).toEqual(SCCP_TAG_CONTROL_V1);
        expect(b1.loadUint(8)).toEqual(SCCP_TAG_TAIRA);
        expect(b1.loadUint(256)).toEqual(VEC_NETWORK_ID);
        expect(b1.loadUint(8)).toEqual(SCCP_TAG_TON);
        expect(b1.loadUint(256)).toEqual(SCCP_TON_IDENTITY_WORD);
        expect(b1.loadUint(256)).toEqual(VEC_MINTER_ACCOUNT_ID);
        expect(b1.loadUint(32)).toEqual(leaf.routeRevision);
        expect(b1.loadUint(64)).toEqual(leaf.controlNonce);
        expect(b1.isEndOfBits()).toBeTrue();
        // b2 (74 bytes): u8 track ‖ u8 parliament_paused ‖ be64
        // fast_pause_until_ms ‖ certificate_id ‖ effect_hash
        var b2 = leaf.b2;
        expect(b2.remainingBitsCount()).toEqual(74 * 8);
        expect(b2.loadUint(8)).toEqual(leaf.track);
        expect(b2.loadUint(8)).toEqual(leaf.parliamentPaused ? 1 : 0);
        expect(b2.loadUint(64)).toEqual(leaf.fastPauseUntilMs);
        expect(b2.loadUint(256)).toEqual(leaf.certificateId);
        expect(b2.loadUint(256)).toEqual(leaf.effectHash);
        expect(b2.isEndOfBits()).toBeTrue();
        // the leaf is the keccak of the 199 bytes, however they are split
        expect(keccak256Slices2(leaf.b1, leaf.b2)).toEqual(leaf.leaf);
        var rest = leaf.b1;
        val tag = rest.loadBits(SCCP_TAG_CONTROL_V1_BITS);
        expect(keccak256Parts([tag, rest, leaf.b2])).toEqual(leaf.leaf);
        expect(
            sccpControlLeaf(
                VEC_NETWORK_ID,
                VEC_MINTER_ACCOUNT_ID,
                leaf.routeRevision,
                leaf.controlNonce,
                leaf.track,
                leaf.parliamentPaused,
                leaf.fastPauseUntilMs,
                leaf.certificateId,
                leaf.effectHash,
            ),
        ).toEqual(leaf.leaf);
        // every row satisfies the §3.4 constraints a destination checks
        sccpCheckControl(leaf.track, leaf.fastPauseUntilMs, leaf.certificateId, leaf.effectHash);
        // a control leaf is no transfer leaf of the same words
        expect(
            sccpTransferLeaf(leaf.certificateId, VEC_MINTER_ACCOUNT_ID) == leaf.leaf,
        ).toBeFalse();
        row += 1;
    }
    expect(row).toEqual(PINNED_CONTROL_LEAVES);
}

/// The exit code of `sccpCheckControl`, or 0 when the fields pass.
fun checkControlExit(track: int, fastPauseUntilMs: int, certificateId: int, effectHash: int): int {
    try {
        sccpCheckControl(track, fastPauseUntilMs, certificateId, effectHash);
        return 0;
    } catch (e) {
        return e;
    }
}

get fun `test the control constraints and the fast pause clamp`() {
    val bad = SccpErrors.BadControl as int;
    // track ∈ {1, 2}
    expect(checkControlExit(SCCP_TRACK_PARLIAMENT, 0, 1, 1)).toEqual(0);
    expect(checkControlExit(SCCP_TRACK_FAST_PAUSE, 1, 1, 1)).toEqual(0);
    expect(checkControlExit(0, 0, 1, 1)).toEqual(bad);
    expect(checkControlExit(3, 1, 1, 1)).toEqual(bad);
    expect(checkControlExit(255, 1, 1, 1)).toEqual(bad);
    // track 2 names an expiry; track 1 may carry one
    expect(checkControlExit(SCCP_TRACK_FAST_PAUSE, 0, 1, 1)).toEqual(bad);
    expect(checkControlExit(SCCP_TRACK_PARLIAMENT, SCCP_MAX_U64, 1, 1)).toEqual(0);
    // certificate id and effect hash are nonzero
    expect(checkControlExit(SCCP_TRACK_PARLIAMENT, 0, 0, 1)).toEqual(bad);
    expect(checkControlExit(SCCP_TRACK_PARLIAMENT, 0, 1, 0)).toEqual(bad);
    expect(checkControlExit(SCCP_TRACK_FAST_PAUSE, 1, 0, 0)).toEqual(bad);
    // min(leaf value, min(now_ms + MAX_FAST_PAUSE_MS, 2^64 − 1))
    val nowMs = T0 * 1000;
    expect(sccpAppliedFastPauseUntilMs(0, nowMs)).toEqual(0);
    expect(sccpAppliedFastPauseUntilMs(nowMs + 5, nowMs)).toEqual(nowMs + 5);
    expect(
        sccpAppliedFastPauseUntilMs(nowMs + SCCP_MAX_FAST_PAUSE_MS, nowMs),
    ).toEqual(nowMs + SCCP_MAX_FAST_PAUSE_MS);
    expect(
        sccpAppliedFastPauseUntilMs(nowMs + SCCP_MAX_FAST_PAUSE_MS + 1, nowMs),
    ).toEqual(nowMs + SCCP_MAX_FAST_PAUSE_MS);
    expect(sccpAppliedFastPauseUntilMs(SCCP_MAX_U64, nowMs)).toEqual(
        nowMs + SCCP_MAX_FAST_PAUSE_MS,
    );
    // the sum saturates at the top of u64
    expect(sccpAppliedFastPauseUntilMs(SCCP_MAX_U64, SCCP_MAX_U64 - 5)).toEqual(SCCP_MAX_U64);
    expect(sccpAppliedFastPauseUntilMs(SCCP_MAX_U64 - 1, SCCP_MAX_U64)).toEqual(SCCP_MAX_U64 - 1);
    // the effective pause: parliamentPaused ∨ now_ms < fastPauseUntilMs
    expect(sccpEffectivePause(false, 0, nowMs)).toBeFalse();
    expect(sccpEffectivePause(true, 0, nowMs)).toBeTrue();
    expect(sccpEffectivePause(false, nowMs + 1, nowMs)).toBeTrue();
    expect(sccpEffectivePause(false, nowMs, nowMs)).toBeFalse();
}

// ---------------------------------------------------------------------------
// Payloads and message ids (§3.2, §3.3).

get fun `test the inbound payload vector parses to its fields, hash and message id`() {
    val payload = snakeFromPieces(vecInboundPayloadPieces());
    val parsed = sccpParseInboundPayload(payload, VEC_INBOUND_REVISION, VEC_MINTER_ACCOUNT_ID);
    expect(parsed.nonce).toEqual(VEC_INBOUND_NONCE);
    expect(parsed.deadlineMs).toEqual(VEC_INBOUND_DEADLINE_MS);
    expect(parsed.amount).toEqual(VEC_INBOUND_AMOUNT);
    expect(parsed.recipientHash).toEqual(VEC_INBOUND_RECIPIENT);
    expect(parsed.payloadHash).toEqual(VEC_INBOUND_PAYLOAD_HASH);
    val messageId = sccpInboundMessageId(VEC_NETWORK_ID, parsed.payloadHash);
    expect(messageId).toEqual(VEC_INBOUND_MESSAGE_ID);
    // the lane enters the id: the same hash on the TON→Taira lane is another message
    expect(sccpOutboundMessageId(VEC_NETWORK_ID, parsed.payloadHash) == messageId).toBeFalse();
    expect(sccpInboundMessageId(VEC_NETWORK_ID + 1, parsed.payloadHash) == messageId).toBeFalse();
    // transfer_leaf = keccak256("SCCP/LEAF/V1" ‖ message_id ‖ destination_word)
    expect(sccpTransferLeaf(messageId, VEC_MINTER_ACCOUNT_ID)).toEqual(
        keccak256Builder(
            beginCell()
                .storeSlice("SCCP/LEAF/V1".literalSlice())
                .storeUint(messageId, 256)
                .storeUint(VEC_MINTER_ACCOUNT_ID, 256),
        ),
    );
    // the payload is for one revision and never for the minter itself
    try {
        sccpParseInboundPayload(payload, VEC_INBOUND_REVISION + 1, VEC_MINTER_ACCOUNT_ID);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadPayload as int);
    }
    try {
        sccpParseInboundPayload(payload, VEC_INBOUND_REVISION, VEC_INBOUND_RECIPIENT);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadRecipient as int);
    }
}

get fun `test the outbound payload vector is what the minter builds for a burn`() {
    val recipient = snakeFromPieces(vecOutboundRecipientPieces());
    val (chunks, len) = sccpParseSnakeBytes(
        recipient,
        SCCP_MAX_TAIRA_ACCOUNT_BYTES,
        SccpErrors.BadRecipient,
    );
    expect(len).toEqual(35);
    val built = sccpBuildOutboundPayload(
        VEC_OUTBOUND_NONCE,
        VEC_OUTBOUND_REVISION,
        VEC_OUTBOUND_AMOUNT,
        VEC_OUTBOUND_SENDER,
        chunks,
        len,
    );
    expect(built.payloadHash).toEqual(VEC_OUTBOUND_PAYLOAD_HASH);
    expect(built.cell.hash()).toEqual(snakeFromPieces(vecOutboundPayloadPieces()).hash());
    expect(sccpOutboundMessageId(VEC_NETWORK_ID, built.payloadHash)).toEqual(
        VEC_OUTBOUND_MESSAGE_ID,
    );
    // every field enters the hash
    expect(
        sccpBuildOutboundPayload(
            VEC_OUTBOUND_NONCE + 1,
            VEC_OUTBOUND_REVISION,
            VEC_OUTBOUND_AMOUNT,
            VEC_OUTBOUND_SENDER,
            chunks,
            len,
        ).payloadHash ==
            VEC_OUTBOUND_PAYLOAD_HASH,
    ).toBeFalse();
    // the largest payload: a 1024-byte recipient gives 1138 bytes in 9 chunks
    val (largest, largestLen) = sccpParseSnakeBytes(
        snakeOfLength(SCCP_MAX_TAIRA_ACCOUNT_BYTES),
        SCCP_MAX_TAIRA_ACCOUNT_BYTES,
        SccpErrors.BadRecipient,
    );
    val (payloadChunks, payloadLen) = sccpParseSnakeBytes(
        sccpBuildOutboundPayload(
            SCCP_MAX_U64 - 1,
            0xFFFFFFFF,
            SCCP_TON_AMOUNT_LIMIT - 1,
            VEC_OUTBOUND_SENDER,
            largest,
            largestLen,
        ).cell,
        SCCP_MAX_PAYLOAD_BYTES,
        SccpErrors.BadPayload,
    );
    expect(payloadLen).toEqual(1138);
    expect(payloadChunks.size()).toEqual(9);
}

// ---------------------------------------------------------------------------
// Commitment trees and the history accumulator (§3.4, §3.5).

get fun `test the tree vectors: roots of 1 to 17 leaves, paths and the 512-leaf tree`() {
    val leaves = vecTreeLeaves();
    val roots = vecTreeRoots();
    expect(leaves.size()).toEqual(PINNED_TREE_ROOTS);
    expect(roots.size()).toEqual(PINNED_TREE_ROOTS);
    expect(sccpNode(leaves.get(0), leaves.get(1))).toEqual(roots.get(1));
    // every count 1..=17: the promote-odd root, and every index proves under it
    var count = 1;
    repeat (PINNED_TREE_ROOTS) {
        var first: array<int> = [];
        var i = 0;
        repeat (count) {
            first.push(leaves.get(i));
            i += 1;
        }
        val root = roots.get(count - 1);
        expect(treeRoot(first)).toEqual(root);
        i = 0;
        repeat (count) {
            expect(sccpMerkleRoot(first.get(i), i, count, treePath(first, i))).toEqual(root);
            i += 1;
        }
        count += 1;
    }
    // the paths of the tree of five leaves, as the fixture lists them
    var five: array<int> = [];
    var k = 0;
    repeat (5) {
        five.push(leaves.get(k));
        k += 1;
    }
    k = 0;
    repeat (5) {
        expect(treePath(five, k)).toEqual(vecTree5Path(k));
        expect(sccpMerkleRoot(five.get(k), k, 5, vecTree5Path(k))).toEqual(roots.get(4));
        k += 1;
    }
    // leaf 4 of 5 is promoted twice: its path is one sibling
    expect(vecTree5Path(4).size()).toEqual(1);
    expect(vecTree5Path(0).size()).toEqual(3);
    // the last leaf of the largest block: nine siblings
    val fullPath = vecTreeFullLastPath();
    expect(fullPath.size()).toEqual(SCCP_MAX_BLOCK_PATH);
    expect(
        sccpMerkleRoot(
            VEC_TREE_FULL_LAST_LEAF,
            SCCP_MAX_BLOCK_LEAVES - 1,
            SCCP_MAX_BLOCK_LEAVES,
            fullPath,
        ),
    ).toEqual(VEC_TREE_FULL_ROOT);
    // through `sccpVerifyLeaf`, with the path in its `HashChunk` cells
    sccpVerifyLeaf(
        VEC_TREE_FULL_LAST_LEAF,
        SCCP_MAX_BLOCK_LEAVES - 1,
        SCCP_MAX_BLOCK_PATH,
        sccpBuildHashPath(fullPath),
        VEC_TREE_FULL_ROOT,
        SCCP_MAX_BLOCK_LEAVES,
    );
    try {
        sccpVerifyLeaf(
            VEC_TREE_FULL_LAST_LEAF,
            SCCP_MAX_BLOCK_LEAVES - 2,
            SCCP_MAX_BLOCK_PATH,
            sccpBuildHashPath(fullPath),
            VEC_TREE_FULL_ROOT,
            SCCP_MAX_BLOCK_LEAVES,
        );
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadProof as int);
    }
}

get fun `test the history vectors: the leaf, the root of 40 leaves and its paths`() {
    expect(
        sccpHistoryLeaf(VEC_HISTORY_HEIGHT, VEC_HISTORY_SCCP_ROOT, VEC_HISTORY_MESSAGE_COUNT),
    ).toEqual(VEC_HISTORY_LEAF);
    // history_leaf = keccak256("SCCP/HISTORY/V1" ‖ be64 height ‖ sccp_root ‖ be32 count)
    expect(VEC_HISTORY_LEAF).toEqual(
        keccak256Builder(
            beginCell()
                .storeSlice("SCCP/HISTORY/V1".literalSlice())
                .storeUint(VEC_HISTORY_HEIGHT, 64)
                .storeUint(VEC_HISTORY_SCCP_ROOT, 256)
                .storeUint(VEC_HISTORY_MESSAGE_COUNT, 32),
        ),
    );
    val leaves = vecHistoryLeaves();
    expect(leaves.size()).toEqual(PINNED_HISTORY_LEAVES);
    expect(leaves.get(0)).toEqual(VEC_HISTORY_LEAF);
    // the accumulator is the same promote-odd tree over the history leaves
    expect(treeRoot(leaves)).toEqual(VEC_HISTORY_ROOT);
    val firstPath = vecHistoryFirstPath();
    val lastPath = vecHistoryLastPath();
    expect(treePath(leaves, 0)).toEqual(firstPath);
    expect(treePath(leaves, PINNED_HISTORY_LEAVES - 1)).toEqual(lastPath);
    expect(sccpMerkleRoot(leaves.get(0), 0, PINNED_HISTORY_LEAVES, firstPath)).toEqual(
        VEC_HISTORY_ROOT,
    );
    expect(
        sccpMerkleRoot(
            leaves.get(PINNED_HISTORY_LEAVES - 1),
            PINNED_HISTORY_LEAVES - 1,
            PINNED_HISTORY_LEAVES,
            lastPath,
        ),
    ).toEqual(VEC_HISTORY_ROOT);
    // a block reference to the first entry under a header that certifies this history
    var x = emptyX(VEC_NETWORK_ID, TEST_GENERATION, 1, VEC_HISTORY_HEIGHT + 1000);
    x.historySize = PINNED_HISTORY_LEAVES;
    x.historyRoot = VEC_HISTORY_ROOT;
    val (header, _, _) = sccpParseX(x.toCell(), VEC_NETWORK_ID);
    val (sccpRoot, messageCount) = sccpCheckBlockRef(
        blockRefCell(
            VEC_HISTORY_HEIGHT,
            VEC_HISTORY_SCCP_ROOT,
            VEC_HISTORY_MESSAGE_COUNT,
            0,
            firstPath,
        ),
        header,
    );
    expect(sccpRoot).toEqual(VEC_HISTORY_SCCP_ROOT);
    expect(messageCount).toEqual(VEC_HISTORY_MESSAGE_COUNT);
    // the same entry does not prove at another index or under another count
    try {
        sccpCheckBlockRef(
            blockRefCell(
                VEC_HISTORY_HEIGHT,
                VEC_HISTORY_SCCP_ROOT,
                VEC_HISTORY_MESSAGE_COUNT + 1,
                0,
                firstPath,
            ),
            header,
        );
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadProof as int);
    }
    try {
        sccpCheckBlockRef(
            blockRefCell(
                VEC_HISTORY_HEIGHT,
                VEC_HISTORY_SCCP_ROOT,
                VEC_HISTORY_MESSAGE_COUNT,
                1,
                firstPath,
            ),
            header,
        );
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadProof as int);
    }
}

get fun `test merkle verification rejects bad index, count and path length`() {
    val leaves = vecTreeLeaves();
    val path = vecTree5Path(3);
    val root = vecTreeRoots().get(4);
    expect(sccpMerkleRoot(leaves.get(3), 3, 5, path)).toEqual(root);
    val bad: array<[int, int]> = [[5, 5], [3, 0], [3, 4], [-1, 5]];
    var i = 0;
    while (i < bad.size()) {
        val [index, count] = bad.get(i);
        try {
            val other = sccpMerkleRoot(leaves.get(3), index, count, path);
            expect(other == root).toBeFalse();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadProof as int);
        }
        i += 1;
    }
    var longer = path;
    longer.push(1);
    try {
        sccpMerkleRoot(leaves.get(3), 3, 5, longer);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadProof as int);
    }
}

get fun `test hash paths are canonical`() {
    val hashes: array<int> = [1, 2, 3, 4, 5];
    val path = sccpBuildHashPath(hashes);
    expect(sccpLoadHashPath(path, 5, 9)).toEqual(hashes);
    expect(sccpLoadHashPath(null, 0, 9)).toEqual([]);
    // wrong length, missing and superfluous cells, over-long paths
    val cases: array<[cell?, int, int]> = [
        [path, 4, 9],
        [path, 6, 9],
        [null, 1, 9],
        [path, 0, 9],
        [path, 5, 4],
    ];
    var i = 0;
    while (i < cases.size()) {
        val [c, len, max] = cases.get(i);
        try {
            sccpLoadHashPath(c, len, max);
            expect(false).toBeTrue();
        } catch (e) {
            expect(
                (e == SccpErrors.BadSnake as int) | (e == SccpErrors.BadProof as int),
            ).toBeTrue();
        }
        i += 1;
    }
    // two hashes in the first chunk instead of three
    val nonMaximal = beginCell()
        .storeUint(1, 256)
        .storeUint(2, 256)
        .storeMaybeRef(
            beginCell().storeUint(3, 256).storeUint(4, 256).storeMaybeRef(null).endCell(),
        )
        .endCell();
    try {
        sccpLoadHashPath(nonMaximal, 4, 9);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadSnake as int);
    }
}

get fun `test snake bytes accept only the canonical shape`() {
    val canonical = snakeOfLength(300);
    val (chunks, len) = sccpParseSnakeBytes(canonical, 4096, SccpErrors.BadPayload);
    expect(len).toEqual(300);
    expect(chunks.size()).toEqual(3);
    // 1 byte and exactly 127 bytes are single chunks
    expect(sccpParseSnakeBytes(snakeOfLength(1), 4096, 1).1).toEqual(1);
    expect(sccpParseSnakeBytes(snakeOfLength(127), 4096, 1).0.size()).toEqual(1);
    val negatives: array<cell> = [
        // empty root
        createEmptyCell(),
        // non-final chunk shorter than 127 bytes
        beginCell().storeUint(0xAB, 8).storeRef(beginCell().storeUint(0xCD, 8).endCell()).endCell(),
        // empty final chunk
        beginCell()
            .storeSlice(snakeOfLength(127).beginParse())
            .storeRef(createEmptyCell())
            .endCell(),
        // non-byte-aligned final chunk
        beginCell().storeUint(1, 9).endCell(),
        // two references
        beginCell()
            .storeUint(0xAB, 8)
            .storeRef(createEmptyCell())
            .storeRef(createEmptyCell())
            .endCell(),
    ];
    var i = 0;
    while (i < negatives.size()) {
        try {
            sccpParseSnakeBytes(negatives.get(i), 4096, SccpErrors.BadPayload);
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(SccpErrors.BadSnake as int);
        }
        i += 1;
    }
    // the length bound uses the caller's error
    try {
        sccpParseSnakeBytes(snakeOfLength(1025), 1024, SccpErrors.BadRecipient);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadRecipient as int);
    }
    expect(sccpParseSnakeBytes(snakeOfLength(1024), 1024, SccpErrors.BadRecipient).1).toEqual(1024);
}

get fun `test inbound payload rules`() {
    val minter = 0x77;
    val good = inboundPayloadCell(1, 1, 5, 10, 0x33);
    expect(sccpParseInboundPayload(good, 1, minter).nonce).toEqual(1);
    expect(
        sccpParseInboundPayload(
            inboundPayloadCell(1, 1, 5, SCCP_TON_AMOUNT_LIMIT - 1, 0x33),
            1,
            minter,
        ).amount,
    ).toEqual(SCCP_TON_AMOUNT_LIMIT - 1);
    // Revision mismatch, zero deadline, zero amount and amount 2^96 are §3.2
    // rules (`BadPayload`); the recipient's own rules answer `BadRecipient`.
    val cases: array<[cell, int]> = [
        [inboundPayloadCell(1, 2, 5, 10, 0x33), SccpErrors.BadPayload as int],
        [inboundPayloadCell(1, 1, 0, 10, 0x33), SccpErrors.BadPayload as int],
        [inboundPayloadCell(1, 1, 5, 0, 0x33), SccpErrors.BadPayload as int],
        [inboundPayloadCell(1, 1, 5, SCCP_TON_AMOUNT_LIMIT, 0x33), SccpErrors.BadPayload as int],
        [inboundPayloadCell(1, 1, 5, 10, 0), SccpErrors.BadRecipient as int],
        [inboundPayloadCell(1, 1, 5, 10, minter), SccpErrors.BadRecipient as int],
        // a payload that breaks a §3.2 rule and names a bad recipient is BadPayload
        [inboundPayloadCell(1, 2, 5, 10, 0), SccpErrors.BadPayload as int],
        // senders of 0 and of 1025 bytes
        [
            inboundPayloadWithSender(
                1,
                1,
                5,
                10,
                0x33,
                0,
            ),
            SccpErrors.BadPayload as int,
        ],
        [
            inboundPayloadWithSender(
                1,
                1,
                5,
                10,
                0x33,
                1025,
            ),
            SccpErrors.BadPayload as int,
        ],
    ];
    expect(
        sccpParseInboundPayload(
            inboundPayloadWithSender(
                1,
                1,
                5,
                10,
                0x33,
                1024,
            ),
            1,
            minter,
        ).nonce,
    ).toEqual(1);
    var i = 0;
    while (i < cases.size()) {
        val [payload, code] = cases.get(i);
        try {
            sccpParseInboundPayload(payload, 1, minter);
            expect(false).toBeTrue();
        } catch (e) {
            expect(e).toEqual(code);
        }
        i += 1;
    }
    // trailing byte and truncation
    var w = SnakeWriter.create();
    val (chunks, _) = sccpParseSnakeBytes(good, 4096, 1);
    var j = 0;
    while (j < chunks.size()) {
        w.writeSlice(chunks.get(j));
        j += 1;
    }
    w.writeUint(0, 1);
    try {
        sccpParseInboundPayload(sccpSnakeCellFromChunks(w.chunks()), 1, minter);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadPayload as int);
    }
    try {
        sccpParseInboundPayload(snakeOfLength(20), 1, minter);
        expect(false).toBeTrue();
    } catch (e) {
        expect(e).toEqual(SccpErrors.BadPayload as int);
    }
}
