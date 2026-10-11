// Roster rotation and weak subjectivity (§5.1.2, §5.1.5): the current roster
// signs the next one, the previous roster keeps a capped grace, sequential
// rotations, and every generation, digest and validity bound.

import "@stdlib/exotic-cells"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/message"
import "@acton/types/transaction"
import "@contracts/sccp-cells"
import "@contracts/sccp-constants"
import "@contracts/sccp-errors"
import "@contracts/sccp-messages"
import "@contracts/sccp-storage"
import "@contracts/sccp-verify"
import "@wrappers/SccpTairaXorMinter.gen"
import "sccp-test-helpers"
import "sccp-test-vectors.gen"

get fun `test rotation installs the next roster and keeps the previous one in grace`() {
    val env = setupEnv();
    val next = nextRoster(env.roster, 7, 4, T0 * 1000 - 5000);
    val res = rotateTo(env, next, 300);
    expect(res).toHaveSuccessfulTx<ReturnExcessesBack>({ to: env.deployer });
    // §5.1.5 step 4: the new generation, digest and expiry
    val event = res
        .findExternalOutMessage<SccpRosterRotatedEvent>({ from: env.minter.address })!
        .loadBody();
    expect(event.generation).toEqual(8);
    expect(event.digest).toEqual(next.digest(env.networkId));
    expect(event.validUntilMs).toEqual(next.validUntilMs);
    val state = env.minter.getSccpState();
    expect(state.digest).toEqual(next.digest(env.networkId));
    expect(state.generation).toEqual(8);
    expect(state.validUntilMs).toEqual(next.validUntilMs);
    expect(state.prevDigest).toEqual(env.digest());
    expect(state.prevValidUntilMs).toEqual(T0 * 1000 + SCCP_PREVIOUS_ROSTER_GRACE_MS);
    // rotations are not counted
    expect(state.opCount).toEqual(0);
    expect(state.initialDigest).toEqual(env.digest());
    expect(state.initialGeneration).toEqual(7);
    expect(env.minter.getSccpMembers()).toEqual(next.members);
}

get fun `test previous roster grace is capped by its own validity`() {
    testing.setNow(T0);
    val deployer = testing.treasury("deployer");
    // current roster expires in 2 hours, before the 24 h grace would end
    val roster = makeRoster(
        7,
        4,
        0,
        0,
        T0 * 1000 - HOUR_MS,
        T0 * 1000 + 2 * HOUR_MS,
    );
    val (minter, _) = deployWithInit(
        canonicalStorage(VEC_NETWORK_ID, TEST_REVISION, TEST_MAX_SUPPLY, roster),
        deployer.address,
        grams("10"),
    );
    val env: Env = {
        minter,
        deployer: deployer.address,
        networkId: VEC_NETWORK_ID,
        roster,
    };
    rotateTo(env, nextRoster(roster, 4, 4, T0 * 1000), 300);
    expect(env.minter.getSccpState().prevValidUntilMs).toEqual(T0 * 1000 + 2 * HOUR_MS);
}

get fun `test the previous roster finalizes within grace and not after`() {
    val env = setupEnv();
    val alice = testing.treasury("alice").address;
    val old = env.roster;
    val next = nextRoster(env.roster, 4, 4, T0 * 1000 - 5000);
    rotateTo(env, next, 300);
    val newEnv: Env = {
        minter: env.minter,
        deployer: env.deployer,
        networkId: env.networkId,
        roster: next,
    };
    // signed by the previous roster, within grace
    val d = deliver(
        env,
        old,
        0,
        10,
        alice,
        T0 * 1000 + 3 * DAY_MS,
        0,
        1,
    );
    expect(
        sendFinalize(env, env.deployer, d, finalizeValue(env, 0)),
    ).toHaveSuccessfulTx<SccpFinalize>({
        to: env.minter.address,
    });
    // after grace the previous roster is refused, the new one works
    testing.setNow(T0 + SCCP_PREVIOUS_ROSTER_GRACE_MS / 1000 + 1);
    val late = deliver(
        env,
        old,
        1,
        10,
        alice,
        T0 * 1000 + 3 * DAY_MS,
        0,
        1,
    );
    expect(
        sendFinalize(env, env.deployer, late, finalizeValue(env, 1)),
    ).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.RosterNotAccepted as int,
    });
    val fresh = deliver(
        newEnv,
        next,
        1,
        10,
        alice,
        T0 * 1000 + 3 * DAY_MS,
        0,
        1,
    );
    expect(
        sendFinalize(newEnv, env.deployer, fresh, finalizeValue(env, 1)),
    ).toHaveSuccessfulTx<SccpFinalize>({
        to: env.minter.address,
    });
    expect(jettonBalanceOf(env, alice)).toEqual(20);
}

get fun `test sequential rotations replay each generation`() {
    val env = setupEnv();
    val g8 = nextRoster(env.roster, 4, 4, T0 * 1000 - 5000);
    rotateTo(env, g8, 300);
    val env8: Env = {
        minter: env.minter,
        deployer: env.deployer,
        networkId: env.networkId,
        roster: g8,
    };
    val g9 = nextRoster(g8, 31, 0, T0 * 1000 - 1000);
    rotateTo(env8, g9, 301);
    val state = env.minter.getSccpState();
    expect(state.generation).toEqual(9);
    expect(state.prevDigest).toEqual(g8.digest(env.networkId));
    // generation 7 is gone entirely
    val alice = testing.treasury("alice").address;
    val stale = deliver(
        env,
        env.roster,
        0,
        1,
        alice,
        T0 * 1000 + DAY_MS,
        0,
        1,
    );
    expect(sendFinalize(env, env.deployer, stale, grams("5"))).toHaveFailedTx<SccpFinalize>({
        to: env.minter.address,
        exitCode: SccpErrors.RosterNotAccepted as int,
    });
    // skipping a generation is refused
    val env9: Env = {
        minter: env.minter,
        deployer: env.deployer,
        networkId: env.networkId,
        roster: g9,
    };
    val g11 = makeRoster(
        11,
        4,
        0,
        8,
        T0 * 1000,
        T0 * 1000 + DAY_MS,
    );
    val statement = rotationStatement(env9, g9, g11, 302);
    expect(
        sendRotate(
            env9,
            statement,
            signByThreshold(g9, statement.digest(env.networkId)),
            g11.spec(),
        ),
    ).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.BadRotation as int,
    });
}

get fun `test only the current roster may sign a rotation`() {
    val env = setupEnv();
    val g8 = nextRoster(env.roster, 4, 4, T0 * 1000 - 5000);
    rotateTo(env, g8, 300);
    val env8: Env = {
        minter: env.minter,
        deployer: env.deployer,
        networkId: env.networkId,
        roster: g8,
    };
    val g9 = nextRoster(g8, 4, 8, T0 * 1000);
    // generation 7 (previous, still in grace) signs: refused
    val statement = rotationStatement(env, env.roster, g9, 301);
    expect(
        sendRotate(
            env8,
            statement,
            signByThreshold(env.roster, statement.digest(env.networkId)),
            g9.spec(),
        ),
    ).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.RosterNotAccepted as int,
    });
}

get fun `test rotation checks the announced digest and the timestamp binding`() {
    val env = setupEnv();
    val next = nextRoster(env.roster, 4, 4, T0 * 1000 - 5000);
    // next digest zero
    var zero = rotationStatement(env, env.roster, next, 300);
    zero.nextRosterDigest = 0;
    expect(
        sendRotate(env, zero, signByThreshold(env.roster, zero.digest(env.networkId)), next.spec()),
    ).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.BadRotation as int,
    });
    // a different roster than the announced one
    val other = nextRoster(env.roster, 4, 5, T0 * 1000 - 5000);
    val announced = rotationStatement(env, env.roster, next, 300);
    expect(
        sendRotate(
            env,
            announced,
            signByThreshold(env.roster, announced.digest(env.networkId)),
            other.spec(),
        ),
    ).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.BadRotation as int,
    });
    // valid_from differs from the boundary timestamp
    var shifted = rotationStatement(env, env.roster, next, 300);
    shifted.timestampMs = next.validFromMs + 1;
    expect(
        sendRotate(
            env,
            shifted,
            signByThreshold(env.roster, shifted.digest(env.networkId)),
            next.spec(),
        ),
    ).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.BadRotation as int,
    });
    // unsigned by enough members
    val fine = rotationStatement(env, env.roster, next, 300);
    expect(
        sendRotate(
            env,
            fine,
            signBySlots(env.roster, fine.digest(env.networkId), [0, 1]),
            next.spec(),
        ),
    ).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.TooFewSignatures as int,
    });
}

get fun `test rotation validity, skew and valid_from bounds`() {
    val now = T0 * 1000;
    val bounds: array<[int, int]> = [
        [now + SCCP_MAX_CLOCK_SKEW_MS + 1, now + 2 * DAY_MS],
        [now - DAY_MS, now - DAY_MS + SCCP_MAX_ROSTER_VALIDITY_MS + 1],
        [now - 2 * DAY_MS, now],
        [now + 1, now + SCCP_MAX_ROSTER_VALIDITY_MS + 1],
    ];
    val env = setupEnv();
    var i = 0;
    while (i < bounds.size()) {
        val [from, until] = bounds.get(i);
        val next = makeRoster(
            8,
            4,
            0,
            4,
            from,
            until,
        );
        val statement = rotationStatement(env, env.roster, next, 300);
        expect(
            sendRotate(
                env,
                statement,
                signByThreshold(env.roster, statement.digest(env.networkId)),
                next.spec(),
            ),
        ).toHaveFailedTx<SccpRotate>({
            to: env.minter.address,
            exitCode: SccpErrors.BadRosterValidity as int,
        });
        i += 1;
    }
    // the edges pass
    val edge = makeRoster(
        8,
        4,
        0,
        4,
        now + SCCP_MAX_CLOCK_SKEW_MS,
        now + SCCP_MAX_ROSTER_VALIDITY_MS,
    );
    rotateTo(env, edge, 300);
}

get fun `test rotation rejects a malformed next roster`() {
    val env = setupEnv();
    val next = nextRoster(env.roster, 4, 4, T0 * 1000 - 5000);
    val statement = rotationStatement(env, env.roster, next, 300);
    val sigs = signByThreshold(env.roster, statement.digest(env.networkId));
    var badThreshold = next.spec();
    badThreshold.t = 4;
    expect(sendRotate(env, statement, sigs, badThreshold)).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.BadRoster as int,
    });
    var badOrder = next.spec();
    badOrder.members = sccpBuildMembers(
        [keyAddress(5), keyAddress(4), keyAddress(6), keyAddress(7)],
    );
    expect(sendRotate(env, statement, sigs, badOrder)).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.BadRoster as int,
    });
}

get fun `test rotation rejects library-cell member chunks and stores an ordinary list`() {
    val env = setupEnv();
    // n = 4: the whole list as a reference to a published library holding the
    // canonical chunk (CTOS alone would resolve it and pass the digest check)
    val next = nextRoster(env.roster, 4, 4, T0 * 1000 - 5000);
    val canonical = next.membersCell();
    testing.registerLibrary(canonical);
    val statement = rotationStatement(env, env.roster, next, 300);
    val sigs = signByThreshold(env.roster, statement.digest(env.networkId));
    var headLibrary = next.spec();
    headLibrary.members = canonical.toLibraryReference();
    expect(sendRotate(env, statement, sigs, headLibrary)).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.BadSnake as int,
    });
    // n = 7: an ordinary first chunk linking a library-reference last chunk
    val next7 = nextRoster(env.roster, 7, 4, T0 * 1000 - 5000);
    val lastChunk = beginCell().storeUint(next7.members.get(6), 160).storeMaybeRef(null).endCell();
    testing.registerLibrary(lastChunk);
    var head = beginCell();
    var i = 0;
    while (i < SCCP_MEMBERS_PER_CHUNK) {
        head.storeUint(next7.members.get(i), 160);
        i += 1;
    }
    var tailLibrary = next7.spec();
    tailLibrary.members = head.storeMaybeRef(lastChunk.toLibraryReference()).endCell();
    val statement7 = rotationStatement(env, env.roster, next7, 301);
    expect(
        sendRotate(
            env,
            statement7,
            signByThreshold(env.roster, statement7.digest(env.networkId)),
            tailLibrary,
        ),
    ).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.BadSnake as int,
    });
    expect(env.minter.getSccpState().generation).toEqual(7);
    // the ordinary encoding rotates, and the stored list is that ordinary cell
    rotateTo(env, next7, 302);
    expect(env.minter.getSccpState().generation).toEqual(8);
    expect(env.minter.getSccpMembers()).toEqual(next7.members);
    val installed = storedMinterData(env.minter.address).roster.load();
    val (_, isExotic) = installed.members.beginParseSpecial();
    expect(isExotic).toBeFalse();
    expect(installed.members.hash()).toEqual(next7.membersCell().hash());
}

/// Minter storage read from the emulated account state.
fun storedMinterData(minter: address): MinterStorage {
    val account = testing.getAccountState(minter)!;
    val state = account.storage.state;
    if (state is TlbAccountStateActive) {
        return MinterStorage.fromCell(state.stateInit.data!);
    }
    throw SccpErrors.InvalidMessage;
}

get fun `test an expired destination cannot rotate`() {
    val env = setupEnv();
    val next = nextRoster(env.roster, 4, 4, env.roster.validUntilMs + 1000);
    testing.setNow(env.roster.validUntilMs / 1000 + 1);
    val statement = rotationStatement(env, env.roster, next, 300);
    expect(
        sendRotate(
            env,
            statement,
            signByThreshold(env.roster, statement.digest(env.networkId)),
            next.spec(),
        ),
    ).toHaveFailedTx<SccpRotate>({
        to: env.minter.address,
        exitCode: SccpErrors.RosterNotAccepted as int,
    });
}
