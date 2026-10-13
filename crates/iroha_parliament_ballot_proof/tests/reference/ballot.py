#!/usr/bin/env python3
"""Experimental, independent correctness reference for Parliament ballot proofs.

Implements specs/parliament_ballot_proof_profile.md section 6: the strengthened
vote relation, 112-byte tape, salted first challenge and H5, bounded 20-bit
counter, and affine-checked 112-byte leaf commitments. No profile is selected or
qualified. This program is not constant time and must never handle real secrets.

Pure Python with standard-library SHA-3/SHAKE. Bit strings and field elements are
little-endian integers: bit i is coefficient X^i, and addition is XOR. The generic
FAEST-derived backend is in faest.py; deterministic CRT generation is independent
of the Rust tables. This reference and Rust share no implementation code.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import faest as FZ  # noqa: E402

D_ZK = FZ.D_ZK
P16 = bytes.fromhex("5041524c2d5348414b452d5631000000")
assert P16 == b"PARL-SHAKE-V1\x00\x00\x00"

TAPE_BYTES = 112
SK_BYTES = 48
PAD_BITS = 256
SK_BITS = 384
STATE_BITS = 1600
GROUPS = 11                       # committed states after 2, 4, .., 22 rounds
SK_OFF = PAD_BITS                 # witness offset of sk
# committed-state offset of permutation d: 640, 18240, 35840 (the third one is vote only)
PERM_OFF = tuple(SK_OFF + SK_BITS + d * GROUPS * STATE_BITS for d in range(3))
N_PERMS = {"reg": 2, "vote": 3}
SEL_A_OFF = PERM_OFF[2] + GROUPS * STATE_BITS                              # 53440 (vote only)
SEL_B_OFF = SEL_A_OFF + 32                                                 # 53472
ELL = {"reg": PERM_OFF[2], "vote": SEL_B_OFF + 32}                         # 35840, 53504
N_CONSTRAINTS = {"reg": 72576, "vote": 108931}
SK_STATE_OFF = 160                # sk bit j sits at initial-state bit 160 + j
C_BITS = 1024                     # commitment output bits
NF_BITS = 1024                    # nullifier output bits
AUTH_BITS = 512                   # registration authorization / vote authorization output bits
NF_BYTES = NF_BITS // 8
# per relation, per permutation: (block name suffix, SHAKE tag, number of constrained output bits)
PERMS = {
    "reg": (("C", b"PCR1", C_BITS), ("A", b"PAU1", AUTH_BITS)),
    "vote": (("C", b"PCR1", C_BITS), ("N", b"PNF1", NF_BITS), ("V", b"PAV1", AUTH_BITS)),
}
assert PERM_OFF == (640, 18240, 35840) and (SEL_A_OFF, SEL_B_OFF) == (53440, 53472)
assert ELL == {"reg": 35840, "vote": 53504}
S_MIN, S_MAX = 3, 1000

# name: (faest.py base set, lambda, tau, w_grind, T_open, n_mult)
ROWS = {
    "fast": ("faest_256f", 256, 33, 8, 229, 704),
    "comparator": ("faest_256s", 256, 22, 6, 225, 696),
}


class GrindingExhausted(Exception):
    """The finite counter range was exhausted without an admissible opening."""

    def __init__(self):
        self.last = 0x000FFFFF
        super().__init__(f"grinding exhausted at {self.last:#010x}")


# ======================================================================== Keccak-f[1600] (own)
def _rc_bit(t):
    """FIPS 202 Algorithm 5."""
    if t % 255 == 0:
        return 1
    r = [1, 0, 0, 0, 0, 0, 0, 0]
    for _ in range(t % 255):
        r = [0] + r
        r[0] ^= r[8]
        r[4] ^= r[8]
        r[5] ^= r[8]
        r[6] ^= r[8]
        r = r[:8]
    return r[0]


def _round_constants():
    out = []
    for ir in range(24):
        rc = 0
        for j in range(7):
            rc |= _rc_bit(j + 7 * ir) << ((1 << j) - 1)
        out.append(rc)
    return out


def _rho_offsets():
    """ROT[x][y] (FIPS 202 Algorithm 2)."""
    rot = [[0] * 5 for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        rot[x][y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return rot


RC = _round_constants()
ROT = _rho_offsets()
_M64 = (1 << 64) - 1


def _rotl(v, n):
    return ((v << n) | (v >> (64 - n))) & _M64 if n else v


def keccak_round_lanes(a, ir):
    """One round on 25 lanes, lane index x + 5y."""
    c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
    d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
    a = [a[i] ^ d[i % 5] for i in range(25)]
    b = [0] * 25
    for x in range(5):
        for y in range(5):
            xs = (x + 3 * y) % 5
            b[x + 5 * y] = _rotl(a[xs + 5 * x], ROT[xs][x])
    out = [b[i] ^ ((b[(i % 5 + 1) % 5 + 5 * (i // 5)] ^ _M64) & b[(i % 5 + 2) % 5 + 5 * (i // 5)])
           for i in range(25)]
    out[0] ^= RC[ir]
    return out


def state_to_lanes(st):
    return [(st >> (64 * i)) & _M64 for i in range(25)]


def lanes_to_state(a):
    st = 0
    for i in range(25):
        st |= a[i] << (64 * i)
    return st


def keccak_f(st, first=0, last=24):
    """Rounds first..last-1 on a state int (bit t = 64*(x+5y)+z)."""
    a = state_to_lanes(st)
    for ir in range(first, last):
        a = keccak_round_lanes(a, ir)
    return lanes_to_state(a)


def _sponge(rate, suffix, msg, outlen):
    blocks = bytearray(msg)
    blocks.append(suffix)
    while len(blocks) % rate:
        blocks.append(0)
    blocks[-1] |= 0x80
    st = 0
    for off in range(0, len(blocks), rate):
        st ^= int.from_bytes(blocks[off:off + rate], "little")
        st = keccak_f(st)
    out = b""
    while True:
        out += (st & ((1 << (8 * rate)) - 1)).to_bytes(rate, "little")
        if len(out) >= outlen:
            return out[:outlen]
        st = keccak_f(st)


def shake256(msg, outlen):
    return _sponge(136, 0x1F, msg, outlen)


def sha3_512(msg):
    return _sponge(72, 0x06, msg, 64)


# ======================================================================== framing, public functions
def u8(v):
    return v.to_bytes(1, "little")


def u16(v):
    return v.to_bytes(2, "little")


def u32(v):
    return v.to_bytes(4, "little")


def frame(tag, *fields):
    """Frame(tag; fields...) = u16_le(len(tag)) || ASCII(tag) || u16_le(n) || concat(u32_le(len f) || f)."""
    t = tag.encode("ascii")
    out = [u16(len(t)), t, u16(len(fields))]
    for f in fields:
        if not isinstance(f, (bytes, bytearray)):
            raise TypeError("frame field must be bytes")
        out.append(u32(len(f)))
        out.append(bytes(f))
    return b"".join(out)


def body_digest(enc_body_context):
    """B."""
    return sha3_512(frame("PARL/BODY/v1", P16, enc_body_context))


def shake_message(tag4, sk, x64):
    """The 132-byte unpadded SHAKE256 message tag || P16 || sk || x."""
    if len(tag4) != 4 or len(sk) != SK_BYTES or len(x64) != 64:
        raise ValueError("shake message field length")
    return tag4 + P16 + sk + x64


def commitment(sk, b):
    """C = SHAKE256("PCR1" || P16 || sk || B, 128 bytes)."""
    return shake256(shake_message(b"PCR1", sk, b), 128)


def nullifier(sk, scope):
    """nf = SHAKE256("PNF1" || P16 || sk || scope, 128 bytes)  ."""
    return shake256(shake_message(b"PNF1", sk, scope), NF_BYTES)


def vote_auth_frame(d, b, scope, r, s, lst, nf, vote, pol):
    """Y_v = Frame("PARL/VOTE-AUTH/v1"; P16, ASCII("VOTE"), D, B, scope, R, u16_le(S),
    concat(L), nf, u8(vote), policy_hash): 128 S + 536 bytes.  `d` = the 64-byte descriptor
    digest D.  auth_v, mu, proof bytes and proving randomness are NOT in it."""
    return frame("PARL/VOTE-AUTH/v1", P16, b"VOTE", d, b, scope, r, u16(s), b"".join(lst), nf,
                 u8(vote), pol)


def vote_auth_digest(d, b, scope, r, s, lst, nf, vote, pol):
    """D_v = SHA3-512(Y_v)."""
    return sha3_512(vote_auth_frame(d, b, scope, r, s, lst, nf, vote, pol))


def vote_auth_value(sk, d_v):
    """auth_v = SHAKE256("PAV1" || P16 || sk || D_v, 64 bytes)."""
    return shake256(shake_message(b"PAV1", sk, d_v), 64)


def auth_value(sk, d_reg):
    """auth = SHAKE256("PAU1" || P16 || sk || D_reg, 64 bytes)."""
    return shake256(shake_message(b"PAU1", sk, d_reg), 64)


REG_ENC_FIELDS = ("enc_network_id", "enc_authority", "enc_assignment_id",
                  "enc_governance_attempt_id", "enc_election_attempt_id", "enc_body_role")


def reg_auth_digest(enc_descriptor, enc_body_context, encs, b, c):
    """D_reg.  `encs` = the six Enc strings in REG_ENC_FIELDS order."""
    return sha3_512(frame("PARL/REG-AUTH/v1", P16, b"REG", enc_descriptor, enc_body_context,
                          *encs, b, c))


def policy_hash(enc_policy):
    return sha3_512(frame("PARL/POLICY/v1", P16, enc_policy))


def proposal_digest(enc_proposal):
    return sha3_512(frame("PARL/PROPOSAL/v1", enc_proposal))


def scope_digest(enc_network_id, proposal_dig, enc_governance_attempt_id, enc_body_instance_id):
    return sha3_512(frame("PARL/SCOPE/v1", P16, enc_network_id, proposal_dig,
                          enc_governance_attempt_id, enc_body_instance_id))


def validate_list(lst):
    """3 <= S <= 1000, every entry 128 bytes, strictly increasing bytewise (hence distinct)."""
    s = len(lst)
    if not S_MIN <= s <= S_MAX:
        raise ValueError("list size out of range")
    prev = None
    for c in lst:
        if not isinstance(c, (bytes, bytearray)) or len(c) != 128:
            raise ValueError("list entry length")
        if prev is not None and not prev < bytes(c):
            raise ValueError("list not strictly increasing")
        prev = bytes(c)
    return s


def list_digest(b, lst, validate=True):
    """R = SHA3-512(Frame("PARL/LIST/v1"; P16, B, u16_le(S), concat(L)))."""
    if validate:
        validate_list(lst)
    return sha3_512(frame("PARL/LIST/v1", P16, b, u16(len(lst)), b"".join(lst)))


# ======================================================================== frozen byte-level protocol
# Record section 6.1 (descriptor, CRT serialisation), 6.3 (namespaces, prefix, mu).
SUITE = (b"KECCAK-F1600/2R-FWD/SEL-32X32-PREFIX/PAD-256/TAPE-112/CTR-U20-LE32/NS-PREFIX77"
         b"/NF-1024/VAUTH-512/SALT-256/H5-SALT/LEAF-AFFINE-896")
assert len(SUITE) == 129
DESC_BYTES = 286
PREFIX_LITERAL = b"PARL/FAEST/v1"
ENC_BODY_CONTEXT_MAX = 4096
ENC_FIELD_MAX = 256

# T_crt: the two digests printed in the record (section 6.1, "Fixed digest values"); unchanged
# by the ballot extensions (same CRT tables).
RECORD_T_CRT = {
    "fast": "a9c572a7c8f2cc735218123c6456e1e016e78b06aa2d03192ef801bf7fdb93ae"
            "014a9e16555e6bad81382c630467e45e76c9b1c3948f9dfea41a7a1435bcffea",
    "comparator": "792f81bf102cac84b7c559595342b6b23ad27dab9065651feb928dd0a649a3f4"
                  "bd1da3d350fbd4c62f1707d441d46ef084430b5f00b53a1af7088281d6a7386e",
}
# Retired descriptor values retained only as negative-test inputs.
# No parser or proof verifier accepts these values.
RETIRED_V1_D = {
    "fast": "44028deb664beb1a06a336cd6f622c223a5c15741dfafa72b55e19cbb42f287b"
            "a48979a0d6a8342c80034cc88b87fcb055f0db686fe97beffb2197bc7f85e910",
    "comparator": "1f59fe5ae24c0d5dfb86611f1ed4439edd7995d6cbbf308f2954b4bb2c3fece8"
                  "fe4c080dcef118bb4100d6cf5c4de012318e3a1227b78299e24d5a113cb31273",
}


def _words(v, width):
    """An integer whose bit c is column c -> ceil(width/64) little-endian u64 words."""
    if v >> width:
        raise AssertionError("row wider than declared")
    return v.to_bytes(8 * ((width + 63) // 64), "little")


def crt_bytes(row):
    """CRT_BYTES: "FAESTCRT" || u64(lambda, tau, w_grind, n_mult) || u64(tree moduli) ||
    M_TREE || F || G || W_TREE || W_GATE || W_CRT, matrices row-major, each row
    ceil(width/64) little-endian u64 words, column c = bit c%64 of word c/64."""
    _base, lam, tau, w, _t_open, n_mult = ROWS[row]
    t = backend_params(row, "reg").t
    nd = lam - w
    assert t["n_mult"] == n_mult and len(t["tree_moduli"]) == tau
    out = [b"FAESTCRT"] + [v.to_bytes(8, "little") for v in (lam, tau, w, n_mult)]
    out += [m.to_bytes(8, "little") for m in t["tree_moduli"]]
    out.append(_words(t["m_tree"], nd + 1))
    for name, rows, width in (("F", n_mult, lam), ("G", n_mult, nd), ("W_TREE", lam, nd),
                              ("W_GATE", lam, n_mult), ("W_CRT", lam, nd)):
        m = t[name]
        assert len(m) == rows, (name, len(m), rows)
        out += [_words(r, width) for r in m]
    return b"".join(out)


_DESC_CACHE = {}


def t_crt(row):
    """T_crt = SHAKE256(CRT_BYTES, 64 bytes)."""
    key = ("t", row)
    if key not in _DESC_CACHE:
        _DESC_CACHE[key] = hashlib.shake_256(crt_bytes(row)).digest(64)
    return _DESC_CACHE[key]


def descriptor(row):
    """DESC bytes of a parameter row (286 bytes)."""
    if row not in _DESC_CACHE:
        _base, lam, tau, w, t_open, n_mult = ROWS[row]
        _DESC_CACHE[row] = frame(
            "PARL/DESC/v1", P16, b"FAEST-3.0",
            u16(lam) + u16(tau) + u16(w) + u16(t_open) + u16(D_ZK) + u16(n_mult),
            t_crt(row),
            u32(ELL["reg"]) + u32(N_CONSTRAINTS["reg"]) + u32(ELL["vote"]) + u32(N_CONSTRAINTS["vote"]),
            SUITE)
        assert len(_DESC_CACHE[row]) == DESC_BYTES
    return _DESC_CACHE[row]


def descriptor_digest(row):
    """D = SHA3-512(DESC)."""
    return sha3_512(descriptor(row))


ROLE = {"reg": "REG", "vote": "VOTE"}


def namespace(d, role):
    """NS_R = SHA3-512(Frame("PARL/NS/v1"; D, ASCII(role))), role "REG" or "VOTE"."""
    return sha3_512(frame("PARL/NS/v1", d, role.encode("ascii")))


def role_prefix(row, kind):
    """PREFIX_R = ASCII("PARL/FAEST/v1") || NS_R: the 77 bytes every backend hash call of a
    ballot proof absorbs before its body."""
    key = ("pre", row, kind)
    if key not in _DESC_CACHE:
        pre = PREFIX_LITERAL + namespace(descriptor_digest(row), ROLE[kind])
        assert len(pre) == 77
        _DESC_CACHE[key] = pre
    return _DESC_CACHE[key]


def f_reg(enc_body_context, encs, b, c, auth):
    """F_REG."""
    return frame("PARL/MU/REG/v1", enc_body_context, *encs, b, c, auth)


def f_vote(b, scope, r, s, lst, nf, auth_v, vote, pol):
    """F_VOTE = Frame("PARL/MU/VOTE/v1"; B, scope, R, u16_le(S), concat(L), nf, auth_v,
    u8(vote), policy_hash): 9 fields, 128 S + 506 bytes."""
    return frame("PARL/MU/VOTE/v1", b, scope, r, u16(s), b"".join(lst), nf, auth_v, u8(vote), pol)


def mu_of(prefix, f_r):
    """mu_R = SHAKE256(PREFIX_R || F_R || 08, 64 bytes) (the backend's H2^0 with the prefix)."""
    return FZ.H2(256, 0, f_r, 64, prefix)


# ======================================================================== backend parameters
class CountField:
    """Wraps a faest.Field; counts multiplications (all calls / calls with both operands
    outside {0, 1})."""

    def __init__(self, f):
        self._f = f
        self.n = f.n
        self.nbytes = f.nbytes
        self.calls = 0
        self.nontrivial = 0

    def mul(self, a, b):
        self.calls += 1
        if a < 2 or b < 2:
            return a * b
        self.nontrivial += 1
        return self._f.reduce(FZ.clmul(a, b))

    def to_bytes(self, a):
        return a.to_bytes(self.nbytes, "little")


_PARAMS = {}


def backend_params(row, kind):
    """Extended backend parameters with the frozen application witness length."""
    key = (row, kind)
    if key not in _PARAMS:
        base, lam, tau, w, t_open, _n_mult = ROWS[row]
        p = FZ.Params(base)
        assert (p.lam, p.tau, p.w, p.t_open, p.n_leafcom) == (lam, tau, w, t_open, 3)
        p.name = "ballot_%s_%s" % (row, kind)
        p.extended = True
        p.ell = ELL[kind]
        p.ell_hat = p.ell + FZ.N_MASK * p.d0
        p.C = N_CONSTRAINTS[kind]
        p.F = CountField(FZ.field(lam))
        p.prefix = None            # set below; a ballot proof never runs with the empty prefix
        # the OWF attributes of faest.Params are meaningless here
        for a in ("nk", "nst", "rounds", "beta", "ske", "senc", "lke", "lenc", "x_bytes",
                  "y_bytes", "pk_bytes", "sk_bytes"):
            setattr(p, a, None)
        _PARAMS[key] = p
        p.prefix = role_prefix(row, kind)        # needs the tables of p (T_crt)
    return _PARAMS[key]


def proof_bytes(row, kind):
    return backend_params(row, kind).sig_bytes


# ======================================================================== evaluation back ends
class BitBackend:
    """Plain evaluator over GF(2), bit-sliced over n instances: a value is an int whose bit k
    is the value in instance k.  n = 1 is the ordinary GF(2) evaluator."""

    def __init__(self, n=1):
        self.ones = (1 << n) - 1

    def const(self, c):
        return self.ones if c else 0

    def add(self, a, b):
        return a ^ b

    def add_const(self, a, c):
        return a ^ self.ones if c else a

    def mul(self, a, b):
        return a & b

    def lift(self, a, f):
        return a


class FieldBackend:
    """Plain evaluator over K (values need not be Boolean)."""

    def __init__(self, f):
        self.F = f

    def const(self, c):
        return c

    def add(self, a, b):
        return a ^ b

    def add_const(self, a, c):
        return a ^ c

    def mul(self, a, b):
        return self.F.mul(a, b)

    def lift(self, a, f):
        return a


def _deg(z):
    """Tracked degree of a commitment: prover = coefficient list, verifier = (key, degree);
    plain values carry no degree."""
    if isinstance(z, list):
        return len(z) - 1
    if isinstance(z, tuple):
        return z[1]
    return None


# ======================================================================== Keccak round as a circuit
def _build_round_tables():
    lin_src = [0] * STATE_BITS       # after theta: out bit t of pi(rho(.)) = theta bit lin_src[t]
    chi1 = [0] * STATE_BITS
    chi2 = [0] * STATE_BITS
    for y in range(5):
        for x in range(5):
            xs, ys = (x + 3 * y) % 5, x
            for z in range(64):
                t = 64 * (x + 5 * y) + z
                lin_src[t] = 64 * (xs + 5 * ys) + (z - ROT[xs][ys]) % 64
                chi1[t] = 64 * ((x + 1) % 5 + 5 * y) + z
                chi2[t] = 64 * ((x + 2) % 5 + 5 * y) + z
    return lin_src, chi1, chi2


LIN_SRC, CHI1, CHI2 = _build_round_tables()
IOTA_BITS = [[z for z in range(64) if (RC[ir] >> z) & 1] for ir in range(24)]


def round_circuit(B, st, ir):
    """R_ir = iota . chi . pi . rho . theta on 1600 commitments of one common degree d;
    returns 1600 commitments of degree 2d."""
    add, mul, add_const = B.add, B.mul, B.add_const
    # theta: column parities
    par = []
    for x in range(5):
        col = []
        for z in range(64):
            i = 64 * x + z
            col.append(add(add(add(add(st[i], st[i + 320]), st[i + 640]), st[i + 960]), st[i + 1280]))
        par.append(col)
    dd = []
    for x in range(5):
        lo, hi = par[(x - 1) % 5], par[(x + 1) % 5]
        dd.append([add(lo[z], hi[(z - 1) % 64]) for z in range(64)])
    th = [add(st[t], dd[(t // 64) % 5][t % 64]) for t in range(STATE_BITS)]
    # rho, pi: a permutation of the bit positions
    lin = [th[s] for s in LIN_SRC]
    # chi
    out = [add(lin[t], mul(add_const(lin[CHI1[t]], 1), lin[CHI2[t]])) for t in range(STATE_BITS)]
    # iota: lane (0, 0)
    for z in IOTA_BITS[ir]:
        out[z] = add_const(out[z], 1)
    return out


def group_circuit(B, st, g):
    """G_g = R_(2g-1) . R_(2g-2), 1 <= g <= 12: degree d -> 4d."""
    return round_circuit(B, round_circuit(B, st, 2 * g - 2), 2 * g - 1)


# ======================================================================== public inputs of a relation
class Public:
    """Everything the constraint stream reads besides the witness."""

    def __init__(self, kind, init_consts, outputs, lst=None):
        self.kind = kind
        self.ell = ELL[kind]
        if len(init_consts) != N_PERMS[kind] or len(outputs) != N_PERMS[kind]:
            raise ValueError("one initial state and one output per permutation")
        # per permutation: 1600-bit int, the absorbed block with the sk positions zero
        self.init_consts = init_consts
        # per permutation: the public output as an int (C 1024 / auth 512 bits; nf 1024 /
        # auth_v 512 bits), or None for the vote commitment (public multiplexer instead)
        self.out_bits = outputs
        for (_nm, _tag, nbits), o in zip(PERMS[kind], outputs):
            if o is not None and o >> nbits:
                raise ValueError("public output wider than its constraint block")
        if kind == "vote":
            if outputs[0] is not None:
                raise ValueError("the vote commitment output is the multiplexer")
            self.S = len(lst)
            ints = [int.from_bytes(c, "little") for c in lst]
            # mux_rows[t] = positions i < S whose commitment has bit t set
            self.mux_rows = [[i for i in range(self.S) if (ints[i] >> t) & 1] for t in range(C_BITS)]


def _init_const(tag4, x64):
    """Initial state of a permutation with the 384 sk bits set to zero."""
    block = shake_message(tag4, bytes(SK_BYTES), x64) + b"\x1f\x00\x00\x80" + bytes(64)
    return int.from_bytes(block, "little")


def public_reg(b, d_reg, c, auth):
    return Public("reg", (_init_const(b"PCR1", b), _init_const(b"PAU1", d_reg)),
                  (int.from_bytes(c, "little"), int.from_bytes(auth, "little")))


def public_vote(b, scope, d_v, lst, nf, auth_v):
    """nf: 128 bytes, auth_v: 64 bytes, d_v: the RECOMPUTED 64-byte D_v."""
    if len(nf) != NF_BYTES or len(auth_v) != 64 or len(d_v) != 64:
        raise ValueError("public field length")
    return Public("vote", (_init_const(b"PCR1", b), _init_const(b"PNF1", scope),
                           _init_const(b"PAV1", d_v)),
                  (None, int.from_bytes(nf, "little"), int.from_bytes(auth_v, "little")), lst)


# ======================================================================== THE constraint stream
def relation_constraints(B, w, pub, blocks=None, mark=None, keep=None):
    """The ordered relation constraints AFTER the booleanity block, each lifted to nominal
    degree 7.  One description for every back end:
        BitBackend / FieldBackend : values, zero iff the constraint holds;
        faest.ProverBackend       : the 8 coefficients of the degree-7 polynomial;
        faest.VerifierBackend     : (that polynomial at Delta, 7).
    `w` = the ell witness commitments (degree 1).  `blocks`, if a list, receives
    (name, first index, end index) with indices counted from the start of the whole stream
    (booleanity = [0, ell)).  `mark(name)` is called at stage boundaries (multiplication
    counters)."""
    add, mul, add_const, lift, const = B.add, B.mul, B.add_const, B.lift, B.const
    out = []
    base = pub.ell

    def emit(z, e):
        dg = _deg(z)
        if dg is not None and dg != e:
            raise AssertionError("constraint degree %d, assigned %d" % (dg, e))
        out.append(lift(z, D_ZK - e))

    def block(name, start):
        if blocks is not None:
            blocks.append((name, base + start, base + len(out)))
        if mark is not None:
            mark(name)

    def xor_all(xs):
        acc = xs[0]
        for x in xs[1:]:
            acc = add(acc, x)
        return acc

    p = None
    if pub.kind == "vote":
        for name, off in (("a", SEL_A_OFF), ("b", SEL_B_OFF)):
            sel = w[off:off + 32]
            start = len(out)
            prefix = const(0)                          # sum_{k<j} sel_k, degree 1
            for j in range(32):
                emit(mul(sel[j], prefix), 2)           # (SP); j = 0 is identically zero
                prefix = add(prefix, sel[j])
            block(name + "-prefix", start)
            start = len(out)
            emit(add_const(prefix, 1), 1)              # (SS) 1 + sum_j sel_j
            block(name + "-sum", start)
        a, b = w[SEL_A_OFF:SEL_A_OFF + 32], w[SEL_B_OFF:SEL_B_OFF + 32]
        p = [mul(a[i // 32], b[i % 32]) for i in range(pub.S)]      # degree 2
        start = len(out)
        emit(add_const(xor_all(p), 1), 2)              # (SR) 1 + sum_{i<S} p_i
        block("range", start)

    sk = w[SK_OFF:SK_OFF + SK_BITS]
    for d, (pname, _tag, out_bits) in enumerate(PERMS[pub.kind]):
        ic = pub.init_consts[d]
        st = [sk[t - SK_STATE_OFF] if SK_STATE_OFF <= t < SK_STATE_OFF + SK_BITS
              else const((ic >> t) & 1) for t in range(STATE_BITS)]
        for g in range(1, GROUPS + 1):
            start = len(out)
            nxt = group_circuit(B, st, g)
            off = PERM_OFF[d] + STATE_BITS * (g - 1)
            st = w[off:off + STATE_BITS]
            for t in range(STATE_BITS):
                emit(add(st[t], nxt[t]), 4)            # (T)
            block("T_%s g=%d" % (pname, g), start)     # (T) commitment, (TA)/(TN), (TV)
        o = group_circuit(B, st, GROUPS + 1)
        start = len(out)
        bits = pub.out_bits[d]
        if bits is None:
            for t in range(out_bits):                  # (VC) public multiplexer
                z = o[t]
                rows = pub.mux_rows[t]
                if rows:
                    z = add(z, xor_all([p[i] for i in rows]))
                emit(z, 4)
        else:
            for t in range(out_bits):                  # (RC) (RA); (VN) 1024 bits; (VA) 512 bits
                emit(add_const(o[t], (bits >> t) & 1), 4)
        block("out_%s" % pname, start)
        if keep is not None:
            keep.append(o)
    return out


def full_stream(B, w, pub, blocks=None):
    """Booleanity (the backend's generic block, increasing witness index) then the relation."""
    if len(w) != pub.ell:
        raise ValueError("witness length")
    z = FZ.booleanity(B, w)
    if blocks is not None:
        blocks.append(("booleanity", 0, len(z)))
    return z + relation_constraints(B, w, pub, blocks)


# ---- plain evaluators
def eval_plain_bits(pub, columns, n=1):
    """columns[i] = int, bit k = witness bit i of instance k.  -> (values, blocks)."""
    blocks = []
    return full_stream(BitBackend(n), columns, pub, blocks), blocks


def eval_plain_field(pub, values, f=None):
    """values[i] in K.  -> (values, blocks)."""
    blocks = []
    return full_stream(FieldBackend(f or FZ.field(256)), values, pub, blocks), blocks


def witness_bits(w, ell):
    return FZ.int_to_bits(w, ell)


# ======================================================================== witness generation
def permutation_states(msg132):
    """-> (states after 2, 4, .., 22 rounds, final state), all as 1600-bit ints."""
    if len(msg132) != 132:
        raise ValueError("message length")
    a = state_to_lanes(int.from_bytes(msg132 + b"\x1f\x00\x00\x80" + bytes(64), "little"))
    states = []
    for ir in range(24):
        a = keccak_round_lanes(a, ir)
        if ir % 2 == 1:
            states.append(lanes_to_state(a))
    return states[:GROUPS], states[GROUPS]


def build_witness(kind, pad, sk, msgs, index=None, selectors=None):
    """The extended witness as an int.  `msgs` = the 132-byte SHAKE messages in permutation
    order: registration (commitment, authorization); vote (commitment, nullifier, vote
    authorization).  `index` = list position (vote); `selectors` overrides the two 32-bit
    selector words (a, b)."""
    if len(pad) != PAD_BITS // 8 or len(sk) != SK_BYTES:
        raise ValueError("pad or sk length")
    if len(msgs) != N_PERMS[kind]:
        raise ValueError("one SHAKE message per permutation")
    w = int.from_bytes(pad, "little") | (int.from_bytes(sk, "little") << SK_OFF)
    for d in range(N_PERMS[kind]):
        states, _final = permutation_states(msgs[d])
        for g in range(GROUPS):
            w |= states[g] << (PERM_OFF[d] + STATE_BITS * g)
    if kind == "vote":
        if selectors is None:
            selectors = (1 << (index // 32), 1 << (index % 32))
        w |= (selectors[0] << SEL_A_OFF) | (selectors[1] << SEL_B_OFF)
    return w


# ======================================================================== statements
class Context:
    pass


def reg_statement(enc_body_context, encs, c, auth):
    """encs: the six Enc strings in REG_ENC_FIELDS order."""
    st = {"enc_body_context": enc_body_context, "C": c, "auth": auth}
    st.update(zip(REG_ENC_FIELDS, encs))
    return st


def vote_statement(b, scope, lst, nf, auth_v, vote, pol, r=None, s=None):
    """The vote statement.  D_v is NOT a statement field: it is always recomputed."""
    return {"B": b, "scope": scope, "R": list_digest(b, lst, validate=False) if r is None else r,
            "S": len(lst) if s is None else s, "L": list(lst), "nf": nf, "auth_v": auth_v,
            "vote": vote, "policy_hash": pol}


def statement_vote_auth_digest(row, stmt):
    """D_v of a vote statement under the row's descriptor digest (no validation)."""
    return vote_auth_digest(descriptor_digest(row), stmt["B"], stmt["scope"], stmt["R"],
                            stmt["S"], stmt["L"], stmt["nf"], stmt["vote"], stmt["policy_hash"])


def _need(x, n, maxlen=None):
    if not isinstance(x, (bytes, bytearray)) or (n is not None and len(x) != n):
        raise ValueError("public field length")
    if maxlen is not None and len(x) > maxlen:
        raise ValueError("opaque public input longer than its bound")


def public_context(row, kind, stmt, skip_list_validation=False):
    """Public validation + derived values (B, D, D_reg, namespaces, mu, relation inputs).
    Raises ValueError on a malformed statement."""
    ctx = Context()
    ctx.row, ctx.kind = row, kind
    ctx.D = descriptor_digest(row)
    if kind == "reg":
        encs = [stmt[k] for k in REG_ENC_FIELDS]
        _need(stmt["enc_body_context"], None, ENC_BODY_CONTEXT_MAX)
        for e in encs:
            _need(e, None, ENC_FIELD_MAX)
        _need(stmt["C"], 128)
        _need(stmt["auth"], 64)
        ctx.B = body_digest(stmt["enc_body_context"])
        ctx.D_reg = reg_auth_digest(ctx.D, stmt["enc_body_context"], encs, ctx.B, stmt["C"])
        ctx.ns = namespace(ctx.D, "REG")
        ctx.prefix = role_prefix(row, kind)
        ctx.F = f_reg(stmt["enc_body_context"], encs, ctx.B, stmt["C"], stmt["auth"])
        ctx.mu = mu_of(ctx.prefix, ctx.F)
        ctx.pub = public_reg(ctx.B, ctx.D_reg, stmt["C"], stmt["auth"])
        ctx.msg_x = (ctx.B, ctx.D_reg)
        ctx.tags = (b"PCR1", b"PAU1")
    elif kind == "vote":
        for k in ("B", "scope", "R", "auth_v", "policy_hash"):
            _need(stmt[k], 64)
        _need(stmt["nf"], NF_BYTES)
        lst, s, vote = stmt["L"], stmt["S"], stmt["vote"]
        if not isinstance(vote, int) or isinstance(vote, bool) or vote not in (0, 1, 2):
            raise ValueError("vote value")
        if not isinstance(s, int) or not 0 <= s < 65536:
            raise ValueError("S encoding")
        if not skip_list_validation:
            if validate_list(lst) != s:
                raise ValueError("S does not equal the list length")
            if list_digest(stmt["B"], lst) != stmt["R"]:
                raise ValueError("R is not the digest of the list")
        ctx.B = stmt["B"]
        ctx.ns = namespace(ctx.D, "VOTE")
        ctx.prefix = role_prefix(row, kind)
        if skip_list_validation:           # test hook only: still require well-formed entries
            for c in lst:
                _need(c, 128)
        # D_v is recomputed from the statement and the compiled descriptor digest; a digest
        # supplied by the caller (for example a stray "D_v" key) is never read.
        ctx.D_v = vote_auth_digest(ctx.D, ctx.B, stmt["scope"], stmt["R"], s, lst, stmt["nf"],
                                   vote, stmt["policy_hash"])
        ctx.F = f_vote(ctx.B, stmt["scope"], stmt["R"], s, lst, stmt["nf"], stmt["auth_v"], vote,
                       stmt["policy_hash"])
        ctx.mu = mu_of(ctx.prefix, ctx.F)
        ctx.pub = public_vote(ctx.B, stmt["scope"], ctx.D_v, lst, stmt["nf"], stmt["auth_v"])
        ctx.msg_x = (ctx.B, stmt["scope"], ctx.D_v)
        ctx.tags = (b"PCR1", b"PNF1", b"PAV1")
    else:
        raise ValueError("kind")
    return ctx


def honest_witness(ctx, pad, sk, index=None):
    msgs = [shake_message(ctx.tags[d], sk, ctx.msg_x[d]) for d in range(len(ctx.tags))]
    return build_witness(ctx.kind, pad, sk, msgs, index)


# ======================================================================== prove / verify
def _stage_marker(trace, f):
    last = [f.calls, f.nontrivial]

    def mark(name):
        if trace is not None:
            st = trace.setdefault("stages", [])
            st.append((name, f.calls - last[0], f.nontrivial - last[1]))
        last[0], last[1] = f.calls, f.nontrivial
    return mark


def _zk_prove_unchecked(P, wbits, V, ubar, vbar, chall2, relation):
    """faest.zk_prove without the 'top coefficient is zero' self-check (soundness tests run
    the honest prover algorithm on an invalid witness)."""
    F = P.F
    B = FZ.ProverBackend(F)
    w = [[V[i], wbits[i]] for i in range(len(wbits))]
    z = FZ.booleanity(B, w) + relation(B, w)
    at = []
    for j in range(D_ZK):
        if j == 0:
            pj = vbar[0]
        elif j == D_ZK - 1:
            pj = ubar[D_ZK - 2]
        else:
            pj = ubar[j - 1] ^ vbar[j]
        at.append(FZ.zk_hash(F, chall2, [c[j] for c in z], pj))
    return at, len(z)


def prove(row, kind, stmt, sk, tape, index=None, witness=None, allow_invalid=False,
          trace=None, vc_cache=None, skip_list_validation=False):
    """-> raw proof bytes.  tape = 112 bytes: r = tape[0..32], iv_pre = tape[32..48],
    pad = tape[48..80], salt = tape[80..112].  `witness` (an int) overrides the honest extended witness;
    `allow_invalid` runs the honest prover algorithm even if the witness violates the
    relation (tests only)."""
    if len(tape) != TAPE_BYTES:
        raise ValueError("the proving tape is exactly 112 bytes")
    P = backend_params(row, kind)
    lam, lb, ell, F = P.lam, P.lb, P.ell, P.F
    ellb = ell // 8
    ctx = public_context(row, kind, stmt, skip_list_validation)
    r, iv_pre, pad, salt = tape[0:32], tape[32:48], tape[48:80], tape[80:112]
    if witness is None:
        witness = honest_witness(ctx, pad, sk, index)
    mark = _stage_marker(trace, F)
    mu = ctx.mu
    pre = P.prefix
    assert pre == ctx.prefix and len(pre) == 77
    iv = FZ.H4(lam, iv_pre + mu, pre)                 # no H3
    key = (P.name, pre, r, iv, salt)
    if vc_cache is not None and key in vc_cache:
        vc = vc_cache[key]
    else:
        vc = FZ.vole_commit(P, r, iv, salt)
        if vc_cache is not None:
            vc_cache[key] = vc
    chall1 = FZ.chall1_of(P, mu, vc["com"], vc["cs"], vc["c_mult"], iv_pre, salt)
    u, V, ubar, vbar = vc["u"], vc["V"], vc["ubar"], vc["vbar"]
    mark("commit")
    u_t = FZ.vole_hash(F, chall1, FZ.int_to_bits(u, ell) + ubar[:D_ZK - 1], ubar[D_ZK - 1:])
    mark("VOLEHash(u)")
    v_t = FZ.vole_hash(F, chall1, V + vbar[:D_ZK - 1], vbar[D_ZK - 1:])
    mark("VOLEHash(V)")
    wbits = FZ.int_to_bits(witness, ell)
    d = witness ^ u
    u_t_b = b"".join(F.to_bytes(e) for e in u_t)
    chall2 = FZ.H2(lam, 2, chall1 + u_t_b + b"".join(F.to_bytes(e) for e in v_t)
                   + d.to_bytes(ellb, "little"), 3 * lb + 8, pre)
    tail, head = [], []

    def relation(B, w):
        mark("booleanity")
        z = relation_constraints(B, w, ctx.pub, mark=mark)
        tail.extend(z[-16:])
        head.extend(z[:16])
        return z
    if allow_invalid:
        at, n_c = _zk_prove_unchecked(P, wbits, V, ubar, vbar, chall2, relation)
    else:
        at, n_c = FZ.zk_prove(P, wbits, V, ubar, vbar, chall2, relation)
    mark("ZKHash")
    assert n_c == N_CONSTRAINTS[kind]
    at_b = b"".join(F.to_bytes(e) for e in at)
    ctr = 0
    while True:
        chall3 = FZ.H2(lam, 3, chall2 + at_b + ctr.to_bytes(4, "little"), lb, pre)
        idx = FZ.decode_all_chall3(P, int.from_bytes(chall3, "little"))
        if idx is not None:
            decom_i = FZ.bavc_open(P, vc["decom"], idx)
            if decom_i is not None:
                break
        if ctr == 0x000FFFFF:
            raise GrindingExhausted()
        ctr += 1
    proof = (b"".join(c.to_bytes(ellb, "little") for c in vc["cs"])
             + FZ.serialize_cm(P, vc["c_mult"]) + u_t_b + d.to_bytes(ellb, "little")
             + at_b[lb:] + decom_i + chall3 + iv_pre + salt + ctr.to_bytes(4, "little"))
    assert len(proof) == P.sig_bytes
    if trace is not None:
        trace.update(ctx=ctx, mu=mu, iv=iv, com=vc["com"], chall1=chall1, chall2=chall2,
                     u_t=u_t, v_t=v_t, at=at, ctr=ctr, chall3=chall3, witness=witness,
                     V=V, last16=tail, rel_first16=head, n_constraints=n_c, u=u, r=r)
    return proof


def verify(row, kind, stmt, proof, cache=None, trace=None, skip_list_validation=False):
    """-> bool.  Rejects any proof whose length is not exactly proof_bytes(row, kind)."""
    def reject(why):
        if trace is not None:
            trace["reject"] = why
        return False
    P = backend_params(row, kind)
    lam, lb, ell, F = P.lam, P.lb, P.ell, P.F
    ellb = ell // 8
    if not isinstance(proof, (bytes, bytearray)) or len(proof) != P.sig_bytes:
        return reject("length")
    proof = bytes(proof)
    try:
        ctx = public_context(row, kind, stmt, skip_list_validation)
    except (ValueError, KeyError, TypeError) as exc:
        return reject("public validation: %s" % exc)
    f = FZ.parse_signature(P, proof)
    if f is None:
        return reject("c_mult padding")
    mark = _stage_marker(trace, F)
    mu = ctx.mu
    pre = P.prefix
    assert pre == ctx.prefix and len(pre) == 77
    iv = FZ.H4(lam, f["iv_pre"] + mu, pre)
    chall = int.from_bytes(f["chall3"], "little")
    if chall >> P.nd:
        return reject("grinding bits")
    rec = FZ.vole_reconstruct(P, chall, f["decom_i"], f["cs"], f["c_mult"], iv, cache=cache, salt=f["salt"])
    if rec is None:
        return reject("BAVC reconstruction")
    Q, qbar, delta = rec["Q"], rec["qbar"], rec["delta"]
    chall1 = FZ.chall1_of(P, mu, rec["com"], f["cs"], f["c_mult"], f["iv_pre"], f["salt"])
    mark("reconstruct")
    q_t = FZ.vole_hash(F, chall1, Q + qbar[:D_ZK - 1], qbar[D_ZK - 1:])
    u_t = [int.from_bytes(f["u_t_b"][i * lb:(i + 1) * lb], "little") for i in range(4)]
    dd = [q_t[i] ^ F.mul(delta, u_t[i]) for i in range(4)]
    mark("VOLEHash(Q)")
    chall2 = FZ.H2(lam, 2, chall1 + f["u_t_b"] + b"".join(F.to_bytes(e) for e in dd)
                   + f["d"].to_bytes(ellb, "little"), 3 * lb + 8, pre)

    def relation(B, w):
        mark("booleanity")
        z = relation_constraints(B, w, ctx.pub, mark=mark)
        # internal check, mirrors the prover's: the stream fed to ZKHash has the frozen length
        assert len(w) + len(z) == N_CONSTRAINTS[kind]
        return z
    a0 = FZ.zk_verify(P, f["d"], Q, qbar, chall2, delta, f["at_tail"], relation)
    mark("ZKHash")
    at_b = F.to_bytes(a0) + b"".join(F.to_bytes(e) for e in f["at_tail"])
    chall3 = FZ.H2(lam, 3, chall2 + at_b + f["ctr"], lb, pre)
    if trace is not None:
        trace.update(mu=mu, iv=iv, com=rec["com"], chall1=chall1, chall2=chall2, a0=a0,
                     delta=delta, chall3=chall3, Q=Q)
    if chall3 != f["chall3"]:
        return reject("chall_3 mismatch")
    return True


def proof_fields(row, kind, proof):
    """[(field name, offset, length)] of the raw proof (FAEST v3 field order)."""
    return backend_params(row, kind).sig_layout()


# ======================================================================== test-only statement codec
TEST_TAG = {"reg": "PARL/TEST/REG/v1", "vote": "PARL/TEST/VOTE/v1"}


def statement_fields(row, kind, stmt):
    """The fields of F_R in their stated order (B recomputed for registration)."""
    if kind == "reg":
        return ([stmt["enc_body_context"]] + [stmt[k] for k in REG_ENC_FIELDS]
                + [body_digest(stmt["enc_body_context"]), stmt["C"], stmt["auth"]])
    return [stmt["B"], stmt["scope"], stmt["R"], u16(stmt["S"]), b"".join(stmt["L"]), stmt["nf"],
            stmt["auth_v"], u8(stmt["vote"]), stmt["policy_hash"]]


def test_statement(row, kind, stmt):
    """TEST_STATEMENT_R = Frame("PARL/TEST/<R>/v1"; D, fields of F_R in their stated order)."""
    return frame(TEST_TAG[kind], descriptor_digest(row), *statement_fields(row, kind, stmt))


def test_record(row, kind, stmt, proof):
    ts = test_statement(row, kind, stmt)
    return u32(len(ts)) + ts + u32(len(proof)) + proof


def _parse_frame(data, tag, nfields):
    t = tag.encode("ascii")
    if data[:2] != u16(len(t)) or data[2:2 + len(t)] != t:
        raise ValueError("test statement tag")
    off = 2 + len(t)
    if data[off:off + 2] != u16(nfields):
        raise ValueError("test statement field count")
    off += 2
    fields = []
    for _ in range(nfields):
        if off + 4 > len(data):
            raise ValueError("test statement truncated")
        n = int.from_bytes(data[off:off + 4], "little")
        off += 4
        if off + n > len(data):
            raise ValueError("test statement truncated")
        fields.append(data[off:off + n])
        off += n
    if off != len(data):
        raise ValueError("test statement trailing bytes")
    return fields


def decode_test_statement(row, kind, data):
    """-> statement dict.  Checks the tag, the exact field count, the expected D, all bounds
    and the absence of trailing bytes (vote: also S, the list and R, through public_context)."""
    if kind == "reg":
        f = _parse_frame(data, TEST_TAG[kind], 11)
        if f[0] != descriptor_digest(row):
            raise ValueError("descriptor digest")
        stmt = reg_statement(f[1], f[2:8], f[9], f[10])
        if len(f[8]) != 64 or f[8] != body_digest(f[1]):
            raise ValueError("B is not the digest of the body context")
    else:
        f = _parse_frame(data, TEST_TAG[kind], 10)
        if f[0] != descriptor_digest(row):
            raise ValueError("descriptor digest")
        if len(f[4]) != 2 or len(f[8]) != 1 or len(f[5]) % 128:
            raise ValueError("vote statement field length")
        lst = [f[5][i:i + 128] for i in range(0, len(f[5]), 128)]
        stmt = {"B": f[1], "scope": f[2], "R": f[3], "S": int.from_bytes(f[4], "little"),
                "L": lst, "nf": f[6], "auth_v": f[7], "vote": f[8][0], "policy_hash": f[9]}
    public_context(row, kind, stmt)          # bounds and public validation
    return stmt


def decode_test_record(row, kind, data):
    """-> (statement, proof).  Exact lengths, no trailing bytes."""
    if len(data) < 4:
        raise ValueError("test record truncated")
    n = int.from_bytes(data[:4], "little")
    if len(data) < 8 + n:
        raise ValueError("test record truncated")
    stmt = decode_test_statement(row, kind, data[4:4 + n])
    m = int.from_bytes(data[4 + n:8 + n], "little")
    proof = data[8 + n:]
    if len(proof) != m or m != proof_bytes(row, kind):
        raise ValueError("test record proof length")
    return stmt, proof
