#!/usr/env/python3

from builtins import chr
from past.utils import old_div
import sys
if sys.version_info < (3, 6):
    from sha3 import sha3_512 as SHA3512
else:
    import hashlib

import sys, os

python_version = sys.version_info.major
b = 256
q = 2 ** 255 - 19
l = 2 ** 252 + 27742317777372353535851937790883648493


def H(m):
    if sys.version_info < (3, 6):
        return SHA3512(m).digest()
    else:
        sha3_512 = hashlib.sha3_512()
        sha3_512.update(m)
        return sha3_512.digest()

def expmod(b, e, m):
    if e == 0: return 1
    t = expmod(b, old_div(e, 2), m) ** 2 % m
    if e & 1: t = (t * b) % m
    return t


def inv(x):
    return expmod(x, q - 2, q)


d = -121665 * inv(121666)
I = expmod(2, old_div((q - 1), 4), q)


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = expmod(xx, old_div((q + 3), 8), q)
    if (x * x - xx) % q != 0: x = (x * I) % q
    if x % 2 != 0: x = q - x
    return x


By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx % q, By % q]


def edwards(P, Q):
    x1 = P[0]
    y1 = P[1]
    x2 = Q[0]
    y2 = Q[1]
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2)
    return [x3 % q, y3 % q]


def scalarmult(P, e):
    if e == 0: return [0, 1]
    Q = scalarmult(P, old_div(e, 2))
    Q = edwards(Q, Q)
    if e & 1: Q = edwards(Q, P)
    return Q


def encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(old_div(b, 8))])


def encodepoint(P):
    x = P[0]
    y = P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(old_div(b, 8))])


if python_version == 3:
    def bit(h, i):
        return ((h[old_div(i, 8)]) >> (i % 8)) & 1
else:
    def bit(h, i):
        return (ord(h[old_div(i, 8)]) >> (i % 8)) & 1


def publickey(sk):
    h = H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * bit(h, i) for i in list(range(3, b - 2)))
    A = scalarmult(B, a)
    return encodepoint(A)


def Hint(m):
    h = H(m)
    return sum(2 ** i * bit(h, i) for i in list(range(2 * b)))


def signature(m, sk, pk):
    h = H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * bit(h, i) for i in list(range(3, b - 2)))
    r = Hint(''.join([h[i] for i in range(old_div(b, 8), old_div(b, 4))]) + m)
    R = scalarmult(B, r)
    S = (r + Hint(encodepoint(R) + pk + m) * a) % l
    return encodepoint(R) + encodeint(S)


def isoncurve(P):
    x = P[0]
    y = P[1]
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def decodeint(s):
    return sum(2 ** i * bit(s, i) for i in list(range(0, b)))


def decodepoint(s):
    y = sum(2 ** i * bit(s, i) for i in list(range(0, b - 1)))
    x = xrecover(y)
    if x & 1 != bit(s, b - 1): x = q - x
    P = [x, y]
    if not isoncurve(P): raise Exception("decoding point that is not on curve")
    return P


def checkvalid(s, m, pk):
    if len(s) != old_div(b, 4): raise Exception("signature length is wrong")
    if len(pk) != old_div(b, 8): raise Exception("public-key length is wrong")
    R = decodepoint(s[0:old_div(b, 8)])
    A = decodepoint(pk)
    S = decodeint(s[old_div(b, 8):old_div(b, 4)])
    h = Hint(encodepoint(R) + pk + m)
    if scalarmult(B, S) != edwards(R, scalarmult(A, h)):
        raise Exception("signature does not pass verification")


def derive_pubkey_from_priv(priv):
    return publickey(priv)


def sign(msg, priv, pub):
    return signature(msg, priv, pub)


def verify(msg, sig, pub):
    try:
        checkvalid(sig, msg, pub)
        return True
    except Exception:
        return False

k = os.urandom(32)
# private key
if sys.version_info >= (3, 0):
    print(k.hex())
else:
    print(k.encode('hex'))
pub = derive_pubkey_from_priv(k)
# public key
print(''.join(hex(ord(j))[2:].zfill(2) for j in pub))
