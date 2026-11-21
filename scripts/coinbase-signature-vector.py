#!/usr/bin/env python3
# Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
# SPDX-License-Identifier: AGPL-3.0-only
#
# This file is part of ZODL OHTTP.
#
# ZODL OHTTP is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License,
# version 3 only, as published by the Free Software Foundation.
#
# ZODL OHTTP is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# Commercial licensing: see COMMERCIAL-LICENSE.md.

"""Reference of the coinbase session signature (gateway/CONFIG.md "Session signature").

An independent implementation for wallet developers, Python 3 standard library only: its own
secp256k1 arithmetic, RFC 6979 deterministic nonces (HMAC-SHA-256), low-S normalisation,
public key recovery, RIPEMD-160 (in pure Python: hashlib's may be missing) and base58check.
It is a reference, not production code: nothing in it is constant time.

    coinbase-signature-vector.py check
        reproduce the published vectors byte for byte (exit 0) or fail
    coinbase-signature-vector.py vector <private key hex> <timestamp> [uncompressed]
        print the message, its hash, the address and the signature of a key
    coinbase-signature-vector.py verify <address> <timestamp> <signature base64>
        exit 0 when the signature is the address's (the gateway's checks but the clock)
"""

import base64
import hashlib
import hmac
import re
import struct
import sys

PURPOSE = "zodl-onramp-session-v1"
MAGIC = b"Zcash Signed Message:\n"
P2PKH = bytes([0x1C, 0xB8])  # Zcash mainnet transparent P2PKH (t1...)

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


# --- secp256k1 (affine coordinates, None is the point at infinity) ---


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (slope * slope - a[0] - b[0]) % P
    return (x, (slope * (a[0] - x) - a[1]) % P)


def point_mul(k, point=G):
    out = None
    while k:
        if k & 1:
            out = point_add(out, point)
        point = point_add(point, point)
        k >>= 1
    return out


def encode_point(point, compressed):
    x, y = point
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def lift_x(x, odd):
    if x >= P:
        return None
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if (y * y - x * x * x - 7) % P:
        return None
    return (x, y if (y & 1) == odd else P - y)


# --- RIPEMD-160 (ISO/IEC 10118-3), pure Python ---

_RL = [
    list(range(16)),
    [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
    [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
    [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
    [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13],
]
_RR = [
    [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
    [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
    [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
    [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
    [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11],
]
_SL = [
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
    [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
    [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
    [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
    [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6],
]
_SR = [
    [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
    [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
    [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
    [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
    [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11],
]
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
_M = 0xFFFFFFFF


def _f(j, x, y, z):
    if j == 0:
        return x ^ y ^ z
    if j == 1:
        return (x & y) | (~x & z)
    if j == 2:
        return (x | ~y) ^ z
    if j == 3:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _M


def ripemd160(data):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    padded = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", 8 * len(data))
    for off in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[off : off + 64])
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(5):
            for i in range(16):
                t = _rol((al + (_f(j, bl, cl, dl) & _M) + x[_RL[j][i]] + _KL[j]) & _M, _SL[j][i])
                t = (t + el) & _M
                al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t
                t = _rol((ar + (_f(4 - j, br, cr, dr) & _M) + x[_RR[j][i]] + _KR[j]) & _M, _SR[j][i])
                t = (t + er) & _M
                ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t
        h = [
            (h[1] + cl + dr) & _M,
            (h[2] + dl + er) & _M,
            (h[3] + el + ar) & _M,
            (h[4] + al + br) & _M,
            (h[0] + bl + cr) & _M,
        ]
    return struct.pack("<5I", *h)


# --- hashes, addresses, the message ---


def sha256(data):
    return hashlib.sha256(data).digest()


def hash160(data):
    return ripemd160(sha256(data))


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check_encode(payload):
    data = payload + sha256(sha256(payload))[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def base58check_decode(text):
    n = 0
    for c in text:
        if c not in B58:
            return None
        n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    data = b"\x00" * (len(text) - len(text.lstrip("1"))) + body
    if len(data) < 5 or sha256(sha256(data[:-4]))[:4] != data[-4:]:
        return None
    return data[:-4]


def address_of(public_key):
    return base58check_encode(P2PKH + hash160(public_key))


def compact_size(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def message(address, timestamp):
    return f"{PURPOSE}\n{address}\n{timestamp}".encode()


def preimage(msg):
    return compact_size(len(MAGIC)) + MAGIC + compact_size(len(msg)) + msg


def message_hash(msg):
    return sha256(sha256(preimage(msg)))


# --- signing (RFC 6979 with SHA-256) and verification ---


def rfc6979_k(secret, digest):
    x = secret.to_bytes(32, "big")
    h = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, "sha256").digest()
    v = hmac.new(k, v, "sha256").digest()
    k = hmac.new(k, v + b"\x01" + x + h, "sha256").digest()
    v = hmac.new(k, v, "sha256").digest()
    while True:
        v = hmac.new(k, v, "sha256").digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", "sha256").digest()
        v = hmac.new(k, v, "sha256").digest()


def sign(secret, digest, compressed=True):
    """The 65-byte compact signature: header, r, s (low s)."""
    if not 1 <= secret < N:
        raise ValueError("the private key must be in 1..n-1")
    z = int.from_bytes(digest, "big") % N
    k = rfc6979_k(secret, digest)
    point = point_mul(k)
    r = point[0] % N
    s = pow(k, -1, N) * (z + r * secret) % N
    if r == 0 or s == 0:
        # Negligible probability; RFC 6979 would derive the next k. Not needed for a reference.
        raise ValueError("r or s is zero for this key and message")
    recid = (point[1] & 1) | (2 if point[0] >= N else 0)
    if s > N // 2:
        s, recid = N - s, recid ^ 1
    header = 27 + recid + (4 if compressed else 0)
    return bytes([header]) + r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(address, timestamp, signature_b64):
    """Whether the signature is the address's, as the gateway checks it (the clock aside)."""
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except ValueError:
        return False
    if len(sig) != 65 or base64.b64encode(sig).decode() != signature_b64:
        return False
    header = sig[0]
    if not 27 <= header <= 34:
        return False
    compressed, recid = header >= 31, (header - 27) & 3
    r, s = int.from_bytes(sig[1:33], "big"), int.from_bytes(sig[33:], "big")
    if not (0 < r < N and 0 < s < N) or s > N // 2:
        return False
    payload = base58check_decode(address)
    if payload is None or len(payload) != 22 or payload[:2] != P2PKH:
        return False
    z = int.from_bytes(message_hash(message(address, timestamp)), "big") % N
    big_r = lift_x(r + (N if recid & 2 else 0), recid & 1)
    if big_r is None:
        return False
    r_inv = pow(r, -1, N)
    neg_z_g = point_mul((-z * r_inv) % N)
    key = point_add(neg_z_g, point_mul(s * r_inv % N, big_r))
    if key is None:
        return False
    return hash160(encode_point(key, compressed)) == payload[2:]


# --- the published vectors (gateway/CONFIG.md) ---

VECTOR = {
    "key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "timestamp": 1700000000,
    "public_key": "0284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351ccffa4b0",
    "address": "t1RwUkDxFKCydymAzBtTwHtVyH9Tvf6CiiL",
    "message": "7a6f646c2d6f6e72616d702d73657373696f6e2d76310a74315277556b4478464b437964796d417a42745477487456794839547666364369694c0a31373030303030303030",
    "preimage": "165a63617368205369676e6564204d6573736167653a0a457a6f646c2d6f6e72616d702d73657373696f6e2d76310a74315277556b4478464b437964796d417a42745477487456794839547666364369694c0a31373030303030303030",
    "hash": "3e0f90d09a41b6cc3a720cf740dbfc68abe90013111494f05aa170cd4143c7fa",
    "signature": "IJdQ6f64QRlbvvFp2dTb33IU8GeRNmRVE1/re+l6yGVkeTv0Lvbid7DGQ3JxOVXZZ4GpXl24i75ZzDQe1Z5jZAs=",
    "signature_hex": "209750e9feb841195bbef169d9d4dbdf7214f06791366455135feb7be97ac86564793bf42ef6e277b0c64372713955d96781a95e5db88bbe59cc341ed59e63640b",
    "uncompressed_address": "t1cJfqUTpZiKZ2r7vLUgQFhuj1yAmtcoDhE",
    "uncompressed_signature": "HFuzIoquD5CClZMiyd9iWfEJvtBXDyfjy0Wd6TYDz7wqX6MwseZHt1iAQy5YWb0zv4+vgYAZNUqe9u36L7jPuMs=",
    "other_key_address": "t1RSr79xfHYE8LALif4h9Puuft9pGgydJv3",
}


def vector(secret, timestamp, compressed=True):
    public_key = encode_point(point_mul(secret), compressed)
    address = address_of(public_key)
    msg = message(address, timestamp)
    digest = message_hash(msg)
    sig = sign(secret, digest, compressed)
    return {
        "public_key": public_key.hex(),
        "address": address,
        "message": msg.hex(),
        "preimage": preimage(msg).hex(),
        "hash": digest.hex(),
        "signature": base64.b64encode(sig).decode(),
        "signature_hex": sig.hex(),
    }


def expect(condition, what):
    """An explicit check (not `assert`: `python3 -O` must not skip it)."""
    if not condition:
        raise SystemExit(f"coinbase signature vectors: FAILED: {what!r}")


def check():
    expect(hashlib.sha256(b"abc").hexdigest().startswith("ba7816bf"), "SHA-256")
    # RIPEMD-160 test vectors of its authors.
    for data, digest in (
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (b"a" * 1000, "aa69deee9a8922e92f8105e007f76110f381e9cf"),
    ):
        expect(ripemd160(data).hex() == digest, ("RIPEMD-160", data[:8]))
    secret, ts = int(VECTOR["key"], 16), str(VECTOR["timestamp"])
    got = vector(secret, ts)
    for name in ("public_key", "address", "message", "preimage", "hash", "signature", "signature_hex"):
        expect(got[name] == VECTOR[name], (name, got[name]))
    text = f"{PURPOSE}\n{VECTOR['address']}\n{ts}"
    expect(bytes.fromhex(got["message"]).decode() == text, "message text")
    loose = vector(secret, ts, compressed=False)
    expect(loose["address"] == VECTOR["uncompressed_address"], ("uncompressed", loose["address"]))
    expect(loose["signature"] == VECTOR["uncompressed_signature"], ("uncompressed", loose["signature"]))
    other = vector(int("22" * 32, 16), ts)["address"]
    expect(other == VECTOR["other_key_address"], ("other key", other))
    # Verification: the vectors, and every refusal the gateway makes.
    expect(verify(VECTOR["address"], ts, VECTOR["signature"]), "the vector verifies")
    expect(
        verify(VECTOR["uncompressed_address"], ts, VECTOR["uncompressed_signature"]),
        "the uncompressed vector verifies",
    )
    expect(not verify(VECTOR["address"], str(VECTOR["timestamp"] + 1), VECTOR["signature"]), "another timestamp")
    expect(not verify(VECTOR["other_key_address"], ts, VECTOR["signature"]), "another address")
    sig = base64.b64decode(VECTOR["signature"])
    for header in (sig[0] - 4, 27 + ((sig[0] - 27) ^ 1), 29, 30, 33, 34, 26, 35):
        bad = bytes([header]) + sig[1:]
        expect(not verify(VECTOR["address"], ts, base64.b64encode(bad).decode()), ("header", header))
    s = int.from_bytes(sig[33:], "big")
    high = bytes([27 + ((sig[0] - 27) ^ 1)]) + sig[1:33] + (N - s).to_bytes(32, "big")
    expect(not verify(VECTOR["address"], ts, base64.b64encode(high).decode()), "high s")
    expect(not verify(VECTOR["address"], ts, VECTOR["signature"].rstrip("=")), "unpadded")
    for bad_key in (0, N):
        try:
            sign(bad_key, bytes(32))
        except ValueError:
            continue
        expect(False, ("a key out of range signs", bad_key))
    print("coinbase signature vectors: OK")


# The gateway's grammar of `timestamp`: decimal, no sign, no leading zero, at most 10 digits.
TIMESTAMP = re.compile(r"(0|[1-9][0-9]{0,9})")


def usage(why):
    print(f"usage error: {why}\n{__doc__}", file=sys.stderr)
    return 2


def main(argv):
    if argv[:1] == ["check"] and len(argv) == 1:
        check()
        return 0
    if argv[:1] in (["vector"], ["verify"]) and len(argv) in (3, 4):
        timestamp = argv[2]
        if not TIMESTAMP.fullmatch(timestamp):
            return usage("the timestamp must match ^(0|[1-9][0-9]{0,9})$")
    if argv[:1] == ["vector"] and len(argv) in (3, 4):
        compressed = len(argv) == 3
        if not compressed and argv[3] != "uncompressed":
            return usage("the fourth argument can only be 'uncompressed'")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", argv[1]):
            return usage("the private key must be 64 hex digits")
        secret = int(argv[1], 16)
        if not 1 <= secret < N:
            return usage("the private key must be in 1..n-1")
        for name, value in vector(secret, timestamp, compressed).items():
            print(f"{name}: {value}")
        return 0
    if argv[:1] == ["verify"] and len(argv) == 4:
        # The address exactly as given (the message signs the string as sent).
        ok = verify(argv[1], timestamp, argv[3])
        print("valid" if ok else "invalid")
        return 0 if ok else 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
