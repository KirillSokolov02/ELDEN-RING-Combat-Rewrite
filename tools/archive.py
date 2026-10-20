"""Reads files straight out of the game's encrypted archives (`Data3.bhd/.bdt`,
`sd/sd.bhd/.bdt`), natively, without UXM or Wine.

The `.bhd` index is RSA-"encrypted" with the archive's public key: each
256-byte block raised to e mod n gives 255 bytes of plaintext. The public keys
are read from your own eldenring.exe, where they are stored as PEM text; the
one that turns the index into "BHD5" is the archive's. Decrypted, it is a BHD5
index (little-endian):

  header   "BHD5", u32 0x1FF, u32 1, u32 size, u32 bucket_count,
           u32 buckets_offset, u32 salt_length, salt
  bucket   u32 entry_count, u32 entries_offset
  entry    u64 path_hash, u32 padded_size, u32 unpadded_size,
           i64 bdt_offset, i64 sha_offset, i64 aes_offset
  aes      u8[16] key, u32 range_count, range_count x (i64 start, i64 end)

A file sits in bucket `path_hash % bucket_count`. Within the `.bdt`, the byte
ranges listed under its AES key are AES-128-ECB encrypted; the rest is plain.
AES runs through the `openssl` command-line tool.
"""
import base64
import re
import struct
import subprocess
from functools import cache
from pathlib import Path

EXE = "eldenring.exe"


def path_hash(path):
    """lowercase, '/'-separated, leading '/', then h = h * 0x85 + byte (64-bit)."""
    p = path.lower().replace("\\", "/")
    if not p.startswith("/"):
        p = "/" + p
    h = 0
    for c in p.encode():
        h = (h * 0x85 + c) & 0xFFFFFFFFFFFFFFFF
    return h


def public_numbers(der):
    """(n, e) of an RSA-2048 public key, found by the modulus's INTEGER header."""
    i = der.find(b"\x02\x82\x01\x01\x00")
    if i < 0 or der[i + 261] != 0x02:
        raise ValueError("not an RSA-2048 public key")
    n = int.from_bytes(der[i + 5:i + 261], "big")
    e = int.from_bytes(der[i + 263:i + 263 + der[i + 262]], "big")
    return n, e


@cache
def exe_keys(game_dir):
    """Every RSA public key stored as PEM text in the game's executable."""
    exe = Path(game_dir) / EXE
    pems = re.findall(rb"-----BEGIN RSA PUBLIC KEY-----(.+?)-----END RSA PUBLIC KEY-----",
                      exe.read_bytes(), re.S)
    keys = []
    for body in pems:
        try:
            keys.append(public_numbers(base64.b64decode(b"".join(body.split()))))
        except ValueError:
            pass
    if not keys:
        raise ValueError(f"no RSA public keys found in {exe}")
    return keys


def _rsa_block(block, n, e):
    return pow(int.from_bytes(block, "big"), e, n).to_bytes(256, "big")[1:]


def rsa_decrypt(raw, keys):
    """Decrypt an index with whichever of `keys` turns it into BHD5."""
    if len(raw) % 256:
        raise ValueError(f"index is {len(raw)} bytes, not a multiple of 256")
    n, e = next(((n, e) for n, e in keys if _rsa_block(raw[:256], n, e)[:4] == b"BHD5"),
                (None, None))
    if n is None:
        raise ValueError("none of the game's public keys decrypts this index")
    out = b"".join(_rsa_block(raw[k:k + 256], n, e) for k in range(0, len(raw), 256))
    return out[:struct.unpack_from("<I", out, 0x0C)[0]]


class Entry:
    def __init__(self, data, offset):
        (self.path_hash, self.padded_size, self.unpadded_size, self.bdt_offset,
         _sha, aes) = struct.unpack_from("<QIIqqq", data, offset)
        self.aes_key, self.aes_ranges = None, []
        if aes:
            self.aes_key = data[aes:aes + 16]
            count, = struct.unpack_from("<I", data, aes + 16)
            for r in range(count):
                start, end = struct.unpack_from("<qq", data, aes + 20 + 16 * r)
                if start != -1:
                    self.aes_ranges.append((start, end))


class Index:
    """A decrypted BHD5 index."""

    def __init__(self, data):
        magic, _, _, size, count, buckets, salt_len = struct.unpack_from("<4sIIIIII", data)
        if magic != b"BHD5" or size != len(data):
            raise ValueError("not a complete BHD5 index")
        self.salt = data[0x1C:0x1C + salt_len].decode("ascii")
        self.buckets = []
        for b in range(count):
            n, at = struct.unpack_from("<II", data, buckets + 8 * b)
            self.buckets.append([Entry(data, at + 40 * k) for k in range(n)])

    def lookup(self, path):
        h = path_hash(path)
        return next((e for e in self.buckets[h % len(self.buckets)] if e.path_hash == h), None)


def _aes_ecb_decrypt(data, key):
    return subprocess.run(["openssl", "enc", "-d", "-aes-128-ecb", "-K", key.hex(), "-nopad"],
                          input=data, capture_output=True, check=True).stdout


class Archive:
    """One `<name>.bhd` / `<name>.bdt` pair under the game folder, e.g. "Data3"."""

    def __init__(self, game_dir, name):
        raw = (Path(game_dir) / f"{name}.bhd").read_bytes()
        self.index = Index(rsa_decrypt(raw, exe_keys(Path(game_dir))))
        self.bdt = Path(game_dir) / f"{name}.bdt"

    def read(self, path):
        """The stored bytes of `path` (still DCX-compressed if it was stored so), or None."""
        entry = self.index.lookup(path)
        if entry is None:
            return None
        with open(self.bdt, "rb") as f:
            f.seek(entry.bdt_offset)
            buf = bytearray(f.read(entry.padded_size))
        for start, end in entry.aes_ranges:
            end = min(end, len(buf))
            if start < end:
                buf[start:end] = _aes_ecb_decrypt(bytes(buf[start:end]), entry.aes_key)
        if entry.unpadded_size:
            del buf[entry.unpadded_size:]
        return bytes(buf)
