"""Unpacks the game's regulation.bin into loose `.param` files, natively,
the layout WitchyBND produces and tools/param.py reads.

regulation.bin is a 16-byte IV followed by AES-256-CBC data. The key is read
from your own eldenring.exe: this file holds only its SHA-256, and the 32
bytes of the executable that hash to it are the key. Decrypted, it is a DCX
holding a ZSTD-compressed BND4 whose entries are the params.
"""
import hashlib
import struct
import subprocess
from pathlib import Path, PureWindowsPath

import erfmt

KEY_SHA256 = bytes.fromhex("cb349d15a6492969e3c801dbf4d60c721e9c58abd4b40cfc5b87aff253d68c72")


def find_key(game_dir):
    """The regulation key, from the game's executable."""
    data = memoryview((Path(game_dir) / "eldenring.exe").read_bytes())
    for step in (16, 1):  # it has been 16-aligned; scan every byte if a patch moves it
        for at in range(0, len(data) - 31, step):
            if hashlib.sha256(data[at:at + 32]).digest() == KEY_SHA256:
                return bytes(data[at:at + 32])
    raise ValueError("the regulation key was not found in eldenring.exe")


def decrypt(data, key):
    return subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", key.hex(), "-iv", data[:16].hex(), "-nopad"],
        input=data[16:], capture_output=True, check=True).stdout


def _zstd(data):
    try:
        from compression import zstd  # Python 3.14+
        return zstd.decompress(data)
    except ImportError:
        pass
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    except ImportError:
        pass
    return subprocess.run(["zstd", "-d", "-c"], input=data, capture_output=True, check=True).stdout


def dcx_zstd(data):
    if data[:4] != b"DCX\0" or data[0x28:0x2C] != b"ZSTD":
        raise ValueError(f"expected a ZSTD DCX, got {data[:4]!r} / {data[0x28:0x2C]!r}: wrong key?")
    raw_size, comp_size = struct.unpack_from(">II", data, 0x1C)
    out = _zstd(data[0x4C:0x4C + comp_size])
    if len(out) != raw_size:
        raise ValueError(f"ZSTD gave {len(out)} bytes, the DCX declares {raw_size}")
    return out


def params(regulation_bin, key):
    """(name, bytes) of every param, e.g. ("BehaviorParam_PC", ...)."""
    for _, name, data in erfmt.bnd4(dcx_zstd(decrypt(regulation_bin, key))):
        yield PureWindowsPath(name).stem, data
