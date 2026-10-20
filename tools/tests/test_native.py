"""Tests for the native Linux unpacking (archive.py, regulation.py, unpack.py)
and erfmt's native Oodle path.

Sources of truth: the layout spec in archive.py (synthetic fixture), and the
game's own files: hashes stored in its indexes, sizes declared in its DCX
headers, the Wwise bank magic, and the struct names the community Paramdex
gives the params. Tests that need the game skip when ER_GAME_DIR has no game.

    python -m unittest discover -s tools/tests -v
"""
import os
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import archive  # noqa: E402
import erfmt  # noqa: E402
import paths  # noqa: E402
import regulation  # noqa: E402
import unpack  # noqa: E402

GAME = Path(os.environ.get("ER_GAME_DIR", paths.DEFAULT_GAME_DIR))
HAVE_GAME = (GAME / "Data3.bhd").exists()


def build_index(salt, buckets):
    """A BHD5 index laid out as archive.py's docstring describes."""
    head = 0x1C + len(salt)
    table = head + 8 * len(buckets)
    keys_at = table + 40 * sum(len(b) for b in buckets)
    directory, body, keys = b"", b"", b""
    for bucket in buckets:
        directory += struct.pack("<II", len(bucket), table + len(body))
        for h, key, ranges in bucket:
            aes = keys_at + len(keys) if key else 0
            if key:
                keys += key + struct.pack("<I", len(ranges)) + b"".join(
                    struct.pack("<qq", s, e) for s, e in ranges)
            body += struct.pack("<QIIqqq", h, 0x20, 0, 0x1000, 0, aes)
    size = keys_at + len(keys)
    header = struct.pack("<4sIIIIII", b"BHD5", 0x1FF, 1, size, len(buckets), head, len(salt))
    return header + salt + directory + body + keys


class TestIndexSpec(unittest.TestCase):
    def test_index_entries_and_aes_ranges_synthetic_spec(self):
        key = bytes(range(16))
        h = archive.path_hash("/chr/x.dcx")
        buckets = [[], []]
        buckets[h % 2].append((h, key, [(0, 0x400), (-1, -1)]))
        index = archive.Index(build_index(b"GR_chr", buckets))
        entry = index.lookup("chr\\X.dcx")  # case and separators don't matter
        self.assertEqual(index.salt, "GR_chr")
        self.assertEqual((entry.padded_size, entry.bdt_offset), (0x20, 0x1000))
        self.assertEqual(entry.aes_key, key)
        self.assertEqual(entry.aes_ranges, [(0, 0x400)])  # (-1, -1) is an unused slot
        self.assertIsNone(index.lookup("chr/y.dcx"))


@unittest.skipUnless(HAVE_GAME, "Elden Ring not found at ER_GAME_DIR")
class TestGameArchives(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data3 = archive.Archive(GAME, "Data3")

    def test_entries_sit_in_hash_bucket_game_index(self):
        n = len(self.data3.index.buckets)
        for b, bucket in enumerate(self.data3.index.buckets):
            for entry in bucket:
                self.assertEqual(entry.path_hash % n, b)

    def test_anibnd_paths_found_game_index(self):
        # A wrong hash function would not match the hashes the game stores.
        for name in unpack.ANIBNDS:
            self.assertIsNotNone(self.data3.index.lookup(f"chr/{name}.anibnd.dcx"), name)

    @unittest.skipUnless(erfmt.linoodle_path(), "liblinoodle.so not found (LINOODLE)")
    def test_native_oodle_matches_dcx_declared_size_game_data(self):
        data = self.data3.read("chr/c0000_a00_lo.anibnd.dcx")
        self.assertEqual(data[:4], b"DCX\0")
        declared, = struct.unpack_from(">I", data, 0x1C)
        bnd = erfmt.dcx(data)
        self.assertEqual(len(bnd), declared)
        self.assertEqual(bnd[:4], b"BND4")

    def test_sound_banks_are_wwise_banks_game_index(self):
        sd = archive.Archive(GAME, "sd/sd")
        for name in unpack.BANKS:
            self.assertEqual(sd.read(name)[:4], b"BKHD", name)


@unittest.skipUnless((GAME / "regulation.bin").exists(), "regulation.bin not found at ER_GAME_DIR")
class TestRegulation(unittest.TestCase):
    # Params tools/extract.py reads, with the struct names Paramdex gives them.
    PARAMDEX = {
        "BehaviorParam_PC": "BEHAVIOR_PARAM_ST",
        "AtkParam_Pc": "ATK_PARAM_ST",
        "EquipParamWeapon": "EQUIP_PARAM_WEAPON_ST",
        "CharaInitParam": "CHARACTER_INIT_PARAM",
        "CalcCorrectGraph": "CACL_CORRECT_GRAPH_ST",
    }

    def test_params_struct_names_paramdex(self):
        key = regulation.find_key(GAME)
        params = dict(regulation.params((GAME / "regulation.bin").read_bytes(), key))
        for name, struct_name in self.PARAMDEX.items():
            data = params[name]
            at, = struct.unpack_from("<q", data, 0x10)
            self.assertEqual(data[at:data.index(b"\0", at)].decode("ascii"), struct_name, name)


if __name__ == "__main__":
    unittest.main()
