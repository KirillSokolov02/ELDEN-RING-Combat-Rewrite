"""Unpacks the game files the tools need, natively, in place of UXM and
WitchyBND (README, step 1):

  chr/c0000*.anibnd.dcx       from Data3
  regulation-bin/*.param      from regulation.bin
  sd/cs_smain.bnk,            from sd/sd, with the streamed recordings
  sd/enus/cs_main.bnk,        the banks refer to (optional: --no-sound)
  sd/wem/**.wem

Everything, the decryption keys included, comes from your own game folder:
nothing from the game ships with this repository. Reads the game folder from
ER_GAME_DIR and writes to ER_FILES (see README):

    python tools/unpack.py
"""
import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import archive
import paths
import regulation
import wwise

ANIBNDS = ["c0000"] + [f"c0000_{s}" for s in
                       ("a00_hi", "a00_lo", "a00_md", "a0x", "a1x", "a2x", "a3x", "a4x", "a5x")]
BANKS = ("cs_smain.bnk", "enus/cs_main.bnk")


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def unpack_anims(game, out):
    data3 = archive.Archive(game, "Data3")
    for name in ANIBNDS:
        data = data3.read(f"chr/{name}.anibnd.dcx")
        if data is None:
            sys.exit(f"chr/{name}.anibnd.dcx is not in Data3")
        _write(out / "chr" / f"{name}.anibnd.dcx", data)
    print(f"  {len(ANIBNDS)} animation binders")


def unpack_params(game, out):
    count = 0
    key = regulation.find_key(game)
    for name, data in regulation.params((game / "regulation.bin").read_bytes(), key):
        _write(out / "regulation-bin" / f"{name}.param", data)
        count += 1
    print(f"  {count} params")


def unpack_sound(game, out):
    sd = archive.Archive(game, "sd/sd")
    banks = []
    for name in BANKS:
        data = sd.read(name)
        if data is None:
            sys.exit(f"{name} is not in sd/sd")
        _write(out / "sd" / name, data)
        banks.append(wwise.Bank(data))
    streamed = sorted({o.media for bank in banks for o in bank.objects.values()
                       if o.kind == wwise.SOUND and o.stream and o.media})
    found = 0
    for mid in streamed:
        rel = f"wem/{str(mid)[:2]}/{mid}.wem"
        data = sd.read(rel)
        if data is not None:
            _write(out / "sd" / rel, data)
            found += 1
    print(f"  {len(BANKS)} sound banks, {found} of {len(streamed)} streamed recordings")


def main():
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--no-sound", action="store_true", help="skip the sound banks")
    args = ap.parse_args()
    game = paths.game_dir()
    out = Path(os.environ.get("ER_FILES", "er-files"))
    print(f"Unpacking from {game} into {out}")
    unpack_anims(game, out)
    unpack_params(game, out)
    if not args.no_sound:
        unpack_sound(game, out)
    print("\nDone. Next:  python tools/setup.py")


if __name__ == "__main__":
    main()
