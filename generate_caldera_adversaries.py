"""
Generate CALDERA-native adversary YAML files from the orchestrator's adversary profiles.

Output: caldera_adversaries/<name>.yaml  (one file per adversary)

Usage:
    python generate_caldera_adversaries.py

Then copy the output directory to your CALDERA installation:
    cp -r caldera_adversaries/* <caldera_dir>/data/adversaries/
    sudo systemctl restart caldera   # or however you run CALDERA
"""
from __future__ import annotations

from pathlib import Path
import yaml

SRC_DIR = Path(__file__).parent / "config" / "adversaries"
OUT_DIR = Path(__file__).parent / "caldera_adversaries"

# Default CALDERA objective UUID ("default" objective present in every CALDERA install)
DEFAULT_OBJECTIVE = "495a9828-cab1-44dd-a0ca-66e58177d8cc"


def convert(src: Path) -> None:
    raw = yaml.safe_load(src.read_text())

    adversary_id = raw.get("caldera_adversary_id", "")
    if not adversary_id:
        print(f"  SKIP {src.name} — no caldera_adversary_id")
        return

    ability_ids = [
        t["caldera_ability_id"]
        for t in raw.get("techniques", [])
        if t.get("caldera_ability_id")
    ]

    caldera_yaml = {
        "id":              adversary_id,
        "name":            raw.get("display_name", raw["name"]),
        "description":     raw.get("description", ""),
        "atomic_ordering": ability_ids,
        "tags":            [],
        "objective":       DEFAULT_OBJECTIVE,
    }

    out_path = OUT_DIR / src.name
    out_path.write_text(yaml.dump(caldera_yaml, allow_unicode=True, sort_keys=False))
    print(f"  OK  {src.name}  ({len(ability_ids)} ability)")


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    files = sorted(SRC_DIR.glob("escu_*.yaml"))
    print(f"Generating {len(files)} adversary file(s) → {OUT_DIR}/\n")
    for f in files:
        convert(f)
    print(f"\nDone. Copy to CALDERA with:")
    print(f"  cp -r {OUT_DIR}/* <caldera_dir>/data/adversaries/")
    print(f"  sudo systemctl restart caldera")


if __name__ == "__main__":
    main()
