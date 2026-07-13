"""Read and update the project ``.env`` file.

Used by the IDS setup scripts to auto-point NetScope at Suricata/Zeek logs.
Preserves existing comments and ordering; upserts the keys it's given.

CLI:  python -m netscope.envfile KEY=VALUE [KEY2=VALUE2 ...]
"""
from __future__ import annotations

import sys
from pathlib import Path

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def read_env() -> dict[str, str]:
    data: dict[str, str] = {}
    if not ENV_PATH.exists():
        return data
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        data[key.strip()] = value.strip()
    return data


def set_env(updates: dict[str, str]) -> None:
    """Insert or update the given keys in .env, preserving the rest of the file."""
    lines = (
        ENV_PATH.read_text(encoding="utf-8").splitlines()
        if ENV_PATH.exists()
        else []
    )
    remaining = dict(updates)

    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        replaced = False
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in remaining:
                out.append(f"{key}={remaining.pop(key)}")
                replaced = True
        if not replaced:
            out.append(line)

    for key, value in remaining.items():
        out.append(f"{key}={value}")

    ENV_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    updates: dict[str, str] = {}
    for arg in argv:
        if "=" not in arg:
            print(f"skipping '{arg}' (expected KEY=VALUE)")
            continue
        key, _, value = arg.partition("=")
        updates[key.strip()] = value.strip()
    if not updates:
        print("usage: python -m netscope.envfile KEY=VALUE [KEY2=VALUE2 ...]")
        return 1
    set_env(updates)
    print(f"Updated {ENV_PATH} with: {', '.join(updates)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
