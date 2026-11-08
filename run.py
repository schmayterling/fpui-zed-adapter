#!/usr/bin/env python3
"""Verify exact build, prepare private ad-hoc signed copy, run optional injection."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
ADAPTER = ROOT / "adapters/zed-1.27.0-arm64.json"
SOURCE = Path("/Applications/Zed.app")


def text_hash(path, pin):
    with path.open("rb") as stream:
        stream.seek(pin["text_offset"])
        return hashlib.sha256(stream.read(pin["text_size"])).hexdigest()


def prepare():
    pin = json.loads(ADAPTER.read_text())
    original = SOURCE / "Contents/MacOS/zed"
    if hashlib.sha256(original.read_bytes()).hexdigest() != pin["source_sha256"]:
        raise SystemExit("installed zed differs; re-pin adapter before running")
    clone = ROOT / "target/Zed.app"
    binary = clone / "Contents/MacOS/zed"
    if not clone.exists():
        shutil.copytree(SOURCE, clone, symlinks=True)
    if text_hash(binary, pin) != pin["text_sha256"]:
        raise SystemExit("private copy differs; inspect it before replacing")
    subprocess.run(["codesign", "--force", "--deep", "--sign", "-", str(clone)], check=True)
    if text_hash(binary, pin) != pin["text_sha256"]:
        raise SystemExit("text changed after signing")
    with binary.open("rb") as stream:
        stream.seek(pin["paint_quad_offset"])
        actual = stream.read(len(bytes.fromhex(pin["paint_quad_bytes"])))
    if actual.hex() != pin["paint_quad_bytes"]:
        raise SystemExit("paint entry mismatch")
    print("paint-spike: source identity, private text hash, and entry verified", flush=True)
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("once", "cover", "observe", "card"), default="once")
    parser.add_argument("--rect", default="360,140,240,96", help="logical x,y,width,height")
    parser.add_argument("--card-xy", default="320,160", help="card mode: logical origin x,y")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--no-inject", action="store_true")
    parser.add_argument("--seconds", type=float, help="bound test run, then terminate own child")
    parser.add_argument("--open", help="path to open in Zed (project/file) for live repaints")
    args = parser.parse_args()
    binary = prepare()
    if args.prepare_only:
        return
    environment = os.environ.copy()
    if not args.no_inject:
        library = ROOT / "target/release/libfpui_paint_inject.dylib"
        if not library.is_file():
            raise SystemExit("build first: cargo build --release -j 2")
        environment.update(DYLD_INSERT_LIBRARIES=str(library),
                           FPUI_PAINT_ADAPTER=str(ADAPTER),
                           FPUI_PAINT_MODE=args.mode, FPUI_PAINT_RECT=args.rect,
                           FPUI_CARD_XY=args.card_xy)
    command = [str(binary), "--user-data-dir", str(ROOT / "target/zed-user-data")]
    if args.open:
        command.append(args.open)
    if args.seconds is None:
        os.execve(binary, command, environment)
    with subprocess.Popen(command, env=environment) as child:
        try:
            code = child.wait(timeout=args.seconds)
        except subprocess.TimeoutExpired:
            child.terminate()
            try:
                code = child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                code = child.wait()
            print(f"paint-spike: bounded run ended; child={code}", flush=True)
            return
        if code:
            raise SystemExit(code)


if __name__ == "__main__":
    main()
