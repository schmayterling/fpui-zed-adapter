# fpui zed adapter

experimental runtime adapter for fpui. injects a rust dylib into a private copy of zed, hooks its paint path, and adds an `fpui` settings category with `woah` and `debug` pages.

## requirements

- macos on apple silicon (arm64).
- zed **1.27.0**, build **20261104.154313**, installed at `/Applications/Zed.app`. the executable must match [the pinned adapter](adapters/zed-1.27.0-arm64.json); version number alone is insufficient.
- rust through rustup, apple command line tools, and python 3. [rust-toolchain.toml](rust-toolchain.toml) selects rust 1.92.0. first build needs network access for dependencies and frida gum.

## build and launch

```sh
git clone https://github.com/schmayterling/fpui-zed-adapter.git
cd fpui-zed-adapter
cargo build --release --locked --features sprites -j 2
python3 run.py --prepare-only
python3 run.py --mode card
```

`run.py` verifies the installed executable, copies the app to `target/Zed.app`, ad-hoc signs that copy, and checks its text hash and paint entry bytes. it launches the copy with `target/zed-user-data` as its separate profile and injects `target/release/libfpui_paint_inject.dylib`. the installed app stays untouched. preparation also runs automatically on each launch.

open zed settings, select `fpui`, then open `woah` for the support card or `debug` for the patch inspector. the `sprites` feature enables text and image rendering; a build without it draws shapes only. quit the launched app to end an unbounded run.

optional mascot: supply your own png or gif. only the first frame renders.

```sh
FPUI_MASCOT=/absolute/path/mascot.png python3 run.py --mode card
```

## launch options

```sh
# keep a purple rectangle visible for 30 seconds
python3 run.py --mode cover --rect 360,140,240,96 --seconds 30

# append one rectangle; it may disappear on the next repaint
python3 run.py --mode once

# observe paint calls without appending paint-hook rectangles
python3 run.py --mode observe --seconds 10

# open a project with the injected app
python3 run.py --mode card --open /absolute/path/to/project

# launch a baseline without the injected dylib
python3 run.py --no-inject
```

`--rect` takes logical `x,y,width,height`; `--card-xy` takes logical `x,y` and defaults to `320,160`. `FPUI_CARD_ANCHOR` accepts `fixed` (default), `tl`, `tr`, `bl`, `br`, or `center` for window-relative placement. logs go to the terminal. `python3 run.py --help` lists all runner flags.

## adapter and limits

[adapters/zed-1.27.0-arm64.json](adapters/zed-1.27.0-arm64.json) holds executable hashes, function offsets, entry signatures, memory layouts, and the native style template. the dylib checks the loaded executable's text hash and paint entry bytes before hooking it. `run.py` selects this adapter directly.

`native_mode` in that json selects paint-only fallback (`0`), wrapping a host element (`1`), or standalone native layout (`2`, bundled default). the native path paints during the element's paint phase; card coordinates and dimensions remain fixed or anchored rather than following layout bounds.

this is an experimental adapter to private rust internals. incorrect offsets or layouts can crash the launched app. an updated zed binary needs newly verified offsets, signatures, and layouts before repinning hashes. the card's donate button is visual only; gif animation and general widget/configuration apis are not implemented. [evidence/](evidence/) contains screenshots and logs from earlier runs.

## ai disclosure

this project uses ai-assisted development, including code, reverse-engineering investigation, and documentation. ai-generated abi and memory-layout hypotheses require validation against the actual binary; generated output alone is not evidence. recorded results apply to the pinned build, not other zed versions. ai assistance does not imply independent review of every code path.

## license

mit; see [license](LICENSE). zed, dependencies, and separately supplied assets retain their own licenses.
