//! Pinned arm64 machine-code bridge. Deliberately does not link gpui.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use frida_gum::{
    interceptor::{InvocationContext, InvocationListener, Interceptor},
    Gum, NativePointer,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    ffi::c_void,
    sync::{atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering}, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

// Live window logical size, captured from the full-window background quad, for anchoring.
static WIN_W: AtomicU32 = AtomicU32::new(0);
static WIN_H: AtomicU32 = AtomicU32::new(0);

// Card origin for anchor mode (bl/tr/tl/center, else bottom-right). Insets account for the
// title bar / status bar so the box aligns inside the editor chrome.
fn anchor_origin(anchor: &str, ww: f32, wh: f32, cw: f32, ch: f32) -> [f32; 2] {
    let m = 24.0;
    let (top, bot) = (40.0, 36.0);
    match anchor {
        "bl" => [m, (wh - ch - bot).max(top)],
        "tr" => [(ww - cw - m).max(m), top],
        "tl" => [m, top],
        "center" => [((ww - cw) / 2.0).max(m), ((wh - ch) / 2.0).max(top)],
        _ => [(ww - cw - m).max(m), (wh - ch - bot).max(top)], // "br"
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[derive(Deserialize)]
struct Adapter {
    text_offset: usize,
    text_size: usize,
    text_sha256: String,
    paint_quad_offset: usize,
    paint_quad_bytes: String,
    scene_offset: usize,
    quads_vec_offset: usize,
    paint_ops_vec_offset: usize,
    scale_offset: usize,
    #[serde(default)]
    paint_image_offset: usize,
    #[serde(default)]
    paint_image_bytes: String,
    // Path-3 native element (0=off, 1=wrap, 2=standalone). The standalone fields are filled
    // from the one live lldb capture (NATIVE-ELEMENTS.md "SINGLE LIVE EXPERIMENT"); wrap needs none.
    #[serde(default)]
    native_mode: u8,
    #[serde(default)]
    native_engine_req_layout_offset: usize, // runtime = base + this (TaffyLayoutEngine::request_layout)
    #[serde(default)]
    native_style_hex: String,               // captured ~632B gpui Style (heap-free/default-shaped)
    #[serde(default)]
    native_win_engine_off: usize,           // Window offset: layout_engine Box ptr
    #[serde(default)]
    native_win_rem_off: usize,              // Window offset: rem_size f32
}

struct State {
    adapter: Adapter,
    rect: [f32; 4],
    mode: String,
    card_xy: [f32; 2],
    anchor: String,
    done: AtomicBool,
    hits: AtomicUsize,
    appends: AtomicUsize,
    // card mode: once-per-frame late-insert tracking (see paint_hook).
    last_before: AtomicUsize,
    cur_max: AtomicUsize,
    prev_max: AtomicUsize,
    inserted: AtomicBool,
}
static STATE: OnceLock<State> = OnceLock::new();
static ORIGINAL: AtomicUsize = AtomicUsize::new(0);
// Resolved entry of Zed's own Window::paint_image (not hooked; we CALL it to append
// an image sprite, letting gpui do the atlas upload + PolychromeSprite insert). 0 = off.
static PAINT_IMAGE: AtomicUsize = AtomicUsize::new(0);
thread_local! { static IN_HOOK: Cell<bool> = const { Cell::new(false) }; }

// Window::paint_image ABI, reversed from the pinned build's prologue+body (all args in
// x0..x6; geometry passed BY POINTER, so a plain extern "C" bridge matches exactly):
//   paint_image(&mut Window, &bounds[4f32], &image_bounds[4f32], &corner_radii[4f32],
//               Arc<RenderImage> inner-ptr, frame_index, grayscale) -> ptr (null = Ok)
// bounds/corner_radii are logical Pixels; gpui snaps/scales via Window+0x2280 itself.
type PaintImageFn = unsafe extern "C" fn(
    *mut u8, *const [f32; 4], *const [f32; 4], *const [f32; 4], *const u8, usize, bool,
) -> *mut u8;

extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(index: u32) -> *const u8;
    fn pthread_main_np() -> i32;
}

// _dyld_get_image_header(0) is NOT reliably the main executable under
// DYLD_INSERT_LIBRARIES: the inserted dylib can take a low index. Pick the image
// whose Mach-O filetype is MH_EXECUTE. Hashing text_size from a wrong, smaller
// base walks off the mapping -> SIGBUS before any hook is installed.
unsafe fn main_image_header() -> *const u8 {
    const MH_EXECUTE: u32 = 0x2;
    for i in 0.._dyld_image_count() {
        let header = _dyld_get_image_header(i);
        if !header.is_null() && header.add(12).cast::<u32>().read() == MH_EXECUTE {
            return header;
        }
    }
    std::ptr::null()
}

// Verified in this target's disassembly: x0=&mut Window, x1=indirect by-value
// PaintQuad, no return value. This is a machine ABI bridge, not a Rust ABI claim.
type PaintFn = unsafe extern "C" fn(*mut u8, *mut u8);

#[repr(C, align(16))]
struct QuadBytes([u32; 36]);

// Craft a by-value PaintQuad. Pinned layout: style 0, background 4 (solid hsla at
// byte 12), bounds 76, corner radii 92, border widths 108, border hsla 124; size
// 140, align 4. All lengths logical px; paint_quad device-scales them itself.
fn quad_bytes(rect: [f32; 4], hsla: [f32; 4], radius: f32) -> QuadBytes {
    let mut bytes = QuadBytes([0; 36]);
    for (i, value) in hsla.into_iter().enumerate() {
        bytes.0[3 + i] = value.to_bits();
    }
    for (i, value) in rect.into_iter().enumerate() {
        bytes.0[19 + i] = value.to_bits();
    }
    for i in 0..4 {
        bytes.0[23 + i] = radius.to_bits();
    }
    bytes
}

// Proof modes (once/cover) keep their pinned purple with square corners.
fn paint_bytes(rect: [f32; 4]) -> QuadBytes {
    quad_bytes(rect, [0.77, 0.82, 0.56, 1.0], 0.0)
}

// sRGB hex -> gpui Hsla [h,s,l,a] in 0..1 (gpui stores HSL in sRGB space; the
// once-mode readback came back as plain HSL, confirming no linearization).
fn rgb_to_hsla(hex: u32, alpha: f32) -> [f32; 4] {
    let r = ((hex >> 16) & 0xff) as f32 / 255.0;
    let g = ((hex >> 8) & 0xff) as f32 / 255.0;
    let b = (hex & 0xff) as f32 / 255.0;
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let l = (max + min) / 2.0;
    let d = max - min;
    let s = if d == 0.0 { 0.0 } else { d / (1.0 - (2.0 * l - 1.0).abs()) };
    let h = if d == 0.0 {
        0.0
    } else if max == r {
        ((g - b) / d).rem_euclid(6.0) / 6.0
    } else if max == g {
        ((b - r) / d + 2.0) / 6.0
    } else {
        ((r - g) / d + 4.0) / 6.0
    };
    [h, s, l, alpha]
}

// "Support The Project" card flattened from fpui-zed-woah/src/main.rs to absolute
// logical rects at origin (ox, oy). Stage A = quads only: rounded purple card bg,
// white mascot disc, white Donate pill. Text / heart / animated mascot are sprites
// (next stage). Returns (rect, hsla, corner_radius), painted back-to-front.
fn card_quads(ox: f32, oy: f32) -> [([f32; 4], [f32; 4], f32); 3] {
    let card = rgb_to_hsla(0x9c85ef, 1.0); // Vencord SpecialCard purple
    let white = [0.0, 0.0, 1.0, 1.0];
    let (w, h) = (600.0_f32, 170.0_f32);
    [
        ([ox, oy, w, h], card, 14.0),
        ([ox + w - 24.0 - 104.0, oy + 20.0, 104.0, 104.0], white, 52.0),
        ([ox + 24.0, oy + 112.0, 106.0, 38.0], white, 19.0),
    ]
}

// The debug panel background: a Zed-surface-colored rounded box.
fn debug_quads(ox: f32, oy: f32) -> [([f32; 4], [f32; 4], f32); 1] {
    [([ox, oy, 600.0, 158.0], rgb_to_hsla(0x2f343c, 1.0), 10.0)]
}

// Stage B: paint the card's sprite content (mascot image + text) into Zed's own scene by
// calling Zed's paint_image once per sprite. Each sprite is a prebuilt ArcInner<RenderImage>
// pointer + its logical rect relative to the card origin. No-op if paint_image isn't armed.
#[cfg(feature = "sprites")]
unsafe fn paint_sprites(window: *mut u8, ox: f32, oy: f32, list: &[sprite::Sprite]) {
    let addr = PAINT_IMAGE.load(Ordering::Acquire);
    if addr == 0 {
        return;
    }
    let paint_image: PaintImageFn = std::mem::transmute(addr);
    for &(block, dx, dy, w, h, radius) in list {
        if block == 0 {
            continue;
        }
        let bounds = [ox + dx, oy + dy, w, h];
        let radii = [radius; 4];
        paint_image(window, &bounds, &bounds, &radii, block as *const u8, 0, false);
    }
}

#[cfg(feature = "sprites")]
unsafe fn draw_card_sprites(window: *mut u8, ox: f32, oy: f32) {
    paint_sprites(window, ox, oy, sprite::card_sprites());
}
#[cfg(feature = "sprites")]
unsafe fn draw_debug_sprites(window: *mut u8, ox: f32, oy: f32) {
    paint_sprites(window, ox, oy, sprite::debug_sprites());
}

#[cfg(not(feature = "sprites"))]
unsafe fn draw_card_sprites(_window: *mut u8, _ox: f32, _oy: f32) {}
#[cfg(not(feature = "sprites"))]
unsafe fn draw_debug_sprites(_window: *mut u8, _ox: f32, _oy: f32) {}

#[cfg(feature = "sprites")]
mod sprite {
    use std::alloc::{alloc_zeroed, Layout};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::OnceLock;

    // Render at 2x so text/images are crisp on the pinned target's Retina (scale=2) display;
    // each sprite's logical rect is the device bitmap divided by this.
    const SCALE: f32 = 2.0;

    // One entry per sprite: (ArcInner block ptr, dx, dy, w, h, corner_radius) in logical px
    // relative to the panel origin. Built once.
    pub type Sprite = (usize, f32, f32, f32, f32, f32);
    static SPRITES: OnceLock<Vec<Sprite>> = OnceLock::new();
    static DEBUG_SP: OnceLock<Vec<Sprite>> = OnceLock::new();

    pub fn card_sprites() -> &'static [Sprite] {
        SPRITES.get_or_init(build_card).as_slice()
    }

    pub fn debug_sprites() -> &'static [Sprite] {
        DEBUG_SP.get_or_init(build_debug).as_slice()
    }

    fn yn(b: bool) -> &'static str {
        if b { "ok" } else { "--" }
    }

    // The debug panel = text sprites of the loader's REAL live state; fields the standalone
    // spike can't see yet are labeled "awaiting loader integration" (never faked).
    fn build_debug() -> Vec<Sprite> {
        let base = super::settings_category::DEBUG_BASE.load(Ordering::Relaxed);
        let pq = super::ORIGINAL.load(Ordering::Relaxed) != 0;
        let pi = super::PAINT_IMAGE.load(Ordering::Relaxed) != 0;
        let sub = super::settings_category::RENDER_FN.load(Ordering::Relaxed) != 0;
        let lines: [(String, u32, f32); 6] = [
            ("fpui - patch inspector".into(), 0xd6dae1, 15.0),
            ("identity   Zed 1.27.0 arm64 | pinned __text sha256 verified".into(), 0x9aa0ad, 11.0),
            (format!("base addr  {base:#x}  (MH_EXECUTE, ASLR-resolved)"), 0x9aa0ad, 11.0),
            (format!("live sites paint_quad {} | paint_image {} | settings_data ok", yn(pq), yn(pi)), 0x9aa0ad, 11.0),
            (format!("fpui cat   appended 15->16 | woah+debug sub-rows {}", yn(sub)), 0x9aa0ad, 11.0),
            ("per-site token map   awaiting loader integration".into(), 0x6b7280, 11.0),
        ];
        let mut out = Vec::new();
        let mut y = 14.0f32;
        for (i, (text, color, size)) in lines.iter().enumerate() {
            if let Some((w, h, px)) = text_bgra(text, *size, *color) {
                if let Some(b) = build_block(w, h, px) {
                    out.push((b, 20.0, y, w as f32 / SCALE, h as f32 / SCALE, 0.0));
                }
            }
            y += if i == 0 { 30.0 } else { 20.0 };
        }
        out
    }

    fn build_card() -> Vec<Sprite> {
        let mut out = Vec::new();
        // mascot image in the white disc (right side of the card)
        if let Some((w, h, px)) = mascot_bgra() {
            if let Some(b) = build_block(w, h, px) {
                out.push((b, 600.0 - 24.0 - 104.0, 20.0, 104.0, 104.0, 52.0));
            }
        }
        // text: (string, logical size, color rgb, dx, dy) — card_ink #12101a, pill_ink #1a1340,
        // heart #db61a2. Flattened from fpui-zed-woah/src/main.rs.
        let texts: &[(&str, f32, u32, f32, f32)] = &[
            ("Support The Project", 20.0, 0x12101a, 24.0, 20.0),
            ("Please consider supporting the development of fpui by donating!", 13.0, 0x12101a, 24.0, 54.0),
            ("\u{2665}", 15.0, 0xdb61a2, 34.0, 120.0),
            ("Donate", 14.0, 0x1a1340, 54.0, 121.0),
        ];
        for &(s, size, rgb, dx, dy) in texts {
            if let Some((w, h, px)) = text_bgra(s, size, rgb) {
                if let Some(b) = build_block(w, h, px) {
                    out.push((b, dx, dy, w as f32 / SCALE, h as f32 / SCALE, 0.0));
                }
            }
        }
        out
    }

    fn mascot_bgra() -> Option<(u32, u32, Vec<u8>)> {
        let path = std::env::var("FPUI_MASCOT").ok()?;
        let rgba = image::load_from_memory(&std::fs::read(&path).ok()?).ok()?.to_rgba8();
        let (w, h) = (rgba.width(), rgba.height());
        let mut d = rgba.into_raw();
        for px in d.chunks_exact_mut(4) {
            px.swap(0, 2); // RGBA -> straight BGRA (Metal blends by SourceAlpha)
        }
        Some((w, h, d))
    }

    fn font() -> Option<&'static ab_glyph::FontVec> {
        static FONT: OnceLock<Option<ab_glyph::FontVec>> = OnceLock::new();
        FONT.get_or_init(|| {
            for p in ["/System/Library/Fonts/SFNS.ttf", "/System/Library/Fonts/Supplemental/Arial.ttf"] {
                if let Ok(bytes) = std::fs::read(p) {
                    if let Ok(f) = ab_glyph::FontVec::try_from_vec(bytes) {
                        return Some(f);
                    }
                }
            }
            None
        })
        .as_ref()
    }

    // Rasterize a single line of text to a straight-alpha BGRA bitmap at device resolution
    // (logical size * SCALE). Color is constant; alpha = glyph coverage.
    fn text_bgra(text: &str, logical_px: f32, rgb: u32) -> Option<(u32, u32, Vec<u8>)> {
        use ab_glyph::{Font, ScaleFont};
        let font = font()?;
        let scaled = font.as_scaled(logical_px * SCALE);
        let (ascent, descent) = (scaled.ascent(), scaled.descent());
        let mut caret = 1.0f32;
        let mut laid = Vec::new();
        for c in text.chars() {
            let id = font.glyph_id(c);
            let g = id.with_scale_and_position(logical_px * SCALE, ab_glyph::point(caret, ascent + 1.0));
            caret += scaled.h_advance(id);
            laid.push(g);
        }
        let width = (caret + 1.0).ceil().max(1.0) as u32;
        let height = (ascent - descent + 2.0).ceil().max(1.0) as u32;
        let (r, g, b) = ((rgb >> 16) & 0xff, (rgb >> 8) & 0xff, rgb & 0xff);
        let mut bgra = vec![0u8; (width * height * 4) as usize];
        for glyph in laid {
            if let Some(outline) = font.outline_glyph(glyph) {
                let bb = outline.px_bounds();
                outline.draw(|gx, gy, cov| {
                    let (x, y) = (bb.min.x as i32 + gx as i32, bb.min.y as i32 + gy as i32);
                    if x < 0 || y < 0 || x as u32 >= width || y as u32 >= height {
                        return;
                    }
                    let i = ((y as u32 * width + x as u32) * 4) as usize;
                    let a = (cov * 255.0) as u8;
                    if a > bgra[i + 3] {
                        bgra[i] = b as u8;
                        bgra[i + 1] = g as u8;
                        bgra[i + 2] = r as u8;
                        bgra[i + 3] = a;
                    }
                });
            }
        }
        Some((width, height, bgra))
    }

    // Hand-assemble the exact ArcInner<RenderImage> Zed's paint_image reads from (w,h,BGRA).
    // Every offset reversed from the pinned binary (RenderImage::as_bytes/size + paint_image
    // disasm), version-independent — raw bytes, never a linked gpui/image/smallvec struct.
    // Block (relative to the ArcInner base passed as x4):
    //   0x00 strong  0x08 weak  0x10 SmallVec len=1  -> inline Frame @ 0x18
    //   0x18 Vec cap  0x20 Vec ptr  0x28 Vec len  0x30 width  0x34 height
    //   0x50 RenderImage.id (unique atlas key)  0x58 scale_factor
    fn build_block(w: u32, h: u32, pixels: Vec<u8>) -> Option<usize> {
        if pixels.len() != (w as usize) * (h as usize) * 4 || w == 0 || h == 0 {
            return None;
        }
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0x6670_7569_0000_0001);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed); // unique per sprite = no atlas collision
        let (cap, len) = (pixels.capacity(), pixels.len());
        let ptr = pixels.leak().as_mut_ptr(); // leak: the atlas reads it; must outlive Zed
        let block = unsafe { alloc_zeroed(Layout::from_size_align(0x60, 8).ok()?) };
        if block.is_null() {
            return None;
        }
        unsafe {
            block.add(0x00).cast::<usize>().write(1 << 28); // strong: never reaches 0
            block.add(0x08).cast::<usize>().write(1); // weak
            block.add(0x10).cast::<usize>().write(1); // SmallVec len = 1 (inline Frame @ 0x18)
            block.add(0x18).cast::<usize>().write(cap); // buffer Vec cap
            block.add(0x20).cast::<usize>().write(ptr as usize); // Vec ptr
            block.add(0x28).cast::<usize>().write(len); // Vec len
            block.add(0x30).cast::<u32>().write(w); // width
            block.add(0x34).cast::<u32>().write(h); // height
            block.add(0x50).cast::<usize>().write(id); // RenderImage.id
            block.add(0x58).cast::<u32>().write(1.0f32.to_bits()); // scale_factor
        }
        eprintln!("paint-spike: sprite block {w}x{h} id={id:#x} block={block:p}");
        Some(block as usize)
    }
}

unsafe fn usize_at(base: *const u8, offset: usize) -> usize {
    base.add(offset).cast::<usize>().read_unaligned()
}

unsafe fn floats_at(base: *const u8, offset: usize) -> [f32; 4] {
    base.add(offset).cast::<[f32; 4]>().read_unaligned()
}

unsafe fn vec_len(scene: *const u8, offset: usize) -> usize {
    usize_at(scene, offset + 16)
}

unsafe extern "C" fn paint_hook(window: *mut u8, quad: *mut u8) {
    let original: PaintFn = std::mem::transmute(ORIGINAL.load(Ordering::Acquire));
    if IN_HOOK.with(|flag| flag.replace(true)) {
        original(window, quad);
        return;
    }
    let state = STATE.get().unwrap();
    let hit = state.hits.fetch_add(1, Ordering::Relaxed);
    let host_rect = floats_at(quad, 76);
    // Capture the window logical size from the full-window background quad (origin 0,0, large).
    if host_rect[0] == 0.0 && host_rect[1] == 0.0 && host_rect[2] > 400.0 && host_rect[3] > 300.0 {
        WIN_W.store(host_rect[2].to_bits(), Ordering::Relaxed);
        WIN_H.store(host_rect[3].to_bits(), Ordering::Relaxed);
    }
    // Original first. Never reuse its by-value argument storage after the call.
    original(window, quad);

    if pthread_main_np() != 1 || state.mode == "observe"
        || (state.mode == "once" && state.done.load(Ordering::Relaxed))
    {
        IN_HOOK.with(|flag| flag.set(false));
        return;
    }
    let scene = window.add(state.adapter.scene_offset);
    let before_quads = vec_len(scene, state.adapter.quads_vec_offset);
    let before_ops = vec_len(scene, state.adapter.paint_ops_vec_offset);
    let scale = window.add(state.adapter.scale_offset).cast::<f32>().read_unaligned();
    if hit < 6 {
        eprintln!("paint-spike: host hit={hit} window={window:p} bounds={host_rect:?} scale={scale} quads={before_quads}");
    }
    // card mode: insert the whole card exactly once per frame, as late as possible
    // so it sits on top, without pinning a new per-frame seam. Frame boundary = the
    // quad count dropped vs the previous paint_quad (the scene was cleared); "near
    // the end of the frame" = the count is within a few of the previous frame's max.
    if state.mode == "card" {
        // Page gate: the card paints ONLY while one of my fpui sub-pages is freshly rendering.
        // The render detour stamps WOAH_MS/DEBUG_MS per sub-page (render + paint are the same
        // draw(), <1ms apart, so a fresh stamp == "this very frame is my sub-page"). On the
        // editor, the category page, or a foreign sub-page nothing is stamped -> no card.
        let now = now_ms();
        let on_woah = now.saturating_sub(settings_category::WOAH_MS.load(Ordering::Relaxed)) < 150;
        let on_debug = now.saturating_sub(settings_category::DEBUG_MS.load(Ordering::Relaxed)) < 150;
        if !on_woah && !on_debug {
            IN_HOOK.with(|flag| flag.set(false));
            return;
        }
        let last = state.last_before.swap(before_quads, Ordering::Relaxed);
        if before_quads < last {
            let maxed = state.cur_max.swap(before_quads, Ordering::Relaxed);
            state.prev_max.store(maxed, Ordering::Relaxed);
            state.inserted.store(false, Ordering::Relaxed);
        } else if before_quads > state.cur_max.load(Ordering::Relaxed) {
            state.cur_max.store(before_quads, Ordering::Relaxed);
        }
        let prev = state.prev_max.load(Ordering::Relaxed);
        let ready = prev > 12
            && before_quads + 3 >= prev
            && !state.inserted.load(Ordering::Relaxed)
            && scale.is_finite()
            && scale > 0.0
            && before_quads < 1_000_000;
        if ready {
            state.inserted.store(true, Ordering::Relaxed);
            // Anchor to a window corner (tracks resize) unless anchor = "fixed" (then card_xy,
            // which on a sub-page sits just under the breadcrumb header).
            let ww = f32::from_bits(WIN_W.load(Ordering::Relaxed));
            let wh = f32::from_bits(WIN_H.load(Ordering::Relaxed));
            let [ox, oy] = if state.anchor != "fixed" && ww > 0.0 && wh > 0.0 {
                anchor_origin(&state.anchor, ww, wh, 600.0, 170.0)
            } else {
                state.card_xy
            };
            // woah sub-page -> Support-The-Project card; debug sub-page -> real-state panel.
            // Each owns its whole sub-page, so neither is offset below the other.
            if on_woah {
                // When the Path-3 native element is active it paints the woah card itself (native
                // paint phase) — skip the hook fallback here so the card isn't drawn twice.
                if !native_element::active() {
                    for (rect, hsla, radius) in card_quads(ox, oy) {
                        let mut qb = quad_bytes(rect, hsla, radius);
                        original(window, qb.0.as_mut_ptr().cast());
                    }
                    draw_card_sprites(window, ox, oy);
                }
            } else {
                for (rect, hsla, radius) in debug_quads(ox, oy) {
                    let mut qb = quad_bytes(rect, hsla, radius);
                    original(window, qb.0.as_mut_ptr().cast());
                }
                draw_debug_sprites(window, ox, oy);
            }
            let after = vec_len(scene, state.adapter.quads_vec_offset);
            let frame = state.appends.fetch_add(1, Ordering::Relaxed) + 1;
            if frame <= 4 || frame.is_power_of_two() {
                let which = if on_woah { "woah/card" } else { "debug/panel" };
                eprintln!("paint-spike: {which} frame={frame} quad_delta={} at=[{ox},{oy}] prev_max={prev}",
                    after.saturating_sub(before_quads));
            }
        }
        IN_HOOK.with(|flag| flag.set(false));
        return;
    }
    // ponytail: cover mode repeats the same visible card after overlapping host
    // quads. Add a late frame hook for exactly one topmost primitive per frame.
    let [x, y, w, h] = state.rect;
    let [hx, hy, hw, hh] = host_rect;
    let overlaps = hx < x+w && x < hx+hw && hy < y+h && y < hy+hh;
    if overlaps && before_quads < 1_000_000 && before_ops < 1_000_000
        && scale.is_finite() && scale > 0.0
    {
        let mut fresh = paint_bytes(state.rect);
        // The trampoline bypasses this detour. The same live Window remains
        // exclusively in the suspended caller; no pointers survive this hook.
        original(window, fresh.0.as_mut_ptr().cast());
        let after_quads = vec_len(scene, state.adapter.quads_vec_offset);
        let after_ops = vec_len(scene, state.adapter.paint_ops_vec_offset);
        if after_quads == before_quads + 1 && after_ops == before_ops + 1 {
            // Reload pointers after the target may have grown either vector.
            let ptr = usize_at(scene, state.adapter.quads_vec_offset + 8) as *const u8;
            let stored = ptr.add(before_quads * 160);
            let stored_rect = floats_at(stored, 8);
            let stored_hsla = floats_at(stored, 48);
            let stored_clip = floats_at(stored, 24);
            let op_ptr = usize_at(scene, state.adapter.paint_ops_vec_offset + 8) as *const u8;
            let replay_hsla = floats_at(op_ptr.add(before_ops * 168), 56);
            let payload_ok = stored_hsla[..3] == [0.77, 0.82, 0.56]
                && stored_hsla == replay_hsla;
            state.done.store(true, Ordering::Relaxed);
            let append = state.appends.fetch_add(1, Ordering::Relaxed) + 1;
            if append <= 8 || append.is_power_of_two() {
                eprintln!("paint-spike: appended={append} quad_delta=1 op_delta=1 payload_ok={payload_ok} bounds={stored_rect:?} clip={stored_clip:?} hsla={stored_hsla:?} order={}",
                    stored.cast::<u32>().read_unaligned());
            }
        } else if hit < 6 {
            eprintln!("paint-spike: clipped or rejected quad_delta={} op_delta={}",
                after_quads.saturating_sub(before_quads), after_ops.saturating_sub(before_ops));
        }
    }
    IN_HOOK.with(|flag| flag.set(false));
}

// Draw the fpui card into Zed's live scene at its anchored origin, using the proven re-invoke
// seam (ORIGINAL = paint_quad trampoline, bypasses the hook so no reentrancy). Shared by the
// paint_quad-hook fallback and the native element's paint phase.
unsafe fn draw_native_card(window: *mut u8) {
    let Some(state) = STATE.get() else { return };
    let orig = ORIGINAL.load(Ordering::Acquire);
    if orig == 0 { return; }
    let original: PaintFn = std::mem::transmute(orig);
    let ww = f32::from_bits(WIN_W.load(Ordering::Relaxed));
    let wh = f32::from_bits(WIN_H.load(Ordering::Relaxed));
    let [ox, oy] = if state.anchor != "fixed" && ww > 0.0 && wh > 0.0 {
        anchor_origin(&state.anchor, ww, wh, 600.0, 170.0)
    } else {
        state.card_xy
    };
    for (rect, hsla, radius) in card_quads(ox, oy) {
        let mut qb = quad_bytes(rect, hsla, radius);
        original(window, qb.0.as_mut_ptr().cast());
    }
    draw_card_sprites(window, ox, oy);
}

// ===== Path 3: native gpui element (hand-built ElementObject vtable) =====
// A `dyn ElementObject` is a fat ptr {data, vtable}. We define our own element + hand-build the
// 8-entry vtable pointing at our extern fns, then make on_leave on the woah sub-page's render fn
// overwrite the returned AnyElement with ours. Two modes:
//   WRAP (mode 1, capture-free): stash the real child, delegate request_layout/prepaint/paint to
//     its vtable, then add our card in paint. Proves the hand-built vtable + native paint phase
//     (right z-order, once/frame, no cover-mode occlusion hack). No captured values needed.
//   STANDALONE (mode 2): our request_layout calls Zed's TaffyLayoutEngine::request_layout with a
//     captured gpui Style so the card occupies its OWN layout box (real reflow). Behind the five
//     values from the one live capture (engine fn addr, Style bytes, Window offsets).
// Arena-sidestep (proven, arena.rs:218-250): AnyElement = ArenaBox{ptr:fat(&ELEM,&VTABLE),
// valid:Rc}. ArenaBox::deref only `assert!(valid.get())`; a static fake RcBox with pinned-high
// counts derefs forever and survives the drop-decrement without freeing. No gpui arena needed.
mod native_element {
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::OnceLock;

    // Captured-at-live-layout values (unset until the 2-min lldb capture; loaded from the adapter).
    pub static MODE: AtomicU8 = AtomicU8::new(0); // 0 off, 1 wrap, 2 standalone
    pub static ENGINE_REQ_LAYOUT: AtomicUsize = AtomicUsize::new(0); // runtime TaffyLayoutEngine::request_layout
    pub static WIN_ENGINE_OFF: AtomicUsize = AtomicUsize::new(usize::MAX); // Window off: layout_engine Box ptr
    pub static WIN_REM_OFF: AtomicUsize = AtomicUsize::new(usize::MAX);    // Window off: rem_size f32
    pub static WIN_SCALE_OFF: AtomicUsize = AtomicUsize::new(usize::MAX);  // Window off: scale_factor f32
    pub static STYLE: OnceLock<Vec<u8>> = OnceLock::new();                 // captured gpui Style template
    pub static IMG_LO: AtomicUsize = AtomicUsize::new(0); // main-image __text lo (vtable detection)
    pub static IMG_HI: AtomicUsize = AtomicUsize::new(0); // main-image __text hi
    // M2 capture (FPUI_CAPTURE=1): the engine ptr grabbed by a CaptureGate on the request_layout
    // candidate; el_request_layout then scans its `window` arg to resolve WIN_ENGINE_OFF live.
    pub static CAPTURE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    pub static ENG_CAP: AtomicUsize = AtomicUsize::new(0);
    static WIN_OFF_LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static VT_LOGGED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    // In capture mode, once the CaptureGate has the engine ptr, scan our `window` arg for it to
    // resolve WIN_ENGINE_OFF (the Window offset holding the layout_engine Box ptr).
    unsafe fn capture_win_scan(window: *mut u8) {
        let eng = ENG_CAP.load(Ordering::Relaxed);
        if eng == 0 || WIN_OFF_LOGGED.swap(true, Ordering::Relaxed) {
            return;
        }
        let mut hits = 0;
        for off in (0..0x4000usize).step_by(8) {
            if (window.add(off) as *const usize).read_unaligned() == eng {
                eprintln!("[fpui-cap] WIN_ENGINE_OFF={off:#x} ({off})  window={:#x} engine={eng:#x}", window as usize);
                hits += 1;
            }
        }
        eprintln!("[fpui-cap] window scan done: engine={eng:#x} hits={hits}");
    }

    pub fn wrap_active() -> bool { MODE.load(Ordering::Relaxed) == 1 }
    pub fn standalone_ready() -> bool {
        MODE.load(Ordering::Relaxed) == 2
            && ENGINE_REQ_LAYOUT.load(Ordering::Relaxed) != 0
            && STYLE.get().is_some()
            && WIN_ENGINE_OFF.load(Ordering::Relaxed) != usize::MAX
            && WIN_REM_OFF.load(Ordering::Relaxed) != usize::MAX
            && WIN_SCALE_OFF.load(Ordering::Relaxed) != usize::MAX
    }
    pub fn active() -> bool { wrap_active() || standalone_ready() }

    // Real child element stashed by inject() for WRAP delegation. One card, one sub-page, main
    // thread, synchronous render->layout->paint => a single slot is race-free for v1.
    static CHILD_DATA: AtomicUsize = AtomicUsize::new(0);
    static CHILD_VT: AtomicUsize = AtomicUsize::new(0);
    // Our element's "data" ptr: a 1-byte marker (our fns read statics, not instance data).
    static ELEM_MARKER: u8 = 0;

    // The hand-built ElementObject vtable. Rust trait-object layout = [drop_in_place, size, align,
    // then methods in declaration order]: inner_element, request_layout, prepaint, paint,
    // layout_as_root (element.rs ElementObject). All dyn methods verified: (self, window, cx).
    #[repr(C)]
    struct Vtable {
        drop_in_place: unsafe extern "C" fn(*mut u8),
        size: usize,
        align: usize,
        inner_element: unsafe extern "C" fn(*mut u8) -> DynAnyRef,
        request_layout: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) -> usize,
        prepaint: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8),
        paint: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8),
        layout_as_root: unsafe extern "C" fn(*mut u8, usize, usize, *mut u8, *mut u8) -> u64,
    }
    static VTABLE: Vtable = Vtable {
        drop_in_place: el_drop,
        size: 1,
        align: 1,
        inner_element: el_inner,
        request_layout: el_request_layout,
        prepaint: el_prepaint,
        paint: el_paint,
        layout_as_root: el_layout_as_root,
    };

    #[inline]
    unsafe fn child_slot(vt: usize, idx: usize) -> usize { (vt as *const usize).add(idx).read() }

    // &mut dyn Any fat pointer (data, vtable) returned in x0:x1.
    #[repr(C)]
    struct DynAnyRef(usize, usize);

    unsafe extern "C" fn el_drop(_self: *mut u8) {} // static element; never truly dropped
    unsafe extern "C" fn el_inner(self_: *mut u8) -> DynAnyRef { DynAnyRef(self_ as usize, 0) } // stub (downcast only)
    unsafe extern "C" fn el_layout_as_root(_s: *mut u8, _w: usize, _h: usize, _win: *mut u8, _cx: *mut u8) -> u64 {
        0 // stub: only roots call this; our card is a child
    }

    unsafe extern "C" fn el_request_layout(_self: *mut u8, window: *mut u8, cx: *mut u8) -> usize {
        if CAPTURE.load(Ordering::Relaxed) {
            capture_win_scan(window);
        }
        if wrap_active() {
            let (cd, cv) = (CHILD_DATA.load(Ordering::Relaxed), CHILD_VT.load(Ordering::Relaxed));
            if cd == 0 || cv == 0 { return 0; }
            let f: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) -> usize =
                std::mem::transmute(child_slot(cv, 4));
            return f(cd as *mut u8, window, cx); // real child's LayoutId
        }
        if !standalone_ready() { return 0; }
        // engine.request_layout(engine, &Style, rem, scale, &[]) -> LayoutId. The callee takes the
        // Style by value + drops it, so hand it a fresh owned copy (template must be heap-free).
        #[repr(C, align(16))]
        struct Buf([u8; 1024]);
        let style = STYLE.get().unwrap();
        let mut buf = Buf([0; 1024]);
        let n = style.len().min(1024);
        std::ptr::copy_nonoverlapping(style.as_ptr(), buf.0.as_mut_ptr(), n);
        let engine = (window.add(WIN_ENGINE_OFF.load(Ordering::Relaxed)) as *const usize).read_unaligned();
        let rem = (window.add(WIN_REM_OFF.load(Ordering::Relaxed)) as *const f32).read_unaligned();
        let scale = (window.add(WIN_SCALE_OFF.load(Ordering::Relaxed)) as *const f32).read_unaligned();
        // C ABI: x0=engine, x1=&Style, s0=rem, s1=scale, x2=children.ptr, x3=children.len.
        let f: unsafe extern "C" fn(usize, *const u8, f32, f32, *const u8, usize) -> usize =
            std::mem::transmute(ENGINE_REQ_LAYOUT.load(Ordering::Relaxed));
        f(engine, buf.0.as_ptr(), rem, scale, std::ptr::null(), 0)
    }

    unsafe extern "C" fn el_prepaint(_self: *mut u8, window: *mut u8, cx: *mut u8) {
        if wrap_active() {
            let (cd, cv) = (CHILD_DATA.load(Ordering::Relaxed), CHILD_VT.load(Ordering::Relaxed));
            if cd != 0 && cv != 0 {
                let f: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) = std::mem::transmute(child_slot(cv, 5));
                f(cd as *mut u8, window, cx);
            }
        }
    }

    unsafe extern "C" fn el_paint(_self: *mut u8, window: *mut u8, cx: *mut u8) {
        if wrap_active() {
            let (cd, cv) = (CHILD_DATA.load(Ordering::Relaxed), CHILD_VT.load(Ordering::Relaxed));
            if cd != 0 && cv != 0 {
                let f: unsafe extern "C" fn(*mut u8, *mut u8, *mut u8) = std::mem::transmute(child_slot(cv, 6));
                f(cd as *mut u8, window, cx); // real content paints first
            }
        }
        super::draw_native_card(window); // our card, in the native paint phase
    }

    // Static arena-sidestep RcBox: ArenaBox.valid derefs to value @ +16 (RcBox = {strong, weak,
    // value}); pinned-high counts so the per-drop decrement never frees.
    // MUST be WRITABLE: Rc clone/drop mutates strong/weak in place — a read-only static faults
    // (SIGBUS KERN_PROTECTION_FAILURE) on the first refcount write. UnsafeCell forces writable
    // placement (__DATA, not __const); counts pinned 1<<40 so they never reach 0 within a session.
    #[repr(C, align(16))]
    struct FakeRcBox {
        strong: usize,
        weak: usize,
        value: u8,
        _pad: [u8; 7],
    }
    struct ValidCell(std::cell::UnsafeCell<FakeRcBox>);
    unsafe impl Sync for ValidCell {}
    static FAKE_VALID: ValidCell = ValidCell(std::cell::UnsafeCell::new(FakeRcBox {
        strong: 1 << 40,
        weak: 1 << 40,
        value: 1,
        _pad: [0; 7],
    }));

    // A word looks like an ElementObject vtable if its drop_in_place slot (vtable[0]) lands in the
    // main image's __text and size/align (vtable[1..3]) are sane. All 3 words of a real returned
    // AnyElement are valid ptrs (data->arena, vtable->const, valid->heap RcBox), so reading them
    // can't fault; only the vtable's drop slot points into __text.
    unsafe fn looks_like_vtable(p: usize, lo: usize, hi: usize) -> bool {
        if p == 0 || (p & 7) != 0 || lo == 0 { return false; }
        let drop = (p as *const usize).read();
        let size = (p as *const usize).add(1).read();
        let align = (p as *const usize).add(2).read();
        drop >= lo && drop < hi && size < 0x0010_0000 && align != 0 && align <= 4096 && (align & (align - 1)) == 0
    }

    // Overwrite the 24-byte AnyElement at the render fn's sret with ours, after stashing the real
    // child for WRAP delegation. AnyElement = ArenaBox<dyn> = a fat ptr (data, vtable) + a valid Rc,
    // but repr(Rust) may order them [valid, data, vtable] (local probe) or [data, vtable, valid].
    // Self-detect: find the vtable slot by signature; data is its fat-ptr partner (immediately
    // before it), valid is the third. Write ours into the SAME slots — drift-proof.
    pub unsafe fn inject(sret: *mut u8) {
        let w = sret as *mut usize;
        let lo = IMG_LO.load(Ordering::Relaxed);
        let hi = IMG_HI.load(Ordering::Relaxed);
        let words = [w.read(), w.add(1).read(), w.add(2).read()];
        // vtable slot — a fat ptr's vtable can be at index 1 ([data,vtable,valid]) or 2
        // ([valid,data,vtable]). If NEITHER looks like a vtable the return isn't the AnyElement we
        // assume (wrong sret/type) — bail rather than scribble over it.
        let vt_idx = if looks_like_vtable(words[2], lo, hi) {
            2
        } else if looks_like_vtable(words[1], lo, hi) {
            1
        } else {
            eprintln!("[fpui-native] inject bail: no vtable in sret {:#x} words={words:#x?}", sret as usize);
            return;
        };
        let (data_idx, valid_idx) = if vt_idx == 1 { (0, 2) } else { (1, 0) };
        CHILD_DATA.store(words[data_idx], Ordering::Relaxed);
        CHILD_VT.store(words[vt_idx], Ordering::Relaxed);
        // M2 path B: log the real child's vtable once. [4]=Drawable::request_layout is the trace
        // entry to window.request_layout (the gpui-Style-taking fn we need to locate).
        if CAPTURE.load(Ordering::Relaxed) && !VT_LOGGED.swap(true, Ordering::Relaxed) {
            let vt = words[vt_idx];
            let mut s = String::new();
            for i in 0..8 {
                s.push_str(&format!(" [{i}]={:#x}", (vt as *const usize).add(i).read()));
            }
            eprintln!("[fpui-cap] child vtable @{vt:#x} data={:#x}:{s}", words[data_idx]);
        }
        w.add(data_idx).write(&ELEM_MARKER as *const u8 as usize);
        w.add(vt_idx).write(&VTABLE as *const Vtable as usize);
        w.add(valid_idx).write(FAKE_VALID.0.get() as usize);
    }
}

// M2 capture: attached (FPUI_CAPTURE=1) to the request_layout candidates. The one whose x1 is a
// real pointer is request_layout → log x0 (engine, for WIN_ENGINE_OFF) + 640B of the Style template.
struct CaptureGate {
    name: &'static str,
    fired: AtomicBool,
}
impl InvocationListener for CaptureGate {
    fn on_enter(&mut self, c: InvocationContext) {
        if self.fired.swap(true, Ordering::Relaxed) {
            return;
        }
        let ctx = c.cpu_context();
        let regs: Vec<usize> = (0..8).map(|i| ctx.reg(i) as usize).collect();
        eprintln!(
            "[fpui-cap] {} x0..x7 = {}",
            self.name,
            regs.iter().map(|r| format!("{r:#x}")).collect::<Vec<_>>().join(" ")
        );
        // Dump the pointee of every arg that looks like a mapped pointer (stack or heap) — the gpui
        // Style arg will show small enum/f32 bytes at offset 0, letting us pick the right reg + ABI.
        for (i, &r) in regs.iter().enumerate() {
            if (0x1_0000_0000..0x8000_0000_0000).contains(&r) && r % 4 == 0 {
                // x0 for candB/request_layout is &{Style(632B), ..}; dump enough to grab the Style.
                let n = if i == 0 { 672 } else { 96 };
                let p = r as *const u8;
                let mut s = String::with_capacity(n * 2);
                for k in 0..n {
                    s.push_str(&format!("{:02x}", unsafe { p.add(k).read() }));
                }
                eprintln!("[fpui-cap]   x{i}={r:#x} -> {s}");
            }
        }
    }
    fn on_leave(&mut self, _c: InvocationContext) {}
}

fn install() -> Result<(), Box<dyn std::error::Error>> {
    let path = match std::env::var("FPUI_PAINT_ADAPTER") {
        Ok(path) => path,
        Err(_) => return Ok(()),
    };
    let adapter: Adapter = serde_json::from_slice(&std::fs::read(path)?)?;
    let base = unsafe { main_image_header() };
    if base.is_null() { return Err("missing main image".into()); }
    eprintln!("paint-spike: main image base={base:p}");
    let actual_hash = unsafe {
        Sha256::digest(std::slice::from_raw_parts(base.add(adapter.text_offset), adapter.text_size))
    };
    if format!("{actual_hash:x}") != adapter.text_sha256 {
        return Err("text sha256 mismatch; refusing hook".into());
    }
    let entry = unsafe { base.add(adapter.paint_quad_offset) };
    let pin = (0..adapter.paint_quad_bytes.len()).step_by(2)
        .map(|i| u8::from_str_radix(&adapter.paint_quad_bytes[i..i+2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    if unsafe { std::slice::from_raw_parts(entry, pin.len()) } != pin {
        return Err("entry bytes mismatch; refusing hook".into());
    }
    // Resolve + gate Zed's paint_image (Stage B sprites). Non-fatal: if the adapter
    // lacks it or the entry drifted, sprites just stay off; the quad path is unaffected.
    if adapter.paint_image_offset != 0 && !adapter.paint_image_bytes.is_empty() {
        let pi = unsafe { base.add(adapter.paint_image_offset) };
        let pin_pi = (0..adapter.paint_image_bytes.len()).step_by(2)
            .map(|i| u8::from_str_radix(&adapter.paint_image_bytes[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()?;
        if unsafe { std::slice::from_raw_parts(pi, pin_pi.len()) } != pin_pi.as_slice() {
            eprintln!("paint-spike: paint_image entry bytes mismatch; sprites off");
        } else {
            PAINT_IMAGE.store(pi as usize, Ordering::Release);
            eprintln!("paint-spike: paint_image armed at {pi:p}");
        }
    }
    let rect: [f32; 4] = match std::env::var("FPUI_PAINT_RECT") {
        Ok(value) => value.split(',').map(str::parse).collect::<Result<Vec<f32>, _>>()?
            .try_into().map_err(|_| "rect must be x,y,width,height")?,
        Err(_) => [360.0, 140.0, 240.0, 96.0],
    };
    if !rect.iter().all(|v| v.is_finite()) || rect[2] <= 0.0 || rect[3] <= 0.0 {
        return Err("invalid rectangle".into());
    }
    let mode = std::env::var("FPUI_PAINT_MODE").unwrap_or_else(|_| "once".into());
    if !["once", "cover", "observe", "card"].contains(&mode.as_str()) {
        return Err("mode must be once, cover, observe, or card".into());
    }
    let card_xy: [f32; 2] = match std::env::var("FPUI_CARD_XY") {
        Ok(value) => value.split(',').map(str::parse).collect::<Result<Vec<f32>, _>>()?
            .try_into().map_err(|_| "card xy must be x,y")?,
        Err(_) => [320.0, 160.0],
    };
    if !card_xy.iter().all(|v| v.is_finite()) {
        return Err("invalid card origin".into());
    }
    let anchor = std::env::var("FPUI_CARD_ANCHOR").unwrap_or_else(|_| "fixed".into());
    // Path-3 native element config (adapter-driven so captured values plug in w/o a recompile).
    if adapter.native_mode != 0 {
        native_element::MODE.store(adapter.native_mode, Ordering::Relaxed);
        native_element::IMG_LO.store(base as usize + adapter.text_offset, Ordering::Relaxed);
        native_element::IMG_HI
            .store(base as usize + adapter.text_offset + adapter.text_size, Ordering::Relaxed);
        if adapter.native_engine_req_layout_offset != 0 {
            native_element::ENGINE_REQ_LAYOUT
                .store(base as usize + adapter.native_engine_req_layout_offset, Ordering::Relaxed);
        }
        if !adapter.native_style_hex.is_empty() {
            let bytes: Result<Vec<u8>, _> = (0..adapter.native_style_hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&adapter.native_style_hex[i..i + 2], 16))
                .collect();
            if let Ok(b) = bytes { let _ = native_element::STYLE.set(b); }
        }
        if adapter.native_win_engine_off != 0 {
            native_element::WIN_ENGINE_OFF.store(adapter.native_win_engine_off, Ordering::Relaxed);
        }
        if adapter.native_win_rem_off != 0 {
            native_element::WIN_REM_OFF.store(adapter.native_win_rem_off, Ordering::Relaxed);
        }
        native_element::WIN_SCALE_OFF.store(adapter.scale_offset, Ordering::Relaxed); // reuse known scale offset
        eprintln!(
            "[fpui-native] mode={} wrap_active={} standalone_ready={} engine={:#x} style={}B",
            adapter.native_mode,
            native_element::wrap_active(),
            native_element::standalone_ready(),
            native_element::ENGINE_REQ_LAYOUT.load(Ordering::Relaxed),
            native_element::STYLE.get().map(|s| s.len()).unwrap_or(0),
        );
    }
    settings_category::DEBUG_BASE.store(base as u64, Ordering::Release);
    STATE.set(State { adapter, rect, mode, card_xy, anchor, done: AtomicBool::new(false),
        hits: AtomicUsize::new(0), appends: AtomicUsize::new(0),
        last_before: AtomicUsize::new(0), cur_max: AtomicUsize::new(0),
        prev_max: AtomicUsize::new(0), inserted: AtomicBool::new(false) })
        .map_err(|_| "already initialized")?;
    let gum = Gum::obtain();
    let mut interceptor = Interceptor::obtain(&gum);
    let trampoline = interceptor.replace(NativePointer(entry as *mut c_void),
        NativePointer(paint_hook as *mut c_void), NativePointer(std::ptr::null_mut()))
        .map_err(|e| format!("replace failed: {e:?}"))?;
    ORIGINAL.store(trampoline.0 as usize, Ordering::Release);
    // Capstone: also append a real `fpui` category to Zed's data-driven settings, via a
    // separate seam (detour settings_data, grow its returned Vec<SettingsPage>). Non-fatal.
    settings_category::attach(base, &mut interceptor);
    // M2 capture gates (FPUI_CAPTURE=1): hook the 3 request_layout candidates (file offsets from
    // the EXPECT_MESSAGE xref). The one with a pointer x1 is request_layout → logs engine + Style.
    if std::env::var("FPUI_CAPTURE").is_ok() {
        native_element::CAPTURE.store(true, Ordering::Relaxed);
        for (name, off) in [("candA", 0x2266430usize), ("candB", 0x2280b3c), ("candC", 0x2315b68)] {
            let gate: &'static mut CaptureGate =
                Box::leak(Box::new(CaptureGate { name, fired: AtomicBool::new(false) }));
            let addr = unsafe { base.add(off) };
            match interceptor.attach(NativePointer(addr as *mut c_void), gate) {
                Ok(_) => eprintln!("[fpui-cap] gate attached {name} @ {addr:p}"),
                Err(e) => eprintln!("[fpui-cap] gate attach failed {name}: {e:?}"),
            }
        }
    }
    // M2 path B trace: FPUI_TRACE=<hex file offset> attaches an arg-dump gate at base+offset, so
    // the Style-build / window.request_layout chain can be walked by relaunch alone (no rebuild).
    if let Ok(v) = std::env::var("FPUI_TRACE") {
        for tok in v.split(',') {
            if let Ok(off) = usize::from_str_radix(tok.trim().trim_start_matches("0x"), 16) {
                let name: &'static str = Box::leak(format!("TRACE@{off:#x}").into_boxed_str());
                let gate: &'static mut CaptureGate =
                    Box::leak(Box::new(CaptureGate { name, fired: AtomicBool::new(false) }));
                let addr = unsafe { base.add(off) };
                match interceptor.attach(NativePointer(addr as *mut c_void), gate) {
                    Ok(_) => eprintln!("[fpui-cap] trace gate @ {addr:p} (off {off:#x})"),
                    Err(e) => eprintln!("[fpui-cap] trace gate failed {off:#x}: {e:?}"),
                }
            }
        }
    }
    // Hook and Gum must outlive every call into the dylib.
    Box::leak(Box::new((gum, interceptor)));
    eprintln!("paint-spike: armed entry={entry:p} mode={} rect={rect:?}", STATE.get().unwrap().mode);
    Ok(())
}

// ---- Capstone: append a real `fpui` category to Zed's data-driven settings ----------
// Detour settings_data() (which returns a runtime Vec<SettingsPage>) and append one more
// SettingsPage before Zed consumes it, so Zed itself lays out + routes a new category.
// Ported faithfully from fpui-settings-inject (proven live). Step 1 appends an EMPTY page;
// the sub-rows (woah/debug SubPageLinks) land in the next step.
mod settings_category {
    use super::*;

    const SETTINGS_DATA_OFF: usize = 0x4ef76dc;
    // First 16 prologue bytes — refuse to attach if the pinned build drifted.
    const SIG: [u8; 16] = [
        0xe1, 0x03, 0x1e, 0xaa, 0xee, 0x8c, 0x01, 0x94, 0xfe, 0x03, 0x01, 0xaa, 0xfd, 0x7b, 0x05,
        0xa9,
    ];
    const EXPECTED_PAGES: u64 = 15; // settings_data builds 15 pages; Developer last
    const PAGE_SIZE: u64 = 32; // SettingsPage = &'static str(16) + Box<[_]>(16)

    static FPUI_NAME: [u8; 4] = *b"fpui"; // 'static bytes in this dylib -> &'static str stays valid
    // Sub-row titles ('static bytes here; handed to Zed as Borrowed SharedStrings).
    static WOAH: [u8; 4] = *b"woah";
    static DEBUG_: [u8; 5] = *b"debug";
    const ITEM_SIZE: u64 = 104; // sizeof(SettingsPageItem), from re/LAYOUT.md
    const SUBPAGELINK_DISC: u64 = 2;
    thread_local! { static SRET: Cell<u64> = const { Cell::new(0) }; }

    // Resolved render fn ptr grabbed from a live SubPageLink (for our sub-rows + the gate).
    pub static RENDER_FN: AtomicUsize = AtomicUsize::new(0);
    // ms of the last time a settings sub-page's render fn fired (the card gate reads this).
    pub static LAST_RENDER_MS: AtomicU64 = AtomicU64::new(0);
    // Resolved main-image base (for the debug panel's real-state readout).
    pub static DEBUG_BASE: AtomicU64 = AtomicU64::new(0);
    static GATE_DONE: AtomicBool = AtomicBool::new(false);
    // Per-sub-page gate: ms when the woah / debug sub-page content last rendered. The card
    // paints only when one is fresh, so it shows ONLY on my fpui sub-pages (never the editor,
    // the category page, or a foreign borrowed sub-page) AND woah->card, debug->panel.
    pub static WOAH_MS: AtomicU64 = AtomicU64::new(0);
    pub static DEBUG_MS: AtomicU64 = AtomicU64::new(0);
    // My fpui page items buffer ptr, excluded when probing a live SettingsWindow for the
    // active sub-page (so the probe can't false-match my own page's "woah"/"debug" bytes).
    pub static FPUI_ITEMS_PTR: AtomicU64 = AtomicU64::new(0);
    // Cached offset of the sub_page_stack data ptr inside SettingsWindow (0 = not yet found).
    static SUBPAGE_PTR_OFF: AtomicUsize = AtomicUsize::new(0);
    // Last sub-page title logged, so the gate prints once per transition (not every frame).
    static LAST_SUBPAGE: AtomicU32 = AtomicU32::new(0);

    // Detour on the shared SubPageLink render fn. woah + debug share this fn, so to route
    // card-vs-panel we read the ACTIVE sub-page's title off the live &SettingsWindow (x0) and
    // stamp the matching clock. A foreign borrowed sub-page (same fn, different title) stamps
    // neither -> no card. This is the page gate: the card lives only on my fpui sub-pages.
    // Path-3: render->layout->paint is synchronous on the main thread, so on_enter can hand the
    // decision + the sret buffer (x8 at entry, before it's clobbered) to on_leave via thread-locals.
    thread_local! {
        static PENDING_NATIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static SRET_BUF: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    struct RenderGate;
    impl InvocationListener for RenderGate {
        fn on_enter(&mut self, c: InvocationContext) {
            let now = super::now_ms();
            LAST_RENDER_MS.store(now, Ordering::Relaxed);
            let ctx = c.cpu_context();
            let sw = ctx.reg(0); // x0 = &SettingsWindow
            let t = unsafe { active_subpage_title(sw) };
            match t {
                1 => WOAH_MS.store(now, Ordering::Relaxed),
                2 => DEBUG_MS.store(now, Ordering::Relaxed),
                _ => {}
            }
            // Native element injects on the woah sub-page only. Stash x8 (the AnyElement sret
            // buffer) now — it is clobbered by the time on_leave fires.
            let inject = t == 1 && super::native_element::active();
            PENDING_NATIVE.with(|p| p.set(inject));
            if inject {
                SRET_BUF.with(|s| s.set(ctx.reg(8) as usize));
            }
            // Log once per transition so "woah render fired" is an explicit, unspammed signal.
            if LAST_SUBPAGE.swap(t as u32, Ordering::Relaxed) != t as u32 {
                let name = match t { 1 => "woah -> Support card", 2 => "debug -> state panel", _ => "other/none" };
                eprintln!("[fpui-gate] sub-page render fired: {name} (sw={sw:#x})");
            }
        }
        fn on_leave(&mut self, _c: InvocationContext) {
            if PENDING_NATIVE.with(|p| p.replace(false)) {
                let sret = SRET_BUF.with(|s| s.get());
                if sret != 0 {
                    unsafe { super::native_element::inject(sret as *mut u8) };
                    eprintln!("[fpui-native] injected AnyElement at sret={sret:#x}");
                }
            }
        }
    }

    // Read the active sub-page title from a live &SettingsWindow: 0 = none/foreign, 1 = woah,
    // 2 = debug. sub_page_stack is a Vec<SubPage> field; when a sub-page is open its data ptr
    // targets a SubPage whose cloned SubPageLink carries the title as a 24B inline SharedString
    // ([len][utf8]). We locate that ptr by scanning the struct's words for one whose target
    // holds our exact [4]"woah"/[5]"debug" byte pattern (self-verifying), then cache its offset.
    // Pure bounded reads; any miss just returns 0 (no card) rather than faulting the host.
    unsafe fn active_subpage_title(sw: u64) -> u8 {
        if sw <= 0x1_0000 || (sw & 7) != 0 {
            return 0;
        }
        let fpui_items = FPUI_ITEMS_PTR.load(Ordering::Relaxed);
        let cached = SUBPAGE_PTR_OFF.load(Ordering::Relaxed);
        if cached != 0 {
            let w = *((sw + cached as u64) as *const u64);
            if let Some(t) = title_at(w, fpui_items) {
                return t;
            }
        }
        // Bound the struct-word scan to a length we've proven mapped: SettingsWindow is heap
        // boxed to exactly its size, so reading a fixed 0x400 could walk off the allocation.
        let scan = [0x400u64, 0x200, 0x100].into_iter().find(|&n| readable(sw, n as usize));
        let Some(scan) = scan else { return 0 };
        let mut off = 0u64;
        while off < scan {
            let w = *((sw + off) as *const u64);
            // Only deref plausible heap/image pointers; small ints (lens, bools) are skipped.
            if w > 0x1_0000_0000 && (w & 7) == 0 {
                if let Some(t) = title_at(w, fpui_items) {
                    SUBPAGE_PTR_OFF.store(off as usize, Ordering::Relaxed);
                    return t;
                }
            }
            off += 8;
        }
        0
    }

    // If `ptr` targets a SubPage carrying an inline "woah"/"debug" title in its first ~130B
    // (the title sits inside the 104B SubPageLink, wherever rustc placed link in SubPage),
    // return 1/2. The candidate ptr comes from scanning struct words, so it MUST be proven
    // mapped before any load: SettingsWindow embeds HashMap/HashSet RandomState seeds (random
    // u64s) that pass the ptr-shape filter but point nowhere. `readable` gates every load.
    unsafe fn title_at(ptr: u64, fpui_items: u64) -> Option<u8> {
        if ptr <= 0x1_0000_0000 || (ptr & 7) != 0 || ptr == fpui_items || !readable(ptr, 136) {
            return None;
        }
        let base = ptr as *const u8;
        for i in 0..128usize {
            match *base.add(i) {
                4 if bytes_eq(base.add(i + 1), b"woah") => return Some(1),
                5 if bytes_eq(base.add(i + 1), b"debug") => return Some(2),
                _ => {}
            }
        }
        None
    }

    unsafe fn bytes_eq(p: *const u8, s: &[u8]) -> bool {
        s.iter().enumerate().all(|(k, &b)| *p.add(k) == b)
    }

    // Non-faulting readability test: write() copies from the user buffer into a pipe and
    // returns EFAULT (n < 0) instead of raising SIGSEGV when the range is unmapped. We drain
    // what we wrote so the (non-blocking) pipe can never fill. Lets the probe deref arbitrary
    // struct words without crashing the host on a bad pointer.
    static PROBE_PIPE: OnceLock<(i32, i32)> = OnceLock::new();
    unsafe fn readable(ptr: u64, len: usize) -> bool {
        let (rd, wr) = *PROBE_PIPE.get_or_init(|| {
            let mut fds = [0i32; 2];
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                return (-1, -1);
            }
            libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
            libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK);
            (fds[0], fds[1])
        });
        if wr < 0 {
            return false;
        }
        let n = libc::write(wr, ptr as *const c_void, len);
        if n > 0 {
            // Drain everything we wrote (len can be up to 0x400) so the pipe never fills and
            // starts returning EAGAIN, which would turn into false "unreadable" verdicts.
            let mut buf = [0u8; 1024];
            while libc::read(rd, buf.as_mut_ptr() as *mut c_void, buf.len()) > 0 {}
            n as usize == len
        } else {
            false
        }
    }

    fn attach_render_gate(render: u64) {
        if GATE_DONE.swap(true, Ordering::Relaxed) {
            return;
        }
        // Attach from a fresh thread so we don't re-enter the interceptor from within on_leave.
        std::thread::spawn(move || unsafe {
            let gum = Gum::obtain();
            let mut interceptor = Interceptor::obtain(&gum);
            let listener: &'static mut RenderGate = Box::leak(Box::new(RenderGate));
            match interceptor.attach(NativePointer(render as *mut c_void), listener) {
                Ok(_) => eprintln!("[fpui-cat] card gate attached on render fn {render:#x}"),
                Err(e) => eprintln!("[fpui-cat] card gate attach failed: {e:?}"),
            }
            Box::leak(Box::new((gum, interceptor)));
        });
    }

    struct Listener {
        img_lo: u64,
        img_hi: u64,
    }

    impl InvocationListener for Listener {
        fn on_enter(&mut self, context: InvocationContext) {
            SRET.with(|s| s.set(context.cpu_context().reg(8))); // x8 = sret (Vec slot)
        }
        fn on_leave(&mut self, context: InvocationContext) {
            let x8 = SRET.with(|s| s.replace(0));
            let x0 = context.cpu_context().reg(0);
            unsafe { append(x0, x8, self.img_lo, self.img_hi) };
        }
    }

    fn ptr_like(w: u64) -> bool {
        w > 0x1_0000 && (w & 7) == 0
    }

    // {ptr,cap,len} in rustc's order: one ptr_like word + two == EXPECTED_PAGES.
    unsafe fn vec_pattern(base: u64) -> Option<(usize, u64)> {
        if base == 0 || (base & 7) != 0 {
            return None;
        }
        let w = [
            *(base as *const u64),
            *((base + 8) as *const u64),
            *((base + 16) as *const u64),
        ];
        let counts = w.iter().filter(|&&x| x == EXPECTED_PAGES).count();
        let ptrs: Vec<usize> = (0..3).filter(|&i| ptr_like(w[i])).collect();
        if counts == 2 && ptrs.len() == 1 {
            Some((ptrs[0], w[ptrs[0]]))
        } else {
            None
        }
    }

    // Grow the returned Vec<SettingsPage> by one and write the `fpui` page (empty items).
    unsafe fn append(x0: u64, x8: u64, img_lo: u64, img_hi: u64) {
        let Some((base, ptr_idx, ptr)) = vec_pattern(x0)
            .map(|(i, p)| (x0, i, p))
            .or_else(|| vec_pattern(x8).map(|(i, p)| (x8, i, p)))
        else {
            eprintln!("[fpui-cat] skip: no Vec{{ptr,15,15}} at x0={x0:#x} x8={x8:#x}");
            return;
        };
        let slot = base as *mut u64;
        let n = EXPECTED_PAGES;
        // Zed uses the System allocator, so a libc::realloc'd buffer is freed correctly by
        // Zed's own Vec drop later.
        let newptr = libc::realloc(ptr as *mut c_void, ((n + 1) * PAGE_SIZE) as usize) as u64;
        if newptr == 0 {
            eprintln!("[fpui-cat] realloc failed");
            return;
        }
        // SettingsPage{title:&str, items:Box} field order is rustc's choice: the &str half's
        // data ptr points INTO the image; the Box half's into the malloc heap.
        let a = *(newptr as *const u64);
        let b = *((newptr + 16) as *const u64);
        let (a_in, b_in) = (a >= img_lo && a < img_hi, b >= img_lo && b < img_hi);
        let title_off: u64 = if a_in && !b_in {
            0
        } else if b_in && !a_in {
            16
        } else {
            *slot = newptr; // keep a valid 15-page Vec; never corrupt the list
            eprintln!("[fpui-cat] field-order ambiguous (a_in={a_in} b_in={b_in}); not appending");
            return;
        };
        let items_off = 16 - title_off;
        let pg = newptr + n * PAGE_SIZE;
        *((pg + title_off) as *mut u64) = FPUI_NAME.as_ptr() as u64;
        *((pg + title_off + 8) as *mut u64) = FPUI_NAME.len() as u64;
        // Build the woah/debug SubPageLink sub-rows (empty fallback if no render fn found).
        let (items_ptr, items_len) = build_fpui_items(newptr, items_off, img_lo, img_hi);
        *((pg + items_off) as *mut u64) = items_ptr;
        *((pg + items_off + 8) as *mut u64) = items_len;
        *slot.add(ptr_idx) = newptr;
        for i in 0..3 {
            if i != ptr_idx {
                *slot.add(i) = n + 1;
            }
        }
        eprintln!("[fpui-cat] APPENDED fpui category: base={base:#x} ptr_word={ptr_idx} pages {n}->{}", n + 1);
    }

    // Grab a valid render fn ptr from any live SubPageLink among the 15 pages (reused for our
    // sub-rows; we detour it for the gate). Items are a 104B-stride [SettingsPageItem].
    unsafe fn find_render_fn(pages: u64, items_off: u64, img_lo: u64, img_hi: u64) -> Option<u64> {
        let _ = img_hi;
        for i in 0..EXPECTED_PAGES {
            let page = pages + i * PAGE_SIZE;
            let iptr = *((page + items_off) as *const u64);
            let ilen = *((page + items_off + 8) as *const u64);
            if iptr < 0x1_0000 || (iptr & 7) != 0 || ilen == 0 || ilen > 4096 {
                continue;
            }
            for j in 0..ilen {
                let item = iptr + j * ITEM_SIZE;
                if *(item as *const u64) == SUBPAGELINK_DISC {
                    let render = *((item + 40) as *const u64); // render @ item+40 (reversed)
                    if render >= img_lo && render < img_lo + 0x6e8_9000 {
                        return Some(render); // a real fn in __text
                    }
                }
            }
        }
        None
    }

    // Write SettingsPageItem::SubPageLink(SubPageLink{title, render, ..}) at `item` (104B).
    // Real reversed layout (re/LAYOUT.md): SharedString is a 24B inline small-string
    // ([len u8][chars]). Drop-safe: inline title, None json_path, empty aliases, empty desc.
    unsafe fn write_sub_page_item(item: *mut u8, title: &[u8], render: u64) {
        std::ptr::write_bytes(item, 0, ITEM_SIZE as usize);
        *(item.add(0) as *mut u64) = SUBPAGELINK_DISC; // enum discriminant = SubPageLink
        // json_path: Option<&str>::None @8 = (0,0) [zeroed]
        *(item.add(24) as *mut u64) = 8; // search_aliases: &[] dangling ptr; len @32 = 0
        *(item.add(40) as *mut u64) = render; // render fn @40
        // description: Option<SharedString> @48 = inline len-0 ("" / None) [zeroed]
        *item.add(72) = title.len() as u8; // title SharedString inline: len byte @72
        std::ptr::copy_nonoverlapping(title.as_ptr(), item.add(73), title.len()); // chars @73..
        *item.add(96) = 1; // files = FileMask::USER
        *item.add(97) = 2; // r#type = SubPageType::Other
        *item.add(98) = 0; // in_json = false
    }

    // Write a SettingsPageItem::SectionHeader(&'static str) at `item`. These (not SubPageLinks)
    // are what build_navbar turns into sidebar child entries. &str is a plain {ptr, len}.
    unsafe fn write_section_header(item: *mut u8, title: &[u8]) {
        std::ptr::write_bytes(item, 0, ITEM_SIZE as usize);
        *(item.add(0) as *mut u64) = 0; // discriminant = SectionHeader
        *(item.add(8) as *mut u64) = title.as_ptr() as u64; // &str ptr
        *(item.add(16) as *mut u64) = title.len() as u64; // &str len
    }

    // Build fpui page items: per sub-row a SectionHeader (-> sidebar entry) then a SubPageLink
    // (-> routed content sub-page). Falls back to section headers alone if no render fn.
    unsafe fn build_fpui_items(pages: u64, items_off: u64, img_lo: u64, img_hi: u64) -> (u64, u64) {
        let render = find_render_fn(pages, items_off, img_lo, img_hi);
        if let Some(r) = render {
            RENDER_FN.store(r as usize, Ordering::Release);
            attach_render_gate(r); // card only paints while a sub-page using this fn is live
        }
        let rows: [&[u8]; 2] = [&WOAH, &DEBUG_];
        let per = if render.is_some() { 2 } else { 1 };
        let n = (rows.len() * per) as u64;
        let buf = libc::malloc((n * ITEM_SIZE) as usize) as *mut u8;
        if buf.is_null() {
            return (8, 0);
        }
        FPUI_ITEMS_PTR.store(buf as u64, Ordering::Release);
        let mut idx = 0usize;
        for title in rows {
            write_section_header(buf.add(idx * ITEM_SIZE as usize), title);
            idx += 1;
            if let Some(r) = render {
                write_sub_page_item(buf.add(idx * ITEM_SIZE as usize), title, r);
                idx += 1;
            }
        }
        eprintln!("[fpui-cat] fpui items built: {n} (section headers + sub-pages), render={render:x?}");
        (buf as u64, n)
    }

    // [base, max segment end) of the main image (to tell an in-image &str ptr from a heap ptr).
    unsafe fn image_bounds(base: u64) -> (u64, u64) {
        let ncmds = *((base + 16) as *const u32);
        let slide = base.wrapping_sub(0x1_0000_0000);
        let mut off = base + 32;
        let mut hi = base;
        for _ in 0..ncmds {
            let cmd = *(off as *const u32);
            let sz = *((off + 4) as *const u32) as u64;
            if cmd == 0x19 {
                let vmaddr = *((off + 24) as *const u64);
                let vmsize = *((off + 32) as *const u64);
                if vmaddr != 0 {
                    let end = vmaddr.wrapping_add(slide).wrapping_add(vmsize);
                    if end > hi {
                        hi = end;
                    }
                }
            }
            off += sz;
        }
        (base, hi)
    }

    pub fn attach(base: *const u8, interceptor: &mut Interceptor) {
        unsafe {
            let addr = base.add(SETTINGS_DATA_OFF);
            if std::slice::from_raw_parts(addr, SIG.len()) != SIG {
                eprintln!("[fpui-cat] settings_data signature mismatch; category off");
                return;
            }
            let (img_lo, img_hi) = image_bounds(base as u64);
            let listener: &'static mut Listener = Box::leak(Box::new(Listener { img_lo, img_hi }));
            match interceptor.attach(NativePointer(addr as *mut c_void), listener) {
                Ok(_) => eprintln!("[fpui-cat] attached settings_data @ {addr:p} image [{img_lo:#x},{img_hi:#x})"),
                Err(e) => eprintln!("[fpui-cat] attach failed: {e:?}"),
            }
        }
    }
}

#[ctor::ctor]
fn init() {
    match std::panic::catch_unwind(install) {
        Ok(Ok(())) => {},
        Ok(Err(error)) => eprintln!("paint-spike: {error}"),
        Err(_) => eprintln!("paint-spike: init panic"),
    }
}
