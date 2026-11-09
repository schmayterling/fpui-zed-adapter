use std::mem::{offset_of, size_of, align_of};
#[derive(Clone,Copy)] struct Pixels(f32);
#[derive(Clone,Copy)] struct Point { x: Pixels, y: Pixels }
#[derive(Clone,Copy)] struct Size { w: Pixels, h: Pixels }
#[derive(Clone,Copy)] struct Bounds { origin: Point, size: Size }
#[derive(Clone,Copy)] struct Corners { tl: Pixels, tr: Pixels, br: Pixels, bl: Pixels }
#[derive(Clone,Copy)] struct Edges { t: Pixels, r: Pixels, b: Pixels, l: Pixels }
#[derive(Clone,Copy)] #[repr(C)] struct Hsla { h: f32, s: f32, l: f32, a: f32 }
#[derive(Clone,Copy)] #[repr(C)] enum BorderStyle { Solid=0, Dashed=1 }
#[derive(Clone,Copy)] #[repr(C)] enum BackgroundTag { Solid=0, LinearGradient=1, PatternSlash=2, Checkerboard=3 }
#[derive(Clone,Copy)] #[repr(C)] enum ColorSpace { Srgb=0, Oklab=1 }
#[derive(Clone,Copy)] #[repr(C)] struct LinearColorStop { color: Hsla, percentage: f32 }
#[derive(Clone,Copy)] #[repr(C)] struct Background {
    tag: BackgroundTag, color_space: ColorSpace, solid: Hsla,
    gradient_angle_or_pattern_height: f32, colors: [LinearColorStop; 2], pad: u32,
}
struct PaintQuad { bounds: Bounds, corner_radii: Corners, background: Background,
    border_widths: Edges, border_color: Hsla, border_style: BorderStyle }
fn main() {
    println!("Background size={} (want 72)", size_of::<Background>());
    println!("PaintQuad size={} align={} (want 140, 4)", size_of::<PaintQuad>(), align_of::<PaintQuad>());
    for (n,o,e) in [("border_style",offset_of!(PaintQuad,border_style),0u32),
                    ("background",offset_of!(PaintQuad,background),4),
                    ("bounds",offset_of!(PaintQuad,bounds),76),
                    ("corner_radii",offset_of!(PaintQuad,corner_radii),92),
                    ("border_widths",offset_of!(PaintQuad,border_widths),108),
                    ("border_color",offset_of!(PaintQuad,border_color),124)] {
        println!("  {:<13}@{:<3} (want {}) {}", n, o, e, if o as u32==e {"OK"} else {"<<< MISMATCH"});
    }
}
