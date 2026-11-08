// Value-type layout probe for the native-card styling layer. These gpui types are small +
// version-stable (plain f32 structs, simple fieldless/f32 enums), so compiling faithful replicas
// with the pinned rustc reproduces Zed's layout reliably (unlike big reordered structs like
// StyleRefinement, whose field offsets must still come from the live binary / a lldb loop).
// Replicas mirror gpui 0.2.2 color.rs / geometry.rs / style.rs exactly.
#![allow(dead_code)]
use std::mem::{align_of, offset_of, size_of};

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Pixels(f32);
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Rems(f32);

#[derive(Clone, Copy, Debug, PartialEq)]
struct Hsla { h: f32, s: f32, l: f32, a: f32 }

// style.rs: Display/FlexDirection/Position are fieldless (taffy) enums.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum Display { Block, #[default] Flex, Grid, None }
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum FlexDirection { #[default] Row, Column, RowReverse, ColumnReverse }
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum Position { #[default] Relative, Absolute }

// geometry.rs length ladder.
#[derive(Clone, Copy, Debug, PartialEq)]
enum AbsoluteLength { Pixels(Pixels), Rems(Rems) }
#[derive(Clone, Copy, Debug, PartialEq)]
enum DefiniteLength { Absolute(AbsoluteLength), Fraction(f32) }
#[derive(Clone, Copy, Debug, PartialEq)]
enum Length { Definite(DefiniteLength), Auto }

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Edges<T> { top: T, right: T, bottom: T, left: T }
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Corners<T> { top_left: T, top_right: T, bottom_right: T, bottom_left: T }
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Size<T> { width: T, height: T }

// style.rs: Fill::Color(Background). Background is bigger than Hsla (solid|gradient) — reverse it
// from the binary; here we only size the solid-Hsla lower bound + Option<Hsla> (border_color).
fn p<T>(name: &str) { println!("{name:<26} size={:>3} align={}", size_of::<T>(), align_of::<T>()); }

fn main() {
    println!("== scalars / colors ==");
    p::<Pixels>("Pixels"); p::<Rems>("Rems"); p::<Hsla>("Hsla");
    println!("Hsla offsets h={} s={} l={} a={}",
        offset_of!(Hsla, h), offset_of!(Hsla, s), offset_of!(Hsla, l), offset_of!(Hsla, a));
    p::<Option<Hsla>>("Option<Hsla>");           // border_color field type

    println!("== enums ==");
    p::<Display>("Display"); p::<FlexDirection>("FlexDirection"); p::<Position>("Position");
    p::<AbsoluteLength>("AbsoluteLength"); p::<DefiniteLength>("DefiniteLength"); p::<Length>("Length");
    p::<Option<Display>>("Option<Display>"); p::<Option<FlexDirection>>("Option<FlexDirection>");

    println!("== composites (card needs these) ==");
    p::<Edges<DefiniteLength>>("Edges<DefiniteLength>");   // padding
    p::<Edges<AbsoluteLength>>("Edges<AbsoluteLength>");   // border_widths
    p::<Edges<Length>>("Edges<Length>");                  // margin / inset
    p::<Corners<AbsoluteLength>>("Corners<AbsoluteLen>");  // corner_radii
    p::<Size<DefiniteLength>>("Size<DefiniteLength>");     // gap
    p::<Size<Length>>("Size<Length>");                    // size / min / max

    // Discriminant probes: where does the payload sit, and what tag values Zed will read.
    let al = AbsoluteLength::Rems(Rems(1.0));
    let raw = unsafe { std::slice::from_raw_parts(&al as *const _ as *const u8, size_of::<AbsoluteLength>()) };
    println!("AbsoluteLength::Rems(1.0) bytes = {raw:02x?}  (tag + payload layout)");
    let dl = DefiniteLength::Fraction(0.5);
    let raw2 = unsafe { std::slice::from_raw_parts(&dl as *const _ as *const u8, size_of::<DefiniteLength>()) };
    println!("DefiniteLength::Fraction(0.5) bytes = {raw2:02x?}");
    let len = Length::Auto;
    let raw3 = unsafe { std::slice::from_raw_parts(&len as *const _ as *const u8, size_of::<Length>()) };
    println!("Length::Auto bytes = {raw3:02x?}");
}
