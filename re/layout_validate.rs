// Validate the rustc-1.92 layout probe against the KNOWN binary offsets of SubPageLink
// (reversed live: json_path@0, search_aliases@16, render@32, description@40, title@64,
// files@88, type@89, in_json@90). If these reproduce, the probe method is trustworthy for
// the StyleRefinement/Interactivity reversal; if not, rustc versions differ and I must capture.
#![allow(dead_code)]
use std::mem::offset_of;
use std::ptr::NonNull;

// SharedString: 24B inline small-string with a niche (so Option<SharedString> stays 24B).
struct SharedString { a: NonNull<u8>, b: usize, c: usize }
enum SubPageType { Language, SkillCreator, Other }   // fieldless -> u8
struct FileMask(u8);
type RenderFn = fn();                                 // 8B fn ptr

struct SubPageLink {
    title: SharedString,
    r#type: SubPageType,
    description: Option<SharedString>,
    search_aliases: &'static [&'static str],
    json_path: Option<&'static str>,
    in_json: bool,
    files: FileMask,
    render: RenderFn,
}

fn main() {
    println!("size={} align={}", std::mem::size_of::<SubPageLink>(), std::mem::align_of::<SubPageLink>());
    println!("json_path   @{}  (expect 0)",  offset_of!(SubPageLink, json_path));
    println!("search_alias@{}  (expect 16)", offset_of!(SubPageLink, search_aliases));
    println!("render      @{}  (expect 32)", offset_of!(SubPageLink, render));
    println!("description @{}  (expect 40)", offset_of!(SubPageLink, description));
    println!("title       @{}  (expect 64)", offset_of!(SubPageLink, title));
    println!("files       @{}  (expect 88)", offset_of!(SubPageLink, files));
    println!("type        @{}  (expect 89)", offset_of!(SubPageLink, r#type));
    println!("in_json     @{}  (expect 90)", offset_of!(SubPageLink, in_json));
    println!("Option<SharedString> size = {} (expect 24)", std::mem::size_of::<Option<SharedString>>());
}
