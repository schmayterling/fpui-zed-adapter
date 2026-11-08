// Layout probe: faithful replica of Zed settings_ui's SettingsPageItem + SubPageLink,
// using std types that match each real field's size/align/niche. rustc computes the same
// repr(Rust) layout as Zed, so this prints the exact offsets/discriminants we must write.
#![allow(dead_code)]
use std::mem::{align_of, offset_of, size_of};
use std::sync::Arc;

enum ArcCow {
    Borrowed(&'static str),
    Owned(Arc<str>),
}
struct SharedString(ArcCow);
enum SubPageType {
    Language,
    SkillCreator,
    Other,
}
struct FileMask(u8);

struct SubPageLink {
    title: SharedString,
    r#type: SubPageType,
    description: Option<SharedString>,
    search_aliases: &'static [&'static str],
    json_path: Option<&'static str>,
    in_json: bool,
    files: FileMask,
    render: fn(), // real: fn(&SettingsWindow,&ScrollHandle,&mut Window,&mut Context)->AnyElement (8B fn ptr)
}

struct SettingItem {
    title: &'static str,
    description: &'static str,
    field: Box<dyn std::fmt::Debug>,   // Box<dyn AnySettingField> (fat 16)
    metadata: Option<Box<u8>>,          // Option<Box<SettingsFieldMetadata>> (8, null niche)
    files: FileMask,
}
struct DynamicItem {
    discriminant: SettingItem,
    pick_discriminant: fn(),
    fields: Vec<u8>, // Vec<Vec<SettingItem>> (24)
}
struct ActionLink {
    title: SharedString,
    description: Option<SharedString>,
    button_text: SharedString,
    on_click: Arc<dyn std::fmt::Debug>, // Arc<dyn Fn...> (fat 16)
    files: FileMask,
}
enum SettingsPageItem {
    SectionHeader(&'static str),
    SettingItem(SettingItem),
    SubPageLink(SubPageLink),
    DynamicItem(DynamicItem),
    ActionLink(ActionLink),
}

fn dump<T>(name: &str, v: &T) {
    let n = size_of::<T>();
    let bytes = unsafe { std::slice::from_raw_parts(v as *const T as *const u8, n) };
    print!("{name} [{n}B]:");
    for (i, b) in bytes.iter().enumerate() {
        if i % 8 == 0 {
            print!(" ");
        }
        print!("{:02x}", b);
    }
    println!();
}
fn dummy() {}

fn main() {
    println!("== sizes ==");
    println!("ArcCow={} SharedString={} Option<SharedString>={} SubPageType={} Option<&str>={}",
        size_of::<ArcCow>(), size_of::<SharedString>(), size_of::<Option<SharedString>>(),
        size_of::<SubPageType>(), size_of::<Option<&str>>());
    println!("SubPageLink size={} align={}", size_of::<SubPageLink>(), align_of::<SubPageLink>());
    println!("SettingItem={} DynamicItem={} ActionLink={}", size_of::<SettingItem>(), size_of::<DynamicItem>(), size_of::<ActionLink>());
    println!("SettingsPageItem size={} align={}", size_of::<SettingsPageItem>(), align_of::<SettingsPageItem>());
    println!("== SubPageLink field offsets ==");
    println!("title@{} type@{} description@{} search_aliases@{} json_path@{} in_json@{} files@{} render@{}",
        offset_of!(SubPageLink, title), offset_of!(SubPageLink, r#type), offset_of!(SubPageLink, description),
        offset_of!(SubPageLink, search_aliases), offset_of!(SubPageLink, json_path),
        offset_of!(SubPageLink, in_json), offset_of!(SubPageLink, files), offset_of!(SubPageLink, render));
    println!("== byte dumps (addr of \"woah\"={:p}) ==", "woah".as_ptr());
    dump("ArcCow::Borrowed(woah)", &ArcCow::Borrowed("woah"));
    dump("SharedString(woah)", &SharedString(ArcCow::Borrowed("woah")));
    dump("Option<SharedString>::None", &Option::<SharedString>::None);
    dump("Option<&str>::None", &Option::<&str>::None);
    let link = SubPageLink {
        title: SharedString(ArcCow::Borrowed("woah")),
        r#type: SubPageType::Other,
        description: None,
        search_aliases: &[],
        json_path: None,
        in_json: true,
        files: FileMask(1),
        render: dummy as fn(),
    };
    println!("render fn ptr (dummy) = {:p}", dummy as fn() as *const ());
    dump("SubPageLink(woah)", &link);
    dump("Item::SubPageLink(woah)", &SettingsPageItem::SubPageLink(link));
    dump("Item::SectionHeader(woah)", &SettingsPageItem::SectionHeader("woah"));
}
