use super::hints::{
    apply_instance_hints, observe_path_namespace_hint, observed_instance_namespace_hints,
    observed_path_namespace_hints, resolve_namespace_id_by_instance, resolve_namespace_id_by_path,
};
use super::maps::{parse_maps_instance_id, parse_maps_line};
use super::noload::noload_path_candidates;
use super::resolve::resolve_namespace_id_from_link_map;
use super::{LinkMap, ObservedIdentityHint, merge_module_identity};
use crate::runtime::state::ModuleInfo;
use std::collections::BTreeMap;
use std::ptr;

#[test]
fn parse_maps_so_ok() {
    let line = "7f68e00000-7f68e1f000 r--p 00000000 103:06 12345 /system/lib64/libc.so";
    let module = parse_maps_line(line).expect("module should parse");
    assert_eq!(module.pathname, "/system/lib64/libc.so");
    assert_eq!(module.base_addr, 0x7f68e00000);
    assert_ne!(module.instance_id, 0);
}

#[test]
fn parse_maps_skip_nonzero_offset() {
    let line = "7f68e1f000-7f68e3f000 r-xp 0001f000 103:06 12345 /system/lib64/libc.so";
    assert!(parse_maps_line(line).is_none());
}

#[test]
fn parse_maps_linker_ok() {
    let line =
        "7f64000000-7f64030000 r-xp 00000000 103:06 67890 /apex/com.android.runtime/bin/linker64";
    let module = parse_maps_line(line).expect("linker should parse");
    assert_eq!(module.pathname, "/apex/com.android.runtime/bin/linker64");
    assert_ne!(module.instance_id, 0);
}

#[test]
fn parse_maps_instance_id_invalid_input() {
    assert!(parse_maps_instance_id("invalid", "1").is_none());
    assert!(parse_maps_instance_id("1:2", "x").is_none());
}

#[test]
fn apply_instance_hints_only_for_maps_modules() {
    observed_instance_namespace_hints().lock().unwrap().clear();
    let mut modules = vec![
        (
            ModuleInfo {
                pathname: "/system/lib64/liba.so".to_string(),
                base_addr: 0x1000,
                instance_id: 0xaaaa,
                namespace_id: 0x1010,
            },
            true,
        ),
        (
            ModuleInfo {
                pathname: "/system/lib64/libb.so".to_string(),
                base_addr: 0x2000,
                instance_id: 0xbbbb,
                namespace_id: 0,
            },
            false,
        ),
    ];

    let mut hints = BTreeMap::new();
    hints.insert(
        0x1000,
        ObservedIdentityHint {
            instance_id: 0x1111,
            namespace_id: 0x1112,
        },
    );
    hints.insert(
        0x2000,
        ObservedIdentityHint {
            instance_id: 0x2222,
            namespace_id: 0x2223,
        },
    );
    hints.insert(
        0x3000,
        ObservedIdentityHint {
            instance_id: 0x3333,
            namespace_id: 0x3334,
        },
    );
    apply_instance_hints(&mut modules, &mut hints);

    assert_eq!(modules[0].0.instance_id, 0xaaaa);
    assert_eq!(modules[0].0.namespace_id, 0x1010);
    assert_eq!(modules[1].0.instance_id, 0x2222);
    assert_eq!(modules[1].0.namespace_id, 0x2223);
    assert_eq!(hints.len(), 2);
    assert!(hints.contains_key(&0x1000));
    assert!(hints.contains_key(&0x2000));
    observed_instance_namespace_hints().lock().unwrap().clear();
}

#[test]
fn resolve_namespace_id_by_instance_hint() {
    let mut hints = observed_instance_namespace_hints().lock().unwrap();
    hints.clear();
    hints.insert(0x1234, 0x8888);
    drop(hints);

    assert_eq!(resolve_namespace_id_by_instance(0x1234), Some(0x8888));
    assert_eq!(resolve_namespace_id_by_instance(0x5678), None);
    observed_instance_namespace_hints().lock().unwrap().clear();
}

#[test]
fn namespace_id_from_link_map_head() {
    let mut head = LinkMap {
        l_addr: 0,
        l_name: ptr::null(),
        l_ld: ptr::null_mut(),
        l_next: ptr::null_mut(),
        l_prev: ptr::null_mut(),
    };
    let mut middle = LinkMap {
        l_addr: 0,
        l_name: ptr::null(),
        l_ld: ptr::null_mut(),
        l_next: ptr::null_mut(),
        l_prev: ptr::null_mut(),
    };
    let mut tail = LinkMap {
        l_addr: 0,
        l_name: ptr::null(),
        l_ld: ptr::null_mut(),
        l_next: ptr::null_mut(),
        l_prev: ptr::null_mut(),
    };

    head.l_next = ptr::addr_of_mut!(middle);
    middle.l_prev = ptr::addr_of_mut!(head);
    middle.l_next = ptr::addr_of_mut!(tail);
    tail.l_prev = ptr::addr_of_mut!(middle);

    let namespace = resolve_namespace_id_from_link_map(ptr::addr_of_mut!(tail))
        .expect("namespace should resolve");
    assert_eq!(namespace, ptr::addr_of!(head) as usize);
}

#[test]
fn namespace_id_from_link_map_cycle_returns_none() {
    let mut node = LinkMap {
        l_addr: 0,
        l_name: ptr::null(),
        l_ld: ptr::null_mut(),
        l_next: ptr::null_mut(),
        l_prev: ptr::null_mut(),
    };
    node.l_prev = ptr::addr_of_mut!(node);
    assert!(resolve_namespace_id_from_link_map(ptr::addr_of_mut!(node)).is_none());
}

#[test]
fn noload_candidates_include_deleted_and_basename_variants() {
    let candidates = noload_path_candidates("/system/lib64/libfoo.so (deleted)");
    let candidate_text: Vec<_> = candidates
        .iter()
        .map(|value| value.to_string_lossy().to_string())
        .collect();
    assert!(candidate_text.contains(&"/system/lib64/libfoo.so (deleted)".to_string()));
    assert!(candidate_text.contains(&"/system/lib64/libfoo.so".to_string()));
    assert!(candidate_text.contains(&"libfoo.so (deleted)".to_string()));
    assert!(candidate_text.contains(&"libfoo.so".to_string()));
}

#[test]
fn resolve_namespace_by_path_hint_prefers_exact_then_basename() {
    observed_path_namespace_hints().lock().unwrap().clear();
    observe_path_namespace_hint("/system/lib64/libfoo.so", 0x1010);
    observe_path_namespace_hint("/vendor/lib64/libfoo.so", 0x2020);

    assert_eq!(
        resolve_namespace_id_by_path("/system/lib64/libfoo.so"),
        Some(0x1010)
    );
    assert_eq!(
        resolve_namespace_id_by_path("/vendor/lib64/libfoo.so"),
        Some(0x2020)
    );
    assert_eq!(resolve_namespace_id_by_path("libfoo.so"), None);
    observed_path_namespace_hints().lock().unwrap().clear();
}

#[test]
fn resolve_namespace_by_path_ignores_ambiguous_basename() {
    observed_path_namespace_hints().lock().unwrap().clear();
    observe_path_namespace_hint("/system/lib64/libbar.so", 0x1111);
    observe_path_namespace_hint("/vendor/lib64/libbar.so", 0x2222);

    assert_eq!(resolve_namespace_id_by_path("libbar.so"), None);
    assert_eq!(
        resolve_namespace_id_by_path("/system/lib64/libbar.so"),
        Some(0x1111)
    );
    observed_path_namespace_hints().lock().unwrap().clear();
}

#[test]
fn merge_identity_prefers_non_zero_namespace_from_fallback() {
    let primary = ModuleInfo {
        pathname: "/system/lib64/libfoo.so".to_string(),
        base_addr: 0x1000,
        instance_id: 0x10,
        namespace_id: 0,
    };
    let fallback = ModuleInfo {
        pathname: "/system/lib64/libfoo.so".to_string(),
        base_addr: 0x1000,
        instance_id: 0x10,
        namespace_id: 0x88,
    };

    let merged = merge_module_identity(Some(primary), Some(fallback)).expect("merged identity");
    assert_eq!(merged.namespace_id, 0x88);
}

#[test]
fn merge_identity_keeps_primary_for_mismatched_module() {
    let primary = ModuleInfo {
        pathname: "/system/lib64/libfoo.so".to_string(),
        base_addr: 0x1000,
        instance_id: 0x10,
        namespace_id: 0x20,
    };
    let fallback = ModuleInfo {
        pathname: "/system/lib64/libbar.so".to_string(),
        base_addr: 0x2000,
        instance_id: 0x30,
        namespace_id: 0x40,
    };

    let merged =
        merge_module_identity(Some(primary.clone()), Some(fallback)).expect("merged identity");
    assert_eq!(merged.pathname, primary.pathname);
    assert_eq!(merged.base_addr, primary.base_addr);
    assert_eq!(merged.instance_id, primary.instance_id);
    assert_eq!(merged.namespace_id, primary.namespace_id);
}
