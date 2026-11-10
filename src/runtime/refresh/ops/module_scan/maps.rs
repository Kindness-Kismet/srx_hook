// /proc/self/maps 解析与缓存，提供基于文件映射的模块枚举
use std::collections::BTreeMap;
use std::fs;

use super::ModuleInfo;

fn enumerate_modules_maps() -> Vec<ModuleInfo> {
    let Ok(content) = fs::read_to_string("/proc/self/maps") else {
        return Vec::new();
    };
    let mut modules = Vec::new();
    for line in content.lines() {
        if let Some(module) = parse_maps_line(line) {
            modules.push(module);
        }
    }
    modules
}

// 每次采集 maps 都获取当前租期内的权限和地址记录。
pub(super) fn enumerate_modules_maps_cached() -> Vec<ModuleInfo> {
    enumerate_modules_maps()
}

// 解析单行 maps 记录，仅保留 offset=0 的可读 .so/linker 映射
pub(super) fn parse_maps_line(line: &str) -> Option<ModuleInfo> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let perms = fields.next()?;
    let offset = fields.next()?;
    let dev = fields.next()?;
    let inode = fields.next()?;
    let pathname = fields.next()?;

    if !pathname.starts_with('/') {
        return None;
    }
    if !is_probable_elf_path(pathname) {
        return None;
    }
    if !perms.starts_with('r') {
        return None;
    }

    let offset = usize::from_str_radix(offset, 16).ok()?;
    if offset != 0 {
        return None;
    }

    let (start, _) = range.split_once('-')?;
    let base_addr = usize::from_str_radix(start, 16).ok()?;
    let instance_id = parse_maps_instance_id(dev, inode).unwrap_or(0);
    Some(ModuleInfo {
        pathname: pathname.to_string(),
        base_addr,
        instance_id,
        namespace_id: 0,
    })
}

fn is_probable_elf_path(pathname: &str) -> bool {
    pathname.ends_with(".so") || pathname.ends_with("/linker") || pathname.ends_with("/linker64")
}

// 将 dev(major:minor) 和 inode 混合哈希为 instance_id，使用 murmur3 finalizer
pub(super) fn parse_maps_instance_id(dev: &str, inode: &str) -> Option<usize> {
    let (major, minor) = dev.split_once(':')?;
    let major = u64::from_str_radix(major, 16)
        .ok()
        .or_else(|| major.parse::<u64>().ok())?;
    let minor = u64::from_str_radix(minor, 16)
        .ok()
        .or_else(|| minor.parse::<u64>().ok())?;
    let inode = inode.parse::<u64>().ok()?;

    let mut mixed = inode
        .wrapping_add(major.wrapping_shl(32))
        .wrapping_add(minor.wrapping_shl(16));
    mixed ^= mixed >> 33;
    mixed = mixed.wrapping_mul(0xff51_afd7_ed55_8ccd);
    mixed ^= mixed >> 33;
    mixed = mixed.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    mixed ^= mixed >> 33;
    Some(if mixed == 0 { 1 } else { mixed as usize })
}

// 从 maps 文本里提取指定模块的 PT_LOAD 段范围。
//
// 起点必须是 base_addr（offset=0 的那一行），之后连续同名映射都算该模块的段。
// maps 按地址升序排列，遇到不同的 pathname 即结束，避免把相邻模块的段并进来。
//
// 这条路径只用于「模块存在但 dl_iterate_phdr 看不到」的情形——注入框架会用自己
// 的 linker 映射模块，不把它们注册进 bionic 的 solist，于是
// `bionic_module_ranges` 拿不到范围，而 `enumerate_modules` 又能从 maps 看到它们。
pub(super) fn parse_module_ranges(
    content: &str,
    pathname: &str,
    base_addr: usize,
) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut started = false;
    for line in content.lines() {
        let Some((start, end, path)) = parse_maps_range_line(line) else {
            continue;
        };
        if !started {
            if path != pathname || start != base_addr {
                continue;
            }
            started = true;
        } else if path != pathname {
            break;
        }
        ranges.push((start, end));
    }
    ranges
}

// 为缺少段范围的模块用 maps 补齐。
//
// 只在确实存在缺失模块时才读一次 /proc/self/maps，常规路径（全部模块都在 phdr
// 名单里）不产生额外 IO。
pub(super) fn supplement_missing_ranges(
    ranges: &mut BTreeMap<usize, Vec<(usize, usize)>>,
    modules: &[ModuleInfo],
) {
    if modules
        .iter()
        .all(|module| ranges.contains_key(&module.base_addr))
    {
        return;
    }
    let Ok(content) = fs::read_to_string("/proc/self/maps") else {
        return;
    };
    for module in modules {
        if ranges.contains_key(&module.base_addr) {
            continue;
        }
        let mapped = parse_module_ranges(&content, &module.pathname, module.base_addr);
        if !mapped.is_empty() {
            ranges.insert(module.base_addr, mapped);
        }
    }
}

fn parse_maps_range_line(line: &str) -> Option<(usize, usize, &str)> {
    let mut fields = line.split_whitespace();
    let range = fields.next()?;
    let _perms = fields.next()?;
    let _offset = fields.next()?;
    let _dev = fields.next()?;
    let _inode = fields.next()?;
    let pathname = fields.next()?;

    let (start, end) = range.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;
    Some((start, end, strip_deleted_marker(pathname)))
}

// 已删除文件的映射在 maps 里带 " (deleted)" 后缀，归属判定要按原名比较。
fn strip_deleted_marker(pathname: &str) -> &str {
    pathname.strip_suffix(" (deleted)").unwrap_or(pathname)
}
