// /proc/self/maps 解析与缓存，提供基于文件映射的模块枚举
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
