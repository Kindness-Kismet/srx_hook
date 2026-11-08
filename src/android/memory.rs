// 内存页面保护属性的读取与修改，通过解析 /proc/self/maps 获取权限

use crate::errno::Errno;
use crate::log;
use std::cell::OnceCell;
use std::fs;
use std::sync::atomic::{Ordering, fence};

pub const PROT_READ_FLAG: u32 = 0x1;
pub const PROT_WRITE_FLAG: u32 = 0x2;
pub const PROT_EXEC_FLAG: u32 = 0x4;

struct ProtectionRange {
    start: usize,
    end: usize,
    protection: u32,
}

// 快照只在调用方持有的同一次 loader 租期内复用。
#[derive(Default)]
pub(crate) struct MemoryProtections {
    ranges: OnceCell<Result<Vec<ProtectionRange>, Errno>>,
}

impl MemoryProtections {
    fn read_ranges() -> Result<Vec<ProtectionRange>, Errno> {
        let content = fs::read("/proc/self/maps").map_err(|_| Errno::BadMaps)?;
        let mut ranges = Vec::new();
        for line in content.split(|byte| *byte == b'\n') {
            if let Some(range) = parse_protection_range(line) {
                ranges.push(range);
            }
        }
        Ok(ranges)
    }

    // maps 按地址递增；跨段取交集，空洞和共享映射不提供私有页权限。
    pub(crate) fn get(&self, addr: usize, len: usize) -> Result<u32, Errno> {
        let ranges = self
            .ranges
            .get_or_init(Self::read_ranges)
            .as_ref()
            .map_err(|error| *error)?;
        let mut current = addr;
        let end = addr.saturating_add(len);
        let mut protection = PROT_READ_FLAG | PROT_WRITE_FLAG | PROT_EXEC_FLAG;
        let first = ranges.partition_point(|range| range.end <= addr);
        for range in &ranges[first..] {
            if current < range.start {
                return Err(Errno::SegvErr);
            }
            protection &= range.protection;
            if end <= range.end {
                return Ok(protection);
            }
            current = range.end;
        }
        Err(Errno::SegvErr)
    }
}

fn parse_protection_range(line: &[u8]) -> Option<ProtectionRange> {
    // maps 路径允许非 UTF-8 字节，只解析地址和权限字段。
    let mut fields = line
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty());
    let (start, end) = std::str::from_utf8(fields.next()?).ok()?.split_once('-')?;
    let permissions = fields.next()?;
    if permissions.len() < 4 || permissions[3] != b'p' {
        return None;
    }
    let mut protection = 0;
    for (value, expected, flag) in [
        (permissions[0], b'r', PROT_READ_FLAG),
        (permissions[1], b'w', PROT_WRITE_FLAG),
        (permissions[2], b'x', PROT_EXEC_FLAG),
    ] {
        if value == expected {
            protection |= flag;
        }
    }
    Some(ProtectionRange {
        start: usize::from_str_radix(start, 16).ok()?,
        end: usize::from_str_radix(end, 16).ok()?,
        protection,
    })
}

// 路径提示不影响权限结果，按地址覆盖直接定位唯一映射。
pub fn get_mem_protect(addr: usize, len: usize, _pathname: Option<&str>) -> Result<u32, Errno> {
    MemoryProtections::default().get(addr, len)
}

// 查询单个指针大小地址的保护属性
pub fn get_addr_protect(addr: usize, pathname: Option<&str>) -> Result<u32, Errno> {
    get_mem_protect(addr, std::mem::size_of::<usize>(), pathname)
}

// 修改指定地址所在页面的保护属性
pub fn set_addr_protect(addr: usize, prot: u32) -> Result<(), Errno> {
    let (start, len) = page_bounds(addr);
    let result = unsafe { libc::mprotect(start as *mut libc::c_void, len, prot as i32) };
    if result != 0 {
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        log::error(format_args!("mprotect failed: {err}"));
        return Err(Errno::Unknown);
    }
    Ok(())
}

// 单地址指令缓存刷新，仅发出内存屏障
pub fn flush_instruction_cache(addr: usize) {
    let _ = addr;
    fence(Ordering::SeqCst);
}

// 刷新指定地址范围的指令缓存
pub fn flush_instruction_cache_range(start: usize, end: usize) {
    if start >= end {
        return;
    }
    clear_cache_range(start as *mut libc::c_void, end as *mut libc::c_void);
}

// aarch64: 逐行清理 dcache 再逐行无效化 icache，最后 dsb+isb 同步
// x86_64: 硬件保证缓存一致性，仅需内存屏障
fn flush_instruction_cache_impl(start: usize, end: usize) {
    if start >= end {
        return;
    }

    #[cfg(target_arch = "aarch64")]
    {
        let (dcache_line, icache_line) = cache_line_size();
        let mut dcache_addr = align_down(start, dcache_line);
        while dcache_addr < end {
            unsafe {
                core::arch::asm!("dc cvau, {}", in(reg) dcache_addr, options(nostack, preserves_flags));
            }
            dcache_addr = dcache_addr.saturating_add(dcache_line);
        }
        unsafe {
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
        }

        let mut icache_addr = align_down(start, icache_line);
        while icache_addr < end {
            unsafe {
                core::arch::asm!("ic ivau, {}", in(reg) icache_addr, options(nostack, preserves_flags));
            }
            icache_addr = icache_addr.saturating_add(icache_line);
        }
        unsafe {
            core::arch::asm!("dsb ish", options(nostack, preserves_flags));
            core::arch::asm!("isb", options(nostack, preserves_flags));
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        fence(Ordering::SeqCst);
    }
}

fn clear_cache_range(start: *mut libc::c_void, end: *mut libc::c_void) {
    if start.is_null() || end.is_null() {
        return;
    }
    flush_instruction_cache_impl(start as usize, end as usize);
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

// 计算地址所在页面的起始地址和覆盖长度（页对齐）
fn page_bounds(addr: usize) -> (usize, usize) {
    let page_size = page_size();
    if page_size == 0 {
        return (addr, std::mem::size_of::<usize>());
    }
    let page_mask = !(page_size - 1);
    let start = addr & page_mask;
    let end = (addr + std::mem::size_of::<usize>() - 1) & page_mask;
    let end = end + page_size;
    (start, end - start)
}

// 读取 CTR_EL0 寄存器，返回 (dcache_line_size, icache_line_size)
#[cfg(target_arch = "aarch64")]
fn cache_line_size() -> (usize, usize) {
    let ctr_el0: usize;
    unsafe {
        core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr_el0, options(nomem, nostack, preserves_flags));
    }

    let dcache_line = 4usize << ((ctr_el0 >> 16) & 0x0f);
    let icache_line = 4usize << (ctr_el0 & 0x0f);
    (dcache_line.max(4), icache_line.max(4))
}

#[cfg(target_arch = "aarch64")]
fn align_down(addr: usize, align: usize) -> usize {
    let mask = !(align.saturating_sub(1));
    addr & mask
}
