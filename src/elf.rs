// ELF 解析与 PLT/GOT hook 核心模块

use crate::android::memory as util;
use crate::errno::Errno;
use crate::log;
use std::collections::BTreeSet;
use std::ffi::{CStr, c_char};
use std::mem;
use std::ptr;
use std::slice;

// ELF 符号哈希算法
mod hash;
// Android packed relocation (SLEB128) 解码
mod packed;
// 重定位条目的 r_sym / r_type 提取
mod reloc;

use hash::{elf_gnu_hash, elf_hash};
use packed::PackedRelocIterator;
use reloc::{elf_r_sym, elf_r_type};

// ELF header e_ident 相关常量
const EI_NIDENT: usize = 16;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const EI_VERSION: usize = 6;

const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const SELFMAG: usize = 4;

const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const SHN_UNDEF: u16 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

// dynamic section 标签常量
const DT_NULL: i64 = 0;
const DT_PLTRELSZ: i64 = 2;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_GNU_HASH: i64 = 0x6ffffef5;

// Android 私有 packed relocation 标签
const DT_ANDROID_REL: i64 = 0x6000_000f;
const DT_ANDROID_RELA: i64 = 0x6000_0010;
const DT_ANDROID_RELSZ: i64 = 0x6000_0011;
const DT_ANDROID_RELASZ: i64 = 0x6000_0012;

const EM_AARCH64: u16 = 183;
const EM_X86_64: u16 = 62;

// AArch64 重定位类型
const R_AARCH64_JUMP_SLOT: u32 = 1026;
const R_AARCH64_GLOB_DAT: u32 = 1025;
const R_AARCH64_ABS64: u32 = 257;

// x86_64 重定位类型
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_64: u32 = 1;

#[cfg(target_arch = "aarch64")]
const EXPECTED_MACHINE: u16 = EM_AARCH64;
#[cfg(target_arch = "x86_64")]
const EXPECTED_MACHINE: u16 = EM_X86_64;

// 按目标架构选择对应的重定位类型常量
#[cfg(target_arch = "aarch64")]
const R_GENERIC_JUMP_SLOT: u32 = R_AARCH64_JUMP_SLOT;
#[cfg(target_arch = "aarch64")]
const R_GENERIC_GLOB_DAT: u32 = R_AARCH64_GLOB_DAT;
#[cfg(target_arch = "aarch64")]
const R_GENERIC_ABS: u32 = R_AARCH64_ABS64;

#[cfg(target_arch = "x86_64")]
const R_GENERIC_JUMP_SLOT: u32 = R_X86_64_JUMP_SLOT;
#[cfg(target_arch = "x86_64")]
const R_GENERIC_GLOB_DAT: u32 = R_X86_64_GLOB_DAT;
#[cfg(target_arch = "x86_64")]
const R_GENERIC_ABS: u32 = R_X86_64_64;

// ELF64 基本类型别名
type ElfAddr = u64;
type ElfOff = u64;
type ElfWord = u32;
type ElfXword = u64;
type ElfSxword = i64;
type ElfHalf = u16;

// ELF64 文件头，与 C 结构体 Elf64_Ehdr 内存布局一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ElfEhdr {
    e_ident: [u8; EI_NIDENT],
    e_type: ElfHalf,
    e_machine: ElfHalf,
    e_version: ElfWord,
    e_entry: ElfAddr,
    e_phoff: ElfOff,
    e_shoff: ElfOff,
    e_flags: ElfWord,
    e_ehsize: ElfHalf,
    e_phentsize: ElfHalf,
    e_phnum: ElfHalf,
    e_shentsize: ElfHalf,
    e_shnum: ElfHalf,
    e_shstrndx: ElfHalf,
}

// ELF64 程序头，描述段的加载信息
#[repr(C)]
#[derive(Clone, Copy)]
struct ElfPhdr {
    p_type: ElfWord,
    p_flags: ElfWord,
    p_offset: ElfOff,
    p_vaddr: ElfAddr,
    p_paddr: ElfAddr,
    p_filesz: ElfXword,
    p_memsz: ElfXword,
    p_align: ElfXword,
}

// ELF64 动态段条目
#[repr(C)]
#[derive(Clone, Copy)]
struct ElfDyn {
    d_tag: ElfSxword,
    d_un: ElfXword,
}

// ELF64 符号表条目
#[repr(C)]
#[derive(Clone, Copy)]
struct ElfSym {
    st_name: ElfWord,
    st_info: u8,
    st_other: u8,
    st_shndx: ElfHalf,
    st_value: ElfAddr,
    st_size: ElfXword,
}

// ELF64 REL 重定位条目（无 addend）
#[repr(C)]
#[derive(Clone, Copy)]
struct ElfRel {
    r_offset: ElfAddr,
    r_info: ElfXword,
}

// ELF64 RELA 重定位条目（含 addend）
#[repr(C)]
#[derive(Clone, Copy)]
struct ElfRela {
    r_offset: ElfAddr,
    r_info: ElfXword,
    r_addend: ElfSxword,
}

// 已解析的 ELF 映像，持有 hook 所需的全部元数据
pub struct Elf {
    pathname: String,
    // 映像在内存中的起始地址
    base_addr: usize,
    // base_addr 与 ELF 虚拟地址之间的偏移量
    bias_addr: usize,
    ehdr: *const ElfEhdr,
    phdr: *const ElfPhdr,
    dyn_section: *const ElfDyn,
    dyn_sz: usize,
    strtab: *const c_char,
    symtab: *const ElfSym,
    // .rel(a).plt 段地址与大小
    relplt: usize,
    relplt_sz: usize,
    // .rel(a).dyn 段地址与大小
    reldyn: usize,
    reldyn_sz: usize,
    // Android packed relocation 段地址与大小
    relandroid: usize,
    relandroid_sz: usize,
    // hash 表的 bucket 数组与计数
    bucket: *const u32,
    bucket_cnt: u32,
    // hash 表的 chain 数组与计数
    chain: *const u32,
    chain_cnt: u32,
    // GNU hash 的 bloom filter 数组与参数
    bloom: *const usize,
    bloom_sz: u32,
    bloom_shift: u32,
    // GNU hash 中已排序符号的起始索引
    symoffset: u32,
    is_use_gnu_hash: bool,
    is_use_rela: bool,
}

include!("elf/check_init.inc.rs");
include!("elf/api.inc.rs");
include!("elf/lookup.inc.rs");
