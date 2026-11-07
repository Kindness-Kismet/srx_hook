// ELF header 校验与 Elf 结构体初始化，通过 include! 嵌入 elf.rs

// 校验内存中的 ELF header：magic、class、字节序、架构等
pub unsafe fn check_elf_header(base_addr: usize) -> Result<(), Errno> {
    let ehdr = &*(base_addr as *const ElfEhdr);
    if ehdr.e_ident[..SELFMAG] != ELFMAG {
        return Err(Errno::Format);
    }

    let class = ehdr.e_ident[EI_CLASS];
    if class != ELFCLASS64 {
        return Err(Errno::Format);
    }

    if ehdr.e_ident[EI_DATA] != ELFDATA2LSB {
        return Err(Errno::Format);
    }
    if ehdr.e_ident[EI_VERSION] != EV_CURRENT {
        return Err(Errno::Format);
    }
    if ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN {
        return Err(Errno::Format);
    }
    if ehdr.e_machine != EXPECTED_MACHINE {
        return Err(Errno::Format);
    }
    if ehdr.e_version as u8 != EV_CURRENT {
        return Err(Errno::Format);
    }

    Ok(())
}

impl Elf {
    // 从内存映像解析 ELF，提取 dynamic section 中的符号表、重定位表、hash 表等
    pub unsafe fn init(base_addr: usize, pathname: &str) -> Result<Self, Errno> {
        if base_addr == 0 {
            return Err(Errno::Invalid);
        }

        let ehdr = base_addr as *const ElfEhdr;
        let phdr = (base_addr + (*ehdr).e_phoff as usize) as *const ElfPhdr;
        let phdrs = slice::from_raw_parts(phdr, (*ehdr).e_phnum as usize);

        // 找到 offset=0 的 PT_LOAD 段，计算 bias（加载基址与虚拟地址的差值）
        let phdr0 = phdrs
            .iter()
            .find(|ph| ph.p_type == PT_LOAD && ph.p_offset == 0)
            .ok_or(Errno::Format)?;

        if base_addr < phdr0.p_vaddr as usize {
            return Err(Errno::Format);
        }
        let bias_addr = base_addr - phdr0.p_vaddr as usize;

        let dhdr = phdrs
            .iter()
            .find(|ph| ph.p_type == PT_DYNAMIC)
            .ok_or(Errno::Format)?;

        let dyn_section = (bias_addr + dhdr.p_vaddr as usize) as *const ElfDyn;
        let dyn_sz = dhdr.p_memsz as usize;

        let mut elf = Elf {
            pathname: pathname.to_string(),
            base_addr,
            bias_addr,
            ehdr,
            phdr,
            dyn_section,
            dyn_sz,
            strtab: ptr::null(),
            symtab: ptr::null(),
            relplt: 0,
            relplt_sz: 0,
            reldyn: 0,
            reldyn_sz: 0,
            relandroid: 0,
            relandroid_sz: 0,
            bucket: ptr::null(),
            bucket_cnt: 0,
            chain: ptr::null(),
            chain_cnt: 0,
            bloom: ptr::null(),
            bloom_sz: 0,
            bloom_shift: 0,
            symoffset: 0,
            is_use_gnu_hash: false,
            is_use_rela: false,
        };

        // 遍历 dynamic section，提取各表地址和大小
        let dyn_cnt = dyn_sz / mem::size_of::<ElfDyn>();
        let dyn_entries = slice::from_raw_parts(dyn_section, dyn_cnt);
        for dyn_entry in dyn_entries {
            match dyn_entry.d_tag {
                DT_NULL => break,
                DT_STRTAB => {
                    let ptr = (bias_addr + dyn_entry.d_un as usize) as *const c_char;
                    if (ptr as usize) < base_addr {
                        return Err(Errno::Format);
                    }
                    elf.strtab = ptr;
                }
                DT_SYMTAB => {
                    let ptr = (bias_addr + dyn_entry.d_un as usize) as *const ElfSym;
                    if (ptr as usize) < base_addr {
                        return Err(Errno::Format);
                    }
                    elf.symtab = ptr;
                }
                DT_PLTREL => {
                    elf.is_use_rela = dyn_entry.d_un as i64 == DT_RELA;
                }
                DT_JMPREL => {
                    let ptr = bias_addr + dyn_entry.d_un as usize;
                    if ptr < base_addr {
                        return Err(Errno::Format);
                    }
                    elf.relplt = ptr;
                }
                DT_PLTRELSZ => {
                    elf.relplt_sz = dyn_entry.d_un as usize;
                }
                DT_REL | DT_RELA => {
                    let ptr = bias_addr + dyn_entry.d_un as usize;
                    if ptr < base_addr {
                        return Err(Errno::Format);
                    }
                    elf.reldyn = ptr;
                }
                DT_RELSZ | DT_RELASZ => {
                    elf.reldyn_sz = dyn_entry.d_un as usize;
                }
                DT_ANDROID_REL | DT_ANDROID_RELA => {
                    let ptr = bias_addr + dyn_entry.d_un as usize;
                    if ptr < base_addr {
                        return Err(Errno::Format);
                    }
                    elf.relandroid = ptr;
                }
                DT_ANDROID_RELSZ | DT_ANDROID_RELASZ => {
                    elf.relandroid_sz = dyn_entry.d_un as usize;
                }
                DT_HASH => {
                    // 优先使用 GNU hash，已有则跳过 ELF hash
                    if elf.is_use_gnu_hash {
                        continue;
                    }
                    let raw = (bias_addr + dyn_entry.d_un as usize) as *const u32;
                    if (raw as usize) < base_addr {
                        return Err(Errno::Format);
                    }
                    elf.bucket_cnt = *raw;
                    elf.chain_cnt = *raw.add(1);
                    elf.bucket = raw.add(2);
                    elf.chain = elf.bucket.add(elf.bucket_cnt as usize);
                }
                DT_GNU_HASH => {
                    // GNU hash 布局：nbuckets | symoffset | bloom_sz | bloom_shift | bloom[] | buckets[] | chains[]
                    let raw = (bias_addr + dyn_entry.d_un as usize) as *const u32;
                    if (raw as usize) < base_addr {
                        return Err(Errno::Format);
                    }
                    elf.bucket_cnt = *raw;
                    elf.symoffset = *raw.add(1);
                    elf.bloom_sz = *raw.add(2);
                    elf.bloom_shift = *raw.add(3);
                    elf.bloom = raw.add(4) as *const usize;
                    elf.bucket = elf.bloom.add(elf.bloom_sz as usize) as *const u32;
                    elf.chain = elf.bucket.add(elf.bucket_cnt as usize);
                    elf.is_use_gnu_hash = true;
                }
                _ => {}
            }
        }

        // Android packed relocation 以 "APS2" 魔数开头，跳过 4 字节头部
        if elf.relandroid != 0 {
            let rel = elf.relandroid as *const u8;
            if elf.relandroid_sz < 4 {
                return Err(Errno::Format);
            }
            let header = slice::from_raw_parts(rel, 4);
            if header != *b"APS2" {
                log::error(format_args!("android rel/rela format error"));
                return Err(Errno::Format);
            }
            elf.relandroid += 4;
            elf.relandroid_sz -= 4;
        }

        elf.check()?;

        log::info(format_args!(
            "init OK: {} ({} {} PLT:{} DYN:{} ANDROID:{})",
            elf.pathname,
            if elf.is_use_rela { "RELA" } else { "REL" },
            if elf.is_use_gnu_hash {
                "GNU_HASH"
            } else {
                "ELF_HASH"
            },
            elf.relplt_sz,
            elf.reldyn_sz,
            elf.relandroid_sz
        ));

        Ok(elf)
    }


    // 校验初始化后的关键字段是否均已正确填充
    fn check(&self) -> Result<(), Errno> {
        if self.base_addr == 0
            || self.bias_addr == 0
            || self.ehdr.is_null()
            || self.phdr.is_null()
            || self.strtab.is_null()
            || self.symtab.is_null()
            || self.bucket.is_null()
            || self.chain.is_null()
        {
            return Err(Errno::Format);
        }
        if self.is_use_gnu_hash && self.bloom.is_null() {
            return Err(Errno::Format);
        }
        Ok(())
    }


    // 判断地址是否落在某个 PT_LOAD 段的虚拟地址范围内
    fn is_addr_in_load_segments(&self, addr: usize) -> bool {
        let phdrs = unsafe { slice::from_raw_parts(self.phdr, (*self.ehdr).e_phnum as usize) };
        for phdr in phdrs {
            if phdr.p_type != PT_LOAD {
                continue;
            }
            let start = self.bias_addr + phdr.p_vaddr as usize;
            let end = start.saturating_add(phdr.p_memsz as usize);
            if addr >= start && addr < end {
                return true;
            }
        }
        false
    }

}
