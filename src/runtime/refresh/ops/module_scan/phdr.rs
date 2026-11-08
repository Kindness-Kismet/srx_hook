// 按 PT_LOAD 的实际页映射识别同一 ELF 的文件首段别名。
use std::collections::BTreeMap;
use std::ffi::{CStr, c_void};

use super::ModuleInfo;

pub(super) struct PhdrModules {
    pub(super) modules: BTreeMap<usize, ModuleInfo>,
    zero_offset_segments: BTreeMap<usize, usize>,
    page_size: Option<usize>,
}

impl PhdrModules {
    pub(super) fn capture() -> Self {
        let mut snapshot = Self {
            modules: BTreeMap::new(),
            zero_offset_segments: BTreeMap::new(),
            page_size: usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
                .ok()
                .filter(|size| *size != 0),
        };
        unsafe {
            libc::dl_iterate_phdr(Some(collect), (&mut snapshot as *mut Self).cast::<c_void>());
        }
        snapshot
    }

    pub(super) fn is_segment_alias(
        &self,
        candidate: &ModuleInfo,
        maps: &BTreeMap<usize, ModuleInfo>,
    ) -> bool {
        // 真实加载基址优先，不能按同路径合并不同加载实例。
        if self.modules.contains_key(&candidate.base_addr) {
            return false;
        }
        let Some(owner_base) = self.zero_offset_segments.get(&candidate.base_addr) else {
            return false;
        };
        let Some(owner) = self.modules.get(owner_base) else {
            return false;
        };
        if let Some(header) = maps.get(owner_base) {
            return candidate.pathname == header.pathname
                && candidate.instance_id == header.instance_id;
        }
        candidate.pathname == owner.pathname
    }

    fn record_segments(&mut self, base: usize, headers: &[libc::Elf64_Phdr]) {
        let Some(page_size) = self.page_size else {
            return;
        };
        for header in headers {
            if header.p_type != libc::PT_LOAD || header.p_filesz == 0 {
                continue;
            }
            let offset = header.p_offset as usize;
            let virtual_address = header.p_vaddr as usize;
            // maps 候选的文件偏移为零，只能属于覆盖文件首个页的段起点。
            if offset >= page_size || offset != virtual_address % page_size {
                continue;
            }
            let Some(start) = base.checked_add(virtual_address / page_size * page_size) else {
                continue;
            };
            self.zero_offset_segments.insert(start, base);
        }
    }
}

unsafe extern "C" fn collect(
    info: *mut libc::dl_phdr_info,
    _size: usize,
    data: *mut c_void,
) -> libc::c_int {
    if info.is_null() {
        return 0;
    }
    let info = unsafe { &*info };
    if info.dlpi_name.is_null() {
        return 0;
    }
    let Ok(pathname) = unsafe { CStr::from_ptr(info.dlpi_name) }.to_str() else {
        return 0;
    };
    if pathname.is_empty() || pathname.starts_with('[') {
        return 0;
    }
    let snapshot = unsafe { &mut *data.cast::<PhdrModules>() };
    let base = info.dlpi_addr as usize;
    snapshot.modules.insert(
        base,
        ModuleInfo {
            pathname: pathname.to_string(),
            base_addr: base,
            instance_id: info.dlpi_name as usize,
            namespace_id: 0,
        },
    );
    if !info.dlpi_phdr.is_null() {
        let headers =
            unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize) };
        snapshot.record_segments(base, headers);
    }
    0
}
