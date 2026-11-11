// 基于 dlinfo/dladdr1 的模块身份解析，从 handle 或符号地址提取完整 ModuleInfo
use crate::log;
use std::ffi::{CStr, CString, c_void};
use std::mem;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::hints::{
    resolve_namespace_id_by_base, resolve_namespace_id_by_instance, resolve_namespace_id_by_path,
};
use super::maps::enumerate_modules_maps_cached;
use super::noload::resolve_namespace_id_from_noload_cached;
use super::{
    Dladdr1Fn, DlinfoFn, LinkMap, ModuleInfo, RTLD_DI_LINKMAP, RTLD_DI_LMID, RTLD_NEXT_FALLBACK,
};

// 延迟解析 dlinfo 函数地址，优先 RTLD_NEXT 再回退到 libdl.so NOLOAD
pub(super) fn resolve_dlinfo_fn() -> Option<DlinfoFn> {
    static DLINFO_FN: AtomicUsize = AtomicUsize::new(0);
    let address = cached_address(&DLINFO_FN, || {
        let mut symbol = unsafe { libc::dlsym(RTLD_NEXT_FALLBACK, c"dlinfo".as_ptr()) };
        if symbol.is_null() {
            let handle =
                unsafe { libc::dlopen(c"libdl.so".as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
            if !handle.is_null() {
                symbol = unsafe { libc::dlsym(handle, c"dlinfo".as_ptr()) };
                unsafe {
                    libc::dlclose(handle);
                }
            }
        }
        if symbol.is_null() {
            log::debug(format_args!("dlinfo symbol unavailable"));
            0
        } else {
            log::debug(format_args!(
                "dlinfo symbol resolved at 0x{:x}",
                symbol as usize
            ));
            symbol as usize
        }
    });
    (address != 0).then(|| unsafe { mem::transmute::<usize, DlinfoFn>(address) })
}

fn resolve_dladdr1_fn() -> Option<Dladdr1Fn> {
    static DLADDR1_FN: AtomicUsize = AtomicUsize::new(0);
    let address = cached_address(&DLADDR1_FN, || {
        let mut symbol = unsafe { libc::dlsym(RTLD_NEXT_FALLBACK, c"dladdr1".as_ptr()) };
        if symbol.is_null() {
            let handle =
                unsafe { libc::dlopen(c"libdl.so".as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
            if !handle.is_null() {
                symbol = unsafe { libc::dlsym(handle, c"dladdr1".as_ptr()) };
                unsafe {
                    libc::dlclose(handle);
                }
            }
        }
        if symbol.is_null() { 0 } else { symbol as usize }
    });
    (address != 0).then(|| unsafe { mem::transmute::<usize, Dladdr1Fn>(address) })
}

fn cached_address(cache: &AtomicUsize, resolve: impl FnOnce() -> usize) -> usize {
    let cached = cache.load(Ordering::Acquire);
    let value = if cached == 0 {
        let resolved = resolve().max(1);
        match cache.compare_exchange(0, resolved, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => resolved,
            Err(published) => published,
        }
    } else {
        cached
    };
    if value == 1 { 0 } else { value }
}

// 通过 dlinfo(RTLD_DI_LINKMAP) 从 handle 解析模块完整身份
pub(super) fn resolve_module_from_handle(handle: *mut c_void) -> Option<ModuleInfo> {
    let dlinfo = resolve_dlinfo_fn()?;
    let link_map_ptr = resolve_link_map_from_handle(dlinfo, handle)?;
    let link_map = unsafe { &*link_map_ptr };
    if link_map.l_name.is_null() {
        return None;
    }
    let pathname = unsafe { CStr::from_ptr(link_map.l_name) }
        .to_str()
        .ok()?
        .trim();
    if pathname.is_empty() || pathname.starts_with('[') {
        return None;
    }
    let base_addr = link_map.l_addr;
    let instance_id = link_map_ptr as usize;
    let namespace_id = resolve_namespace_id_from_handle(dlinfo, handle)
        .filter(|id| *id != 0)
        .or_else(|| resolve_namespace_id_from_link_map(link_map_ptr))
        .or_else(|| {
            resolve_namespace_id_from_noload_cache(pathname, base_addr, instance_id, Some(dlinfo))
        })
        .or_else(|| resolve_namespace_id_by_instance(instance_id))
        .or_else(|| resolve_namespace_id_by_base(base_addr))
        .or_else(|| resolve_namespace_id_by_path(pathname))
        .unwrap_or(0);
    Some(ModuleInfo {
        pathname: pathname.to_string(),
        base_addr,
        instance_id,
        namespace_id,
    })
}

pub(super) fn resolve_link_map_from_handle(
    dlinfo: DlinfoFn,
    handle: *mut c_void,
) -> Option<*mut LinkMap> {
    let mut link_map_ptr: *mut LinkMap = ptr::null_mut();
    let info_ptr = (&mut link_map_ptr as *mut *mut LinkMap).cast::<c_void>();
    if unsafe { dlinfo(handle, RTLD_DI_LINKMAP, info_ptr) } != 0 || link_map_ptr.is_null() {
        return None;
    }
    Some(link_map_ptr)
}

fn resolve_link_map_from_addr(addr: *const c_void) -> Option<*mut LinkMap> {
    let dladdr1 = resolve_dladdr1_fn()?;
    let mut info: libc::Dl_info = unsafe { mem::zeroed() };
    let mut link_map_ptr: *mut c_void = ptr::null_mut();
    if unsafe { dladdr1(addr, &mut info, &mut link_map_ptr, RTLD_DI_LINKMAP) } == 0
        || link_map_ptr.is_null()
    {
        return None;
    }
    Some(link_map_ptr.cast::<LinkMap>())
}

pub(super) fn resolve_namespace_id_from_handle(
    dlinfo: DlinfoFn,
    handle: *mut c_void,
) -> Option<usize> {
    let mut namespace_id = 0usize;
    let info_ptr = (&mut namespace_id as *mut usize).cast::<c_void>();
    if unsafe { dlinfo(handle, RTLD_DI_LMID, info_ptr) } != 0 {
        return None;
    }
    Some(namespace_id)
}

// 沿 link_map 双向链表回溯到头节点，头节点地址即为 namespace_id
pub(super) fn resolve_namespace_id_from_link_map(link_map_ptr: *mut LinkMap) -> Option<usize> {
    if link_map_ptr.is_null() {
        return None;
    }

    let mut head = link_map_ptr;
    let mut guard = 0usize;
    while !head.is_null() && guard < 4096 {
        let prev = unsafe { (*head).l_prev };
        if prev.is_null() {
            break;
        }
        head = prev;
        guard += 1;
    }
    if head.is_null() || guard >= 4096 {
        return None;
    }
    Some(head as usize)
}

// 通过 dlsym 探测符号地址，再由 dladdr 反查模块信息。
pub(super) fn resolve_module_from_handle_symbol(
    handle: *mut c_void,
    probe_symbol: &str,
) -> Option<ModuleInfo> {
    if probe_symbol.is_empty() {
        return None;
    }

    let probe_symbol = CString::new(probe_symbol).ok()?;
    let symbol_addr = unsafe { libc::dlsym(handle, probe_symbol.as_ptr()) };
    if symbol_addr.is_null() {
        log::debug(format_args!(
            "module identity fallback missing symbol {}, handle=0x{:x}",
            probe_symbol.to_string_lossy(),
            handle as usize
        ));
        return None;
    }

    let mut info: libc::Dl_info = unsafe { mem::zeroed() };
    if unsafe { libc::dladdr(symbol_addr as *const c_void, &mut info) } == 0
        || info.dli_fbase.is_null()
        || info.dli_fname.is_null()
    {
        return None;
    }

    let pathname = unsafe { CStr::from_ptr(info.dli_fname) }
        .to_str()
        .ok()?
        .trim();
    if pathname.is_empty() || pathname.starts_with('[') {
        return None;
    }

    let base_addr = info.dli_fbase as usize;
    let dlinfo = resolve_dlinfo_fn();
    let link_map_ptr = dlinfo
        .and_then(|func| resolve_link_map_from_handle(func, handle))
        .or_else(|| resolve_link_map_from_addr(symbol_addr as *const c_void));
    let instance_id = link_map_ptr
        .map(|ptr| ptr as usize)
        .filter(|id| *id != 0)
        .or_else(|| resolve_instance_id_by_base(base_addr))
        .or_else(|| resolve_instance_id_from_maps(base_addr, pathname))
        .unwrap_or(base_addr.max(1));
    let namespace_id = dlinfo
        .and_then(|func| resolve_namespace_id_from_handle(func, handle))
        .filter(|id| *id != 0)
        .or_else(|| link_map_ptr.and_then(resolve_namespace_id_from_link_map))
        .or_else(|| {
            resolve_namespace_id_from_noload_cache(pathname, base_addr, instance_id, dlinfo)
        })
        .or_else(|| resolve_namespace_id_by_instance(instance_id))
        .or_else(|| resolve_namespace_id_by_base(base_addr))
        .or_else(|| resolve_namespace_id_by_path(pathname))
        .unwrap_or(0);
    Some(ModuleInfo {
        pathname: pathname.to_string(),
        base_addr,
        instance_id,
        namespace_id,
    })
}

fn resolve_instance_id_by_base(base_addr: usize) -> Option<usize> {
    #[repr(C)]
    struct Query {
        base_addr: usize,
        instance_id: usize,
    }

    unsafe extern "C" fn iterate_cb(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut c_void,
    ) -> libc::c_int {
        if info.is_null() || data.is_null() {
            return 0;
        }
        let info = unsafe { &*info };
        let query = unsafe { &mut *(data as *mut Query) };
        if info.dlpi_addr as usize != query.base_addr {
            return 0;
        }
        query.instance_id = info.dlpi_name as usize;
        1
    }

    let mut query = Query {
        base_addr,
        instance_id: 0,
    };
    unsafe {
        libc::dl_iterate_phdr(Some(iterate_cb), &mut query as *mut _ as *mut c_void);
    }
    if query.instance_id == 0 {
        None
    } else {
        Some(query.instance_id)
    }
}

fn resolve_instance_id_from_maps(base_addr: usize, pathname: &str) -> Option<usize> {
    let modules = enumerate_modules_maps_cached();
    let mut base_fallback = None;
    for module in modules {
        if module.base_addr != base_addr {
            continue;
        }
        if module.instance_id != 0 {
            base_fallback = Some(module.instance_id);
        }
        if module.pathname == pathname {
            return Some(module.instance_id.max(1));
        }
    }
    base_fallback
}

fn resolve_namespace_id_from_noload_cache(
    pathname: &str,
    base_addr: usize,
    instance_id: usize,
    dlinfo: Option<DlinfoFn>,
) -> Option<usize> {
    let dlinfo = dlinfo?;
    if pathname.is_empty() || base_addr == 0 {
        return None;
    }
    let module = ModuleInfo {
        pathname: pathname.to_string(),
        base_addr,
        instance_id,
        namespace_id: 0,
    };
    resolve_namespace_id_from_noload_cached(&module, dlinfo)
}

#[cfg(test)]
mod tests {
    use super::{LinkMap, resolve_namespace_id_from_link_map};
    use std::ptr;

    #[test]
    fn resolve_namespace_from_link_map_cycle_guarded() {
        let mut left = LinkMap {
            l_addr: 0,
            l_name: ptr::null(),
            l_ld: ptr::null_mut(),
            l_next: ptr::null_mut(),
            l_prev: ptr::null_mut(),
        };
        left.l_prev = ptr::addr_of_mut!(left);

        let namespace = resolve_namespace_id_from_link_map(ptr::addr_of_mut!(left));
        assert!(namespace.is_none());
    }
}
