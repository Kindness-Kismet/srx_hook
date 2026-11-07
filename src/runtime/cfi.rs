// CFI (Control Flow Integrity) 绕过模块，负责禁用 Android 的 CFI slowpath 检查
// 仅 aarch64 架构有实际实现，其他架构为空操作
#[cfg(target_arch = "aarch64")]
use super::state::ModuleInfo;
#[cfg(target_arch = "aarch64")]
use crate::errno::Errno;
use std::ffi::{CStr, c_char};

// Android O (API 26) 起引入 CFI，低于此版本无需处理
const ANDROID_API_LEVEL_CFI_DISABLE: i32 = 26;
const SYSTEM_PROP_VALUE_MAX: usize = 92;
const RTLD_NEXT_FALLBACK: *mut libc::c_void = (-1isize) as *mut libc::c_void;

unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> libc::c_int;
}

#[cfg(target_arch = "aarch64")]
mod module_hook;
#[cfg(target_arch = "aarch64")]
mod slowpath;

#[cfg(target_arch = "aarch64")]
pub(super) const RET_INSTRUCTION: u32 = 0xd65f03c0;

// 调用方持有 Bionic 模块租期，补丁由统一事务提交。
#[cfg(target_arch = "aarch64")]
pub(super) fn global_patch_addresses(modules: &[ModuleInfo]) -> Result<Vec<usize>, Errno> {
    if android_api_level() < ANDROID_API_LEVEL_CFI_DISABLE {
        return Ok(Vec::new());
    }
    slowpath::global_patch_addresses(modules)
}

pub(super) fn module_proxy_addresses() -> Option<(usize, usize)> {
    #[cfg(target_arch = "aarch64")]
    {
        Some(module_hook::proxy_addresses())
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        None
    }
}

fn android_api_level() -> i32 {
    let prop_name = c"ro.build.version.sdk";
    let mut prop_value = [0 as c_char; SYSTEM_PROP_VALUE_MAX];
    let len = unsafe { __system_property_get(prop_name.as_ptr(), prop_value.as_mut_ptr()) };
    if len <= 0 {
        return 0;
    }

    let len = len as usize;
    if len >= SYSTEM_PROP_VALUE_MAX {
        return 0;
    }

    let value = unsafe { CStr::from_ptr(prop_value.as_ptr()) };
    value
        .to_str()
        .ok()
        .and_then(|text| text.parse::<i32>().ok())
        .unwrap_or(0)
}
