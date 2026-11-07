// dlopen 回调管理，支持注册 pre/post 回调以监听动态库加载事件
use crate::api::{PostDlopenCallback, PreDlopenCallback};
use crate::errno::Errno;
use std::ffi::{c_char, c_void};

use super::super::state::{DlopenCallbackEntry, GLOBAL};
use crate::runtime::fork;

pub(super) fn add_dlopen_callback(
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: *mut c_void,
) -> Errno {
    if pre.is_none() && post.is_none() {
        return Errno::InvalidArg;
    }
    if let Err(status) = fork::check_management() {
        return status;
    }
    let data = data as usize;
    GLOBAL.update(|draft| {
        if draft.clearing {
            return Errno::Busy;
        }
        if !draft
            .dlopen_callbacks
            .iter()
            .any(|entry| is_same_dlopen_callback(entry, pre, post, data))
        {
            draft.dlopen_callbacks.push(DlopenCallbackEntry {
                pre,
                post,
                arg: data,
            });
        }
        Errno::Ok
    })
}

pub(super) fn del_dlopen_callback(
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: *mut c_void,
) -> Errno {
    if pre.is_none() && post.is_none() {
        return Errno::InvalidArg;
    }
    if let Err(status) = fork::check_management() {
        return status;
    }
    let data = data as usize;
    GLOBAL.update(|draft| {
        if draft.clearing {
            return Errno::Busy;
        }
        draft
            .dlopen_callbacks
            .retain(|entry| !is_same_dlopen_callback(entry, pre, post, data));
        Errno::Ok
    })
}

// 回调使用已复制的列表，执行前释放内部状态。
pub(super) fn invoke_dlopen_callbacks_pre(filename: *const c_char) {
    if fork::check_management().is_err() {
        return;
    }
    let callbacks = GLOBAL.snapshot().dlopen_callbacks.clone();
    for entry in callbacks {
        if let Some(pre) = entry.pre {
            unsafe {
                pre(filename, entry.arg as *mut c_void);
            }
        }
    }
}

pub(super) fn invoke_dlopen_callbacks_post(filename: *const c_char, result: i32) {
    if fork::check_management().is_err() {
        return;
    }
    let callbacks = GLOBAL.snapshot().dlopen_callbacks.clone();
    for entry in callbacks {
        if let Some(post) = entry.post {
            unsafe {
                post(filename, result, entry.arg as *mut c_void);
            }
        }
    }
}

fn is_same_dlopen_callback(
    entry: &DlopenCallbackEntry,
    pre: Option<PreDlopenCallback>,
    post: Option<PostDlopenCallback>,
    data: usize,
) -> bool {
    entry.pre.map(|callback| callback as usize) == pre.map(|callback| callback as usize)
        && entry.post.map(|callback| callback as usize) == post.map(|callback| callback as usize)
        && entry.arg == data
}
