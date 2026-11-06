// Hub 调用栈的单元测试
use super::{
    HubFrame, get_prev_func, pop_stack_by_return_address, proxy_leave, with_test_hub_stack,
};
use std::sync::atomic::{AtomicBool, AtomicUsize};

fn make_node(
    func: usize,
    enabled: bool,
    next: *mut super::super::ProxyNode,
) -> *mut super::super::ProxyNode {
    Box::into_raw(Box::new(super::super::ProxyNode {
        func,
        ref_count: AtomicUsize::new(1),
        enabled: AtomicBool::new(enabled),
        next,
    }))
}

#[test]
fn get_prev_func_searches_non_top_frame() {
    let tail = make_node(0x2222, true, std::ptr::null_mut());
    let head = make_node(0x1111, true, tail);
    let other = make_node(0x3333, true, std::ptr::null_mut());

    with_test_hub_stack(|stack| {
        let _ = stack.clear();
        assert!(stack.push(HubFrame {
            hub_id: 1,
            head_ptr: head as usize,
            orig_addr: 0x4444,
            first_proxy: 0x1111,
            return_addr: 0xabc,
            stack_sp: usize::MAX,
        }));
        assert!(stack.push(HubFrame {
            hub_id: 2,
            head_ptr: other as usize,
            orig_addr: 0x5555,
            first_proxy: 0x3333,
            return_addr: 0xdef,
            stack_sp: usize::MAX,
        }));
    });

    let prev = get_prev_func(0x1111 as *mut std::ffi::c_void);
    assert_eq!(prev as usize, 0x2222);

    with_test_hub_stack(|stack| {
        let _ = stack.clear();
    });
    unsafe {
        drop(Box::from_raw(head));
        drop(Box::from_raw(tail));
        drop(Box::from_raw(other));
    }
}

#[test]
fn pop_stack_by_return_address_removes_non_top_frame() {
    with_test_hub_stack(|stack| {
        let _ = stack.clear();
        assert!(stack.push(HubFrame {
            hub_id: 1,
            head_ptr: 0,
            orig_addr: 0,
            first_proxy: 0,
            return_addr: 0x111,
            stack_sp: usize::MAX,
        }));
        assert!(stack.push(HubFrame {
            hub_id: 2,
            head_ptr: 0,
            orig_addr: 0,
            first_proxy: 0,
            return_addr: 0x222,
            stack_sp: usize::MAX,
        }));
    });

    pop_stack_by_return_address(0x111 as *mut std::ffi::c_void);
    with_test_hub_stack(|stack| {
        assert_eq!(stack.len(), 1);
        assert_eq!(stack.get(0).map(|frame| frame.hub_id), Some(2));
    });
    with_test_hub_stack(|stack| {
        let _ = stack.clear();
    });
}

#[test]
fn proxy_leave_removes_non_top_frame() {
    with_test_hub_stack(|stack| {
        let _ = stack.clear();
        assert!(stack.push(HubFrame {
            hub_id: 1,
            head_ptr: 0,
            orig_addr: 0,
            first_proxy: 0xaaaa,
            return_addr: 0,
            stack_sp: usize::MAX,
        }));
        assert!(stack.push(HubFrame {
            hub_id: 2,
            head_ptr: 0,
            orig_addr: 0,
            first_proxy: 0xbbbb,
            return_addr: 0,
            stack_sp: usize::MAX,
        }));
    });

    proxy_leave(0xaaaa as *mut std::ffi::c_void);
    with_test_hub_stack(|stack| {
        assert_eq!(stack.len(), 1);
        assert_eq!(stack.get(0).map(|frame| frame.first_proxy), Some(0xbbbb));
    });
    with_test_hub_stack(|stack| {
        let _ = stack.clear();
    });
}
