// Trampoline 代码生成与内存管理
// 通过汇编模板 + 运行时数据填充，为每个 Hub 生成独立的跳板代码
use crate::errno::Errno;
use crate::android::memory;
use std::mem::size_of;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

const TRAMPO_ALIGN: usize = 16;
// 释放后的冷却期，防止被立即复用时指令缓存未刷新
const TRAMPO_DELAY_SEC: u64 = 5;

mod manager;

// aarch64 trampoline 模板：保存全部调用约定寄存器 -> push_stack -> 调用 proxy -> pop_stack -> 恢复并返回
#[cfg(target_arch = "aarch64")]
std::arch::global_asm!(
    r#"
    .text
    .global srx_hub_trampo_template_start
    .global srx_hub_trampo_template_data
    .type srx_hub_trampo_template_start, %function
srx_hub_trampo_template_start:
    stp   x0, x1, [sp, #-0xd0]!
    stp   x2, x3, [sp, #0x10]
    stp   x4, x5, [sp, #0x20]
    stp   x6, x7, [sp, #0x30]
    stp   x8, lr, [sp, #0x40]
    stp   q0, q1, [sp, #0x50]
    stp   q2, q3, [sp, #0x70]
    stp   q4, q5, [sp, #0x90]
    stp   q6, q7, [sp, #0xb0]

    ldr   x0, hub_ptr
    mov   x1, lr
    ldr   x16, push_stack
    blr   x16
    mov   x17, x0

    ldp   q6, q7, [sp, #0xb0]
    ldp   q4, q5, [sp, #0x90]
    ldp   q2, q3, [sp, #0x70]
    ldp   q0, q1, [sp, #0x50]
    ldp   x8, lr, [sp, #0x40]
    ldp   x6, x7, [sp, #0x30]
    ldp   x4, x5, [sp, #0x20]
    ldp   x2, x3, [sp, #0x10]
    ldp   x0, x1, [sp], #0xd0

    sub   sp, sp, #0x40
    str   lr, [sp]
    blr   x17
    stp   x0, x1, [sp, #0x08]
    stp   q0, q1, [sp, #0x20]

    ldr   x0, hub_ptr
    ldr   x16, pop_stack
    blr   x16

    ldp   x0, x1, [sp, #0x08]
    ldp   q0, q1, [sp, #0x20]
    ldr   lr, [sp]
    add   sp, sp, #0x40
    ret

srx_hub_trampo_template_data:
push_stack:
    .quad 0
pop_stack:
    .quad 0
hub_ptr:
    .quad 0
"#
);

// x86_64 trampoline 模板：同 aarch64 逻辑，使用 AT&T 语法
#[cfg(target_arch = "x86_64")]
std::arch::global_asm!(
    r#"
    .text
    .global srx_hub_trampo_template_start
    .global srx_hub_trampo_template_data
    .type srx_hub_trampo_template_start, @function
srx_hub_trampo_template_start:
    pushq   %rbp
    movq    %rsp, %rbp

    subq    $192,  %rsp
    movupd  %xmm0, 176(%rsp)
    movupd  %xmm1, 160(%rsp)
    movupd  %xmm2, 144(%rsp)
    movupd  %xmm3, 128(%rsp)
    movupd  %xmm4, 112(%rsp)
    movupd  %xmm5,  96(%rsp)
    movupd  %xmm6,  80(%rsp)
    movupd  %xmm7,  64(%rsp)
    movq    %rax,   56(%rsp)
    movq    %rdi,   48(%rsp)
    movq    %rsi,   40(%rsp)
    movq    %rdx,   32(%rsp)
    movq    %rcx,   24(%rsp)
    movq    %r8,    16(%rsp)
    movq    %r9,     8(%rsp)
    movq    %r10,     (%rsp)

    movq    hub_ptr(%rip), %rdi
    movq    8(%rbp), %rsi
    call    *push_stack(%rip)
    movq    %rax, %r11

    movupd  176(%rsp), %xmm0
    movupd  160(%rsp), %xmm1
    movupd  144(%rsp), %xmm2
    movupd  128(%rsp), %xmm3
    movupd  112(%rsp), %xmm4
    movupd   96(%rsp), %xmm5
    movupd   80(%rsp), %xmm6
    movupd   64(%rsp), %xmm7
    movq     56(%rsp), %rax
    movq     48(%rsp), %rdi
    movq     40(%rsp), %rsi
    movq     32(%rsp), %rdx
    movq     24(%rsp), %rcx
    movq     16(%rsp), %r8
    movq      8(%rsp), %r9
    movq       (%rsp), %r10
    addq    $192,      %rsp

    movq    %rbp, %rsp
    popq    %rbp
    subq    $8, %rsp
    call    *%r11
    addq    $8, %rsp

    // pop_stack 保存区：48 字节数据 + 8 字节对齐 padding，确保 call 前 rsp 为 16 字节对齐
    subq    $72, %rsp
    movq    %rax,   (%rsp)
    movq    %rdx,  8(%rsp)
    movupd  %xmm0, 16(%rsp)
    movupd  %xmm1, 32(%rsp)

    movq    hub_ptr(%rip), %rdi
    call    *pop_stack(%rip)

    movq      (%rsp), %rax
    movq     8(%rsp), %rdx
    movupd  16(%rsp), %xmm0
    movupd  32(%rsp), %xmm1
    addq    $72, %rsp
    ret

srx_hub_trampo_template_data:
push_stack:
    .quad 0
pop_stack:
    .quad 0
hub_ptr:
    .quad 0
"#
    ,
    options(att_syntax)
);

unsafe extern "C" {
    static srx_hub_trampo_template_start: u8;
    static srx_hub_trampo_template_data: u8;
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    value.div_ceil(align) * align
}

// 计算单个 trampoline 占用大小：代码段 + 3 个 usize 数据槽，按 TRAMPO_ALIGN 对齐
fn trampo_size() -> usize {
    let start = ptr::addr_of!(srx_hub_trampo_template_start) as usize;
    let data = ptr::addr_of!(srx_hub_trampo_template_data) as usize;
    let code_size = data.saturating_sub(start);
    align_up(code_size + size_of::<usize>() * 3, TRAMPO_ALIGN)
}

fn now_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(super) fn alloc_trampo() -> Result<usize, Errno> {
    manager::alloc_trampo()
}

pub(super) fn free_trampo(trampo: usize) {
    manager::free_trampo(trampo);
}

// 初始化 trampoline：复制模板代码、填充数据槽、刷新 icache、设置 RX 权限
pub(super) unsafe fn init_trampo(
    trampo: usize,
    hub_ptr: usize,
    push_stack: usize,
    pop_stack: usize,
) -> Result<(), Errno> {
    let writable_prot = memory::PROT_READ_FLAG | memory::PROT_WRITE_FLAG;
    memory::set_addr_protect(trampo, writable_prot).map_err(|_| Errno::InitErrTrampo)?;

    let start = ptr::addr_of!(srx_hub_trampo_template_start) as usize;
    let data = ptr::addr_of!(srx_hub_trampo_template_data) as usize;
    let code_size = data.saturating_sub(start);
    if code_size == 0 {
        return Err(Errno::InitErrTrampo);
    }

    unsafe {
        ptr::copy_nonoverlapping(start as *const u8, trampo as *mut u8, code_size);
        let data_ptr = (trampo + code_size) as *mut usize;
        ptr::write(data_ptr, push_stack);
        ptr::write(data_ptr.add(1), pop_stack);
        ptr::write(data_ptr.add(2), hub_ptr);
    }

    memory::flush_instruction_cache_range(trampo, trampo + code_size + size_of::<usize>() * 3);
    let execute_prot = memory::PROT_READ_FLAG | memory::PROT_EXEC_FLAG;
    memory::set_addr_protect(trampo, execute_prot).map_err(|_| Errno::InitErrTrampo)?;
    Ok(())
}
