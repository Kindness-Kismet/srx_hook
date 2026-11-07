// Trampoline 代码生成与内存管理
// 通过汇编模板 + 运行时数据填充，为每个 Hub 生成独立的跳板代码
use crate::errno::Errno;
use std::mem::size_of;
use std::ptr;

const TRAMPO_ALIGN: usize = 16;

mod manager;

// aarch64 跳板：保存参数，保持原始 SP 分发调用，恢复返回寄存器和调用方地址。
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
    add   x2, sp, #0xd0
    adr   x3, trampo_return
    ldr   x16, push_stack
    blr   x16
    mov   x17, x0
    str   x1, [sp, #0x48]

    ldp   q6, q7, [sp, #0xb0]
    ldp   q4, q5, [sp, #0x90]
    ldp   q2, q3, [sp, #0x70]
    ldp   q0, q1, [sp, #0x50]
    ldp   x8, lr, [sp, #0x40]
    ldp   x6, x7, [sp, #0x30]
    ldp   x4, x5, [sp, #0x20]
    ldp   x2, x3, [sp, #0x10]
    ldp   x0, x1, [sp], #0xd0

    br    x17

trampo_return:
    sub   sp, sp, #0x50
    stp   x0, x1, [sp]
    stp   q0, q1, [sp, #0x10]
    stp   q2, q3, [sp, #0x30]

    ldr   x0, hub_ptr
    add   x1, sp, #0x50
    ldr   x16, pop_stack
    blr   x16

    mov   lr, x0
    ldp   x0, x1, [sp]
    ldp   q0, q1, [sp, #0x10]
    ldp   q2, q3, [sp, #0x30]
    add   sp, sp, #0x50
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

// x86_64 跳板：替换返回地址后保持原始参数布局分发，使用 AT&T 语法。
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
    leaq    16(%rbp), %rdx
    leaq    trampo_return(%rip), %rcx
    call    *push_stack(%rip)
    movq    %rax, %r11
    movq    %rdx, 8(%rbp)

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
    jmp     *%r11

trampo_return:
    subq    $48, %rsp
    movq    %rax,   (%rsp)
    movq    %rdx,  8(%rsp)
    movupd  %xmm0, 16(%rsp)
    movupd  %xmm1, 32(%rsp)

    movq    hub_ptr(%rip), %rdi
    leaq    48(%rsp), %rsi
    call    *pop_stack(%rip)
    movq    %rax, %r11

    movq      (%rsp), %rax
    movq     8(%rsp), %rdx
    movupd  16(%rsp), %xmm0
    movupd  32(%rsp), %xmm1
    addq    $48, %rsp
    jmp     *%r11

srx_hub_trampo_template_data:
push_stack:
    .quad 0
pop_stack:
    .quad 0
hub_ptr:
    .quad 0
"#,
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

pub(super) fn alloc_hub(orig_addr: usize) -> Result<*mut super::Hub, Errno> {
    manager::alloc_hub(orig_addr)
}

pub(super) fn discard_unpublished_hub(hub_ptr: *mut super::Hub) {
    manager::discard_unpublished_hub(hub_ptr);
}

// 只写入尚未发布的页面，由管理器统一刷新指令缓存并设置 RX 权限。
pub(super) unsafe fn init_trampo(
    trampo: usize,
    hub_ptr: usize,
    push_stack: usize,
    pop_stack: usize,
) -> Result<(), Errno> {
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

    Ok(())
}
