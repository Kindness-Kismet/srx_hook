# srx_hook

基于 Rust 的 Android 64 位 PLT hook 库。

本项目参考了 [ByteHook](https://github.com/bytedance/bhook) 的任务化模型设计，使用 Rust 完全重写。

> 本库不兼容 ByteHook / ShadowHook 等其他 PLT hook 框架同时加载，请勿在同一进程中混用。

## 特性

- 任务式 API：`init / hook_single / hook_partial / hook_all / unhook`
- 运行期持续新增 hook，无需"先注册完再 refresh"
- `caller / callee / ignore` 路径规则支持实例级定位（`libxxx.so@0xBASE%0xINSTANCE`）
- `hub + trampoline` 架构，每个调用点独立管理 proxy 链
- 多任务独立卸载，同一调用点可独立 unhook
- 环形调用检测，命中递归环时自动回落原函数
- 自动模式基于 `dlopen / dlclose` 事件触发刷新，带低频兜底巡检
- ELF 遍历使用 `dl_iterate_phdr`，支持 SYSV / GNU hash 与 packed relocation
- SIGSEGV / SIGBUS 保护槽位支持动态扩容

## 快速示例

```rust
use std::ffi::c_void;
use srx_hook::{init, hook_single, refresh, HookMode, SrxHookErrno};

unsafe extern "C" fn my_proxy() {}

let status = init(HookMode::Manual, true);
assert_eq!(status, SrxHookErrno::Ok);

let stub = hook_single(
    "libtarget.so",
    None,
    "target_symbol",
    my_proxy as *mut c_void,
    None,
    std::ptr::null_mut(),
);
assert!(stub.is_some());

let (status, _errors) = refresh();
assert_eq!(status, SrxHookErrno::Ok);
```

`clear()` 恢复 GOT 并移除任务，旧 `HookStub` 不会复用于新任务。在途调用的返回上下文继续保留；已经发布的跳板入口和 Hub 保留到进程退出，持续创建新入口仍会增加内存。原生返回栈最多追踪 32 层，超出容量或线程状态不可用时回落原函数。

普通 `fork()` 的子进程可继续调用继承的 hook；如需自动监控后续加载的库，应再次调用 `init()`，或通过 `refresh()` 等生命周期入口接管运行时。`fork_safe()` 只表示 atfork 处理器注册成功，不保证第三方锁、直接 syscall/clone、vfork 或异步信号处理中的任意 API 调用安全。

## 测试

### 实机验证

```bash
cargo build --manifest-path hook_test/Cargo.toml \
  --target aarch64-linux-android --release

adb shell mkdir -p /data/local/tmp/srx_hook_test
adb push target/aarch64-linux-android/release/hook_test \
  /data/local/tmp/srx_hook_test/
adb push target/aarch64-linux-android/release/libhook_test.so \
  /data/local/tmp/srx_hook_test/
adb shell chmod 755 /data/local/tmp/srx_hook_test/hook_test
adb shell "cd /data/local/tmp/srx_hook_test && LD_LIBRARY_PATH=. ./hook_test"
```

库单元测试需要在对应架构的 Android 环境执行，并使用 `--test-threads=1` 串行运行，避免测试间共享的进程级 hook 状态相互干扰。

### CI 自动验证

项目通过 GitHub Actions 对两个 Android 架构执行 workspace/all-target Clippy 和 release 构建，并在 x86_64 Android 模拟器上串行执行库单元测试及两级场景验证：

**短时验证**（每次 push / PR 触发）：

| 参数 | 值 |
|---|---|
| `HOOK_TEST_MARATHON_ROUNDS` | 120 |
| `HOOK_TEST_AUTO_MARATHON_ROUNDS` | 60 |
| `HOOK_TEST_SOAK_ROUNDS` | 1 |
| `HOOK_TEST_CONCURRENT_WORKERS` | 16 |
| `HOOK_TEST_CONCURRENT_CALLS` | 16 |
| `HOOK_TEST_LEAK_ROUNDS` | 64 |

**中时验证**（每次 push / PR 触发）：

| 参数 | 值 |
|---|---|
| `HOOK_TEST_MARATHON_ROUNDS` | 1200 |
| `HOOK_TEST_AUTO_MARATHON_ROUNDS` | 600 |
| `HOOK_TEST_SOAK_ROUNDS` | 3 |
| `HOOK_TEST_CONCURRENT_WORKERS` | 48 |
| `HOOK_TEST_CONCURRENT_CALLS` | 48 |
| `HOOK_TEST_LEAK_ROUNDS` | 320 |

### 测试参数说明

| 环境变量 | 说明 | 默认值 |
|---|---|---|
| `HOOK_TEST_MARATHON` | 启用手动长跑场景 | 0 |
| `HOOK_TEST_MARATHON_ROUNDS` | 手动长跑轮次 | 4000 |
| `HOOK_TEST_MARATHON_REPORT_STEP` | 手动长跑进度输出间隔 | 400 |
| `HOOK_TEST_AUTO_MARATHON` | 启用自动模式长跑 | 0 |
| `HOOK_TEST_AUTO_MARATHON_ROUNDS` | 自动模式长跑轮次 | 2000 |
| `HOOK_TEST_AUTO_MARATHON_REPORT_STEP` | 自动模式进度输出间隔 | 400 |
| `HOOK_TEST_SOAK` | 启用复合夜跑场景 | 0 |
| `HOOK_TEST_SOAK_ROUNDS` | 复合夜跑轮次 | 6 |
| `HOOK_TEST_SOAK_REPORT_STEP` | 复合夜跑进度输出间隔 | 1 |
| `HOOK_TEST_AUTO_RELOAD_ROUNDS` | 自动重载压测轮次 | 120 |
| `HOOK_TEST_CONCURRENT_WORKERS` | 并发压测线程数 | 72 |
| `HOOK_TEST_CONCURRENT_CALLS` | 并发压测每线程调用次数 | 80 |
| `HOOK_TEST_CONCURRENT_ROUNDS` | 并发压测 hook/unhook 轮次 | 80 |
| `HOOK_TEST_PERSISTENT_WORKERS` | 持久 hook 并发线程数 | 56 |
| `HOOK_TEST_PERSISTENT_CALLS` | 持久 hook 每线程调用次数 | 320 |
| `HOOK_TEST_LEAK_ROUNDS` | 泄漏 smoke 轮次 | 320 |

## License

MIT
