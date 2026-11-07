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
use srx_hook::{init, hook_single_checked, refresh, HookMode, SrxHookErrno};

unsafe extern "C" fn my_proxy() {}

let status = init(HookMode::Manual, true);
assert_eq!(status, SrxHookErrno::Ok);

let stub = hook_single_checked(
    "libtarget.so",
    None,
    "target_symbol",
    my_proxy as *mut c_void,
    None,
    std::ptr::null_mut(),
);
assert!(stub.is_ok());

let (status, errors) = refresh();
assert_eq!(status, SrxHookErrno::Ok);
assert!(errors.is_empty());
```

## 管理接口与提交结果

需要处理失败原因时，使用 `hook_single_checked`、`hook_partial_checked`、`hook_all_checked` 和 `clear_checked`。

| 接口 | 返回值与含义 |
|---|---|
| `hook_*_checked` | `Result<HookStub, HookError>`；`Ok(stub)` 表示任务已注册，`HookError` 提供状态码、已注册任务的可选 stub 和模块错误 |
| `refresh()` | `(SrxHookErrno, Vec<RefreshError>)`；汇总状态与按模块记录的错误，成功模块可以先行生效 |
| `unhook(stub)` | 返回状态码；处理指定任务并保留同一调用点的其余任务 |
| `clear_checked()` | `Result<ClearReport, ClearError>`；报告包含状态版本、移除/剩余 slot 数、剩余待恢复页数与模块错误 |

同步管理操作在快照版本、模块 epoch、GOT 预期值或发布者竞争导致计划失效时，退出 loader 租期和发布 gate 后重新准备，最多尝试 8 次。任务 stub 在整个调用中分配一次，成功发布后再分发安装回调；调用方过滤器可在重准备期间再次求值。元数据更新同样重取完整快照，持续竞争和重入修改达到上限时返回 `Busy`。

fork 冻结、初始化或清理状态导致的 `Busy` 直接返回，调用方可在普通执行上下文重新调用。`clear_checked()` 可能已经停止 monitor 或完成部分清理，应同时检查 `ClearError.report`；完成清理后再次调用 `init()` 可重新启用运行时。入口检查阶段直接拒绝的清理请求返回默认报告，此时以 `status` 为准。空返回值的 `set_debug`、`set_recordable` 在普通上下文的最终更新失败时输出状态日志，当前值由对应 getter 查询。

`HookError.status` 给出本次错误，`errors` 提供模块详情。`stub: Some(stub)` 表示任务已经注册，调用方可继续 `refresh()` 或使用该 stub 执行 `unhook()`；`stub: None` 表示注册未提交。Manual 模式注册后由 `refresh()` 应用任务，Automatic 模式注册时即可报告应用或权限恢复错误。

兼容接口 `hook_single / hook_partial / hook_all` 对已注册任务仍返回 `Some(stub)`，详细状态通过 checked 接口获取。`clear()` 保留原来的空返回值并记录运行时清理失败日志；需要确认清理结果的调用方应迁移到 `clear_checked()`。

提交先复验模块身份、GOT 原值和页面写权限，再发布代理链与 GOT。`SetProt` 既可能来自写入前的权限准备，也可能来自提交后的原权限恢复；恢复失败的日志包含页面地址与期望权限，`RefreshError` 记录所属模块。checked 注册接口通过 `HookError` 返回该错误，已提交任务的 stub 同时保留，便于后续卸载。

运行时保留恢复失败页面的原权限，后续 `refresh()`、`unhook()` 或 `clear_checked()` 先复验模块租期，再重试恢复。`ClearReport.remaining_protections` 表示仍待恢复的页数；清理成功要求该值与 `remaining_slots` 都为零。若 loader 卸载计数已经变化、原基址又存在模块，实例身份存在歧义时返回 `ModuleLeaseUnavailable` 并保留待恢复记录。

## fork 与运行时寿命

父进程成功初始化后，普通 `fork()` 的 child 可继续执行已经发布的 Hook 链，并保留调用线程的跳板返回上下文。Automatic 模式的 child 可再次调用 `init()` 启动自己的 monitor，继续跟踪后续动态库变化。

若 fork 时库已记录的 loader 操作或信号处理器安装仍在进行，child 的管理接口返回 `ForkContextUnavailable`，该状态持续到进程结束；既有链的调用路径仍可使用。后台模块扫描也属于 loader 操作。`fork_safe()` 表示 atfork 处理器注册成功。验证范围为普通调用栈中的 `fork()`；直接 syscall/clone、vfork、异步信号处理，以及调用方自身的锁和 Binder/ART 状态，需要各自的进程生命周期协议。

已经发布的 Hub 和 trampoline 入口保留至进程退出，退休代理链依据活跃返回帧回收。`clear_checked()` 恢复 GOT 并移除任务，旧 `HookStub` 持续占用其编号；原生返回栈最多追踪 32 层，超出容量时调用原函数。持续创建新入口会增加常驻内存。

child 为管理状态和辅助缓存创建独立的进程运行时，继承的父代控制容器保留至进程退出。这样的内存寿命使 child 可以避开父代线程留下的锁和析构状态。代理函数与原函数所属动态库的加载寿命仍由调用方管理。

## 模块生命周期

模块采集与提交复验使用 Bionic 的 `dl_iterate_phdr` 临界区，覆盖其管理的普通模块和隐藏 namespace 模块。仅由 `/proc/self/maps` 发现、且缺少 Bionic 模块租期的自定义 loader 模块，应用阶段返回 `ModuleLeaseUnavailable`。对应任务仍可完成注册，checked 接口的 `HookError.stub` 标明已注册任务，具体模块错误也通过回调和 `refresh()` 返回；当前版本要求目标模块具备 Bionic 提供的存活保护。

## 测试

### 实机验证

```bash
cargo build --manifest-path hook_test/Cargo.toml \
  --target aarch64-linux-android --release

adb push target/aarch64-linux-android/release/hook_test \
  /data/local/tmp/srx_hook_test/
adb push target/aarch64-linux-android/release/libhook_test.so \
  /data/local/tmp/srx_hook_test/
adb shell chmod 755 /data/local/tmp/srx_hook_test/hook_test
adb shell /data/local/tmp/srx_hook_test/hook_test
```

### CI 自动验证

项目通过 GitHub Actions 在 x86_64 Android 模拟器上执行两级验证：

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
| `HOOK_TEST_AUTO_MARATHON_ROUNDS` | 自动模式长跑轮次 | 4000 |
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
