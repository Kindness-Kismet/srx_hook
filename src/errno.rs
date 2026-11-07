// hook 操作错误码，0 表示成功
#[repr(i32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Errno {
    Ok = 0,                // 成功
    Uninit = 1,            // 未初始化
    InitErrInvalidArg = 2, // 初始化参数无效
    InitErrSym = 3,        // 符号解析失败
    InitErrTask = 4,       // 任务管理器初始化失败
    InitErrHook = 5,       // hook 引擎初始化失败
    InitErrElf = 6,        // ELF 解析器初始化失败
    InitErrElfRefr = 7,    // ELF 刷新器初始化失败
    InitErrTrampo = 8,     // trampoline 管理器初始化失败
    InitErrSig = 9,        // 信号守卫初始化失败
    InitErrDlMtr = 10,     // dlopen 监控器初始化失败
    InvalidArg = 11,       // 参数无效
    UnmatchOrigFunc = 12,  // 原函数地址不匹配
    NoSym = 13,            // 符号未找到
    GetProt = 14,          // 读取内存保护属性失败
    SetProt = 15,          // 设置内存保护属性失败
    SetGot = 16,           // 写入 GOT 表项失败
    NewTrampo = 17,        // 创建 trampoline 失败
    AppendTrampo = 18,     // 追加 trampoline 节点失败
    GotVerify = 19,        // GOT 表项校验失败
    RepeatedFunc = 20,     // 重复的 proxy 函数
    ReadElf = 21,          // 读取 ELF 信息失败
    CfiHookFailed = 22,    // CFI hook 失败
    OrigAddr = 23,         // 原始地址获取失败
    InitErrCfi = 24,       // CFI 模块初始化失败
    Ignore = 25,           // 模块在忽略列表中
    InitErrSafe = 26,      // 在外部回调中调用，拒绝执行
    InitErrHub = 27,       // hub 管理器初始化失败
    Oom = 28,              // 内存分配失败
    Dup = 29,              // 重复操作
    NotFound = 30,         // 未找到目标
    Busy = 31,            // 发布或进程接管正在进行
    ForkContextUnavailable = 32, // 子进程缺少可继续管理的 loader 上下文
    ModuleLeaseUnavailable = 33, // 无法证明目标模块在提交期间保持有效
    Max = 255,             // 保留上界
    Unknown = 1001,        // 未知错误
    Invalid = 1002,        // 无效状态
    NoMem = 1003,          // 内存不足
    Repeat = 1004,         // 重复请求
    BadMaps = 1006,        // /proc/self/maps 解析失败
    Format = 1007,         // 格式错误
    ElfInit = 1008,        // ELF 初始化失败
    SegvErr = 1009,        // 信号保护触发
}

impl Errno {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

impl From<Errno> for i32 {
    fn from(value: Errno) -> Self {
        value as i32
    }
}
