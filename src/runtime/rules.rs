// 模块路径匹配规则解析与判定
// 支持路径后缀 @base_addr、%instance_id、^namespace_id 精确限定

// 解析后的路径规则，各限定符均为可选
struct ParsedPathRule<'a> {
    path_rule: &'a str,
    base_rule: Option<usize>,
    instance_rule: Option<usize>,
    namespace_rule: Option<usize>,
}

// 仅匹配路径部分，忽略 base/instance/namespace 限定符
pub(super) fn path_match(linker_path: &str, external_path: &str) -> bool {
    let Some(rule) = parse_path_rule(external_path) else {
        return false;
    };
    path_match_only(linker_path, rule.path_rule)
}

// 完整模块匹配：路径 + base_addr + instance_id + namespace_id
// 规则中未指定的限定符视为通配
pub(super) fn module_match(
    linker_path: &str,
    linker_base_addr: usize,
    linker_instance_id: usize,
    linker_namespace_id: usize,
    external_path: &str,
) -> bool {
    let Some(rule) = parse_path_rule(external_path) else {
        return false;
    };
    if !path_match_only(linker_path, rule.path_rule) {
        return false;
    }
    if rule.base_rule.is_some_and(|base| base != linker_base_addr) {
        return false;
    }
    if rule
        .instance_rule
        .is_some_and(|instance| instance != linker_instance_id)
    {
        return false;
    }
    if rule
        .namespace_rule
        .is_some_and(|namespace| namespace != linker_namespace_id)
    {
        return false;
    }
    true
}

// 判断模块是否应跳过 hook
// 空路径、vDSO（以 '[' 开头）和自身模块始终跳过
// self_base_addr 为宿主 so 加载基址，按基址跳过自身，与路径无关（覆盖 memfd）
pub(super) fn should_ignore(
    pathname: &str,
    base_addr: usize,
    instance_id: usize,
    namespace_id: usize,
    self_base_addr: usize,
    ignores: &[String],
) -> bool {
    if pathname.is_empty() || pathname.starts_with('[') {
        return true;
    }
    // 按基址跳过自身，避免 hook 框架被 hook 导致段错误
    if self_base_addr != 0 && base_addr == self_base_addr {
        return true;
    }
    // 跳过自身，避免 hook 框架被 hook 导致无限递归
    if pathname.ends_with("libsrx_hook.so") {
        return true;
    }

    ignores
        .iter()
        .any(|rule| module_match(pathname, base_addr, instance_id, namespace_id, rule))
}

// 纯路径匹配：绝对路径要求完全相等，相对路径使用后缀匹配
fn path_match_only(linker_path: &str, external_path: &str) -> bool {
    if external_path.is_empty() {
        return false;
    }

    if external_path.starts_with('/') {
        linker_path == external_path
    } else {
        linker_path.ends_with(external_path)
    }
}

// 从右向左依次拆分 ^namespace、%instance、@base 后缀
fn parse_path_rule(external_path: &str) -> Option<ParsedPathRule<'_>> {
    if external_path.is_empty() {
        return None;
    }

    let (path_and_instance, namespace_rule) = split_namespace_rule(external_path)?;
    let (path_and_base, instance_rule) = split_instance_rule(path_and_instance)?;
    let (path_rule, base_rule) = split_base_rule(path_and_base)?;
    Some(ParsedPathRule {
        path_rule,
        base_rule,
        instance_rule,
        namespace_rule,
    })
}

fn split_namespace_rule(external_path: &str) -> Option<(&str, Option<usize>)> {
    let Some((path_rule, namespace_rule)) = external_path.rsplit_once('^') else {
        return Some((external_path, None));
    };
    if path_rule.is_empty() {
        return None;
    }
    match parse_hex_usize(namespace_rule) {
        Some(namespace) => Some((path_rule, Some(namespace))),
        None => Some((external_path, None)),
    }
}

fn split_instance_rule(external_path: &str) -> Option<(&str, Option<usize>)> {
    let Some((path_rule, instance_rule)) = external_path.rsplit_once('%') else {
        return Some((external_path, None));
    };
    if path_rule.is_empty() {
        return None;
    }
    match parse_hex_usize(instance_rule) {
        Some(instance) => Some((path_rule, Some(instance))),
        None => Some((external_path, None)),
    }
}

fn split_base_rule(path_and_base: &str) -> Option<(&str, Option<usize>)> {
    let Some((path_rule, base_rule)) = path_and_base.rsplit_once('@') else {
        return Some((path_and_base, None));
    };
    if path_rule.is_empty() {
        return None;
    }
    match parse_hex_usize(base_rule) {
        Some(base_addr) => Some((path_rule, Some(base_addr))),
        None => Some((path_and_base, None)),
    }
}

fn parse_hex_usize(rule: &str) -> Option<usize> {
    let value = rule
        .strip_prefix("0x")
        .or_else(|| rule.strip_prefix("0X"))
        .unwrap_or(rule);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    usize::from_str_radix(value, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::{module_match, path_match, should_ignore};

    #[test]
    fn path_match_ignores_instance_suffix() {
        assert!(path_match(
            "/data/app/libfoo.so",
            "libfoo.so%0x1234abcd",
        ));
    }

    #[test]
    fn module_match_supports_base_and_instance_suffix() {
        assert!(module_match(
            "/data/app/libfoo.so",
            0x1A2B,
            0x55AA,
            0x10,
            "libfoo.so@0x1a2b%0x55aa",
        ));
        assert!(!module_match(
            "/data/app/libfoo.so",
            0x1A2B,
            0x55AA,
            0x10,
            "libfoo.so@0x1a2b%0x55ab",
        ));
    }

    #[test]
    fn module_match_keeps_base_only_compatibility() {
        assert!(module_match(
            "/data/app/libfoo.so",
            0x1A2B,
            0x100,
            0x10,
            "libfoo.so@0x1a2b",
        ));
    }

    #[test]
    fn module_match_supports_namespace_suffix() {
        assert!(module_match(
            "/data/app/libfoo.so",
            0x1A2B,
            0x55AA,
            0x66CC,
            "libfoo.so@0x1a2b%0x55aa^0x66cc",
        ));
        assert!(!module_match(
            "/data/app/libfoo.so",
            0x1A2B,
            0x55AA,
            0x66CD,
            "libfoo.so@0x1a2b%0x55aa^0x66cc",
        ));
    }

    #[test]
    fn should_ignore_uses_instance_rule() {
        let ignores = vec!["libfoo.so%0x1234".to_string()];
        assert!(should_ignore("/data/app/libfoo.so", 0x1, 0x1234, 0x10, 0, &ignores));
        assert!(!should_ignore("/data/app/libfoo.so", 0x1, 0x5678, 0x20, 0, &ignores));
    }

    #[test]
    fn should_ignore_uses_namespace_rule() {
        let ignores = vec!["libfoo.so%0x1234^0x8888".to_string()];
        assert!(should_ignore("/data/app/libfoo.so", 0x1, 0x1234, 0x8888, 0, &ignores));
        assert!(!should_ignore("/data/app/libfoo.so", 0x1, 0x1234, 0x9999, 0, &ignores));
    }

    // memfd 加载下路径不含 so 名，仅靠基址跳过自身
    #[test]
    fn should_ignore_self_by_base_addr() {
        let ignores: Vec<String> = Vec::new();
        assert!(should_ignore(
            "/memfd:zygisk-module (deleted)",
            0xABCD,
            0x1,
            0x0,
            0xABCD,
            &ignores
        ));
        assert!(!should_ignore(
            "/memfd:zygisk-module (deleted)",
            0xABCD,
            0x1,
            0x0,
            0x1234,
            &ignores
        ));
    }

    // self_base_addr 为 0（未解析）时不误伤任意模块
    #[test]
    fn should_not_ignore_when_self_base_unknown() {
        let ignores: Vec<String> = Vec::new();
        assert!(!should_ignore("/data/app/libfoo.so", 0x0, 0x1, 0x0, 0, &ignores));
    }
}
