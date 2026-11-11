// ELF 指针访问限定在 Bionic phdr 回调提供的模块租期内。
use crate::errno::Errno;
use crate::runtime;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::mem;
use std::slice;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LoaderEpoch {
    pub(super) adds: u64,
    pub(super) subs: u64,
}

pub(super) fn with_loader_lease<R>(
    operation: impl FnOnce(LoaderEpoch) -> Result<R, Errno>,
) -> Result<R, Errno> {
    struct Context<F, R> {
        operation: Option<F>,
        result: Option<Result<R, Errno>>,
    }

    unsafe extern "C" fn invoke<F, R>(
        info: *mut libc::dl_phdr_info,
        size: usize,
        data: *mut c_void,
    ) -> libc::c_int
    where
        F: FnOnce(LoaderEpoch) -> Result<R, Errno>,
    {
        let context = unsafe { &mut *data.cast::<Context<F, R>>() };
        let required = mem::offset_of!(libc::dl_phdr_info, dlpi_subs) + mem::size_of::<u64>();
        if info.is_null() || size < required {
            context.result = Some(Err(Errno::ModuleLeaseUnavailable));
            return 1;
        }
        let info = unsafe { &*info };
        if let Some(operation) = context.operation.take() {
            context.result = Some(operation(LoaderEpoch {
                adds: info.dlpi_adds,
                subs: info.dlpi_subs,
            }));
        }
        1
    }

    fn run<F, R>(operation: F) -> Result<R, Errno>
    where
        F: FnOnce(LoaderEpoch) -> Result<R, Errno>,
    {
        let _loader_call = runtime::fork::LoaderCall::enter();
        let mut context = Context {
            operation: Some(operation),
            result: None,
        };
        unsafe {
            libc::dl_iterate_phdr(
                Some(invoke::<F, R>),
                (&mut context as *mut Context<F, R>).cast(),
            );
        }
        context.result.unwrap_or(Err(Errno::ModuleLeaseUnavailable))
    }

    run(operation)
}

pub(super) fn bionic_module_ranges() -> BTreeMap<usize, Vec<(usize, usize)>> {
    unsafe extern "C" fn collect(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut c_void,
    ) -> libc::c_int {
        if !info.is_null() {
            let modules = unsafe { &mut *data.cast::<BTreeMap<usize, Vec<(usize, usize)>>>() };
            let info = unsafe { &*info };
            let base = info.dlpi_addr as usize;
            if info.dlpi_phdr.is_null() {
                return 0;
            }
            let headers =
                unsafe { slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize) };
            let ranges = headers
                .iter()
                .filter(|header| header.p_type == libc::PT_LOAD)
                .filter_map(|header| {
                    let start = base.checked_add(header.p_vaddr as usize)?;
                    let end = start.checked_add(header.p_memsz as usize)?;
                    Some((start, end))
                })
                .collect();
            modules.insert(base, ranges);
        }
        0
    }
    let mut modules = BTreeMap::new();
    unsafe {
        libc::dl_iterate_phdr(
            Some(collect),
            (&mut modules as *mut BTreeMap<usize, Vec<(usize, usize)>>).cast(),
        );
    }
    modules
}
