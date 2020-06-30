use libip6tc_sys as sys;
use std::ffi::{CString, CStr};
use std::mem::{forget, size_of, size_of_val};
use std::net::{Ipv6Addr, Ipv4Addr};
use std::ptr::null_mut;
use std::alloc::{handle_alloc_error, AllocInit, AllocRef, Global, Layout, ReallocPlacement};
use std::fmt;
use std::marker::PhantomData;
use std::ptr::NonNull;

const ALIGN: usize = size_of::<u64>();

pub trait Entry: fmt::Debug + Clone {
    type Sys;

    fn set_offsets(entry: &mut Self::Sys, target: usize, next: usize);
}

impl Entry for Ipv6Addr {
    type Sys = sys::ip6t_entry;

    fn set_offsets(entry: &mut Self::Sys, target: usize, next: usize) {
        entry.target_offset = target as _;
        entry.next_offset = next as _;
    }
}

impl Entry for Ipv4Addr {
    type Sys = sys::ipt_entry;

    fn set_offsets(entry: &mut Self::Sys, target: usize, next: usize) {
        entry.target_offset = target as _;
        entry.next_offset = next as _;
    }
}

#[derive(Clone, Debug)]
struct RuleBuf<E: Entry> {
    // ip6t_entry has 8 byte alignment (so does XT_ALIGN)
    ptr: NonNull<u8>,
    cap: usize,
    phantom: PhantomData<(Box<E>, Vec<sys::xt_entry_match>)>,
}

#[derive(Clone, Debug)]
pub struct Rule<E: Entry> {
    buf: RuleBuf<E>,
}

impl<E: Entry> Rule<E> {
    pub fn entry_ptr(&self) -> *const E::Sys {
        self.buf.ptr.as_ptr() as *const E::Sys
    }

    pub fn print_rule(&self, rule: &Rule<Ipv6Addr>) {
        let chain = CString::new("chain-name").unwrap();
        unsafe {sys::print_rule6(rule.entry_ptr(), null_mut(), chain.as_ptr(), 0) };
    }
}

#[derive(Clone, Debug)]
pub struct RuleBuilder<E: Entry> {
    buf: RuleBuf<E>,
    len: usize,
}

#[repr(C)]
#[derive(Debug)]
struct Match<T> {
    m: sys::xt_entry_match,
    data: T,
}

impl<E: Entry> Drop for RuleBuf<E> {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(self.cap, ALIGN).unwrap();
        unsafe { Global.dealloc(self.ptr, layout) };
    }
}

impl RuleBuilder<Ipv4Addr> {
    pub fn ip4() -> Self {
        RuleBuilder::new()
    }

    /// ```
    /// use ip6tables::rule::RuleBuilder;
    /// RuleBuilder::ip4().src("192.0.2.0".parse().unwrap());
    /// ```
    pub fn src(self, ip: Ipv4Addr) -> Self {
        let mut entry = self.buf.ptr.cast::<sys::ipt_entry>();
        let entry = unsafe { entry.as_mut() };
        entry.ip.src.s_addr = ip.into();
        self
    }
}

impl RuleBuilder<Ipv6Addr> {
    pub fn ip6() -> Self {
        RuleBuilder::new()
    }

    pub fn src(mut self, ip: Ipv6Addr) -> Self {
        let mut entry = self.entry();
        entry.ipv6.src.__in6_u.__u6_addr16 = ip.segments();
        self
    }
}

impl<E: Entry> RuleBuilder<E> {
    pub fn new() -> Self {
        // Start with the standard size for IPv6
        let cap = size_of::<sys::xt_standard_target>();
        // let ptr = unsafe { alloc_zeroed(Layout::from_size_align(cap, ALIGN).unwrap()) };
        let layout = Layout::from_size_align(cap, ALIGN).unwrap();
        let block = Global
            .alloc(layout, AllocInit::Zeroed)
            .unwrap_or_else(|_| handle_alloc_error(layout));
        RuleBuilder {
            buf: RuleBuf {
                ptr: block.ptr,
                cap: block.size,
                phantom: PhantomData,
            },
            len: size_of::<E::Sys>(),
        }
    }

    fn entry(&mut self) -> &mut E::Sys {
        unsafe { &mut *self.buf.ptr.as_ptr().cast() }
    }

    pub fn extend<'a, 'b: 'a, T>(&'a mut self) -> &'b mut T {
        // TODO: Is this a good use of lifetimes?

        // see XT_ALIGN macro
        let size = size_of::<T>();
        let mask = ALIGN - 1;
        let size = (size + mask) & !(mask);

        let old_len = self.len;
        self.len += size;
        if self.len > self.buf.cap {
            let new_cap = 2 * self.len;
            let layout = Layout::from_size_align(self.buf.cap, ALIGN).unwrap();
            let block = unsafe {
                Global.grow(
                    self.buf.ptr,
                    layout,
                    new_cap,
                    ReallocPlacement::MayMove,
                    AllocInit::Zeroed,
                )
            }
            .unwrap_or_else(|_| handle_alloc_error(layout));
            self.buf.ptr = block.ptr;
            self.buf.cap = block.size;
        }

        unsafe { &mut *(self.buf.ptr.as_ptr().add(old_len) as *mut _) }
    }

    fn extend_target<T>(&mut self, name: &str, revision: u8) -> &mut T {
        let target_offset = self.len;
        let target = self.extend::<Target<T>>();
        let next_offset = self.len;
        dbg!(target_offset, next_offset);
        E::set_offsets(self.entry(), target_offset, next_offset);
        target.e.target_size = size_of::<Target<T>>() as _;
        let name_c = CString::new(name).unwrap();
        cast_signed(&mut target.e.name[0..name_c.as_bytes().len()])
            .copy_from_slice(name_c.as_bytes());
        target.e.revision = revision;
        return &mut target.data;

        #[repr(C)]
        struct Target<T> {
            e: sys::xt_entry_target,
            data: T,
        }
    }

    pub fn match_comment(mut self, comment: &str) -> Self {
        let comment_c = CString::new(comment).unwrap();
        const MAX: usize = sys::XT_MAX_COMMENT_LEN as _;
        assert!(comment.len() < MAX, "max length is 255 (plus null byte)");
        let mut comment = [0i8; MAX];
        cast_signed(&mut comment[0..comment_c.as_bytes().len()])
            .copy_from_slice(comment_c.as_bytes());

        let name_c = CString::new("comment").unwrap();
        let mut name = [0i8; 29];
        cast_signed(&mut name[0..name_c.as_bytes().len()]).copy_from_slice(name_c.as_bytes());

        dbg!(self.len);
        let m = self.extend::<Match<sys::xt_comment_info>>();
        dbg!(self.len);
        m.m.match_size = size_of_val(m) as _;
        m.m.name = name;
        m.m.revision = 0;
        m.data = sys::xt_comment_info { comment };
        self
    }

    pub fn target_accept(mut self) -> Rule<E> {
        let data = self.extend_target::<std::os::raw::c_int>("", 0);
        *data = sys::NF_ACCEPT as _;
        let rule = Rule {
            buf: self.buf.clone(),
        };
        forget(self);
        rule
    }
}

fn cast_signed(x: &mut [i8]) -> &mut [u8] {
    unsafe { &mut *(x as *mut [i8] as *mut [u8]) }
}

pub fn xtables_init() {
    lazy_static::lazy_static! {
        static ref PROGRAM_NAME: CString = CString::new("ip6tables-rs").unwrap();
        static ref PROGRAM_VERSION: CString = CString::new("0.1").unwrap();
        static ref XTABLES_GLOBALS: Globals = {
            let mut globals = sys::xtables_globals::default();
            globals.program_name = PROGRAM_NAME.as_ptr();
            globals.program_version = PROGRAM_VERSION.as_ptr();
            globals.compat_rev = Some(sys::xtables_compatible_revision);
            Globals(globals)
        };
    };
    unsafe {
        sys::xtables_init_all(&XTABLES_GLOBALS.0 as *const _ as *mut _, sys::NFPROTO_IPV6 as _);
        // sys::init_extensions6();
    }
}

struct Globals(sys::xtables_globals);

unsafe impl Sync for Globals {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::table::*;

    #[test]
    fn build_rule() {
        // let builder = RuleBuilder::ip6();
        // builder.src("2001:db8::".parse().unwrap());
        // builder.match_comment("hello world");
        let builder = RuleBuilder::ip6()
            .src("2001:db8::".parse().unwrap())
            .match_comment("hello world");
        let rule: Rule<_> = builder.target_accept();

        xtables_init();
        // let mut table = Table6::new("mangle").unwrap();
        rule.print_rule(&rule);
    }
}
