use libip6tc_sys as sys;
use std::ffi::CString;
use std::mem::{forget, size_of, size_of_val};
use std::net::Ipv6Addr;
// use std::os::raw::c_int;
use std::alloc::{handle_alloc_error, AllocInit, AllocRef, Global, Layout, ReallocPlacement};
use std::fmt;
use std::marker::PhantomData;
use std::ptr::NonNull;

const ALIGN: usize = size_of::<u64>();

pub trait Entry: fmt::Debug + Clone {
    type Sys;
}

impl Entry for Ipv6Addr {
    type Sys = sys::ip6t_entry;
}
// impl Entry for sys::ipt_entry {}

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

#[derive(Clone, Debug)]
pub struct RuleBuilder<E: Entry> {
    buf: RuleBuf<E>,
    len: usize,
}

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

impl RuleBuilder<Ipv6Addr> {
    pub fn ip6() -> Self {
        RuleBuilder::new()
    }

    fn src(self, ip: Ipv6Addr) -> Self {
        let mut entry = self.buf.ptr.cast::<sys::ip6t_entry>();
        let entry = unsafe { entry.as_mut() };
        entry.ipv6.src.__in6_u.__u6_addr16 = ip.segments();
        self
    }
}

impl<E: Entry> RuleBuilder<E> {
    fn new() -> Self {
        // Start with the standard size for IPv6
        let cap = size_of::<E::Sys>();
        debug_assert_eq!(size_of::<E::Sys>() % ALIGN, 0);
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
            len: size_of::<sys::ip6t_entry>(),
        }
    }

    // fn entry(&mut self) -> &mut sys::ip6t_entry {
    //     unsafe { self.buf.ptr.cast().as_mut() }
    // }

    fn extend<T>(&mut self) -> &mut T {
        // see XT_ALIGN macro
        let size = size_of::<T>();
        let mask = ALIGN - 1;
        let size = (size + mask) & !(mask);

        let old_len = self.len;
        self.len += size;
        if self.len > self.buf.cap {
            let new_cap = 2 * self.len;
            let layout = Layout::from_size_align(self.buf.cap, ALIGN).unwrap();
            dbg!(self.buf.cap, self.len, &layout);
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
            dbg!(self.buf.ptr, self.buf.cap);
        }

        unsafe { &mut *(self.buf.ptr.as_ptr().add(old_len) as *mut _) }
    }

    fn match_comment(mut self, comment: &str) -> Self {
        let comment_c = CString::new(comment).unwrap();
        const MAX: usize = sys::XT_MAX_COMMENT_LEN as _;
        assert!(comment.len() < MAX, "max length is 255 (plus null byte)");
        let mut comment = [0i8; MAX];
        cast_signed(&mut comment[0..comment_c.as_bytes().len()])
            .copy_from_slice(comment_c.as_bytes());

        let name_c = CString::new("comment").unwrap();
        let mut name = [0i8; 29];
        cast_signed(&mut name[0..name_c.as_bytes().len()]).copy_from_slice(name_c.as_bytes());

        let m = self.extend::<Match<sys::xt_comment_info>>();
        m.m.match_size = size_of_val(&m) as _;
        m.m.name = name;
        m.m.revision = 0;
        m.data = sys::xt_comment_info { comment };
        dbg!("comment");
        self
    }

    fn target_accept(mut self) -> Rule<E> {
        dbg!("target");
        let data = self.extend::<sys::xt_standard_target>();
        data.verdict = sys::NF_ACCEPT as _;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_rule() {
        // let builder = RuleBuilder::ip6();
        // builder.src("2001:db8::".parse().unwrap());
        // builder.match_comment("hello world");
        let builder = RuleBuilder::ip6()
            .src("2001:db8::".parse().unwrap())
            .match_comment("hello world");
        let _rule: Rule<_> = builder.target_accept();
    }
}
