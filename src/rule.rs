use libip6tc_sys as sys;
use std::ffi::{CStr, CString};
use std::mem::size_of;
use std::net::Ipv6Addr;
use std::os::raw::c_int;
use std::alloc::{alloc_zeroed, dealloc, Layout};

const ALIGN: usize = size_of::<u64>();

#[derive(Clone)]
pub struct RuleBuilder<E> {
    // ip6t_entry has 8 byte alignment (so does XT_ALIGN)
    ptr: NonNull<u8>,
    cap: usize,
    len: usize,
}

pub struct Match<D, T> {
    m: sys::xt_entry_match,
    data: D,
    tail: T,
}

impl RuleBuilder<sys::ip6t_entry> {
    pub fn ip6() -> Self {
        // Start with the standard size for IPv6
        let cap = size_of<sys::ip6t_standard>() / ALIGN;
        debug_assert_eq!(size_of::<sys::ip6t_standard>() % ALIGN, 0);
        // buffer.resize(size_of::<sys::ip6t_entry>() / ALIGN);
        // buffer: Vec::with_capacity(cap),

        let builder = RuleBuilder {
            // matches: (),
            // target: sys::xt_entry_target::default(),
            // target_data: (),
        }
        let size = builder.extend<sys::ip6t_entry>();
        
    }

    fn entry(&mut self) -> &mut sys::ip6t_entry {
        &mut *(self.buffer.as_mut_ptr() as *mut u64 as *mut _)
    }

    fn extend<T>(&mut self) -> usize {
        // see XT_ALIGN macro
        let size = size_of::<T>();
        let mask = ALIGN - 1;
        let bytes = (size + mask) & !(mask);
        let items = bytes / ALIGN;
        self.buffer.resize(self.buffer.len() + items, 0);
        bytes
    }

    fn src(mut self, ip: Ipv6Addr) -> Self {
        self.entry.ipv6.src.__in6_u.__u6_addr16 = ip.segments();
        self
    }
}

impl<E, M, T> RuleBuilder<E, M, T> {
    fn match_comment(self, comment: &str) -> RuleBuilder<E, Match<sys::xt_comment_info, M>, T> {
        let comment_c = CString::new(comment).unwrap();
        const MAX: usize = sys::XT_MAX_COMMENT_LEN as _;
        assert!(comment.len() < MAX, "max length is 255 (plus null byte)");
        let mut comment = [0i8; MAX];
        cast_signed(&mut comment[0..comment_c.as_bytes().len()])
            .copy_from_slice(comment_c.as_bytes());

        let name_c = CString::new("comment").unwrap();
        let mut name = [0i8; 29];
        cast_signed(&mut name[0..name_c.as_bytes().len()]).copy_from_slice(name_c.as_bytes());

        let m = Match {
            m: sys::xt_entry_match {
                match_size: (size_of::<sys::xt_entry_match>() + size_of::<sys::xt_comment_info>())
                    as _,
                name,
                revision: 0,
                align: [],
            },
            data: sys::xt_comment_info { comment },
            tail: self.matches,
        };
        RuleBuilder {
            matches: m,
            entry: self.entry,
            target: self.target,
            target_data: self.target_data,
        }
    }

    fn target_accept(self) -> RuleBuilder<E, M, c_int> {
        assert_eq!(size_of::<T>(), 0);
        RuleBuilder {
            target_data: sys::NF_ACCEPT as _,
            entry: self.entry,
            matches: self.matches,
            target: self.target,
        }
    }
}

fn cast_signed(x: &mut [i8]) -> &mut [u8] {
    unsafe { &mut *(x as *mut [i8] as *mut [u8]) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::mem::align_of;

    #[test]
    fn builder_align() {
        // align_of::<RuleBuilder>();
    }

    #[test]
    fn it_works() {
        let rule = RuleBuilder::ip6()
            .src("2001:db8::".parse().unwrap()) // TODO: ip net crate support
            .match_comment("hello world")
            .target_accept();
    }
}
