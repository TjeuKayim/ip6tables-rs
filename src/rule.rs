use libip6tc_sys as sys;
use std::ffi::{CStr, CString};
use std::mem::size_of;
use std::net::Ipv6Addr;
use std::os::raw::c_int;

#[derive(Clone)]
pub struct RuleBuilder<E, M, T> {
    entry: E,
    matches: M,
    target: sys::xt_entry_target,
    target_data: T,
}

pub struct Match<D, T> {
    m: sys::xt_entry_match,
    data: D,
    tail: T,
}

// pub struct Target

impl RuleBuilder<(), (), ()> {
    fn ip6() -> RuleBuilder<sys::ip6t_entry, (), ()> {
        RuleBuilder {
            entry: sys::ip6t_entry::default(),
            matches: (),
            target: sys::xt_entry_target::default(),
            target_data: (),
        }
    }
}

impl<M, T> RuleBuilder<sys::ip6t_entry, M, T> {
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

    #[test]
    fn it_works() {
        let rule = RuleBuilder::ip6()
            .src("2001:db8::".parse().unwrap()) // TODO: ip net crate support
            .match_comment("hello world")
            .target_accept();
    }
}
